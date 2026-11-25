"""Attack simulation harness: replay a corpus of attacks and benign traffic through the real Gateway.

Each scenario is one of:

- ``call``            a ``tools/call`` from the client (optionally repeated, optionally human-approved)
- ``result``          a tool output returned by the server for an allowed call
- ``tool-definition`` a tool definition reviewed for poisoning (detector only, no lockfile)
- ``rug-pull``        a tool from ``tools/list`` checked against the lockfile

Attacks declare ``expect: "detect"``; benign scenarios declare ``expect: "pass"``. Scenarios we know
the gateway does not catch are kept in the corpus with ``known_gap: true`` (and benign ones it wrongly
flags with ``known_false_positive: true``), so the report shows the real limits instead of hiding them.

Two numbers come out:
- detection rate over **all** attacks, and false-positive rate over **all** benign traffic (honest rates);
- a regression gate: every attack not marked as a known gap must be detected, and every benign
  scenario not marked as a known false positive must pass. CI fails if the gate fails, so a change
  that weakens a control, or adds a new false positive, is caught.
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .gateway import Gateway
from .pinning import load_lock, review_tools
from .policy import Policy, load_policy

KINDS = {"call", "result", "tool-definition", "rug-pull"}


@dataclass
class ScenarioResult:
    id: str
    category: str
    kind: str
    expect: str  # detect | pass
    detected: bool
    decision: str
    reasons: list[str]
    known_gap: bool
    known_false_positive: bool

    @property
    def correct(self) -> bool:
        return self.detected if self.expect == "detect" else not self.detected

    @property
    def gate_ok(self) -> bool:
        if self.correct:
            return True
        return self.known_gap if self.expect == "detect" else self.known_false_positive


@dataclass
class Report:
    results: list[ScenarioResult]

    def _rate(self, expect: str) -> tuple[int, int]:
        group = [r for r in self.results if r.expect == expect]
        return sum(r.detected for r in group), len(group)

    @property
    def detection(self) -> tuple[int, int]:
        return self._rate("detect")

    @property
    def false_positives(self) -> tuple[int, int]:
        return self._rate("pass")

    @property
    def gate_ok(self) -> bool:
        return all(r.gate_ok for r in self.results)

    @property
    def unexpected(self) -> list[ScenarioResult]:
        return [r for r in self.results if not r.gate_ok]

    def by_category(self) -> dict[str, tuple[int, int]]:
        acc: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for r in self.results:
            if r.expect == "detect":
                acc[r.category][0] += r.detected
                acc[r.category][1] += 1
        return {k: (v[0], v[1]) for k, v in sorted(acc.items())}

    def to_json(self) -> dict[str, Any]:
        d, n = self.detection
        fp, b = self.false_positives
        return {
            "detection": {"detected": d, "attacks": n},
            "false_positives": {"flagged": fp, "benign": b},
            "gate_ok": self.gate_ok,
            "by_category": {k: {"detected": v[0], "attacks": v[1]} for k, v in self.by_category().items()},
            "scenarios": [
                {
                    "id": r.id,
                    "category": r.category,
                    "kind": r.kind,
                    "expect": r.expect,
                    "detected": r.detected,
                    "decision": r.decision,
                    "reasons": r.reasons,
                    "known_gap": r.known_gap,
                    "known_false_positive": r.known_false_positive,
                }
                for r in self.results
            ],
        }

    def to_markdown(self) -> str:
        d, n = self.detection
        fp, b = self.false_positives
        lines = [
            "# mcpguard attack simulation",
            "",
            f"- Attacks detected: **{d} / {n}** ({100 * d / max(n, 1):.0f} %)",
            f"- Benign traffic wrongly flagged: **{fp} / {b}** ({100 * fp / max(b, 1):.0f} %)",
            f"- Regression gate: **{'PASS' if self.gate_ok else 'FAIL'}**",
            "",
            "| Category | Detected |",
            "|---|---|",
        ]
        lines += [f"| {cat} | {x} / {y} |" for cat, (x, y) in self.by_category().items()]
        gaps = [r for r in self.results if r.expect == "detect" and not r.detected]
        if gaps:
            lines += ["", "## Attacks not detected", "", "| Scenario | Category | Known gap |", "|---|---|---|"]
            lines += [f"| `{r.id}` | {r.category} | {'yes' if r.known_gap else '**NO (regression)**'} |" for r in gaps]
        fps = [r for r in self.results if r.expect == "pass" and r.detected]
        if fps:
            lines += ["", "## Benign traffic flagged", "", "| Scenario | Reason | Known |", "|---|---|---|"]
            lines += [
                f"| `{r.id}` | {'; '.join(r.reasons)[:90]} | {'yes' if r.known_false_positive else '**NO**'} |"
                for r in fps
            ]
        return "\n".join(lines) + "\n"


def load_corpus(path: str | Path) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    scenarios = data["scenarios"] if isinstance(data, dict) else data
    seen: set[str] = set()
    for s in scenarios:
        for key in ("id", "category", "kind", "expect"):
            if key not in s:
                raise ValueError(f"scenario {s.get('id', '?')}: missing '{key}'")
        if s["kind"] not in KINDS:
            raise ValueError(f"scenario {s['id']}: unknown kind '{s['kind']}'")
        if s["expect"] not in ("detect", "pass"):
            raise ValueError(f"scenario {s['id']}: expect must be 'detect' or 'pass'")
        if s["id"] in seen:
            raise ValueError(f"duplicate scenario id '{s['id']}'")
        seen.add(s["id"])
    return scenarios


class _Clock:
    """Frozen clock so rate-limit scenarios are deterministic."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _fresh_gateway(policy: Policy, lock: dict[str, str], tools: list[dict[str, Any]], approve: bool) -> Gateway:
    from .ratelimit import RateLimiter

    gw = Gateway(policy, lock=lock, limiter=RateLimiter(clock=_Clock()), approver=lambda _n, _a: approve)
    gw.opa = None  # the harness measures the gateway's own controls; OPA rules are tested with `opa test`
    gw.from_client({"jsonrpc": "2.0", "id": "list", "method": "tools/list"})
    gw.from_server({"jsonrpc": "2.0", "id": "list", "result": {"tools": tools}})
    return gw


def run_scenario(
    s: dict[str, Any], policy: Policy, lock: dict[str, str], tools: list[dict[str, Any]]
) -> ScenarioResult:
    kind = s["kind"]
    decision, reasons = "forward", []
    if kind == "call":
        gw = _fresh_gateway(policy, lock, tools, bool(s.get("approve", False)))
        out = None
        for i in range(int(s.get("repeat", 1))):
            msg = {
                "jsonrpc": "2.0",
                "id": i,
                "method": "tools/call",
                "params": {"name": s["tool"], "arguments": s.get("arguments", {})},
            }
            out = gw.from_client(msg)
            if out.decision != "forward":
                break
        assert out is not None
        decision, reasons = out.decision, out.reasons
    elif kind == "result":
        gw = _fresh_gateway(policy, lock, tools, True)
        call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": s["call"]}
        first = gw.from_client(call)
        if first.decision != "forward":
            raise ValueError(f"scenario {s['id']}: setup call was blocked: {first.reasons}")
        reply = {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": s["text"]}]}}
        out = gw.from_server(reply)
        decision, reasons = out.decision, out.reasons
    elif kind == "tool-definition":
        review = review_tools([s["tool"]], {})[0]
        if review.poisoned:
            decision = "filtered"
            reasons = sorted({f.rule for f in review.findings})
    elif kind == "rug-pull":
        gw = _fresh_gateway(policy, lock, [s["tool"]], True)
        if s["tool"]["name"] not in gw.visible_tools:
            decision = "filtered"
            reasons = [r for r in gw.audit.records if r["event"] == "tool.hidden"][0]["reason"].split("; ")
    return ScenarioResult(
        id=s["id"],
        category=s["category"],
        kind=kind,
        expect=s["expect"],
        detected=decision != "forward",
        decision=decision,
        reasons=reasons,
        known_gap=bool(s.get("known_gap", False)),
        known_false_positive=bool(s.get("known_false_positive", False)),
    )


def run(corpus: str | Path, policy_path: str | Path, lock_path: str | Path, tools_path: str | Path) -> Report:
    policy = load_policy(policy_path)
    lock = load_lock(lock_path)
    data = json.loads(Path(tools_path).read_text(encoding="utf-8"))
    tools = data.get("tools", data) if isinstance(data, dict) else data
    return Report([run_scenario(s, policy, lock, tools) for s in load_corpus(corpus)])
