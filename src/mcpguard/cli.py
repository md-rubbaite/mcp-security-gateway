"""Command line: proxy | lock | scan-tools | verify-audit."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .audit import AuditLog, verify
from .gateway import Gateway
from .pinning import load_lock, review_tools, write_lock
from .policy import PolicyError, load_policy
from .proxy import run_stdio_proxy


def _load_tools(path: str) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("result", data).get("tools", [])
    return data


def cmd_scan(a: argparse.Namespace) -> int:
    reviews = review_tools(_load_tools(a.tools), load_lock(a.lock))
    worst = 0
    for r in reviews:
        flags = ", ".join(sorted({f.rule for f in r.findings})) or "-"
        print(f"{r.name:<28} {r.status:<8} {flags}")
        if r.poisoned:
            worst = 1
        elif r.status != "pinned" and a.lock:
            worst = max(worst, 1)
    print(f"\n{len(reviews)} tools, {sum(r.poisoned for r in reviews)} suspicious")
    return worst


def cmd_lock(a: argparse.Namespace) -> int:
    tools = _load_tools(a.tools)
    poisoned = [r.name for r in review_tools(tools, {}) if r.poisoned]
    if poisoned and not a.force:
        print(f"refusing to pin suspicious tools: {poisoned} (review them, or pass --force)", file=sys.stderr)
        return 1
    pins = write_lock(a.out, tools, a.server)
    print(f"pinned {len(pins)} tools to {a.out}")
    return 0


def cmd_verify(a: argparse.Namespace) -> int:
    ok, n, message = verify(a.log)
    print(message)
    return 0 if ok else 1


def cmd_proxy(a: argparse.Namespace) -> int:
    if not a.command:
        print("usage: mcpguard proxy --policy P [--lock L] -- <server command>", file=sys.stderr)
        return 2
    policy = load_policy(a.policy)
    gw = Gateway(policy, lock=load_lock(a.lock), audit=AuditLog(a.audit))
    return run_stdio_proxy(gw, a.command)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="mcpguard", description="Security gateway for MCP servers")
    p.add_argument("--version", action="version", version=f"mcpguard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan-tools", help="review a tools/list response for poisoning and drift")
    s.add_argument("tools")
    s.add_argument("--lock")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("lock", help="pin approved tool definitions")
    s.add_argument("tools")
    s.add_argument("--out", default="mcpguard.lock.json")
    s.add_argument("--server", default="default")
    s.add_argument("--force", action="store_true")
    s.set_defaults(fn=cmd_lock)

    s = sub.add_parser("verify-audit", help="check the audit log hash chain")
    s.add_argument("log")
    s.set_defaults(fn=cmd_verify)

    s = sub.add_parser("proxy", help="run an MCP server behind the gateway (stdio)")
    s.add_argument("--policy", required=True)
    s.add_argument("--lock")
    s.add_argument("--audit", default="audit/mcpguard.jsonl")
    s.add_argument("command", nargs=argparse.REMAINDER)
    s.set_defaults(fn=cmd_proxy)

    a = p.parse_args(argv)
    if getattr(a, "command", None) and a.command[:1] == ["--"]:
        a.command = a.command[1:]
    try:
        return a.fn(a)
    except (PolicyError, FileNotFoundError, json.JSONDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
