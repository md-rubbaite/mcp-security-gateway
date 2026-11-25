"""Optional external policy decision point: Open Policy Agent (OPA) over its REST Data API.

The local TOML policy is always evaluated first. When `[gateway.opa]` is configured, a call that
passes every local check is also sent to OPA, and it is forwarded only if OPA allows it too. OPA can
add restrictions (organisation rules, cross-server rules, rules owned by a security team) but can
never allow something the local policy blocked. See docs/adr/0003-opa-as-an-additional-decision-point.md.

Failure handling is fail-closed by default: if OPA cannot be reached, answers late, or returns an
unexpected document, the call is blocked with a clear reason. `fail_open = true` exists for
non-production experiments and is logged on every use.

Uses only the standard library (urllib), so the core package keeps zero runtime dependencies.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass
class OpaDecision:
    allow: bool
    reasons: list[str] = field(default_factory=list)
    error: str | None = None  # set when OPA was not consulted successfully


@dataclass
class OpaConfig:
    url: str  # e.g. http://127.0.0.1:8181
    decision: str = "mcpguard/decision"  # data path of a rule returning {"allow": bool, "reasons": [str]}
    timeout_ms: int = 500
    fail_open: bool = False

    def endpoint(self) -> str:
        return self.url.rstrip("/") + "/v1/data/" + self.decision.strip("/")


def validate_config(raw: dict[str, Any]) -> OpaConfig:
    from .policy import PolicyError  # local import avoids a cycle

    unknown = set(raw) - {"url", "decision", "timeout_ms", "fail_open"}
    if unknown:
        raise PolicyError(f"gateway.opa: unknown keys {sorted(unknown)}")
    url = raw.get("url")
    if not isinstance(url, str):
        raise PolicyError("gateway.opa.url is required")
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise PolicyError("gateway.opa.url must be an http(s) URL")
    if u.scheme == "http" and u.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise PolicyError("gateway.opa.url must use https unless OPA runs on localhost (sidecar)")
    timeout = raw.get("timeout_ms", 500)
    if not isinstance(timeout, int) or not 10 <= timeout <= 10_000:
        raise PolicyError("gateway.opa.timeout_ms must be an integer between 10 and 10000")
    decision = raw.get("decision", "mcpguard/decision")
    if not isinstance(decision, str) or not decision.strip("/"):
        raise PolicyError("gateway.opa.decision must be a data path such as 'mcpguard/decision'")
    return OpaConfig(url=url, decision=decision, timeout_ms=timeout, fail_open=bool(raw.get("fail_open", False)))


class OpaClient:
    def __init__(self, config: OpaConfig, opener: Any = None):
        self.config = config
        self._open = opener or urllib.request.urlopen

    def decide(self, input_doc: dict[str, Any]) -> OpaDecision:
        body = json.dumps({"input": input_doc}).encode()
        req = urllib.request.Request(
            self.config.endpoint(), data=body, method="POST", headers={"Content-Type": "application/json"}
        )
        try:
            with self._open(req, timeout=self.config.timeout_ms / 1000) as resp:
                doc = json.loads(resp.read().decode())
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError) as e:
            return self._unavailable(f"OPA not reachable or invalid reply ({type(e).__name__})")
        result = doc.get("result") if isinstance(doc, dict) else None
        if result is None:
            return self._unavailable(f"OPA has no decision at '{self.config.decision}' (undefined)")
        if not isinstance(result, dict) or not isinstance(result.get("allow"), bool):
            return self._unavailable("OPA decision must be an object with a boolean 'allow'")
        reasons = result.get("reasons", [])
        if not isinstance(reasons, list) or not all(isinstance(r, str) for r in reasons):
            return self._unavailable("OPA decision 'reasons' must be a list of strings")
        return OpaDecision(allow=result["allow"], reasons=reasons)

    def _unavailable(self, why: str) -> OpaDecision:
        if self.config.fail_open:
            return OpaDecision(allow=True, reasons=[], error=why + "; fail_open=true, call allowed")
        return OpaDecision(allow=False, reasons=[f"policy decision point unavailable: {why}"], error=why)
