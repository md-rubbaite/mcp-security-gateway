"""Tool pinning: detect 'rug pulls' where a server silently changes a tool after it was approved.

A tool's fingerprint covers its name, description and input schema (canonical JSON, SHA-256).
The lockfile records approved fingerprints; anything new or changed is reported.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .detectors import Finding, find_hidden_text, find_injection, iter_strings


def fingerprint(tool: dict[str, Any]) -> str:
    material = {
        "name": tool.get("name"),
        "description": tool.get("description", ""),
        "inputSchema": tool.get("inputSchema", {}),
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class ToolReview:
    name: str
    status: str  # pinned | new | changed
    findings: list[Finding]

    @property
    def poisoned(self) -> bool:
        return bool(self.findings)


def scan_tool(tool: dict[str, Any]) -> list[Finding]:
    """Look for injection text and hidden characters anywhere in the tool definition."""
    findings: list[Finding] = []
    for s in iter_strings({"d": tool.get("description", ""), "s": tool.get("inputSchema", {})}):
        findings += find_injection(s)
        findings += find_hidden_text(s)
    return findings


def review_tools(tools: list[dict[str, Any]], lock: dict[str, str]) -> list[ToolReview]:
    out = []
    for t in tools:
        name = str(t.get("name", ""))
        fp = fingerprint(t)
        if name not in lock:
            status = "new"
        elif lock[name] != fp:
            status = "changed"
        else:
            status = "pinned"
        out.append(ToolReview(name, status, scan_tool(t)))
    return out


def load_lock(path: str | Path | None) -> dict[str, str]:
    if path is None or not Path(path).exists():
        return {}
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {k: v for k, v in data.get("tools", {}).items()}


def write_lock(path: str | Path, tools: list[dict[str, Any]], server_name: str) -> dict[str, str]:
    pins = {str(t["name"]): fingerprint(t) for t in tools}
    doc = {"version": 1, "server": server_name, "tools": dict(sorted(pins.items()))}
    Path(path).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return pins
