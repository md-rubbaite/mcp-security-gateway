"""Policy model, loaded from TOML. Deny by default: a tool that is not listed cannot be called."""

from __future__ import annotations

import fnmatch
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlparse

from .opa import OpaConfig, validate_config


class PolicyError(ValueError):
    pass


@dataclass
class ArgRule:
    max_length: int | None = None
    pattern: re.Pattern[str] | None = None
    allowed_values: list[Any] | None = None
    path_prefixes: list[str] | None = None
    url_domains: list[str] | None = None

    def check(self, name: str, value: Any) -> str | None:
        """Return a reason string if the value violates the rule, else None."""
        if self.allowed_values is not None and value not in self.allowed_values:
            return f"argument '{name}' must be one of {self.allowed_values}"
        if not isinstance(value, str):
            if any(x is not None for x in (self.max_length, self.pattern, self.path_prefixes, self.url_domains)):
                return f"argument '{name}' must be a string"
            return None
        if self.max_length is not None and len(value) > self.max_length:
            return f"argument '{name}' exceeds {self.max_length} characters"
        if self.pattern is not None and not self.pattern.fullmatch(value):
            return f"argument '{name}' does not match the allowed pattern"
        if self.path_prefixes is not None and not _path_allowed(value, self.path_prefixes):
            return f"argument '{name}' is outside the allowed paths"
        if self.url_domains is not None and not _url_allowed(value, self.url_domains):
            return f"argument '{name}' points to a domain that is not allowed"
        return None


def _path_allowed(raw: str, prefixes: list[str]) -> bool:
    if "\x00" in raw:
        return False
    p = PurePosixPath(raw)
    if not p.is_absolute() or ".." in p.parts:
        return False
    return any(p == PurePosixPath(pre) or PurePosixPath(pre) in p.parents for pre in prefixes)


def _url_allowed(raw: str, domains: list[str]) -> bool:
    u = urlparse(raw)
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        return False
    host = u.hostname.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in (d.lower() for d in domains))


@dataclass
class ToolPolicy:
    name: str
    allow: bool = True
    requires_approval: bool = False
    rate_per_minute: int | None = None
    max_result_chars: int | None = None
    args: dict[str, ArgRule] = field(default_factory=dict)
    allow_unknown_args: bool = False


@dataclass
class Policy:
    server_name: str = "default"
    default_action: str = "deny"  # deny | allow
    block_secrets_in_args: bool = True
    redact_secrets_in_results: bool = True
    redact_pii_in_results: bool = True
    block_injection_in_results: bool = False  # False = wrap & flag, True = replace result with an error
    block_unpinned_tools: bool = True
    block_poisoned_tools: bool = True
    tools: list[ToolPolicy] = field(default_factory=list)
    opa: OpaConfig | None = None  # optional external decision point (v1.1)

    def tool(self, name: str) -> ToolPolicy | None:
        exact = [t for t in self.tools if t.name == name]
        if exact:
            return exact[0]
        globbed = [t for t in self.tools if any(ch in t.name for ch in "*?[") and fnmatch.fnmatchcase(name, t.name)]
        return globbed[0] if globbed else None


def _arg_rule(name: str, raw: dict[str, Any]) -> ArgRule:
    known = {"max_length", "pattern", "allowed_values", "path_prefixes", "url_domains"}
    unknown = set(raw) - known
    if unknown:
        raise PolicyError(f"argument rule '{name}': unknown keys {sorted(unknown)}")
    pattern = None
    if "pattern" in raw:
        try:
            pattern = re.compile(raw["pattern"])
        except re.error as e:
            raise PolicyError(f"argument rule '{name}': invalid pattern: {e}") from e
    return ArgRule(
        max_length=raw.get("max_length"),
        pattern=pattern,
        allowed_values=raw.get("allowed_values"),
        path_prefixes=raw.get("path_prefixes"),
        url_domains=raw.get("url_domains"),
    )


def parse_policy(data: dict[str, Any]) -> Policy:
    g = data.get("gateway", {})
    if g.get("default_action", "deny") not in ("deny", "allow"):
        raise PolicyError("gateway.default_action must be 'deny' or 'allow'")
    pol = Policy(
        server_name=g.get("server_name", "default"),
        default_action=g.get("default_action", "deny"),
        block_secrets_in_args=g.get("block_secrets_in_args", True),
        redact_secrets_in_results=g.get("redact_secrets_in_results", True),
        redact_pii_in_results=g.get("redact_pii_in_results", True),
        block_injection_in_results=g.get("block_injection_in_results", False),
        block_unpinned_tools=g.get("block_unpinned_tools", True),
        block_poisoned_tools=g.get("block_poisoned_tools", True),
        opa=validate_config(g["opa"]) if "opa" in g else None,
    )
    for raw in data.get("tool", []):
        if "name" not in raw:
            raise PolicyError("every [[tool]] needs a name")
        rate = raw.get("rate_per_minute")
        if rate is not None and (not isinstance(rate, int) or rate <= 0):
            raise PolicyError(f"tool '{raw['name']}': rate_per_minute must be a positive integer")
        pol.tools.append(
            ToolPolicy(
                name=raw["name"],
                allow=raw.get("allow", True),
                requires_approval=raw.get("requires_approval", False),
                rate_per_minute=rate,
                max_result_chars=raw.get("max_result_chars"),
                allow_unknown_args=raw.get("allow_unknown_args", False),
                args={k: _arg_rule(k, v) for k, v in raw.get("args", {}).items()},
            )
        )
    return pol


def load_policy(path: str | Path) -> Policy:
    with open(path, "rb") as f:
        return parse_policy(tomllib.load(f))
