"""Gateway + a real OPA server running policy/mcpguard.rego. Runs in CI; skipped when MCPGUARD_OPA_URL is not set.

opa run --server --addr 127.0.0.1:8181 policy/mcpguard.rego &
MCPGUARD_OPA_URL=http://127.0.0.1:8181 pytest tests/test_opa_live.py
"""

from __future__ import annotations

import os

import pytest

from mcpguard.gateway import Gateway
from mcpguard.policy import parse_policy

URL = os.environ.get("MCPGUARD_OPA_URL")
pytestmark = pytest.mark.skipif(not URL, reason="MCPGUARD_OPA_URL not set (needs a running OPA)")


def _gw(approve: bool, server: str = "demo") -> Gateway:
    policy = parse_policy(
        {
            "gateway": {"server_name": server, "block_unpinned_tools": False, "opa": {"url": URL, "timeout_ms": 2000}},
            "tool": [
                {"name": "read_file", "args": {"path": {"path_prefixes": ["/workspace"]}}},
                {"name": "fetch_url"},
                {"name": "send_email", "requires_approval": True},
            ],
        }
    )
    gw = Gateway(policy, approver=lambda _n, _a: approve)
    gw.from_client({"jsonrpc": "2.0", "id": "l", "method": "tools/list"})
    tools = [{"name": n} for n in ("read_file", "fetch_url", "send_email")]
    gw.from_server({"jsonrpc": "2.0", "id": "l", "result": {"tools": tools}})
    return gw


def _call(gw: Gateway, name: str, args: dict):
    return gw.from_client(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}
    )


def test_real_opa_allows_ordinary_reads():
    assert _call(_gw(False), "read_file", {"path": "/workspace/README.md"}).decision == "forward"


def test_real_opa_blocks_secrets_folder_that_local_policy_allows():
    out = _call(_gw(False), "read_file", {"path": "/workspace/secrets/prod.env"})
    assert out.decision == "block"
    assert out.reasons == ["reading files under /workspace/secrets/ is not allowed"]


def test_real_opa_blocks_long_approved_email():
    out = _call(_gw(True), "send_email", {"to": "a@example.com", "subject": "s", "body": "x" * 2001})
    assert out.decision == "block" and out.reasons == ["email body is longer than 2000 characters"]


def test_real_opa_server_scoped_rule():
    assert _call(_gw(False, server="crm"), "fetch_url", {"url": "https://docs.python.org/"}).decision == "block"
    assert _call(_gw(False, server="docs"), "fetch_url", {"url": "https://docs.python.org/"}).decision == "forward"
