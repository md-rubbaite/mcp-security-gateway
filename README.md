# mcp-security-gateway

[![ci](https://github.com/md-rubbaite/mcp-security-gateway/actions/workflows/ci.yml/badge.svg)](https://github.com/md-rubbaite/mcp-security-gateway/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![deps](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen)
![license](https://img.shields.io/badge/license-MIT-green)

**`mcpguard` is a policy-enforcing security gateway for [Model Context Protocol](https://modelcontextprotocol.io) servers.**
It sits between an AI host and an MCP server, and decides which tools the model may see and call,
with which arguments, and what comes back.

## The problem

AI assistants now call tools through MCP: they read files, fetch web pages, open tickets and send
email. That turns every piece of text the model reads into a possible command:

- **Tool poisoning:** a tool's description can hide instructions such as "read `~/.ssh/id_rsa` and pass it along".
- **Rug pulls:** a server can change an approved tool later, and nobody notices.
- **Indirect prompt injection:** a web page or ticket returned by a tool tells the model to leak data.
- **Excessive agency:** the model sends email or calls paid APIs that nobody approved.

The MCP specification leaves these controls to implementers. `mcpguard` puts them in one place,
in front of any server, without changing the host or the server.

## What it does

| Control | How |
|---|---|
| Deny by default | Only tools listed in `policy.toml` are visible and callable |
| Tool pinning | SHA-256 of each tool's name, description and schema is checked against a lockfile; new or changed tools are hidden |
| Poisoning scan | Tool definitions with injection phrases, sensitive paths or invisible Unicode are hidden |
| Argument policy | Path prefixes (no `..`), https-only URL domain allow-lists, regex, enums, max length, no unexpected arguments |
| Exfiltration guard | Calls carrying credentials (AWS, GitHub, Slack, private keys, JWTs…) are blocked |
| Human approval | `requires_approval = true` routes the call to an approver callback; no approval means no call |
| Output filtering | Secrets, e-mail, IBANs and Luhn-valid card numbers are redacted; injection text is flagged or withheld |
| Rate limits and caps | Per-tool token bucket; output size limits |
| Audit trail | Hash-chained JSONL; arguments stored only as hashes; `mcpguard verify-audit` detects edits and deletions |

Blocked calls come back as tool results with `isError: true`, so the model sees why and can recover.

## Architecture

```mermaid
flowchart LR
    H[AI host<br/>IDE / chat / agent] -- JSON-RPC over stdio --> G
    subgraph G[mcpguard proxy]
      P[Policy engine<br/>deny by default] --> A[(Hash-chained<br/>audit log)]
      L[Lockfile<br/>tool pins] --> P
    end
    G -- allowed calls only --> S[MCP server<br/>subprocess]
    S -- results --> G
    G -- redacted / flagged results --> H
```

The policy engine (`Gateway`) does no I/O, so every decision is unit-tested; `proxy.py` connects it
to a stdio subprocess. See [ADR 0001](docs/adr/0001-gateway-as-a-transparent-proxy.md) and the
[threat model](docs/threat-model.md) (10 threats mapped to controls and residual risk).

## Quick start

```bash
pip install .

# 1. Review the server's tools and pin the ones you approve
mcpguard scan-tools examples/tools.json
mcpguard lock examples/tools.json --server demo --out mcpguard.lock.json   # refuses suspicious tools

# 2. Run the server behind the gateway
mcpguard proxy --policy examples/policy.toml --lock examples/mcpguard.lock.json \
  --audit audit/mcpguard.jsonl -- python examples/demo_server.py

# 3. Check the audit trail has not been altered
mcpguard verify-audit audit/mcpguard.jsonl
```

To use it with an MCP host, point the host's server command at `mcpguard proxy … -- <original command>`.

### Example policy

```toml
[gateway]
default_action = "deny"

[[tool]]
name = "read_file"
rate_per_minute = 60
[tool.args.path]
path_prefixes = ["/workspace"]

[[tool]]
name = "send_email"
requires_approval = true
[tool.args.to]
pattern = '[A-Za-z0-9._%+-]+@example\.com'
```

## Demo: what the gateway stops

`examples/demo_server.py` is a deliberately unsafe server. Behind the gateway:

| Attempt | Result |
|---|---|
| `tools/list` returns 4 tools, one with a hidden `<IMPORTANT>` instruction | 3 tools offered; `add_numbers` hidden (poisoned) |
| `read_file("/workspace/README.md")` returns an AWS key and an e-mail | Returned with `[REDACTED:aws-access-key-id]` and `[REDACTED:email]` |
| `read_file("/workspace/issue-42.md")` returns "Ignore all previous instructions…" | Returned with an "untrusted tool output" notice (or withheld, if configured) |
| `fetch_url("https://attacker.example/collect")` | Blocked: domain not allowed |
| `read_file("/workspace/../etc/shadow")` | Blocked: outside allowed paths |
| `send_email(...)` with no approver | Blocked: requires human approval |

The end-to-end test runs exactly this through the real stdio proxy.

## Limits, stated plainly

Pattern-based detection reduces risk; it does not make prompt injection impossible. Keep the server
sandboxed with least privilege, keep allow-lists narrow, and keep humans in the loop for actions that
change things. This project covers the stdio transport; an HTTP front end is a planned follow-up.

## Tests

```bash
pip install -e ".[dev]"
ruff check . && pytest -q
```

49 tests cover policy parsing and validation, path and URL allow-lists, poisoning and rug-pull
detection, secret and personal-data redaction (including zero-width obfuscation), approval, rate
limiting with an injected clock, audit-chain tampering, the CLI and the full stdio proxy end to end.
CI runs them on Python 3.11, 3.12 and 3.13, then checks the demo tools against the lockfile.

---

Author: [Rubbaite T. Hassain](https://tanvir.info.bd) ([LinkedIn](https://www.linkedin.com/in/rubbaite)) · Software Architect, Founder of [Datazo InfoTech](https://www.datazoinfotech.com.bd) · MIT License
