# ADR 0001: Enforce MCP policy in a transparent proxy, deny by default

- **Status:** Accepted
- **Date:** 2026-11-22

## Context

Teams are connecting AI assistants to internal systems through MCP servers, many of them third-party.
Each host (IDE, chat app, agent runtime) has its own and often limited controls, and the servers can
change after they are approved. Security teams need one place to say which tools may run, with which
arguments, and to keep a record of what happened, without modifying every host or server.

## Decision

1. Run the controls in a separate process that speaks MCP on both sides. For stdio, the host launches
   `mcpguard proxy -- <server command>` instead of the server; neither side needs code changes.
2. Keep the policy engine (`Gateway`) free of I/O so it can be unit-tested and reused for other
   transports (for example an HTTP reverse proxy) later.
3. Deny by default. A tool is visible and callable only if the policy allows it, its definition matches
   the lockfile, and the definition is not suspicious.
4. Report blocked calls as tool results with `isError: true`, as the MCP spec recommends for tool
   failures, so the model sees the reason and can recover instead of retrying blindly.
5. Never write raw arguments to the audit log; store a SHA-256 of them so the log cannot leak secrets.
6. No third-party runtime dependencies (stdlib only: `tomllib`, `json`, `hashlib`), which keeps the
   supply-chain surface of a security component small.

## Consequences

- Positive: drop-in for existing hosts; policy reviewed as code; deterministic behaviour that is easy to
  test; tamper-evident evidence for incident response.
- Negative: pattern-based detection will miss novel injections, so it complements but does not replace
  sandboxing and human approval. A proxy adds one hop of latency (sub-millisecond for typical messages).
- Follow-up: an HTTP (Streamable HTTP) front end, and optional signing of the lockfile.
