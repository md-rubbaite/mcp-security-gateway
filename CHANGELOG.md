# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-11-25

### Added
- **Signed audit records:** `mcpguard keygen`, `proxy --sign-key`; every record carries `kid` and an Ed25519 `sig`.
- **Signed checkpoints:** `mcpguard checkpoint`; `verify-audit --pubkey --require-signatures --checkpoint` detects rewrites and truncation ([ADR 0002](docs/adr/0002-signed-audit-records-and-checkpoints.md)).
- **Open Policy Agent as an extra decision point:** `[gateway.opa]`, restrict-only, fail-closed ([ADR 0003](docs/adr/0003-opa-as-an-additional-decision-point.md)).
  - Example Rego policy with unit tests in `policy/`.
  - A live OPA integration test in CI.
- **Attack simulation:** `mcpguard attack-sim` replays `examples/attack-corpus.json`, with 49 scenarios.
  - Reports the detection and false-positive rates, including known gaps.
  - CI fails on any regression ([ADR 0004](docs/adr/0004-measure-detection-with-an-attack-corpus.md)).
- **Optional OpenTelemetry spans:** `mcpguard tools/call` etc., with `gen_ai.tool.name` and `mcpguard.decision`. Spans never include argument values or tool output.
- **Optional extras:** `mcpguard[signing]` and `mcpguard[otel]`. The core still has zero runtime dependencies, and a CI job proves it.
- **Threat model:** new threats T11 (central policy unavailable), T12 (signing key theft) and T13 (detection drift). The T9 residual risk is updated.

### Changed
- GitHub Actions are pinned to full commit SHAs.
- `verify-audit` also reports how many signatures it verified.

### Compatibility
- Unsigned v1.0 logs verify exactly as before. The `sig` field is excluded from the record hash, so signing does not change the chain format.

## [1.0.0] - 2026-11-22

### Added
- Deny-by-default stdio MCP proxy with tool pinning, poisoning scan, argument policy, secret and PII filtering.
- Human approval hook, rate limits, and a hash-chained audit log.
