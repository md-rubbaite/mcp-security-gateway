# ADR 0003: Open Policy Agent as an additional, fail-closed decision point

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

The TOML policy is per server and owned by whoever deploys the gateway. Larger organisations want
rules that a security team owns centrally and reuses across servers and gateways ("nobody reads
`/secrets/`", "every email needs approval", "only the docs server may fetch URLs"), written in a
language they already use for Kubernetes admission and API authorisation. OPA with Rego is the most
common choice for that.

## Decision

1. `[gateway.opa]` in the policy file enables a call to OPA's Data API
   (`POST {url}/v1/data/{decision}`) for every `tools/call` that **passed all local checks**.
2. **OPA can only restrict.** The call is forwarded only if the local policy *and* OPA allow it. A
   call the local policy blocks is never sent to OPA, so OPA cannot widen access, and an OPA outage
   cannot open a hole.
3. **Fail closed.** Unreachable OPA, a late answer (`timeout_ms`, default 500), an undefined decision
   or a malformed document all block the call with a clear reason and an `opa.error` audit record.
   `fail_open = true` exists for experiments and is logged on every use.
4. **Input contract:** `{server, tool, arguments, requires_approval, approved}`. Arguments are sent in
   clear because Rego rules need them; OPA must therefore run as a local sidecar or over HTTPS
   (plain HTTP is accepted only for localhost). Credentials in arguments are already blocked locally
   before OPA is asked.
5. **Output contract:** `{"allow": bool, "reasons": [string]}`, so the model and the audit log see why.
6. The client uses only the standard library (urllib); no new runtime dependency.

## Alternatives considered

- **Embed a Rego evaluator in Python:** no mature, maintained pure-Python implementation; would also
  drift from the OPA the organisation runs. Rejected.
- **Replace the TOML policy with Rego entirely:** raises the entry barrier for small teams and loses
  the offline, dependency-free default. Rejected; both coexist.
- **Let OPA override local denials:** would make a central mistake able to open every gateway. Rejected.

## Consequences

Each allowed call costs one local HTTP round trip (sub-millisecond to a few milliseconds with a
sidecar). Rules ship with unit tests (`policy/mcpguard_test.rego`, run by `opa test` in CI) and a live
integration test runs the gateway against a real OPA server in CI.
