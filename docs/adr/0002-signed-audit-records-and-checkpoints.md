# ADR 0002: Sign audit records with Ed25519 and export signed checkpoints

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

Since v1.0 the audit log is a SHA-256 hash chain. It detects edits, deletions and reordering, but the
threat model listed a residual risk (T9): anyone who can write the file can rebuild the whole chain
from the first line, and a truncated chain is still a valid chain. For incident response and for
regulated users (EU AI Act record keeping, ISO 27001 logging controls) the log has to show who wrote it
and that nothing was removed.

## Decision

1. **Per-record signatures.** With `--sign-key`, every record gets `kid` (key id, part of the hashed
   body) and `sig` (Ed25519 signature over the record hash, not part of the hash). `verify-audit
   --pubkey` checks both chain and signatures; `--require-signatures` rejects unsigned records.
2. **Signed checkpoints.** `mcpguard checkpoint` signs `{log, count, head, ts, kid}`. Checkpoints are
   meant to be copied to storage the gateway host cannot change (object storage with retention lock,
   a SIEM, a separate account). `verify-audit --checkpoint` proves the log still contains that prefix
   unchanged, which also detects truncation.
3. **Ed25519 via `cryptography`, as an optional extra** (`mcpguard[signing]`). The core keeps zero
   runtime dependencies; signing fails with a clear message if the extra is missing.

## What this protects, and what it does not

| Attacker | Hash chain (v1.0) | + record signatures | + checkpoint stored elsewhere |
|---|---|---|---|
| Can edit the log, cannot read the key | Detects edits, not a full rewrite or truncation | Detects all edits and rewrites | Also detects truncation |
| Has the gateway host and its key | Not detected | Not detected | History up to the last exported checkpoint stays provable |
| Controls the gateway from now on | Can write false records | Can write false records | Can write false records |

No log design prevents a compromised writer from lying about the future; the goal is that the past
cannot be changed silently.

## Alternatives considered

- **HMAC with a shared key:** simpler, but verifiers would hold the same secret as the writer and could
  forge records. Rejected.
- **RFC 3161 timestamps or a transparency log (for example Sigstore Rekor) per record:** stronger
  external anchoring, but adds a network dependency to every tool call. A good fit for checkpoints, not
  for records; left as a follow-up.
- **ML-DSA (post-quantum) signatures:** audit records are short-lived evidence and checkpoints can be
  re-signed; Ed25519 is the mature, widely supported choice today. Revisit with library support.

## Consequences

Key handling becomes an operational task: generate the key with `mcpguard keygen` (written with mode
0600, never overwritten), keep it readable only by the gateway user, and rotate by starting a new log
with a new key. Old logs stay verifiable with their old public key (`kid` tells them apart).
