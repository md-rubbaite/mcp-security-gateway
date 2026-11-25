# ADR 0004: Measure detection with a versioned attack corpus that records known gaps

- **Status:** Accepted
- **Date:** 2026-11-25

## Context

Security tools often claim to "prevent prompt injection" without numbers. Pattern-based detectors
will always miss some attacks and wrongly flag some benign text. Users deserve to know both rates,
and maintainers need a test that fails when a change weakens a control.

## Decision

1. `examples/attack-corpus.json` holds attack scenarios (mapped to the OWASP Top 10 for LLM
   Applications 2025 and MCP-specific threats) and benign traffic. `mcpguard attack-sim` replays them
   through the real `Gateway` with the example policy and lockfile.
2. Attacks the gateway does not catch stay in the corpus with `known_gap: true`; benign text it
   wrongly flags stays with `known_false_positive: true`. They count in the published rates.
3. Two outputs: honest rates over everything, and a regression gate that CI enforces (every attack
   not marked as a gap is detected; every benign case not marked as a false positive passes). A test
   also fails if a known gap starts being detected, so the labels cannot go stale.
4. The harness measures the gateway's own controls. OPA rules are measured separately with `opa test`.

## Limits of this evidence

The corpus was written by the same author as the detectors, so it is not an independent evaluation;
the rates describe this corpus, not attacks in general. Contributions of new attack cases, especially
ones that are missed, are the most useful way to improve it.
