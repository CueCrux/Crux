# ADR-002: CROWN Receipts for Receipt-Bearing Operations

**Status:** Accepted
**Date:** 2026-04-01

## Context

In retrieval-augmented systems, users need assurance that query results are authentic and complete. Without receipts, a compromised intermediary could silently omit results or forge responses. We needed a mechanism that provides non-repudiable proof of every operation without requiring a trusted third party at query time.

## Decision

Receipt-bearing operations produce a **CROWN receipt**: an Ed25519-signed envelope containing:
- The operation's BLAKE3 content hash
- A chain hash linking to the previous receipt (forming an ordered sequence)
- A timestamp and operation metadata
- The signer's key ID

AppendBatch also returns write-confirmation material, and when an append seals a segment it includes
a segment-seal receipt signed over the segment hash plus previous sealed segment hash. These response
receipts are not the same as stored CROWN receipt streams.
Receipts are stored alongside events and are independently verifiable via `corecruxctl receipts verify`
or the `/v1/receipts/{id}/verification` API endpoint.

The name "CROWN" stands for **C**ryptographic **R**eceipt for **O**peration **W**ith **N**on-repudiation.

## Consequences

- Receipt-bearing writes have signing overhead (~50us for Ed25519). Acceptable for our throughput targets.
- The receipt chain is append-only. Gap detection is trivial: any missing sequence number indicates tampering or data loss.
- Key management is the operator's responsibility. The signing key lives in daemon memory; compromise exposes future signing capability but does not retroactively invalidate existing receipts.
- Receipt export (TAR/ZST bundles) enables offline audit without access to the live daemon.
