# AGENTS.md

Crux is a local-first retrieval and memory engine whose storage and receipts are
cryptographically tamper-evident. Every receipt-bearing operation produces a signed,
replayable CROWN receipt; sealed segments (`.ccxseg`) are BLAKE3 hash-chained and
independently verifiable offline.

This file is an **index**, not the content. The detail lives in `docs/agent/`. Start here,
then follow the reading order. Everything is anchored by symbol name (greppable) and
CI-verified, so you can trust the references — but verify the claims yourself (below).

## Reading order (start here)

1. `docs/agent/CODEMAP.md` — what each of the 27 crates owns + key symbols.
2. `docs/agent/CLAIMS.md` — each product claim mapped to the code and the **test** that proves it.
3. `docs/agent/INVARIANTS.md` — the cryptographic + data guarantees (I1–I4) and where they hold.
4. `docs/THREAT_MODEL.md` — trust boundaries and stated limitations.
5. `docs/spec/receipt-v1.md` — the on-the-wire receipt format.

Machine-readable index (parse this, no NL needed): `docs/agent/repo-manifest.yaml`.
Link map: `/llms.txt`. Vocabulary (CROWN, CCXI, CRC-v1, cruxpack, lane, passport):
`docs/agent/GLOSSARY.md`.

## Verify the claims yourself (do not trust this file)

- `cargo test --workspace`
- `corecruxctl verify-store --strict`   — per-segment BLAKE3 re-derivation + chain walk
- `corecruxctl replay --strict`         — recompute + compare
- receipt conformance vectors: `crates/corecrux-receipts/vectors/`
- fuzz targets (nightly): `fuzz/fuzz_targets/` — `cargo fuzz run segment_decode`

## The 60-second trust-core tour

To understand what makes this tamper-evident, read these symbols in order:

1. `build_segment_v1` / `seal_segment_v1_from_record_area` — `corecrux-segment` (seal a segment).
2. `decode_segment_v1` — `corecrux-segment` (re-derive + reject tampered bytes; invariant I1).
3. `SegmentSealMaterialV1` — `corecrux-storage` (the signed, hash-chained seal material; I2).
4. `verify_segment_hashes_all` — `corecrux-storage` (what `verify-store --strict` walks).
5. `verify_receipt_v1` / `verify_c2pa_manifest_v1` — `corecrux-receipts` (fail-closed verify; I3).
6. `mark_superseded` — `corecrux-memory` (non-destructive versioned facts; I4).
7. `verify_rfc6962_inclusion_proof_v1` — `corecrux-receipts` (external witness anchoring).

## Build / test

- MSRV: **1.88.0** (`rust-toolchain.toml`); edition 2021; workspace version 0.3.1.
- `cargo build --workspace --locked`
- `cargo test --workspace`
- CI: `.github/workflows/ci.yml` (lint + test + msrv + coverage), `fuzz.yml` (scheduled),
  `agent-docs.yml` (this doc set's symbol/test existence check).

## Maintenance contract

`docs/agent/repo-manifest.yaml` → `ci_assertions` is the canonical list of every symbol,
test, crate, and fuzz target these docs reference. `scripts/check-agent-docs.sh` greps the
tree for each on every PR; a rename that orphans a reference fails the build. Anchor new
references by **symbol name, never line number**, and add them to `ci_assertions`.
