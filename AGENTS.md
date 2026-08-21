# AGENTS.md

Crux is a local-first retrieval and memory engine whose storage and receipts are
cryptographically tamper-evident. Every receipt-bearing operation produces a signed,
replayable CROWN receipt; sealed segments (`.ccxseg`) are BLAKE3 hash-chained and
independently verifiable offline.

This file is an **index**, not the content. The detail lives in `docs/agent/`. Start here,
then follow the reading order. Everything is anchored by symbol name (greppable) and
CI-verified, so you can trust the references — but verify the claims yourself (below).

## Reading order (start here)

1. `docs/agent/CODEMAP.md` — what each of the 28 crates owns + key symbols.
2. `docs/agent/CLAIMS.md` — each product claim mapped to the code and the **test** that proves it.
3. `docs/agent/INVARIANTS.md` — the cryptographic + data guarantees (I1–I6) and where they hold.
4. `docs/THREAT_MODEL.md` — trust boundaries and stated limitations.
5. `docs/spec/receipt-v1.md` — the on-the-wire receipt format.

Machine-readable index (parse this, no NL needed): `docs/agent/repo-manifest.yaml`.
Link map: `/llms.txt`. Vocabulary (CROWN, CCXI, CRC-v1, cruxpack, lane, passport):
`docs/agent/GLOSSARY.md`.

**Live code map (dogfood).** A running daemon can serve this repo's AST-derived structure
back to you: register the checkout (`POST /v1/repos` with `root_path`), then
`GET /v1/repos/{id}/codemap?tenant_id=…&format=summary|full` — same scanner as
`/console/codegraph`. The curated CODEMAP.md is the reading order; the endpoint is ground
truth. Per-crate context lives in `crates/<name>/AGENTS.md` (nearest file wins).

**Building against the daemon instead of modifying it?** Different docs: connect via MCP and
read `docs/agent-guide.md` (budgets, sessions, handoffs) and `docs/mcp-system-prompt.md`
(the full tool surface); HTTP/SDK integration starts at `docs/developer-portal.md`.

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

- MSRV: **1.88.0** (`rust-toolchain.toml`); edition 2021; workspace version 0.5.63
  (`[workspace.package]` in `Cargo.toml` is authoritative, and
  `scripts/check-agent-docs.sh` fails the build when this line disagrees with it).
- `cargo build --workspace --locked`
- `cargo test --workspace`
- `cargo fmt --check` and `cargo clippy --workspace -- -D warnings` (both CI-gated)
- CI: `.github/workflows/ci.yml` (lint + test + msrv + coverage), `fuzz.yml` (scheduled),
  `agent-docs.yml` (this doc set's symbol/test existence check).

## Boundaries

**Always:** anchor doc references by symbol name; keep the Apache-2.0 licence header on every `.rs`
file (`grep -rL "Licensed under" crates/**/*.rs` must return nothing); test and lint before
committing.

**Ask first:** changing any default port (HTTP `14800`, gRPC `4007`, MCP `14801`); changing
receipt formats, seal material, or anything under `crates/corecrux-receipts/`,
`-segment/`, `-storage/` that an invariant (I1–I6) names; adding a new on-disk artifact type
(update all three wiring points: storage allowlist, projection registry, load-at-startup);
instrumenting a new `crux.outcome` site — the set is curated, and the admission bar plus the
two ways to get it silently wrong are in `docs/agent/outcome-instrumentation.md`.

**Never:** GPU/CUDA code, `--features cuda`, or GPU readiness checks (this repo is CPU-only —
ADR 003); references to proprietary crates (`corecrux-analytics`, `corecrux-decision`,
`corecrux-coordinator` do not exist here); line-number anchors in agent docs; deleting live
shard data by hand.

## Maintenance contract

`docs/agent/repo-manifest.yaml` → `ci_assertions` is the canonical list of every symbol,
test, crate, and fuzz target these docs reference. `scripts/check-agent-docs.sh` greps the
tree for each on every PR; a rename that orphans a reference fails the build. Anchor new
references by **symbol name, never line number**, and add them to `ci_assertions`.

The same gate also enforces: every local `llms.txt` link resolves; every crate ships a
nested `AGENTS.md` (≤60 lines); `llms-full.txt` matches its generator
(`scripts/build-llms-full.sh --check`); and, in CI (`--exec`), the cheap documented
commands actually run. Editing any doc linked from `llms.txt` requires regenerating
`llms-full.txt`.
