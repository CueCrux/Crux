# corecrux-frame — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Canonical v1 frame encoding for CoreCrux on-disk data: the v3 event-header layout, the
deterministic canonical-header byte encoding used for receipt signing, and the hash
helpers consumed by `corecrux-segment`, `corecrux-storage`, and replay/receipt machinery.
Pure types + bit-level layout; no I/O. Tiny crate (~0.3k lines), huge blast radius.

## Key symbols
- `canonical_header_bytes_v1` — deterministic byte encoding of a header (`CANONICAL_HEADER_V1_TAG`)
- `decode_canonical_header_bytes_v1` — inverse; errors via `DecodeHeaderError`
- `compute_header_hash` / `compute_payload_hash` — BLAKE3 over canonical bytes / payload
- `EventHeaderV3` — per-event header (tenant, stream, seq, hashes)
- `stream_hash_xxhash64` — stream-partitioning hash (must match `SHARDMAP_HASH_FN_V1`)

## Invariants
- Feeds I1: `header_hash = blake3(canonical header bytes)` is one of the three inputs to
  `segment_hash`. This crate defines what "canonical header bytes" means.

## Test & verify
- `cargo test -p corecrux-frame` (tests in `src/v3.rs`)
- Downstream proof: `corecrux-segment` decode tests and `verify-store --strict` fail if
  canonical bytes drift.

## Local rules
- Everything here is a hash input, so it must be byte-stable: never change field order,
  widths, endianness, or the encoding of `canonical_header_bytes_v1`. Any change silently
  invalidates every existing segment hash and seal receipt.
- A new layout is a new tagged version (new `CANONICAL_HEADER_*_TAG` + new fns), never an
  edit to the v1 encoder/decoder pair.
- Keep the crate pure — no I/O, no new heavyweight deps; nearly every crate in the
  workspace sits downstream.
