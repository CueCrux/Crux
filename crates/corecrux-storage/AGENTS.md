# corecrux-storage — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Append-only shard storage engine. Events are hash-partitioned across shards, written to
active segments, and sealed when full; each shard keeps its own directory, manifest, and
commit markers (`CCMT`) for crash recovery. Provides append with backpressure,
deterministic replay, and integrity verification.

## Key symbols
- `ShardStorage::append_batch` / `append_batch_with_stats` — the append/seal path (`append.rs`)
- `SegmentSealMaterialV1` — signable seal material; `signing_bytes()` is a fixed
  domain-tagged big-endian layout (signed by `corecruxd`'s `sign_segment_seal_material`)
- `verify_segment_hashes_all` — strict BLAKE3 walk of sealed segments (`integrity.rs`;
  backs `corecruxctl verify-store --strict`)
- `integrity_scan_stats_all` — budgeted replay/integrity scan
- `StorageError` — error taxonomy mapped to `CORE_ERROR_*` codes in `corecrux-types`

## Invariants
- Establishes I2 (segment chain): the seal path populates `previous_segment_seq` /
  `previous_segment_hash` linking each seal to the highest-seq prior segment in the shard;
  first segment links to `None`. Checked by the `verify-store --strict` chain walk and
  `tests.rs::append_batch_seal_receipt_links_previous_segment_hash`.
- Checks I1: `verify_segment_hashes_all` re-derives the segment-hash binding
  established in `corecrux-segment`.

## Test & verify
- `cargo test -p corecrux-storage` (tests live in `src/tests.rs`)
- Workspace fuzz target: `fuzz/fuzz_targets/storage_scan_frames.rs`
- Manual end-to-end: `corecruxctl verify-store --strict` against a real store dir

## Local rules
- Never mutate a sealed segment or its manifest entry — sealing is one-way; repairs go
  through new segments/manifest records, never in-place edits.
- `SegmentSealMaterialV1::signing_bytes()` is a signed wire format — any field or
  ordering change breaks every existing seal receipt. Treat as frozen; new material = new version.
- Don't break the previous-link chain: anything that reorders, drops, or renumbers
  segments within a shard violates I2.
- Manifest (`CCMF`) and dir-run (`CCDR`) layouts are versioned on-disk formats with CRCs —
  same rule as segment layouts: version bump, not field surgery.
