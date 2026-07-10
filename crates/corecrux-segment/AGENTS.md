# corecrux-segment — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Sealed segment format (`.ccxseg`, magic `CCS3`). An active segment accepts appended
frames; once sealed, a TOC is written, a BLAKE3 hash covers the file, and the segment
is immutable. Pure format code — building, sealing, decoding — no shard/store logic
(that lives in `corecrux-storage`).

## Key symbols
- `build_segment_v1` — build a full segment from frame inputs (mirror of the seal path)
- `seal_segment_v1_from_record_area` — seal an existing record area; computes `segment_hash`
- `decode_segment_v1` — decode + re-verify all hashes; errors via `SegmentError`
- `SegmentFooterV1` / `SegmentHeaderV1` / `TocEntryV1` — fixed-length on-disk layouts
- `decode_trailer_index_v1` — Phase 5 trailer sections (`BLK1`/`TBO1`/`TSI1`: block meta, TOC-by-offset, blooms)
- `encode_frame_v1` / `decode_frame_v1` — `CRX1` frame wrapper around `corecrux-frame` headers

## Invariants
- Establishes I1: `segment_hash = BLAKE3(header_hash ‖ record_hash ‖ toc_payload_hash)` —
  written in `sealer.rs` / `builder.rs`, re-derived and checked in `decoder.rs`
  (`SegmentError::CrcMismatch` / `HashMismatch` on divergence).

## Test & verify
- `cargo test -p corecrux-segment`
- Workspace fuzz target: `fuzz/fuzz_targets/segment_decode.rs` (decoder hardening).
- End-to-end hash check also runs via `corecrux-storage`'s `verify_segment_hashes_all`
  (`corecruxctl verify-store --strict`).

## Local rules
- Footer/header/TOC layouts are fixed-length wire formats (`SEGMENT_HEADER_LEN` 4096,
  `SEGMENT_FOOTER_LEN` 256, `TOC_ENTRY_LEN` 64). Never reorder or resize fields in place —
  a layout change is a new version (`SEGMENT_MAJOR`/`SEGMENT_MINOR` bump), not an edit.
- Never change the I1 concatenation order (header → record → toc_payload); sealer,
  builder, decoder, and `corecrux-storage/src/integrity.rs` must all agree.
- TOC entries must stay sorted by `(stream_hash, seq)` — decoder rejects with `TocNotSorted`.
- Sealed segments are immutable by contract; do not add any post-seal mutation API.
