# corecrux-index — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

The `.ccxi` companion inverted index: built on CPU at seal time alongside sealed
`.ccxseg` segments, it carries per-token posting lists (PForDelta-compressed on disk),
per-document metadata (length, tenant hash), and a vocabulary table. It powers BM25 in
`corecrux-retrieval`; the dataplane loads the same format to GPU memory.

## Key symbols
- `CcxiBuilder` — builds a `.ccxi` from documents at seal time (see `corecrux-storage/src/companions.rs` for the seal-path caller).
- `CcxiReader` — opens/validates a `.ccxi`; magic/version/integrity checks yield `IndexError::{InvalidMagic, UnsupportedVersion, IntegrityFailure}`.
- `CcxiHeader`, `DocEntry`, `VocabEntry` — the on-disk layout structs.
- `CCXI_MAGIC` / `CCXI_VERSION` — format identity; version bumps gate reader compatibility.
- `pfordelta_encode` / `pfordelta_decode` — posting-list compression codec.
- `tokenize` / `Token` — the shared tokenizer; index-time and query-time tokenisation must match.

## Test & verify
- `cargo test -p corecrux-index`
- `pfordelta.rs` round-trip tests (`round_trip_empty`, `round_trip_exact_block`,
  `round_trip_multi_block`, `round_trip_with_large_gaps`) pin codec behaviour.

## Local rules
- `.ccxi` is a seal-time artifact: files on disk are immutable once written. Any change
  to the byte layout or PForDelta encoding must keep `pfordelta_decode` able to read
  existing files, or bump `CCXI_VERSION` and handle the old version in `CcxiReader` —
  silently changing encode output orphans every sealed index in the fleet.
- Don't change `tokenize` semantics unilaterally — indexes built with the old tokenizer
  will mismatch queries tokenised with the new one (same rebuild-the-world cost).
- Keep this crate CPU-only and dependency-light; GPU loading lives in the dataplane, not here.
