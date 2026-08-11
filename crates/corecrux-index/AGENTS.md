# corecrux-index — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

The `.ccxi` companion inverted index: built on CPU at seal time alongside sealed
`.ccxseg` segments, it carries per-token posting lists (PForDelta-compressed on disk),
per-document metadata (length, tenant hash), and a vocabulary table. It powers BM25 in
`corecrux-retrieval`; the dataplane loads the same format to GPU memory.

Alongside `.ccxi` the crate carries **reader-only** ports of the CoreCrux companion
containers the platform computes and ships down: `.ccxe` (dense, the one format the CE
also writes), `.ccxs`/`.ccxse` (subject traits + their embeddings), `.ccxdi` (document
index), `.ccxal` (vernacular atoms), `.ccxn` (entity matrix), `.ccxf` (reverse frames),
`.ccxev` (extracted events), `.ccxp` (structured-fact projections), and `.ccxatt` (the
CROWN attestation over all of them). Provenance and divergences: `VENDORED_FROM.md`.

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
- **Reader-only for every companion but `.ccxi` and `.ccxe`.** Do not add a
  `Ccx*Builder`. It is constraint C7 of ExecPlan
  `crux-companion-vocabulary-unification-2026-08-08`, and since the readers ship in the
  default public binary it is the only thing standing between a CE operator and
  authoring their own companions. `scripts/assert-reader-only-companions.sh` fails CI on
  a third builder; widening its allowlist is a commercial decision, not a refactor.
- **Record every divergence from the CoreCrux source in `VENDORED_FROM.md`,** at its
  site as well. An unrecorded divergence is silently reverted by the next re-port.
- **Fixtures in `tests/fixtures/corecrux.*` cannot be regenerated here** — only the
  CoreCrux builders produce them. If a parity test fails, the format drifted upstream;
  re-port and bump the source commit rather than editing the expectation.
- `.ccxi` is a seal-time artifact: files on disk are immutable once written. Any change
  to the byte layout or PForDelta encoding must keep `pfordelta_decode` able to read
  existing files, or bump `CCXI_VERSION` and handle the old version in `CcxiReader` —
  silently changing encode output orphans every sealed index in the fleet.
- Don't change `tokenize` semantics unilaterally — indexes built with the old tokenizer
  will mismatch queries tokenised with the new one (same rebuild-the-world cost).
- Keep this crate CPU-only and dependency-light; GPU loading lives in the dataplane, not here.
