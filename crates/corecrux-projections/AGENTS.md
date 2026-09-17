# corecrux-projections — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Living-objects projections: derived read-model state materialised from projection events
on the event spine, plus `.ccxsnap` snapshots and parity-harness plumbing. All projection
logic is deterministic by construction — sorted key orders (BTreeMap/BTreeSet),
integer-only state (quantized confidence, unix micros), stable snapshot/meta encodings.

## Key symbols
- `ProjectionEventV1` / `parse_projection_event` (`events.rs`) — the event vocabulary (`EVT_*_V1` constants) that feeds every projection.
- `ProjectionState::apply` (`state.rs`) — folds one event into derived state, returning `ProjectionApplyStats`.
- `CcxsnapSnapshot` / `CcxsnapProjectionId` (`ccxsnap.rs`) — snapshot format; blake3-hashed, deterministic.
- `ProjectionStoreV1` / `ProjectionsTickResultV1` (`runner.rs`) — the tick loop; on module-version change the next tick replays from genesis.
- `decay::apply_at` — pure freshness function `(HorizonClass, written_ms, now_ms) → Freshness`; no I/O, no clock, no randomness.
- `quantize_confidence_q16` / `dequantize_confidence_f32` — the integer-only confidence rule.
- `ingest_native_memory` / `read_memory_body` (`native_memory.rs`) — **strictly read-only**
  projection over `~/.claude/projects/*/memory/*.md`. Parses frontmatter, `[[wikilinks]]` and the
  `MEMORY.md` groupings; facts link out with `memory_md_ref`, bodies stay on disk.

## Test & verify
- `cargo test -p corecrux-projections`
- Native-memory gate: `cargo test -p corecrux-projections --test native_memory_ingest`
  (fixtures under `tests/fixtures/native-memory/`, never the operator's real store).
- Determinism tests: `snapshot_blake3_hex_is_deterministic` (`ccxsnap.rs`),
  `cold_block_path_v1_deterministic` / `cold_segment_path_v1_deterministic` (`runner.rs` tests).
- The cross-daemon parity harness (`corecruxctl/src/parity.rs`, `ParityLivingReportV1`)
  compares two daemons for byte-equivalent reads — it only works because state here is deterministic.

## Local rules
- Everything in this crate is **derived state**: it must be rebuildable from the event
  spine by replay. Never make a projection the source of truth, and never mutate one
  outside `ProjectionState::apply` / the runner tick.
- No nondeterminism in projection code paths: no `HashMap` iteration into output, no
  floats in stored state (quantize), no `Instant::now()`/random — determinism is what the
  parity harness verifies. Pass `now` in; see `decay::apply_at` for the idiom.
- `native_memory.rs` must never gain a write call. It is pointed at the operator's live memory
  store, loaded into every Claude Code session; `ingest_writes_nothing_to_the_memory_root` pins
  `(path, mtime, sha256)` across a full ingest and `projection_source_contains_no_write_calls`
  greps the module itself.
- Changing a projection's logic or encoding requires bumping its module version in
  `meta.rs` (`ProjectionModuleVersionV1`) so the runner replays from genesis, and keeping
  `parse_projection_event` able to read historical events.
