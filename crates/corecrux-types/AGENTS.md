# corecrux-types — agent notes

> Root `AGENTS.md` and `CLAUDE.md` still apply; this file adds crate-local context.

Foundational shared types for the CoreCrux event store: evidence payloads, control
evidence (seal markers etc.), and decision-plane records. Deliberately a leaf crate with
minimal dependencies so every other crate can depend on it without cycles. Serialisation
is `serde` with JSON as the wire format.

## Key symbols
- `DriftClass` — replay-mismatch classification (6 `DRIFT_*` constants, serde-renamed)
- `BuildInfo` / `UpdateStatus` / `CompatContract` — build identity and version-compat
  contract types (`DEFAULT_COMPAT_REQUIRES = ">=3.0 <4.0"`)
- `CORE_ERROR_CODES` — the 11-code daemon error taxonomy (`CORE_ERROR_*`, GPU variants removed)
- `SHARDMAP_V1` / `SHARDMAP_HASH_FN_V1` / `SHARDMAP_KEY_ENCODING_V1` — routing/sharding contract
- Modules `evidence`, `control_evidence`, `decision_plane` (all re-exported at root)

## Test & verify
- `cargo test -p corecrux-types` (tests module in `src/lib.rs`)

## Local rules
- These types cross wire and disk boundaries via serde JSON — renaming a field or variant
  (or its `#[serde(rename)]` string) is a breaking wire change. Add optional fields;
  don't rename or repurpose existing ones.
- String constants (`CORE_ERROR_*`, `DRIFT_*`, shardmap ids) are matched by external
  clients and stored data — treat their values as frozen.
- Keep it a leaf: no new dependencies on other workspace crates, and keep external deps
  minimal. If a type needs daemon/storage logic, it belongs in that crate, not here.
- `SHARDMAP_HASH_FN_V1 = "xxhash64-v1"` names the algorithm implemented by
  `corecrux-frame::stream_hash_xxhash64` — changing either side desynchronises routing.
