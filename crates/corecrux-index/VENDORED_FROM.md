# Vendored companion formats

Files in this crate ported from the CoreCrux dataplane so that a Crux CE daemon can
**read** companions the platform computed for it (ExecPlan
`crux-companion-vocabulary-unification-2026-08-08`).

| File | Source | Source commit | Ported |
|---|---|---|---|
| `src/ccxe.rs` | `CoreCrux/crates/corecrux-index/src/ccxe.rs` | `88a8439` | 2026-08-08 |
| `src/turboquant.rs` | `CoreCrux/crates/corecrux-index/src/turboquant.rs` | `88a8439` | 2026-08-08 |

## Licence

CoreCrux's workspace declares `license = "MIT"`; this repo is `Apache-2.0`. MIT → Apache-2.0
is a permitted direction for a combined work with notice retained. Neither source file carried
a per-file licence header (both open with `//!` docs), so the Apache-2.0 + SPDX header this
repo requires on every `.rs` was prepended at port time. The MIT origin is recorded here.

## Why the builder came too

Constraint C7 of the ExecPlan is **reader-only** — the CE must not be able to author companions
the platform sells. `.ccxe` is the single, deliberate exception: the CE writes its own dense
vectors from locally-delegated embeddings, so it needs `CcxeBuilder`. Every other companion
format ports its `Ccx*Reader` half only.

`turboquant.rs` ports whole because the decoder is unavoidable — a platform-built `.ccxe` may be
TurboQuant-packed, and reading it requires the codec. Encode and decode share the rotation
math, so splitting the file would create a maintenance seam for no gain. The CE's own builder
writes `Quantization::Float32`; it does not quantise.

## Drift

These are copies, not a path dependency — the two repos are separate cargo workspaces with
different `workspace.package` metadata (the same reasoning as `CoreCrux/crates/corecrux-rcx-token`).
When the upstream format changes, re-port and bump the source commit above. The
round-trip fixture test in `ccxe.rs` is what catches silent divergence: it asserts this crate
can still open bytes a CoreCrux builder produced.
