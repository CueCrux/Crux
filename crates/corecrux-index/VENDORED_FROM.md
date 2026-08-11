# Vendored companion formats

Files in this crate ported from the CoreCrux dataplane so that a Crux CE daemon can
**read** companions the platform computed for it (ExecPlan
`crux-companion-vocabulary-unification-2026-08-08`).

| File | Source | Source commit | Ported |
|---|---|---|---|
| `src/ccxe.rs` | `CoreCrux/crates/corecrux-index/src/ccxe.rs` | `88a8439` | 2026-08-08 |
| `src/turboquant.rs` | `CoreCrux/crates/corecrux-index/src/turboquant.rs` | `88a8439` | 2026-08-08 |
| `src/ccxs.rs` | `CoreCrux/crates/corecrux-index/src/ccxs.rs` | `88a8439` | 2026-08-11 (M5) |
| `src/ccxse.rs` | `CoreCrux/crates/corecrux-index/src/ccxse.rs` | `88a8439` | 2026-08-11 (M5) |
| `src/ccxdi.rs` | `CoreCrux/crates/corecrux-index/src/ccxdi.rs` | `88a8439` | 2026-08-11 (M5) |
| `src/ccxal.rs` | `CoreCrux/crates/corecrux-index/src/ccxal.rs` + `src/vernacular_atom.rs` | `88a8439` | 2026-08-11 (M5) |
| `src/ccxn.rs` | `CoreCrux/crates/corecrux-index/src/ccxn.rs` | `88a8439` | 2026-08-11 (M5) |
| `src/ccxf.rs` | `CoreCrux/crates/corecrux-index/src/ccxf.rs` | `88a8439` | 2026-08-11 (M5) |
| `src/ccxev.rs` | `CoreCrux/crates/corecrux-index/src/ccxev.rs` | `88a8439` | 2026-08-11 (M5) |
| `src/ccxp.rs` | `CoreCrux/crates/corecrux-index/src/ccxp.rs` | `88a8439` | 2026-08-11 (M5) |

`src/le.rs` is **not** a port. It is CE-local, and exists because of the divergences
recorded under "Shared primitives" below.

`.ccxst` (navtree) is deliberately **not** ported: 0% deployed coverage, excluded by the
ExecPlan.

## Licence

CoreCrux's workspace declares `license = "MIT"`; this repo is `Apache-2.0`. MIT →
Apache-2.0 is a permitted direction for a combined work with notice retained. Per-file
headers vary in CoreCrux (some files carry CCL v1.0), so each was checked individually
at port time per constraint C5: **none of the ten source files above carries a per-file
licence header** — every one opens with `//!` module docs. The Apache-2.0 + SPDX header
this repo requires on every `.rs` was prepended at port time. The MIT origin is recorded
here.

## Reader-only — and what "minimal shared types" meant in practice

Constraint C7 of the ExecPlan is **reader-only**: the CE must not be able to author
companions the platform sells. `.ccxe` is the single, deliberate exception, because the
CE writes its own dense vectors from locally-delegated embeddings, so it needs
`CcxeBuilder`. Every other file here ports its `Ccx*Reader` half only.

The barrier is enforced mechanically, not by review: `scripts/assert-reader-only-companions.sh`
runs in CI and fails on any `Ccx*Builder` other than `CcxiBuilder` / `CcxeBuilder`.

C7 permits porting the minimal *types* a reader cannot compile without. In practice the
readers needed **no builder-side logic at all** — every container in this crate has a
clean reader/writer split, and the shared items are the on-disk layout structs, the
enums whose discriminants *are* the wire format, and the constants. Specifically:

- Header structs (`CcxsHeader`, `CcxseHeader`, `CcxdiHeader`, `CcxnHeader`, `CcxfHeader`,
  `CcxevHeader`, `CcxpHeader`, `ccxal::Header`) — decoded, never encoded.
- Wire enums (`SubjectKind`, `CcxseDtype`, `EntityType`, `CcxevModality`,
  `ProjectionPredicate`) — their `from_u8` is the reader's; `as_u8` came along because a
  round-trip test is how the discriminants are pinned as wire format.
- Record structs the reader materialises (`ProfileTrait`, `EntityOccurrence`,
  `EntityRecord`, `ReverseFrame`, `ExtractedEvent`, `ProjectionFact`, `RegionEntry`,
  `PointerEntry`, the `.ccxal` atoms).
- The key-derivation helpers a *caller* needs to look anything up: `ccxs::subject_hash`
  and `ccxn::canonicalise`. These are shared by both halves upstream; without them a
  reader can open a file and never find a record in it.

`turboquant.rs` ports whole because the decoder is unavoidable — a platform-built
`.ccxe` may be TurboQuant-packed — and encode/decode share the rotation math. The CE's
own builder writes `Quantization::Float32`; it does not quantise.

**Excised** (present upstream, absent here): every `Ccx*Builder` and its private build
scaffolding (`BuilderEntry`, `DocBuild`, `RegionBuild`, `PointerBuild`, `StringPool`,
`DocHandle`, `SubjectBuild`), every `encode_*` function, `f32_to_q8_8` and its
`round_half_to_even` helper (encode-side only), `ccxal::encode_header`, and
`vernacular_atom`'s `encode_doc_table_entry` / `encode_d0_atom` / `encode_d1_atom`.
`corecrux-memreport` is a dataplane-only dependency and is excised, not stubbed.

## Divergences

A divergence not recorded here is silently reverted by the next re-port. Each is also
commented at its site.

### Shared primitives (`src/le.rs`)

1. **`crc32c` is shared, not per-file.** Each CoreCrux container carries its own
   byte-identical private copy (verified: all eight hash to the same body modulo
   `u32::from(byte)` vs `byte as u32` and comment text). Eight copies is eight places
   for a transcription slip to hide, in the function that decides whether a companion is
   trusted at all. `le.rs` pins the standard Castagnoli check vector
   (`crc32c(b"123456789") == 0xE3069283`).
2. **`try_into().unwrap()` → `le::read_u16/u32/u64/f32`.** `clippy::unwrap_used` is a
   warn-level lint and CI is `-D warnings`; separately, `scripts/unwrap-baseline.txt`
   allows this crate **3** production `unwrap`/`expect` sites in total, and the seven
   readers carry several hundred `try_into().unwrap()` between them upstream. The
   helpers index a slice the reader has already bounds-checked against the header's
   declared section lengths, which is the same precondition the upstream `unwrap` relied
   on. `ccxe.rs` keeps its own private copies of these helpers; it was ported first and
   is left untouched to keep its re-port diff clean.

### Per-file

3. **`ccxal.rs` — `vernacular_atom.rs` folded in, decode half only.** Upstream keeps the
   per-entry codec in a separate module so cargo-fuzz can target it in isolation. Only
   `decode_doc_table_entry` / `decode_d0_atom` / `decode_d1_atom` port; three functions
   do not need a module of their own.
4. **`ccxal.rs` — `_pad*` struct fields are private.** Upstream marks them `pub`;
   `clippy::pub_underscore_fields` is denied here. They stay in the structs because the
   `const { assert!(size_of::<..>() == ..) }` guards depend on them, and a reader-only
   crate has no caller that should be constructing a header anyway.
5. **`ccxal.rs` — `decode_d1_atom` reads `temporal_value` as `le_u32(..) as i32`** rather
   than `i32::from_le_bytes(try_into().unwrap())`. Same bytes, same two's-complement
   result; it exists only to route through the shared helper. A regression test pins the
   negative case, because decoding this field as unsigned turns "900 seconds before the
   anchor" into ~4.29 billion after it.
6. **`ccxev.rs` — `CcxevReader` borrows the buffer it parsed.** Upstream's reader owns no
   slice and its `events(&self, data: &[u8])` takes the bytes back as an argument, so
   passing a *different* buffer silently decodes wrong objects and categories instead of
   failing. The CE reader holds `&'a [u8]` and `events()` takes no argument, which makes
   the mismatch unrepresentable. The section offsets (`cat_table_start`, `heap_start`,
   `heap_len`) are computed once during parse rather than re-walked on every `events()`
   call, and `events()` now bounds-checks the category table and string heap before
   reading rather than indexing on trust.
7. **`ccxev.rs` — the event-entry loop uses fixed offsets from the entry base** instead of
   a running cursor advanced field by field. Byte-for-byte identical (v1 40 bytes, v2 44),
   but the offsets are now visible at each read rather than implied by the order of
   statements.
8. **`ccxp.rs` — `ProjectionPredicate::BusinessObject(ObjectKind)` and `ObjectKind` are
   excised.** Upstream carries a sixth, data-bearing variant that `.ccxp` encoders must
   never emit — `from_u8` rejects tag 5 and `as_u8` `debug_assert!`s. It is a
   classification hint for a dispatch path (`.ccxb`, `corecrux-federation`) that does not
   exist in the CE. Dropping it lets the enum be a plain `#[repr(u8)]` five-variant type
   with a total `as_u8`, and removes a panic path. Tag 5 is still rejected, with a test,
   so the wire format is unchanged and the forward-compat hook is preserved.
9. **`ccxdi.rs` — `find_doc` is public.** Upstream keeps it private and exposes only
   `regions_for_doc` / `pointers_for_doc`, which each call it. A caller that wants a
   doc's `tenant_hash` without its regions would otherwise have to scan `iter_docs`.
10. **`ccxdi.rs` — section-offset arithmetic is checked.** Upstream computes
    `doc_count * DOC_ENTRY_LEN` and friends with plain multiplication; a hostile header
    can overflow those on a 32-bit target. Same for the `checked_add`/`checked_mul` added
    across `entry_at` / `get` in `ccxs`, `ccxse`, `ccxn`, `ccxf`, `ccxp`. Behaviour on
    well-formed files is identical; on malformed ones the result is `None`/`Err` rather
    than a wrapped index.
11. **Doc comments were retargeted.** Upstream module docs reference CoreCrux-internal
    ExecPlans, Postgres tables, planning-monorepo doc paths and sibling crates that do
    not exist in this repo. The *format* documentation — layouts, offsets, invariants,
    rationale — is kept verbatim in substance; the unresolvable cross-references are
    replaced with prose, because `RUSTDOCFLAGS="-D warnings"` is a CI gate and a link to
    a path outside the repo is not checkable by a reader.
12. **`.ccxst` (navtree) is not ported at all** — 0% deployed, excluded by the ExecPlan.

## Drift

These are copies, not a path dependency — the two repos are separate cargo workspaces
with different `workspace.package` metadata (the same reasoning as
`CoreCrux/crates/corecrux-rcx-token`). When the upstream format changes, re-port and bump
the source commit above.

`tests/corecrux_companion_parity.rs` is what catches silent divergence: it opens
fixtures in `tests/fixtures/corecrux.*` that the **CoreCrux builders** emitted at commit
`88a8439`, and asserts field-level equality with what those builders were handed. Because
C7 keeps the builders out of this repo, there is no CE-side way to regenerate those
fixtures — which is the point.

To refresh them: write a throwaway integration test in
`CoreCrux/crates/corecrux-index/tests/` that drives each `Ccx*Builder` and writes its
`build()` output into this crate's `tests/fixtures/`, run it there, then delete it. That
generator must live in the CoreCrux tree, not this one: a file here that constructs
`CcxsBuilder` and friends would fail `scripts/assert-reader-only-companions.sh`, and
correctly so — the gate does not distinguish "calls a builder" from "is a builder",
because a test fixture is exactly the shape a builder would first reappear in.
