# GLOSSARY — internal vocabulary → meaning → defining symbol

> One line each, mapped to the symbol/file that defines it. Removes guesswork for a cold
> agent. `(inferred)` marks a meaning assembled from usage rather than an explicit definition.

## Core concepts

| Term | Meaning | Defined at |
|---|---|---|
| **CROWN** | **C**ryptographic **R**eceipt for **O**peration **W**ith **N**on-repudiation — the Ed25519-signed envelope minted on a receipt-bearing state mutation. | `docs/adr/002-crown-receipts.md`; label const in `corecrux-receipts/src/c2pa_manifest_v1.rs` (`CUECRUX_CROWN_RECEIPT_LABEL`) |
| **CRC-v1** (`crc_v1`) | **Crux Response Contract v1** — the daemon's negotiated MCP tool-output envelope (kinds `search` / `addressed` / `fact`). **Default ON**; callers opt out to legacy with a `contract` arg. | `crates/crux-mcp/src/crc_v1.rs` (module doc) |
| **passport** | An agent-identity credential carried into the session handshake; the `actor` attribution on substrate writes and the signing key for `.cruxpack` export. Gated by `CORECRUXD_AGENT_PASSPORTS`. | `Passport` in `crates/crux-session/src/`; `CRUX_PASSPORT_ID` env |
| **lane** | A pluggable retrieval-scoring signal fused by the engine: dense vector, BM25, graph (topology), frame, navtree. Each toggleable; non-BM25 lanes default-OFF on the CPU daemon. | `corecrux-retrieval/src/fused.rs` (`FusionWeights`, `dense_lane_active`) |
| **RCX** | The capability / credit / egress routing plane — capability tokens (`rcx-capability-token`) decided by `RcxRouter` (`crux-router`). | `crates/crux-router/src/lib.rs` (`RcxRouter`) |
| **RcxTier / ReceiptClass** | The tier ladder and receipt-class vocabulary carried by an RCX capability token — which backends may be called and which receipt class a call must emit. | `rcx-capability-token/src/lib.rs` (`RcxTier`, `ReceiptClass`) |
| **engram** | A distilled, versioned procedure resolved by declared intent at session start — instinct before retrieval — gated by passport tier, with provenance hashes back to source chunks. | `corecruxd/src/http/engrams.rs`; route `/v1/memory/engrams/resolve` (`corecruxd/src/product.rs`, `engram_resolution`) |
| **observation** | A captured, redacted record of agent/vendor activity (including MCP handoffs), with provider breakdowns; verifiable via `verify_observation`. *(inferred)* | `corecruxd/src/http/observations.rs`; `crux-mcp/src/tools/observations.rs` |
| **credit meter** | Default-off comped-wallet spend rail: pinned quote → signed spend receipt, idempotent on retry. Enabled by `CORECRUXD_CREDIT_METER`. | `corecruxd/src/http/credit_meter.rs` (`post_credit_spend`) |

## On-disk file types

| Extension | Meaning | Defined at |
|---|---|---|
| **`.ccxseg`** | A sealed, append-only segment (header + frames + TOC + footer). The unit of I1's `segment_hash`. | `corecrux-segment/src/builder.rs`, `decoder.rs` |
| **`.ccxi`** | **C**oreCrux **C**ompanion **I**ndex — the seal-time inverted index (vocab table + PForDelta postings + per-doc table) that powers BM25. Built when `CORECRUXD_BUILD_CCXI=1`. | `crates/corecrux-index/src/ccxi.rs` |
| **`.ccxsnap`** | Projection snapshot (living-row / hot-pointer / relations / cold-segment blocks), magic `CSNP`. **Not** a segment companion — it deliberately sits outside the `ccx<lane>` namespace, which is reserved for CoreCrux lane companions. Was `.ccxs` until 2026-08-08, which collided with CoreCrux's subject-profile/traits companion. | `crates/corecrux-projections/src/ccxsnap.rs` |
| **`.ccxe`** | Dense-vector companion, CoreCrux format — model-keyed as `<stem>.ccxe@<key>`, with the authoritative `model_id` in the **header, never the filename**. Written at seal time beside its `.ccxseg` and served by the local cosine `DenseProvider`. Was the CE-only bespoke `.ccxv` until 2026-08-08. | `crates/corecrux-index/src/ccxe.rs`; writer `corecruxd/src/local_ingest.rs` |
| **`.ccxprof`** | Embedder-profile sidecar (JSON `SemanticProfile`) recording tokenizer / prompt-template / normalisation / fingerprint — the parts of the profile the `.ccxe` header does not carry. Was `.ccxp` until 2026-08-08, which collided with CoreCrux's projection companion. | `corecruxd/src/local_ingest.rs` (`write_ccxprof`) |
| **`.ccxatt`** | Detached CROWN attestation over a segment's whole companion bundle — binds segment identity plus a per-companion blake3 digest. Resolves to provenance `platform` / `local` / `invalid` / `none`; `invalid` refuses to load in every mode. | `crates/corecrux-index/src/ccxatt.rs` |
| **`.cruxpack`** | A passport-signed, BLAKE3-hash-anchored memory-portability transfer envelope (schema `crux.cruxpack.v1`) — a snapshot of one daemon's memory for export/import. | `crates/corecrux-memory/src/cruxpack.rs` (`CRUXPACK_SCHEMA_V1`) |

### Platform lane companions (reader-only in the CE)

Computed by the CueCrux platform and shipped to a customer daemon, which reads them
locally. The CE ports the `Ccx*Reader` half only — constraint C7 of ExecPlan
`crux-companion-vocabulary-unification-2026-08-08`, enforced by
`scripts/assert-reader-only-companions.sh`. A reader is inert without artifacts, and only
the platform produces artifacts. Provenance: `crates/corecrux-index/VENDORED_FROM.md`.

| Extension | Meaning | Defined at |
|---|---|---|
| **`.ccxs`** | **Subject-profile / traits** companion — `(subject_kind, subject_id) → [(predicate, object)]`, binary-searched by `xxh64(kind_byte ‖ subject_id)`. | `crates/corecrux-index/src/ccxs.rs` |
| **`.ccxse`** | **Subject-trait embeddings** — one vector per `.ccxs` trait, keyed by the same subject hash; the header's `source_ccxs_crc` pins which `.ccxs` it was built from. | `crates/corecrux-index/src/ccxse.rs` |
| **`.ccxdi`** | **Document index** for the `indexing` lane — per-doc regions and read-pointers with Q8.8 salience. Schema v2 stamps a per-doc `tenant_hash`. | `crates/corecrux-index/src/ccxdi.rs` |
| **`.ccxal`** | **Vernacular atoms** for the `vernacular` lane — D0 pointer crystals (back to source spans) and D1 claim-graph atoms, plus an OOV surface pool. | `crates/corecrux-index/src/ccxal.rs` |
| **`.ccxn`** | **Entity matrix** — `canonical_name → [(session_id, doc_id, frame_offset)]` plus `canonical_name → EntityType`. Callers must normalise through `canonicalise` before lookup. *(Superseded the earlier inferred "graph topology lane" entry, which was wrong.)* | `crates/corecrux-index/src/ccxn.rs` |
| **`.ccxf`** | **Reverse frames** — short canonical-form questions a session uniquely answers, keyed back to `(session_id, doc_id)`. Lane id `topology`. *(Superseded the earlier inferred "query↔question embeddings" entry, which was wrong.)* | `crates/corecrux-index/src/ccxf.rs` |
| **`.ccxev`** | **Extracted events** — verb-anchored `(verb_class, object, time, modality)` records. A scoring signal, not a candidate generator. v2 adds `record_off`, the stable physical join key. | `crates/corecrux-index/src/ccxev.rs` |
| **`.ccxp`** | **Structured-fact projections** — `UserAction` / `UserAttribute` / `TemporalEvent` / `CountState` / `UserPreference` facts keyed to a source frame. | `crates/corecrux-index/src/ccxp.rs` |
| **`.ccxst`** | RAPTOR **navtree** lane file. **Not ported** — 0% deployed coverage, explicitly excluded by the ExecPlan. | CoreCrux only |

## Receipt subtypes (modules in `corecrux-receipts/src/`)

| Term | Meaning | Defined at |
|---|---|---|
| **witness_v1** | External-witness + RFC-3161 trusted-timestamp receipt classes (anchor a CROWN chain head to an external authority via an RFC-6962 inclusion proof). | `witness_v1.rs` |
| **c2pa_manifest_v1** | C2PA content-provenance manifest for AI-generated output: BLAKE3 content hash + Ed25519/X.509 signature, bound to a CROWN receipt id. | `c2pa_manifest_v1.rs` |
| **audit_bundle_v1** | "BYO Audit Trail" export bundle — packages receipts + scope into a verifiable, replayable archive (golden vectors in `vectors/audit-bundle-v1/`). | `audit_bundle_v1.rs` |
| **stream_v1** | Streaming + context-injection receipt classes — receipts over injected-context bodies and stream-end state. | `stream_v1.rs` |
| **memory_use_v1** | "Acknowledged Memory Use" receipt — proof that a memory was retrieved/used. | `memory_use_v1.rs` |
| **usage_receipt_v1** | Opt-in, metadata-only usage-ping receipt (adoption signal) — deterministic body, sign/verify round-trip, content-bearing bodies rejected; submission is consent-gated. | `usage_receipt_v1.rs`; `docs/usage-receipts.md` |
| **ConsolidationReceiptV1** | Receipt from the fact-store consolidation pass, listing the `superseded_fact_ids` it retired. | `corecrux-memory/src/fact_store.rs` |

> Other `*_v1.rs` receipt modules exist (`store_v1`, `forget_v1`, `crypto_shred_v1`,
> `export_v1`, `identity_v1`, `keyring_v1`, `approval_decision_v1`, `audit_gap_v1`, …);
> each is a receipt class named by its file. *(meanings inferred from filename)*
