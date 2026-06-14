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

## On-disk file types

| Extension | Meaning | Defined at |
|---|---|---|
| **`.ccxseg`** | A sealed, append-only segment (header + frames + TOC + footer). The unit of I1's `segment_hash`. | `corecrux-segment/src/builder.rs`, `decoder.rs` |
| **`.ccxi`** | **C**oreCrux **C**ompanion **I**ndex — the seal-time inverted index (vocab table + PForDelta postings + per-doc table) that powers BM25. Built when `CORECRUXD_BUILD_CCXI=1`. | `crates/corecrux-index/src/ccxi.rs` |
| **`.ccxs`** | Projection companion snapshot (living-row / hot-pointer / relations / cold-segment blocks). | `crates/corecrux-projections/src/` |
| **`.cruxpack`** | A passport-signed, BLAKE3-hash-anchored memory-portability transfer envelope (schema `crux.cruxpack.v1`) — a snapshot of one daemon's memory for export/import. | `crates/corecrux-memory/src/cruxpack.rs` (`CRUXPACK_SCHEMA_V1`) |
| **`.ccxn`** | Graph **topology** lane file (entity/edge topology). Default-OFF lane. *(inferred — lane id `topology`)* | `corecrux-retrieval/src/graph.rs`; console `gr-topology` |
| **`.ccxst`** | RAPTOR **navtree** lane file (hierarchical abstractive nav tree). Default-OFF lane. *(inferred — lane id `navtree`)* | `corecruxd` console lane `navtree` |
| **`.ccxf`** | **Frame-substrate** lane file (reverse-frame / query↔question embeddings). Default-OFF. *(inferred — lane id `frames`)* | `corecrux-retrieval/src/fused.rs` |

## Receipt subtypes (modules in `corecrux-receipts/src/`)

| Term | Meaning | Defined at |
|---|---|---|
| **witness_v1** | External-witness + RFC-3161 trusted-timestamp receipt classes (anchor a CROWN chain head to an external authority via an RFC-6962 inclusion proof). | `witness_v1.rs` |
| **c2pa_manifest_v1** | C2PA content-provenance manifest for AI-generated output: BLAKE3 content hash + Ed25519/X.509 signature, bound to a CROWN receipt id. | `c2pa_manifest_v1.rs` |
| **audit_bundle_v1** | "BYO Audit Trail" export bundle — packages receipts + scope into a verifiable, replayable archive (golden vectors in `vectors/audit-bundle-v1/`). | `audit_bundle_v1.rs` |
| **stream_v1** | Streaming + context-injection receipt classes — receipts over injected-context bodies and stream-end state. | `stream_v1.rs` |
| **memory_use_v1** | "Acknowledged Memory Use" receipt — proof that a memory was retrieved/used. | `memory_use_v1.rs` |
| **ConsolidationReceiptV1** | Receipt from the fact-store consolidation pass, listing the `superseded_fact_ids` it retired. | `corecrux-memory/src/fact_store.rs` |

> Other `*_v1.rs` receipt modules exist (`store_v1`, `forget_v1`, `crypto_shred_v1`,
> `export_v1`, `identity_v1`, `keyring_v1`, `approval_decision_v1`, `audit_gap_v1`, …);
> each is a receipt class named by its file. *(meanings inferred from filename)*
