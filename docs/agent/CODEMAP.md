# CODEMAP — the crate atlas

> What each crate owns, its load-bearing public symbols, and who depends on it.
> Anchored by **symbol name** (greppable), not line number (rots). Verified against
> the tree by `scripts/check-agent-docs.sh` in CI.

The workspace has **27 cargo crates** under `crates/`. (`crux-console-ui` is a built
SPA — `dist/` only, not a cargo member — and is excluded below.)

## Trust core (read these first)

| Crate | Purpose | Key public symbols | Used by | ~LOC |
|---|---|---|---|---|
| `corecrux-segment` | Sealed segment format (`.ccxseg`) — build / seal / decode + hash binding | `build_segment_v1`, `seal_segment_v1_from_record_area`, `decode_segment_v1`, `SegmentError` | corecrux-storage, corecrux-index, corecrux-projections, corecruxctl, corecruxd | 4.1k |
| `corecrux-storage` | Append-only shard store; sealing, integrity scan, seal material | `ShardStorage::append`, `SegmentSealMaterialV1`, `integrity_scan_stats_all`, `verify_segment_hashes_all` | corecrux-projections, corecruxctl, corecruxd | 12.4k |
| `corecrux-receipts` | Receipt formats, Ed25519 signing, strict verification, witness anchoring, export bundles | `verify_receipt_v1`, `build_c2pa_manifest_v1`/`verify_c2pa_manifest_v1`, `build_bundle_v1`/`verify_bundle_v1`, `build_external_anchor_body_v1`/`verify_rfc6962_inclusion_proof_v1`, `sign_stream_v1` | crux-integrations, crux-mcp, corecruxctl, corecruxd | 12.0k |
| `corecrux-frame` | Canonical v1 frame encoding + hash helpers (header / payload / stream) | `canonical_header_bytes_v1`, `compute_header_hash`, `compute_payload_hash`, `decode_canonical_header_bytes_v1` | corecrux-{index,projections,storage,segment}, corecruxctl, corecruxd | 0.3k |
| `rcx-capability-token` | RCX capability token v1.0 (schema-lock, CBOR/JSON mirror, validation) | `RcxCapabilityToken`, `verify_token`, `validate_basic`, `RcxTier`, `ReceiptClass` | crux-enterprise-shim, crux-mcp, crux-router | 1.1k |

## Memory & retrieval

| Crate | Purpose | Key public symbols | Used by | ~LOC |
|---|---|---|---|---|
| `corecrux-memory` | Versioned fact store + session store; decay, supersession, CROWN receipts | `Fact`, `FactStore`, `mark_superseded`, `ContradictionCandidateV1`, `ConsolidationReceiptV1`, `consolidate_facts_v1` | crux-lens-features, crux-mcp, crux-observe, corecruxctl, corecruxd | 11.7k |
| `corecrux-index` | Companion inverted index (`.ccxi`) built at seal time; powers BM25 | `CcxiBuilder`, `CcxiReader`, `CcxiHeader`, `pfordelta_encode`/`pfordelta_decode` | corecrux-retrieval, crux-mcp, corecrux-storage, corecruxctl, corecruxd | 1.1k |
| `corecrux-retrieval` | Fused retrieval — BM25 + graph-signal fusion over `.ccxi` | `fused_retrieve`, `IndexManager`, `FusionWeights`, `FusedHit` | corecruxd, crux-mcp | 2.1k |
| `corecrux-projections` | Living-objects projections + snapshots (`.ccxs`) + deterministic parity harness | `ProjectionEventV1`, `CcxsProjectionId`, `build_cold_segment_v1`, `apply`/`apply_at` | corecrux-retrieval, corecruxctl, crux-mcp, crux-session, corecruxd | 12.4k |
| `crux-lens-features` | Feature Registry lens over the memory substrate (coverage / gap reporting) | `compute_coverage_report`, `compute_gaps`, `compute_promise_coverage` | crux-mcp, corecruxd | 0.5k |

## Routing, identity, sessions

| Crate | Purpose | Key public symbols | Used by | ~LOC |
|---|---|---|---|---|
| `crux-router` | RCX daemon router primitives (capability / credit / egress) | `RcxRouter` | crux-mcp, corecruxd | 2.2k |
| `crux-session` | VaultCrux session handshake v1 (canonical CBOR + JCS mirror + Ed25519) | `plan_receipt_hash`/`verify_plan_signature`, `mint_invocation_receipt`/`verify_invocation_receipt`, `to_canonical_cbor` | rcx-capability-token, corecruxctl, crux-mcp, corecruxd | 7.2k |
| `crux-enterprise-shim` | Enterprise customer-hosted RCX token-validation contract | `EnterpriseShim`, `validate_enterprise_trust_root`, `EnterpriseTrustRoot`, `EnterpriseShimDecision` | corecruxd | 0.4k |
| `vaultcrux-local` | Daemon-local VaultCrux classification + content-loading policy (tier boundaries) | `load_content_manifest`/`validate_content_manifest`, `tool_tier`, `ContentManifest`, `ToolTier` | crux-mcp, corecruxd | 0.6k |

## Daemon, CLI, MCP

| Crate | Purpose | Key public symbols | Used by | ~LOC |
|---|---|---|---|---|
| `corecruxd` | The Crux Daemon binary (HTTP / gRPC / MCP host, signing, auth) | *(binary)* — owns `build_segment_seal_receipt`, `sign_segment_seal_material` (`src/grpc.rs`) | — | 83.8k |
| `corecruxctl` | CoreCrux CLI: `verify-store`, `replay`, `gaps` | *(binary)* — `verify_store`, `replay`, `gaps` modules (`src/`) | — | 33.1k |
| `crux-mcp` | Agent-facing MCP server (JSON-RPC 2.0 + axum Streamable-HTTP); ~42 tool modules | `dispatch`, `router`/`with_rcx_router`/`with_agent_passports`, `crc_v1` | corecruxd | 33.1k |
| `crux-observe` | Self-observation layer: ops events + bootstrap docs → memory facts | `Redactor`/`redact_line`, `bootstrap_entity`/`ops_entity`, `self_observe_enabled` | crux-mcp, corecruxd | 2.7k |
| `crux-observe-api` | Wire types for the agent audit-chain data contract | `NodeKind`, `RiskClass`, `StepStatus`, `ReasoningRef` | corecruxd | 0.8k |
| `crux-integrations` | Declarative manifest contract for daemon integration packs | `IntegrationManifest`, `IntegrationEntry`, `EntryKind`, `SafetyPolicy` | corecruxctl, crux-mcp, corecruxd | 2.5k |

## Supporting / standalone

| Crate | Purpose | Key public symbols | Used by | ~LOC |
|---|---|---|---|---|
| `corecrux-types` | Foundational shared event-store types | `DriftClass`, `BuildInfo`, `UpdateStatus`, `CompatContract` | corecrux-receipts, crux-mcp, corecruxctl, corecruxd | 2.5k |
| `corecrux-proto` | Protobuf/gRPC types for the data plane (tonic/prost generated) | `dataplane_v1`, `observe_v1` (modules) | crux-integration-tests, corecruxctl, corecruxd | 0.1k |
| `crux-config-wizard` | Composes `CLAUDE.md`/`AGENTS.md` config from versioned profile fragments | `Target` enum *(also a binary)* | crux-claude-hooks | 1.8k |
| `crux-claude-hooks` | Claude Code lifecycle hook binaries (`crux-hook`, `crux-llm-shim`) | *(binaries + `crux_claude_hooks` lib)* | — | 5.0k |
| `crux-contrib` | Contribution-manifest builder + Ed25519 envelope signing | `build_manifest`, `ContributionManifest`, `Provenance` | — | 0.2k |
| `crux-sync` | Offline-first outbox sync client to the VaultCrux API | `Outbox`/`OutboxEntry`, `push_contributions`/`query_commons` | — | 0.7k |
| `crux-integration-tests` | Cross-crate integration tests (consumes corecrux-proto) | *(test-only crate)* | — | 2.2k |

## Notes / corrections to common assumptions

- The seal-receipt **builders** (`build_segment_seal_receipt`, `sign_segment_seal_material`)
  are private fns in the `corecruxd` binary (`src/grpc.rs`), not a library crate. The
  reusable, signable material type is `SegmentSealMaterialV1` in **corecrux-storage**.
- `witness_v1`, `audit_bundle_v1`, `c2pa_manifest_v1`, `stream_v1` are **modules** of
  `corecrux-receipts`, not functions — call the concrete `build_*_v1` / `verify_*_v1` fns.
- `verify_strict` is the upstream `ed25519-dalek` `VerifyingKey::verify_strict` method
  (rejects malleable / non-canonical signatures), invoked by every per-format verifier.
  It is not a CueCrux-defined symbol.
- Two distinct "coverage" subsystems exist: `crux-lens-features` (feature-registry gaps,
  `compute_gaps`) and `corecruxctl gaps` (segment-indexed-vs-not). Don't conflate them.
