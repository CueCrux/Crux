# Fact / memory storage-layer mutation-path receipt audit (P4 / M5)

- **ExecPlan:** `verifiable-record-products-2026-07-17` — Phase 1, M5 (audit) + M6 (implementation).
- **Date:** 2026-07-17
- **Scope:** every state-mutation path in the fact/memory storage layer (`corecrux-memory::FactStore`, the `corecruxd` background tasks that drive it, and the `corecrux-storage` directory LSM). Threat addressed: **T.4 audit-trail gap** — a mutation that removes or rewrites durable state without leaving a verifiable trail.
- **freshness_horizon:** re-verify file:line before relying after 30 days (architectural counts; the tree moves).

## Classification scheme

Each path is one of:

- **(a) Receipted** — the mutation emits a signed, offline-verifiable CROWN receipt (Ed25519 over a canonical body) recording who/what/how-many, **or** it is an append-only, replayable journal event that is fully reversible and loses no content (the journal *is* the trail).
- **(b) Bypass — needs a receipt** — the mutation removes or physically erases durable content and, before M6, left only a `tracing::info!` log line or a plain report struct. This is the audit gap M6 closes.
- **(c) Explicitly-non-receipted maintenance (justified)** — the mutation is either in-memory-only derived metadata (lost/rebuilt on restart, no durable state change) or a logically-lossless physical reorganization that already emits a structured, replayable maintenance event. No signed receipt required; the justification is recorded here.

The **guard test** `crates/corecruxd/tests/mutation_path_receipt_audit.rs` enumerates every row below and **fails if any path is still classified (b)**. It is RED on the M5 commit (three live bypasses) and GREEN once M6 lands their receipts.

## Audit table

| # | Path | Symbol (file:line) | Journal / event | Classification | Notes |
|---|------|--------------------|-----------------|----------------|-------|
| 1 | Store / update a fact | `FactStore::store` / `try_store` ([fact_store.rs:965,978](../crates/corecrux-memory/src/fact_store.rs)) | `JournalEvent::Store` | (a) journaled-additive | Append-only, versioned, reversible via delete/supersede. No content lost; journal is the replayable trail. |
| 2 | Bulk store | `FactStore::store_bulk` / `try_store_bulk` ([fact_store.rs:1009,1014](../crates/corecrux-memory/src/fact_store.rs)) | `JournalEvent::StoreBatch` | (a) journaled-additive | As #1, batched. |
| 3 | Synced insert (sync pull) | `FactStore::store_synced` ([fact_store.rs:1643](../crates/corecrux-memory/src/fact_store.rs)) | `JournalEvent::Store` | (a) journaled-additive | Remote-origin fact; tenant re-stamped by caller. Journaled. |
| 4 | Soft delete (tombstone) | `FactStore::delete` / `try_delete` ([fact_store.rs:1032,1053](../crates/corecrux-memory/src/fact_store.rs)) | `JournalEvent::Delete` | (a) journaled, reversible | Reversible tombstone; content stays on disk until compaction. The **content-erasure** step is #8, not here. |
| 5 | Cross-entity supersede / clear | `mark_superseded` / `clear_superseded` ([fact_store.rs:805,827](../crates/corecrux-memory/src/fact_store.rs)) | `Supersede` / `ClearSupersede` | (a) journaled, reversible | Reversible retire/un-retire; also carried inside the merge receipt (#7). |
| 6 | Valid-time (bi-temporal) update | `SetValidity` handler ([fact_store.rs:52](../crates/corecrux-memory/src/fact_store.rs)) | `JournalEvent::SetValidity` | (a) journaled-additive | Sets `[valid_from,valid_to)` metadata; never rewrites value. |
| 7 | **Merge / consolidation** + undo | `consolidate_facts_v1` / `consolidate_undo_v1` ([fact_store.rs:1738,1845](../crates/corecrux-memory/src/fact_store.rs)); CROWN mint ([http/consolidation_receipt.rs:41](../crates/corecruxd/src/http/consolidation_receipt.rs)) | `Consolidate` / `ConsolidateUndo` | **(a) receipted** | Emits `ConsolidationReceiptV1` with full ancestry (`superseded_fact_ids` + `source_fact_ids`); corecruxd mints a signed `crux.consolidation_receipt.v1`. Reference minting pattern for M6. |
| 8 | **GDPR content erasure (journal compaction)** | `compact_journal` / `compact_journal_unchecked` ([fact_store.rs:1459,1511](../crates/corecrux-memory/src/fact_store.rs)); driver ([http/admin.rs:1033](../crates/corecruxd/src/http/admin.rs) `compact-facts`) | returns `CompactionReport` (counts only) | **M5: (b) bypass → M6: (a) receipted** | Physically drops the `Store` event (and value) of soft-deleted facts. Before M6 only a `tracing::info!` line + a legal-hold-override receipt on the override branch; the **ordinary** erasure minted no receipt. |
| 9 | **Retention sweep** | `mark_retention_eligible` ([fact_store.rs:1619](../crates/corecrux-memory/src/fact_store.rs)); only caller ([http/admin.rs:1079](../crates/corecruxd/src/http/admin.rs)) | soft-deletes via #4, then #8 erases | **M5: (b) bypass → M6: (a) receipted** | Runs inside the same `compact-facts` op as #8; covered by the erasure receipt's `retentionMarked` / `retentionDays` fields. No standalone/background caller exists. |
| 10 | **Ephemeral reserved-fact GC** | `run_sweep_once` / `spawn_ephemeral_gc` ([ephemeral_gc.rs:140,171](../crates/corecruxd/src/ephemeral_gc.rs)) | soft-deletes via #4 | **M5: (b) bypass → M6: (a) receipted** | Hourly background sweep of `__session_binding__::*` / `__reverify_receipts__::*` past retain. Before M6 only a `tracing::info!` line. |
| 11 | Directory LSM compaction | `compact_directory_until_within_limits` / `compact_dir_run_pair_v1` ([corecrux-storage/src/compact.rs:54,97](../crates/corecrux-storage/src/compact.rs)) | emits `DirCompactionEventV1` (counts: `bytes_in/out`, `input/dropped_extents`) | **(c) justified maintenance** | Physical index run-merge (LSM level compaction). **Logically lossless**: keeps the latest version per key, drops only index extents already below the stream cut. Already emits a structured, replayable maintenance event with counts. **Not wired into the daemon** — only exercised by `corecrux-storage` tests, and gated by `options.enable_directory_compaction`. Lives in the low-level storage crate, which holds no passport signing key. **When it is wired into corecruxd, the caller (which has `AppState`) must mint a CROWN receipt over the returned `Vec<DirCompactionEventV1>` — the same call-layer pattern used for #8.** See open question O-1. |
| 12 | In-memory metadata tweaks | `set_horizon` / `reverify` / `record_access` ([fact_store.rs:771,785,887](../crates/corecrux-memory/src/fact_store.rs)) | none (in-memory only) | **(c) justified maintenance** | No `append_journal`; mutate derived/ephemeral fields (`horizon_class`, `reverified_at`, `access_count`). No durable content change → no receipt. (`set_horizon` not being journaled is a separate durability nit, out of P4 scope — flagged as O-2.) |

## M6 receipt design (paths 8, 9, 10)

CROWN receipts are minted via the existing signed-observation primitive `corecruxd::http::observations::append_one` — the same primitive already used for the `legal_hold_overridden` erasure receipt ([http/admin.rs:1137](../crates/corecruxd/src/http/admin.rs)). Each receipt is Ed25519-signed over its canonical body, chained (tamper-evident JSONL), and offline-verifiable with the daemon passport public key.

- **Erasure receipt** (paths 8 + 9): governance session `__governance__::erasure`, kind `erasure.compact_facts`, payload = `{facts_dropped, facts_retained, tombstones_kept, retention_marked, retention_days, reason, actor}`.
- **GC receipt** (path 10): governance session `__governance__::gc`, kind `gc.ephemeral_sweep`, payload = `{deleted, retain_days, reason, actor}`.

**Redaction invariant (GDPR-clean):** every receipt records **counts + actor + reason only, never erased content**. Payload builders (`build_erasure_receipt_payload`, `build_gc_receipt_payload`) take *counts*, not facts — leakage is impossible by construction. The redaction tests seed secret-bearing facts, run the real erasure/sweep, build the real payload, and assert the secret never appears in any receipt field.

Both mints are **best-effort**: the mutation is already durable when the receipt is minted, so a missing passport key logs a warning and continues (mirrors `mint_consolidation_receipt` returning `None`). All new behaviour is additive — no existing receipt format changes.

## Open questions for the operator

- **O-1 (dir compaction):** the ExecPlan ground truth lists directory compaction as a "bypass needing a receipt", but the code shows it is **not wired into corecruxd** (test-only, gated OFF) and is logically lossless. M6 therefore classifies it as justified maintenance and documents the call-layer minting hook for when it is wired, rather than forcing a signer into the `corecrux-storage` crate (a layering violation). Confirm this disposition, or direct that dir compaction be wired + receipted as its own milestone.
- **O-2 (`set_horizon` durability):** `set_horizon` mutates `horizon_class` in memory without a journal event, so the change is lost on restart. Out of P4 scope; flagging for a separate durability fix.
- **O-3 (profile note):** the eu-ai-act profile line "every state mutation produces a CROWN receipt" lives in the workspace-root `CLAUDE.md` (wizard-managed), outside this Crux worktree. After M6, regenerate with `crux-config-wizard regenerate` to soften it to "every **erasure/GC/merge** mutation" (writes/supersessions are journaled, not per-op CROWN-signed).
</content>
</invoke>
