# Fact / memory storage-layer mutation-path receipt audit (P4 / M5+M6)

- **ExecPlan:** `verifiable-record-products-2026-07-17` — Phase 1, M5 (audit) + M6 (implementation).
- **Date:** 2026-07-17 (rev 2 — incorporates the GPT-5.6 adversarial review of PR #422).
- **Scope:** every state-mutation path in the fact/memory storage layer (`corecrux-memory::FactStore`, the `corecruxd` background tasks that drive it, the `corecrux-storage` directory LSM, and the tenant-mirror wipe). Threat: **T.4 audit-trail gap** — a mutation that removes/rewrites durable state without a verifiable, loud trail.
- **freshness_horizon:** re-verify file:line before relying after 30 days (the tree moves).

## Classification scheme

- **(a) Receipted** — signed, offline-verifiable CROWN receipt recording who/what/how-many, **or** an append-only, reversible journal event that loses no content.
- **(b) Bypass — needs a receipt** — removes/erases durable content with no verifiable trail. The gap M6 closes; the guard test fails while any remain.
- **KnownGapFollowUp** — a pre-existing *mutate-then-optionally-sign* path whose signed receipt can **silently** fail (same shape the erasure/GC paths had before M6). Out of this PR's scope to fix, but **documented and tracked** (never mislabelled Receipted). The guard requires each to carry a follow-up ref.
- **(c) Justified maintenance** — in-memory derived metadata (rebuilt on restart), or a logically-lossless physical reorganization that emits a structured, replayable maintenance event.

Two guard tests in `crates/corecruxd/tests/mutation_path_receipt_audit.rs`:
1. `every_meaningful_mutation_is_receipted_or_justified` — fails on any `BypassNeedsReceipt`; requires every `KnownGapFollowUp` to name a tracked ref.
2. `no_unregistered_factstore_mutator` — parses `FactStore` for every `pub fn … (&mut self …)` and fails if a mutator is not registered here, so a **new** mutator elsewhere cannot silently escape the audit (review finding 6).

## Audit table

| # | Path | Symbol (file:line) | Classification | Notes |
|---|------|--------------------|----------------|-------|
| 1 | Store / update a fact | `try_store` / `store` ([fact_store.rs:965,978](../crates/corecrux-memory/src/fact_store.rs)) | (a) journaled-additive | Append-only, versioned, reversible. **Note:** the non-fallible `store`/`delete` wrappers log-and-swallow a journal-append error ([fact_store.rs:965](../crates/corecrux-memory/src/fact_store.rs)); durability-critical callers must use the `try_*` variants (which propagate). |
| 2 | Bulk store | `try_store_bulk` / `try_store_bulk_durable` / `store_bulk` ([fact_store.rs](../crates/corecrux-memory/src/fact_store.rs)) | (a) journaled-additive | As #1, batched. `try_store_bulk_durable` uses the same replayable `StoreBatch` event and additionally fsyncs the journal before returning; approval paths use it to make the passport and terminal request facts one durable transaction. |
| 3 | Synced insert (sync pull) | `store_synced` ([fact_store.rs:1643](../crates/corecrux-memory/src/fact_store.rs)) | (a) journaled-additive | Remote-origin fact; tenant re-stamped by caller. |
| 4 | Soft delete (tombstone) | `try_delete` / `delete` ([fact_store.rs:1032,1053](../crates/corecrux-memory/src/fact_store.rs)) | (a) journaled, reversible | Reversible tombstone; content stays until #8 erases it. |
| 5 | Supersede / clear | `mark_superseded` / `clear_superseded` ([fact_store.rs:805,827](../crates/corecrux-memory/src/fact_store.rs)) | (a) journaled, reversible | Reversible; also carried in the merge receipt (#7). |
| 6 | Valid-time update | `set_validity` (`JournalEvent::SetValidity` [fact_store.rs:52](../crates/corecrux-memory/src/fact_store.rs)) | (a) journaled-additive | Sets `[valid_from,valid_to)`; never rewrites value. |
| 7 | **Merge / consolidation** + undo | `consolidate_facts_v1` / `consolidate_undo_v1` ([fact_store.rs:1738,1845](../crates/corecrux-memory/src/fact_store.rs)); mint ([http/consolidation_receipt.rs:41](../crates/corecruxd/src/http/consolidation_receipt.rs)), caller ([http/console.rs:504](../crates/corecruxd/src/http/console.rs)) | **KnownGapFollowUp** | The merge is journaled+reversible (`Consolidate` event), but the signed `ConsolidationReceiptV1` is **best-effort**: `mint_consolidation_receipt` returns `None` when no passport key is present, with no debt signal. Same silent shape #8–#10 had pre-M6. **Not** relabelled Receipted. → follow-up F-2. |
| 8 | **GDPR content erasure** | `compact_journal` ([fact_store.rs:1459](../crates/corecrux-memory/src/fact_store.rs)); driver ([http/admin.rs](../crates/corecruxd/src/http/admin.rs) `compact-facts`) | **(a) receipted (M6)** | Mints a signed `crux.erasure_receipt.v1` on **both** the ordinary and legal-hold-override branches. Durable (fsynced) append; failure is loud (debt counter + `receiptStatus:"pending"`), never silent. |
| 9 | **Retention sweep** | `mark_retention_eligible` ([fact_store.rs:1619](../crates/corecrux-memory/src/fact_store.rs)); caller ([http/admin.rs](../crates/corecruxd/src/http/admin.rs)) | **(a) receipted (M6)** | Now uses the **fallible** `try_delete` (returns only durably-tombstoned ids; no silent swallow). Covered by the erasure receipt's `retention_marked` field, **including on the compaction-failure path** (a partial `compaction:"failed"` receipt is still emitted). |
| 10 | **Ephemeral reserved-fact GC** | `run_sweep_once` / `sweep_and_receipt` / `spawn_ephemeral_gc` ([ephemeral_gc.rs:140,196,213](../crates/corecruxd/src/ephemeral_gc.rs)) | **(a) receipted (M6)** | Hourly sweep of `__session_binding__::*` / `__reverify_receipts__::*`. Mints a signed `crux.gc_receipt.v1` (durable append); failure bumps the debt counter + ERROR. |
| 11 | **Tenant-mirror wipe** | `offboard_tenant_mirror` ([corecrux-memory/src/sync.rs:411](../crates/corecrux-memory/src/sync.rs)) → signed at the http layer | **KnownGapFollowUp** | Delete-then-sign: the wipe runs, then the caller signs the `TenantWipeReceipt`; a signer failure at the http layer leaves the wipe with no durable receipt and no debt signal. → follow-up F-3. |
| 12 | Directory LSM compaction | `compact_directory_until_within_limits` / `compact_dir_run_pair_v1` ([corecrux-storage/src/compact.rs:54,97](../crates/corecrux-storage/src/compact.rs)) | **(c) justified maintenance** | Logically-lossless physical index run-merge; already emits a structured `DirCompactionEventV1` (counts). **Not wired into the daemon** (test-only, gated OFF); lives in the storage crate (no passport key). When wired, the corecruxd caller must mint over the returned events — same call-layer pattern as #8. See O-1. |
| 13 | In-memory metadata | `set_horizon[_for_tenant]` / `reverify[_for_tenant]` / `record_access` ([fact_store.rs:771,785,887](../crates/corecrux-memory/src/fact_store.rs)) | **(c) justified maintenance** | No `append_journal`; derived/ephemeral fields only. (`set_horizon_for_tenant` not journaled = durability nit, out of scope → O-2.) |

## M6 receipt design (paths 8, 9, 10) — as revised for the review

CROWN receipts are minted via `corecruxd::http::observations::mint_governance_receipt`, which:

- takes a **typed** payload struct (`ErasureReceiptV1` / `GcReceiptV1`), never arbitrary JSON;
- uses the **fsynced durable** append (`append_one_durable`), so the receipt is crash-durable before success is reported;
- on any failure (encode / missing key / append) **increments a process-wide audit-debt counter** (`receipt_mint_failures()`) and logs at **ERROR**, then returns `None`. `None` is surfaced by the erasure request path as `receiptStatus:"pending"` — never a silent OK. The mutation itself (e.g. a GDPR erasure) is **not** rolled back or blocked for the sake of the audit record: erasure must proceed even if signing is down, but the debt is made **loud**.

**PII / redaction invariant (finding 2):**
- The signed receipt carries a **bounded `reason_code`** (`gdpr_full_tenant_erasure` | `retention_sweep` | `operator_compaction`) + an **opaque `action_id`** — **never** the operator's free-text `reason` (that stays only in the local `tracing` log, never signed/distributed).
- **Cardinality coarsening:** the receipt records `facts_dropped` (== erased count) + `retention_marked` only. `facts_retained` (full-store live count) is **dropped** — it leaked store cardinality and is not needed to attest an erasure. `tombstones_kept` (== `facts_dropped`) is likewise omitted as redundant.
- Payload builders take **counts, not facts** — content leakage is impossible by construction. Redaction tests seed secret-bearing facts, run the real erasure/sweep, and assert neither the secret nor the free-text reason appears in any receipt field or any file under the data dir.

All new behaviour is additive — no existing receipt format changes.

## Verifier interoperability (finding 5)

The new governance receipts use the **observation JSON envelope + hash-chain** (`ObservationRecordV1`, Ed25519 over the canonical body — same envelope as `legal_hold_overridden` and the session observation stream). The **supported verifier path** is signature-over-canonical-body verification against the daemon passport public key: `erasure_receipt_verifies_through_observation_signature_path` proves an end-to-end round-trip for the erasure schema; the GC schema uses the identical envelope.

Interop limitation: the generic dataplane `receipt_verify` MCP tool reads the receipt **stream**, not these per-session observation JSONL files, and the consolidation receipt uses canonical-CBOR — so a single "one verifier for everything" story does not yet hold. Indexing governance observations as first-class receipt-store records (one verifier surface) is **follow-up F-4**.

## Follow-up (tracked TODOs — deferred, not lost)

- **F-1 — durable pending-receipt outbox + retry.** A mint failure is *counted + logged loud* but not *reconciled*: the receipt is simply pending. Add an on-disk pending-receipt outbox + a retry-until-signed worker so audit debt is eventually cleared, and promote `receipt_mint_failures()` to a scraped Prometheus counter. (`TODO(P4-followup)` at [observations.rs](../crates/corecruxd/src/http/observations.rs) `RECEIPT_MINT_FAILURES`.)
- **F-2 — consolidation receipt loud-failure** (path 7): apply the debt-counter + durable-append treatment used for #8–#10.
- **F-3 — tenant-mirror wipe loud-failure** (path 11): make the wipe receipt loud on signer failure (mint-first-intent or debt counter).
- **F-4 — one-verifier interop**: index governance observation receipts as first-class receipt-store records so the generic verifier finds them.
- **F-5 — GC background-loop test**: drive `spawn_ephemeral_gc` with paused Tokio time + a narrow injected receipt sink (the mint path is already covered directly via `sweep_and_receipt`).

## Open questions for the operator

- **O-1 (dir compaction):** confirm the justified-maintenance disposition (it is unwired + logically lossless), or direct a wire+receipt milestone. The call-layer minting hook is documented in row 12.
- **O-2 (`set_horizon_for_tenant` durability):** `set_horizon_for_tenant` mutates `horizon_class` in memory without a journal event (lost on restart). Out of P4 scope; flagged.
- **O-3 (profile note):** the eu-ai-act line "every state mutation produces a CROWN receipt" (workspace-root `CLAUDE.md`, wizard-managed) overstates. After merge, regenerate to scope it to erasure/GC/merge and to say receipts are *loud-on-failure* (pending + counter), not *guaranteed-synchronous*, until F-1 lands.
- **O-4 (cardinality decision):** confirmed — erasure receipts expose `facts_dropped` + `retention_marked` only; store-size (`facts_retained`) is not exposed. Say if a coarser bucketed count is preferred even for `facts_dropped`.
</content>
