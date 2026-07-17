// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! P4 / M5 — mutation-path receipt audit guard (ExecPlan
//! `verifiable-record-products-2026-07-17`, threat T.4 audit-trail gap).
//!
//! Table-driven enumeration of every state-mutation path in the fact/memory
//! storage layer, each classified. The guard [`every_meaningful_mutation_is_receipted_or_justified`]
//! FAILS if any path is still `BypassNeedsReceipt`.
//!
//! - **RED on the M5 commit**: paths 8/9/10 (GDPR erasure, retention sweep,
//!   ephemeral GC) are `BypassNeedsReceipt`, proving the guard detects the
//!   known bypasses.
//! - **GREEN once M6 lands** their CROWN receipts and flips them to `Receipted`.
//!
//! The full rationale + file:line for every row lives in
//! `docs/receipts-mutation-path-audit-2026-07.md` — keep the two in lock-step.

#[derive(Debug, PartialEq, Eq)]
enum Class {
    /// Signed CROWN receipt, OR an append-only reversible journal event that
    /// loses no content (the journal is the replayable trail).
    Receipted,
    /// Removes/erases durable content with no verifiable trail. The audit gap.
    BypassNeedsReceipt,
    /// In-memory derived metadata, or a logically-lossless physical
    /// reorganization that emits a structured, replayable maintenance event.
    JustifiedMaintenance,
}

struct MutationPath {
    id: u32,
    name: &'static str,
    class: Class,
    /// For a `Receipted` erasure/GC path (8/9/10), the companion test that
    /// proves the receipt is actually minted with counts and no content.
    /// Empty for journaled-additive and justified-maintenance rows.
    backing_test: &'static str,
}

/// Source of truth — mirror of the audit table in
/// `docs/receipts-mutation-path-audit-2026-07.md`.
const PATHS: &[MutationPath] = &[
    MutationPath {
        id: 1,
        name: "FactStore::store/try_store (JournalEvent::Store)",
        class: Class::Receipted,
        backing_test: "",
    },
    MutationPath {
        id: 2,
        name: "FactStore::store_bulk/try_store_bulk (StoreBatch)",
        class: Class::Receipted,
        backing_test: "",
    },
    MutationPath {
        id: 3,
        name: "FactStore::store_synced (sync pull insert)",
        class: Class::Receipted,
        backing_test: "",
    },
    MutationPath {
        id: 4,
        name: "FactStore::delete/try_delete (soft-delete tombstone)",
        class: Class::Receipted,
        backing_test: "",
    },
    MutationPath {
        id: 5,
        name: "FactStore::mark_superseded/clear_superseded",
        class: Class::Receipted,
        backing_test: "",
    },
    MutationPath {
        id: 6,
        name: "FactStore SetValidity (bi-temporal update)",
        class: Class::Receipted,
        backing_test: "",
    },
    MutationPath {
        id: 7,
        name: "consolidate_facts_v1/undo (merge) -> ConsolidationReceiptV1",
        class: Class::Receipted,
        backing_test: "http::consolidation_receipt::tests::consolidation_receipt_verifies_offline_and_tamper_fails",
    },
    // --- M6: CROWN receipts landed; the three live bypasses are now receipted. ---
    MutationPath {
        id: 8,
        name: "compact_journal GDPR content erasure",
        class: Class::Receipted,
        backing_test: "http::admin::compact_facts_tests::compact_facts_mints_erasure_receipt_without_leaking_content",
    },
    MutationPath {
        id: 9,
        name: "mark_retention_eligible retention sweep",
        class: Class::Receipted,
        // Folded into the compact_facts erasure receipt (retention_marked/retention_days fields).
        backing_test: "http::admin::compact_facts_tests::compact_facts_mints_erasure_receipt_without_leaking_content",
    },
    MutationPath {
        id: 10,
        name: "ephemeral reserved-fact GC sweep",
        class: Class::Receipted,
        backing_test: "ephemeral_gc::tests::gc_receipt_payload_never_carries_swept_content",
    },
    // --- justified maintenance ---
    MutationPath {
        id: 11,
        name: "directory LSM compaction (DirCompactionEventV1, unwired)",
        class: Class::JustifiedMaintenance,
        backing_test: "",
    },
    MutationPath {
        id: 12,
        name: "set_horizon/reverify/record_access (in-memory metadata)",
        class: Class::JustifiedMaintenance,
        backing_test: "",
    },
];

/// Guard: no meaningful mutation path may remain an unreceipted bypass.
#[test]
fn every_meaningful_mutation_is_receipted_or_justified() {
    let bypasses: Vec<&str> = PATHS
        .iter()
        .filter(|p| p.class == Class::BypassNeedsReceipt)
        .map(|p| p.name)
        .collect();
    assert!(
        bypasses.is_empty(),
        "T.4 audit-trail gap: {} mutation path(s) erase durable state with no receipt: {:#?}. \
         Land the CROWN receipt (M6) and reclassify in docs/receipts-mutation-path-audit-2026-07.md.",
        bypasses.len(),
        bypasses,
    );
}

/// Every erasure/GC path claimed `Receipted` (ids 8/9/10) must name the
/// companion test that proves its receipt is minted with counts + no content,
/// so "Receipted" can never become a bare label unbacked by a test.
#[test]
fn receipted_erasure_gc_paths_name_a_backing_test() {
    for p in PATHS.iter().filter(|p| matches!(p.id, 8 | 9 | 10)) {
        if p.class == Class::Receipted {
            assert!(
                !p.backing_test.is_empty(),
                "path {} '{}' is Receipted but names no backing receipt-minting test",
                p.id,
                p.name,
            );
        }
    }
}

/// Guard against silently dropping a path from the table.
#[test]
fn table_covers_the_expected_path_count() {
    assert_eq!(
        PATHS.len(),
        12,
        "audit table row count changed — update docs/receipts-mutation-path-audit-2026-07.md and this guard together"
    );
}
