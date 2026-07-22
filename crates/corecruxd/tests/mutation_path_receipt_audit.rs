// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! P4 / M5+M6 — mutation-path receipt audit guard (ExecPlan
//! `verifiable-record-products-2026-07-17`, threat T.4 audit-trail gap).
//!
//! Table-driven enumeration of every state-mutation path in the fact/memory
//! storage layer, each classified. Two guards:
//!
//! 1. [`every_meaningful_mutation_is_receipted_or_justified`] — FAILS if any
//!    path is an unaddressed `BypassNeedsReceipt`, and requires every
//!    `KnownGapFollowUp` to name a tracked follow-up ref (so pre-existing gaps
//!    are documented, never hidden or mislabelled `Receipted`).
//! 2. [`no_unregistered_factstore_mutator`] — parses `FactStore` for every
//!    `pub fn … (&mut self …)` and fails if a mutator is not registered here,
//!    so a NEW mutator added elsewhere cannot silently escape the audit
//!    (review finding 6).
//!
//! The full rationale + file:line for every row lives in
//! `docs/receipts-mutation-path-audit-2026-07.md` — keep the two in lock-step.

#[derive(Debug, PartialEq, Eq)]
enum Class {
    /// Signed CROWN receipt, OR an append-only reversible journal event that
    /// loses no content (the journal is the replayable trail).
    Receipted,
    /// Removes/erases durable content with no verifiable trail. The audit gap
    /// the milestone closes; the guard fails while any remain.
    BypassNeedsReceipt,
    /// Pre-existing mutate-then-optionally-sign path whose signed receipt can
    /// silently fail (same shape as the bypasses before M6, but out of this
    /// PR's scope to fix). Must carry a tracked `followup_ref` — documented,
    /// never mislabelled `Receipted`.
    KnownGapFollowUp,
    /// In-memory derived metadata, or a logically-lossless physical
    /// reorganization that emits a structured, replayable maintenance event.
    JustifiedMaintenance,
}

struct MutationPath {
    id: u32,
    name: &'static str,
    class: Class,
    /// For a `Receipted` erasure/GC path, the companion test that proves the
    /// receipt is actually minted with counts and no content.
    backing_test: &'static str,
    /// Required non-empty for `KnownGapFollowUp` rows.
    followup_ref: &'static str,
}

/// Source of truth — mirror of the audit table in
/// `docs/receipts-mutation-path-audit-2026-07.md`.
const PATHS: &[MutationPath] = &[
    MutationPath {
        id: 1,
        name: "FactStore::try_store (JournalEvent::Store)",
        class: Class::Receipted,
        backing_test: "",
        followup_ref: "",
    },
    MutationPath {
        id: 2,
        name: "FactStore::try_store_bulk/try_store_bulk_durable (StoreBatch)",
        class: Class::Receipted,
        backing_test: "",
        followup_ref: "",
    },
    MutationPath {
        id: 3,
        name: "FactStore::store_synced (sync pull insert)",
        class: Class::Receipted,
        backing_test: "",
        followup_ref: "",
    },
    MutationPath {
        id: 4,
        name: "FactStore::try_delete (soft-delete tombstone)",
        class: Class::Receipted,
        backing_test: "",
        followup_ref: "",
    },
    MutationPath {
        id: 5,
        name: "FactStore::mark_superseded/clear_superseded",
        class: Class::Receipted,
        backing_test: "",
        followup_ref: "",
    },
    MutationPath {
        id: 6,
        name: "FactStore SetValidity (bi-temporal update)",
        class: Class::Receipted,
        backing_test: "",
        followup_ref: "",
    },
    // Mutate-then-optionally-sign: the merge is journaled+reversible, but the
    // signed ConsolidationReceiptV1 is best-effort (mint returns None with no
    // passport key — console.rs:504 -> consolidation_receipt.rs:41). Same silent
    // shape the erasure/GC paths had; needs the debt-counter treatment.
    MutationPath {
        id: 7,
        name: "consolidate_facts_v1/undo (merge) -> ConsolidationReceiptV1",
        class: Class::KnownGapFollowUp,
        backing_test: "",
        followup_ref: "TODO(P4-followup): apply mint-failure debt counter to consolidation receipt",
    },
    // --- M6: CROWN receipts landed; the three live bypasses are now receipted. ---
    MutationPath {
        id: 8,
        name: "compact_journal GDPR content erasure",
        class: Class::Receipted,
        backing_test: "http::admin::compact_facts_tests::compact_facts_mints_erasure_receipt_without_leaking_content",
        followup_ref: "",
    },
    MutationPath {
        id: 9,
        name: "mark_retention_eligible retention sweep",
        class: Class::Receipted,
        backing_test: "http::admin::compact_facts_tests::compact_facts_mints_erasure_receipt_without_leaking_content",
        followup_ref: "",
    },
    MutationPath {
        id: 10,
        name: "ephemeral reserved-fact GC sweep",
        class: Class::Receipted,
        backing_test: "ephemeral_gc::tests::sweep_and_receipt_mints_gc_receipt_for_aged_fact",
        followup_ref: "",
    },
    // Delete-then-sign: the wipe (corecrux-memory/src/sync.rs:411
    // offboard_tenant_mirror) runs, then the caller signs the TenantWipeReceipt
    // at the http layer — a signer failure there leaves the wipe unreceipted.
    MutationPath {
        id: 11,
        name: "offboard_tenant_mirror tenant wipe (delete-then-sign)",
        class: Class::KnownGapFollowUp,
        backing_test: "",
        followup_ref: "TODO(P4-followup): make tenant-mirror wipe receipt loud on signer failure",
    },
    // --- justified maintenance ---
    MutationPath {
        id: 12,
        name: "directory LSM compaction (DirCompactionEventV1, unwired)",
        class: Class::JustifiedMaintenance,
        backing_test: "",
        followup_ref: "",
    },
    MutationPath {
        id: 13,
        name: "set_horizon/reverify/record_access (in-memory metadata)",
        class: Class::JustifiedMaintenance,
        backing_test: "",
        followup_ref: "",
    },
];

/// Guard: no unaddressed bypass; every known gap is tracked.
#[test]
fn every_meaningful_mutation_is_receipted_or_justified() {
    let bypasses: Vec<&str> = PATHS
        .iter()
        .filter(|p| p.class == Class::BypassNeedsReceipt)
        .map(|p| p.name)
        .collect();
    assert!(
        bypasses.is_empty(),
        "T.4 audit-trail gap: {} mutation path(s) erase durable state with no receipt: {:#?}",
        bypasses.len(),
        bypasses,
    );
    for p in PATHS.iter().filter(|p| p.class == Class::KnownGapFollowUp) {
        assert!(
            !p.followup_ref.is_empty(),
            "path {} '{}' is a KnownGapFollowUp but names no tracked follow-up ref",
            p.id,
            p.name,
        );
    }
}

/// Every erasure/GC path claimed `Receipted` (ids 8/9/10) must name the
/// companion test that proves its receipt is minted with counts + no content.
#[test]
fn receipted_erasure_gc_paths_name_a_backing_test() {
    for p in PATHS.iter().filter(|p| matches!(p.id, 8 | 9 | 10)) {
        assert_eq!(p.class, Class::Receipted, "path {} regressed off Receipted", p.id);
        assert!(
            !p.backing_test.is_empty() && p.backing_test.contains("::"),
            "path {} '{}' is Receipted but names no backing receipt-minting test",
            p.id,
            p.name,
        );
    }
}

/// Guard against silently dropping a path from the table.
#[test]
fn table_covers_the_expected_path_count() {
    assert_eq!(
        PATHS.len(),
        13,
        "audit table row count changed — update docs/receipts-mutation-path-audit-2026-07.md and this guard together"
    );
}

/// Fact-store mutators that are NOT durable-state mutations: config/setup
/// setters and in-memory-only derived metadata. Not receipt-relevant.
const NON_DURABLE_MUTATORS: &[&str] = &[
    "set_event_bus",
    "set_embedder",
    "set_embedding_client",
    "set_semantic_dedup",
    "take_near_duplicates",
    "set_horizon",
    "reverify",
    "record_access",
];

/// Durable mutators, each covered by a row above (by symbol).
const AUDITED_MUTATORS: &[&str] = &[
    "store",
    "try_store",
    "store_bulk",
    "try_store_bulk",
    "try_store_bulk_durable",
    "store_synced",
    "delete",
    "try_delete",
    "mark_superseded",
    "clear_superseded",
    "set_validity",
    "mark_retention_eligible",
    "consolidate_facts_v1",
    "consolidate_undo_v1",
];

/// Review finding 6: a NEW `FactStore` mutator added elsewhere must not escape
/// the audit. Parse every `pub fn NAME(… &mut self …)` (single- or multi-line
/// signature) and assert each is registered as audited or explicitly
/// non-durable. Fails loudly on an unregistered mutator.
#[test]
fn no_unregistered_factstore_mutator() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../corecrux-memory/src/fact_store.rs"
    ))
    .expect("read fact_store.rs");
    let lines: Vec<&str> = src.lines().collect();

    let mut unregistered = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("pub fn ") else {
            continue;
        };
        let Some(name) = rest.split('(').next().map(str::trim) else {
            continue;
        };
        // A method is a mutator iff `&mut self` appears in its SIGNATURE (up to
        // the opening `{`). Bounding to the signature avoids bleeding into an
        // adjacent `&mut self` fn; the loop handles multi-line signatures like
        // `consolidate_facts_v1`.
        let mut sig = String::new();
        for l in lines[i..(i + 12).min(lines.len())].iter() {
            sig.push_str(l);
            sig.push(' ');
            if l.contains('{') {
                break;
            }
        }
        if !sig.contains("&mut self") {
            continue;
        }
        if AUDITED_MUTATORS.contains(&name) || NON_DURABLE_MUTATORS.contains(&name) {
            continue;
        }
        unregistered.push(name.to_string());
    }
    assert!(
        unregistered.is_empty(),
        "unregistered FactStore &mut self mutator(s): {unregistered:?} — add to the audit table \
         (docs/receipts-mutation-path-audit-2026-07.md) + AUDITED_MUTATORS/NON_DURABLE_MUTATORS, \
         classified honestly (Receipted / KnownGapFollowUp / JustifiedMaintenance)."
    );
}
