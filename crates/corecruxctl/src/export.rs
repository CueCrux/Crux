// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl context-export` — one-shot context portability bundle
//! (ExecPlan `context-custody-surface-2026-06-30`, M2).
//!
//! The "race to context" exit test asks "*can you export it?*" — and until now
//! the answer was a fragmented "yes, three different ways": `memory export`
//! (facts + sessions → `.cruxpack`), `audit-export` (the fact journal +
//! receipt references → signed tar.zst), and per-receipt HTTP exports. This
//! command composes those into a single bundle directory so the answer becomes
//! one command:
//!
//! ```text
//! corecruxctl context-export --data-dir <dir> --out <bundle-dir>
//! ```
//!
//! The bundle directory contains:
//! - `memory.cruxpack` — facts + sessions, passport-signed, re-importable via
//!   `corecruxctl memory import` (CRUX_MEMORY_IMPORT=1).
//! - `audit-bundle.tar.zst` — the signed fact journal + receipt references,
//!   offline-verifiable via `corecruxctl audit-verify`.
//! - `context-manifest.json` — an index over both components: schema, the
//!   exporting passport fingerprint, per-component blake3 hashes + counts, and
//!   re-hydration hints.
//!
//! Read-only against `--data-dir` (the `memory export` / `audit-export`
//! precedent — safe to run while the daemon is up). Private facts are excluded
//! by default; `--include-private` requires the same typed Art.14 consent as
//! `memory export`. Reserved-prefix entries are excluded from the audit half
//! unless `--include-reserved` (operator scope).
//!
//! Each component is independently signed; the manifest is an index that pins
//! their hashes (an outer manifest signature is a deferred follow-up — see the
//! ExecPlan). `context-import` is not a new verb: the cruxpack re-imports via
//! the existing `memory import` path, which is authenticated + journaled.

use std::path::{Path, PathBuf};

use corecrux_memory::cruxpack::PrivateSummary;

use crate::audit_export::{self, AuditExportArgs};
use crate::memory_pack::{self, MemoryExportArgs};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// Schema tag for the top-level manifest.
pub const CONTEXT_EXPORT_SCHEMA_V1: &str = "crux.context_export.v1";

pub const MEMORY_PACK_FILE: &str = "memory.cruxpack";
pub const AUDIT_BUNDLE_FILE: &str = "audit-bundle.tar.zst";
pub const MANIFEST_FILE: &str = "context-manifest.json";

#[derive(Debug)]
pub struct ContextExportArgs {
    /// Daemon data dir holding `facts.jsonl`, `sessions/`, and `passport.key`.
    pub data_dir: PathBuf,
    /// Output **directory** that receives the bundle (created if absent).
    pub out_dir: PathBuf,
    /// Tenant id stamped on the cruxpack (default `local`).
    pub tenant: String,
    /// RFC3339 lower bound (inclusive); applied to both halves.
    pub since: Option<String>,
    /// Copy born-private facts into the cruxpack (Art.14 typed consent).
    pub include_private: bool,
    /// Include reserved-prefix entries in the audit half (operator scope).
    pub include_reserved: bool,
    /// Caller label embedded in the audit-bundle scope.
    pub caller: Option<String>,
}

#[derive(Debug)]
pub struct ContextExportReport {
    pub out_dir: PathBuf,
    pub facts: usize,
    pub sessions: usize,
    pub audit_facts: u64,
    pub receipts: u64,
    pub passport_fpr: String,
    pub manifest_blake3: String,
    pub cruxpack_blake3: String,
    pub audit_bundle_blake3: String,
}

fn blake3_file(path: &Path) -> Result<String, BoxErr> {
    let bytes = std::fs::read(path)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// Run the one-shot context export. `confirm_include_private` is invoked (with
/// the private-fact scan) only when `--include-private` is set; returning
/// `false` aborts before anything is written — identical semantics to
/// `memory export` (the closure is forwarded straight through).
pub fn run_context_export(
    args: &ContextExportArgs,
    confirm_include_private: impl FnOnce(&PrivateSummary) -> bool,
) -> Result<ContextExportReport, BoxErr> {
    std::fs::create_dir_all(&args.out_dir)?;

    let cruxpack_path = args.out_dir.join(MEMORY_PACK_FILE);
    let audit_bundle_path = args.out_dir.join(AUDIT_BUNDLE_FILE);
    let manifest_path = args.out_dir.join(MANIFEST_FILE);

    // 1) facts + sessions → signed, re-importable cruxpack. This is the half
    //    that honours the --include-private consent gate; if the operator
    //    declines, run_memory_export returns ConfirmationDeclined and we abort
    //    before writing the audit half or the manifest.
    let mem = memory_pack::run_memory_export(
        &MemoryExportArgs {
            data_dir: args.data_dir.clone(),
            out: cruxpack_path.clone(),
            tenant: args.tenant.clone(),
            since: args.since.clone(),
            include_private: args.include_private,
        },
        confirm_include_private,
    )?;

    // 2) fact journal + receipt references → signed, offline-verifiable bundle.
    let (audit_facts, receipts, bundle_id) = audit_export::run_audit_export(AuditExportArgs {
        data_dir: args.data_dir.clone(),
        out: audit_bundle_path.clone(),
        since: args.since.clone(),
        until: None,
        scope_entity_prefix: None,
        include_reserved: args.include_reserved,
        caller: args.caller.clone(),
    })?;

    // 3) index manifest pinning both components by blake3.
    let cruxpack_blake3 = blake3_file(&cruxpack_path)?;
    let audit_bundle_blake3 = blake3_file(&audit_bundle_path)?;

    let manifest = serde_json::json!({
        "schema": CONTEXT_EXPORT_SCHEMA_V1,
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "tool": format!("corecruxctl {}", env!("CARGO_PKG_VERSION")),
        "tenant": args.tenant,
        "passport_fpr": mem.passport_fpr,
        "include_private": args.include_private,
        "include_reserved": args.include_reserved,
        "components": [
            {
                "name": MEMORY_PACK_FILE,
                "role": "facts + sessions (passport-signed)",
                "rehydrate": "corecruxctl memory import --file memory.cruxpack (requires CRUX_MEMORY_IMPORT=1)",
                "blake3": cruxpack_blake3,
                "cruxpack_content_hash": mem.blake3_content_hash,
                "facts": mem.facts,
                "sessions": mem.sessions,
            },
            {
                "name": AUDIT_BUNDLE_FILE,
                "role": "signed fact journal + receipt references",
                "verify": "corecruxctl audit-verify audit-bundle.tar.zst",
                "blake3": audit_bundle_blake3,
                "bundle_id": bundle_id,
                "facts": audit_facts,
                "receipts": receipts,
            }
        ],
        "notes": [
            "Each component is independently signed; this manifest is an index pinning their blake3 hashes.",
            "Private facts are excluded unless --include-private (Art.14 typed consent); deleted facts are NEVER exported.",
            "This bundle answers the context-custody exit test's 'can you export it?' as one command."
        ]
    });

    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    std::fs::write(&manifest_path, &manifest_bytes)?;
    let manifest_blake3 = blake3::hash(&manifest_bytes).to_hex().to_string();

    Ok(ContextExportReport {
        out_dir: args.out_dir.clone(),
        facts: mem.facts,
        sessions: mem.sessions,
        audit_facts,
        receipts,
        passport_fpr: mem.passport_fpr,
        manifest_blake3,
        cruxpack_blake3,
        audit_bundle_blake3,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_memory::fact_store::{FactStore, StoreFact};
    use std::path::Path;

    fn seed(dir: &Path) {
        let mut store = FactStore::with_persistence(dir).expect("store");
        store.store(StoreFact {
            entity: "project-alpha".into(),
            key: "status".into(),
            value: "public-value".into(),
            source_receipt: Some("r_alpha_1".into()),
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.store(StoreFact {
            entity: "secret".into(),
            key: "k".into(),
            value: "private-value-stays-home".into(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
    }

    #[test]
    fn context_export_round_trips_facts_sessions_and_receipts() {
        let data = tempfile::tempdir().expect("data");
        seed(data.path());
        let out = tempfile::tempdir().expect("out");
        let bundle = out.path().join("bundle");

        let report = run_context_export(
            &ContextExportArgs {
                data_dir: data.path().to_path_buf(),
                out_dir: bundle.clone(),
                tenant: "local".into(),
                since: None,
                include_private: false,
                include_reserved: false,
                caller: Some("test".into()),
            },
            |_| panic!("must not prompt without --include-private"),
        )
        .expect("export");

        // Public fact present in both halves; private excluded by default.
        assert_eq!(report.facts, 1, "private fact must be excluded by default");

        // cruxpack half: verifies + re-import-ready (facts + sessions).
        let pack = memory_pack::read_and_verify_pack(&bundle.join(MEMORY_PACK_FILE)).expect("verify pack");
        assert_eq!(pack.manifest.counts.facts, 1);
        let pack_raw = std::fs::read_to_string(bundle.join(MEMORY_PACK_FILE)).expect("read pack");
        assert!(
            !pack_raw.contains("private-value-stays-home"),
            "private value leaked into bundle"
        );

        // audit half: offline-verifiable + carries the receipt reference.
        let verify = audit_export::run_audit_verify(&bundle.join(AUDIT_BUNDLE_FILE), None).expect("verify audit");
        assert!(verify.ok, "audit bundle must verify offline: {verify:?}");
        assert_eq!(verify.receipt_count, 1, "the r_alpha_1 receipt ref must travel");

        // manifest: present, parses, lists both components, pins hashes.
        let manifest_raw = std::fs::read(bundle.join(MANIFEST_FILE)).expect("read manifest");
        let manifest: serde_json::Value = serde_json::from_slice(&manifest_raw).expect("parse manifest");
        assert_eq!(manifest["schema"], CONTEXT_EXPORT_SCHEMA_V1);
        assert_eq!(manifest["components"].as_array().expect("components").len(), 2);
        assert_eq!(manifest["components"][0]["blake3"], report.cruxpack_blake3);
        assert_eq!(manifest["include_private"], false);
        assert!(
            !report.passport_fpr.is_empty(),
            "bundle is attributed to the data-dir passport"
        );
    }

    #[test]
    fn include_private_consent_decline_aborts_before_any_write() {
        let data = tempfile::tempdir().expect("data");
        seed(data.path());
        let out = tempfile::tempdir().expect("out");
        let bundle = out.path().join("bundle");

        let err = run_context_export(
            &ContextExportArgs {
                data_dir: data.path().to_path_buf(),
                out_dir: bundle.clone(),
                tenant: "local".into(),
                since: None,
                include_private: true,
                include_reserved: false,
                caller: None,
            },
            |summary| {
                assert_eq!(summary.private_flagged, 1);
                false // operator declines
            },
        );
        assert!(err.is_err(), "declined consent must abort");
        // The cruxpack is never written, so the audit half + manifest never run.
        assert!(!bundle.join(MEMORY_PACK_FILE).exists());
        assert!(!bundle.join(MANIFEST_FILE).exists());
    }
}
