// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl audit-export` + `audit-verify` — BYO Audit Trail (agent-ux-11).
//!
//! `audit-export` loads the fact-store journal from a daemon data dir,
//! filters by `--since`/`--until`/`--scope`, and writes a signed,
//! third-party-verifiable bundle to `--out`. It does NOT require the
//! daemon to be running — the journal is the source of truth on disk.
//!
//! `audit-verify` is fully OFFLINE: it reads the bundle, re-computes
//! content hashes, and re-verifies the Ed25519 signature against the
//! pinned public key embedded in the manifest.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};

use corecrux_memory::FactStore;
use corecrux_receipts::{
    build_bundle_v1, resolve_audit_export_signing_key, verify_bundle_pinned_v1, AuditBundleScopeV1, AuditEventV1,
    AuditReceiptRefV1, BuildBundleInputV1, ExpectedSignerV1, VerifyReportV1, WitnessLogPublicKeyV1,
};

const RESERVED_PREFIXES: &[&str] = &["__agent::", "__ops::", "__bootstrap__::", "__agent_session::"];

#[derive(Debug, Clone)]
pub struct AuditExportArgs {
    /// Data dir holding the `facts.jsonl` journal.
    pub data_dir: PathBuf,
    /// Output bundle path (e.g. `audit-bundle.tar.zst`).
    pub out: PathBuf,
    /// RFC3339 lower bound (inclusive).
    pub since: Option<String>,
    /// RFC3339 upper bound (exclusive).
    pub until: Option<String>,
    /// Optional entity-prefix filter.
    pub scope_entity_prefix: Option<String>,
    /// If set, include reserved-prefix entries (operator scope).
    pub include_reserved: bool,
    /// Caller label embedded in the manifest scope.
    pub caller: Option<String>,
}

/// Build a bundle by replaying the on-disk fact journal. Returns the
/// number of events + receipt references written.
pub fn run_audit_export(args: AuditExportArgs) -> Result<(u64, u64, String), Box<dyn std::error::Error + Send + Sync>> {
    let store = FactStore::with_persistence(&args.data_dir)?;
    let since_dt = parse_rfc3339(args.since.as_deref())?;
    let until_dt = parse_rfc3339(args.until.as_deref())?;

    let mut all: Vec<_> = store.all_facts().collect();
    all.sort_by(|a, b| a.stored_at.cmp(&b.stored_at).then_with(|| a.fact_id.cmp(&b.fact_id)));

    let mut events: Vec<AuditEventV1> = Vec::new();
    let mut receipt_refs: Vec<AuditReceiptRefV1> = Vec::new();
    for fact in all {
        if let Some(since) = since_dt {
            if fact.stored_at < since {
                continue;
            }
        }
        if let Some(until) = until_dt {
            if fact.stored_at >= until {
                continue;
            }
        }
        if let Some(prefix) = &args.scope_entity_prefix {
            if !fact.entity.starts_with(prefix) {
                continue;
            }
        }
        if is_reserved(&fact.entity) && !args.include_reserved {
            continue;
        }
        events.push(AuditEventV1 {
            fact_id: fact.fact_id.clone(),
            entity: fact.entity.clone(),
            key: fact.key.clone(),
            value: fact.value.clone(),
            source_receipt: fact.source_receipt.clone(),
            confidence: fact.confidence,
            stored_at: fact.stored_at.to_rfc3339(),
            tokens: fact.tokens,
            deleted: fact.deleted,
            version: fact.version,
            supersedes: fact.supersedes.clone(),
        });
        if let Some(rid) = &fact.source_receipt {
            receipt_refs.push(AuditReceiptRefV1 {
                fact_id: fact.fact_id.clone(),
                receipt_id: rid.clone(),
            });
        }
    }

    let now = Utc::now();
    let scope_record = AuditBundleScopeV1 {
        entity_prefix: args.scope_entity_prefix,
        include_reserved: args.include_reserved,
        caller: args.caller,
    };
    let bundle_id = format!("bundle-{}", uuid::Uuid::new_v4().simple());
    let resolved_key = resolve_audit_export_signing_key(Some(&args.data_dir))?;

    let built = build_bundle_v1(BuildBundleInputV1 {
        bundle_id: bundle_id.clone(),
        since_rfc3339: since_dt.map_or_else(|| "1970-01-01T00:00:00Z".to_string(), |dt| dt.to_rfc3339()),
        until_rfc3339: until_dt.map_or_else(|| now.to_rfc3339(), |dt| dt.to_rfc3339()),
        generated_at_rfc3339: now.to_rfc3339(),
        scope: scope_record,
        events,
        receipt_refs,
        // corecruxctl exports facts only; witness proofs are populated by the
        // daemon-side assembler (it has the witness store / data_dir).
        witness_proofs: Vec::new(),
        signing_key: &resolved_key.signing_key,
        signer_key_id: resolved_key.signer_key_id,
        key_class: resolved_key.key_class,
    })?;

    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let file = std::fs::File::create(&args.out)?;
    built.write_tar_zst(file)?;
    Ok((built.manifest.fact_count, built.manifest.receipt_count, bundle_id))
}

/// Verify a bundle on disk and return a structured report. Fully OFFLINE.
///
/// `expected` pins the issuer (play03 D2): the signature check alone only says
/// the bundle is consistent with the key it carries, so a bundle re-signed by
/// someone else passes it. With a pin, a different issuer forces `ok = false`;
/// without one the report is labelled `UNPINNED — trust unproven`.
pub fn run_audit_verify(
    path: &Path,
    rekor_pubkey_path: Option<&Path>,
    expected: Option<&ExpectedSignerV1>,
) -> Result<VerifyReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let raw = std::fs::read(path)?;
    let log_key = match rekor_pubkey_path {
        Some(p) => Some(load_log_public_key(p)?),
        None => None,
    };
    let report = verify_bundle_pinned_v1(&raw, log_key.as_ref(), expected)?;
    Ok(report)
}

/// Load a transparency-log public key for checkpoint/SET trust-root
/// verification: a 32-byte file is Ed25519 (self-hosted logs); otherwise a P-256
/// SPKI key in PEM or DER (public-good Rekor). A base64-wrapped 32-byte Ed25519
/// key is also accepted.
fn load_log_public_key(path: &Path) -> Result<WitnessLogPublicKeyV1, Box<dyn std::error::Error + Send + Sync>> {
    use base64::Engine as _;
    let raw = std::fs::read(path)?;
    if let Some(key) = WitnessLogPublicKeyV1::parse(&raw) {
        return Ok(key);
    }
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(String::from_utf8_lossy(&raw).trim()) {
        if let Some(key) = WitnessLogPublicKeyV1::parse(&decoded) {
            return Ok(key);
        }
    }
    Err(format!(
        "rekor pubkey at {} is not an Ed25519 (32-byte/base64) or P-256 (PEM/DER) key",
        path.display()
    )
    .into())
}

fn parse_rfc3339(value: Option<&str>) -> Result<Option<DateTime<Utc>>, Box<dyn std::error::Error + Send + Sync>> {
    let Some(raw) = value else { return Ok(None) };
    let dt = DateTime::parse_from_rfc3339(raw).map(|dt| dt.with_timezone(&Utc))?;
    Ok(Some(dt))
}

fn is_reserved(entity: &str) -> bool {
    RESERVED_PREFIXES.iter().any(|p| entity.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_memory::fact_store::StoreFact;

    #[test]
    fn export_then_verify_round_trip() {
        let data_td = tempfile::tempdir().unwrap();
        // Seed the journal via the persistent store.
        {
            let mut store = FactStore::with_persistence(data_td.path()).unwrap();
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "project-x".to_string(),
                key: "k".to_string(),
                value: "v".to_string(),
                source_receipt: Some("r_abc".to_string()),
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "__ops::config-audit".to_string(),
                key: "sha256:abc".to_string(),
                value: "audited".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }

        let out_td = tempfile::tempdir().unwrap();
        let out = out_td.path().join("bundle.tar.zst");

        // Non-operator export should strip the reserved entry.
        let (facts, receipts, bundle_id) = run_audit_export(AuditExportArgs {
            data_dir: data_td.path().to_path_buf(),
            out: out.clone(),
            since: None,
            until: None,
            scope_entity_prefix: None,
            include_reserved: false,
            caller: Some("test-caller".to_string()),
        })
        .unwrap();
        assert_eq!(facts, 1, "reserved-prefix fact should be filtered out");
        assert_eq!(receipts, 1);
        assert!(!bundle_id.is_empty());

        let report = run_audit_verify(&out, None, None).unwrap();
        assert!(
            report.ok,
            "offline verifier should accept freshly built bundle: {report:?}"
        );
        assert_eq!(report.fact_count, 1);
        assert_eq!(report.receipt_count, 1);
    }

    #[test]
    fn operator_export_includes_reserved() {
        let data_td = tempfile::tempdir().unwrap();
        {
            let mut store = FactStore::with_persistence(data_td.path()).unwrap();
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "__ops::config-audit".to_string(),
                key: "sha256:abc".to_string(),
                value: "audited".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }
        let out_td = tempfile::tempdir().unwrap();
        let out = out_td.path().join("bundle.tar.zst");
        let (facts, _, _) = run_audit_export(AuditExportArgs {
            data_dir: data_td.path().to_path_buf(),
            out: out.clone(),
            since: None,
            until: None,
            scope_entity_prefix: None,
            include_reserved: true,
            caller: None,
        })
        .unwrap();
        assert_eq!(facts, 1);
        let report = run_audit_verify(&out, None, None).unwrap();
        assert!(report.ok);
    }

    #[test]
    fn tampered_bundle_fails_verification() {
        // Build a valid bundle.
        let data_td = tempfile::tempdir().unwrap();
        {
            let mut store = FactStore::with_persistence(data_td.path()).unwrap();
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "project-x".to_string(),
                key: "k".to_string(),
                value: "v".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }
        let out_td = tempfile::tempdir().unwrap();
        let out = out_td.path().join("bundle.tar.zst");
        run_audit_export(AuditExportArgs {
            data_dir: data_td.path().to_path_buf(),
            out: out.clone(),
            since: None,
            until: None,
            scope_entity_prefix: None,
            include_reserved: false,
            caller: None,
        })
        .unwrap();

        // Flip a byte in the middle of the file.
        let mut raw = std::fs::read(&out).unwrap();
        let mid = raw.len() / 2;
        raw[mid] = raw[mid].wrapping_add(1);
        std::fs::write(&out, raw).unwrap();

        // Either zstd will reject the corruption (Err) or the verifier
        // will catch the content-hash mismatch (Ok with !ok). Both are
        // acceptable failure modes.
        match run_audit_verify(&out, None, None) {
            Ok(report) => {
                assert!(!report.ok, "tampered bundle should not pass verification: {report:?}");
            }
            Err(_) => { /* fail-fast on corruption is fine */ }
        }
    }
}
