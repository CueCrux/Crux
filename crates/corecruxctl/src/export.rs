// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl context-export` / `context-verify` — one-shot context
//! portability bundle + offline custody proof
//! (ExecPlan `context-custody-surface-2026-06-30`, M2–M5).
//!
//! The "race to context" exit test asks "*can you export it?*" and "*can you
//! prove what it saw and did?*". Until now export was fragmented (`memory
//! export`, `audit-export`, per-receipt HTTP) and there was no first-class,
//! end-to-end custody proof. This command composes the pieces into one bundle
//! with a **passport-signed manifest** so both answers become one command:
//!
//! ```text
//! corecruxctl context export --data-dir <dir> --out <bundle-dir>
//! corecruxctl context verify <bundle-dir>      # offline, no daemon
//! ```
//!
//! The bundle directory contains:
//! - `memory.cruxpack` — facts + sessions, passport-signed, re-importable via
//!   `corecruxctl memory import` (CRUX_MEMORY_IMPORT=1).
//! - `audit-bundle.tar.zst` — the signed fact journal + receipt references,
//!   offline-verifiable.
//! - `context-manifest.json` — the **custody proof**: an index over both
//!   components (per-component blake3 hashes + counts), the embedded offline
//!   audit-verify report, and an Ed25519 `signature` block from the daemon
//!   passport binding all of the above. `context-verify` re-checks the
//!   signature, the component hashes, and re-runs audit-verify — fully offline.
//!
//! Read-only against `--data-dir` (the `memory export` / `audit-export`
//! precedent — safe while the daemon is up). Private facts are excluded by
//! default; `--include-private` requires the same typed Art.14 consent as
//! `memory export`. Reserved-prefix entries are excluded from the audit half
//! unless `--include-reserved` (operator scope).
//!
//! The signature is over a deterministic `signing_input` string (schema,
//! passport fpr, generated_at, both component hashes, audit-verify ok) — not
//! the JSON — so verification never depends on JSON key ordering. A tampered
//! file fails the hash check; a tampered manifest field fails the signature.

use std::path::{Path, PathBuf};

use corecrux_memory::cruxpack::PrivateSummary;
use crux_session::passport::LocalPassportKey;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

use crate::audit_export::{self, AuditExportArgs};
use crate::memory_pack::{self, MemoryExportArgs};

type BoxErr = Box<dyn std::error::Error + Send + Sync>;

/// Schema tag for the top-level manifest.
pub const CONTEXT_EXPORT_SCHEMA_V1: &str = "crux.context_export.v1";

pub const MEMORY_PACK_FILE: &str = "memory.cruxpack";
pub const AUDIT_BUNDLE_FILE: &str = "audit-bundle.tar.zst";
pub const MANIFEST_FILE: &str = "context-manifest.json";

/// Signature algorithm tag recorded in the manifest.
pub const SIGN_ALG: &str = "ed25519-over-blake3(signing_input)";

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
    /// The embedded offline audit-verify result captured at export time.
    pub audit_verify_ok: bool,
    /// The manifest carries a passport Ed25519 signature (always true on a
    /// successful export — it is the custody proof).
    pub signed: bool,
}

/// Result of an offline `context-verify`.
#[derive(Debug)]
pub struct ContextVerifyReport {
    pub ok: bool,
    pub passport_fpr: String,
    pub signature_valid: bool,
    pub cruxpack_hash_match: bool,
    pub audit_bundle_hash_match: bool,
    pub cruxpack_verify_ok: bool,
    pub audit_verify_ok: bool,
    pub failures: Vec<String>,
}

fn blake3_file(path: &Path) -> Result<String, BoxErr> {
    let bytes = std::fs::read(path)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// Deterministic message the passport signs. Verification reconstructs this
/// from the manifest's own recorded fields, so it never depends on JSON
/// serialization order.
fn build_signing_input(
    passport_fpr: &str,
    generated_at: &str,
    cruxpack_b3: &str,
    audit_b3: &str,
    audit_ok: bool,
) -> String {
    format!(
        "{CONTEXT_EXPORT_SCHEMA_V1}\npassport={passport_fpr}\ngenerated_at={generated_at}\ncruxpack_b3={cruxpack_b3}\naudit_b3={audit_b3}\naudit_verify_ok={audit_ok}"
    )
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

    // 3) component hashes + embedded offline audit-verify report (the proof
    //    pins what the audit half verified to right now).
    let cruxpack_blake3 = blake3_file(&cruxpack_path)?;
    let audit_bundle_blake3 = blake3_file(&audit_bundle_path)?;
    let audit_verify = audit_export::run_audit_verify(&audit_bundle_path, None)?;
    let audit_verify_ok = audit_verify.ok;

    // 4) passport-sign the deterministic binding → the custody proof.
    let key = LocalPassportKey::from_data_dir(&args.data_dir)?;
    let generated_at = chrono::Utc::now().to_rfc3339();
    let signing_input = build_signing_input(
        key.passport_fpr(),
        &generated_at,
        &cruxpack_blake3,
        &audit_bundle_blake3,
        audit_verify_ok,
    );
    let signing_hash = blake3::hash(signing_input.as_bytes());
    let sig = key.sign_hash(signing_hash.as_bytes());

    let manifest = serde_json::json!({
        "schema": CONTEXT_EXPORT_SCHEMA_V1,
        "generated_at": generated_at,
        "tool": format!("corecruxctl {}", env!("CARGO_PKG_VERSION")),
        "tenant": args.tenant,
        "passport_fpr": key.passport_fpr(),
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
        // The embedded offline verification result for the audit half — part of
        // the proof, and re-run independently by `context-verify`.
        "audit_verify": serde_json::to_value(&audit_verify)?,
        // The custody proof: an Ed25519 signature from the daemon passport over
        // the deterministic binding of schema + passport + timestamp + both
        // component hashes + audit-verify ok.
        "signature": {
            "alg": SIGN_ALG,
            "passport_fpr": key.passport_fpr(),
            "public_key_hex": key.public_key_hex(),
            "signed_fields": "schema|passport_fpr|generated_at|cruxpack.blake3|audit-bundle.blake3|audit_verify.ok",
            "signing_input_blake3": signing_hash.to_hex().to_string(),
            "sig_hex": hex::encode(sig),
        },
        "notes": [
            "context-manifest.json is the custody proof: a passport-signed binding of both component hashes + the offline audit-verify result.",
            "Verify offline with `corecruxctl context verify <bundle-dir>` — checks signature, component hashes, and re-runs audit-verify.",
            "Private facts are excluded unless --include-private (Art.14 typed consent); deleted facts are NEVER exported."
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
        audit_verify_ok,
        signed: true,
    })
}

fn manifest_str<'a>(manifest: &'a Value, key: &str) -> Result<&'a str, BoxErr> {
    manifest
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("manifest missing string field '{key}'").into())
}

fn signature_str<'a>(manifest: &'a Value, key: &str) -> Result<&'a str, BoxErr> {
    manifest
        .get("signature")
        .and_then(|s| s.get(key))
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("manifest missing signature.{key}").into())
}

fn component_blake3<'a>(manifest: &'a Value, name: &str) -> Result<&'a str, BoxErr> {
    manifest
        .get("components")
        .and_then(|c| c.as_array())
        .and_then(|arr| {
            arr.iter()
                .find(|c| c.get("name").and_then(|n| n.as_str()) == Some(name))
        })
        .and_then(|c| c.get("blake3"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("manifest missing components[{name}].blake3").into())
}

/// Verify a context-export bundle OFFLINE — no daemon, no network. Checks the
/// passport signature, the per-component blake3 hashes (so a swapped file is
/// caught even though the signature commits to the recorded hash), the cruxpack
/// self-verification, and re-runs audit-verify.
pub fn run_context_verify(bundle_dir: &Path) -> Result<ContextVerifyReport, BoxErr> {
    let manifest_raw = std::fs::read(bundle_dir.join(MANIFEST_FILE))?;
    let manifest: Value = serde_json::from_slice(&manifest_raw)?;
    let mut failures: Vec<String> = Vec::new();

    let passport_fpr = signature_str(&manifest, "passport_fpr")?.to_string();
    let generated_at = manifest_str(&manifest, "generated_at")?;
    let recorded_cruxpack_b3 = component_blake3(&manifest, MEMORY_PACK_FILE)?;
    let recorded_audit_b3 = component_blake3(&manifest, AUDIT_BUNDLE_FILE)?;
    let embedded_audit_ok = manifest
        .get("audit_verify")
        .and_then(|v| v.get("ok"))
        .and_then(|v| v.as_bool())
        .ok_or("manifest missing audit_verify.ok")?;

    // 1) recorded hashes match the files on disk (catches a swapped component).
    let actual_cruxpack_b3 = blake3_file(&bundle_dir.join(MEMORY_PACK_FILE))?;
    let actual_audit_b3 = blake3_file(&bundle_dir.join(AUDIT_BUNDLE_FILE))?;
    let cruxpack_hash_match = actual_cruxpack_b3 == recorded_cruxpack_b3;
    let audit_bundle_hash_match = actual_audit_b3 == recorded_audit_b3;
    if !cruxpack_hash_match {
        failures.push("memory.cruxpack hash does not match the manifest".to_string());
    }
    if !audit_bundle_hash_match {
        failures.push("audit-bundle.tar.zst hash does not match the manifest".to_string());
    }

    // 2) signature over the deterministic binding (uses the RECORDED values, so
    //    a tampered manifest field flips the signature).
    let signing_input = build_signing_input(
        &passport_fpr,
        generated_at,
        recorded_cruxpack_b3,
        recorded_audit_b3,
        embedded_audit_ok,
    );
    let signing_hash = blake3::hash(signing_input.as_bytes());
    let recorded_sih = signature_str(&manifest, "signing_input_blake3")?;
    let sih_match = signing_hash.to_hex().to_string() == recorded_sih;

    let pub_hex = signature_str(&manifest, "public_key_hex")?;
    let sig_hex = signature_str(&manifest, "sig_hex")?;
    let pk_bytes: [u8; 32] = hex::decode(pub_hex)?
        .try_into()
        .map_err(|_| "signature.public_key_hex is not 32 bytes")?;
    let sig_bytes: [u8; 64] = hex::decode(sig_hex)?
        .try_into()
        .map_err(|_| "signature.sig_hex is not 64 bytes")?;
    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)?;
    let signature = Signature::from_bytes(&sig_bytes);
    let ed25519_ok = verifying_key.verify(signing_hash.as_bytes(), &signature).is_ok();
    let signature_valid = sih_match && ed25519_ok;
    if !sih_match {
        failures.push("signing_input hash does not match the manifest (a signed field was altered)".to_string());
    } else if !ed25519_ok {
        failures.push("Ed25519 signature did not verify against the embedded public key".to_string());
    }

    // 3) cruxpack self-verifies (its own content hash + signature).
    let cruxpack_verify_ok = memory_pack::read_and_verify_pack(&bundle_dir.join(MEMORY_PACK_FILE)).is_ok();
    if !cruxpack_verify_ok {
        failures.push("memory.cruxpack failed its own verification".to_string());
    }

    // 4) independently re-run audit-verify (don't trust the embedded result).
    let audit_verify_ok = match audit_export::run_audit_verify(&bundle_dir.join(AUDIT_BUNDLE_FILE), None) {
        Ok(report) => report.ok,
        Err(_) => false,
    };
    if !audit_verify_ok {
        failures.push("audit-bundle.tar.zst failed offline audit-verify".to_string());
    }

    let ok = cruxpack_hash_match && audit_bundle_hash_match && signature_valid && cruxpack_verify_ok && audit_verify_ok;

    Ok(ContextVerifyReport {
        ok,
        passport_fpr,
        signature_valid,
        cruxpack_hash_match,
        audit_bundle_hash_match,
        cruxpack_verify_ok,
        audit_verify_ok,
        failures,
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

    fn export_to(bundle: &Path, data: &Path) -> ContextExportReport {
        run_context_export(
            &ContextExportArgs {
                data_dir: data.to_path_buf(),
                out_dir: bundle.to_path_buf(),
                tenant: "local".into(),
                since: None,
                include_private: false,
                include_reserved: false,
                caller: Some("test".into()),
            },
            |_| panic!("must not prompt without --include-private"),
        )
        .expect("export")
    }

    #[test]
    fn context_export_round_trips_and_is_a_signed_custody_proof() {
        let data = tempfile::tempdir().expect("data");
        seed(data.path());
        let out = tempfile::tempdir().expect("out");
        let bundle = out.path().join("bundle");

        let report = export_to(&bundle, data.path());
        assert_eq!(report.facts, 1, "private fact must be excluded by default");
        assert!(report.signed, "export must produce a signed manifest");
        assert!(report.audit_verify_ok, "embedded audit-verify must be ok");

        // cruxpack half re-import-ready; private value never leaked.
        let pack = memory_pack::read_and_verify_pack(&bundle.join(MEMORY_PACK_FILE)).expect("verify pack");
        assert_eq!(pack.manifest.counts.facts, 1);
        let pack_raw = std::fs::read_to_string(bundle.join(MEMORY_PACK_FILE)).expect("read pack");
        assert!(!pack_raw.contains("private-value-stays-home"), "private value leaked");

        // The custody proof verifies offline, on every axis.
        let v = run_context_verify(&bundle).expect("verify");
        assert!(v.ok, "freshly exported bundle must verify: {v:?}");
        assert!(v.signature_valid);
        assert!(v.cruxpack_hash_match && v.audit_bundle_hash_match);
        assert!(v.cruxpack_verify_ok && v.audit_verify_ok);
        assert!(!v.passport_fpr.is_empty());
    }

    #[test]
    fn tampered_component_fails_verification() {
        let data = tempfile::tempdir().expect("data");
        seed(data.path());
        let out = tempfile::tempdir().expect("out");
        let bundle = out.path().join("bundle");
        export_to(&bundle, data.path());

        // Swap a byte in the audit bundle → hash mismatch + audit-verify fail.
        let p = bundle.join(AUDIT_BUNDLE_FILE);
        let mut raw = std::fs::read(&p).expect("read");
        let mid = raw.len() / 2;
        raw[mid] = raw[mid].wrapping_add(1);
        std::fs::write(&p, raw).expect("write");

        let v = run_context_verify(&bundle).expect("verify runs");
        assert!(!v.ok, "tampered bundle must not verify");
        assert!(!v.audit_bundle_hash_match, "hash mismatch must be detected");
        assert!(!v.failures.is_empty());
    }

    #[test]
    fn tampered_signed_field_fails_signature() {
        let data = tempfile::tempdir().expect("data");
        seed(data.path());
        let out = tempfile::tempdir().expect("out");
        let bundle = out.path().join("bundle");
        export_to(&bundle, data.path());

        // Flip the recorded passport_fpr in the signature block → the
        // reconstructed signing_input no longer matches the signed hash.
        let mp = bundle.join(MANIFEST_FILE);
        let mut manifest: Value = serde_json::from_slice(&std::fs::read(&mp).expect("read")).expect("parse");
        manifest["signature"]["passport_fpr"] = Value::String("forged-fpr".into());
        std::fs::write(&mp, serde_json::to_vec_pretty(&manifest).expect("ser")).expect("write");

        let v = run_context_verify(&bundle).expect("verify runs");
        assert!(!v.signature_valid, "altered signed field must break the signature");
        assert!(!v.ok);
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
        assert!(!bundle.join(MEMORY_PACK_FILE).exists());
        assert!(!bundle.join(MANIFEST_FILE).exists());
    }
}
