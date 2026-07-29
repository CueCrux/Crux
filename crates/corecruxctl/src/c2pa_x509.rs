// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl c2pa-cert-status`, `corecruxctl c2pa-rotate-leaf`, and
//! `corecruxctl c2pa-verify` — operator-facing CLI surface for the
//! Vault PKI X.509 C2PA signer (agent-ux-07 M6).
//!
//! All three commands are OFFLINE-safe by default except
//! `c2pa-rotate-leaf`, which intentionally talks to Vault to mint a
//! fresh leaf.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use base64::Engine as _;
use serde::Serialize;
use x509_cert::der::Decode as _;
use x509_cert::Certificate;

use corecrux_receipts::vault_pki_x509_signer::{
    Config as SignerConfig, VaultPkiX509Signer, DEFAULT_LEAF_CERT_PATH, DEFAULT_LEAF_KEY_PATH, DEFAULT_ROOT_ANCHOR_PATH,
};
use corecrux_receipts::{parse_jumbf_base64, C2paSignedManifestV1};

/// One certificate summarised for `c2pa-cert-status` output.
#[derive(Debug, Clone, Serialize)]
pub struct CertSummary {
    pub subject: String,
    pub issuer: String,
    pub not_before: String,
    pub not_after: String,
    pub days_to_expiry: i64,
    /// `"green"` (>=30 d), `"yellow"` (>=7 d), or `"red"` (<7 d).
    pub urgency: String,
    pub sha256_fingerprint: String,
}

/// Output of `c2pa-cert-status`.
#[derive(Debug, Clone, Serialize)]
pub struct CertStatusReport {
    pub leaf_cert_path: PathBuf,
    pub root_anchor_path: PathBuf,
    pub chain_depth: usize,
    pub leaf: Option<CertSummary>,
    pub anchor_sha256: Option<String>,
    pub notes: Vec<String>,
}

/// Options for `c2pa-cert-status` / `c2pa-rotate-leaf` / `c2pa-verify`.
#[derive(Debug, Clone)]
pub struct StatusOptions {
    pub leaf_cert_path: Option<PathBuf>,
    pub root_anchor_path: Option<PathBuf>,
}

pub fn cert_status(opts: &StatusOptions) -> Result<CertStatusReport, Box<dyn std::error::Error + Send + Sync>> {
    let leaf_cert_path = opts
        .leaf_cert_path
        .clone()
        .map_or_else(|| PathBuf::from(DEFAULT_LEAF_CERT_PATH), |p| p);
    let root_anchor_path = opts
        .root_anchor_path
        .clone()
        .map_or_else(|| PathBuf::from(DEFAULT_ROOT_ANCHOR_PATH), |p| p);
    let mut notes: Vec<String> = Vec::new();

    let leaf_pem = match std::fs::read_to_string(&leaf_cert_path) {
        Ok(s) => Some(s),
        Err(e) => {
            notes.push(format!(
                "leaf cert not readable at {}: {} (run `corecruxctl c2pa-rotate-leaf` to mint one)",
                leaf_cert_path.display(),
                e
            ));
            None
        }
    };
    let chain_pems: Vec<String> = leaf_pem.as_deref().map(split_pem_certs).unwrap_or_default();
    let leaf_summary = if let Some(pem) = chain_pems.first() {
        let der = pem_cert_to_der(pem)?;
        Some(summarise_cert(&der)?)
    } else {
        None
    };

    let anchor_sha256 = match std::fs::read_to_string(&root_anchor_path) {
        Ok(pem) => {
            let pems = split_pem_certs(&pem);
            if let Some(first) = pems.first() {
                let der = pem_cert_to_der(first)?;
                Some(sha256_fingerprint_colon(&der))
            } else {
                notes.push(format!(
                    "root anchor PEM at {} has no certificates",
                    root_anchor_path.display()
                ));
                None
            }
        }
        Err(e) => {
            notes.push(format!(
                "root anchor not readable at {}: {}",
                root_anchor_path.display(),
                e
            ));
            None
        }
    };

    if let Some(summary) = &leaf_summary {
        match summary.urgency.as_str() {
            "red" => notes.push(format!(
                "LEAF EXPIRING IN {} DAYS — run `corecruxctl c2pa-rotate-leaf`",
                summary.days_to_expiry
            )),
            "yellow" => notes.push(format!(
                "leaf expires in {} days — schedule a rotation",
                summary.days_to_expiry
            )),
            _ => {}
        }
    }

    Ok(CertStatusReport {
        leaf_cert_path,
        root_anchor_path,
        chain_depth: chain_pems.len(),
        leaf: leaf_summary,
        anchor_sha256,
        notes,
    })
}

/// Output of `c2pa-rotate-leaf`.
#[derive(Debug, Clone, Serialize)]
pub struct RotateReport {
    pub rotated: bool,
    pub leaf_cert_path: PathBuf,
    pub new_leaf: CertSummary,
    pub notes: Vec<String>,
}

pub fn rotate_leaf(opts: &StatusOptions) -> Result<RotateReport, Box<dyn std::error::Error + Send + Sync>> {
    // Build signer from env (VAULT_ADDR / VAULT_TOKEN required).
    let mut config = SignerConfig::from_env().map_err(|e| {
        format!("VaultPkiX509Signer config from env failed: {e} (need VAULT_ADDR + VAULT_TOKEN at minimum)")
    })?;
    if let Some(leaf_cert) = &opts.leaf_cert_path {
        config.leaf_cert_path.clone_from(leaf_cert);
    }
    if let Some(root_anchor) = &opts.root_anchor_path {
        config.root_anchor_path.clone_from(root_anchor);
    }
    if opts.leaf_cert_path.is_some() {
        // Mirror the override across the key path too — operators
        // typically pin the whole signer state to a single dir.
        if let Some(stem) = config.leaf_cert_path.file_stem().and_then(|s| s.to_str()) {
            let key_path = config.leaf_cert_path.with_file_name(format!("{stem}.key.pem"));
            config.leaf_key_path = key_path;
        }
    }
    let signer = VaultPkiX509Signer::new(config.clone());
    signer.regenerate_leaf()?;
    let chain_pem = signer
        .current_leaf_chain_pem()
        .ok_or("rotate succeeded but signer reported no leaf state")?;
    let chain_pems = split_pem_certs(&chain_pem);
    let leaf_pem = chain_pems
        .first()
        .ok_or("rotate succeeded but emitted no certificates")?;
    let leaf_der = pem_cert_to_der(leaf_pem)?;
    let summary = summarise_cert(&leaf_der)?;
    Ok(RotateReport {
        rotated: true,
        leaf_cert_path: config.leaf_cert_path,
        new_leaf: summary,
        notes: vec!["leaf rotated successfully; verifiers will accept it once they have the root anchor".to_string()],
    })
}

/// Output of `c2pa-verify` (X.509-aware verifier).
#[derive(Debug, Clone, Serialize)]
pub struct X509VerifyReport {
    pub manifest_id: String,
    pub spec_version: String,
    pub signer_alg: String,
    pub signer_key_id: String,
    pub envelope_kind: String,
    pub chain_depth: usize,
    pub anchor_sha256: Option<String>,
    pub canonical_hash_match: bool,
    pub signature_valid: bool,
    pub content_hash_match: Option<bool>,
    pub chain_valid: Option<bool>,
    pub ok: bool,
    pub notes: Vec<String>,
}

/// Options for `c2pa-verify`.
#[derive(Debug, Clone)]
pub struct X509VerifyOptions {
    pub manifest_path: PathBuf,
    pub content: Option<PathBuf>,
    pub root_anchor_path: Option<PathBuf>,
}

pub fn c2pa_verify(opts: &X509VerifyOptions) -> Result<X509VerifyReport, Box<dyn std::error::Error + Send + Sync>> {
    let envelope_b64 = std::fs::read_to_string(&opts.manifest_path)?;
    let parsed = parse_jumbf_base64(envelope_b64.trim())?;

    let (envelope_kind, chain_depth, chain_valid, anchor_sha256, signature_valid, notes) =
        if parsed.signature_alg == "ed25519" {
            // Defer to the legacy Ed25519 verifier path.
            let mut notes = vec![
                "envelope is legacy Ed25519 (CROWN); use `corecruxctl output-verify` for richer Ed25519-specific output"
                    .to_string(),
            ];
            // Without the verifying key in scope here we can't
            // cryptographically check the Ed25519 signature; surface the
            // limitation rather than silently report `false`.
            notes.push(
                "Ed25519 signature verification skipped (X.509 verifier doesn't carry the ed25519 verifying key)"
                    .to_string(),
            );
            ("ed25519".to_string(), 0, None, None, false, notes)
        } else if parsed.signature_alg == "es256" {
            verify_x509_envelope(&parsed, opts.root_anchor_path.as_deref())?
        } else {
            // Algorithm-confusion guard. `signature_alg` lives OUTSIDE the
            // signed body, so an attacker can relabel a genuine ES256 envelope
            // with any other identifier. The X.509 verifier only implements
            // ES256 (ECDSA-P256-SHA256); refuse to route an unknown label to it
            // rather than verifying the P-256 signature anyway and reporting
            // ok=true under a bogus alg. Mirrors the daemon's
            // `verify_c2pa_signed_manifest_es256_v1`, which rejects non-es256
            // envelopes up front.
            let notes = vec![format!(
                "unsupported signature algorithm {:?}: the X.509 verifier only implements es256 (ECDSA-P256-SHA256)",
                parsed.signature_alg
            )];
            (
                format!("unsupported:{}", parsed.signature_alg),
                0,
                None,
                None,
                false,
                notes,
            )
        };

    let canonical_hash_match = canonical_hash_matches(&parsed);
    let content_hash_match = if let Some(path) = &opts.content {
        let content_bytes = std::fs::read(path)?;
        let recomputed = blake3::hash(&content_bytes).to_hex().to_string();
        Some(recomputed == parsed.manifest.content_hash_blake3_hex)
    } else {
        None
    };

    let chain_pass = chain_valid.unwrap_or(true);
    let ok = canonical_hash_match && signature_valid && content_hash_match.unwrap_or(true) && chain_pass;

    Ok(X509VerifyReport {
        manifest_id: parsed.manifest.manifest_id.clone(),
        spec_version: parsed.manifest.spec_version.clone(),
        signer_alg: parsed.signature_alg.clone(),
        signer_key_id: parsed.key_id.clone(),
        envelope_kind,
        chain_depth,
        anchor_sha256,
        canonical_hash_match,
        signature_valid,
        content_hash_match,
        chain_valid,
        ok,
        notes,
    })
}

#[allow(clippy::type_complexity)]
fn verify_x509_envelope(
    parsed: &C2paSignedManifestV1,
    anchor_path: Option<&Path>,
) -> Result<
    (
        String,         // envelope_kind
        usize,          // chain_depth
        Option<bool>,   // chain_valid
        Option<String>, // anchor_sha256
        bool,           // signature_valid
        Vec<String>,    // notes
    ),
    Box<dyn std::error::Error + Send + Sync>,
> {
    use p256::ecdsa::signature::Verifier as _;
    use p256::ecdsa::{Signature as P256Sig, VerifyingKey as P256VerifyingKey};

    let mut notes: Vec<String> = Vec::new();
    let chain_pem = parsed
        .x5chain_pem
        .as_ref()
        .ok_or("X.509 envelope is missing the x5chain")?;
    let chain_pems = split_pem_certs(chain_pem);
    if chain_pems.is_empty() {
        return Err("x5chain contains no certificates".into());
    }
    let chain_der: Vec<Vec<u8>> = chain_pems
        .iter()
        .map(|p| pem_cert_to_der(p))
        .collect::<Result<_, _>>()?;
    let leaf = Certificate::from_der(&chain_der[0])?;
    let leaf_spki = leaf
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .ok_or("leaf subject_public_key has non-octet bits")?
        .to_vec();
    let verifying_key =
        P256VerifyingKey::from_sec1_bytes(&leaf_spki).map_err(|e| format!("leaf SPKI is not a P-256 point: {e}"))?;
    let sig = P256Sig::from_der(&parsed.signature).map_err(|e| format!("signature is not DER ECDSA: {e}"))?;
    // True ES256: verify the ECDSA-P256 signature as ECDSA-over-SHA-256 of
    // the canonical body bytes — the `es256` algorithm identifier's real
    // meaning. Mirrors `verify_c2pa_signed_manifest_es256_v1` (the daemon
    // provenance path), so a manifest that verifies here verifies there.
    let signature_valid = verifying_key.verify(&parsed.canonical_body_bytes, &sig).is_ok();

    let anchor_path_buf = anchor_path.map_or_else(|| PathBuf::from(DEFAULT_ROOT_ANCHOR_PATH), Path::to_path_buf);
    let (chain_valid, anchor_sha256) = match std::fs::read_to_string(&anchor_path_buf) {
        Ok(anchor_pem) => {
            let anchor_pems = split_pem_certs(&anchor_pem);
            if anchor_pems.is_empty() {
                notes.push(format!(
                    "anchor PEM at {} is empty — chain not validated",
                    anchor_path_buf.display()
                ));
                (None, None)
            } else {
                let anchor_der = pem_cert_to_der(&anchor_pems[0])?;
                let anchor_sha = sha256_fingerprint_colon(&anchor_der);
                // Walk: each cert's issuer must equal the next cert's
                // subject, ending at the anchor's subject. We're not
                // cryptographically verifying intermediate signatures
                // here — see notes — but we do check the chain
                // links and reject mismatched names.
                let mut valid = true;
                let mut prev_issuer: Option<String> = Some(leaf.tbs_certificate().issuer().to_string());
                for der in &chain_der[1..] {
                    let cert = Certificate::from_der(der)?;
                    let subj = cert.tbs_certificate().subject().to_string();
                    if prev_issuer.as_deref() != Some(subj.as_str()) {
                        valid = false;
                        notes.push(format!(
                            "chain break: expected subject {:?}, got {:?}",
                            prev_issuer, subj
                        ));
                        break;
                    }
                    prev_issuer = Some(cert.tbs_certificate().issuer().to_string());
                }
                // Last-link check: prev_issuer must equal anchor subject.
                let anchor_cert = Certificate::from_der(&anchor_der)?;
                let anchor_subj = anchor_cert.tbs_certificate().subject().to_string();
                if valid && prev_issuer.as_deref() != Some(anchor_subj.as_str()) {
                    valid = false;
                    notes.push(format!(
                        "anchor subject {:?} does not match expected issuer {:?}",
                        anchor_subj, prev_issuer
                    ));
                }
                notes.push(
                    "chain walk validates subject/issuer linkage to the anchor; intermediate signature \
                     verification is delegated to platform CA libraries"
                        .to_string(),
                );
                (Some(valid), Some(anchor_sha))
            }
        }
        Err(e) => {
            notes.push(format!(
                "root anchor not readable at {}: {} — chain not validated",
                anchor_path_buf.display(),
                e
            ));
            (None, None)
        }
    };

    Ok((
        "x509-p256".to_string(),
        chain_pems.len(),
        chain_valid,
        anchor_sha256,
        signature_valid,
        notes,
    ))
}

fn canonical_hash_matches(parsed: &C2paSignedManifestV1) -> bool {
    let recomputed = blake3::hash(&parsed.canonical_body_bytes);
    *recomputed.as_bytes() == parsed.canonical_body_hash
}

fn summarise_cert(der: &[u8]) -> Result<CertSummary, Box<dyn std::error::Error + Send + Sync>> {
    let cert = Certificate::from_der(der)?;
    let subject = cert.tbs_certificate().subject().to_string();
    let issuer = cert.tbs_certificate().issuer().to_string();
    let not_before = format_validity(
        cert.tbs_certificate()
            .validity()
            .not_before
            .to_unix_duration()
            .as_secs(),
    );
    let not_after_secs = cert.tbs_certificate().validity().not_after.to_unix_duration().as_secs();
    let not_after = format_validity(not_after_secs);
    let now_secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days_to_expiry = (not_after_secs as i64 - now_secs as i64) / 86_400;
    let urgency = if days_to_expiry < 7 {
        "red"
    } else if days_to_expiry < 30 {
        "yellow"
    } else {
        "green"
    }
    .to_string();
    Ok(CertSummary {
        subject,
        issuer,
        not_before,
        not_after,
        days_to_expiry,
        urgency,
        sha256_fingerprint: sha256_fingerprint_colon(der),
    })
}

fn format_validity(unix_secs: u64) -> String {
    // ISO-8601 UTC without milliseconds.
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix_secs as i64, 0).map_or_else(
        || format!("unix:{unix_secs}"),
        |dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
    )
}

fn sha256_fingerprint_colon(der: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(der);
    let out = h.finalize();
    let mut parts = Vec::with_capacity(32);
    for b in &out {
        parts.push(format!("{b:02X}"));
    }
    parts.join(":")
}

fn split_pem_certs(pem: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut inside = false;
    for line in pem.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            inside = true;
            buf.clear();
            buf.push_str(line);
            buf.push('\n');
        } else if line.starts_with("-----END CERTIFICATE-----") {
            buf.push_str(line);
            buf.push('\n');
            out.push(buf.clone());
            buf.clear();
            inside = false;
        } else if inside {
            buf.push_str(line);
            buf.push('\n');
        }
    }
    out
}

fn pem_cert_to_der(pem: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let trimmed = pem.trim();
    let start = trimmed
        .find("-----BEGIN CERTIFICATE-----")
        .ok_or("missing BEGIN CERTIFICATE")?;
    let body_start = start + "-----BEGIN CERTIFICATE-----".len();
    let end = trimmed[body_start..]
        .find("-----END CERTIFICATE-----")
        .ok_or("missing END CERTIFICATE")?;
    let b64 = trimmed[body_start..body_start + end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    let der = base64::engine::general_purpose::STANDARD.decode(b64.as_bytes())?;
    Ok(der)
}

/// Helper for `c2pa-cert-status --leaf-key-path` argument resolution.
pub fn default_leaf_key_path() -> PathBuf {
    PathBuf::from(DEFAULT_LEAF_KEY_PATH)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use corecrux_receipts::vault_pki_x509_signer::{Config, VaultPkiX509Signer, VaultSignResponse};
    use corecrux_receipts::{build_c2pa_manifest_v1, sign_c2pa_manifest_via_signer, C2paManifestInputV1};
    use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    struct TestPki {
        // rcgen 0.14 bundles the issuing params + signing key into an `Issuer`,
        // which is what CSR `signed_by` now consumes (single argument).
        root_issuer: rcgen::Issuer<'static, KeyPair>,
        root_pem: String,
    }
    impl TestPki {
        fn new() -> Self {
            let mut params = CertificateParams::new(vec!["CueCrux C2PA Root TEST".to_string()]).unwrap();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "CueCrux C2PA Root TEST");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let cert = params.self_signed(&kp).unwrap();
            let root_pem = cert.pem();
            let root_issuer = rcgen::Issuer::new(params, kp);
            Self { root_issuer, root_pem }
        }
        fn sign_csr(&self, csr_pem: &str) -> String {
            let csr_params = rcgen::CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
            csr_params.signed_by(&self.root_issuer).unwrap().pem()
        }
    }

    fn make_signer(tmp: &TempDir, pki: TestPki) -> VaultPkiX509Signer {
        let cfg = Config {
            vault_addr: "http://vault.test.invalid".into(),
            vault_token: "t".into(),
            vault_cacert_path: None,
            pki_mount: "pki-c2pa".into(),
            leaf_key_path: tmp.path().join("leaf.key.pem"),
            leaf_cert_path: tmp.path().join("leaf.cert.pem"),
            root_anchor_path: tmp.path().join("root.cert.pem"),
            leaf_ttl_hours: 720,
            leaf_common_name: "cuecrux daemon C2PA signer".into(),
        };
        let root_pem = pki.root_pem.clone();
        std::fs::write(&cfg.root_anchor_path, root_pem.as_bytes()).unwrap();
        let pki_arc = Arc::new(Mutex::new(pki));
        let post_fn = {
            let pki_arc = pki_arc.clone();
            let root_pem = root_pem.clone();
            Arc::new(
                move |_cfg: &Config,
                      csr_pem: &str|
                      -> corecrux_receipts::vault_pki_x509_signer::Result<VaultSignResponse> {
                    let pki = pki_arc.lock().unwrap();
                    let leaf = pki.sign_csr(csr_pem);
                    Ok(VaultSignResponse {
                        certificate_pem: leaf,
                        ca_chain_pem: vec![root_pem.clone()],
                    })
                },
            )
        };
        VaultPkiX509Signer::with_post_fn(cfg, post_fn)
    }

    #[test]
    fn cert_status_reports_green_for_fresh_leaf() {
        let tmp = TempDir::new().unwrap();
        let signer = make_signer(&tmp, TestPki::new());
        signer.regenerate_leaf().unwrap();
        let report = cert_status(&StatusOptions {
            leaf_cert_path: Some(tmp.path().join("leaf.cert.pem")),
            root_anchor_path: Some(tmp.path().join("root.cert.pem")),
        })
        .unwrap();
        let leaf = report.leaf.expect("expected leaf to be present");
        assert_eq!(leaf.urgency, "green", "fresh 30-day leaf should be green");
        assert!(leaf.days_to_expiry > 25);
        assert!(!leaf.sha256_fingerprint.is_empty());
        assert!(report.anchor_sha256.is_some());
        // The signer drops self-signed roots from the leaf chain (the
        // x5chain convention is leaf + intermediates only), so the
        // leaf PEM file contains exactly one cert here.
        assert_eq!(report.chain_depth, 1);
    }

    #[test]
    fn cert_status_handles_missing_leaf() {
        let tmp = TempDir::new().unwrap();
        let report = cert_status(&StatusOptions {
            leaf_cert_path: Some(tmp.path().join("nope.cert.pem")),
            root_anchor_path: Some(tmp.path().join("nope.root.pem")),
        })
        .unwrap();
        assert!(report.leaf.is_none());
        assert!(report.notes.iter().any(|n| n.contains("not readable")));
    }

    #[test]
    fn c2pa_verify_round_trip_x509_envelope() {
        let tmp = TempDir::new().unwrap();
        let signer = make_signer(&tmp, TestPki::new());
        signer.regenerate_leaf().unwrap();
        let content = b"verify-me";
        let manifest = build_c2pa_manifest_v1(&C2paManifestInputV1 {
            content_bytes: content,
            content_type: Some("image/png"),
            crown_receipt_id: "r_v",
            signer_passport: "passport:test",
            claim_generator: "cuecrux/test",
            manifest_id: "urn:cuecrux:c2pa:vt",
            when: "2026-05-28T00:00:00Z",
            model: None,
        });
        let signed = sign_c2pa_manifest_via_signer(manifest, &signer, "2026-05-28T00:00:00Z").unwrap();
        let envelope = signed.to_jumbf_base64();
        let manifest_file = tmp.path().join("env.jumbf");
        std::fs::write(&manifest_file, envelope.as_bytes()).unwrap();
        let content_file = tmp.path().join("content.bin");
        std::fs::write(&content_file, content).unwrap();
        let report = c2pa_verify(&X509VerifyOptions {
            manifest_path: manifest_file,
            content: Some(content_file),
            root_anchor_path: Some(tmp.path().join("root.cert.pem")),
        })
        .unwrap();
        assert_eq!(report.envelope_kind, "x509-p256");
        assert!(report.canonical_hash_match);
        assert!(report.signature_valid, "X.509 signature must verify");
        assert_eq!(report.content_hash_match, Some(true));
        assert_eq!(report.chain_valid, Some(true), "chain walk to anchor must pass");
        assert!(report.ok);
    }

    #[test]
    fn c2pa_verify_detects_tampered_content() {
        let tmp = TempDir::new().unwrap();
        let signer = make_signer(&tmp, TestPki::new());
        signer.regenerate_leaf().unwrap();
        let content = b"original";
        let manifest = build_c2pa_manifest_v1(&C2paManifestInputV1 {
            content_bytes: content,
            content_type: None,
            crown_receipt_id: "r_t",
            signer_passport: "p",
            claim_generator: "g",
            manifest_id: "urn:t",
            when: "t",
            model: None,
        });
        let signed = sign_c2pa_manifest_via_signer(manifest, &signer, "t").unwrap();
        let manifest_file = tmp.path().join("env.jumbf");
        std::fs::write(&manifest_file, signed.to_jumbf_base64()).unwrap();
        let content_file = tmp.path().join("tampered.bin");
        std::fs::write(&content_file, b"TAMPERED").unwrap();
        let report = c2pa_verify(&X509VerifyOptions {
            manifest_path: manifest_file,
            content: Some(content_file),
            root_anchor_path: Some(tmp.path().join("root.cert.pem")),
        })
        .unwrap();
        assert!(report.signature_valid, "manifest signature stays valid");
        assert_eq!(report.content_hash_match, Some(false));
        assert!(!report.ok);
    }

    #[test]
    fn c2pa_verify_with_missing_anchor_pins_chain_to_none() {
        let tmp = TempDir::new().unwrap();
        let signer = make_signer(&tmp, TestPki::new());
        signer.regenerate_leaf().unwrap();
        let manifest = build_c2pa_manifest_v1(&C2paManifestInputV1 {
            content_bytes: b"x",
            content_type: None,
            crown_receipt_id: "r",
            signer_passport: "p",
            claim_generator: "g",
            manifest_id: "u",
            when: "t",
            model: None,
        });
        let signed = sign_c2pa_manifest_via_signer(manifest, &signer, "t").unwrap();
        let manifest_file = tmp.path().join("env.jumbf");
        std::fs::write(&manifest_file, signed.to_jumbf_base64()).unwrap();
        let report = c2pa_verify(&X509VerifyOptions {
            manifest_path: manifest_file,
            content: None,
            root_anchor_path: Some(tmp.path().join("does-not-exist.pem")),
        })
        .unwrap();
        // Signature still verifies against the leaf SPKI.
        assert!(report.signature_valid);
        assert_eq!(report.chain_valid, None);
        // OK because chain check is None (can't validate without anchor).
        assert!(report.ok);
    }

    // Quiet the `unused` warning for the deferred legacy-envelope hook
    // — `c2pa_verify` flagging an ed25519 envelope returns the legacy
    // kind string but doesn't crypto-check (richer path lives in
    // output_verify::run). Keep the assertion to lock the contract.
    #[test]
    fn c2pa_verify_reports_ed25519_envelope_kind() {
        let tmp = TempDir::new().unwrap();
        // Mint a legacy Ed25519 envelope via the existing helper.
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let manifest = build_c2pa_manifest_v1(&C2paManifestInputV1 {
            content_bytes: b"ed25519",
            content_type: None,
            crown_receipt_id: "r",
            signer_passport: "p",
            claim_generator: "g",
            manifest_id: "u",
            when: "t",
            model: None,
        });
        let signed = corecrux_receipts::sign_c2pa_manifest_v1(manifest, &sk, "k", "t").unwrap();
        let manifest_file = tmp.path().join("env.jumbf");
        std::fs::write(&manifest_file, signed.to_jumbf_base64()).unwrap();
        let report = c2pa_verify(&X509VerifyOptions {
            manifest_path: manifest_file,
            content: None,
            root_anchor_path: None,
        })
        .unwrap();
        assert_eq!(report.envelope_kind, "ed25519");
        assert!(report.notes.iter().any(|n| n.contains("legacy Ed25519")));
    }

    #[test]
    fn c2pa_verify_rejects_relabelled_es256_algorithm() {
        // Algorithm-confusion guard: take a genuine ES256 envelope, relabel its
        // `signature_alg` (which is OUTSIDE the signed body) to an unknown
        // identifier, and confirm the verifier refuses it instead of routing
        // the P-256 signature to the ES256 path and reporting ok=true.
        let tmp = TempDir::new().unwrap();
        let signer = make_signer(&tmp, TestPki::new());
        signer.regenerate_leaf().unwrap();
        let content = b"relabel-me";
        let manifest = build_c2pa_manifest_v1(&C2paManifestInputV1 {
            content_bytes: content,
            content_type: None,
            crown_receipt_id: "r_relabel",
            signer_passport: "p",
            claim_generator: "g",
            manifest_id: "u",
            when: "t",
            model: None,
        });
        let mut signed = sign_c2pa_manifest_via_signer(manifest, &signer, "t").unwrap();
        // Tamper: swap the honest "es256" label for a bogus one.
        signed.signature_alg = "es999".to_string();
        let manifest_file = tmp.path().join("relabelled.jumbf");
        std::fs::write(&manifest_file, signed.to_jumbf_base64()).unwrap();
        let content_file = tmp.path().join("content.bin");
        std::fs::write(&content_file, content).unwrap();
        let report = c2pa_verify(&X509VerifyOptions {
            manifest_path: manifest_file,
            content: Some(content_file),
            root_anchor_path: Some(tmp.path().join("root.cert.pem")),
        })
        .unwrap();
        assert!(report.envelope_kind.starts_with("unsupported:"));
        assert!(!report.signature_valid, "must NOT verify a relabelled envelope");
        assert!(!report.ok);
        assert!(report
            .notes
            .iter()
            .any(|n| n.contains("unsupported signature algorithm")));
    }
}
