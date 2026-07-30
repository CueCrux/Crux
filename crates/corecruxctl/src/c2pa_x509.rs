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
use rustls_pki_types::{pem::PemObject as _, CertificateDer, UnixTime};
use serde::Serialize;
use x509_cert::der::Decode as _;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage as X509KeyUsage, KeyUsages};
use x509_cert::Certificate;

use corecrux_receipts::vault_pki_x509_signer::{
    Config as SignerConfig, VaultPkiX509Signer, DEFAULT_LEAF_CERT_PATH, DEFAULT_LEAF_KEY_PATH,
    DEFAULT_ROOT_ANCHOR_PATH, ENV_LEAF_CERT_PATH, ENV_ROOT_ANCHOR_PATH,
};
use corecrux_receipts::{parse_jumbf_base64, C2paSignedManifestV1};

/// DER value bytes for id-kp-emailProtection (`1.3.6.1.5.5.7.3.4`).
///
/// The deployed Vault `c2pa-leaf` role and the repository's documented C2PA
/// profile require this EKU. It is deliberately not treated as an arbitrary
/// TLS server/client certificate usage.
const C2PA_EMAIL_PROTECTION_EKU_DER: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04];
const C2PA_EMAIL_PROTECTION_EKU_OID: &str = "1.3.6.1.5.5.7.3.4";

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
    let leaf_cert_path = configured_path(
        opts.leaf_cert_path.as_deref(),
        ENV_LEAF_CERT_PATH,
        DEFAULT_LEAF_CERT_PATH,
    );
    let root_anchor_path = configured_path(
        opts.root_anchor_path.as_deref(),
        ENV_ROOT_ANCHOR_PATH,
        DEFAULT_ROOT_ANCHOR_PATH,
    );
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
    /// `Some(true)` only when a complete cryptographic path validates at the
    /// current time to the configured root anchor. Missing or invalid trust
    /// material is `Some(false)`, never a success-producing `None`. `None` is
    /// reserved for non-X.509/unsupported envelopes.
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

    let (envelope_kind, chain_depth, chain_valid, anchor_sha256, signature_valid, mut notes) =
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
        notes.push(
            "content bytes were not supplied; ok covers the signed manifest and trust path, \
             not binding to an external asset"
                .to_string(),
        );
        None
    };

    // An X.509 trust result is positive only when a configured anchor was
    // loaded and a complete cryptographic path was built. `None` is retained
    // in the report for non-X.509/unsupported envelopes, but it can never be a
    // success shortcut.
    let chain_pass = chain_valid == Some(true);
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

    let anchor_path_buf = configured_path(anchor_path, ENV_ROOT_ANCHOR_PATH, DEFAULT_ROOT_ANCHOR_PATH);
    let (chain_valid, anchor_sha256) =
        validate_chain_from_anchor_path(&chain_der, &anchor_path_buf, UnixTime::now(), &mut notes);

    Ok((
        "x509-p256".to_string(),
        chain_pems.len(),
        chain_valid,
        anchor_sha256,
        signature_valid,
        notes,
    ))
}

fn validate_chain_from_anchor_path(
    chain_der: &[Vec<u8>],
    anchor_path: &Path,
    now: UnixTime,
    notes: &mut Vec<String>,
) -> (Option<bool>, Option<String>) {
    let anchor_bytes = match std::fs::read(anchor_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            notes.push(format!(
                "root anchor not readable at {}: {err} — trust path rejected",
                anchor_path.display()
            ));
            return (Some(false), None);
        }
    };
    let anchor_certs =
        match CertificateDer::pem_slice_iter(&anchor_bytes).collect::<Result<Vec<_>, rustls_pki_types::pem::Error>>() {
            Ok(certs) => certs,
            Err(err) => {
                notes.push(format!(
                    "root anchor at {} is not valid PEM: {err} — trust path rejected",
                    anchor_path.display()
                ));
                return (Some(false), None);
            }
        };
    if anchor_certs.len() != 1 {
        notes.push(format!(
            "root anchor at {} must contain exactly one certificate, found {} — trust path rejected",
            anchor_path.display(),
            anchor_certs.len()
        ));
        return (Some(false), None);
    }
    let anchor_der = anchor_certs[0].as_ref().to_vec();
    let anchor_sha = sha256_fingerprint_colon(&anchor_der);
    match validate_x509_path_at(chain_der, &anchor_der, now) {
        Ok(()) => {
            notes.push(
                "cryptographic X.509 path validated to the configured anchor, including certificate \
                 signatures, validity, CA constraints, and the C2PA signing usage profile; \
                 revocation was not checked"
                    .to_string(),
            );
            (Some(true), Some(anchor_sha))
        }
        Err(err) => {
            notes.push(format!("X.509 trust path rejected: {err}"));
            (Some(false), Some(anchor_sha))
        }
    }
}

fn configured_path(explicit: Option<&Path>, env_name: &str, default: &str) -> PathBuf {
    explicit.map_or_else(
        || {
            std::env::var_os(env_name)
                .filter(|value| !value.is_empty())
                .map_or_else(|| PathBuf::from(default), PathBuf::from)
        },
        Path::to_path_buf,
    )
}

fn validate_x509_path_at(chain_der: &[Vec<u8>], anchor_der: &[u8], now: UnixTime) -> Result<(), String> {
    let leaf_der = chain_der
        .first()
        .ok_or_else(|| "x5chain contains no leaf certificate".to_string())?;
    validate_leaf_profile(leaf_der, now)?;
    for (index, intermediate_der) in chain_der.iter().enumerate().skip(1) {
        validate_ca_profile(intermediate_der, now, &format!("intermediate certificate {index}"))?;
    }
    validate_ca_profile(anchor_der, now, "configured trust anchor")?;
    if chain_der.iter().any(|cert| cert.as_slice() == anchor_der) {
        return Err("x5chain must not contain the configured trust anchor".to_string());
    }

    let leaf = CertificateDer::from(leaf_der.as_slice());
    let intermediates = chain_der[1..]
        .iter()
        .map(|cert| CertificateDer::from(cert.as_slice()))
        .collect::<Vec<_>>();
    let anchor_cert = CertificateDer::from(anchor_der);
    let anchor = webpki::anchor_from_trusted_cert(&anchor_cert)
        .map_err(|err| format!("invalid configured trust anchor: {err}"))?;
    let end_entity =
        webpki::EndEntityCert::try_from(&leaf).map_err(|err| format!("invalid leaf certificate: {err}"))?;
    end_entity
        .verify_for_usage(
            &[webpki::ring::ECDSA_P256_SHA256],
            &[anchor],
            &intermediates,
            now,
            webpki::KeyUsage::required_if_present(C2PA_EMAIL_PROTECTION_EKU_DER),
            None,
            None,
        )
        .map_err(|err| format!("certificate signature/path validation failed: {err}"))?;
    Ok(())
}

fn validate_leaf_profile(der: &[u8], now: UnixTime) -> Result<(), String> {
    let cert = Certificate::from_der(der).map_err(|err| format!("leaf certificate parse failed: {err}"))?;
    validate_cert_time(&cert, now, "leaf certificate")?;

    let (_, constraints) = cert
        .tbs_certificate()
        .get_extension::<BasicConstraints>()
        .map_err(|err| format!("leaf BasicConstraints is malformed: {err}"))?
        .ok_or_else(|| "leaf certificate is missing BasicConstraints CA:FALSE".to_string())?;
    if constraints.ca {
        return Err("leaf certificate asserts BasicConstraints CA:TRUE".to_string());
    }

    let (key_usage_critical, key_usage) = cert
        .tbs_certificate()
        .get_extension::<X509KeyUsage>()
        .map_err(|err| format!("leaf KeyUsage is malformed: {err}"))?
        .ok_or_else(|| "leaf certificate is missing KeyUsage digitalSignature".to_string())?;
    if !key_usage_critical || key_usage != X509KeyUsage(KeyUsages::DigitalSignature.into()) {
        return Err("leaf KeyUsage must be critical and contain only digitalSignature".to_string());
    }

    let (_, extended_key_usage) = cert
        .tbs_certificate()
        .get_extension::<ExtendedKeyUsage>()
        .map_err(|err| format!("leaf ExtendedKeyUsage is malformed: {err}"))?
        .ok_or_else(|| "leaf certificate is missing ExtendedKeyUsage emailProtection".to_string())?;
    if extended_key_usage.0.len() != 1 || extended_key_usage.0[0].to_string() != C2PA_EMAIL_PROTECTION_EKU_OID {
        return Err("leaf ExtendedKeyUsage must contain only emailProtection".to_string());
    }
    Ok(())
}

fn validate_ca_profile(der: &[u8], now: UnixTime, label: &str) -> Result<(), String> {
    let cert = Certificate::from_der(der).map_err(|err| format!("{label} parse failed: {err}"))?;
    validate_cert_time(&cert, now, label)?;

    let (constraints_critical, constraints) = cert
        .tbs_certificate()
        .get_extension::<BasicConstraints>()
        .map_err(|err| format!("{label} BasicConstraints is malformed: {err}"))?
        .ok_or_else(|| format!("{label} is missing BasicConstraints CA:TRUE"))?;
    if !constraints_critical || !constraints.ca {
        return Err(format!("{label} must assert critical BasicConstraints CA:TRUE"));
    }

    let (key_usage_critical, key_usage) = cert
        .tbs_certificate()
        .get_extension::<X509KeyUsage>()
        .map_err(|err| format!("{label} KeyUsage is malformed: {err}"))?
        .ok_or_else(|| format!("{label} is missing KeyUsage keyCertSign"))?;
    if !key_usage_critical || !key_usage.key_cert_sign() {
        return Err(format!("{label} must assert critical KeyUsage keyCertSign"));
    }
    Ok(())
}

fn validate_cert_time(cert: &Certificate, now: UnixTime, label: &str) -> Result<(), String> {
    let validity = cert.tbs_certificate().validity();
    let not_before = validity.not_before.to_unix_duration().as_secs();
    let not_after = validity.not_after.to_unix_duration().as_secs();
    if now.as_secs() < not_before {
        return Err(format!("{label} is not valid yet"));
    }
    if now.as_secs() > not_after {
        return Err(format!("{label} is expired"));
    }
    Ok(())
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
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256};
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
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let kp = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let cert = params.self_signed(&kp).unwrap();
            let root_pem = cert.pem();
            let root_issuer = rcgen::Issuer::new(params, kp);
            Self { root_issuer, root_pem }
        }
        fn sign_csr(&self, csr_pem: &str) -> String {
            let mut csr_params = rcgen::CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
            csr_params.params.is_ca = IsCa::ExplicitNoCa;
            csr_params.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            csr_params.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
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

    #[derive(Clone, Copy)]
    enum TestLeafProfile {
        C2pa,
        WrongKeyUsage,
        WrongExtendedKeyUsage,
    }

    fn m6_test_time() -> UnixTime {
        let timestamp = rcgen::date_time_ymd(2026, 7, 30).unix_timestamp();
        UnixTime::since_unix_epoch(std::time::Duration::from_secs(timestamp as u64))
    }

    fn make_test_ca(
        common_name: &str,
        parent: Option<&rcgen::Issuer<'_, KeyPair>>,
        is_ca: bool,
    ) -> (rcgen::Issuer<'static, KeyPair>, Vec<u8>) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(rcgen::DnType::CommonName, common_name);
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        params.is_ca = if is_ca {
            IsCa::Ca(rcgen::BasicConstraints::Unconstrained)
        } else {
            IsCa::ExplicitNoCa
        };
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = match parent {
            Some(parent) => params.signed_by(&key, parent).unwrap(),
            None => params.self_signed(&key).unwrap(),
        };
        let cert_der = cert.der().to_vec();
        (rcgen::Issuer::new(params, key), cert_der)
    }

    fn make_test_leaf(issuer: &rcgen::Issuer<'_, KeyPair>, profile: TestLeafProfile, expired: bool) -> Vec<u8> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "CueCrux C2PA leaf TEST");
        params.is_ca = IsCa::ExplicitNoCa;
        if expired {
            params.not_before = rcgen::date_time_ymd(2019, 1, 1);
            params.not_after = rcgen::date_time_ymd(2020, 1, 1);
        } else {
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        }
        match profile {
            TestLeafProfile::C2pa => {
                params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
            }
            TestLeafProfile::WrongKeyUsage => {
                params.key_usages = vec![KeyUsagePurpose::KeyEncipherment];
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
            }
            TestLeafProfile::WrongExtendedKeyUsage => {
                params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
                params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            }
        }
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        params.signed_by(&key, issuer).unwrap().der().to_vec()
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
    fn c2pa_verify_with_missing_anchor_fails_closed() {
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
        assert_eq!(report.chain_valid, Some(false));
        assert!(!report.ok, "missing trust material must never be a success shortcut");
        assert!(report.notes.iter().any(|note| note.contains("not readable")));
    }

    #[test]
    fn c2pa_verify_with_malformed_anchor_fails_closed() {
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
        let malformed_anchor = tmp.path().join("malformed-anchor.pem");
        std::fs::write(&malformed_anchor, "not a certificate").unwrap();

        let report = c2pa_verify(&X509VerifyOptions {
            manifest_path: manifest_file,
            content: None,
            root_anchor_path: Some(malformed_anchor),
        })
        .unwrap();
        assert!(report.signature_valid);
        assert_eq!(report.chain_valid, Some(false));
        assert!(!report.ok);
        assert!(report.notes.iter().any(|note| note.contains("exactly one certificate")));
    }

    #[test]
    #[serial_test::serial]
    fn configured_root_anchor_honors_env_and_explicit_precedence() {
        let previous = std::env::var_os(ENV_ROOT_ANCHOR_PATH);
        let env_path = PathBuf::from("/tmp/cuecrux-test-anchor-from-env.pem");
        let explicit_path = PathBuf::from("/tmp/cuecrux-test-anchor-explicit.pem");
        std::env::set_var(ENV_ROOT_ANCHOR_PATH, &env_path);

        let from_env = configured_path(None, ENV_ROOT_ANCHOR_PATH, DEFAULT_ROOT_ANCHOR_PATH);
        let from_explicit = configured_path(
            Some(explicit_path.as_path()),
            ENV_ROOT_ANCHOR_PATH,
            DEFAULT_ROOT_ANCHOR_PATH,
        );

        if let Some(previous) = previous {
            std::env::set_var(ENV_ROOT_ANCHOR_PATH, previous);
        } else {
            std::env::remove_var(ENV_ROOT_ANCHOR_PATH);
        }
        assert_eq!(from_env, env_path);
        assert_eq!(from_explicit, explicit_path);
    }

    #[test]
    fn x509_path_accepts_valid_root_intermediate_leaf_chain() {
        let (root, root_der) = make_test_ca("CueCrux Root", None, true);
        let (intermediate, intermediate_der) = make_test_ca("CueCrux Intermediate", Some(&root), true);
        let leaf_der = make_test_leaf(&intermediate, TestLeafProfile::C2pa, false);

        validate_x509_path_at(&[leaf_der, intermediate_der], &root_der, m6_test_time())
            .expect("valid root/intermediate/leaf path");
    }

    #[test]
    fn x509_path_rejects_forged_intermediate_with_matching_names() {
        let (_trusted_root, trusted_root_der) = make_test_ca("Shared Root Name", None, true);
        let (attacker_root, _attacker_root_der) = make_test_ca("Shared Root Name", None, true);
        let (forged_intermediate, forged_intermediate_der) =
            make_test_ca("Shared Intermediate Name", Some(&attacker_root), true);
        let leaf_der = make_test_leaf(&forged_intermediate, TestLeafProfile::C2pa, false);

        let err =
            validate_x509_path_at(&[leaf_der, forged_intermediate_der], &trusted_root_der, m6_test_time()).unwrap_err();
        assert!(
            err.contains("signature/path validation"),
            "issuer/subject names alone must not establish trust: {err}"
        );
    }

    #[test]
    fn x509_path_rejects_expired_leaf() {
        let (root, root_der) = make_test_ca("CueCrux Root", None, true);
        let (intermediate, intermediate_der) = make_test_ca("CueCrux Intermediate", Some(&root), true);
        let expired_leaf = make_test_leaf(&intermediate, TestLeafProfile::C2pa, true);

        let err = validate_x509_path_at(&[expired_leaf, intermediate_der], &root_der, m6_test_time()).unwrap_err();
        assert!(err.contains("expired"), "{err}");
    }

    #[test]
    fn x509_path_rejects_wrong_leaf_key_usage() {
        let (root, root_der) = make_test_ca("CueCrux Root", None, true);
        let (intermediate, intermediate_der) = make_test_ca("CueCrux Intermediate", Some(&root), true);
        let wrong_usage_leaf = make_test_leaf(&intermediate, TestLeafProfile::WrongKeyUsage, false);

        let err = validate_x509_path_at(&[wrong_usage_leaf, intermediate_der], &root_der, m6_test_time()).unwrap_err();
        assert!(err.contains("KeyUsage"), "{err}");
    }

    #[test]
    fn x509_path_rejects_wrong_leaf_extended_key_usage() {
        let (root, root_der) = make_test_ca("CueCrux Root", None, true);
        let (intermediate, intermediate_der) = make_test_ca("CueCrux Intermediate", Some(&root), true);
        let wrong_usage_leaf = make_test_leaf(&intermediate, TestLeafProfile::WrongExtendedKeyUsage, false);

        let err = validate_x509_path_at(&[wrong_usage_leaf, intermediate_der], &root_der, m6_test_time()).unwrap_err();
        assert!(err.contains("ExtendedKeyUsage"), "{err}");
    }

    #[test]
    fn x509_path_rejects_non_ca_intermediate() {
        let (root, root_der) = make_test_ca("CueCrux Root", None, true);
        let (non_ca_intermediate, intermediate_der) = make_test_ca("Not A CA Intermediate", Some(&root), false);
        let leaf_der = make_test_leaf(&non_ca_intermediate, TestLeafProfile::C2pa, false);

        let err = validate_x509_path_at(&[leaf_der, intermediate_der], &root_der, m6_test_time()).unwrap_err();
        assert!(err.contains("BasicConstraints CA:TRUE"), "{err}");
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
