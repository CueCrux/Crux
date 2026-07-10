// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl output-verify` — offline verifier for C2PA Content
//! Credentials produced by the `output_attest` MCP tool (agent-ux-07).
//!
//! Reads a JUMBF envelope file (the same `manifest_jumbf_base64` payload
//! the tool returns), validates the canonical-body hash + Ed25519
//! signature, optionally re-hashes content bytes, and optionally
//! cross-references the embedded CROWN receipt id. No network calls —
//! the verifying key is supplied via `--pub-key-hex` or
//! `CRUX_C2PA_VERIFY_PUBLIC_KEY_HEX`.

use std::path::PathBuf;

use ed25519_dalek::VerifyingKey;
use serde::Serialize;

use corecrux_receipts::{assert_crown_receipt_id_v1, parse_jumbf_base64, verify_c2pa_manifest_v1};

const VERIFY_KEY_ENV: &str = "CRUX_C2PA_VERIFY_PUBLIC_KEY_HEX";

#[derive(Debug, Clone)]
pub struct Options {
    pub manifest_path: PathBuf,
    pub content: Option<PathBuf>,
    pub pub_key_hex: Option<String>,
    pub expected_receipt: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub manifest_id: String,
    pub spec_version: String,
    pub crown_receipt_id: String,
    pub signer_key_id: String,
    pub canonical_hash_match: bool,
    pub signature_valid: bool,
    pub content_hash_match: Option<bool>,
    pub receipt_id_cross_reference: Option<bool>,
    pub ok: bool,
    pub notes: Vec<String>,
}

pub fn run(opts: &Options) -> Result<Report, Box<dyn std::error::Error + Send + Sync>> {
    let envelope_b64 = std::fs::read_to_string(&opts.manifest_path)?;
    let parsed = parse_jumbf_base64(envelope_b64.trim())?;

    let pub_key_hex = opts
        .pub_key_hex
        .clone()
        .or_else(|| std::env::var(VERIFY_KEY_ENV).ok())
        .ok_or_else(|| format!("verifying key missing: pass --pub-key-hex <64-hex-chars> or set {VERIFY_KEY_ENV}"))?;
    let pub_key_hex = pub_key_hex.trim();
    if pub_key_hex.len() != 64 {
        return Err(format!(
            "verifying key must be 64 hex chars (32 bytes); got {} chars",
            pub_key_hex.len()
        )
        .into());
    }
    let key_bytes = hex_decode(pub_key_hex).ok_or("verifying key is not valid hex")?;
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let verifying_key = VerifyingKey::from_bytes(&key_arr)?;

    let (content_hash_match, content_note) = if let Some(path) = &opts.content {
        let bytes = std::fs::read(path)?;
        let report = verify_c2pa_manifest_v1(&parsed, &bytes, &verifying_key)?;
        (Some(report.content_hash_match), None)
    } else {
        // No content bytes — verify the manifest signature only.
        // Pass empty bytes; the report's content_hash_match field will
        // be false (which we ignore) but canonical_hash_match +
        // signature_valid are independent of `content`.
        let _report = verify_c2pa_manifest_v1(&parsed, &[], &verifying_key)?;
        (
            None,
            Some("content bytes not supplied (--content); content-hash check skipped".to_string()),
        )
    };

    let full_report = verify_c2pa_manifest_v1(
        &parsed,
        // Re-use the same bytes for the authoritative report so the
        // canonical-hash and signature checks reflect reality even when
        // content was not provided.
        opts.content
            .as_ref()
            .map(std::fs::read)
            .transpose()?
            .as_deref()
            .unwrap_or(&[]),
        &verifying_key,
    )?;

    let receipt_id_cross_reference = opts
        .expected_receipt
        .as_ref()
        .map(|expected| assert_crown_receipt_id_v1(&parsed, expected).is_ok());

    let mut notes = Vec::new();
    if let Some(n) = content_note {
        notes.push(n);
    }
    notes.push(
        "Engineering scaffolding aligned with EU AI Act Art. 50; legal conformity assessment remains the operator's responsibility.".to_string(),
    );

    let ok = full_report.canonical_hash_match
        && full_report.signature_valid
        && content_hash_match.unwrap_or(true)
        && receipt_id_cross_reference.unwrap_or(true);

    Ok(Report {
        manifest_id: full_report.manifest_id,
        spec_version: parsed.manifest.spec_version,
        crown_receipt_id: full_report.crown_receipt_id,
        signer_key_id: full_report.signer_key_id,
        canonical_hash_match: full_report.canonical_hash_match,
        signature_valid: full_report.signature_valid,
        content_hash_match,
        receipt_id_cross_reference,
        ok,
        notes,
    })
}

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = char::from(bytes[i]).to_digit(16)?;
        let lo = char::from(bytes[i + 1]).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use corecrux_receipts::{build_c2pa_manifest_v1, sign_c2pa_manifest_v1, C2paManifestInputV1};
    use ed25519_dalek::SigningKey;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn sign_envelope(content: &[u8], receipt: &str, key: [u8; 32]) -> String {
        let sk = SigningKey::from_bytes(&key);
        let manifest = build_c2pa_manifest_v1(&C2paManifestInputV1 {
            content_bytes: content,
            content_type: Some("image/png"),
            crown_receipt_id: receipt,
            signer_passport: "passport:test",
            claim_generator: "cuecrux/test",
            manifest_id: "urn:cuecrux:c2pa:test",
            when: "2026-05-27T12:00:00Z",
            model: None,
        });
        let signed = sign_c2pa_manifest_v1(manifest, &sk, "k_test", "2026-05-27T12:00:00Z").unwrap();
        signed.to_jumbf_base64()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    fn write_tmp(contents: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(contents).unwrap();
        f
    }

    #[test]
    fn happy_path_round_trip() {
        let key = [9u8; 32];
        let envelope = sign_envelope(b"clean-content", "r_happy", key);
        let manifest_file = write_tmp(envelope.as_bytes());
        let content_file = write_tmp(b"clean-content");

        let vk = SigningKey::from_bytes(&key).verifying_key();
        let report = run(&Options {
            manifest_path: manifest_file.path().to_path_buf(),
            content: Some(content_file.path().to_path_buf()),
            pub_key_hex: Some(hex_encode(vk.as_bytes())),
            expected_receipt: Some("r_happy".to_string()),
        })
        .unwrap();
        assert!(report.ok, "got {report:?}");
        assert!(report.canonical_hash_match);
        assert!(report.signature_valid);
        assert_eq!(report.content_hash_match, Some(true));
        assert_eq!(report.receipt_id_cross_reference, Some(true));
    }

    #[test]
    fn tampered_content_fails() {
        let key = [10u8; 32];
        let envelope = sign_envelope(b"original", "r_tamper", key);
        let manifest_file = write_tmp(envelope.as_bytes());
        let content_file = write_tmp(b"TAMPERED");
        let vk = SigningKey::from_bytes(&key).verifying_key();
        let report = run(&Options {
            manifest_path: manifest_file.path().to_path_buf(),
            content: Some(content_file.path().to_path_buf()),
            pub_key_hex: Some(hex_encode(vk.as_bytes())),
            expected_receipt: None,
        })
        .unwrap();
        assert!(!report.ok);
        assert_eq!(report.content_hash_match, Some(false));
    }

    #[test]
    fn wrong_receipt_id_fails() {
        let key = [11u8; 32];
        let envelope = sign_envelope(b"x", "r_actual", key);
        let manifest_file = write_tmp(envelope.as_bytes());
        let content_file = write_tmp(b"x");
        let vk = SigningKey::from_bytes(&key).verifying_key();
        let report = run(&Options {
            manifest_path: manifest_file.path().to_path_buf(),
            content: Some(content_file.path().to_path_buf()),
            pub_key_hex: Some(hex_encode(vk.as_bytes())),
            expected_receipt: Some("r_other".to_string()),
        })
        .unwrap();
        assert!(!report.ok);
        assert_eq!(report.receipt_id_cross_reference, Some(false));
    }

    #[test]
    fn missing_content_yields_na_with_signature_check() {
        let key = [12u8; 32];
        let envelope = sign_envelope(b"unused", "r_no_content", key);
        let manifest_file = write_tmp(envelope.as_bytes());
        let vk = SigningKey::from_bytes(&key).verifying_key();
        let report = run(&Options {
            manifest_path: manifest_file.path().to_path_buf(),
            content: None,
            pub_key_hex: Some(hex_encode(vk.as_bytes())),
            expected_receipt: None,
        })
        .unwrap();
        assert!(report.signature_valid);
        assert!(report.canonical_hash_match);
        assert_eq!(report.content_hash_match, None);
        assert!(report.ok); // n/a counts as pass
        assert!(report.notes.iter().any(|n| n.contains("content bytes not supplied")));
    }

    #[test]
    fn wrong_public_key_fails_signature() {
        let signer_key = [13u8; 32];
        let envelope = sign_envelope(b"y", "r_keymismatch", signer_key);
        let manifest_file = write_tmp(envelope.as_bytes());
        let content_file = write_tmp(b"y");
        let other_vk = SigningKey::from_bytes(&[14u8; 32]).verifying_key();
        let report = run(&Options {
            manifest_path: manifest_file.path().to_path_buf(),
            content: Some(content_file.path().to_path_buf()),
            pub_key_hex: Some(hex_encode(other_vk.as_bytes())),
            expected_receipt: None,
        })
        .unwrap();
        assert!(!report.signature_valid);
        assert!(!report.ok);
    }

    #[test]
    fn missing_pub_key_errors() {
        let envelope = sign_envelope(b"z", "r_no_key", [15u8; 32]);
        let manifest_file = write_tmp(envelope.as_bytes());
        std::env::remove_var(VERIFY_KEY_ENV);
        let err = run(&Options {
            manifest_path: manifest_file.path().to_path_buf(),
            content: None,
            pub_key_hex: None,
            expected_receipt: None,
        })
        .unwrap_err();
        assert!(err.to_string().contains("verifying key missing"));
    }

    #[test]
    fn _suppress_unused_base64_warning() {
        // Keep the `base64` import in tests live without forcing
        // doc-test boilerplate.
        let _ = base64::engine::general_purpose::STANDARD.encode([0u8]);
    }
}
