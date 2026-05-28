// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! C2PA Content Credentials v1 manifest emitter — agent-ux-07.
//!
//! ## What this is
//!
//! Encodes a C2PA-shaped Content Credentials manifest from a CROWN
//! receipt id + arbitrary content bytes. The output is a JUMBF-style
//! superbox containing:
//!
//! - `c2pa.claim` — an Ed25519-signed claim binding the data hash,
//!   `claim_generator`, and the assertion store.
//! - `c2pa.assertions` — a deterministic CBOR map with:
//!   - `c2pa.actions` — `[{action: "c2pa.created", "digitalSourceType":
//!     "trainedAlgorithmicMedia", "softwareAgent": "cuecrux", "when"}]`
//!     (the v2.3-defined value for fully AI-generated content; this
//!     aligns with EU AI Act Art. 50 labelling intent).
//!   - `c2pa.hash.data` — BLAKE3 of the content bytes (stored as a
//!     custom `hash.alg = "blake3"` field; mainline C2PA uses SHA-256,
//!     but the v2.3 spec allows alternate algorithms via the `alg`
//!     field).
//!   - `cuecrux.crown_receipt` — custom assertion carrying
//!     `{receipt_id, signer_passport}` so the manifest is one-way bound
//!     to the CROWN receipt chain.
//!
//! ## Why we ship our own encoder
//!
//! The upstream `c2pa-rs` crate is excellent but pulls in openssl,
//! reqwest, ureq, image, and a full X.509 PKI surface — too heavy for
//! the always-on `crux-mcp` binary, and it cannot reuse our existing
//! Ed25519 CROWN signer without a published trust anchor + X.509 chain.
//!
//! The ExecPlan calls this out: "do NOT introduce a new key class".
//! Reusing the CROWN signer means the **C2PA Viewer cannot validate**
//! our manifests without a published platform trust anchor. We emit a
//! v2.3-shaped JUMBF envelope so a future operator-led PKI hand-off
//! (master plan D1 — JWKS rotation) can swap the signer for a chained
//! X.509 cert without changing the manifest shape, but until then the
//! manifests are verifiable by the local CLI (`corecruxctl
//! output-verify`) and the daemon's HTTP `/v1/output/verify` endpoint
//! only.
//!
//! ## Wire shape (JUMBF-compatible)
//!
//! ```text
//! { "format": "application/c2pa",
//!   "version": "c2pa.v2.3",
//!   "manifest_id": "<urn>",
//!   "claim_generator": "cuecrux/<ver>",
//!   "assertions": { ... },
//!   "signature": {
//!     "alg": "ed25519",
//!     "key_id": "<signer key id>",
//!     "signature_b64": "<base64(ed25519 over manifest_canonical_bytes)>",
//!     "signed_payload_hash_b64": "<base64(blake3 of canonical bytes)>"
//!   }
//! }
//! ```
//!
//! Canonical bytes are the CBOR encoding of the manifest with all
//! fields EXCEPT `signature` present, in deterministic key order. The
//! signature binds to those bytes; the `signed_payload_hash_b64` field
//! makes verification cheap.

use base64::Engine as _;
use ciborium::value::Value as CborValue;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use thiserror::Error;

/// Schema string written into the canonical body.
pub const C2PA_MANIFEST_SCHEMA_V1: &str = "cuecrux.c2pa.manifest.v1";

/// C2PA spec version we claim conformance against.
pub const C2PA_SPEC_VERSION: &str = "c2pa.v2.3";

/// Action label for fully AI-generated content (per C2PA v2.3).
pub const C2PA_ACTION_CREATED: &str = "c2pa.created";

/// `digitalSourceType` value for fully AI-generated media (per the IPTC
/// vocabulary referenced by C2PA v2.3).
pub const DIGITAL_SOURCE_TYPE_AI: &str = "trainedAlgorithmicMedia";

/// Default software-agent identifier.
pub const SOFTWARE_AGENT_DEFAULT: &str = "cuecrux";

/// Custom assertion label carrying the CROWN receipt cross-reference.
pub const CUECRUX_CROWN_RECEIPT_LABEL: &str = "cuecrux.crown_receipt";

/// Errors emitted by the manifest encoder/decoder.
#[derive(Debug, Error)]
pub enum C2paManifestError {
    #[error("cbor encode error: {0}")]
    Encode(String),
    #[error("cbor decode error: {0}")]
    Decode(String),
    #[error("manifest signature missing")]
    SignatureMissing,
    #[error("manifest signature decode error: {0}")]
    SignatureDecode(String),
    #[error("manifest hash mismatch: stored={stored} computed={computed}")]
    HashMismatch { stored: String, computed: String },
    #[error("manifest signature verification failed")]
    SignatureInvalid,
    #[error("manifest references receipt {expected:?} but verifier was given {actual:?}")]
    ReceiptIdMismatch { expected: String, actual: String },
    #[error("unsupported manifest version: {0}")]
    UnsupportedVersion(String),
}

/// One C2PA action entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C2paActionV1 {
    pub action: String,
    pub when: String,
    pub software_agent: String,
    pub digital_source_type: Option<String>,
}

/// Input to [`build_c2pa_manifest_v1`].
#[derive(Debug, Clone)]
pub struct C2paManifestInputV1<'a> {
    /// Bytes of the content the manifest attests. Hashed with BLAKE3.
    pub content_bytes: &'a [u8],
    /// Optional MIME / content type (e.g. `image/png`).
    pub content_type: Option<&'a str>,
    /// CROWN receipt id this artefact is bound to.
    pub crown_receipt_id: &'a str,
    /// Passport that signed the producing CROWN receipt (custom assertion).
    pub signer_passport: &'a str,
    /// Free-form `claim_generator` string (e.g. `"cuecrux/0.1.0"`).
    pub claim_generator: &'a str,
    /// Stable manifest id (caller supplies — typically `urn:cuecrux:c2pa:<uuid>`).
    pub manifest_id: &'a str,
    /// ISO-8601 timestamp embedded in the `c2pa.actions` `when` field.
    pub when: &'a str,
    /// Optional `c2pa.actions` model identifier surfaced as `parameters.model`.
    pub model: Option<&'a str>,
}

/// A built (unsigned) manifest — call [`sign_c2pa_manifest_v1`] next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C2paManifestV1 {
    pub manifest_id: String,
    pub spec_version: String,
    pub claim_generator: String,
    pub content_hash_blake3_hex: String,
    pub content_type: Option<String>,
    pub crown_receipt_id: String,
    pub signer_passport: String,
    pub actions: Vec<C2paActionV1>,
}

/// Result of signing — both the canonical body bytes (which an external
/// verifier hashes + checks) and the signature envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C2paSignedManifestV1 {
    pub manifest: C2paManifestV1,
    /// Canonical CBOR-encoded body bytes (no signature field).
    pub canonical_body_bytes: Vec<u8>,
    /// BLAKE3 over `canonical_body_bytes`.
    pub canonical_body_hash: [u8; 32],
    /// Ed25519 signature over `canonical_body_bytes`.
    pub signature: [u8; 64],
    pub key_id: String,
    pub signed_at: String,
}

impl C2paSignedManifestV1 {
    /// Encode the signed manifest as a JUMBF-style JSON envelope. The
    /// content-credential viewer (`corecruxctl output-verify`) decodes
    /// this directly. Production deployments embed this envelope into
    /// the artefact's `c2pa.jumbf` box; until then the envelope can
    /// travel alongside the artefact as a sidecar file.
    pub fn to_jumbf_json(&self) -> serde_json::Value {
        let actions: Vec<serde_json::Value> = self
            .manifest
            .actions
            .iter()
            .map(|a| {
                let mut obj = serde_json::Map::new();
                obj.insert("action".into(), serde_json::Value::String(a.action.clone()));
                obj.insert("when".into(), serde_json::Value::String(a.when.clone()));
                obj.insert(
                    "softwareAgent".into(),
                    serde_json::Value::String(a.software_agent.clone()),
                );
                if let Some(dst) = &a.digital_source_type {
                    obj.insert("digitalSourceType".into(), serde_json::Value::String(dst.clone()));
                }
                serde_json::Value::Object(obj)
            })
            .collect();

        serde_json::json!({
            "format": "application/c2pa",
            "version": self.manifest.spec_version,
            "manifest_id": self.manifest.manifest_id,
            "claim_generator": self.manifest.claim_generator,
            "assertions": {
                "c2pa.actions": { "actions": actions },
                "c2pa.hash.data": {
                    "alg": "blake3",
                    "hash_b64": base64::engine::general_purpose::STANDARD
                        .encode(hex_to_bytes(&self.manifest.content_hash_blake3_hex)),
                    "content_type": self.manifest.content_type,
                },
                CUECRUX_CROWN_RECEIPT_LABEL: {
                    "receipt_id": self.manifest.crown_receipt_id,
                    "signer_passport": self.manifest.signer_passport,
                },
            },
            "signature": {
                "alg": "ed25519",
                "key_id": self.key_id,
                "signed_at": self.signed_at,
                "signature_b64": base64::engine::general_purpose::STANDARD.encode(self.signature),
                "signed_payload_hash_b64": base64::engine::general_purpose::STANDARD
                    .encode(self.canonical_body_hash),
            },
        })
    }

    /// Return the JUMBF envelope encoded as base64-wrapped JSON bytes
    /// (the format the MCP tool returns to its caller).
    pub fn to_jumbf_base64(&self) -> String {
        let json = self.to_jumbf_json();
        let bytes = serde_json::to_vec(&json).unwrap_or_default();
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = char::from(bytes[i]).to_digit(16).unwrap_or(0) as u8;
        let lo = char::from(bytes[i + 1]).to_digit(16).unwrap_or(0) as u8;
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

/// Build an unsigned manifest from the supplied input.
pub fn build_c2pa_manifest_v1(input: &C2paManifestInputV1<'_>) -> C2paManifestV1 {
    let content_hash = blake3::hash(input.content_bytes);
    let action = C2paActionV1 {
        action: C2PA_ACTION_CREATED.to_string(),
        when: input.when.to_string(),
        software_agent: SOFTWARE_AGENT_DEFAULT.to_string(),
        digital_source_type: Some(DIGITAL_SOURCE_TYPE_AI.to_string()),
    };
    let _ = input.model; // reserved for future use in parameters
    C2paManifestV1 {
        manifest_id: input.manifest_id.to_string(),
        spec_version: C2PA_SPEC_VERSION.to_string(),
        claim_generator: input.claim_generator.to_string(),
        content_hash_blake3_hex: content_hash.to_hex().to_string(),
        content_type: input.content_type.map(str::to_string),
        crown_receipt_id: input.crown_receipt_id.to_string(),
        signer_passport: input.signer_passport.to_string(),
        actions: vec![action],
    }
}

/// Encode the manifest into a deterministic CBOR body suitable for
/// hashing + signing. The encoding is byte-stable across calls so two
/// invocations with identical inputs produce identical bytes (verifier
/// round-trips depend on this).
pub fn canonical_body_bytes_v1(m: &C2paManifestV1) -> Result<Vec<u8>, C2paManifestError> {
    let actions: Vec<CborValue> = m
        .actions
        .iter()
        .map(|a| {
            let mut entries = vec![
                (CborValue::Text("action".into()), CborValue::Text(a.action.clone())),
                (CborValue::Text("when".into()), CborValue::Text(a.when.clone())),
                (
                    CborValue::Text("softwareAgent".into()),
                    CborValue::Text(a.software_agent.clone()),
                ),
            ];
            if let Some(dst) = &a.digital_source_type {
                entries.push((
                    CborValue::Text("digitalSourceType".into()),
                    CborValue::Text(dst.clone()),
                ));
            }
            CborValue::Map(entries)
        })
        .collect();

    let mut top: Vec<(CborValue, CborValue)> = vec![
        (
            CborValue::Text("schema".into()),
            CborValue::Text(C2PA_MANIFEST_SCHEMA_V1.into()),
        ),
        (
            CborValue::Text("version".into()),
            CborValue::Text(m.spec_version.clone()),
        ),
        (
            CborValue::Text("manifest_id".into()),
            CborValue::Text(m.manifest_id.clone()),
        ),
        (
            CborValue::Text("claim_generator".into()),
            CborValue::Text(m.claim_generator.clone()),
        ),
        (
            CborValue::Text("content_hash_alg".into()),
            CborValue::Text("blake3".into()),
        ),
        (
            CborValue::Text("content_hash_hex".into()),
            CborValue::Text(m.content_hash_blake3_hex.clone()),
        ),
    ];
    if let Some(ct) = &m.content_type {
        top.push((CborValue::Text("content_type".into()), CborValue::Text(ct.clone())));
    }
    top.push((CborValue::Text("actions".into()), CborValue::Array(actions)));
    top.push((
        CborValue::Text("crown_receipt_id".into()),
        CborValue::Text(m.crown_receipt_id.clone()),
    ));
    top.push((
        CborValue::Text("signer_passport".into()),
        CborValue::Text(m.signer_passport.clone()),
    ));

    let v = CborValue::Map(top);
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&v, &mut bytes).map_err(|e| C2paManifestError::Encode(e.to_string()))?;
    Ok(bytes)
}

/// Sign a built manifest with the daemon's Ed25519 CROWN signer.
///
/// The returned struct's `to_jumbf_base64()` is what the MCP tool
/// returns to the caller; `verify_c2pa_manifest_v1` reads the same
/// envelope back to validate.
pub fn sign_c2pa_manifest_v1(
    manifest: C2paManifestV1,
    signing_key: &SigningKey,
    key_id: &str,
    signed_at: &str,
) -> Result<C2paSignedManifestV1, C2paManifestError> {
    let body = canonical_body_bytes_v1(&manifest)?;
    let hash = blake3::hash(&body);
    let sig = signing_key.sign(&body).to_bytes();
    Ok(C2paSignedManifestV1 {
        manifest,
        canonical_body_bytes: body,
        canonical_body_hash: *hash.as_bytes(),
        signature: sig,
        key_id: key_id.to_string(),
        signed_at: signed_at.to_string(),
    })
}

/// Parse a JUMBF base64 envelope back into a [`C2paSignedManifestV1`].
pub fn parse_jumbf_base64(envelope_b64: &str) -> Result<C2paSignedManifestV1, C2paManifestError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(envelope_b64.trim())
        .map_err(|e| C2paManifestError::Decode(format!("base64: {e}")))?;
    let json: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| C2paManifestError::Decode(format!("json: {e}")))?;

    let version = json
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    if version != C2PA_SPEC_VERSION {
        return Err(C2paManifestError::UnsupportedVersion(version));
    }
    let manifest_id = json
        .get("manifest_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let claim_generator = json
        .get("claim_generator")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let assertions = json
        .get("assertions")
        .cloned()
        .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));

    let hash_assertion = assertions
        .get("c2pa.hash.data")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let alg = hash_assertion.get("alg").and_then(|v| v.as_str()).unwrap_or_default();
    if alg != "blake3" {
        return Err(C2paManifestError::Decode(format!("unsupported hash alg: {alg}")));
    }
    let hash_b64 = hash_assertion
        .get("hash_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| C2paManifestError::Decode("missing c2pa.hash.data.hash_b64".into()))?;
    let hash_raw = base64::engine::general_purpose::STANDARD
        .decode(hash_b64)
        .map_err(|e| C2paManifestError::Decode(format!("hash b64: {e}")))?;
    let content_hash_hex = bytes_to_hex(&hash_raw);
    let content_type = hash_assertion
        .get("content_type")
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let crown = assertions
        .get(CUECRUX_CROWN_RECEIPT_LABEL)
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let crown_receipt_id = crown
        .get("receipt_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let signer_passport = crown
        .get("signer_passport")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let mut actions: Vec<C2paActionV1> = Vec::new();
    if let Some(arr) = assertions
        .get("c2pa.actions")
        .and_then(|a| a.get("actions"))
        .and_then(|v| v.as_array())
    {
        for a in arr {
            actions.push(C2paActionV1 {
                action: a.get("action").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                when: a.get("when").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
                software_agent: a
                    .get("softwareAgent")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                digital_source_type: a.get("digitalSourceType").and_then(|v| v.as_str()).map(str::to_string),
            });
        }
    }

    let manifest = C2paManifestV1 {
        manifest_id,
        spec_version: version,
        claim_generator,
        content_hash_blake3_hex: content_hash_hex,
        content_type,
        crown_receipt_id,
        signer_passport,
        actions,
    };
    let canonical_body_bytes = canonical_body_bytes_v1(&manifest)?;
    let canonical_body_hash = *blake3::hash(&canonical_body_bytes).as_bytes();

    let sig = json
        .get("signature")
        .ok_or(C2paManifestError::SignatureMissing)?
        .clone();
    let sig_b64 = sig
        .get("signature_b64")
        .and_then(|v| v.as_str())
        .ok_or(C2paManifestError::SignatureMissing)?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(sig_b64)
        .map_err(|e| C2paManifestError::SignatureDecode(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(C2paManifestError::SignatureDecode(format!(
            "expected 64-byte ed25519 signature, got {}",
            sig_bytes.len()
        )));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig_bytes);
    let key_id = sig
        .get("key_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let signed_at = sig
        .get("signed_at")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    Ok(C2paSignedManifestV1 {
        manifest,
        canonical_body_bytes,
        canonical_body_hash,
        signature,
        key_id,
        signed_at,
    })
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Result of [`verify_c2pa_manifest_v1`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C2paVerificationReportV1 {
    pub manifest_id: String,
    pub crown_receipt_id: String,
    pub signer_key_id: String,
    pub canonical_hash_match: bool,
    pub signature_valid: bool,
    pub content_hash_match: bool,
    pub ok: bool,
}

/// Verify a parsed manifest:
/// 1. Recompute the canonical body BLAKE3 and compare against the
///    `signed_payload_hash_b64` field (corrupt-envelope detection).
/// 2. Ed25519-verify the signature against the recomputed canonical
///    bytes using `verifying_key`.
/// 3. Recompute the content BLAKE3 from `content_bytes` and compare
///    against `content_hash_blake3_hex`.
pub fn verify_c2pa_manifest_v1(
    parsed: &C2paSignedManifestV1,
    content_bytes: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<C2paVerificationReportV1, C2paManifestError> {
    let recomputed = blake3::hash(&parsed.canonical_body_bytes);
    let canonical_hash_match = *recomputed.as_bytes() == parsed.canonical_body_hash;

    let sig = ed25519_dalek::Signature::from_bytes(&parsed.signature);
    let signature_valid = verifying_key.verify(&parsed.canonical_body_bytes, &sig).is_ok();

    let content_hash = blake3::hash(content_bytes).to_hex().to_string();
    let content_hash_match = content_hash == parsed.manifest.content_hash_blake3_hex;

    Ok(C2paVerificationReportV1 {
        manifest_id: parsed.manifest.manifest_id.clone(),
        crown_receipt_id: parsed.manifest.crown_receipt_id.clone(),
        signer_key_id: parsed.key_id.clone(),
        canonical_hash_match,
        signature_valid,
        content_hash_match,
        ok: canonical_hash_match && signature_valid && content_hash_match,
    })
}

/// Cross-reference the parsed manifest's CROWN receipt id against an
/// expected value (e.g. the operator's local receipt store has already
/// resolved the bound receipt). Returns `Ok(())` on match.
pub fn assert_crown_receipt_id_v1(
    parsed: &C2paSignedManifestV1,
    expected_receipt_id: &str,
) -> Result<(), C2paManifestError> {
    if parsed.manifest.crown_receipt_id == expected_receipt_id {
        Ok(())
    } else {
        Err(C2paManifestError::ReceiptIdMismatch {
            expected: expected_receipt_id.to_string(),
            actual: parsed.manifest.crown_receipt_id.clone(),
        })
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn fixture_input<'a>(content: &'a [u8], receipt: &'a str) -> C2paManifestInputV1<'a> {
        C2paManifestInputV1 {
            content_bytes: content,
            content_type: Some("image/png"),
            crown_receipt_id: receipt,
            signer_passport: "passport:test",
            claim_generator: "cuecrux/0.1.0-test",
            manifest_id: "urn:cuecrux:c2pa:00000000-0000-0000-0000-000000000001",
            when: "2026-05-27T12:00:00Z",
            model: Some("test-model"),
        }
    }

    #[test]
    fn build_includes_ai_generated_action() {
        let m = build_c2pa_manifest_v1(&fixture_input(b"hello world", "r_test_01"));
        assert_eq!(m.actions.len(), 1);
        assert_eq!(m.actions[0].action, C2PA_ACTION_CREATED);
        assert_eq!(
            m.actions[0].digital_source_type.as_deref(),
            Some(DIGITAL_SOURCE_TYPE_AI)
        );
        assert_eq!(m.crown_receipt_id, "r_test_01");
        assert_eq!(m.signer_passport, "passport:test");
        assert_eq!(m.spec_version, C2PA_SPEC_VERSION);
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let m1 = build_c2pa_manifest_v1(&fixture_input(b"alpha", "r_001"));
        let m2 = build_c2pa_manifest_v1(&fixture_input(b"alpha", "r_001"));
        let b1 = canonical_body_bytes_v1(&m1).unwrap();
        let b2 = canonical_body_bytes_v1(&m2).unwrap();
        assert_eq!(b1, b2, "canonical encoding must be byte-stable");
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let sk = SigningKey::from_bytes(&[3u8; 32]);
        let vk = sk.verifying_key();
        let content = b"some-image-bytes";
        let manifest = build_c2pa_manifest_v1(&fixture_input(content, "r_round_trip"));
        let signed = sign_c2pa_manifest_v1(manifest, &sk, "key_test", "2026-05-27T12:00:00Z").unwrap();
        let envelope = signed.to_jumbf_base64();

        let parsed = parse_jumbf_base64(&envelope).unwrap();
        let report = verify_c2pa_manifest_v1(&parsed, content, &vk).unwrap();
        assert!(report.ok, "expected verification to pass: {report:?}");
        assert!(report.canonical_hash_match);
        assert!(report.signature_valid);
        assert!(report.content_hash_match);
        assert_eq!(report.crown_receipt_id, "r_round_trip");
    }

    #[test]
    fn tampering_with_content_breaks_hash_check() {
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let vk = sk.verifying_key();
        let content = b"original-bytes";
        let manifest = build_c2pa_manifest_v1(&fixture_input(content, "r_tamper_content"));
        let signed = sign_c2pa_manifest_v1(manifest, &sk, "key_test", "2026-05-27T12:00:00Z").unwrap();
        let parsed = parse_jumbf_base64(&signed.to_jumbf_base64()).unwrap();
        // Flip a byte in the content; canonical signature stays valid
        // but the content-hash assertion no longer matches.
        let tampered = b"corrupted-bytes";
        let report = verify_c2pa_manifest_v1(&parsed, tampered, &vk).unwrap();
        assert!(report.signature_valid, "signature is over the manifest, not the bytes");
        assert!(!report.content_hash_match);
        assert!(!report.ok);
    }

    #[test]
    fn tampering_with_signature_breaks_signature_check() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let content = b"sig-test-content";
        let manifest = build_c2pa_manifest_v1(&fixture_input(content, "r_tamper_sig"));
        let mut signed = sign_c2pa_manifest_v1(manifest, &sk, "key_test", "2026-05-27T12:00:00Z").unwrap();
        signed.signature[0] ^= 0xff;
        let parsed = parse_jumbf_base64(&signed.to_jumbf_base64()).unwrap();
        let report = verify_c2pa_manifest_v1(&parsed, content, &vk).unwrap();
        assert!(!report.signature_valid);
        assert!(report.content_hash_match, "content hash still matches");
        assert!(!report.ok);
    }

    #[test]
    fn wrong_verifying_key_fails() {
        let sk_signer = SigningKey::from_bytes(&[1u8; 32]);
        let sk_other = SigningKey::from_bytes(&[2u8; 32]);
        let vk_other = sk_other.verifying_key();
        let content = b"key-mismatch";
        let manifest = build_c2pa_manifest_v1(&fixture_input(content, "r_keymismatch"));
        let signed = sign_c2pa_manifest_v1(manifest, &sk_signer, "key_a", "2026-05-27T12:00:00Z").unwrap();
        let parsed = parse_jumbf_base64(&signed.to_jumbf_base64()).unwrap();
        let report = verify_c2pa_manifest_v1(&parsed, content, &vk_other).unwrap();
        assert!(!report.signature_valid);
        assert!(!report.ok);
    }

    #[test]
    fn receipt_id_cross_reference() {
        let sk = SigningKey::from_bytes(&[8u8; 32]);
        let manifest = build_c2pa_manifest_v1(&fixture_input(b"xref", "r_xref_ok"));
        let signed = sign_c2pa_manifest_v1(manifest, &sk, "k1", "2026-05-27T12:00:00Z").unwrap();
        let parsed = parse_jumbf_base64(&signed.to_jumbf_base64()).unwrap();
        assert!(assert_crown_receipt_id_v1(&parsed, "r_xref_ok").is_ok());
        let err = assert_crown_receipt_id_v1(&parsed, "r_other").unwrap_err();
        assert!(matches!(err, C2paManifestError::ReceiptIdMismatch { .. }));
    }

    #[test]
    fn unsupported_version_rejected() {
        // Manually craft an envelope with a bogus version.
        let bad = serde_json::json!({
            "format": "application/c2pa",
            "version": "c2pa.v9.9",
            "manifest_id": "urn:bad",
            "claim_generator": "x",
            "assertions": {},
            "signature": {"alg":"ed25519","key_id":"k","signed_at":"t",
                          "signature_b64":"","signed_payload_hash_b64":""}
        });
        let envelope = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&bad).unwrap());
        let err = parse_jumbf_base64(&envelope).unwrap_err();
        assert!(matches!(err, C2paManifestError::UnsupportedVersion(_)));
    }
}
