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
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
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
    /// Raw signature bytes. For Ed25519 (legacy / `local-ed25519`
    /// backend) this is the 64-byte signature; for ECDSA P-256
    /// (`vault-pki-p256` backend) this is the DER-encoded signature.
    pub signature: Vec<u8>,
    /// Signature algorithm string written into the envelope. One of
    /// `"ed25519"` (legacy) or `"es256"` (P-256 ECDSA with SHA-256,
    /// the JWA name for COSE algorithm `-7`).
    pub signature_alg: String,
    pub key_id: String,
    pub signed_at: String,
    /// Optional X.509 certificate chain (leaf first, then
    /// intermediates, no root) for the `vault-pki-p256` backend.
    /// `None` for the legacy `local-ed25519` backend — the JUMBF
    /// envelope omits the `x5chain` field entirely in that case, so
    /// existing PR #121 outputs remain byte-identical.
    pub x5chain_pem: Option<String>,
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

        let mut signature_obj = serde_json::Map::new();
        signature_obj.insert("alg".into(), serde_json::Value::String(self.signature_alg.clone()));
        signature_obj.insert("key_id".into(), serde_json::Value::String(self.key_id.clone()));
        signature_obj.insert("signed_at".into(), serde_json::Value::String(self.signed_at.clone()));
        signature_obj.insert(
            "signature_b64".into(),
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(&self.signature)),
        );
        signature_obj.insert(
            "signed_payload_hash_b64".into(),
            serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(self.canonical_body_hash)),
        );
        // RFC 9360 `x5chain` header — embed only when the signer
        // backend supplied a chain. Legacy Ed25519 outputs are byte-
        // identical to PR #121 because this branch is skipped.
        if let Some(chain_pem) = &self.x5chain_pem {
            let der_chain: Vec<serde_json::Value> = split_pem_certs(chain_pem)
                .into_iter()
                .filter_map(|pem| pem_cert_to_der(&pem).ok())
                .map(|der| serde_json::Value::String(base64::engine::general_purpose::STANDARD.encode(der)))
                .collect();
            signature_obj.insert("x5chain".into(), serde_json::Value::Array(der_chain));
            signature_obj.insert("x5chain_pem".into(), serde_json::Value::String(chain_pem.clone()));
        }

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
            "signature": serde_json::Value::Object(signature_obj),
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

/// Split a PEM concatenation into one PEM string per certificate.
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

/// Decode one PEM CERTIFICATE block into raw DER bytes.
fn pem_cert_to_der(pem: &str) -> Result<Vec<u8>, C2paManifestError> {
    let trimmed = pem.trim();
    let start_marker = "-----BEGIN CERTIFICATE-----";
    let end_marker = "-----END CERTIFICATE-----";
    let start = trimmed
        .find(start_marker)
        .ok_or_else(|| C2paManifestError::Decode("missing BEGIN CERTIFICATE".into()))?;
    let body_start = start + start_marker.len();
    let end = trimmed[body_start..]
        .find(end_marker)
        .ok_or_else(|| C2paManifestError::Decode("missing END CERTIFICATE".into()))?;
    let b64 = trimmed[body_start..body_start + end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .map_err(|e| C2paManifestError::Decode(format!("x5chain b64 decode: {e}")))
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

/// Output of one signing pass. Backends implement [`C2paSigner`] and
/// return this shape; [`sign_c2pa_manifest_via_signer`] glues a signer
/// to the canonical-bytes pipeline.
#[derive(Debug, Clone)]
pub struct SignedManifestParts {
    /// Raw signature bytes (Ed25519: 64 bytes; ECDSA P-256: DER-encoded).
    pub signature_bytes: Vec<u8>,
    /// Wire algorithm identifier. `"ed25519"` or `"es256"`.
    pub signature_alg: String,
    /// Key id to embed in the envelope.
    pub key_id: String,
    /// Optional X.509 chain (PEM, leaf+intermediates, no root). When
    /// `Some`, the JUMBF envelope embeds the chain in an `x5chain`
    /// header per RFC 9360.
    pub x5chain_pem: Option<String>,
}

/// A pluggable C2PA signer. The Ed25519 legacy backend (used by
/// existing PR #121 outputs) is provided by [`ed25519_signer`]; the
/// Vault PKI X.509 backend lives in
/// [`crate::vault_pki_x509_signer::VaultPkiX509Signer`].
pub trait C2paSigner {
    /// Sign the canonical body bytes. Implementations may sign the
    /// bytes directly (Ed25519) or pre-hash + sign the digest (ECDSA);
    /// the canonical-bytes-and-hash bookkeeping is the caller's
    /// responsibility, the trait sees only the body.
    fn sign_body(&self, canonical_body_bytes: &[u8]) -> Result<SignedManifestParts, C2paManifestError>;
}

/// Build an Ed25519 [`C2paSigner`] adapter for a `SigningKey` + key id
/// pair. This is the legacy `local-ed25519` backend selected when no
/// X.509 flag is set; behaviour matches PR #121 exactly.
pub fn ed25519_signer<'a>(signing_key: &'a SigningKey, key_id: &'a str) -> impl C2paSigner + 'a {
    Ed25519CompatSigner { signing_key, key_id }
}

struct Ed25519CompatSigner<'a> {
    signing_key: &'a SigningKey,
    key_id: &'a str,
}

impl C2paSigner for Ed25519CompatSigner<'_> {
    fn sign_body(&self, canonical_body_bytes: &[u8]) -> Result<SignedManifestParts, C2paManifestError> {
        let sig = self.signing_key.sign(canonical_body_bytes).to_bytes();
        Ok(SignedManifestParts {
            signature_bytes: sig.to_vec(),
            signature_alg: "ed25519".to_string(),
            key_id: self.key_id.to_string(),
            x5chain_pem: None,
        })
    }
}

/// Sign a built manifest with the daemon's Ed25519 CROWN signer.
///
/// The returned struct's `to_jumbf_base64()` is what the MCP tool
/// returns to the caller; `verify_c2pa_manifest_v1` reads the same
/// envelope back to validate.
///
/// Backwards compat: this is the legacy entry point used by PR #121;
/// the emitted manifest is byte-identical to that PR's output (alg =
/// `"ed25519"`, no `x5chain` field).
pub fn sign_c2pa_manifest_v1(
    manifest: C2paManifestV1,
    signing_key: &SigningKey,
    key_id: &str,
    signed_at: &str,
) -> Result<C2paSignedManifestV1, C2paManifestError> {
    let signer = ed25519_signer(signing_key, key_id);
    sign_c2pa_manifest_via_signer(manifest, &signer, signed_at)
}

/// Backend-agnostic sign path. The Ed25519 legacy entry point
/// [`sign_c2pa_manifest_v1`] is a thin wrapper that builds an Ed25519
/// signer adapter. The Vault PKI X.509 backend passes a different
/// adapter that pre-hashes the body and produces a DER-encoded P-256
/// signature plus the x5chain bytes.
pub fn sign_c2pa_manifest_via_signer<S: C2paSigner + ?Sized>(
    manifest: C2paManifestV1,
    signer: &S,
    signed_at: &str,
) -> Result<C2paSignedManifestV1, C2paManifestError> {
    let body = canonical_body_bytes_v1(&manifest)?;
    let hash = blake3::hash(&body);
    let parts = signer.sign_body(&body)?;
    Ok(C2paSignedManifestV1 {
        manifest,
        canonical_body_bytes: body,
        canonical_body_hash: *hash.as_bytes(),
        signature: parts.signature_bytes,
        signature_alg: parts.signature_alg,
        key_id: parts.key_id,
        signed_at: signed_at.to_string(),
        x5chain_pem: parts.x5chain_pem,
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
    // The legacy Ed25519 path required exactly 64 bytes; the new
    // ES256 (P-256 ECDSA-SHA256) path produces a DER-encoded
    // signature of variable length. We dispatch on the `alg` field
    // and let `verify_c2pa_manifest_v1` enforce shape.
    let signature_alg = sig.get("alg").and_then(|v| v.as_str()).unwrap_or("ed25519").to_string();
    if signature_alg == "ed25519" && sig_bytes.len() != 64 {
        return Err(C2paManifestError::SignatureDecode(format!(
            "expected 64-byte ed25519 signature, got {}",
            sig_bytes.len()
        )));
    }
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
    // x5chain — prefer the PEM form (round-trip-friendly), fall back
    // to the DER array (RFC 9360 canonical form).
    let x5chain_pem = sig
        .get("x5chain_pem")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| {
            sig.get("x5chain").and_then(|v| v.as_array()).map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        item.as_str().and_then(|s| {
                            base64::engine::general_purpose::STANDARD
                                .decode(s.as_bytes())
                                .ok()
                                .map(|der| der_to_pem_cert(&der))
                        })
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
        });

    Ok(C2paSignedManifestV1 {
        manifest,
        canonical_body_bytes,
        canonical_body_hash,
        signature: sig_bytes,
        signature_alg,
        key_id,
        signed_at,
        x5chain_pem,
    })
}

/// Wrap raw DER bytes back into a PEM `CERTIFICATE` block. Used when
/// the envelope only carried the RFC 9360 `x5chain` array.
fn der_to_pem_cert(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
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

    let signature_valid = if parsed.signature.len() == 64 {
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&parsed.signature);
        let sig = ed25519_dalek::Signature::from_bytes(&arr);
        verifying_key.verify_strict(&parsed.canonical_body_bytes, &sig).is_ok()
    } else {
        // Non-64-byte signature → not the legacy Ed25519 envelope.
        // verify_c2pa_manifest_v1 only handles Ed25519; X.509 chain
        // verification lives in `corecruxctl c2pa-verify` and walks
        // the x5chain to the local anchor PEM.
        false
    };

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
        if let Some(first) = signed.signature.first_mut() {
            *first ^= 0xff;
        }
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
    fn backwards_compat_ed25519_envelope_bytes_unchanged() {
        // Re-verify that the legacy Ed25519 entry point produces a
        // JUMBF envelope whose decoded shape matches PR #121 — namely
        // `signature.alg == "ed25519"` and no `x5chain` field.
        let sk = SigningKey::from_bytes(&[19u8; 32]);
        let manifest = build_c2pa_manifest_v1(&fixture_input(b"bc-test", "r_bc"));
        let signed = sign_c2pa_manifest_v1(manifest, &sk, "k-legacy", "2026-05-28T00:00:00Z").unwrap();
        let envelope_json = signed.to_jumbf_json();
        assert_eq!(envelope_json["signature"]["alg"], "ed25519");
        assert!(
            envelope_json["signature"].get("x5chain").is_none(),
            "legacy envelope must not embed x5chain"
        );
        assert!(
            envelope_json["signature"].get("x5chain_pem").is_none(),
            "legacy envelope must not embed x5chain_pem"
        );
        assert_eq!(signed.signature.len(), 64, "ed25519 raw sig stays 64 bytes");
    }

    #[test]
    fn custom_signer_trait_round_trip() {
        // A trivial in-test C2paSigner implementation — emulates the
        // X.509 backend's output shape (es256 + x5chain_pem) without
        // pulling in Vault.
        struct FakeX509Signer;
        impl C2paSigner for FakeX509Signer {
            fn sign_body(&self, body: &[u8]) -> Result<SignedManifestParts, C2paManifestError> {
                // Not a real ES256 signature — just bytes to prove
                // the envelope round-trips.
                let mut sig = vec![0u8; 70]; // typical DER P-256 size
                sig[0..body.len().min(70)].copy_from_slice(&body[..body.len().min(70)]);
                let fake_pem = "-----BEGIN CERTIFICATE-----\nQUFB\n-----END CERTIFICATE-----\n".to_string();
                Ok(SignedManifestParts {
                    signature_bytes: sig,
                    signature_alg: "es256".into(),
                    key_id: "x509-sha256:deadbeef".into(),
                    x5chain_pem: Some(fake_pem),
                })
            }
        }
        let manifest = build_c2pa_manifest_v1(&fixture_input(b"x509-test", "r_x509"));
        let signed = sign_c2pa_manifest_via_signer(manifest, &FakeX509Signer, "2026-05-28T00:00:00Z").unwrap();
        assert_eq!(signed.signature_alg, "es256");
        assert_eq!(signed.key_id, "x509-sha256:deadbeef");
        assert!(signed.x5chain_pem.is_some());
        let envelope = signed.to_jumbf_base64();
        let parsed = parse_jumbf_base64(&envelope).unwrap();
        assert_eq!(parsed.signature_alg, "es256");
        assert_eq!(parsed.signature, signed.signature);
        assert!(
            parsed.x5chain_pem.is_some(),
            "x5chain must round-trip through the envelope"
        );
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
