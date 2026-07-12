// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Result Envelope import — schema, hashing, and platform-signature verification.
//!
//! The Result Envelope is the signed bundle the CueCrux platform returns to a
//! customer's local Crux Daemon after paid server-side ingest/extraction. It
//! carries open-format `facts` / `entities` / `edges` plus sealed companion
//! artefact descriptors, with a blake3 content hash and a platform Ed25519
//! signature. The daemon verifies the signature on import and routes the
//! payload through *existing* store surfaces (bulk facts / entity_upsert /
//! edge_upsert) — no new write paths.
//!
//! Spec: `Result-Envelope-Spec-v0_1.md`
//! (child of `crux-growth-upsell-master-2026-06-11`, W2.D2).
//!
//! This module owns only the *verification* primitive (the one new requirement
//! in §3.2) plus the typed envelope schema. Application of the payload to the
//! stores lives in the daemon importer so it can reuse the live store handles
//! and emit receipts via the already-receipted surfaces.

use serde::{Deserialize, Serialize};

/// The only schema version accepted in v0.1.
pub const RESULT_ENVELOPE_SCHEMA_V1: &str = "crux.result_envelope.v1";

/// A fact carried inside a Result Envelope payload. This is the open-format
/// `StoreFact`-compatible shape (§2.1 `payload.facts[]`). Kept as an
/// independent serde type (rather than reusing [`crate::fact_store::StoreFact`])
/// so the envelope schema is stable even if the internal store request shape
/// evolves; the importer maps these onto `StoreFact` at apply time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnvelopeFact {
    pub entity: String,
    pub key: String,
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_receipt: Option<String>,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    /// MUST be `false` — the platform never emits private facts (§2.1). The
    /// importer rejects `private: true` to mirror the HTTP bulk contract.
    #[serde(default)]
    pub private: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub horizon_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
}

fn default_confidence() -> f32 {
    1.0
}

/// An entity carried inside a Result Envelope payload — the `entity_upsert`
/// argument shape (§2.1 `payload.entities[]`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnvelopeEntity {
    pub kind: String,
    pub id: String,
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// An edge carried inside a Result Envelope payload — the `edge_upsert`
/// argument shape (§2.1 `payload.edges[]`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnvelopeEdge {
    pub from_kind: String,
    pub from_id: String,
    pub edge_kind: String,
    pub to_kind: String,
    pub to_id: String,
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// The open-format payload section of the envelope. Hashed in field order:
/// `facts`, `entities`, `edges` (§2 ordering rule).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct EnvelopePayload {
    #[serde(default)]
    pub facts: Vec<EnvelopeFact>,
    #[serde(default)]
    pub entities: Vec<EnvelopeEntity>,
    #[serde(default)]
    pub edges: Vec<EnvelopeEdge>,
}

/// A sealed companion artefact descriptor. Content is delivered out-of-band via
/// `fetch_url`; the envelope carries only the content-addressed id, size, and a
/// coarse purpose tag (§2.1 `companion_artifacts[]`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CompanionArtifact {
    /// `art_<blake3_hex_of_content>` — content-addressed id.
    pub artefact_id: String,
    pub size_bytes: u64,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default = "default_sealed")]
    pub sealed: bool,
    /// One of `embedding` | `projection` | `lane_state` (coarse, no pipeline detail).
    pub purpose_tag: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_url: Option<String>,
}

fn default_sealed() -> bool {
    true
}

/// The platform Ed25519 signature over the decoded 32-byte content hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlatformSignature {
    /// Always `ed25519` in v0.1.
    pub alg: String,
    /// Selects a pinned platform public key (§3.3).
    pub key_id: String,
    /// 128-hex (64-byte) Ed25519 signature.
    pub signature: String,
}

/// The full Result Envelope (`crux.result_envelope.v1`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResultEnvelope {
    pub schema_version: String,
    pub job_id: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passport_fpr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credit_spend_receipt: Option<String>,
    pub payload: EnvelopePayload,
    #[serde(default)]
    pub companion_artifacts: Vec<CompanionArtifact>,
    /// `blake3:<64-hex>` over the canonical JSON of `payload` + `companion_artifacts`.
    pub blake3_content_hash: String,
    pub platform_signature: PlatformSignature,
}

/// A pinned platform verification key (config / env, keyring-style).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPlatformKey {
    pub key_id: String,
    /// 64-hex (32-byte) Ed25519 public key.
    pub public_key_hex: String,
}

/// Typed verification failures — each is a hard reject before any write (§5).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeVerifyError {
    #[error("unsupported schema_version: {0}")]
    UnsupportedSchema(String),
    #[error("content serialization failed: {0}")]
    ContentSerialization(String),
    #[error("recomputed content hash {recomputed} != stated {stated}")]
    HashMismatch { stated: String, recomputed: String },
    #[error("malformed content hash: {0}")]
    MalformedHash(String),
    #[error("malformed signature: {0}")]
    MalformedSignature(String),
    #[error("unknown signer key_id: {0}")]
    UnknownSigner(String),
    #[error("malformed pinned public key for key_id {key_id}: {detail}")]
    MalformedPubkey { key_id: String, detail: String },
    #[error("signature verification failed for key_id {0}")]
    BadSignature(String),
}

/// Compute the canonical content hash over `payload` + `companion_artifacts`,
/// returned as `blake3:<64-hex>`. Mirrors the `hash_json` convention used by
/// the sync path (`sync.rs` `hash_json`): stable serde JSON serialization,
/// then blake3 (via the shared [`crate::signed_bundle`] idiom). The platform
/// emits a deterministic array order (§2 ordering rule); the importer hashes
/// the bytes exactly as received.
pub fn result_envelope_content_hash(
    payload: &EnvelopePayload,
    companion_artifacts: &[CompanionArtifact],
) -> Result<String, serde_json::Error> {
    crate::signed_bundle::content_hash_json(&serde_json::json!({
        "payload": payload,
        "companion_artifacts": companion_artifacts,
    }))
}

/// Verify a Result Envelope's integrity and platform signature.
///
/// Steps (§3.2), each a hard reject before any write:
/// 1. `schema_version` must equal [`RESULT_ENVELOPE_SCHEMA_V1`].
/// 2. Recompute the blake3 content hash over `payload` + `companion_artifacts`
///    and compare against `blake3_content_hash`.
/// 3. Resolve `platform_signature.key_id` against the pinned trusted keys.
/// 4. Verify the Ed25519 signature over the decoded 32-byte content hash —
///    the same hash-then-sign pattern as wipe receipts.
///
/// On success returns the decoded 32-byte content hash (useful for the import
/// receipt). No network access, no PKI: keys are pinned in daemon config.
pub fn verify_result_envelope(
    envelope: &ResultEnvelope,
    trusted_platform_keys: &[TrustedPlatformKey],
) -> Result<[u8; 32], EnvelopeVerifyError> {
    use crate::signed_bundle;

    // 1) Schema gate.
    if envelope.schema_version != RESULT_ENVELOPE_SCHEMA_V1 {
        return Err(EnvelopeVerifyError::UnsupportedSchema(envelope.schema_version.clone()));
    }

    // 2) Recompute + compare content hash.
    let recomputed = result_envelope_content_hash(&envelope.payload, &envelope.companion_artifacts)
        .map_err(|err| EnvelopeVerifyError::ContentSerialization(err.to_string()))?;
    if recomputed != envelope.blake3_content_hash {
        return Err(EnvelopeVerifyError::HashMismatch {
            stated: envelope.blake3_content_hash.clone(),
            recomputed,
        });
    }

    // Decode the 32-byte hash that gets signed (strip the `blake3:` prefix).
    let hash = signed_bundle::decode_content_hash(&envelope.blake3_content_hash)
        .map_err(EnvelopeVerifyError::MalformedHash)?;

    // 3) Resolve the pinned signer.
    let key_id = &envelope.platform_signature.key_id;
    let trusted = trusted_platform_keys
        .iter()
        .find(|k| &k.key_id == key_id)
        .ok_or_else(|| EnvelopeVerifyError::UnknownSigner(key_id.clone()))?;

    let malformed_pubkey = |detail: String| EnvelopeVerifyError::MalformedPubkey {
        key_id: key_id.clone(),
        detail,
    };
    let pubkey_arr = signed_bundle::decode_public_key(&trusted.public_key_hex).map_err(malformed_pubkey)?;
    let verifying_key = signed_bundle::parse_verifying_key(&pubkey_arr).map_err(malformed_pubkey)?;

    // 4) Verify the Ed25519 signature over the 32-byte hash.
    let sig_arr = signed_bundle::decode_signature(&envelope.platform_signature.signature)
        .map_err(EnvelopeVerifyError::MalformedSignature)?;
    if !signed_bundle::verify_signature_over_hash(&verifying_key, &hash, &sig_arr) {
        return Err(EnvelopeVerifyError::BadSignature(key_id.clone()));
    }

    Ok(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn sample_payload() -> EnvelopePayload {
        EnvelopePayload {
            facts: vec![EnvelopeFact {
                entity: "person::ada".into(),
                key: "role".into(),
                value: "mathematician".into(),
                source_receipt: None,
                confidence: 0.92,
                private: false,
                horizon_class: None,
                actor: Some("platform:extraction".into()),
            }],
            entities: vec![EnvelopeEntity {
                kind: "person".into(),
                id: "p_ada".into(),
                payload: serde_json::json!({"name": "Ada"}),
            }],
            edges: vec![EnvelopeEdge {
                from_kind: "person".into(),
                from_id: "p_ada".into(),
                edge_kind: "works_at".into(),
                to_kind: "org".into(),
                to_id: "o_analytical".into(),
                payload: serde_json::json!({}),
            }],
        }
    }

    /// Build a fully-signed envelope from a generated key, returning the
    /// envelope and the matching pinned key.
    fn signed_envelope(key_id: &str) -> (ResultEnvelope, TrustedPlatformKey) {
        let signing = SigningKey::from_bytes(&[42_u8; 32]);
        let pubkey_hex = hex::encode(signing.verifying_key().to_bytes());

        let payload = sample_payload();
        let artifacts = vec![CompanionArtifact {
            artefact_id: "art_deadbeef".into(),
            size_bytes: 1024,
            mime_type: Some("application/x-cuecrux-sealed".into()),
            sealed: true,
            purpose_tag: "projection".into(),
            fetch_url: Some("https://platform.example/a".into()),
        }];
        let content_hash = result_envelope_content_hash(&payload, &artifacts).expect("hash");
        let raw = hex::decode(content_hash.strip_prefix("blake3:").unwrap()).unwrap();
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&raw);
        let sig = signing.sign(&hash);

        let envelope = ResultEnvelope {
            schema_version: RESULT_ENVELOPE_SCHEMA_V1.into(),
            job_id: "job_test_1".into(),
            tenant_id: "business::acme".into(),
            passport_fpr: Some("p_abc".into()),
            credit_spend_receipt: Some("crown:r_9f3a".into()),
            payload,
            companion_artifacts: artifacts,
            blake3_content_hash: content_hash,
            platform_signature: PlatformSignature {
                alg: "ed25519".into(),
                key_id: key_id.into(),
                signature: hex::encode(sig.to_bytes()),
            },
        };
        let pinned = TrustedPlatformKey {
            key_id: key_id.into(),
            public_key_hex: pubkey_hex,
        };
        (envelope, pinned)
    }

    #[test]
    fn valid_envelope_verifies_and_returns_hash() {
        let (envelope, pinned) = signed_envelope("platform-result-2026a");
        let hash = verify_result_envelope(&envelope, &[pinned]).expect("should verify");
        let raw = hex::decode(envelope.blake3_content_hash.strip_prefix("blake3:").unwrap()).unwrap();
        assert_eq!(hash.as_slice(), raw.as_slice());
    }

    #[test]
    fn tampered_payload_is_rejected_on_hash_mismatch() {
        let (mut envelope, pinned) = signed_envelope("platform-result-2026a");
        // Mutate a fact after signing — content hash no longer matches.
        envelope.payload.facts[0].value = "tampered".into();
        let err = verify_result_envelope(&envelope, &[pinned]).unwrap_err();
        assert!(matches!(err, EnvelopeVerifyError::HashMismatch { .. }));
    }

    #[test]
    fn stated_hash_mismatch_is_rejected() {
        let (mut envelope, pinned) = signed_envelope("platform-result-2026a");
        // Keep payload, lie about the stated hash.
        envelope.blake3_content_hash = format!("blake3:{}", "00".repeat(32));
        let err = verify_result_envelope(&envelope, &[pinned]).unwrap_err();
        assert!(matches!(err, EnvelopeVerifyError::HashMismatch { .. }));
    }

    #[test]
    fn wrong_signer_key_is_rejected() {
        let (envelope, _pinned) = signed_envelope("platform-result-2026a");
        // Pin a *different* key under the same key_id — signature won't verify.
        let other = SigningKey::from_bytes(&[7_u8; 32]);
        let bad_pinned = TrustedPlatformKey {
            key_id: "platform-result-2026a".into(),
            public_key_hex: hex::encode(other.verifying_key().to_bytes()),
        };
        let err = verify_result_envelope(&envelope, &[bad_pinned]).unwrap_err();
        assert_eq!(err, EnvelopeVerifyError::BadSignature("platform-result-2026a".into()));
    }

    #[test]
    fn unknown_key_id_is_rejected() {
        let (envelope, _pinned) = signed_envelope("platform-result-2026a");
        let err = verify_result_envelope(&envelope, &[]).unwrap_err();
        assert_eq!(err, EnvelopeVerifyError::UnknownSigner("platform-result-2026a".into()));
    }

    #[test]
    fn unsupported_schema_is_rejected() {
        let (mut envelope, pinned) = signed_envelope("platform-result-2026a");
        envelope.schema_version = "crux.result_envelope.v2".into();
        let err = verify_result_envelope(&envelope, &[pinned]).unwrap_err();
        assert!(matches!(err, EnvelopeVerifyError::UnsupportedSchema(_)));
    }

    #[test]
    fn content_hash_is_deterministic() {
        let payload = sample_payload();
        let arts: Vec<CompanionArtifact> = vec![];
        assert_eq!(
            result_envelope_content_hash(&payload, &arts).expect("hash"),
            result_envelope_content_hash(&payload, &arts).expect("hash")
        );
    }
}
