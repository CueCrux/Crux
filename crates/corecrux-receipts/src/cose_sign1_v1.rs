// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! CROWN SCITT Application Profile v0.2 COSE_Sign1 export.
//!
//! This module is deliberately a profile adapter, not a new receipt format. It
//! maps the daemon-facing JSON names accepted by [`CrownReceiptV1`] to the
//! kebab-case CDDL labels, wraps the resulting CBOR payload in a tagged
//! COSE_Sign1 structure, and signs the RFC 9052 `Sig_structure` with Ed25519.
//!
//! The CDDL fields that map directly are represented below. Existing daemon
//! fields that do not map are intentionally not exported: `receiptId`
//! (distinct from `snapshotId`/`snap-id`), `evidence` (the CDDL defines it as a
//! separate `crown-evidence` record), top-level `citations` and
//! `counterfactual` (selection owns those concepts), and `retrieval.rerankK`
//! (the CDDL's `rerank` is a boolean). Legacy structured `signature` objects
//! also do not map to the CDDL's optional bytes/text/null field. No replacement
//! values are synthesized.

use std::collections::BTreeMap;
use std::io::Cursor;

use ciborium::value::Value as CborValue;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, Serializer};

/// RFC 9052 tag for a COSE_Sign1 message.
pub const COSE_SIGN1_CBOR_TAG: u64 = 18;
/// CROWN receipt CBOR media type required in protected header label 3.
pub const CROWN_RECEIPT_CBOR_CONTENT_TYPE: &str = "application/vnd.crown.receipt+cbor";
/// COSE EdDSA algorithm identifier used for Ed25519.
pub const COSE_ALG_EDDSA: i64 = -8;

/// A required CDDL value that may explicitly be CBOR `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TextOrNullV1(pub Option<String>);

/// CDDL `fusion-group`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrownFusionV1 {
    #[serde(rename = "bm25-weight", alias = "bm25Weight", alias = "w_bm25")]
    #[serde(serialize_with = "serialize_float16")]
    pub bm25_weight: f64,
    #[serde(rename = "vector-weight", alias = "vectorWeight", alias = "w_vec")]
    #[serde(serialize_with = "serialize_float16")]
    pub vector_weight: f64,
    #[serde(rename = "rrf-k", alias = "rrfK", alias = "rrf_k")]
    pub rrf_k: u64,
}

/// CDDL `retrieval-group`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrownRetrievalV1 {
    #[serde(rename = "top-k", alias = "topK", skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rerank: Option<bool>,
    #[serde(
        rename = "min-domains",
        alias = "minDomains",
        skip_serializing_if = "Option::is_none"
    )]
    pub min_domains: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget: Option<String>,
}

/// CDDL `candidate-entry`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrownCandidateEntryV1 {
    pub id: String,
    #[serde(serialize_with = "serialize_float16")]
    pub score: f64,
    #[serde(rename = "reject-reason", alias = "rejectReason")]
    pub reject_reason: String,
}

/// CDDL `counterfactual-group`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CrownCounterfactualV1 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub considered: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejected: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidates: Option<Vec<CrownCandidateEntryV1>>,
}

/// CDDL `selection-group`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrownSelectionV1 {
    #[serde(rename = "mi-ses-size", alias = "miSESSize")]
    pub mi_ses_size: u64,
    #[serde(rename = "citation-ids", alias = "citationIds")]
    pub citation_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<BTreeMap<String, Vec<String>>>,
    #[serde(
        rename = "distinct-domains",
        alias = "distinctDomains",
        skip_serializing_if = "Option::is_none"
    )]
    pub distinct_domains: Option<u64>,
    #[serde(
        rename = "fragility-score",
        alias = "fragilityScore",
        skip_serializing_if = "Option::is_none"
    )]
    #[serde(serialize_with = "serialize_optional_float16")]
    pub fragility_score: Option<f64>,
    #[serde(
        rename = "load-bearing-citations",
        alias = "loadBearingCitations",
        skip_serializing_if = "Option::is_none"
    )]
    pub load_bearing_citations: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counterfactual: Option<CrownCounterfactualV1>,
}

/// CDDL `timings-group`, in milliseconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrownTimingsV1 {
    #[serde(rename = "retrieve-ms", alias = "retrieveMs")]
    pub retrieve_ms: u64,
    #[serde(rename = "rerank-ms", alias = "rerankMs")]
    pub rerank_ms: u64,
    #[serde(rename = "llm-ms", alias = "llmMs")]
    pub llm_ms: u64,
    #[serde(rename = "total-ms", alias = "totalMs")]
    pub total_ms: u64,
}

/// CDDL `cursor-group`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrownKnowledgeStateCursorV1 {
    #[serde(rename = "shard-id", alias = "shardId")]
    pub shard_id: u64,
    pub epoch: u64,
    #[serde(rename = "segment-seq", alias = "segmentSeq")]
    pub segment_seq: u64,
    pub offset: u64,
}

/// Typed CROWN receipt payload defined by `crown-receipt.cddl`.
///
/// Deserialization accepts the daemon's camelCase spellings and the CDDL's
/// kebab-case spellings. Serialization always emits the kebab-case CDDL names.
/// Unknown daemon JSON fields are ignored rather than turned into invented
/// profile claims; see the module-level mapping note.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrownReceiptV1 {
    #[serde(rename = "snap-id", alias = "snapId", alias = "snapshotId")]
    pub snap_id: String,
    #[serde(rename = "answer-id", alias = "answerId")]
    pub answer_id: String,
    #[serde(rename = "parent-snap-id", alias = "parentSnapId")]
    pub parent_snap_id: TextOrNullV1,
    #[serde(rename = "generated-at", alias = "generatedAt")]
    pub generated_at: String,
    pub mode: String,
    #[serde(rename = "mode-requested", alias = "modeRequested")]
    pub mode_requested: String,
    #[serde(rename = "query-hash", alias = "queryHash")]
    pub query_hash: String,
    #[serde(rename = "query-text", alias = "queryText")]
    pub query_text: String,
    #[serde(rename = "receipt-hash", alias = "receiptHash")]
    pub receipt_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(
        rename = "signing-kid",
        alias = "signingKid",
        skip_serializing_if = "Option::is_none"
    )]
    pub signing_kid: Option<String>,
    #[serde(
        rename = "signing-pub",
        alias = "signingPub",
        skip_serializing_if = "Option::is_none"
    )]
    pub signing_pub: Option<String>,
    #[serde(rename = "signed-at", alias = "signedAt", skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
    #[serde(rename = "llm-model", alias = "llmModel", skip_serializing_if = "Option::is_none")]
    pub llm_model: Option<String>,
    #[serde(
        rename = "llm-request-id",
        alias = "llmRequestId",
        skip_serializing_if = "Option::is_none"
    )]
    pub llm_request_id: Option<String>,
    pub fusion: CrownFusionV1,
    pub retrieval: CrownRetrievalV1,
    pub selection: CrownSelectionV1,
    pub timings: CrownTimingsV1,
    #[serde(
        rename = "knowledge-state-cursor",
        alias = "knowledgeStateCursor",
        skip_serializing_if = "Option::is_none"
    )]
    pub knowledge_state_cursor: Option<CrownKnowledgeStateCursorV1>,
    #[serde(
        rename = "trigger-action-receipt-id",
        alias = "triggerActionReceiptId",
        skip_serializing_if = "Option::is_none"
    )]
    pub trigger_action_receipt_id: Option<TextOrNullV1>,
    #[serde(rename = "tenant-id", alias = "tenantId")]
    pub tenant_id: String,
}

impl CrownReceiptV1 {
    fn validate(&self) -> Result<(), CoseSign1Error> {
        if self.snap_id.is_empty() || self.answer_id.is_empty() || self.tenant_id.is_empty() {
            return Err(CoseSign1Error::InvalidPayload(
                "snap-id, answer-id, and tenant-id must be non-empty".to_string(),
            ));
        }
        if uuid::Uuid::parse_str(&self.snap_id).is_err() || uuid::Uuid::parse_str(&self.answer_id).is_err() {
            return Err(CoseSign1Error::InvalidPayload(
                "snap-id and answer-id must be UUID strings".to_string(),
            ));
        }
        if let TextOrNullV1(Some(parent)) = &self.parent_snap_id {
            if uuid::Uuid::parse_str(parent).is_err() {
                return Err(CoseSign1Error::InvalidPayload(
                    "parent-snap-id must be a UUID string or null".to_string(),
                ));
            }
        }
        if chrono::DateTime::parse_from_rfc3339(&self.generated_at).is_err() {
            return Err(CoseSign1Error::InvalidPayload(
                "generated-at must be an RFC 3339 timestamp".to_string(),
            ));
        }
        if let Some(signed_at) = &self.signed_at {
            if chrono::DateTime::parse_from_rfc3339(signed_at).is_err() {
                return Err(CoseSign1Error::InvalidPayload(
                    "signed-at must be an RFC 3339 timestamp when present".to_string(),
                ));
            }
        }
        if let Some(TextOrNullV1(Some(receipt_id))) = &self.trigger_action_receipt_id {
            if uuid::Uuid::parse_str(receipt_id).is_err() {
                return Err(CoseSign1Error::InvalidPayload(
                    "trigger-action-receipt-id must be a UUID string or null".to_string(),
                ));
            }
        }
        if !matches!(self.mode.as_str(), "light" | "verified" | "audit") {
            return Err(CoseSign1Error::InvalidPayload(
                "mode must be light, verified, or audit".to_string(),
            ));
        }
        if !is_blake3_hash(&self.query_hash) || !is_blake3_hash(&self.receipt_hash) {
            return Err(CoseSign1Error::InvalidPayload(
                "query-hash and receipt-hash must be blake3:<64 hex>".to_string(),
            ));
        }
        if let Some(score) = self.selection.fragility_score {
            if !score.is_finite() || !(0.0..=1.0).contains(&score) {
                return Err(CoseSign1Error::InvalidPayload(
                    "selection.fragility-score must be finite and between 0 and 1".to_string(),
                ));
            }
        }
        if !is_exact_finite_float16(self.fusion.bm25_weight) || !is_exact_finite_float16(self.fusion.vector_weight) {
            return Err(CoseSign1Error::InvalidPayload(
                "fusion weights must be finite values exactly representable as float16".to_string(),
            ));
        }
        if let Some(score) = self.selection.fragility_score {
            if !is_exact_finite_float16(score) {
                return Err(CoseSign1Error::InvalidPayload(
                    "selection.fragility-score must be exactly representable as float16".to_string(),
                ));
            }
        }
        if let Some(counterfactual) = &self.selection.counterfactual {
            if let Some(candidates) = &counterfactual.candidates {
                if candidates
                    .iter()
                    .any(|candidate| !is_exact_finite_float16(candidate.score))
                {
                    return Err(CoseSign1Error::InvalidPayload(
                        "counterfactual candidate scores must be finite values exactly representable as float16"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Exact profile fields decoded from the protected header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoseProtectedHeaderV1 {
    pub algorithm: i64,
    pub content_type: String,
    pub kid: Vec<u8>,
    pub issuer: String,
    pub subject: String,
}

/// A structurally decoded COSE_Sign1 envelope.
///
/// This low-level decoder validates the exact protected and unprotected header
/// shape but deliberately leaves payload validation to [`verify_cose_sign1`].
/// That allows interoperability tests to inspect headers from independently
/// produced examples whose payload schema version differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedCoseSign1V1 {
    pub protected_header_bytes: Vec<u8>,
    pub protected: CoseProtectedHeaderV1,
    pub payload: Vec<u8>,
    pub signature: [u8; 64],
}

/// Successful fail-closed verification result.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedCoseSign1V1 {
    pub protected: CoseProtectedHeaderV1,
    pub receipt: CrownReceiptV1,
}

#[derive(Debug, thiserror::Error)]
pub enum CoseSign1Error {
    #[error("COSE CBOR encoding failed: {0}")]
    Encode(String),
    #[error("COSE CBOR decoding failed: {0}")]
    Decode(String),
    #[error("invalid COSE_Sign1 envelope: {0}")]
    InvalidEnvelope(String),
    #[error("invalid CROWN protected header: {0}")]
    InvalidProtectedHeader(String),
    #[error("invalid CROWN receipt payload: {0}")]
    InvalidPayload(String),
    #[error("COSE_Sign1 Ed25519 signature verification failed")]
    InvalidSignature,
}

/// Encode and sign a receipt as the profile's tagged COSE_Sign1 statement.
pub fn encode_cose_sign1_v1(
    receipt: &CrownReceiptV1,
    signing_key: &SigningKey,
    issuer: &str,
    kid: &[u8],
) -> Result<Vec<u8>, CoseSign1Error> {
    receipt.validate()?;
    validate_identity_inputs(issuer, kid)?;

    let payload = encode_value(receipt)?;
    let subject = format!("urn:crown:receipt:{}", receipt.snap_id);
    let protected_value = CborValue::Map(vec![
        (CborValue::Integer(1.into()), CborValue::Integer(COSE_ALG_EDDSA.into())),
        (
            CborValue::Integer(3.into()),
            CborValue::Text(CROWN_RECEIPT_CBOR_CONTENT_TYPE.to_string()),
        ),
        (CborValue::Integer(4.into()), CborValue::Bytes(kid.to_vec())),
        (
            CborValue::Integer(15.into()),
            CborValue::Map(vec![
                (CborValue::Integer(1.into()), CborValue::Text(issuer.to_string())),
                (CborValue::Integer(2.into()), CborValue::Text(subject)),
            ]),
        ),
    ]);
    let protected = encode_value(&protected_value)?;
    let to_sign = encode_sig_structure(&protected, &payload)?;
    let signature = signing_key.sign(&to_sign).to_bytes().to_vec();

    let envelope = CborValue::Tag(
        COSE_SIGN1_CBOR_TAG,
        Box::new(CborValue::Array(vec![
            CborValue::Bytes(protected),
            CborValue::Map(Vec::new()),
            CborValue::Bytes(payload),
            CborValue::Bytes(signature),
        ])),
    );
    encode_value(&envelope)
}

/// Decode the COSE envelope and enforce the profile's exact header shape.
pub fn decode_cose_sign1(cose_bytes: &[u8]) -> Result<DecodedCoseSign1V1, CoseSign1Error> {
    let envelope: CborValue = decode_one(cose_bytes)?;
    let CborValue::Tag(COSE_SIGN1_CBOR_TAG, tagged) = envelope else {
        return Err(CoseSign1Error::InvalidEnvelope(
            "expected CBOR tag 18 (COSE_Sign1)".to_string(),
        ));
    };
    let CborValue::Array(mut fields) = *tagged else {
        return Err(CoseSign1Error::InvalidEnvelope(
            "tag 18 value must be a four-element array".to_string(),
        ));
    };
    if fields.len() != 4 {
        return Err(CoseSign1Error::InvalidEnvelope(format!(
            "expected four elements, got {}",
            fields.len()
        )));
    }

    let signature_value = fields
        .pop()
        .ok_or_else(|| CoseSign1Error::InvalidEnvelope("missing signature".into()))?;
    let payload_value = fields
        .pop()
        .ok_or_else(|| CoseSign1Error::InvalidEnvelope("missing payload".into()))?;
    let unprotected = fields
        .pop()
        .ok_or_else(|| CoseSign1Error::InvalidEnvelope("missing unprotected header".into()))?;
    let protected_value = fields
        .pop()
        .ok_or_else(|| CoseSign1Error::InvalidEnvelope("missing protected header".into()))?;

    if unprotected != CborValue::Map(Vec::new()) {
        return Err(CoseSign1Error::InvalidEnvelope(
            "unprotected header must be an empty map".to_string(),
        ));
    }
    let CborValue::Bytes(protected_header_bytes) = protected_value else {
        return Err(CoseSign1Error::InvalidEnvelope(
            "protected header must be a byte string".to_string(),
        ));
    };
    let CborValue::Bytes(payload) = payload_value else {
        return Err(CoseSign1Error::InvalidEnvelope(
            "detached/null payloads are not valid for this profile".to_string(),
        ));
    };
    let CborValue::Bytes(signature_bytes) = signature_value else {
        return Err(CoseSign1Error::InvalidEnvelope(
            "signature must be a byte string".to_string(),
        ));
    };
    let signature: [u8; 64] = signature_bytes.try_into().map_err(|bytes: Vec<u8>| {
        CoseSign1Error::InvalidEnvelope(format!("Ed25519 signature must be 64 bytes, got {}", bytes.len()))
    })?;
    let protected = decode_protected_header(&protected_header_bytes)?;

    Ok(DecodedCoseSign1V1 {
        protected_header_bytes,
        protected,
        payload,
        signature,
    })
}

/// Verify a CROWN COSE_Sign1 statement with a caller-supplied Ed25519 key.
///
/// Verification is fail-closed: envelope/header shape, signature, full typed
/// CDDL payload, mode/hash constraints, and CWT subject linkage must all pass.
/// This checks the `receipt-hash` syntax but does not reconstruct the legacy
/// canonical-JSON receipt hash, which requires the source representation and
/// its separate canonicalization rules.
pub fn verify_cose_sign1(
    cose_bytes: &[u8],
    verifying_key: &VerifyingKey,
) -> Result<VerifiedCoseSign1V1, CoseSign1Error> {
    let decoded = decode_cose_sign1(cose_bytes)?;
    let to_verify = encode_sig_structure(&decoded.protected_header_bytes, &decoded.payload)?;
    let signature = Signature::from_bytes(&decoded.signature);
    verifying_key
        .verify_strict(&to_verify, &signature)
        .map_err(|_| CoseSign1Error::InvalidSignature)?;

    let receipt: CrownReceiptV1 =
        decode_one(&decoded.payload).map_err(|err| CoseSign1Error::InvalidPayload(err.to_string()))?;
    receipt.validate()?;
    validate_profile_float_widths(&decoded.payload)?;
    let expected_subject = format!("urn:crown:receipt:{}", receipt.snap_id);
    if decoded.protected.subject != expected_subject {
        return Err(CoseSign1Error::InvalidProtectedHeader(
            "CWT sub does not identify the payload snap-id".to_string(),
        ));
    }

    Ok(VerifiedCoseSign1V1 {
        protected: decoded.protected,
        receipt,
    })
}

fn validate_identity_inputs(issuer: &str, kid: &[u8]) -> Result<(), CoseSign1Error> {
    if issuer.is_empty() || url::Url::parse(issuer).is_err() {
        return Err(CoseSign1Error::InvalidProtectedHeader(
            "issuer must be a non-empty absolute URI".to_string(),
        ));
    }
    if kid.is_empty() || std::str::from_utf8(kid).is_err() {
        return Err(CoseSign1Error::InvalidProtectedHeader(
            "kid must be non-empty UTF-8 bytes".to_string(),
        ));
    }
    Ok(())
}

fn is_blake3_hash(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("blake3:") else {
        return false;
    };
    hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_exact_finite_float16(value: f64) -> bool {
    value.is_finite() && f64::from(half::f16::from_f64(value)).to_bits() == value.to_bits()
}

fn encode_sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, CoseSign1Error> {
    encode_value(&CborValue::Array(vec![
        CborValue::Text("Signature1".to_string()),
        CborValue::Bytes(protected.to_vec()),
        CborValue::Bytes(Vec::new()),
        CborValue::Bytes(payload.to_vec()),
    ]))
}

fn decode_protected_header(bytes: &[u8]) -> Result<CoseProtectedHeaderV1, CoseSign1Error> {
    let value: CborValue = decode_one(bytes)?;
    let CborValue::Map(entries) = value else {
        return Err(CoseSign1Error::InvalidProtectedHeader(
            "protected bytes must encode a map".to_string(),
        ));
    };
    if entries.len() != 4 {
        return Err(CoseSign1Error::InvalidProtectedHeader(format!(
            "expected exactly labels 1, 3, 4, and 15; got {} entries",
            entries.len()
        )));
    }

    let algorithm = integer_label_value(&entries, 1)?;
    if algorithm != COSE_ALG_EDDSA {
        return Err(CoseSign1Error::InvalidProtectedHeader(
            "label 1 must be -8 (EdDSA)".to_string(),
        ));
    }
    let content_type = text_label_value(&entries, 3)?;
    if content_type != CROWN_RECEIPT_CBOR_CONTENT_TYPE {
        return Err(CoseSign1Error::InvalidProtectedHeader(
            "label 3 has the wrong content type".to_string(),
        ));
    }
    let kid = match label_value(&entries, 4)? {
        CborValue::Bytes(bytes) if !bytes.is_empty() && std::str::from_utf8(bytes).is_ok() => bytes.clone(),
        _ => {
            return Err(CoseSign1Error::InvalidProtectedHeader(
                "label 4 must be a non-empty UTF-8 byte string".to_string(),
            ));
        }
    };
    let claims = match label_value(&entries, 15)? {
        CborValue::Map(claims) if claims.len() == 2 => claims,
        _ => {
            return Err(CoseSign1Error::InvalidProtectedHeader(
                "label 15 must be a two-entry CWT claims map".to_string(),
            ));
        }
    };
    let issuer = text_label_value(claims, 1)?;
    if url::Url::parse(&issuer).is_err() {
        return Err(CoseSign1Error::InvalidProtectedHeader(
            "CWT iss must be an absolute URI".to_string(),
        ));
    }
    let subject = text_label_value(claims, 2)?;
    if !subject.starts_with("urn:crown:receipt:") {
        return Err(CoseSign1Error::InvalidProtectedHeader(
            "CWT sub must start with urn:crown:receipt:".to_string(),
        ));
    }

    Ok(CoseProtectedHeaderV1 {
        algorithm,
        content_type,
        kid,
        issuer,
        subject,
    })
}

fn label_value(entries: &[(CborValue, CborValue)], label: i64) -> Result<&CborValue, CoseSign1Error> {
    let mut found = entries.iter().filter_map(|(key, value)| match key {
        CborValue::Integer(integer) if i64::try_from(*integer).ok() == Some(label) => Some(value),
        _ => None,
    });
    let value = found
        .next()
        .ok_or_else(|| CoseSign1Error::InvalidProtectedHeader(format!("required label {label} is missing")))?;
    if found.next().is_some() {
        return Err(CoseSign1Error::InvalidProtectedHeader(format!(
            "label {label} is duplicated"
        )));
    }
    Ok(value)
}

fn integer_label_value(entries: &[(CborValue, CborValue)], label: i64) -> Result<i64, CoseSign1Error> {
    match label_value(entries, label)? {
        CborValue::Integer(value) => i64::try_from(*value)
            .map_err(|_| CoseSign1Error::InvalidProtectedHeader(format!("label {label} integer is out of range"))),
        _ => Err(CoseSign1Error::InvalidProtectedHeader(format!(
            "label {label} must be an integer"
        ))),
    }
}

fn text_label_value(entries: &[(CborValue, CborValue)], label: i64) -> Result<String, CoseSign1Error> {
    match label_value(entries, label)? {
        CborValue::Text(value) => Ok(value.clone()),
        _ => Err(CoseSign1Error::InvalidProtectedHeader(format!(
            "label {label} must be text"
        ))),
    }
}

fn encode_value<T: Serialize>(value: &T) -> Result<Vec<u8>, CoseSign1Error> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).map_err(|err| CoseSign1Error::Encode(err.to_string()))?;
    Ok(bytes)
}

fn serialize_float16<S>(value: &f64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_f64(f64::from(half::f16::from_f64(*value)))
}

#[allow(clippy::ref_option)] // serde's `serialize_with` ABI borrows the field.
fn serialize_optional_float16<S>(value: &Option<f64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(value) => serializer.serialize_some(&f64::from(half::f16::from_f64(*value))),
        None => serializer.serialize_none(),
    }
}

fn decode_one<T>(bytes: &[u8]) -> Result<T, CoseSign1Error>
where
    T: for<'de> Deserialize<'de>,
{
    let mut cursor = Cursor::new(bytes);
    let decoded = ciborium::de::from_reader(&mut cursor).map_err(|err| CoseSign1Error::Decode(err.to_string()))?;
    if cursor.position() != bytes.len() as u64 {
        return Err(CoseSign1Error::Decode("trailing bytes after CBOR value".to_string()));
    }
    Ok(decoded)
}

fn validate_profile_float_widths(bytes: &[u8]) -> Result<(), CoseSign1Error> {
    let mut decoder = ciborium_ll::Decoder::from(bytes);
    scan_profile_item(&mut decoder, &mut Vec::new())?;
    if decoder.offset() != bytes.len() {
        return Err(CoseSign1Error::InvalidPayload(
            "payload float-width scan did not consume the complete CBOR value".to_string(),
        ));
    }
    Ok(())
}

fn scan_profile_item(decoder: &mut ciborium_ll::Decoder<&[u8]>, path: &mut Vec<String>) -> Result<(), CoseSign1Error> {
    let start = decoder.offset();
    let header = decoder
        .pull()
        .map_err(|_| CoseSign1Error::InvalidPayload("malformed CBOR during float-width scan".to_string()))?;
    let header_width = decoder.offset().saturating_sub(start);
    if is_profile_float16_path(path) && (!matches!(header, ciborium_ll::Header::Float(_)) || header_width != 3) {
        return Err(CoseSign1Error::InvalidPayload(format!(
            "{} must use a CBOR float16 encoding",
            path.join(".")
        )));
    }

    match header {
        ciborium_ll::Header::Bytes(len) => drain_bytes(decoder, len),
        ciborium_ll::Header::Text(len) => {
            let _ = read_text_body(decoder, len)?;
            Ok(())
        }
        ciborium_ll::Header::Array(len) => scan_array(decoder, path, len),
        ciborium_ll::Header::Map(len) => scan_map(decoder, path, len),
        ciborium_ll::Header::Tag(_) => scan_profile_item(decoder, path),
        ciborium_ll::Header::Break => Err(CoseSign1Error::InvalidPayload(
            "unexpected CBOR break during float-width scan".to_string(),
        )),
        _ => Ok(()),
    }
}

fn scan_array(
    decoder: &mut ciborium_ll::Decoder<&[u8]>,
    path: &mut Vec<String>,
    len: Option<usize>,
) -> Result<(), CoseSign1Error> {
    path.push("[]".to_string());
    match len {
        Some(len) => {
            for _ in 0..len {
                scan_profile_item(decoder, path)?;
            }
        }
        None => loop {
            let header = decoder
                .pull()
                .map_err(|_| CoseSign1Error::InvalidPayload("malformed indefinite CBOR array".to_string()))?;
            if header == ciborium_ll::Header::Break {
                break;
            }
            decoder.push(header);
            scan_profile_item(decoder, path)?;
        },
    }
    path.pop();
    Ok(())
}

fn scan_map(
    decoder: &mut ciborium_ll::Decoder<&[u8]>,
    path: &mut Vec<String>,
    len: Option<usize>,
) -> Result<(), CoseSign1Error> {
    match len {
        Some(len) => {
            for _ in 0..len {
                scan_map_entry(decoder, path)?;
            }
        }
        None => loop {
            let header = decoder
                .pull()
                .map_err(|_| CoseSign1Error::InvalidPayload("malformed indefinite CBOR map".to_string()))?;
            if header == ciborium_ll::Header::Break {
                break;
            }
            decoder.push(header);
            scan_map_entry(decoder, path)?;
        },
    }
    Ok(())
}

fn scan_map_entry(decoder: &mut ciborium_ll::Decoder<&[u8]>, path: &mut Vec<String>) -> Result<(), CoseSign1Error> {
    let header = decoder
        .pull()
        .map_err(|_| CoseSign1Error::InvalidPayload("malformed CBOR map key".to_string()))?;
    let ciborium_ll::Header::Text(len) = header else {
        return Err(CoseSign1Error::InvalidPayload(
            "CROWN payload map keys must be text".to_string(),
        ));
    };
    let key = read_text_body(decoder, len)?;
    path.push(key);
    let result = scan_profile_item(decoder, path);
    path.pop();
    result
}

fn read_text_body(decoder: &mut ciborium_ll::Decoder<&[u8]>, len: Option<usize>) -> Result<String, CoseSign1Error> {
    let mut output = String::new();
    let mut segments = decoder.text(len);
    while let Some(mut segment) = segments
        .pull()
        .map_err(|_| CoseSign1Error::InvalidPayload("malformed CBOR text".to_string()))?
    {
        let mut buffer = [0u8; 256];
        while let Some(chunk) = segment
            .pull(&mut buffer)
            .map_err(|_| CoseSign1Error::InvalidPayload("malformed UTF-8 CBOR text".to_string()))?
        {
            output.push_str(chunk);
        }
    }
    Ok(output)
}

fn drain_bytes(decoder: &mut ciborium_ll::Decoder<&[u8]>, len: Option<usize>) -> Result<(), CoseSign1Error> {
    let mut segments = decoder.bytes(len);
    while let Some(mut segment) = segments
        .pull()
        .map_err(|_| CoseSign1Error::InvalidPayload("malformed CBOR byte string".to_string()))?
    {
        let mut buffer = [0u8; 256];
        while segment
            .pull(&mut buffer)
            .map_err(|_| CoseSign1Error::InvalidPayload("malformed CBOR byte string".to_string()))?
            .is_some()
        {}
    }
    Ok(())
}

fn is_profile_float16_path(path: &[String]) -> bool {
    matches!(
        path,
        [fusion, field]
            if fusion == "fusion" && matches!(field.as_str(), "bm25-weight" | "vector-weight")
    ) || matches!(
        path,
        [selection, field]
            if selection == "selection" && field == "fragility-score"
    ) || matches!(
        path,
        [selection, counterfactual, candidates, array, field]
            if selection == "selection"
                && counterfactual == "counterfactual"
                && candidates == "candidates"
                && array == "[]"
                && field == "score"
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const HASH_A: &str = "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn representative_receipt() -> CrownReceiptV1 {
        CrownReceiptV1 {
            snap_id: "d0000001-0001-4000-8000-000000000001".to_string(),
            answer_id: "c0000001-0001-4000-8000-000000000001".to_string(),
            parent_snap_id: TextOrNullV1(None),
            generated_at: "2026-03-24T12:00:01.000Z".to_string(),
            mode: "verified".to_string(),
            mode_requested: "verified".to_string(),
            query_hash: HASH_A.to_string(),
            query_text: "What changed?".to_string(),
            receipt_hash: HASH_B.to_string(),
            signature: None,
            signing_kid: None,
            signing_pub: None,
            signed_at: None,
            llm_model: Some("gpt-test".to_string()),
            llm_request_id: Some("request-1".to_string()),
            fusion: CrownFusionV1 {
                bm25_weight: 0.5,
                vector_weight: 0.5,
                rrf_k: 60,
            },
            retrieval: CrownRetrievalV1 {
                top_k: Some(10),
                rerank: Some(true),
                min_domains: None,
                budget: None,
            },
            selection: CrownSelectionV1 {
                mi_ses_size: 2,
                citation_ids: vec!["doc-1".to_string(), "doc-2".to_string()],
                coverage: None,
                distinct_domains: Some(2),
                fragility_score: Some(0.25),
                load_bearing_citations: None,
                counterfactual: None,
            },
            timings: CrownTimingsV1 {
                retrieve_ms: 120,
                rerank_ms: 35,
                llm_ms: 950,
                total_ms: 1105,
            },
            knowledge_state_cursor: None,
            trigger_action_receipt_id: None,
            tenant_id: "tenant-test".to_string(),
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn encode_verify_round_trip_and_wrong_key_fails() {
        let key = signing_key();
        let cose = encode_cose_sign1_v1(&representative_receipt(), &key, "https://crux.local", b"test:v1").unwrap();
        let verified = verify_cose_sign1(&cose, &key.verifying_key()).unwrap();
        assert_eq!(verified.receipt.snap_id, representative_receipt().snap_id);

        let wrong_key = SigningKey::from_bytes(&[8u8; 32]).verifying_key();
        assert!(matches!(
            verify_cose_sign1(&cose, &wrong_key),
            Err(CoseSign1Error::InvalidSignature)
        ));
    }

    #[test]
    fn flipped_payload_byte_fails_verification() {
        let key = signing_key();
        let cose = encode_cose_sign1_v1(&representative_receipt(), &key, "https://crux.local", b"test:v1").unwrap();
        let mut envelope: CborValue = decode_one(&cose).unwrap();
        let CborValue::Tag(_, tagged) = &mut envelope else {
            panic!("tag")
        };
        let CborValue::Array(fields) = tagged.as_mut() else {
            panic!("array")
        };
        let CborValue::Bytes(payload) = &mut fields[2] else {
            panic!("payload")
        };
        let final_byte = payload.last_mut().unwrap();
        *final_byte ^= 1;
        let tampered = encode_value(&envelope).unwrap();
        assert!(verify_cose_sign1(&tampered, &key.verifying_key()).is_err());
    }

    #[test]
    fn non_float16_payload_is_rejected_even_when_validly_signed() {
        let key = signing_key();
        let cose = encode_cose_sign1_v1(&representative_receipt(), &key, "https://crux.local", b"test:v1").unwrap();
        let mut envelope: CborValue = decode_one(&cose).unwrap();
        let CborValue::Tag(_, tagged) = &mut envelope else {
            panic!("tag")
        };
        let CborValue::Array(fields) = tagged.as_mut() else {
            panic!("array")
        };
        let CborValue::Bytes(payload) = &mut fields[2] else {
            panic!("payload")
        };
        let position = payload
            .windows(3)
            .position(|bytes| bytes == [0xf9, 0x38, 0x00])
            .unwrap();
        payload.splice(position..position + 3, [0xfb, 0x3f, 0xe0, 0, 0, 0, 0, 0, 0]);

        let CborValue::Bytes(protected) = &fields[0] else {
            panic!("protected")
        };
        let CborValue::Bytes(payload) = &fields[2] else {
            panic!("payload")
        };
        let to_sign = encode_sig_structure(protected, payload).unwrap();
        fields[3] = CborValue::Bytes(key.sign(&to_sign).to_bytes().to_vec());
        let nonconforming = encode_value(&envelope).unwrap();

        assert!(matches!(
            verify_cose_sign1(&nonconforming, &key.verifying_key()),
            Err(CoseSign1Error::InvalidPayload(message)) if message.contains("float16")
        ));
    }

    #[test]
    fn encoder_rejects_lossy_float16_conversion() {
        let mut receipt = representative_receipt();
        receipt.fusion.bm25_weight = 0.4;
        receipt.fusion.vector_weight = 0.6;
        assert!(matches!(
            encode_cose_sign1_v1(&receipt, &signing_key(), "https://crux.local", b"test:v1"),
            Err(CoseSign1Error::InvalidPayload(message)) if message.contains("float16")
        ));
    }

    #[test]
    fn protected_header_has_exact_profile_labels_and_values() {
        let key = signing_key();
        let cose = encode_cose_sign1_v1(
            &representative_receipt(),
            &key,
            "https://engine.cuecrux.com",
            b"engine-provenance:v3",
        )
        .unwrap();
        let decoded = decode_cose_sign1(&cose).unwrap();
        assert_eq!(decoded.protected.algorithm, -8);
        assert_eq!(decoded.protected.content_type, CROWN_RECEIPT_CBOR_CONTENT_TYPE);
        assert_eq!(decoded.protected.kid, b"engine-provenance:v3");
        assert_eq!(decoded.protected.issuer, "https://engine.cuecrux.com");
        assert_eq!(
            decoded.protected.subject,
            "urn:crown:receipt:d0000001-0001-4000-8000-000000000001"
        );

        let CborValue::Map(entries) = decode_one(&decoded.protected_header_bytes).unwrap() else {
            panic!("protected map")
        };
        let labels: Vec<i64> = entries
            .iter()
            .map(|(key, _)| match key {
                CborValue::Integer(value) => i64::try_from(*value).unwrap(),
                _ => panic!("integer label"),
            })
            .collect();
        assert_eq!(labels, vec![1, 3, 4, 15]);
    }

    #[test]
    fn payload_keys_match_cddl_required_set() {
        let key = signing_key();
        let cose = encode_cose_sign1_v1(&representative_receipt(), &key, "https://crux.local", b"test:v1").unwrap();
        let decoded = decode_cose_sign1(&cose).unwrap();
        let CborValue::Map(entries) = decode_one(&decoded.payload).unwrap() else {
            panic!("payload map")
        };
        let keys: std::collections::BTreeSet<String> = entries
            .iter()
            .filter_map(|(key, _)| match key {
                CborValue::Text(text) => Some(text.clone()),
                _ => None,
            })
            .collect();
        for required in [
            "snap-id",
            "answer-id",
            "parent-snap-id",
            "generated-at",
            "mode",
            "mode-requested",
            "query-hash",
            "query-text",
            "receipt-hash",
            "fusion",
            "retrieval",
            "selection",
            "timings",
            "tenant-id",
        ] {
            assert!(keys.contains(required), "missing {required}");
        }
        assert!(keys.iter().all(|key| !key.contains('_')));

        fn nested_keys(entries: &[(CborValue, CborValue)], name: &str) -> std::collections::BTreeSet<String> {
            let (_, CborValue::Map(map)) = entries
                .iter()
                .find(|(key, _)| key == &CborValue::Text(name.to_string()))
                .unwrap()
            else {
                panic!("{name} map")
            };
            map.iter()
                .filter_map(|(key, _)| match key {
                    CborValue::Text(text) => Some(text.clone()),
                    _ => None,
                })
                .collect()
        }

        assert_eq!(
            nested_keys(&entries, "fusion"),
            ["bm25-weight", "rrf-k", "vector-weight"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );
        assert!(nested_keys(&entries, "selection").is_superset(
            &["citation-ids", "mi-ses-size"]
                .into_iter()
                .map(str::to_string)
                .collect()
        ));
        assert_eq!(
            nested_keys(&entries, "timings"),
            ["llm-ms", "rerank-ms", "retrieve-ms", "total-ms"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );

        // CDDL uses float16 for weights/scores. ciborium selects the shortest
        // exact representation after the serializer quantizes to f16.
        assert!(decoded.payload.windows(3).any(|bytes| bytes == [0xf9, 0x38, 0x00]));
        assert!(decoded.payload.windows(3).any(|bytes| bytes == [0xf9, 0x34, 0x00]));
    }

    #[test]
    fn researchcrux_example_uses_same_protected_header_labels() {
        let example = include_bytes!("../vectors/cose-sign1-v1/researchcrux-v0.2/signed-statement.cbor");
        let decoded = decode_cose_sign1(example).unwrap();
        assert_eq!(decoded.protected.algorithm, -8);
        assert_eq!(decoded.protected.content_type, CROWN_RECEIPT_CBOR_CONTENT_TYPE);
        assert_eq!(decoded.protected.kid, b"crown-test-key:v1");
        assert_eq!(decoded.protected.issuer, "https://engine.cuecrux.com");
        assert_eq!(
            decoded.protected.subject,
            "urn:crown:receipt:d0000001-0001-4000-8000-000000000001"
        );
    }

    #[test]
    fn deterministic_dev_vector_is_reproducible_and_verifies() {
        let receipt: CrownReceiptV1 =
            serde_json::from_str(include_str!("../vectors/cose-sign1-v1/deterministic-dev/receipt.json")).unwrap();
        let key = SigningKey::from_bytes(&[
            0x0f, 0x1f, 0x4b, 0xcf, 0x72, 0xc9, 0xec, 0x25, 0x6b, 0x59, 0xb4, 0x5b, 0xdd, 0x94, 0x89, 0x09, 0x57, 0xee,
            0x93, 0x2b, 0x19, 0xc4, 0xee, 0xaa, 0x15, 0xd7, 0xd8, 0xd2, 0x96, 0xb3, 0x54, 0x7b,
        ]);
        let encoded = encode_cose_sign1_v1(&receipt, &key, "https://crux.local", b"crux-cose-vector-v1").unwrap();
        let fixture = include_bytes!("../vectors/cose-sign1-v1/deterministic-dev/signed-statement.cose");
        assert_eq!(encoded, fixture);

        let verified = verify_cose_sign1(fixture, &key.verifying_key()).unwrap();
        assert_eq!(verified.receipt.snap_id, receipt.snap_id);
        assert_eq!(verified.protected.kid, b"crux-cose-vector-v1");
    }
}
