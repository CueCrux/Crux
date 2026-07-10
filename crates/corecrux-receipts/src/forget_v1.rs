// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! v1 `Forget` + `PermanentPurge` receipt body types and helpers.
//!
//! These are the cryptographic anchors for GDPR Art. 17 scoped erasure
//! (ExecPlan `agent-ux-09-scoped-forget-2026-05-27`). The receipt body
//! captures:
//!
//! - The typed `Scope` selector that was resolved (enum, never free-form jq).
//! - The list of `fact_id`s actually affected.
//! - Pre-forget `payload_hash` BLAKE3 of each affected value so a future
//!   verifier can prove "this content existed and was deliberately
//!   forgotten" without needing the content itself.
//! - The initiating `passport_id` (T.3) + the reason supplied by the user.
//! - A `recovery_window_ends_at` ISO-8601 timestamp.
//!
//! The bytes-first invariant from `body_v1.rs` still applies: callers
//! canonical-CBOR-encode the body once, hash it with BLAKE3, then sign the
//! hash with Ed25519 via the v1 verifier path. This module ships the body
//! types + canonicalisation + parse helpers; signing and verification reuse
//! `verify_v1.rs`.

use std::io::Cursor;

use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Typed, non-jq-able scope selector for a scoped-forget call.
///
/// Constraint NN-1 (plan spec): "scope is a TYPED enum: {entity_prefix,
/// key_glob, passport_id, before_timestamp, tenant_id}. Reject arbitrary
/// jq/SQL." Anything outside this enum is a parse error at the MCP layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ForgetScopeV1 {
    /// Forget every fact whose entity starts with this literal prefix.
    EntityPrefix { value: String },
    /// Forget every fact whose key matches this glob (supports `*`).
    KeyGlob { value: String },
    /// Forget every fact written by this passport.
    PassportId { value: String },
    /// Forget every fact stored strictly before this ISO-8601 timestamp.
    BeforeTimestamp { value: String },
    /// Forget every fact scoped to this tenant.
    TenantId { value: String },
}

impl ForgetScopeV1 {
    /// Human-readable rendering for logs and CLI output.
    pub fn render(&self) -> String {
        match self {
            Self::EntityPrefix { value } => format!("entity_prefix={value}"),
            Self::KeyGlob { value } => format!("key_glob={value}"),
            Self::PassportId { value } => format!("passport_id={value}"),
            Self::BeforeTimestamp { value } => format!("before_timestamp={value}"),
            Self::TenantId { value } => format!("tenant_id={value}"),
        }
    }
}

/// One entry in the "facts affected" list of a forget receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgetFactRefV1 {
    pub fact_id: String,
    /// Pre-forget BLAKE3 hash of `fact.value` so a future verifier can
    /// prove the content existed and was forgotten without retaining it.
    pub pre_forget_value_hash_hex: String,
    pub entity: String,
    pub key: String,
}

/// Canonical body of a `Forget` receipt (CBOR-encoded by caller).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgetReceiptBodyV1 {
    pub schema: String, // "cuecrux.receipt.forget.v1"
    pub receipt_id: String,
    pub tenant_id: String,
    /// Passport that initiated the forget (T.3 attribution).
    pub passport_id: String,
    pub reason: String,
    pub scope: ForgetScopeV1,
    pub facts_affected: Vec<ForgetFactRefV1>,
    pub initiated_at: String,
    pub recovery_window_ends_at: String,
}

/// Canonical body of a `PermanentPurge` receipt — emitted by the recovery-
/// window purge job when the soft-deleted facts are physically removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermanentPurgeReceiptBodyV1 {
    pub schema: String, // "cuecrux.receipt.permanent_purge.v1"
    pub receipt_id: String,
    pub tenant_id: String,
    /// The forget receipt id that authorised this purge.
    pub source_forget_receipt_id: String,
    /// fact_ids that were physically removed.
    pub purged_fact_ids: Vec<String>,
    pub purged_at: String,
}

/// Receipt body schema identifiers, used in CBOR `schema` fields and the
/// EVT_* stream tags for the v3 dataplane.
pub const SCHEMA_FORGET_BODY_V1: &str = "cuecrux.receipt.forget.v1";
pub const SCHEMA_PERMANENT_PURGE_BODY_V1: &str = "cuecrux.receipt.permanent_purge.v1";

pub const EVT_RECEIPT_FORGET_BODY_V1: &str = "receipt.forget.body.v1";
pub const EVT_RECEIPT_PERMANENT_PURGE_BODY_V1: &str = "receipt.permanent_purge.body.v1";

pub const CONTENT_TYPE_FORGET_BODY_V1: &str = "application/cbor; profile=cuecrux-receipt-forget-v1";
pub const CONTENT_TYPE_PERMANENT_PURGE_BODY_V1: &str = "application/cbor; profile=cuecrux-receipt-permanent-purge-v1";

#[derive(Debug, Error)]
pub enum ForgetReceiptError {
    #[error("cbor encode: {0}")]
    CborEncode(String),
    #[error("cbor decode: {0}")]
    CborDecode(String),
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("invalid scope: {0}")]
    InvalidScope(String),
}

/// Encode a `Forget` body into canonical CBOR bytes for hashing and
/// signing. The producer is responsible for canonical key ordering; serde +
/// ciborium emit struct fields in declaration order, which is stable for
/// these types.
pub fn encode_forget_body_v1(body: &ForgetReceiptBodyV1) -> Result<Vec<u8>, ForgetReceiptError> {
    let mut out = Vec::with_capacity(512);
    ciborium::ser::into_writer(body, &mut out).map_err(|e| ForgetReceiptError::CborEncode(e.to_string()))?;
    Ok(out)
}

/// Encode a `PermanentPurge` body into canonical CBOR bytes.
pub fn encode_permanent_purge_body_v1(body: &PermanentPurgeReceiptBodyV1) -> Result<Vec<u8>, ForgetReceiptError> {
    let mut out = Vec::with_capacity(256);
    ciborium::ser::into_writer(body, &mut out).map_err(|e| ForgetReceiptError::CborEncode(e.to_string()))?;
    Ok(out)
}

/// Decode a `Forget` body from canonical CBOR bytes.
pub fn decode_forget_body_v1(bytes: &[u8]) -> Result<ForgetReceiptBodyV1, ForgetReceiptError> {
    ciborium::de::from_reader(Cursor::new(bytes)).map_err(|e| ForgetReceiptError::CborDecode(e.to_string()))
}

/// Decode a `PermanentPurge` body from canonical CBOR bytes.
pub fn decode_permanent_purge_body_v1(bytes: &[u8]) -> Result<PermanentPurgeReceiptBodyV1, ForgetReceiptError> {
    ciborium::de::from_reader(Cursor::new(bytes)).map_err(|e| ForgetReceiptError::CborDecode(e.to_string()))
}

/// Best-effort extractor used by drift tools and the export bundle. Returns
/// `None` if the bytes aren't a valid forget body (e.g. tampered CBOR).
pub fn extract_forget_summary_v1(body_bytes: &[u8]) -> Option<ForgetReceiptSummaryV1> {
    let v: Value = ciborium::de::from_reader(Cursor::new(body_bytes)).ok()?;
    let Value::Map(map) = v else { return None };

    let schema = get_text(&map, "schema")?;
    if schema != SCHEMA_FORGET_BODY_V1 {
        return None;
    }
    let receipt_id = get_text(&map, "receipt_id")?;
    let tenant_id = get_text(&map, "tenant_id")?;
    let passport_id = get_text(&map, "passport_id")?;
    let facts_affected_count = match get_val(&map, "facts_affected") {
        Some(Value::Array(arr)) => arr.len(),
        _ => 0,
    };
    Some(ForgetReceiptSummaryV1 {
        receipt_id,
        tenant_id,
        passport_id,
        facts_affected_count,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgetReceiptSummaryV1 {
    pub receipt_id: String,
    pub tenant_id: String,
    pub passport_id: String,
    pub facts_affected_count: usize,
}

/// Compute the BLAKE3 hex digest of an arbitrary value, used when building
/// `pre_forget_value_hash_hex` for each affected fact.
pub fn blake3_hex(input: &[u8]) -> String {
    blake3::hash(input).to_hex().to_string()
}

fn get_val<'a>(map: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    for (k, v) in map {
        if let Value::Text(s) = k {
            if s == key {
                return Some(v);
            }
        }
    }
    None
}

fn get_text(map: &[(Value, Value)], key: &str) -> Option<String> {
    match get_val(map, key) {
        Some(Value::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample_body() -> ForgetReceiptBodyV1 {
        ForgetReceiptBodyV1 {
            schema: SCHEMA_FORGET_BODY_V1.to_string(),
            receipt_id: "r_forget_01".to_string(),
            tenant_id: "tenant-alpha".to_string(),
            passport_id: "passport:user-bob".to_string(),
            reason: "GDPR Art. 17 request".to_string(),
            scope: ForgetScopeV1::EntityPrefix {
                value: "personal::".to_string(),
            },
            facts_affected: vec![
                ForgetFactRefV1 {
                    fact_id: "f_001".to_string(),
                    pre_forget_value_hash_hex: blake3_hex(b"first value"),
                    entity: "personal::contact".to_string(),
                    key: "email".to_string(),
                },
                ForgetFactRefV1 {
                    fact_id: "f_002".to_string(),
                    pre_forget_value_hash_hex: blake3_hex(b"second value"),
                    entity: "personal::contact".to_string(),
                    key: "phone".to_string(),
                },
            ],
            initiated_at: "2026-05-27T12:00:00Z".to_string(),
            recovery_window_ends_at: "2026-06-26T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn forget_body_cbor_roundtrip() {
        let body = sample_body();
        let bytes = encode_forget_body_v1(&body).unwrap();
        let decoded = decode_forget_body_v1(&bytes).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn forget_body_summary_extracts_count() {
        let body = sample_body();
        let bytes = encode_forget_body_v1(&body).unwrap();
        let summary = extract_forget_summary_v1(&bytes).unwrap();
        assert_eq!(summary.receipt_id, "r_forget_01");
        assert_eq!(summary.tenant_id, "tenant-alpha");
        assert_eq!(summary.passport_id, "passport:user-bob");
        assert_eq!(summary.facts_affected_count, 2);
    }

    #[test]
    fn forget_body_summary_rejects_other_schemas() {
        let bytes = {
            let val = Value::Map(vec![
                (
                    Value::Text("schema".into()),
                    Value::Text("cuecrux.receipt.body.v1".into()),
                ),
                (Value::Text("receipt_id".into()), Value::Text("r1".into())),
            ]);
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&val, &mut buf).unwrap();
            buf
        };
        assert!(extract_forget_summary_v1(&bytes).is_none());
    }

    #[test]
    fn forget_body_tamper_bit_flip_changes_hash() {
        let body = sample_body();
        let bytes = encode_forget_body_v1(&body).unwrap();
        let orig = blake3::hash(&bytes);
        let mut tampered = bytes.clone();
        // Flip the lowest bit of the last byte — guaranteed CBOR-valid for
        // these payloads (text-string lengths aren't here) but changes the
        // BLAKE3 digest, which is what the v1 verifier checks.
        *tampered.last_mut().unwrap() ^= 0x01;
        let new = blake3::hash(&tampered);
        assert_ne!(orig.as_bytes(), new.as_bytes());
    }

    #[test]
    fn permanent_purge_body_cbor_roundtrip() {
        let body = PermanentPurgeReceiptBodyV1 {
            schema: SCHEMA_PERMANENT_PURGE_BODY_V1.to_string(),
            receipt_id: "r_purge_01".to_string(),
            tenant_id: "tenant-alpha".to_string(),
            source_forget_receipt_id: "r_forget_01".to_string(),
            purged_fact_ids: vec!["f_001".to_string(), "f_002".to_string()],
            purged_at: "2026-06-26T12:00:00Z".to_string(),
        };
        let bytes = encode_permanent_purge_body_v1(&body).unwrap();
        let decoded = decode_permanent_purge_body_v1(&bytes).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn forget_scope_variants_serialise_with_type_tag() {
        let scope = ForgetScopeV1::EntityPrefix {
            value: "test-fixture-".to_string(),
        };
        let json = serde_json::to_string(&scope).unwrap();
        assert!(json.contains("\"type\":\"entity_prefix\""));
        assert!(json.contains("\"value\":\"test-fixture-\""));

        let scope = ForgetScopeV1::TenantId {
            value: "tenant-alpha".to_string(),
        };
        let json = serde_json::to_string(&scope).unwrap();
        assert!(json.contains("\"type\":\"tenant_id\""));
    }

    #[test]
    fn forget_scope_render_is_human_readable() {
        let scope = ForgetScopeV1::KeyGlob {
            value: "secret*".to_string(),
        };
        assert_eq!(scope.render(), "key_glob=secret*");
    }

    #[test]
    fn forget_body_with_empty_facts_affected_still_encodes() {
        // Dry-run / no-match case must still produce a valid receipt body
        // so that "I tried to forget but matched nothing" is a recorded
        // event (Art. 12 audit-retention compromise).
        let mut body = sample_body();
        body.facts_affected.clear();
        let bytes = encode_forget_body_v1(&body).unwrap();
        let decoded = decode_forget_body_v1(&bytes).unwrap();
        assert!(decoded.facts_affected.is_empty());
    }
}
