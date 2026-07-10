// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! v1 `PassportSplit` + `PassportMerge` + `PassportLinkDevice` receipt body
//! types and helpers.
//!
//! These are the cryptographic anchors for the agent-ux-08 identity-
//! continuity ExecPlan (`agent-ux-08-identity-continuity-2026-05-27`). They
//! reuse the existing CROWN signing pipeline from `verify_v1.rs`: callers
//! canonical-CBOR-encode the body once, BLAKE3-hash it, then sign the hash
//! with the daemon's Ed25519 signer. No new key class is introduced.
//!
//! Constraints (from the ExecPlan):
//! - Both passports in a split or merge MUST share the same tenant (T.1).
//! - The initiating passport is recorded in `initiated_by_passport_id`
//!   (T.3 — attribution).
//! - Splits and merges are not reversible at the fact level. The source
//!   passport in a merge is marked retired; sessions become read-only
//!   references.
//! - `conflict_policy` in a merge is one of
//!   `prefer_source | prefer_target | error_on_conflict` — never
//!   silently chosen.

use std::io::Cursor;

use ciborium::value::Value;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Explicit conflict policy for a merge. NEVER silently picked — the caller
/// MUST supply one of these variants, otherwise the MCP layer rejects the
/// call with `INVALID_PARAMS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeConflictPolicyV1 {
    /// Keep the source passport's value when (entity, key) conflicts.
    PreferSource,
    /// Keep the target passport's value when (entity, key) conflicts.
    PreferTarget,
    /// Fail the merge call (409) and return the conflict list to the caller.
    ErrorOnConflict,
}

impl MergeConflictPolicyV1 {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PreferSource => "prefer_source",
            Self::PreferTarget => "prefer_target",
            Self::ErrorOnConflict => "error_on_conflict",
        }
    }
}

/// Canonical body of a `PassportSplit` receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassportSplitReceiptBodyV1 {
    pub schema: String, // "cuecrux.receipt.passport_split.v1"
    pub receipt_id: String,
    pub tenant_id: String,
    /// Passport that initiated the split (T.3 attribution).
    pub initiated_by_passport_id: String,
    /// Source passport id whose facts are inherited via read-through.
    pub source_passport_id: String,
    /// New passport id forked from the source. Future writes diverge here.
    pub new_passport_id: String,
    pub reason: String,
    pub initiated_at: String,
}

/// One (entity, key) conflict resolved during a merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassportMergeConflictV1 {
    pub entity: String,
    pub key: String,
    /// "prefer_source" | "prefer_target" — never empty, never "silent".
    pub resolution: String,
    /// fact_id chosen as the post-merge canonical value.
    pub chosen_fact_id: String,
}

/// Canonical body of a `PassportMerge` receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassportMergeReceiptBodyV1 {
    pub schema: String, // "cuecrux.receipt.passport_merge.v1"
    pub receipt_id: String,
    pub tenant_id: String,
    /// Passport that initiated the merge (T.3 attribution).
    pub initiated_by_passport_id: String,
    /// Source passport — retired post-merge, sessions become read-only refs.
    pub source_passport_id: String,
    /// Target passport — the surviving identity.
    pub target_passport_id: String,
    /// Explicit policy — never silently chosen.
    pub conflict_policy: MergeConflictPolicyV1,
    /// Conflicts resolved (empty unless conflicts existed and policy was
    /// `prefer_source` or `prefer_target`).
    pub conflicts: Vec<PassportMergeConflictV1>,
    pub reason: String,
    pub initiated_at: String,
}

/// Canonical body of a `PassportLinkDevice` receipt — binds an additional
/// device fingerprint to an existing passport with a capability subset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassportLinkDeviceReceiptBodyV1 {
    pub schema: String, // "cuecrux.receipt.passport_link_device.v1"
    pub receipt_id: String,
    pub tenant_id: String,
    /// The passport the device is being linked to. The caller's authenticated
    /// agent must own this passport AND hold operator-tier.
    pub passport_id: String,
    /// Opaque fingerprint of the new device (BLAKE3 hex over the device's
    /// canonical attestation blob). Callers pass an already-hashed value;
    /// we never store the raw attestation.
    pub device_fingerprint: String,
    /// Capability subset propagated to the new device. Defaults to
    /// `facts:read` (read-only) unless explicitly widened.
    pub capabilities_subset: Vec<String>,
    pub initiated_at: String,
}

pub const SCHEMA_PASSPORT_SPLIT_BODY_V1: &str = "cuecrux.receipt.passport_split.v1";
pub const SCHEMA_PASSPORT_MERGE_BODY_V1: &str = "cuecrux.receipt.passport_merge.v1";
pub const SCHEMA_PASSPORT_LINK_DEVICE_BODY_V1: &str = "cuecrux.receipt.passport_link_device.v1";

pub const EVT_RECEIPT_PASSPORT_SPLIT_BODY_V1: &str = "receipt.passport_split.body.v1";
pub const EVT_RECEIPT_PASSPORT_MERGE_BODY_V1: &str = "receipt.passport_merge.body.v1";
pub const EVT_RECEIPT_PASSPORT_LINK_DEVICE_BODY_V1: &str = "receipt.passport_link_device.body.v1";

pub const CONTENT_TYPE_PASSPORT_SPLIT_BODY_V1: &str = "application/cbor; profile=cuecrux-receipt-passport-split-v1";
pub const CONTENT_TYPE_PASSPORT_MERGE_BODY_V1: &str = "application/cbor; profile=cuecrux-receipt-passport-merge-v1";
pub const CONTENT_TYPE_PASSPORT_LINK_DEVICE_BODY_V1: &str =
    "application/cbor; profile=cuecrux-receipt-passport-link-device-v1";

#[derive(Debug, Error)]
pub enum IdentityReceiptError {
    #[error("cbor encode: {0}")]
    CborEncode(String),
    #[error("cbor decode: {0}")]
    CborDecode(String),
}

/// Encode a `PassportSplit` body into canonical CBOR.
pub fn encode_passport_split_body_v1(body: &PassportSplitReceiptBodyV1) -> Result<Vec<u8>, IdentityReceiptError> {
    let mut out = Vec::with_capacity(256);
    ciborium::ser::into_writer(body, &mut out).map_err(|e| IdentityReceiptError::CborEncode(e.to_string()))?;
    Ok(out)
}

/// Decode a `PassportSplit` body from canonical CBOR.
pub fn decode_passport_split_body_v1(bytes: &[u8]) -> Result<PassportSplitReceiptBodyV1, IdentityReceiptError> {
    ciborium::de::from_reader(Cursor::new(bytes)).map_err(|e| IdentityReceiptError::CborDecode(e.to_string()))
}

/// Encode a `PassportMerge` body into canonical CBOR.
pub fn encode_passport_merge_body_v1(body: &PassportMergeReceiptBodyV1) -> Result<Vec<u8>, IdentityReceiptError> {
    let mut out = Vec::with_capacity(384);
    ciborium::ser::into_writer(body, &mut out).map_err(|e| IdentityReceiptError::CborEncode(e.to_string()))?;
    Ok(out)
}

/// Decode a `PassportMerge` body from canonical CBOR.
pub fn decode_passport_merge_body_v1(bytes: &[u8]) -> Result<PassportMergeReceiptBodyV1, IdentityReceiptError> {
    ciborium::de::from_reader(Cursor::new(bytes)).map_err(|e| IdentityReceiptError::CborDecode(e.to_string()))
}

/// Encode a `PassportLinkDevice` body into canonical CBOR.
pub fn encode_passport_link_device_body_v1(
    body: &PassportLinkDeviceReceiptBodyV1,
) -> Result<Vec<u8>, IdentityReceiptError> {
    let mut out = Vec::with_capacity(256);
    ciborium::ser::into_writer(body, &mut out).map_err(|e| IdentityReceiptError::CborEncode(e.to_string()))?;
    Ok(out)
}

/// Decode a `PassportLinkDevice` body from canonical CBOR.
pub fn decode_passport_link_device_body_v1(
    bytes: &[u8],
) -> Result<PassportLinkDeviceReceiptBodyV1, IdentityReceiptError> {
    ciborium::de::from_reader(Cursor::new(bytes)).map_err(|e| IdentityReceiptError::CborDecode(e.to_string()))
}

/// Best-effort summary extractor: read the schema string out of any
/// identity receipt body without committing to a particular schema. Returns
/// `None` if the bytes aren't a recognised identity-receipt body.
pub fn extract_identity_receipt_schema_v1(bytes: &[u8]) -> Option<String> {
    let v: Value = ciborium::de::from_reader(Cursor::new(bytes)).ok()?;
    let Value::Map(map) = v else { return None };
    for (k, val) in map {
        if let (Value::Text(name), Value::Text(value)) = (k, val) {
            if name == "schema" {
                return match value.as_str() {
                    SCHEMA_PASSPORT_SPLIT_BODY_V1
                    | SCHEMA_PASSPORT_MERGE_BODY_V1
                    | SCHEMA_PASSPORT_LINK_DEVICE_BODY_V1 => Some(value),
                    _ => None,
                };
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(dead_code)]
fn blake3_hex(input: &[u8]) -> String {
    blake3::hash(input).to_hex().to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn split_body() -> PassportSplitReceiptBodyV1 {
        PassportSplitReceiptBodyV1 {
            schema: SCHEMA_PASSPORT_SPLIT_BODY_V1.to_string(),
            receipt_id: "r_split_01".to_string(),
            tenant_id: "tenant-alpha".to_string(),
            initiated_by_passport_id: "passport:alice".to_string(),
            source_passport_id: "passport:alice".to_string(),
            new_passport_id: "passport:alice-work".to_string(),
            reason: "separate work persona from personal".to_string(),
            initiated_at: "2026-05-28T12:00:00Z".to_string(),
        }
    }

    fn merge_body() -> PassportMergeReceiptBodyV1 {
        PassportMergeReceiptBodyV1 {
            schema: SCHEMA_PASSPORT_MERGE_BODY_V1.to_string(),
            receipt_id: "r_merge_01".to_string(),
            tenant_id: "tenant-alpha".to_string(),
            initiated_by_passport_id: "passport:alice".to_string(),
            source_passport_id: "passport:alice-old".to_string(),
            target_passport_id: "passport:alice".to_string(),
            conflict_policy: MergeConflictPolicyV1::PreferTarget,
            conflicts: vec![PassportMergeConflictV1 {
                entity: "person:alice".to_string(),
                key: "city".to_string(),
                resolution: "prefer_target".to_string(),
                chosen_fact_id: "f_001".to_string(),
            }],
            reason: "consolidate after device retirement".to_string(),
            initiated_at: "2026-05-28T12:05:00Z".to_string(),
        }
    }

    fn link_device_body() -> PassportLinkDeviceReceiptBodyV1 {
        PassportLinkDeviceReceiptBodyV1 {
            schema: SCHEMA_PASSPORT_LINK_DEVICE_BODY_V1.to_string(),
            receipt_id: "r_link_01".to_string(),
            tenant_id: "tenant-alpha".to_string(),
            passport_id: "passport:alice".to_string(),
            device_fingerprint: blake3_hex(b"laptop-001-attestation"),
            capabilities_subset: vec!["facts:read".to_string()],
            initiated_at: "2026-05-28T12:10:00Z".to_string(),
        }
    }

    #[test]
    fn split_body_cbor_roundtrip() {
        let body = split_body();
        let bytes = encode_passport_split_body_v1(&body).unwrap();
        let decoded = decode_passport_split_body_v1(&bytes).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn merge_body_cbor_roundtrip() {
        let body = merge_body();
        let bytes = encode_passport_merge_body_v1(&body).unwrap();
        let decoded = decode_passport_merge_body_v1(&bytes).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn link_device_body_cbor_roundtrip() {
        let body = link_device_body();
        let bytes = encode_passport_link_device_body_v1(&body).unwrap();
        let decoded = decode_passport_link_device_body_v1(&bytes).unwrap();
        assert_eq!(decoded, body);
    }

    #[test]
    fn split_body_tamper_bit_flip_changes_hash() {
        let body = split_body();
        let bytes = encode_passport_split_body_v1(&body).unwrap();
        let orig = blake3::hash(&bytes);
        let mut tampered = bytes.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        let new = blake3::hash(&tampered);
        assert_ne!(orig.as_bytes(), new.as_bytes());
    }

    #[test]
    fn merge_body_tamper_bit_flip_changes_hash() {
        let body = merge_body();
        let bytes = encode_passport_merge_body_v1(&body).unwrap();
        let orig = blake3::hash(&bytes);
        let mut tampered = bytes.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        let new = blake3::hash(&tampered);
        assert_ne!(orig.as_bytes(), new.as_bytes());
    }

    #[test]
    fn link_device_body_tamper_bit_flip_changes_hash() {
        let body = link_device_body();
        let bytes = encode_passport_link_device_body_v1(&body).unwrap();
        let orig = blake3::hash(&bytes);
        let mut tampered = bytes.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        let new = blake3::hash(&tampered);
        assert_ne!(orig.as_bytes(), new.as_bytes());
    }

    #[test]
    fn conflict_policy_serialises_with_snake_case() {
        let json = serde_json::to_string(&MergeConflictPolicyV1::PreferSource).unwrap();
        assert_eq!(json, "\"prefer_source\"");
        let json = serde_json::to_string(&MergeConflictPolicyV1::ErrorOnConflict).unwrap();
        assert_eq!(json, "\"error_on_conflict\"");
        assert_eq!(MergeConflictPolicyV1::PreferSource.as_str(), "prefer_source");
        assert_eq!(MergeConflictPolicyV1::PreferTarget.as_str(), "prefer_target");
        assert_eq!(MergeConflictPolicyV1::ErrorOnConflict.as_str(), "error_on_conflict");
    }

    #[test]
    fn extract_schema_recognises_all_three_classes() {
        let split = encode_passport_split_body_v1(&split_body()).unwrap();
        assert_eq!(
            extract_identity_receipt_schema_v1(&split).as_deref(),
            Some(SCHEMA_PASSPORT_SPLIT_BODY_V1)
        );
        let merge = encode_passport_merge_body_v1(&merge_body()).unwrap();
        assert_eq!(
            extract_identity_receipt_schema_v1(&merge).as_deref(),
            Some(SCHEMA_PASSPORT_MERGE_BODY_V1)
        );
        let link = encode_passport_link_device_body_v1(&link_device_body()).unwrap();
        assert_eq!(
            extract_identity_receipt_schema_v1(&link).as_deref(),
            Some(SCHEMA_PASSPORT_LINK_DEVICE_BODY_V1)
        );
    }

    #[test]
    fn extract_schema_rejects_other_schemas() {
        let bytes = {
            let val = Value::Map(vec![(
                Value::Text("schema".into()),
                Value::Text("cuecrux.receipt.forget.v1".into()),
            )]);
            let mut buf = Vec::new();
            ciborium::ser::into_writer(&val, &mut buf).unwrap();
            buf
        };
        assert!(extract_identity_receipt_schema_v1(&bytes).is_none());
    }

    #[test]
    fn merge_with_error_on_conflict_carries_no_resolved_entries() {
        let mut body = merge_body();
        body.conflict_policy = MergeConflictPolicyV1::ErrorOnConflict;
        body.conflicts.clear();
        let bytes = encode_passport_merge_body_v1(&body).unwrap();
        let decoded = decode_passport_merge_body_v1(&bytes).unwrap();
        assert!(decoded.conflicts.is_empty());
        assert_eq!(decoded.conflict_policy, MergeConflictPolicyV1::ErrorOnConflict);
    }
}
