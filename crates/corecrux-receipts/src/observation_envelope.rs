// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Observation-envelope receipts — the shape governance surfaces mint.
//!
//! Two receipt shapes coexist in this codebase and must not be conflated:
//!
//! - A **stream** receipt (`r_…`) carries a CBOR body and a [`ReceiptSigV1`]
//!   envelope inside the observation *payload*.
//!   (`ReceiptSigV1`: [`crate::verify_v1`].)
//! - An **observation-envelope** receipt — this module — *is* the observation.
//!   The receipt id is the `observation_id`, the signed body is the canonical
//!   record bytes with `receipt` removed, and the signature sits in the
//!   top-level `receipt{}`. Tenant corpus erasure, `compact_facts` erasure,
//!   `memory_forget` and held hard-erasure overrides all mint this shape.
//!
//! This lives in the library rather than in the daemon because `corecruxd` is
//! a **bin-only** crate: `corecruxctl inspect-receipt` cannot import from it,
//! so verification had to be reachable from both or be duplicated. A second
//! implementation of a signature check is exactly the kind of thing that
//! drifts silently, so there is one.
//!
//! ## Wire-format warning
//!
//! [`canonical_body_bytes`] defines the bytes every observation signature on
//! disk was computed over. Changing this type's serde shape — field order, a
//! `skip_serializing_if`, a rename — invalidates every receipt ever minted.
//! The golden-vector test at the bottom of this file exists to make that
//! failure loud. Never repair it by updating the constant.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Signature envelope attached to a persisted observation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptEnvelopeV1 {
    pub alg: String,
    pub signed_by: String,
    pub body_hash: String,
    pub signature: String,
}

/// Persisted observation record (one JSONL line).
///
/// `seq` + `prev_hash` make the JSONL sequence-level tamper-evident: removing
/// or reordering any line breaks the chain. Both are `Option` with
/// `skip_serializing_if` for backwards compatibility — pre-M5e records carried
/// neither, and re-serialising them must omit both so their original
/// signatures still verify.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationRecordV1 {
    pub observation_id: String,
    pub session_id: String,
    pub ts: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ts: Option<DateTime<Utc>>,
    pub provider: String,
    pub principal: String,
    pub kind: String,
    pub payload: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    pub receipt: ReceiptEnvelopeV1,
}

/// The exact bytes an observation's signature is computed over: the record
/// as JSON with the `receipt` field removed.
///
/// See the wire-format warning in the module docs before touching this.
pub fn canonical_body_bytes(record: &ObservationRecordV1) -> Result<Vec<u8>, String> {
    let mut value = serde_json::to_value(record).map_err(|err| format!("to_value: {err}"))?;
    if let serde_json::Value::Object(obj) = &mut value {
        obj.remove("receipt");
    }
    serde_json::to_vec(&value).map_err(|err| format!("canonicalise observation body: {err}"))
}

/// Verify one record's envelope signature against a node passport key.
///
/// `expected_signer_fpr` and `public_key_hex` are the verifying node's own
/// passport. The binding is deliberately narrow: a record signed by any other
/// key fails rather than resolving against a wider keyring, so a receipt
/// cannot be "verified" by a key its minting node never held.
pub fn verify_observation_envelope(
    record: &ObservationRecordV1,
    expected_signer_fpr: &str,
    public_key_hex: &str,
) -> Result<(), String> {
    use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};

    if record.receipt.signed_by != expected_signer_fpr || record.receipt.alg != "ed25519" {
        return Err("observation envelope signer binding mismatch".to_string());
    }
    let public_key: [u8; 32] = hex::decode(public_key_hex)
        .map_err(|err| format!("decode node passport public key: {err}"))?
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("node passport public key is {} bytes", bytes.len()))?;
    let body_bytes = canonical_body_bytes(record)?;
    let body_hash = blake3::hash(&body_bytes);
    if record.receipt.body_hash != format!("blake3:{}", hex::encode(body_hash.as_bytes())) {
        return Err("observation envelope body hash mismatch".to_string());
    }
    let signature = Signature::from_slice(
        &hex::decode(&record.receipt.signature)
            .map_err(|err| format!("decode observation envelope signature: {err}"))?,
    )
    .map_err(|err| format!("parse observation envelope signature: {err}"))?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|err| format!("parse node passport public key: {err}"))?;
    verifying_key
        .verify(body_hash.as_bytes(), &signature)
        .map_err(|err| format!("verify observation envelope signature: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> ObservationRecordV1 {
        ObservationRecordV1 {
            observation_id: "obs-1".to_string(),
            session_id: "sess-a".to_string(),
            ts: DateTime::parse_from_rfc3339("2026-05-13T10:00:00Z")
                .expect("parse fixture timestamp")
                .with_timezone(&Utc),
            client_ts: None,
            provider: "claude-code".to_string(),
            principal: "fpr-x".to_string(),
            kind: "tool_use".to_string(),
            payload: serde_json::json!({"tool": "Read"}),
            seq: Some(0),
            prev_hash: None,
            receipt: ReceiptEnvelopeV1 {
                alg: "ed25519".to_string(),
                signed_by: "fpr-x".to_string(),
                body_hash: "blake3:deadbeef".to_string(),
                signature: "ffff".to_string(),
            },
        }
    }

    /// GOLDEN VECTOR — the canonical bytes every observation signature on
    /// disk was computed over. This constant was captured from the
    /// pre-extraction implementation in `corecruxd::http::observations`, so
    /// it also proves the move between crates was byte-transparent.
    ///
    /// If this fails, existing receipts no longer verify. Fix the code, never
    /// the constant.
    #[test]
    fn canonical_body_bytes_are_wire_stable() {
        let bytes = canonical_body_bytes(&fixture()).expect("canonicalise");
        assert_eq!(
            format!("blake3:{}", hex::encode(blake3::hash(&bytes).as_bytes())),
            "blake3:13c40869de39a4a8702082024ef6bf01ab3af149edd4966302f69716bbe4f287",
            "observation canonical body bytes changed — every receipt ever minted would stop verifying"
        );
    }

    #[test]
    fn canonical_body_excludes_the_receipt() {
        let bytes = canonical_body_bytes(&fixture()).expect("canonicalise");
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("parse");
        assert!(parsed.get("receipt").is_none());
        assert_eq!(parsed["observation_id"], "obs-1");
    }

    #[test]
    fn a_foreign_signer_is_refused_before_any_crypto() {
        let err = verify_observation_envelope(&fixture(), "someone-else", "00").expect_err("must refuse");
        assert!(err.contains("signer binding mismatch"), "{err}");
    }
}
