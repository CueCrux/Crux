// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! BLAKE3 plan-receipt hashing + ed25519 verification, plus the
//! `InvocationReceipt` type (master-plan §8).

use blake3::Hasher;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::canonical::CborValue;
use crate::error::SessionError;
use crate::plan::{
    ReceiptMode, SessionPlan, HASH_LEN, INVOCATION_RECEIPT_VERSION, SIGNATURE_LEN, ULID_LEN,
};

/// Compute BLAKE3(canonical CBOR of plan with receipt.hash/signature/signer_kid zeroed).
///
/// This is the value that goes in `receipt.hash` and (on hosted) is signed to
/// produce `receipt.signature`.
pub fn plan_receipt_hash(plan: &SessionPlan) -> [u8; HASH_LEN] {
    let zeroed = plan.to_zeroed_canonical_cbor();
    let mut hasher = Hasher::new();
    hasher.update(&zeroed);
    *hasher.finalize().as_bytes()
}

/// Verify the ed25519 signature of a plan in `verified` mode.
///
/// The signed payload is the 32-byte BLAKE3 hash (matching `plan.receipt.hash`),
/// not the canonical bytes themselves — this matches how Vault Transit signs
/// digests rather than arbitrary-length messages.
pub fn verify_plan_signature(plan: &SessionPlan, public_key: &[u8]) -> Result<(), SessionError> {
    if plan.receipt.mode != ReceiptMode::Verified {
        return Err(SessionError::UnsupportedMode(
            plan.receipt.mode.as_str().to_string(),
        ));
    }

    let signature_bytes = plan
        .receipt
        .signature
        .as_ref()
        .ok_or(SessionError::SignatureAbsent)?;

    if public_key.len() != 32 {
        return Err(SessionError::PublicKeyLength(public_key.len()));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(public_key);
    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| SessionError::Decode(format!("bad public key: {e}")))?;

    let signature = Signature::from_bytes(signature_bytes);

    // Re-derive the hash from the plan bytes (do not trust the value in
    // `receipt.hash` — it must match what we compute, otherwise verification
    // fails before we even look at the signature).
    let computed = plan_receipt_hash(plan);
    if computed != plan.receipt.hash {
        return Err(SessionError::BadSignature);
    }

    verifying_key
        .verify(&computed, &signature)
        .map_err(|_| SessionError::BadSignature)
}

// ─── InvocationReceipt ─────────────────────────────────────────────────────

/// Per-call invocation receipt, chained to the plan via
/// `parent_plan_receipt_hash` (master-plan §8.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationReceipt {
    pub invocation_id: [u8; ULID_LEN],
    pub session_id: [u8; ULID_LEN],
    pub parent_plan_receipt_hash: [u8; HASH_LEN],
    pub capability: String,
    /// "bulk" | "mcp"
    pub channel: String,
    pub invoked_at: u64,
    pub completed_at: u64,
    pub input_hash: [u8; HASH_LEN],
    pub output_hash: [u8; HASH_LEN],
    /// "ok" | "error" | "partial"
    pub outcome: String,
    /// Charged credits; hosted only.
    pub cost_crux: Option<u64>,
    pub receipt_hash: [u8; HASH_LEN],
    pub receipt_signature: Option<[u8; SIGNATURE_LEN]>,
    pub signer_kid: Option<String>,
}

impl InvocationReceipt {
    pub fn to_cbor_value(&self, zero_receipt: bool) -> CborValue {
        let receipt_hash = if zero_receipt {
            vec![0u8; HASH_LEN]
        } else {
            self.receipt_hash.to_vec()
        };
        let receipt_signature = if zero_receipt {
            CborValue::Null
        } else {
            match &self.receipt_signature {
                Some(s) => CborValue::Bytes(s.to_vec()),
                None => CborValue::Null,
            }
        };
        let signer_kid = if zero_receipt {
            CborValue::Null
        } else {
            match &self.signer_kid {
                Some(s) => CborValue::Text(s.clone()),
                None => CborValue::Null,
            }
        };
        CborValue::Map(vec![
            ("receipt_version".into(), CborValue::Uint(INVOCATION_RECEIPT_VERSION)),
            ("invocation_id".into(), CborValue::Bytes(self.invocation_id.to_vec())),
            ("session_id".into(), CborValue::Bytes(self.session_id.to_vec())),
            (
                "parent_plan_receipt_hash".into(),
                CborValue::Bytes(self.parent_plan_receipt_hash.to_vec()),
            ),
            ("capability".into(), CborValue::Text(self.capability.clone())),
            ("channel".into(), CborValue::Text(self.channel.clone())),
            ("invoked_at".into(), CborValue::Uint(self.invoked_at)),
            ("completed_at".into(), CborValue::Uint(self.completed_at)),
            ("input_hash".into(), CborValue::Bytes(self.input_hash.to_vec())),
            ("output_hash".into(), CborValue::Bytes(self.output_hash.to_vec())),
            ("outcome".into(), CborValue::Text(self.outcome.clone())),
            (
                "cost_crux".into(),
                match self.cost_crux {
                    Some(n) => CborValue::Uint(n),
                    None => CborValue::Null,
                },
            ),
            ("receipt_hash".into(), CborValue::Bytes(receipt_hash)),
            ("receipt_signature".into(), receipt_signature),
            ("signer_kid".into(), signer_kid),
        ])
    }

    pub fn to_canonical_cbor(&self) -> Vec<u8> {
        self.to_cbor_value(false).encode()
    }

    pub fn to_zeroed_canonical_cbor(&self) -> Vec<u8> {
        self.to_cbor_value(true).encode()
    }

    pub fn compute_hash(&self) -> [u8; HASH_LEN] {
        let zeroed = self.to_zeroed_canonical_cbor();
        let mut hasher = Hasher::new();
        hasher.update(&zeroed);
        *hasher.finalize().as_bytes()
    }
}
