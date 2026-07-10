// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! v1 `ApprovalDecision` receipt class — agent-ux-05 (Risk-Tiered HITL).
//!
//! ## What this is
//!
//! A new receipt class emitted whenever an operator-tier passport
//! decides on a pending approval request created by `approval_request`.
//! The MCP tool [`crate::ApprovalDecisionBodyInputV1`] is canonicalised
//! into CBOR via [`build_approval_decision_body_v1`], then signed with
//! the daemon's Ed25519 passport key via
//! [`sign_approval_decision_v1`]. Verification reuses the generic
//! [`crate::verify_v1::verify_receipt_v1`] path with the additional
//! `kind == "approval_decision"` assertion provided by
//! [`assert_approval_decision_kind_v1`].
//!
//! ## EU AI Act Article 14 — human oversight
//!
//! The receipt records the approving passport, the request id, the
//! decision (approve/reject), the risk tier at the time of the
//! decision, the tenant scope, an optional reviewer note, and the
//! timestamp. Together this satisfies the "passport-attributed +
//! time-bounded gate" requirement called out in the agent-ux-05
//! ExecPlan.
//!
//! ## Reuse of the existing signer
//!
//! Per the agent-ux-05 anti-collision section: "DO NOT introduce a new
//! signing key class for approval receipts — reuse the existing CROWN
//! signer." We sign with the daemon's standard Ed25519 passport key,
//! exactly as `memory_use_v1` does.

use ciborium::value::Value as CborValue;
use ed25519_dalek::{Signer as _, SigningKey};

use crate::verify_v1::ReceiptSigV1;

/// Receipt schema string written into the canonical body for
/// approval-decision receipts.
pub const APPROVAL_DECISION_BODY_SCHEMA_V1: &str = "cuecrux.receipt.body.v1";

/// The `kind` discriminator value identifying an approval-decision
/// receipt.
pub const APPROVAL_DECISION_KIND_V1: &str = "approval_decision";

/// Decision rendered by the reviewer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalDecisionV1 {
    Approve,
    Reject,
}

impl ApprovalDecisionV1 {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
        }
    }

    /// Parse `"approve" | "reject"` into a [`ApprovalDecisionV1`].
    /// Returns `None` on any other value so callers can reject up-front
    /// with a clear error instead of silently accepting unknown labels.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "approve" => Some(Self::Approve),
            "reject" => Some(Self::Reject),
            _ => None,
        }
    }
}

/// Risk tier the request was classified at when it was raised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalRiskTierV1 {
    Low,
    Medium,
    High,
}

impl ApprovalRiskTierV1 {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }
}

/// Input to [`build_approval_decision_body_v1`].
#[derive(Debug, Clone)]
pub struct ApprovalDecisionBodyInputV1<'a> {
    /// Tenant the approval request was raised in. Cross-tenant
    /// approvers are blocked at the tool layer so this field is
    /// authoritative (no need to record both requester and reviewer
    /// tenants).
    pub tenant_id: &'a str,
    /// Receipt identifier — typically `ad_<request_id>`.
    pub receipt_id: &'a str,
    /// Opaque request id minted by `approval_request`.
    pub request_id: &'a str,
    /// Passport of the reviewer that rendered the decision.
    pub reviewer_passport: &'a str,
    /// Reviewer's decision (approve/reject).
    pub decision: ApprovalDecisionV1,
    /// Risk tier of the original request (recorded so a tamper that
    /// flipped tier post-hoc would be detectable).
    pub risk_tier: ApprovalRiskTierV1,
    /// Action summary copied from the original request — recorded so
    /// the receipt is self-describing for downstream EU AI Act audits.
    pub action_summary: &'a str,
    /// Optional reviewer note (free-text justification).
    pub reviewer_notes: Option<&'a str>,
    /// Caller-provided ISO-8601 timestamp for determinism in tests.
    pub decided_at: &'a str,
}

/// Build the canonical CBOR bytes for an approval-decision receipt
/// body. Returns the encoded bytes and the BLAKE3 digest over those
/// bytes; the digest is what the signature binds to.
///
/// CBOR map keys are emitted in a fixed order so two calls with the
/// same input produce byte-identical output.
pub fn build_approval_decision_body_v1(input: &ApprovalDecisionBodyInputV1<'_>) -> (Vec<u8>, [u8; 32]) {
    let mut top: Vec<(CborValue, CborValue)> = vec![
        (
            CborValue::Text("schema".to_string()),
            CborValue::Text(APPROVAL_DECISION_BODY_SCHEMA_V1.to_string()),
        ),
        (
            CborValue::Text("kind".to_string()),
            CborValue::Text(APPROVAL_DECISION_KIND_V1.to_string()),
        ),
        (
            CborValue::Text("receipt_id".to_string()),
            CborValue::Text(input.receipt_id.to_string()),
        ),
        (
            CborValue::Text("tenant_id".to_string()),
            CborValue::Text(input.tenant_id.to_string()),
        ),
        (
            CborValue::Text("request_id".to_string()),
            CborValue::Text(input.request_id.to_string()),
        ),
        (
            CborValue::Text("reviewer_passport".to_string()),
            CborValue::Text(input.reviewer_passport.to_string()),
        ),
        (
            CborValue::Text("decision".to_string()),
            CborValue::Text(input.decision.as_str().to_string()),
        ),
        (
            CborValue::Text("risk_tier".to_string()),
            CborValue::Text(input.risk_tier.as_str().to_string()),
        ),
        (
            CborValue::Text("action_summary".to_string()),
            CborValue::Text(input.action_summary.to_string()),
        ),
        (
            CborValue::Text("decided_at".to_string()),
            CborValue::Text(input.decided_at.to_string()),
        ),
    ];
    if let Some(note) = input.reviewer_notes {
        top.push((
            CborValue::Text("reviewer_notes".to_string()),
            CborValue::Text(note.to_string()),
        ));
    }

    let v = CborValue::Map(top);
    let mut bytes = Vec::new();
    if ciborium::ser::into_writer(&v, &mut bytes).is_err() {
        bytes.clear();
    }
    let digest = blake3::hash(&bytes);
    (bytes, *digest.as_bytes())
}

/// Sign the canonical body produced by
/// [`build_approval_decision_body_v1`] with the daemon's Ed25519
/// passport key (the existing CROWN signer — no new key class).
pub fn sign_approval_decision_v1(
    receipt_id: &str,
    body_bytes: &[u8],
    body_hash: [u8; 32],
    signing_key: &SigningKey,
    key_id: &str,
    signed_at: &str,
) -> ReceiptSigV1 {
    let sig = signing_key.sign(body_bytes).to_bytes().to_vec();
    ReceiptSigV1 {
        schema: "cuecrux.receipt.sig.v1".to_string(),
        receipt_id: receipt_id.to_string(),
        alg: "ed25519".to_string(),
        key_id: key_id.to_string(),
        signed_at: signed_at.to_string(),
        signature: sig,
        signed_payload_hash: body_hash.to_vec(),
    }
}

/// Best-effort kind assertion. Run AFTER
/// [`crate::verify_v1::verify_receipt_v1`] returns OK.
pub fn assert_approval_decision_kind_v1(body_bytes: &[u8]) -> bool {
    let Ok(v) = ciborium::de::from_reader::<CborValue, _>(std::io::Cursor::new(body_bytes)) else {
        return false;
    };
    let CborValue::Map(map) = v else { return false };
    for (k, val) in &map {
        if let (CborValue::Text(k), CborValue::Text(s)) = (k, val) {
            if k == "kind" {
                return s == APPROVAL_DECISION_KIND_V1;
            }
        }
    }
    false
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, VerifyingKey};

    fn sample_input<'a>(receipt_id: &'a str, request_id: &'a str) -> ApprovalDecisionBodyInputV1<'a> {
        ApprovalDecisionBodyInputV1 {
            tenant_id: "personal::alice",
            receipt_id,
            request_id,
            reviewer_passport: "p_operator_001",
            decision: ApprovalDecisionV1::Approve,
            risk_tier: ApprovalRiskTierV1::High,
            action_summary: "delete tenant fixtures",
            reviewer_notes: Some("ok per ticket #42"),
            decided_at: "2026-05-27T00:00:00Z",
        }
    }

    #[test]
    fn body_is_deterministic() {
        let input = sample_input("ad_r-1", "r-1");
        let (b1, h1) = build_approval_decision_body_v1(&input);
        let (b2, h2) = build_approval_decision_body_v1(&input);
        assert_eq!(b1, b2);
        assert_eq!(h1, h2);
    }

    #[test]
    fn kind_assertion_round_trip() {
        let input = sample_input("ad_r-2", "r-2");
        let (bytes, _) = build_approval_decision_body_v1(&input);
        assert!(assert_approval_decision_kind_v1(&bytes));
        // A non-CBOR payload must not be misclassified as
        // approval_decision.
        assert!(!assert_approval_decision_kind_v1(b"not a cbor map"));
    }

    #[test]
    fn parse_decision_strict() {
        assert_eq!(ApprovalDecisionV1::parse("approve"), Some(ApprovalDecisionV1::Approve));
        assert_eq!(ApprovalDecisionV1::parse("reject"), Some(ApprovalDecisionV1::Reject));
        assert_eq!(ApprovalDecisionV1::parse("yes"), None);
    }

    #[test]
    fn parse_risk_tier_strict() {
        assert_eq!(ApprovalRiskTierV1::parse("low"), Some(ApprovalRiskTierV1::Low));
        assert_eq!(ApprovalRiskTierV1::parse("medium"), Some(ApprovalRiskTierV1::Medium));
        assert_eq!(ApprovalRiskTierV1::parse("high"), Some(ApprovalRiskTierV1::High));
        assert_eq!(ApprovalRiskTierV1::parse("critical"), None);
    }

    #[test]
    fn sign_and_verify_via_dalek() {
        let signing = SigningKey::from_bytes(&[0x42u8; 32]);
        let verifying: VerifyingKey = signing.verifying_key();
        let input = sample_input("ad_r-sign", "r-sign");
        let (bytes, hash) = build_approval_decision_body_v1(&input);
        let sig = sign_approval_decision_v1(input.receipt_id, &bytes, hash, &signing, "kid-test", input.decided_at);

        // Signature must verify against the canonical body bytes.
        let parsed_sig = ed25519_dalek::Signature::from_bytes(sig.signature.as_slice().try_into().expect("sig length"));
        verifying
            .verify_strict(&bytes, &parsed_sig)
            .expect("approval-decision signature must verify under the reviewer's passport key");

        // Tamper: flip one byte of the body → verification must fail.
        let mut tampered = bytes.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0x01;
        }
        assert!(
            verifying.verify_strict(&tampered, &parsed_sig).is_err(),
            "tampered body must NOT verify"
        );
    }

    #[test]
    fn reviewer_notes_optional() {
        let mut input = sample_input("ad_r-no-note", "r-no-note");
        input.reviewer_notes = None;
        let (bytes, _) = build_approval_decision_body_v1(&input);
        // The body must still parse and identify as approval_decision.
        assert!(assert_approval_decision_kind_v1(&bytes));
    }
}
