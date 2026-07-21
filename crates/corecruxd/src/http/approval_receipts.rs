// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Shared, typed approval-decision receipt rail for high-risk HTTP gates.

use corecrux_receipts::{
    build_approval_decision_body_v1, sign_approval_decision_v1, ApprovalDecisionBodyInputV1, ApprovalDecisionV1,
    ApprovalRiskTierV1, APPROVAL_DECISION_BODY_SCHEMA_V1, APPROVAL_DECISION_KIND_V1,
};

use super::{AppState, StatusCode};

/// CPU-local source of truth for typed approval receipts. The fixed session is
/// a signed, fsynced observation chain; `http::receipts` exposes its inner
/// CROWN body/signature through the canonical `/v1/receipts/{id}` API.
pub(super) const APPROVAL_RECEIPT_SESSION: &str = ".work_gate_receipts_v1";

/// Attribution prefix for modes whose claimed passport is not backed by a
/// verified JWT identity (auth-off and local dev-scope headers).
pub(super) const UNVERIFIED_APPROVER_PREFIX: &str = "operator:unverified:";

#[derive(Debug)]
pub(super) struct ApprovalReceiptSpec<'a> {
    pub receipt_id: &'a str,
    pub tenant_id: &'a str,
    pub request_id: &'a str,
    pub action_summary: &'a str,
    /// Non-authoritative, audit-friendly envelope fields. The signed
    /// `action_summary` remains the exact retry/subject binding.
    pub envelope_fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug)]
pub(super) struct MintedApprovalReceipt {
    pub receipt_id: String,
    pub observation_id: String,
}

#[derive(Debug)]
pub(super) struct ApprovalReceiptFailure {
    pub status: StatusCode,
    pub detail: String,
    /// The exact signed receipt already binds the caller's preparation. The
    /// caller must retain it so a retry can fsync and reuse that receipt.
    pub receipt_binds_preparation: bool,
}

fn receipt_failure(
    status: StatusCode,
    detail: impl Into<String>,
    receipt_binds_preparation: bool,
) -> ApprovalReceiptFailure {
    ApprovalReceiptFailure {
        status,
        detail: detail.into(),
        receipt_binds_preparation,
    }
}

pub(super) fn load_local_approval_receipt(
    state: &AppState,
    tenant_id: &str,
    receipt_id: &str,
) -> Result<Option<super::receipts::LocalApprovalReceipt>, String> {
    let path = super::observations::observation_file_path(state.data_dir.as_path(), APPROVAL_RECEIPT_SESSION);
    super::observations::repair_observation_tail(&path)
        .map_err(|err| format!("repair torn approval receipt tail: {err}"))?;
    super::receipts::local_approval_receipt(state, tenant_id, receipt_id)
}

/// Mint a typed `ApprovalDecision` receipt, or reuse the exact existing one
/// after a fact-journal failure. Changed reviewer, decision, risk tier, or
/// action subject conflicts instead of reusing a receipt for different bytes.
pub(super) fn mint_or_load_approval_receipt(
    state: &AppState,
    spec: &ApprovalReceiptSpec<'_>,
    reviewer_passport: &str,
    decision: ApprovalDecisionV1,
) -> Result<MintedApprovalReceipt, ApprovalReceiptFailure> {
    match load_local_approval_receipt(state, spec.tenant_id, spec.receipt_id) {
        Ok(Some(existing))
            if existing.request_id == spec.request_id
                && existing.reviewer_passport == reviewer_passport
                && existing.decision == decision.as_str()
                && existing.risk_tier == ApprovalRiskTierV1::High.as_str()
                && existing.action_summary == spec.action_summary =>
        {
            let path = super::observations::observation_file_path(state.data_dir.as_path(), APPROVAL_RECEIPT_SESSION);
            super::observations::sync_observation(&path).map_err(|err| {
                receipt_failure(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("sync existing approval receipt: {err}"),
                    true,
                )
            })?;
            return Ok(MintedApprovalReceipt {
                receipt_id: spec.receipt_id.to_string(),
                observation_id: existing.observation_id,
            });
        }
        Ok(Some(_)) => {
            return Err(receipt_failure(
                StatusCode::CONFLICT,
                "a conflicting approval receipt already exists for this request",
                false,
            ));
        }
        Ok(None) => {}
        Err(detail) => {
            return Err(receipt_failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("existing approval receipt validation failed: {detail}"),
                true,
            ));
        }
    }

    let decided_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let (body_bytes, body_hash) = build_approval_decision_body_v1(&ApprovalDecisionBodyInputV1 {
        tenant_id: spec.tenant_id,
        receipt_id: spec.receipt_id,
        request_id: spec.request_id,
        reviewer_passport,
        decision: decision.clone(),
        risk_tier: ApprovalRiskTierV1::High,
        action_summary: spec.action_summary,
        reviewer_notes: None,
        decided_at: &decided_at,
    });
    if body_bytes.is_empty() {
        return Err(receipt_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            "approval receipt body encoding failed",
            false,
        ));
    }
    let signing_key = super::stream_receipts::load_signing_key(state)
        .map_err(|detail| receipt_failure(StatusCode::INTERNAL_SERVER_ERROR, detail, false))?;
    let signature = sign_approval_decision_v1(
        spec.receipt_id,
        &body_bytes,
        body_hash,
        &signing_key,
        &state.passport_fpr,
        &decided_at,
    );
    let mut signature_bytes = Vec::new();
    ciborium::ser::into_writer(&signature, &mut signature_bytes).map_err(|err| {
        receipt_failure(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("approval receipt signature encoding failed: {err}"),
            false,
        )
    })?;

    let mut payload = spec.envelope_fields.clone();
    payload.insert(
        "receipt_id".to_string(),
        serde_json::Value::String(spec.receipt_id.to_string()),
    );
    payload.insert(
        "tenant_id".to_string(),
        serde_json::Value::String(spec.tenant_id.to_string()),
    );
    payload.insert(
        "request_id".to_string(),
        serde_json::Value::String(spec.request_id.to_string()),
    );
    payload.insert(
        "decision".to_string(),
        serde_json::Value::String(decision.as_str().to_string()),
    );
    payload.insert(
        "reviewer_passport".to_string(),
        serde_json::Value::String(reviewer_passport.to_string()),
    );
    payload.insert(
        "risk_tier".to_string(),
        serde_json::Value::String(ApprovalRiskTierV1::High.as_str().to_string()),
    );
    payload.insert(
        "action_summary".to_string(),
        serde_json::Value::String(spec.action_summary.to_string()),
    );
    payload.insert(
        "body_schema".to_string(),
        serde_json::Value::String(APPROVAL_DECISION_BODY_SCHEMA_V1.to_string()),
    );
    payload.insert(
        "body_cbor_hex".to_string(),
        serde_json::Value::String(hex::encode(&body_bytes)),
    );
    payload.insert(
        "body_hash".to_string(),
        serde_json::Value::String(format!("blake3:{}", hex::encode(body_hash))),
    );
    payload.insert(
        "signature_cbor_hex".to_string(),
        serde_json::Value::String(hex::encode(&signature_bytes)),
    );
    payload.insert(
        "signer_key_id".to_string(),
        serde_json::Value::String(state.passport_fpr.clone()),
    );
    payload.insert(
        "signer_public_key_hex".to_string(),
        serde_json::Value::String(state.passport_public_key_hex.clone()),
    );

    let observation = super::observations::PostObservationBody {
        kind: APPROVAL_DECISION_KIND_V1.to_string(),
        provider: "corecruxd".to_string(),
        client_ts: None,
        payload: serde_json::Value::Object(payload),
    };
    let (persisted, _) = super::observations::append_one_durable_tracked(
        state,
        APPROVAL_RECEIPT_SESSION,
        reviewer_passport,
        observation,
        None,
    )
    .map_err(|failure| {
        receipt_failure(
            failure.error.0,
            format!("approval receipt signing or persistence failed: {}", failure.error.1),
            failure.appended,
        )
    })?;
    Ok(MintedApprovalReceipt {
        receipt_id: spec.receipt_id.to_string(),
        observation_id: persisted.observation_id,
    })
}
