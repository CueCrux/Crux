// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `POST /invocation/verify` — Crux Daemon endpoint for the invocation-verify
//! protocol (master-plan §8).
//!
//! Accepts an `InvocationReceipt` as JSON (hex-encoded byte arrays),
//! looks up the parent plan via the registry's `get_by_plan_hash`, and
//! returns the verifier's verdict. Violations of (3)/(4) — capability
//! not in graph, channel mismatch — are flagged but do NOT cause a
//! non-200 response; the entire verdict is returned so the caller can
//! decide what to do.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{body::Bytes, Json};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crux_session::{
    plan::{SessionPlan, HASH_LEN, ULID_LEN},
    receipt::InvocationReceipt,
    verify_invocation_receipt, InvocationVerdict,
};

use super::session::problem;
use super::AppState;

#[derive(Debug, Clone, Deserialize)]
pub struct InvocationReceiptWire {
    pub invocation_id: String,
    pub session_id: String,
    pub parent_plan_receipt_hash: String,
    pub capability: String,
    pub channel: String,
    pub invoked_at: u64,
    pub completed_at: u64,
    pub input_hash: String,
    pub output_hash: String,
    pub outcome: String,
    #[serde(default)]
    pub cost_crux: Option<u64>,
    pub receipt_hash: String,
    #[serde(default)]
    pub receipt_signature: Option<String>,
    #[serde(default)]
    pub signer_kid: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyResponse {
    pub verified: bool,
    pub integrity_ok: bool,
    pub capability_ok: bool,
    pub channel_ok: bool,
    pub governance_faults: Vec<String>,
    pub parent_plan_found: bool,
    pub parent_plan_principal_id: Option<String>,
}

impl From<(InvocationVerdict, bool, Option<String>)> for VerifyResponse {
    fn from((v, parent_found, principal): (InvocationVerdict, bool, Option<String>)) -> Self {
        Self {
            verified: parent_found && v.verified_overall(),
            integrity_ok: v.integrity_ok,
            capability_ok: v.capability_ok,
            channel_ok: v.channel_ok,
            governance_faults: v.governance_faults,
            parent_plan_found: parent_found,
            parent_plan_principal_id: principal,
        }
    }
}

#[tracing::instrument(level = "info", skip(state, body))]
pub async fn post_invocation_verify(State(state): State<AppState>, body: Bytes) -> Response {
    let services = match state.session.as_ref() {
        Some(s) => s.clone(),
        None => {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "feature_disabled",
                "session feature is not enabled; invocation verify requires the session registry",
            );
        }
    };

    let wire: InvocationReceiptWire = match serde_json::from_slice(&body) {
        Ok(w) => w,
        Err(e) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "bad_request",
                format!("invalid invocation receipt body: {e}"),
            );
        }
    };

    let receipt = match wire_to_receipt(&wire) {
        Ok(r) => r,
        Err(msg) => return problem(StatusCode::BAD_REQUEST, "bad_request", msg),
    };

    // Look up the parent plan. The default-trait impl returns None if the
    // registry has no index; in that case we report parent_plan_found:false
    // so the caller sees the specific fault instead of a false "verified".
    let entry = match services.registry.get_by_plan_hash(&receipt.parent_plan_receipt_hash) {
        Ok(Some(e)) => e,
        Ok(None) => {
            if let Some(m) = services.metrics.as_ref() {
                m.invocation_verify("not_found");
            }
            let verdict = InvocationVerdict {
                integrity_ok: false,
                capability_ok: false,
                channel_ok: false,
                governance_faults: vec!["parent_plan_not_found".into()],
            };
            return (StatusCode::OK, Json(VerifyResponse::from((verdict, false, None)))).into_response();
        }
        Err(e) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("registry lookup failed: {e}"),
            );
        }
    };

    // Decode the plan from the registry entry. We stored the raw canonical
    // CBOR; `from_canonical_cbor` round-trips it to a full `SessionPlan`.
    let plan: SessionPlan = match SessionPlan::from_canonical_cbor(&entry.plan_cbor) {
        Ok(p) => p,
        Err(e) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                format!("failed to decode sealed plan bytes: {e}"),
            );
        }
    };

    let verdict = verify_invocation_receipt(&receipt, &plan);
    if let Some(m) = services.metrics.as_ref() {
        m.invocation_verify(if verdict.verified_overall() {
            "verified"
        } else {
            "flagged"
        });
    }
    (
        StatusCode::OK,
        Json(VerifyResponse::from((verdict, true, Some(plan.passport.principal_id)))),
    )
        .into_response()
}

fn wire_to_receipt(w: &InvocationReceiptWire) -> Result<InvocationReceipt, String> {
    let invocation_id = decode_ulid(&w.invocation_id, "invocation_id")?;
    let session_id = decode_ulid(&w.session_id, "session_id")?;
    let parent = decode_hash(&w.parent_plan_receipt_hash, "parent_plan_receipt_hash")?;
    let input_hash = decode_hash(&w.input_hash, "input_hash")?;
    let output_hash = decode_hash(&w.output_hash, "output_hash")?;
    let receipt_hash = decode_hash(&w.receipt_hash, "receipt_hash")?;
    let receipt_signature = match &w.receipt_signature {
        Some(s) => Some(decode_sig(s, "receipt_signature")?),
        None => None,
    };
    Ok(InvocationReceipt {
        invocation_id,
        session_id,
        parent_plan_receipt_hash: parent,
        capability: w.capability.clone(),
        channel: w.channel.clone(),
        invoked_at: w.invoked_at,
        completed_at: w.completed_at,
        input_hash,
        output_hash,
        outcome: w.outcome.clone(),
        cost_crux: w.cost_crux,
        receipt_hash,
        receipt_signature,
        signer_kid: w.signer_kid.clone(),
    })
}

fn decode_ulid(s: &str, field: &str) -> Result<[u8; ULID_LEN], String> {
    let bytes = hex::decode(s).map_err(|e| format!("{field} hex decode: {e}"))?;
    if bytes.len() != ULID_LEN {
        return Err(format!("{field} must decode to {ULID_LEN} bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; ULID_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hash(s: &str, field: &str) -> Result<[u8; HASH_LEN], String> {
    let bytes = hex::decode(s).map_err(|e| format!("{field} hex decode: {e}"))?;
    if bytes.len() != HASH_LEN {
        return Err(format!("{field} must decode to {HASH_LEN} bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_sig(s: &str, field: &str) -> Result<[u8; 64], String> {
    let bytes = hex::decode(s).map_err(|e| format!("{field} hex decode: {e}"))?;
    if bytes.len() != 64 {
        return Err(format!("{field} must decode to 64 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// Tiny helper — expose a minimal JSON shape for the openapi spec to pick up.
#[allow(dead_code)]
pub fn example_response() -> serde_json::Value {
    json!({
        "verified": true,
        "integrity_ok": true,
        "capability_ok": true,
        "channel_ok": true,
        "governance_faults": [],
        "parent_plan_found": true,
        "parent_plan_principal_id": "ce:abc12345:tester"
    })
}
