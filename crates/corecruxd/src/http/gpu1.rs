// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Pro GPU-1 compute bridge.
//!
//! GPU-1 is treated as a cloud compute service, not as implicit memory sync.
//! Requests carry selected evidence, hashes, and semantic profile IDs. When the
//! service is not configured or is unreachable, routes return a local fallback
//! response with receipts that explain why no remote compute happened.

use super::*;
use corecrux_memory::fact_store::StoreFact;
use corecrux_memory::replay::{AnswerReplayCapsule, BuildAnswerReplayCapsule, ProjectionReplayRef, ReplayEvidenceRef};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub(super) const GPU1_COMPUTE_CONTRACT_SCHEMA: &str = "crux.gpu1.compute_contract.v1";
const GPU1_COMPUTE_RESPONSE_SCHEMA: &str = "crux.gpu1.compute_response.v1";
const GPU1_RECEIPT_SCHEMA: &str = "crux.gpu1.receipt.v1";
const GPU1_RECEIPT_ENTITY_PREFIX: &str = "__gpu1_receipt__";
const RERANK_LANE_SLUG: &str = "rerank";
const RERANK_QUOTE_OPTION: &str = "credit_quote";
const GPU1_PAYLOAD_POLICY: &str =
    "selected_evidence_only: send task payloads, selected context, hashes, receipts, and semantic profile IDs; never upload the whole local store";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gpu1Service {
    Answer,
    Rerank,
    Enrich,
    Coverage,
    Developer,
}

impl Gpu1Service {
    fn operation(self) -> &'static str {
        match self {
            Self::Answer => "answer",
            Self::Rerank => "rerank",
            Self::Enrich => "enrich",
            Self::Coverage => "coverage",
            Self::Developer => "developer",
        }
    }

    fn capability(self) -> &'static str {
        match self {
            Self::Answer => "gpu1:answer",
            Self::Rerank => "gpu1:rerank",
            Self::Enrich => "gpu1:enrich",
            Self::Coverage => "gpu1:coverage",
            Self::Developer => "gpu1:developer",
        }
    }

    fn local_path(self) -> &'static str {
        match self {
            Self::Answer => "/v1/gpu1/answer",
            Self::Rerank => "/v1/gpu1/rerank",
            Self::Enrich => "/v1/gpu1/enrich",
            Self::Coverage => "/v1/gpu1/coverage",
            Self::Developer => "/v1/gpu1/developer",
        }
    }

    fn remote_path(self) -> &'static str {
        match self {
            Self::Answer => "/v1/query/answer",
            Self::Rerank => "/v1/query/rerank",
            Self::Enrich => "/v1/actions/enrich",
            Self::Coverage => "/v1/query/coverage",
            Self::Developer => "/v1/developer/surface",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct Gpu1ComputeContract {
    pub schema: &'static str,
    pub endpoint_configured: bool,
    pub api_key_configured: bool,
    pub enabled_services: Vec<String>,
    pub remote_memory_sync_required: bool,
    pub payload_policy: &'static str,
    pub services: Vec<Gpu1ServiceContract>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct Gpu1ServiceContract {
    pub operation: &'static str,
    pub capability: &'static str,
    pub status: &'static str,
    pub local_path: &'static str,
    pub remote_path: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Gpu1Evidence {
    pub record_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_semantic_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score_space: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Gpu1AnswerRequest {
    pub tenant_id: String,
    pub question: String,
    #[serde(default)]
    pub evidence: Vec<Gpu1Evidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_budget: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_semantic_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_pack_receipt_id: Option<String>,
    #[serde(default)]
    pub options: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Gpu1RerankRequest {
    pub tenant_id: String,
    pub query: String,
    #[serde(default)]
    pub candidates: Vec<Gpu1Evidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_k: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_semantic_profile_id: Option<String>,
    #[serde(default)]
    pub options: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Gpu1EnrichRequest {
    pub tenant_id: String,
    pub tool_name: String,
    #[serde(default)]
    pub tool_parameters: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_action: Option<String>,
    #[serde(default)]
    pub evidence: Vec<Gpu1Evidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_semantic_profile_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Gpu1CoverageRequest {
    pub tenant_id: String,
    pub query: String,
    #[serde(default)]
    pub evidence: Vec<Gpu1Evidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage_floor: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_semantic_profile_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Gpu1DeveloperRequest {
    pub tenant_id: String,
    pub surface: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,
    #[serde(default)]
    pub evidence: Vec<Gpu1Evidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_semantic_profile_id: Option<String>,
    #[serde(default)]
    pub options: Value,
}

#[derive(Debug, Clone, Serialize)]
struct Gpu1Fallback {
    reason_code: String,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct Gpu1ReceiptBundle {
    request: Value,
    context_pack: Value,
    result: Value,
}

#[derive(Debug, Clone)]
struct Gpu1Client {
    base_url: String,
    api_key: Option<String>,
}

type Gpu1Invocation = (&'static str, &'static str, Value, Option<Gpu1Fallback>, bool);

#[derive(Debug, Clone, PartialEq, Eq)]
struct CreditSpendStamp {
    receipt_id: String,
    credits_spent: u64,
    wallet_balance: u64,
}

struct PendingCreditSpend {
    meter: std::sync::Arc<std::sync::Mutex<crate::credit_meter::CreditMeterStore>>,
    quote: crate::credit_meter::PinnedCreditQuote,
    reservation: crate::credit_meter::CreditReservation,
    signing_key: crux_session::LocalPassportKey,
    active: bool,
}

impl PendingCreditSpend {
    fn release(mut self, reason: &str) -> Result<(), String> {
        {
            let mut meter = self
                .meter
                .lock()
                .map_err(|_| "credit meter lock poisoned".to_string())?;
            meter
                .void_reservation(&self.quote.tenant_id, &self.reservation.reservation_id, reason)
                .map_err(|err| err.to_string())?;
        }
        self.active = false;
        Ok(())
    }

    fn complete(mut self) -> Result<CreditSpendStamp, String> {
        let receipt = crate::credit_meter::mint_spend_receipt(&self.quote, &self.reservation, &self.signing_key)
            .map_err(|err| err.to_string())?;
        let spend = {
            let mut meter = self
                .meter
                .lock()
                .map_err(|_| "credit meter lock poisoned".to_string())?;
            meter
                .spend(
                    &self.quote.tenant_id,
                    &self.reservation.reservation_id,
                    &receipt.body.receipt_id,
                )
                .map_err(|err| err.to_string())?
        };
        if spend.spend_receipt != receipt.body.receipt_id {
            return Err("operation already spent with a different pinned quote/spend receipt".to_string());
        }
        self.active = false;
        Ok(CreditSpendStamp {
            receipt_id: receipt.body.receipt_id,
            credits_spent: spend.cost,
            wallet_balance: spend.balance_after,
        })
    }
}

impl Drop for PendingCreditSpend {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut meter) = self.meter.lock() {
            let _ = meter.void_reservation(
                &self.quote.tenant_id,
                &self.reservation.reservation_id,
                "metered_request_aborted",
            );
        }
    }
}

pub(super) fn compute_posture(state: &AppState) -> Gpu1ComputeContract {
    let client = Gpu1Client::from_env();
    Gpu1ComputeContract {
        schema: GPU1_COMPUTE_CONTRACT_SCHEMA,
        endpoint_configured: client.is_some(),
        api_key_configured: client.as_ref().is_some_and(|client| client.api_key.is_some()),
        enabled_services: enabled_gpu1_services(state),
        remote_memory_sync_required: false,
        payload_policy: GPU1_PAYLOAD_POLICY,
        services: gpu1_services()
            .into_iter()
            .map(|service| Gpu1ServiceContract {
                operation: service.operation(),
                capability: service.capability(),
                status: service_status(state, service),
                local_path: service.local_path(),
                remote_path: service.remote_path(),
            })
            .collect(),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_gpu1_contract(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["admin:read", "query:read"]) {
        return problem.into_response();
    }
    Json(compute_posture(&state)).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_gpu1_answer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Gpu1AnswerRequest>,
) -> Response {
    let fallback = json!({
        "answer": null,
        "answer_available": false,
        "message": "GPU-1 answer unavailable; continue with local retrieval/agent reasoning and the returned receipt hashes.",
    });
    handle_compute(
        state,
        headers,
        Gpu1Service::Answer,
        body.tenant_id.clone(),
        body.evidence.clone(),
        body.semantic_profile_id.clone(),
        body.local_semantic_profile_id.clone(),
        to_payload_value(&body),
        fallback,
    )
    .await
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_gpu1_rerank(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Gpu1RerankRequest>,
) -> Response {
    let top_k = body.top_k.unwrap_or(body.candidates.len()).min(body.candidates.len());
    let fallback_results = body
        .candidates
        .iter()
        .take(top_k)
        .enumerate()
        .map(|(idx, candidate)| {
            json!({
                "record_id": candidate.record_id,
                "rank": idx + 1,
                "source_label": candidate.source_label,
                "score": candidate.score,
                "score_space": candidate.score_space,
                "reason": "input_order_fallback",
            })
        })
        .collect::<Vec<_>>();
    let fallback = json!({
        "results": fallback_results,
        "rerank_applied": false,
    });
    handle_compute(
        state,
        headers,
        Gpu1Service::Rerank,
        body.tenant_id.clone(),
        body.candidates.clone(),
        body.semantic_profile_id.clone(),
        body.local_semantic_profile_id.clone(),
        to_payload_value(&body),
        fallback,
    )
    .await
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_gpu1_enrich(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Gpu1EnrichRequest>,
) -> Response {
    let fallback = json!({
        "enriched": false,
        "tool_name": body.tool_name,
        "proposed_action": body.proposed_action,
        "consequences": [],
        "message": "GPU-1 enrichment unavailable; use local basic verification and constraints.",
    });
    handle_compute(
        state,
        headers,
        Gpu1Service::Enrich,
        body.tenant_id.clone(),
        body.evidence.clone(),
        body.semantic_profile_id.clone(),
        body.local_semantic_profile_id.clone(),
        to_payload_value(&body),
        fallback,
    )
    .await
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_gpu1_coverage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Gpu1CoverageRequest>,
) -> Response {
    let fallback = local_coverage_fallback(&body);
    handle_compute(
        state,
        headers,
        Gpu1Service::Coverage,
        body.tenant_id.clone(),
        body.evidence.clone(),
        body.semantic_profile_id.clone(),
        body.local_semantic_profile_id.clone(),
        to_payload_value(&body),
        fallback,
    )
    .await
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_gpu1_developer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Gpu1DeveloperRequest>,
) -> Response {
    let fallback = json!({
        "surface": body.surface,
        "analysis_available": false,
        "route": body.route,
        "message": "GPU-1 developer surface unavailable; use local workspace scan/storyline surfaces.",
    });
    handle_compute(
        state,
        headers,
        Gpu1Service::Developer,
        body.tenant_id.clone(),
        body.evidence.clone(),
        body.semantic_profile_id.clone(),
        body.local_semantic_profile_id.clone(),
        to_payload_value(&body),
        fallback,
    )
    .await
}

#[allow(clippy::result_large_err)]
fn begin_rerank_credit_spend(
    state: &AppState,
    service: Gpu1Service,
    tenant_id: &str,
    payload: &Value,
    payload_hash: &str,
) -> Result<Option<PendingCreditSpend>, Response> {
    let Some(meter) = state.credit_meter.clone() else {
        return Ok(None);
    };
    if !matches!(service, Gpu1Service::Rerank) {
        return Ok(None);
    }

    let capability = rcx_capability_token::corecrux_lane_capability(RERANK_LANE_SLUG);
    let expected_credits = rcx_capability_token::corecrux_lane_credit_cost(RERANK_LANE_SLUG, 0);
    let raw_quote = match payload
        .get("options")
        .and_then(|options| options.get(RERANK_QUOTE_OPTION))
    {
        Some(quote) => quote.clone(),
        None => {
            return Err(credit_quote_problem(
                "options.credit_quote is required when CORECRUXD_CREDIT_METER=1",
                None,
                tenant_id,
                &capability,
                expected_credits,
            ));
        }
    };
    let quote: crate::credit_meter::PinnedCreditQuote = match serde_json::from_value(raw_quote.clone()) {
        Ok(quote) => quote,
        Err(err) => {
            return Err(credit_quote_problem(
                format!("options.credit_quote is invalid: {err}"),
                Some(raw_quote),
                tenant_id,
                &capability,
                expected_credits,
            ));
        }
    };
    if let Err(err) = quote.validate() {
        return Err(credit_quote_problem(
            err.to_string(),
            Some(json!(quote)),
            tenant_id,
            &capability,
            expected_credits,
        ));
    }
    if quote.tenant_id != tenant_id || quote.capability != capability || quote.credits != expected_credits {
        return Err(credit_quote_problem(
            "credit quote does not match the tenant, lane capability, or pinned rerank price",
            Some(json!(quote)),
            tenant_id,
            &capability,
            expected_credits,
        ));
    }

    let Some(router) = state.rcx_router.as_ref() else {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            "RCX router is required for metered rerank",
        ));
    };
    if router.token().tenant_scope.tenant_id != tenant_id {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            "RCX token tenant does not match the metered rerank tenant",
        ));
    }
    let decision = router.decide(
        &crux_router::CallContext {
            capability: capability.clone(),
            preferred_backend: Some("local".to_string()),
            data_egress_classes: vec![rcx_capability_token::DataEgressClass::Text],
            present_attestations: Vec::new(),
            estimated_credit_cost: expected_credits,
            backend_reachable: true,
        },
        current_unix_seconds(),
    );
    if !decision.authorised {
        if decision.reason_code.as_deref() == Some("denied:insufficient_credit") {
            return Err(insufficient_credit_problem(
                &quote,
                expected_credits,
                router.token().credits.balance.unwrap_or(0),
            ));
        }
        return Err(rcx_lane_refusal_problem(&decision, &capability));
    }
    if crux_router::lane_call_cost(router.token(), RERANK_LANE_SLUG) != expected_credits {
        return Err(problem_response(
            StatusCode::CONFLICT,
            "RCX token rerank price does not match the pinned 3-credit price",
        ));
    }

    let signing_key = match crux_session::LocalPassportKey::from_path(&state.passport_key_path) {
        Ok(key) => key,
        Err(err) => {
            tracing::error!(error = %err, "metered rerank passport signing key load failed");
            return Err(problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "passport signing key unavailable",
            ));
        }
    };
    if signing_key.passport_fpr() != state.passport_fpr {
        return Err(problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "passport signer mismatch: state={}, key={}",
                state.passport_fpr,
                signing_key.passport_fpr()
            ),
        ));
    }

    let reservation = {
        let mut guard = match meter.lock() {
            Ok(guard) => guard,
            Err(_) => {
                return Err(problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "credit meter lock poisoned",
                ));
            }
        };
        match guard.reserve(&quote.tenant_id, &quote.operation_id, quote.credits, payload_hash) {
            Ok(reservation) => reservation,
            Err(crate::credit_meter::CreditMeterError::InsufficientCredit { cost, available, .. }) => {
                return Err(insufficient_credit_problem(&quote, cost, available))
            }
            Err(err) => return Err(credit_meter_problem(err)),
        }
    };

    Ok(Some(PendingCreditSpend {
        meter,
        quote,
        reservation,
        signing_key,
        active: true,
    }))
}

fn credit_quote_problem(
    detail: impl Into<String>,
    quote: Option<Value>,
    tenant_id: &str,
    capability: &str,
    credits: u64,
) -> Response {
    ProblemResponse(ProblemDetails::bad_request(detail).with_extensions(json!({
        "quote": quote,
        "expected_quote": {
            "tenant_id": tenant_id,
            "capability": capability,
            "credits": credits,
        },
    })))
    .into_response()
}

fn insufficient_credit_problem(
    quote: &crate::credit_meter::PinnedCreditQuote,
    required: u64,
    available: u64,
) -> Response {
    ProblemResponse(
        ProblemDetails::new(
            StatusCode::PAYMENT_REQUIRED.as_u16(),
            "https://errors.cuecrux.com/payment-required/insufficient-credits",
            "Insufficient Credits",
        )
        .with_detail(format!(
            "metered rerank requires {required} credits; wallet has {available} available"
        ))
        .with_extensions(json!({
            "quote": quote,
            "required_credits": required,
            "available_credits": available,
            "spend_applied": false,
        })),
    )
    .into_response()
}

fn rcx_lane_refusal_problem(decision: &crux_router::RouterDecision, capability: &str) -> Response {
    ProblemResponse(
        ProblemDetails::new(
            StatusCode::FORBIDDEN.as_u16(),
            "https://errors.cuecrux.com/rcx-lane-denied",
            "RCX Lane Denied",
        )
        .with_detail(format!(
            "RCX capability denied: {}",
            decision.reason_code.as_deref().unwrap_or("denied:unknown")
        ))
        .with_extensions(json!({
            "capability": capability,
            "reason_code": decision.reason_code,
            "mode": decision.mode.as_str(),
            "token_id": decision.token_id,
            "token_hash": decision.token_hash,
        })),
    )
    .into_response()
}

fn credit_meter_problem(err: crate::credit_meter::CreditMeterError) -> Response {
    match err {
        crate::credit_meter::CreditMeterError::OperationPayloadMismatch {
            tenant_id,
            operation_id,
            existing_payload_hash,
            requested_payload_hash,
        } => ProblemResponse(
            ProblemDetails::new(
                StatusCode::CONFLICT.as_u16(),
                "https://errors.cuecrux.com/conflict/credit-operation-payload-mismatch",
                "Credit Operation Payload Mismatch",
            )
            .with_detail(format!(
                "operation {operation_id} for tenant {tenant_id} is already reserved for a different payload"
            ))
            .with_extensions(json!({
                "tenant_id": tenant_id,
                "operation_id": operation_id,
                "existing_payload_hash": existing_payload_hash,
                "requested_payload_hash": requested_payload_hash,
                "spend_applied": false,
            })),
        )
        .into_response(),
        crate::credit_meter::CreditMeterError::OperationAlreadySpent {
            tenant_id,
            operation_id,
            spend_receipt,
        } => ProblemResponse(
            ProblemDetails::new(
                StatusCode::CONFLICT.as_u16(),
                "https://errors.cuecrux.com/conflict/credit-operation-already-spent",
                "Credit Operation Already Spent",
            )
            .with_detail(format!(
                "operation {operation_id} for tenant {tenant_id} was already spent"
            ))
            .with_extensions(json!({
                "tenant_id": tenant_id,
                "operation_id": operation_id,
                "spend_receipt": spend_receipt,
                "spend_applied": false,
            })),
        )
        .into_response(),
        err => generic_credit_meter_problem(err),
    }
}

fn generic_credit_meter_problem(err: crate::credit_meter::CreditMeterError) -> Response {
    let status = match err {
        crate::credit_meter::CreditMeterError::OperationConflict { .. }
        | crate::credit_meter::CreditMeterError::OperationPayloadMismatch { .. }
        | crate::credit_meter::CreditMeterError::OperationAlreadySpent { .. }
        | crate::credit_meter::CreditMeterError::ReservationVoided { .. }
        | crate::credit_meter::CreditMeterError::TenantMismatch { .. } => StatusCode::CONFLICT,
        crate::credit_meter::CreditMeterError::ReservationNotFound { .. } => StatusCode::NOT_FOUND,
        crate::credit_meter::CreditMeterError::InvalidQuote { .. }
        | crate::credit_meter::CreditMeterError::QuoteReservationMismatch { .. } => StatusCode::BAD_REQUEST,
        crate::credit_meter::CreditMeterError::InsufficientCredit { .. } => StatusCode::PAYMENT_REQUIRED,
        crate::credit_meter::CreditMeterError::Io(_)
        | crate::credit_meter::CreditMeterError::Json { .. }
        | crate::credit_meter::CreditMeterError::ReceiptBuild(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    problem_response(status, err.to_string())
}

fn stamp_result_envelope(envelope: &mut Value, spend: Option<&CreditSpendStamp>) {
    let Some(spend) = spend else {
        return;
    };
    envelope["credit_spend_receipt"] = json!(spend.receipt_id);
    envelope["credits_spent"] = json!(spend.credits_spent);
    envelope["wallet_balance"] = json!(spend.wallet_balance);
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[allow(clippy::too_many_arguments)]
async fn handle_compute(
    state: AppState,
    headers: HeaderMap,
    service: Gpu1Service,
    tenant_id: String,
    evidence: Vec<Gpu1Evidence>,
    semantic_profile_id: Option<String>,
    local_semantic_profile_id: Option<String>,
    payload: Result<Value, String>,
    fallback_result: Value,
) -> Response {
    let tenant_id = tenant_id.trim().to_string();
    if tenant_id.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id must not be empty");
    }
    if let Err(problem) = require_http_any_scope_for_tenant(
        &state.auth,
        &headers,
        &[service.capability(), "admin:write"],
        &tenant_id,
    ) {
        return problem.into_response();
    }
    if evidence.len() > 100 {
        return problem_response(StatusCode::BAD_REQUEST, "selected evidence must not exceed 100 items");
    }
    let payload = match payload {
        Ok(payload) => payload,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };

    if !service_enabled(&state, service) {
        return (
            StatusCode::PAYMENT_REQUIRED,
            Json(json!({
                "schema": GPU1_COMPUTE_RESPONSE_SCHEMA,
                "service": service.operation(),
                "capability": service.capability(),
                "status": "pro_service_not_enabled",
                "mode": "not_executed",
                "remote_memory_sync_required": false,
                "payload_policy": GPU1_PAYLOAD_POLICY,
                "fallback": {
                    "reason_code": "pro_service_not_enabled",
                    "detail": "enable this GPU-1 capability under Pro before using the compute bridge",
                },
            })),
        )
            .into_response();
    }

    let payload_hash = hash_json(&payload);
    let mut pending_credit_spend = match begin_rerank_credit_spend(&state, service, &tenant_id, &payload, &payload_hash)
    {
        Ok(pending) => pending,
        Err(response) => return response,
    };

    let context_pack_hash = hash_json(&json!({
        "tenant_id": tenant_id,
        "evidence": evidence,
        "semantic_profile_id": semantic_profile_id,
        "local_semantic_profile_id": local_semantic_profile_id,
    }));

    let (mode, status, result, fallback, outbound_attempted) = invoke_gpu1(service, payload.clone(), fallback_result);

    if mode != "gpu1_remote" {
        if let Some(pending) = pending_credit_spend.take() {
            if let Err(err) = pending.release("gpu1_compute_failed") {
                return problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("credit reservation release failed: {err}"),
                );
            }
        }
    }

    let result_hash = hash_json(&result);
    let receipts = build_receipts(
        &tenant_id,
        service,
        &payload_hash,
        &context_pack_hash,
        &result_hash,
        mode,
        fallback.as_ref().map(|fallback| fallback.reason_code.as_str()),
        outbound_attempted,
    );
    let credit_spend = match pending_credit_spend {
        Some(pending) => match pending.complete() {
            Ok(spend) => Some(spend),
            Err(err) => {
                return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("credit spend failed: {err}"));
            }
        },
        None => None,
    };
    store_receipts(&state, &tenant_id, service, &receipts).await;
    let answer_replay = if matches!(service, Gpu1Service::Answer) {
        match build_and_store_answer_capsule(
            &state,
            &tenant_id,
            &payload,
            &result,
            &evidence,
            semantic_profile_id.as_deref(),
            local_semantic_profile_id.as_deref(),
            &receipts,
        )
        .await
        {
            Ok(value) => Some(value),
            Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        }
    } else {
        None
    };

    let mut envelope = json!({
        "schema": GPU1_COMPUTE_RESPONSE_SCHEMA,
        "service": service.operation(),
        "capability": service.capability(),
        "status": status,
        "mode": mode,
        "remote_memory_sync_required": false,
        "payload_policy": GPU1_PAYLOAD_POLICY,
        "result": result,
        "fallback": fallback,
        "receipts": receipts,
        "answer_replay": answer_replay,
    });
    stamp_result_envelope(&mut envelope, credit_spend.as_ref());
    Json(envelope).into_response()
}

fn invoke_gpu1(service: Gpu1Service, payload: Value, fallback_result: Value) -> Gpu1Invocation {
    #[cfg(test)]
    gpu1_test_invoke_count().fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    #[cfg(test)]
    if let Some(result) = gpu1_test_result().lock().ok().and_then(|mut result| result.take()) {
        return match result {
            Ok(result) => ("gpu1_remote", "ok", result, None, true),
            Err(err) => (
                "local_fallback",
                "degraded",
                fallback_result,
                Some(Gpu1Fallback {
                    reason_code: "gpu1_unavailable".to_string(),
                    detail: err,
                }),
                true,
            ),
        };
    }

    match Gpu1Client::from_env() {
        Some(client) => match client.invoke(service, payload) {
            Ok(result) => ("gpu1_remote", "ok", result, None, true),
            Err(err) => (
                "local_fallback",
                "degraded",
                fallback_result,
                Some(Gpu1Fallback {
                    reason_code: "gpu1_unavailable".to_string(),
                    detail: err,
                }),
                true,
            ),
        },
        None => (
            "local_fallback",
            "degraded",
            fallback_result,
            Some(Gpu1Fallback {
                reason_code: "gpu1_not_configured".to_string(),
                detail: "CORECRUXD_GPU1_BASE_URL is not configured".to_string(),
            }),
            false,
        ),
    }
}

#[cfg(test)]
fn gpu1_test_result() -> &'static std::sync::Mutex<Option<Result<Value, String>>> {
    static RESULT: std::sync::OnceLock<std::sync::Mutex<Option<Result<Value, String>>>> = std::sync::OnceLock::new();
    RESULT.get_or_init(|| std::sync::Mutex::new(None))
}

#[cfg(test)]
fn gpu1_test_invoke_count() -> &'static std::sync::atomic::AtomicUsize {
    static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    &COUNT
}

impl Gpu1Client {
    fn from_env() -> Option<Self> {
        let base_url = std::env::var("CORECRUXD_GPU1_BASE_URL")
            .or_else(|_| std::env::var("CRUX_GPU1_BASE_URL"))
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())?;
        let api_key = std::env::var("CORECRUXD_GPU1_API_KEY")
            .or_else(|_| std::env::var("CRUX_GPU1_API_KEY"))
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        Some(Self { base_url, api_key })
    }

    fn invoke(&self, service: Gpu1Service, payload: Value) -> Result<Value, String> {
        let url = format!("{}{}", self.base_url.trim_end_matches('/'), service.remote_path());
        let mut request = ureq::post(&url).header("Content-Type", "application/json");
        if let Some(api_key) = &self.api_key {
            request = request.header("Authorization", &format!("Bearer {api_key}"));
        }
        let mut response = request
            .send_json(payload)
            .map_err(|err| format!("GPU-1 request failed: {err}"))?;
        response
            .body_mut()
            .read_json::<Value>()
            .map_err(|err| format!("GPU-1 response decode failed: {err}"))
    }
}

fn gpu1_services() -> Vec<Gpu1Service> {
    vec![
        Gpu1Service::Answer,
        Gpu1Service::Rerank,
        Gpu1Service::Enrich,
        Gpu1Service::Coverage,
        Gpu1Service::Developer,
    ]
}

fn service_status(state: &AppState, service: Gpu1Service) -> &'static str {
    if service_enabled(state, service) {
        if Gpu1Client::from_env().is_some() {
            "enabled"
        } else {
            "enabled_degraded_not_configured"
        }
    } else if matches!(
        state.operating_mode,
        crate::product::OperatingMode::ProLocalFirst
            | crate::product::OperatingMode::ProCloudOnly
            | crate::product::OperatingMode::ProHybrid
            | crate::product::OperatingMode::MaxPrivate
    ) {
        "entitled_not_enabled"
    } else {
        "pro_required"
    }
}

fn service_enabled(state: &AppState, service: Gpu1Service) -> bool {
    crate::product::ProductPosture::new(state.operating_mode, &state.enabled_pro_services)
        .enabled_pro_services
        .iter()
        .any(|enabled| enabled == service.capability())
}

fn enabled_gpu1_services(state: &AppState) -> Vec<String> {
    crate::product::ProductPosture::new(state.operating_mode, &state.enabled_pro_services)
        .enabled_pro_services
        .into_iter()
        .filter(|service| service.starts_with("gpu1:"))
        .collect()
}

fn to_payload_value<T: Serialize>(body: &T) -> Result<Value, String> {
    serde_json::to_value(body).map_err(|err| format!("GPU-1 payload encode failed: {err}"))
}

fn local_coverage_fallback(body: &Gpu1CoverageRequest) -> Value {
    let query_terms = terms(&body.query);
    let evidence_text = body
        .evidence
        .iter()
        .filter_map(|evidence| evidence.text.as_deref())
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let matched = query_terms
        .iter()
        .filter(|term| evidence_text.contains(term.as_str()))
        .cloned()
        .collect::<Vec<_>>();
    let missing = query_terms
        .iter()
        .filter(|term| !matched.contains(term))
        .cloned()
        .collect::<Vec<_>>();
    let score = if query_terms.is_empty() {
        0.0
    } else {
        matched.len() as f32 / query_terms.len() as f32
    };
    json!({
        "coverage_score": score,
        "matched_terms": matched,
        "missing_terms": missing,
        "coverage_floor": body.coverage_floor,
        "coverage_model": "local_lexical_fallback",
    })
}

fn terms(input: &str) -> Vec<String> {
    let mut out = input
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .map(str::trim)
        .filter(|term| term.len() > 1)
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out
}

#[allow(clippy::too_many_arguments)]
fn build_receipts(
    tenant_id: &str,
    service: Gpu1Service,
    payload_hash: &str,
    context_pack_hash: &str,
    result_hash: &str,
    mode: &str,
    reason_code: Option<&str>,
    outbound_attempted: bool,
) -> Gpu1ReceiptBundle {
    let now = chrono::Utc::now().to_rfc3339();
    let base = json!({
        "tenant_id": tenant_id,
        "service": service.operation(),
        "capability": service.capability(),
        "payload_hash": payload_hash,
        "context_pack_hash": context_pack_hash,
        "result_hash": result_hash,
        "mode": mode,
        "reason_code": reason_code,
        "outbound_attempted": outbound_attempted,
        "remote_memory_sync_required": false,
        "created_at": now,
    });
    let receipt_hash = hash_json(&base);
    let suffix = receipt_hash
        .trim_start_matches("blake3:")
        .chars()
        .take(16)
        .collect::<String>();
    let receipt_id = format!("gpu1:{}:{suffix}", service.operation());
    let request = json!({
        "schema": GPU1_RECEIPT_SCHEMA,
        "receipt_id": format!("{receipt_id}:request"),
        "event_type": "gpu1_compute_request",
        "tenant_id": tenant_id,
        "service": service.operation(),
        "capability": service.capability(),
        "payload_hash": payload_hash,
        "context_pack_hash": context_pack_hash,
        "outbound_attempted": outbound_attempted,
        "remote_memory_sync_required": false,
        "created_at": now,
    });
    let context_pack = json!({
        "schema": GPU1_RECEIPT_SCHEMA,
        "receipt_id": format!("{receipt_id}:context_pack"),
        "event_type": "gpu1_local_context_pack",
        "tenant_id": tenant_id,
        "service": service.operation(),
        "context_pack_hash": context_pack_hash,
        "payload_policy": GPU1_PAYLOAD_POLICY,
        "remote_memory_sync_required": false,
        "created_at": now,
    });
    let result = json!({
        "schema": GPU1_RECEIPT_SCHEMA,
        "receipt_id": format!("{receipt_id}:result"),
        "event_type": "gpu1_compute_result",
        "tenant_id": tenant_id,
        "service": service.operation(),
        "result_hash": result_hash,
        "mode": mode,
        "reason_code": reason_code,
        "remote_memory_sync_required": false,
        "created_at": now,
    });
    Gpu1ReceiptBundle {
        request,
        context_pack,
        result,
    }
}

async fn store_receipts(state: &AppState, tenant_id: &str, service: Gpu1Service, receipts: &Gpu1ReceiptBundle) {
    let value = match serde_json::to_string(receipts) {
        Ok(value) => value,
        Err(err) => {
            tracing::warn!(?err, "gpu1-receipt-encode-failed");
            return;
        }
    };
    let mut fact = StoreFact {
        tenant_hash: "default".to_string(),
        entity: format!("{GPU1_RECEIPT_ENTITY_PREFIX}::{tenant_id}::{}", service.operation()),
        key: "receipt_bundle".to_string(),
        value,
        source_receipt: receipts
            .result
            .get("receipt_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        confidence: 1.0,
        private: true,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce(&state.privacy_policy, &mut fact);
    state.fact_store.write().await.store(fact);
}

#[allow(clippy::too_many_arguments)]
async fn build_and_store_answer_capsule(
    state: &AppState,
    tenant_id: &str,
    payload: &Value,
    result: &Value,
    evidence: &[Gpu1Evidence],
    semantic_profile_id: Option<&str>,
    local_semantic_profile_id: Option<&str>,
    receipts: &Gpu1ReceiptBundle,
) -> std::io::Result<Value> {
    let answer_id = answer_id_for(tenant_id, payload, result);
    let source_receipts = source_receipt_ids(receipts);
    let capsule = AnswerReplayCapsule::build(BuildAnswerReplayCapsule {
        answer_id: answer_id.clone(),
        tenant_id: tenant_id.to_string(),
        source: "gpu1_answer".to_string(),
        question: payload
            .get("question")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        stored_answer: result.clone(),
        evidence: evidence.iter().map(replay_evidence_ref).collect(),
        projection_refs: current_projection_replay_refs(state, payload.get("shard_id").and_then(Value::as_str)).await,
        source_receipts: source_receipts.clone(),
        context_pack_receipt_id: payload
            .get("context_pack_receipt_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        semantic_profile_id: semantic_profile_id.map(str::to_string),
        local_semantic_profile_id: local_semantic_profile_id.map(str::to_string),
        created_at: chrono::Utc::now().to_rfc3339(),
    });
    super::replay::store_answer_capsule(state, &capsule).await?;
    Ok(json!({
        "schema": corecrux_memory::replay::ANSWER_REPLAY_CAPSULE_SCHEMA,
        "answer_id": answer_id,
        "capsule_hash": capsule.capsule_hash,
        "replay_path": format!("/v1/replay/answers/{answer_id}"),
        "validity_path": format!("/v1/replay/answers/{answer_id}/validity"),
        "agent_required": false,
        "llm_required": false,
        "source_receipts": source_receipts,
    }))
}

fn replay_evidence_ref(evidence: &Gpu1Evidence) -> ReplayEvidenceRef {
    ReplayEvidenceRef {
        record_id: evidence.record_id.clone(),
        artifact_id: evidence.artifact_id,
        source_label: evidence.source_label.clone(),
        text: evidence.text.clone(),
        text_hash: evidence.text.as_deref().map(corecrux_memory::replay::hash_text),
        content_hash: evidence.content_hash.clone(),
        semantic_profile_id: evidence.semantic_profile_id.clone(),
        local_semantic_profile_id: evidence.local_semantic_profile_id.clone(),
        score_space: evidence.score_space.clone(),
        receipt_id: evidence.receipt_id.clone(),
    }
}

async fn current_projection_replay_refs(state: &AppState, shard_id: Option<&str>) -> Vec<ProjectionReplayRef> {
    let mut projection_commit_id = None;
    let mut snapshot_hashes = std::collections::BTreeMap::new();
    let mut modules = corecrux_projections::current_projection_module_versions_v1();
    if let Some(shard_id) = shard_id.filter(|value| !value.trim().is_empty()) {
        if state.http_dataplane.enabled() {
            if let Ok(Some(meta)) = state.http_dataplane.projection_meta(shard_id).await {
                projection_commit_id = Some(meta.commit_id);
                snapshot_hashes = projection_snapshot_hashes(&meta);
                if !meta.projection_module_registry.is_empty() {
                    modules = meta.projection_module_registry;
                }
            }
        }
    }
    let registry_hash = hash_json(&json!({
        "projection_commit_id": projection_commit_id,
        "modules": modules.clone(),
    }));
    modules
        .into_iter()
        .map(|module| ProjectionReplayRef {
            projection_snapshot_hash: snapshot_hashes.get(&module.module_id).cloned(),
            projection_commit_id,
            projection_registry_hash: Some(registry_hash.clone()),
            schema_version: Some(module.schema_version),
            install_receipt_id: module.install_receipt_id.clone(),
            module_id: module.module_id,
            module_version: module.module_version,
            code_hash: Some(module.code_hash),
            config_hash: Some(module.config_hash),
            availability: module.status.as_str().to_string(),
        })
        .collect()
}

fn projection_snapshot_hashes(
    meta: &corecrux_projections::ProjectionsMetaV1,
) -> std::collections::BTreeMap<String, String> {
    [
        (
            "corecrux.projections.artifact_living_state",
            &meta.artifact_living_state,
        ),
        ("corecrux.projections.artifact_relations", &meta.artifact_relations),
        ("corecrux.projections.pressure_events", &meta.pressure_events),
        ("corecrux.projections.artifact_dependents", &meta.artifact_dependents),
    ]
    .into_iter()
    .filter_map(|(module_id, projection)| {
        projection
            .snapshot_blake3
            .as_ref()
            .map(|hash| (module_id.to_string(), hash.clone()))
    })
    .collect()
}

fn answer_id_for(tenant_id: &str, payload: &Value, result: &Value) -> String {
    let seed = json!({
        "tenant_id": tenant_id,
        "question": payload.get("question"),
        "payload_hash": hash_json(payload),
        "result_hash": hash_json(result),
    });
    let hash = hash_json(&seed);
    let suffix = hash.trim_start_matches("blake3:").chars().take(20).collect::<String>();
    format!("ans_{suffix}")
}

fn source_receipt_ids(receipts: &Gpu1ReceiptBundle) -> Vec<String> {
    [
        receipts.request.get("receipt_id"),
        receipts.context_pack.get("receipt_id"),
        receipts.result.get("receipt_id"),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .map(str::to_string)
    .collect()
}

fn hash_json(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

#[cfg(test)]
mod credit_meter_tests {
    use axum::body::to_bytes;

    use super::*;

    struct Gpu1EnvGuard;

    impl Gpu1EnvGuard {
        fn clear() -> Self {
            for name in [
                "CORECRUXD_GPU1_BASE_URL",
                "CRUX_GPU1_BASE_URL",
                "CORECRUXD_GPU1_API_KEY",
                "CRUX_GPU1_API_KEY",
            ] {
                std::env::remove_var(name);
            }
            if let Ok(mut result) = gpu1_test_result().lock() {
                *result = None;
            }
            gpu1_test_invoke_count().store(0, std::sync::atomic::Ordering::SeqCst);
            Self
        }
    }

    impl Drop for Gpu1EnvGuard {
        fn drop(&mut self) {
            for name in [
                "CORECRUXD_GPU1_BASE_URL",
                "CRUX_GPU1_BASE_URL",
                "CORECRUXD_GPU1_API_KEY",
                "CRUX_GPU1_API_KEY",
            ] {
                std::env::remove_var(name);
            }
            if let Ok(mut result) = gpu1_test_result().lock() {
                *result = None;
            }
            gpu1_test_invoke_count().store(0, std::sync::atomic::Ordering::SeqCst);
        }
    }

    async fn body_json(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("read response body");
        serde_json::from_slice(&bytes).expect("JSON response body")
    }

    fn quote(operation_id: &str) -> crate::credit_meter::PinnedCreditQuote {
        crate::credit_meter::PinnedCreditQuote::new(
            format!("quote-{operation_id}"),
            "tenant-a",
            operation_id,
            rcx_capability_token::corecrux_lane_capability(RERANK_LANE_SLUG),
            3,
            format!("blake3:{}", blake3::hash(b"rerank-price-list-v1").to_hex()),
        )
    }

    fn rerank_request(quote: crate::credit_meter::PinnedCreditQuote) -> Gpu1RerankRequest {
        Gpu1RerankRequest {
            tenant_id: "tenant-a".to_string(),
            query: "rank these".to_string(),
            candidates: vec![Gpu1Evidence {
                record_id: "record-1".to_string(),
                artifact_id: None,
                source_label: Some("local_tenant_index".to_string()),
                text: Some("candidate text".to_string()),
                content_hash: None,
                semantic_profile_id: None,
                local_semantic_profile_id: None,
                score: Some(1.0),
                score_space: Some("bm25_lexical".to_string()),
                receipt_id: None,
            }],
            top_k: Some(1),
            semantic_profile_id: None,
            local_semantic_profile_id: None,
            options: json!({ RERANK_QUOTE_OPTION: quote }),
        }
    }

    fn metered_rerank_state(wallet_balance: u64) -> AppState {
        let mut state = crate::http::tests::test_app_state(16);
        state.operating_mode = crate::product::OperatingMode::ProHybrid;
        state.enabled_pro_services = vec!["gpu1:rerank".to_string()];

        let signing_key =
            crux_session::LocalPassportKey::from_path(&state.passport_key_path).expect("create test passport key");
        state.passport_fpr = signing_key.passport_fpr().to_string();
        state.passport_public_key_hex = signing_key.public_key_hex().to_string();
        let now = current_unix_seconds();
        let token = crux_router::mint_signed_paid_local_token(
            signing_key.passport_fpr().to_string(),
            "daemon-test",
            "tenant-a",
            Vec::new(),
            100,
            7,
            now.saturating_sub(60),
            now.saturating_add(3600),
            |hash| signing_key.sign_hash(hash),
        );
        state.rcx_router = Some(std::sync::Arc::new(
            crux_router::RcxRouter::new_with_trusted_issuer_pubkey(token, signing_key.verifying_key_bytes()),
        ));

        let mut meter = crate::credit_meter::CreditMeterStore::open(state.data_dir.join("credit-meter.jsonl"))
            .expect("open credit meter");
        meter
            .seed_comped_wallet("tenant-a", wallet_balance, "seed-rerank-tests")
            .expect("seed comped wallet");
        state.credit_meter = Some(std::sync::Arc::new(std::sync::Mutex::new(meter)));
        state
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn metered_rerank_stamps_success_result_envelope() {
        let _env = Gpu1EnvGuard::clear();
        *gpu1_test_result().lock().expect("GPU-1 test result lock") = Some(Ok(json!({
            "results": [{"record_id": "record-1", "rank": 1}],
            "rerank_applied": true,
        })));
        let state = metered_rerank_state(10);
        let shared = state.clone();

        let response = post_gpu1_rerank(
            State(state),
            HeaderMap::new(),
            Json(rerank_request(quote("rerank-success"))),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["mode"], "gpu1_remote");
        assert_eq!(body["credits_spent"], 3);
        assert_eq!(body["wallet_balance"], 7);
        assert!(body["credit_spend_receipt"]
            .as_str()
            .expect("spend receipt id")
            .starts_with("crxspend_"));

        let meter = shared
            .credit_meter
            .as_ref()
            .expect("credit meter")
            .lock()
            .expect("credit meter lock");
        assert_eq!(meter.available_balance("tenant-a"), 7);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn metered_rerank_spent_replay_with_different_payload_is_conflict_without_compute() {
        let _env = Gpu1EnvGuard::clear();
        *gpu1_test_result().lock().expect("GPU-1 test result lock") = Some(Ok(json!({
            "results": [{"record_id": "record-1", "rank": 1}],
            "rerank_applied": true,
        })));
        let state = metered_rerank_state(10);
        let shared = state.clone();
        let replay_quote = quote("rerank-replay");
        let first_request = rerank_request(replay_quote.clone());

        let first_response = post_gpu1_rerank(State(state.clone()), HeaderMap::new(), Json(first_request)).await;

        assert_eq!(first_response.status(), StatusCode::OK);
        let first_body = body_json(first_response).await;
        let first_receipt = first_body["credit_spend_receipt"]
            .as_str()
            .expect("first spend receipt")
            .to_string();
        assert_eq!(first_body["credits_spent"], 3);
        assert_eq!(first_body["wallet_balance"], 7);

        let mut replay_request = rerank_request(replay_quote);
        replay_request.query = "rank a different request".to_string();
        replay_request.candidates[0].text = Some("different candidate content".to_string());
        let replay_response = post_gpu1_rerank(State(state), HeaderMap::new(), Json(replay_request)).await;

        assert_eq!(replay_response.status(), StatusCode::CONFLICT);
        let replay_body = body_json(replay_response).await;
        assert_eq!(
            replay_body["type"],
            "https://errors.cuecrux.com/conflict/credit-operation-already-spent"
        );
        assert_eq!(replay_body["spend_receipt"], first_receipt);
        assert_eq!(replay_body["spend_applied"], false);
        assert_eq!(gpu1_test_invoke_count().load(std::sync::atomic::Ordering::SeqCst), 1);
        let meter = shared
            .credit_meter
            .as_ref()
            .expect("credit meter")
            .lock()
            .expect("credit meter lock");
        assert_eq!(meter.available_balance("tenant-a"), 7);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn metered_rerank_active_payload_matrix_is_enforced_before_compute() {
        let _env = Gpu1EnvGuard::clear();
        let state = metered_rerank_state(10);
        let operation_quote = quote("rerank-active-mismatch");
        let mut original_request = rerank_request(operation_quote.clone());
        original_request.query = "the originally reserved payload".to_string();
        let original_payload = to_payload_value(&original_request).expect("serialize original request");
        let existing_payload_hash = hash_json(&original_payload);
        {
            let mut meter = state
                .credit_meter
                .as_ref()
                .expect("credit meter")
                .lock()
                .expect("credit meter lock");
            meter
                .reserve(
                    "tenant-a",
                    &operation_quote.operation_id,
                    operation_quote.credits,
                    &existing_payload_hash,
                )
                .expect("reserve original payload");
        }
        let requested = rerank_request(operation_quote);
        let requested_payload_hash = hash_json(&to_payload_value(&requested).expect("serialize requested payload"));

        let response = post_gpu1_rerank(State(state.clone()), HeaderMap::new(), Json(requested)).await;

        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = body_json(response).await;
        assert_eq!(
            body["type"],
            "https://errors.cuecrux.com/conflict/credit-operation-payload-mismatch"
        );
        assert_eq!(body["existing_payload_hash"], existing_payload_hash);
        assert_eq!(body["requested_payload_hash"], requested_payload_hash);
        assert_eq!(body["spend_applied"], false);
        assert_eq!(gpu1_test_invoke_count().load(std::sync::atomic::Ordering::SeqCst), 0);
        let meter = state
            .credit_meter
            .as_ref()
            .expect("credit meter")
            .lock()
            .expect("credit meter lock");
        assert_eq!(meter.available_balance("tenant-a"), 7);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn metered_rerank_active_same_payload_is_an_idempotent_handler_retry() {
        let _env = Gpu1EnvGuard::clear();
        *gpu1_test_result().lock().expect("GPU-1 test result lock") = Some(Ok(json!({
            "results": [{"record_id": "record-1", "rank": 1}],
            "rerank_applied": true,
        })));
        let state = metered_rerank_state(10);
        let operation_quote = quote("rerank-active-same");
        let request = rerank_request(operation_quote.clone());
        let payload_hash = hash_json(&to_payload_value(&request).expect("serialize rerank request"));
        {
            let mut meter = state
                .credit_meter
                .as_ref()
                .expect("credit meter")
                .lock()
                .expect("credit meter lock");
            meter
                .reserve(
                    "tenant-a",
                    &operation_quote.operation_id,
                    operation_quote.credits,
                    &payload_hash,
                )
                .expect("reserve matching payload");
        }

        let response = post_gpu1_rerank(State(state.clone()), HeaderMap::new(), Json(request)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["credits_spent"], 3);
        assert_eq!(body["wallet_balance"], 7);
        assert_eq!(gpu1_test_invoke_count().load(std::sync::atomic::Ordering::SeqCst), 1);
        let meter = state
            .credit_meter
            .as_ref()
            .expect("credit meter")
            .lock()
            .expect("credit meter lock");
        assert_eq!(meter.available_balance("tenant-a"), 7);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn metered_rerank_voided_operation_gets_a_fresh_bound_reservation() {
        let _env = Gpu1EnvGuard::clear();
        *gpu1_test_result().lock().expect("GPU-1 test result lock") = Some(Ok(json!({
            "results": [{"record_id": "record-1", "rank": 1}],
            "rerank_applied": true,
        })));
        let state = metered_rerank_state(10);
        let meter_path = state.data_dir.join("credit-meter.jsonl");
        let operation_quote = quote("rerank-after-void");
        let mut failed_request = rerank_request(operation_quote.clone());
        failed_request.query = "failed attempt".to_string();
        let failed_hash = hash_json(&to_payload_value(&failed_request).expect("serialize failed request"));
        let old_reservation_id = {
            let mut meter = state
                .credit_meter
                .as_ref()
                .expect("credit meter")
                .lock()
                .expect("credit meter lock");
            let reservation = meter
                .reserve(
                    "tenant-a",
                    &operation_quote.operation_id,
                    operation_quote.credits,
                    &failed_hash,
                )
                .expect("reserve failed attempt");
            meter
                .void_reservation("tenant-a", &reservation.reservation_id, "gpu1_compute_failed")
                .expect("void failed attempt");
            reservation.reservation_id
        };
        let retry_request = rerank_request(operation_quote);

        let response = post_gpu1_rerank(State(state.clone()), HeaderMap::new(), Json(retry_request)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["credits_spent"], 3);
        let meter = state
            .credit_meter
            .as_ref()
            .expect("credit meter")
            .lock()
            .expect("credit meter lock");
        assert_eq!(meter.available_balance("tenant-a"), 7);
        drop(meter);
        let log = std::fs::read_to_string(meter_path).expect("read meter log");
        assert_eq!(log.matches("\"event\":\"Reserve\"").count(), 2);
        assert_eq!(log.matches(&old_reservation_id).count(), 2);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn metered_rerank_insufficient_credit_is_rfc7807_with_quote() {
        let _env = Gpu1EnvGuard::clear();
        let state = metered_rerank_state(2);
        let shared = state.clone();
        let expected_quote = quote("rerank-insufficient");

        let response = post_gpu1_rerank(
            State(state),
            HeaderMap::new(),
            Json(rerank_request(expected_quote.clone())),
        )
        .await;

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(
            response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok()),
            Some("application/problem+json")
        );
        let body = body_json(response).await;
        assert_eq!(
            body["type"],
            "https://errors.cuecrux.com/payment-required/insufficient-credits"
        );
        assert_eq!(body["quote"]["quote_id"], expected_quote.quote_id);
        assert_eq!(body["quote"]["capability"], expected_quote.capability);
        assert_eq!(body["required_credits"], 3);
        assert_eq!(body["available_credits"], 2);
        assert_eq!(body["spend_applied"], false);

        let meter = shared
            .credit_meter
            .as_ref()
            .expect("credit meter")
            .lock()
            .expect("credit meter lock");
        assert_eq!(meter.available_balance("tenant-a"), 2);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn metered_rerank_requires_rcx_verified_lane_before_reserving() {
        let _env = Gpu1EnvGuard::clear();
        let mut state = metered_rerank_state(10);
        let now = current_unix_seconds();
        state.rcx_router = Some(std::sync::Arc::new(
            crux_router::RcxRouter::new_with_trusted_issuer_pubkey(
                crux_router::mint_free_local_token(
                    "p_free_test",
                    "daemon-test",
                    "tenant-a",
                    vec!["corecrux.query.local".to_string()],
                    now.saturating_sub(60),
                    now.saturating_add(3600),
                    [0_u8; 64],
                ),
                [0_u8; 32],
            ),
        ));
        let shared = state.clone();

        let response = post_gpu1_rerank(
            State(state),
            HeaderMap::new(),
            Json(rerank_request(quote("rerank-unverified"))),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = body_json(response).await;
        assert_eq!(body["type"], "https://errors.cuecrux.com/rcx-lane-denied");
        // The free/local token is unsigned, so under the trusted-issuer router it
        // fails issuer verification (not rcx-verified) before the lane-capability
        // check — the metered lane is refused without reserving credits either way.
        assert_eq!(body["reason_code"], "denied:token_invalid");
        let meter = shared
            .credit_meter
            .as_ref()
            .expect("credit meter")
            .lock()
            .expect("credit meter lock");
        assert_eq!(meter.available_balance("tenant-a"), 10);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn metered_rerank_failure_releases_reservation_without_spend() {
        let _env = Gpu1EnvGuard::clear();
        let state = metered_rerank_state(10);
        let shared = state.clone();
        let meter_path = state.data_dir.join("credit-meter.jsonl");

        let response = post_gpu1_rerank(
            State(state),
            HeaderMap::new(),
            Json(rerank_request(quote("rerank-fallback"))),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["mode"], "local_fallback");
        assert!(body.get("credit_spend_receipt").is_none());
        assert!(body.get("credits_spent").is_none());
        assert!(body.get("wallet_balance").is_none());

        let meter = shared
            .credit_meter
            .as_ref()
            .expect("credit meter")
            .lock()
            .expect("credit meter lock");
        assert_eq!(meter.available_balance("tenant-a"), 10);
        drop(meter);
        let log = std::fs::read_to_string(&meter_path).expect("read credit meter log");
        assert!(log.contains("\"event\":\"Reserve\""));
        assert!(log.contains("\"event\":\"Void\""));
        assert!(!log.contains("\"event\":\"Spend\""));
        let reopened = crate::credit_meter::CreditMeterStore::open(meter_path).expect("replay credit meter");
        assert_eq!(reopened.available_balance("tenant-a"), 10);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn metered_rerank_quote_mismatches_do_not_reserve_or_compute() {
        let _env = Gpu1EnvGuard::clear();
        let mut wrong_tenant = quote("wrong-tenant");
        wrong_tenant.tenant_id = "tenant-b".to_string();
        let mut wrong_capability = quote("wrong-capability");
        wrong_capability.capability = "gpu1:answer".to_string();
        let mut wrong_credits = quote("wrong-credits");
        wrong_credits.credits = 4;

        for invalid_quote in [wrong_tenant, wrong_capability, wrong_credits] {
            let state = metered_rerank_state(10);
            let meter_path = state.data_dir.join("credit-meter.jsonl");
            let response = post_gpu1_rerank(
                State(state.clone()),
                HeaderMap::new(),
                Json(rerank_request(invalid_quote)),
            )
            .await;

            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let meter = state
                .credit_meter
                .as_ref()
                .expect("credit meter")
                .lock()
                .expect("credit meter lock");
            assert_eq!(meter.available_balance("tenant-a"), 10);
            drop(meter);
            let log = std::fs::read_to_string(meter_path).expect("read meter log");
            assert!(!log.contains("\"event\":\"Reserve\""));
        }
        assert_eq!(gpu1_test_invoke_count().load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn metered_rerank_missing_quote_does_not_reserve_or_compute() {
        let _env = Gpu1EnvGuard::clear();
        let state = metered_rerank_state(10);
        let meter_path = state.data_dir.join("credit-meter.jsonl");
        let mut request = rerank_request(quote("missing-quote"));
        request.options = json!({});

        let response = post_gpu1_rerank(State(state.clone()), HeaderMap::new(), Json(request)).await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let meter = state
            .credit_meter
            .as_ref()
            .expect("credit meter")
            .lock()
            .expect("credit meter lock");
        assert_eq!(meter.available_balance("tenant-a"), 10);
        drop(meter);
        let log = std::fs::read_to_string(meter_path).expect("read meter log");
        assert!(!log.contains("\"event\":\"Reserve\""));
        assert_eq!(gpu1_test_invoke_count().load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn credit_meter_flag_off_full_handler_preserves_credit_field_byte_shape() {
        let _env = Gpu1EnvGuard::clear();
        *gpu1_test_result().lock().expect("GPU-1 test result lock") = Some(Ok(json!({
            "results": [{"record_id": "record-1", "rank": 1}],
            "rerank_applied": true,
        })));
        let mut state = crate::http::tests::test_app_state(16);
        state.operating_mode = crate::product::OperatingMode::ProHybrid;
        state.enabled_pro_services = vec!["gpu1:rerank".to_string()];
        assert!(state.credit_meter.is_none());
        let mut request = rerank_request(quote("flag-off"));
        request.options = json!({});

        let response = post_gpu1_rerank(State(state), HeaderMap::new(), Json(request)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("read response body");
        let body: Value = serde_json::from_slice(&bytes).expect("JSON response body");
        assert_eq!(body["mode"], "gpu1_remote");
        for field in ["credit_spend_receipt", "credits_spent", "wallet_balance"] {
            assert!(body.get(field).is_none(), "unexpected credit field {field}");
            assert!(
                !bytes.windows(field.len()).any(|window| window == field.as_bytes()),
                "credit field {field} changed the response bytes"
            );
        }
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn metered_rerank_router_insufficient_credit_uses_payment_problem_before_wallet_reserve() {
        let _env = Gpu1EnvGuard::clear();
        let mut state = metered_rerank_state(10);
        let signing_key =
            crux_session::LocalPassportKey::from_path(&state.passport_key_path).expect("load test signing key");
        let now = current_unix_seconds();
        state.rcx_router = Some(std::sync::Arc::new(
            crux_router::RcxRouter::new_with_trusted_issuer_pubkey(
                crux_router::mint_signed_paid_local_token(
                    signing_key.passport_fpr().to_string(),
                    "daemon-test",
                    "tenant-a",
                    Vec::new(),
                    2,
                    7,
                    now.saturating_sub(60),
                    now.saturating_add(3600),
                    |hash| signing_key.sign_hash(hash),
                ),
                signing_key.verifying_key_bytes(),
            ),
        ));
        let meter_path = state.data_dir.join("credit-meter.jsonl");
        let expected_quote = quote("router-insufficient");

        let response = post_gpu1_rerank(
            State(state.clone()),
            HeaderMap::new(),
            Json(rerank_request(expected_quote.clone())),
        )
        .await;

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body = body_json(response).await;
        assert_eq!(
            body["type"],
            "https://errors.cuecrux.com/payment-required/insufficient-credits"
        );
        assert_eq!(body["quote"]["quote_id"], expected_quote.quote_id);
        assert_eq!(body["required_credits"], 3);
        assert_eq!(body["available_credits"], 2);
        assert_eq!(body["spend_applied"], false);
        let meter = state
            .credit_meter
            .as_ref()
            .expect("credit meter")
            .lock()
            .expect("credit meter lock");
        assert_eq!(meter.available_balance("tenant-a"), 10);
        drop(meter);
        let log = std::fs::read_to_string(meter_path).expect("read meter log");
        assert!(!log.contains("\"event\":\"Reserve\""));
        assert_eq!(gpu1_test_invoke_count().load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn metered_rerank_passport_key_failure_does_not_echo_the_key_path() {
        let _env = Gpu1EnvGuard::clear();
        let mut state = metered_rerank_state(10);
        let missing_key_path = state.data_dir.join("private/secrets/missing-passport.key");
        std::fs::create_dir_all(missing_key_path.parent().expect("key parent")).expect("create key parent");
        std::fs::write(&missing_key_path, "").expect("write invalid passport key fixture");
        let leaked_path = missing_key_path.display().to_string();
        state.passport_key_path = missing_key_path;

        let response = post_gpu1_rerank(
            State(state.clone()),
            HeaderMap::new(),
            Json(rerank_request(quote("missing-passport-key"))),
        )
        .await;

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = body_json(response).await;
        assert_eq!(body["detail"], "passport signing key unavailable");
        assert!(!body.to_string().contains(&leaked_path));
        let meter = state
            .credit_meter
            .as_ref()
            .expect("credit meter")
            .lock()
            .expect("credit meter lock");
        assert_eq!(meter.available_balance("tenant-a"), 10);
        assert_eq!(gpu1_test_invoke_count().load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
