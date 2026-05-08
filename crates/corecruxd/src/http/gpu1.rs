// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
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

pub(super) async fn get_gpu1_contract(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["admin:read", "query:read"]) {
        return problem.into_response();
    }
    Json(compute_posture(&state)).into_response()
}

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
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &[service.capability(), "admin:write"]) {
        return problem.into_response();
    }
    let tenant_id = tenant_id.trim().to_string();
    if tenant_id.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id must not be empty");
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
    let context_pack_hash = hash_json(&json!({
        "tenant_id": tenant_id,
        "evidence": evidence,
        "semantic_profile_id": semantic_profile_id,
        "local_semantic_profile_id": local_semantic_profile_id,
    }));

    let client = Gpu1Client::from_env();
    let (mode, status, result, fallback, outbound_attempted) = match client {
        Some(client) => match client.invoke(service, payload.clone()) {
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
    };

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

    Json(json!({
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
    }))
    .into_response()
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
    };
    crate::fact_privacy::enforce(&state.privacy_policy, &mut fact);
    state.fact_store.write().await.store(fact);
}

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
