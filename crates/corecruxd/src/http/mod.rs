// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

mod admin;
mod append;
mod facts;
mod health;
mod observe;
mod projections;
mod query;
mod receipts;
mod routing;

pub(crate) use admin::AdminActionRecord;
// Receipt export helpers (build_lineage_json_v1, etc.) only used by proprietary ExportReceiptBundle.
#[allow(unused_imports)]
pub(crate) use receipts::{build_lineage_json_v1, build_subject_links_json_v1, build_trace_summary_json_v1};

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{routing::get, Json, Router};
use base64::Engine as _;
use corecrux_proto::dataplane_v1::AppendEvent;
use tokio::sync::RwLock;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::timeout::TimeoutLayer;

use corecrux_frame::compute_header_hash;
use corecrux_frame::stream_hash_xxhash64;
use corecrux_receipts::{
    build_receipt_export_v1, resolve_subject_receipt_id_v1, ExportFormatV1, ExportRedactionV1, ReceiptExportIncludeV1,
    ReceiptExportOptionsV1, SubjectResolveModeV1, EVT_RECEIPT_BODY_V1, EVT_RECEIPT_SIG_V1, STREAM_TYPE_RECEIPT,
};
use corecrux_types::{
    format_u64_hex, parse_shard_id_u32, CompatContract, ControlAdminActionFinishedV1, ControlAdminActionSubmittedV1,
    ControlCheckpointMaterializedV1, ControlStateMutationV1, EvidenceAuthContextV1, EvidenceNodeContextV1,
    EvidenceRequestContextV1, KnowledgeAuthorityModeV1, KnowledgeParityOutcomeV1, KnowledgeParityStatusV1,
    KnowledgeRolloutStageV1, ProblemDetails, RoutingInfo, ShardMapV1, CONTROL_EVIDENCE_CONTENT_TYPE_V1,
    EVT_CONTROL_ADMIN_ACTION_FINISHED_V1, EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1,
    EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1, EVT_CONTROL_STATE_MUTATION_V1,
};
use corecrux_types::{ValveInfo, ValvesInfo};

use crate::config::CommitLevel;
use crate::metrics::Metrics;
use crate::problem::ProblemResponse;
use crate::shard_map::RoutingTable;
use crate::structured_log::{CorrelationIds, ErrorCode, StructuredOpLog};

use crate::auth::{describe_http_evidence, require_http_scopes, require_http_scopes_for_tenant, Authz};
use crate::control::{self, ValveDecision};
use crate::dataplane_store::AppendError;

#[derive(Debug, Clone)]
pub struct Readiness {
    pub control_evidence_hosted: bool,
    pub control_evidence_ok: bool,
    pub control_evidence_error: Option<String>,
}

impl Default for Readiness {
    fn default() -> Self {
        Self {
            control_evidence_hosted: false,
            control_evidence_ok: true,
            control_evidence_error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CapacityState {
    pub total_bytes: u64,
    pub free_bytes: u64,
    pub free_ratio: f64,
    #[allow(dead_code)] // Exposed in /healthz response; read path planned for capacity alerting.
    pub warning_free_ratio: f64,
    #[allow(dead_code)] // Exposed in /healthz response; read path planned for capacity alerting.
    pub critical_free_ratio: f64,
    pub emergency_free_ratio: f64,
    pub auto_paused: bool,
    pub error: Option<String>,
}

impl Default for CapacityState {
    fn default() -> Self {
        Self {
            total_bytes: 0,
            free_bytes: 0,
            free_ratio: 1.0,
            warning_free_ratio: 0.20,
            critical_free_ratio: 0.10,
            emergency_free_ratio: 0.10,
            auto_paused: false,
            error: None,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub lock_held: bool,
    pub build: corecrux_types::BuildInfo,
    pub compat: CompatContract,
    pub sdk_version: String,
    pub auth: Authz,
    pub data_dir: PathBuf,
    pub read_retry_failed_readyz_threshold: u64,
    pub commit_level: CommitLevel,
    pub metrics: Metrics,
    pub node_id: String,
    pub routing: Arc<RwLock<RoutingTable>>,
    pub routing_errors: Arc<RwLock<Vec<String>>>,
    pub dataplane_pool: Option<crate::pool::DataPlanePool>,
    pub readiness: Arc<RwLock<Readiness>>,
    pub control: Arc<RwLock<control::ControlV1>>,
    pub control_path: PathBuf,
    pub action_max_pending: usize,
    pub action_timeout_secs: u64,
    pub scrub_scope: String,
    pub scrub_mode: String,
    pub scrub_sample_rate: f64,
    pub admin_actions: Arc<RwLock<std::collections::BTreeMap<String, AdminActionRecord>>>,
    pub corruption_detected: Arc<RwLock<bool>>,
    pub capacity: Arc<RwLock<CapacityState>>,
    pub admin_force_seal_enabled: bool,
    /// CoreCrux v5: loaded .ccxi companion indexes for BM25 text retrieval.
    pub retrieval_index: Arc<RwLock<corecrux_retrieval::IndexManager>>,
    /// Community edition: fact store (receipted entity memory).
    pub fact_store: Arc<RwLock<corecrux_memory::FactStore>>,
    /// Community edition: session store (scoped state per session).
    pub session_store: Arc<RwLock<corecrux_memory::SessionStore>>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(self::health::healthz))
        .route("/readyz", get(self::health::readyz))
        .route("/metrics", get(self::health::metrics))
        .route("/v1/gpus", get(self::routing::get_gpus))
        .route("/v1/shards", get(self::routing::get_shards))
        .route("/v1/route", get(self::routing::route_v1))
        .route("/v1/receipts/{receiptId}", get(self::receipts::get_receipt_body_v1))
        .route(
            "/v1/receipts/{receiptId}/signature",
            get(self::receipts::get_receipt_signature_v1),
        )
        .route(
            "/v1/receipts/{receiptId}/verification",
            get(self::receipts::get_receipt_verification_v1),
        )
        .route(
            "/v1/replay/exports/receipts/{receiptId}",
            get(self::receipts::get_receipt_export_v1),
        )
        .route(
            "/v1/replay/exports/answers/{answerId}",
            get(self::receipts::get_answer_export_v1),
        )
        .route(
            "/v1/replay/exports/actions/{actionId}",
            get(self::receipts::get_action_export_v1),
        )
        .route(
            "/v1/replay/exports/streams/{streamType}/{streamId}",
            get(self::receipts::get_stream_export_v1),
        )
        .route("/v1/shard-map", get(self::admin::get_shard_map))
        .route("/v1/admin/shard-map", axum::routing::post(self::admin::post_shard_map))
        .route("/v1/admin/control", get(self::admin::get_control))
        .route("/v1/admin/ops-log", get(self::admin::get_ops_log))
        .route("/v1/admin/valves", axum::routing::post(self::admin::post_valves))
        .route("/v1/admin/replication/status", get(self::admin::get_replication_status))
        .route("/v1/admin/actions", axum::routing::post(self::admin::post_admin_action))
        .route("/v1/admin/actions/{actionId}", get(self::admin::get_admin_action))
        .route(
            "/v1/admin/stream-meta",
            axum::routing::post(self::admin::post_stream_meta),
        )
        .route(
            "/v1/internal/replication/segments",
            axum::routing::post(self::admin::post_replication_segment),
        )
        .route(
            "/v1/admin/projections/artifacts/{artifactId}/state",
            get(self::projections::get_proj_artifact_state),
        )
        .route(
            "/v1/admin/projections/artifacts/{artifactId}/relations",
            get(self::projections::get_proj_artifact_relations),
        )
        .route(
            "/v1/admin/projections/artifacts/{artifactId}/dependents",
            get(self::projections::get_proj_artifact_dependents),
        )
        .route(
            "/v1/admin/projections/artifacts/{artifactId}/pressure-events",
            get(self::projections::get_proj_artifact_pressure_events),
        )
        .route("/v1/admin/projections/meta", get(self::projections::get_proj_meta))
        // Phase 7: Entity projection query endpoints
        .route("/v1/projections/entity/count", get(self::projections::get_entity_count))
        .route("/v1/projections/entity/timeline", get(self::projections::get_entity_timeline))
        .route("/v1/projections/entity/current-state", get(self::projections::get_entity_current_state))
        .route(
            "/v1/admin/projections/rebuild",
            axum::routing::post(self::projections::post_projection_rebuild),
        )
        .route("/v1/routing/route", get(self::routing::route_debug))
        .route("/v1/routing/status", get(self::routing::routing_status))
        // ── v4.2 query endpoints (graph expand + temporal range) ─────
        .route(
            "/v1/query/graph-expand",
            axum::routing::post(self::query::post_query_graph_expand),
        )
        .route(
            "/v1/query/time-range",
            axum::routing::post(self::query::post_query_time_range),
        )
        // ── v5 append + text retrieval endpoints ─────────────────────
        .route(
            "/v1/admin/append",
            axum::routing::post(self::append::post_admin_append),
        )
        .route(
            "/v1/query/text-search",
            axum::routing::post(self::query::post_query_text_search),
        )
        .route(
            "/v1/query/text-search/expand",
            axum::routing::post(self::query::post_query_text_search_expand),
        )
        // Memory primitives (Phase 1.5)
        .route("/v1/facts", axum::routing::put(self::facts::put_fact))
        .route("/v1/facts", get(self::facts::query_facts))
        .route("/v1/facts/bulk", axum::routing::put(self::facts::put_facts_bulk))
        .route("/v1/facts/{factId}", get(self::facts::get_fact))
        .route("/v1/facts/{factId}", axum::routing::delete(self::facts::delete_fact))
        .route("/v1/facts/entity/{entity}", get(self::facts::get_facts_by_entity))
        .route("/v1/facts/export", get(self::facts::export_facts))
        .route("/v1/sessions/{sessionId}/state", axum::routing::put(self::facts::put_session_state))
        .route("/v1/sessions/{sessionId}/state", get(self::facts::get_session_state))
        // Self-observation (crux-observe)
        .route("/v1/ops/facts", get(self::observe::query_ops_facts))
        .route("/v1/ops/errors", get(self::observe::query_ops_errors))
        .route("/v1/ops/health", get(self::observe::get_ops_health))
        .route("/v1/bootstrap/pull", axum::routing::post(self::observe::post_bootstrap_pull))
        .route("/v1/bootstrap/status", get(self::observe::get_bootstrap_status))
        // Production hardening: version endpoint
        .route("/v1/version", get(self::health::get_version))
        .with_state(state)
        // Built-in web playground (stateless, merged after with_state)
        .merge(crate::playground::routes())
        .layer(CatchPanicLayer::custom(self::health::handle_panic))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, Duration::from_secs(30)))
        .layer(middleware::from_fn(traceparent_middleware))
        .layer(middleware::from_fn(request_id_middleware))
}

async fn traceparent_middleware(req: Request<axum::body::Body>, next: Next) -> impl IntoResponse {
    #[cfg(feature = "otel")]
    {
        use opentelemetry::global;
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;

        struct HeaderExtractor<'a>(&'a HeaderMap);

        impl opentelemetry::propagation::Extractor for HeaderExtractor<'_> {
            fn get(&self, key: &str) -> Option<&str> {
                self.0.get(key).and_then(|v| v.to_str().ok())
            }

            fn keys(&self) -> Vec<&str> {
                self.0.keys().map(|k| k.as_str()).collect()
            }
        }

        let parent_cx =
            global::get_text_map_propagator(|propagator| propagator.extract(&HeaderExtractor(req.headers())));
        tracing::Span::current().set_parent(parent_cx);
    }
    next.run(req).await
}

async fn request_id_middleware(req: Request<axum::body::Body>, next: Next) -> impl IntoResponse {
    let started = std::time::Instant::now();
    let corr = CorrelationIds::from_headers(req.headers());
    let request_id = corr.request_id_or_new();
    let traceparent = corr.traceparent.clone();

    let mut response = next.run(req).await;
    let status = response.status();
    if let Ok(hv) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", hv);
    }
    if let Some(tp) = traceparent.as_deref() {
        if let Ok(hv) = HeaderValue::from_str(tp) {
            response.headers_mut().insert("traceparent", hv);
        }
    }
    #[cfg(feature = "otel")]
    {
        use opentelemetry::trace::TraceContextExt as _;
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;
        let cx = tracing::Span::current().context();
        let trace_id = cx.span().span_context().trace_id();
        if trace_id != opentelemetry::trace::TraceId::INVALID {
            if let Ok(hv) = HeaderValue::from_str(&trace_id.to_string()) {
                response.headers_mut().insert("x-trace-id", hv);
            }
        }
    }
    let outcome = if status.is_success() || status.is_redirection() {
        "ok"
    } else {
        "fail"
    };
    let mut op_log = StructuredOpLog::new(
        if outcome == "ok" { "info" } else { "warn" },
        "http_control",
        outcome,
        started.elapsed().as_millis() as u64,
    );
    op_log.request_id = Some(request_id.clone());
    op_log.traceparent = traceparent;
    if outcome != "ok" {
        op_log.error_code = Some(ErrorCode::Internal.as_str().to_string());
    }
    tracing::info!(
        ts = %op_log.ts,
        level = %op_log.level,
        request_id = %request_id,
        traceparent = ?op_log.traceparent,
        op = %op_log.op,
        outcome = %op_log.outcome,
        took_ms = op_log.took_ms,
        status = status.as_u16(),
        "http request complete"
    );
    response
}

fn map_store_error_http(err: AppendError) -> ProblemResponse {
    let pd = match err {
        AppendError::InvalidArgument(msg) => ProblemDetails::bad_request(msg),
        AppendError::FailedPrecondition(msg) => ProblemDetails::precondition_failed(msg),
        AppendError::ResourceExhausted(msg) => ProblemDetails::rate_limited(msg),
        AppendError::IoBackend(msg) => ProblemDetails::service_unavailable(msg),
        AppendError::Internal(msg) => ProblemDetails::internal(msg),
        AppendError::ShardUnavailable {
            shard_id,
            owner_gpu_id,
            current_shard_map_version,
        } => ProblemDetails::service_unavailable("shard unavailable").with_extensions(serde_json::json!({
            "code": "SHARD_UNAVAILABLE",
            "shardId": shard_id,
            "ownerGpuId": owner_gpu_id,
            "currentShardMapVersion": current_shard_map_version
        })),
        AppendError::WrongShard {
            leader_grpc_addr,
            current_shard_map_version,
        } => ProblemDetails::precondition_failed("wrong shard").with_extensions(serde_json::json!({
            "code": "WRONG_SHARD",
            "leaderGrpcAddr": leader_grpc_addr,
            "currentShardMapVersion": current_shard_map_version
        })),
        AppendError::ShardMapVersionMismatch {
            client_version,
            current_version,
        } => ProblemDetails::precondition_failed("shard map version mismatch").with_extensions(serde_json::json!({
            "code": "SHARDMAP_VERSION_MISMATCH",
            "clientShardMapVersion": client_version,
            "currentShardMapVersion": current_version
        })),
    };
    ProblemResponse(pd)
}

fn problem_for_status(status: StatusCode, detail: impl Into<String>) -> ProblemResponse {
    let detail = detail.into();
    let pd = match status {
        StatusCode::BAD_REQUEST => ProblemDetails::bad_request(detail),
        StatusCode::NOT_FOUND => ProblemDetails::not_found(detail),
        StatusCode::PRECONDITION_FAILED => ProblemDetails::precondition_failed(detail),
        StatusCode::NOT_IMPLEMENTED => ProblemDetails::not_implemented(detail),
        StatusCode::SERVICE_UNAVAILABLE => ProblemDetails::service_unavailable(detail),
        StatusCode::PAYLOAD_TOO_LARGE => ProblemDetails::new(
            StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
            "https://errors.cuecrux.com/payload-too-large",
            "Payload Too Large",
        )
        .with_detail(detail),
        _ => ProblemDetails::internal(detail),
    };
    ProblemResponse(pd)
}

fn problem_response(status: StatusCode, detail: impl Into<String>) -> Response {
    problem_for_status(status, detail).into_response()
}

#[derive(Debug, serde::Deserialize)]
struct TenantQuery {
    tenant_id: String,
}

#[derive(Debug, serde::Deserialize)]
struct RelationsQuery {
    tenant_id: String,
    direction: Option<String>, // "in" | "out"
    relation_type: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, serde::Deserialize)]
struct DependentsQuery {
    tenant_id: String,
    dependent_type: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, serde::Deserialize)]
struct PressureQuery {
    tenant_id: String,
    open_only: Option<bool>,
    limit: Option<usize>,
    offset: Option<usize>,
}

#[derive(Debug, serde::Deserialize)]
struct ProjMetaQuery {
    shard_id: String,
}

fn is_query_feature_enabled(env_var: &str) -> bool {
    std::env::var(env_var)
        .ok()
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn hex16(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 32];
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    String::from_utf8_lossy(&out).to_string()
}

fn to_valve_info(v: &control::ValveV1) -> ValveInfo {
    ValveInfo {
        enabled: v.enabled,
        actor: v.actor.clone(),
        reason: v.reason.clone(),
        updated_at_unix_ns: v.updated_at_unix_ns,
        retry_after_ms: v.retry_after_ms,
    }
}

fn wants_cbor(headers: &HeaderMap) -> bool {
    let Some(v) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    v.split(',')
        .map(|s| s.trim())
        .any(|s| s.starts_with("application/cbor"))
}

pub(crate) fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    String::from_utf8_lossy(&out).to_string()
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
