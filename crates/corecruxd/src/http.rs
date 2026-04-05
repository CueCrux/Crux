// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
    build_receipt_export_v1, resolve_subject_receipt_id_v1, ExportFormatV1, ExportRedactionV1,
    ReceiptExportIncludeV1, ReceiptExportOptionsV1, SubjectResolveModeV1, EVT_RECEIPT_BODY_V1,
    EVT_RECEIPT_SIG_V1, STREAM_TYPE_RECEIPT,
};
use corecrux_types::{
    format_u64_hex, parse_shard_id_u32, CompatContract,
    ControlAdminActionFinishedV1, ControlAdminActionSubmittedV1, ControlCheckpointMaterializedV1,
    ControlStateMutationV1,
    EvidenceAuthContextV1, EvidenceNodeContextV1, EvidenceRequestContextV1, HealthzResponse,
    KnowledgeAuthorityModeV1, KnowledgeParityOutcomeV1, KnowledgeParityStatusV1,
    KnowledgeRolloutStageV1, ProblemDetails, RoutingInfo, ShardMapV1,
    CONTROL_EVIDENCE_CONTENT_TYPE_V1,
    EVT_CONTROL_ADMIN_ACTION_FINISHED_V1,
    EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1, EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1,
    EVT_CONTROL_STATE_MUTATION_V1,
};
use corecrux_types::{ValveInfo, ValvesInfo};

use crate::config::CommitLevel;
use crate::metrics::Metrics;
use crate::problem::ProblemResponse;
use crate::shard_map::RoutingTable;
use crate::structured_log::{CorrelationIds, ErrorCode, StructuredOpLog};

use crate::auth::{
    describe_http_evidence, require_http_scopes, require_http_scopes_for_tenant, Authz,
};
use crate::control::{self, ValveDecision};
use crate::dataplane_store::AppendError;

#[derive(Debug, Clone)]
pub struct Readiness {
    pub gpu_context: bool,
    pub gpu_context_error: Option<String>,
    pub kernel_module_loaded: bool,
    pub kernel_module_error: Option<String>,
    pub smoke_kernel_ok: bool,
    pub smoke_kernel_error: Option<String>,
    pub io_backend_ok: bool,
    pub io_backend_error: Option<String>,
    // Phase 9: production IO (GDS) engagement status.
    pub gds_active: bool,
    pub gds_degraded: bool,
    pub gds_error: Option<String>,
    // Phase 9: pinned hardware profile match status (optional).
    pub hardware_profile_ok: bool,
    pub hardware_profile_error: Option<String>,
    pub control_evidence_hosted: bool,
    pub control_evidence_ok: bool,
    pub control_evidence_error: Option<String>,
}

impl Default for Readiness {
    fn default() -> Self {
        Self {
            gpu_context: false,
            gpu_context_error: None,
            kernel_module_loaded: false,
            kernel_module_error: None,
            smoke_kernel_ok: false,
            smoke_kernel_error: None,
            io_backend_ok: false,
            io_backend_error: None,
            gds_active: false,
            gds_degraded: false,
            gds_error: None,
            hardware_profile_ok: false,
            hardware_profile_error: None,
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
    pub warning_free_ratio: f64,
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
    pub io_backend: String,
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
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/v1/gpus", get(get_gpus))
        .route("/v1/shards", get(get_shards))
        .route("/v1/route", get(route_v1))
        .route("/v1/receipts/{receiptId}", get(get_receipt_body_v1))
        .route(
            "/v1/receipts/{receiptId}/signature",
            get(get_receipt_signature_v1),
        )
        .route(
            "/v1/receipts/{receiptId}/verification",
            get(get_receipt_verification_v1),
        )
        .route(
            "/v1/replay/exports/receipts/{receiptId}",
            get(get_receipt_export_v1),
        )
        .route(
            "/v1/replay/exports/answers/{answerId}",
            get(get_answer_export_v1),
        )
        .route(
            "/v1/replay/exports/actions/{actionId}",
            get(get_action_export_v1),
        )
        .route(
            "/v1/replay/exports/streams/{streamType}/{streamId}",
            get(get_stream_export_v1),
        )
        .route("/v1/shard-map", get(get_shard_map))
        .route("/v1/admin/shard-map", axum::routing::post(post_shard_map))
        .route("/v1/admin/control", get(get_control))
        .route("/v1/admin/ops-log", get(get_ops_log))
        .route("/v1/admin/valves", axum::routing::post(post_valves))
        .route("/v1/admin/replication/status", get(get_replication_status))
        .route("/v1/admin/actions", axum::routing::post(post_admin_action))
        .route("/v1/admin/actions/{actionId}", get(get_admin_action))
        .route(
            "/v1/admin/stream-meta",
            axum::routing::post(post_stream_meta),
        )
        .route(
            "/v1/internal/replication/segments",
            axum::routing::post(post_replication_segment),
        )
        .route(
            "/v1/admin/projections/artifacts/{artifactId}/state",
            get(get_proj_artifact_state),
        )
        .route(
            "/v1/admin/projections/artifacts/{artifactId}/relations",
            get(get_proj_artifact_relations),
        )
        .route(
            "/v1/admin/projections/artifacts/{artifactId}/dependents",
            get(get_proj_artifact_dependents),
        )
        .route(
            "/v1/admin/projections/artifacts/{artifactId}/pressure-events",
            get(get_proj_artifact_pressure_events),
        )
        .route("/v1/admin/projections/meta", get(get_proj_meta))
        // Phase 7: Entity projection query endpoints
        .route("/v1/projections/entity/count", get(get_entity_count))
        .route("/v1/projections/entity/timeline", get(get_entity_timeline))
        .route("/v1/projections/entity/current-state", get(get_entity_current_state))
        .route(
            "/v1/admin/projections/rebuild",
            axum::routing::post(post_projection_rebuild),
        )
        .route("/v1/routing/route", get(route_debug))
        .route("/v1/routing/status", get(routing_status))
        // ── v4.2 query endpoints (graph expand + temporal range) ─────
        .route(
            "/v1/query/graph-expand",
            axum::routing::post(post_query_graph_expand),
        )
        .route(
            "/v1/query/time-range",
            axum::routing::post(post_query_time_range),
        )
        // ── v5 append + text retrieval endpoints ─────────────────────
        .route(
            "/v1/admin/append",
            axum::routing::post(post_admin_append),
        )
        .route(
            "/v1/query/text-search",
            axum::routing::post(post_query_text_search),
        )
        .route(
            "/v1/query/text-search/expand",
            axum::routing::post(post_query_text_search_expand),
        )
        // Memory primitives (Phase 1.5)
        .route("/v1/facts", axum::routing::put(put_fact))
        .route("/v1/facts", get(query_facts))
        .route("/v1/facts/bulk", axum::routing::put(put_facts_bulk))
        .route("/v1/facts/{factId}", get(get_fact))
        .route("/v1/facts/{factId}", axum::routing::delete(delete_fact))
        .route("/v1/facts/entity/{entity}", get(get_facts_by_entity))
        .route("/v1/sessions/{sessionId}/state", axum::routing::put(put_session_state))
        .route("/v1/sessions/{sessionId}/state", get(get_session_state))
        // Self-observation (crux-observe)
        .route("/v1/ops/facts", get(query_ops_facts))
        .route("/v1/ops/errors", get(query_ops_errors))
        .route("/v1/ops/health", get(get_ops_health))
        .route("/v1/bootstrap/pull", axum::routing::post(post_bootstrap_pull))
        .route("/v1/bootstrap/status", get(get_bootstrap_status))
        // Production hardening: version endpoint
        .route("/v1/version", get(get_version))
        .with_state(state)
        .layer(CatchPanicLayer::custom(handle_panic))
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

        let parent_cx = global::get_text_map_propagator(|propagator| {
            propagator.extract(&HeaderExtractor(req.headers()))
        });
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
        } => ProblemDetails::service_unavailable("shard unavailable").with_extensions(
            serde_json::json!({
                "code": "SHARD_UNAVAILABLE",
                "shardId": shard_id,
                "ownerGpuId": owner_gpu_id,
                "currentShardMapVersion": current_shard_map_version
            }),
        ),
        AppendError::WrongShard {
            leader_grpc_addr,
            current_shard_map_version,
        } => {
            ProblemDetails::precondition_failed("wrong shard").with_extensions(serde_json::json!({
                "code": "WRONG_SHARD",
                "leaderGrpcAddr": leader_grpc_addr,
                "currentShardMapVersion": current_shard_map_version
            }))
        }
        AppendError::ShardMapVersionMismatch {
            client_version,
            current_version,
        } => ProblemDetails::precondition_failed("shard map version mismatch").with_extensions(
            serde_json::json!({
                "code": "SHARDMAP_VERSION_MISMATCH",
                "clientShardMapVersion": client_version,
                "currentShardMapVersion": current_version
            }),
        ),
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

// ── v4.2 query types (graph expand + temporal range) ─────────────────────

#[derive(Debug, serde::Deserialize)]
struct GraphExpandBody {
    tenant_id: String,
    seed_artifact_ids: Vec<u32>,
    #[serde(default)]
    edge_types: Vec<String>,
    #[serde(default = "default_max_hops")]
    max_hops: u32,
    #[serde(default = "default_budget")]
    budget: usize,
    #[serde(default)]
    min_confidence: f32,
    #[serde(default)]
    include_state: bool,
}

fn default_max_hops() -> u32 {
    2
}
fn default_budget() -> usize {
    50
}

#[derive(Debug, serde::Deserialize)]
struct TimeRangeBody {
    tenant_id: String,
    start_micros: i64,
    end_micros: i64,
    #[serde(default)]
    artifact_ids: Vec<u32>,
    #[serde(default)]
    include_relations: bool,
    #[serde(default = "default_time_range_limit")]
    limit: usize,
}

fn default_time_range_limit() -> usize {
    100
}

// ── v4.2 query handlers ──────────────────────────────────────────────────

#[tracing::instrument(level = "info", skip(state, headers, body), fields(tenant_id = %body.tenant_id))]
async fn post_query_graph_expand(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<GraphExpandBody>,
) -> impl IntoResponse {
    if let Err(_problem) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        // Fall back to admin:read for backwards compat
        if let Err(problem2) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem2.into_response();
        }
    }

    if !is_query_feature_enabled("CORECRUXD_QUERY_GRAPH_EXPAND") {
        return problem_response(StatusCode::NOT_FOUND, "graph-expand query not enabled");
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    if body.seed_artifact_ids.is_empty() {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "seed_artifact_ids must not be empty",
        );
    }

    let edge_types: Vec<corecrux_projections::RelationTypeV1> = body
        .edge_types
        .iter()
        .filter_map(|s| corecrux_projections::RelationTypeV1::from_engine_str(s))
        .collect();

    let t0 = std::time::Instant::now();
    let gpu_ids = pool.gpu_ids();
    let mut combined = corecrux_projections::query::graph_expand::GraphExpandResponse {
        artifacts: Vec::new(),
        stats: Default::default(),
    };

    for gpu_id in gpu_ids {
        let Some(store) = pool.store_for_gpu_id(gpu_id) else {
            continue;
        };
        let guard = store.read().await;
        let resp = guard.query_graph_expand(
            &body.tenant_id,
            &body.seed_artifact_ids,
            &edge_types,
            body.max_hops,
            body.budget,
            body.min_confidence,
            body.include_state,
        );
        combined.stats.nodes_visited += resp.stats.nodes_visited;
        combined.stats.edges_traversed += resp.stats.edges_traversed;
        combined.stats.hops_used = combined.stats.hops_used.max(resp.stats.hops_used);
        combined.artifacts.extend(resp.artifacts);
    }

    // Final dedup + re-rank across GPU stores
    combined.artifacts.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    combined.artifacts.dedup_by_key(|a| a.artifact_id);
    combined.artifacts.truncate(body.budget);
    combined.stats.budget_remaining = body.budget.saturating_sub(combined.artifacts.len());

    state
        .metrics
        .observe_graph_expand(t0.elapsed().as_secs_f64(), combined.stats.nodes_visited);

    #[derive(serde::Serialize)]
    struct Resp {
        artifacts: Vec<ArtifactResp>,
        traversal_stats: StatsResp,
    }
    #[derive(serde::Serialize)]
    struct ArtifactResp {
        artifact_id: u32,
        score: f32,
        hop_distance: u32,
        edge_types_used: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        state: Option<ArtifactStateResp>,
    }
    #[derive(serde::Serialize)]
    struct ArtifactStateResp {
        living_status: String,
        confidence: f32,
        updated_at_micros: i64,
        trunk_tier: u8,
    }
    #[derive(serde::Serialize)]
    struct StatsResp {
        nodes_visited: u32,
        hops_used: u32,
        budget_remaining: usize,
        edges_traversed: u64,
    }

    let artifacts: Vec<ArtifactResp> = combined
        .artifacts
        .into_iter()
        .map(|a| {
            let state_resp = a.state.map(|s| ArtifactStateResp {
                living_status: s.living_status.as_engine_str().to_string(),
                confidence: corecrux_projections::dequantize_confidence_f32(s.confidence_q16),
                updated_at_micros: s.updated_at_micros,
                trunk_tier: s.trunk_tier,
            });
            ArtifactResp {
                artifact_id: a.artifact_id,
                score: a.score,
                hop_distance: a.hop_distance,
                edge_types_used: a
                    .edge_types_used
                    .iter()
                    .map(|t| t.as_engine_str().to_string())
                    .collect(),
                state: state_resp,
            }
        })
        .collect();

    (
        StatusCode::OK,
        Json(Resp {
            artifacts,
            traversal_stats: StatsResp {
                nodes_visited: combined.stats.nodes_visited,
                hops_used: combined.stats.hops_used,
                budget_remaining: combined.stats.budget_remaining,
                edges_traversed: combined.stats.edges_traversed,
            },
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers, body), fields(tenant_id = %body.tenant_id))]
async fn post_query_time_range(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TimeRangeBody>,
) -> impl IntoResponse {
    if let Err(_problem) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem2) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem2.into_response();
        }
    }

    if !is_query_feature_enabled("CORECRUXD_QUERY_TIME_RANGE") {
        return problem_response(StatusCode::NOT_FOUND, "time-range query not enabled");
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    if body.start_micros >= body.end_micros {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "start_micros must be less than end_micros",
        );
    }

    // Reject windows > 365 days
    let max_window = 365i64 * 86_400_000_000;
    if body.end_micros - body.start_micros > max_window {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "time window must not exceed 365 days",
        );
    }

    let t0 = std::time::Instant::now();
    let gpu_ids = pool.gpu_ids();
    let mut all_artifacts = Vec::new();
    let mut stats = corecrux_projections::query::time_range::TimeRangeStats::default();

    for gpu_id in gpu_ids {
        let Some(store) = pool.store_for_gpu_id(gpu_id) else {
            continue;
        };
        let guard = store.read().await;
        let resp = guard.query_time_range(
            &body.tenant_id,
            body.start_micros,
            body.end_micros,
            &body.artifact_ids,
            body.include_relations,
            body.limit,
        );
        stats.artifacts_scanned += resp.stats.artifacts_scanned;
        stats.relations_scanned += resp.stats.relations_scanned;
        stats.total_changes += resp.stats.total_changes;
        all_artifacts.extend(resp.artifacts);
    }

    // Final dedup + sort across GPU stores
    all_artifacts.sort_by(|a, b| {
        b.current_state
            .updated_at_micros
            .cmp(&a.current_state.updated_at_micros)
    });
    all_artifacts.dedup_by_key(|a| a.artifact_id);
    all_artifacts.truncate(body.limit);

    state
        .metrics
        .observe_time_range(t0.elapsed().as_secs_f64(), stats.artifacts_scanned);

    #[derive(serde::Serialize)]
    struct Resp {
        artifacts_changed: Vec<ArtifactChanged>,
        scan_stats: ScanStats,
    }
    #[derive(serde::Serialize)]
    struct ArtifactChanged {
        artifact_id: u32,
        living_status: String,
        confidence: f32,
        updated_at_micros: i64,
        relations_changed: Vec<RelChanged>,
        relation_change_count: u32,
    }
    #[derive(serde::Serialize)]
    struct RelChanged {
        src_artifact_id: u32,
        dst_artifact_id: u32,
        relation_type: String,
        confidence: f32,
        created_at_micros: i64,
        updated_at_micros: i64,
    }
    #[derive(serde::Serialize)]
    struct ScanStats {
        artifacts_scanned: u32,
        relations_scanned: u64,
        total_changes: u32,
    }

    let artifacts_changed: Vec<ArtifactChanged> = all_artifacts
        .into_iter()
        .map(|a| ArtifactChanged {
            artifact_id: a.artifact_id,
            living_status: a.current_state.living_status.as_engine_str().to_string(),
            confidence: corecrux_projections::dequantize_confidence_f32(
                a.current_state.confidence_q16,
            ),
            updated_at_micros: a.current_state.updated_at_micros,
            relations_changed: a
                .relations_changed
                .iter()
                .map(|r| RelChanged {
                    src_artifact_id: r.src_artifact_id,
                    dst_artifact_id: r.dst_artifact_id,
                    relation_type: r.relation_type.as_engine_str().to_string(),
                    confidence: r.confidence,
                    created_at_micros: r.created_at_micros,
                    updated_at_micros: r.updated_at_micros,
                })
                .collect(),
            relation_change_count: a.relation_change_count,
        })
        .collect();

    (
        StatusCode::OK,
        Json(Resp {
            artifacts_changed,
            scan_stats: ScanStats {
                artifacts_scanned: stats.artifacts_scanned,
                relations_scanned: stats.relations_scanned,
                total_changes: stats.total_changes,
            },
        }),
    )
        .into_response()
}

// ── v5 general-purpose HTTP append ──────────────────────────────────

#[derive(serde::Deserialize)]
struct AppendBody {
    tenant_id: String,
    stream_type: String,
    stream_id: String,
    #[serde(default)]
    expected_next_seq: u64,
    events: Vec<AppendEventBody>,
}

#[derive(serde::Deserialize)]
struct AppendEventBody {
    event_id: String,
    occurred_at: String,
    event_type: String,
    #[serde(default = "default_content_type")]
    content_type: String,
    /// Payload as raw UTF-8 string (JSON). Stored as-is in the frame.
    payload: String,
}

fn default_content_type() -> String {
    "application/json".to_string()
}

#[tracing::instrument(level = "info", skip(state, headers, body), fields(tenant_id = %body.tenant_id, stream_type = %body.stream_type))]
async fn post_admin_append(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AppendBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.clone() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    if body.events.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "events must not be empty");
    }
    if body.events.len() > 1024 {
        return problem_response(StatusCode::BAD_REQUEST, "max 1024 events per batch");
    }

    let events: Vec<AppendEvent> = body
        .events
        .iter()
        .map(|e| AppendEvent {
            event_id: e.event_id.clone(),
            occurred_at: e.occurred_at.clone(),
            event_type: e.event_type.clone(),
            content_type: e.content_type.clone(),
            payload: e.payload.as_bytes().to_vec(),
        })
        .collect();

    let (_decision, store) = match pool
        .store_for_stream(
            &body.tenant_id,
            &body.stream_type,
            &body.stream_id,
            None,
        )
        .await
    {
        Ok(pair) => pair,
        Err(err) => return map_store_error_http(err).into_response(),
    };

    let store = store.read().await;
    if let Err(err) = store
        .append_batch(
            &body.tenant_id,
            &body.stream_type,
            &body.stream_id,
            body.expected_next_seq,
            None,
            &events,
        )
        .await
    {
        return map_store_error_http(err).into_response();
    }

    // Reload .ccxi indexes after append (seal + ccxi build happens synchronously in Phase 2 mode).
    {
        let idx = state.retrieval_index.clone();
        let data_dir = state.data_dir.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let mut guard = idx.write().await;
            let shards_dir = data_dir.join("shards");
            if let Ok(entries) = std::fs::read_dir(&shards_dir) {
                for entry in entries.flatten() {
                    let seg_dir = entry.path().join("segments");
                    let _ = guard.scan_and_load(&seg_dir);
                }
            }
        });
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "appended": body.events.len(),
            "stream_id": body.stream_id,
        })),
    )
        .into_response()
}

// ── v5 text retrieval ────────────────────────────────────────────────

#[derive(serde::Deserialize)]
struct TextSearchBody {
    tenant_id: String,
    query: String,
    #[serde(default = "default_text_search_limit")]
    limit: usize,
    /// Token budget: if set, fill results by descending score until budget is exhausted.
    /// Overrides `limit` when provided.
    token_budget: Option<usize>,
    /// Minimum BM25 score threshold. Results below this floor are excluded.
    min_score: Option<f32>,
    /// Query mode: "normal" (default) returns full results, "scan" returns metadata only.
    #[serde(default)]
    mode: Option<String>,
    /// Include CROWN receipt in response.
    #[serde(default)]
    include_receipt: Option<bool>,
}

fn default_text_search_limit() -> usize {
    10
}

#[tracing::instrument(level = "info", skip(state, headers, body))]
async fn post_query_text_search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TextSearchBody>,
) -> impl IntoResponse {
    if let Err(_problem) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem2) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem2.into_response();
        }
    }

    if !is_query_feature_enabled("CORECRUXD_QUERY_TEXT_SEARCH") {
        return problem_response(StatusCode::NOT_FOUND, "text-search query not enabled");
    }

    if body.query.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "query must not be empty");
    }

    let limit = body.limit.min(100).max(1);
    let is_scan_mode = body.mode.as_deref() == Some("scan");

    let t0 = std::time::Instant::now();

    let tenant_filter: Option<u16> = if body.tenant_id.is_empty() {
        None
    } else {
        let hash = xxhash_rust::xxh64::xxh64(body.tenant_id.as_bytes(), 0);
        Some((hash & 0xFFFF) as u16)
    };

    let index = state.retrieval_index.read().await;
    let readers = index.readers();

    if readers.is_empty() {
        return (
            StatusCode::OK,
            axum::Json(serde_json::json!({
                "results": [],
                "coverage": { "score": 0.0, "gaps": [], "below_floor": 0 },
                "meta": {
                    "backend": "corecrux-v5-bm25",
                    "took_ms": t0.elapsed().as_millis(),
                    "segments_searched": 0,
                    "total_docs": 0,
                }
            })),
        )
            .into_response();
    }

    // Use the extended search function with min_score and coverage tracking
    let search_result = corecrux_retrieval::bm25::bm25_search(
        &readers,
        &body.query,
        if body.token_budget.is_some() { 1000 } else { limit },
        tenant_filter,
        &corecrux_retrieval::bm25::Bm25Params::default(),
        body.min_score,
    );

    let took_ms = t0.elapsed().as_millis();

    // Apply token budget if specified
    let (results, tokens_used, results_omitted) = if let Some(budget) = body.token_budget {
        let mut used: usize = 0;
        let mut included = Vec::new();
        let mut omitted = 0usize;

        for h in &search_result.hits {
            let token_count = h.doc_length_tokens as usize;
            if used + token_count > budget && !included.is_empty() {
                omitted += 1;
                continue;
            }
            used += token_count;
            included.push(h.clone());
            if used >= budget {
                omitted = search_result.hits.len() - included.len();
                break;
            }
        }
        (included, used, omitted)
    } else {
        let tokens: usize = search_result.hits.iter().map(|h| h.doc_length_tokens as usize).sum();
        (search_result.hits, tokens, 0)
    };

    // Build coverage gaps array
    let gaps: Vec<serde_json::Value> = search_result
        .coverage
        .missing_tokens
        .iter()
        .map(|term| {
            serde_json::json!({
                "query_terms": [term],
                "match_quality": "none",
                "suggestion": format!("No documents in corpus contain '{}'", term)
            })
        })
        .collect();

    #[derive(serde::Serialize)]
    struct HitResp {
        segment_index: usize,
        doc_id: u32,
        score: f32,
        frame_offset: u32,
        token_count: u16,
    }

    let result_items: Vec<HitResp> = results
        .iter()
        .map(|h| HitResp {
            segment_index: h.segment_index,
            doc_id: h.doc_id,
            score: h.score,
            frame_offset: h.frame_offset,
            token_count: h.doc_length_tokens,
        })
        .collect();

    let mut response = serde_json::json!({
        "results": result_items,
        "coverage": {
            "score": search_result.coverage.score,
            "gaps": gaps,
            "below_floor": search_result.coverage.below_floor,
        },
        "meta": {
            "backend": "corecrux-v5-bm25",
            "took_ms": took_ms,
            "segments_searched": readers.len(),
            "total_docs": index.total_docs(),
            "total_candidates": search_result.total_candidates,
        }
    });

    // Add token budget metadata when applicable
    if body.token_budget.is_some() {
        response["tokens_used"] = serde_json::json!(tokens_used);
        response["tokens_available"] = serde_json::json!(body.token_budget.unwrap());
        response["results_omitted"] = serde_json::json!(results_omitted);
    }

    if is_scan_mode {
        response["scan_mode"] = serde_json::json!(true);
    }

    // crux-observe: record low-coverage queries as ops facts
    if crux_observe::config::self_observe_enabled()
        && search_result.coverage.score < 0.3
        && !search_result.coverage.missing_tokens.is_empty()
    {
        let fs = state.fact_store.clone();
        let missing = search_result.coverage.missing_tokens.clone();
        let score = search_result.coverage.score;
        let query_text = body.query.clone();
        tokio::spawn(async move {
            let event = serde_json::json!({
                "event_type": crux_observe::schema::EVT_OPS_QUERY_COVERAGE_V1,
                "query_terms": query_text.split_whitespace().collect::<Vec<&str>>(),
                "coverage_score": score,
                "missing_tokens": missing,
                "timestamp": chrono::Utc::now().to_rfc3339(),
            });
            let json = serde_json::to_string(&event).unwrap_or_default();
            let entity = crux_observe::schema::ops_entity(
                "coverage",
                &uuid::Uuid::new_v4().to_string(),
            );
            let mut store = fs.write().await;
            store.store(corecrux_memory::fact_store::StoreFact {
                entity,
                key: crux_observe::schema::EVT_OPS_QUERY_COVERAGE_V1.to_string(),
                value: json,
                source_receipt: None,
                confidence: score,
            });
        });
    }

    (StatusCode::OK, axum::Json(response)).into_response()
}

// ── Progressive retrieval: expand ──────────────────────────────────────

#[derive(serde::Deserialize)]
struct TextSearchExpandBody {
    /// Tenant ID for the expand request (must match original scan).
    tenant_id: String,
    /// Result IDs to expand (segment_index:doc_id pairs).
    result_ids: Vec<ExpandResultId>,
}

#[derive(serde::Deserialize)]
struct ExpandResultId {
    segment_index: usize,
    doc_id: u32,
}

#[tracing::instrument(level = "info", skip(state, headers, body))]
async fn post_query_text_search_expand(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TextSearchExpandBody>,
) -> impl IntoResponse {
    if let Err(_problem) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem2) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem2.into_response();
        }
    }

    if !is_query_feature_enabled("CORECRUXD_QUERY_TEXT_SEARCH") {
        return problem_response(StatusCode::NOT_FOUND, "text-search query not enabled");
    }

    let index = state.retrieval_index.read().await;
    let readers = index.readers();

    let mut tokens_loaded: usize = 0;
    let mut chunks = Vec::new();

    for rid in &body.result_ids {
        if rid.segment_index >= readers.len() {
            continue;
        }
        let reader = readers[rid.segment_index];
        let doc_id = rid.doc_id as usize;
        if doc_id >= reader.docs.len() {
            continue;
        }
        let doc = &reader.docs[doc_id];
        tokens_loaded += doc.doc_length_tokens as usize;

        chunks.push(serde_json::json!({
            "segment_index": rid.segment_index,
            "doc_id": rid.doc_id,
            "frame_offset": doc.frame_offset,
            "token_count": doc.doc_length_tokens,
        }));
    }

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "chunks": chunks,
            "tokens_loaded": tokens_loaded,
        })),
    )
        .into_response()
}

// ── Fact Store API (Phase 1.5) ──────────────────────────────────────

async fn put_fact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<corecrux_memory::fact_store::StoreFact>,
) -> impl IntoResponse {
    if let Err(_) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let fact = state.fact_store.write().await.store(body);
    (StatusCode::CREATED, axum::Json(serde_json::json!(fact))).into_response()
}

async fn put_facts_bulk(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Vec<corecrux_memory::fact_store::StoreFact>>,
) -> impl IntoResponse {
    if let Err(_) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let facts = state.fact_store.write().await.store_bulk(body);
    (StatusCode::CREATED, axum::Json(serde_json::json!({"facts": facts}))).into_response()
}

async fn get_fact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(fact_id): Path<String>,
) -> impl IntoResponse {
    if let Err(_) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let store = state.fact_store.read().await;
    match store.get(&fact_id) {
        Some(fact) => (StatusCode::OK, axum::Json(serde_json::json!(fact))).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, &format!("fact '{}' not found", fact_id)),
    }
}

async fn delete_fact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(fact_id): Path<String>,
) -> impl IntoResponse {
    if let Err(_) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let deleted = state.fact_store.write().await.delete(&fact_id);
    if deleted {
        (StatusCode::OK, axum::Json(serde_json::json!({"deleted": true}))).into_response()
    } else {
        problem_response(StatusCode::NOT_FOUND, &format!("fact '{}' not found", fact_id))
    }
}

async fn get_facts_by_entity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(entity): Path<String>,
) -> impl IntoResponse {
    if let Err(_) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let store = state.fact_store.read().await;
    let facts: Vec<_> = store.get_by_entity(&entity);
    (StatusCode::OK, axum::Json(serde_json::json!({"facts": facts}))).into_response()
}

async fn query_facts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Err(_) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let q = corecrux_memory::fact_store::FactQuery {
        query: params.get("query").cloned(),
        entity: params.get("entity").cloned(),
        entity_prefix: params.get("entity_prefix").cloned(),
        top_k: params.get("top_k").and_then(|v| v.parse().ok()).unwrap_or(10),
        token_budget: params.get("token_budget").and_then(|v| v.parse().ok()),
    };
    let store = state.fact_store.read().await;
    let result = store.query(&q);
    (StatusCode::OK, axum::Json(serde_json::json!({
        "facts": result.facts,
        "total_tokens": result.total_tokens,
    }))).into_response()
}

// ── Session Store API (Phase 1.5) ──────────────────────────────────

async fn put_session_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Err(_) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let session = state.session_store.write().await.put(&session_id, body);
    (StatusCode::OK, axum::Json(serde_json::json!(session))).into_response()
}

async fn get_session_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    if let Err(_) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let store = state.session_store.read().await;
    match store.get(&session_id) {
        Some(session) => (StatusCode::OK, axum::Json(serde_json::json!(session))).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, &format!("session '{}' not found", session_id)),
    }
}

// ── Self-observation API (crux-observe) ───────────────────────────

fn is_observe_enabled() -> bool {
    crux_observe::config::self_observe_enabled()
}

fn observe_not_enabled_response() -> Response {
    problem_response(
        StatusCode::NOT_IMPLEMENTED,
        "self-observation not enabled",
    )
}

async fn query_ops_facts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Err(_) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    if !is_observe_enabled() {
        return observe_not_enabled_response();
    }
    let q = corecrux_memory::fact_store::FactQuery {
        query: params.get("query").cloned(),
        entity: None,
        entity_prefix: Some(crux_observe::schema::OPS_PREFIX.to_string()),
        top_k: params.get("top_k").and_then(|v| v.parse().ok()).unwrap_or(50),
        token_budget: params.get("token_budget").and_then(|v| v.parse().ok()),
    };
    let store = state.fact_store.read().await;
    let result = store.query(&q);
    (StatusCode::OK, axum::Json(serde_json::json!({
        "facts": result.facts,
        "total_tokens": result.total_tokens,
    }))).into_response()
}

async fn query_ops_errors(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if let Err(_) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    if !is_observe_enabled() {
        return observe_not_enabled_response();
    }
    let q = corecrux_memory::fact_store::FactQuery {
        query: params.get("query").cloned(),
        entity: None,
        entity_prefix: Some("__ops__::error".to_string()),
        top_k: params.get("top_k").and_then(|v| v.parse().ok()).unwrap_or(50),
        token_budget: params.get("token_budget").and_then(|v| v.parse().ok()),
    };
    let store = state.fact_store.read().await;
    let result = store.query(&q);

    // If `since` param is provided, filter by stored_at
    let facts = if let Some(since_str) = params.get("since") {
        if let Ok(since) = chrono::DateTime::parse_from_rfc3339(since_str) {
            let since_utc = since.with_timezone(&chrono::Utc);
            result.facts.into_iter().filter(|f| f.stored_at >= since_utc).collect()
        } else {
            result.facts
        }
    } else {
        result.facts
    };

    (StatusCode::OK, axum::Json(serde_json::json!({
        "facts": facts,
        "total_tokens": result.total_tokens,
    }))).into_response()
}

async fn get_ops_health(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(_) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    if !is_observe_enabled() {
        return observe_not_enabled_response();
    }
    let q = corecrux_memory::fact_store::FactQuery {
        query: None,
        entity: None,
        entity_prefix: Some("__ops__::health".to_string()),
        top_k: 1000,
        token_budget: None,
    };
    let store = state.fact_store.read().await;
    let result = store.query(&q);

    // Deduplicate: keep only the latest fact per component (entity)
    let mut latest: std::collections::HashMap<String, &corecrux_memory::fact_store::Fact> =
        std::collections::HashMap::new();
    for fact in &result.facts {
        let entry = latest.entry(fact.entity.clone()).or_insert(fact);
        if fact.stored_at > entry.stored_at {
            *entry = fact;
        }
    }
    let health_facts: Vec<_> = latest.into_values().collect();

    (StatusCode::OK, axum::Json(serde_json::json!({
        "health": health_facts,
    }))).into_response()
}

#[derive(serde::Deserialize)]
struct BootstrapPullBody {
    query: String,
    #[serde(default = "default_bootstrap_top_k")]
    top_k: usize,
    token_budget: Option<usize>,
}

fn default_bootstrap_top_k() -> usize {
    10
}

async fn post_bootstrap_pull(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BootstrapPullBody>,
) -> impl IntoResponse {
    if let Err(_) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    if !is_observe_enabled() {
        return observe_not_enabled_response();
    }
    let gate = crux_observe::cold_gate::ColdGate::new(state.fact_store.clone());
    let result = gate.pull(&body.query, body.top_k, body.token_budget).await;
    (StatusCode::OK, axum::Json(serde_json::json!({
        "facts": result.facts,
        "total_tokens": result.total_tokens,
        "source": result.source,
    }))).into_response()
}

async fn get_bootstrap_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(_) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    if !is_observe_enabled() {
        return observe_not_enabled_response();
    }
    let seeder = crux_observe::bootstrap::BootstrapSeeder::new(state.fact_store.clone());
    let status = seeder.status().await;
    (StatusCode::OK, axum::Json(serde_json::json!({
        "seeded": status.seeded,
        "fact_count": status.fact_count,
        "categories": status.categories,
        "last_seed_at": status.last_seed_at,
    }))).into_response()
}

fn is_query_feature_enabled(env_var: &str) -> bool {
    std::env::var(env_var)
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[tracing::instrument(level = "info", skip(state, headers), fields(shard_id = %q.shard_id))]
async fn get_proj_meta(
    State(state): State<AppState>,
    Query(q): Query<ProjMetaQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };
    let shard_id_u32 = match parse_shard_id_u32(&q.shard_id) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let (_owner_gpu_id, store) = match pool.store_for_shard_id(&q.shard_id).await {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let guard = store.read().await;
    let meta = guard.projections_meta_for_shard(shard_id_u32);
    match meta {
        Some(m) => (StatusCode::OK, Json(m)).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, "projection meta not found"),
    }
}

/// Online projection rebuild — uses daemon-held shard handles, no downtime.
/// POST /v1/admin/projections/rebuild
#[tracing::instrument(level = "info", skip(state, headers))]
async fn post_projection_rebuild(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let results = pool.rebuild_projections_online(1024).await;
    let mut shards = Vec::new();
    let mut any_failed = false;
    for (shard_label, result) in results {
        match result {
            Ok(r) => {
                shards.push(serde_json::json!({
                    "shard": shard_label,
                    "status": "ok",
                    "frames_processed": r.frames_processed,
                    "commit_id": r.commit_id,
                    "living_rows": r.state_counts.living_rows,
                    "relations_edges": r.state_counts.relations_edges,
                }));
            }
            Err(err) => {
                any_failed = true;
                shards.push(serde_json::json!({
                    "shard": shard_label,
                    "status": "error",
                    "error": err,
                }));
            }
        }
    }

    let status = if any_failed {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    };
    (status, Json(serde_json::json!({ "shards": shards }))).into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(artifact_id, tenant_id = %q.tenant_id))]
async fn get_proj_artifact_state(
    State(state): State<AppState>,
    Path(artifact_id): Path<u32>,
    Query(q): Query<TenantQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let stream_hash = match stream_hash_xxhash64(&q.tenant_id, "artifact", &artifact_id.to_string())
    {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let (decision, store) = match pool.store_for_stream_hash(stream_hash, None).await {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let shard_id_u32 = match parse_shard_id_u32(&decision.shard_id) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let guard = store.read().await;
    let row = guard.projections_living_state_row(shard_id_u32, &q.tenant_id, artifact_id);

    #[derive(serde::Serialize)]
    struct Resp {
        tenant_id: String,
        artifact_id: u32,
        present: bool,
        living_status: Option<String>,
        confidence: Option<f32>,
        last_validated_at_micros: Option<i64>,
        next_review_at_micros: Option<i64>,
        pressure_level: Option<u8>,
        pressure_reasons_mask: Option<u32>,
        trunk_tier: Option<u8>,
        counts: Option<Counts>,
        updated_at_micros: Option<i64>,
    }
    #[derive(serde::Serialize)]
    struct Counts {
        relations_out: i32,
        relations_in: i32,
        dependents: i32,
    }

    if let Some(row) = row {
        return (
            StatusCode::OK,
            Json(Resp {
                tenant_id: q.tenant_id,
                artifact_id,
                present: true,
                living_status: Some(row.living_status.as_engine_str().to_string()),
                confidence: Some(corecrux_projections::dequantize_confidence_f32(
                    row.confidence_q16,
                )),
                last_validated_at_micros: Some(row.last_validated_at_micros),
                next_review_at_micros: Some(row.next_review_at_micros),
                pressure_level: Some(row.pressure_level),
                pressure_reasons_mask: Some(row.pressure_reasons_mask),
                trunk_tier: Some(row.trunk_tier),
                counts: Some(Counts {
                    relations_out: row.relations_out_count,
                    relations_in: row.relations_in_count,
                    dependents: row.dependents_count,
                }),
                updated_at_micros: Some(row.updated_at_micros),
            }),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(Resp {
            tenant_id: q.tenant_id,
            artifact_id,
            present: false,
            living_status: None,
            confidence: None,
            last_validated_at_micros: None,
            next_review_at_micros: None,
            pressure_level: None,
            pressure_reasons_mask: None,
            trunk_tier: None,
            counts: None,
            updated_at_micros: None,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(artifact_id, tenant_id = %q.tenant_id))]
async fn get_proj_artifact_relations(
    State(state): State<AppState>,
    Path(artifact_id): Path<u32>,
    Query(q): Query<RelationsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };
    let tenant_id = q.tenant_id.clone();
    let direction = q.direction.as_deref().unwrap_or("out");
    let relation_type_u8 = q
        .relation_type
        .as_deref()
        .and_then(|s| corecrux_projections::RelationTypeV1::from_engine_str(s).map(|t| t.to_u8()));
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0);

    let stream_hash = match stream_hash_xxhash64(&tenant_id, "artifact", &artifact_id.to_string()) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let (decision, store) = match pool.store_for_stream_hash(stream_hash, None).await {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let shard_id_u32 = match parse_shard_id_u32(&decision.shard_id) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let guard = store.read().await;
    let rows = guard.projections_list_relations(
        shard_id_u32,
        &tenant_id,
        artifact_id,
        direction,
        relation_type_u8,
        limit,
        offset,
    );

    #[derive(serde::Serialize)]
    struct Resp {
        tenant_id: String,
        artifact_id: u32,
        direction: String,
        relations: Vec<Rel>,
        page: Page,
    }
    #[derive(serde::Serialize)]
    struct Rel {
        src_artifact_id: u32,
        dst_artifact_id: u32,
        relation_type: String,
        confidence: f32,
        evidence_ref_hash16: String,
        created_at_micros: i64,
        updated_at_micros: i64,
    }
    #[derive(serde::Serialize)]
    struct Page {
        limit: usize,
        offset: usize,
        next_offset: usize,
    }

    let rels = rows
        .into_iter()
        .map(|r| {
            let rt = corecrux_projections::RelationTypeV1::from_u8(r.relation_type)
                .map(|t| t.as_engine_str().to_string())
                .unwrap_or_else(|| format!("unknown({})", r.relation_type));
            Rel {
                src_artifact_id: r.src_artifact_id,
                dst_artifact_id: r.dst_artifact_id,
                relation_type: rt,
                confidence: corecrux_projections::dequantize_confidence_f32(r.confidence_q16),
                evidence_ref_hash16: hex16(&r.evidence_ref_hash16),
                created_at_micros: r.created_at_micros,
                updated_at_micros: r.updated_at_micros,
            }
        })
        .collect();

    (
        StatusCode::OK,
        Json(Resp {
            tenant_id,
            artifact_id,
            direction: direction.to_string(),
            relations: rels,
            page: Page {
                limit,
                offset,
                next_offset: offset + limit,
            },
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%artifact_id, tenant_id = %q.tenant_id))]
async fn get_proj_artifact_dependents(
    State(state): State<AppState>,
    Path(artifact_id): Path<u32>,
    Query(q): Query<DependentsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };
    let tenant_id = q.tenant_id.clone();
    let dt_u8 = q
        .dependent_type
        .as_deref()
        .and_then(|s| corecrux_projections::DependentTypeV1::from_engine_str(s).map(|t| t.to_u8()));
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0);

    let stream_hash = match stream_hash_xxhash64(&tenant_id, "artifact", &artifact_id.to_string()) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let (decision, store) = match pool.store_for_stream_hash(stream_hash, None).await {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let shard_id_u32 = match parse_shard_id_u32(&decision.shard_id) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let guard = store.read().await;
    let rows = guard.projections_list_dependents(
        shard_id_u32,
        &tenant_id,
        artifact_id,
        dt_u8,
        limit,
        offset,
    );

    #[derive(serde::Serialize)]
    struct Resp {
        tenant_id: String,
        artifact_id: u32,
        dependents: Vec<Dep>,
        page: Page,
    }
    #[derive(serde::Serialize)]
    struct Dep {
        dependent_type: String,
        dependent_id: String,
        last_seen_at_micros: i64,
        usage_weight: f32,
    }
    #[derive(serde::Serialize)]
    struct Page {
        limit: usize,
        offset: usize,
        next_offset: usize,
    }

    let dependents = rows
        .into_iter()
        .map(|r| Dep {
            dependent_type: corecrux_projections::DependentTypeV1::from_u8(r.dependent_type)
                .map(|t| t.as_engine_str().to_string())
                .unwrap_or_else(|| format!("unknown({})", r.dependent_type)),
            dependent_id: r.dependent_id,
            last_seen_at_micros: r.last_seen_at_micros,
            usage_weight: corecrux_projections::dequantize_confidence_f32(r.usage_weight_q16),
        })
        .collect();

    (
        StatusCode::OK,
        Json(Resp {
            tenant_id,
            artifact_id,
            dependents,
            page: Page {
                limit,
                offset,
                next_offset: offset + limit,
            },
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%artifact_id, tenant_id = %q.tenant_id))]
async fn get_proj_artifact_pressure_events(
    State(state): State<AppState>,
    Path(artifact_id): Path<u32>,
    Query(q): Query<PressureQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };
    let tenant_id = q.tenant_id.clone();
    let open_only = q.open_only.unwrap_or(false);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0);

    let stream_hash = match stream_hash_xxhash64(&tenant_id, "artifact", &artifact_id.to_string()) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let (decision, store) = match pool.store_for_stream_hash(stream_hash, None).await {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let shard_id_u32 = match parse_shard_id_u32(&decision.shard_id) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let guard = store.read().await;
    let rows = guard.projections_list_pressure_events(
        shard_id_u32,
        &tenant_id,
        artifact_id,
        open_only,
        limit,
        offset,
    );

    #[derive(serde::Serialize)]
    struct Resp {
        tenant_id: String,
        artifact_id: u32,
        open_only: bool,
        events: Vec<Ev>,
        page: Page,
    }
    #[derive(serde::Serialize)]
    struct Ev {
        event_id: String,
        pressure_code_id: u16,
        severity: u8,
        observed_at_micros: i64,
        acknowledged_at_micros: i64,
        resolved_at_micros: i64,
        receipt_id: Option<String>,
    }
    #[derive(serde::Serialize)]
    struct Page {
        limit: usize,
        offset: usize,
        next_offset: usize,
    }

    let events = rows
        .into_iter()
        .map(|r| Ev {
            event_id: r.event_id.to_string(),
            pressure_code_id: r.pressure_code_id,
            severity: r.severity,
            observed_at_micros: r.observed_at_micros,
            acknowledged_at_micros: r.acknowledged_at_micros,
            resolved_at_micros: r.resolved_at_micros,
            receipt_id: r.receipt_id.map(|u| u.to_string()),
        })
        .collect();

    (
        StatusCode::OK,
        Json(Resp {
            tenant_id,
            artifact_id,
            open_only,
            events,
            page: Page {
                limit,
                offset,
                next_offset: offset + limit,
            },
        }),
    )
        .into_response()
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

async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let _ = state.commit_level;
    let routing = state.routing.read().await.clone();
    let control_state = state.control.read().await.clone();
    let body = HealthzResponse {
        ok: true,
        build: state.build.clone(),
        compat: state.compat.clone(),
        sdk_version: state.sdk_version.clone(),
        routing: Some(RoutingInfo {
            shard_map_version: routing.current_version(),
            shard_count: routing.shard_count() as u64,
            last_reload_at: Some(routing.loaded_at),
            node_id: state.node_id.clone(),
        }),
        valves: Some(ValvesInfo {
            pause_ingest: to_valve_info(&control_state.valves.pause_ingest),
            pause_compaction: to_valve_info(&control_state.valves.pause_compaction),
            throttle: to_valve_info(&control_state.valves.throttle),
            read_only: to_valve_info(&control_state.valves.read_only),
            emergency_brake: to_valve_info(&control_state.valves.emergency_brake),
        }),
    };
    (StatusCode::OK, Json(body))
}

#[derive(serde::Serialize)]
struct ReadyOk {
    ok: bool,
}

#[derive(serde::Serialize)]
struct ReadyCheck {
    name: &'static str,
    ok: bool,
    error: Option<String>,
}

#[derive(serde::Serialize)]
struct ReadyFail {
    ok: bool,
    checks: Vec<ReadyCheck>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AdminActionStatus {
    Submitted,
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AdminActionRecord {
    #[serde(rename = "actionId")]
    action_id: String,
    #[serde(rename = "actionType")]
    action_type: String,
    status: AdminActionStatus,
    #[serde(rename = "submittedAtUnixMs")]
    submitted_at_unix_ms: u64,
    #[serde(rename = "startedAtUnixMs", skip_serializing_if = "Option::is_none")]
    started_at_unix_ms: Option<u64>,
    #[serde(rename = "finishedAtUnixMs", skip_serializing_if = "Option::is_none")]
    finished_at_unix_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip)]
    auth_context: Option<EvidenceAuthContextV1>,
    #[serde(skip)]
    request_context: Option<EvidenceRequestContextV1>,
}

#[derive(Debug, serde::Deserialize)]
struct PostAdminActionRequest {
    #[serde(rename = "actionId")]
    action_id: Option<String>,
    #[serde(rename = "actionType")]
    action_type: String,
    actor: Option<String>,
    reason: Option<String>,
    params: Option<serde_json::Value>,
}

#[derive(Debug, serde::Serialize)]
struct PostAdminActionResponse {
    accepted: bool,
    action: AdminActionRecord,
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

fn is_known_admin_action(ty: &str) -> bool {
    matches!(
        ty,
        "verify-store"
            | "scrub-now"
            | "snapshot-verify"
            | "projection-rebuild"
            | "parity-pack"
            | "runtime-knob-update"
            | "force-seal"
    )
}

fn read_param_str<'a>(params: Option<&'a serde_json::Value>, key: &str) -> Option<&'a str> {
    params
        .and_then(|v| v.get(key))
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
}

fn read_param_bool(params: Option<&serde_json::Value>, key: &str) -> Option<bool> {
    params.and_then(|v| v.get(key)).and_then(|v| {
        if let Some(b) = v.as_bool() {
            Some(b)
        } else if let Some(s) = v.as_str() {
            match s.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "y" => Some(true),
                "0" | "false" | "no" | "n" => Some(false),
                _ => None,
            }
        } else {
            None
        }
    })
}

fn read_param_u64(params: Option<&serde_json::Value>, key: &str) -> Option<u64> {
    params.and_then(|v| v.get(key)).and_then(|v| {
        if let Some(n) = v.as_u64() {
            Some(n)
        } else {
            v.as_str().and_then(|s| s.parse::<u64>().ok())
        }
    })
}

fn read_param_u32(params: Option<&serde_json::Value>, key: &str) -> Option<u32> {
    read_param_u64(params, key).and_then(|v| u32::try_from(v).ok())
}

fn read_param_f64(params: Option<&serde_json::Value>, key: &str) -> Option<f64> {
    params.and_then(|v| v.get(key)).and_then(|v| {
        if let Some(n) = v.as_f64() {
            Some(n)
        } else {
            v.as_str().and_then(|s| s.parse::<f64>().ok())
        }
    })
}

fn parse_tenant_throttle_rules(
    value: &serde_json::Value,
) -> Result<Vec<control::TenantThrottleV1>, String> {
    let rules: Vec<control::TenantThrottleV1> =
        serde_json::from_value(value.clone()).map_err(|e| {
            format!("tenantThrottleRules must be an array of tenant throttle objects: {e}")
        })?;
    for rule in &rules {
        if rule.tenant_id.trim().is_empty() {
            return Err("tenantThrottleRules entries require non-empty tenantId".to_string());
        }
    }
    Ok(rules)
}

fn admin_action_error(detail: impl Into<String>) -> String {
    detail.into()
}

fn parse_knowledge_authority_mode(value: &str) -> Option<KnowledgeAuthorityModeV1> {
    match value.trim() {
        "knowledge_shadow" | "shadow" => Some(KnowledgeAuthorityModeV1::Shadow),
        "knowledge_dual_write" | "dual_write" => Some(KnowledgeAuthorityModeV1::DualWrite),
        "knowledge_shadow_read" | "shadow_read" => Some(KnowledgeAuthorityModeV1::ShadowRead),
        "knowledge_authoritative" | "authoritative" => {
            Some(KnowledgeAuthorityModeV1::Authoritative)
        }
        _ => None,
    }
}

fn parse_knowledge_rollout_stage(value: &str) -> Option<KnowledgeRolloutStageV1> {
    match value.trim() {
        "internal_shadow" | "shadow" => Some(KnowledgeRolloutStageV1::InternalShadow),
        "tenant_validation" => Some(KnowledgeRolloutStageV1::TenantValidation),
        "internal_authority" => Some(KnowledgeRolloutStageV1::InternalAuthority),
        "limited_production_authority" => Some(KnowledgeRolloutStageV1::LimitedProductionAuthority),
        "full_production_authority" => Some(KnowledgeRolloutStageV1::FullProductionAuthority),
        _ => None,
    }
}

fn parse_knowledge_parity_status(value: &str) -> Option<KnowledgeParityStatusV1> {
    match value.trim() {
        "unknown" => Some(KnowledgeParityStatusV1::Unknown),
        "pass" => Some(KnowledgeParityStatusV1::Pass),
        "warn" => Some(KnowledgeParityStatusV1::Warn),
        "fail" => Some(KnowledgeParityStatusV1::Fail),
        _ => None,
    }
}

#[derive(Debug)]
struct AdminActionExecutionResult {
    result: serde_json::Value,
    mutation_event_id: Option<String>,
}

fn trace_id_from_traceparent(traceparent: Option<&str>) -> Option<String> {
    let traceparent = traceparent?;
    let mut parts = traceparent.split('-');
    let _version = parts.next()?;
    let trace_id = parts.next()?;
    if trace_id.len() == 32 && trace_id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(trace_id.to_string())
    } else {
        None
    }
}

fn evidence_request_context_from_headers(headers: &HeaderMap) -> EvidenceRequestContextV1 {
    let correlation = CorrelationIds::from_headers(headers);
    EvidenceRequestContextV1 {
        request_id: correlation.request_id,
        trace_id: trace_id_from_traceparent(correlation.traceparent.as_deref()),
        traceparent: correlation.traceparent,
    }
}

fn evidence_node_context(state: &AppState) -> EvidenceNodeContextV1 {
    EvidenceNodeContextV1 {
        node_id: state.node_id.clone(),
        build: state.build.clone(),
        http_listen_addr: None,
        grpc_listen_addr: None,
    }
}

fn submitted_event_id(action_id: &str) -> String {
    format!("{EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1}:{action_id}")
}

fn finished_event_id(action_id: &str, status: &str) -> String {
    format!("{EVT_CONTROL_ADMIN_ACTION_FINISHED_V1}:{action_id}:{status}")
}

fn mutation_event_id(action_id: &str, control_after_hash: &str) -> String {
    let hash_prefix = control_after_hash.get(0..16).unwrap_or(control_after_hash);
    format!("{EVT_CONTROL_STATE_MUTATION_V1}:{action_id}:{hash_prefix}")
}

fn checkpoint_id(action_id: &str, control_hash: &str) -> String {
    let hash_prefix = control_hash.get(0..16).unwrap_or(control_hash);
    format!("checkpoint:{action_id}:{hash_prefix}")
}

fn checkpoint_event_id(checkpoint_id: &str) -> String {
    format!("{EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1}:{checkpoint_id}")
}

async fn append_control_evidence_event<T: serde::Serialize>(
    state: &AppState,
    event_type: &str,
    event_id: String,
    payload: &T,
) -> Result<bool, String> {
    let Some(pool) = state.dataplane_pool.clone() else {
        tracing::warn!(
            event_type = %event_type,
            event_id = %event_id,
            "control evidence skipped because dataplane is disabled"
        );
        return Ok(false);
    };

    let payload_bytes = serde_json::to_vec(payload)
        .map_err(|e| format!("failed to serialize control evidence payload: {e}"))?;
    let event = AppendEvent {
        event_id,
        occurred_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        event_type: event_type.to_string(),
        content_type: CONTROL_EVIDENCE_CONTENT_TYPE_V1.to_string(),
        payload: payload_bytes,
    };
    let (_decision, store) = pool
        .store_for_stream("system", "corecrux", "control", None)
        .await
        .map_err(|e| format!("failed to route control evidence append: {e}"))?;
    let store = store.read().await;
    let _ = store
        .append_batch("system", "corecrux", "control", 0, None, &[event])
        .await
        .map_err(|e| format!("failed to append control evidence event: {e}"))?;
    Ok(true)
}

fn build_admin_action_submitted_event(
    state: &AppState,
    action_id: &str,
    action_type: &str,
    submitted_at_unix_ms: u64,
    actor: Option<String>,
    reason: Option<String>,
    params: Option<serde_json::Value>,
    auth_context: EvidenceAuthContextV1,
    request_context: EvidenceRequestContextV1,
) -> ControlAdminActionSubmittedV1 {
    ControlAdminActionSubmittedV1 {
        schema: EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1.to_string(),
        action_id: action_id.to_string(),
        action_type: action_type.to_string(),
        submitted_at_unix_ms,
        actor,
        reason,
        params,
        auth: auth_context,
        request: request_context,
        node: evidence_node_context(state),
    }
}

fn build_control_mutation_event(
    state: &AppState,
    action_id: &str,
    mutation_type: &str,
    actor: &str,
    reason: &str,
    auth_context: EvidenceAuthContextV1,
    request_context: EvidenceRequestContextV1,
    before: &control::ControlV1,
    after: &control::ControlV1,
    result: serde_json::Value,
) -> ControlStateMutationV1 {
    ControlStateMutationV1 {
        schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
        action_id: action_id.to_string(),
        mutation_type: mutation_type.to_string(),
        applied_at_unix_ms: now_unix_ms(),
        actor: actor.to_string(),
        reason: reason.to_string(),
        auth: auth_context,
        request: request_context,
        node: evidence_node_context(state),
        control_before: control::control_state_digest_v1(before),
        control_after: control::control_state_digest_v1(after),
        valve_changes: control::valve_changes_v1(before, after),
        knowledge_authority_change: control::knowledge_authority_change_v1(before, after),
        result: Some(result),
    }
}

fn build_admin_action_finished_event(
    state: &AppState,
    action_id: &str,
    action_type: &str,
    status: &str,
    started_at_unix_ms: Option<u64>,
    finished_at_unix_ms: u64,
    mutation_event_id: Option<String>,
    result: Option<serde_json::Value>,
    error: Option<String>,
) -> ControlAdminActionFinishedV1 {
    ControlAdminActionFinishedV1 {
        schema: EVT_CONTROL_ADMIN_ACTION_FINISHED_V1.to_string(),
        action_id: action_id.to_string(),
        action_type: action_type.to_string(),
        status: status.to_string(),
        started_at_unix_ms,
        finished_at_unix_ms,
        mutation_event_id,
        result,
        error,
        node: evidence_node_context(state),
    }
}

fn build_control_checkpoint_materialized_event(
    state: &AppState,
    checkpoint_id: &str,
    control_state: &control::ControlV1,
) -> ControlCheckpointMaterializedV1 {
    let checkpoint_bytes = control::checkpoint_control_bytes_v1(control_state);
    ControlCheckpointMaterializedV1 {
        schema: EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1.to_string(),
        checkpoint_id: checkpoint_id.to_string(),
        materialized_at_unix_ms: now_unix_ms(),
        node: evidence_node_context(state),
        control_state: control::control_state_digest_v1(control_state),
        checkpoint_format: "control.json.pretty.v1".to_string(),
        checkpoint_blake3: blake3::hash(&checkpoint_bytes).to_hex().to_string(),
        checkpoint_size_bytes: checkpoint_bytes.len() as u64,
    }
}

async fn append_control_checkpoint_materialized_event(
    state: &AppState,
    action_id: &str,
    control_state: &control::ControlV1,
) -> Result<(), String> {
    let control_hash = control::control_hash_blake3_hex(control_state);
    let checkpoint_id = checkpoint_id(action_id, &control_hash);
    let payload = build_control_checkpoint_materialized_event(state, &checkpoint_id, control_state);
    append_control_evidence_event(
        state,
        EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1,
        checkpoint_event_id(&checkpoint_id),
        &payload,
    )
    .await?;
    Ok(())
}

fn append_control_event_warning(action_id: &str, event_type: &str, err: &str) {
    tracing::warn!(
        action_id = %action_id,
        event_type = %event_type,
        error = %err,
        "failed to append control evidence event"
    );
}

fn sync_control_metrics(metrics: &Metrics, control: &control::ControlV1) {
    metrics.set_valve_pause_ingest(control.valves.pause_ingest.enabled);
    metrics.set_valve_pause_compaction(control.valves.pause_compaction.enabled);
    metrics.set_valve_throttle(control.valves.throttle.enabled);
    metrics.set_valve_read_only(control.valves.read_only.enabled);
    metrics.set_valve_emergency_brake(control.valves.emergency_brake.enabled);

    metrics.set_valve_state("pause_ingest", control.valves.pause_ingest.enabled);
    metrics.set_valve_state("pause_compaction", control.valves.pause_compaction.enabled);
    metrics.set_valve_state("throttle", control.valves.throttle.enabled);
    metrics.set_valve_state("read_only", control.valves.read_only.enabled);
    metrics.set_valve_state("emergency_brake", control.valves.emergency_brake.enabled);
    metrics.sync_knowledge_authority(&control.knowledge_authority);
    metrics.set_throttle_ratio(1.0);
}

async fn execute_admin_action(
    state: &AppState,
    action_id: &str,
    action_type: &str,
    params: Option<&serde_json::Value>,
    auth_context: Option<&EvidenceAuthContextV1>,
    request_context: Option<&EvidenceRequestContextV1>,
) -> Result<AdminActionExecutionResult, String> {
    match action_type {
        "verify-store" => {
            let started = std::time::Instant::now();
            let scope = read_param_str(params, "scope").unwrap_or("recent");
            let mode = read_param_str(params, "mode").unwrap_or("sampled");
            let full = read_param_bool(params, "full").unwrap_or_else(|| {
                mode.eq_ignore_ascii_case("full") || scope.eq_ignore_ascii_case("all")
            });
            let sample_rate = read_param_f64(params, "sampleRate")
                .or_else(|| read_param_f64(params, "sample_rate"))
                .unwrap_or(if full { 1.0 } else { 0.25 })
                .clamp(0.0, 1.0);
            let budget_bytes = read_param_u64(params, "budgetBytes")
                .or_else(|| read_param_u64(params, "budget_bytes"))
                .unwrap_or(8 * 1024 * 1024) as usize;
            let pool = state
                .dataplane_pool
                .as_ref()
                .ok_or_else(|| admin_action_error("dataplane disabled"))?;
            let summary = pool
                .verify_store_integrity_all(full, sample_rate, budget_bytes, false)
                .await;
            if !summary.ok {
                *state.corruption_detected.write().await = true;
            }
            let mut op_log = StructuredOpLog::new(
                if summary.ok { "info" } else { "warn" },
                "verify_store",
                if summary.ok { "ok" } else { "fail" },
                started.elapsed().as_millis() as u64,
            );
            if !summary.ok {
                op_log.error_code = Some(ErrorCode::SegmentCorrupt.as_str().to_string());
            }
            tracing::info!(
                ts = %op_log.ts,
                level = %op_log.level,
                op = %op_log.op,
                outcome = %op_log.outcome,
                took_ms = op_log.took_ms,
                error_code = ?op_log.error_code,
                "admin verify-store completed"
            );
            Ok(AdminActionExecutionResult {
                result: serde_json::json!({
                "ok": summary.ok,
                "scope": scope,
                "mode": if full { "full" } else { "sampled" },
                "sampleRate": sample_rate,
                "summary": summary
                }),
                mutation_event_id: None,
            })
        }
        "scrub-now" => {
            let started = std::time::Instant::now();
            let scope = read_param_str(params, "scope")
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| state.scrub_scope.clone());
            let mode = read_param_str(params, "mode")
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| state.scrub_mode.clone());
            let full = read_param_bool(params, "full").unwrap_or_else(|| {
                mode.eq_ignore_ascii_case("full") || scope.eq_ignore_ascii_case("all")
            });
            let sample_rate = read_param_f64(params, "sampleRate")
                .or_else(|| read_param_f64(params, "sample_rate"))
                .unwrap_or(state.scrub_sample_rate)
                .clamp(0.0, 1.0);
            let budget_bytes = read_param_u64(params, "budgetBytes")
                .or_else(|| read_param_u64(params, "budget_bytes"))
                .unwrap_or(8 * 1024 * 1024) as usize;
            let pool = state
                .dataplane_pool
                .as_ref()
                .ok_or_else(|| admin_action_error("dataplane disabled"))?;
            let summary = pool
                .verify_store_integrity_all(full, sample_rate, budget_bytes, true)
                .await;
            if !summary.ok {
                *state.corruption_detected.write().await = true;
            }
            let mut op_log = StructuredOpLog::new(
                if summary.ok { "info" } else { "warn" },
                "scrub",
                if summary.ok { "ok" } else { "fail" },
                started.elapsed().as_millis() as u64,
            );
            if !summary.ok {
                op_log.error_code = Some(ErrorCode::SegmentCorrupt.as_str().to_string());
            }
            tracing::info!(
                ts = %op_log.ts,
                level = %op_log.level,
                op = %op_log.op,
                outcome = %op_log.outcome,
                took_ms = op_log.took_ms,
                error_code = ?op_log.error_code,
                "admin scrub-now completed"
            );
            Ok(AdminActionExecutionResult {
                result: serde_json::json!({
                "ok": summary.ok,
                "scope": scope,
                "mode": if full { "full" } else { "sampled" },
                "sampleRate": sample_rate,
                "summary": summary
                }),
                mutation_event_id: None,
            })
        }
        "snapshot-verify" => {
            let started = std::time::Instant::now();
            let pool = state
                .dataplane_pool
                .as_ref()
                .ok_or_else(|| admin_action_error("dataplane disabled"))?;
            let issues = pool.projection_snapshot_issues().await;
            let mut op_log = StructuredOpLog::new(
                if issues.is_empty() { "info" } else { "warn" },
                "snapshot_verify",
                if issues.is_empty() { "ok" } else { "fail" },
                started.elapsed().as_millis() as u64,
            );
            if !issues.is_empty() {
                op_log.error_code = Some(ErrorCode::InvalidToc.as_str().to_string());
            }
            tracing::info!(
                ts = %op_log.ts,
                level = %op_log.level,
                op = %op_log.op,
                outcome = %op_log.outcome,
                took_ms = op_log.took_ms,
                error_code = ?op_log.error_code,
                issue_count = issues.len(),
                "admin snapshot-verify completed"
            );
            Ok(AdminActionExecutionResult {
                result: serde_json::json!({
                "ok": issues.is_empty(),
                "issueCount": issues.len(),
                "issues": issues
                }),
                mutation_event_id: None,
            })
        }
        "projection-rebuild" => {
            let max_frames = read_param_u64(params, "maxFrames")
                .or_else(|| read_param_u64(params, "max_frames"))
                .unwrap_or(2048)
                .clamp(1, 65_536) as u32;
            let pool = state
                .dataplane_pool
                .as_ref()
                .ok_or_else(|| admin_action_error("dataplane disabled"))?;
            pool.tick_projections_all(max_frames).await;
            Ok(AdminActionExecutionResult {
                result: serde_json::json!({
                "ok": true,
                "maxFrames": max_frames
                }),
                mutation_event_id: None,
            })
        }
        "runtime-knob-update" => {
            let actor = read_param_str(params, "actor")
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| "admin-action-runtime-knob-update".to_string());
            let reason = read_param_str(params, "reason")
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| "runtime knob update action".to_string());
            let now = control::now_unix_ns();

            let mut control_state = state.control.write().await;
            let before = control_state.clone();
            let mut changed = false;

            let throttle_enabled = read_param_bool(params, "throttleEnabled")
                .or_else(|| read_param_bool(params, "enabled"));
            if let Some(enabled) = throttle_enabled {
                control_state
                    .valves
                    .throttle
                    .set(enabled, &actor, &reason, now);
                changed = true;
            }

            let events_per_sec = read_param_u64(params, "throttleEventsPerSec")
                .or_else(|| read_param_u64(params, "eventsPerSec"))
                .or(control_state.valves.throttle.events_per_sec);
            let bytes_per_sec = read_param_u64(params, "throttleBytesPerSec")
                .or_else(|| read_param_u64(params, "bytesPerSec"))
                .or(control_state.valves.throttle.bytes_per_sec);
            let max_in_flight = read_param_u64(params, "throttleMaxInFlight")
                .or_else(|| read_param_u64(params, "maxInFlight"))
                .and_then(|v| u32::try_from(v).ok())
                .or(control_state.valves.throttle.max_in_flight);
            if events_per_sec != control_state.valves.throttle.events_per_sec
                || bytes_per_sec != control_state.valves.throttle.bytes_per_sec
                || max_in_flight != control_state.valves.throttle.max_in_flight
            {
                control_state.valves.throttle.set_throttle_params(
                    events_per_sec,
                    bytes_per_sec,
                    max_in_flight,
                );
                changed = true;
            }

            let retry_after_ms = read_param_u64(params, "throttleRetryAfterMs")
                .or_else(|| read_param_u64(params, "retryAfterMs"))
                .and_then(|v| u32::try_from(v).ok());
            if retry_after_ms.is_some() {
                control_state
                    .valves
                    .throttle
                    .set_retry_after_ms(retry_after_ms);
                changed = true;
            }

            if let Some(raw_rules) = params
                .and_then(|value| value.get("tenantThrottleRules"))
                .or_else(|| params.and_then(|value| value.get("tenant_throttle_rules")))
            {
                let parsed = parse_tenant_throttle_rules(raw_rules).map_err(admin_action_error)?;
                if control_state.tenant_throttles != parsed {
                    control_state.tenant_throttles = parsed;
                    changed = true;
                }
            }

            let mut knowledge_authority_changed = false;

            if let Some(mode) = read_param_str(params, "knowledgeAuthorityMode")
                .or_else(|| read_param_str(params, "knowledge_authority_mode"))
            {
                let parsed = parse_knowledge_authority_mode(mode).ok_or_else(|| {
                    admin_action_error(format!("invalid knowledgeAuthorityMode '{mode}'"))
                })?;
                if control_state.knowledge_authority.mode != parsed {
                    control_state.knowledge_authority.mode = parsed;
                    knowledge_authority_changed = true;
                }
            }

            if let Some(stage) = read_param_str(params, "knowledgeAuthorityRolloutStage")
                .or_else(|| read_param_str(params, "knowledge_authority_rollout_stage"))
            {
                let parsed = parse_knowledge_rollout_stage(stage).ok_or_else(|| {
                    admin_action_error(format!("invalid knowledgeAuthorityRolloutStage '{stage}'"))
                })?;
                if control_state.knowledge_authority.rollout_stage != parsed {
                    control_state.knowledge_authority.rollout_stage = parsed;
                    knowledge_authority_changed = true;
                }
            }

            if let Some(value) = read_param_u64(params, "knowledgeMaxMismatchCount")
                .or_else(|| read_param_u64(params, "knowledge_max_mismatch_count"))
            {
                if control_state
                    .knowledge_authority
                    .parity_thresholds
                    .max_mismatch_count
                    != value
                {
                    control_state
                        .knowledge_authority
                        .parity_thresholds
                        .max_mismatch_count = value;
                    knowledge_authority_changed = true;
                }
            }

            if let Some(value) = read_param_u64(params, "knowledgeMaxCursorMissingCount")
                .or_else(|| read_param_u64(params, "knowledge_max_cursor_missing_count"))
            {
                if control_state
                    .knowledge_authority
                    .parity_thresholds
                    .max_cursor_missing_count
                    != value
                {
                    control_state
                        .knowledge_authority
                        .parity_thresholds
                        .max_cursor_missing_count = value;
                    knowledge_authority_changed = true;
                }
            }

            if let Some(value) = read_param_u32(params, "knowledgeMinPassRatioBps")
                .or_else(|| read_param_u32(params, "knowledge_min_pass_ratio_bps"))
            {
                if control_state
                    .knowledge_authority
                    .parity_thresholds
                    .min_pass_ratio_bps
                    != value
                {
                    control_state
                        .knowledge_authority
                        .parity_thresholds
                        .min_pass_ratio_bps = value;
                    knowledge_authority_changed = true;
                }
            }

            if let Some(value) = read_param_u64(params, "knowledgeMaxProjectionLagMs")
                .or_else(|| read_param_u64(params, "knowledge_max_projection_lag_ms"))
            {
                if control_state
                    .knowledge_authority
                    .lag_thresholds
                    .max_projection_lag_ms
                    != value
                {
                    control_state
                        .knowledge_authority
                        .lag_thresholds
                        .max_projection_lag_ms = value;
                    knowledge_authority_changed = true;
                }
            }

            if let Some(value) = read_param_u64(params, "knowledgeMaxCursorAgeMs")
                .or_else(|| read_param_u64(params, "knowledge_max_cursor_age_ms"))
            {
                if control_state
                    .knowledge_authority
                    .lag_thresholds
                    .max_cursor_age_ms
                    != value
                {
                    control_state
                        .knowledge_authority
                        .lag_thresholds
                        .max_cursor_age_ms = value;
                    knowledge_authority_changed = true;
                }
            }

            if let Some(value) = read_param_bool(params, "knowledgeRollbackTriggered")
                .or_else(|| read_param_bool(params, "knowledge_rollback_triggered"))
            {
                if control_state.knowledge_authority.rollback_triggered != value {
                    control_state.knowledge_authority.rollback_triggered = value;
                    knowledge_authority_changed = true;
                }
            }

            if read_param_bool(params, "knowledgeClearParityOutcome")
                .or_else(|| read_param_bool(params, "knowledge_clear_parity_outcome"))
                .unwrap_or(false)
            {
                if control_state
                    .knowledge_authority
                    .last_parity_outcome
                    .is_some()
                {
                    control_state.knowledge_authority.last_parity_outcome = None;
                    knowledge_authority_changed = true;
                }
            } else {
                let parity_status = read_param_str(params, "knowledgeLastParityStatus")
                    .or_else(|| read_param_str(params, "knowledge_last_parity_status"))
                    .map(|value| {
                        parse_knowledge_parity_status(value).ok_or_else(|| {
                            admin_action_error(format!(
                                "invalid knowledgeLastParityStatus '{value}'"
                            ))
                        })
                    })
                    .transpose()?;
                let parity_checked_at =
                    read_param_u64(params, "knowledgeLastParityCheckedAtUnixMs").or_else(|| {
                        read_param_u64(params, "knowledge_last_parity_checked_at_unix_ms")
                    });
                let parity_mismatch = read_param_u64(params, "knowledgeLastParityMismatchCount")
                    .or_else(|| read_param_u64(params, "knowledge_last_parity_mismatch_count"));
                let parity_cursor_missing =
                    read_param_u64(params, "knowledgeLastParityCursorMissingCount").or_else(|| {
                        read_param_u64(params, "knowledge_last_parity_cursor_missing_count")
                    });
                let parity_pass_ratio = read_param_u32(params, "knowledgeLastParityPassRatioBps")
                    .or_else(|| read_param_u32(params, "knowledge_last_parity_pass_ratio_bps"));
                let parity_lag = read_param_u64(params, "knowledgeLastParityLagMs")
                    .or_else(|| read_param_u64(params, "knowledge_last_parity_lag_ms"));
                let parity_detail = read_param_str(params, "knowledgeLastParityDetail")
                    .or_else(|| read_param_str(params, "knowledge_last_parity_detail"))
                    .map(|value| value.trim().to_string());

                if parity_status.is_some()
                    || parity_checked_at.is_some()
                    || parity_mismatch.is_some()
                    || parity_cursor_missing.is_some()
                    || parity_pass_ratio.is_some()
                    || parity_lag.is_some()
                    || parity_detail.is_some()
                {
                    let mut outcome = control_state
                        .knowledge_authority
                        .last_parity_outcome
                        .clone()
                        .unwrap_or(KnowledgeParityOutcomeV1 {
                            status: KnowledgeParityStatusV1::Unknown,
                            checked_at_unix_ms: now_unix_ms(),
                            mismatch_count: 0,
                            cursor_missing_count: 0,
                            pass_ratio_bps: 0,
                            projection_lag_ms: 0,
                            detail: None,
                        });
                    if let Some(value) = parity_status {
                        outcome.status = value;
                    }
                    if let Some(value) = parity_checked_at {
                        outcome.checked_at_unix_ms = value;
                    }
                    if let Some(value) = parity_mismatch {
                        outcome.mismatch_count = value;
                    }
                    if let Some(value) = parity_cursor_missing {
                        outcome.cursor_missing_count = value;
                    }
                    if let Some(value) = parity_pass_ratio {
                        outcome.pass_ratio_bps = value;
                    }
                    if let Some(value) = parity_lag {
                        outcome.projection_lag_ms = value;
                    }
                    if let Some(value) = parity_detail {
                        outcome.detail = if value.is_empty() { None } else { Some(value) };
                    }
                    if control_state
                        .knowledge_authority
                        .last_parity_outcome
                        .as_ref()
                        != Some(&outcome)
                    {
                        control_state.knowledge_authority.last_parity_outcome = Some(outcome);
                        knowledge_authority_changed = true;
                    }
                }
            }

            if knowledge_authority_changed {
                control_state.knowledge_authority.actor = actor.clone();
                control_state.knowledge_authority.reason = reason.clone();
                control_state.knowledge_authority.updated_at_unix_ns = now;
                changed = true;
            }

            let result = serde_json::json!({
                "ok": true,
                "changed": changed,
                "throttle": {
                    "enabled": control_state.valves.throttle.enabled,
                    "eventsPerSec": control_state.valves.throttle.events_per_sec,
                    "bytesPerSec": control_state.valves.throttle.bytes_per_sec,
                    "maxInFlight": control_state.valves.throttle.max_in_flight,
                    "retryAfterMs": control_state.valves.throttle.retry_after_ms
                },
                "tenantThrottles": control_state.tenant_throttles,
                "knowledgeAuthority": control_state.knowledge_authority
            });

            let mut mutation_event_id_out = None;
            if changed {
                control_state.updated_at_unix_ns = now;
                let after = control_state.clone();
                control::write_control_atomic(&state.control_path, &after).map_err(|e| {
                    *control_state = before.clone();
                    admin_action_error(format!("failed to persist CONTROL.json: {e}"))
                })?;

                let auth_context = auth_context.cloned().unwrap_or(EvidenceAuthContextV1 {
                    mode: state.auth.mode().as_str().to_string(),
                    subject: None,
                    tenant_binding: None,
                    scopes: Vec::new(),
                });
                let request_context = request_context.cloned().unwrap_or_default();
                let next_mutation_event_id =
                    mutation_event_id(action_id, &control::control_hash_blake3_hex(&after));
                let mutation_event = build_control_mutation_event(
                    state,
                    action_id,
                    "runtime_knob_update",
                    &actor,
                    &reason,
                    auth_context,
                    request_context,
                    &before,
                    &after,
                    result.clone(),
                );
                if let Err(err) = append_control_evidence_event(
                    state,
                    EVT_CONTROL_STATE_MUTATION_V1,
                    next_mutation_event_id.clone(),
                    &mutation_event,
                )
                .await
                {
                    *control_state = before.clone();
                    let rollback_err =
                        control::write_control_atomic(&state.control_path, &before).err();
                    let detail = match rollback_err {
                        Some(rollback_err) => format!(
                            "failed to append control evidence event: {err}; rollback failed: {rollback_err}"
                        ),
                        None => format!("failed to append control evidence event: {err}"),
                    };
                    return Err(admin_action_error(detail));
                }
                mutation_event_id_out = Some(next_mutation_event_id);
                if let Err(err) =
                    append_control_checkpoint_materialized_event(state, action_id, &after).await
                {
                    append_control_event_warning(
                        action_id,
                        EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1,
                        &err,
                    );
                }
                sync_control_metrics(&state.metrics, &control_state);
            }

            Ok(AdminActionExecutionResult {
                result,
                mutation_event_id: mutation_event_id_out,
            })
        }
        "force-seal" => {
            if !state.admin_force_seal_enabled {
                return Err(admin_action_error(
                    "force-seal is disabled (set CORECRUXD_ADMIN_FORCE_SEAL=1)",
                ));
            }
            let reason = read_param_str(params, "reason")
                .ok_or_else(|| admin_action_error("reason is required for force-seal"))?
                .to_string();
            let wait_proj = read_param_bool(params, "waitForProjection")
                .or_else(|| read_param_bool(params, "wait_for_projection"))
                .unwrap_or(false);
            let max_frames = read_param_u64(params, "maxFrames")
                .or_else(|| read_param_u64(params, "max_frames"))
                .unwrap_or(4096)
                .clamp(1, 65_536) as u32;

            let pool = state
                .dataplane_pool
                .as_ref()
                .ok_or_else(|| admin_action_error("dataplane disabled"))?;

            let started = std::time::Instant::now();

            if wait_proj {
                let results = pool.force_seal_all_and_tick(max_frames).await;
                let wait_ms = started.elapsed().as_millis() as u64;
                let shards: Vec<serde_json::Value> = results
                    .into_iter()
                    .map(|(label, r)| match r {
                        Ok(res) => serde_json::json!({
                            "shardId": label,
                            "sealed": res.seal_result.sealed,
                            "segmentSeq": res.seal_result.segment_seq,
                            "frameCount": res.seal_result.frame_count,
                            "cursorBefore": res.cursor_before,
                            "cursorAfter": res.cursor_after,
                            "projectionFramesProcessed": res.projection_frames_processed,
                        }),
                        Err(err) => serde_json::json!({
                            "shardId": label,
                            "error": err,
                        }),
                    })
                    .collect();
                tracing::info!(
                    action_id = %action_id,
                    reason = %reason,
                    wait_proj = wait_proj,
                    wait_ms,
                    shard_count = shards.len(),
                    "admin force-seal completed"
                );
                Ok(AdminActionExecutionResult {
                    result: serde_json::json!({
                        "ok": true,
                        "reason": reason,
                        "waitForProjection": wait_proj,
                        "waitMs": wait_ms,
                        "shards": shards,
                    }),
                    mutation_event_id: None,
                })
            } else {
                let results = pool.force_seal_all().await;
                let wait_ms = started.elapsed().as_millis() as u64;
                let shards: Vec<serde_json::Value> = results
                    .into_iter()
                    .map(|(label, r)| match r {
                        Ok(seal) => serde_json::json!({
                            "shardId": label,
                            "sealed": seal.sealed,
                            "segmentSeq": seal.segment_seq,
                            "frameCount": seal.frame_count,
                        }),
                        Err(err) => serde_json::json!({
                            "shardId": label,
                            "error": err,
                        }),
                    })
                    .collect();
                tracing::info!(
                    action_id = %action_id,
                    reason = %reason,
                    wait_proj = wait_proj,
                    wait_ms,
                    shard_count = shards.len(),
                    "admin force-seal completed"
                );
                Ok(AdminActionExecutionResult {
                    result: serde_json::json!({
                        "ok": true,
                        "reason": reason,
                        "waitForProjection": false,
                        "waitMs": wait_ms,
                        "shards": shards,
                    }),
                    mutation_event_id: None,
                })
            }
        }
        "parity-pack" => Err(admin_action_error(
            "parity-pack action is not implemented in corecruxd; run corecruxctl parity-pack",
        )),
        other => Err(admin_action_error(format!("unknown actionType '{other}'"))),
    }
}

async fn run_admin_action(state: AppState, action_id: String) {
    let started_at_ms = now_unix_ms();
    let (action_type, params, auth_context, request_context) = {
        let mut actions = state.admin_actions.write().await;
        let Some(rec) = actions.get_mut(&action_id) else {
            return;
        };
        if rec.status != AdminActionStatus::Submitted {
            return;
        }
        rec.status = AdminActionStatus::Running;
        rec.started_at_unix_ms = Some(started_at_ms);
        (
            rec.action_type.clone(),
            rec.params.clone(),
            rec.auth_context.clone(),
            rec.request_context.clone(),
        )
    };

    let mut start_log = StructuredOpLog::new("info", "admin_action", "start", 0);
    start_log.request_id = Some(action_id.clone());
    tracing::info!(
        ts = %start_log.ts,
        level = %start_log.level,
        op = %start_log.op,
        outcome = %start_log.outcome,
        took_ms = start_log.took_ms,
        request_id = %action_id,
        action_id = %action_id,
        action_type = %action_type,
        "admin action started"
    );

    let timeout = Duration::from_secs(state.action_timeout_secs.max(1));
    let outcome = tokio::time::timeout(
        timeout,
        execute_admin_action(
            &state,
            &action_id,
            &action_type,
            params.as_ref(),
            auth_context.as_ref(),
            request_context.as_ref(),
        ),
    )
    .await;
    let finished_at = now_unix_ms();
    let took_ms = finished_at.saturating_sub(started_at_ms);

    let mut actions = state.admin_actions.write().await;
    if let Some(rec) = actions.get_mut(&action_id) {
        let finished_payload = match outcome {
            Ok(Ok(execution)) => {
                rec.status = AdminActionStatus::Succeeded;
                rec.result = Some(execution.result.clone());
                rec.error = None;
                let mut end_log = StructuredOpLog::new("info", "admin_action", "ok", took_ms);
                end_log.request_id = Some(action_id.clone());
                tracing::info!(
                    ts = %end_log.ts,
                    level = %end_log.level,
                    op = %end_log.op,
                    outcome = %end_log.outcome,
                    took_ms = end_log.took_ms,
                    request_id = %action_id,
                    action_id = %action_id,
                    action_type = %action_type,
                    "admin action succeeded"
                );
                Some(build_admin_action_finished_event(
                    &state,
                    &action_id,
                    &action_type,
                    "succeeded",
                    Some(started_at_ms),
                    finished_at,
                    execution.mutation_event_id,
                    Some(execution.result),
                    None,
                ))
            }
            Ok(Err(err)) => {
                rec.status = AdminActionStatus::Failed;
                rec.error = Some(err.clone());
                let mut end_log = StructuredOpLog::new("warn", "admin_action", "fail", took_ms);
                end_log.request_id = Some(action_id.clone());
                end_log.error_code = Some(ErrorCode::Internal.as_str().to_string());
                end_log.error_detail = Some(err.clone());
                tracing::warn!(
                    ts = %end_log.ts,
                    level = %end_log.level,
                    op = %end_log.op,
                    outcome = %end_log.outcome,
                    took_ms = end_log.took_ms,
                    request_id = %action_id,
                    error_code = %end_log.error_code.clone().unwrap_or_default(),
                    action_id = %action_id,
                    action_type = %action_type,
                    error = %err,
                    "admin action failed"
                );
                Some(build_admin_action_finished_event(
                    &state,
                    &action_id,
                    &action_type,
                    "failed",
                    Some(started_at_ms),
                    finished_at,
                    None,
                    None,
                    Some(err),
                ))
            }
            Err(_) => {
                let msg = format!(
                    "action timed out after {}s",
                    state.action_timeout_secs.max(1)
                );
                rec.status = AdminActionStatus::Failed;
                rec.error = Some(msg.clone());
                let mut end_log = StructuredOpLog::new("warn", "admin_action", "fail", took_ms);
                end_log.request_id = Some(action_id.clone());
                end_log.error_code = Some(ErrorCode::Timeout.as_str().to_string());
                end_log.error_detail = Some(msg.clone());
                tracing::warn!(
                    ts = %end_log.ts,
                    level = %end_log.level,
                    op = %end_log.op,
                    outcome = %end_log.outcome,
                    took_ms = end_log.took_ms,
                    request_id = %action_id,
                    error_code = %end_log.error_code.clone().unwrap_or_default(),
                    action_id = %action_id,
                    action_type = %action_type,
                    error = %msg,
                    "admin action timed out"
                );
                Some(build_admin_action_finished_event(
                    &state,
                    &action_id,
                    &action_type,
                    "failed",
                    Some(started_at_ms),
                    finished_at,
                    None,
                    None,
                    Some(msg),
                ))
            }
        };
        rec.finished_at_unix_ms = Some(finished_at);
        drop(actions);
        if let Some(finished_payload) = finished_payload {
            if let Err(err) = append_control_evidence_event(
                &state,
                EVT_CONTROL_ADMIN_ACTION_FINISHED_V1,
                finished_event_id(&action_id, &finished_payload.status),
                &finished_payload,
            )
            .await
            {
                append_control_event_warning(
                    &action_id,
                    EVT_CONTROL_ADMIN_ACTION_FINISHED_V1,
                    &err,
                );
            }
        }
    }
}

#[tracing::instrument(level = "info", skip(state, headers, req))]
async fn post_admin_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PostAdminActionRequest>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }

    let action_type = req.action_type.trim();
    if action_type.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "actionType must be non-empty");
    }
    if !is_known_admin_action(action_type) {
        return problem_response(
            StatusCode::BAD_REQUEST,
            format!(
                "unknown actionType '{action_type}' (expected verify-store|scrub-now|snapshot-verify|projection-rebuild|parity-pack|runtime-knob-update|force-seal)"
            ),
        );
    }

    let action_id = req
        .action_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("act_{}", uuid::Uuid::new_v4()));
    if action_id.len() > 128 {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "actionId must be <= 128 characters",
        );
    }

    let mut actions = state.admin_actions.write().await;
    if let Some(existing) = actions.get(&action_id) {
        return (
            StatusCode::ACCEPTED,
            Json(PostAdminActionResponse {
                accepted: true,
                action: existing.clone(),
            }),
        )
            .into_response();
    }

    let pending_count = actions
        .values()
        .filter(|r| {
            matches!(
                r.status,
                AdminActionStatus::Submitted | AdminActionStatus::Running
            )
        })
        .count();
    if pending_count >= state.action_max_pending {
        return problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "operator action queue is full (pending={pending_count}, limit={})",
                state.action_max_pending
            ),
        );
    }

    let action = AdminActionRecord {
        action_id: action_id.clone(),
        action_type: action_type.to_string(),
        status: AdminActionStatus::Submitted,
        submitted_at_unix_ms: now_unix_ms(),
        started_at_unix_ms: None,
        finished_at_unix_ms: None,
        actor: req.actor.filter(|s| !s.trim().is_empty()),
        reason: req.reason.filter(|s| !s.trim().is_empty()),
        params: req.params,
        result: None,
        error: None,
        auth_context: None,
        request_context: None,
    };

    let auth_context = match describe_http_evidence(&state.auth, &headers) {
        Ok(ok) => ok,
        Err(problem) => return problem.into_response(),
    };
    let request_context = evidence_request_context_from_headers(&headers);
    let submitted_event = build_admin_action_submitted_event(
        &state,
        &action_id,
        action_type,
        action.submitted_at_unix_ms,
        action.actor.clone(),
        action.reason.clone(),
        action.params.clone(),
        auth_context.clone(),
        request_context.clone(),
    );
    if let Err(err) = append_control_evidence_event(
        &state,
        EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1,
        submitted_event_id(&action_id),
        &submitted_event,
    )
    .await
    {
        return problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to append control evidence event: {err}"),
        );
    }

    actions.insert(action_id.clone(), action.clone());
    if let Some(rec) = actions.get_mut(&action_id) {
        rec.auth_context = Some(auth_context);
        rec.request_context = Some(request_context);
    }

    let retain_limit = state.action_max_pending.saturating_mul(8).max(256);
    if actions.len() > retain_limit {
        let mut finished: Vec<(String, u64)> = actions
            .iter()
            .filter_map(|(id, rec)| {
                if matches!(
                    rec.status,
                    AdminActionStatus::Succeeded | AdminActionStatus::Failed
                ) {
                    Some((id.clone(), rec.finished_at_unix_ms.unwrap_or(0)))
                } else {
                    None
                }
            })
            .collect();
        finished.sort_by_key(|(_, ts)| *ts);
        let to_remove = actions.len().saturating_sub(retain_limit);
        for (id, _) in finished.into_iter().take(to_remove) {
            actions.remove(&id);
        }
    }
    drop(actions);

    let task_state = state.clone();
    let task_action_id = action_id.clone();
    tokio::spawn(async move {
        run_admin_action(task_state, task_action_id).await;
    });

    (
        StatusCode::ACCEPTED,
        Json(PostAdminActionResponse {
            accepted: true,
            action,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%action_id))]
async fn get_admin_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(action_id): Path<String>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let actions = state.admin_actions.read().await;
    match actions.get(&action_id) {
        Some(action) => (StatusCode::OK, Json(action.clone())).into_response(),
        None => problem_response(
            StatusCode::NOT_FOUND,
            format!("action '{action_id}' not found"),
        ),
    }
}

#[derive(Debug, Default)]
struct ReplicatedCommitTopologyStatus {
    local_leader_shards: usize,
    missing_followers: Vec<String>,
}

fn evaluate_replicated_commit_topology(
    table: &RoutingTable,
    node_id: &str,
) -> ReplicatedCommitTopologyStatus {
    let mut status = ReplicatedCommitTopologyStatus::default();
    for shard in &table.shard_map.shards {
        if shard.leader.node_id != node_id {
            continue;
        }
        if matches!(shard.state, corecrux_types::ShardState::Retired) {
            continue;
        }
        status.local_leader_shards = status.local_leader_shards.saturating_add(1);
        let follower_count = shard
            .followers
            .as_ref()
            .map(|followers| followers.iter().filter(|f| f.node_id != node_id).count())
            .unwrap_or(0);
        if follower_count == 0 {
            status.missing_followers.push(shard.shard_id.clone());
        }
    }
    status
}

async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    // Phase 3 readiness: lock held + routing table loaded + GPU init checks (when enabled).
    let routing = state.routing.read().await;
    let routing_loaded = !routing.shard_map.shards.is_empty();
    let replicated_topology = if matches!(state.commit_level, CommitLevel::ReplicatedCommit) {
        Some(evaluate_replicated_commit_topology(
            &routing,
            &state.node_id,
        ))
    } else {
        None
    };
    drop(routing);

    let readiness = state.readiness.read().await.clone();

    let gds_ok = if state.io_backend == "gpu-gds" {
        readiness.gds_active && !readiness.gds_degraded
    } else {
        true
    };

    let replicated_commit_dataplane_ok =
        !matches!(state.commit_level, CommitLevel::ReplicatedCommit)
            || state.dataplane_pool.is_some();
    let replicated_commit_dataplane_error = if replicated_commit_dataplane_ok {
        None
    } else {
        Some("replicated commit selected but dataplane store is unavailable".to_string())
    };

    let replicated_commit_topology_ok = replicated_topology
        .as_ref()
        .is_none_or(|status| status.missing_followers.is_empty());
    let replicated_commit_topology_error = replicated_topology
        .as_ref()
        .and_then(|status| {
            if status.missing_followers.is_empty() {
                None
            } else {
                let mut listed = status.missing_followers.clone();
                if listed.len() > 8 {
                    listed.truncate(8);
                }
                Some(format!(
                    "replicated commit requires followers; {} local leader shard(s) missing followers: {}",
                    status.missing_followers.len(),
                    listed.join(", ")
                ))
            }
        });

    let read_retry_failed_total = state.metrics.read_retry_failed_total("cuda_context_lost");
    let read_retry_failed_ok = state.read_retry_failed_readyz_threshold == 0
        || read_retry_failed_total < state.read_retry_failed_readyz_threshold;
    let read_retry_failed_error = if read_retry_failed_ok {
        None
    } else {
        Some(format!(
            "failed read retries exceeded threshold (failed={} threshold={})",
            read_retry_failed_total, state.read_retry_failed_readyz_threshold
        ))
    };
    let projection_snapshot_issues = if let Some(pool) = state.dataplane_pool.as_ref() {
        pool.projection_snapshot_issues().await
    } else {
        Vec::new()
    };
    for projection in [
        "artifact_living_state",
        "artifact_relations",
        "pressure_events",
        "artifact_dependents",
    ] {
        let ok = state.dataplane_pool.is_none()
            || !projection_snapshot_issues
                .iter()
                .any(|issue| issue.projection == "all" || issue.projection == projection);
        state.metrics.set_projection_snapshot_valid(projection, ok);
    }
    let projection_snapshots_valid_ok =
        state.dataplane_pool.is_none() || projection_snapshot_issues.is_empty();
    let projection_snapshots_valid_error = if projection_snapshots_valid_ok {
        None
    } else {
        let mut sample = projection_snapshot_issues
            .iter()
            .take(4)
            .map(|i| format!("{}:{}:{}", i.shard_id, i.projection, i.reason))
            .collect::<Vec<_>>();
        if projection_snapshot_issues.len() > sample.len() {
            sample.push(format!(
                "...+{} more",
                projection_snapshot_issues.len() - sample.len()
            ));
        }
        Some(format!(
            "projection snapshots invalid ({})",
            sample.join(", ")
        ))
    };
    let corruption_state_clear = !*state.corruption_detected.read().await;
    let corruption_state_error = if corruption_state_clear {
        None
    } else {
        Some("corruption state set by verify-store/scrub".to_string())
    };
    let control_evidence_ready =
        !readiness.control_evidence_hosted || readiness.control_evidence_ok;
    let control_evidence_error = if control_evidence_ready {
        None
    } else {
        Some(
            readiness
                .control_evidence_error
                .clone()
                .unwrap_or_else(|| "control evidence verification failed".to_string()),
        )
    };
    let capacity = state.capacity.read().await.clone();
    let capacity_ok = capacity.error.is_none()
        && capacity.total_bytes > 0
        && capacity.free_ratio >= capacity.emergency_free_ratio;
    let capacity_error = if capacity_ok {
        None
    } else if let Some(err) = capacity.error.clone() {
        Some(err)
    } else {
        Some(format!(
            "data dir free ratio below emergency threshold (free_ratio={:.3} threshold={:.3} free_bytes={} total_bytes={})",
            capacity.free_ratio,
            capacity.emergency_free_ratio,
            capacity.free_bytes,
            capacity.total_bytes
        ))
    };

    if state.lock_held
        && routing_loaded
        && readiness.gpu_context
        && readiness.kernel_module_loaded
        && readiness.smoke_kernel_ok
        && readiness.io_backend_ok
        && gds_ok
        && readiness.hardware_profile_ok
        && replicated_commit_dataplane_ok
        && replicated_commit_topology_ok
        && read_retry_failed_ok
        && projection_snapshots_valid_ok
        && corruption_state_clear
        && control_evidence_ready
        && capacity_ok
    {
        return (StatusCode::OK, Json(ReadyOk { ok: true })).into_response();
    }

    let mut checks = Vec::new();
    if !state.lock_held {
        checks.push(ReadyCheck {
            name: "data_dir_lock_held",
            ok: false,
            error: Some("LOCK file not held".to_string()),
        });
    }
    if !routing_loaded {
        checks.push(ReadyCheck {
            name: "routing_loaded",
            ok: false,
            error: Some("routing table not loaded".to_string()),
        });
    }
    if !readiness.gpu_context {
        checks.push(ReadyCheck {
            name: "gpu_context",
            ok: false,
            error: Some(
                readiness
                    .gpu_context_error
                    .unwrap_or_else(|| "CUDA context not initialized".to_string()),
            ),
        });
    }
    if !readiness.kernel_module_loaded {
        checks.push(ReadyCheck {
            name: "kernel_module_loaded",
            ok: false,
            error: Some(
                readiness
                    .kernel_module_error
                    .unwrap_or_else(|| "kernel module not loaded".to_string()),
            ),
        });
    }
    if !readiness.smoke_kernel_ok {
        checks.push(ReadyCheck {
            name: "smoke_kernel_ok",
            ok: false,
            error: Some(
                readiness
                    .smoke_kernel_error
                    .unwrap_or_else(|| "smoke kernel did not pass".to_string()),
            ),
        });
    }
    if !readiness.io_backend_ok {
        checks.push(ReadyCheck {
            name: "io_backend_ok",
            ok: false,
            error: Some(
                readiness
                    .io_backend_error
                    .unwrap_or_else(|| "IO backend not initialized".to_string()),
            ),
        });
    }
    if state.io_backend == "gpu-gds" && !readiness.gds_active {
        checks.push(ReadyCheck {
            name: "gds_active",
            ok: false,
            error: Some(
                readiness
                    .gds_error
                    .clone()
                    .unwrap_or_else(|| "gpu-gds selected but GDS not engaged".to_string()),
            ),
        });
    }
    if state.io_backend == "gpu-gds" && readiness.gds_degraded {
        checks.push(ReadyCheck {
            name: "gds_degraded",
            ok: false,
            error: Some(
                readiness
                    .gds_error
                    .clone()
                    .unwrap_or_else(|| "gpu-gds running in degraded mode".to_string()),
            ),
        });
    }
    if !readiness.hardware_profile_ok {
        checks.push(ReadyCheck {
            name: "hardware_profile_ok",
            ok: false,
            error: Some(
                readiness
                    .hardware_profile_error
                    .unwrap_or_else(|| "hardware profile mismatch".to_string()),
            ),
        });
    }
    if !replicated_commit_dataplane_ok {
        checks.push(ReadyCheck {
            name: "replicated_commit_dataplane",
            ok: false,
            error: replicated_commit_dataplane_error,
        });
    }
    if !replicated_commit_topology_ok {
        checks.push(ReadyCheck {
            name: "replicated_commit_topology",
            ok: false,
            error: replicated_commit_topology_error,
        });
    }
    if !read_retry_failed_ok {
        checks.push(ReadyCheck {
            name: "read_retry_failed_threshold",
            ok: false,
            error: read_retry_failed_error,
        });
    }
    if !projection_snapshots_valid_ok {
        checks.push(ReadyCheck {
            name: "projection_snapshots_valid",
            ok: false,
            error: projection_snapshots_valid_error,
        });
    }
    if !corruption_state_clear {
        checks.push(ReadyCheck {
            name: "corruption_state_clear",
            ok: false,
            error: corruption_state_error,
        });
    }
    if !control_evidence_ready {
        checks.push(ReadyCheck {
            name: "control_evidence_ok",
            ok: false,
            error: control_evidence_error,
        });
    }
    if !capacity_ok {
        checks.push(ReadyCheck {
            name: "data_dir_capacity",
            ok: false,
            error: capacity_error,
        });
    }

    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ReadyFail { ok: false, checks }),
    )
        .into_response()
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    match state.metrics.render() {
        Ok(body) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8".parse().unwrap(),
            );
            (StatusCode::OK, headers, body).into_response()
        }
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
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

#[tracing::instrument(level = "info", skip(state, headers), fields(%receipt_id, tenant_id = %q.tenant_id))]
async fn get_receipt_body_v1(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
    Query(q): Query<TenantQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) =
        require_http_scopes_for_tenant(&state.auth, &headers, &["receipts:read"], &q.tenant_id)
    {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let (_decision, store) = match pool
        .store_for_stream(&q.tenant_id, STREAM_TYPE_RECEIPT, &receipt_id, None)
        .await
    {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let store = store.read().await;
    let events = match store
        .read_stream(&q.tenant_id, STREAM_TYPE_RECEIPT, &receipt_id, 0, 16, None)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };

    let mut body = None;
    for e in events {
        if e.event_type == EVT_RECEIPT_BODY_V1
            && body
                .as_ref()
                .map(|b: &corecrux_storage::StoredEvent| b.seq)
                .unwrap_or(0)
                <= e.seq
        {
            body = Some(e);
        }
    }
    let Some(body) = body else {
        return problem_response(StatusCode::NOT_FOUND, "receipt body not found");
    };

    if wants_cbor(&headers) {
        let mut resp = axum::response::Response::new(axum::body::Body::from(body.payload));
        *resp.status_mut() = StatusCode::OK;
        if let Ok(v) = body.content_type.parse() {
            resp.headers_mut().insert(header::CONTENT_TYPE, v);
        }
        return resp;
    }

    #[derive(serde::Serialize)]
    struct Resp {
        tenant_id: String,
        receipt_id: String,
        seq: u64,
        #[serde(rename = "occurredAt")]
        occurred_at: String,
        #[serde(rename = "ingestedAt")]
        ingested_at: String,
        #[serde(rename = "contentType")]
        content_type: String,
        #[serde(rename = "payloadBase64")]
        payload_base64: String,
        #[serde(rename = "payloadHash")]
        payload_hash: String,
    }

    let ph = corecrux_frame::compute_payload_hash(&body.payload);
    let payload_hash = hex32(&ph);
    (
        StatusCode::OK,
        Json(Resp {
            tenant_id: q.tenant_id,
            receipt_id,
            seq: body.seq,
            occurred_at: body.occurred_at,
            ingested_at: body.ingested_at,
            content_type: body.content_type,
            payload_base64: base64::engine::general_purpose::STANDARD.encode(&body.payload),
            payload_hash,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%receipt_id, tenant_id = %q.tenant_id))]
async fn get_receipt_signature_v1(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
    Query(q): Query<TenantQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) =
        require_http_scopes_for_tenant(&state.auth, &headers, &["receipts:read"], &q.tenant_id)
    {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let (_decision, store) = match pool
        .store_for_stream(&q.tenant_id, STREAM_TYPE_RECEIPT, &receipt_id, None)
        .await
    {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let store = store.read().await;
    let events = match store
        .read_stream(&q.tenant_id, STREAM_TYPE_RECEIPT, &receipt_id, 0, 16, None)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };

    let mut sig = None;
    for e in events {
        if e.event_type == EVT_RECEIPT_SIG_V1
            && sig
                .as_ref()
                .map(|s: &corecrux_storage::StoredEvent| s.seq)
                .unwrap_or(0)
                <= e.seq
        {
            sig = Some(e);
        }
    }
    let Some(sig) = sig else {
        return problem_response(StatusCode::NOT_FOUND, "receipt signature not found");
    };

    if wants_cbor(&headers) {
        let mut resp = axum::response::Response::new(axum::body::Body::from(sig.payload));
        *resp.status_mut() = StatusCode::OK;
        if let Ok(v) = sig.content_type.parse() {
            resp.headers_mut().insert(header::CONTENT_TYPE, v);
        }
        return resp;
    }

    #[derive(serde::Serialize)]
    struct Resp {
        tenant_id: String,
        receipt_id: String,
        seq: u64,
        #[serde(rename = "occurredAt")]
        occurred_at: String,
        #[serde(rename = "ingestedAt")]
        ingested_at: String,
        #[serde(rename = "contentType")]
        content_type: String,
        #[serde(rename = "payloadBase64")]
        payload_base64: String,
        #[serde(rename = "payloadHash")]
        payload_hash: String,
    }

    let ph = corecrux_frame::compute_payload_hash(&sig.payload);
    let payload_hash = hex32(&ph);
    (
        StatusCode::OK,
        Json(Resp {
            tenant_id: q.tenant_id,
            receipt_id,
            seq: sig.seq,
            occurred_at: sig.occurred_at,
            ingested_at: sig.ingested_at,
            content_type: sig.content_type,
            payload_base64: base64::engine::general_purpose::STANDARD.encode(&sig.payload),
            payload_hash,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%receipt_id, tenant_id = %q.tenant_id))]
async fn get_receipt_verification_v1(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
    Query(q): Query<TenantQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) =
        require_http_scopes_for_tenant(&state.auth, &headers, &["receipts:read"], &q.tenant_id)
    {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let stream_hash = match stream_hash_xxhash64(&q.tenant_id, STREAM_TYPE_RECEIPT, &receipt_id) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let (decision, store) = match pool.store_for_stream_hash(stream_hash, None).await {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let shard_id_u32 = match parse_shard_id_u32(&decision.shard_id) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let store = store.read().await;
    match store.verify_receipt_stream_v1(shard_id_u32, &q.tenant_id, &receipt_id) {
        Ok(Some(report)) => (StatusCode::OK, Json(report)).into_response(),
        Ok(None) => problem_response(StatusCode::NOT_FOUND, "receipt body not found"),
        Err(err) => map_store_error_http(err).into_response(),
    }
}

#[derive(Debug, serde::Deserialize)]
struct ExportQueryV1 {
    tenant_id: String,
    include: Option<String>,
    redaction: Option<String>,
    format: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct SubjectExportQueryV1 {
    tenant_id: String,
    mode: Option<String>, // latest|verified|audit
    include: Option<String>,
    redaction: Option<String>,
    format: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct StreamExportQueryV1 {
    tenant_id: String,
    #[serde(rename = "fromSeq")]
    from_seq: Option<u64>,
    #[serde(rename = "toSeq")]
    to_seq: Option<u64>,
    #[serde(rename = "maxEvents")]
    max_events: Option<u32>,
    include: Option<String>,
    redaction: Option<String>,
    format: Option<String>,
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%receipt_id, tenant_id = %q.tenant_id))]
async fn get_receipt_export_v1(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
    Query(q): Query<ExportQueryV1>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(
        &state.auth,
        &headers,
        &["exports:read", "receipts:read"],
        &q.tenant_id,
    ) {
        return problem.into_response();
    }

    let opts = match parse_receipt_export_options_v1(
        q.include.as_deref(),
        q.redaction.as_deref(),
        q.format.as_deref(),
    ) {
        Ok(v) => v,
        Err(msg) => return problem_response(StatusCode::BAD_REQUEST, msg),
    };
    export_receipt_bundle_v1(&state, &q.tenant_id, &receipt_id, opts).await
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%answer_id, tenant_id = %q.tenant_id))]
async fn get_answer_export_v1(
    State(state): State<AppState>,
    Path(answer_id): Path<String>,
    Query(q): Query<SubjectExportQueryV1>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(
        &state.auth,
        &headers,
        &["exports:read", "receipts:read"],
        &q.tenant_id,
    ) {
        return problem.into_response();
    }

    let opts = match parse_receipt_export_options_v1(
        q.include.as_deref(),
        q.redaction.as_deref(),
        q.format.as_deref(),
    ) {
        Ok(v) => v,
        Err(msg) => return problem_response(StatusCode::BAD_REQUEST, msg),
    };

    let mode = q.mode.as_deref().unwrap_or("latest");
    let resolve_mode = match SubjectResolveModeV1::parse(mode) {
        Some(v) => v,
        None => {
            return problem_response(
                StatusCode::BAD_REQUEST,
                format!("invalid mode '{mode}' (expected latest|verified|audit)"),
            );
        }
    };

    let root = state
        .data_dir
        .join("meta")
        .join("receipts")
        .join("subjects");
    let receipt_id = match resolve_subject_receipt_id_v1(
        &root,
        &q.tenant_id,
        "answer",
        &answer_id,
        resolve_mode,
    ) {
        Ok(Some(v)) => v,
        Ok(None) => return problem_response(StatusCode::NOT_FOUND, "receipt not found for answer"),
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };

    export_receipt_bundle_v1(&state, &q.tenant_id, &receipt_id, opts).await
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%action_id, tenant_id = %q.tenant_id))]
async fn get_action_export_v1(
    State(state): State<AppState>,
    Path(action_id): Path<String>,
    Query(q): Query<SubjectExportQueryV1>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(
        &state.auth,
        &headers,
        &["exports:read", "receipts:read"],
        &q.tenant_id,
    ) {
        return problem.into_response();
    }

    let opts = match parse_receipt_export_options_v1(
        q.include.as_deref(),
        q.redaction.as_deref(),
        q.format.as_deref(),
    ) {
        Ok(v) => v,
        Err(msg) => return problem_response(StatusCode::BAD_REQUEST, msg),
    };

    let mode = q.mode.as_deref().unwrap_or("latest");
    let resolve_mode = match SubjectResolveModeV1::parse(mode) {
        Some(v) => v,
        None => {
            return problem_response(
                StatusCode::BAD_REQUEST,
                format!("invalid mode '{mode}' (expected latest|verified|audit)"),
            );
        }
    };

    let root = state
        .data_dir
        .join("meta")
        .join("receipts")
        .join("subjects");
    let receipt_id = match resolve_subject_receipt_id_v1(
        &root,
        &q.tenant_id,
        "action",
        &action_id,
        resolve_mode,
    ) {
        Ok(Some(v)) => v,
        Ok(None) => return problem_response(StatusCode::NOT_FOUND, "receipt not found for action"),
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };

    export_receipt_bundle_v1(&state, &q.tenant_id, &receipt_id, opts).await
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%stream_type, %stream_id, tenant_id = %q.tenant_id))]
async fn get_stream_export_v1(
    State(state): State<AppState>,
    Path((stream_type, stream_id)): Path<(String, String)>,
    Query(q): Query<StreamExportQueryV1>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) =
        require_http_scopes_for_tenant(&state.auth, &headers, &["exports:read"], &q.tenant_id)
    {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let (_decision, store) = match pool
        .store_for_stream(&q.tenant_id, &stream_type, &stream_id, None)
        .await
    {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };

    let format = match q.format.as_deref() {
        None => ExportFormatV1::Zip,
        Some(s) => match ExportFormatV1::parse(s) {
            Some(v) => v,
            None => {
                return problem_response(
                    StatusCode::BAD_REQUEST,
                    format!("invalid format '{s}' (expected zip|tar.zst)"),
                );
            }
        },
    };
    let redaction = match q.redaction.as_deref() {
        None => ExportRedactionV1::TenantSafe,
        Some(s) => match ExportRedactionV1::parse(s) {
            Some(v) => v,
            None => {
                return problem_response(
                    StatusCode::BAD_REQUEST,
                    format!("invalid redaction '{s}' (expected none|metadata_only|tenant_safe)"),
                );
            }
        },
    };

    let include = match q.include.as_deref() {
        None => Vec::new(),
        Some(s) => {
            let mut out = Vec::new();
            for part in s.split(',').map(|v| v.trim()).filter(|v| !v.is_empty()) {
                match part {
                    "headers" | "payloads" => out.push(part.to_string()),
                    _ => {
                        return problem_response(
                            StatusCode::BAD_REQUEST,
                            format!("invalid include '{part}' (expected headers,payloads)"),
                        );
                    }
                }
            }
            out
        }
    };

    let from_seq = q.from_seq.unwrap_or(0);
    let to_seq = q.to_seq;
    if let Some(to) = to_seq {
        if to < from_seq {
            return problem_response(StatusCode::BAD_REQUEST, "toSeq must be >= fromSeq");
        }
    }

    let max_events_total = q.max_events.unwrap_or(10_000).min(50_000);

    let mut events: Vec<corecrux_storage::StoredEvent> = Vec::new();
    {
        let store = store.read().await;
        let mut cur = from_seq;
        while (events.len() as u32) < max_events_total {
            let remaining = max_events_total - (events.len() as u32);
            let batch = remaining.min(1024);
            let batch_events = match store
                .read_stream(&q.tenant_id, &stream_type, &stream_id, cur, batch, None)
                .await
            {
                Ok(v) => v,
                Err(err) => {
                    return map_store_error_http(err).into_response();
                }
            };
            if batch_events.is_empty() {
                break;
            }
            for ev in batch_events {
                if let Some(to) = to_seq {
                    if ev.seq > to {
                        break;
                    }
                }
                cur = ev.seq.saturating_add(1);
                events.push(ev);
                if (events.len() as u32) >= max_events_total {
                    break;
                }
            }
            if let Some(to) = to_seq {
                if cur > to {
                    break;
                }
            }
        }
    }

    // Build headers JSONL deterministically (serde struct field order).
    #[derive(serde::Serialize, Clone, Copy)]
    struct Loc {
        #[serde(rename = "shardId")]
        shard_id: u64,
        epoch: u64,
        #[serde(rename = "segmentSeq")]
        segment_seq: u64,
        offset: u64,
    }

    #[derive(serde::Serialize)]
    struct HeaderLine<'a> {
        #[serde(rename = "tenantId")]
        tenant_id: &'a str,
        #[serde(rename = "streamType")]
        stream_type: &'a str,
        #[serde(rename = "streamId")]
        stream_id: &'a str,
        seq: u64,
        #[serde(rename = "eventId")]
        event_id: &'a str,
        #[serde(rename = "occurredAt")]
        occurred_at: &'a str,
        #[serde(rename = "ingestedAt")]
        ingested_at: &'a str,
        #[serde(rename = "eventType")]
        event_type: &'a str,
        #[serde(rename = "contentType")]
        content_type: &'a str,
        #[serde(rename = "payloadLen")]
        payload_len: u32,
        #[serde(rename = "payloadHash")]
        payload_hash: String,
        #[serde(rename = "headerHash")]
        header_hash: String,
        location: Loc,
    }

    let mut headers_jsonl = Vec::<u8>::with_capacity(events.len() * 256);
    let mut payload_files: Vec<(String, Vec<u8>)> = Vec::new();

    let include_headers = include.is_empty() || include.iter().any(|v| v == "headers");
    let include_payloads = if include.is_empty() {
        redaction != ExportRedactionV1::MetadataOnly
    } else {
        include.iter().any(|v| v == "payloads")
    };

    if include_headers {
        for ev in &events {
            let payload_hash = corecrux_frame::compute_payload_hash(&ev.payload);
            let canonical = corecrux_frame::CanonicalHeaderV1 {
                tenant_id: q.tenant_id.clone(),
                stream_id: stream_id.clone(),
                stream_type: stream_type.clone(),
                seq: ev.seq,
                event_id: ev.event_id.clone(),
                occurred_at: ev.occurred_at.clone(),
                ingested_at: ev.ingested_at.clone(),
                event_type: ev.event_type.clone(),
                content_type: ev.content_type.clone(),
                payload_len: ev.payload.len() as u32,
                payload_hash,
            };
            let canon_bytes = corecrux_frame::canonical_header_bytes_v1(&canonical);
            let header_hash = compute_header_hash(&canon_bytes);

            let line = HeaderLine {
                tenant_id: &q.tenant_id,
                stream_type: &stream_type,
                stream_id: &stream_id,
                seq: ev.seq,
                event_id: &ev.event_id,
                occurred_at: &ev.occurred_at,
                ingested_at: &ev.ingested_at,
                event_type: &ev.event_type,
                content_type: &ev.content_type,
                payload_len: ev.payload.len() as u32,
                payload_hash: hex32(&payload_hash),
                header_hash: hex32(&header_hash),
                location: Loc {
                    shard_id: ev.location.shard_id,
                    epoch: ev.location.epoch,
                    segment_seq: ev.location.segment_seq,
                    offset: ev.location.offset,
                },
            };
            if serde_json::to_writer(&mut headers_jsonl, &line).is_err() {
                return problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "failed to serialize header jsonl",
                );
            }
            headers_jsonl.push(b'\n');
        }
    }

    if include_payloads {
        for ev in &events {
            let name = format!("events/payloads/seq-{seq:020}.bin", seq = ev.seq);
            payload_files.push((name, ev.payload.clone()));
        }
    }

    // Manifest for stream slice export.
    #[derive(serde::Serialize)]
    struct BuildInfoV1 {
        version: String,
        commit: String,
    }

    #[derive(serde::Serialize)]
    struct StreamManifestV1 {
        #[serde(rename = "export_schema")]
        export_schema: String,
        #[serde(rename = "generated_at")]
        generated_at: String,
        #[serde(rename = "tenant_id")]
        tenant_id: String,
        #[serde(rename = "stream_type")]
        stream_type: String,
        #[serde(rename = "stream_id")]
        stream_id: String,
        #[serde(rename = "from_seq_inclusive")]
        from_seq_inclusive: u64,
        #[serde(rename = "to_seq_inclusive", skip_serializing_if = "Option::is_none")]
        to_seq_inclusive: Option<u64>,
        #[serde(rename = "corecrux_build")]
        corecrux_build: BuildInfoV1,
        #[serde(rename = "format")]
        format: String,
        #[serde(rename = "redaction")]
        redaction: String,
        #[serde(rename = "include")]
        include: Vec<String>,
        #[serde(rename = "included_files")]
        included_files: Vec<corecrux_receipts::ExportFileV1>,
        #[serde(rename = "total_events")]
        total_events: u64,
    }

    let generated_at = events
        .last()
        .map(|e| e.ingested_at.clone())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));

    // Compute included file digests.
    let mut included_files: Vec<corecrux_receipts::ExportFileV1> = Vec::new();
    if include_headers {
        included_files.push(corecrux_receipts::ExportFileV1 {
            path: "events/headers.jsonl".to_string(),
            blake3: blake3::hash(&headers_jsonl).to_hex().to_string(),
            size: headers_jsonl.len() as u64,
        });
    }
    for (path, bytes) in &payload_files {
        included_files.push(corecrux_receipts::ExportFileV1 {
            path: path.clone(),
            blake3: blake3::hash(bytes).to_hex().to_string(),
            size: bytes.len() as u64,
        });
    }

    let manifest = StreamManifestV1 {
        export_schema: "cuecrux.replay.export.v1".to_string(),
        generated_at: generated_at.clone(),
        tenant_id: q.tenant_id.clone(),
        stream_type: stream_type.clone(),
        stream_id: stream_id.clone(),
        from_seq_inclusive: from_seq,
        to_seq_inclusive: to_seq,
        corecrux_build: BuildInfoV1 {
            version: state.build.version.clone(),
            commit: state.build.commit.clone(),
        },
        format: format.as_str().to_string(),
        redaction: redaction.as_str().to_string(),
        include,
        included_files: included_files.clone(),
        total_events: events.len() as u64,
    };
    let manifest_json = match serde_json::to_vec_pretty(&manifest) {
        Ok(v) => v,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };

    // Build archive.
    let mut archive_entries: Vec<(String, Vec<u8>)> = Vec::new();
    archive_entries.push(("manifest.json".to_string(), manifest_json.clone()));
    if include_headers {
        archive_entries.push(("events/headers.jsonl".to_string(), headers_jsonl));
    }
    archive_entries.extend(payload_files);
    archive_entries.sort_by(|a, b| a.0.cmp(&b.0));

    let archive_bytes = match format {
        ExportFormatV1::Zip => build_zip_deterministic_bytes(&archive_entries),
        ExportFormatV1::TarZst => build_tar_zst_deterministic_bytes(&archive_entries),
    };
    let archive_bytes = match archive_bytes {
        Ok(v) => v,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err),
    };

    let filename = format!(
        "stream-{stream_type}-{stream_id}-from{from_seq}.{ext}",
        ext = format.filename_ext()
    );

    let mut resp = axum::response::Response::new(axum::body::Body::from(archive_bytes));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, format.content_type().parse().unwrap());
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\"")
            .parse()
            .unwrap(),
    );
    resp
}

fn parse_receipt_export_options_v1(
    include: Option<&str>,
    redaction: Option<&str>,
    format: Option<&str>,
) -> Result<ReceiptExportOptionsV1, String> {
    let format = match format {
        None => ExportFormatV1::Zip,
        Some(s) => ExportFormatV1::parse(s)
            .ok_or_else(|| format!("invalid format '{s}' (expected zip|tar.zst)"))?,
    };
    let redaction = match redaction {
        None => ExportRedactionV1::TenantSafe,
        Some(s) => ExportRedactionV1::parse(s).ok_or_else(|| {
            format!("invalid redaction '{s}' (expected none|metadata_only|tenant_safe)")
        })?,
    };
    let include = match include {
        None => Vec::new(),
        Some(s) => {
            let mut out = Vec::new();
            for part in s.split(',').map(|v| v.trim()).filter(|v| !v.is_empty()) {
                let v = ReceiptExportIncludeV1::parse(part).ok_or_else(|| {
                    format!(
                        "invalid include '{part}' (expected body,sig,verification,trace_summary,subject_links,linked_receipts)"
                    )
                })?;
                out.push(v);
            }
            out
        }
    };
    Ok(ReceiptExportOptionsV1 {
        format,
        redaction,
        include,
    })
}

async fn export_receipt_bundle_v1(
    state: &AppState,
    tenant_id: &str,
    receipt_id: &str,
    opts: ReceiptExportOptionsV1,
) -> axum::response::Response {
    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let (_decision, store) = match pool
        .store_for_stream(tenant_id, STREAM_TYPE_RECEIPT, receipt_id, None)
        .await
    {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let store = store.read().await;
    let events = match store
        .read_tail(tenant_id, STREAM_TYPE_RECEIPT, receipt_id, 32, None)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            state.metrics.inc_receipt_export_total("error");
            return map_store_error_http(err).into_response();
        }
    };

    let mut body = None;
    let mut sig = None;
    for e in events {
        if e.event_type == EVT_RECEIPT_BODY_V1
            && body
                .as_ref()
                .map(|b: &corecrux_storage::StoredEvent| b.seq)
                .unwrap_or(0)
                <= e.seq
        {
            body = Some(e);
        } else if e.event_type == EVT_RECEIPT_SIG_V1
            && sig
                .as_ref()
                .map(|s: &corecrux_storage::StoredEvent| s.seq)
                .unwrap_or(0)
                <= e.seq
        {
            sig = Some(e);
        }
    }

    let Some(body) = body else {
        state.metrics.inc_receipt_export_total("not_found");
        return problem_response(StatusCode::NOT_FOUND, "receipt body not found");
    };
    let Some(sig) = sig else {
        state.metrics.inc_receipt_export_total("precondition");
        return problem_response(StatusCode::PRECONDITION_FAILED, "receipt signature missing");
    };

    let body_payload_hash = corecrux_frame::compute_payload_hash(&body.payload);
    let sig_payload_hash = corecrux_frame::compute_payload_hash(&sig.payload);

    let body_canon = corecrux_frame::CanonicalHeaderV1 {
        tenant_id: tenant_id.to_string(),
        stream_id: receipt_id.to_string(),
        stream_type: STREAM_TYPE_RECEIPT.to_string(),
        seq: body.seq,
        event_id: body.event_id.clone(),
        occurred_at: body.occurred_at.clone(),
        ingested_at: body.ingested_at.clone(),
        event_type: body.event_type.clone(),
        content_type: body.content_type.clone(),
        payload_len: body.payload.len() as u32,
        payload_hash: body_payload_hash,
    };
    let sig_canon = corecrux_frame::CanonicalHeaderV1 {
        tenant_id: tenant_id.to_string(),
        stream_id: receipt_id.to_string(),
        stream_type: STREAM_TYPE_RECEIPT.to_string(),
        seq: sig.seq,
        event_id: sig.event_id.clone(),
        occurred_at: sig.occurred_at.clone(),
        ingested_at: sig.ingested_at.clone(),
        event_type: sig.event_type.clone(),
        content_type: sig.content_type.clone(),
        payload_len: sig.payload.len() as u32,
        payload_hash: sig_payload_hash,
    };
    let body_canon_bytes = corecrux_frame::canonical_header_bytes_v1(&body_canon);
    let sig_canon_bytes = corecrux_frame::canonical_header_bytes_v1(&sig_canon);
    let body_header_hash = compute_header_hash(&body_canon_bytes);
    let sig_header_hash = compute_header_hash(&sig_canon_bytes);

    let generated_at = sig.ingested_at.clone();

    let shard_id_u32 = match u32::try_from(body.location.shard_id) {
        Ok(v) => v,
        Err(_) => {
            state.metrics.inc_receipt_export_total("error");
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "shard_id out of range");
        }
    };
    let report = match store.verify_receipt_stream_v1(shard_id_u32, tenant_id, receipt_id) {
        Ok(Some(r)) => r,
        Ok(None) => {
            state.metrics.inc_receipt_export_total("not_found");
            return problem_response(StatusCode::NOT_FOUND, "receipt body not found");
        }
        Err(err) => {
            state.metrics.inc_receipt_export_total("error");
            return problem_response(StatusCode::BAD_REQUEST, err.to_string());
        }
    };

    let sig_event_ref = format!(
        "shard={} segmentSeq={} offset={}",
        sig.location.shard_id, sig.location.segment_seq, sig.location.offset
    );

    let trace_summary_json = if opts.include.contains(&ReceiptExportIncludeV1::TraceSummary) {
        Some(build_trace_summary_json_v1(
            tenant_id,
            receipt_id,
            &body.payload,
        ))
    } else {
        None
    };
    let subject_links_json = if opts.include.contains(&ReceiptExportIncludeV1::SubjectLinks) {
        Some(build_subject_links_json_v1(
            tenant_id,
            receipt_id,
            &body.payload,
        ))
    } else {
        None
    };
    let lineage_json = if opts
        .include
        .contains(&ReceiptExportIncludeV1::LinkedReceipts)
    {
        Some(build_lineage_json_v1(tenant_id, receipt_id, &body.payload))
    } else {
        None
    };

    let export = match build_receipt_export_v1(
        corecrux_receipts::BuildReceiptExportInput {
            generated_at: &generated_at,
            tenant_id,
            receipt_id,
            build: &state.build,
            body_bytes: &body.payload,
            sig_bytes: &sig.payload,
            verification_report: &report,
            body_payload_hash_hex: &hex32(&body_payload_hash),
            sig_event_ref: &sig_event_ref,
            event_headers: vec![
                corecrux_receipts::ReceiptEventHeaderRefV1 {
                    header_hash: hex32(&body_header_hash),
                    payload_hash: hex32(&body_payload_hash),
                    seq: body.seq,
                    event_id: body.event_id.clone(),
                    occurred_at: body.occurred_at.clone(),
                },
                corecrux_receipts::ReceiptEventHeaderRefV1 {
                    header_hash: hex32(&sig_header_hash),
                    payload_hash: hex32(&sig_payload_hash),
                    seq: sig.seq,
                    event_id: sig.event_id.clone(),
                    occurred_at: sig.occurred_at.clone(),
                },
            ],
            trace_summary_json: trace_summary_json.as_deref(),
            subject_links_json: subject_links_json.as_deref(),
            lineage_json: lineage_json.as_deref(),
        },
        &opts,
    ) {
        Ok(b) => b,
        Err(err) => {
            state.metrics.inc_receipt_export_total("error");
            return match err {
                corecrux_receipts::ExportError::Precondition { msg } => {
                    problem_response(StatusCode::PRECONDITION_FAILED, msg)
                }
                _ => problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            };
        }
    };

    state.metrics.inc_receipt_export_total("ok");

    let filename = format!("receipt-{receipt_id}.{}", export.filename_ext);

    let mut resp = axum::response::Response::new(axum::body::Body::from(export.archive_bytes));
    *resp.status_mut() = StatusCode::OK;
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, export.content_type.parse().unwrap());
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{filename}\"")
            .parse()
            .unwrap(),
    );
    resp
}

pub(crate) fn build_trace_summary_json_v1(
    tenant_id: &str,
    receipt_id: &str,
    body_bytes: &[u8],
) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct TraceSummary<'a> {
        schema: &'a str,
        #[serde(rename = "tenant_id")]
        tenant_id: &'a str,
        #[serde(rename = "receipt_id")]
        receipt_id: &'a str,
        #[serde(rename = "parse_ok")]
        parse_ok: bool,
        kind: Option<String>,
        mode: Option<String>,
        #[serde(rename = "subject_type")]
        subject_type: Option<String>,
        #[serde(rename = "subject_id")]
        subject_id: Option<String>,
    }

    let idx = corecrux_receipts::extract_body_index_v1(body_bytes);
    let (parse_ok, kind, mode, subject_type, subject_id) = match idx {
        Some(v) => (true, v.kind, v.mode, v.subject_type, v.subject_id),
        None => (false, None, None, None, None),
    };
    serde_json::to_vec_pretty(&TraceSummary {
        schema: "cuecrux.receipt.trace_summary.v1",
        tenant_id,
        receipt_id,
        parse_ok,
        kind,
        mode,
        subject_type,
        subject_id,
    })
    .unwrap_or_else(|_| {
        b"{\"schema\":\"cuecrux.receipt.trace_summary.v1\",\"parse_ok\":false}\n".to_vec()
    })
}

pub(crate) fn build_subject_links_json_v1(
    tenant_id: &str,
    receipt_id: &str,
    body_bytes: &[u8],
) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct SubjectLinks<'a> {
        schema: &'a str,
        #[serde(rename = "tenant_id")]
        tenant_id: &'a str,
        #[serde(rename = "receipt_id")]
        receipt_id: &'a str,
        #[serde(rename = "parse_ok")]
        parse_ok: bool,
        kind: Option<String>,
        mode: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        subject: Option<Subject<'a>>,
    }
    #[derive(serde::Serialize)]
    struct Subject<'a> {
        #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
        subject_type: Option<&'a str>,
        id: &'a str,
    }

    let idx = corecrux_receipts::extract_body_index_v1(body_bytes);
    let (parse_ok, kind, mode, subject_type, subject_id) = match idx {
        Some(v) => (true, v.kind, v.mode, v.subject_type, v.subject_id),
        None => (false, None, None, None, None),
    };

    let subject_id = subject_id.unwrap_or_default();
    let subject_type = subject_type.as_deref();

    serde_json::to_vec_pretty(&SubjectLinks {
        schema: "cuecrux.receipt.subject_links.v1",
        tenant_id,
        receipt_id,
        parse_ok: parse_ok && !subject_id.is_empty(),
        kind,
        mode,
        subject: if subject_id.is_empty() {
            None
        } else {
            Some(Subject {
                subject_type,
                id: &subject_id,
            })
        },
    })
    .unwrap_or_else(|_| {
        b"{\"schema\":\"cuecrux.receipt.subject_links.v1\",\"parse_ok\":false}\n".to_vec()
    })
}

pub(crate) fn build_lineage_json_v1(
    tenant_id: &str,
    receipt_id: &str,
    body_bytes: &[u8],
) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct Lineage<'a> {
        schema: &'a str,
        #[serde(rename = "tenant_id")]
        tenant_id: &'a str,
        #[serde(rename = "receipt_id")]
        receipt_id: &'a str,
        #[serde(rename = "parse_ok")]
        parse_ok: bool,
        kind: Option<String>,
        mode: Option<String>,
        #[serde(rename = "subject_type")]
        subject_type: Option<String>,
        #[serde(rename = "subject_id")]
        subject_id: Option<String>,
        #[serde(rename = "linked_receipts")]
        linked_receipts: Vec<String>,
    }

    let idx = corecrux_receipts::extract_body_index_v1(body_bytes);
    let (kind, mode, subject_type, subject_id) = match idx {
        Some(v) => (v.kind, v.mode, v.subject_type, v.subject_id),
        None => (None, None, None, None),
    };
    let linked = corecrux_receipts::extract_linked_receipts_v1(body_bytes);
    let (parse_ok, linked_receipts) = match linked {
        Some(v) => (true, v),
        None => (false, Vec::new()),
    };

    serde_json::to_vec_pretty(&Lineage {
        schema: "cuecrux.receipt.lineage.v1",
        tenant_id,
        receipt_id,
        parse_ok,
        kind,
        mode,
        subject_type,
        subject_id,
        linked_receipts,
    })
    .unwrap_or_else(|_| {
        b"{\"schema\":\"cuecrux.receipt.lineage.v1\",\"parse_ok\":false}\n".to_vec()
    })
}

fn build_zip_deterministic_bytes(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let mut cursor = std::io::Cursor::new(Vec::<u8>::with_capacity(4096));
    {
        let mut zw = zip::ZipWriter::new(&mut cursor);
        let ts =
            zip::DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).expect("static zip timestamp");
        let opts = zip::write::FileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .last_modified_time(ts)
            .unix_permissions(0o644);
        for (path, bytes) in files {
            zw.start_file(path, opts).map_err(|e| e.to_string())?;
            zw.write_all(bytes).map_err(|e| e.to_string())?;
        }
        zw.finish().map_err(|e| e.to_string())?;
    }
    Ok(cursor.into_inner())
}

fn build_tar_zst_deterministic_bytes(files: &[(String, Vec<u8>)]) -> Result<Vec<u8>, String> {
    let mut tar_bytes = Vec::<u8>::with_capacity(4096);
    {
        let mut tb = tar::Builder::new(&mut tar_bytes);
        tb.mode(tar::HeaderMode::Deterministic);

        for (path, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            tb.append_data(&mut header, path.as_str(), std::io::Cursor::new(bytes))
                .map_err(|e| e.to_string())?;
        }
        tb.finish().map_err(|e| e.to_string())?;
    }

    let mut enc = zstd::Encoder::new(Vec::new(), 3).map_err(|e| e.to_string())?;
    enc.write_all(&tar_bytes).map_err(|e| e.to_string())?;
    enc.finish().map_err(|e| e.to_string())
}

#[tracing::instrument(level = "info", skip(state, headers))]
async fn get_shard_map(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    #[derive(serde::Serialize)]
    struct Resp {
        #[serde(rename = "shardMap")]
        shard_map: ShardMapV1,
        #[serde(rename = "currentVersion")]
        current_version: u64,
        blake3: String,
    }

    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let routing = state.routing.read().await.clone();
    let map = routing.shard_map.clone();
    (
        StatusCode::OK,
        Json(Resp {
            shard_map: map.clone(),
            current_version: map.version,
            blake3: map.blake3,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers, _body))]
async fn post_shard_map(
    State(state): State<AppState>,
    headers: HeaderMap,
    _body: axum::body::Bytes,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }

    problem_response(
        StatusCode::NOT_IMPLEMENTED,
        "Phase 3: shard map publishing is CLI-only (use corecruxctl shardmap publish)",
    )
}

#[tracing::instrument(level = "info", skip(state, headers))]
async fn get_control(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let c = state.control.read().await.clone();
    (StatusCode::OK, Json(c)).into_response()
}

#[derive(Debug, Clone, serde::Deserialize)]
struct OpsLogQuery {
    #[serde(rename = "nodeId")]
    node_id: Option<String>,
    since: Option<String>,
    until: Option<String>,
    #[serde(rename = "fromSeq")]
    from_seq: Option<u64>,
    #[serde(rename = "maxEvents")]
    max_events: Option<u32>,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OpsLogEvent {
    seq: u64,
    #[serde(rename = "eventId")]
    event_id: String,
    #[serde(rename = "eventType")]
    event_type: String,
    #[serde(rename = "occurredAt")]
    occurred_at: String,
    #[serde(rename = "ingestedAt")]
    ingested_at: String,
    payload: serde_json::Value,
}

#[derive(Debug, Clone, serde::Serialize)]
struct OpsLogResponse {
    #[serde(rename = "nodeId")]
    node_id: String,
    events: Vec<OpsLogEvent>,
}

#[tracing::instrument(level = "info", skip(state, headers))]
async fn get_ops_log(
    State(state): State<AppState>,
    Query(query): Query<OpsLogQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(
            StatusCode::PRECONDITION_FAILED,
            "ops log unavailable without dataplane",
        );
    };

    let node_id = query.node_id.unwrap_or_else(|| state.node_id.clone());
    let max_events = query.max_events.unwrap_or(256).clamp(1, 4096);
    let batch_size = max_events.min(256);
    let (_decision, store) = match pool
        .store_for_stream("system", "__ops__", &node_id, None)
        .await
    {
        Ok(value) => value,
        Err(err) => {
            return problem_response(
                StatusCode::PRECONDITION_FAILED,
                format!("failed to route ops log stream: {err}"),
            )
        }
    };
    let store = store.read().await;

    let mut from_seq = query.from_seq.unwrap_or(0);
    let mut events = Vec::new();
    while (events.len() as u32) < max_events {
        let batch = match store
            .read_stream("system", "__ops__", &node_id, from_seq, batch_size, None)
            .await
        {
            Ok(value) => value,
            Err(err) => {
                return problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("failed to read ops log stream: {err}"),
                )
            }
        };
        if batch.is_empty() {
            break;
        }

        let mut exhausted = false;
        for event in batch {
            from_seq = event.seq.saturating_add(1);
            if query
                .since
                .as_deref()
                .is_some_and(|since| event.occurred_at.as_str() < since)
            {
                continue;
            }
            if query
                .until
                .as_deref()
                .is_some_and(|until| event.occurred_at.as_str() > until)
            {
                exhausted = true;
                break;
            }
            events.push(OpsLogEvent {
                seq: event.seq,
                event_id: event.event_id,
                event_type: event.event_type,
                occurred_at: event.occurred_at,
                ingested_at: event.ingested_at,
                payload: serde_json::from_slice(&event.payload).unwrap_or_else(|_| {
                    serde_json::json!({
                        "decodeError": "payload was not valid JSON"
                    })
                }),
            });
            if (events.len() as u32) >= max_events {
                exhausted = true;
                break;
            }
        }

        if exhausted {
            break;
        }
    }

    (StatusCode::OK, Json(OpsLogResponse { node_id, events })).into_response()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SetThrottle {
    enabled: bool,
    #[serde(rename = "retryAfterMs")]
    retry_after_ms: Option<u32>,
    #[serde(rename = "eventsPerSec")]
    events_per_sec: Option<u64>,
    #[serde(rename = "bytesPerSec")]
    bytes_per_sec: Option<u64>,
    #[serde(rename = "maxInFlight")]
    max_in_flight: Option<u32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SetValvesReq {
    actor: String,
    reason: String,
    #[serde(rename = "pauseIngest")]
    pause_ingest: Option<bool>,
    #[serde(rename = "pauseCompaction")]
    pause_compaction: Option<bool>,
    throttle: Option<SetThrottle>,
    #[serde(rename = "readOnly")]
    read_only: Option<bool>,
    #[serde(rename = "emergencyBrake")]
    emergency_brake: Option<bool>,
}

#[tracing::instrument(level = "info", skip(state, headers, req))]
async fn post_valves(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SetValvesReq>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }

    if req.actor.trim().is_empty() || req.reason.trim().is_empty() {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "actor and reason must be non-empty",
        );
    }

    let auth_context = match describe_http_evidence(&state.auth, &headers) {
        Ok(ok) => ok,
        Err(problem) => return problem.into_response(),
    };
    let request_context = evidence_request_context_from_headers(&headers);
    let action_id = format!("valves_{}", uuid::Uuid::new_v4());
    let submitted_at_unix_ms = now_unix_ms();
    let submitted_event = build_admin_action_submitted_event(
        &state,
        &action_id,
        "set_valves",
        submitted_at_unix_ms,
        Some(req.actor.clone()),
        Some(req.reason.clone()),
        serde_json::to_value(&req).ok(),
        auth_context.clone(),
        request_context.clone(),
    );
    if let Err(err) = append_control_evidence_event(
        &state,
        EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1,
        submitted_event_id(&action_id),
        &submitted_event,
    )
    .await
    {
        return problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to append control evidence event: {err}"),
        );
    }

    let now = control::now_unix_ns();
    let mut c = state.control.write().await;
    let before = c.clone();
    let prev_emergency_brake = c.valves.emergency_brake.enabled;
    let mut changed = false;
    let mut mutation_event_id_out = None;

    if let Some(v) = req.pause_ingest {
        c.valves.pause_ingest.set(v, &req.actor, &req.reason, now);
        changed = true;
    }
    if let Some(v) = req.pause_compaction {
        c.valves
            .pause_compaction
            .set(v, &req.actor, &req.reason, now);
        changed = true;
    }
    if let Some(t) = req.throttle {
        c.valves
            .throttle
            .set(t.enabled, &req.actor, &req.reason, now);
        c.valves.throttle.set_retry_after_ms(t.retry_after_ms);
        let events_per_sec = t.events_per_sec.or(c.valves.throttle.events_per_sec);
        let bytes_per_sec = t.bytes_per_sec.or(c.valves.throttle.bytes_per_sec);
        let max_in_flight = t.max_in_flight.or(c.valves.throttle.max_in_flight);
        c.valves
            .throttle
            .set_throttle_params(events_per_sec, bytes_per_sec, max_in_flight);
        changed = true;
    }
    if let Some(v) = req.read_only {
        c.valves.read_only.set(v, &req.actor, &req.reason, now);
        changed = true;
    }
    if let Some(v) = req.emergency_brake {
        c.valves
            .emergency_brake
            .set(v, &req.actor, &req.reason, now);
        if v {
            // Emergency brake implies an immediate non-mutating posture.
            c.valves.read_only.set(true, &req.actor, &req.reason, now);
            c.valves
                .pause_ingest
                .set(true, &req.actor, &req.reason, now);
            c.valves
                .pause_compaction
                .set(true, &req.actor, &req.reason, now);
        }
        changed = true;
    }

    if changed {
        c.updated_at_unix_ns = now;
        let after = c.clone();
        if let Err(err) = control::write_control_atomic(&state.control_path, &after) {
            *c = before;
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("failed to persist CONTROL.json: {err}"),
            );
        }

        let next_mutation_event_id =
            mutation_event_id(&action_id, &control::control_hash_blake3_hex(&after));
        let mutation_event = build_control_mutation_event(
            &state,
            &action_id,
            "set_valves",
            &req.actor,
            &req.reason,
            auth_context.clone(),
            request_context.clone(),
            &before,
            &after,
            serde_json::to_value(&after).unwrap_or_else(|_| serde_json::json!({ "ok": true })),
        );
        if let Err(err) = append_control_evidence_event(
            &state,
            EVT_CONTROL_STATE_MUTATION_V1,
            next_mutation_event_id.clone(),
            &mutation_event,
        )
        .await
        {
            *c = before.clone();
            let rollback_err = control::write_control_atomic(&state.control_path, &before).err();
            let detail = match rollback_err {
                Some(rollback_err) => format!(
                    "failed to append control evidence event: {err}; rollback failed: {rollback_err}"
                ),
                None => format!("failed to append control evidence event: {err}"),
            };
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, detail);
        }
        mutation_event_id_out = Some(next_mutation_event_id);
        if let Err(err) =
            append_control_checkpoint_materialized_event(&state, &action_id, &after).await
        {
            append_control_event_warning(&action_id, EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1, &err);
        }

        sync_control_metrics(&state.metrics, &c);

        if !prev_emergency_brake
            && req.emergency_brake == Some(true)
            && c.valves.emergency_brake.enabled
        {
            state.metrics.inc_emergency_brake("admin_http");
            tracing::error!(
                actor = %req.actor,
                reason = %req.reason,
                updated_at_unix_ns = now,
                "emergency brake enabled"
            );
        }
    }

    let finished_event = build_admin_action_finished_event(
        &state,
        &action_id,
        "set_valves",
        "succeeded",
        Some(submitted_at_unix_ms),
        now_unix_ms(),
        mutation_event_id_out,
        Some(serde_json::to_value(c.clone()).unwrap_or_else(|_| serde_json::json!({}))),
        None,
    );
    if let Err(err) = append_control_evidence_event(
        &state,
        EVT_CONTROL_ADMIN_ACTION_FINISHED_V1,
        finished_event_id(&action_id, "succeeded"),
        &finished_event,
    )
    .await
    {
        append_control_event_warning(&action_id, EVT_CONTROL_ADMIN_ACTION_FINISHED_V1, &err);
    }

    (StatusCode::OK, Json(c.clone())).into_response()
}

#[derive(Debug, serde::Deserialize)]
struct StreamMetaReq {
    #[serde(rename = "tenantId")]
    tenant_id: String,
    #[serde(rename = "streamType")]
    stream_type: String,
    #[serde(rename = "streamId")]
    stream_id: String,
    #[serde(rename = "minLiveSeq")]
    min_live_seq: Option<u64>,
    #[serde(rename = "tombstoneSeq")]
    tombstone_seq: Option<u64>,
    actor: String,
    reason: String,
}

#[derive(Debug, serde::Deserialize)]
struct ReplicationSegmentReq {
    #[serde(rename = "shardId")]
    shard_id: String,
    epoch: u64,
    #[serde(rename = "leaderNodeId")]
    leader_node_id: Option<String>,
    #[serde(rename = "segmentBase64")]
    segment_base64: String,
    #[serde(rename = "segmentHash")]
    segment_hash: Option<String>,
}

#[tracing::instrument(level = "info", skip(state, headers, req), fields(shard_id))]
async fn post_replication_segment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ReplicationSegmentReq>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["replication:write"]) {
        state.metrics.inc_replication_receive_total("rejected");
        return problem.into_response();
    }

    if req.shard_id.trim().is_empty() {
        state.metrics.inc_replication_receive_total("rejected");
        return problem_response(StatusCode::BAD_REQUEST, "shardId must be non-empty");
    }
    if req.segment_base64.trim().is_empty() {
        state.metrics.inc_replication_receive_total("rejected");
        return problem_response(StatusCode::BAD_REQUEST, "segmentBase64 must be non-empty");
    }

    let segment_bytes = match base64::engine::general_purpose::STANDARD.decode(&req.segment_base64)
    {
        Ok(v) => v,
        Err(e) => {
            state.metrics.inc_replication_receive_total("rejected");
            return problem_response(
                StatusCode::BAD_REQUEST,
                format!("segmentBase64 decode failed: {e}"),
            );
        }
    };
    if segment_bytes.len() > 512 * 1024 * 1024 {
        state.metrics.inc_replication_receive_total("rejected");
        return problem_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "segment payload exceeds 512MiB limit",
        );
    }
    if let Some(expected_hash) = req.segment_hash.as_ref() {
        let expected = expected_hash.trim().to_ascii_lowercase();
        if expected.len() != 64 || !expected.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
            state.metrics.inc_replication_receive_total("rejected");
            return problem_response(
                StatusCode::BAD_REQUEST,
                "segmentHash must be 64 lowercase hex chars",
            );
        }
        let actual = hex32(blake3::hash(&segment_bytes).as_bytes());
        if actual != expected {
            state.metrics.inc_replication_receive_total("rejected");
            return problem_response(
                StatusCode::PRECONDITION_FAILED,
                serde_json::json!({
                    "code": "REPLICATION_SEGMENT_HASH_MISMATCH",
                    "expectedSegmentHash": expected,
                    "actualSegmentHash": actual
                })
                .to_string(),
            );
        }
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        state.metrics.inc_replication_receive_total("error");
        return problem_response(
            StatusCode::NOT_IMPLEMENTED,
            "replication receiver requires CUDA dataplane store",
        );
    };

    let (routing_epoch, owner_gpu_id, store) =
        match pool.store_for_replication_shard(&req.shard_id).await {
            Ok(v) => v,
            Err(err) => {
                state.metrics.inc_replication_receive_total("rejected");
                return map_store_error_http(err).into_response();
            }
        };
    if routing_epoch != req.epoch {
        state.metrics.inc_replication_receive_total("rejected");
        return problem_response(
            StatusCode::PRECONDITION_FAILED,
            serde_json::json!({
                "code": "REPLICATION_EPOCH_MISMATCH",
                "shardId": req.shard_id,
                "routingEpoch": routing_epoch,
                "requestEpoch": req.epoch
            })
            .to_string(),
        );
    }

    let store = store.read().await;
    let applied = match store
        .apply_replicated_segment(&req.shard_id, req.epoch, &segment_bytes)
        .await
    {
        Ok(v) => v,
        Err(err) => {
            state.metrics.inc_replication_receive_total("error");
            return map_store_error_http(err).into_response();
        }
    };

    if applied.applied {
        state.metrics.inc_replication_receive_total("applied");
    } else {
        state.metrics.inc_replication_receive_total("duplicate");
    }
    state
        .metrics
        .set_replication_follower_watermark(&applied.shard_id, applied.segment_seq);
    pool.update_follower_watermark(&applied.shard_id, applied.segment_seq)
        .await;

    #[derive(serde::Serialize)]
    struct Resp<'a> {
        ok: bool,
        #[serde(rename = "leaderNodeId", skip_serializing_if = "Option::is_none")]
        leader_node_id: Option<&'a str>,
        #[serde(rename = "ownerGpuId")]
        owner_gpu_id: i32,
        result: crate::dataplane_store::ReplicationApplyResult,
    }
    (
        StatusCode::OK,
        Json(Resp {
            ok: true,
            leader_node_id: req.leader_node_id.as_deref(),
            owner_gpu_id,
            result: applied,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers, req))]
async fn post_stream_meta(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<StreamMetaReq>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }

    if req.actor.trim().is_empty() || req.reason.trim().is_empty() {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "actor and reason must be non-empty",
        );
    }

    let decision = {
        let c = state.control.read().await.clone();
        ValveDecision::from_control(&c)
    };
    if !decision.allow_storage_writes {
        return problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage writes are disabled by valves",
        );
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(
            StatusCode::NOT_IMPLEMENTED,
            "stream-meta requires CUDA dataplane store",
        );
    };

    let (_rd, store) = match pool
        .store_for_stream(&req.tenant_id, &req.stream_type, &req.stream_id, None)
        .await
    {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let mut store = store.write().await;
    let res = store
        .update_stream_meta(
            &req.tenant_id,
            &req.stream_type,
            &req.stream_id,
            req.min_live_seq.unwrap_or(0),
            req.tombstone_seq.unwrap_or(0),
        )
        .await;
    match res {
        Ok((min_live_seq, tombstone_seq)) => {
            #[derive(serde::Serialize)]
            struct Resp {
                #[serde(rename = "minLiveSeq")]
                min_live_seq: u64,
                #[serde(rename = "tombstoneSeq")]
                tombstone_seq: u64,
            }
            (
                StatusCode::OK,
                Json(Resp {
                    min_live_seq,
                    tombstone_seq,
                }),
            )
                .into_response()
        }
        Err(err) => map_store_error_http(err).into_response(),
    }
}

#[derive(Debug, serde::Deserialize)]
struct RouteQuery {
    #[serde(rename = "tenantId")]
    tenant_id: String,
    #[serde(rename = "streamType")]
    stream_type: String,
    #[serde(rename = "streamId")]
    stream_id: String,
}

#[derive(serde::Serialize)]
struct RouteResponse {
    #[serde(rename = "streamHash")]
    stream_hash: String,
    #[serde(rename = "shardId")]
    shard_id: String,
    epoch: u64,
    #[serde(rename = "shardMapVersion")]
    shard_map_version: u64,
    #[serde(rename = "leaderGrpcAddr")]
    leader_grpc_addr: String,
}

#[derive(serde::Serialize)]
struct RouteV1Response {
    #[serde(rename = "streamHash")]
    stream_hash: String,
    #[serde(rename = "shardId")]
    shard_id: String,
    epoch: u64,
    #[serde(rename = "shardMapVersion")]
    shard_map_version: u64,
    #[serde(rename = "leaderGrpcAddr")]
    leader_grpc_addr: String,
    #[serde(rename = "leaderNodeId")]
    leader_node_id: String,
    #[serde(rename = "shardGpuId")]
    shard_gpu_id: Option<i32>,
    #[serde(rename = "ownerGpuId")]
    owner_gpu_id: i32,
    #[serde(rename = "workerUp")]
    worker_up: bool,
    #[serde(rename = "shardHosted")]
    shard_hosted: bool,
}

#[tracing::instrument(level = "info", skip(state, headers), fields(tenant_id = %q.tenant_id, stream_type = %q.stream_type, stream_id = %q.stream_id))]
async fn route_debug(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<RouteQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let stream_hash = match stream_hash_xxhash64(&q.tenant_id, &q.stream_type, &q.stream_id) {
        Ok(h) => h,
        Err(err) => {
            return problem_response(StatusCode::BAD_REQUEST, err.to_string());
        }
    };

    let routing = state.routing.read().await.clone();
    let Some(decision) = routing.route_stream_hash(stream_hash) else {
        return problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no shard range matched streamHash (invalid routing table)",
        );
    };

    (
        StatusCode::OK,
        Json(RouteResponse {
            stream_hash: format_u64_hex(decision.stream_hash),
            shard_id: decision.shard_id,
            epoch: decision.epoch,
            shard_map_version: decision.shard_map_version,
            leader_grpc_addr: decision.leader_grpc_addr,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(tenant_id = %q.tenant_id, stream_type = %q.stream_type, stream_id = %q.stream_id))]
async fn route_v1(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<RouteQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let stream_hash = match stream_hash_xxhash64(&q.tenant_id, &q.stream_type, &q.stream_id) {
        Ok(h) => h,
        Err(err) => {
            return problem_response(StatusCode::BAD_REQUEST, err.to_string());
        }
    };

    let routing = state.routing.read().await.clone();
    let Some(decision) = routing.route_stream_hash(stream_hash) else {
        return problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no shard range matched streamHash (invalid routing table)",
        );
    };

    let default_gpu_id = state
        .dataplane_pool
        .as_ref()
        .map(|p| p.default_gpu_id())
        .unwrap_or(0);
    let owner_gpu_id = decision.gpu_id.unwrap_or(default_gpu_id);

    let mut worker_up = false;
    let mut shard_hosted = false;
    if let Some(pool) = state.dataplane_pool.as_ref() {
        if let Some(store) = pool.store_for_gpu_id(owner_gpu_id) {
            worker_up = true;
            let guard = store.read().await;
            shard_hosted = guard
                .hosted_shards()
                .iter()
                .any(|s| s == &decision.shard_id);
        }
    }

    (
        StatusCode::OK,
        Json(RouteV1Response {
            stream_hash: format_u64_hex(decision.stream_hash),
            shard_id: decision.shard_id,
            epoch: decision.epoch,
            shard_map_version: decision.shard_map_version,
            leader_grpc_addr: decision.leader_grpc_addr,
            leader_node_id: decision.leader_node_id,
            shard_gpu_id: decision.gpu_id,
            owner_gpu_id,
            worker_up,
            shard_hosted,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers))]
async fn get_shards(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    #[derive(serde::Serialize)]
    struct ShardInfo {
        #[serde(rename = "shardId")]
        shard_id: String,
        epoch: u64,
        state: corecrux_types::ShardState,
        ranges: Vec<corecrux_types::HashRange>,
        leader: corecrux_types::NodeAddr,
        #[serde(rename = "gpuId")]
        gpu_id: Option<i32>,
        #[serde(rename = "ownerGpuId")]
        owner_gpu_id: i32,
        #[serde(rename = "workerUp")]
        worker_up: bool,
        #[serde(rename = "shardHosted")]
        shard_hosted: bool,
        #[serde(rename = "dataDir")]
        data_dir: Option<String>,
    }

    #[derive(serde::Serialize)]
    struct Resp {
        #[serde(rename = "nodeId")]
        node_id: String,
        #[serde(rename = "shardMapVersion")]
        shard_map_version: u64,
        #[serde(rename = "defaultGpuId")]
        default_gpu_id: i32,
        shards: Vec<ShardInfo>,
    }

    let routing = state.routing.read().await.clone();
    let default_gpu_id = state
        .dataplane_pool
        .as_ref()
        .map(|p| p.default_gpu_id())
        .unwrap_or(0);

    let mut hosted: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut workers_up: std::collections::BTreeSet<i32> = std::collections::BTreeSet::new();
    if let Some(pool) = state.dataplane_pool.as_ref() {
        for gpu_id in pool.gpu_ids() {
            workers_up.insert(gpu_id);
            if let Some(store) = pool.store_for_gpu_id(gpu_id) {
                let guard = store.read().await;
                for s in guard.hosted_shards() {
                    hosted.insert(s);
                }
            }
        }
    }

    let shards: Vec<ShardInfo> = routing
        .shard_map
        .shards
        .iter()
        .map(|s| {
            let owner_gpu_id = s.gpu_id.unwrap_or(default_gpu_id);
            ShardInfo {
                shard_id: s.shard_id.clone(),
                epoch: s.epoch,
                state: s.state,
                ranges: s.ranges.clone(),
                leader: s.leader.clone(),
                gpu_id: s.gpu_id,
                owner_gpu_id,
                worker_up: workers_up.contains(&owner_gpu_id),
                shard_hosted: hosted.contains(&s.shard_id),
                data_dir: s.data_dir.clone(),
            }
        })
        .collect();

    (
        StatusCode::OK,
        Json(Resp {
            node_id: state.node_id.clone(),
            shard_map_version: routing.current_version(),
            default_gpu_id,
            shards,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers))]
async fn get_replication_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    #[derive(serde::Serialize)]
    struct ReplicatedCommitObsResp {
        #[serde(rename = "requiredAcks")]
        required_acks: usize,
        #[serde(rename = "actualAcks")]
        actual_acks: usize,
        #[serde(rename = "ackDeficit")]
        ack_deficit: usize,
        #[serde(rename = "followerCount")]
        follower_count: usize,
        #[serde(rename = "leaderSegmentSeq")]
        leader_segment_seq: u64,
        #[serde(rename = "minFollowerAckedSegmentSeq")]
        min_follower_acked_segment_seq: u64,
        #[serde(rename = "lagSegments")]
        lag_segments: u64,
        result: String,
        #[serde(rename = "failureCount")]
        failure_count: usize,
        #[serde(rename = "failureSample", skip_serializing_if = "Option::is_none")]
        failure_sample: Option<String>,
        #[serde(rename = "observedUnixMs")]
        observed_unix_ms: u64,
    }

    #[derive(serde::Serialize)]
    struct ShardReplicationStatus {
        #[serde(rename = "shardId")]
        shard_id: String,
        epoch: u64,
        state: corecrux_types::ShardState,
        role: String,
        #[serde(rename = "leaderNodeId")]
        leader_node_id: String,
        #[serde(rename = "followerTargets")]
        follower_targets: usize,
        #[serde(rename = "topologyOk")]
        topology_ok: bool,
        #[serde(
            rename = "localFollowerWatermarkSegmentSeq",
            skip_serializing_if = "Option::is_none"
        )]
        local_follower_watermark_segment_seq: Option<u64>,
        #[serde(rename = "replicatedCommit", skip_serializing_if = "Option::is_none")]
        replicated_commit: Option<ReplicatedCommitObsResp>,
    }

    #[derive(serde::Serialize)]
    struct Resp {
        #[serde(rename = "nodeId")]
        node_id: String,
        #[serde(rename = "commitLevel")]
        commit_level: String,
        #[serde(rename = "shardMapVersion")]
        shard_map_version: u64,
        #[serde(rename = "localLeaderShards")]
        local_leader_shards: usize,
        #[serde(rename = "topologyMissingFollowers")]
        topology_missing_followers: usize,
        #[serde(rename = "maxLagSegments")]
        max_lag_segments: u64,
        shards: Vec<ShardReplicationStatus>,
    }

    let routing = state.routing.read().await.clone();
    let (follower_watermarks, observations) = if let Some(pool) = state.dataplane_pool.as_ref() {
        (
            pool.follower_watermarks_snapshot().await,
            pool.replicated_commit_observations_snapshot().await,
        )
    } else {
        (
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
        )
    };

    let mut local_leader_shards: usize = 0;
    let mut topology_missing_followers: usize = 0;
    let mut max_lag_segments: u64 = 0;
    let mut shards = Vec::with_capacity(routing.shard_map.shards.len());
    for shard in &routing.shard_map.shards {
        let is_leader = shard.leader.node_id == state.node_id;
        let is_follower = shard
            .followers
            .as_ref()
            .is_some_and(|followers| followers.iter().any(|f| f.node_id == state.node_id));

        let role = if is_leader {
            "leader"
        } else if is_follower {
            "follower"
        } else {
            "unassigned"
        };

        let follower_targets = shard
            .followers
            .as_ref()
            .map(|followers| {
                followers
                    .iter()
                    .filter(|f| f.node_id != state.node_id)
                    .count()
            })
            .unwrap_or(0);
        let topology_ok = follower_targets > 0;
        if is_leader && !matches!(shard.state, corecrux_types::ShardState::Retired) {
            local_leader_shards = local_leader_shards.saturating_add(1);
            if !topology_ok {
                topology_missing_followers = topology_missing_followers.saturating_add(1);
            }
        }

        let local_follower_watermark_segment_seq =
            follower_watermarks.get(&shard.shard_id).copied();
        let replicated_commit =
            observations
                .get(&shard.shard_id)
                .map(|obs| ReplicatedCommitObsResp {
                    required_acks: obs.required_acks,
                    actual_acks: obs.actual_acks,
                    ack_deficit: obs.required_acks.saturating_sub(obs.actual_acks),
                    follower_count: obs.follower_count,
                    leader_segment_seq: obs.leader_segment_seq,
                    min_follower_acked_segment_seq: obs.min_follower_acked_segment_seq,
                    lag_segments: obs.lag_segments,
                    result: obs.result.clone(),
                    failure_count: obs.failure_count,
                    failure_sample: obs.failure_sample.clone(),
                    observed_unix_ms: obs.observed_unix_ms,
                });
        if let Some(obs) = replicated_commit.as_ref() {
            max_lag_segments = max_lag_segments.max(obs.lag_segments);
        }

        shards.push(ShardReplicationStatus {
            shard_id: shard.shard_id.clone(),
            epoch: shard.epoch,
            state: shard.state,
            role: role.to_string(),
            leader_node_id: shard.leader.node_id.clone(),
            follower_targets,
            topology_ok,
            local_follower_watermark_segment_seq,
            replicated_commit,
        });
    }

    shards.sort_by(|a, b| a.shard_id.cmp(&b.shard_id));
    (
        StatusCode::OK,
        Json(Resp {
            node_id: state.node_id.clone(),
            commit_level: state.commit_level.as_str().to_string(),
            shard_map_version: routing.current_version(),
            local_leader_shards,
            topology_missing_followers,
            max_lag_segments,
            shards,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers))]
async fn get_gpus(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    #[derive(serde::Serialize)]
    struct Dev {
        index: i32,
        name: String,
    }

    #[derive(serde::Serialize)]
    struct GpuEntry {
        #[serde(rename = "gpuId")]
        gpu_id: i32,
        #[serde(rename = "workerUp")]
        worker_up: bool,
        device: Option<Dev>,
        #[serde(rename = "shardsLoaded")]
        shards_loaded: Vec<String>,
    }

    #[derive(serde::Serialize)]
    struct Resp {
        #[serde(rename = "defaultGpuId")]
        default_gpu_id: i32,
        #[serde(rename = "cudaDriverVersion")]
        cuda_driver_version: Option<String>,
        #[serde(rename = "inventoryError")]
        inventory_error: Option<String>,
        gpus: Vec<GpuEntry>,
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(
            StatusCode::NOT_IMPLEMENTED,
            "dataplane disabled (CUDA build required)",
        );
    };

    let default_gpu_id = pool.default_gpu_id();
    let cuda_driver_version: Option<String> = None;

    let inventory_error: Option<String> = Some("GPU support removed (CPU-only build)".to_string());
    let by_index: std::collections::BTreeMap<i32, String> = std::collections::BTreeMap::new();

    let mut gpus: Vec<GpuEntry> = Vec::new();
    for gpu_id in pool.gpu_ids() {
        let store = pool.store_for_gpu_id(gpu_id);
        let worker_up = store.is_some();
        let shards_loaded = if let Some(store) = store {
            let guard = store.read().await;
            guard.hosted_shards()
        } else {
            Vec::new()
        };
        let device = by_index.get(&gpu_id).map(|name| Dev {
            index: gpu_id,
            name: name.clone(),
        });

        gpus.push(GpuEntry {
            gpu_id,
            worker_up,
            device,
            shards_loaded,
        });
    }

    (
        StatusCode::OK,
        Json(Resp {
            default_gpu_id,
            cuda_driver_version,
            inventory_error,
            gpus,
        }),
    )
        .into_response()
}

#[derive(serde::Serialize)]
struct RoutingStatusResponse {
    #[serde(rename = "routingTableVersion")]
    routing_table_version: u64,
    #[serde(rename = "lastReloadAt")]
    last_reload_at: String,
    #[serde(rename = "reloadErrors")]
    reload_errors: Vec<String>,
    #[serde(rename = "shardsLoaded")]
    shards_loaded: Vec<String>,
}

#[tracing::instrument(level = "info", skip(state, headers))]
async fn routing_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let routing = state.routing.read().await.clone();
    let reload_errors = state.routing_errors.read().await.clone();

    let shards_loaded = if let Some(pool) = state.dataplane_pool.as_ref() {
        let mut out = Vec::new();
        for gpu_id in pool.gpu_ids() {
            let Some(store) = pool.store_for_gpu_id(gpu_id) else {
                continue;
            };
            let store = store.read().await;
            out.extend(store.hosted_shards());
        }
        out.sort();
        out.dedup();
        out
    } else {
        routing
            .shard_map
            .shards
            .iter()
            .map(|s| s.shard_id.clone())
            .collect()
    };

    (
        StatusCode::OK,
        Json(RoutingStatusResponse {
            routing_table_version: routing.current_version(),
            last_reload_at: routing.loaded_at,
            reload_errors,
            shards_loaded,
        }),
    )
        .into_response()
}

// ── Phase 7: Entity projection HTTP handlers ────────────────────────────

async fn get_entity_count(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let tenant_id = params.get("tenant_id").cloned().unwrap_or_default();
    let entity_type = params.get("entity_type").cloned().unwrap_or_default();
    let predicate = params.get("predicate").cloned().unwrap_or_default();

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let mut all_items: Vec<String> = Vec::new();
    for gpu_id in pool.gpu_ids() {
        let Some(store) = pool.store_for_gpu_id(gpu_id) else { continue };
        let guard = store.read().await;
        let items = guard.query_entity_count(&tenant_id, &entity_type, &predicate);
        all_items.extend(items);
    }
    all_items.sort();
    all_items.dedup();

    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "entity_type": entity_type,
        "predicate": predicate,
        "count": all_items.len(),
        "items": all_items,
    }))
    .into_response()
}

async fn get_entity_timeline(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let tenant_id = params.get("tenant_id").cloned().unwrap_or_default();
    let entity_type = params.get("entity_type").cloned().unwrap_or_default();
    let predicate = params.get("predicate").cloned().unwrap_or_default();

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let mut all_events: Vec<serde_json::Value> = Vec::new();
    for gpu_id in pool.gpu_ids() {
        let Some(store) = pool.store_for_gpu_id(gpu_id) else { continue };
        let guard = store.read().await;
        let events = guard.query_entity_timeline(&tenant_id, &entity_type, &predicate);
        for (name, value, micros) in events {
            let ts_secs = micros / 1_000_000;
            let date_str = chrono::DateTime::from_timestamp(ts_secs, 0)
                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_default();
            all_events.push(serde_json::json!({
                "entity_name": name,
                "object_value": value,
                "occurred_at": date_str,
            }));
        }
    }

    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "entity_type": entity_type,
        "predicate": predicate,
        "event_count": all_events.len(),
        "timeline": all_events,
    }))
    .into_response()
}

async fn get_entity_current_state(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let tenant_id = params.get("tenant_id").cloned().unwrap_or_default();
    let entity_name = params.get("entity_name").cloned().unwrap_or_default();
    let predicate = params.get("predicate").cloned().unwrap_or_default();

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    for gpu_id in pool.gpu_ids() {
        let Some(store) = pool.store_for_gpu_id(gpu_id) else { continue };
        let guard = store.read().await;
        if let Some((current_value, occurred_at_micros, previous_value, _prev_at)) =
            guard.query_entity_current_state(&tenant_id, &entity_name, &predicate)
        {
            let ts_secs = occurred_at_micros / 1_000_000;
            let date_str = chrono::DateTime::from_timestamp(ts_secs, 0)
                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_default();
            return Json(serde_json::json!({
                "tenant_id": tenant_id,
                "entity_name": entity_name,
                "predicate": predicate,
                "current_value": current_value,
                "occurred_at": date_str,
                "previous_value": previous_value,
            }))
            .into_response();
        }
    }

    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "entity_name": entity_name,
        "predicate": predicate,
        "current_value": serde_json::Value::Null,
        "not_found": true,
    }))
    .into_response()
}

// ── Production hardening: structured panic handler ──────────────────

fn handle_panic(err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    let msg = if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else {
        "unknown panic".to_string()
    };
    tracing::error!(panic = %msg, "handler panicked");
    let pd = ProblemDetails::internal("internal server error (panic recovered)");
    let body = serde_json::to_string(&pd).unwrap_or_default();
    Response::builder()
        .status(500)
        .header("content-type", "application/problem+json")
        .body(axum::body::Body::from(body))
        .unwrap_or_default()
}

// ── Production hardening: /v1/version endpoint ──────────────────────

async fn get_version(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "version": state.build.version,
        "commit": state.build.commit,
        "msrv": "1.88.0",
        "features": {
            "text_search": is_query_feature_enabled("CORECRUXD_QUERY_TEXT_SEARCH"),
            "graph_expand": is_query_feature_enabled("CORECRUXD_QUERY_GRAPH_EXPAND"),
            "self_observe": crux_observe::config::self_observe_enabled(),
            "mcp": std::env::var("CRUX_MCP_ENABLED").map(|v| v == "true" || v == "1").unwrap_or(false),
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::auth::AuthMode;
    use crate::shard_map::LoadedShardMap;
    use axum::body::to_bytes;
    use corecrux_types::{
        compute_shard_map_v1_blake3_hex, format_u64_hex, HashRange, KnowledgeAuthorityModeV1,
        KnowledgeRolloutStageV1, NodeAddr, ShardDescriptor, ShardMapV1, ShardState,
        DEFAULT_COMPAT_REQUIRES, DEFAULT_SDK_VERSION, SHARDMAP_HASH_FN_V1,
        SHARDMAP_KEY_ENCODING_V1, SHARDMAP_V1,
    };

    fn test_node(node_id: &str, http_addr: &str, grpc_addr: &str) -> NodeAddr {
        NodeAddr {
            node_id: node_id.to_string(),
            grpc_addr: grpc_addr.to_string(),
            http_addr: http_addr.to_string(),
        }
    }

    fn test_routing() -> RoutingTable {
        let mut map = ShardMapV1 {
            v: SHARDMAP_V1,
            cluster_id: "test-cluster".to_string(),
            version: 1,
            created_at: "2026-03-04T00:00:00Z".to_string(),
            hash_fn: SHARDMAP_HASH_FN_V1.to_string(),
            key_encoding: SHARDMAP_KEY_ENCODING_V1.to_string(),
            shards: vec![ShardDescriptor {
                shard_id: "shard-0001".to_string(),
                epoch: 1,
                state: ShardState::Active,
                ranges: vec![HashRange {
                    start_inclusive: format_u64_hex(0),
                    end_exclusive: format_u64_hex(0),
                }],
                leader: test_node("node-a", "http://127.0.0.1:4006", "http://127.0.0.1:50051"),
                followers: None,
                data_dir: None,
                gpu_id: Some(0),
            }],
            blake3: String::new(),
            prev_blake3: None,
        };
        map.blake3 = compute_shard_map_v1_blake3_hex(&map).expect("compute shardmap hash");
        RoutingTable::new(LoadedShardMap {
            current_version: map.version,
            shard_map: map,
        })
        .expect("routing table")
    }

    fn test_app_state_with_auth(action_max_pending: usize, auth_mode: AuthMode) -> AppState {
        let build = corecrux_types::BuildInfo {
            version: "test".to_string(),
            commit: "test".to_string(),
        };
        let metrics = crate::metrics::Metrics::new(&build, "corecruxd-test");
        let auth = Authz::from_env(auth_mode).expect("auth init");

        let root =
            std::env::temp_dir().join(format!("corecruxd-http-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create test dir");
        let control_path = root.join("CONTROL.json");

        AppState {
            lock_held: true,
            build,
            compat: CompatContract {
                requires: DEFAULT_COMPAT_REQUIRES.to_string(),
            },
            sdk_version: DEFAULT_SDK_VERSION.to_string(),
            auth,
            data_dir: root.clone(),
            io_backend: "gpu-dev".to_string(),
            read_retry_failed_readyz_threshold: 0,
            commit_level: CommitLevel::LocalCommit,
            metrics,
            node_id: "node-a".to_string(),
            routing: Arc::new(RwLock::new(test_routing())),
            routing_errors: Arc::new(RwLock::new(Vec::new())),
            dataplane_pool: None,
            readiness: Arc::new(RwLock::new(Readiness::default())),
            control: Arc::new(RwLock::new(control::ControlV1::default())),
            control_path,
            action_max_pending,
            action_timeout_secs: 5,
            scrub_scope: "recent".to_string(),
            scrub_mode: "sampled".to_string(),
            scrub_sample_rate: 0.25,
            admin_actions: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
            corruption_detected: Arc::new(RwLock::new(false)),
            admin_force_seal_enabled: false,
            retrieval_index: Arc::new(RwLock::new(corecrux_retrieval::IndexManager::new())),
            fact_store: Arc::new(RwLock::new(corecrux_memory::FactStore::new())),
            session_store: Arc::new(RwLock::new(corecrux_memory::SessionStore::new())),
            capacity: Arc::new(RwLock::new(CapacityState {
                total_bytes: 100,
                free_bytes: 80,
                free_ratio: 0.8,
                warning_free_ratio: 0.20,
                critical_free_ratio: 0.10,
                emergency_free_ratio: 0.10,
                auto_paused: false,
                error: None,
            })),
        }
    }

    fn test_app_state(action_max_pending: usize) -> AppState {
        test_app_state_with_auth(action_max_pending, AuthMode::Off)
    }

    fn dev_scope_headers(scopes: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-corecrux-scopes",
            HeaderValue::from_str(scopes).expect("valid test scope header"),
        );
        headers
    }

    async fn json_body(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 1_048_576)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    async fn mark_ready_except_control(state: &AppState) {
        let mut readiness = state.readiness.write().await;
        readiness.gpu_context = true;
        readiness.kernel_module_loaded = true;
        readiness.smoke_kernel_ok = true;
        readiness.io_backend_ok = true;
        readiness.gds_active = true;
        readiness.gds_degraded = false;
        readiness.hardware_profile_ok = true;
    }

    #[tokio::test]
    async fn readyz_fails_when_hosted_control_evidence_is_invalid() {
        let state = test_app_state(16);
        mark_ready_except_control(&state).await;
        {
            let mut readiness = state.readiness.write().await;
            readiness.control_evidence_hosted = true;
            readiness.control_evidence_ok = false;
            readiness.control_evidence_error = Some("checkpoint mismatch".to_string());
        }

        let resp = readyz(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json_body(resp).await;
        assert_eq!(body["ok"], false);
        let checks = body["checks"].as_array().expect("checks array");
        assert!(checks.iter().any(|check| {
            check["name"] == "control_evidence_ok" && check["error"] == "checkpoint mismatch"
        }));
    }

    #[tokio::test]
    async fn readyz_ignores_control_evidence_errors_when_stream_not_hosted() {
        let state = test_app_state(16);
        mark_ready_except_control(&state).await;
        {
            let mut readiness = state.readiness.write().await;
            readiness.control_evidence_hosted = false;
            readiness.control_evidence_ok = false;
            readiness.control_evidence_error =
                Some("not hosted locally; checkpoint fallback".to_string());
        }

        let resp = readyz(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["ok"], true);
    }

    #[tokio::test]
    async fn runtime_knob_update_updates_knowledge_authority() {
        let state = test_app_state(16);
        let params = serde_json::json!({
            "actor": "ops",
            "reason": "rollout-stage",
            "knowledgeAuthorityMode": "knowledge_dual_write",
            "knowledgeAuthorityRolloutStage": "tenant_validation",
            "knowledgeMaxMismatchCount": 3,
            "knowledgeMaxCursorMissingCount": 5,
            "knowledgeMinPassRatioBps": 9750,
            "knowledgeMaxProjectionLagMs": 1500,
            "knowledgeMaxCursorAgeMs": 2400,
            "knowledgeRollbackTriggered": true,
            "knowledgeLastParityStatus": "warn",
            "knowledgeLastParityCheckedAtUnixMs": 111,
            "knowledgeLastParityMismatchCount": 2,
            "knowledgeLastParityCursorMissingCount": 1,
            "knowledgeLastParityPassRatioBps": 9810,
            "knowledgeLastParityLagMs": 444,
            "knowledgeLastParityDetail": "parity drift"
        });

        let result = execute_admin_action(
            &state,
            "act-knowledge-1",
            "runtime-knob-update",
            Some(&params),
            None,
            None,
        )
        .await
        .expect("runtime knob update succeeds");

        assert_eq!(
            result.result["knowledgeAuthority"]["mode"],
            serde_json::json!("knowledge_dual_write")
        );

        let control = state.control.read().await.clone();
        assert_eq!(
            control.knowledge_authority.mode,
            KnowledgeAuthorityModeV1::DualWrite
        );
        assert_eq!(
            control.knowledge_authority.rollout_stage,
            KnowledgeRolloutStageV1::TenantValidation
        );
        assert_eq!(
            control
                .knowledge_authority
                .parity_thresholds
                .max_mismatch_count,
            3
        );
        assert_eq!(
            control
                .knowledge_authority
                .parity_thresholds
                .max_cursor_missing_count,
            5
        );
        assert_eq!(
            control
                .knowledge_authority
                .parity_thresholds
                .min_pass_ratio_bps,
            9750
        );
        assert_eq!(
            control
                .knowledge_authority
                .lag_thresholds
                .max_projection_lag_ms,
            1500
        );
        assert_eq!(
            control.knowledge_authority.lag_thresholds.max_cursor_age_ms,
            2400
        );
        assert!(control.knowledge_authority.rollback_triggered);
        assert_eq!(control.knowledge_authority.actor, "ops");
        assert_eq!(control.knowledge_authority.reason, "rollout-stage");
        assert!(control.knowledge_authority.updated_at_unix_ns > 0);
        let parity = control
            .knowledge_authority
            .last_parity_outcome
            .expect("parity outcome recorded");
        assert_eq!(parity.status.as_str(), "warn");
        assert_eq!(parity.checked_at_unix_ms, 111);
        assert_eq!(parity.mismatch_count, 2);
        assert_eq!(parity.cursor_missing_count, 1);
        assert_eq!(parity.pass_ratio_bps, 9810);
        assert_eq!(parity.projection_lag_ms, 444);
        assert_eq!(parity.detail.as_deref(), Some("parity drift"));
    }

    #[tokio::test]
    async fn runtime_knob_update_updates_tenant_throttles() {
        let state = test_app_state(16);
        let params = serde_json::json!({
            "actor": "ops",
            "reason": "tenant-isolation",
            "tenantThrottleRules": [
                {
                    "tenantId": "tenant-a",
                    "eventsPerSec": 15,
                    "bytesPerSec": 4096,
                    "maxInFlight": 3
                }
            ]
        });

        let result = execute_admin_action(
            &state,
            "act-tenant-throttle-1",
            "runtime-knob-update",
            Some(&params),
            None,
            None,
        )
        .await
        .expect("runtime knob update succeeds");

        assert_eq!(
            result.result["tenantThrottles"][0]["tenantId"],
            serde_json::json!("tenant-a")
        );
        let control = state.control.read().await.clone();
        assert_eq!(control.tenant_throttles.len(), 1);
        assert_eq!(control.tenant_throttles[0].tenant_id, "tenant-a");
        assert_eq!(control.tenant_throttles[0].events_per_sec, Some(15));
        assert_eq!(control.tenant_throttles[0].bytes_per_sec, Some(4096));
        assert_eq!(control.tenant_throttles[0].max_in_flight, Some(3));
    }

    #[tokio::test]
    async fn runtime_knob_update_clears_knowledge_parity_outcome() {
        let state = test_app_state(16);
        execute_admin_action(
            &state,
            "act-knowledge-seed",
            "runtime-knob-update",
            Some(&serde_json::json!({
                "actor": "ops",
                "reason": "seed-parity",
                "knowledgeLastParityStatus": "fail",
                "knowledgeLastParityCheckedAtUnixMs": 222,
                "knowledgeLastParityMismatchCount": 9
            })),
            None,
            None,
        )
        .await
        .expect("seed parity outcome");

        execute_admin_action(
            &state,
            "act-knowledge-clear",
            "runtime-knob-update",
            Some(&serde_json::json!({
                "actor": "ops",
                "reason": "clear-parity",
                "knowledgeClearParityOutcome": true
            })),
            None,
            None,
        )
        .await
        .expect("clear parity outcome");

        assert!(state
            .control
            .read()
            .await
            .knowledge_authority
            .last_parity_outcome
            .is_none());
    }

    #[tokio::test]
    async fn get_control_returns_knowledge_authority() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        {
            let mut control = state.control.write().await;
            control.knowledge_authority.mode = KnowledgeAuthorityModeV1::Authoritative;
            control.knowledge_authority.rollout_stage =
                KnowledgeRolloutStageV1::FullProductionAuthority;
        }

        let resp = get_control(State(state), dev_scope_headers("admin:read"))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(
            body["knowledgeAuthority"]["mode"],
            "knowledge_authoritative"
        );
        assert_eq!(
            body["knowledgeAuthority"]["rolloutStage"],
            "full_production_authority"
        );
    }

    #[tokio::test]
    async fn admin_action_submit_is_idempotent_by_action_id() {
        let state = test_app_state(16);
        let req_a = PostAdminActionRequest {
            action_id: Some("act-fixed-1".to_string()),
            action_type: "runtime-knob-update".to_string(),
            actor: Some("test".to_string()),
            reason: Some("idempotency-check".to_string()),
            params: Some(serde_json::json!({
                "throttleEnabled": true,
                "throttleEventsPerSec": 42
            })),
        };

        let resp_a = post_admin_action(State(state.clone()), HeaderMap::new(), Json(req_a))
            .await
            .into_response();
        assert_eq!(resp_a.status(), StatusCode::ACCEPTED);
        let body_a = json_body(resp_a).await;
        assert_eq!(body_a["accepted"], true);
        assert_eq!(body_a["action"]["actionId"], "act-fixed-1");

        let req_b = PostAdminActionRequest {
            action_id: Some("act-fixed-1".to_string()),
            action_type: "runtime-knob-update".to_string(),
            actor: Some("test".to_string()),
            reason: Some("idempotency-check".to_string()),
            params: Some(serde_json::json!({
                "throttleEnabled": true,
                "throttleEventsPerSec": 42
            })),
        };
        let resp_b = post_admin_action(State(state.clone()), HeaderMap::new(), Json(req_b))
            .await
            .into_response();
        assert_eq!(resp_b.status(), StatusCode::ACCEPTED);
        let body_b = json_body(resp_b).await;
        assert_eq!(body_b["accepted"], true);
        assert_eq!(body_b["action"]["actionId"], "act-fixed-1");

        let actions = state.admin_actions.read().await;
        assert_eq!(
            actions.len(),
            1,
            "idempotent submit must not create duplicates"
        );
        drop(actions);

        let get_resp = get_admin_action(
            State(state),
            HeaderMap::new(),
            Path("act-fixed-1".to_string()),
        )
        .await
        .into_response();
        assert_eq!(get_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_action_unknown_type_returns_problem_details() {
        let state = test_app_state(16);
        let req = PostAdminActionRequest {
            action_id: None,
            action_type: "unknown-action".to_string(),
            actor: None,
            reason: None,
            params: None,
        };

        let resp = post_admin_action(State(state), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json")
        );

        let body = json_body(resp).await;
        assert_eq!(body["status"], 400);
        assert_eq!(body["title"], "Bad Request");
        let detail = body["detail"].as_str().unwrap_or_default();
        assert!(
            detail.contains("unknown actionType"),
            "unexpected detail: {detail}"
        );
    }

    #[tokio::test]
    async fn admin_action_get_missing_returns_problem_details() {
        let state = test_app_state(16);
        let resp = get_admin_action(
            State(state),
            HeaderMap::new(),
            Path("missing-action".to_string()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers()
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/problem+json")
        );
        let body = json_body(resp).await;
        assert_eq!(body["status"], 404);
        assert_eq!(body["title"], "Not Found");
        assert!(body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("missing-action"));
    }

    #[tokio::test]
    async fn shard_map_requires_admin_scope_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);

        let unauthorized = get_shard_map(State(state.clone()), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let authorized = get_shard_map(State(state), dev_scope_headers("admin:read"))
            .await
            .into_response();
        assert_eq!(authorized.status(), StatusCode::OK);
    }

    // ── Phase 1 / 1.5 endpoint tests ─────────────────────────────────

    // ── Fact Store (PUT /v1/facts) ──────────────────────────────────

    #[tokio::test]
    async fn put_fact_returns_created() {
        let state = test_app_state(16);
        let body = corecrux_memory::fact_store::StoreFact {
            entity: "server".to_string(),
            key: "role".to_string(),
            value: "database primary".to_string(),
            source_receipt: Some("crx_abc".to_string()),
            confidence: 0.95,
        };

        let resp = put_fact(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = json_body(resp).await;
        assert!(body["fact_id"].as_str().unwrap().starts_with("f_"));
        assert_eq!(body["entity"], "server");
        assert_eq!(body["key"], "role");
        assert_eq!(body["value"], "database primary");
        assert_eq!(body["source_receipt"], "crx_abc");
        assert_eq!(body["deleted"], false);
    }

    // ── Fact Store (GET /v1/facts/{factId}) ─────────────────────────

    #[tokio::test]
    async fn get_fact_returns_stored_fact() {
        let state = test_app_state(16);
        let body = corecrux_memory::fact_store::StoreFact {
            entity: "deploy".to_string(),
            key: "strategy".to_string(),
            value: "canary".to_string(),
            source_receipt: None,
            confidence: 1.0,
        };

        let create_resp = put_fact(State(state.clone()), HeaderMap::new(), Json(body))
            .await
            .into_response();
        let created = json_body(create_resp).await;
        let fact_id = created["fact_id"].as_str().unwrap().to_string();

        let resp = get_fact(State(state), HeaderMap::new(), Path(fact_id.clone()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["fact_id"], fact_id);
        assert_eq!(body["value"], "canary");
    }

    #[tokio::test]
    async fn get_fact_not_found() {
        let state = test_app_state(16);
        let resp = get_fact(
            State(state),
            HeaderMap::new(),
            Path("nonexistent".to_string()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = json_body(resp).await;
        assert!(body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("nonexistent"));
    }

    // ── Fact Store (DELETE /v1/facts/{factId}) ──────────────────────

    #[tokio::test]
    async fn delete_fact_soft_deletes() {
        let state = test_app_state(16);
        let body = corecrux_memory::fact_store::StoreFact {
            entity: "e".to_string(),
            key: "k".to_string(),
            value: "v".to_string(),
            source_receipt: None,
            confidence: 1.0,
        };

        let create_resp = put_fact(State(state.clone()), HeaderMap::new(), Json(body))
            .await
            .into_response();
        let created = json_body(create_resp).await;
        let fact_id = created["fact_id"].as_str().unwrap().to_string();

        let del_resp = delete_fact(State(state.clone()), HeaderMap::new(), Path(fact_id.clone()))
            .await
            .into_response();
        assert_eq!(del_resp.status(), StatusCode::OK);
        let del_body = json_body(del_resp).await;
        assert_eq!(del_body["deleted"], true);

        // GET after delete should return 404
        let get_resp = get_fact(State(state), HeaderMap::new(), Path(fact_id))
            .await
            .into_response();
        assert_eq!(get_resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_fact_not_found() {
        let state = test_app_state(16);
        let resp = delete_fact(
            State(state),
            HeaderMap::new(),
            Path("no-such-fact".to_string()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── Fact Store (GET /v1/facts/entity/{entity}) ──────────────────

    #[tokio::test]
    async fn get_facts_by_entity_returns_matching() {
        let state = test_app_state(16);

        for (entity, key, value) in [
            ("proj-a", "name", "alpha"),
            ("proj-a", "status", "active"),
            ("proj-b", "name", "beta"),
        ] {
            let body = corecrux_memory::fact_store::StoreFact {
                entity: entity.to_string(),
                key: key.to_string(),
                value: value.to_string(),
                source_receipt: None,
                confidence: 1.0,
            };
            let _ = put_fact(State(state.clone()), HeaderMap::new(), Json(body))
                .await
                .into_response();
        }

        let resp = get_facts_by_entity(
            State(state),
            HeaderMap::new(),
            Path("proj-a".to_string()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let facts = body["facts"].as_array().expect("facts array");
        assert_eq!(facts.len(), 2);
    }

    #[tokio::test]
    async fn get_facts_by_entity_empty() {
        let state = test_app_state(16);
        let resp = get_facts_by_entity(
            State(state),
            HeaderMap::new(),
            Path("no-entity".to_string()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let facts = body["facts"].as_array().expect("facts array");
        assert!(facts.is_empty());
    }

    // ── Fact Store (PUT /v1/facts/bulk) ─────────────────────────────

    #[tokio::test]
    async fn bulk_store_facts() {
        let state = test_app_state(16);
        let facts = vec![
            corecrux_memory::fact_store::StoreFact {
                entity: "a".to_string(),
                key: "k1".to_string(),
                value: "v1".to_string(),
                source_receipt: None,
                confidence: 0.8,
            },
            corecrux_memory::fact_store::StoreFact {
                entity: "b".to_string(),
                key: "k2".to_string(),
                value: "v2".to_string(),
                source_receipt: Some("rcpt".to_string()),
                confidence: 0.9,
            },
        ];

        let resp = put_facts_bulk(State(state.clone()), HeaderMap::new(), Json(facts))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = json_body(resp).await;
        let stored = body["facts"].as_array().expect("facts array");
        assert_eq!(stored.len(), 2);
        assert_eq!(stored[0]["entity"], "a");
        assert_eq!(stored[1]["entity"], "b");

        // Verify they're queryable
        let store = state.fact_store.read().await;
        assert_eq!(store.count(), 2);
    }

    // ── Fact Store (GET /v1/facts?query=...) ────────────────────────

    #[tokio::test]
    async fn query_facts_by_keyword() {
        let state = test_app_state(16);
        for (entity, key, value) in [
            ("deploy", "method", "canary deployment"),
            ("testing", "approach", "integration tests"),
        ] {
            let body = corecrux_memory::fact_store::StoreFact {
                entity: entity.to_string(),
                key: key.to_string(),
                value: value.to_string(),
                source_receipt: None,
                confidence: 1.0,
            };
            let _ = put_fact(State(state.clone()), HeaderMap::new(), Json(body))
                .await
                .into_response();
        }

        let mut params = std::collections::HashMap::new();
        params.insert("query".to_string(), "canary".to_string());

        let resp = query_facts(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let facts = body["facts"].as_array().expect("facts array");
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0]["entity"], "deploy");
        assert!(body["total_tokens"].as_u64().unwrap() > 0);
    }

    #[tokio::test]
    async fn query_facts_no_params_returns_all() {
        let state = test_app_state(16);
        for i in 0..3 {
            let body = corecrux_memory::fact_store::StoreFact {
                entity: format!("e{}", i),
                key: "k".to_string(),
                value: format!("val{}", i),
                source_receipt: None,
                confidence: 1.0,
            };
            let _ = put_fact(State(state.clone()), HeaderMap::new(), Json(body))
                .await
                .into_response();
        }

        let params = std::collections::HashMap::new();
        let resp = query_facts(State(state), HeaderMap::new(), Query(params))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let facts = body["facts"].as_array().expect("facts array");
        assert_eq!(facts.len(), 3);
    }

    // ── Session Store (PUT /v1/sessions/{sessionId}/state) ──────────

    #[tokio::test]
    async fn put_session_state_creates_session() {
        let state = test_app_state(16);
        let session_data = serde_json::json!({
            "decisions": ["chose canary"],
            "open_questions": ["GPU timing"],
        });

        let resp = put_session_state(
            State(state.clone()),
            HeaderMap::new(),
            Path("sess-001".to_string()),
            Json(session_data.clone()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["session_id"], "sess-001");
        assert!(body["total_tokens"].as_u64().unwrap() > 0);
    }

    // ── Session Store (GET /v1/sessions/{sessionId}/state) ──────────

    #[tokio::test]
    async fn get_session_state_round_trip() {
        let state = test_app_state(16);
        let session_data = serde_json::json!({"step": 1, "context": "building"});

        let _ = put_session_state(
            State(state.clone()),
            HeaderMap::new(),
            Path("sess-rt".to_string()),
            Json(session_data.clone()),
        )
        .await
        .into_response();

        let resp = get_session_state(
            State(state),
            HeaderMap::new(),
            Path("sess-rt".to_string()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["session_id"], "sess-rt");
        assert_eq!(body["state"]["step"], 1);
        assert_eq!(body["state"]["context"], "building");
    }

    #[tokio::test]
    async fn get_session_state_not_found() {
        let state = test_app_state(16);
        let resp = get_session_state(
            State(state),
            HeaderMap::new(),
            Path("no-session".to_string()),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = json_body(resp).await;
        assert!(body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("no-session"));
    }

    #[tokio::test]
    async fn put_session_state_overwrites() {
        let state = test_app_state(16);

        let _ = put_session_state(
            State(state.clone()),
            HeaderMap::new(),
            Path("sess-ow".to_string()),
            Json(serde_json::json!({"v": 1})),
        )
        .await
        .into_response();

        let _ = put_session_state(
            State(state.clone()),
            HeaderMap::new(),
            Path("sess-ow".to_string()),
            Json(serde_json::json!({"v": 2, "extra": true})),
        )
        .await
        .into_response();

        let resp = get_session_state(
            State(state),
            HeaderMap::new(),
            Path("sess-ow".to_string()),
        )
        .await
        .into_response();
        let body = json_body(resp).await;
        assert_eq!(body["state"]["v"], 2);
        assert_eq!(body["state"]["extra"], true);
    }

    // ── Text Search (POST /v1/query/text-search) ────────────────────
    //
    // NOTE: text-search tests rely on the CORECRUXD_QUERY_TEXT_SEARCH env var
    // which is process-global. These tests set it to "1" and must be run with
    // --test-threads=1 if the feature-gate-off test is included. The enable
    // helper sets it once at the start of each test to minimise races.

    #[allow(deprecated)]
    fn enable_text_search() {
        std::env::set_var("CORECRUXD_QUERY_TEXT_SEARCH", "1");
    }

    fn build_test_ccxi(docs: &[&str]) -> Vec<u8> {
        let tenant_hash = xxhash_rust::xxh64::xxh64(b"tenant-a", 0);
        let mut builder = corecrux_index::CcxiBuilder::new(0, 1, 100);
        for (i, text) in docs.iter().enumerate() {
            builder.add_document(i as u32, text, (i as u32) * 100, tenant_hash);
        }
        builder.build()
    }

    async fn load_test_index(state: &AppState, ccxi_bytes: &[u8]) {
        let mut index = state.retrieval_index.write().await;
        index
            .load_ccxi_bytes(ccxi_bytes)
            .expect("load test ccxi");
    }

    #[tokio::test]
    async fn text_search_empty_index_returns_empty_results() {
        enable_text_search();

        let state = test_app_state(16);
        let body = TextSearchBody {
            tenant_id: "tenant-a".to_string(),
            query: "hello world".to_string(),
            limit: 10,
            token_budget: None,
            min_score: None,
            mode: None,
            include_receipt: None,
        };

        let resp = post_query_text_search(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let results = body["results"].as_array().expect("results array");
        assert!(results.is_empty());
        assert_eq!(body["coverage"]["score"], 0.0);
        assert_eq!(body["meta"]["segments_searched"], 0);
        assert_eq!(body["meta"]["total_docs"], 0);
    }

    #[tokio::test]
    async fn text_search_empty_query_returns_400() {
        enable_text_search();

        let state = test_app_state(16);
        let body = TextSearchBody {
            tenant_id: "tenant-a".to_string(),
            query: "   ".to_string(),
            limit: 10,
            token_budget: None,
            min_score: None,
            mode: None,
            include_receipt: None,
        };

        let resp = post_query_text_search(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn is_query_feature_disabled_by_default() {
        // Test the feature gate logic directly without env var mutation (avoids races)
        assert!(!is_query_feature_enabled("CORECRUXD_QUERY_TEXT_SEARCH_TEST_FAKE_ENV"));
    }

    #[tokio::test]
    async fn text_search_with_index_returns_hits() {
        enable_text_search();

        let state = test_app_state(16);
        let ccxi_bytes = build_test_ccxi(&[
            "the rust programming language is fast",
            "python is great for data science",
            "rust and python are both popular languages",
        ]);
        load_test_index(&state, &ccxi_bytes).await;

        let body = TextSearchBody {
            tenant_id: "tenant-a".to_string(),
            query: "rust programming".to_string(),
            limit: 10,
            token_budget: None,
            min_score: None,
            mode: None,
            include_receipt: None,
        };

        let resp = post_query_text_search(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let results = body["results"].as_array().expect("results array");
        assert!(!results.is_empty(), "should have at least one hit for 'rust programming'");
        assert!(body["meta"]["segments_searched"].as_u64().unwrap() > 0);
        assert!(body["meta"]["total_docs"].as_u64().unwrap() == 3);
        assert!(body["coverage"]["score"].as_f64().is_some());
    }

    #[tokio::test]
    async fn text_search_scan_mode() {
        enable_text_search();

        let state = test_app_state(16);
        let ccxi_bytes = build_test_ccxi(&["hello world test document"]);
        load_test_index(&state, &ccxi_bytes).await;

        let body = TextSearchBody {
            tenant_id: "tenant-a".to_string(),
            query: "hello".to_string(),
            limit: 10,
            token_budget: None,
            min_score: None,
            mode: Some("scan".to_string()),
            include_receipt: None,
        };

        let resp = post_query_text_search(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["scan_mode"], true);
    }

    #[tokio::test]
    async fn text_search_with_token_budget() {
        enable_text_search();

        let state = test_app_state(16);
        let ccxi_bytes = build_test_ccxi(&[
            "shared term document one with extra words here",
            "shared term document two also has extra words",
            "shared term document three many more words added",
        ]);
        load_test_index(&state, &ccxi_bytes).await;

        let body = TextSearchBody {
            tenant_id: "tenant-a".to_string(),
            query: "shared term".to_string(),
            limit: 10,
            token_budget: Some(10),
            min_score: None,
            mode: None,
            include_receipt: None,
        };

        let resp = post_query_text_search(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert!(body["tokens_used"].as_u64().is_some());
        assert!(body["tokens_available"].as_u64().unwrap() == 10);
    }

    // ── Text Search Expand (POST /v1/query/text-search/expand) ──────

    #[tokio::test]
    async fn text_search_expand_returns_chunks() {
        enable_text_search();

        let state = test_app_state(16);
        let ccxi_bytes = build_test_ccxi(&[
            "hello world test",
            "another document here",
        ]);
        load_test_index(&state, &ccxi_bytes).await;

        let body = TextSearchExpandBody {
            tenant_id: "tenant-a".to_string(),
            result_ids: vec![
                ExpandResultId {
                    segment_index: 0,
                    doc_id: 0,
                },
                ExpandResultId {
                    segment_index: 0,
                    doc_id: 1,
                },
            ],
        };

        let resp = post_query_text_search_expand(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let chunks = body["chunks"].as_array().expect("chunks array");
        assert_eq!(chunks.len(), 2);
        assert!(body["tokens_loaded"].as_u64().unwrap() > 0);
        assert_eq!(chunks[0]["segment_index"], 0);
        assert_eq!(chunks[0]["doc_id"], 0);
        assert_eq!(chunks[1]["doc_id"], 1);
    }

    #[tokio::test]
    async fn text_search_expand_skips_invalid_ids() {
        enable_text_search();

        let state = test_app_state(16);
        let ccxi_bytes = build_test_ccxi(&["only doc"]);
        load_test_index(&state, &ccxi_bytes).await;

        let body = TextSearchExpandBody {
            tenant_id: "tenant-a".to_string(),
            result_ids: vec![
                ExpandResultId {
                    segment_index: 0,
                    doc_id: 0,
                },
                ExpandResultId {
                    segment_index: 99,
                    doc_id: 0,
                },
                ExpandResultId {
                    segment_index: 0,
                    doc_id: 999,
                },
            ],
        };

        let resp = post_query_text_search_expand(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let chunks = body["chunks"].as_array().expect("chunks array");
        assert_eq!(chunks.len(), 1, "only valid doc should be returned");
    }

    #[tokio::test]
    async fn text_search_expand_empty_index() {
        enable_text_search();

        let state = test_app_state(16);

        let body = TextSearchExpandBody {
            tenant_id: "tenant-a".to_string(),
            result_ids: vec![ExpandResultId {
                segment_index: 0,
                doc_id: 0,
            }],
        };

        let resp = post_query_text_search_expand(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let chunks = body["chunks"].as_array().expect("chunks array");
        assert!(chunks.is_empty());
        assert_eq!(body["tokens_loaded"], 0);
    }

    #[test]
    fn is_query_feature_enabled_when_set_true() {
        #[allow(deprecated)]
        std::env::set_var("__TEST_GATE_ENABLED__", "1");
        assert!(is_query_feature_enabled("__TEST_GATE_ENABLED__"));
        #[allow(deprecated)]
        std::env::remove_var("__TEST_GATE_ENABLED__");
    }

    // ── Auth gating for Phase 1 / 1.5 endpoints (DevScopes) ────────

    #[tokio::test]
    async fn fact_endpoints_require_auth_in_dev_scopes_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);

        // PUT /v1/facts — no scopes → 401
        let body = corecrux_memory::fact_store::StoreFact {
            entity: "e".to_string(),
            key: "k".to_string(),
            value: "v".to_string(),
            source_receipt: None,
            confidence: 1.0,
        };
        let resp = put_fact(State(state.clone()), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // PUT /v1/facts — with query:read → 201
        let body2 = corecrux_memory::fact_store::StoreFact {
            entity: "e".to_string(),
            key: "k".to_string(),
            value: "v".to_string(),
            source_receipt: None,
            confidence: 1.0,
        };
        let resp2 = put_fact(
            State(state.clone()),
            dev_scope_headers("query:read"),
            Json(body2),
        )
        .await
        .into_response();
        assert_eq!(resp2.status(), StatusCode::CREATED);

        // GET /v1/sessions/{id}/state — no scopes → 401
        let resp3 = get_session_state(
            State(state),
            HeaderMap::new(),
            Path("sess".to_string()),
        )
        .await
        .into_response();
        assert_eq!(resp3.status(), StatusCode::UNAUTHORIZED);
    }

    // ── healthz ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn healthz_returns_ok_with_build_and_routing() {
        let state = test_app_state(16);
        let resp = healthz(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["ok"], true);
        assert_eq!(body["build"]["version"], "test");
        assert_eq!(body["build"]["commit"], "test");
        assert!(body["routing"]["shardMapVersion"].as_u64().is_some());
        assert!(body["routing"]["shardCount"].as_u64().unwrap() > 0);
        assert_eq!(body["routing"]["nodeId"], "node-a");
        // Valves should be present
        assert!(body["valves"]["pauseIngest"].is_object());
        assert!(body["valves"]["pauseCompaction"].is_object());
        assert!(body["valves"]["throttle"].is_object());
        assert!(body["valves"]["readOnly"].is_object());
        assert!(body["valves"]["emergencyBrake"].is_object());
    }

    #[tokio::test]
    async fn healthz_valves_reflect_control_state() {
        let state = test_app_state(16);
        {
            let mut c = state.control.write().await;
            c.valves.pause_ingest.set(true, "test", "unit-test", 123);
        }
        let resp = healthz(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["valves"]["pauseIngest"]["enabled"], true);
        assert_eq!(body["valves"]["pauseIngest"]["actor"], "test");
        assert_eq!(body["valves"]["pauseIngest"]["reason"], "unit-test");
    }

    // ── readyz (happy path) ──────────────────────────────────────────

    #[tokio::test]
    async fn readyz_returns_ok_when_all_checks_pass() {
        let state = test_app_state(16);
        mark_ready_except_control(&state).await;
        let resp = readyz(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["ok"], true);
    }

    #[tokio::test]
    async fn readyz_fails_when_lock_not_held() {
        let mut state = test_app_state(16);
        state.lock_held = false;
        mark_ready_except_control(&state).await;
        let resp = readyz(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json_body(resp).await;
        assert_eq!(body["ok"], false);
        let checks = body["checks"].as_array().expect("checks array");
        assert!(checks.iter().any(|c| c["name"] == "data_dir_lock_held"));
    }

    #[tokio::test]
    async fn readyz_fails_when_corruption_detected() {
        let state = test_app_state(16);
        mark_ready_except_control(&state).await;
        {
            *state.corruption_detected.write().await = true;
        }
        let resp = readyz(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json_body(resp).await;
        assert_eq!(body["ok"], false);
        let checks = body["checks"].as_array().expect("checks array");
        assert!(checks
            .iter()
            .any(|c| c["name"] == "corruption_state_clear"));
    }

    #[tokio::test]
    async fn readyz_fails_when_capacity_low() {
        let state = test_app_state(16);
        mark_ready_except_control(&state).await;
        {
            let mut cap = state.capacity.write().await;
            cap.free_ratio = 0.05; // Below emergency threshold of 0.10
            cap.free_bytes = 5;
            cap.total_bytes = 100;
        }
        let resp = readyz(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json_body(resp).await;
        assert_eq!(body["ok"], false);
        let checks = body["checks"].as_array().expect("checks array");
        assert!(checks.iter().any(|c| c["name"] == "data_dir_capacity"));
    }

    #[tokio::test]
    async fn readyz_fails_when_gpu_context_not_ready() {
        let state = test_app_state(16);
        // Only set some checks, leave gpu_context false (the default)
        {
            let mut readiness = state.readiness.write().await;
            readiness.kernel_module_loaded = true;
            readiness.smoke_kernel_ok = true;
            readiness.io_backend_ok = true;
            readiness.gds_active = true;
            readiness.hardware_profile_ok = true;
        }
        let resp = readyz(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json_body(resp).await;
        let checks = body["checks"].as_array().expect("checks array");
        assert!(checks.iter().any(|c| c["name"] == "gpu_context"));
    }

    // ── metrics ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn metrics_returns_prometheus_text() {
        let state = test_app_state(16);
        let resp = metrics(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            ct.contains("text/plain"),
            "expected text/plain, got: {ct}"
        );
        // Body should be non-empty prometheus text
        let body_bytes = to_bytes(resp.into_body(), 1_048_576)
            .await
            .expect("read body");
        assert!(!body_bytes.is_empty());
    }

    // ── get_gpus (no dataplane) ─────────────────────────────────────

    #[tokio::test]
    async fn get_gpus_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let resp = get_gpus(State(state), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        let body = json_body(resp).await;
        assert!(body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("dataplane disabled"));
    }

    // ── get_shards ──────────────────────────────────────────────────

    #[tokio::test]
    async fn get_shards_returns_shard_info() {
        let state = test_app_state(16);
        let resp = get_shards(State(state), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["nodeId"], "node-a");
        assert!(body["shardMapVersion"].as_u64().unwrap() > 0);
        assert_eq!(body["defaultGpuId"], 0);
        let shards = body["shards"].as_array().expect("shards array");
        assert_eq!(shards.len(), 1);
        assert_eq!(shards[0]["shardId"], "shard-0001");
        assert_eq!(shards[0]["epoch"], 1);
        assert_eq!(shards[0]["workerUp"], false);
        assert_eq!(shards[0]["shardHosted"], false);
    }

    #[tokio::test]
    async fn get_shards_requires_auth_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let resp = get_shards(State(state.clone()), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp2 = get_shards(State(state), dev_scope_headers("admin:read"))
            .await
            .into_response();
        assert_eq!(resp2.status(), StatusCode::OK);
    }

    // ── route_v1 ────────────────────────────────────────────────────

    #[tokio::test]
    async fn route_v1_returns_routing_decision() {
        let state = test_app_state(16);
        let q = RouteQuery {
            tenant_id: "tenant-a".to_string(),
            stream_type: "answers".to_string(),
            stream_id: "stream-1".to_string(),
        };
        let resp = route_v1(State(state), axum::extract::Query(q), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert!(body["streamHash"].as_str().is_some());
        assert_eq!(body["shardId"], "shard-0001");
        assert_eq!(body["epoch"], 1);
        assert!(body["shardMapVersion"].as_u64().unwrap() > 0);
        assert!(body["leaderGrpcAddr"].as_str().is_some());
        assert_eq!(body["leaderNodeId"], "node-a");
        assert_eq!(body["ownerGpuId"], 0);
        assert_eq!(body["workerUp"], false);
        assert_eq!(body["shardHosted"], false);
    }

    #[tokio::test]
    async fn route_v1_requires_auth_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let q = RouteQuery {
            tenant_id: "tenant-a".to_string(),
            stream_type: "answers".to_string(),
            stream_id: "stream-1".to_string(),
        };
        let resp = route_v1(State(state), axum::extract::Query(q), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── get_receipt_body_v1 (no dataplane) ──────────────────────────

    #[tokio::test]
    async fn get_receipt_body_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let resp = get_receipt_body_v1(
            State(state),
            Path("crx_abc".to_string()),
            Query(TenantQuery {
                tenant_id: "tenant-a".to_string(),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── get_receipt_signature_v1 (no dataplane) ─────────────────────

    #[tokio::test]
    async fn get_receipt_signature_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let resp = get_receipt_signature_v1(
            State(state),
            Path("crx_abc".to_string()),
            Query(TenantQuery {
                tenant_id: "tenant-a".to_string(),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── get_receipt_verification_v1 (no dataplane) ──────────────────

    #[tokio::test]
    async fn get_receipt_verification_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let resp = get_receipt_verification_v1(
            State(state),
            Path("crx_abc".to_string()),
            Query(TenantQuery {
                tenant_id: "tenant-a".to_string(),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── get_receipt_export_v1 (no dataplane) ────────────────────────

    #[tokio::test]
    async fn get_receipt_export_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let resp = get_receipt_export_v1(
            State(state),
            Path("crx_abc".to_string()),
            Query(ExportQueryV1 {
                tenant_id: "tenant-a".to_string(),
                include: None,
                redaction: None,
                format: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── get_answer_export_v1 (not found path) ───────────────────────

    #[tokio::test]
    async fn get_answer_export_not_found_without_subject_link() {
        let state = test_app_state(16);
        let resp = get_answer_export_v1(
            State(state),
            Path("ans-123".to_string()),
            Query(SubjectExportQueryV1 {
                tenant_id: "tenant-a".to_string(),
                mode: None,
                include: None,
                redaction: None,
                format: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_answer_export_invalid_mode() {
        let state = test_app_state(16);
        let resp = get_answer_export_v1(
            State(state),
            Path("ans-123".to_string()),
            Query(SubjectExportQueryV1 {
                tenant_id: "tenant-a".to_string(),
                mode: Some("bogus".to_string()),
                include: None,
                redaction: None,
                format: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = json_body(resp).await;
        assert!(body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("invalid mode"));
    }

    // ── get_action_export_v1 (not found path) ───────────────────────

    #[tokio::test]
    async fn get_action_export_not_found_without_subject_link() {
        let state = test_app_state(16);
        let resp = get_action_export_v1(
            State(state),
            Path("act-123".to_string()),
            Query(SubjectExportQueryV1 {
                tenant_id: "tenant-a".to_string(),
                mode: None,
                include: None,
                redaction: None,
                format: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── get_stream_export_v1 (no dataplane) ─────────────────────────

    #[tokio::test]
    async fn get_stream_export_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let resp = get_stream_export_v1(
            State(state),
            Path(("receipt".to_string(), "crx_abc".to_string())),
            Query(StreamExportQueryV1 {
                tenant_id: "tenant-a".to_string(),
                from_seq: None,
                to_seq: None,
                max_events: None,
                include: None,
                redaction: None,
                format: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── post_shard_map (not implemented) ────────────────────────────

    #[tokio::test]
    async fn post_shard_map_returns_501() {
        let state = test_app_state(16);
        let resp = post_shard_map(
            State(state),
            HeaderMap::new(),
            axum::body::Bytes::from_static(b"{}"),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        let body = json_body(resp).await;
        assert!(body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("CLI-only"));
    }

    // ── get_shard_map (happy path) ──────────────────────────────────

    #[tokio::test]
    async fn get_shard_map_returns_map_body() {
        let state = test_app_state(16);
        let resp = get_shard_map(State(state), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert!(body["currentVersion"].as_u64().unwrap() > 0);
        assert!(body["blake3"].as_str().is_some());
        let sm = &body["shardMap"];
        assert_eq!(sm["clusterId"], "test-cluster");
        assert_eq!(sm["shards"].as_array().unwrap().len(), 1);
    }

    // ── get_control (happy path, valves) ────────────────────────────

    #[tokio::test]
    async fn get_control_returns_valves() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        {
            let mut c = state.control.write().await;
            c.valves
                .pause_ingest
                .set(true, "ops", "maintenance", 1000);
        }
        let resp = get_control(State(state), dev_scope_headers("admin:read"))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert!(body["valves"]["pauseIngest"]["enabled"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn get_control_requires_auth_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let resp = get_control(State(state), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── get_ops_log (no dataplane) ──────────────────────────────────

    #[serial_test::serial]
    #[tokio::test]
    async fn get_ops_log_returns_precondition_failed_without_dataplane() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let resp = get_ops_log(
            State(state),
            Query(OpsLogQuery {
                node_id: None,
                since: None,
                until: None,
                from_seq: None,
                max_events: None,
            }),
            dev_scope_headers("admin:read"),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    }

    // ── post_valves (validation) ────────────────────────────────────

    #[tokio::test]
    async fn post_valves_rejects_empty_actor_and_reason() {
        let state = test_app_state(16);
        let req = SetValvesReq {
            actor: "".to_string(),
            reason: "".to_string(),
            pause_ingest: Some(true),
            pause_compaction: None,
            throttle: None,
            read_only: None,
            emergency_brake: None,
        };
        let resp = post_valves(State(state), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = json_body(resp).await;
        assert!(body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("actor and reason"));
    }

    // ── post_stream_meta (validation + no dataplane) ────────────────

    #[tokio::test]
    async fn post_stream_meta_rejects_empty_actor() {
        let state = test_app_state(16);
        let req = StreamMetaReq {
            tenant_id: "tenant-a".to_string(),
            stream_type: "answers".to_string(),
            stream_id: "stream-1".to_string(),
            min_live_seq: Some(5),
            tombstone_seq: None,
            actor: "  ".to_string(),
            reason: "  ".to_string(),
        };
        let resp = post_stream_meta(State(state), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_stream_meta_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let req = StreamMetaReq {
            tenant_id: "tenant-a".to_string(),
            stream_type: "answers".to_string(),
            stream_id: "stream-1".to_string(),
            min_live_seq: Some(5),
            tombstone_seq: None,
            actor: "ops".to_string(),
            reason: "cleanup".to_string(),
        };
        let resp = post_stream_meta(State(state), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── post_replication_segment (validation) ───────────────────────

    #[tokio::test]
    async fn post_replication_segment_rejects_empty_shard_id() {
        let state = test_app_state(16);
        let req = ReplicationSegmentReq {
            shard_id: "".to_string(),
            epoch: 1,
            leader_node_id: None,
            segment_base64: "AAAA".to_string(),
            segment_hash: None,
        };
        let resp = post_replication_segment(State(state), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = json_body(resp).await;
        assert!(body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("shardId"));
    }

    #[tokio::test]
    async fn post_replication_segment_rejects_empty_segment() {
        let state = test_app_state(16);
        let req = ReplicationSegmentReq {
            shard_id: "shard-0001".to_string(),
            epoch: 1,
            leader_node_id: None,
            segment_base64: "".to_string(),
            segment_hash: None,
        };
        let resp = post_replication_segment(State(state), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = json_body(resp).await;
        assert!(body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("segmentBase64"));
    }

    // ── post_admin_append (no dataplane) ────────────────────────────

    #[tokio::test]
    async fn post_admin_append_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let body = AppendBody {
            tenant_id: "tenant-a".to_string(),
            stream_type: "test".to_string(),
            stream_id: "stream-1".to_string(),
            expected_next_seq: 0,
            events: vec![AppendEventBody {
                event_id: "ev1".to_string(),
                occurred_at: "2026-01-01T00:00:00Z".to_string(),
                event_type: "test.v1".to_string(),
                content_type: "application/json".to_string(),
                payload: "{}".to_string(),
            }],
        };
        let resp = post_admin_append(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn post_admin_append_requires_auth_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let body = AppendBody {
            tenant_id: "tenant-a".to_string(),
            stream_type: "test".to_string(),
            stream_id: "stream-1".to_string(),
            expected_next_seq: 0,
            events: vec![AppendEventBody {
                event_id: "ev1".to_string(),
                occurred_at: "2026-01-01T00:00:00Z".to_string(),
                event_type: "test.v1".to_string(),
                content_type: "application/json".to_string(),
                payload: "{}".to_string(),
            }],
        };
        let resp = post_admin_append(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── post_query_graph_expand (feature gate + no dataplane) ───────

    #[tokio::test]
    async fn post_query_graph_expand_returns_not_found_when_disabled() {
        // Feature gate is off by default
        let state = test_app_state(16);
        let body = GraphExpandBody {
            tenant_id: "tenant-a".to_string(),
            seed_artifact_ids: vec![1, 2],
            edge_types: vec![],
            max_hops: 2,
            budget: 50,
            min_confidence: 0.0,
            include_state: false,
        };
        let resp = post_query_graph_expand(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── post_query_time_range (feature gate + validation) ───────────

    #[tokio::test]
    async fn post_query_time_range_returns_not_found_when_disabled() {
        let state = test_app_state(16);
        let body = TimeRangeBody {
            tenant_id: "tenant-a".to_string(),
            start_micros: 1000,
            end_micros: 2000,
            artifact_ids: vec![],
            include_relations: false,
            limit: 10,
        };
        let resp = post_query_time_range(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── get_proj_meta (no dataplane) ────────────────────────────────

    #[tokio::test]
    async fn get_proj_meta_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let resp = get_proj_meta(
            State(state),
            Query(ProjMetaQuery {
                shard_id: "shard-0001".to_string(),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── post_projection_rebuild (no dataplane) ──────────────────────

    #[tokio::test]
    async fn post_projection_rebuild_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let resp = post_projection_rebuild(State(state), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── get_proj_artifact_state (no dataplane) ──────────────────────

    #[tokio::test]
    async fn get_proj_artifact_state_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let resp = get_proj_artifact_state(
            State(state),
            Path(1u32),
            Query(TenantQuery {
                tenant_id: "tenant-a".to_string(),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── get_proj_artifact_relations (no dataplane) ──────────────────

    #[tokio::test]
    async fn get_proj_artifact_relations_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let resp = get_proj_artifact_relations(
            State(state),
            Path(1u32),
            Query(RelationsQuery {
                tenant_id: "tenant-a".to_string(),
                direction: None,
                relation_type: None,
                limit: None,
                offset: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── get_proj_artifact_dependents (no dataplane) ─────────────────

    #[tokio::test]
    async fn get_proj_artifact_dependents_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let resp = get_proj_artifact_dependents(
            State(state),
            Path(1u32),
            Query(DependentsQuery {
                tenant_id: "tenant-a".to_string(),
                dependent_type: None,
                limit: None,
                offset: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── get_proj_artifact_pressure_events (no dataplane) ────────────

    #[tokio::test]
    async fn get_proj_artifact_pressure_events_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let resp = get_proj_artifact_pressure_events(
            State(state),
            Path(1u32),
            Query(PressureQuery {
                tenant_id: "tenant-a".to_string(),
                open_only: None,
                limit: None,
                offset: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── Entity projection endpoints (no dataplane) ──────────────────

    #[tokio::test]
    async fn get_entity_count_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let mut params = std::collections::HashMap::new();
        params.insert("tenant_id".to_string(), "tenant-a".to_string());
        params.insert("entity_type".to_string(), "server".to_string());
        let resp = get_entity_count(State(state), axum::extract::Query(params))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn get_entity_timeline_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let mut params = std::collections::HashMap::new();
        params.insert("tenant_id".to_string(), "tenant-a".to_string());
        let resp = get_entity_timeline(State(state), axum::extract::Query(params))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn get_entity_current_state_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let mut params = std::collections::HashMap::new();
        params.insert("tenant_id".to_string(), "tenant-a".to_string());
        params.insert("entity_name".to_string(), "server-1".to_string());
        let resp = get_entity_current_state(State(state), axum::extract::Query(params))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── get_replication_status ──────────────────────────────────────

    #[tokio::test]
    async fn get_replication_status_returns_ok_without_dataplane() {
        let state = test_app_state(16);
        let resp = get_replication_status(State(state), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["nodeId"], "node-a");
        assert_eq!(body["commitLevel"], "LocalCommit");
        assert!(body["shardMapVersion"].as_u64().unwrap() > 0);
        let shards = body["shards"].as_array().expect("shards array");
        assert_eq!(shards.len(), 1);
        assert_eq!(shards[0]["shardId"], "shard-0001");
        assert_eq!(shards[0]["role"], "leader");
    }

    #[tokio::test]
    async fn get_replication_status_requires_auth_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let resp = get_replication_status(State(state), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── route_debug (happy path) ────────────────────────────────────

    #[tokio::test]
    async fn route_debug_returns_routing_info() {
        let state = test_app_state(16);
        let q = RouteQuery {
            tenant_id: "tenant-a".to_string(),
            stream_type: "answers".to_string(),
            stream_id: "stream-1".to_string(),
        };
        let resp = route_debug(State(state), axum::extract::Query(q), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert!(body["streamHash"].as_str().is_some());
        assert_eq!(body["shardId"], "shard-0001");
        assert_eq!(body["epoch"], 1);
    }

    // ── routing_status (happy path) ─────────────────────────────────

    #[tokio::test]
    async fn routing_status_returns_version_and_shards() {
        let state = test_app_state(16);
        let resp = routing_status(State(state), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert!(body["routingTableVersion"].as_u64().unwrap() > 0);
        assert!(body["lastReloadAt"].as_str().is_some());
        let shards = body["shardsLoaded"].as_array().expect("shardsLoaded array");
        // Without dataplane, lists shards from shard map
        assert_eq!(shards.len(), 1);
        assert_eq!(shards[0], "shard-0001");
    }

    // ── parse_receipt_export_options_v1 ─────────────────────────────

    #[test]
    fn parse_export_options_defaults() {
        let opts = parse_receipt_export_options_v1(None, None, None).unwrap();
        assert!(matches!(opts.format, ExportFormatV1::Zip));
        assert!(matches!(opts.redaction, ExportRedactionV1::TenantSafe));
        assert!(opts.include.is_empty());
    }

    #[test]
    fn parse_export_options_invalid_format() {
        let result = parse_receipt_export_options_v1(None, None, Some("badformat"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid format"));
    }

    #[test]
    fn parse_export_options_invalid_redaction() {
        let result = parse_receipt_export_options_v1(None, Some("badredaction"), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid redaction"));
    }

    #[test]
    fn parse_export_options_invalid_include() {
        let result = parse_receipt_export_options_v1(Some("badinclude"), None, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid include"));
    }

    #[test]
    fn parse_export_options_valid_include() {
        let opts = parse_receipt_export_options_v1(Some("body,sig"), None, None).unwrap();
        assert_eq!(opts.include.len(), 2);
    }

    // ── wants_cbor ──────────────────────────────────────────────────

    #[test]
    fn wants_cbor_false_by_default() {
        let headers = HeaderMap::new();
        assert!(!wants_cbor(&headers));
    }

    #[test]
    fn wants_cbor_true_with_accept_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/cbor"),
        );
        assert!(wants_cbor(&headers));
    }

    #[test]
    fn wants_cbor_true_with_mixed_accept() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/json, application/cbor"),
        );
        assert!(wants_cbor(&headers));
    }

    #[test]
    fn wants_cbor_false_for_json_only() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::ACCEPT,
            HeaderValue::from_static("application/json"),
        );
        assert!(!wants_cbor(&headers));
    }

    // ── hex16 / hex32 ───────────────────────────────────────────────

    #[test]
    fn hex16_formats_correctly() {
        let bytes = [0u8; 16];
        assert_eq!(hex16(&bytes), "00000000000000000000000000000000");
        let bytes2 = [0xFF; 16];
        assert_eq!(hex16(&bytes2), "ffffffffffffffffffffffffffffffff");
    }

    #[test]
    fn hex32_formats_correctly() {
        let bytes = [0u8; 32];
        assert_eq!(hex32(&bytes).len(), 64);
        assert_eq!(hex32(&bytes), "0".repeat(64));
    }

    // ── problem_for_status ──────────────────────────────────────────

    #[test]
    fn problem_for_status_sets_correct_fields() {
        let problem = problem_for_status(StatusCode::BAD_REQUEST, "test error");
        let resp = problem.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn problem_for_status_not_found() {
        let problem = problem_for_status(StatusCode::NOT_FOUND, "not here");
        let resp = problem.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn problem_for_status_service_unavailable() {
        let problem = problem_for_status(StatusCode::SERVICE_UNAVAILABLE, "down");
        let resp = problem.into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn problem_for_status_payload_too_large() {
        let problem = problem_for_status(StatusCode::PAYLOAD_TOO_LARGE, "too big");
        let resp = problem.into_response();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ── is_known_admin_action ───────────────────────────────────────

    #[test]
    fn known_admin_actions_match() {
        assert!(is_known_admin_action("verify-store"));
        assert!(is_known_admin_action("scrub-now"));
        assert!(is_known_admin_action("snapshot-verify"));
        assert!(is_known_admin_action("projection-rebuild"));
        assert!(is_known_admin_action("parity-pack"));
        assert!(is_known_admin_action("runtime-knob-update"));
        assert!(is_known_admin_action("force-seal"));
        assert!(!is_known_admin_action("unknown"));
        assert!(!is_known_admin_action(""));
    }

    // ── read_param helpers ──────────────────────────────────────────

    #[test]
    fn read_param_str_extracts_value() {
        let v = serde_json::json!({"key": "value", "empty": "", "ws": "  "});
        assert_eq!(read_param_str(Some(&v), "key"), Some("value"));
        assert_eq!(read_param_str(Some(&v), "missing"), None);
        assert_eq!(read_param_str(Some(&v), "empty"), None);
        assert_eq!(read_param_str(Some(&v), "ws"), None);
        assert_eq!(read_param_str(None, "key"), None);
    }

    #[test]
    fn read_param_bool_extracts_value() {
        let v = serde_json::json!({"t": true, "f": false, "s_true": "yes", "s_false": "no", "bad": "maybe"});
        assert_eq!(read_param_bool(Some(&v), "t"), Some(true));
        assert_eq!(read_param_bool(Some(&v), "f"), Some(false));
        assert_eq!(read_param_bool(Some(&v), "s_true"), Some(true));
        assert_eq!(read_param_bool(Some(&v), "s_false"), Some(false));
        assert_eq!(read_param_bool(Some(&v), "bad"), None);
        assert_eq!(read_param_bool(Some(&v), "missing"), None);
        assert_eq!(read_param_bool(None, "t"), None);
    }

    #[test]
    fn read_param_u64_extracts_value() {
        let v = serde_json::json!({"n": 42, "s": "100", "bad": "xyz"});
        assert_eq!(read_param_u64(Some(&v), "n"), Some(42));
        assert_eq!(read_param_u64(Some(&v), "s"), Some(100));
        assert_eq!(read_param_u64(Some(&v), "bad"), None);
        assert_eq!(read_param_u64(Some(&v), "missing"), None);
        assert_eq!(read_param_u64(None, "n"), None);
    }

    #[test]
    fn read_param_u32_extracts_value() {
        let v = serde_json::json!({"n": 42, "big": 5000000000u64});
        assert_eq!(read_param_u32(Some(&v), "n"), Some(42));
        assert_eq!(read_param_u32(Some(&v), "big"), None); // u32 overflow
    }

    #[test]
    fn read_param_f64_extracts_value() {
        let v = serde_json::json!({"n": 3.14, "s": "2.5", "bad": "xyz"});
        assert_eq!(read_param_f64(Some(&v), "n"), Some(3.14));
        assert_eq!(read_param_f64(Some(&v), "s"), Some(2.5));
        assert_eq!(read_param_f64(Some(&v), "bad"), None);
        assert_eq!(read_param_f64(None, "n"), None);
    }

    // ── parse_tenant_throttle_rules ─────────────────────────────────

    #[test]
    fn parse_tenant_throttle_rules_valid() {
        let v = serde_json::json!([
            {"tenantId": "t1", "eventsPerSec": 10, "bytesPerSec": 1024, "maxInFlight": 3}
        ]);
        let rules = parse_tenant_throttle_rules(&v).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].tenant_id, "t1");
    }

    #[test]
    fn parse_tenant_throttle_rules_empty_tenant_id() {
        let v = serde_json::json!([
            {"tenantId": "  ", "eventsPerSec": 10}
        ]);
        let result = parse_tenant_throttle_rules(&v);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-empty tenantId"));
    }

    #[test]
    fn parse_tenant_throttle_rules_invalid_json() {
        let v = serde_json::json!("not an array");
        let result = parse_tenant_throttle_rules(&v);
        assert!(result.is_err());
    }

    // ── parse_knowledge_authority_mode / rollout_stage ──────────────

    #[test]
    fn parse_knowledge_authority_modes() {
        assert!(parse_knowledge_authority_mode("knowledge_shadow").is_some());
        assert!(parse_knowledge_authority_mode("shadow").is_some());
        assert!(parse_knowledge_authority_mode("knowledge_dual_write").is_some());
        assert!(parse_knowledge_authority_mode("dual_write").is_some());
        assert!(parse_knowledge_authority_mode("knowledge_shadow_read").is_some());
        assert!(parse_knowledge_authority_mode("knowledge_authoritative").is_some());
        assert!(parse_knowledge_authority_mode("authoritative").is_some());
        assert!(parse_knowledge_authority_mode("invalid").is_none());
        assert!(parse_knowledge_authority_mode("").is_none());
    }

    #[test]
    fn parse_knowledge_rollout_stages() {
        assert!(parse_knowledge_rollout_stage("internal_shadow").is_some());
        assert!(parse_knowledge_rollout_stage("shadow").is_some());
        assert!(parse_knowledge_rollout_stage("tenant_validation").is_some());
        assert!(parse_knowledge_rollout_stage("internal_authority").is_some());
        assert!(parse_knowledge_rollout_stage("limited_production_authority").is_some());
        assert!(parse_knowledge_rollout_stage("full_production_authority").is_some());
        assert!(parse_knowledge_rollout_stage("invalid").is_none());
        assert!(parse_knowledge_rollout_stage("").is_none());
    }

    #[test]
    fn parse_knowledge_parity_statuses() {
        assert!(parse_knowledge_parity_status("unknown").is_some());
        assert!(parse_knowledge_parity_status("pass").is_some());
        assert!(parse_knowledge_parity_status("warn").is_some());
        assert!(parse_knowledge_parity_status("fail").is_some());
        assert!(parse_knowledge_parity_status("invalid").is_none());
        assert!(parse_knowledge_parity_status("").is_none());
    }

    // ── admin_action_error ──────────────────────────────────────────

    #[test]
    fn admin_action_error_wraps_message() {
        let err = admin_action_error("something broke");
        assert!(err.contains("something broke"));
    }

    // ── post_admin_action (queue full) ──────────────────────────────

    #[tokio::test]
    async fn post_admin_action_queue_full_returns_503() {
        let state = test_app_state(1); // max 1 pending
        // Submit first action
        let req1 = PostAdminActionRequest {
            action_id: Some("act-fill-1".to_string()),
            action_type: "runtime-knob-update".to_string(),
            actor: Some("test".to_string()),
            reason: Some("fill queue".to_string()),
            params: Some(serde_json::json!({"throttleEnabled": false})),
        };
        let resp1 = post_admin_action(State(state.clone()), HeaderMap::new(), Json(req1))
            .await
            .into_response();
        assert_eq!(resp1.status(), StatusCode::ACCEPTED);

        // Wait briefly for background task
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Manually put an action into running state to block queue
        {
            let mut actions = state.admin_actions.write().await;
            actions.insert(
                "act-running-1".to_string(),
                AdminActionRecord {
                    action_id: "act-running-1".to_string(),
                    action_type: "verify-store".to_string(),
                    status: AdminActionStatus::Running,
                    submitted_at_unix_ms: 1000,
                    started_at_unix_ms: Some(1000),
                    finished_at_unix_ms: None,
                    actor: None,
                    reason: None,
                    params: None,
                    result: None,
                    error: None,
                    auth_context: None,
                    request_context: None,
                },
            );
        }

        // Submit another (should be rejected)
        let req2 = PostAdminActionRequest {
            action_id: Some("act-overflow".to_string()),
            action_type: "runtime-knob-update".to_string(),
            actor: Some("test".to_string()),
            reason: Some("overflow".to_string()),
            params: Some(serde_json::json!({"throttleEnabled": true})),
        };
        let resp2 = post_admin_action(State(state), HeaderMap::new(), Json(req2))
            .await
            .into_response();
        assert_eq!(resp2.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn post_admin_action_empty_type_returns_400() {
        let state = test_app_state(16);
        let req = PostAdminActionRequest {
            action_id: None,
            action_type: "  ".to_string(),
            actor: None,
            reason: None,
            params: None,
        };
        let resp = post_admin_action(State(state), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_admin_action_too_long_id_returns_400() {
        let state = test_app_state(16);
        let req = PostAdminActionRequest {
            action_id: Some("x".repeat(200)),
            action_type: "runtime-knob-update".to_string(),
            actor: None,
            reason: None,
            params: None,
        };
        let resp = post_admin_action(State(state), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = json_body(resp).await;
        assert!(body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("128 characters"));
    }

    // ── to_valve_info ───────────────────────────────────────────────

    #[test]
    fn to_valve_info_maps_fields() {
        let v = control::ValveV1 {
            enabled: true,
            actor: "ops".to_string(),
            reason: "test".to_string(),
            updated_at_unix_ns: 999,
            retry_after_ms: Some(5000),
            events_per_sec: None,
            bytes_per_sec: None,
            max_in_flight: None,
        };
        let info = to_valve_info(&v);
        assert!(info.enabled);
        assert_eq!(info.actor, "ops");
        assert_eq!(info.reason, "test");
        assert_eq!(info.updated_at_unix_ns, 999);
        assert_eq!(info.retry_after_ms, Some(5000));
    }

    // ── default value functions ─────────────────────────────────────

    #[test]
    fn default_values_are_correct() {
        assert_eq!(default_max_hops(), 2);
        assert_eq!(default_budget(), 50);
        assert_eq!(default_time_range_limit(), 100);
        assert_eq!(default_text_search_limit(), 10);
        assert_eq!(default_content_type(), "application/json");
    }

    // ── map_store_error_http ────────────────────────────────────────

    #[test]
    fn map_store_error_bad_request() {
        let err = AppendError::InvalidArgument("test".to_string());
        let resp = map_store_error_http(err).into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn map_store_error_precondition_failed() {
        let err = AppendError::FailedPrecondition("test".to_string());
        let resp = map_store_error_http(err).into_response();
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[test]
    fn map_store_error_rate_limited() {
        let err = AppendError::ResourceExhausted("test".to_string());
        let resp = map_store_error_http(err).into_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn map_store_error_io_backend() {
        let err = AppendError::IoBackend("test".to_string());
        let resp = map_store_error_http(err).into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn map_store_error_internal() {
        let err = AppendError::Internal("test".to_string());
        let resp = map_store_error_http(err).into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn map_store_error_shard_unavailable() {
        let err = AppendError::ShardUnavailable {
            shard_id: "shard-0001".to_string(),
            owner_gpu_id: 0,
            current_shard_map_version: 1,
        };
        let resp = map_store_error_http(err).into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn map_store_error_wrong_shard() {
        let err = AppendError::WrongShard {
            leader_grpc_addr: "http://localhost:50051".to_string(),
            current_shard_map_version: 1,
        };
        let resp = map_store_error_http(err).into_response();
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[test]
    fn map_store_error_version_mismatch() {
        let err = AppendError::ShardMapVersionMismatch {
            client_version: 1,
            current_version: 2,
        };
        let resp = map_store_error_http(err).into_response();
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    }

    // ── Readiness default ───────────────────────────────────────────

    #[test]
    fn readiness_default_has_correct_values() {
        let r = Readiness::default();
        assert!(!r.gpu_context);
        assert!(!r.kernel_module_loaded);
        assert!(!r.smoke_kernel_ok);
        assert!(!r.io_backend_ok);
        assert!(!r.gds_active);
        assert!(!r.gds_degraded);
        assert!(!r.hardware_profile_ok);
        assert!(!r.control_evidence_hosted);
        assert!(r.control_evidence_ok); // default is true
    }

    // ── CapacityState default ───────────────────────────────────────

    #[test]
    fn capacity_state_default_has_correct_values() {
        let c = CapacityState::default();
        assert_eq!(c.total_bytes, 0);
        assert_eq!(c.free_bytes, 0);
        assert_eq!(c.free_ratio, 1.0);
        assert!(!c.auto_paused);
        assert!(c.error.is_none());
    }

    #[tokio::test]
    async fn routing_debug_and_status_require_admin_scope_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let query = RouteQuery {
            tenant_id: "tenant-a".to_string(),
            stream_type: "answers".to_string(),
            stream_id: "stream-a".to_string(),
        };

        let debug_unauthorized = route_debug(
            State(state.clone()),
            axum::extract::Query(query),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(debug_unauthorized.status(), StatusCode::UNAUTHORIZED);

        let debug_authorized = route_debug(
            State(state.clone()),
            axum::extract::Query(RouteQuery {
                tenant_id: "tenant-a".to_string(),
                stream_type: "answers".to_string(),
                stream_id: "stream-a".to_string(),
            }),
            dev_scope_headers("admin:read"),
        )
        .await
        .into_response();
        assert_eq!(debug_authorized.status(), StatusCode::OK);

        let status_unauthorized = routing_status(State(state.clone()), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(status_unauthorized.status(), StatusCode::UNAUTHORIZED);

        let status_authorized = routing_status(State(state), dev_scope_headers("admin:read"))
            .await
            .into_response();
        assert_eq!(status_authorized.status(), StatusCode::OK);
    }

    // ── trace_id_from_traceparent ──────────────────────────────────

    #[test]
    fn trace_id_from_traceparent_valid() {
        let tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        let id = trace_id_from_traceparent(Some(tp));
        assert_eq!(id.as_deref(), Some("0af7651916cd43dd8448eb211c80319c"));
    }

    #[test]
    fn trace_id_from_traceparent_none() {
        assert_eq!(trace_id_from_traceparent(None), None);
    }

    #[test]
    fn trace_id_from_traceparent_invalid_length() {
        let tp = "00-tooshort-span-01";
        assert_eq!(trace_id_from_traceparent(Some(tp)), None);
    }

    #[test]
    fn trace_id_from_traceparent_non_hex() {
        let tp = "00-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-span-01";
        assert_eq!(trace_id_from_traceparent(Some(tp)), None);
    }

    #[test]
    fn trace_id_from_traceparent_missing_parts() {
        assert_eq!(trace_id_from_traceparent(Some("00")), None);
        assert_eq!(trace_id_from_traceparent(Some("")), None);
    }

    // ── evaluate_replicated_commit_topology ─────────────────────────

    #[test]
    fn evaluate_replicated_commit_topology_no_followers() {
        let routing = test_routing();
        let status = evaluate_replicated_commit_topology(&routing, "node-a");
        assert_eq!(status.local_leader_shards, 1);
        assert_eq!(status.missing_followers.len(), 1);
        assert_eq!(status.missing_followers[0], "shard-0001");
    }

    #[test]
    fn evaluate_replicated_commit_topology_with_followers() {
        let mut map = ShardMapV1 {
            v: SHARDMAP_V1,
            cluster_id: "test-cluster".to_string(),
            version: 1,
            created_at: "2026-03-04T00:00:00Z".to_string(),
            hash_fn: SHARDMAP_HASH_FN_V1.to_string(),
            key_encoding: SHARDMAP_KEY_ENCODING_V1.to_string(),
            shards: vec![ShardDescriptor {
                shard_id: "shard-0001".to_string(),
                epoch: 1,
                state: ShardState::Active,
                ranges: vec![HashRange {
                    start_inclusive: format_u64_hex(0),
                    end_exclusive: format_u64_hex(0),
                }],
                leader: test_node("node-a", "http://127.0.0.1:4006", "http://127.0.0.1:50051"),
                followers: Some(vec![
                    test_node("node-b", "http://node-b:4006", "http://node-b:50051"),
                ]),
                data_dir: None,
                gpu_id: Some(0),
            }],
            blake3: String::new(),
            prev_blake3: None,
        };
        map.blake3 = compute_shard_map_v1_blake3_hex(&map).expect("hash");
        let routing = RoutingTable::new(LoadedShardMap {
            current_version: map.version,
            shard_map: map,
        })
        .expect("routing table");
        let status = evaluate_replicated_commit_topology(&routing, "node-a");
        assert_eq!(status.local_leader_shards, 1);
        assert!(status.missing_followers.is_empty());
    }

    #[test]
    fn evaluate_replicated_commit_topology_not_leader() {
        let routing = test_routing();
        let status = evaluate_replicated_commit_topology(&routing, "node-b");
        assert_eq!(status.local_leader_shards, 0);
        assert!(status.missing_followers.is_empty());
    }

    // ── build_trace_summary_json_v1 ────────────────────────────────

    #[test]
    fn build_trace_summary_valid_json() {
        let bytes = build_trace_summary_json_v1("tenant-a", "crx_abc", b"{}");
        let val: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
        assert_eq!(val["schema"], "cuecrux.receipt.trace_summary.v1");
        assert_eq!(val["tenant_id"], "tenant-a");
        assert_eq!(val["receipt_id"], "crx_abc");
    }

    #[test]
    fn build_trace_summary_unparseable_body() {
        let bytes = build_trace_summary_json_v1("t", "r", b"not-json");
        let val: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
        assert_eq!(val["parse_ok"], false);
    }

    // ── build_subject_links_json_v1 ────────────────────────────────

    #[test]
    fn build_subject_links_valid_json() {
        let bytes = build_subject_links_json_v1("tenant-a", "crx_abc", b"{}");
        let val: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
        assert_eq!(val["schema"], "cuecrux.receipt.subject_links.v1");
        assert_eq!(val["tenant_id"], "tenant-a");
        assert_eq!(val["receipt_id"], "crx_abc");
    }

    #[test]
    fn build_subject_links_unparseable_body() {
        let bytes = build_subject_links_json_v1("t", "r", b"not-json");
        let val: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
        assert_eq!(val["parse_ok"], false);
    }

    // ── build_lineage_json_v1 ──────────────────────────────────────

    #[test]
    fn build_lineage_valid_json() {
        let bytes = build_lineage_json_v1("tenant-a", "crx_abc", b"{}");
        let val: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
        assert_eq!(val["schema"], "cuecrux.receipt.lineage.v1");
        assert_eq!(val["tenant_id"], "tenant-a");
        assert_eq!(val["receipt_id"], "crx_abc");
    }

    #[test]
    fn build_lineage_unparseable_body() {
        let bytes = build_lineage_json_v1("t", "r", b"not-json");
        let val: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
        assert_eq!(val["parse_ok"], false);
    }

    // ── build_zip_deterministic_bytes ──────────────────────────────

    #[test]
    fn build_zip_deterministic_round_trip() {
        let files = vec![
            ("hello.txt".to_string(), b"hello world".to_vec()),
            ("sub/nested.json".to_string(), b"{}".to_vec()),
        ];
        let bytes = build_zip_deterministic_bytes(&files).expect("zip build");
        assert!(!bytes.is_empty());

        // Verify it's a valid zip
        let cursor = std::io::Cursor::new(&bytes);
        let mut archive = zip::ZipArchive::new(cursor).expect("valid zip");
        assert_eq!(archive.len(), 2);
        let names: Vec<String> = (0..archive.len())
            .map(|i| archive.by_index(i).unwrap().name().to_string())
            .collect();
        assert!(names.contains(&"hello.txt".to_string()));
        assert!(names.contains(&"sub/nested.json".to_string()));
    }

    #[test]
    fn build_zip_deterministic_empty() {
        let bytes = build_zip_deterministic_bytes(&[]).expect("empty zip");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn build_zip_deterministic_is_reproducible() {
        let files = vec![("a.txt".to_string(), b"data".to_vec())];
        let b1 = build_zip_deterministic_bytes(&files).expect("zip1");
        let b2 = build_zip_deterministic_bytes(&files).expect("zip2");
        assert_eq!(b1, b2, "deterministic zip must be reproducible");
    }

    // ── build_tar_zst_deterministic_bytes ──────────────────────────

    #[test]
    fn build_tar_zst_deterministic_round_trip() {
        let files = vec![
            ("file1.txt".to_string(), b"content1".to_vec()),
            ("file2.bin".to_string(), vec![0u8; 64]),
        ];
        let bytes = build_tar_zst_deterministic_bytes(&files).expect("tar.zst build");
        assert!(!bytes.is_empty());

        // Decompress and verify
        let decompressed = zstd::decode_all(std::io::Cursor::new(&bytes)).expect("zstd decompress");
        let mut archive = tar::Archive::new(std::io::Cursor::new(&decompressed));
        let entries: Vec<String> = archive
            .entries()
            .expect("entries")
            .filter_map(|e| e.ok())
            .map(|e| e.path().unwrap().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn build_tar_zst_deterministic_is_reproducible() {
        let files = vec![("a.txt".to_string(), b"data".to_vec())];
        let b1 = build_tar_zst_deterministic_bytes(&files).expect("tar.zst 1");
        let b2 = build_tar_zst_deterministic_bytes(&files).expect("tar.zst 2");
        assert_eq!(b1, b2, "deterministic tar.zst must be reproducible");
    }

    // ── post_valves (happy path with pause_ingest) ─────────────────

    #[tokio::test]
    async fn post_valves_sets_pause_ingest() {
        let state = test_app_state(16);
        let req = SetValvesReq {
            actor: "ops".to_string(),
            reason: "maintenance window".to_string(),
            pause_ingest: Some(true),
            pause_compaction: None,
            throttle: None,
            read_only: None,
            emergency_brake: None,
        };
        let resp = post_valves(State(state.clone()), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let c = state.control.read().await;
        assert!(c.valves.pause_ingest.enabled);
        assert_eq!(c.valves.pause_ingest.actor, "ops");
        assert_eq!(c.valves.pause_ingest.reason, "maintenance window");
    }

    #[tokio::test]
    async fn post_valves_sets_read_only() {
        let state = test_app_state(16);
        let req = SetValvesReq {
            actor: "ops".to_string(),
            reason: "pre-upgrade".to_string(),
            pause_ingest: None,
            pause_compaction: None,
            throttle: None,
            read_only: Some(true),
            emergency_brake: None,
        };
        let resp = post_valves(State(state.clone()), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let c = state.control.read().await;
        assert!(c.valves.read_only.enabled);
    }

    #[tokio::test]
    async fn post_valves_emergency_brake_cascades() {
        let state = test_app_state(16);
        let req = SetValvesReq {
            actor: "ops".to_string(),
            reason: "emergency".to_string(),
            pause_ingest: None,
            pause_compaction: None,
            throttle: None,
            read_only: None,
            emergency_brake: Some(true),
        };
        let resp = post_valves(State(state.clone()), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let c = state.control.read().await;
        assert!(c.valves.emergency_brake.enabled);
        assert!(c.valves.read_only.enabled, "emergency brake implies read_only");
        assert!(c.valves.pause_ingest.enabled, "emergency brake implies pause_ingest");
        assert!(c.valves.pause_compaction.enabled, "emergency brake implies pause_compaction");
    }

    #[tokio::test]
    async fn post_valves_requires_admin_write_scope() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let req = SetValvesReq {
            actor: "ops".to_string(),
            reason: "test".to_string(),
            pause_ingest: Some(true),
            pause_compaction: None,
            throttle: None,
            read_only: None,
            emergency_brake: None,
        };
        let resp = post_valves(State(state), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn post_valves_sets_throttle_with_params() {
        let state = test_app_state(16);
        let req = SetValvesReq {
            actor: "ops".to_string(),
            reason: "rate-limit".to_string(),
            pause_ingest: None,
            pause_compaction: None,
            throttle: Some(SetThrottle {
                enabled: true,
                retry_after_ms: Some(500),
                events_per_sec: Some(100),
                bytes_per_sec: Some(1_000_000),
                max_in_flight: Some(10),
            }),
            read_only: None,
            emergency_brake: None,
        };
        let resp = post_valves(State(state.clone()), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let c = state.control.read().await;
        assert!(c.valves.throttle.enabled);
        assert_eq!(c.valves.throttle.retry_after_ms, Some(500));
        assert_eq!(c.valves.throttle.events_per_sec, Some(100));
        assert_eq!(c.valves.throttle.bytes_per_sec, Some(1_000_000));
        assert_eq!(c.valves.throttle.max_in_flight, Some(10));
    }

    // ── post_replication_segment (bad base64) ──────────────────────

    #[tokio::test]
    async fn post_replication_segment_rejects_bad_base64() {
        let state = test_app_state(16);
        let req = ReplicationSegmentReq {
            shard_id: "shard-0001".to_string(),
            epoch: 1,
            leader_node_id: None,
            segment_base64: "!!!not-valid-base64!!!".to_string(),
            segment_hash: None,
        };
        let resp = post_replication_segment(State(state), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = json_body(resp).await;
        assert!(body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("segmentBase64 decode failed"));
    }

    #[tokio::test]
    async fn post_replication_segment_returns_501_without_dataplane() {
        let state = test_app_state(16);
        let req = ReplicationSegmentReq {
            shard_id: "shard-0001".to_string(),
            epoch: 1,
            leader_node_id: None,
            segment_base64: base64::engine::general_purpose::STANDARD.encode(b"segment-data"),
            segment_hash: None,
        };
        let resp = post_replication_segment(State(state), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── problem_for_status (additional edge cases) ─────────────────

    #[test]
    fn problem_for_status_not_implemented() {
        let problem = problem_for_status(StatusCode::NOT_IMPLEMENTED, "not yet");
        let resp = problem.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn problem_for_status_internal_server_error_fallback() {
        let problem = problem_for_status(StatusCode::INTERNAL_SERVER_ERROR, "oops");
        let resp = problem.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn problem_for_status_precondition_failed() {
        let problem = problem_for_status(StatusCode::PRECONDITION_FAILED, "stale");
        let resp = problem.into_response();
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
    }

    // ── evidence helper functions ──────────────────────────────────

    #[test]
    fn evidence_node_context_populates_fields() {
        let state = test_app_state(16);
        let ctx = evidence_node_context(&state);
        assert_eq!(ctx.node_id, "node-a");
        assert_eq!(ctx.build.version, "test");
        assert_eq!(ctx.build.commit, "test");
    }

    #[test]
    fn submitted_event_id_format() {
        let id = submitted_event_id("act-1");
        assert!(id.contains("act-1"));
        assert!(id.starts_with(EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1));
    }

    #[test]
    fn finished_event_id_format() {
        let id = finished_event_id("act-1", "succeeded");
        assert!(id.contains("act-1"));
        assert!(id.contains("succeeded"));
    }

    #[test]
    fn mutation_event_id_format() {
        let long_hash = "0123456789abcdef0123456789abcdef";
        let id = mutation_event_id("act-1", long_hash);
        assert!(id.contains("act-1"));
        assert!(id.contains("0123456789abcdef"));
    }

    #[test]
    fn mutation_event_id_short_hash() {
        let id = mutation_event_id("act-1", "short");
        assert!(id.contains("short"));
    }

    #[test]
    fn checkpoint_id_format() {
        let id = checkpoint_id("act-1", "0123456789abcdef0123456789abcdef");
        assert!(id.starts_with("checkpoint:"));
        assert!(id.contains("act-1"));
    }

    #[test]
    fn checkpoint_event_id_format() {
        let id = checkpoint_event_id("checkpoint:act-1:hash");
        assert!(id.contains("checkpoint:act-1:hash"));
    }

    // ── now_unix_ms ────────────────────────────────────────────────

    #[test]
    fn now_unix_ms_returns_plausible_value() {
        let ms = now_unix_ms();
        // Should be after year 2020 in milliseconds
        assert!(ms > 1_577_836_800_000);
    }

    // ── sync_control_metrics ───────────────────────────────────────

    #[test]
    fn sync_control_metrics_runs_without_panic() {
        let state = test_app_state(16);
        let mut c = control::ControlV1::default();
        c.valves.pause_ingest.enabled = true;
        c.valves.throttle.enabled = true;
        sync_control_metrics(&state.metrics, &c);
        // No panic = pass (metrics are set internally)
    }

    // ── post_admin_append (validation) ─────────────────────────────

    #[tokio::test]
    async fn post_admin_append_empty_events_returns_501() {
        let state = test_app_state(16);
        let body = AppendBody {
            tenant_id: "tenant-a".to_string(),
            stream_type: "test".to_string(),
            stream_id: "stream-1".to_string(),
            expected_next_seq: 0,
            events: vec![],
        };
        let resp = post_admin_append(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        // No dataplane -> 501
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── get_proj_meta / post_projection_rebuild auth ───────────────

    #[tokio::test]
    async fn get_proj_meta_requires_auth_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let resp = get_proj_meta(
            State(state.clone()),
            Query(ProjMetaQuery {
                shard_id: "shard-0001".to_string(),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp2 = get_proj_meta(
            State(state),
            Query(ProjMetaQuery {
                shard_id: "shard-0001".to_string(),
            }),
            dev_scope_headers("admin:read"),
        )
        .await
        .into_response();
        assert_eq!(resp2.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn post_projection_rebuild_requires_auth_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let resp = post_projection_rebuild(State(state.clone()), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp2 =
            post_projection_rebuild(State(state), dev_scope_headers("admin:write"))
                .await
                .into_response();
        assert_eq!(resp2.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── get_gpus requires auth ─────────────────────────────────────

    #[tokio::test]
    async fn get_gpus_requires_auth_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let resp = get_gpus(State(state), HeaderMap::new()).await.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── post_stream_meta requires auth ─────────────────────────────

    #[tokio::test]
    async fn post_stream_meta_requires_auth_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let req = StreamMetaReq {
            tenant_id: "tenant-a".to_string(),
            stream_type: "answers".to_string(),
            stream_id: "stream-1".to_string(),
            min_live_seq: Some(5),
            tombstone_seq: None,
            actor: "ops".to_string(),
            reason: "cleanup".to_string(),
        };
        let resp = post_stream_meta(State(state), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── receipt endpoints require auth ──────────────────────────────

    #[tokio::test]
    async fn receipt_body_requires_auth_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let resp = get_receipt_body_v1(
            State(state),
            Path("crx_abc".to_string()),
            Query(TenantQuery {
                tenant_id: "tenant-a".to_string(),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn receipt_signature_requires_auth_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let resp = get_receipt_signature_v1(
            State(state),
            Path("crx_abc".to_string()),
            Query(TenantQuery {
                tenant_id: "tenant-a".to_string(),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn receipt_verification_requires_auth_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let resp = get_receipt_verification_v1(
            State(state),
            Path("crx_abc".to_string()),
            Query(TenantQuery {
                tenant_id: "tenant-a".to_string(),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn receipt_export_requires_auth_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let resp = get_receipt_export_v1(
            State(state),
            Path("crx_abc".to_string()),
            Query(ExportQueryV1 {
                tenant_id: "tenant-a".to_string(),
                include: None,
                redaction: None,
                format: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── replication segment requires auth ──────────────────────────

    #[tokio::test]
    async fn post_replication_segment_requires_auth_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let req = ReplicationSegmentReq {
            shard_id: "shard-0001".to_string(),
            epoch: 1,
            leader_node_id: None,
            segment_base64: "AAAA".to_string(),
            segment_hash: None,
        };
        let resp = post_replication_segment(State(state), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── parse_export_options (tar.zst format) ──────────────────────

    #[test]
    fn parse_export_options_tar_zst_format() {
        let opts = parse_receipt_export_options_v1(None, None, Some("tar.zst")).unwrap();
        assert!(matches!(opts.format, ExportFormatV1::TarZst));
    }

    #[test]
    fn parse_export_options_zip_format() {
        let opts = parse_receipt_export_options_v1(None, None, Some("zip")).unwrap();
        assert!(matches!(opts.format, ExportFormatV1::Zip));
    }

    #[test]
    fn parse_export_options_redaction_none() {
        let opts = parse_receipt_export_options_v1(None, Some("none"), None).unwrap();
        assert!(matches!(opts.redaction, ExportRedactionV1::None));
    }

    #[test]
    fn parse_export_options_redaction_metadata_only() {
        let opts = parse_receipt_export_options_v1(None, Some("metadata_only"), None).unwrap();
        assert!(matches!(opts.redaction, ExportRedactionV1::MetadataOnly));
    }

    #[test]
    fn parse_export_options_redaction_tenant_safe() {
        let opts = parse_receipt_export_options_v1(None, Some("tenant_safe"), None).unwrap();
        assert!(matches!(opts.redaction, ExportRedactionV1::TenantSafe));
    }

    // ── map_store_error_http (additional edge case) ────────────────

    #[tokio::test]
    async fn map_store_error_http_shard_unavailable_body_fields() {
        let err = AppendError::ShardUnavailable {
            shard_id: "shard-0042".to_string(),
            owner_gpu_id: 7,
            current_shard_map_version: 99,
        };
        let resp = map_store_error_http(err).into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json_body(resp).await;
        // Extensions are flattened into the top-level JSON
        assert_eq!(body["code"], "SHARD_UNAVAILABLE");
        assert_eq!(body["shardId"], "shard-0042");
        assert_eq!(body["ownerGpuId"], 7);
        assert_eq!(body["currentShardMapVersion"], 99);
    }

    #[tokio::test]
    async fn map_store_error_http_wrong_shard_body_fields() {
        let err = AppendError::WrongShard {
            leader_grpc_addr: "http://leader:50051".to_string(),
            current_shard_map_version: 3,
        };
        let resp = map_store_error_http(err).into_response();
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
        let body = json_body(resp).await;
        assert_eq!(body["code"], "WRONG_SHARD");
        assert_eq!(body["leaderGrpcAddr"], "http://leader:50051");
    }

    #[tokio::test]
    async fn map_store_error_http_version_mismatch_body_fields() {
        let err = AppendError::ShardMapVersionMismatch {
            client_version: 5,
            current_version: 8,
        };
        let resp = map_store_error_http(err).into_response();
        assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
        let body = json_body(resp).await;
        assert_eq!(body["code"], "SHARDMAP_VERSION_MISMATCH");
        assert_eq!(body["clientShardMapVersion"], 5);
        assert_eq!(body["currentShardMapVersion"], 8);
    }

    // ── CapacityState auto_paused ──────────────────────────────────

    #[tokio::test]
    async fn readyz_ok_when_capacity_warning_but_above_emergency() {
        let state = test_app_state(16);
        mark_ready_except_control(&state).await;
        {
            let mut cap = state.capacity.write().await;
            cap.free_ratio = 0.15; // Above emergency (0.10) but below warning (0.20)
            cap.free_bytes = 15;
            cap.total_bytes = 100;
        }
        let resp = readyz(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── post_admin_action (runtime-knob-update with throttle params) ─

    #[tokio::test]
    async fn runtime_knob_update_throttle_params() {
        let state = test_app_state(16);
        let params = serde_json::json!({
            "actor": "ops",
            "reason": "throttle-config",
            "throttleEnabled": true,
            "throttleEventsPerSec": 50,
            "throttleBytesPerSec": 102400,
            "throttleMaxInFlight": 8,
            "throttleRetryAfterMs": 200
        });

        let result = execute_admin_action(
            &state,
            "act-throttle-1",
            "runtime-knob-update",
            Some(&params),
            None,
            None,
        )
        .await
        .expect("runtime knob update succeeds");

        let control = state.control.read().await.clone();
        assert!(control.valves.throttle.enabled);
        assert_eq!(control.valves.throttle.events_per_sec, Some(50));
        assert_eq!(control.valves.throttle.bytes_per_sec, Some(102400));
        assert_eq!(control.valves.throttle.max_in_flight, Some(8));
        assert_eq!(control.valves.throttle.retry_after_ms, Some(200));
        assert!(result.result.is_object());
    }

    // ── text search with min_score ─────────────────────────────────

    #[tokio::test]
    async fn text_search_with_min_score_filters() {
        enable_text_search();

        let state = test_app_state(16);
        let ccxi_bytes = build_test_ccxi(&[
            "the rust programming language",
            "unrelated document about cooking",
        ]);
        load_test_index(&state, &ccxi_bytes).await;

        let body = TextSearchBody {
            tenant_id: "tenant-a".to_string(),
            query: "rust programming".to_string(),
            limit: 10,
            token_budget: None,
            min_score: Some(100.0), // Very high threshold
            mode: None,
            include_receipt: None,
        };

        let resp = post_query_text_search(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── ops log requires auth ──────────────────────────────────────

    #[serial_test::serial]
    #[tokio::test]
    async fn get_ops_log_requires_auth_in_dev_mode() {
        let state = test_app_state_with_auth(16, AuthMode::DevScopes);
        let resp = get_ops_log(
            State(state),
            Query(OpsLogQuery {
                node_id: None,
                since: None,
                until: None,
                from_seq: None,
                max_events: None,
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── post_valves with pause_compaction ───────────────────────────

    #[tokio::test]
    async fn post_valves_sets_pause_compaction() {
        let state = test_app_state(16);
        let req = SetValvesReq {
            actor: "ops".to_string(),
            reason: "compaction-pause".to_string(),
            pause_ingest: None,
            pause_compaction: Some(true),
            throttle: None,
            read_only: None,
            emergency_brake: None,
        };
        let resp = post_valves(State(state.clone()), HeaderMap::new(), Json(req))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let c = state.control.read().await;
        assert!(c.valves.pause_compaction.enabled);
    }

    // ── get_entity_count validation ────────────────────────────────

    #[tokio::test]
    async fn get_entity_count_missing_tenant_id_returns_501() {
        let state = test_app_state(16);
        let params = std::collections::HashMap::new();
        let resp = get_entity_count(State(state), axum::extract::Query(params))
            .await
            .into_response();
        // Missing tenant_id should still reach no-dataplane path -> 501
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    // ── admin_action_error helper ──────────────────────────────────

    #[test]
    fn admin_action_error_wraps_multiple_messages() {
        let err = admin_action_error("first failure");
        assert!(err.contains("first failure"));
        let err2 = admin_action_error("second failure with details");
        assert!(err2.contains("second failure with details"));
    }

    // ── problem_response helper ────────────────────────────────────

    #[tokio::test]
    async fn problem_response_returns_correct_status_and_content_type() {
        let resp = problem_response(StatusCode::CONFLICT, "conflict happened");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR); // CONFLICT uses fallback -> internal
        let ct = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(ct.contains("application/problem+json"));
    }

    // ── hex16 ───────────────────────────────────────────────────────

    #[test]
    fn hex16_encodes_all_zeros() {
        let bytes = [0u8; 16];
        assert_eq!(hex16(&bytes), "00000000000000000000000000000000");
    }

    #[test]
    fn hex16_encodes_all_ff() {
        let bytes = [0xffu8; 16];
        assert_eq!(hex16(&bytes), "ffffffffffffffffffffffffffffffff");
    }

    #[test]
    fn hex16_encodes_known_pattern() {
        let mut bytes = [0u8; 16];
        bytes[0] = 0xde;
        bytes[1] = 0xad;
        bytes[15] = 0xef;
        let hex = hex16(&bytes);
        assert!(hex.starts_with("dead"));
        assert!(hex.ends_with("ef"));
        assert_eq!(hex.len(), 32);
    }

    // ── read_param_str ──────────────────────────────────────────────

    #[test]
    fn read_param_str_extracts_and_trims() {
        let params = serde_json::json!({"name": "  hello  "});
        assert_eq!(read_param_str(Some(&params), "name"), Some("hello"));
    }

    #[test]
    fn read_param_str_none_for_missing() {
        let params = serde_json::json!({"name": "val"});
        assert_eq!(read_param_str(Some(&params), "missing"), None);
    }

    #[test]
    fn read_param_str_none_for_empty() {
        let params = serde_json::json!({"name": "  "});
        assert_eq!(read_param_str(Some(&params), "name"), None);
    }

    #[test]
    fn read_param_str_none_for_none_params() {
        assert_eq!(read_param_str(None, "name"), None);
    }

    // ── read_param_bool ─────────────────────────────────────────────

    #[test]
    fn read_param_bool_from_bool_value() {
        let params = serde_json::json!({"flag": true});
        assert_eq!(read_param_bool(Some(&params), "flag"), Some(true));
        let params = serde_json::json!({"flag": false});
        assert_eq!(read_param_bool(Some(&params), "flag"), Some(false));
    }

    #[test]
    fn read_param_bool_from_string_value() {
        for (s, expected) in [
            ("true", true), ("1", true), ("yes", true), ("y", true),
            ("false", false), ("0", false), ("no", false), ("n", false),
        ] {
            let params = serde_json::json!({"flag": s});
            assert_eq!(read_param_bool(Some(&params), "flag"), Some(expected), "failed for {s}");
        }
    }

    #[test]
    fn read_param_bool_none_for_invalid() {
        let params = serde_json::json!({"flag": "maybe"});
        assert_eq!(read_param_bool(Some(&params), "flag"), None);
    }

    #[test]
    fn read_param_bool_none_for_missing() {
        let params = serde_json::json!({});
        assert_eq!(read_param_bool(Some(&params), "flag"), None);
    }

    // ── read_param_u64 ──────────────────────────────────────────────

    #[test]
    fn read_param_u64_from_number() {
        let params = serde_json::json!({"val": 42});
        assert_eq!(read_param_u64(Some(&params), "val"), Some(42));
    }

    #[test]
    fn read_param_u64_from_string() {
        let params = serde_json::json!({"val": "99"});
        assert_eq!(read_param_u64(Some(&params), "val"), Some(99));
    }

    #[test]
    fn read_param_u64_none_for_invalid() {
        let params = serde_json::json!({"val": "not-a-number"});
        assert_eq!(read_param_u64(Some(&params), "val"), None);
    }

    // ── read_param_u32 ──────────────────────────────────────────────

    #[test]
    fn read_param_u32_valid() {
        let params = serde_json::json!({"val": 100});
        assert_eq!(read_param_u32(Some(&params), "val"), Some(100));
    }

    #[test]
    fn read_param_u32_overflow() {
        let params = serde_json::json!({"val": u64::MAX});
        assert_eq!(read_param_u32(Some(&params), "val"), None);
    }

    // ── read_param_f64 ──────────────────────────────────────────────

    #[test]
    fn read_param_f64_from_number() {
        let params = serde_json::json!({"val": 3.14});
        let result = read_param_f64(Some(&params), "val");
        assert!(result.is_some());
        assert!((result.unwrap() - 3.14).abs() < 0.001);
    }

    #[test]
    fn read_param_f64_from_string() {
        let params = serde_json::json!({"val": "2.718"});
        let result = read_param_f64(Some(&params), "val");
        assert!(result.is_some());
        assert!((result.unwrap() - 2.718).abs() < 0.001);
    }

    #[test]
    fn read_param_f64_none_for_invalid() {
        let params = serde_json::json!({"val": "abc"});
        assert_eq!(read_param_f64(Some(&params), "val"), None);
    }

    // ── is_known_admin_action ───────────────────────────────────────

    #[test]
    fn is_known_admin_action_all_known() {
        for action in [
            "verify-store", "scrub-now", "snapshot-verify", "projection-rebuild",
            "parity-pack", "runtime-knob-update", "force-seal",
        ] {
            assert!(is_known_admin_action(action), "expected {action} to be known");
        }
    }

    #[test]
    fn is_known_admin_action_unknown() {
        assert!(!is_known_admin_action("unknown-action"));
        assert!(!is_known_admin_action(""));
        assert!(!is_known_admin_action("VERIFY-STORE")); // case sensitive
    }

    // ── trace_id_from_traceparent (additional) ──────────────────────

    #[test]
    fn trace_id_from_traceparent_valid_w3c() {
        let tp = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";
        assert_eq!(
            trace_id_from_traceparent(Some(tp)),
            Some("0af7651916cd43dd8448eb211c80319c".to_string())
        );
    }

    #[test]
    fn trace_id_from_traceparent_none_input() {
        assert_eq!(trace_id_from_traceparent(None), None);
    }

    #[test]
    fn trace_id_from_traceparent_bad_format() {
        assert_eq!(trace_id_from_traceparent(Some("invalid")), None);
        assert_eq!(trace_id_from_traceparent(Some("00-short-b7-01")), None);
    }

    // ── parse_knowledge_authority_mode ──────────────────────────────

    #[test]
    fn parse_knowledge_authority_mode_all_variants() {
        assert_eq!(parse_knowledge_authority_mode("shadow"), Some(KnowledgeAuthorityModeV1::Shadow));
        assert_eq!(parse_knowledge_authority_mode("knowledge_shadow"), Some(KnowledgeAuthorityModeV1::Shadow));
        assert_eq!(parse_knowledge_authority_mode("dual_write"), Some(KnowledgeAuthorityModeV1::DualWrite));
        assert_eq!(parse_knowledge_authority_mode("shadow_read"), Some(KnowledgeAuthorityModeV1::ShadowRead));
        assert_eq!(parse_knowledge_authority_mode("authoritative"), Some(KnowledgeAuthorityModeV1::Authoritative));
        assert_eq!(parse_knowledge_authority_mode("unknown"), None);
    }

    // ── parse_knowledge_rollout_stage ──────────────────────────────

    #[test]
    fn parse_knowledge_rollout_stage_all_variants() {
        assert_eq!(parse_knowledge_rollout_stage("shadow"), Some(KnowledgeRolloutStageV1::InternalShadow));
        assert_eq!(parse_knowledge_rollout_stage("internal_shadow"), Some(KnowledgeRolloutStageV1::InternalShadow));
        assert_eq!(parse_knowledge_rollout_stage("tenant_validation"), Some(KnowledgeRolloutStageV1::TenantValidation));
        assert_eq!(parse_knowledge_rollout_stage("internal_authority"), Some(KnowledgeRolloutStageV1::InternalAuthority));
        assert_eq!(parse_knowledge_rollout_stage("limited_production_authority"), Some(KnowledgeRolloutStageV1::LimitedProductionAuthority));
        assert_eq!(parse_knowledge_rollout_stage("full_production_authority"), Some(KnowledgeRolloutStageV1::FullProductionAuthority));
        assert_eq!(parse_knowledge_rollout_stage("unknown"), None);
    }

    // ── parse_knowledge_parity_status ──────────────────────────────

    #[test]
    fn parse_knowledge_parity_status_all_variants() {
        use corecrux_types::KnowledgeParityStatusV1;
        assert_eq!(parse_knowledge_parity_status("unknown"), Some(KnowledgeParityStatusV1::Unknown));
        assert_eq!(parse_knowledge_parity_status("pass"), Some(KnowledgeParityStatusV1::Pass));
        assert_eq!(parse_knowledge_parity_status("warn"), Some(KnowledgeParityStatusV1::Warn));
        assert_eq!(parse_knowledge_parity_status("fail"), Some(KnowledgeParityStatusV1::Fail));
        assert_eq!(parse_knowledge_parity_status("other"), None);
    }

    // ── parse_tenant_throttle_rules ─────────────────────────────────

    #[test]
    fn parse_tenant_throttle_rules_valid_array() {
        let rules = serde_json::json!([
            {"tenantId": "t1", "eventsPerSec": 100},
            {"tenantId": "t2", "bytesPerSec": 1000}
        ]);
        let result = parse_tenant_throttle_rules(&rules);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn parse_tenant_throttle_rules_empty_tenant_fails() {
        let rules = serde_json::json!([
            {"tenantId": "  ", "eventsPerSec": 100}
        ]);
        let result = parse_tenant_throttle_rules(&rules);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("non-empty tenantId"));
    }

    #[test]
    fn parse_tenant_throttle_rules_string_input_fails() {
        let rules = serde_json::json!("not an array");
        let result = parse_tenant_throttle_rules(&rules);
        assert!(result.is_err());
    }

    // ── event_id helpers (additional) ─────────────────────────────────

    #[test]
    fn submitted_event_id_contains_schema() {
        let id = submitted_event_id("act-99");
        assert!(id.contains("act-99"));
        assert!(id.contains("submitted"));
    }

    #[test]
    fn finished_event_id_contains_status() {
        let id = finished_event_id("act-99", "failed");
        assert!(id.contains("act-99"));
        assert!(id.contains("failed"));
    }

    #[test]
    fn mutation_event_id_with_short_hash() {
        let id = mutation_event_id("act-1", "short");
        assert!(id.contains("act-1"));
        assert!(id.contains("short"));
    }

    #[test]
    fn checkpoint_id_with_long_hash() {
        let id = checkpoint_id("act-2", "0123456789abcdef0123456789abcdef");
        assert!(id.starts_with("checkpoint:"));
        assert!(id.contains("act-2"));
    }

    // ── now_unix_ms (additional) ────────────────────────────────────

    #[test]
    fn now_unix_ms_after_2025() {
        let ms = now_unix_ms();
        assert!(ms > 1_735_689_600_000); // after 2025-01-01
    }

    // ── AdminActionStatus serialization ─────────────────────────────

    #[test]
    fn admin_action_status_serializes() {
        assert_eq!(serde_json::to_string(&AdminActionStatus::Submitted).unwrap(), "\"submitted\"");
        assert_eq!(serde_json::to_string(&AdminActionStatus::Running).unwrap(), "\"running\"");
        assert_eq!(serde_json::to_string(&AdminActionStatus::Succeeded).unwrap(), "\"succeeded\"");
        assert_eq!(serde_json::to_string(&AdminActionStatus::Failed).unwrap(), "\"failed\"");
    }

    #[test]
    fn admin_action_status_round_trip() {
        for status in [AdminActionStatus::Submitted, AdminActionStatus::Running, AdminActionStatus::Succeeded, AdminActionStatus::Failed] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: AdminActionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, status);
        }
    }

    // ── crux-observe endpoint tests ──────────────────────────────────

    #[serial_test::serial]
    #[tokio::test]
    async fn ops_facts_returns_501_when_observe_disabled() {
        std::env::remove_var("CRUX_SELF_OBSERVE");
        let state = test_app_state(16);
        let headers = dev_scope_headers("admin:read");
        let params = std::collections::HashMap::new();
        let resp = query_ops_facts(
            State(state),
            headers,
            Query(params),
        ).await.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn ops_facts_returns_200_when_observe_enabled() {
        std::env::set_var("CRUX_SELF_OBSERVE", "true");
        let state = test_app_state(16);
        let headers = dev_scope_headers("admin:read");
        let params = std::collections::HashMap::new();
        let resp = query_ops_facts(
            State(state),
            headers,
            Query(params),
        ).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert!(body["facts"].is_array());
        std::env::remove_var("CRUX_SELF_OBSERVE");
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn ops_errors_returns_501_when_observe_disabled() {
        std::env::remove_var("CRUX_SELF_OBSERVE");
        let state = test_app_state(16);
        let headers = dev_scope_headers("admin:read");
        let params = std::collections::HashMap::new();
        let resp = query_ops_errors(
            State(state),
            headers,
            Query(params),
        ).await.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }
    #[serial_test::serial]

    #[serial_test::serial]
    #[tokio::test]
    async fn ops_errors_returns_facts_when_enabled() {
        std::env::set_var("CRUX_SELF_OBSERVE", "true");
        let state = test_app_state(16);
        // Store an error fact
        {
            let mut store = state.fact_store.write().await;
            store.store(corecrux_memory::fact_store::StoreFact {
                entity: "__ops__::error:test-err-1".to_string(),
                key: "test error".to_string(),
                value: "something went wrong".to_string(),
                source_receipt: None,
                confidence: 1.0,
            });
        }
        let headers = dev_scope_headers("admin:read");
        let params = std::collections::HashMap::new();
        let resp = query_ops_errors(
            State(state),
            headers,
            Query(params),
        ).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let facts = body["facts"].as_array().unwrap();
        assert_eq!(facts.len(), 1);
        std::env::remove_var("CRUX_SELF_OBSERVE");
    }    #[serial_test::serial]
    #[tokio::test]
    async fn ops_health_returns_latest_per_component() {
        std::env::set_var("CRUX_SELF_OBSERVE", "true");
        let state = test_app_state(16);
        {
            let mut store = state.fact_store.write().await;
            store.store(corecrux_memory::fact_store::StoreFact {
                entity: "__ops__::health:shard_store".to_string(),
                key: "health".to_string(),
                value: "degraded".to_string(),
                source_receipt: None,
                confidence: 1.0,
            });
            store.store(corecrux_memory::fact_store::StoreFact {
                entity: "__ops__::health:shard_store".to_string(),
                key: "health".to_string(),
                value: "healthy".to_string(),
                source_receipt: None,
                confidence: 1.0,
            });
        }
        let headers = dev_scope_headers("admin:read");
        let resp = get_ops_health(
            State(state),
            headers,
        ).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let health = body["health"].as_array().unwrap();
        // Should deduplicate to 1 entry for the component
        assert_eq!(health.len(), 1);
        std::env::remove_var("CRUX_SELF_OBSERVE");
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn bootstrap_pull_returns_501_when_disabled() {
        std::env::remove_var("CRUX_SELF_OBSERVE");
        let state = test_app_state(16);
        let headers = dev_scope_headers("admin:read");
        let body = BootstrapPullBody {
            query: "error".to_string(),
            top_k: 10,
            token_budget: None,
        };
        let resp = post_bootstrap_pull(
            State(state),
            headers,
            Json(body),
        ).await.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn bootstrap_pull_returns_facts_when_enabled() {
        std::env::set_var("CRUX_SELF_OBSERVE", "true");
        let state = test_app_state(16);
        // Seed bootstrap data
        {
            let seeder = crux_observe::bootstrap::BootstrapSeeder::new(state.fact_store.clone());
            seeder.seed().await;
        }
        let headers = dev_scope_headers("admin:read");
        let body = BootstrapPullBody {
            query: "error".to_string(),
            top_k: 10,
            token_budget: None,
        };
        let resp = post_bootstrap_pull(
            State(state),
            headers,
            Json(body),
        ).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["source"].as_str(), Some("__bootstrap__"));
        assert!(body["facts"].is_array());
        std::env::remove_var("CRUX_SELF_OBSERVE");
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn bootstrap_status_returns_seeded_false_initially() {
        std::env::set_var("CRUX_SELF_OBSERVE", "true");
        let state = test_app_state(16);
        let headers = dev_scope_headers("admin:read");
        let resp = get_bootstrap_status(
            State(state),
            headers,
        ).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["seeded"].as_bool(), Some(false));
        assert_eq!(body["fact_count"].as_u64(), Some(0));
        std::env::remove_var("CRUX_SELF_OBSERVE");
    }

    #[serial_test::serial]
    #[tokio::test]
    async fn bootstrap_status_returns_seeded_true_after_seed() {
        std::env::set_var("CRUX_SELF_OBSERVE", "true");
        let state = test_app_state(16);
        {
            let seeder = crux_observe::bootstrap::BootstrapSeeder::new(state.fact_store.clone());
            seeder.seed().await;
        }
        let headers = dev_scope_headers("admin:read");
        let resp = get_bootstrap_status(
            State(state),
            headers,
        ).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["seeded"].as_bool(), Some(true));
        assert!(body["fact_count"].as_u64().unwrap() > 0);
        assert!(body["categories"].is_object());
        std::env::remove_var("CRUX_SELF_OBSERVE");
    }

    // ── Production hardening: timeout layer compiles ────────────────

    #[tokio::test]
    async fn router_with_timeout_and_panic_layers_compiles() {
        let state = test_app_state(16);
        let app = router(state);
        // Verify the router can be converted to a service (layers are applied).
        let _service = app.into_service::<axum::body::Body>();
    }

    // ── Production hardening: panic handler returns 500 ─────────────

    #[tokio::test]
    async fn panic_handler_returns_500_problem_json() {
        let resp = handle_panic(Box::new("test panic"));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let ct = resp.headers().get("content-type").unwrap().to_str().unwrap();
        assert_eq!(ct, "application/problem+json");
        let body = json_body(resp).await;
        assert_eq!(body["status"], 500);
    }

    #[tokio::test]
    async fn panic_handler_handles_string_panic() {
        let resp = handle_panic(Box::new(String::from("string panic")));
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = json_body(resp).await;
        assert_eq!(body["status"], 500);
    }

    // ── Production hardening: /v1/version endpoint ──────────────────

    #[serial_test::serial]
    #[tokio::test]
    async fn version_endpoint_returns_build_info_and_features() {
        let state = test_app_state(16);
        let resp = get_version(State(state)).await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        assert_eq!(body["version"], "test");
        assert_eq!(body["commit"], "test");
        assert_eq!(body["msrv"], "1.88.0");
        assert!(body["features"].is_object());
        // Features should be booleans
        assert!(body["features"]["text_search"].is_boolean());
        assert!(body["features"]["graph_expand"].is_boolean());
        assert!(body["features"]["self_observe"].is_boolean());
        assert!(body["features"]["mcp"].is_boolean());
    }
}
