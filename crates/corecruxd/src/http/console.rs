// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Aggregation and guarded mutation endpoints for the embedded Crux Console.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    problem_response, require_http_scopes, require_http_scopes_for_tenant, AppState, HeaderMap, IntoResponse, Json,
    Path, Query, State, StatusCode,
};

type BoostOverlay = BTreeMap<String, String>;
type BoostOverlayPair = (BoostOverlay, BoostOverlay);

#[derive(Debug, serde::Deserialize)]
pub(super) struct InstallIntegrationBody {
    pub(super) manifest: Option<crux_integrations::IntegrationManifest>,
    pub(super) pack_id: Option<String>,
    pub(super) version: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct GrantIntegrationBody {
    pub(super) version: String,
    #[serde(default)]
    pub(super) capabilities: Vec<String>,
    #[serde(default)]
    pub(super) reason: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct DisableIntegrationBody {
    #[serde(default)]
    pub(super) reason: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ConsoleChunksQuery {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct CompleteOnboardingBody {
    pub auth_mode: String,
    #[serde(default)]
    pub hide_onboarding: bool,
}

const SUPPORTED_ONBOARDING_AUTH_MODES: &[&str] = &["off", "dev_scopes", "jwt_hs256", "jwt_jwks"];

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_onboarding(State(state): State<AppState>) -> impl IntoResponse {
    let onboarding = state.onboarding.read().await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "completed_at_unix_ms": onboarding.completed_at_unix_ms,
            "chosen_auth_mode": onboarding.chosen_auth_mode,
            "running_auth_mode": state.auth.mode().as_str(),
            "bind_is_loopback": state.http_bind_loopback,
            "allow_insecure_dev_auth_bind": state.allow_insecure_dev_auth_bind,
            "supported_auth_modes": SUPPORTED_ONBOARDING_AUTH_MODES,
        })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_console_onboarding_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CompleteOnboardingBody>,
) -> impl IntoResponse {
    let chosen = body.auth_mode.trim().to_ascii_lowercase();
    if !SUPPORTED_ONBOARDING_AUTH_MODES.contains(&chosen.as_str()) {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "auth_mode must be one of off, dev_scopes, jwt_hs256, jwt_jwks",
        );
    }

    if chosen == "off" && !state.http_bind_loopback && !state.allow_insecure_dev_auth_bind {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "auth_mode=off requires a loopback bind or CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND=1",
        );
    }

    let running = state.auth.mode().as_str().to_string();
    let restart_required = chosen != running;

    let mut current = state.onboarding.write().await;
    let anonymous_first_run_allowed = current.completed_at_unix_ms.is_none() && state.http_bind_loopback;
    if !anonymous_first_run_allowed {
        if !state.http_bind_loopback && state.auth.mode().as_str() == "off" {
            return problem_response(
                StatusCode::FORBIDDEN,
                "onboarding completion on a non-loopback bind requires authenticated admin:write",
            );
        }
        if let Err(problem) = require_console_write(&state, &headers) {
            return problem.into_response();
        }
    }

    current.chosen_auth_mode = Some(chosen.clone());
    if body.hide_onboarding {
        current.completed_at_unix_ms = Some(now_unix_ms());
    }
    if let Err(err) = crate::onboarding::write_state(&state.data_dir, &current) {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    let snapshot = current.clone();
    drop(current);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "completed_at_unix_ms": snapshot.completed_at_unix_ms,
            "chosen_auth_mode": snapshot.chosen_auth_mode,
            "running_auth_mode": running,
            "restart_required": restart_required,
            "restart_command": "docker compose restart crux"
        })),
    )
        .into_response()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct UpdateSettingsBody {
    #[serde(default)]
    pub auth_mode: Option<String>,
    #[serde(default)]
    pub embedding_enabled: Option<bool>,
    #[serde(default)]
    pub embedding_url: Option<String>,
    #[serde(default)]
    pub embedding_model: Option<String>,
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_settings(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }
    let onboarding = state.onboarding.read().await;
    let env_embedding_url = std::env::var("CORECRUXD_EMBEDDING_URL").ok().filter(|s| !s.is_empty());
    let env_embedding_model = std::env::var("CORECRUXD_EMBEDDING_MODEL")
        .ok()
        .filter(|s| !s.is_empty());
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "auth": {
                "running_mode": state.auth.mode().as_str(),
                "chosen_mode": onboarding.chosen_auth_mode,
                "bind_is_loopback": state.http_bind_loopback,
                "allow_insecure_dev_auth_bind": state.allow_insecure_dev_auth_bind,
                "supported_modes": SUPPORTED_ONBOARDING_AUTH_MODES,
            },
            "embedding": {
                "enabled_intent": onboarding.embedding_enabled,
                "chosen_url": onboarding.chosen_embedding_url,
                "chosen_model": onboarding.chosen_embedding_model,
                "active_url": env_embedding_url,
                "active_model": env_embedding_model,
                "active": env_embedding_url.is_some(),
            },
            "onboarding": {
                "completed_at_unix_ms": onboarding.completed_at_unix_ms,
            }
        })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn put_console_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UpdateSettingsBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_write(&state, &headers) {
        return problem.into_response();
    }

    let mut onboarding = state.onboarding.write().await;
    let mut restart_required = false;

    if let Some(raw) = body.auth_mode {
        let mode = raw.trim().to_ascii_lowercase();
        if !SUPPORTED_ONBOARDING_AUTH_MODES.contains(&mode.as_str()) {
            return problem_response(
                StatusCode::BAD_REQUEST,
                "auth_mode must be one of off, dev_scopes, jwt_hs256, jwt_jwks",
            );
        }
        if mode == "off" && !state.http_bind_loopback && !state.allow_insecure_dev_auth_bind {
            return problem_response(
                StatusCode::BAD_REQUEST,
                "auth_mode=off requires a loopback bind or CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND=1",
            );
        }
        if state.auth.mode().as_str() != mode {
            restart_required = true;
        }
        onboarding.chosen_auth_mode = Some(mode);
    }

    if let Some(enabled) = body.embedding_enabled {
        if onboarding.embedding_enabled != Some(enabled) {
            restart_required = true;
        }
        onboarding.embedding_enabled = Some(enabled);
    }
    if let Some(url) = body.embedding_url {
        let trimmed = url.trim().to_string();
        let new = if trimmed.is_empty() { None } else { Some(trimmed) };
        if onboarding.chosen_embedding_url != new {
            restart_required = true;
        }
        onboarding.chosen_embedding_url = new;
    }
    if let Some(model) = body.embedding_model {
        let trimmed = model.trim().to_string();
        let new = if trimmed.is_empty() { None } else { Some(trimmed) };
        if onboarding.chosen_embedding_model != new {
            restart_required = true;
        }
        onboarding.chosen_embedding_model = new;
    }

    if let Err(err) = crate::onboarding::write_state(&state.data_dir, &onboarding) {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    let snapshot = onboarding.clone();
    drop(onboarding);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "saved": {
                "chosen_auth_mode": snapshot.chosen_auth_mode,
                "chosen_embedding_url": snapshot.chosen_embedding_url,
                "chosen_embedding_model": snapshot.chosen_embedding_model,
                "embedding_enabled": snapshot.embedding_enabled,
            },
            "restart_required": restart_required,
            "restart_command": "docker compose restart crux"
        })),
    )
        .into_response()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ProbeEmbeddingBody {
    pub url: String,
}

/// Probe an embedding endpoint URL for available models. Tries Ollama-style
/// (`GET {url}/api/tags`) first, falls back to OpenAI-compatible
/// (`GET {url}/v1/models`). Returns whichever shape parsed; the UI shows the
/// flat list and lets the operator override manually if both probes fail.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_console_embedding_probe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ProbeEmbeddingBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_write(&state, &headers) {
        return problem.into_response();
    }
    let url = body.url.trim().trim_end_matches('/').to_string();
    let policy = match validate_embedding_probe_url(&url) {
        Ok(policy) => policy,
        Err(err) => return problem_response(StatusCode::BAD_REQUEST, err),
    };

    let result = tokio::task::spawn_blocking(move || probe_embedding_url(&policy))
        .await
        .map_err(|e| e.to_string());
    match result {
        Ok(Ok(probe)) => (StatusCode::OK, Json(probe)).into_response(),
        Ok(Err(err)) => problem_response(StatusCode::BAD_GATEWAY, err),
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("probe join failed: {err}")),
    }
}

const CORECRUX_LANE_WEIGHTS_KEY: &str = "FUSION_RRF_LANE_WEIGHTS";
const CORECRUX_FUSION_RRF_KEY: &str = "FEATURE_FUSION_RRF";
const CORECRUX_LANE_KEYS: &[&str] = &[
    "bm25",
    "cosine",
    "sparse",
    "hyde",
    "topology",
    "vernacular",
    "indexing",
    "topology_trait_expansion",
    "navtree",
    "events",
];

#[derive(Debug, serde::Deserialize)]
pub(super) struct CoreCruxLaneWeightsQuery {
    #[serde(default)]
    pub tenant_id: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct UpdateCoreCruxLaneWeightsBody {
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub weights: BTreeMap<String, f64>,
    #[serde(default = "default_true")]
    pub fusion_rrf_enabled: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
}

#[derive(Debug)]
struct CoreCruxProxyError {
    status: StatusCode,
    detail: String,
}

impl CoreCruxProxyError {
    fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
        }
    }
}

fn default_true() -> bool {
    true
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_corecrux_lane_weights(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CoreCruxLaneWeightsQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }
    let base_url = match corecrux_base_url_from_env() {
        Ok(url) => url,
        Err(err) => return problem_response(StatusCode::SERVICE_UNAVAILABLE, err),
    };
    let tenant_id = normalize_optional_tenant(query.tenant_id);
    let result = tokio::task::spawn_blocking(move || fetch_corecrux_lane_weights(&base_url, tenant_id))
        .await
        .map_err(|err| {
            CoreCruxProxyError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("CoreCrux proxy join failed: {err}"),
            )
        });

    match result {
        Ok(Ok(body)) => (StatusCode::OK, Json(body)).into_response(),
        Ok(Err(err)) | Err(err) => problem_response(err.status, err.detail),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn put_console_corecrux_lane_weights(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UpdateCoreCruxLaneWeightsBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_write(&state, &headers) {
        return problem.into_response();
    }
    if body.weights.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "weights must include at least one lane");
    }
    let updates = match normalize_lane_weights(&body.weights) {
        Ok(weights) => weights,
        Err(err) => return problem_response(StatusCode::BAD_REQUEST, err),
    };
    let base_url = match corecrux_base_url_from_env() {
        Ok(url) => url,
        Err(err) => return problem_response(StatusCode::SERVICE_UNAVAILABLE, err),
    };
    let tenant_id = normalize_optional_tenant(body.tenant_id);
    let fusion_rrf_enabled = body.fusion_rrf_enabled;
    let actor = body.actor;
    let reason = body.reason;
    let result = tokio::task::spawn_blocking(move || {
        put_corecrux_lane_weights(&base_url, tenant_id, updates, fusion_rrf_enabled, actor, reason)
    })
    .await
    .map_err(|err| {
        CoreCruxProxyError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("CoreCrux proxy join failed: {err}"),
        )
    });

    match result {
        Ok(Ok(body)) => (StatusCode::OK, Json(body)).into_response(),
        Ok(Err(err)) | Err(err) => problem_response(err.status, err.detail),
    }
}

/// `DELETE /v1/console/corecrux/lane-weights[?tenant_id=...]` — scoped reset.
///
/// Clears **only** the two lane-weight overlay keys (`FUSION_RRF_LANE_WEIGHTS`,
/// `FEATURE_FUSION_RRF`) from the global or per-tenant CoreCrux boost overlay,
/// returning that scope to its process-env / inherited defaults. Other boost
/// overlay keys are left untouched — this is intentionally narrower than
/// CoreCrux's whole-overlay `DELETE /v1/admin/boost-config/tenant`.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn delete_console_corecrux_lane_weights(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CoreCruxLaneWeightsQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_write(&state, &headers) {
        return problem.into_response();
    }
    let base_url = match corecrux_base_url_from_env() {
        Ok(url) => url,
        Err(err) => return problem_response(StatusCode::SERVICE_UNAVAILABLE, err),
    };
    let tenant_id = normalize_optional_tenant(query.tenant_id);
    let result = tokio::task::spawn_blocking(move || reset_corecrux_lane_weights(&base_url, tenant_id))
        .await
        .map_err(|err| {
            CoreCruxProxyError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("CoreCrux proxy join failed: {err}"),
            )
        });

    match result {
        Ok(Ok(body)) => (StatusCode::OK, Json(body)).into_response(),
        Ok(Err(err)) | Err(err) => problem_response(err.status, err.detail),
    }
}

// ── CoreCrux link-graph mediation proxy ──────────────────────────────────────
//
// ExecPlan `wikicrux-link-graph-explorer-2026-07-23` (M4, D-D / D2 / R5). GET-only,
// read-only console → CoreCrux translation for the six-degrees link-graph pane.
// The console is same-origin cookie/scope auth by design (generated `CruxApi`, no
// bearer in the browser, T.3); it never talks to CoreCrux directly. These four
// GET routes translate allowlisted query params into the upstream CoreCrux
// `/v1/graph/*` JSON POST bodies (`stats` is GET-passthrough), exactly mirroring
// the lane-weights / gpu1 shim env + timeout + error-mapping family.
//
// Upstream base URL + bearer token live in the daemon env ONLY. Client request
// headers are NEVER forwarded upstream; the daemon injects its own graph scope +
// token. When the graph base URL is unset the routes 503 with a build hint so the
// console hides the pane (the capability plan gates visibility first; this is the
// same-origin safety net). This is Crux CE (CPU-only) — no CoreCrux engine code
// is compiled here; all graph work happens over the wire on the CoreCrux daemon.

/// The console proxy caps `resolve` well under the upstream 10 000; the pane only
/// resolves a handful of titles (two-article path search + a few ego seeds).
const GRAPH_RESOLVE_MAX_TITLES: usize = 256;
/// Mirror of the upstream `ego` seed cap (m2 contract: at most 256 seeds).
const GRAPH_EGO_MAX_SEEDS: usize = 256;
/// Mirror of the upstream `ego` budget maxima (m2 contract).
const GRAPH_EGO_MAX_BUDGET_NODES: u64 = 50_000;
const GRAPH_EGO_MAX_BUDGET_EDGES: u64 = 200_000;

const GRAPH_RESOLVE_PARAMS: &[&str] = &["titles"];
const GRAPH_EGO_PARAMS: &[&str] = &[
    "seeds",
    "hops",
    "budget_nodes",
    "budget_edges",
    "kind",
    "direction",
    "degree_cap",
];
const GRAPH_PATH_PARAMS: &[&str] = &["src", "dst", "max_hops", "k", "context_edge_budget"];

/// `GET /v1/console/corecrux/graph/stats` — GET-passthrough to upstream
/// `GET /v1/graph/stats` (corpus counts, snapshot id, build digest, degree histogram).
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_corecrux_graph_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }
    let base_url = match corecrux_graph_base_url_from_env() {
        Ok(url) => url,
        Err(err) => return problem_response(StatusCode::SERVICE_UNAVAILABLE, err),
    };
    let result = tokio::task::spawn_blocking(move || fetch_graph_stats(&base_url))
        .await
        .map_err(graph_join_error);
    finish_graph_proxy(result)
}

/// `GET /v1/console/corecrux/graph/resolve?titles=A|B|C` — translated to upstream
/// `POST /v1/graph/resolve {titles:[...]}`. `|` is the delimiter (invalid in ns0
/// titles, so it can never appear inside one).
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_corecrux_graph_resolve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }
    if let Err(err) = reject_unknown_graph_params(&params, GRAPH_RESOLVE_PARAMS) {
        return problem_response(StatusCode::BAD_REQUEST, err);
    }
    let titles: Vec<String> = params
        .get("titles")
        .map_or("", String::as_str)
        .split('|')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if titles.is_empty() {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "titles is required: a '|'-separated list of article titles",
        );
    }
    if titles.len() > GRAPH_RESOLVE_MAX_TITLES {
        return problem_response(
            StatusCode::BAD_REQUEST,
            format!("at most {GRAPH_RESOLVE_MAX_TITLES} titles per request"),
        );
    }
    let base_url = match corecrux_graph_base_url_from_env() {
        Ok(url) => url,
        Err(err) => return problem_response(StatusCode::SERVICE_UNAVAILABLE, err),
    };
    let result = tokio::task::spawn_blocking(move || fetch_graph_resolve(&base_url, titles))
        .await
        .map_err(graph_join_error);
    finish_graph_proxy(result)
}

/// `GET /v1/console/corecrux/graph/ego?seeds=1,2&hops=2&budget_nodes=5000&…` →
/// upstream `POST /v1/graph/ego`. Budgets are mandatory (mirroring the upstream
/// contract, R3); all params validated + capped server-side before any network
/// call.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_corecrux_graph_ego(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }
    if let Err(err) = reject_unknown_graph_params(&params, GRAPH_EGO_PARAMS) {
        return problem_response(StatusCode::BAD_REQUEST, err);
    }
    let body = match build_graph_ego_body(&params) {
        Ok(body) => body,
        Err(err) => return problem_response(StatusCode::BAD_REQUEST, err),
    };
    let base_url = match corecrux_graph_base_url_from_env() {
        Ok(url) => url,
        Err(err) => return problem_response(StatusCode::SERVICE_UNAVAILABLE, err),
    };
    let result = tokio::task::spawn_blocking(move || fetch_graph_ego(&base_url, body))
        .await
        .map_err(graph_join_error);
    finish_graph_proxy(result)
}

/// `GET /v1/console/corecrux/graph/path?src=1&dst=2&max_hops=6&…` → upstream
/// `POST /v1/graph/path` (k-shortest bidirectional BFS + 1-hop context subgraph).
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_corecrux_graph_path(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }
    if let Err(err) = reject_unknown_graph_params(&params, GRAPH_PATH_PARAMS) {
        return problem_response(StatusCode::BAD_REQUEST, err);
    }
    let body = match build_graph_path_body(&params) {
        Ok(body) => body,
        Err(err) => return problem_response(StatusCode::BAD_REQUEST, err),
    };
    let base_url = match corecrux_graph_base_url_from_env() {
        Ok(url) => url,
        Err(err) => return problem_response(StatusCode::SERVICE_UNAVAILABLE, err),
    };
    let result = tokio::task::spawn_blocking(move || fetch_graph_path(&base_url, body))
        .await
        .map_err(graph_join_error);
    finish_graph_proxy(result)
}

fn graph_join_error(err: tokio::task::JoinError) -> CoreCruxProxyError {
    CoreCruxProxyError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("CoreCrux graph proxy join failed: {err}"),
    )
}

fn finish_graph_proxy(
    result: Result<Result<serde_json::Value, CoreCruxProxyError>, CoreCruxProxyError>,
) -> axum::response::Response {
    match result {
        Ok(Ok(body)) => (StatusCode::OK, Json(body)).into_response(),
        Ok(Err(err)) | Err(err) => problem_response(err.status, err.detail),
    }
}

/// Reject any query key not in the per-endpoint allowlist (T.5 posture: the
/// console proxy forwards a fixed, audited param surface — never an arbitrary
/// passthrough).
fn reject_unknown_graph_params(params: &HashMap<String, String>, allowed: &[&str]) -> Result<(), String> {
    for key in params.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!(
                "unknown query parameter '{key}' (allowed: {})",
                allowed.join(", ")
            ));
        }
    }
    Ok(())
}

fn parse_graph_u32(raw: &str, name: &str) -> Result<u32, String> {
    raw.trim()
        .parse::<u32>()
        .map_err(|_| format!("{name} must be a non-negative integer node id"))
}

/// Validate + translate the `ego` query params into the upstream POST body,
/// mirroring the m2 contract's caps (seeds ≤ 256, hops clamp \[0,3\], mandatory
/// budgets ≤ 50 000 nodes / 200 000 edges, kind/direction enums).
fn build_graph_ego_body(params: &HashMap<String, String>) -> Result<serde_json::Value, String> {
    let seeds_raw = params.get("seeds").map_or("", String::as_str).trim();
    if seeds_raw.is_empty() {
        return Err("seeds is required: a comma-separated list of node ids".to_string());
    }
    let mut seeds: Vec<u32> = Vec::new();
    for tok in seeds_raw.split(',') {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        seeds.push(parse_graph_u32(tok, "seeds")?);
    }
    if seeds.is_empty() {
        return Err("seeds must not be empty".to_string());
    }
    if seeds.len() > GRAPH_EGO_MAX_SEEDS {
        return Err(format!("at most {GRAPH_EGO_MAX_SEEDS} seeds per request"));
    }

    let hops = match params.get("hops") {
        Some(raw) => parse_graph_u32(raw, "hops")?.min(3),
        None => 1,
    };

    let budget_nodes = params
        .get("budget_nodes")
        .ok_or_else(|| "budget_nodes is required (> 0)".to_string())?
        .trim()
        .parse::<u64>()
        .map_err(|_| "budget_nodes must be a positive integer".to_string())?;
    let budget_edges = params
        .get("budget_edges")
        .ok_or_else(|| "budget_edges is required (> 0)".to_string())?
        .trim()
        .parse::<u64>()
        .map_err(|_| "budget_edges must be a positive integer".to_string())?;
    if budget_nodes == 0 || budget_edges == 0 {
        return Err("budget_nodes and budget_edges must both be > 0".to_string());
    }
    if budget_nodes > GRAPH_EGO_MAX_BUDGET_NODES || budget_edges > GRAPH_EGO_MAX_BUDGET_EDGES {
        return Err(format!(
            "budget too large (max nodes {GRAPH_EGO_MAX_BUDGET_NODES}, max edges {GRAPH_EGO_MAX_BUDGET_EDGES})"
        ));
    }

    let kind = match params.get("kind").map(String::as_str) {
        None => "link",
        Some(k @ ("link" | "category" | "both")) => k,
        Some(other) => return Err(format!("kind must be 'link' | 'category' | 'both', got '{other}'")),
    };
    let direction = match params.get("direction").map(String::as_str) {
        None => "both",
        Some(d @ ("forward" | "reverse" | "both")) => d,
        Some(other) => {
            return Err(format!(
                "direction must be 'forward' | 'reverse' | 'both', got '{other}'"
            ))
        }
    };
    let degree_cap = match params.get("degree_cap") {
        Some(raw) => parse_graph_u32(raw, "degree_cap")?,
        None => 0,
    };

    Ok(serde_json::json!({
        "seeds": seeds,
        "hops": hops,
        "budget": { "nodes": budget_nodes, "edges": budget_edges },
        "kind": kind,
        "direction": direction,
        "degree_cap": degree_cap,
    }))
}

/// Validate + translate the `path` query params into the upstream POST body,
/// mirroring the m2 contract (max_hops 1..=8, k clamp \[1,64\], context edge budget
/// clamp \[0,20000\]).
fn build_graph_path_body(params: &HashMap<String, String>) -> Result<serde_json::Value, String> {
    let src = parse_graph_u32(params.get("src").ok_or_else(|| "src is required".to_string())?, "src")?;
    let dst = parse_graph_u32(params.get("dst").ok_or_else(|| "dst is required".to_string())?, "dst")?;
    let max_hops = match params.get("max_hops") {
        Some(raw) => {
            let mh = parse_graph_u32(raw, "max_hops")?;
            if mh == 0 {
                return Err("max_hops must be >= 1".to_string());
            }
            if mh > 8 {
                return Err("max_hops must be <= 8".to_string());
            }
            mh
        }
        None => 6,
    };
    let k = match params.get("k") {
        Some(raw) => parse_graph_u32(raw, "k")?.clamp(1, 64),
        None => 4,
    };
    let context_edge_budget = match params.get("context_edge_budget") {
        Some(raw) => parse_graph_u32(raw, "context_edge_budget")?.min(20_000),
        None => 500,
    };

    Ok(serde_json::json!({
        "src": src,
        "dst": dst,
        "max_hops": max_hops,
        "k": k,
        "context_edge_budget": context_edge_budget,
    }))
}

/// Read the CoreCrux graph base URL from the daemon env (graph-specific first,
/// then the un-prefixed fallback — same lookup family as `corecrux_base_url_from_env`).
/// `pub(super)` so `/v1/version` (health.rs) can surface the `console_link_graph`
/// runtime capability from the same source of truth.
pub(super) fn corecrux_graph_base_url_from_env() -> Result<String, String> {
    for key in ["CORECRUXD_CORECRUX_GRAPH_BASE_URL", "CORECRUX_GRAPH_BASE_URL"] {
        if let Ok(raw) = std::env::var(key) {
            let trimmed = raw.trim().trim_end_matches('/').to_string();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }
    }
    Err(
        "CoreCrux graph base URL is not configured; set CORECRUXD_CORECRUX_GRAPH_BASE_URL on the Crux daemon"
            .to_string(),
    )
}

/// Whether the CoreCrux graph mediation proxy is configured on this daemon — the
/// `console_link_graph` runtime-capability signal the console gates its pane on.
pub(super) fn corecrux_graph_base_url_configured() -> bool {
    corecrux_graph_base_url_from_env().is_ok()
}

fn corecrux_graph_token_from_env() -> Option<String> {
    std::env::var("CORECRUXD_CORECRUX_GRAPH_TOKEN")
        .or_else(|_| std::env::var("CORECRUX_GRAPH_TOKEN"))
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn corecrux_graph_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(15)))
        .build()
        .into()
}

/// Attach only the daemon-injected scope + bearer. Client request headers are
/// never forwarded upstream (T.3); the graph endpoints are scope-only auth
/// (`query:read`), tenant-agnostic (whole-corpus `.ccxg`, no tenant binding).
fn apply_corecrux_graph_headers<S>(mut req: ureq::RequestBuilder<S>) -> ureq::RequestBuilder<S> {
    req = req
        .header("Accept", "application/json")
        .header("X-Corecrux-Scopes", "query:read");
    if let Some(token) = corecrux_graph_token_from_env() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    req
}

/// Map an upstream CoreCrux graph HTTP status onto the status the console sees.
/// Upstream auth failures (401/403 — a daemon-token misconfig, never the browser
/// user's fault) and any 5xx collapse to 502 so no upstream auth signal leaks to
/// the same-origin console. Upstream `404` (link-graph flag off) and `503` (no
/// `.ccxg` loaded) both surface as `503` so the pane shows the enable/build hint.
fn map_graph_upstream_status(upstream: u16) -> StatusCode {
    match upstream {
        400 => StatusCode::BAD_REQUEST,
        404 | 503 => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::BAD_GATEWAY,
    }
}

fn read_corecrux_graph_json(
    mut response: ureq::http::Response<ureq::Body>,
) -> Result<serde_json::Value, CoreCruxProxyError> {
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().map_err(|err| {
        CoreCruxProxyError::new(
            StatusCode::BAD_GATEWAY,
            format!("CoreCrux graph response read failed: {err}"),
        )
    })?;
    let body = if text.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str::<serde_json::Value>(&text).map_err(|err| {
            CoreCruxProxyError::new(
                StatusCode::BAD_GATEWAY,
                format!("CoreCrux graph returned non-JSON response ({status}): {err}"),
            )
        })?
    };
    if (200..300).contains(&status) {
        return Ok(body);
    }
    // Surface the upstream problem+json `detail` when present (e.g. the build
    // hint), otherwise a generic mapped message. Never echo upstream auth detail.
    let mapped = map_graph_upstream_status(status);
    let detail = if mapped == StatusCode::BAD_GATEWAY {
        format!("CoreCrux graph endpoint returned {status}")
    } else {
        body.get("detail")
            .and_then(|v| v.as_str())
            .map_or_else(|| format!("CoreCrux graph endpoint returned {status}"), str::to_string)
    };
    Err(CoreCruxProxyError::new(mapped, detail))
}

fn corecrux_graph_get(agent: &ureq::Agent, url: &str) -> Result<serde_json::Value, CoreCruxProxyError> {
    let response = apply_corecrux_graph_headers(agent.get(url)).call().map_err(|err| {
        CoreCruxProxyError::new(StatusCode::BAD_GATEWAY, format!("CoreCrux graph request failed: {err}"))
    })?;
    read_corecrux_graph_json(response)
}

fn corecrux_graph_post(
    agent: &ureq::Agent,
    url: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, CoreCruxProxyError> {
    let response = apply_corecrux_graph_headers(agent.post(url))
        .send_json(body)
        .map_err(|err| {
            CoreCruxProxyError::new(StatusCode::BAD_GATEWAY, format!("CoreCrux graph request failed: {err}"))
        })?;
    read_corecrux_graph_json(response)
}

fn fetch_graph_stats(base_url: &str) -> Result<serde_json::Value, CoreCruxProxyError> {
    let agent = corecrux_graph_agent();
    corecrux_graph_get(&agent, &format!("{base_url}/v1/graph/stats"))
}

fn fetch_graph_resolve(base_url: &str, titles: Vec<String>) -> Result<serde_json::Value, CoreCruxProxyError> {
    let agent = corecrux_graph_agent();
    let body = serde_json::json!({ "titles": titles });
    corecrux_graph_post(&agent, &format!("{base_url}/v1/graph/resolve"), &body)
}

fn fetch_graph_ego(base_url: &str, body: serde_json::Value) -> Result<serde_json::Value, CoreCruxProxyError> {
    let agent = corecrux_graph_agent();
    corecrux_graph_post(&agent, &format!("{base_url}/v1/graph/ego"), &body)
}

fn fetch_graph_path(base_url: &str, body: serde_json::Value) -> Result<serde_json::Value, CoreCruxProxyError> {
    let agent = corecrux_graph_agent();
    corecrux_graph_post(&agent, &format!("{base_url}/v1/graph/path"), &body)
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ConsoleReviewQuery {
    pub limit: Option<usize>,
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_review_contradictions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ConsoleReviewQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }
    let limit = query.limit.unwrap_or(50).min(250);
    let candidates = {
        let store = state.fact_store.read().await;
        store.contradiction_candidates_v1(limit)
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "schema": "crux.console.review.contradictions.v1",
            "limit": limit,
            "count": candidates.len(),
            "candidates": candidates,
        })),
    )
        .into_response()
}

/// `GET /v1/console/review/queue` — read-only review-queue view (P1 widen).
///
/// Lists the surfaced `__consolidation_review__::<run_id>` receipt facts written
/// by the (default-OFF) consolidation scheduler, newest first, with the parsed
/// review body (contradiction + expiry proposals). This is the data the embedded
/// `/console/review` page renders. Distinct from
/// `GET /v1/console/review/contradictions`, which runs a LIVE contradiction pass.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_review_queue(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ConsoleReviewQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }
    let limit = query.limit.unwrap_or(50).min(250);
    let (runs, live_contradictions) = {
        let store = state.fact_store.read().await;
        // Confidence 1.0 on every review receipt ⇒ query_inner's confidence-desc,
        // stored_at-desc order already yields newest-first.
        let result = store.query(&corecrux_memory::fact_store::FactQuery {
            entity_prefix: Some(crate::consolidation_scheduler::REVIEW_ENTITY_PREFIX.to_string()),
            top_k: limit,
            ..Default::default()
        });
        let runs: Vec<serde_json::Value> = result
            .facts
            .iter()
            .map(|fact| {
                serde_json::json!({
                    "fact_id": fact.fact_id,
                    "entity": fact.entity,
                    "surfaced_at": fact.stored_at.to_rfc3339(),
                    // Parsed review body when it is JSON; the raw string otherwise.
                    "review": serde_json::from_str::<serde_json::Value>(&fact.value)
                        .unwrap_or_else(|_| serde_json::Value::String(fact.value.clone())),
                })
            })
            .collect();
        // Live contradiction pass so the console still shows current
        // contradictions even when the scheduler is OFF (nothing surfaced yet) —
        // repointing the page to the queue must not hide them (review finding 6).
        let live = store.contradiction_candidates_v1(limit);
        (runs, live)
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "schema": "crux.console.review.queue.v1",
            // Lets the page tell "scheduler off, nothing surfaced" apart from
            // "scheduler on, genuinely empty" (review finding 6).
            "scheduler_enabled": state.consolidation_scheduler_enabled,
            "limit": limit,
            "count": runs.len(),
            "runs": runs,
            "live_contradictions": live_contradictions,
            "live_count": live_contradictions.len(),
        })),
    )
        .into_response()
}

/// Per-request cap on the expiry batch so one call can never sweep an unbounded
/// set of facts (review finding 2).
const MAX_EXPIRY_BATCH: usize = 500;

#[derive(Debug, serde::Deserialize)]
pub(super) struct ConsoleExpiryApplyRequest {
    /// Explicit fact_ids to expire — the operator's selection from the surfaced
    /// expiry proposals. Every id is RE-VALIDATED at apply time (see the handler)
    /// before it is soft-deleted; there is deliberately no blanket cutoff.
    pub fact_ids: Vec<String>,
}

/// `POST /v1/console/review/expiries` — operator applies REVIEWED expiry
/// proposals (P1 widen). Console-write gated; the scheduler itself never mutates.
///
/// Safety (review findings 1 & 2): the apply takes an explicit, bounded list of
/// fact_ids and, under the write lock, recomputes the CURRENT expiry-candidate
/// set (`select_expiry_candidates`) — which enforces the exact same protections
/// the scheduler applied at proposal time (private / receipt-linked / pinned /
/// `>= PROTECTED_CONFIDENCE_FLOOR`) AND re-checks staleness / low-confidence NOW.
/// Any requested id that is no longer a live candidate (became protected, was
/// re-verified fresh, gained confidence, or never qualified) is SKIPPED, never
/// deleted. There is no cutoff, so a future timestamp can no longer mass-delete.
/// Deletion uses the fallible [`corecrux_memory::FactStore::try_delete`] so an
/// unpersisted tombstone is reported as skipped, not expired (finding 3).
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_console_review_expiries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ConsoleExpiryApplyRequest>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_write(&state, &headers) {
        return problem.into_response();
    }
    if body.fact_ids.is_empty() {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "fact_ids must be a non-empty list of proposed expiry-candidate ids",
        );
    }
    if body.fact_ids.len() > MAX_EXPIRY_BATCH {
        return problem_response(StatusCode::BAD_REQUEST, "fact_ids exceeds the 500-id per-request cap");
    }
    let actor = console_actor_from_headers(&headers);
    let (expired, skipped) = {
        let mut store = state.fact_store.write().await;
        // Recompute the live candidate set under the SAME write lock we delete
        // under — atomic revalidation, no TOCTOU. `select_expiry_candidates`
        // applies the protection + stale/low-confidence rules exactly as the
        // scheduler does at proposal time.
        let facts: Vec<corecrux_memory::Fact> = store.all_facts().cloned().collect();
        let now = chrono::Utc::now();
        let policy = corecrux_projections::decay::DecayPolicy::from_env();
        let current: std::collections::HashMap<String, String> =
            crate::consolidation_scheduler::select_expiry_candidates(&facts, now, policy, usize::MAX)
                .into_iter()
                .map(|candidate| (candidate.fact_id, candidate.reason))
                .collect();

        let mut expired = Vec::new();
        let mut skipped = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for id in &body.fact_ids {
            if !seen.insert(id.as_str()) {
                continue; // de-dup so a repeated id is counted once
            }
            match current.get(id) {
                Some(reason) => match store.try_delete(id) {
                    Ok(true) => expired.push(serde_json::json!({ "fact_id": id, "reason": reason })),
                    Ok(false) => {
                        skipped.push(serde_json::json!({ "fact_id": id, "reason": "not_found_or_already_deleted" }));
                    }
                    Err(err) => {
                        tracing::warn!(?err, %id, "expiry-soft-delete-journal-append-failed");
                        skipped.push(serde_json::json!({ "fact_id": id, "reason": "journal_append_failed" }));
                    }
                },
                // Protected / re-verified fresh / gained confidence / never a
                // candidate → refuse to delete (findings 1 & 2).
                None => skipped.push(serde_json::json!({ "fact_id": id, "reason": "not_a_current_expiry_candidate" })),
            }
        }
        (expired, skipped)
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "schema": "crux.console.review.expiries.v1",
            "expired_count": expired.len(),
            "skipped_count": skipped.len(),
            "expired": expired,
            "skipped": skipped,
            "actor": actor,
        })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_console_review_consolidation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut body): Json<corecrux_memory::fact_store::ConsolidationRequestV1>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_write(&state, &headers) {
        return problem.into_response();
    }
    if body.consolidation_id.trim().is_empty() {
        body.consolidation_id = format!("console-{}", uuid::Uuid::new_v4());
    }
    if body.actor.as_deref().unwrap_or_default().trim().is_empty() {
        body.actor = Some(console_actor_from_headers(&headers));
    }
    // Capture the audit fields before the request is moved into the store op.
    let entity = body.entity.clone();
    let key = body.key.clone();
    let actor = body.actor.clone().unwrap_or_else(|| "console".to_string());
    let report = {
        let mut store = state.fact_store.write().await;
        store.consolidate_facts_v1(body)
    };
    match report {
        Ok(report) => {
            let now = chrono::Utc::now().to_rfc3339();
            // M2: emit a signed, offline-verifiable diff receipt.
            let signed = super::consolidation_receipt::mint_consolidation_receipt(
                &state,
                &report.receipt,
                &entity,
                &key,
                &actor,
                "canonical_merge",
                &now,
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "schema": "crux.console.review.consolidation.v1",
                    "status": report.status,
                    "receipt": report.receipt,
                    "signed_receipt": signed,
                })),
            )
                .into_response()
        }
        Err(err) => consolidation_problem(err),
    }
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ConsolidationUndoRequest {
    pub canonical_fact_id: String,
    #[serde(default)]
    pub source_fact_ids: Vec<String>,
    #[serde(default)]
    pub entity: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
}

/// `POST /v1/console/review/consolidations/undo` — atomically reverse a
/// consolidation (retire the canonical, restore its sources) and emit a signed
/// undo receipt (M2). Idempotent: undoing an already-undone consolidation
/// returns `status = "already_undone"`.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_console_review_consolidation_undo(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ConsolidationUndoRequest>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_write(&state, &headers) {
        return problem.into_response();
    }
    let actor = console_actor_from_headers(&headers);
    let undo = {
        let mut store = state.fact_store.write().await;
        store.consolidate_undo_v1(&req.canonical_fact_id, &req.source_fact_ids)
    };
    match undo {
        Ok(undo) => {
            let now = chrono::Utc::now().to_rfc3339();
            let receipt = corecrux_memory::fact_store::ConsolidationReceiptV1 {
                consolidation_id: format!("undo:{}", req.canonical_fact_id),
                canonical_fact_id: undo.canonical_fact_id.clone(),
                canonical_hash: String::new(),
                superseded_fact_ids: undo.restored_fact_ids.clone(),
                source_fact_ids: undo.restored_fact_ids.clone(),
            };
            let signed = super::consolidation_receipt::mint_consolidation_receipt(
                &state,
                &receipt,
                req.entity.as_deref().unwrap_or(""),
                req.key.as_deref().unwrap_or(""),
                &actor,
                "undo",
                &now,
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "schema": "crux.console.review.consolidation_undo.v1",
                    "status": undo.status,
                    "canonical_fact_id": undo.canonical_fact_id,
                    "restored_fact_ids": undo.restored_fact_ids,
                    "signed_receipt": signed,
                })),
            )
                .into_response()
        }
        Err(err) => consolidation_problem(err),
    }
}

fn console_actor_from_headers(headers: &HeaderMap) -> String {
    headers
        .get("x-corecrux-passport-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("console")
        .to_string()
}

fn consolidation_problem(err: corecrux_memory::fact_store::ConsolidationErrorV1) -> axum::response::Response {
    use corecrux_memory::fact_store::ConsolidationErrorV1;
    let status = match &err {
        ConsolidationErrorV1::NoTargets | ConsolidationErrorV1::TargetOutsideEntityKey(_) => StatusCode::BAD_REQUEST,
        ConsolidationErrorV1::TargetNotFound(_) => StatusCode::NOT_FOUND,
        ConsolidationErrorV1::TargetDeleted(_)
        | ConsolidationErrorV1::TargetPinned(_)
        | ConsolidationErrorV1::TargetPrivate(_)
        | ConsolidationErrorV1::TargetReceiptLinked(_)
        | ConsolidationErrorV1::TargetHighConfidence { .. } => StatusCode::CONFLICT,
        ConsolidationErrorV1::Journal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    problem_response(status, err.to_string())
}

fn corecrux_base_url_from_env() -> Result<String, String> {
    for key in [
        "CORECRUXD_CORECRUX_BASE_URL",
        "CORECRUXD_CORECRUX_URL",
        "CORECRUX_BASE_URL",
    ] {
        if let Ok(raw) = std::env::var(key) {
            let trimmed = raw.trim().trim_end_matches('/').to_string();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }
    }
    Err("CoreCrux base URL is not configured; set CORECRUXD_CORECRUX_BASE_URL on the Crux daemon".to_string())
}

fn normalize_optional_tenant(raw: Option<String>) -> Option<String> {
    raw.map(|tenant| tenant.trim().to_string())
        .filter(|tenant| !tenant.is_empty())
}

fn default_lane_weights() -> BTreeMap<String, f64> {
    [
        ("bm25", 1.0),
        ("cosine", 1.0),
        ("sparse", 1.0),
        ("hyde", 1.0),
        ("topology", 0.0),
        ("vernacular", 0.0),
        ("indexing", 0.0),
        ("topology_trait_expansion", 0.0),
        ("navtree", 0.0),
        ("events", 0.0),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect()
}

fn canonical_lane_key(name: &str) -> Option<&'static str> {
    match name.trim().to_ascii_lowercase().as_str() {
        "bm25" => Some("bm25"),
        "cosine" | "dense" | "vec" | "vector" => Some("cosine"),
        "sparse" | "splade" => Some("sparse"),
        "hyde" => Some("hyde"),
        "topology" => Some("topology"),
        "vernacular" => Some("vernacular"),
        "indexing" | "ccxdi" => Some("indexing"),
        "topology_trait_expansion" | "trait_expansion" | "ccxse_expansion" => Some("topology_trait_expansion"),
        "navtree" | "nav" | "ccxst" => Some("navtree"),
        "events" | "event" | "ccxev" => Some("events"),
        _ => None,
    }
}

fn normalize_lane_weights(raw: &BTreeMap<String, f64>) -> Result<BTreeMap<String, f64>, String> {
    let mut out = BTreeMap::new();
    for (name, value) in raw {
        let Some(key) = canonical_lane_key(name) else {
            return Err(format!("unknown lane '{name}'"));
        };
        if !value.is_finite() || *value < 0.0 {
            return Err(format!("lane '{name}' must be a non-negative finite number"));
        }
        out.insert(key.to_string(), *value);
    }
    Ok(out)
}

fn parse_overlay_map(body: &serde_json::Value) -> BTreeMap<String, String> {
    body.get("overlay")
        .and_then(|overlay| overlay.as_object())
        .map(|overlay| {
            overlay
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn overlay_bool(tenant: &BoostOverlay, global: &BoostOverlay, key: &str) -> bool {
    tenant
        .get(key)
        .or_else(|| global.get(key))
        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
}

fn parse_lane_weights_raw(raw: &str) -> BTreeMap<String, f64> {
    let mut weights = default_lane_weights();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return weights;
    }
    if trimmed.starts_with('{') {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if let Some(obj) = json.as_object() {
                for (name, value) in obj {
                    if let (Some(key), Some(weight)) = (canonical_lane_key(name), value.as_f64()) {
                        if weight.is_finite() && weight >= 0.0 {
                            weights.insert(key.to_string(), weight);
                        }
                    }
                }
            }
        }
        return weights;
    }
    for part in trimmed.split(',') {
        let Some((name, value)) = part.split_once('=').or_else(|| part.split_once(':')) else {
            continue;
        };
        let Ok(weight) = value.trim().parse::<f64>() else {
            continue;
        };
        if let Some(key) = canonical_lane_key(name) {
            if weight.is_finite() && weight >= 0.0 {
                weights.insert(key.to_string(), weight);
            }
        }
    }
    weights
}

fn resolved_lane_weights(
    global_overlay: &BTreeMap<String, String>,
    tenant_overlay: &BTreeMap<String, String>,
) -> (BTreeMap<String, f64>, &'static str, Option<String>) {
    if let Some(raw) = tenant_overlay.get(CORECRUX_LANE_WEIGHTS_KEY) {
        return (parse_lane_weights_raw(raw), "tenant", Some(raw.clone()));
    }
    if let Some(raw) = global_overlay.get(CORECRUX_LANE_WEIGHTS_KEY) {
        return (parse_lane_weights_raw(raw), "global", Some(raw.clone()));
    }
    (default_lane_weights(), "default", None)
}

fn lane_weights_to_overlay_json(weights: &BTreeMap<String, f64>) -> Result<String, CoreCruxProxyError> {
    let mut body = serde_json::Map::new();
    for key in CORECRUX_LANE_KEYS {
        let value = weights
            .get(*key)
            .copied()
            .unwrap_or_else(|| default_lane_weights()[*key]);
        body.insert((*key).to_string(), serde_json::json!(value));
    }
    serde_json::to_string(&serde_json::Value::Object(body)).map_err(|err| {
        CoreCruxProxyError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize CoreCrux lane weights: {err}"),
        )
    })
}

fn corecrux_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(std::time::Duration::from_secs(8)))
        .build()
        .into()
}

fn bearer_token_from_env() -> Option<String> {
    std::env::var("CORECRUXD_CORECRUX_ADMIN_TOKEN")
        .or_else(|_| std::env::var("CORECRUX_ADMIN_TOKEN"))
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn passport_id_from_env() -> Option<String> {
    std::env::var("CORECRUXD_CORECRUX_PASSPORT_ID")
        .or_else(|_| std::env::var("CORECRUX_PASSPORT_ID"))
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn apply_corecrux_headers<S>(mut req: ureq::RequestBuilder<S>, scopes: &str) -> ureq::RequestBuilder<S> {
    req = req
        .header("Accept", "application/json")
        .header("X-Corecrux-Scopes", scopes);
    if let Some(token) = bearer_token_from_env() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    if let Some(passport_id) = passport_id_from_env() {
        req = req.header("X-Corecrux-Passport-Id", passport_id);
    }
    req
}

fn read_corecrux_json(mut response: ureq::http::Response<ureq::Body>) -> Result<serde_json::Value, CoreCruxProxyError> {
    let status = response.status().as_u16();
    let text = response.body_mut().read_to_string().map_err(|err| {
        CoreCruxProxyError::new(StatusCode::BAD_GATEWAY, format!("CoreCrux response read failed: {err}"))
    })?;
    let body = if text.trim().is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str::<serde_json::Value>(&text).map_err(|err| {
            CoreCruxProxyError::new(
                StatusCode::BAD_GATEWAY,
                format!("CoreCrux returned non-JSON response ({status}): {err}"),
            )
        })?
    };
    if !(200..300).contains(&status) {
        return Err(CoreCruxProxyError::new(
            StatusCode::BAD_GATEWAY,
            format!("CoreCrux admin endpoint returned {status}"),
        ));
    }
    Ok(body)
}

fn corecrux_get_json(agent: &ureq::Agent, url: &str, scopes: &str) -> Result<serde_json::Value, CoreCruxProxyError> {
    let response = apply_corecrux_headers(agent.get(url), scopes)
        .call()
        .map_err(|err| CoreCruxProxyError::new(StatusCode::BAD_GATEWAY, format!("CoreCrux request failed: {err}")))?;
    read_corecrux_json(response)
}

fn corecrux_post_json(
    agent: &ureq::Agent,
    url: &str,
    scopes: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, CoreCruxProxyError> {
    let response = apply_corecrux_headers(agent.post(url), scopes)
        .send_json(body)
        .map_err(|err| CoreCruxProxyError::new(StatusCode::BAD_GATEWAY, format!("CoreCrux request failed: {err}")))?;
    read_corecrux_json(response)
}

fn fetch_corecrux_overlays(
    agent: &ureq::Agent,
    base_url: &str,
    tenant_id: Option<&str>,
) -> Result<BoostOverlayPair, CoreCruxProxyError> {
    let global = corecrux_get_json(agent, &format!("{base_url}/v1/admin/boost-config"), "admin:read")?;
    let global_overlay = parse_overlay_map(&global);
    let tenant_overlay = if let Some(tenant_id) = tenant_id {
        let encoded = encode_query_component(tenant_id);
        let tenant = corecrux_get_json(
            agent,
            &format!("{base_url}/v1/admin/boost-config/tenant?tenant_id={encoded}"),
            "admin:read",
        )?;
        parse_overlay_map(&tenant)
    } else {
        BTreeMap::new()
    };
    Ok((global_overlay, tenant_overlay))
}

fn encode_query_component(raw: &str) -> String {
    let mut out = String::new();
    for b in raw.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn fetch_corecrux_lane_weights(
    base_url: &str,
    tenant_id: Option<String>,
) -> Result<serde_json::Value, CoreCruxProxyError> {
    let agent = corecrux_agent();
    let (global_overlay, tenant_overlay) = fetch_corecrux_overlays(&agent, base_url, tenant_id.as_deref())?;
    let (weights, source, raw) = resolved_lane_weights(&global_overlay, &tenant_overlay);
    Ok(serde_json::json!({
        "ok": true,
        "configured": true,
        "scope": if tenant_id.is_some() { "tenant" } else { "global" },
        "tenant_id": tenant_id,
        "source": source,
        "fusion_rrf_enabled": overlay_bool(&tenant_overlay, &global_overlay, CORECRUX_FUSION_RRF_KEY),
        "lanes": CORECRUX_LANE_KEYS,
        "weights": weights,
        "raw_lane_weights": raw,
        "global_overlay_size": global_overlay.len(),
        "tenant_overlay_size": tenant_overlay.len(),
    }))
}

fn put_corecrux_lane_weights(
    base_url: &str,
    tenant_id: Option<String>,
    updates: BTreeMap<String, f64>,
    fusion_rrf_enabled: bool,
    actor: Option<String>,
    reason: Option<String>,
) -> Result<serde_json::Value, CoreCruxProxyError> {
    let agent = corecrux_agent();
    let (global_overlay, tenant_overlay) = fetch_corecrux_overlays(&agent, base_url, tenant_id.as_deref())?;
    let (mut weights, _, _) = resolved_lane_weights(&global_overlay, &tenant_overlay);
    for (key, value) in updates {
        weights.insert(key, value);
    }

    let mut set = HashMap::new();
    set.insert(
        CORECRUX_FUSION_RRF_KEY.to_string(),
        if fusion_rrf_enabled { "true" } else { "false" }.to_string(),
    );
    set.insert(
        CORECRUX_LANE_WEIGHTS_KEY.to_string(),
        lane_weights_to_overlay_json(&weights)?,
    );

    let target = if tenant_id.is_some() {
        format!("{base_url}/v1/admin/boost-config/tenant")
    } else {
        format!("{base_url}/v1/admin/boost-config")
    };
    let body = if let Some(tenant_id) = &tenant_id {
        serde_json::json!({
            "tenant_id": tenant_id,
            "set": set,
        })
    } else {
        serde_json::json!({
            "set": set,
        })
    };
    let upstream = corecrux_post_json(&agent, &target, "admin:write", &body)?;
    Ok(serde_json::json!({
        "ok": true,
        "scope": if tenant_id.is_some() { "tenant" } else { "global" },
        "tenant_id": tenant_id,
        "source": if tenant_id.is_some() { "tenant" } else { "global" },
        "fusion_rrf_enabled": fusion_rrf_enabled,
        "lanes": CORECRUX_LANE_KEYS,
        "weights": weights,
        "upstream_overlay_size": upstream.get("overlay_size").and_then(|v| v.as_u64()),
        "actor": actor,
        "reason": reason,
    }))
}

/// Clear only the lane-weight overlay keys for the global or tenant scope, then
/// re-read so the caller sees the post-reset (inherited / default) weights.
fn reset_corecrux_lane_weights(
    base_url: &str,
    tenant_id: Option<String>,
) -> Result<serde_json::Value, CoreCruxProxyError> {
    let agent = corecrux_agent();
    let clear = vec![
        CORECRUX_LANE_WEIGHTS_KEY.to_string(),
        CORECRUX_FUSION_RRF_KEY.to_string(),
    ];
    let (target, body) = if let Some(tenant_id) = &tenant_id {
        (
            format!("{base_url}/v1/admin/boost-config/tenant"),
            serde_json::json!({ "tenant_id": tenant_id, "clear": clear }),
        )
    } else {
        (
            format!("{base_url}/v1/admin/boost-config"),
            serde_json::json!({ "clear": clear }),
        )
    };
    corecrux_post_json(&agent, &target, "admin:write", &body)?;

    // Re-read so the response reflects the now-inherited weights and scope.
    let (global_overlay, tenant_overlay) = fetch_corecrux_overlays(&agent, base_url, tenant_id.as_deref())?;
    let (weights, source, raw) = resolved_lane_weights(&global_overlay, &tenant_overlay);
    Ok(serde_json::json!({
        "ok": true,
        "reset": true,
        "scope": if tenant_id.is_some() { "tenant" } else { "global" },
        "tenant_id": tenant_id,
        "source": source,
        "cleared_keys": [CORECRUX_LANE_WEIGHTS_KEY, CORECRUX_FUSION_RRF_KEY],
        "fusion_rrf_enabled": overlay_bool(&tenant_overlay, &global_overlay, CORECRUX_FUSION_RRF_KEY),
        "lanes": CORECRUX_LANE_KEYS,
        "weights": weights,
        "raw_lane_weights": raw,
        "global_overlay_size": global_overlay.len(),
        "tenant_overlay_size": tenant_overlay.len(),
    }))
}

#[derive(Debug, serde::Serialize)]
struct EmbeddingProbeResult {
    shape: &'static str,
    models: Vec<String>,
    /// The actual URL the probe succeeded against — may differ from the
    /// operator's input if a Docker-aware fallback (host.docker.internal,
    /// sibling-service hostname) was used. UI surfaces this so the operator
    /// can persist the working URL.
    resolved_url: String,
}

#[derive(Debug, Clone)]
struct EmbeddingProbePolicy {
    base_url: String,
    allow_private_targets: bool,
}

fn probe_embedding_url(policy: &EmbeddingProbePolicy) -> Result<EmbeddingProbeResult, String> {
    // Inside a Docker container, `localhost`/`127.0.0.1` from the daemon's
    // perspective resolves to the daemon itself, NOT the user's host or a
    // sibling container. We try the URL the operator gave us first; if that
    // fails AND the URL points at localhost, we transparently retry with
    // common Docker-aware fallbacks before giving up.
    let candidates = build_probe_candidates(&policy.base_url);

    let probe_endpoints: [(&str, &str); 2] = [("ollama", "/api/tags"), ("openai-compat", "/v1/models")];
    let mut last_error = String::new();

    for candidate in &candidates {
        // L1 (DNS-rebind): resolve + validate the host ONCE, then pin the agent
        // to those exact addresses so the actual fetch cannot re-resolve to a
        // different (e.g. metadata / CGNAT) IP between the check and the connect.
        let parsed = match parse_embedding_probe_url(candidate) {
            Ok(parsed) => parsed,
            Err(err) => {
                last_error = err;
                continue;
            }
        };
        let addrs = match resolve_validated_probe_addrs(&parsed, policy.allow_private_targets) {
            Ok(addrs) => addrs,
            Err(err) => {
                last_error = err;
                continue;
            }
        };
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(6)))
            .build();
        let agent: ureq::Agent = ureq::Agent::with_parts(
            config,
            ureq::unversioned::transport::DefaultConnector::new(),
            PinnedResolver { addrs },
        );
        for (shape, path) in probe_endpoints {
            let probe_url = format!("{candidate}{path}");
            match agent.get(&probe_url).header("Accept", "application/json").call() {
                Ok(mut response) => {
                    let status = response.status().as_u16();
                    if status != 200 {
                        last_error = format!("{shape} ({probe_url}) returned {status}");
                        continue;
                    }
                    let text = response.body_mut().read_to_string().map_err(|e| e.to_string())?;
                    let parsed: serde_json::Value = match serde_json::from_str(&text) {
                        Ok(v) => v,
                        Err(e) => {
                            last_error = format!("{shape} returned non-JSON: {e}");
                            continue;
                        }
                    };
                    let models = match shape {
                        "ollama" => parsed
                            .get("models")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|m| m.get("name").and_then(|x| x.as_str()).map(str::to_string))
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default(),
                        "openai-compat" => parsed
                            .get("data")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|m| m.get("id").and_then(|x| x.as_str()).map(str::to_string))
                                    .collect::<Vec<_>>()
                            })
                            .unwrap_or_default(),
                        _ => Vec::new(),
                    };
                    if models.is_empty() {
                        last_error = format!("{shape} ({probe_url}) returned 200 but no models parsed");
                        continue;
                    }
                    return Ok(EmbeddingProbeResult {
                        shape,
                        models,
                        resolved_url: candidate.clone(),
                    });
                }
                Err(err) => {
                    last_error = format!("{shape} ({probe_url}): {err}");
                }
            }
        }
    }
    Err(format!(
        "no probe shape worked across {} candidate host(s). last error: {last_error}",
        candidates.len()
    ))
}

fn validate_embedding_probe_url(url: &str) -> Result<EmbeddingProbePolicy, String> {
    if url.is_empty() {
        return Err("url must not be empty".to_string());
    }
    let parsed = parse_embedding_probe_url(url)?;
    let allow_private_targets = embedding_probe_private_targets_allowed(&parsed);
    ensure_embedding_probe_addr_allowed(&parsed, allow_private_targets)?;
    Ok(EmbeddingProbePolicy {
        base_url: url.trim().trim_end_matches('/').to_string(),
        allow_private_targets,
    })
}

fn parse_embedding_probe_url(url: &str) -> Result<url::Url, String> {
    let parsed = url::Url::parse(url).map_err(|e| format!("invalid url: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("url must start with http:// or https://".to_string());
    }
    if parsed.host_str().is_none() {
        return Err("url must include a host".to_string());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("url must not include credentials".to_string());
    }
    Ok(parsed)
}

fn ensure_embedding_probe_addr_allowed(parsed: &url::Url, allow_private_targets: bool) -> Result<(), String> {
    resolve_validated_probe_addrs(parsed, allow_private_targets).map(|_| ())
}

/// Resolve the probe URL's host to concrete socket addresses **once** and
/// validate every one against the private/CGNAT/metadata denylist, returning the
/// validated set. The caller pins the ureq agent to exactly these addresses
/// (via [`PinnedResolver`]) so the fetch cannot re-resolve to a different IP
/// after the check — closing the DNS-rebind window (L1).
fn resolve_validated_probe_addrs(parsed: &url::Url, allow_private_targets: bool) -> Result<Vec<SocketAddr>, String> {
    let host = parsed.host_str().ok_or_else(|| "url must include a host".to_string())?;
    let port = parsed.port_or_known_default().unwrap_or(80);
    if let Ok(ip) = host.parse::<IpAddr>() {
        ensure_embedding_ip_allowed(ip, allow_private_targets)?;
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("could not resolve embedding probe host '{host}': {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("embedding probe host '{host}' resolved to no addresses"));
    }
    for addr in &addrs {
        ensure_embedding_ip_allowed(addr.ip(), allow_private_targets)?;
    }
    Ok(addrs)
}

/// A ureq resolver pinned to a pre-validated set of socket addresses. It ignores
/// the request URI's host entirely and always returns the addresses validated at
/// check time, so the transport connects to exactly what was vetted (L1).
#[derive(Debug)]
struct PinnedResolver {
    addrs: Vec<SocketAddr>,
}

impl ureq::unversioned::resolver::Resolver for PinnedResolver {
    fn resolve(
        &self,
        _uri: &ureq::http::Uri,
        _config: &ureq::config::Config,
        _timeout: ureq::unversioned::transport::NextTimeout,
    ) -> Result<ureq::unversioned::resolver::ResolvedSocketAddrs, ureq::Error> {
        // `self.addrs` is always non-empty (validated by resolve_validated_probe_addrs).
        let mut out = self.empty();
        // ureq's ResolvedSocketAddrs holds at most 16 (MAX_ADDRS) entries.
        for addr in self.addrs.iter().take(16) {
            out.push(*addr);
        }
        Ok(out)
    }
}

fn ensure_embedding_ip_allowed(ip: IpAddr, allow_private_targets: bool) -> Result<(), String> {
    if allow_private_targets || !is_private_probe_ip(ip) {
        return Ok(());
    }
    Err(format!(
        "embedding probe target {ip} is private, loopback, link-local, metadata, multicast, or unspecified; configure CORECRUXD_EMBEDDING_URL or CORECRUXD_EMBEDDING_PROBE_ALLOW_LOCAL=1 for local endpoints"
    ))
}

fn is_private_probe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                // L2: CGNAT / Tailscale shared range 100.64.0.0/10 (RFC 6598).
                // `Ipv4Addr::is_shared()` is still unstable, so match the range
                // directly: first octet 100, second octet 64..=127.
                || is_cgnat_shared_v4(v4)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

/// RFC 6598 shared address space `100.64.0.0/10` (carrier-grade NAT; also the
/// Tailscale CGNAT range). `Ipv4Addr::is_shared()` is unstable, so match by hand.
fn is_cgnat_shared_v4(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

fn embedding_probe_private_targets_allowed(parsed: &url::Url) -> bool {
    if std::env::var("CORECRUXD_EMBEDDING_PROBE_ALLOW_LOCAL")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
    {
        return true;
    }
    let Some(configured) = std::env::var("CORECRUXD_EMBEDDING_URL")
        .ok()
        .and_then(|value| url::Url::parse(value.trim()).ok())
    else {
        return false;
    };
    same_probe_origin(parsed, &configured)
}

fn same_probe_origin(left: &url::Url, right: &url::Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str().map(str::to_ascii_lowercase) == right.host_str().map(str::to_ascii_lowercase)
        && left.port_or_known_default() == right.port_or_known_default()
}

/// Given a user-supplied embedding URL, build the ordered list of hostnames
/// to actually probe. The operator's URL is always first. When the URL points
/// at localhost, we append `host.docker.internal` (Docker Desktop bridge) and
/// the documented compose-sibling hostname `crux-ollama-1` (matches
/// docker-compose.yml's `ollama` service when launched with the embeddings
/// profile) so the operator's "obvious" URL Just Works from inside the daemon.
#[cfg(test)]
mod probe_candidate_tests {
    use super::{build_probe_candidates, validate_embedding_probe_url};

    #[test]
    fn non_localhost_url_returns_only_itself() {
        let c = build_probe_candidates("http://api.example.com:8080");
        assert_eq!(c, vec!["http://api.example.com:8080".to_string()]);
    }

    #[test]
    fn localhost_appends_docker_aware_fallbacks() {
        let c = build_probe_candidates("http://localhost:11434/");
        assert_eq!(
            c,
            vec![
                "http://localhost:11434".to_string(),
                "http://host.docker.internal:11434".to_string(),
                "http://crux-ollama-1:11434".to_string(),
            ]
        );
    }

    #[test]
    fn ipv4_loopback_also_gets_fallbacks() {
        let c = build_probe_candidates("http://127.0.0.1:11434");
        assert!(c.contains(&"http://host.docker.internal:11434".to_string()));
        assert!(c.contains(&"http://crux-ollama-1:11434".to_string()));
    }

    #[test]
    fn fallback_dedups_when_already_present() {
        let c = build_probe_candidates("http://host.docker.internal:11434");
        // Not localhost, so no rewrite.
        assert_eq!(c, vec!["http://host.docker.internal:11434".to_string()]);
    }

    #[test]
    #[serial_test::serial]
    fn embedding_probe_blocks_metadata_ip() {
        std::env::remove_var("CORECRUXD_EMBEDDING_URL");
        std::env::remove_var("CORECRUXD_EMBEDDING_PROBE_ALLOW_LOCAL");
        let err = validate_embedding_probe_url("http://169.254.169.254/latest").unwrap_err();
        assert!(err.contains("private"));
    }

    #[test]
    #[serial_test::serial]
    fn embedding_probe_blocks_private_cidr_by_default() {
        std::env::remove_var("CORECRUXD_EMBEDDING_URL");
        std::env::remove_var("CORECRUXD_EMBEDDING_PROBE_ALLOW_LOCAL");
        let err = validate_embedding_probe_url("http://10.0.0.5:11434").unwrap_err();
        assert!(err.contains("private"));
    }

    #[test]
    #[serial_test::serial]
    fn embedding_probe_allows_configured_local_endpoint() {
        std::env::set_var("CORECRUXD_EMBEDDING_URL", "http://127.0.0.1:11434");
        std::env::remove_var("CORECRUXD_EMBEDDING_PROBE_ALLOW_LOCAL");
        let policy = validate_embedding_probe_url("http://127.0.0.1:11434").expect("configured local endpoint");
        assert!(policy.allow_private_targets);
        std::env::remove_var("CORECRUXD_EMBEDDING_URL");
    }

    // ── M4 L2: CGNAT / Tailscale shared range 100.64.0.0/10 ──────────────
    #[test]
    fn cgnat_shared_range_counts_as_private() {
        use super::is_private_probe_ip;
        for ip in ["100.64.0.1", "100.100.5.5", "100.127.255.255"] {
            assert!(
                is_private_probe_ip(ip.parse().unwrap()),
                "{ip} is CGNAT (100.64.0.0/10) and must be blocked"
            );
        }
        // Just outside the /10 boundary, and unrelated 100.x — must NOT be flagged CGNAT.
        for ip in ["100.63.255.255", "100.128.0.0", "99.64.0.0", "101.64.0.0", "8.8.8.8"] {
            assert!(
                !is_private_probe_ip(ip.parse().unwrap()),
                "{ip} is not CGNAT/private and must be allowed"
            );
        }
    }

    #[test]
    #[serial_test::serial]
    fn embedding_probe_blocks_cgnat_by_default() {
        std::env::remove_var("CORECRUXD_EMBEDDING_URL");
        std::env::remove_var("CORECRUXD_EMBEDDING_PROBE_ALLOW_LOCAL");
        let err = validate_embedding_probe_url("http://100.64.0.5:11434").unwrap_err();
        assert!(err.contains("private"), "CGNAT target must be rejected: {err}");
    }

    // ── M4 L1: resolve-once-and-pin (DNS-rebind) ─────────────────────────
    #[test]
    fn resolve_validated_probe_addrs_pins_exact_validated_ip() {
        use super::{parse_embedding_probe_url, resolve_validated_probe_addrs};
        // A literal public IP resolves to exactly itself — this is the address
        // the PinnedResolver hands the transport, so the fetch cannot re-resolve
        // to a different (rebound) IP after the check.
        let parsed = parse_embedding_probe_url("http://8.8.8.8:11434").unwrap();
        let addrs = resolve_validated_probe_addrs(&parsed, false).unwrap();
        assert_eq!(addrs, vec!["8.8.8.8:11434".parse().unwrap()]);
    }

    #[test]
    fn resolve_validated_probe_addrs_rejects_blocked_ip() {
        use super::{parse_embedding_probe_url, resolve_validated_probe_addrs};
        for url in [
            "http://100.64.0.9:11434",
            "http://169.254.169.254:80",
            "http://10.1.2.3:11434",
        ] {
            let parsed = parse_embedding_probe_url(url).unwrap();
            assert!(
                resolve_validated_probe_addrs(&parsed, false).is_err(),
                "{url} must be rejected as private/CGNAT/metadata"
            );
        }
    }
}

fn build_probe_candidates(url: &str) -> Vec<String> {
    let trimmed = url.trim().trim_end_matches('/').to_string();
    let mut out = vec![trimmed.clone()];
    let lower = trimmed.to_lowercase();

    let is_localhost = lower.contains("//localhost") || lower.contains("//127.0.0.1") || lower.contains("//0.0.0.0");

    if is_localhost {
        for host in ["host.docker.internal", "crux-ollama-1"] {
            for needle in ["//localhost", "//127.0.0.1", "//0.0.0.0"] {
                if lower.contains(needle) {
                    let rewritten = trimmed.replace(needle.trim_start_matches("//"), host);
                    if !out.contains(&rewritten) {
                        out.push(rewritten);
                    }
                }
            }
        }
    }
    out
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_storage_breakdown(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }

    let retrieval = state.retrieval_index.read().await;
    let sparse_chunks = retrieval.total_docs();
    let tier_stats = retrieval.tier_stats();
    let sparse_bytes = (tier_stats.hot_bytes as u64).saturating_add(tier_stats.warm_bytes as u64);
    let sparse_segment_count = retrieval.segment_count();
    drop(retrieval);

    let extraction_rows = state.extraction_cache.read().await.len();
    let graph_edges = state.projection_state.read().await.relations.len();
    // Conservative byte estimate: each on-disk RelationRecord JSONL line is
    // ~150 bytes (tenant_id + edge_type + ids + timestamps + JSON envelope).
    let graph_bytes_est = (graph_edges as u64).saturating_mul(150);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "kinds": [
                {
                    "kind": "text_search",
                    "label": "Text Search",
                    "available": sparse_segment_count > 0,
                    "chunks": sparse_chunks,
                    "bytes": sparse_bytes,
                    "tooltip": "BM25 keyword search over sealed .ccxi companion indexes. Build with CORECRUXD_BUILD_CCXI=1; documents are added when shards seal a segment."
                },
                {
                    "kind": "projections",
                    "label": "Projections",
                    "available": extraction_rows > 0,
                    "chunks": extraction_rows,
                    "bytes": 0,
                    "tooltip": "Materialised cache rows derived from append events (extraction_cache_current). Populated by the projection runner; raw byte size is not tracked in this distribution."
                },
                {
                    "kind": "embedding",
                    "label": "Embedding",
                    "available": false,
                    "chunks": 0,
                    "bytes": 0,
                    "tooltip": "Dense vector embeddings produced by an external endpoint (Ollama, vLLM, TEI, llama.cpp, LiteLLM). Configure via CORECRUXD_EMBEDDING_URL / CORECRUXD_EMBEDDING_MODEL. Storage and counts surface once the embedding pipeline is wired."
                },
                {
                    "kind": "graph",
                    "label": "Graph",
                    "available": graph_edges > 0,
                    "chunks": graph_edges,
                    "bytes": graph_bytes_est,
                    "tooltip": "Relation edges (supports / contradicts / cites / supersedes / elaborates / derived_from / duplicates / about_same_entity). Write via POST /v1/relations; read via GET /v1/relations or POST /v1/relations/expand. Persisted to relations.jsonl."
                }
            ]
        })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_console_onboarding_restart(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_console_write(&state, &headers) {
        return problem.into_response();
    }
    let mut current = state.onboarding.write().await;
    current.completed_at_unix_ms = None;
    if let Err(err) = crate::onboarding::write_state(&state.data_dir, &current) {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "completed_at_unix_ms": null,
            "chosen_auth_mode": current.chosen_auth_mode
        })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_summary(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }

    let routing = state.routing.read().await;
    let readiness = state.readiness.read().await.clone();
    let capacity = state.capacity.read().await.clone();
    let update = state.update_status.read().await.clone();
    let fact_count = state.fact_store.read().await.count();
    let session_count = state.session_store.read().await.count();
    let integration_count = integration_snapshot(&state).map_or(0, |snapshot| snapshot.packs.len());

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "console": {
                "enabled": state.console_enabled,
                "route": "/console",
                "external_network_dependencies": 0
            },
            "daemon": {
                "build": state.build,
                "compat": state.compat,
                "sdk_version": state.sdk_version,
                "node_id": state.node_id,
                "auth_mode": state.auth.mode().as_str(),
                "mcp_enabled": state.mcp_enabled,
                "mcp_agent_count": state.mcp_agent_count,
                "dataplane_enabled": state.http_dataplane.enabled()
            },
            "routing": {
                "shard_map_version": routing.current_version(),
                "shard_count": routing.shard_count()
            },
            "readiness": {
                "control_evidence_hosted": readiness.control_evidence_hosted,
                "control_evidence_ok": readiness.control_evidence_ok,
                "control_evidence_error": readiness.control_evidence_error
            },
            "capacity": {
                "total_bytes": capacity.total_bytes,
                "free_bytes": capacity.free_bytes,
                "free_ratio": capacity.free_ratio,
                "emergency_free_ratio": capacity.emergency_free_ratio,
                "auto_paused": capacity.auto_paused,
                "error": capacity.error
            },
            "stores": {
                "facts": fact_count,
                "sessions": session_count
            },
            "integrations": {
                "enabled": state.integrations_enabled,
                "safe_mode": state.integrations_safe_mode,
                "allow_executable_helpers": state.integrations_allow_executable_helpers,
                "builtin_pack_count": integration_count
            },
            "update": update
        })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_integrations(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }

    if !state.integrations_enabled {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "enabled": false,
                "safe_mode": state.integrations_safe_mode,
                "allow_executable_helpers": state.integrations_allow_executable_helpers,
                "allowed_capabilities": crux_integrations::allowed_capabilities(),
                "packs": []
            })),
        )
            .into_response();
    }

    let snapshot = match integration_snapshot(&state) {
        Ok(snapshot) => snapshot,
        Err(err) => return integration_problem(err),
    };
    let packs = apply_safe_mode(snapshot.packs, state.integrations_safe_mode);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "enabled": true,
            "safe_mode": state.integrations_safe_mode,
            "allow_executable_helpers": state.integrations_allow_executable_helpers,
            "allowed_capabilities": crux_integrations::allowed_capabilities(),
            "packs": packs,
            "grants": snapshot.grants,
            "audit_tail": snapshot.audit_tail
        })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_console_integration_install(
    State(state): State<AppState>,
    Path(pack_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<InstallIntegrationBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["integrations:install"]) {
        return problem.into_response();
    }
    if !state.integrations_enabled {
        return problem_response(StatusCode::FORBIDDEN, "integrations are disabled");
    }
    if state.integrations_safe_mode {
        return problem_response(StatusCode::FORBIDDEN, "integration safe mode blocks install");
    }

    let manifest = match resolve_install_manifest(&pack_id, body) {
        Ok(manifest) => manifest,
        Err((status, detail)) => return problem_response(status, detail),
    };
    let trust_tier = manifest_trust_tier(&manifest);
    let descriptor = match crux_integrations::install_pack(
        &state.data_dir,
        &manifest,
        trust_tier,
        now_unix_ms(),
        &validation_policy(&state),
    ) {
        Ok(descriptor) => descriptor,
        Err(err) => return integration_problem(err),
    };

    (StatusCode::CREATED, Json(descriptor)).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_console_integration_grant(
    State(state): State<AppState>,
    Path(pack_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<GrantIntegrationBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["integrations:grant"]) {
        return problem.into_response();
    }
    if !state.integrations_enabled {
        return problem_response(StatusCode::FORBIDDEN, "integrations are disabled");
    }
    if state.integrations_safe_mode {
        return problem_response(StatusCode::FORBIDDEN, "integration safe mode blocks grants");
    }
    if body.capabilities.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "capabilities must not be empty");
    }

    let grant = match crux_integrations::grant_pack(
        &state.data_dir,
        crux_integrations::GrantPackRequest {
            passport_fpr: &state.passport_fpr,
            granted_by_passport_fpr: &state.passport_fpr,
            pack_id: &pack_id,
            version: &body.version,
            capabilities: &body.capabilities,
            reason: body.reason,
            now_unix_ms: now_unix_ms(),
        },
    ) {
        Ok(grant) => grant,
        Err(err) => return integration_problem(err),
    };

    (StatusCode::OK, Json(grant)).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_console_integration_disable(
    State(state): State<AppState>,
    Path(pack_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DisableIntegrationBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["integrations:disable"]) {
        return problem.into_response();
    }

    let grant = match crux_integrations::disable_pack(
        &state.data_dir,
        &state.passport_fpr,
        &pack_id,
        body.reason,
        now_unix_ms(),
    ) {
        Ok(grant) => grant,
        Err(err) => return integration_problem(err),
    };

    (StatusCode::OK, Json(grant)).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_passports(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "passport": {
                "fingerprint": state.passport_fpr,
                "public_key_hex": state.passport_public_key_hex,
                "private_key_exported": false,
                "claim_state": "local_or_anonymous_claim_pending"
            },
            "agents": {
                "registered_count": state.mcp_agent_count,
                "raw_tokens_exposed": false
            },
            "session_defaults": {
                "mcp_enabled": state.mcp_enabled,
                "mcp_path": "/mcp",
                "session_endpoint": "/session"
            }
        })),
    )
        .into_response()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ConsoleSessionsQuery {
    /// When true, archived sessions are included in the listing. Default false —
    /// archived sessions are preserved but hidden from the default view.
    #[serde(default)]
    pub include_archived: bool,
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ConsoleSessionsQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }

    // A session is "active" if it was written within this window, "idle" beyond
    // it, "archived" if soft-archived. `updated_at` is refreshed on every
    // `put()`, so it is the authoritative last-activity signal — the console
    // previously surfaced none, which is why every tile read as idle.
    const LIVE_WINDOW_MS: i64 = 15 * 60 * 1000; // 15 min (matches coord presence TTL)
    let now_ms = chrono::Utc::now().timestamp_millis();

    // Snapshot the base rows from the session store, then release its lock
    // before joining the fact store (bindings + coord) so we never hold two
    // stores at once. `title` (the logical id, scoped prefix stripped) is the
    // candidate key we join on — see `session_link_maps`.
    let (base, total_count, archived_count): (Vec<SessionRowBase>, usize, usize) = {
        let store = state.session_store.read().await;
        let total_count = store.count();
        let archived_count = store
            .list_filtered(true)
            .len()
            .saturating_sub(store.list_filtered(false).len());
        let rows = store
            .list_filtered(query.include_archived)
            .into_iter()
            .filter_map(|raw_key| store.get(raw_key).map(|session| (raw_key.to_string(), session)))
            .map(|(raw_key, session)| {
                let (agent, title) = match crux_mcp::scope::split_scoped_session_id(&raw_key) {
                    Some((owner, logical)) => (Some(owner.to_string()), logical.to_string()),
                    None => (None, raw_key.clone()),
                };
                let last_active_ms = session.updated_at.timestamp_millis();
                let live_state = if session.archived {
                    "archived"
                } else if now_ms.saturating_sub(last_active_ms) <= LIVE_WINDOW_MS {
                    "active"
                } else {
                    "idle"
                };
                SessionRowBase {
                    raw_key,
                    title,
                    agent,
                    archived: session.archived,
                    archived_at: session.archived_at.map(|t| t.to_rfc3339()),
                    archive_reason: session.archive_reason.clone(),
                    last_active_ms,
                    updated_at: session.updated_at.to_rfc3339(),
                    live_state,
                    total_tokens: session.total_tokens,
                    expires_at: session.expires_at.map(|t| t.to_rfc3339()),
                    state_first_line: session_state_first_line(&session.state),
                    // M21 — the conventional agent-authored name + summary
                    // (`state.title` / `state.summary`, documented on the
                    // `save_session` tool schema). Absent on every session written
                    // before the convention existed; the console says so rather
                    // than inventing a name.
                    state_title: session_state_str(&session.state, "title"),
                    state_summary: session_state_str(&session.state, "summary"),
                    // M21 — identity stamped at write time (see SessionState::actor).
                    actor: session.actor.clone(),
                }
            })
            .collect();
        (rows, total_count, archived_count)
    };

    // Passport (session binding) + live ExecPlan (coord intent) joins. The
    // session store is keyed by the raw scoped id; bindings/coord are keyed by
    // `session_id_hex` (a sealed-plan ULID). We join on the logical `title` the
    // same way `principal::resolve_by_session` does — passing the id straight to
    // `session_bindings::get_binding` / matching `coord::CoordIntent.session_id_hex`,
    // with NO client-side hashing. Sessions whose id is not a sealed-plan hex
    // (agent `save_session` ids) resolve to null — honest, not fabricated.
    let (binding_by_hex, intent_by_hex) = {
        let store = state.fact_store.read().await;
        let bindings: HashMap<String, crate::session_bindings::SessionBinding> =
            crate::session_bindings::list_bindings(&store)
                .into_iter()
                .map(|b| (b.session_id_hex.clone(), b))
                .collect();
        let now_u64 = now_ms.max(0) as u64;
        let intents: HashMap<String, crate::coord::CoordIntent> = crate::coord::list_intents(&store, None)
            .into_iter()
            .filter(|i| i.is_live(now_u64))
            .map(|i| (i.session_id_hex.clone(), i))
            .collect();
        (bindings, intents)
    };

    let mut rows: Vec<serde_json::Value> = base
        .into_iter()
        .map(|b| {
            let binding = binding_by_hex.get(&b.title);
            let intent = intent_by_hex.get(&b.title);
            serde_json::json!({
                "session_id": b.title,
                "agent": b.agent,
                "raw_key": b.raw_key,
                "archived": b.archived,
                "archived_at": b.archived_at,
                "archive_reason": b.archive_reason,
                "last_active_unix_ms": b.last_active_ms,
                "updated_at": b.updated_at,
                "state": b.live_state,
                "total_tokens": b.total_tokens,
                "expires_at": b.expires_at,
                "state_first_line": b.state_first_line,
                "state_title": b.state_title,
                "state_summary": b.state_summary,
                "actor": b.actor,
                "passport_id": binding.map(|x| x.passport_id.clone()),
                "passport_category": binding.map(|x| x.passport_category.clone()),
                "execplan_slug": intent.and_then(|x| x.execplan_slug.clone()),
                "milestone": intent.and_then(|x| x.milestone.clone()),
            })
        })
        .collect();
    // Most-recently-active first (was alphabetic by id).
    rows.sort_by(|a, b| {
        b["last_active_unix_ms"]
            .as_i64()
            .unwrap_or(0)
            .cmp(&a["last_active_unix_ms"].as_i64().unwrap_or(0))
    });
    // M21 — SESSION ALLOCATION, counted server-side over every listed row (before
    // the 100-row display truncation, so the numbers describe the store and not
    // the page). This exists because the honest answer to "why do so many sessions
    // lack a passport / plan?" needs a measurement, not an anecdote:
    //
    //  * `passport_id`/`execplan_slug` come from session BINDINGS and live coord
    //    INTENTS, both keyed by a sealed-plan `session_id_hex` ULID minted by
    //    POST /session. Agent `save_session` ids live in a DISJOINT key space
    //    (`__agent_session::<agent>::<slug>`), so they can never match — this is a
    //    key-space fact, not a bug, and the count makes it legible.
    //  * `actor` is the write-time identity stamp. It is `None` for anonymous
    //    callers (a daemon with no CRUX_AGENT_TOKENS — the default local posture)
    //    and for every session written before the stamp existed. There is no
    //    backfill pass, so `actor_pre_stamp_or_anonymous` will stay non-zero.
    let alloc_total = rows.len();
    let count_present =
        |key: &str| -> usize { rows.iter().filter(|r| r.get(key).is_some_and(|v| !v.is_null())).count() };
    let with_actor = count_present("actor");
    let with_agent = count_present("agent");
    let with_binding = count_present("passport_id");
    let with_intent = count_present("execplan_slug");
    let with_title = count_present("state_title");
    let with_any_identity = rows
        .iter()
        .filter(|r| !r["actor"].is_null() || !r["agent"].is_null() || !r["passport_id"].is_null())
        .count();
    let with_any_plan_link = rows
        .iter()
        .filter(|r| !r["execplan_slug"].is_null() || !r["passport_id"].is_null())
        .count();
    let allocation = serde_json::json!({
        "counted": alloc_total,
        "with_actor": with_actor,
        "with_agent_from_key_prefix": with_agent,
        "with_any_identity": with_any_identity,
        "no_identity": alloc_total.saturating_sub(with_any_identity),
        "with_passport_binding": with_binding,
        "with_live_execplan_intent": with_intent,
        "with_any_plan_link": with_any_plan_link,
        "no_plan_link": alloc_total.saturating_sub(with_any_plan_link),
        "with_agent_title": with_title,
        "no_agent_title": alloc_total.saturating_sub(with_title),
        "why": "passport_id/execplan_slug are keyed by the sealed-plan session_id_hex minted by POST /session; \
                agent save_session ids are a disjoint key space (__agent_session::<agent>::<slug>) and never match. \
                actor is stamped at write time and is absent for anonymous callers and for sessions written before the stamp.",
    });

    if rows.len() > 100 {
        rows.truncate(100);
    }

    // Backward-compatible flat list of friendly ids (consumed by the classic
    // console and any older caller). Mirrors `session_rows` post-filter/sort.
    let session_ids: Vec<&str> = rows.iter().filter_map(|r| r["session_id"].as_str()).collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "count": rows.len(),
            "total_count": total_count,
            "archived_count": archived_count,
            "include_archived": query.include_archived,
            "sessions": session_ids,
            "session_rows": rows,
            "allocation": allocation,
            "state_preview": "first_line",
            "raw_state_exposed": false
        })),
    )
        .into_response()
}

/// Owned snapshot of one session row taken while the session-store lock is held,
/// so the lock is released before the fact-store (binding + coord) join.
struct SessionRowBase {
    raw_key: String,
    /// Logical session id (scoped prefix stripped) — also the candidate key we
    /// join to bindings / coord intents on.
    title: String,
    agent: Option<String>,
    archived: bool,
    archived_at: Option<String>,
    archive_reason: Option<String>,
    last_active_ms: i64,
    updated_at: String,
    live_state: &'static str,
    total_tokens: usize,
    expires_at: Option<String>,
    state_first_line: Option<String>,
    /// Conventional `state.title` — the agent-given human name for the session.
    state_title: Option<String>,
    /// Conventional `state.summary` — one paragraph on where the work stands.
    state_summary: Option<String>,
    /// Identity stamped onto the record at write time (`SessionState::actor`).
    /// `None` for anonymous writers and for every session written before the
    /// field existed — there is no backfill and none is invented.
    actor: Option<String>,
}

/// Read one CONVENTIONAL top-level string field out of a session `state` blob,
/// clipped like the first-line preview. Same redaction stance as
/// [`session_state_first_line`]: named conventional keys only, never an
/// arbitrary-leaf walk, so an agent's stashed secret can never ride the list.
fn session_state_str(state: &serde_json::Value, field: &str) -> Option<String> {
    let s = state.as_object()?.get(field)?.as_str()?;
    clip_preview(s, 240)
}

/// Collapse whitespace and clip to `max` chars with an ellipsis. Empty → `None`.
fn clip_preview(s: &str, max: usize) -> Option<String> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    let one_line: String = t.split_whitespace().collect::<Vec<_>>().join(" ");
    Some(if one_line.chars().count() > max {
        let mut out: String = one_line.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    } else {
        one_line
    })
}

/// Server-derived short (≤140 char) preview of a session `state` blob. Picks the
/// first meaningful string among the CONVENTIONAL summary fields only
/// (`decisions`/`decisions_made` first element, `note`, `context_summary`,
/// `summary`). Returns `None` for a blob that carries none of those.
///
/// This is deliberately NOT a "first string leaf anywhere" walk: the sessions
/// LIST is guarded by `console_redacts_private_facts_and_session_state` (state
/// content must not transit the list), and an arbitrary-leaf preview would leak
/// whatever an agent happened to stash (e.g. a `{"token": …}` blob). The
/// convention fields are the human-authored session summary — the intended,
/// safe preview. The full blob is exposed only by the admin-read detail route.
fn session_state_first_line(state: &serde_json::Value) -> Option<String> {
    fn clip140(s: &str) -> Option<String> {
        clip_preview(s, 140)
    }
    // Convention-only: the fields agents write by habit (see session_store tests
    // + CLAUDE.md fact conventions). No arbitrary-leaf fallback — see the doc note.
    let obj = state.as_object()?;
    for field in ["decisions", "decisions_made"] {
        if let Some(first) = obj.get(field).and_then(|v| v.as_array()).and_then(|a| a.first()) {
            if let Some(s) = first.as_str().and_then(clip140) {
                return Some(s);
            }
        }
    }
    for field in ["note", "context_summary", "summary"] {
        if let Some(s) = obj.get(field).and_then(|v| v.as_str()).and_then(clip140) {
            return Some(s);
        }
    }
    None
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ConsoleSessionDetailQuery {
    /// The raw scoped session-store key (e.g. `__agent_session::openai::slug`).
    /// A query param, not a path segment, because raw keys contain `/` and `::`.
    pub key: String,
}

/// `GET /v1/console/sessions/detail?key=<raw_key>` — the full operator drawer for
/// one session (console-surfaces-remediation M3). Same auth as the list
/// (admin-read). DELIBERATELY exposes the full `state` blob — a plan decision for
/// the operator console — which is why it does NOT flow through the canvas
/// `renderSessionDetail` path (whose smoke gate forbids reading session state).
///
/// Joins (all honest-null when absent):
///   * `binding` — passport via `session_bindings::get_binding` on the logical id.
///   * `coord_intent` — live ExecPlan focus via `coord::list_intents` (TTL).
///   * `gates` — cross-work `__work_transition__::` scan where `by_passport`
///     matches the bound passport and the gate was decided (approved / rejected /
///     auto_approved), newest first, capped at 50.
///   * `linked_plans_heuristic` — `execplan:*` facts authored by the bound
///     passport, grouped by entity, top 5 by latest write. Fact-authorship is a
///     heuristic — journaled session↔plan linkage is a daemon follow-up.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_session_detail(
    State(state): State<AppState>,
    Query(query): Query<ConsoleSessionDetailQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }

    // Resolve the session from the store by its raw key.
    const LIVE_WINDOW_MS: i64 = 15 * 60 * 1000;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let session = {
        let store = state.session_store.read().await;
        store.get(&query.key).cloned()
    };
    let Some(session) = session else {
        return problem_response(
            StatusCode::NOT_FOUND,
            format!("no session stored under key '{}'", query.key),
        );
    };

    let (agent, title) = match crux_mcp::scope::split_scoped_session_id(&query.key) {
        Some((owner, logical)) => (Some(owner.to_string()), logical.to_string()),
        None => (None, query.key.clone()),
    };
    let last_active_ms = session.updated_at.timestamp_millis();
    let live_state = if session.archived {
        "archived"
    } else if now_ms.saturating_sub(last_active_ms) <= LIVE_WINDOW_MS {
        "active"
    } else {
        "idle"
    };

    // Fact-store joins under a single read lock.
    let store = state.fact_store.read().await;
    let binding = crate::session_bindings::get_binding(&store, &title);
    let now_u64 = now_ms.max(0) as u64;
    let coord_intent = crate::coord::list_intents(&store, None)
        .into_iter()
        .find(|i| i.session_id_hex == title && i.is_live(now_u64));

    // Gates + linked plans require the bound passport as the actor key.
    let (gates, linked_plans) = match binding.as_ref() {
        Some(b) => (
            gates_for_passport(&store, &b.passport_id),
            linked_plans_for_passport(&store, &b.passport_id),
        ),
        None => (Vec::new(), Vec::new()),
    };
    drop(store);

    let binding_json = binding.as_ref().map(|b| {
        serde_json::json!({
            "passport_id": b.passport_id,
            "passport_category": b.passport_category,
            "project_id": b.project_id,
        })
    });
    let coord_json = coord_intent.as_ref().map(|i| {
        serde_json::json!({
            "execplan_slug": i.execplan_slug,
            "milestone": i.milestone,
            "paths": i.paths,
            "note": i.note,
        })
    });

    let session_meta = serde_json::json!({
        "session_id": title,
        "agent": agent,
        "raw_key": query.key,
        "archived": session.archived,
        "archived_at": session.archived_at.map(|t| t.to_rfc3339()),
        "archive_reason": session.archive_reason,
        "last_active_unix_ms": last_active_ms,
        "updated_at": session.updated_at.to_rfc3339(),
        "state": live_state,
        "total_tokens": session.total_tokens,
        "expires_at": session.expires_at.map(|t| t.to_rfc3339()),
        "state_first_line": session_state_first_line(&session.state),
        "state_title": session_state_str(&session.state, "title"),
        "state_summary": session_state_str(&session.state, "summary"),
        "actor": session.actor,
        "passport_id": binding.as_ref().map(|b| b.passport_id.clone()),
        "passport_category": binding.as_ref().map(|b| b.passport_category.clone()),
        "execplan_slug": coord_intent.as_ref().and_then(|i| i.execplan_slug.clone()),
        "milestone": coord_intent.as_ref().and_then(|i| i.milestone.clone()),
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "session": session_meta,
            "state": session.state,
            "binding": binding_json,
            "coord_intent": coord_json,
            "gates": gates,
            "linked_plans_heuristic": linked_plans,
        })),
    )
        .into_response()
}

/// Cross-work scan of `__work_transition__::` facts for the gates a passport
/// decided (approved / rejected / auto_approved), newest first, capped at 50.
/// Each row carries the work title when the work item is still readable.
fn gates_for_passport(store: &corecrux_memory::fact_store::FactStore, passport_id: &str) -> Vec<serde_json::Value> {
    let prefix = format!("{}::", crate::work::WORK_TRANSITION_ENTITY_PREFIX);
    let mut transitions: Vec<crate::work::WorkTransition> = store
        .all_facts()
        .filter(|f| !f.deleted && f.key == crate::work::RECORD_KEY && f.entity.starts_with(&prefix))
        .filter_map(|f| serde_json::from_str::<crate::work::WorkTransition>(&f.value).ok())
        .filter(|t| {
            t.by_passport == passport_id && matches!(t.gate_status.as_str(), "approved" | "rejected" | "auto_approved")
        })
        .collect();
    transitions.sort_by(|a, b| b.at_unix_ms.cmp(&a.at_unix_ms));
    transitions.truncate(50);

    // Resolve work titles once per distinct work id (bounded by the 50 cap).
    let mut titles: HashMap<String, Option<String>> = HashMap::new();
    transitions
        .into_iter()
        .map(|t| {
            let work_title = titles
                .entry(t.work_id.clone())
                .or_insert_with(|| crate::work::get_work(store, &t.work_id).map(|w| w.title))
                .clone();
            serde_json::json!({
                "work_id": t.work_id,
                "work_title": work_title,
                "from_state": t.from_state,
                "to_state": t.to_state,
                "gate_status": t.gate_status,
                "at_unix_ms": t.at_unix_ms,
                "receipt_id": t.receipt_id,
            })
        })
        .collect()
}

/// `execplan:*` facts authored by a passport, grouped by entity, top 5 by latest
/// write. Heuristic linkage — fact authorship, not a journaled session↔plan edge.
fn linked_plans_for_passport(
    store: &corecrux_memory::fact_store::FactStore,
    passport_id: &str,
) -> Vec<serde_json::Value> {
    // (matches, latest stored_at ms) per execplan entity.
    let mut by_entity: BTreeMap<String, (u64, i64)> = BTreeMap::new();
    for f in store.all_facts() {
        if f.deleted || !f.entity.starts_with("execplan:") {
            continue;
        }
        if f.actor.as_deref() != Some(passport_id) {
            continue;
        }
        let at = f.stored_at.timestamp_millis();
        let e = by_entity.entry(f.entity.clone()).or_insert((0, at));
        e.0 += 1;
        if at > e.1 {
            e.1 = at;
        }
    }
    let mut rows: Vec<(String, u64, i64)> = by_entity.into_iter().map(|(k, (n, at))| (k, n, at)).collect();
    rows.sort_by(|a, b| b.2.cmp(&a.2));
    rows.truncate(5);
    rows.into_iter()
        .map(|(entity, matches, latest_at)| {
            serde_json::json!({
                "entity": entity,
                "matches": matches,
                "latest_at": latest_at,
            })
        })
        .collect()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ConsoleFactsQuery {
    pub q: Option<String>,
    pub top_k: Option<usize>,
    /// AX time-machine (#6): when set, the response only includes facts whose
    /// `stored_at` is <= this Unix-ms timestamp. Useful for "view facts as of T".
    pub as_of_unix_ms: Option<i64>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ConsoleAddFactBody {
    pub entity: String,
    pub key: String,
    pub value: String,
    #[serde(default = "default_console_confidence")]
    pub confidence: f32,
}

fn default_console_confidence() -> f32 {
    1.0
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_facts(
    State(state): State<AppState>,
    Query(query): Query<ConsoleFactsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }

    let q = query
        .q
        .as_ref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let top_k = query.top_k.unwrap_or(50).clamp(1, 200);

    let store = state.fact_store.read().await;
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: q.clone(),
        entity: None,
        entity_prefix: None,
        top_k,
        token_budget: None,
    });
    let mut visible_facts: Vec<_> = result.facts.into_iter().filter(|fact| !fact.private).collect();

    // #6 — server-side as-of filter. We compare against `stored_at` (DateTime<Utc>)
    // converted to ms; facts created strictly after the cutoff are dropped.
    if let Some(as_of) = query.as_of_unix_ms.filter(|t| *t > 0) {
        visible_facts.retain(|fact| fact.stored_at.timestamp_millis() <= as_of);
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "count": store.count(),
            "visible_count": visible_facts.len(),
            "query": q,
            "top_k": top_k,
            "as_of_unix_ms": query.as_of_unix_ms,
            "private_facts_hidden": true,
            "facts": visible_facts,
            "total_tokens": result.total_tokens
        })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_console_fact_add(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ConsoleAddFactBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["facts:write"]) {
        return problem.into_response();
    }
    let ctx = match crate::auth::http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };

    let entity = body.entity.trim();
    let key = body.key.trim();
    let value = body.value.trim();
    if entity.is_empty() || key.is_empty() || value.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "entity, key, and value must all be non-empty");
    }
    if !(0.0..=1.0).contains(&body.confidence) {
        return problem_response(StatusCode::BAD_REQUEST, "confidence must be in [0.0, 1.0]");
    }

    let mut store = state.fact_store.write().await;
    if let Err(e) =
        crux_mcp::category_enforce::check_passport_can_write_entity(&store, ctx.passport_id.as_deref(), entity)
    {
        return problem_response(StatusCode::FORBIDDEN, e.to_string());
    }
    let mut sf = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: entity.to_string(),
        key: key.to_string(),
        value: value.to_string(),
        source_receipt: None,
        confidence: body.confidence,
        // Default false; the privacy gate below promotes to true for any
        // entity matching an always-private prefix (__ax__::, __work__::,
        // __project_layer__::, github::, etc.).
        private: false,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    let stored = store.store(sf);

    (StatusCode::CREATED, Json(stored)).into_response()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ConsoleTenantsQuery {
    pub category: Option<String>,
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_tenants(
    State(state): State<AppState>,
    Query(query): Query<ConsoleTenantsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }

    let category_filter = match query.category.as_deref() {
        None | Some("") | Some("all") => None,
        Some("personal") => Some("personal"),
        Some("work") => Some("work"),
        Some("public") => Some("public"),
        Some(other) => {
            return problem_response(
                StatusCode::BAD_REQUEST,
                format!("category must be one of personal, work, public, all (got '{other}')"),
            );
        }
    };

    let routing = state.routing.read().await;
    let store = state.fact_store.read().await;
    let mut tenants = BTreeSet::new();
    tenants.insert("local".to_string());
    for entity in store.entities() {
        if let Some((tenant, _rest)) = entity.split_once("::") {
            if !tenant.is_empty() {
                tenants.insert(tenant.to_string());
            }
        }
    }
    if let Ok(indexed_tenants) = crate::console_index::list_tenants(&state.data_dir) {
        tenants.extend(indexed_tenants);
    }

    let tenant_objects: Vec<_> = tenants
        .into_iter()
        .map(|tenant_id| {
            let override_ = crate::tenant_metadata::get_tenant_category_override(&store, &tenant_id);
            let category = crux_mcp::tenant_category::classify_tenant(&tenant_id, override_).as_str();
            serde_json::json!({
                "tenant_id": tenant_id,
                "category": category,
                "override": override_.map(|c| c.as_str()),
                "source": "local_metadata",
                "chunk_visibility": "metadata_only",
                "content_preview": false
            })
        })
        .filter(|t| match category_filter {
            Some(filter) => t["category"] == filter,
            None => true,
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tenants": tenant_objects,
            "category_filter": category_filter,
            "routing": {
                "shard_map_version": routing.current_version(),
                "shard_count": routing.shard_count()
            },
            "dataplane_enabled": state.http_dataplane.enabled()
        })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_tenant_chunks(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    Query(query): Query<ConsoleChunksQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["tenant:chunks:read"], &tenant_id) {
        return problem.into_response();
    }

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let page = match crate::console_index::list_chunks(&state.data_dir, &tenant_id, limit, query.cursor.as_deref()) {
        Ok(page) => page,
        Err(err) => return problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tenant_id": tenant_id,
            "chunks": page.chunks,
            "page": {
                "limit": limit,
                "cursor": query.cursor,
                "next_cursor": page.next_cursor
            },
            "visibility": "metadata_only",
            "dataplane_enabled": state.http_dataplane.enabled(),
            "detail": "chunk metadata is populated from HTTP append metadata when available; raw content remains gated by preview scope"
        })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_chunk(
    State(state): State<AppState>,
    Path(chunk_digest): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }

    let Some(chunk) = (match crate::console_index::find_chunk(&state.data_dir, &chunk_digest) {
        Ok(chunk) => chunk,
        Err(err) => return problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }) else {
        return problem_response(StatusCode::NOT_FOUND, "chunk metadata not found");
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "chunk_digest": chunk_digest,
            "present": true,
            "visibility": "metadata_only",
            "dataplane_enabled": state.http_dataplane.enabled(),
            "metadata": chunk,
            "detail": "raw content preview requires tenant:content:preview scope"
        })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_chunk_preview(
    State(state): State<AppState>,
    Path(chunk_digest): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let Some(chunk) = (match crate::console_index::find_chunk(&state.data_dir, &chunk_digest) {
        Ok(chunk) => chunk,
        Err(err) => return problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }) else {
        return problem_response(StatusCode::NOT_FOUND, "chunk metadata not found");
    };

    if let Err(problem) =
        require_http_scopes_for_tenant(&state.auth, &headers, &["tenant:content:preview"], &chunk.tenant_id)
    {
        return problem.into_response();
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "chunk_digest": chunk_digest,
            "tenant_id": chunk.tenant_id,
            "preview": chunk.redacted_preview,
            "preview_available": chunk.preview_available,
            "redacted": true,
            "detail": "console preview is redacted; raw chunk bytes are not returned by this endpoint"
        })),
    )
        .into_response()
}

#[allow(clippy::result_large_err)]
fn require_console_read(state: &AppState, headers: &HeaderMap) -> Result<(), crate::problem::ProblemResponse> {
    require_http_scopes(&state.auth, headers, &["admin:read"])
}

/// Opt-in for returning the raw agent token from `GET /v1/console/connections`.
///
/// Default OFF, and it must stay that way. The console is publicly exposed
/// (`crux.cuecrux.com`), and the agent token is the credential for the entire MCP
/// surface — a route that hands it back is a credential-disclosure route, so the
/// operator has to arm it deliberately on a daemon they administer.
///
/// Note for anyone tempted to replace this with a peer-address check: the public
/// console is proxied by Caddy on the same host, so every public request arrives
/// from loopback. `auth_rails::peer_identity_trusted` would return `true` for the
/// open internet — an address gate here would leak the token while looking like a
/// security control.
const CONSOLE_REVEAL_AGENT_TOKEN_ENV: &str = "CORECRUXD_CONSOLE_REVEAL_AGENT_TOKEN";

/// Non-reversible identifier for a token: first 8 hex of its SHA-256.
///
/// Enough for an operator to confirm the console, the daemon env, and their
/// client all mean the same credential, without disclosing any of it. Deliberately
/// a digest prefix rather than a slice of the token itself.
fn token_fingerprint(token: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(token.as_bytes());
    hex::encode(digest)[..8].to_string()
}

/// `GET /v1/console/connections` — how a client connects to this daemon.
///
/// Returns endpoint URLs plus the state of the agent-token rail. The token's raw
/// value is included ONLY when `CORECRUXD_CONSOLE_REVEAL_AGENT_TOKEN=1`; otherwise
/// the response carries a fingerprint and length so the operator can identify the
/// credential without the route disclosing it.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_connections(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }

    // Mirrors the resolution order in `crux_mcp::agent`: the multi-agent map
    // wins, then the single-token var.
    let named = std::env::var("CRUX_AGENT_TOKENS").ok().filter(|s| !s.trim().is_empty());
    let single = std::env::var("CRUX_AGENT_TOKEN").ok().filter(|s| !s.trim().is_empty());

    let reveal = super::auth_rails::env_flag_enabled(CONSOLE_REVEAL_AGENT_TOKEN_ENV);
    let (source, token) = match (&named, &single) {
        // `name:token,name:token` — report the names, never the secrets, and
        // leave reveal to the single-token rail.
        (Some(raw), _) => {
            let names: Vec<&str> = raw
                .split(',')
                .filter_map(|pair| pair.split_once(':').map(|(name, _)| name.trim()))
                .filter(|name| !name.is_empty())
                .collect();
            ("CRUX_AGENT_TOKENS", Some((names.join(", "), None::<String>)))
        }
        (None, Some(tok)) => ("CRUX_AGENT_TOKEN", Some((String::new(), Some(tok.clone())))),
        (None, None) => ("", None),
    };

    let token_json = match token {
        None => serde_json::json!({
            "configured": false,
            "hint": "no CRUX_AGENT_TOKEN or CRUX_AGENT_TOKENS in the daemon environment; \
                     this daemon accepts MCP requests without a bearer token",
        }),
        Some((names, raw)) => {
            let mut obj = serde_json::json!({
                "configured": true,
                "source_env": source,
                "reveal_enabled": reveal,
            });
            if !names.is_empty() {
                obj["agent_names"] = serde_json::json!(names);
            }
            if let Some(raw) = raw {
                obj["fingerprint"] = serde_json::json!(token_fingerprint(&raw));
                obj["length"] = serde_json::json!(raw.len());
                if reveal {
                    obj["token"] = serde_json::json!(raw);
                } else {
                    obj["hint"] = serde_json::json!(format!(
                        "set {CONSOLE_REVEAL_AGENT_TOKEN_ENV}=1 on this daemon to reveal the \
                         token here, or read {source} from the daemon's environment file"
                    ));
                }
            } else {
                obj["hint"] = serde_json::json!(
                    "per-agent tokens are never revealed here; read CRUX_AGENT_TOKENS from the \
                     daemon's environment file"
                );
            }
            obj
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "mcp": {
                "path": "/mcp",
                "local_url": "http://127.0.0.1:14801/mcp",
                "note": "the MCP port (14801) is separate from this HTTP port (14800); a public \
                         deployment usually proxies /mcp on 443 instead of exposing 14801",
            },
            "agent_token": token_json,
            "claude_desktop": {
                "bundle_url": "/console-assets/crux.mcpb",
                "filename": "crux.mcpb",
                "install": "download, then drag onto Claude Desktop's Settings → Extensions pane",
                "prompts_for": ["server_url", "agent_token"],
            },
        })),
    )
        .into_response()
}

#[allow(clippy::result_large_err)]
fn require_console_write(state: &AppState, headers: &HeaderMap) -> Result<(), crate::problem::ProblemResponse> {
    require_http_scopes(&state.auth, headers, &["admin:write"])
}

/// Build the response body for `GET/PATCH /v1/console/tenants/:tenant/category`.
/// `effective` is what `classify_tenant` returns under the current override.
fn tenant_category_response(
    tenant_id: &str,
    override_: Option<crux_mcp::tenant_category::TenantCategory>,
) -> serde_json::Value {
    let effective = crux_mcp::tenant_category::classify_tenant(tenant_id, override_);
    let derived = crux_mcp::tenant_category::classify_tenant(tenant_id, None);
    serde_json::json!({
        "tenant_id": tenant_id,
        "derived": derived.as_str(),
        "override": override_.map(|c| c.as_str()),
        "effective": effective.as_str(),
    })
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_console_tenant_category(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }
    if tenant_id.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id must not be empty".to_string());
    }
    let store = state.fact_store.read().await;
    let override_ = crate::tenant_metadata::get_tenant_category_override(&store, &tenant_id);
    let body = tenant_category_response(&tenant_id, override_);
    (StatusCode::OK, Json(body)).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn patch_console_tenant_category(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<crate::tenant_metadata::PatchTenantCategoryBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_write(&state, &headers) {
        return problem.into_response();
    }
    if tenant_id.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id must not be empty".to_string());
    }
    // `parse_user_input` rejects "system" with its own error; surface as 400.
    let category = match crux_mcp::tenant_category::TenantCategory::parse_user_input(&body.category) {
        Ok(c) => c,
        Err(e) => {
            return problem_response(StatusCode::BAD_REQUEST, e.to_string());
        }
    };
    let mut store = state.fact_store.write().await;
    if let Err(e) = crate::tenant_metadata::set_tenant_category_override(&mut store, &tenant_id, category) {
        return problem_response(StatusCode::BAD_REQUEST, e.to_string());
    }
    // Re-read so the response reflects what's actually in the store.
    let override_ = crate::tenant_metadata::get_tenant_category_override(&store, &tenant_id);
    let resp = tenant_category_response(&tenant_id, override_);
    (StatusCode::OK, Json(resp)).into_response()
}

fn validation_policy(state: &AppState) -> crux_integrations::ValidationPolicy {
    crux_integrations::ValidationPolicy {
        allow_executable_helpers: state.integrations_allow_executable_helpers,
        ..crux_integrations::ValidationPolicy::default()
    }
}

fn integration_snapshot(
    state: &AppState,
) -> Result<crux_integrations::IntegrationLibrarySnapshot, crux_integrations::IntegrationError> {
    crux_integrations::library_snapshot(&state.data_dir, &state.passport_fpr, &validation_policy(state))
}

fn apply_safe_mode(
    packs: Vec<crux_integrations::IntegrationPackDescriptor>,
    safe_mode: bool,
) -> Vec<crux_integrations::IntegrationPackDescriptor> {
    if !safe_mode {
        return packs;
    }
    packs
        .into_iter()
        .map(|mut pack| {
            if pack.trust_tier != crux_integrations::TrustTier::FirstParty
                && pack.install_state == crux_integrations::InstallState::Enabled
            {
                pack.install_state = crux_integrations::InstallState::Blocked;
            }
            pack
        })
        .collect()
}

fn resolve_install_manifest(
    path_pack_id: &str,
    body: InstallIntegrationBody,
) -> Result<crux_integrations::IntegrationManifest, (StatusCode, &'static str)> {
    if let Some(manifest) = body.manifest {
        if manifest.id != path_pack_id {
            return Err((StatusCode::BAD_REQUEST, "manifest id must match path pack id"));
        }
        return Ok(manifest);
    }

    let version = body.version.unwrap_or_else(|| "0.1.0".to_string());
    let manifest = crux_integrations::builtin_manifests()
        .into_iter()
        .find(|manifest| manifest.id == path_pack_id && manifest.version == version)
        .ok_or((StatusCode::NOT_FOUND, "integration pack not found"))?;
    if let Some(body_pack_id) = body.pack_id {
        if body_pack_id != path_pack_id {
            return Err((StatusCode::BAD_REQUEST, "body pack_id must match path pack id"));
        }
    }
    Ok(manifest)
}

fn manifest_trust_tier(manifest: &crux_integrations::IntegrationManifest) -> crux_integrations::TrustTier {
    if manifest.publisher_passport_fpr == crux_integrations::FIRST_PARTY_PASSPORT {
        crux_integrations::TrustTier::FirstParty
    } else if manifest.signature.is_some() {
        crux_integrations::TrustTier::LocallySigned
    } else {
        crux_integrations::TrustTier::Unknown
    }
}

fn integration_problem(err: crux_integrations::IntegrationError) -> axum::response::Response {
    let status = match err {
        crux_integrations::IntegrationError::PackNotInstalled { .. }
        | crux_integrations::IntegrationError::GrantNotFound { .. } => StatusCode::NOT_FOUND,
        crux_integrations::IntegrationError::ExternalHelperDisabled => StatusCode::FORBIDDEN,
        crux_integrations::IntegrationError::Io(_) | crux_integrations::IntegrationError::Json(_) => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        _ => StatusCode::BAD_REQUEST,
    };
    problem_response(status, err.to_string())
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod lane_weight_tests {
    use super::*;

    fn st() -> AppState {
        super::super::tests::test_app_state(16)
    }

    async fn status_of(resp: axum::response::Response) -> StatusCode {
        resp.status()
    }

    #[test]
    fn canonical_lane_key_aliases_and_unknown() {
        assert_eq!(canonical_lane_key("BM25"), Some("bm25"));
        assert_eq!(canonical_lane_key("dense"), Some("cosine"));
        assert_eq!(canonical_lane_key("vector"), Some("cosine"));
        assert_eq!(canonical_lane_key("splade"), Some("sparse"));
        assert_eq!(canonical_lane_key("ccxdi"), Some("indexing"));
        assert_eq!(canonical_lane_key("nav"), Some("navtree"));
        assert_eq!(canonical_lane_key("event"), Some("events"));
        assert_eq!(canonical_lane_key("nonsense"), None);
    }

    #[test]
    fn default_lane_weights_has_all_lanes() {
        let d = default_lane_weights();
        assert_eq!(d.len(), 10);
        assert_eq!(d["bm25"], 1.0);
        assert_eq!(d["topology"], 0.0);
    }

    #[test]
    fn normalize_lane_weights_valid_and_errors() {
        let mut raw = BTreeMap::new();
        raw.insert("BM25".to_string(), 2.0);
        raw.insert("dense".to_string(), 0.5);
        let out = normalize_lane_weights(&raw).unwrap();
        assert_eq!(out["bm25"], 2.0);
        assert_eq!(out["cosine"], 0.5);

        let mut bad = BTreeMap::new();
        bad.insert("not-a-lane".to_string(), 1.0);
        assert!(normalize_lane_weights(&bad).unwrap_err().contains("unknown lane"));

        let mut neg = BTreeMap::new();
        neg.insert("bm25".to_string(), -1.0);
        assert!(normalize_lane_weights(&neg).is_err());

        let mut nan = BTreeMap::new();
        nan.insert("bm25".to_string(), f64::NAN);
        assert!(normalize_lane_weights(&nan).is_err());
    }

    #[test]
    fn normalize_optional_tenant_trims_and_drops_empty() {
        assert_eq!(
            normalize_optional_tenant(Some("  t1 ".to_string())),
            Some("t1".to_string())
        );
        assert_eq!(normalize_optional_tenant(Some("   ".to_string())), None);
        assert_eq!(normalize_optional_tenant(None), None);
    }

    #[test]
    fn parse_overlay_map_extracts_string_values_only() {
        let body = serde_json::json!({ "overlay": { "A": "1", "B": 2, "C": "x" } });
        let m = parse_overlay_map(&body);
        assert_eq!(m.get("A").map(String::as_str), Some("1"));
        assert_eq!(m.get("C").map(String::as_str), Some("x"));
        assert!(!m.contains_key("B"), "non-string values are dropped");
        assert!(parse_overlay_map(&serde_json::json!({})).is_empty());
    }

    #[test]
    fn overlay_bool_prefers_tenant_then_global() {
        let mut tenant = BoostOverlay::new();
        let mut global = BoostOverlay::new();
        global.insert("FEATURE".to_string(), "true".to_string());
        assert!(overlay_bool(&tenant, &global, "FEATURE"));
        tenant.insert("FEATURE".to_string(), "0".to_string());
        assert!(!overlay_bool(&tenant, &global, "FEATURE"), "tenant overrides global");
        assert!(!overlay_bool(&BoostOverlay::new(), &BoostOverlay::new(), "MISSING"));
    }

    #[test]
    fn parse_lane_weights_raw_json_kv_and_empty() {
        // empty → defaults
        assert_eq!(parse_lane_weights_raw("  "), default_lane_weights());
        // JSON object form
        let j = parse_lane_weights_raw(r#"{"bm25": 3.0, "dense": 0.25, "bad": 9}"#);
        assert_eq!(j["bm25"], 3.0);
        assert_eq!(j["cosine"], 0.25);
        // comma/kv form with = and :
        let kv = parse_lane_weights_raw("bm25=2, cosine:0.5, junk, navtree=oops");
        assert_eq!(kv["bm25"], 2.0);
        assert_eq!(kv["cosine"], 0.5);
        // navtree=oops fails to parse → stays default 0.0
        assert_eq!(kv["navtree"], 0.0);
    }

    #[test]
    fn resolved_lane_weights_precedence() {
        let mut global = BTreeMap::new();
        let mut tenant = BTreeMap::new();
        // default when neither set
        let (_, src, raw) = resolved_lane_weights(&global, &tenant);
        assert_eq!(src, "default");
        assert!(raw.is_none());
        // global set
        global.insert(CORECRUX_LANE_WEIGHTS_KEY.to_string(), "bm25=5".to_string());
        let (w, src, _) = resolved_lane_weights(&global, &tenant);
        assert_eq!(src, "global");
        assert_eq!(w["bm25"], 5.0);
        // tenant overrides global
        tenant.insert(CORECRUX_LANE_WEIGHTS_KEY.to_string(), "bm25=7".to_string());
        let (w, src, _) = resolved_lane_weights(&global, &tenant);
        assert_eq!(src, "tenant");
        assert_eq!(w["bm25"], 7.0);
    }

    #[test]
    fn lane_weights_to_overlay_json_fills_all_keys() {
        let mut w = BTreeMap::new();
        w.insert("bm25".to_string(), 2.5);
        let json = lane_weights_to_overlay_json(&w).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["bm25"], 2.5);
        // unset lanes fall back to defaults
        assert!(v.get("cosine").is_some());
    }

    #[test]
    #[serial_test::serial]
    fn corecrux_base_url_from_env_unset_and_set() {
        for k in [
            "CORECRUXD_CORECRUX_BASE_URL",
            "CORECRUXD_CORECRUX_URL",
            "CORECRUX_BASE_URL",
        ] {
            std::env::remove_var(k);
        }
        assert!(corecrux_base_url_from_env().is_err());
        std::env::set_var("CORECRUX_BASE_URL", "http://engine:9/");
        assert_eq!(corecrux_base_url_from_env().unwrap(), "http://engine:9");
        std::env::remove_var("CORECRUX_BASE_URL");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn lane_weight_handlers_503_without_engine_and_400_on_empty() {
        for k in [
            "CORECRUXD_CORECRUX_BASE_URL",
            "CORECRUXD_CORECRUX_URL",
            "CORECRUX_BASE_URL",
        ] {
            std::env::remove_var(k);
        }
        let state = st();
        // GET → 503 (engine unconfigured).
        let resp = get_console_corecrux_lane_weights(
            State(state.clone()),
            HeaderMap::new(),
            Query(CoreCruxLaneWeightsQuery { tenant_id: None }),
        )
        .await
        .into_response();
        assert_eq!(status_of(resp).await, StatusCode::SERVICE_UNAVAILABLE);

        // PUT empty weights → 400 (before engine lookup).
        let resp = put_console_corecrux_lane_weights(
            State(state.clone()),
            HeaderMap::new(),
            Json(UpdateCoreCruxLaneWeightsBody {
                weights: BTreeMap::new(),
                tenant_id: None,
                fusion_rrf_enabled: true,
                actor: None,
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(status_of(resp).await, StatusCode::BAD_REQUEST);

        // PUT unknown lane → 400.
        let mut weights = BTreeMap::new();
        weights.insert("not-a-lane".to_string(), 1.0);
        let resp = put_console_corecrux_lane_weights(
            State(state.clone()),
            HeaderMap::new(),
            Json(UpdateCoreCruxLaneWeightsBody {
                weights,
                tenant_id: None,
                fusion_rrf_enabled: true,
                actor: None,
                reason: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(status_of(resp).await, StatusCode::BAD_REQUEST);

        // DELETE → 503.
        let resp = delete_console_corecrux_lane_weights(
            State(state.clone()),
            HeaderMap::new(),
            Query(CoreCruxLaneWeightsQuery { tenant_id: None }),
        )
        .await
        .into_response();
        assert_eq!(status_of(resp).await, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn review_contradictions_and_consolidation() {
        let state = st();
        let resp = get_console_review_contradictions(
            State(state.clone()),
            HeaderMap::new(),
            Query(ConsoleReviewQuery { limit: Some(10) }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        // Blank id gets an auto id + actor filled in; an empty `target_fact_ids`
        // is a `NoTargets` error which the handler maps to 400 (not a silent 200).
        let body: corecrux_memory::fact_store::ConsolidationRequestV1 = serde_json::from_value(serde_json::json!({
            "consolidation_id": "",
            "entity": "person:alice",
            "key": "city",
            "canonical_value": "NYC",
            "target_fact_ids": [],
        }))
        .unwrap();
        let resp = post_console_review_consolidation(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "empty target set is rejected, not laundered into 200"
        );
    }

    // ── CoreCrux link-graph mediation proxy (ExecPlan wikicrux-link-graph M4) ──

    fn qmap(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn reject_unknown_graph_params_allows_known_rejects_extras() {
        assert!(reject_unknown_graph_params(&qmap(&[("titles", "Dog|Cat")]), GRAPH_RESOLVE_PARAMS).is_ok());
        // A cache-buster / arbitrary param is rejected (T.5: fixed audited surface).
        assert!(reject_unknown_graph_params(&qmap(&[("titles", "Dog"), ("_", "9")]), GRAPH_RESOLVE_PARAMS).is_err());
        assert!(reject_unknown_graph_params(&qmap(&[("tenant_id", "x")]), GRAPH_EGO_PARAMS).is_err());
    }

    #[test]
    fn build_graph_ego_body_valid_and_caps() {
        let body = build_graph_ego_body(&qmap(&[
            ("seeds", "1,2,3"),
            ("hops", "9"),
            ("budget_nodes", "5000"),
            ("budget_edges", "20000"),
        ]))
        .expect("valid ego body");
        assert_eq!(body["seeds"], serde_json::json!([1, 2, 3]));
        assert_eq!(
            body["hops"],
            serde_json::json!(3),
            "hops clamps to the upstream max of 3"
        );
        assert_eq!(body["budget"]["nodes"], serde_json::json!(5000));
        assert_eq!(body["kind"], serde_json::json!("link"), "kind defaults to link");
        assert_eq!(body["direction"], serde_json::json!("both"));
    }

    #[test]
    fn build_graph_ego_body_error_paths() {
        assert!(
            build_graph_ego_body(&qmap(&[("budget_nodes", "1"), ("budget_edges", "1")])).is_err(),
            "seeds required"
        );
        assert!(
            build_graph_ego_body(&qmap(&[("seeds", "1")])).is_err(),
            "budgets required"
        );
        assert!(
            build_graph_ego_body(&qmap(&[("seeds", "1"), ("budget_nodes", "0"), ("budget_edges", "1")])).is_err(),
            "budget must be > 0"
        );
        assert!(
            build_graph_ego_body(&qmap(&[
                ("seeds", "1"),
                ("budget_nodes", "999999"),
                ("budget_edges", "1")
            ]))
            .is_err(),
            "budget over the upstream max is rejected"
        );
        assert!(
            build_graph_ego_body(&qmap(&[
                ("seeds", "1"),
                ("budget_nodes", "1"),
                ("budget_edges", "1"),
                ("kind", "nope")
            ]))
            .is_err(),
            "bad kind rejected"
        );
        assert!(
            build_graph_ego_body(&qmap(&[
                ("seeds", "1"),
                ("budget_nodes", "1"),
                ("budget_edges", "1"),
                ("direction", "sideways")
            ]))
            .is_err(),
            "bad direction rejected"
        );
        assert!(build_graph_ego_body(&qmap(&[
            ("seeds", "notanint"),
            ("budget_nodes", "1"),
            ("budget_edges", "1")
        ]))
        .is_err());
    }

    #[test]
    fn build_graph_path_body_valid_and_caps() {
        let body = build_graph_path_body(&qmap(&[
            ("src", "1"),
            ("dst", "2"),
            ("k", "999"),
            ("context_edge_budget", "999999"),
        ]))
        .expect("valid path body");
        assert_eq!(body["src"], serde_json::json!(1));
        assert_eq!(body["dst"], serde_json::json!(2));
        assert_eq!(body["max_hops"], serde_json::json!(6), "max_hops defaults to 6");
        assert_eq!(body["k"], serde_json::json!(64), "k clamps to 64");
        assert_eq!(
            body["context_edge_budget"],
            serde_json::json!(20000),
            "context edge budget clamps to 20000"
        );
    }

    #[test]
    fn build_graph_path_body_error_paths() {
        assert!(build_graph_path_body(&qmap(&[("dst", "2")])).is_err(), "src required");
        assert!(build_graph_path_body(&qmap(&[("src", "1")])).is_err(), "dst required");
        assert!(
            build_graph_path_body(&qmap(&[("src", "1"), ("dst", "2"), ("max_hops", "0")])).is_err(),
            "max_hops must be >= 1"
        );
        assert!(
            build_graph_path_body(&qmap(&[("src", "1"), ("dst", "2"), ("max_hops", "9")])).is_err(),
            "max_hops must be <= 8"
        );
    }

    #[test]
    fn map_graph_upstream_status_hides_auth_and_surfaces_availability() {
        // Upstream flag-off (404) and graph-absent (503) both surface as 503 so the
        // pane shows the enable/build hint.
        assert_eq!(map_graph_upstream_status(404), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(map_graph_upstream_status(503), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(map_graph_upstream_status(400), StatusCode::BAD_REQUEST);
        // Upstream auth failure (daemon-token misconfig) never leaks — collapses to 502.
        assert_eq!(map_graph_upstream_status(401), StatusCode::BAD_GATEWAY);
        assert_eq!(map_graph_upstream_status(403), StatusCode::BAD_GATEWAY);
        assert_eq!(map_graph_upstream_status(500), StatusCode::BAD_GATEWAY);
    }

    #[test]
    #[serial_test::serial]
    fn corecrux_graph_base_url_env_unset_and_set() {
        for k in ["CORECRUXD_CORECRUX_GRAPH_BASE_URL", "CORECRUX_GRAPH_BASE_URL"] {
            std::env::remove_var(k);
        }
        assert!(corecrux_graph_base_url_from_env().is_err());
        assert!(!corecrux_graph_base_url_configured());
        std::env::set_var("CORECRUX_GRAPH_BASE_URL", "http://data-1:14800/");
        assert_eq!(corecrux_graph_base_url_from_env().unwrap(), "http://data-1:14800");
        assert!(corecrux_graph_base_url_configured());
        std::env::remove_var("CORECRUX_GRAPH_BASE_URL");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn graph_handlers_503_without_upstream_and_400_on_bad_params() {
        for k in ["CORECRUXD_CORECRUX_GRAPH_BASE_URL", "CORECRUX_GRAPH_BASE_URL"] {
            std::env::remove_var(k);
        }
        let state = st();
        // stats → 503 (graph upstream unconfigured; console hides / dims the pane).
        let resp = get_console_corecrux_graph_stats(State(state.clone()), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(status_of(resp).await, StatusCode::SERVICE_UNAVAILABLE);

        // resolve with no titles → 400 (validated before the env lookup).
        let resp =
            get_console_corecrux_graph_resolve(State(state.clone()), HeaderMap::new(), Query(qmap(&[("titles", "")])))
                .await
                .into_response();
        assert_eq!(status_of(resp).await, StatusCode::BAD_REQUEST);

        // ego with an unknown param → 400.
        let resp = get_console_corecrux_graph_ego(
            State(state.clone()),
            HeaderMap::new(),
            Query(qmap(&[("seeds", "1"), ("nope", "1")])),
        )
        .await
        .into_response();
        assert_eq!(status_of(resp).await, StatusCode::BAD_REQUEST);

        // path with max_hops out of range → 400.
        let resp = get_console_corecrux_graph_path(
            State(state.clone()),
            HeaderMap::new(),
            Query(qmap(&[("src", "1"), ("dst", "2"), ("max_hops", "9")])),
        )
        .await
        .into_response();
        assert_eq!(status_of(resp).await, StatusCode::BAD_REQUEST);

        // resolve with a real title but upstream unset → 503.
        let resp =
            get_console_corecrux_graph_resolve(State(state), HeaderMap::new(), Query(qmap(&[("titles", "Dog")])))
                .await
                .into_response();
        assert_eq!(status_of(resp).await, StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod session_detail_tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::response::Response;
    use corecrux_memory::fact_store::StoreFact;
    use serde_json::{json, Value};

    fn st() -> AppState {
        super::super::tests::test_app_state(16)
    }

    async fn body_json(resp: Response) -> Value {
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("read body");
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    /// Store a work-transition fact the way `work::transition_store_fact` does,
    /// so `gates_for_passport`'s prefix scan finds it.
    fn store_transition(store: &mut corecrux_memory::fact_store::FactStore, tx: &crate::work::WorkTransition) {
        let sf = StoreFact {
            tenant_hash: "default".to_string(),
            entity: format!(
                "{}::{}::{}-{}",
                crate::work::WORK_TRANSITION_ENTITY_PREFIX,
                tx.work_id,
                tx.at_unix_ms,
                tx.id
            ),
            key: crate::work::RECORD_KEY.to_string(),
            value: serde_json::to_string(tx).unwrap(),
            source_receipt: tx.receipt_id.clone(),
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: Some(tx.by_passport.clone()),
        };
        store.store(sf);
    }

    fn mk_transition(
        work_id: &str,
        passport: &str,
        gate: &str,
        at: u64,
        receipt: Option<&str>,
    ) -> crate::work::WorkTransition {
        crate::work::WorkTransition {
            id: format!("t_{at}"),
            work_id: work_id.to_string(),
            from_state: "in_progress".to_string(),
            to_state: "done".to_string(),
            by_passport: passport.to_string(),
            gate_status: gate.to_string(),
            at_unix_ms: at,
            blocker_kind: None,
            receipt_id: receipt.map(str::to_string),
        }
    }

    #[test]
    fn state_first_line_prefers_conventional_fields_then_leaf() {
        assert_eq!(
            session_state_first_line(&json!({ "decisions_made": ["chose canary"], "x": 1 })).as_deref(),
            Some("chose canary")
        );
        assert_eq!(
            session_state_first_line(&json!({ "note": "  wired M3  " })).as_deref(),
            Some("wired M3")
        );
        assert_eq!(
            session_state_first_line(&json!({ "context_summary": "building Crux" })).as_deref(),
            Some("building Crux")
        );
        // NO arbitrary-leaf fallback: a non-conventional blob yields no preview,
        // so the list can't leak an agent's stashed content (redaction invariant).
        assert_eq!(
            session_state_first_line(&json!({ "misc": { "deep": ["", "hello"] } })),
            None
        );
        assert_eq!(
            session_state_first_line(&json!({ "token": "secret-session-token" })),
            None
        );
        // Empty / string-less blobs → None (honest).
        assert_eq!(session_state_first_line(&json!({ "n": 42 })), None);
        assert_eq!(session_state_first_line(&json!({})), None);
        // Long lines are clipped to <=140 chars with an ellipsis.
        let long = "x".repeat(300);
        let clipped = session_state_first_line(&json!({ "note": long })).unwrap();
        assert!(clipped.chars().count() <= 140, "got {}", clipped.chars().count());
        assert!(clipped.ends_with('…'));
    }

    #[tokio::test]
    async fn list_rows_carry_new_fields() {
        let state = st();
        {
            let mut store = state.session_store.write().await;
            store.put(
                "__agent_session::anthropic::plan-slug",
                json!({ "decisions": ["shipped M3"] }),
                Some(3600),
            );
        }
        let resp = get_console_sessions(
            State(state.clone()),
            HeaderMap::new(),
            Query(ConsoleSessionsQuery {
                include_archived: false,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["state_preview"], "first_line");
        let row = &body["session_rows"][0];
        assert_eq!(row["session_id"], "plan-slug");
        assert_eq!(row["agent"], "anthropic");
        assert!(row["total_tokens"].as_u64().unwrap() > 0);
        assert!(row["expires_at"].is_string());
        assert_eq!(row["state_first_line"], "shipped M3");
        // No binding / coord intent for this session → honest null.
        assert!(row["passport_id"].is_null());
        assert!(row["execplan_slug"].is_null());
    }

    #[tokio::test]
    async fn list_carries_actor_title_summary_and_allocation() {
        // M21 — the three new row fields plus the server-computed allocation
        // block. The point of the block is that "why is so much unlinked?" has a
        // measured answer: two of these three sessions carry no identity at all,
        // and none of them can carry a plan link because agent session ids are a
        // different key space from the sealed-plan hex the joins use.
        let state = st();
        {
            let mut store = state.session_store.write().await;
            // (a) titled + summarised + stamped, written through the actor path.
            store.put_with_actor(
                "__agent_session::anthropic::named",
                json!({ "title": "M21 console round 10", "summary": "Accordion icons and the LOD anchor fix landed." }),
                None,
                Some("claude-work".to_string()),
            );
            // (b) anonymous, conventional first line only.
            store.put("anon-one", json!({ "note": "resume here" }), None);
            // (c) anonymous, nothing conventional at all.
            store.put("anon-two", json!({ "n": 1 }), None);
        }
        let resp = get_console_sessions(
            State(state.clone()),
            HeaderMap::new(),
            Query(ConsoleSessionsQuery {
                include_archived: false,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;

        let rows = body["session_rows"].as_array().unwrap();
        let named = rows.iter().find(|r| r["session_id"] == "named").unwrap();
        assert_eq!(named["actor"], "claude-work");
        assert_eq!(named["state_title"], "M21 console round 10");
        assert_eq!(named["state_summary"], "Accordion icons and the LOD anchor fix landed.");
        assert_eq!(named["agent"], "anthropic");

        let anon = rows.iter().find(|r| r["session_id"] == "anon-two").unwrap();
        assert!(anon["actor"].is_null(), "anonymous writers stamp nothing");
        assert!(anon["state_title"].is_null());
        assert!(anon["state_summary"].is_null());
        assert!(anon["state_first_line"].is_null());

        let a = &body["allocation"];
        assert_eq!(a["counted"], 3);
        assert_eq!(a["with_actor"], 1);
        assert_eq!(a["with_agent_from_key_prefix"], 1); // only the scoped key carries one
        assert_eq!(a["with_any_identity"], 1);
        assert_eq!(a["no_identity"], 2);
        assert_eq!(a["with_agent_title"], 1);
        assert_eq!(a["no_agent_title"], 2);
        // Disjoint key spaces: no agent session id can match a sealed-plan hex.
        assert_eq!(a["with_passport_binding"], 0);
        assert_eq!(a["with_live_execplan_intent"], 0);
        assert_eq!(a["no_plan_link"], 3);
        assert!(a["why"].as_str().unwrap().contains("disjoint key space"));
    }

    #[tokio::test]
    async fn detail_joins_binding_gates_and_plans() {
        let state = st();
        let hex = "abcdef0123456789abcdef0123456789";
        let raw_key = format!("__agent_session::anthropic::{hex}");
        {
            let mut sstore = state.session_store.write().await;
            sstore.put(&raw_key, json!({ "note": "resume here" }), None);
        }
        {
            let mut fstore = state.fact_store.write().await;
            // Binding keyed by the session's logical id (== hex here) → join works.
            let binding = crate::session_bindings::SessionBinding {
                session_id_hex: hex.to_string(),
                project_id: Some("plancrux".to_string()),
                tenant_id: "work::team".to_string(),
                passport_id: "claude-work".to_string(),
                passport_category: "work".to_string(),
                agent_work_gate: true,
                bound_at_unix_ms: 1000,
            };
            crate::session_bindings::write_binding(&mut fstore, &binding).unwrap();
            // A decided gate by this passport (newest first) + an undecided one (filtered out).
            store_transition(
                &mut fstore,
                &mk_transition("w_1", "claude-work", "approved", 2000, Some("ad_ga_1")),
            );
            store_transition(&mut fstore, &mk_transition("w_2", "claude-work", "queued", 3000, None));
            store_transition(
                &mut fstore,
                &mk_transition("w_3", "someone-else", "approved", 4000, None),
            );
            // execplan authorship by this passport (heuristic plan linkage).
            let mut ef = StoreFact {
                tenant_hash: "default".to_string(),
                entity: "execplan:my-plan".to_string(),
                key: "gate:M3".to_string(),
                value: "{\"status\":\"pass\"}".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: Some("claude-work".to_string()),
            };
            crate::fact_privacy::enforce_global(&mut ef);
            fstore.store(ef);
        }
        let resp = get_console_session_detail(
            State(state.clone()),
            Query(ConsoleSessionDetailQuery { key: raw_key.clone() }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        // Full state blob is exposed (deliberate admin-read decision).
        assert_eq!(body["state"], json!({ "note": "resume here" }));
        assert_eq!(body["binding"]["passport_id"], "claude-work");
        assert_eq!(body["binding"]["project_id"], "plancrux");
        // Only the decided gate by this passport survives.
        let gates = body["gates"].as_array().unwrap();
        assert_eq!(gates.len(), 1);
        assert_eq!(gates[0]["work_id"], "w_1");
        assert_eq!(gates[0]["gate_status"], "approved");
        assert_eq!(gates[0]["receipt_id"], "ad_ga_1");
        // Heuristic plan linkage grouped by entity.
        let plans = body["linked_plans_heuristic"].as_array().unwrap();
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0]["entity"], "execplan:my-plan");
        assert_eq!(plans[0]["matches"], 1);
    }

    #[tokio::test]
    async fn detail_missing_session_is_404() {
        let state = st();
        let resp = get_console_session_detail(
            State(state.clone()),
            Query(ConsoleSessionDetailQuery {
                key: "nope".to_string(),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn detail_without_binding_is_honest_empty() {
        let state = st();
        {
            let mut sstore = state.session_store.write().await;
            sstore.put("__agent_session::openai::unbound", json!({ "k": "v" }), None);
        }
        let resp = get_console_session_detail(
            State(state.clone()),
            Query(ConsoleSessionDetailQuery {
                key: "__agent_session::openai::unbound".to_string(),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert!(body["binding"].is_null());
        assert!(body["coord_intent"].is_null());
        assert_eq!(body["gates"].as_array().unwrap().len(), 0);
        assert_eq!(body["linked_plans_heuristic"].as_array().unwrap().len(), 0);
        // State is still exposed even with no linkage.
        assert_eq!(body["state"], json!({ "k": "v" }));
    }
}
