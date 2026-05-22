// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Aggregation and guarded mutation endpoints for the embedded Crux Console.

use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    problem_response, require_http_scopes, require_http_scopes_for_tenant, AppState, HeaderMap, IntoResponse, Json,
    Path, Query, State, StatusCode,
};

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

pub(super) async fn post_console_onboarding_complete(
    State(state): State<AppState>,
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

pub(super) async fn put_console_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UpdateSettingsBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
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
pub(super) async fn post_console_embedding_probe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ProbeEmbeddingBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }
    let url = body.url.trim().trim_end_matches('/').to_string();
    if url.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "url must not be empty");
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return problem_response(StatusCode::BAD_REQUEST, "url must start with http:// or https://");
    }

    let result = tokio::task::spawn_blocking(move || probe_embedding_url(&url))
        .await
        .map_err(|e| e.to_string());
    match result {
        Ok(Ok(probe)) => (StatusCode::OK, Json(probe)).into_response(),
        Ok(Err(err)) => problem_response(StatusCode::BAD_GATEWAY, err),
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("probe join failed: {err}")),
    }
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

fn probe_embedding_url(url: &str) -> Result<EmbeddingProbeResult, String> {
    // Inside a Docker container, `localhost`/`127.0.0.1` from the daemon's
    // perspective resolves to the daemon itself, NOT the user's host or a
    // sibling container. We try the URL the operator gave us first; if that
    // fails AND the URL points at localhost, we transparently retry with
    // common Docker-aware fallbacks before giving up.
    let candidates = build_probe_candidates(url);
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(6)))
        .build()
        .into();

    let probe_endpoints: [(&str, &str); 2] = [("ollama", "/api/tags"), ("openai-compat", "/v1/models")];
    let mut last_error = String::new();

    for candidate in &candidates {
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

/// Given a user-supplied embedding URL, build the ordered list of hostnames
/// to actually probe. The operator's URL is always first. When the URL points
/// at localhost, we append `host.docker.internal` (Docker Desktop bridge) and
/// the documented compose-sibling hostname `crux-ollama-1` (matches
/// docker-compose.yml's `ollama` service when launched with the embeddings
/// profile) so the operator's "obvious" URL Just Works from inside the daemon.
#[cfg(test)]
mod probe_candidate_tests {
    use super::build_probe_candidates;

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

pub(super) async fn post_console_onboarding_restart(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
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
                "playground_alias": "/playground",
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

pub(super) async fn get_console_sessions(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }

    let store = state.session_store.read().await;
    let mut session_ids: Vec<String> = store.list().into_iter().map(str::to_string).collect();
    session_ids.sort();
    if session_ids.len() > 50 {
        session_ids.truncate(50);
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "count": store.count(),
            "sessions": session_ids,
            "state_preview": "ids_only",
            "raw_state_exposed": false
        })),
    )
        .into_response()
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
    if let Err(e) = crux_mcp::category_enforce::check_passport_can_write_entity(&store, ctx.passport_id.as_deref(), entity)
    {
        return problem_response(StatusCode::FORBIDDEN, e.to_string());
    }
    let mut sf = corecrux_memory::fact_store::StoreFact {
        entity: entity.to_string(),
        key: key.to_string(),
        value: value.to_string(),
        source_receipt: None,
        confidence: body.confidence,
        // Default false; the privacy gate below promotes to true for any
        // entity matching an always-private prefix (__ax__::, __work__::,
        // __project_layer__::, github::, etc.).
        private: false,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    let stored = store.store(sf);

    (StatusCode::CREATED, Json(stored)).into_response()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ConsoleTenantsQuery {
    pub category: Option<String>,
}

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
