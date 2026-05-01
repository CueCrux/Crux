// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Read-only aggregation endpoints for the embedded Crux Console.

use std::collections::BTreeSet;

use super::{
    problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Path, Query, State, StatusCode,
};

#[derive(Debug, serde::Deserialize)]
pub(super) struct ConsoleChunksQuery {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
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
    let integration_count = crux_integrations::builtin_packs().map_or(0, |packs| packs.len());

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

    let packs = match crux_integrations::builtin_packs() {
        Ok(packs) => packs,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "enabled": true,
            "safe_mode": state.integrations_safe_mode,
            "allow_executable_helpers": state.integrations_allow_executable_helpers,
            "allowed_capabilities": crux_integrations::allowed_capabilities(),
            "packs": packs
        })),
    )
        .into_response()
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

pub(super) async fn get_console_facts(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }

    let store = state.fact_store.read().await;
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        query: None,
        entity: None,
        entity_prefix: None,
        top_k: 50,
        token_budget: None,
    });
    let visible_facts: Vec<_> = result.facts.into_iter().filter(|fact| !fact.private).collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "count": store.count(),
            "visible_count": visible_facts.len(),
            "private_facts_hidden": true,
            "facts": visible_facts,
            "total_tokens": result.total_tokens
        })),
    )
        .into_response()
}

pub(super) async fn get_console_tenants(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }

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

    let tenants: Vec<_> = tenants
        .into_iter()
        .map(|tenant_id| {
            serde_json::json!({
                "tenant_id": tenant_id,
                "source": "local_metadata",
                "chunk_visibility": "metadata_only",
                "content_preview": false
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tenants": tenants,
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
    if let Err(problem) = require_console_read(&state, &headers) {
        return problem.into_response();
    }

    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tenant_id": tenant_id,
            "chunks": [],
            "page": {
                "limit": limit,
                "cursor": query.cursor,
                "next_cursor": null
            },
            "visibility": "metadata_only",
            "dataplane_enabled": state.http_dataplane.enabled(),
            "detail": "chunk metadata explorer is wired; dataplane-backed chunk enumeration is not available in this build"
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

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "chunk_digest": chunk_digest,
            "present": false,
            "visibility": "metadata_only",
            "dataplane_enabled": state.http_dataplane.enabled(),
            "detail": "chunk lookup requires dataplane-backed metadata"
        })),
    )
        .into_response()
}

pub(super) async fn get_console_chunk_preview(
    State(state): State<AppState>,
    Path(chunk_digest): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["tenant:content:preview"]) {
        return problem.into_response();
    }

    (
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "chunk_digest": chunk_digest,
            "preview": null,
            "redacted": true,
            "detail": "raw chunk preview is disabled until tenant-scoped dataplane preview is implemented"
        })),
    )
        .into_response()
}

#[allow(clippy::result_large_err)]
fn require_console_read(state: &AppState, headers: &HeaderMap) -> Result<(), crate::problem::ProblemResponse> {
    require_http_scopes(&state.auth, headers, &["admin:read"])
}
