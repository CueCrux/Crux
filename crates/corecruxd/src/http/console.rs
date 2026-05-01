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
    if let Ok(indexed_tenants) = crate::console_index::list_tenants(&state.data_dir) {
        tenants.extend(indexed_tenants);
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
