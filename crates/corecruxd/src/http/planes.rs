// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP CRUD for project planes (sub-units inside a project) + their members,
//! tenants, and layers.
//!
//! All routes scope under `/v1/projects/{id}/planes/...`. Reads need
//! `admin:read`; mutations need `admin:read` for member/tenant changes (same
//! posture as the parent project routes) and `facts:write` for layer writes.

use super::{problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Path, State, StatusCode};

const PLANE_LAYER_PREFIX: &str = "__plane_layer__";

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn plane_layer_entity(project_id: &str, plane_id: &str, layer: &str) -> String {
    format!("{PLANE_LAYER_PREFIX}::{project_id}::{plane_id}::{layer}")
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct CreatePlaneBody {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub default_passport_id: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct PlaneMemberBody {
    pub passport_id: String,
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "contributor".to_string()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct PlaneTenantBody {
    pub tenant_id: String,
    #[serde(default)]
    pub default_passport_id: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct PutPlaneLayerBody {
    pub content: String,
}

pub(super) async fn get_planes(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let planes = crate::planes::list_planes(&store, &project_id);
    drop(store);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "project_id": project_id,
            "count": planes.len(),
            "planes": planes,
        })),
    )
        .into_response()
}

pub(super) async fn get_plane(
    State(state): State<AppState>,
    Path((project_id, plane_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let detail = crate::planes::get_plane_detail(&store, &project_id, &plane_id);
    drop(store);
    match detail {
        Some(d) => (StatusCode::OK, Json(d)).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, "plane not found"),
    }
}

pub(super) async fn post_plane(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CreatePlaneBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::planes::create_plane(
        &mut store,
        crate::planes::CreatePlaneInput {
            project_id: project_id.clone(),
            id: body.id,
            name: body.name,
            description: body.description,
            default_passport_id: body.default_passport_id,
        },
        now_unix_ms(),
    );
    drop(store);
    match result {
        Ok(p) => (StatusCode::CREATED, Json(p)).into_response(),
        Err(crate::planes::PlanesError::DuplicateId(_, _)) => {
            problem_response(StatusCode::CONFLICT, "plane id already exists in this project")
        }
        Err(crate::planes::PlanesError::InvalidId(_)) => problem_response(StatusCode::BAD_REQUEST, "invalid plane id"),
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

pub(super) async fn delete_plane(
    State(state): State<AppState>,
    Path((project_id, plane_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::planes::delete_plane(&mut store, &project_id, &plane_id);
    drop(store);
    match result {
        Ok(()) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(crate::planes::PlanesError::NotFound(_, _)) => problem_response(StatusCode::NOT_FOUND, "plane not found"),
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

pub(super) async fn post_plane_member(
    State(state): State<AppState>,
    Path((project_id, plane_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<PlaneMemberBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::planes::add_member(
        &mut store,
        &project_id,
        &plane_id,
        &body.passport_id,
        &body.role,
        now_unix_ms(),
    );
    drop(store);
    match result {
        Ok(m) => (StatusCode::CREATED, Json(m)).into_response(),
        Err(crate::planes::PlanesError::NotFound(_, _)) => problem_response(StatusCode::NOT_FOUND, "plane not found"),
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

pub(super) async fn delete_plane_member(
    State(state): State<AppState>,
    Path((project_id, plane_id, passport_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::planes::remove_member(&mut store, &project_id, &plane_id, &passport_id);
    drop(store);
    match result {
        Ok(()) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

pub(super) async fn post_plane_tenant(
    State(state): State<AppState>,
    Path((project_id, plane_id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<PlaneTenantBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::planes::add_tenant(
        &mut store,
        &project_id,
        &plane_id,
        &body.tenant_id,
        body.default_passport_id,
        now_unix_ms(),
    );
    drop(store);
    match result {
        Ok(t) => (StatusCode::CREATED, Json(t)).into_response(),
        Err(crate::planes::PlanesError::NotFound(_, _)) => problem_response(StatusCode::NOT_FOUND, "plane not found"),
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

pub(super) async fn delete_plane_tenant(
    State(state): State<AppState>,
    Path((project_id, plane_id, tenant_id)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::planes::remove_tenant(&mut store, &project_id, &plane_id, &tenant_id);
    drop(store);
    match result {
        Ok(()) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

pub(super) async fn get_plane_layers(
    State(state): State<AppState>,
    Path((project_id, plane_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let prefix = format!("{PLANE_LAYER_PREFIX}::{project_id}::{plane_id}::");
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: Some(prefix.clone()),
        entity: None,
        entity_prefix: None,
        top_k: 200,
        token_budget: None,
    });
    let mut latest: std::collections::HashMap<String, corecrux_memory::fact_store::Fact> =
        std::collections::HashMap::new();
    for fact in result.facts {
        if !fact.entity.starts_with(&prefix) || fact.key != "content" {
            continue;
        }
        let layer_name = fact.entity[prefix.len()..].to_string();
        match latest.get(&layer_name) {
            Some(existing) if existing.version >= fact.version => {}
            _ => {
                latest.insert(layer_name, fact);
            }
        }
    }
    let mut layers = serde_json::Map::new();
    for (layer_name, fact) in latest {
        if fact.value.is_empty() {
            continue;
        }
        layers.insert(
            layer_name,
            serde_json::json!({
                "content": fact.value,
                "version": fact.version,
                "stored_at": fact.stored_at.to_rfc3339(),
                "fact_id": fact.fact_id,
            }),
        );
    }
    drop(store);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "project_id": project_id,
            "plane_id": plane_id,
            "count": layers.len(),
            "layers": layers,
        })),
    )
        .into_response()
}

pub(super) async fn put_plane_layer(
    State(state): State<AppState>,
    Path((project_id, plane_id, layer)): Path<(String, String, String)>,
    headers: HeaderMap,
    Json(body): Json<PutPlaneLayerBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["facts:write"]) {
        return problem.into_response();
    }
    let layer = layer.trim();
    if layer.is_empty() || layer.contains("::") {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "layer name must be non-empty and must not contain '::'",
        );
    }
    let mut store = state.fact_store.write().await;
    let mut sf = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: plane_layer_entity(&project_id, &plane_id, layer),
        key: "content".to_string(),
        value: body.content,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    let stored = store.store(sf);
    drop(store);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "project_id": project_id,
            "plane_id": plane_id,
            "layer": layer,
            "fact_id": stored.fact_id,
            "version": stored.version,
            "bytes": stored.value.len(),
            "private": stored.private,
        })),
    )
        .into_response()
}

/// `POST /v1/projects/{id}/planes/sync-layers` — Phase 2B.
/// Body: `{source_path, layer, max_bytes?, confirm?}`.
/// Walks `<source_path>/<plane_id>/` for each plane, picks the most likely
/// "main doc" markdown file (heuristic), and writes the leading content as
/// the named plane layer (vision or goals). Defaults to dry-run; pass
/// `confirm=true` to actually write.
#[derive(Debug, serde::Deserialize)]
pub(super) struct SyncLayersBody {
    pub source_path: String,
    pub layer: String,
    #[serde(default = "default_sync_max_bytes")]
    pub max_bytes: usize,
    #[serde(default)]
    pub confirm: bool,
}

fn default_sync_max_bytes() -> usize {
    24 * 1024 // 24 KB per layer is plenty for keyword-overlap signal
}

pub(super) async fn post_sync_layers(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SyncLayersBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["facts:write"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::plane_layer_sync::run_sync(
        &mut store,
        &project_id,
        &body.source_path,
        &body.layer,
        body.max_bytes,
        body.confirm,
    );
    drop(store);
    match result {
        Ok(report) => (StatusCode::OK, Json(report)).into_response(),
        Err(crate::plane_layer_sync::SyncError::NotAllowed(_, _)) => problem_response(
            StatusCode::BAD_REQUEST,
            "source_path is outside the allowed roots (CORECRUXD_SOURCE_ROOTS)",
        ),
        Err(crate::plane_layer_sync::SyncError::PathMissing(p)) => problem_response(
            StatusCode::BAD_REQUEST,
            format!("source path '{p}' does not exist inside the daemon"),
        ),
        Err(crate::plane_layer_sync::SyncError::InvalidLayer(l)) => problem_response(
            StatusCode::BAD_REQUEST,
            format!("layer must be 'vision' or 'goals'; got '{l}'"),
        ),
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

pub(super) async fn delete_plane_layer(
    State(state): State<AppState>,
    Path((project_id, plane_id, layer)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["facts:write"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let mut sf = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: plane_layer_entity(&project_id, &plane_id, &layer),
        key: "content".to_string(),
        value: String::new(),
        source_receipt: None,
        confidence: 0.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    let stored = store.store(sf);
    drop(store);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "project_id": project_id,
            "plane_id": plane_id,
            "layer": layer,
            "cleared": true,
            "version": stored.version,
        })),
    )
        .into_response()
}
