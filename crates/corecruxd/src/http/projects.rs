// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! HTTP CRUD for projects + members + tenants.

#![allow(clippy::option_option)] // PATCH tri-state semantics

use super::{
    problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Path, Query, State, StatusCode,
};

#[derive(Debug, serde::Deserialize)]
pub(super) struct CreateProjectBody {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub planning_target: Option<String>,
    pub default_passport_id: String,
    #[serde(default)]
    pub working_tenants: Vec<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct AddMemberBody {
    pub passport_id: String,
    #[serde(default = "default_role")]
    pub role: String,
}

fn default_role() -> String {
    "contributor".to_string()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct AddTenantBody {
    pub tenant_id: String,
    #[serde(default)]
    pub default_passport_id: Option<String>,
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_projects(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let projects = crate::projects::list_projects(&store);
    drop(store);
    (StatusCode::OK, Json(serde_json::json!({ "projects": projects }))).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let detail = crate::projects::get_project_detail(&store, &id);
    drop(store);
    match detail {
        Some(d) => (StatusCode::OK, Json(d)).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, format!("project '{id}' not found")),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateProjectBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::projects::create_project(
        &mut store,
        crate::projects::CreateProjectInput {
            id: body.id,
            name: body.name,
            planning_target: body.planning_target,
            default_passport_id: body.default_passport_id,
            working_tenants: body.working_tenants,
        },
        now_unix_ms(),
    );
    drop(store);
    match result {
        Ok(p) => (StatusCode::CREATED, Json(p)).into_response(),
        Err(crate::projects::ProjectsError::DuplicateId(_)) => {
            problem_response(StatusCode::CONFLICT, "project id already exists")
        }
        Err(err @ crate::projects::ProjectsError::PassportNotFound(_)) => {
            problem_response(StatusCode::NOT_FOUND, err.to_string())
        }
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct UpdateProjectBody {
    #[serde(default)]
    pub name: Option<String>,
    /// Outer Some = present in body. Inner None = clear; inner Some = set.
    #[serde(default, deserialize_with = "deserialize_some_option")]
    pub planning_target: Option<Option<String>>,
    #[serde(default)]
    pub default_passport_id: Option<String>,
    #[serde(default)]
    pub archived: Option<bool>,
    #[serde(default)]
    pub is_default: Option<bool>,
}

fn deserialize_some_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    use serde::Deserialize;
    Option::<T>::deserialize(deserializer).map(Some)
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn patch_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpdateProjectBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::projects::update_project(
        &mut store,
        &id,
        crate::projects::UpdateProjectInput {
            name: body.name,
            planning_target: body.planning_target,
            default_passport_id: body.default_passport_id,
            archived: body.archived,
            is_default: body.is_default,
        },
        now_unix_ms(),
    );
    drop(store);
    match result {
        Ok(p) => (StatusCode::OK, Json(p)).into_response(),
        Err(crate::projects::ProjectsError::NotFound(_)) => {
            problem_response(StatusCode::NOT_FOUND, "project not found")
        }
        Err(err @ crate::projects::ProjectsError::PassportNotFound(_)) => {
            problem_response(StatusCode::NOT_FOUND, err.to_string())
        }
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn delete_project(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::projects::delete_project(&mut store, &id);
    drop(store);
    match result {
        Ok(()) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(crate::projects::ProjectsError::NotFound(_)) => {
            problem_response(StatusCode::NOT_FOUND, "project not found")
        }
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_project_member(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<AddMemberBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::projects::add_member(&mut store, &id, &body.passport_id, &body.role, now_unix_ms());
    drop(store);
    match result {
        Ok(m) => (StatusCode::CREATED, Json(m)).into_response(),
        Err(crate::projects::ProjectsError::NotFound(_)) => {
            problem_response(StatusCode::NOT_FOUND, "project not found")
        }
        Err(err @ crate::projects::ProjectsError::PassportNotFound(_)) => {
            problem_response(StatusCode::NOT_FOUND, err.to_string())
        }
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn delete_project_member(
    State(state): State<AppState>,
    Path((id, passport_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::projects::remove_member(&mut store, &id, &passport_id);
    drop(store);
    match result {
        Ok(()) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_project_tenant(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<AddTenantBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::projects::add_tenant(
        &mut store,
        &id,
        &body.tenant_id,
        body.default_passport_id,
        now_unix_ms(),
    );
    drop(store);
    match result {
        Ok(t) => (StatusCode::CREATED, Json(t)).into_response(),
        Err(crate::projects::ProjectsError::NotFound(_)) => {
            problem_response(StatusCode::NOT_FOUND, "project not found")
        }
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn delete_project_tenant(
    State(state): State<AppState>,
    Path((id, tenant_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::projects::remove_tenant(&mut store, &id, &tenant_id);
    drop(store);
    match result {
        Ok(()) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

// ── Project ↔ GitHub-repo links ────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub(super) struct LinkRepoBody {
    pub repo: String, // "owner/repo"
    #[serde(default)]
    pub plane_id: Option<String>,
    #[serde(default = "default_link_role")]
    pub role: String,
}

fn default_link_role() -> String {
    "work".to_string()
}

fn extract_link_passport(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-corecrux-passport-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn link_now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_project_repos(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let links = crate::project_repo_links::list_links(&store, &project_id);
    drop(store);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "project_id": project_id,
            "count": links.len(),
            "links": links,
        })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_project_repo(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<LinkRepoBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["facts:write"]) {
        return problem.into_response();
    }
    let by = extract_link_passport(&headers);
    let mut store = state.fact_store.write().await;
    let result = crate::project_repo_links::link_repo(
        &mut store,
        &project_id,
        &body.repo,
        body.plane_id,
        &body.role,
        by,
        link_now_unix_ms(),
    );
    drop(store);
    match result {
        Ok(link) => (StatusCode::CREATED, Json(link)).into_response(),
        Err(crate::project_repo_links::RepoLinkError::InvalidRepo(_)) => {
            problem_response(StatusCode::BAD_REQUEST, "repo must look like 'owner/repo'")
        }
        Err(crate::project_repo_links::RepoLinkError::InvalidRole(_)) => problem_response(
            StatusCode::BAD_REQUEST,
            "role must be one of: planning, work, reference",
        ),
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn delete_project_repo(
    State(state): State<AppState>,
    Path((project_id, owner, repo)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["facts:write"]) {
        return problem.into_response();
    }
    let slug = format!("{owner}/{repo}");
    let mut store = state.fact_store.write().await;
    let result = crate::project_repo_links::unlink_repo(&mut store, &project_id, &slug);
    drop(store);
    match result {
        Ok(()) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_plane_repos(
    State(state): State<AppState>,
    Path((project_id, plane_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let links = crate::project_repo_links::list_links_for_plane(&store, &project_id, &plane_id);
    drop(store);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "project_id": project_id,
            "plane_id": plane_id,
            "count": links.len(),
            "links": links,
        })),
    )
        .into_response()
}

// ── Project layers (Vision, Goals, Manifesto, etc.) ───────────────────────
// Layers are free-text content cards attached to a project. The Console
// surfaces them on the project detail page; agents populate them by syncing
// from upstream docs (e.g. an operator's manifesto repo → vision layer).
//
// Storage: facts under `__project_layer__::{project_id}::{layer_name}` with
// key=`content`. The Console used to reach into facts directly to set these;
// these routes give the operation a proper contract so external integrations
// don't need to know the prefix convention.

const PROJECT_LAYER_PREFIX: &str = "__project_layer__";

fn layer_entity(project_id: &str, layer: &str) -> String {
    format!("{PROJECT_LAYER_PREFIX}::{project_id}::{layer}")
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct PutLayerBody {
    pub content: String,
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_project_layers(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let prefix = format!("{PROJECT_LAYER_PREFIX}::{id}::");
    // Pull a generous slice — facts are stored append-only so the same layer
    // can have many versions; we'll dedupe to the latest below.
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix.clone()),
        top_k: 200,
        token_budget: None,
    });
    // Track max version per layer so we always return the latest payload,
    // independent of the store's iteration order.
    let mut latest: std::collections::HashMap<String, corecrux_memory::fact_store::Fact> =
        std::collections::HashMap::new();
    for fact in result.facts {
        if !fact.entity.starts_with(&prefix) || fact.key != "content" {
            continue;
        }
        let layer_name = fact.entity[prefix.len()..].to_string();
        match latest.get(&layer_name) {
            Some(existing) if existing.version >= fact.version => {} // keep
            _ => {
                latest.insert(layer_name, fact);
            }
        }
    }
    let mut layers = serde_json::Map::new();
    for (layer_name, fact) in latest {
        // Skip cleared layers (delete writes empty content with confidence 0).
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
            "project_id": id,
            "count": layers.len(),
            "layers": layers,
        })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn put_project_layer(
    State(state): State<AppState>,
    Path((id, layer)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<PutLayerBody>,
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
        entity: layer_entity(&id, layer),
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
            "project_id": id,
            "layer": layer,
            "fact_id": stored.fact_id,
            "version": stored.version,
            "bytes": stored.value.len(),
            "private": stored.private,
        })),
    )
        .into_response()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct GraphQuery {
    /// Phase 2: when `true`, fold the latest workspace scan (modules, deps,
    /// stubs, dead-code) into the graph.
    #[serde(default)]
    pub include_workspace: bool,
    /// When `true`, also include per-symbol nodes. Heavy.
    #[serde(default)]
    pub include_symbols: bool,
}

/// `GET /v1/projects/{id}/context-graph` — canonical {nodes, edges} graph for
/// this project. Phase 1A is extracted-only (project / planes / tenants /
/// passports / layers / github). Phase 2 adds modules / files / symbols /
/// stubs / dead_code via `?include_workspace=true`.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_context_graph(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(q): Query<GraphQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    if q.include_workspace {
        if let Err(problem) = super::workspace::require_workspace_scan_global_authority(&state, &headers) {
            return problem.into_response();
        }
    }
    let store = state.fact_store.read().await;
    let graph = crate::context_graph::build_for_project_with_opts(
        &store,
        &id,
        &crate::context_graph::GraphOptions {
            include_workspace: q.include_workspace,
            include_symbols: q.include_symbols,
        },
    );
    drop(store);
    (StatusCode::OK, Json(graph)).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn delete_project_layer(
    State(state): State<AppState>,
    Path((id, layer)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["facts:write"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    // The fact store is append-only with versioning, so "delete" is "store empty".
    let mut sf = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity: layer_entity(&id, &layer),
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
            "project_id": id,
            "layer": layer,
            "cleared": true,
            "version": stored.version,
        })),
    )
        .into_response()
}
