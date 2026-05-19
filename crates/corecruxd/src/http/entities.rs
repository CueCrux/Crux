// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP surface for the Crux substrate: `/v1/entities/*`, `/v1/edges/*`,
//! `/v1/kinds/*`.
//!
//! The substrate is a generic `(kind, id, payload)` + labelled-edge store
//! intended to host domain data from lens crates (e.g. `crux-lens-features`).
//! Distinct from the legacy `/v1/relations` graph-projection surface which
//! serves CoreCrux's narrow tenant-scoped artifact graph.

use super::{
    problem_response, require_http_any_scope, AppState, HeaderMap, IntoResponse, Json, Path, Query, State, StatusCode,
};
use corecrux_memory::{EdgeQuery, EntityQuery};
use serde::Deserialize;
use serde_json::{json, Value};

fn actor_from_headers(state: &AppState, headers: &HeaderMap) -> String {
    crate::auth::http_scope_context(&state.auth, headers)
        .ok()
        .and_then(|ctx| ctx.passport_id)
        .unwrap_or_else(|| "anonymous".into())
}

// ── Entities ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(super) struct ListEntitiesQuery {
    pub kind: Option<String>,
    pub limit: Option<usize>,
    #[serde(default)]
    pub include_deleted: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct UpsertEntityBody {
    pub payload: Value,
}

pub(super) async fn get_entity(
    State(state): State<AppState>,
    Path((kind, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
    let store = state.entity_store.read().await;
    match store.get(&kind, &id) {
        Some(rec) => (StatusCode::OK, Json(json!({"entity": rec}))).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, format!("entity {kind}/{id} not found")),
    }
}

pub(super) async fn list_entities(
    State(state): State<AppState>,
    Query(q): Query<ListEntitiesQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
    let query = EntityQuery {
        kind: q.kind,
        limit: q.limit,
        include_deleted: q.include_deleted,
    };
    let store = state.entity_store.read().await;
    let entities: Vec<_> = store.list(&query).into_iter().cloned().collect();
    let count = entities.len();
    (StatusCode::OK, Json(json!({"entities": entities, "count": count}))).into_response()
}

pub(super) async fn put_entity(
    State(state): State<AppState>,
    Path((kind, id)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<UpsertEntityBody>,
) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:write", "admin:write"]) {
        return p.into_response();
    }
    let actor = actor_from_headers(&state, &headers);
    let registry = state.kind_registry.read().await;
    let registry_opt = if registry.is_registered(&kind) {
        Some(&*registry)
    } else {
        None
    };
    let mut store = state.entity_store.write().await;
    match store.upsert(&kind, &id, body.payload, &actor, registry_opt) {
        Ok(rec) => (StatusCode::OK, Json(json!({"entity": rec}))).into_response(),
        Err(e) => problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

pub(super) async fn get_entity_history(
    State(state): State<AppState>,
    Path((kind, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
    let store = state.entity_store.read().await;
    let versions: Vec<_> = store.history(&kind, &id).into_iter().cloned().collect();
    let count = versions.len();
    (StatusCode::OK, Json(json!({"versions": versions, "count": count}))).into_response()
}

pub(super) async fn delete_entity(
    State(state): State<AppState>,
    Path((kind, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:write", "admin:write"]) {
        return p.into_response();
    }
    let actor = actor_from_headers(&state, &headers);
    let mut store = state.entity_store.write().await;
    match store.delete(&kind, &id, &actor) {
        Ok(rec) => (StatusCode::OK, Json(json!({"entity": rec}))).into_response(),
        Err(e) => problem_response(StatusCode::NOT_FOUND, e.to_string()),
    }
}

// ── Edges ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(super) struct ListEdgesQuery {
    pub from_kind: Option<String>,
    pub from_id: Option<String>,
    pub to_kind: Option<String>,
    pub to_id: Option<String>,
    pub edge_kind: Option<String>,
    pub limit: Option<usize>,
    #[serde(default)]
    pub include_deleted: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct UpsertEdgeBody {
    pub from_kind: String,
    pub from_id: String,
    pub edge_kind: String,
    pub to_kind: String,
    pub to_id: String,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Deserialize)]
pub(super) struct DeleteEdgeBody {
    pub from_kind: String,
    pub from_id: String,
    pub edge_kind: String,
    pub to_kind: String,
    pub to_id: String,
}

pub(super) async fn list_edges(
    State(state): State<AppState>,
    Query(q): Query<ListEdgesQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
    let query = EdgeQuery {
        from_kind: q.from_kind,
        from_id: q.from_id,
        to_kind: q.to_kind,
        to_id: q.to_id,
        edge_kind: q.edge_kind,
        limit: q.limit,
        include_deleted: q.include_deleted,
    };
    let store = state.edge_store.read().await;
    let edges: Vec<_> = store.list(&query).into_iter().cloned().collect();
    let count = edges.len();
    (StatusCode::OK, Json(json!({"edges": edges, "count": count}))).into_response()
}

pub(super) async fn put_edge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UpsertEdgeBody>,
) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:write", "admin:write"]) {
        return p.into_response();
    }
    let actor = actor_from_headers(&state, &headers);
    let mut store = state.edge_store.write().await;
    match store.upsert(
        &body.from_kind,
        &body.from_id,
        &body.edge_kind,
        &body.to_kind,
        &body.to_id,
        body.payload,
        &actor,
    ) {
        Ok(rec) => (StatusCode::OK, Json(json!({"edge": rec}))).into_response(),
        Err(e) => problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

pub(super) async fn delete_edge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<DeleteEdgeBody>,
) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:write", "admin:write"]) {
        return p.into_response();
    }
    let actor = actor_from_headers(&state, &headers);
    let mut store = state.edge_store.write().await;
    match store.delete(
        &body.from_kind,
        &body.from_id,
        &body.edge_kind,
        &body.to_kind,
        &body.to_id,
        &actor,
    ) {
        Ok(rec) => (StatusCode::OK, Json(json!({"edge": rec}))).into_response(),
        Err(e) => problem_response(StatusCode::NOT_FOUND, e.to_string()),
    }
}

// ── Kinds ────────────────────────────────────────────────────────────

pub(super) async fn list_kinds(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
    let reg = state.kind_registry.read().await;
    let kinds: Vec<_> = reg.list().into_iter().cloned().collect();
    let count = kinds.len();
    (StatusCode::OK, Json(json!({"kinds": kinds, "count": count}))).into_response()
}

pub(super) async fn get_kind(
    State(state): State<AppState>,
    Path(kind): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
    let reg = state.kind_registry.read().await;
    match reg.get(&kind) {
        Some(r) => (StatusCode::OK, Json(json!({"registration": r}))).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, format!("kind {kind} not registered")),
    }
}
