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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use corecrux_memory::KindRegistration;

    fn state() -> AppState {
        super::super::tests::test_app_state(16)
    }

    async fn parts(resp: axum::response::Response) -> (StatusCode, Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        (status, json)
    }

    async fn upsert(state: &AppState, kind: &str, id: &str, payload: Value) -> (StatusCode, Value) {
        parts(
            put_entity(
                State(state.clone()),
                Path((kind.to_string(), id.to_string())),
                HeaderMap::new(),
                Json(UpsertEntityBody { payload }),
            )
            .await
            .into_response(),
        )
        .await
    }

    #[tokio::test]
    async fn entity_lifecycle_put_get_list_history_delete() {
        let st = state();

        // Create.
        let (status, body) = upsert(&st, "capability", "cap-1", json!({"name": "alpha"})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["entity"]["id"], "cap-1");
        assert_eq!(body["entity"]["version"], 1);

        // Update → version bumps, history grows.
        let (_, body) = upsert(&st, "capability", "cap-1", json!({"name": "alpha2"})).await;
        assert_eq!(body["entity"]["version"], 2);

        // Get.
        let (status, body) = parts(
            get_entity(
                State(st.clone()),
                Path(("capability".into(), "cap-1".into())),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["entity"]["payload"]["name"], "alpha2");

        // History has both versions.
        let (status, body) = parts(
            get_entity_history(
                State(st.clone()),
                Path(("capability".into(), "cap-1".into())),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["count"].as_u64().unwrap() >= 2);

        // List by kind.
        let (status, body) = parts(
            list_entities(
                State(st.clone()),
                Query(ListEntitiesQuery {
                    kind: Some("capability".into()),
                    limit: None,
                    include_deleted: false,
                }),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], 1);

        // Delete.
        let (status, _) = parts(
            delete_entity(
                State(st.clone()),
                Path(("capability".into(), "cap-1".into())),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // After delete it is gone from default get.
        let (status, _) = parts(
            get_entity(
                State(st.clone()),
                Path(("capability".into(), "cap-1".into())),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_entity_missing_is_404() {
        let st = state();
        let (status, body) = parts(
            get_entity(State(st), Path(("k".into(), "missing".into())), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body["detail"].as_str().unwrap_or_default().contains("not found"));
    }

    #[tokio::test]
    async fn delete_entity_missing_is_404() {
        let st = state();
        let (status, _) = parts(
            delete_entity(State(st), Path(("k".into(), "missing".into())), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_entities_limit_and_include_deleted() {
        let st = state();
        upsert(&st, "k", "a", json!({})).await;
        upsert(&st, "k", "b", json!({})).await;
        upsert(&st, "k", "c", json!({})).await;
        // Delete one then list with include_deleted both ways.
        delete_entity(State(st.clone()), Path(("k".into(), "c".into())), HeaderMap::new()).await;

        let (_, body) = parts(
            list_entities(
                State(st.clone()),
                Query(ListEntitiesQuery {
                    kind: Some("k".into()),
                    limit: Some(1),
                    include_deleted: false,
                }),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(body["count"], 1, "limit caps the result set");

        let (_, body) = parts(
            list_entities(
                State(st.clone()),
                Query(ListEntitiesQuery {
                    kind: Some("k".into()),
                    limit: None,
                    include_deleted: true,
                }),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert!(
            body["count"].as_u64().unwrap() >= 3,
            "deleted row visible with include_deleted"
        );
    }

    #[tokio::test]
    async fn put_entity_validation_error_is_400() {
        let st = state();
        {
            let mut reg = st.kind_registry.write().await;
            reg.register(KindRegistration {
                kind: "strict".to_string(),
                json_schema: json!({"type": "object", "required": ["name"]}),
                allowed_outgoing_edges: vec![],
                allowed_incoming_edges: vec![],
                description: "strict kind".to_string(),
            })
            .unwrap();
        }
        // Missing required "name" → validation fails → 400.
        let (status, _) = upsert(&st, "strict", "x", json!({"other": 1})).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Valid payload → 200.
        let (status, _) = upsert(&st, "strict", "x", json!({"name": "ok"})).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn edge_lifecycle_put_list_delete() {
        let st = state();
        let mk = |from: &str, to: &str| UpsertEdgeBody {
            from_kind: "capability".into(),
            from_id: from.into(),
            edge_kind: "depends_on".into(),
            to_kind: "capability".into(),
            to_id: to.into(),
            payload: json!({"weight": 1}),
        };
        let (status, body) = parts(
            put_edge(State(st.clone()), HeaderMap::new(), Json(mk("a", "b")))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["edge"]["from_id"], "a");

        let (status, body) = parts(
            list_edges(
                State(st.clone()),
                Query(ListEdgesQuery {
                    from_kind: Some("capability".into()),
                    from_id: Some("a".into()),
                    to_kind: None,
                    to_id: None,
                    edge_kind: None,
                    limit: None,
                    include_deleted: false,
                }),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], 1);

        let del = DeleteEdgeBody {
            from_kind: "capability".into(),
            from_id: "a".into(),
            edge_kind: "depends_on".into(),
            to_kind: "capability".into(),
            to_id: "b".into(),
        };
        let (status, _) = parts(
            delete_edge(State(st.clone()), HeaderMap::new(), Json(del))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Deleting an edge that was never created → NOT_FOUND.
        let del2 = DeleteEdgeBody {
            from_kind: "capability".into(),
            from_id: "a".into(),
            edge_kind: "depends_on".into(),
            to_kind: "capability".into(),
            to_id: "never-existed".into(),
        };
        let (status, _) = parts(
            delete_edge(State(st.clone()), HeaderMap::new(), Json(del2))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn kinds_list_and_get() {
        let st = state();
        {
            let mut reg = st.kind_registry.write().await;
            reg.register(KindRegistration {
                kind: "capability".to_string(),
                json_schema: json!({"type": "object"}),
                allowed_outgoing_edges: vec!["depends_on".into()],
                allowed_incoming_edges: vec![],
                description: "a capability".to_string(),
            })
            .unwrap();
        }
        let (status, body) = parts(list_kinds(State(st.clone()), HeaderMap::new()).await.into_response()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], 1);

        let (status, body) = parts(
            get_kind(State(st.clone()), Path("capability".into()), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["registration"]["kind"], "capability");

        let (status, _) = parts(
            get_kind(State(st.clone()), Path("unknown".into()), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
