// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use super::*;

/// Query parameters for the GET /v1/facts endpoint.
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub(super) struct QueryFactsParams {
    /// Free-text BM25 query over fact values.
    pub query: Option<String>,
    /// Exact entity match.
    pub entity: Option<String>,
    /// Entity prefix filter (e.g. `__ops__::`)
    pub entity_prefix: Option<String>,
    /// Maximum number of results to return (default 10).
    pub top_k: Option<usize>,
    /// Token budget — fill results by descending score until exhausted.
    pub token_budget: Option<usize>,
}

/// Query parameters for the GET /v1/facts/export endpoint.
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub(super) struct ExportFactsParams {
    /// Only include facts stored after this RFC 3339 timestamp.
    pub since: Option<String>,
    /// Cursor for pagination (from previous response).
    pub cursor: Option<String>,
    /// Maximum number of facts to return (default 1000, max 10000).
    pub limit: Option<u32>,
}

#[utoipa::path(
    put,
    path = "/v1/facts",
    tag = "Facts",
    request_body = corecrux_memory::fact_store::StoreFact,
    responses(
        (status = 201, description = "Fact created", body = corecrux_memory::fact_store::Fact),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn put_fact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<corecrux_memory::fact_store::StoreFact>,
) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let fact = state.fact_store.write().await.store(body);
    (StatusCode::CREATED, axum::Json(serde_json::json!(fact))).into_response()
}

#[utoipa::path(
    put,
    path = "/v1/facts/bulk",
    tag = "Facts",
    request_body = Vec<corecrux_memory::fact_store::StoreFact>,
    responses(
        (status = 201, description = "Facts created"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn put_facts_bulk(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Vec<corecrux_memory::fact_store::StoreFact>>,
) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let facts = state.fact_store.write().await.store_bulk(body);
    (StatusCode::CREATED, axum::Json(serde_json::json!({"facts": facts}))).into_response()
}

#[utoipa::path(
    get,
    path = "/v1/facts/{factId}",
    tag = "Facts",
    params(("factId" = String, Path, description = "Fact identifier")),
    responses(
        (status = 200, description = "Fact found", body = corecrux_memory::fact_store::Fact),
        (status = 404, description = "Fact not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn get_fact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(fact_id): Path<String>,
) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let store = state.fact_store.read().await;
    match store.get(&fact_id) {
        Some(fact) => (StatusCode::OK, axum::Json(serde_json::json!(fact))).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, format!("fact '{}' not found", fact_id)),
    }
}

#[utoipa::path(
    delete,
    path = "/v1/facts/{factId}",
    tag = "Facts",
    params(("factId" = String, Path, description = "Fact identifier")),
    responses(
        (status = 200, description = "Fact deleted"),
        (status = 404, description = "Fact not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn delete_fact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(fact_id): Path<String>,
) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let deleted = state.fact_store.write().await.delete(&fact_id);
    if deleted {
        (StatusCode::OK, axum::Json(serde_json::json!({"deleted": true}))).into_response()
    } else {
        problem_response(StatusCode::NOT_FOUND, format!("fact '{}' not found", fact_id))
    }
}

#[utoipa::path(
    get,
    path = "/v1/facts/entity/{entity}",
    tag = "Facts",
    params(("entity" = String, Path, description = "Entity name")),
    responses(
        (status = 200, description = "Facts for entity"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn get_facts_by_entity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(entity): Path<String>,
) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let store = state.fact_store.read().await;
    let facts: Vec<_> = store.get_by_entity(&entity);
    (StatusCode::OK, axum::Json(serde_json::json!({"facts": facts}))).into_response()
}

#[utoipa::path(
    get,
    path = "/v1/facts",
    tag = "Facts",
    params(QueryFactsParams),
    responses(
        (status = 200, description = "Matching facts"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn query_facts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<QueryFactsParams>,
) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let q = corecrux_memory::fact_store::FactQuery {
        query: params.query,
        entity: params.entity,
        entity_prefix: params.entity_prefix,
        top_k: params.top_k.unwrap_or(10),
        token_budget: params.token_budget,
    };
    let store = state.fact_store.read().await;
    let result = store.query(&q);
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "facts": result.facts,
            "total_tokens": result.total_tokens,
        })),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/v1/facts/export",
    tag = "Facts",
    params(ExportFactsParams),
    responses(
        (status = 200, description = "Exported facts"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn export_facts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ExportFactsParams>,
) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }

    let since = params
        .since
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    let cursor = params.cursor.as_deref();

    let limit = params.limit.map_or(1000, |v| v.min(10000) as usize);

    let store = state.fact_store.read().await;
    let result = store.export(since, cursor, limit);

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "facts": result.facts,
            "next_cursor": result.next_cursor,
            "has_more": result.has_more,
            "exported_at": chrono::Utc::now().to_rfc3339(),
        })),
    )
        .into_response()
}

// ── Session Store API (Phase 1.5) ──────────────────────────────────

#[utoipa::path(
    put,
    path = "/v1/sessions/{sessionId}/state",
    tag = "Sessions",
    params(("sessionId" = String, Path, description = "Session identifier")),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Session state stored", body = corecrux_memory::session_store::SessionState),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn put_session_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let session = state.session_store.write().await.put(&session_id, body, None);
    (StatusCode::OK, axum::Json(serde_json::json!(session))).into_response()
}

#[utoipa::path(
    get,
    path = "/v1/sessions/{sessionId}/state",
    tag = "Sessions",
    params(("sessionId" = String, Path, description = "Session identifier")),
    responses(
        (status = 200, description = "Session state found", body = corecrux_memory::session_store::SessionState),
        (status = 404, description = "Session not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn get_session_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    let store = state.session_store.read().await;
    match store.get(&session_id) {
        Some(session) => (StatusCode::OK, axum::Json(serde_json::json!(session))).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, format!("session '{}' not found", session_id)),
    }
}
