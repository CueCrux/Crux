// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use super::*;

pub(super) async fn put_fact(
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

pub(super) async fn put_facts_bulk(
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

pub(super) async fn get_fact(
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

pub(super) async fn delete_fact(
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

pub(super) async fn get_facts_by_entity(
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

pub(super) async fn query_facts(
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
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "facts": result.facts,
            "total_tokens": result.total_tokens,
        })),
    )
        .into_response()
}

// ── Session Store API (Phase 1.5) ──────────────────────────────────

pub(super) async fn put_session_state(
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
    let session = state.session_store.write().await.put(&session_id, body, None);
    (StatusCode::OK, axum::Json(serde_json::json!(session))).into_response()
}

pub(super) async fn get_session_state(
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
