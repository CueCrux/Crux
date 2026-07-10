// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Self-observation routes — `/v1/ops/{facts,errors,health}` + `/v1/bootstrap/{pull,status}`.

use super::{
    problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Query, Response, State, StatusCode,
};

// ── Self-observation API (crux-observe) ───────────────────────────

pub(super) fn is_observe_enabled() -> bool {
    crux_observe::config::self_observe_enabled()
}

pub(super) fn observe_not_enabled_response() -> Response {
    problem_response(StatusCode::NOT_IMPLEMENTED, "self-observation not enabled")
}

pub(super) async fn query_ops_facts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    if !is_observe_enabled() {
        return observe_not_enabled_response();
    }
    let q = corecrux_memory::fact_store::FactQuery {
        query: params.get("query").cloned(),
        entity: None,
        entity_prefix: Some(crux_observe::schema::OPS_PREFIX.to_string()),
        top_k: params.get("top_k").and_then(|v| v.parse().ok()).unwrap_or(50),
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

pub(super) async fn query_ops_errors(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    if !is_observe_enabled() {
        return observe_not_enabled_response();
    }
    let q = corecrux_memory::fact_store::FactQuery {
        query: params.get("query").cloned(),
        entity: None,
        entity_prefix: Some("__ops__::error".to_string()),
        top_k: params.get("top_k").and_then(|v| v.parse().ok()).unwrap_or(50),
        token_budget: params.get("token_budget").and_then(|v| v.parse().ok()),
    };
    let store = state.fact_store.read().await;
    let result = store.query(&q);

    // If `since` param is provided, filter by stored_at
    let facts = if let Some(since_str) = params.get("since") {
        if let Ok(since) = chrono::DateTime::parse_from_rfc3339(since_str) {
            let since_utc = since.with_timezone(&chrono::Utc);
            result.facts.into_iter().filter(|f| f.stored_at >= since_utc).collect()
        } else {
            result.facts
        }
    } else {
        result.facts
    };

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "facts": facts,
            "total_tokens": result.total_tokens,
        })),
    )
        .into_response()
}

pub(super) async fn get_ops_health(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    if !is_observe_enabled() {
        return observe_not_enabled_response();
    }
    let q = corecrux_memory::fact_store::FactQuery {
        query: None,
        entity: None,
        entity_prefix: Some("__ops__::health".to_string()),
        top_k: 1000,
        token_budget: None,
    };
    let store = state.fact_store.read().await;
    let result = store.query(&q);

    // Deduplicate: keep only the latest fact per component (entity)
    let mut latest: std::collections::HashMap<String, &corecrux_memory::fact_store::Fact> =
        std::collections::HashMap::new();
    for fact in &result.facts {
        let entry = latest.entry(fact.entity.clone()).or_insert(fact);
        if fact.stored_at > entry.stored_at {
            *entry = fact;
        }
    }
    let health_facts: Vec<_> = latest.into_values().collect();

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "health": health_facts,
        })),
    )
        .into_response()
}

#[derive(serde::Deserialize)]
pub(super) struct BootstrapPullBody {
    pub(super) query: String,
    #[serde(default = "default_bootstrap_top_k")]
    pub(super) top_k: usize,
    pub(super) token_budget: Option<usize>,
}

pub(super) fn default_bootstrap_top_k() -> usize {
    10
}

pub(super) async fn post_bootstrap_pull(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<BootstrapPullBody>,
) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    if !is_observe_enabled() {
        return observe_not_enabled_response();
    }
    let gate = crux_observe::cold_gate::ColdGate::new(state.fact_store.clone());
    let result = gate.pull(&body.query, body.top_k, body.token_budget).await;
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "facts": result.facts,
            "total_tokens": result.total_tokens,
            "source": result.source,
        })),
    )
        .into_response()
}

pub(super) async fn get_bootstrap_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }
    if !is_observe_enabled() {
        return observe_not_enabled_response();
    }
    let seeder = crux_observe::bootstrap::BootstrapSeeder::new(state.fact_store.clone());
    let status = seeder.status().await;
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "seeded": status.seeded,
            "fact_count": status.fact_count,
            "categories": status.categories,
            "last_seed_at": status.last_seed_at,
        })),
    )
        .into_response()
}
