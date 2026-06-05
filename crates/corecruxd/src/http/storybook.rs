// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP routes for the storybook readout (Phase 3 of the context graph).
//!
//! - `POST /v1/projects/{id}/storybook`               — generate a fresh readout
//! - `GET  /v1/projects/{id}/storybook`               — return the latest
//! - `GET  /v1/projects/{id}/storybook/versions`      — list saved readouts
//! - `GET  /v1/projects/{id}/storybook/{ts}`          — fetch one specific
//! - `GET  /v1/projects/{id}/storybook/diff?a=&b=`    — diff two readouts
//!
//! Each readout is persisted as a single private fact under
//! `__storybook__::{project_id}::{ts}` key=`content`. The privacy gate covers
//! `__storybook__::*` so they're never push-eligible without explicit opt-in.

use super::{
    problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Path, Query, State, StatusCode,
};

const STORYBOOK_PREFIX: &str = "__storybook__";
const STORYBOOK_KEY: &str = "content";

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn entity_for(project_id: &str, ts: u64) -> String {
    format!("{STORYBOOK_PREFIX}::{project_id}::{ts}")
}

fn extract_passport_id(headers: &HeaderMap) -> String {
    headers
        .get("x-corecrux-passport-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "anonymous".to_string())
}

pub(super) async fn post_generate(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let by_passport = extract_passport_id(&headers);
    let now_ms = now_unix_ms();

    let store = state.fact_store.read().await;
    let doc = match crate::storybook::generate(
        &store,
        crate::storybook::GenerateInput {
            project_id: &project_id,
            by_passport: &by_passport,
            now_unix_ms: now_ms,
        },
    ) {
        Some(d) => d,
        None => return problem_response(StatusCode::NOT_FOUND, format!("project '{project_id}' not found")),
    };
    drop(store);

    let value = match serde_json::to_string(&doc) {
        Ok(v) => v,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("encode: {err}")),
    };
    {
        let mut store = state.fact_store.write().await;
        let mut sf = corecrux_memory::fact_store::StoreFact {
            entity: entity_for(&project_id, now_ms),
            key: STORYBOOK_KEY.to_string(),
            value,
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };
        crate::fact_privacy::enforce_global(&mut sf);
        store.store(sf);
    }

    let summary = serde_json::json!({
        "project_id": doc.project_id,
        "generated_at_unix_ms": doc.generated_at_unix_ms,
        "generated_by_passport": doc.generated_by_passport,
        "stats": doc.stats,
        "bytes": doc.markdown.len(),
        "section_count": doc.sections.len(),
    });
    (StatusCode::OK, Json(summary)).into_response()
}

async fn list_storybook_versions_internal(
    fact_store: &std::sync::Arc<tokio::sync::RwLock<corecrux_memory::FactStore>>,
    project_id: &str,
) -> Vec<u64> {
    let store = fact_store.read().await;
    let prefix = format!("{STORYBOOK_PREFIX}::{project_id}::");
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        query: Some(prefix.clone()),
        entity: None,
        entity_prefix: None,
        top_k: 200,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    let mut tss: Vec<u64> = latest
        .into_iter()
        .filter(|f| f.entity.starts_with(&prefix) && f.key == STORYBOOK_KEY && !f.value.is_empty())
        .filter_map(|f| f.entity[prefix.len()..].parse::<u64>().ok())
        .collect();
    tss.sort_by(|a, b| b.cmp(a));
    tss
}

async fn load_storybook(
    fact_store: &std::sync::Arc<tokio::sync::RwLock<corecrux_memory::FactStore>>,
    project_id: &str,
    ts: u64,
) -> Option<crate::storybook::StorybookDocument> {
    let store = fact_store.read().await;
    let entity = entity_for(project_id, ts);
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        query: None,
        entity: Some(entity.clone()),
        entity_prefix: None,
        top_k: 8,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    let fact = latest
        .into_iter()
        .find(|f| f.entity == entity && f.key == STORYBOOK_KEY)?;
    serde_json::from_str::<crate::storybook::StorybookDocument>(&fact.value).ok()
}

pub(super) async fn get_latest(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let versions = list_storybook_versions_internal(&state.fact_store, &project_id).await;
    let latest_ts = match versions.first() {
        Some(t) => *t,
        None => {
            return problem_response(
                StatusCode::NOT_FOUND,
                "no readout yet — POST /v1/projects/{id}/storybook to generate one",
            )
        }
    };
    match load_storybook(&state.fact_store, &project_id, latest_ts).await {
        Some(d) => (StatusCode::OK, Json(d)).into_response(),
        None => problem_response(StatusCode::INTERNAL_SERVER_ERROR, "failed to load latest readout"),
    }
}

pub(super) async fn list_versions(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let versions = list_storybook_versions_internal(&state.fact_store, &project_id).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "project_id": project_id,
            "count": versions.len(),
            "versions": versions,
        })),
    )
        .into_response()
}

pub(super) async fn get_version(
    State(state): State<AppState>,
    Path((project_id, ts)): Path<(String, u64)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    match load_storybook(&state.fact_store, &project_id, ts).await {
        Some(d) => (StatusCode::OK, Json(d)).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, "no readout with that timestamp"),
    }
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct DiffQuery {
    pub a: u64,
    pub b: u64,
}

pub(super) async fn get_diff(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    Query(q): Query<DiffQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let a = match load_storybook(&state.fact_store, &project_id, q.a).await {
        Some(d) => d,
        None => return problem_response(StatusCode::NOT_FOUND, format!("readout 'a' (ts={}) not found", q.a)),
    };
    let b = match load_storybook(&state.fact_store, &project_id, q.b).await {
        Some(d) => d,
        None => return problem_response(StatusCode::NOT_FOUND, format!("readout 'b' (ts={}) not found", q.b)),
    };
    let diff = crate::storybook::diff_documents(&a, &b);
    (StatusCode::OK, Json(diff)).into_response()
}
