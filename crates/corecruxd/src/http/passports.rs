// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP CRUD for the multi-passport store.

#![allow(clippy::option_option)] // PATCH tri-state semantics

use super::{
    problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Path, Query, State, StatusCode,
};

#[derive(Debug, serde::Deserialize)]
pub(super) struct ListPassportsQuery {
    pub category: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct CreatePassportBody {
    pub id: String,
    pub category: String,
    #[serde(default)]
    pub sponsor_id: Option<String>,
    #[serde(default)]
    pub agent_work_gate: bool,
    #[serde(default)]
    pub is_default_for_category: bool,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub position: Option<String>,
    #[serde(default)]
    pub company: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct UpdatePassportBody {
    #[serde(default)]
    pub agent_work_gate: Option<bool>,
    #[serde(default)]
    pub is_default_for_category: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_some_option")]
    pub sponsor_id: Option<Option<String>>,
    #[serde(default)]
    pub reputation_tier: Option<String>,
    #[serde(default)]
    pub receipt_count: Option<u64>,
    #[serde(default, deserialize_with = "deserialize_some_option")]
    pub name: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some_option")]
    pub owner: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some_option")]
    pub position: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some_option")]
    pub company: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some_option")]
    pub notes: Option<Option<String>>,
}

/// Treats explicit `null` as `Some(None)` (clear the sponsor) and absent as
/// `None` (no change). Supports the standard PATCH-clears semantics.
fn deserialize_some_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    use serde::Deserialize;
    Option::<T>::deserialize(deserializer).map(Some)
}

pub(super) async fn get_passports(
    State(state): State<AppState>,
    Query(query): Query<ListPassportsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    if let Some(cat) = query.category.as_deref() {
        if cat != "all" && crate::passports::validate_category(cat).is_err() {
            return problem_response(
                StatusCode::BAD_REQUEST,
                "category must be one of personal, work, public, all",
            );
        }
    }
    let store = state.fact_store.read().await;
    let cat_filter = query.category.as_deref().filter(|c| *c != "all");
    let passports = crate::passports::list_passports(&store, cat_filter);
    drop(store);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "passports": passports,
            "category_filter": cat_filter,
        })),
    )
        .into_response()
}

pub(super) async fn get_passport(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let result = crate::passports::get_passport(&store, &id);
    drop(store);
    match result {
        Some(p) => (StatusCode::OK, Json(p)).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, format!("passport '{id}' not found")),
    }
}

pub(super) async fn post_passport(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreatePassportBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let mut store = state.fact_store.write().await;
    let result = crate::passports::create_passport(
        &state.data_dir,
        &mut store,
        crate::passports::CreatePassportInput {
            id: body.id,
            category: body.category,
            sponsor_id: body.sponsor_id,
            agent_work_gate: body.agent_work_gate,
            is_default_for_category: body.is_default_for_category,
            name: body.name,
            owner: body.owner,
            position: body.position,
            company: body.company,
            notes: body.notes,
        },
        now_ms,
    );
    drop(store);
    match result {
        Ok(p) => (StatusCode::CREATED, Json(p)).into_response(),
        Err(crate::passports::PassportsError::DuplicateId(_)) => {
            problem_response(StatusCode::CONFLICT, "passport id already exists")
        }
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

pub(super) async fn patch_passport(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpdatePassportBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::passports::update_passport(
        &mut store,
        &id,
        crate::passports::UpdatePassportInput {
            agent_work_gate: body.agent_work_gate,
            is_default_for_category: body.is_default_for_category,
            sponsor_id: body.sponsor_id,
            reputation_tier: body.reputation_tier,
            receipt_count: body.receipt_count,
            name: body.name,
            owner: body.owner,
            position: body.position,
            company: body.company,
            notes: body.notes,
        },
    );
    drop(store);
    match result {
        Ok(p) => (StatusCode::OK, Json(p)).into_response(),
        Err(crate::passports::PassportsError::NotFound(_)) => {
            problem_response(StatusCode::NOT_FOUND, "passport not found")
        }
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

pub(super) async fn delete_passport(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::passports::delete_passport(&mut store, &id);
    drop(store);
    match result {
        Ok(()) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(crate::passports::PassportsError::NotFound(_)) => {
            problem_response(StatusCode::NOT_FOUND, "passport not found")
        }
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

/// `GET /v1/passports/presence` — multi-agent presence snapshot. Returns the
/// list of passports the daemon has observed in the last process lifetime,
/// most-recently-seen first. In-memory only; never touches disk.
pub(super) async fn get_presence(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let snapshot = state.presence.snapshot().await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "count": snapshot.len(),
            "presence": snapshot,
        })),
    )
        .into_response()
}
