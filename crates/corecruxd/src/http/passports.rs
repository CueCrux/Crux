// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
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
pub(super) struct ListPendingMintRequestsQuery {
    pub by_passport: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ResolveMintRequestBody {
    pub approver_passport: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
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
    pub category: Option<String>,
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

fn mint_requests_disabled_response() -> axum::response::Response {
    problem_response(
        StatusCode::NOT_FOUND,
        "passport mint requests disabled (set CORECRUXD_FEATURE_PASSPORT_MINT_REQUESTS=1)",
    )
}

fn mint_request_error_response(err: crate::mint_requests::MintRequestResolutionError) -> axum::response::Response {
    use crate::mint_requests::MintRequestResolutionError;

    let status = match &err {
        MintRequestResolutionError::MissingApprover | MintRequestResolutionError::MissingCategory => {
            StatusCode::BAD_REQUEST
        }
        MintRequestResolutionError::Request(crate::mint_requests::MintRequestError::NotFound(_)) => {
            StatusCode::NOT_FOUND
        }
        MintRequestResolutionError::Request(crate::mint_requests::MintRequestError::NotPending { .. }) => {
            StatusCode::CONFLICT
        }
        MintRequestResolutionError::Request(crate::mint_requests::MintRequestError::ReasonTooLong { .. }) => {
            StatusCode::BAD_REQUEST
        }
        MintRequestResolutionError::Request(crate::mint_requests::MintRequestError::AlreadyPending { .. }) => {
            StatusCode::CONFLICT
        }
        MintRequestResolutionError::Request(crate::mint_requests::MintRequestError::QueueFull { .. }) => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        MintRequestResolutionError::Request(
            crate::mint_requests::MintRequestError::Json(_) | crate::mint_requests::MintRequestError::Store(_),
        ) => StatusCode::INTERNAL_SERVER_ERROR,
        MintRequestResolutionError::Passport(
            crate::passports::PassportsError::InvalidId(_) | crate::passports::PassportsError::InvalidCategory(_),
        ) => StatusCode::BAD_REQUEST,
        MintRequestResolutionError::Passport(crate::passports::PassportsError::DuplicateId(_)) => StatusCode::CONFLICT,
        MintRequestResolutionError::Passport(crate::passports::PassportsError::NotFound(_)) => StatusCode::NOT_FOUND,
        MintRequestResolutionError::Passport(
            crate::passports::PassportsError::Io(_)
            | crate::passports::PassportsError::Json(_)
            | crate::passports::PassportsError::Session(_),
        ) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    problem_response(status, err.to_string())
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64)
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

pub(super) async fn get_pending_mint_requests(
    State(state): State<AppState>,
    Query(query): Query<ListPendingMintRequestsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !state.passport_mint_requests_enabled {
        return mint_requests_disabled_response();
    }
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let store = state.fact_store.read().await;
    let mut pending = crate::mint_requests::list_pending_mint_requests(&store);
    drop(store);

    if let Some(by_passport) = query.by_passport.as_deref() {
        pending.retain(|request| request.requested_by_passport == by_passport);
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "count": pending.len(),
            "pending": pending,
        })),
    )
        .into_response()
}

pub(super) async fn post_mint_request_approve(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ResolveMintRequestBody>,
) -> impl IntoResponse {
    // Load-bearing: feature-off requests return before auth, locking, or any
    // passport/request mutation.
    if !state.passport_mint_requests_enabled {
        return mint_requests_disabled_response();
    }
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }

    // One exclusive guard spans pending preflight, passport mint/update, and
    // terminal transition. Approve and reject therefore cannot race between
    // their status check and mutation.
    let mut store = state.fact_store.write().await;
    let result = crate::mint_requests::approve_mint_request(
        &state.data_dir,
        &mut store,
        &request_id,
        body.approver_passport,
        body.category,
        body.name,
        now_unix_ms(),
    );
    drop(store);

    match result {
        Ok(approved) => (StatusCode::OK, Json(approved)).into_response(),
        Err(err) => mint_request_error_response(err),
    }
}

pub(super) async fn post_mint_request_reject(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ResolveMintRequestBody>,
) -> impl IntoResponse {
    // Keep the same pre-lock no-op gate as approval. Category/name overrides
    // are intentionally ignored because rejection must never touch a passport.
    if !state.passport_mint_requests_enabled {
        return mint_requests_disabled_response();
    }
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }

    let mut store = state.fact_store.write().await;
    let result =
        crate::mint_requests::reject_mint_request(&mut store, &request_id, body.approver_passport, now_unix_ms());
    drop(store);

    match result {
        Ok(rejected) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "request_id": rejected.request_id,
                "requester_id": rejected.requester_id,
                "minted": false,
                "status": rejected.status,
            })),
        )
            .into_response(),
        Err(err) => mint_request_error_response(err),
    }
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
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let now_ms = now_unix_ms();
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
            category: body.category,
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
