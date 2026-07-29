// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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
    #[serde(default)]
    pub approver_passport: Option<String>,
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

#[allow(clippy::result_large_err)] // Axum responses preserve the exact HTTP denial at this boundary.
fn mint_request_approver(
    state: &AppState,
    headers: &HeaderMap,
    claimed_approver: Option<&str>,
) -> Result<(String, String), axum::response::Response> {
    let context = crate::auth::passport_bound_context(&state.auth, headers).map_err(IntoResponse::into_response)?;
    if let Err(problem) = crate::auth::require_http_scopes_for_tenant(&state.auth, headers, &["admin:write"], "default")
    {
        return Err(problem.into_response());
    }
    let claimed_approver = claimed_approver.map(str::trim).filter(|claimed| !claimed.is_empty());

    if !context.auth_enforced() {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            "a cryptographically verified human passport is required for passport-mint decisions",
        ));
    }
    if context.passport_override_used() {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            "passport impersonation is not permitted for passport-mint decisions",
        ));
    }
    if context.credential_is_agent_token() {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            "automation credentials cannot satisfy a human passport-mint decision",
        ));
    }
    if !context.canonical_passport_claim_verified() {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            "a cryptographically verified canonical passport_id claim is required for passport-mint decisions",
        ));
    }
    let Some(asserted) = context.passport_id.as_deref() else {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            "an authenticated passport is required for passport-mint decisions",
        ));
    };
    if claimed_approver.is_some_and(|claimed| claimed != asserted) {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            "approver_passport does not match the authenticated passport",
        ));
    }
    Ok((asserted.to_string(), asserted.to_string()))
}

#[allow(clippy::result_large_err)] // Axum responses preserve the exact HTTP denial at this boundary.
fn deny_mint_request_self_review(
    request: &crate::mint_requests::PendingMintRequest,
    asserted_approver: &str,
) -> Result<(), axum::response::Response> {
    if request.requested_by_passport == asserted_approver || request.requester_id == asserted_approver {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            "the requesting passport cannot resolve its own passport-mint request",
        ));
    }
    Ok(())
}

#[tracing::instrument(level = "info", skip_all)]
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

#[tracing::instrument(level = "info", skip_all)]
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

#[tracing::instrument(level = "info", skip_all)]
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
    let (asserted_approver, approver_actor) =
        match mint_request_approver(&state, &headers, body.approver_passport.as_deref()) {
            Ok(approver) => approver,
            Err(response) => return response,
        };

    // One exclusive guard spans pending preflight, receipt persistence,
    // passport mint/update, and terminal transition. Approve and reject cannot
    // race between authorization and the fact-store commit.
    let mut store = state.fact_store.write().await;
    let pending = match crate::mint_requests::pending_request(&store, &request_id) {
        Ok(pending) => pending,
        Err(err) => return mint_request_error_response(err.into()),
    };
    if let Err(response) = deny_mint_request_self_review(&pending, &asserted_approver) {
        return response;
    }

    let receipt_id = format!("ad_{request_id}");
    let passport_issued_at_unix_ms =
        match super::approval_receipts::load_local_approval_receipt(&state, "default", &receipt_id) {
            Ok(Some(existing)) => match existing.passport_issued_at_unix_ms {
                Some(issued_at) => issued_at,
                None => {
                    return problem_response(
                        StatusCode::CONFLICT,
                        "the existing approval receipt lacks passport issuance metadata",
                    );
                }
            },
            Ok(None) => now_unix_ms(),
            Err(detail) => {
                return problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("existing approval receipt validation failed: {detail}"),
                );
            }
        };
    let prepared = match crate::mint_requests::prepare_mint_request_approval(
        &state.data_dir,
        &store,
        &request_id,
        approver_actor.clone(),
        body.category,
        body.name,
        &receipt_id,
        passport_issued_at_unix_ms,
    ) {
        Ok(prepared) => prepared,
        Err(err) => return mint_request_error_response(err),
    };
    let mut envelope_fields = serde_json::Map::new();
    envelope_fields.insert(
        "requester_id".to_string(),
        serde_json::Value::String(prepared.request.requester_id.clone()),
    );
    envelope_fields.insert(
        "category".to_string(),
        serde_json::Value::String(prepared.approved.category.clone()),
    );
    envelope_fields.insert(
        "passport_operation".to_string(),
        serde_json::Value::String(prepared.approved.passport_operation.clone()),
    );
    envelope_fields.insert(
        "passport_record_hash".to_string(),
        serde_json::Value::String(prepared.approved.passport_record_hash.clone()),
    );
    envelope_fields.insert(
        "passport_mutation_hash".to_string(),
        serde_json::Value::String(prepared.approved.passport_mutation_hash.clone()),
    );
    envelope_fields.insert(
        "passport_issued_at_unix_ms".to_string(),
        serde_json::Value::Number(passport_issued_at_unix_ms.into()),
    );
    let receipt = match super::approval_receipts::mint_or_load_approval_receipt(
        &state,
        &super::approval_receipts::ApprovalReceiptSpec {
            receipt_id: &receipt_id,
            tenant_id: "default",
            request_id: &request_id,
            action_summary: &prepared.action_summary,
            envelope_fields,
        },
        &approver_actor,
        corecrux_receipts::ApprovalDecisionV1::Approve,
    ) {
        Ok(receipt) => receipt,
        Err(failure) => {
            if !failure.receipt_binds_preparation {
                if let Err(cleanup_err) = prepared.cleanup_uncommitted_key() {
                    return problem_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("{}; uncommitted key cleanup failed: {cleanup_err}", failure.detail),
                    );
                }
            }
            return problem_response(failure.status, failure.detail);
        }
    };
    let result = prepared.commit(&mut store);
    drop(store);

    match result {
        Ok(approved) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "request_id": approved.request_id,
                "requester_id": approved.requester_id,
                "category": approved.category,
                "minted": approved.minted,
                "status": approved.status,
                "passport_operation": approved.passport_operation,
                "passport_record_hash": approved.passport_record_hash,
                "passport_mutation_hash": approved.passport_mutation_hash,
                "receipt_id": receipt.receipt_id,
                "receipt_record_id": receipt.observation_id,
                "receipt_session_id": super::approval_receipts::APPROVAL_RECEIPT_SESSION,
            })),
        )
            .into_response(),
        Err(err) => mint_request_error_response(err),
    }
}

#[tracing::instrument(level = "info", skip_all)]
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
    let (asserted_approver, approver_actor) =
        match mint_request_approver(&state, &headers, body.approver_passport.as_deref()) {
            Ok(approver) => approver,
            Err(response) => return response,
        };

    let mut store = state.fact_store.write().await;
    let pending = match crate::mint_requests::pending_request(&store, &request_id) {
        Ok(pending) => pending,
        Err(err) => return mint_request_error_response(err.into()),
    };
    if let Err(response) = deny_mint_request_self_review(&pending, &asserted_approver) {
        return response;
    }
    let receipt_id = format!("ad_{request_id}");
    let action_summary = crate::mint_requests::mint_request_rejection_action_summary(&pending);
    let mut envelope_fields = serde_json::Map::new();
    envelope_fields.insert(
        "requester_id".to_string(),
        serde_json::Value::String(pending.requester_id.clone()),
    );
    let receipt = match super::approval_receipts::mint_or_load_approval_receipt(
        &state,
        &super::approval_receipts::ApprovalReceiptSpec {
            receipt_id: &receipt_id,
            tenant_id: "default",
            request_id: &request_id,
            action_summary: &action_summary,
            envelope_fields,
        },
        &approver_actor,
        corecrux_receipts::ApprovalDecisionV1::Reject,
    ) {
        Ok(receipt) => receipt,
        Err(failure) => return problem_response(failure.status, failure.detail),
    };
    let result =
        crate::mint_requests::reject_mint_request(&mut store, &request_id, approver_actor, &receipt_id, now_unix_ms());
    drop(store);

    match result {
        Ok(rejected) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "request_id": rejected.request_id,
                "requester_id": rejected.requester_id,
                "minted": false,
                "status": rejected.status,
                "receipt_id": receipt.receipt_id,
                "receipt_record_id": receipt.observation_id,
                "receipt_session_id": super::approval_receipts::APPROVAL_RECEIPT_SESSION,
            })),
        )
            .into_response(),
        Err(err) => mint_request_error_response(err),
    }
}

#[tracing::instrument(level = "info", skip_all)]
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

#[tracing::instrument(level = "info", skip_all)]
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

#[tracing::instrument(level = "info", skip_all)]
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

#[tracing::instrument(level = "info", skip_all)]
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
#[tracing::instrument(level = "info", skip_all)]
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
