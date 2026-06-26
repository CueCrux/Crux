// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP case-store routes — `/v1/cases` (record) + `/v1/cases/retrieve`
//! (similar-case lookup) for the Memento-style procedural memory (M3).
//!
//! The `CaseStore` is NOT a field on [`AppState`] (which has ~25 construction
//! sites); it is supplied to handlers via an axum `Extension` layer, while
//! `State<AppState>` is still extracted for scope authorization. This keeps the
//! surface additive with zero `AppState` churn.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use tokio::sync::RwLock;

use corecrux_memory::case_store::{CaseStore, RecordCase};

use super::*;

/// Shared handle injected via the router's `Extension` layer.
pub(super) type SharedCaseStore = Arc<RwLock<CaseStore>>;

/// Body for `POST /v1/cases/retrieve`.
#[derive(Debug, serde::Deserialize)]
pub(super) struct RetrieveCasesBody {
    /// The task / situation to find analogous past cases for.
    pub task: String,
    /// Maximum number of cases to return (default 5).
    #[serde(default = "default_retrieve_top_k")]
    pub top_k: usize,
    /// When true, return only successful precedents (default false).
    #[serde(default)]
    pub only_success: bool,
}

fn default_retrieve_top_k() -> usize {
    5
}

const MAX_RETRIEVE_TOP_K: usize = 100;

#[allow(clippy::result_large_err)]
fn require_write(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    crate::auth::require_http_any_scope(&state.auth, headers, &["facts:write", "admin:write"])
        .map_err(IntoResponse::into_response)
}

#[allow(clippy::result_large_err)]
fn require_read(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    crate::auth::require_http_any_scope(&state.auth, headers, &["query:read", "admin:read"])
        .map_err(IntoResponse::into_response)
}

/// `POST /v1/cases` — record a procedural-memory case.
pub(super) async fn record_case(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(case_store): Extension<SharedCaseStore>,
    Json(req): Json<RecordCase>,
) -> Response {
    if let Err(resp) = require_write(&state, &headers) {
        return resp;
    }
    if req.task.trim().is_empty() || req.action.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "task and action are required");
    }
    let case = case_store.write().await.record_case(req);
    (StatusCode::OK, Json(serde_json::json!({ "case": case }))).into_response()
}

/// `POST /v1/cases/retrieve` — return cases analogous to a task, best first.
pub(super) async fn retrieve_cases(
    State(state): State<AppState>,
    headers: HeaderMap,
    Extension(case_store): Extension<SharedCaseStore>,
    Json(body): Json<RetrieveCasesBody>,
) -> Response {
    if let Err(resp) = require_read(&state, &headers) {
        return resp;
    }
    let top_k = body.top_k.clamp(1, MAX_RETRIEVE_TOP_K);
    let cases = case_store
        .read()
        .await
        .retrieve_similar(&body.task, top_k, body.only_success);
    (StatusCode::OK, Json(serde_json::json!({ "cases": cases }))).into_response()
}
