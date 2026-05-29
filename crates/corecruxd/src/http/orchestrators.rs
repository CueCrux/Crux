// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `/v1/orchestrators/*` — multi-agent orchestrator surface (orchestrators
//! plan).
//!
//! Mounted via `Router::merge` so the Wave-2 orchestrators plan owns the
//! handler bodies without touching `http/mod.rs`. Gated by
//! `CORECRUXD_ORCHESTRATORS` (default OFF): when off, every route returns a
//! `501` problem. When on, the scaffold handlers still return `501` with a
//! "not implemented (M1+ pending)" detail — the real CRUD lands in the
//! orchestrators plan's milestones.

use axum::routing::{delete, get, post};
use axum::Router;

use super::{problem_response, AppState, Response, StatusCode};

/// Routes for the orchestrator surface. Merged into the main router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/orchestrators", post(create_orchestrator).get(list_orchestrators))
        .route(
            "/v1/orchestrators/{id}",
            get(get_orchestrator).patch(patch_orchestrator),
        )
        .route("/v1/orchestrators/{id}/members", post(add_member))
        .route("/v1/orchestrators/{id}/members/{ref}", delete(remove_member))
        .route("/v1/orchestrators/{id}/work", get(list_orchestrator_work))
}

/// 501 helper for the orchestrator stubs — gate-aware: returns the disabled
/// message when the feature is off, otherwise the "pending" message.
fn stub(op: &str) -> Response {
    if !crate::agentgraph_kinds::orchestrators_enabled() {
        return problem_response(
            StatusCode::NOT_IMPLEMENTED,
            "orchestrators surface disabled (set CORECRUXD_ORCHESTRATORS=1)",
        );
    }
    problem_response(
        StatusCode::NOT_IMPLEMENTED,
        format!("orchestrator {op} not implemented (M1+ pending)"),
    )
}

// Wrappers keep ungated routing signatures uniform; `patch`/`get` reuse the
// same body since the scaffold has no per-op logic yet.

pub(super) async fn create_orchestrator() -> Response {
    stub("create")
}

pub(super) async fn list_orchestrators() -> Response {
    stub("list")
}

pub(super) async fn get_orchestrator() -> Response {
    stub("get")
}

pub(super) async fn patch_orchestrator() -> Response {
    stub("patch")
}

pub(super) async fn add_member() -> Response {
    stub("add-member")
}

pub(super) async fn remove_member() -> Response {
    stub("remove-member")
}

pub(super) async fn list_orchestrator_work() -> Response {
    stub("list-work")
}
