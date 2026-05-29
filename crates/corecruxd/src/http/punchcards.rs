// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `/v1/punchcards/*` — resource-lease surface (punchcard plan).
//!
//! Mounted via `Router::merge` so the Wave-2 punchcard plan owns the handler
//! bodies without touching `http/mod.rs`. Gated by `CORECRUXD_PUNCHCARD`
//! (`off` | `advisory` | `enforce`, default `off`): when off, every route
//! returns a `501` problem. When advisory/enforce, the scaffold handlers
//! still return `501` with a "not implemented (M1+ pending)" detail — the
//! real acquire/release/force-release logic lands in the punchcard plan's
//! milestones.
//!
//! `POST /v1/punchcards/check` is the endpoint the shared PreToolUse hook
//! probes before an Edit/Write/NotebookEdit. While stubbed it returns 501,
//! which the hook interprets as fail-open (ALLOW).

use axum::routing::{get, post};
use axum::Router;

use super::{problem_response, AppState, Response, StatusCode};

/// Routes for the punchcard surface. Merged into the main router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/punchcards/acquire", post(acquire))
        .route("/v1/punchcards/release", post(release))
        .route("/v1/punchcards", get(list_punchcards))
        .route("/v1/punchcards/{id}/force-release", post(force_release))
        .route("/v1/punchcards/check", post(check))
}

/// 501 helper for the punchcard stubs — gate-aware: returns the disabled
/// message when the feature is off, otherwise the "pending" message.
fn stub(op: &str) -> Response {
    if !crate::agentgraph_kinds::punchcard_enabled() {
        return problem_response(
            StatusCode::NOT_IMPLEMENTED,
            "punchcard surface disabled (set CORECRUXD_PUNCHCARD=advisory|enforce)",
        );
    }
    problem_response(
        StatusCode::NOT_IMPLEMENTED,
        format!("punchcard {op} not implemented (M1+ pending)"),
    )
}

pub(super) async fn acquire() -> Response {
    stub("acquire")
}

pub(super) async fn release() -> Response {
    stub("release")
}

pub(super) async fn list_punchcards() -> Response {
    stub("list")
}

pub(super) async fn force_release() -> Response {
    stub("force-release")
}

pub(super) async fn check() -> Response {
    stub("check")
}
