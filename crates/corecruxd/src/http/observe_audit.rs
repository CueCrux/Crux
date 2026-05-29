// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `/v1/observe/*` — agent audit-chain surface (observe plan).
//!
//! Mounted via `Router::merge` so the Wave-2 observe plan can flesh out the
//! handlers without touching `http/mod.rs`. Gated by `CORECRUXD_OBSERVE`
//! (default OFF): when off, every route returns a `501` problem.
//!
//! The scaffold currently serves an empty [`crux_observe_api::SessionAudit`].
//! M1+ of the observe plan replaces the empty `steps` vec with the real
//! `agent_trace_node`-derived chain.

use axum::routing::get;
use axum::Router;

use super::{
    problem_response, require_http_any_scope, AppState, HeaderMap, IntoResponse, Json, Path, Response, State,
    StatusCode,
};

/// Routes for the observe audit-chain surface. Merged into the main router.
pub fn routes() -> Router<AppState> {
    Router::new().route("/v1/observe/sessions/{id}/audit", get(get_session_audit))
}

/// `GET /v1/observe/sessions/{id}/audit` — return the ordered audit chain for
/// one session. Scaffold returns an empty (but well-formed) `SessionAudit`.
pub(super) async fn get_session_audit(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !crate::agentgraph_kinds::observe_enabled() {
        return problem_response(
            StatusCode::NOT_IMPLEMENTED,
            "observe surface disabled (set CORECRUXD_OBSERVE=1)",
        );
    }
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
    let audit = crux_observe_api::SessionAudit {
        session_id: id,
        contract_version: crux_observe_api::CONTRACT_VERSION,
        steps: vec![],
    };
    (StatusCode::OK, Json(audit)).into_response()
}
