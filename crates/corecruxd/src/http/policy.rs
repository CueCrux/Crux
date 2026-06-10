// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `GET /v1/policy/capabilities` — the canonical tool tier/capability policy
//! (B3). The single source the gateway and daemon authorize against, so the
//! gateway fetches it instead of hard-coding a ladder that can drift from the
//! daemon's `resolve_principal` capability tokens.

use super::{require_http_any_scope, AppState, HeaderMap, IntoResponse, Json, State, StatusCode};

/// Return the canonical tool-capability policy document
/// (`crate::policy::policy_document`). Non-sensitive, but gated behind a low
/// read scope so it isn't world-readable on an authenticated daemon.
pub(super) async fn get_policy_capabilities(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["query:read", "facts:read", "admin:read"]) {
        return p.into_response();
    }
    (StatusCode::OK, Json(crate::policy::policy_document())).into_response()
}
