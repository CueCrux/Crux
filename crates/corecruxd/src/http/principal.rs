// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `GET /v1/principal/resolve` — read-only principal resolution for an external
//! mediator (the MCP gateway). Authenticated (T.3); tenant-scoped (T.1): the
//! caller may only resolve a principal whose tenant it is allowed.

use super::{
    http_scope_context, problem_response, require_http_any_scope_for_tenant, AppState, HeaderMap, IntoResponse, Json,
    Query, State, StatusCode,
};

#[derive(Debug, serde::Deserialize)]
pub(super) struct ResolvePrincipalQuery {
    pub session_id: Option<String>,
    pub passport_id: Option<String>,
}

/// Resolve the principal for a `session_id` or `passport_id`, or — when neither
/// is supplied — the authenticated caller's own bound passport. Returns
/// `{passport_id, category, tier, tier_rank, capabilities[], tenant_id,
/// agent_work_gate, resolved_via}` so a mediator can authorize and attribute
/// tool calls against the real identity.
pub(super) async fn get_resolve_principal(
    State(state): State<AppState>,
    Query(query): Query<ResolvePrincipalQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // T.3: the caller must be authenticated. `http_scope_context` rejects an
    // unauthenticated caller (unless auth mode is Off) and yields the caller's
    // own bound passport id for the "resolve me" path.
    let ctx = match http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };

    let store = state.fact_store.read().await;
    let resolved = if let Some(sid) = query.session_id.as_deref().filter(|s| !s.is_empty()) {
        crate::principal::resolve_by_session(&store, sid)
    } else if let Some(pid) = query.passport_id.as_deref().filter(|s| !s.is_empty()) {
        crate::principal::resolve_by_passport(&store, pid, None)
    } else if let Some(pid) = ctx.passport_id.as_deref() {
        // "resolve me" — the caller's own bound passport.
        crate::principal::resolve_by_passport(&store, pid, None)
    } else {
        drop(store);
        return problem_response(
            StatusCode::BAD_REQUEST,
            "provide session_id or passport_id, or authenticate with a bound passport",
        );
    };
    drop(store);

    match resolved {
        Ok(principal) => {
            // T.1: the caller must be allowed the *resolved* tenant. Mirrors the
            // `/v1/sessions/active` scope set; an `admin:*` scope bypasses tenant
            // scoping (operator/loopback), while a `sessions:read` caller is held
            // to its own tenant claim — so it cannot resolve another tenant's
            // passport.
            if let Err(problem) = require_http_any_scope_for_tenant(
                &state.auth,
                &headers,
                &["sessions:read", "admin:read"],
                &principal.tenant_id,
            ) {
                return problem.into_response();
            }
            (StatusCode::OK, Json(principal)).into_response()
        }
        Err(crate::principal::ResolveError::BindingNotFound(_)) => {
            problem_response(StatusCode::NOT_FOUND, "no session binding for that session id")
        }
        Err(crate::principal::ResolveError::PassportNotFound(_)) => {
            problem_response(StatusCode::NOT_FOUND, "passport not found")
        }
    }
}
