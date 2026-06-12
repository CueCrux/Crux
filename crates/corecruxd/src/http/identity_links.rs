// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `/v1/identity/links` — identity-federation link CRUD (G4b, ExecPlan
//! `identity-memory-portability-2026-06-11` M5). Behind
//! `CORECRUXD_IDENTITY_LINKS=1`; 404 when off (the `/v1/context` gate
//! pattern). Operator surface: link creation and revocation are explicit
//! Art. 14 actions, so they require `admin:write`; listing requires
//! `admin:read`.

use super::{
    http_scope_context, problem_response, require_http_any_scope, AppState, HeaderMap, IntoResponse, Json, Path,
    Response, State, StatusCode,
};
use crate::identity_links::{self, CreateLinkRequest, LinkError};
use corecrux_memory::identity_link::LinkVerifyError;

fn links_disabled() -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        "identity links disabled (set CORECRUXD_IDENTITY_LINKS=1)",
    )
    .into_response()
}

fn link_error_response(err: &LinkError) -> Response {
    let status = match err {
        LinkError::LocalPassportNotFound(_) | LinkError::LinkNotFound(_) => StatusCode::NOT_FOUND,
        LinkError::AlreadyExists(_) => StatusCode::CONFLICT,
        LinkError::Verify(LinkVerifyError::BadSignature(_) | LinkVerifyError::FingerprintMismatch { .. }) => {
            StatusCode::FORBIDDEN
        }
        LinkError::Verify(_) => StatusCode::BAD_REQUEST,
        LinkError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    problem_response(status, err.to_string()).into_response()
}

/// Actor string for the audit trail: the caller's bound passport when
/// present, otherwise the operator marker (QC.3 — no silently-anonymous
/// writes).
fn actor_for(ctx: &crate::auth::HttpScopeContext) -> String {
    ctx.passport_id.clone().unwrap_or_else(|| "operator:admin".to_string())
}

#[utoipa::path(
    post,
    path = "/v1/identity/links",
    tag = "Identity",
    request_body = CreateLinkRequest,
    responses(
        (status = 201, description = "Link created (both signatures verified)"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Signature or fingerprint verification failed"),
        (status = 404, description = "Disabled, or local passport not found"),
        (status = 409, description = "Identical live link already exists"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn post_identity_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateLinkRequest>,
) -> Response {
    if !state.identity_links_enabled {
        return links_disabled();
    }
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let ctx = match http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };

    let facts = state.fact_store.read().await;
    let mut entities = state.entity_store.write().await;
    match identity_links::create_link(&mut entities, &facts, &body, &actor_for(&ctx)) {
        Ok((link_id, payload)) => {
            tracing::info!(
                link_id,
                local_fpr = %payload.local_fpr,
                remote_fpr = %payload.remote_fpr,
                "identity-link-created"
            );
            (
                StatusCode::CREATED,
                Json(serde_json::json!({"link_id": link_id, "link": payload})),
            )
                .into_response()
        }
        Err(err) => link_error_response(&err),
    }
}

#[utoipa::path(
    get,
    path = "/v1/identity/links",
    tag = "Identity",
    responses(
        (status = 200, description = "All link records (live + revoked)"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Disabled"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn get_identity_links(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !state.identity_links_enabled {
        return links_disabled();
    }
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["admin:read", "admin:write"]) {
        return problem.into_response();
    }
    let entities = state.entity_store.read().await;
    let links: Vec<serde_json::Value> = identity_links::list_links(&entities)
        .into_iter()
        .map(|(link_id, payload)| serde_json::json!({"link_id": link_id, "link": payload}))
        .collect();
    (StatusCode::OK, Json(serde_json::json!({"links": links}))).into_response()
}

#[utoipa::path(
    post,
    path = "/v1/identity/links/{linkId}/revoke",
    tag = "Identity",
    params(("linkId" = String, Path, description = "Link identifier (il_…)")),
    responses(
        (status = 200, description = "Link revoked (idempotent)"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Disabled or link not found"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn post_identity_link_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(link_id): Path<String>,
) -> Response {
    if !state.identity_links_enabled {
        return links_disabled();
    }
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let ctx = match http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };
    let mut entities = state.entity_store.write().await;
    match identity_links::revoke_link(&mut entities, &link_id, &actor_for(&ctx)) {
        Ok(payload) => {
            tracing::info!(link_id, remote_fpr = %payload.remote_fpr, "identity-link-revoked");
            (
                StatusCode::OK,
                Json(serde_json::json!({"link_id": link_id, "link": payload})),
            )
                .into_response()
        }
        Err(err) => link_error_response(&err),
    }
}
