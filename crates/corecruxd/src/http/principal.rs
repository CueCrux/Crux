// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `GET /v1/principal/resolve` — read-only principal resolution for an external
//! mediator (the MCP gateway). Authenticated (T.3); tenant-scoped (T.1): the
//! caller may only resolve a principal whose tenant it is allowed.

use super::{
    http_scope_context, problem_response, require_http_any_scope, require_http_any_scope_for_tenant, AppState,
    HeaderMap, HeaderName, HeaderValue, IntoResponse, Json, Query, Response, State, StatusCode,
};
use corecrux_memory::candidate_link::CandidateLinkStatus;

#[derive(Debug, serde::Deserialize)]
pub(super) struct ResolvePrincipalQuery {
    pub session_id: Option<String>,
    pub passport_id: Option<String>,
    /// Accepts `1`, `true`, `yes`, or `on`. Suggestions are read-only and
    /// never make a `candidate_link` resolving.
    pub include_candidates: Option<String>,
}

/// Resolve the principal for a `session_id` or `passport_id`, or — when neither
/// is supplied — the authenticated caller's own bound passport. Returns
/// `{passport_id, category, tier, tier_rank, capabilities[], tenant_id,
/// agent_work_gate, resolved_via}` so a mediator can authorize and attribute
/// tool calls against the real identity.
#[tracing::instrument(level = "info", skip_all)]
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
    let mut federation_decision: Option<crux_router::RouterDecision> = None;
    let resolved = if let Some(sid) = query.session_id.as_deref().filter(|s| !s.is_empty()) {
        crate::principal::resolve_by_session(&store, sid)
    } else if let Some(pid) = query.passport_id.as_deref().filter(|s| !s.is_empty()) {
        match crate::principal::resolve_by_passport(&store, pid, None) {
            // G4b federation fallback (CORECRUXD_IDENTITY_LINKS): an unknown
            // passport id may be a *linked* remote fingerprint. Resolution
            // first consumes the RCX `federation.read` grant, then returns the
            // linked local passport capped to that grant's memory-read subset.
            // Unlinked and revoked fingerprints fall through to the same 404
            // as before the feature.
            Err(crate::principal::ResolveError::PassportNotFound(_)) if state.identity_links_enabled => {
                let entities = state.entity_store.read().await;
                if crate::identity_links::find_live_link_for_remote(&entities, pid).is_some() {
                    if let Some(decision) = federation_read_decision(&state) {
                        if !decision.authorised {
                            drop(store);
                            return rcx_refusal_response(&decision);
                        }
                        federation_decision = Some(decision);
                    }
                }
                crate::principal::resolve_by_linked_passport(&store, &entities, pid)
            }
            direct => direct,
        }
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
            let response = if query_include_candidates(&query) && state.identity_links_enabled {
                let mut body = match serde_json::to_value(&principal) {
                    Ok(body) => body,
                    Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
                };
                let entities = state.entity_store.read().await;
                let candidates = candidate_suggestions_for_query(&entities, &query);
                if let Some(obj) = body.as_object_mut() {
                    obj.insert("candidates".to_string(), serde_json::Value::Array(candidates));
                    obj.insert("candidates_resolve".to_string(), serde_json::Value::Bool(false));
                }
                (StatusCode::OK, Json(body)).into_response()
            } else {
                (StatusCode::OK, Json(principal)).into_response()
            };
            response_with_rcx_mode(response, federation_decision.as_ref())
        }
        Err(crate::principal::ResolveError::BindingNotFound(_)) => {
            unresolved_with_candidate_suggestions(
                &state,
                &headers,
                &query,
                "binding_not_found",
                "no session binding for that session id",
            )
            .await
        }
        Err(crate::principal::ResolveError::PassportNotFound(_)) => {
            unresolved_with_candidate_suggestions(&state, &headers, &query, "passport_not_found", "passport not found")
                .await
        }
    }
}

async fn unresolved_with_candidate_suggestions(
    state: &AppState,
    headers: &HeaderMap,
    query: &ResolvePrincipalQuery,
    error: &str,
    detail: &str,
) -> Response {
    if query_include_candidates(query) && state.identity_links_enabled {
        if let Err(problem) = require_http_any_scope(&state.auth, headers, &["admin:read"]) {
            return problem.into_response();
        }
        let entities = state.entity_store.read().await;
        let candidates = candidate_suggestions_for_query(&entities, query);
        if !candidates.is_empty() {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": error,
                    "detail": detail,
                    "candidates": candidates,
                    "candidates_resolve": false,
                })),
            )
                .into_response();
        }
    }
    problem_response(StatusCode::NOT_FOUND, detail)
}

fn query_include_candidates(query: &ResolvePrincipalQuery) -> bool {
    query
        .include_candidates
        .as_deref()
        .map(str::trim)
        .is_some_and(|raw| matches!(raw.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
}

fn candidate_suggestions_for_query(
    entities: &corecrux_memory::EntityStore,
    query: &ResolvePrincipalQuery,
) -> Vec<serde_json::Value> {
    let subject = query
        .passport_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .or_else(|| query.session_id.as_deref().filter(|s| !s.is_empty()));
    let Some(subject) = subject else {
        return Vec::new();
    };
    let mut candidates: Vec<serde_json::Value> =
        crate::candidate_links::list_candidates_for_subject(entities, subject, Some(CandidateLinkStatus::Proposed))
            .into_iter()
            .map(|(candidate_id, candidate)| {
                serde_json::json!({
                    "candidate_id": candidate_id,
                    "candidate": candidate,
                    "action_required": "confirm_candidate",
                    "resolving": false,
                })
            })
            .collect();
    candidates.sort_by(|a, b| {
        a["candidate"]["proposed_at"]
            .as_str()
            .unwrap_or_default()
            .cmp(b["candidate"]["proposed_at"].as_str().unwrap_or_default())
            .then_with(|| {
                a["candidate_id"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(b["candidate_id"].as_str().unwrap_or_default())
            })
    });
    candidates
}

fn federation_read_decision(state: &AppState) -> Option<crux_router::RouterDecision> {
    state.rcx_router.as_ref().map(|router| {
        router.decide(
            &crux_router::CallContext::local(crate::policy::FEDERATION_READ_CAPABILITY),
            current_unix_seconds(),
        )
    })
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn rcx_refusal_response(decision: &crux_router::RouterDecision) -> Response {
    let refusal_receipt = decision.refusal_receipt.as_ref().map(|receipt| {
        serde_json::json!({
            "event_type": &receipt.event_type,
            "token_id": &receipt.token_id,
            "token_hash": &receipt.token_hash,
            "capability": &receipt.capability,
            "backend_id": &receipt.backend_id,
            "data_egress_classes": &receipt.data_egress_classes,
            "required_attestations": &receipt.required_attestations,
            "present_attestations": &receipt.present_attestations,
            "reason_code": &receipt.reason_code,
            "receipt_class": &receipt.receipt_class,
        })
    });
    response_with_rcx_mode(
        (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": "rcx_capability_denied",
                "reason_code": decision.reason_code,
                "mode": decision.mode.as_str(),
                "token_id": decision.token_id,
                "token_hash": decision.token_hash,
                "refusal_receipt": refusal_receipt,
            })),
        )
            .into_response(),
        Some(decision),
    )
}

fn response_with_rcx_mode(mut response: Response, decision: Option<&crux_router::RouterDecision>) -> Response {
    if let Some(decision) = decision {
        if let Ok(value) = HeaderValue::from_str(&decision.stamp.mode) {
            response
                .headers_mut()
                .insert(HeaderName::from_static("x-crux-mode"), value);
        }
    }
    response
}
