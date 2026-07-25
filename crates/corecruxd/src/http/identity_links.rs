// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `/v1/identity/links` — identity-federation link CRUD (G4b, ExecPlan
//! `identity-memory-portability-2026-06-11` M5). Behind
//! `CORECRUXD_IDENTITY_LINKS=1`; 404 when off (the `/v1/context` gate
//! pattern). Operator surface: link creation and revocation are explicit
//! Art. 14 actions, so they require `admin:write`; listing requires
//! `admin:read`.

use super::{
    http_scope_context, problem_response, require_http_any_scope, AppState, HeaderMap, IntoResponse, Json, Path, Query,
    Response, State, StatusCode,
};
use crate::candidate_links::{self, CandidateLinkError, CandidateObservation, ProposerConfig};
use crate::identity_links::{self, CreateLinkRequest, LinkError};
use corecrux_memory::candidate_link::CandidateLinkStatus;
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

fn candidate_error_response(err: &CandidateLinkError) -> Response {
    match err {
        CandidateLinkError::Link(link) => link_error_response(link),
        CandidateLinkError::LocalPassportNotFound(_) | CandidateLinkError::NotFound(_) => {
            problem_response(StatusCode::NOT_FOUND, err.to_string()).into_response()
        }
        CandidateLinkError::AlreadyExists(_) => problem_response(StatusCode::CONFLICT, err.to_string()).into_response(),
        CandidateLinkError::Invalid(_) => problem_response(StatusCode::BAD_REQUEST, err.to_string()).into_response(),
        CandidateLinkError::Store(_) => {
            problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response()
        }
    }
}

/// Actor string for the audit trail: the caller's bound passport when
/// present, otherwise the operator marker (QC.3 — no silently-anonymous
/// writes).
fn actor_for(ctx: &crate::auth::HttpScopeContext) -> String {
    ctx.passport_id.clone().unwrap_or_else(|| "operator:admin".to_string())
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ListIdentityCandidatesQuery {
    /// `proposed`, `confirmed`, `rejected`, or `all` (default).
    #[serde(default)]
    pub status: Option<String>,
}

fn parse_candidate_status(raw: Option<&str>) -> Result<Option<CandidateLinkStatus>, String> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None | Some("all") => Ok(None),
        Some("proposed") => Ok(Some(CandidateLinkStatus::Proposed)),
        Some("confirmed") => Ok(Some(CandidateLinkStatus::Confirmed)),
        Some("rejected") => Ok(Some(CandidateLinkStatus::Rejected)),
        Some(other) => Err(format!(
            "status must be proposed, confirmed, rejected, or all; got '{other}'"
        )),
    }
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
    path = "/v1/identity/candidates",
    tag = "Identity",
    params(("status" = Option<String>, Query, description = "Candidate status filter: proposed, confirmed, rejected, or all")),
    responses(
        (status = 200, description = "Candidate records, non-resolving unless confirmed as identity links"),
        (status = 400, description = "Invalid status filter"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing admin read scope"),
        (status = 404, description = "Disabled"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn get_identity_candidates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ListIdentityCandidatesQuery>,
) -> Response {
    if !state.identity_links_enabled {
        return links_disabled();
    }
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["admin:read", "admin:write"]) {
        return problem.into_response();
    }
    let status = match parse_candidate_status(query.status.as_deref()) {
        Ok(status) => status,
        Err(message) => return problem_response(StatusCode::BAD_REQUEST, message).into_response(),
    };
    let entities = state.entity_store.read().await;
    let mut candidates: Vec<serde_json::Value> = candidate_links::list_candidates(&entities, status)
        .into_iter()
        .map(|(candidate_id, candidate)| serde_json::json!({"candidate_id": candidate_id, "candidate": candidate}))
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
    (StatusCode::OK, Json(serde_json::json!({"candidates": candidates}))).into_response()
}

/// Upper bound on candidate observations returned from the journals. The
/// proposer is O(n²) over its input, so this caps the cost even against a
/// pathologically multi-principal corpus (the CE mirror already carries ~140k
/// observation records across ~39k sessions).
const MAX_JOURNAL_CANDIDATE_OBSERVATIONS: usize = 4000;

/// Build candidate observations from the on-disk observation journals — the
/// second evidence source ("observation principals", Part C.7). Recon proved the
/// candidate proposers have no shipped caller, so the propose route is the
/// deliberate seed path. `local_passport_fpr` is the daemon's first local
/// passport (validated by `create_candidate`); `observed_subject` is the
/// record's signing principal; `project_id` is the session id.
///
/// The proposer only fires for two *distinct* principals sharing a `project_id`
/// (session) inside the temporal window, so this deduplicates to one observation
/// per `(session, principal)` and DROPS single-principal sessions entirely —
/// they can never yield a cross-principal candidate. That collapses the 140k-row
/// journal to the handful of genuinely multi-signer sessions, keeping the
/// proposer's O(n²) tractable (cross-session pairs never fire — distinct
/// `project_id` — so dropping them changes no output). Read lock-free (no store
/// locks held); returns empty when there is no local anchor.
fn journal_candidate_observations(data_dir: &std::path::Path, anchor: &str) -> Vec<CandidateObservation> {
    let records = match super::observations::read_all_observations(data_dir) {
        Ok(records) => records,
        Err(err) => {
            tracing::warn!(target = "identity", error = %err, "reading observation journals for candidate seeding");
            return Vec::new();
        }
    };
    // session_id -> (principal -> earliest observation for that principal).
    let mut by_session: std::collections::BTreeMap<String, std::collections::BTreeMap<String, CandidateObservation>> =
        Default::default();
    for record in records {
        let principals = by_session.entry(record.session_id.clone()).or_default();
        principals
            .entry(record.principal.clone())
            .or_insert_with(|| CandidateObservation {
                local_passport_fpr: anchor.to_string(),
                observed_subject: record.principal.clone(),
                tenant_id: "local".to_string(),
                project_id: Some(record.session_id.clone()),
                observed_at_unix_ms: record.ts.timestamp_millis().max(0) as u64,
                evidence_ref: format!("observation:{}", record.observation_id),
                cruxpack_source_receipt: None,
            });
    }
    let mut out = Vec::new();
    for (_session, principals) in by_session {
        if principals.len() < 2 {
            continue; // single-signer session — no cross-principal candidate possible
        }
        for observation in principals.into_values() {
            out.push(observation);
            if out.len() >= MAX_JOURNAL_CANDIDATE_OBSERVATIONS {
                return out;
            }
        }
    }
    out
}

/// `POST /v1/identity/candidates/propose` — run the (previously uncalled)
/// candidate proposers so a fresh workspace can populate
/// `GET /v1/identity/candidates`. Deliberate write: it is the ONLY shipped
/// producer of candidate-link records (see the module + `docs/agent/
/// identity-candidate-links.md`). Idempotent — `create_candidate` dedups by a
/// content-derived id, so re-proposing over the same evidence creates nothing.
/// Two evidence sources: `bindings` (session→passport bindings) and
/// `observations` (observation-journal principals). `admin:write`, and 404 when
/// `CORECRUXD_IDENTITY_LINKS` is off (same posture as the rest of the group).
#[utoipa::path(
    post,
    path = "/v1/identity/candidates/propose",
    tag = "Identity",
    responses(
        (status = 200, description = "Proposers run; counts of created + examined candidate observations by source"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Missing admin write scope"),
        (status = 404, description = "Disabled"),
        (status = 500, description = "Local passport lookup failed for a proposed candidate"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn post_identity_candidates_propose(State(state): State<AppState>, headers: HeaderMap) -> Response {
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
    let actor = actor_for(&ctx);
    let config = ProposerConfig::default();

    // Gather the binding-source observations and the local anchor under a brief
    // read lock, then release it — the journal scan below is slow (tens of
    // thousands of files) and must NOT hold the fact/entity store locks.
    let (binding_obs, anchor) = {
        let facts = state.fact_store.read().await;
        let binding_obs = candidate_links::observations_from_session_bindings(&facts);
        let anchor = crate::passports::list_passports(&facts, None)
            .into_iter()
            .map(|passport| passport.principal_id)
            .next();
        (binding_obs, anchor)
    };

    // Source 2 read: scan the observation journals lock-free on a blocking task
    // (140k+ records across ~39k files on the mirror).
    let journal_obs = match anchor {
        Some(anchor) => {
            let data_dir = state.data_dir.clone();
            match tokio::task::spawn_blocking(move || journal_candidate_observations(&data_dir, &anchor)).await {
                Ok(obs) => obs,
                Err(err) => {
                    tracing::warn!(target = "identity", error = %err, "journal scan task failed");
                    Vec::new()
                }
            }
        }
        None => Vec::new(),
    };

    let examined_bindings = binding_obs.len();
    let examined_observations = journal_obs.len();

    // Propose under the store locks — both proposers are now over small inputs.
    let facts = state.fact_store.read().await;
    let mut entities = state.entity_store.write().await;
    let created_bindings =
        match candidate_links::propose_from_observations(&mut entities, &facts, &binding_obs, &actor, &config) {
            Ok(created) => created.len(),
            Err(err) => return candidate_error_response(&err),
        };
    let created_observations =
        match candidate_links::propose_from_observations(&mut entities, &facts, &journal_obs, &actor, &config) {
            Ok(created) => created.len(),
            Err(err) => return candidate_error_response(&err),
        };
    drop(entities);
    drop(facts);

    tracing::info!(
        created_bindings,
        created_observations,
        examined_bindings,
        examined_observations,
        "identity-candidates-proposed"
    );
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "created": created_bindings + created_observations,
            "examined": examined_bindings + examined_observations,
            "by_source": {
                "bindings": { "created": created_bindings, "examined": examined_bindings },
                "observations": { "created": created_observations, "examined": examined_observations },
            },
        })),
    )
        .into_response()
}

#[utoipa::path(
    post,
    path = "/v1/identity/candidates/{candidateId}/confirm",
    tag = "Identity",
    params(("candidateId" = String, Path, description = "Candidate identifier (cl_…)")),
    request_body = CreateLinkRequest,
    responses(
        (status = 201, description = "Candidate confirmed by creating a cross-signed identity link"),
        (status = 400, description = "Candidate and link proof do not match"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Signature or fingerprint verification failed"),
        (status = 404, description = "Disabled, candidate not found, or local passport not found"),
        (status = 409, description = "Identical live link already exists"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn post_identity_candidate_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(candidate_id): Path<String>,
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
    match candidate_links::confirm_candidate_with_link(&mut entities, &facts, &candidate_id, &body, &actor_for(&ctx)) {
        Ok((link_id, link, candidate)) => {
            tracing::info!(
                candidate_id,
                link_id,
                remote_fpr = %link.remote_fpr,
                "identity-candidate-confirmed"
            );
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "candidate_id": candidate_id,
                    "candidate": candidate,
                    "link_id": link_id,
                    "link": link,
                })),
            )
                .into_response()
        }
        Err(err) => candidate_error_response(&err),
    }
}

#[utoipa::path(
    post,
    path = "/v1/identity/candidates/{candidateId}/reject",
    tag = "Identity",
    params(("candidateId" = String, Path, description = "Candidate identifier (cl_…)")),
    responses(
        (status = 200, description = "Candidate rejected without deleting its audit trail"),
        (status = 400, description = "Confirmed candidates cannot be rejected"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Disabled or candidate not found"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn post_identity_candidate_reject(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(candidate_id): Path<String>,
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
    match candidate_links::reject_candidate(&mut entities, &candidate_id, &actor_for(&ctx)) {
        Ok(candidate) => {
            tracing::info!(candidate_id, "identity-candidate-rejected");
            (
                StatusCode::OK,
                Json(serde_json::json!({"candidate_id": candidate_id, "candidate": candidate})),
            )
                .into_response()
        }
        Err(err) => candidate_error_response(&err),
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
