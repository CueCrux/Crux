// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP fact-store routes — `/v1/facts` CRUD + bulk-write + export + per-entity listing.

use super::*;

const MAX_FACT_QUERY_TOP_K: usize = 100;

/// Query parameters for the GET /v1/facts endpoint.
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub(super) struct QueryFactsParams {
    /// Free-text BM25 query over fact values.
    pub query: Option<String>,
    /// Exact entity match.
    pub entity: Option<String>,
    /// Entity prefix filter (e.g. `__ops__::`)
    pub entity_prefix: Option<String>,
    /// Maximum number of results to return (default 10).
    pub top_k: Option<usize>,
    /// Token budget — fill results by descending score until exhausted.
    pub token_budget: Option<usize>,
    /// Bi-temporal as-of filter (RFC 3339). When set, only facts whose
    /// valid-time interval `[valid_from, valid_to)` contains this instant are
    /// returned — i.e. facts that were TRUE IN THE WORLD at `as_of`, regardless
    /// of when they were learned. Omitted ⇒ no valid-time filtering.
    pub as_of: Option<String>,
}

/// Query parameters for the GET /v1/facts/export endpoint.
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub(super) struct ExportFactsParams {
    /// Only include facts stored after this RFC 3339 timestamp.
    pub since: Option<String>,
    /// Cursor for pagination (from previous response).
    pub cursor: Option<String>,
    /// Maximum number of facts to return (default 1000, max 10000).
    pub limit: Option<u32>,
}

// `axum::response::Response` is large by clippy's reckoning, but
// returning it as the Err arm is the idiomatic axum pattern; suppress
// the lint at the helper boundary.
#[allow(clippy::result_large_err)]
pub(super) fn require_fact_read_ctx(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<crate::auth::HttpScopeContext, Response> {
    require_http_any_scope(&state.auth, headers, &["query:read", "admin:read"]).map_err(IntoResponse::into_response)?;
    http_scope_context(&state.auth, headers).map_err(IntoResponse::into_response)
}

#[allow(clippy::result_large_err)]
fn require_fact_write_ctx(state: &AppState, headers: &HeaderMap) -> Result<crate::auth::HttpScopeContext, Response> {
    require_http_any_scope(&state.auth, headers, &["facts:write", "admin:write"])
        .map_err(IntoResponse::into_response)?;
    http_scope_context(&state.auth, headers).map_err(IntoResponse::into_response)
}

#[allow(clippy::result_large_err)]
pub(super) fn require_session_write_ctx(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<crate::auth::HttpScopeContext, Response> {
    require_http_any_scope(&state.auth, headers, &["sessions:write", "admin:write"])
        .map_err(IntoResponse::into_response)?;
    http_scope_context(&state.auth, headers).map_err(IntoResponse::into_response)
}

fn raw_admin_read(ctx: &crate::auth::HttpScopeContext) -> bool {
    ctx.passport_id.is_none() && ctx.has_scope("admin:read")
}

fn raw_admin_write(ctx: &crate::auth::HttpScopeContext) -> bool {
    ctx.passport_id.is_none() && ctx.has_scope("admin:write")
}

/// Resolve the trusted tenant stamp for an HTTP write.
///
/// HTTP auth context has no tenant claim yet, so current deployments resolve to
/// `default`. When a real tenant source is added here, three other surfaces must
/// be revisited in the SAME change or they become a stamping/read bypass (tracked
/// as security-critical-7-tenant-isolation C5 follow-ups):
///
/// - `FactStore::store_synced` (sync-pull) inserts a peer-supplied `Fact` verbatim, so a peer-controlled `tenant_hash` would survive — validate or re-stamp it.
/// - The unfiltered read helpers (`all_facts`, `get`, `get_by_entity`, `fact_history`, export) do not apply the tenant filter — no-op while everything is `default`, but they must gain a tenant predicate.
/// - MCP `handle_store_fact`'s equivalent write hook.
fn tenant_hash_for_write_context(_ctx: &crate::auth::HttpScopeContext) -> String {
    corecrux_memory::fact_store::default_tenant_hash()
}

fn render_fact_for_http(
    fact: &corecrux_memory::fact_store::Fact,
    ctx: &crate::auth::HttpScopeContext,
) -> Option<corecrux_memory::fact_store::Fact> {
    if raw_admin_read(ctx) || raw_admin_write(ctx) {
        return Some(fact.clone());
    }
    let entity = crux_mcp::scope::visible_entity_for_agent(fact, ctx.passport_id.as_deref())?;
    let mut out = fact.clone();
    out.entity = entity;
    Some(out)
}

fn fact_visible_for_http_write(fact: &corecrux_memory::fact_store::Fact, ctx: &crate::auth::HttpScopeContext) -> bool {
    raw_admin_write(ctx) || crux_mcp::scope::fact_visible_to_agent(fact, ctx.passport_id.as_deref())
}

#[allow(clippy::result_large_err)]
fn prepare_fact_write_checked(
    state: &AppState,
    store: &corecrux_memory::FactStore,
    ctx: &crate::auth::HttpScopeContext,
    mut fact: corecrux_memory::fact_store::StoreFact,
) -> Result<corecrux_memory::fact_store::StoreFact, Response> {
    // Never trust a client-supplied tenant stamp; derive it from auth context.
    fact.tenant_hash = tenant_hash_for_write_context(ctx);
    if fact.private {
        return Err(problem_response(
            StatusCode::BAD_REQUEST,
            "private facts require MCP agent identity; HTTP /v1/facts does not support private=true",
        ));
    }
    crate::fact_privacy::enforce(&state.privacy_policy, &mut fact);
    if let Err(e) =
        crux_mcp::category_enforce::check_passport_can_write_entity(store, ctx.passport_id.as_deref(), &fact.entity)
    {
        return Err(problem_response(StatusCode::FORBIDDEN, e.to_string()));
    }
    Ok(fact)
}

#[allow(clippy::result_large_err)]
fn try_store_fact_checked(
    state: &AppState,
    store: &mut corecrux_memory::FactStore,
    ctx: &crate::auth::HttpScopeContext,
    fact: corecrux_memory::fact_store::StoreFact,
) -> Result<corecrux_memory::fact_store::Fact, Response> {
    let fact = prepare_fact_write_checked(state, store, ctx, fact)?;
    store
        .try_store(fact)
        .map_err(|err| problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))
}

fn fact_matches_query(fact: &corecrux_memory::fact_store::Fact, query: &str, agent_name: Option<&str>) -> bool {
    let query_lower = query.to_lowercase();
    let terms: Vec<&str> = query_lower.split_whitespace().collect();
    let value_lower = fact.value.to_lowercase();
    let key_lower = fact.key.to_lowercase();
    let entity_lower = crux_mcp::scope::visible_entity_for_agent(fact, agent_name)
        .unwrap_or_else(|| fact.entity.clone())
        .to_lowercase();

    terms
        .iter()
        .any(|term| value_lower.contains(term) || key_lower.contains(term) || entity_lower.contains(term))
}

pub(super) fn query_visible_http_facts(
    store: &corecrux_memory::FactStore,
    q: &corecrux_memory::fact_store::FactQuery,
    ctx: &crate::auth::HttpScopeContext,
) -> Vec<corecrux_memory::fact_store::Fact> {
    query_visible_http_facts_as_of(store, q, ctx, None)
}

/// As [`query_visible_http_facts`] but with an optional bi-temporal `as_of`
/// filter (M1): when set, only facts whose valid-time interval contains the
/// instant are returned. `None` ⇒ identical to the plain variant.
pub(super) fn query_visible_http_facts_as_of(
    store: &corecrux_memory::FactStore,
    q: &corecrux_memory::fact_store::FactQuery,
    ctx: &crate::auth::HttpScopeContext,
    as_of: Option<chrono::DateTime<chrono::Utc>>,
) -> Vec<corecrux_memory::fact_store::Fact> {
    if raw_admin_read(ctx) {
        return match as_of {
            Some(instant) => store.query_as_of(q, instant).facts,
            None => store.query(q).facts,
        };
    }

    let agent_name = ctx.passport_id.as_deref();
    let mut results: Vec<&corecrux_memory::fact_store::Fact> = store
        .all_facts()
        .filter(|fact| !fact.deleted)
        .filter(|fact| as_of.is_none_or(|instant| fact.valid_at(instant)))
        .filter(|fact| crux_mcp::scope::fact_visible_to_agent(fact, agent_name))
        .filter(|fact| q.tenant_hash.as_ref().is_none_or(|tenant| fact.tenant_hash == *tenant))
        .filter(|fact| {
            q.entity_prefix
                .as_ref()
                .is_none_or(|prefix| crux_mcp::scope::entity_prefix_matches_for_agent(fact, prefix, agent_name))
        })
        .filter(|fact| {
            q.entity
                .as_ref()
                .is_none_or(|entity| crux_mcp::scope::entity_matches_for_agent(fact, entity, agent_name))
        })
        .filter(|fact| {
            q.query
                .as_ref()
                .is_none_or(|query| fact_matches_query(fact, query, agent_name))
        })
        .collect();

    results.sort_by(|left, right| {
        right
            .confidence
            .partial_cmp(&left.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.stored_at.cmp(&left.stored_at))
    });

    let selected = if let Some(budget) = q.token_budget {
        let mut used = 0usize;
        let mut selected = Vec::new();
        for fact in results {
            if used + fact.tokens > budget && !selected.is_empty() {
                break;
            }
            used += fact.tokens;
            selected.push(fact);
            if used >= budget {
                break;
            }
        }
        selected
    } else {
        results.truncate(q.top_k);
        results
    };

    selected
        .into_iter()
        .filter_map(|fact| render_fact_for_http(fact, ctx))
        .collect()
}

pub(super) fn scoped_session_id_for_http(ctx: &crate::auth::HttpScopeContext, session_id: &str) -> String {
    crux_mcp::scope::scoped_session_id(ctx.passport_id.as_deref(), session_id)
}

fn render_session_for_http(
    session: &corecrux_memory::session_store::SessionState,
    ctx: &crate::auth::HttpScopeContext,
) -> Option<corecrux_memory::session_store::SessionState> {
    if raw_admin_read(ctx) || raw_admin_write(ctx) {
        return Some(session.clone());
    }
    let visible_id = crux_mcp::scope::visible_session_for_agent(&session.session_id, ctx.passport_id.as_deref())?;
    let mut out = session.clone();
    out.session_id = visible_id;
    Some(out)
}

#[utoipa::path(
    put,
    path = "/v1/facts",
    tag = "Facts",
    request_body = corecrux_memory::fact_store::StoreFact,
    responses(
        (status = 201, description = "Fact created", body = corecrux_memory::fact_store::Fact),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn put_fact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<corecrux_memory::fact_store::StoreFact>,
) -> impl IntoResponse {
    let ctx = match require_fact_write_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let mut store = state.fact_store.write().await;
    let fact = match try_store_fact_checked(&state, &mut store, &ctx, body) {
        Ok(fact) => fact,
        Err(response) => return response,
    };
    (StatusCode::CREATED, axum::Json(serde_json::json!(fact))).into_response()
}

#[utoipa::path(
    put,
    path = "/v1/facts/bulk",
    tag = "Facts",
    request_body = Vec<corecrux_memory::fact_store::StoreFact>,
    responses(
        (status = 201, description = "Facts created"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn put_facts_bulk(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Vec<corecrux_memory::fact_store::StoreFact>>,
) -> impl IntoResponse {
    let ctx = match require_fact_write_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    if body.iter().any(|fact| fact.private) {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "private facts require MCP agent identity; HTTP /v1/facts/bulk does not support private=true",
        );
    }
    let mut store = state.fact_store.write().await;
    let mut checked = Vec::with_capacity(body.len());
    for fact in body {
        match prepare_fact_write_checked(&state, &store, &ctx, fact) {
            Ok(fact) => checked.push(fact),
            Err(response) => return response,
        }
    }
    let facts = match store.try_store_bulk(checked) {
        Ok(facts) => facts,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    (StatusCode::CREATED, axum::Json(serde_json::json!({"facts": facts}))).into_response()
}

#[utoipa::path(
    get,
    path = "/v1/facts/{factId}",
    tag = "Facts",
    params(("factId" = String, Path, description = "Fact identifier")),
    responses(
        (status = 200, description = "Fact found", body = corecrux_memory::fact_store::Fact),
        (status = 404, description = "Fact not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn get_fact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(fact_id): Path<String>,
) -> impl IntoResponse {
    let ctx = match require_fact_read_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let store = state.fact_store.read().await;
    match store.get(&fact_id).and_then(|fact| render_fact_for_http(fact, &ctx)) {
        Some(fact) => (StatusCode::OK, axum::Json(serde_json::json!(fact))).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, format!("fact '{}' not found", fact_id)),
    }
}

#[utoipa::path(
    delete,
    path = "/v1/facts/{factId}",
    tag = "Facts",
    params(("factId" = String, Path, description = "Fact identifier")),
    responses(
        (status = 200, description = "Fact deleted"),
        (status = 404, description = "Fact not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn delete_fact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(fact_id): Path<String>,
) -> impl IntoResponse {
    let ctx = match require_fact_write_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let mut store = state.fact_store.write().await;
    let visible = store
        .get(&fact_id)
        .is_some_and(|fact| fact_visible_for_http_write(fact, &ctx));
    let deleted = if visible {
        match store.try_delete(&fact_id) {
            Ok(deleted) => deleted,
            Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        }
    } else {
        false
    };
    if deleted {
        (StatusCode::OK, axum::Json(serde_json::json!({"deleted": true}))).into_response()
    } else {
        problem_response(StatusCode::NOT_FOUND, format!("fact '{}' not found", fact_id))
    }
}

#[utoipa::path(
    get,
    path = "/v1/facts/entity/{entity}",
    tag = "Facts",
    params(("entity" = String, Path, description = "Entity name")),
    responses(
        (status = 200, description = "Facts for entity"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn get_facts_by_entity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(entity): Path<String>,
) -> impl IntoResponse {
    let ctx = match require_fact_read_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let store = state.fact_store.read().await;
    let facts: Vec<_> = if raw_admin_read(&ctx) {
        store.get_by_entity(&entity).into_iter().cloned().collect()
    } else {
        store
            .all_facts()
            .filter(|fact| !fact.deleted)
            .filter(|fact| crux_mcp::scope::entity_matches_for_agent(fact, &entity, ctx.passport_id.as_deref()))
            .filter_map(|fact| render_fact_for_http(fact, &ctx))
            .collect()
    };
    (StatusCode::OK, axum::Json(serde_json::json!({"facts": facts}))).into_response()
}

#[utoipa::path(
    get,
    path = "/v1/facts",
    tag = "Facts",
    params(QueryFactsParams),
    responses(
        (status = 200, description = "Matching facts"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn query_facts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<QueryFactsParams>,
) -> impl IntoResponse {
    let ctx = match require_fact_read_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let q = corecrux_memory::fact_store::FactQuery {
        query: params.query,
        entity: params.entity,
        tenant_hash: None,
        entity_prefix: params.entity_prefix,
        top_k: params.top_k.unwrap_or(10).clamp(1, MAX_FACT_QUERY_TOP_K),
        token_budget: params.token_budget,
    };
    // Bi-temporal as-of (M1): reject an unparseable timestamp rather than
    // silently ignoring it (a silently-dropped filter would return present-day
    // facts under a historical query — a correctness trap for the caller).
    let as_of = match params.as_of.as_deref() {
        Some(raw) => match chrono::DateTime::parse_from_rfc3339(raw) {
            Ok(dt) => Some(dt.with_timezone(&chrono::Utc)),
            Err(_) => {
                return problem_response(
                    StatusCode::BAD_REQUEST,
                    "as_of must be an RFC 3339 timestamp (e.g. 2026-01-15T00:00:00Z)",
                );
            }
        },
        None => None,
    };
    let store = state.fact_store.read().await;
    let facts = query_visible_http_facts_as_of(&store, &q, &ctx, as_of);
    let total_tokens = facts.iter().map(|fact| fact.tokens).sum::<usize>();
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "facts": facts,
            "total_tokens": total_tokens,
        })),
    )
        .into_response()
}

#[utoipa::path(
    get,
    path = "/v1/facts/export",
    tag = "Facts",
    params(ExportFactsParams),
    responses(
        (status = 200, description = "Exported facts"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn export_facts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ExportFactsParams>,
) -> impl IntoResponse {
    let ctx = match require_fact_read_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };

    let since = params
        .since
        .as_deref()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc));

    let cursor = params.cursor.as_deref();

    let limit = params.limit.map_or(1000, |v| v.min(10000) as usize);

    let store = state.fact_store.read().await;
    let mut result = store.export(since, cursor, limit);
    if !raw_admin_read(&ctx) {
        result.facts = result
            .facts
            .iter()
            .filter_map(|fact| render_fact_for_http(fact, &ctx))
            .collect();
    }

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "facts": result.facts,
            "next_cursor": result.next_cursor,
            "has_more": result.has_more,
            "exported_at": chrono::Utc::now().to_rfc3339(),
        })),
    )
        .into_response()
}

// ── Session Store API (Phase 1.5) ──────────────────────────────────

#[utoipa::path(
    put,
    path = "/v1/sessions/{sessionId}/state",
    tag = "Sessions",
    params(("sessionId" = String, Path, description = "Session identifier")),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Session state stored", body = corecrux_memory::session_store::SessionState),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn put_session_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let ctx = match require_session_write_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let stored_session_id = scoped_session_id_for_http(&ctx, &session_id);
    let session = match state
        .session_store
        .write()
        .await
        .try_put(&stored_session_id, body, None)
    {
        Ok(session) => session,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    match render_session_for_http(&session, &ctx) {
        Some(session) => (StatusCode::OK, axum::Json(serde_json::json!(session))).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, format!("session '{}' not found", session_id)),
    }
}

#[utoipa::path(
    get,
    path = "/v1/sessions/{sessionId}/state",
    tag = "Sessions",
    params(("sessionId" = String, Path, description = "Session identifier")),
    responses(
        (status = 200, description = "Session state found", body = corecrux_memory::session_store::SessionState),
        (status = 404, description = "Session not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn get_session_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    let ctx = match require_fact_read_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let stored_session_id = if ctx.passport_id.is_some() {
        scoped_session_id_for_http(&ctx, &session_id)
    } else if raw_admin_read(&ctx) || crux_mcp::scope::split_scoped_session_id(&session_id).is_none() {
        session_id.clone()
    } else {
        return problem_response(StatusCode::NOT_FOUND, format!("session '{}' not found", session_id));
    };
    let store = state.session_store.read().await;
    match store
        .get(&stored_session_id)
        .and_then(|session| render_session_for_http(session, &ctx))
    {
        Some(session) => (StatusCode::OK, axum::Json(serde_json::json!(session))).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, format!("session '{}' not found", session_id)),
    }
}

/// Resolve the stored session key for a write/lifecycle mutation, mirroring the
/// read-path resolution in [`get_session_state`]: passport callers are scoped to
/// their own namespace; a raw `admin:write` caller (or an already-unscoped id)
/// operates on the raw key directly. Returns `None` when a scoped caller targets
/// someone else's key (surfaced as 404 by the caller).
fn resolve_session_key_for_write(ctx: &crate::auth::HttpScopeContext, session_id: &str) -> Option<String> {
    if ctx.passport_id.is_some() {
        Some(scoped_session_id_for_http(ctx, session_id))
    } else if raw_admin_write(ctx) || crux_mcp::scope::split_scoped_session_id(session_id).is_none() {
        Some(session_id.to_string())
    } else {
        None
    }
}

/// Optional JSON body for the archive endpoint: `{ "reason": "..." }`.
#[derive(Debug, Default, serde::Deserialize, utoipa::ToSchema)]
pub(super) struct ArchiveSessionBody {
    #[serde(default)]
    pub reason: Option<String>,
}

async fn set_session_archived(
    state: AppState,
    headers: HeaderMap,
    session_id: String,
    archived: bool,
    reason: Option<String>,
) -> Response {
    let ctx = match require_session_write_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let Some(stored_session_id) = resolve_session_key_for_write(&ctx, &session_id) else {
        return problem_response(StatusCode::NOT_FOUND, format!("session '{}' not found", session_id));
    };
    let result = state
        .session_store
        .write()
        .await
        .try_set_archived(&stored_session_id, archived, reason);
    match result {
        Ok(Some(session)) => match render_session_for_http(&session, &ctx) {
            Some(session) => (StatusCode::OK, axum::Json(serde_json::json!(session))).into_response(),
            None => problem_response(StatusCode::NOT_FOUND, format!("session '{}' not found", session_id)),
        },
        Ok(None) => problem_response(StatusCode::NOT_FOUND, format!("session '{}' not found", session_id)),
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

#[utoipa::path(
    post,
    path = "/v1/sessions/{sessionId}/archive",
    tag = "Sessions",
    params(("sessionId" = String, Path, description = "Session identifier")),
    request_body(content = ArchiveSessionBody, description = "Optional archive reason"),
    responses(
        (status = 200, description = "Session archived", body = corecrux_memory::session_store::SessionState),
        (status = 404, description = "Session not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn archive_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    body: Option<Json<ArchiveSessionBody>>,
) -> impl IntoResponse {
    let reason = body.and_then(|Json(b)| b.reason);
    set_session_archived(state, headers, session_id, true, reason).await
}

#[utoipa::path(
    post,
    path = "/v1/sessions/{sessionId}/unarchive",
    tag = "Sessions",
    params(("sessionId" = String, Path, description = "Session identifier")),
    responses(
        (status = 200, description = "Session restored", body = corecrux_memory::session_store::SessionState),
        (status = 404, description = "Session not found"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn unarchive_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    set_session_archived(state, headers, session_id, false, None).await
}
