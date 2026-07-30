// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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
    /// P2 confidence floor in 0..1: drop facts whose recall-time effective
    /// confidence (stored confidence, stale-demoted) is below this. The
    /// response's `filtered_below_threshold` distinguishes "no facts" from
    /// "nothing above the floor". Omit for no floor.
    pub min_effective_confidence: Option<f32>,
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

/// Default page size for the `GET /v1/facts/list` console listing route.
const FACT_LIST_DEFAULT_LIMIT: usize = 100;
/// Hard cap on the page size (a single response never returns more).
const FACT_LIST_MAX_LIMIT: usize = 500;
/// Values longer than this (in `char`s) are truncated in the row; `value_len`
/// carries the true length and `value_truncated` flags it.
const FACT_LIST_VALUE_MAX_CHARS: usize = 500;

/// Query parameters for the GET /v1/facts/list endpoint (console paged listing).
#[derive(Debug, serde::Deserialize, utoipa::IntoParams)]
pub(super) struct ListFactsParams {
    /// Opaque cursor from a prior response's `next_cursor`. Do not construct.
    pub cursor: Option<String>,
    /// Page size, clamped to 1..=500. Defaults to 100.
    pub limit: Option<usize>,
    /// Include daemon-reserved-prefix entities (`__work__::` etc.). Accepts
    /// `1`/`true`/`yes`/`on`. Defaults to false (reserved hidden, console parity).
    pub include_reserved: Option<String>,
    /// Include cross-entity-retired (superseded) facts. Accepts
    /// `0`/`false`/`no`/`off` to exclude. Defaults to true (parity with
    /// `/v1/facts` + `/v1/console/facts`, which show retired facts today).
    pub include_superseded: Option<String>,
    /// Server-side entity-prefix filter (exact `starts_with`).
    pub entity_prefix: Option<String>,
    /// Case-insensitive substring over entity / key / value (server-side search).
    pub q: Option<String>,
    /// Server-side time-machine: when set, exclude facts stored AFTER this
    /// instant (Unix epoch **milliseconds**) — the page keeps only facts whose
    /// `stored_at.timestamp_millis() <= as_of_unix_ms`. Distinct from
    /// `/v1/facts`' bi-temporal `as_of` (which filters *valid-time*): this
    /// filters INGEST time (`stored_at`), so the console can ask "what did the
    /// store hold as of `<t>`" and page the whole matching set — not just a
    /// recent window. Omitted ⇒ live (whole visible store).
    pub as_of_unix_ms: Option<i64>,
}

/// Parse a query-string boolean flag that may arrive as `1`/`0`/`true`/`false`/
/// `yes`/`no`/`on`/`off` (axum's default bool decoder rejects `1`/`0`). Absent ⇒
/// `default`.
fn parse_query_flag(raw: Option<&str>, default: bool) -> bool {
    match raw {
        None => default,
        Some(s) => matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
    }
}

/// Render one fact into the console-listing row shape: value truncated to
/// [`FACT_LIST_VALUE_MAX_CHARS`] with `value_len` (full length) + a
/// `value_truncated` flag, timestamps in both RFC 3339 and unix-ms form, and
/// the retirement marker so the UI can badge superseded rows. `private` is
/// always `false` — private facts never reach this surface.
fn fact_list_row(fact: &corecrux_memory::fact_store::Fact) -> serde_json::Value {
    let value_len = fact.value.chars().count();
    let value_truncated = value_len > FACT_LIST_VALUE_MAX_CHARS;
    let value = if value_truncated {
        fact.value.chars().take(FACT_LIST_VALUE_MAX_CHARS).collect::<String>()
    } else {
        fact.value.clone()
    };
    serde_json::json!({
        "fact_id": fact.fact_id,
        "entity": fact.entity,
        "key": fact.key,
        "value": value,
        "value_len": value_len,
        "value_truncated": value_truncated,
        "confidence": fact.confidence,
        "horizon_class": fact.horizon_class,
        "actor": fact.actor,
        "stored_at": fact.stored_at.to_rfc3339(),
        "stored_at_unix_ms": fact.stored_at.timestamp_millis(),
        "tokens": fact.tokens,
        "version": fact.version,
        "superseded_by": fact.superseded_by,
        "private": false,
    })
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
    ctx.passport_id.is_none() && ctx.has_scope("admin:read") && ctx.has_global_tenant_authority()
}

fn raw_admin_write(ctx: &crate::auth::HttpScopeContext) -> bool {
    ctx.passport_id.is_none() && ctx.has_scope("admin:write") && ctx.has_global_tenant_authority()
}

/// Resolve the trusted tenant stamp for an HTTP write (OD-37 / audit-v2 closeout M1).
///
/// The tenant is derived from the bearer token's tenant claim (`HttpScopeContext`
/// carries `tenants`, the same authority the query path authorizes against) plus an
/// optional `x-corecrux-tenant-id` selector for multi-tenant tokens — never from the
/// client-supplied fact body. Gated by `CORECRUXD_TENANT_WRITE_STAMP` (default OFF →
/// `default`, byte-identical to pre-M1). `Err` on an unauthorized/ambiguous selector.
///
/// Sibling surfaces (kept consistent with this resolver, verified on this base):
/// - HTTP fact reads (`get_for_tenant` / `all_facts_for_tenant`, and `export_facts`
///   below) apply the tenant predicate; `tenant_hash_for_read_context` moves in lockstep.
/// - `FactStore::store_synced` re-stamps peer-supplied `tenant_hash` on pull (audit-v2 M3, #407).
/// - The MCP write plane has no per-token tenant claim, so it uniformly stamps `default`
///   (no cross-tenant bypass); MCP-plane multi-tenancy is a scoped follow-up.
#[allow(clippy::result_large_err)]
pub(super) fn tenant_hash_for_write_context(ctx: &crate::auth::HttpScopeContext) -> Result<String, Response> {
    match ctx.resolve_write_tenant() {
        Ok(Some(tenant)) => Ok(tenant),
        Ok(None) => Ok(corecrux_memory::fact_store::default_tenant_hash()),
        Err(problem) => Err(problem.into_response()),
    }
}

pub(super) fn tenant_hash_for_read_context(ctx: &crate::auth::HttpScopeContext) -> String {
    ctx.resolve_read_tenant()
        .unwrap_or_else(corecrux_memory::fact_store::default_tenant_hash)
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

fn logical_entity_for_target_policy(fact: &corecrux_memory::fact_store::Fact) -> &str {
    crux_mcp::scope::split_private_entity(&fact.entity).map_or(&fact.entity, |(_, logical)| logical)
}

#[allow(clippy::result_large_err)]
fn prepare_fact_write_checked(
    state: &AppState,
    store: &corecrux_memory::FactStore,
    ctx: &crate::auth::HttpScopeContext,
    mut fact: corecrux_memory::fact_store::StoreFact,
) -> Result<corecrux_memory::fact_store::StoreFact, Response> {
    // Never trust a client-supplied tenant stamp; derive it from auth context.
    fact.tenant_hash = tenant_hash_for_write_context(ctx)?;
    if let Some(prefix) = crate::fact_privacy::generic_create_reserved_entity_prefix(&fact.entity) {
        return Err(ProblemResponse(
            ProblemDetails::forbidden(format!("entity uses create-reserved prefix `{prefix}`")).with_extensions(
                serde_json::json!({
                    "code": "RESERVED_ENTITY_PREFIX",
                    "entity": fact.entity,
                    "reserved_prefix": prefix,
                }),
            ),
        )
        .into_response());
    }
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
) -> Result<Vec<corecrux_memory::fact_store::Fact>, corecrux_memory::embeddings::EmbeddingError> {
    // Internal callers (context_surface) never set a confidence floor; drop the count.
    Ok(query_visible_http_facts_as_of(store, q, ctx, None)?.0)
}

/// P2 confidence floor: drop facts whose recall-time EFFECTIVE confidence
/// (stored confidence, stale-demoted — the same value `query_facts` ranks by)
/// is below `floor`. `None` ⇒ keep all. Returns the number of facts dropped so
/// the caller can surface `filtered_below_threshold`. Generic over owned/borrowed
/// facts so both the raw-admin and scoped branches share one implementation.
fn drop_below_confidence_floor<T: std::borrow::Borrow<corecrux_memory::fact_store::Fact>>(
    facts: &mut Vec<T>,
    floor: Option<f32>,
) -> usize {
    let Some(floor) = floor else {
        return 0;
    };
    let floor = floor as f64;
    let now = chrono::Utc::now();
    let policy = corecrux_projections::decay::DecayPolicy::from_env();
    let before = facts.len();
    facts.retain(|fact| crux_mcp::tools::freshness::fact_effective_confidence(fact.borrow(), now, policy) >= floor);
    before - facts.len()
}

/// Apply the `token_budget`-then-`top_k` selection to an already-ranked list
/// (the same rule `FactStore::query` uses internally): fill by descending rank
/// until the budget is hit, else truncate to `top_k`. Factored out so the
/// raw-admin path can filter the FULL matched set BEFORE this cut.
fn take_within_budget(
    facts: Vec<corecrux_memory::fact_store::Fact>,
    token_budget: Option<usize>,
    top_k: usize,
) -> Vec<corecrux_memory::fact_store::Fact> {
    match token_budget {
        Some(budget) => {
            let mut used = 0usize;
            let mut selected = Vec::new();
            for fact in facts {
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
        }
        None => {
            let mut facts = facts;
            facts.truncate(top_k);
            facts
        }
    }
}

/// As [`query_visible_http_facts`] but with an optional bi-temporal `as_of`
/// filter (M1): when set, only facts whose valid-time interval contains the
/// instant are returned. `None` ⇒ identical to the plain variant. Returns the
/// visible facts plus the P2 `filtered_below_threshold` count.
pub(super) fn query_visible_http_facts_as_of(
    store: &corecrux_memory::FactStore,
    q: &corecrux_memory::fact_store::FactQuery,
    ctx: &crate::auth::HttpScopeContext,
    as_of: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(Vec<corecrux_memory::fact_store::Fact>, usize), corecrux_memory::embeddings::EmbeddingError> {
    if raw_admin_read(ctx) {
        // Run the floor filter/count over the FULL matched+ranked set, THEN
        // apply budget/top_k — so a below-floor row never consumes the window
        // and the count reflects the whole matched set, matching the scoped
        // path and the M7 contract (review finding 4).
        let mut unbounded = q.clone();
        unbounded.top_k = usize::MAX;
        unbounded.token_budget = None;
        unbounded.min_effective_confidence = None;
        let mut facts = match (as_of, store.delegation_status().is_some()) {
            (Some(instant), true) => store.try_query_as_of(&unbounded, instant)?.facts,
            (None, true) => store.try_query(&unbounded)?.facts,
            (Some(instant), false) => store.query_as_of(&unbounded, instant).facts,
            (None, false) => store.query(&unbounded).facts,
        };
        let filtered = drop_below_confidence_floor(&mut facts, q.min_effective_confidence);
        return Ok((take_within_budget(facts, q.token_budget, q.top_k), filtered));
    }

    let agent_name = ctx.passport_id.as_deref();
    let tenant_hash = tenant_hash_for_read_context(ctx);
    let mut results: Vec<&corecrux_memory::fact_store::Fact> = store
        .all_facts_for_tenant(&tenant_hash)
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

    // P2 confidence floor — counted over the full matched set BEFORE the
    // budget/top_k cut so an empty result still reports the true count.
    let filtered_below_threshold = drop_below_confidence_floor(&mut results, q.min_effective_confidence);

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

    let rendered = selected
        .into_iter()
        .filter_map(|fact| render_fact_for_http(fact, ctx))
        .collect();
    Ok((rendered, filtered_below_threshold))
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
#[tracing::instrument(level = "info", skip_all)]
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
    // FU2: file any store-time semantic near-duplicate flags as review candidates.
    crate::candidate_store::route_near_duplicates(&mut store, &chrono::Utc::now().to_rfc3339());
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
#[tracing::instrument(level = "info", skip_all)]
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
    // FU2: file any store-time semantic near-duplicate flags as review candidates.
    crate::candidate_store::route_near_duplicates(&mut store, &chrono::Utc::now().to_rfc3339());
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
#[tracing::instrument(level = "info", skip_all)]
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
    let tenant_hash = tenant_hash_for_read_context(&ctx);
    let fact = if raw_admin_read(&ctx) {
        store.get(&fact_id)
    } else {
        store.get_for_tenant(&fact_id, &tenant_hash)
    };
    match fact.and_then(|fact| render_fact_for_http(fact, &ctx)) {
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
#[tracing::instrument(level = "info", skip_all)]
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
    let tenant_hash = tenant_hash_for_read_context(&ctx);
    let fact = if raw_admin_write(&ctx) {
        store.get(&fact_id)
    } else {
        store.get_for_tenant(&fact_id, &tenant_hash)
    };
    let visible_fact = fact.filter(|fact| fact_visible_for_http_write(fact, &ctx));
    if let Some(prefix) = visible_fact
        .and_then(|fact| crate::fact_privacy::daemon_owned_entity_prefix(logical_entity_for_target_policy(fact)))
    {
        return ProblemResponse(
            ProblemDetails::forbidden(format!("fact belongs to reserved daemon-owned prefix `{prefix}`"))
                .with_extensions(serde_json::json!({
                    "code": "RESERVED_ENTITY_PREFIX",
                    "fact_id": fact_id,
                    "reserved_prefix": prefix,
                })),
        )
        .into_response();
    }
    if let Some(fact) = visible_fact {
        if store.is_consolidation_canonical_for_tenant(&fact_id, &fact.tenant_hash) {
            return ProblemResponse(
                ProblemDetails::new(
                    StatusCode::CONFLICT.as_u16(),
                    "https://errors.cuecrux.com/conflict",
                    "Conflict",
                )
                .with_detail("consolidation canonical must be retired through the dedicated undo surface")
                .with_extensions(serde_json::json!({
                    "code": "CONSOLIDATION_CANONICAL_REQUIRES_UNDO",
                    "fact_id": fact_id,
                })),
            )
            .into_response();
        }
    }
    let delete_tenant = visible_fact.map(|fact| fact.tenant_hash.clone());
    let deleted = if let Some(delete_tenant) = delete_tenant {
        match store.try_delete(&delete_tenant, &fact_id) {
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
#[tracing::instrument(level = "info", skip_all)]
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
    let tenant_hash = tenant_hash_for_read_context(&ctx);
    let facts: Vec<_> = if raw_admin_read(&ctx) {
        store.get_by_entity(&entity).into_iter().cloned().collect()
    } else {
        store
            .all_facts_for_tenant(&tenant_hash)
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
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn query_facts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<QueryFactsParams>,
) -> impl IntoResponse {
    let ctx = match require_fact_read_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    // P2 floor must be finite and in 0..=1 (review finding 5) — reject nonsense
    // rather than silently returning "all kept / all filtered".
    if let Some(floor) = params.min_effective_confidence {
        if !crux_mcp::tools::freshness::valid_confidence_floor(floor as f64) {
            return problem_response(
                StatusCode::BAD_REQUEST,
                "min_effective_confidence must be a number in 0.0..=1.0",
            );
        }
    }
    let q = corecrux_memory::fact_store::FactQuery {
        min_effective_confidence: params.min_effective_confidence,
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
    let (facts, filtered_below_threshold) = match query_visible_http_facts_as_of(&store, &q, &ctx, as_of) {
        Ok(result) => result,
        Err(err) => {
            tracing::warn!(error = %err, "fact-query-embedding-delegation-failed");
            if let Some(status) = store.delegation_status() {
                return super::embedding_delegation_degraded_response(&status);
            }
            return problem_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Fact query embedding failed; no fallback result was returned.",
            );
        }
    };
    let total_tokens = facts.iter().map(|fact| fact.tokens).sum::<usize>();
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "facts": facts,
            "total_tokens": total_tokens,
            // P2: distinguishes "no facts" from "nothing above the floor".
            "filtered_below_threshold": filtered_below_threshold,
        })),
    )
        .into_response()
}

/// `POST /v1/facts/aggregate` — deterministic, 0-LLM aggregate lane (buyer-fit
/// M4, knock-out #5). Answers count / sum_numeric / distinct / temporal_diff
/// over the visible fact set, under an optional `token_budget`. No model call.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_aggregate(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<corecrux_memory::fact_store::AggregateRequestV1>,
) -> impl IntoResponse {
    let ctx = match require_fact_read_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    let tenant_hash = match ctx.resolve_authorized_tenant(None) {
        Ok(tenant_hash) => tenant_hash,
        Err(problem) => return problem.into_response(),
    };
    let store = state.fact_store.read().await;
    Json(store.aggregate_v1(&tenant_hash, &req)).into_response()
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
#[tracing::instrument(level = "info", skip_all)]
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
    let result = if raw_admin_read(&ctx) {
        store.export(since, cursor, limit)
    } else {
        let tenant_hash = match ctx.resolve_authorized_tenant(None) {
            Ok(tenant_hash) => tenant_hash,
            Err(problem) => return problem.into_response(),
        };
        store.export_for_tenant(&tenant_hash, since, cursor, limit)
    };
    let mut result = result;
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

#[utoipa::path(
    get,
    path = "/v1/facts/list",
    tag = "Facts",
    params(ListFactsParams),
    responses(
        (status = 200, description = "Paged, newest-first fact listing"),
        (status = 400, description = "Malformed cursor"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
/// `GET /v1/facts/list` — descending (newest-first), cursor-paginated listing of
/// the fact store for console / operator browsing (console-surfaces-remediation
/// M1). Distinct from `/v1/facts` (recall-ranked recent window) and
/// `/v1/facts/export` (ascending sync-push path): this walks the *whole* visible
/// store in stable `(stored_at, fact_id)` DESC order with server-side reserved /
/// prefix / substring filtering (and an optional `as_of_unix_ms` ingest-time
/// time-machine), so the console can page + search the full set.
///
/// Always excludes private and deleted facts. Tenant scoping mirrors
/// `query_facts`: a raw-admin (auth-off) caller sees the store; a scoped caller
/// is filtered to its read-tenant.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn list_facts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ListFactsParams>,
) -> impl IntoResponse {
    let ctx = match require_fact_read_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };

    // Malformed cursor ⇒ 400 (never silently restart the walk).
    let cursor = match params.cursor.as_deref() {
        Some(raw) => match corecrux_memory::fact_store::FactListCursor::decode(raw) {
            Some(c) => Some(c),
            None => {
                return problem_response(
                    StatusCode::BAD_REQUEST,
                    "cursor is malformed; pass back only a next_cursor from a prior response",
                );
            }
        },
        None => None,
    };

    let limit = params
        .limit
        .unwrap_or(FACT_LIST_DEFAULT_LIMIT)
        .clamp(1, FACT_LIST_MAX_LIMIT);
    let include_reserved = parse_query_flag(params.include_reserved.as_deref(), false);
    let include_superseded = parse_query_flag(params.include_superseded.as_deref(), true);
    let entity_prefix = params.entity_prefix.clone();
    let q_lower = params.q.as_ref().map(|q| q.to_lowercase());
    // Server-side time-machine (M2): exclude facts stored after this instant.
    // Applied inside the page predicate so `total_visible` reflects the as-of
    // universe (not the whole store) and pagination stays exact over it.
    let as_of_unix_ms = params.as_of_unix_ms;

    // Raw-admin (auth-off console) sees the whole store; a scoped caller is
    // confined to its read-tenant — same authority the query path uses.
    let is_admin = raw_admin_read(&ctx);
    let tenant_hash = tenant_hash_for_read_context(&ctx);

    // The consumer-surface reserved list is the single source of truth in
    // crux-mcp (`crux_mcp::tools::memory::RESERVED_ENTITY_PREFIXES`); the store
    // stays ignorant of it, so we apply it here in the caller's predicate.
    let reserved = crux_mcp::tools::memory::RESERVED_ENTITY_PREFIXES;

    let store = state.fact_store.read().await;
    let page = store.list_page(cursor.as_ref(), limit, include_superseded, |fact| {
        if let Some(cutoff) = as_of_unix_ms {
            if fact.stored_at.timestamp_millis() > cutoff {
                return false;
            }
        }
        if !is_admin && fact.tenant_hash != tenant_hash {
            return false;
        }
        if !include_reserved && reserved.iter().any(|p| fact.entity.starts_with(p)) {
            return false;
        }
        if let Some(prefix) = entity_prefix.as_deref() {
            if !fact.entity.starts_with(prefix) {
                return false;
            }
        }
        if let Some(needle) = q_lower.as_deref() {
            let hit = fact.entity.to_lowercase().contains(needle)
                || fact.key.to_lowercase().contains(needle)
                || fact.value.to_lowercase().contains(needle);
            if !hit {
                return false;
            }
        }
        true
    });

    // `total_nondeleted` is the universe count in scope (non-deleted, INCLUDING
    // private + reserved) so a client can render "N of TOTAL" and reconcile the
    // delta (private / reserved / superseded) against `total_visible`.
    let total_nondeleted = if is_admin {
        store.all_facts().filter(|f| !f.deleted).count()
    } else {
        store.all_facts_for_tenant(&tenant_hash).filter(|f| !f.deleted).count()
    };

    let rows: Vec<serde_json::Value> = page.facts.iter().map(fact_list_row).collect();
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "facts": rows,
            "next_cursor": page.next_cursor,
            "has_more": page.has_more,
            "total_visible": page.total_visible,
            "total_nondeleted": total_nondeleted,
            "limit": limit,
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
#[tracing::instrument(level = "info", skip_all)]
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
    // M21 — stamp the authenticated writer. The HTTP lane is the one place a
    // passport is already resolved on the request (HttpScopeContext), so these
    // writes carry an identity even where the MCP lane is anonymous.
    let actor = ctx.passport_id.clone();
    let session = match state
        .session_store
        .write()
        .await
        .try_put_with_actor(&stored_session_id, body, None, actor)
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
#[tracing::instrument(level = "info", skip_all)]
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
#[tracing::instrument(level = "info", skip_all)]
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
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn unarchive_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> impl IntoResponse {
    set_session_archived(state, headers, session_id, false, None).await
}
