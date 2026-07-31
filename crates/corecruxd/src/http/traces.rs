// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! HTTP surface over runtime span capture.
//!
//! ExecPlan `crux-runtime-codemap-and-agent-query-api-2026-07-27`, milestone M2.
//!
//! Everything here reports `capture_enabled: false` and empty data when
//! `CORECRUXD_TRACE_CAPTURE` is unset, rather than 404ing: a caller needs to
//! distinguish "capture is off" from "capture is on and nothing ran", and those
//! are very different answers.

use super::{
    problem_response, require_http_scopes, require_http_scopes_for_tenant, AppState, HeaderMap, IntoResponse, Json,
    Path, Query, State, StatusCode,
};

/// Open the persisted store, or `None` when persistence is off.
fn open_store(state: &AppState) -> Option<crate::trace_store::TraceStore> {
    if !crate::trace_store::persist_enabled() {
        return None;
    }
    crate::trace_store::TraceStore::open(
        state.data_dir.join("traces").join("spans.jsonl"),
        crate::trace_store::max_records(),
    )
    .ok()
}

/// Authorise a span-reading surface and resolve which tenant it answers for (M3b).
///
/// Returns `(tenant, bound)`. `bound = false` means no tenant was named and the
/// daemon's capture tenant was used — the single-tenant-only path. Callers must
/// surface that on the response; a surface that silently answers for the wrong
/// tenant is exactly the defect M2 found.
///
/// **This performs the authorization itself; callers must not authorise
/// separately.** When the request names a tenant the check is
/// `require_http_scopes_for_tenant` against *that* tenant, which is the whole
/// point of the milestone. Authorising with the tenant-blind
/// `require_http_scopes` and then answering from a caller-supplied `tenant_id`
/// lets any holder of a valid token read any tenant's spans — strictly worse
/// than the pinned holding position #560 established, because the pin at least
/// failed closed. Resolution and authorization live in one function so the two
/// cannot drift apart again, which is exactly how they drifted the first time.
// Same allow as `require_http_scopes_for_tenant` itself carries: the error is a
// `ProblemResponse`, and boxing it here would differ from every other
// authorization helper for no benefit.
#[allow(clippy::result_large_err)]
pub(super) fn runtime_tenant_for(
    state: &AppState,
    headers: &HeaderMap,
    required: &[&str],
    requested: Option<&str>,
) -> Result<(String, bool), crate::problem::ProblemResponse> {
    match requested {
        Some(t) if !t.trim().is_empty() => {
            require_http_scopes_for_tenant(&state.auth, headers, required, t)?;
            Ok((t.to_string(), true))
        }
        _ => {
            require_http_scopes(&state.auth, headers, required)?;
            Ok((crate::trace_store::TraceStore::capture_tenant(), false))
        }
    }
}

/// Optional tenant binding (M3b).
///
/// When `tenant_id` is supplied the request is authorised against *that* tenant
/// and answered only from its spans — the hostable path. When it is absent the
/// surface falls back to this daemon's own capture tenant, which is correct for
/// a single-tenant local daemon and is **not** hostable, because every customer
/// on a shared daemon would resolve to the same tenant.
///
/// The fallback is reported as `tenant_scope` on the response rather than left
/// implicit: a surface that silently answers for the wrong tenant is the failure
/// M2 was written to prevent, and "it looked like it worked" is how it ships.
#[derive(Debug, Default, serde::Deserialize)]
pub(super) struct OptionalTenantQuery {
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// `GET /v1/traces/{trace_id}` — one persisted trace, spans resolved to symbols.
///
/// This is the M4 read side: the ordered path a request actually took through
/// the code, with each step carrying the `symbol_id` it was joined to and the
/// `join` quality that produced it.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_trace(
    State(state): State<AppState>,
    Path(trace_id): Path<String>,
    headers: HeaderMap,
    Query(tq): Query<OptionalTenantQuery>,
) -> impl IntoResponse {
    let (tenant, bound) = match tq.tenant_id.as_deref() {
        Some(t) => {
            if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], t) {
                return problem.into_response();
            }
            (t.to_string(), true)
        }
        None => {
            if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
                return problem.into_response();
            }
            (crate::trace_store::TraceStore::capture_tenant(), false)
        }
    };

    let Ok(trace_id) = trace_id.parse::<u64>() else {
        return problem_response(StatusCode::BAD_REQUEST, "trace_id must be a u64");
    };
    let Some(store) = open_store(&state) else {
        return problem_response(
            StatusCode::CONFLICT,
            format!(
                "trace persistence is off; set {}=1",
                crate::trace_store::TRACE_PERSIST_ENV
            ),
        );
    };
    match store.load_trace(trace_id, &tenant) {
        Ok(spans) if spans.is_empty() => problem_response(StatusCode::NOT_FOUND, "no such trace"),
        Ok(spans) => {
            let resolved = spans.iter().filter(|s| s.symbol_id.is_some()).count();
            let total_ns: u64 = spans
                .iter()
                .filter(|s| s.span.depth == 0)
                .map(|s| s.span.duration_ns)
                .sum();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                "tenant_id": tenant,
                "tenant_scope": if bound { "request" } else { "daemon-capture-tenant" },
                    "trace_id": trace_id,
                    "span_count": spans.len(),
                    "resolved_symbols": resolved,
                    "root_duration_ns": total_ns,
                    "spans": spans,
                })),
            )
                .into_response()
        }
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("trace read failed: {err}")),
    }
}

/// `GET /v1/traces` — persisted traces, newest first.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn list_traces(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TraceSpansQuery>,
    Query(tq): Query<OptionalTenantQuery>,
) -> impl IntoResponse {
    let (list_tenant, list_bound) = match tq.tenant_id.as_deref() {
        Some(t) => {
            if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], t) {
                return problem.into_response();
            }
            (t.to_string(), true)
        }
        None => {
            if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
                return problem.into_response();
            }
            (crate::trace_store::TraceStore::capture_tenant(), false)
        }
    };
    let Some(store) = open_store(&state) else {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "persist_enabled": false,
                "traces": [],
                "hint": format!("set {}=1 to persist traces", crate::trace_store::TRACE_PERSIST_ENV),
                // Scope is a property of the request, not of whether persistence
                // happens to be on — a caller must be able to tell which tenant
                // it asked for regardless of the answer being empty.
                "tenant_id": list_tenant,
                "tenant_scope": if list_bound { "request" } else { "daemon-capture-tenant" },
            })),
        )
            .into_response();
    };
    match store.list_traces(query.limit.unwrap_or(100), &list_tenant) {
        Ok(traces) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "persist_enabled": true,
                "traces": traces.iter().map(|(id, n)| serde_json::json!({"trace_id": id, "span_count": n})).collect::<Vec<_>>(),
                "tenant_id": list_tenant,
                // `daemon-capture-tenant` means no tenant was named, so this
                // answered for whatever tenant the process captures as. Correct
                // locally, NOT hostable — see OptionalTenantQuery.
                "tenant_scope": if list_bound { "request" } else { "daemon-capture-tenant" },
            })),
        )
            .into_response(),
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("trace list failed: {err}")),
    }
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct TraceSpansQuery {
    /// Restrict to a single trace.
    #[serde(default)]
    pub trace_id: Option<u64>,
    /// Cap the number of spans returned, newest-biased. Defaults to 500 so an
    /// unbounded ring cannot become an unbounded response.
    #[serde(default)]
    pub limit: Option<usize>,
}

const DEFAULT_SPAN_LIMIT: usize = 500;

/// `GET /v1/traces/stats` — is capture on, and what has it seen?
///
/// `dropped` is the honest data-loss counter: the ring evicts oldest-first when
/// full, so a rising `dropped` means the flush interval or capacity needs
/// raising, not that the daemon is misbehaving.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_trace_stats(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let body = match crate::trace_span_ring() {
        Some(ring) => serde_json::json!({
            "capture_enabled": true,
            "retained": ring.len(),
            "capacity": ring.capacity(),
            "captured_total": ring.captured(),
            "dropped_total": ring.dropped(),
        }),
        None => serde_json::json!({
            "capture_enabled": false,
            "hint": format!(
                "set {}=1 to enable runtime span capture",
                crux_observe::span_layer::TRACE_CAPTURE_ENV
            ),
        }),
    };
    (StatusCode::OK, Json(body)).into_response()
}

/// `GET /v1/traces/spans` — the captured span tree, optionally one trace.
///
/// Read-only and non-draining, so polling this never destroys data the M4
/// flusher has not yet persisted.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_trace_spans(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TraceSpansQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let Some(ring) = crate::trace_span_ring() else {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "capture_enabled": false,
                "spans": [],
                "hint": format!(
                    "set {}=1 to enable runtime span capture",
                    crux_observe::span_layer::TRACE_CAPTURE_ENV
                ),
            })),
        )
            .into_response();
    };

    let mut spans = ring.snapshot();
    if let Some(trace_id) = query.trace_id {
        spans.retain(|s| s.trace_id == trace_id);
    }
    let total_matched = spans.len();
    let limit = query.limit.unwrap_or(DEFAULT_SPAN_LIMIT);
    if spans.len() > limit {
        // Keep the newest: the tail of the ring is the interesting end.
        spans = spans.split_off(total_matched - limit);
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "capture_enabled": true,
            "total_matched": total_matched,
            "returned": spans.len(),
            "spans": spans,
        })),
    )
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// M5 — the agent query API.
//
// Every handler here takes a mandatory `token_budget` (QC.2) and answers in a
// compact, ranked form. The point is that "what runs when X fires" costs an
// agent a few hundred tokens instead of forty file reads.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub(super) struct CodeIntelQuery {
    pub tenant_id: String,
    #[serde(default)]
    pub repo_id: Option<String>,
    /// Mandatory per the workspace retrieval contract. No default that silently
    /// returns an unbounded answer.
    pub token_budget: usize,
    #[serde(default)]
    pub entry_point: Option<String>,
    #[serde(default)]
    pub symbol: Option<String>,
    /// Compare two releases rather than two trace ids (M6).
    #[serde(default)]
    pub release_a: Option<String>,
    #[serde(default)]
    pub release_b: Option<String>,
    /// Answer across every enabled repo the tenant has registered, not just one.
    ///
    /// This is the Pro capability (P1): the arithmetic a local daemon cannot do,
    /// because the callers live in repos its checkout has never seen. Defaults to
    /// false, so the free single-repo answer is byte-for-byte unchanged.
    #[serde(default)]
    pub all_repos: bool,
    #[serde(default)]
    pub trace_a: Option<u64>,
    #[serde(default)]
    pub trace_b: Option<u64>,
}

/// Load persisted spans, falling back to the live ring when persistence is off
/// so the API still answers on a capture-only daemon.
/// Load the runtime span window: the persisted store if enabled and non-empty,
/// otherwise the in-memory ring.
///
/// `pub(super)` so `dossier::post_auto` can feed the same window the code-intel
/// routes answer from — a dossier whose runtime tier disagreed with
/// `/v1/code-intel/dead-code` would be worse than one with no runtime tier.
///
/// **Tenant-scoped (M2 finding, `crux-code-intel-pro-hosted-surface` M3).**
/// Every caller must name the tenant it is answering for. There is no unscoped
/// variant: the defect M2 found was an authorization check with no matching data
/// filter, and the fix is only durable if the unfiltered read cannot be reached.
///
/// The in-memory ring is process-wide and holds this daemon's own execution, so
/// its spans belong to the capture tenant and are withheld from every other —
/// the same rule the store applies to legacy unlabelled records.
pub(super) fn load_spans(state: &AppState, tenant_id: &str) -> Vec<crate::trace_store::StoredSpan> {
    if let Some(store) = open_store(state) {
        if let Ok(spans) = store.load_for_tenant(tenant_id) {
            if !spans.is_empty() {
                return spans;
            }
        }
    }
    if tenant_id != crate::trace_store::TraceStore::capture_tenant() {
        return Vec::new();
    }
    crate::trace_span_ring().map_or_else(Vec::new, |ring| {
        ring.snapshot()
            .into_iter()
            .map(|span| crate::trace_store::StoredSpan {
                span,
                symbol_id: None,
                join: "unresolved_live".to_string(),
                stored_at_unix_ms: 0,
                tenant_id: tenant_id.to_string(),
                release: String::new(),
            })
            .collect()
    })
}

async fn load_scan(state: &AppState, tenant_id: &str, repo_id: &str) -> Option<crate::workspace_scan::WorkspaceScan> {
    let store = state.fact_store.read().await;
    let json = crate::repo_registry::load_scan_json(&store, tenant_id, repo_id)?;
    drop(store);
    serde_json::from_str(&json).ok()
}

/// `GET /v1/code-intel/path` — what actually executes for an entry point.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_code_path(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CodeIntelQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &q.tenant_id) {
        return problem.into_response();
    }
    let Some(entry) = q.entry_point.as_deref() else {
        return problem_response(StatusCode::BAD_REQUEST, "entry_point is required");
    };
    let spans = load_spans(&state, &q.tenant_id);
    let path = crate::code_intel::code_path(&spans, entry, q.token_budget);

    if q.all_repos {
        // This route reads the span window only — no static scan — and the window
        // is already tenant-wide, so the answer *is* cross-repo whether or not the
        // flag is set. Saying so beats accepting the flag and discarding it: a
        // caller that sets `all_repos` and gets an unannotated single-repo-shaped
        // body cannot tell "already aggregate" from "silently ignored".
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "aggregate": true,
                "aggregate_basis": "runtime spans are tenant-wide; no static scan is consulted",
                "path": path,
            })),
        )
            .into_response();
    }
    (StatusCode::OK, Json(path)).into_response()
}

/// Query for the M8 enrichment surface.
#[derive(Debug, serde::Deserialize)]
pub(super) struct EnrichQuery {
    pub tenant_id: String,
    /// Which seat the call is charged against. The ceiling is per seat, so an
    /// account that does not distinguish them shares one bucket — which is the
    /// safe default, not a silent merge of everybody's headroom.
    #[serde(default)]
    pub seat_id: Option<String>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(default)]
    pub token_budget: Option<usize>,
}

/// Credits charged for one enriched verdict.
///
/// Matches `extraction` on the published rate card because it is the same shape
/// of work — a third-party model reasoning over one unit of evidence. Anything
/// that changes this must change the price list in the same commit, or the
/// daemon and the thing the customer agreed to stop agreeing.
pub(super) const ENRICHED_VERDICT_COST_CR: u64 = 5;

/// `GET /v1/code-intel/enrich-budget` — a seat's remaining enrichment headroom (M8).
///
/// Readable without consuming, which is the whole point: the ceiling has to be
/// visible before it bites, not discovered by being refused.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_enrich_budget(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<EnrichQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &q.tenant_id) {
        return problem.into_response();
    }
    let seat = q.seat_id.as_deref().unwrap_or("default");
    let Ok(mut budgets) = state.enrich_budgets.lock() else {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "enrich budget lock poisoned");
    };
    let view = budgets.peek(&q.tenant_id, seat);
    drop(budgets);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "budget": view,
            "cost_cr_per_verdict": ENRICHED_VERDICT_COST_CR,
        })),
    )
        .into_response()
}

/// `POST /v1/code-intel/enrich` — an LLM-reviewed dead-code verdict (M8, P3).
///
/// The order of the two limits is deliberate. **The seat ceiling is checked
/// first**, before the wallet is touched: a rate refusal must not reserve, spend
/// or otherwise disturb credit, because the caller has not been given anything.
/// Reserving and then refusing would leave holds on a wallet for calls that
/// never happened.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_enrich_verdict(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<EnrichQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:write"], &q.tenant_id) {
        return problem.into_response();
    }
    let Some(symbol) = q.symbol.as_deref() else {
        return problem_response(StatusCode::BAD_REQUEST, "symbol is required");
    };
    let seat = q.seat_id.as_deref().unwrap_or("default");

    // 1. Rate ceiling. Refuse here and nothing else has happened yet.
    let budget = {
        let Ok(mut budgets) = state.enrich_budgets.lock() else {
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "enrich budget lock poisoned");
        };
        match budgets.try_consume(&q.tenant_id, seat) {
            Ok(b) => b,
            Err(exhausted) => {
                // 429, not 402: this is a rate limit, not a billing failure, and
                // the caller's recovery is to wait rather than to buy credit.
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({
                        "error": "enrichment rate ceiling reached for this seat",
                        "budget": exhausted,
                        "retry_after_secs": crate::enrich_budget::window_secs(),
                    })),
                )
                    .into_response();
            }
        }
    };

    // 2. Evidence. Enrichment reasons over the deterministic ladder rather than
    //    replacing it — the free answer stays the substrate, and a model that is
    //    unavailable degrades the response, never the verdict underneath.
    let spans = load_spans(&state, &q.tenant_id);
    let repo_id = q.repo_id.as_deref().unwrap_or("crux");
    let Some(scan) = load_scan(&state, &q.tenant_id, repo_id).await else {
        return problem_response(StatusCode::NOT_FOUND, "no scan for this repo; register it first");
    };
    let ladder = crate::code_intel::dead_code_ladder(&scan, &spans, Some(symbol), q.token_budget.unwrap_or(4000));

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "symbol": symbol,
            "evidence": ladder,
            // The enrichment provider is not wired yet: this returns the
            // deterministic ladder and says so, rather than inventing a
            // rationale. `enriched: false` is the honest wire signal, and no
            // credit is charged for work that was not done.
            "enriched": false,
            "enrichment_status": "provider_not_configured",
            "cost_cr": 0,
            "budget": budget,
        })),
    )
        .into_response()
}

/// `GET /v1/code-intel/volume` — retained spans against the tenant's ceiling (M5).
///
/// The ceiling's gate is that containment is "visible to the customer before it
/// bites". A limit whose first observable symptom is missing data is a support
/// ticket, not a limit — so the counter is readable before the refusals start.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_span_volume(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<super::repos::RepoTenantQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &q.tenant_id) {
        return problem.into_response();
    }
    let Some(store) = open_store(&state) else {
        return problem_response(
            StatusCode::CONFLICT,
            format!(
                "trace persistence is off; set {}=1",
                crate::trace_store::TRACE_PERSIST_ENV
            ),
        );
    };
    match store.volume_for_tenant(&q.tenant_id) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

/// `GET /v1/code-intel/releases` — releases this tenant holds history for (M6).
///
/// Release-over-release `trace_diff` is unusable without knowing which releases
/// are actually retained; asking a caller to guess a label is asking them to
/// discover the retention window by trial and error.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_releases(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<super::repos::RepoTenantQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &q.tenant_id) {
        return problem.into_response();
    }
    let Some(store) = open_store(&state) else {
        return problem_response(
            StatusCode::CONFLICT,
            format!(
                "trace persistence is off; set {}=1",
                crate::trace_store::TRACE_PERSIST_ENV
            ),
        );
    };
    match store.releases_for_tenant(&q.tenant_id) {
        Ok(rs) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "releases": rs.iter().map(|(r, c)| serde_json::json!({"release": r, "spans": c})).collect::<Vec<_>>(),
                "retention_days": crate::trace_store::retention_days(),
            })),
        )
            .into_response(),
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

/// `GET /v1/code-intel/blast-radius` — who breaks if this changes.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_blast_radius(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CodeIntelQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &q.tenant_id) {
        return problem.into_response();
    }
    let Some(symbol) = q.symbol.as_deref() else {
        return problem_response(StatusCode::BAD_REQUEST, "symbol is required");
    };
    let spans = load_spans(&state, &q.tenant_id);

    if q.all_repos {
        // P1: one graph across every enabled repo this tenant registered. Paths
        // are repo-qualified by the aggregator so the answer says which repo each
        // caller is in rather than leaving that to a second lookup.
        let (scan, repos) = crate::repo_aggregate::aggregate_tenant(&state, &q.tenant_id).await;
        let radius = crate::code_intel::blast_radius(&scan, &spans, symbol, q.token_budget);
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "aggregate": true,
                "repos": repos,
                "radius": radius,
                // Named in the payload, not just the docs: references resolve by
                // symbol name, so across repos two unrelated symbols sharing a
                // name merge. Sound for "what might break", not precise enough to
                // delete from without reading.
                "precision": "superset: cross-repo edges resolve by symbol name",
            })),
        )
            .into_response();
    }

    let repo_id = q.repo_id.as_deref().unwrap_or("crux");
    let Some(scan) = load_scan(&state, &q.tenant_id, repo_id).await else {
        return problem_response(StatusCode::NOT_FOUND, "no scan for this repo; register it first");
    };
    let radius = crate::code_intel::blast_radius(&scan, &spans, symbol, q.token_budget);
    (StatusCode::OK, Json(radius)).into_response()
}

/// `GET /v1/code-intel/liveness` — did this run, in a stated window.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_liveness(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CodeIntelQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &q.tenant_id) {
        return problem.into_response();
    }
    let Some(symbol) = q.symbol.as_deref() else {
        return problem_response(StatusCode::BAD_REQUEST, "symbol is required");
    };
    let spans = load_spans(&state, &q.tenant_id);

    if q.all_repos {
        // P1. Liveness reads the static scan as well as the span window, so a
        // single-repo scan answers "is this used" against one repo's references
        // only — which is the wrong answer, not a partial one, when the caller
        // lives elsewhere in the estate.
        let (scan, repos) = crate::repo_aggregate::aggregate_tenant(&state, &q.tenant_id).await;
        let l = crate::code_intel::liveness(&scan, &spans, symbol);
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "aggregate": true,
                "repos": repos,
                "liveness": l,
                "precision": "superset: cross-repo edges resolve by symbol name",
            })),
        )
            .into_response();
    }

    let repo_id = q.repo_id.as_deref().unwrap_or("crux");
    let Some(scan) = load_scan(&state, &q.tenant_id, repo_id).await else {
        return problem_response(StatusCode::NOT_FOUND, "no scan for this repo; register it first");
    };
    let l = crate::code_intel::liveness(&scan, &spans, symbol);
    (StatusCode::OK, Json(l)).into_response()
}

/// `GET /v1/code-intel/trace-diff` — where two traces diverge.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_trace_diff(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CodeIntelQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &q.tenant_id) {
        return problem.into_response();
    }
    // M6: release-over-release. "What executes now that did not before a
    // release" is the question that makes this operational — two trace ids from
    // the same afternoon cannot answer it.
    if let (Some(ra), Some(rb)) = (q.release_a.as_deref(), q.release_b.as_deref()) {
        let Some(store) = open_store(&state) else {
            return problem_response(
                StatusCode::CONFLICT,
                format!(
                    "trace persistence is off; set {}=1",
                    crate::trace_store::TRACE_PERSIST_ENV
                ),
            );
        };
        let (Ok(sa), Ok(sb)) = (
            store.load_for_release(&q.tenant_id, ra),
            store.load_for_release(&q.tenant_id, rb),
        ) else {
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "could not read release history");
        };
        let names = |v: &[crate::trace_store::StoredSpan]| -> std::collections::BTreeSet<String> {
            v.iter().map(|s| s.span.name.clone()).collect()
        };
        let (na, nb) = (names(&sa), names(&sb));
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "release_a": ra,
                "release_b": rb,
                "spans_a": sa.len(),
                "spans_b": sb.len(),
                "appeared": nb.difference(&na).collect::<Vec<_>>(),
                "disappeared": na.difference(&nb).collect::<Vec<_>>(),
            })),
        )
            .into_response();
    }

    let (Some(a), Some(b)) = (q.trace_a, q.trace_b) else {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "provide trace_a and trace_b, or release_a and release_b",
        );
    };
    let spans = load_spans(&state, &q.tenant_id);
    let d = crate::code_intel::trace_diff(&spans, a, b, q.token_budget);

    if q.all_repos {
        // Span-only, like code_path: the window is already tenant-wide, so this is
        // annotated rather than silently dropping the flag.
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "aggregate": true,
                "aggregate_basis": "runtime spans are tenant-wide; no static scan is consulted",
                "diff": d,
            })),
        )
            .into_response();
    }
    (StatusCode::OK, Json(d)).into_response()
}

/// `GET /v1/code-intel/dead-code` — the M6 evidence ladder.
///
/// One verdict per statically-flagged symbol, each carrying the tiers that
/// spoke and whether they agree. `actionable` is true only when two independent
/// tiers agree over a non-empty observation window; everything else is a lead.
///
/// Pass `symbol` to ask about one symbol. Without it the answer is the whole
/// repo, which a token budget will truncate — and truncation used to drop the
/// symbol the caller cared about.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_dead_code_ladder(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<CodeIntelQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &q.tenant_id) {
        return problem.into_response();
    }
    let spans = load_spans(&state, &q.tenant_id);

    if q.all_repos {
        // P1, and the highest-stakes aggregate on this surface. A symbol defined
        // in repo A and referenced only from repo B is statically unreferenced
        // *within A*, so a single-repo ladder reports it as dead. Someone acting
        // on that deletes live code. Aggregating first is what makes the verdict
        // safe to act on.
        let (scan, repos) = crate::repo_aggregate::aggregate_tenant(&state, &q.tenant_id).await;
        let ladder = crate::code_intel::dead_code_ladder(&scan, &spans, q.symbol.as_deref(), q.token_budget);
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "aggregate": true,
                "repos": repos,
                "ladder": ladder,
                "precision": "superset: cross-repo edges resolve by symbol name",
            })),
        )
            .into_response();
    }

    let repo_id = q.repo_id.as_deref().unwrap_or("crux");
    let Some(scan) = load_scan(&state, &q.tenant_id, repo_id).await else {
        return problem_response(StatusCode::NOT_FOUND, "no scan for this repo; register it first");
    };
    let ladder = crate::code_intel::dead_code_ladder(&scan, &spans, q.symbol.as_deref(), q.token_budget);
    (StatusCode::OK, Json(ladder)).into_response()
}

/// `GET /v1/repos/{repo_id}/spatial` — the M8 spatial seam.
///
/// Deterministic coordinates for a future 3D renderer: districts (crates),
/// buildings (files, sized by LOC and symbol count), and district-level edge
/// bundles. No renderer here; `layout_digest` lets a client verify the map did
/// not move between scans.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_repo_spatial(
    State(state): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    Query(q): Query<super::repos::RepoTenantQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &q.tenant_id) {
        return problem.into_response();
    }
    let Some(scan) = load_scan(&state, &q.tenant_id, &repo_id).await else {
        return problem_response(StatusCode::NOT_FOUND, "no scan for this repo; register it first");
    };
    let spans = load_spans(&state, &q.tenant_id);
    let map = crate::code_intel::spatial_map(&scan, &spans);
    (StatusCode::OK, Json(map)).into_response()
}
