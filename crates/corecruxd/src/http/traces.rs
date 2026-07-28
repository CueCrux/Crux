// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
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
    match store.load_trace(trace_id) {
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
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let Some(store) = open_store(&state) else {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "persist_enabled": false,
                "traces": [],
                "hint": format!("set {}=1 to persist traces", crate::trace_store::TRACE_PERSIST_ENV),
            })),
        )
            .into_response();
    };
    match store.list_traces(query.limit.unwrap_or(100)) {
        Ok(traces) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "persist_enabled": true,
                "traces": traces.iter().map(|(id, n)| serde_json::json!({"trace_id": id, "span_count": n})).collect::<Vec<_>>(),
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
pub(super) fn load_spans(state: &AppState) -> Vec<crate::trace_store::StoredSpan> {
    if let Some(store) = open_store(state) {
        if let Ok(spans) = store.load_all() {
            if !spans.is_empty() {
                return spans;
            }
        }
    }
    crate::trace_span_ring().map_or_else(Vec::new, |ring| {
        ring.snapshot()
            .into_iter()
            .map(|span| crate::trace_store::StoredSpan {
                span,
                symbol_id: None,
                join: "unresolved_live".to_string(),
                stored_at_unix_ms: 0,
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
    let spans = load_spans(&state);
    let path = crate::code_intel::code_path(&spans, entry, q.token_budget);
    (StatusCode::OK, Json(path)).into_response()
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
    let repo_id = q.repo_id.as_deref().unwrap_or("crux");
    let Some(scan) = load_scan(&state, &q.tenant_id, repo_id).await else {
        return problem_response(StatusCode::NOT_FOUND, "no scan for this repo; register it first");
    };
    let spans = load_spans(&state);
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
    let repo_id = q.repo_id.as_deref().unwrap_or("crux");
    let Some(scan) = load_scan(&state, &q.tenant_id, repo_id).await else {
        return problem_response(StatusCode::NOT_FOUND, "no scan for this repo; register it first");
    };
    let spans = load_spans(&state);
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
    let (Some(a), Some(b)) = (q.trace_a, q.trace_b) else {
        return problem_response(StatusCode::BAD_REQUEST, "trace_a and trace_b are required");
    };
    let spans = load_spans(&state);
    let d = crate::code_intel::trace_diff(&spans, a, b, q.token_budget);
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
    let repo_id = q.repo_id.as_deref().unwrap_or("crux");
    let Some(scan) = load_scan(&state, &q.tenant_id, repo_id).await else {
        return problem_response(StatusCode::NOT_FOUND, "no scan for this repo; register it first");
    };
    let spans = load_spans(&state);
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
    let spans = load_spans(&state);
    let map = crate::code_intel::spatial_map(&scan, &spans);
    (StatusCode::OK, Json(map)).into_response()
}
