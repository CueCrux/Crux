// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP CRUD for work items, comments, transitions, and gated actions.

#![allow(clippy::option_option)] // PATCH tri-state semantics

use super::{
    problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Path, Query, State, StatusCode,
};

/// Where `/v1/work` reads from.
///
/// - `Kanban` (default for backwards-compat with existing callers that omit
///   the param) — the `__work__::*` fact table populated by `create_work`.
/// - `Execplans` — the read-time aggregator over plan files under
///   `$CRUX_EXECPLANS_ROOT` joined with facts under `entity = "execplan:<slug>"`.
///   See [`crate::work_execplans`].
/// - `All` — both, deduplicated by `id` (kanban wins on collision).
#[derive(Debug, Clone, Copy, Default, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum WorkSource {
    Kanban,
    Execplans,
    /// Default. Includes both kanban-table items and the read-time ExecPlan
    /// projection. ExecPlans are only included when `CRUX_EXECPLANS_ROOT` is
    /// set; otherwise this behaves identically to `Kanban`.
    #[default]
    All,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ListWorkQuery {
    pub project_id: Option<String>,
    pub state: Option<String>,
    pub tenant_id: Option<String>,
    pub assignee_passport: Option<String>,
    #[serde(default)]
    pub source: WorkSource,
    /// Agent-graph orchestrator filter (orchestrators plan). When set, the
    /// merged work list is narrowed to the items belonging to this
    /// orchestrator: kanban items are matched on their stamped
    /// `orchestrator_id`, and ExecPlan items are stamped at read time from the
    /// orchestrator's member list. Additive — omitting it preserves the prior
    /// merged behaviour.
    #[serde(default)]
    pub orchestrator: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct CreateWorkBody {
    pub project_id: String,
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub assignee_passport: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub linked_pr: Option<String>,
    #[serde(default)]
    pub linked_issue: Option<String>,
    /// Required: which passport is creating the item. The HTTP layer accepts
    /// it explicitly so callers without a session binding can still write.
    /// Aliases: `by_passport`, `author_passport` (the other work routes use
    /// these names; accepting all three reduces caller error).
    #[serde(alias = "by_passport", alias = "author_passport")]
    pub created_by_passport: String,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct UpdateWorkBody {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default, deserialize_with = "deserialize_some_option")]
    pub assignee_passport: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some_option")]
    pub tenant_id: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some_option")]
    pub linked_pr: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some_option")]
    pub linked_issue: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some_option")]
    pub blocker_reason: Option<Option<String>>,
    /// Typed blocker kind (`needs_info` | `needs_approval`). Unknown strings are
    /// rejected by serde; absent = leave unchanged.
    #[serde(default)]
    pub blocker_kind: Option<crate::work::BlockerKind>,
    /// Identity making the change. Determines whether the change is gated.
    /// Aliases: `created_by_passport`, `author_passport`.
    #[serde(alias = "created_by_passport", alias = "author_passport")]
    pub by_passport: String,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct CommentBody {
    /// Aliases: `by_passport`, `created_by_passport`.
    #[serde(alias = "by_passport", alias = "created_by_passport")]
    pub author_passport: String,
    pub body: String,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct GateResolutionBody {
    pub approver_passport: String,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct GateListQuery {
    pub by_passport: Option<String>,
}

fn deserialize_some_option<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    use serde::Deserialize;
    Option::<T>::deserialize(deserializer).map(Some)
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

pub(super) async fn get_work(
    State(state): State<AppState>,
    Query(q): Query<ListWorkQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    if let Some(s) = &q.state {
        if crate::work::validate_state(s).is_err() {
            return problem_response(
                StatusCode::BAD_REQUEST,
                format!(
                    "state must be one of {} (got '{}')",
                    crate::work::WORK_STATES.join(", "),
                    s
                ),
            );
        }
    }
    let store = state.fact_store.read().await;

    let kanban_items = if matches!(q.source, WorkSource::Kanban | WorkSource::All) {
        crate::work::list_work(
            &store,
            q.project_id.as_deref(),
            q.state.as_deref(),
            q.tenant_id.as_deref(),
            q.assignee_passport.as_deref(),
        )
    } else {
        Vec::new()
    };

    let mut execplan_items = if matches!(q.source, WorkSource::Execplans | WorkSource::All) {
        execplan_items_for_query(&store, &q)
    } else {
        Vec::new()
    };

    // Orchestrator filter (agent-graph). Stamp `orchestrator_id` on the
    // ExecPlan items that are members of the requested orchestrator (kanban
    // items already carry it from the membership write path), then below we
    // keep only items whose `orchestrator_id` matches.
    if let Some(orc_id) = q.orchestrator.as_deref() {
        let estore = state.entity_store.read().await;
        let member_ids = crate::http::orchestrators::orchestrator_member_refs(&estore, orc_id);
        drop(estore);
        crate::work_execplans::stamp_orchestrator_id(&mut execplan_items, &member_ids, orc_id);
    }
    drop(store);

    // Per-ExecPlan token-burn rollup: join the cost lens (one report per coding
    // session, keyed by transcript UUID) onto the ExecPlan items at read time
    // (window-overlap + passport-refine; see `crate::cost_attribution`). Gated by
    // the cost-lens flag so the daemon is byte-identical when it's off, and
    // skipped when there are no ExecPlan items to stamp. Cost reports are
    // per-tenant; attribute the requested tenant's (default `default`).
    if crate::cost::cost_lens_enabled() && !execplan_items.is_empty() {
        let tenant = q.tenant_id.as_deref().unwrap_or("default");
        let reports = {
            let cstore = crate::cost::global().lock().await;
            cstore.reports_for_tenant(tenant)
        };
        let sessions = crate::cost_attribution::session_burns_from_reports(&reports);
        crate::cost_attribution::stamp_token_burn(&mut execplan_items, &sessions);
    }

    // Merge: kanban first (wins on id collision), then execplan items not
    // already present. ExecPlan ids are namespaced (`execplan:<slug>`) so
    // collisions are not expected in practice — the dedup is defence in depth.
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::with_capacity(kanban_items.len());
    let mut items = Vec::with_capacity(kanban_items.len() + execplan_items.len());
    for w in kanban_items {
        seen.insert(w.id.clone());
        items.push(w);
    }
    for w in execplan_items {
        if !seen.contains(&w.id) {
            items.push(w);
        }
    }

    // Apply the orchestrator filter so it intersects both kanban + execplan sources.
    if let Some(orc_id) = q.orchestrator.as_deref() {
        items.retain(|w| w.orchestrator_id.as_deref() == Some(orc_id));
    }

    // agent-ux-05 — risk-tiered HITL projection. When the caller asks for
    // `state=pending_approval` (or no state filter at all), splice in the
    // in-memory approval queue managed by `crux_mcp::tools::approvals`.
    // Approval entries are emitted with `kind: "approval"` so the SPA can
    // render them with a distinct row class. Tenant + state filters from
    // `q` are honoured so cross-tenant approvers don't see other tenants'
    // pending requests.
    let want_approvals = match q.state.as_deref() {
        Some("pending_approval") | None => true,
        Some(_) => false,
    };
    let mut approval_entries: Vec<serde_json::Value> = if want_approvals {
        crux_mcp::tools::approvals::pending_requests_for_work_panel().await
    } else {
        Vec::new()
    };
    if let Some(tenant) = q.tenant_id.as_deref() {
        approval_entries.retain(|e| e.get("tenant_id").and_then(|v| v.as_str()) == Some(tenant));
    }
    let approval_count = approval_entries.len();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "count": items.len() + approval_count,
            "source": match q.source {
                WorkSource::Kanban => "kanban",
                WorkSource::Execplans => "execplans",
                WorkSource::All => "all",
            },
            "work": items,
            "approvals": approval_entries,
        })),
    )
        .into_response()
}

/// Build the ExecPlan slice of the response. Applies the same state /
/// tenant / assignee filters that kanban uses so `?source=all&state=planned`
/// returns a coherent merged list.
fn execplan_items_for_query(
    store: &corecrux_memory::fact_store::FactStore,
    q: &ListWorkQuery,
) -> Vec<crate::work::WorkItem> {
    // No root configured = aggregator off. Return empty rather than 500.
    let Some(root) = crate::work_execplans::execplans_root_from_env() else {
        return Vec::new();
    };
    let now_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64);
    let items = match crate::work_execplans::list_execplans(store, &root, now_unix_ms) {
        Ok(items) => items,
        Err(err) => {
            tracing::warn!(error = %err, root = %root.display(), "execplan-aggregator-io-error");
            return Vec::new();
        }
    };
    // ExecPlan items are workspace-scoped, not project-scoped — they live
    // in a virtual `execplans` project (`VIRTUAL_PROJECT_ID`) that callers
    // don't filter against explicitly. Skip `project_id` here so the common
    // SPA pattern `?source=all&project_id=default` still surfaces them; the
    // user disambiguates kanban vs execplans via the `source` chip.
    items
        .into_iter()
        .filter(|w| {
            q.state.as_deref().is_none_or(|s| w.state == s)
                && q.tenant_id.as_deref().is_none_or(|t| w.tenant_id.as_deref() == Some(t))
                && q.assignee_passport
                    .as_deref()
                    .is_none_or(|a| w.assignee_passport.as_deref() == Some(a))
        })
        .collect()
}

pub(super) async fn get_work_item(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let item = crate::work::get_work(&store, &id);
    drop(store);
    match item {
        Some(w) => (StatusCode::OK, Json(w)).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, format!("work item '{id}' not found")),
    }
}

pub(super) async fn post_work(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateWorkBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["facts:write"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::work::create_work(
        &mut store,
        crate::work::CreateWorkInput {
            project_id: body.project_id,
            title: body.title,
            body: body.body,
            state: body.state,
            assignee_passport: body.assignee_passport,
            tenant_id: body.tenant_id,
            linked_pr: body.linked_pr,
            linked_issue: body.linked_issue,
            created_by_passport: body.created_by_passport,
        },
        now_unix_ms(),
    );
    drop(store);
    match result {
        Ok(w) => (StatusCode::CREATED, Json(w)).into_response(),
        Err(crate::work::WorkError::ProjectNotFound(_)) => problem_response(StatusCode::NOT_FOUND, "project not found"),
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

pub(super) async fn patch_work(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<UpdateWorkBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["facts:write"]) {
        return problem.into_response();
    }
    // Look up the calling passport's gate flag to decide whether state moves are gated.
    let mut store = state.fact_store.write().await;
    let passport_gated = crate::passports::get_passport(&store, &body.by_passport).is_some_and(|p| p.agent_work_gate);
    let result = crate::work::update_work(
        &mut store,
        &id,
        crate::work::UpdateWorkInput {
            title: body.title,
            body: body.body,
            state: body.state,
            assignee_passport: body.assignee_passport,
            tenant_id: body.tenant_id,
            linked_pr: body.linked_pr,
            linked_issue: body.linked_issue,
            blocker_reason: body.blocker_reason,
            blocker_kind: body.blocker_kind,
        },
        crate::work::UpdateWorkContext {
            by_passport: body.by_passport,
            passport_gated,
            now_unix_ms: now_unix_ms(),
        },
    );
    drop(store);
    match result {
        Ok(crate::work::UpdateOutcome::Applied(w)) => {
            (StatusCode::OK, Json(serde_json::json!({"applied": true, "work": w}))).into_response()
        }
        Ok(crate::work::UpdateOutcome::Queued(p)) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({"applied": false, "queued": p})),
        )
            .into_response(),
        Err(crate::work::WorkError::NotFound(_)) => problem_response(StatusCode::NOT_FOUND, "work item not found"),
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

pub(super) async fn post_comment(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<CommentBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["facts:write"]) {
        return problem.into_response();
    }
    if body.body.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "comment body must not be empty");
    }
    let mut store = state.fact_store.write().await;
    let result = crate::work::add_comment(&mut store, &id, &body.author_passport, &body.body, now_unix_ms());
    drop(store);
    match result {
        Ok(c) => (StatusCode::CREATED, Json(c)).into_response(),
        Err(crate::work::WorkError::NotFound(_)) => problem_response(StatusCode::NOT_FOUND, "work item not found"),
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

pub(super) async fn get_comments(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let comments = crate::work::list_comments(&store, &id);
    drop(store);
    (
        StatusCode::OK,
        Json(serde_json::json!({"work_id": id, "comments": comments})),
    )
        .into_response()
}

pub(super) async fn get_transitions(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let txns = crate::work::list_transitions(&store, &id);
    drop(store);
    (
        StatusCode::OK,
        Json(serde_json::json!({"work_id": id, "transitions": txns})),
    )
        .into_response()
}

pub(super) async fn get_pending_gates(
    State(state): State<AppState>,
    Query(q): Query<GateListQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let pending = crate::work::list_pending_gates(&store, q.by_passport.as_deref());
    drop(store);
    (
        StatusCode::OK,
        Json(serde_json::json!({"count": pending.len(), "pending": pending})),
    )
        .into_response()
}

pub(super) async fn post_gate_approve(
    State(state): State<AppState>,
    Path(action_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<GateResolutionBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::work::resolve_gate(&mut store, &action_id, &body.approver_passport, true, now_unix_ms());
    drop(store);
    match result {
        Ok(w) => (StatusCode::OK, Json(w)).into_response(),
        Err(crate::work::WorkError::GateNotFound(_)) => {
            problem_response(StatusCode::NOT_FOUND, "gated action not found")
        }
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

pub(super) async fn post_gate_reject(
    State(state): State<AppState>,
    Path(action_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<GateResolutionBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::work::resolve_gate(&mut store, &action_id, &body.approver_passport, false, now_unix_ms());
    drop(store);
    match result {
        Ok(w) => (StatusCode::OK, Json(w)).into_response(),
        Err(crate::work::WorkError::GateNotFound(_)) => {
            problem_response(StatusCode::NOT_FOUND, "gated action not found")
        }
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}
