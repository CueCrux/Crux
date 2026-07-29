// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP CRUD for work items, comments, transitions, and gated actions.

#![allow(clippy::option_option)] // PATCH tri-state semantics

use super::{
    problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Path, Query, Response, State,
    StatusCode,
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
    /// Ready-order projection. When true the response is narrowed to open work
    /// (`planned` / `in_progress` / `blocked` / `drafting`) and sorted into a
    /// recommended order by [`crate::work_execplans::rank_open`]. Additive:
    /// omitting it preserves the historical unranked, unfiltered response
    /// exactly, so existing clients are unaffected.
    #[serde(default, deserialize_with = "deserialize_flexible_bool")]
    pub ranked: bool,
    /// Cap the number of returned work items. Applied after ranking, so
    /// `?ranked=1&limit=20` yields the top twenty. Approvals are not truncated.
    #[serde(default)]
    pub limit: Option<usize>,
    /// `slim` emits five fields per item (id, state, current_milestone,
    /// milestones_done, milestones_total) plus `blocked_by` when non-empty.
    /// The full board is ~192k tokens; slim + ranked + limit=20 is under 1k,
    /// which is what makes this readable on every agent boot.
    #[serde(default)]
    pub fields: Option<String>,
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
    /// In an enforcing auth mode this is a legacy hint that must match the
    /// authenticated passport. In auth-off mode it is the operator's
    /// self-asserted identity and is persisted with an unverified actor tag.
    #[serde(default)]
    pub approver_passport: Option<String>,
}

#[derive(Debug, serde::Serialize)]
struct GateResolutionResponse {
    #[serde(flatten)]
    work: crate::work::WorkItem,
    receipt_id: String,
    receipt_record_id: String,
    receipt_session_id: String,
}

pub(super) use super::approval_receipts::{
    APPROVAL_RECEIPT_SESSION as WORK_GATE_RECEIPT_SESSION, UNVERIFIED_APPROVER_PREFIX as AUTH_OFF_APPROVER_PREFIX,
};

#[derive(Debug, serde::Deserialize)]
pub(super) struct GateListQuery {
    pub by_passport: Option<String>,
}

/// Query-string booleans, permissively. Bare `serde` accepts only `true`/`false`,
/// so `?ranked=1` — the form every caller reaches for, and the one the docs and
/// agent instructions use — 400s. Accept the usual truthy/falsey spellings, and
/// treat a valueless `?ranked` as true.
fn deserialize_flexible_bool<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;
    let raw = String::deserialize(deserializer)?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(serde::de::Error::custom(format!(
            "expected a boolean (1/true/yes/on or 0/false/no/off), got '{other}'"
        ))),
    }
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

#[tracing::instrument(level = "info", skip_all)]
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

    // Ready-order projection. Narrow to open work, sort by `rank_open`, stamp
    // `blocked_by`. Everything below this point is skipped when `ranked` is
    // absent, which is what keeps the default response byte-identical.
    let mut cycles: Vec<String> = Vec::new();
    if q.ranked {
        let ranked = crate::work_execplans::rank_open(&items);
        cycles = ranked.cycles;
        let mut reordered = Vec::with_capacity(ranked.order.len());
        for (rank_pos, &idx) in ranked.order.iter().enumerate() {
            let mut item = items[idx].clone();
            item.blocked_by.clone_from(&ranked.blocked_by[rank_pos]);
            reordered.push(item);
        }
        items = reordered;
    }

    if let Some(limit) = q.limit {
        items.truncate(limit);
    }

    let slim = q.fields.as_deref() == Some("slim");
    let work_json: serde_json::Value = if slim {
        serde_json::Value::Array(
            items
                .iter()
                .map(|w| {
                    let mut o = serde_json::Map::new();
                    o.insert("id".into(), serde_json::json!(w.id));
                    o.insert("state".into(), serde_json::json!(w.state));
                    if let Some(m) = &w.current_milestone {
                        o.insert("current_milestone".into(), serde_json::json!(m));
                    }
                    if let Some(d) = w.milestones_done {
                        o.insert("milestones_done".into(), serde_json::json!(d));
                    }
                    if let Some(t) = w.milestones_total {
                        o.insert("milestones_total".into(), serde_json::json!(t));
                    }
                    if !w.blocked_by.is_empty() {
                        o.insert("blocked_by".into(), serde_json::json!(w.blocked_by));
                    }
                    serde_json::Value::Object(o)
                })
                .collect(),
        )
    } else {
        serde_json::json!(items)
    };

    let mut body = serde_json::json!({
        "count": items.len() + approval_count,
        "source": match q.source {
            WorkSource::Kanban => "kanban",
            WorkSource::Execplans => "execplans",
            WorkSource::All => "all",
        },
        "work": work_json,
        "approvals": approval_entries,
    });
    if q.ranked {
        body["ranked"] = serde_json::json!(true);
        // A dependency cycle makes "foundations first" undefined for the plans
        // involved. Surface it rather than resolving it silently — the drift
        // check turns this into an operator-visible finding.
        if !cycles.is_empty() {
            body["dependency_cycles"] = serde_json::json!(cycles);
        }
    }

    (StatusCode::OK, Json(body)).into_response()
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

#[tracing::instrument(level = "info", skip_all)]
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

#[tracing::instrument(level = "info", skip_all)]
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

#[tracing::instrument(level = "info", skip_all)]
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

#[tracing::instrument(level = "info", skip_all)]
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

#[tracing::instrument(level = "info", skip_all)]
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

#[tracing::instrument(level = "info", skip_all)]
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

#[tracing::instrument(level = "info", skip_all)]
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

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_gate_approve(
    State(state): State<AppState>,
    Path(action_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<GateResolutionBody>,
) -> impl IntoResponse {
    resolve_gate_http(&state, &action_id, &headers, &body, true).await
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_gate_reject(
    State(state): State<AppState>,
    Path(action_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<GateResolutionBody>,
) -> impl IntoResponse {
    resolve_gate_http(&state, &action_id, &headers, &body, false).await
}

async fn resolve_gate_http(
    state: &AppState,
    action_id: &str,
    headers: &HeaderMap,
    body: &GateResolutionBody,
    approve: bool,
) -> axum::response::Response {
    // This is intentionally independent of route_auth: its default posture is
    // shadow. Enforcing modes retain the hard boundary; auth-off uses an
    // explicitly unverified operator attribution instead.
    let context = match crate::auth::passport_bound_context(&state.auth, headers) {
        Ok(context) => context,
        Err(problem) => return problem.into_response(),
    };
    let (asserted_approver, approver_actor) = if context.auth_enforced() {
        if context.passport_override_used() {
            return problem_response(
                StatusCode::FORBIDDEN,
                "passport impersonation is not permitted for gate resolution",
            );
        }
        if !context.has_scope("facts:write") {
            return problem_response(StatusCode::FORBIDDEN, "facts:write scope required for gate resolution");
        }
        let Some(approver_passport) = context.passport_id.as_deref() else {
            return problem_response(
                StatusCode::FORBIDDEN,
                "an authenticated passport is required for gate resolution",
            );
        };
        if body
            .approver_passport
            .as_deref()
            .is_some_and(|claimed| claimed != approver_passport)
        {
            return problem_response(
                StatusCode::FORBIDDEN,
                "approver_passport does not match the authenticated passport",
            );
        }
        (approver_passport.to_string(), approver_passport.to_string())
    } else {
        let Some(approver_passport) = body
            .approver_passport
            .as_deref()
            .map(str::trim)
            .filter(|claimed| !claimed.is_empty())
        else {
            return problem_response(
                StatusCode::BAD_REQUEST,
                "approver_passport is required in auth-off mode",
            );
        };
        (
            approver_passport.to_string(),
            format!("{AUTH_OFF_APPROVER_PREFIX}{approver_passport}"),
        )
    };

    // Keep target inspection, tenant authorization, receipt persistence, and
    // resolution under one write guard. That serializes concurrent decisions
    // and prevents a work tenant change between authorization and commit.
    let mut store = state.fact_store.write().await;
    let target = match crate::work::gate_resolution_target(&store, action_id) {
        Ok(target) => target,
        Err(err) => return gate_error_response(err),
    };
    if let Err(problem) =
        crate::auth::require_http_scopes_for_tenant(&state.auth, headers, &["facts:write"], &target.tenant_id)
    {
        return problem.into_response();
    }
    if target.tenant_mismatch {
        return gate_error_response(crate::work::WorkError::GateTenantChanged(action_id.to_string()));
    }
    if target.gate.status != "pending" {
        return gate_error_response(crate::work::WorkError::GateAlreadyResolved(action_id.to_string()));
    }
    if target.gate.requested_by_passport == asserted_approver {
        return problem_response(
            StatusCode::FORBIDDEN,
            "the requesting passport cannot resolve its own gate",
        );
    }

    let receipt = match mint_gate_receipt(state, &target, &approver_actor, approve) {
        Ok(receipt) => receipt,
        Err((status, detail)) => return problem_response(status, detail),
    };
    let result = crate::work::resolve_gate(
        &mut store,
        action_id,
        &approver_actor,
        &receipt.receipt_id,
        approve,
        now_unix_ms(),
    );
    drop(store);

    match result {
        Ok(work) => (
            StatusCode::OK,
            Json(GateResolutionResponse {
                work,
                receipt_id: receipt.receipt_id,
                receipt_record_id: receipt.observation_id,
                receipt_session_id: WORK_GATE_RECEIPT_SESSION.to_string(),
            }),
        )
            .into_response(),
        Err(err) => gate_error_response(err),
    }
}

fn gate_error_response(err: crate::work::WorkError) -> axum::response::Response {
    match err {
        crate::work::WorkError::GateNotFound(_) => problem_response(StatusCode::NOT_FOUND, "gated action not found"),
        crate::work::WorkError::GateAlreadyResolved(_) => {
            problem_response(StatusCode::CONFLICT, "gated action is already resolved")
        }
        crate::work::WorkError::GateTenantChanged(_) => problem_response(
            StatusCode::CONFLICT,
            "gated action tenant no longer matches its work item",
        ),
        crate::work::WorkError::NotFound(_) => problem_response(StatusCode::NOT_FOUND, "work item not found"),
        crate::work::WorkError::Io(_) | crate::work::WorkError::Json(_) => {
            problem_response(StatusCode::INTERNAL_SERVER_ERROR, "gate resolution persistence failed")
        }
        err => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

fn mint_gate_receipt(
    state: &AppState,
    target: &crate::work::GateResolutionTarget,
    approver_passport: &str,
    approve: bool,
) -> Result<super::approval_receipts::MintedApprovalReceipt, (StatusCode, String)> {
    use corecrux_receipts::ApprovalDecisionV1;

    let receipt_id = format!("ad_{}", target.gate.action_id);
    let decision = if approve {
        ApprovalDecisionV1::Approve
    } else {
        ApprovalDecisionV1::Reject
    };
    let target_state = target.gate.target_state.as_deref().unwrap_or("unchanged");
    let action_summary = format!(
        "work:{}:{}:{}",
        target.work.id, target.gate.requested_action, target_state
    );
    let mut envelope_fields = serde_json::Map::new();
    envelope_fields.insert("work_id".to_string(), serde_json::Value::String(target.work.id.clone()));
    super::approval_receipts::mint_or_load_approval_receipt(
        state,
        &super::approval_receipts::ApprovalReceiptSpec {
            receipt_id: &receipt_id,
            tenant_id: &target.tenant_id,
            request_id: &target.gate.action_id,
            action_summary: &action_summary,
            envelope_fields,
        },
        approver_passport,
        decision,
    )
    .map_err(|failure| (failure.status, failure.detail))
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct StatusFeedQuery {
    /// Optional single-work-item filter; omit to span every item.
    pub work_id: Option<String>,
    /// Max events returned (most recent kept). Defaults to 200.
    pub limit: Option<usize>,
}

/// `GET /v1/status-feed` — the Open Engine 6-state glance feed (M3).
///
/// Flag-gated behind `CORECRUXD_FEATURE_STATUS_FEED` (default OFF). When off,
/// returns a 200 disabled-notice (mirroring the `context_custody_audit`
/// handler-gate idiom) rather than an error, so clients can probe it safely.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_status_feed(
    State(state): State<AppState>,
    Query(q): Query<StatusFeedQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    if !crate::status_feed::status_feed_enabled() {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "enabled": false,
                "feature_flag": crate::status_feed::STATUS_FEED_FLAG_ENV,
                "note": format!(
                    "status feed is disabled; set {}=1 to enable",
                    crate::status_feed::STATUS_FEED_FLAG_ENV
                ),
                "events": [],
            })),
        )
            .into_response();
    }
    let limit = q.limit.unwrap_or(200).clamp(1, 2000);
    let store = state.fact_store.read().await;
    let events = crate::status_feed::status_feed(&store, q.work_id.as_deref(), limit);
    drop(store);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "enabled": true, "events": events })),
    )
        .into_response()
}

/// `POST /v1/execplans/refresh` — pull the git-backed projection root to the
/// remote branch tip, on demand.
///
/// The board is a read-time projection over a directory, so "the plan I just
/// pushed is not on the board" has exactly one cause: the replica has not
/// fetched yet. This is the operator's and the write tool's answer to that,
/// without waiting for the periodic task.
///
/// Returns `409` when git backing is not configured, so a caller can tell
/// "not configured" apart from "configured and failed" (which is `200` with an
/// `error` in the outcome — the replica is intact either way, and the
/// distinction matters when deciding whether to retry).
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_execplans_refresh(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // Pulling rewrites the projection root, so this is an admin-write action
    // even though it mutates nothing the daemon owns.
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let Some(cfg) = crate::execplan_git::git_config_from_env() else {
        return problem_response(
            StatusCode::CONFLICT,
            format!(
                "ExecPlan git backing is not configured — set {} (and {} / {})",
                crate::execplan_git::GIT_REMOTE_ENV,
                crate::execplan_git::GIT_BRANCH_ENV,
                crate::execplan_git::GIT_INTERVAL_ENV
            ),
        );
    };
    // The CHECKOUT is the repository; the projection root is normally a
    // subdirectory of it. Refreshing the root instead of the checkout is the
    // misconfiguration this module warns about, so the route must not make it.
    let Some(checkout) = crate::execplan_git::checkout_path_from_env() else {
        return problem_response(
            StatusCode::CONFLICT,
            format!(
                "ExecPlan root is not configured — set CRUX_EXECPLANS_ROOT (and {} when the repo \
                 root is not the plans directory)",
                crate::execplan_git::GIT_CHECKOUT_ENV
            ),
        );
    };
    // `git` is blocking; keep it off the async runtime.
    let outcome = match tokio::task::spawn_blocking(move || crate::execplan_git::refresh(&cfg, &checkout)).await {
        Ok(o) => o,
        Err(e) => {
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("refresh task failed: {e}"));
        }
    };
    (StatusCode::OK, Json(serde_json::json!({ "refresh": outcome }))).into_response()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct WriteExecplanBody {
    pub slug: String,
    pub content: String,
    /// Lost-update guard. Omit to create (fails if the plan exists); supply the
    /// plan's current `plan_content_hash` to update it.
    #[serde(default)]
    pub expected_content_hash: Option<String>,
    /// Push after committing. Defaults to false — pushing is outward-facing, so
    /// it is opt-in per call rather than ambient.
    #[serde(default)]
    pub push: bool,
    #[serde(default, alias = "author_passport", alias = "by_passport")]
    pub author: Option<String>,
}

/// `POST /v1/execplans` — the one legal write path for a plan.
///
/// Validates against the `PLANS.md` skeleton, writes into the git checkout, and
/// commits **that single file**. Existed because the projection is read-only:
/// an agent without a checkout had no way to author a plan, which is how three
/// plans came to exist on the live host in no git repository at all.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_execplan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<WriteExecplanBody>,
) -> Response {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let Some(checkout) = crate::execplan_git::checkout_path_from_env() else {
        return problem_response(
            StatusCode::CONFLICT,
            "ExecPlan root is not configured — set CRUX_EXECPLANS_ROOT".to_string(),
        );
    };
    // The plans directory relative to the checkout. When the root IS the
    // checkout this is empty, which `join` handles as "write at the top level".
    let subdir = crate::work_execplans::execplans_root_from_env()
        .and_then(|root| root.strip_prefix(&checkout).ok().map(|p| p.to_path_buf()))
        .unwrap_or_default();

    let result = tokio::task::spawn_blocking(move || {
        crate::execplan_git::write_plan(
            &checkout,
            &subdir,
            &body.slug,
            &body.content,
            body.expected_content_hash.as_deref(),
            body.push,
            body.author.as_deref(),
        )
    })
    .await;

    match result {
        Ok(Ok(outcome)) => (StatusCode::OK, Json(serde_json::json!({ "execplan": outcome }))).into_response(),
        Ok(Err(crate::execplan_git::WriteError::Invalid(m))) => problem_response(StatusCode::BAD_REQUEST, m),
        Ok(Err(crate::execplan_git::WriteError::Conflict { message, current_hash })) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "type": "https://errors.cuecrux.com/conflict",
                "title": "Conflict",
                "status": 409,
                "detail": message,
                // Hand back the current hash so the caller can re-read, merge and
                // retry against a known base instead of guessing.
                "current_content_hash": current_hash,
            })),
        )
            .into_response(),
        Ok(Err(crate::execplan_git::WriteError::Failed(m))) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, m),
        Err(e) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("write task failed: {e}")),
    }
}
