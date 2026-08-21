// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! HTTP CRUD for work items, comments, transitions, and gated actions.

#![allow(clippy::option_option)] // PATCH tri-state semantics

use super::{
    problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Path, Query, Response, State,
    StatusCode,
};

/// The `fields=slim` row: the minimum a client needs to decide what to work on
/// next. Exists because the full board is ~164k tokens and the ranked slim list
/// is ~650, so this projection — not the full row — is what the boot banner and
/// every token-conscious agent actually reads.
///
/// Optional fields are omitted rather than emitted as null, so a row never
/// carries a key that means nothing for its kind.
fn slim_row(w: &crate::work::WorkItem) -> serde_json::Value {
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
    // Staleness is computed on every request (`STALE_AGE_MS`) and `rank_open`
    // already sorts stale-first — but omitting it here meant the signal was
    // computed, ranked on, and then discarded before reaching any client that
    // reads `slim`. Measured 2026-08-06: 37 of 63 `in_progress` plans were
    // stale and not one of them said so on the wire.
    if let Some(s) = w.stale {
        o.insert("stale".into(), serde_json::json!(s));
    }
    serde_json::Value::Object(o)
}

#[cfg(test)]
mod slim_tests {
    use super::slim_row;
    use crate::work::WorkItem;

    fn item(state: &str) -> WorkItem {
        WorkItem {
            id: "execplan:demo-2026-08-06".into(),
            project_id: "execplans".into(),
            state: state.into(),
            title: "demo".into(),
            body: String::new(),
            assignee_passport: None,
            tenant_id: None,
            linked_pr: None,
            linked_issue: None,
            blocker_reason: None,
            blocker_kind: None,
            created_by_passport: "test".into(),
            created_at_unix_ms: 0,
            updated_at_unix_ms: 0,
            plan_path: None,
            plan_content_hash: None,
            current_milestone: None,
            next_ready_milestone: None,
            superseded_by: None,
            depends_on: Vec::new(),
            extended_by: Vec::new(),
            blocked_by: Vec::new(),
            open_decisions: Vec::new(),
            orchestrator_id: None,
            milestones_done: None,
            milestones_total: None,
            notes_count: None,
            provenance: None,
            stale: None,
            token_burn: None,
        }
    }

    /// The regression this milestone exists for: `stale` is computed and ranked
    /// on, and used to be dropped before it reached any `slim` client.
    #[test]
    fn slim_row_carries_stale_when_the_projection_set_it() {
        let mut w = item("in_progress");
        w.stale = Some(true);
        assert_eq!(
            slim_row(&w).get("stale").and_then(serde_json::Value::as_bool),
            Some(true)
        );

        w.stale = Some(false);
        assert_eq!(
            slim_row(&w).get("stale").and_then(serde_json::Value::as_bool),
            Some(false),
            "a fresh in_progress plan must say so explicitly — absent would read as unknown"
        );
    }

    /// `None` means "this flag is meaningless here" (kanban items, terminal
    /// states). Emitting `null` would grow every row on the board's hottest
    /// projection for no information.
    #[test]
    fn slim_row_omits_stale_when_unset() {
        assert!(
            !slim_row(&item("planned"))
                .as_object()
                .is_some_and(|o| o.contains_key("stale")),
            "unset staleness must be omitted, not null"
        );
    }

    /// Guards the rest of the contract: adding a field must not drop or rename
    /// one. These six are what the boot banner and `ep board` parse.
    #[test]
    fn slim_row_keeps_its_existing_keys() {
        let mut w = item("in_progress");
        w.current_milestone = Some("M3".into());
        w.milestones_done = Some(3);
        w.milestones_total = Some(5);
        w.blocked_by = vec!["execplan:other".into()];
        let v = slim_row(&w);
        let o = v.as_object().expect("slim row is an object");
        for k in [
            "id",
            "state",
            "current_milestone",
            "milestones_done",
            "milestones_total",
            "blocked_by",
        ] {
            assert!(o.contains_key(k), "slim row lost `{k}`");
        }
        assert!(
            !o.contains_key("body") && !o.contains_key("provenance"),
            "slim must stay slim — the full board is ~164k tokens for this reason"
        );
    }
}

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

/// `Default` is what the attention roll-up constructs against — it needs the
/// unfiltered, unranked board and only ever sets `project_id`, so every other
/// field must default to "as if the caller omitted it". `WorkSource::All`
/// already defaults that way.
#[derive(Debug, Default, serde::Deserialize)]
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
    /// Legacy identity hint. In an enforcing auth mode it may be omitted and,
    /// when present, must match the authenticated passport. Auth-off mode
    /// requires it and persists an explicitly unverified actor tag.
    #[serde(default, alias = "by_passport", alias = "author_passport")]
    pub created_by_passport: Option<String>,
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
    /// Legacy identity hint; authority comes from the authenticated context.
    #[serde(default, alias = "created_by_passport", alias = "author_passport")]
    pub by_passport: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct CommentBody {
    /// Legacy identity hint; authority comes from the authenticated context.
    #[serde(default, alias = "by_passport", alias = "created_by_passport")]
    pub author_passport: Option<String>,
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
    pub tenant_id: Option<String>,
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

struct ResolvedWorkActor {
    context: crate::auth::HttpScopeContext,
    /// Durable actor/user-facing passport field. Auth-off assertions carry an
    /// explicit prefix so they cannot be confused with verified passports.
    actor_id: String,
    /// Raw passport id used only to look up the agent-work-gate policy.
    passport_lookup_id: String,
}

#[allow(clippy::result_large_err)]
pub(super) fn work_scope_context(
    state: &AppState,
    headers: &HeaderMap,
    required_scope: &str,
) -> Result<crate::auth::HttpScopeContext, Response> {
    let context = crate::auth::passport_bound_context(&state.auth, headers).map_err(IntoResponse::into_response)?;
    if !context.has_scope(required_scope) {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            format!("{required_scope} scope required for work access"),
        ));
    }
    Ok(context)
}

#[allow(clippy::result_large_err)]
fn resolve_work_actor(
    state: &AppState,
    headers: &HeaderMap,
    hint: Option<&str>,
) -> Result<ResolvedWorkActor, Response> {
    let context = work_scope_context(state, headers, "facts:write")?;
    let hint = hint.map(str::trim).filter(|value| !value.is_empty());
    if !context.local_unverified_identity() {
        if context.passport_override_used() {
            return Err(problem_response(
                StatusCode::FORBIDDEN,
                "passport impersonation is not permitted for work mutations",
            ));
        }
        let Some(passport_id) = context.passport_id.as_deref() else {
            return Err(problem_response(
                StatusCode::FORBIDDEN,
                "an authenticated passport is required for work mutations",
            ));
        };
        if hint.is_some_and(|claimed| claimed != passport_id) {
            return Err(problem_response(
                StatusCode::FORBIDDEN,
                "body passport does not match the authenticated passport",
            ));
        }
        Ok(ResolvedWorkActor {
            actor_id: passport_id.to_string(),
            passport_lookup_id: passport_id.to_string(),
            context,
        })
    } else {
        let header_hint = context.passport_id.as_deref();
        if let (Some(body_hint), Some(header_hint)) = (hint, header_hint) {
            if body_hint != header_hint {
                return Err(problem_response(
                    StatusCode::FORBIDDEN,
                    "body passport does not match the local identity assertion header",
                ));
            }
        }
        let Some(asserted) = hint.or(header_hint) else {
            return Err(problem_response(
                StatusCode::BAD_REQUEST,
                "an explicit passport identity assertion is required in local unverified mode",
            ));
        };
        Ok(ResolvedWorkActor {
            actor_id: format!("{AUTH_OFF_APPROVER_PREFIX}{asserted}"),
            passport_lookup_id: asserted.to_string(),
            context,
        })
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_work(
    State(state): State<AppState>,
    Query(q): Query<ListWorkQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let context = match work_scope_context(&state, &headers, "admin:read") {
        Ok(context) => context,
        Err(response) => return response,
    };
    let tenant_id = match context.resolve_authorized_tenant(q.tenant_id.as_deref()) {
        Ok(tenant_id) => tenant_id,
        Err(problem) => return problem.into_response(),
    };
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

    let kanban_items = kanban_items_for_query(&store, &q, &tenant_id);
    let mut execplan_items = if matches!(q.source, WorkSource::Execplans | WorkSource::All) {
        execplan_items_for_query(&store, &q, &tenant_id)
    } else {
        Vec::new()
    };

    // Orchestrator filter (agent-graph). Stamp `orchestrator_id` on the
    // ExecPlan items that are members of the requested orchestrator (kanban
    // items already carry it from the membership write path), then below we
    // keep only items whose `orchestrator_id` matches.
    let requested_orchestrator_members = if let Some(orc_id) = q.orchestrator.as_deref() {
        if orc_id == crate::work_execplans::default_orchestrator_id() {
            None
        } else {
            let estore = state.entity_store.read().await;
            let member_ids = crate::http::orchestrators::orchestrator_member_refs(&estore, orc_id, &tenant_id);
            drop(estore);
            crate::work_execplans::stamp_orchestrator_id(&mut execplan_items, &member_ids, orc_id);
            Some(member_ids)
        }
    } else {
        None
    };
    drop(store);

    // Per-ExecPlan token-burn rollup: join the cost lens (one report per coding
    // session, keyed by transcript UUID) onto the ExecPlan items at read time
    // (window-overlap + passport-refine; see `crate::cost_attribution`). Gated by
    // the cost-lens flag so the daemon is byte-identical when it's off, and
    // skipped when there are no ExecPlan items to stamp. Cost reports are
    // per-tenant; attribute the requested tenant's (default `default`).
    if crate::cost::cost_lens_enabled() && !execplan_items.is_empty() {
        let reports = {
            let cstore = crate::cost::global().lock().await;
            cstore.reports_for_tenant(&tenant_id)
        };
        let sessions = crate::cost_attribution::session_burns_from_reports(&reports);
        crate::cost_attribution::stamp_token_burn(&mut execplan_items, &sessions);
    }

    let mut items = merge_work_sources(kanban_items, execplan_items);

    // Orchestration is the parent, so make the relationship TOTAL: anything no
    // orchestrator claims belongs to the default one. This runs BEFORE the
    // filter, so `?orchestrator=orchestrator:unassigned` is a real query — "what
    // is nobody looking after" — rather than a hole in the data.
    crate::work_execplans::apply_default_orchestrator(&mut items, &crate::work_execplans::default_orchestrator_id());

    // Apply the orchestrator filter so it intersects both kanban + execplan sources.
    if let Some(orc_id) = q.orchestrator.as_deref() {
        if let Some(member_ids) = requested_orchestrator_members.as_ref() {
            items.retain(|work| member_ids.contains(&work.id));
        } else {
            items.retain(|work| work.orchestrator_id.as_deref() == Some(orc_id));
        }
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
    approval_entries.retain(|entry| {
        entry
            .get("tenant_id")
            .and_then(|value| value.as_str())
            .unwrap_or("default")
            == tenant_id
    });
    let approval_count = approval_entries.len();

    // Ready-order projection. Narrow to open work, sort by `rank_open`, stamp
    // `blocked_by`. Everything below this point is skipped when `ranked` is
    // absent, which is what keeps the default response byte-identical.
    let mut cycles: Vec<String> = Vec::new();
    let mut inverted: Vec<String> = Vec::new();
    if q.ranked {
        let ranked = crate::work_execplans::rank_open(&items);
        cycles = ranked.cycles;
        inverted = ranked.inverted_orchestrator_edges;
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
        serde_json::Value::Array(items.iter().map(slim_row).collect())
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
        // Actionable half of a cycle report: an orchestrator is a parent, so an
        // orchestrator depending outward names the exact `Depends on` line to
        // flip. "There is a cycle" is a problem; this is a fix.
        if !inverted.is_empty() {
            body["inverted_orchestrator_edges"] = serde_json::json!(inverted);
        }
    }

    (StatusCode::OK, Json(body)).into_response()
}

/// Build the kanban slice of the response.
///
/// Extracted, with [`merge_work_sources`], so the attention roll-up
/// (`GET /v1/attention/summary`) derives its counts from the *same* item set
/// this endpoint returns. Two surfaces quoting different numbers for one daemon
/// is a discrepancy an operator cannot diagnose from either one, and a
/// duplicated source-merge is how that happens.
///
/// `tenant_id` is the **authenticated** tenant, resolved by the caller through
/// `resolve_authorized_tenant`. It is deliberately a parameter rather than
/// `q.tenant_id`: the query string is caller-supplied, so reading it here
/// would let any reader enumerate another tenant's work items by asking. Every
/// caller must therefore prove which tenant it is answering for.
pub(super) fn kanban_items_for_query(
    store: &corecrux_memory::FactStore,
    q: &ListWorkQuery,
    tenant_id: &str,
) -> Vec<crate::work::WorkItem> {
    if !matches!(q.source, WorkSource::Kanban | WorkSource::All) {
        return Vec::new();
    }
    crate::work::list_work(
        store,
        q.project_id.as_deref(),
        q.state.as_deref(),
        Some(tenant_id),
        q.assignee_passport.as_deref(),
    )
}

/// Merge: kanban first (wins on id collision), then ExecPlan items not already
/// present. ExecPlan ids are namespaced (`execplan:<slug>`) so collisions are
/// not expected in practice — the dedup is defence in depth.
pub(super) fn merge_work_sources(
    kanban_items: Vec<crate::work::WorkItem>,
    execplan_items: Vec<crate::work::WorkItem>,
) -> Vec<crate::work::WorkItem> {
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
    items
}

/// Build the ExecPlan slice of the response. Applies the same state /
/// tenant / assignee filters that kanban uses so `?source=all&state=planned`
/// returns a coherent merged list.
pub(super) fn execplan_items_for_query(
    store: &corecrux_memory::fact_store::FactStore,
    q: &ListWorkQuery,
    tenant_id: &str,
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
    //
    // The same argument decides `tenant_id`, and getting it wrong took the
    // board out entirely: the projection walks plan *files* under one root and
    // stamps every item `tenant_id: None` (`work_execplans.rs`), so a flat
    // `work_tenant_id(w) == tenant_id` compares "default" against the caller's
    // tenant and drops all of them — as `200 {"count":0}`, indistinguishable
    // from an empty backlog or an unconfigured root. Any token whose tenant
    // claim is not `default` saw an empty board, on `/v1/work` and on
    // `/v1/attention/summary` alike.
    //
    // Tenant binding on the kanban path is deliberate and stays (it is what
    // stops one tenant's rows being counted into another's roll-up); it was
    // never load-bearing here, because these items carry no tenant to bind.
    // So filter only the items that actually declare one — that keeps the
    // narrowing for any future tenant-stamped plan while letting the
    // workspace-scoped ones through.
    filter_execplan_items(items, q, tenant_id)
}

/// The post-walk narrowing for projected ExecPlan items, split out so the
/// tenant rule can be asserted without a plan root on disk or process env.
pub(super) fn filter_execplan_items(
    items: Vec<crate::work::WorkItem>,
    q: &ListWorkQuery,
    tenant_id: &str,
) -> Vec<crate::work::WorkItem> {
    items
        .into_iter()
        .filter(|w| {
            q.state.as_deref().is_none_or(|s| w.state == s)
                && w.tenant_id.as_deref().is_none_or(|t| t == tenant_id)
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
    let context = match work_scope_context(&state, &headers, "admin:read") {
        Ok(context) => context,
        Err(response) => return response,
    };
    let store = state.fact_store.read().await;
    let item = crate::work::get_work(&store, &id);
    if let Some(item) = item.as_ref() {
        if let Err(problem) = context.resolve_authorized_tenant(Some(crate::work::work_tenant_id(item))) {
            return problem.into_response();
        }
    }
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
    let actor = match resolve_work_actor(&state, &headers, body.created_by_passport.as_deref()) {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    let tenant_id = match actor.context.resolve_authorized_tenant(body.tenant_id.as_deref()) {
        Ok(tenant_id) => tenant_id,
        Err(problem) => return problem.into_response(),
    };
    let mut store = state.fact_store.write().await;
    if body.state.as_deref().is_some_and(|state| state != "planned") {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "work must be created in the planned state and transitioned separately",
        );
    }
    let result = crate::work::create_work(
        &mut store,
        crate::work::CreateWorkInput {
            project_id: body.project_id,
            title: body.title,
            body: body.body,
            state: body.state,
            assignee_passport: body.assignee_passport,
            tenant_id: Some(tenant_id),
            linked_pr: body.linked_pr,
            linked_issue: body.linked_issue,
            created_by_passport: actor.actor_id,
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
    let actor = match resolve_work_actor(&state, &headers, body.by_passport.as_deref()) {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    // Target lookup, tenant authorization, gate-policy lookup, and mutation
    // share one write guard so the authorization decision cannot race a rewrite.
    let mut store = state.fact_store.write().await;
    let Some(target) = crate::work::get_work(&store, &id) else {
        return problem_response(StatusCode::NOT_FOUND, "work item not found");
    };
    if let Err(problem) = actor
        .context
        .resolve_authorized_tenant(Some(crate::work::work_tenant_id(&target)))
    {
        return problem.into_response();
    }
    // Local auth-off/DevScopes identities are assertions, not principals.
    // They may never select a known ungated passport to bypass review.
    let passport_gated = actor.context.local_unverified_identity()
        || crate::passports::get_passport(&store, &actor.passport_lookup_id)
            .is_none_or(|passport| passport.agent_work_gate);
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
            by_passport: actor.actor_id,
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
        Err(crate::work::WorkError::TenantImmutable) => {
            problem_response(StatusCode::CONFLICT, "a work item's tenant is immutable")
        }
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
    let actor = match resolve_work_actor(&state, &headers, body.author_passport.as_deref()) {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if body.body.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "comment body must not be empty");
    }
    let mut store = state.fact_store.write().await;
    let Some(target) = crate::work::get_work(&store, &id) else {
        return problem_response(StatusCode::NOT_FOUND, "work item not found");
    };
    if let Err(problem) = actor
        .context
        .resolve_authorized_tenant(Some(crate::work::work_tenant_id(&target)))
    {
        return problem.into_response();
    }
    let result = crate::work::add_comment(&mut store, &id, &actor.actor_id, &body.body, now_unix_ms());
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
    let context = match work_scope_context(&state, &headers, "admin:read") {
        Ok(context) => context,
        Err(response) => return response,
    };
    let store = state.fact_store.read().await;
    let Some(target) = crate::work::get_work(&store, &id) else {
        return problem_response(StatusCode::NOT_FOUND, "work item not found");
    };
    if let Err(problem) = context.resolve_authorized_tenant(Some(crate::work::work_tenant_id(&target))) {
        return problem.into_response();
    }
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
    let context = match work_scope_context(&state, &headers, "admin:read") {
        Ok(context) => context,
        Err(response) => return response,
    };
    let store = state.fact_store.read().await;
    let Some(target) = crate::work::get_work(&store, &id) else {
        return problem_response(StatusCode::NOT_FOUND, "work item not found");
    };
    if let Err(problem) = context.resolve_authorized_tenant(Some(crate::work::work_tenant_id(&target))) {
        return problem.into_response();
    }
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
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let context = match work_scope_context(&state, &headers, "admin:read") {
        Ok(context) => context,
        Err(response) => return response,
    };
    // A local-only daemon has no remote reader to protect from, so the
    // unverified narrowing below is keyed on REACHABILITY, not auth mode
    // (issue #706). Both halves are required: the listener must be
    // loopback-only, and this request must not have come through a proxy.
    let direct_local =
        state.http_bind_loopback && super::ingress::is_direct_loopback_request(&headers, Some(peer.ip()));
    // An oversight queue answers for every tenant the credential is authorized
    // for unless the caller narrows it. Collapsing to one tenant here is what
    // hid pending gates held outside `default` (issue #703).
    let scope = match context.resolve_authorized_tenant_scope(q.tenant_id.as_deref(), direct_local) {
        Ok(scope) => scope,
        Err(problem) => return problem.into_response(),
    };
    let store = state.fact_store.read().await;
    let mut pending = crate::work::list_pending_gates(&store, None, q.by_passport.as_deref());
    drop(store);
    if let Some(allowed) = scope.as_ref() {
        pending.retain(|gate| allowed.iter().any(|tenant| tenant == gate_tenant(gate)));
    }
    // `["*"]` = answered across every tenant. Callers render this verbatim, so
    // an empty queue can never be confused with a queue narrowed to one tenant.
    let tenant_scope = scope.unwrap_or_else(|| vec!["*".to_string()]);
    (
        StatusCode::OK,
        Json(serde_json::json!({"count": pending.len(), "pending": pending, "tenant_scope": tenant_scope})),
    )
        .into_response()
}

/// Gates written before the tenant field existed authorize against `default`,
/// matching [`crate::work::list_pending_gates`].
fn gate_tenant(gate: &crate::work::PendingGateAction) -> &str {
    gate.tenant_id.as_deref().unwrap_or("default")
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_gate_approve(
    State(state): State<AppState>,
    Path(action_id): Path<String>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<GateResolutionBody>,
) -> impl IntoResponse {
    resolve_gate_http(&state, &action_id, &headers, Some(peer.ip()), &body, true).await
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_gate_reject(
    State(state): State<AppState>,
    Path(action_id): Path<String>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<GateResolutionBody>,
) -> impl IntoResponse {
    resolve_gate_http(&state, &action_id, &headers, Some(peer.ip()), &body, false).await
}

async fn resolve_gate_http(
    state: &AppState,
    action_id: &str,
    headers: &HeaderMap,
    peer: Option<std::net::IpAddr>,
    body: &GateResolutionBody,
    approve: bool,
) -> axum::response::Response {
    // This is intentionally independent of route_auth: its default posture is
    // shadow. Enforcing modes retain the hard boundary; auth-off uses an
    // explicitly unverified operator attribution instead. A bearer without a
    // canonical passport claim may still be named by the trusted-proxy
    // identity rail (the proxied-console posture) — see `auth_rails`.
    let context = match super::auth_rails::passport_bound_context_for_human_decision(&state.auth, headers, peer) {
        Ok(context) => context,
        Err(problem) => return problem.into_response(),
    };
    if !context.has_scope("facts:write") {
        return problem_response(StatusCode::FORBIDDEN, "facts:write scope required for gate resolution");
    }
    let (asserted_approver, approver_actor) = if !context.local_unverified_identity() {
        if context.passport_override_used() {
            return problem_response(
                StatusCode::FORBIDDEN,
                "passport impersonation is not permitted for gate resolution",
            );
        }
        if context.credential_is_agent_token() {
            return problem_response(
                StatusCode::FORBIDDEN,
                "an MCP agent token cannot satisfy a human gate decision",
            );
        }
        if !context.canonical_passport_claim_verified() {
            return problem_response(
                StatusCode::FORBIDDEN,
                "a canonical passport_id claim is required for gate resolution",
            );
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
        let body_hint = body
            .approver_passport
            .as_deref()
            .map(str::trim)
            .filter(|claimed| !claimed.is_empty());
        let header_hint = context.passport_id.as_deref();
        if let (Some(body_hint), Some(header_hint)) = (body_hint, header_hint) {
            if body_hint != header_hint {
                return problem_response(
                    StatusCode::FORBIDDEN,
                    "approver_passport does not match the local identity assertion header",
                );
            }
        }
        let Some(approver_passport) = body_hint.or(header_hint) else {
            return problem_response(
                StatusCode::BAD_REQUEST,
                "an explicit approver identity assertion is required in local unverified mode",
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
    if let Err(problem) = context.resolve_authorized_tenant(Some(&target.tenant_id)) {
        return problem.into_response();
    }
    if target.tenant_mismatch {
        return gate_error_response(crate::work::WorkError::GateTenantChanged(action_id.to_string()));
    }
    if target.gate.status != "pending" {
        return gate_error_response(crate::work::WorkError::GateAlreadyResolved(action_id.to_string()));
    }
    // How many DISTINCT PASSPORTS this deployment requires on a gate decision.
    //
    // A hard ban on self-resolution does not produce four-eyes on a deployment
    // with one human in it — it produces a second passport created solely to
    // approve one's own work, which passes this check while making the audit
    // trail *less* honest than admitting single-party approval. So the count is
    // the operator's to set, and whichever way it is set the receipt records
    // what actually happened.
    let required_approvers = required_gate_approvers();
    let self_resolution =
        target.gate.requested_by_passport == asserted_approver || target.gate.requested_by_passport == approver_actor;
    if self_resolution && required_approvers >= 2 {
        return problem_response(
            StatusCode::FORBIDDEN,
            "the requesting passport cannot resolve its own gate (CORECRUXD_WORK_GATE_APPROVERS=2); \
             set it to 1 to permit single-party approval, which is recorded as such on the receipt",
        );
    }

    let separation = GateSeparation {
        required_approvers,
        self_resolution,
    };
    let approver_source = context
        .passport_from_identity_rail()
        .then(super::auth_rails::rail_label);
    let receipt = match mint_gate_receipt(state, &target, &approver_actor, approver_source, approve, separation) {
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

/// Env naming the number of distinct passports a gate decision requires.
pub(super) const WORK_GATE_APPROVERS_ENV: &str = "CORECRUXD_WORK_GATE_APPROVERS";

/// Distinct passports required to resolve a gate: `1` or `2`.
///
/// Anything unset, malformed, or out of range resolves to **2** — the shipped
/// behaviour. A typo must never silently relax a human-oversight boundary, so
/// this fails safe upward rather than towards permissiveness.
pub(super) fn required_gate_approvers() -> u8 {
    match std::env::var(WORK_GATE_APPROVERS_ENV) {
        Ok(raw) => match raw.trim() {
            "1" => 1,
            _ => 2,
        },
        Err(_) => 2,
    }
}

/// What the daemon actually established about separation of duties on one
/// decision. Recorded on the receipt so an auditor never has to infer it.
#[derive(Debug, Clone, Copy)]
pub(super) struct GateSeparation {
    pub required_approvers: u8,
    pub self_resolution: bool,
}

impl GateSeparation {
    /// Distinct passports that took part: 1 when the requester resolved their
    /// own gate, otherwise 2.
    fn parties(self) -> u8 {
        if self.self_resolution {
            1
        } else {
            2
        }
    }

    /// The evidence class, worded for an auditor.
    ///
    /// `distinct_passports` is deliberately NOT called "four eyes": the daemon
    /// verifies that two passports differ, and cannot establish that they belong
    /// to two people. Claiming separation of duties it never proved is the
    /// failure this wording exists to prevent.
    fn evidence(self) -> &'static str {
        if self.self_resolution {
            "none:self_approved"
        } else {
            "distinct_passports"
        }
    }
}

fn mint_gate_receipt(
    state: &AppState,
    target: &crate::work::GateResolutionTarget,
    approver_passport: &str,
    // `Some(rail)` when the approver was named by the trusted-proxy identity
    // rail rather than the bearer's own claims; recorded on the envelope so the
    // provenance of a proxied-console decision is visible to an auditor.
    approver_source: Option<&str>,
    approve: bool,
    separation: GateSeparation,
) -> Result<super::approval_receipts::MintedApprovalReceipt, (StatusCode, String)> {
    use corecrux_receipts::ApprovalDecisionV1;

    let receipt_id = format!("ad_{}", target.gate.action_id);
    let decision = if approve {
        ApprovalDecisionV1::Approve
    } else {
        ApprovalDecisionV1::Reject
    };
    let target_state = target.gate.target_state.as_deref().unwrap_or("unchanged");
    // The separation facts ride the SIGNED `action_summary`, not the envelope:
    // envelope fields are documented as non-authoritative, and "was this really
    // two-party?" is exactly the question an auditor must be able to answer from
    // tamper-evident material. (`action_summary` is also the retry binding, so a
    // policy change between attempts correctly reads as a different decision
    // rather than silently reusing the earlier receipt.)
    let action_summary = format!(
        "work:{}:{}:{}:approvers={}:parties={}:sep={}",
        target.work.id,
        target.gate.requested_action,
        target_state,
        separation.required_approvers,
        separation.parties(),
        separation.evidence(),
    );
    let mut envelope_fields = serde_json::Map::new();
    envelope_fields.insert("work_id".to_string(), serde_json::Value::String(target.work.id.clone()));
    // Mirrored for readability; the signed summary above is authoritative.
    envelope_fields.insert(
        "required_approvers".to_string(),
        serde_json::Value::from(separation.required_approvers),
    );
    envelope_fields.insert("parties".to_string(), serde_json::Value::from(separation.parties()));
    envelope_fields.insert(
        "separation_evidence".to_string(),
        serde_json::Value::String(separation.evidence().to_string()),
    );
    envelope_fields.insert(
        "self_approved".to_string(),
        serde_json::Value::Bool(separation.self_resolution),
    );
    if let Some(source) = approver_source {
        envelope_fields.insert(
            "approver_source".to_string(),
            serde_json::Value::String(source.to_string()),
        );
    }
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
    /// Concrete tenant selector. Multi-tenant tokens must choose one.
    pub tenant_id: Option<String>,
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
    let context = match work_scope_context(&state, &headers, "admin:read") {
        Ok(context) => context,
        Err(response) => return response,
    };
    let tenant_id = match context.resolve_authorized_tenant(q.tenant_id.as_deref()) {
        Ok(tenant_id) => tenant_id,
        Err(problem) => return problem.into_response(),
    };
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
    let visible_work_ids: std::collections::HashSet<String> =
        crate::work::list_work(&store, None, None, Some(&tenant_id), None)
            .into_iter()
            .map(|work| work.id)
            .collect();
    if let Some(work_id) = q.work_id.as_deref() {
        let Some(target) = crate::work::get_work(&store, work_id) else {
            return problem_response(StatusCode::NOT_FOUND, "work item not found");
        };
        if crate::work::work_tenant_id(&target) != tenant_id {
            return problem_response(StatusCode::FORBIDDEN, "work item belongs to another tenant");
        }
    }
    // Project each visible work lane before applying the caller's global cap.
    // Filtering a pre-truncated global feed lets a noisy foreign tenant starve
    // this tenant's events even though no foreign row is returned.
    let mut events = if let Some(work_id) = q.work_id.as_deref() {
        crate::status_feed::status_feed(&store, Some(work_id), limit)
    } else {
        visible_work_ids
            .iter()
            .flat_map(|work_id| crate::status_feed::status_feed(&store, Some(work_id), limit))
            .collect()
    };
    events.sort_by(|left, right| {
        left.at_unix_ms
            .cmp(&right.at_unix_ms)
            .then_with(|| left.transition_id.cmp(&right.transition_id))
    });
    if events.len() > limit {
        events = events.split_off(events.len() - limit);
    }
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

#[cfg(test)]
mod gate_approver_policy_tests {
    use super::*;

    // The policy is read from process env, so these serialise.

    #[test]
    #[serial_test::serial]
    fn default_is_two_distinct_passports() {
        std::env::remove_var(WORK_GATE_APPROVERS_ENV);
        assert_eq!(required_gate_approvers(), 2);
    }

    #[test]
    #[serial_test::serial]
    fn one_is_honoured_for_a_single_human_deployment() {
        std::env::set_var(WORK_GATE_APPROVERS_ENV, " 1 ");
        assert_eq!(required_gate_approvers(), 1);
        std::env::remove_var(WORK_GATE_APPROVERS_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn junk_fails_safe_upward_never_towards_permissiveness() {
        // A typo must not silently relax a human-oversight boundary. Every
        // unparseable value resolves to the stricter setting, including "0",
        // which would otherwise read as "no approver required at all".
        for raw in ["0", "", "   ", "3", "one", "true", "-1", "2x"] {
            std::env::set_var(WORK_GATE_APPROVERS_ENV, raw);
            assert_eq!(required_gate_approvers(), 2, "input {raw:?} must fail safe to 2");
        }
        std::env::remove_var(WORK_GATE_APPROVERS_ENV);
    }

    // ── what the receipt records ──────────────────────────────────────────

    #[test]
    fn a_two_party_decision_records_distinct_passports_and_never_claims_four_eyes() {
        let sep = GateSeparation {
            required_approvers: 2,
            self_resolution: false,
        };
        assert_eq!(sep.parties(), 2);
        assert_eq!(sep.evidence(), "distinct_passports");
        // The daemon cannot establish that two passports are two people, so the
        // wording must never imply it.
        assert!(!sep.evidence().contains("four"));
        assert!(!sep.evidence().contains("human"));
        assert!(!sep.evidence().contains("person"));
    }

    #[test]
    fn a_single_party_decision_is_recorded_as_self_approved_not_hidden() {
        // The whole point: a solo deployment gets an honest receipt instead of
        // an operator minting a second passport to defeat the check, which
        // would record `distinct_passports` for what is really one human.
        let sep = GateSeparation {
            required_approvers: 1,
            self_resolution: true,
        };
        assert_eq!(sep.parties(), 1);
        assert_eq!(sep.evidence(), "none:self_approved");
    }

    #[test]
    fn a_one_policy_deployment_still_records_two_parties_when_two_acted() {
        // Policy 1 is a ceiling on what is REQUIRED, not a claim about what
        // happened: if a second passport did approve, the receipt says so.
        let sep = GateSeparation {
            required_approvers: 1,
            self_resolution: false,
        };
        assert_eq!(sep.parties(), 2);
        assert_eq!(sep.evidence(), "distinct_passports");
    }
}

#[cfg(test)]
mod execplan_tenant_scope_tests {
    use super::{filter_execplan_items, ListWorkQuery, WorkSource};
    use crate::work::WorkItem;

    fn plan(id: &str, tenant_id: Option<&str>) -> WorkItem {
        WorkItem {
            id: id.into(),
            project_id: crate::work_execplans::VIRTUAL_PROJECT_ID.into(),
            state: "in_progress".into(),
            title: id.into(),
            body: String::new(),
            assignee_passport: None,
            tenant_id: tenant_id.map(str::to_string),
            linked_pr: None,
            linked_issue: None,
            blocker_reason: None,
            blocker_kind: None,
            created_by_passport: "test".into(),
            created_at_unix_ms: 0,
            updated_at_unix_ms: 0,
            plan_path: None,
            plan_content_hash: None,
            current_milestone: None,
            next_ready_milestone: None,
            superseded_by: None,
            depends_on: Vec::new(),
            extended_by: Vec::new(),
            blocked_by: Vec::new(),
            open_decisions: Vec::new(),
            orchestrator_id: None,
            milestones_done: None,
            milestones_total: None,
            notes_count: None,
            provenance: None,
            stale: None,
            token_burn: None,
        }
    }

    fn query() -> ListWorkQuery {
        ListWorkQuery {
            source: WorkSource::Execplans,
            ..Default::default()
        }
    }

    /// The regression: the projection stamps `tenant_id: None` on every plan,
    /// so binding it to the caller's tenant hid the entire board from any
    /// token whose claim was not `default` — silently, as an empty 200.
    #[test]
    fn workspace_scoped_plans_are_visible_to_a_non_default_tenant() {
        let items = vec![plan("execplan:alpha", None), plan("execplan:beta", None)];
        let kept = filter_execplan_items(items, &query(), "work");
        assert_eq!(
            kept.len(),
            2,
            "plans carrying no tenant are workspace-scoped and must survive a non-default caller tenant"
        );
    }

    /// Positive control for the narrowing half: a plan that *does* declare a
    /// tenant is still scoped, so the predicate is not vacuously true.
    #[test]
    fn tenant_stamped_plans_are_still_narrowed_to_the_caller() {
        let items = vec![
            plan("execplan:workspace", None),
            plan("execplan:mine", Some("work")),
            plan("execplan:theirs", Some("other")),
        ];
        let kept = filter_execplan_items(items, &query(), "work");
        let ids: Vec<&str> = kept.iter().map(|w| w.id.as_str()).collect();
        assert_eq!(ids, vec!["execplan:workspace", "execplan:mine"]);
    }
}
