// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Work coordination — six-state kanban (Planned · In Progress · Blocked ·
//! Archive · Complete · Deployed) with comments, transitions audit log, and
//! per-passport gating for human-in-the-loop on agent-driven state changes.
//!
//! Storage (everything-as-facts):
//!
//! - `__work__::{project_id}::{work_id}` key=`record` — the work item.
//! - `__work_comment__::{work_id}::{comment_id}` key=`record` — comments.
//! - `__work_transition__::{work_id}::{ts_micros}-{tx_id}` key=`record` — audit.
//! - `__work_gate__::{action_id}` key=`record` — pending gated actions.

#![allow(clippy::option_option)] // PATCH tri-state semantics: outer Some=present, inner None=clear, inner Some=set
#![allow(clippy::assigning_clones)] // plain `x = y.clone()` is more obvious than `clone_from`

use corecrux_memory::fact_store::{FactQuery, FactStore, StoreFact};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const WORK_ENTITY_PREFIX: &str = "__work__";
pub const WORK_COMMENT_ENTITY_PREFIX: &str = "__work_comment__";
pub const WORK_TRANSITION_ENTITY_PREFIX: &str = "__work_transition__";
pub const WORK_GATE_ENTITY_PREFIX: &str = "__work_gate__";
pub const RECORD_KEY: &str = "record";

/// Accepted work states.
///
/// `pending_approval` is the agent-ux-05 risk-tiered HITL state. It does not
/// originate from the kanban write path (`create_work`); it surfaces from
/// the in-memory approval queue managed by
/// [`crux_mcp::tools::approvals`]. Validators accept it so the existing
/// `/v1/work?state=pending_approval` path returns approval entries without
/// rejecting the query.
/// `drafting` is the A4 generative-ExecPlan front-door state: a plan whose
/// markdown declares `Status: Draft` (and the `CORECRUXD_FEATURE_DRAFTING_STATE`
/// flag is on) projects into this state so the board can separate not-yet-ready
/// drafts from `planned` work. It is accepted by the validators so the existing
/// `/v1/work?state=drafting` query path and `update_state` transitions to it
/// resolve without rejecting; the kanban write path never originates it.
pub const WORK_STATES: &[&str] = &[
    "planned",
    "in_progress",
    "blocked",
    "archive",
    "complete",
    "deployed",
    "pending_approval",
    "drafting",
];

#[derive(Debug, thiserror::Error)]
pub enum WorkError {
    #[error("invalid work state '{0}'")]
    InvalidState(String),
    #[error("blocked items must carry a non-empty blocker_reason")]
    MissingBlockerReason,
    #[error("work item '{0}' not found")]
    NotFound(String),
    #[error("project '{0}' not found")]
    ProjectNotFound(String),
    #[error("gated action '{0}' not found")]
    GateNotFound(String),
    #[error("gated action '{0}' is already resolved")]
    GateAlreadyResolved(String),
    #[error("gated action '{0}' tenant no longer matches its work item")]
    GateTenantChanged(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Why a `blocked` work item is paused — Open Engine's "BLOCKED vs HUMAN HOLD"
/// distinction (audit §2.1). `needs_info` is "blocked, waiting on an answer
/// about the task"; `needs_approval` is "blocked, waiting on an owner's
/// go/no-go". The free-text `blocker_reason` still carries the prose; this
/// typed dimension carries the *kind* so a glance feed (M3) can separate the
/// two without parsing English. Decoupled from the gate layer (`agent_work_gate`
/// / `approval_request`): `needs_approval` is a *hint* that an approval is owed,
/// not the gate itself (the gate stays keyed on passport/risk).
///
/// Back-compat: serialised as a snake_case string and `#[serde(default)]` +
/// skip-if-`None` on `WorkItem`, so pre-existing `blocked` rows (no field)
/// deserialise as `None` ("unspecified", read as needs_info) and unknown
/// strings are rejected by serde.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BlockerKind {
    NeedsInfo,
    NeedsApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkItem {
    pub id: String,
    pub project_id: String,
    pub state: String,
    pub title: String,
    #[serde(default)]
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assignee_passport: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_pr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_issue: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocker_reason: Option<String>,
    /// Typed kind of a block (`needs_info` | `needs_approval`); `None` when the
    /// item is not blocked or the block predates this field. Additive +
    /// `#[serde(default)]` so the kanban path stays byte-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocker_kind: Option<BlockerKind>,
    pub created_by_passport: String,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    /// ExecPlan-aggregator extension fields. Populated only for items produced
    /// by `work_execplans::list_execplans`. Optional + `#[serde(default)]` so
    /// the kanban path stays byte-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_path: Option<String>,
    /// ExecPlan-only BLAKE3 digest of the canonical plan bytes, encoded as
    /// lowercase hexadecimal without an algorithm prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_milestone: Option<String>,
    /// ExecPlan-aggregator only: the lowest-ordered milestone id whose `after`
    /// dependency list (declared via `deps:<ID>` facts) is fully satisfied by
    /// milestones with a passing gate — i.e. the next milestone that is ready to
    /// start. `None` when the plan declares no `deps:*` facts, or behind the
    /// `CORECRUXD_FEATURE_NEXT_READY_MILESTONE` flag (default OFF). Milestone ids
    /// are alphanumeric (`M0`, `A1`, `B5`); see `work_execplans::milestone_id_key`
    /// for the ordering.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_ready_milestone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    /// Lineage graph: plans this one builds on / is blocked by (`Depends on
    /// [[slug]]`), and plans that build on this one (`Extended by [[slug]]`).
    /// Slugs only. The reciprocal edge is derived at projection time, so a plan
    /// declares one direction and `list_execplans` fills the other. Additive +
    /// empty-skipped so the kanban path stays byte-compatible.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extended_by: Vec<String>,
    /// Ready-order projection only (`/v1/work?ranked=1`): the subset of
    /// `depends_on` that is still *open*, i.e. what is actually holding this
    /// item back. Empty = ready to start now. Never populated on an unranked
    /// response, so the default board stays byte-identical.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_by: Vec<String>,
    /// Unresolved Open-Decision ids (`OD-<n>`) this plan references, per the
    /// registry — overdue first. Empty unless the daemon has the registry path
    /// (`CRUX_OPEN_DECISIONS_PATH`) set and the plan cites a still-open OD.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub open_decisions: Vec<String>,
    /// Agent-graph: orchestrator this work item belongs to, if any. Additive
    /// + `#[serde(default)]` so existing records remain byte-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orchestrator_id: Option<String>,
    /// ExecPlan milestone progress: how many declared milestones are done and
    /// the total declared. Populated only for ExecPlan-aggregator items.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub milestones_done: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub milestones_total: Option<u32>,
    /// Number of notes (work comments) attached to this item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes_count: Option<u32>,
    /// Fact-derived provenance rollup (ExecPlan-aggregator items only). Surfaces
    /// the activity window, contributing agents, and decision commit SHAs that
    /// the fact store + CROWN receipts already hold — read-only, never written
    /// back to the plan `.md`. `None` for kanban items and fact-less plans.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    /// ExecPlan-aggregator only: `Some(true)` when an `in_progress` plan has had
    /// no fact/file activity for longer than the staleness window — likely
    /// finished-but-unmarked or stalling, not actively in flight. `Some(false)`
    /// for a fresh `in_progress` plan; `None` for kanban items and non-in_progress
    /// states. Lets the board split in_progress into active vs stale without
    /// hiding anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<bool>,
    /// Per-ExecPlan **token-burn** rollup: the sum of attributed session cost
    /// reports (the cost lens, keyed by transcript UUID, joined to this plan at
    /// read time — see [`crate::cost_attribution`]). ExecPlan-aggregator items
    /// only, and only when the cost lens is fed; `None` for kanban items and
    /// plans with no attributed session, so the field is omitted on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_burn: Option<crate::cost_attribution::TokenBurn>,
}

/// Compact, fact-derived provenance for an ExecPlan work item. Assembled at
/// projection time from `execplan:<slug>` facts (milestone/gate/decision) — the
/// same data that produced CROWN receipts upstream — so it carries no new
/// authority and mutates nothing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Provenance {
    /// Earliest fact timestamp (ms since epoch) — when work on the plan began.
    pub first_activity_unix_ms: u64,
    /// Most recent fact timestamp (ms since epoch) — last touch.
    pub last_activity_unix_ms: u64,
    /// Distinct real-principal actors that contributed facts, sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub contributing_agents: Vec<String>,
    /// Distinct commit SHAs from `decision:*` facts, in insertion order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub commit_shas: Vec<String>,
    /// Count of `decision:*` facts logged against the plan.
    pub decision_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkComment {
    pub id: String,
    pub work_id: String,
    pub author_passport: String,
    pub body: String,
    pub posted_at_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkTransition {
    pub id: String,
    pub work_id: String,
    pub from_state: String,
    pub to_state: String,
    pub by_passport: String,
    /// `allowed` (ungated direct apply), `queued` (awaiting human), `approved`,
    /// `rejected`, `auto_approved` (timeout fallback).
    pub gate_status: String,
    pub at_unix_ms: u64,
    /// The typed blocker kind in effect when this transition landed on
    /// `blocked` (M1). Lets the status feed (M3) distinguish BLOCKED from
    /// HUMAN_HOLD per historical event without re-reading the live item.
    /// Additive + skip-if-`None` so pre-existing transition records load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocker_kind: Option<BlockerKind>,
    /// CROWN receipt that proves an approved or rejected gated transition.
    /// Legacy and ungated transitions omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingGateAction {
    pub action_id: String,
    pub work_id: String,
    pub requested_by_passport: String,
    /// Tenant at request time. Legacy gates omit this and authorize against
    /// the current work tenant; new gates fail closed if that tenant drifts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Currently `update_state` is the only gated action; other patches go
    /// through directly. Carry the requested target state when applicable.
    pub requested_action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_state: Option<String>,
    pub status: String, // pending / approved / rejected / auto_approved
    pub requested_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_by_passport: Option<String>,
    /// CROWN approval-decision receipt for the resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
}

/// Immutable authorization material for a gate. HTTP authorization
/// reads this while holding the same write guard later passed to
/// [`resolve_gate`], preventing a tenant-check/resolution TOCTOU.
#[derive(Debug, Clone)]
pub struct GateResolutionTarget {
    pub gate: PendingGateAction,
    pub work: WorkItem,
    pub tenant_id: String,
    pub tenant_mismatch: bool,
}

pub fn validate_state(state: &str) -> Result<(), WorkError> {
    if WORK_STATES.contains(&state) {
        Ok(())
    } else {
        Err(WorkError::InvalidState(state.to_string()))
    }
}

pub struct CreateWorkInput {
    pub project_id: String,
    pub title: String,
    pub body: Option<String>,
    pub state: Option<String>,
    pub assignee_passport: Option<String>,
    pub tenant_id: Option<String>,
    pub linked_pr: Option<String>,
    pub linked_issue: Option<String>,
    pub created_by_passport: String,
}

pub fn create_work(store: &mut FactStore, input: CreateWorkInput, now_unix_ms: u64) -> Result<WorkItem, WorkError> {
    if crate::projects::get_project(store, &input.project_id).is_none() {
        return Err(WorkError::ProjectNotFound(input.project_id));
    }
    let state = input.state.as_deref().unwrap_or("planned").to_string();
    validate_state(&state)?;
    let id = format!("w_{}", Uuid::new_v4().simple());
    let item = WorkItem {
        id: id.clone(),
        project_id: input.project_id,
        state: state.clone(),
        title: input.title,
        body: input.body.unwrap_or_default(),
        assignee_passport: input.assignee_passport,
        tenant_id: input.tenant_id,
        linked_pr: input.linked_pr,
        linked_issue: input.linked_issue,
        blocker_reason: None,
        blocker_kind: None,
        created_by_passport: input.created_by_passport.clone(),
        created_at_unix_ms: now_unix_ms,
        updated_at_unix_ms: now_unix_ms,
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
    };
    write_record(store, &item)?;
    write_transition(
        store,
        &WorkTransition {
            id: format!("tx_{}", Uuid::new_v4().simple()),
            work_id: id,
            from_state: "(none)".to_string(),
            to_state: state,
            by_passport: input.created_by_passport,
            gate_status: "allowed".to_string(),
            at_unix_ms: now_unix_ms,
            blocker_kind: None,
            receipt_id: None,
        },
    )?;
    Ok(item)
}

pub fn list_work(
    store: &FactStore,
    project_id: Option<&str>,
    state_filter: Option<&str>,
    tenant_filter: Option<&str>,
    assignee_filter: Option<&str>,
) -> Vec<WorkItem> {
    let prefix = match project_id {
        Some(pid) => format!("{WORK_ENTITY_PREFIX}::{pid}::"),
        None => format!("{WORK_ENTITY_PREFIX}::"),
    };
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix),
        top_k: 1000,
        token_budget: None,
    });
    let mut out = Vec::new();
    for fact in crate::fact_helpers::dedup_latest(result.facts) {
        if fact.key != RECORD_KEY {
            continue;
        }
        if let Ok(item) = serde_json::from_str::<WorkItem>(&fact.value) {
            if state_filter.is_none_or(|s| item.state == s)
                && tenant_filter.is_none_or(|t| item.tenant_id.as_deref() == Some(t))
                && assignee_filter.is_none_or(|a| item.assignee_passport.as_deref() == Some(a))
            {
                out.push(item);
            }
        }
    }
    out.sort_by(|a, b| b.updated_at_unix_ms.cmp(&a.updated_at_unix_ms));
    out
}

pub fn get_work(store: &FactStore, id: &str) -> Option<WorkItem> {
    list_work(store, None, None, None, None)
        .into_iter()
        .find(|w| w.id == id)
}

pub struct UpdateWorkInput {
    pub title: Option<String>,
    pub body: Option<String>,
    pub state: Option<String>,
    pub assignee_passport: Option<Option<String>>,
    pub tenant_id: Option<Option<String>>,
    pub linked_pr: Option<Option<String>>,
    pub linked_issue: Option<Option<String>>,
    pub blocker_reason: Option<Option<String>>,
    /// Set the typed blocker kind. `None` = leave unchanged. A `blocked`
    /// transition with no kind defaults to `needs_info` (applied below).
    pub blocker_kind: Option<BlockerKind>,
}

pub struct UpdateWorkContext {
    pub by_passport: String,
    pub passport_gated: bool,
    pub now_unix_ms: u64,
}

#[derive(Debug)]
pub enum UpdateOutcome {
    // Both payloads are boxed to keep this transient result compact as their
    // additive audit fields grow.
    Applied(Box<WorkItem>),
    Queued(Box<PendingGateAction>),
}

pub fn update_work(
    store: &mut FactStore,
    id: &str,
    input: UpdateWorkInput,
    ctx: UpdateWorkContext,
) -> Result<UpdateOutcome, WorkError> {
    let mut item = get_work(store, id).ok_or_else(|| WorkError::NotFound(id.to_string()))?;
    let prev_state = item.state.clone();

    // State changes are gateable; non-state field updates always go through.
    if let Some(new_state) = &input.state {
        validate_state(new_state)?;
        if new_state == "blocked"
            && input
                .blocker_reason
                .as_ref()
                .map_or(item.blocker_reason.is_none(), |r| {
                    r.is_none() || r.as_deref().is_none_or(str::is_empty)
                })
        {
            return Err(WorkError::MissingBlockerReason);
        }
        if ctx.passport_gated && new_state != &prev_state {
            // Queue a gated action; do NOT apply field changes yet (we only
            // queue the state move; other concurrent fields apply directly to
            // keep the item in sync with non-state edits).
            let pending = PendingGateAction {
                action_id: format!("ga_{}", Uuid::new_v4().simple()),
                work_id: item.id.clone(),
                requested_by_passport: ctx.by_passport.clone(),
                tenant_id: Some(item.tenant_id.clone().unwrap_or_else(|| "default".to_string())),
                requested_action: "update_state".to_string(),
                target_state: Some(new_state.clone()),
                status: "pending".to_string(),
                requested_at_unix_ms: ctx.now_unix_ms,
                resolved_at_unix_ms: None,
                resolved_by_passport: None,
                receipt_id: None,
            };
            write_gate(store, &pending)?;
            // Apply non-state fields, leave state untouched.
            apply_non_state_fields(&mut item, &input);
            item.updated_at_unix_ms = ctx.now_unix_ms;
            write_record(store, &item)?;
            return Ok(UpdateOutcome::Queued(Box::new(pending)));
        }
    }

    apply_non_state_fields(&mut item, &input);
    if let Some(new_state) = &input.state {
        item.state = new_state.clone();
        // A `blocked` transition with no explicit kind defaults to `needs_info`
        // (Open Engine: the unqualified block is "waiting on an answer").
        if new_state == "blocked" && item.blocker_kind.is_none() {
            item.blocker_kind = Some(BlockerKind::NeedsInfo);
        }
        // Leaving `blocked` clears the kind so a stale needs_approval doesn't
        // linger on an item that is no longer paused.
        if new_state != "blocked" {
            item.blocker_kind = None;
        }
    }
    item.updated_at_unix_ms = ctx.now_unix_ms;
    write_record(store, &item)?;

    if let Some(new_state) = input.state {
        if new_state != prev_state {
            write_transition(
                store,
                &WorkTransition {
                    id: format!("tx_{}", Uuid::new_v4().simple()),
                    work_id: item.id.clone(),
                    from_state: prev_state,
                    to_state: new_state,
                    by_passport: ctx.by_passport,
                    gate_status: "allowed".to_string(),
                    at_unix_ms: ctx.now_unix_ms,
                    blocker_kind: item.blocker_kind,
                    receipt_id: None,
                },
            )?;
        }
    }
    Ok(UpdateOutcome::Applied(Box::new(item)))
}

fn apply_non_state_fields(item: &mut WorkItem, input: &UpdateWorkInput) {
    if let Some(t) = &input.title {
        item.title = t.clone();
    }
    if let Some(b) = &input.body {
        item.body = b.clone();
    }
    if let Some(a) = &input.assignee_passport {
        item.assignee_passport = a.clone();
    }
    if let Some(t) = &input.tenant_id {
        item.tenant_id = t.clone();
    }
    if let Some(p) = &input.linked_pr {
        item.linked_pr = p.clone();
    }
    if let Some(i) = &input.linked_issue {
        item.linked_issue = i.clone();
    }
    if let Some(r) = &input.blocker_reason {
        item.blocker_reason = r.clone();
    }
    if let Some(k) = input.blocker_kind {
        item.blocker_kind = Some(k);
    }
}

pub fn add_comment(
    store: &mut FactStore,
    work_id: &str,
    author_passport: &str,
    body: &str,
    now_unix_ms: u64,
) -> Result<WorkComment, WorkError> {
    if get_work(store, work_id).is_none() {
        return Err(WorkError::NotFound(work_id.to_string()));
    }
    let comment = WorkComment {
        id: format!("c_{}", Uuid::new_v4().simple()),
        work_id: work_id.to_string(),
        author_passport: author_passport.to_string(),
        body: body.to_string(),
        posted_at_unix_ms: now_unix_ms,
    };
    let value = serde_json::to_string(&comment)?;
    let mut sf = StoreFact {
        tenant_hash: "default".to_string(),
        entity: format!("{WORK_COMMENT_ENTITY_PREFIX}::{}::{}", work_id, comment.id),
        key: RECORD_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    Ok(comment)
}

pub fn list_comments(store: &FactStore, work_id: &str) -> Vec<WorkComment> {
    let prefix = format!("{WORK_COMMENT_ENTITY_PREFIX}::{work_id}::");
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix),
        top_k: 500,
        token_budget: None,
    });
    let mut out = Vec::new();
    for fact in crate::fact_helpers::dedup_latest(result.facts) {
        if fact.key != RECORD_KEY {
            continue;
        }
        if let Ok(c) = serde_json::from_str::<WorkComment>(&fact.value) {
            out.push(c);
        }
    }
    out.sort_by(|a, b| a.posted_at_unix_ms.cmp(&b.posted_at_unix_ms));
    out
}

pub fn list_transitions(store: &FactStore, work_id: &str) -> Vec<WorkTransition> {
    let prefix = format!("{WORK_TRANSITION_ENTITY_PREFIX}::{work_id}::");
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix),
        top_k: 500,
        token_budget: None,
    });
    let mut out = Vec::new();
    for fact in crate::fact_helpers::dedup_latest(result.facts) {
        if fact.key != RECORD_KEY {
            continue;
        }
        if let Ok(t) = serde_json::from_str::<WorkTransition>(&fact.value) {
            out.push(t);
        }
    }
    // Two transitions can land in the same millisecond when create+patch happen in
    // quick succession (tests, scripted workflows). Sort by (at, from→to ordering)
    // so the create transition (`from_state = "(none)"`) precedes any subsequent move.
    out.sort_by(|a, b| {
        a.at_unix_ms
            .cmp(&b.at_unix_ms)
            .then_with(|| (a.from_state == "(none)").cmp(&(b.from_state == "(none)")).reverse())
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

pub fn list_pending_gates(store: &FactStore, by_passport_filter: Option<&str>) -> Vec<PendingGateAction> {
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(format!("{WORK_GATE_ENTITY_PREFIX}::")),
        top_k: 500,
        token_budget: None,
    });
    let mut out = Vec::new();
    for fact in crate::fact_helpers::dedup_latest(result.facts) {
        if fact.key != RECORD_KEY {
            continue;
        }
        if let Ok(p) = serde_json::from_str::<PendingGateAction>(&fact.value) {
            if p.status == "pending" && by_passport_filter.is_none_or(|f| p.requested_by_passport == f) {
                out.push(p);
            }
        }
    }
    out.sort_by(|a, b| a.requested_at_unix_ms.cmp(&b.requested_at_unix_ms));
    out
}

pub fn resolve_gate(
    store: &mut FactStore,
    action_id: &str,
    approver_passport: &str,
    receipt_id: &str,
    approve: bool,
    now_unix_ms: u64,
) -> Result<WorkItem, WorkError> {
    let target = gate_resolution_target(store, action_id)?;
    if target.tenant_mismatch {
        return Err(WorkError::GateTenantChanged(action_id.to_string()));
    }
    if target.gate.status != "pending" {
        return Err(WorkError::GateAlreadyResolved(action_id.to_string()));
    }
    let mut pending = target.gate;
    let item = target.work;

    pending.status = if approve {
        "approved".to_string()
    } else {
        "rejected".to_string()
    };
    pending.resolved_at_unix_ms = Some(now_unix_ms);
    pending.resolved_by_passport = Some(approver_passport.to_string());
    pending.receipt_id = Some(receipt_id.to_string());
    let gate_fact = gate_store_fact(&pending, Some(approver_passport), Some(receipt_id))?;

    if !approve {
        let rejected = WorkTransition {
            id: format!("tx_{}", Uuid::new_v4().simple()),
            work_id: item.id.clone(),
            from_state: item.state.clone(),
            to_state: item.state.clone(),
            by_passport: approver_passport.to_string(),
            gate_status: "rejected".to_string(),
            at_unix_ms: now_unix_ms,
            blocker_kind: item.blocker_kind,
            receipt_id: Some(receipt_id.to_string()),
        };
        let transition_fact = transition_store_fact(&rejected, Some(approver_passport), Some(receipt_id))?;
        store.try_store_bulk(vec![gate_fact, transition_fact])?;
        return Ok(item);
    }

    // Apply the requested action.
    if pending.requested_action == "update_state" {
        if let Some(target) = &pending.target_state {
            let mut updated = item;
            let from_state = updated.state.clone();
            updated.state = target.clone();
            // Mirror the direct path's M1 semantics: default a blocked target to
            // needs_info, clear the kind when leaving blocked.
            if target == "blocked" {
                if updated.blocker_kind.is_none() {
                    updated.blocker_kind = Some(BlockerKind::NeedsInfo);
                }
            } else {
                updated.blocker_kind = None;
            }
            updated.updated_at_unix_ms = now_unix_ms;
            let transition = WorkTransition {
                id: format!("tx_{}", Uuid::new_v4().simple()),
                work_id: updated.id.clone(),
                from_state,
                to_state: target.clone(),
                by_passport: approver_passport.to_string(),
                gate_status: "approved".to_string(),
                at_unix_ms: now_unix_ms,
                blocker_kind: updated.blocker_kind,
                receipt_id: Some(receipt_id.to_string()),
            };
            let work_fact = record_store_fact(&updated, Some(approver_passport), Some(receipt_id))?;
            let transition_fact = transition_store_fact(&transition, Some(approver_passport), Some(receipt_id))?;
            store.try_store_bulk(vec![gate_fact, work_fact, transition_fact])?;
            return Ok(updated);
        }
    }
    store.try_store_bulk(vec![gate_fact])?;
    Ok(item)
}

pub fn gate_resolution_target(store: &FactStore, action_id: &str) -> Result<GateResolutionTarget, WorkError> {
    let gate = get_gate(store, action_id).ok_or_else(|| WorkError::GateNotFound(action_id.to_string()))?;
    let work = get_work(store, &gate.work_id).ok_or_else(|| WorkError::NotFound(gate.work_id.clone()))?;
    let work_tenant_id = work.tenant_id.clone().unwrap_or_else(|| "default".to_string());
    let tenant_id = gate.tenant_id.clone().unwrap_or_else(|| work_tenant_id.clone());
    let tenant_mismatch = gate.tenant_id.is_some() && tenant_id != work_tenant_id;
    Ok(GateResolutionTarget {
        gate,
        work,
        tenant_id,
        tenant_mismatch,
    })
}

fn get_gate(store: &FactStore, action_id: &str) -> Option<PendingGateAction> {
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: Some(format!("{WORK_GATE_ENTITY_PREFIX}::{action_id}")),
        entity_prefix: None,
        top_k: 50,
        token_budget: None,
    });
    for fact in crate::fact_helpers::dedup_latest(result.facts) {
        if fact.key != RECORD_KEY {
            continue;
        }
        if let Ok(p) = serde_json::from_str::<PendingGateAction>(&fact.value) {
            return Some(p);
        }
    }
    None
}

/// Public re-write of an existing work item record. Used by the orchestrator
/// surface to stamp / clear `orchestrator_id` without going through the full
/// `update_work` state-machine (which would emit a spurious transition). The
/// caller is responsible for having loaded a current copy via `get_work`.
pub fn write_work_record(store: &mut FactStore, item: &WorkItem) -> Result<(), WorkError> {
    write_record(store, item)
}

fn write_record(store: &mut FactStore, item: &WorkItem) -> Result<(), WorkError> {
    write_record_with_attribution(store, item, None, None)
}

fn write_record_with_attribution(
    store: &mut FactStore,
    item: &WorkItem,
    actor: Option<&str>,
    receipt_id: Option<&str>,
) -> Result<(), WorkError> {
    let sf = record_store_fact(item, actor, receipt_id)?;
    store.store(sf);
    Ok(())
}

fn record_store_fact(item: &WorkItem, actor: Option<&str>, receipt_id: Option<&str>) -> Result<StoreFact, WorkError> {
    let value = serde_json::to_string(item)?;
    let mut fact = StoreFact {
        tenant_hash: "default".to_string(),
        entity: format!("{WORK_ENTITY_PREFIX}::{}::{}", item.project_id, item.id),
        key: RECORD_KEY.to_string(),
        value,
        source_receipt: receipt_id.map(str::to_string),
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: actor.map(str::to_string),
    };
    crate::fact_privacy::enforce_global(&mut fact);
    Ok(fact)
}

fn write_transition(store: &mut FactStore, tx: &WorkTransition) -> Result<(), WorkError> {
    write_transition_with_attribution(store, tx, None, None)
}

fn write_transition_with_attribution(
    store: &mut FactStore,
    tx: &WorkTransition,
    actor: Option<&str>,
    receipt_id: Option<&str>,
) -> Result<(), WorkError> {
    let sf = transition_store_fact(tx, actor, receipt_id)?;
    store.store(sf);
    Ok(())
}

fn transition_store_fact(
    tx: &WorkTransition,
    actor: Option<&str>,
    receipt_id: Option<&str>,
) -> Result<StoreFact, WorkError> {
    let value = serde_json::to_string(tx)?;
    let mut fact = StoreFact {
        tenant_hash: "default".to_string(),
        entity: format!(
            "{WORK_TRANSITION_ENTITY_PREFIX}::{}::{}-{}",
            tx.work_id, tx.at_unix_ms, tx.id
        ),
        key: RECORD_KEY.to_string(),
        value,
        source_receipt: receipt_id.map(str::to_string),
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: actor.map(str::to_string),
    };
    crate::fact_privacy::enforce_global(&mut fact);
    Ok(fact)
}

fn write_gate(store: &mut FactStore, gate: &PendingGateAction) -> Result<(), WorkError> {
    write_gate_with_attribution(store, gate, None, None)
}

fn write_gate_with_attribution(
    store: &mut FactStore,
    gate: &PendingGateAction,
    actor: Option<&str>,
    receipt_id: Option<&str>,
) -> Result<(), WorkError> {
    let sf = gate_store_fact(gate, actor, receipt_id)?;
    store.store(sf);
    Ok(())
}

fn gate_store_fact(
    gate: &PendingGateAction,
    actor: Option<&str>,
    receipt_id: Option<&str>,
) -> Result<StoreFact, WorkError> {
    let value = serde_json::to_string(gate)?;
    let mut fact = StoreFact {
        tenant_hash: "default".to_string(),
        entity: format!("{WORK_GATE_ENTITY_PREFIX}::{}", gate.action_id),
        key: RECORD_KEY.to_string(),
        value,
        source_receipt: receipt_id.map(str::to_string),
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: actor.map(str::to_string),
    };
    crate::fact_privacy::enforce_global(&mut fact);
    Ok(fact)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        // nanos alone collides on VMs with coarse clocks (parallel tests
        // land in the same quantum and share a dir) — salt with pid + a counter.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("corecruxd-work-{name}-{nanos}-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn seeded_store() -> (PathBuf, FactStore) {
        let dir = temp_dir("seeded");
        let mut store = FactStore::new();
        crate::passports::seed_defaults_if_missing(&dir, &mut store, 1).expect("passport seed");
        crate::projects::seed_default_if_missing(&mut store, 1).expect("project seed");
        (dir, store)
    }

    fn mk_work(store: &mut FactStore) -> WorkItem {
        create_work(
            store,
            CreateWorkInput {
                project_id: "default".to_string(),
                title: "fix the thing".to_string(),
                body: None,
                state: None,
                assignee_passport: Some("personal-default".to_string()),
                tenant_id: Some("personal".to_string()),
                linked_pr: None,
                linked_issue: None,
                created_by_passport: "personal-default".to_string(),
            },
            1_000,
        )
        .expect("create")
    }

    #[test]
    fn create_initial_state_is_planned_and_logs_transition() {
        let (dir, mut store) = seeded_store();
        let item = mk_work(&mut store);
        assert_eq!(item.state, "planned");
        let txns = list_transitions(&store, &item.id);
        assert_eq!(txns.len(), 1);
        assert_eq!(txns[0].from_state, "(none)");
        assert_eq!(txns[0].to_state, "planned");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kanban_item_serializes_without_plan_content_hash() -> Result<(), serde_json::Error> {
        let (dir, mut store) = seeded_store();
        let item = mk_work(&mut store);
        let json = serde_json::to_value(item)?;

        assert!(json.get("plan_content_hash").is_none());
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    #[test]
    fn full_lifecycle_planned_to_deployed() {
        let (dir, mut store) = seeded_store();
        let item = mk_work(&mut store);
        let states = ["in_progress", "blocked", "in_progress", "complete", "deployed"];
        let blocker_reasons = ["", "waiting on infra", "", "", ""];
        let mut now = 2_000u64;
        for (state, reason) in states.iter().zip(blocker_reasons) {
            let outcome = update_work(
                &mut store,
                &item.id,
                UpdateWorkInput {
                    title: None,
                    body: None,
                    state: Some((*state).to_string()),
                    assignee_passport: None,
                    tenant_id: None,
                    linked_pr: None,
                    linked_issue: None,
                    blocker_reason: if !reason.is_empty() {
                        Some(Some(reason.to_string()))
                    } else {
                        None
                    },
                    blocker_kind: None,
                },
                UpdateWorkContext {
                    by_passport: "personal-default".to_string(),
                    passport_gated: false,
                    now_unix_ms: now,
                },
            )
            .expect("update");
            assert!(matches!(outcome, UpdateOutcome::Applied(_)));
            now += 1000;
        }
        let txns = list_transitions(&store, &item.id);
        assert_eq!(txns.len(), 6, "1 create + 5 transitions");
        let final_item = get_work(&store, &item.id).expect("item");
        assert_eq!(final_item.state, "deployed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blocked_without_reason_rejected() {
        let (dir, mut store) = seeded_store();
        let item = mk_work(&mut store);
        let err = update_work(
            &mut store,
            &item.id,
            UpdateWorkInput {
                title: None,
                body: None,
                state: Some("blocked".to_string()),
                assignee_passport: None,
                tenant_id: None,
                linked_pr: None,
                linked_issue: None,
                blocker_reason: None,
                blocker_kind: None,
            },
            UpdateWorkContext {
                by_passport: "personal-default".to_string(),
                passport_gated: false,
                now_unix_ms: 2_000,
            },
        )
        .expect_err("should reject");
        assert!(matches!(err, WorkError::MissingBlockerReason));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gated_state_change_queues_then_approves() {
        let (dir, mut store) = seeded_store();
        let item = mk_work(&mut store);
        let outcome = update_work(
            &mut store,
            &item.id,
            UpdateWorkInput {
                title: None,
                body: None,
                state: Some("in_progress".to_string()),
                assignee_passport: None,
                tenant_id: None,
                linked_pr: None,
                linked_issue: None,
                blocker_reason: None,
                blocker_kind: None,
            },
            UpdateWorkContext {
                by_passport: "personal-default".to_string(),
                passport_gated: true,
                now_unix_ms: 2_000,
            },
        )
        .expect("queued");
        let pending = match outcome {
            UpdateOutcome::Queued(p) => p,
            UpdateOutcome::Applied(_) => panic!("expected queued"),
        };
        let still_planned = get_work(&store, &item.id).expect("item");
        assert_eq!(still_planned.state, "planned");
        assert_eq!(list_pending_gates(&store, None).len(), 1);
        let approved = resolve_gate(
            &mut store,
            &pending.action_id,
            "operator-passport",
            "ad_test_approve",
            true,
            3_000,
        )
        .expect("resolve");
        assert_eq!(approved.state, "in_progress");
        assert!(list_pending_gates(&store, None).is_empty(), "no longer pending");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gated_state_change_rejection_keeps_state() {
        let (dir, mut store) = seeded_store();
        let item = mk_work(&mut store);
        let outcome = update_work(
            &mut store,
            &item.id,
            UpdateWorkInput {
                title: None,
                body: None,
                state: Some("complete".to_string()),
                assignee_passport: None,
                tenant_id: None,
                linked_pr: None,
                linked_issue: None,
                blocker_reason: None,
                blocker_kind: None,
            },
            UpdateWorkContext {
                by_passport: "personal-default".to_string(),
                passport_gated: true,
                now_unix_ms: 2_000,
            },
        )
        .expect("queued");
        let pending = match outcome {
            UpdateOutcome::Queued(p) => p,
            UpdateOutcome::Applied(_) => panic!("expected queued"),
        };
        let _ = resolve_gate(
            &mut store,
            &pending.action_id,
            "operator-passport",
            "ad_test_reject",
            false,
            3_000,
        )
        .expect("rejected");
        let still_planned = get_work(&store, &item.id).expect("item");
        assert_eq!(still_planned.state, "planned");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn comments_round_trip_in_chronological_order() {
        let (dir, mut store) = seeded_store();
        let item = mk_work(&mut store);
        for (i, body) in ["first", "second", "third"].iter().enumerate() {
            add_comment(&mut store, &item.id, "personal-default", body, 2_000 + i as u64).expect("comment");
        }
        let comments = list_comments(&store, &item.id);
        assert_eq!(comments.len(), 3);
        assert_eq!(comments[0].body, "first");
        assert_eq!(comments[2].body, "third");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_filters_by_state_and_assignee() {
        let (dir, mut store) = seeded_store();
        let _w1 = mk_work(&mut store);
        let w2 = mk_work(&mut store);
        update_work(
            &mut store,
            &w2.id,
            UpdateWorkInput {
                title: None,
                body: None,
                state: Some("in_progress".to_string()),
                assignee_passport: Some(Some("work-default".to_string())),
                tenant_id: None,
                linked_pr: None,
                linked_issue: None,
                blocker_reason: None,
                blocker_kind: None,
            },
            UpdateWorkContext {
                by_passport: "work-default".to_string(),
                passport_gated: false,
                now_unix_ms: 2_000,
            },
        )
        .expect("update");
        let in_progress = list_work(&store, Some("default"), Some("in_progress"), None, None);
        assert_eq!(in_progress.len(), 1);
        let work_assigned = list_work(&store, None, None, None, Some("work-default"));
        assert_eq!(work_assigned.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_project_rejected() {
        let (dir, mut store) = seeded_store();
        let err = create_work(
            &mut store,
            CreateWorkInput {
                project_id: "ghost".to_string(),
                title: "x".to_string(),
                body: None,
                state: None,
                assignee_passport: None,
                tenant_id: None,
                linked_pr: None,
                linked_issue: None,
                created_by_passport: "personal-default".to_string(),
            },
            1_000,
        )
        .expect_err("rejected");
        assert!(matches!(err, WorkError::ProjectNotFound(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- M1: typed blocker reason -----------------------------------------

    /// Build an `UpdateWorkInput` with only the fields a blocker test needs.
    fn blocker_update(state: Option<&str>, kind: Option<BlockerKind>, reason: Option<&str>) -> UpdateWorkInput {
        UpdateWorkInput {
            title: None,
            body: None,
            state: state.map(str::to_string),
            assignee_passport: None,
            tenant_id: None,
            linked_pr: None,
            linked_issue: None,
            blocker_reason: reason.map(|r| Some(r.to_string())),
            blocker_kind: kind,
        }
    }

    fn ctx_at(now: u64) -> UpdateWorkContext {
        UpdateWorkContext {
            by_passport: "personal-default".to_string(),
            passport_gated: false,
            now_unix_ms: now,
        }
    }

    #[test]
    fn blocker_kind_serde_round_trips_both_values() {
        for (kind, wire) in [
            (BlockerKind::NeedsInfo, "needs_info"),
            (BlockerKind::NeedsApproval, "needs_approval"),
        ] {
            let json = serde_json::to_string(&kind).expect("serialize");
            assert_eq!(json, format!("\"{wire}\""));
            let back: BlockerKind = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn legacy_blocked_row_without_kind_deserializes_to_none() {
        // A pre-M1 serialized WorkItem has no `blocker_kind` field at all.
        let legacy = r#"{
            "id": "w_legacy",
            "project_id": "p",
            "state": "blocked",
            "title": "old",
            "blocker_reason": "waiting",
            "created_by_passport": "personal-default",
            "created_at_unix_ms": 1,
            "updated_at_unix_ms": 2
        }"#;
        let item: WorkItem = serde_json::from_str(legacy).expect("legacy row must deserialize");
        assert_eq!(item.state, "blocked");
        assert_eq!(
            item.blocker_kind, None,
            "missing field defaults to None (read as needs_info)"
        );
        // And it does not re-serialize a spurious null field.
        let round = serde_json::to_string(&item).expect("serialize");
        assert!(!round.contains("blocker_kind"), "None is skipped on the wire");
    }

    #[test]
    fn unknown_blocker_kind_is_rejected() {
        let bad = serde_json::from_str::<BlockerKind>("\"needs_coffee\"");
        assert!(bad.is_err(), "serde must reject unknown blocker kinds");
    }

    #[test]
    fn blocked_transition_defaults_to_needs_info() {
        let (dir, mut store) = seeded_store();
        let item = mk_work(&mut store);
        let outcome = update_work(
            &mut store,
            &item.id,
            blocker_update(Some("blocked"), None, Some("waiting on infra")),
            ctx_at(2_000),
        )
        .expect("update");
        match outcome {
            UpdateOutcome::Applied(w) => assert_eq!(w.blocker_kind, Some(BlockerKind::NeedsInfo)),
            UpdateOutcome::Queued(_) => panic!("ungated update should apply"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blocked_transition_honours_explicit_needs_approval() {
        let (dir, mut store) = seeded_store();
        let item = mk_work(&mut store);
        let outcome = update_work(
            &mut store,
            &item.id,
            blocker_update(
                Some("blocked"),
                Some(BlockerKind::NeedsApproval),
                Some("needs sign-off"),
            ),
            ctx_at(2_000),
        )
        .expect("update");
        let UpdateOutcome::Applied(w) = outcome else {
            panic!("should apply")
        };
        assert_eq!(w.blocker_kind, Some(BlockerKind::NeedsApproval));
        // Persisted, not just returned.
        let reloaded = get_work(&store, &item.id).expect("reload");
        assert_eq!(reloaded.blocker_kind, Some(BlockerKind::NeedsApproval));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn leaving_blocked_clears_kind() {
        let (dir, mut store) = seeded_store();
        let item = mk_work(&mut store);
        update_work(
            &mut store,
            &item.id,
            blocker_update(Some("blocked"), Some(BlockerKind::NeedsApproval), Some("hold")),
            ctx_at(2_000),
        )
        .expect("block");
        let outcome = update_work(
            &mut store,
            &item.id,
            blocker_update(Some("in_progress"), None, None),
            ctx_at(3_000),
        )
        .expect("unblock");
        let UpdateOutcome::Applied(w) = outcome else {
            panic!("should apply")
        };
        assert_eq!(w.state, "in_progress");
        assert_eq!(w.blocker_kind, None, "kind cleared once no longer blocked");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
