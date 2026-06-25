// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
pub const WORK_STATES: &[&str] = &[
    "planned",
    "in_progress",
    "blocked",
    "archive",
    "complete",
    "deployed",
    "pending_approval",
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
    #[error(transparent)]
    Json(#[from] serde_json::Error),
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
    pub created_by_passport: String,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    /// ExecPlan-aggregator extension fields. Populated only for items produced
    /// by `work_execplans::list_execplans`. Optional + `#[serde(default)]` so
    /// the kanban path stays byte-compatible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_milestone: Option<String>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingGateAction {
    pub action_id: String,
    pub work_id: String,
    pub requested_by_passport: String,
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
        created_by_passport: input.created_by_passport.clone(),
        created_at_unix_ms: now_unix_ms,
        updated_at_unix_ms: now_unix_ms,
        plan_path: None,
        current_milestone: None,
        superseded_by: None,
        depends_on: Vec::new(),
        extended_by: Vec::new(),
        orchestrator_id: None,
        milestones_done: None,
        milestones_total: None,
        notes_count: None,
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
}

pub struct UpdateWorkContext {
    pub by_passport: String,
    pub passport_gated: bool,
    pub now_unix_ms: u64,
}

#[derive(Debug)]
pub enum UpdateOutcome {
    // Boxed: WorkItem is much larger than PendingGateAction (clippy
    // large_enum_variant); this enum is a transient return value.
    Applied(Box<WorkItem>),
    Queued(PendingGateAction),
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
                requested_action: "update_state".to_string(),
                target_state: Some(new_state.clone()),
                status: "pending".to_string(),
                requested_at_unix_ms: ctx.now_unix_ms,
                resolved_at_unix_ms: None,
                resolved_by_passport: None,
            };
            write_gate(store, &pending)?;
            // Apply non-state fields, leave state untouched.
            apply_non_state_fields(&mut item, &input);
            item.updated_at_unix_ms = ctx.now_unix_ms;
            write_record(store, &item)?;
            return Ok(UpdateOutcome::Queued(pending));
        }
    }

    apply_non_state_fields(&mut item, &input);
    if let Some(new_state) = &input.state {
        item.state = new_state.clone();
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
    approve: bool,
    now_unix_ms: u64,
) -> Result<WorkItem, WorkError> {
    let mut pending = get_gate(store, action_id).ok_or_else(|| WorkError::GateNotFound(action_id.to_string()))?;
    if pending.status != "pending" {
        return Err(WorkError::GateNotFound(action_id.to_string()));
    }
    let item = get_work(store, &pending.work_id).ok_or_else(|| WorkError::NotFound(pending.work_id.clone()))?;

    pending.status = if approve {
        "approved".to_string()
    } else {
        "rejected".to_string()
    };
    pending.resolved_at_unix_ms = Some(now_unix_ms);
    pending.resolved_by_passport = Some(approver_passport.to_string());
    write_gate(store, &pending)?;

    if !approve {
        return Ok(item);
    }

    // Apply the requested action.
    if pending.requested_action == "update_state" {
        if let Some(target) = &pending.target_state {
            let mut updated = item;
            let from_state = updated.state.clone();
            updated.state = target.clone();
            updated.updated_at_unix_ms = now_unix_ms;
            write_record(store, &updated)?;
            write_transition(
                store,
                &WorkTransition {
                    id: format!("tx_{}", Uuid::new_v4().simple()),
                    work_id: updated.id.clone(),
                    from_state,
                    to_state: target.clone(),
                    by_passport: approver_passport.to_string(),
                    gate_status: "approved".to_string(),
                    at_unix_ms: now_unix_ms,
                },
            )?;
            return Ok(updated);
        }
    }
    Ok(item)
}

fn get_gate(store: &FactStore, action_id: &str) -> Option<PendingGateAction> {
    let result = store.query(&FactQuery {
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
    let value = serde_json::to_string(item)?;
    let mut sf = StoreFact {
        entity: format!("{WORK_ENTITY_PREFIX}::{}::{}", item.project_id, item.id),
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
    Ok(())
}

fn write_transition(store: &mut FactStore, tx: &WorkTransition) -> Result<(), WorkError> {
    let value = serde_json::to_string(tx)?;
    let mut sf = StoreFact {
        entity: format!(
            "{WORK_TRANSITION_ENTITY_PREFIX}::{}::{}-{}",
            tx.work_id, tx.at_unix_ms, tx.id
        ),
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
    Ok(())
}

fn write_gate(store: &mut FactStore, gate: &PendingGateAction) -> Result<(), WorkError> {
    let value = serde_json::to_string(gate)?;
    let mut sf = StoreFact {
        entity: format!("{WORK_GATE_ENTITY_PREFIX}::{}", gate.action_id),
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("corecruxd-work-{name}-{nanos}"));
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
        let approved = resolve_gate(&mut store, &pending.action_id, "operator-passport", true, 3_000).expect("resolve");
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
        let _ = resolve_gate(&mut store, &pending.action_id, "operator-passport", false, 3_000).expect("rejected");
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
}
