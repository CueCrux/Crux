// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Pro Agent Workbench surfaces.
//!
//! These handlers compose existing local-first primitives rather than executing
//! commands or calling a model: fact memory, sessions, workspace storyline,
//! local receipts, command metadata, and constraints. Free keeps the safety
//! primitives; this module gates the acceleration/provenance workbench layer.

use super::observations::{append_one, PostObservationBody};
use super::*;
use corecrux_memory::action_enrichment::{enrich_action, hash_json, ActionEnrichmentInput, Materiality};
use corecrux_memory::fact_store::{Fact, FactQuery, FactStore, StoreFact};
use corecrux_memory::replay::{hash_text, AnswerReplayCapsule, ANSWER_REPLAY_CAPSULE_ENTITY_PREFIX};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const WORKBENCH_CONTRACT_SCHEMA: &str = "crux.agent_workbench.contract.v1";
const WORKBENCH_RECEIPT_SCHEMA: &str = "crux.agent_workbench.receipt.v1";
const WORKBENCH_FACT_PREFIX: &str = "__workbench__";
const CONTEXT_PACK_KEY: &str = "context_pack";
const COMMAND_LEDGER_KEY: &str = "command_ledger";
const HANDOFF_KEY: &str = "handoff_v2";
const PREFLIGHT_KEY: &str = "impact_preflight";
const POLICY_SIM_KEY: &str = "policy_simulation";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkbenchSurface {
    AgentBrief,
    ContextPack,
    ImpactPreflight,
    CommandLedger,
    AuditTriage,
    ReasoningTimeline,
    HandoffV2,
    RouteProbe,
    ApiDrift,
    PolicySimulation,
}

impl WorkbenchSurface {
    fn capability(self) -> &'static str {
        match self {
            Self::AgentBrief => "agent_brief:pro",
            Self::ContextPack => "context_pack:budgeted",
            Self::ImpactPreflight => "impact:preflight",
            Self::CommandLedger => "ledger:history",
            Self::AuditTriage => "audit:triage",
            Self::ReasoningTimeline => "reasoning:timeline",
            Self::HandoffV2 => "handoff:v2",
            Self::RouteProbe => "route_probe:lab",
            Self::ApiDrift => "api_drift:check",
            Self::PolicySimulation => "policy:simulate",
        }
    }

    fn path(self) -> &'static str {
        match self {
            Self::AgentBrief => "/v1/workbench/brief",
            Self::ContextPack => "/v1/workbench/context-pack",
            Self::ImpactPreflight => "/v1/workbench/impact-preflight",
            Self::CommandLedger => "/v1/workbench/command-ledger",
            Self::AuditTriage => "/v1/workbench/audit-triage",
            Self::ReasoningTimeline => "/v1/workbench/reasoning-timeline",
            Self::HandoffV2 => "/v1/workbench/handoff-v2",
            Self::RouteProbe => "/v1/workbench/route-probe",
            Self::ApiDrift => "/v1/workbench/api-drift",
            Self::PolicySimulation => "/v1/workbench/policy-simulation",
        }
    }

    fn method(self) -> &'static str {
        match self {
            Self::AgentBrief | Self::AuditTriage | Self::ReasoningTimeline | Self::ApiDrift => "GET",
            Self::CommandLedger => "GET/POST",
            _ => "POST",
        }
    }

    fn all() -> Vec<Self> {
        vec![
            Self::AgentBrief,
            Self::ContextPack,
            Self::ImpactPreflight,
            Self::CommandLedger,
            Self::AuditTriage,
            Self::ReasoningTimeline,
            Self::HandoffV2,
            Self::RouteProbe,
            Self::ApiDrift,
            Self::PolicySimulation,
        ]
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct TenantWorkbenchQuery {
    pub tenant_id: String,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ContextPackBody {
    pub tenant_id: String,
    pub query: String,
    #[serde(default = "default_context_pack_budget")]
    pub token_budget: usize,
    #[serde(default)]
    pub include_private: bool,
    #[serde(default)]
    pub source_labels: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ImpactPreflightBody {
    pub tenant_id: String,
    #[serde(default)]
    pub changed_paths: Vec<String>,
    #[serde(default)]
    pub routes: Vec<String>,
    #[serde(default)]
    pub selected_tests: Vec<String>,
    #[serde(default)]
    pub include_storyline: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CommandLedgerBody {
    pub tenant_id: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_hash: Option<String>,
    #[serde(default)]
    pub linked_receipts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct RouteProbeBody {
    pub route: String,
    #[serde(default)]
    pub include_storyline: bool,
    #[serde(default)]
    pub include_tests: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct HandoffV2Body {
    pub tenant_id: String,
    pub goal: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub source_agent: Option<String>,
    #[serde(default)]
    pub target_agent: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
    #[serde(default)]
    pub next_actions: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct PolicySimulationBody {
    #[serde(flatten)]
    pub action: ActionEnrichmentInput,
}

fn default_context_pack_budget() -> usize {
    4000
}

pub(super) fn workbench_posture(state: &AppState) -> Value {
    let product = crate::product::ProductPosture::new(state.operating_mode, &state.enabled_pro_services);
    json!({
        "schema": WORKBENCH_CONTRACT_SCHEMA,
        "contract_path": "/v1/workbench/contract",
        "tier": product.tier,
        "mode": product.mode,
        "surfaces": WorkbenchSurface::all()
            .into_iter()
            .map(|surface| service_contract(&product, surface))
            .collect::<Vec<_>>(),
    })
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_workbench_contract(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["query:read", "admin:read"]) {
        return problem.into_response();
    }
    Json(workbench_posture(&state)).into_response()
}

/// How many ranked items the brief carries. Twenty is enough to see the next
/// several things worth doing and still cost well under a thousand tokens.
const BRIEF_OPEN_WORK_LIMIT: usize = 20;

/// The brief's `open_work`: kanban items **merged with** the ExecPlan projection,
/// narrowed to open work and sorted into recommended order by
/// [`crate::work_execplans::rank_open`], then trimmed to the cheap fields.
///
/// Previously this read the kanban table alone, so the ExecPlan board — the
/// large majority of real work — never appeared in the brief at all, and the
/// twenty items it did return were in arbitrary order. Emitting slim rows keeps
/// the whole section under ~1 KB, which is what makes it readable on every
/// agent boot instead of a 160 KB board fetch.
fn ranked_open_work(
    store: &corecrux_memory::fact_store::FactStore,
    project_id: Option<&str>,
    tenant_id: &str,
) -> Vec<Value> {
    let mut items = crate::work::list_work(store, project_id, None, Some(tenant_id), None);

    // ExecPlan items are tenant-agnostic (the projection is per-root, not
    // per-tenant), so they are appended rather than tenant-filtered — same
    // treatment `/v1/work?source=all` gives them.
    if let Some(root) = crate::work_execplans::execplans_root_from_env() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);
        match crate::work_execplans::list_execplans(store, &root, now) {
            Ok(plans) => items.extend(plans),
            Err(err) => {
                tracing::warn!(error = %err, root = %root.display(), "brief-execplan-aggregator-io-error");
            }
        }
    }

    let ranked = crate::work_execplans::rank_open(&items);
    ranked
        .order
        .iter()
        .take(BRIEF_OPEN_WORK_LIMIT)
        .enumerate()
        .map(|(pos, &idx)| {
            let w = &items[idx];
            let mut o = serde_json::Map::new();
            o.insert("id".into(), json!(w.id));
            o.insert("state".into(), json!(w.state));
            if let Some(m) = &w.current_milestone {
                o.insert("current_milestone".into(), json!(m));
            }
            if let Some(d) = w.milestones_done {
                o.insert("milestones_done".into(), json!(d));
            }
            if let Some(t) = w.milestones_total {
                o.insert("milestones_total".into(), json!(t));
            }
            let blocked = &ranked.blocked_by[pos];
            if !blocked.is_empty() {
                o.insert("blocked_by".into(), json!(blocked));
            }
            Value::Object(o)
        })
        .collect()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_agent_brief(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TenantWorkbenchQuery>,
) -> Response {
    let tenant_id = match tenant_id(&q.tenant_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    if let Some(response) =
        require_surface_for_tenant(&state, &headers, WorkbenchSurface::AgentBrief, false, &tenant_id)
    {
        return response;
    }
    let sync_status = super::health::sync_runtime_status();
    let workspace = crate::workspace_scan::load_latest(&state.fact_store).await;
    let sessions = {
        let sessions = state.session_store.read().await;
        let mut ids: Vec<String> = sessions.list().into_iter().map(str::to_string).collect();
        ids.sort();
        ids.truncate(20);
        json!({
            "count": sessions.count(),
            "sample": ids,
        })
    };
    let (constraints, decisions, recent_receipts, tenant_fact_count, open_work) = {
        let store = state.fact_store.read().await;
        (
            tenant_facts_by_prefix(&store, "__constraints__::", &tenant_id, 12),
            tenant_facts_by_prefix(&store, "__decisions__::", &tenant_id, 12),
            recent_receipt_refs(&store, &tenant_id, 16),
            tenant_facts(&store, &tenant_id, 200).len(),
            ranked_open_work(&store, q.project_id.as_deref(), &tenant_id),
        )
    };

    Json(json!({
        "schema": "crux.agent_workbench.brief.v1",
        "tenant_id": tenant_id,
        "project_id": q.project_id,
        "tenant_memory": {
            "matched_fact_count": tenant_fact_count,
            "local_mirror_state": sync_status.mode,
            "sync_configured": sync_status.configured,
            "sync_degraded": sync_status.degraded,
            "sync_degraded_reason": sync_status.degraded_reason,
        },
        "workspace": workspace.as_ref().map(|scan| json!({
            "scan_id": scan.scan_id,
            "root_path": scan.root_path,
            "stats": scan.stats,
            "unresolved_routes": scan.diagnostics.unresolved_routes.len(),
        })),
        "sessions": sessions,
        "active_constraints": constraints,
        "open_decisions": decisions,
        "open_work": open_work,
        // The rows above are ranked, not merely filtered, and carry only the
        // cheap fields. Stated explicitly so a consumer knows the order is
        // meaningful (pick the first one) and that a full row lives at
        // `/v1/work?ranked=1` without `fields=slim`.
        "open_work_order": "ranked",
        "recent_receipts": recent_receipts,
    }))
    .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_context_pack(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ContextPackBody>,
) -> Response {
    let tenant_id = match tenant_id(&body.tenant_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    if let Some(response) =
        require_surface_for_tenant(&state, &headers, WorkbenchSurface::ContextPack, true, &tenant_id)
    {
        return response;
    }
    if body.query.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "query must not be empty");
    }
    let token_budget = body.token_budget.clamp(128, 128_000);
    let semantic_profile = state.fact_store.read().await.semantic_profile();
    let local_semantic_profile_id = semantic_profile.as_ref().map(|profile| profile.profile_id.clone());
    let mut used = 0usize;
    let selected = {
        let store = state.fact_store.read().await;
        let mut facts = query_facts(&store, Some(&body.query), None, 200);
        facts.retain(|fact| {
            fact.entity.contains(&tenant_id) || fact.value.contains(&tenant_id) || fact.key.contains(&tenant_id)
        });
        if !body.include_private {
            facts.retain(|fact| !fact.private);
        }
        facts
            .into_iter()
            .filter_map(|fact| {
                let tokens = fact.tokens.max(estimate_tokens(&fact.value));
                if used + tokens > token_budget && used > 0 {
                    return None;
                }
                used += tokens;
                Some(json!({
                    "fact_id": fact.fact_id,
                    "entity": fact.entity,
                    "key": fact.key,
                    "text": fact.value,
                    "tokens": tokens,
                    "source_label": source_label_for_entity(&fact.entity),
                    "content_hash": format!("blake3:{}", blake3::hash(fact.value.as_bytes()).to_hex()),
                    "source_receipt": fact.source_receipt,
                    "semantic_profile_id": local_semantic_profile_id,
                    "score_space": "fact_store_keyword_confidence",
                }))
            })
            .collect::<Vec<_>>()
    };
    let pack = json!({
        "schema": "crux.agent_workbench.context_pack.v1",
        "tenant_id": tenant_id,
        "query": body.query,
        "token_budget": token_budget,
        "tokens_used": used,
        "source_labels": body.source_labels,
        "local_semantic_profile": semantic_profile,
        "items": selected,
    });
    let receipt = workbench_receipt("context_pack", &tenant_id, &pack);
    let response = json!({
        "status": "ok",
        "pack": pack,
        "receipt": receipt,
    });
    if let Err(err) = store_workbench_fact(&state, &tenant_id, CONTEXT_PACK_KEY, &receipt, &response).await {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    Json(response).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_impact_preflight(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ImpactPreflightBody>,
) -> Response {
    let tenant_id = match tenant_id(&body.tenant_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    if let Some(response) =
        require_surface_for_tenant(&state, &headers, WorkbenchSurface::ImpactPreflight, true, &tenant_id)
    {
        return response;
    }
    let scan = crate::workspace_scan::load_latest(&state.fact_store).await;
    let impacted_routes = scan
        .as_ref()
        .map(|scan| impacted_routes(scan, &body.changed_paths, &body.routes, body.include_storyline))
        .unwrap_or_default();
    let superseded_facts = {
        let store = state.fact_store.read().await;
        tenant_facts(&store, &tenant_id, 500)
            .into_iter()
            .filter(|fact| fact.supersedes.is_some() || fact.version > 1)
            .take(50)
            .map(|fact| {
                json!({
                    "fact_id": fact.fact_id,
                    "entity": fact.entity,
                    "key": fact.key,
                    "version": fact.version,
                    "supersedes": fact.supersedes,
                })
            })
            .collect::<Vec<_>>()
    };
    let living_objects = living_object_preflight(&state, &tenant_id, &body.changed_paths).await;
    let preflight = json!({
        "schema": "crux.agent_workbench.impact_preflight.v1",
        "tenant_id": tenant_id,
        "changed_paths": body.changed_paths,
        "requested_routes": body.routes,
        "impacted_routes": impacted_routes,
        "selected_tests": body.selected_tests,
        "fact_supersession_refs": superseded_facts,
        "living_objects": living_objects,
    });
    let receipt = workbench_receipt("impact_preflight", &tenant_id, &preflight);
    let response = json!({ "status": "ok", "preflight": preflight, "receipt": receipt });
    if let Err(err) = store_workbench_fact(&state, &tenant_id, PREFLIGHT_KEY, &receipt, &response).await {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    Json(response).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_command_ledger(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CommandLedgerBody>,
) -> Response {
    let tenant_id = match tenant_id(&body.tenant_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    if let Some(response) =
        require_surface_for_tenant(&state, &headers, WorkbenchSurface::CommandLedger, true, &tenant_id)
    {
        return response;
    }
    if body.command.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "command must not be empty");
    }
    let started = body.started_at_unix_ms.unwrap_or_else(crate::ops_events::now_unix_ms);
    let completed = body.completed_at_unix_ms;
    let record = json!({
        "schema": "crux.agent_workbench.command_ledger.v1",
        "tenant_id": tenant_id,
        "recorded_at_unix_ms": crate::ops_events::now_unix_ms(),
        "started_at_unix_ms": started,
        "completed_at_unix_ms": completed,
        "command": body.command,
        "args": body.args,
        "cwd": body.cwd,
        "exit_status": body.exit_status,
        "duration_ms": body.duration_ms,
        "stdout_hash": body.stdout_hash,
        "stderr_hash": body.stderr_hash,
        "linked_receipts": body.linked_receipts,
        "project_id": body.project_id,
        "work_id": body.work_id,
        "replay_note": "metadata only; command output bytes are not stored by this route",
    });
    let receipt = workbench_receipt("command_ledger", &tenant_id, &record);
    let response = json!({ "status": "ok", "record": record, "receipt": receipt });
    if let Err(err) = store_workbench_fact(&state, &tenant_id, COMMAND_LEDGER_KEY, &receipt, &response).await {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    Json(response).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_command_ledger(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TenantWorkbenchQuery>,
) -> Response {
    let tenant_id = match tenant_id(&q.tenant_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    if let Some(response) =
        require_surface_for_tenant(&state, &headers, WorkbenchSurface::CommandLedger, false, &tenant_id)
    {
        return response;
    }
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let entries = {
        let store = state.fact_store.read().await;
        workbench_facts(&store, &tenant_id, COMMAND_LEDGER_KEY, limit)
    };
    Json(json!({
        "schema": "crux.agent_workbench.command_ledger_page.v1",
        "tenant_id": tenant_id,
        "count": entries.len(),
        "entries": entries,
    }))
    .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_audit_triage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TenantWorkbenchQuery>,
) -> Response {
    let tenant_id = match tenant_id(&q.tenant_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    if let Some(response) =
        require_surface_for_tenant(&state, &headers, WorkbenchSurface::AuditTriage, false, &tenant_id)
    {
        return response;
    }
    let ctx = match http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };
    let tenant_hash = super::facts::tenant_hash_for_read_context(&ctx);
    let sync_status = super::health::sync_runtime_status();
    let scan = crate::workspace_scan::load_latest(&state.fact_store).await;
    let queues = {
        let store = state.fact_store.read().await;
        audit_queues(&store, &tenant_id, &tenant_hash, &sync_status, scan.as_ref())
    };
    Json(json!({
        "schema": "crux.agent_workbench.audit_triage.v1",
        "tenant_id": tenant_id,
        "queues": queues,
    }))
    .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_reasoning_timeline(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TenantWorkbenchQuery>,
) -> Response {
    let tenant_id = match tenant_id(&q.tenant_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    if let Some(response) =
        require_surface_for_tenant(&state, &headers, WorkbenchSurface::ReasoningTimeline, false, &tenant_id)
    {
        return response;
    }
    let limit = q.limit.unwrap_or(80).clamp(1, 250);
    let events = {
        let store = state.fact_store.read().await;
        timeline_events(&store, &tenant_id, limit)
    };
    Json(json!({
        "schema": "crux.agent_workbench.reasoning_timeline.v1",
        "tenant_id": tenant_id,
        "count": events.len(),
        "events": events,
    }))
    .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_handoff_v2(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<HandoffV2Body>,
) -> Response {
    let tenant_id = match tenant_id(&body.tenant_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    if let Some(response) = require_surface_for_tenant(&state, &headers, WorkbenchSurface::HandoffV2, true, &tenant_id)
    {
        return response;
    }
    if body.goal.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "goal must not be empty");
    }
    let session_state = {
        let sessions = state.session_store.read().await;
        body.session_id
            .as_deref()
            .and_then(|id| sessions.get(id).cloned())
            .map(|session| json!(session))
    };
    let (constraints, decisions, command_summary) = {
        let store = state.fact_store.read().await;
        (
            tenant_facts_by_prefix(&store, "__constraints__::", &tenant_id, 25),
            tenant_facts_by_prefix(&store, "__decisions__::", &tenant_id, 25),
            workbench_facts(&store, &tenant_id, COMMAND_LEDGER_KEY, 10),
        )
    };
    let package = json!({
        "schema": "crux.agent_workbench.handoff_v2.v1",
        "tenant_id": tenant_id,
        "goal": &body.goal,
        "session_id": &body.session_id,
        "session_state": session_state,
        "project_id": &body.project_id,
        "source_agent": &body.source_agent,
        "target_agent": &body.target_agent,
        "constraints": constraints,
        "open_decisions": decisions,
        "evidence_refs": &body.evidence_refs,
        "command_ledger_summary": command_summary,
        "next_actions": &body.next_actions,
        "created_at_unix_ms": crate::ops_events::now_unix_ms(),
    });
    let receipt = workbench_receipt("handoff_v2", &tenant_id, &package);
    let mut response = json!({ "status": "ok", "package": package, "receipt": receipt });
    if state.handoff_observations_enabled {
        let obs = handoff_observation_body(&tenant_id, &body, &receipt);
        let scoped_session = body.session_id.as_deref().map_or_else(
            || format!("handoff::{tenant_id}"),
            |session_id| format!("handoff::{tenant_id}::{session_id}"),
        );
        let principal = obs
            .payload
            .get("source_passport")
            .and_then(Value::as_str)
            .unwrap_or(&state.passport_fpr)
            .to_string();
        match append_one(&state, &scoped_session, &principal, obs, None) {
            Ok((observation, _tip)) => {
                response["handoff_observation_id"] = json!(observation.observation_id);
            }
            Err((status, msg)) => return problem_response(status, msg),
        }
    }
    if let Err(err) = store_workbench_fact(&state, &tenant_id, HANDOFF_KEY, &receipt, &response).await {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    Json(response).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_route_probe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RouteProbeBody>,
) -> Response {
    if let Some(response) = require_surface(&state, &headers, WorkbenchSurface::RouteProbe, true) {
        return response;
    }
    let scan = match crate::workspace_scan::load_latest(&state.fact_store).await {
        Some(scan) => scan,
        None => {
            return problem_response(
                StatusCode::NOT_FOUND,
                "no scan found. POST /v1/workspace/scan to run one.",
            )
        }
    };
    let route = body.route.trim();
    let matched = route.split_once(' ').and_then(|(method, path)| {
        let method = method.to_ascii_uppercase();
        let path = path.trim();
        scan.routes
            .iter()
            .find(|r| r.method == method && r.path == path)
            .cloned()
    });
    let Some(route) = matched else {
        return problem_response(
            StatusCode::NOT_FOUND,
            format!("route '{}' not found in latest scan", body.route),
        );
    };
    let storyline = if body.include_storyline {
        crate::workspace_scan::compose_storyline_for_route(&scan, &route, body.include_tests)
            .map(|story| crate::workspace_scan::format_storyline_tree(&story))
    } else {
        None
    };
    Json(json!({
        "schema": "crux.agent_workbench.route_probe.v1",
        "route": {
            "method": route.method,
            "path": route.path,
            "handler_fn": route.handler_fn,
            "handler_file": route.handler_file,
            "handler_line": route.handler_line,
            "source_file": route.source_file,
            "source_line": route.source_line,
        },
        "scope_hints": scope_hints_for_route(&route.method, &route.path),
        "storyline": storyline,
        "warnings": if route.handler_file.is_none() {
            vec!["handler_file_unresolved"]
        } else {
            Vec::<&str>::new()
        },
    }))
    .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_api_drift(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TenantWorkbenchQuery>,
) -> Response {
    let tenant_id = match tenant_id(&q.tenant_id) {
        Ok(id) => id,
        Err(response) => return response,
    };
    if let Some(response) = require_surface_for_tenant(&state, &headers, WorkbenchSurface::ApiDrift, false, &tenant_id)
    {
        return response;
    }
    let scan = crate::workspace_scan::load_latest(&state.fact_store).await;
    let drift = api_drift_report(scan.as_ref());
    Json(drift).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_policy_simulation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PolicySimulationBody>,
) -> Response {
    let tenant_id = match body.action.tenant_id.as_deref().map_or_else(
        || Err(problem_response(StatusCode::BAD_REQUEST, "tenant_id must not be empty")),
        tenant_id,
    ) {
        Ok(id) => id,
        Err(response) => return response,
    };
    if let Some(response) =
        require_surface_for_tenant(&state, &headers, WorkbenchSurface::PolicySimulation, true, &tenant_id)
    {
        return response;
    }
    let proposal = {
        let store = state.fact_store.read().await;
        enrich_action(Some(&store), body.action)
    };
    let constraints = {
        let store = state.fact_store.read().await;
        active_constraints(&store, &tenant_id)
    };
    let matches = match_constraints(&proposal.narrative, &constraints);
    let verdict = if matches.iter().any(|m| m["severity"] == "critical") {
        "block"
    } else if matches.iter().any(|m| m["severity"] == "high")
        || proposal
            .consequence_metadata
            .materiality
            .contains(&Materiality::TouchesProduction)
    {
        "warn"
    } else {
        "pass"
    };
    let simulation = json!({
        "schema": "crux.agent_workbench.policy_simulation.v1",
        "tenant_id": tenant_id,
        "verdict": verdict,
        "proposal": proposal,
        "matched_constraints": matches,
    });
    let receipt = workbench_receipt("policy_simulation", &tenant_id, &simulation);
    let response = json!({ "status": "ok", "simulation": simulation, "receipt": receipt });
    if let Err(err) = store_workbench_fact(&state, &tenant_id, POLICY_SIM_KEY, &receipt, &response).await {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    Json(response).into_response()
}

fn service_contract(product: &crate::product::ProductPosture, surface: WorkbenchSurface) -> Value {
    let enabled = product
        .enabled_pro_services
        .iter()
        .any(|service| service == surface.capability());
    let status = if enabled {
        "enabled"
    } else if product.tier == "free" {
        "pro_required"
    } else {
        "entitled_not_enabled"
    };
    json!({
        "capability": surface.capability(),
        "method": surface.method(),
        "path": surface.path(),
        "status": status,
    })
}

fn require_surface(state: &AppState, headers: &HeaderMap, surface: WorkbenchSurface, write: bool) -> Option<Response> {
    let fallback_scope = if write { "admin:write" } else { "admin:read" };
    if let Err(problem) = require_http_any_scope(&state.auth, headers, &[surface.capability(), fallback_scope]) {
        return Some(problem.into_response());
    }
    require_surface_enabled(state, surface)
}

fn require_surface_for_tenant(
    state: &AppState,
    headers: &HeaderMap,
    surface: WorkbenchSurface,
    write: bool,
    tenant_id: &str,
) -> Option<Response> {
    let fallback_scope = if write { "admin:write" } else { "admin:read" };
    if require_http_any_scope(&state.auth, headers, &[fallback_scope]).is_err() {
        if let Err(problem) = require_http_scopes_for_tenant(&state.auth, headers, &[surface.capability()], tenant_id) {
            return Some(problem.into_response());
        }
    }
    require_surface_enabled(state, surface)
}

fn require_surface_enabled(state: &AppState, surface: WorkbenchSurface) -> Option<Response> {
    let product = crate::product::ProductPosture::new(state.operating_mode, &state.enabled_pro_services);
    if !product
        .enabled_pro_services
        .iter()
        .any(|service| service == surface.capability())
    {
        return Some(
            (
                StatusCode::PAYMENT_REQUIRED,
                Json(json!({
                    "schema": WORKBENCH_CONTRACT_SCHEMA,
                    "status": "pro_service_not_enabled",
                    "capability": surface.capability(),
                    "path": surface.path(),
                    "fallback": {
                        "reason_code": "pro_service_not_enabled",
                        "detail": "enable this Agent Workbench Pro capability before using the surface"
                    }
                })),
            )
                .into_response(),
        );
    }
    None
}

#[allow(clippy::result_large_err)]
fn tenant_id(value: &str) -> Result<String, Response> {
    let id = value.trim();
    if id.is_empty() {
        return Err(problem_response(StatusCode::BAD_REQUEST, "tenant_id must not be empty"));
    }
    Ok(id.to_string())
}

async fn store_workbench_fact(
    state: &AppState,
    tenant_id: &str,
    key: &str,
    receipt: &Value,
    value: &Value,
) -> std::io::Result<()> {
    let receipt_id = receipt
        .get("receipt_id")
        .and_then(Value::as_str)
        .unwrap_or("unsealed")
        .to_string();
    let mut fact = StoreFact {
        tenant_hash: "default".to_string(),
        entity: format!("{WORKBENCH_FACT_PREFIX}::{tenant_id}::{key}::{receipt_id}"),
        key: key.to_string(),
        value: serde_json::to_string(value).map_err(std::io::Error::other)?,
        source_receipt: Some(receipt_id),
        confidence: 1.0,
        private: true,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce(&state.privacy_policy, &mut fact);
    state.fact_store.write().await.try_store(fact)?;
    Ok(())
}

fn workbench_receipt(kind: &str, tenant_id: &str, payload: &Value) -> Value {
    let payload_hash = hash_json(payload);
    let suffix = payload_hash
        .trim_start_matches("blake3:")
        .chars()
        .take(16)
        .collect::<String>();
    json!({
        "schema": WORKBENCH_RECEIPT_SCHEMA,
        "receipt_id": format!("workbench:{kind}:{suffix}"),
        "event_type": format!("agent_workbench_{kind}"),
        "tenant_id": tenant_id,
        "payload_hash": payload_hash,
        "created_at_unix_ms": crate::ops_events::now_unix_ms(),
    })
}

fn normalize_handoff_agent(agent: Option<&str>) -> Option<String> {
    let trimmed = agent?.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_ascii_lowercase())
    }
}

fn handoff_agent_lookup_key(agent: &str) -> &str {
    match agent {
        "claude" | "claude-code" | "anthropic" => "anthropic",
        "codex" | "codex-cli" | "openai" => "openai",
        other => other,
    }
}

fn resolve_handoff_agent_passport(agent: &str) -> Option<String> {
    let map = crux_mcp::agent_passport::AgentPassportMap::from_env_or_default();
    crux_mcp::agent_passport::resolve_agent_passport(handoff_agent_lookup_key(agent), &map).or_else(|| {
        let fallback = crux_mcp::agent_passport::AgentPassportMap::builtin_default();
        crux_mcp::agent_passport::resolve_agent_passport(handoff_agent_lookup_key(agent), &fallback)
    })
}

fn handoff_observation_body(tenant_id: &str, body: &HandoffV2Body, receipt: &Value) -> PostObservationBody {
    let source_agent = normalize_handoff_agent(body.source_agent.as_deref());
    let target_agent = normalize_handoff_agent(body.target_agent.as_deref());
    let source_passport = source_agent.as_deref().and_then(resolve_handoff_agent_passport);
    let target_passport = target_agent.as_deref().and_then(resolve_handoff_agent_passport);
    let cross_vendor = match (&source_passport, &target_passport) {
        (Some(source), Some(target)) => Some(source != target),
        _ => None,
    };
    PostObservationBody {
        kind: "handoff".to_string(),
        provider: "crux-handoff".to_string(),
        client_ts: None,
        payload: json!({
            "schema": "crux.s1.handoff_observation.v1",
            "tenant_id": tenant_id,
            "session_id": &body.session_id,
            "project_id": &body.project_id,
            "goal_hash": hash_text(&body.goal),
            "source_agent": source_agent,
            "target_agent": target_agent,
            "source_passport": source_passport,
            "target_passport": target_passport,
            "cross_vendor": cross_vendor,
            "handoff_receipt_id": receipt.get("receipt_id").and_then(Value::as_str),
            "handoff_payload_hash": receipt.get("payload_hash").and_then(Value::as_str),
        }),
    }
}

fn query_facts(store: &FactStore, query: Option<&str>, entity_prefix: Option<&str>, top_k: usize) -> Vec<Fact> {
    crate::fact_helpers::dedup_latest(
        store
            .query(&FactQuery {
                min_effective_confidence: None,
                tenant_hash: None,
                query: query.map(str::to_string),
                entity: None,
                entity_prefix: entity_prefix.map(str::to_string),
                top_k,
                token_budget: None,
            })
            .facts,
    )
}

fn tenant_facts_by_prefix(store: &FactStore, prefix: &str, tenant_id: &str, limit: usize) -> Vec<Value> {
    query_facts(store, None, Some(prefix), limit.saturating_mul(4).max(limit))
        .into_iter()
        .filter(|fact| {
            fact.entity.contains(tenant_id) || fact.value.contains(tenant_id) || fact.key.contains(tenant_id)
        })
        .take(limit)
        .map(fact_summary)
        .collect()
}

fn tenant_facts(store: &FactStore, tenant_id: &str, limit: usize) -> Vec<Fact> {
    query_facts(store, Some(tenant_id), None, limit)
        .into_iter()
        .filter(|fact| fact.entity.contains(tenant_id) || fact.value.contains(tenant_id))
        .take(limit)
        .collect()
}

fn workbench_facts(store: &FactStore, tenant_id: &str, key: &str, limit: usize) -> Vec<Value> {
    let prefix = format!("{WORKBENCH_FACT_PREFIX}::{tenant_id}::{key}::");
    query_facts(store, None, Some(&prefix), limit)
        .into_iter()
        .take(limit)
        .filter_map(|fact| serde_json::from_str::<Value>(&fact.value).ok())
        .collect()
}

fn recent_receipt_refs(store: &FactStore, tenant_id: &str, limit: usize) -> Vec<Value> {
    let mut out = Vec::new();
    for prefix in [
        format!("__gpu1_receipt__::{tenant_id}::"),
        format!(
            "{}::{tenant_id}::",
            corecrux_memory::action_enrichment::ACTION_ENRICHMENT_RECEIPT_ENTITY_PREFIX
        ),
        format!("{WORKBENCH_FACT_PREFIX}::{tenant_id}::"),
    ] {
        out.extend(
            query_facts(store, None, Some(&prefix), limit)
                .into_iter()
                .map(|fact| {
                    json!({
                        "fact_id": fact.fact_id,
                        "entity": fact.entity,
                        "key": fact.key,
                        "source_receipt": fact.source_receipt,
                        "stored_at": fact.stored_at,
                    })
                })
                .collect::<Vec<_>>(),
        );
    }
    out.sort_by(|a, b| {
        b["stored_at"]
            .as_str()
            .unwrap_or_default()
            .cmp(a["stored_at"].as_str().unwrap_or_default())
    });
    out.truncate(limit);
    out
}

fn fact_summary(fact: Fact) -> Value {
    json!({
        "fact_id": fact.fact_id,
        "entity": fact.entity,
        "key": fact.key,
        "value_preview": truncate(&fact.value, 240),
        "source_receipt": fact.source_receipt,
        "confidence": fact.confidence,
        "stored_at": fact.stored_at,
        "version": fact.version,
    })
}

fn estimate_tokens(text: &str) -> usize {
    text.len().div_ceil(4)
}

fn source_label_for_entity(entity: &str) -> &'static str {
    if entity.starts_with("__constraints__::") {
        "constraint"
    } else if entity.starts_with("__decisions__::") {
        "decision"
    } else if entity.starts_with("__work__::") {
        "work"
    } else if entity.starts_with("__workspace_scan__::") {
        "workspace_scan"
    } else if entity.starts_with("github::") {
        "github"
    } else {
        "fact_store"
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        format!("{}...", value.chars().take(max).collect::<String>())
    }
}

fn impacted_routes(
    scan: &crate::workspace_scan::WorkspaceScan,
    changed_paths: &[String],
    requested_routes: &[String],
    include_storyline: bool,
) -> Vec<Value> {
    let mut routes = scan
        .routes
        .iter()
        .filter(|route| {
            requested_routes
                .iter()
                .any(|needle| route_matches(needle, &route.method, &route.path))
                || route.handler_file.as_deref().is_some_and(|file| {
                    changed_paths
                        .iter()
                        .any(|path| file.contains(path) || path.contains(file))
                })
                || changed_paths
                    .iter()
                    .any(|path| route.source_file.contains(path) || path.contains(&route.source_file))
        })
        .map(|route| {
            let storyline = include_storyline
                .then(|| crate::workspace_scan::compose_storyline_for_route(scan, route, false))
                .flatten()
                .map(|story| crate::workspace_scan::format_storyline_tree(&story));
            json!({
                "method": route.method,
                "path": route.path,
                "handler_fn": route.handler_fn,
                "handler_file": route.handler_file,
                "source_file": route.source_file,
                "scope_hints": scope_hints_for_route(&route.method, &route.path),
                "storyline": storyline,
            })
        })
        .collect::<Vec<_>>();
    routes.sort_by_key(route_key);
    routes.dedup_by(|a, b| route_key(a) == route_key(b));
    routes
}

fn route_key(value: &Value) -> String {
    format!(
        "{} {}",
        value["method"].as_str().unwrap_or_default(),
        value["path"].as_str().unwrap_or_default()
    )
}

fn route_matches(needle: &str, method: &str, path: &str) -> bool {
    needle.trim() == format!("{method} {path}") || needle.trim() == path
}

fn scope_hints_for_route(method: &str, path: &str) -> Vec<&'static str> {
    if let Some(surface) = surface_for_path(path) {
        let mut scopes = vec![surface.capability()];
        if matches!(
            method.to_ascii_uppercase().as_str(),
            "POST" | "PUT" | "PATCH" | "DELETE"
        ) {
            scopes.push("admin:write");
        } else {
            scopes.push("admin:read");
        }
        scopes.sort_unstable();
        scopes.dedup();
        return scopes;
    }

    let mut scopes = Vec::new();
    let method = method.to_ascii_uppercase();
    if path.contains("/admin") || path.contains("/workspace") || path.contains("/workbench") {
        scopes.push("admin:read");
    }
    if matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE") {
        if path.contains("/facts")
            || path.contains("/sync")
            || path.contains("/projects")
            || path.contains("/work")
            || path.contains("/actions")
        {
            scopes.push("facts:write");
        }
        if path.contains("/sessions") {
            scopes.push("sessions:write");
        }
    } else if path.contains("/facts") || path.contains("/query") {
        scopes.push("query:read");
    }
    if path.contains("/receipts") || path.contains("/replay") {
        scopes.push("receipts:read");
    }
    if scopes.is_empty() {
        scopes.push("query:read");
    }
    scopes.sort_unstable();
    scopes.dedup();
    scopes
}

fn surface_for_path(path: &str) -> Option<WorkbenchSurface> {
    WorkbenchSurface::all()
        .into_iter()
        .find(|surface| surface.path() == path)
}

fn api_drift_report(scan: Option<&crate::workspace_scan::WorkspaceScan>) -> Value {
    let tools = crux_mcp::tools::list_tools_json();
    let tool_count = tools["tools"].as_array().map_or(0, Vec::len);
    let Some(scan) = scan else {
        return json!({
            "schema": "crux.agent_workbench.api_drift.v1",
            "status": "no_workspace_scan",
            "tool_count": tool_count,
            "route_count": 0,
            "queues": [{
                "category": "workspace_scan_missing",
                "severity": "medium",
                "items": ["POST /v1/workspace/scan before route/API drift checks"]
            }]
        });
    };
    let unresolved = scan
        .diagnostics
        .unresolved_routes
        .iter()
        .map(|route| {
            json!({
                "method": route.method,
                "path": route.path,
                "handler_fn": route.handler_fn,
                "reason": route.reason,
            })
        })
        .collect::<Vec<_>>();
    let workbench_routes = WorkbenchSurface::all()
        .into_iter()
        .filter(|surface| !route_exists(scan, surface.method(), surface.path()))
        .map(|surface| {
            json!({
                "method": surface.method(),
                "path": surface.path(),
                "capability": surface.capability(),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema": "crux.agent_workbench.api_drift.v1",
        "status": if unresolved.is_empty() && workbench_routes.is_empty() { "ok" } else { "drift_detected" },
        "route_count": scan.routes.len(),
        "tool_count": tool_count,
        "routes_by_crate": scan.stats.routes_by_crate,
        "queues": [
            {
                "category": "unresolved_routes",
                "severity": if unresolved.is_empty() { "ok" } else { "medium" },
                "count": unresolved.len(),
                "items": unresolved,
            },
            {
                "category": "workbench_contract_missing_from_scan",
                "severity": if workbench_routes.is_empty() { "ok" } else { "low" },
                "count": workbench_routes.len(),
                "items": workbench_routes,
            }
        ],
    })
}

fn route_exists(scan: &crate::workspace_scan::WorkspaceScan, method: &str, path: &str) -> bool {
    scan.routes
        .iter()
        .any(|route| method.contains(&route.method) && normalize_path(&route.path) == normalize_path(path))
}

fn normalize_path(path: &str) -> String {
    let mut out = String::new();
    let mut in_brace = false;
    for c in path.chars() {
        match c {
            '{' => {
                in_brace = true;
                out.push_str("{}");
            }
            '}' => in_brace = false,
            _ if !in_brace => out.push(c),
            _ => {}
        }
    }
    out
}

fn audit_queues(
    store: &FactStore,
    tenant_id: &str,
    tenant_hash: &str,
    sync_status: &corecrux_memory::sync::SyncRuntimeStatus,
    scan: Option<&crate::workspace_scan::WorkspaceScan>,
) -> Vec<Value> {
    let degraded_receipts = recent_receipt_refs(store, tenant_id, 100)
        .into_iter()
        .filter(|receipt| serde_json::to_string(receipt).unwrap_or_default().contains("degraded"))
        .collect::<Vec<_>>();
    let sync_conflicts = if sync_status.degraded {
        vec![json!({
                "mode": sync_status.mode,
                "reason": sync_status.degraded_reason,
        })]
    } else {
        Vec::new()
    };
    let unresolved_routes = scan
        .map(|scan| scan.diagnostics.unresolved_routes.len())
        .unwrap_or_default();
    let replay_failures = replay_failure_items(store, tenant_id, tenant_hash, 50);
    let replay_failure_severity = replay_failure_severity(&replay_failures);
    vec![
        json!({
            "category": "receipt_anomalies",
            "severity": if degraded_receipts.is_empty() { "ok" } else { "medium" },
            "count": degraded_receipts.len(),
            "items": degraded_receipts,
        }),
        json!({
            "category": "sync_conflicts",
            "severity": if sync_conflicts.is_empty() { "ok" } else { "high" },
            "count": sync_conflicts.len(),
            "items": sync_conflicts,
        }),
        json!({
            "category": "route_resolution_drift",
            "severity": if unresolved_routes == 0 { "ok" } else { "medium" },
            "count": unresolved_routes,
            "items": scan.map(|scan| scan.diagnostics.unresolved_routes.clone()).unwrap_or_default(),
        }),
        json!({
            "category": "replay_failures",
            "severity": replay_failure_severity,
            "count": replay_failures.len(),
            "items": replay_failures,
        }),
    ]
}

async fn living_object_preflight(state: &AppState, tenant_id: &str, changed_paths: &[String]) -> Value {
    let tenant_hash = corecrux_projections::tenant_hash_xxhash64(tenant_id);
    let projection = state.projection_state.read().await;
    let mut status_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut drift_categories: BTreeSet<String> = BTreeSet::new();
    let mut drifted_artifacts = Vec::new();
    let mut tracked_count = 0usize;
    let mut dependent_count = 0i64;

    for ((row_tenant_hash, artifact_id), row) in &projection.living {
        if *row_tenant_hash != tenant_hash {
            continue;
        }
        tracked_count += 1;
        dependent_count += i64::from(row.dependents_count);
        let status = row.living_status.as_engine_str();
        *status_counts.entry(status.to_string()).or_default() += 1;
        if let Some(category) = living_status_drift_category(row.living_status) {
            drift_categories.insert(category.to_string());
            if drifted_artifacts.len() < 50 {
                drifted_artifacts.push(json!({
                    "artifact_id": artifact_id,
                    "living_status": status,
                    "confidence": corecrux_projections::dequantize_confidence_f32(row.confidence_q16),
                    "dependents_count": row.dependents_count,
                    "pressure_level": row.pressure_level,
                    "updated_at_micros": row.updated_at_micros,
                }));
            }
        }
    }

    let open_pressure_event_count = projection
        .pressure
        .keys()
        .filter(|(row_tenant_hash, _, _)| *row_tenant_hash == tenant_hash)
        .count();
    let status = if tracked_count == 0 {
        "not_recorded"
    } else if drifted_artifacts.is_empty() {
        "current"
    } else {
        "stale"
    };

    json!({
        "status": status,
        "source": "local_projection_state",
        "tenant_hash": format!("{tenant_hash:016x}"),
        "changed_path_count": changed_paths.len(),
        "tracked_artifact_count": tracked_count,
        "status_counts": status_counts,
        "drift_categories": drift_categories.into_iter().collect::<Vec<_>>(),
        "drifted_artifacts": drifted_artifacts,
        "affected_downstream_projections": {
            "dependent_count": dependent_count,
        },
        "open_pressure_event_count": open_pressure_event_count,
    })
}

fn living_status_drift_category(status: corecrux_projections::LivingStatusV1) -> Option<&'static str> {
    match status {
        corecrux_projections::LivingStatusV1::Stale => Some("living_state_stale"),
        corecrux_projections::LivingStatusV1::Contested => Some("living_state_contested"),
        corecrux_projections::LivingStatusV1::Superseded => Some("living_state_superseded"),
        corecrux_projections::LivingStatusV1::Deprecated => Some("living_state_deprecated"),
        corecrux_projections::LivingStatusV1::Dormant | corecrux_projections::LivingStatusV1::Active => None,
    }
}

fn replay_failure_items(store: &FactStore, tenant_id: &str, tenant_hash: &str, limit: usize) -> Vec<Value> {
    let prefix = format!("{ANSWER_REPLAY_CAPSULE_ENTITY_PREFIX}::{tenant_id}::");
    query_facts(store, None, Some(&prefix), limit)
        .into_iter()
        .filter_map(|fact| serde_json::from_str::<AnswerReplayCapsule>(&fact.value).ok())
        .filter_map(|capsule| replay_failure_item(store, capsule, tenant_hash))
        .take(limit)
        .collect()
}

fn replay_failure_item(store: &FactStore, capsule: AnswerReplayCapsule, tenant_hash: &str) -> Option<Value> {
    let mut categories = BTreeSet::new();
    for evidence in &capsule.evidence {
        if let Some(category) = replay_evidence_drift_category(store, evidence, tenant_hash) {
            categories.insert(category);
        }
    }
    if let Some(category) = replay_semantic_profile_category(store, &capsule) {
        categories.insert(category);
    }
    for category in replay_projection_categories(&capsule) {
        categories.insert(category);
    }
    if categories.is_empty() {
        return None;
    }
    Some(json!({
        "answer_id": capsule.answer_id,
        "capsule_hash": capsule.capsule_hash,
        "question_preview": truncate(&capsule.question, 180),
        "categories": categories.into_iter().collect::<Vec<_>>(),
        "evidence_count": capsule.evidence.len(),
        "projection_ref_count": capsule.projection_refs.len(),
        "created_at": capsule.created_at,
    }))
}

fn replay_evidence_drift_category(
    store: &FactStore,
    evidence: &corecrux_memory::replay::ReplayEvidenceRef,
    tenant_hash: &str,
) -> Option<String> {
    let Some(fact) = store.get_for_tenant(&evidence.record_id, tenant_hash) else {
        return Some("fact_missing".to_string());
    };
    let latest_id = latest_fact_for_entity_key(store, fact, tenant_hash).map(|latest| latest.fact_id.as_str());
    if latest_id.is_some_and(|id| id != evidence.record_id) {
        return Some("fact_superseded".to_string());
    }
    let current_hash = hash_text(&fact.value);
    let captured_hash = evidence.text_hash.as_ref().or(evidence.content_hash.as_ref());
    if captured_hash.is_some_and(|hash| hash == &current_hash)
        || evidence.content_hash.as_ref().is_some_and(|hash| hash == &current_hash)
    {
        None
    } else {
        Some("fact_changed".to_string())
    }
}

fn latest_fact_for_entity_key<'a>(store: &'a FactStore, fact: &Fact, tenant_hash: &str) -> Option<&'a Fact> {
    store
        .get_by_entity_for_tenant(&fact.entity, tenant_hash)
        .into_iter()
        .filter(|candidate| candidate.key == fact.key)
        .max_by_key(|candidate| candidate.version)
}

fn replay_semantic_profile_category(store: &FactStore, capsule: &AnswerReplayCapsule) -> Option<String> {
    let captured = capsule
        .local_semantic_profile_id
        .as_deref()
        .or(capsule.semantic_profile_id.as_deref())?;
    let current = store.semantic_profile();
    let current_id = current.as_ref().map(|profile| profile.profile_id.as_str());
    match current_id {
        Some(id) if id == captured => None,
        Some(_) => Some("semantic_profile_changed".to_string()),
        None => Some("semantic_profile_unavailable".to_string()),
    }
}

fn replay_projection_categories(capsule: &AnswerReplayCapsule) -> Vec<String> {
    let current = corecrux_projections::current_projection_module_versions_v1();
    capsule
        .projection_refs
        .iter()
        .filter_map(|reference| {
            let matched = current.iter().find(|module| {
                module.matches_ref(
                    &reference.module_id,
                    &reference.module_version,
                    reference.code_hash.as_deref(),
                    reference.config_hash.as_deref(),
                ) && reference
                    .schema_version
                    .is_none_or(|schema_version| schema_version == module.schema_version)
            })?;
            match &matched.status {
                corecrux_projections::ProjectionModuleStatusV1::Active
                | corecrux_projections::ProjectionModuleStatusV1::RetainedForReplay => None,
                corecrux_projections::ProjectionModuleStatusV1::Deprecated => {
                    Some("projection_module_deprecated".to_string())
                }
                corecrux_projections::ProjectionModuleStatusV1::Unavailable => {
                    Some("projection_module_unavailable".to_string())
                }
            }
        })
        .chain(
            capsule
                .projection_refs
                .iter()
                .filter(|reference| {
                    !current.iter().any(|module| {
                        module.matches_ref(
                            &reference.module_id,
                            &reference.module_version,
                            reference.code_hash.as_deref(),
                            reference.config_hash.as_deref(),
                        ) && reference
                            .schema_version
                            .is_none_or(|schema_version| schema_version == module.schema_version)
                    })
                })
                .map(|_| "projection_module_unavailable".to_string()),
        )
        .collect()
}

fn replay_failure_severity(items: &[Value]) -> &'static str {
    if items.is_empty() {
        return "ok";
    }
    let has_high = items.iter().any(|item| {
        item["categories"].as_array().is_some_and(|categories| {
            categories.iter().any(|category| {
                category
                    .as_str()
                    .is_some_and(|value| matches!(value, "fact_missing" | "projection_module_unavailable"))
            })
        })
    });
    if has_high {
        "high"
    } else {
        "medium"
    }
}

pub(super) fn timeline_events(store: &FactStore, tenant_id: &str, limit: usize) -> Vec<Value> {
    let mut events = Vec::new();
    for (prefix, kind) in [
        (
            format!(
                "{}::{tenant_id}::",
                corecrux_memory::action_enrichment::ACTION_ENRICHMENT_RECEIPT_ENTITY_PREFIX
            ),
            "action_enrichment",
        ),
        (format!("__gpu1_receipt__::{tenant_id}::"), "gpu1_compute"),
        (format!("{WORKBENCH_FACT_PREFIX}::{tenant_id}::"), "workbench"),
        (format!("__work__::{tenant_id}::"), "work"),
    ] {
        events.extend(
            query_facts(store, None, Some(&prefix), limit)
                .into_iter()
                .map(|fact| {
                    json!({
                        "kind": kind,
                        "fact_id": fact.fact_id,
                        "entity": fact.entity,
                        "key": fact.key,
                        "source_receipt": fact.source_receipt,
                        "stored_at": fact.stored_at,
                    })
                })
                .collect::<Vec<_>>(),
        );
    }
    events.sort_by(|a, b| {
        b["stored_at"]
            .as_str()
            .unwrap_or_default()
            .cmp(a["stored_at"].as_str().unwrap_or_default())
    });
    events.truncate(limit);
    events
}

fn active_constraints(store: &FactStore, tenant_id: &str) -> Vec<Value> {
    query_facts(store, None, Some("__constraints__::"), 200)
        .into_iter()
        .filter(|fact| {
            fact.entity.contains(tenant_id) || fact.value.contains(tenant_id) || fact.key.contains(tenant_id)
        })
        .map(|fact| {
            let parsed = serde_json::from_str::<Value>(&fact.value).ok();
            if let Some(mut value) = parsed {
                if let Some(obj) = value.as_object_mut() {
                    obj.entry("fact_id").or_insert_with(|| json!(fact.fact_id));
                    obj.entry("entity").or_insert_with(|| json!(fact.entity));
                    obj.entry("key").or_insert_with(|| json!(fact.key));
                }
                value
            } else {
                fact_summary(fact)
            }
        })
        .collect()
}

fn match_constraints(narrative: &str, constraints: &[Value]) -> Vec<Value> {
    let action_terms = terms(narrative);
    let mut matches = Vec::new();
    for constraint in constraints {
        let assertion = constraint
            .get("assertion")
            .and_then(Value::as_str)
            .or_else(|| constraint.get("value_preview").and_then(Value::as_str))
            .unwrap_or_default();
        let assertion_terms = terms(assertion);
        if assertion_terms.is_empty() {
            continue;
        }
        let overlap = assertion_terms
            .iter()
            .filter(|term| action_terms.contains(term))
            .count();
        if overlap > 0 {
            matches.push(json!({
                "constraint_id": constraint.get("constraint_id").cloned().unwrap_or_else(|| constraint.get("fact_id").cloned().unwrap_or(Value::Null)),
                "assertion": assertion,
                "severity": constraint.get("severity").and_then(Value::as_str).unwrap_or("medium"),
                "match_score": overlap as f32 / assertion_terms.len() as f32,
            }));
        }
    }
    matches.sort_by(|a, b| {
        b["match_score"]
            .as_f64()
            .unwrap_or_default()
            .partial_cmp(&a["match_score"].as_f64().unwrap_or_default())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    matches
}

fn terms(input: &str) -> Vec<String> {
    let mut out = input
        .to_ascii_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|term| term.len() >= 3)
        .map(str::to_string)
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_replaces_path_params() {
        assert_eq!(normalize_path("/v1/work/{id}/comments"), "/v1/work/{}/comments");
    }

    #[test]
    fn scope_hints_distinguish_write_routes() {
        let scopes = scope_hints_for_route("POST", "/v1/facts");
        assert!(scopes.contains(&"facts:write"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod helper_tests {
    use super::*;

    fn st_free() -> AppState {
        super::super::tests::test_app_state(16)
    }

    fn seed(store: &mut FactStore, entity: &str, key: &str, value: &str) {
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
    }

    #[test]
    fn estimate_tokens_rounds_up_by_four() {
        assert_eq!(estimate_tokens(""), 0);
        assert_eq!(estimate_tokens("abcd"), 1);
        assert_eq!(estimate_tokens("abcde"), 2);
    }

    #[test]
    fn source_label_covers_each_prefix() {
        assert_eq!(source_label_for_entity("__constraints__::x"), "constraint");
        assert_eq!(source_label_for_entity("__decisions__::x"), "decision");
        assert_eq!(source_label_for_entity("__work__::x"), "work");
        assert_eq!(source_label_for_entity("__workspace_scan__::x"), "workspace_scan");
        assert_eq!(source_label_for_entity("github::x"), "github");
        assert_eq!(source_label_for_entity("person:alice"), "fact_store");
    }

    #[test]
    fn tenant_id_validates() {
        assert_eq!(tenant_id("  t1 ").unwrap(), "t1");
        assert!(tenant_id("   ").is_err());
    }

    #[test]
    fn truncate_caps_length() {
        assert_eq!(truncate("hello", 100), "hello");
        let t = truncate(&"x".repeat(300), 240);
        assert!(t.len() <= 244, "truncated + ellipsis stays bounded: {}", t.len());
    }

    #[test]
    fn workbench_receipt_shape() {
        let payload = json!({ "a": 1 });
        let r = workbench_receipt("brief", "t1", &payload);
        assert_eq!(r["schema"], WORKBENCH_RECEIPT_SCHEMA);
        assert_eq!(r["tenant_id"], "t1");
        assert_eq!(r["event_type"], "agent_workbench_brief");
        assert!(r["receipt_id"].as_str().unwrap().starts_with("workbench:brief:"));
        assert!(r["payload_hash"].as_str().unwrap().starts_with("blake3:"));
    }

    #[test]
    fn handoff_observation_payload_marks_cross_vendor() {
        let body = HandoffV2Body {
            tenant_id: "work".to_string(),
            goal: "move the work".to_string(),
            session_id: Some("s1".to_string()),
            project_id: Some("p1".to_string()),
            source_agent: Some("anthropic".to_string()),
            target_agent: Some("openai".to_string()),
            evidence_refs: Vec::new(),
            next_actions: Vec::new(),
        };
        let obs = handoff_observation_body("work", &body, &workbench_receipt("handoff_v2", "work", &json!({})));
        assert_eq!(obs.kind, "handoff");
        assert_eq!(obs.provider, "crux-handoff");
        assert_eq!(obs.payload["source_passport"], "claude-work");
        assert_eq!(obs.payload["target_passport"], "codex-work");
        assert_eq!(obs.payload["cross_vendor"], true);
    }

    #[test]
    fn handoff_observation_payload_marks_same_vendor_and_unknown_target() {
        let same = HandoffV2Body {
            tenant_id: "work".to_string(),
            goal: "same vendor".to_string(),
            session_id: None,
            project_id: None,
            source_agent: Some("claude-code".to_string()),
            target_agent: Some("anthropic".to_string()),
            evidence_refs: Vec::new(),
            next_actions: Vec::new(),
        };
        let same_obs = handoff_observation_body("work", &same, &workbench_receipt("handoff_v2", "work", &json!({})));
        assert_eq!(same_obs.payload["source_passport"], "claude-work");
        assert_eq!(same_obs.payload["target_passport"], "claude-work");
        assert_eq!(same_obs.payload["cross_vendor"], false);

        let unknown = HandoffV2Body {
            target_agent: Some("unknown-agent".to_string()),
            ..same
        };
        let unknown_obs =
            handoff_observation_body("work", &unknown, &workbench_receipt("handoff_v2", "work", &json!({})));
        assert_eq!(unknown_obs.payload["source_passport"], "claude-work");
        assert!(unknown_obs.payload["target_passport"].is_null());
        assert!(unknown_obs.payload["cross_vendor"].is_null());
    }

    #[test]
    fn service_contract_status_transitions() {
        use crate::product::{OperatingMode, ProductPosture};
        let cap = WorkbenchSurface::AgentBrief.capability().to_string();
        // Free tier → pro_required.
        let free = ProductPosture::new(OperatingMode::FreeLocal, &[]);
        assert_eq!(
            service_contract(&free, WorkbenchSurface::AgentBrief)["status"],
            "pro_required"
        );
        // Pro tier, capability enabled → enabled.
        let enabled = ProductPosture::new(OperatingMode::ProHybrid, std::slice::from_ref(&cap));
        assert_eq!(
            service_contract(&enabled, WorkbenchSurface::AgentBrief)["status"],
            "enabled"
        );
        // Pro tier, not enabled → entitled_not_enabled.
        let pro_off = ProductPosture::new(OperatingMode::ProHybrid, &[]);
        assert_eq!(
            service_contract(&pro_off, WorkbenchSurface::AgentBrief)["status"],
            "entitled_not_enabled"
        );
    }

    #[tokio::test]
    async fn query_and_workbench_facts_round_trip() {
        let st = st_free();
        {
            let mut store = st.fact_store.write().await;
            seed(
                &mut store,
                "__workbench__::t1::brief::r1",
                "brief",
                r#"{"hello":"world"}"#,
            );
            seed(&mut store, "person:alice", "city", "NYC");
        }
        let store = st.fact_store.read().await;
        // query_facts by prefix.
        let facts = query_facts(&store, None, Some("__workbench__::t1::"), 10);
        assert!(!facts.is_empty());
        // fact_summary builds a preview object.
        let summary = fact_summary(facts[0].clone());
        assert!(summary["entity"].as_str().unwrap().contains("__workbench__::t1::brief"));
        // workbench_facts parses the stored JSON value.
        let wf = workbench_facts(&store, "t1", "brief", 10);
        assert_eq!(wf.len(), 1);
        assert_eq!(wf[0]["hello"], "world");
        // tenant_facts filters by tenant occurrence.
        let tf = tenant_facts(&store, "t1", 10);
        assert!(tf.iter().all(|f| f.entity.contains("t1") || f.value.contains("t1")));
    }

    #[tokio::test]
    async fn contract_handler_ok_and_brief_requires_pro() {
        let st = st_free();
        // Contract is always readable (Off-mode bypasses scope).
        let resp = get_workbench_contract(State(st.clone()), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Empty tenant → 400.
        let q: TenantWorkbenchQuery = serde_json::from_value(json!({ "tenant_id": "" })).unwrap();
        let resp = get_agent_brief(State(st.clone()), HeaderMap::new(), Query(q)).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Valid tenant but FreeLocal → AgentBrief pro capability not enabled → 402.
        let q: TenantWorkbenchQuery = serde_json::from_value(json!({ "tenant_id": "t1" })).unwrap();
        let resp = get_agent_brief(State(st), HeaderMap::new(), Query(q)).await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    }

    // ── Shared fixtures for the handler-level tests below ────────────────

    /// Pro posture with an explicit capability allowlist, auth OFF (scope checks
    /// bypassed) so a test can isolate the entitlement gate from the auth gate.
    fn st_pro(services: &[&str]) -> AppState {
        let mut state = super::super::tests::test_app_state(16);
        state.operating_mode = crate::product::OperatingMode::ProHybrid;
        state.enabled_pro_services = services.iter().map(|service| (*service).to_string()).collect();
        state
    }

    /// Pro posture with `DevScopes` auth, so 401 (no credential) and 403 (wrong
    /// scope) can be told apart.
    fn st_pro_dev(services: &[&str]) -> AppState {
        let mut state = super::super::tests::test_app_state_with_auth(16, crate::auth::AuthMode::DevScopes);
        state.operating_mode = crate::product::OperatingMode::ProHybrid;
        state.enabled_pro_services = services.iter().map(|service| (*service).to_string()).collect();
        state
    }

    fn scoped(scopes: &str) -> HeaderMap {
        super::super::tests::dev_scope_headers(scopes)
    }

    async fn body_of(resp: axum::response::Response) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    fn tenant_query(tenant_id: &str) -> Query<TenantWorkbenchQuery> {
        Query(TenantWorkbenchQuery {
            tenant_id: tenant_id.to_string(),
            project_id: None,
            limit: None,
        })
    }

    fn seed_private(store: &mut FactStore, entity: &str, key: &str, value: &str, private: bool) {
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private,
            horizon_class: None,
            actor: None,
        });
    }

    fn route_hit(method: &str, path: &str, handler_file: Option<&str>) -> crate::workspace_scan::RouteHit {
        crate::workspace_scan::RouteHit {
            method: method.to_string(),
            path: path.to_string(),
            handler_fn: format!("handler_for_{}", path.replace(['/', '{', '}', '-'], "_")),
            framework: None,
            handler_file: handler_file.map(str::to_string),
            handler_line: handler_file.map(|_| 42),
            source_file: "crates/corecruxd/src/http/mod.rs".to_string(),
            source_line: 7,
        }
    }

    fn scan_with_routes(routes: Vec<crate::workspace_scan::RouteHit>) -> crate::workspace_scan::WorkspaceScan {
        let mut scan = crate::workspace_scan::WorkspaceScan {
            scan_id: "scan-1".to_string(),
            root_path: "/repo".to_string(),
            ..Default::default()
        };
        scan.stats.route_count = routes.len();
        scan.routes = routes;
        scan
    }

    async fn store_scan(state: &AppState, scan: &crate::workspace_scan::WorkspaceScan) {
        let mut store = state.fact_store.write().await;
        seed_private(
            &mut store,
            crate::workspace_scan::LATEST_SCAN_ENTITY,
            crate::workspace_scan::SCAN_KEY,
            &serde_json::to_string(scan).unwrap(),
            false,
        );
    }

    // ── Pure helpers ─────────────────────────────────────────────────────

    #[test]
    fn route_matches_accepts_method_path_pair_and_bare_path() {
        assert!(route_matches("GET /v1/facts", "GET", "/v1/facts"));
        assert!(route_matches("  /v1/facts  ", "GET", "/v1/facts"));
        assert!(!route_matches("POST /v1/facts", "GET", "/v1/facts"));
        assert!(!route_matches("/v1/other", "GET", "/v1/facts"));
    }

    #[test]
    fn route_key_is_stable_and_tolerates_missing_fields() {
        assert_eq!(route_key(&json!({ "method": "GET", "path": "/a" })), "GET /a");
        // A malformed row degrades to a blank key rather than panicking.
        assert_eq!(route_key(&json!({})), " ");
    }

    #[test]
    fn scope_hints_cover_surface_read_write_and_fallbacks() {
        // A known workbench surface contributes its capability plus the
        // read/write admin scope for the method.
        let read = scope_hints_for_route("GET", "/v1/workbench/audit-triage");
        assert!(read.contains(&"audit:triage") && read.contains(&"admin:read"));
        let write = scope_hints_for_route("POST", "/v1/workbench/context-pack");
        assert!(write.contains(&"context_pack:budgeted") && write.contains(&"admin:write"));

        // Non-surface paths fall through to the heuristic table.
        assert_eq!(scope_hints_for_route("POST", "/v1/sessions"), vec!["sessions:write"]);
        assert_eq!(scope_hints_for_route("GET", "/v1/receipts/abc"), vec!["receipts:read"]);
        assert!(scope_hints_for_route("GET", "/v1/admin/status").contains(&"admin:read"));
        // Nothing matched → the least-privilege default, never an empty list
        // (an empty hint list would read as "no scope needed").
        assert_eq!(scope_hints_for_route("GET", "/healthz"), vec!["query:read"]);
    }

    #[test]
    fn surface_for_path_resolves_known_paths_only() {
        assert_eq!(
            surface_for_path("/v1/workbench/handoff-v2"),
            Some(WorkbenchSurface::HandoffV2)
        );
        assert_eq!(surface_for_path("/v1/workbench/nope"), None);
    }

    #[test]
    fn normalize_path_collapses_every_param_segment() {
        assert_eq!(normalize_path("/v1/a/{id}/b/{sub}"), "/v1/a/{}/b/{}");
        assert_eq!(normalize_path("/v1/plain"), "/v1/plain");
        // An unterminated brace swallows the rest rather than panicking.
        assert_eq!(normalize_path("/v1/a/{id"), "/v1/a/{}");
    }

    #[test]
    fn route_exists_matches_through_param_normalisation() {
        let scan = scan_with_routes(vec![route_hit("GET", "/v1/work/{id}", Some("http/work.rs"))]);
        assert!(route_exists(&scan, "GET", "/v1/work/{work_id}"));
        assert!(route_exists(&scan, "GET/POST", "/v1/work/{id}"), "method list matches");
        assert!(!route_exists(&scan, "GET", "/v1/work"));
    }

    #[test]
    fn terms_drops_short_tokens_and_dedups() {
        assert_eq!(terms("Deploy to Prod, deploy AT db"), vec!["deploy", "prod"]);
        assert!(terms("a b c").is_empty());
        assert_eq!(terms("snake_case_word"), vec!["snake_case_word"]);
    }

    #[test]
    fn match_constraints_ranks_by_overlap_and_defaults_severity_to_medium() {
        let constraints = vec![
            json!({ "constraint_id": "c1", "assertion": "never delete production data", "severity": "critical" }),
            json!({ "fact_id": "f2", "value_preview": "prefer smaller commits" }),
            json!({ "assertion": "" }),
        ];
        let matches = match_constraints("delete production data now", &constraints);
        assert_eq!(matches.len(), 1, "only the overlapping constraint matches");
        assert_eq!(matches[0]["constraint_id"], "c1");
        assert_eq!(matches[0]["severity"], "critical");

        // A constraint with no explicit severity is reported as `medium`, not
        // silently dropped.
        let matches = match_constraints("prefer smaller commits", &constraints);
        assert_eq!(matches[0]["constraint_id"], "f2");
        assert_eq!(matches[0]["severity"], "medium");
    }

    #[test]
    fn replay_failure_severity_escalates_on_missing_evidence() {
        assert_eq!(replay_failure_severity(&[]), "ok");
        assert_eq!(
            replay_failure_severity(&[json!({ "categories": ["fact_changed"] })]),
            "medium"
        );
        assert_eq!(
            replay_failure_severity(&[json!({ "categories": ["fact_changed", "fact_missing"] })]),
            "high"
        );
        assert_eq!(
            replay_failure_severity(&[json!({ "categories": ["projection_module_unavailable"] })]),
            "high"
        );
        // A row without a categories array must not be read as "high".
        assert_eq!(replay_failure_severity(&[json!({})]), "medium");
    }

    #[test]
    fn living_status_drift_category_names_only_the_drifted_states() {
        use corecrux_projections::LivingStatusV1 as S;
        assert_eq!(living_status_drift_category(S::Stale), Some("living_state_stale"));
        assert_eq!(
            living_status_drift_category(S::Contested),
            Some("living_state_contested")
        );
        assert_eq!(
            living_status_drift_category(S::Superseded),
            Some("living_state_superseded")
        );
        assert_eq!(
            living_status_drift_category(S::Deprecated),
            Some("living_state_deprecated")
        );
        assert_eq!(living_status_drift_category(S::Active), None);
        assert_eq!(living_status_drift_category(S::Dormant), None);
    }

    #[test]
    fn truncate_counts_characters_not_bytes() {
        // Multi-byte input must not be cut mid-character (a byte slice here
        // would panic).
        let out = truncate(&"é".repeat(300), 240);
        assert_eq!(out.chars().count(), 243, "240 chars + the three-dot marker");
    }

    #[test]
    fn normalize_handoff_agent_trims_lowercases_and_drops_blank() {
        assert_eq!(
            normalize_handoff_agent(Some("  Claude-Code ")),
            Some("claude-code".into())
        );
        assert_eq!(normalize_handoff_agent(Some("   ")), None);
        assert_eq!(normalize_handoff_agent(None), None);
    }

    #[test]
    fn handoff_agent_lookup_key_folds_vendor_aliases() {
        for alias in ["claude", "claude-code", "anthropic"] {
            assert_eq!(handoff_agent_lookup_key(alias), "anthropic");
        }
        for alias in ["codex", "codex-cli", "openai"] {
            assert_eq!(handoff_agent_lookup_key(alias), "openai");
        }
        assert_eq!(handoff_agent_lookup_key("mistral"), "mistral");
    }

    #[test]
    fn api_drift_report_without_scan_asks_for_a_scan() {
        let report = api_drift_report(None);
        assert_eq!(report["status"], "no_workspace_scan");
        assert_eq!(report["route_count"], 0);
        assert_eq!(report["queues"][0]["category"], "workspace_scan_missing");
    }

    #[test]
    fn api_drift_report_flags_workbench_routes_absent_from_the_scan() {
        // A scan that knows about exactly one workbench route must still report
        // the other nine as contract drift.
        let scan = scan_with_routes(vec![route_hit(
            "GET",
            "/v1/workbench/api-drift",
            Some("http/workbench.rs"),
        )]);
        let report = api_drift_report(Some(&scan));
        assert_eq!(report["status"], "drift_detected");
        let missing = &report["queues"][1];
        assert_eq!(missing["category"], "workbench_contract_missing_from_scan");
        assert_eq!(missing["count"], WorkbenchSurface::all().len() - 1);
    }

    #[test]
    fn impacted_routes_matches_by_request_changed_path_and_dedups() {
        let scan = scan_with_routes(vec![
            route_hit("GET", "/v1/alpha", Some("crates/corecruxd/src/http/alpha.rs")),
            route_hit("POST", "/v1/beta", None),
        ]);
        // Requested explicitly AND touched by a changed path → one row, not two.
        let routes = impacted_routes(
            &scan,
            &["http/alpha.rs".to_string()],
            &["GET /v1/alpha".to_string()],
            false,
        );
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0]["path"], "/v1/alpha");
        assert!(routes[0]["storyline"].is_null(), "storyline is opt-in");

        // A route whose handler never resolved is still reachable via the
        // declaration file.
        let routes = impacted_routes(&scan, &["http/mod.rs".to_string()], &[], false);
        assert_eq!(routes.len(), 2);

        assert!(impacted_routes(&scan, &[], &[], false).is_empty());
    }

    #[tokio::test]
    async fn recent_receipt_refs_orders_newest_first_and_truncates() {
        let st = st_free();
        {
            let mut store = st.fact_store.write().await;
            for n in 0..4 {
                seed_private(&mut store, &format!("__gpu1_receipt__::t1::{n}"), "r", "{}", false);
            }
        }
        let store = st.fact_store.read().await;
        let refs = recent_receipt_refs(&store, "t1", 2);
        assert_eq!(refs.len(), 2, "limit is honoured across all three prefixes");
        let first = refs[0]["stored_at"].as_str().unwrap_or_default();
        let second = refs[1]["stored_at"].as_str().unwrap_or_default();
        assert!(first >= second, "newest first");
    }

    #[test]
    fn workbench_posture_lists_every_surface_with_a_status() {
        let st = st_free();
        let posture = workbench_posture(&st);
        assert_eq!(posture["schema"], WORKBENCH_CONTRACT_SCHEMA);
        let surfaces = posture["surfaces"].as_array().unwrap();
        assert_eq!(surfaces.len(), WorkbenchSurface::all().len());
        assert!(
            surfaces.iter().all(|s| s["status"] == "pro_required"),
            "free posture gates every surface"
        );
    }

    // ── Auth and entitlement gates ───────────────────────────────────────

    /// 401 (no credential) and 403 (credential without the scope) are different
    /// bugs; a regression that collapsed them into one status would be invisible
    /// to a status-code-only assertion.
    #[tokio::test]
    async fn contract_distinguishes_missing_credential_from_missing_scope() {
        let st = super::super::tests::test_app_state_with_auth(16, crate::auth::AuthMode::DevScopes);
        assert_eq!(
            get_workbench_contract(State(st.clone()), HeaderMap::new())
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get_workbench_contract(State(st.clone()), scoped("facts:write"))
                .await
                .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            get_workbench_contract(State(st), scoped("query:read")).await.status(),
            StatusCode::OK
        );
    }

    /// The entitlement gate must run for an authenticated caller too: a valid
    /// admin scope does not buy a Pro capability.
    #[tokio::test]
    async fn admin_scope_does_not_bypass_the_pro_entitlement_gate() {
        let st = super::super::tests::test_app_state_with_auth(16, crate::auth::AuthMode::DevScopes);
        let resp = get_agent_brief(State(st), scoped("admin:read"), tenant_query("t1")).await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn pro_gate_402_body_names_the_capability_and_path() {
        let st = st_free();
        let resp = post_context_pack(
            State(st),
            HeaderMap::new(),
            Json(ContextPackBody {
                tenant_id: "t1".to_string(),
                query: "anything".to_string(),
                token_budget: 4000,
                include_private: false,
                source_labels: Vec::new(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let body = body_of(resp).await;
        assert_eq!(body["status"], "pro_service_not_enabled");
        assert_eq!(body["capability"], "context_pack:budgeted");
        assert_eq!(body["path"], "/v1/workbench/context-pack");
        assert_eq!(body["fallback"]["reason_code"], "pro_service_not_enabled");
    }

    #[tokio::test]
    async fn route_probe_requires_a_credential_before_the_entitlement_gate() {
        let st = st_pro_dev(&["route_probe:lab"]);
        let resp = post_route_probe(
            State(st),
            HeaderMap::new(),
            Json(RouteProbeBody {
                route: "GET /v1/alpha".to_string(),
                include_storyline: false,
                include_tests: false,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn every_tenant_scoped_surface_rejects_a_blank_tenant_id() {
        let st = st_pro(&[
            "context_pack:budgeted",
            "impact:preflight",
            "ledger:history",
            "audit:triage",
            "reasoning:timeline",
            "handoff:v2",
            "api_drift:check",
            "policy:simulate",
        ]);
        let blank = "   ";
        assert_eq!(
            get_command_ledger(State(st.clone()), HeaderMap::new(), tenant_query(blank))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            get_audit_triage(State(st.clone()), HeaderMap::new(), tenant_query(blank))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            get_reasoning_timeline(State(st.clone()), HeaderMap::new(), tenant_query(blank))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            get_api_drift(State(st.clone()), HeaderMap::new(), tenant_query(blank))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            post_impact_preflight(
                State(st.clone()),
                HeaderMap::new(),
                Json(ImpactPreflightBody {
                    tenant_id: blank.to_string(),
                    changed_paths: Vec::new(),
                    routes: Vec::new(),
                    selected_tests: Vec::new(),
                    include_storyline: false,
                }),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
        // A policy simulation with NO tenant_id at all must fail the same way an
        // empty one does — an absent tenant is not a pass.
        assert_eq!(
            post_policy_simulation(
                State(st),
                HeaderMap::new(),
                Json(PolicySimulationBody {
                    action: ActionEnrichmentInput {
                        tenant_id: None,
                        tool_name: "bash".to_string(),
                        tool_parameters: json!({}),
                        action_description: None,
                        include_first_party_enrichers: false,
                    },
                }),
            )
            .await
            .status(),
            StatusCode::BAD_REQUEST
        );
    }

    // ── Context pack ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn context_pack_rejects_empty_query_and_clamps_the_budget() {
        let st = st_pro(&["context_pack:budgeted"]);
        let resp = post_context_pack(
            State(st.clone()),
            HeaderMap::new(),
            Json(ContextPackBody {
                tenant_id: "tnA".to_string(),
                query: "   ".to_string(),
                token_budget: 4000,
                include_private: false,
                source_labels: Vec::new(),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = post_context_pack(
            State(st),
            HeaderMap::new(),
            Json(ContextPackBody {
                tenant_id: "tnA".to_string(),
                query: "deployment".to_string(),
                token_budget: 1,
                include_private: false,
                source_labels: vec!["fact_store".to_string()],
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_of(resp).await;
        assert_eq!(body["pack"]["token_budget"], 128, "budget clamps up to the floor");
        assert_eq!(body["pack"]["source_labels"][0], "fact_store");
        assert!(body["receipt"]["receipt_id"]
            .as_str()
            .unwrap()
            .starts_with("workbench:context_pack:"));
    }

    /// Redaction invariant: a private fact must not ride out in a context pack
    /// unless the caller explicitly asked for private material.
    #[tokio::test]
    async fn context_pack_hides_private_facts_unless_explicitly_requested() {
        let st = st_pro(&["context_pack:budgeted"]);
        {
            let mut store = st.fact_store.write().await;
            seed_private(&mut store, "tnA::open", "note", "deployment runbook for tnA", false);
            seed_private(&mut store, "tnA::closed", "note", "deployment secret for tnA", true);
        }
        let pack = |include_private: bool| {
            let st = st.clone();
            async move {
                let resp = post_context_pack(
                    State(st),
                    HeaderMap::new(),
                    Json(ContextPackBody {
                        tenant_id: "tnA".to_string(),
                        query: "deployment".to_string(),
                        token_budget: 4000,
                        include_private,
                        source_labels: Vec::new(),
                    }),
                )
                .await;
                assert_eq!(resp.status(), StatusCode::OK);
                body_of(resp).await
            }
        };

        // Opt-in first: at this point exactly the two seeded facts exist. (Each
        // call persists its own pack as a PRIVATE `__workbench__::` fact, so a
        // later include_private run would also see the earlier pack.)
        let with_private = pack(true).await;
        assert_eq!(with_private["pack"]["items"].as_array().unwrap().len(), 2);

        let public_only = pack(false).await;
        let items = public_only["pack"]["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert!(
            !serde_json::to_string(items).unwrap().contains("secret"),
            "private fact text must not transit the pack"
        );
    }

    /// Pins CURRENT behaviour: tenant scoping in the context pack is a SUBSTRING
    /// test over entity/value/key, so a fact belonging to `tnA10` is served to a
    /// caller asking for `tnA1`. Reported, not fixed.
    #[tokio::test]
    async fn context_pack_tenant_scoping_is_substring_not_exact() {
        let st = st_pro(&["context_pack:budgeted"]);
        {
            let mut store = st.fact_store.write().await;
            seed_private(&mut store, "tnA10::note", "note", "deployment plan for tnA10", false);
        }
        let resp = post_context_pack(
            State(st),
            HeaderMap::new(),
            Json(ContextPackBody {
                tenant_id: "tnA1".to_string(),
                query: "deployment".to_string(),
                token_budget: 4000,
                include_private: false,
                source_labels: Vec::new(),
            }),
        )
        .await;
        let body = body_of(resp).await;
        assert_eq!(
            body["pack"]["items"].as_array().unwrap().len(),
            1,
            "current behaviour: the tnA10 fact leaks into the tnA1 pack"
        );
    }

    // ── Command ledger ───────────────────────────────────────────────────

    fn ledger_body(tenant_id: &str, command: &str) -> CommandLedgerBody {
        CommandLedgerBody {
            tenant_id: tenant_id.to_string(),
            command: command.to_string(),
            args: vec!["--release".to_string()],
            cwd: Some("/repo".to_string()),
            exit_status: Some(0),
            duration_ms: Some(12),
            started_at_unix_ms: None,
            completed_at_unix_ms: None,
            stdout_hash: None,
            stderr_hash: None,
            linked_receipts: Vec::new(),
            project_id: Some("p1".to_string()),
            work_id: None,
        }
    }

    /// Both command-ledger routes are unreachable by design, in both
    /// directions, even when a caller explicitly asks for `ledger:history`.
    ///
    /// `5e6543a` (ExecPlan `crux-command-ledger-claim-truth-2026-07-30`) dropped
    /// `ledger:history` from `PRO_CAPABILITY_CLAIMS` because nothing has ever
    /// written a record, so the surface could only render an empty page.
    /// `ProductPosture::new` filters `enabled_pro_services` through that list,
    /// so the capability cannot be switched back on from config alone.
    ///
    /// `product.rs`'s `workbench_command_ledger_is_not_a_sold_claim_without_a_producer`
    /// pins this at the posture layer; this pins it at the route layer, so a
    /// future producer landing must consciously flip both. Until then the
    /// entitlement gate runs *before* body validation — a blank command still
    /// yields 402, not 400.
    #[tokio::test]
    async fn command_ledger_routes_are_not_sellable_without_a_producer() {
        let st = st_pro(&["ledger:history"]);

        let resp = post_command_ledger(
            State(st.clone()),
            HeaderMap::new(),
            Json(ledger_body("tnL", "cargo build")),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);

        let resp = get_command_ledger(State(st.clone()), HeaderMap::new(), tenant_query("tnL")).await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);

        // The entitlement gate precedes body validation: an invalid body is
        // still 402, never 400, so the refusal cannot be probed for validity.
        let resp = post_command_ledger(State(st), HeaderMap::new(), Json(ledger_body("tnL", "   "))).await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    }

    // ── Impact preflight / audit triage / timeline ────────────────────────

    #[tokio::test]
    async fn impact_preflight_without_a_scan_is_honestly_empty() {
        let st = st_pro(&["impact:preflight"]);
        let resp = post_impact_preflight(
            State(st),
            HeaderMap::new(),
            Json(ImpactPreflightBody {
                tenant_id: "tnP".to_string(),
                changed_paths: vec!["src/lib.rs".to_string()],
                routes: vec!["GET /v1/facts".to_string()],
                selected_tests: vec!["t1".to_string()],
                include_storyline: true,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let pre = body_of(resp).await;
        let pf = &pre["preflight"];
        assert_eq!(pf["impacted_routes"].as_array().unwrap().len(), 0);
        assert_eq!(pf["requested_routes"][0], "GET /v1/facts");
        // No living-object rows tracked → "not_recorded", NOT "current": an
        // absent signal must not read as a clean bill of health.
        assert_eq!(pf["living_objects"]["status"], "not_recorded");
        assert_eq!(pf["living_objects"]["tracked_artifact_count"], 0);
        assert_eq!(pf["living_objects"]["changed_path_count"], 1);
    }

    #[tokio::test]
    async fn impact_preflight_reports_route_impact_from_a_stored_scan() {
        let st = st_pro(&["impact:preflight"]);
        store_scan(
            &st,
            &scan_with_routes(vec![route_hit(
                "GET",
                "/v1/alpha",
                Some("crates/corecruxd/src/http/alpha.rs"),
            )]),
        )
        .await;
        let resp = post_impact_preflight(
            State(st),
            HeaderMap::new(),
            Json(ImpactPreflightBody {
                tenant_id: "tnP".to_string(),
                changed_paths: vec!["http/alpha.rs".to_string()],
                routes: Vec::new(),
                selected_tests: Vec::new(),
                include_storyline: false,
            }),
        )
        .await;
        let pf = body_of(resp).await;
        let routes = pf["preflight"]["impacted_routes"].as_array().unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0]["path"], "/v1/alpha");
        assert!(routes[0]["scope_hints"]
            .as_array()
            .unwrap()
            .contains(&json!("query:read")));
    }

    #[tokio::test]
    async fn audit_triage_reports_all_four_queues_clean_on_an_empty_store() {
        let st = st_pro(&["audit:triage"]);
        let resp = get_audit_triage(State(st), HeaderMap::new(), tenant_query("tnT")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_of(resp).await;
        let queues = body["queues"].as_array().unwrap();
        let categories: Vec<&str> = queues.iter().filter_map(|q| q["category"].as_str()).collect();
        assert_eq!(
            categories,
            vec![
                "receipt_anomalies",
                "sync_conflicts",
                "route_resolution_drift",
                "replay_failures"
            ]
        );
        assert_eq!(queues[0]["severity"], "ok");
        assert_eq!(queues[3]["severity"], "ok");
    }

    #[tokio::test]
    async fn reasoning_timeline_labels_events_by_source_prefix() {
        let st = st_pro(&["reasoning:timeline"]);
        {
            let mut store = st.fact_store.write().await;
            seed_private(&mut store, "__work__::tnR::w1", "record", "{}", false);
            seed_private(&mut store, "__gpu1_receipt__::tnR::r1", "record", "{}", false);
            seed_private(&mut store, "person:alice", "city", "NYC", false);
        }
        let resp = get_reasoning_timeline(State(st), HeaderMap::new(), tenant_query("tnR")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_of(resp).await;
        assert_eq!(body["count"], 2, "unrelated facts are not timeline events");
        let kinds: BTreeSet<&str> = body["events"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["kind"].as_str())
            .collect();
        assert!(kinds.contains("work") && kinds.contains("gpu1_compute"));
    }

    // ── Handoff v2 ───────────────────────────────────────────────────────

    fn handoff_body(tenant_id: &str, goal: &str, session_id: Option<&str>) -> HandoffV2Body {
        HandoffV2Body {
            tenant_id: tenant_id.to_string(),
            goal: goal.to_string(),
            session_id: session_id.map(str::to_string),
            project_id: Some("p1".to_string()),
            source_agent: Some("claude".to_string()),
            target_agent: Some("codex".to_string()),
            evidence_refs: vec!["ad_r1".to_string()],
            next_actions: vec!["run the gate".to_string()],
        }
    }

    #[tokio::test]
    async fn handoff_v2_rejects_a_blank_goal() {
        let st = st_pro(&["handoff:v2"]);
        let resp = post_handoff_v2(State(st), HeaderMap::new(), Json(handoff_body("tnH", "  ", None))).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn handoff_v2_packages_session_state_constraints_and_ledger() {
        let st = st_pro(&["handoff:v2", "ledger:history"]);
        {
            let mut sessions = st.session_store.write().await;
            sessions.put("s-tnH", json!({ "note": "resume here" }), None);
        }
        {
            let mut store = st.fact_store.write().await;
            seed_private(
                &mut store,
                "__constraints__::tnH::c1",
                "record",
                r#"{"assertion":"no prod writes","severity":"high"}"#,
                false,
            );
            seed_private(
                &mut store,
                "__decisions__::tnH::d1",
                "record",
                r#"{"decision":"ship it"}"#,
                false,
            );
        }
        let resp = post_handoff_v2(
            State(st),
            HeaderMap::new(),
            Json(handoff_body("tnH", "finish M4", Some("s-tnH"))),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_of(resp).await;
        let package = &body["package"];
        assert_eq!(package["goal"], "finish M4");
        assert_eq!(package["session_state"]["state"]["note"], "resume here");
        assert_eq!(package["constraints"].as_array().unwrap().len(), 1);
        assert_eq!(package["open_decisions"].as_array().unwrap().len(), 1);
        assert_eq!(package["evidence_refs"][0], "ad_r1");
        // Observation emission is opt-in; the default posture adds no id.
        assert!(body.get("handoff_observation_id").is_none());
    }

    #[tokio::test]
    async fn handoff_v2_with_an_unknown_session_id_is_null_not_an_error() {
        let st = st_pro(&["handoff:v2"]);
        let resp = post_handoff_v2(
            State(st),
            HeaderMap::new(),
            Json(handoff_body("tnH", "finish M4", Some("nope"))),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_of(resp).await["package"]["session_state"].is_null());
    }

    // ── Route probe / api drift ──────────────────────────────────────────

    #[tokio::test]
    async fn route_probe_404s_without_a_scan_and_for_an_unknown_route() {
        let st = st_pro(&["route_probe:lab"]);
        let probe = |state: AppState, route: &str| {
            let route = route.to_string();
            async move {
                post_route_probe(
                    State(state),
                    HeaderMap::new(),
                    Json(RouteProbeBody {
                        route,
                        include_storyline: false,
                        include_tests: false,
                    }),
                )
                .await
            }
        };
        let resp = probe(st.clone(), "GET /v1/alpha").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(body_of(resp)
            .await
            .to_string()
            .contains("POST /v1/workspace/scan to run one"));

        store_scan(&st, &scan_with_routes(vec![route_hit("GET", "/v1/alpha", None)])).await;
        let resp = probe(st.clone(), "GET /v1/missing").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        // A route string with no method at all also 404s rather than panicking.
        let resp = probe(st.clone(), "/v1/alpha").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let resp = probe(st, "get /v1/alpha").await;
        assert_eq!(resp.status(), StatusCode::OK, "method matching is case-insensitive");
        let body = body_of(resp).await;
        assert_eq!(body["route"]["path"], "/v1/alpha");
        assert_eq!(
            body["warnings"][0], "handler_file_unresolved",
            "an unresolved handler is surfaced, not silently omitted"
        );
    }

    #[tokio::test]
    async fn api_drift_handler_reports_the_missing_scan() {
        let st = st_pro(&["api_drift:check"]);
        let resp = get_api_drift(State(st), HeaderMap::new(), tenant_query("tnD")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_of(resp).await["status"], "no_workspace_scan");
    }

    // ── Policy simulation ────────────────────────────────────────────────

    #[tokio::test]
    async fn policy_simulation_blocks_on_a_matching_critical_constraint() {
        let st = st_pro(&["policy:simulate"]);
        {
            let mut store = st.fact_store.write().await;
            seed_private(
                &mut store,
                "__constraints__::tnS::c1",
                "record",
                r#"{"constraint_id":"c1","assertion":"never delete the production database","severity":"critical","tenant_id":"tnS"}"#,
                false,
            );
        }
        let resp = post_policy_simulation(
            State(st),
            HeaderMap::new(),
            Json(PolicySimulationBody {
                action: ActionEnrichmentInput {
                    tenant_id: Some("tnS".to_string()),
                    tool_name: "bash".to_string(),
                    tool_parameters: json!({ "command": "dropdb" }),
                    action_description: Some("delete the production database".to_string()),
                    include_first_party_enrichers: false,
                },
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_of(resp).await;
        assert_eq!(body["simulation"]["verdict"], "block");
        assert_eq!(body["simulation"]["matched_constraints"][0]["constraint_id"], "c1");
        assert_eq!(body["simulation"]["tenant_id"], "tnS");
    }

    #[tokio::test]
    async fn policy_simulation_with_no_constraints_matches_nothing() {
        let st = st_pro(&["policy:simulate"]);
        let resp = post_policy_simulation(
            State(st),
            HeaderMap::new(),
            Json(PolicySimulationBody {
                action: ActionEnrichmentInput {
                    tenant_id: Some("tnS".to_string()),
                    tool_name: "read_file".to_string(),
                    tool_parameters: json!({}),
                    action_description: None,
                    include_first_party_enrichers: false,
                },
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_of(resp).await;
        assert!(body["simulation"]["matched_constraints"].as_array().unwrap().is_empty());
        assert!(["pass", "warn", "block"].contains(&body["simulation"]["verdict"].as_str().unwrap()));
    }

    // ── Agent brief ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn agent_brief_reports_memory_sessions_and_ranked_work() {
        let st = st_pro(&["agent_brief:pro"]);
        {
            let mut sessions = st.session_store.write().await;
            sessions.put("s1", json!({ "note": "hi" }), None);
        }
        {
            let mut store = st.fact_store.write().await;
            seed_private(
                &mut store,
                "__constraints__::tnB::c1",
                "record",
                r#"{"assertion":"tnB stays local"}"#,
                false,
            );
        }
        let resp = get_agent_brief(State(st), HeaderMap::new(), tenant_query("tnB")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_of(resp).await;
        assert_eq!(body["schema"], "crux.agent_workbench.brief.v1");
        assert_eq!(body["tenant_id"], "tnB");
        assert_eq!(body["sessions"]["count"], 1);
        assert_eq!(body["active_constraints"].as_array().unwrap().len(), 1);
        assert_eq!(body["open_work_order"], "ranked");
        assert!(body["workspace"].is_null(), "no scan → honest null, not a stub");
    }
}
