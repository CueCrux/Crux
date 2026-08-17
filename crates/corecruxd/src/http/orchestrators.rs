// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `/v1/orchestrators/*` — multi-agent orchestrator surface (orchestrators
//! plan).
//!
//! Mounted via `Router::merge` so the orchestrators plan owns the handler
//! bodies without touching `http/mod.rs`. Gated by `CORECRUXD_ORCHESTRATORS`
//! (default OFF): when off, every route returns a `501` problem.
//!
//! An *orchestrator* is a coordinator record that groups work items,
//! ExecPlans, and handoffs (its *members*) under a single passport-attributed
//! owner. Members are held *by reference* — the orchestrator never copies the
//! member payload, it only stores `{type, ref}` tuples. `GET …/{id}/work`
//! resolves those references to live [`WorkItem`](crate::work::WorkItem)s at read time so a dangling
//! reference surfaces as `missing: true` rather than failing the whole call.
//!
//! Storage: orchestrators persist as `orchestrator`-kind entities in the
//! substrate entity store, so they inherit the journal + restart-survival that
//! Package S wired. Generic HTTP/MCP entity CRUD reserves this governed kind;
//! callers must use this typed surface so tenant and actor checks cannot be
//! bypassed. Each mutation emits a `CruxEvent::OrchestratorChanged` and writes
//! a receipt fact.

use axum::routing::{delete, get, post};
use axum::Router;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{problem_response, AppState, HeaderMap, IntoResponse, Json, Path, Query, Response, State, StatusCode};
use crate::agentgraph_kinds::{orchestrators_enabled, ORCHESTRATOR_KIND};

/// Member reference types accepted by `POST …/{id}/members`.
const MEMBER_TYPE_EXECPLAN: &str = "execplan";
const MEMBER_TYPE_WORK: &str = "work";
const MEMBER_TYPE_HANDOFF: &str = "handoff";
/// A member that is an agent/human principal. The orchestrator concept groups
/// work items AND member passports; this is the latter. Validated against the
/// passport store by id or principal_id.
const MEMBER_TYPE_PASSPORT: &str = "passport";

/// `true` when `member_ref` names a registered passport (by its `id` such as
/// `claude-work`, or by its `principal_id` such as `ce:4e6c4e2a:local`).
fn passport_ref_exists(store: &corecrux_memory::FactStore, member_ref: &str) -> bool {
    crate::passports::list_passports(store, None)
        .iter()
        .any(|p| p.id == member_ref || p.principal_id == member_ref)
}

/// Default state for a freshly minted orchestrator. The substrate kind schema
/// constrains state to `planned | active | done | archived`.
const DEFAULT_STATE: &str = "planned";
const ORCHESTRATOR_STATES: &[&str] = &["planned", "active", "done", "archived"];

/// Routes for the orchestrator surface. Merged into the main router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/orchestrators", post(create_orchestrator).get(list_orchestrators))
        .route(
            "/v1/orchestrators/{id}",
            get(get_orchestrator).patch(patch_orchestrator),
        )
        .route("/v1/orchestrators/{id}/members", post(add_member))
        .route("/v1/orchestrators/{id}/members/{ref}", delete(remove_member))
        .route("/v1/orchestrators/{id}/work", get(list_orchestrator_work))
}

// ── gate + helpers ───────────────────────────────────────────────────

/// Gate-aware 501 for when the surface is disabled. Returns `Some(resp)` when
/// the feature is OFF — callers should early-return it.
fn gate_check() -> Option<axum::response::Response> {
    if orchestrators_enabled() {
        None
    } else {
        Some(problem_response(
            StatusCode::NOT_IMPLEMENTED,
            "orchestrators surface disabled (set CORECRUXD_ORCHESTRATORS=1)",
        ))
    }
}

#[allow(clippy::result_large_err)]
fn scoped_context(
    state: &AppState,
    headers: &HeaderMap,
    accepted_scopes: &[&str],
) -> Result<crate::auth::HttpScopeContext, Response> {
    let context = crate::auth::passport_bound_context(&state.auth, headers)
        .map_err(axum::response::IntoResponse::into_response)?;
    if !accepted_scopes.iter().any(|scope| context.has_scope(scope)) {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            format!("one of {} is required", accepted_scopes.join(", ")),
        ));
    }
    Ok(context)
}

struct MutationAuthority {
    context: crate::auth::HttpScopeContext,
    actor: String,
}

#[allow(clippy::result_large_err)]
fn mutation_authority(
    state: &AppState,
    headers: &HeaderMap,
    identity_hint: Option<&str>,
) -> Result<MutationAuthority, Response> {
    let context = scoped_context(state, headers, &["facts:write", "admin:write"])?;
    let body_hint = identity_hint.map(str::trim).filter(|value| !value.is_empty());
    if !context.local_unverified_identity() {
        if context.passport_override_used() {
            return Err(problem_response(
                StatusCode::FORBIDDEN,
                "passport impersonation is not permitted for orchestrator mutations",
            ));
        }
        let Some(passport_id) = context.passport_id.as_deref() else {
            return Err(problem_response(
                StatusCode::FORBIDDEN,
                "an authenticated passport is required for orchestrator mutations",
            ));
        };
        if body_hint.is_some_and(|hint| hint != passport_id) {
            return Err(problem_response(
                StatusCode::FORBIDDEN,
                "body passport does not match the authenticated passport",
            ));
        }
        Ok(MutationAuthority {
            actor: passport_id.to_string(),
            context,
        })
    } else {
        let header_hint = context.passport_id.as_deref();
        if let (Some(body_hint), Some(header_hint)) = (body_hint, header_hint) {
            if body_hint != header_hint {
                return Err(problem_response(
                    StatusCode::FORBIDDEN,
                    "body passport does not match the local identity assertion header",
                ));
            }
        }
        let Some(asserted) = body_hint.or(header_hint) else {
            return Err(problem_response(
                StatusCode::BAD_REQUEST,
                "an explicit passport identity assertion is required in local unverified mode",
            ));
        };
        Ok(MutationAuthority {
            actor: format!("{}{asserted}", super::approval_receipts::UNVERIFIED_APPROVER_PREFIX),
            context,
        })
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// A member reference held by an orchestrator. `type` is one of
/// `execplan | work | handoff`; `ref` is the member's id in its own surface.
#[derive(Debug, Clone, serde::Serialize, Deserialize, PartialEq, Eq)]
struct MemberRef {
    #[serde(rename = "type")]
    member_type: String,
    #[serde(rename = "ref")]
    member_ref: String,
}

/// Build the orchestrator entity payload. Mirrors the `orchestrator`-kind JSON
/// schema in `agentgraph_kinds.rs` (all required fields present; `members` is
/// an array of `{type, ref}`).
#[allow(clippy::too_many_arguments)]
fn orchestrator_payload(
    id: &str,
    name: &str,
    assignee_passport: &str,
    created_by_passport: &str,
    tenant_id: &str,
    state: &str,
    members: &[MemberRef],
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
) -> Value {
    json!({
        "id": id,
        "name": name,
        "assignee_passport": assignee_passport,
        "created_by_passport": created_by_passport,
        "tenant_id": tenant_id,
        "state": state,
        "members": members,
        "created_at_unix_ms": created_at_unix_ms,
        "updated_at_unix_ms": updated_at_unix_ms,
    })
}

/// Pull the `members` array out of a stored orchestrator payload, tolerating a
/// missing/malformed field (treated as empty).
fn members_of(payload: &Value) -> Vec<MemberRef> {
    payload
        .get("members")
        .and_then(|v| serde_json::from_value::<Vec<MemberRef>>(v.clone()).ok())
        .unwrap_or_default()
}

/// Concrete tenant of a stored orchestrator payload. Legacy records without a
/// tenant belong to `default`; there are no tenant-wildcard orchestrators.
fn tenant_of(payload: &Value) -> String {
    payload
        .get("tenant_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|tenant| !tenant.is_empty())
        .unwrap_or("default")
        .to_string()
}

/// Emit `OrchestratorChanged` + write a receipt fact. Best-effort: a receipt
/// encode failure is logged, not surfaced (the mutation already committed to
/// the entity journal).
async fn after_mutation(state: &AppState, id: &str, actor: &str) {
    state
        .event_bus
        .emit(corecrux_memory::events::CruxEvent::OrchestratorChanged { id: id.to_string() });

    let receipt_id = format!("orchestrator:{id}");
    let receipt = json!({
        "schema": "crux.orchestrator.receipt.v1",
        "receipt_id": receipt_id,
        "orchestrator_id": id,
        "actor": actor,
        "at_unix_ms": now_unix_ms(),
    });
    match serde_json::to_string(&receipt) {
        Ok(value) => {
            let mut fact = corecrux_memory::fact_store::StoreFact {
                tenant_hash: "default".to_string(),
                entity: format!("__orchestrator_receipt__::{id}"),
                key: "record".to_string(),
                value,
                source_receipt: Some(receipt_id),
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: Some(actor.to_string()),
            };
            crate::fact_privacy::enforce(&state.privacy_policy, &mut fact);
            state.fact_store.write().await.store(fact);
        }
        Err(err) => tracing::warn!(error = %err, orchestrator = %id, "orchestrator receipt encode failed"),
    }
}

// ── M1: create / list / get / patch ──────────────────────────────────

#[derive(Debug, Deserialize)]
pub(super) struct CreateOrchestratorBody {
    pub name: String,
    /// Identity authoring the orchestrator. Recorded as `created_by_passport`.
    /// Falls back to the request's authenticated passport when omitted.
    #[serde(default, alias = "by_passport")]
    pub created_by_passport: Option<String>,
    #[serde(default)]
    pub assignee_passport: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn create_orchestrator(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateOrchestratorBody>,
) -> impl IntoResponse {
    if let Some(resp) = gate_check() {
        return resp;
    }
    let authority = match mutation_authority(&state, &headers, body.created_by_passport.as_deref()) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let tenant = match authority.context.resolve_authorized_tenant(body.tenant_id.as_deref()) {
        Ok(tenant) => tenant,
        Err(problem) => return problem.into_response(),
    };
    if body.name.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "name must not be empty");
    }
    let actor = authority.actor;
    let created_by = actor.clone();
    let assignee = body.assignee_passport.unwrap_or_else(|| created_by.clone());
    let st = body.state.unwrap_or_else(|| DEFAULT_STATE.to_string());
    if !ORCHESTRATOR_STATES.contains(&st.as_str()) {
        return problem_response(
            StatusCode::BAD_REQUEST,
            format!("state must be one of {} (got '{st}')", ORCHESTRATOR_STATES.join(", ")),
        );
    }

    // `uuid` (v4) is the workspace-standard id generator (see work.rs `w_…`).
    // `ulid` is not a dependency; a v4 uuid satisfies the "unique, opaque id"
    // contract of the ExecPlan's `orc_<…>` shape.
    let id = format!("orc_{}", uuid::Uuid::new_v4().simple());
    let now = now_unix_ms();
    let payload = orchestrator_payload(&id, &body.name, &assignee, &created_by, &tenant, &st, &[], now, now);

    let registry = state.kind_registry.read().await;
    let registry_opt = registry.is_registered(ORCHESTRATOR_KIND).then_some(&*registry);
    let mut store = state.entity_store.write().await;
    let result = store.upsert(ORCHESTRATOR_KIND, &id, payload, &actor, registry_opt);
    drop(store);
    drop(registry);

    match result {
        Ok(rec) => {
            after_mutation(&state, &id, &actor).await;
            (StatusCode::CREATED, Json(json!({ "orchestrator": rec }))).into_response()
        }
        Err(e) => problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ListOrchestratorsQuery {
    pub assignee: Option<String>,
    pub tenant_id: Option<String>,
    pub state: Option<String>,
    pub limit: Option<usize>,
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn list_orchestrators(
    State(state): State<AppState>,
    Query(q): Query<ListOrchestratorsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(resp) = gate_check() {
        return resp;
    }
    let context = match scoped_context(&state, &headers, &["facts:read", "admin:read"]) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let tenant = match context.resolve_authorized_tenant(q.tenant_id.as_deref()) {
        Ok(tenant) => tenant,
        Err(problem) => return problem.into_response(),
    };
    let query = corecrux_memory::EntityQuery {
        kind: Some(ORCHESTRATOR_KIND.to_string()),
        limit: None,
        include_deleted: false,
    };
    let store = state.entity_store.read().await;
    let mut orchestrators: Vec<Value> = store
        .list(&query)
        .into_iter()
        .filter(|rec| {
            let p = &rec.payload;
            q.assignee
                .as_deref()
                .is_none_or(|a| p.get("assignee_passport").and_then(Value::as_str) == Some(a))
                && tenant_of(p) == tenant
                && q.state
                    .as_deref()
                    .is_none_or(|s| p.get("state").and_then(Value::as_str) == Some(s))
        })
        .map(|rec| json!(rec))
        .collect();
    drop(store);
    if let Some(limit) = q.limit {
        orchestrators.truncate(limit);
    }
    let count = orchestrators.len();
    (
        StatusCode::OK,
        Json(json!({ "orchestrators": orchestrators, "count": count })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_orchestrator(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(resp) = gate_check() {
        return resp;
    }
    let context = match scoped_context(&state, &headers, &["facts:read", "admin:read"]) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let store = state.entity_store.read().await;
    match store.get(ORCHESTRATOR_KIND, &id) {
        Some(rec) => {
            if let Err(problem) = context.resolve_authorized_tenant(Some(&tenant_of(&rec.payload))) {
                return problem.into_response();
            }
            (StatusCode::OK, Json(json!({ "orchestrator": rec }))).into_response()
        }
        None => problem_response(StatusCode::NOT_FOUND, format!("orchestrator {id} not found")),
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct PatchOrchestratorBody {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub assignee_passport: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn patch_orchestrator(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<PatchOrchestratorBody>,
) -> impl IntoResponse {
    if let Some(resp) = gate_check() {
        return resp;
    }
    let authority = match mutation_authority(&state, &headers, None) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    if let Some(s) = &body.state {
        if !ORCHESTRATOR_STATES.contains(&s.as_str()) {
            return problem_response(
                StatusCode::BAD_REQUEST,
                format!("state must be one of {} (got '{s}')", ORCHESTRATOR_STATES.join(", ")),
            );
        }
    }
    let actor = authority.actor;

    let mut store = state.entity_store.write().await;
    let mut payload = match store.get(ORCHESTRATOR_KIND, &id) {
        Some(rec) => rec.payload.clone(),
        None => {
            drop(store);
            return problem_response(StatusCode::NOT_FOUND, format!("orchestrator {id} not found"));
        }
    };
    if let Err(problem) = authority.context.resolve_authorized_tenant(Some(&tenant_of(&payload))) {
        return problem.into_response();
    }
    if let Some(name) = &body.name {
        if name.trim().is_empty() {
            drop(store);
            return problem_response(StatusCode::BAD_REQUEST, "name must not be empty");
        }
        payload["name"] = json!(name);
    }
    if let Some(a) = &body.assignee_passport {
        payload["assignee_passport"] = json!(a);
    }
    if let Some(s) = &body.state {
        payload["state"] = json!(s);
    }
    payload["updated_at_unix_ms"] = json!(now_unix_ms());

    let registry = state.kind_registry.read().await;
    let registry_opt = registry.is_registered(ORCHESTRATOR_KIND).then_some(&*registry);
    let result = store.upsert(ORCHESTRATOR_KIND, &id, payload, &actor, registry_opt);
    drop(store);
    drop(registry);

    match result {
        Ok(rec) => {
            after_mutation(&state, &id, &actor).await;
            (StatusCode::OK, Json(json!({ "orchestrator": rec }))).into_response()
        }
        Err(e) => problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

// ── M2: membership ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(super) struct AddMemberBody {
    /// Member type: `execplan | work | handoff`. Optional when `member_ref`
    /// carries an inferable id prefix (`w_`/`execplan:`/`ho_`).
    #[serde(rename = "type", default)]
    pub member_type: Option<String>,
    /// The member's id. Accepts `ref` (canonical) or `member_ref` (the shape
    /// the MCP `attach_to_orchestrator` tool sends).
    #[serde(alias = "member_ref", default)]
    pub r#ref: Option<String>,
}

/// True when a member's tenant conflicts with the orchestrator's tenant (T.1).
///
/// Legacy missing/empty values on either side mean `default`; orchestrators
/// never act as tenant wildcards.
fn tenant_conflict(orchestrator_tenant: &str, member_tenant: Option<&str>) -> bool {
    let orchestrator_tenant = if orchestrator_tenant.trim().is_empty() {
        "default"
    } else {
        orchestrator_tenant
    };
    member_tenant.unwrap_or("default") != orchestrator_tenant
}

/// Infer the member type from an id prefix when the caller omitted `type`.
/// `w_…`→work, `execplan:…`→execplan, `ho_…`/`handoff:…`→handoff.
fn infer_member_type(member_ref: &str) -> Option<&'static str> {
    if member_ref.starts_with("w_") {
        Some(MEMBER_TYPE_WORK)
    } else if member_ref.starts_with("execplan:") {
        Some(MEMBER_TYPE_EXECPLAN)
    } else if member_ref.starts_with("ho_") || member_ref.starts_with("handoff:") {
        Some(MEMBER_TYPE_HANDOFF)
    } else {
        None
    }
}

/// Validate that a member reference exists and (for work/execplan) shares the
/// orchestrator's tenant. Returns the validated [`MemberRef`] or an error
/// `(status, detail)`.
async fn validate_member(
    state: &AppState,
    member_type: &str,
    member_ref: &str,
    orchestrator_tenant: &str,
) -> Result<MemberRef, (StatusCode, String)> {
    match member_type {
        MEMBER_TYPE_WORK => {
            let store = state.fact_store.read().await;
            let item = crate::work::get_work(&store, member_ref);
            drop(store);
            let Some(item) = item else {
                return Err((StatusCode::NOT_FOUND, format!("work item '{member_ref}' not found")));
            };
            // T.1: cross-tenant reject.
            if tenant_conflict(orchestrator_tenant, Some(crate::work::work_tenant_id(&item))) {
                return Err((
                    StatusCode::CONFLICT,
                    format!(
                        "cross-tenant membership rejected: work '{member_ref}' tenant '{}' != orchestrator tenant '{orchestrator_tenant}'",
                        crate::work::work_tenant_id(&item)
                    ),
                ));
            }
        }
        MEMBER_TYPE_EXECPLAN => {
            // ExecPlan members are validated against the read-time aggregator
            // when a root is configured. When no root is set the aggregator is
            // off; accept the reference so the membership survives a later
            // root configuration (resolution at read time surfaces missing).
            if let Some(root) = crate::work_execplans::execplans_root_from_env() {
                let store = state.fact_store.read().await;
                let items = crate::work_execplans::list_execplans(&store, &root, now_unix_ms()).unwrap_or_default();
                drop(store);
                let Some(item) = items.iter().find(|work| work.id == member_ref) else {
                    return Err((StatusCode::NOT_FOUND, format!("execplan '{member_ref}' not found")));
                };
                if tenant_conflict(orchestrator_tenant, Some(crate::work::work_tenant_id(item))) {
                    return Err((
                        StatusCode::CONFLICT,
                        format!(
                            "cross-tenant membership rejected: execplan '{member_ref}' tenant '{}' != orchestrator tenant '{orchestrator_tenant}'",
                            crate::work::work_tenant_id(item)
                        ),
                    ));
                }
            }
        }
        MEMBER_TYPE_HANDOFF => {
            // Handoffs are signed, client-held bundles — the daemon does not
            // persist them, so existence cannot be verified server-side. The
            // reference is accepted and resolved best-effort at read time.
        }
        MEMBER_TYPE_PASSPORT => {
            let store = state.fact_store.read().await;
            let found = passport_ref_exists(&store, member_ref);
            drop(store);
            if !found {
                return Err((StatusCode::NOT_FOUND, format!("passport '{member_ref}' not found")));
            }
            // Passports are workspace principals — no tenant containment check.
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown member type '{other}' (expected passport|work|execplan|handoff)"),
            ));
        }
    }
    Ok(MemberRef {
        member_type: member_type.to_string(),
        member_ref: member_ref.to_string(),
    })
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn add_member(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<AddMemberBody>,
) -> impl IntoResponse {
    if let Some(resp) = gate_check() {
        return resp;
    }
    let authority = match mutation_authority(&state, &headers, None) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let Some(member_ref) = body.r#ref.filter(|s| !s.trim().is_empty()) else {
        return problem_response(StatusCode::BAD_REQUEST, "ref (or member_ref) is required");
    };
    let member_type = match body.member_type {
        Some(t) if !t.trim().is_empty() => t,
        _ => match infer_member_type(&member_ref) {
            Some(t) => t.to_string(),
            None => {
                // No id-prefix match (w_/execplan:/ho_). A passport ref has no
                // stable prefix, so resolve it against the passport store before
                // giving up — this is what lets `attach_to_orchestrator` accept a
                // passport member without an explicit type.
                let is_passport = {
                    let store = state.fact_store.read().await;
                    passport_ref_exists(&store, &member_ref)
                };
                if is_passport {
                    MEMBER_TYPE_PASSPORT.to_string()
                } else {
                    return problem_response(
                        StatusCode::BAD_REQUEST,
                        format!(
                            "could not resolve member '{member_ref}'; pass an explicit type (passport|work|execplan|handoff)"
                        ),
                    );
                }
            }
        },
    };

    let actor = authority.actor;

    // Load the orchestrator first (for tenant + existing members).
    let (mut payload, orchestrator_tenant) = {
        let store = state.entity_store.read().await;
        match store.get(ORCHESTRATOR_KIND, &id) {
            Some(rec) => (rec.payload.clone(), tenant_of(&rec.payload)),
            None => {
                drop(store);
                return problem_response(StatusCode::NOT_FOUND, format!("orchestrator {id} not found"));
            }
        }
    };
    if let Err(problem) = authority.context.resolve_authorized_tenant(Some(&orchestrator_tenant)) {
        return problem.into_response();
    }

    let new_member = match validate_member(&state, &member_type, &member_ref, &orchestrator_tenant).await {
        Ok(m) => m,
        Err((status, detail)) => return problem_response(status, detail),
    };

    let mut members = members_of(&payload);
    if !members.iter().any(|m| m.member_ref == new_member.member_ref) {
        members.push(new_member.clone());
    }
    payload["members"] = json!(members);
    payload["updated_at_unix_ms"] = json!(now_unix_ms());

    // Persist the orchestrator record.
    let registry = state.kind_registry.read().await;
    let registry_opt = registry.is_registered(ORCHESTRATOR_KIND).then_some(&*registry);
    let mut estore = state.entity_store.write().await;
    let result = estore.upsert(ORCHESTRATOR_KIND, &id, payload, &actor, registry_opt);
    drop(estore);
    drop(registry);
    let rec = match result {
        Ok(rec) => rec,
        Err(e) => return problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    };

    // For work members, stamp orchestrator_id on the WorkItem.
    if new_member.member_type == MEMBER_TYPE_WORK {
        if let Err(e) =
            stamp_work_orchestrator(&state, &new_member.member_ref, Some(&id), &orchestrator_tenant, &actor).await
        {
            tracing::warn!(error = %e, work = %new_member.member_ref, "failed to stamp orchestrator_id on work item");
        }
    }

    after_mutation(&state, &id, &actor).await;
    (StatusCode::OK, Json(json!({ "orchestrator": rec }))).into_response()
}

/// Set (or clear) `orchestrator_id` on a kanban work item by rewriting its
/// record fact. No-op (returns Ok) when the work item is absent.
async fn stamp_work_orchestrator(
    state: &AppState,
    work_ref: &str,
    orchestrator_id: Option<&str>,
    expected_tenant: &str,
    actor: &str,
) -> Result<(), String> {
    let mut store = state.fact_store.write().await;
    let Some(mut item) = crate::work::get_work(&store, work_ref) else {
        return Ok(());
    };
    if crate::work::work_tenant_id(&item) != expected_tenant {
        return Err(format!(
            "work item tenant '{}' does not match authorized orchestrator tenant '{expected_tenant}'",
            crate::work::work_tenant_id(&item)
        ));
    }
    item.orchestrator_id = orchestrator_id.map(str::to_string);
    item.updated_at_unix_ms = now_unix_ms();
    crate::work::write_work_record_with_actor(&mut store, &item, actor).map_err(|e| e.to_string())?;
    Ok(())
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn remove_member(
    State(state): State<AppState>,
    Path((id, member_ref)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(resp) = gate_check() {
        return resp;
    }
    let authority = match mutation_authority(&state, &headers, None) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let actor = authority.actor;

    let (mut payload, orchestrator_tenant) = {
        let store = state.entity_store.read().await;
        match store.get(ORCHESTRATOR_KIND, &id) {
            Some(rec) => (rec.payload.clone(), tenant_of(&rec.payload)),
            None => {
                drop(store);
                return problem_response(StatusCode::NOT_FOUND, format!("orchestrator {id} not found"));
            }
        }
    };
    if let Err(problem) = authority.context.resolve_authorized_tenant(Some(&orchestrator_tenant)) {
        return problem.into_response();
    }

    let mut members = members_of(&payload);
    let before = members.len();
    let removed: Vec<MemberRef> = members.iter().filter(|m| m.member_ref == member_ref).cloned().collect();
    members.retain(|m| m.member_ref != member_ref);
    if members.len() == before {
        return problem_response(
            StatusCode::NOT_FOUND,
            format!("member '{member_ref}' not found on orchestrator {id}"),
        );
    }
    payload["members"] = json!(members);
    payload["updated_at_unix_ms"] = json!(now_unix_ms());

    let registry = state.kind_registry.read().await;
    let registry_opt = registry.is_registered(ORCHESTRATOR_KIND).then_some(&*registry);
    let mut estore = state.entity_store.write().await;
    let result = estore.upsert(ORCHESTRATOR_KIND, &id, payload, &actor, registry_opt);
    drop(estore);
    drop(registry);
    let rec = match result {
        Ok(rec) => rec,
        Err(e) => return problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    };

    // Unstamp orchestrator_id on any removed work members.
    for m in &removed {
        if m.member_type == MEMBER_TYPE_WORK {
            if let Err(e) = stamp_work_orchestrator(&state, &m.member_ref, None, &orchestrator_tenant, &actor).await {
                tracing::warn!(error = %e, work = %m.member_ref, "failed to clear orchestrator_id on work item");
            }
        }
    }

    after_mutation(&state, &id, &actor).await;
    (StatusCode::OK, Json(json!({ "orchestrator": rec }))).into_response()
}

// ── M3: member resolution ────────────────────────────────────────────

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn list_orchestrator_work(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(resp) = gate_check() {
        return resp;
    }
    let context = match scoped_context(&state, &headers, &["facts:read", "admin:read"]) {
        Ok(context) => context,
        Err(response) => return response,
    };

    let (payload, orchestrator_tenant) = {
        let store = state.entity_store.read().await;
        match store.get(ORCHESTRATOR_KIND, &id) {
            Some(rec) => (rec.payload.clone(), tenant_of(&rec.payload)),
            None => {
                drop(store);
                return problem_response(StatusCode::NOT_FOUND, format!("orchestrator {id} not found"));
            }
        }
    };
    if let Err(problem) = context.resolve_authorized_tenant(Some(&orchestrator_tenant)) {
        return problem.into_response();
    }
    let members = members_of(&payload);

    let resolved = resolve_members(&state, &members, &orchestrator_tenant).await;
    (
        StatusCode::OK,
        Json(json!({
            "orchestrator_id": id,
            "count": resolved.len(),
            "members": resolved,
        })),
    )
        .into_response()
}

/// Resolve every member reference to a live record. Dangling references
/// surface as `{type, ref, missing: true}` rather than failing the call.
async fn resolve_members(state: &AppState, members: &[MemberRef], tenant_id: &str) -> Vec<Value> {
    // Load the kanban + execplan universes once, then resolve each member.
    let store = state.fact_store.read().await;
    let kanban = crate::work::list_work(&store, None, None, Some(tenant_id), None);
    let mut execplans = crate::work_execplans::execplans_root_from_env()
        .and_then(|root| crate::work_execplans::list_execplans(&store, &root, now_unix_ms()).ok())
        .unwrap_or_default();
    execplans.retain(|work| crate::work::work_tenant_id(work) == tenant_id);
    drop(store);
    resolve_members_against(members, &kanban, &execplans)
}

/// Pure resolution: join member references against the live kanban + execplan
/// universes. A `work`/`execplan` member that has no matching live item, and
/// every `handoff` member (handoffs are client-held, never server-persisted),
/// surface as `{type, ref, missing: true}`. Never fails.
fn resolve_members_against(
    members: &[MemberRef],
    kanban: &[crate::work::WorkItem],
    execplans: &[crate::work::WorkItem],
) -> Vec<Value> {
    members
        .iter()
        .map(|m| match m.member_type.as_str() {
            MEMBER_TYPE_WORK => match kanban.iter().find(|w| w.id == m.member_ref) {
                Some(w) => json!({ "type": m.member_type, "ref": m.member_ref, "work": w }),
                None => json!({ "type": m.member_type, "ref": m.member_ref, "missing": true }),
            },
            MEMBER_TYPE_EXECPLAN => match execplans.iter().find(|w| w.id == m.member_ref) {
                Some(w) => json!({ "type": m.member_type, "ref": m.member_ref, "work": w }),
                None => json!({ "type": m.member_type, "ref": m.member_ref, "missing": true }),
            },
            // Passport members are validated at attach time and carry no
            // resolvable kanban/execplan payload — echo the reference plainly
            // (not "missing", which would misreport a valid principal).
            MEMBER_TYPE_PASSPORT => json!({ "type": m.member_type, "ref": m.member_ref }),
            // Handoffs are not server-persisted: echo the reference, flag it as
            // unresolvable server-side (not an error).
            _ => json!({ "type": m.member_type, "ref": m.member_ref, "missing": true }),
        })
        .collect()
}

/// All member reference ids of an orchestrator (any type), as a set. Used by
/// the `/v1/work?orchestrator=<id>` filter to stamp ExecPlan items at read
/// time. Returns an empty set for an unknown orchestrator.
pub(crate) fn orchestrator_member_refs(
    entity_store: &corecrux_memory::EntityStore,
    orchestrator_id: &str,
    tenant_id: &str,
) -> std::collections::HashSet<String> {
    entity_store
        .get(ORCHESTRATOR_KIND, orchestrator_id)
        .filter(|rec| tenant_of(&rec.payload) == tenant_id)
        .map(|rec| members_of(&rec.payload).into_iter().map(|m| m.member_ref).collect())
        .unwrap_or_default()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn infer_member_type_by_prefix() {
        assert_eq!(infer_member_type("w_abc123"), Some(MEMBER_TYPE_WORK));
        assert_eq!(infer_member_type("execplan:my-plan-2026"), Some(MEMBER_TYPE_EXECPLAN));
        assert_eq!(infer_member_type("ho_xyz"), Some(MEMBER_TYPE_HANDOFF));
        assert_eq!(infer_member_type("handoff:xyz"), Some(MEMBER_TYPE_HANDOFF));
        assert_eq!(infer_member_type("bare-token"), None);
    }

    #[test]
    fn members_round_trip_through_payload() {
        let members = vec![
            MemberRef {
                member_type: MEMBER_TYPE_WORK.to_string(),
                member_ref: "w_1".to_string(),
            },
            MemberRef {
                member_type: MEMBER_TYPE_EXECPLAN.to_string(),
                member_ref: "execplan:p".to_string(),
            },
        ];
        let payload = orchestrator_payload("orc_1", "Coord", "p1", "p1", "tenant-a", "planned", &members, 1, 1);
        assert_eq!(payload["tenant_id"], "tenant-a");
        assert_eq!(payload["state"], "planned");
        let back = members_of(&payload);
        assert_eq!(back, members);
        assert_eq!(tenant_of(&payload), "tenant-a");
    }

    #[test]
    fn members_of_tolerates_missing_field() {
        let payload = json!({ "id": "orc_1", "name": "x" });
        assert!(members_of(&payload).is_empty());
        assert_eq!(tenant_of(&payload), "default");
    }

    #[test]
    fn member_ref_serde_uses_type_and_ref_keys() {
        let m = MemberRef {
            member_type: "work".to_string(),
            member_ref: "w_1".to_string(),
        };
        let v = json!(m);
        assert_eq!(v["type"], "work");
        assert_eq!(v["ref"], "w_1");
    }

    // ── tenant conflict (T.1) ─────────────────────────────────────────

    #[test]
    fn tenant_conflict_rules() {
        // Missing/empty values are the legacy spelling of default.
        assert!(tenant_conflict("", Some("tenant-a")));
        assert!(!tenant_conflict("", None));
        // Matching tenants are fine.
        assert!(!tenant_conflict("tenant-a", Some("tenant-a")));
        // A legacy default member conflicts with a non-default orchestrator.
        assert!(tenant_conflict("tenant-a", None));
        // Populated + differing = conflict.
        assert!(tenant_conflict("tenant-a", Some("tenant-b")));
    }

    // ── entity-store CRUD round-trip (M1 substrate persistence) ──────

    fn registry() -> corecrux_memory::KindRegistry {
        let mut r = corecrux_memory::KindRegistry::new();
        crate::agentgraph_kinds::bootstrap(&mut r).expect("bootstrap kinds");
        r
    }

    /// Mint an orchestrator directly into an `EntityStore`, validated against
    /// the real kind schema (proves the payload satisfies the required fields).
    fn mint(store: &mut corecrux_memory::EntityStore, reg: &corecrux_memory::KindRegistry, id: &str, tenant: &str) {
        let payload = orchestrator_payload(id, "Coord", "p1", "p1", tenant, "planned", &[], 1, 1);
        store
            .upsert(ORCHESTRATOR_KIND, id, payload, "p1", Some(reg))
            .expect("orchestrator payload must satisfy the kind schema");
    }

    #[test]
    fn create_payload_satisfies_kind_schema_and_round_trips() {
        let reg = registry();
        let mut store = corecrux_memory::EntityStore::new();
        mint(&mut store, &reg, "orc_1", "tenant-a");

        let rec = store.get(ORCHESTRATOR_KIND, "orc_1").expect("present");
        assert_eq!(rec.payload["id"], "orc_1");
        assert_eq!(rec.payload["state"], "planned");
        assert_eq!(rec.payload["tenant_id"], "tenant-a");
        assert!(members_of(&rec.payload).is_empty());

        // list by kind
        let q = corecrux_memory::EntityQuery {
            kind: Some(ORCHESTRATOR_KIND.to_string()),
            limit: None,
            include_deleted: false,
        };
        assert_eq!(store.list(&q).len(), 1);
    }

    #[test]
    fn membership_appends_by_reference_with_dedup() {
        let reg = registry();
        let mut store = corecrux_memory::EntityStore::new();
        mint(&mut store, &reg, "orc_1", "tenant-a");

        // Simulate add_member's payload mutation: append two refs, one a dup.
        let mut payload = store.get(ORCHESTRATOR_KIND, "orc_1").unwrap().payload.clone();
        let mut members = members_of(&payload);
        for r in ["w_1", "execplan:p", "w_1"] {
            let candidate = MemberRef {
                member_type: infer_member_type(r).unwrap().to_string(),
                member_ref: r.to_string(),
            };
            if !members.iter().any(|m| m.member_ref == candidate.member_ref) {
                members.push(candidate);
            }
        }
        payload["members"] = json!(members);
        store
            .upsert(ORCHESTRATOR_KIND, "orc_1", payload, "p1", Some(&reg))
            .unwrap();

        let refs = orchestrator_member_refs(&store, "orc_1", "tenant-a");
        assert_eq!(refs.len(), 2, "duplicate w_1 collapsed");
        assert!(refs.contains("w_1"));
        assert!(refs.contains("execplan:p"));
        assert!(orchestrator_member_refs(&store, "orc_1", "tenant-b").is_empty());
        assert!(orchestrator_member_refs(&store, "orc_unknown", "tenant-a").is_empty());
    }

    // ── resolution (M3) ─────────────────────────────────────────────

    fn work_item(id: &str, tenant: Option<&str>) -> crate::work::WorkItem {
        crate::work::WorkItem {
            id: id.to_string(),
            project_id: "default".to_string(),
            state: "planned".to_string(),
            title: "t".to_string(),
            body: String::new(),
            assignee_passport: None,
            tenant_id: tenant.map(str::to_string),
            linked_pr: None,
            linked_issue: None,
            blocker_reason: None,
            blocker_kind: None,
            created_by_passport: "p1".to_string(),
            created_at_unix_ms: 1,
            updated_at_unix_ms: 1,
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

    #[test]
    fn resolve_surfaces_live_items_and_marks_dangling_missing() {
        let members = vec![
            MemberRef {
                member_type: MEMBER_TYPE_WORK.to_string(),
                member_ref: "w_live".to_string(),
            },
            MemberRef {
                member_type: MEMBER_TYPE_WORK.to_string(),
                member_ref: "w_gone".to_string(),
            },
            MemberRef {
                member_type: MEMBER_TYPE_EXECPLAN.to_string(),
                member_ref: "execplan:live".to_string(),
            },
            MemberRef {
                member_type: MEMBER_TYPE_HANDOFF.to_string(),
                member_ref: "ho_1".to_string(),
            },
        ];
        let kanban = vec![work_item("w_live", Some("tenant-a"))];
        let execplans = vec![work_item("execplan:live", None)];

        let resolved = resolve_members_against(&members, &kanban, &execplans);
        assert_eq!(resolved.len(), 4);
        assert_eq!(resolved[0]["work"]["id"], "w_live");
        assert!(resolved[0].get("missing").is_none());
        assert_eq!(resolved[1]["missing"], true, "dangling work ref");
        assert_eq!(resolved[2]["work"]["id"], "execplan:live");
        assert_eq!(resolved[3]["missing"], true, "handoff never resolves server-side");
    }

    #[test]
    fn stamp_orchestrator_id_on_execplan_members_only() {
        let mut execplans = vec![work_item("execplan:a", None), work_item("execplan:b", None)];
        let mut member_ids = std::collections::HashSet::new();
        member_ids.insert("execplan:a".to_string());
        crate::work_execplans::stamp_orchestrator_id(&mut execplans, &member_ids, "orc_9");
        assert_eq!(execplans[0].orchestrator_id.as_deref(), Some("orc_9"));
        assert_eq!(execplans[1].orchestrator_id, None);
    }

    // ── passport members (probe finding 6) ───────────────────────────

    #[test]
    fn passport_ref_exists_matches_id_and_principal() {
        use corecrux_memory::fact_store::{FactStore, StoreFact};
        let mut store = FactStore::new();
        let rec = json!({
            "id": "claude-work",
            "principal_id": "ce:abc:local",
            "public_key_hex": "deadbeef",
            "category": "work",
            "issued_at_unix_ms": 1u64,
        });
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "__passport__::claude-work".to_string(),
            key: "record".to_string(),
            value: rec.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
        assert!(passport_ref_exists(&store, "claude-work"), "match by passport id");
        assert!(passport_ref_exists(&store, "ce:abc:local"), "match by principal_id");
        assert!(!passport_ref_exists(&store, "nope"), "unknown ref does not match");
    }

    #[test]
    fn resolve_passport_member_echoes_without_missing() {
        let members = vec![MemberRef {
            member_type: MEMBER_TYPE_PASSPORT.to_string(),
            member_ref: "claude-work".to_string(),
        }];
        let resolved = resolve_members_against(&members, &[], &[]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0]["type"], "passport");
        assert_eq!(resolved[0]["ref"], "claude-work");
        assert!(
            resolved[0].get("missing").is_none(),
            "a validated passport member must not be reported missing"
        );
    }

    // ── async HTTP handlers (gate-on path) ───────────────────────────

    async fn handler_state() -> AppState {
        let st = super::super::tests::test_app_state(16);
        {
            let mut reg = st.kind_registry.write().await;
            crate::agentgraph_kinds::bootstrap(&mut reg).expect("bootstrap kinds");
        }
        st
    }

    async fn parts(resp: axum::response::Response) -> (StatusCode, Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn seed_work(st: &AppState, id: &str) {
        let mut store = st.fact_store.write().await;
        crate::work::write_work_record_with_actor(&mut store, &work_item(id, None), "test:orchestrator").unwrap();
    }

    async fn seed_passport(st: &AppState, id: &str, principal: &str) {
        use corecrux_memory::fact_store::StoreFact;
        let rec = json!({
            "id": id,
            "principal_id": principal,
            "public_key_hex": "deadbeef",
            "category": "work",
            "issued_at_unix_ms": 1u64,
        });
        st.fact_store.write().await.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: format!("__passport__::{id}"),
            key: "record".to_string(),
            value: rec.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
    }

    fn local_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-passport-id", axum::http::HeaderValue::from_static("p1"));
        headers
    }

    fn verified_headers(tenant: &str, passport: &str) -> HeaderMap {
        const SECRET: &str = "orchestrator-auth-test-secret-32-bytes";
        const ISSUER: &str = "corecrux-orchestrator-test";
        const AUDIENCE: &str = "corecrux";
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_secs()
            .saturating_add(3_600) as usize;
        let claims = json!({
            "exp": exp,
            "iss": ISSUER,
            "aud": AUDIENCE,
            "scope": "admin:read facts:write",
            "tenant_id": tenant,
            "passport_id": passport,
        });
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .expect("orchestrator auth test JWT");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(&format!("Bearer {token}")).expect("bearer header"),
        );
        headers
    }

    async fn create_with_headers(st: &AppState, headers: HeaderMap, body: Value) -> (StatusCode, Value) {
        let body: CreateOrchestratorBody = serde_json::from_value(body).unwrap();
        parts(
            create_orchestrator(State(st.clone()), headers, Json(body))
                .await
                .into_response(),
        )
        .await
    }

    async fn create(st: &AppState, body: Value) -> (StatusCode, Value) {
        create_with_headers(st, local_headers(), body).await
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn gate_off_returns_501() {
        std::env::remove_var("CORECRUXD_ORCHESTRATORS");
        let st = handler_state().await;
        let (status, _) = create(&st, json!({ "name": "x" })).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn create_get_list_patch_lifecycle() {
        std::env::set_var("CORECRUXD_ORCHESTRATORS", "1");
        let st = handler_state().await;

        // Create (defaults: state=planned, assignee=created_by=actor).
        let (status, body) = create(&st, json!({ "name": "Coord", "tenant_id": "tenant-a" })).await;
        assert_eq!(status, StatusCode::CREATED);
        let id = body["orchestrator"]["id"].as_str().unwrap().to_string();
        assert_eq!(body["orchestrator"]["payload"]["state"], "planned");

        // Validation: empty name, bad state.
        assert_eq!(create(&st, json!({ "name": "  " })).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(
            create(&st, json!({ "name": "z", "state": "bogus" })).await.0,
            StatusCode::BAD_REQUEST
        );

        // Get found + missing.
        let (status, body) = parts(
            get_orchestrator(State(st.clone()), Path(id.clone()), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["orchestrator"]["payload"]["name"], "Coord");
        let (status, _) = parts(
            get_orchestrator(State(st.clone()), Path("orc_missing".into()), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // List with filters.
        let list = |q: ListOrchestratorsQuery| {
            let st = st.clone();
            async move {
                parts(
                    list_orchestrators(State(st), Query(q), local_headers())
                        .await
                        .into_response(),
                )
                .await
            }
        };
        let (_, body) = list(ListOrchestratorsQuery {
            assignee: None,
            tenant_id: None,
            state: None,
            limit: None,
        })
        .await;
        assert_eq!(body["count"], 0, "default-tenant list must not leak tenant-a");
        let (_, body) = list(ListOrchestratorsQuery {
            assignee: None,
            tenant_id: Some("tenant-a".into()),
            state: Some("planned".into()),
            limit: Some(10),
        })
        .await;
        assert_eq!(body["count"], 1);
        let (_, body) = list(ListOrchestratorsQuery {
            assignee: None,
            tenant_id: Some("nope".into()),
            state: None,
            limit: None,
        })
        .await;
        assert_eq!(body["count"], 0);

        // Patch: name + state + assignee.
        let (status, body) = parts(
            patch_orchestrator(
                State(st.clone()),
                Path(id.clone()),
                local_headers(),
                Json(
                    serde_json::from_value(json!({ "name": "Coord2", "state": "active", "assignee_passport": "p9" }))
                        .unwrap(),
                ),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["orchestrator"]["payload"]["name"], "Coord2");
        assert_eq!(body["orchestrator"]["payload"]["state"], "active");
        assert_eq!(body["orchestrator"]["payload"]["assignee_passport"], "p9");

        // Patch invalid state, empty name, missing id.
        let patch = |id: String, b: Value| {
            let st = st.clone();
            async move {
                patch_orchestrator(
                    State(st),
                    Path(id),
                    local_headers(),
                    Json(serde_json::from_value(b).unwrap()),
                )
                .await
                .into_response()
                .status()
            }
        };
        assert_eq!(
            patch(id.clone(), json!({ "state": "bogus" })).await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            patch(id.clone(), json!({ "name": "  " })).await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            patch("orc_missing".into(), json!({ "name": "x" })).await,
            StatusCode::NOT_FOUND
        );

        std::env::remove_var("CORECRUXD_ORCHESTRATORS");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn verified_tenant_cannot_read_or_mutate_foreign_orchestrator() {
        const SECRET: &str = "orchestrator-auth-test-secret-32-bytes";
        const ISSUER: &str = "corecrux-orchestrator-test";
        const AUDIENCE: &str = "corecrux";
        std::env::set_var("CORECRUXD_ORCHESTRATORS", "1");
        let mut st = handler_state().await;
        st.auth = crate::auth::Authz::test_hs256(SECRET.as_bytes(), ISSUER, AUDIENCE);

        let (status, a) = create_with_headers(
            &st,
            verified_headers("tenant-a", "passport-a"),
            json!({"name":"A","tenant_id":"tenant-a"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(a["orchestrator"]["payload"]["created_by_passport"], "passport-a");
        let a_id = a["orchestrator"]["id"].as_str().expect("A id").to_string();
        let (status, b) = create_with_headers(
            &st,
            verified_headers("tenant-b", "passport-b"),
            json!({"name":"B","tenant_id":"tenant-b"}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        let b_id = b["orchestrator"]["id"].as_str().expect("B id").to_string();
        let b_version = b["orchestrator"]["version"].as_u64().expect("B version") as u32;

        let list_a = list_orchestrators(
            State(st.clone()),
            Query(ListOrchestratorsQuery {
                assignee: None,
                tenant_id: None,
                state: None,
                limit: None,
            }),
            verified_headers("tenant-a", "passport-a"),
        )
        .await
        .into_response();
        assert_eq!(list_a.status(), StatusCode::OK);
        let (_, list_a) = parts(list_a).await;
        assert_eq!(list_a["count"], 1);
        assert_eq!(list_a["orchestrators"][0]["id"], a_id);

        let cross_list = list_orchestrators(
            State(st.clone()),
            Query(ListOrchestratorsQuery {
                assignee: None,
                tenant_id: Some("tenant-b".to_string()),
                state: None,
                limit: None,
            }),
            verified_headers("tenant-a", "passport-a"),
        )
        .await
        .into_response();
        assert_eq!(cross_list.status(), StatusCode::FORBIDDEN);

        let cross_get = get_orchestrator(
            State(st.clone()),
            Path(b_id.clone()),
            verified_headers("tenant-a", "passport-a"),
        )
        .await
        .into_response();
        assert_eq!(cross_get.status(), StatusCode::FORBIDDEN);
        let cross_patch = patch_orchestrator(
            State(st.clone()),
            Path(b_id.clone()),
            verified_headers("tenant-a", "passport-a"),
            Json(PatchOrchestratorBody {
                name: Some("stolen".to_string()),
                assignee_passport: None,
                state: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(cross_patch.status(), StatusCode::FORBIDDEN);
        let cross_add = add_member(
            State(st.clone()),
            Path(b_id.clone()),
            verified_headers("tenant-a", "passport-a"),
            Json(AddMemberBody {
                member_type: Some("work".to_string()),
                r#ref: Some("w_missing".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(cross_add.status(), StatusCode::FORBIDDEN);
        let cross_remove = remove_member(
            State(st.clone()),
            Path((b_id.clone(), "w_missing".to_string())),
            verified_headers("tenant-a", "passport-a"),
        )
        .await
        .into_response();
        assert_eq!(cross_remove.status(), StatusCode::FORBIDDEN);
        let cross_members = list_orchestrator_work(
            State(st.clone()),
            Path(b_id.clone()),
            verified_headers("tenant-a", "passport-a"),
        )
        .await
        .into_response();
        assert_eq!(cross_members.status(), StatusCode::FORBIDDEN);

        let spoofed_identity = create_with_headers(
            &st,
            verified_headers("tenant-a", "passport-a"),
            json!({
                "name":"spoofed",
                "tenant_id":"tenant-a",
                "created_by_passport":"passport-b"
            }),
        )
        .await;
        assert_eq!(spoofed_identity.0, StatusCode::FORBIDDEN);
        let cross_create = create_with_headers(
            &st,
            verified_headers("tenant-a", "passport-a"),
            json!({"name":"cross","tenant_id":"tenant-b"}),
        )
        .await;
        assert_eq!(cross_create.0, StatusCode::FORBIDDEN);

        let store = st.entity_store.read().await;
        let b_after = store.get(ORCHESTRATOR_KIND, &b_id).expect("B remains");
        assert_eq!(b_after.version, b_version);
        assert_eq!(b_after.payload["name"], "B");
        assert_eq!(
            store
                .list(&corecrux_memory::EntityQuery {
                    kind: Some(ORCHESTRATOR_KIND.to_string()),
                    limit: None,
                    include_deleted: false,
                })
                .len(),
            2,
            "denied creates must not add orchestrators"
        );
        std::env::remove_var("CORECRUXD_ORCHESTRATORS");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn membership_add_remove_and_resolution() {
        std::env::set_var("CORECRUXD_ORCHESTRATORS", "1");
        let st = handler_state().await;
        let (_, body) = create(&st, json!({ "name": "Coord" })).await; // absent tenant = default
        let id = body["orchestrator"]["id"].as_str().unwrap().to_string();

        seed_work(&st, "w_1").await;
        seed_passport(&st, "claude-work", "ce:abc:local").await;

        let add = |id: String, b: Value| {
            let st = st.clone();
            async move {
                parts(
                    add_member(
                        State(st),
                        Path(id),
                        local_headers(),
                        Json(serde_json::from_value(b).unwrap()),
                    )
                    .await
                    .into_response(),
                )
                .await
            }
        };

        // Work member (explicit type).
        assert_eq!(
            add(id.clone(), json!({ "type": "work", "ref": "w_1" })).await.0,
            StatusCode::OK
        );
        // Passport member (type inferred via passport store lookup).
        assert_eq!(add(id.clone(), json!({ "ref": "claude-work" })).await.0, StatusCode::OK);
        // Handoff member (prefix-inferred, never validated server-side).
        assert_eq!(add(id.clone(), json!({ "ref": "ho_9" })).await.0, StatusCode::OK);
        // ExecPlan member (no root env → accepted optimistically).
        assert_eq!(add(id.clone(), json!({ "ref": "execplan:p1" })).await.0, StatusCode::OK);
        // Dedup: re-adding w_1 stays OK and does not duplicate.
        assert_eq!(
            add(id.clone(), json!({ "type": "work", "ref": "w_1" })).await.0,
            StatusCode::OK
        );

        // Error arms.
        assert_eq!(
            add(id.clone(), json!({ "type": "work", "ref": "  " })).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            add(id.clone(), json!({ "type": "bogus", "ref": "x" })).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            add(id.clone(), json!({ "type": "work", "ref": "w_missing" })).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            add(id.clone(), json!({ "ref": "bare-token-no-prefix" })).await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            add("orc_missing".into(), json!({ "type": "work", "ref": "w_1" }))
                .await
                .0,
            StatusCode::NOT_FOUND
        );

        // Resolve members → live work resolves, handoff/execplan-missing flagged.
        let (status, body) = parts(
            list_orchestrator_work(State(st.clone()), Path(id.clone()), local_headers())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], 4, "w_1, passport, handoff, execplan");

        // Remove the work member (also unstamps), then a non-member, then missing orchestrator.
        assert_eq!(
            parts(
                remove_member(State(st.clone()), Path((id.clone(), "w_1".into())), local_headers())
                    .await
                    .into_response()
            )
            .await
            .0,
            StatusCode::OK
        );
        assert_eq!(
            remove_member(
                State(st.clone()),
                Path((id.clone(), "not-a-member".into())),
                local_headers()
            )
            .await
            .into_response()
            .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            remove_member(
                State(st.clone()),
                Path(("orc_missing".into(), "w_1".into())),
                local_headers()
            )
            .await
            .into_response()
            .status(),
            StatusCode::NOT_FOUND
        );

        // list_orchestrator_work on a missing orchestrator → 404.
        assert_eq!(
            list_orchestrator_work(State(st.clone()), Path("orc_missing".into()), local_headers())
                .await
                .into_response()
                .status(),
            StatusCode::NOT_FOUND
        );

        std::env::remove_var("CORECRUXD_ORCHESTRATORS");
    }
}
