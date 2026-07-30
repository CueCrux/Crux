// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `/v1/punchcards/*` — resource-lease surface (punchcard plan).
//!
//! Mounted via `Router::merge` so the punchcard plan owns the handler bodies
//! without touching `http/mod.rs`. Gated by `CORECRUXD_PUNCHCARD`
//! (`off` | `advisory` | `enforce`, default `off`): when off, every route
//! returns a `501` problem.
//!
//! ## Lease model (M1–M6)
//!
//! A *punchcard* is an advisory/enforced lease on a resource held by a
//! passport. Resources use a URI scheme:
//!
//! - `file://<path>` — a single file.
//! - `tree://<subtree>` — a subtree; a `file://` resource is considered
//!   *contained* by a `tree://` lease when the file path is at or under the
//!   subtree path.
//! - `service://<name>` — a deploy target / named service (M3).
//!
//! Leases live in the substrate [`PUNCHCARD_KIND`] entity store as
//! `pc_<uuid>` records. The status FSM is
//! `held → released | expired | force_released`. Reads never consult leases;
//! only mutating tools (`acquire` / `release` / `check` / `force-release`)
//! interact with them. A crashed holder cannot deadlock a resource: every
//! `acquire` and `list` first runs an *expiry sweep* that flips any `held`
//! card past its `expires_at_unix_ms` to `expired`, freeing the resource.
//!
//! `POST /v1/punchcards/check` is the endpoint the shared PreToolUse hook
//! probes before an Edit/Write/NotebookEdit. It always returns `200` (so the
//! hook can read the body) with `{held_by_other, enforce, holder_passport,
//! resource, expires_at_unix_ms}`. The hook denies the edit only when
//! `held_by_other && enforce`.

use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use super::{problem_response, AppState, HeaderMap, IntoResponse, Json, Query, Response, State, StatusCode};
use crate::agentgraph_kinds::{punchcard_enabled, punchcard_mode, PunchcardMode, PUNCHCARD_KIND};

/// Default lease TTL when a caller omits `ttl_secs`.
const DEFAULT_TTL_SECS: u64 = 1800;
/// Upper bound on lease TTL to stop a typo pinning a resource forever.
const MAX_TTL_SECS: u64 = 86_400;

/// Routes for the punchcard surface. Merged into the main router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/v1/punchcards/acquire", post(acquire))
        .route("/v1/punchcards/release", post(release))
        .route("/v1/punchcards", get(list_punchcards))
        .route("/v1/punchcards/{id}/force-release", post(force_release))
        .route("/v1/punchcards/check", post(check))
}

// ── Gate ────────────────────────────────────────────────────────────────

/// Gate-aware 501 when the surface is disabled. Returns `Some(problem)` when
/// the caller should short-circuit (mode is Off), `None` when serving is OK.
fn gate_disabled() -> Option<Response> {
    if punchcard_enabled() {
        None
    } else {
        Some(problem_response(
            StatusCode::NOT_IMPLEMENTED,
            "punchcard surface disabled (set CORECRUXD_PUNCHCARD=advisory|enforce)",
        ))
    }
}

// ── Request bodies ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub(super) struct AcquireBody {
    pub resource: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Explicit lease holder. In authenticated modes this must match the
    /// request-derived authority. Cross-owner intervention uses the separate
    /// force-release route.
    #[serde(default)]
    pub holder_passport: Option<String>,
}

fn default_mode() -> String {
    "modify".to_string()
}

#[derive(Debug, Deserialize)]
pub(super) struct ReleaseBody {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub release_commit_sha: Option<String>,
    /// Explicit lease holder (see [`AcquireBody::holder_passport`]). Used to
    /// match the held card by (resource, holder) when releasing by resource.
    #[serde(default)]
    pub holder_passport: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct CheckBody {
    pub resource: String,
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub passport: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ForceReleaseBody {
    #[serde(default)]
    pub confirm: bool,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub by_passport: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ListPunchcardsQuery {
    pub resource: Option<String>,
    pub holder: Option<String>,
    pub holder_passport: Option<String>,
    pub status: Option<String>,
    pub tenant_id: Option<String>,
}

// ── Pure lease helpers (unit-testable without AppState / env) ───────────────

/// Current wall-clock in unix milliseconds.
fn now_unix_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Read a string field from a punchcard payload.
fn payload_str(payload: &Value, key: &str) -> Option<String> {
    payload.get(key).and_then(Value::as_str).map(str::to_string)
}

/// Read an i64 field from a punchcard payload.
fn payload_i64(payload: &Value, key: &str) -> Option<i64> {
    payload.get(key).and_then(Value::as_i64)
}

/// Split a resource URI into `(scheme, path)`. Unrecognised schemes are
/// returned verbatim as the path with an empty scheme so equality still works.
fn split_resource(uri: &str) -> (&str, &str) {
    match uri.split_once("://") {
        Some((scheme, rest)) => (scheme, rest),
        None => ("", uri),
    }
}

/// `true` when a `held` lease on `held_resource` covers a request for
/// `req_resource`.
///
/// Overlap rules:
/// - Identical URIs overlap.
/// - A `tree://T` lease covers a `file://F` (or `tree://F`) request when `F`
///   is at or under `T` (path-segment containment, so `tree://a/b` covers
///   `file://a/b/c.rs` but not `file://a/bc/c.rs`).
/// - Symmetrically, a `file://F`/`tree://F` lease is covered by a request for
///   the enclosing `tree://T` — i.e. acquiring a subtree conflicts with an
///   existing leaf lease inside it.
/// - `service://` and `deploy://` leases are **point-exclusive**: they conflict
///   ONLY on exact URI equality (host+path), never by prefix containment. A
///   `deploy://host/a` lease therefore does NOT cover `deploy://host/a/b` — a
///   deploy target is an atomic resource, not a subtree.
fn resources_overlap(held_resource: &str, req_resource: &str) -> bool {
    if held_resource == req_resource {
        return true;
    }
    let (held_scheme, held_path) = split_resource(held_resource);
    let (req_scheme, req_path) = split_resource(req_resource);

    // `deploy://` (and `service://`) are point-exclusive: only exact equality
    // (handled above) conflicts. Never apply subtree containment to a deploy
    // lease, even if the other side is a `tree://` request.
    if held_scheme == "deploy" || req_scheme == "deploy" {
        return false;
    }

    // `tree://` held lease covering a deeper request.
    if held_scheme == "tree" && path_contains(held_path, req_path) {
        return true;
    }
    // Request for an enclosing `tree://` covering an existing leaf lease.
    if req_scheme == "tree" && path_contains(req_path, held_path) {
        return true;
    }
    false
}

/// `true` when `parent` path contains (is an ancestor of, or equals) `child`,
/// using `/`-segment boundaries so `a/b` contains `a/b/c` but not `a/bc`.
fn path_contains(parent: &str, child: &str) -> bool {
    let parent = parent.trim_end_matches('/');
    let child = child.trim_end_matches('/');
    if parent == child {
        return true;
    }
    match child.strip_prefix(parent) {
        Some(rest) => rest.starts_with('/'),
        None => false,
    }
}

/// `true` when this payload is a `held` card whose TTL has elapsed by `now`.
fn is_expired_held(payload: &Value, now_ms: i64) -> bool {
    payload_str(payload, "status").as_deref() == Some("held")
        && payload_i64(payload, "expires_at_unix_ms").is_some_and(|exp| exp <= now_ms)
}

/// `true` when this payload is a currently-effective `held` lease at `now`.
fn is_active_held(payload: &Value, now_ms: i64) -> bool {
    payload_str(payload, "status").as_deref() == Some("held")
        && payload_i64(payload, "expires_at_unix_ms").is_none_or(|exp| exp > now_ms)
}

/// Clamp a caller-supplied TTL into `[1, MAX_TTL_SECS]`, defaulting when absent.
fn resolve_ttl_secs(ttl_secs: Option<u64>) -> u64 {
    ttl_secs.unwrap_or(DEFAULT_TTL_SECS).clamp(1, MAX_TTL_SECS)
}

// ── Handlers ──────────────────────────────────────────────────────────────

struct PunchcardAuthority {
    context: crate::auth::HttpScopeContext,
    actor: String,
    tenant_id: String,
}

#[allow(clippy::result_large_err)]
fn punchcard_authority(
    state: &AppState,
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    requested_identity: Option<&str>,
    requested_tenant: Option<&str>,
    accepted_scopes: &[&str],
) -> Result<PunchcardAuthority, Response> {
    let context = crate::auth::passport_bound_context(&state.auth, headers).map_err(IntoResponse::into_response)?;
    if !accepted_scopes.iter().any(|scope| context.has_scope(scope)) {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            format!("one of {} is required for punchcard access", accepted_scopes.join(", ")),
        ));
    }
    let requested_identity = requested_identity.map(str::trim).filter(|value| !value.is_empty());
    let actor = if context.local_unverified_identity() {
        if !state.http_bind_loopback || !super::ingress::is_direct_loopback_request(headers, peer_ip) {
            return Err(problem_response(
                StatusCode::FORBIDDEN,
                "local unverified punchcard authority is restricted to the direct loopback listener",
            ));
        }
        let header_identity = context.passport_id.as_deref();
        if let (Some(body), Some(header)) = (requested_identity, header_identity) {
            if body != header {
                return Err(problem_response(
                    StatusCode::FORBIDDEN,
                    "body passport does not match the local identity assertion header",
                ));
            }
        }
        if let Some(asserted) = requested_identity.or(header_identity) {
            format!("{}{asserted}", super::approval_receipts::UNVERIFIED_APPROVER_PREFIX)
        } else {
            let local_principal = state.session.as_ref().map_or_else(
                || "local-daemon".to_string(),
                |services| services.passport_cfg.synthesise().0.principal_id,
            );
            format!(
                "{}local:{local_principal}",
                super::approval_receipts::UNVERIFIED_APPROVER_PREFIX
            )
        }
    } else {
        if context.passport_override_used() {
            return Err(problem_response(
                StatusCode::FORBIDDEN,
                "passport impersonation is not permitted for punchcard operations",
            ));
        }
        let identity = context.verified_authority_actor().ok_or_else(|| {
            problem_response(
                StatusCode::FORBIDDEN,
                "an authenticated passport is required for punchcard operations",
            )
        })?;
        if requested_identity.is_some_and(|requested| requested != identity) {
            return Err(problem_response(
                StatusCode::FORBIDDEN,
                "body passport does not match the authenticated passport",
            ));
        }
        identity
    };
    let tenant_id = context
        .resolve_authorized_tenant(requested_tenant)
        .map_err(IntoResponse::into_response)?;
    Ok(PunchcardAuthority {
        context,
        actor,
        tenant_id,
    })
}

#[allow(clippy::result_large_err)]
fn force_release_authority(
    state: &AppState,
    headers: &HeaderMap,
    claimed_actor: Option<&str>,
) -> Result<PunchcardAuthority, Response> {
    let context = crate::auth::passport_bound_context(&state.auth, headers).map_err(IntoResponse::into_response)?;
    if !context.auth_enforced()
        || context.local_unverified_identity()
        || !context.has_scope("admin:write")
        || context.passport_override_used()
        || context.credential_is_agent_token()
        || !context.canonical_passport_claim_verified()
    {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            "force-release requires an issuer-verified canonical passport claim with admin:write; opaque agent tokens are not accepted",
        ));
    }
    let actor = context
        .passport_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| problem_response(StatusCode::FORBIDDEN, "verified admin passport is missing"))?
        .to_string();
    if claimed_actor
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|claimed| claimed != actor)
    {
        return Err(problem_response(
            StatusCode::FORBIDDEN,
            "body passport does not match the verified admin passport",
        ));
    }
    Ok(PunchcardAuthority {
        context,
        actor,
        tenant_id: String::new(),
    })
}

/// Sweep expired `held` cards to `expired` and emit a `PunchcardChanged`.
///
/// Runs under a held write lock on the entity store. Returns the number of
/// cards swept. A crashed holder cannot deadlock a resource because the next
/// `acquire`/`list` flips its expired card here before evaluating conflicts.
async fn sweep_expired(state: &AppState) -> usize {
    let now = now_unix_ms();
    let registry = state.kind_registry.read().await;
    let registry_opt = registry.is_registered(PUNCHCARD_KIND).then_some(&*registry);
    let mut store = state.entity_store.write().await;
    let query = corecrux_memory::EntityQuery {
        kind: Some(PUNCHCARD_KIND.to_string()),
        limit: None,
        include_deleted: false,
    };
    let expired_ids: Vec<(String, Value)> = store
        .list(&query)
        .into_iter()
        .filter(|rec| is_expired_held(&rec.payload, now))
        .map(|rec| (rec.id.clone(), rec.payload.clone()))
        .collect();
    let count = expired_ids.len();
    for (id, mut payload) in expired_ids {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("status".to_string(), json!("expired"));
        }
        if store
            .upsert(PUNCHCARD_KIND, &id, payload, "system:punchcard-sweep", registry_opt)
            .is_ok()
        {
            state
                .event_bus
                .emit(corecrux_memory::events::CruxEvent::PunchcardChanged {
                    id,
                    status: "expired".to_string(),
                });
        }
    }
    count
}

/// Build a CROWN-style receipt id for a punchcard transition. Mirrors the
/// `rcx_publish` receipt-id idiom (stable, hash-free here since the id itself
/// carries the transition + card id).
fn receipt_id(op: &str, card_id: &str) -> String {
    format!("rcx-punchcard:{op}:{card_id}")
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn acquire(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<AcquireBody>,
) -> Response {
    acquire_with_peer(state, Some(peer.ip()), headers, body).await
}

async fn acquire_with_peer(
    state: AppState,
    peer_ip: Option<IpAddr>,
    headers: HeaderMap,
    body: AcquireBody,
) -> Response {
    if let Some(p) = gate_disabled() {
        return p;
    }
    if body.resource.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "resource must not be empty");
    }
    let authority = match punchcard_authority(
        &state,
        &headers,
        peer_ip,
        body.holder_passport.as_deref(),
        body.tenant_id.as_deref(),
        &["facts:write", "admin:write"],
    ) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let holder = authority.actor;
    let tenant_id = authority.tenant_id;

    // Expiry sweep first so a crashed holder's card cannot block us.
    sweep_expired(&state).await;

    let now = now_unix_ms();
    let registry = state.kind_registry.read().await;
    let registry_opt = registry.is_registered(PUNCHCARD_KIND).then_some(&*registry);
    let mut store = state.entity_store.write().await;
    let query = corecrux_memory::EntityQuery {
        kind: Some(PUNCHCARD_KIND.to_string()),
        limit: None,
        include_deleted: false,
    };

    // Scan active held cards for (a) a reentrant card by the same holder on the
    // same resource, and (b) a conflicting card by a different holder.
    let mut reentrant_id: Option<String> = None;
    let mut conflict: Option<(String, String, i64)> = None; // (id, holder, expires)
    for rec in store.list(&query) {
        if !is_active_held(&rec.payload, now) {
            continue;
        }
        let card_resource = payload_str(&rec.payload, "resource").unwrap_or_default();
        let card_holder = payload_str(&rec.payload, "holder_passport").unwrap_or_default();
        let card_tenant = payload_str(&rec.payload, "tenant_id").unwrap_or_else(|| "default".to_string());
        if card_tenant != tenant_id {
            continue;
        }
        if card_resource == body.resource && card_holder == holder {
            reentrant_id = Some(rec.id.clone());
            continue;
        }
        if resources_overlap(&card_resource, &body.resource) && card_holder != holder {
            conflict = Some((
                rec.id.clone(),
                card_holder,
                payload_i64(&rec.payload, "expires_at_unix_ms").unwrap_or_default(),
            ));
        }
    }

    let ttl = resolve_ttl_secs(body.ttl_secs);
    let expires_at = now + (ttl as i64) * 1000;
    let mode = punchcard_mode();

    // A same-holder exact card does not erase a different holder's overlapping
    // card. This state can arise after advisory grants; if the daemon later
    // switches to enforce, the peer conflict wins before any reentrant refresh.
    if let Some((conflict_id, conflict_holder, conflict_expires)) = conflict.as_ref() {
        if mode == PunchcardMode::Enforce {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "resource held by another passport",
                    "resource": body.resource,
                    "held_by": conflict_holder,
                    "punchcard_id": conflict_id,
                    "expires_at_unix_ms": conflict_expires,
                })),
            )
                .into_response();
        }
    }

    let advisory_conflict = conflict
        .as_ref()
        .map(|(conflict_id, conflict_holder, conflict_expires)| {
            json!({
                "held_by": conflict_holder,
                "punchcard_id": conflict_id,
                "expires_at_unix_ms": conflict_expires,
            })
        });

    // Reentrant: same holder refreshes its own TTL → 200.
    if let Some(id) = reentrant_id {
        let prev = match store.get(PUNCHCARD_KIND, &id) {
            Some(rec) => rec.payload.clone(),
            None => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "reentrant card vanished"),
        };
        let mut payload = prev;
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("expires_at_unix_ms".to_string(), json!(expires_at));
            if let Some(reason) = &body.reason {
                obj.insert("reason".to_string(), json!(reason));
            }
        }
        return match store.upsert(PUNCHCARD_KIND, &id, payload, &holder, registry_opt) {
            Ok(rec) => {
                drop(store);
                state
                    .event_bus
                    .emit(corecrux_memory::events::CruxEvent::PunchcardChanged {
                        id: id.clone(),
                        status: "held".to_string(),
                    });
                let mut out = json!({"punchcard": rec.payload, "reentrant": true});
                if let Some(conflict) = advisory_conflict {
                    out["advisory_conflict"] = conflict;
                }
                (StatusCode::OK, Json(out)).into_response()
            }
            Err(e) => problem_response(StatusCode::BAD_REQUEST, e.to_string()),
        };
    }

    // Set when a peer already holds this resource and advisory mode granted
    // anyway. Carried on the 201 so the caller can warn its operator.
    // Mint a fresh lease.
    let id = format!("pc_{}", Uuid::new_v4().simple());
    let rid = receipt_id("acquire", &id);
    let payload = json!({
        "id": id,
        "resource": body.resource,
        "mode": body.mode,
        "holder_passport": holder,
        "tenant_id": tenant_id,
        "status": "held",
        "reason": body.reason,
        "acquired_at_unix_ms": now,
        "expires_at_unix_ms": expires_at,
        "receipt_acquire": rid,
    });
    match store.upsert(PUNCHCARD_KIND, &id, payload, &holder, registry_opt) {
        Ok(rec) => {
            drop(store);
            state
                .event_bus
                .emit(corecrux_memory::events::CruxEvent::PunchcardChanged {
                    id: id.clone(),
                    status: "held".to_string(),
                });
            let mut out = json!({"punchcard": rec.payload});
            if let Some(c) = advisory_conflict {
                out["advisory_conflict"] = c;
            }
            (StatusCode::CREATED, Json(out)).into_response()
        }
        Err(e) => problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn release(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<ReleaseBody>,
) -> Response {
    release_with_peer(state, Some(peer.ip()), headers, body).await
}

async fn release_with_peer(
    state: AppState,
    peer_ip: Option<IpAddr>,
    headers: HeaderMap,
    body: ReleaseBody,
) -> Response {
    if let Some(p) = gate_disabled() {
        return p;
    }
    let authority = match punchcard_authority(
        &state,
        &headers,
        peer_ip,
        body.holder_passport.as_deref(),
        None,
        &["facts:write", "admin:write"],
    ) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let holder = authority.actor;
    let tenant_id = authority.tenant_id;
    let now = now_unix_ms();
    let registry = state.kind_registry.read().await;
    let registry_opt = registry.is_registered(PUNCHCARD_KIND).then_some(&*registry);
    let mut store = state.entity_store.write().await;

    // Resolve the target card by id, or by (resource, holder) for an active
    // held card owned by the caller.
    let target_id = match (&body.id, &body.resource) {
        (Some(id), _) => Some(id.clone()),
        (None, Some(resource)) => {
            let query = corecrux_memory::EntityQuery {
                kind: Some(PUNCHCARD_KIND.to_string()),
                limit: None,
                include_deleted: false,
            };
            store
                .list(&query)
                .into_iter()
                .find(|rec| {
                    is_active_held(&rec.payload, now)
                        && payload_str(&rec.payload, "resource").as_deref() == Some(resource.as_str())
                        && payload_str(&rec.payload, "holder_passport").as_deref() == Some(holder.as_str())
                        && payload_str(&rec.payload, "tenant_id").as_deref() == Some(tenant_id.as_str())
                })
                .map(|rec| rec.id.clone())
        }
        (None, None) => {
            return problem_response(StatusCode::BAD_REQUEST, "release requires `id` or `resource`");
        }
    };

    let id = match target_id {
        Some(id) => id,
        None => return problem_response(StatusCode::NOT_FOUND, "no matching held punchcard to release"),
    };
    let mut payload = match store.get(PUNCHCARD_KIND, &id) {
        Some(rec) => rec.payload.clone(),
        None => return problem_response(StatusCode::NOT_FOUND, format!("punchcard {id} not found")),
    };
    if payload_str(&payload, "tenant_id").as_deref() != Some(tenant_id.as_str()) {
        return problem_response(StatusCode::FORBIDDEN, "punchcard belongs to a different tenant");
    }
    if payload_str(&payload, "holder_passport").as_deref() != Some(holder.as_str()) {
        return problem_response(
            StatusCode::FORBIDDEN,
            "punchcard is owned by another passport; use the verified admin force-release route",
        );
    }
    if payload_str(&payload, "status").as_deref() != Some("held") {
        return problem_response(StatusCode::CONFLICT, "only a held punchcard can be released");
    }
    let rid = receipt_id("release", &id);
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("status".to_string(), json!("released"));
        obj.insert("released_at_unix_ms".to_string(), json!(now));
        obj.insert("receipt_release".to_string(), json!(rid));
        if let Some(sha) = &body.release_commit_sha {
            obj.insert("release_commit_sha".to_string(), json!(sha));
        }
    }
    match store.upsert(PUNCHCARD_KIND, &id, payload, &holder, registry_opt) {
        Ok(rec) => {
            drop(store);
            state
                .event_bus
                .emit(corecrux_memory::events::CruxEvent::PunchcardChanged {
                    id: id.clone(),
                    status: "released".to_string(),
                });
            (StatusCode::OK, Json(json!({"punchcard": rec.payload}))).into_response()
        }
        Err(e) => problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn list_punchcards(
    State(state): State<AppState>,
    Query(q): Query<ListPunchcardsQuery>,
    headers: HeaderMap,
) -> Response {
    if let Some(p) = gate_disabled() {
        return p;
    }
    let context = match crate::auth::passport_bound_context(&state.auth, &headers) {
        Ok(context) => context,
        Err(problem) => return problem.into_response(),
    };
    if !context.has_scope("facts:read") && !context.has_scope("admin:read") {
        return problem_response(
            StatusCode::FORBIDDEN,
            "facts:read or admin:read is required for punchcard access",
        );
    }
    let tenant_id = match context.resolve_authorized_tenant(q.tenant_id.as_deref()) {
        Ok(tenant_id) => tenant_id,
        Err(problem) => return problem.into_response(),
    };
    // Sweep so the list reflects freed (expired) resources.
    sweep_expired(&state).await;

    let store = state.entity_store.read().await;
    let query = corecrux_memory::EntityQuery {
        kind: Some(PUNCHCARD_KIND.to_string()),
        limit: None,
        include_deleted: false,
    };
    let holder_filter = q.holder.or(q.holder_passport);
    let punchcards: Vec<Value> = store
        .list(&query)
        .into_iter()
        .filter(|rec| {
            q.resource
                .as_ref()
                .is_none_or(|r| payload_str(&rec.payload, "resource").as_deref() == Some(r.as_str()))
                && holder_filter
                    .as_ref()
                    .is_none_or(|h| payload_str(&rec.payload, "holder_passport").as_deref() == Some(h.as_str()))
                && q.status
                    .as_ref()
                    .is_none_or(|s| payload_str(&rec.payload, "status").as_deref() == Some(s.as_str()))
                && payload_str(&rec.payload, "tenant_id").as_deref() == Some(tenant_id.as_str())
        })
        .map(|rec| rec.payload.clone())
        .collect();
    let count = punchcards.len();
    (StatusCode::OK, Json(json!({"punchcards": punchcards, "count": count}))).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn check(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<CheckBody>,
) -> Response {
    check_with_peer(state, Some(peer.ip()), headers, body).await
}

async fn check_with_peer(state: AppState, peer_ip: Option<IpAddr>, headers: HeaderMap, body: CheckBody) -> Response {
    // `check` always returns 200 (even when disabled / no conflict) so the
    // PreToolUse hook can read the body and fail-open. When the surface is
    // disabled we report `enforce:false, held_by_other:false` → ALLOW.
    if !punchcard_enabled() {
        return (
            StatusCode::OK,
            Json(json!({
                "held_by_other": false,
                "enforce": false,
                "holder_passport": Value::Null,
                "resource": body.resource,
                "expires_at_unix_ms": Value::Null,
            })),
        )
            .into_response();
    }
    let authority = match punchcard_authority(
        &state,
        &headers,
        peer_ip,
        body.passport.as_deref(),
        None,
        &["facts:read", "admin:read"],
    ) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    // Sweep so an expired holder doesn't show as a live conflict.
    sweep_expired(&state).await;

    let probe = authority.actor;
    let tenant_id = authority.tenant_id;
    let enforce = punchcard_mode() == PunchcardMode::Enforce;
    let now = now_unix_ms();

    let store = state.entity_store.read().await;
    let query = corecrux_memory::EntityQuery {
        kind: Some(PUNCHCARD_KIND.to_string()),
        limit: None,
        include_deleted: false,
    };
    // Find an active held card by a DIFFERENT passport overlapping the resource.
    let conflict = store.list(&query).into_iter().find_map(|rec| {
        if !is_active_held(&rec.payload, now) {
            return None;
        }
        let card_resource = payload_str(&rec.payload, "resource").unwrap_or_default();
        let card_holder = payload_str(&rec.payload, "holder_passport").unwrap_or_default();
        let card_tenant = payload_str(&rec.payload, "tenant_id").unwrap_or_else(|| "default".to_string());
        if card_tenant == tenant_id && card_holder != probe && resources_overlap(&card_resource, &body.resource) {
            Some((card_holder, payload_i64(&rec.payload, "expires_at_unix_ms")))
        } else {
            None
        }
    });

    let (held_by_other, holder_passport, expires_at) = match conflict {
        Some((holder, expires)) => (true, json!(holder), expires.map_or(Value::Null, |e| json!(e))),
        None => (false, Value::Null, Value::Null),
    };
    (
        StatusCode::OK,
        Json(json!({
            "held_by_other": held_by_other,
            "enforce": enforce,
            "holder_passport": holder_passport,
            "resource": body.resource,
            "mode": body.mode,
            "expires_at_unix_ms": expires_at,
        })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn force_release(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
    Json(body): Json<ForceReleaseBody>,
) -> Response {
    if let Some(p) = gate_disabled() {
        return p;
    }
    // Destructive override (Art.14): require explicit confirmation in-body.
    if !body.confirm {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "force-release is destructive; resubmit with {\"confirm\": true}",
        );
    }
    let authority = match force_release_authority(&state, &headers, body.by_passport.as_deref()) {
        Ok(authority) => authority,
        Err(response) => return response,
    };
    let by = authority.actor;
    let now = now_unix_ms();
    let registry = state.kind_registry.read().await;
    let registry_opt = registry.is_registered(PUNCHCARD_KIND).then_some(&*registry);
    let mut store = state.entity_store.write().await;
    let mut payload = match store.get(PUNCHCARD_KIND, &id) {
        Some(rec) => rec.payload.clone(),
        None => return problem_response(StatusCode::NOT_FOUND, format!("punchcard {id} not found")),
    };
    let target_tenant = payload_str(&payload, "tenant_id").unwrap_or_else(|| "default".to_string());
    if let Err(problem) = authority.context.resolve_authorized_tenant(Some(&target_tenant)) {
        return problem.into_response();
    }
    if payload_str(&payload, "status").as_deref() != Some("held") {
        return problem_response(StatusCode::CONFLICT, "only a held punchcard can be force-released");
    }
    let rid = receipt_id("force-release", &id);
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("status".to_string(), json!("force_released"));
        obj.insert("released_at_unix_ms".to_string(), json!(now));
        obj.insert("receipt_release".to_string(), json!(rid));
        obj.insert("force_released_by".to_string(), json!(by));
        if let Some(reason) = &body.reason {
            obj.insert("force_release_reason".to_string(), json!(reason));
        }
    }
    match store.upsert(PUNCHCARD_KIND, &id, payload, &by, registry_opt) {
        Ok(rec) => {
            drop(store);
            state
                .event_bus
                .emit(corecrux_memory::events::CruxEvent::PunchcardChanged {
                    id: id.clone(),
                    status: "force_released".to_string(),
                });
            (StatusCode::OK, Json(json!({"punchcard": rec.payload}))).into_response()
        }
        Err(e) => problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    fn held(resource: &str, holder: &str, expires: i64) -> Value {
        json!({
            "status": "held",
            "resource": resource,
            "holder_passport": holder,
            "expires_at_unix_ms": expires,
        })
    }

    // ── Resource overlap (file:// ⊂ tree://) ─────────────────────────────

    #[test]
    fn identical_resources_overlap() {
        assert!(resources_overlap("file:///a/b.rs", "file:///a/b.rs"));
    }

    #[test]
    fn distinct_files_do_not_overlap() {
        assert!(!resources_overlap("file:///a/b.rs", "file:///a/c.rs"));
    }

    #[test]
    fn tree_lease_covers_contained_file() {
        assert!(resources_overlap("tree:///a/b", "file:///a/b/c.rs"));
        assert!(resources_overlap("tree:///a/b", "file:///a/b/deep/c.rs"));
    }

    #[test]
    fn tree_lease_does_not_cover_sibling_prefix() {
        // `a/bc` must not be treated as under `a/b` (segment boundary).
        assert!(!resources_overlap("tree:///a/b", "file:///a/bc.rs"));
    }

    #[test]
    fn requesting_enclosing_tree_conflicts_with_leaf_lease() {
        // Existing leaf lease, request for the enclosing subtree.
        assert!(resources_overlap("file:///a/b/c.rs", "tree:///a/b"));
    }

    #[test]
    fn unrelated_trees_do_not_overlap() {
        assert!(!resources_overlap("tree:///a/b", "tree:///x/y"));
    }

    #[test]
    fn service_resources_match_only_on_equality() {
        assert!(resources_overlap("service://gpu1", "service://gpu1"));
        assert!(!resources_overlap("service://gpu1", "service://data1"));
    }

    // ── deploy:// (point-exclusive: exact host+path only) ────────────────

    #[test]
    fn deploy_resources_conflict_on_exact_host_and_path() {
        assert!(resources_overlap(
            "deploy://crux/opt/crux/bin",
            "deploy://crux/opt/crux/bin"
        ));
    }

    #[test]
    fn deploy_resources_differ_on_path() {
        // Same host, different path → no conflict (point-exclusive).
        assert!(!resources_overlap(
            "deploy://crux/opt/crux/bin",
            "deploy://crux/opt/crux/other"
        ));
    }

    #[test]
    fn deploy_resources_differ_on_host() {
        assert!(!resources_overlap("deploy://crux/path", "deploy://data1/path"));
    }

    #[test]
    fn deploy_is_not_prefix_based_unlike_tree() {
        // A deploy lease on a "parent" path must NOT cover a deeper path the way
        // a tree:// lease would. Deploy targets are atomic, not subtrees.
        assert!(!resources_overlap(
            "deploy://crux/opt/crux",
            "deploy://crux/opt/crux/bin"
        ));
        // And a tree:// request must not swallow a deploy:// leaf lease.
        assert!(!resources_overlap("deploy://crux/opt/crux/bin", "tree:///opt/crux"));
        assert!(!resources_overlap("tree:///opt/crux", "deploy://crux/opt/crux/bin"));
    }

    #[test]
    fn path_contains_respects_segment_boundary() {
        assert!(path_contains("/a/b", "/a/b/c"));
        assert!(path_contains("/a/b", "/a/b"));
        assert!(!path_contains("/a/b", "/a/bc"));
        assert!(!path_contains("/a/b/c", "/a/b"));
    }

    // ── Expiry / active classification ──────────────────────────────────

    #[test]
    fn expired_held_card_is_detected() {
        let p = held("file:///x", "A", 1_000);
        assert!(is_expired_held(&p, 2_000));
        assert!(!is_expired_held(&p, 500));
    }

    #[test]
    fn released_card_is_never_expired_or_active() {
        let p =
            json!({"status": "released", "resource": "file:///x", "holder_passport": "A", "expires_at_unix_ms": 1_000});
        assert!(!is_expired_held(&p, 2_000));
        assert!(!is_active_held(&p, 500));
    }

    #[test]
    fn active_held_card_within_ttl() {
        let p = held("file:///x", "A", 5_000);
        assert!(is_active_held(&p, 1_000));
        assert!(!is_active_held(&p, 6_000)); // past expiry → not active
    }

    #[test]
    fn ttl_is_clamped() {
        assert_eq!(resolve_ttl_secs(None), DEFAULT_TTL_SECS);
        assert_eq!(resolve_ttl_secs(Some(0)), 1);
        assert_eq!(resolve_ttl_secs(Some(10)), 10);
        assert_eq!(resolve_ttl_secs(Some(MAX_TTL_SECS + 100)), MAX_TTL_SECS);
    }

    #[test]
    fn split_resource_parses_scheme() {
        assert_eq!(split_resource("file:///a/b"), ("file", "/a/b"));
        assert_eq!(split_resource("tree://sub"), ("tree", "sub"));
        assert_eq!(split_resource("bare"), ("", "bare"));
    }

    // ── Handler-level FSM integration (serial: mutate process env gate) ──

    use crate::http::tests::test_app_state;
    use axum::body::to_bytes;
    use axum::extract::{Json as JsonExtract, Path as PathExtract, Query as QueryExtract, State as StateExtract};

    async fn acquire(
        StateExtract(state): StateExtract<AppState>,
        headers: HeaderMap,
        JsonExtract(body): JsonExtract<AcquireBody>,
    ) -> Response {
        acquire_with_peer(state, Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)), headers, body).await
    }

    async fn release(
        StateExtract(state): StateExtract<AppState>,
        headers: HeaderMap,
        JsonExtract(body): JsonExtract<ReleaseBody>,
    ) -> Response {
        release_with_peer(state, Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)), headers, body).await
    }

    async fn check(
        StateExtract(state): StateExtract<AppState>,
        headers: HeaderMap,
        JsonExtract(body): JsonExtract<CheckBody>,
    ) -> Response {
        check_with_peer(state, Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)), headers, body).await
    }

    /// Register the punchcard kind so upserts validate against the schema.
    async fn state_with_kind() -> AppState {
        let state = test_app_state(1);
        {
            let mut reg = state.kind_registry.write().await;
            crate::agentgraph_kinds::bootstrap(&mut reg).expect("bootstrap kinds");
        }
        state
    }

    /// Drain a handler [`Response`] body into a JSON value.
    async fn body_json(resp: Response) -> Value {
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("read body");
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    fn headers_for(passport: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            "x-corecrux-passport-id",
            axum::http::HeaderValue::from_str(passport).unwrap(),
        );
        h
    }

    fn dev_headers_for(scopes: &str, passport: &str) -> HeaderMap {
        let mut h = headers_for(passport);
        h.insert("x-corecrux-scopes", axum::http::HeaderValue::from_str(scopes).unwrap());
        h
    }

    const JWT_SECRET: &[u8] = b"punchcard-test-secret-at-least-32-bytes";
    const JWT_ISSUER: &str = "punchcard-tests";
    const JWT_AUDIENCE: &str = "corecrux";

    fn jwt_headers(scopes: &str, passport_id: Option<&str>, subject: Option<&str>) -> HeaderMap {
        jwt_headers_for_tenant(scopes, passport_id, subject, "default")
    }

    fn jwt_headers_for_tenant(
        scopes: &str,
        passport_id: Option<&str>,
        subject: Option<&str>,
        tenant_id: &str,
    ) -> HeaderMap {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs()
            .saturating_add(3_600);
        let mut claims = json!({
            "exp": exp,
            "iss": JWT_ISSUER,
            "aud": JWT_AUDIENCE,
            "scope": scopes,
            "tenant_id": tenant_id,
        });
        if let Some(passport_id) = passport_id {
            claims["passport_id"] = json!(passport_id);
        }
        if let Some(subject) = subject {
            claims["sub"] = json!(subject);
        }
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(JWT_SECRET),
        )
        .expect("test JWT");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(&format!("Bearer {token}")).expect("bearer"),
        );
        headers
    }

    fn local_actor(passport: &str) -> String {
        format!(
            "{}{passport}",
            super::super::approval_receipts::UNVERIFIED_APPROVER_PREFIX
        )
    }

    fn acquire_body(resource: &str, ttl_secs: u64) -> AcquireBody {
        AcquireBody {
            resource: resource.to_string(),
            mode: "modify".to_string(),
            reason: Some("test".to_string()),
            ttl_secs: Some(ttl_secs),
            tenant_id: None,
            holder_passport: None,
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn gate_off_returns_501() {
        std::env::remove_var("CORECRUXD_PUNCHCARD");
        let state = state_with_kind().await;
        let resp = acquire(
            StateExtract(state),
            headers_for("A"),
            JsonExtract(acquire_body("file:///x.rs", 60)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn holder_body_spoof_is_denied_in_authenticated_mode() {
        std::env::set_var("CORECRUXD_PUNCHCARD", "enforce");
        let mut state = state_with_kind().await;
        state.auth = crate::auth::Authz::from_env(crate::auth::AuthMode::DevScopes).expect("dev auth");
        let mut body = acquire_body("file:///spoof.rs", 60);
        body.holder_passport = Some("passport-b".to_string());

        let resp = acquire(
            StateExtract(state),
            dev_headers_for("facts:write", "passport-a"),
            JsonExtract(body),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn lifecycle_held_conflict_reentrant_release() {
        std::env::set_var("CORECRUXD_PUNCHCARD", "enforce");
        let state = state_with_kind().await;

        // A acquires file://X → 201 held.
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(acquire_body("file:///proj/x.rs", 600)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let card = body_json(resp).await;
        assert_eq!(card["punchcard"]["status"], "held");
        assert_eq!(card["punchcard"]["holder_passport"], local_actor("A"));
        let card_id = card["punchcard"]["id"].as_str().unwrap().to_string();

        let version_before = state
            .entity_store
            .read()
            .await
            .get(PUNCHCARD_KIND, &card_id)
            .expect("held card")
            .version;
        let resp = release(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(ReleaseBody {
                id: Some(card_id.clone()),
                resource: None,
                release_commit_sha: Some("attacker".to_string()),
                holder_passport: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let store = state.entity_store.read().await;
        let unchanged = store.get(PUNCHCARD_KIND, &card_id).expect("held card remains");
        assert_eq!(unchanged.version, version_before);
        assert_eq!(unchanged.payload["status"], "held");
        drop(store);

        // B acquires the same file → 409 conflict naming A.
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(acquire_body("file:///proj/x.rs", 600)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = body_json(resp).await;
        assert_eq!(body["held_by"], local_actor("A"));
        assert_eq!(body["punchcard_id"], card_id);

        // A re-acquires (reentrant) → 200, refreshes TTL.
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(acquire_body("file:///proj/x.rs", 1200)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["reentrant"], true);
        assert_eq!(body["punchcard"]["id"], card_id);

        // A releases → 200 released.
        let resp = release(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(ReleaseBody {
                id: None,
                resource: Some("file:///proj/x.rs".to_string()),
                release_commit_sha: Some("deadbeef".to_string()),
                holder_passport: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["punchcard"]["status"], "released");
        assert_eq!(body["punchcard"]["release_commit_sha"], "deadbeef");

        let resp = release(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(ReleaseBody {
                id: Some(card_id.clone()),
                resource: None,
                release_commit_sha: None,
                holder_passport: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // B can now acquire the freed resource → 201.
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(acquire_body("file:///proj/x.rs", 600)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn reentrant_card_cannot_hide_a_peer_conflict_after_enforce_cutover() {
        std::env::set_var("CORECRUXD_PUNCHCARD", "advisory");
        let state = state_with_kind().await;
        let resource = "file:///proj/advisory-overlap.rs";

        let a = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(acquire_body(resource, 600)),
        )
        .await;
        let a_id = body_json(a).await["punchcard"]["id"]
            .as_str()
            .expect("A card id")
            .to_string();
        let b = acquire(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(acquire_body(resource, 600)),
        )
        .await;
        assert_eq!(b.status(), StatusCode::CREATED);
        assert!(body_json(b).await["advisory_conflict"].is_object());

        let a_refresh = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(acquire_body(resource, 1_200)),
        )
        .await;
        assert_eq!(a_refresh.status(), StatusCode::OK);
        let a_refresh = body_json(a_refresh).await;
        assert_eq!(a_refresh["reentrant"], true);
        assert!(
            a_refresh["advisory_conflict"].is_object(),
            "a reentrant advisory grant must surface the peer conflict"
        );
        let version_before_enforce = state
            .entity_store
            .read()
            .await
            .get(PUNCHCARD_KIND, &a_id)
            .expect("A card")
            .version;

        std::env::set_var("CORECRUXD_PUNCHCARD", "enforce");
        let denied = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(acquire_body(resource, 1_800)),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::CONFLICT);
        assert_eq!(
            state
                .entity_store
                .read()
                .await
                .get(PUNCHCARD_KIND, &a_id)
                .expect("A card remains")
                .version,
            version_before_enforce,
            "denied reentrant acquire must not refresh or mutate the lease"
        );
        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn check_reports_held_by_other_then_freed() {
        std::env::set_var("CORECRUXD_PUNCHCARD", "enforce");
        let state = state_with_kind().await;

        // A acquires file://Y.
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(acquire_body("file:///proj/y.rs", 600)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        // check for passport B → held_by_other:true, enforce:true.
        let resp = check(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(CheckBody {
                resource: "file:///proj/y.rs".to_string(),
                mode: "modify".to_string(),
                passport: Some("B".to_string()),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["held_by_other"], true);
        assert_eq!(body["enforce"], true);
        assert_eq!(body["holder_passport"], local_actor("A"));

        // check for the holder A itself → not held_by_other.
        let resp = check(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(CheckBody {
                resource: "file:///proj/y.rs".to_string(),
                mode: "modify".to_string(),
                passport: Some("A".to_string()),
            }),
        )
        .await;
        let body = body_json(resp).await;
        assert_eq!(body["held_by_other"], false);

        // A releases → check for B now free.
        let _ = release(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(ReleaseBody {
                id: None,
                resource: Some("file:///proj/y.rs".to_string()),
                release_commit_sha: None,
                holder_passport: None,
            }),
        )
        .await;
        let resp = check(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(CheckBody {
                resource: "file:///proj/y.rs".to_string(),
                mode: "modify".to_string(),
                passport: Some("B".to_string()),
            }),
        )
        .await;
        let body = body_json(resp).await;
        assert_eq!(body["held_by_other"], false);

        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn expired_card_is_swept_and_frees_resource() {
        std::env::set_var("CORECRUXD_PUNCHCARD", "enforce");
        let state = state_with_kind().await;

        // A acquires with a 1-second TTL.
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(acquire_body("file:///proj/z.rs", 1)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let card_id = body_json(resp).await["punchcard"]["id"].as_str().unwrap().to_string();

        // Force the stored card's expiry into the past (simulate a crashed
        // holder whose TTL elapsed) without sleeping.
        {
            let registry = state.kind_registry.read().await;
            let reg_opt = registry.is_registered(PUNCHCARD_KIND).then_some(&*registry);
            let mut store = state.entity_store.write().await;
            let mut payload = store.get(PUNCHCARD_KIND, &card_id).unwrap().payload.clone();
            payload
                .as_object_mut()
                .unwrap()
                .insert("expires_at_unix_ms".to_string(), json!(now_unix_ms() - 10_000));
            store.upsert(PUNCHCARD_KIND, &card_id, payload, "A", reg_opt).unwrap();
        }

        // B acquires the same resource: the sweep flips A's card to expired,
        // so B gets the lease (deadlock recovery).
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(acquire_body("file:///proj/z.rs", 600)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        // A's original card is now `expired`.
        {
            let store = state.entity_store.read().await;
            let a_card = store.get(PUNCHCARD_KIND, &card_id).unwrap();
            assert_eq!(a_card.payload["status"], "expired");
        }

        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn acquire_rejects_body_holder_that_differs_from_request_identity() {
        std::env::set_var("CORECRUXD_PUNCHCARD", "advisory");
        let state = state_with_kind().await;

        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("anonymous"), // header actor says "anonymous"
            JsonExtract(AcquireBody {
                resource: "file:///proj/h.rs".to_string(),
                mode: "modify".to_string(),
                reason: None,
                ttl_secs: Some(600),
                tenant_id: None,
                holder_passport: Some("ce:probe:local".to_string()),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let store = state.entity_store.read().await;
        assert!(
            store
                .list(&corecrux_memory::EntityQuery {
                    kind: Some(PUNCHCARD_KIND.to_string()),
                    limit: None,
                    include_deleted: false,
                })
                .is_empty(),
            "spoofed holder must not create a lease"
        );

        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn local_unverified_authority_is_denied_on_non_loopback_or_forwarded_ingress() {
        std::env::set_var("CORECRUXD_PUNCHCARD", "enforce");
        let mut state = state_with_kind().await;
        state.http_bind_loopback = false;
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(acquire_body("file:///remote.rs", 60)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        state.http_bind_loopback = true;
        let mut forwarded = headers_for("A");
        forwarded.insert("x-forwarded-for", "203.0.113.4".parse().expect("header"));
        let resp = acquire(
            StateExtract(state),
            forwarded,
            JsonExtract(acquire_body("file:///proxied.rs", 60)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn local_unverified_authority_requires_a_loopback_socket_peer() {
        std::env::set_var("CORECRUXD_PUNCHCARD", "enforce");
        let state = state_with_kind().await;

        let resp = acquire_with_peer(
            state.clone(),
            Some(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 9))),
            headers_for("A"),
            acquire_body("file:///proxied-without-forwarded.rs", 60),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let resp = acquire_with_peer(
            state,
            Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            headers_for("A"),
            acquire_body("file:///direct-loopback.rs", 60),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn tree_lease_blocks_contained_file() {
        std::env::set_var("CORECRUXD_PUNCHCARD", "enforce");
        let state = state_with_kind().await;

        // A acquires a subtree lease.
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(acquire_body("tree:///proj/src", 600)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        // B tries to acquire a file inside the subtree → 409.
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(acquire_body("file:///proj/src/main.rs", 600)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // check confirms the conflict for B.
        let resp = check(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(CheckBody {
                resource: "file:///proj/src/main.rs".to_string(),
                mode: "modify".to_string(),
                passport: Some("B".to_string()),
            }),
        )
        .await;
        let body = body_json(resp).await;
        assert_eq!(body["held_by_other"], true);
        assert_eq!(body["holder_passport"], local_actor("A"));

        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn service_card_lifecycle() {
        std::env::set_var("CORECRUXD_PUNCHCARD", "enforce");
        let state = state_with_kind().await;

        // A acquires a service lease (deploy target).
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(AcquireBody {
                resource: "service://corecrux-gpu-1".to_string(),
                mode: "deploy".to_string(),
                reason: Some("cargo-deploy".to_string()),
                ttl_secs: Some(600),
                tenant_id: None,
                holder_passport: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        // B's check on the same service → held_by_other.
        let resp = check(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(CheckBody {
                resource: "service://corecrux-gpu-1".to_string(),
                mode: "deploy".to_string(),
                passport: Some("B".to_string()),
            }),
        )
        .await;
        let body = body_json(resp).await;
        assert_eq!(body["held_by_other"], true);

        // A different service is unaffected.
        let resp = check(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(CheckBody {
                resource: "service://cuecrux-data-1".to_string(),
                mode: "deploy".to_string(),
                passport: Some("B".to_string()),
            }),
        )
        .await;
        let body = body_json(resp).await;
        assert_eq!(body["held_by_other"], false);

        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn deploy_card_lifecycle_enforce() {
        // A deploy lease is point-exclusive under enforce: a second holder on
        // the SAME host+path is rejected (409); a DIFFERENT path on the same
        // host is unaffected; releasing frees the resource for the next holder.
        std::env::set_var("CORECRUXD_PUNCHCARD", "enforce");
        let state = state_with_kind().await;

        // A acquires a deploy lease (host+path point).
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(AcquireBody {
                resource: "deploy://crux/opt/crux/bin".to_string(),
                mode: "deploy".to_string(),
                reason: Some("release-train v0.5.22".to_string()),
                ttl_secs: Some(600),
                tenant_id: None,
                holder_passport: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let card = body_json(resp).await;
        assert_eq!(card["punchcard"]["status"], "held");
        assert_eq!(card["punchcard"]["resource"], "deploy://crux/opt/crux/bin");

        // B acquires the EXACT same deploy target → 409 conflict naming A.
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(AcquireBody {
                resource: "deploy://crux/opt/crux/bin".to_string(),
                mode: "deploy".to_string(),
                reason: None,
                ttl_secs: Some(600),
                tenant_id: None,
                holder_passport: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        assert_eq!(body_json(resp).await["held_by"], local_actor("A"));

        // B acquires a DIFFERENT path on the same host → 201 (point-exclusive,
        // not prefix-based).
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(AcquireBody {
                resource: "deploy://crux/opt/crux/other".to_string(),
                mode: "deploy".to_string(),
                reason: None,
                ttl_secs: Some(600),
                tenant_id: None,
                holder_passport: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        // check for B on A's target → held_by_other:true under enforce.
        let resp = check(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(CheckBody {
                resource: "deploy://crux/opt/crux/bin".to_string(),
                mode: "deploy".to_string(),
                passport: Some("B".to_string()),
            }),
        )
        .await;
        let body = body_json(resp).await;
        assert_eq!(body["held_by_other"], true);
        assert_eq!(body["enforce"], true);
        assert_eq!(body["holder_passport"], local_actor("A"));

        // A releases its deploy target.
        let resp = release(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(ReleaseBody {
                id: None,
                resource: Some("deploy://crux/opt/crux/bin".to_string()),
                release_commit_sha: Some("d432319".to_string()),
                holder_passport: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(body_json(resp).await["punchcard"]["status"], "released");

        // B can now acquire the freed deploy target → 201.
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(AcquireBody {
                resource: "deploy://crux/opt/crux/bin".to_string(),
                mode: "deploy".to_string(),
                reason: None,
                ttl_secs: Some(600),
                tenant_id: None,
                holder_passport: None,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn force_release_requires_issuer_verified_canonical_admin_and_confirm() {
        std::env::set_var("CORECRUXD_PUNCHCARD", "enforce");
        let mut state = state_with_kind().await;

        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(acquire_body("file:///proj/f.rs", 600)),
        )
        .await;
        let card_id = body_json(resp).await["punchcard"]["id"].as_str().unwrap().to_string();
        state.auth = crate::auth::Authz::test_hs256(JWT_SECRET, JWT_ISSUER, JWT_AUDIENCE);

        // force-release without confirm → 400.
        let resp = force_release(
            StateExtract(state.clone()),
            PathExtract(card_id.clone()),
            jwt_headers("admin:write", Some("operator"), Some("operator-sub")),
            JsonExtract(ForceReleaseBody {
                confirm: false,
                reason: Some("holder offline".to_string()),
                by_passport: Some("operator".to_string()),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // A facts writer, a sub-only admin, and a spoofed actor are all denied.
        for (headers, claimed) in [
            (
                jwt_headers("facts:write", Some("operator"), Some("operator-sub")),
                Some("operator"),
            ),
            (
                jwt_headers("admin:write", None, Some("operator-sub")),
                Some("operator-sub"),
            ),
            (
                jwt_headers("admin:write", Some("operator"), Some("operator-sub")),
                Some("someone-else"),
            ),
        ] {
            let resp = force_release(
                StateExtract(state.clone()),
                PathExtract(card_id.clone()),
                headers,
                JsonExtract(ForceReleaseBody {
                    confirm: true,
                    reason: Some("holder offline".to_string()),
                    by_passport: claimed.map(str::to_string),
                }),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }

        // An issuer-verified canonical passport admin can force-release with confirmation.
        let resp = force_release(
            StateExtract(state.clone()),
            PathExtract(card_id.clone()),
            jwt_headers("admin:write", Some("operator"), Some("operator-sub")),
            JsonExtract(ForceReleaseBody {
                confirm: true,
                reason: Some("holder offline".to_string()),
                by_passport: Some("operator".to_string()),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["punchcard"]["status"], "force_released");
        assert_eq!(body["punchcard"]["force_released_by"], "operator");

        let resp = force_release(
            StateExtract(state.clone()),
            PathExtract(card_id),
            jwt_headers("admin:write", Some("operator"), Some("operator-sub")),
            JsonExtract(ForceReleaseBody {
                confirm: true,
                reason: None,
                by_passport: Some("operator".to_string()),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn force_release_authorizes_target_tenant_before_revealing_status() {
        std::env::set_var("CORECRUXD_PUNCHCARD", "enforce");
        let mut state = state_with_kind().await;

        let held = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(acquire_body("file:///tenant-b/held.rs", 600)),
        )
        .await;
        let held_id = body_json(held).await["punchcard"]["id"]
            .as_str()
            .expect("held id")
            .to_string();
        let terminal = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(acquire_body("file:///tenant-b/released.rs", 600)),
        )
        .await;
        let terminal_id = body_json(terminal).await["punchcard"]["id"]
            .as_str()
            .expect("terminal id")
            .to_string();

        let registry = state.kind_registry.read().await;
        let registry_opt = registry.is_registered(PUNCHCARD_KIND).then_some(&*registry);
        let mut store = state.entity_store.write().await;
        for (id, status) in [(&held_id, "held"), (&terminal_id, "released")] {
            let mut payload = store.get(PUNCHCARD_KIND, id).expect("seeded punchcard").payload.clone();
            payload["tenant_id"] = json!("tenant-b");
            payload["status"] = json!(status);
            store
                .upsert(PUNCHCARD_KIND, id, payload, "fixture", registry_opt)
                .expect("move fixture to tenant-b");
        }
        let held_version = store.get(PUNCHCARD_KIND, &held_id).expect("held fixture").version;
        let terminal_version = store
            .get(PUNCHCARD_KIND, &terminal_id)
            .expect("terminal fixture")
            .version;
        drop(store);
        drop(registry);

        state.auth = crate::auth::Authz::test_hs256(JWT_SECRET, JWT_ISSUER, JWT_AUDIENCE);
        for id in [&held_id, &terminal_id] {
            let response = force_release(
                StateExtract(state.clone()),
                PathExtract(id.to_string()),
                jwt_headers("admin:write", Some("operator"), Some("operator-sub")),
                JsonExtract(ForceReleaseBody {
                    confirm: true,
                    reason: Some("cross-tenant probe".to_string()),
                    by_passport: Some("operator".to_string()),
                }),
            )
            .await;
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "held and terminal cross-tenant cards must have the same denial"
            );
        }
        let store = state.entity_store.read().await;
        assert_eq!(
            store
                .get(PUNCHCARD_KIND, &held_id)
                .expect("held fixture remains")
                .version,
            held_version
        );
        assert_eq!(
            store
                .get(PUNCHCARD_KIND, &terminal_id)
                .expect("terminal fixture remains")
                .version,
            terminal_version
        );

        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn reads_never_consult_leases() {
        // The lease surface only governs acquire/release/check/force-release.
        // A held lease must NOT appear as a conflict to a same-holder probe,
        // and `list` is a pure read that never mutates lease state. This test
        // asserts that listing held cards leaves their status untouched.
        std::env::set_var("CORECRUXD_PUNCHCARD", "advisory");
        let state = state_with_kind().await;

        let _ = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(acquire_body("file:///proj/r.rs", 600)),
        )
        .await;

        let resp = list_punchcards(
            StateExtract(state.clone()),
            QueryExtract(ListPunchcardsQuery {
                resource: None,
                holder: None,
                holder_passport: None,
                status: Some("held".to_string()),
                tenant_id: None,
            }),
            headers_for("anyone"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["count"], 1);
        assert_eq!(body["punchcards"][0]["status"], "held");

        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn cross_tenant_lease_isolation_via_filter() {
        // T.1: a list filtered by tenant must not surface another tenant's
        // cards. Acquire under two tenants and confirm the filter isolates.
        std::env::set_var("CORECRUXD_PUNCHCARD", "advisory");
        let state = state_with_kind().await;

        let _ = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(AcquireBody {
                resource: "file:///t1/x.rs".to_string(),
                mode: "modify".to_string(),
                reason: None,
                ttl_secs: Some(600),
                tenant_id: Some("tenant-1".to_string()),
                holder_passport: None,
            }),
        )
        .await;
        let _ = acquire(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(AcquireBody {
                resource: "file:///t2/y.rs".to_string(),
                mode: "modify".to_string(),
                reason: None,
                ttl_secs: Some(600),
                tenant_id: Some("tenant-2".to_string()),
                holder_passport: None,
            }),
        )
        .await;

        let resp = list_punchcards(
            StateExtract(state.clone()),
            QueryExtract(ListPunchcardsQuery {
                resource: None,
                holder: None,
                holder_passport: None,
                status: None,
                tenant_id: Some("tenant-1".to_string()),
            }),
            headers_for("anyone"),
        )
        .await;
        let body = body_json(resp).await;
        assert_eq!(body["count"], 1);
        assert_eq!(body["punchcards"][0]["tenant_id"], "tenant-1");

        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn jwt_tenant_cannot_acquire_list_check_or_release_another_tenants_lease() {
        std::env::set_var("CORECRUXD_PUNCHCARD", "enforce");
        let mut state = state_with_kind().await;
        state.auth = crate::auth::Authz::test_hs256(JWT_SECRET, JWT_ISSUER, JWT_AUDIENCE);
        let resource = "file:///shared/path.rs";

        let tenant_b = acquire(
            StateExtract(state.clone()),
            jwt_headers_for_tenant("facts:write", Some("passport-b"), Some("subject-b"), "tenant-b"),
            JsonExtract(AcquireBody {
                resource: resource.to_string(),
                mode: "modify".to_string(),
                reason: None,
                ttl_secs: Some(600),
                tenant_id: Some("tenant-b".to_string()),
                holder_passport: None,
            }),
        )
        .await;
        assert_eq!(tenant_b.status(), StatusCode::CREATED);
        let tenant_b_id = body_json(tenant_b).await["punchcard"]["id"]
            .as_str()
            .expect("tenant B id")
            .to_string();
        let tenant_b_version = state
            .entity_store
            .read()
            .await
            .get(PUNCHCARD_KIND, &tenant_b_id)
            .expect("tenant B lease")
            .version;

        let denied_acquire = acquire(
            StateExtract(state.clone()),
            jwt_headers_for_tenant("facts:write", Some("passport-a"), Some("subject-a"), "tenant-a"),
            JsonExtract(AcquireBody {
                resource: resource.to_string(),
                mode: "modify".to_string(),
                reason: None,
                ttl_secs: Some(600),
                tenant_id: Some("tenant-b".to_string()),
                holder_passport: None,
            }),
        )
        .await;
        assert_eq!(denied_acquire.status(), StatusCode::FORBIDDEN);

        let denied_list = list_punchcards(
            StateExtract(state.clone()),
            QueryExtract(ListPunchcardsQuery {
                resource: None,
                holder: None,
                holder_passport: None,
                status: None,
                tenant_id: Some("tenant-b".to_string()),
            }),
            jwt_headers_for_tenant("facts:read", Some("passport-a"), Some("subject-a"), "tenant-a"),
        )
        .await;
        assert_eq!(denied_list.status(), StatusCode::FORBIDDEN);

        let isolated_check = check_with_peer(
            state.clone(),
            Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            jwt_headers_for_tenant("facts:read", Some("passport-a"), Some("subject-a"), "tenant-a"),
            CheckBody {
                resource: resource.to_string(),
                mode: "modify".to_string(),
                passport: None,
            },
        )
        .await;
        assert_eq!(isolated_check.status(), StatusCode::OK);
        assert_eq!(body_json(isolated_check).await["held_by_other"], false);

        let denied_release = release_with_peer(
            state.clone(),
            Some(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            jwt_headers_for_tenant("facts:write", Some("passport-a"), Some("subject-a"), "tenant-a"),
            ReleaseBody {
                id: Some(tenant_b_id.clone()),
                resource: None,
                release_commit_sha: None,
                holder_passport: None,
            },
        )
        .await;
        assert_eq!(denied_release.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            state
                .entity_store
                .read()
                .await
                .get(PUNCHCARD_KIND, &tenant_b_id)
                .expect("tenant B lease remains")
                .version,
            tenant_b_version
        );

        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn subject_only_jwt_cannot_collide_with_same_spelled_canonical_passport() {
        std::env::set_var("CORECRUXD_PUNCHCARD", "enforce");
        let mut state = state_with_kind().await;
        state.auth = crate::auth::Authz::test_hs256(JWT_SECRET, JWT_ISSUER, JWT_AUDIENCE);
        let canonical = acquire(
            StateExtract(state.clone()),
            jwt_headers("facts:write", Some("alice"), Some("alice-subject")),
            JsonExtract(acquire_body("file:///canonical-alice.rs", 600)),
        )
        .await;
        assert_eq!(canonical.status(), StatusCode::CREATED);
        let canonical_id = body_json(canonical).await["punchcard"]["id"]
            .as_str()
            .expect("canonical id")
            .to_string();

        let subject_release = release(
            StateExtract(state.clone()),
            jwt_headers("facts:write", None, Some("alice")),
            JsonExtract(ReleaseBody {
                id: Some(canonical_id),
                resource: None,
                release_commit_sha: None,
                holder_passport: None,
            }),
        )
        .await;
        assert_eq!(subject_release.status(), StatusCode::FORBIDDEN);

        let subject_reentrant = acquire(
            StateExtract(state.clone()),
            jwt_headers("facts:write", None, Some("alice")),
            JsonExtract(acquire_body("file:///canonical-alice.rs", 1_200)),
        )
        .await;
        assert_eq!(subject_reentrant.status(), StatusCode::CONFLICT);

        let subject_owned = acquire(
            StateExtract(state),
            jwt_headers("facts:write", None, Some("alice")),
            JsonExtract(acquire_body("file:///subject-alice.rs", 600)),
        )
        .await;
        assert_eq!(subject_owned.status(), StatusCode::CREATED);
        assert_eq!(
            body_json(subject_owned).await["punchcard"]["holder_passport"],
            "principal:alice"
        );
        std::env::remove_var("CORECRUXD_PUNCHCARD");
    }
}
