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

use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use super::{
    problem_response, require_http_any_scope, AppState, HeaderMap, IntoResponse, Json, Query, Response, State,
    StatusCode,
};
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
    /// bound request passport unless the caller has an override scope.
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

fn actor(state: &AppState, headers: &HeaderMap) -> String {
    crate::auth::http_scope_context(&state.auth, headers)
        .ok()
        .and_then(|ctx| ctx.passport_id)
        .unwrap_or_else(|| "anonymous".into())
}

fn requested_passport(value: Option<&String>) -> Option<String> {
    value.map(|s| s.trim()).filter(|s| !s.is_empty()).map(str::to_string)
}

#[allow(clippy::result_large_err)]
fn resolve_holder_passport(
    state: &AppState,
    headers: &HeaderMap,
    requested: Option<&String>,
    override_scopes: &[&str],
) -> Result<String, Response> {
    let actual = actor(state, headers);
    let Some(requested) = requested_passport(requested) else {
        return Ok(actual);
    };
    if requested == actual || state.auth.mode() == crate::auth::AuthMode::Off {
        return Ok(requested);
    }
    require_http_any_scope(&state.auth, headers, override_scopes)
        .map(|()| requested)
        .map_err(IntoResponse::into_response)
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
    headers: HeaderMap,
    Json(body): Json<AcquireBody>,
) -> Response {
    if let Some(p) = gate_disabled() {
        return p;
    }
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:write", "admin:write"]) {
        return p.into_response();
    }
    if body.resource.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "resource must not be empty");
    }
    let holder = match resolve_holder_passport(
        &state,
        &headers,
        body.holder_passport.as_ref(),
        &["admin:write", "passport:impersonate"],
    ) {
        Ok(holder) => holder,
        Err(response) => return response,
    };

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
        if card_resource == body.resource && card_holder == holder {
            reentrant_id = Some(rec.id.clone());
            break;
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
    let tenant_id = body.tenant_id.clone().unwrap_or_else(|| "default".to_string());

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
                (
                    StatusCode::OK,
                    Json(json!({"punchcard": rec.payload, "reentrant": true})),
                )
                    .into_response()
            }
            Err(e) => problem_response(StatusCode::BAD_REQUEST, e.to_string()),
        };
    }

    // Set when a peer already holds this resource and advisory mode granted
    // anyway. Carried on the 201 so the caller can warn its operator.
    let mut advisory_conflict: Option<serde_json::Value> = None;

    // Conflict by a different holder → 409 with current holder + expiry.
    // Advisory mode reports the conflict but still grants (writers are never
    // denied); Enforce mode rejects with 409.
    if let Some((conflict_id, conflict_holder, conflict_expires)) = conflict {
        if punchcard_mode() == PunchcardMode::Enforce {
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
        // Advisory: fall through and grant a (possibly overlapping) lease — but
        // SAY SO. Advisory previously granted in silence, which meant a caller
        // could not distinguish "nobody else is here" from "someone is, and we
        // let you in anyway". A warning nobody receives is not advisory, it is
        // absent, so the grant carries the conflict for the caller to surface.
        advisory_conflict = Some(json!({
            "held_by": conflict_holder,
            "punchcard_id": conflict_id,
            "expires_at_unix_ms": conflict_expires,
        }));
    }

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
    headers: HeaderMap,
    Json(body): Json<ReleaseBody>,
) -> Response {
    if let Some(p) = gate_disabled() {
        return p;
    }
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:write", "admin:write"]) {
        return p.into_response();
    }
    let holder = match resolve_holder_passport(
        &state,
        &headers,
        body.holder_passport.as_ref(),
        &["admin:write", "passport:impersonate"],
    ) {
        Ok(holder) => holder,
        Err(response) => return response,
    };
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
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
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
                && q.tenant_id
                    .as_ref()
                    .is_none_or(|t| payload_str(&rec.payload, "tenant_id").as_deref() == Some(t.as_str()))
        })
        .map(|rec| rec.payload.clone())
        .collect();
    let count = punchcards.len();
    (StatusCode::OK, Json(json!({"punchcards": punchcards, "count": count}))).into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn check(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<CheckBody>) -> Response {
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
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
    // Sweep so an expired holder doesn't show as a live conflict.
    sweep_expired(&state).await;

    let probe = match resolve_holder_passport(
        &state,
        &headers,
        body.passport.as_ref(),
        &["admin:read", "admin:write", "passport:impersonate"],
    ) {
        Ok(passport) => passport,
        Err(response) => return response,
    };
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
        if card_holder != probe && resources_overlap(&card_resource, &body.resource) {
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
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:write", "admin:write"]) {
        return p.into_response();
    }
    // Destructive override (Art.14): require explicit confirmation in-body.
    if !body.confirm {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "force-release is destructive; resubmit with {\"confirm\": true}",
        );
    }
    let by = match resolve_holder_passport(
        &state,
        &headers,
        body.by_passport.as_ref(),
        &["admin:write", "passport:impersonate"],
    ) {
        Ok(passport) => passport,
        Err(response) => return response,
    };
    let now = now_unix_ms();
    let registry = state.kind_registry.read().await;
    let registry_opt = registry.is_registered(PUNCHCARD_KIND).then_some(&*registry);
    let mut store = state.entity_store.write().await;
    let mut payload = match store.get(PUNCHCARD_KIND, &id) {
        Some(rec) => rec.payload.clone(),
        None => return problem_response(StatusCode::NOT_FOUND, format!("punchcard {id} not found")),
    };
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
    async fn holder_body_override_requires_override_scope_in_authenticated_mode() {
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
        assert_eq!(card["punchcard"]["holder_passport"], "A");
        let card_id = card["punchcard"]["id"].as_str().unwrap().to_string();

        // B acquires the same file → 409 conflict naming A.
        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("B"),
            JsonExtract(acquire_body("file:///proj/x.rs", 600)),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body = body_json(resp).await;
        assert_eq!(body["held_by"], "A");
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
        assert_eq!(body["holder_passport"], "A");

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
    async fn acquire_prefers_body_holder_passport_over_header() {
        // Probe finding 4: punch_in's explicit holder_passport must win, so the
        // lease records the real passport instead of the header/anonymous actor.
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
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_json(resp).await;
        assert_eq!(
            body["punchcard"]["holder_passport"], "ce:probe:local",
            "explicit body holder_passport must win over the header actor"
        );

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
        assert_eq!(body["holder_passport"], "A");

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
        assert_eq!(body_json(resp).await["held_by"], "A");

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
        assert_eq!(body["holder_passport"], "A");

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
    async fn force_release_requires_confirm() {
        std::env::set_var("CORECRUXD_PUNCHCARD", "enforce");
        let state = state_with_kind().await;

        let resp = acquire(
            StateExtract(state.clone()),
            headers_for("A"),
            JsonExtract(acquire_body("file:///proj/f.rs", 600)),
        )
        .await;
        let card_id = body_json(resp).await["punchcard"]["id"].as_str().unwrap().to_string();

        // force-release without confirm → 400.
        let resp = force_release(
            StateExtract(state.clone()),
            PathExtract(card_id.clone()),
            headers_for("operator"),
            JsonExtract(ForceReleaseBody {
                confirm: false,
                reason: Some("holder offline".to_string()),
                by_passport: Some("operator".to_string()),
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // force-release with confirm:true → 200 force_released.
        let resp = force_release(
            StateExtract(state.clone()),
            PathExtract(card_id.clone()),
            headers_for("operator"),
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
}
