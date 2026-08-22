// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Vault key escrow HTTP surface (ExecPlan `crux-key-escrow-and-recovery-2026-07-31`, M3b).
//!
//! Wires the `crux-escrow` crate into the daemon. Until this module existed, the
//! crate's gates were properties of its types; here they become properties of a
//! running system.
//!
//! Two design points, both load-bearing:
//!
//! **The server stores only ciphertext.** A vault's wrapped DEK is a private,
//! daemon-owned fact under `__escrow__::vault::<vault_id>`. It carries no key, no
//! salt and no derivation input — `crux_escrow::WrappedDek` is `{vault_id, nonce,
//! ciphertext}` and the crate's `server_dump_yields_nothing` test fails if that
//! field set ever grows. Reusing the fact store rather than introducing a new
//! on-disk artifact type also avoids the three-place wiring (storage allowlist,
//! projection registry, load-at-startup) and its quarantine-on-restart bug class —
//! the same call `auth_device` made for refresh credentials.
//!
//! **Release state is derived from the receipt chain, never stored beside it.**
//! Every release event is appended to a per-request observation chain, which is
//! Ed25519-signed and hash-linked (`seq` + `prev_hash`), so removing or reordering
//! a line breaks it. `GET` replays that chain through
//! `ReleaseRequest::replay`. There is deliberately no state record that could
//! disagree with the receipts: if the chain does not say it happened, it did not
//! happen.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde_json::json;

use super::facts::{tenant_hash_for_read_context, tenant_hash_for_write_context};
use super::observations::{append_one_durable, read_observations_strict, PostObservationBody};
use super::{problem_response, AppState};
use crux_escrow::release::{ReleaseError, ReleaseEvent, ReleaseRequest};
use crux_escrow::WrappedDek;

/// Reserved, daemon-owned entity prefix. Registered in
/// `corecrux_memory::fact_privacy` as both always-private (never pushed to a
/// remote by sync) and daemon-owned (client fact-write handlers reject it, so a
/// caller cannot forge escrow state through the generic fact API).
const ESCROW_ENTITY_PREFIX: &str = "__escrow__";
const WRAPPED_DEK_KEY: &str = "wrapped_dek";
const LATEST_RELEASE_KEY: &str = "latest_release";

/// Receipt `kind` values. Stable strings — they are what an auditor greps for.
const KIND_DEK_STORED: &str = "escrow_dek_stored";
const KIND_RELEASE_EVENT: &str = "escrow_release_event";

fn vault_entity(vault_id: &str) -> String {
    format!("{ESCROW_ENTITY_PREFIX}::vault::{vault_id}")
}

/// One observation chain per release request. A dedicated chain means the
/// replay in [`load_release`] reads exactly the events of one request and
/// nothing else, so a second request cannot contaminate the first's history.
fn release_session(request_id: &str) -> String {
    format!("{ESCROW_ENTITY_PREFIX}::release::{request_id}")
}

/// A vault id must be safe to embed in an entity key and an observation
/// filename. Rejecting rather than sanitising: two ids that sanitise to the same
/// file would share a receipt chain.
fn valid_vault_id(vault_id: &str) -> bool {
    !vault_id.is_empty()
        && vault_id.len() <= 128
        && vault_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

#[allow(clippy::result_large_err)]
fn write_ctx(state: &AppState, headers: &HeaderMap) -> Result<crate::auth::HttpScopeContext, Response> {
    super::require_http_scopes(&state.auth, headers, &["admin:write"]).map_err(IntoResponse::into_response)?;
    crate::auth::http_scope_context(&state.auth, headers).map_err(IntoResponse::into_response)
}

#[allow(clippy::result_large_err)]
fn read_ctx(state: &AppState, headers: &HeaderMap) -> Result<crate::auth::HttpScopeContext, Response> {
    super::require_http_scopes(&state.auth, headers, &["admin:read"]).map_err(IntoResponse::into_response)?;
    crate::auth::http_scope_context(&state.auth, headers).map_err(IntoResponse::into_response)
}

fn actor_of(state: &AppState, ctx: &crate::auth::HttpScopeContext) -> String {
    ctx.passport_id.clone().unwrap_or_else(|| state.passport_fpr.clone())
}

#[allow(clippy::result_large_err)]
/// Append one signed, hash-chained receipt. Durable before the caller is told it
/// happened.
fn receipt(
    state: &AppState,
    session: &str,
    actor: &str,
    kind: &str,
    payload: serde_json::Value,
) -> Result<String, Response> {
    let body = PostObservationBody {
        kind: kind.to_string(),
        provider: "corecruxd".to_string(),
        client_ts: None,
        payload,
    };
    append_one_durable(state, session, actor, body, None)
        .map(|(response, _)| response.observation_id)
        .map_err(|(status, detail)| problem_response(status, format!("escrow receipt could not be written: {detail}")))
}

// ── wrapped DEK storage ─────────────────────────────────────────────

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub(super) struct PutWrappedDekBody {
    /// XChaCha20-Poly1305 nonce, 24 bytes.
    pub nonce: [u8; 24],
    /// Wrapped DEK with its Poly1305 tag appended.
    pub ciphertext: Vec<u8>,
}

/// Store a vault's wrapped data encryption key.
///
/// The daemon never sees the recovery code, the wrapping key or the DEK — only
/// this blob, which is useless without a customer-held code or two escrow shares.
#[utoipa::path(
    put,
    path = "/v1/escrow/vaults/{vault_id}",
    tag = "escrow",
    responses((status = 200, description = "stored"))
)]
pub(super) async fn put_wrapped_dek(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<String>,
    Json(body): Json<PutWrappedDekBody>,
) -> Response {
    let ctx = match write_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    if !valid_vault_id(&vault_id) {
        return problem_response(StatusCode::BAD_REQUEST, "vault_id must be [A-Za-z0-9_-]{1,128}");
    }
    if body.ciphertext.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "ciphertext is empty");
    }
    let blob = WrappedDek {
        vault_id: vault_id.clone(),
        nonce: body.nonce,
        ciphertext: body.ciphertext,
    };
    let Ok(value) = serde_json::to_string(&blob) else {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "wrapped DEK could not be encoded");
    };
    let actor = actor_of(&state, &ctx);
    let tenant = match tenant_hash_for_write_context(&ctx) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };

    let stored = {
        let mut store = state.fact_store.write().await;
        store.try_store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: tenant,
            entity: vault_entity(&vault_id),
            key: WRAPPED_DEK_KEY.to_string(),
            value,
            source_receipt: None,
            confidence: 1.0,
            // Never leaves this machine, and never decays. A wrapped DEK that
            // "grew stale" and dropped out of recall is a customer locked out.
            private: true,
            horizon_class: Some(corecrux_memory::fact_store::HorizonClass::None),
            actor: Some(actor.clone()),
        })
    };
    if let Err(err) = stored {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("could not persist: {err}"));
    }

    // The receipt records that a wrap happened, and binds the ciphertext by
    // hash. It does not carry the ciphertext: a receipt chain is a different
    // durability class from the fact store and duplicating key material into it
    // widens the blast radius of a dump for no audit gain.
    let digest = blake3::hash(&blob.ciphertext).to_hex().to_string();
    let payload = json!({
        "vault_id": vault_id,
        "ciphertext_blake3": digest,
        "ciphertext_len": blob.ciphertext.len(),
    });
    match receipt(&state, &vault_entity(&vault_id), &actor, KIND_DEK_STORED, payload) {
        Ok(observation_id) => Json(json!({ "vault_id": vault_id, "observation_id": observation_id })).into_response(),
        Err(response) => response,
    }
}

/// Return a vault's wrapped DEK. Ciphertext only — there is nothing else to return.
#[utoipa::path(
    get,
    path = "/v1/escrow/vaults/{vault_id}",
    tag = "escrow",
    responses((status = 200, body = Object, description = "the wrapped DEK"))
)]
pub(super) async fn get_wrapped_dek(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<String>,
) -> Response {
    let ctx = match read_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    if !valid_vault_id(&vault_id) {
        return problem_response(StatusCode::BAD_REQUEST, "vault_id must be [A-Za-z0-9_-]{1,128}");
    }
    let tenant = match tenant_hash_for_read_context(&ctx) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };
    let facts = {
        let store = state.fact_store.read().await;
        store
            .get_by_entity_for_tenant(&vault_entity(&vault_id), &tenant)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>()
    };
    match newest_wrapped_dek(&facts) {
        Some(blob) => Json(blob).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, "no wrapped DEK for that vault"),
    }
}

/// Take the highest-version, non-deleted `wrapped_dek` fact.
///
/// The fact store is versioned: re-storing an `(entity, key)` appends a new
/// version rather than replacing it, so a re-wrap leaves the *old* blob present
/// alongside the new one. Returning an arbitrary version would hand back a blob
/// the customer's current recovery code no longer opens.
fn newest_wrapped_dek(facts: &[corecrux_memory::Fact]) -> Option<WrappedDek> {
    facts
        .iter()
        .filter(|fact| fact.key == WRAPPED_DEK_KEY && !fact.deleted)
        .max_by_key(|fact| fact.version)
        .and_then(|fact| serde_json::from_str::<WrappedDek>(&fact.value).ok())
}

/// Take the highest-version pointer to the vault's most recent release request.
fn newest_latest_release(facts: &[corecrux_memory::Fact]) -> Option<String> {
    facts
        .iter()
        .filter(|fact| fact.key == LATEST_RELEASE_KEY && !fact.deleted)
        .max_by_key(|fact| fact.version)
        .map(|fact| fact.value.clone())
}

// ── custodian-share release ─────────────────────────────────────────

#[allow(clippy::result_large_err)]
/// Rebuild a release request from its receipt chain.
///
/// This is the only reader. There is no stored state to prefer over the chain,
/// which is what makes "the whole sequence is reconstructable from receipts" a
/// property of the system rather than a claim about it.
fn load_release(state: &AppState, request_id: &str) -> Result<Option<ReleaseRequest>, Response> {
    let path = super::observations::observation_file_path(&state.data_dir, &release_session(request_id));
    // Strict: one malformed line invalidates the chain rather than being
    // skipped. A release history with a hole in it is not a release history.
    let records = read_observations_strict(&path).map_err(|err| {
        problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("receipt chain unreadable: {err}"),
        )
    })?;
    if records.is_empty() {
        return Ok(None);
    }
    let mut events = Vec::with_capacity(records.len());
    for record in records.iter().filter(|r| r.kind == KIND_RELEASE_EVENT) {
        let event: ReleaseEvent = serde_json::from_value(record.payload.clone()).map_err(|err| {
            problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("receipt chain holds an unreadable release event: {err}"),
            )
        })?;
        events.push(event);
    }
    if events.is_empty() {
        return Ok(None);
    }
    ReleaseRequest::replay(&events).map(Some).map_err(|err| {
        problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("receipt chain does not replay: {err}"),
        )
    })
}

fn release_error_response(err: &ReleaseError) -> Response {
    let status = match err {
        ReleaseError::NotAccountHolder => StatusCode::FORBIDDEN,
        ReleaseError::AlreadyPending | ReleaseError::NotPending => StatusCode::CONFLICT,
        ReleaseError::TooSoon { .. } => StatusCode::TOO_EARLY,
        ReleaseError::UnknownDevice => StatusCode::FORBIDDEN,
        ReleaseError::Unreplayable(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    problem_response(status, err.to_string())
}

#[allow(clippy::result_large_err)]
/// Write a batch of release events to the request's chain, in order.
fn receipt_events(state: &AppState, request_id: &str, events: &[ReleaseEvent]) -> Result<(), Response> {
    let session = release_session(request_id);
    for event in events {
        let Ok(payload) = serde_json::to_value(event) else {
            return Err(problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "release event could not be encoded",
            ));
        };
        receipt(state, &session, &event.actor, KIND_RELEASE_EVENT, payload)?;
    }
    Ok(())
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub(super) struct PostReleaseBody {
    /// Passport of the account holder this vault belongs to. The request is
    /// refused unless the caller *is* that passport — support cannot initiate a
    /// release on a customer's behalf.
    pub account_holder: String,
}

/// Request release of the custodian share.
///
/// Delayed by `crux_escrow::release::RELEASE_DELAY`, announced to every device
/// currently paired with this daemon, and cancellable by any of them.
#[utoipa::path(
    post,
    path = "/v1/escrow/vaults/{vault_id}/release",
    tag = "escrow",
    responses((status = 200, body = Object, description = "the pending release"))
)]
pub(super) async fn post_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(vault_id): Path<String>,
    Json(body): Json<PostReleaseBody>,
) -> Response {
    let ctx = match write_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(response) => return response,
    };
    if !valid_vault_id(&vault_id) {
        return problem_response(StatusCode::BAD_REQUEST, "vault_id must be [A-Za-z0-9_-]{1,128}");
    }
    let actor = actor_of(&state, &ctx);
    let tenant = match tenant_hash_for_write_context(&ctx) {
        Ok(tenant) => tenant,
        Err(response) => return response,
    };

    let facts = {
        let store = state.fact_store.read().await;
        store
            .get_by_entity_for_tenant(&vault_entity(&vault_id), &tenant)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>()
    };
    let previous = match newest_latest_release(&facts) {
        Some(request_id) => match load_release(&state, &request_id) {
            Ok(previous) => previous,
            Err(response) => return response,
        },
        None => None,
    };

    // Every device currently paired with this daemon. Not a hosted registry:
    // the daemon a customer runs is the thing that knows which devices are
    // theirs, and reaching for a remote list would make recovery depend on a
    // network the customer may have lost access to.
    let devices = super::auth_device::paired_device_ids(&tenant);

    let (request, events) = match ReleaseRequest::open(
        previous.as_ref(),
        &vault_id,
        &body.account_holder,
        &actor,
        &devices,
        Utc::now(),
    ) {
        Ok(opened) => opened,
        Err(err) => return release_error_response(&err),
    };

    let request_id = request.id.to_string();
    // Receipts first: a release that is not receipted has not happened, and the
    // pointer below is only an index into chains that already exist.
    if let Err(response) = receipt_events(&state, &request_id, &events) {
        return response;
    }
    let stored = {
        let mut store = state.fact_store.write().await;
        store.try_store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: tenant,
            entity: vault_entity(&vault_id),
            key: LATEST_RELEASE_KEY.to_string(),
            value: request_id.clone(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: Some(corecrux_memory::fact_store::HorizonClass::None),
            actor: Some(actor),
        })
    };
    if let Err(err) = stored {
        return problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("release was receipted but its index could not be written: {err}"),
        );
    }
    Json(request).into_response()
}

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub(super) struct PostCancelBody {
    /// The device cancelling. Must be one that was notified when the request opened.
    pub device: String,
}

/// Cancel a pending release from a notified device.
#[utoipa::path(
    post,
    path = "/v1/escrow/releases/{request_id}/cancel",
    tag = "escrow",
    responses((status = 200, body = Object, description = "the cancelled release"))
)]
pub(super) async fn post_release_cancel(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
    Json(body): Json<PostCancelBody>,
) -> Response {
    if let Err(response) = write_ctx(&state, &headers) {
        return response;
    }
    let mut request = match load_release(&state, &request_id) {
        Ok(Some(request)) => request,
        Ok(None) => return problem_response(StatusCode::NOT_FOUND, "no such release"),
        Err(response) => return response,
    };
    let event = match request.cancel(&body.device, Utc::now()) {
        Ok(event) => event,
        Err(err) => return release_error_response(&err),
    };
    if let Err(response) = receipt_events(&state, &request_id, std::slice::from_ref(&event)) {
        return response;
    }
    Json(request).into_response()
}

/// Complete a release once its delay has elapsed. There is no override.
#[utoipa::path(
    post,
    path = "/v1/escrow/releases/{request_id}/complete",
    tag = "escrow",
    responses((status = 200, body = Object, description = "the completed release"))
)]
pub(super) async fn post_release_complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> Response {
    if let Err(response) = write_ctx(&state, &headers) {
        return response;
    }
    let mut request = match load_release(&state, &request_id) {
        Ok(Some(request)) => request,
        Ok(None) => return problem_response(StatusCode::NOT_FOUND, "no such release"),
        Err(response) => return response,
    };
    let event = match request.complete(Utc::now()) {
        Ok(event) => event,
        Err(err) => return release_error_response(&err),
    };
    if let Err(response) = receipt_events(&state, &request_id, std::slice::from_ref(&event)) {
        return response;
    }
    Json(request).into_response()
}

/// Read a release, reconstructed from its receipt chain.
#[utoipa::path(
    get,
    path = "/v1/escrow/releases/{request_id}",
    tag = "escrow",
    responses((status = 200, body = Object, description = "the release, replayed from receipts"))
)]
pub(super) async fn get_release(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(request_id): Path<String>,
) -> Response {
    if let Err(response) = read_ctx(&state, &headers) {
        return response;
    }
    match load_release(&state, &request_id) {
        Ok(Some(request)) => Json(request).into_response(),
        Ok(None) => problem_response(StatusCode::NOT_FOUND, "no such release"),
        Err(response) => response,
    }
}

#[cfg(test)]
mod tests;
