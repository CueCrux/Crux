// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Tenant-aware sync endpoints for local/cloud mirror, explicit promotion, and
//! business-tenant offboarding receipts.
//!
//! With `CORECRUXD_SYNC_MUTUAL_AUTH=1`, every tenant sync endpoint requires
//! the M2a peer handshake and ordinary/admin scopes cannot bypass it. A peer
//! first fetches `POST /v1/sync/handshake/nonce`, then presents exactly one of
//! each header: `x-crux-peer-token` (standard-base64 canonical token JSON),
//! `x-crux-peer-pubkey` (32-byte hex), `x-crux-peer-nonce` (32-byte hex), and
//! `x-crux-peer-sig` (64-byte hex). The authenticated token tenant must exactly
//! equal the tenant path parameter.

use super::*;
use base64::Engine as _;
use corecrux_memory::fact_store::StoreFact;
use corecrux_memory::sync::{
    apply_promoted_records, build_tenant_manifest, offboard_tenant_mirror, promotion_preview, sync_records_hash,
    tenant_collection_page, SyncCollectionRecord, TenantManifestInput,
};
use crux_sync::peer_handshake::{verify_peer_handshake, AuthenticatedPeer, PeerAuthError, PeerHandshake};
use rand::TryRng as _;
use rcx_capability_token::RcxCapabilityToken;
use serde_json::json;

const PEER_TOKEN_HEADER: &str = "x-crux-peer-token";
const PEER_PUBLIC_KEY_HEADER: &str = "x-crux-peer-pubkey";
const PEER_NONCE_HEADER: &str = "x-crux-peer-nonce";
const PEER_SIGNATURE_HEADER: &str = "x-crux-peer-sig";
const MAX_PEER_TOKEN_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerHandshakeParseError {
    Missing,
    Malformed,
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn peer_auth_problem(reason_class: &'static str) -> Response {
    ProblemResponse(
        ProblemDetails::unauthorized("sync peer authentication failed").with_extensions(json!({
            "code": "SYNC_PEER_AUTH_FAILED",
            "reason_class": reason_class,
        })),
    )
    .into_response()
}

fn peer_tenant_problem() -> Response {
    ProblemResponse(
        ProblemDetails::forbidden("sync peer is not authorized for the requested tenant").with_extensions(json!({
            "code": "SYNC_PEER_TENANT_MISMATCH",
            "reason_class": "peer_tenant_mismatch",
        })),
    )
    .into_response()
}

fn peer_verification_unavailable() -> Response {
    ProblemResponse(
        ProblemDetails::service_unavailable("sync peer verification is unavailable").with_extensions(json!({
            "code": "SYNC_PEER_AUTH_UNAVAILABLE",
            "reason_class": "peer_verification_unavailable",
        })),
    )
    .into_response()
}

fn required_single_header<'a>(headers: &'a HeaderMap, name: &'static str) -> Result<&'a str, PeerHandshakeParseError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next().ok_or(PeerHandshakeParseError::Missing)?;
    if values.next().is_some() {
        return Err(PeerHandshakeParseError::Malformed);
    }
    value.to_str().map_err(|_| PeerHandshakeParseError::Malformed)
}

fn decode_hex_array<const N: usize>(encoded: &str) -> Result<[u8; N], PeerHandshakeParseError> {
    let decoded = hex::decode(encoded).map_err(|_| PeerHandshakeParseError::Malformed)?;
    decoded.try_into().map_err(|_| PeerHandshakeParseError::Malformed)
}

fn parse_peer_handshake(headers: &HeaderMap) -> Result<PeerHandshake, PeerHandshakeParseError> {
    let encoded_token = required_single_header(headers, PEER_TOKEN_HEADER)?;
    if encoded_token.len() > MAX_PEER_TOKEN_HEADER_BYTES {
        return Err(PeerHandshakeParseError::Malformed);
    }
    let token_json = base64::engine::general_purpose::STANDARD
        .decode(encoded_token.as_bytes())
        .map_err(|_| PeerHandshakeParseError::Malformed)?;
    if base64::engine::general_purpose::STANDARD.encode(&token_json) != encoded_token {
        return Err(PeerHandshakeParseError::Malformed);
    }
    let capability_token =
        serde_json::from_slice::<RcxCapabilityToken>(&token_json).map_err(|_| PeerHandshakeParseError::Malformed)?;

    Ok(PeerHandshake {
        capability_token,
        peer_public_key: decode_hex_array(required_single_header(headers, PEER_PUBLIC_KEY_HEADER)?)?,
        nonce: decode_hex_array::<32>(required_single_header(headers, PEER_NONCE_HEADER)?)?.to_vec(),
        nonce_signature: decode_hex_array(required_single_header(headers, PEER_SIGNATURE_HEADER)?)?,
    })
}

fn peer_rejection_class(error: &PeerAuthError) -> &'static str {
    match error {
        PeerAuthError::TokenInvalid(_) => "peer_token_rejected",
        PeerAuthError::FprMismatch | PeerAuthError::BadPossessionSig => "peer_possession_rejected",
        PeerAuthError::NonceUnknownOrUsed | PeerAuthError::NonceExpired => "peer_nonce_rejected",
        PeerAuthError::Revoked => "peer_revoked",
    }
}

#[allow(clippy::result_large_err)]
async fn require_sync_peer(state: &AppState, headers: &HeaderMap, tenant_id: &str) -> Result<(), Response> {
    let handshake = parse_peer_handshake(headers).map_err(|error| match error {
        PeerHandshakeParseError::Missing => peer_auth_problem("missing_peer_handshake"),
        PeerHandshakeParseError::Malformed => peer_auth_problem("malformed_peer_handshake"),
    })?;
    let trust_root = state
        .sync_peer_trust_root
        .as_deref()
        .ok_or_else(|| peer_auth_problem("peer_trust_unavailable"))?;
    let now = current_unix_seconds();

    // M3: resolve peer revocation from the identity-links plane (v0.5.30). Links
    // are keyed by remote fingerprint; a link with `revoked_at` set revokes that
    // peer. Fail-open — an unlinked or live peer is not revoked (matches
    // `caller_revocation_reason`). Only read the store when links are enabled.
    let revoked_peer_fprs: std::collections::HashSet<String> = if state.identity_links_enabled {
        let entities = state.entity_store.read().await;
        crate::identity_links::list_links(&entities)
            .into_iter()
            .filter(|(_, link)| link.revoked_at.is_some())
            .map(|(_, link)| link.remote_fpr)
            .collect()
    } else {
        std::collections::HashSet::new()
    };

    let mut nonce_cache = state
        .sync_handshake_nonces
        .lock()
        .map_err(|_| peer_verification_unavailable())?;

    let verification = verify_peer_handshake(&handshake, trust_root, now, &mut nonce_cache, |token| {
        revoked_peer_fprs.contains(&token.subject.passport_fpr)
    });
    nonce_cache.sweep_expired(now);
    let authenticated = verification.map_err(|error| peer_auth_problem(peer_rejection_class(&error)))?;
    drop(nonce_cache);

    let AuthenticatedPeer {
        tenant_id: authenticated_tenant,
        ..
    } = authenticated;
    if authenticated_tenant != tenant_id {
        return Err(peer_tenant_problem());
    }
    Ok(())
}

pub(super) async fn post_handshake_nonce(State(state): State<AppState>) -> Response {
    if !state.sync_mutual_auth {
        return problem_response(StatusCode::NOT_FOUND, "sync mutual authentication is disabled");
    }

    let mut random_nonce = [0_u8; 32];
    let mut rng = rand::rngs::SysRng;
    if let Err(error) = rng.try_fill_bytes(&mut random_nonce) {
        tracing::error!(?error, "failed to generate sync peer-handshake nonce");
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "sync peer nonce generation failed");
    }

    let now = current_unix_seconds();
    let nonce = {
        let mut nonce_cache = match state.sync_handshake_nonces.lock() {
            Ok(cache) => cache,
            Err(_) => return peer_verification_unavailable(),
        };
        nonce_cache.sweep_expired(now);
        nonce_cache.issue(now, random_nonce)
    };
    let mut response = Json(json!({
        "nonce": hex::encode(nonce),
        "ttl_seconds": SYNC_HANDSHAKE_NONCE_TTL_SECONDS,
    }))
    .into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ManifestQuery {
    pub tenant_category: Option<String>,
    pub owner_id: Option<String>,
    pub membership_epoch: Option<u64>,
    pub role_grants: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct CollectionQuery {
    pub cursor: Option<String>,
    pub limit: Option<usize>,
    #[serde(default)]
    pub include_content: bool,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct PromotionRequest {
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default)]
    pub include_content: bool,
    #[serde(default)]
    pub confirm_hash: Option<String>,
    #[serde(default)]
    pub records: Vec<SyncCollectionRecord>,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct OffboardRequest {
    #[serde(default)]
    pub membership_epoch: u64,
}

fn parse_role_grants(raw: Option<String>) -> Vec<String> {
    raw.unwrap_or_default()
        .split([',', ' '])
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

#[allow(clippy::result_large_err)]
fn validate_tenant_id(tenant_id: &str) -> Result<(), Response> {
    if tenant_id.trim().is_empty() {
        return Err(problem_response(StatusCode::BAD_REQUEST, "tenant_id must not be empty"));
    }
    if tenant_id.contains('/') {
        return Err(problem_response(
            StatusCode::BAD_REQUEST,
            "tenant_id path segment must not contain '/'",
        ));
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
async fn require_sync_read(state: &AppState, headers: &HeaderMap, tenant_id: &str) -> Result<(), Response> {
    if state.sync_mutual_auth {
        return require_sync_peer(state, headers, tenant_id).await;
    }

    let ctx = crate::auth::http_scope_context(&state.auth, headers).map_err(IntoResponse::into_response)?;
    if ctx.has_scope("admin:read") {
        return Ok(());
    }
    require_http_scopes_for_tenant(&state.auth, headers, &["facts:read"], tenant_id)
        .map_err(IntoResponse::into_response)
}

#[allow(clippy::result_large_err)]
async fn require_sync_write(state: &AppState, headers: &HeaderMap, tenant_id: &str) -> Result<(), Response> {
    if state.sync_mutual_auth {
        return require_sync_peer(state, headers, tenant_id).await;
    }

    let ctx = crate::auth::http_scope_context(&state.auth, headers).map_err(IntoResponse::into_response)?;
    if ctx.has_scope("admin:write") {
        return Ok(());
    }
    require_http_scopes_for_tenant(&state.auth, headers, &["facts:write"], tenant_id)
        .map_err(IntoResponse::into_response)
}

pub(super) async fn get_tenant_manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Query(q): Query<ManifestQuery>,
) -> Response {
    if let Err(problem) = validate_tenant_id(&tenant_id) {
        return problem;
    }
    if let Err(problem) = require_sync_read(&state, &headers, &tenant_id).await {
        return problem;
    }
    let store = state.fact_store.read().await;
    let manifest = build_tenant_manifest(
        &store,
        TenantManifestInput {
            tenant_id,
            tenant_category: q.tenant_category,
            owner_id: q.owner_id,
            membership_epoch: q.membership_epoch.unwrap_or_default(),
            role_grants: parse_role_grants(q.role_grants),
        },
    );
    Json(manifest).into_response()
}

pub(super) async fn get_tenant_collection(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((tenant_id, collection)): Path<(String, String)>,
    Query(q): Query<CollectionQuery>,
) -> Response {
    if let Err(problem) = validate_tenant_id(&tenant_id) {
        return problem;
    }
    if let Err(problem) = require_sync_read(&state, &headers, &tenant_id).await {
        return problem;
    }
    let store = state.fact_store.read().await;
    match tenant_collection_page(
        &store,
        &tenant_id,
        &collection,
        q.cursor.as_deref(),
        q.limit.unwrap_or(1000),
        q.include_content,
    ) {
        Ok(page) => Json(page).into_response(),
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err),
    }
}

pub(super) async fn post_promotion_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Json(req): Json<PromotionRequest>,
) -> Response {
    if let Err(problem) = validate_tenant_id(&tenant_id) {
        return problem;
    }
    if let Err(problem) = require_sync_read(&state, &headers, &tenant_id).await {
        return problem;
    }
    let store = state.fact_store.read().await;
    let preview = promotion_preview(&store, &tenant_id, &req.allowlist, req.include_content);
    Json(preview).into_response()
}

pub(super) async fn post_promotion_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Json(req): Json<PromotionRequest>,
) -> Response {
    if let Err(problem) = validate_tenant_id(&tenant_id) {
        return problem;
    }
    if let Err(problem) = require_sync_write(&state, &headers, &tenant_id).await {
        return problem;
    }

    let records = if req.records.is_empty() {
        let store = state.fact_store.read().await;
        let preview = promotion_preview(&store, &tenant_id, &req.allowlist, true);
        if let Some(expected) = req.confirm_hash.as_deref() {
            if expected != preview.preview_hash {
                return problem_response(StatusCode::PRECONDITION_FAILED, "promotion preview hash mismatch");
            }
        }
        preview.records
    } else {
        let actual = sync_records_hash(&req.records);
        if let Some(expected) = req.confirm_hash.as_deref() {
            if expected != actual {
                return problem_response(StatusCode::PRECONDITION_FAILED, "promotion record hash mismatch");
            }
        }
        req.records
    };

    let applied = {
        let mut store = state.fact_store.write().await;
        apply_promoted_records(&mut store, &records, &format!("http:{}", state.node_id))
    };

    Json(json!({
        "schema": "crux.sync.promotion_confirm.v1",
        "tenant_id": tenant_id,
        "applied_count": applied,
        "record_hash": sync_records_hash(&records),
    }))
    .into_response()
}

pub(super) async fn post_tenant_offboard(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(tenant_id): Path<String>,
    Json(req): Json<OffboardRequest>,
) -> Response {
    if let Err(problem) = validate_tenant_id(&tenant_id) {
        return problem;
    }
    if let Err(problem) = require_sync_write(&state, &headers, &tenant_id).await {
        return problem;
    }

    let mut receipt = {
        let mut store = state.fact_store.write().await;
        offboard_tenant_mirror(&mut store, &tenant_id, req.membership_epoch)
    };
    if let Err((status, detail)) = sign_wipe_receipt(&state, &mut receipt) {
        return problem_response(status, detail);
    }

    let receipt_json = match serde_json::to_string(&receipt) {
        Ok(value) => value,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("encode wipe receipt: {err}")),
    };
    {
        let mut store = state.fact_store.write().await;
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: format!("__sync_wipe_receipt__::{tenant_id}"),
            key: receipt.receipt_hash.clone(),
            value: receipt_json,
            source_receipt: Some(format!("sync-wipe:{}", receipt.receipt_hash)),
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
    }

    Json(receipt).into_response()
}

fn sign_wipe_receipt(
    state: &AppState,
    receipt: &mut corecrux_memory::sync::TenantWipeReceipt,
) -> Result<(), (StatusCode, String)> {
    let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("passport key load failed: {err}"),
        )
    })?;
    if key.passport_fpr() != state.passport_fpr {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "passport signer mismatch: state={}, key={}",
                state.passport_fpr,
                key.passport_fpr()
            ),
        ));
    }

    let hex_hash = receipt
        .receipt_hash
        .strip_prefix("blake3:")
        .unwrap_or(receipt.receipt_hash.as_str());
    let decoded = hex::decode(hex_hash)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, format!("decode receipt hash: {err}")))?;
    if decoded.len() != 32 {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "receipt hash is not 32 bytes".to_string(),
        ));
    }
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&decoded);
    receipt.signed_by = Some(state.passport_fpr.clone());
    receipt.signature = Some(hex::encode(key.sign_hash(&hash)));
    Ok(())
}
