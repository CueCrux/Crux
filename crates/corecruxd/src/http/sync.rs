// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Tenant-aware sync endpoints for local/cloud mirror, explicit promotion, and
//! business-tenant offboarding receipts.

use super::*;
use corecrux_memory::fact_store::StoreFact;
use corecrux_memory::sync::{
    apply_promoted_records, build_tenant_manifest, offboard_tenant_mirror, promotion_preview, sync_records_hash,
    tenant_collection_page, SyncCollectionRecord, TenantManifestInput,
};
use serde_json::json;

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
fn require_sync_read(state: &AppState, headers: &HeaderMap, tenant_id: &str) -> Result<(), Response> {
    let ctx = crate::auth::http_scope_context(&state.auth, headers).map_err(IntoResponse::into_response)?;
    if ctx.has_scope("admin:read") {
        return Ok(());
    }
    require_http_scopes_for_tenant(&state.auth, headers, &["facts:read"], tenant_id)
        .map_err(IntoResponse::into_response)
}

#[allow(clippy::result_large_err)]
fn require_sync_write(state: &AppState, headers: &HeaderMap, tenant_id: &str) -> Result<(), Response> {
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
    if let Err(problem) = require_sync_read(&state, &headers, &tenant_id) {
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
    if let Err(problem) = require_sync_read(&state, &headers, &tenant_id) {
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
    if let Err(problem) = require_sync_read(&state, &headers, &tenant_id) {
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
    if let Err(problem) = require_sync_write(&state, &headers, &tenant_id) {
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
    if let Err(problem) = require_sync_write(&state, &headers, &tenant_id) {
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
