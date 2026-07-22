// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Governance-tier legal-hold HTTP surface.
//!
//! Hold state lives in the append-only fact store. Every place/release also
//! goes through the daemon's Ed25519-signed observation lane; the resulting
//! observation id is attached to the latest hold-state fact as its receipt.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

use super::observations::{append_one_durable, PostObservationBody, PostObservationResponse};
use super::{problem_response, require_http_scopes, AppState};
use corecrux_memory::{LegalHoldMutation, LegalHoldReceiptKind, PlaceLegalHold};

pub const LEGAL_HOLD_FEATURE_FLAG: &str = "CORECRUXD_FEATURE_LEGAL_HOLD";
const GOVERNANCE_RECEIPT_SESSION: &str = "__governance__::legal-holds";

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub(super) struct PostLegalHoldBody {
    pub tenant_id: String,
    #[serde(default, alias = "entityPrefixes")]
    pub entity_prefixes: Vec<String>,
    pub reason: String,
}

fn feature_enabled() -> bool {
    std::env::var(LEGAL_HOLD_FEATURE_FLAG)
        .ok()
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn feature_disabled_response() -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        format!("legal holds are disabled (set {LEGAL_HOLD_FEATURE_FLAG}=1)"),
    )
}

fn caller(state: &AppState, headers: &HeaderMap) -> Result<String, Box<Response>> {
    require_http_scopes(&state.auth, headers, &["admin:write"]).map_err(|problem| Box::new(problem.into_response()))?;
    let context =
        crate::auth::http_scope_context(&state.auth, headers).map_err(|problem| Box::new(problem.into_response()))?;
    Ok(context.passport_id.unwrap_or_else(|| state.passport_fpr.clone()))
}

fn sign_mutation(
    state: &AppState,
    actor: &str,
    kind: LegalHoldReceiptKind,
    mutation: &LegalHoldMutation,
) -> Result<PostObservationResponse, Box<Response>> {
    let kind_name = match kind {
        LegalHoldReceiptKind::Placed => "legal_hold_placed",
        LegalHoldReceiptKind::Released => "legal_hold_released",
        LegalHoldReceiptKind::Overridden => "legal_hold_overridden",
    };
    let body = PostObservationBody {
        kind: kind_name.to_string(),
        provider: "corecruxd".to_string(),
        client_ts: None,
        payload: json!({
            "tenant_id": mutation.hold.tenant_id,
            "hold": mutation.hold,
            "receipt_material": mutation.receipt,
        }),
    };
    append_one_durable(state, GOVERNANCE_RECEIPT_SESSION, actor, body, None)
        .map(|(response, _)| response)
        .map_err(|(status, detail)| {
            Box::new(problem_response(
                status,
                format!("legal-hold receipt signing or persistence failed: {detail}"),
            ))
        })
}

fn release_error_response(err: corecrux_memory::LegalHoldError) -> Response {
    match err {
        corecrux_memory::LegalHoldError::NotFound(hold_id) => {
            problem_response(StatusCode::NOT_FOUND, format!("legal hold not found: {hold_id}"))
        }
        corecrux_memory::LegalHoldError::AlreadyReleased(hold_id) => {
            problem_response(StatusCode::CONFLICT, format!("legal hold already released: {hold_id}"))
        }
        err => problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

/// Persist the signed release observation before committing released state.
/// Receipt failure therefore leaves the hold active; commit failure can only
/// leave an orphaned receipt, never an unreceipted release.
async fn release_with_signed_receipt(
    state: &AppState,
    hold_id: &str,
    actor: &str,
) -> Result<(corecrux_memory::LegalHold, PostObservationResponse), Response> {
    let prepared = state
        .fact_store
        .read()
        .await
        .prepare_legal_hold_release(hold_id, Some(actor))
        .map_err(release_error_response)?;

    // sign_mutation signs, appends, and fsyncs the observation JSONL record.
    // Do not acquire the state write lock or mark the hold released before
    // this durable operation succeeds.
    let signed =
        sign_mutation(state, actor, LegalHoldReceiptKind::Released, &prepared).map_err(|response| *response)?;
    let committed = state
        .fact_store
        .write()
        .await
        .release_legal_hold(&prepared, &signed.observation_id)
        .map_err(release_error_response)?;
    Ok((committed.hold, signed))
}

async fn persist_signed_receipt(
    state: &AppState,
    hold_id: &str,
    kind: LegalHoldReceiptKind,
    signed: &PostObservationResponse,
) -> Result<corecrux_memory::LegalHold, Box<Response>> {
    state
        .fact_store
        .write()
        .await
        .attach_signed_legal_hold_receipt(hold_id, kind, &signed.observation_id)
        .map_err(|err| {
            Box::new(problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("signed legal-hold receipt could not be linked to state: {err}"),
            ))
        })
}

#[utoipa::path(
    post,
    path = "/v1/legal-holds",
    tag = "Governance",
    request_body = PostLegalHoldBody,
    responses(
        (status = 201, description = "Legal hold placed with signed receipt"),
        (status = 400, description = "Invalid legal hold"),
        (status = 404, description = "Feature disabled"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn post_legal_hold(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PostLegalHoldBody>,
) -> Response {
    if !feature_enabled() {
        return feature_disabled_response();
    }
    let actor = match caller(&state, &headers) {
        Ok(actor) => actor,
        Err(response) => return *response,
    };
    let mutation = match state.fact_store.write().await.place_legal_hold(PlaceLegalHold {
        tenant_id: body.tenant_id,
        entity_prefixes: body.entity_prefixes,
        reason: body.reason,
        actor: Some(actor.clone()),
    }) {
        Ok(mutation) => mutation,
        Err(corecrux_memory::LegalHoldError::MissingTenant | corecrux_memory::LegalHoldError::MissingReason) => {
            return problem_response(StatusCode::BAD_REQUEST, "tenant_id and reason are required");
        }
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };
    let signed = match sign_mutation(&state, &actor, LegalHoldReceiptKind::Placed, &mutation) {
        Ok(signed) => signed,
        Err(response) => return *response,
    };
    let hold = match persist_signed_receipt(&state, &mutation.hold.hold_id, LegalHoldReceiptKind::Placed, &signed).await
    {
        Ok(hold) => hold,
        Err(response) => return *response,
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "schema": corecrux_memory::LEGAL_HOLD_SCHEMA_V1,
            "hold": hold,
            "receipt_record_id": signed.observation_id,
            "receipt": signed.receipt,
        })),
    )
        .into_response()
}

#[utoipa::path(
    delete,
    path = "/v1/legal-holds/{id}",
    tag = "Governance",
    params(("id" = String, Path, description = "Legal hold id")),
    responses(
        (status = 200, description = "Legal hold released with signed receipt"),
        (status = 404, description = "Feature disabled or hold not found"),
        (status = 409, description = "Hold already released"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn delete_legal_hold(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(hold_id): Path<String>,
) -> Response {
    if !feature_enabled() {
        return feature_disabled_response();
    }
    let actor = match caller(&state, &headers) {
        Ok(actor) => actor,
        Err(response) => return *response,
    };
    let (hold, signed) = match release_with_signed_receipt(&state, &hold_id, &actor).await {
        Ok(released) => released,
        Err(response) => return response,
    };
    (
        StatusCode::OK,
        Json(json!({
            "schema": corecrux_memory::LEGAL_HOLD_SCHEMA_V1,
            "hold": hold,
            "receipt_record_id": signed.observation_id,
            "receipt": signed.receipt,
        })),
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn place_and_release_emit_ed25519_observation_receipts() {
        let mut state = crate::http::tests::test_app_state(4);
        let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).unwrap();
        state.passport_fpr = key.passport_fpr().to_string();
        state.passport_public_key_hex = key.public_key_hex().to_string();
        let actor = "p_dpo";
        let mutation = state
            .fact_store
            .write()
            .await
            .place_legal_hold(PlaceLegalHold {
                tenant_id: "default".to_string(),
                entity_prefixes: vec!["customer::42::".to_string()],
                reason: "litigation".to_string(),
                actor: Some(actor.to_string()),
            })
            .unwrap();
        let placed = sign_mutation(&state, actor, LegalHoldReceiptKind::Placed, &mutation).unwrap();
        assert_eq!(placed.receipt.alg, "ed25519");
        assert!(!placed.receipt.signature.is_empty());
        let hold = persist_signed_receipt(&state, &mutation.hold.hold_id, LegalHoldReceiptKind::Placed, &placed)
            .await
            .unwrap();
        assert_eq!(hold.place_receipt_id, placed.observation_id);

        let (hold, signed_release) = release_with_signed_receipt(&state, &hold.hold_id, actor).await.unwrap();
        assert_eq!(signed_release.receipt.alg, "ed25519");
        assert!(!signed_release.receipt.signature.is_empty());
        assert_eq!(
            hold.release_receipt_id.as_deref(),
            Some(signed_release.observation_id.as_str())
        );

        let observation_file =
            super::super::observations::observation_file_path(&state.data_dir, GOVERNANCE_RECEIPT_SESSION);
        let records = std::fs::read_to_string(observation_file).unwrap();
        assert!(records.contains("legal_hold_placed"));
        assert!(records.contains("legal_hold_released"));
    }

    #[tokio::test]
    async fn release_receipt_persist_failure_keeps_hold_active() {
        let mut state = crate::http::tests::test_app_state(4);
        let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).unwrap();
        state.passport_fpr = key.passport_fpr().to_string();
        state.passport_public_key_hex = key.public_key_hex().to_string();
        let placed = state
            .fact_store
            .write()
            .await
            .place_legal_hold(PlaceLegalHold {
                tenant_id: "default".to_string(),
                entity_prefixes: vec!["customer::42::".to_string()],
                reason: "litigation".to_string(),
                actor: Some("p_dpo".to_string()),
            })
            .unwrap();

        // An empty, read-only observation file lets chain-tip resolution and
        // receipt minting succeed, then forces the durable journal path to
        // fail either during pre-append tail repair or the append itself.
        let observation_file =
            super::super::observations::observation_file_path(&state.data_dir, GOVERNANCE_RECEIPT_SESSION);
        std::fs::create_dir_all(observation_file.parent().unwrap()).unwrap();
        std::fs::write(&observation_file, b"").unwrap();
        let mut permissions = std::fs::metadata(&observation_file).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&observation_file, permissions).unwrap();

        let err = release_with_signed_receipt(&state, &placed.hold.hold_id, "p_dpo")
            .await
            .unwrap_err();
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let error_body = axum::body::to_bytes(err.into_body(), usize::MAX).await.unwrap();
        let error_body = String::from_utf8_lossy(&error_body);
        assert!(
            error_body.contains("legal-hold receipt signing or persistence failed")
                && error_body.contains("observation"),
            "unexpected failure body: {error_body}"
        );
        let hold = state.fact_store.read().await.legal_hold(&placed.hold.hold_id).unwrap();
        assert!(hold.active());
        assert!(hold.released_at.is_none());
        assert!(hold.release_receipt_id.is_none());
    }
}
