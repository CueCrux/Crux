// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Authenticated daemon-to-daemon embedding provider.
//!
//! The route is always mounted so a disabled provider is an explicit runtime
//! capability response, never a silent 404/501. Successful calls are bound to
//! a durable, signed observation receipt containing hashes and profile metadata
//! only; caller text is never copied into the audit log.
//!
//! This is CueCrux-side compute, so it is billable: with
//! `CORECRUXD_CREDIT_METER=1` every call reserves, then settles or voids, one
//! `dense_managed` credit through the same reserve/settle/void lifecycle
//! `/v1/gpu1/rerank` uses. That lifecycle is mirrored here rather than shared:
//! `http::gpu1` is compiled out of the default Community Edition binary by the
//! `hosted-surfaces` feature, while this door is always compiled, so its
//! `PendingCreditSpend` is not reachable from here. Extraction into an
//! always-compiled module is the reserved follow-up
//! (`credit-spend-lifecycle-extraction`); until then the two copies must be
//! changed together. With the meter off the handler behaves exactly as it did
//! before metering existed.

use super::AppState;
use crate::auth::require_http_scopes;
use crate::problem::ProblemResponse;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use corecrux_memory::embeddings::SemanticProfile;
use corecrux_types::ProblemDetails;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub(super) const COMPUTE_EMBED_MAX_REQUEST_BYTES: usize = 512 * 1024;
const COMPUTE_EMBED_MAX_TEXTS: usize = 64;
const COMPUTE_EMBED_MAX_TEXT_BYTES: usize = 64 * 1024;
const COMPUTE_EMBED_MAX_TOTAL_TEXT_BYTES: usize = 256 * 1024;
const COMPUTE_EMBED_SCOPE: &str = "compute:embed";
const COMPUTE_EMBED_RESPONSE_SCHEMA: &str = "crux.compute.embed.response.v1";
const COMPUTE_EMBED_RECEIPT_SCHEMA: &str = "crux.compute.embed.receipt.v1";
const COMPUTE_EMBED_RECEIPT_SESSION: &str = "__compute__::embed";
/// The already-priced premium lane this door bills against: one credit per
/// hosted query embedding call. Not a new lane and not a new price — see
/// `rcx_capability_token::corecrux_lane_credit_cost`.
const COMPUTE_EMBED_LANE_SLUG: &str = "dense_managed";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct ComputeEmbedRequest {
    pub texts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_profile: Option<SemanticProfile>,
    /// Pinned credit quote for the `dense_managed` lane.
    ///
    /// Optional on the wire so delegate clients written before metering keep
    /// working unchanged; required only when the daemon runs with
    /// `CORECRUXD_CREDIT_METER=1`. `skip_serializing_if` keeps the request hash
    /// — and therefore the receipt — byte-identical when it is absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credit_quote: Option<crate::credit_meter::PinnedCreditQuote>,
}

#[derive(Debug, Serialize)]
struct ComputeEmbedResponse {
    schema: &'static str,
    embeddings: Vec<Vec<f32>>,
    semantic_profile: SemanticProfile,
    receipt_id: String,
    receipt_session_id: &'static str,
    receipt: super::observations::ReceiptEnvelopeV1,
    // Additive spend stamp, absent when the meter is off. Named
    // `credit_spend_receipt` to match the gpu1 envelope and because
    // `receipt_id` above already names the observation receipt.
    #[serde(skip_serializing_if = "Option::is_none")]
    credit_spend_receipt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credits_spent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_balance: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ComputeEmbedReceiptPayload<'a> {
    schema: &'static str,
    operation: &'static str,
    input_hash: &'a str,
    output_hash: &'a str,
    text_count: usize,
    semantic_profile_id: &'a str,
    model: &'a str,
    dimensions: usize,
    // Additive spend stamp; `crux.compute.embed.receipt.v1` is unchanged when
    // the meter is off, so no schema version bump.
    #[serde(skip_serializing_if = "Option::is_none")]
    credit_spend_receipt: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    credits_spent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wallet_balance: Option<u64>,
}

/// Either the embeddings plus the profile they were produced under, or the
/// problem to answer with and the void reason to release the credit hold under.
type EmbedOutcome = Result<(Vec<Vec<f32>>, SemanticProfile), (&'static str, Response)>;

/// What a settled spend stamps onto the response and the observation receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CreditSpendStamp {
    receipt_id: String,
    credits_spent: u64,
    wallet_balance: u64,
}

/// A credit hold taken before the compute it pays for.
///
/// Mirror of `http::gpu1`'s type of the same name — see the module docs for why
/// it is copied rather than imported. The invariant it exists to hold: the hold
/// is settled by [`Self::complete`], voided by [`Self::release`], and voided by
/// `Drop` on every other way out of the handler, so no path charges without a
/// receipt and none aborts leaving the wallet short.
struct PendingCreditSpend {
    meter: std::sync::Arc<std::sync::Mutex<crate::credit_meter::CreditMeterStore>>,
    quote: crate::credit_meter::PinnedCreditQuote,
    reservation: crate::credit_meter::CreditReservation,
    signing_key: crux_session::LocalPassportKey,
    active: bool,
}

impl PendingCreditSpend {
    fn release(mut self, reason: &str) -> Result<(), String> {
        {
            let mut meter = self
                .meter
                .lock()
                .map_err(|_| "credit meter lock poisoned".to_string())?;
            meter
                .void_reservation(&self.quote.tenant_id, &self.reservation.reservation_id, reason)
                .map_err(|err| err.to_string())?;
        }
        self.active = false;
        Ok(())
    }

    fn complete(mut self) -> Result<CreditSpendStamp, String> {
        let receipt = crate::credit_meter::mint_spend_receipt(&self.quote, &self.reservation, &self.signing_key)
            .map_err(|err| err.to_string())?;
        let spend = {
            let mut meter = self
                .meter
                .lock()
                .map_err(|_| "credit meter lock poisoned".to_string())?;
            meter
                .spend(
                    &self.quote.tenant_id,
                    &self.reservation.reservation_id,
                    &receipt.body.receipt_id,
                )
                .map_err(|err| err.to_string())?
        };
        if spend.spend_receipt != receipt.body.receipt_id {
            return Err("operation already spent with a different pinned quote/spend receipt".to_string());
        }
        self.active = false;
        Ok(CreditSpendStamp {
            receipt_id: receipt.body.receipt_id,
            credits_spent: spend.cost,
            wallet_balance: spend.balance_after,
        })
    }
}

impl Drop for PendingCreditSpend {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut meter) = self.meter.lock() {
            let _ = meter.void_reservation(
                &self.quote.tenant_id,
                &self.reservation.reservation_id,
                "metered_request_aborted",
            );
        }
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_compute_embed(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ComputeEmbedRequest>,
) -> Response {
    // This deliberately does not reuse query:read: reading stored memory must
    // not implicitly grant access to potentially costly provider compute.
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &[COMPUTE_EMBED_SCOPE]) {
        return problem.into_response();
    }
    let auth_ctx = match crate::auth::http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };
    let Some(caller_passport) = auth_ctx.passport_id.as_deref() else {
        return compute_problem(
            StatusCode::FORBIDDEN,
            "COMPUTE_CALLER_PASSPORT_REQUIRED",
            "Embedding compute requires a passport-bound caller so its receipt can be isolated and attributed.",
            json!({ "capability": "compute:embed" }),
        );
    };

    if !state.compute_provider_enabled {
        return compute_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "COMPUTE_PROVIDER_DISABLED",
            "Embedding compute provider is disabled; set CORECRUXD_COMPUTE_PROVIDER=1 on the full daemon to enable it.",
            json!({ "capability": "compute:embed", "availability": "unavailable" }),
        );
    }
    if let Err(detail) = validate_request(&body) {
        return compute_problem(
            StatusCode::BAD_REQUEST,
            "COMPUTE_EMBED_INVALID_REQUEST",
            detail,
            json!({ "capability": "compute:embed" }),
        );
    }

    let input_hash = match hash_json(&body) {
        Ok(hash) => hash,
        Err(detail) => {
            return compute_problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "COMPUTE_EMBED_HASH_FAILED",
                detail,
                json!({ "capability": "compute:embed" }),
            );
        }
    };
    // Reserve before any compute: an insufficient wallet must refuse the call,
    // not pay for it after the fact. `Ok(None)` when the meter is off.
    let mut pending_credit_spend = match begin_embed_credit_spend(&state, &headers, &body, &input_hash) {
        Ok(pending) => pending,
        Err(problem) => return problem,
    };

    let text_refs = body.texts.iter().map(String::as_str).collect::<Vec<_>>();
    let embed_outcome = {
        let store = state.fact_store.read().await;
        embed_texts_with_store(&store, &body, &text_refs)
    };
    let (embeddings, actual_profile) = match embed_outcome {
        Ok(embedded) => embedded,
        Err((void_reason, problem)) => {
            if let Some(pending) = pending_credit_spend.take() {
                if let Err(err) = pending.release(void_reason) {
                    tracing::error!(error = %err, "compute-provider-credit-release-failed");
                    return compute_problem(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "COMPUTE_CREDIT_RELEASE_FAILED",
                        format!("credit reservation release failed: {err}"),
                        json!({ "capability": "compute:embed", "spend_applied": false }),
                    );
                }
            }
            return problem;
        }
    };

    if let Some(expected) = body.semantic_profile.as_ref() {
        if !profiles_compatible(expected, &actual_profile) {
            return semantic_profile_mismatch_problem(expected, &actual_profile);
        }
    }

    if let Err(detail) = validate_embeddings(&embeddings, body.texts.len(), &actual_profile) {
        return compute_problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "COMPUTE_INVALID_EMBEDDING_SHAPE",
            detail,
            json!({ "capability": "compute:embed", "availability": "degraded" }),
        );
    }

    let output_hash = match hash_json(&json!({
        "embeddings": &embeddings,
        "semantic_profile": &actual_profile,
    })) {
        Ok(hash) => hash,
        Err(detail) => {
            return compute_problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "COMPUTE_EMBED_HASH_FAILED",
                detail,
                json!({ "capability": "compute:embed" }),
            );
        }
    };
    // Every early return above this line drops an un-settled reservation, and
    // `PendingCreditSpend`'s `Drop` voids it — no compute failure can charge.
    // From here the work is done and owed, so settle before the receipt is minted
    // and stamp both with the result.
    let credit_spend = match pending_credit_spend.take() {
        Some(pending) => match pending.complete() {
            Ok(stamp) => Some(stamp),
            Err(err) => {
                tracing::error!(error = %err, "compute-provider-credit-spend-failed");
                return compute_problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "COMPUTE_CREDIT_SPEND_FAILED",
                    format!("credit spend failed: {err}"),
                    json!({ "capability": "compute:embed", "spend_applied": false }),
                );
            }
        },
        None => None,
    };

    let scoped_receipt_session = super::facts::scoped_session_id_for_http(&auth_ctx, COMPUTE_EMBED_RECEIPT_SESSION);
    let actor = caller_passport;
    let receipt_payload = ComputeEmbedReceiptPayload {
        schema: COMPUTE_EMBED_RECEIPT_SCHEMA,
        operation: "embed",
        input_hash: &input_hash,
        output_hash: &output_hash,
        text_count: body.texts.len(),
        semantic_profile_id: &actual_profile.profile_id,
        model: &actual_profile.model,
        dimensions: actual_profile.dimensions,
        credit_spend_receipt: credit_spend.as_ref().map(|spend| spend.receipt_id.as_str()),
        credits_spent: credit_spend.as_ref().map(|spend| spend.credits_spent),
        wallet_balance: credit_spend.as_ref().map(|spend| spend.wallet_balance),
    };
    let receipt_payload = match serde_json::to_value(receipt_payload) {
        Ok(payload) => payload,
        Err(err) => {
            tracing::error!(?err, "compute-provider-receipt-encode-failed");
            return compute_problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "COMPUTE_RECEIPT_FAILED",
                "Embedding computation completed, but its signed receipt could not be encoded.",
                json!({ "capability": "compute:embed" }),
            );
        }
    };
    let observation = super::observations::PostObservationBody {
        kind: "compute.embed".to_string(),
        provider: "corecruxd".to_string(),
        client_ts: None,
        payload: receipt_payload,
    };
    let (receipt, _tip) =
        match super::observations::append_one_durable(&state, &scoped_receipt_session, actor, observation, None) {
            Ok(receipt) => receipt,
            Err((_, detail)) => {
                tracing::error!(reason = %detail, "compute-provider-receipt-persist-failed");
                return compute_problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "COMPUTE_RECEIPT_FAILED",
                    "Embedding computation completed, but its signed receipt could not be persisted.",
                    json!({ "capability": "compute:embed" }),
                );
            }
        };

    Json(ComputeEmbedResponse {
        schema: COMPUTE_EMBED_RESPONSE_SCHEMA,
        embeddings,
        semantic_profile: actual_profile,
        receipt_id: receipt.observation_id,
        receipt_session_id: COMPUTE_EMBED_RECEIPT_SESSION,
        receipt: receipt.receipt,
        credit_spend_receipt: credit_spend.as_ref().map(|spend| spend.receipt_id.clone()),
        credits_spent: credit_spend.as_ref().map(|spend| spend.credits_spent),
        wallet_balance: credit_spend.as_ref().map(|spend| spend.wallet_balance),
    })
    .into_response()
}

/// Embed the batch under the store's live embedder.
///
/// Split out of the handler so its failure arms can name a void reason for an
/// open credit reservation instead of returning straight out of the handler and
/// leaving the release implicit.
#[allow(clippy::result_large_err)]
fn embed_texts_with_store(
    store: &corecrux_memory::FactStore,
    body: &ComputeEmbedRequest,
    text_refs: &[&str],
) -> EmbedOutcome {
    let profile_unavailable = || {
        (
            "compute_semantic_profile_unavailable",
            compute_problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "COMPUTE_SEMANTIC_PROFILE_UNAVAILABLE",
                "The configured embedding model did not publish a semantic profile.",
                json!({ "capability": "compute:embed", "availability": "degraded" }),
            ),
        )
    };
    let Some(preflight_profile) = store.semantic_profile() else {
        return Err(profile_unavailable());
    };
    if let Some(expected) = body.semantic_profile.as_ref() {
        if known_profile_incompatible(expected, &preflight_profile) {
            return Err((
                "compute_semantic_profile_mismatch",
                semantic_profile_mismatch_problem(expected, &preflight_profile),
            ));
        }
    }
    let embeddings = match store.try_embed_texts(text_refs) {
        Ok(Some(embeddings)) => embeddings,
        Ok(None) => {
            return Err((
                "compute_embedder_unavailable",
                compute_problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "COMPUTE_EMBEDDER_UNAVAILABLE",
                    "Compute provider is enabled, but no embedding model is initialized.",
                    json!({ "capability": "compute:embed", "availability": "degraded" }),
                ),
            ));
        }
        Err(err) => {
            tracing::warn!(error = %err, text_count = text_refs.len(), "compute-provider-embed-failed");
            return Err((
                "compute_embed_failed",
                compute_problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "COMPUTE_EMBED_FAILED",
                    "The configured embedding model failed to produce embeddings.",
                    json!({ "capability": "compute:embed", "availability": "degraded" }),
                ),
            ));
        }
    };
    let Some(profile) = store.semantic_profile() else {
        return Err(profile_unavailable());
    };
    Ok((embeddings, profile))
}

/// Reserve one `dense_managed` credit for this call, or `Ok(None)` when the
/// credit meter is switched off.
///
/// Structurally parallel to `http::gpu1`'s `begin_rerank_credit_spend`. It
/// deliberately omits that function's RCX-router checks: on the rerank bridge
/// the daemon spends its *own* tenant's entitlement on outbound compute, while
/// here the daemon is the provider billing a *remote* caller's tenant, so the
/// local router token names the wrong party. The quote's tenant is authorised
/// against the caller's credential instead (C5).
#[allow(clippy::result_large_err)]
fn begin_embed_credit_spend(
    state: &AppState,
    headers: &HeaderMap,
    body: &ComputeEmbedRequest,
    payload_hash: &str,
) -> Result<Option<PendingCreditSpend>, Response> {
    let Some(meter) = state.credit_meter.clone() else {
        return Ok(None);
    };

    let capability = rcx_capability_token::corecrux_lane_capability(COMPUTE_EMBED_LANE_SLUG);
    // Priced per call, not per text: the lane is minted per call and the request
    // is already capped at COMPUTE_EMBED_MAX_TEXTS, which bounds the batch.
    let expected_credits = rcx_capability_token::corecrux_lane_credit_cost(COMPUTE_EMBED_LANE_SLUG, 0);
    let Some(quote) = body.credit_quote.clone() else {
        return Err(credit_quote_problem(
            "credit_quote is required when CORECRUXD_CREDIT_METER=1",
            None,
            crate::auth::http_tenant_selector(headers)
                .as_deref()
                .unwrap_or_default(),
            &capability,
            expected_credits,
        ));
    };
    if let Err(err) = quote.validate() {
        return Err(credit_quote_problem(
            format!("credit_quote is invalid: {err}"),
            Some(json!(quote)),
            &quote.tenant_id,
            &capability,
            expected_credits,
        ));
    }
    // C5: the quote binds a tenant, so the credential must be authorised for
    // that tenant. A quote for tenant A on tenant B's token is a 403 here,
    // never a silent re-bind of the charge onto whoever called.
    if let Err(problem) =
        crate::auth::require_http_scopes_for_tenant(&state.auth, headers, &[COMPUTE_EMBED_SCOPE], &quote.tenant_id)
    {
        return Err(problem.into_response());
    }
    if quote.capability != capability || quote.credits != expected_credits {
        return Err(credit_quote_problem(
            "credit quote does not match the dense_managed lane capability or its pinned price",
            Some(json!(quote)),
            &quote.tenant_id,
            &capability,
            expected_credits,
        ));
    }

    let signing_key = match crux_session::LocalPassportKey::from_path(&state.passport_key_path) {
        Ok(key) => key,
        Err(err) => {
            tracing::error!(error = %err, "metered embed passport signing key load failed");
            return Err(compute_problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "COMPUTE_CREDIT_SIGNING_KEY_UNAVAILABLE",
                "passport signing key unavailable",
                json!({ "capability": "compute:embed", "spend_applied": false }),
            ));
        }
    };
    if signing_key.passport_fpr() != state.passport_fpr {
        return Err(compute_problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "COMPUTE_CREDIT_SIGNER_MISMATCH",
            format!(
                "passport signer mismatch: state={}, key={}",
                state.passport_fpr,
                signing_key.passport_fpr()
            ),
            json!({ "capability": "compute:embed", "spend_applied": false }),
        ));
    }

    let reservation = {
        let mut guard = match meter.lock() {
            Ok(guard) => guard,
            Err(_) => {
                // Fail closed: a poisoned meter must never serve free compute.
                return Err(compute_problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "COMPUTE_CREDIT_METER_UNAVAILABLE",
                    "credit meter lock poisoned",
                    json!({ "capability": "compute:embed", "spend_applied": false }),
                ));
            }
        };
        match guard.reserve(&quote.tenant_id, &quote.operation_id, quote.credits, payload_hash) {
            Ok(reservation) => reservation,
            Err(err) => return Err(credit_meter_problem(err)),
        }
    };

    Ok(Some(PendingCreditSpend {
        meter,
        quote,
        reservation,
        signing_key,
        active: true,
    }))
}

/// Structured "your pinned quote is missing or wrong" answer.
///
/// Same body shape `/v1/gpu1/rerank` returns, so a client that already knows how
/// to recover from a bad rerank quote recovers the same way here: the problem
/// names the tenant, the lane capability, and the credits the quote must pin.
fn credit_quote_problem(
    detail: impl Into<String>,
    quote: Option<Value>,
    tenant_id: &str,
    capability: &str,
    credits: u64,
) -> Response {
    ProblemResponse(ProblemDetails::bad_request(detail).with_extensions(json!({
        "quote": quote,
        "expected_quote": {
            "tenant_id": tenant_id,
            "capability": capability,
            "credits": credits,
        },
    })))
    .into_response()
}

/// Meter-error → problem mapping, mirroring the gpu1 bridge so the two metered
/// doors answer the same failure with the same status and extensions.
fn credit_meter_problem(err: crate::credit_meter::CreditMeterError) -> Response {
    match err {
        crate::credit_meter::CreditMeterError::InsufficientCredit {
            tenant_id,
            cost,
            available,
        } => ProblemResponse(
            ProblemDetails::new(
                StatusCode::PAYMENT_REQUIRED.as_u16(),
                "https://errors.cuecrux.com/payment-required/insufficient-credits",
                "Insufficient Credits",
            )
            .with_detail(format!(
                "metered embed requires {cost} credits; wallet has {available} available"
            ))
            .with_extensions(json!({
                "capability": "compute:embed",
                "tenant_id": tenant_id,
                "required_credits": cost,
                "available_credits": available,
                "spend_applied": false,
            })),
        )
        .into_response(),
        crate::credit_meter::CreditMeterError::OperationPayloadMismatch {
            tenant_id,
            operation_id,
            existing_payload_hash,
            requested_payload_hash,
        } => ProblemResponse(
            ProblemDetails::new(
                StatusCode::CONFLICT.as_u16(),
                "https://errors.cuecrux.com/conflict/credit-operation-payload-mismatch",
                "Credit Operation Payload Mismatch",
            )
            .with_detail(format!(
                "operation {operation_id} for tenant {tenant_id} is already reserved for a different payload"
            ))
            .with_extensions(json!({
                "capability": "compute:embed",
                "tenant_id": tenant_id,
                "operation_id": operation_id,
                "existing_payload_hash": existing_payload_hash,
                "requested_payload_hash": requested_payload_hash,
                "spend_applied": false,
            })),
        )
        .into_response(),
        crate::credit_meter::CreditMeterError::OperationAlreadySpent {
            tenant_id,
            operation_id,
            spend_receipt,
        } => ProblemResponse(
            ProblemDetails::new(
                StatusCode::CONFLICT.as_u16(),
                "https://errors.cuecrux.com/conflict/credit-operation-already-spent",
                "Credit Operation Already Spent",
            )
            .with_detail(format!(
                "operation {operation_id} for tenant {tenant_id} was already spent"
            ))
            .with_extensions(json!({
                "capability": "compute:embed",
                "tenant_id": tenant_id,
                "operation_id": operation_id,
                "spend_receipt": spend_receipt,
                "spend_applied": false,
            })),
        )
        .into_response(),
        err => {
            let status = match err {
                crate::credit_meter::CreditMeterError::OperationConflict { .. }
                | crate::credit_meter::CreditMeterError::ReservationVoided { .. }
                | crate::credit_meter::CreditMeterError::TenantMismatch { .. } => StatusCode::CONFLICT,
                crate::credit_meter::CreditMeterError::ReservationNotFound { .. } => StatusCode::NOT_FOUND,
                crate::credit_meter::CreditMeterError::InvalidQuote { .. }
                | crate::credit_meter::CreditMeterError::QuoteReservationMismatch { .. } => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            ProblemResponse(
                ProblemDetails::new(
                    status.as_u16(),
                    "https://errors.cuecrux.com/credit-meter-error",
                    "Credit Meter Error",
                )
                .with_detail(err.to_string())
                .with_extensions(json!({ "capability": "compute:embed", "spend_applied": false })),
            )
            .into_response()
        }
    }
}

fn validate_request(body: &ComputeEmbedRequest) -> Result<(), String> {
    if body.texts.is_empty() {
        return Err("texts must contain at least one item".to_string());
    }
    if body.texts.len() > COMPUTE_EMBED_MAX_TEXTS {
        return Err(format!(
            "texts contains {} items; maximum is {COMPUTE_EMBED_MAX_TEXTS}",
            body.texts.len()
        ));
    }
    let mut total_bytes = 0usize;
    for text in &body.texts {
        if text.trim().is_empty() {
            return Err("texts must not contain an empty item".to_string());
        }
        if text.len() > COMPUTE_EMBED_MAX_TEXT_BYTES {
            return Err(format!(
                "one text is {} bytes; maximum is {COMPUTE_EMBED_MAX_TEXT_BYTES}",
                text.len()
            ));
        }
        total_bytes = total_bytes.saturating_add(text.len());
    }
    if total_bytes > COMPUTE_EMBED_MAX_TOTAL_TEXT_BYTES {
        return Err(format!(
            "texts total {total_bytes} bytes; maximum is {COMPUTE_EMBED_MAX_TOTAL_TEXT_BYTES}"
        ));
    }
    Ok(())
}

fn validate_embeddings(
    embeddings: &[Vec<f32>],
    expected_count: usize,
    profile: &SemanticProfile,
) -> Result<(), String> {
    if embeddings.len() != expected_count {
        return Err(format!(
            "embedding model returned {} vectors for {expected_count} texts",
            embeddings.len()
        ));
    }
    if profile.dimensions == 0 {
        return Err("embedding model reported zero dimensions".to_string());
    }
    if embeddings.iter().any(|embedding| {
        embedding.len() != profile.dimensions || embedding.iter().any(|component| !component.is_finite())
    }) {
        return Err(format!(
            "embedding model returned a non-finite or wrong-sized vector; expected {} dimensions",
            profile.dimensions
        ));
    }
    Ok(())
}

fn profiles_compatible(expected: &SemanticProfile, actual: &SemanticProfile) -> bool {
    expected.model == actual.model && expected.dimensions == actual.dimensions
}

fn known_profile_incompatible(expected: &SemanticProfile, actual: &SemanticProfile) -> bool {
    expected.model != actual.model || (actual.dimensions != 0 && expected.dimensions != actual.dimensions)
}

fn semantic_profile_mismatch_problem(expected: &SemanticProfile, actual: &SemanticProfile) -> Response {
    compute_problem(
        StatusCode::CONFLICT,
        "SEMANTIC_PROFILE_MISMATCH",
        "Provider semantic profile does not match the requested model and dimensions; no embeddings were returned.",
        json!({
            "capability": "compute:embed",
            "expected": {
                "model": expected.model,
                "dimensions": expected.dimensions,
            },
            "actual": {
                "model": actual.model,
                "dimensions": actual.dimensions,
            },
        }),
    )
}

fn hash_json<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|err| format!("compute payload canonicalization failed: {err}"))?;
    Ok(format!("blake3:{}", blake3::hash(&bytes).to_hex()))
}

fn compute_problem(status: StatusCode, code: &'static str, detail: impl Into<String>, extensions: Value) -> Response {
    let title = match status {
        StatusCode::BAD_REQUEST => "Invalid Compute Request",
        StatusCode::CONFLICT => "Semantic Profile Conflict",
        StatusCode::SERVICE_UNAVAILABLE => "Compute Capability Unavailable",
        _ => "Compute Provider Error",
    };
    ProblemResponse(
        ProblemDetails::new(
            status.as_u16(),
            format!("https://errors.cuecrux.com/{}", code.to_ascii_lowercase()),
            title,
        )
        .with_detail(detail)
        .with_extensions(merge_code(extensions, code)),
    )
    .into_response()
}

fn merge_code(mut extensions: Value, code: &'static str) -> Value {
    if let Value::Object(fields) = &mut extensions {
        fields.insert("code".to_string(), Value::String(code.to_string()));
    }
    extensions
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::{Path as AxumPath, Query};
    use axum::http::{header, HeaderValue, Request};
    use axum::response::IntoResponse;
    use tower::ServiceExt;

    fn scoped_headers(scope: &'static str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", HeaderValue::from_static(scope));
        headers
    }

    fn scoped_passport_headers(scope: &'static str, passport: &'static str) -> HeaderMap {
        let mut headers = scoped_headers(scope);
        headers.insert("x-corecrux-passport-id", HeaderValue::from_static(passport));
        headers
    }

    fn provider_state() -> AppState {
        let mut state = super::super::tests::test_app_state_with_auth(8, crate::auth::AuthMode::DevScopes);
        state.compute_provider_enabled = true;
        let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path)
            .expect("create provider receipt signing key");
        state.passport_fpr = key.passport_fpr().to_string();
        state.passport_public_key_hex = key.public_key_hex().to_string();
        state
    }

    async fn json_body(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), COMPUTE_EMBED_MAX_REQUEST_BYTES)
            .await
            .expect("read response body");
        serde_json::from_slice(&bytes).expect("decode response JSON")
    }

    fn request(text: &str) -> ComputeEmbedRequest {
        ComputeEmbedRequest {
            texts: vec![text.to_string()],
            semantic_profile: None,
            credit_quote: None,
        }
    }

    #[tokio::test]
    async fn provider_embed_returns_profile_and_resolvable_signed_receipt() {
        const SECRET_TEXT: &str = "receipt plaintext must not persist";
        const CALLER: &str = "provider-caller";
        let state = provider_state();
        state
            .fact_store
            .write()
            .await
            .set_embedder(Box::<corecrux_memory::embeddings::LocalHashEmbedder>::default());

        let response = post_compute_embed(
            State(state.clone()),
            scoped_passport_headers(COMPUTE_EMBED_SCOPE, CALLER),
            Json(request(SECRET_TEXT)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["schema"], COMPUTE_EMBED_RESPONSE_SCHEMA);
        assert_eq!(body["semantic_profile"]["model"], "crux-local-hash-v1");
        assert_eq!(body["semantic_profile"]["dimensions"], 256);
        assert_eq!(body["embeddings"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["receipt"]["alg"], "ed25519");
        assert_eq!(body["receipt"]["signed_by"], state.passport_fpr);
        let receipt_id = body["receipt_id"].as_str().expect("receipt id");

        let resolved = super::super::observations::get_observations(
            State(state.clone()),
            scoped_passport_headers("query:read", CALLER),
            AxumPath(COMPUTE_EMBED_RECEIPT_SESSION.to_string()),
            Query(super::super::observations::ListObservationsQuery {
                since: None,
                limit: Some(10),
                provider: Some("corecruxd".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(resolved.status(), StatusCode::OK);
        let resolved_body = json_body(resolved).await;
        assert!(resolved_body["observations"].as_array().is_some_and(|records| {
            records
                .iter()
                .any(|record| record["observation_id"].as_str() == Some(receipt_id))
        }));

        let stored_session = crux_mcp::scope::scoped_session_id(Some(CALLER), COMPUTE_EMBED_RECEIPT_SESSION);
        let receipt_file = super::super::observations::observation_file_path(&state.data_dir, &stored_session);
        let persisted = std::fs::read_to_string(receipt_file).expect("read persisted receipt");
        assert!(
            !persisted.contains(SECRET_TEXT),
            "receipt must contain hashes, never caller text"
        );
        assert!(persisted.contains("compute.embed"));
    }

    #[tokio::test]
    async fn provider_embed_rejects_unauthenticated_and_wrong_scope() {
        let state = provider_state();
        state
            .fact_store
            .write()
            .await
            .set_embedder(Box::<corecrux_memory::embeddings::LocalHashEmbedder>::default());

        let unauthenticated = post_compute_embed(State(state.clone()), HeaderMap::new(), Json(request("alpha"))).await;
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

        let wrong_scope = post_compute_embed(
            State(state.clone()),
            scoped_headers("query:read"),
            Json(request("alpha")),
        )
        .await;
        assert_eq!(wrong_scope.status(), StatusCode::FORBIDDEN);

        let missing_passport = post_compute_embed(
            State(state),
            scoped_headers(COMPUTE_EMBED_SCOPE),
            Json(request("alpha")),
        )
        .await;
        assert_eq!(missing_passport.status(), StatusCode::FORBIDDEN);
        let body = json_body(missing_passport).await;
        assert_eq!(body["code"], "COMPUTE_CALLER_PASSPORT_REQUIRED");
    }

    #[tokio::test]
    async fn provider_embed_flag_off_is_explicit_not_found_or_not_implemented() {
        let mut state = provider_state();
        state.compute_provider_enabled = false;
        let cases = std::sync::Arc::new(tokio::sync::RwLock::new(corecrux_memory::CaseStore::new()));
        let app = super::super::router_with_route_auth(state, cases, super::super::route_auth::RouteAuthMode::Enforce);
        let payload = serde_json::to_vec(&request("alpha")).expect("encode request");
        let request = Request::builder()
            .method("POST")
            .uri("/v1/compute/embed")
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-corecrux-scopes", COMPUTE_EMBED_SCOPE)
            .header("x-corecrux-passport-id", "disabled-caller")
            .body(axum::body::Body::from(payload))
            .expect("build request");
        let response = app.oneshot(request).await.expect("provider response");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_ne!(response.status(), StatusCode::NOT_FOUND);
        assert_ne!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let body = json_body(response).await;
        assert_eq!(body["code"], "COMPUTE_PROVIDER_DISABLED");
    }

    #[tokio::test]
    async fn provider_requested_profile_mismatch_returns_no_embeddings() {
        let state = provider_state();
        state
            .fact_store
            .write()
            .await
            .set_embedder(Box::<corecrux_memory::embeddings::LocalHashEmbedder>::default());
        let mut body = request("alpha");
        body.semantic_profile = Some(SemanticProfile::from_parts(
            "wrong-model",
            256,
            "whitespace_ngram_v1",
            "none",
            "l2",
        ));

        let response = post_compute_embed(
            State(state),
            scoped_passport_headers(COMPUTE_EMBED_SCOPE, "mismatch-caller"),
            Json(body),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = json_body(response).await;
        assert_eq!(body["code"], "SEMANTIC_PROFILE_MISMATCH");
        assert!(body.get("embeddings").is_none());
    }

    // ── credit metering (ExecPlan compute-embed-credit-metering-2026-08-06) ──
    //
    // The matrix these cover, in plan order: meter-off is byte-identical (1),
    // a valid quote spends exactly once (2), an absent (3) or invalid (4) quote
    // is a structured refusal with no hold left open, an embedder failure voids
    // the hold (5), a mid-flight early return voids it via `Drop` (6), a
    // foreign tenant is 403 (7), an empty wallet refuses before any compute
    // (8), a replayed spent quote does not double-charge (9), the lane price is
    // pinned (10), and no caller text reaches the receipt or the meter log (11).

    use corecrux_memory::embeddings::{Embedder, EmbeddingError};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const TEST_TENANT: &str = "tenant-a";
    const TEST_HS256_SECRET: &str = "0123456789abcdef0123456789abcdef";

    fn test_profile(model: &str) -> SemanticProfile {
        SemanticProfile::from_parts(model, 256, "whitespace_ngram_v1", "none", "l2")
    }

    /// Fails every batch, to exercise the void-on-embedder-failure arm.
    #[derive(Debug)]
    struct FailingEmbedder;

    impl Embedder for FailingEmbedder {
        fn embed_batch(&self, _texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
            Err(EmbeddingError::Model("deliberate test embedder failure".to_string()))
        }
        fn dimensions(&self) -> usize {
            256
        }
        fn model(&self) -> &str {
            "crux-test-failing-v1"
        }
        fn semantic_profile(&self) -> SemanticProfile {
            test_profile("crux-test-failing-v1")
        }
    }

    /// Succeeds, but returns vectors of the wrong width so the handler bails at
    /// `validate_embeddings` — an early return with no explicit release, which
    /// is precisely the path `Drop` has to cover.
    #[derive(Debug)]
    struct WrongShapeEmbedder;

    impl Embedder for WrongShapeEmbedder {
        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
            Ok(texts.iter().map(|_| vec![0.5f32; 8]).collect())
        }
        fn dimensions(&self) -> usize {
            256
        }
        fn model(&self) -> &str {
            "crux-test-wrong-shape-v1"
        }
        fn semantic_profile(&self) -> SemanticProfile {
            test_profile("crux-test-wrong-shape-v1")
        }
    }

    /// Counts batches so a test can assert compute never ran.
    #[derive(Debug)]
    struct CountingEmbedder(Arc<AtomicUsize>);

    impl Embedder for CountingEmbedder {
        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(texts.iter().map(|_| vec![0.25f32; 256]).collect())
        }
        fn dimensions(&self) -> usize {
            256
        }
        fn model(&self) -> &str {
            "crux-test-counting-v1"
        }
        fn semantic_profile(&self) -> SemanticProfile {
            test_profile("crux-test-counting-v1")
        }
    }

    fn embed_quote(operation_id: &str) -> crate::credit_meter::PinnedCreditQuote {
        crate::credit_meter::PinnedCreditQuote::new(
            format!("quote-{operation_id}"),
            TEST_TENANT,
            operation_id,
            rcx_capability_token::corecrux_lane_capability(COMPUTE_EMBED_LANE_SLUG),
            rcx_capability_token::corecrux_lane_credit_cost(COMPUTE_EMBED_LANE_SLUG, 0),
            format!("blake3:{}", blake3::hash(b"dense-managed-price-list-v1").to_hex()),
        )
    }

    fn metered_request(text: &str, quote: crate::credit_meter::PinnedCreditQuote) -> ComputeEmbedRequest {
        ComputeEmbedRequest {
            texts: vec![text.to_string()],
            semantic_profile: None,
            credit_quote: Some(quote),
        }
    }

    fn seed_meter(state: &mut AppState, wallet_balance: u64) {
        let mut meter = crate::credit_meter::CreditMeterStore::open(state.data_dir.join("credit-meter.jsonl"))
            .expect("open credit meter");
        meter
            .seed_comped_wallet(TEST_TENANT, wallet_balance, "seed-embed-tests")
            .expect("seed comped wallet");
        state.credit_meter = Some(std::sync::Arc::new(std::sync::Mutex::new(meter)));
    }

    fn metered_provider_state(wallet_balance: u64) -> AppState {
        let mut state = provider_state();
        seed_meter(&mut state, wallet_balance);
        state
    }

    async fn set_embedder(state: &AppState, embedder: Box<dyn Embedder>) {
        state.fact_store.write().await.set_embedder(embedder);
    }

    fn available_credits(state: &AppState) -> u64 {
        state
            .credit_meter
            .as_ref()
            .expect("credit meter")
            .lock()
            .expect("credit meter lock")
            .available_balance(TEST_TENANT)
    }

    /// 1 — meter off: the response and the persisted receipt carry no spend
    /// fields, and a client that sends a quote anyway is not charged for it.
    #[tokio::test]
    async fn meter_off_response_and_receipt_are_unchanged() {
        const CALLER: &str = "unmetered-caller";
        let state = provider_state();
        assert!(state.credit_meter.is_none(), "this test pins the meter-off contract");
        set_embedder(&state, Box::<corecrux_memory::embeddings::LocalHashEmbedder>::default()).await;

        for body in [request("alpha"), metered_request("alpha", embed_quote("ignored"))] {
            let response = post_compute_embed(
                State(state.clone()),
                scoped_passport_headers(COMPUTE_EMBED_SCOPE, CALLER),
                Json(body),
            )
            .await;
            assert_eq!(response.status(), StatusCode::OK);
            let body = json_body(response).await;
            let mut keys = body
                .as_object()
                .expect("object response")
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>();
            keys.sort_unstable();
            assert_eq!(
                keys,
                vec![
                    "embeddings",
                    "receipt",
                    "receipt_id",
                    "receipt_session_id",
                    "schema",
                    "semantic_profile",
                ],
                "meter-off response must carry exactly the pre-metering field set"
            );
        }

        let stored_session = crux_mcp::scope::scoped_session_id(Some(CALLER), COMPUTE_EMBED_RECEIPT_SESSION);
        let receipt_file = super::super::observations::observation_file_path(&state.data_dir, &stored_session);
        let persisted = std::fs::read_to_string(receipt_file).expect("read persisted receipt");
        assert!(
            !persisted.contains("credit_spend_receipt")
                && !persisted.contains("credits_spent")
                && !persisted.contains("wallet_balance"),
            "meter-off receipt must not gain spend fields"
        );
    }

    /// 2 — meter on with a valid quote: one credit leaves the wallet, one spend
    /// receipt comes back, and both the response and the observation receipt
    /// carry the stamp.
    #[tokio::test]
    async fn metered_embed_spends_one_credit_and_stamps_response_and_receipt() {
        const CALLER: &str = "metered-caller";
        let state = metered_provider_state(10);
        set_embedder(&state, Box::<corecrux_memory::embeddings::LocalHashEmbedder>::default()).await;

        let response = post_compute_embed(
            State(state.clone()),
            scoped_passport_headers(COMPUTE_EMBED_SCOPE, CALLER),
            Json(metered_request("alpha", embed_quote("embed-success"))),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await;
        assert_eq!(body["credits_spent"], 1);
        assert_eq!(body["wallet_balance"], 9);
        assert_eq!(body["embeddings"].as_array().map(Vec::len), Some(1));
        let spend_receipt = body["credit_spend_receipt"].as_str().expect("spend receipt id");
        assert!(spend_receipt.starts_with("crxspend_"));
        assert_eq!(available_credits(&state), 9);

        let stored_session = crux_mcp::scope::scoped_session_id(Some(CALLER), COMPUTE_EMBED_RECEIPT_SESSION);
        let receipt_file = super::super::observations::observation_file_path(&state.data_dir, &stored_session);
        let persisted = std::fs::read_to_string(receipt_file).expect("read persisted receipt");
        assert!(
            persisted.contains(spend_receipt),
            "the observation receipt must name the spend it was billed under"
        );
        // Schema stays v1: the stamp is additive, not a new receipt shape.
        assert!(persisted.contains(COMPUTE_EMBED_RECEIPT_SCHEMA));
    }

    /// 3 — meter on, quote absent: a structured refusal that names what to pin,
    /// not a bare 400.
    #[tokio::test]
    async fn metered_embed_without_quote_returns_structured_quote_problem() {
        let state = metered_provider_state(10);
        set_embedder(&state, Box::<corecrux_memory::embeddings::LocalHashEmbedder>::default()).await;

        let response = post_compute_embed(
            State(state.clone()),
            scoped_passport_headers(COMPUTE_EMBED_SCOPE, "quoteless-caller"),
            Json(request("alpha")),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await;
        assert_eq!(body["expected_quote"]["capability"], "corecrux.lane.dense_managed");
        assert_eq!(body["expected_quote"]["credits"], 1);
        assert!(body["expected_quote"].get("tenant_id").is_some());
        assert_eq!(body["quote"], Value::Null);
        assert_eq!(available_credits(&state), 10);
    }

    /// 4 — meter on, quote malformed or mispriced: refused, and nothing is held.
    #[tokio::test]
    async fn metered_embed_invalid_quote_refuses_and_leaves_no_reservation() {
        let state = metered_provider_state(10);
        set_embedder(&state, Box::<corecrux_memory::embeddings::LocalHashEmbedder>::default()).await;

        let mut malformed = embed_quote("embed-malformed");
        malformed.schema = "crux.credit.quote.v99".to_string();
        let response = post_compute_embed(
            State(state.clone()),
            scoped_passport_headers(COMPUTE_EMBED_SCOPE, "malformed-caller"),
            Json(metered_request("alpha", malformed)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = json_body(response).await;
        assert!(body["detail"]
            .as_str()
            .expect("detail")
            .contains("credit_quote is invalid"));

        let mut mispriced = embed_quote("embed-mispriced");
        mispriced.credits = 7;
        let response = post_compute_embed(
            State(state.clone()),
            scoped_passport_headers(COMPUTE_EMBED_SCOPE, "mispriced-caller"),
            Json(metered_request("alpha", mispriced)),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(available_credits(&state), 10, "a refused quote must hold nothing");
    }

    /// 5 — the embedder fails after the hold is taken: the hold is voided
    /// explicitly and the wallet is whole.
    #[tokio::test]
    async fn metered_embed_voids_reservation_when_embedder_fails() {
        let state = metered_provider_state(10);
        set_embedder(&state, Box::new(FailingEmbedder)).await;

        let response = post_compute_embed(
            State(state.clone()),
            scoped_passport_headers(COMPUTE_EMBED_SCOPE, "failing-caller"),
            Json(metered_request("alpha", embed_quote("embed-failure"))),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json_body(response).await;
        assert_eq!(body["code"], "COMPUTE_EMBED_FAILED");
        assert!(body.get("credit_spend_receipt").is_none());
        assert_eq!(available_credits(&state), 10, "a failed embed must not charge");
    }

    /// 6 — the handler early-returns after the hold with no explicit release
    /// (bad vector shape). `Drop` has to void it.
    #[tokio::test]
    async fn metered_embed_drop_voids_reservation_on_early_return() {
        let state = metered_provider_state(10);
        set_embedder(&state, Box::new(WrongShapeEmbedder)).await;

        let response = post_compute_embed(
            State(state.clone()),
            scoped_passport_headers(COMPUTE_EMBED_SCOPE, "wrong-shape-caller"),
            Json(metered_request("alpha", embed_quote("embed-early-return"))),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = json_body(response).await;
        assert_eq!(body["code"], "COMPUTE_INVALID_EMBEDDING_SHAPE");
        assert_eq!(
            available_credits(&state),
            10,
            "Drop must void a reservation the handler abandoned"
        );
    }

    /// 7 — a quote for another tenant on this credential is a 403, never a
    /// silent re-bind of the charge. Needs a real tenant-bearing credential:
    /// dev-scopes mode authorises every tenant by construction.
    #[serial_test::serial]
    #[tokio::test]
    async fn metered_embed_quote_tenant_mismatch_is_forbidden() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", TEST_HS256_SECRET);
        std::env::remove_var("CORECRUXD_ALLOW_WEAK_HS256_SECRET");
        std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-test");
        std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");
        let auth = crate::auth::Authz::from_env(crate::auth::AuthMode::JwtHs256).expect("jwt auth from env");
        let bearer_for = |tenant: &str| {
            let claims = json!({
                "scope": COMPUTE_EMBED_SCOPE,
                "tenant_id": tenant,
                "passport_id": format!("{tenant}-caller"),
                "iss": "corecrux-test",
                "aud": "corecrux",
                "exp": std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_secs()
                    + 3600,
            });
            let token = encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
            )
            .expect("encode test jwt");
            let mut headers = HeaderMap::new();
            headers.insert(
                header::AUTHORIZATION,
                format!("Bearer {token}").parse().expect("bearer header"),
            );
            headers
        };

        let mut state = metered_provider_state(10);
        state.auth = auth;
        set_embedder(&state, Box::<corecrux_memory::embeddings::LocalHashEmbedder>::default()).await;

        // The quote pins tenant-a; this credential owns tenant-b.
        let refused = post_compute_embed(
            State(state.clone()),
            bearer_for("tenant-b"),
            Json(metered_request("alpha", embed_quote("embed-foreign-tenant"))),
        )
        .await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            available_credits(&state),
            10,
            "a foreign-tenant quote must not touch that tenant's wallet"
        );

        // Positive control: the same call on tenant-a's own credential is
        // served, so the 403 above is the tenant binding and not the scope.
        let allowed = post_compute_embed(
            State(state.clone()),
            bearer_for(TEST_TENANT),
            Json(metered_request("alpha", embed_quote("embed-own-tenant"))),
        )
        .await;
        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(available_credits(&state), 9);

        std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
        std::env::remove_var("CORECRUXD_JWT_ISS");
        std::env::remove_var("CORECRUXD_JWT_AUD");
    }

    /// 8 — an empty wallet is refused before any embedding runs, so the
    /// giveaway a 402 is meant to prevent never happens.
    #[tokio::test]
    async fn metered_embed_insufficient_balance_refuses_before_any_compute() {
        let state = metered_provider_state(0);
        let calls = Arc::new(AtomicUsize::new(0));
        set_embedder(&state, Box::new(CountingEmbedder(Arc::clone(&calls)))).await;

        let response = post_compute_embed(
            State(state.clone()),
            scoped_passport_headers(COMPUTE_EMBED_SCOPE, "broke-caller"),
            Json(metered_request("alpha", embed_quote("embed-insufficient"))),
        )
        .await;

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body = json_body(response).await;
        assert_eq!(body["required_credits"], 1);
        assert_eq!(body["available_credits"], 0);
        assert_eq!(body["spend_applied"], false);
        assert!(body.get("embeddings").is_none());
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "an unpayable request must not reach the embedder"
        );
        assert_eq!(available_credits(&state), 0);
    }

    /// 9 — replaying a spent quote is a conflict that names the original spend
    /// receipt; it does not charge twice.
    #[tokio::test]
    async fn metered_embed_replay_of_spent_quote_does_not_double_charge() {
        let state = metered_provider_state(10);
        let calls = Arc::new(AtomicUsize::new(0));
        set_embedder(&state, Box::new(CountingEmbedder(Arc::clone(&calls)))).await;
        let replay_quote = embed_quote("embed-replay");

        let first = post_compute_embed(
            State(state.clone()),
            scoped_passport_headers(COMPUTE_EMBED_SCOPE, "replay-caller"),
            Json(metered_request("alpha", replay_quote.clone())),
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);
        let first_body = json_body(first).await;
        let first_receipt = first_body["credit_spend_receipt"]
            .as_str()
            .expect("first spend receipt")
            .to_string();
        assert_eq!(first_body["wallet_balance"], 9);

        let replay = post_compute_embed(
            State(state.clone()),
            scoped_passport_headers(COMPUTE_EMBED_SCOPE, "replay-caller"),
            Json(metered_request("alpha", replay_quote)),
        )
        .await;

        assert_eq!(replay.status(), StatusCode::CONFLICT);
        let replay_body = json_body(replay).await;
        assert_eq!(
            replay_body["type"],
            "https://errors.cuecrux.com/conflict/credit-operation-already-spent"
        );
        assert_eq!(replay_body["spend_receipt"], first_receipt);
        assert_eq!(replay_body["spend_applied"], false);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the replay must not re-run compute");
        assert_eq!(available_credits(&state), 9, "the replay must not debit again");
    }

    /// 10 — the lane price is pinned. `dense_managed` is 1 credit/call and must
    /// stay in step with the TS minter's `CORECRUX_LANE_CREDIT_COST`; a change
    /// on either side without the other silently mis-bills.
    #[test]
    fn dense_managed_lane_cost_is_pinned_at_one_credit() {
        assert_eq!(
            rcx_capability_token::corecrux_lane_credit_cost(COMPUTE_EMBED_LANE_SLUG, 0),
            1
        );
        assert_eq!(
            rcx_capability_token::corecrux_lane_capability(COMPUTE_EMBED_LANE_SLUG),
            "corecrux.lane.dense_managed"
        );
        assert!(rcx_capability_token::CORECRUX_PREMIUM_LANE_SLUGS.contains(&COMPUTE_EMBED_LANE_SLUG));
    }

    /// 11 — billing must not become a second copy of the caller's text. Neither
    /// the observation receipt nor the credit-meter log may contain it.
    #[tokio::test]
    async fn metered_embed_keeps_caller_text_out_of_receipt_and_meter_log() {
        const SECRET_TEXT: &str = "metered plaintext must not persist";
        const CALLER: &str = "metered-privacy-caller";
        let state = metered_provider_state(10);
        set_embedder(&state, Box::<corecrux_memory::embeddings::LocalHashEmbedder>::default()).await;

        let response = post_compute_embed(
            State(state.clone()),
            scoped_passport_headers(COMPUTE_EMBED_SCOPE, CALLER),
            Json(metered_request(SECRET_TEXT, embed_quote("embed-privacy"))),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let stored_session = crux_mcp::scope::scoped_session_id(Some(CALLER), COMPUTE_EMBED_RECEIPT_SESSION);
        let receipt_file = super::super::observations::observation_file_path(&state.data_dir, &stored_session);
        let persisted = std::fs::read_to_string(receipt_file).expect("read persisted receipt");
        assert!(
            !persisted.contains(SECRET_TEXT),
            "receipt must contain hashes, never caller text"
        );

        let meter_log = std::fs::read_to_string(state.data_dir.join("credit-meter.jsonl")).expect("read meter log");
        assert!(
            !meter_log.contains(SECRET_TEXT),
            "the credit meter log must contain hashes, never caller text"
        );
    }
}
