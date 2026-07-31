// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Default-off credit-burn request path for comped wallets.

use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::credit_meter::{mint_spend_receipt, CreditMeterError, PinnedCreditQuote};

use super::{problem_response, require_http_any_scope, AppState, HeaderMap, State, StatusCode};

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct SpendCreditsBody {
    pub quote: PinnedCreditQuote,
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_credit_spend(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SpendCreditsBody>,
) -> Response {
    let Some(meter) = state.credit_meter.clone() else {
        return problem_response(
            StatusCode::NOT_FOUND,
            "credit meter disabled (set CORECRUXD_CREDIT_METER=1)".to_string(),
        );
    };
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    if let Err(err) = body.quote.validate() {
        return meter_error_response(err);
    }

    let key = match crux_session::LocalPassportKey::from_path(&state.passport_key_path) {
        Ok(key) => key,
        Err(err) => {
            tracing::error!(error = %err, "credit spend passport signing key load failed");
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "passport signing key unavailable");
        }
    };
    if key.passport_fpr() != state.passport_fpr {
        return problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "passport signer mismatch: state={}, key={}",
                state.passport_fpr,
                key.passport_fpr()
            ),
        );
    }

    let mut guard = match meter.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "credit meter lock poisoned".to_string(),
            );
        }
    };

    let payload_hash = hash_json(&json!(body));
    let reservation = match guard.reserve(
        &body.quote.tenant_id,
        &body.quote.operation_id,
        body.quote.credits,
        &payload_hash,
    ) {
        Ok(reservation) => reservation,
        Err(err) => return meter_error_response(err),
    };
    let receipt = match mint_spend_receipt(&body.quote, &reservation, &key) {
        Ok(receipt) => receipt,
        Err(err) => {
            let _ = guard.void_reservation(
                &body.quote.tenant_id,
                &reservation.reservation_id,
                "receipt_build_failed",
            );
            return meter_error_response(err);
        }
    };
    let spend = match guard.spend(
        &body.quote.tenant_id,
        &reservation.reservation_id,
        &receipt.body.receipt_id,
    ) {
        Ok(spend) => spend,
        Err(err) => return meter_error_response(err),
    };
    if spend.spend_receipt != receipt.body.receipt_id {
        return problem_response(
            StatusCode::CONFLICT,
            "operation already spent with a different pinned quote/spend receipt".to_string(),
        );
    }

    (
        StatusCode::CREATED,
        Json(json!({
            "reservation": reservation,
            "spend": spend,
            "credit_spend_receipt": receipt.body.receipt_id,
            "spend_receipt": receipt,
        })),
    )
        .into_response()
}

fn meter_error_response(err: CreditMeterError) -> Response {
    match err {
        CreditMeterError::InsufficientCredit { .. } => problem_response(StatusCode::PAYMENT_REQUIRED, err.to_string()),
        CreditMeterError::InvalidQuote { .. } | CreditMeterError::QuoteReservationMismatch { .. } => {
            problem_response(StatusCode::BAD_REQUEST, err.to_string())
        }
        CreditMeterError::OperationConflict { .. }
        | CreditMeterError::OperationPayloadMismatch { .. }
        | CreditMeterError::OperationAlreadySpent { .. }
        | CreditMeterError::ReservationVoided { .. }
        | CreditMeterError::TenantMismatch { .. } => problem_response(StatusCode::CONFLICT, err.to_string()),
        CreditMeterError::ReservationNotFound { .. } => problem_response(StatusCode::NOT_FOUND, err.to_string()),
        CreditMeterError::Io(_) | CreditMeterError::Json { .. } | CreditMeterError::ReceiptBuild(_) => {
            problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
        }
    }
}

fn hash_json(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use serde_json::Value;

    use super::*;

    async fn body_json(resp: Response) -> Value {
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("read body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    fn quote(credits: u64) -> PinnedCreditQuote {
        PinnedCreditQuote::new(
            "quote-1",
            "tenant-a",
            "op-1",
            "context.attestation",
            credits,
            format!("blake3:{}", blake3::hash(b"price-list").to_hex()),
        )
    }

    #[tokio::test]
    async fn disabled_credit_meter_is_invisible() {
        let state = crate::http::tests::test_app_state(10);
        let resp = post_credit_spend(
            State(state),
            HeaderMap::new(),
            Json(SpendCreditsBody { quote: quote(1) }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn spends_seeded_comped_wallet_and_returns_signed_receipt() {
        let mut state = crate::http::tests::test_app_state_with_auth(10, crate::auth::AuthMode::DevScopes);
        let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).expect("passport key");
        state.passport_fpr = key.passport_fpr().to_string();
        state.passport_public_key_hex = key.public_key_hex().to_string();
        let meter_path = state.data_dir.join("credit-meter.jsonl");
        let mut meter = crate::credit_meter::CreditMeterStore::open(&meter_path).expect("meter");
        meter.seed_comped_wallet("tenant-a", 10, "seed-1").expect("seed wallet");
        state.credit_meter = Some(std::sync::Arc::new(std::sync::Mutex::new(meter)));

        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "admin:write".parse().unwrap());
        let resp = post_credit_spend(
            State(state.clone()),
            headers,
            Json(SpendCreditsBody { quote: quote(4) }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_json(resp).await;
        assert_eq!(
            body["credit_spend_receipt"],
            body["spend_receipt"]["body"]["receipt_id"]
        );
        assert_eq!(body["spend"]["cost"], 4);
        assert_eq!(body["spend"]["balance_after"], 6);
        assert_eq!(body["spend_receipt"]["body"]["quote_id"], "quote-1");
        assert_eq!(body["spend_receipt"]["receipt"]["signed_by"], state.passport_fpr);
        assert!(body["spend_receipt"]["receipt"]["body_hash"]
            .as_str()
            .unwrap()
            .starts_with("blake3:"));

        let guard = state.credit_meter.as_ref().unwrap().lock().unwrap();
        assert_eq!(guard.available_balance("tenant-a"), 6);
        drop(guard);

        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "admin:write".parse().unwrap());
        let retry = post_credit_spend(
            State(state.clone()),
            headers,
            Json(SpendCreditsBody { quote: quote(4) }),
        )
        .await;
        assert_eq!(retry.status(), StatusCode::CONFLICT);
        let guard = state.credit_meter.as_ref().unwrap().lock().unwrap();
        assert_eq!(guard.available_balance("tenant-a"), 6);
    }

    #[tokio::test]
    async fn quote_mutation_retry_conflicts_without_second_debit() {
        let mut state = crate::http::tests::test_app_state_with_auth(10, crate::auth::AuthMode::DevScopes);
        let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).expect("passport key");
        state.passport_fpr = key.passport_fpr().to_string();
        state.passport_public_key_hex = key.public_key_hex().to_string();
        let meter_path = state.data_dir.join("credit-meter.jsonl");
        let mut meter = crate::credit_meter::CreditMeterStore::open(&meter_path).expect("meter");
        meter.seed_comped_wallet("tenant-a", 10, "seed-1").expect("seed wallet");
        state.credit_meter = Some(std::sync::Arc::new(std::sync::Mutex::new(meter)));

        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "admin:write".parse().unwrap());
        let resp = post_credit_spend(
            State(state.clone()),
            headers,
            Json(SpendCreditsBody { quote: quote(4) }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let mut changed_quote = quote(4);
        changed_quote.quote_id = "quote-2".to_string();
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "admin:write".parse().unwrap());
        let retry = post_credit_spend(
            State(state.clone()),
            headers,
            Json(SpendCreditsBody { quote: changed_quote }),
        )
        .await;
        assert_eq!(retry.status(), StatusCode::CONFLICT);
        let guard = state.credit_meter.as_ref().unwrap().lock().unwrap();
        assert_eq!(guard.available_balance("tenant-a"), 6);
    }

    #[tokio::test]
    async fn insufficient_credit_returns_payment_required_without_spend() {
        let mut state = crate::http::tests::test_app_state_with_auth(10, crate::auth::AuthMode::DevScopes);
        let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).expect("passport key");
        state.passport_fpr = key.passport_fpr().to_string();
        state.passport_public_key_hex = key.public_key_hex().to_string();
        let meter_path = state.data_dir.join("credit-meter.jsonl");
        let mut meter = crate::credit_meter::CreditMeterStore::open(&meter_path).expect("meter");
        meter.seed_comped_wallet("tenant-a", 3, "seed-1").expect("seed wallet");
        state.credit_meter = Some(std::sync::Arc::new(std::sync::Mutex::new(meter)));

        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "admin:write".parse().unwrap());
        let resp = post_credit_spend(
            State(state.clone()),
            headers,
            Json(SpendCreditsBody { quote: quote(4) }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
        let guard = state.credit_meter.as_ref().unwrap().lock().unwrap();
        assert_eq!(guard.available_balance("tenant-a"), 3);
    }

    /// A poisoned meter mutex must fail every metered request **closed** with
    /// 500 — never fall through to compute, and never debit. Recovering the
    /// lock here would mean serving from state whose last writer panicked
    /// mid-update, which on a money path can permit an untracked debit or
    /// compute without one.
    ///
    /// Guards `post_credit_spend`'s `meter.lock()` arm. There was no coverage
    /// for it before the credit-meter store moved to `corecrux-billing`; the
    /// fail-closed decision stays here in the handler, so it is pinned here.
    #[tokio::test]
    async fn poisoned_meter_fails_closed_without_spending() {
        let mut state = crate::http::tests::test_app_state_with_auth(10, crate::auth::AuthMode::DevScopes);
        let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).expect("passport key");
        state.passport_fpr = key.passport_fpr().to_string();
        state.passport_public_key_hex = key.public_key_hex().to_string();
        let meter_path = state.data_dir.join("credit-meter.jsonl");
        let mut meter = crate::credit_meter::CreditMeterStore::open(&meter_path).expect("meter");
        meter.seed_comped_wallet("tenant-a", 10, "seed-1").expect("seed wallet");
        let meter = std::sync::Arc::new(std::sync::Mutex::new(meter));
        state.credit_meter = Some(std::sync::Arc::clone(&meter));

        // Poison the mutex: a thread that panics while holding the guard.
        let poisoner = std::sync::Arc::clone(&meter);
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.lock().expect("lock for poisoning");
            panic!("deliberate panic to poison the credit meter");
        })
        .join();
        assert!(meter.is_poisoned(), "test setup must actually poison the mutex");

        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "admin:write".parse().unwrap());
        let resp = post_credit_spend(
            State(state.clone()),
            headers,
            Json(SpendCreditsBody { quote: quote(4) }),
        )
        .await;

        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a poisoned meter must fail closed, not serve the request"
        );
        // And nothing was debited: the wallet is untouched behind the poison.
        let guard = meter.lock().unwrap_or_else(|poison| poison.into_inner());
        assert_eq!(guard.available_balance("tenant-a"), 10, "fail-closed must not debit");
    }
}
