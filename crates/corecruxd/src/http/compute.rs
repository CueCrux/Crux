// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Authenticated daemon-to-daemon embedding provider.
//!
//! The route is always mounted so a disabled provider is an explicit runtime
//! capability response, never a silent 404/501. Successful calls are bound to
//! a durable, signed observation receipt containing hashes and profile metadata
//! only; caller text is never copied into the audit log.

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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(super) struct ComputeEmbedRequest {
    pub texts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_profile: Option<SemanticProfile>,
}

#[derive(Debug, Serialize)]
struct ComputeEmbedResponse {
    schema: &'static str,
    embeddings: Vec<Vec<f32>>,
    semantic_profile: SemanticProfile,
    receipt_id: String,
    receipt_session_id: &'static str,
    receipt: super::observations::ReceiptEnvelopeV1,
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
    let text_refs = body.texts.iter().map(String::as_str).collect::<Vec<_>>();
    let (embeddings, actual_profile) = {
        let store = state.fact_store.read().await;
        let Some(preflight_profile) = store.semantic_profile() else {
            return compute_problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "COMPUTE_SEMANTIC_PROFILE_UNAVAILABLE",
                "The configured embedding model did not publish a semantic profile.",
                json!({ "capability": "compute:embed", "availability": "degraded" }),
            );
        };
        if let Some(expected) = body.semantic_profile.as_ref() {
            if known_profile_incompatible(expected, &preflight_profile) {
                return semantic_profile_mismatch_problem(expected, &preflight_profile);
            }
        }
        let embeddings = match store.try_embed_texts(&text_refs) {
            Ok(Some(embeddings)) => embeddings,
            Ok(None) => {
                return compute_problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "COMPUTE_EMBEDDER_UNAVAILABLE",
                    "Compute provider is enabled, but no embedding model is initialized.",
                    json!({ "capability": "compute:embed", "availability": "degraded" }),
                );
            }
            Err(err) => {
                tracing::warn!(error = %err, text_count = text_refs.len(), "compute-provider-embed-failed");
                return compute_problem(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "COMPUTE_EMBED_FAILED",
                    "The configured embedding model failed to produce embeddings.",
                    json!({ "capability": "compute:embed", "availability": "degraded" }),
                );
            }
        };
        let Some(profile) = store.semantic_profile() else {
            return compute_problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "COMPUTE_SEMANTIC_PROFILE_UNAVAILABLE",
                "The configured embedding model did not publish a semantic profile.",
                json!({ "capability": "compute:embed", "availability": "degraded" }),
            );
        };
        (embeddings, profile)
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
    })
    .into_response()
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
}
