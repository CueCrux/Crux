// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP CRUD for OpenAI integration: connect (POST API key), disconnect, status.

use super::{problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, State, StatusCode};

#[derive(Debug, serde::Deserialize)]
pub(super) struct ConnectOpenAiBody {
    pub api_key: String,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub default_model: Option<String>,
    /// When `true`, persist without contacting api.openai.com. Allows scripted
    /// setup (e.g. test harnesses) and avoids a hard fail on intermittent
    /// outbound connectivity. Production setups should leave this `false`.
    #[serde(default)]
    pub skip_verify: bool,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct UpdateOpenAiBody {
    #[serde(default)]
    pub default_model: Option<String>,
    #[serde(default)]
    pub organization_id: Option<String>,
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

pub(super) async fn get_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let status = crate::integrations_openai::read_status(&state.data_dir);
    (StatusCode::OK, Json(status)).into_response()
}

pub(super) async fn post_connect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ConnectOpenAiBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["integrations:install"]) {
        return problem.into_response();
    }
    let api_key = body.api_key.trim().to_string();
    if api_key.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "api_key must not be empty");
    }
    let organization_id = body
        .organization_id
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let (available_models, last_verified_at_unix_ms) = if body.skip_verify {
        (Vec::<String>::new(), None)
    } else {
        let key_for_verify = api_key.clone();
        let org_for_verify = organization_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            crate::integrations_openai::verify_api_key(&key_for_verify, org_for_verify.as_deref())
        })
        .await
        .map_err(|e| e.to_string());
        match result {
            Ok(Ok(verified)) => (verified.available_models, Some(now_unix_ms())),
            Ok(Err(err)) => return problem_response(StatusCode::BAD_REQUEST, err.to_string()),
            Err(err) => {
                return problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("verification join failed: {err}"),
                )
            }
        }
    };

    let envelope = crate::encrypted_secrets::seal(api_key.as_bytes(), state.integration_encryption_key.as_ref());
    let default_model = body
        .default_model
        .as_ref()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let creds = crate::integrations_openai::OpenAiCredentials {
        encrypted_api_key: envelope,
        organization_id,
        default_model,
        available_models,
        connected_at_unix_ms: now_unix_ms(),
        last_verified_at_unix_ms,
    };
    if let Err(err) = crate::integrations_openai::write_credentials(&state.data_dir, &creds) {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    let status = crate::integrations_openai::read_status(&state.data_dir);
    (StatusCode::OK, Json(status)).into_response()
}

pub(super) async fn post_disconnect(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["integrations:disable"]) {
        return problem.into_response();
    }
    if let Err(err) = crate::integrations_openai::delete_credentials(&state.data_dir) {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    (StatusCode::NO_CONTENT, ()).into_response()
}

pub(super) async fn patch_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UpdateOpenAiBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["integrations:install"]) {
        return problem.into_response();
    }
    let mut creds = match crate::integrations_openai::read_credentials(&state.data_dir) {
        Ok(c) => c,
        Err(_) => return problem_response(StatusCode::PRECONDITION_FAILED, "OpenAI not connected"),
    };
    if let Some(model) = body.default_model {
        let trimmed = model.trim();
        creds.default_model = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }
    if let Some(org) = body.organization_id {
        let trimmed = org.trim();
        creds.organization_id = if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        };
    }
    if let Err(err) = crate::integrations_openai::write_credentials(&state.data_dir, &creds) {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    let status = crate::integrations_openai::read_status(&state.data_dir);
    (StatusCode::OK, Json(status)).into_response()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ChatBody {
    /// Pass-through of OpenAI Chat Completions messages array.
    pub messages: serde_json::Value,
    /// Optional override; falls back to the saved default_model, then "gpt-4o-mini".
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub temperature: Option<f32>,
}

/// `POST /v1/integrations/openai/chat` — proxy a chat-completion call through
/// the daemon. The encrypted API key is decrypted in-process and never leaves
/// the box. Returns the upstream OpenAI response body verbatim, plus a
/// `_proxy` envelope with model used + duration so the console can render it
/// without re-parsing.
pub(super) async fn post_chat(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ChatBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["integrations:install"]) {
        return problem.into_response();
    }
    let creds = match crate::integrations_openai::read_credentials(&state.data_dir) {
        Ok(c) => c,
        Err(_) => {
            return problem_response(
                StatusCode::PRECONDITION_FAILED,
                "OpenAI not connected; POST /v1/integrations/openai/connect first",
            )
        }
    };
    let api_key = match crate::integrations_openai::decrypt_api_key(&creds, state.integration_encryption_key.as_ref()) {
        Ok(k) => k,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("decrypt failed: {err}")),
    };
    let model = body
        .model
        .clone()
        .or_else(|| creds.default_model.clone())
        .unwrap_or_else(|| "gpt-4o-mini".to_string());

    let mut payload = serde_json::json!({
        "model": model,
        "messages": body.messages,
    });
    if let Some(mt) = body.max_tokens {
        payload["max_tokens"] = serde_json::json!(mt);
    }
    if let Some(t) = body.temperature {
        payload["temperature"] = serde_json::json!(t);
    }

    let org_id = creds.organization_id.clone();
    let started = std::time::Instant::now();
    let result = tokio::task::spawn_blocking(move || -> Result<serde_json::Value, String> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(60)))
            .build()
            .into();
        let mut req = agent
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", &format!("Bearer {api_key}"))
            .header("Content-Type", "application/json")
            .header("User-Agent", "crux-daemon");
        if let Some(org) = org_id.as_deref().filter(|s| !s.trim().is_empty()) {
            req = req.header("OpenAI-Organization", org);
        }
        let mut response = req.send_json(payload).map_err(|e| e.to_string())?;
        let status = response.status().as_u16();
        let text = response.body_mut().read_to_string().map_err(|e| e.to_string())?;
        if status != 200 {
            return Err(format!(
                "openai returned {status}: {}",
                text.chars().take(512).collect::<String>()
            ));
        }
        serde_json::from_str::<serde_json::Value>(&text).map_err(|e| e.to_string())
    })
    .await;

    let duration_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(Ok(mut value)) => {
            value["_proxy"] = serde_json::json!({
                "model": model,
                "duration_ms": duration_ms,
            });
            (StatusCode::OK, Json(value)).into_response()
        }
        Ok(Err(err)) => problem_response(StatusCode::BAD_GATEWAY, err),
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {err}")),
    }
}
