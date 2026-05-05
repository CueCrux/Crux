// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP CRUD for community extensions (M2 of the community-extensions
//! ExecPlan) — the contributor-facing surface of the registry.
//!
//! Routes mounted under `/v1/extensions/` plus a sub-tree at
//! `/v1/extensions/keys/` that the operator uses to manage trusted
//! signing keys. The `extension_registry` module owns persistence; this
//! module is purely the HTTP boundary.
//!
//! Scope posture (matches sibling `/v1/projects` routes):
//! - All reads require `admin:read`.
//! - Mutations also require `facts:write` (the registry persists records
//!   as private facts under `__extension__::*`).
//!
//! M3 + M4 will add `/v1/extensions/{id}/grants/...` for capability-token
//! issuance and tool dispatch; this milestone stops at install/list/get/
//! delete + the keyring sub-routes so the install path is end-to-end
//! testable without RCX integration.

use super::{problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Path, State, StatusCode};
use crux_integrations::{IntegrationManifest, TrustTier, TrustedKeyEntry, TrustedKeyring};

const ALLOW_UNSIGNED_ENV: &str = "CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED";

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn allow_unsigned_dev() -> bool {
    std::env::var(ALLOW_UNSIGNED_ENV)
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn extract_passport_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-corecrux-passport-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct RegisterExtensionBody {
    /// Signed (or unsigned, with bypass) integration manifest.
    pub manifest: IntegrationManifest,
}

/// `GET /v1/extensions` — list every installed extension.
pub(super) async fn list_extensions(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let installed = crate::extension_registry::list_extensions(&store);
    drop(store);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "count": installed.len(),
            "extensions": installed,
            "allow_unsigned_dev": allow_unsigned_dev(),
        })),
    )
        .into_response()
}

/// `GET /v1/extensions/{id}` — fetch one installed extension.
pub(super) async fn get_extension(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let found = crate::extension_registry::get_extension(&store, &id);
    drop(store);
    match found {
        Some(record) => (StatusCode::OK, Json(record)).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, format!("extension '{id}' not found")),
    }
}

/// `POST /v1/extensions/register` — install a (signed) manifest.
pub(super) async fn register_extension(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterExtensionBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let installed_by = extract_passport_id(&headers);
    let mut store = state.fact_store.write().await;
    let bypass = allow_unsigned_dev();
    let result = crate::extension_registry::install_extension(
        &mut store,
        &state.data_dir,
        body.manifest,
        installed_by,
        now_unix_ms(),
        bypass,
    );
    drop(store);
    match result {
        Ok(record) => (StatusCode::CREATED, Json(record)).into_response(),
        Err(crate::extension_registry::ExtensionsError::AlreadyInstalled(_)) => {
            problem_response(StatusCode::CONFLICT, "extension id already installed")
        }
        Err(err @ crate::extension_registry::ExtensionsError::ManifestInvalid(_)) => {
            // Dev-bypass advisory: surface what env knob to flip in the
            // error detail so the operator doesn't have to grep source.
            use std::fmt::Write as _;
            let mut msg = err.to_string();
            if !bypass {
                let _ = write!(
                    msg,
                    " (set {ALLOW_UNSIGNED_ENV}=true to bypass signature requirement in dev)"
                );
            }
            problem_response(StatusCode::BAD_REQUEST, msg)
        }
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

/// `DELETE /v1/extensions/{id}` — uninstall.
pub(super) async fn delete_extension(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::extension_registry::delete_extension(&mut store, &id);
    drop(store);
    match result {
        Ok(()) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(crate::extension_registry::ExtensionsError::NotFound(_)) => {
            problem_response(StatusCode::NOT_FOUND, format!("extension '{id}' not found"))
        }
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

// ── Trusted keyring management ──────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub(super) struct AddTrustedKeyBody {
    pub passport_fpr: String,
    pub public_key_hex: String,
    pub trust_tier: TrustTier,
    #[serde(default)]
    pub added_by: String,
}

/// `GET /v1/extensions/keys` — list trusted signing keys.
pub(super) async fn list_trusted_keys(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let path = crate::extension_registry::trusted_keys_path(&state.data_dir);
    match TrustedKeyring::load(&path) {
        Ok(keyring) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "count": keyring.keys.len(),
                "keys": keyring.keys,
            })),
        )
            .into_response(),
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

/// `POST /v1/extensions/keys` — add a trusted signing key.
pub(super) async fn add_trusted_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AddTrustedKeyBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let path = crate::extension_registry::trusted_keys_path(&state.data_dir);
    let mut keyring = match TrustedKeyring::load(&path) {
        Ok(k) => k,
        Err(err) => {
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
        }
    };
    keyring.add(
        body.passport_fpr.clone(),
        TrustedKeyEntry {
            public_key_hex: body.public_key_hex,
            trust_tier: body.trust_tier,
            added_at_unix_ms: now_unix_ms(),
            added_by: body.added_by,
        },
    );
    if let Err(err) = keyring.save(&path) {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "passport_fpr": body.passport_fpr })),
    )
        .into_response()
}

/// `DELETE /v1/extensions/keys/{passport_fpr}` — revoke a trusted key.
pub(super) async fn delete_trusted_key(
    State(state): State<AppState>,
    Path(passport_fpr): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let path = crate::extension_registry::trusted_keys_path(&state.data_dir);
    let mut keyring = match TrustedKeyring::load(&path) {
        Ok(k) => k,
        Err(err) => {
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
        }
    };
    if keyring.remove(&passport_fpr).is_none() {
        return problem_response(
            StatusCode::NOT_FOUND,
            format!("trusted key '{passport_fpr}' not in keyring"),
        );
    }
    if let Err(err) = keyring.save(&path) {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    (StatusCode::NO_CONTENT, ()).into_response()
}
