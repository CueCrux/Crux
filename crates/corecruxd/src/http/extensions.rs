// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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

use std::io::Read as _;
use std::path::{Path as FsPath, PathBuf};

use super::{problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Path, State, StatusCode};
use crux_integrations::{
    append_audit_event, CommunityExtensionsIndex, IntegrationAuditEvent, IntegrationManifest, TrustTier,
    TrustedKeyEntry, TrustedKeyring, AUDIT_TRUSTED_KEY_ADDED, AUDIT_TRUSTED_KEY_REMOVED,
};
use sha2::Digest as _;

const ALLOW_UNSIGNED_ENV: &str = "CORECRUXD_EXTENSIONS_ALLOW_UNSIGNED";
const REGISTRY_INDEX_REL_PATH: &str = "extensions/registry/index.json";
const REGISTRY_MANIFEST_DOWNLOAD_LIMIT_BYTES: usize = 2 * 1024 * 1024;

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

#[derive(Debug, serde::Deserialize)]
pub(super) struct InstallFromRegistryBody {
    /// Extension id to install from the cached community-extension index.
    pub id: String,
    /// Optional alternate cached index path. Relative paths resolve under
    /// `data_dir`; absolute paths are accepted for operator-controlled tests
    /// and private mirrors.
    #[serde(default)]
    pub index_path: Option<PathBuf>,
}

/// `GET /v1/extensions` — list every installed extension.
#[tracing::instrument(level = "info", skip_all)]
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
#[tracing::instrument(level = "info", skip_all)]
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
///
/// For `kind: wasm` manifests with `wasm_module_url` set, the daemon
/// downloads the module bytes via HTTPS at install time, verifies them
/// against `wasm_module_sha256`, caches the result under
/// `<data_dir>/extensions/{id}/extension.wasm`, and rewrites the
/// persisted manifest to use the cached path form. Once cached, the
/// daemon never re-fetches; an extension that wants a new module
/// version is uninstalled + re-installed.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn register_extension(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<RegisterExtensionBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let installed_by = extract_passport_id(&headers);
    let bypass = allow_unsigned_dev();

    // Phase B (M6.4): if the manifest declares `kind: wasm` with a URL,
    // download + verify the module bytes BEFORE we touch the fact store,
    // then rewrite the manifest to the cached path form. The validator
    // already constrained the URL to https:// at this point.
    // `mut` only used under the `wasm-extensions` feature; default
    // builds bind it as immutable.
    #[cfg(feature = "wasm-extensions")]
    let mut manifest = body.manifest;
    #[cfg(not(feature = "wasm-extensions"))]
    let manifest = body.manifest;
    #[cfg(feature = "wasm-extensions")]
    {
        if manifest.entry.kind == crux_integrations::EntryKind::Wasm
            && manifest.wasm_module_url.is_some()
            && manifest.wasm_module_path.is_none()
        {
            let url = manifest.wasm_module_url.clone().unwrap_or_default();
            let sha = match manifest.wasm_module_sha256.clone() {
                Some(s) => s,
                None => {
                    return problem_response(
                        StatusCode::BAD_REQUEST,
                        "kind=wasm manifest with wasm_module_url MUST also set wasm_module_sha256",
                    );
                }
            };
            let id = manifest.id.clone();
            match crate::wasm_dispatcher::download_module_to_cache_async(url, sha, state.data_dir.clone(), id).await {
                Ok(_path) => {
                    // Rewrite to the path form so the persisted record
                    // never carries a stale URL.
                    manifest.wasm_module_path = Some("extension.wasm".to_string());
                    manifest.wasm_module_url = None;
                }
                Err(crate::wasm_dispatcher::WasmDownloadError::Sha256Mismatch { expected, actual }) => {
                    return problem_response(
                        StatusCode::CONFLICT,
                        format!("downloaded module sha256 mismatch: manifest={expected}, downloaded={actual}"),
                    );
                }
                Err(crate::wasm_dispatcher::WasmDownloadError::TooLarge) => {
                    return problem_response(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        format!(
                            "wasm module exceeds the {}-byte cap",
                            crate::wasm_dispatcher::WASM_MODULE_DOWNLOAD_LIMIT_BYTES
                        ),
                    );
                }
                Err(crate::wasm_dispatcher::WasmDownloadError::UpstreamStatus(s)) => {
                    return problem_response(StatusCode::BAD_GATEWAY, format!("module URL returned status {s}"));
                }
                Err(err) => return problem_response(StatusCode::BAD_GATEWAY, err.to_string()),
            }
        }
    }

    let mut store = state.fact_store.write().await;
    let result = crate::extension_registry::install_extension(
        &mut store,
        &state.data_dir,
        manifest,
        installed_by,
        crate::pack_lifecycle::default_install_state(),
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

/// `GET /v1/extensions/registry` — browse the VERIFIED cached community
/// index so a console can render the catalog before anyone installs.
///
/// Read-only twin of `install_from_registry`: same cache path, same
/// signature verification, no network. Entries are joined against the
/// installed set so the caller can render "installed / update available"
/// without a second round-trip.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn list_registry_entries(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let index_path = registry_index_path(&state.data_dir, None);
    let index = match load_and_verify_registry_index(&state.data_dir, &index_path) {
        Ok(index) => index,
        // The no-cache case is the common one on a fresh daemon; name the
        // command that populates it rather than leaking a bare io error.
        Err((StatusCode::NOT_FOUND, msg)) => {
            return problem_response(
                StatusCode::NOT_FOUND,
                format!("{msg} (run `corecruxctl extensions sync` to populate the cached registry index)"),
            );
        }
        Err((status, msg)) => return problem_response(status, msg),
    };

    let store = state.fact_store.read().await;
    let installed = crate::extension_registry::list_extensions(&store);
    drop(store);

    let entries: Vec<serde_json::Value> = index
        .entries
        .iter()
        .map(|entry| {
            let installed_version = installed
                .iter()
                .find(|record| record.manifest.id == entry.id)
                .map(|record| record.manifest.version.clone());
            let mut value = serde_json::to_value(entry).unwrap_or_else(|_| serde_json::json!({}));
            if let Some(obj) = value.as_object_mut() {
                obj.insert("installed".to_string(), serde_json::json!(installed_version.is_some()));
                obj.insert("installed_version".to_string(), serde_json::json!(installed_version));
            }
            value
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "schema": "crux.extensions.registry_list.v1",
            "curator_passport_fpr": index.curator_passport_fpr,
            "updated_at_unix_ms": index.updated_at_unix_ms,
            "entries": entries,
        })),
    )
        .into_response()
}

/// `POST /v1/extensions/install-from-registry` — install by id from a
/// verified cached community-extension index. The daemon re-verifies the
/// signed index against the local trusted-keyring, fetches the manifest URL,
/// enforces the curator-published `manifest_sha256`, then delegates to the
/// same signed-manifest installer as `/v1/extensions/register`.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn install_from_registry(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<InstallFromRegistryBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let installed_by = extract_passport_id(&headers);
    let bypass = allow_unsigned_dev();

    let index_path = registry_index_path(&state.data_dir, body.index_path.as_deref());
    let index = match load_and_verify_registry_index(&state.data_dir, &index_path) {
        Ok(index) => index,
        Err((status, msg)) => return problem_response(status, msg),
    };
    let Some(entry) = index.entries.iter().find(|entry| entry.id == body.id).cloned() else {
        return problem_response(
            StatusCode::NOT_FOUND,
            format!("extension '{}' not found in registry index", body.id),
        );
    };
    let manifest_bytes = match fetch_registry_manifest(entry.manifest_url.clone()).await {
        Ok(bytes) => bytes,
        Err((status, msg)) => return problem_response(status, msg),
    };
    let actual_sha256 = sha256_hex(&manifest_bytes);
    if !actual_sha256.eq_ignore_ascii_case(entry.manifest_sha256.trim()) {
        return problem_response(
            StatusCode::CONFLICT,
            format!(
                "manifest_sha256 mismatch for '{}': registry={}, downloaded={actual_sha256}",
                entry.id, entry.manifest_sha256
            ),
        );
    }
    let manifest: IntegrationManifest = match serde_json::from_slice(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(err) => return problem_response(StatusCode::BAD_GATEWAY, format!("manifest JSON decode failed: {err}")),
    };
    if manifest.id != entry.id || manifest.version != entry.version {
        return problem_response(
            StatusCode::CONFLICT,
            format!(
                "registry entry mismatch: expected {}@{}, manifest is {}@{}",
                entry.id, entry.version, manifest.id, manifest.version
            ),
        );
    }

    let mut store = state.fact_store.write().await;
    let result = crate::extension_registry::install_extension(
        &mut store,
        &state.data_dir,
        manifest,
        installed_by,
        crate::pack_lifecycle::default_install_state(),
        now_unix_ms(),
        bypass,
    );
    drop(store);
    match result {
        Ok(record) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "schema": "crux.extensions.registry_install.v1",
                "registry_entry": entry,
                "manifest_sha256": actual_sha256,
                "installed": record,
            })),
        )
            .into_response(),
        Err(crate::extension_registry::ExtensionsError::AlreadyInstalled(_)) => {
            problem_response(StatusCode::CONFLICT, "extension id already installed")
        }
        Err(err @ crate::extension_registry::ExtensionsError::ManifestInvalid(_)) => {
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

fn registry_index_path(data_dir: &FsPath, override_path: Option<&FsPath>) -> PathBuf {
    match override_path {
        Some(path) if path.is_absolute() => path.to_path_buf(),
        Some(path) => data_dir.join(path),
        None => data_dir.join(REGISTRY_INDEX_REL_PATH),
    }
}

fn load_and_verify_registry_index(
    data_dir: &FsPath,
    index_path: &FsPath,
) -> Result<CommunityExtensionsIndex, (StatusCode, String)> {
    let bytes = std::fs::read(index_path)
        .map_err(|err| (StatusCode::NOT_FOUND, format!("registry index read failed: {err}")))?;
    let index: CommunityExtensionsIndex = serde_json::from_slice(&bytes).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("registry index JSON decode failed: {err}"),
        )
    })?;
    let policy = crate::extension_registry::build_policy(data_dir)
        .map_err(|err| (StatusCode::BAD_REQUEST, format!("trusted keyring read failed: {err}")))?;
    index.verify(&policy).map_err(|err| {
        (
            StatusCode::FORBIDDEN,
            format!("registry index signature verification failed: {err}"),
        )
    })?;
    Ok(index)
}

async fn fetch_registry_manifest(url: String) -> Result<Vec<u8>, (StatusCode, String)> {
    if !registry_manifest_url_allowed(&url) {
        return Err((
            StatusCode::BAD_REQUEST,
            "manifest_url must be https://, or loopback http:// for local tests".to_string(),
        ));
    }
    tokio::task::spawn_blocking(move || fetch_registry_manifest_blocking(&url))
        .await
        .map_err(|err| (StatusCode::BAD_GATEWAY, format!("manifest fetch join error: {err}")))?
}

fn registry_manifest_url_allowed(url: &str) -> bool {
    url.starts_with("https://") || url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost")
}

fn fetch_registry_manifest_blocking(url: &str) -> Result<Vec<u8>, (StatusCode, String)> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build()
        .into();
    let mut response = agent
        .get(url)
        .call()
        .map_err(|err| (StatusCode::BAD_GATEWAY, format!("manifest fetch failed: {err}")))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("manifest URL returned status {status}"),
        ));
    }
    let mut reader = response.body_mut().as_reader();
    let mut out = Vec::with_capacity(64 * 1024);
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let n = reader
            .read(&mut chunk)
            .map_err(|err| (StatusCode::BAD_GATEWAY, format!("manifest read failed: {err}")))?;
        if n == 0 {
            break;
        }
        if out.len() + n > REGISTRY_MANIFEST_DOWNLOAD_LIMIT_BYTES {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("manifest exceeds the {REGISTRY_MANIFEST_DOWNLOAD_LIMIT_BYTES}-byte cap"),
            ));
        }
        out.extend_from_slice(&chunk[..n]);
    }
    Ok(out)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// `DELETE /v1/extensions/{id}` — uninstall.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn delete_extension(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let deleted_by = extract_passport_id(&headers);
    let mut store = state.fact_store.write().await;
    let result = crate::extension_registry::delete_extension(
        &mut store,
        &state.data_dir,
        &id,
        deleted_by.as_deref(),
        now_unix_ms(),
    );
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
#[tracing::instrument(level = "info", skip_all)]
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
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn add_trusted_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AddTrustedKeyBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let path = crate::extension_registry::trusted_keys_path(&state.data_dir);
    let actor = extract_passport_id(&headers);
    let added_at_unix_ms = now_unix_ms();
    let trust_tier = body.trust_tier;
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
            trust_tier,
            added_at_unix_ms,
            added_by: body.added_by,
        },
    );
    if let Err(err) = keyring.save(&path) {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    append_audit_event(
        &state.data_dir,
        &IntegrationAuditEvent::extension(
            added_at_unix_ms,
            AUDIT_TRUSTED_KEY_ADDED,
            actor.as_deref(),
            &body.passport_fpr,
            None,
            "added",
            serde_json::json!({ "trust_tier": trust_tier }),
        ),
    );
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "passport_fpr": body.passport_fpr })),
    )
        .into_response()
}

// ── Per-passport grants (M3) ────────────────────────────────────────────

#[derive(Debug, serde::Deserialize)]
pub(super) struct IssueGrantBody {
    pub passport_fpr: String,
    #[serde(default)]
    pub allowed_tool_names: Vec<String>,
    #[serde(default)]
    pub allowed_prefixes_read: Vec<String>,
    #[serde(default)]
    pub allowed_prefixes_write: Vec<String>,
    #[serde(default)]
    pub rate_limit_per_min: Option<u32>,
}

/// `GET /v1/extensions/{id}/grants` — list grants for one extension.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn list_grants(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let store = state.fact_store.read().await;
    let grants = crate::extension_grants::list_grants_for_extension(&store, &id);
    drop(store);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "extension_id": id,
            "count": grants.len(),
            "grants": grants,
        })),
    )
        .into_response()
}

/// `POST /v1/extensions/{id}/grants` — issue a grant to a passport.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn issue_grant(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<IssueGrantBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let granted_by = extract_passport_id(&headers);
    let mut store = state.fact_store.write().await;
    // Check the extension is installed *before* delegating; the grant
    // module also asserts this but we surface a 404 (more specific than
    // 400) here for clarity.
    let installed = crate::extension_registry::get_extension(&store, &id);
    let Some(installed) = installed else {
        drop(store);
        return problem_response(StatusCode::NOT_FOUND, format!("extension '{id}' not installed"));
    };
    let version = installed.manifest.version;
    let result = crate::extension_grants::issue_grant(
        &mut store,
        &state.data_dir,
        true,
        Some(&version),
        crate::extension_grants::IssueGrantInput {
            extension_id: id.clone(),
            passport_fpr: body.passport_fpr,
            allowed_tool_names: body.allowed_tool_names,
            allowed_prefixes_read: body.allowed_prefixes_read,
            allowed_prefixes_write: body.allowed_prefixes_write,
            rate_limit_per_min: body.rate_limit_per_min,
            granted_by_passport: granted_by,
        },
        now_unix_ms(),
    );
    drop(store);
    match result {
        Ok(grant) => (StatusCode::CREATED, Json(grant)).into_response(),
        Err(crate::extension_grants::GrantError::AlreadyGranted(_, _)) => {
            problem_response(StatusCode::CONFLICT, "grant already exists; revoke first to replace")
        }
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

// ── Direct invoke (M4 — Phase A entry point before MCP dispatch lands in M5) ─

#[derive(Debug, serde::Deserialize)]
pub(super) struct InvokeToolBody {
    /// Caller's passport (the grant must be issued to this fpr). Defaults
    /// to the `X-Corecrux-Passport-Id` header when absent from the body.
    #[serde(default)]
    pub passport_fpr: Option<String>,
    /// Arbitrary args object forwarded as-is to the extension endpoint.
    #[serde(default = "InvokeToolBody::empty_args")]
    pub args: serde_json::Value,
}

impl InvokeToolBody {
    fn empty_args() -> serde_json::Value {
        serde_json::json!({})
    }
}

fn make_request_id() -> String {
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("req-{now_ns}")
}

/// `POST /v1/extensions/{id}/tools/{tool_name}/invoke` — direct dispatch
/// surface for an installed extension. Branches on `manifest.entry.kind`:
/// `ExternalTool` → Phase A HTTPS path; `Wasm` → Phase B in-process
/// wasmtime path (M6.3, requires `--features wasm-extensions`).
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn invoke_extension_tool(
    State(state): State<AppState>,
    Path((extension_id, tool_name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(body): Json<InvokeToolBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let calling_passport = body.passport_fpr.clone().or_else(|| extract_passport_id(&headers));
    let Some(calling_passport) = calling_passport else {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "passport_fpr required (body field or X-Corecrux-Passport-Id header)",
        );
    };

    // Snapshot installed extension + grant out of the store before the
    // outbound call so we can drop the read lock during the (potentially
    // slow) network round-trip / wasm execution.
    let (manifest, attribution, lifecycle, grant) = {
        let store = state.fact_store.read().await;
        let installed = match crate::extension_registry::get_extension(&store, &extension_id) {
            Some(r) => r,
            None => {
                return problem_response(
                    StatusCode::NOT_FOUND,
                    format!("extension '{extension_id}' not installed"),
                );
            }
        };
        let grant = match crate::extension_grants::get_grant(&store, &extension_id, &calling_passport) {
            Some(g) => g,
            None => {
                return problem_response(
                    StatusCode::FORBIDDEN,
                    format!("passport '{calling_passport}' has no grant for extension '{extension_id}'"),
                );
            }
        };
        // Built once, from the install record — the only place that knows the
        // hash of the bytes the operator actually installed. Both dispatch
        // branches and every fact they write carry this same value.
        let attribution = crate::extension_registry::PackAttribution::from_installed(&installed);
        (installed.manifest, attribution, installed.lifecycle, grant)
    };

    // Staged-activation seam: a quarantined pack is refused here, before
    // any transport is opened or any module is loaded — the point of
    // quarantine is that the code does not run, not that its writes are
    // discarded afterwards.
    if !lifecycle.is_dispatchable() {
        return problem_response(
            StatusCode::CONFLICT,
            format!(
                "extension '{extension_id}' is {}; POST /v1/extensions/{extension_id}/lifecycle with a reason to re-instate it",
                lifecycle.as_str()
            ),
        );
    }

    // Tool name must be in the grant's allow-list (or the allow-list
    // must be empty, meaning "all tools the manifest declares").
    if !grant.allowed_tool_names.is_empty() && !grant.allowed_tool_names.contains(&tool_name) {
        return problem_response(
            StatusCode::FORBIDDEN,
            format!("tool '{tool_name}' is not in the grant's allowed_tool_names"),
        );
    }

    // Branch on entry.kind: Wasm → Phase B host, ExternalTool → Phase A.
    if manifest.entry.kind == crux_integrations::EntryKind::Wasm {
        return dispatch_wasm_kind_or_unsupported(
            state,
            extension_id,
            manifest,
            attribution,
            lifecycle,
            grant,
            tool_name,
            body.args,
            calling_passport,
        )
        .await;
    }
    if manifest.entry.kind != crux_integrations::EntryKind::ExternalTool {
        return problem_response(
            StatusCode::BAD_REQUEST,
            format!(
                "extension '{}' has unsupported entry.kind {:?} for tool dispatch",
                extension_id, manifest.entry.kind
            ),
        );
    }

    // Run the outbound HTTP call off the async runtime — ureq is blocking.
    let cfg = crate::extension_outbound::OutboundConfig::from_env();
    let rate_table = state.extension_rate_table.clone();
    let request_id = make_request_id();
    let args = body.args;
    let manifest_clone = manifest.clone();
    let grant_clone = grant.clone();
    let calling_clone = calling_passport.clone();
    let rid = request_id.clone();
    let data_dir = state.data_dir.clone();
    // A staged call takes the unaudited variant: the staged branch below
    // writes an `extension_invoke_staged` row instead, so exactly one audit
    // row describes this call and it says which mode the call ran in.
    // Without that, `extension_invoke_ok` would mean "live or replayed" and
    // the per-pack outcome stream would credit a pack for being replayed.
    let live = lifecycle.commits_writes();
    let dispatch_result = tokio::task::spawn_blocking(move || {
        let transport = crate::extension_outbound::UreqTransport;
        if live {
            crate::extension_outbound::dispatch_external_tool(
                &transport,
                &rate_table,
                &cfg,
                &data_dir,
                &manifest_clone,
                &attribution,
                &grant_clone,
                &tool_name,
                &args,
                &calling_clone,
                &rid,
                None, // M5 will pull the auth secret via `encrypted_secrets`
            )
        } else {
            crate::extension_outbound::dispatch_external_tool_staged(
                &transport,
                &rate_table,
                &cfg,
                &manifest_clone,
                &attribution,
                &grant_clone,
                &tool_name,
                &args,
                &calling_clone,
                &rid,
                None,
            )
        }
    })
    .await;

    let (outcome, parsed) = match dispatch_result {
        Ok(Ok((outcome, parsed))) => (outcome, parsed),
        Ok(Err(crate::extension_outbound::OutboundError::NoGrant(_, _)))
        | Ok(Err(crate::extension_outbound::OutboundError::ToolNotInGrant(_, _, _))) => {
            return problem_response(StatusCode::FORBIDDEN, "scope violation".to_string());
        }
        Ok(Err(crate::extension_outbound::OutboundError::RateLimited(_, _, cap))) => {
            return problem_response(StatusCode::TOO_MANY_REQUESTS, format!("rate limited (cap {cap}/min)"));
        }
        Ok(Err(err)) => {
            return problem_response(StatusCode::BAD_GATEWAY, err.to_string());
        }
        Err(err) => {
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("dispatch join error: {err}"));
        }
    };

    // Scope filtering + the `actor` stamp both come from the dispatcher's
    // own outcome, so a stored fact's authorship is the same value the
    // receipt reports rather than a second derivation that can drift.
    // Whether those writes then land is the lifecycle's call, not this
    // handler's — see `classify_dispatch_writes`.
    let writes = crate::extension_outbound::attributed_fact_writes(&parsed, &grant, &outcome.attribution);
    match crate::pack_lifecycle::classify_dispatch_writes(lifecycle, writes) {
        crate::pack_lifecycle::DispatchWrites::Commit(writes) => {
            if !writes.is_empty() {
                let mut store = state.fact_store.write().await;
                for sf in writes {
                    store.store(sf);
                }
                drop(store);
            }
            (StatusCode::OK, Json(outcome)).into_response()
        }
        // Staged: the pack ran and we know precisely what it would have
        // changed — and the store was never opened for writing.
        crate::pack_lifecycle::DispatchWrites::Observe(observed) => {
            append_audit_event(
                &state.data_dir,
                &IntegrationAuditEvent::extension(
                    now_unix_ms(),
                    crux_integrations::AUDIT_EXTENSION_INVOKE_STAGED,
                    Some(&calling_passport),
                    &outcome.attribution.extension_id,
                    Some(&outcome.attribution.extension_version),
                    lifecycle.as_str(),
                    serde_json::json!({
                        "manifest_hash": outcome.attribution.manifest_hash,
                        "observed_fact_writes": observed.len(),
                    }),
                ),
            );
            (
                StatusCode::OK,
                Json(crate::pack_lifecycle::StagedDispatchEnvelope::new(
                    lifecycle, observed, outcome,
                )),
            )
                .into_response()
        }
    }
}

// ── Outcome events (buyer-fit M5 frontier seam) ──────────────────────────

/// `GET /v1/extensions/{id}/outcomes` — what became of this pack's writes,
/// plus its dispatch and lifecycle history.
///
/// Mostly *derived* rather than stored: corrections, supersessions and decay
/// are re-computed from the fact store on every read, and dispatch history
/// is re-read from the audit tail. Each event names the fact or audit row it
/// came from, which is what makes the score
/// `proof-carrying-adaptive-packs-2026-07-13` M3 builds on this traceable
/// rather than asserted.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn list_extension_outcomes(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let audit = crux_integrations::read_audit_tail(&state.data_dir, crate::pack_outcomes::AUDIT_TAIL_SCAN_LIMIT)
        .unwrap_or_default();
    let store = state.fact_store.read().await;
    if crate::extension_registry::get_extension(&store, &id).is_none() {
        drop(store);
        return problem_response(StatusCode::NOT_FOUND, format!("extension '{id}' not installed"));
    }
    let events = crate::pack_outcomes::collect_outcomes(
        &store,
        &audit,
        &corecrux_memory::fact_store::default_tenant_hash(),
        &id,
        chrono::Utc::now(),
    );
    drop(store);

    let totals = crate::pack_outcomes::totals(&events);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "schema": "crux.extensions.outcomes.v1",
            "extension_id": id,
            "count": events.len(),
            "totals": totals,
            "events": events,
        })),
    )
        .into_response()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct RecordOutcomeBody {
    pub kind: crate::pack_outcomes::PackOutcomeKind,
    #[serde(default)]
    pub subject: Option<crate::pack_outcomes::PackOutcomeSubject>,
    /// Why the caller is asserting this. Free-form, but it is the only thing
    /// standing behind a recorded outcome, so an empty object makes for a
    /// score movement nobody can explain later.
    #[serde(default)]
    pub evidence: serde_json::Value,
}

/// `POST /v1/extensions/{id}/outcomes` — record a judgement the daemon
/// cannot derive: a rejected or accepted recall, or a cross-agent signal.
///
/// Derivable kinds are refused. Accepting a posted `correction` or `decayed`
/// would let a caller assert what the fact store contradicts, and the whole
/// value of this seam is that most of the evidence is re-checkable.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn record_extension_outcome(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<RecordOutcomeBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let actor = extract_passport_id(&headers);
    let now = now_unix_ms();
    let nonce = make_request_id();
    let mut store = state.fact_store.write().await;
    let Some(installed) = crate::extension_registry::get_extension(&store, &id) else {
        drop(store);
        return problem_response(StatusCode::NOT_FOUND, format!("extension '{id}' not installed"));
    };
    let attribution = crate::extension_registry::PackAttribution::from_installed(&installed);
    let mut evidence = body.evidence;
    if let Some(object) = evidence.as_object_mut() {
        // Who asserted this is part of the evidence, not metadata: a
        // recorded outcome is one party's judgement and has to say whose.
        object.insert("reported_by".to_string(), serde_json::json!(actor));
    }
    let result = crate::pack_outcomes::record_outcome(
        &mut store,
        &id,
        crate::pack_outcomes::RecordOutcomeInput {
            pack: attribution,
            kind: body.kind,
            subject: body.subject,
            evidence,
            now_unix_ms: now,
            nonce,
        },
    );
    drop(store);
    match result {
        Ok(event) => (StatusCode::CREATED, Json(event)).into_response(),
        Err(err @ crate::pack_outcomes::OutcomeError::NotRecordable(_)) => {
            problem_response(StatusCode::UNPROCESSABLE_ENTITY, err.to_string())
        }
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

// ── Conformance hook (buyer-fit M5 frontier seam) ────────────────────────

#[derive(Debug, serde::Deserialize)]
pub(super) struct ConformanceRunBody {
    /// Name of the shadow corpus these cases came from. Required — a
    /// behavioural result whose corpus is unnamed cannot be compared to
    /// anything later.
    pub corpus_id: String,
    #[serde(default)]
    pub passport_fpr: Option<String>,
    /// Operations to replay. Omit to fall back to one case per tool the
    /// manifest declares — see
    /// [`crate::pack_conformance::cases_from_manifest`].
    #[serde(default)]
    pub cases: Option<Vec<crate::pack_conformance::ConformanceCase>>,
}

/// Run one declared operation against a staged pack and report what it
/// would have done.
///
/// Deliberately *not* folded together with [`invoke_extension_tool`]: that
/// handler maps each dispatch failure onto a distinct HTTP status (403 for
/// a scope violation, 429 for a rate limit, 502 upstream), and a replay
/// wants every failure flattened into one recorded observation instead. The
/// part that must not diverge — whether a write lands — is shared: both go
/// through [`crate::pack_lifecycle::classify_dispatch_writes`], so an
/// operation observed here behaves exactly as it would through the invoke
/// route.
#[allow(clippy::too_many_arguments)]
async fn run_staged_operation(
    state: &AppState,
    extension_id: &str,
    manifest: &IntegrationManifest,
    attribution: &crate::extension_registry::PackAttribution,
    grant: &crate::extension_grants::ExtensionGrant,
    tool_name: &str,
    args: serde_json::Value,
    calling_passport: &str,
) -> Result<crate::pack_conformance::StagedOperationOutcome, String> {
    if !grant.allowed_tool_names.is_empty() && !grant.allowed_tool_names.contains(&tool_name.to_string()) {
        return Err(format!("tool '{tool_name}' is not in the grant's allowed_tool_names"));
    }
    let started = std::time::Instant::now();

    if manifest.entry.kind == crux_integrations::EntryKind::Wasm {
        return run_staged_wasm_operation(
            state,
            extension_id,
            manifest,
            attribution,
            grant,
            tool_name,
            args,
            calling_passport,
            started,
        )
        .await;
    }
    if manifest.entry.kind != crux_integrations::EntryKind::ExternalTool {
        return Err(format!(
            "unsupported entry.kind {:?} for tool dispatch",
            manifest.entry.kind
        ));
    }

    let cfg = crate::extension_outbound::OutboundConfig::from_env();
    let rate_table = state.extension_rate_table.clone();
    let manifest_clone = manifest.clone();
    let attribution_clone = attribution.clone();
    let grant_clone = grant.clone();
    let tool = tool_name.to_string();
    let passport = calling_passport.to_string();
    let request_id = make_request_id();
    // Unaudited: a replay is not an invocation. The conformance run writes
    // one `extension_conformance_run` row for the whole run instead.
    let dispatched = tokio::task::spawn_blocking(move || {
        let transport = crate::extension_outbound::UreqTransport;
        crate::extension_outbound::dispatch_external_tool_staged(
            &transport,
            &rate_table,
            &cfg,
            &manifest_clone,
            &attribution_clone,
            &grant_clone,
            &tool,
            &args,
            &passport,
            &request_id,
            None,
        )
    })
    .await
    .map_err(|err| format!("dispatch join error: {err}"))?
    .map_err(|err| err.to_string())?;

    let (outcome, parsed) = dispatched;
    let writes = crate::extension_outbound::attributed_fact_writes(&parsed, grant, &outcome.attribution);
    // Forced staged: a conformance run is only reachable on a staged pack
    // (see `precheck`), and passing the state explicitly keeps that true
    // even if a future caller reaches this helper another way.
    let observed = match crate::pack_lifecycle::classify_dispatch_writes(
        crate::pack_lifecycle::PackLifecycleState::Staged,
        writes,
    ) {
        crate::pack_lifecycle::DispatchWrites::Observe(observed) => observed,
        crate::pack_lifecycle::DispatchWrites::Commit(_) => {
            return Err("staged classification returned a commit; refusing to proceed".to_string());
        }
    };
    Ok(crate::pack_conformance::StagedOperationOutcome {
        result: outcome.result,
        observed_fact_writes: observed,
        dropped_fact_writes: outcome.dropped_fact_writes,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

#[cfg(feature = "wasm-extensions")]
#[allow(clippy::too_many_arguments)]
async fn run_staged_wasm_operation(
    state: &AppState,
    extension_id: &str,
    manifest: &IntegrationManifest,
    attribution: &crate::extension_registry::PackAttribution,
    grant: &crate::extension_grants::ExtensionGrant,
    tool_name: &str,
    args: serde_json::Value,
    calling_passport: &str,
    started: std::time::Instant,
) -> Result<crate::pack_conformance::StagedOperationOutcome, String> {
    let engine = state
        .wasm_engine
        .clone()
        .ok_or_else(|| "wasm engine init failed at startup".to_string())?;
    let (outcome, observed) = crate::wasm_dispatcher::dispatch_wasm_via_http(
        engine,
        crate::wasm_host::WasmConfig::from_env(),
        state.data_dir.clone(),
        state.fact_store.clone(),
        extension_id.to_string(),
        manifest.clone(),
        attribution.clone(),
        false, // staged: observe, never commit
        grant.clone(),
        tool_name.to_string(),
        args,
        calling_passport.to_string(),
        make_request_id(),
    )
    .await
    .map_err(|err| err.to_string())?;
    Ok(crate::pack_conformance::StagedOperationOutcome {
        result: outcome.result,
        observed_fact_writes: observed,
        // A wasm module writes through the host ABI, where an out-of-scope
        // write is refused inline rather than counted at the end — so there
        // is no drop tally to report here.
        dropped_fact_writes: 0,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

#[cfg(not(feature = "wasm-extensions"))]
#[allow(clippy::unused_async, clippy::too_many_arguments)]
async fn run_staged_wasm_operation(
    _state: &AppState,
    _extension_id: &str,
    _manifest: &IntegrationManifest,
    _attribution: &crate::extension_registry::PackAttribution,
    _grant: &crate::extension_grants::ExtensionGrant,
    _tool_name: &str,
    _args: serde_json::Value,
    _calling_passport: &str,
    _started: std::time::Instant,
) -> Result<crate::pack_conformance::StagedOperationOutcome, String> {
    Err("wasm extensions require building corecruxd with --features wasm-extensions".to_string())
}

/// `POST /v1/extensions/{id}/conformance` — replay a staged pack's declared
/// operations and return what each one would have done.
///
/// The hook `proof-carrying-adaptive-packs-2026-07-13` M1 calls before
/// enabling a pack. It reports evidence and never a verdict: comparing the
/// observed behaviour against a declared envelope, and deciding whether the
/// pack may go live, belong to that plan.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn run_extension_conformance(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<ConformanceRunBody>,
) -> impl IntoResponse {
    // `facts:write` even though a staged run writes nothing: it executes the
    // pack's code and reaches its endpoint, so it is not a read.
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let calling_passport = body.passport_fpr.clone().or_else(|| extract_passport_id(&headers));
    let Some(calling_passport) = calling_passport else {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "passport_fpr required (body field or X-Corecrux-Passport-Id header)",
        );
    };

    let (manifest, attribution, lifecycle, grant) = {
        let store = state.fact_store.read().await;
        let Some(installed) = crate::extension_registry::get_extension(&store, &id) else {
            return problem_response(StatusCode::NOT_FOUND, format!("extension '{id}' not installed"));
        };
        let Some(grant) = crate::extension_grants::get_grant(&store, &id, &calling_passport) else {
            return problem_response(
                StatusCode::FORBIDDEN,
                format!("passport '{calling_passport}' has no grant for extension '{id}'"),
            );
        };
        let attribution = crate::extension_registry::PackAttribution::from_installed(&installed);
        (installed.manifest, attribution, installed.lifecycle, grant)
    };

    let cases = body
        .cases
        .unwrap_or_else(|| crate::pack_conformance::cases_from_manifest(&manifest));
    if let Err(err) = crate::pack_conformance::precheck(&id, lifecycle, &body.corpus_id, &cases) {
        let status = match err {
            crate::pack_conformance::ConformanceError::NotStaged(_, _) => StatusCode::CONFLICT,
            _ => StatusCode::UNPROCESSABLE_ENTITY,
        };
        return problem_response(status, err.to_string());
    }

    let started_at_unix_ms = now_unix_ms();
    let mut observations = Vec::with_capacity(cases.len());
    for case in &cases {
        // Sequentially, in declaration order: a pack's later operations can
        // depend on what its earlier ones did, so a parallel run would not
        // be the replay the corpus describes.
        let outcome = run_staged_operation(
            &state,
            &id,
            &manifest,
            &attribution,
            &grant,
            &case.tool_name,
            case.args.clone(),
            &calling_passport,
        )
        .await;
        observations.push(crate::pack_conformance::observe(case, outcome));
    }

    let run =
        crate::pack_conformance::build_run(attribution, lifecycle, body.corpus_id, started_at_unix_ms, observations);
    append_audit_event(
        &state.data_dir,
        &IntegrationAuditEvent::extension(
            now_unix_ms(),
            crux_integrations::AUDIT_EXTENSION_CONFORMANCE_RUN,
            Some(&calling_passport),
            &run.pack.extension_id,
            Some(&run.pack.extension_version),
            if run.totals.errors == 0 { "ok" } else { "errors" },
            serde_json::json!({
                "manifest_hash": run.pack.manifest_hash,
                "corpus_id": run.corpus_id,
                "observed_digest": run.observed_digest,
                "totals": run.totals,
            }),
        ),
    );
    (StatusCode::OK, Json(run)).into_response()
}

// ── Staged activation (buyer-fit M5 frontier seam) ───────────────────────

#[derive(Debug, serde::Deserialize)]
pub(super) struct SetLifecycleBody {
    pub state: crate::pack_lifecycle::PackLifecycleState,
    /// Mandatory only when leaving quarantine — see
    /// [`crate::pack_lifecycle::LifecycleError::ReasonRequired`].
    #[serde(default)]
    pub reason: Option<String>,
}

/// `POST /v1/extensions/{id}/lifecycle` — move a pack between staged,
/// active and quarantined.
///
/// This is the operator-facing half of the staged-activation seam: the
/// pre-enable replay that `proof-carrying-adaptive-packs` M1 performs runs
/// against a `staged` pack and then calls this route to take it live, and
/// its M4 auto-quarantine calls it the other way with the regression as the
/// `reason`.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn set_extension_lifecycle(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<SetLifecycleBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let actor = extract_passport_id(&headers);
    let mut store = state.fact_store.write().await;
    let result = crate::pack_lifecycle::set_lifecycle(
        &mut store,
        &state.data_dir,
        &id,
        body.state,
        body.reason.as_deref(),
        actor.as_deref(),
        now_unix_ms(),
    );
    drop(store);
    match result {
        Ok((record, transition)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "schema": "crux.extensions.lifecycle.v1",
                "transition": transition,
                "extension": record,
            })),
        )
            .into_response(),
        Err(crate::pack_lifecycle::LifecycleError::NotFound(_)) => {
            problem_response(StatusCode::NOT_FOUND, format!("extension '{id}' not installed"))
        }
        Err(err @ crate::pack_lifecycle::LifecycleError::ReasonRequired) => {
            problem_response(StatusCode::UNPROCESSABLE_ENTITY, err.to_string())
        }
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

/// `DELETE /v1/extensions/{id}/grants/{passport_fpr}` — revoke a grant.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn revoke_grant(
    State(state): State<AppState>,
    Path((id, passport_fpr)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let revoked_by = extract_passport_id(&headers);
    let mut store = state.fact_store.write().await;
    let extension_version =
        crate::extension_registry::get_extension(&store, &id).map(|installed| installed.manifest.version);
    let result = crate::extension_grants::revoke_grant(
        &mut store,
        &state.data_dir,
        &id,
        extension_version.as_deref(),
        &passport_fpr,
        revoked_by.as_deref(),
        now_unix_ms(),
    );
    drop(store);
    match result {
        Ok(()) => (StatusCode::NO_CONTENT, ()).into_response(),
        Err(crate::extension_grants::GrantError::NotFound(_, _)) => problem_response(
            StatusCode::NOT_FOUND,
            format!("grant for '{id}' + '{passport_fpr}' not found"),
        ),
        Err(err) => problem_response(StatusCode::BAD_REQUEST, err.to_string()),
    }
}

/// `DELETE /v1/extensions/keys/{passport_fpr}` — revoke a trusted key.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn delete_trusted_key(
    State(state): State<AppState>,
    Path(passport_fpr): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let actor = extract_passport_id(&headers);
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
    append_audit_event(
        &state.data_dir,
        &IntegrationAuditEvent::extension(
            now_unix_ms(),
            AUDIT_TRUSTED_KEY_REMOVED,
            actor.as_deref(),
            &passport_fpr,
            None,
            "removed",
            serde_json::json!({}),
        ),
    );
    (StatusCode::NO_CONTENT, ()).into_response()
}

// ── Phase B (M6.3) wasm-dispatch entry point ─────────────────────────────

/// Wasm dispatch path for `kind: wasm` extensions. Without
/// `--features wasm-extensions` the daemon returns 501; with the
/// feature, calls into [`crate::wasm_dispatcher`].
#[cfg(feature = "wasm-extensions")]
#[allow(clippy::too_many_arguments)]
async fn dispatch_wasm_kind_or_unsupported(
    state: AppState,
    extension_id: String,
    manifest: IntegrationManifest,
    attribution: crate::extension_registry::PackAttribution,
    lifecycle: crate::pack_lifecycle::PackLifecycleState,
    grant: crate::extension_grants::ExtensionGrant,
    tool_name: String,
    args: serde_json::Value,
    calling_passport: String,
) -> axum::response::Response {
    let Some(engine) = state.wasm_engine.clone() else {
        return problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "wasm engine init failed at startup; restart the daemon and check logs",
        );
    };
    let cfg = crate::wasm_host::WasmConfig::from_env();
    let request_id = make_request_id();
    // A wasm pack writes through the host ABI mid-call, so staging cannot
    // be applied after the fact the way the external-tool path does it —
    // the adapter itself has to be the one that observes instead of
    // committing. `commits_writes()` is the same predicate both paths use.
    let commit = lifecycle.commits_writes();
    let result = crate::wasm_dispatcher::dispatch_wasm_via_http(
        engine,
        cfg,
        state.data_dir.clone(),
        state.fact_store.clone(),
        extension_id,
        manifest,
        attribution,
        commit,
        grant,
        tool_name,
        args,
        calling_passport,
        request_id,
    )
    .await;
    match result {
        Ok((outcome, observed)) if !commit => (
            StatusCode::OK,
            Json(crate::pack_lifecycle::StagedDispatchEnvelope::new(
                lifecycle, observed, outcome,
            )),
        )
            .into_response(),
        Ok((outcome, _)) => (StatusCode::OK, Json(outcome)).into_response(),
        Err(crate::wasm_dispatcher::WasmDispatchError::ModuleFileMissing(p)) => problem_response(
            StatusCode::NOT_FOUND,
            format!("wasm module file missing at '{}'", p.display()),
        ),
        Err(crate::wasm_dispatcher::WasmDispatchError::Sha256Mismatch { expected, actual }) => problem_response(
            StatusCode::CONFLICT,
            format!("module sha256 mismatch: manifest={expected}, on-disk={actual}"),
        ),
        Err(err @ crate::wasm_dispatcher::WasmDispatchError::Dispatch(crate::wasm_host::WasmError::FuelExhausted)) => {
            problem_response(StatusCode::REQUEST_TIMEOUT, err.to_string())
        }
        Err(
            err @ crate::wasm_dispatcher::WasmDispatchError::Dispatch(crate::wasm_host::WasmError::DeadlineExceeded),
        ) => problem_response(StatusCode::REQUEST_TIMEOUT, err.to_string()),
        Err(err @ crate::wasm_dispatcher::WasmDispatchError::Dispatch(crate::wasm_host::WasmError::OutOfMemory)) => {
            problem_response(StatusCode::INSUFFICIENT_STORAGE, err.to_string())
        }
        Err(err) => problem_response(StatusCode::BAD_GATEWAY, err.to_string()),
    }
}

/// Without the `wasm-extensions` feature, the route returns 501 so the
/// operator immediately understands what to flip to enable it. Marked
/// `async` to share the call-site signature with the wasm-feature
/// variant (which IS async); suppress the unused_async lint here since
/// the body is a synchronous early-return.
#[cfg(not(feature = "wasm-extensions"))]
#[allow(clippy::unused_async, clippy::too_many_arguments)]
async fn dispatch_wasm_kind_or_unsupported(
    _state: AppState,
    _extension_id: String,
    _manifest: IntegrationManifest,
    _attribution: crate::extension_registry::PackAttribution,
    _lifecycle: crate::pack_lifecycle::PackLifecycleState,
    _grant: crate::extension_grants::ExtensionGrant,
    _tool_name: String,
    _args: serde_json::Value,
    _calling_passport: String,
) -> axum::response::Response {
    problem_response(
        StatusCode::NOT_IMPLEMENTED,
        "wasm extensions require building corecruxd with --features wasm-extensions",
    )
}
