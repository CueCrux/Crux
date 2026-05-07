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
///
/// For `kind: wasm` manifests with `wasm_module_url` set, the daemon
/// downloads the module bytes via HTTPS at install time, verifies them
/// against `wasm_module_sha256`, caches the result under
/// `<data_dir>/extensions/{id}/extension.wasm`, and rewrites the
/// persisted manifest to use the cached path form. Once cached, the
/// daemon never re-fetches; an extension that wants a new module
/// version is uninstalled + re-installed.
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
    let installed = crate::extension_registry::get_extension(&store, &id).is_some();
    if !installed {
        drop(store);
        return problem_response(StatusCode::NOT_FOUND, format!("extension '{id}' not installed"));
    }
    let result = crate::extension_grants::issue_grant(
        &mut store,
        true,
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
    let (manifest, grant) = {
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
        (installed.manifest, grant)
    };

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
    let dispatch_result = tokio::task::spawn_blocking(move || {
        let transport = crate::extension_outbound::UreqTransport;
        crate::extension_outbound::dispatch_external_tool(
            &transport,
            &rate_table,
            &cfg,
            &manifest_clone,
            &grant_clone,
            &tool_name,
            &args,
            &calling_clone,
            &rid,
            None, // M5 will pull the auth secret via `encrypted_secrets`
        )
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

    // Persist the accepted fact_writes (the dispatcher already filtered
    // out-of-scope ones). Each write hits the privacy gate as a final
    // belt-and-braces check; identical-shape entries that snuck through
    // would still be marked private at storage time.
    if outcome.accepted_fact_writes > 0 {
        let mut store = state.fact_store.write().await;
        for w in &parsed.fact_writes {
            if !grant.allowed_prefixes_write.iter().any(|p| w.entity.starts_with(p)) {
                continue; // already counted as dropped
            }
            let mut sf = corecrux_memory::fact_store::StoreFact {
                entity: w.entity.clone(),
                key: w.key.clone(),
                value: w.value.clone(),
                source_receipt: None,
                confidence: w.confidence,
                private: false,
            };
            crate::fact_privacy::enforce_global(&mut sf);
            store.store(sf);
        }
        drop(store);
    }

    (StatusCode::OK, Json(outcome)).into_response()
}

/// `DELETE /v1/extensions/{id}/grants/{passport_fpr}` — revoke a grant.
pub(super) async fn revoke_grant(
    State(state): State<AppState>,
    Path((id, passport_fpr)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let mut store = state.fact_store.write().await;
    let result = crate::extension_grants::revoke_grant(&mut store, &id, &passport_fpr);
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

// ── Phase B (M6.3) wasm-dispatch entry point ─────────────────────────────

/// Wasm dispatch path for `kind: wasm` extensions. Without
/// `--features wasm-extensions` the daemon returns 501; with the
/// feature, calls into [`crate::wasm_dispatcher`].
#[cfg(feature = "wasm-extensions")]
async fn dispatch_wasm_kind_or_unsupported(
    state: AppState,
    extension_id: String,
    manifest: IntegrationManifest,
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
    let result = crate::wasm_dispatcher::dispatch_wasm_via_http(
        engine,
        cfg,
        state.data_dir.clone(),
        state.fact_store.clone(),
        extension_id,
        manifest,
        grant,
        tool_name,
        args,
        calling_passport,
        request_id,
    )
    .await;
    match result {
        Ok(outcome) => (StatusCode::OK, Json(outcome)).into_response(),
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
#[allow(clippy::unused_async)]
async fn dispatch_wasm_kind_or_unsupported(
    _state: AppState,
    _extension_id: String,
    _manifest: IntegrationManifest,
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
