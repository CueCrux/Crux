// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Device-authorization grant (RFC 8628) — the "Claude-style" browser login for
//! callers with no host/env access (ExecPlan `crux-unified-login-rails`, M3).
//!
//! Flow:
//! 1. `POST /v1/auth/device/start` → `{device_code, user_code, verification_uri,
//!    interval, expires_in}`. The client shows `user_code` + `verification_uri`
//!    to the human and begins polling.
//! 2. The human opens `/activate` (served by `console.rs`), authenticates as a
//!    console admin, enters the `user_code`, and approves — choosing one tenant
//!    plus a scope subset already held by that admin.
//!    `POST /v1/auth/device/approve` records the attenuated choice.
//! 3. `POST /v1/auth/device/token` (poll) → `authorization_pending` /
//!    `slow_down` / `expired_token` / `access_denied`, or, once approved,
//!    `{access_token, refresh_token, expires_in, scopes}`. The `device_code` is
//!    one-time: a second successful poll is rejected.
//! 4. `POST /v1/auth/device/refresh` mints a fresh access token from a named
//!    refresh credential; `POST /v1/auth/device/revoke` revokes it (`crux logout`).
//!
//! Security posture (see ExecPlan Risks):
//! - **Phishing:** short `user_code` TTL; `/activate` shows the requesting client
//!   name; approval is bound to an authenticated console admin (`admin:write`).
//! - **Tenant leakage (T.1):** the issued `tenant_id` + scopes are a concrete
//!   subset of the authenticated approver's verified grants, never authority
//!   supplied by the polling client or approval form.
//! - **Availability:** every device-auth request has a route-local body cap;
//!   client labels and the process-local grant/refresh registries are bounded.
//! - Gated behind `CORECRUXD_DEVICE_GRANT_ENABLED` (default off) ⇒ 404 disabled.
//!
//! Known limitation (M3): pending grants and refresh credentials live in a
//! process-local registry — a daemon restart invalidates them. Persisting +
//! externalising revocation is tracked for M5 hardening.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::ConnectInfo;
use base64::Engine as _;
use rand::Rng as _; // brings `fill_bytes` into scope (matches repo idiom)
use subtle::ConstantTimeEq as _;

use super::auth_rails::{env_flag_enabled, ISSUED_TOKEN_TTL_SECS};
use crate::auth::HttpScopeContext;
use crux_mcp::tools::loopback_auth::{mint_scoped_jwt_from_env, ScopedClaims};

use super::*;

/// Opt-in flag for the device-authorization grant. Default off.
const DEVICE_ENABLED_ENV: &str = "CORECRUXD_DEVICE_GRANT_ENABLED";
/// How long a `device_code` / `user_code` pair is valid before it expires.
const DEVICE_CODE_TTL_SECS: u64 = 600;
/// Minimum seconds a client must wait between polls (RFC 8628 `interval`).
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
/// Route-local body cap for every public device-auth request.
pub(super) const DEVICE_AUTH_MAX_REQUEST_BYTES: usize = 16 * 1024;
/// Maximum UTF-8 byte length of the client label rendered on `/activate`.
const MAX_CLIENT_NAME_BYTES: usize = 256;
/// Hard cap on pending grants from one ingress-resolved effective client IP.
const MAX_PENDING_DEVICE_GRANTS_PER_IP: usize = 16;
/// Hard cap on pending grants across all effective client IPs.
const MAX_PENDING_DEVICE_GRANTS: usize = 1_024;
/// Hard cap on all live device-code rows. Expired rows are pruned before admission.
const MAX_DEVICE_GRANTS_TOTAL: usize = 4_096;
/// Hard cap on active refresh credentials. Revoked rows are pruned before admission.
const MAX_REFRESH_CREDENTIALS: usize = 4_096;
/// Absolute lifetime of a device refresh credential (90 days).
const REFRESH_CREDENTIAL_TTL_SECS: u64 = 90 * 24 * 60 * 60;
/// Unambiguous user-code alphabet (no 0/O/1/I).
const USER_CODE_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── server-side registry (process-local; see module note) ──────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
enum GrantState {
    Pending,
    Approved { tenant_id: String, scopes: Vec<String> },
    Denied,
}

#[derive(Debug, Clone)]
struct DeviceGrant {
    user_code: String,
    client_name: String,
    request_ip: IpAddr,
    expires_at: u64,
    last_poll: u64,
    interval: u64,
    state: GrantState,
}

#[derive(Debug, Clone)]
struct RefreshCred {
    tenant_id: String,
    scopes: Vec<String>,
    secret: String,
    expires_at: u64,
    revoked: bool,
}

#[derive(Default)]
struct DeviceRegistry {
    grants: HashMap<String, DeviceGrant>,  // device_code → grant
    by_user_code: HashMap<String, String>, // user_code → device_code
    refresh: HashMap<String, RefreshCred>, // cred_id → refresh credential
}

static REGISTRY: LazyLock<Mutex<DeviceRegistry>> = LazyLock::new(|| Mutex::new(DeviceRegistry::default()));

impl DeviceRegistry {
    /// Drop every expired grant (and its user-code index entry). Successfully
    /// issued grants are removed immediately, so replay and expiry share the
    /// same non-enumerating `expired_token` response.
    fn prune(&mut self, now: u64) {
        let expired: Vec<String> = self
            .grants
            .iter()
            .filter(|(_, g)| now > g.expires_at)
            .map(|(k, _)| k.clone())
            .collect();
        for device_code in expired {
            if let Some(g) = self.grants.remove(&device_code) {
                self.by_user_code.remove(&g.user_code);
            }
        }
    }

    fn insert_grant(&mut self, device_code: String, grant: DeviceGrant, now: u64) -> Result<(), RegistryCapacityError> {
        self.prune(now);
        if self.grants.len() >= MAX_DEVICE_GRANTS_TOTAL {
            return Err(RegistryCapacityError);
        }
        let pending_total = self
            .grants
            .values()
            .filter(|existing| matches!(existing.state, GrantState::Pending))
            .count();
        if pending_total >= MAX_PENDING_DEVICE_GRANTS {
            return Err(RegistryCapacityError);
        }
        let pending_for_ip = self
            .grants
            .values()
            .filter(|existing| existing.request_ip == grant.request_ip && matches!(existing.state, GrantState::Pending))
            .count();
        if pending_for_ip >= MAX_PENDING_DEVICE_GRANTS_PER_IP {
            return Err(RegistryCapacityError);
        }
        self.by_user_code.insert(grant.user_code.clone(), device_code.clone());
        self.grants.insert(device_code, grant);
        Ok(())
    }

    fn insert_refresh_credential(
        &mut self,
        cred_id: String,
        credential: RefreshCred,
        now: u64,
    ) -> Result<(), RegistryCapacityError> {
        self.prune_refresh_credentials(now);
        if self.refresh.len() >= MAX_REFRESH_CREDENTIALS || self.refresh.contains_key(&cred_id) {
            return Err(RegistryCapacityError);
        }
        self.refresh.insert(cred_id, credential);
        Ok(())
    }

    fn prune_refresh_credentials(&mut self, now: u64) {
        self.refresh
            .retain(|_, credential| !credential.revoked && now < credential.expires_at);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegistryCapacityError;

// ── code generation ────────────────────────────────────────────────────────

fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    buf
}

fn random_token_b64(n_bytes: usize) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes(n_bytes))
}

/// Generate a human-friendly `XXXX-XXXX` user code from the unambiguous alphabet.
/// The modulo over a 31-char alphabet adds negligible bias for a display code.
fn random_user_code() -> String {
    let bytes = random_bytes(8);
    let pick = |b: u8| USER_CODE_ALPHABET[(b as usize) % USER_CODE_ALPHABET.len()] as char;
    let first: String = bytes[0..4].iter().map(|&b| pick(b)).collect();
    let second: String = bytes[4..8].iter().map(|&b| pick(b)).collect();
    format!("{first}-{second}")
}

// ── pure poll-decision state machine (unit-tested) ─────────────────────────

#[derive(Debug, PartialEq, Eq)]
enum PollDecision {
    SlowDown,
    Pending,
    Denied,
    Expired,
    Issue { tenant_id: String, scopes: Vec<String> },
}

/// Advance the poll state machine for one `device/token` call. This mutates
/// only `last_poll`; an approved grant is retired atomically with refresh
/// credential insertion by [`issue_approved_grant`].
fn decide_poll(grant: &mut DeviceGrant, now: u64) -> PollDecision {
    if now > grant.expires_at {
        return PollDecision::Expired;
    }
    // Rate-limit polls (RFC 8628 slow_down): reject if quicker than `interval`.
    if now.saturating_sub(grant.last_poll) < grant.interval {
        grant.last_poll = now;
        return PollDecision::SlowDown;
    }
    grant.last_poll = now;
    match &grant.state {
        GrantState::Pending => PollDecision::Pending,
        GrantState::Denied => PollDecision::Denied,
        GrantState::Approved { tenant_id, scopes } => PollDecision::Issue {
            tenant_id: tenant_id.clone(),
            scopes: scopes.clone(),
        },
    }
}

fn device_disabled_response() -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        "device authorization grant disabled (set CORECRUXD_DEVICE_GRANT_ENABLED=1)",
    )
}

fn oauth_error(status: StatusCode, error: &str, description: &str) -> Response {
    (
        status,
        Json(serde_json::json!({ "error": error, "error_description": description })),
    )
        .into_response()
}

fn oauth_retryable_error(status: StatusCode, error: &str, description: &str, retry_after_secs: u64) -> Response {
    let mut response = oauth_error(status, error, description);
    if let Ok(value) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        response.headers_mut().insert(header::RETRY_AFTER, value);
    }
    response
}

fn normalize_client_name(client_name: Option<String>) -> Result<String, &'static str> {
    let normalized = client_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("unknown client");
    if normalized.len() > MAX_CLIENT_NAME_BYTES || normalized.chars().any(char::is_control) {
        return Err("client_name must be at most 256 UTF-8 bytes and contain no control characters");
    }
    Ok(normalized.to_string())
}

fn device_request_ip(state: &AppState, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    let trusted_proxy_cidrs = state
        .session
        .as_ref()
        .map(|services| super::ingress::parse_trusted_proxy_cidrs(&services.policy.trusted_proxy_cidrs))
        .unwrap_or_default();
    super::ingress::effective_client_ip(headers, Some(peer.ip()), &trusted_proxy_cidrs)
        .key_ip
        .unwrap_or_else(|| peer.ip())
}

// ── handlers ────────────────────────────────────────────────────────────────

#[derive(Debug, Default, serde::Deserialize)]
pub(super) struct DeviceStartReq {
    /// Human-readable name of the requesting client (shown on `/activate`).
    #[serde(default)]
    pub client_name: Option<String>,
    // The client may also send an advisory `scopes` array; it is intentionally
    // ignored (serde drops unknown fields) — the *approver* decides the granted
    // scopes (threat ref T.1).
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_device_start(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Option<Json<DeviceStartReq>>,
) -> Response {
    if !env_flag_enabled(DEVICE_ENABLED_ENV) {
        return device_disabled_response();
    }
    let req = body.map(|Json(b)| b).unwrap_or_default();
    let now = now_secs();
    let device_code = random_token_b64(32);
    let user_code = random_user_code();
    let request_ip = device_request_ip(&state, &headers, peer);
    let client_name = match normalize_client_name(req.client_name) {
        Ok(client_name) => client_name,
        Err(description) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", description),
    };

    let verification_uri = activate_uri(&headers);
    let verification_uri_complete = format!("{verification_uri}?user_code={user_code}");

    let grant = DeviceGrant {
        user_code: user_code.clone(),
        client_name,
        request_ip,
        expires_at: now + DEVICE_CODE_TTL_SECS,
        last_poll: 0,
        interval: DEFAULT_POLL_INTERVAL_SECS,
        state: GrantState::Pending,
    };
    {
        let Ok(mut reg) = REGISTRY.lock() else {
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "device registry unavailable");
        };
        if reg.insert_grant(device_code.clone(), grant, now).is_err() {
            return oauth_retryable_error(
                StatusCode::TOO_MANY_REQUESTS,
                "temporarily_unavailable",
                "device authorization capacity reached; retry after existing codes expire",
                DEFAULT_POLL_INTERVAL_SECS,
            );
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": verification_uri_complete,
            "expires_in": DEVICE_CODE_TTL_SECS,
            "interval": DEFAULT_POLL_INTERVAL_SECS,
        })),
    )
        .into_response()
}

/// Build the `/activate` URI from the request's forwarded host/proto headers.
fn activate_uri(headers: &HeaderMap) -> String {
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| "127.0.0.1:14800".to_string(), str::to_string);
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map_or_else(
            || "http".to_string(),
            |s| s.split(',').next().unwrap_or(s).trim().to_string(),
        );
    format!("{scheme}://{host}/activate")
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct DeviceApproveReq {
    pub user_code: String,
    /// Desired tenant. The server requires it to be inside the approver's
    /// verified tenant grant.
    pub tenant_id: String,
    /// Desired scopes. The server rejects any scope the approver does not hold.
    pub scopes: Vec<String>,
    /// Set true to deny instead of approve.
    #[serde(default)]
    pub deny: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AttenuatedDeviceGrant {
    tenant_id: String,
    scopes: Vec<String>,
}

#[allow(clippy::result_large_err)]
fn require_device_approver(context: &HttpScopeContext) -> Result<(), ProblemResponse> {
    if !context.auth_enforced() {
        return Err(ProblemResponse(
            corecrux_types::ProblemDetails::forbidden("device approval requires enforced HTTP authentication")
                .with_extensions(serde_json::json!({
                    "code": "DEVICE_APPROVER_AUTH_REQUIRED",
                })),
        ));
    }
    if !context.has_scope("admin:write") {
        return Err(ProblemResponse(
            corecrux_types::ProblemDetails::forbidden("insufficient scopes").with_extensions(serde_json::json!({
                "code": "MISSING_SCOPE",
                "missingScopes": ["admin:write"],
            })),
        ));
    }
    // DevScopes is an explicit local-development rail. In production JWT
    // modes, device approval is a human delegation boundary: an automation
    // token, a device token (no canonical passport), a sub-only JWT, or an
    // admin passport-header override must not mint a fresh credential chain.
    if !context.local_unverified_identity()
        && (context.credential_is_agent_token()
            || context.passport_override_used()
            || !context.canonical_passport_claim_verified())
    {
        return Err(ProblemResponse(
            corecrux_types::ProblemDetails::forbidden(
                "device approval requires the bearer token's canonical human passport",
            )
            .with_extensions(serde_json::json!({
                "code": "DEVICE_APPROVER_HUMAN_REQUIRED",
            })),
        ));
    }
    Ok(())
}

/// Resolve one concrete tenant and a canonical scope subset from the verified
/// approver context. Approval is delegation, not a fresh authority source:
/// `admin:write` permits the decision but does not widen tenant or scope.
#[allow(clippy::result_large_err)]
fn attenuate_device_grant(
    context: &HttpScopeContext,
    requested_tenant: &str,
    requested_scopes: &[String],
) -> Result<AttenuatedDeviceGrant, ProblemResponse> {
    require_device_approver(context)?;

    let requested_tenant = requested_tenant.trim();
    if requested_tenant.is_empty() || requested_tenant == "*" {
        return Err(ProblemResponse(corecrux_types::ProblemDetails::bad_request(
            "one concrete tenant_id is required to approve a device grant",
        )));
    }
    let tenant_id = context.resolve_authorized_tenant(Some(requested_tenant))?;

    let scopes: BTreeSet<String> = requested_scopes
        .iter()
        .map(|scope| scope.trim())
        .filter(|scope| !scope.is_empty())
        .map(str::to_string)
        .collect();
    if scopes.is_empty() {
        return Err(ProblemResponse(corecrux_types::ProblemDetails::bad_request(
            "at least one scope is required to approve",
        )));
    }

    let unauthorized_scopes: Vec<String> = scopes
        .iter()
        .filter(|scope| !context.has_scope(scope))
        .cloned()
        .collect();
    if !unauthorized_scopes.is_empty() {
        return Err(ProblemResponse(
            corecrux_types::ProblemDetails::forbidden("device grant scopes exceed approver authority").with_extensions(
                serde_json::json!({
                    "code": "DEVICE_GRANT_SCOPE_WIDENING",
                    "unauthorizedScopes": unauthorized_scopes,
                }),
            ),
        ));
    }

    Ok(AttenuatedDeviceGrant {
        tenant_id,
        scopes: scopes.into_iter().collect(),
    })
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_device_approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeviceApproveReq>,
) -> Response {
    if !env_flag_enabled(DEVICE_ENABLED_ENV) {
        return device_disabled_response();
    }
    // Approval is delegation by an authenticated admin, not authority supplied
    // by this request body.
    let context = match http_scope_context(&state.auth, &headers) {
        Ok(context) => context,
        Err(problem) => return problem.into_response(),
    };
    if let Err(problem) = require_device_approver(&context) {
        return problem.into_response();
    }
    let user_code = req.user_code.trim().to_ascii_uppercase();
    let approved = if req.deny {
        None
    } else {
        match attenuate_device_grant(&context, &req.tenant_id, &req.scopes) {
            Ok(grant) => Some(grant),
            Err(problem) => return problem.into_response(),
        }
    };

    let now = now_secs();
    let Ok(mut reg) = REGISTRY.lock() else {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "device registry unavailable");
    };
    reg.prune(now);
    let Some(device_code) = reg.by_user_code.get(&user_code).cloned() else {
        return problem_response(StatusCode::NOT_FOUND, "unknown or expired user_code");
    };
    let Some(grant) = reg.grants.get_mut(&device_code) else {
        return problem_response(StatusCode::NOT_FOUND, "unknown or expired user_code");
    };
    if !matches!(grant.state, GrantState::Pending) {
        return problem_response(StatusCode::CONFLICT, "device grant is no longer pending");
    }
    let client_name = grant.client_name.clone();
    grant.state = match approved {
        None => GrantState::Denied,
        Some(AttenuatedDeviceGrant { tenant_id, scopes }) => GrantState::Approved { tenant_id, scopes },
    };
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "ok": true,
            "user_code": user_code,
            "client_name": client_name,
            "decision": if req.deny { "denied" } else { "approved" },
        })),
    )
        .into_response()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct DeviceTokenReq {
    pub device_code: String,
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_device_token(State(_state): State<AppState>, Json(req): Json<DeviceTokenReq>) -> Response {
    if !env_flag_enabled(DEVICE_ENABLED_ENV) {
        return device_disabled_response();
    }
    let now = now_secs();
    // The local JWT mint, refresh insertion, and grant retirement share one
    // registry critical section. Any failure leaves Approved retryable instead
    // of burning the one-time code.
    let Ok(mut reg) = REGISTRY.lock() else {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "device registry unavailable");
    };
    reg.prune(now);
    let Some(grant) = reg.grants.get_mut(&req.device_code) else {
        // Unknown device_code: treat as expired (also covers pruned/consumed codes).
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "unknown or expired device_code",
        );
    };
    let decision = decide_poll(grant, now);
    match decision {
        PollDecision::SlowDown => oauth_error(StatusCode::BAD_REQUEST, "slow_down", "poll interval not yet elapsed"),
        PollDecision::Pending => oauth_error(
            StatusCode::BAD_REQUEST,
            "authorization_pending",
            "approval is still pending",
        ),
        PollDecision::Denied => oauth_error(StatusCode::BAD_REQUEST, "access_denied", "the request was denied"),
        PollDecision::Expired => oauth_error(
            StatusCode::BAD_REQUEST,
            "expired_token",
            "the device_code has expired or was already used",
        ),
        PollDecision::Issue { .. } => {
            let issued = issue_approved_grant(&mut reg, &req.device_code, now, |cred_id, tenant_id, scopes| {
                let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();
                let sub = format!("device:{cred_id}");
                mint_scoped_jwt_from_env(&ScopedClaims {
                    sub: &sub,
                    passport_id: None,
                    scopes: &scope_refs,
                    tenant_id,
                    ttl_secs: ISSUED_TOKEN_TTL_SECS,
                })
            });
            match issued {
                Ok(issued) => issued_device_tokens_response(issued),
                Err(DeviceIssueError::MintUnavailable) => problem_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "token issuance requires CORECRUXD_JWT_HS256_SECRET (run the daemon in jwt_hs256 mode)",
                ),
                Err(DeviceIssueError::RefreshCapacity) => oauth_retryable_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "temporarily_unavailable",
                    "device refresh credential capacity reached; revoke an existing login and retry",
                    DEFAULT_POLL_INTERVAL_SECS,
                ),
                Err(DeviceIssueError::GrantUnavailable) => problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "approved device grant disappeared during token issuance",
                ),
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IssuedDeviceTokens {
    access_token: String,
    refresh_token: String,
    tenant_id: String,
    scopes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceIssueError {
    GrantUnavailable,
    MintUnavailable,
    RefreshCapacity,
}

/// Mint and commit one approved grant while the caller holds the registry
/// lock. T.1: tenant/scopes were attenuated against the approver before they
/// reached the registry. The grant remains Approved on every error.
fn issue_approved_grant<F>(
    reg: &mut DeviceRegistry,
    device_code: &str,
    now: u64,
    mint: F,
) -> Result<IssuedDeviceTokens, DeviceIssueError>
where
    F: FnOnce(&str, &str, &[String]) -> Option<String>,
{
    let (user_code, tenant_id, scopes) = match reg.grants.get(device_code) {
        Some(DeviceGrant {
            user_code,
            state: GrantState::Approved { tenant_id, scopes },
            ..
        }) => (user_code.clone(), tenant_id.clone(), scopes.clone()),
        _ => return Err(DeviceIssueError::GrantUnavailable),
    };
    reg.prune_refresh_credentials(now);
    if reg.refresh.len() >= MAX_REFRESH_CREDENTIALS {
        return Err(DeviceIssueError::RefreshCapacity);
    }
    let cred_id = uuid::Uuid::new_v4().simple().to_string();
    if reg.refresh.contains_key(&cred_id) {
        return Err(DeviceIssueError::RefreshCapacity);
    }
    let Some(access_token) = mint(&cred_id, &tenant_id, &scopes) else {
        return Err(DeviceIssueError::MintUnavailable);
    };
    let secret = random_token_b64(32);
    let refresh_token = format!("{cred_id}.{secret}");
    reg.insert_refresh_credential(
        cred_id.clone(),
        RefreshCred {
            tenant_id: tenant_id.clone(),
            scopes: scopes.clone(),
            secret,
            expires_at: now.saturating_add(REFRESH_CREDENTIAL_TTL_SECS),
            revoked: false,
        },
        now,
    )
    .map_err(|_| DeviceIssueError::RefreshCapacity)?;
    let removed = reg.grants.remove(device_code);
    if removed.is_none() {
        reg.refresh.remove(&cred_id);
        return Err(DeviceIssueError::GrantUnavailable);
    }
    reg.by_user_code.remove(&user_code);
    Ok(IssuedDeviceTokens {
        access_token,
        refresh_token,
        tenant_id,
        scopes,
    })
}

fn issued_device_tokens_response(issued: IssuedDeviceTokens) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "access_token": issued.access_token,
            "token_type": "Bearer",
            "expires_in": ISSUED_TOKEN_TTL_SECS,
            "refresh_token": issued.refresh_token,
            "refresh_expires_in": REFRESH_CREDENTIAL_TTL_SECS,
            "scopes": issued.scopes,
            "tenant_id": issued.tenant_id,
            "rail": "device",
        })),
    )
        .into_response()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct RefreshReq {
    pub refresh_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RefreshedDeviceAccess {
    access_token: String,
    tenant_id: String,
    scopes: Vec<String>,
    refresh_expires_in: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefreshAccessError {
    RegistryUnavailable,
    Unknown,
    Revoked,
    Expired,
    IssuanceUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RegistryUnavailable;

/// Split a `cred_id.secret` refresh token into its parts.
fn split_refresh(token: &str) -> Option<(&str, &str)> {
    token
        .split_once('.')
        .filter(|(id, secret)| !id.is_empty() && !secret.is_empty())
}

fn refresh_secrets_match(stored: &str, presented: &str) -> bool {
    bool::from(stored.as_bytes().ct_eq(presented.as_bytes()))
}

/// Validate and mint while holding the credential registry lock. This gives
/// refresh and revoke one ordering boundary: when revoke returns, no refresh
/// that validated before it can still enter token issuance afterwards.
fn refresh_device_credential<F>(
    registry: &Mutex<DeviceRegistry>,
    cred_id: &str,
    secret: &str,
    now: u64,
    mint: F,
) -> Result<RefreshedDeviceAccess, RefreshAccessError>
where
    F: FnOnce(&str, &[String]) -> Option<String>,
{
    let mut reg = registry.lock().map_err(|_| RefreshAccessError::RegistryUnavailable)?;
    let Some(credential) = reg.refresh.get(cred_id) else {
        return Err(RefreshAccessError::Unknown);
    };
    // Check the bearer secret before exposing whether a known credential has
    // been revoked. The access-token subject discloses only `cred_id`.
    if !refresh_secrets_match(&credential.secret, secret) {
        return Err(RefreshAccessError::Unknown);
    }
    if credential.revoked {
        return Err(RefreshAccessError::Revoked);
    }
    let tenant_id = credential.tenant_id.clone();
    let scopes = credential.scopes.clone();
    let expires_at = credential.expires_at;
    if now >= expires_at {
        reg.refresh.remove(cred_id);
        return Err(RefreshAccessError::Expired);
    }
    let access_token = mint(&tenant_id, &scopes).ok_or(RefreshAccessError::IssuanceUnavailable)?;
    let refreshed = RefreshedDeviceAccess {
        access_token,
        tenant_id,
        scopes,
        refresh_expires_in: expires_at.saturating_sub(now),
    };
    drop(reg);
    Ok(refreshed)
}

/// RFC 7009-style idempotent revocation: unknown and incorrectly authenticated
/// credentials both report `false`, and neither changes registry state.
fn revoke_refresh_credential(
    registry: &Mutex<DeviceRegistry>,
    cred_id: &str,
    secret: &str,
) -> Result<bool, RegistryUnavailable> {
    let mut reg = registry.lock().map_err(|_| RegistryUnavailable)?;
    let authenticated = reg
        .refresh
        .get(cred_id)
        .is_some_and(|credential| refresh_secrets_match(&credential.secret, secret));
    if authenticated {
        reg.refresh.remove(cred_id);
        Ok(true)
    } else {
        Ok(false)
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_device_refresh(State(_state): State<AppState>, Json(req): Json<RefreshReq>) -> Response {
    if !env_flag_enabled(DEVICE_ENABLED_ENV) {
        return device_disabled_response();
    }
    let Some((cred_id, secret)) = split_refresh(req.refresh_token.trim()) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_grant", "malformed refresh_token");
    };
    let now = now_secs();
    let refreshed = refresh_device_credential(&REGISTRY, cred_id, secret, now, |tenant_id, scopes| {
        let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();
        let sub = format!("device:{cred_id}");
        mint_scoped_jwt_from_env(&ScopedClaims {
            sub: &sub,
            passport_id: None,
            scopes: &scope_refs,
            tenant_id,
            ttl_secs: ISSUED_TOKEN_TTL_SECS,
        })
    });
    match refreshed {
        Ok(RefreshedDeviceAccess {
            access_token,
            tenant_id,
            scopes,
            refresh_expires_in,
        }) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ISSUED_TOKEN_TTL_SECS,
                "refresh_expires_in": refresh_expires_in,
                "scopes": scopes,
                "tenant_id": tenant_id,
                "rail": "device",
            })),
        )
            .into_response(),
        Err(RefreshAccessError::RegistryUnavailable) => {
            problem_response(StatusCode::INTERNAL_SERVER_ERROR, "device registry unavailable")
        }
        Err(RefreshAccessError::Revoked) => oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_grant",
            "refresh credential was revoked",
        ),
        Err(RefreshAccessError::Expired) => oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_grant",
            "refresh credential expired; run device login again",
        ),
        Err(RefreshAccessError::Unknown) => {
            oauth_error(StatusCode::UNAUTHORIZED, "invalid_grant", "unknown refresh credential")
        }
        Err(RefreshAccessError::IssuanceUnavailable) => problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "token issuance requires CORECRUXD_JWT_HS256_SECRET (run the daemon in jwt_hs256 mode)",
        ),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_device_revoke(State(_state): State<AppState>, Json(req): Json<RefreshReq>) -> Response {
    if !env_flag_enabled(DEVICE_ENABLED_ENV) {
        return device_disabled_response();
    }
    let Some((cred_id, secret)) = split_refresh(req.refresh_token.trim()) else {
        // Idempotent: a malformed/absent token is already "not active".
        return (StatusCode::OK, Json(serde_json::json!({ "revoked": false }))).into_response();
    };
    let revoked = match revoke_refresh_credential(&REGISTRY, cred_id, secret) {
        Ok(revoked) => revoked,
        Err(RegistryUnavailable) => {
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "device registry unavailable");
        }
    };
    (StatusCode::OK, Json(serde_json::json!({ "revoked": revoked }))).into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const APPROVAL_TEST_SECRET: &[u8] = b"device-approval-test-secret-32-bytes";
    const APPROVAL_TEST_ISSUER: &str = "corecrux-device-approval-test";
    const APPROVAL_TEST_AUDIENCE: &str = "corecrux";

    fn approval_context(claims: serde_json::Value, tenant_header: Option<&str>) -> HttpScopeContext {
        approval_context_with_passport_header(claims, tenant_header, None)
    }

    fn approval_context_with_passport_header(
        mut claims: serde_json::Value,
        tenant_header: Option<&str>,
        passport_header: Option<&str>,
    ) -> HttpScopeContext {
        let object = claims.as_object_mut().expect("claims object");
        object.insert(
            "exp".to_string(),
            serde_json::json!(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system time after epoch")
                    .as_secs()
                    + 3_600
            ),
        );
        object.insert("iss".to_string(), serde_json::json!(APPROVAL_TEST_ISSUER));
        object.insert("aud".to_string(), serde_json::json!(APPROVAL_TEST_AUDIENCE));
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(APPROVAL_TEST_SECRET),
        )
        .expect("approval test JWT");
        let auth = crate::auth::Authz::test_hs256(APPROVAL_TEST_SECRET, APPROVAL_TEST_ISSUER, APPROVAL_TEST_AUDIENCE);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("bearer header"),
        );
        if let Some(tenant) = tenant_header {
            headers.insert(
                "x-corecrux-tenant-id",
                HeaderValue::from_str(tenant).expect("tenant header"),
            );
        }
        if let Some(passport) = passport_header {
            headers.insert(
                "x-corecrux-passport-id",
                HeaderValue::from_str(passport).expect("passport header"),
            );
        }
        http_scope_context(&auth, &headers).expect("verified approval context")
    }

    fn problem_code(problem: &ProblemResponse) -> Option<&str> {
        problem
            .0
            .extensions
            .as_ref()
            .and_then(|extensions| extensions.get("code"))
            .and_then(serde_json::Value::as_str)
    }

    fn pending_grant(now: u64) -> DeviceGrant {
        DeviceGrant {
            user_code: "ABCD-2345".to_string(),
            client_name: "test".to_string(),
            request_ip: "192.0.2.1".parse().expect("test IP"),
            expires_at: now + 600,
            last_poll: 0,
            interval: 5,
            state: GrantState::Pending,
        }
    }

    #[test]
    fn user_code_shape() {
        let c = random_user_code();
        assert_eq!(c.len(), 9);
        assert_eq!(c.as_bytes()[4], b'-');
        assert!(c
            .chars()
            .all(|ch| ch == '-' || USER_CODE_ALPHABET.contains(&(ch as u8))));
    }

    #[test]
    fn poll_pending_then_slow_down() {
        let now = 1_000_000;
        let mut g = pending_grant(now);
        // First poll (last_poll=0, now huge) → interval elapsed → Pending.
        assert_eq!(decide_poll(&mut g, now), PollDecision::Pending);
        // Immediate re-poll → slow_down.
        assert_eq!(decide_poll(&mut g, now + 1), PollDecision::SlowDown);
        // After interval → Pending again.
        assert_eq!(decide_poll(&mut g, now + 10), PollDecision::Pending);
    }

    #[test]
    fn poll_expired() {
        let now = 1_000_000;
        let mut g = pending_grant(now);
        assert_eq!(decide_poll(&mut g, now + 601), PollDecision::Expired);
    }

    #[test]
    fn poll_denied() {
        let now = 1_000_000;
        let mut g = pending_grant(now);
        g.state = GrantState::Denied;
        assert_eq!(decide_poll(&mut g, now), PollDecision::Denied);
    }

    #[test]
    fn poll_approved_remains_retryable_until_committed() {
        let now = 1_000_000;
        let mut g = pending_grant(now);
        g.state = GrantState::Approved {
            tenant_id: "acme".to_string(),
            scopes: vec!["query:read".to_string()],
        };
        match decide_poll(&mut g, now) {
            PollDecision::Issue { tenant_id, scopes } => {
                assert_eq!(tenant_id, "acme");
                assert_eq!(scopes, vec!["query:read"]);
            }
            other => panic!("expected Issue, got {other:?}"),
        }
        assert!(matches!(g.state, GrantState::Approved { .. }));
        assert!(matches!(decide_poll(&mut g, now + 10), PollDecision::Issue { .. }));
    }

    #[test]
    fn split_refresh_parses_and_rejects() {
        assert_eq!(split_refresh("id123.secretabc"), Some(("id123", "secretabc")));
        assert!(split_refresh("nodot").is_none());
        assert!(split_refresh(".secret").is_none());
        assert!(split_refresh("id.").is_none());
    }

    fn registry_with_refresh_credential() -> Mutex<DeviceRegistry> {
        let mut registry = DeviceRegistry::default();
        registry.refresh.insert(
            "credential-id".to_string(),
            RefreshCred {
                tenant_id: "tenant-a".to_string(),
                scopes: vec!["query:read".to_string()],
                secret: "legitimate-secret".to_string(),
                expires_at: 2_000_000,
                revoked: false,
            },
        );
        Mutex::new(registry)
    }

    #[test]
    fn refresh_revoke_requires_the_complete_secret_and_is_idempotent() {
        let registry = registry_with_refresh_credential();

        assert_eq!(
            revoke_refresh_credential(&registry, "credential-id", "attacker-secret"),
            Ok(false)
        );
        let refreshed = refresh_device_credential(
            &registry,
            "credential-id",
            "legitimate-secret",
            1_000_000,
            |tenant_id, scopes| {
                assert_eq!(tenant_id, "tenant-a");
                assert_eq!(scopes, ["query:read"]);
                Some("fresh-access-token".to_string())
            },
        )
        .expect("wrong-secret revocation must leave the credential active");
        assert_eq!(refreshed.access_token, "fresh-access-token");

        assert_eq!(
            revoke_refresh_credential(&registry, "credential-id", "legitimate-secret"),
            Ok(true)
        );
        assert_eq!(
            revoke_refresh_credential(&registry, "credential-id", "legitimate-secret"),
            Ok(false)
        );
        assert_eq!(
            revoke_refresh_credential(&registry, "credential-id", "attacker-secret"),
            Ok(false)
        );
        assert_eq!(
            refresh_device_credential(&registry, "credential-id", "attacker-secret", 1_000_000, |_, _| {
                Some("must-not-mint".to_string())
            },),
            Err(RefreshAccessError::Unknown)
        );
        assert_eq!(
            refresh_device_credential(&registry, "credential-id", "legitimate-secret", 1_000_000, |_, _| {
                Some("must-not-mint".to_string())
            },),
            Err(RefreshAccessError::Unknown)
        );
    }

    #[test]
    fn revoke_waits_for_an_inflight_refresh_to_finish_minting() {
        use std::sync::{mpsc, Arc, TryLockError};

        let registry = Arc::new(registry_with_refresh_credential());
        let refresh_registry = Arc::clone(&registry);
        let (mint_started_tx, mint_started_rx) = mpsc::channel();
        let (allow_mint_tx, allow_mint_rx) = mpsc::channel();
        let refresh = std::thread::spawn(move || {
            refresh_device_credential(
                &refresh_registry,
                "credential-id",
                "legitimate-secret",
                1_000_000,
                |_, _| {
                    mint_started_tx.send(()).expect("signal mint start");
                    allow_mint_rx.recv().expect("release mint");
                    Some("ordered-access-token".to_string())
                },
            )
        });
        mint_started_rx.recv().expect("refresh reached mint boundary");
        assert!(
            matches!(registry.try_lock(), Err(TryLockError::WouldBlock)),
            "refresh must retain the registry ordering lock throughout token issuance"
        );

        let revoke_registry = Arc::clone(&registry);
        let (revoke_started_tx, revoke_started_rx) = mpsc::channel();
        let revoke = std::thread::spawn(move || {
            revoke_started_tx.send(()).expect("signal revoke attempt");
            revoke_refresh_credential(&revoke_registry, "credential-id", "legitimate-secret")
        });
        revoke_started_rx.recv().expect("revoke thread started");

        allow_mint_tx.send(()).expect("finish refresh mint");
        let refreshed = refresh.join().expect("refresh thread").expect("refresh succeeds");
        assert_eq!(refreshed.access_token, "ordered-access-token");
        assert_eq!(revoke.join().expect("revoke thread"), Ok(true));
    }

    #[test]
    fn activate_uri_uses_host_and_forwarded_proto() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "crux.example.com".parse().unwrap());
        h.insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(activate_uri(&h), "https://crux.example.com/activate");
    }

    #[test]
    fn activate_uri_defaults_when_headers_absent() {
        assert_eq!(activate_uri(&HeaderMap::new()), "http://127.0.0.1:14800/activate");
    }

    #[test]
    fn registry_prune_drops_every_expired_state_and_keeps_active_rows() {
        let now = 1_000_000;
        let mut reg = DeviceRegistry::default();
        for (index, state) in [
            GrantState::Pending,
            GrantState::Approved {
                tenant_id: "tenant-a".to_string(),
                scopes: vec!["query:read".to_string()],
            },
            GrantState::Denied,
        ]
        .into_iter()
        .enumerate()
        {
            let mut grant = pending_grant(now);
            grant.user_code = format!("EXPIRED-{index}");
            grant.expires_at = now - 1;
            grant.state = state;
            let device_code = format!("expired-device-{index}");
            reg.by_user_code.insert(grant.user_code.clone(), device_code.clone());
            reg.grants.insert(device_code, grant);
        }
        let active = pending_grant(now);
        reg.by_user_code
            .insert(active.user_code.clone(), "active-device".to_string());
        reg.grants.insert("active-device".to_string(), active);

        reg.prune(now);

        assert_eq!(reg.grants.len(), 1);
        assert_eq!(reg.by_user_code.len(), 1);
        assert!(reg.grants.contains_key("active-device"));
    }

    #[test]
    fn client_name_is_trimmed_and_byte_bounded() {
        assert_eq!(
            normalize_client_name(Some("  trusted client  ".to_string())),
            Ok("trusted client".to_string())
        );
        assert_eq!(normalize_client_name(None), Ok("unknown client".to_string()));
        assert_eq!(
            normalize_client_name(Some("   ".to_string())),
            Ok("unknown client".to_string())
        );
        assert!(normalize_client_name(Some("a".repeat(MAX_CLIENT_NAME_BYTES))).is_ok());
        assert!(normalize_client_name(Some("a".repeat(MAX_CLIENT_NAME_BYTES + 1))).is_err());
        assert!(normalize_client_name(Some("line\nbreak".to_string())).is_err());
        assert!(normalize_client_name(Some("é".repeat((MAX_CLIENT_NAME_BYTES / 2) + 1))).is_err());
    }

    #[test]
    fn device_grant_registry_limits_pending_per_effective_ip() {
        let now = 1_000_000;
        let mut reg = DeviceRegistry::default();
        for index in 0..MAX_PENDING_DEVICE_GRANTS_PER_IP {
            let mut grant = pending_grant(now);
            grant.user_code = format!("USER-{index}");
            reg.insert_grant(format!("device-{index}"), grant, now)
                .expect("per-IP capacity admits configured number of grants");
        }

        let mut rejected = pending_grant(now);
        rejected.user_code = "REJECTED".to_string();
        assert_eq!(
            reg.insert_grant("rejected-device".to_string(), rejected, now),
            Err(RegistryCapacityError)
        );
        assert!(!reg.by_user_code.contains_key("REJECTED"));

        let mut other_ip = pending_grant(now);
        other_ip.user_code = "OTHER-IP".to_string();
        other_ip.request_ip = "192.0.2.2".parse().expect("test IP");
        reg.insert_grant("other-ip-device".to_string(), other_ip, now)
            .expect("one saturated IP must not starve another");
    }

    #[test]
    fn device_grant_registry_limits_pending_and_total_rows() {
        let now = 1_000_000;
        let mut pending = DeviceRegistry::default();
        for index in 0..MAX_PENDING_DEVICE_GRANTS {
            let mut grant = pending_grant(now);
            grant.user_code = format!("PENDING-{index}");
            grant.request_ip = IpAddr::V6((index as u128 + 1).into());
            pending
                .insert_grant(format!("pending-device-{index}"), grant, now)
                .expect("global pending capacity admits configured number");
        }
        let mut pending_rejected = pending_grant(now);
        pending_rejected.user_code = "PENDING-REJECTED".to_string();
        pending_rejected.request_ip = "2001:db8::ffff".parse().expect("test IP");
        assert_eq!(
            pending.insert_grant("pending-rejected".to_string(), pending_rejected, now),
            Err(RegistryCapacityError)
        );

        let mut total = DeviceRegistry::default();
        for index in 0..MAX_DEVICE_GRANTS_TOTAL {
            let mut grant = pending_grant(now);
            grant.user_code = format!("TOTAL-{index}");
            grant.state = GrantState::Denied;
            total
                .insert_grant(format!("total-device-{index}"), grant, now)
                .expect("total capacity admits configured number");
        }
        let mut total_rejected = pending_grant(now);
        total_rejected.user_code = "TOTAL-REJECTED".to_string();
        assert_eq!(
            total.insert_grant("total-rejected".to_string(), total_rejected, now),
            Err(RegistryCapacityError)
        );
        assert_eq!(total.grants.len(), MAX_DEVICE_GRANTS_TOTAL);
        assert!(!total.by_user_code.contains_key("TOTAL-REJECTED"));
    }

    #[test]
    fn expired_grant_frees_admission_and_preserves_indexes() {
        let now = 1_000_000;
        let mut reg = DeviceRegistry::default();
        for index in 0..MAX_PENDING_DEVICE_GRANTS_PER_IP {
            let mut grant = pending_grant(now);
            grant.user_code = format!("EXPIRED-{index}");
            grant.expires_at = now - 1;
            let device_code = format!("expired-{index}");
            reg.by_user_code.insert(grant.user_code.clone(), device_code.clone());
            reg.grants.insert(device_code, grant);
        }
        let mut admitted = pending_grant(now);
        admitted.user_code = "ADMITTED".to_string();
        reg.insert_grant("admitted".to_string(), admitted, now)
            .expect("expired rows are pruned before admission");
        assert_eq!(reg.grants.len(), 1);
        assert_eq!(reg.by_user_code.len(), 1);
        assert_eq!(reg.by_user_code.get("ADMITTED").map(String::as_str), Some("admitted"));
    }

    #[test]
    fn refresh_registry_is_bounded_and_reclaims_revoked_rows() {
        let now = 1_000_000;
        let mut reg = DeviceRegistry::default();
        for index in 0..MAX_REFRESH_CREDENTIALS {
            reg.insert_refresh_credential(
                format!("credential-{index}"),
                RefreshCred {
                    tenant_id: "tenant-a".to_string(),
                    scopes: vec!["query:read".to_string()],
                    secret: format!("secret-{index}"),
                    expires_at: now + REFRESH_CREDENTIAL_TTL_SECS,
                    revoked: false,
                },
                now,
            )
            .expect("capacity admits configured number of refresh credentials");
        }

        let credential = RefreshCred {
            tenant_id: "tenant-a".to_string(),
            scopes: vec!["query:read".to_string()],
            secret: "replacement-secret".to_string(),
            expires_at: now + REFRESH_CREDENTIAL_TTL_SECS,
            revoked: false,
        };
        assert_eq!(
            reg.insert_refresh_credential("rejected".to_string(), credential.clone(), now),
            Err(RegistryCapacityError)
        );
        reg.refresh.get_mut("credential-0").expect("seeded credential").revoked = true;
        reg.insert_refresh_credential("replacement".to_string(), credential, now)
            .expect("revoked row is reclaimed before capacity check");
        assert_eq!(reg.refresh.len(), MAX_REFRESH_CREDENTIALS);
        assert!(!reg.refresh.contains_key("credential-0"));
        assert!(reg.refresh.contains_key("replacement"));
    }

    fn approved_registry(now: u64) -> DeviceRegistry {
        let mut reg = DeviceRegistry::default();
        let mut grant = pending_grant(now);
        grant.state = GrantState::Approved {
            tenant_id: "tenant-a".to_string(),
            scopes: vec!["query:read".to_string()],
        };
        reg.insert_grant("approved-device".to_string(), grant, now)
            .expect("approved fixture admission");
        reg
    }

    #[test]
    fn failed_device_token_mint_leaves_approved_grant_retryable() {
        let now = 1_000_000;
        let mut reg = approved_registry(now);

        assert_eq!(
            issue_approved_grant(&mut reg, "approved-device", now, |_, _, _| None),
            Err(DeviceIssueError::MintUnavailable)
        );
        assert!(matches!(
            reg.grants.get("approved-device").map(|grant| &grant.state),
            Some(GrantState::Approved { .. })
        ));
        assert_eq!(
            reg.by_user_code.get("ABCD-2345").map(String::as_str),
            Some("approved-device")
        );
        assert!(reg.refresh.is_empty());
    }

    #[test]
    fn refresh_capacity_failure_does_not_mint_or_consume_and_retry_commits_once() {
        use std::cell::Cell;

        let now = 1_000_000;
        let mut reg = approved_registry(now);
        for index in 0..MAX_REFRESH_CREDENTIALS {
            reg.refresh.insert(
                format!("existing-{index}"),
                RefreshCred {
                    tenant_id: "tenant-a".to_string(),
                    scopes: vec!["query:read".to_string()],
                    secret: format!("secret-{index}"),
                    expires_at: now + REFRESH_CREDENTIAL_TTL_SECS,
                    revoked: false,
                },
            );
        }
        let mint_called = Cell::new(false);
        assert_eq!(
            issue_approved_grant(&mut reg, "approved-device", now, |_, _, _| {
                mint_called.set(true);
                Some("must-not-mint".to_string())
            }),
            Err(DeviceIssueError::RefreshCapacity)
        );
        assert!(!mint_called.get());
        assert!(matches!(
            reg.grants.get("approved-device").map(|grant| &grant.state),
            Some(GrantState::Approved { .. })
        ));

        reg.refresh.remove("existing-0");
        let issued = issue_approved_grant(&mut reg, "approved-device", now, |_, tenant_id, scopes| {
            assert_eq!(tenant_id, "tenant-a");
            assert_eq!(scopes, ["query:read"]);
            Some("issued-access-token".to_string())
        })
        .expect("free capacity permits atomic retry");
        assert_eq!(issued.access_token, "issued-access-token");
        assert_eq!(reg.refresh.len(), MAX_REFRESH_CREDENTIALS);
        assert!(!reg.grants.contains_key("approved-device"));
        assert!(!reg.by_user_code.contains_key("ABCD-2345"));
        assert_eq!(
            issue_approved_grant(&mut reg, "approved-device", now, |_, _, _| {
                Some("must-not-replay".to_string())
            }),
            Err(DeviceIssueError::GrantUnavailable)
        );
    }

    #[test]
    fn refresh_expiry_is_terminal_before_mint_and_prunes_the_row() {
        use std::cell::Cell;

        let now = 1_000_000;
        let registry = registry_with_refresh_credential();
        registry
            .lock()
            .expect("registry lock")
            .refresh
            .get_mut("credential-id")
            .expect("seeded credential")
            .expires_at = now;
        let mint_called = Cell::new(false);
        assert_eq!(
            refresh_device_credential(&registry, "credential-id", "legitimate-secret", now, |_, _| {
                mint_called.set(true);
                Some("must-not-mint".to_string())
            }),
            Err(RefreshAccessError::Expired)
        );
        assert!(!mint_called.get());
        assert!(!registry
            .lock()
            .expect("registry lock")
            .refresh
            .contains_key("credential-id"));
    }

    #[test]
    fn refresh_prune_removes_expired_and_revoked_but_retains_active() {
        let now = 1_000_000;
        let credential = |expires_at, revoked| RefreshCred {
            tenant_id: "tenant-a".to_string(),
            scopes: vec!["query:read".to_string()],
            secret: "secret".to_string(),
            expires_at,
            revoked,
        };
        let mut reg = DeviceRegistry::default();
        reg.refresh.insert("active".to_string(), credential(now + 1, false));
        reg.refresh.insert("expired".to_string(), credential(now, false));
        reg.refresh.insert("revoked".to_string(), credential(now + 1, true));

        reg.prune_refresh_credentials(now);

        assert_eq!(reg.refresh.len(), 1);
        assert!(reg.refresh.contains_key("active"));
    }

    #[test]
    fn device_approval_accepts_only_an_admins_tenant_and_scope_subset() {
        let context = approval_context(
            serde_json::json!({
                "scope": "admin:write query:read facts:write",
                "tenant_id": "tenant-a",
                "passport_id": "approver-1",
            }),
            None,
        );
        let grant = attenuate_device_grant(
            &context,
            " tenant-a ",
            &[
                "facts:write".to_string(),
                " query:read ".to_string(),
                "facts:write".to_string(),
            ],
        )
        .expect("authorized subset");
        assert_eq!(grant.tenant_id, "tenant-a");
        assert_eq!(grant.scopes, vec!["facts:write", "query:read"]);
    }

    #[test]
    fn device_approval_rejects_scope_widening() {
        let context = approval_context(
            serde_json::json!({
                "scope": "admin:write query:read",
                "tenant_id": "tenant-a",
                "passport_id": "approver-1",
            }),
            None,
        );
        let error = attenuate_device_grant(
            &context,
            "tenant-a",
            &["query:read".to_string(), "facts:write".to_string()],
        )
        .expect_err("facts:write exceeds approver authority");
        assert_eq!(error.0.status, 403);
        assert_eq!(problem_code(&error), Some("DEVICE_GRANT_SCOPE_WIDENING"));
        assert_eq!(
            error
                .0
                .extensions
                .as_ref()
                .and_then(|extensions| extensions.get("unauthorizedScopes")),
            Some(&serde_json::json!(["facts:write"]))
        );
    }

    #[test]
    fn device_approval_rejects_tenant_widening_and_missing_tenant_claim() {
        let context = approval_context(
            serde_json::json!({
                "scope": "admin:write query:read",
                "tenant_id": "tenant-a",
                "passport_id": "approver-1",
            }),
            None,
        );
        let wrong_tenant = attenuate_device_grant(&context, "tenant-b", &["query:read".to_string()])
            .expect_err("tenant-b exceeds approver authority");
        assert_eq!(wrong_tenant.0.status, 403);
        assert_eq!(problem_code(&wrong_tenant), Some("TENANT_FORBIDDEN"));

        let missing_tenant = approval_context(
            serde_json::json!({
                "scope": "admin:write query:read",
                "passport_id": "approver-1",
            }),
            None,
        );
        let error = attenuate_device_grant(&missing_tenant, "default", &["query:read".to_string()])
            .expect_err("authenticated device approval requires tenant authority");
        assert_eq!(error.0.status, 403);
        assert_eq!(problem_code(&error), Some("TENANT_CLAIM_MISSING"));
    }

    #[test]
    fn device_approval_requires_unambiguous_multi_tenant_selection() {
        let context = approval_context(
            serde_json::json!({
                "scope": "admin:write query:read",
                "tenants": ["tenant-a", "tenant-b"],
                "passport_id": "approver-1",
            }),
            None,
        );
        let ambiguous = attenuate_device_grant(&context, "", &["query:read".to_string()])
            .expect_err("approval must choose one tenant");
        assert_eq!(ambiguous.0.status, 400);

        let grant =
            attenuate_device_grant(&context, "tenant-b", &["query:read".to_string()]).expect("explicit allowed tenant");
        assert_eq!(grant.tenant_id, "tenant-b");

        let header_bound = approval_context(
            serde_json::json!({
                "scope": "admin:write query:read",
                "tenants": ["tenant-a", "tenant-b"],
                "passport_id": "approver-1",
            }),
            Some("tenant-a"),
        );
        let mismatch = attenuate_device_grant(&header_bound, "tenant-b", &["query:read".to_string()])
            .expect_err("body and verified selector must agree");
        assert_eq!(mismatch.0.status, 403);
        assert_eq!(problem_code(&mismatch), Some("TENANT_SELECTOR_MISMATCH"));
    }

    #[test]
    fn device_approval_allows_global_admin_only_for_an_explicit_tenant() {
        let context = approval_context(
            serde_json::json!({
                "scope": "admin:write query:read",
                "tenant_id": "*",
                "passport_id": "approver-1",
            }),
            None,
        );
        let grant = attenuate_device_grant(&context, "tenant-new", &["query:read".to_string()])
            .expect("global tenant authority with explicit tenant");
        assert_eq!(grant.tenant_id, "tenant-new");

        let ambiguous = attenuate_device_grant(&context, " ", &["query:read".to_string()])
            .expect_err("global admin must still choose a tenant");
        assert_eq!(ambiguous.0.status, 400);

        let wildcard = attenuate_device_grant(&context, "*", &["query:read".to_string()])
            .expect_err("issued token must bind one concrete tenant");
        assert_eq!(wildcard.0.status, 400);
    }

    #[test]
    fn device_approval_rejects_non_human_production_credentials() {
        let device_context = approval_context(
            serde_json::json!({
                "scope": "admin:write query:read",
                "tenant_id": "tenant-a",
                "sub": "device:credential-id",
            }),
            None,
        );
        let error = attenuate_device_grant(&device_context, "tenant-a", &["query:read".to_string()])
            .expect_err("device credentials cannot recursively approve");
        assert_eq!(error.0.status, 403);
        assert_eq!(problem_code(&error), Some("DEVICE_APPROVER_HUMAN_REQUIRED"));

        let sub_only_context = approval_context(
            serde_json::json!({
                "scope": "admin:write query:read",
                "tenant_id": "tenant-a",
                "sub": "operator@example.test",
            }),
            None,
        );
        let error = attenuate_device_grant(&sub_only_context, "tenant-a", &["query:read".to_string()])
            .expect_err("sub-only identity is not a canonical human passport");
        assert_eq!(problem_code(&error), Some("DEVICE_APPROVER_HUMAN_REQUIRED"));

        let override_context = approval_context_with_passport_header(
            serde_json::json!({
                "scope": "admin:write query:read",
                "tenant_id": "tenant-a",
                "passport_id": "approver-1",
            }),
            None,
            Some("impersonated-approver"),
        );
        let error = attenuate_device_grant(&override_context, "tenant-a", &["query:read".to_string()])
            .expect_err("passport override cannot satisfy the approval boundary");
        assert_eq!(problem_code(&error), Some("DEVICE_APPROVER_HUMAN_REQUIRED"));
    }

    #[test]
    fn device_approval_requires_admin_write_without_scope_implication() {
        let context = approval_context(
            serde_json::json!({
                "scope": "query:read facts:write",
                "tenant_id": "tenant-a",
                "passport_id": "approver-1",
            }),
            None,
        );
        let error = attenuate_device_grant(&context, "tenant-a", &["query:read".to_string()])
            .expect_err("delegation requires admin:write");
        assert_eq!(error.0.status, 403);
        assert_eq!(problem_code(&error), Some("MISSING_SCOPE"));
    }

    #[test]
    fn device_approval_retains_explicit_dev_scopes_local_flow() {
        let auth = crate::auth::Authz::from_env(crate::auth::AuthMode::DevScopes).expect("dev scopes auth");
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-corecrux-scopes",
            "admin:write query:read".parse().expect("scope header"),
        );
        let context = http_scope_context(&auth, &headers).expect("dev approval context");
        let grant = attenuate_device_grant(&context, "local-dev", &["query:read".to_string()])
            .expect("explicit dev-scopes flow");
        assert_eq!(grant.tenant_id, "local-dev");
        assert_eq!(grant.scopes, vec!["query:read"]);
    }

    #[test]
    fn device_approval_rejects_auth_off_even_with_scope_bypass() {
        let auth = crate::auth::Authz::from_env(crate::auth::AuthMode::Off).expect("off auth");
        let context = http_scope_context(&auth, &HeaderMap::new()).expect("local auth-off context");
        let error = attenuate_device_grant(&context, "default", &["admin:write".to_string()])
            .expect_err("auth-off cannot approve durable bearer credentials");
        assert_eq!(error.0.status, 403);
        assert_eq!(problem_code(&error), Some("DEVICE_APPROVER_AUTH_REQUIRED"));
    }
}
