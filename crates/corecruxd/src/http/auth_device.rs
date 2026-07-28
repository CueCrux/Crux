// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Device-authorization grant (RFC 8628) — the "Claude-style" browser login for
//! callers with no host/env access (ExecPlan `crux-unified-login-rails`, M3).
//!
//! Flow:
//! 1. `POST /v1/auth/device/start` → `{device_code, user_code, verification_uri,
//!    interval, expires_in}`. The client shows `user_code` + `verification_uri`
//!    to the human and begins polling.
//! 2. The human opens `/activate` (served by `console.rs`), authenticates as a
//!    console admin, enters the `user_code`, and approves — choosing the tenant +
//!    scopes. `POST /v1/auth/device/approve` records the approver's choice.
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
//! - **Tenant leakage (T.1):** the issued `tenant_id` + scopes come from the
//!   *approver*, never from the polling client.
//! - Gated behind `CORECRUXD_DEVICE_GRANT_ENABLED` (default off) ⇒ 404 disabled.
//!
//! Known limitation (M3): pending grants and refresh credentials live in a
//! process-local registry — a daemon restart invalidates them. Persisting +
//! externalising revocation is tracked for M5 hardening.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use rand::Rng as _; // brings `fill_bytes` into scope (matches repo idiom)

use super::auth_rails::{env_flag_enabled, ISSUED_TOKEN_TTL_SECS};
use crux_mcp::tools::loopback_auth::{mint_scoped_jwt_from_env, ScopedClaims};

use super::*;

/// Opt-in flag for the device-authorization grant. Default off.
const DEVICE_ENABLED_ENV: &str = "CORECRUXD_DEVICE_GRANT_ENABLED";
/// How long a `device_code` / `user_code` pair is valid before it expires.
const DEVICE_CODE_TTL_SECS: u64 = 600;
/// Minimum seconds a client must wait between polls (RFC 8628 `interval`).
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
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
    Consumed,
}

#[derive(Debug, Clone)]
struct DeviceGrant {
    user_code: String,
    client_name: String,
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
    /// Drop expired pending grants (and their user-code index entries).
    fn prune(&mut self, now: u64) {
        let expired: Vec<String> = self
            .grants
            .iter()
            .filter(|(_, g)| now > g.expires_at && g.state != GrantState::Consumed)
            .map(|(k, _)| k.clone())
            .collect();
        for device_code in expired {
            if let Some(g) = self.grants.remove(&device_code) {
                self.by_user_code.remove(&g.user_code);
            }
        }
    }
}

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

/// Advance the poll state machine for one `device/token` call. Mutates the
/// grant's `last_poll` and (on issue) marks it `Consumed` so the `device_code`
/// is one-time. Pure w.r.t. the clock for deterministic tests.
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
        GrantState::Consumed => PollDecision::Expired, // one-time: replay rejected
        GrantState::Approved { tenant_id, scopes } => {
            let decision = PollDecision::Issue {
                tenant_id: tenant_id.clone(),
                scopes: scopes.clone(),
            };
            grant.state = GrantState::Consumed;
            decision
        }
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
    State(_state): State<AppState>,
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
    let client_name = req
        .client_name
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown client".to_string());

    let verification_uri = activate_uri(&headers);
    let verification_uri_complete = format!("{verification_uri}?user_code={user_code}");

    let grant = DeviceGrant {
        user_code: user_code.clone(),
        client_name,
        expires_at: now + DEVICE_CODE_TTL_SECS,
        last_poll: 0,
        interval: DEFAULT_POLL_INTERVAL_SECS,
        state: GrantState::Pending,
    };
    {
        let Ok(mut reg) = REGISTRY.lock() else {
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "device registry unavailable");
        };
        reg.prune(now);
        reg.by_user_code.insert(user_code.clone(), device_code.clone());
        reg.grants.insert(device_code.clone(), grant);
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
    /// Tenant the issued token will be bound to (approver-chosen — T.1).
    pub tenant_id: String,
    /// Scopes the approver grants.
    pub scopes: Vec<String>,
    /// Set true to deny instead of approve.
    #[serde(default)]
    pub deny: bool,
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
    // Approval is an admin action — bind to an authenticated console admin.
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let user_code = req.user_code.trim().to_ascii_uppercase();
    let tenant_id = req.tenant_id.trim().to_string();
    if tenant_id.is_empty() {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "tenant_id is required to approve a device grant",
        );
    }
    let scopes: Vec<String> = req
        .scopes
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if !req.deny && scopes.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "at least one scope is required to approve");
    }

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
    grant.state = if req.deny {
        GrantState::Denied
    } else {
        GrantState::Approved {
            tenant_id: tenant_id.clone(),
            scopes: scopes.clone(),
        }
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
    // Decide under the lock, then mint outside it.
    let decision = {
        let Ok(mut reg) = REGISTRY.lock() else {
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "device registry unavailable");
        };
        reg.prune(now);
        let Some(grant) = reg.grants.get_mut(&req.device_code) else {
            // Unknown device_code: treat as expired (also covers pruned codes).
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "expired_token",
                "unknown or expired device_code",
            );
        };
        decide_poll(grant, now)
    };

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
        PollDecision::Issue { tenant_id, scopes } => issue_device_tokens(&tenant_id, &scopes),
    }
}

/// Mint an access token + create a revocable refresh credential for an approved
/// grant. T.1: `tenant_id`/`scopes` are the approver's, passed in here.
fn issue_device_tokens(tenant_id: &str, scopes: &[String]) -> Response {
    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();
    let cred_id = uuid::Uuid::new_v4().simple().to_string();
    let sub = format!("device:{cred_id}");
    let claims = ScopedClaims {
        sub: &sub,
        scopes: &scope_refs,
        tenant_id,
        ttl_secs: ISSUED_TOKEN_TTL_SECS,
    };
    let Some(access_token) = mint_scoped_jwt_from_env(&claims) else {
        return problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "token issuance requires CORECRUXD_JWT_HS256_SECRET (run the daemon in jwt_hs256 mode)",
        );
    };
    let secret = random_token_b64(32);
    let refresh_token = format!("{cred_id}.{secret}");
    {
        let Ok(mut reg) = REGISTRY.lock() else {
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "device registry unavailable");
        };
        reg.refresh.insert(
            cred_id,
            RefreshCred {
                tenant_id: tenant_id.to_string(),
                scopes: scopes.to_vec(),
                secret,
                revoked: false,
            },
        );
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ISSUED_TOKEN_TTL_SECS,
            "refresh_token": refresh_token,
            "scopes": scopes,
            "tenant_id": tenant_id,
            "rail": "device",
        })),
    )
        .into_response()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct RefreshReq {
    pub refresh_token: String,
}

/// Split a `cred_id.secret` refresh token into its parts.
fn split_refresh(token: &str) -> Option<(&str, &str)> {
    token
        .split_once('.')
        .filter(|(id, secret)| !id.is_empty() && !secret.is_empty())
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_device_refresh(State(_state): State<AppState>, Json(req): Json<RefreshReq>) -> Response {
    if !env_flag_enabled(DEVICE_ENABLED_ENV) {
        return device_disabled_response();
    }
    let Some((cred_id, secret)) = split_refresh(req.refresh_token.trim()) else {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_grant", "malformed refresh_token");
    };
    // Validate under the lock; clone the principal, then mint outside it.
    let principal = {
        let Ok(reg) = REGISTRY.lock() else {
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "device registry unavailable");
        };
        match reg.refresh.get(cred_id) {
            Some(cred) if !cred.revoked && cred.secret == secret => (cred.tenant_id.clone(), cred.scopes.clone()),
            Some(cred) if cred.revoked => {
                return oauth_error(
                    StatusCode::UNAUTHORIZED,
                    "invalid_grant",
                    "refresh credential was revoked",
                );
            }
            _ => return oauth_error(StatusCode::UNAUTHORIZED, "invalid_grant", "unknown refresh credential"),
        }
    };
    let (tenant_id, scopes) = principal;
    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();
    let sub = format!("device:{cred_id}");
    let claims = ScopedClaims {
        sub: &sub,
        scopes: &scope_refs,
        tenant_id: &tenant_id,
        ttl_secs: ISSUED_TOKEN_TTL_SECS,
    };
    match mint_scoped_jwt_from_env(&claims) {
        Some(access_token) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": ISSUED_TOKEN_TTL_SECS,
                "scopes": scopes,
                "tenant_id": tenant_id,
                "rail": "device",
            })),
        )
            .into_response(),
        None => problem_response(
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
    let Some((cred_id, _secret)) = split_refresh(req.refresh_token.trim()) else {
        // Idempotent: a malformed/absent token is already "not active".
        return (StatusCode::OK, Json(serde_json::json!({ "revoked": false }))).into_response();
    };
    let revoked = {
        let Ok(mut reg) = REGISTRY.lock() else {
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, "device registry unavailable");
        };
        match reg.refresh.get_mut(cred_id) {
            Some(cred) => {
                let was_active = !cred.revoked;
                cred.revoked = true;
                was_active
            }
            None => false,
        }
    };
    (StatusCode::OK, Json(serde_json::json!({ "revoked": revoked }))).into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn pending_grant(now: u64) -> DeviceGrant {
        DeviceGrant {
            user_code: "ABCD-2345".to_string(),
            client_name: "test".to_string(),
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
    fn poll_approved_issues_once_then_expired() {
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
        assert_eq!(g.state, GrantState::Consumed);
        // Replay of the same device_code → expired_token (one-time use).
        assert_eq!(decide_poll(&mut g, now + 10), PollDecision::Expired);
    }

    #[test]
    fn split_refresh_parses_and_rejects() {
        assert_eq!(split_refresh("id123.secretabc"), Some(("id123", "secretabc")));
        assert!(split_refresh("nodot").is_none());
        assert!(split_refresh(".secret").is_none());
        assert!(split_refresh("id.").is_none());
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
    fn registry_prune_drops_expired_pending() {
        let now = 1_000_000;
        let mut reg = DeviceRegistry::default();
        let mut g = pending_grant(now);
        g.expires_at = now - 1;
        reg.by_user_code.insert(g.user_code.clone(), "D".to_string());
        reg.grants.insert("D".to_string(), g);
        reg.prune(now);
        assert!(reg.grants.is_empty());
        assert!(reg.by_user_code.is_empty());
    }
}
