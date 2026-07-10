// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Shared loopback-auth helpers for MCP tools that call the daemon over HTTP.
//!
//! Background. MCP tools used to send only `X-Corecrux-Scopes: admin:read,…`
//! on loopback requests. That header is consumed by the daemon's `DevScopes`
//! auth mode and ignored by `Off`, but the `JwtHs256` / `JwtJwks` modes ignore
//! it and demand `Authorization: Bearer <token>` — producing a 401 on every
//! coordination, github, storyline, and extension tool when the daemon is in
//! production JWT mode.
//!
//! Fix. Tools must additionally attach a bearer token when one is available
//! in the process environment. Two paths, tried in order:
//!
//! 1. **Mint a short-lived HS256 JWT** using the same `CORECRUXD_JWT_HS256_SECRET`
//!    the daemon's auth module reads on startup. Required for `JwtHs256` mode
//!    (the daemon validates `iss` / `aud` / `exp` / `nbf` exactly as operators
//!    set them in env). Tokens are cached for 4 minutes (TTL is 5 minutes
//!    with a 60 s safety lead) so the sign cost amortises across calls.
//! 2. **Fall back to a raw env-supplied token** (`CRUX_AGENT_TOKEN` or
//!    `CORECRUX_LOOPBACK_TOKEN`). Useful under `Off` / `DevScopes`, harmless
//!    under JWT modes where it will be rejected.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::Serialize;

/// Env var names checked, in order, for a fallback opaque bearer token to
/// attach when a JWT can't be minted.
pub const LOOPBACK_TOKEN_ENV_VARS: &[&str] = &["CORECRUX_LOOPBACK_TOKEN", "CRUX_AGENT_TOKEN"];

/// JWT-secret env var. Must mirror `corecruxd::auth::Authz::from_env`'s read.
pub const JWT_SECRET_ENV: &str = "CORECRUXD_JWT_HS256_SECRET";
pub const JWT_ISS_ENV: &str = "CORECRUXD_JWT_ISS";
pub const JWT_AUD_ENV: &str = "CORECRUXD_JWT_AUD";

/// Claims the minted JWT carries. The daemon's scope-from-claims helper
/// accepts arrays under the `scopes`, `scp`, or `permissions` keys; we use
/// the `scopes` array for clarity. `tenant_id="*"` matches the bridge JWT
/// pattern (cross-tenant scope for internal loopback).
const LOOPBACK_SCOPES: &[&str] = &[
    "admin:read",
    "admin:write",
    "facts:write",
    "query:read",
    "sessions:read",
];

/// Lifetime of a minted JWT. Long enough to amortise the sign cost across
/// dozens of MCP calls; short enough that a leaked token expires fast.
const JWT_TTL_SECS: u64 = 300;
/// Re-mint this many seconds before the cached JWT actually expires so an
/// in-flight loopback never trips `validate_exp` against the daemon.
const JWT_REFRESH_LEAD_SECS: u64 = 60;
/// Backdate `nbf` so a small clock skew between the MCP server and the
/// daemon's `validate_nbf` (with 30 s leeway) can't reject the token at use.
const JWT_NBF_BACKDATE_SECS: u64 = 30;

/// Cached minted JWT.
struct CachedJwt {
    token: String,
    exp_unix: u64,
}

static JWT_CACHE: Mutex<Option<CachedJwt>> = Mutex::new(None);

#[derive(Serialize)]
struct LoopbackClaims<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<&'a str>,
    sub: &'a str,
    scopes: &'a [&'a str],
    tenant_id: &'a str,
    iat: u64,
    nbf: u64,
    exp: u64,
}

/// Parse the daemon's JWT secret env value the way `corecruxd::auth::parse_secret`
/// does — `base64:<payload>` prefix → base64-decode, else raw bytes.
/// Returns `None` (rather than `Err`) so callers can treat "secret not set
/// or malformed" as "no JWT path available; fall back to raw token".
fn parse_jwt_secret(raw: &str) -> Option<Vec<u8>> {
    if let Some(b64) = raw.strip_prefix("base64:") {
        return base64::engine::general_purpose::STANDARD
            .decode(b64)
            .ok()
            .filter(|b| !b.is_empty());
    }
    if raw.is_empty() {
        None
    } else {
        Some(raw.as_bytes().to_vec())
    }
}

/// Pure: mint a JWT with the given inputs. No env reads; no clock reads;
/// no cache. Lets tests verify the claim shape with a deterministic clock.
fn mint_loopback_jwt_inner(
    now_secs: u64,
    secret: &[u8],
    iss: Option<&str>,
    aud: Option<&str>,
) -> Result<String, jsonwebtoken::errors::Error> {
    mint_scoped_jwt_inner(
        now_secs,
        secret,
        iss,
        aud,
        &ScopedClaims {
            sub: "mcp-loopback",
            scopes: LOOPBACK_SCOPES,
            tenant_id: "*",
            ttl_secs: JWT_TTL_SECS,
        },
    )
}

/// Parameters for minting a scoped issuance JWT (the tailnet + device rails reuse
/// this single signing path — see [`crate::tools::loopback_auth`] module docs and
/// the `crux-unified-login-rails` ExecPlan: "one minter, one scope model").
///
/// Unlike the loopback token, an issued credential carries a *specific* subject,
/// scope set, and `tenant_id` (derived from the approving identity, never
/// client-supplied — threat ref T.1).
pub struct ScopedClaims<'a> {
    /// Token subject (the principal the credential acts as).
    pub sub: &'a str,
    /// Granted scopes (the daemon's `scopes_from_claims` reads the `scopes` array).
    pub scopes: &'a [&'a str],
    /// Tenant binding. Use a concrete tenant id; `"*"` only for cross-tenant
    /// internal callers.
    pub tenant_id: &'a str,
    /// Lifetime in seconds. Issuance rails MUST keep this ≤ 300 (5 min).
    pub ttl_secs: u64,
}

/// Pure: mint a scoped HS256 JWT with the daemon-compatible claim shape. No env
/// or clock reads; lets tests assert the claim shape against the daemon's
/// `verify_jwt_hs256` with a deterministic clock.
pub fn mint_scoped_jwt_inner(
    now_secs: u64,
    secret: &[u8],
    iss: Option<&str>,
    aud: Option<&str>,
    claims: &ScopedClaims,
) -> Result<String, jsonwebtoken::errors::Error> {
    let payload = LoopbackClaims {
        iss,
        aud,
        sub: claims.sub,
        scopes: claims.scopes,
        tenant_id: claims.tenant_id,
        iat: now_secs,
        nbf: now_secs.saturating_sub(JWT_NBF_BACKDATE_SECS),
        exp: now_secs + claims.ttl_secs,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &payload,
        &EncodingKey::from_secret(secret),
    )
}

/// Mint a scoped issuance JWT from the daemon's env (`CORECRUXD_JWT_HS256_SECRET`,
/// plus optional `CORECRUXD_JWT_ISS` / `CORECRUXD_JWT_AUD`). Returns `None` when
/// the secret is unset or malformed — issuance requires the daemon to be running
/// in a JWT mode so the minted token verifies. Not cached: each issued token is a
/// distinct subject/tenant and is minted per request.
pub fn mint_scoped_jwt_from_env(claims: &ScopedClaims) -> Option<String> {
    let secret_raw = std::env::var(JWT_SECRET_ENV).ok()?;
    let secret = parse_jwt_secret(&secret_raw)?;
    let iss = std::env::var(JWT_ISS_ENV).ok();
    let aud = std::env::var(JWT_AUD_ENV).ok();
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    mint_scoped_jwt_inner(now_secs, &secret, iss.as_deref(), aud.as_deref(), claims).ok()
}

/// Try to mint and cache a loopback JWT from current env + clock.
/// Returns `None` if the secret env var is unset/malformed or signing fails.
fn mint_loopback_jwt() -> Option<String> {
    let secret_raw = std::env::var(JWT_SECRET_ENV).ok()?;
    let secret = parse_jwt_secret(&secret_raw)?;
    let iss = std::env::var(JWT_ISS_ENV).ok();
    let aud = std::env::var(JWT_AUD_ENV).ok();

    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

    if let Ok(guard) = JWT_CACHE.lock() {
        if let Some(cached) = guard.as_ref() {
            if cached.exp_unix > now_secs + JWT_REFRESH_LEAD_SECS {
                return Some(cached.token.clone());
            }
        }
    }

    let token = mint_loopback_jwt_inner(now_secs, &secret, iss.as_deref(), aud.as_deref()).ok()?;

    if let Ok(mut guard) = JWT_CACHE.lock() {
        *guard = Some(CachedJwt {
            token: token.clone(),
            exp_unix: now_secs + JWT_TTL_SECS,
        });
    }

    Some(token)
}

/// Resolve a bearer token for loopback. Prefers a minted JWT (required by
/// `AuthMode::JwtHs256` / `JwtJwks`); falls back to a raw opaque token from
/// `CRUX_AGENT_TOKEN` or `CORECRUX_LOOPBACK_TOKEN` (which works under `Off` /
/// `DevScopes` but is ignored by JWT modes — sent as defence in depth).
pub fn loopback_bearer_token() -> Option<String> {
    if let Some(jwt) = mint_loopback_jwt() {
        return Some(jwt);
    }
    resolve_bearer_token(|name| std::env::var(name).ok())
}

/// Pure variant of the raw-token resolver used by tests; scans the env-var
/// list but reads from the supplied closure instead of the real environment.
pub(crate) fn resolve_bearer_token<F>(getter: F) -> Option<String>
where
    F: Fn(&str) -> Option<String>,
{
    for var in LOOPBACK_TOKEN_ENV_VARS {
        if let Some(raw) = getter(var) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, DecodingKey, Validation};
    use std::collections::HashMap;

    fn fake_env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        move |name: &str| map.get(name).cloned()
    }

    // ── resolve_bearer_token (raw env path) ──

    #[test]
    fn raw_returns_none_when_all_unset() {
        assert!(resolve_bearer_token(fake_env(&[])).is_none());
    }

    #[test]
    fn raw_returns_value_from_crux_agent_token() {
        let getter = fake_env(&[("CRUX_AGENT_TOKEN", "crux_at_abc")]);
        assert_eq!(resolve_bearer_token(getter).as_deref(), Some("crux_at_abc"));
    }

    #[test]
    fn raw_override_takes_precedence() {
        let getter = fake_env(&[
            ("CRUX_AGENT_TOKEN", "fallback"),
            ("CORECRUX_LOOPBACK_TOKEN", "override"),
        ]);
        assert_eq!(resolve_bearer_token(getter).as_deref(), Some("override"));
    }

    #[test]
    fn raw_whitespace_only_treated_as_unset() {
        let getter = fake_env(&[("CRUX_AGENT_TOKEN", "   ")]);
        assert!(resolve_bearer_token(getter).is_none());
    }

    #[test]
    fn raw_falls_through_to_second_var_when_first_blank() {
        let getter = fake_env(&[("CORECRUX_LOOPBACK_TOKEN", ""), ("CRUX_AGENT_TOKEN", "real")]);
        assert_eq!(resolve_bearer_token(getter).as_deref(), Some("real"));
    }

    // ── parse_jwt_secret (mirrors daemon's parse_secret) ──

    #[test]
    fn parse_jwt_secret_plain_text() {
        let s = parse_jwt_secret("supersecret").unwrap();
        assert_eq!(s, b"supersecret");
    }

    #[test]
    fn parse_jwt_secret_base64_prefix() {
        // "hello" base64 = "aGVsbG8="
        let s = parse_jwt_secret("base64:aGVsbG8=").unwrap();
        assert_eq!(s, b"hello");
    }

    #[test]
    fn parse_jwt_secret_empty_is_none() {
        assert!(parse_jwt_secret("").is_none());
        assert!(parse_jwt_secret("base64:").is_none());
    }

    #[test]
    fn parse_jwt_secret_invalid_base64_is_none() {
        assert!(parse_jwt_secret("base64:!!!not_b64!!!").is_none());
    }

    // ── mint_loopback_jwt_inner (round-trips the daemon's verify_jwt_hs256) ──

    /// Mirrors `corecruxd::auth::verify_jwt_hs256` *except* we disable exp/nbf
    /// time-based checks because the test uses a fixed timestamp that's in the
    /// past relative to wall-clock. exp/nbf values are asserted directly on the
    /// decoded claims below; the time validation behaviour is exercised by
    /// `mint_with_*_rejected_by_validator` instead.
    fn verify_with_daemon_rules(token: &str, secret: &[u8], iss: Option<&str>, aud: Option<&str>) -> serde_json::Value {
        let mut v = Validation::new(Algorithm::HS256);
        v.validate_exp = false;
        v.validate_nbf = false;
        if let Some(i) = iss {
            v.set_issuer(&[i]);
        }
        if let Some(a) = aud {
            v.set_audience(&[a]);
        }
        decode::<serde_json::Value>(token, &DecodingKey::from_secret(secret), &v)
            .expect("verify with daemon rules")
            .claims
    }

    #[test]
    fn mint_round_trips_through_daemon_validation() {
        let secret = b"some-test-secret-bytes-long-enough";
        let now: u64 = 1_700_000_000;
        let token = mint_loopback_jwt_inner(now, secret, Some("cuecrux-crux-mint"), Some("crux.cuecrux.com")).unwrap();
        let claims = verify_with_daemon_rules(&token, secret, Some("cuecrux-crux-mint"), Some("crux.cuecrux.com"));
        assert_eq!(claims["sub"], "mcp-loopback");
        assert_eq!(claims["tenant_id"], "*");
        assert_eq!(claims["iss"], "cuecrux-crux-mint");
        assert_eq!(claims["aud"], "crux.cuecrux.com");
        let scopes = claims["scopes"].as_array().unwrap();
        let scope_strs: Vec<&str> = scopes.iter().map(|s| s.as_str().unwrap()).collect();
        for required in ["admin:read", "facts:write", "query:read", "sessions:read"] {
            assert!(scope_strs.contains(&required), "missing scope {required}");
        }
        assert_eq!(claims["iat"].as_u64().unwrap(), now);
        assert_eq!(claims["exp"].as_u64().unwrap(), now + 300);
        assert_eq!(claims["nbf"].as_u64().unwrap(), now - 30);
    }

    #[test]
    fn scoped_mint_carries_specific_sub_scopes_and_tenant() {
        // Issuance rails (tailnet/device) mint with a concrete principal +
        // tenant — not the loopback "*"/mcp-loopback defaults. Verify the claim
        // shape round-trips through the daemon's validation rules.
        let secret = b"some-test-secret-bytes-long-enough";
        let now: u64 = 1_700_000_000;
        let token = mint_scoped_jwt_inner(
            now,
            secret,
            Some("cuecrux-crux-mint"),
            Some("crux.cuecrux.com"),
            &ScopedClaims {
                sub: "ts:alice@example.com",
                scopes: &["facts:write", "query:read"],
                tenant_id: "acme",
                ttl_secs: 300,
            },
        )
        .unwrap();
        let claims = verify_with_daemon_rules(&token, secret, Some("cuecrux-crux-mint"), Some("crux.cuecrux.com"));
        assert_eq!(claims["sub"], "ts:alice@example.com");
        assert_eq!(claims["tenant_id"], "acme");
        let scopes: Vec<&str> = claims["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        assert_eq!(scopes, vec!["facts:write", "query:read"]);
        assert_eq!(claims["exp"].as_u64().unwrap(), now + 300);
        assert_eq!(claims["nbf"].as_u64().unwrap(), now - 30);
    }

    #[test]
    fn loopback_inner_matches_scoped_inner_for_loopback_defaults() {
        // The loopback minter must remain a thin wrapper over the scoped minter:
        // identical inputs ⇒ identical token (one signing path).
        let secret = b"some-test-secret-bytes-long-enough";
        let now: u64 = 1_700_000_000;
        let a = mint_loopback_jwt_inner(now, secret, None, None).unwrap();
        let b = mint_scoped_jwt_inner(
            now,
            secret,
            None,
            None,
            &ScopedClaims {
                sub: "mcp-loopback",
                scopes: LOOPBACK_SCOPES,
                tenant_id: "*",
                ttl_secs: JWT_TTL_SECS,
            },
        )
        .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn mint_skips_iss_aud_when_unset() {
        let secret = b"some-test-secret";
        let now: u64 = 1_700_000_000;
        let token = mint_loopback_jwt_inner(now, secret, None, None).unwrap();
        // No iss/aud configured on validator either.
        let claims = verify_with_daemon_rules(&token, secret, None, None);
        assert!(claims.get("iss").is_none() || claims["iss"].is_null());
        assert!(claims.get("aud").is_none() || claims["aud"].is_null());
        assert_eq!(claims["sub"], "mcp-loopback");
    }

    #[test]
    fn mint_with_wrong_audience_is_rejected_by_validator() {
        let secret = b"some-test-secret";
        // Use a future timestamp so exp validation isn't the failure cause.
        let now: u64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 60;
        let token = mint_loopback_jwt_inner(now, secret, None, Some("crux.cuecrux.com")).unwrap();
        let mut v = Validation::new(Algorithm::HS256);
        v.validate_exp = true;
        v.set_audience(&["other.cuecrux.com"]);
        let result = decode::<serde_json::Value>(&token, &DecodingKey::from_secret(secret), &v);
        assert!(result.is_err(), "wrong audience should be rejected");
    }

    #[test]
    fn mint_with_wrong_secret_is_rejected_by_validator() {
        let secret = b"correct-secret";
        let wrong = b"wrong-secret";
        let now: u64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 60;
        let token = mint_loopback_jwt_inner(now, secret, None, None).unwrap();
        let mut v = Validation::new(Algorithm::HS256);
        v.validate_exp = true;
        let result = decode::<serde_json::Value>(&token, &DecodingKey::from_secret(wrong), &v);
        assert!(result.is_err(), "wrong secret should be rejected");
    }

    #[test]
    fn nbf_backdate_protects_against_small_clock_skew() {
        // Daemon's clock runs `JWT_NBF_BACKDATE_SECS - 1` ahead of MCP.
        // Token minted at MCP's "now" should still be acceptable.
        let secret = b"s";
        let mcp_now: u64 = 1_700_000_000;
        let token = mint_loopback_jwt_inner(mcp_now, secret, None, None).unwrap();
        // Daemon validates against its own (slightly ahead) clock. We can't
        // easily inject a clock into jsonwebtoken's decode, but the leeway+nbf
        // backdate together give us 60 s of headroom — verify the nbf claim
        // is mcp_now-30 directly.
        let claims = verify_with_daemon_rules(&token, secret, None, None);
        assert_eq!(claims["nbf"].as_u64().unwrap(), mcp_now - 30);
        assert_eq!(claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(), 300);
    }
}
