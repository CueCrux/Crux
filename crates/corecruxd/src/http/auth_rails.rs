// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Auth-rail endpoints — the daemon side of `crux login` (ExecPlan
//! `crux-unified-login-rails`).
//!
//! M2 — **Tailscale identity rail.** Behind `tailscale serve`, the local proxy
//! injects a verified tailnet identity header (`Tailscale-User-Login`) on
//! forwarded requests. This module:
//!
//! - `GET  /v1/auth/whoami` — echoes the identity the daemon *trusts* for the
//!   caller (public-ish; no credential needed). Used by the CLI to decide
//!   whether the tailnet rail is available.
//! - `POST /v1/auth/tailscale/token` — maps the verified identity to a principal
//!   via an operator-controlled allowlist and mints a short-lived scoped JWT
//!   (reusing the single minter, `crux_mcp::tools::loopback_auth`).
//!
//! Security posture (see ExecPlan Risks):
//! - Identity headers are trusted **only** when the request peer is loopback or
//!   an operator-listed trusted proxy CIDR — never from a direct non-loopback
//!   client (which could spoof the header). WireGuard is the proof.
//! - `tenant_id` is derived from the allowlist mapping for the identity, never
//!   from anything the client sends (threat ref T.1).
//! - The whole rail is gated behind `CORECRUXD_TS_IDENTITY_ENABLED` (default
//!   off): disabled ⇒ 404, so existing deployments are unaffected.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use axum::extract::ConnectInfo;
use crux_mcp::tools::loopback_auth::{mint_scoped_jwt_from_env, ScopedClaims};

use super::{problem_response, AppState, HeaderMap, IntoResponse, Json, Response, State, StatusCode};

/// Opt-in flag for the Tailscale identity rail. Default off.
const TS_ENABLED_ENV: &str = "CORECRUXD_TS_IDENTITY_ENABLED";
/// Operator allowlist mapping tailnet logins → principal (tenant + scopes).
/// Format: comma-separated `login=tenant:scopeA|scopeB`, e.g.
/// `alice@example.com=acme:facts:write|query:read,bot@ex.com=acme:query:read`.
const TS_ALLOWLIST_ENV: &str = "CORECRUXD_TS_IDENTITY_ALLOWLIST";
/// Extra trusted-proxy CIDRs from which identity headers are honoured. Loopback
/// is always trusted; this adds the tailnet-proxy peer when it is not loopback.
const TS_TRUSTED_CIDRS_ENV: &str = "CORECRUXD_TS_TRUSTED_PROXY_CIDRS";
/// Header injected by `tailscale serve` carrying the verified user login.
const TS_LOGIN_HEADER: &str = "tailscale-user-login";
/// Lifetime of issued access tokens. Issuance rails keep this ≤ 5 minutes.
pub(super) const ISSUED_TOKEN_TTL_SECS: u64 = 300;

/// A principal the daemon will issue a token for, resolved from the allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TsPrincipal {
    /// Tenant the issued token is bound to (T.1: from the allowlist only).
    pub tenant_id: String,
    /// Scopes the issued token carries.
    pub scopes: Vec<String>,
}

/// Read a boolean opt-in env flag (`1`/`true`/`yes`, case-insensitive).
pub(super) fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"))
}

/// Parse the tailnet identity allowlist. Malformed entries are skipped. Logins
/// are lowercased for case-insensitive matching.
pub(super) fn parse_ts_allowlist(raw: &str) -> BTreeMap<String, TsPrincipal> {
    let mut out = BTreeMap::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((login, spec)) = entry.split_once('=') else {
            continue;
        };
        let login = login.trim().to_ascii_lowercase();
        if login.is_empty() {
            continue;
        }
        let Some((tenant, scopes_raw)) = spec.split_once(':') else {
            continue;
        };
        let tenant = tenant.trim().to_string();
        if tenant.is_empty() {
            continue;
        }
        let scopes: Vec<String> = scopes_raw
            .split('|')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if scopes.is_empty() {
            continue;
        }
        out.insert(
            login,
            TsPrincipal {
                tenant_id: tenant,
                scopes,
            },
        );
    }
    out
}

/// Extract the tailnet login from the request headers (lowercased, trimmed).
pub(super) fn extract_ts_login(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(TS_LOGIN_HEADER).and_then(|v| v.to_str().ok())?;
    let trimmed = raw.trim().to_ascii_lowercase();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// Normalise an IP: collapse IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to IPv4 so
/// loopback/CIDR checks behave consistently across dual-stack listeners.
pub(super) fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        other => other,
    }
}

/// Parse a `addr/prefix` CIDR. Returns `None` on malformed input.
pub(super) fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (addr, bits) = s.trim().split_once('/')?;
    let ip: IpAddr = addr.trim().parse().ok()?;
    let prefix: u8 = bits.trim().parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    (prefix <= max).then_some((normalize_ip(ip), prefix))
}

/// Whether `ip` falls inside the CIDR `(network, prefix)`. Mixed families ⇒ false.
pub(super) fn ip_in_cidr(ip: IpAddr, (network, prefix): (IpAddr, u8)) -> bool {
    match (normalize_ip(ip), network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            (u128::from(ip) & mask) == (u128::from(net) & mask)
        }
        _ => false,
    }
}

/// Parse the trusted-proxy CIDRs from env; loopback is always trusted, so an
/// empty/unset value still trusts the local `tailscale serve` proxy.
fn trusted_cidrs() -> Vec<(IpAddr, u8)> {
    std::env::var(TS_TRUSTED_CIDRS_ENV)
        .ok()
        .map(|raw| raw.split(',').filter_map(parse_cidr).collect())
        .unwrap_or_default()
}

/// Decide whether identity headers from `peer` may be trusted. Loopback is
/// always trusted (the proxy runs on the same host); otherwise the peer must be
/// in an operator-listed trusted CIDR. No peer info ⇒ never trusted (fail closed).
pub(super) fn peer_identity_trusted(peer: Option<IpAddr>, trusted: &[(IpAddr, u8)]) -> bool {
    let Some(peer) = peer.map(normalize_ip) else {
        return false;
    };
    if peer.is_loopback() {
        return true;
    }
    trusted.iter().any(|cidr| ip_in_cidr(peer, *cidr))
}

/// `GET /v1/auth/whoami` — echo the identity the daemon trusts for this caller.
pub(super) async fn get_whoami(
    State(_state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !env_flag_enabled(TS_ENABLED_ENV) {
        return ts_disabled_response();
    }
    let trusted = peer_identity_trusted(Some(normalize_ip(peer.ip())), &trusted_cidrs());
    let login = if trusted { extract_ts_login(&headers) } else { None };
    let allowlist = parse_ts_allowlist(&std::env::var(TS_ALLOWLIST_ENV).unwrap_or_default());
    let allowlisted = login.as_ref().is_some_and(|l| allowlist.contains_key(l));
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "source": if login.is_some() { "tailscale" } else { "none" },
            "trusted": trusted,
            "login": login,
            "allowlisted": allowlisted,
            "rail": "tailscale",
        })),
    )
        .into_response()
}

/// `POST /v1/auth/tailscale/token` — mint a scoped short-lived JWT for a verified,
/// allowlisted tailnet identity.
pub(super) async fn post_tailscale_token(
    State(_state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if !env_flag_enabled(TS_ENABLED_ENV) {
        return ts_disabled_response();
    }
    if !peer_identity_trusted(Some(normalize_ip(peer.ip())), &trusted_cidrs()) {
        return problem_response(
            StatusCode::FORBIDDEN,
            "tailscale identity is only trusted from the local proxy peer (loopback or \
             CORECRUXD_TS_TRUSTED_PROXY_CIDRS); a direct non-loopback client cannot use this rail",
        );
    }
    let Some(login) = extract_ts_login(&headers) else {
        return problem_response(
            StatusCode::UNAUTHORIZED,
            "no tailscale identity header (Tailscale-User-Login) on the request",
        );
    };
    let allowlist = parse_ts_allowlist(&std::env::var(TS_ALLOWLIST_ENV).unwrap_or_default());
    let Some(principal) = allowlist.get(&login) else {
        return problem_response(
            StatusCode::FORBIDDEN,
            format!("tailnet identity '{login}' is not in CORECRUXD_TS_IDENTITY_ALLOWLIST"),
        );
    };

    // T.1: tenant + scopes come from the allowlist (approver-controlled), never
    // from the client.
    let scope_refs: Vec<&str> = principal.scopes.iter().map(String::as_str).collect();
    let sub = format!("ts:{login}");
    let claims = ScopedClaims {
        sub: &sub,
        scopes: &scope_refs,
        tenant_id: &principal.tenant_id,
        ttl_secs: ISSUED_TOKEN_TTL_SECS,
    };
    match mint_scoped_jwt_from_env(&claims) {
        Some(token) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": ISSUED_TOKEN_TTL_SECS,
                "scopes": principal.scopes,
                "tenant_id": principal.tenant_id,
                "sub": sub,
                "rail": "tailscale",
            })),
        )
            .into_response(),
        None => problem_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "token issuance requires CORECRUXD_JWT_HS256_SECRET (run the daemon in jwt_hs256 mode)",
        ),
    }
}

fn ts_disabled_response() -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        "tailscale identity rail disabled (set CORECRUXD_TS_IDENTITY_ENABLED=1)",
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_parses_login_tenant_scopes() {
        let raw = "Alice@Example.com=acme:facts:write|query:read, bot@ex.com=acme:query:read";
        let m = parse_ts_allowlist(raw);
        // login lowercased.
        let alice = m.get("alice@example.com").unwrap();
        assert_eq!(alice.tenant_id, "acme");
        assert_eq!(alice.scopes, vec!["facts:write", "query:read"]);
        let bot = m.get("bot@ex.com").unwrap();
        assert_eq!(bot.scopes, vec!["query:read"]);
    }

    #[test]
    fn allowlist_skips_malformed_entries() {
        let raw = "noequals, login-without-colon=oops, =acme:scope, ok@x=acme:query:read, blank@x=acme:";
        let m = parse_ts_allowlist(raw);
        assert!(m.contains_key("ok@x"));
        assert!(!m.contains_key("blank@x")); // no scopes
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn extract_login_lowercases_and_trims() {
        let mut h = HeaderMap::new();
        h.insert(TS_LOGIN_HEADER, "  Alice@Example.com  ".parse().unwrap());
        assert_eq!(extract_ts_login(&h).as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn extract_login_none_when_absent_or_blank() {
        assert!(extract_ts_login(&HeaderMap::new()).is_none());
        let mut h = HeaderMap::new();
        h.insert(TS_LOGIN_HEADER, "   ".parse().unwrap());
        assert!(extract_ts_login(&h).is_none());
    }

    #[test]
    fn loopback_peer_is_trusted() {
        let v4: IpAddr = "127.0.0.1".parse().unwrap();
        let v6: IpAddr = "::1".parse().unwrap();
        assert!(peer_identity_trusted(Some(v4), &[]));
        assert!(peer_identity_trusted(Some(v6), &[]));
    }

    #[test]
    fn ipv4_mapped_loopback_is_trusted() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(peer_identity_trusted(Some(mapped), &[]));
    }

    #[test]
    fn non_loopback_peer_untrusted_without_cidr() {
        let peer: IpAddr = "100.89.67.6".parse().unwrap();
        assert!(!peer_identity_trusted(Some(peer), &[]));
    }

    #[test]
    fn non_loopback_peer_trusted_when_in_cidr() {
        let peer: IpAddr = "100.89.67.6".parse().unwrap();
        let cidr = parse_cidr("100.64.0.0/10").unwrap();
        assert!(peer_identity_trusted(Some(peer), &[cidr]));
    }

    #[test]
    fn missing_peer_fails_closed() {
        assert!(!peer_identity_trusted(None, &[parse_cidr("0.0.0.0/0").unwrap()]));
    }

    #[test]
    fn cidr_match_v4_and_v6() {
        assert!(ip_in_cidr(
            "10.1.2.3".parse().unwrap(),
            parse_cidr("10.0.0.0/8").unwrap()
        ));
        assert!(!ip_in_cidr(
            "11.1.2.3".parse().unwrap(),
            parse_cidr("10.0.0.0/8").unwrap()
        ));
        assert!(ip_in_cidr(
            "2001:db8::1".parse().unwrap(),
            parse_cidr("2001:db8::/32").unwrap()
        ));
        assert!(!ip_in_cidr(
            "2001:dead::1".parse().unwrap(),
            parse_cidr("2001:db8::/32").unwrap()
        ));
    }

    #[test]
    fn cidr_mixed_family_no_match() {
        assert!(!ip_in_cidr("10.0.0.1".parse().unwrap(), parse_cidr("::/0").unwrap()));
    }

    #[test]
    fn parse_cidr_rejects_bad_prefix() {
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert!(parse_cidr("notanip/8").is_none());
        assert!(parse_cidr("10.0.0.0").is_none());
    }

    #[test]
    fn env_flag_truthy_values() {
        // Exercised via a temporary env var unique to this test.
        let key = "CORECRUXD_TS_TEST_FLAG_X";
        std::env::set_var(key, "1");
        assert!(env_flag_enabled(key));
        std::env::set_var(key, "off");
        assert!(!env_flag_enabled(key));
        std::env::remove_var(key);
        assert!(!env_flag_enabled(key));
    }
}
