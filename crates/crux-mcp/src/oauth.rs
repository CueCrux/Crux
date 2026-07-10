// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! OAuth 2.0 resource-server metadata for the MCP endpoint.
//!
//! Makes this daemon's `/mcp` surface an OAuth 2.0 *protected resource* so
//! hosted MCP clients (claude.ai, ChatGPT) can discover the Authorization
//! Server that fronts it (the shared VaultCrux AS) and complete an
//! authorization-code + PKCE flow. Two pieces:
//!
//! - the RFC 9728 *Protected Resource Metadata* document, served at
//!   `/.well-known/oauth-protected-resource`; and
//! - the `WWW-Authenticate: Bearer resource_metadata="…"` challenge added to
//!   the `401` so a client knows where to look.
//!
//! Opt-in and per-daemon: active only when `CRUX_MCP_RESOURCE_URL` is set, so
//! daemons that don't front OAuth behave exactly as before. This is the
//! resource-server half; token *validation* (introspection) lands in a later
//! milestone. See ExecPlan `crux-mcp-oauth-for-hosted-clients-2026-06-23`
//! (M3, work item B).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

/// Default shared Authorization Server when `CRUX_MCP_AUTH_SERVER` is unset.
const DEFAULT_AUTH_SERVER: &str = "https://api.vaultcrux.com";

/// Upper bound on how long an active introspection result is trusted from
/// cache — bounds token-revocation latency.
const MAX_INTROSPECTION_CACHE_TTL_SECS: u64 = 60;

/// Per-daemon OAuth resource configuration, sourced from env.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceConfig {
    /// This daemon's public MCP resource URL, e.g. `https://crux.cuecrux.com/mcp`.
    pub resource_url: String,
    /// Authorization Server base URL(s) — the shared VaultCrux AS.
    pub authorization_servers: Vec<String>,
}

impl ResourceConfig {
    /// Build from env. Returns `None` when OAuth is not configured for this
    /// daemon (`CRUX_MCP_RESOURCE_URL` unset/empty) — preserving pre-OAuth
    /// behaviour for daemons that do not front a hosted-client flow.
    pub fn from_env() -> Option<Self> {
        let resource_url = std::env::var("CRUX_MCP_RESOURCE_URL")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        let authorization_servers = std::env::var("CRUX_MCP_AUTH_SERVER")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map_or_else(|| vec![DEFAULT_AUTH_SERVER.to_string()], |s| vec![s]);
        Some(Self {
            resource_url,
            authorization_servers,
        })
    }

    /// RFC 9728 Protected Resource Metadata document.
    pub fn protected_resource_document(&self) -> Value {
        json!({
            "resource": self.resource_url,
            "authorization_servers": self.authorization_servers,
            "scopes_supported": ["mcp:read"],
            "bearer_methods_supported": ["header"],
        })
    }

    /// The `resource_metadata` URL advertised in the `WWW-Authenticate`
    /// challenge: the metadata doc lives at the resource origin's well-known
    /// path (RFC 9728 §3.1).
    pub fn resource_metadata_url(&self) -> String {
        match origin_of(&self.resource_url) {
            Some(origin) => format!("{origin}/.well-known/oauth-protected-resource"),
            None => format!(
                "{}/.well-known/oauth-protected-resource",
                self.resource_url.trim_end_matches('/')
            ),
        }
    }

    /// `WWW-Authenticate` challenge value for a `401` (RFC 9728 §5.3).
    pub fn www_authenticate_value(&self) -> String {
        format!("Bearer resource_metadata=\"{}\"", self.resource_metadata_url())
    }
}

/// Extract `scheme://host[:port]` from a URL without pulling in a URL crate.
/// The resource URL is operator-configured and well-formed; this only needs to
/// strip the path.
fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let host = rest.split('/').next().filter(|h| !h.is_empty())?;
    Some(format!("{scheme}://{host}"))
}

// ---- Token introspection (RFC 7662) against the shared Authorization Server ----

/// Config for calling the AS token-introspection endpoint.
#[derive(Clone, Debug)]
pub struct IntrospectionConfig {
    pub introspect_url: String,
    pub client_id: String,
    pub client_secret: String,
}

impl IntrospectionConfig {
    /// Build from env; `None` unless both client credentials are present
    /// (introspection — and thus hosted-client OAuth auth — is opt-in).
    pub fn from_env() -> Option<Self> {
        let client_id = nonempty_env("CRUX_MCP_INTROSPECT_CLIENT_ID")?;
        let client_secret = nonempty_env("CRUX_MCP_INTROSPECT_CLIENT_SECRET")?;
        let introspect_url = derive_introspect_url(
            nonempty_env("CRUX_MCP_INTROSPECT_URL").as_deref(),
            nonempty_env("CRUX_MCP_AUTH_SERVER").as_deref(),
        );
        Some(Self {
            introspect_url,
            client_id,
            client_secret,
        })
    }
}

fn derive_introspect_url(explicit: Option<&str>, auth_server: Option<&str>) -> String {
    if let Some(url) = explicit {
        return url.to_string();
    }
    let base = auth_server.unwrap_or(DEFAULT_AUTH_SERVER);
    format!("{}/v1/auth/introspect", base.trim_end_matches('/'))
}

fn nonempty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Parsed RFC 7662 introspection response (the fields we consume).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Introspection {
    pub active: bool,
    pub scopes: Vec<String>,
    pub sub: Option<String>,
    pub client_id: Option<String>,
    pub aud: Vec<String>,
    pub exp: Option<i64>,
}

impl Introspection {
    pub fn from_json(v: &Value) -> Self {
        let active = v.get("active").and_then(Value::as_bool).unwrap_or(false);
        let scopes = v
            .get("scope")
            .and_then(Value::as_str)
            .map(|s| s.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default();
        let sub = v.get("sub").and_then(Value::as_str).map(str::to_string);
        let client_id = v.get("client_id").and_then(Value::as_str).map(str::to_string);
        let aud = parse_aud(v.get("aud"));
        let exp = v.get("exp").and_then(Value::as_i64);
        Self {
            active,
            scopes,
            sub,
            client_id,
            aud,
            exp,
        }
    }

    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// OD-24 anti-replay hook: does this token's audience admit `resource_url`?
    /// An empty `aud` admits any resource (operator-v1 single daemon, where the
    /// AS does not yet issue resource-scoped tokens); once multi-daemon tokens
    /// carry a resource `aud`, callers enforce this with
    /// `CRUX_MCP_REQUIRE_RESOURCE_AUD`.
    pub fn aud_allows(&self, resource_url: &str) -> bool {
        self.aud.is_empty() || self.aud.iter().any(|a| a == resource_url)
    }
}

/// `aud` may be a single string or an array of strings (RFC 7519/7662).
fn parse_aud(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items.iter().filter_map(|i| i.as_str().map(str::to_string)).collect(),
        _ => Vec::new(),
    }
}

/// Cache TTL for an active result: `min(exp - now, cap)`, floored at 0.
pub fn cache_ttl_secs(exp: Option<i64>, now_unix: i64) -> u64 {
    match exp {
        Some(e) => {
            let remaining = e - now_unix;
            if remaining <= 0 {
                0
            } else {
                (remaining as u64).min(MAX_INTROSPECTION_CACHE_TTL_SECS)
            }
        }
        None => MAX_INTROSPECTION_CACHE_TTL_SECS,
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Validates hosted-client bearer tokens via the AS introspection endpoint,
/// with a short result cache to bound per-request latency. Fail-closed: any
/// transport/parse error yields an inactive result (callers deny on inactive).
pub struct Introspector {
    cfg: IntrospectionConfig,
    agent: ureq::Agent,
    cache: Mutex<HashMap<String, (Introspection, Instant)>>,
}

impl Introspector {
    pub fn new(cfg: IntrospectionConfig) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(10)))
            .build()
            .into();
        Self {
            cfg,
            agent,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Introspect a token, serving a fresh cached result when available.
    pub fn introspect_cached(&self, token: &str) -> Introspection {
        if let Some(hit) = self.cache_get(token) {
            return hit;
        }
        let result = self.introspect_remote(token).unwrap_or_default();
        if result.active {
            let ttl = cache_ttl_secs(result.exp, now_unix());
            if ttl > 0 {
                self.cache_put(token, &result, Duration::from_secs(ttl));
            }
        }
        result
    }

    fn cache_get(&self, token: &str) -> Option<Introspection> {
        let guard = self.cache.lock().ok()?;
        guard.get(token).and_then(|(res, until)| {
            if Instant::now() < *until {
                Some(res.clone())
            } else {
                None
            }
        })
    }

    fn cache_put(&self, token: &str, result: &Introspection, ttl: Duration) {
        if let Ok(mut guard) = self.cache.lock() {
            guard.insert(token.to_string(), (result.clone(), Instant::now() + ttl));
        }
    }

    fn introspect_remote(&self, token: &str) -> Result<Introspection, String> {
        let mut resp = self
            .agent
            .post(&self.cfg.introspect_url)
            .header("Accept", "application/json")
            .send_json(json!({
                "token": token,
                "client_id": self.cfg.client_id,
                "client_secret": self.cfg.client_secret,
            }))
            .map_err(|e| e.to_string())?;
        let body: Value = resp.body_mut().read_json().map_err(|e| e.to_string())?;
        Ok(Introspection::from_json(&body))
    }
}

/// Process-wide introspector, built once from env on first use. `None` when
/// hosted-client OAuth is not configured for this daemon (no introspect creds).
static INTROSPECTOR: OnceLock<Option<Introspector>> = OnceLock::new();

pub fn shared_introspector() -> Option<&'static Introspector> {
    INTROSPECTOR
        .get_or_init(|| IntrospectionConfig::from_env().map(Introspector::new))
        .as_ref()
}

/// True when this daemon is configured to validate hosted-client OAuth tokens.
pub fn introspection_enabled() -> bool {
    shared_introspector().is_some()
}

/// Crux tenant that every hosted-client OAuth identity maps to (OD-21, v1 =
/// fixed single tenant). Default `work`.
pub fn oauth_tenant() -> String {
    nonempty_env("CRUX_MCP_OAUTH_TENANT").unwrap_or_else(|| "work".to_string())
}

/// Whether to enforce the resource `aud` check (OD-24). Off for operator-v1
/// (single daemon); MUST be on once the AS issues resource-scoped tokens for
/// multiple daemons.
pub fn require_resource_aud() -> bool {
    nonempty_env("CRUX_MCP_REQUIRE_RESOURCE_AUD").is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

/// Decide whether an introspected token authorises a hosted-client MCP caller,
/// and if so return the [`crate::agent::AgentIdentity`] it maps to (named after
/// the configured tenant so `scope_identity` resolves there). Returns `None`
/// (deny) unless active + holds `mcp:read` + passes the `aud` check.
pub fn authorize_oauth_with(
    intro: &Introspection,
    resource_url: &str,
    tenant: &str,
    require_aud: bool,
) -> Option<crate::agent::AgentIdentity> {
    if !intro.active || !intro.has_scope("mcp:read") {
        return None;
    }
    if require_aud && !intro.aud_allows(resource_url) {
        return None;
    }
    let sub = intro.sub.as_deref().unwrap_or("anon");
    let marker = format!("oauth-mcp:{tenant}:{sub}");
    Some(crate::agent::AgentIdentity {
        name: tenant.to_string(),
        token_hash: blake3::hash(marker.as_bytes()).into(),
    })
}

pub fn authorize_oauth(intro: &Introspection, resource_url: &str) -> Option<crate::agent::AgentIdentity> {
    authorize_oauth_with(intro, resource_url, &oauth_tenant(), require_resource_aud())
}

/// JSON-RPC methods a read-only (`mcp:read`) OAuth caller may invoke.
const OAUTH_READ_METHODS: &[&str] = &[
    "initialize",
    "tools/list",
    "ping",
    "notifications/initialized",
    "resources/list",
    "resources/read",
    "resources/templates/list",
];

/// `tools/call` tool names a read-only OAuth caller may invoke (read-biased).
const OAUTH_READ_TOOLS: &[&str] = &[
    "query",
    "query_scan",
    "query_expand",
    "query_facts",
    "get_session",
    "list_sessions",
    "get_bootstrap",
    "receipt_verify",
    "sync_status",
    "coord_status",
];

/// Read-only allowlist for hosted-client OAuth callers (default-deny). The MCP
/// port has no per-scope ACL, so read-only is enforced here at the request
/// boundary (ExecPlan .m1-spec §2).
pub fn oauth_request_allowed(method: &str, tool_name: Option<&str>) -> bool {
    if method == "tools/call" {
        tool_name.is_some_and(|name| OAUTH_READ_TOOLS.contains(&name))
    } else {
        OAUTH_READ_METHODS.contains(&method)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> ResourceConfig {
        ResourceConfig {
            resource_url: "https://crux.cuecrux.com/mcp".to_string(),
            authorization_servers: vec!["https://api.vaultcrux.com".to_string()],
        }
    }

    #[test]
    fn protected_resource_document_shape() {
        let doc = cfg().protected_resource_document();
        assert_eq!(doc["resource"], "https://crux.cuecrux.com/mcp");
        assert_eq!(doc["authorization_servers"][0], "https://api.vaultcrux.com");
        assert_eq!(doc["scopes_supported"][0], "mcp:read");
        assert_eq!(doc["bearer_methods_supported"][0], "header");
    }

    #[test]
    fn resource_metadata_url_is_origin_rooted() {
        assert_eq!(
            cfg().resource_metadata_url(),
            "https://crux.cuecrux.com/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn www_authenticate_points_at_resource_metadata() {
        assert_eq!(
            cfg().www_authenticate_value(),
            "Bearer resource_metadata=\"https://crux.cuecrux.com/.well-known/oauth-protected-resource\""
        );
    }

    #[test]
    fn origin_extraction() {
        assert_eq!(
            origin_of("https://h.example:8443/mcp/x"),
            Some("https://h.example:8443".to_string())
        );
        assert_eq!(origin_of("https://h.example"), Some("https://h.example".to_string()));
        assert_eq!(origin_of("not-a-url"), None);
    }

    #[test]
    fn introspection_parse_active() {
        let v = json!({
            "active": true,
            "scope": "openid mcp:read",
            "sub": "u1",
            "client_id": "c1",
            "aud": "https://crux.cuecrux.com/mcp",
            "exp": 9_999_999_999i64
        });
        let i = Introspection::from_json(&v);
        assert!(i.active);
        assert!(i.has_scope("mcp:read"));
        assert!(!i.has_scope("facts:write"));
        assert_eq!(i.sub.as_deref(), Some("u1"));
        assert!(i.aud_allows("https://crux.cuecrux.com/mcp"));
        assert!(!i.aud_allows("https://other.example/mcp"));
    }

    #[test]
    fn introspection_inactive_default_and_empty_aud_admits_any() {
        let i = Introspection::from_json(&json!({"active": false}));
        assert!(!i.active);
        assert!(i.scopes.is_empty());
        // empty aud admits any resource (operator-v1 single daemon)
        assert!(i.aud_allows("https://anything.example/mcp"));
    }

    #[test]
    fn introspection_aud_array() {
        let i = Introspection::from_json(&json!({"active": true, "aud": ["a", "b"]}));
        assert_eq!(i.aud, vec!["a".to_string(), "b".to_string()]);
        assert!(i.aud_allows("b"));
    }

    #[test]
    fn cache_ttl_caps_and_floors() {
        let now = 1_000_000i64;
        assert_eq!(cache_ttl_secs(Some(now + 10), now), 10);
        assert_eq!(cache_ttl_secs(Some(now + 10_000), now), 60); // capped
        assert_eq!(cache_ttl_secs(Some(now - 5), now), 0); // expired
        assert_eq!(cache_ttl_secs(None, now), 60);
    }

    #[test]
    fn derive_introspect_url_defaults() {
        assert_eq!(
            derive_introspect_url(None, None),
            "https://api.vaultcrux.com/v1/auth/introspect"
        );
        assert_eq!(
            derive_introspect_url(None, Some("https://as.example/")),
            "https://as.example/v1/auth/introspect"
        );
        assert_eq!(
            derive_introspect_url(Some("https://x/introspect"), Some("ignored")),
            "https://x/introspect"
        );
    }

    fn read_token() -> Introspection {
        Introspection {
            active: true,
            scopes: vec!["mcp:read".to_string()],
            sub: Some("u1".to_string()),
            client_id: None,
            aud: vec![],
            exp: None,
        }
    }

    #[test]
    fn authorize_oauth_gates_on_active_scope_and_aud() {
        let res = "https://crux.cuecrux.com/mcp";
        // active + mcp:read + no aud requirement -> identity named after tenant
        assert_eq!(
            authorize_oauth_with(&read_token(), res, "work", false).map(|i| i.name),
            Some("work".to_string())
        );
        // inactive -> denied
        let inactive = Introspection {
            active: false,
            ..read_token()
        };
        assert!(authorize_oauth_with(&inactive, res, "work", false).is_none());
        // missing mcp:read -> denied
        let no_scope = Introspection {
            scopes: vec!["openid".to_string()],
            ..read_token()
        };
        assert!(authorize_oauth_with(&no_scope, res, "work", false).is_none());
        // require_aud + mismatched aud -> denied
        let other_aud = Introspection {
            aud: vec!["https://other.example/mcp".to_string()],
            ..read_token()
        };
        assert!(authorize_oauth_with(&other_aud, res, "work", true).is_none());
        // require_aud + matching aud -> allowed
        let match_aud = Introspection {
            aud: vec![res.to_string()],
            ..read_token()
        };
        assert!(authorize_oauth_with(&match_aud, res, "work", true).is_some());
    }

    #[test]
    fn oauth_allowlist_is_default_deny() {
        assert!(oauth_request_allowed("initialize", None));
        assert!(oauth_request_allowed("tools/list", None));
        assert!(oauth_request_allowed("tools/call", Some("query")));
        assert!(oauth_request_allowed("tools/call", Some("query_facts")));
        // writes denied
        assert!(!oauth_request_allowed("tools/call", Some("store_fact")));
        assert!(!oauth_request_allowed("tools/call", Some("delete_fact")));
        assert!(!oauth_request_allowed("tools/call", Some("save_session")));
        // tools/call with no tool name, unknown tool, unknown method -> denied
        assert!(!oauth_request_allowed("tools/call", None));
        assert!(!oauth_request_allowed("tools/call", Some("unknown_tool")));
        assert!(!oauth_request_allowed("admin/whatever", None));
    }
}
