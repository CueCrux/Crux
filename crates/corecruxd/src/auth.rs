// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! HTTP + gRPC authentication: token + passport extraction, scope checks, and the `HttpScopeContext` accessor.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use base64::Engine as _;
use corecrux_types::{EvidenceAuthContextV1, ProblemDetails};
use tonic::metadata::MetadataMap;
use tonic::Status;

use crate::problem::ProblemResponse;

const MIN_HS256_SECRET_BYTES: usize = 32;
const ALLOW_WEAK_HS256_SECRET_ENV: &str = "CORECRUXD_ALLOW_WEAK_HS256_SECRET";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    Off,
    /// Development auth mode: scopes are provided directly via headers/metadata.
    ///
    /// Supported inputs:
    /// - HTTP: `X-Corecrux-Scopes: receipts:read,exports:read`
    /// - HTTP/gRPC: `Authorization: Bearer receipts:read exports:read`
    DevScopes,
    /// Production-ish auth mode: verify HS256 JWTs and extract scopes from claims.
    ///
    /// Required env:
    /// - `CORECRUXD_JWT_HS256_SECRET`
    ///
    /// Optional env:
    /// - `CORECRUXD_JWT_ISS` (issuer)
    /// - `CORECRUXD_JWT_AUD` (audience)
    JwtHs256,
    /// Verify JWTs using a JWKS (optionally via OIDC discovery) and extract scopes from claims.
    ///
    /// Required env (one of):
    /// - `CORECRUXD_JWT_JWKS_JSON`
    /// - `CORECRUXD_JWT_JWKS_PATH`
    /// - `CORECRUXD_JWT_JWKS_URL`
    /// - `CORECRUXD_JWT_OIDC_DISCOVERY_URL`
    ///
    /// Optional env:
    /// - `CORECRUXD_JWT_ISS` (issuer)
    /// - `CORECRUXD_JWT_AUD` (audience)
    /// - `CORECRUXD_JWT_ALGS` (comma/space-separated, default: RS256)
    /// - `CORECRUXD_JWT_JWKS_MIN_REFRESH_SECONDS` (default: 30)
    JwtJwks,
}

impl AuthMode {
    pub fn parse(s: &str) -> Option<Self> {
        // A value that is *present but blank* is not "off" — it is a
        // misconfiguration. Returning `Off` here would boot the daemon with
        // authentication disabled while the config looks set. Only a
        // genuinely empty string (an unset variable) means "unset".
        if !s.is_empty() && s.trim().is_empty() {
            return None;
        }
        match s.trim() {
            "" | "off" | "OFF" => Some(Self::Off),
            "dev" | "DEV" | "dev_scopes" | "DEV_SCOPES" | "devscopes" | "DEVSCOPES" | "dev-scopes" | "DEV-SCOPES" => {
                Some(Self::DevScopes)
            }
            "jwt" | "JWT" | "jwt_hs256" | "JWT_HS256" | "jwt-hs256" | "JWT-HS256" => Some(Self::JwtHs256),
            "jwt_jwks" | "JWT_JWKS" | "jwt-jwks" | "JWT-JWKS" | "jwks" | "JWKS" | "oidc" | "OIDC" | "jwt_oidc"
            | "JWT_OIDC" | "jwt-oidc" | "JWT-OIDC" => Some(Self::JwtJwks),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::DevScopes => "dev_scopes",
            Self::JwtHs256 => "jwt_hs256",
            Self::JwtJwks => "jwt_jwks",
        }
    }
}

#[derive(Debug, Clone)]
struct JwtHs256Config {
    secret: Vec<u8>,
    issuer: Option<String>,
    audience: Option<String>,
}

#[derive(Clone)]
struct JwtJwksConfig {
    issuer: Option<String>,
    audience: Option<String>,
    algorithms: Vec<jsonwebtoken::Algorithm>,
    jwks_url: Option<String>,
    min_refresh_interval: Duration,
    agent: ureq::Agent,
    state: Arc<Mutex<JwksState>>,
}

struct JwksState {
    keys: HashMap<String, jsonwebtoken::DecodingKey>,
    last_refresh_attempt: Option<Instant>,
    last_refresh_ok: Option<Instant>,
    last_error: Option<String>,
}

type InitialJwks = (
    Option<String>,
    Option<String>,
    HashMap<String, jsonwebtoken::DecodingKey>,
);

#[derive(Clone)]
pub struct Authz {
    mode: AuthMode,
    jwt_hs256: Option<JwtHs256Config>,
    jwt_jwks: Option<JwtJwksConfig>,
    /// Opt-in: under a JWT mode, also accept a registered MCP agent token
    /// (`CRUX_AGENT_TOKENS`) on HTTP so a single credential unlocks both the
    /// HTTP API and the MCP plane. `None` unless `CORECRUXD_HTTP_ACCEPT_AGENT_TOKENS`
    /// is enabled.
    agent_http: Option<AgentTokenHttpConfig>,
}

/// Opt-in HTTP acceptance of MCP agent tokens (see [`Authz::agent_http`]).
///
/// Agent tokens carry no claims, so every accepted agent token maps to the same
/// operator-configured scope set + tenant binding (`CORECRUXD_AGENT_TOKEN_HTTP_SCOPES`
/// / `CORECRUXD_AGENT_TOKEN_HTTP_TENANT`).
#[derive(Clone)]
struct AgentTokenHttpConfig {
    registry: crux_mcp::agent::AgentRegistry,
    scopes: BTreeSet<String>,
    tenants: TenantAllow,
}

/// Env flag enabling HTTP acceptance of MCP agent tokens. Default off.
const HTTP_ACCEPT_AGENT_TOKENS_ENV: &str = "CORECRUXD_HTTP_ACCEPT_AGENT_TOKENS";

fn env_truthy(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .is_some_and(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"))
}

/// Build the agent-token HTTP config from env, or `None` if disabled / no tokens.
fn build_agent_http_config() -> Option<AgentTokenHttpConfig> {
    if !env_truthy(HTTP_ACCEPT_AGENT_TOKENS_ENV) {
        return None;
    }
    // Fail closed: if the agent-token env is present but invalid, `from_env`
    // returns Err. Treat that as "no usable registry" here (HTTP agent-token
    // auth stays disabled = deny); startup is independently gated in `main`.
    let registry = match crux_mcp::agent::AgentRegistry::from_env() {
        Ok(registry) if !registry.is_empty() => registry,
        _ => return None,
    };
    let scopes = std::env::var("CORECRUXD_AGENT_TOKEN_HTTP_SCOPES")
        .ok()
        .map(|s| parse_scopes(&s))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_agent_http_scopes);
    let tenant_raw = std::env::var("CORECRUXD_AGENT_TOKEN_HTTP_TENANT")
        .ok()
        .unwrap_or_else(|| "*".to_string());
    let tenants = tenant_allow_from_str(&tenant_raw);
    Some(AgentTokenHttpConfig {
        registry,
        scopes,
        tenants,
    })
}

fn default_agent_http_scopes() -> BTreeSet<String> {
    [
        "admin:read",
        "admin:write",
        "facts:write",
        "query:read",
        "sessions:read",
        "sessions:write",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

fn tenant_allow_from_str(raw: &str) -> TenantAllow {
    let trimmed = raw.trim();
    if trimmed == "*" {
        return TenantAllow::Any;
    }
    let set: BTreeSet<String> = trimmed
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if set.is_empty() {
        TenantAllow::Missing
    } else {
        TenantAllow::Only(set)
    }
}

impl AgentTokenHttpConfig {
    /// If `token` is a registered agent token, return an `AuthContext` carrying
    /// the configured scopes + tenant binding, attributed to the agent name.
    fn try_auth(&self, token: &str) -> Option<AuthContext> {
        self.registry.lookup(token).map(|agent| AuthContext {
            subject: Some(format!("agent:{}", agent.name)),
            passport_id: Some(format!("agent:{}", agent.name)),
            scopes: self.scopes.clone(),
            tenants: self.tenants.clone(),
            canonical_passport_claim_verified: false,
            credential_is_agent_token: true,
        })
    }
}

impl std::fmt::Debug for Authz {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Authz")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl Authz {
    pub fn from_env(mode: AuthMode) -> Result<Self, String> {
        match mode {
            AuthMode::Off | AuthMode::DevScopes => Ok(Self {
                mode,
                jwt_hs256: None,
                jwt_jwks: None,
                agent_http: None,
            }),
            AuthMode::JwtHs256 => {
                let raw = std::env::var("CORECRUXD_JWT_HS256_SECRET")
                    .map_err(|_| "missing CORECRUXD_JWT_HS256_SECRET".to_string())?;
                let secret = parse_secret(&raw)?;
                let issuer = std::env::var("CORECRUXD_JWT_ISS").ok();
                let audience = std::env::var("CORECRUXD_JWT_AUD").ok();
                Ok(Self {
                    mode,
                    jwt_hs256: Some(JwtHs256Config {
                        secret,
                        issuer,
                        audience,
                    }),
                    jwt_jwks: None,
                    agent_http: build_agent_http_config(),
                })
            }
            AuthMode::JwtJwks => {
                let issuer = std::env::var("CORECRUXD_JWT_ISS").ok();
                let audience = std::env::var("CORECRUXD_JWT_AUD").ok();

                let algorithms = parse_jwt_algs(std::env::var("CORECRUXD_JWT_ALGS").ok().as_deref())?;

                let min_refresh_secs = std::env::var("CORECRUXD_JWT_JWKS_MIN_REFRESH_SECONDS")
                    .ok()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(30);

                let agent: ureq::Agent = ureq::Agent::config_builder()
                    .timeout_connect(Some(Duration::from_secs(2)))
                    .timeout_recv_response(Some(Duration::from_secs(5)))
                    .timeout_recv_body(Some(Duration::from_secs(5)))
                    .build()
                    .into();

                let jwks_json = std::env::var("CORECRUXD_JWT_JWKS_JSON")
                    .ok()
                    .or_else(|| std::env::var("CORECRUXD_JWKS_JSON").ok());
                let jwks_path = std::env::var("CORECRUXD_JWT_JWKS_PATH")
                    .ok()
                    .or_else(|| std::env::var("CORECRUXD_JWKS_PATH").ok());
                let jwks_url = std::env::var("CORECRUXD_JWT_JWKS_URL")
                    .ok()
                    .or_else(|| std::env::var("CORECRUXD_JWKS_URL").ok());
                let oidc_discovery_url = std::env::var("CORECRUXD_JWT_OIDC_DISCOVERY_URL")
                    .ok()
                    .or_else(|| std::env::var("CORECRUXD_OIDC_DISCOVERY_URL").ok());

                let (resolved_issuer, resolved_jwks_url, keys) =
                    resolve_initial_jwks(&agent, issuer, jwks_json, jwks_path, jwks_url, oidc_discovery_url)?;

                Ok(Self {
                    mode,
                    jwt_hs256: None,
                    jwt_jwks: Some(JwtJwksConfig {
                        issuer: resolved_issuer,
                        audience,
                        algorithms,
                        jwks_url: resolved_jwks_url,
                        min_refresh_interval: Duration::from_secs(min_refresh_secs),
                        agent,
                        state: Arc::new(Mutex::new(JwksState {
                            keys,
                            last_refresh_attempt: None,
                            last_refresh_ok: Some(Instant::now()),
                            last_error: None,
                        })),
                    }),
                    agent_http: build_agent_http_config(),
                })
            }
        }
    }

    pub fn mode(&self) -> AuthMode {
        self.mode
    }

    #[cfg(test)]
    pub(crate) fn test_hs256(secret: &[u8], issuer: &str, audience: &str) -> Self {
        Self {
            mode: AuthMode::JwtHs256,
            jwt_hs256: Some(JwtHs256Config {
                secret: secret.to_vec(),
                issuer: Some(issuer.to_string()),
                audience: Some(audience.to_string()),
            }),
            jwt_jwks: None,
            agent_http: None,
        }
    }
}

fn parse_secret(raw: &str) -> Result<Vec<u8>, String> {
    let bytes = if let Some(b64) = raw.strip_prefix("base64:") {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| format!("invalid base64 jwt secret: {e}"))?;
        if bytes.is_empty() {
            return Err("empty jwt secret".to_string());
        }
        bytes
    } else if raw.is_empty() {
        return Err("empty jwt secret".to_string());
    } else {
        raw.as_bytes().to_vec()
    };
    validate_hs256_secret(&bytes)?;
    Ok(bytes)
}

fn validate_hs256_secret(secret: &[u8]) -> Result<(), String> {
    if secret.len() >= MIN_HS256_SECRET_BYTES || weak_hs256_secret_allowed() {
        return Ok(());
    }
    Err(format!(
        "CORECRUXD_JWT_HS256_SECRET must decode to at least {MIN_HS256_SECRET_BYTES} bytes; set {ALLOW_WEAK_HS256_SECRET_ENV}=1 only for local dev/tests"
    ))
}

fn weak_hs256_secret_allowed() -> bool {
    std::env::var(ALLOW_WEAK_HS256_SECRET_ENV)
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

fn parse_scopes(raw: &str) -> BTreeSet<String> {
    raw.split(|c: char| c == ',' || c.is_ascii_whitespace())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .collect()
}

fn extract_bearer_token_http(headers: &HeaderMap) -> Option<String> {
    let auth = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let token = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer "))?;
    Some(token.trim().to_string())
}

fn extract_bearer_token_grpc(meta: &MetadataMap) -> Option<String> {
    let auth = meta.get("authorization").and_then(|v| v.to_str().ok())?;
    let token = auth.strip_prefix("Bearer ").or_else(|| auth.strip_prefix("bearer "))?;
    Some(token.trim().to_string())
}

fn extract_scopes_http_dev(headers: &HeaderMap) -> Option<BTreeSet<String>> {
    if let Some(v) = headers.get("x-corecrux-scopes").and_then(|v| v.to_str().ok()) {
        return Some(parse_scopes(v));
    }
    extract_bearer_token_http(headers).map(|t| parse_scopes(&t))
}

fn extract_scopes_grpc_dev(meta: &MetadataMap) -> Option<BTreeSet<String>> {
    if let Some(v) = meta.get("x-corecrux-scopes").and_then(|v| v.to_str().ok()) {
        return Some(parse_scopes(v));
    }
    extract_bearer_token_grpc(meta).map(|t| parse_scopes(&t))
}

#[derive(Debug, Clone)]
struct AuthContext {
    subject: Option<String>,
    passport_id: Option<String>,
    scopes: BTreeSet<String>,
    tenants: TenantAllow,
    /// True only when a cryptographically verified JWT carried a canonical,
    /// non-empty `passport_id` claim. Legacy aliases and `sub` remain valid
    /// identity fallbacks for ordinary routes, but cannot authorize sensitive
    /// human-approval boundaries.
    canonical_passport_claim_verified: bool,
    /// MCP agent tokens authenticate automation, not a human reviewer. High-
    /// risk four-eyes boundaries use this provenance to deny machine approval.
    credential_is_agent_token: bool,
}

#[derive(Debug, Clone)]
enum TenantAllow {
    Any,
    Only(BTreeSet<String>),
    Missing,
}

fn scopes_from_claims(claims: &serde_json::Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some(scope) = claims.get("scope").and_then(|v| v.as_str()) {
        out.extend(parse_scopes(scope));
    }
    if let Some(scp) = claims.get("scp").and_then(|v| v.as_str()) {
        out.extend(parse_scopes(scp));
    }
    for key in ["scopes", "scp", "permissions"] {
        if let Some(arr) = claims.get(key).and_then(|v| v.as_array()) {
            for el in arr {
                if let Some(s) = el.as_str() {
                    out.extend(parse_scopes(s));
                }
            }
        }
    }
    out
}

fn tenants_from_claims(claims: &serde_json::Value) -> TenantAllow {
    for key in ["tenant_id", "tenantId", "tid"] {
        if let Some(s) = claims.get(key).and_then(|v| v.as_str()) {
            let trimmed = s.trim();
            if trimmed == "*" {
                return TenantAllow::Any;
            }
            if !trimmed.is_empty() {
                let mut set = BTreeSet::new();
                set.insert(trimmed.to_string());
                return TenantAllow::Only(set);
            }
        }
    }

    if let Some(arr) = claims.get("tenants").and_then(|v| v.as_array()) {
        let mut set = BTreeSet::new();
        for el in arr {
            if let Some(s) = el.as_str() {
                let trimmed = s.trim();
                if trimmed == "*" {
                    return TenantAllow::Any;
                }
                if !trimmed.is_empty() {
                    set.insert(trimmed.to_string());
                }
            }
        }
        if !set.is_empty() {
            return TenantAllow::Only(set);
        }
    }

    TenantAllow::Missing
}

fn subject_from_claims(claims: &serde_json::Value) -> Option<String> {
    for key in ["sub", "subject"] {
        if let Some(subject) = claims.get(key).and_then(|v| v.as_str()) {
            let trimmed = subject.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn canonical_passport_from_claims(claims: &serde_json::Value) -> Option<String> {
    claims
        .get("passport_id")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|passport| !passport.is_empty())
        .map(str::to_string)
}

fn passport_from_claims(claims: &serde_json::Value) -> Option<String> {
    if let Some(passport) = canonical_passport_from_claims(claims) {
        return Some(passport);
    }
    for key in ["passportId", "passport", "passport_fpr", "passportFpr", "pid"] {
        if let Some(passport) = claims.get(key).and_then(|v| v.as_str()) {
            let trimmed = passport.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    subject_from_claims(claims)
}

fn verify_jwt_hs256(cfg: &JwtHs256Config, token: &str) -> Result<AuthContext, String> {
    use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 30;
    if let Some(iss) = cfg.issuer.as_deref() {
        validation.set_issuer(&[iss]);
        // jsonwebtoken only compares a pinned claim WHEN PRESENT; an absent
        // claim otherwise falls through to `Ok`. Require it so that "not
        // checked" cannot read the same as "checked and matched".
        validation.required_spec_claims.insert("iss".to_string());
    }
    if let Some(aud) = cfg.audience.as_deref() {
        validation.set_audience(&[aud]);
        validation.required_spec_claims.insert("aud".to_string());
    }

    let data = decode::<serde_json::Value>(token, &DecodingKey::from_secret(cfg.secret.as_slice()), &validation)
        .map_err(|e| format!("jwt decode failed: {e}"))?;

    let scopes = scopes_from_claims(&data.claims);
    let tenants = tenants_from_claims(&data.claims);
    let subject = subject_from_claims(&data.claims);
    let canonical_passport_claim_verified = canonical_passport_from_claims(&data.claims).is_some();
    let passport_id = passport_from_claims(&data.claims);
    Ok(AuthContext {
        subject,
        passport_id,
        scopes,
        tenants,
        canonical_passport_claim_verified,
        credential_is_agent_token: false,
    })
}

#[derive(Debug, serde::Deserialize)]
struct OidcDiscovery {
    issuer: Option<String>,
    jwks_uri: String,
}

#[derive(Debug, serde::Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, serde::Deserialize)]
struct Jwk {
    kty: String,
    kid: Option<String>,
    #[serde(rename = "use")]
    use_: Option<String>,
    n: Option<String>,
    e: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

fn parse_jwt_algs(raw: Option<&str>) -> Result<Vec<jsonwebtoken::Algorithm>, String> {
    use jsonwebtoken::Algorithm;

    let raw = raw.unwrap_or("RS256");
    let mut out = Vec::new();
    for part in raw.split(|c: char| c == ',' || c.is_ascii_whitespace()) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        let alg = match p {
            "RS256" => Algorithm::RS256,
            "RS384" => Algorithm::RS384,
            "RS512" => Algorithm::RS512,
            "ES256" => Algorithm::ES256,
            "ES384" => Algorithm::ES384,
            "PS256" => Algorithm::PS256,
            "PS384" => Algorithm::PS384,
            "PS512" => Algorithm::PS512,
            other => return Err(format!("unsupported jwt alg {other}")),
        };
        if !out.contains(&alg) {
            out.push(alg);
        }
    }
    if out.is_empty() {
        return Err("no jwt algs configured".to_string());
    }
    Ok(out)
}

fn resolve_initial_jwks(
    agent: &ureq::Agent,
    issuer_env: Option<String>,
    jwks_json: Option<String>,
    jwks_path: Option<String>,
    jwks_url: Option<String>,
    oidc_discovery_url: Option<String>,
) -> Result<InitialJwks, String> {
    if let Some(json) = jwks_json {
        let jwks: Jwks = serde_json::from_str(&json).map_err(|e| format!("invalid CORECRUXD_JWT_JWKS_JSON: {e}"))?;
        let keys = parse_jwks_keys(&jwks)?;
        return Ok((issuer_env, None, keys));
    }

    if let Some(path) = jwks_path {
        let bytes = std::fs::read(&path).map_err(|e| format!("read jwks path failed: {e}"))?;
        let s = String::from_utf8_lossy(&bytes).to_string();
        let jwks: Jwks = serde_json::from_str(&s).map_err(|e| format!("invalid jwks json: {e}"))?;
        let keys = parse_jwks_keys(&jwks)?;
        return Ok((issuer_env, None, keys));
    }

    if let Some(discovery_url) = oidc_discovery_url {
        let discovery: OidcDiscovery = fetch_json(agent, &discovery_url)
            .and_then(|v| serde_json::from_value(v).map_err(|e| e.to_string()))
            .map_err(|e| format!("oidc discovery failed: {e}"))?;
        let jwks_url = discovery.jwks_uri;
        let issuer = issuer_env.or(discovery.issuer);
        let jwks: Jwks = fetch_json(agent, &jwks_url)
            .and_then(|v| serde_json::from_value(v).map_err(|e| e.to_string()))
            .map_err(|e| format!("jwks fetch failed: {e}"))?;
        let keys = parse_jwks_keys(&jwks)?;
        return Ok((issuer, Some(jwks_url), keys));
    }

    let Some(jwks_url) = jwks_url else {
        return Err(
            "missing JWKS source: set CORECRUXD_JWT_JWKS_JSON|PATH|URL or CORECRUXD_JWT_OIDC_DISCOVERY_URL".to_string(),
        );
    };

    let jwks: Jwks = fetch_json(agent, &jwks_url)
        .and_then(|v| serde_json::from_value(v).map_err(|e| e.to_string()))
        .map_err(|e| format!("jwks fetch failed: {e}"))?;
    let keys = parse_jwks_keys(&jwks)?;
    Ok((issuer_env, Some(jwks_url), keys))
}

fn fetch_json(agent: &ureq::Agent, url: &str) -> Result<serde_json::Value, String> {
    let mut resp = agent
        .get(url)
        .header("accept", "application/json")
        .call()
        .map_err(|e| format!("{e}"))?;
    resp.body_mut()
        .read_json::<serde_json::Value>()
        .map_err(|e| format!("{e}"))
}

fn parse_jwks_keys(jwks: &Jwks) -> Result<HashMap<String, jsonwebtoken::DecodingKey>, String> {
    use jsonwebtoken::DecodingKey;

    let mut out = HashMap::new();
    for k in &jwks.keys {
        if let Some(use_) = k.use_.as_deref() {
            if use_ != "sig" {
                continue;
            }
        }
        let Some(kid) = k.kid.as_deref() else {
            continue;
        };

        match k.kty.as_str() {
            "RSA" => {
                let (Some(n), Some(e)) = (k.n.as_deref(), k.e.as_deref()) else {
                    continue;
                };
                let dk = DecodingKey::from_rsa_components(n, e).map_err(|e| format!("bad rsa jwk: {e}"))?;
                out.insert(kid.to_string(), dk);
            }
            "EC" => {
                let (Some(x), Some(y)) = (k.x.as_deref(), k.y.as_deref()) else {
                    continue;
                };
                let dk = DecodingKey::from_ec_components(x, y).map_err(|e| format!("bad ec jwk: {e}"))?;
                out.insert(kid.to_string(), dk);
            }
            _ => {}
        }
    }

    if out.is_empty() {
        return Err("jwks contains no usable sig keys".to_string());
    }
    Ok(out)
}

fn verify_jwt_jwks(cfg: &JwtJwksConfig, token: &str) -> Result<AuthContext, String> {
    use jsonwebtoken::{decode, decode_header, Validation};

    let header = decode_header(token).map_err(|e| format!("jwt header decode failed: {e}"))?;
    if !cfg.algorithms.contains(&header.alg) {
        return Err(format!("jwt alg {:?} not allowed", header.alg));
    }
    let kid = header.kid.as_deref();

    let mut validation = Validation::new(cfg.algorithms[0]);
    validation.algorithms.clone_from(&cfg.algorithms);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 30;
    if let Some(iss) = cfg.issuer.as_deref() {
        validation.set_issuer(&[iss]);
        // See `verify_jwt_hs256`: pinning without requiring the claim lets a
        // token that simply omits it bypass the pin.
        validation.required_spec_claims.insert("iss".to_string());
    }
    if let Some(aud) = cfg.audience.as_deref() {
        validation.set_audience(&[aud]);
        validation.required_spec_claims.insert("aud".to_string());
    }

    let key = resolve_jwks_key(cfg, kid)?;
    let data = decode::<serde_json::Value>(token, &key, &validation).map_err(|e| format!("jwt decode failed: {e}"))?;

    let scopes = scopes_from_claims(&data.claims);
    let tenants = tenants_from_claims(&data.claims);
    let subject = subject_from_claims(&data.claims);
    let canonical_passport_claim_verified = canonical_passport_from_claims(&data.claims).is_some();
    let passport_id = passport_from_claims(&data.claims);
    Ok(AuthContext {
        subject,
        passport_id,
        scopes,
        tenants,
        canonical_passport_claim_verified,
        credential_is_agent_token: false,
    })
}

fn resolve_jwks_key(cfg: &JwtJwksConfig, kid: Option<&str>) -> Result<jsonwebtoken::DecodingKey, String> {
    // 1) Fast path: check cache.
    {
        let state = cfg.state.lock().map_err(|_| "jwks lock poisoned".to_string())?;
        if let Some(kid) = kid {
            if let Some(k) = state.keys.get(kid) {
                return Ok(k.clone());
            }
        } else if let Some(only_key) = state.keys.values().next().filter(|_| state.keys.len() == 1) {
            return Ok(only_key.clone());
        }
    }

    // 2) Missing kid/key: optional refresh-on-miss (rate-limited).
    let Some(jwks_url) = cfg.jwks_url.as_deref() else {
        return Err(match kid {
            Some(k) => format!("jwt kid {k} not found (static jwks)"),
            None => "jwt missing kid and jwks has multiple keys".to_string(),
        });
    };

    let now = Instant::now();
    {
        let mut state = cfg.state.lock().map_err(|_| "jwks lock poisoned".to_string())?;
        if let Some(prev) = state.last_refresh_attempt {
            if now.duration_since(prev) < cfg.min_refresh_interval {
                let last_ok_age = state.last_refresh_ok.map(|t| now.duration_since(t).as_secs());
                let last_err = state.last_error.clone();
                return Err(match kid {
                    Some(k) => format!("jwt kid {k} not found (jwks refresh rate-limited)"),
                    None => "jwt missing kid and jwks has multiple keys".to_string(),
                } + &format!(" (last_ok_age_s={:?} last_error={:?})", last_ok_age, last_err));
            }
        }
        state.last_refresh_attempt = Some(now);
    }

    match fetch_json(&cfg.agent, jwks_url)
        .and_then(|v| serde_json::from_value::<Jwks>(v).map_err(|e| e.to_string()))
        .and_then(|jwks| parse_jwks_keys(&jwks))
    {
        Ok(new_keys) => {
            let mut state = cfg.state.lock().map_err(|_| "jwks lock poisoned".to_string())?;
            state.keys = new_keys;
            state.last_refresh_ok = Some(now);
            state.last_error = None;
        }
        Err(err) => {
            let mut state = cfg.state.lock().map_err(|_| "jwks lock poisoned".to_string())?;
            state.last_error = Some(err.clone());
            return Err(format!("jwks refresh failed: {err}"));
        }
    }

    let state = cfg.state.lock().map_err(|_| "jwks lock poisoned".to_string())?;
    if let Some(kid) = kid {
        if let Some(k) = state.keys.get(kid) {
            return Ok(k.clone());
        }
        return Err(format!("jwt kid {kid} not found after jwks refresh"));
    }
    if let Some(only_key) = state.keys.values().next().filter(|_| state.keys.len() == 1) {
        return Ok(only_key.clone());
    }
    Err("jwt missing kid and jwks has multiple keys".to_string())
}

fn missing_scopes<'a>(scopes: &BTreeSet<String>, required: &'a [&'a str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    for r in required {
        if !scopes.iter().any(|s| s == r) {
            out.push(*r);
        }
    }
    out
}

fn tenant_binding_string(tenant_allow: &TenantAllow) -> Option<String> {
    match tenant_allow {
        TenantAllow::Any => Some("*".to_string()),
        TenantAllow::Only(set) if !set.is_empty() => Some(set.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")),
        TenantAllow::Only(_) | TenantAllow::Missing => None,
    }
}

#[allow(clippy::result_large_err)]
fn require_tenant_allowed(tenant_allow: &TenantAllow, tenant_id: &str) -> Result<(), ProblemResponse> {
    match tenant_allow {
        TenantAllow::Any => Ok(()),
        TenantAllow::Only(set) => {
            if set.contains(tenant_id) {
                Ok(())
            } else {
                Err(ProblemResponse(
                    ProblemDetails::forbidden("tenant not allowed").with_extensions(serde_json::json!({
                        "code": "TENANT_FORBIDDEN",
                        "tenantId": tenant_id,
                    })),
                ))
            }
        }
        TenantAllow::Missing => Err(ProblemResponse(
            ProblemDetails::forbidden("token missing tenant_id/tenants claim").with_extensions(serde_json::json!({
                "code": "TENANT_CLAIM_MISSING",
            })),
        )),
    }
}

#[allow(clippy::result_large_err)]
fn http_ctx(auth: &Authz, headers: &HeaderMap) -> Result<AuthContext, ProblemResponse> {
    match auth.mode {
        AuthMode::Off => Ok(AuthContext {
            subject: None,
            passport_id: None,
            scopes: BTreeSet::new(),
            tenants: TenantAllow::Any,
            canonical_passport_claim_verified: false,
            credential_is_agent_token: false,
        }),
        AuthMode::DevScopes => {
            let scopes = extract_scopes_http_dev(headers).ok_or_else(|| {
                ProblemResponse(ProblemDetails::unauthorized("missing auth scopes").with_extensions(
                    serde_json::json!({
                        "code": "UNAUTHENTICATED",
                        "hint": "set X-Corecrux-Scopes or Authorization: Bearer <scopes>"
                    }),
                ))
            })?;
            Ok(AuthContext {
                subject: None,
                passport_id: None,
                scopes,
                tenants: TenantAllow::Any,
                canonical_passport_claim_verified: false,
                credential_is_agent_token: false,
            })
        }
        AuthMode::JwtHs256 => {
            let cfg = auth.jwt_hs256.as_ref().ok_or_else(|| {
                ProblemResponse(
                    ProblemDetails::internal("auth misconfigured")
                        .with_extensions(serde_json::json!({ "code": "AUTH_MISCONFIGURED" })),
                )
            })?;
            let token = extract_bearer_token_http(headers).ok_or_else(|| {
                ProblemResponse(ProblemDetails::unauthorized("missing bearer token").with_extensions(
                    serde_json::json!({
                        "code": "UNAUTHENTICATED",
                        "hint": "set Authorization: Bearer <jwt>"
                    }),
                ))
            })?;
            match verify_jwt_hs256(cfg, &token) {
                Ok(ctx) => Ok(ctx),
                Err(msg) => auth
                    .agent_http
                    .as_ref()
                    .and_then(|a| a.try_auth(&token))
                    .ok_or_else(|| {
                        ProblemResponse(ProblemDetails::unauthorized("invalid bearer token").with_extensions(
                            serde_json::json!({
                                "code": "UNAUTHENTICATED",
                                "details": msg,
                            }),
                        ))
                    }),
            }
        }
        AuthMode::JwtJwks => {
            let cfg = auth.jwt_jwks.as_ref().ok_or_else(|| {
                ProblemResponse(
                    ProblemDetails::internal("auth misconfigured")
                        .with_extensions(serde_json::json!({ "code": "AUTH_MISCONFIGURED" })),
                )
            })?;
            let token = extract_bearer_token_http(headers).ok_or_else(|| {
                ProblemResponse(ProblemDetails::unauthorized("missing bearer token").with_extensions(
                    serde_json::json!({
                        "code": "UNAUTHENTICATED",
                        "hint": "set Authorization: Bearer <jwt>"
                    }),
                ))
            })?;
            match verify_jwt_jwks(cfg, &token) {
                Ok(ctx) => Ok(ctx),
                Err(msg) => auth
                    .agent_http
                    .as_ref()
                    .and_then(|a| a.try_auth(&token))
                    .ok_or_else(|| {
                        ProblemResponse(ProblemDetails::unauthorized("invalid bearer token").with_extensions(
                            serde_json::json!({
                                "code": "UNAUTHENTICATED",
                                "details": msg,
                            }),
                        ))
                    }),
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct HttpScopeContext {
    pub scopes: Vec<String>,
    pub passport_id: Option<String>,
    auth_enforced: bool,
    passport_override_used: bool,
    canonical_passport_claim_verified: bool,
    credential_is_agent_token: bool,
    scope_bypass: bool,
    /// Tenant authority derived from the bearer token's `tenant_id`/`tenants`
    /// claim (same source the query path authorizes against). Drives the
    /// write-stamp / read-filter resolvers below (audit-v2 closeout M1 / OD-37).
    tenants: TenantAllow,
    /// Optional per-request tenant selector (`x-corecrux-tenant-id`), authorized
    /// against `tenants` when the token owns more than one tenant.
    write_tenant_selector: Option<String>,
}

/// Enforcement posture for write-context tenant stamping (OD-37 / audit-v2 M1),
/// parsed from `CORECRUXD_TENANT_WRITE_STAMP`. Mirrors the `RouteAuthMode` /
/// `RedactMode` off|shadow|on ladder already used elsewhere in the daemon.
///
/// Default **Off** (unlike `RouteAuthMode`, whose default is Shadow) because the
/// shipped v0.5.43 contract is "stamping is dark until deliberately enabled".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TenantStampMode {
    /// Every write stamps `default`, every read resolves `default` — byte-identical
    /// to pre-M1 behaviour. DEFAULT.
    Off,
    /// Resolve the tenant and **log what would happen**, but still stamp `default`
    /// and still read `default`. Observation only — zero behaviour change. Use this
    /// to prove a window is clean before flipping to `On`.
    Shadow,
    /// Stamp/read the real tenant derived from the bearer token's tenant claim.
    On,
}

impl TenantStampMode {
    pub(crate) fn from_env() -> Self {
        match std::env::var("CORECRUXD_TENANT_WRITE_STAMP")
            .ok()
            .map(|v| v.trim().to_ascii_lowercase())
            .as_deref()
        {
            Some("1") | Some("true") | Some("on") | Some("enforce") => Self::On,
            Some("shadow") | Some("audit") => Self::Shadow,
            // Anything else (unset, "0", "off", junk) → Off. Fail-safe towards the
            // shipped behaviour, never towards silently stamping real tenants.
            _ => Self::Off,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
            Self::On => "on",
        }
    }
}

/// The `On`-mode resolution, independent of posture. Shadow runs this purely to
/// report what it *would* do; `On` runs it for real.
#[allow(clippy::result_large_err)]
fn resolve_write_tenant_on(tenants: &TenantAllow, selector: Option<&str>) -> Result<Option<String>, ProblemResponse> {
    let selector = selector.map(str::trim).filter(|s| !s.is_empty());
    match tenants {
        // No tenant claim → single-tenant deployment → default (backward-compat hinge).
        TenantAllow::Missing => Ok(None),
        // Wildcard/admin token: a selector picks the target tenant; absent → default
        // (legacy admin writes keep landing `default`).
        TenantAllow::Any => Ok(selector.map(str::to_string)),
        TenantAllow::Only(set) => match selector {
            Some(sel) => {
                if set.contains(sel) {
                    Ok(Some(sel.to_string()))
                } else {
                    Err(ProblemResponse(
                        ProblemDetails::forbidden("write tenant not allowed by token")
                            .with_extensions(serde_json::json!({ "code": "TENANT_FORBIDDEN", "tenantId": sel })),
                    ))
                }
            }
            None => {
                // Unambiguous single-tenant token → that tenant; multi-tenant token
                // needs an explicit selector so we never guess which tenant to stamp.
                if set.len() == 1 {
                    Ok(set.iter().next().cloned())
                } else {
                    Err(ProblemResponse(
                        ProblemDetails::forbidden("multi-tenant token must supply x-corecrux-tenant-id on write")
                            .with_extensions(serde_json::json!({ "code": "TENANT_SELECTOR_REQUIRED" })),
                    ))
                }
            }
        },
    }
}

/// Resolve the tenant a writer stamps, honouring the posture.
///
/// `Shadow` is the load-bearing case: it runs the full `On` resolution, emits a
/// `tenant_stamp_shadow_*` warning for the two outcomes that would actually change
/// behaviour, and then returns `Ok(None)` so the write still stamps `default`.
/// It is deliberately SILENT when `On` would also have produced `default` — so a
/// window with zero `tenant_stamp_shadow_*` lines proves the flip is a no-op.
#[allow(clippy::result_large_err)]
fn resolve_write_tenant_flagged(
    tenants: &TenantAllow,
    selector: Option<&str>,
    mode: TenantStampMode,
) -> Result<Option<String>, ProblemResponse> {
    match mode {
        TenantStampMode::Off => Ok(None),
        TenantStampMode::On => resolve_write_tenant_on(tenants, selector),
        TenantStampMode::Shadow => {
            match resolve_write_tenant_on(tenants, selector) {
                // Would orphan: this write would land under a non-default tenant,
                // and reads would move with it.
                Ok(Some(would_stamp)) => tracing::warn!(
                    would_stamp = %would_stamp,
                    "tenant_stamp_shadow_would_stamp: enabling CORECRUXD_TENANT_WRITE_STAMP=1 would stamp a NON-default tenant here"
                ),
                // Would break: this caller would start getting a 4xx.
                Err(problem) => tracing::warn!(
                    status = problem.0.status,
                    detail = %problem.0.detail.as_deref().unwrap_or(""),
                    "tenant_stamp_shadow_would_reject: enabling CORECRUXD_TENANT_WRITE_STAMP=1 would REJECT this write"
                ),
                // Would be `default` anyway — the quiet, safe case. No signal.
                Ok(None) => {}
            }
            Ok(None)
        }
    }
}

/// Resolve the tenant a reader is scoped to. `None` = default. Kept in lockstep
/// with the write resolver so a writer and reader on the same single-tenant token
/// agree. Multi-tenant / wildcard tokens read `default` here (their concrete-tenant
/// reads go through the query path's `tenant_id` body selector or the admin bypass).
///
/// `Shadow` reads `default` — shadow must not move reads, or it would not be
/// observation-only.
fn resolve_read_tenant_flagged(tenants: &TenantAllow, mode: TenantStampMode) -> Option<String> {
    if mode != TenantStampMode::On {
        return None;
    }
    match tenants {
        TenantAllow::Only(set) if set.len() == 1 => set.iter().next().cloned(),
        _ => None,
    }
}

impl HttpScopeContext {
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scope_bypass || self.scopes.iter().any(|s| s == scope)
    }

    /// Whether JWT authentication accepted a passport header that differs
    /// from the verified token identity. Most admin surfaces support this
    /// explicit override; sensitive human-approval boundaries can deny it.
    pub(crate) fn passport_override_used(&self) -> bool {
        self.passport_override_used
    }

    /// Whether the daemon enforces its configured request-auth contract rather
    /// than taking the auth-off bypass. Auth-off identities are unverified.
    pub(crate) fn auth_enforced(&self) -> bool {
        self.auth_enforced
    }

    /// Whether the verified JWT carried a canonical, non-empty `passport_id`
    /// claim. This is stricter than the ordinary identity fallback to `sub`.
    pub(crate) fn canonical_passport_claim_verified(&self) -> bool {
        self.canonical_passport_claim_verified
    }

    /// Whether HTTP authentication fell back to a registered MCP agent token.
    /// These credentials may call automation APIs but cannot satisfy a human
    /// four-eyes decision.
    pub(crate) fn credential_is_agent_token(&self) -> bool {
        self.credential_is_agent_token
    }

    /// Tenant to stamp on an HTTP write (OD-37). `Ok(None)` → default tenant.
    #[allow(clippy::result_large_err)]
    pub(crate) fn resolve_write_tenant(&self) -> Result<Option<String>, ProblemResponse> {
        resolve_write_tenant_flagged(
            &self.tenants,
            self.write_tenant_selector.as_deref(),
            TenantStampMode::from_env(),
        )
    }

    /// Tenant an HTTP read is scoped to. `None` → default tenant.
    pub(crate) fn resolve_read_tenant(&self) -> Option<String> {
        resolve_read_tenant_flagged(&self.tenants, TenantStampMode::from_env())
    }
}

pub fn http_passport_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-corecrux-passport-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Per-request write tenant selector (`x-corecrux-tenant-id`), authorized against
/// the token's tenant claim by the write resolver.
pub fn http_tenant_selector(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-corecrux-tenant-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[allow(clippy::result_large_err)]
pub fn passport_bound_context(auth: &Authz, headers: &HeaderMap) -> Result<HttpScopeContext, ProblemResponse> {
    let ctx = http_ctx(auth, headers)?;
    let verified_passport_id = ctx.passport_id.clone();
    let passport_id = bind_http_passport(auth.mode, &ctx, http_passport_id(headers))?;
    let passport_override_used =
        matches!(auth.mode, AuthMode::JwtHs256 | AuthMode::JwtJwks) && passport_id != verified_passport_id;
    let tenants = ctx.tenants.clone();
    Ok(HttpScopeContext {
        scopes: ctx.scopes.into_iter().collect(),
        passport_id,
        auth_enforced: auth.mode != AuthMode::Off,
        passport_override_used,
        canonical_passport_claim_verified: ctx.canonical_passport_claim_verified,
        credential_is_agent_token: ctx.credential_is_agent_token,
        scope_bypass: auth.mode == AuthMode::Off,
        tenants,
        write_tenant_selector: http_tenant_selector(headers),
    })
}

#[allow(clippy::result_large_err)]
pub fn http_scope_context(auth: &Authz, headers: &HeaderMap) -> Result<HttpScopeContext, ProblemResponse> {
    passport_bound_context(auth, headers)
}

#[allow(clippy::result_large_err)]
fn bind_http_passport(
    mode: AuthMode,
    ctx: &AuthContext,
    header_passport: Option<String>,
) -> Result<Option<String>, ProblemResponse> {
    if matches!(mode, AuthMode::Off | AuthMode::DevScopes) {
        return Ok(header_passport);
    }

    match (ctx.passport_id.as_deref(), header_passport.as_deref()) {
        (claim, None) => Ok(claim.map(str::to_string)),
        (Some(claim), Some(header)) if claim == header => Ok(Some(claim.to_string())),
        (_, Some(header)) if can_override_passport_header(&ctx.scopes) => Ok(Some(header.to_string())),
        (None, Some(_)) => Err(ProblemResponse(
            ProblemDetails::forbidden("passport header is not bound to the bearer token").with_extensions(
                serde_json::json!({
                    "code": "PASSPORT_HEADER_UNBOUND",
                }),
            ),
        )),
        (Some(_), Some(_)) => Err(ProblemResponse(
            ProblemDetails::forbidden("passport header does not match bearer token").with_extensions(
                serde_json::json!({
                    "code": "PASSPORT_HEADER_MISMATCH",
                }),
            ),
        )),
    }
}

fn can_override_passport_header(scopes: &BTreeSet<String>) -> bool {
    scopes.iter().any(|s| s == "passport:impersonate" || s == "admin:write")
}

#[allow(clippy::result_large_err)]
fn grpc_ctx(auth: &Authz, meta: &MetadataMap) -> Result<AuthContext, Status> {
    match auth.mode {
        AuthMode::Off => Ok(AuthContext {
            subject: None,
            passport_id: None,
            scopes: BTreeSet::new(),
            tenants: TenantAllow::Any,
            canonical_passport_claim_verified: false,
            credential_is_agent_token: false,
        }),
        AuthMode::DevScopes => {
            let scopes = extract_scopes_grpc_dev(meta).ok_or_else(|| {
                Status::unauthenticated(
                    serde_json::json!({
                        "code": "UNAUTHENTICATED",
                        "message": "missing auth scopes",
                        "hint": "set x-corecrux-scopes or authorization: Bearer <scopes>"
                    })
                    .to_string(),
                )
            })?;
            Ok(AuthContext {
                subject: None,
                passport_id: None,
                scopes,
                tenants: TenantAllow::Any,
                canonical_passport_claim_verified: false,
                credential_is_agent_token: false,
            })
        }
        AuthMode::JwtHs256 => {
            let cfg = auth
                .jwt_hs256
                .as_ref()
                .ok_or_else(|| Status::internal("{\"code\":\"AUTH_MISCONFIGURED\"}".to_string()))?;
            let token = extract_bearer_token_grpc(meta).ok_or_else(|| {
                Status::unauthenticated(
                    serde_json::json!({
                        "code": "UNAUTHENTICATED",
                        "message": "missing bearer token",
                        "hint": "set authorization: Bearer <jwt>"
                    })
                    .to_string(),
                )
            })?;
            let ctx = verify_jwt_hs256(cfg, &token).map_err(|msg| {
                Status::unauthenticated(
                    serde_json::json!({
                        "code": "UNAUTHENTICATED",
                        "message": "invalid bearer token",
                        "details": msg,
                    })
                    .to_string(),
                )
            })?;
            Ok(ctx)
        }
        AuthMode::JwtJwks => {
            let cfg = auth
                .jwt_jwks
                .as_ref()
                .ok_or_else(|| Status::internal("{\"code\":\"AUTH_MISCONFIGURED\"}".to_string()))?;
            let token = extract_bearer_token_grpc(meta).ok_or_else(|| {
                Status::unauthenticated(
                    serde_json::json!({
                        "code": "UNAUTHENTICATED",
                        "message": "missing bearer token",
                        "hint": "set authorization: Bearer <jwt>"
                    })
                    .to_string(),
                )
            })?;
            let ctx = verify_jwt_jwks(cfg, &token).map_err(|msg| {
                Status::unauthenticated(
                    serde_json::json!({
                        "code": "UNAUTHENTICATED",
                        "message": "invalid bearer token",
                        "details": msg,
                    })
                    .to_string(),
                )
            })?;
            Ok(ctx)
        }
    }
}

#[allow(clippy::result_large_err)]
pub fn describe_http_evidence(auth: &Authz, headers: &HeaderMap) -> Result<EvidenceAuthContextV1, ProblemResponse> {
    let ctx = http_ctx(auth, headers)?;
    Ok(EvidenceAuthContextV1 {
        mode: auth.mode.as_str().to_string(),
        subject: ctx.subject,
        tenant_binding: tenant_binding_string(&ctx.tenants),
        scopes: ctx.scopes.into_iter().collect(),
    })
}

#[allow(clippy::result_large_err)]
pub fn require_http_scopes(auth: &Authz, headers: &HeaderMap, required: &[&str]) -> Result<(), ProblemResponse> {
    if auth.mode == AuthMode::Off {
        return Ok(());
    }

    let ctx = http_ctx(auth, headers)?;
    let missing = missing_scopes(&ctx.scopes, required);
    if missing.is_empty() {
        return Ok(());
    }

    Err(ProblemResponse(
        ProblemDetails::forbidden("insufficient scopes").with_extensions(serde_json::json!({
            "code": "MISSING_SCOPE",
            "missingScopes": missing
        })),
    ))
}

#[allow(clippy::result_large_err)]
pub fn require_http_any_scope(auth: &Authz, headers: &HeaderMap, any_of: &[&str]) -> Result<(), ProblemResponse> {
    if auth.mode == AuthMode::Off {
        return Ok(());
    }

    let ctx = http_ctx(auth, headers)?;
    if any_of.iter().any(|scope| ctx.scopes.iter().any(|s| s == scope)) {
        return Ok(());
    }

    Err(ProblemResponse(
        ProblemDetails::forbidden("insufficient scopes").with_extensions(serde_json::json!({
            "code": "MISSING_SCOPE",
            "missingAnyScope": any_of
        })),
    ))
}

#[allow(clippy::result_large_err)]
pub fn require_http_any_scope_for_tenant(
    auth: &Authz,
    headers: &HeaderMap,
    any_of: &[&str],
    tenant_id: &str,
) -> Result<(), ProblemResponse> {
    if auth.mode == AuthMode::Off {
        return Ok(());
    }

    let ctx = http_ctx(auth, headers)?;
    let Some(matched_scope) = any_of.iter().find(|scope| ctx.scopes.iter().any(|s| s == **scope)) else {
        return Err(ProblemResponse(
            ProblemDetails::forbidden("insufficient scopes").with_extensions(serde_json::json!({
                "code": "MISSING_SCOPE",
                "missingAnyScope": any_of
            })),
        ));
    };

    if matched_scope.starts_with("admin:") {
        return Ok(());
    }

    require_tenant_allowed(&ctx.tenants, tenant_id)?;
    Ok(())
}

#[allow(clippy::result_large_err)]
pub fn require_http_scopes_for_tenant(
    auth: &Authz,
    headers: &HeaderMap,
    required: &[&str],
    tenant_id: &str,
) -> Result<(), ProblemResponse> {
    if auth.mode == AuthMode::Off {
        return Ok(());
    }

    let ctx = http_ctx(auth, headers)?;
    let missing = missing_scopes(&ctx.scopes, required);
    if !missing.is_empty() {
        return Err(ProblemResponse(
            ProblemDetails::forbidden("insufficient scopes").with_extensions(serde_json::json!({
                "code": "MISSING_SCOPE",
                "missingScopes": missing
            })),
        ));
    }

    require_tenant_allowed(&ctx.tenants, tenant_id)?;
    Ok(())
}

#[allow(clippy::result_large_err, dead_code)]
pub fn require_grpc_scopes(auth: &Authz, meta: &MetadataMap, required: &[&str]) -> Result<(), Status> {
    if auth.mode == AuthMode::Off {
        return Ok(());
    }

    let ctx = grpc_ctx(auth, meta)?;
    let missing = missing_scopes(&ctx.scopes, required);
    if missing.is_empty() {
        return Ok(());
    }

    Err(Status::permission_denied(
        serde_json::json!({
            "code": "MISSING_SCOPE",
            "missingScopes": missing
        })
        .to_string(),
    ))
}

#[allow(clippy::result_large_err)]
pub fn require_grpc_scopes_for_tenant(
    auth: &Authz,
    meta: &MetadataMap,
    required: &[&str],
    tenant_id: &str,
) -> Result<(), Status> {
    if auth.mode == AuthMode::Off {
        return Ok(());
    }

    let ctx = grpc_ctx(auth, meta)?;
    let missing = missing_scopes(&ctx.scopes, required);
    if !missing.is_empty() {
        return Err(Status::permission_denied(
            serde_json::json!({
                "code": "MISSING_SCOPE",
                "missingScopes": missing
            })
            .to_string(),
        ));
    }

    match require_tenant_allowed(&ctx.tenants, tenant_id) {
        Ok(_) => Ok(()),
        Err(problem) => Err(Status::permission_denied(problem.0.title)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HS256_SECRET: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn parse_scopes_splits_commas_and_spaces() {
        let s = parse_scopes("a:b,c:d  e:f\tg:h\n");
        assert!(s.contains("a:b"));
        assert!(s.contains("c:d"));
        assert!(s.contains("e:f"));
        assert!(s.contains("g:h"));
    }

    #[test]
    #[serial_test::serial]
    fn jwt_hs256_requires_secret_env() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
        std::env::remove_var(ALLOW_WEAK_HS256_SECRET_ENV);
        let err = Authz::from_env(AuthMode::JwtHs256).unwrap_err();
        assert!(err.contains("CORECRUXD_JWT_HS256_SECRET"));
    }

    #[test]
    #[serial_test::serial]
    fn hs256_rejects_short_secret() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", "secret");
        std::env::remove_var(ALLOW_WEAK_HS256_SECRET_ENV);
        let err = Authz::from_env(AuthMode::JwtHs256).unwrap_err();
        assert!(err.contains("at least 32 bytes"));
        std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
    }

    #[test]
    #[serial_test::serial]
    fn hs256_accepts_32_byte_secret() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", TEST_HS256_SECRET);
        std::env::remove_var(ALLOW_WEAK_HS256_SECRET_ENV);
        let auth = Authz::from_env(AuthMode::JwtHs256).expect("strong secret accepted");
        assert_eq!(auth.mode(), AuthMode::JwtHs256);
        std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
    }

    #[test]
    #[serial_test::serial]
    fn agent_token_accepted_on_http_when_enabled() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        const AGENT_TOK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", TEST_HS256_SECRET);
        std::env::remove_var(ALLOW_WEAK_HS256_SECRET_ENV);
        std::env::remove_var("CORECRUXD_JWT_ISS");
        std::env::remove_var("CORECRUXD_JWT_AUD");
        std::env::set_var("CORECRUXD_HTTP_ACCEPT_AGENT_TOKENS", "1");
        std::env::set_var("CRUX_AGENT_TOKENS", format!("drivew:{AGENT_TOK}"));
        std::env::set_var("CORECRUXD_AGENT_TOKEN_HTTP_SCOPES", "query:read facts:write");
        std::env::set_var("CORECRUXD_AGENT_TOKEN_HTTP_TENANT", "*");

        let auth = Authz::from_env(AuthMode::JwtHs256).expect("auth from env");

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {AGENT_TOK}").parse().unwrap(),
        );
        // The agent token authenticates on HTTP with the configured scopes.
        require_http_scopes(&auth, &headers, &["query:read", "facts:write"]).expect("agent token accepted");
        require_http_scopes_for_tenant(&auth, &headers, &["query:read"], "any-tenant").expect("tenant * allows any");

        // A bogus bearer is still rejected.
        let mut bad = HeaderMap::new();
        bad.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer ffffffffffffffffffffffffffffffffffffffffffffffff"
                .parse()
                .unwrap(),
        );
        assert!(require_http_scopes(&auth, &bad, &["query:read"]).is_err());

        for k in [
            "CORECRUXD_JWT_HS256_SECRET",
            "CORECRUXD_HTTP_ACCEPT_AGENT_TOKENS",
            "CRUX_AGENT_TOKENS",
            "CORECRUXD_AGENT_TOKEN_HTTP_SCOPES",
            "CORECRUXD_AGENT_TOKEN_HTTP_TENANT",
        ] {
            std::env::remove_var(k);
        }
    }

    #[test]
    #[serial_test::serial]
    fn agent_token_rejected_on_http_when_disabled() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        const AGENT_TOK: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";
        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", TEST_HS256_SECRET);
        std::env::remove_var(ALLOW_WEAK_HS256_SECRET_ENV);
        std::env::remove_var("CORECRUXD_HTTP_ACCEPT_AGENT_TOKENS"); // disabled (default)
        std::env::set_var("CRUX_AGENT_TOKENS", format!("drivew:{AGENT_TOK}"));

        let auth = Authz::from_env(AuthMode::JwtHs256).expect("auth from env");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {AGENT_TOK}").parse().unwrap(),
        );
        // Default posture unchanged: an agent token is NOT accepted on HTTP.
        assert!(require_http_scopes(&auth, &headers, &["query:read"]).is_err());

        std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
        std::env::remove_var("CRUX_AGENT_TOKENS");
    }

    #[test]
    #[serial_test::serial]
    fn jwt_hs256_enforces_scopes_and_tenant() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", TEST_HS256_SECRET);
        std::env::remove_var(ALLOW_WEAK_HS256_SECRET_ENV);
        std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-test");
        std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");

        let auth = Authz::from_env(AuthMode::JwtHs256).expect("auth from env");

        #[derive(serde::Serialize)]
        struct Claims<'a> {
            exp: usize,
            iss: &'a str,
            aud: &'a str,
            scope: &'a str,
            tenant_id: &'a str,
        }

        let claims = Claims {
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as usize,
            iss: "corecrux-test",
            aud: "corecrux",
            scope: "receipts:read exports:read",
            tenant_id: "t1",
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
        )
        .expect("jwt");

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );

        require_http_scopes_for_tenant(&auth, &headers, &["exports:read", "receipts:read"], "t1").expect("ok");

        let err = require_http_scopes_for_tenant(&auth, &headers, &["receipts:read"], "t2").unwrap_err();
        assert_eq!(err.0.status, 403);

        let err = require_http_scopes_for_tenant(&auth, &headers, &["admin:read"], "t1").unwrap_err();
        assert_eq!(err.0.status, 403);
    }

    /// D-1 (inverted pin): a token that OMITS a pinned `iss`/`aud` must be
    /// rejected, not waved through. `jsonwebtoken` only compares a pinned
    /// claim when it is present, so pinning without `required_spec_claims`
    /// let a credential minted by the same key for a different audience
    /// authenticate simply by leaving the claim out.
    #[test]
    #[serial_test::serial]
    fn jwt_hs256_token_omitting_pinned_iss_or_aud_is_rejected() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", TEST_HS256_SECRET);
        std::env::remove_var(ALLOW_WEAK_HS256_SECRET_ENV);
        std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-test");
        std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");

        let auth = Authz::from_env(AuthMode::JwtHs256).expect("auth from env");
        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600) as usize;

        let headers_for = |claims: serde_json::Value| {
            let token = encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
            )
            .expect("jwt");
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap(),
            );
            headers
        };

        // Both claims omitted.
        let both = headers_for(serde_json::json!({
            "exp": exp, "scope": "admin:write", "tenant_id": "t1",
        }));
        assert_eq!(
            require_http_scopes(&auth, &both, &["admin:write"])
                .unwrap_err()
                .0
                .status,
            401,
            "a token omitting both pinned claims must not authenticate"
        );

        // `iss` omitted, `aud` correct.
        let no_iss = headers_for(serde_json::json!({
            "exp": exp, "aud": "corecrux", "scope": "admin:write", "tenant_id": "t1",
        }));
        assert_eq!(
            require_http_scopes(&auth, &no_iss, &["admin:write"])
                .unwrap_err()
                .0
                .status,
            401,
            "an absent iss must not read the same as a matching iss"
        );

        // `aud` omitted, `iss` correct.
        let no_aud = headers_for(serde_json::json!({
            "exp": exp, "iss": "corecrux-test", "scope": "admin:write", "tenant_id": "t1",
        }));
        assert_eq!(
            require_http_scopes(&auth, &no_aud, &["admin:write"])
                .unwrap_err()
                .0
                .status,
            401,
            "an absent aud must not read the same as a matching aud"
        );

        // Control: both present and correct still authenticates.
        let good = headers_for(serde_json::json!({
            "exp": exp, "iss": "corecrux-test", "aud": "corecrux",
            "scope": "admin:write", "tenant_id": "t1",
        }));
        require_http_scopes(&auth, &good, &["admin:write"]).expect("fully-claimed token still works");

        std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
        std::env::remove_var("CORECRUXD_JWT_ISS");
        std::env::remove_var("CORECRUXD_JWT_AUD");
    }

    /// D-1 (inverted pin), unpinned-config control: when the daemon pins
    /// neither `iss` nor `aud`, a token omitting them is still fine. The fix
    /// must tighten only what the operator actually configured.
    #[test]
    #[serial_test::serial]
    fn jwt_hs256_unpinned_iss_and_aud_do_not_become_required() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", TEST_HS256_SECRET);
        std::env::remove_var(ALLOW_WEAK_HS256_SECRET_ENV);
        std::env::remove_var("CORECRUXD_JWT_ISS");
        std::env::remove_var("CORECRUXD_JWT_AUD");

        let auth = Authz::from_env(AuthMode::JwtHs256).expect("auth from env");
        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600) as usize;
        let token = encode(
            &Header::new(Algorithm::HS256),
            &serde_json::json!({ "exp": exp, "scope": "admin:write", "tenant_id": "t1" }),
            &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
        )
        .expect("jwt");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        require_http_scopes(&auth, &headers, &["admin:write"]).expect("unpinned config is unchanged");

        std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
    }

    #[test]
    fn jwt_jwks_requires_config_env() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::remove_var("CORECRUXD_JWT_JWKS_JSON");
        std::env::remove_var("CORECRUXD_JWT_JWKS_PATH");
        std::env::remove_var("CORECRUXD_JWT_JWKS_URL");
        std::env::remove_var("CORECRUXD_JWT_OIDC_DISCOVERY_URL");
        std::env::remove_var("CORECRUXD_JWKS_JSON");
        std::env::remove_var("CORECRUXD_JWKS_PATH");
        std::env::remove_var("CORECRUXD_JWKS_URL");
        std::env::remove_var("CORECRUXD_OIDC_DISCOVERY_URL");

        let err = Authz::from_env(AuthMode::JwtJwks).unwrap_err();
        assert!(err.contains("JWKS source"));
    }

    const TEST_RSA_PRIVATE_KEY_PEM: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDNwDIf8ZW0CSCT
utqQBPxrWFmk6Djs1jldflnhw13y0p7iFbx/RlJHwmpmQu9AgjfyRI7nYafoFh/q
IXmnWFbO7Gln9s1GP1t5ASuJse5LBFYRfk3h+hvDROhk92ZgYLI3JpiaXsdGcwa5
xRfZc4/fmFNdE4plg+HhMAxLg8N0fRXYkPerj+ujleWmlq62kU2HwpIr2ZyH7Ry4
VdQ7al2nqjEzElBzYhOpxFQKQlW/OrWd7AbjyGGpW6plYDaY05/yb5nX6Rydn8C4
6DS7of6tnzUP4qvqk9BhfbiMft7T9B65EbIcf5Upz8DD4GeHUZS2W9kZbrXZ2WP1
aObpSloDAgMBAAECggEALRn6YuI0LLjreTa2fmd5ZZaCYBG/mLsE7CesUD7hMz9U
ML8PCN9DXhOR+0Sk6YEh/mtk3/eaNNfUuyAHaNWGgel02aNSMBnnVUkaYB6u26bh
rwf+zpBi0ZUjVC6fNHU927UMMpqgGCNS0BoSNkqMuTjM3VRRPBuCwjgkGdGSYNA9
kBwy6QldQZAQpdr6fJGuSsLjxRDC2YCLlO9+hzUzj+V3yz+I2GAiuB7+4XGWtrsv
ZjVqD+Qi4EXzcVAnNYkBBzNJKHghy+Hj3lgZm1KbdGVaPIbAS1bpAka6GpnwFzbe
DdWKeRlkLL0gVmuNRWv3K65Ey+wwu/8cgixN/6iK0QKBgQD8ELVvwsad8cPBXbgN
/b9LmC0fdE3i4dbLZW3RrQP7QvfNzyByQAJSzrjnKv6PF0JuVhNjNjHGrX/H/F5s
vb0C3TYu+whArhWwNUxaLeym6gVwurWEbamM8TYrfIxMTHsict3BTK/a2OQnkk7y
vjUiDQlYvdByYL+oBVVRp4C/pwKBgQDQ9mhA//ufHWTCfZ+A+Zw/Xu/SKTD87o2w
/XVwGaYqa2D1AGEiKs2TTbPgVkHiYMyU80tb1z9hodqbQDTsE1LxC+GPJfzwQAT0
Y+PYyCdXI+uevChUCTUHgdGl6kaQFczuE76JuvbxxOeELJ3B5H77KvQwsyG6CwMh
KtT2BPn+RQKBgF9zMFGG71FGCLvDcnwR14uXr5aWoxvEK2NQIFri6nwOKupLgdzh
sj+LOmeHV2f2BdjkTWknT4gNkTK4tUT2QInCHM+Djed4RIw6UpRfiZrXSYIbobrp
D+hoOvwSqMoHuCUeXCzjjkAQG62EcNLpBhPD3gM1taZqTokgo+NMy6tHAoGAe/46
zpcWz8u5Rk8Unot+03uaArK+htdm7Gb5kJMnrnQZDEg1WvjbE1VALxX/8jxOKPRU
+yI2UdCgzw7CWHL+/Fl4dmCsPkM+rWW4haH+9g4yefZcV8E+3j2CEVl6lXTaLUs5
/LAcaEnWtu9ijPLxBkjurRceJC70pHGt/G3niaECgYEAiEKqS23CUWaU+ImEJ50v
qyuNpgqT7xnXjqHpRxvxCLFe5WXO7GBqZM9ihRkANg1sDA4Pk8UHEfVmNhT1Wjig
2K9jwjyru7ACsXa+/mkMohSaaeclntPn26K6587SWSsidOF4l4wz+Ys4VroYI6jH
rG+Vg0mnrwArNdy2hX9Qkwc=
-----END PRIVATE KEY-----";

    const TEST_JWKS_JSON: &str = r#"{
  "keys": [
    {
      "kty": "RSA",
      "kid": "test-kid",
      "use": "sig",
      "alg": "RS256",
      "n": "zcAyH_GVtAkgk7rakAT8a1hZpOg47NY5XX5Z4cNd8tKe4hW8f0ZSR8JqZkLvQII38kSO52Gn6BYf6iF5p1hWzuxpZ_bNRj9beQEribHuSwRWEX5N4fobw0ToZPdmYGCyNyaYml7HRnMGucUX2XOP35hTXROKZYPh4TAMS4PDdH0V2JD3q4_ro5XlppautpFNh8KSK9mch-0cuFXUO2pdp6oxMxJQc2ITqcRUCkJVvzq1newG48hhqVuqZWA2mNOf8m-Z1-kcnZ_AuOg0u6H-rZ81D-Kr6pPQYX24jH7e0_QeuRGyHH-VKc_Aw-Bnh1GUtlvZGW612dlj9Wjm6UpaAw",
      "e": "AQAB"
    }
  ]
}"#;

    #[test]
    #[serial_test::serial]
    fn jwt_jwks_rs256_enforces_scopes_and_tenant() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-test");
        std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");
        std::env::set_var("CORECRUXD_JWT_JWKS_JSON", TEST_JWKS_JSON);
        std::env::remove_var("CORECRUXD_JWT_JWKS_URL");
        std::env::remove_var("CORECRUXD_JWT_OIDC_DISCOVERY_URL");

        let auth = Authz::from_env(AuthMode::JwtJwks).expect("auth from env");

        #[derive(serde::Serialize)]
        struct Claims<'a> {
            exp: usize,
            iss: &'a str,
            aud: &'a str,
            scope: &'a str,
            tenant_id: &'a str,
        }

        let claims = Claims {
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600) as usize,
            iss: "corecrux-test",
            aud: "corecrux",
            scope: "receipts:read exports:read",
            tenant_id: "t1",
        };

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".to_string());
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes()).expect("rsa key"),
        )
        .expect("jwt");

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );

        require_http_scopes_for_tenant(&auth, &headers, &["exports:read", "receipts:read"], "t1").expect("ok");

        let err = require_http_scopes_for_tenant(&auth, &headers, &["receipts:read"], "t2").unwrap_err();
        assert_eq!(err.0.status, 403);

        let err = require_http_scopes_for_tenant(&auth, &headers, &["admin:read"], "t1").unwrap_err();
        assert_eq!(err.0.status, 403);

        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600) as usize;
        let signed_context = |claims: serde_json::Value| {
            let token = encode(
                &header,
                &claims,
                &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes()).expect("rsa key"),
            )
            .expect("jwt");
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {token}").parse().unwrap(),
            );
            passport_bound_context(&auth, &headers).expect("passport context")
        };

        let canonical = signed_context(serde_json::json!({
            "exp": exp,
            "iss": "corecrux-test",
            "aud": "corecrux",
            "scope": "admin:write",
            "tenant_id": "default",
            "sub": "automation-subject",
            "passport_id": "operator-passport",
        }));
        assert_eq!(canonical.passport_id.as_deref(), Some("operator-passport"));
        assert!(canonical.canonical_passport_claim_verified());

        let sub_only = signed_context(serde_json::json!({
            "exp": exp,
            "iss": "corecrux-test",
            "aud": "corecrux",
            "scope": "admin:write",
            "tenant_id": "default",
            "sub": "automation-subject",
        }));
        assert_eq!(sub_only.passport_id.as_deref(), Some("automation-subject"));
        assert!(!sub_only.canonical_passport_claim_verified());

        let legacy_alias = signed_context(serde_json::json!({
            "exp": exp,
            "iss": "corecrux-test",
            "aud": "corecrux",
            "scope": "admin:write",
            "tenant_id": "default",
            "passportId": "legacy-passport",
        }));
        assert_eq!(legacy_alias.passport_id.as_deref(), Some("legacy-passport"));
        assert!(!legacy_alias.canonical_passport_claim_verified());

        // D-1 (inverted pin) on the JWKS path: omitting a pinned claim must
        // not bypass the pin. Same defect, same fix as `verify_jwt_hs256`.
        let omitted = encode(
            &header,
            &serde_json::json!({ "exp": exp, "scope": "admin:write", "tenant_id": "t1" }),
            &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes()).expect("rsa key"),
        )
        .expect("jwt");
        let mut omitted_headers = HeaderMap::new();
        omitted_headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {omitted}").parse().unwrap(),
        );
        assert_eq!(
            require_http_scopes(&auth, &omitted_headers, &["admin:write"])
                .unwrap_err()
                .0
                .status,
            401,
            "a JWKS token omitting the pinned iss/aud must not authenticate"
        );

        std::env::remove_var("CORECRUXD_JWT_JWKS_JSON");
        std::env::remove_var("CORECRUXD_JWT_ISS");
        std::env::remove_var("CORECRUXD_JWT_AUD");
    }

    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    fn hs256_auth_headers(mut claims: serde_json::Value) -> (Authz, HeaderMap) {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", TEST_HS256_SECRET);
        std::env::remove_var(ALLOW_WEAK_HS256_SECRET_ENV);
        std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-test");
        std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");

        let obj = claims.as_object_mut().expect("claims object");
        obj.insert(
            "exp".to_string(),
            serde_json::json!(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 3600
            ),
        );
        obj.insert("iss".to_string(), serde_json::json!("corecrux-test"));
        obj.insert("aud".to_string(), serde_json::json!("corecrux"));

        let auth = Authz::from_env(AuthMode::JwtHs256).expect("auth from env");
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
        )
        .expect("jwt");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        (auth, headers)
    }

    // ── AuthMode parsing ──────────────────────────────────────────────────

    #[test]
    fn auth_mode_parse_off_aliases() {
        for alias in &["", "off", "OFF"] {
            assert_eq!(
                AuthMode::parse(alias),
                Some(AuthMode::Off),
                "expected Off for alias '{alias}'"
            );
        }
    }

    /// D-2 (inverted pin): a *present but blank* auth mode is a
    /// misconfiguration, not "off". `parse` trimmed first, so
    /// `CORECRUXD_AUTH_MODE="   "` resolved to `Off` — the daemon booted with
    /// authentication disabled while the config looked set — and
    /// `auth_mode_invalid` stayed `None`, so `main`'s fail-closed guard never
    /// fired. Only a genuinely empty string means "unset".
    #[test]
    fn auth_mode_parse_blank_string_is_rejected_not_off() {
        for blank in &["   ", "\t", "\n", " \t\n "] {
            assert_eq!(
                AuthMode::parse(blank),
                None,
                "a present-but-blank mode must be reported as invalid, not Off"
            );
        }
        // The unset case is still Off.
        assert_eq!(AuthMode::parse(""), Some(AuthMode::Off));
        // Padded but meaningful values are still trimmed and accepted.
        assert_eq!(AuthMode::parse("  off  "), Some(AuthMode::Off));
        assert_eq!(AuthMode::parse("\tdev\n"), Some(AuthMode::DevScopes));
    }

    #[test]
    fn auth_mode_parse_dev_scopes_aliases() {
        for alias in &[
            "dev",
            "DEV",
            "dev_scopes",
            "DEV_SCOPES",
            "devscopes",
            "DEVSCOPES",
            "dev-scopes",
            "DEV-SCOPES",
        ] {
            assert_eq!(
                AuthMode::parse(alias),
                Some(AuthMode::DevScopes),
                "expected DevScopes for alias '{alias}'"
            );
        }
    }

    #[test]
    fn auth_mode_parse_jwt_hs256_aliases() {
        for alias in &["jwt", "JWT", "jwt_hs256", "JWT_HS256", "jwt-hs256", "JWT-HS256"] {
            assert_eq!(
                AuthMode::parse(alias),
                Some(AuthMode::JwtHs256),
                "expected JwtHs256 for alias '{alias}'"
            );
        }
    }

    #[test]
    fn auth_mode_parse_jwt_jwks_aliases() {
        for alias in &[
            "jwt_jwks", "JWT_JWKS", "jwt-jwks", "JWT-JWKS", "jwks", "JWKS", "oidc", "OIDC", "jwt_oidc", "JWT_OIDC",
            "jwt-oidc", "JWT-OIDC",
        ] {
            assert_eq!(
                AuthMode::parse(alias),
                Some(AuthMode::JwtJwks),
                "expected JwtJwks for alias '{alias}'"
            );
        }
    }

    #[test]
    fn auth_mode_parse_trims_whitespace() {
        assert_eq!(AuthMode::parse("  off  "), Some(AuthMode::Off));
        assert_eq!(AuthMode::parse("\tdev\n"), Some(AuthMode::DevScopes));
    }

    #[test]
    fn auth_mode_parse_rejects_unknown() {
        assert_eq!(AuthMode::parse("kerberos"), None);
        assert_eq!(AuthMode::parse("oauth2"), None);
    }

    #[test]
    fn auth_mode_as_str_is_stable() {
        assert_eq!(AuthMode::Off.as_str(), "off");
        assert_eq!(AuthMode::DevScopes.as_str(), "dev_scopes");
        assert_eq!(AuthMode::JwtHs256.as_str(), "jwt_hs256");
        assert_eq!(AuthMode::JwtJwks.as_str(), "jwt_jwks");
    }

    // ── parse_secret ──────────────────────────────────────────────────────

    #[test]
    fn parse_secret_plain_text() {
        let s = parse_secret(TEST_HS256_SECRET).unwrap();
        assert_eq!(s, TEST_HS256_SECRET.as_bytes());
    }

    #[test]
    fn parse_secret_base64_prefix() {
        let s = parse_secret("base64:MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=").unwrap();
        assert_eq!(s, TEST_HS256_SECRET.as_bytes());
    }

    #[test]
    fn parse_secret_empty_is_error() {
        let err = parse_secret("").unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn parse_secret_base64_empty_payload_is_error() {
        let err = parse_secret("base64:").unwrap_err();
        assert!(err.contains("empty"));
    }

    #[test]
    fn parse_secret_base64_invalid_is_error() {
        let err = parse_secret("base64:!!!invalid!!!").unwrap_err();
        assert!(err.contains("base64"));
    }

    // ── parse_scopes ──────────────────────────────────────────────────────

    #[test]
    fn parse_scopes_empty_string() {
        let s = parse_scopes("");
        assert!(s.is_empty());
    }

    #[test]
    fn parse_scopes_whitespace_only() {
        let s = parse_scopes("   \t\n ");
        assert!(s.is_empty());
    }

    #[test]
    fn parse_scopes_deduplicates() {
        let s = parse_scopes("a:b a:b c:d");
        assert_eq!(s.len(), 2);
        assert!(s.contains("a:b"));
        assert!(s.contains("c:d"));
    }

    // ── extract_bearer_token_http ──────────────────────────────────────────

    #[test]
    fn extract_bearer_token_http_with_bearer_prefix() {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::AUTHORIZATION, "Bearer mytoken123".parse().unwrap());
        assert_eq!(extract_bearer_token_http(&headers), Some("mytoken123".to_string()));
    }

    #[test]
    fn extract_bearer_token_http_lowercase_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::AUTHORIZATION, "bearer mytoken".parse().unwrap());
        assert_eq!(extract_bearer_token_http(&headers), Some("mytoken".to_string()));
    }

    #[test]
    fn extract_bearer_token_http_missing_header() {
        let headers = HeaderMap::new();
        assert_eq!(extract_bearer_token_http(&headers), None);
    }

    #[test]
    fn extract_bearer_token_http_non_bearer_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::AUTHORIZATION, "Basic abc123".parse().unwrap());
        assert_eq!(extract_bearer_token_http(&headers), None);
    }

    // ── extract_scopes_http_dev ──────────────────────────────────────────

    #[test]
    fn extract_scopes_http_dev_from_x_corecrux_scopes() {
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "a:read,b:write".parse().unwrap());
        let scopes = extract_scopes_http_dev(&headers).unwrap();
        assert!(scopes.contains("a:read"));
        assert!(scopes.contains("b:write"));
    }

    #[test]
    fn extract_scopes_http_dev_from_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer x:read y:write".parse().unwrap(),
        );
        let scopes = extract_scopes_http_dev(&headers).unwrap();
        assert!(scopes.contains("x:read"));
        assert!(scopes.contains("y:write"));
    }

    #[test]
    fn extract_scopes_http_dev_x_corecrux_takes_precedence() {
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "a:read".parse().unwrap());
        headers.insert(axum::http::header::AUTHORIZATION, "Bearer b:read".parse().unwrap());
        let scopes = extract_scopes_http_dev(&headers).unwrap();
        assert!(scopes.contains("a:read"));
        assert!(!scopes.contains("b:read"));
    }

    #[test]
    fn extract_scopes_http_dev_missing_both() {
        let headers = HeaderMap::new();
        assert!(extract_scopes_http_dev(&headers).is_none());
    }

    // ── scopes_from_claims ────────────────────────────────────────────────

    #[test]
    fn scopes_from_claims_scope_string() {
        let claims = serde_json::json!({ "scope": "a:read b:write" });
        let s = scopes_from_claims(&claims);
        assert!(s.contains("a:read"));
        assert!(s.contains("b:write"));
    }

    #[test]
    fn scopes_from_claims_scp_string() {
        let claims = serde_json::json!({ "scp": "x:read" });
        let s = scopes_from_claims(&claims);
        assert!(s.contains("x:read"));
    }

    #[test]
    fn scopes_from_claims_scopes_array() {
        let claims = serde_json::json!({ "scopes": ["a:read", "b:write"] });
        let s = scopes_from_claims(&claims);
        assert!(s.contains("a:read"));
        assert!(s.contains("b:write"));
    }

    #[test]
    fn scopes_from_claims_permissions_array() {
        let claims = serde_json::json!({ "permissions": ["admin:read"] });
        let s = scopes_from_claims(&claims);
        assert!(s.contains("admin:read"));
    }

    #[test]
    fn scopes_from_claims_combined() {
        let claims = serde_json::json!({
            "scope": "a:read",
            "permissions": ["b:write"],
        });
        let s = scopes_from_claims(&claims);
        assert!(s.contains("a:read"));
        assert!(s.contains("b:write"));
    }

    #[test]
    fn scopes_from_claims_empty_object() {
        let claims = serde_json::json!({});
        let s = scopes_from_claims(&claims);
        assert!(s.is_empty());
    }

    // ── tenants_from_claims ───────────────────────────────────────────────

    #[test]
    fn tenants_from_claims_tenant_id_string() {
        let claims = serde_json::json!({ "tenant_id": "t1" });
        match tenants_from_claims(&claims) {
            TenantAllow::Only(set) => {
                assert_eq!(set.len(), 1);
                assert!(set.contains("t1"));
            }
            other => panic!("expected Only, got {other:?}"),
        }
    }

    #[test]
    fn tenants_from_claims_wildcard() {
        let claims = serde_json::json!({ "tenant_id": "*" });
        assert!(matches!(tenants_from_claims(&claims), TenantAllow::Any));
    }

    #[test]
    fn tenants_from_claims_tenants_array() {
        let claims = serde_json::json!({ "tenants": ["t1", "t2"] });
        match tenants_from_claims(&claims) {
            TenantAllow::Only(set) => {
                assert_eq!(set.len(), 2);
                assert!(set.contains("t1"));
                assert!(set.contains("t2"));
            }
            other => panic!("expected Only, got {other:?}"),
        }
    }

    #[test]
    fn tenants_from_claims_tenants_array_with_wildcard() {
        let claims = serde_json::json!({ "tenants": ["t1", "*"] });
        assert!(matches!(tenants_from_claims(&claims), TenantAllow::Any));
    }

    #[test]
    fn tenants_from_claims_missing() {
        let claims = serde_json::json!({});
        assert!(matches!(tenants_from_claims(&claims), TenantAllow::Missing));
    }

    #[test]
    fn tenants_from_claims_empty_string() {
        let claims = serde_json::json!({ "tenant_id": "" });
        // Empty tenant_id falls through to Missing
        assert!(matches!(tenants_from_claims(&claims), TenantAllow::Missing));
    }

    #[test]
    fn tenants_from_claims_tid_alias() {
        let claims = serde_json::json!({ "tid": "t-via-tid" });
        match tenants_from_claims(&claims) {
            TenantAllow::Only(set) => assert!(set.contains("t-via-tid")),
            other => panic!("expected Only, got {other:?}"),
        }
    }

    #[test]
    fn tenants_from_claims_tenant_id_alias() {
        let claims = serde_json::json!({ "tenantId": "t-via-camel" });
        match tenants_from_claims(&claims) {
            TenantAllow::Only(set) => assert!(set.contains("t-via-camel")),
            other => panic!("expected Only, got {other:?}"),
        }
    }

    // ── subject_from_claims ───────────────────────────────────────────────

    #[test]
    fn subject_from_claims_sub() {
        let claims = serde_json::json!({ "sub": "user-1" });
        assert_eq!(subject_from_claims(&claims), Some("user-1".to_string()));
    }

    #[test]
    fn subject_from_claims_subject_field() {
        let claims = serde_json::json!({ "subject": "user-2" });
        assert_eq!(subject_from_claims(&claims), Some("user-2".to_string()));
    }

    #[test]
    fn subject_from_claims_empty() {
        let claims = serde_json::json!({});
        assert_eq!(subject_from_claims(&claims), None);
    }

    #[test]
    fn subject_from_claims_whitespace_only() {
        let claims = serde_json::json!({ "sub": "   " });
        assert_eq!(subject_from_claims(&claims), None);
    }

    // ── passport_from_claims ──────────────────────────────────────────────

    #[test]
    fn passport_from_claims_prefers_explicit_passport_claim() {
        let claims = serde_json::json!({
            "sub": "subject-id",
            "passport_id": "passport-id",
        });
        assert_eq!(passport_from_claims(&claims), Some("passport-id".to_string()));
    }

    #[test]
    fn passport_from_claims_falls_back_to_subject() {
        let claims = serde_json::json!({ "sub": "subject-id" });
        assert_eq!(passport_from_claims(&claims), Some("subject-id".to_string()));
    }

    #[test]
    fn canonical_passport_from_claims_requires_exact_non_empty_claim() {
        assert_eq!(
            canonical_passport_from_claims(&serde_json::json!({ "passport_id": " passport-id " })),
            Some("passport-id".to_string())
        );
        assert_eq!(
            canonical_passport_from_claims(&serde_json::json!({
                "sub": "subject-id",
                "passportId": "legacy-alias",
            })),
            None
        );
        assert_eq!(
            canonical_passport_from_claims(&serde_json::json!({ "passport_id": "   " })),
            None
        );
    }

    // ── missing_scopes ────────────────────────────────────────────────────

    #[test]
    fn missing_scopes_all_present() {
        let scopes: BTreeSet<String> = ["a:read", "b:write"].iter().map(|s| (*s).to_string()).collect();
        let missing = missing_scopes(&scopes, &["a:read", "b:write"]);
        assert!(missing.is_empty());
    }

    #[test]
    fn missing_scopes_some_missing() {
        let scopes: BTreeSet<String> = ["a:read"].iter().map(|s| (*s).to_string()).collect();
        let missing = missing_scopes(&scopes, &["a:read", "b:write"]);
        assert_eq!(missing, vec!["b:write"]);
    }

    #[test]
    fn missing_scopes_all_missing() {
        let scopes: BTreeSet<String> = BTreeSet::new();
        let missing = missing_scopes(&scopes, &["a:read", "b:write"]);
        assert_eq!(missing, vec!["a:read", "b:write"]);
    }

    #[test]
    fn missing_scopes_empty_required() {
        let scopes: BTreeSet<String> = ["a:read"].iter().map(|s| (*s).to_string()).collect();
        let missing = missing_scopes(&scopes, &[]);
        assert!(missing.is_empty());
    }

    // ── tenant_binding_string ─────────────────────────────────────────────

    #[test]
    fn tenant_binding_string_any() {
        assert_eq!(tenant_binding_string(&TenantAllow::Any), Some("*".to_string()));
    }

    #[test]
    fn tenant_binding_string_only() {
        let mut set = BTreeSet::new();
        set.insert("t1".to_string());
        set.insert("t2".to_string());
        let s = tenant_binding_string(&TenantAllow::Only(set)).unwrap();
        assert_eq!(s, "t1,t2");
    }

    #[test]
    fn tenant_binding_string_missing() {
        assert_eq!(tenant_binding_string(&TenantAllow::Missing), None);
    }

    #[test]
    fn tenant_binding_string_empty_only() {
        assert_eq!(tenant_binding_string(&TenantAllow::Only(BTreeSet::new())), None);
    }

    // ── require_tenant_allowed ────────────────────────────────────────────

    #[test]
    fn require_tenant_allowed_any_always_ok() {
        require_tenant_allowed(&TenantAllow::Any, "anything").unwrap();
    }

    #[test]
    fn require_tenant_allowed_only_matching() {
        let mut set = BTreeSet::new();
        set.insert("t1".to_string());
        require_tenant_allowed(&TenantAllow::Only(set), "t1").unwrap();
    }

    #[test]
    fn require_tenant_allowed_only_not_matching() {
        let mut set = BTreeSet::new();
        set.insert("t1".to_string());
        let err = require_tenant_allowed(&TenantAllow::Only(set), "t2").unwrap_err();
        assert_eq!(err.0.status, 403);
    }

    #[test]
    fn require_tenant_allowed_missing() {
        let err = require_tenant_allowed(&TenantAllow::Missing, "t1").unwrap_err();
        assert_eq!(err.0.status, 403);
    }

    // ── OD-37: write/read tenant resolvers (audit-v2 closeout M1) ──────────

    fn only(ids: &[&str]) -> TenantAllow {
        TenantAllow::Only(ids.iter().map(|s| s.to_string()).collect())
    }

    #[test]
    fn write_tenant_mode_off_always_default() {
        // Backward-compat: flag OFF → default regardless of claim/selector.
        assert_eq!(
            resolve_write_tenant_flagged(&only(&["t1"]), Some("t1"), TenantStampMode::Off).unwrap(),
            None
        );
        assert_eq!(
            resolve_write_tenant_flagged(&TenantAllow::Any, Some("t9"), TenantStampMode::Off).unwrap(),
            None
        );
        assert_eq!(
            resolve_write_tenant_flagged(&TenantAllow::Missing, None, TenantStampMode::Off).unwrap(),
            None
        );
    }

    #[test]
    fn write_tenant_missing_claim_is_default() {
        // No tenant claim (single-tenant deployment) → default even with flag ON.
        assert_eq!(
            resolve_write_tenant_flagged(&TenantAllow::Missing, None, TenantStampMode::On).unwrap(),
            None
        );
    }

    #[test]
    fn write_tenant_single_claim_stamps_that_tenant() {
        assert_eq!(
            resolve_write_tenant_flagged(&only(&["t1"]), None, TenantStampMode::On).unwrap(),
            Some("t1".to_string())
        );
        // A matching selector is fine.
        assert_eq!(
            resolve_write_tenant_flagged(&only(&["t1"]), Some("t1"), TenantStampMode::On).unwrap(),
            Some("t1".to_string())
        );
    }

    #[test]
    fn write_tenant_unauthorized_selector_rejected() {
        // Adversarial: caller tries to stamp a tenant its token does not own.
        let err = resolve_write_tenant_flagged(&only(&["t1"]), Some("t2"), TenantStampMode::On).unwrap_err();
        assert_eq!(err.0.status, 403);
    }

    #[test]
    fn write_tenant_multi_claim_requires_selector() {
        // Ambiguous multi-tenant token with no selector → rejected (never guess).
        let err = resolve_write_tenant_flagged(&only(&["t1", "t2"]), None, TenantStampMode::On).unwrap_err();
        assert_eq!(err.0.status, 403);
        // With a valid selector → that tenant.
        assert_eq!(
            resolve_write_tenant_flagged(&only(&["t1", "t2"]), Some("t2"), TenantStampMode::On).unwrap(),
            Some("t2".to_string())
        );
        // Selector outside the set → rejected.
        assert!(resolve_write_tenant_flagged(&only(&["t1", "t2"]), Some("t3"), TenantStampMode::On).is_err());
    }

    #[test]
    fn write_tenant_wildcard_token_uses_selector_or_default() {
        // Wildcard/admin: selector picks the tenant; absent → default (legacy admin writes).
        assert_eq!(
            resolve_write_tenant_flagged(&TenantAllow::Any, Some("t7"), TenantStampMode::On).unwrap(),
            Some("t7".to_string())
        );
        assert_eq!(
            resolve_write_tenant_flagged(&TenantAllow::Any, None, TenantStampMode::On).unwrap(),
            None
        );
    }

    // ── Shadow posture: observation only, zero behaviour change ───────────

    #[test]
    fn shadow_never_changes_write_behaviour() {
        // Every case that On would stamp or reject, Shadow must still land `default`.
        for (tenants, sel) in [
            (only(&["t1"]), None),             // On: stamps t1
            (only(&["t1", "t2"]), Some("t2")), // On: stamps t2
            (TenantAllow::Any, Some("t7")),    // On: stamps t7
            (only(&["t1", "t2"]), None),       // On: REJECTS (selector required)
            (only(&["t1"]), Some("t2")),       // On: REJECTS (forbidden)
            (TenantAllow::Missing, None),      // On: default anyway
        ] {
            let got = resolve_write_tenant_flagged(&tenants, sel, TenantStampMode::Shadow);
            assert!(
                matches!(got, Ok(None)),
                "shadow must never stamp or reject: {tenants:?} sel={sel:?}"
            );
        }
    }

    #[test]
    fn shadow_never_moves_reads() {
        // If shadow moved reads, it would not be observation-only.
        assert_eq!(
            resolve_read_tenant_flagged(&only(&["t1"]), TenantStampMode::Shadow),
            None
        );
        assert_eq!(
            resolve_read_tenant_flagged(&TenantAllow::Any, TenantStampMode::Shadow),
            None
        );
    }

    #[test]
    fn tenant_stamp_mode_from_env_parsing() {
        // Pure parse check via the same table from_env uses; fail-safe to Off.
        for (raw, want) in [
            ("1", TenantStampMode::On),
            ("true", TenantStampMode::On),
            ("on", TenantStampMode::On),
            ("shadow", TenantStampMode::Shadow),
            ("audit", TenantStampMode::Shadow),
            ("0", TenantStampMode::Off),
            ("off", TenantStampMode::Off),
            ("banana", TenantStampMode::Off),
        ] {
            let got = match raw.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "on" | "enforce" => TenantStampMode::On,
                "shadow" | "audit" => TenantStampMode::Shadow,
                _ => TenantStampMode::Off,
            };
            assert_eq!(got, want, "parse {raw:?}");
        }
    }

    #[test]
    fn read_tenant_lockstep_with_write() {
        // Flag OFF → default; single-tenant token → that tenant; multi/wildcard/missing → default.
        assert_eq!(resolve_read_tenant_flagged(&only(&["t1"]), TenantStampMode::Off), None);
        assert_eq!(
            resolve_read_tenant_flagged(&only(&["t1"]), TenantStampMode::On),
            Some("t1".to_string())
        );
        assert_eq!(
            resolve_read_tenant_flagged(&only(&["t1", "t2"]), TenantStampMode::On),
            None
        );
        assert_eq!(
            resolve_read_tenant_flagged(&TenantAllow::Any, TenantStampMode::On),
            None
        );
        assert_eq!(
            resolve_read_tenant_flagged(&TenantAllow::Missing, TenantStampMode::On),
            None
        );
    }

    // ── parse_jwt_algs ────────────────────────────────────────────────────

    #[test]
    fn parse_jwt_algs_default_rs256() {
        let algs = parse_jwt_algs(None).unwrap();
        assert_eq!(algs, vec![jsonwebtoken::Algorithm::RS256]);
    }

    #[test]
    fn parse_jwt_algs_multiple() {
        let algs = parse_jwt_algs(Some("RS256,ES256")).unwrap();
        assert_eq!(
            algs,
            vec![jsonwebtoken::Algorithm::RS256, jsonwebtoken::Algorithm::ES256,]
        );
    }

    #[test]
    fn parse_jwt_algs_space_separated() {
        let algs = parse_jwt_algs(Some("RS256 ES384")).unwrap();
        assert_eq!(
            algs,
            vec![jsonwebtoken::Algorithm::RS256, jsonwebtoken::Algorithm::ES384,]
        );
    }

    #[test]
    fn parse_jwt_algs_deduplicates() {
        let algs = parse_jwt_algs(Some("RS256,RS256,RS256")).unwrap();
        assert_eq!(algs, vec![jsonwebtoken::Algorithm::RS256]);
    }

    #[test]
    fn parse_jwt_algs_unsupported() {
        let err = parse_jwt_algs(Some("HS256")).unwrap_err();
        assert!(err.contains("unsupported"));
    }

    #[test]
    fn parse_jwt_algs_empty_string() {
        let err = parse_jwt_algs(Some("")).unwrap_err();
        assert!(err.contains("no jwt algs"));
    }

    #[test]
    fn parse_jwt_algs_all_supported() {
        let algs = parse_jwt_algs(Some("RS256,RS384,RS512,ES256,ES384,PS256,PS384,PS512")).unwrap();
        assert_eq!(algs.len(), 8);
    }

    // ── Authz::from_env for Off/DevScopes ─────────────────────────────────

    #[test]
    #[serial_test::serial]
    fn authz_from_env_off_mode() {
        let auth = Authz::from_env(AuthMode::Off).unwrap();
        assert_eq!(auth.mode(), AuthMode::Off);
        assert!(auth.jwt_hs256.is_none());
        assert!(auth.jwt_jwks.is_none());
    }

    #[test]
    #[serial_test::serial]
    fn authz_from_env_dev_scopes_mode() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        assert_eq!(auth.mode(), AuthMode::DevScopes);
        assert!(auth.jwt_hs256.is_none());
        assert!(auth.jwt_jwks.is_none());
    }

    // ── require_http_scopes with Off mode ─────────────────────────────────

    #[test]
    fn require_http_scopes_off_mode_always_ok() {
        let auth = Authz::from_env(AuthMode::Off).unwrap();
        let headers = HeaderMap::new();
        require_http_scopes(&auth, &headers, &["admin:read"]).unwrap();
    }

    // ── require_http_scopes with DevScopes ────────────────────────────────

    #[test]
    fn require_http_scopes_dev_scopes_ok() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "a:read,b:write".parse().unwrap());
        require_http_scopes(&auth, &headers, &["a:read"]).unwrap();
    }

    #[test]
    fn require_http_scopes_dev_scopes_missing_scope() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "a:read".parse().unwrap());
        let err = require_http_scopes(&auth, &headers, &["b:write"]).unwrap_err();
        assert_eq!(err.0.status, 403);
    }

    #[test]
    fn require_http_scopes_dev_scopes_missing_header() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let headers = HeaderMap::new();
        let err = require_http_scopes(&auth, &headers, &["a:read"]).unwrap_err();
        assert_eq!(err.0.status, 401);
    }

    // ── require_http_scopes_for_tenant with DevScopes ─────────────────────

    #[test]
    fn require_http_scopes_for_tenant_dev_scopes_always_any_tenant() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "a:read".parse().unwrap());
        // DevScopes mode sets TenantAllow::Any, so any tenant is allowed
        require_http_scopes_for_tenant(&auth, &headers, &["a:read"], "any-tenant").unwrap();
    }

    #[test]
    #[serial_test::serial]
    fn passport_bound_context_rejects_mismatched_jwt_passport_header() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        let (auth, mut headers) = hs256_auth_headers(serde_json::json!({
            "scope": "facts:write",
            "tenant_id": "t1",
            "passport_id": "passport-a",
        }));
        headers.insert("x-corecrux-passport-id", "passport-b".parse().unwrap());

        let err = passport_bound_context(&auth, &headers).unwrap_err();
        assert_eq!(err.0.status, 403);
    }

    #[test]
    #[serial_test::serial]
    fn passport_bound_context_uses_verified_jwt_passport() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        let (auth, mut headers) = hs256_auth_headers(serde_json::json!({
            "scope": "facts:write",
            "tenant_id": "t1",
            "passport_id": "passport-a",
        }));
        let ctx = passport_bound_context(&auth, &headers).expect("bound context");
        assert_eq!(ctx.passport_id.as_deref(), Some("passport-a"));

        headers.insert("x-corecrux-passport-id", "passport-a".parse().unwrap());
        let ctx = passport_bound_context(&auth, &headers).expect("matching header");
        assert_eq!(ctx.passport_id.as_deref(), Some("passport-a"));
    }

    #[test]
    #[serial_test::serial]
    fn require_http_any_scope_for_tenant_checks_tenant_for_non_admin_scope() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        let (auth, headers) = hs256_auth_headers(serde_json::json!({
            "scope": "gpu1:answer",
            "tenant_id": "tenant-a",
            "passport_id": "passport-a",
        }));

        require_http_any_scope_for_tenant(&auth, &headers, &["gpu1:answer", "admin:write"], "tenant-a")
            .expect("tenant allowed");
        let err = require_http_any_scope_for_tenant(&auth, &headers, &["gpu1:answer", "admin:write"], "tenant-b")
            .unwrap_err();
        assert_eq!(err.0.status, 403);
    }

    #[test]
    #[serial_test::serial]
    fn require_http_any_scope_for_tenant_allows_admin_scope_without_tenant_claim() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        let (auth, headers) = hs256_auth_headers(serde_json::json!({
            "scope": "admin:write",
            "passport_id": "passport-a",
        }));

        require_http_any_scope_for_tenant(&auth, &headers, &["gpu1:answer", "admin:write"], "tenant-b")
            .expect("admin scope bypasses tenant binding");
    }

    // ── extract_bearer_token_grpc ─────────────────────────────────────────

    #[test]
    fn extract_bearer_token_grpc_with_bearer_prefix() {
        let mut meta = MetadataMap::new();
        meta.insert("authorization", "Bearer grpc-token".parse().unwrap());
        assert_eq!(extract_bearer_token_grpc(&meta), Some("grpc-token".to_string()));
    }

    #[test]
    fn extract_bearer_token_grpc_missing() {
        let meta = MetadataMap::new();
        assert_eq!(extract_bearer_token_grpc(&meta), None);
    }

    // ── extract_scopes_grpc_dev ───────────────────────────────────────────

    #[test]
    fn extract_scopes_grpc_dev_from_header() {
        let mut meta = MetadataMap::new();
        meta.insert("x-corecrux-scopes", "a:read,b:write".parse().unwrap());
        let scopes = extract_scopes_grpc_dev(&meta).unwrap();
        assert!(scopes.contains("a:read"));
        assert!(scopes.contains("b:write"));
    }

    #[test]
    fn extract_scopes_grpc_dev_from_bearer() {
        let mut meta = MetadataMap::new();
        meta.insert("authorization", "Bearer c:read d:write".parse().unwrap());
        let scopes = extract_scopes_grpc_dev(&meta).unwrap();
        assert!(scopes.contains("c:read"));
        assert!(scopes.contains("d:write"));
    }

    #[test]
    fn extract_scopes_grpc_dev_header_takes_precedence() {
        let mut meta = MetadataMap::new();
        meta.insert("x-corecrux-scopes", "a:read".parse().unwrap());
        meta.insert("authorization", "Bearer b:read".parse().unwrap());
        let scopes = extract_scopes_grpc_dev(&meta).unwrap();
        assert!(scopes.contains("a:read"));
        assert!(!scopes.contains("b:read"));
    }

    // ══════════════════════════════════════════════════════════════════════
    // Rejection-path coverage. Everything below asserts a DENY (and the exact
    // status: 401 = unauthenticated, 403 = authenticated-but-unauthorised;
    // conflating the two is a real bug), or pins a documented bypass.
    // ══════════════════════════════════════════════════════════════════════

    /// Env-free HS256 `Authz` — lets the JWT rejection matrix run in parallel
    /// instead of serialising on the process env.
    fn hs256_authz() -> Authz {
        Authz::test_hs256(TEST_HS256_SECRET.as_bytes(), "corecrux-test", "corecrux")
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_secs()
    }

    /// Sign `claims` as HS256 with an arbitrary secret (so wrong-key rejection
    /// is reachable without touching the process env).
    fn sign_hs256(claims: &serde_json::Value, secret: &str) -> String {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        encode(
            &Header::new(Algorithm::HS256),
            claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("sign hs256")
    }

    fn valid_claims(extra: serde_json::Value) -> serde_json::Value {
        let mut claims = serde_json::json!({
            "exp": now_secs() + 3600,
            "iss": "corecrux-test",
            "aud": "corecrux",
        });
        let obj = claims.as_object_mut().expect("claims object");
        for (k, v) in extra.as_object().expect("extra object") {
            obj.insert(k.clone(), v.clone());
        }
        claims
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("header value"),
        );
        headers
    }

    fn problem_code(problem: &ProblemResponse) -> String {
        problem
            .0
            .extensions
            .as_ref()
            .and_then(|ext| ext.get("code"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string()
    }

    fn grpc_meta(pairs: &[(&'static str, &str)]) -> MetadataMap {
        let mut meta = MetadataMap::new();
        for (k, v) in pairs {
            meta.insert(*k, v.parse().expect("metadata value"));
        }
        meta
    }

    // ── DEFECT PIN: a whitespace-only auth mode silently means "off" ───────

    // The characterization test that pinned blank-is-Off lived here. It said of
    // itself "This test pins CURRENT behaviour. It is not an endorsement" — the
    // behaviour it pinned is D-2, fixed above. `auth_mode_parse_blank_string_is_rejected_not_off`
    // is its replacement and covers the same inputs with the corrected expectation.

    // ── AuthMode::Off — the documented total bypass ────────────────────────

    #[test]
    fn off_mode_grants_every_scope_without_any_credential() {
        let auth = Authz::from_env(AuthMode::Off).unwrap();
        let headers = HeaderMap::new();
        require_http_scopes(&auth, &headers, &["admin:write", "facts:write"]).unwrap();
        require_http_any_scope(&auth, &headers, &["admin:write"]).unwrap();
        require_http_scopes_for_tenant(&auth, &headers, &["admin:write"], "any-tenant").unwrap();
        require_http_any_scope_for_tenant(&auth, &headers, &["gpu1:answer"], "any-tenant").unwrap();
        require_grpc_scopes(&auth, &MetadataMap::new(), &["admin:write"]).unwrap();
        require_grpc_scopes_for_tenant(&auth, &MetadataMap::new(), &["admin:write"], "any-tenant").unwrap();
    }

    #[test]
    fn off_mode_context_reports_unenforced_and_bypasses_scope_checks() {
        let auth = Authz::from_env(AuthMode::Off).unwrap();
        let ctx = http_scope_context(&auth, &HeaderMap::new()).expect("off-mode context");
        assert!(!ctx.auth_enforced(), "auth-off identities are unverified");
        // scope_bypass: every scope reads as held, including invented ones.
        assert!(ctx.has_scope("admin:write"));
        assert!(ctx.has_scope("not-a-real-scope"));
        assert!(ctx.scopes.is_empty(), "the bypass grants no *actual* scopes");
        assert!(!ctx.passport_override_used());
        assert!(!ctx.canonical_passport_claim_verified());
        assert!(!ctx.credential_is_agent_token());
    }

    #[test]
    fn off_mode_evidence_reports_wildcard_tenant_binding() {
        let auth = Authz::from_env(AuthMode::Off).unwrap();
        let evidence = describe_http_evidence(&auth, &HeaderMap::new()).expect("evidence");
        assert_eq!(evidence.mode, "off");
        assert_eq!(evidence.subject, None);
        assert_eq!(evidence.tenant_binding.as_deref(), Some("*"));
        assert!(evidence.scopes.is_empty());
    }

    // ── DevScopes — missing vs empty vs wrong scopes ───────────────────────

    #[test]
    fn dev_scopes_missing_credential_is_401_not_403() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let err = require_http_scopes(&auth, &HeaderMap::new(), &["admin:read"]).unwrap_err();
        assert_eq!(err.0.status, 401);
        assert_eq!(problem_code(&err), "UNAUTHENTICATED");
    }

    #[test]
    fn dev_scopes_present_but_empty_header_is_403_not_401() {
        // An empty `X-Corecrux-Scopes` still *authenticates* (the header is
        // present), so the failure must be 403 MISSING_SCOPE, not 401.
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "".parse().unwrap());
        let err = require_http_scopes(&auth, &headers, &["admin:read"]).unwrap_err();
        assert_eq!(err.0.status, 403);
        assert_eq!(problem_code(&err), "MISSING_SCOPE");
    }

    #[test]
    fn dev_scopes_whitespace_only_header_authenticates_with_zero_scopes() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "   ,  ,\t".parse().unwrap());
        let ctx = http_scope_context(&auth, &headers).expect("authenticated");
        assert!(ctx.scopes.is_empty());
        assert!(!ctx.has_scope("admin:read"), "no scope_bypass outside auth-off");
        assert_eq!(
            require_http_scopes(&auth, &headers, &["admin:read"])
                .unwrap_err()
                .0
                .status,
            403
        );
    }

    #[test]
    fn dev_scopes_unknown_scope_name_does_not_satisfy_a_required_scope() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let headers = {
            let mut h = HeaderMap::new();
            h.insert("x-corecrux-scopes", "admin:reed,admin,admin:*".parse().unwrap());
            h
        };
        // Near-misses and a would-be wildcard must NOT match `admin:read`.
        let err = require_http_scopes(&auth, &headers, &["admin:read"]).unwrap_err();
        assert_eq!(err.0.status, 403);
        assert_eq!(problem_code(&err), "MISSING_SCOPE");
    }

    #[test]
    fn dev_scopes_duplicated_scopes_collapse_and_still_authorize() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "admin:read,admin:read admin:read".parse().unwrap());
        let ctx = http_scope_context(&auth, &headers).expect("authenticated");
        assert_eq!(ctx.scopes, vec!["admin:read".to_string()]);
        require_http_scopes(&auth, &headers, &["admin:read"]).unwrap();
    }

    #[test]
    fn dev_scopes_partial_scope_set_reports_only_the_missing_ones() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "admin:read".parse().unwrap());
        let err = require_http_scopes(&auth, &headers, &["admin:read", "admin:write"]).unwrap_err();
        assert_eq!(err.0.status, 403);
        let missing = err
            .0
            .extensions
            .as_ref()
            .and_then(|ext| ext.get("missingScopes").cloned())
            .expect("missingScopes extension");
        assert_eq!(missing, serde_json::json!(["admin:write"]));
    }

    #[test]
    fn dev_scopes_non_ascii_bearer_header_is_unauthenticated() {
        // A header whose bytes are not visible ASCII fails `to_str`, so both
        // extractors return None → 401, never a silent empty scope set.
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderValue::from_bytes(b"Bearer \xff\xfe").unwrap(),
        );
        let err = require_http_scopes(&auth, &headers, &["admin:read"]).unwrap_err();
        assert_eq!(err.0.status, 401);
    }

    #[test]
    fn dev_scopes_non_bearer_authorization_scheme_is_unauthenticated() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::AUTHORIZATION, "Basic YWJjOmRlZg==".parse().unwrap());
        assert_eq!(
            require_http_scopes(&auth, &headers, &["admin:read"])
                .unwrap_err()
                .0
                .status,
            401
        );
    }

    #[test]
    fn dev_scopes_tenant_binding_is_wildcard_by_construction() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "gpu1:answer".parse().unwrap());
        // DevScopes carries no tenant claim; it is deliberately `Any`.
        require_http_any_scope_for_tenant(&auth, &headers, &["gpu1:answer"], "whatever").unwrap();
        let evidence = describe_http_evidence(&auth, &headers).expect("evidence");
        assert_eq!(evidence.mode, "dev_scopes");
        assert_eq!(evidence.tenant_binding.as_deref(), Some("*"));
    }

    // ── require_http_any_scope ─────────────────────────────────────────────

    #[test]
    fn require_http_any_scope_accepts_one_of_many() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "exports:read".parse().unwrap());
        require_http_any_scope(&auth, &headers, &["admin:read", "exports:read"]).unwrap();
    }

    #[test]
    fn require_http_any_scope_rejects_when_none_match() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "exports:read".parse().unwrap());
        let err = require_http_any_scope(&auth, &headers, &["admin:read", "admin:write"]).unwrap_err();
        assert_eq!(err.0.status, 403);
        assert_eq!(problem_code(&err), "MISSING_SCOPE");
    }

    #[test]
    fn require_http_any_scope_with_empty_candidate_list_fails_closed() {
        // Absent-signal guard: an empty `any_of` must deny, never allow.
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "admin:write".parse().unwrap());
        assert_eq!(require_http_any_scope(&auth, &headers, &[]).unwrap_err().0.status, 403);
    }

    #[test]
    fn require_http_any_scope_missing_credential_is_401() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        assert_eq!(
            require_http_any_scope(&auth, &HeaderMap::new(), &["admin:read"])
                .unwrap_err()
                .0
                .status,
            401
        );
    }

    #[test]
    fn require_http_any_scope_for_tenant_missing_credential_is_401() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        assert_eq!(
            require_http_any_scope_for_tenant(&auth, &HeaderMap::new(), &["admin:read"], "t1")
                .unwrap_err()
                .0
                .status,
            401
        );
    }

    // ── HS256: credential rejection matrix ─────────────────────────────────

    #[test]
    fn hs256_missing_bearer_is_401_unauthenticated() {
        let auth = hs256_authz();
        let err = require_http_scopes(&auth, &HeaderMap::new(), &["admin:read"]).unwrap_err();
        assert_eq!(err.0.status, 401);
        assert_eq!(problem_code(&err), "UNAUTHENTICATED");
    }

    #[test]
    fn hs256_ignores_dev_scope_header_entirely() {
        // Absent-signal guard: the DevScopes header must not authenticate under
        // a JWT mode, or the dev bypass would survive into production.
        let auth = hs256_authz();
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "admin:write".parse().unwrap());
        let err = require_http_scopes(&auth, &headers, &["admin:write"]).unwrap_err();
        assert_eq!(err.0.status, 401);
    }

    #[test]
    fn hs256_malformed_token_is_401() {
        let auth = hs256_authz();
        for token in ["", "not-a-jwt", "a.b", "a.b.c", "....."] {
            let err = require_http_scopes(&auth, &bearer(token), &["admin:read"]).unwrap_err();
            assert_eq!(err.0.status, 401, "token {token:?} must be 401");
            assert_eq!(problem_code(&err), "UNAUTHENTICATED");
        }
    }

    #[test]
    fn hs256_wrong_signing_key_is_401() {
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "admin:write" })),
            "ffffffffffffffffffffffffffffffff",
        );
        let err = require_http_scopes(&auth, &bearer(&token), &["admin:write"]).unwrap_err();
        assert_eq!(err.0.status, 401);
    }

    #[test]
    fn hs256_expired_token_is_401() {
        let auth = hs256_authz();
        // 30s leeway is configured, so back-date well past it.
        let token = sign_hs256(
            &serde_json::json!({
                "exp": now_secs() - 7200,
                "iss": "corecrux-test",
                "aud": "corecrux",
                "scope": "admin:write",
            }),
            TEST_HS256_SECRET,
        );
        let err = require_http_scopes(&auth, &bearer(&token), &["admin:write"]).unwrap_err();
        assert_eq!(err.0.status, 401);
    }

    #[test]
    fn hs256_not_yet_valid_token_is_401() {
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({
                "nbf": now_secs() + 7200,
                "scope": "admin:write",
            })),
            TEST_HS256_SECRET,
        );
        assert_eq!(
            require_http_scopes(&auth, &bearer(&token), &["admin:write"])
                .unwrap_err()
                .0
                .status,
            401
        );
    }

    #[test]
    fn hs256_missing_exp_claim_is_401() {
        // Absent-signal guard: a token with no expiry must not validate.
        let auth = hs256_authz();
        let token = sign_hs256(
            &serde_json::json!({
                "iss": "corecrux-test",
                "aud": "corecrux",
                "scope": "admin:write",
            }),
            TEST_HS256_SECRET,
        );
        assert_eq!(
            require_http_scopes(&auth, &bearer(&token), &["admin:write"])
                .unwrap_err()
                .0
                .status,
            401
        );
    }

    #[test]
    fn hs256_wrong_issuer_is_401() {
        let auth = hs256_authz();
        let token = sign_hs256(
            &serde_json::json!({
                "exp": now_secs() + 3600,
                "iss": "evil-idp",
                "aud": "corecrux",
                "scope": "admin:write",
            }),
            TEST_HS256_SECRET,
        );
        assert_eq!(
            require_http_scopes(&auth, &bearer(&token), &["admin:write"])
                .unwrap_err()
                .0
                .status,
            401
        );
    }

    #[test]
    fn hs256_wrong_audience_is_401() {
        let auth = hs256_authz();
        let token = sign_hs256(
            &serde_json::json!({
                "exp": now_secs() + 3600,
                "iss": "corecrux-test",
                "aud": "someone-else",
                "scope": "admin:write",
            }),
            TEST_HS256_SECRET,
        );
        assert_eq!(
            require_http_scopes(&auth, &bearer(&token), &["admin:write"])
                .unwrap_err()
                .0
                .status,
            401
        );
    }

    // The DEFECT PIN block for D-1 lived here: two tests asserting that an
    // absent iss/aud claim sails past the configured pinning. Both said of
    // themselves "This test pins CURRENT behaviour. It is not an endorsement".
    // That behaviour is the defect fixed above; the replacements are
    // jwt_hs256_token_omitting_pinned_iss_or_aud_is_rejected and its control
    // jwt_hs256_unpinned_iss_and_aud_do_not_become_required.

    #[test]
    fn hs256_valid_token_with_wrong_scope_is_403_not_401() {
        // The 401/403 split is the contract: this credential is *valid*.
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "exports:read", "tenant_id": "t1" })),
            TEST_HS256_SECRET,
        );
        let err = require_http_scopes(&auth, &bearer(&token), &["admin:write"]).unwrap_err();
        assert_eq!(err.0.status, 403);
        assert_eq!(problem_code(&err), "MISSING_SCOPE");
    }

    #[test]
    fn hs256_token_with_no_scope_claim_authorizes_nothing() {
        let auth = hs256_authz();
        let token = sign_hs256(&valid_claims(serde_json::json!({ "sub": "u1" })), TEST_HS256_SECRET);
        let ctx = http_scope_context(&auth, &bearer(&token)).expect("valid token");
        assert!(ctx.scopes.is_empty());
        assert!(!ctx.has_scope("admin:read"));
        assert_eq!(
            require_http_scopes(&auth, &bearer(&token), &["admin:read"])
                .unwrap_err()
                .0
                .status,
            403
        );
    }

    #[test]
    fn hs256_auth_is_enforced_and_reports_the_verified_subject() {
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "sub": "svc-1", "scope": "admin:read", "tenant_id": "t1" })),
            TEST_HS256_SECRET,
        );
        let ctx = http_scope_context(&auth, &bearer(&token)).expect("valid token");
        assert!(ctx.auth_enforced());
        assert!(!ctx.credential_is_agent_token());
        let evidence = describe_http_evidence(&auth, &bearer(&token)).expect("evidence");
        assert_eq!(evidence.mode, "jwt_hs256");
        assert_eq!(evidence.subject.as_deref(), Some("svc-1"));
        assert_eq!(evidence.tenant_binding.as_deref(), Some("t1"));
    }

    #[test]
    fn describe_http_evidence_propagates_the_credential_rejection() {
        let auth = hs256_authz();
        let err = describe_http_evidence(&auth, &HeaderMap::new()).unwrap_err();
        assert_eq!(err.0.status, 401);
    }

    // ── Tenant resolution + cross-tenant refusal ───────────────────────────

    #[test]
    fn hs256_cross_tenant_access_is_403_tenant_forbidden() {
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "exports:read", "tenant_id": "t1" })),
            TEST_HS256_SECRET,
        );
        let err = require_http_scopes_for_tenant(&auth, &bearer(&token), &["exports:read"], "t2").unwrap_err();
        assert_eq!(err.0.status, 403);
        assert_eq!(problem_code(&err), "TENANT_FORBIDDEN");
    }

    #[test]
    fn hs256_missing_tenant_claim_is_403_tenant_claim_missing() {
        // Absent-signal guard: no tenant claim must NOT read as "all tenants".
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "exports:read" })),
            TEST_HS256_SECRET,
        );
        let err = require_http_scopes_for_tenant(&auth, &bearer(&token), &["exports:read"], "t1").unwrap_err();
        assert_eq!(err.0.status, 403);
        assert_eq!(problem_code(&err), "TENANT_CLAIM_MISSING");
    }

    #[test]
    fn hs256_empty_tenant_claim_is_treated_as_missing_not_wildcard() {
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "exports:read", "tenant_id": "   " })),
            TEST_HS256_SECRET,
        );
        let err = require_http_scopes_for_tenant(&auth, &bearer(&token), &["exports:read"], "t1").unwrap_err();
        assert_eq!(problem_code(&err), "TENANT_CLAIM_MISSING");
    }

    #[test]
    fn hs256_wildcard_tenant_claim_crosses_tenants() {
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "exports:read", "tenant_id": "*" })),
            TEST_HS256_SECRET,
        );
        require_http_scopes_for_tenant(&auth, &bearer(&token), &["exports:read"], "anything").unwrap();
    }

    #[test]
    fn hs256_multi_tenant_claim_allows_only_listed_tenants() {
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "exports:read", "tenants": ["t1", "t2"] })),
            TEST_HS256_SECRET,
        );
        require_http_scopes_for_tenant(&auth, &bearer(&token), &["exports:read"], "t2").unwrap();
        assert_eq!(
            require_http_scopes_for_tenant(&auth, &bearer(&token), &["exports:read"], "t3")
                .unwrap_err()
                .0
                .status,
            403
        );
    }

    #[test]
    fn tenant_check_runs_after_the_scope_check() {
        // A caller with neither must be told about the scope, not the tenant —
        // the tenant id is the more sensitive of the two to leak back.
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "exports:read", "tenant_id": "t1" })),
            TEST_HS256_SECRET,
        );
        let err = require_http_scopes_for_tenant(&auth, &bearer(&token), &["admin:write"], "t2").unwrap_err();
        assert_eq!(problem_code(&err), "MISSING_SCOPE");
    }

    #[test]
    fn any_scope_for_tenant_admin_prefix_skips_the_tenant_binding() {
        let auth = hs256_authz();
        // Documented bypass: an `admin:*` scope authorizes any tenant, even
        // when the token is bound to exactly one.
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "admin:read", "tenant_id": "t1" })),
            TEST_HS256_SECRET,
        );
        require_http_any_scope_for_tenant(&auth, &bearer(&token), &["admin:read"], "t2").unwrap();
    }

    #[test]
    fn any_scope_for_tenant_non_admin_scope_still_checks_the_tenant() {
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "gpu1:answer", "tenant_id": "t1" })),
            TEST_HS256_SECRET,
        );
        let err = require_http_any_scope_for_tenant(&auth, &bearer(&token), &["gpu1:answer"], "t2").unwrap_err();
        assert_eq!(err.0.status, 403);
        assert_eq!(problem_code(&err), "TENANT_FORBIDDEN");
    }

    #[test]
    fn any_scope_for_tenant_admin_bypass_is_prefix_matched_on_the_matched_scope() {
        // `administrator:read` is not `admin:` — the bypass must not fire.
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "administrator:read", "tenant_id": "t1" })),
            TEST_HS256_SECRET,
        );
        let err = require_http_any_scope_for_tenant(&auth, &bearer(&token), &["administrator:read"], "t2").unwrap_err();
        assert_eq!(problem_code(&err), "TENANT_FORBIDDEN");
    }

    // ── Passport binding ───────────────────────────────────────────────────

    #[test]
    fn passport_header_unbound_to_a_claimless_token_is_403() {
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "facts:write", "tenant_id": "t1" })),
            TEST_HS256_SECRET,
        );
        let mut headers = bearer(&token);
        headers.insert("x-corecrux-passport-id", "p-invented".parse().unwrap());
        let err = passport_bound_context(&auth, &headers).unwrap_err();
        assert_eq!(err.0.status, 403);
        assert_eq!(problem_code(&err), "PASSPORT_HEADER_UNBOUND");
    }

    #[test]
    fn passport_header_mismatch_reports_a_distinct_code() {
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({
                "scope": "facts:write", "tenant_id": "t1", "passport_id": "p-a",
            })),
            TEST_HS256_SECRET,
        );
        let mut headers = bearer(&token);
        headers.insert("x-corecrux-passport-id", "p-b".parse().unwrap());
        let err = passport_bound_context(&auth, &headers).unwrap_err();
        assert_eq!(err.0.status, 403);
        assert_eq!(problem_code(&err), "PASSPORT_HEADER_MISMATCH");
    }

    #[test]
    fn passport_override_requires_an_explicit_override_scope() {
        for (scope, allowed) in [
            ("admin:write", true),
            ("passport:impersonate", true),
            ("facts:write", false),
            ("admin:read", false),
        ] {
            let auth = hs256_authz();
            let token = sign_hs256(
                &valid_claims(serde_json::json!({
                    "scope": scope, "tenant_id": "t1", "passport_id": "p-a",
                })),
                TEST_HS256_SECRET,
            );
            let mut headers = bearer(&token);
            headers.insert("x-corecrux-passport-id", "p-b".parse().unwrap());
            let got = passport_bound_context(&auth, &headers);
            assert_eq!(got.is_ok(), allowed, "scope {scope} override expectation");
            if let Ok(ctx) = got {
                assert_eq!(ctx.passport_id.as_deref(), Some("p-b"));
                assert!(ctx.passport_override_used(), "an override must be flagged");
            }
        }
    }

    #[test]
    fn passport_override_scope_also_binds_a_header_to_a_claimless_token() {
        // Pinned behaviour: the override arm is checked BEFORE the unbound arm,
        // so `admin:write` with no passport/sub claim can assert any passport.
        // `canonical_passport_claim_verified` stays false so four-eyes
        // boundaries can still refuse it.
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "admin:write", "tenant_id": "t1" })),
            TEST_HS256_SECRET,
        );
        let mut headers = bearer(&token);
        headers.insert("x-corecrux-passport-id", "p-anything".parse().unwrap());
        let ctx = passport_bound_context(&auth, &headers).expect("override accepted");
        assert_eq!(ctx.passport_id.as_deref(), Some("p-anything"));
        assert!(ctx.passport_override_used());
        assert!(!ctx.canonical_passport_claim_verified());
    }

    #[test]
    fn matching_passport_header_is_not_an_override() {
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({
                "scope": "facts:write", "tenant_id": "t1", "passport_id": "p-a",
            })),
            TEST_HS256_SECRET,
        );
        let mut headers = bearer(&token);
        headers.insert("x-corecrux-passport-id", "p-a".parse().unwrap());
        let ctx = passport_bound_context(&auth, &headers).expect("matching header");
        assert!(!ctx.passport_override_used());
        assert!(ctx.canonical_passport_claim_verified());
    }

    #[test]
    fn dev_and_off_modes_accept_any_passport_header_unverified() {
        // Pinned: outside a JWT mode there is nothing to bind against, so the
        // header is taken at face value and `auth_enforced()` is the only
        // signal a caller has that the identity is unverified.
        for mode in [AuthMode::Off, AuthMode::DevScopes] {
            let auth = Authz::from_env(mode).unwrap();
            let mut headers = HeaderMap::new();
            headers.insert("x-corecrux-scopes", "admin:read".parse().unwrap());
            headers.insert("x-corecrux-passport-id", "p-claimed".parse().unwrap());
            let ctx = passport_bound_context(&auth, &headers).expect("context");
            assert_eq!(ctx.passport_id.as_deref(), Some("p-claimed"));
            assert!(!ctx.passport_override_used(), "override flag is JWT-only");
            assert!(!ctx.canonical_passport_claim_verified());
        }
    }

    #[test]
    fn bind_http_passport_without_a_header_keeps_the_claim() {
        let ctx = AuthContext {
            subject: None,
            passport_id: Some("p-claim".to_string()),
            scopes: BTreeSet::new(),
            tenants: TenantAllow::Missing,
            canonical_passport_claim_verified: true,
            credential_is_agent_token: false,
        };
        assert_eq!(
            bind_http_passport(AuthMode::JwtHs256, &ctx, None).unwrap(),
            Some("p-claim".to_string())
        );
    }

    #[test]
    fn can_override_passport_header_accepts_only_two_scopes() {
        let scopes = |names: &[&str]| -> BTreeSet<String> { names.iter().map(|s| (*s).to_string()).collect() };
        assert!(can_override_passport_header(&scopes(&["admin:write"])));
        assert!(can_override_passport_header(&scopes(&["passport:impersonate"])));
        assert!(!can_override_passport_header(&scopes(&["admin:read", "facts:write"])));
        assert!(!can_override_passport_header(&scopes(&[])));
    }

    #[test]
    fn http_passport_id_rejects_blank_and_unreadable_headers() {
        assert_eq!(http_passport_id(&HeaderMap::new()), None);
        let mut blank = HeaderMap::new();
        blank.insert("x-corecrux-passport-id", "   ".parse().unwrap());
        assert_eq!(http_passport_id(&blank), None);
        let mut binary = HeaderMap::new();
        binary.insert(
            "x-corecrux-passport-id",
            axum::http::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        assert_eq!(http_passport_id(&binary), None);
        let mut padded = HeaderMap::new();
        padded.insert("x-corecrux-passport-id", "  p-a  ".parse().unwrap());
        assert_eq!(http_passport_id(&padded), Some("p-a".to_string()));
    }

    #[test]
    fn http_tenant_selector_rejects_blank_and_unreadable_headers() {
        assert_eq!(http_tenant_selector(&HeaderMap::new()), None);
        let mut blank = HeaderMap::new();
        blank.insert("x-corecrux-tenant-id", "  ".parse().unwrap());
        assert_eq!(http_tenant_selector(&blank), None);
        let mut binary = HeaderMap::new();
        binary.insert(
            "x-corecrux-tenant-id",
            axum::http::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        assert_eq!(http_tenant_selector(&binary), None);
        let mut ok = HeaderMap::new();
        ok.insert("x-corecrux-tenant-id", " t9 ".parse().unwrap());
        assert_eq!(http_tenant_selector(&ok), Some("t9".to_string()));
    }

    // ── Misconfigured auth must be 500, never an open door ─────────────────

    #[test]
    fn jwt_mode_without_a_loaded_config_is_500_not_a_bypass() {
        for mode in [AuthMode::JwtHs256, AuthMode::JwtJwks] {
            let auth = Authz {
                mode,
                jwt_hs256: None,
                jwt_jwks: None,
                agent_http: None,
            };
            let err = require_http_scopes(&auth, &bearer("anything"), &["admin:read"]).unwrap_err();
            assert_eq!(err.0.status, 500, "{mode:?} must not fall open");
            assert_eq!(problem_code(&err), "AUTH_MISCONFIGURED");

            let status =
                require_grpc_scopes(&auth, &grpc_meta(&[("authorization", "Bearer x")]), &["admin:read"]).unwrap_err();
            assert_eq!(status.code(), tonic::Code::Internal);
        }
    }

    #[test]
    fn authz_debug_does_not_leak_the_secret() {
        let auth = hs256_authz();
        let rendered = format!("{auth:?}");
        assert!(rendered.contains("JwtHs256"));
        assert!(
            !rendered.contains(TEST_HS256_SECRET),
            "Authz Debug must not print the HS256 secret"
        );
    }

    // ── gRPC plane ─────────────────────────────────────────────────────────

    #[test]
    fn grpc_dev_scopes_missing_credential_is_unauthenticated() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let status = require_grpc_scopes(&auth, &MetadataMap::new(), &["admin:read"]).unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unauthenticated);
        assert!(status.message().contains("UNAUTHENTICATED"));
    }

    #[test]
    fn grpc_dev_scopes_wrong_scope_is_permission_denied_not_unauthenticated() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let meta = grpc_meta(&[("x-corecrux-scopes", "exports:read")]);
        let status = require_grpc_scopes(&auth, &meta, &["admin:write"]).unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
        assert!(status.message().contains("MISSING_SCOPE"));
    }

    #[test]
    fn grpc_dev_scopes_sufficient_scope_is_allowed() {
        let auth = Authz::from_env(AuthMode::DevScopes).unwrap();
        let meta = grpc_meta(&[("x-corecrux-scopes", "admin:write,admin:read")]);
        require_grpc_scopes(&auth, &meta, &["admin:read", "admin:write"]).unwrap();
    }

    #[test]
    fn grpc_hs256_missing_and_invalid_tokens_are_unauthenticated() {
        let auth = hs256_authz();
        let missing = require_grpc_scopes(&auth, &MetadataMap::new(), &["admin:read"]).unwrap_err();
        assert_eq!(missing.code(), tonic::Code::Unauthenticated);

        let bad = require_grpc_scopes(
            &auth,
            &grpc_meta(&[("authorization", "Bearer not-a-jwt")]),
            &["admin:read"],
        )
        .unwrap_err();
        assert_eq!(bad.code(), tonic::Code::Unauthenticated);
        assert!(bad.message().contains("invalid bearer token"));
    }

    #[test]
    fn grpc_hs256_valid_token_enforces_scopes_and_tenant() {
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "exports:read", "tenant_id": "t1" })),
            TEST_HS256_SECRET,
        );
        let meta = grpc_meta(&[("authorization", format!("Bearer {token}").as_str())]);
        require_grpc_scopes_for_tenant(&auth, &meta, &["exports:read"], "t1").unwrap();

        let cross = require_grpc_scopes_for_tenant(&auth, &meta, &["exports:read"], "t2").unwrap_err();
        assert_eq!(cross.code(), tonic::Code::PermissionDenied);

        let scope = require_grpc_scopes_for_tenant(&auth, &meta, &["admin:write"], "t1").unwrap_err();
        assert_eq!(scope.code(), tonic::Code::PermissionDenied);
        assert!(scope.message().contains("MISSING_SCOPE"));
    }

    #[test]
    fn grpc_missing_tenant_claim_is_permission_denied() {
        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "exports:read" })),
            TEST_HS256_SECRET,
        );
        let meta = grpc_meta(&[("authorization", format!("Bearer {token}").as_str())]);
        let status = require_grpc_scopes_for_tenant(&auth, &meta, &["exports:read"], "t1").unwrap_err();
        assert_eq!(status.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn grpc_lowercase_bearer_prefix_is_accepted() {
        let meta = grpc_meta(&[("authorization", "bearer grpc-token")]);
        assert_eq!(extract_bearer_token_grpc(&meta), Some("grpc-token".to_string()));
    }

    #[test]
    fn grpc_non_bearer_scheme_is_not_a_token() {
        let meta = grpc_meta(&[("authorization", "Basic abc")]);
        assert_eq!(extract_bearer_token_grpc(&meta), None);
        assert!(extract_scopes_grpc_dev(&meta).is_none());
    }

    // ── Claim extraction edge cases ────────────────────────────────────────

    #[test]
    fn scopes_from_claims_accepts_scp_as_an_array() {
        let claims = serde_json::json!({ "scp": ["a:read", "b:write"] });
        let s = scopes_from_claims(&claims);
        assert!(s.contains("a:read"));
        assert!(s.contains("b:write"));
    }

    #[test]
    fn scopes_from_claims_ignores_non_string_array_members() {
        let claims = serde_json::json!({ "scopes": ["a:read", 42, null, { "x": 1 }] });
        let s = scopes_from_claims(&claims);
        assert_eq!(s.len(), 1);
        assert!(s.contains("a:read"));
    }

    #[test]
    fn scopes_from_claims_ignores_wrong_typed_scope_claims() {
        // A numeric/array `scope` (rather than a space-delimited string) must
        // grant nothing, not silently pass.
        assert!(scopes_from_claims(&serde_json::json!({ "scope": 7 })).is_empty());
        assert!(scopes_from_claims(&serde_json::json!({ "permissions": "a:read" })).is_empty());
    }

    #[test]
    fn tenants_from_claims_ignores_non_string_array_members_and_blanks() {
        let claims = serde_json::json!({ "tenants": ["t1", "   ", 5, null] });
        match tenants_from_claims(&claims) {
            TenantAllow::Only(set) => {
                assert_eq!(set.len(), 1);
                assert!(set.contains("t1"));
            }
            other => panic!("expected Only, got {other:?}"),
        }
    }

    #[test]
    fn tenants_from_claims_all_blank_array_is_missing_not_wildcard() {
        let claims = serde_json::json!({ "tenants": ["  ", ""] });
        assert!(matches!(tenants_from_claims(&claims), TenantAllow::Missing));
    }

    #[test]
    fn tenants_from_claims_prefers_scalar_claims_over_the_array() {
        let claims = serde_json::json!({ "tenant_id": "t-scalar", "tenants": ["t-array"] });
        match tenants_from_claims(&claims) {
            TenantAllow::Only(set) => assert!(set.contains("t-scalar")),
            other => panic!("expected Only, got {other:?}"),
        }
    }

    #[test]
    fn tenants_from_claims_wrong_typed_claim_is_missing() {
        assert!(matches!(
            tenants_from_claims(&serde_json::json!({ "tenant_id": 7 })),
            TenantAllow::Missing
        ));
        assert!(matches!(
            tenants_from_claims(&serde_json::json!({ "tenants": "t1" })),
            TenantAllow::Missing
        ));
    }

    #[test]
    fn passport_from_claims_walks_every_legacy_alias() {
        for alias in ["passportId", "passport", "passport_fpr", "passportFpr", "pid"] {
            let claims = serde_json::json!({ alias: "p-legacy" });
            assert_eq!(
                passport_from_claims(&claims),
                Some("p-legacy".to_string()),
                "alias {alias}"
            );
            assert_eq!(canonical_passport_from_claims(&claims), None, "alias {alias}");
        }
    }

    #[test]
    fn passport_from_claims_skips_blank_aliases() {
        let claims = serde_json::json!({ "passportId": "  ", "sub": "u1" });
        assert_eq!(passport_from_claims(&claims), Some("u1".to_string()));
    }

    #[test]
    fn passport_from_claims_returns_none_when_nothing_identifies_the_caller() {
        assert_eq!(passport_from_claims(&serde_json::json!({})), None);
        assert_eq!(passport_from_claims(&serde_json::json!({ "sub": "   " })), None);
    }

    #[test]
    fn subject_from_claims_ignores_non_string_values() {
        assert_eq!(subject_from_claims(&serde_json::json!({ "sub": 42 })), None);
    }

    // ── Secret parsing / strength policy ───────────────────────────────────

    #[test]
    fn parse_secret_rejects_a_short_base64_secret() {
        let short = base64::engine::general_purpose::STANDARD.encode(b"tooshort");
        let err = parse_secret(&format!("base64:{short}")).unwrap_err();
        assert!(err.contains("at least 32 bytes"), "got {err}");
    }

    #[test]
    fn parse_secret_accepts_exactly_the_minimum_length() {
        let secret = "a".repeat(MIN_HS256_SECRET_BYTES);
        assert_eq!(parse_secret(&secret).unwrap().len(), MIN_HS256_SECRET_BYTES);
    }

    #[test]
    #[serial_test::serial]
    fn weak_secret_is_only_accepted_behind_the_explicit_dev_override() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::remove_var(ALLOW_WEAK_HS256_SECRET_ENV);
        assert!(validate_hs256_secret(b"short").is_err());

        for value in ["1", "true", "TRUE", "yes", "YES"] {
            std::env::set_var(ALLOW_WEAK_HS256_SECRET_ENV, value);
            assert!(
                validate_hs256_secret(b"short").is_ok(),
                "{value} should enable the override"
            );
        }
        // Anything else must NOT enable it — the override is opt-in only.
        for value in ["0", "on", "no", "", "  1  "] {
            std::env::set_var(ALLOW_WEAK_HS256_SECRET_ENV, value);
            assert!(
                validate_hs256_secret(b"short").is_err(),
                "{value:?} must not enable the override"
            );
        }
        std::env::remove_var(ALLOW_WEAK_HS256_SECRET_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn hs256_from_env_accepts_a_weak_secret_only_with_the_override() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", "weak");
        std::env::set_var(ALLOW_WEAK_HS256_SECRET_ENV, "1");
        let auth = Authz::from_env(AuthMode::JwtHs256).expect("override accepted");
        assert_eq!(auth.mode(), AuthMode::JwtHs256);

        std::env::remove_var(ALLOW_WEAK_HS256_SECRET_ENV);
        std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
    }

    // ── env_truthy (gates HTTP acceptance of MCP agent tokens) ─────────────

    #[test]
    #[serial_test::serial]
    fn env_truthy_accepts_only_the_documented_affirmatives() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        const KEY: &str = "CORECRUXD_ENV_TRUTHY_PROBE";
        std::env::remove_var(KEY);
        assert!(!env_truthy(KEY), "an unset flag must be false");

        for value in ["1", "true", "TRUE", "yes", "YES", "on", "ON", "  1  "] {
            std::env::set_var(KEY, value);
            assert!(env_truthy(KEY), "{value:?} should be truthy");
        }
        for value in ["0", "false", "FALSE", "no", "off", "", "  ", "True", "enabled"] {
            std::env::set_var(KEY, value);
            assert!(!env_truthy(KEY), "{value:?} must not be truthy");
        }
        std::env::remove_var(KEY);
    }

    // ── Agent-token HTTP acceptance ────────────────────────────────────────

    const TEST_AGENT_TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

    fn clear_agent_env() {
        for key in [
            "CORECRUXD_HTTP_ACCEPT_AGENT_TOKENS",
            "CRUX_AGENT_TOKENS",
            "CRUX_AGENT_TOKEN",
            "CORECRUXD_AGENT_TOKEN_HTTP_SCOPES",
            "CORECRUXD_AGENT_TOKEN_HTTP_TENANT",
        ] {
            std::env::remove_var(key);
        }
    }

    #[test]
    #[serial_test::serial]
    fn agent_http_config_is_none_unless_the_flag_and_a_token_are_both_present() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_agent_env();

        // Flag off, token present → disabled.
        std::env::set_var("CRUX_AGENT_TOKENS", format!("a:{TEST_AGENT_TOKEN}"));
        assert!(build_agent_http_config().is_none());

        // Flag on, no tokens → disabled (empty registry).
        std::env::remove_var("CRUX_AGENT_TOKENS");
        std::env::set_var("CORECRUXD_HTTP_ACCEPT_AGENT_TOKENS", "1");
        assert!(build_agent_http_config().is_none());

        // Flag on, malformed token env → fail closed, still disabled.
        std::env::set_var("CRUX_AGENT_TOKENS", "a:short");
        assert!(build_agent_http_config().is_none());

        clear_agent_env();
    }

    #[test]
    #[serial_test::serial]
    fn agent_http_config_defaults_scopes_when_the_scope_env_is_blank() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_agent_env();

        std::env::set_var("CORECRUXD_HTTP_ACCEPT_AGENT_TOKENS", "1");
        std::env::set_var("CRUX_AGENT_TOKENS", format!("a:{TEST_AGENT_TOKEN}"));
        std::env::set_var("CORECRUXD_AGENT_TOKEN_HTTP_SCOPES", "   ,  ");
        let cfg = build_agent_http_config().expect("agent http config");
        assert_eq!(cfg.scopes, default_agent_http_scopes());
        assert!(matches!(cfg.tenants, TenantAllow::Any), "tenant defaults to '*'");

        clear_agent_env();
    }

    #[test]
    #[serial_test::serial]
    fn agent_token_is_bound_to_the_configured_tenant_set() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_agent_env();

        std::env::set_var("CORECRUXD_HTTP_ACCEPT_AGENT_TOKENS", "1");
        std::env::set_var("CRUX_AGENT_TOKENS", format!("drivew:{TEST_AGENT_TOKEN}"));
        std::env::set_var("CORECRUXD_AGENT_TOKEN_HTTP_SCOPES", "query:read");
        std::env::set_var("CORECRUXD_AGENT_TOKEN_HTTP_TENANT", "t1 t2");
        let cfg = build_agent_http_config().expect("agent http config");

        let ctx = cfg.try_auth(TEST_AGENT_TOKEN).expect("registered token");
        assert_eq!(ctx.subject.as_deref(), Some("agent:drivew"));
        assert_eq!(ctx.passport_id.as_deref(), Some("agent:drivew"));
        assert!(ctx.credential_is_agent_token);
        assert!(!ctx.canonical_passport_claim_verified);
        require_tenant_allowed(&ctx.tenants, "t2").unwrap();
        assert_eq!(require_tenant_allowed(&ctx.tenants, "t3").unwrap_err().0.status, 403);

        // An unregistered token authenticates nothing.
        assert!(cfg
            .try_auth("ffffffffffffffffffffffffffffffffffffffffffffffff")
            .is_none());
        assert!(cfg.try_auth("").is_none());

        clear_agent_env();
    }

    #[test]
    #[serial_test::serial]
    fn agent_token_over_http_cannot_cross_its_tenant_binding() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_agent_env();

        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", TEST_HS256_SECRET);
        std::env::remove_var(ALLOW_WEAK_HS256_SECRET_ENV);
        std::env::remove_var("CORECRUXD_JWT_ISS");
        std::env::remove_var("CORECRUXD_JWT_AUD");
        std::env::set_var("CORECRUXD_HTTP_ACCEPT_AGENT_TOKENS", "1");
        std::env::set_var("CRUX_AGENT_TOKENS", format!("drivew:{TEST_AGENT_TOKEN}"));
        std::env::set_var("CORECRUXD_AGENT_TOKEN_HTTP_SCOPES", "query:read");
        std::env::set_var("CORECRUXD_AGENT_TOKEN_HTTP_TENANT", "t1");

        let auth = Authz::from_env(AuthMode::JwtHs256).expect("auth from env");
        let headers = bearer(TEST_AGENT_TOKEN);

        require_http_scopes_for_tenant(&auth, &headers, &["query:read"], "t1").expect("bound tenant");
        let cross = require_http_scopes_for_tenant(&auth, &headers, &["query:read"], "t2").unwrap_err();
        assert_eq!(cross.0.status, 403);
        assert_eq!(problem_code(&cross), "TENANT_FORBIDDEN");

        // Scopes outside the configured set are still denied (403, not 401).
        let scope = require_http_scopes(&auth, &headers, &["admin:write"]).unwrap_err();
        assert_eq!(scope.0.status, 403);

        // And the credential is flagged as machine provenance.
        let ctx = passport_bound_context(&auth, &headers).expect("agent context");
        assert!(ctx.credential_is_agent_token());
        assert!(!ctx.canonical_passport_claim_verified());
        assert_eq!(ctx.passport_id.as_deref(), Some("agent:drivew"));

        clear_agent_env();
        std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
    }

    #[test]
    fn tenant_allow_from_str_parses_wildcard_lists_and_blanks() {
        assert!(matches!(tenant_allow_from_str("*"), TenantAllow::Any));
        assert!(matches!(tenant_allow_from_str("  *  "), TenantAllow::Any));
        assert!(matches!(tenant_allow_from_str(""), TenantAllow::Missing));
        assert!(matches!(tenant_allow_from_str("  , ,\t"), TenantAllow::Missing));
        match tenant_allow_from_str("t1, t2\tt3") {
            TenantAllow::Only(set) => assert_eq!(set.len(), 3),
            other => panic!("expected Only, got {other:?}"),
        }
        // A list containing `*` is NOT a wildcard — only a bare `*` is.
        match tenant_allow_from_str("t1,*") {
            TenantAllow::Only(set) => assert!(set.contains("*")),
            other => panic!("expected Only, got {other:?}"),
        }
    }

    #[test]
    fn default_agent_http_scopes_is_the_documented_set() {
        let scopes = default_agent_http_scopes();
        for expected in [
            "admin:read",
            "admin:write",
            "facts:write",
            "query:read",
            "sessions:read",
            "sessions:write",
        ] {
            assert!(scopes.contains(expected), "missing {expected}");
        }
        assert_eq!(scopes.len(), 6, "scope set must not silently grow");
    }

    // ── JWKS: key selection + verification rejections ──────────────────────

    fn test_jwks_agent() -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_millis(1)))
            .build()
            .into()
    }

    fn jwks_cfg(keys: HashMap<String, jsonwebtoken::DecodingKey>, jwks_url: Option<&str>) -> JwtJwksConfig {
        JwtJwksConfig {
            issuer: None,
            audience: None,
            algorithms: vec![jsonwebtoken::Algorithm::RS256],
            jwks_url: jwks_url.map(str::to_string),
            min_refresh_interval: Duration::from_secs(3600),
            agent: test_jwks_agent(),
            state: Arc::new(Mutex::new(JwksState {
                keys,
                last_refresh_attempt: None,
                last_refresh_ok: None,
                last_error: None,
            })),
        }
    }

    fn dummy_key(seed: &[u8]) -> jsonwebtoken::DecodingKey {
        jsonwebtoken::DecodingKey::from_secret(seed)
    }

    #[test]
    fn resolve_jwks_key_returns_the_only_key_when_no_kid_is_present() {
        let mut keys = HashMap::new();
        keys.insert("only".to_string(), dummy_key(b"k"));
        let cfg = jwks_cfg(keys, None);
        assert!(resolve_jwks_key(&cfg, None).is_ok());
        assert!(resolve_jwks_key(&cfg, Some("only")).is_ok());
    }

    #[test]
    fn resolve_jwks_key_static_jwks_rejects_an_unknown_kid() {
        let mut keys = HashMap::new();
        keys.insert("known".to_string(), dummy_key(b"k"));
        let cfg = jwks_cfg(keys, None);
        let err = resolve_jwks_key(&cfg, Some("attacker-kid")).unwrap_err();
        assert!(err.contains("not found (static jwks)"), "got {err}");
    }

    #[test]
    fn resolve_jwks_key_refuses_to_guess_between_multiple_keys() {
        // Absent-signal guard: a token with no `kid` must not be matched
        // against an arbitrary key when several are loaded.
        let mut keys = HashMap::new();
        keys.insert("a".to_string(), dummy_key(b"a"));
        keys.insert("b".to_string(), dummy_key(b"b"));
        let cfg = jwks_cfg(keys, None);
        let err = resolve_jwks_key(&cfg, None).unwrap_err();
        assert!(err.contains("multiple keys"), "got {err}");
    }

    #[test]
    fn resolve_jwks_key_rate_limits_refresh_on_miss_without_hitting_the_network() {
        let mut keys = HashMap::new();
        keys.insert("known".to_string(), dummy_key(b"k"));
        let cfg = jwks_cfg(keys, Some("http://127.0.0.1:1/jwks"));
        {
            // Pretend we just refreshed, so the miss path short-circuits.
            let mut state = cfg.state.lock().unwrap();
            state.last_refresh_attempt = Some(Instant::now());
            state.last_refresh_ok = Some(Instant::now());
            state.last_error = Some("previous failure".to_string());
        }
        let err = resolve_jwks_key(&cfg, Some("attacker-kid")).unwrap_err();
        assert!(err.contains("rate-limited"), "got {err}");
        assert!(err.contains("last_error"), "got {err}");
        // The cached key is still served — rate limiting must not break the
        // happy path for a kid we already hold.
        assert!(resolve_jwks_key(&cfg, Some("known")).is_ok());
    }

    #[test]
    fn resolve_jwks_key_no_kid_with_many_keys_is_rate_limited_too() {
        let mut keys = HashMap::new();
        keys.insert("a".to_string(), dummy_key(b"a"));
        keys.insert("b".to_string(), dummy_key(b"b"));
        let cfg = jwks_cfg(keys, Some("http://127.0.0.1:1/jwks"));
        {
            let mut state = cfg.state.lock().unwrap();
            state.last_refresh_attempt = Some(Instant::now());
        }
        let err = resolve_jwks_key(&cfg, None).unwrap_err();
        assert!(err.contains("multiple keys"), "got {err}");
    }

    #[test]
    fn parse_jwks_keys_skips_unusable_entries() {
        let jwks = Jwks {
            keys: vec![
                // encryption key — not for signatures
                Jwk {
                    kty: "RSA".into(),
                    kid: Some("enc".into()),
                    use_: Some("enc".into()),
                    n: Some("zcAyH".into()),
                    e: Some("AQAB".into()),
                    x: None,
                    y: None,
                },
                // no kid
                Jwk {
                    kty: "RSA".into(),
                    kid: None,
                    use_: Some("sig".into()),
                    n: Some("zcAyH".into()),
                    e: Some("AQAB".into()),
                    x: None,
                    y: None,
                },
                // unknown key type
                Jwk {
                    kty: "oct".into(),
                    kid: Some("sym".into()),
                    use_: Some("sig".into()),
                    n: None,
                    e: None,
                    x: None,
                    y: None,
                },
                // RSA missing components
                Jwk {
                    kty: "RSA".into(),
                    kid: Some("partial".into()),
                    use_: None,
                    n: Some("zcAyH".into()),
                    e: None,
                    x: None,
                    y: None,
                },
                // EC missing components
                Jwk {
                    kty: "EC".into(),
                    kid: Some("ec-partial".into()),
                    use_: Some("sig".into()),
                    n: None,
                    e: None,
                    x: Some("abc".into()),
                    y: None,
                },
            ],
        };
        let err = parse_jwks_keys(&jwks).unwrap_err();
        assert!(err.contains("no usable sig keys"), "got {err}");
    }

    #[test]
    fn parse_jwks_keys_accepts_an_ec_signing_key() {
        let jwks = Jwks {
            keys: vec![Jwk {
                kty: "EC".into(),
                kid: Some("ec-1".into()),
                use_: Some("sig".into()),
                n: None,
                e: None,
                x: Some("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4".into()),
                y: Some("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM".into()),
            }],
        };
        let keys = parse_jwks_keys(&jwks).expect("ec key parsed");
        assert!(keys.contains_key("ec-1"));
    }

    #[test]
    fn parse_jwks_keys_on_an_empty_set_is_an_error_not_an_empty_allow() {
        let err = parse_jwks_keys(&Jwks { keys: Vec::new() }).unwrap_err();
        assert!(err.contains("no usable sig keys"));
    }

    #[test]
    fn resolve_initial_jwks_reports_each_bad_source() {
        let agent = test_jwks_agent();

        let err = resolve_initial_jwks(&agent, None, Some("{not json".into()), None, None, None).unwrap_err();
        assert!(err.contains("invalid CORECRUXD_JWT_JWKS_JSON"), "got {err}");

        let err = resolve_initial_jwks(
            &agent,
            None,
            None,
            Some("/nonexistent/path/to/jwks.json".into()),
            None,
            None,
        )
        .unwrap_err();
        assert!(err.contains("read jwks path failed"), "got {err}");

        let err = resolve_initial_jwks(&agent, None, None, None, None, None).unwrap_err();
        assert!(err.contains("missing JWKS source"), "got {err}");
    }

    #[test]
    fn resolve_initial_jwks_loads_inline_json_and_a_file() {
        let agent = test_jwks_agent();

        let (issuer, url, keys) = resolve_initial_jwks(
            &agent,
            Some("https://idp.example".to_string()),
            Some(TEST_JWKS_JSON.to_string()),
            None,
            None,
            None,
        )
        .expect("inline jwks");
        assert_eq!(issuer.as_deref(), Some("https://idp.example"));
        assert_eq!(url, None);
        assert!(keys.contains_key("test-kid"));

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("jwks.json");
        std::fs::write(&path, TEST_JWKS_JSON).expect("write jwks");
        let (_, url, keys) =
            resolve_initial_jwks(&agent, None, None, Some(path.to_string_lossy().to_string()), None, None)
                .expect("file jwks");
        assert_eq!(url, None);
        assert!(keys.contains_key("test-kid"));

        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, "{not json").expect("write bad jwks");
        let err =
            resolve_initial_jwks(&agent, None, None, Some(bad.to_string_lossy().to_string()), None, None).unwrap_err();
        assert!(err.contains("invalid jwks json"), "got {err}");
    }

    #[test]
    #[serial_test::serial]
    fn jwt_jwks_rejects_a_disallowed_algorithm_before_verifying() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::remove_var("CORECRUXD_JWT_ISS");
        std::env::remove_var("CORECRUXD_JWT_AUD");
        std::env::remove_var("CORECRUXD_JWT_ALGS");
        std::env::set_var("CORECRUXD_JWT_JWKS_JSON", TEST_JWKS_JSON);
        std::env::remove_var("CORECRUXD_JWT_JWKS_URL");
        std::env::remove_var("CORECRUXD_JWT_OIDC_DISCOVERY_URL");
        let auth = Authz::from_env(AuthMode::JwtJwks).expect("auth from env");

        // Alg-confusion attempt: sign with HS256 using the public modulus as a
        // shared secret. Only RS256 is configured, so it must never verify.
        let token = sign_hs256(
            &serde_json::json!({ "exp": now_secs() + 3600, "scope": "admin:write" }),
            "an-attacker-chosen-hs256-secret!!",
        );
        let err = require_http_scopes(&auth, &bearer(&token), &["admin:write"]).unwrap_err();
        assert_eq!(err.0.status, 401);
        assert_eq!(problem_code(&err), "UNAUTHENTICATED");

        std::env::remove_var("CORECRUXD_JWT_JWKS_JSON");
    }

    #[test]
    #[serial_test::serial]
    fn jwt_jwks_missing_and_malformed_credentials_are_401() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::remove_var("CORECRUXD_JWT_ISS");
        std::env::remove_var("CORECRUXD_JWT_AUD");
        std::env::remove_var("CORECRUXD_JWT_ALGS");
        std::env::set_var("CORECRUXD_JWT_JWKS_JSON", TEST_JWKS_JSON);
        std::env::remove_var("CORECRUXD_JWT_JWKS_URL");
        std::env::remove_var("CORECRUXD_JWT_OIDC_DISCOVERY_URL");
        let auth = Authz::from_env(AuthMode::JwtJwks).expect("auth from env");

        assert_eq!(
            require_http_scopes(&auth, &HeaderMap::new(), &["admin:read"])
                .unwrap_err()
                .0
                .status,
            401
        );
        assert_eq!(
            require_http_scopes(&auth, &bearer("garbage"), &["admin:read"])
                .unwrap_err()
                .0
                .status,
            401
        );
        assert_eq!(
            describe_http_evidence(&auth, &HeaderMap::new()).unwrap_err().0.status,
            401
        );

        std::env::remove_var("CORECRUXD_JWT_JWKS_JSON");
    }

    #[test]
    #[serial_test::serial]
    fn jwt_jwks_unknown_kid_is_rejected() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-test");
        std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");
        std::env::remove_var("CORECRUXD_JWT_ALGS");
        std::env::set_var("CORECRUXD_JWT_JWKS_JSON", TEST_JWKS_JSON);
        std::env::remove_var("CORECRUXD_JWT_JWKS_URL");
        std::env::remove_var("CORECRUXD_JWT_OIDC_DISCOVERY_URL");
        let auth = Authz::from_env(AuthMode::JwtJwks).expect("auth from env");

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("attacker-kid".to_string());
        let token = encode(
            &header,
            &valid_claims(serde_json::json!({ "scope": "admin:write", "tenant_id": "t1" })),
            &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes()).expect("rsa key"),
        )
        .expect("jwt");

        let err = require_http_scopes(&auth, &bearer(&token), &["admin:write"]).unwrap_err();
        assert_eq!(err.0.status, 401);

        std::env::remove_var("CORECRUXD_JWT_JWKS_JSON");
    }

    #[test]
    #[serial_test::serial]
    fn jwt_jwks_expired_token_is_401() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-test");
        std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");
        std::env::remove_var("CORECRUXD_JWT_ALGS");
        std::env::set_var("CORECRUXD_JWT_JWKS_JSON", TEST_JWKS_JSON);
        std::env::remove_var("CORECRUXD_JWT_JWKS_URL");
        std::env::remove_var("CORECRUXD_JWT_OIDC_DISCOVERY_URL");
        let auth = Authz::from_env(AuthMode::JwtJwks).expect("auth from env");

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".to_string());
        let token = encode(
            &header,
            &serde_json::json!({
                "exp": now_secs() - 7200,
                "iss": "corecrux-test",
                "aud": "corecrux",
                "scope": "admin:write",
                "tenant_id": "t1",
            }),
            &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes()).expect("rsa key"),
        )
        .expect("jwt");

        assert_eq!(
            require_http_scopes(&auth, &bearer(&token), &["admin:write"])
                .unwrap_err()
                .0
                .status,
            401
        );

        std::env::remove_var("CORECRUXD_JWT_JWKS_JSON");
    }

    #[test]
    #[serial_test::serial]
    fn jwt_jwks_rejects_an_unsupported_alg_env() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::set_var("CORECRUXD_JWT_JWKS_JSON", TEST_JWKS_JSON);
        std::env::set_var("CORECRUXD_JWT_ALGS", "HS256");
        let err = Authz::from_env(AuthMode::JwtJwks).unwrap_err();
        assert!(err.contains("unsupported jwt alg HS256"), "got {err}");

        std::env::remove_var("CORECRUXD_JWT_ALGS");
        std::env::remove_var("CORECRUXD_JWT_JWKS_JSON");
    }

    #[test]
    #[serial_test::serial]
    fn jwt_jwks_rejects_invalid_inline_jwks() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::remove_var("CORECRUXD_JWT_ALGS");
        std::env::set_var("CORECRUXD_JWT_JWKS_JSON", "{\"keys\": []}");
        let err = Authz::from_env(AuthMode::JwtJwks).unwrap_err();
        assert!(err.contains("no usable sig keys"), "got {err}");

        std::env::remove_var("CORECRUXD_JWT_JWKS_JSON");
    }

    #[test]
    #[serial_test::serial]
    fn jwt_jwks_loads_from_a_path_and_verifies() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        let lock = env_lock();
        let _g = lock.lock().unwrap();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("jwks.json");
        std::fs::write(&path, TEST_JWKS_JSON).expect("write jwks");

        std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-test");
        std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");
        std::env::remove_var("CORECRUXD_JWT_ALGS");
        std::env::remove_var("CORECRUXD_JWT_JWKS_JSON");
        std::env::remove_var("CORECRUXD_JWKS_JSON");
        std::env::set_var("CORECRUXD_JWT_JWKS_PATH", &path);
        std::env::remove_var("CORECRUXD_JWT_JWKS_URL");
        std::env::remove_var("CORECRUXD_JWT_OIDC_DISCOVERY_URL");
        let auth = Authz::from_env(AuthMode::JwtJwks).expect("auth from env");

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-kid".to_string());
        let token = encode(
            &header,
            &valid_claims(serde_json::json!({ "scope": "admin:read", "tenant_id": "t1" })),
            &EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes()).expect("rsa key"),
        )
        .expect("jwt");
        require_http_scopes_for_tenant(&auth, &bearer(&token), &["admin:read"], "t1").expect("verified");

        std::env::remove_var("CORECRUXD_JWT_JWKS_PATH");
    }

    // ── TenantStampMode env plumbing ───────────────────────────────────────

    #[test]
    fn tenant_stamp_mode_as_str_is_stable() {
        assert_eq!(TenantStampMode::Off.as_str(), "off");
        assert_eq!(TenantStampMode::Shadow.as_str(), "shadow");
        assert_eq!(TenantStampMode::On.as_str(), "on");
    }

    #[test]
    #[serial_test::serial]
    fn tenant_stamp_mode_from_env_reads_the_real_env() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        std::env::remove_var("CORECRUXD_TENANT_WRITE_STAMP");
        assert_eq!(TenantStampMode::from_env(), TenantStampMode::Off);

        for (raw, want) in [
            ("1", TenantStampMode::On),
            ("TRUE", TenantStampMode::On),
            ("On", TenantStampMode::On),
            ("enforce", TenantStampMode::On),
            ("SHADOW", TenantStampMode::Shadow),
            ("audit", TenantStampMode::Shadow),
            ("0", TenantStampMode::Off),
            ("off", TenantStampMode::Off),
            ("banana", TenantStampMode::Off),
            ("", TenantStampMode::Off),
        ] {
            std::env::set_var("CORECRUXD_TENANT_WRITE_STAMP", raw);
            assert_eq!(TenantStampMode::from_env(), want, "raw {raw:?}");
        }

        std::env::remove_var("CORECRUXD_TENANT_WRITE_STAMP");
    }

    #[test]
    #[serial_test::serial]
    fn scope_context_write_and_read_tenant_follow_the_env_posture() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "facts:write", "tenant_id": "t1" })),
            TEST_HS256_SECRET,
        );

        std::env::remove_var("CORECRUXD_TENANT_WRITE_STAMP");
        let ctx = passport_bound_context(&auth, &bearer(&token)).expect("context");
        assert_eq!(ctx.resolve_write_tenant().unwrap(), None, "default posture is off");
        assert_eq!(ctx.resolve_read_tenant(), None);

        std::env::set_var("CORECRUXD_TENANT_WRITE_STAMP", "1");
        assert_eq!(ctx.resolve_write_tenant().unwrap(), Some("t1".to_string()));
        assert_eq!(ctx.resolve_read_tenant(), Some("t1".to_string()));

        // A selector the token does not own is refused even under `On`.
        let mut headers = bearer(&token);
        headers.insert("x-corecrux-tenant-id", "t2".parse().unwrap());
        let ctx = passport_bound_context(&auth, &headers).expect("context");
        let err = ctx.resolve_write_tenant().unwrap_err();
        assert_eq!(err.0.status, 403);
        assert_eq!(problem_code(&err), "TENANT_FORBIDDEN");

        std::env::set_var("CORECRUXD_TENANT_WRITE_STAMP", "shadow");
        assert_eq!(
            ctx.resolve_write_tenant().unwrap(),
            None,
            "shadow must never reject or stamp"
        );

        std::env::remove_var("CORECRUXD_TENANT_WRITE_STAMP");
    }

    #[test]
    #[serial_test::serial]
    fn multi_tenant_token_needs_a_selector_when_stamping_is_on() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();

        let auth = hs256_authz();
        let token = sign_hs256(
            &valid_claims(serde_json::json!({ "scope": "facts:write", "tenants": ["t1", "t2"] })),
            TEST_HS256_SECRET,
        );
        std::env::set_var("CORECRUXD_TENANT_WRITE_STAMP", "on");

        let ctx = passport_bound_context(&auth, &bearer(&token)).expect("context");
        let err = ctx.resolve_write_tenant().unwrap_err();
        assert_eq!(problem_code(&err), "TENANT_SELECTOR_REQUIRED");
        // Multi-tenant tokens read `default`, in lockstep with the write side.
        assert_eq!(ctx.resolve_read_tenant(), None);

        let mut headers = bearer(&token);
        headers.insert("x-corecrux-tenant-id", "  t2  ".parse().unwrap());
        let ctx = passport_bound_context(&auth, &headers).expect("context");
        assert_eq!(ctx.resolve_write_tenant().unwrap(), Some("t2".to_string()));

        std::env::remove_var("CORECRUXD_TENANT_WRITE_STAMP");
    }

    #[test]
    fn resolve_write_tenant_on_ignores_a_blank_selector() {
        assert_eq!(
            resolve_write_tenant_on(&only(&["t1"]), Some("   ")).unwrap(),
            Some("t1".to_string())
        );
        assert_eq!(resolve_write_tenant_on(&TenantAllow::Any, Some("")).unwrap(), None);
    }
}
