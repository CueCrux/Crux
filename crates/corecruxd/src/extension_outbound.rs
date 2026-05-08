// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Outbound HTTP dispatch for community-extension Phase A (M4 of the
//! community-extensions ExecPlan).
//!
//! Given a calling passport, an installed extension whose
//! `entry.kind == ExternalTool`, and a tool name + args object, this
//! module:
//!
//! 1. Confirms the tool name is in the manifest's `tools[]` list.
//! 2. Looks up the per-passport `ExtensionGrant` (see [`super::extension_grants`])
//!    from the fact store and verifies the calling passport is allowed
//!    to call this tool.
//! 3. Enforces the daemon-wide payload + rate limits + the per-grant
//!    rate-limit override.
//! 4. POSTs a JSON envelope `{ tool, args, calling_passport_id, request_id }`
//!    to the manifest's `external_tool_endpoint`.
//! 5. Validates the response shape and any `fact_writes[]` against the
//!    grant's `allowed_prefixes_write`. Out-of-scope writes are dropped
//!    + warning-logged; the caller still gets the `result` payload.
//!
//! ## Why a transport trait
//!
//! The transport is wrapped behind [`OutboundTransport`] so unit tests
//! can inject canned responses without spinning up a real HTTP server.
//! Production binds to [`UreqTransport`], matching the in-tree
//! `cuecrux_session` pattern that already uses ureq via spawn_blocking.

use crux_integrations::{ExternalToolDefinition, IntegrationManifest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT_SECONDS: u64 = 5;
const DEFAULT_MAX_REQUEST_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 256 * 1024;
const DEFAULT_RATE_PER_MIN: u32 = 10;

#[derive(Debug, thiserror::Error)]
pub enum OutboundError {
    #[error("extension '{0}' is not configured for external_tool dispatch")]
    NotExternalTool(String),
    #[error("tool '{1}' not declared by extension '{0}'")]
    ToolNotInManifest(String, String),
    #[error("calling passport '{0}' has no grant for extension '{1}'")]
    NoGrant(String, String),
    #[error("calling passport '{0}' grant for extension '{1}' does not include tool '{2}'")]
    ToolNotInGrant(String, String, String),
    #[error("rate limit exceeded for extension '{0}' + passport '{1}' ({2} calls/min cap)")]
    RateLimited(String, String, u32),
    #[error("request payload too large: {0} bytes (max {1})")]
    RequestTooLarge(usize, usize),
    #[error("response payload too large: {0} bytes (max {1})")]
    ResponseTooLarge(usize, usize),
    #[error("plain http endpoint blocked (set CORECRUXD_EXTENSIONS_ALLOW_PLAIN_HTTP=true for dev)")]
    PlainHttpBlocked,
    #[error("transport: {0}")]
    Transport(String),
    #[error("upstream returned {status}: {body}")]
    UpstreamError { status: u16, body: String },
    #[error("upstream returned malformed response: {0}")]
    MalformedResponse(String),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Trait the outbound HTTP call hides behind. Production: [`UreqTransport`].
/// Tests: a mock that returns canned responses.
pub trait OutboundTransport: Send + Sync {
    fn invoke(
        &self,
        url: &str,
        bearer: Option<&str>,
        body_json: String,
        timeout: Duration,
    ) -> Result<TransportResponse, OutboundError>;
}

#[derive(Debug, Clone)]
pub struct TransportResponse {
    pub status: u16,
    pub body: String,
}

/// Daemon-wide outbound config. All knobs are env-overridable from the
/// HTTP layer; constants above are the defaults.
#[derive(Debug, Clone)]
pub struct OutboundConfig {
    pub timeout: Duration,
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub default_rate_per_min: u32,
    pub allow_plain_http: bool,
}

impl Default for OutboundConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECONDS),
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            default_rate_per_min: DEFAULT_RATE_PER_MIN,
            allow_plain_http: false,
        }
    }
}

impl OutboundConfig {
    /// Build from process env. Mirrors the pattern used by `fact_privacy`
    /// + `extension_registry` so operator overrides are colocated.
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(s) = std::env::var("CORECRUXD_EXTENSIONS_TIMEOUT_SECONDS") {
            if let Ok(n) = s.parse::<u64>() {
                cfg.timeout = Duration::from_secs(n);
            }
        }
        if let Ok(s) = std::env::var("CORECRUXD_EXTENSIONS_MAX_REQUEST_BYTES") {
            if let Ok(n) = s.parse::<usize>() {
                cfg.max_request_bytes = n;
            }
        }
        if let Ok(s) = std::env::var("CORECRUXD_EXTENSIONS_MAX_RESPONSE_BYTES") {
            if let Ok(n) = s.parse::<usize>() {
                cfg.max_response_bytes = n;
            }
        }
        if let Ok(s) = std::env::var("CORECRUXD_EXTENSIONS_DEFAULT_RATE_PER_MIN") {
            if let Ok(n) = s.parse::<u32>() {
                cfg.default_rate_per_min = n;
            }
        }
        if let Ok(s) = std::env::var("CORECRUXD_EXTENSIONS_ALLOW_PLAIN_HTTP") {
            cfg.allow_plain_http = matches!(s.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }
        cfg
    }
}

/// Sliding-window rate limiter keyed by (extension_id, passport_fpr).
/// Each entry holds call timestamps within the last 60s; stale entries
/// are pruned on access. Cheap for the expected scale (≤10s of calls
/// per (ext, passport) per minute).
#[derive(Debug, Default)]
pub struct RateTable {
    inner: Mutex<HashMap<(String, String), Vec<Instant>>>,
}

impl RateTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a call attempt. Returns Ok if within the window cap, Err
    /// otherwise. The cap is per-grant unless the grant doesn't override
    /// (then the daemon default applies).
    pub fn check_and_record(
        &self,
        extension_id: &str,
        passport_fpr: &str,
        cap_per_min: u32,
    ) -> Result<(), OutboundError> {
        let key = (extension_id.to_string(), passport_fpr.to_string());
        // Mutex poisoning would only happen if a previous holder panicked.
        // We tolerate it: extract the inner table even when poisoned and
        // continue — rate limiting is best-effort, not security-critical.
        let mut guard = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let entries = guard.entry(key.clone()).or_default();
        entries.retain(|t| now.duration_since(*t) < window);
        if entries.len() as u32 >= cap_per_min {
            return Err(OutboundError::RateLimited(
                extension_id.to_string(),
                passport_fpr.to_string(),
                cap_per_min,
            ));
        }
        entries.push(now);
        Ok(())
    }
}

/// Wire payload sent to the extension endpoint.
#[derive(Debug, Serialize)]
pub struct ExternalToolRequest<'a> {
    pub tool: &'a str,
    pub args: &'a serde_json::Value,
    pub calling_passport_id: &'a str,
    pub request_id: &'a str,
}

/// Expected response shape from the extension endpoint. `fact_writes`
/// are validated against the grant before being persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalToolResponse {
    pub result: serde_json::Value,
    #[serde(default)]
    pub fact_writes: Vec<ProposedFactWrite>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedFactWrite {
    pub entity: String,
    pub key: String,
    pub value: String,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
}

fn default_confidence() -> f32 {
    1.0
}

/// What the dispatcher returns to the operator (or the MCP layer in M5).
/// `accepted_fact_writes` count is exposed in CROWN receipts and the
/// audit tail.
#[derive(Debug, Clone, Serialize)]
pub struct DispatchOutcome {
    pub result: serde_json::Value,
    pub accepted_fact_writes: usize,
    pub dropped_fact_writes: usize,
    /// Drop reasons by index in the original `fact_writes[]` array.
    pub drop_reasons: Vec<String>,
    pub upstream_status: u16,
    pub elapsed_ms: u64,
    pub request_id: String,
}

/// Resolve which tool the manifest declares (or error if missing).
fn find_tool<'a>(
    manifest: &'a IntegrationManifest,
    tool_name: &str,
) -> Result<&'a ExternalToolDefinition, OutboundError> {
    manifest
        .tools
        .iter()
        .find(|t| t.name == tool_name)
        .ok_or_else(|| OutboundError::ToolNotInManifest(manifest.id.clone(), tool_name.to_string()))
}

/// Test whether the proposed write's entity-prefix is on the grant's
/// allowlist. Per the privacy-gate rules in `extension_grants`, we already
/// reject privacy-gated prefixes at grant-issue time; this is a final
/// per-call belt-and-braces check.
fn write_allowed_by_grant(grant_prefixes_write: &[String], proposed_entity: &str) -> bool {
    grant_prefixes_write
        .iter()
        .any(|prefix| proposed_entity.starts_with(prefix))
}

#[allow(clippy::too_many_arguments)]
pub fn dispatch_external_tool(
    transport: &dyn OutboundTransport,
    rate_table: &RateTable,
    config: &OutboundConfig,
    manifest: &IntegrationManifest,
    grant: &crate::extension_grants::ExtensionGrant,
    tool_name: &str,
    args: &serde_json::Value,
    calling_passport_fpr: &str,
    request_id: &str,
    auth_secret_resolved: Option<String>,
) -> Result<(DispatchOutcome, ExternalToolResponse), OutboundError> {
    use crux_integrations::EntryKind;

    if manifest.entry.kind != EntryKind::ExternalTool {
        return Err(OutboundError::NotExternalTool(manifest.id.clone()));
    }
    let endpoint = manifest
        .external_tool_endpoint
        .as_deref()
        .ok_or_else(|| OutboundError::NotExternalTool(manifest.id.clone()))?;

    if !endpoint.starts_with("https://") && (!endpoint.starts_with("http://") || !config.allow_plain_http) {
        return Err(OutboundError::PlainHttpBlocked);
    }

    let _ = find_tool(manifest, tool_name)?;

    if grant.extension_id != manifest.id || grant.passport_fpr != calling_passport_fpr {
        return Err(OutboundError::NoGrant(
            calling_passport_fpr.to_string(),
            manifest.id.clone(),
        ));
    }
    // Empty allowed_tool_names => grant covers every tool the manifest declares.
    if !grant.allowed_tool_names.is_empty() && !grant.allowed_tool_names.iter().any(|t| t == tool_name) {
        return Err(OutboundError::ToolNotInGrant(
            calling_passport_fpr.to_string(),
            manifest.id.clone(),
            tool_name.to_string(),
        ));
    }

    let cap = grant.rate_limit_per_min.unwrap_or(config.default_rate_per_min);
    rate_table.check_and_record(&manifest.id, calling_passport_fpr, cap)?;

    let request = ExternalToolRequest {
        tool: tool_name,
        args,
        calling_passport_id: calling_passport_fpr,
        request_id,
    };
    let body_json = serde_json::to_string(&request)?;
    if body_json.len() > config.max_request_bytes {
        return Err(OutboundError::RequestTooLarge(
            body_json.len(),
            config.max_request_bytes,
        ));
    }

    let started = Instant::now();
    let resp = transport.invoke(endpoint, auth_secret_resolved.as_deref(), body_json, config.timeout)?;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    if resp.body.len() > config.max_response_bytes {
        return Err(OutboundError::ResponseTooLarge(
            resp.body.len(),
            config.max_response_bytes,
        ));
    }
    if !(200..=299).contains(&resp.status) {
        return Err(OutboundError::UpstreamError {
            status: resp.status,
            body: resp.body.chars().take(512).collect(),
        });
    }

    let parsed: ExternalToolResponse =
        serde_json::from_str(&resp.body).map_err(|e| OutboundError::MalformedResponse(e.to_string()))?;

    // Drop any fact_writes that violate the grant's write scope. We
    // record drop reasons in the outcome so the operator can debug
    // misconfigured extensions; we do NOT bubble the drops as errors —
    // the caller still gets a useful `result`.
    let mut drop_reasons: Vec<String> = Vec::new();
    let mut accepted = 0usize;
    for (idx, w) in parsed.fact_writes.iter().enumerate() {
        if write_allowed_by_grant(&grant.allowed_prefixes_write, &w.entity) {
            accepted += 1;
        } else {
            drop_reasons.push(format!(
                "fact_writes[{idx}] entity '{}' not covered by grant.allowed_prefixes_write",
                w.entity
            ));
        }
    }
    let outcome = DispatchOutcome {
        result: parsed.result.clone(),
        accepted_fact_writes: accepted,
        dropped_fact_writes: parsed.fact_writes.len() - accepted,
        drop_reasons,
        upstream_status: resp.status,
        elapsed_ms,
        request_id: request_id.to_string(),
    };
    Ok((outcome, parsed))
}

/// Production transport: ureq via spawn_blocking at the call site
/// (matches `cuecrux_session` pattern).
pub struct UreqTransport;

impl OutboundTransport for UreqTransport {
    fn invoke(
        &self,
        url: &str,
        bearer: Option<&str>,
        body_json: String,
        timeout: Duration,
    ) -> Result<TransportResponse, OutboundError> {
        use std::io::Read as _;
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .build()
            .into();
        let mut req = agent
            .post(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json");
        if let Some(token) = bearer {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        match req.send(body_json) {
            Ok(mut r) => {
                let status = r.status().as_u16();
                let mut buf = String::new();
                let _ = r.body_mut().as_reader().read_to_string(&mut buf);
                Ok(TransportResponse { status, body: buf })
            }
            Err(e) => Err(OutboundError::Transport(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extension_grants::ExtensionGrant;
    use crux_integrations::{
        DataAccess, EntryKind, ExternalToolDefinition, IntegrationEntry, ManifestHashes, NetworkAccess, SafetyPolicy,
        INTEGRATION_SCHEMA_V1,
    };
    use std::sync::{Arc, Mutex};

    /// Configurable canned-response transport.
    struct MockTransport {
        canned: Arc<Mutex<Vec<TransportResponse>>>,
        seen: Arc<Mutex<Vec<(String, Option<String>, String)>>>,
    }

    impl MockTransport {
        fn new(canned: Vec<TransportResponse>) -> Self {
            Self {
                canned: Arc::new(Mutex::new(canned)),
                seen: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl OutboundTransport for MockTransport {
        fn invoke(
            &self,
            url: &str,
            bearer: Option<&str>,
            body_json: String,
            _timeout: Duration,
        ) -> Result<TransportResponse, OutboundError> {
            self.seen
                .lock()
                .unwrap()
                .push((url.to_string(), bearer.map(str::to_string), body_json));
            self.canned
                .lock()
                .unwrap()
                .pop()
                .ok_or_else(|| OutboundError::Transport("no canned response".into()))
        }
    }

    fn manifest(id: &str) -> IntegrationManifest {
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: id.to_string(),
            name: "Quote".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: "p_test".to_string(),
            summary: "Returns quotes.".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::ExternalTool,
                path: "tools/quote.json".to_string(),
            },
            capabilities: vec!["facts:read".to_string()],
            network: NetworkAccess::default(),
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
            external_tool_endpoint: Some("https://quote.example.com/invoke".to_string()),
            tools: vec![ExternalToolDefinition {
                name: "quote.daily".to_string(),
                description: "Today's quote.".to_string(),
                input_schema: serde_json::json!({"type":"object"}),
                consequence_metadata: None,
                auth_shared_secret_id: None,
            }],
            wasm_module_path: None,
            wasm_module_url: None,
            wasm_module_sha256: None,
        }
    }

    fn grant(ext: &str, fpr: &str) -> ExtensionGrant {
        ExtensionGrant {
            extension_id: ext.to_string(),
            passport_fpr: fpr.to_string(),
            allowed_tool_names: vec![],
            allowed_prefixes_read: vec!["personal::quotes::".to_string()],
            allowed_prefixes_write: vec!["personal::quotes::".to_string()],
            rate_limit_per_min: Some(2),
            granted_at_unix_ms: 1,
            granted_by_passport: None,
        }
    }

    fn happy_response() -> TransportResponse {
        TransportResponse {
            status: 200,
            body: serde_json::to_string(&ExternalToolResponse {
                result: serde_json::json!({"quote":"Roses are red","author":"alice"}),
                fact_writes: vec![ProposedFactWrite {
                    entity: "personal::quotes::today".into(),
                    key: "content".into(),
                    value: "Roses are red".into(),
                    confidence: 1.0,
                }],
            })
            .unwrap(),
        }
    }

    #[test]
    fn happy_path_returns_result_and_accepts_in_scope_writes() {
        let transport = MockTransport::new(vec![happy_response()]);
        let rates = RateTable::new();
        let cfg = OutboundConfig::default();
        let m = manifest("ext.example.quote");
        let g = grant("ext.example.quote", "p_alice");
        let (outcome, parsed) = dispatch_external_tool(
            &transport,
            &rates,
            &cfg,
            &m,
            &g,
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-001",
            None,
        )
        .expect("dispatch");
        assert_eq!(outcome.upstream_status, 200);
        assert_eq!(outcome.accepted_fact_writes, 1);
        assert_eq!(outcome.dropped_fact_writes, 0);
        assert_eq!(parsed.fact_writes.len(), 1);
    }

    #[test]
    fn drops_out_of_scope_fact_writes() {
        let resp = TransportResponse {
            status: 200,
            body: serde_json::to_string(&ExternalToolResponse {
                result: serde_json::json!({}),
                fact_writes: vec![
                    ProposedFactWrite {
                        entity: "personal::quotes::ok".into(),
                        key: "k".into(),
                        value: "v".into(),
                        confidence: 1.0,
                    },
                    ProposedFactWrite {
                        entity: "__ax__::sneaky".into(),
                        key: "k".into(),
                        value: "v".into(),
                        confidence: 1.0,
                    },
                ],
            })
            .unwrap(),
        };
        let transport = MockTransport::new(vec![resp]);
        let rates = RateTable::new();
        let cfg = OutboundConfig::default();
        let (outcome, _) = dispatch_external_tool(
            &transport,
            &rates,
            &cfg,
            &manifest("ext.example.quote"),
            &grant("ext.example.quote", "p_alice"),
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-002",
            None,
        )
        .expect("dispatch");
        assert_eq!(outcome.accepted_fact_writes, 1);
        assert_eq!(outcome.dropped_fact_writes, 1);
        assert!(outcome.drop_reasons[0].contains("__ax__::"));
    }

    #[test]
    fn rejects_when_tool_not_in_manifest() {
        let transport = MockTransport::new(vec![happy_response()]);
        let err = dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &OutboundConfig::default(),
            &manifest("ext.example.quote"),
            &grant("ext.example.quote", "p_alice"),
            "quote.unknown",
            &serde_json::json!({}),
            "p_alice",
            "req-003",
            None,
        )
        .expect_err("must reject");
        assert!(matches!(err, OutboundError::ToolNotInManifest(_, _)));
    }

    #[test]
    fn rejects_when_grant_doesnt_match_passport() {
        let transport = MockTransport::new(vec![happy_response()]);
        let err = dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &OutboundConfig::default(),
            &manifest("ext.example.quote"),
            &grant("ext.example.quote", "p_alice"),
            "quote.daily",
            &serde_json::json!({}),
            "p_bob", // <-- mismatch
            "req-004",
            None,
        )
        .expect_err("must reject");
        assert!(matches!(err, OutboundError::NoGrant(_, _)));
    }

    #[test]
    fn rejects_when_grant_excludes_tool() {
        let transport = MockTransport::new(vec![happy_response()]);
        let mut g = grant("ext.example.quote", "p_alice");
        g.allowed_tool_names = vec!["quote.weekly".to_string()];
        let err = dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &OutboundConfig::default(),
            &manifest("ext.example.quote"),
            &g,
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-005",
            None,
        )
        .expect_err("must reject");
        assert!(matches!(err, OutboundError::ToolNotInGrant(_, _, _)));
    }

    #[test]
    fn rate_limit_caps_at_grant_value() {
        let mut canned = vec![happy_response(), happy_response(), happy_response()];
        canned.reverse(); // pop() returns last
        let transport = MockTransport::new(canned);
        let rates = RateTable::new();
        let cfg = OutboundConfig::default();
        let m = manifest("ext.example.quote");
        let g = grant("ext.example.quote", "p_alice"); // cap=2

        // Two calls should succeed, third should hit the cap.
        for i in 0..2 {
            dispatch_external_tool(
                &transport,
                &rates,
                &cfg,
                &m,
                &g,
                "quote.daily",
                &serde_json::json!({}),
                "p_alice",
                &format!("req-{i}"),
                None,
            )
            .expect("under cap");
        }
        let err = dispatch_external_tool(
            &transport,
            &rates,
            &cfg,
            &m,
            &g,
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-cap",
            None,
        )
        .expect_err("over cap");
        assert!(matches!(err, OutboundError::RateLimited(_, _, 2)));
    }

    #[test]
    fn plain_http_blocked_unless_dev_flag() {
        let transport = MockTransport::new(vec![happy_response()]);
        let mut m = manifest("ext.example.quote");
        m.external_tool_endpoint = Some("http://localhost:8081/invoke".to_string());
        let err = dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &OutboundConfig::default(),
            &m,
            &grant("ext.example.quote", "p_alice"),
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-006",
            None,
        )
        .expect_err("plain http blocked");
        assert!(matches!(err, OutboundError::PlainHttpBlocked));

        // With the dev flag on, plain http succeeds.
        let transport = MockTransport::new(vec![happy_response()]);
        let cfg = OutboundConfig {
            allow_plain_http: true,
            ..OutboundConfig::default()
        };
        dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &cfg,
            &m,
            &grant("ext.example.quote", "p_alice"),
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-007",
            None,
        )
        .expect("plain http allowed under dev flag");
    }

    #[test]
    fn upstream_5xx_bubbles_as_error() {
        let transport = MockTransport::new(vec![TransportResponse {
            status: 500,
            body: "{\"err\":\"boom\"}".into(),
        }]);
        let err = dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &OutboundConfig::default(),
            &manifest("ext.example.quote"),
            &grant("ext.example.quote", "p_alice"),
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-008",
            None,
        )
        .expect_err("5xx must error");
        assert!(matches!(err, OutboundError::UpstreamError { status: 500, .. }));
    }

    #[test]
    fn malformed_upstream_response_errors() {
        let transport = MockTransport::new(vec![TransportResponse {
            status: 200,
            body: "not json".into(),
        }]);
        let err = dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &OutboundConfig::default(),
            &manifest("ext.example.quote"),
            &grant("ext.example.quote", "p_alice"),
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-009",
            None,
        )
        .expect_err("malformed must error");
        assert!(matches!(err, OutboundError::MalformedResponse(_)));
    }

    #[test]
    fn response_too_large_rejected() {
        let big = "x".repeat(300_000);
        let transport = MockTransport::new(vec![TransportResponse { status: 200, body: big }]);
        let cfg = OutboundConfig {
            max_response_bytes: 100_000,
            ..OutboundConfig::default()
        };
        let err = dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &cfg,
            &manifest("ext.example.quote"),
            &grant("ext.example.quote", "p_alice"),
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-010",
            None,
        )
        .expect_err("oversize");
        assert!(matches!(err, OutboundError::ResponseTooLarge(_, _)));
    }

    #[test]
    fn forwards_bearer_when_secret_resolved() {
        let transport = MockTransport::new(vec![happy_response()]);
        // Capture the seen Authorization handle by holding the Arc.
        let seen = transport.seen.clone();
        dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &OutboundConfig::default(),
            &manifest("ext.example.quote"),
            &grant("ext.example.quote", "p_alice"),
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-011",
            Some("super-secret-token".to_string()),
        )
        .expect("ok");
        let captured = seen.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].1.as_deref(), Some("super-secret-token"));
    }
}
