// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Outbound HTTP dispatch for community-extension Phase A (M4 of the
//! community-extensions ExecPlan).
//!
//! Given a calling passport, an installed extension whose
//! `entry.kind == ExternalTool`, and a tool name + args object, this
//! module:
//!
//! 1. Confirms the manifest entry is `ExternalTool` and has an endpoint.
//! 2. Requires HTTPS unless the daemon's development-only plain-HTTP flag is set.
//! 3. Enforces `network.allowed_hosts` against the endpoint host and optional port.
//! 4. Confirms the tool name is in the manifest's `tools[]` list.
//! 5. Looks up the per-passport `ExtensionGrant` (see [`super::extension_grants`])
//!    from the fact store and verifies the calling passport is allowed
//!    to call this tool.
//! 6. Enforces the grant's `allowed_tool_names`.
//! 7. Tightens the daemon-wide timeout and response cap with non-zero
//!    manifest safety values, then enforces the configured/grant rate limit.
//! 8. Enforces the request cap, POSTs a JSON envelope
//!    `{ tool, args, calling_passport_id, request_id }`, and enforces the
//!    response cap.
//! 9. Validates the response shape and any `fact_writes[]` against the
//!    grant's `allowed_prefixes_write`. Out-of-scope writes are dropped
//!    + warning-logged; the caller still gets the `result` payload.
//!
//! ## Why a transport trait
//!
//! The transport is wrapped behind [`OutboundTransport`] so unit tests
//! can inject canned responses without spinning up a real HTTP server.
//! Production binds to [`UreqTransport`], matching the in-tree
//! `cuecrux_session` pattern that already uses ureq via spawn_blocking.

use crux_integrations::{
    append_audit_event, ExternalToolDefinition, IntegrationAuditEvent, IntegrationManifest, AUDIT_EXTENSION_INVOKE_OK,
    AUDIT_EXTENSION_INVOKE_REJECTED, AUDIT_SUPPRESSED,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DEFAULT_TIMEOUT_SECONDS: u64 = 5;
const DEFAULT_MAX_REQUEST_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 256 * 1024;
const DEFAULT_RATE_PER_MIN: u32 = 10;
const AUDIT_INVOKE_RATE_PER_MIN: u32 = 60;

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
    #[error("invalid external tool endpoint '{0}'")]
    InvalidEndpoint(String),
    #[error("endpoint '{1}' is not allowed by extension '{0}' network.allowed_hosts")]
    EndpointNotAllowed(String, String),
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
    audit_inner: Mutex<HashMap<String, InvokeAuditWindow>>,
}

#[derive(Debug)]
struct InvokeAuditWindow {
    started: Instant,
    appended: u32,
    suppressed: u64,
    marker_emitted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvokeAuditDecision {
    Append,
    AppendSuppressedMarker { count: u64 },
    Suppress,
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

    fn invoke_audit_decision(&self, extension_id: &str) -> InvokeAuditDecision {
        let mut guard = self.audit_inner.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        let entry = guard
            .entry(extension_id.to_string())
            .or_insert_with(|| InvokeAuditWindow {
                started: now,
                appended: 0,
                suppressed: 0,
                marker_emitted: false,
            });
        if now.duration_since(entry.started) >= Duration::from_secs(60) {
            *entry = InvokeAuditWindow {
                started: now,
                appended: 0,
                suppressed: 0,
                marker_emitted: false,
            };
        }
        if entry.appended < AUDIT_INVOKE_RATE_PER_MIN {
            entry.appended += 1;
            return InvokeAuditDecision::Append;
        }
        entry.suppressed = entry.suppressed.saturating_add(1);
        if entry.marker_emitted {
            InvokeAuditDecision::Suppress
        } else {
            entry.marker_emitted = true;
            InvokeAuditDecision::AppendSuppressedMarker {
                count: entry.suppressed,
            }
        }
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
    crate::fact_privacy::generic_create_reserved_entity_prefix(proposed_entity).is_none()
        && grant_prefixes_write
            .iter()
            .any(|prefix| proposed_entity.starts_with(prefix))
}

/// Parse an `allowed_hosts` entry into a host and optional port. Entries
/// are deliberately literal: wildcards, URL schemes, paths, and malformed
/// ports do not match.
fn parse_allowed_host_entry(entry: &str) -> Option<(&str, Option<u16>)> {
    let entry = entry.trim();
    if entry.is_empty() || entry.contains("://") || entry.contains(['/', '?', '#', '*']) {
        return None;
    }

    if let Some(bracketed) = entry.strip_prefix('[') {
        let closing = bracketed.find(']')?;
        let host = &bracketed[..closing];
        let remainder = &bracketed[closing + 1..];
        return if remainder.is_empty() {
            Some((host, None))
        } else {
            let port = remainder.strip_prefix(':')?.parse::<u16>().ok()?;
            Some((host, Some(port)))
        };
    }

    match entry.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && !host.is_empty() => Some((host, Some(port.parse::<u16>().ok()?))),
        Some(_) => None,
        None => Some((entry, None)),
    }
}

fn endpoint_allowed_by_network(endpoint: &url::Url, allowed_hosts: &[String]) -> bool {
    if allowed_hosts.is_empty() {
        return true;
    }
    let Some(endpoint_host) = endpoint.host_str() else {
        return false;
    };

    allowed_hosts.iter().any(|entry| {
        let Some((allowed_host, allowed_port)) = parse_allowed_host_entry(entry) else {
            return false;
        };
        if !endpoint_host.eq_ignore_ascii_case(allowed_host) {
            return false;
        }
        allowed_port.is_none() || endpoint.port_or_known_default() == allowed_port
    })
}

fn u64_to_usize_saturating(value: u64) -> usize {
    match usize::try_from(value) {
        Ok(value) => value,
        Err(_) => usize::MAX,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn dispatch_external_tool(
    transport: &dyn OutboundTransport,
    rate_table: &RateTable,
    config: &OutboundConfig,
    data_dir: &Path,
    manifest: &IntegrationManifest,
    grant: &crate::extension_grants::ExtensionGrant,
    tool_name: &str,
    args: &serde_json::Value,
    calling_passport_fpr: &str,
    request_id: &str,
    auth_secret_resolved: Option<String>,
) -> Result<(DispatchOutcome, ExternalToolResponse), OutboundError> {
    let result = dispatch_external_tool_inner(
        transport,
        rate_table,
        config,
        manifest,
        grant,
        tool_name,
        args,
        calling_passport_fpr,
        request_id,
        auth_secret_resolved,
    );
    audit_dispatch_result(data_dir, rate_table, manifest, tool_name, calling_passport_fpr, &result);
    result
}

#[allow(clippy::too_many_arguments)]
fn dispatch_external_tool_inner(
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
    let endpoint_url = url::Url::parse(endpoint).map_err(|_| OutboundError::InvalidEndpoint(endpoint.to_string()))?;
    let endpoint_host = endpoint_url
        .host_str()
        .ok_or_else(|| OutboundError::InvalidEndpoint(endpoint.to_string()))?;
    if !endpoint_allowed_by_network(&endpoint_url, &manifest.network.allowed_hosts) {
        let endpoint_authority = match endpoint_url.port() {
            Some(port) => format!("{endpoint_host}:{port}"),
            None => endpoint_host.to_string(),
        };
        return Err(OutboundError::EndpointNotAllowed(
            manifest.id.clone(),
            endpoint_authority,
        ));
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

    let effective_timeout = if manifest.safety.max_runtime_ms == 0 {
        config.timeout
    } else {
        config
            .timeout
            .min(Duration::from_millis(manifest.safety.max_runtime_ms))
    };
    let effective_max_response_bytes = if manifest.safety.max_output_bytes == 0 {
        config.max_response_bytes
    } else {
        config
            .max_response_bytes
            .min(u64_to_usize_saturating(manifest.safety.max_output_bytes))
    };

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
    let resp = transport.invoke(endpoint, auth_secret_resolved.as_deref(), body_json, effective_timeout)?;
    let elapsed_ms = started.elapsed().as_millis() as u64;

    if resp.body.len() > effective_max_response_bytes {
        return Err(OutboundError::ResponseTooLarge(
            resp.body.len(),
            effective_max_response_bytes,
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

fn audit_dispatch_result(
    data_dir: &Path,
    rate_table: &RateTable,
    manifest: &IntegrationManifest,
    tool_name: &str,
    calling_passport_fpr: &str,
    result: &Result<(DispatchOutcome, ExternalToolResponse), OutboundError>,
) {
    let now_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis() as u64);
    let event = match rate_table.invoke_audit_decision(&manifest.id) {
        InvokeAuditDecision::Append => match result {
            Ok(_) => IntegrationAuditEvent::extension(
                now_unix_ms,
                AUDIT_EXTENSION_INVOKE_OK,
                Some(calling_passport_fpr),
                &manifest.id,
                Some(&manifest.version),
                "ok",
                serde_json::json!({ "tool_name": tool_name }),
            ),
            Err(error) => IntegrationAuditEvent::extension(
                now_unix_ms,
                AUDIT_EXTENSION_INVOKE_REJECTED,
                Some(calling_passport_fpr),
                &manifest.id,
                Some(&manifest.version),
                "rejected",
                serde_json::json!({
                    "tool_name": tool_name,
                    "reason": error.audit_reason(),
                }),
            ),
        },
        InvokeAuditDecision::AppendSuppressedMarker { count } => IntegrationAuditEvent::extension(
            now_unix_ms,
            AUDIT_SUPPRESSED,
            Some(calling_passport_fpr),
            &manifest.id,
            Some(&manifest.version),
            "suppressed",
            serde_json::json!({
                "event_family": "extension_invoke",
                "count": count,
                "limit_per_min": AUDIT_INVOKE_RATE_PER_MIN,
            }),
        ),
        InvokeAuditDecision::Suppress => return,
    };
    append_audit_event(data_dir, &event);
}

impl OutboundError {
    fn audit_reason(&self) -> &'static str {
        match self {
            Self::NotExternalTool(_) => "not_external_tool",
            Self::ToolNotInManifest(_, _) => "tool_not_in_manifest",
            Self::NoGrant(_, _) => "no_grant",
            Self::ToolNotInGrant(_, _, _) => "tool_not_in_grant",
            Self::RateLimited(_, _, _) => "rate_limited",
            Self::RequestTooLarge(_, _) => "request_too_large",
            Self::ResponseTooLarge(_, _) => "response_too_large",
            Self::PlainHttpBlocked => "plain_http_blocked",
            Self::InvalidEndpoint(_) => "invalid_endpoint",
            Self::EndpointNotAllowed(_, _) => "endpoint_not_allowed",
            Self::Transport(_) => "transport",
            Self::UpstreamError { .. } => "upstream_error",
            Self::MalformedResponse(_) => "malformed_response",
            Self::Json(_) => "json",
        }
    }
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
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    fn audit_dir() -> &'static Path {
        static AUDIT_DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        AUDIT_DIR.get_or_init(|| tempfile::tempdir().expect("tempdir")).path()
    }

    /// Configurable canned-response transport.
    struct MockTransport {
        canned: Arc<Mutex<Vec<TransportResponse>>>,
        seen: Arc<Mutex<Vec<(String, Option<String>, String, Duration)>>>,
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
                .push((url.to_string(), bearer.map(str::to_string), body_json, _timeout));
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
            audit_dir(),
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
    fn allowed_hosts_mismatch_rejected() {
        let transport = MockTransport::new(vec![happy_response()]);
        let seen = transport.seen.clone();
        let mut m = manifest("ext.example.quote");
        m.network.allowed_hosts = vec!["other.example.com".to_string()];

        let err = dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &OutboundConfig::default(),
            audit_dir(),
            &m,
            &grant("ext.example.quote", "p_alice"),
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-host-mismatch",
            None,
        )
        .expect_err("host mismatch must reject");

        assert!(matches!(err, OutboundError::EndpointNotAllowed(_, _)));
        assert!(seen.lock().unwrap().is_empty());
    }

    #[test]
    fn allowed_hosts_exact_case_insensitive_match_passes() {
        let transport = MockTransport::new(vec![happy_response()]);
        let mut m = manifest("ext.example.quote");
        m.network.allowed_hosts = vec!["QUOTE.EXAMPLE.COM".to_string()];

        dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &OutboundConfig::default(),
            audit_dir(),
            &m,
            &grant("ext.example.quote", "p_alice"),
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-host-match",
            None,
        )
        .expect("case-insensitive exact host match");
    }

    #[test]
    fn allowed_hosts_port_mismatch_rejected() {
        let transport = MockTransport::new(vec![happy_response()]);
        let seen = transport.seen.clone();
        let mut m = manifest("ext.example.quote");
        m.external_tool_endpoint = Some("https://quote.example.com:8443/invoke".to_string());
        m.network.allowed_hosts = vec!["quote.example.com:443".to_string()];

        let err = dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &OutboundConfig::default(),
            audit_dir(),
            &m,
            &grant("ext.example.quote", "p_alice"),
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-port-mismatch",
            None,
        )
        .expect_err("port mismatch must reject");

        assert!(matches!(err, OutboundError::EndpointNotAllowed(_, _)));
        assert!(seen.lock().unwrap().is_empty());
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
            audit_dir(),
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
    fn forged_broad_grant_cannot_write_daemon_control_state() {
        let broad = vec!["__".to_string()];
        assert!(!write_allowed_by_grant(&broad, "__passport__::victim"));
        assert!(!write_allowed_by_grant(&broad, "__work__::project::item"));
        assert!(write_allowed_by_grant(
            &["personal::".to_string()],
            "personal::quotes::today"
        ));
    }

    #[test]
    fn rejects_when_tool_not_in_manifest() {
        let transport = MockTransport::new(vec![happy_response()]);
        let err = dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &OutboundConfig::default(),
            audit_dir(),
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
            audit_dir(),
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
            audit_dir(),
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
                audit_dir(),
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
            audit_dir(),
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
            audit_dir(),
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
            audit_dir(),
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
            audit_dir(),
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
            audit_dir(),
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
            audit_dir(),
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
    fn safety_tightens_timeout() {
        let transport = MockTransport::new(vec![happy_response()]);
        let seen = transport.seen.clone();
        let cfg = OutboundConfig {
            timeout: Duration::from_secs(5),
            ..OutboundConfig::default()
        };
        let mut m = manifest("ext.example.quote");
        m.safety.max_runtime_ms = 125;

        dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &cfg,
            audit_dir(),
            &m,
            &grant("ext.example.quote", "p_alice"),
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-safety-timeout",
            None,
        )
        .expect("dispatch");

        assert_eq!(seen.lock().unwrap()[0].3, Duration::from_millis(125));
    }

    #[test]
    fn safety_tightens_response_limit() {
        let transport = MockTransport::new(vec![TransportResponse {
            status: 200,
            body: "{}".to_string(),
        }]);
        let cfg = OutboundConfig {
            max_response_bytes: 100,
            ..OutboundConfig::default()
        };
        let mut m = manifest("ext.example.quote");
        m.safety.max_output_bytes = 1;

        let err = dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &cfg,
            audit_dir(),
            &m,
            &grant("ext.example.quote", "p_alice"),
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-safety-response",
            None,
        )
        .expect_err("manifest output cap must tighten env cap");

        assert!(matches!(err, OutboundError::ResponseTooLarge(2, 1)));
    }

    #[test]
    fn safety_cannot_raise_env_limits() {
        let transport = MockTransport::new(vec![TransportResponse {
            status: 200,
            body: "{}".to_string(),
        }]);
        let seen = transport.seen.clone();
        let cfg = OutboundConfig {
            timeout: Duration::from_millis(250),
            max_response_bytes: 1,
            ..OutboundConfig::default()
        };
        let mut m = manifest("ext.example.quote");
        m.safety.max_runtime_ms = 5_000;
        m.safety.max_output_bytes = 100;

        let err = dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &cfg,
            audit_dir(),
            &m,
            &grant("ext.example.quote", "p_alice"),
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-safety-cannot-raise",
            None,
        )
        .expect_err("manifest safety must not raise env limits");

        assert!(matches!(err, OutboundError::ResponseTooLarge(2, 1)));
        assert_eq!(seen.lock().unwrap()[0].3, Duration::from_millis(250));
    }

    #[test]
    fn zero_safety_fields_leave_env_limits_unchanged() {
        let response = happy_response();
        let response_len = response.body.len();
        let transport = MockTransport::new(vec![response]);
        let seen = transport.seen.clone();
        let cfg = OutboundConfig {
            timeout: Duration::from_millis(750),
            max_response_bytes: response_len,
            ..OutboundConfig::default()
        };
        let m = manifest("ext.example.quote");

        dispatch_external_tool(
            &transport,
            &RateTable::new(),
            &cfg,
            audit_dir(),
            &m,
            &grant("ext.example.quote", "p_alice"),
            "quote.daily",
            &serde_json::json!({}),
            "p_alice",
            "req-safety-zero",
            None,
        )
        .expect("zero safety fields retain env limits");

        assert_eq!(seen.lock().unwrap()[0].3, Duration::from_millis(750));
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
            audit_dir(),
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

    #[test]
    fn invoke_ok_and_rejected_emit_sanitized_audit_events() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rates = RateTable::new();
        let transport = MockTransport::new(vec![happy_response()]);
        let manifest = manifest("ext.example.audit");
        let grant = grant("ext.example.audit", "p_alice");

        dispatch_external_tool(
            &transport,
            &rates,
            &OutboundConfig::default(),
            dir.path(),
            &manifest,
            &grant,
            "quote.daily",
            &serde_json::json!({"secret": "must-not-be-audited"}),
            "p_alice",
            "req-audit-ok",
            Some("bearer-must-not-be-audited".to_string()),
        )
        .expect("ok");
        let rejected = dispatch_external_tool(
            &transport,
            &rates,
            &OutboundConfig::default(),
            dir.path(),
            &manifest,
            &grant,
            "quote.undeclared",
            &serde_json::json!({"secret": "also-not-audited"}),
            "p_alice",
            "req-audit-rejected",
            None,
        )
        .expect_err("rejected");
        assert!(matches!(rejected, OutboundError::ToolNotInManifest(_, _)));

        let audit = crux_integrations::read_audit_tail(dir.path(), 50).expect("audit");
        assert_eq!(audit.len(), 2);
        assert_eq!(audit[0].action, AUDIT_EXTENSION_INVOKE_OK);
        assert_eq!(audit[1].action, AUDIT_EXTENSION_INVOKE_REJECTED);
        assert_eq!(
            audit[1].detail.as_ref().and_then(|detail| detail.get("reason")),
            Some(&serde_json::json!("tool_not_in_manifest"))
        );
        let serialized = serde_json::to_string(&audit).expect("serialize");
        assert!(!serialized.contains("must-not-be-audited"));
        assert!(!serialized.contains("bearer-must-not-be-audited"));
    }

    #[test]
    fn invoke_audit_caps_at_sixty_and_emits_one_suppression_marker() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rates = RateTable::new();
        let transport = MockTransport::new(Vec::new());
        let mut manifest = manifest("ext.example.audit-storm");
        manifest.external_tool_endpoint = Some("http://quote.example.com/invoke".to_string());
        let grant = grant("ext.example.audit-storm", "p_alice");

        for index in 0..62 {
            let error = dispatch_external_tool(
                &transport,
                &rates,
                &OutboundConfig::default(),
                dir.path(),
                &manifest,
                &grant,
                "quote.daily",
                &serde_json::json!({}),
                "p_alice",
                &format!("req-storm-{index}"),
                None,
            )
            .expect_err("plain HTTP rejected");
            assert!(matches!(error, OutboundError::PlainHttpBlocked));
        }

        let audit = crux_integrations::read_audit_tail(dir.path(), 100).expect("audit");
        assert_eq!(audit.len(), 61);
        assert_eq!(
            audit
                .iter()
                .filter(|event| event.action == AUDIT_EXTENSION_INVOKE_REJECTED)
                .count(),
            60
        );
        let markers: Vec<&IntegrationAuditEvent> =
            audit.iter().filter(|event| event.action == AUDIT_SUPPRESSED).collect();
        assert_eq!(markers.len(), 1);
        assert_eq!(
            markers[0].detail.as_ref().and_then(|detail| detail.get("count")),
            Some(&serde_json::json!(1))
        );
    }
}
