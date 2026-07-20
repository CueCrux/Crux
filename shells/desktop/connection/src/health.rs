// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::collections::BTreeMap;
use std::io::Read;

use crate::json::{self, JsonValue};
use crate::{ForwardRequest, SecretToken, Upstream, UpstreamResponse};

const MAX_PROBE_BODY: u64 = 1_048_576;
const PROBE_REFLECTION_REASON: &str = "daemon probe reflected credential material";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    Ok,
    Degraded,
    Unreachable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCapabilitiesSummary {
    pub schema_version: u32,
    pub capability_count: usize,
    pub degraded: bool,
    pub degraded_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    pub state: HealthState,
    pub reason: Option<String>,
    pub runtime_capabilities: Option<RuntimeCapabilitiesSummary>,
    forwarding_allowed: bool,
}

impl HealthReport {
    fn ok(runtime_capabilities: Option<RuntimeCapabilitiesSummary>) -> Self {
        Self {
            state: HealthState::Ok,
            reason: None,
            runtime_capabilities,
            forwarding_allowed: true,
        }
    }

    fn degraded(reason: impl Into<String>, runtime_capabilities: Option<RuntimeCapabilitiesSummary>) -> Self {
        Self {
            state: HealthState::Degraded,
            reason: Some(reason.into()),
            runtime_capabilities,
            forwarding_allowed: true,
        }
    }

    fn blocked(reason: impl Into<String>) -> Self {
        Self {
            state: HealthState::Degraded,
            reason: Some(reason.into()),
            runtime_capabilities: None,
            forwarding_allowed: false,
        }
    }

    fn unreachable(reason: impl Into<String>) -> Self {
        Self {
            state: HealthState::Unreachable,
            reason: Some(reason.into()),
            runtime_capabilities: None,
            forwarding_allowed: false,
        }
    }

    /// Whether the probe result is safe to promote into credential-forwarding
    /// mode. Credential reflection and unreachable transports fail closed.
    pub const fn forwarding_allowed(&self) -> bool {
        self.forwarding_allowed
    }
}

/// Probe `/healthz`, then tolerate and summarize the schema-v1 descriptor at
/// `/v1/version`. The adapter is responsible for connection/TLS timeouts.
pub fn probe_health(upstream: &dyn Upstream, token: Option<&SecretToken>) -> HealthReport {
    let health = match execute_probe(upstream, "/healthz", token) {
        Ok(response) => response,
        Err(reason) => return HealthReport::unreachable(reason),
    };
    let health_status = health.status;
    let health_body = match read_probe_body(health, token) {
        Ok(body) => body,
        Err(reason) if reason == PROBE_REFLECTION_REASON => return HealthReport::blocked(reason),
        Err(reason) => return HealthReport::degraded(reason, None),
    };
    if !(200..300).contains(&health_status) {
        return HealthReport::degraded(format!("daemon health probe returned HTTP {health_status}"), None);
    }
    if let Ok(value) = std::str::from_utf8(&health_body)
        .map_err(|_| ())
        .and_then(|raw| json::parse(raw).map_err(|_| ()))
    {
        if value
            .as_object()
            .and_then(|object| object.get("ok"))
            .and_then(JsonValue::as_bool)
            == Some(false)
        {
            return HealthReport::degraded("daemon health response reports ok=false", None);
        }
    }

    let version = match execute_probe(upstream, "/v1/version", token) {
        Ok(response) => response,
        Err(reason) if reason == PROBE_REFLECTION_REASON => return HealthReport::blocked(reason),
        Err(reason) => return HealthReport::degraded(reason, None),
    };
    let version_status = version.status;
    let version_body = match read_probe_body(version, token) {
        Ok(body) => body,
        Err(reason) if reason == PROBE_REFLECTION_REASON => return HealthReport::blocked(reason),
        Err(reason) => return HealthReport::degraded(reason, None),
    };
    if !(200..300).contains(&version_status) {
        return HealthReport::degraded(format!("daemon version probe returned HTTP {version_status}"), None);
    }
    let raw = match std::str::from_utf8(&version_body) {
        Ok(raw) => raw,
        Err(_) => return HealthReport::degraded("daemon version response is not UTF-8", None),
    };
    let version_json = match json::parse(raw) {
        Ok(value) => value,
        Err(_) => return HealthReport::degraded("daemon version response is not valid JSON", None),
    };
    let (runtime, sync_reason) = match summarize_version(&version_json) {
        Ok(summary) => summary,
        Err(reason) => return HealthReport::degraded(reason, None),
    };
    if let Some(reason) = sync_reason {
        return HealthReport::degraded(reason, runtime);
    }
    if let Some(summary) = &runtime {
        if summary.degraded {
            let reason = summary
                .degraded_reasons
                .first()
                .cloned()
                .unwrap_or_else(|| "daemon runtime capabilities are degraded".to_string());
            return HealthReport::degraded(reason, runtime);
        }
    }
    HealthReport::ok(runtime)
}

fn execute_probe(upstream: &dyn Upstream, path: &str, token: Option<&SecretToken>) -> Result<UpstreamResponse, String> {
    let mut headers = vec![("accept".to_string(), b"application/json".to_vec())];
    if let Some(token) = token {
        let mut bearer = Vec::with_capacity(7 + token.expose_bytes().len());
        bearer.extend_from_slice(b"Bearer ");
        bearer.extend_from_slice(token.expose_bytes());
        headers.push(("authorization".to_string(), bearer));
    }
    upstream
        .execute(ForwardRequest {
            method: "GET".to_string(),
            url: path.to_string(),
            headers,
            body: Vec::new(),
        })
        .map_err(|error| error.reason().to_string())
}

fn read_probe_body(mut response: UpstreamResponse, token: Option<&SecretToken>) -> Result<Vec<u8>, String> {
    if token.is_some_and(|token| {
        response.headers.iter().any(|(name, value)| {
            contains_bytes(name.as_bytes(), token.expose_bytes()) || contains_bytes(value, token.expose_bytes())
        })
    }) {
        return Err(PROBE_REFLECTION_REASON.to_string());
    }
    let mut body = Vec::new();
    response
        .body
        .by_ref()
        .take(MAX_PROBE_BODY + 1)
        .read_to_end(&mut body)
        .map_err(|_| "could not read daemon probe response".to_string())?;
    if u64::try_from(body.len())
        .ok()
        .is_some_and(|length| length > MAX_PROBE_BODY)
    {
        return Err("daemon probe response exceeds the size limit".to_string());
    }
    if token.is_some_and(|token| contains_bytes(&body, token.expose_bytes())) {
        body.fill(0);
        return Err(PROBE_REFLECTION_REASON.to_string());
    }
    Ok(body)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
}

fn summarize_version(value: &JsonValue) -> Result<(Option<RuntimeCapabilitiesSummary>, Option<String>), String> {
    let root = value
        .as_object()
        .ok_or_else(|| "daemon version response must be a JSON object".to_string())?;
    let sync_reason = summarize_sync(root);
    let Some(product) = root.get("product").and_then(JsonValue::as_object) else {
        return Ok((None, sync_reason));
    };
    let Some(runtime) = product.get("runtime_capabilities") else {
        return Ok((None, sync_reason));
    };
    let runtime = runtime
        .as_object()
        .ok_or_else(|| "runtime_capabilities must be a JSON object".to_string())?;
    let schema = runtime
        .get("schema_version")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| "runtime_capabilities schema_version is missing".to_string())?;
    if schema != 1 {
        // Forward-compatible: health remains useful when a newer descriptor is
        // encountered. M2 controls can treat the absent summary as unknown.
        return Ok((None, sync_reason));
    }
    let capabilities = runtime
        .get("capabilities")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| "runtime_capabilities capabilities must be an object".to_string())?;
    let mut reasons = Vec::new();
    for capability in capabilities.values() {
        let Some(capability) = capability.as_object() else {
            continue;
        };
        let degraded = capability.get("degraded").and_then(JsonValue::as_bool) == Some(true)
            || capability.get("availability").and_then(JsonValue::as_str) == Some("degraded");
        if degraded {
            let reason = capability
                .get("reason")
                .and_then(JsonValue::as_str)
                .filter(|reason| !reason.is_empty())
                .unwrap_or("daemon runtime capability is degraded");
            reasons.push(reason.to_string());
        }
    }
    Ok((
        Some(RuntimeCapabilitiesSummary {
            schema_version: 1,
            capability_count: capabilities.len(),
            degraded: !reasons.is_empty(),
            degraded_reasons: reasons,
        }),
        sync_reason,
    ))
}

fn summarize_sync(root: &BTreeMap<String, JsonValue>) -> Option<String> {
    let sync = root.get("sync")?.as_object()?;
    if sync.get("degraded").and_then(JsonValue::as_bool) != Some(true) {
        return None;
    }
    Some(
        sync.get("degraded_reason")
            .and_then(JsonValue::as_str)
            .filter(|reason| !reason.is_empty())
            .unwrap_or("daemon sync is degraded")
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::sync::Mutex;

    use super::{probe_health, HealthState, PROBE_REFLECTION_REASON};
    use crate::{ForwardRequest, SecretToken, Upstream, UpstreamError, UpstreamResponse};

    const TOKEN: &[u8] = b"0123456789abcdef0123456789abcdef";

    struct Sequence {
        responses: Mutex<VecDeque<Result<UpstreamResponse, UpstreamError>>>,
    }

    impl Sequence {
        fn new(responses: Vec<Result<UpstreamResponse, UpstreamError>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
            }
        }
    }

    impl Upstream for Sequence {
        fn execute(&self, _request: ForwardRequest) -> Result<UpstreamResponse, UpstreamError> {
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(UpstreamError::sanitized("missing test response")))
        }
    }

    fn response(status: u16, body: &str) -> Result<UpstreamResponse, UpstreamError> {
        Ok(UpstreamResponse::new(
            status,
            Vec::new(),
            Cursor::new(body.as_bytes().to_vec()),
        ))
    }

    fn token() -> SecretToken {
        SecretToken::from_bytes(TOKEN.to_vec()).unwrap()
    }

    #[test]
    fn parses_schema_one_tolerantly_and_reports_degradation() {
        let source = Sequence::new(vec![
            response(200, r#"{"ok":true,"unknown":1}"#),
            response(
                200,
                r#"{"unknown":"kept","product":{"runtime_capabilities":{"schema_version":1,"unknown":true,"capabilities":{"append":{"availability":"available","degraded":false,"future":1},"hosted_sync":{"availability":"degraded","degraded":true,"reason":"sync is offline"}}}},"sync":{"degraded":false}}"#,
            ),
        ]);
        let report = probe_health(&source, None);
        assert_eq!(report.state, HealthState::Degraded);
        let summary = report.runtime_capabilities.unwrap();
        assert_eq!(summary.schema_version, 1);
        assert_eq!(summary.capability_count, 2);
        assert_eq!(summary.degraded_reasons, vec!["sync is offline"]);
    }

    #[test]
    fn absent_and_future_descriptors_preserve_ok_health() {
        for version in [
            r#"{"product":{},"future":true}"#,
            r#"{"product":{"runtime_capabilities":{"schema_version":2,"capabilities":{}}}}"#,
        ] {
            let source = Sequence::new(vec![response(200, r#"{"ok":true}"#), response(200, version)]);
            let report = probe_health(&source, None);
            assert_eq!(report.state, HealthState::Ok);
            assert!(report.runtime_capabilities.is_none());
        }
    }

    #[test]
    fn unreachable_and_bad_version_are_explicit() {
        let unreachable = Sequence::new(vec![Err(UpstreamError::sanitized("daemon is unreachable"))]);
        let report = probe_health(&unreachable, None);
        assert_eq!(report.state, HealthState::Unreachable);
        assert_eq!(report.reason.as_deref(), Some("daemon is unreachable"));

        let malformed = Sequence::new(vec![response(200, r#"{"ok":true}"#), response(200, "not-json")]);
        let report = probe_health(&malformed, None);
        assert_eq!(report.state, HealthState::Degraded);
        assert!(report.reason.unwrap().contains("valid JSON"));
    }

    #[test]
    fn reflected_probe_token_is_rejected_before_json_parsing() {
        let header_source = Sequence::new(vec![Ok(UpstreamResponse::new(
            200,
            vec![("x-reflected-secret".to_string(), TOKEN.to_vec())],
            Cursor::new(br#"{"ok":true}"#.to_vec()),
        ))]);
        let header_token = token();
        let report = probe_health(&header_source, Some(&header_token));
        assert_eq!(report.state, HealthState::Degraded);
        assert_eq!(report.reason.as_deref(), Some(PROBE_REFLECTION_REASON));
        assert!(!report.forwarding_allowed());

        let reflected_version = format!(
            "{{\"product\":{{}},\"reflected\":\"{}\"}}",
            std::str::from_utf8(TOKEN).unwrap()
        );
        let body_source = Sequence::new(vec![response(200, r#"{"ok":true}"#), response(200, &reflected_version)]);
        let body_token = token();
        let report = probe_health(&body_source, Some(&body_token));
        assert_eq!(report.state, HealthState::Degraded);
        assert_eq!(report.reason.as_deref(), Some(PROBE_REFLECTION_REASON));
        assert!(!report.forwarding_allowed());
    }
}
