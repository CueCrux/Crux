// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Local hardening helper tools for agent sessions.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};
use corecrux_memory::fact_store::{HorizonClass, StoreFact};

pub async fn handle_execplan_gate(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let slug = require_str(args, "slug")?;
    let milestone = require_str(args, "milestone")?;
    let status = require_str(args, "status")?;
    let commit_sha = require_str(args, "commit_sha")?;
    let token_budget = require_u64(args, "token_budget")?;
    if token_budget == 0 {
        return invalid("token_budget", "token_budget must be greater than zero");
    }
    if !matches!(status, "passed" | "failed" | "blocked" | "skipped") {
        return invalid("status", "status must be one of passed, failed, blocked, skipped");
    }

    let key = if milestone.starts_with("gate:") {
        milestone.to_string()
    } else {
        format!("gate:{milestone}")
    };
    let value = json!({
        "status": status,
        "date": chrono::Utc::now().date_naive().to_string(),
        "commit_sha": commit_sha,
        "tests_passing": args.get("tests_passing").cloned().unwrap_or(Value::Null),
        "artifacts": args.get("artifacts").cloned().unwrap_or_else(|| json!([])),
        "notes": args.get("notes").cloned().unwrap_or(Value::Null),
        "actor": ctx.scope_identity(),
        "token_budget": token_budget,
    });

    let mut store = ctx.fact_store.write().await;
    let fact = store
        .try_store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: format!("execplan:{slug}"),
            key: key.clone(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: Some(HorizonClass::Stable),
            actor: ctx.scope_identity(),
        })
        .map_err(|err| JsonRpcError {
            code: INTERNAL_ERROR,
            message: "fact journal append failed".to_string(),
            data: Some(json!({"error": err.to_string()})),
        })?;

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!("recorded {key} for execplan:{slug} at {commit_sha}")
        }],
        "structuredContent": {
            "fact_id": fact.fact_id,
            "entity": fact.entity,
            "key": fact.key,
            "commit_sha": commit_sha,
            "status": status
        }
    }))
}

#[allow(clippy::unused_async)]
pub async fn handle_route_access_matrix(_args: &Value, _ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let routes = json!([
        {
            "route": "PUT /v1/facts",
            "required_any_scope": ["facts:write", "admin:write"],
            "passport_binding": "JWT passport comes from verified claims; header accepted only in local/dev or explicit override",
            "tenant_binding": null,
            "notes": "Reserved-prefix facts are forced private before storage"
        },
        {
            "route": "PUT /v1/facts/bulk",
            "required_any_scope": ["facts:write", "admin:write"],
            "passport_binding": "same as PUT /v1/facts",
            "tenant_binding": null,
            "notes": "Bulk inputs are prechecked before try_store_bulk"
        },
        {
            "route": "POST /v1/relations",
            "required_any_scope": ["facts:write", "admin:write"],
            "passport_binding": "standard HTTP scope context",
            "tenant_binding": "facts:write must include tenant claim; admin:* bypasses tenant claim",
            "notes": "tenant_id is trimmed and validated before authz"
        },
        {
            "route": "POST /v1/gpu1/*/compute",
            "required_any_scope": ["gpu1:<service>", "admin:write"],
            "passport_binding": "standard HTTP scope context",
            "tenant_binding": "service scope must include tenant claim; admin:* bypasses tenant claim",
            "notes": "selected evidence only; no full-store upload"
        },
        {
            "route": "POST /v1/punchcards/*",
            "required_any_scope": ["facts:read/write", "admin:read/write"],
            "passport_binding": "holder is request-derived; body fields are equality assertions; cross-owner release is a separate issuer-verified canonical-passport admin route",
            "tenant_binding": "request-derived and enforced before mutation or returning target state/details",
            "notes": "off/dev identities are explicitly namespaced as unverified local actors"
        },
        {
            "route": "GET /v1/sessions/{id}/plan",
            "required_any_scope": ["sessions:read", "admin:read"],
            "passport_binding": "sessions:read proves immutable admission ownership; admin:read is tenant-scoped",
            "tenant_binding": "authoritative session binding is authorized before registry data is returned",
            "notes": "only global-tenant admin authority can inspect every tenant"
        }
    ]);
    Ok(text_with_structured("route access matrix", json!({"routes": routes})))
}

#[allow(clippy::unused_async)]
pub async fn handle_auth_posture_audit(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let posture = json!({
        "schema": "crux.auth_posture_audit.v1",
        "checked_at": chrono::Utc::now().to_rfc3339(),
        "mcp_agent": ctx.scope_identity(),
        "daemon_loopback_configured": ctx.daemon_base_url.is_some(),
        "rcx_router_configured": ctx.rcx_router.is_some(),
        "agent_passports_enabled": ctx.agent_passports_enabled,
        "data_dir_configured": ctx.data_dir.is_some(),
        "notes": [
            "HTTP auth mode is daemon-local state and is not exposed directly through MCP",
            "Use route_access_matrix for expected high-risk route gates"
        ],
        "recommended_checks": [
            "verify HTTP JWT mode in daemon env for non-loopback binds",
            "verify X-Corecrux-Passport-Id is stripped or generated by trusted edge only",
            "probe /readyz and one tenant-bound route after auth changes"
        ]
    });
    Ok(text_with_structured("auth posture audit complete", posture))
}

#[allow(clippy::unused_async)]
pub async fn handle_egress_policy_check(args: &Value, _ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let target = require_str(args, "target")?;
    let purpose = args.get("purpose").and_then(Value::as_str).unwrap_or("unspecified");
    let allow_plain_http = args.get("allow_plain_http").and_then(Value::as_bool).unwrap_or(false);
    let allow_loopback_http = args.get("allow_loopback_http").and_then(Value::as_bool).unwrap_or(true);
    let (scheme, host) = parse_urlish(target);
    let mut reasons = Vec::new();
    let mut allowed = true;

    match scheme.as_deref() {
        Some("https") => {}
        Some("http") if allow_loopback_http && host.as_deref().is_some_and(is_loopback_host) => {}
        Some("http") if allow_plain_http => reasons.push("plain HTTP allowed by explicit input".to_string()),
        Some("http") => {
            allowed = false;
            reasons.push("plain HTTP egress denied unless loopback or explicitly allowed".to_string());
        }
        Some(other) => {
            allowed = false;
            reasons.push(format!("unsupported URL scheme: {other}"));
        }
        None => {
            allowed = false;
            reasons.push("target must include a URL scheme".to_string());
        }
    }
    if purpose.trim().is_empty() || purpose == "unspecified" {
        reasons.push("purpose should be explicit for auditability".to_string());
    }

    let result = json!({
        "schema": "crux.egress_policy_check.v1",
        "target": target,
        "purpose": purpose,
        "allowed": allowed,
        "scheme": scheme,
        "host": host,
        "reasons": reasons,
    });
    Ok(text_with_structured(
        if allowed { "egress allowed" } else { "egress denied" },
        result,
    ))
}

fn parse_urlish(target: &str) -> (Option<String>, Option<String>) {
    let Some((scheme, rest)) = target.split_once("://") else {
        return (None, None);
    };
    let authority = rest
        .split('/')
        .next()
        .and_then(|authority| authority.rsplit('@').next())
        .unwrap_or_default();
    let host = if authority.starts_with('[') {
        authority
            .find(']')
            .map(|end| authority[..=end].to_string())
            .filter(|s| !s.is_empty())
    } else {
        authority
            .split(':')
            .next()
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    (Some(scheme.to_ascii_lowercase()), host)
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]")
}

fn text_with_structured(text: &str, structured: Value) -> Value {
    json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": structured
    })
}

fn require_str<'a>(args: &'a Value, field: &str) -> Result<&'a str, JsonRpcError> {
    args.get(field).and_then(Value::as_str).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing required param: {field}"),
        data: Some(json!({"param": field, "required": true})),
    })
}

fn require_u64(args: &Value, field: &str) -> Result<u64, JsonRpcError> {
    args.get(field).and_then(Value::as_u64).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing required param: {field}"),
        data: Some(json!({"param": field, "required": true})),
    })
}

fn invalid<T>(field: &str, message: &str) -> Result<T, JsonRpcError> {
    Err(JsonRpcError {
        code: INVALID_PARAMS,
        message: message.to_string(),
        data: Some(json!({"param": field})),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;

    #[test]
    fn parse_urlish_extracts_scheme_and_host() {
        assert_eq!(
            parse_urlish("https://example.com/path"),
            (Some("https".to_string()), Some("example.com".to_string()))
        );
        assert_eq!(
            parse_urlish("http://user@127.0.0.1:14800/v1"),
            (Some("http".to_string()), Some("127.0.0.1".to_string()))
        );
    }

    #[test]
    fn loopback_hosts_are_recognized() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(!is_loopback_host("example.com"));
    }

    #[tokio::test]
    async fn egress_policy_denies_external_plain_http() {
        let ctx = McpContext::new_default("test-node");
        let result = handle_egress_policy_check(&json!({"target": "http://example.com/a", "purpose": "test"}), &ctx)
            .await
            .unwrap();
        assert_eq!(result["structuredContent"]["allowed"], false);
    }

    #[tokio::test]
    async fn egress_policy_allows_loopback_plain_http() {
        let ctx = McpContext::new_default("test-node");
        let result = handle_egress_policy_check(
            &json!({"target": "http://127.0.0.1:14800/readyz", "purpose": "probe"}),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(result["structuredContent"]["allowed"], true);
    }

    #[tokio::test]
    async fn execplan_gate_stores_stable_fact() {
        let ctx = McpContext::new_default("test-node");
        let result = handle_execplan_gate(
            &json!({
                "slug": "audit-plan",
                "milestone": "M2",
                "status": "passed",
                "commit_sha": "abc1234",
                "token_budget": 500
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(result["structuredContent"]["entity"], "execplan:audit-plan");
        assert_eq!(result["structuredContent"]["key"], "gate:M2");

        let store = ctx.fact_store.read().await;
        let fact = store
            .all_facts()
            .find(|fact| fact.entity == "execplan:audit-plan")
            .unwrap();
        assert_eq!(fact.key, "gate:M2");
        assert!(fact.value.contains("\"commit_sha\":\"abc1234\""));
    }
}
