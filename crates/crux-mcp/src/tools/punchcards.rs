// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Punchcard MCP tools (punchcard plan).
//!
//! Thin loopback wrappers over the daemon's `/v1/punchcards/*` surface,
//! mirroring the `coordination.rs` pattern. `check_punchcard` is the tool the
//! shared PreToolUse hook calls before an Edit/Write/NotebookEdit; it loops
//! back to `POST /v1/punchcards/check`, which always returns `200` so the hook
//! can read `{held_by_other, enforce, holder_passport, resource}` and deny the
//! edit only when `held_by_other && enforce`.

use serde_json::{json, Value};

use crate::dispatch::{McpContext, CAPABILITY_DENIED};
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use crate::tools::coordination::{
    authority_identity, claimed_identity_matches, loopback_base, loopback_get_for_context, loopback_post_for_context,
    text_content,
};

const PUNCHCARD_READ_SCOPES: &[&str] = &["facts:read"];
const PUNCHCARD_WRITE_SCOPES: &[&str] = &["facts:write"];

pub const PUNCH_IN_DESCRIPTION: &str =
    "Acquire a punchcard lease on a resource (a file path or a deploy target) so other agents see it is being worked on. The holder and tenant come from the authenticated MCP authority; optional identity fields are consistency assertions only. Returns the lease record.";

pub const PUNCH_OUT_DESCRIPTION: &str =
    "Release a punchcard lease owned by the authenticated MCP authority, optionally recording the commit_sha that closed the work. Optional identity fields are consistency assertions only.";

pub const LIST_PUNCHCARDS_DESCRIPTION: &str =
    "List punchcard leases in the authenticated MCP tenant, optionally filtered by resource, holder, or status. An optional tenant_id is a consistency assertion only.";

pub const CHECK_PUNCHCARD_DESCRIPTION: &str =
    "Check whether a resource (file://<path>, tree://<subtree>, or service://<name>) is leased by another passport. Returns { held_by_other, enforce, holder_passport, resource, expires_at_unix_ms }. The PreToolUse hook calls this before an edit and denies only when held_by_other && enforce.";

fn required_str<'a>(args: &'a Value, key: &str, tool: &str) -> Result<&'a str, JsonRpcError> {
    args.get(key).and_then(Value::as_str).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("{tool}: {key} is required"),
        data: None,
    })
}

fn urlencoding(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn mutation_identity(ctx: &McpContext, args: &Value, field: &str, tool: &str) -> Result<String, JsonRpcError> {
    let identity = authority_identity(ctx, tool)?;
    if let Some(claimed) = args
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if !claimed_identity_matches(ctx, claimed, &identity) {
            return Err(JsonRpcError {
                code: INVALID_PARAMS,
                message: format!("{tool}: {field} does not match the authenticated MCP authority"),
                data: None,
            });
        }
    }
    if let Some(claimed_tenant) = args
        .get("tenant_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if claimed_tenant != ctx.scope_tenant() {
            return Err(JsonRpcError {
                code: INVALID_PARAMS,
                message: format!("{tool}: tenant_id does not match the authenticated MCP tenant"),
                data: None,
            });
        }
    }
    Ok(identity)
}

fn punch_in_body(args: &Value, resource: &str) -> Value {
    let mut body = json!({
        "resource": resource,
    });
    for key in ["mode", "reason", "ttl_secs"] {
        if let Some(v) = args.get(key) {
            body[key] = v.clone();
        }
    }
    body
}

pub async fn handle_punch_in(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let resource = required_str(args, "resource", "punch_in")?;
    let _holder = mutation_identity(ctx, args, "holder_passport", "punch_in")?;
    let body = punch_in_body(args, resource);
    let base = loopback_base(ctx)?;
    let (_, resp) = loopback_post_for_context(
        format!("{base}/v1/punchcards/acquire"),
        body,
        false,
        ctx,
        PUNCHCARD_WRITE_SCOPES,
    )
    .await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

pub async fn handle_punch_out(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let resource = required_str(args, "resource", "punch_out")?;
    let _holder = mutation_identity(ctx, args, "holder_passport", "punch_out")?;
    let mut body = json!({
        "resource": resource,
    });
    for key in ["release_commit_sha"] {
        if let Some(v) = args.get(key) {
            body[key] = v.clone();
        }
    }
    let base = loopback_base(ctx)?;
    let (_, resp) = loopback_post_for_context(
        format!("{base}/v1/punchcards/release"),
        body,
        false,
        ctx,
        PUNCHCARD_WRITE_SCOPES,
    )
    .await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

pub async fn handle_list_punchcards(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let tenant = ctx.scope_tenant();
    if args
        .get("tenant_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|claimed| claimed != tenant)
    {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "list_punchcards: tenant_id does not match the authenticated MCP tenant".to_string(),
            data: None,
        });
    }
    let mut params = Vec::new();
    for key in ["resource", "holder_passport", "tenant_id", "status"] {
        if let Some(v) = args.get(key).and_then(Value::as_str) {
            params.push(format!("{key}={}", urlencoding(v)));
        }
    }
    let qs = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    };
    let base = loopback_base(ctx)?;
    let (_, resp) = loopback_get_for_context(format!("{base}/v1/punchcards{qs}"), ctx, PUNCHCARD_READ_SCOPES).await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

pub fn handle_force_release(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let _ = (args, ctx);
    Err(JsonRpcError {
        code: CAPABILITY_DENIED,
        message: "force_release is HTTP-only and requires an issuer-verified canonical passport claim with admin:write"
            .to_string(),
        data: None,
    })
}

/// `check_punchcard` — the PreToolUse hook's lease probe. Loops back to
/// `POST /v1/punchcards/check`, which always returns `200` (fail-open), so the
/// hook can read the body and deny only when `held_by_other && enforce`.
pub async fn handle_check_punchcard(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let resource = required_str(args, "resource", "check_punchcard")?;
    let _identity = mutation_identity(ctx, args, "passport", "check_punchcard")?;
    let mut body = json!({ "resource": resource });
    for key in ["mode"] {
        if let Some(v) = args.get(key) {
            body[key] = v.clone();
        }
    }
    let base = loopback_base(ctx)?;
    let (_, resp) = loopback_post_for_context(
        format!("{base}/v1/punchcards/check"),
        body,
        false,
        ctx,
        PUNCHCARD_READ_SCOPES,
    )
    .await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::protocol::INTERNAL_ERROR;

    fn context(name: &str, tenant: &str) -> McpContext {
        let mut context = McpContext::new_default("punchcard-mcp-test")
            .with_agent(AgentIdentity {
                name: name.to_string(),
                token_hash: [7; 32],
            })
            .with_request_loopback_bearer_token(Some(format!("test-token-{name}")));
        context.daemon_base_url = Some("http://127.0.0.1:9".to_string());
        context.request_tenant = Some(tenant.to_string());
        context
    }

    #[test]
    fn punchcard_loopback_claims_only_fact_scopes() {
        assert_eq!(PUNCHCARD_READ_SCOPES, &["facts:read"]);
        assert_eq!(PUNCHCARD_WRITE_SCOPES, &["facts:write"]);
    }

    #[tokio::test]
    async fn owner_and_tenant_spoofs_fail_before_loopback() {
        let ctx = context("alice", "tenant-a");
        for error in [
            handle_punch_in(&json!({"resource":"file:///x","holder_passport":"bob"}), &ctx)
                .await
                .expect_err("spoofed holder"),
            handle_punch_out(&json!({"resource":"file:///x","holder_passport":"bob"}), &ctx)
                .await
                .expect_err("spoofed release holder"),
            handle_check_punchcard(&json!({"resource":"file:///x","passport":"bob"}), &ctx)
                .await
                .expect_err("spoofed check passport"),
            handle_list_punchcards(&json!({"tenant_id":"tenant-b"}), &ctx)
                .await
                .expect_err("spoofed list tenant"),
        ] {
            assert_eq!(error.code, INVALID_PARAMS);
            assert!(
                !error.message.contains("loopback"),
                "identity denial must happen before network: {}",
                error.message
            );
        }
    }

    #[tokio::test]
    async fn anonymous_mutation_and_native_force_release_are_denied_pre_network() {
        let mut anonymous = McpContext::new_default("anonymous");
        anonymous.daemon_base_url = Some("http://127.0.0.1:9".to_string());
        let error = handle_punch_in(&json!({"resource":"file:///x"}), &anonymous)
            .await
            .expect_err("anonymous mutation");
        assert_eq!(error.code, INVALID_PARAMS);

        let error = handle_force_release(
            &json!({"punchcard_id":"pc_x","confirm":true}),
            &context("operator", "tenant-a"),
        )
        .expect_err("native force release");
        assert_eq!(error.code, CAPABILITY_DENIED);
        assert!(!error.message.contains("loopback"));
    }

    #[tokio::test]
    async fn valid_owner_reaches_transport_with_canonicalized_identity() {
        let ctx = context("alice", "tenant-a");
        let error = handle_punch_in(
            &json!({
                "resource":"file:///x",
                "holder_passport":"alice",
                "tenant_id":"tenant-a"
            }),
            &ctx,
        )
        .await
        .expect_err("port 9 has no server");
        assert_eq!(error.code, INTERNAL_ERROR);
        assert!(error.message.contains("loopback transport"));
    }

    #[test]
    fn punch_in_forwards_http_ttl_contract_and_drops_legacy_absolute_expiry() {
        let body = punch_in_body(
            &json!({
                "resource": "file:///x",
                "ttl_secs": 321,
                "expires_at_unix_ms": 999_999,
            }),
            "file:///x",
        );
        assert_eq!(body["ttl_secs"], 321);
        assert!(body.get("expires_at_unix_ms").is_none());
        assert!(body.get("holder_passport").is_none());
        assert!(body.get("tenant_id").is_none());
    }
}
