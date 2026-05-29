// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Orchestrator MCP tools (orchestrators plan).
//!
//! Thin loopback wrappers over the daemon's `/v1/orchestrators/*` surface,
//! mirroring the `coordination.rs` pattern. The HTTP endpoints are stubs
//! today (gated default-OFF, 501 when called), so these handlers currently
//! surface that 501 to the caller — by design for the Package S scaffold.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use crate::tools::coordination::{loopback_base, loopback_delete, loopback_get, loopback_post, text_content};

pub const CREATE_ORCHESTRATOR_DESCRIPTION: &str =
    "Create a multi-agent orchestrator — a coordinator that groups work items and member passports under one umbrella. Returns the minted orchestrator record.";

pub const ATTACH_TO_ORCHESTRATOR_DESCRIPTION: &str =
    "Attach a member (passport or work item) to an orchestrator so it shows up in the coordinator's roster.";

pub const DETACH_FROM_ORCHESTRATOR_DESCRIPTION: &str = "Detach a member from an orchestrator.";

pub const LIST_ORCHESTRATORS_DESCRIPTION: &str =
    "List orchestrators defined on this daemon, optionally filtered by tenant_id or state.";

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

pub async fn handle_create_orchestrator(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let name = required_str(args, "name", "create_orchestrator")?;
    let created_by = required_str(args, "created_by_passport", "create_orchestrator")?;
    let mut body = json!({
        "name": name,
        "created_by_passport": created_by,
    });
    for key in ["assignee_passport", "tenant_id", "state"] {
        if let Some(v) = args.get(key) {
            body[key] = v.clone();
        }
    }
    let base = loopback_base(ctx)?;
    let (_, resp) = loopback_post(format!("{base}/v1/orchestrators"), body, true).await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

pub async fn handle_attach_to_orchestrator(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let id = required_str(args, "orchestrator_id", "attach_to_orchestrator")?;
    let member = required_str(args, "member_ref", "attach_to_orchestrator")?;
    let body = json!({ "member_ref": member });
    let base = loopback_base(ctx)?;
    let (_, resp) = loopback_post(format!("{base}/v1/orchestrators/{id}/members"), body, false).await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

pub async fn handle_detach_from_orchestrator(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let id = required_str(args, "orchestrator_id", "detach_from_orchestrator")?;
    let member = required_str(args, "member_ref", "detach_from_orchestrator")?;
    let base = loopback_base(ctx)?;
    let url = format!("{base}/v1/orchestrators/{id}/members/{}", urlencoding(member));
    let (_, resp) = loopback_delete(url).await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

pub async fn handle_list_orchestrators(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let mut params = Vec::new();
    for key in ["tenant_id", "state"] {
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
    let (_, resp) = loopback_get(format!("{base}/v1/orchestrators{qs}")).await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}
