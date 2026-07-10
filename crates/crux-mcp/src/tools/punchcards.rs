// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Punchcard MCP tools (punchcard plan).
//!
//! Thin loopback wrappers over the daemon's `/v1/punchcards/*` surface,
//! mirroring the `coordination.rs` pattern. `check_punchcard` is the tool the
//! shared PreToolUse hook calls before an Edit/Write/NotebookEdit; it loops
//! back to `POST /v1/punchcards/check`, which always returns `200` so the hook
//! can read `{held_by_other, enforce, holder_passport, resource}` and deny the
//! edit only when `held_by_other && enforce`.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use crate::tools::coordination::{loopback_base, loopback_get, loopback_post, text_content};

pub const PUNCH_IN_DESCRIPTION: &str =
    "Acquire a punchcard lease on a resource (a file path or a deploy target) so other agents see it's being worked on. Returns the lease record.";

pub const PUNCH_OUT_DESCRIPTION: &str =
    "Release a punchcard lease you hold, optionally recording the commit_sha that closed the work.";

pub const LIST_PUNCHCARDS_DESCRIPTION: &str =
    "List active punchcard leases, optionally filtered by resource, holder, or tenant_id.";

pub const FORCE_RELEASE_DESCRIPTION: &str =
    "Force-release a punchcard lease held by another passport (operator override). Destructive: requires confirm=true. Records the override in the lease's receipt chain.";

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

pub async fn handle_punch_in(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let resource = required_str(args, "resource", "punch_in")?;
    let holder = required_str(args, "holder_passport", "punch_in")?;
    let mut body = json!({
        "resource": resource,
        "holder_passport": holder,
    });
    for key in ["mode", "tenant_id", "reason", "expires_at_unix_ms"] {
        if let Some(v) = args.get(key) {
            body[key] = v.clone();
        }
    }
    let base = loopback_base(ctx)?;
    let (_, resp) = loopback_post(
        format!("{base}/v1/punchcards/acquire"),
        body,
        true,
        ctx.scope_identity(),
    )
    .await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

pub async fn handle_punch_out(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let resource = required_str(args, "resource", "punch_out")?;
    let holder = required_str(args, "holder_passport", "punch_out")?;
    let mut body = json!({
        "resource": resource,
        "holder_passport": holder,
    });
    for key in ["release_commit_sha", "tenant_id"] {
        if let Some(v) = args.get(key) {
            body[key] = v.clone();
        }
    }
    let base = loopback_base(ctx)?;
    let (_, resp) = loopback_post(
        format!("{base}/v1/punchcards/release"),
        body,
        false,
        ctx.scope_identity(),
    )
    .await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

pub async fn handle_list_punchcards(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
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
    let (_, resp) = loopback_get(format!("{base}/v1/punchcards{qs}")).await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

pub async fn handle_force_release(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let id = required_str(args, "punchcard_id", "force_release")?;
    // Destructive override: the daemon requires an explicit confirm:true. Pass
    // the caller's value through (default false) so an unconfirmed call gets a
    // 400 from the daemon rather than silently force-releasing.
    let confirm = args.get("confirm").and_then(Value::as_bool).unwrap_or(false);
    let mut body = json!({ "confirm": confirm });
    for key in ["reason", "by_passport"] {
        if let Some(v) = args.get(key) {
            body[key] = v.clone();
        }
    }
    let base = loopback_base(ctx)?;
    let (_, resp) = loopback_post(
        format!("{base}/v1/punchcards/{id}/force-release"),
        body,
        false,
        ctx.scope_identity(),
    )
    .await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

/// `check_punchcard` — the PreToolUse hook's lease probe. Loops back to
/// `POST /v1/punchcards/check`, which always returns `200` (fail-open), so the
/// hook can read the body and deny only when `held_by_other && enforce`.
pub async fn handle_check_punchcard(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let resource = required_str(args, "resource", "check_punchcard")?;
    let mut body = json!({ "resource": resource });
    for key in ["mode", "passport"] {
        if let Some(v) = args.get(key) {
            body[key] = v.clone();
        }
    }
    let base = loopback_base(ctx)?;
    let (_, resp) = loopback_post(format!("{base}/v1/punchcards/check"), body, false, ctx.scope_identity()).await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}
