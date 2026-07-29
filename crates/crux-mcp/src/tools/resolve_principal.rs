// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `resolve_principal` MCP tool — agent-facing parity for the daemon's
//! `GET /v1/principal/resolve`.
//!
//! Loops back to the embedded corecruxd HTTP server (the same pattern as
//! `receipt_verify` / `cuecrux_session`) so an agent — or an MCP-only client —
//! can read its own (or a given session's) resolved passport / tier /
//! capabilities / tenant. Read-only; tenant-scoped server-side. The standalone
//! mediator (the gateway) calls the HTTP endpoint directly; this tool is the
//! MCP surface of the same resolver.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};

use super::loopback_auth::loopback_bearer_token;

/// Scope advertised on the loopback (DevScopes mode); the minted loopback JWT
/// also carries `sessions:read`, so JWT modes authorize too.
const SCOPES: &str = "sessions:read";

pub const RESOLVE_PRINCIPAL_DESCRIPTION: &str = concat!(
    "Resolve the real passport, reputation tier, capabilities, and tenant behind a ",
    "session — your own by default, or a given session_id / passport_id. Read-only; ",
    "the daemon tenant-scopes the result. Use this to learn what tier/capabilities ",
    "you are authorized for before attempting a gated action."
);

pub fn tool_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "session_id": { "type": "string", "description": "Resolve the principal bound to this session id (hex)." },
            "passport_id": { "type": "string", "description": "Resolve this passport id directly (e.g. \"claude-work\")." }
        },
        "additionalProperties": false,
        "examples": [ {}, { "passport_id": "claude-work" }, { "session_id": "deadbeef" } ]
    })
}

pub async fn handle_resolve_principal(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let base_url = ctx.daemon_base_url.as_deref().ok_or_else(|| JsonRpcError {
        code: INTERNAL_ERROR,
        message: "resolve_principal: daemon_base_url not configured; the MCP server was not wired to corecruxd"
            .to_string(),
        data: None,
    })?;

    // Resolution target: explicit session_id / passport_id, else the calling
    // agent's own passport key (e.g. `claude-work`).
    let (param, value) = if let Some(sid) = args.get("session_id").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        ("session_id", sid.to_string())
    } else if let Some(pid) = args
        .get("passport_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        ("passport_id", pid.to_string())
    } else if let Some(name) = super::passport::passport_key_name(ctx) {
        ("passport_id", name)
    } else {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "resolve_principal: pass session_id or passport_id, or authenticate an agent identity".to_string(),
            data: None,
        });
    };

    let url = format!(
        "{}/v1/principal/resolve?{param}={value}",
        base_url.trim_end_matches('/')
    );

    let (status, body) = loopback_get(url).await?;
    if status != 200 {
        return Err(JsonRpcError {
            code: INTERNAL_ERROR,
            message: format!(
                "resolve_principal: corecruxd returned {status}: {}",
                truncate(&body, 256)
            ),
            data: None,
        });
    }

    let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    Ok(json!({
        "content": [{ "type": "text", "text": body }],
        "principal": parsed,
        "resolved_param": param,
    }))
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

async fn loopback_get(url: String) -> Result<(u16, String), JsonRpcError> {
    let bearer = loopback_bearer_token();
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(10)))
            .build()
            .into();
        let mut req = agent
            .get(&url)
            .header("X-Corecrux-Scopes", SCOPES)
            .header("Accept", "application/json");
        if let Some(token) = &bearer {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        match req.call() {
            Ok(mut r) => {
                let status = r.status().as_u16();
                let body = r.body_mut().read_to_string().unwrap_or_default();
                Ok((status, body))
            }
            Err(ureq::Error::StatusCode(code)) => Ok((code, String::new())),
            Err(other) => Err(other.to_string()),
        }
    })
    .await
    .map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("resolve_principal loopback join error: {e}"),
        data: None,
    })?
    .map_err(|message| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("resolve_principal loopback failed: {message}"),
        data: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_declares_both_optional_inputs() {
        let s = tool_input_schema();
        let props = &s["properties"];
        assert!(props.get("session_id").is_some());
        assert!(props.get("passport_id").is_some());
        assert_eq!(s["additionalProperties"], json!(false));
    }

    #[test]
    fn truncate_is_char_safe() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello", 3), "hel…");
        // multi-byte char must not panic on a non-boundary slice
        assert_eq!(truncate("héllo", 2), "hé…");
    }
}
