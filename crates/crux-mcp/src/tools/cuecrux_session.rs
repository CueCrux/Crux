// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `cuecrux_session` — the single collapsed-surface MCP tool
//! (master-plan §6).
//!
//! Calling this tool is equivalent to `POST /session` on the embedded
//! corecruxd HTTP server. The tool is a thin wrapper so MCP-only clients
//! (Claude Desktop, Cursor, the Anthropic MCP inspector) can open a
//! handshake and receive a typed `SessionPlan` without learning the
//! per-service MCP surface.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};

/// Master-plan §6.1 description, used verbatim. Do not edit without
/// updating the plan. Exposed as a constant so the tool listing in
/// [`super::list_tools`] and any documentation site pull from one place.
pub const CUECRUX_SESSION_DESCRIPTION: &str = concat!(
    "Opens a CueCrux session. Returns a capability plan covering retrieval, proofing, ",
    "memory, journaling, and audit across VaultCrux and MemoryCrux. ",
    "Call this first. All subsequent work flows through the plan's channels. ",
    "Works identically for local Crux CE installations and the hosted CueCrux platform. ",
    "The plan includes typed routing hints so bulk-capable agents use the HTTP/2 binary channel transparently; ",
    "MCP-only agents use the MCP fallback URLs in the plan.",
);

pub fn tool_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "intent": {
                "type": "string",
                "description": "Optional intent hint, e.g. 'audit_review', 'document_ingest'."
            },
            "hints": {
                "type": "object",
                "properties": {
                    "prefer_bulk":       { "type": "boolean" },
                    "max_capabilities":  { "type": "integer", "minimum": 0 },
                    "want_parent_chain": { "type": "boolean" }
                },
                "additionalProperties": false
            }
        },
        "additionalProperties": false,
        "examples": [
            { "intent": "audit_review" },
            { "hints": { "prefer_bulk": false } }
        ]
    })
}

pub async fn handle_cuecrux_session(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let Some(base_url) = ctx.daemon_base_url.as_deref() else {
        return Err(JsonRpcError {
            code: INTERNAL_ERROR,
            message: "cuecrux_session: daemon_base_url not configured; the MCP server was not wired to corecruxd"
                .to_string(),
            data: None,
        });
    };

    let mut body = serde_json::Map::new();
    body.insert("client_id".into(), Value::String("crux-mcp".into()));
    body.insert("client_version".into(), Value::String(env!("CARGO_PKG_VERSION").into()));
    body.insert(
        "accepts".into(),
        Value::Array(vec![Value::String("application/json".into())]),
    );
    if let Some(intent) = args.get("intent").and_then(Value::as_str) {
        if !intent.is_empty() {
            body.insert("intent".into(), Value::String(intent.to_string()));
        }
    }
    if let Some(hints) = args.get("hints").cloned() {
        if hints.is_object() {
            body.insert("hints".into(), hints);
        } else {
            return Err(JsonRpcError {
                code: INVALID_PARAMS,
                message: "cuecrux_session: hints must be an object".into(),
                data: None,
            });
        }
    }

    let url = format!("{}/session", base_url.trim_end_matches('/'));
    let payload = Value::Object(body);

    // The HTTP round-trip is blocking; move it off the async runtime via
    // spawn_blocking so we don't stall the tokio reactor.
    let response = tokio::task::spawn_blocking(move || {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .build();
        agent
            .post(&url)
            .set("Content-Type", "application/json")
            .set("Accept", "application/json")
            .send_string(&payload.to_string())
            .map(|r| (r.status(), r.into_string().unwrap_or_default()))
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("cuecrux_session: join error: {e}"),
        data: None,
    })?;

    let (status, body_text) = response.map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("cuecrux_session: loopback request failed: {e}"),
        data: None,
    })?;

    if status != 200 {
        return Err(JsonRpcError {
            code: INTERNAL_ERROR,
            message: format!(
                "cuecrux_session: corecruxd returned {status}: {}",
                truncate(&body_text, 512)
            ),
            data: None,
        });
    }

    // Hand the plan back as-is inside the MCP `content` wrapper so the
    // agent can parse it with any SessionPlan library.
    Ok(json!({
        "content": [
            {
                "type": "text",
                "text": body_text,
            }
        ]
    }))
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        let mut out = s[..n].to_string();
        out.push_str("...");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;

    #[test]
    fn description_matches_master_plan_section_6_1() {
        // The description must name every unlocked capability class so keyword
        // search in MCP registries + agent catalogues finds the tool.
        let desc = CUECRUX_SESSION_DESCRIPTION;
        for needle in [
            "retrieval",
            "proofing",
            "memory",
            "journaling",
            "audit",
            "VaultCrux",
            "MemoryCrux",
            "Crux CE",
            "Call this first",
        ] {
            assert!(desc.contains(needle), "description missing `{needle}`");
        }
    }

    #[test]
    fn input_schema_accepts_empty_and_rich_bodies() {
        let schema = tool_input_schema();
        assert_eq!(schema["type"], "object");
        assert!(schema["properties"]["intent"].is_object());
        assert!(schema["properties"]["hints"].is_object());
        // `additionalProperties: false` prevents unknown top-level keys from
        // being silently accepted.
        assert_eq!(schema["additionalProperties"], false);
    }

    #[tokio::test]
    async fn errors_when_daemon_base_url_is_unset() {
        let ctx = McpContext::new_default("test-node");
        let result = handle_cuecrux_session(&json!({}), &ctx).await;
        let err = result.expect_err("must fail without daemon_base_url");
        assert!(err.message.contains("daemon_base_url not configured"));
    }

    #[tokio::test]
    async fn errors_when_hints_not_object() {
        let ctx = McpContext::new_default("test-node").with_daemon_base_url("http://127.0.0.1:14800");
        let result = handle_cuecrux_session(&json!({ "hints": "not-an-object" }), &ctx).await;
        let err = result.expect_err("must reject non-object hints");
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn errors_cleanly_on_loopback_connection_refused() {
        // Point at a port that is (almost certainly) not listening. The
        // tool must return a clear INTERNAL_ERROR, not panic.
        let ctx = McpContext::new_default("test-node").with_daemon_base_url("http://127.0.0.1:1");
        let result = handle_cuecrux_session(&json!({}), &ctx).await;
        let err = result.expect_err("must fail on refused connection");
        assert!(err.message.contains("loopback request failed"));
    }

    #[test]
    fn truncate_preserves_short_strings() {
        assert_eq!(truncate("hello", 10), "hello");
        assert!(truncate(&"x".repeat(1000), 16).ends_with("..."));
    }
}
