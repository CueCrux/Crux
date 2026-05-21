// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Minimal synchronous JSON-RPC 2.0 client targeting the Crux MCP endpoint
//! (`POST /mcp`). Uses `ureq` per the workspace convention. Daemon-unreachable
//! errors are returned to the caller, which logs and exits 0 — hooks never
//! block tool execution.
//!
//! Auth contract: when `CRUX_AGENT_TOKEN` is set and non-empty, every
//! request carries `Authorization: Bearer <token>`. When unset/empty, no
//! header is emitted — preserves the pre-auth local-daemon path. Regression
//! test in `tests/hook_e2e.rs` pins this contract: a missing header against
//! the auth'd remote daemon at `100.70.12.73:14801` produced silent 401s
//! for ~12+ sessions before the bug was found (2026-05-21).

use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};

use crate::{DEFAULT_MCP_URL, MCP_TIMEOUT_SECS};

/// Resolve the MCP endpoint URL, honouring `CRUX_MCP_URL`.
pub fn mcp_url() -> String {
    std::env::var("CRUX_MCP_URL").unwrap_or_else(|_| DEFAULT_MCP_URL.to_string())
}

/// Resolve the agent token from env. `None` (or empty) preserves the
/// pre-auth local-daemon path: no `Authorization` header is emitted.
pub fn mcp_token() -> Option<String> {
    std::env::var("CRUX_AGENT_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Call an MCP tool by name with the given arguments. Returns the
/// JSON-RPC `result` payload on success.
pub fn call_tool<A: Serialize>(name: &str, arguments: A) -> anyhow::Result<Value> {
    call_tool_at_with_token(&mcp_url(), name, arguments, mcp_token())
}

/// Variant that accepts an explicit endpoint URL — used by tests that
/// spin up a mock server. Resolves the token from env.
pub fn call_tool_at<A: Serialize>(url: &str, name: &str, arguments: A) -> anyhow::Result<Value> {
    call_tool_at_with_token(url, name, arguments, mcp_token())
}

/// Lowest-level call: explicit URL and explicit token. Used by the
/// integration test in `tests/hook_e2e.rs` to exercise the auth contract
/// without env-var racing.
pub fn call_tool_at_with_token<A: Serialize>(
    url: &str,
    name: &str,
    arguments: A,
    token: Option<String>,
) -> anyhow::Result<Value> {
    let envelope = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
        }
    });

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(MCP_TIMEOUT_SECS)))
        .build()
        .into();

    let mut request = agent
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json");
    if let Some(t) = token {
        request = request.header("Authorization", &format!("Bearer {t}"));
    }
    let mut response = request.send_json(&envelope)?;

    let body: Value = response.body_mut().read_json()?;

    if let Some(err) = body.get("error") {
        anyhow::bail!("mcp error: {err}");
    }
    body.get("result")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("mcp response missing `result`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_url_defaults_when_env_absent() {
        let prev = std::env::var("CRUX_MCP_URL").ok();
        std::env::remove_var("CRUX_MCP_URL");
        assert_eq!(mcp_url(), DEFAULT_MCP_URL);
        if let Some(v) = prev {
            std::env::set_var("CRUX_MCP_URL", v);
        }
    }

    #[test]
    fn mcp_token_treats_empty_as_none() {
        let prev = std::env::var("CRUX_AGENT_TOKEN").ok();
        std::env::set_var("CRUX_AGENT_TOKEN", "");
        assert!(mcp_token().is_none(), "empty CRUX_AGENT_TOKEN must yield None");
        std::env::set_var("CRUX_AGENT_TOKEN", "nonempty");
        assert_eq!(mcp_token(), Some("nonempty".to_string()));
        match prev {
            Some(v) => std::env::set_var("CRUX_AGENT_TOKEN", v),
            None => std::env::remove_var("CRUX_AGENT_TOKEN"),
        }
    }

    #[test]
    fn envelope_shape_is_jsonrpc_2_0() {
        let envelope = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "save_session",
                "arguments": {"session_id": "s1", "state": {"step": 1}}
            }
        });
        assert_eq!(envelope["jsonrpc"], "2.0");
        assert_eq!(envelope["method"], "tools/call");
        assert_eq!(envelope["params"]["name"], "save_session");
    }
}
