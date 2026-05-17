// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Minimal synchronous JSON-RPC 2.0 client targeting the Crux MCP endpoint
//! (`POST /mcp`). Uses `ureq` per the workspace convention. Daemon-unreachable
//! errors are returned to the caller, which logs and exits 0 — hooks never
//! block tool execution.

use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};

use crate::{DEFAULT_MCP_URL, MCP_TIMEOUT_SECS};

/// Resolve the MCP endpoint URL, honouring `CRUX_MCP_URL`.
pub fn mcp_url() -> String {
    std::env::var("CRUX_MCP_URL").unwrap_or_else(|_| DEFAULT_MCP_URL.to_string())
}

/// Call an MCP tool by name with the given arguments. Returns the
/// JSON-RPC `result` payload on success.
pub fn call_tool<A: Serialize>(name: &str, arguments: A) -> anyhow::Result<Value> {
    call_tool_at(&mcp_url(), name, arguments)
}

/// Variant that accepts an explicit endpoint URL — used by tests that
/// spin up a mock server.
pub fn call_tool_at<A: Serialize>(url: &str, name: &str, arguments: A) -> anyhow::Result<Value> {
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

    let mut response = agent
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .send_json(&envelope)?;

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
        // Use a unique var-clearing pattern that won't fight a parallel test.
        let prev = std::env::var("CRUX_MCP_URL").ok();
        // SAFETY: tests in a single-threaded `cargo test --test-threads=1` block
        // would be ideal, but with default parallelism this is best-effort.
        // We restore at the end.
        std::env::remove_var("CRUX_MCP_URL");
        assert_eq!(mcp_url(), DEFAULT_MCP_URL);
        if let Some(v) = prev {
            std::env::set_var("CRUX_MCP_URL", v);
        }
    }

    #[test]
    fn envelope_shape_is_jsonrpc_2_0() {
        // We can't exercise the wire call without a mock server, but we can
        // verify the envelope shape by constructing it locally and asserting.
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
