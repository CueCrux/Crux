// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Repository registry MCP loopback tools.

use std::io::Read;

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};

pub fn register_description() -> &'static str {
    "Register a repository with corecruxd for a tenant. A local root_path is \
     scanned immediately by the daemon; clone_url registrations are recorded \
     and scan is deferred."
}

pub fn list_description() -> &'static str {
    "List repository registrations visible for one tenant."
}

pub fn register_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "tenant_id": { "type": "string", "description": "Tenant that owns the repo registration." },
            "repo_id": { "type": "string", "description": "Optional repo id. Defaults to a slug derived from root_path or clone_url." },
            "root_path": { "type": "string", "description": "Local absolute repo path to scan immediately." },
            "clone_url": { "type": "string", "description": "Remote clone URL to register without cloning yet." },
            "languages": { "type": "array", "items": { "type": "string" }, "default": [] }
        },
        "required": ["tenant_id"],
        "examples": [
            { "tenant_id": "test", "root_path": "/home/myles/CueCrux" },
            { "tenant_id": "test", "repo_id": "cuecrux", "clone_url": "https://github.com/example/cuecrux.git", "languages": ["rust"] }
        ]
    })
}

pub fn list_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "tenant_id": { "type": "string", "description": "Tenant to list." }
        },
        "required": ["tenant_id"],
        "examples": [{ "tenant_id": "test" }]
    })
}

fn required_string(args: &Value, name: &str, tool: &str) -> Result<String, JsonRpcError> {
    args.get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("{tool}: missing required string '{name}'"),
            data: None,
        })
}

fn optional_string(args: &Value, name: &str) -> Option<String> {
    args.get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn languages(args: &Value) -> Result<Vec<String>, JsonRpcError> {
    let Some(value) = args.get("languages") else {
        return Ok(Vec::new());
    };
    let Some(arr) = value.as_array() else {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "register_repo: languages must be an array of strings".to_string(),
            data: None,
        });
    };
    let mut out = Vec::new();
    for value in arr {
        let Some(s) = value.as_str() else {
            return Err(JsonRpcError {
                code: INVALID_PARAMS,
                message: "register_repo: languages must be an array of strings".to_string(),
                data: None,
            });
        };
        out.push(s.to_string());
    }
    Ok(out)
}

/// Proxy one request to the local corecruxd over the loopback surface and
/// return its parsed JSON body.
///
/// Shared with [`super::context_graph`] so the MCP context-graph tools are thin
/// adapters over the very same HTTP routes rather than a second implementation:
/// a divergence between the two surfaces would be a silent correctness bug.
pub(super) async fn loopback_json(
    tool: &'static str,
    method: &'static str,
    url: String,
    body: Option<Value>,
    scope: &'static str,
) -> Result<Value, JsonRpcError> {
    let bearer = crate::tools::loopback_auth::loopback_bearer_token();
    let response = tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(120)))
            .build()
            .into();
        let result = if method == "POST" {
            let mut request = agent
                .post(&url)
                .header("Content-Type", "application/json")
                .header("X-Corecrux-Scopes", scope)
                .header("Accept", "application/json");
            if let Some(token) = &bearer {
                request = request.header("Authorization", &format!("Bearer {token}"));
            }
            request.send_json(body.unwrap_or_else(|| json!({})))
        } else {
            let mut request = agent
                .get(&url)
                .header("X-Corecrux-Scopes", scope)
                .header("Accept", "application/json");
            if let Some(token) = &bearer {
                request = request.header("Authorization", &format!("Bearer {token}"));
            }
            request.call()
        };
        result
            .map(|mut r| {
                let status = r.status().as_u16();
                let mut buf = String::new();
                let _ = r.body_mut().as_reader().read_to_string(&mut buf);
                (status, buf)
            })
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("{tool}: join error: {e}"),
        data: None,
    })?;

    let (status, body_text) = response.map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("{tool}: loopback request failed: {e}"),
        data: None,
    })?;
    if !(200..300).contains(&status) {
        return Err(JsonRpcError {
            code: INTERNAL_ERROR,
            message: format!("{tool}: corecruxd returned {status}: {}", truncate(&body_text, 512)),
            data: None,
        });
    }
    serde_json::from_str(&body_text).map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("{tool}: invalid daemon JSON: {e}"),
        data: Some(json!({ "body": truncate(&body_text, 512) })),
    })
}

pub async fn handle_register_repo(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let Some(base_url) = ctx.daemon_base_url.as_deref() else {
        return Err(JsonRpcError {
            code: INTERNAL_ERROR,
            message: "register_repo: daemon_base_url not configured; the MCP server was not wired to corecruxd"
                .to_string(),
            data: None,
        });
    };
    let tenant_id = required_string(args, "tenant_id", "register_repo")?;
    let root_path = optional_string(args, "root_path");
    let clone_url = optional_string(args, "clone_url");
    if root_path.is_some() == clone_url.is_some() {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "register_repo: exactly one of root_path or clone_url is required".to_string(),
            data: None,
        });
    }
    let body = json!({
        "tenant_id": tenant_id,
        "repo_id": optional_string(args, "repo_id"),
        "root_path": root_path,
        "clone_url": clone_url,
        "languages": languages(args)?,
    });
    let url = format!("{}/v1/repos", base_url.trim_end_matches('/'));
    loopback_json("register_repo", "POST", url, Some(body), "admin:write").await
}

pub async fn handle_list_repos(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let Some(base_url) = ctx.daemon_base_url.as_deref() else {
        return Err(JsonRpcError {
            code: INTERNAL_ERROR,
            message: "list_repos: daemon_base_url not configured; the MCP server was not wired to corecruxd"
                .to_string(),
            data: None,
        });
    };
    let tenant_id = required_string(args, "tenant_id", "list_repos")?;
    let url = format!(
        "{}/v1/repos?tenant_id={}",
        base_url.trim_end_matches('/'),
        encode_query(&tenant_id)
    );
    loopback_json("list_repos", "GET", url, None, "admin:read").await
}

/// Percent-encode a value for use in a query string. Shared with
/// [`super::context_graph`] — see [`loopback_json`].
pub(super) fn encode_query(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u32),
        })
        .collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_repo_dispatches_and_requires_loopback_base() {
        let ctx = McpContext::new_default("test-node");
        let err = crate::tools::call_tool(
            "register_repo",
            &json!({"tenant_id":"test","root_path":"/tmp/fixture"}),
            &ctx,
        )
        .await
        .expect_err("missing daemon base should fail");
        assert!(err.message.contains("register_repo"));
        assert!(err.message.contains("daemon_base_url not configured"));
    }

    #[tokio::test]
    async fn list_repos_dispatches_and_requires_loopback_base() {
        let ctx = McpContext::new_default("test-node");
        let err = crate::tools::call_tool("list_repos", &json!({"tenant_id":"test"}), &ctx)
            .await
            .expect_err("missing daemon base should fail");
        assert!(err.message.contains("list_repos"));
        assert!(err.message.contains("daemon_base_url not configured"));
    }

    #[test]
    fn schemas_require_tenant() {
        assert!(register_schema()["required"]
            .as_array()
            .expect("required")
            .iter()
            .any(|v| v == "tenant_id"));
        assert!(list_schema()["required"]
            .as_array()
            .expect("required")
            .iter()
            .any(|v| v == "tenant_id"));
    }
}
