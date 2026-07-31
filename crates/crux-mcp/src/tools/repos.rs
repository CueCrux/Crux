// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Repository registry MCP loopback tools.

use std::io::Read;

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};
use crate::tools::loopback_auth::request_loopback_authority;

pub fn register_description() -> &'static str {
    "Register a repository with corecruxd for the authenticated MCP tenant. \
     Local root_path registration is restricted to a global operator context \
     and defaults to an asynchronous bounded scan; clone_url registration is \
     recorded without cloning."
}

pub fn list_description() -> &'static str {
    "List repository registrations visible for one tenant."
}

pub fn register_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "tenant_id": { "type": "string", "description": "Consistency assertion for the authenticated MCP tenant. A global operator may name a concrete target tenant." },
            "repo_id": { "type": "string", "description": "Optional repo id. Defaults to a slug derived from root_path or clone_url." },
            "root_path": { "type": "string", "description": "Local absolute repo path. Requires global operator authority and must fall under CORECRUXD_REPO_SCAN_ALLOWED_ROOTS." },
            "clone_url": { "type": "string", "description": "Remote clone URL to register without cloning yet." },
            "languages": { "type": "array", "items": { "type": "string" }, "default": [] },
            "scan_mode": { "type": "string", "enum": ["async"], "description": "Local root scans are queued asynchronously so they cannot outlive the daemon HTTP request budget." }
        },
        "required": ["tenant_id"],
        "examples": [
            { "tenant_id": "test", "root_path": "/srv/repos/example", "scan_mode": "async" },
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
/// Shared with [`super::context_graph`] and [`super::code_intel`] so those MCP
/// tools are thin adapters over the very same HTTP routes rather than a second
/// implementation: a divergence between the two surfaces would be a silent
/// correctness bug.
pub(super) async fn loopback_json(
    tool: &'static str,
    method: &'static str,
    url: String,
    body: Option<Value>,
    scope: &'static str,
    ctx: &McpContext,
) -> Result<Value, JsonRpcError> {
    let scopes: Vec<&str> = scope
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .collect();
    let authority = request_loopback_authority(ctx, &scopes)?;
    let bearer = authority.bearer;
    let agent_proof = authority.agent_proof;
    let passport_header = authority.passport_header;
    let tenant = authority.tenant;
    let response = tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            // Inline scans may use the daemon's 300-second default policy.
            // Leave response/transport headroom while async remains the MCP
            // default for local paths.
            .timeout_global(Some(std::time::Duration::from_secs(330)))
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
            if let Some(proof) = &agent_proof {
                request = request.header(crate::agent::INTERNAL_LOOPBACK_AGENT_PROOF_HEADER, proof);
            }
            if let Some(passport_id) = &passport_header {
                request = request.header("X-Corecrux-Passport-Id", passport_id);
            }
            request = request.header("X-Corecrux-Tenant-Id", &tenant);
            request.send_json(body.unwrap_or_else(|| json!({})))
        } else {
            let mut request = agent
                .get(&url)
                .header("X-Corecrux-Scopes", scope)
                .header("Accept", "application/json");
            if let Some(token) = &bearer {
                request = request.header("Authorization", &format!("Bearer {token}"));
            }
            if let Some(proof) = &agent_proof {
                request = request.header(crate::agent::INTERNAL_LOOPBACK_AGENT_PROOF_HEADER, proof);
            }
            if let Some(passport_id) = &passport_header {
                request = request.header("X-Corecrux-Passport-Id", passport_id);
            }
            request = request.header("X-Corecrux-Tenant-Id", &tenant);
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

pub(super) fn requested_tenant(args: &Value, ctx: &McpContext, tool: &str) -> Result<String, JsonRpcError> {
    let requested = required_string(args, "tenant_id", tool)?;
    let authenticated = ctx.scope_tenant();
    if authenticated != "*" && requested != authenticated {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("{tool}: tenant_id does not match the authenticated MCP tenant"),
            data: Some(json!({
                "requested_tenant_id": requested,
                "authenticated_tenant_id": authenticated,
            })),
        });
    }
    Ok(requested)
}

fn requested_scan_mode(args: &Value, root_path: bool) -> Result<Option<String>, JsonRpcError> {
    match optional_string(args, "scan_mode").as_deref() {
        None if root_path => Ok(Some("async".to_string())),
        None => Ok(None),
        Some("inline") if root_path => Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "register_repo: local root scans require scan_mode 'async'".to_string(),
            data: None,
        }),
        Some("inline") => Ok(Some("inline".to_string())),
        Some("async") => Ok(Some("async".to_string())),
        Some(other) => Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("register_repo: unknown scan_mode '{other}'; expected 'inline' or 'async'"),
            data: None,
        }),
    }
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
    let tenant_id = requested_tenant(args, ctx, "register_repo")?;
    let root_path = optional_string(args, "root_path");
    let clone_url = optional_string(args, "clone_url");
    if root_path.is_some() == clone_url.is_some() {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "register_repo: exactly one of root_path or clone_url is required".to_string(),
            data: None,
        });
    }
    if root_path.is_some() && ctx.scope_tenant() != "*" {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "register_repo: local root_path requires a global MCP operator context".to_string(),
            data: None,
        });
    }
    let scan_mode = requested_scan_mode(args, root_path.is_some())?;
    let body = json!({
        "tenant_id": tenant_id,
        "repo_id": optional_string(args, "repo_id"),
        "root_path": root_path,
        "clone_url": clone_url,
        "languages": languages(args)?,
        "scan_mode": scan_mode,
    });
    let url = format!("{}/v1/repos", base_url.trim_end_matches('/'));
    loopback_json("register_repo", "POST", url, Some(body), "admin:write", ctx).await
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
    let tenant_id = requested_tenant(args, ctx, "list_repos")?;
    let url = format!(
        "{}/v1/repos?tenant_id={}",
        base_url.trim_end_matches('/'),
        encode_query(&tenant_id)
    );
    loopback_json("list_repos", "GET", url, None, "admin:read", ctx).await
}

/// Percent-encode one query-string value.
///
/// Shared with [`super::context_graph`] and [`super::code_intel`] — see
/// [`loopback_json`].
///
/// Encodes UTF-8 *bytes*, not `char`s: `%XX` is a byte escape, so formatting a
/// multi-byte code point as a single escape would emit an unparseable value.
/// Reachable with non-ASCII input now that [`super::code_intel`] passes
/// user-supplied symbol names through here.
pub(super) fn encode_query(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
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

    #[tokio::test]
    async fn tenant_spoof_is_rejected_before_loopback() {
        let mut ctx =
            McpContext::new_default("test-node").with_request_authority(Some("verified-agent".to_string()), "tenant-a");
        ctx.daemon_base_url = Some("http://127.0.0.1:9".to_string());
        let err = handle_list_repos(&json!({"tenant_id":"tenant-b"}), &ctx)
            .await
            .expect_err("cross-tenant request must fail locally");
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("authenticated MCP tenant"));
    }

    #[tokio::test]
    async fn local_path_requires_global_operator_context() {
        let mut ctx =
            McpContext::new_default("test-node").with_request_authority(Some("verified-agent".to_string()), "tenant-a");
        ctx.daemon_base_url = Some("http://127.0.0.1:9".to_string());
        let err = handle_register_repo(&json!({"tenant_id":"tenant-a","root_path":"/srv/repos/example"}), &ctx)
            .await
            .expect_err("tenant-scoped caller must not nominate host paths");
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("global MCP operator"));
    }

    #[test]
    fn local_path_defaults_async_and_rejects_unknown_modes() {
        assert_eq!(
            requested_scan_mode(&json!({}), true).expect("default"),
            Some("async".to_string())
        );
        let err = requested_scan_mode(&json!({"scan_mode":"later"}), true).expect_err("unknown mode");
        assert_eq!(err.code, INVALID_PARAMS);
        let err = requested_scan_mode(&json!({"scan_mode":"inline"}), true).expect_err("inline local scan");
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("require scan_mode 'async'"));
    }
}
