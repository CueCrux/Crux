// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `get_workspace_storyline` MCP tool. Loops back to the daemon's
//! `GET /v1/workspace/storyline` endpoint so any agent on the daemon can
//! pull the per-route call tree (text or compact JSON) without needing to
//! know the HTTP surface directly. Mirrors the cuecrux_session pattern.

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};
use serde_json::{json, Value};
use std::io::Read;

pub fn description() -> &'static str {
    "Retrieve the per-endpoint call-tree storyline derived from the latest \
     workspace scan. `format=tree` returns ASCII tree-art (default — designed \
     for LLM consumption); `format=json` returns a compact integer-keyed \
     graph of files + edges + routes (designed for programmatic traversal). \
     `endpoint` filters to a single route in the form 'METHOD PATH' (e.g. \
     'POST /v1/projects'). Without `endpoint`, returns every route's \
     storyline. Requires a workspace scan to have been run first via \
     POST /v1/workspace/scan."
}

pub fn input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "endpoint": {
                "type": "string",
                "description": "Optional 'METHOD PATH' filter (e.g. 'POST /v1/projects'). Without this, every route's storyline is returned."
            },
            "format": {
                "type": "string",
                "enum": ["tree", "json"],
                "description": "Output format: 'tree' (default, ASCII tree-art for LLM consumption) or 'json' (compact integer-keyed graph for traversal)."
            },
            "include_tests": {
                "type": "boolean",
                "default": false,
                "description": "Include edges that point at test files (paths under tests/, ending _tests.rs or tests.rs, or carrying #![cfg(test)]). Default false — test code skews density metrics."
            }
        },
        "examples": [
            { "endpoint": "POST /v1/projects" },
            { "format": "json" },
            { "include_tests": true },
            { }
        ]
    })
}

pub async fn handle_get_workspace_storyline(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let Some(base_url) = ctx.daemon_base_url.as_deref() else {
        return Err(JsonRpcError {
            code: INTERNAL_ERROR,
            message: "get_workspace_storyline: daemon_base_url not configured; \
                      the MCP server was not wired to corecruxd"
                .to_string(),
            data: None,
        });
    };

    let format = args.get("format").and_then(Value::as_str).unwrap_or("tree").to_string();
    if !matches!(format.as_str(), "tree" | "json") {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "get_workspace_storyline: format must be 'tree' or 'json'".into(),
            data: None,
        });
    }
    let endpoint = args.get("endpoint").and_then(Value::as_str).map(|s| s.to_string());
    let include_tests = args.get("include_tests").and_then(Value::as_bool).unwrap_or(false);

    // Build the URL with manual query encoding (no extra dep needed).
    let mut url = format!(
        "{}/v1/workspace/storyline?format={}&include_tests={}",
        base_url.trim_end_matches('/'),
        format,
        if include_tests { "1" } else { "0" }
    );
    if let Some(ep) = endpoint {
        // URL-encode just space + the obvious specials; the rest are
        // path-safe chars used in route templates.
        let encoded: String = ep
            .chars()
            .map(|c| match c {
                ' ' => "%20".to_string(),
                '#' => "%23".to_string(),
                '?' => "%3F".to_string(),
                '&' => "%26".to_string(),
                _ => c.to_string(),
            })
            .collect();
        use std::fmt::Write;
        let _ = write!(url, "&root={encoded}");
    }

    let bearer = crate::tools::loopback_auth::loopback_bearer_token();
    let response = tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(15)))
            .build()
            .into();
        let mut req = agent
            .get(&url)
            // Loopback to the same daemon: `X-Corecrux-Scopes` is consumed by
            // `AuthMode::DevScopes`; `Authorization: Bearer` is required in
            // `AuthMode::JwtHs256` / `JwtJwks`. Send both so the call works
            // across all auth modes — see `tools::loopback_auth`.
            .header("X-Corecrux-Scopes", "admin:read")
            .header("Accept", "*/*");
        if let Some(token) = &bearer {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        req.call()
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
        message: format!("get_workspace_storyline: join error: {e}"),
        data: None,
    })?;

    let (status, body_text) = response.map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("get_workspace_storyline: loopback request failed: {e}"),
        data: None,
    })?;

    if status == 404 {
        return Err(JsonRpcError {
            code: INTERNAL_ERROR,
            message: format!(
                "get_workspace_storyline: no scan available — POST /v1/workspace/scan first. \
                 Server said: {}",
                truncate(&body_text, 240)
            ),
            data: None,
        });
    }
    if status != 200 {
        return Err(JsonRpcError {
            code: INTERNAL_ERROR,
            message: format!(
                "get_workspace_storyline: corecruxd returned {status}: {}",
                truncate(&body_text, 512)
            ),
            data: None,
        });
    }

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

    #[test]
    fn description_mentions_both_formats() {
        let d = description();
        assert!(d.contains("tree"));
        assert!(d.contains("json"));
        assert!(d.contains("workspace scan"));
    }

    #[test]
    fn schema_lists_endpoint_and_format() {
        let s = input_schema();
        let props = s.get("properties").and_then(Value::as_object).expect("props");
        assert!(props.contains_key("endpoint"));
        assert!(props.contains_key("format"));
    }

    #[tokio::test]
    async fn rejects_invalid_format() {
        let ctx = McpContext::new_default("test-node");
        // Need daemon_base_url set, otherwise we get a different error first.
        let mut ctx = ctx;
        ctx.daemon_base_url = Some("http://127.0.0.1:1".to_string());
        let err = handle_get_workspace_storyline(&json!({ "format": "xml" }), &ctx)
            .await
            .expect_err("must reject");
        assert!(err.message.contains("format must be"), "msg was: {}", err.message);
    }
}
