// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Orchestrator MCP tools (orchestrators plan).
//!
//! Thin loopback wrappers over the daemon's `/v1/orchestrators/*` surface,
//! mirroring the `coordination.rs` pattern.
//!
//! The HTTP surface is **implemented** — seven handlers persisting to the
//! entity store under `ORCHESTRATOR_KIND` — and feature-flagged off by default
//! behind `CORECRUXD_ORCHESTRATORS`, the same posture as `CORECRUXD_COORD` and
//! `CORECRUXD_PUNCHCARD`. With the flag off every route answers a 501 naming
//! the variable to set.
//!
//! This comment previously read "the HTTP endpoints are stubs today … by design
//! for the Package S scaffold". That was true when the MCP wrappers were
//! written and stopped being true when the endpoints landed; nothing updated
//! it. A 2026-08-06 audit read it, concluded the tools were unimplemented
//! scaffolding advertised for no reason, and proposed removing them from the
//! surface — which would have made a working feature undiscoverable to any
//! operator who enables the flag. A stale doc comment is a live hazard when it
//! describes capability.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use crate::tools::coordination::{
    loopback_base, loopback_delete, loopback_get_scoped, loopback_patch, loopback_post, text_content,
};

pub const CREATE_ORCHESTRATOR_DESCRIPTION: &str =
    "Create a multi-agent orchestrator — a coordinator that groups work items and member passports under one umbrella. Returns the minted orchestrator record. Requires CORECRUXD_ORCHESTRATORS=1 on the daemon.";

pub const ATTACH_TO_ORCHESTRATOR_DESCRIPTION: &str =
    "Attach a member to an orchestrator's roster. `member_ref` may be a work item id (w_…), an execplan id (execplan:…), a handoff id (ho_…), or a passport (id like `claude-work`, or principal_id like `ce:…:local`). The member type is inferred from the ref; pass an explicit `member_type` (passport|work|execplan|handoff) to override. Requires CORECRUXD_ORCHESTRATORS=1 on the daemon.";

pub const DETACH_FROM_ORCHESTRATOR_DESCRIPTION: &str =
    "Detach a member from an orchestrator. Requires CORECRUXD_ORCHESTRATORS=1 on the daemon.";

pub const LIST_ORCHESTRATORS_DESCRIPTION: &str =
    "List orchestrators defined on this daemon, optionally filtered by tenant_id or state. Requires CORECRUXD_ORCHESTRATORS=1 on the daemon.";

pub const UPDATE_ORCHESTRATOR_DESCRIPTION: &str =
    "Update an orchestrator's name, assignee_passport, or state (planned|active|done|archived). Use state=archived to close out an orchestrator. Returns the updated record. Requires CORECRUXD_ORCHESTRATORS=1 on the daemon.";

fn required_str<'a>(args: &'a Value, key: &str, tool: &str) -> Result<&'a str, JsonRpcError> {
    args.get(key).and_then(Value::as_str).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("{tool}: {key} is required"),
        data: None,
    })
}

fn authority_identity(ctx: &McpContext, tool: &str) -> Result<String, JsonRpcError> {
    ctx.authority_identity().ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("{tool}: authenticated MCP authority is required"),
        data: None,
    })
}

fn claimed_identity_matches(ctx: &McpContext, claimed: &str, authority: &str) -> bool {
    claimed == authority || ctx.scope_identity().as_deref() == Some(claimed)
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
    let claimed_created_by = required_str(args, "created_by_passport", "create_orchestrator")?;
    let identity = authority_identity(ctx, "create_orchestrator")?;
    if !claimed_identity_matches(ctx, claimed_created_by, &identity) {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "create_orchestrator: created_by_passport does not match the authenticated MCP agent".to_string(),
            data: None,
        });
    }
    let tenant = ctx.scope_tenant();
    if args
        .get("tenant_id")
        .and_then(Value::as_str)
        .is_some_and(|requested| requested != tenant)
    {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "create_orchestrator: tenant_id does not match the authenticated MCP agent".to_string(),
            data: None,
        });
    }
    let mut body = json!({
        "name": name,
        "created_by_passport": identity,
        "tenant_id": tenant,
    });
    for key in ["assignee_passport", "state"] {
        if let Some(v) = args.get(key) {
            body[key] = v.clone();
        }
    }
    let base = loopback_base(ctx)?;
    let (_, resp) = loopback_post(
        format!("{base}/v1/orchestrators"),
        body,
        true,
        ctx.authority_identity(),
        Some(ctx.scope_tenant()),
    )
    .await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

pub async fn handle_attach_to_orchestrator(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let id = required_str(args, "orchestrator_id", "attach_to_orchestrator")?;
    let member = required_str(args, "member_ref", "attach_to_orchestrator")?;
    let mut body = json!({ "member_ref": member });
    // Optional explicit type (passport|work|execplan|handoff). When omitted the
    // daemon infers it from the ref (id prefix, else passport-store lookup).
    if let Some(t) = args.get("member_type").and_then(Value::as_str) {
        body["type"] = json!(t);
    }
    let base = loopback_base(ctx)?;
    let (_, resp) = loopback_post(
        format!("{base}/v1/orchestrators/{id}/members"),
        body,
        false,
        ctx.authority_identity(),
        Some(ctx.scope_tenant()),
    )
    .await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

pub async fn handle_detach_from_orchestrator(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let id = required_str(args, "orchestrator_id", "detach_from_orchestrator")?;
    let member = required_str(args, "member_ref", "detach_from_orchestrator")?;
    let base = loopback_base(ctx)?;
    let url = format!("{base}/v1/orchestrators/{id}/members/{}", urlencoding(member));
    let (_, resp) = loopback_delete(url, ctx.authority_identity(), Some(ctx.scope_tenant())).await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

pub async fn handle_list_orchestrators(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let tenant = ctx.scope_tenant();
    if args
        .get("tenant_id")
        .and_then(Value::as_str)
        .is_some_and(|requested| requested != tenant)
    {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "list_orchestrators: tenant_id does not match the authenticated MCP agent".to_string(),
            data: None,
        });
    }
    let mut params = Vec::new();
    params.push(format!("tenant_id={}", urlencoding(&tenant)));
    if let Some(state) = args.get("state").and_then(Value::as_str) {
        params.push(format!("state={}", urlencoding(state)));
    }
    let qs = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    };
    let base = loopback_base(ctx)?;
    let (_, resp) = loopback_get_scoped(
        format!("{base}/v1/orchestrators{qs}"),
        ctx.authority_identity(),
        Some(tenant),
    )
    .await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

pub async fn handle_update_orchestrator(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let id = required_str(args, "orchestrator_id", "update_orchestrator")?;
    let mut body = json!({});
    for key in ["name", "assignee_passport", "state"] {
        if let Some(v) = args.get(key) {
            body[key] = v.clone();
        }
    }
    if body.as_object().is_some_and(|o| o.is_empty()) {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "update_orchestrator: pass at least one of name, assignee_passport, state".to_string(),
            data: None,
        });
    }
    let base = loopback_base(ctx)?;
    let (_, resp) = loopback_patch(
        format!("{base}/v1/orchestrators/{id}"),
        body,
        ctx.authority_identity(),
        Some(ctx.scope_tenant()),
    )
    .await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::time::Duration;

    /// Every orchestrator tool must name its feature flag in its description.
    /// The surface advertises these whether or not `CORECRUXD_ORCHESTRATORS` is
    /// set, so without this the first an agent knows of the gate is a 501 from
    /// a tool it was invited to call. `coord_announce` already states its own
    /// flag this way; this pins the same convention rather than inventing one.
    #[test]
    fn every_orchestrator_description_names_its_feature_flag() {
        for (name, desc) in [
            ("create_orchestrator", CREATE_ORCHESTRATOR_DESCRIPTION),
            ("attach_to_orchestrator", ATTACH_TO_ORCHESTRATOR_DESCRIPTION),
            ("detach_from_orchestrator", DETACH_FROM_ORCHESTRATOR_DESCRIPTION),
            ("list_orchestrators", LIST_ORCHESTRATORS_DESCRIPTION),
            ("update_orchestrator", UPDATE_ORCHESTRATOR_DESCRIPTION),
        ] {
            assert!(
                desc.contains("CORECRUXD_ORCHESTRATORS=1"),
                "{name} description must name the flag that gates it: {desc}"
            );
        }
    }

    #[test]
    fn urlencoding_handles_special_chars() {
        assert_eq!(urlencoding("execplan:p"), "execplan%3Ap");
        assert_eq!(urlencoding("w_abc-123"), "w_abc-123");
    }

    fn serve_orchestrator_loopback() -> (String, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind orchestrator loopback");
        listener.set_nonblocking(true).expect("nonblocking loopback");
        let base = format!("http://{}", listener.local_addr().expect("addr"));
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                };
                let req = crate::tools::test_support::read_full_request(&mut stream);
                let mut lines = req.lines();
                let mut parts = lines.next().unwrap_or_default().split_whitespace();
                let method = parts.next().unwrap_or_default();
                let path = parts.next().unwrap_or_default();

                let (status, body) = match (method, path) {
                    ("POST", "/v1/orchestrators") => (
                        201,
                        r#"{"orchestrator":{"kind":"orchestrator","id":"orc_1","payload":{"id":"orc_1","name":"Coord","state":"planned","members":[]}}}"#,
                    ),
                    ("GET", p) if p.starts_with("/v1/orchestrators/orc_1/members") => (404, r#"{"detail":"unused"}"#),
                    ("PATCH", "/v1/orchestrators/orc_1") => (
                        200,
                        r#"{"orchestrator":{"id":"orc_1","payload":{"id":"orc_1","state":"archived"}}}"#,
                    ),
                    ("POST", "/v1/orchestrators/orc_1/members") if req.contains("\"type\":\"passport\"") => (
                        200,
                        r#"{"orchestrator":{"id":"orc_1","payload":{"members":[{"type":"passport","ref":"claude-work"}]}}}"#,
                    ),
                    ("POST", "/v1/orchestrators/orc_1/members") => (
                        200,
                        r#"{"orchestrator":{"id":"orc_1","payload":{"members":[{"type":"work","ref":"w_1"}]}}}"#,
                    ),
                    ("DELETE", p) if p.starts_with("/v1/orchestrators/orc_1/members/") => {
                        (200, r#"{"orchestrator":{"id":"orc_1","payload":{"members":[]}}}"#)
                    }
                    ("GET", p) if p.starts_with("/v1/orchestrators") => (
                        200,
                        r#"{"orchestrators":[{"id":"orc_1","payload":{"state":"planned"}}],"count":1}"#,
                    ),
                    _ => (404, r#"{"detail":"not found"}"#),
                };
                let response = format!(
                    "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        (base, stop, handle)
    }

    fn stop_loopback(base: &str, stop: Arc<AtomicBool>, handle: std::thread::JoinHandle<()>) {
        stop.store(true, Ordering::Relaxed);
        let _ = std::net::TcpStream::connect(base.trim_start_matches("http://"));
        handle.join().expect("loopback thread");
    }

    fn text_json(value: Value) -> Value {
        serde_json::from_str(value["content"][0]["text"].as_str().expect("text content")).expect("json text")
    }

    fn scoped_agent_context(base: String) -> McpContext {
        McpContext::new_default("node-a")
            .with_daemon_base_url(base)
            .with_agent_passports(
                true,
                crate::agent_passport::AgentPassportMap::from_pairs_str("p1:p1:tenant-a"),
            )
            .with_agent(crate::agent::AgentIdentity {
                name: "p1".to_string(),
                token_hash: [0u8; 32],
            })
    }

    #[tokio::test]
    async fn orchestrator_handlers_call_loopback_endpoints() {
        let (base, stop, handle) = serve_orchestrator_loopback();
        let ctx = scoped_agent_context(base.clone());

        let created = text_json(
            handle_create_orchestrator(
                &json!({ "name": "Coord", "created_by_passport": "p1", "tenant_id": "tenant-a" }),
                &ctx,
            )
            .await
            .expect("create"),
        );
        assert_eq!(created["orchestrator"]["id"], "orc_1");

        let attached = text_json(
            handle_attach_to_orchestrator(&json!({ "orchestrator_id": "orc_1", "member_ref": "w_1" }), &ctx)
                .await
                .expect("attach"),
        );
        assert_eq!(attached["orchestrator"]["payload"]["members"][0]["ref"], "w_1");

        let detached = text_json(
            handle_detach_from_orchestrator(&json!({ "orchestrator_id": "orc_1", "member_ref": "w_1" }), &ctx)
                .await
                .expect("detach"),
        );
        assert!(detached["orchestrator"]["payload"]["members"]
            .as_array()
            .unwrap()
            .is_empty());

        let listed = text_json(
            handle_list_orchestrators(&json!({ "tenant_id": "tenant-a", "state": "planned" }), &ctx)
                .await
                .expect("list"),
        );
        assert_eq!(listed["count"], 1);

        stop_loopback(&base, stop, handle);
    }

    #[tokio::test]
    async fn update_orchestrator_patches_via_loopback() {
        let (base, stop, handle) = serve_orchestrator_loopback();
        let ctx = McpContext::new_default("node-a").with_daemon_base_url(base.clone());
        let updated = text_json(
            handle_update_orchestrator(&json!({ "orchestrator_id": "orc_1", "state": "archived" }), &ctx)
                .await
                .expect("update"),
        );
        assert_eq!(updated["orchestrator"]["payload"]["state"], "archived");
        stop_loopback(&base, stop, handle);
    }

    #[tokio::test]
    async fn update_orchestrator_requires_a_field() {
        let ctx = McpContext::new_default("node-a").with_daemon_base_url("http://127.0.0.1:9");
        assert_eq!(
            handle_update_orchestrator(&json!({ "orchestrator_id": "orc_1" }), &ctx)
                .await
                .expect_err("no fields")
                .code,
            INVALID_PARAMS
        );
    }

    #[tokio::test]
    async fn attach_forwards_explicit_passport_member_type() {
        let (base, stop, handle) = serve_orchestrator_loopback();
        let ctx = McpContext::new_default("node-a").with_daemon_base_url(base.clone());
        let attached = text_json(
            handle_attach_to_orchestrator(
                &json!({ "orchestrator_id": "orc_1", "member_ref": "claude-work", "member_type": "passport" }),
                &ctx,
            )
            .await
            .expect("attach passport"),
        );
        assert_eq!(attached["orchestrator"]["payload"]["members"][0]["type"], "passport");
        assert_eq!(attached["orchestrator"]["payload"]["members"][0]["ref"], "claude-work");
        stop_loopback(&base, stop, handle);
    }

    #[tokio::test]
    async fn orchestrator_handlers_validate_required_arguments() {
        let ctx = McpContext::new_default("node-a").with_daemon_base_url("http://127.0.0.1:9");
        assert_eq!(
            handle_create_orchestrator(&json!({ "name": "x" }), &ctx)
                .await
                .expect_err("missing created_by")
                .code,
            INVALID_PARAMS
        );
        assert_eq!(
            handle_attach_to_orchestrator(&json!({ "orchestrator_id": "orc_1" }), &ctx)
                .await
                .expect_err("missing member_ref")
                .code,
            INVALID_PARAMS
        );
        assert_eq!(
            handle_detach_from_orchestrator(&json!({ "member_ref": "w_1" }), &ctx)
                .await
                .expect_err("missing orchestrator_id")
                .code,
            INVALID_PARAMS
        );
    }
}
