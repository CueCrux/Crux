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
    let (_, resp) = loopback_post(format!("{base}/v1/orchestrators"), body, true, ctx.scope_identity()).await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

pub async fn handle_attach_to_orchestrator(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let id = required_str(args, "orchestrator_id", "attach_to_orchestrator")?;
    let member = required_str(args, "member_ref", "attach_to_orchestrator")?;
    let body = json!({ "member_ref": member });
    let base = loopback_base(ctx)?;
    let (_, resp) = loopback_post(
        format!("{base}/v1/orchestrators/{id}/members"),
        body,
        false,
        ctx.scope_identity(),
    )
    .await?;
    Ok(text_content(serde_json::from_str(&resp).unwrap_or(Value::String(resp))))
}

pub async fn handle_detach_from_orchestrator(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let id = required_str(args, "orchestrator_id", "detach_from_orchestrator")?;
    let member = required_str(args, "member_ref", "detach_from_orchestrator")?;
    let base = loopback_base(ctx)?;
    let url = format!("{base}/v1/orchestrators/{id}/members/{}", urlencoding(member));
    let (_, resp) = loopback_delete(url, ctx.scope_identity()).await?;
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::time::Duration;

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
                let mut buf = [0u8; 8192];
                let read = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..read]);
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

    #[tokio::test]
    async fn orchestrator_handlers_call_loopback_endpoints() {
        let (base, stop, handle) = serve_orchestrator_loopback();
        let ctx = McpContext::new_default("node-a").with_daemon_base_url(base.clone());

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
