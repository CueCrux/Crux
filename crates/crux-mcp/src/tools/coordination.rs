// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Coordination MCP tools — projects, work items, comments.
//!
//! All handlers wrap loopback HTTP calls to the daemon's `/v1/projects`,
//! `/v1/work`, and related endpoints. The MCP server is co-located with
//! corecruxd, so the loopback round-trip is sub-millisecond and lets the
//! tools stay thin (no duplicated state or schema logic).

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};

const SCOPES: &str = "admin:read,facts:write";

use crate::tools::loopback_auth::loopback_bearer_token;

pub const LIST_PROJECTS_DESCRIPTION: &str =
    "List all projects defined on this daemon. Each project carries a planning_target (a tenant or a github repo URL), a default_passport_id, and counts of members + working tenants.";

pub const GET_PROJECT_CONTEXT_DESCRIPTION: &str =
    "Get full detail for a single project: planning target, allowed passports, working tenants, and recent work counts.";

pub const LIST_WORK_DESCRIPTION: &str =
    "List work items, optionally filtered by project_id, state (planned/in_progress/blocked/archive/complete/deployed), tenant_id, or assignee_passport. Use this to learn what other agents have queued, are working on, or have shipped — the kanban surface that makes agent collaboration possible.";

pub const CREATE_WORK_DESCRIPTION: &str =
    "Create a new work item under a project. `project_id` must be an EXISTING project id (call list_projects first — there is no implicit 'default' project; an unknown id returns 'project not found'). Defaults: state=planned, assignee=current passport. Use this to record a unit of work you're about to take on (or one you're proposing for another agent or human to pick up).";

pub const UPDATE_WORK_STATE_DESCRIPTION: &str =
    "Move a work item to a new state. If your passport has agent_work_gate=true, the move queues for human approval (response status 202) instead of applying directly.";

pub const COMMENT_ON_WORK_DESCRIPTION: &str =
    "Post a comment on a work item. Use this to leave context for the next agent or human — what you tried, what blocked, what's next.";

pub const COORD_STATUS_DESCRIPTION: &str =
    "See which other agent sessions are live RIGHT NOW and what each is doing: presence heartbeat, declared focus (execplan/milestone/paths), punchcard leases held, and work items in flight. Call at session start and before editing files another session may be touching. Requires CORECRUXD_COORD=1 on the daemon.";

pub const COORD_ANNOUNCE_DESCRIPTION: &str =
    "Declare what this session is working on (execplan slug, milestone, paths, free-text note) so concurrent sessions can coordinate. Re-announce whenever your focus changes; pass ttl_seconds=0 to clear on the way out. The intent is stored as a private fact attributed to your session's passport. Requires CORECRUXD_COORD=1 on the daemon.";

pub(crate) fn loopback_base(ctx: &McpContext) -> Result<String, JsonRpcError> {
    ctx.daemon_base_url
        .as_deref()
        .map(|s| s.trim_end_matches('/').to_string())
        .ok_or_else(|| JsonRpcError {
            code: INTERNAL_ERROR,
            message: "daemon_base_url not configured; coordination tools require loopback to corecruxd".to_string(),
            data: None,
        })
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

/// Build the loopback HTTP agent. `http_status_as_error(false)` is the crux of
/// the error-surfacing behaviour: ureq otherwise raises a 4xx/5xx as an opaque
/// `StatusCode` error and never reads the body, flattening the daemon's
/// problem+json detail (`"project not found"`, `"passport 'x' not found"`,
/// validation messages) to a bare `"status NNN"`. With it OFF, error responses
/// come back as a normal response whose body we read and surface.
fn loopback_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(10)))
        .http_status_as_error(false)
        .build()
        .into()
}

/// Turn a NON-success daemon response into a `JsonRpcError` that carries the
/// daemon's own error detail so the agent sees WHY the call failed, not just the
/// code. Prefers the structured `detail`/`error`/`message`/`title` field of a
/// problem+json / error body, falling back to the raw (truncated) body.
fn loopback_status_error(status: u16, body: &str) -> JsonRpcError {
    let detail = serde_json::from_str::<Value>(body).ok().and_then(|v| {
        ["detail", "error", "message", "title"]
            .iter()
            .find_map(|k| v.get(*k).and_then(Value::as_str).map(str::to_string))
    });
    let message = match detail {
        Some(d) => format!("daemon returned {status}: {d}"),
        None if !body.trim().is_empty() => format!("daemon returned {status}: {}", truncate(body, 512)),
        None => format!("daemon returned {status}"),
    };
    JsonRpcError {
        code: INTERNAL_ERROR,
        message,
        data: Some(json!({ "status": status, "body": truncate(body, 1024) })),
    }
}

/// Unwrap the `spawn_blocking` join + transport-level result into `(status,
/// body)`. With `http_status_as_error(false)` the inner `Err` is ONLY a
/// transport failure (connection refused, timeout) — never an HTTP status — so
/// it maps to a clear transport error distinct from a daemon status error.
fn loopback_transport_result(
    joined: Result<Result<(u16, String), String>, tokio::task::JoinError>,
) -> Result<(u16, String), JsonRpcError> {
    joined
        .map_err(|e| JsonRpcError {
            code: INTERNAL_ERROR,
            message: format!("loopback join error: {e}"),
            data: None,
        })?
        .map_err(|transport| JsonRpcError {
            code: INTERNAL_ERROR,
            message: format!("loopback transport error: {transport}"),
            data: None,
        })
}

/// `true` when a status code is a success for the given verb contract. POST
/// honours `expect_201`; all other verbs accept any 2xx (200/202 in practice).
fn loopback_ok(status: u16, expect_201: bool) -> bool {
    if expect_201 {
        status == 201
    } else {
        (200..300).contains(&status)
    }
}

pub(crate) async fn loopback_get(url: String) -> Result<(u16, String), JsonRpcError> {
    let bearer = loopback_bearer_token();
    let joined = tokio::task::spawn_blocking(move || {
        let agent = loopback_agent();
        let mut req = agent
            .get(&url)
            .header("X-Corecrux-Scopes", SCOPES)
            .header("Accept", "application/json");
        if let Some(token) = &bearer {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        req.call()
            .map(|mut r| (r.status().as_u16(), r.body_mut().read_to_string().unwrap_or_default()))
            .map_err(|e| e.to_string())
    })
    .await;
    let (status, body) = loopback_transport_result(joined)?;
    if loopback_ok(status, false) {
        Ok((status, body))
    } else {
        Err(loopback_status_error(status, &body))
    }
}

pub(crate) async fn loopback_post(
    url: String,
    body: Value,
    expect_201: bool,
    passport: Option<String>,
) -> Result<(u16, String), JsonRpcError> {
    let bearer = loopback_bearer_token();
    let joined = tokio::task::spawn_blocking(move || {
        let agent = loopback_agent();
        let mut req = agent
            .post(&url)
            .header("X-Corecrux-Scopes", SCOPES)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json");
        if let Some(token) = &bearer {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        // Forward the bound session passport so the daemon attributes the write
        // to a real principal instead of falling back to "anonymous" (the
        // loopback JWT's `sub` carries no passport claim). Honoured by
        // `corecruxd::auth::http_passport_id`.
        if let Some(pid) = &passport {
            req = req.header("X-Corecrux-Passport-Id", pid);
        }
        req.send(body.to_string())
            .map(|mut r| (r.status().as_u16(), r.body_mut().read_to_string().unwrap_or_default()))
            .map_err(|e| e.to_string())
    })
    .await;
    let (status, resp_body) = loopback_transport_result(joined)?;
    if loopback_ok(status, expect_201) {
        Ok((status, resp_body))
    } else {
        Err(loopback_status_error(status, &resp_body))
    }
}

pub(crate) async fn loopback_patch(
    url: String,
    body: Value,
    passport: Option<String>,
) -> Result<(u16, String), JsonRpcError> {
    let bearer = loopback_bearer_token();
    let joined = tokio::task::spawn_blocking(move || {
        let agent = loopback_agent();
        // PATCH was the ONE loopback helper missing the bearer token — every
        // other verb (get/post/delete) attaches it. Under JWT auth modes that
        // omission produced a 401 on update_work_state (the only PATCH caller).
        let mut request = agent
            .patch(&url)
            .header("X-Corecrux-Scopes", SCOPES)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json");
        if let Some(token) = &bearer {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        if let Some(pid) = &passport {
            request = request.header("X-Corecrux-Passport-Id", pid);
        }
        request
            .send(body.to_string())
            .map(|mut r| (r.status().as_u16(), r.body_mut().read_to_string().unwrap_or_default()))
            .map_err(|e| e.to_string())
    })
    .await;
    let (status, resp_body) = loopback_transport_result(joined)?;
    if loopback_ok(status, false) {
        Ok((status, resp_body))
    } else {
        Err(loopback_status_error(status, &resp_body))
    }
}

pub(crate) async fn loopback_delete(url: String, passport: Option<String>) -> Result<(u16, String), JsonRpcError> {
    let bearer = loopback_bearer_token();
    let joined = tokio::task::spawn_blocking(move || {
        let agent = loopback_agent();
        let mut request = agent
            .delete(&url)
            .header("X-Corecrux-Scopes", SCOPES)
            .header("Accept", "application/json");
        if let Some(token) = &bearer {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        if let Some(pid) = &passport {
            request = request.header("X-Corecrux-Passport-Id", pid);
        }
        request
            .call()
            .map(|mut r| (r.status().as_u16(), r.body_mut().read_to_string().unwrap_or_default()))
            .map_err(|e| e.to_string())
    })
    .await;
    let (status, body) = loopback_transport_result(joined)?;
    if loopback_ok(status, false) {
        Ok((status, body))
    } else {
        Err(loopback_status_error(status, &body))
    }
}

pub(crate) fn text_content(value: Value) -> Value {
    json!({
        "content": [
            { "type": "text", "text": value.to_string() }
        ]
    })
}

pub async fn handle_list_projects(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let base = loopback_base(ctx)?;
    let (_, body) = loopback_get(format!("{base}/v1/projects")).await?;
    Ok(text_content(serde_json::from_str(&body).unwrap_or(Value::String(body))))
}

pub async fn handle_get_project_context(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let id = args
        .get("project_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "get_project_context: project_id is required".to_string(),
            data: None,
        })?;
    let base = loopback_base(ctx)?;
    let (_, body) = loopback_get(format!("{base}/v1/projects/{id}")).await?;
    Ok(text_content(serde_json::from_str(&body).unwrap_or(Value::String(body))))
}

pub async fn handle_list_work(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let mut params = Vec::new();
    for key in ["project_id", "state", "tenant_id", "assignee_passport"] {
        if let Some(v) = args.get(key).and_then(|v| v.as_str()) {
            params.push(format!("{key}={}", urlencoding(v)));
        }
    }
    let qs = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    };
    let base = loopback_base(ctx)?;
    let (_, body) = loopback_get(format!("{base}/v1/work{qs}")).await?;
    Ok(text_content(serde_json::from_str(&body).unwrap_or(Value::String(body))))
}

pub async fn handle_create_work(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let project_id = args
        .get("project_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "create_work: project_id is required".to_string(),
            data: None,
        })?;
    let title = args.get("title").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "create_work: title is required".to_string(),
        data: None,
    })?;
    let created_by = args
        .get("created_by_passport")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "create_work: created_by_passport is required (use the passport bound to your session)"
                .to_string(),
            data: None,
        })?;
    let mut body = json!({
        "project_id": project_id,
        "title": title,
        "created_by_passport": created_by,
    });
    for key in [
        "body",
        "state",
        "assignee_passport",
        "tenant_id",
        "linked_pr",
        "linked_issue",
    ] {
        if let Some(v) = args.get(key) {
            body[key] = v.clone();
        }
    }
    let base = loopback_base(ctx)?;
    let (_, resp_body) = loopback_post(format!("{base}/v1/work"), body, true, ctx.scope_identity()).await?;
    Ok(text_content(
        serde_json::from_str(&resp_body).unwrap_or(Value::String(resp_body)),
    ))
}

pub async fn handle_update_work_state(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let id = args
        .get("work_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "update_work_state: work_id is required".to_string(),
            data: None,
        })?;
    let new_state = args.get("state").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "update_work_state: state is required (planned|in_progress|blocked|archive|complete|deployed)"
            .to_string(),
        data: None,
    })?;
    let by = args
        .get("by_passport")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "update_work_state: by_passport is required".to_string(),
            data: None,
        })?;
    let mut body = json!({
        "state": new_state,
        "by_passport": by,
    });
    if let Some(reason) = args.get("blocker_reason") {
        body["blocker_reason"] = reason.clone();
    }
    let base = loopback_base(ctx)?;
    let (_, resp_body) = loopback_patch(format!("{base}/v1/work/{id}"), body, ctx.scope_identity()).await?;
    Ok(text_content(
        serde_json::from_str(&resp_body).unwrap_or(Value::String(resp_body)),
    ))
}

pub async fn handle_comment_on_work(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let id = args
        .get("work_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "comment_on_work: work_id is required".to_string(),
            data: None,
        })?;
    let author = args
        .get("author_passport")
        .and_then(|v| v.as_str())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "comment_on_work: author_passport is required".to_string(),
            data: None,
        })?;
    let body_text = args.get("body").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "comment_on_work: body is required".to_string(),
        data: None,
    })?;
    let payload = json!({
        "author_passport": author,
        "body": body_text,
    });
    let base = loopback_base(ctx)?;
    let (_, resp_body) = loopback_post(
        format!("{base}/v1/work/{id}/comments"),
        payload,
        true,
        ctx.scope_identity(),
    )
    .await?;
    Ok(text_content(
        serde_json::from_str(&resp_body).unwrap_or(Value::String(resp_body)),
    ))
}

pub async fn handle_coord_status(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let qs = match args
        .get("project_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(pid) => format!("?project_id={}", urlencoding(pid)),
        None => String::new(),
    };
    let base = loopback_base(ctx)?;
    let (_, body) = loopback_get(format!("{base}/v1/coord/active{qs}")).await?;
    Ok(text_content(serde_json::from_str(&body).unwrap_or(Value::String(body))))
}

pub async fn handle_coord_announce(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let mut payload = json!({});
    for key in ["session_id", "project_id"] {
        let v = args.get(key).and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("coord_announce: {key} is required"),
            data: None,
        })?;
        payload[key] = json!(v);
    }
    for key in [
        "by_passport",
        "execplan_slug",
        "milestone",
        "paths",
        "note",
        "ttl_seconds",
    ] {
        if let Some(v) = args.get(key) {
            payload[key] = v.clone();
        }
    }
    let base = loopback_base(ctx)?;
    let (_, resp_body) = loopback_post(
        format!("{base}/v1/coord/announce"),
        payload,
        false,
        ctx.scope_identity(),
    )
    .await?;
    Ok(text_content(
        serde_json::from_str(&resp_body).unwrap_or(Value::String(resp_body)),
    ))
}

fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::time::Duration;

    #[test]
    fn urlencoding_handles_special_chars() {
        assert_eq!(urlencoding("work::team"), "work%3A%3Ateam");
        assert_eq!(urlencoding("alphanum-123"), "alphanum-123");
    }

    fn serve_coordination_loopback() -> (String, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind coordination loopback");
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
                let mut parts = req.lines().next().unwrap_or_default().split_whitespace();
                let method = parts.next().unwrap_or_default();
                let path = parts.next().unwrap_or_default();

                let (status, body) = match (method, path) {
                    ("GET", "/v1/projects") => (
                        200,
                        r#"{"projects":[{"id":"alpha","name":"Alpha","planning_target":"tenant://alpha","default_passport_id":"p1"}]}"#,
                    ),
                    ("GET", "/v1/projects/alpha") => (
                        200,
                        r#"{"id":"alpha","members":[{"passport_id":"p1","role":"owner"}],"tenants":[{"tenant_id":"tenant-a"}]}"#,
                    ),
                    ("GET", p) if p.starts_with("/v1/work") => (
                        200,
                        r#"{"count":1,"work":[{"id":"w1","project_id":"alpha","state":"planned","tenant_id":"tenant-a"}]}"#,
                    ),
                    ("POST", "/v1/work") => (
                        201,
                        r#"{"id":"w1","project_id":"alpha","state":"planned","created_by_passport":"p1"}"#,
                    ),
                    ("PATCH", "/v1/work/w1") => (200, r#"{"applied":true,"work":{"id":"w1","state":"in_progress"}}"#),
                    ("POST", "/v1/work/w1/comments") => (
                        201,
                        r#"{"id":"c1","work_id":"w1","author_passport":"p1","body":"note"}"#,
                    ),
                    ("GET", p) if p.starts_with("/v1/coord/active") => (
                        200,
                        r#"{"now_unix_ms":1,"presence_ttl_secs":900,"active_sessions":[{"session_id_hex":"aaaa","passport_id":"p1"}],"work_in_flight":[]}"#,
                    ),
                    ("POST", "/v1/coord/announce") => (
                        200,
                        r#"{"intent":{"project_id":"alpha","session_id_hex":"aaaa","passport_id":"p1","execplan_slug":"plan-x"},"cleared":false}"#,
                    ),
                    _ => (404, r#"{"error":"not found"}"#),
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
    async fn coordination_handlers_call_loopback_endpoints() {
        let (base, stop, handle) = serve_coordination_loopback();
        let ctx = McpContext::new_default("node-a").with_daemon_base_url(base.clone());

        let projects = text_json(handle_list_projects(&json!({}), &ctx).await.expect("list projects"));
        assert_eq!(projects["projects"][0]["id"], "alpha");

        let project = text_json(
            handle_get_project_context(&json!({"project_id": "alpha"}), &ctx)
                .await
                .expect("project"),
        );
        assert_eq!(project["id"], "alpha");

        let work = text_json(
            handle_list_work(
                &json!({
                    "project_id": "alpha",
                    "state": "planned",
                    "tenant_id": "tenant-a",
                    "assignee_passport": "p1"
                }),
                &ctx,
            )
            .await
            .expect("list work"),
        );
        assert_eq!(work["count"], 1);

        let created = text_json(
            handle_create_work(
                &json!({
                    "project_id": "alpha",
                    "title": "Ship coverage",
                    "body": "exercise loopback",
                    "state": "planned",
                    "created_by_passport": "p1"
                }),
                &ctx,
            )
            .await
            .expect("create work"),
        );
        assert_eq!(created["id"], "w1");

        let updated = text_json(
            handle_update_work_state(
                &json!({
                    "work_id": "w1",
                    "state": "in_progress",
                    "by_passport": "p1",
                    "blocker_reason": "none"
                }),
                &ctx,
            )
            .await
            .expect("update work"),
        );
        assert_eq!(updated["applied"], true);

        let comment = text_json(
            handle_comment_on_work(
                &json!({
                    "work_id": "w1",
                    "author_passport": "p1",
                    "body": "covered"
                }),
                &ctx,
            )
            .await
            .expect("comment"),
        );
        assert_eq!(comment["work_id"], "w1");

        let status = text_json(
            handle_coord_status(&json!({"project_id": "alpha"}), &ctx)
                .await
                .expect("coord status"),
        );
        assert_eq!(status["active_sessions"][0]["session_id_hex"], "aaaa");

        let announced = text_json(
            handle_coord_announce(
                &json!({
                    "session_id": "aaaa",
                    "project_id": "alpha",
                    "execplan_slug": "plan-x",
                    "milestone": "M3",
                    "paths": ["crates/crux-mcp/src/tools/coordination.rs"]
                }),
                &ctx,
            )
            .await
            .expect("coord announce"),
        );
        assert_eq!(announced["intent"]["execplan_slug"], "plan-x");
        assert_eq!(announced["cleared"], false);

        // Required-arg validation does not hit the network.
        assert_eq!(
            handle_coord_announce(&json!({"project_id": "alpha"}), &ctx)
                .await
                .expect_err("missing session_id")
                .code,
            INVALID_PARAMS
        );

        stop_loopback(&base, stop, handle);
    }

    /// Loopback stub whose PATCH route returns 401 unless the request carries
    /// an `Authorization: Bearer` header — directly encoding the M3 fix.
    fn serve_patch_requires_auth() -> (String, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind patch-auth loopback");
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
                let method = req
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .split_whitespace()
                    .next()
                    .unwrap_or_default();
                let has_bearer = req.to_ascii_lowercase().contains("authorization: bearer ");
                let (status, body) = if method == "PATCH" && !has_bearer {
                    (401, r#"{"error":"missing bearer"}"#)
                } else {
                    (200, r#"{"applied":true,"work":{"id":"w1","state":"in_progress"}}"#)
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

    /// Loopback stub whose POST /v1/work echoes the received
    /// `X-Corecrux-Passport-Id` header into the response body.
    fn serve_capture_passport() -> (String, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind passport loopback");
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
                let seen = req
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("x-corecrux-passport-id:"))
                    .and_then(|l| l.split_once(':'))
                    .map(|(_, v)| v.trim().to_string())
                    .unwrap_or_default();
                let body = format!(r#"{{"id":"w1","seen_passport":"{seen}"}}"#);
                let response = format!(
                    "HTTP/1.1 201 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        (base, stop, handle)
    }

    #[tokio::test]
    async fn create_work_forwards_session_passport_header() {
        // Probe finding 4: loopback writes must forward the bound session
        // passport so the daemon attributes the write to a real principal.
        let (base, stop, handle) = serve_capture_passport();
        let ctx = McpContext::new_default("node-a")
            .with_daemon_base_url(base.clone())
            .with_agent(crate::agent::AgentIdentity {
                name: "anthropic".to_string(),
                token_hash: [0u8; 32],
            });
        let created = text_json(
            handle_create_work(
                &json!({"project_id": "p", "title": "t", "created_by_passport": "ce:x"}),
                &ctx,
            )
            .await
            .expect("create_work"),
        );
        stop_loopback(&base, stop, handle);
        assert_eq!(
            created["seen_passport"], "anthropic",
            "loopback POST must forward X-Corecrux-Passport-Id from the session"
        );
    }

    #[tokio::test]
    async fn update_work_state_patch_attaches_bearer() {
        // Probe finding 5: PATCH must carry the loopback bearer (it was the one
        // helper missing it → 401). Force the raw-token fallback so a token is
        // available regardless of JWT-secret env.
        let _lock = crate::test_env_lock().lock().await;
        std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
        std::env::set_var("CRUX_AGENT_TOKEN", "tok_test_patch_m3");

        let (base, stop, handle) = serve_patch_requires_auth();
        let ctx = McpContext::new_default("node-a").with_daemon_base_url(base.clone());
        let res = handle_update_work_state(
            &json!({"work_id": "w1", "state": "in_progress", "by_passport": "p1"}),
            &ctx,
        )
        .await;
        stop_loopback(&base, stop, handle);
        std::env::remove_var("CRUX_AGENT_TOKEN");

        let updated = text_json(res.expect("patch with bearer should succeed (not 401)"));
        assert_eq!(updated["applied"], true);
    }

    /// Loopback stub that returns a 404 problem+json body on POST /v1/work,
    /// mirroring the daemon's real "project not found" response.
    fn serve_problem_json() -> (String, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind problem loopback");
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
                let _ = crate::tools::test_support::read_full_request(&mut stream);
                let body = r#"{"type":"about:blank","title":"Not Found","status":404,"detail":"project not found"}"#;
                let response = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Type: application/problem+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        (base, stop, handle)
    }

    #[tokio::test]
    async fn loopback_error_surfaces_daemon_problem_detail() {
        // Probe finding 11 (deep fix): a daemon 4xx must surface its problem+json
        // `detail`, not a bare "status 404". Disabling ureq's http_status_as_error
        // is what lets the body through.
        let (base, stop, handle) = serve_problem_json();
        let ctx = McpContext::new_default("node-a").with_daemon_base_url(base.clone());
        let err = handle_create_work(
            &json!({"project_id": "ghost", "title": "t", "created_by_passport": "p1"}),
            &ctx,
        )
        .await
        .expect_err("unknown project must error");
        stop_loopback(&base, stop, handle);
        assert!(
            err.message.contains("project not found"),
            "error must carry the daemon detail, got: {}",
            err.message
        );
        assert_eq!(
            err.data.as_ref().and_then(|d| d.get("status")).and_then(|s| s.as_u64()),
            Some(404)
        );
    }

    #[tokio::test]
    async fn coordination_handlers_validate_required_arguments() {
        let ctx = McpContext::new_default("node-a").with_daemon_base_url("http://127.0.0.1:9");
        assert_eq!(
            handle_get_project_context(&json!({}), &ctx)
                .await
                .expect_err("missing project")
                .code,
            INVALID_PARAMS
        );
        assert_eq!(
            handle_create_work(&json!({"project_id": "alpha"}), &ctx)
                .await
                .expect_err("missing title")
                .code,
            INVALID_PARAMS
        );
        assert_eq!(
            handle_update_work_state(&json!({"work_id": "w1"}), &ctx)
                .await
                .expect_err("missing state")
                .code,
            INVALID_PARAMS
        );
        assert_eq!(
            handle_comment_on_work(&json!({"work_id": "w1", "author_passport": "p1"}), &ctx)
                .await
                .expect_err("missing body")
                .code,
            INVALID_PARAMS
        );
    }
}
