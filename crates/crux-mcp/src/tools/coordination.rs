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
    "Create a new work item under a project. Defaults: state=planned, assignee=current passport. Use this to record a unit of work you're about to take on (or one you're proposing for another agent or human to pick up).";

pub const UPDATE_WORK_STATE_DESCRIPTION: &str =
    "Move a work item to a new state. If your passport has agent_work_gate=true, the move queues for human approval (response status 202) instead of applying directly.";

pub const COMMENT_ON_WORK_DESCRIPTION: &str =
    "Post a comment on a work item. Use this to leave context for the next agent or human — what you tried, what blocked, what's next.";

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

pub(crate) async fn loopback_get(url: String) -> Result<(u16, String), JsonRpcError> {
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
        req.call()
            .map(|mut r| (r.status().as_u16(), r.body_mut().read_to_string().unwrap_or_default()))
            .map_err(|e| match e {
                ureq::Error::StatusCode(code) => (code, format!("status {code}")),
                other => (0, other.to_string()),
            })
    })
    .await
    .map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("loopback join error: {e}"),
        data: None,
    })?
    .map_err(|(code, message)| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("loopback request failed ({code}): {message}"),
        data: None,
    })
}

pub(crate) async fn loopback_post(url: String, body: Value, expect_201: bool) -> Result<(u16, String), JsonRpcError> {
    let bearer = loopback_bearer_token();
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(10)))
            .build()
            .into();
        let mut req = agent
            .post(&url)
            .header("X-Corecrux-Scopes", SCOPES)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json");
        if let Some(token) = &bearer {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        req.send(body.to_string())
            .map(|mut r| (r.status().as_u16(), r.body_mut().read_to_string().unwrap_or_default()))
            .map_err(|e| match e {
                ureq::Error::StatusCode(code) => (code, format!("status {code}")),
                other => (0, other.to_string()),
            })
    })
    .await
    .map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("loopback join error: {e}"),
        data: None,
    })
    .and_then(|res| {
        res.map_err(|(code, message)| JsonRpcError {
            code: INTERNAL_ERROR,
            message: format!("loopback request failed ({code}): {message}"),
            data: None,
        })
    })
    .and_then(|(status, body)| {
        if (expect_201 && status != 201) || (!expect_201 && status != 200 && status != 202) {
            Err(JsonRpcError {
                code: INTERNAL_ERROR,
                message: format!("daemon returned {status}: {}", truncate(&body, 512)),
                data: None,
            })
        } else {
            Ok((status, body))
        }
    })
}

async fn loopback_patch(url: String, body: Value) -> Result<(u16, String), JsonRpcError> {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(10)))
            .build()
            .into();
        let request = agent
            .patch(&url)
            .header("X-Corecrux-Scopes", SCOPES)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json");
        request
            .send(body.to_string())
            .map(|mut r| (r.status().as_u16(), r.body_mut().read_to_string().unwrap_or_default()))
            .map_err(|e| match e {
                ureq::Error::StatusCode(code) => (code, format!("status {code}")),
                other => (0, other.to_string()),
            })
    })
    .await
    .map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("loopback join error: {e}"),
        data: None,
    })?
    .map_err(|(code, message)| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("loopback request failed ({code}): {message}"),
        data: None,
    })
}

pub(crate) async fn loopback_delete(url: String) -> Result<(u16, String), JsonRpcError> {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(10)))
            .build()
            .into();
        let bearer = loopback_bearer_token();
        let mut request = agent
            .delete(&url)
            .header("X-Corecrux-Scopes", SCOPES)
            .header("Accept", "application/json");
        if let Some(token) = &bearer {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        request
            .call()
            .map(|mut r| (r.status().as_u16(), r.body_mut().read_to_string().unwrap_or_default()))
            .map_err(|e| match e {
                ureq::Error::StatusCode(code) => (code, format!("status {code}")),
                other => (0, other.to_string()),
            })
    })
    .await
    .map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("loopback join error: {e}"),
        data: None,
    })?
    .map_err(|(code, message)| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("loopback request failed ({code}): {message}"),
        data: None,
    })
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
    let (_, resp_body) = loopback_post(format!("{base}/v1/work"), body, true).await?;
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
    let (_, resp_body) = loopback_patch(format!("{base}/v1/work/{id}"), body).await?;
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
    let (_, resp_body) = loopback_post(format!("{base}/v1/work/{id}/comments"), payload, true).await?;
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
    use std::io::{Read as _, Write as _};
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
                let mut buf = [0u8; 8192];
                let read = stream.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..read]);
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

        stop_loopback(&base, stop, handle);
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
