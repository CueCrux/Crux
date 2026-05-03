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

fn loopback_base(ctx: &McpContext) -> Result<String, JsonRpcError> {
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

async fn loopback_get(url: String) -> Result<(u16, String), JsonRpcError> {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(10)))
            .build()
            .into();
        agent
            .get(&url)
            .header("X-Corecrux-Scopes", SCOPES)
            .header("Accept", "application/json")
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

async fn loopback_post(url: String, body: Value, expect_201: bool) -> Result<(u16, String), JsonRpcError> {
    tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(10)))
            .build()
            .into();
        agent
            .post(&url)
            .header("X-Corecrux-Scopes", SCOPES)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
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

fn text_content(value: Value) -> Value {
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
    let id = args.get("project_id").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
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
    let qs = if params.is_empty() { String::new() } else { format!("?{}", params.join("&")) };
    let base = loopback_base(ctx)?;
    let (_, body) = loopback_get(format!("{base}/v1/work{qs}")).await?;
    Ok(text_content(serde_json::from_str(&body).unwrap_or(Value::String(body))))
}

pub async fn handle_create_work(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let project_id = args.get("project_id").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "create_work: project_id is required".to_string(),
        data: None,
    })?;
    let title = args.get("title").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "create_work: title is required".to_string(),
        data: None,
    })?;
    let created_by = args.get("created_by_passport").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "create_work: created_by_passport is required (use the passport bound to your session)".to_string(),
        data: None,
    })?;
    let mut body = json!({
        "project_id": project_id,
        "title": title,
        "created_by_passport": created_by,
    });
    for key in ["body", "state", "assignee_passport", "tenant_id", "linked_pr", "linked_issue"] {
        if let Some(v) = args.get(key) {
            body[key] = v.clone();
        }
    }
    let base = loopback_base(ctx)?;
    let (_, resp_body) = loopback_post(format!("{base}/v1/work"), body, true).await?;
    Ok(text_content(serde_json::from_str(&resp_body).unwrap_or(Value::String(resp_body))))
}

pub async fn handle_update_work_state(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let id = args.get("work_id").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "update_work_state: work_id is required".to_string(),
        data: None,
    })?;
    let new_state = args.get("state").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "update_work_state: state is required (planned|in_progress|blocked|archive|complete|deployed)".to_string(),
        data: None,
    })?;
    let by = args.get("by_passport").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
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
    Ok(text_content(serde_json::from_str(&resp_body).unwrap_or(Value::String(resp_body))))
}

pub async fn handle_comment_on_work(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let id = args.get("work_id").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "comment_on_work: work_id is required".to_string(),
        data: None,
    })?;
    let author = args.get("author_passport").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
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
    Ok(text_content(serde_json::from_str(&resp_body).unwrap_or(Value::String(resp_body))))
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

    #[test]
    fn urlencoding_handles_special_chars() {
        assert_eq!(urlencoding("work::team"), "work%3A%3Ateam");
        assert_eq!(urlencoding("alphanum-123"), "alphanum-123");
    }
}
