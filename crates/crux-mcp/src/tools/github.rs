// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! GitHub MCP tools — surface indexed commits / PRs / issues / comments to
//! coding agents (Claude, Codex, etc.) over the loopback to corecruxd's
//! `/v1/console/facts` endpoint. Storage is everything-as-facts under
//! `github::owner/repo::{kind}/{id}`; these tools are thin filtering wrappers.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};

const SCOPES: &str = "admin:read";

pub const GITHUB_SEARCH_DESCRIPTION: &str =
    "Search the indexed GitHub corpus (commits, PRs, issues, comments) under repos selected via /v1/integrations/github/repos. Pass `repo` as `owner/repo` to narrow.";

pub const GITHUB_RECENT_COMMITS_DESCRIPTION: &str =
    "Recent commits for a selected repo. Use this to learn what other agents (or humans) have shipped lately. Pass `repo` as `owner/repo`.";

pub const GITHUB_OPEN_PRS_DESCRIPTION: &str =
    "Open PRs in a selected repo, including author + body. Pass `repo` as `owner/repo`.";

pub const GITHUB_OPEN_ISSUES_DESCRIPTION: &str =
    "Open issues in a selected repo. Pass `repo` as `owner/repo`. Optional `label` filter.";

pub const GITHUB_COMMENTS_SINCE_DESCRIPTION: &str =
    "Recent comments across selected repos — useful for the 'what happened since I last looked' question.";

fn loopback_base(ctx: &McpContext) -> Result<String, JsonRpcError> {
    ctx.daemon_base_url
        .as_deref()
        .map(|s| s.trim_end_matches('/').to_string())
        .ok_or_else(|| JsonRpcError {
            code: INTERNAL_ERROR,
            message: "daemon_base_url not configured; github tools require loopback to corecruxd".to_string(),
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

async fn loopback_get(url: String) -> Result<String, JsonRpcError> {
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
            .map(|mut r| r.body_mut().read_to_string().unwrap_or_default())
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("github loopback join error: {e}"),
        data: None,
    })?
    .map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("github loopback request failed: {e}"),
        data: None,
    })
}

fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

fn filter_by_entity_prefix(body: &str, prefix: &str, top_k: usize) -> Value {
    let parsed: Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return json!({ "raw": truncate(body, 1024) }),
    };
    let facts = parsed
        .get("facts")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let filtered: Vec<Value> = facts
        .into_iter()
        .filter(|f| f.get("entity").and_then(|e| e.as_str()).is_some_and(|e| e.starts_with(prefix)))
        .take(top_k)
        .collect();
    json!({ "count": filtered.len(), "facts": filtered })
}

fn text_content(value: Value) -> Value {
    json!({
        "content": [
            { "type": "text", "text": value.to_string() }
        ]
    })
}

fn require_repo(args: &Value, tool: &str) -> Result<String, JsonRpcError> {
    args.get("repo")
        .and_then(|v| v.as_str())
        .filter(|s| s.contains('/'))
        .map(str::to_string)
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("{tool}: repo is required (format: owner/repo)"),
            data: None,
        })
}

pub async fn handle_github_search(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let q = args.get("query").and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "github_search: query is required".to_string(),
        data: None,
    })?;
    let repo = args.get("repo").and_then(|v| v.as_str());
    let top_k = args.get("top_k").and_then(|v| v.as_u64()).unwrap_or(20).min(200) as usize;
    let base = loopback_base(ctx)?;
    let url = format!(
        "{base}/v1/console/facts?q={}&top_k={top_k}",
        urlencoding(q)
    );
    let body = loopback_get(url).await?;
    let prefix = match repo {
        Some(r) => format!("github::{r}::"),
        None => "github::".to_string(),
    };
    Ok(text_content(filter_by_entity_prefix(&body, &prefix, top_k)))
}

pub async fn handle_github_recent_commits(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let repo = require_repo(args, "github_recent_commits")?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20).min(200) as usize;
    let base = loopback_base(ctx)?;
    let url = format!(
        "{base}/v1/console/facts?q={}&top_k=200",
        urlencoding(&format!("github::{repo}::commit"))
    );
    let body = loopback_get(url).await?;
    Ok(text_content(filter_by_entity_prefix(&body, &format!("github::{repo}::commit/"), limit)))
}

pub async fn handle_github_open_prs(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let repo = require_repo(args, "github_open_prs")?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20).min(200) as usize;
    let base = loopback_base(ctx)?;
    let url = format!(
        "{base}/v1/console/facts?q={}&top_k=200",
        urlencoding(&format!("github::{repo}::pr"))
    );
    let body = loopback_get(url).await?;
    let raw = filter_by_entity_prefix(&body, &format!("github::{repo}::pr/"), 200);
    let facts = raw.get("facts").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let open: Vec<Value> = facts
        .into_iter()
        .filter(|f| {
            f.get("value")
                .and_then(|v| v.as_str())
                .and_then(|s| serde_json::from_str::<Value>(s).ok())
                .and_then(|parsed| parsed.get("state").and_then(|v| v.as_str()).map(str::to_string))
                .is_some_and(|state| state == "open")
        })
        .take(limit)
        .collect();
    Ok(text_content(json!({ "count": open.len(), "facts": open })))
}

pub async fn handle_github_open_issues(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let repo = require_repo(args, "github_open_issues")?;
    let label_filter = args.get("label").and_then(|v| v.as_str()).map(str::to_string);
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(20).min(200) as usize;
    let base = loopback_base(ctx)?;
    let url = format!(
        "{base}/v1/console/facts?q={}&top_k=200",
        urlencoding(&format!("github::{repo}::issue"))
    );
    let body = loopback_get(url).await?;
    let raw = filter_by_entity_prefix(&body, &format!("github::{repo}::issue/"), 200);
    let facts = raw.get("facts").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let filtered: Vec<Value> = facts
        .into_iter()
        .filter(|f| {
            let parsed: Option<Value> = f
                .get("value")
                .and_then(|v| v.as_str())
                .and_then(|s| serde_json::from_str::<Value>(s).ok());
            let state_open = parsed
                .as_ref()
                .and_then(|v| v.get("state").and_then(|x| x.as_str()))
                .is_some_and(|s| s == "open");
            if !state_open {
                return false;
            }
            if let Some(label) = &label_filter {
                let labels = parsed
                    .as_ref()
                    .and_then(|v| v.get("labels").and_then(|x| x.as_array()))
                    .cloned()
                    .unwrap_or_default();
                labels.iter().any(|l| l.as_str() == Some(label.as_str()))
            } else {
                true
            }
        })
        .take(limit)
        .collect();
    Ok(text_content(json!({ "count": filtered.len(), "facts": filtered })))
}

pub async fn handle_github_comments_since(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50).min(500) as usize;
    let base = loopback_base(ctx)?;
    // Pull all `github::*::comment/*` facts. We query with q=`github::` then filter
    // on `::comment/`. Cheap because top_k bounds the response.
    let url = format!("{base}/v1/console/facts?q=github::&top_k=500");
    let body = loopback_get(url).await?;
    let parsed: Value = serde_json::from_str(&body).unwrap_or_else(|_| json!({}));
    let facts = parsed.get("facts").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let comments: Vec<Value> = facts
        .into_iter()
        .filter(|f| {
            f.get("entity")
                .and_then(|e| e.as_str())
                .is_some_and(|e| e.contains("::comment/"))
        })
        .take(limit)
        .collect();
    Ok(text_content(json!({ "count": comments.len(), "facts": comments })))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_repo_rejects_missing_slash() {
        let args = json!({ "repo": "no-slash" });
        let err = require_repo(&args, "test").expect_err("rejected");
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[test]
    fn require_repo_accepts_owner_slash_repo() {
        let args = json!({ "repo": "owner/repo" });
        let r = require_repo(&args, "test").expect("ok");
        assert_eq!(r, "owner/repo");
    }

    #[test]
    fn filter_by_entity_prefix_keeps_matching_only() {
        let body = json!({
            "facts": [
                { "entity": "github::a/b::commit/aaa", "value": "v1" },
                { "entity": "github::c/d::commit/bbb", "value": "v2" },
                { "entity": "github::a/b::pr/1",       "value": "v3" }
            ]
        })
        .to_string();
        let out = filter_by_entity_prefix(&body, "github::a/b::commit/", 10);
        assert_eq!(out["count"], 1);
        let arr = out["facts"].as_array().expect("arr");
        assert_eq!(arr[0]["entity"], "github::a/b::commit/aaa");
    }

    #[test]
    fn urlencoding_encodes_special_chars() {
        assert_eq!(urlencoding("a/b::commit"), "a%2Fb%3A%3Acommit");
    }
}
