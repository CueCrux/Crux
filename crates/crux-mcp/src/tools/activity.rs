// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `activity_recent` — agent lane of the dual-surface activity log (ExecPlan
//! `crux-dual-surface-activity-log-2026-06-18`, M2).
//!
//! The cheap "what just happened in this session" pull. Calls the daemon's
//! `GET /v1/activity` route over loopback and returns compact rows under a
//! `token_budget` (QC.2 — always sent; defaults to 500). This is
//! `tool_trace_recent` widened from tool dispatches to the seven activity
//! categories (questions, answers, reasoning, commands, facts, execplans /
//! handoffs, errors).
//!
//! ## Design notes
//!
//! - **Pull, never push** — the agent asks; the log is never streamed into
//!   context.
//! - **Requires a passport** (QC.3) — the daemon's HTTP route enforces tenant
//!   scope and privacy; the MCP boundary enforces "authenticated agent".
//! - **Feature-flagged** behind `CORECRUXD_FEATURE_ACTIVITY_LOG` (default
//!   OFF). With the flag off the daemon route returns 404; the tool surfaces
//!   that as `feature_enabled:false` rather than erroring.
//! - **No envelope** — this is not a memory retrieval (no `memories_used[]`).

use std::fmt::Write as _;

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};
use crate::scope;
use crate::tools::loopback_auth::loopback_bearer_token;

/// HTTP scopes minted into the loopback bearer for the read call.
const SCOPES: &str = "facts:read";

/// Default tenant when the caller doesn't pass `tenant_id`.
const DEFAULT_TENANT: &str = "default";

/// Default token budget when the caller omits one (QC.2 default for
/// confirmations / cheap pulls).
const DEFAULT_TOKEN_BUDGET: u64 = 500;

/// RFC 3986 unreserved-only percent-encoding (mirrors `receipt_verify`).
fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

/// Build the `GET /v1/activity` URL from typed args against the loopback base.
pub fn build_activity_url(
    base_url: &str,
    tenant_id: &str,
    session: &str,
    since: Option<&str>,
    kinds: Option<&str>,
    token_budget: u64,
) -> String {
    let base = base_url.trim_end_matches('/');
    let mut url = format!(
        "{base}/v1/activity?tenant_id={}&session={}&token_budget={token_budget}",
        urlencoding(tenant_id),
        urlencoding(session),
    );
    if let Some(since) = since.filter(|s| !s.trim().is_empty()) {
        let _ = write!(url, "&since={}", urlencoding(since));
    }
    if let Some(kinds) = kinds.filter(|k| !k.trim().is_empty()) {
        let _ = write!(url, "&kinds={}", urlencoding(kinds));
    }
    url
}

/// `activity_recent(session_id, tenant_id?, since?, kinds?, token_budget?)`.
pub async fn handle_activity_recent(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    // ── 1. Passport gate (QC.3) ─────────────────────────────────────────
    let _agent_name = scope::agent_name(ctx.agent.as_ref()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "activity_recent requires an authenticated agent identity (passport). \
                  Set CRUX_AGENT_TOKEN or CRUX_AGENT_TOKENS and pass a Bearer header."
            .to_string(),
        data: Some(json!({"requires_agent_identity": true})),
    })?;

    // ── 2. Parse args ──────────────────────────────────────────────────
    let session = args
        .get("session_id")
        .or_else(|| args.get("session"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "session_id is required".to_string(),
            data: None,
        })?
        .to_string();
    let tenant_id = args
        .get("tenant_id")
        .and_then(Value::as_str)
        .map_or_else(|| DEFAULT_TENANT.to_string(), str::to_string);
    let since = args.get("since").and_then(Value::as_str).map(str::to_string);
    // `kinds` accepts an array or a csv string.
    let kinds = match args.get("kinds") {
        Some(Value::Array(items)) => Some(items.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(",")),
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    };
    // QC.2 — always carry a budget; default 500 when omitted.
    let token_budget = args
        .get("token_budget")
        .and_then(Value::as_u64)
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_TOKEN_BUDGET);

    // ── 3. Loopback HTTP call ──────────────────────────────────────────
    let base_url = ctx.daemon_base_url.as_deref().ok_or_else(|| JsonRpcError {
        code: INTERNAL_ERROR,
        message: "daemon_base_url not configured; activity_recent requires loopback to corecruxd".to_string(),
        data: None,
    })?;
    let url = build_activity_url(
        base_url,
        &tenant_id,
        &session,
        since.as_deref(),
        kinds.as_deref(),
        token_budget,
    );
    let (status, body) = loopback_get(url).await?;

    // ── 4. Shape the payload ───────────────────────────────────────────
    if status == 404 {
        return Ok(json!({
            "content": [{"type": "text", "text":
                "activity_recent: feature disabled (CORECRUXD_FEATURE_ACTIVITY_LOG off)."}],
            "session_id": session,
            "tenant_id": tenant_id,
            "feature_enabled": false,
            "rows": [],
        }));
    }
    let parsed: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    if status != 200 {
        let detail = parsed
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("activity pull failed");
        return Err(JsonRpcError {
            code: INTERNAL_ERROR,
            message: format!("activity_recent: HTTP {status}: {detail}"),
            data: Some(parsed),
        });
    }

    let returned = parsed.get("returned").and_then(Value::as_u64).unwrap_or(0);
    let truncated = parsed.get("truncated").and_then(Value::as_bool).unwrap_or(false);
    let rows = parsed.get("rows").cloned().unwrap_or(Value::Array(vec![]));
    Ok(json!({
        "content": [{"type": "text", "text":
            format!("{returned} activity row(s) for session {session}{}",
                if truncated { " (budget-truncated)" } else { "" })}],
        "session_id": session,
        "tenant_id": tenant_id,
        "feature_enabled": true,
        "token_budget": token_budget,
        "returned": returned,
        "truncated": truncated,
        "rows": rows,
    }))
}

async fn loopback_get(url: String) -> Result<(u16, String), JsonRpcError> {
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
        match req.call() {
            Ok(mut r) => {
                let status = r.status().as_u16();
                let body = r.body_mut().read_to_string().unwrap_or_default();
                Ok((status, body))
            }
            Err(ureq::Error::StatusCode(code)) => Ok((code, String::new())),
            Err(other) => Err(other.to_string()),
        }
    })
    .await
    .map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("loopback join error: {e}"),
        data: None,
    })?
    .map_err(|message| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("loopback request failed: {message}"),
        data: None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;

    fn ctx_with_agent(name: &str) -> McpContext {
        McpContext::new_default("test-act-node").with_agent(AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        })
    }

    #[tokio::test]
    async fn requires_passport() {
        let ctx = McpContext::new_default("test-act-node");
        let err = handle_activity_recent(&json!({"session_id": "s1"}), &ctx)
            .await
            .expect_err("missing passport must fail");
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("authenticated agent identity"));
    }

    #[tokio::test]
    async fn requires_session_id() {
        let ctx = ctx_with_agent("alice");
        let err = handle_activity_recent(&json!({}), &ctx)
            .await
            .expect_err("missing session_id must fail");
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("session_id is required"));
    }

    #[tokio::test]
    async fn requires_daemon_base_url() {
        let ctx = ctx_with_agent("alice");
        let err = handle_activity_recent(&json!({"session_id": "s1"}), &ctx)
            .await
            .expect_err("missing daemon_base_url must fail");
        assert_eq!(err.code, INTERNAL_ERROR);
        assert!(err.message.contains("daemon_base_url not configured"));
    }

    #[test]
    fn build_url_includes_mandatory_budget_and_encodes() {
        let url = build_activity_url("http://127.0.0.1:14800/", "tenant a", "s 1", None, None, 500);
        assert_eq!(
            url,
            "http://127.0.0.1:14800/v1/activity?tenant_id=tenant%20a&session=s%201&token_budget=500"
        );
    }

    #[test]
    fn build_url_appends_since_and_kinds() {
        let url = build_activity_url(
            "http://127.0.0.1:14800",
            "default",
            "s1",
            Some("3"),
            Some("error,command"),
            2000,
        );
        assert!(url.contains("&since=3"));
        assert!(url.contains("&kinds=error%2Ccommand"));
        assert!(url.contains("&token_budget=2000"));
    }
}
