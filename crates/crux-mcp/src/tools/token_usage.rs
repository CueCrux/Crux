// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! MCP tool handler for `session_token_usage` (action-ledger M1).
//!
//! Surfaces the per-passport accumulator from
//! [`crate::token_accounting`] as `{used, limit, pct}` plus the in/out
//! split and call count. The response is fixed-size (a handful of
//! integers), so `token_budget` is accepted for QC.2 conformance but
//! never forces truncation.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::JsonRpcError;
use crate::scope;
use crate::token_accounting;
use crate::traces::ANON_PASSPORT;

pub const TOOL_DESCRIPTION: &str = "Read this session's estimated token usage for the calling passport: \
{used, limit, pct, tokens_in, tokens_out, calls}. `used` is the sum of estimated argument + result tokens \
across every tools/call this daemon process has dispatched for the passport (~4 chars/token heuristic — \
comparable, not exact). `limit` comes from CORECRUXD_SESSION_TOKEN_BUDGET (unset/0 = no limit, pct omitted). \
Unauthenticated callers are accumulated under the __anon__ sentinel.";

pub fn tool_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "token_budget": {
                "type": "integer",
                "description": "QC.2 — response-size cap. The payload is fixed-size; any positive integer is fine.",
                "default": 500
            }
        },
        "examples": [{}, {"token_budget": 500}]
    })
}

pub async fn handle_session_token_usage(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let passport = scope::agent_name(ctx.agent.as_ref()).unwrap_or(ANON_PASSPORT);
    let usage = token_accounting::usage_for(passport).await;
    let used = usage.total();
    let limit = token_accounting::session_budget_limit();
    // Integer percent; saturating at u64 bounds. Omitted when no limit.
    let pct = limit.map(|l| (used.saturating_mul(100)) / l.max(1));

    let summary = match (limit, pct) {
        (Some(l), Some(p)) => {
            format!(
                "session_token_usage: passport={passport} used≈{used} of {l} tokens ({p}%) across {} calls",
                usage.calls
            )
        }
        _ => format!(
            "session_token_usage: passport={passport} used≈{used} tokens (no limit set) across {} calls",
            usage.calls
        ),
    };

    let mut payload = json!({
        "content": [{ "type": "text", "text": summary }],
        "passport": passport,
        "used": used,
        "tokens_in": usage.tokens_in,
        "tokens_out": usage.tokens_out,
        "declared_budget_in": usage.declared_budget_in,
        "calls": usage.calls,
        "estimator": "chars/4",
    });
    if let Some(l) = limit {
        payload["limit"] = json!(l);
    }
    if let Some(p) = pct {
        payload["pct"] = json!(p);
    }
    Ok(payload)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ctx_with_agent(name: &str) -> McpContext {
        let agent = crate::agent::AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        };
        McpContext::new_default("test-node").with_agent(agent)
    }

    #[tokio::test]
    async fn zero_usage_for_fresh_passport() {
        let _g = crate::test_env_lock().lock().await;
        std::env::remove_var(token_accounting::SESSION_BUDGET_ENV);
        let ctx = ctx_with_agent("token-usage-test::fresh");
        token_accounting::clear_for_test("token-usage-test::fresh").await;
        let res = handle_session_token_usage(&json!({}), &ctx).await.unwrap();
        assert_eq!(res["used"], 0);
        assert_eq!(res["calls"], 0);
        assert!(res.get("limit").is_none());
        assert!(res.get("pct").is_none());
    }

    #[tokio::test]
    async fn reflects_recorded_usage_and_limit() {
        let _g = crate::test_env_lock().lock().await;
        let p = "token-usage-test::recorded";
        token_accounting::clear_for_test(p).await;
        token_accounting::record_usage(p, 100, 400, Some(500)).await;
        std::env::set_var(token_accounting::SESSION_BUDGET_ENV, "1000");
        let ctx = ctx_with_agent(p);
        let res = handle_session_token_usage(&json!({}), &ctx).await.unwrap();
        std::env::remove_var(token_accounting::SESSION_BUDGET_ENV);
        assert_eq!(res["used"], 500);
        assert_eq!(res["tokens_in"], 100);
        assert_eq!(res["tokens_out"], 400);
        assert_eq!(res["calls"], 1);
        assert_eq!(res["limit"], 1000);
        assert_eq!(res["pct"], 50);
        let text = res["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("50%"), "summary should carry pct: {text}");
    }

    #[tokio::test]
    async fn anon_caller_uses_sentinel_bucket() {
        let _g = crate::test_env_lock().lock().await;
        std::env::remove_var(token_accounting::SESSION_BUDGET_ENV);
        let ctx = McpContext::new_default("test-node");
        let res = handle_session_token_usage(&json!({}), &ctx).await.unwrap();
        assert_eq!(res["passport"], ANON_PASSPORT);
    }
}
