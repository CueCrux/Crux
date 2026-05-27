// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `tool_trace_recent` — agent-ux-06 free-tier inspector tool.
//!
//! Returns the most recent [`crate::traces::TraceEntry`] values for the calling
//! passport, newest-first, capped by `top_k` and trimmed against the
//! supplied `token_budget`. The traces are sourced from the per-passport
//! ring buffer maintained by [`crate::traces`].
//!
//! ## Privacy
//!
//! - Per-passport partitioning: a passport never sees another
//!   passport's traces (master plan T.3).
//! - Reserved-prefix predicted effects are stripped at read time by
//!   [`crate::traces::TraceStore::recent`] so the response can never leak
//!   `__agent::*` / `__ops::*` / `__bootstrap__::*` entities (T.1).
//!
//! ## token_budget
//!
//! Mandatory per master plan §11 QC.2. We honour it loosely: each entry
//! is roughly 200 chars of JSON, so we cap returned entries at
//! `token_budget / 50`. Callers can omit it; we default to 2000 (a
//! "scan" budget) to match the daemon-wide convention.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use crate::scope;
use crate::traces::{global as trace_store, trace_payload, traces_enabled, ANON_PASSPORT};

/// Default `top_k` for the tool.
pub const DEFAULT_TOP_K: usize = 50;

/// Default `token_budget` when the caller omits one. Matches the
/// scan-tier default used by the rest of the daemon (master plan §11).
pub const DEFAULT_TOKEN_BUDGET: usize = 2_000;

pub fn tool_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "turn_id": {
                "type": "string",
                "description": "Optional turn id filter. When provided, only traces tagged with this turn are returned."
            },
            "top_k": {
                "type": "integer",
                "description": "Maximum number of traces to return (newest first).",
                "default": DEFAULT_TOP_K
            },
            "token_budget": {
                "type": "integer",
                "description": "Token budget (mandatory per master plan §11 QC.2). Default 2000.",
                "default": DEFAULT_TOKEN_BUDGET
            }
        },
        "examples": [
            { "top_k": 10, "token_budget": 500 },
            { "turn_id": "turn-abc", "token_budget": 2000 }
        ]
    })
}

pub const TOOL_DESCRIPTION: &str = "Inspect the most-recent typed action traces for the calling \
passport. Each trace lists the tool, timestamp, predicted effects (filtered to drop \
reserved-prefix entities), and outcome. Gated by CORECRUXD_FEATURE_TOOL_TRACES.";

/// Implement the `tool_trace_recent` MCP tool.
pub async fn handle_tool_trace_recent(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let top_k = args
        .get("top_k")
        .and_then(|v| v.as_u64())
        .map_or(DEFAULT_TOP_K, |v| v as usize);
    let token_budget = args
        .get("token_budget")
        .and_then(|v| v.as_u64())
        .map_or(DEFAULT_TOKEN_BUDGET, |v| v as usize);
    let filter_turn = args.get("turn_id").and_then(|v| v.as_str()).map(|s| s.to_string());

    if top_k == 0 {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "top_k must be >= 1".to_string(),
            data: None,
        });
    }

    if !traces_enabled() {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": "tool_trace_recent: feature disabled (set CORECRUXD_FEATURE_TOOL_TRACES=1)"
            }],
            "traces": [],
            "count": 0,
            "feature_disabled": true,
        }));
    }

    let passport = scope::agent_name(ctx.agent.as_ref()).unwrap_or(ANON_PASSPORT);
    let mut entries = trace_store().lock().await.recent(passport, top_k);
    if let Some(turn) = filter_turn {
        entries.retain(|e| e.turn_id.as_deref() == Some(turn.as_str()));
    }
    let payload = trace_payload(entries, Some(token_budget));
    let summary = format!(
        "tool_trace_recent: {} entries for passport={passport}",
        payload["count"].as_u64().unwrap_or(0)
    );
    let mut payload = payload;
    payload["content"] = json!([{"type": "text", "text": summary}]);
    Ok(payload)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;
    use crate::envelope::PredictedEffect;
    use crate::traces::{record_dispatch, test_env_lock as trace_env_lock, FEATURE_FLAG_ENV};

    fn ctx_with_agent(name: &str) -> McpContext {
        let agent = crate::agent::AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        };
        McpContext::new_default("test-node").with_agent(agent)
    }

    /// Per-test unique passport id so concurrent tokio tests don't
    /// stomp on each other's buckets (the env var is global; the
    /// bucket key is not).
    fn unique_passport(prefix: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("tools-traces-test::{prefix}::{n}")
    }

    #[tokio::test]
    async fn returns_feature_disabled_when_flag_off() {
        let _g = trace_env_lock().lock().await;
        std::env::remove_var(FEATURE_FLAG_ENV);
        let ctx = ctx_with_agent(&unique_passport("disabled"));
        let res = handle_tool_trace_recent(&json!({}), &ctx).await.unwrap();
        assert_eq!(res["feature_disabled"], true);
        assert_eq!(res["count"], 0);
    }

    #[tokio::test]
    async fn returns_recent_entries_for_passport() {
        let _g = trace_env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        let passport = unique_passport("recent");
        let ctx = ctx_with_agent(&passport);
        record_dispatch(
            &passport,
            "query_facts",
            Some("turn-1"),
            vec![PredictedEffect::now("fact_read", "project-x", "status")],
            crate::traces::TraceOutcome::Ok,
        )
        .await;
        let res = handle_tool_trace_recent(&json!({"top_k": 10, "token_budget": 2000}), &ctx)
            .await
            .unwrap();
        assert_eq!(res["count"], 1);
        let traces = res["traces"].as_array().unwrap();
        assert_eq!(traces[0]["tool"], "query_facts");
        assert_eq!(traces[0]["turn_id"], "turn-1");
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn isolates_passports() {
        let _g = trace_env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        let alice_p = unique_passport("alice-iso");
        let bob_p = unique_passport("bob-iso");
        record_dispatch(
            &alice_p,
            "store_fact",
            Some("turn-a"),
            vec![PredictedEffect::now("fact_write", "p", "k")],
            crate::traces::TraceOutcome::Ok,
        )
        .await;
        record_dispatch(
            &bob_p,
            "query_facts",
            Some("turn-b"),
            vec![PredictedEffect::now("fact_read", "p", "k")],
            crate::traces::TraceOutcome::Ok,
        )
        .await;
        let alice = handle_tool_trace_recent(&json!({}), &ctx_with_agent(&alice_p))
            .await
            .unwrap();
        assert_eq!(alice["count"], 1);
        assert_eq!(alice["traces"][0]["tool"], "store_fact");
        let bob = handle_tool_trace_recent(&json!({}), &ctx_with_agent(&bob_p))
            .await
            .unwrap();
        assert_eq!(bob["count"], 1);
        assert_eq!(bob["traces"][0]["tool"], "query_facts");
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn filters_reserved_prefix_effects() {
        let _g = trace_env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        let passport = unique_passport("filter");
        record_dispatch(
            &passport,
            "store_fact",
            Some("turn-x"),
            vec![
                PredictedEffect::now("fact_write", "project-y", "status"),
                PredictedEffect::now("fact_write", "__ops::config-audit", "sha"),
                PredictedEffect::now("fact_write", "__bootstrap__::pattern:foo", "k"),
            ],
            crate::traces::TraceOutcome::Ok,
        )
        .await;
        let res = handle_tool_trace_recent(&json!({}), &ctx_with_agent(&passport))
            .await
            .unwrap();
        assert_eq!(res["count"], 1);
        let effects = res["traces"][0]["predicted_effects"].as_array().unwrap();
        assert_eq!(effects.len(), 1, "reserved-prefix effects must be filtered");
        assert_eq!(effects[0]["entity"], "project-y");
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn turn_id_filter_narrows_response() {
        let _g = trace_env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        let passport = unique_passport("turn-filter");
        for turn in ["t1", "t2", "t3"] {
            record_dispatch(
                &passport,
                "query_facts",
                Some(turn),
                vec![],
                crate::traces::TraceOutcome::Ok,
            )
            .await;
        }
        let res = handle_tool_trace_recent(&json!({"turn_id": "t2"}), &ctx_with_agent(&passport))
            .await
            .unwrap();
        assert_eq!(res["count"], 1);
        assert_eq!(res["traces"][0]["turn_id"], "t2");
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn rejects_zero_top_k() {
        let _g = trace_env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        let res = handle_tool_trace_recent(&json!({"top_k": 0}), &ctx_with_agent("alice")).await;
        let err = res.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        std::env::remove_var(FEATURE_FLAG_ENV);
    }
}
