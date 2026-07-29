// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `learn` — deterministic session-mining tool (ExecPlan milestone M4).
//!
//! Mines the calling passport's typed-action ring ([`crate::traces`]) for tool
//! signatures that looped (≥3× after pagination-dedup) and **proposes** — never
//! auto-writes (OD-C) — a guardrail for each, ranked by *measured* token waste.
//! The ranking is [`crate::learn::detect_loops`]; this tool is the read-only
//! surface over the per-passport ring.
//!
//! ## Privacy & safety
//!
//! - Per-passport partitioning: a passport only mines its own traces (T.3),
//!   inherited from [`crate::traces::TraceStore::recent`].
//! - **Read-only / propose-only:** emits draft guardrails + the waste that
//!   justifies them. Writes nothing, runs behind no hook (Crux don't-list).
//! - Gated by the same `CORECRUXD_FEATURE_TOOL_TRACES` flag as its data source —
//!   no ring, no proposals.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::learn::{detect_loops, GuardrailProposal, ToolEvent, MIN_REPEATS};
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use crate::scope;
use crate::traces::{global as trace_store, traces_enabled, ANON_PASSPORT};

/// How many recent traces to scan by default (a session's worth).
pub const DEFAULT_SCAN: usize = 1_000;

pub fn tool_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "min_repeats": {
                "type": "integer",
                "description": "Minimum repeats before a signature is flagged as a loop.",
                "default": MIN_REPEATS,
                "minimum": 2
            },
            "scan": {
                "type": "integer",
                "description": "How many recent traces to mine (newest first).",
                "default": DEFAULT_SCAN
            }
        },
        "examples": [ {}, { "min_repeats": 3, "scan": 500 } ]
    })
}

pub const TOOL_DESCRIPTION: &str = "Mine the calling passport's recent tool-call traces for looping \
re-fetches (a signature repeated >=3x, pagination variants folded together) and PROPOSE guardrails \
ranked by measured token waste. Read-only and propose-only: writes nothing. Gated by \
CORECRUXD_FEATURE_TOOL_TRACES.";

/// Implement the `learn` MCP tool.
pub async fn handle_learn(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let min_repeats = args
        .get("min_repeats")
        .and_then(|v| v.as_u64())
        .map_or(MIN_REPEATS, |v| v as usize);
    let scan = args
        .get("scan")
        .and_then(|v| v.as_u64())
        .map_or(DEFAULT_SCAN, |v| v as usize);

    if min_repeats < 2 {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "min_repeats must be >= 2".to_string(),
            data: None,
        });
    }

    if !traces_enabled() {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": "learn: feature disabled (set CORECRUXD_FEATURE_TOOL_TRACES=1)"
            }],
            "proposals": [],
            "count": 0,
            "feature_disabled": true,
        }));
    }

    let passport = scope::agent_name(ctx.agent.as_ref()).unwrap_or(ANON_PASSPORT);
    // `recent` returns newest-first; reverse so loop detection sees calls in the
    // order they happened (the first fetch in a loop is the legitimate one).
    let mut entries = trace_store().lock().await.recent(passport, scan);
    entries.reverse();

    let events: Vec<ToolEvent> = entries
        .into_iter()
        .filter_map(|e| {
            // Only metered traces (post-M4) carry a signature + response tokens.
            match (e.signature, e.response_tokens) {
                (Some(signature), Some(response_tokens)) => Some(ToolEvent {
                    signature,
                    response_tokens,
                }),
                _ => None,
            }
        })
        .collect();

    let proposals = detect_loops(&events, min_repeats);
    let summary = if proposals.is_empty() {
        format!(
            "learn: no looping signatures in the last {} traces for passport={passport}",
            events.len()
        )
    } else {
        format!(
            "learn: {} guardrail proposal(s) for passport={passport} (propose-only — nothing written)",
            proposals.len()
        )
    };

    Ok(json!({
        "content": [{ "type": "text", "text": render_text(&summary, &proposals) }],
        "proposals": proposals.iter().map(proposal_json).collect::<Vec<_>>(),
        "count": proposals.len(),
        "scanned": events.len(),
        "propose_only": true,
    }))
}

fn proposal_json(p: &GuardrailProposal) -> Value {
    json!({
        "signature": p.signature,
        "occurrences": p.occurrences,
        "wasted_tokens": p.wasted_tokens,
        "draft_guardrail": p.draft_guardrail,
    })
}

/// Render a human-readable, deterministic report. Ranked, with the measured
/// waste that justifies each proposal.
fn render_text(summary: &str, proposals: &[GuardrailProposal]) -> String {
    use std::fmt::Write as _;
    let mut out = String::from(summary);
    for (i, p) in proposals.iter().enumerate() {
        let _ = write!(
            out,
            "\n{}. [{} tok wasted, {}×] {}",
            i + 1,
            p.wasted_tokens,
            p.occurrences,
            p.draft_guardrail
        );
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::envelope::PredictedEffect;
    use crate::traces::{record_dispatch_metered, test_env_lock as trace_env_lock, TraceOutcome, FEATURE_FLAG_ENV};

    fn ctx_with_agent(name: &str) -> McpContext {
        let agent = crate::agent::AgentIdentity {
            name: name.to_string(),
            token_hash: [0u8; 32],
        };
        McpContext::new_default("test-node").with_agent(agent)
    }

    fn unique_passport(prefix: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("tools-learn-test::{prefix}::{n}")
    }

    async fn seed(passport: &str, signature: &str, response_tokens: u64) {
        record_dispatch_metered(
            passport,
            "query",
            Some("turn-1"),
            Some(signature.to_string()),
            Some(response_tokens),
            vec![PredictedEffect::now("fact_read", "p", "k")],
            TraceOutcome::Ok,
        )
        .await;
    }

    #[tokio::test]
    async fn feature_disabled_when_flag_off() {
        let _g = trace_env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "0");
        let ctx = ctx_with_agent(&unique_passport("off"));
        let res = handle_learn(&json!({}), &ctx).await.unwrap();
        assert_eq!(res["feature_disabled"], true);
        assert_eq!(res["count"], 0);
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn proposes_a_loop_and_writes_nothing() {
        let _g = trace_env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        let passport = unique_passport("loop");
        let ctx = ctx_with_agent(&passport);
        // A 3× loop of the same canonical signature, plus a one-off.
        for _ in 0..3 {
            seed(&passport, "query(q=docs)", 80).await;
        }
        seed(&passport, "query(q=other)", 200).await;

        let res = handle_learn(&json!({}), &ctx).await.unwrap();
        assert_eq!(res["count"], 1, "only the loop is proposed");
        assert_eq!(res["propose_only"], true);
        let p = &res["proposals"][0];
        assert_eq!(p["signature"], "query(q=docs)");
        assert_eq!(p["occurrences"], 3);
        assert_eq!(p["wasted_tokens"], 160); // 2 redundant × 80
        std::env::remove_var(FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn quiet_when_no_loops() {
        let _g = trace_env_lock().lock().await;
        std::env::set_var(FEATURE_FLAG_ENV, "1");
        let passport = unique_passport("quiet");
        let ctx = ctx_with_agent(&passport);
        seed(&passport, "query(q=a)", 50).await;
        seed(&passport, "query(q=b)", 50).await;
        let res = handle_learn(&json!({}), &ctx).await.unwrap();
        assert_eq!(res["count"], 0);
        assert!(res["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("no looping signatures"));
        std::env::remove_var(FEATURE_FLAG_ENV);
    }
}
