// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! HTTP surface for the token-burn **cost lens**.
//!
//! - `POST /v1/cost/report` — the `corecruxctl session cost --post` producer
//!   ships a ground-truth [`crux_cost::CostReport`] (computed from the operator's
//!   local transcript). Stored under `(tenant_id, session_id)`, latest wins.
//! - `GET  /v1/cost/report` — the console `cx-cost` page reads back the report
//!   + the session picker.
//!
//! Gated by `CORECRUXD_FEATURE_COST_LENS` (default OFF): both handlers return a
//! 404 disabled-problem when the flag is unset, so the daemon is unchanged.

use std::collections::HashMap;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;

use crate::auth::{http_scope_context, require_http_any_scope_for_tenant};
use crate::cost::{self, StoredReport};

use super::{problem_response, AppState};

/// Write scopes for posting a report — mirrors the activity/observe surface.
const WRITE_SCOPES: &[&str] = &["facts:write", "admin:write"];
/// Read scopes for the console pull.
const READ_SCOPES: &[&str] = &["facts:read", "admin:read"];

fn cost_disabled_response() -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        "cost lens disabled (set CORECRUXD_FEATURE_COST_LENS=1)".to_string(),
    )
}

/// `POST /v1/cost/report` body.
#[derive(Debug, Deserialize)]
pub(super) struct PostCostBody {
    tenant_id: String,
    /// Optional explicit session key; defaults to the report's `session_id`,
    /// then its `source` filename.
    #[serde(default)]
    session_id: Option<String>,
    report: crux_cost::CostReport,
}

/// `POST /v1/cost/report` — store a ground-truth cost report for a session.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_cost_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PostCostBody>,
) -> Response {
    if !cost::cost_lens_enabled() {
        return cost_disabled_response();
    }
    if body.tenant_id.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id is required".to_string());
    }
    if let Err(p) = require_http_any_scope_for_tenant(&state.auth, &headers, WRITE_SCOPES, &body.tenant_id) {
        return p.into_response();
    }
    let actor = http_scope_context(&state.auth, &headers)
        .ok()
        .and_then(|c| c.passport_id)
        .unwrap_or_else(|| cost::ANON_PASSPORT.to_string());

    // session key: explicit > report.session_id > report.source.
    let session_id = body
        .session_id
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            let sid = body.report.session_id.trim();
            (!sid.is_empty()).then(|| sid.to_string())
        })
        .unwrap_or_else(|| body.report.source.trim().to_string());
    if session_id.is_empty() {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "report has no session_id or source to key on".to_string(),
        );
    }

    let stored = {
        let mut store = cost::global().lock().await;
        store.put(body.tenant_id, session_id, actor, body.report)
    };
    // Restart-durability: journal the accepted report (append-only, latest-wins
    // on replay). Non-fatal — the in-memory store above is already authoritative.
    cost::append_report_to_journal(&stored);

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "stored": true,
            "session_id": stored.session_id,
            "received_at": stored.received_at,
        })),
    )
        .into_response()
}

/// `GET /v1/cost/report` — read the report for a session (or the tenant's
/// latest) plus the session picker. Query: `tenant_id` (required),
/// `token_budget` (**required**, QC.2), `session` (optional).
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_cost_report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    if !cost::cost_lens_enabled() {
        return cost_disabled_response();
    }
    let Some(tenant_id) = params.get("tenant_id").filter(|s| !s.trim().is_empty()) else {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id is required".to_string());
    };
    // QC.2 — token_budget is mandatory on every retrieval pull.
    let token_budget = match params.get("token_budget") {
        Some(raw) => match raw.trim().parse::<u64>() {
            Ok(n) if n > 0 => n,
            _ => {
                return problem_response(
                    StatusCode::BAD_REQUEST,
                    "token_budget must be a positive integer (QC.2)".to_string(),
                )
            }
        },
        None => {
            return problem_response(
                StatusCode::BAD_REQUEST,
                "token_budget query parameter is required (QC.2)".to_string(),
            )
        }
    };
    if let Err(p) = require_http_any_scope_for_tenant(&state.auth, &headers, READ_SCOPES, tenant_id) {
        return p.into_response();
    }
    let session = params.get("session").map(|s| s.trim()).filter(|s| !s.is_empty());

    let (report, sessions) = {
        let store = cost::global().lock().await;
        let report = match session {
            Some(s) => store.get(tenant_id, s),
            None => store.latest_for_tenant(tenant_id),
        };
        (report, store.sessions(tenant_id))
    };
    let report = report.map(|r| fit_budget(r, token_budget));

    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "token_budget": token_budget,
        "session_id": report.as_ref().map(|r| r.session_id.clone()),
        "has_report": report.is_some(),
        "report": report,
        "sessions": sessions,
    }))
    .into_response()
}

/// Trim the heaviest field (top_blocks) until the report fits the budget. The
/// headline + buckets + levers (the screenshot-worthy core) are always kept.
fn fit_budget(mut stored: StoredReport, budget: u64) -> StoredReport {
    let est = |s: &StoredReport| {
        serde_json::to_value(s)
            .map(|v| crux_mcp::token_estimate::estimate_tokens(&v))
            .unwrap_or(0)
    };
    while !stored.report.top_blocks.is_empty() && est(&stored) > budget {
        stored.report.top_blocks.pop();
    }
    stored
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::cost::StoredReport;

    fn stored_with_blocks(n: usize) -> StoredReport {
        let top_blocks = (0..n)
            .map(|i| crux_cost::BlockCost {
                source: format!("tool_result:T{i}"),
                tool: Some(format!("T{i}")),
                est_tokens: 1000,
                turns_live: 5,
                carried_cost: 5000,
                preview: "x".repeat(80),
            })
            .collect();
        let report = crux_cost::CostReport {
            schema: crux_cost::COST_REPORT_SCHEMA.to_owned(),
            session_id: "s".to_owned(),
            source: "s.jsonl".to_owned(),
            generated_at: None,
            started_at: None,
            ended_at: None,
            execplan_slugs: Vec::new(),
            model: None,
            effort: None,
            cwd: None,
            git_branch: None,
            breakdown: None,
            headline: crux_cost::Headline {
                assistant_turns: 10,
                tasks: 1,
                segments: 1,
                context_tokens_per_turn: 1000,
                cache_read_to_output_ratio: 50.0,
                measured_context_total: 10_000,
                prefix_pct: 50.0,
            },
            measured: crux_cost::Measured::default(),
            buckets: Vec::new(),
            top_blocks,
            levers: Vec::new(),
        };
        StoredReport {
            tenant_id: "t".to_owned(),
            session_id: "s".to_owned(),
            actor_passport: "p".to_owned(),
            received_at: "2026-06-22T00:00:00Z".to_owned(),
            report,
        }
    }

    #[test]
    fn fit_budget_keeps_all_under_a_large_budget() {
        let fitted = fit_budget(stored_with_blocks(25), 1_000_000);
        assert_eq!(fitted.report.top_blocks.len(), 25);
    }

    #[test]
    fn fit_budget_trims_top_blocks_under_a_tight_budget() {
        let fitted = fit_budget(stored_with_blocks(25), 50);
        assert!(
            fitted.report.top_blocks.len() < 25,
            "tight budget must drop some top_blocks"
        );
    }

    /// A transcript in the shape the real corpus has: two models, one of them
    /// with partial `effort` coverage, plus a `<synthetic>` record.
    fn transcript() -> String {
        [
            r#"{"type":"assistant","sessionId":"e2e","effort":"xhigh","cwd":"/w","gitBranch":"feat/axis","message":{"role":"assistant","model":"claude-opus-5","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":990},"content":[{"type":"text","text":"a"}]}}"#,
            r#"{"type":"assistant","sessionId":"e2e","effort":"high","cwd":"/w","gitBranch":"feat/axis","message":{"role":"assistant","model":"claude-opus-5","usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":490},"content":[{"type":"text","text":"b"}]}}"#,
            r#"{"type":"assistant","sessionId":"e2e","cwd":"/w","message":{"role":"assistant","model":"claude-fable-5","usage":{"input_tokens":0,"output_tokens":1,"cache_read_input_tokens":100},"content":[{"type":"text","text":"c"}]}}"#,
            r#"{"type":"assistant","sessionId":"e2e","message":{"role":"assistant","model":"<synthetic>","usage":{"input_tokens":0,"output_tokens":0,"cache_read_input_tokens":7},"content":[{"type":"text","text":"d"}]}}"#,
        ]
        .join("\n")
    }

    /// End-to-end through the two handlers: analyse a real-shaped transcript,
    /// POST it, GET it back, and assert the model/effort axis survived the round
    /// trip intact and still reconciles.
    ///
    /// This is the cost lane's first integration coverage of any kind — the lane
    /// named in the `SHARED-OBSERVABILITY` capability gap (`no_integration_tests`).
    #[tokio::test]
    #[serial_test::serial]
    async fn post_then_get_round_trips_the_model_axis() {
        std::env::set_var("CORECRUXD_FEATURE_COST_LENS", "1");
        let state = crate::http::tests::test_app_state(1);
        let report = crux_cost::analyze_str(&transcript(), "e2e.jsonl");
        // The producer side must have found the axis at all.
        assert_eq!(report.model.as_deref(), Some("claude-opus-5"));

        let resp = post_cost_report(
            State(state.clone()),
            HeaderMap::new(),
            Json(PostCostBody {
                tenant_id: "default".to_owned(),
                session_id: None,
                report,
            }),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        let resp = get_cost_report(
            State(state),
            HeaderMap::new(),
            Query(HashMap::from([
                ("tenant_id".to_owned(), "default".to_owned()),
                ("token_budget".to_owned(), "8000".to_owned()),
                ("session".to_owned(), "e2e".to_owned()),
            ])),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["has_report"], true);
        let r = &v["report"]["report"];

        assert_eq!(r["model"], "claude-opus-5");
        assert_eq!(r["effort"], "xhigh");
        assert_eq!(r["cwd"], "/w");
        assert_eq!(r["git_branch"], "feat/axis");

        let models = r["breakdown"]["models"].as_array().expect("models");
        assert_eq!(models.len(), 2, "<synthetic> must not be ranked as a model");
        assert_eq!(models[0]["model"], "claude-opus-5");
        assert_eq!(models[0]["turns"], 2);
        assert_eq!(models[0]["effort_coverage_pct"], 100.0);
        // fable's single turn carried no effort — 0% coverage, no effort rows.
        let fable = models.iter().find(|m| m["model"] == "claude-fable-5").expect("fable");
        assert_eq!(fable["effort_coverage_pct"], 0.0);
        assert!(
            fable.get("efforts").is_none(),
            "empty efforts must be skipped on the wire"
        );
        // Separated, not dropped.
        assert_eq!(r["breakdown"]["synthetic"]["model"], "<synthetic>");
        assert_eq!(r["breakdown"]["synthetic"]["turns"], 1);

        // …and it still adds up after the round trip.
        let summed: u64 = models
            .iter()
            .map(|m| m["context_total"].as_u64().unwrap_or(0))
            .sum::<u64>()
            + r["breakdown"]["synthetic"]["context_total"].as_u64().unwrap_or(0)
            + r["breakdown"]["unattributed_context"].as_u64().unwrap_or(0);
        assert_eq!(summed, r["headline"]["measured_context_total"].as_u64().unwrap_or(0));
        std::env::remove_var("CORECRUXD_FEATURE_COST_LENS");
    }

    /// Wire compatibility in the direction that actually happens in the field: a
    /// producer newer than the daemon. A legacy body with none of the axis
    /// fields must still be accepted and read back unchanged.
    #[tokio::test]
    #[serial_test::serial]
    async fn legacy_report_without_the_axis_still_posts_and_reads_back() {
        std::env::set_var("CORECRUXD_FEATURE_COST_LENS", "1");
        let state = crate::http::tests::test_app_state(1);
        let body: PostCostBody = serde_json::from_value(serde_json::json!({
            "tenant_id": "default",
            "report": {
                "schema": crux_cost::COST_REPORT_SCHEMA,
                "session_id": "legacy", "source": "legacy.jsonl",
                "headline": {"assistant_turns":1,"tasks":1,"segments":1,"context_tokens_per_turn":10,
                             "cache_read_to_output_ratio":1.0,"measured_context_total":10,"prefix_pct":0.0},
                "measured": {"input":10,"output":10,"cache_read":0,"cache_creation":0},
                "buckets": [], "top_blocks": [], "levers": []
            }
        }))
        .expect("a pre-axis report must still deserialise");
        assert_eq!(
            post_cost_report(State(state.clone()), HeaderMap::new(), Json(body))
                .await
                .status(),
            StatusCode::CREATED
        );

        let resp = get_cost_report(
            State(state),
            HeaderMap::new(),
            Query(HashMap::from([
                ("tenant_id".to_owned(), "default".to_owned()),
                ("token_budget".to_owned(), "8000".to_owned()),
                ("session".to_owned(), "legacy".to_owned()),
            ])),
        )
        .await;
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let r = &v["report"]["report"];
        assert_eq!(r["session_id"], "legacy");
        for f in ["model", "effort", "cwd", "git_branch", "breakdown"] {
            assert!(r.get(f).is_none(), "{f} must not be invented on a legacy report");
        }
        std::env::remove_var("CORECRUXD_FEATURE_COST_LENS");
    }
}
