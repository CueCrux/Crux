// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `GET /v1/agents/{passport}/usage` — per-passport tool-usage rollup
//! (action-ledger M3).
//!
//! Computed from the durable `agent.tool_invocation.v1` events the MCP
//! dispatch ledger appends to the observations stream (one JSONL file
//! per passport: `ledger::<passport>`). Returns
//! `{passport, calls_total, tokens_total, error_rate, tools, window}`
//! where `tools` carries per-tool `{tool, calls, avg_tokens, p50_ms}`.
//!
//! Authorization (mirrors the 2026-06-11 isolation posture):
//! - no / invalid credentials → **401**;
//! - a passport-bound principal may read **its own** usage → **200**;
//! - a raw admin principal (`admin:read` / `admin:write`, no passport
//!   binding) may read anyone's → **200**;
//! - everything else (other passports, even with read scopes) → **403**.
//!
//! The scan is a single bounded JSONL read per request (the per-passport
//! file is exactly the passport's own events). A rolling cache can be
//! layered later if usage polling becomes hot; correctness first.

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::auth::{http_scope_context, require_http_any_scope};

use super::{problem_response, AppState};

/// Observation `kind` for ledger events (must match `crux_mcp::ledger`).
const LEDGER_EVENT_KIND: &str = "agent.tool_invocation.v1";

/// Hard cap on JSONL lines scanned per request.
const MAX_SCAN_LINES: usize = 100_000;

#[derive(Debug, Deserialize)]
pub(super) struct UsageQuery {
    /// Restrict the rollup to events newer than `now - window_hours`.
    /// Omitted → whole ledger file (`window: "all"`).
    pub window_hours: Option<u32>,
}

/// Mirror of the observation-store filename sanitisation: the ledger
/// session id `ledger::<passport>` maps to `ledger__<passport>.jsonl`.
fn sanitize_session_id_for_filename(session_id: &str) -> String {
    session_id
        .chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => c,
            _ => '_',
        })
        .collect()
}

fn ledger_file_path(data_dir: &std::path::Path, passport: &str) -> std::path::PathBuf {
    let scoped = format!("ledger::{passport}");
    data_dir
        .join("observations")
        .join(format!("{}.jsonl", sanitize_session_id_for_filename(&scoped)))
}

/// Read ledger event payloads (+ timestamps) for one passport. A
/// missing file is an empty ledger, not an error.
fn read_ledger_payloads(
    data_dir: &std::path::Path,
    passport: &str,
    since: Option<DateTime<Utc>>,
) -> std::io::Result<Vec<Value>> {
    use std::io::BufRead;
    let path = ledger_file_path(data_dir, passport);
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let reader = std::io::BufReader::new(file);
    let mut out = Vec::new();
    for line in reader.lines().take(MAX_SCAN_LINES) {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(record) = serde_json::from_str::<Value>(&line) else {
            continue; // tolerate a torn tail line; chain verification is a different route
        };
        if record["kind"] != LEDGER_EVENT_KIND {
            continue;
        }
        if let Some(since) = since {
            let ts = record["ts"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|d| d.with_timezone(&Utc));
            if ts.map(|t| t < since).unwrap_or(false) {
                continue;
            }
        }
        out.push(record["payload"].clone());
    }
    Ok(out)
}

/// Pure rollup over ledger payloads — unit-testable without IO.
fn usage_rollup(passport: &str, payloads: &[Value], window: &str) -> Value {
    let calls_total = payloads.len() as u64;
    let mut tokens_total: u64 = 0;
    let mut errors: u64 = 0;
    let mut per_tool: std::collections::BTreeMap<String, (u64, u64, Vec<u64>)> = std::collections::BTreeMap::new();

    for p in payloads {
        let tokens = p["est_tokens_in"].as_u64().unwrap_or(0) + p["est_tokens_out"].as_u64().unwrap_or(0);
        tokens_total = tokens_total.saturating_add(tokens);
        if p["outcome"].as_str() == Some("error") {
            errors += 1;
        }
        let tool = p["tool"].as_str().unwrap_or("unknown").to_string();
        let entry = per_tool.entry(tool).or_insert((0, 0, Vec::new()));
        entry.0 += 1;
        entry.1 = entry.1.saturating_add(tokens);
        if let Some(ms) = p["latency_ms"].as_u64() {
            entry.2.push(ms);
        }
    }

    let mut tools: Vec<Value> = per_tool
        .into_iter()
        .map(|(tool, (calls, tokens, mut latencies))| {
            latencies.sort_unstable();
            let p50_ms = if latencies.is_empty() {
                Value::Null
            } else {
                json!(latencies[latencies.len() / 2])
            };
            json!({
                "tool": tool,
                "calls": calls,
                "avg_tokens": if calls > 0 { tokens / calls } else { 0 },
                "p50_ms": p50_ms,
            })
        })
        .collect();
    tools.sort_by_key(|t| std::cmp::Reverse(t["calls"].as_u64().unwrap_or(0)));

    let error_rate = if calls_total > 0 {
        (errors as f64) / (calls_total as f64)
    } else {
        0.0
    };

    json!({
        "passport": passport,
        "calls_total": calls_total,
        "tokens_total": tokens_total,
        "errors_total": errors,
        "error_rate": (error_rate * 10_000.0).round() / 10_000.0,
        "tools": tools,
        "window": window,
        "source": "agent.tool_invocation.v1",
    })
}

/// `GET /v1/agents/{passport}/usage`.
pub(super) async fn get_agent_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(passport): AxumPath<String>,
    Query(params): Query<UsageQuery>,
) -> Response {
    // 401 on missing/invalid credentials; minimum read surface.
    if let Err(resp) = require_http_any_scope(&state.auth, &headers, &["sessions:read", "admin:read", "admin:write"]) {
        return resp.into_response();
    }
    let ctx = match http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(resp) => return resp.into_response(),
    };

    // Own-passport read, or raw-admin (no passport binding) for others.
    let is_self = ctx.passport_id.as_deref() == Some(passport.as_str());
    let is_raw_admin = ctx.passport_id.is_none() && (ctx.has_scope("admin:read") || ctx.has_scope("admin:write"));
    if !(is_self || is_raw_admin) {
        return problem_response(
            StatusCode::FORBIDDEN,
            "usage is readable by the owning passport or a raw admin principal".to_string(),
        );
    }

    let (since, window) = match params.window_hours {
        Some(h) => (Some(Utc::now() - ChronoDuration::hours(i64::from(h))), format!("{h}h")),
        None => (None, "all".to_string()),
    };

    let payloads = match read_ledger_payloads(&state.data_dir, &passport, since) {
        Ok(p) => p,
        Err(err) => {
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("read ledger: {err}"));
        }
    };

    (StatusCode::OK, Json(usage_rollup(&passport, &payloads, &window))).into_response()
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn payload(tool: &str, tokens_in: u64, tokens_out: u64, latency_ms: u64, ok: bool) -> Value {
        json!({
            "tool": tool,
            "passport": "alice",
            "est_tokens_in": tokens_in,
            "est_tokens_out": tokens_out,
            "latency_ms": latency_ms,
            "outcome": if ok { "ok" } else { "error" },
        })
    }

    #[test]
    fn rollup_empty_ledger() {
        let v = usage_rollup("alice", &[], "all");
        assert_eq!(v["calls_total"], 0);
        assert_eq!(v["tokens_total"], 0);
        assert_eq!(v["error_rate"], 0.0);
        assert!(v["tools"].as_array().unwrap().is_empty());
        assert_eq!(v["window"], "all");
    }

    #[test]
    fn rollup_aggregates_per_tool_and_overall() {
        let payloads = vec![
            payload("query_facts", 10, 90, 4, true),
            payload("query_facts", 10, 290, 8, true),
            payload("store_fact", 50, 50, 2, false),
        ];
        let v = usage_rollup("alice", &payloads, "24h");
        assert_eq!(v["calls_total"], 3);
        assert_eq!(v["tokens_total"], 500);
        assert_eq!(v["errors_total"], 1);
        assert!((v["error_rate"].as_f64().unwrap() - 0.3333).abs() < 0.001);
        let tools = v["tools"].as_array().unwrap();
        // Sorted by calls desc → query_facts first.
        assert_eq!(tools[0]["tool"], "query_facts");
        assert_eq!(tools[0]["calls"], 2);
        assert_eq!(tools[0]["avg_tokens"], 200);
        assert_eq!(tools[0]["p50_ms"], 8);
        assert_eq!(tools[1]["tool"], "store_fact");
        assert_eq!(tools[1]["calls"], 1);
    }

    #[test]
    fn ledger_file_path_sanitises_scoped_id() {
        let p = ledger_file_path(std::path::Path::new("/data"), "claude-work");
        assert_eq!(
            p,
            std::path::PathBuf::from("/data/observations/ledger__claude-work.jsonl")
        );
    }

    #[test]
    fn read_missing_file_is_empty_not_error() {
        let dir = tempfile::tempdir().unwrap();
        let out = read_ledger_payloads(dir.path(), "nobody", None).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn read_filters_kind_and_window() {
        let dir = tempfile::tempdir().unwrap();
        let obs_dir = dir.path().join("observations");
        std::fs::create_dir_all(&obs_dir).unwrap();
        let old_ts = "2020-01-01T00:00:00Z";
        let new_ts = Utc::now().to_rfc3339();
        let lines = [
            json!({"kind": LEDGER_EVENT_KIND, "ts": new_ts, "payload": payload("query", 1, 1, 1, true)}),
            json!({"kind": LEDGER_EVENT_KIND, "ts": old_ts, "payload": payload("query", 1, 1, 1, true)}),
            json!({"kind": "session_start", "ts": new_ts, "payload": {}}),
        ];
        let body = lines.iter().map(|l| l.to_string()).collect::<Vec<_>>().join("\n");
        std::fs::write(obs_dir.join("ledger__alice.jsonl"), body).unwrap();

        let all = read_ledger_payloads(dir.path(), "alice", None).unwrap();
        assert_eq!(all.len(), 2, "non-ledger kinds filtered");
        let recent = read_ledger_payloads(dir.path(), "alice", Some(Utc::now() - ChronoDuration::hours(1))).unwrap();
        assert_eq!(recent.len(), 1, "window filter drops the 2020 event");
    }
}
