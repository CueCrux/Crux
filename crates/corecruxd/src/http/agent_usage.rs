// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
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

/// True when `file_name` is a ledger file for `passport`. Observation
/// writes scope session ids (`__agent_session::<principal>::ledger::<p>`),
/// so the on-disk name carries a deploy-dependent principal prefix —
/// `__agent_session__mcp-loopback__ledger__<p>.jsonl` on current deploys,
/// bare `ledger__<p>.jsonl` on pre-scoping ones. Suffix-match both rather
/// than reconstructing the prefix, so a principal rename can't silently
/// zero the rollup again (the 2026-07-24 bug this replaced).
fn is_ledger_file_for(file_name: &str, passport: &str) -> bool {
    let base = format!(
        "{}.jsonl",
        sanitize_session_id_for_filename(&format!("ledger::{passport}"))
    );
    file_name == base || file_name.ends_with(&format!("__{base}"))
}

/// True for any passport's ledger file (fleet scan).
fn is_any_ledger_file(file_name: &str) -> bool {
    let is_jsonl = std::path::Path::new(file_name)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"));
    is_jsonl && (file_name.starts_with("ledger__") || file_name.contains("__ledger__"))
}

/// All observation files matching `filter`, sorted for determinism. A
/// missing observations dir is an empty ledger, not an error.
fn ledger_file_paths(data_dir: &std::path::Path, filter: impl Fn(&str) -> bool) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(data_dir.join("observations")) {
        for entry in entries.flatten() {
            if filter(&entry.file_name().to_string_lossy()) {
                out.push(entry.path());
            }
        }
    }
    out.sort();
    out
}

/// Read ledger event payloads (with envelope timestamps) from one file
/// into `out`. A missing file is an empty ledger, not an error.
fn read_ledger_file(
    path: &std::path::Path,
    since: Option<DateTime<Utc>>,
    out: &mut Vec<(Value, Option<DateTime<Utc>>)>,
) -> std::io::Result<()> {
    use std::io::BufRead;
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    let reader = std::io::BufReader::new(file);
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
        let ts = record["ts"]
            .as_str()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc));
        if let Some(since) = since {
            if ts.is_some_and(|t| t < since) {
                continue;
            }
        }
        out.push((record["payload"].clone(), ts));
    }
    Ok(())
}

/// Read ledger event payloads for one passport, merged across every
/// matching file (scoped + legacy names).
fn read_ledger_payloads(
    data_dir: &std::path::Path,
    passport: &str,
    since: Option<DateTime<Utc>>,
) -> std::io::Result<Vec<Value>> {
    let mut records = Vec::new();
    for path in ledger_file_paths(data_dir, |name| is_ledger_file_for(name, passport)) {
        read_ledger_file(&path, since, &mut records)?;
    }
    Ok(records.into_iter().map(|(payload, _)| payload).collect())
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

// ── Fleet-wide per-tool rollup (`GET /v1/mcp/tools/usage`) ───────────────

/// Pure fleet rollup: every catalog tool appears (zeros when never
/// called); tools present in the ledger but absent from the catalog are
/// flagged `in_catalog: false` (removed/renamed tools). Catalog entries
/// are `(name, description)` so the console can render the page from
/// this one response. Unit-testable without IO.
fn fleet_rollup(catalog: &[(String, String)], records: &[(Value, Option<DateTime<Utc>>)], window: &str) -> Value {
    struct Agg {
        calls: u64,
        errors: u64,
        tokens: u64,
        latencies: Vec<u64>,
        passports: std::collections::BTreeSet<String>,
        last_called: Option<DateTime<Utc>>,
    }
    let mut per_tool: std::collections::BTreeMap<String, Agg> = std::collections::BTreeMap::new();
    let mut fleet_passports: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut errors_total: u64 = 0;

    for (p, ts) in records {
        let tool = p["tool"].as_str().unwrap_or("unknown").to_string();
        let agg = per_tool.entry(tool).or_insert_with(|| Agg {
            calls: 0,
            errors: 0,
            tokens: 0,
            latencies: Vec::new(),
            passports: std::collections::BTreeSet::new(),
            last_called: None,
        });
        agg.calls += 1;
        if p["outcome"].as_str() == Some("error") {
            agg.errors += 1;
            errors_total += 1;
        }
        agg.tokens = agg
            .tokens
            .saturating_add(p["est_tokens_in"].as_u64().unwrap_or(0) + p["est_tokens_out"].as_u64().unwrap_or(0));
        if let Some(ms) = p["latency_ms"].as_u64() {
            agg.latencies.push(ms);
        }
        if let Some(passport) = p["passport"].as_str() {
            agg.passports.insert(passport.to_string());
            fleet_passports.insert(passport.to_string());
        }
        if ts.is_some() && (*ts > agg.last_called) {
            agg.last_called = *ts;
        }
    }

    let descriptions: std::collections::BTreeMap<&str, &str> =
        catalog.iter().map(|(n, d)| (n.as_str(), d.as_str())).collect();
    let mut names: std::collections::BTreeSet<String> = catalog.iter().map(|(n, _)| n.clone()).collect();
    names.extend(per_tool.keys().cloned());

    let mut tools: Vec<Value> = names
        .into_iter()
        .map(|name| {
            let description = descriptions.get(name.as_str());
            let in_catalog = description.is_some();
            let description = description.copied().unwrap_or("");
            match per_tool.get_mut(&name) {
                Some(agg) => {
                    agg.latencies.sort_unstable();
                    let p50_ms = agg
                        .latencies
                        .get(agg.latencies.len() / 2)
                        .map_or(Value::Null, |ms| json!(ms));
                    json!({
                        "tool": name,
                        "description": description,
                        "in_catalog": in_catalog,
                        "calls": agg.calls,
                        "errors": agg.errors,
                        "error_rate": if agg.calls > 0 { ((agg.errors as f64 / agg.calls as f64) * 10_000.0).round() / 10_000.0 } else { 0.0 },
                        "passports": agg.passports.len(),
                        "avg_tokens": if agg.calls > 0 { agg.tokens / agg.calls } else { 0 },
                        "p50_ms": p50_ms,
                        "last_called": agg.last_called.map_or(Value::Null, |t| json!(t.to_rfc3339())),
                    })
                }
                None => json!({
                    "tool": name,
                    "description": description,
                    "in_catalog": in_catalog,
                    "calls": 0,
                    "errors": 0,
                    "error_rate": 0.0,
                    "passports": 0,
                    "avg_tokens": 0,
                    "p50_ms": Value::Null,
                    "last_called": Value::Null,
                }),
            }
        })
        .collect();
    tools.sort_by(|a, b| {
        b["calls"]
            .as_u64()
            .cmp(&a["calls"].as_u64())
            .then_with(|| a["tool"].as_str().cmp(&b["tool"].as_str()))
    });

    let called = tools.iter().filter(|t| t["calls"].as_u64().unwrap_or(0) > 0).count();
    json!({
        "window": window,
        "calls_total": records.len() as u64,
        "errors_total": errors_total,
        "passports_total": fleet_passports.len(),
        "tools_in_catalog": catalog.len(),
        "tools_called": called,
        "tools_never_called": catalog.iter().filter(|(n, _)| !per_tool.contains_key(n)).count(),
        "tools": tools,
        "source": "agent.tool_invocation.v1",
    })
}

/// `GET /v1/mcp/tools/usage` — fleet-wide per-tool call rollup joined
/// against the full MCP catalog. Admin-read (same posture as the
/// `/v1/mcp/tools` catalog proxy it augments).
pub(super) async fn get_mcp_tools_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<UsageQuery>,
) -> Response {
    if let Err(resp) = require_http_any_scope(&state.auth, &headers, &["admin:read", "admin:write"]) {
        return resp.into_response();
    }
    let (since, window) = match params.window_hours {
        Some(h) => (Some(Utc::now() - ChronoDuration::hours(i64::from(h))), format!("{h}h")),
        None => (None, "all".to_string()),
    };
    let mut records = Vec::new();
    for path in ledger_file_paths(&state.data_dir, is_any_ledger_file) {
        if let Err(err) = read_ledger_file(&path, since, &mut records) {
            return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("read ledger: {err}"));
        }
    }
    let catalog: Vec<(String, String)> = crux_mcp::tools::list_tools()
        .into_iter()
        .map(|t| (t.name, t.description))
        .collect();
    (StatusCode::OK, Json(fleet_rollup(&catalog, &records, &window))).into_response()
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
    fn ledger_filename_matching_covers_scoped_and_legacy() {
        // Current deploys: the observation write path scopes the session id.
        assert!(is_ledger_file_for(
            "__agent_session__mcp-loopback__ledger__claude-work.jsonl",
            "claude-work"
        ));
        // Pre-scoping deploys wrote the bare name.
        assert!(is_ledger_file_for("ledger__claude-work.jsonl", "claude-work"));
        // A different principal prefix still matches (deploy-config rename).
        assert!(is_ledger_file_for(
            "__agent_session__other__ledger__alice.jsonl",
            "alice"
        ));
        // No cross-passport or partial-name matches.
        assert!(!is_ledger_file_for("__agent_session__x__ledger__alice.jsonl", "e"));
        assert!(!is_ledger_file_for("ledger__alice2.jsonl", "alice"));
        assert!(!is_ledger_file_for("ledger__alice.jsonl", "bob"));

        assert!(is_any_ledger_file("ledger__alice.jsonl"));
        assert!(is_any_ledger_file("__agent_session__mcp-loopback__ledger__bob.jsonl"));
        assert!(!is_any_ledger_file("__agent_session__x__mediation__group.jsonl"));
        assert!(!is_any_ledger_file("ledger__alice.tmp"));
    }

    #[test]
    fn read_merges_scoped_and_legacy_files() {
        let dir = tempfile::tempdir().unwrap();
        let obs_dir = dir.path().join("observations");
        std::fs::create_dir_all(&obs_dir).unwrap();
        let now = Utc::now().to_rfc3339();
        let line = |tool: &str| {
            json!({"kind": LEDGER_EVENT_KIND, "ts": now, "payload": payload(tool, 1, 1, 1, true)}).to_string()
        };
        std::fs::write(obs_dir.join("ledger__alice.jsonl"), line("query")).unwrap();
        std::fs::write(
            obs_dir.join("__agent_session__mcp-loopback__ledger__alice.jsonl"),
            line("store_fact"),
        )
        .unwrap();
        let out = read_ledger_payloads(dir.path(), "alice", None).unwrap();
        assert_eq!(out.len(), 2, "both file forms merged");
    }

    #[test]
    fn fleet_rollup_joins_catalog_with_zeros_and_flags_uncatalogued() {
        let catalog = vec![
            ("query_facts".to_string(), "Recall stored facts".to_string()),
            ("query_scan".to_string(), "Scan the substrate".to_string()),
        ];
        let ts = Utc::now();
        let records = vec![
            (payload("query_facts", 10, 90, 4, true), Some(ts)),
            (payload("query_facts", 10, 290, 8, false), Some(ts)),
            (payload("removed_tool", 1, 1, 2, true), Some(ts)),
        ];
        let v = fleet_rollup(&catalog, &records, "168h");
        assert_eq!(v["calls_total"], 3);
        assert_eq!(v["errors_total"], 1);
        assert_eq!(v["tools_in_catalog"], 2);
        assert_eq!(v["tools_called"], 2);
        assert_eq!(v["tools_never_called"], 1);
        let tools = v["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 3, "catalog union ledger");
        // Sorted by calls desc, then name.
        assert_eq!(tools[0]["tool"], "query_facts");
        assert_eq!(tools[0]["calls"], 2);
        assert_eq!(tools[0]["in_catalog"], true);
        assert_eq!(tools[0]["description"], "Recall stored facts");
        assert_eq!(tools[0]["passports"], 1);
        assert!((tools[0]["error_rate"].as_f64().unwrap() - 0.5).abs() < 0.001);
        assert!(tools[0]["last_called"].is_string());
        assert_eq!(tools[1]["tool"], "removed_tool");
        assert_eq!(tools[1]["in_catalog"], false);
        // Never-called catalog tool present with zeros.
        assert_eq!(tools[2]["tool"], "query_scan");
        assert_eq!(tools[2]["calls"], 0);
        assert_eq!(tools[2]["in_catalog"], true);
        assert!(tools[2]["last_called"].is_null());
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
