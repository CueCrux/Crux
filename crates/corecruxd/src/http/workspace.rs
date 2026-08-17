// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! HTTP routes for the workspace scanner. The scanner walks a Rust workspace
//! (default `/src` under docker-compose.dev.yml) and emits structured facts
//! about crates, modules, files, symbols, deps, stubs, and dead code. The
//! latest scan is stored as a single fact `__workspace_scan__::latest::content`
//! so the context-graph endpoint can fold it into the graph.

#![allow(clippy::format_push_string)] // builder pattern: many appends to one String — write! macro hurts readability vs push_str(&format!(..))

use super::{problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, State, StatusCode};

use crate::workspace_scan::{LATEST_SCAN_ENTITY, SCAN_KEY};

/// `POST /v1/workspace/scan` — kick off a scan of the configured workspace
/// path. Returns the scan summary (no file contents) inline; full payload is
/// persisted as a fact.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_scan(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let scan_result = tokio::task::spawn_blocking(crate::workspace_scan::run_scan).await;
    let scan = match scan_result {
        Ok(Ok(s)) => s,
        Ok(Err(crate::workspace_scan::ScanError::NotConfigured)) => {
            return problem_response(
                StatusCode::PRECONDITION_FAILED,
                "workspace path not configured. Set CORECRUXD_WORKSPACE_PATH (or use docker-compose.dev.yml which mounts ./crates → /src/crates).",
            );
        }
        Ok(Err(crate::workspace_scan::ScanError::PathMissing(p))) => {
            return problem_response(
                StatusCode::PRECONDITION_FAILED,
                format!("workspace path '{p}' does not exist inside the daemon"),
            );
        }
        Ok(Err(err)) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {err}")),
    };

    // Persist the full scan as a single private fact.
    let value = match serde_json::to_string(&scan) {
        Ok(v) => v,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("encode: {err}")),
    };
    {
        let mut store = state.fact_store.write().await;
        let mut sf = corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: LATEST_SCAN_ENTITY.to_string(),
            key: SCAN_KEY.to_string(),
            value,
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };
        crate::fact_privacy::enforce_global(&mut sf);
        store.store(sf);
    }

    let summary = serde_json::json!({
        "scan_id": scan.scan_id,
        "root_path": scan.root_path,
        "duration_ms": scan.duration_ms,
        "stats": scan.stats,
    });
    (StatusCode::OK, Json(summary)).into_response()
}

/// `GET /v1/mcp/tools` — proxy of the MCP `tools/list` catalog through the
/// main HTTP port (14800) so the in-browser console can read it without
/// crossing CORS to the MCP port (14801). Returns the same shape as the
/// JSON-RPC tools/list result, minus the JSON-RPC envelope.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_mcp_tools(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let tools = crux_mcp::tools::list_tools();
    let serialised: Vec<serde_json::Value> = tools
        .into_iter()
        .map(|t| {
            serde_json::json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "count": serialised.len(),
            "tools": serialised,
        })),
    )
        .into_response()
}

/// `GET /v1/workspace/scan` — return the latest persisted scan in full.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_scan(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    match crate::workspace_scan::load_latest(&state.fact_store).await {
        Some(scan) => (StatusCode::OK, Json(scan)).into_response(),
        None => problem_response(
            StatusCode::NOT_FOUND,
            "no scan found. POST /v1/workspace/scan to run one.",
        ),
    }
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct StorylineQuery {
    /// Either `METHOD PATH` (e.g. `POST /v1/projects`) to root at a route's
    /// handler, or a file rel_path to root at any file. If absent, returns
    /// every route's storyline (or just the file inventory if no routes).
    #[serde(default)]
    pub root: Option<String>,
    /// `tree` (default) → ascii tree-art for LLM consumption.
    /// `json` → compact integer-keyed graph (files + edges + routes).
    #[serde(default)]
    pub format: Option<String>,
    /// When true, include edges that point at test files (paths under
    /// `tests/`, ending `_tests.rs` or `tests.rs`, or carrying
    /// `#![cfg(test)]`). Default false — test code skews density metrics.
    /// Accepts `1`, `true`, `yes`, `on` (case-insensitive); anything else
    /// is treated as false.
    #[serde(default)]
    pub include_tests: Option<String>,
}

fn parse_truthy(s: Option<&str>) -> bool {
    match s.map(|v| v.trim().to_ascii_lowercase()) {
        Some(v) => matches!(v.as_str(), "1" | "true" | "yes" | "on"),
        None => false,
    }
}

/// `GET /v1/workspace/storyline` — agent-friendly per-endpoint call tree
/// derived from the latest persisted workspace scan.
///
/// Examples:
/// - `?format=json` — full compact graph (no root needed; agents want it all).
/// - `?root=POST /v1/projects&format=tree` — single route storyline as text.
/// - `?root=crates/corecruxd/src/main.rs&format=tree` — root at any file.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_storyline(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<StorylineQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let scan = match crate::workspace_scan::load_latest(&state.fact_store).await {
        Some(s) => s,
        None => {
            return problem_response(
                StatusCode::NOT_FOUND,
                "no scan found. POST /v1/workspace/scan to run one.",
            )
        }
    };

    let format = q.format.as_deref().unwrap_or("tree");
    let include_tests = parse_truthy(q.include_tests.as_deref());

    // JSON mode: emit the compact graph regardless of root (agents pull it
    // once and reason locally).
    if format == "json" {
        return (
            StatusCode::OK,
            Json(crate::workspace_scan::storyline_compact_json(&scan, include_tests)),
        )
            .into_response();
    }

    // Tree mode.
    let mut out = String::new();
    match q.root.as_deref().map(|s| s.trim()) {
        Some(root) if !root.is_empty() => {
            // Try to match a route first ("METHOD PATH"), then fall back to
            // file rel_path.
            let route_match = root.split_once(' ').and_then(|(method, path)| {
                let m = method.to_ascii_uppercase();
                let p = path.trim();
                scan.routes.iter().find(|r| r.method == m && r.path == p).cloned()
            });
            if let Some(route) = route_match {
                if let Some(s) = crate::workspace_scan::compose_storyline_for_route(&scan, &route, include_tests) {
                    out.push_str(&crate::workspace_scan::format_storyline_tree(&s));
                } else {
                    return problem_response(
                        StatusCode::NOT_FOUND,
                        format!("route '{root}' has no resolvable handler file"),
                    );
                }
            } else if let Some(s) = crate::workspace_scan::compose_storyline_for_file(&scan, root, None, include_tests)
            {
                out.push_str(&crate::workspace_scan::format_storyline_tree(&s));
            } else {
                return problem_response(StatusCode::NOT_FOUND, format!("no route or file matched '{root}'"));
            }
        }
        _ => {
            // No root: emit one tree per route. Cap at 80 routes to keep
            // output bounded.
            for (i, route) in scan.routes.iter().take(80).enumerate() {
                if i > 0 {
                    out.push('\n');
                }
                if let Some(s) = crate::workspace_scan::compose_storyline_for_route(&scan, route, include_tests) {
                    out.push_str(&crate::workspace_scan::format_storyline_tree(&s));
                }
            }
            if scan.routes.len() > 80 {
                out.push_str(&format!(
                    "\n[... and {} more routes — pass &root=METHOD PATH for one]\n",
                    scan.routes.len() - 80
                ));
            }
        }
    }
    ([(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")], out).into_response()
}
