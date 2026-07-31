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

struct CappedWorkspaceJson {
    bytes: Vec<u8>,
    limit: usize,
}

impl std::io::Write for CappedWorkspaceJson {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "workspace scan exceeds its serialized-byte ceiling",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode_workspace_scan_with_limit(
    scan: &crate::workspace_scan::WorkspaceScan,
    limit: usize,
) -> std::io::Result<String> {
    let mut writer = CappedWorkspaceJson {
        bytes: Vec::with_capacity(limit.min(64 * 1024)),
        limit,
    };
    serde_json::to_writer(&mut writer, scan)
        .map_err(|error| std::io::Error::new(error.io_error_kind().unwrap_or(std::io::ErrorKind::Other), error))?;
    String::from_utf8(writer.bytes).map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

#[allow(clippy::result_large_err)]
pub(super) fn require_workspace_scan_global_authority(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), crate::problem::ProblemResponse> {
    let context = crate::auth::passport_bound_context(&state.auth, headers)?;
    if context.auth_enforced() && !context.has_global_tenant_authority() {
        return Err(crate::problem::ProblemResponse(
            corecrux_types::ProblemDetails::forbidden("workspace scanning requires cross-tenant operator authority")
                .with_extensions(serde_json::json!({
                    "code": "GLOBAL_TENANT_AUTHORITY_REQUIRED",
                })),
        ));
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn require_workspace_scan_operator(
    state: &AppState,
    headers: &HeaderMap,
    scopes: &[&str],
) -> Result<(), crate::problem::ProblemResponse> {
    require_http_scopes(&state.auth, headers, scopes)?;
    require_workspace_scan_global_authority(state, headers)
}

/// `POST /v1/workspace/scan` — kick off a scan of the configured workspace
/// path. Returns the scan summary (no file contents) inline; full payload is
/// persisted as a fact.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_scan(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_workspace_scan_operator(&state, &headers, &["admin:write"]) {
        return problem.into_response();
    }
    let permit = match state.repo_scan_semaphore.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return problem_response(StatusCode::SERVICE_UNAVAILABLE, "repository scan admission is busy"),
    };
    let scan_policy = state.repo_scan_policy.clone();
    let scan_result = tokio::task::spawn_blocking(move || {
        crate::workspace_scan::run_scan_with_policy(&scan_policy).map(|scan| (scan, permit))
    })
    .await;
    let (scan, scan_permit) = match scan_result {
        Ok(Ok(result)) => result,
        Ok(Err(crate::workspace_scan::ScanError::NotConfigured)) => {
            return problem_response(
                StatusCode::PRECONDITION_FAILED,
                "workspace path not configured. Set CORECRUXD_WORKSPACE_PATH (or use docker-compose.dev.yml which mounts ./crates → /src/crates).",
            );
        }
        Ok(Err(err)) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("join: {err}")),
    };

    // Encoding can traverse tens of MiB of generated state, so keep it on the
    // blocking pool and retain global scan admission until publication.
    let encoded = tokio::task::spawn_blocking(move || {
        encode_workspace_scan_with_limit(&scan, crate::repo_scan_policy::MAX_DURABLE_SCAN_OUTPUT_BYTES as usize)
            .map(|value| (scan, value, scan_permit))
    })
    .await;
    let (scan, value, _scan_permit) = match encoded {
        Ok(Ok(result)) => result,
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::InvalidData => {
            return problem_response(StatusCode::PAYLOAD_TOO_LARGE, error.to_string())
        }
        Ok(Err(error)) => {
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("workspace scan encode failed: {error}"),
            )
        }
        Err(error) => {
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("workspace scan encode task failed: {error}"),
            )
        }
    };

    // Persist only the latest full scan. A durable latest-only replacement
    // bounds resident/replay history and refuses to erase held predecessors.
    {
        let mut store = state.fact_store.write().await;
        let sf = corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: LATEST_SCAN_ENTITY.to_string(),
            key: SCAN_KEY.to_string(),
            value,
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        };
        if let Err(error) = store.try_replace_latest_daemon_control(sf) {
            return match error.kind() {
                std::io::ErrorKind::InvalidData => problem_response(StatusCode::PAYLOAD_TOO_LARGE, error.to_string()),
                std::io::ErrorKind::PermissionDenied => problem_response(StatusCode::LOCKED, error.to_string()),
                std::io::ErrorKind::WouldBlock => problem_response(StatusCode::SERVICE_UNAVAILABLE, error.to_string()),
                _ => problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("workspace scan persistence failed: {error}"),
                ),
            };
        }
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
    if let Err(problem) = require_workspace_scan_operator(&state, &headers, &["admin:read"]) {
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
    if let Err(problem) = require_workspace_scan_operator(&state, &headers, &["admin:read"]) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_scan_encoding_is_bounded_before_fact_persistence() {
        let scan = crate::workspace_scan::WorkspaceScan {
            root_path: "x".repeat(256),
            ..Default::default()
        };
        let error = encode_workspace_scan_with_limit(&scan, 128).expect_err("oversized JSON must be bounded");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(encode_workspace_scan_with_limit(&crate::workspace_scan::WorkspaceScan::default(), 4096).is_ok());
    }
}
