// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP surface over runtime span capture.
//!
//! ExecPlan `crux-runtime-codemap-and-agent-query-api-2026-07-27`, milestone M2.
//!
//! Everything here reports `capture_enabled: false` and empty data when
//! `CORECRUXD_TRACE_CAPTURE` is unset, rather than 404ing: a caller needs to
//! distinguish "capture is off" from "capture is on and nothing ran", and those
//! are very different answers.

use super::{require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Query, State, StatusCode};

#[derive(Debug, serde::Deserialize)]
pub(super) struct TraceSpansQuery {
    /// Restrict to a single trace.
    #[serde(default)]
    pub trace_id: Option<u64>,
    /// Cap the number of spans returned, newest-biased. Defaults to 500 so an
    /// unbounded ring cannot become an unbounded response.
    #[serde(default)]
    pub limit: Option<usize>,
}

const DEFAULT_SPAN_LIMIT: usize = 500;

/// `GET /v1/traces/stats` — is capture on, and what has it seen?
///
/// `dropped` is the honest data-loss counter: the ring evicts oldest-first when
/// full, so a rising `dropped` means the flush interval or capacity needs
/// raising, not that the daemon is misbehaving.
pub(super) async fn get_trace_stats(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let body = match crate::trace_span_ring() {
        Some(ring) => serde_json::json!({
            "capture_enabled": true,
            "retained": ring.len(),
            "capacity": ring.capacity(),
            "captured_total": ring.captured(),
            "dropped_total": ring.dropped(),
        }),
        None => serde_json::json!({
            "capture_enabled": false,
            "hint": format!(
                "set {}=1 to enable runtime span capture",
                crux_observe::span_layer::TRACE_CAPTURE_ENV
            ),
        }),
    };
    (StatusCode::OK, Json(body)).into_response()
}

/// `GET /v1/traces/spans` — the captured span tree, optionally one trace.
///
/// Read-only and non-draining, so polling this never destroys data the M4
/// flusher has not yet persisted.
pub(super) async fn get_trace_spans(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<TraceSpansQuery>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let Some(ring) = crate::trace_span_ring() else {
        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "capture_enabled": false,
                "spans": [],
                "hint": format!(
                    "set {}=1 to enable runtime span capture",
                    crux_observe::span_layer::TRACE_CAPTURE_ENV
                ),
            })),
        )
            .into_response();
    };

    let mut spans = ring.snapshot();
    if let Some(trace_id) = query.trace_id {
        spans.retain(|s| s.trace_id == trace_id);
    }
    let total_matched = spans.len();
    let limit = query.limit.unwrap_or(DEFAULT_SPAN_LIMIT);
    if spans.len() > limit {
        // Keep the newest: the tail of the ring is the interesting end.
        spans = spans.split_off(total_matched - limit);
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "capture_enabled": true,
            "total_matched": total_matched,
            "returned": spans.len(),
            "spans": spans,
        })),
    )
        .into_response()
}
