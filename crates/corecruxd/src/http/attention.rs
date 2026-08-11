// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `GET /v1/attention/summary` — counts-only attention roll-up (ExecPlan
//! `crux-hosted-relay-gateway-2026-07-30`, M7a).
//!
//! The classification lives in [`crate::attention`]; this file is only the
//! feed-gathering and the response. See that module for why the payload is
//! counts and nothing else, and for the parity rules against
//! `console/v2/render.js`.
//!
//! The item set is drawn through `work::kanban_items_for_query` +
//! `work::merge_work_sources` — the same helpers `GET /v1/work` uses — so this
//! endpoint cannot come to disagree with the panel it summarises.

use super::{AppState, HeaderMap, IntoResponse, Json, Query, State, StatusCode};

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[derive(Debug, Default, serde::Deserialize)]
pub(super) struct SummaryQuery {
    /// Narrow to one project, matching `/v1/work?project_id=`. Absent means the
    /// whole board.
    pub project_id: Option<String>,
}

/// `GET /v1/attention/summary?project_id=` — four counts and a clock.
///
/// Requires `admin:read`, the same scope as the three feeds it aggregates.
/// Aggregating does not lower the bar: the counts are derived from work items
/// and coord sessions, so anyone who may read the summary is someone who may
/// already read the inputs.
///
/// Coord being disabled is **not** an error here. Unlike `/v1/coord/active`,
/// which 404s when the coordination plane is off, this endpoint still has work
/// items to count — so it reports the work-derived counts and simply contributes
/// no sessions. Returning an error instead would take the whole roll-up down
/// over an optional subsystem.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_attention_summary(
    State(state): State<AppState>,
    Query(q): Query<SummaryQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Resolved through the same context `GET /v1/work` uses, not
    // `require_http_scopes`: the counts below are derived from work items, and
    // those are tenant-owned. Holding `admin:read` says you may read a summary,
    // not whose summary — without a tenant to answer for, this endpoint counted
    // every tenant's items into one roll-up.
    let context = match super::work::work_scope_context(&state, &headers, "admin:read") {
        Ok(context) => context,
        Err(response) => return response,
    };
    let tenant_id = match context.resolve_authorized_tenant(None) {
        Ok(tenant_id) => tenant_id,
        Err(problem) => return problem.into_response(),
    };
    let now = now_unix_ms();

    let work_query = super::work::ListWorkQuery {
        project_id: q.project_id.clone(),
        ..Default::default()
    };

    let store = state.fact_store.read().await;
    let kanban = super::work::kanban_items_for_query(&store, &work_query, &tenant_id);
    let execplans = super::work::execplan_items_for_query(&store, &work_query, &tenant_id);
    let gates = crate::work::list_pending_gates(&store, Some(&tenant_id), None);
    let bindings = if state.coord_enabled {
        crate::session_bindings::list_bindings(&store)
    } else {
        Vec::new()
    };
    drop(store);

    let items = super::work::merge_work_sources(kanban, execplans);

    // Only `pending` gates are attention. `approved` / `rejected` /
    // `auto_approved` rows are history and counting them would make the queue
    // look permanently occupied.
    let pending_gates: Vec<&crate::work::PendingGateAction> =
        gates.iter().filter(|gate| gate.status == "pending").collect();
    let gate_work_ids: Vec<&str> = pending_gates.iter().map(|gate| gate.work_id.as_str()).collect();

    let work_signals: Vec<crate::attention::WorkSignal<'_>> = items
        .iter()
        .map(|item| crate::attention::WorkSignal {
            id: &item.id,
            state: &item.state,
            superseded: item.superseded_by.is_some(),
        })
        .collect();

    // Session liveness is passport-level presence, exactly as `/v1/coord/active`
    // reads it; the classifier applies the staleness window on top.
    let sessions: Vec<crate::attention::SessionSignal> = if state.coord_enabled {
        let presence: std::collections::BTreeMap<String, u64> = state
            .presence
            .snapshot()
            .await
            .into_iter()
            .map(|entry| (entry.passport_id, entry.last_seen_at_unix_ms))
            .collect();
        bindings
            .iter()
            .filter(|binding| {
                q.project_id.as_deref().is_none_or(|pid| {
                    // A session that declared no project is still a potential
                    // writer on this tree, so it is not filtered out — the same
                    // rule `coord::assemble_active` applies.
                    binding.project_id.as_deref().is_none_or(|bound| bound == pid)
                })
            })
            .filter_map(|binding| {
                presence
                    .get(&binding.passport_id)
                    .map(|&last_seen_unix_ms| crate::attention::SessionSignal { last_seen_unix_ms })
            })
            .collect()
    } else {
        Vec::new()
    };

    let summary = crate::attention::summarize(&work_signals, &gate_work_ids, pending_gates.len(), &sessions, now);

    (StatusCode::OK, Json(summary)).into_response()
}
