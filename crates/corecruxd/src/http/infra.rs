// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! IX / Infra console surface — `GET /v1/console/infra/summary`.
//!
//! One read endpoint feeding the console's IX (Infra) section: which auth rails
//! the daemon has enabled, the machines registered with it (the
//! `__infra__::machines` facts written by `corecruxctl login` / `machine
//! register`), live-presence count, and a derived onboarding checklist. Gated
//! `admin:read` (the `/v1/console/` route class).

use std::collections::BTreeMap;

use super::auth_rails::env_flag_enabled;
use super::{require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Response, State, StatusCode};

/// Reserved entity holding one fact per machine (keyed by hostname).
const MACHINES_ENTITY: &str = "__infra__::machines";

pub(super) async fn get_infra_summary(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let rails = serde_json::json!({
        "tailscale": env_flag_enabled("CORECRUXD_TS_IDENTITY_ENABLED"),
        "device": env_flag_enabled("CORECRUXD_DEVICE_GRANT_ENABLED"),
        "http_accept_agent_tokens": env_flag_enabled("CORECRUXD_HTTP_ACCEPT_AGENT_TOKENS"),
    });

    // Latest, non-deleted machine record per hostname.
    let machines: Vec<serde_json::Value> = {
        let store = state.fact_store.read().await;
        let mut latest: BTreeMap<String, &corecrux_memory::fact_store::Fact> = BTreeMap::new();
        for fact in store.get_by_entity(MACHINES_ENTITY) {
            if fact.deleted {
                continue;
            }
            latest
                .entry(fact.key.clone())
                .and_modify(|cur| {
                    if fact.version > cur.version {
                        *cur = fact;
                    }
                })
                .or_insert(fact);
        }
        latest
            .values()
            .map(|fact| {
                let record: serde_json::Value = serde_json::from_str(&fact.value).unwrap_or(serde_json::Value::Null);
                serde_json::json!({ "id": fact.key, "record": record, "updated_at": fact.stored_at })
            })
            .collect()
    };

    let presence_count = state.presence.snapshot().await.len();
    let machines_with_hooks = machines
        .iter()
        .filter(|m| m["record"]["hooks_installed"].as_bool().unwrap_or(false))
        .count();

    let checklist = serde_json::json!({
        "auth_configured": state.auth.mode().as_str() != "off",
        "mcp_enabled": state.mcp_enabled,
        "machines_registered": machines.len(),
        "machines_with_hooks": machines_with_hooks,
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "auth_mode": state.auth.mode().as_str(),
            "mcp_enabled": state.mcp_enabled,
            "node_id": state.node_id,
            "rails": rails,
            "machines": machines,
            "presence_count": presence_count,
            "checklist": checklist,
        })),
    )
        .into_response()
}
