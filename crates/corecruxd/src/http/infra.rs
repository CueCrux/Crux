// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
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
/// Reserved entity holding one fact per saved config bundle (keyed by name).
const CONFIGS_ENTITY: &str = "__infra__::configs";
/// Reserved entity holding one fact per shared session snapshot (keyed by id).
const SESSIONS_ENTITY: &str = "__infra__::sessions";

/// Latest, non-deleted fact per key under `entity`, mapped via `f`.
fn latest_by_key<F: Fn(&str, &corecrux_memory::fact_store::Fact, &serde_json::Value) -> serde_json::Value>(
    store: &corecrux_memory::FactStore,
    entity: &str,
    tenant_hash: &str,
    f: F,
) -> Vec<serde_json::Value> {
    let mut latest: BTreeMap<String, &corecrux_memory::fact_store::Fact> = BTreeMap::new();
    for fact in store.get_by_entity_for_tenant(entity, tenant_hash) {
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
            let value: serde_json::Value = serde_json::from_str(&fact.value).unwrap_or(serde_json::Value::Null);
            f(&fact.key, fact, &value)
        })
        .collect()
}

pub(super) async fn get_infra_summary(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let ctx = match crate::auth::http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };
    let tenant_hash = super::facts::tenant_hash_for_read_context(&ctx);

    let rails = serde_json::json!({
        "tailscale": env_flag_enabled("CORECRUXD_TS_IDENTITY_ENABLED"),
        "device": env_flag_enabled("CORECRUXD_DEVICE_GRANT_ENABLED"),
        "http_accept_agent_tokens": env_flag_enabled("CORECRUXD_HTTP_ACCEPT_AGENT_TOKENS"),
    });

    // Latest, non-deleted records under each __infra__ entity. Config bundles +
    // session snapshots return metadata only (not full contents).
    let (machines, configs, sessions) = {
        let store = state.fact_store.read().await;
        let machines = latest_by_key(
            &store,
            MACHINES_ENTITY,
            &tenant_hash,
            |key, fact, record| serde_json::json!({ "id": key, "record": record, "updated_at": fact.stored_at }),
        );
        let configs = latest_by_key(&store, CONFIGS_ENTITY, &tenant_hash, |key, fact, b| {
            serde_json::json!({
                "name": key,
                "source_host": b.get("source_host"),
                "files": b.get("files").and_then(|v| v.as_array()).map_or(0, |a| a.len()),
                "updated_at": fact.stored_at,
            })
        });
        let sessions = latest_by_key(&store, SESSIONS_ENTITY, &tenant_hash, |key, fact, snap| {
            serde_json::json!({
                "id": key,
                "source_host": snap.get("source_host"),
                "bytes": snap.get("bytes"),
                "updated_at": fact.stored_at,
            })
        });
        (machines, configs, sessions)
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
            "configs": configs,
            "sessions": sessions,
            "presence_count": presence_count,
            "checklist": checklist,
        })),
    )
        .into_response()
}
