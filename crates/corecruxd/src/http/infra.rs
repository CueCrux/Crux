// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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

#[tracing::instrument(level = "info", skip_all)]
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::auth::AuthMode;
    use crate::http::tests::{dev_scope_headers, test_app_state, test_app_state_with_auth};
    use crate::test_support::EnvVarGuard;
    use axum::body::to_bytes;
    use serde_json::Value;

    async fn body_json(resp: Response) -> Value {
        let bytes = to_bytes(resp.into_body(), 1 << 22).await.expect("read body");
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    /// Store one `__infra__` record. `AuthMode::Off` states read the default
    /// tenant, so key the fact the same way the handler will.
    async fn seed(state: &AppState, entity: &str, key: &str, value: Value) -> corecrux_memory::fact_store::Fact {
        let mut store = state.fact_store.write().await;
        store
            .try_store(corecrux_memory::fact_store::StoreFact {
                tenant_hash: corecrux_memory::fact_store::default_tenant_hash(),
                entity: entity.to_string(),
                key: key.to_string(),
                value: value.to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            })
            .expect("store infra fact")
    }

    async fn summary(state: AppState) -> Value {
        let resp = get_infra_summary(State(state), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        body_json(resp).await
    }

    // ── Auth gate ─────────────────────────────────────────────────────────

    /// `/v1/console/infra/summary` exposes registered machines and auth rails,
    /// so it must never be an unauthenticated read.
    #[tokio::test]
    async fn unauthenticated_read_is_rejected() {
        let state = test_app_state_with_auth(1, AuthMode::DevScopes);
        let resp = get_infra_summary(State(state), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// The route class is `admin:read`; a lesser read scope must not reach it.
    #[tokio::test]
    async fn lesser_read_scope_is_forbidden() {
        let state = test_app_state_with_auth(1, AuthMode::DevScopes);
        let resp = get_infra_summary(State(state), dev_scope_headers("facts:read")).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let state = test_app_state_with_auth(1, AuthMode::DevScopes);
        let resp = get_infra_summary(State(state), dev_scope_headers("admin:read")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── Response shape ────────────────────────────────────────────────────

    #[tokio::test]
    async fn empty_daemon_reports_empty_collections_not_null() {
        let body = summary(test_app_state(1)).await;
        assert_eq!(body["machines"], serde_json::json!([]));
        assert_eq!(body["configs"], serde_json::json!([]));
        assert_eq!(body["sessions"], serde_json::json!([]));
        assert_eq!(body["presence_count"], 0);
        assert_eq!(body["checklist"]["machines_registered"], 0);
        assert_eq!(body["checklist"]["machines_with_hooks"], 0);
        // AuthMode::Off must report the checklist item as NOT satisfied.
        assert_eq!(body["checklist"]["auth_configured"], false);
        assert_eq!(body["auth_mode"], "off");
    }

    #[tokio::test]
    async fn auth_configured_is_true_once_auth_is_on() {
        let state = test_app_state_with_auth(1, AuthMode::DevScopes);
        let resp = get_infra_summary(State(state), dev_scope_headers("admin:read")).await;
        let body = body_json(resp).await;
        assert_eq!(body["checklist"]["auth_configured"], true);
        assert_ne!(body["auth_mode"], "off");
    }

    // ── latest_by_key semantics ───────────────────────────────────────────

    /// Facts are append-only, so a re-registered machine leaves two rows for
    /// one key. The summary must show the newest, not both and not the first.
    #[tokio::test]
    async fn only_the_highest_version_per_key_is_returned() {
        let state = test_app_state(1);
        seed(&state, MACHINES_ENTITY, "hostA", serde_json::json!({"os": "old"})).await;
        seed(&state, MACHINES_ENTITY, "hostA", serde_json::json!({"os": "new"})).await;

        let body = summary(state).await;
        let machines = body["machines"].as_array().expect("machines array");
        assert_eq!(machines.len(), 1, "one row per key, got {machines:?}");
        assert_eq!(machines[0]["id"], "hostA");
        assert_eq!(machines[0]["record"]["os"], "new");
    }

    #[tokio::test]
    async fn deleted_records_are_excluded() {
        let state = test_app_state(1);
        let doomed = seed(&state, MACHINES_ENTITY, "hostGone", serde_json::json!({"os": "linux"})).await;
        seed(&state, MACHINES_ENTITY, "hostKept", serde_json::json!({"os": "linux"})).await;
        assert!(state.fact_store.write().await.delete(&doomed.fact_id));

        let body = summary(state).await;
        let ids: Vec<&str> = body["machines"]
            .as_array()
            .expect("machines array")
            .iter()
            .filter_map(|m| m["id"].as_str())
            .collect();
        assert_eq!(ids, vec!["hostKept"]);
    }

    /// A malformed stored value must degrade to `null`, not panic the whole
    /// console surface — one bad row cannot take out the endpoint.
    #[tokio::test]
    async fn an_unparsable_record_becomes_null_and_does_not_poison_siblings() {
        let state = test_app_state(1);
        {
            let mut store = state.fact_store.write().await;
            store
                .try_store(corecrux_memory::fact_store::StoreFact {
                    tenant_hash: corecrux_memory::fact_store::default_tenant_hash(),
                    entity: MACHINES_ENTITY.to_string(),
                    key: "hostBad".to_string(),
                    value: "not json at all".to_string(),
                    source_receipt: None,
                    confidence: 1.0,
                    private: false,
                    horizon_class: None,
                    actor: None,
                })
                .expect("store malformed fact");
        }
        seed(&state, MACHINES_ENTITY, "hostGood", serde_json::json!({"os": "linux"})).await;

        let body = summary(state).await;
        let machines = body["machines"].as_array().expect("machines array");
        assert_eq!(machines.len(), 2);
        let bad = machines.iter().find(|m| m["id"] == "hostBad").expect("bad row present");
        assert_eq!(bad["record"], Value::Null);
        let good = machines
            .iter()
            .find(|m| m["id"] == "hostGood")
            .expect("good row present");
        assert_eq!(good["record"]["os"], "linux");
    }

    #[tokio::test]
    async fn machines_with_hooks_counts_only_the_installed_ones() {
        let state = test_app_state(1);
        seed(
            &state,
            MACHINES_ENTITY,
            "a",
            serde_json::json!({"hooks_installed": true}),
        )
        .await;
        seed(
            &state,
            MACHINES_ENTITY,
            "b",
            serde_json::json!({"hooks_installed": false}),
        )
        .await;
        // Absent field must count as not-installed, not as unknown-so-true.
        seed(&state, MACHINES_ENTITY, "c", serde_json::json!({})).await;

        let body = summary(state).await;
        assert_eq!(body["checklist"]["machines_registered"], 3);
        assert_eq!(body["checklist"]["machines_with_hooks"], 1);
    }

    // ── Metadata-only projections (contents must not leak) ────────────────

    /// The doc comment promises config bundles return "metadata only (not full
    /// contents)". This is the assertion that holds that promise: `files` is a
    /// count, and no file body appears anywhere in the payload.
    #[tokio::test]
    async fn config_bundles_return_a_file_count_never_file_contents() {
        let state = test_app_state(1);
        seed(
            &state,
            CONFIGS_ENTITY,
            "laptop-bundle",
            serde_json::json!({
                "source_host": "laptop",
                "files": [
                    {"path": ".crux/agent-profile.toml", "contents": "SUPER_SECRET_TOKEN_VALUE"},
                    {"path": "settings.json", "contents": "another-secret"},
                ],
            }),
        )
        .await;

        let body = summary(state).await;
        let configs = body["configs"].as_array().expect("configs array");
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0]["name"], "laptop-bundle");
        assert_eq!(configs[0]["source_host"], "laptop");
        assert_eq!(configs[0]["files"], 2, "files must be a COUNT, not the array");
        let serialized = body.to_string();
        assert!(
            !serialized.contains("SUPER_SECRET_TOKEN_VALUE") && !serialized.contains("another-secret"),
            "config bundle contents leaked into the infra summary: {serialized}"
        );
    }

    /// A bundle with no `files` key must report 0 rather than failing.
    #[tokio::test]
    async fn a_bundle_without_files_reports_zero() {
        let state = test_app_state(1);
        seed(&state, CONFIGS_ENTITY, "empty", serde_json::json!({"source_host": "h"})).await;
        let body = summary(state).await;
        assert_eq!(body["configs"][0]["files"], 0);
    }

    #[tokio::test]
    async fn session_snapshots_return_metadata_never_the_snapshot_body() {
        let state = test_app_state(1);
        seed(
            &state,
            SESSIONS_ENTITY,
            "sess-1",
            serde_json::json!({
                "source_host": "laptop",
                "bytes": 4096,
                "transcript": "PRIVATE_TRANSCRIPT_BODY",
            }),
        )
        .await;

        let body = summary(state).await;
        let sessions = body["sessions"].as_array().expect("sessions array");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["id"], "sess-1");
        assert_eq!(sessions[0]["bytes"], 4096);
        assert!(
            !body.to_string().contains("PRIVATE_TRANSCRIPT_BODY"),
            "session snapshot body leaked into the infra summary"
        );
    }

    // ── Presence + rails ──────────────────────────────────────────────────

    #[tokio::test]
    async fn presence_count_reflects_live_touches() {
        let state = test_app_state(1);
        state.presence.touch("personal-default", "GET", "/v1/facts").await;
        state.presence.touch("agent-claude", "GET", "/v1/facts").await;
        // Same passport again must not double-count.
        state.presence.touch("agent-claude", "GET", "/v1/query").await;

        let body = summary(state).await;
        assert_eq!(body["presence_count"], 2);
    }

    /// The three rail flags are read from process env, so assert both
    /// directions — a flag stuck at `true` would misreport the daemon's
    /// posture on the console.
    #[tokio::test]
    #[serial_test::serial]
    async fn rails_track_their_env_flags_in_both_directions() {
        let _ts = EnvVarGuard::unset("CORECRUXD_TS_IDENTITY_ENABLED");
        let _dev = EnvVarGuard::unset("CORECRUXD_DEVICE_GRANT_ENABLED");
        let _tok = EnvVarGuard::unset("CORECRUXD_HTTP_ACCEPT_AGENT_TOKENS");

        let body = summary(test_app_state(1)).await;
        assert_eq!(body["rails"]["tailscale"], false);
        assert_eq!(body["rails"]["device"], false);
        assert_eq!(body["rails"]["http_accept_agent_tokens"], false);

        let _ts_on = EnvVarGuard::set("CORECRUXD_TS_IDENTITY_ENABLED", "1");
        let _dev_on = EnvVarGuard::set("CORECRUXD_DEVICE_GRANT_ENABLED", "true");
        // A value that is NOT a recognised truthy token must stay false.
        let _tok_bad = EnvVarGuard::set("CORECRUXD_HTTP_ACCEPT_AGENT_TOKENS", "0");

        let body = summary(test_app_state(1)).await;
        assert_eq!(body["rails"]["tailscale"], true);
        assert_eq!(body["rails"]["device"], true);
        assert_eq!(body["rails"]["http_accept_agent_tokens"], false);
    }

    // ── Tenant isolation ──────────────────────────────────────────────────

    /// Another tenant's machines must not appear in this tenant's summary.
    #[tokio::test]
    async fn records_from_another_tenant_are_not_returned() {
        let state = test_app_state(1);
        seed(&state, MACHINES_ENTITY, "mine", serde_json::json!({"os": "linux"})).await;
        {
            let mut store = state.fact_store.write().await;
            store
                .try_store(corecrux_memory::fact_store::StoreFact {
                    tenant_hash: "some-other-tenant".to_string(),
                    entity: MACHINES_ENTITY.to_string(),
                    key: "theirs".to_string(),
                    value: serde_json::json!({"os": "linux"}).to_string(),
                    source_receipt: None,
                    confidence: 1.0,
                    private: false,
                    horizon_class: None,
                    actor: None,
                })
                .expect("store other-tenant fact");
        }

        let body = summary(state).await;
        let ids: Vec<&str> = body["machines"]
            .as_array()
            .expect("machines array")
            .iter()
            .filter_map(|m| m["id"].as_str())
            .collect();
        assert_eq!(ids, vec!["mine"], "cross-tenant infra record leaked");
    }
}
