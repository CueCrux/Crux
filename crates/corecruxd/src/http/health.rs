// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Liveness + readiness probes — `/healthz`, `/readyz`, `/metrics` (Prometheus text format).

use corecrux_types::{HealthzResponse, ProblemDetails};

use super::{
    is_query_feature_enabled, problem_response, require_http_scopes, to_valve_info, AppState, CommitLevel, HeaderMap,
    IntoResponse, Json, Response, RoutingInfo, RoutingTable, State, StatusCode, ValvesInfo,
};

#[utoipa::path(
    get,
    path = "/healthz",
    tag = "Health",
    responses(
        (status = 200, description = "Node health status"),
    )
)]
pub(super) async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let _ = state.commit_level;
    let routing = state.routing.read().await.clone();
    let control_state = state.control.read().await.clone();
    let body = HealthzResponse {
        ok: true,
        build: state.build.clone(),
        compat: state.compat.clone(),
        sdk_version: state.sdk_version.clone(),
        routing: Some(RoutingInfo {
            shard_map_version: routing.current_version(),
            shard_count: routing.shard_count() as u64,
            last_reload_at: Some(routing.loaded_at),
            node_id: state.node_id.clone(),
        }),
        valves: Some(ValvesInfo {
            pause_ingest: to_valve_info(&control_state.valves.pause_ingest),
            pause_compaction: to_valve_info(&control_state.valves.pause_compaction),
            throttle: to_valve_info(&control_state.valves.throttle),
            read_only: to_valve_info(&control_state.valves.read_only),
            emergency_brake: to_valve_info(&control_state.valves.emergency_brake),
        }),
    };
    (StatusCode::OK, Json(body))
}

#[derive(serde::Serialize)]
struct ReadyOk {
    ok: bool,
}

#[derive(serde::Serialize)]
struct ReadyCheck {
    name: &'static str,
    ok: bool,
    error: Option<String>,
}

#[derive(serde::Serialize)]
struct ReadyFail {
    ok: bool,
    checks: Vec<ReadyCheck>,
}

#[derive(Debug, Default)]
pub(super) struct ReplicatedCommitTopologyStatus {
    pub(super) local_leader_shards: usize,
    pub(super) missing_followers: Vec<String>,
}

pub(super) fn evaluate_replicated_commit_topology(
    table: &RoutingTable,
    node_id: &str,
) -> ReplicatedCommitTopologyStatus {
    let mut status = ReplicatedCommitTopologyStatus::default();
    for shard in &table.shard_map.shards {
        if shard.leader.node_id != node_id {
            continue;
        }
        if matches!(shard.state, corecrux_types::ShardState::Retired) {
            continue;
        }
        status.local_leader_shards = status.local_leader_shards.saturating_add(1);
        let follower_count = shard
            .followers
            .as_ref()
            .map_or(0, |followers| followers.iter().filter(|f| f.node_id != node_id).count());
        if follower_count == 0 {
            status.missing_followers.push(shard.shard_id.clone());
        }
    }
    status
}

#[utoipa::path(
    get,
    path = "/readyz",
    tag = "Health",
    responses(
        (status = 200, description = "Node ready"),
        (status = 503, description = "Node not ready"),
    )
)]
pub(super) async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    // Phase 3 readiness: lock held + routing table loaded + control evidence + capacity checks.
    let routing = state.routing.read().await;
    let routing_loaded = !routing.shard_map.shards.is_empty();
    let replicated_topology = if matches!(state.commit_level, CommitLevel::ReplicatedCommit) {
        Some(evaluate_replicated_commit_topology(&routing, &state.node_id))
    } else {
        None
    };
    drop(routing);

    let readiness = state.readiness.read().await.clone();

    let replicated_commit_dataplane_ok =
        !matches!(state.commit_level, CommitLevel::ReplicatedCommit) || state.dataplane_pool.is_some();
    let replicated_commit_dataplane_error = if replicated_commit_dataplane_ok {
        None
    } else {
        Some("replicated commit selected but dataplane store is unavailable".to_string())
    };

    let replicated_commit_topology_ok = replicated_topology
        .as_ref()
        .is_none_or(|status| status.missing_followers.is_empty());
    let replicated_commit_topology_error = replicated_topology.as_ref().and_then(|status| {
        if status.missing_followers.is_empty() {
            None
        } else {
            let mut listed = status.missing_followers.clone();
            if listed.len() > 8 {
                listed.truncate(8);
            }
            Some(format!(
                "replicated commit requires followers; {} local leader shard(s) missing followers: {}",
                status.missing_followers.len(),
                listed.join(", ")
            ))
        }
    });

    let read_retry_failed_total = state.metrics.read_retry_failed_total("context_lost");
    let read_retry_failed_ok = state.read_retry_failed_readyz_threshold == 0
        || read_retry_failed_total < state.read_retry_failed_readyz_threshold;
    let read_retry_failed_error = if read_retry_failed_ok {
        None
    } else {
        Some(format!(
            "failed read retries exceeded threshold (failed={} threshold={})",
            read_retry_failed_total, state.read_retry_failed_readyz_threshold
        ))
    };
    let projection_snapshot_issues = if let Some(pool) = state.dataplane_pool.as_ref() {
        pool.projection_snapshot_issues().await
    } else {
        Vec::new()
    };
    for projection in [
        "artifact_living_state",
        "artifact_relations",
        "pressure_events",
        "artifact_dependents",
    ] {
        let ok = state.dataplane_pool.is_none()
            || !projection_snapshot_issues
                .iter()
                .any(|issue| issue.projection == "all" || issue.projection == projection);
        state.metrics.set_projection_snapshot_valid(projection, ok);
    }
    let projection_snapshots_valid_ok = state.dataplane_pool.is_none() || projection_snapshot_issues.is_empty();
    let projection_snapshots_valid_error = if projection_snapshots_valid_ok {
        None
    } else {
        let mut sample = projection_snapshot_issues
            .iter()
            .take(4)
            .map(|i| format!("{}:{}:{}", i.shard_id, i.projection, i.reason))
            .collect::<Vec<_>>();
        if projection_snapshot_issues.len() > sample.len() {
            sample.push(format!("...+{} more", projection_snapshot_issues.len() - sample.len()));
        }
        Some(format!("projection snapshots invalid ({})", sample.join(", ")))
    };
    let corruption_state_clear = !*state.corruption_detected.read().await;
    let corruption_state_error = if corruption_state_clear {
        None
    } else {
        Some("corruption state set by verify-store/scrub".to_string())
    };
    let control_evidence_ready = !readiness.control_evidence_hosted || readiness.control_evidence_ok;
    let control_evidence_error = if control_evidence_ready {
        None
    } else {
        Some(
            readiness
                .control_evidence_error
                .clone()
                .unwrap_or_else(|| "control evidence verification failed".to_string()),
        )
    };
    let capacity = state.capacity.read().await.clone();
    let capacity_ok =
        capacity.error.is_none() && capacity.total_bytes > 0 && capacity.free_ratio >= capacity.emergency_free_ratio;
    let capacity_error = if capacity_ok {
        None
    } else if let Some(err) = capacity.error.clone() {
        Some(err)
    } else {
        Some(format!(
            "data dir free ratio below emergency threshold (free_ratio={:.3} threshold={:.3} free_bytes={} total_bytes={})",
            capacity.free_ratio,
            capacity.emergency_free_ratio,
            capacity.free_bytes,
            capacity.total_bytes
        ))
    };

    if state.lock_held
        && routing_loaded
        && replicated_commit_dataplane_ok
        && replicated_commit_topology_ok
        && read_retry_failed_ok
        && projection_snapshots_valid_ok
        && corruption_state_clear
        && control_evidence_ready
        && capacity_ok
    {
        return (StatusCode::OK, Json(ReadyOk { ok: true })).into_response();
    }

    let mut checks = Vec::new();
    if !state.lock_held {
        checks.push(ReadyCheck {
            name: "data_dir_lock_held",
            ok: false,
            error: Some("LOCK file not held".to_string()),
        });
    }
    if !routing_loaded {
        checks.push(ReadyCheck {
            name: "routing_loaded",
            ok: false,
            error: Some("routing table not loaded".to_string()),
        });
    }
    if !replicated_commit_dataplane_ok {
        checks.push(ReadyCheck {
            name: "replicated_commit_dataplane",
            ok: false,
            error: replicated_commit_dataplane_error,
        });
    }
    if !replicated_commit_topology_ok {
        checks.push(ReadyCheck {
            name: "replicated_commit_topology",
            ok: false,
            error: replicated_commit_topology_error,
        });
    }
    if !read_retry_failed_ok {
        checks.push(ReadyCheck {
            name: "read_retry_failed_threshold",
            ok: false,
            error: read_retry_failed_error,
        });
    }
    if !projection_snapshots_valid_ok {
        checks.push(ReadyCheck {
            name: "projection_snapshots_valid",
            ok: false,
            error: projection_snapshots_valid_error,
        });
    }
    if !corruption_state_clear {
        checks.push(ReadyCheck {
            name: "corruption_state_clear",
            ok: false,
            error: corruption_state_error,
        });
    }
    if !control_evidence_ready {
        checks.push(ReadyCheck {
            name: "control_evidence_ok",
            ok: false,
            error: control_evidence_error,
        });
    }
    if !capacity_ok {
        checks.push(ReadyCheck {
            name: "data_dir_capacity",
            ok: false,
            error: capacity_error,
        });
    }

    (StatusCode::SERVICE_UNAVAILABLE, Json(ReadyFail { ok: false, checks })).into_response()
}

#[utoipa::path(
    get,
    path = "/metrics",
    tag = "Health",
    responses(
        (status = 200, description = "Prometheus metrics", content_type = "text/plain"),
    )
)]
pub(super) async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    match state.metrics.render() {
        Ok(body) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::CONTENT_TYPE,
                axum::http::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            );
            (StatusCode::OK, headers, body).into_response()
        }
        Err(err) => problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    }
}

// ── Production hardening: structured panic handler ──────────────────

pub(super) fn handle_panic(err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    let msg = if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        (*s).to_string()
    } else {
        "unknown panic".to_string()
    };
    tracing::error!(panic = %msg, "handler panicked");
    let pd = ProblemDetails::internal("internal server error (panic recovered)");
    let body = serde_json::to_string(&pd).unwrap_or_default();
    Response::builder()
        .status(500)
        .header("content-type", "application/problem+json")
        .body(axum::body::Body::from(body))
        .unwrap_or_default()
}

// ── Production hardening: /v1/version endpoint ──────────────────────

#[utoipa::path(
    get,
    path = "/v1/version",
    tag = "Health",
    responses(
        (status = 200, description = "Build version and feature flags"),
    )
)]
pub(super) async fn get_version(State(state): State<AppState>) -> impl IntoResponse {
    let sync_status = sync_runtime_status();
    let product = crate::product::ProductPosture::new(state.operating_mode, &state.enabled_pro_services);
    let cloud = crate::product::CloudPosture::from_sync(&sync_status);
    let cloud_access =
        crate::product::CloudAccessContract::new(state.operating_mode, &state.enabled_pro_services, &cloud);
    let agent_workbench = super::workbench::workbench_posture(&state);
    let (embeddings_enabled, semantic_profile) = {
        let store = state.fact_store.read().await;
        (store.embeddings_enabled(), store.semantic_profile())
    };
    let retrieval_segment_count = state.retrieval_index.read().await.segment_count();
    let protocol_contracts =
        crate::protocol_posture::ProtocolPosture::from_runtime(retrieval_segment_count, semantic_profile.as_ref());
    // Update/upgrade *status* is product-facing (is a newer build available, and
    // the upgrade hint) and is part of the public /v1/version contract (the
    // daemon's own smoke probe and integration tests assert it). Expose only the
    // status-shaped subset; operational internals (commit SHAs, repo dir, remote
    // and tracking refs) stay admin-only on /v1/admin/version, consistent with
    // the top-level `commit` redaction.
    let update = state.update_status.read().await.clone();
    let update_public = serde_json::json!({
        "enabled": update.enabled,
        "state": update.state,
        "ahead_by": update.ahead_by,
        "behind_by": update.behind_by,
        "comparison_stale": update.comparison_stale,
        "upgrade_hint": update.upgrade_hint,
    });
    Json(serde_json::json!({
        "version": state.build.version,
        "msrv": "1.88.0",
        "product": product,
        "cloud_access": {
            "schema": cloud_access.schema,
            "contract_path": "/v1/cloud/access-contract",
            "cloud_only_entitled": cloud_access.cloud_only_entitled,
            "cloud_only_active": cloud_access.cloud_only_active,
            "local_daemon_required_for_current_mode": cloud_access.local_daemon_required_for_current_mode,
            "mode_switching_supported": cloud_access.mode_switching_supported,
        },
        "agent_workbench": agent_workbench,
        "features": {
            "text_search": is_query_feature_enabled("CORECRUXD_QUERY_TEXT_SEARCH"),
            "graph_expand": is_query_feature_enabled("CORECRUXD_QUERY_GRAPH_EXPAND"),
            "self_observe": crux_observe::config::self_observe_enabled(),
            "mcp": state.mcp_enabled,
            "embeddings": embeddings_enabled,
        },
        "semantic_profile": semantic_profile,
        "protocol_contracts": protocol_contracts,
        "sync": {
            "mode": sync_status.mode,
            "configured": sync_status.configured,
            "background_sync_enabled": sync_status.background_sync_enabled,
            "degraded": sync_status.degraded,
            "degraded_reason": sync_status.degraded_reason,
            "remote_url_redacted": !sync_status.remote_url.is_empty(),
            "api_key_configured": sync_status.api_key_configured,
        },
        "update": update_public
    }))
}

pub(super) async fn get_admin_version(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let sync_status = sync_runtime_status();
    let update_status = state.update_status.read().await.public_view();
    let product = crate::product::ProductPosture::new(state.operating_mode, &state.enabled_pro_services);
    let cloud = crate::product::CloudPosture::from_sync(&sync_status);
    let cloud_access =
        crate::product::CloudAccessContract::new(state.operating_mode, &state.enabled_pro_services, &cloud);
    let action_enrichment = super::actions::action_enrichment_posture(&state);
    let agent_workbench = super::workbench::workbench_posture(&state);
    let gpu1_compute = super::gpu1::compute_posture(&state);
    let (embeddings_enabled, semantic_profile) = {
        let store = state.fact_store.read().await;
        (store.embeddings_enabled(), store.semantic_profile())
    };
    let retrieval_segment_count = state.retrieval_index.read().await.segment_count();
    let protocol_contracts =
        crate::protocol_posture::ProtocolPosture::from_runtime(retrieval_segment_count, semantic_profile.as_ref());
    Json(serde_json::json!({
        "version": state.build.version,
        "commit": state.build.commit,
        "msrv": "1.88.0",
        "passport": {
            // Daemon's local RCX passport identity. The public key is the
            // verification key for receipts minted by this daemon (e.g.
            // observation signatures); auditors with the JSONL + this hex
            // can verify offline.
            "fingerprint": state.passport_fpr,
            "public_key_hex": state.passport_public_key_hex,
            "alg": "ed25519",
        },
        "product": product,
        "cloud": cloud,
        "cloud_access": {
            "schema": cloud_access.schema,
            "contract_path": "/v1/cloud/access-contract",
            "cloud_only_entitled": cloud_access.cloud_only_entitled,
            "cloud_only_active": cloud_access.cloud_only_active,
            "local_daemon_required_for_current_mode": cloud_access.local_daemon_required_for_current_mode,
            "mode_switching_supported": cloud_access.mode_switching_supported,
        },
        "action_enrichment": action_enrichment,
        "agent_workbench": agent_workbench,
        "gpu1_compute": {
            "schema": gpu1_compute.schema,
            "contract_path": "/v1/gpu1/contract",
            "endpoint_configured": gpu1_compute.endpoint_configured,
            "api_key_configured": gpu1_compute.api_key_configured,
            "enabled_services": gpu1_compute.enabled_services,
            "remote_memory_sync_required": gpu1_compute.remote_memory_sync_required,
            "payload_policy": gpu1_compute.payload_policy,
        },
        "semantic_profile": semantic_profile,
        "protocol_contracts": protocol_contracts,
        "features": {
            "text_search": is_query_feature_enabled("CORECRUXD_QUERY_TEXT_SEARCH"),
            "graph_expand": is_query_feature_enabled("CORECRUXD_QUERY_GRAPH_EXPAND"),
            "self_observe": crux_observe::config::self_observe_enabled(),
            "mcp": state.mcp_enabled,
            "embeddings": embeddings_enabled,
        },
        "sync": {
            "mode": sync_status.mode,
            "configured": sync_status.configured,
            "background_sync_enabled": sync_status.background_sync_enabled,
            "remote_url": sync_status.remote_url,
            "api_key_configured": sync_status.api_key_configured,
            "degraded": sync_status.degraded,
            "degraded_reason": sync_status.degraded_reason,
        },
        "update": update_status
    }))
    .into_response()
}

pub(super) fn sync_runtime_status() -> corecrux_memory::sync::SyncRuntimeStatus {
    let background_sync_enabled = std::env::var("CORECRUXD_SYNC_ENABLED")
        .ok()
        .is_some_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
    let remote_url = std::env::var("CORECRUXD_SYNC_REMOTE_URL")
        .ok()
        .filter(|value| !value.is_empty());
    let api_key_configured = std::env::var("CORECRUXD_SYNC_API_KEY")
        .ok()
        .is_some_and(|value| !value.is_empty());

    corecrux_memory::sync::SyncRuntimeStatus::from_settings(
        background_sync_enabled,
        remote_url.as_deref(),
        api_key_configured,
    )
}
