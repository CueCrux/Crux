// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use corecrux_types::{HealthzResponse, ProblemDetails};

use super::{
    is_query_feature_enabled, problem_response, to_valve_info, AppState, CommitLevel, HeaderMap, IntoResponse, Json,
    Response, RoutingInfo, RoutingTable, State, StatusCode, ValvesInfo,
};

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
            .map(|followers| followers.iter().filter(|f| f.node_id != node_id).count())
            .unwrap_or(0);
        if follower_count == 0 {
            status.missing_followers.push(shard.shard_id.clone());
        }
    }
    status
}

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
        s.to_string()
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

pub(super) async fn get_version(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "version": state.build.version,
        "commit": state.build.commit,
        "msrv": "1.88.0",
        "features": {
            "text_search": is_query_feature_enabled("CORECRUXD_QUERY_TEXT_SEARCH"),
            "graph_expand": is_query_feature_enabled("CORECRUXD_QUERY_GRAPH_EXPAND"),
            "self_observe": crux_observe::config::self_observe_enabled(),
            "mcp": std::env::var("CRUX_MCP_ENABLED").map(|v| v == "true" || v == "1").unwrap_or(false),
        }
    }))
}
