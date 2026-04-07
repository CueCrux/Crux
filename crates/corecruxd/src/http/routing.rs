// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use super::{
    format_u64_hex, problem_response, require_http_scopes, stream_hash_xxhash64, AppState, HeaderMap, IntoResponse,
    Json, State, StatusCode,
};

#[derive(Debug, serde::Deserialize)]
pub(super) struct RouteQuery {
    #[serde(rename = "tenantId")]
    pub(super) tenant_id: String,
    #[serde(rename = "streamType")]
    pub(super) stream_type: String,
    #[serde(rename = "streamId")]
    pub(super) stream_id: String,
}

#[derive(serde::Serialize)]
pub(super) struct RouteResponse {
    #[serde(rename = "streamHash")]
    pub(super) stream_hash: String,
    #[serde(rename = "shardId")]
    pub(super) shard_id: String,
    pub(super) epoch: u64,
    #[serde(rename = "shardMapVersion")]
    pub(super) shard_map_version: u64,
    #[serde(rename = "leaderGrpcAddr")]
    pub(super) leader_grpc_addr: String,
}

#[derive(serde::Serialize)]
pub(super) struct RouteV1Response {
    #[serde(rename = "streamHash")]
    pub(super) stream_hash: String,
    #[serde(rename = "shardId")]
    pub(super) shard_id: String,
    pub(super) epoch: u64,
    #[serde(rename = "shardMapVersion")]
    pub(super) shard_map_version: u64,
    #[serde(rename = "leaderGrpcAddr")]
    pub(super) leader_grpc_addr: String,
    #[serde(rename = "leaderNodeId")]
    pub(super) leader_node_id: String,
    #[serde(rename = "shardGpuId")]
    pub(super) shard_gpu_id: Option<i32>,
    #[serde(rename = "ownerGpuId")]
    pub(super) owner_gpu_id: i32,
    #[serde(rename = "workerUp")]
    pub(super) worker_up: bool,
    #[serde(rename = "shardHosted")]
    pub(super) shard_hosted: bool,
}

#[tracing::instrument(level = "info", skip(state, headers), fields(tenant_id = %q.tenant_id, stream_type = %q.stream_type, stream_id = %q.stream_id))]
pub(super) async fn route_debug(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<RouteQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let stream_hash = match stream_hash_xxhash64(&q.tenant_id, &q.stream_type, &q.stream_id) {
        Ok(h) => h,
        Err(err) => {
            return problem_response(StatusCode::BAD_REQUEST, err.to_string());
        }
    };

    let routing = state.routing.read().await.clone();
    let Some(decision) = routing.route_stream_hash(stream_hash) else {
        return problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no shard range matched streamHash (invalid routing table)",
        );
    };

    (
        StatusCode::OK,
        Json(RouteResponse {
            stream_hash: format_u64_hex(decision.stream_hash),
            shard_id: decision.shard_id,
            epoch: decision.epoch,
            shard_map_version: decision.shard_map_version,
            leader_grpc_addr: decision.leader_grpc_addr,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(tenant_id = %q.tenant_id, stream_type = %q.stream_type, stream_id = %q.stream_id))]
pub(super) async fn route_v1(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<RouteQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let stream_hash = match stream_hash_xxhash64(&q.tenant_id, &q.stream_type, &q.stream_id) {
        Ok(h) => h,
        Err(err) => {
            return problem_response(StatusCode::BAD_REQUEST, err.to_string());
        }
    };

    let routing = state.routing.read().await.clone();
    let Some(decision) = routing.route_stream_hash(stream_hash) else {
        return problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "no shard range matched streamHash (invalid routing table)",
        );
    };

    let default_gpu_id = state.dataplane_pool.as_ref().map_or(0, |p| p.default_gpu_id());
    let owner_gpu_id = decision.gpu_id.unwrap_or(default_gpu_id);

    let mut worker_up = false;
    let mut shard_hosted = false;
    if let Some(pool) = state.dataplane_pool.as_ref() {
        if let Some(store) = pool.store_for_gpu_id(owner_gpu_id) {
            worker_up = true;
            let guard = store.read().await;
            shard_hosted = guard.hosted_shards().iter().any(|s| s == &decision.shard_id);
        }
    }

    (
        StatusCode::OK,
        Json(RouteV1Response {
            stream_hash: format_u64_hex(decision.stream_hash),
            shard_id: decision.shard_id,
            epoch: decision.epoch,
            shard_map_version: decision.shard_map_version,
            leader_grpc_addr: decision.leader_grpc_addr,
            leader_node_id: decision.leader_node_id,
            shard_gpu_id: decision.gpu_id,
            owner_gpu_id,
            worker_up,
            shard_hosted,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers))]
pub(super) async fn get_shards(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    #[derive(serde::Serialize)]
    struct ShardInfo {
        #[serde(rename = "shardId")]
        shard_id: String,
        epoch: u64,
        state: corecrux_types::ShardState,
        ranges: Vec<corecrux_types::HashRange>,
        leader: corecrux_types::NodeAddr,
        #[serde(rename = "gpuId")]
        gpu_id: Option<i32>,
        #[serde(rename = "ownerGpuId")]
        owner_gpu_id: i32,
        #[serde(rename = "workerUp")]
        worker_up: bool,
        #[serde(rename = "shardHosted")]
        shard_hosted: bool,
        #[serde(rename = "dataDir")]
        data_dir: Option<String>,
    }

    #[derive(serde::Serialize)]
    struct Resp {
        #[serde(rename = "nodeId")]
        node_id: String,
        #[serde(rename = "shardMapVersion")]
        shard_map_version: u64,
        #[serde(rename = "defaultGpuId")]
        default_gpu_id: i32,
        shards: Vec<ShardInfo>,
    }

    let routing = state.routing.read().await.clone();
    let default_gpu_id = state.dataplane_pool.as_ref().map_or(0, |p| p.default_gpu_id());

    let mut hosted: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut workers_up: std::collections::BTreeSet<i32> = std::collections::BTreeSet::new();
    if let Some(pool) = state.dataplane_pool.as_ref() {
        for gpu_id in pool.gpu_ids() {
            workers_up.insert(gpu_id);
            if let Some(store) = pool.store_for_gpu_id(gpu_id) {
                let guard = store.read().await;
                for s in guard.hosted_shards() {
                    hosted.insert(s);
                }
            }
        }
    }

    let shards: Vec<ShardInfo> = routing
        .shard_map
        .shards
        .iter()
        .map(|s| {
            let owner_gpu_id = s.gpu_id.unwrap_or(default_gpu_id);
            ShardInfo {
                shard_id: s.shard_id.clone(),
                epoch: s.epoch,
                state: s.state,
                ranges: s.ranges.clone(),
                leader: s.leader.clone(),
                gpu_id: s.gpu_id,
                owner_gpu_id,
                worker_up: workers_up.contains(&owner_gpu_id),
                shard_hosted: hosted.contains(&s.shard_id),
                data_dir: s.data_dir.clone(),
            }
        })
        .collect();

    (
        StatusCode::OK,
        Json(Resp {
            node_id: state.node_id.clone(),
            shard_map_version: routing.current_version(),
            default_gpu_id,
            shards,
        }),
    )
        .into_response()
}

pub(super) async fn get_gpus(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    problem_response(StatusCode::NOT_IMPLEMENTED, "requires the proprietary edition")
}

#[derive(serde::Serialize)]
pub(super) struct RoutingStatusResponse {
    #[serde(rename = "routingTableVersion")]
    pub(super) routing_table_version: u64,
    #[serde(rename = "lastReloadAt")]
    pub(super) last_reload_at: String,
    #[serde(rename = "reloadErrors")]
    pub(super) reload_errors: Vec<String>,
    #[serde(rename = "shardsLoaded")]
    pub(super) shards_loaded: Vec<String>,
}

#[tracing::instrument(level = "info", skip(state, headers))]
pub(super) async fn routing_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let routing = state.routing.read().await.clone();
    let reload_errors = state.routing_errors.read().await.clone();

    let shards_loaded = if let Some(pool) = state.dataplane_pool.as_ref() {
        let mut out = Vec::new();
        for gpu_id in pool.gpu_ids() {
            let Some(store) = pool.store_for_gpu_id(gpu_id) else {
                continue;
            };
            let store = store.read().await;
            out.extend(store.hosted_shards());
        }
        out.sort();
        out.dedup();
        out
    } else {
        routing.shard_map.shards.iter().map(|s| s.shard_id.clone()).collect()
    };

    (
        StatusCode::OK,
        Json(RoutingStatusResponse {
            routing_table_version: routing.current_version(),
            last_reload_at: routing.loaded_at,
            reload_errors,
            shards_loaded,
        }),
    )
        .into_response()
}
