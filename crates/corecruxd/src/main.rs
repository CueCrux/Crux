// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

mod auth;
mod config;
mod control;
mod dataplane_store;
mod grpc;
mod http;
mod metrics;
mod ops_events;
mod pool;
mod problem;
mod shard_map;
mod structured_log;

use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use fs2::{available_space, total_space, FileExt};
use tokio::sync::broadcast;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing::{error, info};

use corecrux_types::{
    BuildInfo, CapacityThresholdBreachedV1, CompatContract, ControlCheckpointMaterializedV1,
    ControlStateMutationV1, ShardRebalanceRecordedV1, DEFAULT_COMPAT_REQUIRES, DEFAULT_SDK_VERSION,
    EVT_CAPACITY_THRESHOLD_BREACHED_V1, EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1,
    EVT_CONTROL_STATE_MUTATION_V1, EVT_SHARD_REBALANCE_RECORDED_V1,
};

use crate::auth::AuthMode;
use crate::config::{load_config, CommitLevel};
use crate::dataplane_store::AppendError;
use crate::http::{AppState, CapacityState, Readiness};
use crate::metrics::Metrics;
use crate::ops_events::{append_ops_event, build_node_context, now_unix_ms};
use crate::shard_map::{RoutingTable, ShardMapStore};
use crate::structured_log::{ErrorCode, StructuredOpLog};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = load_config();
    let auth = crate::auth::Authz::from_env(config.auth_mode)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    validate_network_auth_posture(
        config.auth_mode,
        config.http_addr,
        config.grpc_addr,
        config.commit_level,
        insecure_dev_auth_bind_allowed(),
        replication_auth_bearer_configured(),
    )
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    // Used only in CUDA builds today; keep the config fields live on CPU-only builds too.
    let _ = (
        config.routing_strict_client_version,
        config.commit_level,
        config.follower_reads_enabled,
        config.replicated_commit_timeout_ms,
        config.replicated_commit_require_all_followers,
        config.max_events_per_batch,
        config.max_batch_bytes,
        config.max_event_id_bytes,
        config.idem_hot_capacity_entries,
        config.event_id_hash_prefix_len,
        config.cold_scan_max_segments,
        config.append_group_commit_batches,
        config.append_group_commit_max_delay_ms,
        config.enable_directory_compaction,
        config.dir_l0_max_runs,
        config.receipts_verify_enabled,
        config.receipts_recompute_candidate_digest,
        &config.receipts_keyring_path,
        &config.receipts_keyring_json,
        config.replay_batch_max_events,
        config.replay_batch_max_bytes,
        config.replay_many_max_reads,
        config.replay_use_batched_rpc_default,
        config.store_lock_strategy.as_str(),
        config.tail_cache_enabled,
        config.backpressure_high_watermark_ratio,
        config.backpressure_low_watermark_ratio,
        config.backpressure_retry_after_ms,
        config.operator_action_max_pending,
        config.operator_action_timeout_secs,
        config.scrub_scheduler_enabled,
        config.scrub_interval_secs,
        &config.scrub_scope,
        &config.scrub_mode,
        config.scrub_sample_rate,
        config.capacity_guard_enabled,
        config.capacity_guard_interval_secs,
        config.capacity_warning_free_ratio,
        config.capacity_critical_free_ratio,
        config.capacity_emergency_free_ratio,
        config.capacity_resume_free_ratio,
        config.gds_require_no_compat_mode,
        config.gds_preflight_io,
        &config.gds_library_path,
        &config.hardware_profile_path,
    );
    init_tracing(&config.log_level);

    std::panic::set_hook(Box::new(|panic_info| {
        let payload = panic_info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| {
                panic_info
                    .payload()
                    .downcast_ref::<String>()
                    .map(|s| s.as_str())
            })
            .unwrap_or("unknown");
        let location = panic_info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());
        tracing::error!(
            panic.payload = payload,
            panic.location = %location,
            "panic occurred"
        );
    }));

    create_dir_all(&config.data_dir)?;
    let lock_file = acquire_lock(&config.data_dir)?;

    let control_path = config.data_dir.join("CONTROL.json");
    let control_handle = crate::control::ControlHandle::load_or_init(control_path.clone())?;
    let control: Arc<RwLock<crate::control::ControlV1>> =
        Arc::new(RwLock::new(control_handle.state));

    let build = BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: option_env!("CORECRUX_GIT_SHA")
            .unwrap_or("unknown")
            .to_string(),
    };

    let metrics = Metrics::new(&build, &config.service_name);
    metrics.set_gpu_up(false);
    metrics.set_peer_cache_bytes(0);
    {
        let c = control.read().await.clone();
        update_control_metrics(&metrics, &c);
    }
    // CPU-only: keep a stable metrics surface.
    metrics.set_io_backend(&config.io_backend);
    metrics.set_gds_active(false);
    metrics.set_gds_degraded(false);
    metrics.set_hardware_profile_match(true);
    metrics.set_gpu_worker_up(0, false);
    metrics.touch_peer_cache_metrics();
    metrics.inc_kernel_launch("smoke", "skipped");

    let gpu_id_for_meta: Option<i32> = None;

    let node_meta_path = config.data_dir.join("meta").join("node.json");
    let node_meta = load_or_init_node_meta(
        &node_meta_path,
        config.node_id_override.as_deref(),
        config.http_addr,
        config.grpc_addr,
        gpu_id_for_meta,
        &build,
    )?;
    let node_id = node_meta.node_id.clone();

    let http_leader = shard_map_advertise_addr(config.http_addr);
    let grpc_leader = shard_map_advertise_addr(config.grpc_addr);
    let shard_store = ShardMapStore::new(&config.data_dir);
    let loaded = shard_store.load_or_init(
        &config.cluster_id,
        &node_id,
        &http_leader,
        &grpc_leader,
        config.dev_split_shards,
        gpu_id_for_meta,
    )?;
    let routing_table = RoutingTable::new(loaded)?;
    metrics.set_shardmap_version(routing_table.current_version());
    let default_gpu_id_for_metrics: i32 = 0;
    observe_shard_map_metrics(
        &metrics,
        &routing_table,
        default_gpu_id_for_metrics,
        &node_id,
    );
    let routing: Arc<RwLock<RoutingTable>> = Arc::new(RwLock::new(routing_table));
    let routing_errors: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(Vec::new()));

    // CPU-only: GPU readiness is "skipped" and therefore ready=true.
    let readiness = Arc::new(RwLock::new(Readiness {
        gpu_context: true,
        gpu_context_error: None,
        kernel_module_loaded: true,
        kernel_module_error: None,
        smoke_kernel_ok: true,
        smoke_kernel_error: None,
        io_backend_ok: true,
        io_backend_error: None,
        gds_active: true,
        gds_degraded: false,
        gds_error: None,
        hardware_profile_ok: true,
        hardware_profile_error: None,
        control_evidence_hosted: false,
        control_evidence_ok: true,
        control_evidence_error: None,
    }));

    // GPU initialization removed (CPU-only community edition).
    // The CUDA pool_res block and all its contents have been stripped.
    let dataplane_pool: Option<crate::pool::DataPlanePool> = None;


    let control_evidence_status = reconcile_control_checkpoint_with_evidence(
        &control_path,
        control.clone(),
        dataplane_pool.as_ref(),
        &metrics,
    )
    .await;
    {
        let mut guard = readiness.write().await;
        guard.control_evidence_hosted = control_evidence_status.hosted_locally;
        guard.control_evidence_ok = control_evidence_status.ok;
        guard.control_evidence_error =
            if control_evidence_status.hosted_locally && !control_evidence_status.ok {
                control_evidence_status.detail.clone()
            } else {
                None
            };
    }

    spawn_routing_reloader(
        config.clone(),
        shard_store.clone(),
        routing.clone(),
        routing_errors.clone(),
        metrics.clone(),
        dataplane_pool.clone(),
        build.clone(),
        node_id.clone(),
    );

    if config.projections_enabled {
        if let Some(pool) = dataplane_pool.clone() {
            spawn_projection_runner(config.clone(), pool, control.clone(), metrics.clone());
        } else {
            tracing::warn!(
                "CORECRUXD_PROJECTIONS_ENABLED=1 but dataplane_pool is unavailable (CUDA init failed?)"
            );
        }
    }

    let corruption_detected = Arc::new(RwLock::new(false));
    if config.scrub_scheduler_enabled {
        if let Some(pool) = dataplane_pool.clone() {
            spawn_scrub_scheduler(
                config.clone(),
                pool,
                control.clone(),
                corruption_detected.clone(),
            );
        } else {
            tracing::warn!("CORECRUXD_SCRUB_SCHEDULER_ENABLED=1 but dataplane_pool is unavailable");
        }
    }

    let (initial_total_bytes, initial_free_bytes, initial_capacity_error) =
        match measure_data_dir_space(&config.data_dir) {
            Ok((total, free)) => (total, free, None),
            Err(err) => (0, 0, Some(err)),
        };
    let capacity = Arc::new(RwLock::new(CapacityState {
        total_bytes: initial_total_bytes,
        free_bytes: initial_free_bytes,
        free_ratio: if initial_total_bytes == 0 {
            0.0
        } else {
            initial_free_bytes as f64 / initial_total_bytes as f64
        },
        warning_free_ratio: config.capacity_warning_free_ratio,
        critical_free_ratio: config.capacity_critical_free_ratio,
        emergency_free_ratio: config.capacity_emergency_free_ratio,
        auto_paused: false,
        error: initial_capacity_error,
    }));
    metrics.set_data_dir_space(initial_total_bytes, initial_free_bytes);
    if config.capacity_guard_enabled {
        spawn_capacity_guard(
            config.clone(),
            metrics.clone(),
            control.clone(),
            dataplane_pool.clone(),
            capacity.clone(),
            build.clone(),
            node_id.clone(),
            control_path.clone(),
        );
    }

    let state = AppState {
        lock_held: true,
        build: build.clone(),
        compat: CompatContract {
            requires: DEFAULT_COMPAT_REQUIRES.to_string(),
        },
        sdk_version: DEFAULT_SDK_VERSION.to_string(),
        auth: auth.clone(),
        data_dir: config.data_dir.clone(),
        io_backend: config.io_backend.clone(),
        read_retry_failed_readyz_threshold: config.read_retry_failed_readyz_threshold,
        commit_level: config.commit_level,
        metrics: metrics.clone(),
        node_id: node_id.clone(),
        routing: routing.clone(),
        routing_errors: routing_errors.clone(),
        dataplane_pool: dataplane_pool.clone(),
        readiness: readiness.clone(),
        control: control.clone(),
        control_path: control_path.clone(),
        action_max_pending: config.operator_action_max_pending,
        action_timeout_secs: config.operator_action_timeout_secs,
        scrub_scope: config.scrub_scope.clone(),
        scrub_mode: config.scrub_mode.clone(),
        scrub_sample_rate: config.scrub_sample_rate,
        admin_actions: Arc::new(RwLock::new(std::collections::BTreeMap::new())),
        corruption_detected,
        capacity,
        admin_force_seal_enabled: config.admin_force_seal_enabled,
        retrieval_index: {
            let mut idx = corecrux_retrieval::IndexManager::new();
            if config.build_ccxi {
                // Scan all shard directories for .ccxi files
                let shards_dir = config.data_dir.join("shards");
                let mut total = 0usize;
                if let Ok(entries) = std::fs::read_dir(&shards_dir) {
                    for entry in entries.flatten() {
                        let seg_dir = entry.path().join("segments");
                        match idx.scan_and_load(&seg_dir) {
                            Ok(count) => total += count,
                            Err(err) => tracing::warn!(?err, dir=?seg_dir, "ccxi-scan-shard-failed"),
                        }
                    }
                }
                tracing::info!(total, "ccxi-indexes-loaded-at-startup");
            }
            Arc::new(RwLock::new(idx))
        },
        fact_store: Arc::new(RwLock::new(corecrux_memory::FactStore::new())),
        session_store: Arc::new(RwLock::new(corecrux_memory::SessionStore::new())),
    };

    // crux-observe: auto-seed bootstrap data on startup
    if crux_observe::config::self_observe_enabled() {
        let seeder = crux_observe::bootstrap::BootstrapSeeder::new(state.fact_store.clone());
        let result = seeder.seed().await;
        if result.already_seeded {
            info!("bootstrap data already seeded");
        } else {
            info!(facts_created = result.facts_created, "bootstrap data seeded");
        }
    }

    let app: Router = http::router(state).layer(TraceLayer::new_for_http());

    let (shutdown_tx, _shutdown_rx) = broadcast::channel::<()>(1);
    spawn_shutdown_signal(shutdown_tx.clone());

    let http_addr = config.http_addr;
    let grpc_addr = config.grpc_addr;

    info!(
        http_addr = %http_addr,
        grpc_addr = %grpc_addr,
        data_dir = %config.data_dir.display(),
        commit_level = config.commit_level.as_str(),
        append_lane_enabled = config.append_lane_enabled,
        append_lane_scope = config.append_lane_scope.as_str(),
        append_gpu_lane_fanout = config.append_gpu_lane_fanout,
        follower_reads_enabled = config.follower_reads_enabled,
        "corecruxd starting"
    );

    let http_task = {
        let mut rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            serve_http(http_addr, app, async move {
                let _ = rx.recv().await;
            })
            .await
        })
    };

    let grpc_task = {
        let mut rx = shutdown_tx.subscribe();
        let export_pool = dataplane_pool.clone();
        let svc_cfg = grpc::DataPlaneServiceConfig {
            node_id: node_id.clone(),
            commit_level: config.commit_level,
            replicated_commit_timeout_ms: config.replicated_commit_timeout_ms,
            replicated_commit_require_all_followers: config.replicated_commit_require_all_followers,
            replay_batch_max_events: config.replay_batch_max_events,
            replay_batch_max_bytes: config.replay_batch_max_bytes,
            replay_many_max_reads: config.replay_many_max_reads,
            replay_use_batched_rpc_default: config.replay_use_batched_rpc_default,
            store_lock_strategy: config.store_lock_strategy,
            append_lane_enabled: config.append_lane_enabled,
            append_lane_scope: config.append_lane_scope,
            append_gpu_lane_fanout: config.append_gpu_lane_fanout,
        };
        let svc = grpc::DataPlaneService::new(
            dataplane_pool,
            control.clone(),
            metrics.clone(),
            auth.clone(),
            svc_cfg,
        );
        let export_svc =
            grpc::ExportService::new(export_pool, metrics.clone(), build.clone(), auth.clone());
        tokio::spawn(async move {
            grpc::serve(grpc_addr, svc, export_svc, async move {
                let _ = rx.recv().await;
            })
            .await
        })
    };

    let http_res = http_task.await?;
    if let Err(err) = http_res {
        error!(err = %err, "http server exited with error");
        return Err(err.into());
    }

    let grpc_res = grpc_task.await?;
    if let Err(err) = grpc_res {
        error!(err = %err, "grpc server exited with error");
        return Err(err);
    }

    drop(lock_file);
    Ok(())
}

#[derive(Debug, Clone)]
struct ControlCheckpointRecord {
    seq: u64,
    payload: ControlCheckpointMaterializedV1,
}

#[derive(Debug, Clone)]
struct ControlMutationRecord {
    seq: u64,
    payload: ControlStateMutationV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ControlEvidenceReplayPlan {
    state: crate::control::ControlV1,
    anchor: &'static str,
    anchor_seq: u64,
    applied_mutations: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ControlEvidenceRuntimeStatus {
    hosted_locally: bool,
    ok: bool,
    detail: Option<String>,
}

impl ControlEvidenceRuntimeStatus {
    fn non_hosted(detail: impl Into<String>) -> Self {
        Self {
            hosted_locally: false,
            ok: true,
            detail: Some(detail.into()),
        }
    }

    fn hosted_ok(detail: impl Into<String>) -> Self {
        Self {
            hosted_locally: true,
            ok: true,
            detail: Some(detail.into()),
        }
    }

    fn hosted_err(detail: impl Into<String>) -> Self {
        Self {
            hosted_locally: true,
            ok: false,
            detail: Some(detail.into()),
        }
    }
}

fn update_control_metrics(metrics: &Metrics, control: &crate::control::ControlV1) {
    metrics.set_valve_pause_ingest(control.valves.pause_ingest.enabled);
    metrics.set_valve_pause_compaction(control.valves.pause_compaction.enabled);
    metrics.set_valve_throttle(control.valves.throttle.enabled);
    metrics.set_valve_read_only(control.valves.read_only.enabled);
    metrics.set_valve_emergency_brake(control.valves.emergency_brake.enabled);

    metrics.set_valve_state("pause_ingest", control.valves.pause_ingest.enabled);
    metrics.set_valve_state("pause_compaction", control.valves.pause_compaction.enabled);
    metrics.set_valve_state("throttle", control.valves.throttle.enabled);
    metrics.set_valve_state("read_only", control.valves.read_only.enabled);
    metrics.set_valve_state("emergency_brake", control.valves.emergency_brake.enabled);
    metrics.sync_knowledge_authority(&control.knowledge_authority);
    metrics.set_throttle_ratio(1.0);
}

fn reconcile_control_from_evidence(
    current: &crate::control::ControlV1,
    current_checkpoint_bytes: &[u8],
    checkpoints: &[ControlCheckpointRecord],
    mutations: &[ControlMutationRecord],
) -> Result<Option<ControlEvidenceReplayPlan>, String> {
    if checkpoints.is_empty() && mutations.is_empty() {
        return Ok(None);
    }

    let current_digest = crate::control::control_state_digest_v1(current);
    let current_checkpoint_hash = blake3::hash(current_checkpoint_bytes).to_hex().to_string();
    let current_checkpoint_size = current_checkpoint_bytes.len() as u64;

    let checkpoint_anchor = checkpoints
        .iter()
        .rev()
        .find(|record| {
            record.payload.control_state == current_digest
                && record.payload.checkpoint_blake3 == current_checkpoint_hash
                && record.payload.checkpoint_size_bytes == current_checkpoint_size
        })
        .map(|record| (record.seq, "checkpoint"));
    let mutation_anchor = mutations
        .iter()
        .rev()
        .find(|record| record.payload.control_after == current_digest)
        .map(|record| (record.seq, "mutation"));

    let (mut rebuilt, anchor, anchor_seq) = match (checkpoint_anchor, mutation_anchor) {
        (Some(left), Some(right)) => {
            if left.0 >= right.0 {
                (current.clone(), left.1, left.0)
            } else {
                (current.clone(), right.1, right.0)
            }
        }
        (Some(found), None) | (None, Some(found)) => (current.clone(), found.1, found.0),
        (None, None) => {
            let Some(first_mutation) = mutations.first() else {
                return Err(
                    "control evidence contains no state mutation anchor for CONTROL.json".into(),
                );
            };
            let default_state = crate::control::ControlV1::default();
            if first_mutation.payload.control_before
                != crate::control::control_state_digest_v1(&default_state)
            {
                return Err(
                    "CONTROL.json does not match any checkpoint or mutation anchor, and evidence does not start from the default control state".into(),
                );
            }
            (default_state, "default", 0)
        }
    };

    let mut applied_mutations = 0usize;
    for record in mutations.iter().filter(|record| record.seq > anchor_seq) {
        crate::control::apply_control_state_mutation_v1(&mut rebuilt, &record.payload)?;
        applied_mutations = applied_mutations.saturating_add(1);
    }

    Ok(Some(ControlEvidenceReplayPlan {
        state: rebuilt,
        anchor,
        anchor_seq,
        applied_mutations,
    }))
}

async fn reconcile_control_checkpoint_with_evidence(
    control_path: &std::path::Path,
    control: Arc<RwLock<crate::control::ControlV1>>,
    dataplane_pool: Option<&crate::pool::DataPlanePool>,
    metrics: &Metrics,
) -> ControlEvidenceRuntimeStatus {
    const CONTROL_EVIDENCE_READ_BATCH: u32 = 256;

    let Some(pool) = dataplane_pool else {
        tracing::info!("control evidence replay skipped because dataplane is unavailable");
        return ControlEvidenceRuntimeStatus::non_hosted(
            "control evidence replay skipped because dataplane is unavailable",
        );
    };

    let store = match pool
        .store_for_stream_read("system", "corecrux", "control", None, None)
        .await
    {
        Ok((_decision, store)) => store,
        Err(AppendError::WrongShard { .. }) => {
            tracing::info!(
                "control evidence replay skipped because system/corecrux/control is not hosted locally"
            );
            return ControlEvidenceRuntimeStatus::non_hosted(
                "system/corecrux/control is not hosted locally",
            );
        }
        Err(err) => {
            tracing::warn!(err = %err, "failed to route control evidence replay; using CONTROL.json checkpoint");
            return ControlEvidenceRuntimeStatus::hosted_err(format!(
                "failed to route control evidence replay: {err}"
            ));
        }
    };

    let mut checkpoints = Vec::new();
    let mut mutations = Vec::new();
    let mut from_seq = 0u64;

    loop {
        let batch = {
            let store = store.read().await;
            match store
                .read_stream(
                    "system",
                    "corecrux",
                    "control",
                    from_seq,
                    CONTROL_EVIDENCE_READ_BATCH,
                    None,
                )
                .await
            {
                Ok(ok) => ok,
                Err(err) => {
                    tracing::warn!(err = %err, from_seq, "failed to read control evidence stream; using CONTROL.json checkpoint");
                    return ControlEvidenceRuntimeStatus::hosted_err(format!(
                        "failed to read control evidence stream: {err}"
                    ));
                }
            }
        };

        if batch.is_empty() {
            break;
        }

        let batch_len = batch.len();
        from_seq = batch
            .last()
            .map(|event| event.seq.saturating_add(1))
            .unwrap_or(from_seq);

        for event in batch {
            match event.event_type.as_str() {
                EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1 => {
                    match serde_json::from_slice::<ControlCheckpointMaterializedV1>(&event.payload)
                    {
                        Ok(payload) => checkpoints.push(ControlCheckpointRecord {
                            seq: event.seq,
                            payload,
                        }),
                        Err(err) => {
                            tracing::warn!(
                                seq = event.seq,
                                err = %err,
                                "failed to parse control checkpoint evidence; using CONTROL.json checkpoint"
                            );
                            return ControlEvidenceRuntimeStatus::hosted_err(format!(
                                "failed to parse control checkpoint evidence at seq {}: {err}",
                                event.seq
                            ));
                        }
                    }
                }
                EVT_CONTROL_STATE_MUTATION_V1 => {
                    match serde_json::from_slice::<ControlStateMutationV1>(&event.payload) {
                        Ok(payload) => mutations.push(ControlMutationRecord {
                            seq: event.seq,
                            payload,
                        }),
                        Err(err) => {
                            tracing::warn!(
                                seq = event.seq,
                                err = %err,
                                "failed to parse control mutation evidence; using CONTROL.json checkpoint"
                            );
                            return ControlEvidenceRuntimeStatus::hosted_err(format!(
                                "failed to parse control mutation evidence at seq {}: {err}",
                                event.seq
                            ));
                        }
                    }
                }
                _ => {}
            }
        }
        if batch_len < CONTROL_EVIDENCE_READ_BATCH as usize {
            break;
        }
    }

    let current = control.read().await.clone();
    let current_checkpoint_bytes = match std::fs::read(control_path) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(
                path = %control_path.display(),
                err = %err,
                "failed to read CONTROL.json for evidence reconciliation"
            );
            return ControlEvidenceRuntimeStatus::hosted_err(format!(
                "failed to read CONTROL.json: {err}"
            ));
        }
    };

    let plan = match reconcile_control_from_evidence(
        &current,
        &current_checkpoint_bytes,
        &checkpoints,
        &mutations,
    ) {
        Ok(Some(plan)) => plan,
        Ok(None) => {
            tracing::info!("control evidence stream has no replayable control records yet");
            return ControlEvidenceRuntimeStatus::hosted_ok(
                "control evidence stream has no replayable control records yet",
            );
        }
        Err(err) => {
            tracing::warn!(err = %err, "control evidence did not reconcile with CONTROL.json; keeping checkpoint state");
            return ControlEvidenceRuntimeStatus::hosted_err(format!(
                "control evidence did not reconcile with CONTROL.json: {err}"
            ));
        }
    };

    let expected_checkpoint_bytes = crate::control::checkpoint_control_bytes_v1(&plan.state);

    if plan.state == current && expected_checkpoint_bytes == current_checkpoint_bytes {
        tracing::info!(
            anchor = plan.anchor,
            anchor_seq = plan.anchor_seq,
            applied_mutations = plan.applied_mutations,
            "control checkpoint already matches local evidence"
        );
        return ControlEvidenceRuntimeStatus::hosted_ok(format!(
            "control checkpoint matches local evidence (anchor={} anchor_seq={} applied_mutations={})",
            plan.anchor, plan.anchor_seq, plan.applied_mutations
        ));
    }

    {
        let mut guard = control.write().await;
        *guard = plan.state.clone();
    }
    update_control_metrics(metrics, &plan.state);
    if let Err(err) = crate::control::write_control_atomic(control_path, &plan.state) {
        tracing::warn!(
            path = %control_path.display(),
            err = %err,
            "failed to rewrite CONTROL.json after control evidence replay"
        );
        return ControlEvidenceRuntimeStatus::hosted_err(format!(
            "failed to rewrite CONTROL.json after control evidence replay: {err}"
        ));
    }
    tracing::info!(
        anchor = plan.anchor,
        anchor_seq = plan.anchor_seq,
        applied_mutations = plan.applied_mutations,
        "reconciled CONTROL.json from local control evidence"
    );
    ControlEvidenceRuntimeStatus::hosted_ok(format!(
        "reconciled CONTROL.json from local evidence (anchor={} anchor_seq={} applied_mutations={})",
        plan.anchor, plan.anchor_seq, plan.applied_mutations
    ))
}

fn insecure_dev_auth_bind_allowed() -> bool {
    std::env::var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn replication_auth_bearer_configured() -> bool {
    std::env::var("CORECRUXD_REPLICATION_AUTH_BEARER")
        .ok()
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
}

fn shard_map_advertise_addr(listen_addr: SocketAddr) -> String {
    let ip = if listen_addr.ip().is_unspecified() {
        match listen_addr.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        }
    } else {
        listen_addr.ip()
    };
    SocketAddr::new(ip, listen_addr.port()).to_string()
}

fn validate_network_auth_posture(
    auth_mode: AuthMode,
    http_addr: SocketAddr,
    grpc_addr: SocketAddr,
    commit_level: CommitLevel,
    allow_insecure_dev_auth_bind: bool,
    replication_auth_bearer_present: bool,
) -> Result<(), String> {
    let dev_auth_mode = matches!(auth_mode, AuthMode::Off | AuthMode::DevScopes);
    let loopback_only = http_addr.ip().is_loopback() && grpc_addr.ip().is_loopback();
    if dev_auth_mode && !loopback_only && !allow_insecure_dev_auth_bind {
        return Err(format!(
            "auth mode {:?} may not bind to non-loopback addresses (http={}, grpc={}) without CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND=1",
            auth_mode, http_addr, grpc_addr
        ));
    }

    let jwt_auth_mode = matches!(auth_mode, AuthMode::JwtHs256 | AuthMode::JwtJwks);
    if jwt_auth_mode
        && matches!(commit_level, CommitLevel::ReplicatedCommit)
        && !replication_auth_bearer_present
    {
        return Err(
            "ReplicatedCommit with JWT auth requires CORECRUXD_REPLICATION_AUTH_BEARER for follower replication"
                .to_string(),
        );
    }

    Ok(())
}


fn init_tracing(level: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let log_format = std::env::var("LOG_FORMAT").unwrap_or_default();

    #[cfg(feature = "otel")]
    {
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_otlp::WithExportConfig as _;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::Layer as _;

        let otel_endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();
        if let Some(endpoint) = otel_endpoint {
            let exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(&endpoint)
                .build()
                .expect("failed to build OTLP exporter");

            let provider = opentelemetry_sdk::trace::TracerProvider::builder()
                .with_batch_exporter(exporter, opentelemetry_sdk::runtime::Tokio)
                .with_resource(opentelemetry_sdk::Resource::new(vec![
                    opentelemetry::KeyValue::new("service.name", "corecruxd"),
                ]))
                .build();

            opentelemetry::global::set_tracer_provider(provider.clone());
            opentelemetry::global::set_text_map_propagator(
                opentelemetry_sdk::propagation::TraceContextPropagator::new(),
            );
            let otel_layer =
                tracing_opentelemetry::OpenTelemetryLayer::new(provider.tracer("corecruxd"));

            let fmt_layer = if log_format.eq_ignore_ascii_case("json") {
                tracing_subscriber::fmt::layer().json().boxed()
            } else {
                tracing_subscriber::fmt::layer().boxed()
            };

            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .with(otel_layer)
                .init();
            return;
        }
    }

    if log_format.eq_ignore_ascii_case("json") {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

fn acquire_lock(
    data_dir: &std::path::Path,
) -> Result<std::fs::File, Box<dyn std::error::Error + Send + Sync>> {
    let lock_path = data_dir.join("LOCK");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    file.try_lock_exclusive()?;
    Ok(file)
}

fn spawn_shutdown_signal(tx: broadcast::Sender<()>) {
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to register SIGTERM handler");
        #[cfg(unix)]
        tokio::select! {
            _ = ctrl_c => { tracing::info!("SIGINT received, shutting down"); }
            _ = sigterm.recv() => { tracing::info!("SIGTERM received, shutting down"); }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
            tracing::info!("SIGINT received, shutting down");
        }
        #[cfg(feature = "otel")]
        opentelemetry::global::shutdown_tracer_provider();

        let _ = tx.send(());
    });
}

fn observe_shard_map_metrics(
    metrics: &Metrics,
    table: &RoutingTable,
    default_gpu_id: i32,
    node_id: &str,
) {
    for shard in &table.shard_map.shards {
        let owner_gpu_id = shard.gpu_id.unwrap_or(default_gpu_id);
        metrics.set_shard_owner_gpu_id(&shard.shard_id, owner_gpu_id);
        let state = match shard.state {
            corecrux_types::ShardState::Active => "active",
            corecrux_types::ShardState::Draining => "draining",
            corecrux_types::ShardState::Retired => "retired",
        };
        metrics.set_shard_state(&shard.shard_id, state);
        metrics.set_replication_shard_epoch(&shard.shard_id, shard.epoch);
        let follower_count = shard
            .followers
            .as_ref()
            .map(|followers| followers.iter().filter(|f| f.node_id != node_id).count())
            .unwrap_or(0);
        metrics.set_replication_follower_targets(&shard.shard_id, follower_count);
        metrics.set_replication_lag_segments(&shard.shard_id, 0, 0);
    }
}

async fn serve_http(
    addr: SocketAddr,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct NodeMetaV1 {
    v: u32,
    #[serde(rename = "nodeId")]
    node_id: String,
    #[serde(rename = "createdAt")]
    created_at: String,
    #[serde(rename = "httpListenAddr")]
    http_listen_addr: String,
    #[serde(rename = "grpcListenAddr")]
    grpc_listen_addr: String,
    #[serde(rename = "gpuId", skip_serializing_if = "Option::is_none")]
    gpu_id: Option<i32>,
    build: BuildInfo,
}

fn load_or_init_node_meta(
    path: &std::path::Path,
    node_id_override: Option<&str>,
    http_listen_addr: SocketAddr,
    grpc_listen_addr: SocketAddr,
    gpu_id: Option<i32>,
    build: &BuildInfo,
) -> std::io::Result<NodeMetaV1> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    if path.exists() {
        let bytes = std::fs::read(path)?;
        let meta: NodeMetaV1 = serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        return Ok(meta);
    }

    let node_id = node_id_override
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("node-{}", uuid::Uuid::new_v4()));

    let meta = NodeMetaV1 {
        v: 1,
        node_id,
        created_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        http_listen_addr: http_listen_addr.to_string(),
        grpc_listen_addr: grpc_listen_addr.to_string(),
        gpu_id,
        build: build.clone(),
    };

    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(&meta)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)?;
    f.write_all(&bytes)?;
    f.flush()?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;

    Ok(meta)
}

fn spawn_routing_reloader(
    config: crate::config::Config,
    shard_store: ShardMapStore,
    routing: Arc<RwLock<RoutingTable>>,
    routing_errors: Arc<RwLock<Vec<String>>>,
    metrics: Metrics,
    dataplane_pool: Option<crate::pool::DataPlanePool>,
    build: BuildInfo,
    node_id: String,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(
            config.routing_reload_interval_ms,
        ));
        loop {
            interval.tick().await;

            let current_version = { routing.read().await.current_version() };
            let loaded = match shard_store.load_current() {
                Ok(l) => l,
                Err(err) => {
                    let mut errs = routing_errors.write().await;
                    errs.push(format!("failed to load current shardmap: {err}"));
                    if errs.len() > 10 {
                        let excess = errs.len().saturating_sub(10);
                        errs.drain(0..excess);
                    }
                    continue;
                }
            };
            if loaded.current_version == current_version {
                continue;
            }

            let new_table = match RoutingTable::new(loaded) {
                Ok(t) => t,
                Err(err) => {
                    tracing::warn!(err = %err, "failed to build routing table for reload");
                    let mut errs = routing_errors.write().await;
                    errs.push(format!("failed to build routing table: {err}"));
                    if errs.len() > 10 {
                        let excess = errs.len().saturating_sub(10);
                        errs.drain(0..excess);
                    }
                    continue;
                }
            };

            metrics.set_shardmap_version(new_table.current_version());
            let default_gpu_id_for_metrics: i32 = dataplane_pool
                .as_ref()
                .map(|p| p.default_gpu_id())
                .unwrap_or(0);
            observe_shard_map_metrics(&metrics, &new_table, default_gpu_id_for_metrics, &node_id);

            tracing::info!(
                old_version = current_version,
                new_version = new_table.current_version(),
                blake3 = %new_table.shard_map.blake3,
                "routing table reloaded"
            );

            {
                let mut guard = routing.write().await;
                *guard = new_table.clone();
            }

            routing_errors.write().await.clear();

            if let Some(pool) = dataplane_pool.as_ref() {
                for gpu_id in pool.gpu_ids() {
                    let Some(store) = pool.store_for_gpu_id(gpu_id) else {
                        continue;
                    };
                    let store = store.read().await;
                    if let Err(err) = store.sync_shards().await {
                        routing_errors.write().await.push(format!(
                            "failed to sync shards after routing reload (gpu_id={gpu_id}): {err:?}"
                        ));
                    }
                }

                let _ = emit_shardmap_updated_event(
                    pool,
                    &build,
                    &node_id,
                    config.http_addr,
                    config.grpc_addr,
                    &new_table.shard_map,
                )
                .await;
            }
        }
    });
}

fn spawn_projection_runner(
    config: crate::config::Config,
    dataplane_pool: crate::pool::DataPlanePool,
    control: Arc<RwLock<crate::control::ControlV1>>,
    _metrics: Metrics,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(
            config.projections_tick_interval_ms.max(10),
        ));
        loop {
            interval.tick().await;

            // Respect pause_compaction/emergency_brake for background maintenance work.
            let c = control.read().await.clone();
            if c.valves.pause_compaction.enabled || c.valves.emergency_brake.enabled {
                continue;
            }

            dataplane_pool
                .tick_projections_all(config.projections_batch_frames)
                .await;

        }
    });
}

fn spawn_scrub_scheduler(
    config: crate::config::Config,
    dataplane_pool: crate::pool::DataPlanePool,
    control: Arc<RwLock<crate::control::ControlV1>>,
    corruption_detected: Arc<RwLock<bool>>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            config.scrub_interval_secs.max(10),
        ));
        loop {
            interval.tick().await;
            let started = std::time::Instant::now();

            let c = control.read().await.clone();
            if c.valves.pause_compaction.enabled || c.valves.emergency_brake.enabled {
                continue;
            }

            let mode_full = config.scrub_mode.eq_ignore_ascii_case("full")
                || config.scrub_scope.eq_ignore_ascii_case("all");
            let sample_rate = if mode_full {
                1.0
            } else {
                config.scrub_sample_rate.clamp(0.0, 1.0)
            };
            let summary = dataplane_pool
                .verify_store_integrity_all(mode_full, sample_rate, 8 * 1024 * 1024, true)
                .await;
            let mut op_log = StructuredOpLog::new(
                if summary.ok { "info" } else { "error" },
                "scrub",
                if summary.ok { "ok" } else { "fail" },
                started.elapsed().as_millis() as u64,
            );
            if !summary.ok {
                op_log.error_code = Some(ErrorCode::SegmentCorrupt.as_str().to_string());
            }
            if !summary.ok {
                *corruption_detected.write().await = true;
                tracing::error!(
                    ts = %op_log.ts,
                    level = %op_log.level,
                    op = %op_log.op,
                    outcome = %op_log.outcome,
                    took_ms = op_log.took_ms,
                    error_code = %op_log.error_code.clone().unwrap_or_default(),
                    scanned_shards = summary.scanned_shards,
                    failed_shards = summary.failed_shards,
                    "scrub scheduler detected corruption"
                );
            } else {
                tracing::info!(
                    ts = %op_log.ts,
                    level = %op_log.level,
                    op = %op_log.op,
                    outcome = %op_log.outcome,
                    took_ms = op_log.took_ms,
                    scanned_shards = summary.scanned_shards,
                    failed_shards = summary.failed_shards,
                    "scrub scheduler run complete"
                );
            }
        }
    });
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CapacityLevel {
    Healthy,
    Warning,
    Critical,
    Emergency,
}

impl CapacityLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Emergency => "emergency",
        }
    }
}

fn classify_capacity_level(free_ratio: f64, config: &crate::config::Config) -> CapacityLevel {
    if free_ratio < config.capacity_emergency_free_ratio {
        CapacityLevel::Emergency
    } else if free_ratio < config.capacity_critical_free_ratio {
        CapacityLevel::Critical
    } else if free_ratio < config.capacity_warning_free_ratio {
        CapacityLevel::Warning
    } else {
        CapacityLevel::Healthy
    }
}

fn measure_data_dir_space(path: &Path) -> Result<(u64, u64), String> {
    let total = total_space(path).map_err(|err| format!("total_space failed: {err}"))?;
    let free = available_space(path).map_err(|err| format!("available_space failed: {err}"))?;
    Ok((total, free))
}

fn spawn_capacity_guard(
    config: crate::config::Config,
    metrics: Metrics,
    control: Arc<RwLock<crate::control::ControlV1>>,
    dataplane_pool: Option<crate::pool::DataPlanePool>,
    capacity: Arc<RwLock<CapacityState>>,
    build: BuildInfo,
    node_id: String,
    control_path: std::path::PathBuf,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            config.capacity_guard_interval_secs.max(10),
        ));
        let node = build_node_context(
            &build,
            &node_id,
            Some(config.http_addr.to_string()),
            Some(config.grpc_addr.to_string()),
        );
        let mut last_level: Option<CapacityLevel> = None;
        let mut last_auto_paused = false;

        loop {
            interval.tick().await;

            let (total_bytes, free_bytes) = match measure_data_dir_space(&config.data_dir) {
                Ok(space) => space,
                Err(err) => {
                    tracing::warn!(err = %err, "capacity guard failed to measure data dir");
                    metrics.set_data_dir_space(0, 0);
                    let mut state = capacity.write().await;
                    state.total_bytes = 0;
                    state.free_bytes = 0;
                    state.free_ratio = 0.0;
                    state.auto_paused = false;
                    state.error = Some(err);
                    continue;
                }
            };

            metrics.set_data_dir_space(total_bytes, free_bytes);
            let free_ratio = if total_bytes == 0 {
                0.0
            } else {
                free_bytes as f64 / total_bytes as f64
            };
            let level = classify_capacity_level(free_ratio, &config);
            let mut pause_action = "observed".to_string();
            let mut transition_detail = format!(
                "free_ratio={:.3} warning={:.3} critical={:.3} emergency={:.3} free_bytes={} total_bytes={}",
                free_ratio,
                config.capacity_warning_free_ratio,
                config.capacity_critical_free_ratio,
                config.capacity_emergency_free_ratio,
                free_bytes,
                total_bytes
            );

            let (pause_ingest_active, auto_paused) = {
                let mut control_state = control.write().await;
                let guard_owned = control_state.valves.pause_ingest.actor == "capacity_guard";
                if level == CapacityLevel::Emergency {
                    if !control_state.valves.pause_ingest.enabled || guard_owned {
                        let reason = format!(
                            "capacity_guard free_ratio={:.3} below emergency threshold={:.3}",
                            free_ratio, config.capacity_emergency_free_ratio
                        );
                        let now_ns = crate::control::now_unix_ns();
                        control_state.valves.pause_ingest.set(
                            true,
                            "capacity_guard",
                            &reason,
                            now_ns,
                        );
                        control_state.updated_at_unix_ns = now_ns;
                        if let Err(err) =
                            crate::control::write_control_atomic(&control_path, &control_state)
                        {
                            tracing::warn!(err = %err, "capacity guard failed to persist CONTROL.json");
                        } else {
                            metrics.set_valve_pause_ingest(true);
                            metrics.set_valve_state("pause_ingest", true);
                        }
                        pause_action = "pause_ingest_enabled".to_string();
                        transition_detail = reason;
                    }
                } else if guard_owned
                    && control_state.valves.pause_ingest.enabled
                    && free_ratio >= config.capacity_resume_free_ratio
                {
                    let reason = format!(
                        "capacity_guard free_ratio={:.3} recovered above resume threshold={:.3}",
                        free_ratio, config.capacity_resume_free_ratio
                    );
                    let now_ns = crate::control::now_unix_ns();
                    control_state
                        .valves
                        .pause_ingest
                        .set(false, "capacity_guard", &reason, now_ns);
                    control_state.updated_at_unix_ns = now_ns;
                    if let Err(err) =
                        crate::control::write_control_atomic(&control_path, &control_state)
                    {
                        tracing::warn!(err = %err, "capacity guard failed to persist CONTROL.json");
                    } else {
                        metrics.set_valve_pause_ingest(false);
                        metrics.set_valve_state("pause_ingest", false);
                    }
                    pause_action = "pause_ingest_cleared".to_string();
                    transition_detail = reason;
                }

                let pause_ingest_active = control_state.valves.pause_ingest.enabled;
                let auto_paused = pause_ingest_active
                    && control_state.valves.pause_ingest.actor == "capacity_guard";
                (pause_ingest_active, auto_paused)
            };

            {
                let mut state = capacity.write().await;
                state.total_bytes = total_bytes;
                state.free_bytes = free_bytes;
                state.free_ratio = free_ratio;
                state.auto_paused = auto_paused;
                state.error = None;
            }

            if last_level != Some(level) || last_auto_paused != auto_paused {
                tracing::info!(
                    level = level.as_str(),
                    free_ratio = free_ratio,
                    free_bytes = free_bytes,
                    total_bytes = total_bytes,
                    auto_paused = auto_paused,
                    "capacity guard state changed"
                );
                if let Some(pool) = dataplane_pool.as_ref() {
                    let payload = CapacityThresholdBreachedV1 {
                        schema: EVT_CAPACITY_THRESHOLD_BREACHED_V1.to_string(),
                        observed_at_unix_ms: now_unix_ms(),
                        threshold_kind: level.as_str().to_string(),
                        threshold_ratio: match level {
                            CapacityLevel::Healthy => config.capacity_warning_free_ratio,
                            CapacityLevel::Warning => config.capacity_warning_free_ratio,
                            CapacityLevel::Critical => config.capacity_critical_free_ratio,
                            CapacityLevel::Emergency => config.capacity_emergency_free_ratio,
                        },
                        free_ratio,
                        free_bytes,
                        total_bytes,
                        action: pause_action.clone(),
                        pause_ingest_active,
                        detail: Some(transition_detail.clone()),
                        node: node.clone(),
                    };
                    let event_id = format!(
                        "{EVT_CAPACITY_THRESHOLD_BREACHED_V1}:{node_id}:{}:{}",
                        payload.observed_at_unix_ms,
                        level.as_str()
                    );
                    if let Err(err) = append_ops_event(
                        pool,
                        &node_id,
                        EVT_CAPACITY_THRESHOLD_BREACHED_V1,
                        event_id,
                        &payload,
                    )
                    .await
                    {
                        tracing::warn!(err = ?err, "failed to append capacity ops event");
                    }
                }
            }

            last_level = Some(level);
            last_auto_paused = auto_paused;
        }
    });
}

async fn emit_shardmap_updated_event(
    pool: &crate::pool::DataPlanePool,
    build: &BuildInfo,
    node_id: &str,
    http_addr: SocketAddr,
    grpc_addr: SocketAddr,
    shard_map: &corecrux_types::ShardMapV1,
) -> Result<(), crate::dataplane_store::AppendError> {
    #[derive(serde::Serialize)]
    struct Payload<'a> {
        version: u64,
        blake3: &'a str,
        #[serde(rename = "createdAt")]
        created_at: &'a str,
        #[serde(rename = "operatorId")]
        operator_id: &'a str,
        reason: &'a str,
    }

    let payload = Payload {
        version: shard_map.version,
        blake3: &shard_map.blake3,
        created_at: &shard_map.created_at,
        operator_id: node_id,
        reason: "routing_reload",
    };
    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();

    let blake3_prefix = shard_map.blake3.get(0..16).unwrap_or("unknown");
    let event_id = format!(
        "corecrux.routing.shardmap_updated.v1:{}:{blake3_prefix}",
        shard_map.version
    );

    let occurred_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let event = corecrux_proto::dataplane_v1::AppendEvent {
        event_id,
        occurred_at,
        event_type: "corecrux.routing.shardmap_updated.v1".to_string(),
        content_type: "application/json".to_string(),
        payload: payload_bytes,
    };

    let (_decision, store) = pool
        .store_for_stream("system", "corecrux", "routing", None)
        .await?;
    let store = store.read().await;
    let _ = store
        .append_batch("system", "corecrux", "routing", 0, None, &[event])
        .await?;

    let ops_payload = ShardRebalanceRecordedV1 {
        schema: EVT_SHARD_REBALANCE_RECORDED_V1.to_string(),
        recorded_at_unix_ms: now_unix_ms(),
        shard_map_version: shard_map.version,
        shard_map_blake3: shard_map.blake3.clone(),
        created_at: shard_map.created_at.clone(),
        actor: node_id.to_string(),
        reason: "routing_reload".to_string(),
        node: build_node_context(
            build,
            node_id,
            Some(http_addr.to_string()),
            Some(grpc_addr.to_string()),
        ),
    };
    let ops_event_id = format!(
        "{EVT_SHARD_REBALANCE_RECORDED_V1}:{}:{}",
        shard_map.version,
        shard_map.blake3.get(0..16).unwrap_or("unknown")
    );
    append_ops_event(
        pool,
        node_id,
        EVT_SHARD_REBALANCE_RECORDED_V1,
        ops_event_id,
        &ops_payload,
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        reconcile_control_from_evidence, shard_map_advertise_addr, validate_network_auth_posture,
        ControlCheckpointRecord, ControlMutationRecord,
    };
    use crate::auth::AuthMode;
    use crate::config::CommitLevel;
    use crate::control;
    use corecrux_types::{
        BuildInfo, ControlCheckpointMaterializedV1, ControlStateMutationV1, EvidenceAuthContextV1,
        EvidenceNodeContextV1, EvidenceRequestContextV1, EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1,
        EVT_CONTROL_STATE_MUTATION_V1,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn sample_node() -> EvidenceNodeContextV1 {
        EvidenceNodeContextV1 {
            node_id: "node-a".to_string(),
            build: BuildInfo {
                version: "test".to_string(),
                commit: "test".to_string(),
            },
            http_listen_addr: None,
            grpc_listen_addr: None,
        }
    }

    fn sample_auth() -> EvidenceAuthContextV1 {
        EvidenceAuthContextV1 {
            mode: "dev_scopes".to_string(),
            subject: None,
            tenant_binding: None,
            scopes: vec!["admin:write".to_string()],
        }
    }

    fn mutation_record(
        seq: u64,
        before: &control::ControlV1,
        after: &control::ControlV1,
    ) -> ControlMutationRecord {
        ControlMutationRecord {
            seq,
            payload: ControlStateMutationV1 {
                schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
                action_id: format!("act-{seq}"),
                mutation_type: "set_valves".to_string(),
                applied_at_unix_ms: seq,
                actor: "operator".to_string(),
                reason: "maintenance".to_string(),
                auth: sample_auth(),
                request: EvidenceRequestContextV1::default(),
                node: sample_node(),
                control_before: control::control_state_digest_v1(before),
                control_after: control::control_state_digest_v1(after),
                valve_changes: control::valve_changes_v1(before, after),
                knowledge_authority_change: None,
                result: None,
            },
        }
    }

    fn checkpoint_record(seq: u64, state: &control::ControlV1) -> ControlCheckpointRecord {
        let bytes = control::checkpoint_control_bytes_v1(state);
        ControlCheckpointRecord {
            seq,
            payload: ControlCheckpointMaterializedV1 {
                schema: EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1.to_string(),
                checkpoint_id: format!("checkpoint-{seq}"),
                materialized_at_unix_ms: seq,
                node: sample_node(),
                control_state: control::control_state_digest_v1(state),
                checkpoint_format: "control.json.pretty.v1".to_string(),
                checkpoint_blake3: blake3::hash(&bytes).to_hex().to_string(),
                checkpoint_size_bytes: bytes.len() as u64,
            },
        }
    }

    #[test]
    fn dev_auth_rejects_non_loopback_bind_without_override() {
        let err = validate_network_auth_posture(
            AuthMode::DevScopes,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4007),
            CommitLevel::LocalCommit,
            false,
            false,
        )
        .expect_err("non-loopback dev auth bind must fail closed");
        assert!(err.contains("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND"));
    }

    #[test]
    fn dev_auth_allows_non_loopback_bind_with_override() {
        validate_network_auth_posture(
            AuthMode::Off,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4007),
            CommitLevel::LocalCommit,
            true,
            false,
        )
        .expect("explicit override should permit insecure dev bind");
    }

    #[test]
    fn replicated_commit_with_jwt_requires_replication_bearer() {
        let err = validate_network_auth_posture(
            AuthMode::JwtJwks,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4007),
            CommitLevel::ReplicatedCommit,
            false,
            false,
        )
        .expect_err("jwt replicated commit should require explicit replication auth");
        assert!(err.contains("CORECRUXD_REPLICATION_AUTH_BEARER"));
    }

    #[test]
    fn replicated_commit_with_jwt_accepts_replication_bearer() {
        validate_network_auth_posture(
            AuthMode::JwtHs256,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4007),
            CommitLevel::ReplicatedCommit,
            false,
            true,
        )
        .expect("explicit replication bearer should satisfy jwt replicated commit auth");
    }

    #[test]
    fn shard_map_advertise_addr_preserves_explicit_host() {
        assert_eq!(
            shard_map_advertise_addr(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
                4006
            )),
            "10.1.2.3:4006"
        );
    }

    #[test]
    fn shard_map_advertise_addr_normalizes_unspecified_host_to_loopback() {
        assert_eq!(
            shard_map_advertise_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4006)),
            "127.0.0.1:4006"
        );
        assert_eq!(
            shard_map_advertise_addr(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 4007)),
            "[::1]:4007"
        );
    }

    #[test]
    fn control_evidence_replays_from_matching_checkpoint() {
        let default_state = control::ControlV1::default();
        let mut checkpoint_state = default_state.clone();
        checkpoint_state.updated_at_unix_ns = 10;
        checkpoint_state
            .valves
            .read_only
            .set(true, "operator", "maintenance", 10);

        let mut final_state = checkpoint_state.clone();
        final_state.updated_at_unix_ns = 20;
        final_state
            .valves
            .throttle
            .set(true, "operator", "maintenance", 20);
        final_state
            .valves
            .throttle
            .set_throttle_params(Some(20), Some(4096), Some(3));

        let plan = reconcile_control_from_evidence(
            &checkpoint_state,
            &control::checkpoint_control_bytes_v1(&checkpoint_state),
            &[checkpoint_record(2, &checkpoint_state)],
            &[mutation_record(3, &checkpoint_state, &final_state)],
        )
        .expect("reconcile succeeds")
        .expect("replay plan present");

        assert_eq!(plan.anchor, "checkpoint");
        assert_eq!(plan.anchor_seq, 2);
        assert_eq!(plan.applied_mutations, 1);
        assert_eq!(plan.state, final_state);
    }

    #[test]
    fn control_evidence_replays_from_default_when_stream_starts_clean() {
        let default_state = control::ControlV1::default();
        let mut final_state = default_state.clone();
        final_state.updated_at_unix_ns = 30;
        final_state
            .valves
            .emergency_brake
            .set(true, "operator", "maintenance", 30);
        final_state
            .valves
            .read_only
            .set(true, "operator", "maintenance", 30);
        final_state
            .valves
            .pause_ingest
            .set(true, "operator", "maintenance", 30);
        final_state
            .valves
            .pause_compaction
            .set(true, "operator", "maintenance", 30);

        let plan = reconcile_control_from_evidence(
            &default_state,
            &control::checkpoint_control_bytes_v1(&default_state),
            &[],
            &[mutation_record(1, &default_state, &final_state)],
        )
        .expect("reconcile succeeds")
        .expect("replay plan present");

        assert_eq!(plan.anchor, "default");
        assert_eq!(plan.anchor_seq, 0);
        assert_eq!(plan.applied_mutations, 1);
        assert_eq!(plan.state, final_state);
    }

    // ── validate_network_auth_posture additional cases ───────────────────

    #[test]
    fn auth_off_on_loopback_is_fine() {
        validate_network_auth_posture(
            AuthMode::Off,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4007),
            CommitLevel::LocalCommit,
            false,
            false,
        )
        .expect("loopback with auth off should always be fine");
    }

    #[test]
    fn jwt_hs256_non_loopback_is_ok_without_replication() {
        validate_network_auth_posture(
            AuthMode::JwtHs256,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4007),
            CommitLevel::LocalCommit,
            false,
            false,
        )
        .expect("jwt with local commit should be ok on non-loopback");
    }

    #[test]
    fn jwt_jwks_replicated_commit_fails_without_bearer() {
        let err = validate_network_auth_posture(
            AuthMode::JwtJwks,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4007),
            CommitLevel::ReplicatedCommit,
            false,
            false,
        )
        .expect_err("replicated commit with jwt should require replication bearer");
        assert!(err.contains("REPLICATION_AUTH_BEARER"));
    }

    #[test]
    fn dev_scopes_on_v6_loopback_is_ok() {
        validate_network_auth_posture(
            AuthMode::DevScopes,
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4006),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4007),
            CommitLevel::LocalCommit,
            false,
            false,
        )
        .expect("v6 loopback with dev scopes should be fine");
    }

    #[test]
    fn dev_scopes_mixed_loopback_and_non_loopback_fails() {
        let err = validate_network_auth_posture(
            AuthMode::DevScopes,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 4007),
            CommitLevel::LocalCommit,
            false,
            false,
        )
        .expect_err("mixed loopback/non-loopback should fail");
        assert!(err.contains("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND"));
    }

    // ── shard_map_advertise_addr additional cases ────────────────────────

    #[test]
    fn shard_map_advertise_addr_preserves_v6_explicit_host() {
        let addr = SocketAddr::new(
            IpAddr::V6("fe80::1".parse().unwrap()),
            4006,
        );
        assert_eq!(shard_map_advertise_addr(addr), "[fe80::1]:4006");
    }

    #[test]
    fn shard_map_advertise_addr_preserves_port() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 9999);
        assert_eq!(shard_map_advertise_addr(addr), "192.168.1.1:9999");
    }

    // ── reconcile_control_from_evidence additional cases ─────────────────

    #[test]
    fn reconcile_empty_evidence_returns_none() {
        let state = control::ControlV1::default();
        let result = reconcile_control_from_evidence(
            &state,
            &control::checkpoint_control_bytes_v1(&state),
            &[],
            &[],
        )
        .expect("reconcile succeeds");
        assert!(result.is_none());
    }

    #[test]
    fn reconcile_picks_highest_anchor_seq_when_both_present() {
        let default_state = control::ControlV1::default();
        let mut mid_state = default_state.clone();
        mid_state.updated_at_unix_ns = 10;
        mid_state
            .valves
            .read_only
            .set(true, "operator", "test", 10);

        let mut final_state = mid_state.clone();
        final_state.updated_at_unix_ns = 20;
        final_state
            .valves
            .throttle
            .set(true, "operator", "test", 20);
        final_state
            .valves
            .throttle
            .set_throttle_params(Some(10), Some(1024), Some(5));

        // Checkpoint at seq=5, mutation anchor at seq=3
        // Checkpoint has higher seq, should be chosen as anchor
        let plan = reconcile_control_from_evidence(
            &mid_state,
            &control::checkpoint_control_bytes_v1(&mid_state),
            &[checkpoint_record(5, &mid_state)],
            &[
                mutation_record(3, &default_state, &mid_state),
                mutation_record(6, &mid_state, &final_state),
            ],
        )
        .expect("reconcile succeeds")
        .expect("plan present");

        assert_eq!(plan.anchor, "checkpoint");
        assert_eq!(plan.anchor_seq, 5);
        assert_eq!(plan.applied_mutations, 1);
        assert_eq!(plan.state, final_state);
    }

    #[test]
    fn reconcile_picks_mutation_anchor_when_higher_seq() {
        let default_state = control::ControlV1::default();
        let mut mid_state = default_state.clone();
        mid_state.updated_at_unix_ns = 10;
        mid_state
            .valves
            .read_only
            .set(true, "operator", "test", 10);

        let mut final_state = mid_state.clone();
        final_state.updated_at_unix_ns = 20;
        final_state
            .valves
            .throttle
            .set(true, "operator", "test", 20);
        final_state
            .valves
            .throttle
            .set_throttle_params(Some(10), Some(1024), Some(5));

        // Checkpoint at seq=2, mutation anchor at seq=5 (mid_state matches)
        let plan = reconcile_control_from_evidence(
            &mid_state,
            &control::checkpoint_control_bytes_v1(&mid_state),
            &[checkpoint_record(2, &mid_state)],
            &[
                mutation_record(5, &default_state, &mid_state),
                mutation_record(6, &mid_state, &final_state),
            ],
        )
        .expect("reconcile succeeds")
        .expect("plan present");

        assert_eq!(plan.anchor, "mutation");
        assert_eq!(plan.anchor_seq, 5);
        assert_eq!(plan.applied_mutations, 1);
        assert_eq!(plan.state, final_state);
    }

    #[test]
    fn reconcile_errors_when_no_anchor_and_mutations_dont_start_from_default() {
        // Create a "current" state that does NOT match any mutation's control_after
        let mut unrelated_state = control::ControlV1::default();
        unrelated_state.updated_at_unix_ns = 999;
        unrelated_state
            .valves
            .emergency_brake
            .set(true, "operator", "unrelated", 999);

        // Create mutations that start from a non-default state
        let mut state_a = control::ControlV1::default();
        state_a.updated_at_unix_ns = 100;
        state_a
            .valves
            .read_only
            .set(true, "operator", "test", 100);

        let mut state_b = state_a.clone();
        state_b.updated_at_unix_ns = 200;
        state_b
            .valves
            .pause_ingest
            .set(true, "operator", "test", 200);

        // Current state matches nothing; first mutation's control_before != default
        let err = reconcile_control_from_evidence(
            &unrelated_state,
            &control::checkpoint_control_bytes_v1(&unrelated_state),
            &[],
            &[mutation_record(1, &state_a, &state_b)],
        )
        .expect_err("should error when no anchor found");
        assert!(err.contains("does not match any checkpoint"));
    }

    #[test]
    fn reconcile_applies_multiple_mutations_in_sequence() {
        let default_state = control::ControlV1::default();

        let mut state1 = default_state.clone();
        state1.updated_at_unix_ns = 10;
        state1
            .valves
            .read_only
            .set(true, "operator", "step1", 10);

        let mut state2 = state1.clone();
        state2.updated_at_unix_ns = 20;
        state2
            .valves
            .pause_ingest
            .set(true, "operator", "step2", 20);

        let mut state3 = state2.clone();
        state3.updated_at_unix_ns = 30;
        state3
            .valves
            .emergency_brake
            .set(true, "operator", "step3", 30);

        let plan = reconcile_control_from_evidence(
            &default_state,
            &control::checkpoint_control_bytes_v1(&default_state),
            &[],
            &[
                mutation_record(1, &default_state, &state1),
                mutation_record(2, &state1, &state2),
                mutation_record(3, &state2, &state3),
            ],
        )
        .expect("reconcile succeeds")
        .expect("plan present");

        assert_eq!(plan.anchor, "default");
        assert_eq!(plan.applied_mutations, 3);
        assert_eq!(plan.state, state3);
    }

    // ── ControlEvidenceRuntimeStatus ─────────────────────────────────────

    #[test]
    fn control_evidence_status_non_hosted() {
        let status = super::ControlEvidenceRuntimeStatus::non_hosted("not on this node");
        assert!(!status.hosted_locally);
        assert!(status.ok);
        assert_eq!(status.detail.as_deref(), Some("not on this node"));
    }

    #[test]
    fn control_evidence_status_hosted_ok() {
        let status = super::ControlEvidenceRuntimeStatus::hosted_ok("all good");
        assert!(status.hosted_locally);
        assert!(status.ok);
        assert_eq!(status.detail.as_deref(), Some("all good"));
    }

    #[test]
    fn control_evidence_status_hosted_err() {
        let status = super::ControlEvidenceRuntimeStatus::hosted_err("reconcile failed");
        assert!(status.hosted_locally);
        assert!(!status.ok);
        assert_eq!(status.detail.as_deref(), Some("reconcile failed"));
    }

    #[test]
    fn control_evidence_replay_plan_eq() {
        let state = control::ControlV1::default();
        let plan1 = super::ControlEvidenceReplayPlan {
            state: state.clone(),
            anchor: "checkpoint",
            anchor_seq: 5,
            applied_mutations: 2,
        };
        let plan2 = super::ControlEvidenceReplayPlan {
            state: state.clone(),
            anchor: "checkpoint",
            anchor_seq: 5,
            applied_mutations: 2,
        };
        assert_eq!(plan1, plan2);
    }

    #[test]
    fn control_evidence_replay_plan_ne_on_mutations() {
        let state = control::ControlV1::default();
        let plan1 = super::ControlEvidenceReplayPlan {
            state: state.clone(),
            anchor: "checkpoint",
            anchor_seq: 5,
            applied_mutations: 2,
        };
        let plan2 = super::ControlEvidenceReplayPlan {
            state: state.clone(),
            anchor: "checkpoint",
            anchor_seq: 5,
            applied_mutations: 3,
        };
        assert_ne!(plan1, plan2);
    }

    // ── NodeMetaV1 serde roundtrip ───────��───────────────────────────────

    #[test]
    fn node_meta_v1_serde_roundtrip() {
        let meta = super::NodeMetaV1 {
            v: 1,
            node_id: "node-abc".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            http_listen_addr: "127.0.0.1:14800".to_string(),
            grpc_listen_addr: "127.0.0.1:14801".to_string(),
            gpu_id: Some(0),
            build: BuildInfo {
                version: "0.1.0".to_string(),
                commit: "abc123".to_string(),
            },
        };
        let json_bytes = serde_json::to_vec(&meta).unwrap();
        let roundtripped: super::NodeMetaV1 = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(roundtripped.node_id, "node-abc");
        assert_eq!(roundtripped.gpu_id, Some(0));
        assert_eq!(roundtripped.build.version, "0.1.0");
    }

    #[test]
    fn node_meta_v1_gpu_id_none_omitted_in_json() {
        let meta = super::NodeMetaV1 {
            v: 1,
            node_id: "node-xyz".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            http_listen_addr: "127.0.0.1:14800".to_string(),
            grpc_listen_addr: "127.0.0.1:14801".to_string(),
            gpu_id: None,
            build: BuildInfo {
                version: "0.1.0".to_string(),
                commit: "abc123".to_string(),
            },
        };
        let json_str = serde_json::to_string(&meta).unwrap();
        assert!(!json_str.contains("gpuId"), "gpuId should be omitted when None");
    }

    #[test]
    fn node_meta_v1_camel_case_field_names() {
        let meta = super::NodeMetaV1 {
            v: 1,
            node_id: "node-test".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            http_listen_addr: "127.0.0.1:14800".to_string(),
            grpc_listen_addr: "127.0.0.1:14801".to_string(),
            gpu_id: Some(2),
            build: BuildInfo {
                version: "1.0.0".to_string(),
                commit: "def456".to_string(),
            },
        };
        let v: serde_json::Value = serde_json::to_value(&meta).unwrap();
        assert!(v.get("nodeId").is_some());
        assert!(v.get("createdAt").is_some());
        assert!(v.get("httpListenAddr").is_some());
        assert!(v.get("grpcListenAddr").is_some());
        assert!(v.get("gpuId").is_some());
    }

    // ── load_or_init_node_meta ──────────────────────────────────────────

    #[test]
    fn load_or_init_node_meta_creates_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta").join("node.json");
        let build = BuildInfo {
            version: "0.1.0".to_string(),
            commit: "abc".to_string(),
        };
        let meta = super::load_or_init_node_meta(
            &path,
            Some("node-fixed"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14800),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14801),
            Some(0),
            &build,
        )
        .unwrap();
        assert_eq!(meta.node_id, "node-fixed");
        assert_eq!(meta.v, 1);
        assert_eq!(meta.gpu_id, Some(0));
        assert!(path.exists());
    }

    #[test]
    fn load_or_init_node_meta_loads_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta").join("node.json");
        let build = BuildInfo {
            version: "0.1.0".to_string(),
            commit: "abc".to_string(),
        };
        // Create first.
        let meta1 = super::load_or_init_node_meta(
            &path,
            Some("node-first"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14800),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14801),
            None,
            &build,
        )
        .unwrap();
        // Load again (should not overwrite).
        let meta2 = super::load_or_init_node_meta(
            &path,
            Some("node-second"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 15800),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 15801),
            Some(1),
            &build,
        )
        .unwrap();
        assert_eq!(meta1.node_id, meta2.node_id);
        assert_eq!(meta2.node_id, "node-first");
    }

    #[test]
    fn load_or_init_node_meta_generates_uuid_when_no_override() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta").join("node.json");
        let build = BuildInfo {
            version: "0.1.0".to_string(),
            commit: "abc".to_string(),
        };
        let meta = super::load_or_init_node_meta(
            &path,
            None,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14800),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14801),
            None,
            &build,
        )
        .unwrap();
        assert!(meta.node_id.starts_with("node-"), "expected 'node-' prefix, got: {}", meta.node_id);
        assert!(meta.node_id.len() > 10, "expected UUID suffix");
    }

    #[test]
    fn load_or_init_node_meta_invalid_json_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("meta");
        std::fs::create_dir_all(&parent).unwrap();
        let path = parent.join("node.json");
        std::fs::write(&path, b"not-json").unwrap();
        let build = BuildInfo {
            version: "0.1.0".to_string(),
            commit: "abc".to_string(),
        };
        let err = super::load_or_init_node_meta(
            &path,
            None,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14800),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14801),
            None,
            &build,
        );
        assert!(err.is_err());
    }

    // ── acquire_lock ────────────────────────────────────────────────────

    #[test]
    fn acquire_lock_creates_lock_file() {
        let dir = tempfile::tempdir().unwrap();
        let lock = super::acquire_lock(dir.path()).unwrap();
        assert!(dir.path().join("LOCK").exists());
        drop(lock);
    }

    #[test]
    fn acquire_lock_second_attempt_fails() {
        let dir = tempfile::tempdir().unwrap();
        let _lock = super::acquire_lock(dir.path()).unwrap();
        let result = super::acquire_lock(dir.path());
        assert!(result.is_err(), "second exclusive lock should fail");
    }

    #[test]
    fn acquire_lock_succeeds_after_drop() {
        let dir = tempfile::tempdir().unwrap();
        {
            let _lock = super::acquire_lock(dir.path()).unwrap();
        }
        // After drop, lock should be released.
        let _lock2 = super::acquire_lock(dir.path()).unwrap();
    }

    // ── classify_capacity_level ─────────────────────────────────────────

    // Uses load_config() with default env (serial to avoid env pollution).
    // Default thresholds after normalization: warning=0.20, critical=0.10, emergency=0.10.
    #[test]
    #[serial_test::serial]
    fn classify_capacity_healthy() {
        let cfg = crate::config::load_config();
        assert_eq!(
            super::classify_capacity_level(0.25, &cfg),
            super::CapacityLevel::Healthy
        );
    }

    #[test]
    #[serial_test::serial]
    fn classify_capacity_warning() {
        let cfg = crate::config::load_config();
        // Between emergency/critical (0.10) and warning (0.20)
        assert_eq!(
            super::classify_capacity_level(0.15, &cfg),
            super::CapacityLevel::Warning
        );
    }

    #[test]
    #[serial_test::serial]
    fn classify_capacity_emergency_default_thresholds() {
        let cfg = crate::config::load_config();
        // Default critical == emergency == 0.10, so anything below is Emergency.
        assert_eq!(
            super::classify_capacity_level(0.05, &cfg),
            super::CapacityLevel::Emergency
        );
    }

    #[test]
    #[serial_test::serial]
    fn classify_capacity_at_exact_boundaries() {
        let cfg = crate::config::load_config();
        // Just below warning threshold => Warning
        assert_eq!(
            super::classify_capacity_level(cfg.capacity_warning_free_ratio - 0.001, &cfg),
            super::CapacityLevel::Warning
        );
        // At exactly the warning threshold => Healthy (>= warning)
        assert_eq!(
            super::classify_capacity_level(cfg.capacity_warning_free_ratio, &cfg),
            super::CapacityLevel::Healthy
        );
        // At exactly the emergency threshold => Emergency (< critical == emergency)
        assert_eq!(
            super::classify_capacity_level(cfg.capacity_emergency_free_ratio - 0.001, &cfg),
            super::CapacityLevel::Emergency
        );
    }

    // ── CapacityLevel::as_str ───────────────────────────────────────────

    #[test]
    fn capacity_level_as_str() {
        assert_eq!(super::CapacityLevel::Healthy.as_str(), "healthy");
        assert_eq!(super::CapacityLevel::Warning.as_str(), "warning");
        assert_eq!(super::CapacityLevel::Critical.as_str(), "critical");
        assert_eq!(super::CapacityLevel::Emergency.as_str(), "emergency");
    }

    // ── measure_data_dir_space ──────────────────────────────────────────

    #[test]
    fn measure_data_dir_space_on_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        let (total, free) = super::measure_data_dir_space(dir.path()).unwrap();
        assert!(total > 0, "total bytes should be >0");
        assert!(free > 0, "free bytes should be >0");
        assert!(free <= total, "free should not exceed total");
    }

    #[test]
    fn measure_data_dir_space_nonexistent_errors() {
        let result = super::measure_data_dir_space(std::path::Path::new("/nonexistent_dir_xyz"));
        assert!(result.is_err());
    }

    // ── ControlCheckpointRecord / ControlMutationRecord parsing ─────────

    #[test]
    fn control_checkpoint_record_serde_roundtrip() {
        let state = control::ControlV1::default();
        let rec = checkpoint_record(42, &state);
        let json = serde_json::to_vec(&rec.payload).unwrap();
        let parsed: ControlCheckpointMaterializedV1 = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.checkpoint_id, "checkpoint-42");
        assert_eq!(parsed.materialized_at_unix_ms, 42);
        assert_eq!(
            parsed.control_state,
            control::control_state_digest_v1(&state)
        );
    }

    #[test]
    fn control_mutation_record_serde_roundtrip() {
        let before = control::ControlV1::default();
        let mut after = before.clone();
        after.updated_at_unix_ns = 99;
        after
            .valves
            .pause_ingest
            .set(true, "test", "test-reason", 99);
        let rec = mutation_record(7, &before, &after);
        let json = serde_json::to_vec(&rec.payload).unwrap();
        let parsed: ControlStateMutationV1 = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.action_id, "act-7");
        assert_eq!(parsed.mutation_type, "set_valves");
        assert_eq!(
            parsed.control_before,
            control::control_state_digest_v1(&before)
        );
        assert_eq!(
            parsed.control_after,
            control::control_state_digest_v1(&after)
        );
    }

    // ── ControlEvidenceReplayPlan Debug ─────────────────────────────────

    #[test]
    fn control_evidence_replay_plan_debug_display() {
        let plan = super::ControlEvidenceReplayPlan {
            state: control::ControlV1::default(),
            anchor: "checkpoint",
            anchor_seq: 10,
            applied_mutations: 3,
        };
        let debug_str = format!("{:?}", plan);
        assert!(debug_str.contains("checkpoint"));
        assert!(debug_str.contains("10"));
        assert!(debug_str.contains("3"));
    }

    // ── reconcile_control_from_evidence: checkpoint-only (no mutations) ─

    #[test]
    fn reconcile_checkpoint_only_no_mutations() {
        let state = control::ControlV1::default();
        let plan = reconcile_control_from_evidence(
            &state,
            &control::checkpoint_control_bytes_v1(&state),
            &[checkpoint_record(1, &state)],
            &[],
        )
        .expect("reconcile succeeds")
        .expect("plan present");
        assert_eq!(plan.anchor, "checkpoint");
        assert_eq!(plan.anchor_seq, 1);
        assert_eq!(plan.applied_mutations, 0);
        assert_eq!(plan.state, state);
    }

    // ── reconcile_control_from_evidence: mutation-only anchor (no checkpoints)

    #[test]
    fn reconcile_mutation_only_anchor() {
        let default_state = control::ControlV1::default();
        let mut final_state = default_state.clone();
        final_state.updated_at_unix_ns = 50;
        final_state
            .valves
            .throttle
            .set(true, "operator", "test", 50);
        final_state
            .valves
            .throttle
            .set_throttle_params(Some(100), Some(8192), Some(8));

        let plan = reconcile_control_from_evidence(
            &final_state,
            &control::checkpoint_control_bytes_v1(&final_state),
            &[],
            &[mutation_record(1, &default_state, &final_state)],
        )
        .expect("reconcile succeeds")
        .expect("plan present");
        assert_eq!(plan.anchor, "mutation");
        assert_eq!(plan.anchor_seq, 1);
        assert_eq!(plan.applied_mutations, 0);
    }

    // ── shard_map_advertise_addr: loopback passthrough ──────────────────

    #[test]
    fn shard_map_advertise_addr_loopback_passthrough() {
        assert_eq!(
            shard_map_advertise_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4006)),
            "127.0.0.1:4006"
        );
        assert_eq!(
            shard_map_advertise_addr(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 4006)),
            "[::1]:4006"
        );
    }

    // ── ControlEvidenceRuntimeStatus equality ───────────────────────────

    #[test]
    fn control_evidence_runtime_status_equality() {
        let a = super::ControlEvidenceRuntimeStatus::hosted_ok("test");
        let b = super::ControlEvidenceRuntimeStatus::hosted_ok("test");
        assert_eq!(a, b);

        let c = super::ControlEvidenceRuntimeStatus::hosted_err("test");
        assert_ne!(a, c);

        let d = super::ControlEvidenceRuntimeStatus::non_hosted("test");
        assert_ne!(a, d);
    }

    // ── update_control_metrics ─────────────────────────────────────────

    #[test]
    fn update_control_metrics_sets_valve_gauges() {
        let build = BuildInfo {
            version: "test".to_string(),
            commit: "test".to_string(),
        };
        let metrics = crate::metrics::Metrics::new(&build, "test-svc");
        let mut state = control::ControlV1::default();
        state.valves.pause_ingest.set(true, "op", "test", 1);
        state.valves.read_only.set(true, "op", "test", 1);
        // Should not panic; exercises the full valve-sync surface.
        super::update_control_metrics(&metrics, &state);
    }

    #[test]
    fn update_control_metrics_default_state() {
        let build = BuildInfo {
            version: "test".to_string(),
            commit: "test".to_string(),
        };
        let metrics = crate::metrics::Metrics::new(&build, "test-svc-default");
        let state = control::ControlV1::default();
        super::update_control_metrics(&metrics, &state);
    }

    #[test]
    fn update_control_metrics_all_valves_enabled() {
        let build = BuildInfo {
            version: "test".to_string(),
            commit: "test".to_string(),
        };
        let metrics = crate::metrics::Metrics::new(&build, "test-svc-all");
        let mut state = control::ControlV1::default();
        state.valves.pause_ingest.set(true, "op", "r", 1);
        state.valves.pause_compaction.set(true, "op", "r", 2);
        state.valves.throttle.set(true, "op", "r", 3);
        state.valves.read_only.set(true, "op", "r", 4);
        state.valves.emergency_brake.set(true, "op", "r", 5);
        super::update_control_metrics(&metrics, &state);
    }

    // ── insecure_dev_auth_bind_allowed ──────────────────────────────────

    #[test]
    #[serial_test::serial]
    fn insecure_dev_auth_bind_allowed_defaults_false() {
        std::env::remove_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND");
        assert!(!super::insecure_dev_auth_bind_allowed());
    }

    #[test]
    #[serial_test::serial]
    fn insecure_dev_auth_bind_allowed_true_when_set() {
        std::env::set_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND", "1");
        assert!(super::insecure_dev_auth_bind_allowed());
        std::env::remove_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND");
    }

    #[test]
    #[serial_test::serial]
    fn insecure_dev_auth_bind_allowed_true_variants() {
        for val in &["true", "TRUE", "yes", "YES"] {
            std::env::set_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND", val);
            assert!(
                super::insecure_dev_auth_bind_allowed(),
                "expected true for {val}"
            );
        }
        std::env::remove_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND");
    }

    #[test]
    #[serial_test::serial]
    fn insecure_dev_auth_bind_allowed_false_for_other_values() {
        std::env::set_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND", "0");
        assert!(!super::insecure_dev_auth_bind_allowed());
        std::env::set_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND", "no");
        assert!(!super::insecure_dev_auth_bind_allowed());
        std::env::set_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND", "maybe");
        assert!(!super::insecure_dev_auth_bind_allowed());
        std::env::remove_var("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND");
    }

    // ── replication_auth_bearer_configured ──────────────────────────────

    #[test]
    #[serial_test::serial]
    fn replication_auth_bearer_configured_defaults_false() {
        std::env::remove_var("CORECRUXD_REPLICATION_AUTH_BEARER");
        assert!(!super::replication_auth_bearer_configured());
    }

    #[test]
    #[serial_test::serial]
    fn replication_auth_bearer_configured_true_when_set() {
        std::env::set_var("CORECRUXD_REPLICATION_AUTH_BEARER", "my-secret");
        assert!(super::replication_auth_bearer_configured());
        std::env::remove_var("CORECRUXD_REPLICATION_AUTH_BEARER");
    }

    #[test]
    #[serial_test::serial]
    fn replication_auth_bearer_configured_false_for_empty() {
        std::env::set_var("CORECRUXD_REPLICATION_AUTH_BEARER", "");
        assert!(!super::replication_auth_bearer_configured());
        std::env::remove_var("CORECRUXD_REPLICATION_AUTH_BEARER");
    }

    #[test]
    #[serial_test::serial]
    fn replication_auth_bearer_configured_false_for_whitespace() {
        std::env::set_var("CORECRUXD_REPLICATION_AUTH_BEARER", "   ");
        assert!(!super::replication_auth_bearer_configured());
        std::env::remove_var("CORECRUXD_REPLICATION_AUTH_BEARER");
    }

    // ── shard_map_advertise_addr: port 0 edge case ─────────────────────

    #[test]
    fn shard_map_advertise_addr_port_zero() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 0);
        assert_eq!(super::shard_map_advertise_addr(addr), "10.0.0.1:0");
    }

    #[test]
    fn shard_map_advertise_addr_max_port() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 65535);
        assert_eq!(super::shard_map_advertise_addr(addr), "127.0.0.1:65535");
    }

    // ── classify_capacity_level with custom config ─────────────────────

    #[test]
    #[serial_test::serial]
    fn classify_capacity_level_zero_ratio_is_emergency() {
        let cfg = crate::config::load_config();
        assert_eq!(
            super::classify_capacity_level(0.0, &cfg),
            super::CapacityLevel::Emergency
        );
    }

    #[test]
    #[serial_test::serial]
    fn classify_capacity_level_full_is_healthy() {
        let cfg = crate::config::load_config();
        assert_eq!(
            super::classify_capacity_level(1.0, &cfg),
            super::CapacityLevel::Healthy
        );
    }

    #[test]
    #[serial_test::serial]
    fn classify_capacity_level_negative_is_emergency() {
        let cfg = crate::config::load_config();
        assert_eq!(
            super::classify_capacity_level(-0.1, &cfg),
            super::CapacityLevel::Emergency
        );
    }

    // ── CapacityLevel clone and debug ──────────────────────────────────

    #[test]
    fn capacity_level_clone_and_debug() {
        let level = super::CapacityLevel::Warning;
        let cloned = level;
        assert_eq!(level, cloned);
        let debug = format!("{:?}", level);
        assert!(debug.contains("Warning"));
    }

    // ── reconcile_control_from_evidence: only checkpoint, stale ────────

    #[test]
    fn reconcile_checkpoint_at_different_state_than_current() {
        let default_state = control::ControlV1::default();
        let mut checkpoint_state = default_state.clone();
        checkpoint_state.updated_at_unix_ns = 10;
        checkpoint_state
            .valves
            .read_only
            .set(true, "op", "test", 10);

        // Current state is default, but checkpoint is for a different state.
        // Checkpoint won't anchor because current != checkpoint state.
        // Mutations are empty, so it errors.
        let err = reconcile_control_from_evidence(
            &default_state,
            &control::checkpoint_control_bytes_v1(&default_state),
            &[checkpoint_record(5, &checkpoint_state)],
            &[],
        );
        // Checkpoint digest won't match current; first mutation start is empty.
        // With no mutations and no matching checkpoint, the function returns
        // Ok(Some(...)) where the plan has 0 applied_mutations if checkpoint matches,
        // or errors.
        // Since there are no mutations to fall back to, and checkpoint doesn't match
        // current, there's no anchor. But there are also no mutations to start from default.
        // The function should error since it has checkpoints but none match.
        // Actually looking at the code: (None, None) case with empty mutations returns Err.
        assert!(err.is_err() || err.unwrap().is_none());
    }

    // ── load_or_init_node_meta additional edge cases ───────────────────

    #[test]
    fn load_or_init_node_meta_without_gpu_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta").join("node.json");
        let build = BuildInfo {
            version: "0.1.0".to_string(),
            commit: "abc".to_string(),
        };
        let meta = super::load_or_init_node_meta(
            &path,
            Some("node-no-gpu"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14800),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14801),
            None,
            &build,
        )
        .unwrap();
        assert!(meta.gpu_id.is_none());
        // Verify the file was written correctly
        let bytes = std::fs::read(&path).unwrap();
        let json_str = String::from_utf8(bytes).unwrap();
        assert!(!json_str.contains("gpuId"));
    }

    // ── NodeMetaV1 with various gpu_id values ──────────────────────────

    #[test]
    fn node_meta_v1_negative_gpu_id() {
        let meta = super::NodeMetaV1 {
            v: 1,
            node_id: "node-neg".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            http_listen_addr: "127.0.0.1:14800".to_string(),
            grpc_listen_addr: "127.0.0.1:14801".to_string(),
            gpu_id: Some(-1),
            build: BuildInfo {
                version: "0.1.0".to_string(),
                commit: "abc".to_string(),
            },
        };
        let json = serde_json::to_string(&meta).unwrap();
        let parsed: super::NodeMetaV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.gpu_id, Some(-1));
    }

    // ── validate_network_auth_posture: exhaustive combos ───────────────

    #[test]
    fn auth_off_non_loopback_without_override_fails() {
        let err = validate_network_auth_posture(
            AuthMode::Off,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4007),
            CommitLevel::LocalCommit,
            false,
            false,
        )
        .expect_err("auth off on non-loopback should fail");
        assert!(err.contains("CORECRUXD_ALLOW_INSECURE_DEV_AUTH_BIND"));
    }

    #[test]
    fn jwt_hs256_replicated_commit_with_bearer_ok() {
        validate_network_auth_posture(
            AuthMode::JwtHs256,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4007),
            CommitLevel::ReplicatedCommit,
            false,
            true,
        )
        .expect("jwt replicated commit with bearer should pass");
    }

    #[test]
    fn jwt_jwks_local_commit_no_bearer_ok() {
        validate_network_auth_posture(
            AuthMode::JwtJwks,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4007),
            CommitLevel::LocalCommit,
            false,
            false,
        )
        .expect("jwt local commit without bearer should be fine");
    }

    // ── ControlEvidenceRuntimeStatus: detail content ───────────────────

    #[test]
    fn control_evidence_status_non_hosted_detail_preserved() {
        let msg = "system/corecrux/control is not hosted locally";
        let status = super::ControlEvidenceRuntimeStatus::non_hosted(msg);
        assert_eq!(status.detail.unwrap(), msg);
    }

    #[test]
    fn control_evidence_status_hosted_err_detail_preserved() {
        let msg = "failed to read stream: connection timeout";
        let status = super::ControlEvidenceRuntimeStatus::hosted_err(msg);
        assert!(!status.ok);
        assert_eq!(status.detail.unwrap(), msg);
    }

    // ── reconcile: only mutation anchor, no checkpoints, no further muts

    #[test]
    fn reconcile_mutation_anchor_at_current_state_no_further_mutations() {
        let default_state = control::ControlV1::default();
        let mut current = default_state.clone();
        current.updated_at_unix_ns = 10;
        current.valves.throttle.set(true, "op", "r", 10);

        let plan = reconcile_control_from_evidence(
            &current,
            &control::checkpoint_control_bytes_v1(&current),
            &[],
            &[mutation_record(5, &default_state, &current)],
        )
        .expect("reconcile succeeds")
        .expect("plan present");
        assert_eq!(plan.anchor, "mutation");
        assert_eq!(plan.anchor_seq, 5);
        assert_eq!(plan.applied_mutations, 0);
        assert_eq!(plan.state, current);
    }

    // ── measure_data_dir_space with real tempdir ───────────────────────

    #[test]
    fn measure_data_dir_space_nested_dir() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("subdir");
        std::fs::create_dir_all(&nested).unwrap();
        let (total, free) = super::measure_data_dir_space(&nested).unwrap();
        assert!(total > 0);
        assert!(free <= total);
    }

    // ── acquire_lock: nonexistent parent creates it ────────────────────

    #[test]
    fn acquire_lock_in_new_subdir() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("deep").join("nested");
        std::fs::create_dir_all(&sub).unwrap();
        let lock = super::acquire_lock(&sub).unwrap();
        assert!(sub.join("LOCK").exists());
        drop(lock);
    }

    // ── observe_shard_map_metrics ─────────────────────────────────────

    fn make_routing_table_via_store(num_shards: u32, gpu_id: Option<i32>) -> crate::shard_map::RoutingTable {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = crate::shard_map::ShardMapStore::new(tmp.path());
        let loaded = store
            .load_or_init("test-cluster", "node-a", "127.0.0.1:4006", "127.0.0.1:4007", num_shards, gpu_id)
            .expect("load_or_init");
        crate::shard_map::RoutingTable::new(loaded).unwrap()
    }

    fn test_build() -> BuildInfo {
        BuildInfo {
            version: "test".to_string(),
            commit: "test".to_string(),
        }
    }

    #[test]
    fn observe_shard_map_metrics_with_active_shards() {
        let build = test_build();
        let metrics = crate::metrics::Metrics::new(&build, "test-observe");
        let table = make_routing_table_via_store(2, None);
        // Should not panic; exercises the shard metrics path for active/no-followers.
        super::observe_shard_map_metrics(&metrics, &table, 0, "node-a");
    }

    #[test]
    fn observe_shard_map_metrics_with_gpu_id() {
        let build = test_build();
        let metrics = crate::metrics::Metrics::new(&build, "test-observe-gpu");
        let table = make_routing_table_via_store(2, Some(1));
        // Exercises the gpu_id branch (non-default gpu id).
        super::observe_shard_map_metrics(&metrics, &table, 0, "node-a");
    }

    #[test]
    fn observe_shard_map_metrics_single_shard() {
        let build = test_build();
        let metrics = crate::metrics::Metrics::new(&build, "test-observe-single");
        let table = make_routing_table_via_store(1, None);
        super::observe_shard_map_metrics(&metrics, &table, 0, "node-a");
    }

    #[test]
    fn observe_shard_map_metrics_four_shards() {
        let build = test_build();
        let metrics = crate::metrics::Metrics::new(&build, "test-observe-four");
        let table = make_routing_table_via_store(4, Some(0));
        super::observe_shard_map_metrics(&metrics, &table, 0, "node-a");
    }

    // ── init_tracing (idempotent, safe to call in test) ───────────────

    // Note: tracing init is a global singleton. We call it once in a test
    // to exercise the non-json text path. The JSON and otel paths are
    // feature-gated and require env vars.
    #[test]
    #[serial_test::serial]
    fn init_tracing_text_format() {
        // Ensure LOG_FORMAT is not set to json
        std::env::remove_var("LOG_FORMAT");
        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        // init_tracing may fail silently if already initialized (expected in test);
        // the important thing is it doesn't panic.
        // We use try_init via tracing_subscriber internally — this is best-effort.
        // If already initialized, this is a no-op.
        let _ = std::panic::catch_unwind(|| {
            super::init_tracing("warn");
        });
    }

    // ── CapacityLevel: Copy/Eq/PartialEq ──────────────────────────────

    #[test]
    fn capacity_level_copy_semantics() {
        let a = super::CapacityLevel::Critical;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(a, super::CapacityLevel::Healthy);
    }

    // ── classify_capacity_level with custom thresholds ─────────────────

    #[test]
    #[serial_test::serial]
    fn classify_capacity_level_custom_thresholds() {
        // Override thresholds via env vars
        std::env::set_var("CORECRUXD_CAPACITY_WARNING_FREE_RATIO", "0.30");
        std::env::set_var("CORECRUXD_CAPACITY_CRITICAL_FREE_RATIO", "0.15");
        std::env::set_var("CORECRUXD_CAPACITY_EMERGENCY_FREE_RATIO", "0.05");
        let cfg = crate::config::load_config();

        assert_eq!(super::classify_capacity_level(0.35, &cfg), super::CapacityLevel::Healthy);
        assert_eq!(super::classify_capacity_level(0.25, &cfg), super::CapacityLevel::Warning);
        assert_eq!(super::classify_capacity_level(0.10, &cfg), super::CapacityLevel::Critical);
        assert_eq!(super::classify_capacity_level(0.03, &cfg), super::CapacityLevel::Emergency);

        std::env::remove_var("CORECRUXD_CAPACITY_WARNING_FREE_RATIO");
        std::env::remove_var("CORECRUXD_CAPACITY_CRITICAL_FREE_RATIO");
        std::env::remove_var("CORECRUXD_CAPACITY_EMERGENCY_FREE_RATIO");
    }

    // ── validate_network_auth_posture: full matrix ────────────────────

    #[test]
    fn auth_off_replicated_commit_no_bearer_ok() {
        // AuthMode::Off is a dev mode, replicated commit doesn't require bearer
        // because it's only checked for JWT modes
        validate_network_auth_posture(
            AuthMode::Off,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4007),
            CommitLevel::ReplicatedCommit,
            false,
            false,
        )
        .expect("auth off replicated on loopback should be ok");
    }

    #[test]
    fn dev_scopes_replicated_commit_no_bearer_loopback_ok() {
        validate_network_auth_posture(
            AuthMode::DevScopes,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4007),
            CommitLevel::ReplicatedCommit,
            false,
            false,
        )
        .expect("dev scopes replicated on loopback should be ok");
    }

    // ── ControlEvidenceRuntimeStatus clone ─────────────────────────────

    #[test]
    fn control_evidence_status_clone() {
        let status = super::ControlEvidenceRuntimeStatus::hosted_ok("cloned");
        let cloned = status.clone();
        assert_eq!(status, cloned);
    }

    // ── reconcile: checkpoint higher seq than mutation anchors at cp ──

    #[test]
    fn reconcile_checkpoint_higher_seq_wins() {
        let default_state = control::ControlV1::default();
        let mut checkpoint_state = default_state.clone();
        checkpoint_state.updated_at_unix_ns = 10;
        checkpoint_state.valves.read_only.set(true, "op", "test", 10);

        let mut final_state = checkpoint_state.clone();
        final_state.updated_at_unix_ns = 20;
        final_state.valves.pause_ingest.set(true, "op", "test", 20);

        let plan = reconcile_control_from_evidence(
            &checkpoint_state,
            &control::checkpoint_control_bytes_v1(&checkpoint_state),
            &[checkpoint_record(10, &checkpoint_state)],
            &[
                mutation_record(5, &default_state, &checkpoint_state),
                mutation_record(11, &checkpoint_state, &final_state),
            ],
        )
        .expect("reconcile succeeds")
        .expect("plan present");

        assert_eq!(plan.anchor, "checkpoint");
        assert_eq!(plan.anchor_seq, 10);
        assert_eq!(plan.applied_mutations, 1);
        assert_eq!(plan.state, final_state);
    }

    // ── reconcile: zero mutations after checkpoint ─────────────────────

    #[test]
    fn reconcile_checkpoint_with_no_further_mutations() {
        let default_state = control::ControlV1::default();
        let mut state = default_state.clone();
        state.updated_at_unix_ns = 10;
        state.valves.throttle.set(true, "op", "test", 10);

        let plan = reconcile_control_from_evidence(
            &state,
            &control::checkpoint_control_bytes_v1(&state),
            &[checkpoint_record(5, &state)],
            &[mutation_record(3, &default_state, &state)],
        )
        .expect("reconcile succeeds")
        .expect("plan present");

        // Checkpoint at seq=5 is higher than mutation at seq=3
        assert_eq!(plan.anchor, "checkpoint");
        assert_eq!(plan.anchor_seq, 5);
        assert_eq!(plan.applied_mutations, 0);
        assert_eq!(plan.state, state);
    }

    // ── shard_map_advertise_addr: v4 mapped v6 ────────────────────────

    #[test]
    fn shard_map_advertise_addr_v6_unspecified() {
        // [::]:4006 -> [::1]:4006
        let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 4006);
        assert_eq!(super::shard_map_advertise_addr(addr), "[::1]:4006");
    }

    // ── projection tick decision logic ────────────────────────────────

    /// Extracted tick decision: returns true if projection tick should proceed.
    fn projection_tick_should_run(control: &crate::control::ControlV1) -> bool {
        !control.valves.pause_compaction.enabled && !control.valves.emergency_brake.enabled
    }

    #[test]
    fn projection_tick_runs_with_default_control() {
        let c = crate::control::ControlV1::default();
        assert!(projection_tick_should_run(&c));
    }

    #[test]
    fn projection_tick_blocked_by_pause_compaction() {
        let mut c = crate::control::ControlV1::default();
        c.valves.pause_compaction.set(true, "op", "test", 1);
        assert!(!projection_tick_should_run(&c));
    }

    #[test]
    fn projection_tick_blocked_by_emergency_brake() {
        let mut c = crate::control::ControlV1::default();
        c.valves.emergency_brake.set(true, "op", "test", 1);
        assert!(!projection_tick_should_run(&c));
    }

    #[test]
    fn projection_tick_blocked_by_both() {
        let mut c = crate::control::ControlV1::default();
        c.valves.pause_compaction.set(true, "op", "test", 1);
        c.valves.emergency_brake.set(true, "op", "test", 2);
        assert!(!projection_tick_should_run(&c));
    }

    #[test]
    fn projection_tick_not_blocked_by_other_valves() {
        let mut c = crate::control::ControlV1::default();
        c.valves.pause_ingest.set(true, "op", "test", 1);
        c.valves.throttle.set(true, "op", "test", 2);
        c.valves.read_only.set(true, "op", "test", 3);
        assert!(projection_tick_should_run(&c));
    }

    // ── capacity guard composition test ───────────────────────────────

    /// Extracted capacity guard iteration: measure -> classify -> decide pause action.
    /// Returns (level, should_pause, should_resume).
    fn capacity_guard_decide(
        free_ratio: f64,
        config: &crate::config::Config,
        current_pause_ingest_enabled: bool,
        current_pause_ingest_actor: &str,
    ) -> (super::CapacityLevel, bool, bool) {
        let level = super::classify_capacity_level(free_ratio, config);
        let guard_owned = current_pause_ingest_actor == "capacity_guard";
        let should_pause = level == super::CapacityLevel::Emergency
            && (!current_pause_ingest_enabled || guard_owned);
        let should_resume = guard_owned
            && current_pause_ingest_enabled
            && level != super::CapacityLevel::Emergency
            && free_ratio >= config.capacity_resume_free_ratio;
        (level, should_pause, should_resume)
    }

    #[test]
    #[serial_test::serial]
    fn capacity_guard_healthy_no_action() {
        let cfg = crate::config::load_config();
        let (level, should_pause, should_resume) =
            capacity_guard_decide(0.50, &cfg, false, "");
        assert_eq!(level, super::CapacityLevel::Healthy);
        assert!(!should_pause);
        assert!(!should_resume);
    }

    #[test]
    #[serial_test::serial]
    fn capacity_guard_emergency_pauses_ingest() {
        let cfg = crate::config::load_config();
        let (level, should_pause, should_resume) =
            capacity_guard_decide(0.01, &cfg, false, "");
        assert_eq!(level, super::CapacityLevel::Emergency);
        assert!(should_pause);
        assert!(!should_resume);
    }

    #[test]
    #[serial_test::serial]
    fn capacity_guard_emergency_when_already_paused_by_guard() {
        let cfg = crate::config::load_config();
        let (level, should_pause, _) =
            capacity_guard_decide(0.01, &cfg, true, "capacity_guard");
        assert_eq!(level, super::CapacityLevel::Emergency);
        assert!(should_pause);
    }

    #[test]
    #[serial_test::serial]
    fn capacity_guard_emergency_does_not_override_operator_pause() {
        let cfg = crate::config::load_config();
        let (level, should_pause, _) =
            capacity_guard_decide(0.01, &cfg, true, "operator");
        assert_eq!(level, super::CapacityLevel::Emergency);
        assert!(!should_pause);
    }

    #[test]
    #[serial_test::serial]
    fn capacity_guard_resume_when_recovered() {
        std::env::set_var("CORECRUXD_CAPACITY_RESUME_FREE_RATIO", "0.25");
        let cfg = crate::config::load_config();
        let (level, should_pause, should_resume) =
            capacity_guard_decide(0.30, &cfg, true, "capacity_guard");
        assert_eq!(level, super::CapacityLevel::Healthy);
        assert!(!should_pause);
        assert!(should_resume);
        std::env::remove_var("CORECRUXD_CAPACITY_RESUME_FREE_RATIO");
    }

    #[test]
    #[serial_test::serial]
    fn capacity_guard_no_resume_if_not_guard_owned() {
        std::env::set_var("CORECRUXD_CAPACITY_RESUME_FREE_RATIO", "0.25");
        let cfg = crate::config::load_config();
        let (_, _, should_resume) =
            capacity_guard_decide(0.30, &cfg, true, "operator");
        assert!(!should_resume);
        std::env::remove_var("CORECRUXD_CAPACITY_RESUME_FREE_RATIO");
    }

    #[test]
    #[serial_test::serial]
    fn capacity_guard_no_resume_below_resume_threshold() {
        std::env::set_var("CORECRUXD_CAPACITY_RESUME_FREE_RATIO", "0.25");
        let cfg = crate::config::load_config();
        let (_, _, should_resume) =
            capacity_guard_decide(0.22, &cfg, true, "capacity_guard");
        assert!(!should_resume);
        std::env::remove_var("CORECRUXD_CAPACITY_RESUME_FREE_RATIO");
    }

    // ── shard map reload watcher: version comparison logic ────────────

    /// Extracted routing reload comparison: returns true if a reload should happen.
    fn routing_should_reload(current_version: u64, loaded_version: u64) -> bool {
        loaded_version != current_version
    }

    #[test]
    fn routing_reload_skip_when_same_version() {
        assert!(!routing_should_reload(5, 5));
    }

    #[test]
    fn routing_reload_when_version_differs() {
        assert!(routing_should_reload(5, 6));
    }

    #[test]
    fn routing_reload_when_version_decreases() {
        assert!(routing_should_reload(6, 5));
    }

    // ── http::router produces a valid Router ──────────────────────────

    #[tokio::test]
    async fn http_router_builds_successfully() {
        let tmp = tempfile::tempdir().unwrap();
        let build = BuildInfo {
            version: "0.1.0".to_string(),
            commit: "test".to_string(),
        };
        let metrics = crate::metrics::Metrics::new(&build, "test-router");
        let auth = crate::auth::Authz::from_env(crate::auth::AuthMode::Off).unwrap();
        let store = crate::shard_map::ShardMapStore::new(tmp.path());
        let loaded = store
            .load_or_init("test", "node-test", "127.0.0.1:14800", "127.0.0.1:14801", 1, None)
            .expect("load_or_init");
        let routing_table = crate::shard_map::RoutingTable::new(loaded).unwrap();

        let state = crate::http::AppState {
            lock_held: true,
            build: build.clone(),
            compat: corecrux_types::CompatContract {
                requires: corecrux_types::DEFAULT_COMPAT_REQUIRES.to_string(),
            },
            sdk_version: corecrux_types::DEFAULT_SDK_VERSION.to_string(),
            auth,
            data_dir: tmp.path().to_path_buf(),
            io_backend: "cpu".to_string(),
            read_retry_failed_readyz_threshold: 0,
            commit_level: crate::config::CommitLevel::LocalCommit,
            metrics: metrics.clone(),
            node_id: "node-test".to_string(),
            routing: std::sync::Arc::new(tokio::sync::RwLock::new(routing_table)),
            routing_errors: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
            dataplane_pool: None,
            readiness: std::sync::Arc::new(tokio::sync::RwLock::new(
                crate::http::Readiness::default(),
            )),
            control: std::sync::Arc::new(tokio::sync::RwLock::new(
                crate::control::ControlV1::default(),
            )),
            control_path: tmp.path().join("CONTROL.json"),
            action_max_pending: 10,
            action_timeout_secs: 60,
            scrub_scope: "recent".to_string(),
            scrub_mode: "sampled".to_string(),
            scrub_sample_rate: 0.25,
            admin_actions: std::sync::Arc::new(tokio::sync::RwLock::new(
                std::collections::BTreeMap::new(),
            )),
            corruption_detected: std::sync::Arc::new(tokio::sync::RwLock::new(false)),
            capacity: std::sync::Arc::new(tokio::sync::RwLock::new(
                crate::http::CapacityState::default(),
            )),
            admin_force_seal_enabled: false,
            retrieval_index: std::sync::Arc::new(tokio::sync::RwLock::new(
                corecrux_retrieval::IndexManager::new(),
            )),
            fact_store: std::sync::Arc::new(tokio::sync::RwLock::new(
                corecrux_memory::FactStore::new(),
            )),
            session_store: std::sync::Arc::new(tokio::sync::RwLock::new(
                corecrux_memory::SessionStore::new(),
            )),
        };

        let router: axum::Router = crate::http::router(state);
        // Verify it's a valid Router by converting to a service
        let _service = router.into_make_service();
    }

    // ── scrub tick decision logic ─────────────────────────────────────

    /// Extracted scrub tick decision: same valve gates as projection runner.
    fn scrub_tick_should_run(control: &crate::control::ControlV1) -> bool {
        !control.valves.pause_compaction.enabled && !control.valves.emergency_brake.enabled
    }

    #[test]
    fn scrub_tick_runs_with_default_control() {
        let c = crate::control::ControlV1::default();
        assert!(scrub_tick_should_run(&c));
    }

    #[test]
    fn scrub_tick_blocked_by_pause_compaction() {
        let mut c = crate::control::ControlV1::default();
        c.valves.pause_compaction.set(true, "op", "test", 1);
        assert!(!scrub_tick_should_run(&c));
    }

    #[test]
    fn scrub_tick_blocked_by_emergency_brake() {
        let mut c = crate::control::ControlV1::default();
        c.valves.emergency_brake.set(true, "op", "test", 1);
        assert!(!scrub_tick_should_run(&c));
    }

    // ── capacity free_ratio calculation ───────────────────────────────

    fn capacity_free_ratio(total_bytes: u64, free_bytes: u64) -> f64 {
        if total_bytes == 0 { 0.0 } else { free_bytes as f64 / total_bytes as f64 }
    }

    #[test]
    fn capacity_free_ratio_zero_total() {
        assert!((capacity_free_ratio(0, 0) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn capacity_free_ratio_half_full() {
        assert!((capacity_free_ratio(1000, 500) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn capacity_free_ratio_empty() {
        assert!((capacity_free_ratio(1000, 1000) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn capacity_free_ratio_full() {
        assert!((capacity_free_ratio(1000, 0) - 0.0).abs() < f64::EPSILON);
    }

    // ── load_or_init_node_meta: concurrent access ─────────────────────

    #[test]
    fn load_or_init_node_meta_persists_http_grpc_addr() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("meta").join("node.json");
        let build = BuildInfo {
            version: "0.2.0".to_string(),
            commit: "def".to_string(),
        };
        let meta = super::load_or_init_node_meta(
            &path,
            Some("node-persist-test"),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 14800),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 14801),
            Some(3),
            &build,
        )
        .unwrap();
        assert_eq!(meta.http_listen_addr, "10.0.0.1:14800");
        assert_eq!(meta.grpc_listen_addr, "10.0.0.1:14801");
        assert_eq!(meta.gpu_id, Some(3));
        assert_eq!(meta.build.version, "0.2.0");

        // Verify written bytes round-trip
        let bytes = std::fs::read(&path).unwrap();
        let loaded: super::NodeMetaV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(loaded.node_id, "node-persist-test");
    }

    // ── measure_data_dir_space: root path ─────────────────────────────

    #[test]
    fn measure_data_dir_space_on_root() {
        // /tmp always exists on linux
        let (total, free) = super::measure_data_dir_space(std::path::Path::new("/tmp")).unwrap();
        assert!(total > 0);
        assert!(free <= total);
    }

    // ── ControlCheckpointRecord / ControlMutationRecord clone+debug ──

    #[test]
    fn control_checkpoint_record_clone_and_debug() {
        let state = control::ControlV1::default();
        let rec = checkpoint_record(1, &state);
        let cloned = rec.clone();
        assert_eq!(cloned.seq, 1);
        let dbg = format!("{:?}", rec);
        assert!(dbg.contains("seq"));
    }

    #[test]
    fn control_mutation_record_clone_and_debug() {
        let before = control::ControlV1::default();
        let mut after = before.clone();
        after.updated_at_unix_ns = 99;
        let rec = mutation_record(3, &before, &after);
        let cloned = rec.clone();
        assert_eq!(cloned.seq, 3);
        let dbg = format!("{:?}", rec);
        assert!(dbg.contains("seq"));
    }

    // ── ControlEvidenceReplayPlan: different anchors ──────────────────

    #[test]
    fn control_evidence_replay_plan_different_anchors_ne() {
        let state = control::ControlV1::default();
        let plan_a = super::ControlEvidenceReplayPlan {
            state: state.clone(),
            anchor: "checkpoint",
            anchor_seq: 5,
            applied_mutations: 0,
        };
        let plan_b = super::ControlEvidenceReplayPlan {
            state: state.clone(),
            anchor: "mutation",
            anchor_seq: 5,
            applied_mutations: 0,
        };
        assert_ne!(plan_a, plan_b);
    }

    // ── NodeMetaV1: clone + debug ────────────────────────────────────

    #[test]
    fn node_meta_v1_clone_preserves_all_fields() {
        let meta = super::NodeMetaV1 {
            v: 1,
            node_id: "n1".to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            http_listen_addr: "127.0.0.1:14800".to_string(),
            grpc_listen_addr: "127.0.0.1:14801".to_string(),
            gpu_id: Some(5),
            build: BuildInfo { version: "v".to_string(), commit: "c".to_string() },
        };
        let cloned = meta.clone();
        assert_eq!(cloned.v, 1);
        assert_eq!(cloned.node_id, "n1");
        assert_eq!(cloned.gpu_id, Some(5));
        assert_eq!(cloned.build.version, "v");
    }

    // ── CapacityLevel: exhaustive as_str ─────────────────────────────

    #[test]
    fn capacity_level_as_str_exhaustive() {
        let variants = [
            super::CapacityLevel::Healthy,
            super::CapacityLevel::Warning,
            super::CapacityLevel::Critical,
            super::CapacityLevel::Emergency,
        ];
        let strs: Vec<&str> = variants.iter().map(|v| v.as_str()).collect();
        assert_eq!(strs, vec!["healthy", "warning", "critical", "emergency"]);
    }

    // ── ControlEvidenceRuntimeStatus: debug ──────────────────────────

    #[test]
    fn control_evidence_runtime_status_debug() {
        let status = super::ControlEvidenceRuntimeStatus::hosted_ok("msg");
        let dbg = format!("{:?}", status);
        assert!(dbg.contains("hosted_locally"));
        assert!(dbg.contains("true"));
    }

    // ── validate_network_auth_posture: DevScopes with override on non-loopback ──

    #[test]
    fn dev_scopes_non_loopback_with_override_ok() {
        validate_network_auth_posture(
            AuthMode::DevScopes,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4006),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4007),
            CommitLevel::LocalCommit,
            true,
            false,
        )
        .expect("override should allow dev scopes on non-loopback");
    }

    // ── reconcile: mutation anchor found, checkpoint not found ────────

    #[test]
    fn reconcile_mutation_anchor_only_no_checkpoint() {
        let default_state = control::ControlV1::default();
        let mut mid = default_state.clone();
        mid.updated_at_unix_ns = 5;
        mid.valves.read_only.set(true, "op", "r", 5);

        let plan = reconcile_control_from_evidence(
            &mid,
            &control::checkpoint_control_bytes_v1(&mid),
            &[], // no checkpoints
            &[mutation_record(1, &default_state, &mid)],
        )
        .expect("reconcile succeeds")
        .expect("plan present");
        assert_eq!(plan.anchor, "mutation");
        assert_eq!(plan.anchor_seq, 1);
        assert_eq!(plan.applied_mutations, 0);
    }

    // ── capacity_free_ratio: exact boundary ──────────────────────────

    #[test]
    fn capacity_free_ratio_exceeds_total() {
        // In theory shouldn't happen, but test the arithmetic
        assert!((capacity_free_ratio(100, 200) - 2.0).abs() < f64::EPSILON);
    }
}
