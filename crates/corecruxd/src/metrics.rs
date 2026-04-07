// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::sync::Arc;

use prometheus::{Counter, CounterVec, Encoder, Gauge, GaugeVec, Histogram, HistogramVec, Registry, TextEncoder};

use corecrux_types::{
    BuildInfo, KnowledgeAuthorityModeV1, KnowledgeAuthorityV1, KnowledgeParityOutcomeV1, KnowledgeParityStatusV1,
    KnowledgeRolloutStageV1,
};

// Some metric fields are registered at init but only exercised in the
// proprietary edition. Suppress dead-code warnings for the struct+impl.
#[allow(dead_code)]
#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Registry>,
    io_backend: GaugeVec,
    valve_pause_ingest: Gauge,
    valve_pause_compaction: Gauge,
    valve_throttle: Gauge,
    valve_read_only: Gauge,
    valve_emergency_brake: Gauge,
    valve_state: GaugeVec,
    throttle_ratio: Gauge,
    data_dir_bytes_total: Gauge,
    data_dir_bytes_free: Gauge,
    data_dir_free_ratio: Gauge,
    write_confirmations_total: CounterVec,
    write_confirmation_sign_duration_ms: Histogram,
    write_confirmation_unsigned_queue_depth: Gauge,
    tenant_throttle_rejected_total: CounterVec,
    emergency_brake_total: CounterVec,
    write_rejects_total: CounterVec,
    backpressure_active_gauge: Gauge,
    replay_total: CounterVec,
    replay_mismatch_total: CounterVec,
    segment_corrupt_total: CounterVec,
    verify_store_seconds: Histogram,
    segment_scrub_seconds: Histogram,

    dir_l0_runs: GaugeVec,
    dir_level_bytes: GaugeVec,
    dir_compactions_total: CounterVec,
    dir_compaction_seconds: HistogramVec,
    dir_compaction_bytes_in_total: CounterVec,
    dir_compaction_bytes_out_total: CounterVec,
    dir_dead_extent_ratio: GaugeVec,

    checkpoints_installed_total: CounterVec,
    checkpoint_min_live_seq: GaugeVec,
    stream_tombstones_total: CounterVec,
    stream_tombstone_rejects_total: CounterVec,

    append_latency_seconds: HistogramVec,
    stream_read_latency_seconds: HistogramVec,
    read_retry_total: CounterVec,
    store_lock_wait_seconds: HistogramVec,
    store_lock_hold_seconds: HistogramVec,
    store_service_seconds: HistogramVec,
    append_lane_waiters: Gauge,
    append_lane_waiters_peak: Gauge,
    append_lane_queue_depth: Histogram,
    append_lane_selected_total: CounterVec,
    append_lane_wait_seconds_by_bucket: HistogramVec,
    grpc_messages_sent_total: CounterVec,
    grpc_send_seconds: HistogramVec,
    grpc_send_blocked_seconds: HistogramVec,
    replay_events_total: CounterVec,
    replay_bytes_total: CounterVec,
    replay_build_response_seconds: HistogramVec,
    replay_encode_seconds: HistogramVec,
    rpc_total_seconds: HistogramVec,
    storage_tail_stage_seconds: HistogramVec,
    storage_append_stage_seconds: HistogramVec,
    append_fence_wait_seconds: HistogramVec,
    append_fence_fsync_seconds: HistogramVec,
    storage_tail_bytes_total: CounterVec,
    storage_tail_items_total: CounterVec,
    storage_tail_path_total: CounterVec,
    storage_head_frames_scanned_total: Counter,

    read_amplification_p50: GaugeVec,
    read_amplification_p95: GaugeVec,

    kernel_launch_total: CounterVec,
    shardmap_version: Gauge,
    routing_lookup_total: CounterVec,
    routing_lookup_seconds: HistogramVec,
    shard_requests_total: CounterVec,
    replication_receive_total: CounterVec,
    replication_follower_watermark: GaugeVec,
    replicated_commit_total: CounterVec,
    replicated_commit_required_acks: GaugeVec,
    replicated_commit_actual_acks: GaugeVec,
    replicated_commit_ack_deficit: GaugeVec,
    replication_shard_epoch: GaugeVec,
    replication_follower_targets: GaugeVec,
    replication_topology_ok: GaugeVec,
    replication_leader_segment_seq: GaugeVec,
    replication_min_follower_acked_segment_seq: GaugeVec,
    replication_lag_segments: GaugeVec,

    shard_state: GaugeVec,

    peer_cache_hits_total: Counter,
    peer_cache_misses_total: Counter,
    peer_cache_bytes: Gauge,
    tail_cache_hits_total: CounterVec,
    tail_cache_misses_total: CounterVec,
    tail_cache_bytes: GaugeVec,

    projections_commit_id: GaugeVec,
    projections_cursor_segment_seq: GaugeVec,
    projections_cursor_offset: GaugeVec,
    projections_row_count: GaugeVec,
    projections_tick_frames_total: CounterVec,
    projections_tick_seconds: HistogramVec,
    projections_tick_fail_total: CounterVec,
    shard_open_attempts_total: CounterVec,
    lock_contention_total: CounterVec,
    projection_snapshot_valid: GaugeVec,
    knowledge_authority_mode: GaugeVec,
    knowledge_rollout_stage: GaugeVec,
    knowledge_parity_status: GaugeVec,
    knowledge_rollback_triggered: Gauge,
    knowledge_parity_mismatch_count: Gauge,
    knowledge_parity_cursor_missing_count: Gauge,
    knowledge_parity_pass_ratio_bps: Gauge,
    knowledge_parity_projection_lag_ms: Gauge,

    receipt_verify_total: CounterVec,
    receipt_verify_fail_total: CounterVec,
    receipt_export_total: CounterVec,

    // ── v4.2 query metrics ───────────────────────────────────────────
    query_graph_expand_duration_seconds: Histogram,
    query_graph_expand_nodes_visited: Histogram,
    query_time_range_duration_seconds: Histogram,
    query_time_range_artifacts_scanned: Histogram,

    // ── v5 seal + retrieval metrics ─────────────────────────────────
    seal_duration_seconds: HistogramVec,
    seal_backlog_frames: Gauge,
    ccxi_missing_total: Gauge,
}

#[allow(dead_code)] // See struct-level comment above.
impl Metrics {
    pub fn new(build: &BuildInfo, service: &str) -> Self {
        let registry = Arc::new(Registry::new());

        let build_info = GaugeVec::new(
            prometheus::Opts::new("build_info", "Build metadata for CoreCrux v3"),
            &["version", "commit", "service"],
        )
        .expect("build_info gauge");

        build_info
            .with_label_values(&[&build.version, &build.commit, service])
            .set(1.0);

        registry
            .register(Box::new(build_info.clone()))
            .expect("register build_info");

        let corecrux_build_info = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_build_info",
                "Build metadata for CoreCrux v3.1 hardening contract",
            ),
            &["version", "commit", "service", "sdkVersion"],
        )
        .expect("corecrux_build_info gauge");
        corecrux_build_info
            .with_label_values(&[
                &build.version,
                &build.commit,
                service,
                corecrux_types::DEFAULT_SDK_VERSION,
            ])
            .set(1.0);
        registry
            .register(Box::new(corecrux_build_info.clone()))
            .expect("register corecrux_build_info");

        let io_backend = GaugeVec::new(
            prometheus::Opts::new("corecrux_io_backend", "Selected IO backend (label backend=...)"),
            &["backend"],
        )
        .expect("corecrux_io_backend gauge");
        registry
            .register(Box::new(io_backend.clone()))
            .expect("register corecrux_io_backend");

        let peer_cache_hits_total = Counter::new(
            "corecrux_peer_cache_hits_total",
            "Peer cache hits (sealed immutable blocks only)",
        )
        .expect("corecrux_peer_cache_hits_total counter");
        registry
            .register(Box::new(peer_cache_hits_total.clone()))
            .expect("register corecrux_peer_cache_hits_total");

        let peer_cache_misses_total = Counter::new(
            "corecrux_peer_cache_misses_total",
            "Peer cache misses (sealed immutable blocks only)",
        )
        .expect("corecrux_peer_cache_misses_total counter");
        registry
            .register(Box::new(peer_cache_misses_total.clone()))
            .expect("register corecrux_peer_cache_misses_total");

        let peer_cache_bytes = Gauge::new(
            "corecrux_peer_cache_bytes",
            "Peer cache size in bytes (best-effort, non-correctness-critical)",
        )
        .expect("corecrux_peer_cache_bytes gauge");
        registry
            .register(Box::new(peer_cache_bytes.clone()))
            .expect("register corecrux_peer_cache_bytes");

        let tail_cache_hits_total = CounterVec::new(
            prometheus::Opts::new("corecrux_tail_cache_hits_total", "Tail cache hits by shard"),
            &["shard"],
        )
        .expect("corecrux_tail_cache_hits_total counter");
        registry
            .register(Box::new(tail_cache_hits_total.clone()))
            .expect("register corecrux_tail_cache_hits_total");

        let tail_cache_misses_total = CounterVec::new(
            prometheus::Opts::new("corecrux_tail_cache_misses_total", "Tail cache misses by shard"),
            &["shard"],
        )
        .expect("corecrux_tail_cache_misses_total counter");
        registry
            .register(Box::new(tail_cache_misses_total.clone()))
            .expect("register corecrux_tail_cache_misses_total");

        let tail_cache_bytes = GaugeVec::new(
            prometheus::Opts::new("corecrux_tail_cache_bytes", "Tail cache resident bytes by shard"),
            &["shard"],
        )
        .expect("corecrux_tail_cache_bytes gauge");
        registry
            .register(Box::new(tail_cache_bytes.clone()))
            .expect("register corecrux_tail_cache_bytes");

        let valve_pause_ingest = Gauge::new("corecrux_valve_pause_ingest", "Operator valve: pause_ingest (0/1)")
            .expect("corecrux_valve_pause_ingest gauge");
        registry
            .register(Box::new(valve_pause_ingest.clone()))
            .expect("register corecrux_valve_pause_ingest");

        let valve_pause_compaction = Gauge::new(
            "corecrux_valve_pause_compaction",
            "Operator valve: pause_compaction (0/1)",
        )
        .expect("corecrux_valve_pause_compaction gauge");
        registry
            .register(Box::new(valve_pause_compaction.clone()))
            .expect("register corecrux_valve_pause_compaction");

        let valve_throttle = Gauge::new("corecrux_valve_throttle", "Operator valve: throttle (0/1)")
            .expect("corecrux_valve_throttle gauge");
        registry
            .register(Box::new(valve_throttle.clone()))
            .expect("register corecrux_valve_throttle");

        let valve_read_only = Gauge::new("corecrux_valve_read_only", "Operator valve: read_only (0/1)")
            .expect("corecrux_valve_read_only gauge");
        registry
            .register(Box::new(valve_read_only.clone()))
            .expect("register corecrux_valve_read_only");

        let valve_emergency_brake = Gauge::new(
            "corecrux_valve_emergency_brake",
            "Operator valve: emergency_brake (0/1)",
        )
        .expect("corecrux_valve_emergency_brake gauge");
        registry
            .register(Box::new(valve_emergency_brake.clone()))
            .expect("register corecrux_valve_emergency_brake");

        let valve_state = GaugeVec::new(
            prometheus::Opts::new("corecrux_valve_state", "Operator valve state (0/1)"),
            &["valve"],
        )
        .expect("corecrux_valve_state gauge");
        registry
            .register(Box::new(valve_state.clone()))
            .expect("register corecrux_valve_state");

        let throttle_ratio = Gauge::new(
            "corecrux_throttle_ratio",
            "Throttle pressure / token bucket fullness (0..=1; 1 means no throttle pressure)",
        )
        .expect("corecrux_throttle_ratio gauge");
        registry
            .register(Box::new(throttle_ratio.clone()))
            .expect("register corecrux_throttle_ratio");

        let data_dir_bytes_total = Gauge::new("corecrux_data_dir_bytes_total", "Configured data directory total bytes")
            .expect("corecrux_data_dir_bytes_total gauge");
        registry
            .register(Box::new(data_dir_bytes_total.clone()))
            .expect("register corecrux_data_dir_bytes_total");

        let data_dir_bytes_free = Gauge::new("corecrux_data_dir_bytes_free", "Configured data directory free bytes")
            .expect("corecrux_data_dir_bytes_free gauge");
        registry
            .register(Box::new(data_dir_bytes_free.clone()))
            .expect("register corecrux_data_dir_bytes_free");

        let data_dir_free_ratio = Gauge::new("corecrux_data_dir_free_ratio", "Configured data directory free ratio")
            .expect("corecrux_data_dir_free_ratio gauge");
        registry
            .register(Box::new(data_dir_free_ratio.clone()))
            .expect("register corecrux_data_dir_free_ratio");

        let write_confirmations_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_write_confirmations_total",
                "AppendBatch write confirmations emitted by signed state",
            ),
            &["signed"],
        )
        .expect("corecrux_write_confirmations_total counter");
        registry
            .register(Box::new(write_confirmations_total.clone()))
            .expect("register corecrux_write_confirmations_total");

        let write_confirmation_sign_duration_ms = Histogram::with_opts(prometheus::HistogramOpts::new(
            "corecrux_write_confirmation_sign_duration_ms",
            "Write confirmation signing latency in milliseconds",
        ))
        .expect("corecrux_write_confirmation_sign_duration_ms histogram");
        registry
            .register(Box::new(write_confirmation_sign_duration_ms.clone()))
            .expect("register corecrux_write_confirmation_sign_duration_ms");

        let write_confirmation_unsigned_queue_depth = Gauge::new(
            "corecrux_write_confirmation_unsigned_queue_depth",
            "Unsigned write confirmations pending re-sign",
        )
        .expect("corecrux_write_confirmation_unsigned_queue_depth gauge");
        registry
            .register(Box::new(write_confirmation_unsigned_queue_depth.clone()))
            .expect("register corecrux_write_confirmation_unsigned_queue_depth");

        let tenant_throttle_rejected_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_tenant_throttle_rejected_total",
                "Tenant throttle rejections keyed by hashed tenant id",
            ),
            &["tenant_id_hash"],
        )
        .expect("corecrux_tenant_throttle_rejected_total counter");
        registry
            .register(Box::new(tenant_throttle_rejected_total.clone()))
            .expect("register corecrux_tenant_throttle_rejected_total");

        let emergency_brake_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_emergency_brake_total",
                "Emergency brake activations (low-cardinality source label)",
            ),
            &["source"],
        )
        .expect("corecrux_emergency_brake_total counter");
        registry
            .register(Box::new(emergency_brake_total.clone()))
            .expect("register corecrux_emergency_brake_total");

        let write_rejects_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_write_rejects_total",
                "Write rejects by reason (low-cardinality)",
            ),
            &["reason"],
        )
        .expect("corecrux_write_rejects_total counter");
        registry
            .register(Box::new(write_rejects_total.clone()))
            .expect("register corecrux_write_rejects_total");

        let backpressure_active_gauge =
            Gauge::new("corecrux_backpressure_active_gauge", "Backpressure active state (0/1)")
                .expect("corecrux_backpressure_active_gauge gauge");
        registry
            .register(Box::new(backpressure_active_gauge.clone()))
            .expect("register corecrux_backpressure_active_gauge");

        let replay_total = CounterVec::new(
            prometheus::Opts::new("corecrux_replay_total", "Replay attempts by result (ok|fail)"),
            &["result"],
        )
        .expect("corecrux_replay_total counter");
        registry
            .register(Box::new(replay_total.clone()))
            .expect("register corecrux_replay_total");

        let replay_mismatch_total = CounterVec::new(
            prometheus::Opts::new("corecrux_replay_mismatch_total", "Replay mismatches by drift class"),
            &["drift_class"],
        )
        .expect("corecrux_replay_mismatch_total counter");
        registry
            .register(Box::new(replay_mismatch_total.clone()))
            .expect("register corecrux_replay_mismatch_total");

        let segment_corrupt_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_segment_corrupt_total",
                "Detected segment corruption count by reason",
            ),
            &["reason"],
        )
        .expect("corecrux_segment_corrupt_total counter");
        registry
            .register(Box::new(segment_corrupt_total.clone()))
            .expect("register corecrux_segment_corrupt_total");

        let verify_store_seconds = Histogram::with_opts(prometheus::HistogramOpts::new(
            "corecrux_verify_store_seconds",
            "verify-store run duration in seconds",
        ))
        .expect("corecrux_verify_store_seconds histogram");
        registry
            .register(Box::new(verify_store_seconds.clone()))
            .expect("register corecrux_verify_store_seconds");

        let segment_scrub_seconds = Histogram::with_opts(prometheus::HistogramOpts::new(
            "corecrux_segment_scrub_seconds",
            "segment scrub run duration in seconds",
        ))
        .expect("corecrux_segment_scrub_seconds histogram");
        registry
            .register(Box::new(segment_scrub_seconds.clone()))
            .expect("register corecrux_segment_scrub_seconds");

        let dir_l0_runs = GaugeVec::new(
            prometheus::Opts::new("corecrux_dir_l0_runs", "Directory L0 run count (LSM) per shard"),
            &["shard"],
        )
        .expect("corecrux_dir_l0_runs gauge");
        registry
            .register(Box::new(dir_l0_runs.clone()))
            .expect("register corecrux_dir_l0_runs");

        let dir_level_bytes = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_dir_level_bytes",
                "Directory run bytes per shard/level (sum of referenced .ccxdir file sizes)",
            ),
            &["shard", "level"],
        )
        .expect("corecrux_dir_level_bytes gauge");
        registry
            .register(Box::new(dir_level_bytes.clone()))
            .expect("register corecrux_dir_level_bytes");

        let dir_compactions_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_dir_compactions_total",
                "Directory compactions by level and status",
            ),
            &["shard", "level_from", "level_to", "status"],
        )
        .expect("corecrux_dir_compactions_total counter");
        registry
            .register(Box::new(dir_compactions_total.clone()))
            .expect("register corecrux_dir_compactions_total");

        let dir_compaction_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_dir_compaction_seconds",
                "Directory compaction duration in seconds",
            ),
            &["shard", "level_from", "level_to"],
        )
        .expect("corecrux_dir_compaction_seconds histogram");
        registry
            .register(Box::new(dir_compaction_seconds.clone()))
            .expect("register corecrux_dir_compaction_seconds");

        let dir_compaction_bytes_in_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_dir_compaction_bytes_in_total",
                "Total directory run bytes read as compaction inputs",
            ),
            &["shard"],
        )
        .expect("corecrux_dir_compaction_bytes_in_total counter");
        registry
            .register(Box::new(dir_compaction_bytes_in_total.clone()))
            .expect("register corecrux_dir_compaction_bytes_in_total");

        let dir_compaction_bytes_out_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_dir_compaction_bytes_out_total",
                "Total directory run bytes published as compaction outputs",
            ),
            &["shard"],
        )
        .expect("corecrux_dir_compaction_bytes_out_total counter");
        registry
            .register(Box::new(dir_compaction_bytes_out_total.clone()))
            .expect("register corecrux_dir_compaction_bytes_out_total");

        let dir_dead_extent_ratio = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_dir_dead_extent_ratio",
                "Dead extent ratio observed during compaction (dropped/input)",
            ),
            &["shard"],
        )
        .expect("corecrux_dir_dead_extent_ratio gauge");
        registry
            .register(Box::new(dir_dead_extent_ratio.clone()))
            .expect("register corecrux_dir_dead_extent_ratio");

        let checkpoints_installed_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_checkpoints_installed_total",
                "Checkpoint installs (stream meta updates) by shard and stream_type",
            ),
            &["shard", "stream_type"],
        )
        .expect("corecrux_checkpoints_installed_total counter");
        registry
            .register(Box::new(checkpoints_installed_total.clone()))
            .expect("register corecrux_checkpoints_installed_total");

        let checkpoint_min_live_seq = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_checkpoint_min_live_seq",
                "Latest observed min_live_seq installed (sampled; do not label by streamId)",
            ),
            &["shard", "stream_type"],
        )
        .expect("corecrux_checkpoint_min_live_seq gauge");
        registry
            .register(Box::new(checkpoint_min_live_seq.clone()))
            .expect("register corecrux_checkpoint_min_live_seq");

        let stream_tombstones_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_stream_tombstones_total",
                "Stream tombstones installed (tombstone_seq updates)",
            ),
            &["shard"],
        )
        .expect("corecrux_stream_tombstones_total counter");
        registry
            .register(Box::new(stream_tombstones_total.clone()))
            .expect("register corecrux_stream_tombstones_total");

        let stream_tombstone_rejects_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_stream_tombstone_rejects_total",
                "Append requests rejected because the stream is tombstoned",
            ),
            &["shard"],
        )
        .expect("corecrux_stream_tombstone_rejects_total counter");
        registry
            .register(Box::new(stream_tombstone_rejects_total.clone()))
            .expect("register corecrux_stream_tombstone_rejects_total");

        let append_latency_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_append_latency_seconds",
                "AppendBatch latency in seconds (includes IO+kernel orchestration)",
            ),
            &["shard"],
        )
        .expect("corecrux_append_latency_seconds histogram");
        registry
            .register(Box::new(append_latency_seconds.clone()))
            .expect("register corecrux_append_latency_seconds");

        let stream_read_latency_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_stream_read_latency_seconds",
                "Stream read latency in seconds (tail/range)",
            ),
            &["shard", "op"],
        )
        .expect("corecrux_stream_read_latency_seconds histogram");
        registry
            .register(Box::new(stream_read_latency_seconds.clone()))
            .expect("register corecrux_stream_read_latency_seconds");

        let read_retry_total = CounterVec::new(
            prometheus::Opts::new("corecrux_read_retry_total", "Read retries by operation/reason/outcome"),
            &["op", "reason", "outcome"],
        )
        .expect("corecrux_read_retry_total counter");
        registry
            .register(Box::new(read_retry_total.clone()))
            .expect("register corecrux_read_retry_total");

        let store_lock_wait_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_store_lock_wait_seconds",
                "Time spent waiting to acquire store lock by operation",
            ),
            &["op"],
        )
        .expect("corecrux_store_lock_wait_seconds histogram");
        registry
            .register(Box::new(store_lock_wait_seconds.clone()))
            .expect("register corecrux_store_lock_wait_seconds");

        let store_lock_hold_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_store_lock_hold_seconds",
                "Time spent holding store lock by operation",
            ),
            &["op"],
        )
        .expect("corecrux_store_lock_hold_seconds histogram");
        registry
            .register(Box::new(store_lock_hold_seconds.clone()))
            .expect("register corecrux_store_lock_hold_seconds");

        let store_service_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_store_service_seconds",
                "Store service time (excluding lock wait) by operation",
            ),
            &["op"],
        )
        .expect("corecrux_store_service_seconds histogram");
        registry
            .register(Box::new(store_service_seconds.clone()))
            .expect("register corecrux_store_service_seconds");

        let append_lane_waiters = Gauge::new(
            "corecrux_append_lane_waiters",
            "Current number of append requests waiting to acquire a lane lock",
        )
        .expect("corecrux_append_lane_waiters gauge");
        registry
            .register(Box::new(append_lane_waiters.clone()))
            .expect("register corecrux_append_lane_waiters");

        let append_lane_waiters_peak = Gauge::new(
            "corecrux_append_lane_waiters_peak",
            "Peak concurrent append lane waiters observed since process start",
        )
        .expect("corecrux_append_lane_waiters_peak gauge");
        registry
            .register(Box::new(append_lane_waiters_peak.clone()))
            .expect("register corecrux_append_lane_waiters_peak");

        let append_lane_queue_depth = Histogram::with_opts(prometheus::HistogramOpts::new(
            "corecrux_append_lane_queue_depth",
            "Append lane queue depth sampled when a request joins the lane queue",
        ))
        .expect("corecrux_append_lane_queue_depth histogram");
        registry
            .register(Box::new(append_lane_queue_depth.clone()))
            .expect("register corecrux_append_lane_queue_depth");

        let append_lane_selected_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_append_lane_selected_total",
                "Append requests selected into lane fairness buckets (low-cardinality)",
            ),
            &["bucket"],
        )
        .expect("corecrux_append_lane_selected_total counter");
        registry
            .register(Box::new(append_lane_selected_total.clone()))
            .expect("register corecrux_append_lane_selected_total");

        let append_lane_wait_seconds_by_bucket = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_append_lane_wait_seconds_by_bucket",
                "Append lane wait time in seconds by fairness bucket",
            ),
            &["bucket"],
        )
        .expect("corecrux_append_lane_wait_seconds_by_bucket histogram");
        registry
            .register(Box::new(append_lane_wait_seconds_by_bucket.clone()))
            .expect("register corecrux_append_lane_wait_seconds_by_bucket");

        let grpc_messages_sent_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_grpc_messages_sent_total",
                "gRPC response messages sent by rpc",
            ),
            &["rpc"],
        )
        .expect("corecrux_grpc_messages_sent_total counter");
        registry
            .register(Box::new(grpc_messages_sent_total.clone()))
            .expect("register corecrux_grpc_messages_sent_total");

        let grpc_send_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new("corecrux_grpc_send_seconds", "gRPC send+encode duration by rpc"),
            &["rpc"],
        )
        .expect("corecrux_grpc_send_seconds histogram");
        registry
            .register(Box::new(grpc_send_seconds.clone()))
            .expect("register corecrux_grpc_send_seconds");

        let grpc_send_blocked_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_grpc_send_blocked_seconds",
                "gRPC send blocking duration by rpc",
            ),
            &["rpc"],
        )
        .expect("corecrux_grpc_send_blocked_seconds histogram");
        registry
            .register(Box::new(grpc_send_blocked_seconds.clone()))
            .expect("register corecrux_grpc_send_blocked_seconds");

        let replay_events_total = CounterVec::new(
            prometheus::Opts::new("corecrux_replay_events_total", "Replay events returned by rpc"),
            &["rpc"],
        )
        .expect("corecrux_replay_events_total counter");
        registry
            .register(Box::new(replay_events_total.clone()))
            .expect("register corecrux_replay_events_total");

        let replay_bytes_total = CounterVec::new(
            prometheus::Opts::new("corecrux_replay_bytes_total", "Replay bytes returned by rpc"),
            &["rpc"],
        )
        .expect("corecrux_replay_bytes_total counter");
        registry
            .register(Box::new(replay_bytes_total.clone()))
            .expect("register corecrux_replay_bytes_total");

        let replay_build_response_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_replay_build_response_seconds",
                "Replay response materialization time in seconds by rpc",
            ),
            &["rpc"],
        )
        .expect("corecrux_replay_build_response_seconds histogram");
        registry
            .register(Box::new(replay_build_response_seconds.clone()))
            .expect("register corecrux_replay_build_response_seconds");

        let replay_encode_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_replay_encode_seconds",
                "Replay protobuf encode sampling time in seconds by rpc",
            ),
            &["rpc"],
        )
        .expect("corecrux_replay_encode_seconds histogram");
        registry
            .register(Box::new(replay_encode_seconds.clone()))
            .expect("register corecrux_replay_encode_seconds");

        let rpc_total_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_rpc_total_seconds",
                "Total server-side time per RPC in seconds (includes store+materialize+send) by rpc",
            ),
            &["rpc"],
        )
        .expect("corecrux_rpc_total_seconds histogram");
        registry
            .register(Box::new(rpc_total_seconds.clone()))
            .expect("register corecrux_rpc_total_seconds");

        let storage_tail_stage_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_storage_tail_stage_seconds",
                "Tail read stage duration in seconds (stage=index_lookup|io|decode|total)",
            ),
            &["stage"],
        )
        .expect("corecrux_storage_tail_stage_seconds histogram");
        registry
            .register(Box::new(storage_tail_stage_seconds.clone()))
            .expect("register corecrux_storage_tail_stage_seconds");

        let storage_append_stage_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_storage_append_stage_seconds",
                "Append stage duration in seconds (stage=idempotency_check|index_update|io_write|fence_wait|fence_fsync|fence|total)",
            ),
            &["stage"],
        )
        .expect("corecrux_storage_append_stage_seconds histogram");
        registry
            .register(Box::new(storage_append_stage_seconds.clone()))
            .expect("register corecrux_storage_append_stage_seconds");

        let append_fence_wait_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_append_fence_wait_seconds",
                "Append durability fence wait time in seconds by shard",
            ),
            &["shard"],
        )
        .expect("corecrux_append_fence_wait_seconds histogram");
        registry
            .register(Box::new(append_fence_wait_seconds.clone()))
            .expect("register corecrux_append_fence_wait_seconds");

        let append_fence_fsync_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_append_fence_fsync_seconds",
                "Append durability fsync/sync_data time in seconds by shard",
            ),
            &["shard"],
        )
        .expect("corecrux_append_fence_fsync_seconds histogram");
        registry
            .register(Box::new(append_fence_fsync_seconds.clone()))
            .expect("register corecrux_append_fence_fsync_seconds");

        let storage_tail_bytes_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_storage_tail_bytes_total",
                "Tail read bytes by kind (kind=disk_estimate|frame)",
            ),
            &["kind"],
        )
        .expect("corecrux_storage_tail_bytes_total counter");
        registry
            .register(Box::new(storage_tail_bytes_total.clone()))
            .expect("register corecrux_storage_tail_bytes_total");

        let storage_tail_items_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_storage_tail_items_total",
                "Tail read touched items by kind (kind=segments|blocks|frames)",
            ),
            &["kind"],
        )
        .expect("corecrux_storage_tail_items_total counter");
        registry
            .register(Box::new(storage_tail_items_total.clone()))
            .expect("register corecrux_storage_tail_items_total");

        let storage_tail_path_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_storage_tail_path_total",
                "Tail-read fast-path outcomes by path (path=head_tail_fastpath|locator_fully_satisfied, outcome=hit|miss)",
            ),
            &["path", "outcome"],
        )
        .expect("corecrux_storage_tail_path_total counter");
        registry
            .register(Box::new(storage_tail_path_total.clone()))
            .expect("register corecrux_storage_tail_path_total");

        let storage_head_frames_scanned_total = Counter::new(
            "corecrux_storage_head_frames_scanned_total",
            "Total head frames inspected while serving tail reads",
        )
        .expect("corecrux_storage_head_frames_scanned_total counter");
        registry
            .register(Box::new(storage_head_frames_scanned_total.clone()))
            .expect("register corecrux_storage_head_frames_scanned_total");

        let read_amplification_p50 = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_read_amplification_p50",
                "Read amplification p50 (segments touched), rolling sample",
            ),
            &["shard"],
        )
        .expect("corecrux_read_amplification_p50 gauge");
        registry
            .register(Box::new(read_amplification_p50.clone()))
            .expect("register corecrux_read_amplification_p50");

        let read_amplification_p95 = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_read_amplification_p95",
                "Read amplification p95 (segments touched), rolling sample",
            ),
            &["shard"],
        )
        .expect("corecrux_read_amplification_p95 gauge");
        registry
            .register(Box::new(read_amplification_p95.clone()))
            .expect("register corecrux_read_amplification_p95");

        let kernel_launch_total = CounterVec::new(
            prometheus::Opts::new("corecrux_kernel_launch_total", "Kernel launches and outcomes"),
            &["kernel", "result"],
        )
        .expect("corecrux_kernel_launch_total counter");
        registry
            .register(Box::new(kernel_launch_total.clone()))
            .expect("register corecrux_kernel_launch_total");

        let shardmap_version = Gauge::new(
            "corecrux_shardmap_version",
            "Current shard map version loaded by this process",
        )
        .expect("corecrux_shardmap_version gauge");
        registry
            .register(Box::new(shardmap_version.clone()))
            .expect("register corecrux_shardmap_version");

        let routing_lookup_total = CounterVec::new(
            prometheus::Opts::new("corecrux_routing_lookup_total", "Routing lookups and outcomes"),
            &["op", "outcome"],
        )
        .expect("corecrux_routing_lookup_total counter");
        registry
            .register(Box::new(routing_lookup_total.clone()))
            .expect("register corecrux_routing_lookup_total");

        let routing_lookup_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new("corecrux_routing_lookup_seconds", "Routing lookup duration in seconds"),
            &["op"],
        )
        .expect("corecrux_routing_lookup_seconds histogram");
        registry
            .register(Box::new(routing_lookup_seconds.clone()))
            .expect("register corecrux_routing_lookup_seconds");

        let shard_requests_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_shard_requests_total",
                "Requests routed to a shard (low-cardinality by shardId)",
            ),
            &["shardId", "op"],
        )
        .expect("corecrux_shard_requests_total counter");
        registry
            .register(Box::new(shard_requests_total.clone()))
            .expect("register corecrux_shard_requests_total");

        let replication_receive_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_replication_receive_total",
                "Replication segment receive/apply outcomes",
            ),
            &["result"],
        )
        .expect("corecrux_replication_receive_total counter");
        registry
            .register(Box::new(replication_receive_total.clone()))
            .expect("register corecrux_replication_receive_total");

        let replication_follower_watermark = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_replication_follower_watermark_segment_seq",
                "Follower-applied highest segment_seq per shard",
            ),
            &["shardId"],
        )
        .expect("corecrux_replication_follower_watermark_segment_seq gauge");
        registry
            .register(Box::new(replication_follower_watermark.clone()))
            .expect("register corecrux_replication_follower_watermark_segment_seq");

        let replicated_commit_total = CounterVec::new(
            prometheus::Opts::new("corecrux_replicated_commit_total", "ReplicatedCommit outcomes"),
            &["result"],
        )
        .expect("corecrux_replicated_commit_total counter");
        registry
            .register(Box::new(replicated_commit_total.clone()))
            .expect("register corecrux_replicated_commit_total");

        let replicated_commit_required_acks = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_replicated_commit_required_acks",
                "Required acknowledgements for ReplicatedCommit per shard",
            ),
            &["shardId"],
        )
        .expect("corecrux_replicated_commit_required_acks gauge");
        registry
            .register(Box::new(replicated_commit_required_acks.clone()))
            .expect("register corecrux_replicated_commit_required_acks");

        let replicated_commit_actual_acks = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_replicated_commit_actual_acks",
                "Observed acknowledgements for ReplicatedCommit per shard",
            ),
            &["shardId"],
        )
        .expect("corecrux_replicated_commit_actual_acks gauge");
        registry
            .register(Box::new(replicated_commit_actual_acks.clone()))
            .expect("register corecrux_replicated_commit_actual_acks");

        let replicated_commit_ack_deficit = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_replicated_commit_ack_deficit",
                "ReplicatedCommit acknowledgement deficit (required-actual) per shard",
            ),
            &["shardId"],
        )
        .expect("corecrux_replicated_commit_ack_deficit gauge");
        registry
            .register(Box::new(replicated_commit_ack_deficit.clone()))
            .expect("register corecrux_replicated_commit_ack_deficit");

        let replication_shard_epoch = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_replication_shard_epoch",
                "Current shard epoch from loaded shard map",
            ),
            &["shardId"],
        )
        .expect("corecrux_replication_shard_epoch gauge");
        registry
            .register(Box::new(replication_shard_epoch.clone()))
            .expect("register corecrux_replication_shard_epoch");

        let replication_follower_targets = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_replication_follower_targets",
                "Configured follower count per shard (excluding self)",
            ),
            &["shardId"],
        )
        .expect("corecrux_replication_follower_targets gauge");
        registry
            .register(Box::new(replication_follower_targets.clone()))
            .expect("register corecrux_replication_follower_targets");

        let replication_topology_ok = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_replication_topology_ok",
                "Replication topology sanity for a shard (followers configured => 1)",
            ),
            &["shardId"],
        )
        .expect("corecrux_replication_topology_ok gauge");
        registry
            .register(Box::new(replication_topology_ok.clone()))
            .expect("register corecrux_replication_topology_ok");

        let replication_leader_segment_seq = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_replication_leader_segment_seq",
                "Latest leader segment_seq observed for replication shipping per shard",
            ),
            &["shardId"],
        )
        .expect("corecrux_replication_leader_segment_seq gauge");
        registry
            .register(Box::new(replication_leader_segment_seq.clone()))
            .expect("register corecrux_replication_leader_segment_seq");

        let replication_min_follower_acked_segment_seq = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_replication_min_follower_acked_segment_seq",
                "Minimum follower-acked segment_seq observed per shard",
            ),
            &["shardId"],
        )
        .expect("corecrux_replication_min_follower_acked_segment_seq gauge");
        registry
            .register(Box::new(replication_min_follower_acked_segment_seq.clone()))
            .expect("register corecrux_replication_min_follower_acked_segment_seq");

        let replication_lag_segments = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_replication_lag_segments",
                "Observed replication lag in segment_seq units (leader - min follower ack) per shard",
            ),
            &["shardId"],
        )
        .expect("corecrux_replication_lag_segments gauge");
        registry
            .register(Box::new(replication_lag_segments.clone()))
            .expect("register corecrux_replication_lag_segments");

        let shard_state = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_shard_state",
                "Shard state (one series per shardId,state; value is 1 for current state)",
            ),
            &["shardId", "state"],
        )
        .expect("corecrux_shard_state gauge");
        registry
            .register(Box::new(shard_state.clone()))
            .expect("register corecrux_shard_state");

        let projections_commit_id = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_projections_commit_id",
                "Latest projections commit_id (meta generation) per shard",
            ),
            &["shard"],
        )
        .expect("corecrux_projections_commit_id gauge");
        registry
            .register(Box::new(projections_commit_id.clone()))
            .expect("register corecrux_projections_commit_id");

        let projections_cursor_segment_seq = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_projections_cursor_segment_seq",
                "Projection cursor segment_seq (sealed replay cursor) per shard/projection",
            ),
            &["shard", "projection"],
        )
        .expect("corecrux_projections_cursor_segment_seq gauge");
        registry
            .register(Box::new(projections_cursor_segment_seq.clone()))
            .expect("register corecrux_projections_cursor_segment_seq");

        let projections_cursor_offset = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_projections_cursor_offset",
                "Projection cursor offset (sealed replay cursor) per shard/projection",
            ),
            &["shard", "projection"],
        )
        .expect("corecrux_projections_cursor_offset gauge");
        registry
            .register(Box::new(projections_cursor_offset.clone()))
            .expect("register corecrux_projections_cursor_offset");

        let projections_row_count = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_projections_row_count",
                "Committed projection row/edge count per shard/projection",
            ),
            &["shard", "projection"],
        )
        .expect("corecrux_projections_row_count gauge");
        registry
            .register(Box::new(projections_row_count.clone()))
            .expect("register corecrux_projections_row_count");

        let projections_tick_frames_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_projections_tick_frames_total",
                "Total frames processed by projection ticks per shard",
            ),
            &["shard"],
        )
        .expect("corecrux_projections_tick_frames_total counter");
        registry
            .register(Box::new(projections_tick_frames_total.clone()))
            .expect("register corecrux_projections_tick_frames_total");

        let projections_tick_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_projections_tick_seconds",
                "Projection tick duration in seconds per shard",
            ),
            &["shard"],
        )
        .expect("corecrux_projections_tick_seconds histogram");
        registry
            .register(Box::new(projections_tick_seconds.clone()))
            .expect("register corecrux_projections_tick_seconds");

        let projections_tick_fail_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_projections_tick_fail_total",
                "Projection tick failures per shard",
            ),
            &["shard"],
        )
        .expect("corecrux_projections_tick_fail_total counter");
        registry
            .register(Box::new(projections_tick_fail_total.clone()))
            .expect("register corecrux_projections_tick_fail_total");

        let shard_open_attempts_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_shard_open_attempts_total",
                "ShardStorage::open() calls by caller context",
            ),
            &["caller"],
        )
        .expect("corecrux_shard_open_attempts_total counter");
        registry
            .register(Box::new(shard_open_attempts_total.clone()))
            .expect("register corecrux_shard_open_attempts_total");

        let lock_contention_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_lock_contention_total",
                "File lock contention events by caller context",
            ),
            &["caller"],
        )
        .expect("corecrux_lock_contention_total counter");
        registry
            .register(Box::new(lock_contention_total.clone()))
            .expect("register corecrux_lock_contention_total");

        let projection_snapshot_valid = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_projection_snapshot_valid",
                "Projection snapshot validity by required projection (1 = valid)",
            ),
            &["projection"],
        )
        .expect("corecrux_projection_snapshot_valid gauge");
        registry
            .register(Box::new(projection_snapshot_valid.clone()))
            .expect("register corecrux_projection_snapshot_valid");

        let knowledge_authority_mode = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_knowledge_authority_mode",
                "Knowledge authority mode one-hot gauge (1 = current mode)",
            ),
            &["mode"],
        )
        .expect("corecrux_knowledge_authority_mode gauge");
        registry
            .register(Box::new(knowledge_authority_mode.clone()))
            .expect("register corecrux_knowledge_authority_mode");

        let knowledge_rollout_stage = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_knowledge_rollout_stage",
                "Knowledge rollout stage one-hot gauge (1 = current stage)",
            ),
            &["stage"],
        )
        .expect("corecrux_knowledge_rollout_stage gauge");
        registry
            .register(Box::new(knowledge_rollout_stage.clone()))
            .expect("register corecrux_knowledge_rollout_stage");

        let knowledge_parity_status = GaugeVec::new(
            prometheus::Opts::new(
                "corecrux_knowledge_parity_status",
                "Last knowledge parity status one-hot gauge (1 = current status)",
            ),
            &["status"],
        )
        .expect("corecrux_knowledge_parity_status gauge");
        registry
            .register(Box::new(knowledge_parity_status.clone()))
            .expect("register corecrux_knowledge_parity_status");

        let knowledge_rollback_triggered = Gauge::new(
            "corecrux_knowledge_rollback_triggered",
            "Whether the knowledge authority rollback trigger is active (1 = active)",
        )
        .expect("corecrux_knowledge_rollback_triggered gauge");
        registry
            .register(Box::new(knowledge_rollback_triggered.clone()))
            .expect("register corecrux_knowledge_rollback_triggered");

        let knowledge_parity_mismatch_count = Gauge::new(
            "corecrux_knowledge_parity_mismatch_count",
            "Last observed knowledge parity mismatch count",
        )
        .expect("corecrux_knowledge_parity_mismatch_count gauge");
        registry
            .register(Box::new(knowledge_parity_mismatch_count.clone()))
            .expect("register corecrux_knowledge_parity_mismatch_count");

        let knowledge_parity_cursor_missing_count = Gauge::new(
            "corecrux_knowledge_parity_cursor_missing_count",
            "Last observed missing-cursor count during knowledge parity checks",
        )
        .expect("corecrux_knowledge_parity_cursor_missing_count gauge");
        registry
            .register(Box::new(knowledge_parity_cursor_missing_count.clone()))
            .expect("register corecrux_knowledge_parity_cursor_missing_count");

        let knowledge_parity_pass_ratio_bps = Gauge::new(
            "corecrux_knowledge_parity_pass_ratio_bps",
            "Last observed knowledge parity pass ratio in basis points",
        )
        .expect("corecrux_knowledge_parity_pass_ratio_bps gauge");
        registry
            .register(Box::new(knowledge_parity_pass_ratio_bps.clone()))
            .expect("register corecrux_knowledge_parity_pass_ratio_bps");

        let knowledge_parity_projection_lag_ms = Gauge::new(
            "corecrux_knowledge_parity_projection_lag_ms",
            "Last observed knowledge parity projection lag in milliseconds",
        )
        .expect("corecrux_knowledge_parity_projection_lag_ms gauge");
        registry
            .register(Box::new(knowledge_parity_projection_lag_ms.clone()))
            .expect("register corecrux_knowledge_parity_projection_lag_ms");

        let receipt_verify_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_receipt_verify_total",
                "Receipt signature verification outcomes (ok/fail)",
            ),
            &["result"],
        )
        .expect("corecrux_receipt_verify_total counter");
        registry
            .register(Box::new(receipt_verify_total.clone()))
            .expect("register corecrux_receipt_verify_total");

        let receipt_verify_fail_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_receipt_verify_fail_total",
                "Receipt verification failures by reason (low-cardinality)",
            ),
            &["reason"],
        )
        .expect("corecrux_receipt_verify_fail_total counter");
        registry
            .register(Box::new(receipt_verify_fail_total.clone()))
            .expect("register corecrux_receipt_verify_fail_total");

        let receipt_export_total = CounterVec::new(
            prometheus::Opts::new(
                "corecrux_receipt_export_total",
                "Receipt export bundle requests by status",
            ),
            &["status"],
        )
        .expect("corecrux_receipt_export_total counter");
        registry
            .register(Box::new(receipt_export_total.clone()))
            .expect("register corecrux_receipt_export_total");

        // ── v4.2 query metrics ───────────────────────────────────────
        let query_graph_expand_duration_seconds = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "corecrux_query_graph_expand_duration_seconds",
                "Duration of graph-expand queries",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25]),
        )
        .expect("corecrux_query_graph_expand_duration_seconds histogram");
        registry
            .register(Box::new(query_graph_expand_duration_seconds.clone()))
            .expect("register corecrux_query_graph_expand_duration_seconds");

        let query_graph_expand_nodes_visited = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "corecrux_query_graph_expand_nodes_visited",
                "Nodes visited per graph-expand query",
            )
            .buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 200.0]),
        )
        .expect("corecrux_query_graph_expand_nodes_visited histogram");
        registry
            .register(Box::new(query_graph_expand_nodes_visited.clone()))
            .expect("register corecrux_query_graph_expand_nodes_visited");

        let query_time_range_duration_seconds = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "corecrux_query_time_range_duration_seconds",
                "Duration of time-range queries",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.5]),
        )
        .expect("corecrux_query_time_range_duration_seconds histogram");
        registry
            .register(Box::new(query_time_range_duration_seconds.clone()))
            .expect("register corecrux_query_time_range_duration_seconds");

        let query_time_range_artifacts_scanned = Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "corecrux_query_time_range_artifacts_scanned",
                "Artifacts scanned per time-range query",
            )
            .buckets(vec![1.0, 10.0, 50.0, 100.0, 250.0, 500.0]),
        )
        .expect("corecrux_query_time_range_artifacts_scanned histogram");
        registry
            .register(Box::new(query_time_range_artifacts_scanned.clone()))
            .expect("register corecrux_query_time_range_artifacts_scanned");

        // ── v5 seal + retrieval metrics ─────────────────────────────────
        let seal_duration_seconds = HistogramVec::new(
            prometheus::HistogramOpts::new(
                "corecrux_seal_duration_seconds",
                "Time to seal a segment (includes .ccxi companion build)",
            )
            .buckets(vec![0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]),
            &["phase"], // "phase1" or "phase2"
        )
        .expect("corecrux_seal_duration_seconds histogram");
        registry
            .register(Box::new(seal_duration_seconds.clone()))
            .expect("register corecrux_seal_duration_seconds");

        let seal_backlog_frames = Gauge::new(
            "corecrux_seal_backlog_frames",
            "Number of frames in the head segment not yet sealed",
        )
        .expect("corecrux_seal_backlog_frames gauge");
        registry
            .register(Box::new(seal_backlog_frames.clone()))
            .expect("register corecrux_seal_backlog_frames");

        let ccxi_missing_total = Gauge::new(
            "corecrux_ccxi_missing_total",
            "Number of sealed segments missing a .ccxi companion index",
        )
        .expect("corecrux_ccxi_missing_total gauge");
        registry
            .register(Box::new(ccxi_missing_total.clone()))
            .expect("register corecrux_ccxi_missing_total");

        Self {
            registry,
            io_backend,
            valve_pause_ingest,
            valve_pause_compaction,
            valve_throttle,
            valve_read_only,
            valve_emergency_brake,
            valve_state,
            throttle_ratio,
            data_dir_bytes_total,
            data_dir_bytes_free,
            data_dir_free_ratio,
            write_confirmations_total,
            write_confirmation_sign_duration_ms,
            write_confirmation_unsigned_queue_depth,
            tenant_throttle_rejected_total,
            emergency_brake_total,
            write_rejects_total,
            backpressure_active_gauge,
            replay_total,
            replay_mismatch_total,
            segment_corrupt_total,
            verify_store_seconds,
            segment_scrub_seconds,

            dir_l0_runs,
            dir_level_bytes,
            dir_compactions_total,
            dir_compaction_seconds,
            dir_compaction_bytes_in_total,
            dir_compaction_bytes_out_total,
            dir_dead_extent_ratio,

            checkpoints_installed_total,
            checkpoint_min_live_seq,
            stream_tombstones_total,
            stream_tombstone_rejects_total,

            append_latency_seconds,
            stream_read_latency_seconds,
            read_retry_total,
            store_lock_wait_seconds,
            store_lock_hold_seconds,
            store_service_seconds,
            append_lane_waiters,
            append_lane_waiters_peak,
            append_lane_queue_depth,
            append_lane_selected_total,
            append_lane_wait_seconds_by_bucket,
            grpc_messages_sent_total,
            grpc_send_seconds,
            grpc_send_blocked_seconds,
            replay_events_total,
            replay_bytes_total,
            replay_build_response_seconds,
            replay_encode_seconds,
            rpc_total_seconds,
            storage_tail_stage_seconds,
            storage_append_stage_seconds,
            append_fence_wait_seconds,
            append_fence_fsync_seconds,
            storage_tail_bytes_total,
            storage_tail_items_total,
            storage_tail_path_total,
            storage_head_frames_scanned_total,

            read_amplification_p50,
            read_amplification_p95,

            kernel_launch_total,
            shardmap_version,
            routing_lookup_total,
            routing_lookup_seconds,
            shard_requests_total,
            replication_receive_total,
            replication_follower_watermark,
            replicated_commit_total,
            replicated_commit_required_acks,
            replicated_commit_actual_acks,
            replicated_commit_ack_deficit,
            replication_shard_epoch,
            replication_follower_targets,
            replication_topology_ok,
            replication_leader_segment_seq,
            replication_min_follower_acked_segment_seq,
            replication_lag_segments,
            shard_state,
            peer_cache_hits_total,
            peer_cache_misses_total,
            peer_cache_bytes,
            tail_cache_hits_total,
            tail_cache_misses_total,
            tail_cache_bytes,

            projections_commit_id,
            projections_cursor_segment_seq,
            projections_cursor_offset,
            projections_row_count,
            projections_tick_frames_total,
            projections_tick_seconds,
            projections_tick_fail_total,
            shard_open_attempts_total,
            lock_contention_total,
            projection_snapshot_valid,
            knowledge_authority_mode,
            knowledge_rollout_stage,
            knowledge_parity_status,
            knowledge_rollback_triggered,
            knowledge_parity_mismatch_count,
            knowledge_parity_cursor_missing_count,
            knowledge_parity_pass_ratio_bps,
            knowledge_parity_projection_lag_ms,

            receipt_verify_total,
            receipt_verify_fail_total,
            receipt_export_total,

            query_graph_expand_duration_seconds,
            query_graph_expand_nodes_visited,
            query_time_range_duration_seconds,
            query_time_range_artifacts_scanned,

            seal_duration_seconds,
            seal_backlog_frames,
            ccxi_missing_total,
        }
    }

    pub fn set_io_backend(&self, backend: &str) {
        self.io_backend.with_label_values(&[backend]).set(1.0);
    }

    pub fn set_shard_state(&self, shard_id: &str, state: &str) {
        for s in ["active", "draining", "retired"] {
            self.shard_state
                .with_label_values(&[shard_id, s])
                .set(if s == state { 1.0 } else { 0.0 });
        }
    }

    pub fn inc_tail_cache_hit(&self, shard_id: &str) {
        self.tail_cache_hits_total.with_label_values(&[shard_id]).inc();
    }

    pub fn inc_tail_cache_miss(&self, shard_id: &str) {
        self.tail_cache_misses_total.with_label_values(&[shard_id]).inc();
    }

    pub fn set_tail_cache_bytes(&self, shard_id: &str, bytes: u64) {
        self.tail_cache_bytes.with_label_values(&[shard_id]).set(bytes as f64);
    }

    pub fn touch_peer_cache_metrics(&self) {
        // Keep the counters registered and referenced on CPU-only builds without introducing
        // fake traffic (inc_by(0.0) is a no-op).
        self.peer_cache_hits_total.inc_by(0.0);
        self.peer_cache_misses_total.inc_by(0.0);
    }

    #[allow(dead_code)]
    pub fn inc_peer_cache_hit(&self) {
        self.peer_cache_hits_total.inc();
    }

    #[allow(dead_code)]
    pub fn inc_peer_cache_miss(&self) {
        self.peer_cache_misses_total.inc();
    }

    pub fn set_peer_cache_bytes(&self, bytes: u64) {
        self.peer_cache_bytes.set(bytes as f64);
    }

    pub fn set_valve_pause_ingest(&self, enabled: bool) {
        self.valve_pause_ingest.set(if enabled { 1.0 } else { 0.0 });
    }

    pub fn set_valve_pause_compaction(&self, enabled: bool) {
        self.valve_pause_compaction.set(if enabled { 1.0 } else { 0.0 });
    }

    pub fn set_valve_throttle(&self, enabled: bool) {
        self.valve_throttle.set(if enabled { 1.0 } else { 0.0 });
    }

    pub fn set_valve_read_only(&self, enabled: bool) {
        self.valve_read_only.set(if enabled { 1.0 } else { 0.0 });
    }

    pub fn set_valve_emergency_brake(&self, enabled: bool) {
        self.valve_emergency_brake.set(if enabled { 1.0 } else { 0.0 });
    }

    pub fn set_valve_state(&self, valve: &str, enabled: bool) {
        self.valve_state
            .with_label_values(&[valve])
            .set(if enabled { 1.0 } else { 0.0 });
    }

    pub fn set_throttle_ratio(&self, ratio_0_to_1: f64) {
        let r = ratio_0_to_1.clamp(0.0, 1.0);
        self.throttle_ratio.set(r);
    }

    pub fn set_data_dir_space(&self, total_bytes: u64, free_bytes: u64) {
        self.data_dir_bytes_total.set(total_bytes as f64);
        self.data_dir_bytes_free.set(free_bytes as f64);
        let ratio = if total_bytes == 0 {
            0.0
        } else {
            free_bytes as f64 / total_bytes as f64
        };
        self.data_dir_free_ratio.set(ratio.clamp(0.0, 1.0));
    }

    pub fn inc_write_confirmation(&self, signed: bool) {
        self.write_confirmations_total
            .with_label_values(&[if signed { "true" } else { "false" }])
            .inc();
    }

    pub fn observe_write_confirmation_sign_duration_ms(&self, duration_ms: f64) {
        if duration_ms.is_finite() && duration_ms >= 0.0 {
            self.write_confirmation_sign_duration_ms.observe(duration_ms);
        }
    }

    pub fn set_write_confirmation_unsigned_queue_depth(&self, depth: u64) {
        self.write_confirmation_unsigned_queue_depth.set(depth as f64);
    }

    pub fn inc_tenant_throttle_reject(&self, tenant_id_hash: &str) {
        self.tenant_throttle_rejected_total
            .with_label_values(&[tenant_id_hash])
            .inc();
    }

    pub fn inc_emergency_brake(&self, source: &str) {
        self.emergency_brake_total.with_label_values(&[source]).inc();
    }

    pub fn inc_write_reject(&self, reason: &str) {
        self.write_rejects_total.with_label_values(&[reason]).inc();
    }

    pub fn set_backpressure_active(&self, active: bool) {
        self.backpressure_active_gauge.set(if active { 1.0 } else { 0.0 });
    }

    pub fn inc_replay_total(&self, result: &str) {
        self.replay_total.with_label_values(&[result]).inc();
    }

    pub fn inc_replay_mismatch(&self, drift_class: &str) {
        self.replay_mismatch_total.with_label_values(&[drift_class]).inc();
    }

    pub fn inc_segment_corrupt(&self, reason: &str) {
        self.segment_corrupt_total.with_label_values(&[reason]).inc();
    }

    pub fn observe_verify_store_seconds(&self, secs: f64) {
        self.verify_store_seconds.observe(secs);
    }

    pub fn observe_segment_scrub_seconds(&self, secs: f64) {
        self.segment_scrub_seconds.observe(secs);
    }

    pub fn set_dir_l0_runs(&self, shard: &str, runs: u32) {
        self.dir_l0_runs.with_label_values(&[shard]).set(runs as f64);
    }

    pub fn set_dir_level_bytes(&self, shard: &str, level: u32, bytes: u64) {
        self.dir_level_bytes
            .with_label_values(&[shard, &level.to_string()])
            .set(bytes as f64);
    }

    pub fn inc_dir_compaction(&self, shard: &str, level_from: u32, level_to: u32, status: &str) {
        self.dir_compactions_total
            .with_label_values(&[shard, &level_from.to_string(), &level_to.to_string(), status])
            .inc();
    }

    pub fn observe_dir_compaction_seconds(&self, shard: &str, level_from: u32, level_to: u32, secs: f64) {
        self.dir_compaction_seconds
            .with_label_values(&[shard, &level_from.to_string(), &level_to.to_string()])
            .observe(secs);
    }

    pub fn add_dir_compaction_bytes_in(&self, shard: &str, bytes: u64) {
        self.dir_compaction_bytes_in_total
            .with_label_values(&[shard])
            .inc_by(bytes as f64);
    }

    pub fn add_dir_compaction_bytes_out(&self, shard: &str, bytes: u64) {
        self.dir_compaction_bytes_out_total
            .with_label_values(&[shard])
            .inc_by(bytes as f64);
    }

    pub fn set_dir_dead_extent_ratio(&self, shard: &str, ratio_0_to_1: f64) {
        let r = ratio_0_to_1.clamp(0.0, 1.0);
        self.dir_dead_extent_ratio.with_label_values(&[shard]).set(r);
    }

    pub fn inc_checkpoints_installed(&self, shard: &str, stream_type: &str) {
        self.checkpoints_installed_total
            .with_label_values(&[shard, stream_type])
            .inc();
    }

    pub fn set_checkpoint_min_live_seq(&self, shard: &str, stream_type: &str, min_live_seq: u64) {
        self.checkpoint_min_live_seq
            .with_label_values(&[shard, stream_type])
            .set(min_live_seq as f64);
    }

    pub fn inc_stream_tombstones(&self, shard: &str) {
        self.stream_tombstones_total.with_label_values(&[shard]).inc();
    }

    pub fn inc_stream_tombstone_rejects(&self, shard: &str) {
        self.stream_tombstone_rejects_total.with_label_values(&[shard]).inc();
    }

    pub fn observe_append_latency_seconds(&self, shard: &str, secs: f64) {
        self.append_latency_seconds.with_label_values(&[shard]).observe(secs);
    }

    pub fn observe_stream_read_latency_seconds(&self, shard: &str, op: &str, secs: f64) {
        self.stream_read_latency_seconds
            .with_label_values(&[shard, op])
            .observe(secs);
    }

    pub fn inc_read_retry(&self, op: &str, reason: &str, outcome: &str) {
        self.read_retry_total.with_label_values(&[op, reason, outcome]).inc();
    }

    pub fn read_retry_failed_total(&self, reason: &str) -> u64 {
        let mut total = 0.0f64;
        for op in ["tail", "range"] {
            total += self.read_retry_total.with_label_values(&[op, reason, "failed"]).get();
        }
        total.max(0.0).round() as u64
    }

    pub fn observe_store_lock_wait_seconds(&self, op: &str, secs: f64) {
        self.store_lock_wait_seconds.with_label_values(&[op]).observe(secs);
    }

    pub fn observe_store_lock_hold_seconds(&self, op: &str, secs: f64) {
        self.store_lock_hold_seconds.with_label_values(&[op]).observe(secs);
    }

    pub fn observe_store_service_seconds(&self, op: &str, secs: f64) {
        self.store_service_seconds.with_label_values(&[op]).observe(secs);
    }

    pub fn set_append_lane_waiters(&self, waiters: u64) {
        self.append_lane_waiters.set(waiters as f64);
    }

    pub fn set_append_lane_waiters_peak(&self, waiters: u64) {
        self.append_lane_waiters_peak.set(waiters as f64);
    }

    pub fn observe_append_lane_queue_depth(&self, depth: u64) {
        self.append_lane_queue_depth.observe(depth as f64);
    }

    pub fn inc_append_lane_selected_bucket(&self, bucket: u8) {
        let bucket_s = bucket.to_string();
        self.append_lane_selected_total
            .with_label_values(&[bucket_s.as_str()])
            .inc();
    }

    pub fn observe_append_lane_wait_seconds_bucket(&self, bucket: u8, secs: f64) {
        let bucket_s = bucket.to_string();
        self.append_lane_wait_seconds_by_bucket
            .with_label_values(&[bucket_s.as_str()])
            .observe(secs);
    }

    pub fn inc_grpc_messages_sent(&self, rpc: &str, count: u64) {
        self.grpc_messages_sent_total
            .with_label_values(&[rpc])
            .inc_by(count as f64);
    }

    pub fn observe_grpc_send_seconds(&self, rpc: &str, secs: f64) {
        self.grpc_send_seconds.with_label_values(&[rpc]).observe(secs);
    }

    pub fn observe_grpc_send_blocked_seconds(&self, rpc: &str, secs: f64) {
        self.grpc_send_blocked_seconds.with_label_values(&[rpc]).observe(secs);
    }

    pub fn add_replay_events(&self, rpc: &str, count: u64) {
        self.replay_events_total.with_label_values(&[rpc]).inc_by(count as f64);
    }

    pub fn add_replay_bytes(&self, rpc: &str, bytes: u64) {
        self.replay_bytes_total.with_label_values(&[rpc]).inc_by(bytes as f64);
    }

    pub fn observe_replay_build_response_seconds(&self, rpc: &str, secs: f64) {
        self.replay_build_response_seconds
            .with_label_values(&[rpc])
            .observe(secs);
    }

    pub fn observe_replay_encode_seconds(&self, rpc: &str, secs: f64) {
        self.replay_encode_seconds.with_label_values(&[rpc]).observe(secs);
    }

    pub fn observe_rpc_total_seconds(&self, rpc: &str, secs: f64) {
        self.rpc_total_seconds.with_label_values(&[rpc]).observe(secs);
    }

    pub fn observe_storage_tail_stage_seconds(&self, stage: &str, secs: f64) {
        self.storage_tail_stage_seconds
            .with_label_values(&[stage])
            .observe(secs);
    }

    pub fn observe_storage_append_stage_seconds(&self, stage: &str, secs: f64) {
        self.storage_append_stage_seconds
            .with_label_values(&[stage])
            .observe(secs);
    }

    pub fn observe_append_fence_wait_seconds(&self, shard: &str, secs: f64) {
        self.append_fence_wait_seconds.with_label_values(&[shard]).observe(secs);
    }

    pub fn observe_append_fence_fsync_seconds(&self, shard: &str, secs: f64) {
        self.append_fence_fsync_seconds
            .with_label_values(&[shard])
            .observe(secs);
    }

    pub fn add_storage_tail_bytes(&self, kind: &str, bytes: u64) {
        self.storage_tail_bytes_total
            .with_label_values(&[kind])
            .inc_by(bytes as f64);
    }

    pub fn add_storage_tail_items(&self, kind: &str, count: u64) {
        self.storage_tail_items_total
            .with_label_values(&[kind])
            .inc_by(count as f64);
    }

    pub fn inc_storage_tail_path(&self, path: &str, outcome: &str) {
        self.storage_tail_path_total.with_label_values(&[path, outcome]).inc();
    }

    pub fn add_storage_head_frames_scanned(&self, count: u64) {
        self.storage_head_frames_scanned_total.inc_by(count as f64);
    }

    pub fn set_read_amplification_p50(&self, shard: &str, segs: f64) {
        self.read_amplification_p50.with_label_values(&[shard]).set(segs);
    }

    pub fn set_read_amplification_p95(&self, shard: &str, segs: f64) {
        self.read_amplification_p95.with_label_values(&[shard]).set(segs);
    }

    pub fn inc_kernel_launch(&self, kernel: &str, result: &str) {
        self.kernel_launch_total.with_label_values(&[kernel, result]).inc();
    }

    pub fn set_shardmap_version(&self, version: u64) {
        self.shardmap_version.set(version as f64);
    }

    pub fn inc_routing_lookup(&self, op: &str, outcome: &str) {
        self.routing_lookup_total.with_label_values(&[op, outcome]).inc();
    }

    pub fn observe_routing_lookup_seconds(&self, op: &str, secs: f64) {
        self.routing_lookup_seconds.with_label_values(&[op]).observe(secs);
    }

    pub fn inc_shard_request(&self, shard_id: &str, op: &str) {
        self.shard_requests_total.with_label_values(&[shard_id, op]).inc();
    }

    pub fn inc_replication_receive_total(&self, result: &str) {
        self.replication_receive_total.with_label_values(&[result]).inc();
    }

    pub fn set_replication_follower_watermark(&self, shard_id: &str, segment_seq: u64) {
        self.replication_follower_watermark
            .with_label_values(&[shard_id])
            .set(segment_seq as f64);
    }

    pub fn inc_replicated_commit_total(&self, result: &str) {
        self.replicated_commit_total.with_label_values(&[result]).inc();
    }

    pub fn set_replicated_commit_acks(&self, shard_id: &str, required: usize, actual: usize) {
        self.replicated_commit_required_acks
            .with_label_values(&[shard_id])
            .set(required as f64);
        self.replicated_commit_actual_acks
            .with_label_values(&[shard_id])
            .set(actual as f64);
        let deficit = required.saturating_sub(actual);
        self.replicated_commit_ack_deficit
            .with_label_values(&[shard_id])
            .set(deficit as f64);
    }

    pub fn set_replication_shard_epoch(&self, shard_id: &str, epoch: u64) {
        self.replication_shard_epoch
            .with_label_values(&[shard_id])
            .set(epoch as f64);
    }

    pub fn set_replication_follower_targets(&self, shard_id: &str, follower_count: usize) {
        self.replication_follower_targets
            .with_label_values(&[shard_id])
            .set(follower_count as f64);
        self.replication_topology_ok
            .with_label_values(&[shard_id])
            .set(if follower_count > 0 { 1.0 } else { 0.0 });
    }

    pub fn set_replication_lag_segments(
        &self,
        shard_id: &str,
        leader_segment_seq: u64,
        min_follower_acked_segment_seq: u64,
    ) {
        self.replication_leader_segment_seq
            .with_label_values(&[shard_id])
            .set(leader_segment_seq as f64);
        self.replication_min_follower_acked_segment_seq
            .with_label_values(&[shard_id])
            .set(min_follower_acked_segment_seq as f64);
        let lag = leader_segment_seq.saturating_sub(min_follower_acked_segment_seq);
        self.replication_lag_segments
            .with_label_values(&[shard_id])
            .set(lag as f64);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn observe_projection_tick(
        &self,
        shard: &str,
        frames_processed: u64,
        secs: f64,
        commit_id: u64,
        cursor_segment_seq: u64,
        cursor_offset: u64,
        living_rows: u64,
        relations_edges: u64,
        pressure_rows: u64,
        dependents_edges: u64,
    ) {
        self.projections_commit_id
            .with_label_values(&[shard])
            .set(commit_id as f64);
        self.projections_tick_frames_total
            .with_label_values(&[shard])
            .inc_by(frames_processed as f64);
        self.projections_tick_seconds
            .with_label_values(&[shard])
            .observe(secs.max(0.0));

        for (projection, rows) in [
            ("artifact_living_state", living_rows),
            ("artifact_relations", relations_edges),
            ("pressure_events", pressure_rows),
            ("artifact_dependents", dependents_edges),
        ] {
            self.projections_cursor_segment_seq
                .with_label_values(&[shard, projection])
                .set(cursor_segment_seq as f64);
            self.projections_cursor_offset
                .with_label_values(&[shard, projection])
                .set(cursor_offset as f64);
            self.projections_row_count
                .with_label_values(&[shard, projection])
                .set(rows as f64);
        }
    }

    pub fn inc_projection_tick_fail(&self, shard: &str) {
        self.projections_tick_fail_total.with_label_values(&[shard]).inc();
    }

    pub fn inc_shard_open_attempts(&self, caller: &str) {
        self.shard_open_attempts_total.with_label_values(&[caller]).inc();
    }

    pub fn inc_lock_contention(&self, caller: &str) {
        self.lock_contention_total.with_label_values(&[caller]).inc();
    }

    pub fn set_projection_snapshot_valid(&self, projection: &str, ok: bool) {
        self.projection_snapshot_valid
            .with_label_values(&[projection])
            .set(if ok { 1.0 } else { 0.0 });
    }

    pub fn sync_knowledge_authority(&self, state: &KnowledgeAuthorityV1) {
        for mode in [
            KnowledgeAuthorityModeV1::Shadow,
            KnowledgeAuthorityModeV1::DualWrite,
            KnowledgeAuthorityModeV1::ShadowRead,
            KnowledgeAuthorityModeV1::Authoritative,
        ] {
            self.knowledge_authority_mode
                .with_label_values(&[mode.as_str()])
                .set(if state.mode == mode { 1.0 } else { 0.0 });
        }
        for stage in [
            KnowledgeRolloutStageV1::InternalShadow,
            KnowledgeRolloutStageV1::TenantValidation,
            KnowledgeRolloutStageV1::InternalAuthority,
            KnowledgeRolloutStageV1::LimitedProductionAuthority,
            KnowledgeRolloutStageV1::FullProductionAuthority,
        ] {
            self.knowledge_rollout_stage
                .with_label_values(&[stage.as_str()])
                .set(if state.rollout_stage == stage { 1.0 } else { 0.0 });
        }
        self.knowledge_rollback_triggered
            .set(if state.rollback_triggered { 1.0 } else { 0.0 });
        self.set_knowledge_parity_outcome(state.last_parity_outcome.as_ref());
    }

    pub fn set_knowledge_parity_outcome(&self, outcome: Option<&KnowledgeParityOutcomeV1>) {
        let status = outcome.map_or(KnowledgeParityStatusV1::Unknown, |entry| entry.status);
        for candidate in [
            KnowledgeParityStatusV1::Unknown,
            KnowledgeParityStatusV1::Pass,
            KnowledgeParityStatusV1::Warn,
            KnowledgeParityStatusV1::Fail,
        ] {
            self.knowledge_parity_status
                .with_label_values(&[candidate.as_str()])
                .set(if candidate == status { 1.0 } else { 0.0 });
        }
        self.knowledge_parity_mismatch_count
            .set(outcome.map_or(0, |entry| entry.mismatch_count) as f64);
        self.knowledge_parity_cursor_missing_count
            .set(outcome.map_or(0, |entry| entry.cursor_missing_count) as f64);
        self.knowledge_parity_pass_ratio_bps
            .set(outcome.map_or(0, |entry| entry.pass_ratio_bps) as f64);
        self.knowledge_parity_projection_lag_ms
            .set(outcome.map_or(0, |entry| entry.projection_lag_ms) as f64);
    }

    pub fn inc_receipt_verify_total(&self, result: &str) {
        self.receipt_verify_total.with_label_values(&[result]).inc();
    }

    pub fn inc_receipt_verify_fail(&self, reason: &str) {
        self.receipt_verify_fail_total.with_label_values(&[reason]).inc();
    }

    pub fn inc_receipt_export_total(&self, status: &str) {
        self.receipt_export_total.with_label_values(&[status]).inc();
    }

    // ── v4.2 query metrics ─────────────────────────────────────────

    pub fn observe_graph_expand(&self, duration_secs: f64, nodes_visited: u32) {
        self.query_graph_expand_duration_seconds.observe(duration_secs.max(0.0));
        self.query_graph_expand_nodes_visited.observe(nodes_visited as f64);
    }

    pub fn observe_time_range(&self, duration_secs: f64, artifacts_scanned: u32) {
        self.query_time_range_duration_seconds.observe(duration_secs.max(0.0));
        self.query_time_range_artifacts_scanned
            .observe(artifacts_scanned as f64);
    }

    // ── v5 seal + retrieval ───────────────────────────────────────────

    pub fn observe_seal_duration(&self, phase: &str, duration_secs: f64) {
        self.seal_duration_seconds
            .with_label_values(&[phase])
            .observe(duration_secs.max(0.0));
    }

    pub fn set_seal_backlog_frames(&self, count: u64) {
        self.seal_backlog_frames.set(count as f64);
    }

    pub fn set_ccxi_missing_total(&self, count: u64) {
        self.ccxi_missing_total.set(count as f64);
    }

    pub fn render(&self) -> Result<String, prometheus::Error> {
        let metric_families = self.registry.gather();
        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        encoder.encode(&metric_families, &mut buf)?;
        Ok(String::from_utf8_lossy(&buf).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_types::BuildInfo;

    fn test_metrics() -> Metrics {
        let build = BuildInfo {
            version: "0.0.1-test".to_string(),
            commit: "abc123".to_string(),
        };
        Metrics::new(&build, "test-service")
    }

    #[test]
    fn metrics_new_creates_valid_instance() {
        let m = test_metrics();
        let rendered = m.render().unwrap();
        assert!(rendered.contains("build_info"));
        assert!(rendered.contains("corecrux_build_info"));
    }

    #[test]
    fn render_contains_build_info_labels() {
        let m = test_metrics();
        let rendered = m.render().unwrap();
        assert!(rendered.contains("0.0.1-test"));
        assert!(rendered.contains("abc123"));
        assert!(rendered.contains("test-service"));
    }

    #[test]
    fn set_io_backend_records_label() {
        let m = test_metrics();
        m.set_io_backend("gpu-dev");
        let rendered = m.render().unwrap();
        assert!(rendered.contains("gpu-dev"));
    }

    #[test]
    fn valve_gauges_toggle() {
        let m = test_metrics();
        m.set_valve_pause_ingest(true);
        m.set_valve_pause_compaction(false);
        m.set_valve_throttle(true);
        m.set_valve_read_only(false);
        m.set_valve_emergency_brake(true);
        let rendered = m.render().unwrap();
        assert!(rendered.contains("corecrux_valve_pause_ingest 1"));
        assert!(rendered.contains("corecrux_valve_pause_compaction 0"));
        assert!(rendered.contains("corecrux_valve_throttle 1"));
        assert!(rendered.contains("corecrux_valve_read_only 0"));
        assert!(rendered.contains("corecrux_valve_emergency_brake 1"));
    }

    #[test]
    fn set_valve_state_by_name() {
        let m = test_metrics();
        m.set_valve_state("test_valve", true);
        let rendered = m.render().unwrap();
        assert!(rendered.contains("test_valve"));
    }

    #[test]
    fn set_data_dir_space_records_values() {
        let m = test_metrics();
        m.set_data_dir_space(1_000_000, 500_000);
        let rendered = m.render().unwrap();
        // Prometheus may render 1000000 as "1e6" or "1000000" depending on version.
        assert!(
            rendered.contains("corecrux_data_dir_bytes_total 1e6")
                || rendered.contains("corecrux_data_dir_bytes_total 1000000"),
            "expected corecrux_data_dir_bytes_total in rendered output"
        );
        assert!(
            rendered.contains("corecrux_data_dir_bytes_free 500000")
                || rendered.contains("corecrux_data_dir_bytes_free 5e5"),
            "expected corecrux_data_dir_bytes_free in rendered output"
        );
    }

    #[test]
    fn set_shardmap_version_records_value() {
        let m = test_metrics();
        m.set_shardmap_version(42);
        let rendered = m.render().unwrap();
        assert!(rendered.contains("corecrux_shardmap_version 42"));
    }

    #[test]
    fn inc_write_confirmation_signed_and_unsigned() {
        let m = test_metrics();
        m.inc_write_confirmation(true);
        m.inc_write_confirmation(false);
        let rendered = m.render().unwrap();
        assert!(rendered.contains("corecrux_write_confirmations_total"));
    }

    #[test]
    fn set_backpressure_active() {
        let m = test_metrics();
        m.set_backpressure_active(true);
        let rendered = m.render().unwrap();
        assert!(rendered.contains("corecrux_backpressure_active_gauge 1"));
    }

    #[test]
    fn observe_append_latency() {
        let m = test_metrics();
        m.observe_append_latency_seconds("shard-0001", 0.005);
        let rendered = m.render().unwrap();
        assert!(rendered.contains("corecrux_append_latency_seconds"));
    }

    #[test]
    fn set_throttle_ratio() {
        let m = test_metrics();
        m.set_throttle_ratio(0.75);
        let rendered = m.render().unwrap();
        assert!(rendered.contains("corecrux_throttle_ratio 0.75"));
    }

    #[test]
    fn peer_cache_counters() {
        let m = test_metrics();
        m.touch_peer_cache_metrics();
        m.inc_peer_cache_hit();
        m.inc_peer_cache_miss();
        m.set_peer_cache_bytes(4096);
        let rendered = m.render().unwrap();
        assert!(rendered.contains("corecrux_peer_cache_hits_total 1"));
        assert!(rendered.contains("corecrux_peer_cache_misses_total 1"));
        assert!(rendered.contains("corecrux_peer_cache_bytes 4096"));
    }

    #[test]
    fn tail_cache_counters() {
        let m = test_metrics();
        m.inc_tail_cache_hit("shard-0001");
        m.inc_tail_cache_miss("shard-0001");
        m.set_tail_cache_bytes("shard-0001", 2048);
        let rendered = m.render().unwrap();
        assert!(rendered.contains("corecrux_tail_cache_hits_total"));
        assert!(rendered.contains("corecrux_tail_cache_misses_total"));
        assert!(rendered.contains("corecrux_tail_cache_bytes"));
    }

    #[test]
    fn dir_compaction_metrics() {
        let m = test_metrics();
        m.set_dir_l0_runs("shard-0001", 3);
        m.set_dir_level_bytes("shard-0001", 0, 1024);
        m.inc_dir_compaction("shard-0001", 0, 1, "ok");
        m.observe_dir_compaction_seconds("shard-0001", 0, 1, 0.5);
        m.add_dir_compaction_bytes_in("shard-0001", 512);
        m.add_dir_compaction_bytes_out("shard-0001", 256);
        m.set_dir_dead_extent_ratio("shard-0001", 0.15);
        let rendered = m.render().unwrap();
        assert!(rendered.contains("corecrux_dir_l0_runs"));
        assert!(rendered.contains("corecrux_dir_compactions_total"));
    }

    #[test]
    fn receipt_metrics() {
        let m = test_metrics();
        m.inc_receipt_verify_total("ok");
        m.inc_receipt_verify_fail("SIG_INVALID");
        m.inc_receipt_export_total("success");
        let rendered = m.render().unwrap();
        assert!(rendered.contains("corecrux_receipt_verify_total"));
        assert!(rendered.contains("corecrux_receipt_verify_fail_total"));
        assert!(rendered.contains("corecrux_receipt_export_total"));
    }

    #[test]
    fn seal_metrics() {
        let m = test_metrics();
        m.observe_seal_duration("seal", 0.02);
        m.set_seal_backlog_frames(100);
        m.set_ccxi_missing_total(5);
        let rendered = m.render().unwrap();
        assert!(rendered.contains("corecrux_seal_duration_seconds"));
        assert!(rendered.contains("corecrux_seal_backlog_frames 100"));
        assert!(rendered.contains("corecrux_ccxi_missing_total 5"));
    }

    #[test]
    fn replication_metrics() {
        let m = test_metrics();
        m.inc_replication_receive_total("ok");
        m.set_replication_follower_watermark("shard-0001", 42);
        m.inc_replicated_commit_total("ok");
        m.set_replicated_commit_acks("shard-0001", 2, 1);
        m.set_replication_shard_epoch("shard-0001", 3);
        m.set_replication_follower_targets("shard-0001", 2);
        m.set_replication_lag_segments("shard-0001", 100, 95);
        let rendered = m.render().unwrap();
        assert!(rendered.contains("corecrux_replication_receive_total"));
        assert!(rendered.contains("corecrux_replication_follower_watermark"));
        assert!(rendered.contains("corecrux_replication_lag_segments"));
    }

    #[test]
    fn projection_metrics() {
        let m = test_metrics();
        m.set_projection_snapshot_valid("artifact_living_state", true);
        m.inc_projection_tick_fail("shard-0001");
        let rendered = m.render().unwrap();
        assert!(rendered.contains("corecrux_projection_snapshot_valid"));
        assert!(rendered.contains("corecrux_projections_tick_fail_total"));
    }

    #[test]
    fn query_metrics() {
        let m = test_metrics();
        m.observe_graph_expand(0.01, 50);
        m.observe_time_range(0.005, 100);
        let rendered = m.render().unwrap();
        assert!(rendered.contains("corecrux_query_graph_expand_duration_seconds"));
        assert!(rendered.contains("corecrux_query_time_range_duration_seconds"));
    }

    #[test]
    fn read_retry_failed_total_returns_zero_initially() {
        let m = test_metrics();
        assert_eq!(m.read_retry_failed_total("corruption"), 0);
    }

    #[test]
    fn read_retry_increments_correctly() {
        let m = test_metrics();
        // read_retry_failed_total sums over ops "tail" and "range" only.
        m.inc_read_retry("tail", "corruption", "failed");
        let count = m.read_retry_failed_total("corruption");
        assert_eq!(count, 1);
    }
}
