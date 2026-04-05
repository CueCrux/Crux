// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use crate::auth::AuthMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitLevel {
    LocalCommit,
    ReplicatedCommit,
}

impl CommitLevel {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "local" | "LOCAL" | "local_commit" | "LOCAL_COMMIT" | "local-commit"
            | "LOCAL-COMMIT" => Some(Self::LocalCommit),
            "replicated" | "REPLICATED" | "replicated_commit" | "REPLICATED_COMMIT"
            | "replicated-commit" | "REPLICATED-COMMIT" => Some(Self::ReplicatedCommit),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalCommit => "LocalCommit",
            Self::ReplicatedCommit => "ReplicatedCommit",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreLockStrategy {
    Mutex,
    RwLock,
    Sharded,
}

impl StoreLockStrategy {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "mutex" | "MUTEX" => Some(Self::Mutex),
            "rwlock" | "RWLOCK" | "rw_lock" | "RW_LOCK" | "rw-lock" | "RW-LOCK" => {
                Some(Self::RwLock)
            }
            "sharded" | "SHARDED" => Some(Self::Sharded),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mutex => "mutex",
            Self::RwLock => "rwlock",
            Self::Sharded => "sharded",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendLaneScope {
    Gpu,
    Shard,
}

impl AppendLaneScope {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "gpu" | "GPU" => Some(Self::Gpu),
            "shard" | "SHARD" => Some(Self::Shard),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Gpu => "gpu",
            Self::Shard => "shard",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub http_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub data_dir: PathBuf,
    pub log_level: String,
    pub service_name: String,
    pub cluster_id: String,
    pub node_id_override: Option<String>,
    pub routing_reload_interval_ms: u64,
    pub routing_strict_client_version: bool,
    pub dev_split_shards: u32,
    pub commit_level: CommitLevel,
    pub follower_reads_enabled: bool,
    pub replicated_commit_timeout_ms: u64,
    pub replicated_commit_require_all_followers: bool,
    pub auth_mode: AuthMode,

    // Phase 9: IO backend selection (gpu-dev vs gpu-gds).
    pub io_backend: String,
    pub gds_require_no_compat_mode: bool,
    pub gds_preflight_io: bool,
    pub gds_library_path: Option<String>,

    // Phase 9: Optional hardware-profile pinning (fail /readyz on mismatch).
    pub hardware_profile_path: Option<PathBuf>,

    // Phase 7 projections (Living Objects).
    pub projections_enabled: bool,
    pub projections_batch_frames: u32,
    pub projections_tick_interval_ms: u64,

    // Admin force-seal: allows force-sealing head segments via admin actions.
    pub admin_force_seal_enabled: bool,

    // CoreCrux v5: build .ccxi companion indexes at seal time for BM25 retrieval.
    pub build_ccxi: bool,

    // Phase 8 receipts: bytes-first fetch + signature verification projection.
    pub receipts_verify_enabled: bool,
    pub receipts_recompute_candidate_digest: bool,
    pub receipts_keyring_path: Option<PathBuf>,
    pub receipts_keyring_json: Option<String>,

    // Replay/batching path configuration.
    pub replay_batch_max_events: u32,
    pub replay_batch_max_bytes: u32,
    pub replay_many_max_reads: u32,
    pub replay_use_batched_rpc_default: bool,
    pub store_lock_strategy: StoreLockStrategy,
    pub append_lane_enabled: bool,
    pub append_lane_scope: AppendLaneScope,
    pub append_gpu_lane_fanout: usize,
    pub tail_cache_enabled: bool,
    pub read_retry_failed_readyz_threshold: u64,
    pub backpressure_high_watermark_ratio: f64,
    pub backpressure_low_watermark_ratio: f64,
    pub backpressure_retry_after_ms: u32,

    // Phase 9 operator actions policy bounds.
    pub operator_action_max_pending: usize,
    pub operator_action_timeout_secs: u64,

    // Phase 5 scrub scheduler knobs.
    pub scrub_scheduler_enabled: bool,
    pub scrub_interval_secs: u64,
    pub scrub_scope: String,
    pub scrub_mode: String,
    pub scrub_sample_rate: f64,
    pub capacity_guard_enabled: bool,
    pub capacity_guard_interval_secs: u64,
    pub capacity_warning_free_ratio: f64,
    pub capacity_critical_free_ratio: f64,
    pub capacity_emergency_free_ratio: f64,
    pub capacity_resume_free_ratio: f64,

    // Phase 4 ingest bounds / idempotency knobs.
    pub max_events_per_batch: usize,
    pub max_batch_bytes: usize,
    pub max_event_id_bytes: usize,
    pub idem_hot_capacity_entries: usize,
    pub event_id_hash_prefix_len: usize,
    pub cold_scan_max_segments: usize,
    pub append_group_commit_batches: usize,
    pub append_group_commit_max_delay_ms: u64,
    // Phase 6 directory LSM compaction.
    pub enable_directory_compaction: bool,
    pub dir_l0_max_runs: usize,
}

pub fn load_config() -> Config {
    let http_host: IpAddr = std::env::var("CORECRUXD_HTTP_HOST")
        .unwrap_or_else(|_| "127.0.0.1".to_string())
        .parse()
        .unwrap_or_else(|_| "127.0.0.1".parse().expect("default http host parses"));
    let http_port: u16 = std::env::var("CORECRUXD_HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(14800);

    let grpc_host: IpAddr = std::env::var("CORECRUXD_GRPC_HOST")
        .unwrap_or_else(|_| "127.0.0.1".to_string())
        .parse()
        .unwrap_or_else(|_| "127.0.0.1".parse().expect("default grpc host parses"));
    let grpc_port: u16 = std::env::var("CORECRUXD_GRPC_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4007);

    let data_dir =
        std::env::var("CORECRUXD_DATA_DIR").unwrap_or_else(|_| "../CoreCruxData/v3".to_string());
    let log_level = std::env::var("CORECRUXD_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    let service_name =
        std::env::var("CORECRUXD_SERVICE").unwrap_or_else(|_| "corecruxd".to_string());
    let cluster_id = std::env::var("CORECRUXD_CLUSTER_ID").unwrap_or_else(|_| "dev".to_string());
    let node_id_override = std::env::var("CORECRUXD_NODE_ID").ok();
    let routing_reload_interval_ms = std::env::var("CORECRUXD_ROUTING_RELOAD_INTERVAL_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    let routing_strict_client_version = std::env::var("CORECRUXD_ROUTING_STRICT_CLIENT_VERSION")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    let dev_split_shards = std::env::var("CORECRUXD_DEV_SPLIT_SHARDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let commit_level = std::env::var("CORECRUXD_COMMIT_LEVEL")
        .ok()
        .as_deref()
        .and_then(CommitLevel::parse)
        .unwrap_or(CommitLevel::LocalCommit);
    let follower_reads_enabled = std::env::var("CORECRUXD_FOLLOWER_READS_ENABLED")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(matches!(commit_level, CommitLevel::ReplicatedCommit));
    let replicated_commit_timeout_ms = std::env::var("CORECRUXD_REPLICATED_COMMIT_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000)
        .clamp(100, 120_000);
    let replicated_commit_require_all_followers =
        std::env::var("CORECRUXD_REPLICATED_COMMIT_REQUIRE_ALL_FOLLOWERS")
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(true);

    let auth_mode = std::env::var("CORECRUXD_AUTH_MODE")
        .ok()
        .and_then(|s| AuthMode::parse(&s))
        .unwrap_or(AuthMode::DevScopes);

    let io_backend =
        std::env::var("CORECRUXD_IO_BACKEND").unwrap_or_else(|_| "gpu-dev".to_string());
    let gds_require_no_compat_mode = std::env::var("CORECRUXD_GDS_REQUIRE_NO_COMPAT_MODE")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(true);
    let gds_preflight_io = std::env::var("CORECRUXD_GDS_PREFLIGHT_IO")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(true);
    let gds_library_path = std::env::var("CORECRUXD_GDS_LIBRARY_PATH").ok();

    let hardware_profile_path = std::env::var("CORECRUXD_HARDWARE_PROFILE_PATH")
        .ok()
        .map(PathBuf::from);

    let build_ccxi = std::env::var("CORECRUXD_BUILD_CCXI")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);

    let projections_enabled = std::env::var("CORECRUXD_PROJECTIONS_ENABLED")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    let projections_batch_frames = std::env::var("CORECRUXD_PROJECTIONS_BATCH_FRAMES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1024);
    let projections_tick_interval_ms = std::env::var("CORECRUXD_PROJECTIONS_TICK_INTERVAL_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);

    let admin_force_seal_enabled = std::env::var("CORECRUXD_ADMIN_FORCE_SEAL")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);

    let receipts_verify_enabled = std::env::var("CORECRUXD_RECEIPTS_VERIFY_ENABLED")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(true);
    let receipts_recompute_candidate_digest =
        std::env::var("CORECRUXD_RECEIPTS_RECOMPUTE_CANDIDATE_DIGEST")
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
    let receipts_keyring_path = std::env::var("CORECRUXD_RECEIPTS_KEYRING_PATH")
        .ok()
        .map(PathBuf::from);
    let receipts_keyring_json = std::env::var("CORECRUXD_RECEIPTS_KEYRING_JSON").ok();
    let replay_batch_max_events = std::env::var("CORECRUXD_REPLAY_BATCH_MAX_EVENTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64)
        .max(1);
    let replay_batch_max_bytes = std::env::var("CORECRUXD_REPLAY_BATCH_MAX_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(262_144)
        .max(1024);
    let replay_many_max_reads = std::env::var("CORECRUXD_REPLAY_MANY_MAX_READS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(64)
        .max(1);
    let replay_use_batched_rpc_default = std::env::var("CORECRUXD_REPLAY_USE_BATCHED_RPC_DEFAULT")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(true);
    let store_lock_strategy = std::env::var("CORECRUXD_STORE_LOCK_STRATEGY")
        .ok()
        .as_deref()
        .and_then(StoreLockStrategy::parse)
        .unwrap_or(StoreLockStrategy::Sharded);
    let append_lane_enabled = std::env::var("CORECRUXD_APPEND_LANE_ENABLED")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(true);
    let append_lane_scope = std::env::var("CORECRUXD_APPEND_LANE_SCOPE")
        .ok()
        .as_deref()
        .and_then(AppendLaneScope::parse)
        // Keep default lane scope aligned with current store write-lock domain (per-GPU store).
        // Per-shard lane scope is available via env for experiments, but shifts queueing into
        // store.lockWait until store-level shard lock domains are implemented.
        .unwrap_or(AppendLaneScope::Gpu);
    let append_gpu_lane_fanout = std::env::var("CORECRUXD_APPEND_GPU_LANE_FANOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1)
        .clamp(1, 64);
    let tail_cache_enabled = std::env::var("CORECRUXD_TAIL_CACHE_ENABLED")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(true);
    let read_retry_failed_readyz_threshold =
        std::env::var("CORECRUXD_READ_RETRY_FAILED_READYZ_THRESHOLD")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);
    let mut backpressure_high_watermark_ratio: f64 =
        std::env::var("CORECRUXD_BACKPRESSURE_HIGH_WATERMARK_RATIO")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.90);
    let mut backpressure_low_watermark_ratio: f64 =
        std::env::var("CORECRUXD_BACKPRESSURE_LOW_WATERMARK_RATIO")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.80);
    backpressure_high_watermark_ratio = backpressure_high_watermark_ratio.clamp(0.01, 0.99);
    backpressure_low_watermark_ratio = backpressure_low_watermark_ratio.clamp(0.0, 0.98);
    if backpressure_low_watermark_ratio >= backpressure_high_watermark_ratio {
        backpressure_low_watermark_ratio =
            (backpressure_high_watermark_ratio - 0.05).clamp(0.0, 0.95);
    }
    let backpressure_retry_after_ms = std::env::var("CORECRUXD_BACKPRESSURE_RETRY_AFTER_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(250)
        .clamp(1, 60_000);

    let operator_action_max_pending = std::env::var("CORECRUXD_OPERATOR_ACTION_MAX_PENDING")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(128)
        .max(1);
    let operator_action_timeout_secs = std::env::var("CORECRUXD_OPERATOR_ACTION_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(900)
        .clamp(5, 86_400);

    let scrub_scheduler_enabled = std::env::var("CORECRUXD_SCRUB_SCHEDULER_ENABLED")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);
    let scrub_interval_secs = std::env::var("CORECRUXD_SCRUB_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300)
        .clamp(10, 86_400);
    let scrub_scope =
        std::env::var("CORECRUXD_SCRUB_SCOPE").unwrap_or_else(|_| "recent".to_string());
    let scrub_mode =
        std::env::var("CORECRUXD_SCRUB_MODE").unwrap_or_else(|_| "sampled".to_string());
    let scrub_sample_rate: f64 = std::env::var("CORECRUXD_SCRUB_SAMPLE_RATE")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.25)
        .clamp(0.0, 1.0);
    let capacity_guard_enabled = std::env::var("CORECRUXD_CAPACITY_GUARD_ENABLED")
        .ok()
        .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(true);
    let capacity_guard_interval_secs = std::env::var("CORECRUXD_CAPACITY_GUARD_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30)
        .clamp(10, 3_600);
    let capacity_warning_free_ratio: f64 = std::env::var("CORECRUXD_CAPACITY_WARNING_FREE_RATIO")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.20)
        .clamp(0.01, 0.95);
    let capacity_critical_free_ratio: f64 = std::env::var("CORECRUXD_CAPACITY_CRITICAL_FREE_RATIO")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.10)
        .clamp(0.01, 0.90);
    let capacity_emergency_free_ratio: f64 =
        std::env::var("CORECRUXD_CAPACITY_EMERGENCY_FREE_RATIO")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.10)
            .clamp(0.01, 0.90);
    let mut capacity_resume_free_ratio: f64 = std::env::var("CORECRUXD_CAPACITY_RESUME_FREE_RATIO")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.20)
        .clamp(0.02, 0.99);
    let capacity_warning_free_ratio = capacity_warning_free_ratio
        .max(capacity_critical_free_ratio)
        .max(capacity_emergency_free_ratio);
    let capacity_critical_free_ratio = capacity_critical_free_ratio
        .max(capacity_emergency_free_ratio)
        .min(capacity_warning_free_ratio);
    let capacity_emergency_free_ratio =
        capacity_emergency_free_ratio.min(capacity_critical_free_ratio);
    if capacity_resume_free_ratio <= capacity_emergency_free_ratio {
        capacity_resume_free_ratio =
            (capacity_emergency_free_ratio + 0.05).min(capacity_warning_free_ratio);
    }

    Config {
        http_addr: SocketAddr::new(http_host, http_port),
        grpc_addr: SocketAddr::new(grpc_host, grpc_port),
        data_dir: PathBuf::from(data_dir),
        log_level,
        service_name,
        cluster_id,
        node_id_override,
        routing_reload_interval_ms,
        routing_strict_client_version,
        dev_split_shards,
        commit_level,
        follower_reads_enabled,
        replicated_commit_timeout_ms,
        replicated_commit_require_all_followers,
        auth_mode,

        io_backend,
        gds_require_no_compat_mode,
        gds_preflight_io,
        gds_library_path,
        hardware_profile_path,

        build_ccxi,

        projections_enabled,
        projections_batch_frames,
        projections_tick_interval_ms,

        admin_force_seal_enabled,

        receipts_verify_enabled,
        receipts_recompute_candidate_digest,
        receipts_keyring_path,
        receipts_keyring_json,
        replay_batch_max_events,
        replay_batch_max_bytes,
        replay_many_max_reads,
        replay_use_batched_rpc_default,
        store_lock_strategy,
        append_lane_enabled,
        append_lane_scope,
        append_gpu_lane_fanout,
        tail_cache_enabled,
        read_retry_failed_readyz_threshold,
        backpressure_high_watermark_ratio,
        backpressure_low_watermark_ratio,
        backpressure_retry_after_ms,
        operator_action_max_pending,
        operator_action_timeout_secs,
        scrub_scheduler_enabled,
        scrub_interval_secs,
        scrub_scope,
        scrub_mode,
        scrub_sample_rate,
        capacity_guard_enabled,
        capacity_guard_interval_secs,
        capacity_warning_free_ratio,
        capacity_critical_free_ratio,
        capacity_emergency_free_ratio,
        capacity_resume_free_ratio,

        max_events_per_batch: std::env::var("CORECRUXD_MAX_EVENTS_PER_BATCH")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1024),
        max_batch_bytes: std::env::var("CORECRUXD_MAX_BATCH_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(16 * 1024 * 1024),
        max_event_id_bytes: std::env::var("CORECRUXD_MAX_EVENT_ID_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(128),
        idem_hot_capacity_entries: std::env::var("CORECRUXD_IDEM_HOT_CAPACITY_ENTRIES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100_000),
        event_id_hash_prefix_len: std::env::var("CORECRUXD_EVENT_ID_HASH_PREFIX_LEN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(16),
        cold_scan_max_segments: std::env::var("CORECRUXD_COLD_SCAN_MAX_SEGMENTS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(256),
        append_group_commit_batches: std::env::var("CORECRUXD_APPEND_GROUP_COMMIT_BATCHES")
            .ok()
            .and_then(|s| s.parse().ok())
            // Perf default tuned from append sweep: b16,d0 lowered lane/fence waits while
            // improving throughput and p95 versus nearby batch sizes on this host.
            .unwrap_or(16)
            .max(1),
        append_group_commit_max_delay_ms: std::env::var(
            "CORECRUXD_APPEND_GROUP_COMMIT_MAX_DELAY_MS",
        )
        .ok()
        .and_then(|s| s.parse().ok())
        // Prefer batch-count boundary by default; keep bounded delay available via env override.
        .unwrap_or(0),
        enable_directory_compaction: std::env::var("CORECRUXD_ENABLE_DIRECTORY_COMPACTION")
            .ok()
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false),
        dir_l0_max_runs: std::env::var("CORECRUXD_DIR_L0_MAX_RUNS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8),
    }
}

#[cfg(test)]
mod tests {
    use super::{AppendLaneScope, CommitLevel, StoreLockStrategy};

    #[test]
    fn commit_level_parse_accepts_aliases() {
        assert_eq!(CommitLevel::parse("local"), Some(CommitLevel::LocalCommit));
        assert_eq!(
            CommitLevel::parse("LOCAL_COMMIT"),
            Some(CommitLevel::LocalCommit)
        );
        assert_eq!(
            CommitLevel::parse("replicated"),
            Some(CommitLevel::ReplicatedCommit)
        );
        assert_eq!(
            CommitLevel::parse("REPLICATED-COMMIT"),
            Some(CommitLevel::ReplicatedCommit)
        );
    }

    #[test]
    fn commit_level_parse_rejects_invalid_values() {
        assert_eq!(CommitLevel::parse(""), None);
        assert_eq!(CommitLevel::parse("replicatedCommit"), None);
        assert_eq!(CommitLevel::parse("unknown"), None);
    }

    #[test]
    fn commit_level_as_str_is_stable() {
        assert_eq!(CommitLevel::LocalCommit.as_str(), "LocalCommit");
        assert_eq!(CommitLevel::ReplicatedCommit.as_str(), "ReplicatedCommit");
    }

    #[test]
    fn store_lock_strategy_parse_accepts_aliases() {
        assert_eq!(
            StoreLockStrategy::parse("mutex"),
            Some(StoreLockStrategy::Mutex)
        );
        assert_eq!(
            StoreLockStrategy::parse("RW_LOCK"),
            Some(StoreLockStrategy::RwLock)
        );
        assert_eq!(
            StoreLockStrategy::parse("sharded"),
            Some(StoreLockStrategy::Sharded)
        );
    }

    #[test]
    fn store_lock_strategy_parse_rejects_invalid_values() {
        assert_eq!(StoreLockStrategy::parse(""), None);
        assert_eq!(StoreLockStrategy::parse("rw"), None);
    }

    #[test]
    fn append_lane_scope_parse_accepts_aliases() {
        assert_eq!(AppendLaneScope::parse("gpu"), Some(AppendLaneScope::Gpu));
        assert_eq!(
            AppendLaneScope::parse("SHARD"),
            Some(AppendLaneScope::Shard)
        );
    }

    #[test]
    fn append_lane_scope_parse_rejects_invalid_values() {
        assert_eq!(AppendLaneScope::parse(""), None);
        assert_eq!(AppendLaneScope::parse("store"), None);
    }

    #[test]
    fn append_lane_scope_as_str_is_stable() {
        assert_eq!(AppendLaneScope::Gpu.as_str(), "gpu");
        assert_eq!(AppendLaneScope::Shard.as_str(), "shard");
    }

    #[test]
    fn store_lock_strategy_as_str_is_stable() {
        assert_eq!(StoreLockStrategy::Mutex.as_str(), "mutex");
        assert_eq!(StoreLockStrategy::RwLock.as_str(), "rwlock");
        assert_eq!(StoreLockStrategy::Sharded.as_str(), "sharded");
    }

    #[test]
    fn commit_level_parse_trims_whitespace() {
        assert_eq!(
            CommitLevel::parse("  local  "),
            Some(CommitLevel::LocalCommit)
        );
        assert_eq!(
            CommitLevel::parse("\treplicated\n"),
            Some(CommitLevel::ReplicatedCommit)
        );
    }

    #[test]
    fn store_lock_strategy_parse_trims_whitespace() {
        assert_eq!(
            StoreLockStrategy::parse("  mutex  "),
            Some(StoreLockStrategy::Mutex)
        );
        assert_eq!(
            StoreLockStrategy::parse("\trwlock\n"),
            Some(StoreLockStrategy::RwLock)
        );
    }

    #[test]
    fn append_lane_scope_parse_trims_whitespace() {
        assert_eq!(
            AppendLaneScope::parse("  gpu  "),
            Some(AppendLaneScope::Gpu)
        );
    }

    #[test]
    fn commit_level_all_parse_aliases() {
        // LocalCommit aliases
        for alias in &[
            "local",
            "LOCAL",
            "local_commit",
            "LOCAL_COMMIT",
            "local-commit",
            "LOCAL-COMMIT",
        ] {
            assert_eq!(
                CommitLevel::parse(alias),
                Some(CommitLevel::LocalCommit),
                "expected LocalCommit for alias '{alias}'"
            );
        }
        // ReplicatedCommit aliases
        for alias in &[
            "replicated",
            "REPLICATED",
            "replicated_commit",
            "REPLICATED_COMMIT",
            "replicated-commit",
            "REPLICATED-COMMIT",
        ] {
            assert_eq!(
                CommitLevel::parse(alias),
                Some(CommitLevel::ReplicatedCommit),
                "expected ReplicatedCommit for alias '{alias}'"
            );
        }
    }

    #[test]
    fn store_lock_strategy_all_parse_aliases() {
        for alias in &["mutex", "MUTEX"] {
            assert_eq!(
                StoreLockStrategy::parse(alias),
                Some(StoreLockStrategy::Mutex),
                "expected Mutex for alias '{alias}'"
            );
        }
        for alias in &["rwlock", "RWLOCK", "rw_lock", "RW_LOCK", "rw-lock", "RW-LOCK"] {
            assert_eq!(
                StoreLockStrategy::parse(alias),
                Some(StoreLockStrategy::RwLock),
                "expected RwLock for alias '{alias}'"
            );
        }
        for alias in &["sharded", "SHARDED"] {
            assert_eq!(
                StoreLockStrategy::parse(alias),
                Some(StoreLockStrategy::Sharded),
                "expected Sharded for alias '{alias}'"
            );
        }
    }

    #[test]
    fn append_lane_scope_all_parse_aliases() {
        for alias in &["gpu", "GPU"] {
            assert_eq!(
                AppendLaneScope::parse(alias),
                Some(AppendLaneScope::Gpu),
                "expected Gpu for alias '{alias}'"
            );
        }
        for alias in &["shard", "SHARD"] {
            assert_eq!(
                AppendLaneScope::parse(alias),
                Some(AppendLaneScope::Shard),
                "expected Shard for alias '{alias}'"
            );
        }
    }

    fn env_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// Helper: clear all CORECRUXD_* env vars so load_config sees clean defaults.
    fn clear_corecruxd_env() {
        let vars: Vec<String> = std::env::vars()
            .filter(|(k, _)| k.starts_with("CORECRUXD_"))
            .map(|(k, _)| k)
            .collect();
        for k in vars {
            std::env::remove_var(&k);
        }
    }

    #[test]
    #[serial_test::serial]
    fn load_config_defaults() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        let cfg = super::load_config();

        assert_eq!(cfg.http_addr.port(), 14800);
        assert_eq!(cfg.http_addr.ip().to_string(), "127.0.0.1");
        assert_eq!(cfg.grpc_addr.port(), 4007);
        assert_eq!(cfg.grpc_addr.ip().to_string(), "127.0.0.1");
        assert_eq!(cfg.data_dir.to_str().unwrap(), "../CoreCruxData/v3");
        assert_eq!(cfg.log_level, "info");
        assert_eq!(cfg.service_name, "corecruxd");
        assert_eq!(cfg.cluster_id, "dev");
        assert_eq!(cfg.node_id_override, None);
        assert_eq!(cfg.routing_reload_interval_ms, 1000);
        assert!(!cfg.routing_strict_client_version);
        assert_eq!(cfg.dev_split_shards, 4);
        assert_eq!(cfg.commit_level, CommitLevel::LocalCommit);
        // follower_reads_enabled defaults to false when commit_level is LocalCommit
        assert!(!cfg.follower_reads_enabled);
        assert_eq!(cfg.replicated_commit_timeout_ms, 5000);
        assert!(cfg.replicated_commit_require_all_followers);
        assert_eq!(cfg.auth_mode, crate::auth::AuthMode::DevScopes);
        assert_eq!(cfg.io_backend, "gpu-dev");
        assert!(cfg.gds_require_no_compat_mode);
        assert!(cfg.gds_preflight_io);
        assert_eq!(cfg.gds_library_path, None);
        assert_eq!(cfg.hardware_profile_path, None);
        assert!(!cfg.build_ccxi);
        assert!(!cfg.projections_enabled);
        assert_eq!(cfg.projections_batch_frames, 1024);
        assert_eq!(cfg.projections_tick_interval_ms, 1000);
        assert!(!cfg.admin_force_seal_enabled);
        assert!(cfg.receipts_verify_enabled);
        assert!(!cfg.receipts_recompute_candidate_digest);
        assert_eq!(cfg.receipts_keyring_path, None);
        assert_eq!(cfg.receipts_keyring_json, None);
        assert_eq!(cfg.replay_batch_max_events, 64);
        assert_eq!(cfg.replay_batch_max_bytes, 262_144);
        assert_eq!(cfg.replay_many_max_reads, 64);
        assert!(cfg.replay_use_batched_rpc_default);
        assert_eq!(cfg.store_lock_strategy, StoreLockStrategy::Sharded);
        assert!(cfg.append_lane_enabled);
        assert_eq!(cfg.append_lane_scope, AppendLaneScope::Gpu);
        assert_eq!(cfg.append_gpu_lane_fanout, 1);
        assert!(cfg.tail_cache_enabled);
        assert_eq!(cfg.read_retry_failed_readyz_threshold, 3);
        // backpressure defaults
        assert!((cfg.backpressure_high_watermark_ratio - 0.90).abs() < 0.001);
        assert!((cfg.backpressure_low_watermark_ratio - 0.80).abs() < 0.001);
        assert_eq!(cfg.backpressure_retry_after_ms, 250);
        // operator actions
        assert_eq!(cfg.operator_action_max_pending, 128);
        assert_eq!(cfg.operator_action_timeout_secs, 900);
        // scrub
        assert!(!cfg.scrub_scheduler_enabled);
        assert_eq!(cfg.scrub_interval_secs, 300);
        assert_eq!(cfg.scrub_scope, "recent");
        assert_eq!(cfg.scrub_mode, "sampled");
        assert!((cfg.scrub_sample_rate - 0.25).abs() < 0.001);
        // capacity
        assert!(cfg.capacity_guard_enabled);
        assert_eq!(cfg.capacity_guard_interval_secs, 30);
        // ingest bounds
        assert_eq!(cfg.max_events_per_batch, 1024);
        assert_eq!(cfg.max_batch_bytes, 16 * 1024 * 1024);
        assert_eq!(cfg.max_event_id_bytes, 128);
        assert_eq!(cfg.idem_hot_capacity_entries, 100_000);
        assert_eq!(cfg.event_id_hash_prefix_len, 16);
        assert_eq!(cfg.cold_scan_max_segments, 256);
        assert_eq!(cfg.append_group_commit_batches, 16);
        assert_eq!(cfg.append_group_commit_max_delay_ms, 0);
        assert!(!cfg.enable_directory_compaction);
        assert_eq!(cfg.dir_l0_max_runs, 8);
    }

    #[test]
    #[serial_test::serial]
    fn load_config_custom_values() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        std::env::set_var("CORECRUXD_HTTP_HOST", "0.0.0.0");
        std::env::set_var("CORECRUXD_HTTP_PORT", "9999");
        std::env::set_var("CORECRUXD_GRPC_HOST", "0.0.0.0");
        std::env::set_var("CORECRUXD_GRPC_PORT", "9998");
        std::env::set_var("CORECRUXD_DATA_DIR", "/tmp/test-data");
        std::env::set_var("CORECRUXD_LOG_LEVEL", "debug");
        std::env::set_var("CORECRUXD_SERVICE", "test-svc");
        std::env::set_var("CORECRUXD_CLUSTER_ID", "prod");
        std::env::set_var("CORECRUXD_NODE_ID", "node-42");
        std::env::set_var("CORECRUXD_ROUTING_RELOAD_INTERVAL_MS", "5000");
        std::env::set_var("CORECRUXD_ROUTING_STRICT_CLIENT_VERSION", "true");
        std::env::set_var("CORECRUXD_DEV_SPLIT_SHARDS", "8");
        std::env::set_var("CORECRUXD_COMMIT_LEVEL", "replicated");
        std::env::set_var("CORECRUXD_FOLLOWER_READS_ENABLED", "1");
        std::env::set_var("CORECRUXD_REPLICATED_COMMIT_TIMEOUT_MS", "10000");
        std::env::set_var("CORECRUXD_REPLICATED_COMMIT_REQUIRE_ALL_FOLLOWERS", "false");
        std::env::set_var("CORECRUXD_AUTH_MODE", "off");
        std::env::set_var("CORECRUXD_IO_BACKEND", "gpu-gds");
        std::env::set_var("CORECRUXD_GDS_REQUIRE_NO_COMPAT_MODE", "false");
        std::env::set_var("CORECRUXD_GDS_PREFLIGHT_IO", "false");
        std::env::set_var("CORECRUXD_BUILD_CCXI", "true");
        std::env::set_var("CORECRUXD_PROJECTIONS_ENABLED", "1");
        std::env::set_var("CORECRUXD_PROJECTIONS_BATCH_FRAMES", "2048");
        std::env::set_var("CORECRUXD_PROJECTIONS_TICK_INTERVAL_MS", "500");
        std::env::set_var("CORECRUXD_ADMIN_FORCE_SEAL", "yes");
        std::env::set_var("CORECRUXD_RECEIPTS_VERIFY_ENABLED", "false");
        std::env::set_var("CORECRUXD_RECEIPTS_RECOMPUTE_CANDIDATE_DIGEST", "true");
        std::env::set_var("CORECRUXD_STORE_LOCK_STRATEGY", "rwlock");
        std::env::set_var("CORECRUXD_APPEND_LANE_ENABLED", "false");
        std::env::set_var("CORECRUXD_APPEND_LANE_SCOPE", "shard");
        std::env::set_var("CORECRUXD_APPEND_GPU_LANE_FANOUT", "4");
        std::env::set_var("CORECRUXD_TAIL_CACHE_ENABLED", "false");
        std::env::set_var("CORECRUXD_REPLAY_USE_BATCHED_RPC_DEFAULT", "false");
        std::env::set_var("CORECRUXD_SCRUB_SCHEDULER_ENABLED", "true");
        std::env::set_var("CORECRUXD_SCRUB_INTERVAL_SECS", "600");
        std::env::set_var("CORECRUXD_SCRUB_SCOPE", "full");
        std::env::set_var("CORECRUXD_SCRUB_MODE", "exhaustive");
        std::env::set_var("CORECRUXD_SCRUB_SAMPLE_RATE", "0.5");
        std::env::set_var("CORECRUXD_ENABLE_DIRECTORY_COMPACTION", "true");
        std::env::set_var("CORECRUXD_DIR_L0_MAX_RUNS", "16");

        let cfg = super::load_config();

        assert_eq!(cfg.http_addr.port(), 9999);
        assert_eq!(cfg.http_addr.ip().to_string(), "0.0.0.0");
        assert_eq!(cfg.grpc_addr.port(), 9998);
        assert_eq!(cfg.grpc_addr.ip().to_string(), "0.0.0.0");
        assert_eq!(cfg.data_dir.to_str().unwrap(), "/tmp/test-data");
        assert_eq!(cfg.log_level, "debug");
        assert_eq!(cfg.service_name, "test-svc");
        assert_eq!(cfg.cluster_id, "prod");
        assert_eq!(cfg.node_id_override.as_deref(), Some("node-42"));
        assert_eq!(cfg.routing_reload_interval_ms, 5000);
        assert!(cfg.routing_strict_client_version);
        assert_eq!(cfg.dev_split_shards, 8);
        assert_eq!(cfg.commit_level, CommitLevel::ReplicatedCommit);
        assert!(cfg.follower_reads_enabled);
        assert_eq!(cfg.replicated_commit_timeout_ms, 10000);
        assert!(!cfg.replicated_commit_require_all_followers);
        assert_eq!(cfg.auth_mode, crate::auth::AuthMode::Off);
        assert_eq!(cfg.io_backend, "gpu-gds");
        assert!(!cfg.gds_require_no_compat_mode);
        assert!(!cfg.gds_preflight_io);
        assert!(cfg.build_ccxi);
        assert!(cfg.projections_enabled);
        assert_eq!(cfg.projections_batch_frames, 2048);
        assert_eq!(cfg.projections_tick_interval_ms, 500);
        assert!(cfg.admin_force_seal_enabled);
        assert!(!cfg.receipts_verify_enabled);
        assert!(cfg.receipts_recompute_candidate_digest);
        assert_eq!(cfg.store_lock_strategy, StoreLockStrategy::RwLock);
        assert!(!cfg.append_lane_enabled);
        assert_eq!(cfg.append_lane_scope, AppendLaneScope::Shard);
        assert_eq!(cfg.append_gpu_lane_fanout, 4);
        assert!(!cfg.tail_cache_enabled);
        assert!(!cfg.replay_use_batched_rpc_default);
        assert!(cfg.scrub_scheduler_enabled);
        assert_eq!(cfg.scrub_interval_secs, 600);
        assert_eq!(cfg.scrub_scope, "full");
        assert_eq!(cfg.scrub_mode, "exhaustive");
        assert!((cfg.scrub_sample_rate - 0.5).abs() < 0.001);
        assert!(cfg.enable_directory_compaction);
        assert_eq!(cfg.dir_l0_max_runs, 16);

        // Clean up
        clear_corecruxd_env();
    }

    #[test]
    #[serial_test::serial]
    fn load_config_clamping_replicated_commit_timeout() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        // Below minimum (100ms)
        std::env::set_var("CORECRUXD_REPLICATED_COMMIT_TIMEOUT_MS", "1");
        let cfg = super::load_config();
        assert_eq!(cfg.replicated_commit_timeout_ms, 100);

        // Above maximum (120_000ms)
        std::env::set_var("CORECRUXD_REPLICATED_COMMIT_TIMEOUT_MS", "999999");
        let cfg = super::load_config();
        assert_eq!(cfg.replicated_commit_timeout_ms, 120_000);

        clear_corecruxd_env();
    }

    #[test]
    #[serial_test::serial]
    fn load_config_clamping_append_gpu_lane_fanout() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        std::env::set_var("CORECRUXD_APPEND_GPU_LANE_FANOUT", "0");
        let cfg = super::load_config();
        assert_eq!(cfg.append_gpu_lane_fanout, 1);

        std::env::set_var("CORECRUXD_APPEND_GPU_LANE_FANOUT", "999");
        let cfg = super::load_config();
        assert_eq!(cfg.append_gpu_lane_fanout, 64);

        clear_corecruxd_env();
    }

    #[test]
    #[serial_test::serial]
    fn load_config_clamping_backpressure_ratios() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        // Set low >= high to trigger the correction logic
        std::env::set_var("CORECRUXD_BACKPRESSURE_HIGH_WATERMARK_RATIO", "0.50");
        std::env::set_var("CORECRUXD_BACKPRESSURE_LOW_WATERMARK_RATIO", "0.60");
        let cfg = super::load_config();
        assert!(
            cfg.backpressure_low_watermark_ratio < cfg.backpressure_high_watermark_ratio,
            "low ({}) must be < high ({})",
            cfg.backpressure_low_watermark_ratio,
            cfg.backpressure_high_watermark_ratio
        );

        clear_corecruxd_env();
    }

    #[test]
    #[serial_test::serial]
    fn load_config_clamping_backpressure_retry_after_ms() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        std::env::set_var("CORECRUXD_BACKPRESSURE_RETRY_AFTER_MS", "0");
        let cfg = super::load_config();
        assert_eq!(cfg.backpressure_retry_after_ms, 1);

        std::env::set_var("CORECRUXD_BACKPRESSURE_RETRY_AFTER_MS", "999999");
        let cfg = super::load_config();
        assert_eq!(cfg.backpressure_retry_after_ms, 60_000);

        clear_corecruxd_env();
    }

    #[test]
    #[serial_test::serial]
    fn load_config_clamping_operator_action_timeout_secs() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        std::env::set_var("CORECRUXD_OPERATOR_ACTION_TIMEOUT_SECS", "1");
        let cfg = super::load_config();
        assert_eq!(cfg.operator_action_timeout_secs, 5);

        std::env::set_var("CORECRUXD_OPERATOR_ACTION_TIMEOUT_SECS", "999999");
        let cfg = super::load_config();
        assert_eq!(cfg.operator_action_timeout_secs, 86_400);

        clear_corecruxd_env();
    }

    #[test]
    #[serial_test::serial]
    fn load_config_clamping_scrub_interval_secs() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        std::env::set_var("CORECRUXD_SCRUB_INTERVAL_SECS", "1");
        let cfg = super::load_config();
        assert_eq!(cfg.scrub_interval_secs, 10);

        std::env::set_var("CORECRUXD_SCRUB_INTERVAL_SECS", "999999");
        let cfg = super::load_config();
        assert_eq!(cfg.scrub_interval_secs, 86_400);

        clear_corecruxd_env();
    }

    #[test]
    #[serial_test::serial]
    fn load_config_clamping_scrub_sample_rate() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        std::env::set_var("CORECRUXD_SCRUB_SAMPLE_RATE", "-1.0");
        let cfg = super::load_config();
        assert!((cfg.scrub_sample_rate - 0.0).abs() < 0.001);

        std::env::set_var("CORECRUXD_SCRUB_SAMPLE_RATE", "5.0");
        let cfg = super::load_config();
        assert!((cfg.scrub_sample_rate - 1.0).abs() < 0.001);

        clear_corecruxd_env();
    }

    #[test]
    #[serial_test::serial]
    fn load_config_replay_batch_max_events_min() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        std::env::set_var("CORECRUXD_REPLAY_BATCH_MAX_EVENTS", "0");
        let cfg = super::load_config();
        assert_eq!(cfg.replay_batch_max_events, 1);

        clear_corecruxd_env();
    }

    #[test]
    #[serial_test::serial]
    fn load_config_replay_batch_max_bytes_min() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        std::env::set_var("CORECRUXD_REPLAY_BATCH_MAX_BYTES", "0");
        let cfg = super::load_config();
        assert_eq!(cfg.replay_batch_max_bytes, 1024);

        clear_corecruxd_env();
    }

    #[test]
    #[serial_test::serial]
    fn load_config_follower_reads_default_follows_commit_level() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        // When commit_level is replicated, follower_reads defaults to true
        std::env::set_var("CORECRUXD_COMMIT_LEVEL", "replicated");
        let cfg = super::load_config();
        assert!(cfg.follower_reads_enabled);

        // When commit_level is local (default), follower_reads defaults to false
        clear_corecruxd_env();
        let cfg = super::load_config();
        assert!(!cfg.follower_reads_enabled);

        clear_corecruxd_env();
    }

    #[test]
    #[serial_test::serial]
    fn load_config_bool_truthy_values() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        // Test "1"
        std::env::set_var("CORECRUXD_ROUTING_STRICT_CLIENT_VERSION", "1");
        let cfg = super::load_config();
        assert!(cfg.routing_strict_client_version);

        // Test "yes"
        std::env::set_var("CORECRUXD_ROUTING_STRICT_CLIENT_VERSION", "yes");
        let cfg = super::load_config();
        assert!(cfg.routing_strict_client_version);

        // Test "YES"
        std::env::set_var("CORECRUXD_ROUTING_STRICT_CLIENT_VERSION", "YES");
        let cfg = super::load_config();
        assert!(cfg.routing_strict_client_version);

        // Test "TRUE"
        std::env::set_var("CORECRUXD_ROUTING_STRICT_CLIENT_VERSION", "TRUE");
        let cfg = super::load_config();
        assert!(cfg.routing_strict_client_version);

        // Non-truthy value
        std::env::set_var("CORECRUXD_ROUTING_STRICT_CLIENT_VERSION", "nope");
        let cfg = super::load_config();
        assert!(!cfg.routing_strict_client_version);

        clear_corecruxd_env();
    }

    #[test]
    #[serial_test::serial]
    fn load_config_invalid_port_uses_default() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        std::env::set_var("CORECRUXD_HTTP_PORT", "not-a-number");
        let cfg = super::load_config();
        assert_eq!(cfg.http_addr.port(), 14800);

        std::env::set_var("CORECRUXD_GRPC_PORT", "nope");
        let cfg = super::load_config();
        assert_eq!(cfg.grpc_addr.port(), 4007);

        clear_corecruxd_env();
    }

    #[test]
    #[serial_test::serial]
    fn load_config_invalid_host_uses_default() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        std::env::set_var("CORECRUXD_HTTP_HOST", "not-an-ip");
        let cfg = super::load_config();
        assert_eq!(cfg.http_addr.ip().to_string(), "127.0.0.1");

        clear_corecruxd_env();
    }
}
