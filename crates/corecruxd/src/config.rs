// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Daemon configuration: parses `CORECRUXD_*` environment variables into a typed `Config` at startup.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use crate::auth::AuthMode;
use crate::product::OperatingMode;
use crux_enterprise_shim::EnterpriseTrustRoot;
use serde::Deserialize;

const DEFAULT_PASSPORT_CLAIM_ENDPOINT: &str = "https://passport.vaultcrux.com/v1/claim-anonymous";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitLevel {
    LocalCommit,
    ReplicatedCommit,
}

impl CommitLevel {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "local" | "LOCAL" | "local_commit" | "LOCAL_COMMIT" | "local-commit" | "LOCAL-COMMIT" => {
                Some(Self::LocalCommit)
            }
            "replicated" | "REPLICATED" | "replicated_commit" | "REPLICATED_COMMIT" | "replicated-commit"
            | "REPLICATED-COMMIT" => Some(Self::ReplicatedCommit),
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
            "rwlock" | "RWLOCK" | "rw_lock" | "RW_LOCK" | "rw-lock" | "RW-LOCK" => Some(Self::RwLock),
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
    Global,
    Shard,
}

impl AppendLaneScope {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "global" | "GLOBAL" => Some(Self::Global),
            "shard" | "SHARD" => Some(Self::Shard),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Shard => "shard",
        }
    }
}

/// HTTP/gRPC ingress-hardening knobs (ExecPlan
/// `crux-http-ingress-hardening-2026-06-11`). All limits are env-tunable;
/// `0` means "disabled / unbounded" so an emergency rollback never needs a
/// redeploy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressConfig {
    /// Maximum accepted HTTP request body, in bytes
    /// (`CORECRUXD_MAX_REQUEST_BODY_BYTES`). `0` disables the limit.
    pub max_request_body_bytes: usize,
    /// Hard cap on the graceful-shutdown connection drain, in seconds
    /// (`CORECRUXD_SHUTDOWN_DRAIN_SECS`). `0` means drain without bound
    /// (pre-hardening behaviour).
    pub shutdown_drain_secs: u64,
    /// Maximum concurrently-admitted HTTP requests per listener
    /// (`CORECRUXD_MAX_INFLIGHT`). Excess requests are load-shed with a
    /// 503 problem+json. `0` disables the cap.
    pub max_inflight: usize,
    /// Sustained per-client-IP request rate (`CORECRUXD_RATE_LIMIT_RPS`).
    /// `0` disables rate limiting.
    pub rate_limit_rps: u64,
    /// Burst capacity per key (`CORECRUXD_RATE_LIMIT_BURST`). Clamped to
    /// at least `rate_limit_rps`.
    pub rate_limit_burst: u64,
    /// CIDRs whose client IPs bypass rate limiting entirely
    /// (`CORECRUXD_RATE_LIMIT_EXEMPT_CIDRS`, comma-separated). Defaults to
    /// loopback (console/local agents).
    pub rate_limit_exempt_cidrs: Vec<String>,
    /// CIDRs for reverse proxies whose `Forwarded` / `X-Forwarded-For`
    /// headers may be used to derive the effective client IP
    /// (`CORECRUXD_TRUSTED_PROXY_CIDRS`, comma-separated). Defaults empty.
    pub trusted_proxy_cidrs: Vec<String>,
    /// HTTP/2 keep-alive ping interval for the gRPC plane, in seconds
    /// (`CORECRUXD_GRPC_KEEPALIVE_INTERVAL_SECS`). `0` disables server
    /// keep-alive pings (pre-hardening behaviour: dead peers hold
    /// connections open indefinitely).
    pub grpc_keepalive_interval_secs: u64,
    /// How long to wait for a keep-alive ping ack before closing the
    /// connection, in seconds (`CORECRUXD_GRPC_KEEPALIVE_TIMEOUT_SECS`).
    /// Only meaningful when the interval is non-zero.
    pub grpc_keepalive_timeout_secs: u64,
    /// Maximum concurrent HTTP/2 streams per gRPC connection
    /// (`CORECRUXD_GRPC_MAX_CONCURRENT_STREAMS`). `0` leaves it unbounded.
    pub grpc_max_concurrent_streams: u32,
}

/// Default HTTP body limit: 16 MB. Bulk/import routes get explicit higher
/// caps in the ingress layer; ordinary admin/query/console writes should not
/// need multi-hundred-MB bodies.
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Default graceful-shutdown drain cap: matches the router-wide 30s
/// `TimeoutLayer`, so no request that can still complete is cut short.
pub const DEFAULT_SHUTDOWN_DRAIN_SECS: u64 = 30;
/// Default in-flight request cap: 1024 — far above observed prod
/// concurrency, low enough to shed a connection flood before memory does.
pub const DEFAULT_MAX_INFLIGHT: usize = 1024;
/// Default sustained per-key request rate: 300 req/s — ≥10× the busiest
/// observed single-agent traffic.
pub const DEFAULT_RATE_LIMIT_RPS: u64 = 300;
/// Default per-key burst capacity.
pub const DEFAULT_RATE_LIMIT_BURST: u64 = 600;
/// Default exempt CIDRs: loopback only (console SPA on the operator host
/// and local agents).
pub const DEFAULT_RATE_LIMIT_EXEMPT_CIDRS: &[&str] = &["127.0.0.0/8", "::1/128"];
/// Default trusted proxy CIDRs: none. Operators must opt in before forwarded
/// headers affect rate-limit keys.
pub const DEFAULT_TRUSTED_PROXY_CIDRS: &[&str] = &[];
/// Default gRPC keep-alive ping interval: 30s — frequent enough to reap
/// dead peers within a minute, far above any ping-flood concern.
pub const DEFAULT_GRPC_KEEPALIVE_INTERVAL_SECS: u64 = 30;
/// Default gRPC keep-alive ack timeout.
pub const DEFAULT_GRPC_KEEPALIVE_TIMEOUT_SECS: u64 = 10;
/// Default per-connection HTTP/2 stream cap: 1024 — a single client
/// cannot multiplex unbounded streams over one connection. The existing
/// per-tenant token-bucket throttle (`grpc.rs`) stays the fairness layer.
pub const DEFAULT_GRPC_MAX_CONCURRENT_STREAMS: u32 = 1024;

impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            shutdown_drain_secs: DEFAULT_SHUTDOWN_DRAIN_SECS,
            max_inflight: DEFAULT_MAX_INFLIGHT,
            rate_limit_rps: DEFAULT_RATE_LIMIT_RPS,
            rate_limit_burst: DEFAULT_RATE_LIMIT_BURST,
            rate_limit_exempt_cidrs: DEFAULT_RATE_LIMIT_EXEMPT_CIDRS
                .iter()
                .map(ToString::to_string)
                .collect(),
            trusted_proxy_cidrs: DEFAULT_TRUSTED_PROXY_CIDRS.iter().map(ToString::to_string).collect(),
            grpc_keepalive_interval_secs: DEFAULT_GRPC_KEEPALIVE_INTERVAL_SECS,
            grpc_keepalive_timeout_secs: DEFAULT_GRPC_KEEPALIVE_TIMEOUT_SECS,
            grpc_max_concurrent_streams: DEFAULT_GRPC_MAX_CONCURRENT_STREAMS,
        }
    }
}

impl IngressConfig {
    /// Pure constructor shared by `from_env` and the unit tests:
    /// missing or unparseable values fall back to the documented defaults.
    /// One positional arg per env var, in `from_env` order — a config
    /// struct for a private 2-caller helper would be ceremony.
    #[allow(clippy::too_many_arguments)]
    fn from_values(
        max_request_body_bytes: Option<&str>,
        shutdown_drain_secs: Option<&str>,
        max_inflight: Option<&str>,
        rate_limit_rps: Option<&str>,
        rate_limit_burst: Option<&str>,
        rate_limit_exempt_cidrs: Option<&str>,
        trusted_proxy_cidrs: Option<&str>,
        grpc_keepalive_interval_secs: Option<&str>,
        grpc_keepalive_timeout_secs: Option<&str>,
        grpc_max_concurrent_streams: Option<&str>,
    ) -> Self {
        let rate_limit_rps = rate_limit_rps
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(DEFAULT_RATE_LIMIT_RPS);
        Self {
            max_request_body_bytes: max_request_body_bytes
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(DEFAULT_MAX_REQUEST_BODY_BYTES),
            shutdown_drain_secs: shutdown_drain_secs
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(DEFAULT_SHUTDOWN_DRAIN_SECS),
            max_inflight: max_inflight
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(DEFAULT_MAX_INFLIGHT),
            rate_limit_rps,
            // Burst below the sustained rate makes no sense; clamp up.
            rate_limit_burst: rate_limit_burst
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(DEFAULT_RATE_LIMIT_BURST)
                .max(rate_limit_rps),
            rate_limit_exempt_cidrs: rate_limit_exempt_cidrs.map_or_else(
                || {
                    DEFAULT_RATE_LIMIT_EXEMPT_CIDRS
                        .iter()
                        .map(ToString::to_string)
                        .collect()
                },
                |s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|part| !part.is_empty())
                        .map(ToString::to_string)
                        .collect()
                },
            ),
            trusted_proxy_cidrs: trusted_proxy_cidrs.map_or_else(
                || DEFAULT_TRUSTED_PROXY_CIDRS.iter().map(ToString::to_string).collect(),
                |s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|part| !part.is_empty())
                        .map(ToString::to_string)
                        .collect()
                },
            ),
            grpc_keepalive_interval_secs: grpc_keepalive_interval_secs
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(DEFAULT_GRPC_KEEPALIVE_INTERVAL_SECS),
            grpc_keepalive_timeout_secs: grpc_keepalive_timeout_secs
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(DEFAULT_GRPC_KEEPALIVE_TIMEOUT_SECS),
            grpc_max_concurrent_streams: grpc_max_concurrent_streams
                .and_then(|s| s.trim().parse().ok())
                .unwrap_or(DEFAULT_GRPC_MAX_CONCURRENT_STREAMS),
        }
    }

    pub fn from_env() -> Self {
        Self::from_values(
            env_string("CORECRUXD_MAX_REQUEST_BODY_BYTES").as_deref(),
            env_string("CORECRUXD_SHUTDOWN_DRAIN_SECS").as_deref(),
            env_string("CORECRUXD_MAX_INFLIGHT").as_deref(),
            env_string("CORECRUXD_RATE_LIMIT_RPS").as_deref(),
            env_string("CORECRUXD_RATE_LIMIT_BURST").as_deref(),
            env_string("CORECRUXD_RATE_LIMIT_EXEMPT_CIDRS").as_deref(),
            env_string("CORECRUXD_TRUSTED_PROXY_CIDRS").as_deref(),
            env_string("CORECRUXD_GRPC_KEEPALIVE_INTERVAL_SECS").as_deref(),
            env_string("CORECRUXD_GRPC_KEEPALIVE_TIMEOUT_SECS").as_deref(),
            env_string("CORECRUXD_GRPC_MAX_CONCURRENT_STREAMS").as_deref(),
        )
    }

    /// Drain cap as a `Duration`; `None` when unbounded (`0`).
    pub fn shutdown_drain_cap(&self) -> Option<std::time::Duration> {
        (self.shutdown_drain_secs > 0).then(|| std::time::Duration::from_secs(self.shutdown_drain_secs))
    }

    /// gRPC keep-alive ping interval; `None` when disabled (`0`).
    pub fn grpc_keepalive_interval(&self) -> Option<std::time::Duration> {
        (self.grpc_keepalive_interval_secs > 0)
            .then(|| std::time::Duration::from_secs(self.grpc_keepalive_interval_secs))
    }

    /// gRPC keep-alive ack timeout; `None` when keep-alive is disabled or
    /// the timeout is `0` (tonic's own default applies).
    pub fn grpc_keepalive_timeout(&self) -> Option<std::time::Duration> {
        (self.grpc_keepalive_interval_secs > 0 && self.grpc_keepalive_timeout_secs > 0)
            .then(|| std::time::Duration::from_secs(self.grpc_keepalive_timeout_secs))
    }

    /// Per-connection HTTP/2 stream cap; `None` when unbounded (`0`).
    pub fn grpc_max_streams(&self) -> Option<u32> {
        (self.grpc_max_concurrent_streams > 0).then_some(self.grpc_max_concurrent_streams)
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub loaded_config_path: Option<PathBuf>,
    pub http_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub mcp_addr: SocketAddr,
    pub mcp_enabled: bool,
    pub console_enabled: bool,
    pub state_dir: PathBuf,
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
    pub auth_mode_explicitly_set: bool,
    pub passport_key_path: PathBuf,
    pub passport_claim_on_startup: bool,
    pub passport_claim_endpoint: String,
    pub content_manifest_path: Option<PathBuf>,
    pub content_verify_signatures: bool,
    pub router_refresh_interval_seconds: u64,
    pub router_cache_ttl_seconds: u64,
    pub router_fallback_policy: String,
    pub enterprise_trust_root: Option<EnterpriseTrustRoot>,
    pub llm_endpoint: Option<String>,
    pub llm_model: Option<String>,

    // IO backend selection.
    pub io_backend: String,

    // Phase 7 projections (Living Objects).
    pub projections_enabled: bool,
    pub projections_batch_frames: u32,
    pub projections_tick_interval_ms: u64,

    // Admin force-seal: allows force-sealing head segments via admin actions.
    pub admin_force_seal_enabled: bool,

    // Fact-store retention (launch-gate 5.1 / W2.E2). When `Some(n)`, the
    // `compact-facts` admin action may mark facts older than `n` days as
    // deletion-eligible before compacting. `None` (default, env unset) = off:
    // retention never deletes anything; compaction still scrubs already
    // soft-deleted facts. Sourced from `CORECRUXD_RETENTION_DAYS`.
    pub retention_days: Option<u32>,

    // CoreCrux v5: build .ccxi companion indexes at seal time for BM25 retrieval.
    pub build_ccxi: bool,

    // agent-passport M1: when true, the MCP `store_fact` path resolves the
    // calling agent token-name to a passport_id and stamps it as the fact
    // `actor`. Default OFF — attribution only, no enforcement (M5).
    pub agent_passports_enabled: bool,

    // Phase 8 receipts: bytes-first fetch + signature verification projection.
    pub receipts_verify_enabled: bool,
    pub receipts_recompute_candidate_digest: bool,
    pub receipts_keyring_path: Option<PathBuf>,
    pub receipts_keyring_json: Option<String>,
    pub witness_enabled: bool,
    pub witness_provider: String,
    pub witness_timeout_ms: u64,
    pub rekor_url: Option<String>,
    pub rekor_public_key_path: Option<PathBuf>,
    pub tsa_enabled: bool,
    pub tsa_url: Option<String>,
    pub tsa_root_cert_path: Option<PathBuf>,
    pub tsa_policy_oid: Option<String>,

    // Replay/batching path configuration.
    pub replay_batch_max_events: u32,
    pub replay_batch_max_bytes: u32,
    pub replay_many_max_reads: u32,
    pub replay_use_batched_rpc_default: bool,
    pub store_lock_strategy: StoreLockStrategy,
    pub append_lane_enabled: bool,
    pub append_lane_scope: AppendLaneScope,
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

    // HTTP/gRPC ingress hardening (crux-http-ingress-hardening-2026-06-11).
    pub ingress: IngressConfig,

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

    // JSONL persistence for FactStore and SessionStore.
    pub fact_persistence_enabled: bool,

    // Optional embedding endpoint for dense vector retrieval on facts.
    pub embedding_url: Option<String>,
    pub embedding_model: String,

    // Background sync: pull/push facts to a remote CoreCrux instance.
    pub sync_enabled: bool,
    pub sync_remote_url: String,
    pub sync_api_key: String,
    pub sync_interval_secs: u64,

    // Background update checks against a tracked git ref.
    pub update_check_enabled: bool,
    pub update_check_remote: String,
    pub update_check_ref: String,
    pub update_check_interval_secs: u64,
    pub update_check_repo_dir: Option<PathBuf>,

    // Ephemeral reserved-fact GC: soft-deletes stale daemon-minted
    // bookkeeping facts (`__session_binding__::*`, `__reverify_receipts__::*`)
    // via the journaled delete path. Default OFF.
    pub ephemeral_gc_enabled: bool,

    // Multi-agent coordination plane (`/v1/coord/*`, `crate::coord`):
    // presence-joined session board + advisory claims. Default OFF.
    pub coord_enabled: bool,
    // Liveness horizon for the coord active view, in seconds.
    pub coord_presence_ttl_secs: u64,

    // Provider-agnostic injection-bundle surface (`/v1/context`,
    // `crate::http::context_surface`). Default OFF.
    pub context_surface_enabled: bool,

    // G19 stream/context receipt wiring (`crate::http::stream_receipts`).
    // Default OFF.
    pub stream_receipts_enabled: bool,

    // G21b assembly cache for /v1/context bundles. Default OFF.
    pub assembly_cache_enabled: bool,

    // G20 per-surface request quota (`crate::http::quota`). Default OFF.
    pub quota_enabled: bool,
    // Path prefixes classified as hosted (quota-limited) surfaces.
    // Comma-separated; empty default = everything is local compute.
    pub quota_hosted_surfaces: Vec<String>,

    // OpenAI function-calling shim over the MCP tool surface
    // (`crate::http::openai_shim`). Default OFF.
    pub openai_shim_enabled: bool,

    // `.cruxpack` import surface (`POST /v1/memory/import`,
    // `crate::http::memory_import`). Default OFF (`CRUX_MEMORY_IMPORT=1`).
    // Export needs no flag — it is read-only and lives in corecruxctl.
    pub memory_import_enabled: bool,

    // Identity-federation resolver extension + link CRUD
    // (`/v1/identity/links*`, `crate::http::identity_links`). Default OFF
    // (`CORECRUXD_IDENTITY_LINKS=1`).
    pub identity_links_enabled: bool,

    // Embedded console + declarative integration library.
    pub integrations_enabled: bool,
    pub integrations_safe_mode: bool,
    pub integrations_allow_executable_helpers: bool,

    // Product posture / entitlement reporting. These values report the local
    // daemon's operating contract; paid-gate enforcement is layered separately.
    pub operating_mode: OperatingMode,
    pub enabled_pro_services: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct FileConfig {
    daemon: FileDaemonConfig,
    passport: FilePassportConfig,
    content: FileContentConfig,
    router: FileRouterConfig,
    enterprise: FileEnterpriseConfig,
    llm: FileLlmConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct FileDaemonConfig {
    instance_id: Option<String>,
    state_dir: Option<String>,
    data_dir: Option<String>,
    listen_addr: Option<String>,
    http_port: Option<u16>,
    grpc_port: Option<u16>,
    mcp_port: Option<u16>,
    mcp_enabled: Option<bool>,
    auth_mode: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct FilePassportConfig {
    key_path: Option<String>,
    claim_on_startup: Option<bool>,
    claim_endpoint: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct FileContentConfig {
    manifest_path: Option<String>,
    verify_signatures: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct FileRouterConfig {
    refresh_interval_seconds: Option<u64>,
    cache_ttl_seconds: Option<u64>,
    fallback_policy: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct FileEnterpriseConfig {
    enabled: Option<bool>,
    customer_id: Option<String>,
    backend_id: Option<String>,
    trust_root_kid: Option<String>,
    trusted_issuer_kids: Option<Vec<String>>,
    airgap: Option<bool>,
    allow_vaultcrux_cross_sign: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct FileLlmConfig {
    endpoint: Option<String>,
    model: Option<String>,
}

fn load_file_config() -> (Option<PathBuf>, FileConfig) {
    let Some(path) = configured_config_path() else {
        return (None, FileConfig::default());
    };
    match std::fs::read_to_string(&path) {
        Ok(raw) => match serde_yaml::from_str::<FileConfig>(&raw) {
            Ok(config) => (Some(path), config),
            Err(_err) => (Some(path), FileConfig::default()),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (Some(path), FileConfig::default()),
        Err(_err) => (Some(path), FileConfig::default()),
    }
}

fn configured_config_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("CORECRUXD_CONFIG_PATH") {
        let trimmed = path.trim();
        return (!trimmed.is_empty()).then(|| expand_path(trimmed));
    }
    std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|base| PathBuf::from(base).join("crux").join("config.yaml"))
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}

fn env_bool(key: &str) -> Option<bool> {
    std::env::var(key).ok().map(|value| bool_value(&value))
}

fn env_csv(key: &str) -> Option<Vec<String>> {
    env_string(key).map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(ToString::to_string)
            .collect()
    })
}

fn bool_value(value: &str) -> bool {
    matches!(value, "1" | "true" | "TRUE" | "yes" | "YES")
}

fn expand_path(raw: &str) -> PathBuf {
    PathBuf::from(expand_config_value(raw))
}

fn expand_config_value(raw: &str) -> String {
    let mut value = raw.to_string();
    if let Some(state_home) = std::env::var("XDG_STATE_HOME").ok().filter(|value| !value.is_empty()) {
        value = value.replace("$XDG_STATE_HOME", &state_home);
    }
    if let Some(config_home) = std::env::var("XDG_CONFIG_HOME").ok().filter(|value| !value.is_empty()) {
        value = value.replace("$XDG_CONFIG_HOME", &config_home);
    }
    if let Some(home) = std::env::var("HOME").ok().filter(|value| !value.is_empty()) {
        value = value.replace("$HOME", &home);
        if let Some(rest) = value.strip_prefix("~/") {
            value = format!("{home}/{rest}");
        }
    }
    value
}

pub fn load_config() -> Config {
    let (config_path, file_config) = load_file_config();
    let listen_addr = file_config.daemon.listen_addr.as_deref();
    let http_host: IpAddr = env_string("CORECRUXD_HTTP_HOST")
        .or_else(|| listen_addr.map(ToString::to_string))
        .unwrap_or_else(|| "127.0.0.1".to_string())
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let http_port: u16 = std::env::var("CORECRUXD_HTTP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .or(file_config.daemon.http_port)
        .unwrap_or(14800);

    let grpc_host: IpAddr = env_string("CORECRUXD_GRPC_HOST")
        .or_else(|| listen_addr.map(ToString::to_string))
        .unwrap_or_else(|| "127.0.0.1".to_string())
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let grpc_port: u16 = std::env::var("CORECRUXD_GRPC_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .or(file_config.daemon.grpc_port)
        .unwrap_or(4007);
    let mcp_host: IpAddr = env_string("CORECRUXD_MCP_HOST")
        .or_else(|| listen_addr.map(ToString::to_string))
        .unwrap_or_else(|| "127.0.0.1".to_string())
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    let mcp_port: u16 = std::env::var("CORECRUXD_MCP_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .or(file_config.daemon.mcp_port)
        .unwrap_or(14801);
    let mcp_enabled = env_bool("CORECRUXD_MCP_ENABLED")
        .or(file_config.daemon.mcp_enabled)
        .unwrap_or(true);
    let console_enabled = env_bool("CORECRUXD_CONSOLE_ENABLED").unwrap_or(true);

    let file_state_dir = file_config.daemon.state_dir.as_deref().map(expand_path);
    let file_data_dir = file_config.daemon.data_dir.as_deref().map(expand_path);
    let data_dir = env_string("CORECRUXD_DATA_DIR")
        .map(|value| expand_path(&value))
        .or(file_data_dir)
        .or_else(|| file_state_dir.clone())
        .unwrap_or_else(|| PathBuf::from("../CoreCruxData/v1"));
    let state_dir = env_string("CORECRUXD_STATE_DIR")
        .map(|value| expand_path(&value))
        .or(file_state_dir)
        .unwrap_or_else(|| data_dir.clone());
    let log_level = std::env::var("CORECRUXD_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());
    let service_name = std::env::var("CORECRUXD_SERVICE").unwrap_or_else(|_| "corecruxd".to_string());
    let cluster_id = std::env::var("CORECRUXD_CLUSTER_ID").unwrap_or_else(|_| "dev".to_string());
    let node_id_override = env_string("CORECRUXD_NODE_ID").or(file_config.daemon.instance_id.clone());
    let routing_reload_interval_ms = std::env::var("CORECRUXD_ROUTING_RELOAD_INTERVAL_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    let routing_strict_client_version = std::env::var("CORECRUXD_ROUTING_STRICT_CLIENT_VERSION")
        .ok()
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
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
    let replicated_commit_require_all_followers = std::env::var("CORECRUXD_REPLICATED_COMMIT_REQUIRE_ALL_FOLLOWERS")
        .ok()
        .is_none_or(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));

    let auth_mode_raw = env_string("CORECRUXD_AUTH_MODE").or(file_config.daemon.auth_mode.clone());
    let auth_mode_explicitly_set = auth_mode_raw.is_some();
    let auth_mode = auth_mode_raw
        .as_deref()
        .and_then(AuthMode::parse)
        .unwrap_or(AuthMode::DevScopes);
    let passport_key_path = env_string("CORECRUXD_PASSPORT_KEY_PATH")
        .or_else(|| file_config.passport.key_path.clone())
        .map_or_else(|| state_dir.join("passport.key"), |value| expand_path(&value));
    let passport_claim_on_startup = env_bool("CORECRUXD_PASSPORT_CLAIM_ON_STARTUP")
        .or(file_config.passport.claim_on_startup)
        .unwrap_or(true);
    let passport_claim_endpoint = env_string("CRUX_PASSPORT_CLAIM_ENDPOINT")
        .or_else(|| env_string("CORECRUXD_PASSPORT_CLAIM_ENDPOINT"))
        .or(file_config.passport.claim_endpoint.clone())
        .unwrap_or_else(|| DEFAULT_PASSPORT_CLAIM_ENDPOINT.to_string());
    let content_manifest_path = env_string("CORECRUXD_CONTENT_MANIFEST_PATH")
        .or(file_config.content.manifest_path.clone())
        .map(|value| expand_path(&value));
    let content_verify_signatures = env_bool("CORECRUXD_CONTENT_VERIFY_SIGNATURES")
        .or(file_config.content.verify_signatures)
        .unwrap_or(true);
    let router_refresh_interval_seconds = std::env::var("CORECRUXD_ROUTER_REFRESH_INTERVAL_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .or(file_config.router.refresh_interval_seconds)
        .unwrap_or(60)
        .clamp(1, 86_400);
    let router_cache_ttl_seconds = std::env::var("CORECRUXD_ROUTER_CACHE_TTL_SECONDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .or(file_config.router.cache_ttl_seconds)
        .unwrap_or(60)
        .clamp(1, 86_400);
    let router_fallback_policy = env_string("CORECRUXD_ROUTER_FALLBACK_POLICY")
        .or(file_config.router.fallback_policy.clone())
        .unwrap_or_else(|| "degrade_to_local".to_string());
    let enterprise_enabled = env_bool("CORECRUXD_ENTERPRISE_ENABLED")
        .or(file_config.enterprise.enabled)
        .unwrap_or(false);
    let enterprise_trust_root = enterprise_enabled.then(|| EnterpriseTrustRoot {
        customer_id: env_string("CORECRUXD_ENTERPRISE_CUSTOMER_ID")
            .or(file_config.enterprise.customer_id.clone())
            .unwrap_or_default(),
        backend_id: env_string("CORECRUXD_ENTERPRISE_BACKEND_ID")
            .or(file_config.enterprise.backend_id.clone())
            .unwrap_or_default(),
        trust_root_kid: env_string("CORECRUXD_ENTERPRISE_TRUST_ROOT_KID")
            .or(file_config.enterprise.trust_root_kid.clone())
            .unwrap_or_default(),
        trusted_issuer_kids: env_csv("CORECRUXD_ENTERPRISE_TRUSTED_ISSUER_KIDS")
            .or(file_config.enterprise.trusted_issuer_kids.clone())
            .unwrap_or_default(),
        airgap: env_bool("CORECRUXD_ENTERPRISE_AIRGAP")
            .or(file_config.enterprise.airgap)
            .unwrap_or(true),
        allow_vaultcrux_cross_sign: env_bool("CORECRUXD_ENTERPRISE_ALLOW_VAULTCRUX_CROSS_SIGN")
            .or(file_config.enterprise.allow_vaultcrux_cross_sign)
            .unwrap_or(false),
    });
    let operating_mode = env_string("CORECRUXD_OPERATING_MODE")
        .or_else(|| env_string("CRUX_OPERATING_MODE"))
        .as_deref()
        .and_then(OperatingMode::parse)
        .unwrap_or_default();
    let enabled_pro_services = env_csv("CORECRUXD_ENABLED_PRO_SERVICES")
        .or_else(|| env_csv("CRUX_ENABLED_PRO_SERVICES"))
        .unwrap_or_default();
    let llm_endpoint = env_string("CORECRUXD_LLM_ENDPOINT").or(file_config.llm.endpoint.clone());
    let llm_model = env_string("CORECRUXD_LLM_MODEL").or(file_config.llm.model.clone());

    let io_backend = std::env::var("CORECRUXD_IO_BACKEND").unwrap_or_else(|_| "cpu".to_string());

    let build_ccxi = std::env::var("CORECRUXD_BUILD_CCXI")
        .ok()
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));

    // agent-passport M1: default OFF. Only the env var enables it (no file
    // override needed — this is a deliberate, operator-set switch).
    let agent_passports_enabled = env_bool("CORECRUXD_AGENT_PASSPORTS").unwrap_or(false);

    let projections_enabled = std::env::var("CORECRUXD_PROJECTIONS_ENABLED")
        .ok()
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
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
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));

    // Fact-store retention window in days. Unset (or 0) = retention off.
    let retention_days = std::env::var("CORECRUXD_RETENTION_DAYS")
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|n| *n > 0);

    let receipts_verify_enabled = std::env::var("CORECRUXD_RECEIPTS_VERIFY_ENABLED")
        .ok()
        .is_none_or(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
    let receipts_recompute_candidate_digest = std::env::var("CORECRUXD_RECEIPTS_RECOMPUTE_CANDIDATE_DIGEST")
        .ok()
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
    let receipts_keyring_path = std::env::var("CORECRUXD_RECEIPTS_KEYRING_PATH").ok().map(PathBuf::from);
    let receipts_keyring_json = std::env::var("CORECRUXD_RECEIPTS_KEYRING_JSON").ok();
    let witness_enabled = env_bool("CORECRUXD_WITNESS_ENABLED").unwrap_or(false);
    let witness_provider = env_string("CORECRUXD_WITNESS_PROVIDER").unwrap_or_else(|| "disabled".to_string());
    let witness_timeout_ms = std::env::var("CORECRUXD_WITNESS_TIMEOUT_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5_000)
        .clamp(100, 120_000);
    let rekor_url = env_string("CORECRUXD_REKOR_URL");
    let rekor_public_key_path = env_string("CORECRUXD_REKOR_PUBLIC_KEY_PATH").map(PathBuf::from);
    let tsa_enabled = env_bool("CORECRUXD_TSA_ENABLED").unwrap_or(false);
    let tsa_url = env_string("CORECRUXD_TSA_URL");
    let tsa_root_cert_path = env_string("CORECRUXD_TSA_ROOT_CERT_PATH").map(PathBuf::from);
    let tsa_policy_oid = env_string("CORECRUXD_TSA_POLICY_OID");
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
        .is_none_or(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
    let store_lock_strategy = std::env::var("CORECRUXD_STORE_LOCK_STRATEGY")
        .ok()
        .as_deref()
        .and_then(StoreLockStrategy::parse)
        .unwrap_or(StoreLockStrategy::Sharded);
    let append_lane_enabled = std::env::var("CORECRUXD_APPEND_LANE_ENABLED")
        .ok()
        .is_none_or(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
    let append_lane_scope = std::env::var("CORECRUXD_APPEND_LANE_SCOPE")
        .ok()
        .as_deref()
        .and_then(AppendLaneScope::parse)
        .unwrap_or(AppendLaneScope::Global);
    let tail_cache_enabled = std::env::var("CORECRUXD_TAIL_CACHE_ENABLED")
        .ok()
        .is_none_or(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
    let read_retry_failed_readyz_threshold = std::env::var("CORECRUXD_READ_RETRY_FAILED_READYZ_THRESHOLD")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    let mut backpressure_high_watermark_ratio: f64 = std::env::var("CORECRUXD_BACKPRESSURE_HIGH_WATERMARK_RATIO")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.90);
    let mut backpressure_low_watermark_ratio: f64 = std::env::var("CORECRUXD_BACKPRESSURE_LOW_WATERMARK_RATIO")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.80);
    backpressure_high_watermark_ratio = backpressure_high_watermark_ratio.clamp(0.01, 0.99);
    backpressure_low_watermark_ratio = backpressure_low_watermark_ratio.clamp(0.0, 0.98);
    if backpressure_low_watermark_ratio >= backpressure_high_watermark_ratio {
        backpressure_low_watermark_ratio = (backpressure_high_watermark_ratio - 0.05).clamp(0.0, 0.95);
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
        .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
    let scrub_interval_secs = std::env::var("CORECRUXD_SCRUB_INTERVAL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300)
        .clamp(10, 86_400);
    let scrub_scope = std::env::var("CORECRUXD_SCRUB_SCOPE").unwrap_or_else(|_| "recent".to_string());
    let scrub_mode = std::env::var("CORECRUXD_SCRUB_MODE").unwrap_or_else(|_| "sampled".to_string());
    let scrub_sample_rate: f64 = std::env::var("CORECRUXD_SCRUB_SAMPLE_RATE")
        .ok()
        .and_then(|s| s.parse::<f64>().ok())
        .unwrap_or(0.25)
        .clamp(0.0, 1.0);
    let capacity_guard_enabled = std::env::var("CORECRUXD_CAPACITY_GUARD_ENABLED")
        .ok()
        .is_none_or(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
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
    let capacity_emergency_free_ratio: f64 = std::env::var("CORECRUXD_CAPACITY_EMERGENCY_FREE_RATIO")
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
    let capacity_emergency_free_ratio = capacity_emergency_free_ratio.min(capacity_critical_free_ratio);
    if capacity_resume_free_ratio <= capacity_emergency_free_ratio {
        capacity_resume_free_ratio = (capacity_emergency_free_ratio + 0.05).min(capacity_warning_free_ratio);
    }

    Config {
        loaded_config_path: config_path,
        http_addr: SocketAddr::new(http_host, http_port),
        grpc_addr: SocketAddr::new(grpc_host, grpc_port),
        mcp_addr: SocketAddr::new(mcp_host, mcp_port),
        mcp_enabled,
        console_enabled,
        state_dir,
        data_dir,
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
        auth_mode_explicitly_set,
        passport_key_path,
        passport_claim_on_startup,
        passport_claim_endpoint,
        content_manifest_path,
        content_verify_signatures,
        router_refresh_interval_seconds,
        router_cache_ttl_seconds,
        router_fallback_policy,
        enterprise_trust_root,
        llm_endpoint,
        llm_model,

        io_backend,

        build_ccxi,
        agent_passports_enabled,

        projections_enabled,
        projections_batch_frames,
        projections_tick_interval_ms,

        admin_force_seal_enabled,
        retention_days,

        receipts_verify_enabled,
        receipts_recompute_candidate_digest,
        receipts_keyring_path,
        receipts_keyring_json,
        witness_enabled,
        witness_provider,
        witness_timeout_ms,
        rekor_url,
        rekor_public_key_path,
        tsa_enabled,
        tsa_url,
        tsa_root_cert_path,
        tsa_policy_oid,
        replay_batch_max_events,
        replay_batch_max_bytes,
        replay_many_max_reads,
        replay_use_batched_rpc_default,
        store_lock_strategy,
        append_lane_enabled,
        append_lane_scope,
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
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")),
        dir_l0_max_runs: std::env::var("CORECRUXD_DIR_L0_MAX_RUNS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8),

        fact_persistence_enabled: std::env::var("CORECRUXD_FACT_PERSISTENCE")
            .ok()
            .is_none_or(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")),

        embedding_url: std::env::var("CORECRUXD_EMBEDDING_URL").ok().filter(|s| !s.is_empty()),
        embedding_model: std::env::var("CORECRUXD_EMBEDDING_MODEL").unwrap_or_else(|_| "nomic-embed-text".to_string()),

        sync_enabled: std::env::var("CORECRUXD_SYNC_ENABLED")
            .ok()
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")),
        sync_remote_url: std::env::var("CORECRUXD_SYNC_REMOTE_URL").unwrap_or_default(),
        sync_api_key: std::env::var("CORECRUXD_SYNC_API_KEY").unwrap_or_default(),
        sync_interval_secs: std::env::var("CORECRUXD_SYNC_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300)
            .max(10),
        update_check_enabled: std::env::var("CORECRUXD_UPDATE_CHECK_ENABLED")
            .ok()
            .is_none_or(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")),
        update_check_remote: std::env::var("CORECRUXD_UPDATE_CHECK_REMOTE").unwrap_or_else(|_| "origin".to_string()),
        update_check_ref: std::env::var("CORECRUXD_UPDATE_CHECK_REF").unwrap_or_else(|_| "main".to_string()),
        update_check_interval_secs: std::env::var("CORECRUXD_UPDATE_CHECK_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3600)
            .clamp(60, 86_400),
        update_check_repo_dir: std::env::var("CORECRUXD_UPDATE_CHECK_REPO_DIR")
            .ok()
            .map(PathBuf::from)
            .filter(|path| !path.as_os_str().is_empty()),
        ephemeral_gc_enabled: env_bool("CORECRUXD_EPHEMERAL_GC").unwrap_or(false),
        coord_enabled: env_bool("CORECRUXD_COORD").unwrap_or(false),
        coord_presence_ttl_secs: std::env::var("CORECRUXD_COORD_PRESENCE_TTL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(crate::coord::DEFAULT_PRESENCE_TTL_SECS)
            .clamp(60, crate::coord::MAX_TTL_SECS),
        context_surface_enabled: env_bool("CORECRUXD_CONTEXT_SURFACE").unwrap_or(false),
        stream_receipts_enabled: env_bool("CORECRUXD_STREAM_RECEIPTS").unwrap_or(false),
        assembly_cache_enabled: env_bool("CORECRUXD_ASSEMBLY_CACHE").unwrap_or(false),
        quota_enabled: env_bool("CORECRUXD_QUOTA").unwrap_or(false),
        quota_hosted_surfaces: std::env::var("CORECRUXD_QUOTA_HOSTED_SURFACES")
            .ok()
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        memory_import_enabled: env_bool("CRUX_MEMORY_IMPORT").unwrap_or(false),
        identity_links_enabled: env_bool("CORECRUXD_IDENTITY_LINKS").unwrap_or(false),
        openai_shim_enabled: env_bool("CORECRUXD_OPENAI_SHIM").unwrap_or(false),
        integrations_enabled: std::env::var("CORECRUXD_INTEGRATIONS_ENABLED")
            .ok()
            .is_none_or(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")),
        integrations_safe_mode: std::env::var("CORECRUXD_INTEGRATIONS_SAFE_MODE")
            .ok()
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")),
        integrations_allow_executable_helpers: std::env::var("CORECRUXD_INTEGRATIONS_ALLOW_EXECUTABLE_HELPERS")
            .ok()
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES")),
        operating_mode,
        enabled_pro_services,
        ingress: IngressConfig::from_env(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AppendLaneScope, CommitLevel, IngressConfig, StoreLockStrategy, DEFAULT_GRPC_KEEPALIVE_INTERVAL_SECS,
        DEFAULT_GRPC_KEEPALIVE_TIMEOUT_SECS, DEFAULT_GRPC_MAX_CONCURRENT_STREAMS, DEFAULT_MAX_INFLIGHT,
        DEFAULT_MAX_REQUEST_BODY_BYTES, DEFAULT_RATE_LIMIT_BURST, DEFAULT_RATE_LIMIT_RPS, DEFAULT_SHUTDOWN_DRAIN_SECS,
    };

    #[test]
    fn ingress_config_defaults_when_unset() {
        let cfg = IngressConfig::from_values(None, None, None, None, None, None, None, None, None, None);
        assert_eq!(cfg.max_request_body_bytes, DEFAULT_MAX_REQUEST_BODY_BYTES);
        assert_eq!(cfg.shutdown_drain_secs, DEFAULT_SHUTDOWN_DRAIN_SECS);
        assert_eq!(cfg.max_inflight, DEFAULT_MAX_INFLIGHT);
        assert_eq!(cfg.rate_limit_rps, DEFAULT_RATE_LIMIT_RPS);
        assert_eq!(cfg.rate_limit_burst, DEFAULT_RATE_LIMIT_BURST);
        assert_eq!(cfg.rate_limit_exempt_cidrs, vec!["127.0.0.0/8", "::1/128"]);
        assert!(cfg.trusted_proxy_cidrs.is_empty());
        assert_eq!(cfg.grpc_keepalive_interval_secs, DEFAULT_GRPC_KEEPALIVE_INTERVAL_SECS);
        assert_eq!(cfg.grpc_keepalive_timeout_secs, DEFAULT_GRPC_KEEPALIVE_TIMEOUT_SECS);
        assert_eq!(cfg.grpc_max_concurrent_streams, DEFAULT_GRPC_MAX_CONCURRENT_STREAMS);
        assert_eq!(cfg, IngressConfig::default());
    }

    #[test]
    fn ingress_config_parses_overrides() {
        let cfg = IngressConfig::from_values(
            Some("1048576"),
            Some("5"),
            Some("128"),
            Some("10"),
            Some("20"),
            Some("10.0.0.0/8, 192.168.1.1/32"),
            Some("127.0.0.1/32, ::1/128"),
            Some("15"),
            Some("5"),
            Some("256"),
        );
        assert_eq!(cfg.max_request_body_bytes, 1_048_576);
        assert_eq!(cfg.shutdown_drain_secs, 5);
        assert_eq!(cfg.max_inflight, 128);
        assert_eq!(cfg.rate_limit_rps, 10);
        assert_eq!(cfg.rate_limit_burst, 20);
        assert_eq!(cfg.rate_limit_exempt_cidrs, vec!["10.0.0.0/8", "192.168.1.1/32"]);
        assert_eq!(cfg.trusted_proxy_cidrs, vec!["127.0.0.1/32", "::1/128"]);
        assert_eq!(cfg.shutdown_drain_cap(), Some(std::time::Duration::from_secs(5)));
        assert_eq!(cfg.grpc_keepalive_interval(), Some(std::time::Duration::from_secs(15)));
        assert_eq!(cfg.grpc_keepalive_timeout(), Some(std::time::Duration::from_secs(5)));
        assert_eq!(cfg.grpc_max_streams(), Some(256));
    }

    #[test]
    fn ingress_config_burst_clamps_up_to_rps() {
        let cfg = IngressConfig::from_values(None, None, None, Some("500"), Some("100"), None, None, None, None, None);
        assert_eq!(cfg.rate_limit_rps, 500);
        assert_eq!(cfg.rate_limit_burst, 500, "burst below rps must clamp up");
    }

    #[test]
    fn ingress_config_zero_means_disabled() {
        let cfg = IngressConfig::from_values(
            Some("0"),
            Some("0"),
            Some("0"),
            Some("0"),
            Some("0"),
            Some(""),
            Some(""),
            Some("0"),
            Some("0"),
            Some("0"),
        );
        assert_eq!(cfg.max_request_body_bytes, 0);
        assert_eq!(cfg.shutdown_drain_secs, 0);
        assert_eq!(cfg.max_inflight, 0);
        assert_eq!(cfg.rate_limit_rps, 0);
        assert!(cfg.rate_limit_exempt_cidrs.is_empty(), "empty CIDR list stays empty");
        assert!(
            cfg.trusted_proxy_cidrs.is_empty(),
            "empty trusted proxy list stays empty"
        );
        assert_eq!(cfg.shutdown_drain_cap(), None);
        assert_eq!(cfg.grpc_keepalive_interval(), None);
        assert_eq!(cfg.grpc_keepalive_timeout(), None);
        assert_eq!(cfg.grpc_max_streams(), None);
    }

    #[test]
    fn ingress_config_keepalive_timeout_inert_when_interval_disabled() {
        // Interval 0 disables keep-alive entirely; a configured timeout
        // must not leak through on its own.
        let cfg = IngressConfig::from_values(None, None, None, None, None, None, None, Some("0"), Some("10"), None);
        assert_eq!(cfg.grpc_keepalive_interval(), None);
        assert_eq!(cfg.grpc_keepalive_timeout(), None);
    }

    #[test]
    fn ingress_config_invalid_values_fall_back_to_defaults() {
        let cfg = IngressConfig::from_values(
            Some("not-a-number"),
            Some("-3"),
            Some("4.5"),
            Some("x"),
            Some("y"),
            None,
            None,
            Some("z"),
            Some("-1"),
            Some("1.5"),
        );
        assert_eq!(cfg.max_request_body_bytes, DEFAULT_MAX_REQUEST_BODY_BYTES);
        assert_eq!(cfg.shutdown_drain_secs, DEFAULT_SHUTDOWN_DRAIN_SECS);
        assert_eq!(cfg.max_inflight, DEFAULT_MAX_INFLIGHT);
        assert_eq!(cfg.grpc_keepalive_interval_secs, DEFAULT_GRPC_KEEPALIVE_INTERVAL_SECS);
        assert_eq!(cfg.grpc_keepalive_timeout_secs, DEFAULT_GRPC_KEEPALIVE_TIMEOUT_SECS);
        assert_eq!(cfg.grpc_max_concurrent_streams, DEFAULT_GRPC_MAX_CONCURRENT_STREAMS);
    }

    #[test]
    fn ingress_config_trims_whitespace() {
        let cfg = IngressConfig::from_values(
            Some(" 2048 "),
            Some("\t60\n"),
            Some(" 512 "),
            Some(" 7 "),
            Some(" 14 "),
            None,
            Some(" 127.0.0.1/32, 10.0.0.0/8 "),
            Some(" 45 "),
            Some(" 9 "),
            Some(" 64 "),
        );
        assert_eq!(cfg.max_request_body_bytes, 2048);
        assert_eq!(cfg.shutdown_drain_secs, 60);
        assert_eq!(cfg.max_inflight, 512);
        assert_eq!(cfg.trusted_proxy_cidrs, vec!["127.0.0.1/32", "10.0.0.0/8"]);
        assert_eq!(cfg.grpc_keepalive_interval_secs, 45);
        assert_eq!(cfg.grpc_keepalive_timeout_secs, 9);
        assert_eq!(cfg.grpc_max_concurrent_streams, 64);
    }

    #[test]
    fn commit_level_parse_accepts_aliases() {
        assert_eq!(CommitLevel::parse("local"), Some(CommitLevel::LocalCommit));
        assert_eq!(CommitLevel::parse("LOCAL_COMMIT"), Some(CommitLevel::LocalCommit));
        assert_eq!(CommitLevel::parse("replicated"), Some(CommitLevel::ReplicatedCommit));
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
        assert_eq!(StoreLockStrategy::parse("mutex"), Some(StoreLockStrategy::Mutex));
        assert_eq!(StoreLockStrategy::parse("RW_LOCK"), Some(StoreLockStrategy::RwLock));
        assert_eq!(StoreLockStrategy::parse("sharded"), Some(StoreLockStrategy::Sharded));
    }

    #[test]
    fn store_lock_strategy_parse_rejects_invalid_values() {
        assert_eq!(StoreLockStrategy::parse(""), None);
        assert_eq!(StoreLockStrategy::parse("rw"), None);
    }

    #[test]
    fn append_lane_scope_parse_accepts_aliases() {
        assert_eq!(AppendLaneScope::parse("global"), Some(AppendLaneScope::Global));
        assert_eq!(AppendLaneScope::parse("SHARD"), Some(AppendLaneScope::Shard));
    }

    #[test]
    fn append_lane_scope_parse_rejects_invalid_values() {
        assert_eq!(AppendLaneScope::parse(""), None);
        assert_eq!(AppendLaneScope::parse("store"), None);
        assert_eq!(AppendLaneScope::parse("gpu"), None);
    }

    #[test]
    fn append_lane_scope_as_str_is_stable() {
        assert_eq!(AppendLaneScope::Global.as_str(), "global");
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
        assert_eq!(CommitLevel::parse("  local  "), Some(CommitLevel::LocalCommit));
        assert_eq!(
            CommitLevel::parse("\treplicated\n"),
            Some(CommitLevel::ReplicatedCommit)
        );
    }

    #[test]
    fn store_lock_strategy_parse_trims_whitespace() {
        assert_eq!(StoreLockStrategy::parse("  mutex  "), Some(StoreLockStrategy::Mutex));
        assert_eq!(StoreLockStrategy::parse("\trwlock\n"), Some(StoreLockStrategy::RwLock));
    }

    #[test]
    fn append_lane_scope_parse_trims_whitespace() {
        assert_eq!(AppendLaneScope::parse("  global  "), Some(AppendLaneScope::Global));
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
        for alias in &["global", "GLOBAL"] {
            assert_eq!(
                AppendLaneScope::parse(alias),
                Some(AppendLaneScope::Global),
                "expected Global for alias '{alias}'"
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
        std::env::remove_var("CRUX_PASSPORT_CLAIM_ENDPOINT");
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("XDG_STATE_HOME");
    }

    #[test]
    #[serial_test::serial]
    fn load_config_defaults() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        let cfg = super::load_config();

        assert_eq!(cfg.loaded_config_path, None);
        assert_eq!(cfg.http_addr.port(), 14800);
        assert_eq!(cfg.http_addr.ip().to_string(), "127.0.0.1");
        assert_eq!(cfg.grpc_addr.port(), 4007);
        assert_eq!(cfg.grpc_addr.ip().to_string(), "127.0.0.1");
        assert_eq!(cfg.mcp_addr.port(), 14801);
        assert_eq!(cfg.mcp_addr.ip().to_string(), "127.0.0.1");
        assert!(cfg.mcp_enabled);
        assert_eq!(cfg.state_dir.to_str().unwrap(), "../CoreCruxData/v1");
        assert_eq!(cfg.data_dir.to_str().unwrap(), "../CoreCruxData/v1");
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
        assert!(!cfg.auth_mode_explicitly_set);
        assert_eq!(
            cfg.passport_key_path.to_str().unwrap(),
            "../CoreCruxData/v1/passport.key"
        );
        assert!(cfg.passport_claim_on_startup);
        assert_eq!(
            cfg.passport_claim_endpoint,
            "https://passport.vaultcrux.com/v1/claim-anonymous"
        );
        assert_eq!(cfg.content_manifest_path, None);
        assert!(cfg.content_verify_signatures);
        assert_eq!(cfg.router_refresh_interval_seconds, 60);
        assert_eq!(cfg.router_cache_ttl_seconds, 60);
        assert_eq!(cfg.router_fallback_policy, "degrade_to_local");
        assert!(cfg.enterprise_trust_root.is_none());
        assert_eq!(cfg.llm_endpoint, None);
        assert_eq!(cfg.llm_model, None);
        assert_eq!(cfg.io_backend, "cpu");
        assert!(!cfg.build_ccxi);
        assert!(!cfg.projections_enabled);
        assert_eq!(cfg.projections_batch_frames, 1024);
        assert_eq!(cfg.projections_tick_interval_ms, 1000);
        assert!(!cfg.admin_force_seal_enabled);
        assert_eq!(cfg.retention_days, None);
        assert!(cfg.receipts_verify_enabled);
        assert!(!cfg.receipts_recompute_candidate_digest);
        assert_eq!(cfg.receipts_keyring_path, None);
        assert_eq!(cfg.receipts_keyring_json, None);
        assert!(!cfg.witness_enabled);
        assert_eq!(cfg.witness_provider, "disabled");
        assert_eq!(cfg.witness_timeout_ms, 5_000);
        assert_eq!(cfg.rekor_url, None);
        assert_eq!(cfg.rekor_public_key_path, None);
        assert!(!cfg.tsa_enabled);
        assert_eq!(cfg.tsa_url, None);
        assert_eq!(cfg.tsa_root_cert_path, None);
        assert_eq!(cfg.tsa_policy_oid, None);
        assert_eq!(cfg.replay_batch_max_events, 64);
        assert_eq!(cfg.replay_batch_max_bytes, 262_144);
        assert_eq!(cfg.replay_many_max_reads, 64);
        assert!(cfg.replay_use_batched_rpc_default);
        assert_eq!(cfg.store_lock_strategy, StoreLockStrategy::Sharded);
        assert!(cfg.append_lane_enabled);
        assert_eq!(cfg.append_lane_scope, AppendLaneScope::Global);
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
        // Ephemeral GC is default OFF.
        assert!(!cfg.ephemeral_gc_enabled);
        // Coordination plane is default OFF; presence TTL defaults to 15 min.
        assert!(!cfg.coord_enabled);
        assert_eq!(cfg.coord_presence_ttl_secs, crate::coord::DEFAULT_PRESENCE_TTL_SECS);
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
        std::env::set_var("CORECRUXD_MCP_HOST", "0.0.0.0");
        std::env::set_var("CORECRUXD_MCP_PORT", "9997");
        std::env::set_var("CORECRUXD_MCP_ENABLED", "false");
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
        std::env::set_var("CORECRUXD_STATE_DIR", "/tmp/test-state");
        std::env::set_var("CORECRUXD_PASSPORT_KEY_PATH", "/tmp/test-state/passport.key");
        std::env::set_var("CORECRUXD_PASSPORT_CLAIM_ON_STARTUP", "false");
        std::env::set_var(
            "CORECRUXD_PASSPORT_CLAIM_ENDPOINT",
            "https://passport.example.test/claim",
        );
        std::env::set_var("CORECRUXD_CONTENT_MANIFEST_PATH", "/opt/crux/content/MANIFEST.json");
        std::env::set_var("CORECRUXD_CONTENT_VERIFY_SIGNATURES", "false");
        std::env::set_var("CORECRUXD_ROUTER_REFRESH_INTERVAL_SECONDS", "15");
        std::env::set_var("CORECRUXD_ROUTER_CACHE_TTL_SECONDS", "20");
        std::env::set_var("CORECRUXD_ROUTER_FALLBACK_POLICY", "refuse");
        std::env::set_var("CORECRUXD_ENTERPRISE_ENABLED", "true");
        std::env::set_var("CORECRUXD_ENTERPRISE_CUSTOMER_ID", "customer-a");
        std::env::set_var("CORECRUXD_ENTERPRISE_BACKEND_ID", "customer:cluster-a");
        std::env::set_var("CORECRUXD_ENTERPRISE_TRUST_ROOT_KID", "customer-root-a");
        std::env::set_var(
            "CORECRUXD_ENTERPRISE_TRUSTED_ISSUER_KIDS",
            "customer-issuer-a,customer-issuer-b",
        );
        std::env::set_var("CORECRUXD_ENTERPRISE_AIRGAP", "true");
        std::env::set_var("CORECRUXD_ENTERPRISE_ALLOW_VAULTCRUX_CROSS_SIGN", "false");
        std::env::set_var("CORECRUXD_LLM_ENDPOINT", "http://localhost:11434/api/generate");
        std::env::set_var("CORECRUXD_LLM_MODEL", "llama3.2:3b");
        std::env::set_var("CORECRUXD_IO_BACKEND", "gpu-gds");
        std::env::set_var("CORECRUXD_BUILD_CCXI", "true");
        std::env::set_var("CORECRUXD_PROJECTIONS_ENABLED", "1");
        std::env::set_var("CORECRUXD_PROJECTIONS_BATCH_FRAMES", "2048");
        std::env::set_var("CORECRUXD_PROJECTIONS_TICK_INTERVAL_MS", "500");
        std::env::set_var("CORECRUXD_ADMIN_FORCE_SEAL", "yes");
        std::env::set_var("CORECRUXD_RECEIPTS_VERIFY_ENABLED", "false");
        std::env::set_var("CORECRUXD_RECEIPTS_RECOMPUTE_CANDIDATE_DIGEST", "true");
        std::env::set_var("CORECRUXD_WITNESS_ENABLED", "true");
        std::env::set_var("CORECRUXD_WITNESS_PROVIDER", "rekor");
        std::env::set_var("CORECRUXD_WITNESS_TIMEOUT_MS", "7500");
        std::env::set_var("CORECRUXD_REKOR_URL", "https://rekor.example");
        std::env::set_var("CORECRUXD_REKOR_PUBLIC_KEY_PATH", "/tmp/rekor.pub");
        std::env::set_var("CORECRUXD_TSA_ENABLED", "true");
        std::env::set_var("CORECRUXD_TSA_URL", "https://tsa.example");
        std::env::set_var("CORECRUXD_TSA_ROOT_CERT_PATH", "/tmp/tsa-root.pem");
        std::env::set_var("CORECRUXD_TSA_POLICY_OID", "1.2.3.4");
        std::env::set_var("CORECRUXD_STORE_LOCK_STRATEGY", "rwlock");
        std::env::set_var("CORECRUXD_APPEND_LANE_ENABLED", "false");
        std::env::set_var("CORECRUXD_APPEND_LANE_SCOPE", "shard");
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
        assert_eq!(cfg.mcp_addr.port(), 9997);
        assert_eq!(cfg.mcp_addr.ip().to_string(), "0.0.0.0");
        assert!(!cfg.mcp_enabled);
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
        assert!(cfg.auth_mode_explicitly_set);
        assert_eq!(cfg.state_dir.to_str().unwrap(), "/tmp/test-state");
        assert_eq!(cfg.passport_key_path.to_str().unwrap(), "/tmp/test-state/passport.key");
        assert!(!cfg.passport_claim_on_startup);
        assert_eq!(cfg.passport_claim_endpoint, "https://passport.example.test/claim");
        assert_eq!(
            cfg.content_manifest_path.as_ref().unwrap().to_str().unwrap(),
            "/opt/crux/content/MANIFEST.json"
        );
        assert!(!cfg.content_verify_signatures);
        assert_eq!(cfg.router_refresh_interval_seconds, 15);
        assert_eq!(cfg.router_cache_ttl_seconds, 20);
        assert_eq!(cfg.router_fallback_policy, "refuse");
        let enterprise = cfg.enterprise_trust_root.as_ref().unwrap();
        assert_eq!(enterprise.customer_id, "customer-a");
        assert_eq!(enterprise.backend_id, "customer:cluster-a");
        assert_eq!(enterprise.trust_root_kid, "customer-root-a");
        assert_eq!(
            enterprise.trusted_issuer_kids,
            vec!["customer-issuer-a".to_string(), "customer-issuer-b".to_string()]
        );
        assert!(enterprise.airgap);
        assert!(!enterprise.allow_vaultcrux_cross_sign);
        assert_eq!(cfg.llm_endpoint.as_deref(), Some("http://localhost:11434/api/generate"));
        assert_eq!(cfg.llm_model.as_deref(), Some("llama3.2:3b"));
        // io_backend from CORECRUXD_IO_BACKEND env (test sets "gpu-gds", kept for compatibility)
        assert_eq!(cfg.io_backend, "gpu-gds");
        assert!(cfg.build_ccxi);
        assert!(cfg.projections_enabled);
        assert_eq!(cfg.projections_batch_frames, 2048);
        assert_eq!(cfg.projections_tick_interval_ms, 500);
        assert!(cfg.admin_force_seal_enabled);
        assert!(!cfg.receipts_verify_enabled);
        assert!(cfg.receipts_recompute_candidate_digest);
        assert!(cfg.witness_enabled);
        assert_eq!(cfg.witness_provider, "rekor");
        assert_eq!(cfg.witness_timeout_ms, 7_500);
        assert_eq!(cfg.rekor_url.as_deref(), Some("https://rekor.example"));
        assert_eq!(
            cfg.rekor_public_key_path.as_ref().unwrap().to_str().unwrap(),
            "/tmp/rekor.pub"
        );
        assert!(cfg.tsa_enabled);
        assert_eq!(cfg.tsa_url.as_deref(), Some("https://tsa.example"));
        assert_eq!(
            cfg.tsa_root_cert_path.as_ref().unwrap().to_str().unwrap(),
            "/tmp/tsa-root.pem"
        );
        assert_eq!(cfg.tsa_policy_oid.as_deref(), Some("1.2.3.4"));
        assert_eq!(cfg.store_lock_strategy, StoreLockStrategy::RwLock);
        assert!(!cfg.append_lane_enabled);
        assert_eq!(cfg.append_lane_scope, AppendLaneScope::Shard);
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
    fn load_config_reads_xdg_yaml_and_env_overrides() {
        let lock = env_lock();
        let _g = lock.lock().unwrap();
        clear_corecruxd_env();

        let tmp = tempfile::tempdir().unwrap();
        let config_home = tmp.path().join("config");
        let state_home = tmp.path().join("state");
        let config_dir = config_home.join("crux");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(
            config_dir.join("config.yaml"),
            r#"
daemon:
  instance_id: "daemon-from-yaml"
  state_dir: "$XDG_STATE_HOME/crux"
  listen_addr: "127.0.0.2"
  http_port: 15000
  grpc_port: 15002
  mcp_port: 15001
  mcp_enabled: false
  auth_mode: "off"
passport:
  key_path: "$XDG_STATE_HOME/crux/passport.key"
  claim_on_startup: false
  claim_endpoint: "https://passport.example.test/v1/claim"
content:
  manifest_path: "$XDG_STATE_HOME/crux/content/MANIFEST.json"
  verify_signatures: false
router:
  refresh_interval_seconds: 7
  cache_ttl_seconds: 9
  fallback_policy: "refuse"
enterprise:
  enabled: true
  customer_id: "customer-yaml"
  backend_id: "customer:yaml-cluster"
  trust_root_kid: "yaml-root"
  trusted_issuer_kids:
    - "yaml-issuer"
  airgap: true
  allow_vaultcrux_cross_sign: true
llm:
  endpoint: "http://localhost:11434/api/generate"
  model: "llama3.2:3b"
"#,
        )
        .unwrap();

        std::env::set_var("XDG_CONFIG_HOME", &config_home);
        std::env::set_var("XDG_STATE_HOME", &state_home);
        std::env::set_var("CORECRUXD_HTTP_PORT", "16000");

        let cfg = super::load_config();

        assert_eq!(
            cfg.loaded_config_path.as_ref().unwrap(),
            &config_dir.join("config.yaml")
        );
        assert_eq!(cfg.http_addr.ip().to_string(), "127.0.0.2");
        assert_eq!(cfg.http_addr.port(), 16000);
        assert_eq!(cfg.grpc_addr.port(), 15002);
        assert_eq!(cfg.mcp_addr.port(), 15001);
        assert!(!cfg.mcp_enabled);
        assert_eq!(cfg.state_dir, state_home.join("crux"));
        assert_eq!(cfg.data_dir, state_home.join("crux"));
        assert_eq!(cfg.node_id_override.as_deref(), Some("daemon-from-yaml"));
        assert_eq!(cfg.auth_mode, crate::auth::AuthMode::Off);
        assert!(cfg.auth_mode_explicitly_set);
        assert_eq!(cfg.passport_key_path, state_home.join("crux").join("passport.key"));
        assert!(!cfg.passport_claim_on_startup);
        assert_eq!(cfg.passport_claim_endpoint, "https://passport.example.test/v1/claim");
        assert_eq!(
            cfg.content_manifest_path.as_ref().unwrap(),
            &state_home.join("crux").join("content").join("MANIFEST.json")
        );
        assert!(!cfg.content_verify_signatures);
        assert_eq!(cfg.router_refresh_interval_seconds, 7);
        assert_eq!(cfg.router_cache_ttl_seconds, 9);
        assert_eq!(cfg.router_fallback_policy, "refuse");
        let enterprise = cfg.enterprise_trust_root.as_ref().unwrap();
        assert_eq!(enterprise.customer_id, "customer-yaml");
        assert_eq!(enterprise.backend_id, "customer:yaml-cluster");
        assert_eq!(enterprise.trust_root_kid, "yaml-root");
        assert_eq!(enterprise.trusted_issuer_kids, vec!["yaml-issuer".to_string()]);
        assert!(enterprise.airgap);
        assert!(enterprise.allow_vaultcrux_cross_sign);
        assert_eq!(cfg.llm_endpoint.as_deref(), Some("http://localhost:11434/api/generate"));
        assert_eq!(cfg.llm_model.as_deref(), Some("llama3.2:3b"));

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
