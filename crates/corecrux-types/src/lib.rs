// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecrux-types` — Core types for the CoreCrux event store.
//!
//! This crate defines the foundational data types shared across all CoreCrux crates:
//!
//! - **Evidence types** — structured evidence payloads attached to events
//! - **Control evidence** — system-level control signals (e.g., seal markers)
//! - **Decision plane types** — decision context and outcome records
//!
//! These types are intentionally kept in a leaf crate with minimal dependencies
//! so that every other crate in the workspace can depend on them without
//! introducing cycles. Serialisation uses `serde` with JSON as the wire format.

mod control_evidence;
mod decision_plane;
mod evidence;

use serde::{Deserialize, Serialize};

pub use control_evidence::*;
pub use decision_plane::*;
pub use evidence::*;

pub const DEFAULT_COMPAT_REQUIRES: &str = ">=3.0 <4.0";
pub const DEFAULT_SDK_VERSION: &str = "3.0.0-dev";
pub const CORE_ERROR_BASE_URI: &str = "https://errors.cuecrux.com";

// Phase 3 routing/sharding contracts (ShardMapV1).
pub const SHARDMAP_V1: u32 = 1;
pub const SHARDMAP_HASH_FN_V1: &str = "xxhash64-v1";
pub const SHARDMAP_KEY_ENCODING_V1: &str = "utf8-nul-delimited-v1";

// CoreCrux Community Edition error taxonomy (11/11 — GPU variants removed).
pub const CORE_ERROR_IO_READ_FAILED: &str = "IO_READ_FAILED";
pub const CORE_ERROR_IO_WRITE_FAILED: &str = "IO_WRITE_FAILED";
pub const CORE_ERROR_IO_FSYNC_FAILED: &str = "IO_FSYNC_FAILED";
pub const CORE_ERROR_SEGMENT_CORRUPT: &str = "SEGMENT_CORRUPT";
pub const CORE_ERROR_INVALID_FRAME: &str = "INVALID_FRAME";
pub const CORE_ERROR_INVALID_TOC: &str = "INVALID_TOC";
pub const CORE_ERROR_SHARD_NOT_OWNER: &str = "SHARD_NOT_OWNER";
pub const CORE_ERROR_EPOCH_MISMATCH: &str = "EPOCH_MISMATCH";
pub const CORE_ERROR_BACKPRESSURE: &str = "BACKPRESSURE";
pub const CORE_ERROR_TIMEOUT: &str = "TIMEOUT";
pub const CORE_ERROR_INTERNAL: &str = "INTERNAL";

pub const CORE_ERROR_CODES: [&str; 11] = [
    CORE_ERROR_IO_READ_FAILED,
    CORE_ERROR_IO_WRITE_FAILED,
    CORE_ERROR_IO_FSYNC_FAILED,
    CORE_ERROR_SEGMENT_CORRUPT,
    CORE_ERROR_INVALID_FRAME,
    CORE_ERROR_INVALID_TOC,
    CORE_ERROR_SHARD_NOT_OWNER,
    CORE_ERROR_EPOCH_MISMATCH,
    CORE_ERROR_BACKPRESSURE,
    CORE_ERROR_TIMEOUT,
    CORE_ERROR_INTERNAL,
];

// CoreCrux Master Plan v3.1 replay mismatch classification constants (6/6).
pub const DRIFT_SOURCE_CHANGE: &str = "DRIFT_SOURCE_CHANGE";
pub const DRIFT_MODEL_CHANGE: &str = "DRIFT_MODEL_CHANGE";
pub const DRIFT_POLICY_CHANGE: &str = "DRIFT_POLICY_CHANGE";
pub const DRIFT_INDEX_CHANGE: &str = "DRIFT_INDEX_CHANGE";
pub const DRIFT_NONDETERMINISM: &str = "DRIFT_NONDETERMINISM";
pub const DRIFT_UNKNOWN: &str = "DRIFT_UNKNOWN";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DriftClass {
    #[serde(rename = "DRIFT_SOURCE_CHANGE")]
    SourceChange,
    #[serde(rename = "DRIFT_MODEL_CHANGE")]
    ModelChange,
    #[serde(rename = "DRIFT_POLICY_CHANGE")]
    PolicyChange,
    #[serde(rename = "DRIFT_INDEX_CHANGE")]
    IndexChange,
    #[serde(rename = "DRIFT_NONDETERMINISM")]
    Nondeterminism,
    #[serde(rename = "DRIFT_UNKNOWN")]
    Unknown,
}

impl DriftClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceChange => DRIFT_SOURCE_CHANGE,
            Self::ModelChange => DRIFT_MODEL_CHANGE,
            Self::PolicyChange => DRIFT_POLICY_CHANGE,
            Self::IndexChange => DRIFT_INDEX_CHANGE,
            Self::Nondeterminism => DRIFT_NONDETERMINISM,
            Self::Unknown => DRIFT_UNKNOWN,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildInfo {
    pub version: String,
    pub commit: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateCheckState {
    Disabled,
    Current,
    Behind,
    Ahead,
    Diverged,
    Unavailable,
    Error,
}

impl UpdateCheckState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Current => "current",
            Self::Behind => "behind",
            Self::Ahead => "ahead",
            Self::Diverged => "diverged",
            Self::Unavailable => "unavailable",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateStatus {
    pub enabled: bool,
    pub state: UpdateCheckState,
    pub remote: String,
    #[serde(rename = "ref")]
    pub ref_name: String,
    pub tracking_ref: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_commit: Option<String>,
    pub ahead_by: u64,
    pub behind_by: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub upgrade_hint: String,
}

impl UpdateStatus {
    pub fn public_view(&self) -> Self {
        let mut status = self.clone();
        status.repo_dir = None;
        status.error = None;
        status
    }
}

impl Default for UpdateStatus {
    fn default() -> Self {
        Self {
            enabled: false,
            state: UpdateCheckState::Disabled,
            remote: String::new(),
            ref_name: String::new(),
            tracking_ref: String::new(),
            repo_dir: None,
            current_commit: None,
            latest_commit: None,
            ahead_by: 0,
            behind_by: 0,
            checked_at: None,
            error: None,
            upgrade_hint: "Update checks are disabled.".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatContract {
    pub requires: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KnowledgeAuthorityModeV1 {
    #[serde(rename = "knowledge_shadow")]
    Shadow,
    #[serde(rename = "knowledge_dual_write")]
    DualWrite,
    #[serde(rename = "knowledge_shadow_read")]
    ShadowRead,
    #[serde(rename = "knowledge_authoritative")]
    Authoritative,
}

impl KnowledgeAuthorityModeV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "knowledge_shadow",
            Self::DualWrite => "knowledge_dual_write",
            Self::ShadowRead => "knowledge_shadow_read",
            Self::Authoritative => "knowledge_authoritative",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KnowledgeRolloutStageV1 {
    #[serde(rename = "internal_shadow")]
    InternalShadow,
    #[serde(rename = "tenant_validation")]
    TenantValidation,
    #[serde(rename = "internal_authority")]
    InternalAuthority,
    #[serde(rename = "limited_production_authority")]
    LimitedProductionAuthority,
    #[serde(rename = "full_production_authority")]
    FullProductionAuthority,
}

impl KnowledgeRolloutStageV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InternalShadow => "internal_shadow",
            Self::TenantValidation => "tenant_validation",
            Self::InternalAuthority => "internal_authority",
            Self::LimitedProductionAuthority => "limited_production_authority",
            Self::FullProductionAuthority => "full_production_authority",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum KnowledgeParityStatusV1 {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "pass")]
    Pass,
    #[serde(rename = "warn")]
    Warn,
    #[serde(rename = "fail")]
    Fail,
}

impl KnowledgeParityStatusV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeParityThresholdsV1 {
    #[serde(rename = "maxMismatchCount")]
    pub max_mismatch_count: u64,
    #[serde(rename = "maxCursorMissingCount")]
    pub max_cursor_missing_count: u64,
    #[serde(rename = "minPassRatioBps")]
    pub min_pass_ratio_bps: u32,
}

impl Default for KnowledgeParityThresholdsV1 {
    fn default() -> Self {
        Self {
            max_mismatch_count: 0,
            max_cursor_missing_count: 0,
            min_pass_ratio_bps: 10_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeLagThresholdsV1 {
    #[serde(rename = "maxProjectionLagMs")]
    pub max_projection_lag_ms: u64,
    #[serde(rename = "maxCursorAgeMs")]
    pub max_cursor_age_ms: u64,
}

impl Default for KnowledgeLagThresholdsV1 {
    fn default() -> Self {
        Self {
            max_projection_lag_ms: 60_000,
            max_cursor_age_ms: 300_000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeParityOutcomeV1 {
    pub status: KnowledgeParityStatusV1,
    #[serde(rename = "checkedAtUnixMs")]
    pub checked_at_unix_ms: u64,
    #[serde(rename = "mismatchCount")]
    pub mismatch_count: u64,
    #[serde(rename = "cursorMissingCount")]
    pub cursor_missing_count: u64,
    #[serde(rename = "passRatioBps")]
    pub pass_ratio_bps: u32,
    #[serde(rename = "projectionLagMs")]
    pub projection_lag_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeAuthorityV1 {
    pub mode: KnowledgeAuthorityModeV1,
    #[serde(rename = "rolloutStage")]
    pub rollout_stage: KnowledgeRolloutStageV1,
    #[serde(rename = "parityThresholds")]
    pub parity_thresholds: KnowledgeParityThresholdsV1,
    #[serde(rename = "lagThresholds")]
    pub lag_thresholds: KnowledgeLagThresholdsV1,
    #[serde(rename = "lastParityOutcome", skip_serializing_if = "Option::is_none")]
    pub last_parity_outcome: Option<KnowledgeParityOutcomeV1>,
    #[serde(rename = "rollbackTriggered")]
    pub rollback_triggered: bool,
    pub actor: String,
    pub reason: String,
    #[serde(rename = "updatedAtUnixNs")]
    pub updated_at_unix_ns: u64,
}

impl Default for KnowledgeAuthorityV1 {
    fn default() -> Self {
        Self {
            mode: KnowledgeAuthorityModeV1::Shadow,
            rollout_stage: KnowledgeRolloutStageV1::InternalShadow,
            parity_thresholds: KnowledgeParityThresholdsV1::default(),
            lag_thresholds: KnowledgeLagThresholdsV1::default(),
            last_parity_outcome: None,
            rollback_triggered: false,
            actor: String::new(),
            reason: String::new(),
            updated_at_unix_ns: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthzResponse {
    pub ok: bool,
    pub build: BuildInfo,
    pub compat: CompatContract,
    #[serde(rename = "sdkVersion")]
    pub sdk_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing: Option<RoutingInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valves: Option<ValvesInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValveInfo {
    pub enabled: bool,
    pub actor: String,
    pub reason: String,
    #[serde(rename = "updatedAtUnixNs")]
    pub updated_at_unix_ns: u64,
    #[serde(rename = "retryAfterMs", skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValvesInfo {
    #[serde(rename = "pauseIngest")]
    pub pause_ingest: ValveInfo,
    #[serde(rename = "pauseCompaction")]
    pub pause_compaction: ValveInfo,
    #[serde(rename = "throttle")]
    pub throttle: ValveInfo,
    #[serde(rename = "readOnly")]
    pub read_only: ValveInfo,
    #[serde(rename = "emergencyBrake")]
    pub emergency_brake: ValveInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingInfo {
    #[serde(rename = "shardMapVersion")]
    pub shard_map_version: u64,
    #[serde(rename = "shardCount")]
    pub shard_count: u64,
    #[serde(rename = "lastReloadAt")]
    pub last_reload_at: Option<String>,
    #[serde(rename = "nodeId")]
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashRange {
    #[serde(rename = "startInclusive")]
    pub start_inclusive: String,
    #[serde(rename = "endExclusive")]
    pub end_exclusive: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAddr {
    #[serde(rename = "nodeId")]
    pub node_id: String,
    #[serde(rename = "grpcAddr")]
    pub grpc_addr: String,
    #[serde(rename = "httpAddr")]
    pub http_addr: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ShardState {
    Active,
    Draining,
    Retired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardDescriptor {
    #[serde(rename = "shardId")]
    pub shard_id: String,
    pub epoch: u64,
    pub state: ShardState,
    pub ranges: Vec<HashRange>,
    pub leader: NodeAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub followers: Option<Vec<NodeAddr>>,
    #[serde(rename = "dataDir", skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<String>,
    #[serde(rename = "gpuId", skip_serializing_if = "Option::is_none")]
    pub gpu_id: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardMapV1 {
    pub v: u32,
    #[serde(rename = "clusterId")]
    pub cluster_id: String,
    pub version: u64,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "hashFn")]
    pub hash_fn: String,
    #[serde(rename = "keyEncoding")]
    pub key_encoding: String,
    pub shards: Vec<ShardDescriptor>,
    pub blake3: String,
    #[serde(rename = "prevBlake3", skip_serializing_if = "Option::is_none")]
    pub prev_blake3: Option<String>,
}

pub fn build_info() -> BuildInfo {
    BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: option_env!("CORECRUX_GIT_SHA").unwrap_or("unknown").to_string(),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ShardMapError {
    #[error("invalid shard map: {msg}")]
    Invalid { msg: String },
}

pub type ShardMapResult<T> = std::result::Result<T, ShardMapError>;

pub fn format_u64_hex(v: u64) -> String {
    format!("0x{v:016x}")
}

pub fn parse_u64_hex(input: &str) -> ShardMapResult<u64> {
    let s = input.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() {
        return Err(ShardMapError::Invalid {
            msg: "empty hex string".to_string(),
        });
    }
    u64::from_str_radix(s, 16).map_err(|e| ShardMapError::Invalid {
        msg: format!("invalid u64 hex '{input}': {e}"),
    })
}

pub fn parse_shard_id_u32(shard_id: &str) -> ShardMapResult<u32> {
    // Phase 3 convention: shardId is a string, typically "shard-0001".
    // For Phase 2 storage/manifest fields we still carry a numeric shard_id.
    let (_, suffix) = shard_id.rsplit_once('-').ok_or_else(|| ShardMapError::Invalid {
        msg: format!("invalid shardId '{shard_id}' (expected 'shard-<digits>')"),
    })?;
    if suffix.is_empty() || !suffix.as_bytes().iter().all(|b| b.is_ascii_digit()) {
        return Err(ShardMapError::Invalid {
            msg: format!("invalid shardId '{shard_id}' (expected digits suffix)"),
        });
    }
    suffix.parse::<u32>().map_err(|e| ShardMapError::Invalid {
        msg: format!("invalid shardId '{shard_id}' (u32 parse failed): {e}"),
    })
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    String::from_utf8_lossy(&out).to_string()
}

fn normalize_range(mut r: HashRange) -> ShardMapResult<HashRange> {
    let s = parse_u64_hex(&r.start_inclusive)?;
    let e = parse_u64_hex(&r.end_exclusive)?;
    r.start_inclusive = format_u64_hex(s);
    r.end_exclusive = format_u64_hex(e);
    Ok(r)
}

fn normalize_shard(mut s: ShardDescriptor) -> ShardMapResult<ShardDescriptor> {
    let mut ranges: Vec<(u64, HashRange)> = Vec::with_capacity(s.ranges.len());
    for r in s.ranges.drain(..) {
        let nr = normalize_range(r)?;
        let start = parse_u64_hex(&nr.start_inclusive)?;
        ranges.push((start, nr));
    }
    ranges.sort_by_key(|(start, _)| *start);
    s.ranges = ranges.into_iter().map(|(_, r)| r).collect();

    if let Some(followers) = s.followers.as_mut() {
        followers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
    }
    Ok(s)
}

pub fn canonicalize_shard_map_v1(map: &ShardMapV1) -> ShardMapResult<ShardMapV1> {
    let mut out = map.clone();
    out.blake3.clear();

    out.shards = out
        .shards
        .drain(..)
        .map(normalize_shard)
        .collect::<ShardMapResult<Vec<_>>>()?;
    out.shards.sort_by(|a, b| a.shard_id.cmp(&b.shard_id));
    Ok(out)
}

pub fn compute_shard_map_v1_blake3(map: &ShardMapV1) -> ShardMapResult<[u8; 32]> {
    #[derive(Serialize)]
    struct DigestView<'a> {
        v: u32,
        #[serde(rename = "clusterId")]
        cluster_id: &'a str,
        version: u64,
        #[serde(rename = "createdAt")]
        created_at: &'a str,
        #[serde(rename = "hashFn")]
        hash_fn: &'a str,
        #[serde(rename = "keyEncoding")]
        key_encoding: &'a str,
        shards: &'a [ShardDescriptor],
        #[serde(rename = "prevBlake3", skip_serializing_if = "Option::is_none")]
        prev_blake3: &'a Option<String>,
    }

    let canon = canonicalize_shard_map_v1(map)?;
    let view = DigestView {
        v: canon.v,
        cluster_id: &canon.cluster_id,
        version: canon.version,
        created_at: &canon.created_at,
        hash_fn: &canon.hash_fn,
        key_encoding: &canon.key_encoding,
        shards: &canon.shards,
        prev_blake3: &canon.prev_blake3,
    };

    let bytes = serde_json::to_vec(&view).map_err(|e| ShardMapError::Invalid {
        msg: format!("failed to serialize shard map digest view: {e}"),
    })?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

pub fn compute_shard_map_v1_blake3_hex(map: &ShardMapV1) -> ShardMapResult<String> {
    Ok(hex32(&compute_shard_map_v1_blake3(map)?))
}

pub fn validate_shard_map_v1(map: &ShardMapV1) -> ShardMapResult<()> {
    if map.v != SHARDMAP_V1 {
        return Err(ShardMapError::Invalid {
            msg: format!("unsupported shard map version v={} (expected {SHARDMAP_V1})", map.v),
        });
    }
    if map.cluster_id.trim().is_empty() {
        return Err(ShardMapError::Invalid {
            msg: "clusterId must be non-empty".to_string(),
        });
    }
    if map.version == 0 {
        return Err(ShardMapError::Invalid {
            msg: "version must be >= 1".to_string(),
        });
    }
    if map.hash_fn != SHARDMAP_HASH_FN_V1 {
        return Err(ShardMapError::Invalid {
            msg: format!("hashFn must be '{SHARDMAP_HASH_FN_V1}'"),
        });
    }
    if map.key_encoding != SHARDMAP_KEY_ENCODING_V1 {
        return Err(ShardMapError::Invalid {
            msg: format!("keyEncoding must be '{SHARDMAP_KEY_ENCODING_V1}'"),
        });
    }
    if map.shards.is_empty() {
        return Err(ShardMapError::Invalid {
            msg: "shards must be non-empty".to_string(),
        });
    }

    let computed = compute_shard_map_v1_blake3_hex(map)?;
    if map.blake3 != computed {
        return Err(ShardMapError::Invalid {
            msg: format!("blake3 mismatch: expected {computed}, got {}", map.blake3),
        });
    }

    // Validate ring coverage for ACTIVE ranges.
    // Ring is [0, 2^64). Ranges are [startInclusive, endExclusive).
    const RING_END: u128 = 1u128 << 64;

    #[derive(Clone, Copy)]
    struct Interval {
        start: u128,
        end: u128,
    }

    let mut intervals: Vec<Interval> = Vec::new();
    let mut seen_shard_ids = std::collections::HashSet::<String>::new();

    for shard in &map.shards {
        if !seen_shard_ids.insert(shard.shard_id.clone()) {
            return Err(ShardMapError::Invalid {
                msg: format!("duplicate shardId '{}'", shard.shard_id),
            });
        }
        if shard.epoch == 0 {
            return Err(ShardMapError::Invalid {
                msg: format!("shard '{}' epoch must be >= 1", shard.shard_id),
            });
        }

        if shard.state != ShardState::Active {
            continue;
        }
        if shard.ranges.is_empty() {
            return Err(ShardMapError::Invalid {
                msg: format!("shard '{}' ranges must be non-empty", shard.shard_id),
            });
        }

        for r in &shard.ranges {
            let start = parse_u64_hex(&r.start_inclusive)? as u128;
            let end = parse_u64_hex(&r.end_exclusive)? as u128;

            if start == end {
                // Special-case: a single full-ring range is represented as [0,0).
                // This is only valid for the canonical full-ring encoding (start=end=0).
                if start != 0 {
                    return Err(ShardMapError::Invalid {
                        msg: format!(
                            "range startInclusive==endExclusive is only valid for full-ring [0,0) (got startInclusive={})",
                            r.start_inclusive
                        ),
                    });
                }
                intervals.push(Interval {
                    start: 0,
                    end: RING_END,
                });
                continue;
            }

            if start < end {
                intervals.push(Interval { start, end });
            } else {
                // Wrap-around: split into [start, 2^64) and [0, end)
                intervals.push(Interval { start, end: RING_END });
                if end != 0 {
                    intervals.push(Interval { start: 0, end });
                }
            }
        }
    }

    if intervals.is_empty() {
        return Err(ShardMapError::Invalid {
            msg: "no ACTIVE ranges found in shard map".to_string(),
        });
    }

    intervals.sort_by_key(|i| i.start);
    for w in intervals.windows(2) {
        let a = w[0];
        let b = w[1];
        if b.start < a.end {
            return Err(ShardMapError::Invalid {
                msg: "active ranges overlap".to_string(),
            });
        }
    }
    // SAFETY: intervals is non-empty — validated by the overlap check loop above.
    #[allow(clippy::unwrap_used)]
    if intervals[0].start != 0 || intervals.last().unwrap().end != RING_END {
        return Err(ShardMapError::Invalid {
            msg: "active ranges do not cover full ring (missing start/end)".to_string(),
        });
    }
    for w in intervals.windows(2) {
        if w[0].end != w[1].start {
            return Err(ShardMapError::Invalid {
                msg: "active ranges do not cover full ring (gap detected)".to_string(),
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// RFC 9457 Problem Details
// ---------------------------------------------------------------------------

/// RFC 9457 Problem Details for HTTP APIs.
///
/// Serialises to `application/problem+json`. Extension members live in
/// `extensions` and are flattened into the top-level JSON object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemDetails {
    /// A URI reference identifying the problem type.
    #[serde(rename = "type")]
    pub problem_type: String,
    /// A short human-readable summary.
    pub title: String,
    /// The HTTP status code.
    pub status: u16,
    /// A human-readable explanation specific to this occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// A URI identifying this specific occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Extension members (flattened into the top-level JSON object).
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<serde_json::Value>,
}

impl ProblemDetails {
    pub fn new(status: u16, problem_type: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            problem_type: problem_type.into(),
            title: title.into(),
            status,
            detail: None,
            instance: None,
            extensions: None,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = Some(instance.into());
        self
    }

    pub fn with_extensions(mut self, ext: serde_json::Value) -> Self {
        self.extensions = Some(ext);
        self
    }

    // -- Factory methods for common HTTP errors --

    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(400, format!("{CORE_ERROR_BASE_URI}/bad-request"), "Bad Request").with_detail(detail)
    }

    pub fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(401, format!("{CORE_ERROR_BASE_URI}/unauthorized"), "Unauthorized").with_detail(detail)
    }

    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(403, format!("{CORE_ERROR_BASE_URI}/forbidden"), "Forbidden").with_detail(detail)
    }

    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::new(404, format!("{CORE_ERROR_BASE_URI}/not-found"), "Not Found").with_detail(detail)
    }

    pub fn precondition_failed(detail: impl Into<String>) -> Self {
        Self::new(
            412,
            format!("{CORE_ERROR_BASE_URI}/precondition-failed"),
            "Precondition Failed",
        )
        .with_detail(detail)
    }

    pub fn rate_limited(detail: impl Into<String>) -> Self {
        Self::new(429, format!("{CORE_ERROR_BASE_URI}/rate-limited"), "Too Many Requests").with_detail(detail)
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(500, format!("{CORE_ERROR_BASE_URI}/internal"), "Internal Server Error").with_detail(detail)
    }

    pub fn not_implemented(detail: impl Into<String>) -> Self {
        Self::new(501, format!("{CORE_ERROR_BASE_URI}/not-implemented"), "Not Implemented").with_detail(detail)
    }

    pub fn service_unavailable(detail: impl Into<String>) -> Self {
        Self::new(
            503,
            format!("{CORE_ERROR_BASE_URI}/service-unavailable"),
            "Service Unavailable",
        )
        .with_detail(detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_shard_map() -> ShardMapV1 {
        ShardMapV1 {
            v: SHARDMAP_V1,
            cluster_id: "cluster-a".to_string(),
            version: 1,
            created_at: "2026-02-21T00:00:00Z".to_string(),
            hash_fn: SHARDMAP_HASH_FN_V1.to_string(),
            key_encoding: SHARDMAP_KEY_ENCODING_V1.to_string(),
            shards: vec![
                ShardDescriptor {
                    shard_id: "shard-0002".to_string(),
                    epoch: 1,
                    state: ShardState::Active,
                    ranges: vec![HashRange {
                        start_inclusive: "0x8000000000000000".to_string(),
                        end_exclusive: "0x0".to_string(),
                    }],
                    leader: NodeAddr {
                        node_id: "node-b".to_string(),
                        grpc_addr: "127.0.0.1:7441".to_string(),
                        http_addr: "127.0.0.1:8441".to_string(),
                    },
                    followers: Some(vec![
                        NodeAddr {
                            node_id: "node-c".to_string(),
                            grpc_addr: "127.0.0.1:7442".to_string(),
                            http_addr: "127.0.0.1:8442".to_string(),
                        },
                        NodeAddr {
                            node_id: "node-a".to_string(),
                            grpc_addr: "127.0.0.1:7440".to_string(),
                            http_addr: "127.0.0.1:8440".to_string(),
                        },
                    ]),
                    data_dir: None,
                    gpu_id: None,
                },
                ShardDescriptor {
                    shard_id: "shard-0001".to_string(),
                    epoch: 1,
                    state: ShardState::Active,
                    ranges: vec![HashRange {
                        start_inclusive: "0x0".to_string(),
                        end_exclusive: "0x8000000000000000".to_string(),
                    }],
                    leader: NodeAddr {
                        node_id: "node-a".to_string(),
                        grpc_addr: "127.0.0.1:7440".to_string(),
                        http_addr: "127.0.0.1:8440".to_string(),
                    },
                    followers: None,
                    data_dir: None,
                    gpu_id: None,
                },
            ],
            blake3: String::new(),
            prev_blake3: None,
        }
    }

    #[test]
    fn shard_helpers_parse_and_normalize() {
        assert_eq!(parse_shard_id_u32("shard-0042").expect("shard id"), 42);
        assert!(parse_shard_id_u32("bad-shard").is_err());
        assert_eq!(parse_u64_hex("0x000000000000000f").expect("hex parse"), 15_u64);
        assert_eq!(format_u64_hex(15), "0x000000000000000f");
    }

    #[test]
    fn canonicalize_and_validate_shard_map() {
        let mut map = sample_shard_map();
        let canon = canonicalize_shard_map_v1(&map).expect("canonicalize");
        assert_eq!(canon.shards[0].shard_id, "shard-0001");
        assert_eq!(
            canon.shards[1].followers.as_ref().expect("followers")[0].node_id,
            "node-a"
        );
        assert_eq!(canon.shards[1].ranges[0].end_exclusive, "0x0000000000000000");

        map.blake3 = compute_shard_map_v1_blake3_hex(&map).expect("hash");
        validate_shard_map_v1(&map).expect("valid shard map");

        map.blake3 = "deadbeef".to_string();
        assert!(validate_shard_map_v1(&map).is_err());
    }

    #[test]
    fn problem_details_factories_emit_rfc9457_shape() {
        let problem = ProblemDetails::rate_limited("slow down")
            .with_instance("/v1/ingest")
            .with_extensions(json!({ "request_id": "req-123" }));

        let encoded = serde_json::to_value(problem).expect("serialize");
        assert_eq!(encoded["type"], format!("{CORE_ERROR_BASE_URI}/rate-limited"));
        assert_eq!(encoded["title"], "Too Many Requests");
        assert_eq!(encoded["status"], 429);
        assert_eq!(encoded["detail"], "slow down");
        assert_eq!(encoded["instance"], "/v1/ingest");
        assert_eq!(encoded["request_id"], "req-123");
    }

    // ── Error constant tests ───────────────────────────────────────

    #[test]
    fn error_codes_array_length_matches_community_edition() {
        assert_eq!(CORE_ERROR_CODES.len(), 11);
    }

    #[test]
    fn error_codes_array_contains_no_gpu_variants() {
        for code in &CORE_ERROR_CODES {
            assert!(
                !code.starts_with("GPU_"),
                "community edition must not contain GPU error code: {code}"
            );
        }
    }

    #[test]
    fn error_codes_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for code in &CORE_ERROR_CODES {
            assert!(seen.insert(*code), "duplicate error code: {code}");
        }
    }

    #[test]
    fn error_code_constants_match_array_entries() {
        assert!(CORE_ERROR_CODES.contains(&CORE_ERROR_IO_READ_FAILED));
        assert!(CORE_ERROR_CODES.contains(&CORE_ERROR_IO_WRITE_FAILED));
        assert!(CORE_ERROR_CODES.contains(&CORE_ERROR_IO_FSYNC_FAILED));
        assert!(CORE_ERROR_CODES.contains(&CORE_ERROR_SEGMENT_CORRUPT));
        assert!(CORE_ERROR_CODES.contains(&CORE_ERROR_INVALID_FRAME));
        assert!(CORE_ERROR_CODES.contains(&CORE_ERROR_INVALID_TOC));
        assert!(CORE_ERROR_CODES.contains(&CORE_ERROR_SHARD_NOT_OWNER));
        assert!(CORE_ERROR_CODES.contains(&CORE_ERROR_EPOCH_MISMATCH));
        assert!(CORE_ERROR_CODES.contains(&CORE_ERROR_BACKPRESSURE));
        assert!(CORE_ERROR_CODES.contains(&CORE_ERROR_TIMEOUT));
        assert!(CORE_ERROR_CODES.contains(&CORE_ERROR_INTERNAL));
    }

    // ── ProblemDetails factory method tests ─────────────────────────

    #[test]
    fn problem_details_bad_request() {
        let pd = ProblemDetails::bad_request("missing field");
        assert_eq!(pd.status, 400);
        assert_eq!(pd.problem_type, format!("{CORE_ERROR_BASE_URI}/bad-request"));
        assert_eq!(pd.title, "Bad Request");
        assert_eq!(pd.detail.as_deref(), Some("missing field"));
    }

    #[test]
    fn problem_details_unauthorized() {
        let pd = ProblemDetails::unauthorized("invalid token");
        assert_eq!(pd.status, 401);
        assert_eq!(pd.problem_type, format!("{CORE_ERROR_BASE_URI}/unauthorized"));
        assert_eq!(pd.title, "Unauthorized");
        assert_eq!(pd.detail.as_deref(), Some("invalid token"));
    }

    #[test]
    fn problem_details_forbidden() {
        let pd = ProblemDetails::forbidden("access denied");
        assert_eq!(pd.status, 403);
        assert_eq!(pd.problem_type, format!("{CORE_ERROR_BASE_URI}/forbidden"));
        assert_eq!(pd.title, "Forbidden");
    }

    #[test]
    fn problem_details_not_found() {
        let pd = ProblemDetails::not_found("no such stream");
        assert_eq!(pd.status, 404);
        assert_eq!(pd.problem_type, format!("{CORE_ERROR_BASE_URI}/not-found"));
        assert_eq!(pd.title, "Not Found");
    }

    #[test]
    fn problem_details_precondition_failed() {
        let pd = ProblemDetails::precondition_failed("wrong epoch");
        assert_eq!(pd.status, 412);
        assert_eq!(pd.problem_type, format!("{CORE_ERROR_BASE_URI}/precondition-failed"));
        assert_eq!(pd.title, "Precondition Failed");
    }

    #[test]
    fn problem_details_internal() {
        let pd = ProblemDetails::internal("unexpected state");
        assert_eq!(pd.status, 500);
        assert_eq!(pd.problem_type, format!("{CORE_ERROR_BASE_URI}/internal"));
        assert_eq!(pd.title, "Internal Server Error");
    }

    #[test]
    fn problem_details_not_implemented() {
        let pd = ProblemDetails::not_implemented("feature disabled");
        assert_eq!(pd.status, 501);
        assert_eq!(pd.problem_type, format!("{CORE_ERROR_BASE_URI}/not-implemented"));
        assert_eq!(pd.title, "Not Implemented");
    }

    #[test]
    fn problem_details_service_unavailable() {
        let pd = ProblemDetails::service_unavailable("shard down");
        assert_eq!(pd.status, 503);
        assert_eq!(pd.problem_type, format!("{CORE_ERROR_BASE_URI}/service-unavailable"));
        assert_eq!(pd.title, "Service Unavailable");
    }

    #[test]
    fn problem_details_with_instance_and_extensions() {
        let pd = ProblemDetails::internal("boom")
            .with_instance("/v1/events/append")
            .with_extensions(json!({ "code": "INTERNAL", "shard_id": "shard-0001" }));

        assert_eq!(pd.instance.as_deref(), Some("/v1/events/append"));

        let encoded = serde_json::to_value(&pd).expect("serialize");
        assert_eq!(encoded["code"], "INTERNAL");
        assert_eq!(encoded["shard_id"], "shard-0001");
        // Extensions are flattened into top-level JSON
        assert!(encoded.get("extensions").is_none());
    }

    #[test]
    fn problem_details_minimal_no_optional_fields() {
        let pd = ProblemDetails::new(418, "https://example.com/teapot", "I'm a Teapot");
        assert!(pd.detail.is_none());
        assert!(pd.instance.is_none());
        assert!(pd.extensions.is_none());

        let encoded = serde_json::to_value(&pd).expect("serialize");
        assert!(encoded.get("detail").is_none());
        assert!(encoded.get("instance").is_none());
    }
}
