// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::sync::{Arc, Mutex, RwLock as StdRwLock};

use chrono::Utc;
use serde_json::json;
use tokio::sync::RwLock;

use corecrux_frame::stream_hash_xxhash64;
use corecrux_types::parse_shard_id_u32;

use corecrux_projections::{ProjectionStoreV1, ProjectionsTickResultV1};
use corecrux_receipts::{
    extract_body_index_v1, load_verification_report_v1, store_verification_report_v1,
    update_subject_index_v1, verify_receipt_v1, VerificationReportV1, VerifyReceiptInput,
    EVT_RECEIPT_BODY_V1, EVT_RECEIPT_SIG_V1, STREAM_TYPE_RECEIPT,
};
use corecrux_segment::decode_frame_v1;

use crate::control::ValveDecision;
use crate::metrics::Metrics;
use crate::shard_map::{RouteDecision, RoutingTable};

#[derive(Debug)]
pub enum AppendError {
    InvalidArgument(String),
    FailedPrecondition(String),
    ResourceExhausted(String),
    IoBackend(String),
    Internal(String),
    ShardUnavailable {
        shard_id: String,
        owner_gpu_id: i32,
        current_shard_map_version: u64,
    },
    WrongShard {
        leader_grpc_addr: String,
        current_shard_map_version: u64,
    },
    ShardMapVersionMismatch {
        client_version: u64,
        current_version: u64,
    },
}

impl std::fmt::Display for AppendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppendError::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            AppendError::FailedPrecondition(msg) => write!(f, "failed precondition: {msg}"),
            AppendError::ResourceExhausted(msg) => write!(f, "resource exhausted: {msg}"),
            AppendError::IoBackend(msg) => write!(f, "io backend error: {msg}"),
            AppendError::Internal(msg) => write!(f, "internal error: {msg}"),
            AppendError::ShardUnavailable {
                shard_id,
                owner_gpu_id,
                current_shard_map_version,
            } => write!(
                f,
                "shard unavailable: shard_id={shard_id} owner_gpu_id={owner_gpu_id} shard_map_version={current_shard_map_version}"
            ),
            AppendError::WrongShard {
                leader_grpc_addr,
                current_shard_map_version,
            } => write!(
                f,
                "wrong shard: leader_grpc_addr={leader_grpc_addr} shard_map_version={current_shard_map_version}"
            ),
            AppendError::ShardMapVersionMismatch {
                client_version,
                current_version,
            } => write!(
                f,
                "shard map version mismatch: client_version={client_version} current_version={current_version}"
            ),
        }
    }
}

impl std::error::Error for AppendError {}

/// Result of a force-seal + projection tick operation on a single shard.
#[derive(Debug)]
pub struct ForceSealAndTickResult {
    pub shard_id: String,
    pub seal_result: corecrux_storage::SealResultV1,
    pub cursor_before: Option<serde_json::Value>,
    pub cursor_after: Option<serde_json::Value>,
    pub projection_frames_processed: u64,
}

fn cursor_to_json(
    cursor: &Option<corecrux_projections::ProjectionCursorV1>,
) -> serde_json::Value {
    match cursor {
        Some(c) => json!({
            "segmentSeq": c.segment_seq,
            "offset": c.offset,
        }),
        None => serde_json::Value::Null,
    }
}

fn bypass_valve_gate_for_internal_stream(tenant_id: &str, stream_type: &str) -> bool {
    tenant_id == "system" && stream_type == "corecrux"
}

fn is_transient_cuda_context_error(err: &AppendError) -> bool {
    let msg = match err {
        AppendError::IoBackend(msg)
        | AppendError::Internal(msg)
        | AppendError::ResourceExhausted(msg) => msg,
        _ => return false,
    };
    let lower = msg.to_ascii_lowercase();
    lower.contains("cuda error 201")
        || lower.contains("invalid device context")
        || lower.contains("cuda_error_invalid_context")
        || lower.contains("\"code\":\"cuda_context_lost\"")
        || lower.contains("cuda_context_lost")
}

const MAX_TRANSIENT_READ_RETRIES: u32 = 2;
const TRANSIENT_CUDA_RECOVERY_STREAK_THRESHOLD: Option<u32> = None;

impl AppendError {
    fn from_storage(err: corecrux_storage::StorageError) -> Self {
        match err {
            corecrux_storage::StorageError::InvalidArgument { code, msg } => {
                AppendError::InvalidArgument(json!({ "code": code, "message": msg }).to_string())
            }
            corecrux_storage::StorageError::FailedPrecondition { code, msg } => {
                AppendError::FailedPrecondition(json!({ "code": code, "message": msg }).to_string())
            }
            corecrux_storage::StorageError::ResourceExhausted {
                code,
                msg,
                retry_after_ms,
            } => AppendError::ResourceExhausted(
                json!({ "code": code, "message": msg, "retryAfterMs": retry_after_ms }).to_string(),
            ),
            corecrux_storage::StorageError::Internal { msg } => AppendError::Internal(msg),
            corecrux_storage::StorageError::Io { msg } => AppendError::IoBackend(msg),
            corecrux_storage::StorageError::ManifestHeaderInvalid { msg } => {
                AppendError::Internal(msg)
            }
            corecrux_storage::StorageError::ManifestCrcMismatch { expected, actual } => {
                AppendError::Internal(format!(
                    "manifest crc mismatch: expected={expected:#x} actual={actual:#x}"
                ))
            }
            corecrux_storage::StorageError::ManifestRecordCrcMismatch { expected, actual } => {
                AppendError::Internal(format!(
                    "manifest record crc mismatch: expected={expected:#x} actual={actual:#x}"
                ))
            }
            corecrux_storage::StorageError::ManifestRecordInvalid { msg } => {
                AppendError::FailedPrecondition(msg)
            }
            corecrux_storage::StorageError::Segment(err) => {
                AppendError::Internal(format!("segment error: {err}"))
            }
        }
    }
}

pub type AppendOutcome = corecrux_storage::AppendOutcome;
pub type AppendStatus = corecrux_storage::AppendStatus;
pub type AppendStats = corecrux_storage::AppendStatsV1;
pub type StoredEvent = corecrux_storage::StoredEvent;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReplicationApplyResult {
    #[serde(rename = "shardId")]
    pub shard_id: String,
    pub epoch: u64,
    #[serde(rename = "segmentSeq")]
    pub segment_seq: u64,
    #[serde(rename = "segmentHash")]
    pub segment_hash_hex: String,
    #[serde(rename = "fileLen")]
    pub file_len: u64,
    pub applied: bool,
}

#[derive(Debug, Clone)]
pub struct ReplicationSegmentPayload {
    pub segment_seq: u64,
    pub segment_hash_hex: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProjectionRelationRowV1 {
    pub src_artifact_id: u32,
    pub dst_artifact_id: u32,
    pub relation_type: u8,
    pub confidence_q16: u16,
    pub evidence_ref_hash16: [u8; 16],
    pub created_at_micros: i64,
    pub updated_at_micros: i64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProjectionDependentRowV1 {
    pub dependent_type: u8,
    pub dependent_id: String,
    pub last_seen_at_micros: i64,
    pub usage_weight_q16: u16,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProjectionPressureEventRowV1 {
    pub event_id: uuid::Uuid,
    pub pressure_code_id: u16,
    pub severity: u8,
    pub observed_at_micros: i64,
    pub acknowledged_at_micros: i64,
    pub resolved_at_micros: i64,
    pub receipt_id: Option<uuid::Uuid>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyStoreShardSummary {
    #[serde(rename = "shardId")]
    pub shard_id: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub total_segments: u64,
    pub total_blocks: u64,
    pub total_frames: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyStoreSummary {
    pub ok: bool,
    #[serde(rename = "scannedShards")]
    pub scanned_shards: u64,
    #[serde(rename = "failedShards")]
    pub failed_shards: u64,
    pub shards: Vec<VerifyStoreShardSummary>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ProjectionSnapshotIssue {
    #[serde(rename = "shardId")]
    pub shard_id: String,
    pub projection: String,
    pub reason: String,
    pub detail: String,
}

#[derive(Debug)]
struct ThrottleTokenBucket {
    cfg_events_per_sec: Option<u64>,
    cfg_bytes_per_sec: Option<u64>,
    burst_secs: u64,
    events_tokens: u64,
    bytes_tokens: u64,
    // Remainder in "token*ns" units for precise integer refill without float drift.
    events_rem_token_ns: u128,
    bytes_rem_token_ns: u128,
    last_refill: std::time::Instant,
}

impl Default for ThrottleTokenBucket {
    fn default() -> Self {
        Self {
            cfg_events_per_sec: None,
            cfg_bytes_per_sec: None,
            burst_secs: 1,
            events_tokens: 0,
            bytes_tokens: 0,
            events_rem_token_ns: 0,
            bytes_rem_token_ns: 0,
            last_refill: std::time::Instant::now(),
        }
    }
}

impl ThrottleTokenBucket {
    fn update_config(&mut self, events_per_sec: Option<u64>, bytes_per_sec: Option<u64>) {
        if self.cfg_events_per_sec == events_per_sec && self.cfg_bytes_per_sec == bytes_per_sec {
            return;
        }
        self.cfg_events_per_sec = events_per_sec;
        self.cfg_bytes_per_sec = bytes_per_sec;
        self.events_rem_token_ns = 0;
        self.bytes_rem_token_ns = 0;
        self.last_refill = std::time::Instant::now();
        self.events_tokens = self.events_capacity();
        self.bytes_tokens = self.bytes_capacity();
    }

    fn events_capacity(&self) -> u64 {
        self.cfg_events_per_sec
            .unwrap_or(0)
            .saturating_mul(self.burst_secs)
    }

    fn bytes_capacity(&self) -> u64 {
        self.cfg_bytes_per_sec
            .unwrap_or(0)
            .saturating_mul(self.burst_secs)
    }

    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed_ns = now.duration_since(self.last_refill).as_nanos();
        if elapsed_ns == 0 {
            return;
        }

        self.last_refill = now;

        if let Some(rate) = self.cfg_events_per_sec {
            let cap = self.events_capacity();
            if cap > 0 && rate > 0 {
                let numer = (rate as u128)
                    .saturating_mul(elapsed_ns)
                    .saturating_add(self.events_rem_token_ns);
                let add = numer / 1_000_000_000u128;
                self.events_rem_token_ns = numer % 1_000_000_000u128;
                self.events_tokens = self
                    .events_tokens
                    .saturating_add(add.min(u64::MAX as u128) as u64)
                    .min(cap);
            }
        }

        if let Some(rate) = self.cfg_bytes_per_sec {
            let cap = self.bytes_capacity();
            if cap > 0 && rate > 0 {
                let numer = (rate as u128)
                    .saturating_mul(elapsed_ns)
                    .saturating_add(self.bytes_rem_token_ns);
                let add = numer / 1_000_000_000u128;
                self.bytes_rem_token_ns = numer % 1_000_000_000u128;
                self.bytes_tokens = self
                    .bytes_tokens
                    .saturating_add(add.min(u64::MAX as u128) as u64)
                    .min(cap);
            }
        }
    }

    fn ratio_0_to_1(&self) -> f64 {
        let mut ratios: Vec<f64> = Vec::new();
        if let Some(rate) = self.cfg_events_per_sec {
            if rate > 0 {
                let cap = self.events_capacity().max(1);
                ratios.push((self.events_tokens as f64) / (cap as f64));
            }
        }
        if let Some(rate) = self.cfg_bytes_per_sec {
            if rate > 0 {
                let cap = self.bytes_capacity().max(1);
                ratios.push((self.bytes_tokens as f64) / (cap as f64));
            }
        }
        if ratios.is_empty() {
            return 1.0;
        }
        ratios
            .into_iter()
            .fold(1.0f64, |a, b| a.min(b))
            .clamp(0.0, 1.0)
    }

    fn try_consume(
        &mut self,
        events_needed: u64,
        bytes_needed: u64,
        retry_after_default_ms: u32,
    ) -> Result<(), u32> {
        self.refill();

        // If configured with an explicit zero rate, treat as fully throttled.
        if matches!(self.cfg_events_per_sec, Some(0)) && events_needed > 0 {
            return Err(retry_after_default_ms.max(1));
        }
        if matches!(self.cfg_bytes_per_sec, Some(0)) && bytes_needed > 0 {
            return Err(retry_after_default_ms.max(1));
        }

        if let Some(rate) = self.cfg_events_per_sec {
            if rate > 0 && events_needed > self.events_tokens {
                let deficit = events_needed - self.events_tokens;
                let ns = ((deficit as u128)
                    .saturating_mul(1_000_000_000u128)
                    .saturating_add(rate as u128 - 1))
                    / (rate as u128);
                let ms = ns.div_ceil(1_000_000u128).min(u32::MAX as u128) as u32;
                return Err(ms.max(retry_after_default_ms));
            }
        }

        if let Some(rate) = self.cfg_bytes_per_sec {
            if rate > 0 && bytes_needed > self.bytes_tokens {
                let deficit = bytes_needed - self.bytes_tokens;
                let ns = ((deficit as u128)
                    .saturating_mul(1_000_000_000u128)
                    .saturating_add(rate as u128 - 1))
                    / (rate as u128);
                let ms = ns.div_ceil(1_000_000u128).min(u32::MAX as u128) as u32;
                return Err(ms.max(retry_after_default_ms));
            }
        }

        if self.cfg_events_per_sec.is_some() {
            self.events_tokens = self.events_tokens.saturating_sub(events_needed);
        }
        if self.cfg_bytes_per_sec.is_some() {
            self.bytes_tokens = self.bytes_tokens.saturating_sub(bytes_needed);
        }
        Ok(())
    }
}

#[derive(Debug)]
struct ReadAmpTracker {
    samples: std::collections::VecDeque<u32>,
    cap: usize,
}

impl ReadAmpTracker {
    fn new(cap: usize) -> Self {
        Self {
            samples: std::collections::VecDeque::with_capacity(cap),
            cap,
        }
    }

    fn record(&mut self, segments_touched: u32) -> (f64, f64) {
        if self.cap == 0 {
            return (segments_touched as f64, segments_touched as f64);
        }
        if self.samples.len() == self.cap {
            self.samples.pop_front();
        }
        self.samples.push_back(segments_touched);

        let mut v: Vec<u32> = self.samples.iter().copied().collect();
        v.sort_unstable();
        let n = v.len();
        if n == 0 {
            return (0.0, 0.0);
        }
        let p50_idx = (n - 1) * 50 / 100;
        let p95_idx = ((n - 1) * 95).div_ceil(100);
        (v[p50_idx] as f64, v[p95_idx.min(n - 1)] as f64)
    }
}

const TAIL_CACHE_DEFAULT_CAP_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TailCacheKey {
    tenant_id: String,
    stream_type: String,
    stream_id: String,
}

#[derive(Debug, Clone)]
struct TailCacheEntry {
    stamp: u64,
    tail_events: u32,
    events: Vec<StoredEvent>,
    bytes: usize,
}

#[derive(Debug)]
struct TailCache {
    cap_bytes: usize,
    total_bytes: usize,
    next_stamp: u64,
    by_key: std::collections::HashMap<TailCacheKey, TailCacheEntry>,
    lru: std::collections::VecDeque<(TailCacheKey, u64)>,
}

impl TailCache {
    fn new(cap_bytes: usize) -> Self {
        Self {
            cap_bytes: cap_bytes.max(1024 * 1024),
            total_bytes: 0,
            next_stamp: 1,
            by_key: std::collections::HashMap::new(),
            lru: std::collections::VecDeque::new(),
        }
    }

    fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    fn key(tenant_id: &str, stream_type: &str, stream_id: &str) -> TailCacheKey {
        TailCacheKey {
            tenant_id: tenant_id.to_string(),
            stream_type: stream_type.to_string(),
            stream_id: stream_id.to_string(),
        }
    }

    fn get(
        &mut self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        tail_events: u32,
    ) -> Option<Vec<StoredEvent>> {
        let key = Self::key(tenant_id, stream_type, stream_id);
        let stamp = self.next_stamp;
        self.next_stamp = self.next_stamp.saturating_add(1);
        let entry = self.by_key.get_mut(&key)?;
        if entry.tail_events != tail_events {
            return None;
        }
        entry.stamp = stamp;
        self.lru.push_back((key, stamp));
        Some(entry.events.clone())
    }

    fn put(
        &mut self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        tail_events: u32,
        events: &[StoredEvent],
    ) {
        let key = Self::key(tenant_id, stream_type, stream_id);
        let bytes = estimate_tail_cache_bytes(events);
        if let Some(prev) = self.by_key.remove(&key) {
            self.total_bytes = self.total_bytes.saturating_sub(prev.bytes);
        }

        let stamp = self.next_stamp;
        self.next_stamp = self.next_stamp.saturating_add(1);
        self.total_bytes = self.total_bytes.saturating_add(bytes);
        self.by_key.insert(
            key.clone(),
            TailCacheEntry {
                stamp,
                tail_events,
                events: events.to_vec(),
                bytes,
            },
        );
        self.lru.push_back((key, stamp));

        while self.total_bytes > self.cap_bytes {
            let Some((old_key, old_stamp)) = self.lru.pop_front() else {
                break;
            };
            let stale = self
                .by_key
                .get(&old_key)
                .map(|e| e.stamp != old_stamp)
                .unwrap_or(true);
            if stale {
                continue;
            }
            if let Some(removed) = self.by_key.remove(&old_key) {
                self.total_bytes = self.total_bytes.saturating_sub(removed.bytes);
            }
        }
    }

    fn invalidate_stream(&mut self, tenant_id: &str, stream_type: &str, stream_id: &str) {
        let key = Self::key(tenant_id, stream_type, stream_id);
        if let Some(removed) = self.by_key.remove(&key) {
            self.total_bytes = self.total_bytes.saturating_sub(removed.bytes);
        }
    }
}

fn estimate_tail_cache_bytes(events: &[StoredEvent]) -> usize {
    events
        .iter()
        .map(|e| {
            e.event_id
                .len()
                .saturating_add(e.occurred_at.len())
                .saturating_add(e.ingested_at.len())
                .saturating_add(e.event_type.len())
                .saturating_add(e.content_type.len())
                .saturating_add(e.payload.len())
                .saturating_add(64)
        })
        .sum()
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

struct HostedShard {
    shard_id: String,
    epoch: u64,
    storage: StdRwLock<corecrux_storage::ShardStorage>,
    read_amp: Mutex<ReadAmpTracker>,
    tail_cache: Mutex<TailCache>,
    transient_recovery: Mutex<ShardTransientRecoveryState>,
    projections: Mutex<Option<ProjectionStoreV1>>,
}

#[derive(Debug, Clone, Copy)]
enum ReadOpKind {
    Tail,
    Range,
}

impl ReadOpKind {
    fn from_metric_op(op: &str) -> Option<Self> {
        match op {
            "tail" => Some(Self::Tail),
            "range" => Some(Self::Range),
            _ => None,
        }
    }
}

#[derive(Debug, Default)]
struct ShardTransientRecoveryState {
    tail_failed_streak: u32,
    range_failed_streak: u32,
}

impl ShardTransientRecoveryState {
    fn mark_success(&mut self, op: ReadOpKind) {
        match op {
            ReadOpKind::Tail => self.tail_failed_streak = 0,
            ReadOpKind::Range => self.range_failed_streak = 0,
        }
    }

    fn mark_failure(&mut self, op: ReadOpKind) -> u32 {
        match op {
            ReadOpKind::Tail => {
                self.tail_failed_streak = self.tail_failed_streak.saturating_add(1);
                self.tail_failed_streak
            }
            ReadOpKind::Range => {
                self.range_failed_streak = self.range_failed_streak.saturating_add(1);
                self.range_failed_streak
            }
        }
    }

    fn reset(&mut self, op: ReadOpKind) {
        self.mark_success(op);
    }

    fn streak(&self, op: ReadOpKind) -> u32 {
        match op {
            ReadOpKind::Tail => self.tail_failed_streak,
            ReadOpKind::Range => self.range_failed_streak,
        }
    }
}

fn gate_receipt_subject_mode_v1(
    requested_mode: &str,
    body_payload: &[u8],
    report: Option<&VerificationReportV1>,
) -> String {
    if requested_mode != "verified" {
        return requested_mode.to_string();
    }

    let payload_hash_hex = blake3::hash(body_payload).to_hex().to_string();
    match report {
        Some(report)
            if report.error_code == "OK" && report.payload_hash_hex == payload_hash_hex =>
        {
            "verified".to_string()
        }
        _ => "unknown".to_string(),
    }
}

pub struct DataPlaneStore {
    build: corecrux_types::BuildInfo,
    node_id: String,
    strict_client_version: bool,
    routing: Arc<RwLock<RoutingTable>>,
    owned_gpu_id: i32,
    default_gpu_id: i32,
    metrics: Metrics,
    control: Arc<RwLock<crate::control::ControlV1>>,

    shard_root: std::path::PathBuf,
    storage_options: corecrux_storage::ShardStorageOptions,
    throttle: Mutex<ThrottleTokenBucket>,
    backpressure_high_watermark_ratio: f64,
    backpressure_low_watermark_ratio: f64,
    backpressure_retry_after_ms: u32,
    backpressure_active: Mutex<bool>,

    shards: StdRwLock<std::collections::HashMap<u32, Arc<HostedShard>>>,

    projections_enabled: bool,
    allow_follower_reads: bool,

    receipts_verify_enabled: bool,
    receipts_recompute_candidate_digest: bool,
    receipts_keyring: Option<Arc<corecrux_receipts::Ed25519KeyRingV1>>,
    receipts_subject_index_root: std::path::PathBuf,
    tail_cache_enabled: bool,
}

impl DataPlaneStore {
    // GPU-only `open` and `gds_runtime_stats` removed (CPU-only community edition).
    // DataPlaneStore cannot be constructed without GPU; dataplane_pool is always None.

    fn shard_ids_sorted(&self) -> Vec<u32> {
        let mut shard_ids: Vec<u32> = self
            .shards
            .read()
            .expect("shards rwlock")
            .keys()
            .copied()
            .collect();
        shard_ids.sort_unstable();
        shard_ids
    }

    fn shard_arc(&self, shard_id_u32: u32) -> Option<Arc<HostedShard>> {
        self.shards
            .read()
            .expect("shards rwlock")
            .get(&shard_id_u32)
            .cloned()
    }

    /// Rebuild projections using the daemon's already-open shard storage handles.
    ///
    /// This is the online-safe alternative to `corecruxctl projections rebuild`, which
    /// opens fresh `ShardStorage` handles and conflicts with daemon flocks.
    /// Reads continue to be served from the existing (stale) projection during rebuild.
    pub fn rebuild_projections_pooled(
        &self,
        batch_frames: u32,
    ) -> Vec<(String, Result<ProjectionsTickResultV1, String>)> {
        if !self.projections_enabled {
            return Vec::new();
        }

        let shard_ids = self.shard_ids_sorted();
        let mut out = Vec::new();

        for sid in shard_ids {
            let Some(shard) = self.shard_arc(sid) else {
                continue;
            };
            let mut proj_guard = shard.projections.lock().expect("projection mutex");
            let Some(proj) = proj_guard.as_mut() else {
                continue;
            };
            let storage_guard = shard.storage.read().expect("storage rwlock");
            let shard_label = format!("shard-{sid}");
            match proj.rebuild_from_genesis(&storage_guard, batch_frames) {
                Ok(r) => {
                    tracing::info!(
                        shard_id = %sid,
                        frames = r.frames_processed,
                        commit_id = r.commit_id,
                        living = r.state_counts.living_rows,
                        relations = r.state_counts.relations_edges,
                        "online projection rebuild complete"
                    );
                    out.push((shard_label, Ok(r)));
                }
                Err(err) => {
                    tracing::error!(shard_id = %sid, err = %err, "online projection rebuild failed");
                    out.push((shard_label, Err(err.to_string())));
                }
            }
        }
        out
    }

    pub fn tick_projections(&self, max_frames: u32) -> Vec<(String, ProjectionsTickResultV1)> {
        if !self.projections_enabled {
            return Vec::new();
        }

        let shard_ids = self.shard_ids_sorted();

        let mut out = Vec::new();
        for sid in shard_ids {
            let Some(shard) = self.shard_arc(sid) else {
                continue;
            };
            let mut proj_guard = shard.projections.lock().expect("projection mutex");
            let Some(proj) = proj_guard.as_mut() else {
                continue;
            };
            let storage_guard = shard.storage.read().expect("storage rwlock");
            let start = std::time::Instant::now();
            match proj.tick(&storage_guard, max_frames) {
                Ok(Some(r)) => {
                    let secs = start.elapsed().as_secs_f64();
                    let (cursor_seg, cursor_off) = r
                        .cursor_after
                        .as_ref()
                        .map(|c| (c.segment_seq, c.offset))
                        .unwrap_or((0, 0));
                    self.metrics.observe_projection_tick(
                        &shard.shard_id,
                        r.frames_processed,
                        secs,
                        r.commit_id,
                        cursor_seg,
                        cursor_off,
                        r.state_counts.living_rows,
                        r.state_counts.relations_edges,
                        r.state_counts.pressure_rows,
                        r.state_counts.dependents_edges,
                    );
                    out.push((shard.shard_id.clone(), r));
                }
                Ok(None) => {}
                Err(err) => {
                    self.metrics.inc_projection_tick_fail(&shard.shard_id);
                    tracing::warn!(
                        shard_id = %shard.shard_id,
                        err = %err,
                        "projection tick failed"
                    );
                }
            }
        }
        out
    }

    /// Force-seal the head segment of a specific shard.
    pub fn force_seal_shard(
        &self,
        shard_id_u32: u32,
    ) -> Result<corecrux_storage::SealResultV1, String> {
        let shard = self
            .shard_arc(shard_id_u32)
            .ok_or_else(|| format!("shard {} not found", shard_id_u32))?;
        let mut storage = shard.storage.write().expect("storage write lock");
        let result = storage
            .force_seal_head()
            .map_err(|e| format!("seal failed: {e}"))?;
        if result.sealed {
            self.metrics.observe_seal_duration("phase1", result.seal_duration_secs);
        }
        Ok(result)
    }

    /// Force-seal all shards and return per-shard results.
    pub fn force_seal_all_shards(
        &self,
    ) -> Vec<(String, Result<corecrux_storage::SealResultV1, String>)> {
        let shard_ids = self.shard_ids_sorted();
        let mut out = Vec::new();
        for sid in shard_ids {
            let label = format!("shard-{sid}");
            let result = self.force_seal_shard(sid);
            out.push((label, result));
        }
        out
    }

    /// Force-seal a shard, then tick its projections so the cursor advances.
    pub fn force_seal_and_tick_shard(
        &self,
        shard_id_u32: u32,
        max_frames: u32,
    ) -> Result<ForceSealAndTickResult, String> {
        let shard = self
            .shard_arc(shard_id_u32)
            .ok_or_else(|| format!("shard {} not found", shard_id_u32))?;

        // Seal under write lock, then release.
        let seal_result = {
            let mut storage = shard.storage.write().expect("storage write lock");
            let r = storage
                .force_seal_head()
                .map_err(|e| format!("seal failed: {e}"))?;
            if r.sealed {
                self.metrics.observe_seal_duration("phase1", r.seal_duration_secs);
            }
            r
        };

        // Read cursor before tick.
        let cursor_before = {
            let proj_guard = shard.projections.lock().expect("projection mutex");
            proj_guard
                .as_ref()
                .map(|p| cursor_to_json(&p.meta.artifact_living_state.cursor))
        };

        // Tick projections via CPU path in a loop until fully caught up.
        // We use tick_cpu because:
        // 1. The GPU kernel fails on non-projection events (code=21, non-binary content_type)
        // 2. The CPU replay_from_sealed batches across multiple segments per call
        //    (GPU replay_from_sealed_device only processes one segment per call)
        let mut tick_frames = 0u64;
        if self.projections_enabled {
            let mut proj_guard = shard.projections.lock().expect("projection mutex");
            if let Some(proj) = proj_guard.as_mut() {
                let storage_guard = shard.storage.read().expect("storage rwlock");
                loop {
                    match proj.tick(&storage_guard, max_frames) {
                        Ok(Some(r)) => {
                            tick_frames += r.frames_processed;
                        }
                        Ok(None) => break, // fully caught up
                        Err(err) => {
                            tracing::warn!(
                                shard_id = %shard.shard_id,
                                err = %err,
                                tick_frames,
                                "projection tick after force-seal failed"
                            );
                            break;
                        }
                    }
                }
            }
        }

        // Read cursor after tick.
        let cursor_after = {
            let proj_guard = shard.projections.lock().expect("projection mutex");
            proj_guard
                .as_ref()
                .map(|p| cursor_to_json(&p.meta.artifact_living_state.cursor))
        };

        Ok(ForceSealAndTickResult {
            shard_id: shard.shard_id.clone(),
            seal_result,
            cursor_before,
            cursor_after,
            projection_frames_processed: tick_frames,
        })
    }

    /// Force-seal all shards and tick projections for each.
    pub fn force_seal_all_shards_and_tick(
        &self,
        max_frames: u32,
    ) -> Vec<(String, Result<ForceSealAndTickResult, String>)> {
        let shard_ids = self.shard_ids_sorted();
        let mut out = Vec::new();
        for sid in shard_ids {
            let label = format!("shard-{sid}");
            let result = self.force_seal_and_tick_shard(sid, max_frames);
            out.push((label, result));
        }
        out
    }

    #[tracing::instrument(
        level = "info",
        skip(self, events),
        fields(
            tenant_id = %tenant_id,
            stream_type = %stream_type,
            stream_id = %stream_id,
            expected_next_seq,
            events_len = events.len()
        )
    )]
    pub async fn append_batch(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        expected_next_seq: u64,
        client_shard_map_version: Option<u64>,
        events: &[corecrux_proto::dataplane_v1::AppendEvent],
    ) -> Result<(RouteDecision, Vec<AppendOutcome>, AppendStats), AppendError> {
        let start = std::time::Instant::now();

        let bypass_valve_gate = bypass_valve_gate_for_internal_stream(tenant_id, stream_type);
        let c = if bypass_valve_gate {
            None
        } else {
            Some(self.control.read().await.clone())
        };
        let valve_decision = c
            .as_ref()
            .map(ValveDecision::from_control)
            .unwrap_or(ValveDecision {
                allow_ingest: true,
                ingest_error: None,
                allow_compaction: true,
                allow_storage_writes: true,
            });
        if c.is_some() {
            if !valve_decision.allow_ingest {
                let (code, _retry_after_ms) = valve_decision
                    .ingest_error
                    .unwrap_or(("VALVE_BLOCKED".to_string(), 0));
                let msg = format!("ingest blocked by valve {code}");
                match code.as_str() {
                    "VALVE_READ_ONLY" => self.metrics.inc_write_reject("read_only"),
                    "VALVE_PAUSE_INGEST" => self.metrics.inc_write_reject("ingest_paused"),
                    "VALVE_EMERGENCY_BRAKE" => self.metrics.inc_write_reject("emergency_brake"),
                    _ => self.metrics.inc_write_reject("valve_blocked"),
                }
                return Err(AppendError::FailedPrecondition(
                    json!({ "code": code, "message": msg }).to_string(),
                ));
            }
        }

        if self.refresh_backpressure_state() {
            self.metrics.inc_write_reject("backpressure");
            return Err(AppendError::ResourceExhausted(
                json!({
                    "code": "BACKPRESSURE",
                    "message": "ingest backpressured by GPU memory watermark",
                    "retryAfterMs": self.backpressure_retry_after_ms
                })
                .to_string(),
            ));
        }

        // Throttle (Phase 6): token bucket on events/sec and bytes/sec. max_in_flight is enforced
        // at the gRPC layer to reject queued requests before they pile up behind the store lock.
        if c.as_ref().is_some_and(|c| c.valves.throttle.enabled) {
            let mut throttle = self.throttle.lock().expect("throttle mutex");
            let c = c
                .as_ref()
                .expect("control state present when throttle enabled");
            throttle.update_config(
                c.valves.throttle.events_per_sec,
                c.valves.throttle.bytes_per_sec,
            );
            let mut bytes_needed: u64 = 0;
            for e in events {
                bytes_needed = bytes_needed.saturating_add(e.payload.len() as u64);
                bytes_needed = bytes_needed.saturating_add(e.event_id.len() as u64);
            }
            let retry_after_default_ms = c.valves.throttle.retry_after_ms.unwrap_or(50);
            if let Err(retry_after_ms) =
                throttle.try_consume(events.len() as u64, bytes_needed, retry_after_default_ms)
            {
                self.metrics.inc_write_reject("throttled");
                self.metrics.set_throttle_ratio(throttle.ratio_0_to_1());
                return Err(AppendError::ResourceExhausted(
                    json!({
                        "code": "VALVE_THROTTLE",
                        "message": "ingest throttled",
                        "retryAfterMs": retry_after_ms
                    })
                    .to_string(),
                ));
            }
            self.metrics.set_throttle_ratio(throttle.ratio_0_to_1());
        } else {
            self.metrics.set_throttle_ratio(1.0);
        }

        let stream_hash = stream_hash_xxhash64(tenant_id, stream_type, stream_id)
            .map_err(|e| AppendError::InvalidArgument(format!("invalid stream key: {e}")))?;

        let decision = self
            .route("append", stream_hash, client_shard_map_version, false)
            .await?;

        let shard_id_u32 = parse_shard_id_u32(&decision.shard_id)
            .map_err(|e| AppendError::InvalidArgument(format!("{e}")))?;
        self.ensure_shard_open(shard_id_u32, &decision.shard_id, decision.epoch)?;
        let shard = self
            .shard_arc(shard_id_u32)
            .ok_or_else(|| AppendError::Internal("hosted shard missing after open".to_string()))?;

        let ingested_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

        let mut inputs: Vec<corecrux_storage::AppendEventInput<'_>> =
            Vec::with_capacity(events.len());
        for e in events {
            inputs.push(corecrux_storage::AppendEventInput {
                event_id: &e.event_id,
                occurred_at: &e.occurred_at,
                event_type: &e.event_type,
                content_type: &e.content_type,
                payload_bytes: &e.payload,
            });
        }

        let (outcomes, append_stats, compaction_events, dir_stats) = {
            let mut storage = shard.storage.write().expect("storage rwlock");

            let (outcomes, append_stats) = storage
                .append_batch_with_stats(
                    stream_hash,
                    expected_next_seq,
                    tenant_id,
                    stream_type,
                    stream_id,
                    &ingested_at,
                    &inputs,
                )
                .map_err(|err| {
                    if let corecrux_storage::StorageError::FailedPrecondition { ref code, .. } = err
                    {
                        if code == "STREAM_TOMBSTONED" {
                            self.metrics.inc_write_reject("tombstoned");
                            self.metrics
                                .inc_stream_tombstone_rejects(&decision.shard_id);
                        }
                    }
                    if let corecrux_storage::StorageError::ResourceExhausted { .. } = err {
                        self.metrics.inc_write_reject("backpressure");
                        if let Ok(mut active) = self.backpressure_active.lock() {
                            *active = true;
                        }
                        self.metrics.set_backpressure_active(true);
                    }
                    AppendError::from_storage(err)
                })?;

            if self.tail_cache_enabled {
                let mut tail_cache = shard.tail_cache.lock().expect("tail cache mutex");
                tail_cache.invalidate_stream(tenant_id, stream_type, stream_id);
                self.metrics
                    .set_tail_cache_bytes(&decision.shard_id, tail_cache.total_bytes() as u64);
            }

            let compaction_events =
                if valve_decision.allow_compaction && valve_decision.allow_storage_writes {
                    storage
                        .compact_directory_until_within_limits()
                        .map_err(|err| {
                            self.metrics
                                .inc_dir_compaction(&decision.shard_id, 0, 0, "error");
                            AppendError::from_storage(err)
                        })?
                } else {
                    Vec::new()
                };

            let dir_stats = storage.directory_lsm_stats_v1();
            (outcomes, append_stats, compaction_events, dir_stats)
        };

        self.metrics.observe_storage_append_stage_seconds(
            "idempotency_check",
            (append_stats.idempotency_check_nanos as f64) / 1_000_000_000.0,
        );
        self.metrics.observe_storage_append_stage_seconds(
            "index_update",
            (append_stats.index_update_nanos as f64) / 1_000_000_000.0,
        );
        self.metrics.observe_storage_append_stage_seconds(
            "io_write",
            (append_stats.io_write_nanos as f64) / 1_000_000_000.0,
        );
        self.metrics.observe_storage_append_stage_seconds(
            "fence_wait",
            (append_stats.fence_wait_nanos as f64) / 1_000_000_000.0,
        );
        self.metrics.observe_storage_append_stage_seconds(
            "fence_fsync",
            (append_stats.fence_fsync_nanos as f64) / 1_000_000_000.0,
        );
        self.metrics.observe_storage_append_stage_seconds(
            "fence",
            (append_stats.fence_nanos as f64) / 1_000_000_000.0,
        );
        self.metrics.observe_storage_append_stage_seconds(
            "total",
            (append_stats.total_nanos as f64) / 1_000_000_000.0,
        );
        self.metrics.observe_append_fence_wait_seconds(
            &decision.shard_id,
            (append_stats.fence_wait_nanos as f64) / 1_000_000_000.0,
        );
        self.metrics.observe_append_fence_fsync_seconds(
            &decision.shard_id,
            (append_stats.fence_fsync_nanos as f64) / 1_000_000_000.0,
        );

        for e in compaction_events {
            self.metrics
                .inc_dir_compaction(&decision.shard_id, e.level_from, e.level_to, "ok");
            self.metrics.observe_dir_compaction_seconds(
                &decision.shard_id,
                e.level_from,
                e.level_to,
                (e.duration_ns as f64) / 1e9,
            );
            self.metrics
                .add_dir_compaction_bytes_in(&decision.shard_id, e.bytes_in);
            self.metrics
                .add_dir_compaction_bytes_out(&decision.shard_id, e.bytes_out);
            if e.input_extents > 0 {
                self.metrics.set_dir_dead_extent_ratio(
                    &decision.shard_id,
                    (e.dropped_extents as f64) / (e.input_extents as f64),
                );
            }
        }

        self.update_dir_metrics(&decision.shard_id, dir_stats);
        self.update_gpu_mem_metrics();
        let _ = self.refresh_backpressure_state();
        self.metrics
            .observe_append_latency_seconds(&decision.shard_id, start.elapsed().as_secs_f64());

        if self.receipts_verify_enabled && stream_type == STREAM_TYPE_RECEIPT {
            // Best-effort: verification is derived state; do not fail writes on verifier issues.
            if let Err(err) =
                self.maybe_verify_receipt_stream_v1(shard_id_u32, tenant_id, stream_id)
            {
                self.metrics.inc_receipt_verify_fail("internal");
                tracing::warn!(
                    shard_id = %decision.shard_id,
                    tenant_id = tenant_id,
                    receipt_id = stream_id,
                    err = %err,
                    "receipt verification update failed"
                );
            }
        }

        if stream_type == STREAM_TYPE_RECEIPT {
            if let Err(err) =
                self.maybe_index_receipt_subject_v1(shard_id_u32, tenant_id, stream_id, stream_hash)
            {
                tracing::warn!(
                    shard_id = %decision.shard_id,
                    tenant_id = tenant_id,
                    receipt_id = stream_id,
                    err = %err,
                    "receipt subject index update failed"
                );
            }
        }

        Ok((decision, outcomes, append_stats))
    }

    fn maybe_index_receipt_subject_v1(
        &self,
        shard_id_u32: u32,
        tenant_id: &str,
        receipt_id: &str,
        stream_hash: u64,
    ) -> Result<(), AppendError> {
        let shard = self.shard_arc(shard_id_u32).ok_or_else(|| {
            AppendError::FailedPrecondition(format!("shard_id {shard_id_u32} not hosted"))
        })?;
        let storage = shard.storage.read().expect("storage rwlock");

        // Index off the stored body bytes (bytes-first contract).
        let (events, _stats) = storage
            .read_tail_with_stats(tenant_id, STREAM_TYPE_RECEIPT, receipt_id, stream_hash, 16)
            .map_err(AppendError::from_storage)?;

        let mut body = None;
        for e in events {
            if e.event_type == EVT_RECEIPT_BODY_V1
                && body
                    .as_ref()
                    .map(|b: &corecrux_storage::StoredEvent| b.seq)
                    .unwrap_or(0)
                    <= e.seq
            {
                body = Some(e);
            }
        }
        let Some(body) = body else {
            return Ok(());
        };

        let Some(idx) = extract_body_index_v1(&body.payload) else {
            return Ok(());
        };
        let Some(kind) = idx.kind else {
            return Ok(());
        };
        let Some(subject_id) = idx.subject_id else {
            return Ok(());
        };
        let requested_mode = idx.mode.unwrap_or_else(|| "unknown".to_string());

        if kind != "answer" && kind != "action" {
            return Ok(());
        }

        let shard_dir =
            corecrux_storage::ShardPaths::for_root(&self.shard_root, shard_id_u32).shard_dir;
        let report = if requested_mode == "verified" {
            load_verification_report_v1(&shard_dir, tenant_id, receipt_id)
                .map_err(|e| AppendError::Internal(e.to_string()))?
        } else {
            None
        };
        let mode = gate_receipt_subject_mode_v1(&requested_mode, &body.payload, report.as_ref());
        if requested_mode == "verified" && mode != "verified" {
            tracing::warn!(
                tenant_id,
                receipt_id,
                "receipt body requested verified subject indexing without a matching successful verification report; downgrading subject mode"
            );
        }

        update_subject_index_v1(
            &self.receipts_subject_index_root,
            tenant_id,
            &kind,
            &subject_id,
            receipt_id,
            &mode,
            &body.ingested_at,
        )
        .map_err(|e| AppendError::Internal(e.to_string()))?;

        Ok(())
    }

    pub async fn update_stream_meta(
        &mut self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        min_live_seq: u64,
        tombstone_seq: u64,
    ) -> Result<(u64, u64), AppendError> {
        let c = self.control.read().await.clone();
        let valve_decision = ValveDecision::from_control(&c);
        if !valve_decision.allow_storage_writes {
            self.metrics.inc_write_reject("read_only");
            return Err(AppendError::FailedPrecondition(
                json!({ "code": "VALVE_STORAGE_WRITES_DISABLED", "message": "storage writes disabled by valves" }).to_string(),
            ));
        }

        let stream_hash = stream_hash_xxhash64(tenant_id, stream_type, stream_id)
            .map_err(|e| AppendError::InvalidArgument(format!("invalid stream key: {e}")))?;

        let decision = self.route("stream-meta", stream_hash, None, false).await?;
        let shard_id_u32 = parse_shard_id_u32(&decision.shard_id)
            .map_err(|e| AppendError::InvalidArgument(format!("{e}")))?;
        self.ensure_shard_open(shard_id_u32, &decision.shard_id, decision.epoch)?;
        let shard = self
            .shard_arc(shard_id_u32)
            .ok_or_else(|| AppendError::Internal("hosted shard missing after open".to_string()))?;
        let (
            before_min_live_seq,
            before_tombstone_seq,
            after_min_live_seq,
            after_tombstone_seq,
            compaction_events,
            dir_stats,
        ) = {
            let mut storage = shard.storage.write().expect("storage rwlock");

            let (before_min_live_seq, before_tombstone_seq) = storage.stream_meta_v1(stream_hash);
            let (after_min_live_seq, after_tombstone_seq) = storage
                .update_stream_meta(stream_hash, min_live_seq, tombstone_seq)
                .map_err(AppendError::from_storage)?;

            let mut compaction_events: Vec<corecrux_storage::DirCompactionEventV1> = Vec::new();
            if valve_decision.allow_compaction {
                match storage.compact_directory_until_within_limits() {
                    Ok(events) => compaction_events = events,
                    Err(err) => {
                        self.metrics
                            .inc_dir_compaction(&decision.shard_id, 0, 0, "error");
                        tracing::warn!(err = %err, shard_id = %decision.shard_id, "dir compaction after stream-meta update failed");
                    }
                }
            }

            let dir_stats = storage.directory_lsm_stats_v1();

            (
                before_min_live_seq,
                before_tombstone_seq,
                after_min_live_seq,
                after_tombstone_seq,
                compaction_events,
                dir_stats,
            )
        };

        if after_min_live_seq > before_min_live_seq {
            self.metrics
                .inc_checkpoints_installed(&decision.shard_id, stream_type);
            self.metrics.set_checkpoint_min_live_seq(
                &decision.shard_id,
                stream_type,
                after_min_live_seq,
            );
        }
        if after_tombstone_seq > before_tombstone_seq {
            self.metrics.inc_stream_tombstones(&decision.shard_id);
        }

        for e in compaction_events {
            self.metrics
                .inc_dir_compaction(&decision.shard_id, e.level_from, e.level_to, "ok");
            self.metrics.observe_dir_compaction_seconds(
                &decision.shard_id,
                e.level_from,
                e.level_to,
                (e.duration_ns as f64) / 1e9,
            );
            self.metrics
                .add_dir_compaction_bytes_in(&decision.shard_id, e.bytes_in);
            self.metrics
                .add_dir_compaction_bytes_out(&decision.shard_id, e.bytes_out);
            if e.input_extents > 0 {
                self.metrics.set_dir_dead_extent_ratio(
                    &decision.shard_id,
                    (e.dropped_extents as f64) / (e.input_extents as f64),
                );
            }
        }

        self.update_dir_metrics(&decision.shard_id, dir_stats);
        self.update_gpu_mem_metrics();

        Ok((after_min_live_seq, after_tombstone_seq))
    }

    pub async fn read_stream(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        from_seq_inclusive: u64,
        max_events: u32,
        client_shard_map_version: Option<u64>,
    ) -> Result<Vec<StoredEvent>, AppendError> {
        let start = std::time::Instant::now();

        let stream_hash = stream_hash_xxhash64(tenant_id, stream_type, stream_id)
            .map_err(|e| AppendError::InvalidArgument(format!("invalid stream key: {e}")))?;

        let decision = self
            .route(
                "read",
                stream_hash,
                client_shard_map_version,
                self.allow_follower_reads,
            )
            .await?;
        let shard_id_u32 = parse_shard_id_u32(&decision.shard_id)
            .map_err(|e| AppendError::InvalidArgument(format!("{e}")))?;
        let shard = self.shard_arc(shard_id_u32).ok_or_else(|| {
            AppendError::FailedPrecondition(format!("shard '{}' not hosted", decision.shard_id))
        })?;
        let read_op = ReadOpKind::Range;

        let read_once = || {
            let storage = shard.storage.read().expect("storage rwlock");
            storage.read_stream_with_stats(
                tenant_id,
                stream_type,
                stream_id,
                stream_hash,
                from_seq_inclusive,
                max_events,
            )
        };
        let mut retries = 0u32;
        let (events, stats) = loop {
            match read_once().map_err(AppendError::from_storage) {
                Ok(v) => {
                    if retries > 0 {
                        self.metrics
                            .inc_read_retry("range", "cuda_context_lost", "success");
                    }
                    self.mark_shard_read_success(&shard, read_op);
                    break v;
                }
                Err(err)
                    if is_transient_cuda_context_error(&err)
                        && retries < MAX_TRANSIENT_READ_RETRIES =>
                {
                    retries = retries.saturating_add(1);
                    self.metrics
                        .inc_read_retry("range", "cuda_context_lost", "retry");
                    tracing::warn!(
                        shard_id = %decision.shard_id,
                        tenant_id = tenant_id,
                        stream_type = stream_type,
                        stream_id = stream_id,
                        retry_attempt = retries,
                        max_retries = MAX_TRANSIENT_READ_RETRIES,
                        err = %err,
                        "transient cuda context error on range read; retrying"
                    );
                    tokio::task::yield_now().await;
                }
                Err(err) => {
                    if retries > 0 && is_transient_cuda_context_error(&err) {
                        self.metrics
                            .inc_read_retry("range", "cuda_context_lost", "failed");
                        let streak = self.mark_shard_read_failure(&shard, read_op);
                        tracing::warn!(
                            shard_id = %decision.shard_id,
                            tenant_id = tenant_id,
                            stream_type = stream_type,
                            stream_id = stream_id,
                            retry_attempts = retries,
                            max_retries = MAX_TRANSIENT_READ_RETRIES,
                            failure_streak = streak,
                            err = %err,
                            "range read failed after transient cuda context retries"
                        );
                    } else {
                        self.mark_shard_read_success(&shard, read_op);
                    }
                    return Err(err);
                }
            }
        };

        let (p50, p95) = shard
            .read_amp
            .lock()
            .expect("read amp mutex")
            .record(stats.segments_touched);
        self.metrics
            .set_read_amplification_p50(&decision.shard_id, p50);
        self.metrics
            .set_read_amplification_p95(&decision.shard_id, p95);
        self.metrics.observe_stream_read_latency_seconds(
            &decision.shard_id,
            "range",
            start.elapsed().as_secs_f64(),
        );

        Ok(events)
    }

    pub async fn read_tail(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        tail_events: u32,
        client_shard_map_version: Option<u64>,
    ) -> Result<Vec<StoredEvent>, AppendError> {
        let start = std::time::Instant::now();

        let stream_hash = stream_hash_xxhash64(tenant_id, stream_type, stream_id)
            .map_err(|e| AppendError::InvalidArgument(format!("invalid stream key: {e}")))?;

        let decision = self
            .route(
                "read_tail",
                stream_hash,
                client_shard_map_version,
                self.allow_follower_reads,
            )
            .await?;
        let shard_id_u32 = parse_shard_id_u32(&decision.shard_id)
            .map_err(|e| AppendError::InvalidArgument(format!("{e}")))?;
        let shard = self.shard_arc(shard_id_u32).ok_or_else(|| {
            AppendError::FailedPrecondition(format!("shard '{}' not hosted", decision.shard_id))
        })?;
        let read_op = ReadOpKind::Tail;

        if self.tail_cache_enabled {
            let mut tail_cache = shard.tail_cache.lock().expect("tail cache mutex");
            if let Some(events) = tail_cache.get(tenant_id, stream_type, stream_id, tail_events) {
                self.metrics.inc_tail_cache_hit(&decision.shard_id);
                self.metrics
                    .set_tail_cache_bytes(&decision.shard_id, tail_cache.total_bytes() as u64);
                self.metrics.observe_stream_read_latency_seconds(
                    &decision.shard_id,
                    "tail_cache_hit",
                    start.elapsed().as_secs_f64(),
                );
                return Ok(events);
            }
            self.metrics.inc_tail_cache_miss(&decision.shard_id);
            self.metrics
                .set_tail_cache_bytes(&decision.shard_id, tail_cache.total_bytes() as u64);
        }

        let read_once = || {
            let storage = shard.storage.read().expect("storage rwlock");
            storage.read_tail_with_stats(
                tenant_id,
                stream_type,
                stream_id,
                stream_hash,
                tail_events,
            )
        };
        let mut retries = 0u32;
        let (events, stats) = loop {
            match read_once().map_err(AppendError::from_storage) {
                Ok(v) => {
                    if retries > 0 {
                        self.metrics
                            .inc_read_retry("tail", "cuda_context_lost", "success");
                    }
                    self.mark_shard_read_success(&shard, read_op);
                    break v;
                }
                Err(err)
                    if is_transient_cuda_context_error(&err)
                        && retries < MAX_TRANSIENT_READ_RETRIES =>
                {
                    retries = retries.saturating_add(1);
                    self.metrics
                        .inc_read_retry("tail", "cuda_context_lost", "retry");
                    tracing::warn!(
                        shard_id = %decision.shard_id,
                        tenant_id = tenant_id,
                        stream_type = stream_type,
                        stream_id = stream_id,
                        retry_attempt = retries,
                        max_retries = MAX_TRANSIENT_READ_RETRIES,
                        err = %err,
                        "transient cuda context error on tail read; retrying"
                    );
                    tokio::task::yield_now().await;
                }
                Err(err) => {
                    if retries > 0 && is_transient_cuda_context_error(&err) {
                        self.metrics
                            .inc_read_retry("tail", "cuda_context_lost", "failed");
                        let streak = self.mark_shard_read_failure(&shard, read_op);
                        tracing::warn!(
                            shard_id = %decision.shard_id,
                            tenant_id = tenant_id,
                            stream_type = stream_type,
                            stream_id = stream_id,
                            retry_attempts = retries,
                            max_retries = MAX_TRANSIENT_READ_RETRIES,
                            failure_streak = streak,
                            err = %err,
                            "tail read failed after transient cuda context retries"
                        );
                    } else {
                        self.mark_shard_read_success(&shard, read_op);
                    }
                    return Err(err);
                }
            }
        };

        self.metrics.observe_storage_tail_stage_seconds(
            "index_lookup",
            (stats.index_lookup_nanos as f64) / 1_000_000_000.0,
        );
        self.metrics
            .observe_storage_tail_stage_seconds("io", (stats.io_nanos as f64) / 1_000_000_000.0);
        self.metrics.observe_storage_tail_stage_seconds(
            "decode",
            (stats.decode_nanos as f64) / 1_000_000_000.0,
        );
        self.metrics.observe_storage_tail_stage_seconds(
            "total",
            (stats.total_nanos as f64) / 1_000_000_000.0,
        );
        self.metrics
            .add_storage_tail_bytes("disk_estimate", stats.disk_bytes_estimate);
        self.metrics
            .add_storage_tail_bytes("frame", stats.frame_bytes);
        self.metrics
            .add_storage_tail_items("segments", stats.segments_touched as u64);
        self.metrics
            .add_storage_tail_items("blocks", stats.blocks_touched as u64);
        self.metrics
            .add_storage_tail_items("frames", stats.frames_selected as u64);
        self.metrics
            .add_storage_head_frames_scanned(stats.head_frames_scanned as u64);

        let head_fastpath_hits = stats.head_tail_fastpath_hits as u64;
        let head_fastpath_misses = stats.head_tail_fastpath_misses as u64;
        if head_fastpath_hits > 0 {
            self.metrics
                .inc_storage_tail_path("head_tail_fastpath", "hit");
        }
        if head_fastpath_misses > 0 {
            self.metrics
                .inc_storage_tail_path("head_tail_fastpath", "miss");
        }

        let locator_hits = stats.locator_fully_satisfied_hits as u64;
        let locator_misses = stats.locator_fully_satisfied_misses as u64;
        if locator_hits > 0 {
            self.metrics
                .inc_storage_tail_path("locator_fully_satisfied", "hit");
        }
        if locator_misses > 0 {
            self.metrics
                .inc_storage_tail_path("locator_fully_satisfied", "miss");
        }

        let (p50, p95) = shard
            .read_amp
            .lock()
            .expect("read amp mutex")
            .record(stats.segments_touched);
        self.metrics
            .set_read_amplification_p50(&decision.shard_id, p50);
        self.metrics
            .set_read_amplification_p95(&decision.shard_id, p95);
        self.metrics.observe_stream_read_latency_seconds(
            &decision.shard_id,
            "tail",
            start.elapsed().as_secs_f64(),
        );

        if self.tail_cache_enabled {
            let mut tail_cache = shard.tail_cache.lock().expect("tail cache mutex");
            tail_cache.put(tenant_id, stream_type, stream_id, tail_events, &events);
            self.metrics
                .set_tail_cache_bytes(&decision.shard_id, tail_cache.total_bytes() as u64);
        }

        Ok(events)
    }

    fn mark_shard_read_success(&self, shard: &HostedShard, op: ReadOpKind) {
        let mut st = shard
            .transient_recovery
            .lock()
            .expect("transient recovery mutex");
        st.mark_success(op);
    }

    fn mark_shard_read_failure(&self, shard: &HostedShard, op: ReadOpKind) -> u32 {
        let mut st = shard
            .transient_recovery
            .lock()
            .expect("transient recovery mutex");
        st.mark_failure(op)
    }

    pub async fn recover_shard_after_transient_cuda(
        &self,
        op: &str,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        client_shard_map_version: Option<u64>,
    ) -> Result<bool, AppendError> {
        let Some(op_kind) = ReadOpKind::from_metric_op(op) else {
            return Ok(false);
        };

        let stream_hash = stream_hash_xxhash64(tenant_id, stream_type, stream_id)
            .map_err(|e| AppendError::InvalidArgument(format!("invalid stream key: {e}")))?;
        let decision = self
            .route(
                "read_recover",
                stream_hash,
                client_shard_map_version,
                self.allow_follower_reads,
            )
            .await?;
        let shard_id_u32 = parse_shard_id_u32(&decision.shard_id)
            .map_err(|e| AppendError::InvalidArgument(format!("{e}")))?;
        let shard = self.shard_arc(shard_id_u32).ok_or_else(|| {
            AppendError::FailedPrecondition(format!("shard '{}' not hosted", decision.shard_id))
        })?;

        let failure_streak = {
            let st = shard
                .transient_recovery
                .lock()
                .expect("transient recovery mutex");
            st.streak(op_kind)
        };
        if let Some(threshold) = TRANSIENT_CUDA_RECOVERY_STREAK_THRESHOLD {
            if failure_streak < threshold {
                return Ok(false);
            }
        }

        // reinitialize_cuda_streams removed (CPU-only community edition).
        {
            let mut st = shard
                .transient_recovery
                .lock()
                .expect("transient recovery mutex");
            st.reset(op_kind);
        }
        self.metrics
            .inc_read_retry(op, "cuda_context_lost", "reinitialized");
        tracing::warn!(
            shard_id = %decision.shard_id,
            tenant_id = tenant_id,
            stream_type = stream_type,
            stream_id = stream_id,
            failure_streak,
            threshold = TRANSIENT_CUDA_RECOVERY_STREAK_THRESHOLD.unwrap_or(0),
            "reinitialized shard-local CUDA streams after repeated transient context-loss"
        );
        Ok(true)
    }

    pub fn read_frame_bytes(
        &self,
        shard_id: u64,
        segment_id: u64,
        offset: u64,
    ) -> Result<Vec<u8>, AppendError> {
        let shard_id_u32 = u32::try_from(shard_id).map_err(|_| {
            AppendError::InvalidArgument(format!("shard_id out of range: {shard_id}"))
        })?;
        let shard = self.shard_arc(shard_id_u32).ok_or_else(|| {
            AppendError::FailedPrecondition(format!("shard_id {shard_id} not hosted"))
        })?;
        // Phase 2: FrameLocation.segment_id maps to segment_seq (monotonic per shard).
        let result = {
            let storage = shard.storage.read().expect("storage rwlock");
            storage
                .read_frame_bytes(segment_id, offset)
                .map_err(AppendError::from_storage)
        };
        result
    }

    pub fn read_frame_bytes_batch_packed(
        &self,
        locations: &[corecrux_storage::FrameLocation],
    ) -> Result<corecrux_storage::ReadFrameBatchPackedV1, AppendError> {
        if locations.is_empty() {
            return Ok(corecrux_storage::ReadFrameBatchPackedV1 {
                frames_blob: Vec::new(),
                frame_offsets: Vec::new(),
                frame_lens: Vec::new(),
                frame_bytes: 0,
            });
        }
        let shard_id_u32 = u32::try_from(locations[0].shard_id).map_err(|_| {
            AppendError::InvalidArgument(format!(
                "shard_id out of range: {}",
                locations[0].shard_id
            ))
        })?;
        for loc in locations.iter().skip(1) {
            let sid = u32::try_from(loc.shard_id).map_err(|_| {
                AppendError::InvalidArgument(format!("shard_id out of range: {}", loc.shard_id))
            })?;
            if sid != shard_id_u32 {
                return Err(AppendError::InvalidArgument(
                    "frame batch locations span multiple shard_ids".to_string(),
                ));
            }
        }
        let shard = self.shard_arc(shard_id_u32).ok_or_else(|| {
            AppendError::FailedPrecondition(format!(
                "shard_id {} not hosted",
                locations[0].shard_id
            ))
        })?;
        let result = {
            let storage = shard.storage.read().expect("storage rwlock");
            storage
                .read_frame_bytes_batch_packed(locations)
                .map_err(AppendError::from_storage)
        };
        result
    }

    pub fn hosted_shards(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .shards
            .read()
            .expect("shards rwlock")
            .values()
            .map(|s| s.shard_id.clone())
            .collect();
        out.sort();
        out
    }

    pub fn projections_meta_for_shard(
        &self,
        shard_id_u32: u32,
    ) -> Option<corecrux_projections::ProjectionsMetaV1> {
        let hs = self.shard_arc(shard_id_u32)?;
        let proj_guard = hs.projections.lock().ok()?;
        let proj = proj_guard.as_ref()?;
        Some(proj.meta.clone())
    }

    pub fn projections_living_state_row(
        &self,
        shard_id_u32: u32,
        tenant_id: &str,
        artifact_id: u32,
    ) -> Option<corecrux_projections::LivingStateRowV1> {
        let hs = self.shard_arc(shard_id_u32)?;
        let proj_guard = hs.projections.lock().ok()?;
        let proj = proj_guard.as_ref()?;
        let tenant_hash = corecrux_projections::tenant_hash_xxhash64(tenant_id);
        proj.state.living.get(&(tenant_hash, artifact_id)).cloned()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn projections_list_relations(
        &self,
        shard_id_u32: u32,
        tenant_id: &str,
        artifact_id: u32,
        direction: &str,
        relation_type: Option<u8>,
        limit: usize,
        offset: usize,
    ) -> Vec<ProjectionRelationRowV1> {
        let Some(hs) = self.shard_arc(shard_id_u32) else {
            return Vec::new();
        };
        let Ok(proj_guard) = hs.projections.lock() else {
            return Vec::new();
        };
        let Some(proj) = proj_guard.as_ref() else {
            return Vec::new();
        };
        let tenant_hash = corecrux_projections::tenant_hash_xxhash64(tenant_id);

        let mut out: Vec<ProjectionRelationRowV1> = Vec::new();
        match direction {
            // Out edges are contiguous in the BTreeMap key order: (tenant_hash, src, dst, rt).
            "out" | "" => {
                let start = (tenant_hash, artifact_id, 0u32, 0u8);
                let end = (tenant_hash, artifact_id, u32::MAX, u8::MAX);
                for ((_t, src, dst, rt), edge) in proj.state.relations.range(start..=end) {
                    if let Some(filter_rt) = relation_type {
                        if *rt != filter_rt {
                            continue;
                        }
                    }
                    out.push(ProjectionRelationRowV1 {
                        src_artifact_id: *src,
                        dst_artifact_id: *dst,
                        relation_type: *rt,
                        confidence_q16: edge.confidence_q16,
                        evidence_ref_hash16: edge.evidence_ref_hash16,
                        created_at_micros: edge.created_at_micros,
                        updated_at_micros: edge.updated_at_micros,
                    });
                }
            }
            // In edges are not contiguous in this key order; Phase 11 will likely add a mirrored
            // inbound index. For now, scan with tenant filter.
            _ => {
                for ((t, src, dst, rt), edge) in &proj.state.relations {
                    if *t != tenant_hash {
                        continue;
                    }
                    if *dst != artifact_id {
                        continue;
                    }
                    if let Some(filter_rt) = relation_type {
                        if *rt != filter_rt {
                            continue;
                        }
                    }
                    out.push(ProjectionRelationRowV1 {
                        src_artifact_id: *src,
                        dst_artifact_id: *dst,
                        relation_type: *rt,
                        confidence_q16: edge.confidence_q16,
                        evidence_ref_hash16: edge.evidence_ref_hash16,
                        created_at_micros: edge.created_at_micros,
                        updated_at_micros: edge.updated_at_micros,
                    });
                }
            }
        }

        out.into_iter().skip(offset).take(limit).collect()
    }

    pub fn projections_list_dependents(
        &self,
        shard_id_u32: u32,
        tenant_id: &str,
        artifact_id: u32,
        dependent_type: Option<u8>,
        limit: usize,
        offset: usize,
    ) -> Vec<ProjectionDependentRowV1> {
        let Some(hs) = self.shard_arc(shard_id_u32) else {
            return Vec::new();
        };
        let Ok(proj_guard) = hs.projections.lock() else {
            return Vec::new();
        };
        let Some(proj) = proj_guard.as_ref() else {
            return Vec::new();
        };
        let tenant_hash = corecrux_projections::tenant_hash_xxhash64(tenant_id);

        let uuid_min = uuid::Uuid::from_bytes([0u8; 16]);
        let uuid_max = uuid::Uuid::from_bytes([0xFFu8; 16]);
        let start = (tenant_hash, artifact_id, 0u8, uuid_min);
        let end = (tenant_hash, artifact_id, u8::MAX, uuid_max);

        let mut out: Vec<ProjectionDependentRowV1> = Vec::new();
        for ((_t, _aid, dt, did), edge) in proj.state.dependents.range(start..=end) {
            if let Some(filter_dt) = dependent_type {
                if *dt != filter_dt {
                    continue;
                }
            }
            out.push(ProjectionDependentRowV1 {
                dependent_type: *dt,
                dependent_id: did.to_string(),
                last_seen_at_micros: edge.last_seen_at_micros,
                usage_weight_q16: edge.usage_weight_q16,
            });
        }

        out.into_iter().skip(offset).take(limit).collect()
    }

    pub fn projections_list_pressure_events(
        &self,
        shard_id_u32: u32,
        tenant_id: &str,
        artifact_id: u32,
        open_only: bool,
        limit: usize,
        offset: usize,
    ) -> Vec<ProjectionPressureEventRowV1> {
        let Some(hs) = self.shard_arc(shard_id_u32) else {
            return Vec::new();
        };
        let Ok(proj_guard) = hs.projections.lock() else {
            return Vec::new();
        };
        let Some(proj) = proj_guard.as_ref() else {
            return Vec::new();
        };
        let tenant_hash = corecrux_projections::tenant_hash_xxhash64(tenant_id);

        let uuid_min = uuid::Uuid::from_bytes([0u8; 16]);
        let uuid_max = uuid::Uuid::from_bytes([0xFFu8; 16]);
        let start = (tenant_hash, artifact_id, uuid_min);
        let end = (tenant_hash, artifact_id, uuid_max);

        let mut out: Vec<ProjectionPressureEventRowV1> = Vec::new();
        for ((_t, _aid, eid), row) in proj.state.pressure.range(start..=end) {
            if open_only && row.resolved_at_micros != 0 {
                continue;
            }
            out.push(ProjectionPressureEventRowV1 {
                event_id: *eid,
                pressure_code_id: row.pressure_code_id,
                severity: row.severity,
                observed_at_micros: row.observed_at_micros,
                acknowledged_at_micros: row.acknowledged_at_micros,
                resolved_at_micros: row.resolved_at_micros,
                receipt_id: row.receipt_id,
            });
        }

        out.into_iter().skip(offset).take(limit).collect()
    }

    // ── Graph expand + temporal range query methods (v4.2) ─────────────

    pub fn query_graph_expand(
        &self,
        tenant_id: &str,
        seed_artifact_ids: &[u32],
        edge_types: &[corecrux_projections::RelationTypeV1],
        max_hops: u32,
        budget: usize,
        min_confidence: f32,
        include_state: bool,
    ) -> corecrux_projections::query::graph_expand::GraphExpandResponse {
        use corecrux_projections::query::graph_expand::{
            graph_expand, GraphExpandRequest, GraphExpandResponse,
        };

        let tenant_hash = corecrux_projections::tenant_hash_xxhash64(tenant_id);
        let req = GraphExpandRequest {
            tenant_hash,
            seed_artifact_ids: seed_artifact_ids.to_vec(),
            edge_types: edge_types.to_vec(),
            max_hops,
            budget,
            min_confidence,
            include_state,
        };

        // Aggregate across all shards — each shard holds a subset of projection state.
        let shard_ids = self.shard_ids_sorted();
        let mut best = GraphExpandResponse {
            artifacts: Vec::new(),
            stats: Default::default(),
        };

        for sid in shard_ids {
            let Some(hs) = self.shard_arc(sid) else {
                continue;
            };
            let Ok(proj_guard) = hs.projections.lock() else {
                continue;
            };
            let Some(proj) = proj_guard.as_ref() else {
                continue;
            };
            let resp = graph_expand(&proj.state, &req);
            best.stats.nodes_visited += resp.stats.nodes_visited;
            best.stats.edges_traversed += resp.stats.edges_traversed;
            best.stats.hops_used = best.stats.hops_used.max(resp.stats.hops_used);
            best.artifacts.extend(resp.artifacts);
        }

        // De-duplicate and re-rank across shards (same artifact could appear from multiple shards)
        best.artifacts.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        best.artifacts.dedup_by_key(|a| a.artifact_id);
        best.artifacts.truncate(budget);
        best.stats.budget_remaining = budget.saturating_sub(best.artifacts.len());
        best
    }

    pub fn query_time_range(
        &self,
        tenant_id: &str,
        start_micros: i64,
        end_micros: i64,
        artifact_ids: &[u32],
        include_relations: bool,
        limit: usize,
    ) -> corecrux_projections::query::time_range::TimeRangeResponse {
        use corecrux_projections::query::time_range::{
            time_range_scan, TimeRangeRequest, TimeRangeResponse,
        };

        let tenant_hash = corecrux_projections::tenant_hash_xxhash64(tenant_id);
        let req = TimeRangeRequest {
            tenant_hash,
            start_micros,
            end_micros,
            artifact_ids: artifact_ids.to_vec(),
            include_relations,
            limit,
        };

        let shard_ids = self.shard_ids_sorted();
        let mut all_artifacts = Vec::new();
        let mut stats = corecrux_projections::query::time_range::TimeRangeStats::default();

        for sid in shard_ids {
            let Some(hs) = self.shard_arc(sid) else {
                continue;
            };
            let Ok(proj_guard) = hs.projections.lock() else {
                continue;
            };
            let Some(proj) = proj_guard.as_ref() else {
                continue;
            };
            let resp = time_range_scan(&proj.state, &req);
            stats.artifacts_scanned += resp.stats.artifacts_scanned;
            stats.relations_scanned += resp.stats.relations_scanned;
            stats.total_changes += resp.stats.total_changes;
            all_artifacts.extend(resp.artifacts);
        }

        // Sort by most recently updated, dedup, truncate
        all_artifacts.sort_by(|a, b| {
            b.current_state
                .updated_at_micros
                .cmp(&a.current_state.updated_at_micros)
        });
        all_artifacts.dedup_by_key(|a| a.artifact_id);
        all_artifacts.truncate(limit);
        stats.total_changes = all_artifacts.len() as u32;

        TimeRangeResponse {
            artifacts: all_artifacts,
            stats,
        }
    }

    // ── Phase 7: Entity projection query methods ──────────────────────────

    pub fn query_entity_count(
        &self,
        tenant_id: &str,
        entity_type: &str,
        predicate: &str,
    ) -> Vec<String> {
        use corecrux_projections::tenant_hash_xxhash64;
        use xxhash_rust::xxh64::xxh64;

        let tenant_hash = tenant_hash_xxhash64(tenant_id);
        let type_hash = xxh64(entity_type.as_bytes(), 0);
        let pred_hash = xxh64(predicate.as_bytes(), 0);
        let key = (tenant_hash, type_hash, pred_hash);

        let shard_ids = self.shard_ids_sorted();
        let mut items: Vec<String> = Vec::new();

        for sid in shard_ids {
            let Some(hs) = self.shard_arc(sid) else { continue };
            let Ok(proj_guard) = hs.projections.lock() else { continue };
            let Some(proj) = proj_guard.as_ref() else { continue };
            if let Some(row) = proj.state.entity_counts.get(&key) {
                items.extend(row.items.iter().cloned());
            }
        }
        items.sort();
        items.dedup();
        items
    }

    pub fn query_entity_timeline(
        &self,
        tenant_id: &str,
        entity_type: &str,
        predicate: &str,
    ) -> Vec<(String, String, i64)> {
        use corecrux_projections::tenant_hash_xxhash64;
        use xxhash_rust::xxh64::xxh64;

        let tenant_hash = tenant_hash_xxhash64(tenant_id);
        let type_hash = xxh64(entity_type.as_bytes(), 0);
        let pred_hash = xxh64(predicate.as_bytes(), 0);
        let key = (tenant_hash, type_hash, pred_hash);

        let shard_ids = self.shard_ids_sorted();
        let mut events: Vec<(String, String, i64)> = Vec::new();

        for sid in shard_ids {
            let Some(hs) = self.shard_arc(sid) else { continue };
            let Ok(proj_guard) = hs.projections.lock() else { continue };
            let Some(proj) = proj_guard.as_ref() else { continue };
            if let Some(timeline) = proj.state.entity_timelines.get(&key) {
                for entry in timeline.iter() {
                    events.push((
                        entry.entity_name.clone(),
                        entry.object_value.clone(),
                        entry.occurred_at_micros,
                    ));
                }
            }
        }
        events.sort_by_key(|e| e.2);
        events
    }

    pub fn query_entity_current_state(
        &self,
        tenant_id: &str,
        entity_name: &str,
        predicate: &str,
    ) -> Option<(String, i64, Option<String>, i64)> {
        use corecrux_projections::tenant_hash_xxhash64;
        use xxhash_rust::xxh64::xxh64;

        let tenant_hash = tenant_hash_xxhash64(tenant_id);
        let name_hash = xxh64(entity_name.as_bytes(), 0);
        let pred_hash = xxh64(predicate.as_bytes(), 0);
        let key = (tenant_hash, name_hash, pred_hash);

        let shard_ids = self.shard_ids_sorted();
        for sid in shard_ids {
            let Some(hs) = self.shard_arc(sid) else { continue };
            let Ok(proj_guard) = hs.projections.lock() else { continue };
            let Some(proj) = proj_guard.as_ref() else { continue };
            if let Some(row) = proj.state.entity_current_state.get(&key) {
                return Some((
                    row.current_value.clone(),
                    row.occurred_at_micros,
                    row.previous_value.clone(),
                    row.previous_occurred_at_micros,
                ));
            }
        }
        None
    }

    fn refresh_backpressure_state(&self) -> bool {
        // GPU memory pool removed (CPU-only community edition).
        // Backpressure is always inactive without a device pool.
        let mut active = self.backpressure_active.lock().expect("backpressure mutex");
        *active = false;
        self.metrics.set_backpressure_active(false);
        false
    }

    fn classify_corruption_reason(err: &str) -> String {
        let lower = err.to_ascii_lowercase();
        if lower.contains("trailer") && lower.contains("hash") {
            return "TRAILER_HASH_MISMATCH".to_string();
        }
        if lower.contains("toc") && (lower.contains("checksum") || lower.contains("crc")) {
            return "TOC_CHECKSUM_MISMATCH".to_string();
        }
        if lower.contains("headerhash") || (lower.contains("header") && lower.contains("hash")) {
            return "FRAME_HEADER_HASH_MISMATCH".to_string();
        }
        if lower.contains("payloadhash") || (lower.contains("payload") && lower.contains("hash")) {
            return "FRAME_PAYLOAD_HASH_MISMATCH".to_string();
        }
        if lower.contains("invalid toc") {
            return "INVALID_TOC".to_string();
        }
        if lower.contains("invalid frame") || lower.contains("frame count mismatch") {
            return "INVALID_FRAME".to_string();
        }
        if lower.contains("io") || lower.contains("not found") || lower.contains("permission") {
            return "IO_READ_FAILED".to_string();
        }
        "INTERNAL".to_string()
    }

    pub fn verify_store_integrity(
        &self,
        full: bool,
        sample_rate: f64,
        budget_bytes: usize,
        is_scrub: bool,
    ) -> VerifyStoreSummary {
        let shard_ids = self.shard_ids_sorted();
        let mut scanned = 0u64;
        let mut failed = 0u64;
        let mut out = Vec::new();
        let sample_rate = sample_rate.clamp(0.0, 1.0);

        for sid in shard_ids {
            if !full {
                let d = blake3::hash(&sid.to_le_bytes());
                let mut u = [0u8; 8];
                u.copy_from_slice(&d.as_bytes()[..8]);
                let p = (u64::from_le_bytes(u) as f64) / (u64::MAX as f64);
                if p >= sample_rate {
                    continue;
                }
            }

            let Some(hs) = self.shard_arc(sid) else {
                continue;
            };
            scanned = scanned.saturating_add(1);
            let started = std::time::Instant::now();
            let result = {
                let storage = hs.storage.read().expect("storage rwlock");
                storage.integrity_scan_stats_all(budget_bytes)
            };
            let elapsed = started.elapsed().as_secs_f64();
            if is_scrub {
                self.metrics.observe_segment_scrub_seconds(elapsed);
            } else {
                self.metrics.observe_verify_store_seconds(elapsed);
            }

            match result {
                Ok(stats) => out.push(VerifyStoreShardSummary {
                    shard_id: hs.shard_id.clone(),
                    ok: true,
                    reason: None,
                    total_segments: stats.total_segments,
                    total_blocks: stats.total_blocks,
                    total_frames: stats.total_frames,
                }),
                Err(err) => {
                    failed = failed.saturating_add(1);
                    let reason = Self::classify_corruption_reason(&err.to_string());
                    self.metrics.inc_segment_corrupt(&reason);
                    out.push(VerifyStoreShardSummary {
                        shard_id: hs.shard_id.clone(),
                        ok: false,
                        reason: Some(reason),
                        total_segments: 0,
                        total_blocks: 0,
                        total_frames: 0,
                    });
                }
            }
        }

        VerifyStoreSummary {
            ok: failed == 0,
            scanned_shards: scanned,
            failed_shards: failed,
            shards: out,
        }
    }

    pub fn projection_snapshot_issues(&self) -> Vec<ProjectionSnapshotIssue> {
        let mut out = Vec::new();
        for sid in self.shard_ids_sorted() {
            let Some(hs) = self.shard_arc(sid) else {
                continue;
            };
            let shard_id = hs.shard_id.clone();
            let Ok(proj_guard) = hs.projections.lock() else {
                out.push(ProjectionSnapshotIssue {
                    shard_id: shard_id.clone(),
                    projection: "all".to_string(),
                    reason: "MISSING_SNAPSHOT".to_string(),
                    detail: "projection lock unavailable".to_string(),
                });
                continue;
            };
            let Some(proj) = proj_guard.as_ref() else {
                out.push(ProjectionSnapshotIssue {
                    shard_id: shard_id.clone(),
                    projection: "all".to_string(),
                    reason: "MISSING_SNAPSHOT".to_string(),
                    detail: "projection store unavailable".to_string(),
                });
                continue;
            };

            let mut check =
                |projection: &str, path: &std::path::Path, expected: Option<&String>| {
                    if expected.is_none() {
                        out.push(ProjectionSnapshotIssue {
                            shard_id: shard_id.clone(),
                            projection: projection.to_string(),
                            reason: "MISSING_SNAPSHOT".to_string(),
                            detail: "meta missing snapshotBlake3".to_string(),
                        });
                        return;
                    }
                    if !path.exists() {
                        out.push(ProjectionSnapshotIssue {
                            shard_id: shard_id.clone(),
                            projection: projection.to_string(),
                            reason: "MISSING_SNAPSHOT".to_string(),
                            detail: format!("snapshot file missing: {}", path.display()),
                        });
                        return;
                    }
                    match std::fs::read(path) {
                        Ok(bytes) => {
                            let actual =
                                corecrux_projections::CcxsSnapshot::snapshot_blake3_hex(&bytes);
                            if Some(&actual) != expected {
                                out.push(ProjectionSnapshotIssue {
                                    shard_id: shard_id.clone(),
                                    projection: projection.to_string(),
                                    reason: "SNAPSHOT_HASH_MISMATCH".to_string(),
                                    detail: "snapshot hash does not match meta".to_string(),
                                });
                            }
                        }
                        Err(err) => {
                            out.push(ProjectionSnapshotIssue {
                                shard_id: shard_id.clone(),
                                projection: projection.to_string(),
                                reason: "MISSING_SNAPSHOT".to_string(),
                                detail: format!("snapshot read failed: {err}"),
                            });
                        }
                    }
                };

            check(
                "artifact_living_state",
                &proj.files.living_snapshot_path,
                proj.meta.artifact_living_state.snapshot_blake3.as_ref(),
            );
            check(
                "artifact_relations",
                &proj.files.relations_snapshot_path,
                proj.meta.artifact_relations.snapshot_blake3.as_ref(),
            );
            check(
                "pressure_events",
                &proj.files.pressure_snapshot_path,
                proj.meta.pressure_events.snapshot_blake3.as_ref(),
            );
            check(
                "artifact_dependents",
                &proj.files.dependents_snapshot_path,
                proj.meta.artifact_dependents.snapshot_blake3.as_ref(),
            );
        }
        out
    }

    pub async fn sync_shards(&self) -> Result<(), AppendError> {
        let routing = self.routing.read().await.shard_map.clone();

        for shard in routing.shards {
            if shard.state != corecrux_types::ShardState::Active {
                continue;
            }
            let hosted_here = if shard.leader.node_id == self.node_id {
                true
            } else if self.allow_follower_reads {
                shard
                    .followers
                    .as_ref()
                    .is_some_and(|followers| followers.iter().any(|n| n.node_id == self.node_id))
            } else {
                false
            };
            if !hosted_here {
                continue;
            }
            let owner_gpu_id = shard.gpu_id.unwrap_or(self.default_gpu_id);
            if owner_gpu_id != self.owned_gpu_id {
                continue;
            }
            let shard_id_u32 = parse_shard_id_u32(&shard.shard_id)
                .map_err(|e| AppendError::InvalidArgument(format!("{e}")))?;
            self.ensure_shard_open(shard_id_u32, &shard.shard_id, shard.epoch)?;
        }
        Ok(())
    }

    pub async fn apply_replicated_segment(
        &self,
        shard_id: &str,
        expected_epoch: u64,
        segment_bytes: &[u8],
    ) -> Result<ReplicationApplyResult, AppendError> {
        let shard_id_u32 = parse_shard_id_u32(shard_id)
            .map_err(|e| AppendError::InvalidArgument(e.to_string()))?;

        self.ensure_shard_open(shard_id_u32, shard_id, expected_epoch)?;
        let shard = self.shard_arc(shard_id_u32).ok_or_else(|| {
            AppendError::Internal("hosted shard missing for replication apply".to_string())
        })?;
        let (out, shard_label, stats) = {
            if shard.epoch != expected_epoch {
                return Err(AppendError::FailedPrecondition(
                    json!({
                        "code": "REPLICATION_EPOCH_MISMATCH",
                        "message": format!("replication apply epoch mismatch (expected {} got {})", shard.epoch, expected_epoch),
                        "shardId": shard_id,
                        "expectedEpoch": shard.epoch,
                        "receivedEpoch": expected_epoch
                    })
                    .to_string(),
                ));
            }

            let mut storage = shard.storage.write().expect("storage rwlock");
            let applied = storage
                .apply_replicated_segment_v1(segment_bytes)
                .map_err(AppendError::from_storage)?;

            let stats = storage.directory_lsm_stats_v1();
            let shard_label = shard.shard_id.clone();
            let out = ReplicationApplyResult {
                shard_id: shard_label.clone(),
                epoch: applied.epoch,
                segment_seq: applied.segment_seq,
                segment_hash_hex: hex32(&applied.segment_hash),
                file_len: applied.file_len,
                applied: applied.applied,
            };
            (out, shard_label, stats)
        };
        self.update_dir_metrics(&shard_label, stats);
        self.update_gpu_mem_metrics();
        Ok(out)
    }

    pub fn collect_replication_segments(
        &self,
        shard_id: &str,
        outcomes: &[AppendOutcome],
    ) -> Result<Vec<ReplicationSegmentPayload>, AppendError> {
        let shard_id_u32 = parse_shard_id_u32(shard_id)
            .map_err(|e| AppendError::InvalidArgument(e.to_string()))?;
        let shard = self.shard_arc(shard_id_u32).ok_or_else(|| {
            AppendError::Internal("hosted shard missing for replication segment read".to_string())
        })?;

        let mut seqs: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for o in outcomes {
            if o.status != AppendStatus::Appended {
                continue;
            }
            let Some(loc) = o.location else {
                continue;
            };
            if loc.segment_seq == 0 {
                continue;
            }
            seqs.insert(loc.segment_seq);
        }

        let mut out: Vec<ReplicationSegmentPayload> = Vec::new();
        let storage = shard.storage.read().expect("storage rwlock");
        for seq in seqs {
            let (bytes, segment_hash) = storage
                .read_segment_bytes_for_replication(seq)
                .map_err(AppendError::from_storage)?;
            out.push(ReplicationSegmentPayload {
                segment_seq: seq,
                segment_hash_hex: hex32(&segment_hash),
                bytes,
            });
        }
        Ok(out)
    }

    fn update_gpu_mem_metrics(&self) {
        // No-op: GPU memory pools removed (CPU-only community edition).
    }

    fn update_dir_metrics(&self, shard_id: &str, stats: corecrux_storage::DirectoryLsmStatsV1) {
        let mut bytes_by_level: std::collections::HashMap<u32, (u32, u64)> =
            std::collections::HashMap::new();
        let mut max_level: u32 = 0;
        for l in stats.levels {
            max_level = max_level.max(l.level);
            bytes_by_level.insert(l.level, (l.run_count, l.bytes));
        }

        // Make it easy for dashboards to expect a small fixed set of levels.
        max_level = max_level.clamp(6, 32);

        for level in 0..=max_level {
            let (runs, bytes) = bytes_by_level.get(&level).copied().unwrap_or((0, 0));
            self.metrics.set_dir_level_bytes(shard_id, level, bytes);
            if level == 0 {
                self.metrics.set_dir_l0_runs(shard_id, runs);
            }
        }
    }

    async fn route(
        &self,
        op: &'static str,
        stream_hash: u64,
        client_shard_map_version: Option<u64>,
        allow_follower_reads: bool,
    ) -> Result<RouteDecision, AppendError> {
        let start = std::time::Instant::now();
        let routing = self.routing.read().await.clone();

        let current_version = routing.current_version();
        if self.strict_client_version {
            if let Some(client_version) = client_shard_map_version {
                if client_version != current_version {
                    tracing::debug!(
                        op,
                        stream_hash,
                        client_version,
                        current_version,
                        "routing version mismatch"
                    );
                    self.metrics.inc_routing_lookup(op, "version_mismatch");
                    self.metrics
                        .observe_routing_lookup_seconds(op, start.elapsed().as_secs_f64());
                    return Err(AppendError::ShardMapVersionMismatch {
                        client_version,
                        current_version,
                    });
                }
            }
        }

        let decision = routing.route_stream_hash(stream_hash).ok_or_else(|| {
            AppendError::Internal("streamHash did not match any shard range".to_string())
        })?;

        if decision.leader_node_id != self.node_id {
            let is_follower = routing
                .shard_map
                .shards
                .iter()
                .find(|s| s.shard_id == decision.shard_id)
                .and_then(|s| s.followers.as_ref())
                .is_some_and(|followers| followers.iter().any(|n| n.node_id == self.node_id));
            if allow_follower_reads && is_follower {
                // Read-only follower path is allowed in replicated mode.
            } else {
                tracing::debug!(
                    op,
                    stream_hash,
                    shard_map_version = current_version,
                    shard_id = %decision.shard_id,
                    epoch = decision.epoch,
                    leader_node_id = %decision.leader_node_id,
                    "wrong shard (not hosted by this node)"
                );
                self.metrics.inc_routing_lookup(op, "wrong_shard");
                self.metrics
                    .observe_routing_lookup_seconds(op, start.elapsed().as_secs_f64());
                return Err(AppendError::WrongShard {
                    leader_grpc_addr: decision.leader_grpc_addr.clone(),
                    current_shard_map_version: current_version,
                });
            }
        }

        let owner_gpu_id = decision.gpu_id.unwrap_or(self.default_gpu_id);
        if owner_gpu_id != self.owned_gpu_id {
            tracing::debug!(
                op,
                stream_hash,
                shard_map_version = current_version,
                shard_id = %decision.shard_id,
                epoch = decision.epoch,
                owner_gpu_id,
                this_gpu_id = self.owned_gpu_id,
                "wrong gpu owner (not owned by this worker)"
            );
            self.metrics.inc_routing_lookup(op, "wrong_gpu_owner");
            self.metrics
                .observe_routing_lookup_seconds(op, start.elapsed().as_secs_f64());
            return Err(AppendError::FailedPrecondition(
                json!({
                    "code": "WRONG_GPU_OWNER",
                    "message": "request routed to a non-owning GPU worker",
                    "shardId": decision.shard_id,
                    "ownerGpuId": owner_gpu_id,
                    "thisGpuId": self.owned_gpu_id,
                    "currentShardMapVersion": current_version
                })
                .to_string(),
            ));
        }

        self.metrics.inc_routing_lookup(op, "ok");
        self.metrics
            .observe_routing_lookup_seconds(op, start.elapsed().as_secs_f64());
        self.metrics.inc_shard_request(&decision.shard_id, op);
        tracing::debug!(
            op,
            stream_hash,
            shard_map_version = current_version,
            shard_id = %decision.shard_id,
            epoch = decision.epoch,
            "route ok"
        );
        Ok(decision)
    }

    fn maybe_verify_receipt_stream_v1(
        &self,
        shard_id_u32: u32,
        tenant_id: &str,
        receipt_id: &str,
    ) -> Result<Option<VerificationReportV1>, AppendError> {
        let shard = self.shard_arc(shard_id_u32).ok_or_else(|| {
            AppendError::Internal("hosted shard missing for receipt verification".to_string())
        })?;
        let storage = shard.storage.read().expect("storage rwlock");

        let stream_hash = stream_hash_xxhash64(tenant_id, STREAM_TYPE_RECEIPT, receipt_id)
            .map_err(|e| {
                AppendError::InvalidArgument(format!("invalid receipt stream key: {e}"))
            })?;

        let events = storage
            .read_stream(
                tenant_id,
                STREAM_TYPE_RECEIPT,
                receipt_id,
                stream_hash,
                0,
                32,
            )
            .map_err(AppendError::from_storage)?;

        // Pick the latest body/sig in the stream (append-only; newer supersedes).
        let mut body: Option<corecrux_storage::StoredEvent> = None;
        let mut sig: Option<corecrux_storage::StoredEvent> = None;
        for e in events {
            if e.event_type == EVT_RECEIPT_BODY_V1
                && body.as_ref().map(|b| b.seq).unwrap_or(0) <= e.seq
            {
                body = Some(e);
            } else if e.event_type == EVT_RECEIPT_SIG_V1
                && sig.as_ref().map(|s| s.seq).unwrap_or(0) <= e.seq
            {
                sig = Some(e);
            }
        }

        let Some(body) = body else {
            // Nothing to verify yet.
            return Ok(None);
        };

        let shard_dir =
            corecrux_storage::ShardPaths::for_root(&self.shard_root, shard_id_u32).shard_dir;

        // Decode body frame so we can anchor against the stored header payloadHash and use the
        // stable ingested_at timestamp.
        let body_frame = storage
            .read_frame_bytes(body.location.segment_seq, body.location.offset)
            .map_err(AppendError::from_storage)?;
        let decoded_body = decode_frame_v1(&body_frame).map_err(|e| {
            AppendError::Internal(format!("failed to decode stored body frame: {e}"))
        })?;
        if decoded_body.header_bytes.len() < 32 {
            return Err(AppendError::Internal(
                "stored body header_bytes too small".to_string(),
            ));
        }
        let canonical_len = decoded_body.header_bytes.len() - 32;
        let canonical_bytes = &decoded_body.header_bytes[..canonical_len];
        let stored_header_hash = &decoded_body.header_bytes[canonical_len..];
        let canonical = corecrux_frame::decode_canonical_header_bytes_v1(canonical_bytes)
            .map_err(|e| AppendError::Internal(format!("invalid stored body header: {e}")))?;
        let computed_header_hash = corecrux_frame::compute_header_hash(canonical_bytes);
        if &computed_header_hash[..] != stored_header_hash {
            return Err(AppendError::Internal(
                "stored body headerHash mismatch (corrupt frame header bytes)".to_string(),
            ));
        }

        // Signature frame (optional).
        let (sig_payload_bytes, verified_at) = if let Some(sig_ev) = sig {
            let sig_frame = storage
                .read_frame_bytes(sig_ev.location.segment_seq, sig_ev.location.offset)
                .map_err(AppendError::from_storage)?;
            let decoded_sig = decode_frame_v1(&sig_frame).map_err(|e| {
                AppendError::Internal(format!("failed to decode stored sig frame: {e}"))
            })?;
            if decoded_sig.header_bytes.len() < 32 {
                return Err(AppendError::Internal(
                    "stored sig header_bytes too small".to_string(),
                ));
            }
            let sig_canonical_len = decoded_sig.header_bytes.len() - 32;
            let sig_canonical_bytes = &decoded_sig.header_bytes[..sig_canonical_len];
            let sig_header = corecrux_frame::decode_canonical_header_bytes_v1(sig_canonical_bytes)
                .map_err(|e| AppendError::Internal(format!("invalid stored sig header: {e}")))?;
            (Some(decoded_sig.payload_bytes), sig_header.ingested_at)
        } else {
            (None, canonical.ingested_at.clone())
        };

        let report = verify_receipt_v1(VerifyReceiptInput {
            tenant_id,
            receipt_id,
            body_bytes: &decoded_body.payload_bytes,
            stored_body_payload_hash: canonical.payload_hash,
            sig_bytes: sig_payload_bytes.as_deref(),
            keyring: self.receipts_keyring.as_deref(),
            verified_at: &verified_at,
            verifier_build: &self.build,
            recompute_candidate_digest: self.receipts_recompute_candidate_digest,
        })
        .map_err(|e| AppendError::Internal(format!("receipt verify error: {e}")))?;

        let _path = store_verification_report_v1(&shard_dir, &report)
            .map_err(|e| AppendError::Internal(e.to_string()))?;

        if report.error_code == "OK" {
            self.metrics.inc_receipt_verify_total("ok");
        } else {
            self.metrics.inc_receipt_verify_total("fail");
            self.metrics
                .inc_receipt_verify_fail(report.error_code.as_str());
        }

        Ok(Some(report))
    }

    pub fn verify_receipt_stream_v1(
        &self,
        shard_id_u32: u32,
        tenant_id: &str,
        receipt_id: &str,
    ) -> Result<Option<VerificationReportV1>, AppendError> {
        self.maybe_verify_receipt_stream_v1(shard_id_u32, tenant_id, receipt_id)
    }

    fn ensure_shard_open(
        &self,
        shard_id_u32: u32,
        shard_id: &str,
        epoch: u64,
    ) -> Result<(), AppendError> {
        {
            if let Some(existing) = self.shard_arc(shard_id_u32) {
                if existing.epoch != epoch {
                    return Err(AppendError::FailedPrecondition(format!(
                        "shard '{}' epoch changed (have {}, map says {}); restart required",
                        shard_id, existing.epoch, epoch
                    )));
                }
                return Ok(());
            }
        }

        let storage = corecrux_storage::ShardStorage::open(
            &self.shard_root,
            shard_id_u32,
            epoch,
            self.storage_options.clone(),
        )
        .map_err(AppendError::from_storage)?;

        let shard_dir = self.shard_root.join(format!("shard-{shard_id_u32:04}"));

        let projections = if self.projections_enabled {
            match ProjectionStoreV1::load_or_init(&shard_dir, shard_id_u32, epoch) {
                Ok(s) => Some(s),
                Err(err) => {
                    tracing::warn!(
                        shard_id = %shard_id,
                        err = %err,
                        "failed to load projection store; projections disabled for shard"
                    );
                    None
                }
            }
        } else {
            None
        };

        let new_shard = Arc::new(HostedShard {
            shard_id: shard_id.to_string(),
            epoch,
            storage: StdRwLock::new(storage),
            read_amp: Mutex::new(ReadAmpTracker::new(256)),
            tail_cache: Mutex::new(TailCache::new(TAIL_CACHE_DEFAULT_CAP_BYTES)),
            transient_recovery: Mutex::new(ShardTransientRecoveryState::default()),
            projections: Mutex::new(projections),
        });

        let shard_arc = {
            let mut shards = self.shards.write().expect("shards rwlock");
            if let Some(existing) = shards.get(&shard_id_u32) {
                if existing.epoch != epoch {
                    return Err(AppendError::FailedPrecondition(format!(
                        "shard '{}' epoch changed (have {}, map says {}); restart required",
                        shard_id, existing.epoch, epoch
                    )));
                }
                existing.clone()
            } else {
                shards.insert(shard_id_u32, new_shard.clone());
                new_shard
            }
        };

        let stats = {
            let storage = shard_arc.storage.read().expect("storage rwlock");
            storage.directory_lsm_stats_v1()
        };
        self.update_dir_metrics(&shard_arc.shard_id, stats);
        self.update_gpu_mem_metrics();

        Ok(())
    }
}

#[cfg(test)]
impl DataPlaneStore {
    /// Construct a minimal `DataPlaneStore` for pool routing tests that never
    /// touch shard storage. Fields are initialised to harmless defaults.
    pub(crate) fn new_empty_for_test() -> Self {
        use std::sync::Arc;

        let build = corecrux_types::BuildInfo {
            version: "test".to_string(),
            commit: "test".to_string(),
        };
        let metrics = crate::metrics::Metrics::new(&build, "test-store");
        let mut shard_map = corecrux_types::ShardMapV1 {
            v: corecrux_types::SHARDMAP_V1,
            cluster_id: "test".to_string(),
            version: 1,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            hash_fn: corecrux_types::SHARDMAP_HASH_FN_V1.to_string(),
            key_encoding: corecrux_types::SHARDMAP_KEY_ENCODING_V1.to_string(),
            shards: vec![corecrux_types::ShardDescriptor {
                shard_id: "shard-0000".to_string(),
                epoch: 1,
                state: corecrux_types::ShardState::Active,
                ranges: vec![corecrux_types::HashRange {
                    start_inclusive: "0x0000000000000000".to_string(),
                    end_exclusive: "0x0000000000000000".to_string(),
                }],
                leader: corecrux_types::NodeAddr {
                    node_id: "test-node".to_string(),
                    grpc_addr: "http://test-node.grpc".to_string(),
                    http_addr: "http://test-node.http".to_string(),
                },
                followers: None,
                data_dir: None,
                gpu_id: Some(0),
            }],
            blake3: String::new(),
            prev_blake3: None,
        };
        shard_map.blake3 =
            corecrux_types::compute_shard_map_v1_blake3_hex(&shard_map).expect("blake3");
        let routing = crate::shard_map::RoutingTable::new(crate::shard_map::LoadedShardMap {
            current_version: 1,
            shard_map,
        })
        .expect("empty routing table");

        Self {
            build,
            node_id: "test-node".to_string(),
            strict_client_version: false,
            routing: Arc::new(tokio::sync::RwLock::new(routing)),
            owned_gpu_id: 0,
            default_gpu_id: 0,
            metrics,
            control: Arc::new(tokio::sync::RwLock::new(
                crate::control::ControlV1::default(),
            )),
            shard_root: std::path::PathBuf::from("/tmp/corecrux-test-empty"),
            storage_options: corecrux_storage::ShardStorageOptions::default(),
            throttle: std::sync::Mutex::new(ThrottleTokenBucket::default()),
            backpressure_high_watermark_ratio: 0.8,
            backpressure_low_watermark_ratio: 0.5,
            backpressure_retry_after_ms: 50,
            backpressure_active: std::sync::Mutex::new(false),
            shards: std::sync::RwLock::new(std::collections::HashMap::new()),
            projections_enabled: false,
            allow_follower_reads: false,
            receipts_verify_enabled: false,
            receipts_recompute_candidate_digest: false,
            receipts_keyring: None,
            receipts_subject_index_root: std::path::PathBuf::from(
                "/tmp/corecrux-test-empty-receipts",
            ),
            tail_cache_enabled: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{bypass_valve_gate_for_internal_stream, gate_receipt_subject_mode_v1};
    use corecrux_receipts::VerificationReportV1;
    use serde_json::json;

    fn verification_report(payload_hash_hex: &str, error_code: &str) -> VerificationReportV1 {
        serde_json::from_value(json!({
            "schema": "cuecrux.receipt.verification.v1",
            "receipt_id": "rcpt-1",
            "tenant_id": "tenant-a",
            "payload_hash": payload_hash_hex,
            "signature": {
                "alg": "ed25519",
                "key_id": "dev-key"
            },
            "integrity": {
                "payload_hash_matches": true,
                "canonical_bytes_parse_ok": true
            },
            "trace_checks": {
                "retrieval_trace_present": false,
                "lanes_used_present": false,
                "candidate_generation_present": false,
                "filters_present": false,
                "normalisation_present": false,
                "fusion_present": false,
                "priors_applied_present": false,
                "anchors_present": false,
                "anchors_ids_present": false,
                "anchors_derivation_method_present": false,
                "rerank_present": false,
                "candidates_present": false,
                "candidate_digest_present": false,
                "candidate_digest_matches_recompute": null
            },
            "signature_valid": error_code == "OK",
            "pubkey_fingerprint": null,
            "error_code": error_code,
            "error_message": null,
            "verified_at": "2026-03-06T00:00:00Z",
            "verifier_build": "test"
        }))
        .expect("verification report json")
    }

    #[test]
    fn verified_subject_mode_requires_matching_ok_report() {
        let body = b"receipt-body";
        let matching = verification_report(&blake3::hash(body).to_hex().to_string(), "OK");
        assert_eq!(
            gate_receipt_subject_mode_v1("verified", body, Some(&matching)),
            "verified"
        );

        let stale = verification_report(&blake3::hash(b"other-body").to_hex().to_string(), "OK");
        assert_eq!(
            gate_receipt_subject_mode_v1("verified", body, Some(&stale)),
            "unknown"
        );

        let failed = verification_report(&blake3::hash(body).to_hex().to_string(), "SIG_INVALID");
        assert_eq!(
            gate_receipt_subject_mode_v1("verified", body, Some(&failed)),
            "unknown"
        );

        assert_eq!(
            gate_receipt_subject_mode_v1("verified", body, None),
            "unknown"
        );
        assert_eq!(gate_receipt_subject_mode_v1("audit", body, None), "audit");
    }

    #[test]
    fn internal_corecrux_streams_bypass_valve_gate() {
        assert!(bypass_valve_gate_for_internal_stream("system", "corecrux"));
        assert!(!bypass_valve_gate_for_internal_stream(
            "tenant-a", "corecrux"
        ));
        assert!(!bypass_valve_gate_for_internal_stream("system", "receipt"));
    }

    // ── AppendError Display ──────────────────────────────────────────────

    #[test]
    fn append_error_display_invalid_argument() {
        let err = super::AppendError::InvalidArgument("bad field".into());
        assert_eq!(format!("{err}"), "invalid argument: bad field");
    }

    #[test]
    fn append_error_display_failed_precondition() {
        let err = super::AppendError::FailedPrecondition("not ready".into());
        assert_eq!(format!("{err}"), "failed precondition: not ready");
    }

    #[test]
    fn append_error_display_resource_exhausted() {
        let err = super::AppendError::ResourceExhausted("oom".into());
        assert_eq!(format!("{err}"), "resource exhausted: oom");
    }

    #[test]
    fn append_error_display_io_backend() {
        let err = super::AppendError::IoBackend("disk full".into());
        assert_eq!(format!("{err}"), "io backend error: disk full");
    }

    #[test]
    fn append_error_display_internal() {
        let err = super::AppendError::Internal("bug".into());
        assert_eq!(format!("{err}"), "internal error: bug");
    }

    #[test]
    fn append_error_display_shard_unavailable() {
        let err = super::AppendError::ShardUnavailable {
            shard_id: "shard-0001".into(),
            owner_gpu_id: 3,
            current_shard_map_version: 42,
        };
        let msg = format!("{err}");
        assert!(msg.contains("shard_id=shard-0001"));
        assert!(msg.contains("owner_gpu_id=3"));
        assert!(msg.contains("shard_map_version=42"));
    }

    #[test]
    fn append_error_display_wrong_shard() {
        let err = super::AppendError::WrongShard {
            leader_grpc_addr: "http://leader:4007".into(),
            current_shard_map_version: 7,
        };
        let msg = format!("{err}");
        assert!(msg.contains("leader_grpc_addr=http://leader:4007"));
        assert!(msg.contains("shard_map_version=7"));
    }

    #[test]
    fn append_error_display_version_mismatch() {
        let err = super::AppendError::ShardMapVersionMismatch {
            client_version: 5,
            current_version: 10,
        };
        let msg = format!("{err}");
        assert!(msg.contains("client_version=5"));
        assert!(msg.contains("current_version=10"));
    }

    #[test]
    fn append_error_implements_error_trait() {
        let err = super::AppendError::Internal("test".into());
        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &err;
    }

    // ── AppendError::from_storage ────────────────────────────────────────

    #[test]
    fn from_storage_invalid_argument() {
        let storage_err = corecrux_storage::StorageError::InvalidArgument {
            code: "BAD_INPUT".into(),
            msg: "field missing".into(),
        };
        let err = super::AppendError::from_storage(storage_err);
        match &err {
            super::AppendError::InvalidArgument(msg) => {
                let v: serde_json::Value = serde_json::from_str(msg).unwrap();
                assert_eq!(v["code"], "BAD_INPUT");
                assert_eq!(v["message"], "field missing");
            }
            _ => panic!("expected InvalidArgument, got {err:?}"),
        }
    }

    #[test]
    fn from_storage_failed_precondition() {
        let storage_err = corecrux_storage::StorageError::FailedPrecondition {
            code: "SEQ_MISMATCH".into(),
            msg: "wrong seq".into(),
        };
        let err = super::AppendError::from_storage(storage_err);
        assert!(matches!(err, super::AppendError::FailedPrecondition(_)));
    }

    #[test]
    fn from_storage_resource_exhausted() {
        let storage_err = corecrux_storage::StorageError::ResourceExhausted {
            code: "MEM_FULL".into(),
            msg: "out of memory".into(),
            retry_after_ms: Some(500),
        };
        let err = super::AppendError::from_storage(storage_err);
        match &err {
            super::AppendError::ResourceExhausted(msg) => {
                let v: serde_json::Value = serde_json::from_str(msg).unwrap();
                assert_eq!(v["retryAfterMs"], 500);
            }
            _ => panic!("expected ResourceExhausted, got {err:?}"),
        }
    }

    #[test]
    fn from_storage_internal() {
        let err = super::AppendError::from_storage(corecrux_storage::StorageError::Internal {
            msg: "boom".into(),
        });
        assert!(matches!(err, super::AppendError::Internal(_)));
    }

    #[test]
    fn from_storage_io() {
        let err = super::AppendError::from_storage(corecrux_storage::StorageError::Io {
            msg: "disk fail".into(),
        });
        assert!(matches!(err, super::AppendError::IoBackend(_)));
    }

    #[test]
    fn from_storage_manifest_header_invalid() {
        let err = super::AppendError::from_storage(
            corecrux_storage::StorageError::ManifestHeaderInvalid {
                msg: "corrupt".into(),
            },
        );
        assert!(matches!(err, super::AppendError::Internal(_)));
    }

    #[test]
    fn from_storage_manifest_crc_mismatch() {
        let err = super::AppendError::from_storage(
            corecrux_storage::StorageError::ManifestCrcMismatch {
                expected: 0xDEAD,
                actual: 0xBEEF,
            },
        );
        match &err {
            super::AppendError::Internal(msg) => {
                assert!(msg.contains("0xdead"));
                assert!(msg.contains("0xbeef"));
            }
            _ => panic!("expected Internal, got {err:?}"),
        }
    }

    #[test]
    fn from_storage_manifest_record_crc_mismatch() {
        let err = super::AppendError::from_storage(
            corecrux_storage::StorageError::ManifestRecordCrcMismatch {
                expected: 0xAAAA,
                actual: 0xBBBB,
            },
        );
        assert!(matches!(err, super::AppendError::Internal(_)));
    }

    #[test]
    fn from_storage_manifest_record_invalid() {
        let err = super::AppendError::from_storage(
            corecrux_storage::StorageError::ManifestRecordInvalid {
                msg: "bad record".into(),
            },
        );
        assert!(matches!(err, super::AppendError::FailedPrecondition(_)));
    }

    // ── is_transient_cuda_context_error ──────────────────────────────────

    #[test]
    fn transient_cuda_error_detects_error_201() {
        let err = super::AppendError::IoBackend("CUDA error 201: invalid device context".into());
        assert!(super::is_transient_cuda_context_error(&err));
    }

    #[test]
    fn transient_cuda_error_detects_context_lost() {
        let err = super::AppendError::Internal("cuda_context_lost in read path".into());
        assert!(super::is_transient_cuda_context_error(&err));
    }

    #[test]
    fn transient_cuda_error_detects_json_code() {
        let err = super::AppendError::ResourceExhausted(
            r#"{"code":"cuda_context_lost","message":"fail"}"#.into(),
        );
        assert!(super::is_transient_cuda_context_error(&err));
    }

    #[test]
    fn transient_cuda_error_false_for_unrelated() {
        let err = super::AppendError::Internal("some other error".into());
        assert!(!super::is_transient_cuda_context_error(&err));
    }

    #[test]
    fn transient_cuda_error_false_for_non_io_variants() {
        let err = super::AppendError::InvalidArgument("cuda error 201".into());
        assert!(!super::is_transient_cuda_context_error(&err));
        let err2 = super::AppendError::FailedPrecondition("cuda_context_lost".into());
        assert!(!super::is_transient_cuda_context_error(&err2));
    }

    #[test]
    fn transient_cuda_error_case_insensitive() {
        let err = super::AppendError::IoBackend("CUDA_ERROR_INVALID_CONTEXT at offset 0".into());
        assert!(super::is_transient_cuda_context_error(&err));
    }

    // ── cursor_to_json ───────────────────────────────────────────────────

    #[test]
    fn cursor_to_json_none_is_null() {
        assert_eq!(super::cursor_to_json(&None), serde_json::Value::Null);
    }

    #[test]
    fn cursor_to_json_some_produces_object() {
        let cursor = corecrux_projections::ProjectionCursorV1 {
            shard_id: 0,
            epoch: 1,
            segment_seq: 42,
            offset: 99,
        };
        let val = super::cursor_to_json(&Some(cursor));
        assert_eq!(val["segmentSeq"], 42);
        assert_eq!(val["offset"], 99);
    }

    // ── hex32 ────────────────────────────────────────────────────────────

    #[test]
    fn hex32_encodes_all_zeros() {
        let bytes = [0u8; 32];
        assert_eq!(
            super::hex32(&bytes),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn hex32_encodes_all_ff() {
        let bytes = [0xffu8; 32];
        assert_eq!(
            super::hex32(&bytes),
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn hex32_encodes_known_pattern() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xde;
        bytes[1] = 0xad;
        bytes[31] = 0xef;
        let hex = super::hex32(&bytes);
        assert!(hex.starts_with("dead"));
        assert!(hex.ends_with("ef"));
        assert_eq!(hex.len(), 64);
    }

    // ── estimate_tail_cache_bytes ────────────────────────────────────────

    #[test]
    fn estimate_tail_cache_bytes_empty() {
        assert_eq!(super::estimate_tail_cache_bytes(&[]), 0);
    }

    fn default_frame_location() -> corecrux_storage::FrameLocation {
        corecrux_storage::FrameLocation {
            shard_id: 0,
            epoch: 0,
            segment_seq: 0,
            offset: 0,
        }
    }

    #[test]
    fn estimate_tail_cache_bytes_includes_overhead() {
        let event = corecrux_storage::StoredEvent {
            seq: 0,
            event_id: "e1".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:00Z".to_string(),
            event_type: "test".to_string(),
            content_type: "application/json".to_string(),
            payload: b"hello".to_vec(),
            location: default_frame_location(),
        };
        let est = super::estimate_tail_cache_bytes(&[event]);
        // Each field length + 64 overhead
        assert!(est >= 64);
        assert!(est < 300);
    }

    // ── ThrottleTokenBucket ──────────────────────────────────────────────

    #[test]
    fn throttle_default_unconfigured_allows_everything() {
        let mut tb = super::ThrottleTokenBucket::default();
        // No rates configured: try_consume should succeed
        assert!(tb.try_consume(100, 100, 50).is_ok());
    }

    #[test]
    fn throttle_default_ratio_is_one_when_unconfigured() {
        let tb = super::ThrottleTokenBucket::default();
        assert_eq!(tb.ratio_0_to_1(), 1.0);
    }

    #[test]
    fn throttle_zero_rate_blocks_all() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(Some(0), None);
        assert!(tb.try_consume(1, 0, 50).is_err());
    }

    #[test]
    fn throttle_zero_bytes_rate_blocks_bytes() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(None, Some(0));
        assert!(tb.try_consume(0, 1, 50).is_err());
    }

    #[test]
    fn throttle_configured_rate_provides_initial_burst() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(Some(1000), Some(1_000_000));
        // Initial burst = rate * burst_secs (1) = 1000 events, 1M bytes
        assert!(tb.try_consume(500, 500_000, 50).is_ok());
    }

    #[test]
    fn throttle_exhaustion_returns_retry_after() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(Some(100), None);
        // Consume all initial burst tokens
        assert!(tb.try_consume(100, 0, 50).is_ok());
        // Next consume should fail with retry_after
        let err = tb.try_consume(1, 0, 50).unwrap_err();
        assert!(err >= 1, "retry_after_ms should be at least 1ms");
    }

    #[test]
    fn throttle_events_capacity_reflects_rate_times_burst() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(Some(500), None);
        assert_eq!(tb.events_capacity(), 500); // 500 * 1 burst_sec
    }

    #[test]
    fn throttle_bytes_capacity_reflects_rate_times_burst() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(None, Some(2048));
        assert_eq!(tb.bytes_capacity(), 2048);
    }

    #[test]
    fn throttle_update_config_no_change_is_noop() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(Some(100), Some(200));
        // Consume some tokens
        assert!(tb.try_consume(50, 100, 50).is_ok());
        let events_before = tb.events_tokens;
        // Same config again — should not reset tokens
        tb.update_config(Some(100), Some(200));
        assert_eq!(tb.events_tokens, events_before);
    }

    #[test]
    fn throttle_update_config_changed_resets_tokens() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(Some(100), None);
        assert!(tb.try_consume(100, 0, 50).is_ok());
        assert_eq!(tb.events_tokens, 0);
        // Change config — tokens should reset to new capacity
        tb.update_config(Some(200), None);
        assert_eq!(tb.events_tokens, 200);
    }

    #[test]
    fn throttle_ratio_clamped_between_0_and_1() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(Some(100), Some(1000));
        let r = tb.ratio_0_to_1();
        assert!((0.0..=1.0).contains(&r));
        // Drain tokens
        assert!(tb.try_consume(100, 1000, 50).is_ok());
        let r2 = tb.ratio_0_to_1();
        assert!((0.0..=1.0).contains(&r2));
        assert!(r2 <= r);
    }

    // ── ReadAmpTracker ───────────────────────────────────────────────────

    #[test]
    fn read_amp_zero_cap_returns_identity() {
        let mut tracker = super::ReadAmpTracker::new(0);
        let (p50, p95) = tracker.record(5);
        assert_eq!(p50, 5.0);
        assert_eq!(p95, 5.0);
    }

    #[test]
    fn read_amp_single_sample() {
        let mut tracker = super::ReadAmpTracker::new(10);
        let (p50, p95) = tracker.record(7);
        assert_eq!(p50, 7.0);
        assert_eq!(p95, 7.0);
    }

    #[test]
    fn read_amp_evicts_oldest_when_full() {
        let mut tracker = super::ReadAmpTracker::new(3);
        tracker.record(100);
        tracker.record(200);
        tracker.record(300);
        // This should evict 100
        let (p50, _p95) = tracker.record(1);
        // After eviction: [200, 300, 1] sorted: [1, 200, 300]
        assert_eq!(p50, 200.0); // median of 3 elements
    }

    #[test]
    fn read_amp_percentiles_with_spread() {
        let mut tracker = super::ReadAmpTracker::new(100);
        for i in 1..=100 {
            tracker.record(i);
        }
        let (p50, p95) = tracker.record(50);
        // p50 should be around 50, p95 around 96
        assert!(p50 >= 40.0 && p50 <= 60.0, "p50={p50}");
        assert!(p95 >= 90.0 && p95 <= 100.0, "p95={p95}");
    }

    // ── TailCache ────────────────────────────────────────────────────────

    fn make_stored_event(id: &str) -> corecrux_storage::StoredEvent {
        corecrux_storage::StoredEvent {
            seq: 0,
            event_id: id.to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:00Z".to_string(),
            event_type: "test".to_string(),
            content_type: "application/json".to_string(),
            payload: b"data".to_vec(),
            location: default_frame_location(),
        }
    }

    #[test]
    fn tail_cache_get_miss() {
        let mut cache = super::TailCache::new(1024 * 1024);
        assert!(cache.get("t", "s", "i", 10).is_none());
    }

    #[test]
    fn tail_cache_put_then_get() {
        let mut cache = super::TailCache::new(1024 * 1024);
        let events = vec![make_stored_event("e1")];
        cache.put("t", "s", "i", 10, &events);
        let got = cache.get("t", "s", "i", 10);
        assert!(got.is_some());
        assert_eq!(got.unwrap().len(), 1);
    }

    #[test]
    fn tail_cache_get_wrong_tail_events_misses() {
        let mut cache = super::TailCache::new(1024 * 1024);
        let events = vec![make_stored_event("e1")];
        cache.put("t", "s", "i", 10, &events);
        // Different tail_events count
        assert!(cache.get("t", "s", "i", 20).is_none());
    }

    #[test]
    fn tail_cache_invalidate_removes_entry() {
        let mut cache = super::TailCache::new(1024 * 1024);
        let events = vec![make_stored_event("e1")];
        cache.put("t", "s", "i", 10, &events);
        cache.invalidate_stream("t", "s", "i");
        assert!(cache.get("t", "s", "i", 10).is_none());
    }

    #[test]
    fn tail_cache_evicts_on_capacity() {
        // Tiny capacity to force eviction
        let mut cache = super::TailCache::new(1024 * 1024); // min is 1MB
        let big_event = corecrux_storage::StoredEvent {
            seq: 0,
            event_id: "e1".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:00Z".to_string(),
            event_type: "test".to_string(),
            content_type: "application/json".to_string(),
            payload: vec![0u8; 512 * 1024], // 512KB each
            location: default_frame_location(),
        };
        // Put enough entries to exceed 1MB
        cache.put("t", "s", "a", 1, &[big_event.clone()]);
        cache.put("t", "s", "b", 1, &[big_event.clone()]);
        cache.put("t", "s", "c", 1, &[big_event.clone()]);
        // Oldest should have been evicted
        // (exact eviction depends on overhead calc, but total_bytes should be bounded)
        assert!(cache.total_bytes() <= 1024 * 1024 + 512 * 1024);
    }

    #[test]
    fn tail_cache_total_bytes_tracks_size() {
        let mut cache = super::TailCache::new(10 * 1024 * 1024);
        assert_eq!(cache.total_bytes(), 0);
        let events = vec![make_stored_event("e1")];
        cache.put("t", "s", "i", 10, &events);
        assert!(cache.total_bytes() > 0);
        cache.invalidate_stream("t", "s", "i");
        assert_eq!(cache.total_bytes(), 0);
    }

    #[test]
    fn tail_cache_overwrite_updates_size() {
        let mut cache = super::TailCache::new(10 * 1024 * 1024);
        let events1 = vec![make_stored_event("e1")];
        cache.put("t", "s", "i", 10, &events1);
        let size1 = cache.total_bytes();
        let events2 = vec![make_stored_event("e1"), make_stored_event("e2")];
        cache.put("t", "s", "i", 10, &events2);
        let size2 = cache.total_bytes();
        assert!(size2 > size1, "size should grow with more events");
    }

    // ── ShardTransientRecoveryState ──────────────────────────────────────

    #[test]
    fn transient_recovery_default_zero_streaks() {
        let st = super::ShardTransientRecoveryState::default();
        assert_eq!(st.streak(super::ReadOpKind::Tail), 0);
        assert_eq!(st.streak(super::ReadOpKind::Range), 0);
    }

    #[test]
    fn transient_recovery_mark_failure_increments() {
        let mut st = super::ShardTransientRecoveryState::default();
        assert_eq!(st.mark_failure(super::ReadOpKind::Tail), 1);
        assert_eq!(st.mark_failure(super::ReadOpKind::Tail), 2);
        // Range is independent
        assert_eq!(st.streak(super::ReadOpKind::Range), 0);
    }

    #[test]
    fn transient_recovery_mark_success_resets() {
        let mut st = super::ShardTransientRecoveryState::default();
        st.mark_failure(super::ReadOpKind::Tail);
        st.mark_failure(super::ReadOpKind::Tail);
        st.mark_success(super::ReadOpKind::Tail);
        assert_eq!(st.streak(super::ReadOpKind::Tail), 0);
    }

    #[test]
    fn transient_recovery_reset_is_same_as_success() {
        let mut st = super::ShardTransientRecoveryState::default();
        st.mark_failure(super::ReadOpKind::Range);
        st.mark_failure(super::ReadOpKind::Range);
        st.reset(super::ReadOpKind::Range);
        assert_eq!(st.streak(super::ReadOpKind::Range), 0);
    }

    #[test]
    fn transient_recovery_tail_and_range_independent() {
        let mut st = super::ShardTransientRecoveryState::default();
        st.mark_failure(super::ReadOpKind::Tail);
        st.mark_failure(super::ReadOpKind::Tail);
        st.mark_failure(super::ReadOpKind::Range);
        assert_eq!(st.streak(super::ReadOpKind::Tail), 2);
        assert_eq!(st.streak(super::ReadOpKind::Range), 1);
        st.mark_success(super::ReadOpKind::Tail);
        assert_eq!(st.streak(super::ReadOpKind::Tail), 0);
        assert_eq!(st.streak(super::ReadOpKind::Range), 1);
    }

    // ── ReadOpKind::from_metric_op ───────────────────────────────────────

    #[test]
    fn read_op_kind_from_metric_op() {
        assert!(matches!(
            super::ReadOpKind::from_metric_op("tail"),
            Some(super::ReadOpKind::Tail)
        ));
        assert!(matches!(
            super::ReadOpKind::from_metric_op("range"),
            Some(super::ReadOpKind::Range)
        ));
        assert!(super::ReadOpKind::from_metric_op("unknown").is_none());
        assert!(super::ReadOpKind::from_metric_op("").is_none());
    }

    // ── Serde roundtrips ─────────────────────────────────────────────────

    #[test]
    fn replication_apply_result_serializes_with_camel_case() {
        let result = super::ReplicationApplyResult {
            shard_id: "shard-0000".to_string(),
            epoch: 1,
            segment_seq: 5,
            segment_hash_hex: "abc123".to_string(),
            file_len: 1024,
            applied: true,
        };
        let json_str = serde_json::to_string(&result).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(v["shardId"], "shard-0000");
        assert_eq!(v["segmentSeq"], 5);
        assert_eq!(v["segmentHash"], "abc123");
        assert_eq!(v["fileLen"], 1024);
        assert_eq!(v["applied"], true);
    }

    #[test]
    fn verify_store_shard_summary_omits_none_reason() {
        let summary = super::VerifyStoreShardSummary {
            shard_id: "shard-0001".to_string(),
            ok: true,
            reason: None,
            total_segments: 10,
            total_blocks: 100,
            total_frames: 500,
        };
        let json_str = serde_json::to_string(&summary).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(v.get("reason").is_none());
        assert_eq!(v["shardId"], "shard-0001");
    }

    #[test]
    fn verify_store_shard_summary_includes_reason_when_present() {
        let summary = super::VerifyStoreShardSummary {
            shard_id: "shard-0001".to_string(),
            ok: false,
            reason: Some("corruption detected".to_string()),
            total_segments: 5,
            total_blocks: 50,
            total_frames: 200,
        };
        let json_str = serde_json::to_string(&summary).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(v["reason"], "corruption detected");
    }

    #[test]
    fn verify_store_summary_serializes() {
        let summary = super::VerifyStoreSummary {
            ok: false,
            scanned_shards: 4,
            failed_shards: 1,
            shards: vec![super::VerifyStoreShardSummary {
                shard_id: "shard-0000".to_string(),
                ok: false,
                reason: Some("bad crc".to_string()),
                total_segments: 1,
                total_blocks: 1,
                total_frames: 1,
            }],
        };
        let v: serde_json::Value = serde_json::to_value(&summary).unwrap();
        assert_eq!(v["scannedShards"], 4);
        assert_eq!(v["failedShards"], 1);
        assert_eq!(v["shards"][0]["shardId"], "shard-0000");
    }

    #[test]
    fn projection_snapshot_issue_serializes() {
        let issue = super::ProjectionSnapshotIssue {
            shard_id: "shard-0002".to_string(),
            projection: "living_state".to_string(),
            reason: "stale cursor".to_string(),
            detail: "cursor behind by 100 frames".to_string(),
        };
        let v: serde_json::Value = serde_json::to_value(&issue).unwrap();
        assert_eq!(v["shardId"], "shard-0002");
        assert_eq!(v["projection"], "living_state");
    }

    #[test]
    fn projection_relation_row_serializes() {
        let row = super::ProjectionRelationRowV1 {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: 3,
            confidence_q16: 65535,
            evidence_ref_hash16: [0u8; 16],
            created_at_micros: 1000,
            updated_at_micros: 2000,
        };
        let v: serde_json::Value = serde_json::to_value(&row).unwrap();
        assert_eq!(v["src_artifact_id"], 1);
        assert_eq!(v["dst_artifact_id"], 2);
        assert_eq!(v["confidence_q16"], 65535);
    }

    #[test]
    fn projection_dependent_row_serializes() {
        let row = super::ProjectionDependentRowV1 {
            dependent_type: 1,
            dependent_id: "dep-abc".to_string(),
            last_seen_at_micros: 5000,
            usage_weight_q16: 32768,
        };
        let v: serde_json::Value = serde_json::to_value(&row).unwrap();
        assert_eq!(v["dependent_type"], 1);
        assert_eq!(v["dependent_id"], "dep-abc");
    }

    #[test]
    fn projection_pressure_event_row_serializes() {
        let row = super::ProjectionPressureEventRowV1 {
            event_id: uuid::Uuid::nil(),
            pressure_code_id: 42,
            severity: 2,
            observed_at_micros: 100,
            acknowledged_at_micros: 200,
            resolved_at_micros: 300,
            receipt_id: None,
        };
        let v: serde_json::Value = serde_json::to_value(&row).unwrap();
        assert_eq!(v["pressure_code_id"], 42);
        assert_eq!(v["severity"], 2);
        assert!(v["receipt_id"].is_null());
    }

    // ── classify_corruption_reason ──────────────────────────────────────

    #[test]
    fn classify_corruption_trailer_hash() {
        assert_eq!(
            super::DataPlaneStore::classify_corruption_reason("trailer hash mismatch at offset 4"),
            "TRAILER_HASH_MISMATCH"
        );
    }

    #[test]
    fn classify_corruption_toc_checksum() {
        assert_eq!(
            super::DataPlaneStore::classify_corruption_reason("toc checksum failed"),
            "TOC_CHECKSUM_MISMATCH"
        );
    }

    #[test]
    fn classify_corruption_toc_crc() {
        assert_eq!(
            super::DataPlaneStore::classify_corruption_reason("toc crc mismatch"),
            "TOC_CHECKSUM_MISMATCH"
        );
    }

    #[test]
    fn classify_corruption_frame_header_hash() {
        assert_eq!(
            super::DataPlaneStore::classify_corruption_reason("headerHash mismatch"),
            "FRAME_HEADER_HASH_MISMATCH"
        );
    }

    #[test]
    fn classify_corruption_header_hash_two_words() {
        assert_eq!(
            super::DataPlaneStore::classify_corruption_reason("frame header hash error"),
            "FRAME_HEADER_HASH_MISMATCH"
        );
    }

    #[test]
    fn classify_corruption_payload_hash() {
        assert_eq!(
            super::DataPlaneStore::classify_corruption_reason("payloadHash mismatch"),
            "FRAME_PAYLOAD_HASH_MISMATCH"
        );
    }

    #[test]
    fn classify_corruption_payload_hash_two_words() {
        assert_eq!(
            super::DataPlaneStore::classify_corruption_reason("bad payload hash"),
            "FRAME_PAYLOAD_HASH_MISMATCH"
        );
    }

    #[test]
    fn classify_corruption_invalid_toc() {
        assert_eq!(
            super::DataPlaneStore::classify_corruption_reason("invalid toc entry at block 3"),
            "INVALID_TOC"
        );
    }

    #[test]
    fn classify_corruption_invalid_frame() {
        assert_eq!(
            super::DataPlaneStore::classify_corruption_reason("invalid frame at offset 0"),
            "INVALID_FRAME"
        );
    }

    #[test]
    fn classify_corruption_frame_count_mismatch() {
        assert_eq!(
            super::DataPlaneStore::classify_corruption_reason("frame count mismatch"),
            "INVALID_FRAME"
        );
    }

    #[test]
    fn classify_corruption_io_error() {
        assert_eq!(
            super::DataPlaneStore::classify_corruption_reason("io error: disk failure"),
            "IO_READ_FAILED"
        );
    }

    #[test]
    fn classify_corruption_not_found() {
        assert_eq!(
            super::DataPlaneStore::classify_corruption_reason("segment not found"),
            "IO_READ_FAILED"
        );
    }

    #[test]
    fn classify_corruption_permission() {
        assert_eq!(
            super::DataPlaneStore::classify_corruption_reason("permission denied"),
            "IO_READ_FAILED"
        );
    }

    #[test]
    fn classify_corruption_unknown() {
        assert_eq!(
            super::DataPlaneStore::classify_corruption_reason("something unexpected"),
            "INTERNAL"
        );
    }

    // ── Real-storage-backed DataPlaneStore tests ────────────────────────

    /// Create a `DataPlaneStore` backed by a real tempdir with one shard open.
    fn new_store_with_real_shard() -> (tempfile::TempDir, super::DataPlaneStore) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = super::DataPlaneStore::new_empty_for_test();
        store.shard_root = dir.path().to_path_buf();
        store.receipts_subject_index_root = dir.path().join("receipts-idx");
        store.ensure_shard_open(0, "shard-0000", 1).unwrap();
        (dir, store)
    }

    #[test]
    fn ensure_shard_open_creates_shard() {
        let (_dir, store) = new_store_with_real_shard();
        assert_eq!(store.hosted_shards(), vec!["shard-0000".to_string()]);
    }

    #[test]
    fn ensure_shard_open_idempotent() {
        let (_dir, store) = new_store_with_real_shard();
        // Opening the same shard twice with same epoch should succeed
        store.ensure_shard_open(0, "shard-0000", 1).unwrap();
        assert_eq!(store.hosted_shards().len(), 1);
    }

    #[test]
    fn ensure_shard_open_epoch_mismatch_fails() {
        let (_dir, store) = new_store_with_real_shard();
        let err = store.ensure_shard_open(0, "shard-0000", 2);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("epoch changed"), "msg: {msg}");
    }

    #[test]
    fn shard_ids_sorted_returns_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = super::DataPlaneStore::new_empty_for_test();
        store.shard_root = dir.path().to_path_buf();
        store.ensure_shard_open(3, "shard-0003", 1).unwrap();
        store.ensure_shard_open(1, "shard-0001", 1).unwrap();
        store.ensure_shard_open(0, "shard-0000", 1).unwrap();
        assert_eq!(store.shard_ids_sorted(), vec![0, 1, 3]);
    }

    #[test]
    fn shard_arc_returns_none_for_missing() {
        let store = super::DataPlaneStore::new_empty_for_test();
        assert!(store.shard_arc(999).is_none());
    }

    #[test]
    fn shard_arc_returns_some_for_existing() {
        let (_dir, store) = new_store_with_real_shard();
        assert!(store.shard_arc(0).is_some());
    }

    #[test]
    fn hosted_shards_empty_initially() {
        let store = super::DataPlaneStore::new_empty_for_test();
        assert!(store.hosted_shards().is_empty());
    }

    #[test]
    fn hosted_shards_returns_sorted() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = super::DataPlaneStore::new_empty_for_test();
        store.shard_root = dir.path().to_path_buf();
        store.ensure_shard_open(2, "shard-0002", 1).unwrap();
        store.ensure_shard_open(0, "shard-0000", 1).unwrap();
        let shards = store.hosted_shards();
        assert_eq!(shards, vec!["shard-0000", "shard-0002"]);
    }

    #[test]
    fn refresh_backpressure_state_returns_false_on_cpu() {
        let (_dir, store) = new_store_with_real_shard();
        assert!(!store.refresh_backpressure_state());
    }

    #[test]
    fn refresh_backpressure_state_clears_active_flag() {
        let (_dir, store) = new_store_with_real_shard();
        // Artificially set backpressure active
        {
            let mut active = store.backpressure_active.lock().unwrap();
            *active = true;
        }
        let result = store.refresh_backpressure_state();
        assert!(!result);
        let active = store.backpressure_active.lock().unwrap();
        assert!(!*active);
    }

    #[test]
    fn force_seal_shard_on_empty_shard() {
        let (_dir, store) = new_store_with_real_shard();
        let result = store.force_seal_shard(0).unwrap();
        // Empty shard has nothing to seal
        assert!(!result.sealed);
    }

    #[test]
    fn force_seal_shard_missing_returns_error() {
        let (_dir, store) = new_store_with_real_shard();
        let err = store.force_seal_shard(999);
        assert!(err.is_err());
        assert!(err.unwrap_err().contains("not found"));
    }

    #[test]
    fn force_seal_all_shards_on_empty() {
        let (_dir, store) = new_store_with_real_shard();
        let results = store.force_seal_all_shards();
        assert_eq!(results.len(), 1);
        let (label, result) = &results[0];
        assert_eq!(label, "shard-0");
        assert!(result.is_ok());
    }

    #[test]
    fn force_seal_and_tick_on_empty_shard() {
        let (_dir, store) = new_store_with_real_shard();
        let result = store.force_seal_and_tick_shard(0, 1000).unwrap();
        assert_eq!(result.shard_id, "shard-0000");
        assert!(!result.seal_result.sealed);
        assert_eq!(result.projection_frames_processed, 0);
    }

    #[test]
    fn force_seal_and_tick_missing_shard_errors() {
        let (_dir, store) = new_store_with_real_shard();
        let err = store.force_seal_and_tick_shard(999, 1000);
        assert!(err.is_err());
    }

    #[test]
    fn force_seal_all_shards_and_tick() {
        let (_dir, store) = new_store_with_real_shard();
        let results = store.force_seal_all_shards_and_tick(1000);
        assert_eq!(results.len(), 1);
        assert!(results[0].1.is_ok());
    }

    #[test]
    fn tick_projections_disabled_returns_empty() {
        let (_dir, store) = new_store_with_real_shard();
        // projections_enabled is false by default in new_empty_for_test
        let results = store.tick_projections(1000);
        assert!(results.is_empty());
    }

    #[test]
    fn rebuild_projections_pooled_disabled_returns_empty() {
        let (_dir, store) = new_store_with_real_shard();
        let results = store.rebuild_projections_pooled(1000);
        assert!(results.is_empty());
    }

    #[test]
    fn verify_store_integrity_on_empty_shard() {
        let (_dir, store) = new_store_with_real_shard();
        let summary = store.verify_store_integrity(true, 1.0, 16 * 1024 * 1024, false);
        assert!(summary.ok);
        assert_eq!(summary.scanned_shards, 1);
        assert_eq!(summary.failed_shards, 0);
        assert_eq!(summary.shards.len(), 1);
        assert_eq!(summary.shards[0].shard_id, "shard-0000");
    }

    #[test]
    fn verify_store_integrity_scrub_mode() {
        let (_dir, store) = new_store_with_real_shard();
        let summary = store.verify_store_integrity(true, 1.0, 16 * 1024 * 1024, true);
        assert!(summary.ok);
    }

    #[test]
    fn verify_store_integrity_sampled_may_skip() {
        let (_dir, store) = new_store_with_real_shard();
        // With sample_rate=0.0 and full=false, no shards should be scanned
        let summary = store.verify_store_integrity(false, 0.0, 16 * 1024 * 1024, false);
        assert!(summary.ok);
        assert_eq!(summary.scanned_shards, 0);
    }

    #[test]
    fn projection_snapshot_issues_no_projections() {
        let (_dir, store) = new_store_with_real_shard();
        // Projections are None, so we expect MISSING_SNAPSHOT issues
        let issues = store.projection_snapshot_issues();
        assert!(!issues.is_empty());
        assert!(issues.iter().all(|i| i.reason == "MISSING_SNAPSHOT"));
    }

    #[test]
    fn projections_meta_for_missing_shard() {
        let (_dir, store) = new_store_with_real_shard();
        assert!(store.projections_meta_for_shard(999).is_none());
    }

    #[test]
    fn projections_meta_for_shard_no_projection() {
        let (_dir, store) = new_store_with_real_shard();
        // Shard exists but projection is None
        assert!(store.projections_meta_for_shard(0).is_none());
    }

    #[test]
    fn projections_living_state_row_missing() {
        let (_dir, store) = new_store_with_real_shard();
        assert!(store.projections_living_state_row(0, "tenant-a", 42).is_none());
    }

    #[test]
    fn projections_list_relations_empty() {
        let (_dir, store) = new_store_with_real_shard();
        let rows = store.projections_list_relations(0, "tenant-a", 42, "out", None, 100, 0);
        assert!(rows.is_empty());
    }

    #[test]
    fn projections_list_relations_in_direction_empty() {
        let (_dir, store) = new_store_with_real_shard();
        let rows = store.projections_list_relations(0, "tenant-a", 42, "in", None, 100, 0);
        assert!(rows.is_empty());
    }

    #[test]
    fn projections_list_dependents_empty() {
        let (_dir, store) = new_store_with_real_shard();
        let rows = store.projections_list_dependents(0, "tenant-a", 42, None, 100, 0);
        assert!(rows.is_empty());
    }

    #[test]
    fn projections_list_pressure_events_empty() {
        let (_dir, store) = new_store_with_real_shard();
        let rows = store.projections_list_pressure_events(0, "tenant-a", 42, false, 100, 0);
        assert!(rows.is_empty());
    }

    #[test]
    fn query_graph_expand_no_projections() {
        let (_dir, store) = new_store_with_real_shard();
        let resp = store.query_graph_expand("tenant-a", &[1, 2], &[], 2, 100, 0.0, false);
        assert!(resp.artifacts.is_empty());
    }

    #[test]
    fn query_time_range_no_projections() {
        let (_dir, store) = new_store_with_real_shard();
        let resp = store.query_time_range("tenant-a", 0, i64::MAX, &[], false, 100);
        assert!(resp.artifacts.is_empty());
    }

    #[test]
    fn query_entity_count_no_projections() {
        let (_dir, store) = new_store_with_real_shard();
        let items = store.query_entity_count("tenant-a", "user", "active");
        assert!(items.is_empty());
    }

    #[test]
    fn query_entity_timeline_no_projections() {
        let (_dir, store) = new_store_with_real_shard();
        let events = store.query_entity_timeline("tenant-a", "user", "login");
        assert!(events.is_empty());
    }

    #[test]
    fn query_entity_current_state_no_projections() {
        let (_dir, store) = new_store_with_real_shard();
        assert!(store.query_entity_current_state("tenant-a", "alice", "status").is_none());
    }

    #[test]
    fn read_frame_bytes_missing_shard() {
        let (_dir, store) = new_store_with_real_shard();
        let err = store.read_frame_bytes(999, 0, 0);
        assert!(err.is_err());
    }

    #[test]
    fn read_frame_bytes_shard_id_out_of_range() {
        let (_dir, store) = new_store_with_real_shard();
        let err = store.read_frame_bytes(u64::MAX, 0, 0);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("out of range"));
    }

    #[test]
    fn read_frame_bytes_batch_packed_empty() {
        let (_dir, store) = new_store_with_real_shard();
        let result = store.read_frame_bytes_batch_packed(&[]).unwrap();
        assert!(result.frames_blob.is_empty());
        assert_eq!(result.frame_bytes, 0);
    }

    #[test]
    fn read_frame_bytes_batch_packed_multi_shard_rejected() {
        let (_dir, store) = new_store_with_real_shard();
        let locs = vec![
            corecrux_storage::FrameLocation { shard_id: 0, epoch: 1, segment_seq: 0, offset: 0 },
            corecrux_storage::FrameLocation { shard_id: 1, epoch: 1, segment_seq: 0, offset: 0 },
        ];
        let err = store.read_frame_bytes_batch_packed(&locs);
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("multiple shard_ids"));
    }

    #[test]
    fn read_frame_bytes_batch_packed_shard_id_out_of_range() {
        let (_dir, store) = new_store_with_real_shard();
        let locs = vec![
            corecrux_storage::FrameLocation { shard_id: u64::MAX, epoch: 1, segment_seq: 0, offset: 0 },
        ];
        let err = store.read_frame_bytes_batch_packed(&locs);
        assert!(err.is_err());
    }

    // ── Append + read round-trip via DataPlaneStore storage handles ─────

    /// Append events directly through the shard's ShardStorage (bypassing the
    /// async append_batch path which requires a full routing setup) and verify
    /// we can read them back via DataPlaneStore methods that operate on the
    /// same storage handle.
    #[test]
    fn append_via_shard_storage_then_read_frame_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = super::DataPlaneStore::new_empty_for_test();
        store.shard_root = dir.path().to_path_buf();
        store.ensure_shard_open(0, "shard-0000", 1).unwrap();

        let shard = store.shard_arc(0).unwrap();
        let stream_hash = corecrux_frame::stream_hash_xxhash64("t1", "artifact", "s1").unwrap();

        let events = vec![corecrux_storage::AppendEventInput {
            event_id: "evt-1",
            occurred_at: "2026-01-01T00:00:00Z",
            event_type: "test.created",
            content_type: "application/octet-stream",
            payload_bytes: b"hello-world",
        }];

        let (outcomes, _stats) = {
            let mut storage = shard.storage.write().unwrap();
            storage
                .append_batch_with_stats(
                    stream_hash,
                    1,
                    "t1",
                    "artifact",
                    "s1",
                    "2026-01-01T00:00:00Z",
                    &events,
                )
                .unwrap()
        };
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].status, corecrux_storage::AppendStatus::Appended);

        let loc = outcomes[0].location.expect("location present after append");
        let frame_bytes = store.read_frame_bytes(0, loc.segment_seq, loc.offset).unwrap();
        assert!(!frame_bytes.is_empty());

        // Also test batch packed read
        let locs = vec![corecrux_storage::FrameLocation {
            shard_id: 0,
            epoch: 1,
            segment_seq: loc.segment_seq,
            offset: loc.offset,
        }];
        let packed = store.read_frame_bytes_batch_packed(&locs).unwrap();
        assert_eq!(packed.frame_offsets.len(), 1);
        assert!(packed.frame_bytes > 0);
    }

    /// Helper: create a store with head segments enabled so force_seal has something to seal.
    fn new_store_with_head_segments() -> (tempfile::TempDir, super::DataPlaneStore) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = super::DataPlaneStore::new_empty_for_test();
        store.shard_root = dir.path().to_path_buf();
        store.storage_options.head_max_record_bytes = 1024 * 1024;
        store.ensure_shard_open(0, "shard-0000", 1).unwrap();
        (dir, store)
    }

    #[test]
    fn force_seal_after_append_seals_segment() {
        let (_dir, store) = new_store_with_head_segments();

        let shard = store.shard_arc(0).unwrap();
        let stream_hash = corecrux_frame::stream_hash_xxhash64("t1", "artifact", "s1").unwrap();

        {
            let mut storage = shard.storage.write().unwrap();
            storage
                .append_batch_with_stats(
                    stream_hash,
                    1,
                    "t1",
                    "artifact",
                    "s1",
                    "2026-01-01T00:00:00Z",
                    &[corecrux_storage::AppendEventInput {
                        event_id: "evt-1",
                        occurred_at: "2026-01-01T00:00:00Z",
                        event_type: "test.created",
                        content_type: "application/octet-stream",
                        payload_bytes: b"seal-me",
                    }],
                )
                .unwrap();
        }

        let seal = store.force_seal_shard(0).unwrap();
        assert!(seal.sealed);

        // Sealing again with no new data should not seal
        let seal2 = store.force_seal_shard(0).unwrap();
        assert!(!seal2.sealed);
    }

    #[test]
    fn verify_store_integrity_after_append() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = super::DataPlaneStore::new_empty_for_test();
        store.shard_root = dir.path().to_path_buf();
        store.ensure_shard_open(0, "shard-0000", 1).unwrap();

        let shard = store.shard_arc(0).unwrap();
        let stream_hash = corecrux_frame::stream_hash_xxhash64("t1", "artifact", "s1").unwrap();

        {
            let mut storage = shard.storage.write().unwrap();
            storage
                .append_batch_with_stats(
                    stream_hash,
                    1,
                    "t1",
                    "artifact",
                    "s1",
                    "2026-01-01T00:00:00Z",
                    &[corecrux_storage::AppendEventInput {
                        event_id: "evt-1",
                        occurred_at: "2026-01-01T00:00:00Z",
                        event_type: "test.created",
                        content_type: "application/octet-stream",
                        payload_bytes: b"integrity-check",
                    }],
                )
                .unwrap();
        }

        // Seal so integrity scan has something to verify
        store.force_seal_shard(0).unwrap();
        let summary = store.verify_store_integrity(true, 1.0, 64 * 1024 * 1024, false);
        assert!(summary.ok);
        assert_eq!(summary.scanned_shards, 1);
        assert!(summary.shards[0].total_frames > 0);
    }

    #[test]
    fn multiple_shards_management() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = super::DataPlaneStore::new_empty_for_test();
        store.shard_root = dir.path().to_path_buf();
        store.ensure_shard_open(0, "shard-0000", 1).unwrap();
        store.ensure_shard_open(1, "shard-0001", 1).unwrap();
        store.ensure_shard_open(2, "shard-0002", 1).unwrap();

        assert_eq!(store.shard_ids_sorted(), vec![0, 1, 2]);
        assert_eq!(store.hosted_shards(), vec!["shard-0000", "shard-0001", "shard-0002"]);

        // Force seal all returns results for each shard
        let results = store.force_seal_all_shards();
        assert_eq!(results.len(), 3);
        for (_, result) in &results {
            assert!(result.is_ok());
        }
    }

    #[test]
    fn force_seal_and_tick_after_append() {
        let (_dir, store) = new_store_with_head_segments();

        let shard = store.shard_arc(0).unwrap();
        let stream_hash = corecrux_frame::stream_hash_xxhash64("t1", "artifact", "s1").unwrap();

        {
            let mut storage = shard.storage.write().unwrap();
            storage
                .append_batch_with_stats(
                    stream_hash,
                    1,
                    "t1",
                    "artifact",
                    "s1",
                    "2026-01-01T00:00:00Z",
                    &[corecrux_storage::AppendEventInput {
                        event_id: "evt-1",
                        occurred_at: "2026-01-01T00:00:00Z",
                        event_type: "test.created",
                        content_type: "application/octet-stream",
                        payload_bytes: b"seal-and-tick",
                    }],
                )
                .unwrap();
        }

        let result = store.force_seal_and_tick_shard(0, 1000).unwrap();
        assert!(result.seal_result.sealed);
        assert_eq!(result.shard_id, "shard-0000");
        // projections disabled, so no frames processed
        assert_eq!(result.projection_frames_processed, 0);
    }

    #[test]
    fn force_seal_all_shards_and_tick_after_append() {
        let (_dir, store) = new_store_with_head_segments();

        let shard = store.shard_arc(0).unwrap();
        let stream_hash = corecrux_frame::stream_hash_xxhash64("t1", "artifact", "s1").unwrap();

        {
            let mut storage = shard.storage.write().unwrap();
            storage
                .append_batch_with_stats(
                    stream_hash,
                    1,
                    "t1",
                    "artifact",
                    "s1",
                    "2026-01-01T00:00:00Z",
                    &[corecrux_storage::AppendEventInput {
                        event_id: "evt-1",
                        occurred_at: "2026-01-01T00:00:00Z",
                        event_type: "test.created",
                        content_type: "application/octet-stream",
                        payload_bytes: b"seal-tick-all",
                    }],
                )
                .unwrap();
        }

        let results = store.force_seal_all_shards_and_tick(1000);
        assert_eq!(results.len(), 1);
        let (label, result) = &results[0];
        assert_eq!(label, "shard-0");
        let r = result.as_ref().unwrap();
        assert!(r.seal_result.sealed);
    }

    #[test]
    fn collect_replication_segments_empty_outcomes() {
        let (_dir, store) = new_store_with_real_shard();
        let segments = store.collect_replication_segments("shard-0000", &[]).unwrap();
        assert!(segments.is_empty());
    }

    #[test]
    fn collect_replication_segments_missing_shard() {
        let (_dir, store) = new_store_with_real_shard();
        let err = store.collect_replication_segments("shard-9999", &[]);
        assert!(err.is_err());
    }

    // ── Projections-enabled tests ───────────────────────────────────────

    fn new_store_with_projections() -> (tempfile::TempDir, super::DataPlaneStore) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = super::DataPlaneStore::new_empty_for_test();
        store.shard_root = dir.path().to_path_buf();
        store.receipts_subject_index_root = dir.path().join("receipts-idx");
        store.projections_enabled = true;
        store.ensure_shard_open(0, "shard-0000", 1).unwrap();
        (dir, store)
    }

    #[test]
    fn projections_enabled_store_has_meta() {
        let (_dir, store) = new_store_with_projections();
        let meta = store.projections_meta_for_shard(0);
        assert!(meta.is_some());
    }

    #[test]
    fn tick_projections_enabled_on_empty() {
        let (_dir, store) = new_store_with_projections();
        let results = store.tick_projections(1000);
        // Nothing to tick on empty storage
        assert!(results.is_empty());
    }

    #[test]
    fn rebuild_projections_pooled_enabled_on_empty() {
        let (_dir, store) = new_store_with_projections();
        let results = store.rebuild_projections_pooled(1000);
        // Rebuild runs but finds nothing
        assert_eq!(results.len(), 1);
        let (label, result) = &results[0];
        assert_eq!(label, "shard-0");
        assert!(result.is_ok());
    }

    #[test]
    fn tick_projections_after_append_and_seal() {
        let (_dir, store) = new_store_with_projections();

        let shard = store.shard_arc(0).unwrap();
        let stream_hash = corecrux_frame::stream_hash_xxhash64("t1", "artifact", "s1").unwrap();

        {
            let mut storage = shard.storage.write().unwrap();
            storage
                .append_batch_with_stats(
                    stream_hash,
                    1,
                    "t1",
                    "artifact",
                    "s1",
                    "2026-01-01T00:00:00Z",
                    &[corecrux_storage::AppendEventInput {
                        event_id: "evt-1",
                        occurred_at: "2026-01-01T00:00:00Z",
                        event_type: "test.created",
                        content_type: "application/octet-stream",
                        payload_bytes: b"proj-tick-test",
                    }],
                )
                .unwrap();
        }

        // Seal first so projection tick can process sealed segments
        store.force_seal_shard(0).unwrap();

        let results = store.tick_projections(1000);
        // Should find the sealed segment and process at least one frame
        assert!(!results.is_empty());
        let (_shard_id, tick_result) = &results[0];
        assert!(tick_result.frames_processed > 0);
    }

    #[test]
    fn force_seal_and_tick_with_projections() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = super::DataPlaneStore::new_empty_for_test();
        store.shard_root = dir.path().to_path_buf();
        store.projections_enabled = true;
        store.storage_options.head_max_record_bytes = 1024 * 1024;
        store.ensure_shard_open(0, "shard-0000", 1).unwrap();

        let shard = store.shard_arc(0).unwrap();
        let stream_hash = corecrux_frame::stream_hash_xxhash64("t1", "artifact", "s1").unwrap();

        {
            let mut storage = shard.storage.write().unwrap();
            storage
                .append_batch_with_stats(
                    stream_hash,
                    1,
                    "t1",
                    "artifact",
                    "s1",
                    "2026-01-01T00:00:00Z",
                    &[corecrux_storage::AppendEventInput {
                        event_id: "evt-1",
                        occurred_at: "2026-01-01T00:00:00Z",
                        event_type: "test.created",
                        content_type: "application/octet-stream",
                        payload_bytes: b"seal-tick-proj",
                    }],
                )
                .unwrap();
        }

        let result = store.force_seal_and_tick_shard(0, 1000).unwrap();
        assert!(result.seal_result.sealed);
        // With projections enabled, frames should have been processed
        assert!(result.projection_frames_processed > 0);
    }

    #[test]
    fn projection_snapshot_issues_with_projections() {
        let (_dir, store) = new_store_with_projections();
        // Fresh projection store — snapshots are expected to exist but may
        // or may not have blake3 hashes set depending on whether any tick ran.
        let issues = store.projection_snapshot_issues();
        // Issues should relate to snapshot state, not panics
        for issue in &issues {
            assert!(
                issue.reason == "MISSING_SNAPSHOT" || issue.reason == "SNAPSHOT_HASH_MISMATCH",
                "unexpected reason: {}",
                issue.reason
            );
        }
    }

    // ── Tail cache integration ──────────────────────────────────────────

    #[test]
    fn tail_cache_enabled_store() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = super::DataPlaneStore::new_empty_for_test();
        store.shard_root = dir.path().to_path_buf();
        store.tail_cache_enabled = true;
        store.ensure_shard_open(0, "shard-0000", 1).unwrap();

        // Verify the shard has a tail cache
        let shard = store.shard_arc(0).unwrap();
        let cache = shard.tail_cache.lock().unwrap();
        assert_eq!(cache.total_bytes(), 0);
    }

    // ── update_gpu_mem_metrics (no-op on CPU) ───────────────────────────

    #[test]
    fn update_gpu_mem_metrics_noop() {
        let (_dir, store) = new_store_with_real_shard();
        // Should not panic
        store.update_gpu_mem_metrics();
    }

    // ── ReadOpKind (additional) ──────────────────────────────────────────

    #[test]
    fn read_op_kind_from_metric_op_exhaustive() {
        assert!(matches!(super::ReadOpKind::from_metric_op("tail"), Some(super::ReadOpKind::Tail)));
        assert!(matches!(super::ReadOpKind::from_metric_op("range"), Some(super::ReadOpKind::Range)));
        assert!(super::ReadOpKind::from_metric_op("unknown").is_none());
        assert!(super::ReadOpKind::from_metric_op("").is_none());
    }

    // ── ShardTransientRecoveryState ────────────────────────────────────

    #[test]
    fn transient_recovery_state_tracks_streaks() {
        let mut state = super::ShardTransientRecoveryState::default();
        assert_eq!(state.streak(super::ReadOpKind::Tail), 0);
        assert_eq!(state.streak(super::ReadOpKind::Range), 0);

        assert_eq!(state.mark_failure(super::ReadOpKind::Tail), 1);
        assert_eq!(state.mark_failure(super::ReadOpKind::Tail), 2);
        assert_eq!(state.streak(super::ReadOpKind::Tail), 2);
        assert_eq!(state.streak(super::ReadOpKind::Range), 0);

        state.mark_success(super::ReadOpKind::Tail);
        assert_eq!(state.streak(super::ReadOpKind::Tail), 0);
    }

    #[test]
    fn transient_recovery_state_reset_clears_streak() {
        let mut state = super::ShardTransientRecoveryState::default();
        state.mark_failure(super::ReadOpKind::Range);
        state.mark_failure(super::ReadOpKind::Range);
        assert_eq!(state.streak(super::ReadOpKind::Range), 2);
        state.reset(super::ReadOpKind::Range);
        assert_eq!(state.streak(super::ReadOpKind::Range), 0);
    }

    #[test]
    fn transient_recovery_state_independent_ops() {
        let mut state = super::ShardTransientRecoveryState::default();
        state.mark_failure(super::ReadOpKind::Tail);
        state.mark_failure(super::ReadOpKind::Range);
        state.mark_failure(super::ReadOpKind::Range);
        assert_eq!(state.streak(super::ReadOpKind::Tail), 1);
        assert_eq!(state.streak(super::ReadOpKind::Range), 2);
        state.mark_success(super::ReadOpKind::Tail);
        assert_eq!(state.streak(super::ReadOpKind::Tail), 0);
        assert_eq!(state.streak(super::ReadOpKind::Range), 2);
    }

    // ── estimate_tail_cache_bytes additional ────────────────────────────

    #[test]
    fn estimate_tail_cache_bytes_multiple_events() {
        let events: Vec<corecrux_storage::StoredEvent> = (0..5)
            .map(|i| corecrux_storage::StoredEvent {
                seq: i,
                event_id: format!("evt-{i}"),
                occurred_at: "2026-01-01T00:00:00Z".to_string(),
                ingested_at: "2026-01-01T00:00:00Z".to_string(),
                event_type: "test".to_string(),
                content_type: "application/json".to_string(),
                payload: vec![0u8; 100],
                location: default_frame_location(),
            })
            .collect();
        let est = super::estimate_tail_cache_bytes(&events);
        assert!(est >= 5 * 100); // At least payload bytes
        assert!(est >= 5 * 164); // Payload + overhead per event
    }

    // ── bypass_valve_gate additional ────────────────────────────────────

    #[test]
    fn bypass_valve_gate_empty_strings() {
        assert!(!bypass_valve_gate_for_internal_stream("", ""));
        assert!(!bypass_valve_gate_for_internal_stream("system", ""));
        assert!(!bypass_valve_gate_for_internal_stream("", "corecrux"));
    }

    // ── gate_receipt_subject_mode_v1 additional ─────────────────────────

    #[test]
    fn gate_receipt_subject_mode_passthrough_non_verified() {
        let body = b"body";
        assert_eq!(gate_receipt_subject_mode_v1("standard", body, None), "standard");
        assert_eq!(gate_receipt_subject_mode_v1("light", body, None), "light");
        assert_eq!(gate_receipt_subject_mode_v1("", body, None), "");
    }

    // ── ThrottleTokenBucket: ratio with only bytes configured ───────

    #[test]
    fn throttle_ratio_with_only_bytes() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(None, Some(1000));
        let r = tb.ratio_0_to_1();
        assert!((0.0..=1.0).contains(&r));
        assert!(tb.try_consume(0, 1000, 50).is_ok());
        let r2 = tb.ratio_0_to_1();
        assert_eq!(r2, 0.0);
    }

    // ── ThrottleTokenBucket: ratio with only events configured ──────

    #[test]
    fn throttle_ratio_with_only_events() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(Some(100), None);
        assert_eq!(tb.ratio_0_to_1(), 1.0);
        assert!(tb.try_consume(50, 0, 50).is_ok());
        let r = tb.ratio_0_to_1();
        assert!((0.0..=1.0).contains(&r));
        assert!(r < 1.0);
    }

    // ── ThrottleTokenBucket: ratio minimum of both ──────────────────

    #[test]
    fn throttle_ratio_returns_minimum_of_both_rates() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(Some(100), Some(1000));
        // Full capacity: ratio = 1.0
        assert_eq!(tb.ratio_0_to_1(), 1.0);
        // Drain bytes completely but leave events
        assert!(tb.try_consume(10, 1000, 50).is_ok());
        let r = tb.ratio_0_to_1();
        // Bytes ratio is 0.0, events ratio is 0.9, min = 0.0
        assert_eq!(r, 0.0);
    }

    // ── AppendError::from_storage Segment variant ───────────────────

    #[test]
    fn from_storage_segment_error() {
        let seg_err = corecrux_storage::StorageError::Segment(
            corecrux_segment::SegmentError::BufferTooSmall,
        );
        let err = super::AppendError::from_storage(seg_err);
        match &err {
            super::AppendError::Internal(msg) => {
                assert!(msg.contains("segment error"));
            }
            _ => panic!("expected Internal, got {err:?}"),
        }
    }

    // ── ForceSealAndTickResult Debug ─────────────────────────────────

    #[test]
    fn force_seal_and_tick_result_debug() {
        let result = super::ForceSealAndTickResult {
            shard_id: "shard-0000".to_string(),
            seal_result: corecrux_storage::SealResultV1 {
                sealed: false,
                segment_seq: None,
                frame_count: None,
                seal_duration_secs: 0.0,
            },
            cursor_before: None,
            cursor_after: None,
            projection_frames_processed: 0,
        };
        let dbg = format!("{:?}", result);
        assert!(dbg.contains("shard-0000"));
    }

    // ── ReplicationApplyResult Clone and Debug ───────────────────────

    #[test]
    fn replication_apply_result_clone_debug() {
        let result = super::ReplicationApplyResult {
            shard_id: "shard-0001".to_string(),
            epoch: 3,
            segment_seq: 10,
            segment_hash_hex: "abc".to_string(),
            file_len: 1024,
            applied: true,
        };
        let cloned = result.clone();
        assert_eq!(cloned.shard_id, "shard-0001");
        let dbg = format!("{:?}", result);
        assert!(dbg.contains("shard-0001"));
    }

    // ── ReplicationSegmentPayload Clone and Debug ────────────────────

    #[test]
    fn replication_segment_payload_clone_debug() {
        let payload = super::ReplicationSegmentPayload {
            segment_seq: 42,
            segment_hash_hex: "deadbeef".to_string(),
            bytes: vec![1, 2, 3],
        };
        let cloned = payload.clone();
        assert_eq!(cloned.segment_seq, 42);
        assert_eq!(cloned.bytes, vec![1, 2, 3]);
        let dbg = format!("{:?}", payload);
        assert!(dbg.contains("42"));
    }

    // ── ThrottleTokenBucket: try_consume with both zero needs ───────

    #[test]
    fn throttle_try_consume_zero_needs_always_ok() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(Some(0), Some(0));
        assert!(tb.try_consume(0, 0, 50).is_ok());
    }

    // ── ReadAmpTracker: percentiles with single value ───────────────

    #[test]
    fn read_amp_two_samples() {
        let mut tracker = super::ReadAmpTracker::new(10);
        tracker.record(10);
        let (p50, p95) = tracker.record(20);
        // sorted: [10, 20] → p50=idx 0=10, p95=idx 1=20
        assert_eq!(p50, 10.0);
        assert_eq!(p95, 20.0);
    }

    // ── TailCache: put replaces matching entry ──────────────────────

    #[test]
    fn tail_cache_put_replaces_same_key() {
        let mut cache = super::TailCache::new(10 * 1024 * 1024);
        let events1 = vec![make_stored_event("e1")];
        cache.put("t", "s", "i", 10, &events1);
        let events2 = vec![make_stored_event("e2")];
        cache.put("t", "s", "i", 10, &events2);
        let got = cache.get("t", "s", "i", 10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].event_id, "e2");
    }

    // ── TailCache: get miss on different stream parts ───────────────

    #[test]
    fn tail_cache_get_miss_different_tenant() {
        let mut cache = super::TailCache::new(1024 * 1024);
        let events = vec![make_stored_event("e1")];
        cache.put("t1", "s", "i", 10, &events);
        assert!(cache.get("t2", "s", "i", 10).is_none());
    }

    #[test]
    fn tail_cache_get_miss_different_stream_type() {
        let mut cache = super::TailCache::new(1024 * 1024);
        let events = vec![make_stored_event("e1")];
        cache.put("t", "s1", "i", 10, &events);
        assert!(cache.get("t", "s2", "i", 10).is_none());
    }

    // ── ThrottleTokenBucket: refill does not exceed capacity ────────

    #[test]
    fn throttle_refill_does_not_exceed_capacity() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(Some(100), Some(200));
        // Drain all tokens
        assert!(tb.try_consume(100, 200, 50).is_ok());
        // Refill (time-dependent — just ensure no panic and tokens <= cap)
        tb.refill();
        assert!(tb.events_tokens <= tb.events_capacity());
        assert!(tb.bytes_tokens <= tb.bytes_capacity());
    }

    // ── from_storage: ResourceExhausted with no retry_after_ms ──────

    #[test]
    fn from_storage_resource_exhausted_no_retry() {
        let storage_err = corecrux_storage::StorageError::ResourceExhausted {
            code: "FULL".into(),
            msg: "full".into(),
            retry_after_ms: None,
        };
        let err = super::AppendError::from_storage(storage_err);
        match &err {
            super::AppendError::ResourceExhausted(msg) => {
                let v: serde_json::Value = serde_json::from_str(msg).unwrap();
                assert!(v["retryAfterMs"].is_null());
            }
            _ => panic!("expected ResourceExhausted, got {err:?}"),
        }
    }

    // ── classify_corruption: additional patterns ────────────────────

    #[test]
    fn classify_corruption_case_insensitive_trailer() {
        assert_eq!(
            super::DataPlaneStore::classify_corruption_reason("Trailer Hash Mismatch"),
            "TRAILER_HASH_MISMATCH"
        );
    }

    // ── append then read_stream round-trip ──────────────────────────

    #[test]
    fn append_then_read_stream_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = super::DataPlaneStore::new_empty_for_test();
        store.shard_root = dir.path().to_path_buf();
        store.ensure_shard_open(0, "shard-0000", 1).unwrap();

        let shard = store.shard_arc(0).unwrap();
        let stream_hash = corecrux_frame::stream_hash_xxhash64("t1", "knowledge", "s1").unwrap();

        let events = vec![
            corecrux_storage::AppendEventInput {
                event_id: "evt-1",
                occurred_at: "2026-01-01T00:00:00Z",
                event_type: "test",
                content_type: "application/json",
                payload_bytes: b"payload-1",
            },
            corecrux_storage::AppendEventInput {
                event_id: "evt-2",
                occurred_at: "2026-01-01T00:00:01Z",
                event_type: "test",
                content_type: "application/json",
                payload_bytes: b"payload-2",
            },
        ];

        {
            let mut storage = shard.storage.write().unwrap();
            let (outcomes, _) = storage
                .append_batch_with_stats(stream_hash, 1, "t1", "knowledge", "s1", "2026-01-01T00:00:00Z", &events)
                .unwrap();
            assert_eq!(outcomes.len(), 2);
            assert!(outcomes.iter().all(|o| o.status == corecrux_storage::AppendStatus::Appended));
        }

        // Read back
        {
            let storage = shard.storage.read().unwrap();
            let read = storage.read_stream("t1", "knowledge", "s1", stream_hash, 1, 100).unwrap();
            assert_eq!(read.len(), 2);
            assert_eq!(read[0].event_id, "evt-1");
            assert_eq!(read[1].event_id, "evt-2");
        }
    }

    // ── append then read_tail round-trip ────────────────────────────

    #[test]
    fn append_then_read_tail() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = super::DataPlaneStore::new_empty_for_test();
        store.shard_root = dir.path().to_path_buf();
        store.ensure_shard_open(0, "shard-0000", 1).unwrap();

        let shard = store.shard_arc(0).unwrap();
        let stream_hash = corecrux_frame::stream_hash_xxhash64("t1", "artifact", "s1").unwrap();

        let events: Vec<corecrux_storage::AppendEventInput> = (0..5)
            .map(|i| corecrux_storage::AppendEventInput {
                event_id: Box::leak(format!("evt-{i}").into_boxed_str()),
                occurred_at: "2026-01-01T00:00:00Z",
                event_type: "test",
                content_type: "application/json",
                payload_bytes: b"data",
            })
            .collect();

        {
            let mut storage = shard.storage.write().unwrap();
            storage
                .append_batch_with_stats(stream_hash, 1, "t1", "artifact", "s1", "2026-01-01T00:00:00Z", &events)
                .unwrap();
        }

        {
            let storage = shard.storage.read().unwrap();
            let tail = storage.read_tail("t1", "artifact", "s1", stream_hash, 2).unwrap();
            assert_eq!(tail.len(), 2);
            // Last 2 events
            assert_eq!(tail[0].event_id, "evt-3");
            assert_eq!(tail[1].event_id, "evt-4");
        }
    }

    // ── ThrottleTokenBucket: ratio with only events configured ───────

    #[test]
    fn throttle_ratio_events_only() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(Some(100), None);
        let r = tb.ratio_0_to_1();
        assert!((r - 1.0).abs() < f64::EPSILON); // fully refilled
        tb.try_consume(50, 0, 50).unwrap();
        let r2 = tb.ratio_0_to_1();
        assert!((r2 - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn throttle_ratio_bytes_only() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(None, Some(1000));
        let r = tb.ratio_0_to_1();
        assert!((r - 1.0).abs() < f64::EPSILON);
        tb.try_consume(0, 250, 50).unwrap();
        let r2 = tb.ratio_0_to_1();
        assert!((r2 - 0.75).abs() < f64::EPSILON);
    }

    #[test]
    fn throttle_ratio_min_of_events_and_bytes() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(Some(100), Some(1000));
        tb.try_consume(50, 0, 50).unwrap(); // events 50/100=0.5, bytes 1000/1000=1.0
        let r = tb.ratio_0_to_1();
        assert!((r - 0.5).abs() < f64::EPSILON); // min(0.5, 1.0)
    }

    // ── ThrottleTokenBucket: zero consume succeeds ───────────────────

    #[test]
    fn throttle_zero_consume_succeeds() {
        let mut tb = super::ThrottleTokenBucket::default();
        tb.update_config(Some(100), Some(100));
        assert!(tb.try_consume(0, 0, 50).is_ok());
    }

    // ── gate_receipt_subject_mode_v1: non-verified passthrough ────────

    #[test]
    fn gate_receipt_subject_mode_non_verified_passthrough() {
        for mode in &["audit", "light", "unknown", ""] {
            assert_eq!(
                gate_receipt_subject_mode_v1(mode, b"any", None),
                mode.to_string()
            );
        }
    }

    // ── ReplicationApplyResult: serde round-trip ───────────────────────

    #[test]
    fn replication_apply_result_serde_round_trip() {
        let result = super::ReplicationApplyResult {
            shard_id: "shard-test".to_string(),
            epoch: 3,
            segment_seq: 10,
            segment_hash_hex: "deadbeef".to_string(),
            file_len: 4096,
            applied: false,
        };
        let json = serde_json::to_string(&result).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["applied"], false);
        assert_eq!(val["fileLen"], 4096);
        assert_eq!(val["shardId"], "shard-test");
    }

    // ── ReplicationSegmentPayload fields ─────────────────────────────

    #[test]
    fn replication_segment_payload_field_access() {
        let payload = super::ReplicationSegmentPayload {
            segment_seq: 5,
            segment_hash_hex: "abc".to_string(),
            bytes: vec![0u8; 16],
        };
        assert_eq!(payload.segment_seq, 5);
        assert_eq!(payload.segment_hash_hex, "abc");
        assert_eq!(payload.bytes.len(), 16);
    }

    // ── bypass_valve_gate: exhaustive cases ──────────────────────────

    #[test]
    fn bypass_valve_gate_system_non_corecrux_blocked() {
        assert!(!bypass_valve_gate_for_internal_stream("system", "ops"));
        assert!(!bypass_valve_gate_for_internal_stream("system", "routing"));
    }

    // ── ReadAmpTracker: cap=1 always returns same value ──────────────

    #[test]
    fn read_amp_cap_one() {
        let mut tracker = super::ReadAmpTracker::new(1);
        let (p50, p95) = tracker.record(10);
        assert_eq!(p50, 10.0);
        assert_eq!(p95, 10.0);
        let (p50_2, p95_2) = tracker.record(20);
        assert_eq!(p50_2, 20.0);
        assert_eq!(p95_2, 20.0);
    }

    // ── TailCacheKey: different streams ──────────────────────────────

    #[test]
    fn tail_cache_different_streams_independent() {
        let mut cache = super::TailCache::new(1024 * 1024);
        let events = vec![make_stored_event("e1")];
        cache.put("t", "s1", "i1", 10, &events);
        cache.put("t", "s2", "i2", 10, &events);
        assert!(cache.get("t", "s1", "i1", 10).is_some());
        assert!(cache.get("t", "s2", "i2", 10).is_some());
        cache.invalidate_stream("t", "s1", "i1");
        assert!(cache.get("t", "s1", "i1", 10).is_none());
        assert!(cache.get("t", "s2", "i2", 10).is_some());
    }
}
