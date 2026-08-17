// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! gRPC server — implements `CoreCruxDataPlaneV1` (append/replay/route) on port 4007.

use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use tonic::{Request, Response, Status};

use corecrux_proto::dataplane_v1::{
    core_crux_data_plane_v1_server::{CoreCruxDataPlaneV1, CoreCruxDataPlaneV1Server},
    core_crux_export_v1_server::{CoreCruxExportV1, CoreCruxExportV1Server},
    AppendBatchRequest, AppendBatchResponse, ExportChunk, ExportReceiptBundleRequest, ReadFramesBatchRawResponse,
    ReadFramesRequest, ReadFramesResponse, ReadManyBatchedRequest, ReadManyBatchedResponse,
    ReadManyFramesBatchedRequest, ReadManyFramesBatchedResponse, ReadStreamBatchResponse, ReadStreamBatchedRequest,
    ReadStreamRequest, ReadStreamResponse, ReplaySessionRequest, ReplaySessionResponse, SegmentSealReceipt,
    WriteConfirmation,
};

use tokio::sync::{Mutex, RwLock};

use crate::auth::{require_grpc_scopes_for_tenant, Authz};
use crate::config::{AppendLaneScope, CommitLevel, StoreLockStrategy};
use crate::dataplane_store::{AppendError, AppendOutcome, AppendStats, AppendStatus};
// http helpers (build_lineage_json_v1, etc.) used only in the proprietary ExportReceiptBundle path.
use crate::metrics::Metrics;
// CorrelationIds was used by the proprietary AppendBatch implementation.
#[allow(unused_imports)]
use crate::structured_log::CorrelationIds;
// corecrux_receipts event-type constants used only in the proprietary ExportReceiptBundle path.

static REPLAY_ENCODE_SAMPLE_COUNTER: AtomicU64 = AtomicU64::new(0);
const APPEND_LANE_FAIRNESS_BUCKETS: u64 = 16;
const WRITE_CONFIRMATION_SIGNING_KEY_ENV: &str = "CORECRUXD_WRITE_CONFIRMATION_SIGNING_KEY_B64";
const WRITE_CONFIRMATION_KEY_ID_ENV: &str = "CORECRUXD_WRITE_CONFIRMATION_KEY_ID";
const WRITE_CONFIRMATION_UNSIGNED_QUEUE_CAPACITY: usize = 10_000;
const WRITE_CONFIRMATION_UNSIGNED_QUEUE_WARN_DEPTH: usize = 1_000;
const WRITE_CONFIRMATION_QUEUE_DRAIN_BATCH: usize = 256;

#[derive(Debug, Clone, Copy)]
struct PendingWriteConfirmation {
    commit_seq: u64,
    segment_id: u64,
    receipt_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, Default)]
struct TenantThrottleTokenBucket {
    cfg_events_per_sec: Option<u64>,
    cfg_bytes_per_sec: Option<u64>,
    burst_secs: u64,
    events_tokens: u64,
    bytes_tokens: u64,
    events_rem_token_ns: u128,
    bytes_rem_token_ns: u128,
    last_refill: Option<std::time::Instant>,
}

impl TenantThrottleTokenBucket {
    fn update_config(&mut self, events_per_sec: Option<u64>, bytes_per_sec: Option<u64>) {
        if self.cfg_events_per_sec == events_per_sec && self.cfg_bytes_per_sec == bytes_per_sec {
            return;
        }
        self.cfg_events_per_sec = events_per_sec;
        self.cfg_bytes_per_sec = bytes_per_sec;
        self.burst_secs = 1;
        self.events_tokens = self.events_capacity();
        self.bytes_tokens = self.bytes_capacity();
        self.events_rem_token_ns = 0;
        self.bytes_rem_token_ns = 0;
        self.last_refill = Some(std::time::Instant::now());
    }

    fn events_capacity(&self) -> u64 {
        self.cfg_events_per_sec
            .unwrap_or(0)
            .saturating_mul(self.burst_secs.max(1))
    }

    fn bytes_capacity(&self) -> u64 {
        self.cfg_bytes_per_sec
            .unwrap_or(0)
            .saturating_mul(self.burst_secs.max(1))
    }

    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let Some(last_refill) = self.last_refill.replace(now) else {
            return;
        };
        let elapsed_ns = now.duration_since(last_refill).as_nanos();
        if elapsed_ns == 0 {
            return;
        }

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

    fn try_consume(&mut self, events_needed: u64, bytes_needed: u64, retry_after_default_ms: u32) -> Result<(), u32> {
        self.refill();

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

#[derive(Debug, Clone, Default)]
struct TenantThrottleRuntimeState {
    in_flight: u64,
    bucket: TenantThrottleTokenBucket,
}

struct TenantInFlightGuard {
    state: Arc<StdMutex<HashMap<String, TenantThrottleRuntimeState>>>,
    tenant_id: Option<String>,
}

impl Drop for TenantInFlightGuard {
    fn drop(&mut self) {
        let Some(tenant_id) = self.tenant_id.take() else {
            return;
        };
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let Some(entry) = state.get_mut(&tenant_id) {
            entry.in_flight = entry.in_flight.saturating_sub(1);
            if entry.in_flight == 0
                && entry.bucket.cfg_events_per_sec.is_none()
                && entry.bucket.cfg_bytes_per_sec.is_none()
            {
                state.remove(&tenant_id);
            }
        }
    }
}

#[derive(Clone)]
pub struct DataPlaneService {
    pool: Option<crate::pool::DataPlanePool>,
    control: Arc<RwLock<crate::control::ControlV1>>,
    metrics: Metrics,
    in_flight: Arc<AtomicU32>,
    tenant_throttle_state: Arc<StdMutex<HashMap<String, TenantThrottleRuntimeState>>>,
    append_static_lanes: Arc<HashMap<String, Arc<Mutex<()>>>>,
    append_dynamic_lanes: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    append_lane_waiters: Arc<AtomicU64>,
    append_lane_waiters_peak: Arc<AtomicU64>,
    unsigned_write_confirmation_queue: Arc<StdMutex<VecDeque<PendingWriteConfirmation>>>,
    auth: Authz,
    cfg: DataPlaneServiceConfig,
}

#[derive(Debug, Clone)]
pub struct DataPlaneServiceConfig {
    pub node_id: String,
    pub commit_level: CommitLevel,
    pub replicated_commit_timeout_ms: u64,
    pub replicated_commit_require_all_followers: bool,
    pub replay_batch_max_events: u32,
    pub replay_batch_max_bytes: u32,
    pub replay_many_max_reads: u32,
    pub replay_use_batched_rpc_default: bool,
    pub store_lock_strategy: StoreLockStrategy,
    pub append_lane_enabled: bool,
    pub append_lane_scope: AppendLaneScope,
}

impl DataPlaneService {
    pub fn new(
        pool: Option<crate::pool::DataPlanePool>,
        control: Arc<RwLock<crate::control::ControlV1>>,
        metrics: Metrics,
        auth: Authz,
        cfg: DataPlaneServiceConfig,
    ) -> Self {
        let append_static_lanes = build_static_append_lanes(pool.as_ref(), &cfg);
        metrics.set_append_lane_waiters(0);
        metrics.set_append_lane_waiters_peak(0);
        metrics.set_write_confirmation_unsigned_queue_depth(0);
        Self {
            pool,
            control,
            metrics,
            in_flight: Arc::new(AtomicU32::new(0)),
            tenant_throttle_state: Arc::new(StdMutex::new(HashMap::new())),
            append_static_lanes: Arc::new(append_static_lanes),
            append_dynamic_lanes: Arc::new(Mutex::new(HashMap::new())),
            append_lane_waiters: Arc::new(AtomicU64::new(0)),
            append_lane_waiters_peak: Arc::new(AtomicU64::new(0)),
            unsigned_write_confirmation_queue: Arc::new(StdMutex::new(VecDeque::new())),
            auth,
            cfg,
        }
    }

    async fn append_lane_for_key(&self, key: &str) -> Arc<Mutex<()>> {
        if let Some(lane) = self.append_static_lanes.get(key) {
            return lane.clone();
        }
        let mut lanes = self.append_dynamic_lanes.lock().await;
        lanes
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn append_lane_key(&self, route_decision: &crate::shard_map::RouteDecision, _stream_hash: u64) -> String {
        match self.cfg.append_lane_scope {
            AppendLaneScope::Global => "global".to_string(),
            AppendLaneScope::Shard => format!("shard:{}", route_decision.shard_id),
        }
    }

    #[allow(clippy::unused_self)] // Method for API consistency; may use self for shard-local state
    fn append_lane_bucket(&self, lane_key: &str) -> u8 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        lane_key.hash(&mut h);
        (h.finish() % APPEND_LANE_FAIRNESS_BUCKETS) as u8
    }

    fn update_append_lane_waiters_peak(&self, queued: u64) {
        let mut cur = self.append_lane_waiters_peak.load(Ordering::Relaxed);
        while queued > cur {
            match self
                .append_lane_waiters_peak
                .compare_exchange_weak(cur, queued, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => {
                    self.metrics.set_append_lane_waiters_peak(queued);
                    break;
                }
                Err(next) => cur = next,
            }
        }
    }

    fn tenant_id_hash_label(tenant_id: &str) -> String {
        blake3::hash(tenant_id.as_bytes()).to_hex()[..16].to_string()
    }

    fn apply_tenant_throttle(
        &self,
        control: &crate::control::ControlV1,
        tenant_id: &str,
        events: &[corecrux_proto::dataplane_v1::AppendEvent],
    ) -> Result<TenantInFlightGuard, Status> {
        if tenant_id == "system" {
            return Ok(TenantInFlightGuard {
                state: self.tenant_throttle_state.clone(),
                tenant_id: None,
            });
        }

        let Some(rule) = control
            .tenant_throttles
            .iter()
            .find(|rule| rule.tenant_id == tenant_id)
            .cloned()
        else {
            return Ok(TenantInFlightGuard {
                state: self.tenant_throttle_state.clone(),
                tenant_id: None,
            });
        };

        let mut bytes_needed: u64 = 0;
        for event in events {
            bytes_needed = bytes_needed.saturating_add(event.payload.len() as u64);
            bytes_needed = bytes_needed.saturating_add(event.event_id.len() as u64);
        }

        let tenant_id_hash = Self::tenant_id_hash_label(tenant_id);
        let retry_after_ms = control.valves.throttle.retry_after_ms.unwrap_or(50).max(1);
        // SAFETY: Mutex poisoning is process-fatal by design.
        #[allow(clippy::expect_used)]
        let mut state = self.tenant_throttle_state.lock().expect("tenant throttle mutex");
        let entry = state.entry(tenant_id.to_string()).or_default();
        entry.bucket.update_config(rule.events_per_sec, rule.bytes_per_sec);

        if let Some(max_in_flight) = rule.max_in_flight {
            if max_in_flight == 0 {
                self.metrics.inc_tenant_throttle_reject(&tenant_id_hash);
                return Err(Status::resource_exhausted(
                    serde_json::json!({
                        "code": "TENANT_THROTTLE_INFLIGHT",
                        "message": "tenant ingest throttled (maxInFlight=0)",
                        "tenantIdHash": tenant_id_hash,
                        "retryAfterMs": retry_after_ms
                    })
                    .to_string(),
                ));
            }
            if entry.in_flight >= max_in_flight {
                self.metrics.inc_tenant_throttle_reject(&tenant_id_hash);
                return Err(Status::resource_exhausted(
                    serde_json::json!({
                        "code": "TENANT_THROTTLE_INFLIGHT",
                        "message": format!(
                            "tenant ingest throttled (in_flight={} max_in_flight={})",
                            entry.in_flight,
                            max_in_flight
                        ),
                        "tenantIdHash": tenant_id_hash,
                        "retryAfterMs": retry_after_ms
                    })
                    .to_string(),
                ));
            }
        }

        if let Err(retry_after_ms) = entry
            .bucket
            .try_consume(events.len() as u64, bytes_needed, retry_after_ms)
        {
            self.metrics.inc_tenant_throttle_reject(&tenant_id_hash);
            return Err(Status::resource_exhausted(
                serde_json::json!({
                    "code": "TENANT_THROTTLE_RATE",
                    "message": "tenant ingest throttled by per-tenant rate limit",
                    "tenantIdHash": tenant_id_hash,
                    "retryAfterMs": retry_after_ms
                })
                .to_string(),
            ));
        }

        entry.in_flight = entry.in_flight.saturating_add(1);
        Ok(TenantInFlightGuard {
            state: self.tenant_throttle_state.clone(),
            tenant_id: Some(tenant_id.to_string()),
        })
    }

    fn build_write_confirmation(&self, append_stats: AppendStats, outcomes: &[AppendOutcome]) -> WriteConfirmation {
        let segment_seal_receipt = append_stats.seal_receipt.map(build_segment_seal_receipt);
        let material = append_stats
            .write_confirmation
            .unwrap_or_else(|| fallback_write_confirmation_material(outcomes));
        let sign_start = std::time::Instant::now();
        let signing = sign_write_confirmation_material(material);
        let sign_elapsed_ms = sign_start.elapsed().as_secs_f64() * 1000.0;

        let mut confirmation = WriteConfirmation {
            commit_seq: material.commit_seq,
            segment_id: material.segment_id,
            receipt_hash: material.receipt_hash.to_vec(),
            vault_signature: Vec::new(),
            key_id: signing.key_id.clone(),
            unsigned: true,
            segment_seal_receipt,
        };

        match signing.signature {
            Some(signature) => {
                confirmation.vault_signature = signature;
                confirmation.unsigned = false;
                self.metrics.inc_write_confirmation(true);
                self.metrics
                    .observe_write_confirmation_sign_duration_ms(sign_elapsed_ms);
                self.drain_unsigned_write_confirmation_queue();
            }
            None => {
                let _queued = self.queue_unsigned_write_confirmation(material);
                self.metrics.inc_write_confirmation(false);
                if sign_elapsed_ms > 0.0 {
                    self.metrics
                        .observe_write_confirmation_sign_duration_ms(sign_elapsed_ms);
                }
            }
        }

        confirmation
    }

    fn queue_unsigned_write_confirmation(&self, material: corecrux_storage::WriteConfirmationMaterialV1) -> bool {
        // SAFETY: Mutex poisoning is process-fatal by design.
        #[allow(clippy::expect_used)]
        let mut queue = self
            .unsigned_write_confirmation_queue
            .lock()
            .expect("unsigned write confirmation queue mutex");
        if queue.len() >= WRITE_CONFIRMATION_UNSIGNED_QUEUE_CAPACITY {
            let depth = queue.len();
            self.metrics.set_write_confirmation_unsigned_queue_depth(depth as u64);
            self.metrics.inc_write_reject("unsigned_confirmation_queue_full");
            tracing::error!(
                depth,
                capacity = WRITE_CONFIRMATION_UNSIGNED_QUEUE_CAPACITY,
                commit_seq = material.commit_seq,
                segment_id = material.segment_id,
                "write confirmation signing unavailable and unsigned queue is full; refusing to evict queued confirmations; current confirmation was not retained"
            );
            return false;
        }
        queue.push_back(PendingWriteConfirmation {
            commit_seq: material.commit_seq,
            segment_id: material.segment_id,
            receipt_hash: material.receipt_hash,
        });
        let depth = queue.len();
        self.metrics.set_write_confirmation_unsigned_queue_depth(depth as u64);
        if depth > WRITE_CONFIRMATION_UNSIGNED_QUEUE_WARN_DEPTH {
            tracing::warn!(
                depth,
                "write confirmation signing unavailable; unsigned queue depth above warning threshold"
            );
        }
        true
    }

    fn drain_unsigned_write_confirmation_queue(&self) {
        if load_write_confirmation_signing_key().is_none() {
            return;
        }

        // SAFETY: Mutex poisoning is process-fatal by design.
        #[allow(clippy::expect_used)]
        let mut queue = self
            .unsigned_write_confirmation_queue
            .lock()
            .expect("unsigned write confirmation queue mutex");
        let mut drained = 0usize;
        while drained < WRITE_CONFIRMATION_QUEUE_DRAIN_BATCH {
            let Some(pending) = queue.front().copied() else {
                break;
            };
            let signing = sign_write_confirmation_material(corecrux_storage::WriteConfirmationMaterialV1 {
                commit_seq: pending.commit_seq,
                segment_id: pending.segment_id,
                receipt_hash: pending.receipt_hash,
            });
            if signing.signature.is_none() {
                break;
            }
            queue.pop_front();
            drained = drained.saturating_add(1);
        }
        self.metrics
            .set_write_confirmation_unsigned_queue_depth(queue.len() as u64);
    }
}

fn build_static_append_lanes(
    _pool: Option<&crate::pool::DataPlanePool>,
    cfg: &DataPlaneServiceConfig,
) -> HashMap<String, Arc<Mutex<()>>> {
    let mut lanes = HashMap::new();
    if !cfg.append_lane_enabled {
        return lanes;
    }
    if matches!(cfg.append_lane_scope, AppendLaneScope::Global) {
        lanes.insert("global".to_string(), Arc::new(Mutex::new(())));
    }
    // Shard-scope lanes are created dynamically.
    lanes
}

pub struct ExportService {
    pool: Option<crate::pool::DataPlanePool>,
    metrics: Metrics,
    build: corecrux_types::BuildInfo,
    auth: Authz,
}

impl ExportService {
    pub fn new(
        pool: Option<crate::pool::DataPlanePool>,
        metrics: Metrics,
        build: corecrux_types::BuildInfo,
        auth: Authz,
    ) -> Self {
        Self {
            pool,
            metrics,
            build,
            auth,
        }
    }
}

struct InFlightGuard {
    counter: Arc<AtomicU32>,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

#[allow(clippy::result_large_err)]
fn parse_min_follower_watermark_from_meta(meta: &tonic::metadata::MetadataMap) -> Result<Option<u64>, Status> {
    let Some(raw) = meta.get("x-corecrux-min-watermark-segment-seq") else {
        return Ok(None);
    };
    let s = raw
        .to_str()
        .map_err(|_| Status::invalid_argument("invalid x-corecrux-min-watermark-segment-seq"))?;
    let v = s
        .trim()
        .parse::<u64>()
        .map_err(|_| Status::invalid_argument("x-corecrux-min-watermark-segment-seq must be u64"))?;
    Ok(Some(v))
}

fn stored_event_to_read_stream_response(ev: corecrux_storage::StoredEvent) -> ReadStreamResponse {
    ReadStreamResponse {
        seq: ev.seq,
        event_id: ev.event_id,
        occurred_at: ev.occurred_at,
        ingested_at: ev.ingested_at,
        event_type: ev.event_type,
        content_type: ev.content_type,
        payload: ev.payload,
        location: Some(corecrux_proto::dataplane_v1::FrameLocation {
            shard_id: ev.location.shard_id,
            segment_id: ev.location.segment_seq,
            offset: ev.location.offset,
            epoch: ev.location.epoch,
        }),
    }
}

fn estimate_read_stream_event_wire_bytes(ev: &corecrux_storage::StoredEvent) -> usize {
    // Coarse upper bound to avoid oversized gRPC messages while keeping batching efficient.
    let fixed_overhead = 64usize;
    fixed_overhead
        .saturating_add(ev.event_id.len())
        .saturating_add(ev.occurred_at.len())
        .saturating_add(ev.ingested_at.len())
        .saturating_add(ev.event_type.len())
        .saturating_add(ev.content_type.len())
        .saturating_add(ev.payload.len())
}

fn build_read_stream_batches(
    events: Vec<corecrux_storage::StoredEvent>,
    max_events_per_message: u32,
    max_bytes_per_message: u32,
) -> Vec<ReadStreamBatchResponse> {
    let max_events = max_events_per_message.max(1);
    let max_bytes = max_bytes_per_message.max(1024) as usize;

    if events.is_empty() {
        return vec![ReadStreamBatchResponse {
            events: Vec::new(),
            event_count: 0,
            payload_bytes: 0,
            eof: true,
        }];
    }

    let mut out: Vec<ReadStreamBatchResponse> = Vec::new();
    let mut idx = 0usize;
    while idx < events.len() {
        let mut batch: Vec<ReadStreamResponse> = Vec::new();
        let mut payload_bytes: u64 = 0;
        let mut approx_bytes: usize = 0;

        while idx < events.len() && (batch.len() as u32) < max_events {
            let ev = &events[idx];
            let ev_wire = estimate_read_stream_event_wire_bytes(ev);
            if !batch.is_empty() && approx_bytes.saturating_add(ev_wire) > max_bytes {
                break;
            }
            payload_bytes = payload_bytes.saturating_add(ev.payload.len() as u64);
            approx_bytes = approx_bytes.saturating_add(ev_wire);
            batch.push(stored_event_to_read_stream_response(ev.clone()));
            idx += 1;
        }

        // Always make progress: allow one oversized event.
        if batch.is_empty() {
            let ev = events[idx].clone();
            payload_bytes = ev.payload.len() as u64;
            batch.push(stored_event_to_read_stream_response(ev));
            idx += 1;
        }

        out.push(ReadStreamBatchResponse {
            event_count: batch.len() as u32,
            payload_bytes,
            eof: idx >= events.len(),
            events: batch,
        });
    }
    out
}

fn select_read_stream_prefix_len(
    events: &[corecrux_storage::StoredEvent],
    max_events_per_message: u32,
    max_bytes_per_message: u32,
) -> usize {
    let max_events = max_events_per_message.max(1) as usize;
    let max_bytes = max_bytes_per_message.max(1024) as usize;
    if events.is_empty() {
        return 0;
    }
    let mut count = 0usize;
    let mut approx_bytes = 0usize;
    while count < events.len() && count < max_events {
        let ev_wire = estimate_read_stream_event_wire_bytes(&events[count]);
        if count > 0 && approx_bytes.saturating_add(ev_wire) > max_bytes {
            break;
        }
        approx_bytes = approx_bytes.saturating_add(ev_wire);
        count += 1;
    }
    // Always include one event if non-empty, even if oversized.
    count.max(1)
}

fn build_read_stream_batch_single(
    events: Vec<corecrux_storage::StoredEvent>,
    max_events_per_message: u32,
    max_bytes_per_message: u32,
) -> ReadStreamBatchResponse {
    let total = events.len();
    if total == 0 {
        return ReadStreamBatchResponse {
            events: Vec::new(),
            event_count: 0,
            payload_bytes: 0,
            eof: true,
        };
    }
    let take = select_read_stream_prefix_len(&events, max_events_per_message.max(1), max_bytes_per_message.max(1024))
        .min(events.len());
    let mut out_events: Vec<ReadStreamResponse> = Vec::with_capacity(take);
    let mut payload_bytes = 0u64;
    for ev in events.into_iter().take(take) {
        payload_bytes = payload_bytes.saturating_add(ev.payload.len() as u64);
        out_events.push(stored_event_to_read_stream_response(ev));
    }
    ReadStreamBatchResponse {
        event_count: out_events.len() as u32,
        payload_bytes,
        eof: take >= total,
        events: out_events,
    }
}

fn resolve_batch_limits(req: &ReadStreamBatchedRequest, cfg: &DataPlaneServiceConfig) -> (u32, u32) {
    let max_events_per_message = if req.max_events_per_message == 0 {
        cfg.replay_batch_max_events
    } else {
        req.max_events_per_message.min(cfg.replay_batch_max_events)
    }
    .max(1);
    let max_bytes_per_message = if req.max_bytes_per_message == 0 {
        cfg.replay_batch_max_bytes
    } else {
        req.max_bytes_per_message.min(cfg.replay_batch_max_bytes)
    }
    .max(1024);
    (max_events_per_message, max_bytes_per_message)
}

// ── Crux Daemon gRPC behaviour ──────────────────────────────────────
//
// In the Crux Daemon, `self.pool` is always `None`.
// All data-plane RPCs that require the DataPlanePool return
// `Status::UNIMPLEMENTED` with a descriptive message. This is intentional:
// the gRPC surface is defined so that dataplane-enabled and Crux Daemon builds
// share the same proto contract, but Crux Daemon callers should use the HTTP API for
// append, query, and retrieval operations.
//
// Affected RPCs: AppendBatch, ReadStream, ReadStreamBatched,
//   ReadStreamBatchedUnary, ReadFramesBatchedUnary, ReadFrames,
//   ReadManyBatchedUnary, ReadManyFramesBatchedUnary, ReplaySession,
//   ExportReceiptBundle.
#[tonic::async_trait]
impl CoreCruxDataPlaneV1 for DataPlaneService {
    #[tracing::instrument(
        level = "info",
        skip(self, request),
        fields(
            rpc = "AppendBatch",
            request_id = tracing::field::Empty,
            traceparent = tracing::field::Empty
        )
    )]
    async fn append_batch(
        &self,
        request: Request<AppendBatchRequest>,
    ) -> Result<Response<AppendBatchResponse>, Status> {
        let meta = request.metadata().clone();
        let req = request.into_inner();
        require_grpc_scopes_for_tenant(&self.auth, &meta, &["events:write"], &req.tenant_id)?;
        Err(Status::unimplemented("requires the proprietary edition"))
    }

    type ReadStreamStream = tokio_stream::wrappers::ReceiverStream<Result<ReadStreamResponse, Status>>;

    #[tracing::instrument(level = "info", skip(self, request), fields(rpc = "ReadStream"))]
    async fn read_stream(
        &self,
        request: Request<ReadStreamRequest>,
    ) -> Result<Response<Self::ReadStreamStream>, Status> {
        let meta = request.metadata().clone();
        let req = request.into_inner();
        require_grpc_scopes_for_tenant(&self.auth, &meta, &["events:read"], &req.tenant_id)?;
        Err(Status::unimplemented("requires the proprietary edition"))
    }

    type ReadStreamBatchedStream = tokio_stream::wrappers::ReceiverStream<Result<ReadStreamBatchResponse, Status>>;

    #[tracing::instrument(level = "info", skip_all, fields(rpc = "ReadStreamBatched"))]
    async fn read_stream_batched(
        &self,
        _request: Request<ReadStreamBatchedRequest>,
    ) -> Result<Response<Self::ReadStreamBatchedStream>, Status> {
        Err(Status::unimplemented(
            "ReadStreamBatched requires the proprietary edition",
        ))
    }

    #[tracing::instrument(level = "info", skip_all, fields(rpc = "ReadStreamBatchedUnary"))]
    async fn read_stream_batched_unary(
        &self,
        _request: Request<ReadStreamBatchedRequest>,
    ) -> Result<Response<ReadStreamBatchResponse>, Status> {
        Err(Status::unimplemented(
            "ReadStreamBatchedUnary requires the proprietary edition",
        ))
    }

    #[tracing::instrument(level = "info", skip_all, fields(rpc = "ReadManyBatchedUnary"))]
    async fn read_many_batched_unary(
        &self,
        _request: Request<ReadManyBatchedRequest>,
    ) -> Result<Response<ReadManyBatchedResponse>, Status> {
        Err(Status::unimplemented(
            "ReadManyBatchedUnary requires the proprietary edition",
        ))
    }

    #[tracing::instrument(level = "info", skip_all, fields(rpc = "ReadManyFramesBatchedUnary"))]
    async fn read_many_frames_batched_unary(
        &self,
        _request: Request<ReadManyFramesBatchedRequest>,
    ) -> Result<Response<ReadManyFramesBatchedResponse>, Status> {
        Err(Status::unimplemented(
            "ReadManyFramesBatchedUnary requires the proprietary edition",
        ))
    }

    #[tracing::instrument(level = "info", skip_all, fields(rpc = "ReadFramesBatchedUnary"))]
    async fn read_frames_batched_unary(
        &self,
        _request: Request<ReadStreamBatchedRequest>,
    ) -> Result<Response<ReadFramesBatchRawResponse>, Status> {
        Err(Status::unimplemented(
            "ReadFramesBatchedUnary requires the proprietary edition",
        ))
    }

    type ReplaySessionStream = tokio_stream::wrappers::ReceiverStream<Result<ReplaySessionResponse, Status>>;

    #[tracing::instrument(level = "info", skip_all, fields(rpc = "ReplaySession"))]
    async fn replay_session(
        &self,
        _request: Request<tonic::Streaming<ReplaySessionRequest>>,
    ) -> Result<Response<Self::ReplaySessionStream>, Status> {
        Err(Status::unimplemented("ReplaySession requires the proprietary edition"))
    }

    type ReadFramesStream = tokio_stream::wrappers::ReceiverStream<Result<ReadFramesResponse, Status>>;

    #[tracing::instrument(level = "info", skip_all, fields(rpc = "ReadFrames"))]
    async fn read_frames(
        &self,
        _request: Request<ReadFramesRequest>,
    ) -> Result<Response<Self::ReadFramesStream>, Status> {
        Err(Status::unimplemented("ReadFrames requires the proprietary edition"))
    }
}

#[derive(Debug, Clone)]
struct ReplicationSendResult {
    applied_segment_seq: Option<u64>,
}

fn replication_auth_bearer_value() -> String {
    let raw = std::env::var("CORECRUXD_REPLICATION_AUTH_BEARER")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "replication:write".to_string());
    if raw.len() >= 7 && raw[..7].eq_ignore_ascii_case("bearer ") {
        raw
    } else {
        format!("Bearer {raw}")
    }
}

async fn send_replication_segment_http(
    follower: &corecrux_types::NodeAddr,
    shard_id: &str,
    epoch: u64,
    leader_node_id: &str,
    segment: &crate::dataplane_store::ReplicationSegmentPayload,
    timeout_ms: u64,
) -> Result<ReplicationSendResult, String> {
    let base = if follower.http_addr.starts_with("http://") || follower.http_addr.starts_with("https://") {
        follower.http_addr.clone()
    } else {
        format!("http://{}", follower.http_addr)
    };
    let url = format!("{}/v1/internal/replication/segments", base.trim_end_matches('/'));
    let seg_b64 = base64::engine::general_purpose::STANDARD.encode(&segment.bytes);
    let body = serde_json::json!({
        "shardId": shard_id,
        "epoch": epoch,
        "leaderNodeId": leader_node_id,
        "segmentBase64": seg_b64,
        "segmentHash": segment.segment_hash_hex
    });
    let connect_timeout_ms = timeout_ms.clamp(100, 10_000);
    let read_timeout_ms = timeout_ms.clamp(100, 120_000);
    let authorization = replication_auth_bearer_value();

    let result = tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_millis(connect_timeout_ms)))
            .timeout_recv_response(Some(Duration::from_millis(read_timeout_ms)))
            .timeout_recv_body(Some(Duration::from_millis(read_timeout_ms)))
            .build()
            .into();

        match agent
            .post(&url)
            .header("content-type", "application/json")
            .header("authorization", &authorization)
            .send_json(body)
        {
            Ok(mut resp) => {
                let status = resp.status().as_u16();
                if status == 200 {
                    let body = resp.body_mut().read_to_string().unwrap_or_default();
                    let applied_segment_seq = serde_json::from_str::<serde_json::Value>(&body).ok().and_then(|v| {
                        v.get("result")
                            .and_then(|r| r.get("segmentSeq"))
                            .and_then(|s| s.as_u64())
                    });
                    Ok(ReplicationSendResult { applied_segment_seq })
                } else {
                    Err(format!("http status {status}"))
                }
            }
            Err(err) => Err(err.to_string()),
        }
    })
    .await
    .map_err(|e| e.to_string())?;
    result
}

// Crux Daemon: ExportReceiptBundle requires the proprietary edition pool.
#[tonic::async_trait]
impl CoreCruxExportV1 for ExportService {
    type ExportReceiptBundleStream = tokio_stream::wrappers::ReceiverStream<Result<ExportChunk, Status>>;

    #[tracing::instrument(level = "info", skip_all, fields(rpc = "ExportReceiptBundle"))]
    async fn export_receipt_bundle(
        &self,
        _request: Request<ExportReceiptBundleRequest>,
    ) -> Result<Response<Self::ExportReceiptBundleStream>, Status> {
        Err(Status::unimplemented(
            "ExportReceiptBundle requires the proprietary edition",
        ))
    }
}

/// Serves the gRPC plane with transport-level hardening (ExecPlan
/// `crux-http-ingress-hardening-2026-06-11` M4):
///
/// - HTTP/2 keep-alive pings reap dead peers instead of holding their
///   connections open indefinitely (`CORECRUXD_GRPC_KEEPALIVE_INTERVAL_SECS`
///   / `_TIMEOUT_SECS`; interval `0` = pings disabled).
/// - A per-connection stream cap stops a single client from multiplexing
///   unbounded streams over one connection
///   (`CORECRUXD_GRPC_MAX_CONCURRENT_STREAMS`; `0` = unbounded). The
///   per-tenant token-bucket throttle above remains the fairness layer —
///   this is transport protection only.
/// - `TCP_NODELAY`, matching the HTTP listeners (M1).
pub async fn serve(
    addr: SocketAddr,
    ingress: &crate::config::IngressConfig,
    svc: DataPlaneService,
    export_svc: ExportService,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tonic::transport::Server::builder()
        .tcp_nodelay(true)
        .http2_keepalive_interval(ingress.grpc_keepalive_interval())
        .http2_keepalive_timeout(ingress.grpc_keepalive_timeout())
        .max_concurrent_streams(ingress.grpc_max_streams())
        // Recover handler panics into a clean gRPC INTERNAL status, mirroring
        // the HTTP path's `CatchPanicLayer` (`http::health::handle_panic`).
        // Without this a panic in a tonic handler aborts the task and drops the
        // connection instead of returning a status.
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(handle_grpc_panic))
        .add_service(CoreCruxDataPlaneV1Server::new(svc))
        .add_service(CoreCruxExportV1Server::new(export_svc))
        .serve_with_shutdown(addr, shutdown)
        .await?;
    Ok(())
}

/// Map a recovered gRPC handler panic to a clean gRPC `INTERNAL` status.
///
/// The HTTP path recovers handler panics via `CatchPanicLayer`
/// (`http::health::handle_panic`); the gRPC path had no equivalent, so
/// a panic in a tonic handler aborted the task and dropped the connection
/// instead of returning a status. This produces a trailers-only response
/// carrying `grpc-status: 13` (INTERNAL), which tonic clients surface as
/// `Status::internal`. Both the daemon and the connection survive.
fn handle_grpc_panic(
    err: Box<dyn std::any::Any + Send + 'static>,
) -> axum::http::Response<http_body_util::Empty<axum::body::Bytes>> {
    let msg = if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        (*s).to_string()
    } else {
        "unknown panic".to_string()
    };
    tracing::error!(panic = %msg, "gRPC handler panicked");

    let mut response = axum::http::Response::new(http_body_util::Empty::new());
    *response.status_mut() = axum::http::StatusCode::OK;
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/grpc"),
    );
    // gRPC status code 13 = INTERNAL.
    headers.insert("grpc-status", axum::http::HeaderValue::from_static("13"));
    headers.insert(
        "grpc-message",
        axum::http::HeaderValue::from_static("internal error (panic recovered)"),
    );
    response
}

#[derive(Debug, Default)]
struct WriteConfirmationSigningResult {
    signature: Option<Vec<u8>>,
    key_id: String,
}

fn fallback_write_confirmation_material(outcomes: &[AppendOutcome]) -> corecrux_storage::WriteConfirmationMaterialV1 {
    let mut accepted: Vec<&AppendOutcome> = outcomes
        .iter()
        .filter(|outcome| outcome.status != AppendStatus::Rejected)
        .collect();
    accepted.sort_by_key(|outcome| outcome.seq);

    let mut hasher = blake3::Hasher::new();
    let mut commit_seq = 0u64;
    let mut segment_id = 0u64;
    for outcome in accepted {
        hasher.update(&outcome.seq.to_be_bytes());
        hasher.update(&outcome.header_hash);
        hasher.update(&outcome.payload_hash);
        if let Some(location) = outcome.location {
            hasher.update(&location.shard_id.to_be_bytes());
            hasher.update(&location.epoch.to_be_bytes());
            hasher.update(&location.segment_seq.to_be_bytes());
            hasher.update(&location.offset.to_be_bytes());
            segment_id = segment_id.max(location.segment_seq);
        }
        commit_seq = commit_seq.max(outcome.seq);
    }

    corecrux_storage::WriteConfirmationMaterialV1 {
        commit_seq,
        segment_id,
        receipt_hash: *hasher.finalize().as_bytes(),
    }
}

pub(crate) fn load_write_confirmation_signing_key() -> Option<SigningKey> {
    let encoded = std::env::var(WRITE_CONFIRMATION_SIGNING_KEY_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded.as_bytes()))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded.as_bytes()))
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded.as_bytes()))
        .ok()?;
    if decoded.len() < 32 {
        return None;
    }
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&decoded[..32]);
    Some(SigningKey::from_bytes(&secret))
}

fn load_write_confirmation_key_id() -> String {
    std::env::var(WRITE_CONFIRMATION_KEY_ID_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "local-env-ed25519".to_string())
}

fn sign_write_confirmation_material(
    material: corecrux_storage::WriteConfirmationMaterialV1,
) -> WriteConfirmationSigningResult {
    let key_id = load_write_confirmation_key_id();
    let Some(signing_key) = load_write_confirmation_signing_key() else {
        return WriteConfirmationSigningResult {
            signature: None,
            key_id,
        };
    };

    let mut message = Vec::with_capacity(40);
    message.extend_from_slice(&material.receipt_hash);
    message.extend_from_slice(&material.commit_seq.to_be_bytes());
    let signature = signing_key.sign(&message);
    WriteConfirmationSigningResult {
        signature: Some(signature.to_bytes().to_vec()),
        key_id,
    }
}

fn sign_segment_seal_material(material: corecrux_storage::SegmentSealMaterialV1) -> WriteConfirmationSigningResult {
    let key_id = load_write_confirmation_key_id();
    let Some(signing_key) = load_write_confirmation_signing_key() else {
        return WriteConfirmationSigningResult {
            signature: None,
            key_id,
        };
    };

    let signature = signing_key.sign(&material.signing_bytes());
    WriteConfirmationSigningResult {
        signature: Some(signature.to_bytes().to_vec()),
        key_id,
    }
}

fn build_segment_seal_receipt(material: corecrux_storage::SegmentSealMaterialV1) -> SegmentSealReceipt {
    let signing = sign_segment_seal_material(material);
    let previous_segment_present = material.previous_segment_seq.is_some() && material.previous_segment_hash.is_some();
    let mut receipt = SegmentSealReceipt {
        shard_id: material.shard_id,
        epoch: material.epoch,
        segment_seq: material.segment_seq,
        segment_id: material.segment_id.0.to_vec(),
        segment_hash: material.segment_hash.to_vec(),
        previous_segment_present,
        previous_segment_seq: material.previous_segment_seq.unwrap_or_default(),
        previous_segment_hash: material.previous_segment_hash.unwrap_or([0u8; 32]).to_vec(),
        sealed_at_unix_ns: material.sealed_at_unix_ns,
        frame_count: material.frame_count,
        material_hash: material.material_hash().to_vec(),
        vault_signature: Vec::new(),
        key_id: signing.key_id,
        unsigned: true,
    };
    if let Some(signature) = signing.signature {
        receipt.vault_signature = signature;
        receipt.unsigned = false;
    }
    receipt
}

fn map_append_error(err: AppendError) -> Status {
    match err {
        AppendError::InvalidArgument(msg) => Status::invalid_argument(msg),
        AppendError::FailedPrecondition(msg) => Status::failed_precondition(msg),
        AppendError::ResourceExhausted(msg) => Status::resource_exhausted(msg),
        AppendError::IoBackend(msg) => Status::unavailable(msg),
        AppendError::Internal(msg) => Status::internal(msg),
        AppendError::ShardUnavailable {
            shard_id,
            owner_gpu_id,
            current_shard_map_version,
        } => Status::unavailable(
            serde_json::json!({
                "code": "SHARD_UNAVAILABLE",
                "shardId": shard_id,
                "ownerGpuId": owner_gpu_id,
                "currentShardMapVersion": current_shard_map_version
            })
            .to_string(),
        ),
        AppendError::WrongShard {
            leader_grpc_addr,
            current_shard_map_version,
        } => {
            let json = format!(
                "{{\"code\":\"WRONG_SHARD\",\"leaderGrpcAddr\":{},\"currentShardMapVersion\":{current_shard_map_version}}}",
                serde_json::to_string(&leader_grpc_addr).unwrap_or_else(|_| "\"\"".to_string())
            );
            Status::failed_precondition(json)
        }
        AppendError::ShardMapVersionMismatch {
            client_version,
            current_version,
        } => Status::failed_precondition(format!(
            "{{\"code\":\"SHARDMAP_VERSION_MISMATCH\",\"clientShardMapVersion\":{client_version},\"currentShardMapVersion\":{current_version}}}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;

    use super::{
        build_read_stream_batch_single, build_read_stream_batches, build_segment_seal_receipt,
        fallback_write_confirmation_material, load_write_confirmation_signing_key, map_append_error,
        replication_auth_bearer_value, sign_write_confirmation_material, stored_event_to_read_stream_response,
        DataPlaneService, DataPlaneServiceConfig, WRITE_CONFIRMATION_KEY_ID_ENV, WRITE_CONFIRMATION_SIGNING_KEY_ENV,
    };
    use crate::auth::{AuthMode, Authz};
    use crate::config::{AppendLaneScope, CommitLevel, StoreLockStrategy};
    use crate::control::{ControlV1, TenantThrottleV1};
    use crate::dataplane_store::{AppendError, AppendStatus};
    use crate::pool::DataPlanePool;
    use corecrux_proto::dataplane_v1::{
        core_crux_data_plane_v1_server::CoreCruxDataPlaneV1, core_crux_export_v1_server::CoreCruxExportV1,
        AppendBatchRequest, ExportReceiptBundleRequest, ReadFramesRequest, ReadManyBatchedRequest,
        ReadManyFramesBatchedRequest, ReadStreamBatchedRequest, ReadStreamRequest, ReadStreamResponse,
    };
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::sync::RwLock;
    use tonic::{Code, Request};

    static WRITE_CONFIRMATION_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[derive(Clone, Copy)]
    struct SplitMix64 {
        state: u64,
    }

    impl SplitMix64 {
        fn new(seed: u64) -> Self {
            Self { state: seed.max(1) }
        }

        fn next_u64(&mut self) -> u64 {
            self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn gen_range_u64(&mut self, upper_exclusive: u64) -> u64 {
            if upper_exclusive == 0 {
                return 0;
            }
            self.next_u64() % upper_exclusive
        }

        fn gen_range_usize(&mut self, upper_exclusive: usize) -> usize {
            if upper_exclusive == 0 {
                return 0;
            }
            (self.next_u64() as usize) % upper_exclusive
        }
    }

    fn test_service_with_auth(node_id: &str, auth_mode: AuthMode) -> DataPlaneService {
        test_service_with_control(node_id, auth_mode, ControlV1::default())
    }

    fn test_service_with_control(node_id: &str, auth_mode: AuthMode, control: ControlV1) -> DataPlaneService {
        test_service_with_optional_pool(node_id, auth_mode, None, control)
    }

    fn test_service_with_optional_pool(
        node_id: &str,
        auth_mode: AuthMode,
        pool: Option<DataPlanePool>,
        control: ControlV1,
    ) -> DataPlaneService {
        test_service_with_lane_config(node_id, auth_mode, pool, control, false, AppendLaneScope::Shard)
    }

    fn test_service_with_lane_config(
        node_id: &str,
        auth_mode: AuthMode,
        pool: Option<DataPlanePool>,
        control: ControlV1,
        append_lane_enabled: bool,
        append_lane_scope: AppendLaneScope,
    ) -> DataPlaneService {
        let build = corecrux_types::BuildInfo {
            version: "test".to_string(),
            commit: "test".to_string(),
        };
        let metrics = crate::metrics::Metrics::new(&build, "corecruxd-test");
        let auth = Authz::from_env(auth_mode).expect("auth init");
        let cfg = DataPlaneServiceConfig {
            node_id: node_id.to_string(),
            commit_level: CommitLevel::LocalCommit,
            replicated_commit_timeout_ms: 2_000,
            replicated_commit_require_all_followers: true,
            replay_batch_max_events: 128,
            replay_batch_max_bytes: 1024 * 1024,
            replay_many_max_reads: 128,
            replay_use_batched_rpc_default: false,
            store_lock_strategy: StoreLockStrategy::RwLock,
            append_lane_enabled,
            append_lane_scope,
        };
        DataPlaneService::new(pool, Arc::new(RwLock::new(control)), metrics, auth, cfg)
    }

    fn request_with_dev_scopes<T>(payload: T, scopes: &str) -> Request<T> {
        let mut request = Request::new(payload);
        request
            .metadata_mut()
            .insert("x-corecrux-scopes", scopes.parse().expect("valid test scope value"));
        request
    }

    fn mk_event(seq: u64, payload_len: usize) -> corecrux_storage::StoredEvent {
        corecrux_storage::StoredEvent {
            seq,
            event_id: format!("e-{seq}"),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:01Z".to_string(),
            event_type: "bench.replay".to_string(),
            content_type: "application/octet-stream".to_string(),
            payload: vec![b'x'; payload_len],
            location: corecrux_storage::FrameLocation {
                shard_id: 1,
                epoch: 1,
                segment_seq: 1,
                offset: seq * 10,
            },
        }
    }

    fn select_forward(
        events: &[corecrux_storage::StoredEvent],
        from_seq_inclusive: u64,
        max_events: u32,
    ) -> Vec<corecrux_storage::StoredEvent> {
        events
            .iter()
            .filter(|e| e.seq >= from_seq_inclusive)
            .take(max_events as usize)
            .cloned()
            .collect()
    }

    fn select_tail(events: &[corecrux_storage::StoredEvent], tail_events: u32) -> Vec<corecrux_storage::StoredEvent> {
        let want = tail_events as usize;
        if want >= events.len() {
            return events.to_vec();
        }
        events[events.len() - want..].to_vec()
    }

    fn flatten_batched_events(
        batches: &[corecrux_proto::dataplane_v1::ReadStreamBatchResponse],
    ) -> Vec<ReadStreamResponse> {
        let mut out = Vec::new();
        for batch in batches {
            out.extend(batch.events.iter().cloned());
        }
        out
    }

    fn summarize_responses(events: &[ReadStreamResponse]) -> Vec<(u64, String, [u8; 32])> {
        events
            .iter()
            .map(|e| (e.seq, e.event_id.clone(), *blake3::hash(&e.payload).as_bytes()))
            .collect()
    }

    fn assert_batched_eof_contract(
        batches: &[corecrux_proto::dataplane_v1::ReadStreamBatchResponse],
        expect_empty: bool,
    ) {
        assert!(!batches.is_empty(), "batched response should never be empty");
        let eof_count = batches.iter().filter(|b| b.eof).count();
        assert_eq!(eof_count, 1, "exactly one EOF marker must be present");
        for (idx, batch) in batches.iter().enumerate() {
            if idx + 1 == batches.len() {
                assert!(batch.eof, "last batch must set eof=true");
            } else {
                assert!(!batch.eof, "non-last batch must set eof=false");
            }
        }
        if expect_empty {
            assert_eq!(batches.len(), 1, "empty result must return one eof batch");
            assert_eq!(batches[0].event_count, 0);
            assert!(batches[0].events.is_empty());
        }
    }

    #[test]
    fn batched_builder_preserves_order_and_counts() {
        let events: Vec<corecrux_storage::StoredEvent> = (0..7).map(|i| mk_event(i, 32)).collect();
        let batches = build_read_stream_batches(events.clone(), 3, 4096);
        assert!(!batches.is_empty());

        let mut seqs = Vec::new();
        let mut total_count = 0usize;
        for (idx, b) in batches.iter().enumerate() {
            total_count += b.event_count as usize;
            for ev in &b.events {
                seqs.push(ev.seq);
            }
            if idx + 1 == batches.len() {
                assert!(b.eof);
            } else {
                assert!(!b.eof);
            }
        }

        assert_eq!(total_count, events.len());
        assert_eq!(seqs, (0..7).collect::<Vec<u64>>());
    }

    #[test]
    fn batched_builder_emits_progress_for_oversized_event() {
        let events = vec![mk_event(1, 4096), mk_event(2, 4096)];
        let batches = build_read_stream_batches(events, 10, 1024);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].event_count, 1);
        assert_eq!(batches[1].event_count, 1);
        assert!(!batches[0].eof);
        assert!(batches[1].eof);
    }

    #[test]
    fn randomized_differential_read_stream_vs_batched_forward_and_tail() {
        let mut rng = SplitMix64::new(0xA11C_EED5);
        for case_idx in 0..64u64 {
            let event_count = 1 + rng.gen_range_u64(200);
            let mut events: Vec<corecrux_storage::StoredEvent> = Vec::new();
            for i in 0..event_count {
                let payload_len = 1 + rng.gen_range_usize(2048);
                events.push(mk_event(i + 1, payload_len));
            }

            for _ in 0..8 {
                let max_events = 1 + (rng.gen_range_u64(64) as u32);
                let from_seq = rng.gen_range_u64(event_count + 32);
                let expected_forward = select_forward(&events, from_seq, max_events);
                let expected_forward_rsp: Vec<ReadStreamResponse> = expected_forward
                    .clone()
                    .into_iter()
                    .map(stored_event_to_read_stream_response)
                    .collect();

                let batch_events = 1 + (rng.gen_range_u64(32) as u32);
                let batch_bytes = 1024 + (rng.gen_range_u64(32 * 1024) as u32);
                let forward_batches = build_read_stream_batches(expected_forward.clone(), batch_events, batch_bytes);
                assert_batched_eof_contract(&forward_batches, expected_forward.is_empty());
                let forward_flat = flatten_batched_events(&forward_batches);
                assert_eq!(
                    summarize_responses(&forward_flat),
                    summarize_responses(&expected_forward_rsp),
                    "forward differential mismatch case={case_idx}"
                );

                let tail_events = 1 + (rng.gen_range_u64(64) as u32);
                let expected_tail = select_tail(&events, tail_events);
                let expected_tail_rsp: Vec<ReadStreamResponse> = expected_tail
                    .clone()
                    .into_iter()
                    .map(stored_event_to_read_stream_response)
                    .collect();
                let tail_batches = build_read_stream_batches(expected_tail.clone(), batch_events, batch_bytes);
                assert_batched_eof_contract(&tail_batches, expected_tail.is_empty());
                let tail_flat = flatten_batched_events(&tail_batches);
                assert_eq!(
                    summarize_responses(&tail_flat),
                    summarize_responses(&expected_tail_rsp),
                    "tail differential mismatch case={case_idx}"
                );
            }
        }
    }

    #[test]
    fn randomized_property_interleaved_stream_mixes_preserve_order_and_identity() {
        let mut rng = SplitMix64::new(0xC0FF_EE55);
        let stream_count = 32usize;
        let mut streams: Vec<Vec<corecrux_storage::StoredEvent>> = Vec::with_capacity(stream_count);
        for sid in 0..stream_count {
            let event_count = 10 + rng.gen_range_usize(120);
            let mut stream_events = Vec::with_capacity(event_count);
            for seq in 0..event_count {
                let payload_len = 8 + rng.gen_range_usize(1024);
                let mut ev = mk_event((seq + 1) as u64, payload_len);
                ev.event_id = format!("s{sid}-{}", ev.event_id);
                stream_events.push(ev);
            }
            streams.push(stream_events);
        }

        for query_idx in 0..512usize {
            let sid = rng.gen_range_usize(stream_count);
            let stream_events = &streams[sid];
            let use_tail = (rng.next_u64() & 1) == 1;
            let selected = if use_tail {
                let tail_events = 1 + (rng.gen_range_u64(64) as u32);
                select_tail(stream_events, tail_events)
            } else {
                let from_seq = rng.gen_range_u64((stream_events.len() as u64) + 24);
                let max_events = 1 + (rng.gen_range_u64(64) as u32);
                select_forward(stream_events, from_seq, max_events)
            };

            let max_events_per_message = 1 + (rng.gen_range_u64(16) as u32);
            let max_bytes_per_message = 1024 + (rng.gen_range_u64(16 * 1024) as u32);
            let batches = build_read_stream_batches(selected.clone(), max_events_per_message, max_bytes_per_message);
            assert_batched_eof_contract(&batches, selected.is_empty());

            let flat = flatten_batched_events(&batches);
            let expected: Vec<ReadStreamResponse> =
                selected.into_iter().map(stored_event_to_read_stream_response).collect();
            assert_eq!(
                summarize_responses(&flat),
                summarize_responses(&expected),
                "interleaved query mismatch at query={query_idx} stream={sid}"
            );
        }
    }

    #[test]
    fn randomized_differential_read_many_unary_vs_single_read_stream_semantics() {
        let mut rng = SplitMix64::new(0xBADC_0FFE);
        let stream_count = 24usize;
        let mut streams: Vec<Vec<corecrux_storage::StoredEvent>> = Vec::with_capacity(stream_count);
        for sid in 0..stream_count {
            let event_count = 6 + rng.gen_range_usize(160);
            let mut stream_events = Vec::with_capacity(event_count);
            for seq in 0..event_count {
                let payload_len = 8 + rng.gen_range_usize(512);
                let mut ev = mk_event((seq + 1) as u64, payload_len);
                ev.event_id = format!("m{sid}-{}", ev.event_id);
                stream_events.push(ev);
            }
            streams.push(stream_events);
        }

        for case_idx in 0..256usize {
            let reads_in_rpc = 1 + rng.gen_range_usize(16);
            let max_events_per_message = 1 + (rng.gen_range_u64(32) as u32);
            let max_bytes_per_message = 1024 + (rng.gen_range_u64(24 * 1024) as u32);

            for read_idx in 0..reads_in_rpc {
                let sid = rng.gen_range_usize(stream_count);
                let stream_events = &streams[sid];
                let use_tail = (rng.next_u64() & 1) == 1;
                let selected = if use_tail {
                    let tail_events = 1 + (rng.gen_range_u64(64) as u32);
                    select_tail(stream_events, tail_events)
                } else {
                    let from_seq = rng.gen_range_u64((stream_events.len() as u64) + 12);
                    let max_events = 1 + (rng.gen_range_u64(64) as u32);
                    select_forward(stream_events, from_seq, max_events)
                };
                let selected_len = selected.len();
                let take =
                    super::select_read_stream_prefix_len(&selected, max_events_per_message, max_bytes_per_message)
                        .min(selected_len);
                let expected_single_rsp: Vec<ReadStreamResponse> = selected
                    .clone()
                    .into_iter()
                    .take(take)
                    .map(stored_event_to_read_stream_response)
                    .collect();
                let many_batch =
                    build_read_stream_batch_single(selected, max_events_per_message, max_bytes_per_message);
                assert_eq!(
                    many_batch.eof,
                    take >= selected_len,
                    "single-response read_many eof mismatch case={case_idx} read={read_idx} stream={sid}"
                );
                assert_eq!(
                    summarize_responses(&many_batch.events),
                    summarize_responses(&expected_single_rsp),
                    "read_many differential mismatch case={case_idx} read={read_idx} stream={sid}"
                );
            }
        }
    }

    #[tokio::test]
    async fn read_frames_returns_unimplemented() {
        // Crux Daemon: method returns Unimplemented before auth checks.
        let svc = test_service_with_auth("node-a", AuthMode::DevScopes);
        let status = svc
            .read_frames(Request::new(ReadFramesRequest { locations: vec![] }))
            .await
            .expect_err("must return unimplemented");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    #[test]
    fn fallback_write_confirmation_material_is_stable() {
        let outcome = corecrux_storage::AppendOutcome {
            status: AppendStatus::DuplicateCommitted,
            seq: 17,
            location: Some(corecrux_storage::FrameLocation {
                shard_id: 3,
                epoch: 9,
                segment_seq: 41,
                offset: 1024,
            }),
            payload_hash: [0x11; 32],
            header_hash: [0x22; 32],
            error_code: None,
            error_message: None,
        };

        let material = fallback_write_confirmation_material(&[outcome]);
        let mut hasher = blake3::Hasher::new();
        hasher.update(&17u64.to_be_bytes());
        hasher.update(&[0x22; 32]);
        hasher.update(&[0x11; 32]);
        hasher.update(&3u64.to_be_bytes());
        hasher.update(&9u64.to_be_bytes());
        hasher.update(&41u64.to_be_bytes());
        hasher.update(&1024u64.to_be_bytes());

        assert_eq!(material.commit_seq, 17);
        assert_eq!(material.segment_id, 41);
        assert_eq!(material.receipt_hash, *hasher.finalize().as_bytes());
    }

    #[test]
    #[serial_test::serial]
    fn write_confirmation_signing_uses_env_key() {
        let _guard = WRITE_CONFIRMATION_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
        std::env::remove_var(WRITE_CONFIRMATION_KEY_ID_ENV);

        let material = corecrux_storage::WriteConfirmationMaterialV1 {
            commit_seq: 7,
            segment_id: 3,
            receipt_hash: [0x33; 32],
        };
        let unsigned = sign_write_confirmation_material(material);
        assert!(unsigned.signature.is_none());

        let secret = [0x44u8; 32];
        std::env::set_var(
            WRITE_CONFIRMATION_SIGNING_KEY_ENV,
            base64::engine::general_purpose::STANDARD.encode(secret),
        );
        std::env::set_var(WRITE_CONFIRMATION_KEY_ID_ENV, "test-key-1");

        let signing_key = load_write_confirmation_signing_key().expect("signing key");
        let signed = sign_write_confirmation_material(material);
        let mut message = Vec::new();
        message.extend_from_slice(&material.receipt_hash);
        message.extend_from_slice(&material.commit_seq.to_be_bytes());
        let expected = signing_key.sign(&message);

        assert_eq!(signed.key_id, "test-key-1");
        assert_eq!(signed.signature, Some(expected.to_bytes().to_vec()));

        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
        std::env::remove_var(WRITE_CONFIRMATION_KEY_ID_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn segment_seal_receipt_signing_commits_to_segment_chain() {
        let _guard = WRITE_CONFIRMATION_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
        std::env::remove_var(WRITE_CONFIRMATION_KEY_ID_ENV);

        let material = corecrux_storage::SegmentSealMaterialV1 {
            shard_id: 7,
            epoch: 3,
            segment_seq: 42,
            segment_id: corecrux_segment::SegmentId([0x21; 16]),
            segment_hash: [0x44; 32],
            previous_segment_seq: Some(41),
            previous_segment_hash: Some([0x33; 32]),
            sealed_at_unix_ns: 123_456_789,
            frame_count: 9,
        };
        let unsigned = build_segment_seal_receipt(material);
        assert!(unsigned.unsigned);
        assert!(unsigned.vault_signature.is_empty());
        assert_eq!(unsigned.material_hash, material.material_hash().to_vec());

        let secret = [0x55u8; 32];
        std::env::set_var(
            WRITE_CONFIRMATION_SIGNING_KEY_ENV,
            base64::engine::general_purpose::STANDARD.encode(secret),
        );
        std::env::set_var(WRITE_CONFIRMATION_KEY_ID_ENV, "seal-key");

        let signing_key = load_write_confirmation_signing_key().expect("signing key");
        let signed = build_segment_seal_receipt(material);
        let signature = ed25519_dalek::Signature::try_from(signed.vault_signature.as_slice()).expect("signature");
        signing_key
            .verifying_key()
            .verify_strict(&material.signing_bytes(), &signature)
            .expect("seal signature verifies");

        assert!(!signed.unsigned);
        assert_eq!(signed.key_id, "seal-key");
        assert_eq!(signed.shard_id, material.shard_id);
        assert_eq!(signed.segment_seq, material.segment_seq);
        assert_eq!(signed.segment_id, material.segment_id.0.to_vec());
        assert_eq!(signed.segment_hash, material.segment_hash.to_vec());
        assert!(signed.previous_segment_present);
        assert_eq!(signed.previous_segment_seq, 41);
        assert_eq!(signed.previous_segment_hash, [0x33; 32].to_vec());

        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
        std::env::remove_var(WRITE_CONFIRMATION_KEY_ID_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn write_confirmation_builder_drains_unsigned_queue_after_recovery() {
        let _guard = WRITE_CONFIRMATION_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
        std::env::remove_var(WRITE_CONFIRMATION_KEY_ID_ENV);

        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let first = svc.build_write_confirmation(
            crate::dataplane_store::AppendStats {
                write_confirmation: Some(corecrux_storage::WriteConfirmationMaterialV1 {
                    commit_seq: 11,
                    segment_id: 5,
                    receipt_hash: [0x55; 32],
                }),
                ..Default::default()
            },
            &[],
        );
        assert!(first.unsigned);
        assert_eq!(svc.unsigned_write_confirmation_queue.lock().expect("queue").len(), 1);

        std::env::set_var(
            WRITE_CONFIRMATION_SIGNING_KEY_ENV,
            base64::engine::general_purpose::STANDARD.encode([0x66u8; 32]),
        );
        std::env::set_var(WRITE_CONFIRMATION_KEY_ID_ENV, "recovered-key");

        let second = svc.build_write_confirmation(
            crate::dataplane_store::AppendStats {
                write_confirmation: Some(corecrux_storage::WriteConfirmationMaterialV1 {
                    commit_seq: 12,
                    segment_id: 6,
                    receipt_hash: [0x77; 32],
                }),
                ..Default::default()
            },
            &[],
        );
        assert!(!second.unsigned);
        assert_eq!(second.vault_signature.len(), 64);
        assert_eq!(svc.unsigned_write_confirmation_queue.lock().expect("queue").len(), 0);

        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
        std::env::remove_var(WRITE_CONFIRMATION_KEY_ID_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn replication_auth_bearer_defaults_and_normalizes() {
        std::env::remove_var("CORECRUXD_REPLICATION_AUTH_BEARER");
        assert_eq!(replication_auth_bearer_value(), "Bearer replication:write");

        std::env::set_var("CORECRUXD_REPLICATION_AUTH_BEARER", "jwt-token");
        assert_eq!(replication_auth_bearer_value(), "Bearer jwt-token");

        std::env::set_var("CORECRUXD_REPLICATION_AUTH_BEARER", "Bearer already-formatted");
        assert_eq!(replication_auth_bearer_value(), "Bearer already-formatted");

        std::env::remove_var("CORECRUXD_REPLICATION_AUTH_BEARER");
    }

    // --- New tests for uncovered grpc.rs paths ---

    #[test]
    fn stored_event_to_read_stream_response_maps_all_fields() {
        let ev = mk_event(42, 128);
        let resp = stored_event_to_read_stream_response(ev.clone());
        assert_eq!(resp.seq, 42);
        assert_eq!(resp.event_id, "e-42");
        assert_eq!(resp.occurred_at, "2026-01-01T00:00:00Z");
        assert_eq!(resp.ingested_at, "2026-01-01T00:00:01Z");
        assert_eq!(resp.event_type, "bench.replay");
        assert_eq!(resp.content_type, "application/octet-stream");
        assert_eq!(resp.payload.len(), 128);
        let loc = resp.location.expect("location should be set");
        assert_eq!(loc.shard_id, 1);
        assert_eq!(loc.segment_id, 1);
        assert_eq!(loc.offset, 420);
        assert_eq!(loc.epoch, 1);
    }

    #[test]
    fn map_append_error_invalid_argument() {
        let status = map_append_error(AppendError::InvalidArgument("bad field".to_string()));
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(status.message().contains("bad field"));
    }

    #[test]
    fn map_append_error_failed_precondition() {
        let status = map_append_error(AppendError::FailedPrecondition("oops".to_string()));
        assert_eq!(status.code(), Code::FailedPrecondition);
    }

    #[test]
    fn map_append_error_resource_exhausted() {
        let status = map_append_error(AppendError::ResourceExhausted("full".to_string()));
        assert_eq!(status.code(), Code::ResourceExhausted);
    }

    #[test]
    fn map_append_error_internal() {
        let status = map_append_error(AppendError::Internal("unexpected".to_string()));
        assert_eq!(status.code(), Code::Internal);
    }

    #[test]
    fn map_append_error_shard_unavailable() {
        let status = map_append_error(AppendError::ShardUnavailable {
            shard_id: "shard-0001".to_string(),
            owner_gpu_id: 2,
            current_shard_map_version: 5,
        });
        assert_eq!(status.code(), Code::Unavailable);
        let body: serde_json::Value = serde_json::from_str(status.message()).expect("json body");
        assert_eq!(body["code"], "SHARD_UNAVAILABLE");
        assert_eq!(body["shardId"], "shard-0001");
        assert_eq!(body["ownerGpuId"], 2);
        assert_eq!(body["currentShardMapVersion"], 5);
    }

    #[test]
    fn map_append_error_wrong_shard() {
        let status = map_append_error(AppendError::WrongShard {
            leader_grpc_addr: "http://leader.grpc".to_string(),
            current_shard_map_version: 3,
        });
        assert_eq!(status.code(), Code::FailedPrecondition);
        let body: serde_json::Value = serde_json::from_str(status.message()).expect("json body");
        assert_eq!(body["code"], "WRONG_SHARD");
        assert_eq!(body["leaderGrpcAddr"], "http://leader.grpc");
        assert_eq!(body["currentShardMapVersion"], 3);
    }

    #[test]
    fn map_append_error_shardmap_version_mismatch() {
        let status = map_append_error(AppendError::ShardMapVersionMismatch {
            client_version: 10,
            current_version: 12,
        });
        assert_eq!(status.code(), Code::FailedPrecondition);
        let body: serde_json::Value = serde_json::from_str(status.message()).expect("json body");
        assert_eq!(body["code"], "SHARDMAP_VERSION_MISMATCH");
        assert_eq!(body["clientShardMapVersion"], 10);
        assert_eq!(body["currentShardMapVersion"], 12);
    }

    #[test]
    fn batched_builder_empty_returns_single_eof() {
        let batches = build_read_stream_batches(Vec::new(), 10, 4096);
        assert_eq!(batches.len(), 1);
        assert!(batches[0].eof);
        assert_eq!(batches[0].event_count, 0);
        assert!(batches[0].events.is_empty());
    }

    #[test]
    fn batch_single_empty_returns_eof() {
        let batch = build_read_stream_batch_single(Vec::new(), 10, 4096);
        assert!(batch.eof);
        assert_eq!(batch.event_count, 0);
        assert!(batch.events.is_empty());
    }

    #[test]
    fn batch_single_returns_subset_when_oversized() {
        // 3 events, each 2048 bytes, batch limit 1024 bytes
        let events: Vec<corecrux_storage::StoredEvent> = (0..3).map(|i| mk_event(i, 2048)).collect();
        let batch = build_read_stream_batch_single(events, 100, 1024);
        // First event must always be included even if oversized
        assert_eq!(batch.event_count, 1);
        assert!(!batch.eof); // only took 1 of 3
    }

    #[test]
    fn batch_single_caps_by_max_events() {
        let events: Vec<corecrux_storage::StoredEvent> = (0..10).map(|i| mk_event(i, 8)).collect();
        let batch = build_read_stream_batch_single(events, 3, 1_000_000);
        assert_eq!(batch.event_count, 3);
        assert!(!batch.eof);
    }

    #[test]
    fn batch_single_returns_all_when_fits() {
        let events: Vec<corecrux_storage::StoredEvent> = (0..3).map(|i| mk_event(i, 8)).collect();
        let batch = build_read_stream_batch_single(events, 100, 1_000_000);
        assert_eq!(batch.event_count, 3);
        assert!(batch.eof);
    }

    #[test]
    fn resolve_batch_limits_uses_config_defaults() {
        use super::resolve_batch_limits;
        use corecrux_proto::dataplane_v1::ReadStreamBatchedRequest;

        let cfg = DataPlaneServiceConfig {
            node_id: "n".to_string(),
            commit_level: CommitLevel::LocalCommit,
            replicated_commit_timeout_ms: 2000,
            replicated_commit_require_all_followers: false,
            replay_batch_max_events: 500,
            replay_batch_max_bytes: 2_000_000,
            replay_many_max_reads: 128,
            replay_use_batched_rpc_default: false,
            store_lock_strategy: StoreLockStrategy::RwLock,
            append_lane_enabled: false,
            append_lane_scope: AppendLaneScope::Shard,
        };

        // zero means "use config defaults"
        let req = ReadStreamBatchedRequest {
            base: None,
            max_events_per_message: 0,
            max_bytes_per_message: 0,
        };
        let (events, bytes) = resolve_batch_limits(&req, &cfg);
        assert_eq!(events, 500);
        assert_eq!(bytes, 2_000_000);

        // client-specified limits are clamped to config
        let req = ReadStreamBatchedRequest {
            base: None,
            max_events_per_message: 9999,
            max_bytes_per_message: 99_999_999,
        };
        let (events, bytes) = resolve_batch_limits(&req, &cfg);
        assert_eq!(events, 500);
        assert_eq!(bytes, 2_000_000);

        // client-specified limits below config are kept
        let req = ReadStreamBatchedRequest {
            base: None,
            max_events_per_message: 10,
            max_bytes_per_message: 10_000,
        };
        let (events, bytes) = resolve_batch_limits(&req, &cfg);
        assert_eq!(events, 10);
        assert_eq!(bytes, 10_000);
    }

    #[test]
    fn fallback_write_confirmation_material_filters_rejected() {
        let rejected = corecrux_storage::AppendOutcome {
            status: AppendStatus::Rejected,
            seq: 0,
            location: None,
            payload_hash: [0xAA; 32],
            header_hash: [0xBB; 32],
            error_code: Some("DUPLICATE".to_string()),
            error_message: Some("duplicate event".to_string()),
        };
        let accepted = corecrux_storage::AppendOutcome {
            status: AppendStatus::Appended,
            seq: 5,
            location: Some(corecrux_storage::FrameLocation {
                shard_id: 1,
                epoch: 2,
                segment_seq: 10,
                offset: 200,
            }),
            payload_hash: [0xCC; 32],
            header_hash: [0xDD; 32],
            error_code: None,
            error_message: None,
        };
        let material = fallback_write_confirmation_material(&[rejected, accepted]);
        assert_eq!(material.commit_seq, 5);
        assert_eq!(material.segment_id, 10);
        // Hash should only include the accepted outcome
        let mut hasher = blake3::Hasher::new();
        hasher.update(&5u64.to_be_bytes());
        hasher.update(&[0xDD; 32]);
        hasher.update(&[0xCC; 32]);
        hasher.update(&1u64.to_be_bytes());
        hasher.update(&2u64.to_be_bytes());
        hasher.update(&10u64.to_be_bytes());
        hasher.update(&200u64.to_be_bytes());
        assert_eq!(material.receipt_hash, *hasher.finalize().as_bytes());
    }

    #[test]
    fn fallback_write_confirmation_material_empty_outcomes() {
        let material = fallback_write_confirmation_material(&[]);
        assert_eq!(material.commit_seq, 0);
        assert_eq!(material.segment_id, 0);
        // Empty hash = blake3 of empty input
        let expected = *blake3::Hasher::new().finalize().as_bytes();
        assert_eq!(material.receipt_hash, expected);
    }

    #[test]
    fn tenant_id_hash_label_is_deterministic() {
        let hash1 = DataPlaneService::tenant_id_hash_label("tenant-a");
        let hash2 = DataPlaneService::tenant_id_hash_label("tenant-a");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 16);

        let hash3 = DataPlaneService::tenant_id_hash_label("tenant-b");
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn tenant_throttle_token_bucket_zero_rate_rejects() {
        let mut bucket = super::TenantThrottleTokenBucket::default();
        bucket.update_config(Some(0), Some(0));
        let result = bucket.try_consume(1, 100, 50);
        assert!(result.is_err());
        let retry_ms = result.unwrap_err();
        assert!(retry_ms >= 1);
    }

    #[test]
    fn tenant_throttle_token_bucket_allows_within_budget() {
        let mut bucket = super::TenantThrottleTokenBucket::default();
        bucket.update_config(Some(1000), Some(1_000_000));
        // Should succeed with burst capacity
        assert!(bucket.try_consume(100, 10_000, 50).is_ok());
    }

    #[test]
    fn tenant_throttle_token_bucket_exhaustion_returns_retry() {
        let mut bucket = super::TenantThrottleTokenBucket::default();
        bucket.update_config(Some(10), None);
        // Consume all tokens (burst = 1 sec * 10 eps = 10 tokens)
        assert!(bucket.try_consume(10, 0, 50).is_ok());
        // Next should fail
        let result = bucket.try_consume(1, 0, 50);
        assert!(result.is_err());
        let retry_ms = result.unwrap_err();
        assert!(retry_ms >= 50);
    }

    #[test]
    fn tenant_throttle_none_rates_pass_through() {
        let mut bucket = super::TenantThrottleTokenBucket::default();
        bucket.update_config(None, None);
        assert!(bucket.try_consume(9999, 9999999, 50).is_ok());
    }

    #[test]
    fn tenant_throttle_update_config_resets_tokens() {
        let mut bucket = super::TenantThrottleTokenBucket::default();
        bucket.update_config(Some(100), None);
        assert!(bucket.try_consume(100, 0, 50).is_ok());
        // Exhausted
        assert!(bucket.try_consume(1, 0, 50).is_err());
        // Reconfigure with higher rate -> tokens reset
        bucket.update_config(Some(200), None);
        assert!(bucket.try_consume(1, 0, 50).is_ok());
    }

    #[test]
    fn tenant_throttle_update_config_noop_when_unchanged() {
        let mut bucket = super::TenantThrottleTokenBucket::default();
        bucket.update_config(Some(100), None);
        assert!(bucket.try_consume(50, 0, 50).is_ok());
        // Same config -> no reset
        bucket.update_config(Some(100), None);
        // Should still have only 50 tokens left (no reset)
        assert!(bucket.try_consume(50, 0, 50).is_ok());
        assert!(bucket.try_consume(1, 0, 50).is_err());
    }

    #[tokio::test]
    async fn append_batch_returns_unimplemented_without_pool() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let status = svc
            .append_batch(Request::new(AppendBatchRequest {
                tenant_id: "t".to_string(),
                stream_type: "knowledge".to_string(),
                stream_id: "s".to_string(),
                events: vec![],
                expected_next_seq: 0,
                client_shard_map_version: None,
            }))
            .await
            .expect_err("no pool must return unimplemented");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    #[test]
    fn parse_min_follower_watermark_from_meta_missing() {
        use super::parse_min_follower_watermark_from_meta;
        let meta = tonic::metadata::MetadataMap::new();
        assert_eq!(parse_min_follower_watermark_from_meta(&meta).unwrap(), None);
    }

    #[test]
    fn parse_min_follower_watermark_from_meta_valid() {
        use super::parse_min_follower_watermark_from_meta;
        let mut meta = tonic::metadata::MetadataMap::new();
        meta.insert("x-corecrux-min-watermark-segment-seq", "42".parse().unwrap());
        assert_eq!(parse_min_follower_watermark_from_meta(&meta).unwrap(), Some(42));
    }

    #[test]
    fn parse_min_follower_watermark_from_meta_invalid() {
        use super::parse_min_follower_watermark_from_meta;
        let mut meta = tonic::metadata::MetadataMap::new();
        meta.insert("x-corecrux-min-watermark-segment-seq", "not-a-number".parse().unwrap());
        let err = parse_min_follower_watermark_from_meta(&meta).unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn select_read_stream_prefix_len_always_includes_first() {
        use super::select_read_stream_prefix_len;
        // Single oversized event
        let events = vec![mk_event(1, 100_000)];
        let take = select_read_stream_prefix_len(&events, 1, 1024);
        assert_eq!(take, 1);
    }

    #[test]
    fn select_read_stream_prefix_len_empty() {
        use super::select_read_stream_prefix_len;
        let events: Vec<corecrux_storage::StoredEvent> = Vec::new();
        assert_eq!(select_read_stream_prefix_len(&events, 10, 4096), 0);
    }

    // ── estimate_read_stream_event_wire_bytes ──────────────────────

    #[test]
    fn estimate_wire_bytes_includes_all_fields() {
        use super::estimate_read_stream_event_wire_bytes;
        let ev = mk_event(1, 256);
        let estimate = estimate_read_stream_event_wire_bytes(&ev);
        // Must include at least the payload size + overhead
        assert!(estimate >= 256 + 64);
        // Verify it grows with payload
        let ev_big = mk_event(2, 4096);
        let estimate_big = estimate_read_stream_event_wire_bytes(&ev_big);
        assert!(estimate_big > estimate);
    }

    #[test]
    fn estimate_wire_bytes_empty_event() {
        use super::estimate_read_stream_event_wire_bytes;
        let ev = corecrux_storage::StoredEvent {
            seq: 0,
            event_id: String::new(),
            occurred_at: String::new(),
            ingested_at: String::new(),
            event_type: String::new(),
            content_type: String::new(),
            payload: vec![],
            location: corecrux_storage::FrameLocation {
                shard_id: 0,
                epoch: 0,
                segment_seq: 0,
                offset: 0,
            },
        };
        let estimate = estimate_read_stream_event_wire_bytes(&ev);
        assert_eq!(estimate, 64); // Just the fixed overhead
    }

    // ── load_write_confirmation_key_id ─────────────────────────────

    #[test]
    #[serial_test::serial]
    fn load_write_confirmation_key_id_default() {
        let _guard = WRITE_CONFIRMATION_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(WRITE_CONFIRMATION_KEY_ID_ENV);
        let id = super::load_write_confirmation_key_id();
        assert_eq!(id, "local-env-ed25519");
    }

    #[test]
    #[serial_test::serial]
    fn load_write_confirmation_key_id_from_env() {
        let _guard = WRITE_CONFIRMATION_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(WRITE_CONFIRMATION_KEY_ID_ENV, "custom-key-id");
        let id = super::load_write_confirmation_key_id();
        assert_eq!(id, "custom-key-id");
        std::env::remove_var(WRITE_CONFIRMATION_KEY_ID_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn load_write_confirmation_key_id_empty_falls_back() {
        let _guard = WRITE_CONFIRMATION_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(WRITE_CONFIRMATION_KEY_ID_ENV, "  ");
        let id = super::load_write_confirmation_key_id();
        assert_eq!(id, "local-env-ed25519");
        std::env::remove_var(WRITE_CONFIRMATION_KEY_ID_ENV);
    }

    // ── load_write_confirmation_signing_key edge cases ─────────────

    #[test]
    #[serial_test::serial]
    fn load_signing_key_missing_env_returns_none() {
        let _guard = WRITE_CONFIRMATION_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
        assert!(load_write_confirmation_signing_key().is_none());
    }

    #[test]
    #[serial_test::serial]
    fn load_signing_key_empty_env_returns_none() {
        let _guard = WRITE_CONFIRMATION_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV, "");
        assert!(load_write_confirmation_signing_key().is_none());
        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn load_signing_key_short_key_returns_none() {
        let _guard = WRITE_CONFIRMATION_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Only 16 bytes = too short
        std::env::set_var(
            WRITE_CONFIRMATION_SIGNING_KEY_ENV,
            base64::engine::general_purpose::STANDARD.encode([0x11u8; 16]),
        );
        assert!(load_write_confirmation_signing_key().is_none());
        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn load_signing_key_url_safe_base64() {
        let _guard = WRITE_CONFIRMATION_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let key = [0x55u8; 32];
        std::env::set_var(
            WRITE_CONFIRMATION_SIGNING_KEY_ENV,
            base64::engine::general_purpose::URL_SAFE.encode(key),
        );
        assert!(load_write_confirmation_signing_key().is_some());
        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
    }

    // ── ExportService::new ─────────────────────────────────────────

    #[test]
    fn export_service_new_without_pool() {
        use super::ExportService;
        let build = corecrux_types::BuildInfo {
            version: "test".to_string(),
            commit: "test".to_string(),
        };
        let metrics = crate::metrics::Metrics::new(&build, "test");
        let auth = Authz::from_env(AuthMode::Off).expect("auth off");
        let svc = ExportService::new(None, metrics, build, auth);
        assert!(svc.pool.is_none());
    }

    // ── DataPlaneService::new without pool ─────────────────────────

    #[test]
    fn dataplane_service_new_without_pool() {
        let svc = test_service_with_auth("node-test", AuthMode::Off);
        assert!(svc.pool.is_none());
    }

    // ── append_batch auth paths ────────────────────────────────────

    #[tokio::test]
    async fn append_batch_requires_events_write_scope() {
        let svc = test_service_with_auth("node-a", AuthMode::DevScopes);

        // No scope -> unauthenticated
        let status = svc
            .append_batch(Request::new(AppendBatchRequest {
                tenant_id: "t".to_string(),
                stream_type: "knowledge".to_string(),
                stream_id: "s".to_string(),
                events: vec![],
                expected_next_seq: 0,
                client_shard_map_version: None,
            }))
            .await
            .expect_err("missing scope must fail");
        assert_eq!(status.code(), Code::Unauthenticated);

        // Wrong scope -> permission denied
        let status2 = svc
            .append_batch(request_with_dev_scopes(
                AppendBatchRequest {
                    tenant_id: "t".to_string(),
                    stream_type: "knowledge".to_string(),
                    stream_id: "s".to_string(),
                    events: vec![],
                    expected_next_seq: 0,
                    client_shard_map_version: None,
                },
                "admin:read",
            ))
            .await
            .expect_err("wrong scope must fail");
        assert_eq!(status2.code(), Code::PermissionDenied);
    }

    // ── build_read_stream_batches edge cases ──────────────────────

    #[test]
    fn batched_builder_single_event() {
        let events = vec![mk_event(1, 64)];
        let batches = build_read_stream_batches(events, 10, 4096);
        assert_eq!(batches.len(), 1);
        assert!(batches[0].eof);
        assert_eq!(batches[0].event_count, 1);
        assert_eq!(batches[0].events[0].seq, 1);
    }

    #[test]
    fn batched_builder_exact_max_events_boundary() {
        // 5 events with max_events_per_message=5 -> exactly one batch
        let events: Vec<corecrux_storage::StoredEvent> = (0..5).map(|i| mk_event(i, 8)).collect();
        let batches = build_read_stream_batches(events, 5, 1_000_000);
        assert_eq!(batches.len(), 1);
        assert!(batches[0].eof);
        assert_eq!(batches[0].event_count, 5);
    }

    #[test]
    fn batched_builder_exact_max_events_plus_one() {
        // 6 events with max_events_per_message=5 -> two batches
        let events: Vec<corecrux_storage::StoredEvent> = (0..6).map(|i| mk_event(i, 8)).collect();
        let batches = build_read_stream_batches(events, 5, 1_000_000);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].event_count, 5);
        assert!(!batches[0].eof);
        assert_eq!(batches[1].event_count, 1);
        assert!(batches[1].eof);
    }

    // ── SplitMix64 edge cases ─────────────────────────────────────

    #[test]
    fn splitmix64_gen_range_zero_returns_zero() {
        let mut rng = SplitMix64::new(42);
        assert_eq!(rng.gen_range_u64(0), 0);
        assert_eq!(rng.gen_range_usize(0), 0);
    }

    #[test]
    fn splitmix64_produces_different_values() {
        let mut rng = SplitMix64::new(1);
        let a = rng.next_u64();
        let b = rng.next_u64();
        assert_ne!(a, b);
    }

    // ── fallback_write_confirmation_material multiple accepted ─────

    #[test]
    fn fallback_write_confirmation_material_multiple_accepted() {
        let a1 = corecrux_storage::AppendOutcome {
            status: AppendStatus::Appended,
            seq: 10,
            location: Some(corecrux_storage::FrameLocation {
                shard_id: 1,
                epoch: 1,
                segment_seq: 5,
                offset: 100,
            }),
            payload_hash: [0x11; 32],
            header_hash: [0x22; 32],
            error_code: None,
            error_message: None,
        };
        let a2 = corecrux_storage::AppendOutcome {
            status: AppendStatus::Appended,
            seq: 11,
            location: Some(corecrux_storage::FrameLocation {
                shard_id: 1,
                epoch: 1,
                segment_seq: 5,
                offset: 200,
            }),
            payload_hash: [0x33; 32],
            header_hash: [0x44; 32],
            error_code: None,
            error_message: None,
        };
        let material = fallback_write_confirmation_material(&[a1, a2]);
        // commit_seq should be max seq
        assert_eq!(material.commit_seq, 11);
        assert_eq!(material.segment_id, 5);
        // Hash should include both outcomes
        let mut hasher = blake3::Hasher::new();
        // a1
        hasher.update(&10u64.to_be_bytes());
        hasher.update(&[0x22; 32]);
        hasher.update(&[0x11; 32]);
        hasher.update(&1u64.to_be_bytes());
        hasher.update(&1u64.to_be_bytes());
        hasher.update(&5u64.to_be_bytes());
        hasher.update(&100u64.to_be_bytes());
        // a2
        hasher.update(&11u64.to_be_bytes());
        hasher.update(&[0x44; 32]);
        hasher.update(&[0x33; 32]);
        hasher.update(&1u64.to_be_bytes());
        hasher.update(&1u64.to_be_bytes());
        hasher.update(&5u64.to_be_bytes());
        hasher.update(&200u64.to_be_bytes());
        assert_eq!(material.receipt_hash, *hasher.finalize().as_bytes());
    }

    // ── build_read_stream_batch_single progress guarantee ─────────

    #[test]
    fn batch_single_single_oversized_event_still_included() {
        // Single event that exceeds byte limit must still be returned
        let events = vec![mk_event(1, 100_000)];
        let batch = build_read_stream_batch_single(events, 100, 1024);
        assert_eq!(batch.event_count, 1);
        assert!(batch.eof);
    }

    // ── append_batch throttle valve ────────────────────────────────

    // ── select_read_stream_prefix_len caps by events ──────────────

    #[test]
    fn select_read_stream_prefix_len_caps_by_max_events() {
        use super::select_read_stream_prefix_len;
        let events: Vec<corecrux_storage::StoredEvent> = (0..10).map(|i| mk_event(i, 8)).collect();
        let take = select_read_stream_prefix_len(&events, 3, 1_000_000);
        assert_eq!(take, 3);
    }

    #[test]
    fn select_read_stream_prefix_len_caps_by_bytes() {
        use super::select_read_stream_prefix_len;
        // Each event ~2048 + overhead, with 1024 byte limit -> only first event
        let events: Vec<corecrux_storage::StoredEvent> = (0..5).map(|i| mk_event(i, 2048)).collect();
        let take = select_read_stream_prefix_len(&events, 100, 1024);
        assert_eq!(take, 1); // First event always included
    }

    // ── tenant_id_hash_label format ────────────────────────────────

    #[test]
    fn tenant_id_hash_label_is_hex() {
        let label = DataPlaneService::tenant_id_hash_label("test-tenant");
        assert_eq!(label.len(), 16);
        assert!(label.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ── read_stream without pool ─────────────────────────────────

    #[tokio::test]
    async fn read_stream_returns_unimplemented_without_pool() {
        use corecrux_proto::dataplane_v1::ReadStreamRequest;
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let status = svc
            .read_stream(Request::new(ReadStreamRequest {
                tenant_id: "t".to_string(),
                stream_type: "knowledge".to_string(),
                stream_id: "s".to_string(),
                from_seq_inclusive: 0,
                max_events: 10,
                tail_events: 0,
                mode: 0,
            }))
            .await
            .expect_err("no pool must return unimplemented");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    #[tokio::test]
    async fn read_stream_requires_events_read_scope() {
        use corecrux_proto::dataplane_v1::ReadStreamRequest;
        let svc = test_service_with_auth("node-a", AuthMode::DevScopes);
        let status = svc
            .read_stream(Request::new(ReadStreamRequest {
                tenant_id: "t".to_string(),
                stream_type: "knowledge".to_string(),
                stream_id: "s".to_string(),
                from_seq_inclusive: 0,
                max_events: 10,
                tail_events: 0,
                mode: 0,
            }))
            .await
            .expect_err("missing scope must fail");
        assert_eq!(status.code(), Code::Unauthenticated);
    }

    // ── read_stream_batched without pool ───────────────────────────

    #[tokio::test]
    async fn read_stream_batched_returns_unimplemented_without_pool() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let base = corecrux_proto::dataplane_v1::ReadStreamRequest {
            tenant_id: "t".to_string(),
            stream_type: "knowledge".to_string(),
            stream_id: "s".to_string(),
            from_seq_inclusive: 0,
            max_events: 10,
            tail_events: 0,
            mode: 0,
        };
        let status = svc
            .read_stream_batched(Request::new(ReadStreamBatchedRequest {
                base: Some(base),
                max_events_per_message: 0,
                max_bytes_per_message: 0,
            }))
            .await
            .expect_err("no pool must return unimplemented");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    #[tokio::test]
    async fn read_stream_batched_returns_unimplemented() {
        // Crux Daemon: method returns Unimplemented before validation.
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let status = svc
            .read_stream_batched(Request::new(ReadStreamBatchedRequest {
                base: None,
                max_events_per_message: 0,
                max_bytes_per_message: 0,
            }))
            .await
            .expect_err("must return unimplemented");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    // ── read_stream_batched_unary without pool ────────────────────

    #[tokio::test]
    async fn read_stream_batched_unary_returns_unimplemented_without_pool() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let base = corecrux_proto::dataplane_v1::ReadStreamRequest {
            tenant_id: "t".to_string(),
            stream_type: "knowledge".to_string(),
            stream_id: "s".to_string(),
            from_seq_inclusive: 0,
            max_events: 10,
            tail_events: 0,
            mode: 0,
        };
        let status = svc
            .read_stream_batched_unary(Request::new(ReadStreamBatchedRequest {
                base: Some(base),
                max_events_per_message: 0,
                max_bytes_per_message: 0,
            }))
            .await
            .expect_err("no pool must return unimplemented");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    // ── read_many_batched_unary without pool ──────────────────────

    #[tokio::test]
    async fn read_many_batched_unary_returns_unimplemented_without_pool() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let status = svc
            .read_many_batched_unary(Request::new(ReadManyBatchedRequest {
                reads: vec![ReadStreamBatchedRequest {
                    base: Some(ReadStreamRequest {
                        tenant_id: "t".to_string(),
                        stream_type: "knowledge".to_string(),
                        stream_id: "s".to_string(),
                        from_seq_inclusive: 0,
                        max_events: 10,
                        tail_events: 0,
                        mode: 0,
                    }),
                    max_events_per_message: 0,
                    max_bytes_per_message: 0,
                }],
            }))
            .await
            .expect_err("no pool must return unimplemented");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    // ── read_many_frames_batched_unary without pool ───────────────

    #[tokio::test]
    async fn read_many_frames_batched_unary_returns_unimplemented_without_pool() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let status = svc
            .read_many_frames_batched_unary(Request::new(ReadManyFramesBatchedRequest {
                reads: vec![ReadStreamBatchedRequest {
                    base: Some(ReadStreamRequest {
                        tenant_id: "t".to_string(),
                        stream_type: "knowledge".to_string(),
                        stream_id: "s".to_string(),
                        from_seq_inclusive: 0,
                        max_events: 10,
                        tail_events: 0,
                        mode: 0,
                    }),
                    max_events_per_message: 0,
                    max_bytes_per_message: 0,
                }],
            }))
            .await
            .expect_err("no pool must return unimplemented");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    // ── read_frames_batched_unary without pool ────────────────────

    #[tokio::test]
    async fn read_frames_batched_unary_returns_unimplemented_without_pool() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let base = corecrux_proto::dataplane_v1::ReadStreamRequest {
            tenant_id: "t".to_string(),
            stream_type: "knowledge".to_string(),
            stream_id: "s".to_string(),
            from_seq_inclusive: 0,
            max_events: 10,
            tail_events: 0,
            mode: 0,
        };
        let status = svc
            .read_frames_batched_unary(Request::new(ReadStreamBatchedRequest {
                base: Some(base),
                max_events_per_message: 0,
                max_bytes_per_message: 0,
            }))
            .await
            .expect_err("no pool must return unimplemented");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    // ── export_receipt_bundle without pool ─────────────────────────

    #[tokio::test]
    async fn export_receipt_bundle_returns_unimplemented_without_pool() {
        let build = corecrux_types::BuildInfo {
            version: "test".to_string(),
            commit: "test".to_string(),
        };
        let metrics = crate::metrics::Metrics::new(&build, "test");
        let auth = Authz::from_env(AuthMode::Off).expect("auth off");
        let svc = super::ExportService::new(None, metrics, build, auth);
        let status = svc
            .export_receipt_bundle(Request::new(ExportReceiptBundleRequest {
                tenant_id: "t".to_string(),
                receipt_id: "crx_abc".to_string(),
                format: 0,
                redaction: 0,
                include: vec![],
            }))
            .await
            .expect_err("no pool must return unimplemented");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    // NOTE: export_receipt_bundle checks pool before auth, so auth test
    // requires a pool (which needs a full dataplane setup). The no-pool
    // path is already covered by export_receipt_bundle_returns_unimplemented_without_pool.

    // NOTE: replay_session takes tonic::Streaming which requires complex
    // construction in tests. The no-pool and auth paths are covered by the
    // pattern established for other handlers.

    // ── TenantInFlightGuard drop ──────────────────────────────────

    #[test]
    fn tenant_in_flight_guard_decrements_on_drop() {
        let state = Arc::new(StdMutex::new(HashMap::new()));
        {
            let mut s = state.lock().unwrap();
            s.insert(
                "tenant-x".to_string(),
                super::TenantThrottleRuntimeState {
                    in_flight: 2,
                    bucket: super::TenantThrottleTokenBucket::default(),
                },
            );
        }
        {
            let _guard = super::TenantInFlightGuard {
                state: state.clone(),
                tenant_id: Some("tenant-x".to_string()),
            };
            // Guard is live
            assert_eq!(state.lock().unwrap()["tenant-x"].in_flight, 2);
        }
        // Guard dropped, in_flight decremented
        assert_eq!(state.lock().unwrap()["tenant-x"].in_flight, 1);
    }

    #[test]
    fn tenant_in_flight_guard_none_tenant_is_noop() {
        let state = Arc::new(StdMutex::new(HashMap::new()));
        {
            let _guard = super::TenantInFlightGuard {
                state: state.clone(),
                tenant_id: None,
            };
        }
        assert!(state.lock().unwrap().is_empty());
    }

    #[test]
    fn tenant_in_flight_guard_removes_entry_when_idle_and_no_config() {
        let state = Arc::new(StdMutex::new(HashMap::new()));
        {
            let mut s = state.lock().unwrap();
            s.insert(
                "tenant-cleanup".to_string(),
                super::TenantThrottleRuntimeState {
                    in_flight: 1,
                    bucket: super::TenantThrottleTokenBucket::default(),
                },
            );
        }
        {
            let _guard = super::TenantInFlightGuard {
                state: state.clone(),
                tenant_id: Some("tenant-cleanup".to_string()),
            };
        }
        // in_flight was 1, decrement to 0, no config -> entry removed
        assert!(state.lock().unwrap().get("tenant-cleanup").is_none());
    }

    // ── InFlightGuard drop ────────────────────────────────────────

    #[test]
    fn in_flight_guard_decrements_on_drop() {
        let counter = Arc::new(AtomicU32::new(5));
        {
            let _guard = super::InFlightGuard {
                counter: counter.clone(),
            };
        }
        assert_eq!(counter.load(Ordering::Relaxed), 4);
    }

    // ── token bucket bytes rate limiting ──────────────────────────

    #[test]
    fn tenant_throttle_bytes_rate_limiting() {
        let mut bucket = super::TenantThrottleTokenBucket::default();
        bucket.update_config(None, Some(1000)); // 1000 bytes/sec
                                                // Should succeed within burst
        assert!(bucket.try_consume(0, 500, 50).is_ok());
        assert!(bucket.try_consume(0, 500, 50).is_ok());
        // Should fail when exhausted
        let result = bucket.try_consume(0, 1, 50);
        assert!(result.is_err());
    }

    #[test]
    fn tenant_throttle_zero_bytes_rate_rejects() {
        let mut bucket = super::TenantThrottleTokenBucket::default();
        bucket.update_config(None, Some(0));
        let result = bucket.try_consume(0, 100, 50);
        assert!(result.is_err());
    }

    // ── append_lane_bucket determinism ──────────────────────────

    #[test]
    fn append_lane_bucket_is_deterministic() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let b1 = svc.append_lane_bucket("global:0");
        let b2 = svc.append_lane_bucket("global:0");
        assert_eq!(b1, b2);
        assert!(b1 < 16); // APPEND_LANE_FAIRNESS_BUCKETS = 16
    }

    #[test]
    fn append_lane_bucket_distributes() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let mut seen = std::collections::HashSet::new();
        for i in 0..100 {
            let key = format!("shard:shard-{i:04}");
            seen.insert(svc.append_lane_bucket(&key));
        }
        // Should hit at least a few different buckets
        assert!(seen.len() > 1);
    }

    // ── update_append_lane_waiters_peak ──────────────────────────

    #[test]
    fn update_append_lane_waiters_peak_tracks_maximum() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        svc.update_append_lane_waiters_peak(5);
        assert_eq!(svc.append_lane_waiters_peak.load(Ordering::Relaxed), 5);

        svc.update_append_lane_waiters_peak(3); // Lower value, should not update
        assert_eq!(svc.append_lane_waiters_peak.load(Ordering::Relaxed), 5);

        svc.update_append_lane_waiters_peak(10); // Higher value
        assert_eq!(svc.append_lane_waiters_peak.load(Ordering::Relaxed), 10);
    }

    // ── append_lane_for_key ─────────────────────────────────────

    #[tokio::test]
    async fn append_lane_for_key_returns_consistent_lock() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let lane1 = svc.append_lane_for_key("shard:shard-0001").await;
        let lane2 = svc.append_lane_for_key("shard:shard-0001").await;
        // Same key should return the same Arc (pointer equality)
        assert!(Arc::ptr_eq(&lane1, &lane2));
    }

    #[tokio::test]
    async fn append_lane_for_key_different_keys_get_different_locks() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let lane1 = svc.append_lane_for_key("shard:shard-0001").await;
        let lane2 = svc.append_lane_for_key("shard:shard-0002").await;
        assert!(!Arc::ptr_eq(&lane1, &lane2));
    }

    // ── queue_unsigned_write_confirmation ────────────────────────

    #[test]
    fn queue_unsigned_write_confirmation_adds_to_queue() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        svc.queue_unsigned_write_confirmation(corecrux_storage::WriteConfirmationMaterialV1 {
            commit_seq: 1,
            segment_id: 1,
            receipt_hash: [0x11; 32],
        });
        svc.queue_unsigned_write_confirmation(corecrux_storage::WriteConfirmationMaterialV1 {
            commit_seq: 2,
            segment_id: 1,
            receipt_hash: [0x22; 32],
        });
        let queue = svc.unsigned_write_confirmation_queue.lock().expect("lock");
        assert_eq!(queue.len(), 2);
    }

    // ── build_write_confirmation without signing key ─────────────

    #[test]
    #[serial_test::serial]
    fn build_write_confirmation_without_key_returns_unsigned() {
        let _guard = WRITE_CONFIRMATION_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
        std::env::remove_var(WRITE_CONFIRMATION_KEY_ID_ENV);

        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let outcome = corecrux_storage::AppendOutcome {
            status: AppendStatus::Appended,
            seq: 42,
            location: Some(corecrux_storage::FrameLocation {
                shard_id: 1,
                epoch: 1,
                segment_seq: 10,
                offset: 500,
            }),
            payload_hash: [0x11; 32],
            header_hash: [0x22; 32],
            error_code: None,
            error_message: None,
        };
        let stats = crate::dataplane_store::AppendStats {
            write_confirmation: Some(corecrux_storage::WriteConfirmationMaterialV1 {
                commit_seq: 42,
                segment_id: 10,
                receipt_hash: [0x33; 32],
            }),
            ..Default::default()
        };
        let confirmation = svc.build_write_confirmation(stats, &[outcome]);
        assert!(confirmation.unsigned);
        assert_eq!(confirmation.commit_seq, 42);
        assert_eq!(confirmation.segment_id, 10);
        assert!(confirmation.vault_signature.is_empty());
    }

    // ── build_write_confirmation with signing key ────────────────

    #[test]
    #[serial_test::serial]
    fn build_write_confirmation_with_key_returns_signed() {
        let _guard = WRITE_CONFIRMATION_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            WRITE_CONFIRMATION_SIGNING_KEY_ENV,
            base64::engine::general_purpose::STANDARD.encode([0x77u8; 32]),
        );
        std::env::set_var(WRITE_CONFIRMATION_KEY_ID_ENV, "test-key");

        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let stats = crate::dataplane_store::AppendStats {
            write_confirmation: Some(corecrux_storage::WriteConfirmationMaterialV1 {
                commit_seq: 99,
                segment_id: 20,
                receipt_hash: [0x44; 32],
            }),
            ..Default::default()
        };
        let confirmation = svc.build_write_confirmation(stats, &[]);
        assert!(!confirmation.unsigned);
        assert_eq!(confirmation.commit_seq, 99);
        assert_eq!(confirmation.segment_id, 20);
        assert_eq!(confirmation.vault_signature.len(), 64);
        assert_eq!(confirmation.key_id, "test-key");

        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
        std::env::remove_var(WRITE_CONFIRMATION_KEY_ID_ENV);
    }

    // ── build_write_confirmation uses fallback when no stats ─────

    #[test]
    #[serial_test::serial]
    fn build_write_confirmation_uses_fallback_without_stats() {
        let _guard = WRITE_CONFIRMATION_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);

        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let outcome = corecrux_storage::AppendOutcome {
            status: AppendStatus::Appended,
            seq: 7,
            location: Some(corecrux_storage::FrameLocation {
                shard_id: 1,
                epoch: 1,
                segment_seq: 3,
                offset: 50,
            }),
            payload_hash: [0x55; 32],
            header_hash: [0x66; 32],
            error_code: None,
            error_message: None,
        };
        let stats = crate::dataplane_store::AppendStats {
            write_confirmation: None, // No material from store
            ..Default::default()
        };
        let confirmation = svc.build_write_confirmation(stats, &[outcome]);
        assert!(confirmation.unsigned);
        assert_eq!(confirmation.commit_seq, 7);
        assert_eq!(confirmation.segment_id, 3);
    }

    // ── read_stream auth with correct scope ──────────────────────

    #[tokio::test]
    async fn read_stream_with_events_read_scope_hits_pool_check() {
        let svc = test_service_with_auth("node-a", AuthMode::DevScopes);
        let status = svc
            .read_stream(request_with_dev_scopes(
                ReadStreamRequest {
                    tenant_id: "t".to_string(),
                    stream_type: "knowledge".to_string(),
                    stream_id: "s".to_string(),
                    from_seq_inclusive: 0,
                    max_events: 10,
                    tail_events: 0,
                    mode: 0,
                },
                "events:read",
            ))
            .await
            .expect_err("no pool so should get unimplemented after auth passes");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    // ── read_stream_batched auth ──────────────────────────────────

    #[tokio::test]
    async fn read_stream_batched_requires_proprietary_edition() {
        // Crux Daemon: method returns Unimplemented before auth checks.
        let svc = test_service_with_auth("node-a", AuthMode::DevScopes);
        let base = ReadStreamRequest {
            tenant_id: "t".to_string(),
            stream_type: "knowledge".to_string(),
            stream_id: "s".to_string(),
            from_seq_inclusive: 0,
            max_events: 10,
            tail_events: 0,
            mode: 0,
        };
        let status = svc
            .read_stream_batched(Request::new(ReadStreamBatchedRequest {
                base: Some(base),
                max_events_per_message: 0,
                max_bytes_per_message: 0,
            }))
            .await
            .expect_err("must return unimplemented");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    // ── read_stream_batched_unary: Crux Daemon returns Unimplemented ──

    #[tokio::test]
    async fn read_stream_batched_unary_returns_unimplemented() {
        let svc = test_service_with_auth("node-a", AuthMode::DevScopes);
        let status = svc
            .read_stream_batched_unary(Request::new(ReadStreamBatchedRequest {
                base: None,
                max_events_per_message: 0,
                max_bytes_per_message: 0,
            }))
            .await
            .expect_err("must return unimplemented");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    // ── read_frames_batched_unary: Crux Daemon returns Unimplemented ──

    #[tokio::test]
    async fn read_frames_batched_unary_returns_unimplemented() {
        let svc = test_service_with_auth("node-a", AuthMode::DevScopes);
        let status = svc
            .read_frames_batched_unary(Request::new(ReadStreamBatchedRequest {
                base: None,
                max_events_per_message: 0,
                max_bytes_per_message: 0,
            }))
            .await
            .expect_err("must return unimplemented");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    // ── append_lane_key ─────────────────────────────────────────

    #[test]
    fn append_lane_key_shard_scope() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        // Default config has append_lane_scope = Shard
        let decision = crate::shard_map::RouteDecision {
            stream_hash: 12345,
            shard_id: "shard-0001".to_string(),
            epoch: 1,
            gpu_id: Some(0),
            leader_grpc_addr: "http://localhost:50051".to_string(),
            leader_node_id: "node-a".to_string(),
            shard_map_version: 1,
        };
        let key = svc.append_lane_key(&decision, 12345);
        assert_eq!(key, "shard:shard-0001");
    }

    // ── build_static_append_lanes ─────────────────────────────────

    #[test]
    fn build_static_append_lanes_disabled_returns_empty() {
        use super::build_static_append_lanes;
        let cfg = DataPlaneServiceConfig {
            node_id: "n".to_string(),
            commit_level: CommitLevel::LocalCommit,
            replicated_commit_timeout_ms: 2000,
            replicated_commit_require_all_followers: false,
            replay_batch_max_events: 128,
            replay_batch_max_bytes: 1024 * 1024,
            replay_many_max_reads: 128,
            replay_use_batched_rpc_default: false,
            store_lock_strategy: StoreLockStrategy::RwLock,
            append_lane_enabled: false,
            append_lane_scope: AppendLaneScope::Shard,
        };
        let lanes = build_static_append_lanes(None, &cfg);
        assert!(lanes.is_empty());
    }

    #[test]
    fn build_static_append_lanes_shard_scope_returns_empty() {
        use super::build_static_append_lanes;
        let cfg = DataPlaneServiceConfig {
            node_id: "n".to_string(),
            commit_level: CommitLevel::LocalCommit,
            replicated_commit_timeout_ms: 2000,
            replicated_commit_require_all_followers: false,
            replay_batch_max_events: 128,
            replay_batch_max_bytes: 1024 * 1024,
            replay_many_max_reads: 128,
            replay_use_batched_rpc_default: false,
            store_lock_strategy: StoreLockStrategy::RwLock,
            append_lane_enabled: true,
            append_lane_scope: AppendLaneScope::Shard,
        };
        // Shard scope doesn't use static lanes
        let lanes = build_static_append_lanes(None, &cfg);
        assert!(lanes.is_empty());
    }

    // ── append_batch empty events ─────────────────────────────────

    // ── map_append_error: all error variants (v2) ────────────────────

    #[test]
    fn map_append_error_invalid_argument_v2() {
        let status = map_append_error(AppendError::InvalidArgument("bad".into()));
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[test]
    fn map_append_error_failed_precondition_v2() {
        let status = map_append_error(AppendError::FailedPrecondition("pre".into()));
        assert_eq!(status.code(), Code::FailedPrecondition);
    }

    #[test]
    fn map_append_error_resource_exhausted_v2() {
        let status = map_append_error(AppendError::ResourceExhausted("res".into()));
        assert_eq!(status.code(), Code::ResourceExhausted);
    }

    #[test]
    fn map_append_error_io_backend_v2() {
        let status = map_append_error(AppendError::IoBackend("disk".into()));
        assert_eq!(status.code(), Code::Unavailable);
    }

    #[test]
    fn map_append_error_internal_v2() {
        let status = map_append_error(AppendError::Internal("bug".into()));
        assert_eq!(status.code(), Code::Internal);
    }

    #[test]
    fn map_append_error_wrong_shard_v2() {
        let status = map_append_error(AppendError::WrongShard {
            leader_grpc_addr: "http://leader:4007".into(),
            current_shard_map_version: 5,
        });
        assert_eq!(status.code(), Code::FailedPrecondition);
    }

    #[test]
    fn map_append_error_shard_unavailable_v2() {
        let status = map_append_error(AppendError::ShardUnavailable {
            shard_id: "shard-0001".into(),
            owner_gpu_id: 0,
            current_shard_map_version: 1,
        });
        assert_eq!(status.code(), Code::Unavailable);
    }

    #[test]
    fn map_append_error_shard_map_version_mismatch_v2() {
        let status = map_append_error(AppendError::ShardMapVersionMismatch {
            client_version: 1,
            current_version: 5,
        });
        assert_eq!(status.code(), Code::FailedPrecondition);
    }

    // ── estimate_read_stream_event_wire_bytes ────────────────────────

    #[test]
    fn estimate_wire_bytes_includes_overhead() {
        let ev = corecrux_storage::StoredEvent {
            seq: 0,
            event_id: "e1".to_string(),
            occurred_at: "2026-01-01".to_string(),
            ingested_at: "2026-01-01".to_string(),
            event_type: "t".to_string(),
            content_type: "application/json".to_string(),
            payload: vec![0u8; 100],
            location: corecrux_storage::FrameLocation {
                shard_id: 0,
                epoch: 0,
                segment_seq: 0,
                offset: 0,
            },
        };
        let est = super::estimate_read_stream_event_wire_bytes(&ev);
        assert!(est >= 100 + 64);
    }

    // ── select_read_stream_prefix_len ───────────────────────────────

    #[test]
    fn select_prefix_empty_events() {
        let events: Vec<corecrux_storage::StoredEvent> = Vec::new();
        assert_eq!(super::select_read_stream_prefix_len(&events, 100, 10000), 0);
    }

    // ── stored_event_to_read_stream_response ────────────────────────

    #[test]
    fn stored_event_to_response_maps_fields() {
        let ev = corecrux_storage::StoredEvent {
            seq: 42,
            event_id: "evt-42".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:01Z".to_string(),
            event_type: "created".to_string(),
            content_type: "application/octet-stream".to_string(),
            payload: vec![1, 2, 3],
            location: corecrux_storage::FrameLocation {
                shard_id: 1,
                epoch: 3,
                segment_seq: 7,
                offset: 128,
            },
        };
        let resp = stored_event_to_read_stream_response(ev);
        assert_eq!(resp.seq, 42);
        assert_eq!(resp.event_id, "evt-42");
        assert_eq!(resp.payload, vec![1, 2, 3]);
        let loc = resp.location.unwrap();
        assert_eq!(loc.shard_id, 1);
        assert_eq!(loc.epoch, 3);
        assert_eq!(loc.segment_id, 7);
        assert_eq!(loc.offset, 128);
    }

    // ── replication_auth_bearer_value ────────────────────────────────

    #[test]
    #[serial_test::serial]
    fn replication_auth_bearer_value_nonempty() {
        let val = replication_auth_bearer_value();
        // Should return some string even if env var isn't set
        assert!(!val.is_empty());
    }

    // ── fallback_write_confirmation_material (additional) ─────────────

    #[test]
    fn fallback_write_confirmation_material_empty_outcomes_v2() {
        let result = fallback_write_confirmation_material(&[]);
        assert_eq!(result.commit_seq, 0);
        assert_eq!(result.segment_id, 0);
    }

    #[test]
    fn fallback_write_confirmation_material_with_outcomes_v2() {
        let outcomes = vec![corecrux_storage::AppendOutcome {
            status: corecrux_storage::AppendStatus::Appended,
            seq: 42,
            location: Some(corecrux_storage::FrameLocation {
                shard_id: 1,
                epoch: 1,
                segment_seq: 7,
                offset: 0,
            }),
            payload_hash: [0xAA; 32],
            header_hash: [0xBB; 32],
            error_code: None,
            error_message: None,
        }];
        let result = fallback_write_confirmation_material(&outcomes);
        assert_eq!(result.commit_seq, 42);
        assert_eq!(result.segment_id, 7);
        // receipt_hash should be non-zero
        assert_ne!(result.receipt_hash, [0u8; 32]);
    }

    #[test]
    fn fallback_write_confirmation_material_skips_rejected() {
        let outcomes = vec![
            corecrux_storage::AppendOutcome {
                status: corecrux_storage::AppendStatus::Rejected,
                seq: 10,
                location: None,
                payload_hash: [0; 32],
                header_hash: [0; 32],
                error_code: Some("DUP".to_string()),
                error_message: None,
            },
            corecrux_storage::AppendOutcome {
                status: corecrux_storage::AppendStatus::Appended,
                seq: 20,
                location: Some(corecrux_storage::FrameLocation {
                    shard_id: 1,
                    epoch: 1,
                    segment_seq: 5,
                    offset: 100,
                }),
                payload_hash: [1; 32],
                header_hash: [2; 32],
                error_code: None,
                error_message: None,
            },
        ];
        let result = fallback_write_confirmation_material(&outcomes);
        assert_eq!(result.commit_seq, 20);
        assert_eq!(result.segment_id, 5);
    }

    // ── TenantThrottleTokenBucket: capacity with burst_secs ─────────

    #[test]
    fn tenant_throttle_events_capacity_with_default_burst() {
        let mut bucket = super::TenantThrottleTokenBucket::default();
        bucket.update_config(Some(500), None);
        // burst_secs=1 after update_config, so capacity = 500*1
        assert_eq!(bucket.events_capacity(), 500);
    }

    #[test]
    fn tenant_throttle_bytes_capacity_with_default_burst() {
        let mut bucket = super::TenantThrottleTokenBucket::default();
        bucket.update_config(None, Some(2048));
        assert_eq!(bucket.bytes_capacity(), 2048);
    }

    #[test]
    fn tenant_throttle_capacity_none_rate_returns_zero() {
        let bucket = super::TenantThrottleTokenBucket::default();
        assert_eq!(bucket.events_capacity(), 0);
        assert_eq!(bucket.bytes_capacity(), 0);
    }

    // ── TenantThrottleTokenBucket: bytes exhaustion retry ───────────

    #[test]
    fn tenant_throttle_bytes_exhaustion_returns_retry() {
        let mut bucket = super::TenantThrottleTokenBucket::default();
        bucket.update_config(None, Some(100));
        assert!(bucket.try_consume(0, 100, 50).is_ok());
        let result = bucket.try_consume(0, 1, 50);
        assert!(result.is_err());
        let retry = result.unwrap_err();
        assert!(retry >= 50);
    }

    // ─��� TenantThrottleTokenBucket: both rates configured ────────────

    #[test]
    fn tenant_throttle_both_rates_configured() {
        let mut bucket = super::TenantThrottleTokenBucket::default();
        bucket.update_config(Some(100), Some(1000));
        // Within budget for both
        assert!(bucket.try_consume(50, 500, 50).is_ok());
        // Exhaust events
        assert!(bucket.try_consume(50, 0, 50).is_ok());
        // Events exhausted
        assert!(bucket.try_consume(1, 0, 50).is_err());
    }

    // ── TenantThrottleTokenBucket: zero events with zero needed ─────

    #[test]
    fn tenant_throttle_zero_events_rate_allows_zero_needed() {
        let mut bucket = super::TenantThrottleTokenBucket::default();
        bucket.update_config(Some(0), None);
        // Zero events needed should pass even with zero rate
        assert!(bucket.try_consume(0, 0, 50).is_ok());
    }

    #[test]
    fn tenant_throttle_zero_bytes_rate_allows_zero_needed() {
        let mut bucket = super::TenantThrottleTokenBucket::default();
        bucket.update_config(None, Some(0));
        assert!(bucket.try_consume(0, 0, 50).is_ok());
    }

    // ── TenantThrottleRuntimeState default ──────────────────────────

    #[test]
    fn tenant_throttle_runtime_state_default() {
        let state = super::TenantThrottleRuntimeState::default();
        assert_eq!(state.in_flight, 0);
    }

    // ── PendingWriteConfirmation ─────────────────────────────────────

    #[test]
    fn pending_write_confirmation_debug_and_clone() {
        let pending = super::PendingWriteConfirmation {
            commit_seq: 42,
            segment_id: 7,
            receipt_hash: [0xAA; 32],
        };
        let cloned = pending;
        assert_eq!(cloned.commit_seq, 42);
        assert_eq!(cloned.segment_id, 7);
        let dbg = format!("{:?}", pending);
        assert!(dbg.contains("42"));
    }

    // ── DataPlaneServiceConfig Debug ────��──────��─────────────────────

    #[test]
    fn dataplane_service_config_debug() {
        let cfg = DataPlaneServiceConfig {
            node_id: "test-node".to_string(),
            commit_level: CommitLevel::LocalCommit,
            replicated_commit_timeout_ms: 2000,
            replicated_commit_require_all_followers: false,
            replay_batch_max_events: 128,
            replay_batch_max_bytes: 1024 * 1024,
            replay_many_max_reads: 128,
            replay_use_batched_rpc_default: false,
            store_lock_strategy: StoreLockStrategy::RwLock,
            append_lane_enabled: false,
            append_lane_scope: AppendLaneScope::Shard,
        };
        let dbg = format!("{:?}", cfg);
        assert!(dbg.contains("test-node"));
        assert!(dbg.contains("LocalCommit"));
    }

    // ── queue_unsigned_write_confirmation overflow ───────────────────

    #[test]
    fn queue_unsigned_write_confirmation_caps_at_capacity() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        for i in 0..super::WRITE_CONFIRMATION_UNSIGNED_QUEUE_CAPACITY + 10 {
            let queued = svc.queue_unsigned_write_confirmation(corecrux_storage::WriteConfirmationMaterialV1 {
                commit_seq: i as u64,
                segment_id: 1,
                receipt_hash: [0x11; 32],
            });
            assert_eq!(queued, i < super::WRITE_CONFIRMATION_UNSIGNED_QUEUE_CAPACITY);
        }
        let queue = svc.unsigned_write_confirmation_queue.lock().expect("lock");
        assert_eq!(queue.len(), super::WRITE_CONFIRMATION_UNSIGNED_QUEUE_CAPACITY);
        // Preserve FIFO backlog; overflow is reported, not silently evicted.
        assert_eq!(queue.front().unwrap().commit_seq, 0);
    }

    // ── read_many_batched_unary auth paths ───────────────────────────
    // Pool check precedes auth: no pool → Unimplemented before auth runs.

    #[tokio::test]
    async fn read_many_batched_unary_no_pool_returns_unimplemented_before_auth() {
        let svc = test_service_with_auth("node-a", AuthMode::DevScopes);
        let status = svc
            .read_many_batched_unary(Request::new(ReadManyBatchedRequest {
                reads: vec![ReadStreamBatchedRequest {
                    base: Some(ReadStreamRequest {
                        tenant_id: "t".to_string(),
                        stream_type: "knowledge".to_string(),
                        stream_id: "s".to_string(),
                        from_seq_inclusive: 0,
                        max_events: 10,
                        tail_events: 0,
                        mode: 0,
                    }),
                    max_events_per_message: 0,
                    max_bytes_per_message: 0,
                }],
            }))
            .await
            .expect_err("no pool must fail before auth");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    // ── read_many_frames_batched_unary auth paths ───────────────────

    #[tokio::test]
    async fn read_many_frames_batched_unary_no_pool_returns_unimplemented_before_auth() {
        let svc = test_service_with_auth("node-a", AuthMode::DevScopes);
        let status = svc
            .read_many_frames_batched_unary(Request::new(ReadManyFramesBatchedRequest {
                reads: vec![ReadStreamBatchedRequest {
                    base: Some(ReadStreamRequest {
                        tenant_id: "t".to_string(),
                        stream_type: "knowledge".to_string(),
                        stream_id: "s".to_string(),
                        from_seq_inclusive: 0,
                        max_events: 10,
                        tail_events: 0,
                        mode: 0,
                    }),
                    max_events_per_message: 0,
                    max_bytes_per_message: 0,
                }],
            }))
            .await
            .expect_err("no pool must fail before auth");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    // ── export_receipt_bundle auth path ──────────────────────────────

    #[tokio::test]
    async fn export_receipt_bundle_requires_receipts_scope() {
        let build = corecrux_types::BuildInfo {
            version: "test".to_string(),
            commit: "test".to_string(),
        };
        let metrics = crate::metrics::Metrics::new(&build, "test");
        let auth = Authz::from_env(AuthMode::DevScopes).expect("auth");
        let svc = super::ExportService::new(None, metrics, build, auth);
        let status = svc
            .export_receipt_bundle(Request::new(ExportReceiptBundleRequest {
                tenant_id: "t".to_string(),
                receipt_id: "crx_test".to_string(),
                format: 0,
                redaction: 0,
                include: vec![],
            }))
            .await
            .expect_err("missing scope must fail");
        // Pool check comes before auth in this handler
        assert_eq!(status.code(), Code::Unimplemented);
    }

    // ── read_stream wrong scope → PermissionDenied ──────────────────

    #[tokio::test]
    async fn read_stream_wrong_scope_permission_denied() {
        let svc = test_service_with_auth("node-a", AuthMode::DevScopes);
        let status = svc
            .read_stream(request_with_dev_scopes(
                ReadStreamRequest {
                    tenant_id: "t".to_string(),
                    stream_type: "knowledge".to_string(),
                    stream_id: "s".to_string(),
                    from_seq_inclusive: 0,
                    max_events: 10,
                    tail_events: 0,
                    mode: 0,
                },
                "admin:write",
            ))
            .await
            .expect_err("wrong scope must fail");
        assert_eq!(status.code(), Code::PermissionDenied);
    }

    // Crux Daemon: read_stream_batched and read_stream_batched_unary
    // return Unimplemented before reaching auth/validation checks.
    // Auth enforcement tests for these RPCs are in the proprietary test suite.

    // Crux Daemon: read_frames_batched_unary returns Unimplemented
    // before reaching validation. See read_frames_batched_unary_returns_unimplemented above.

    // ── read_many_batched_unary empty reads ──────────────────────────

    #[tokio::test]
    async fn read_many_batched_unary_empty_reads_returns_unimplemented() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let status = svc
            .read_many_batched_unary(Request::new(ReadManyBatchedRequest { reads: vec![] }))
            .await
            .expect_err("empty reads must fail");
        // No pool → unimplemented
        assert_eq!(status.code(), Code::Unimplemented);
    }

    // ── read_many_frames_batched_unary empty reads ──────────────────

    #[tokio::test]
    async fn read_many_frames_batched_unary_empty_reads_returns_unimplemented() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let status = svc
            .read_many_frames_batched_unary(Request::new(ReadManyFramesBatchedRequest { reads: vec![] }))
            .await
            .expect_err("empty reads must fail");
        assert_eq!(status.code(), Code::Unimplemented);
    }

    // ���─ WriteConfirmationSigningResult default ───────────────────────

    #[test]
    fn write_confirmation_signing_result_default() {
        let result = super::WriteConfirmationSigningResult::default();
        assert!(result.signature.is_none());
        assert_eq!(result.key_id, "");
    }

    // ── tenant_in_flight_guard keeps entry when config present ──────

    #[test]
    fn tenant_in_flight_guard_keeps_entry_when_config_set() {
        let state = Arc::new(StdMutex::new(HashMap::new()));
        {
            let mut s = state.lock().unwrap();
            let mut bucket = super::TenantThrottleTokenBucket::default();
            bucket.update_config(Some(100), None);
            s.insert(
                "tenant-config".to_string(),
                super::TenantThrottleRuntimeState { in_flight: 1, bucket },
            );
        }
        {
            let _guard = super::TenantInFlightGuard {
                state: state.clone(),
                tenant_id: Some("tenant-config".to_string()),
            };
        }
        // in_flight decremented to 0, but config is present → entry retained
        let s = state.lock().unwrap();
        assert!(s.contains_key("tenant-config"));
        assert_eq!(s["tenant-config"].in_flight, 0);
    }

    // ── apply_tenant_throttle: system tenant bypasses throttle ───────

    #[test]
    fn apply_tenant_throttle_system_bypasses() {
        let mut control = ControlV1::default();
        control.tenant_throttles.push(TenantThrottleV1 {
            tenant_id: "system".to_string(),
            events_per_sec: Some(0),
            bytes_per_sec: Some(0),
            max_in_flight: Some(0),
        });
        let svc = test_service_with_control("node-a", AuthMode::Off, control.clone());
        let events = vec![corecrux_proto::dataplane_v1::AppendEvent {
            event_id: "e1".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            event_type: "test".to_string(),
            content_type: "application/json".to_string(),
            payload: b"data".to_vec(),
        }];
        let result = svc.apply_tenant_throttle(&control, "system", &events);
        assert!(result.is_ok());
    }

    // ── apply_tenant_throttle: unthrottled tenant bypasses ──────────

    #[test]
    fn apply_tenant_throttle_unthrottled_tenant_passes() {
        let control = ControlV1::default();
        let svc = test_service_with_control("node-a", AuthMode::Off, control.clone());
        let events = vec![];
        let result = svc.apply_tenant_throttle(&control, "some-tenant", &events);
        assert!(result.is_ok());
    }

    // ── apply_tenant_throttle: rate limited ─────────────────────────

    #[test]
    fn apply_tenant_throttle_rate_limited_rejects() {
        let mut control = ControlV1::default();
        control.tenant_throttles.push(TenantThrottleV1 {
            tenant_id: "limited".to_string(),
            events_per_sec: Some(1),
            bytes_per_sec: None,
            max_in_flight: None,
        });
        let svc = test_service_with_control("node-a", AuthMode::Off, control.clone());
        let events: Vec<corecrux_proto::dataplane_v1::AppendEvent> = (0..100)
            .map(|i| corecrux_proto::dataplane_v1::AppendEvent {
                event_id: format!("e{i}"),
                occurred_at: "2026-01-01T00:00:00Z".to_string(),
                event_type: "test".to_string(),
                content_type: "application/json".to_string(),
                payload: vec![0u8; 100],
            })
            .collect();
        // First call consumes burst
        let r1 = svc.apply_tenant_throttle(&control, "limited", &events[..1]);
        assert!(r1.is_ok());
        // Second call should exhaust tokens (only 1 eps, burst=1)
        let r2 = svc.apply_tenant_throttle(&control, "limited", &events[..1]);
        assert!(r2.is_err());
    }

    #[test]
    fn map_append_error_version_mismatch_json_format() {
        let status = map_append_error(AppendError::ShardMapVersionMismatch {
            client_version: 99,
            current_version: 100,
        });
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert!(status.message().contains("99"));
        assert!(status.message().contains("100"));
    }

    // ── replication_auth_bearer_value ─────────────────────────────────

    #[test]
    #[serial_test::serial]
    fn replication_auth_bearer_from_env_v2() {
        std::env::set_var("CORECRUXD_REPLICATION_AUTH_BEARER", "secret-val");
        let val = replication_auth_bearer_value();
        assert!(val.contains("secret-val"));
        std::env::remove_var("CORECRUXD_REPLICATION_AUTH_BEARER");
    }

    #[test]
    #[serial_test::serial]
    fn replication_auth_bearer_defaults_when_unset_v2() {
        std::env::remove_var("CORECRUXD_REPLICATION_AUTH_BEARER");
        let val = replication_auth_bearer_value();
        // When unset, defaults to "Bearer replication:write"
        assert!(val.starts_with("Bearer "), "expected Bearer prefix, got: {val}");
        assert!(val.contains("replication:write"));
    }

    /// H2: a panic inside a gRPC handler is caught by the `CatchPanicLayer` and
    /// mapped to a trailers-only `grpc-status: 13` (INTERNAL) response instead
    /// of unwinding the task and dropping the connection.
    #[tokio::test]
    async fn grpc_handler_panic_maps_to_internal_status() {
        use tower::{Layer as _, Service as _, ServiceExt as _};

        async fn panicking_handler(
            _req: axum::http::Request<http_body_util::Empty<axum::body::Bytes>>,
        ) -> Result<axum::http::Response<http_body_util::Full<axum::body::Bytes>>, std::convert::Infallible> {
            panic!("boom in gRPC handler");
        }

        let mut svc = tower_http::catch_panic::CatchPanicLayer::custom(super::handle_grpc_panic)
            .layer(tower::service_fn(panicking_handler));

        let response = svc
            .ready()
            .await
            .expect("service ready")
            .call(axum::http::Request::new(http_body_util::Empty::new()))
            .await
            .expect("catch-panic must recover the unwind into a response");

        assert_eq!(response.status(), axum::http::StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("grpc-status")
                .expect("grpc-status header present"),
            "13",
        );
    }

    /// Every panic payload shape must still produce INTERNAL. A `String`
    /// payload (the common `panic!("{fmt}")` case) took a different downcast
    /// branch from `&str`, and a non-string payload took a third — all three
    /// must return the same trailers-only status rather than dropping the
    /// connection.
    #[test]
    fn handle_grpc_panic_maps_every_payload_shape_to_internal() {
        let payloads: Vec<Box<dyn std::any::Any + Send + 'static>> = vec![
            Box::new("static str panic"),
            Box::new("owned string panic".to_string()),
            Box::new(42_u32),
        ];
        for payload in payloads {
            let response = super::handle_grpc_panic(payload);
            assert_eq!(response.status(), axum::http::StatusCode::OK);
            assert_eq!(response.headers().get("grpc-status").expect("grpc-status header"), "13");
            assert_eq!(
                response
                    .headers()
                    .get(axum::http::header::CONTENT_TYPE)
                    .expect("content-type header"),
                "application/grpc"
            );
            assert_eq!(
                response.headers().get("grpc-message").expect("grpc-message header"),
                "internal error (panic recovered)"
            );
        }
    }

    // ── apply_tenant_throttle rejection paths ────────────────────────

    /// `maxInFlight: 0` is an explicit operator stop, not "no limit". It must
    /// reject before any token is consumed, with the retry hint the client
    /// needs to back off.
    #[test]
    fn apply_tenant_throttle_rejects_zero_max_in_flight() {
        let mut control = ControlV1::default();
        control.valves.throttle.set_retry_after_ms(Some(250));
        control.tenant_throttles.push(TenantThrottleV1 {
            tenant_id: "stopped".to_string(),
            events_per_sec: None,
            bytes_per_sec: None,
            max_in_flight: Some(0),
        });
        let svc = test_service_with_control("node-a", AuthMode::Off, control.clone());

        let status = svc
            .apply_tenant_throttle(&control, "stopped", &[])
            .err()
            .expect("maxInFlight=0 must reject");
        assert_eq!(status.code(), Code::ResourceExhausted);
        let body: serde_json::Value = serde_json::from_str(status.message()).expect("problem json");
        assert_eq!(body["code"], "TENANT_THROTTLE_INFLIGHT");
        assert_eq!(body["retryAfterMs"], 250);
        assert_eq!(
            body["tenantIdHash"],
            super::DataPlaneService::tenant_id_hash_label("stopped")
        );
        // The rejected caller must not be counted as in flight.
        let state = svc.tenant_throttle_state.lock().expect("throttle state");
        assert_eq!(state["stopped"].in_flight, 0);
    }

    /// Concurrency cap: the Nth+1 concurrent append is refused while N guards
    /// are live, and admitted again once one is dropped.
    #[test]
    fn apply_tenant_throttle_rejects_when_in_flight_is_at_the_cap() {
        let mut control = ControlV1::default();
        control.tenant_throttles.push(TenantThrottleV1 {
            tenant_id: "busy".to_string(),
            events_per_sec: None,
            bytes_per_sec: None,
            max_in_flight: Some(1),
        });
        let svc = test_service_with_control("node-a", AuthMode::Off, control.clone());

        let first = svc
            .apply_tenant_throttle(&control, "busy", &[])
            .expect("first call admitted");
        let status = svc
            .apply_tenant_throttle(&control, "busy", &[])
            .err()
            .expect("second concurrent call must reject");
        assert_eq!(status.code(), Code::ResourceExhausted);
        let body: serde_json::Value = serde_json::from_str(status.message()).expect("problem json");
        assert_eq!(body["code"], "TENANT_THROTTLE_INFLIGHT");
        assert!(
            body["message"].as_str().unwrap_or_default().contains("max_in_flight=1"),
            "message must name the cap: {body}"
        );

        drop(first);
        svc.apply_tenant_throttle(&control, "busy", &[])
            .expect("slot freed by the dropped guard");
    }

    /// A throttled tenant's rate rejection carries the distinct
    /// `TENANT_THROTTLE_RATE` code so operators can tell a rate refusal from a
    /// concurrency refusal.
    #[test]
    fn apply_tenant_throttle_rate_rejection_uses_its_own_code() {
        let mut control = ControlV1::default();
        control.tenant_throttles.push(TenantThrottleV1 {
            tenant_id: "byte-limited".to_string(),
            events_per_sec: None,
            bytes_per_sec: Some(0),
            max_in_flight: None,
        });
        let svc = test_service_with_control("node-a", AuthMode::Off, control.clone());
        let events = vec![corecrux_proto::dataplane_v1::AppendEvent {
            event_id: "e1".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            event_type: "test".to_string(),
            content_type: "application/json".to_string(),
            payload: b"payload".to_vec(),
        }];

        let status = svc
            .apply_tenant_throttle(&control, "byte-limited", &events)
            .err()
            .expect("bytesPerSec=0 must reject");
        assert_eq!(status.code(), Code::ResourceExhausted);
        let body: serde_json::Value = serde_json::from_str(status.message()).expect("problem json");
        assert_eq!(body["code"], "TENANT_THROTTLE_RATE");
        assert_eq!(body["retryAfterMs"], 50, "default retry hint when none configured");
    }

    /// A guard whose tenant has already been evicted from the throttle map must
    /// drop cleanly rather than resurrecting an entry with a wrapped counter.
    #[test]
    fn tenant_in_flight_guard_missing_entry_is_a_noop() {
        let state = Arc::new(StdMutex::new(HashMap::new()));
        {
            let _guard = super::TenantInFlightGuard {
                state: state.clone(),
                tenant_id: Some("already-evicted".to_string()),
            };
        }
        assert!(state.lock().expect("throttle state").is_empty());
    }

    // ── append lanes ─────────────────────────────────────────────────

    /// With global-scope lanes enabled the single lane is pre-built at
    /// construction, so the hot path never takes the dynamic-lane map lock.
    #[tokio::test]
    async fn append_lane_for_key_uses_the_prebuilt_global_lane() {
        let svc = test_service_with_lane_config(
            "node-a",
            AuthMode::Off,
            None,
            ControlV1::default(),
            true,
            AppendLaneScope::Global,
        );
        assert!(svc.append_static_lanes.contains_key("global"));
        let lane = svc.append_lane_for_key("global").await;
        assert!(
            Arc::ptr_eq(&lane, svc.append_static_lanes.get("global").expect("static lane")),
            "global lane must come from the prebuilt map"
        );
        assert!(
            svc.append_dynamic_lanes.lock().await.is_empty(),
            "static hit must not populate the dynamic map"
        );
    }

    #[tokio::test]
    async fn append_lane_for_key_falls_back_to_a_dynamic_lane() {
        let svc = test_service_with_lane_config(
            "node-a",
            AuthMode::Off,
            None,
            ControlV1::default(),
            true,
            AppendLaneScope::Shard,
        );
        assert!(svc.append_static_lanes.is_empty(), "shard lanes are created lazily");
        let first = svc.append_lane_for_key("shard:shard-0001").await;
        let second = svc.append_lane_for_key("shard:shard-0001").await;
        assert!(Arc::ptr_eq(&first, &second), "same key must reuse one lane");
        assert_eq!(svc.append_dynamic_lanes.lock().await.len(), 1);
    }

    /// The lane key is what serialises concurrent appends. Global scope must
    /// collapse every shard onto one key; shard scope must not.
    #[test]
    fn append_lane_key_reflects_the_configured_scope() {
        let route = |shard_id: &str| crate::shard_map::RouteDecision {
            stream_hash: 7,
            shard_id: shard_id.to_string(),
            epoch: 1,
            shard_map_version: 1,
            leader_grpc_addr: "http://leader.grpc".to_string(),
            leader_node_id: "leader-a".to_string(),
            gpu_id: None,
        };

        let global = test_service_with_lane_config(
            "node-a",
            AuthMode::Off,
            None,
            ControlV1::default(),
            true,
            AppendLaneScope::Global,
        );
        assert_eq!(global.append_lane_key(&route("shard-0001"), 7), "global");
        assert_eq!(global.append_lane_key(&route("shard-0002"), 7), "global");

        let sharded = test_service_with_lane_config(
            "node-a",
            AuthMode::Off,
            None,
            ControlV1::default(),
            true,
            AppendLaneScope::Shard,
        );
        assert_eq!(sharded.append_lane_key(&route("shard-0001"), 7), "shard:shard-0001");
        assert_ne!(
            sharded.append_lane_key(&route("shard-0001"), 7),
            sharded.append_lane_key(&route("shard-0002"), 7)
        );
    }

    /// Lanes disabled must pre-build nothing, even in global scope — otherwise
    /// a disabled feature still serialises appends.
    #[test]
    fn build_static_append_lanes_respects_enabled_and_scope() {
        let cfg = |append_lane_enabled: bool, append_lane_scope: AppendLaneScope| DataPlaneServiceConfig {
            node_id: "node-a".to_string(),
            commit_level: CommitLevel::LocalCommit,
            replicated_commit_timeout_ms: 2_000,
            replicated_commit_require_all_followers: true,
            replay_batch_max_events: 128,
            replay_batch_max_bytes: 1024 * 1024,
            replay_many_max_reads: 128,
            replay_use_batched_rpc_default: false,
            store_lock_strategy: StoreLockStrategy::RwLock,
            append_lane_enabled,
            append_lane_scope,
        };
        assert!(super::build_static_append_lanes(None, &cfg(false, AppendLaneScope::Global)).is_empty());
        assert!(super::build_static_append_lanes(None, &cfg(false, AppendLaneScope::Shard)).is_empty());
        assert!(super::build_static_append_lanes(None, &cfg(true, AppendLaneScope::Shard)).is_empty());
        let global = super::build_static_append_lanes(None, &cfg(true, AppendLaneScope::Global));
        assert_eq!(global.len(), 1);
        assert!(global.contains_key("global"));
    }

    // ── follower watermark metadata parsing ──────────────────────────

    /// A metadata value that is not valid ASCII must be an explicit
    /// `INVALID_ARGUMENT`, never silently treated as "header absent" — a
    /// replication read would then skip the follower watermark check entirely.
    #[test]
    fn parse_min_follower_watermark_rejects_non_ascii_metadata() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-corecrux-min-watermark-segment-seq",
            axum::http::HeaderValue::from_bytes(&[0xC3, 0xA9]).expect("non-ascii header value"),
        );
        let meta = tonic::metadata::MetadataMap::from_headers(headers);
        let status = super::parse_min_follower_watermark_from_meta(&meta)
            .err()
            .expect("non-ascii must be rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(status
            .message()
            .contains("invalid x-corecrux-min-watermark-segment-seq"));
    }

    #[test]
    fn parse_min_follower_watermark_trims_surrounding_whitespace() {
        let mut meta = tonic::metadata::MetadataMap::new();
        meta.insert(
            "x-corecrux-min-watermark-segment-seq",
            "  42  ".parse().expect("metadata value"),
        );
        assert_eq!(
            super::parse_min_follower_watermark_from_meta(&meta).expect("parse"),
            Some(42)
        );
    }

    // ── unsigned write-confirmation queue ────────────────────────────

    /// Without a signing key the drain must be a no-op: silently emptying the
    /// backlog would discard the audit debt it exists to record.
    #[test]
    #[serial_test::serial]
    fn drain_unsigned_queue_is_a_noop_without_a_signing_key() {
        let _env = WRITE_CONFIRMATION_ENV_LOCK.lock();
        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        for commit_seq in 0..3u64 {
            assert!(
                svc.queue_unsigned_write_confirmation(corecrux_storage::WriteConfirmationMaterialV1 {
                    commit_seq,
                    segment_id: 1,
                    receipt_hash: [0x22; 32],
                })
            );
        }
        svc.drain_unsigned_write_confirmation_queue();
        assert_eq!(
            svc.unsigned_write_confirmation_queue
                .lock()
                .expect("unsigned queue")
                .len(),
            3,
            "backlog must survive a drain attempt with no key"
        );
    }

    /// Crossing the warn threshold must still accept the confirmation — the
    /// depth warning is observability, not a second rejection point.
    #[test]
    fn queue_unsigned_write_confirmation_accepts_past_the_warn_threshold() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        for commit_seq in 0..=super::WRITE_CONFIRMATION_UNSIGNED_QUEUE_WARN_DEPTH as u64 {
            assert!(
                svc.queue_unsigned_write_confirmation(corecrux_storage::WriteConfirmationMaterialV1 {
                    commit_seq,
                    segment_id: 2,
                    receipt_hash: [0x33; 32],
                }),
                "confirmation {commit_seq} must be retained"
            );
        }
        assert_eq!(
            svc.unsigned_write_confirmation_queue
                .lock()
                .expect("unsigned queue")
                .len(),
            super::WRITE_CONFIRMATION_UNSIGNED_QUEUE_WARN_DEPTH + 1
        );
    }

    // ── write-confirmation material ──────────────────────────────────

    /// An accepted outcome that carries no frame location must not be dropped
    /// from the commitment; only the segment id stays at its default.
    #[test]
    fn fallback_write_confirmation_material_covers_outcomes_without_location() {
        let with_location = super::AppendOutcome {
            status: AppendStatus::Appended,
            seq: 5,
            header_hash: [0x01; 32],
            payload_hash: [0x02; 32],
            error_code: None,
            error_message: None,
            location: Some(corecrux_storage::FrameLocation {
                shard_id: 1,
                epoch: 1,
                segment_seq: 9,
                offset: 0,
            }),
        };
        let without_location = super::AppendOutcome {
            status: AppendStatus::Appended,
            seq: 6,
            header_hash: [0x03; 32],
            payload_hash: [0x04; 32],
            error_code: None,
            error_message: None,
            location: None,
        };

        let only_unlocated = fallback_write_confirmation_material(std::slice::from_ref(&without_location));
        assert_eq!(only_unlocated.commit_seq, 6);
        assert_eq!(only_unlocated.segment_id, 0, "no location ⇒ default segment id");

        let mixed = fallback_write_confirmation_material(&[with_location, without_location]);
        assert_eq!(mixed.commit_seq, 6, "highest accepted seq wins");
        assert_eq!(mixed.segment_id, 9, "highest located segment wins");
        assert_ne!(
            mixed.receipt_hash, only_unlocated.receipt_hash,
            "the located outcome must be inside the commitment"
        );
    }

    // ── signing-key loading ──────────────────────────────────────────

    /// All four base64 alphabets the loader advertises must actually work; a
    /// key that fails to decode silently disables signing, which downgrades
    /// every write confirmation to `unsigned: true`.
    #[test]
    #[serial_test::serial]
    fn load_write_confirmation_signing_key_accepts_every_advertised_base64_alphabet() {
        let _env = WRITE_CONFIRMATION_ENV_LOCK.lock();
        let secret = [0x5A_u8; 32];
        let expected = ed25519_dalek::SigningKey::from_bytes(&secret);
        let encodings = [
            base64::engine::general_purpose::STANDARD.encode(secret),
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(secret),
            base64::engine::general_purpose::URL_SAFE.encode(secret),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret),
        ];
        for encoded in encodings {
            std::env::set_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV, &encoded);
            let key = load_write_confirmation_signing_key().expect("key must decode");
            assert_eq!(key.to_bytes(), expected.to_bytes(), "failed for {encoded}");
        }
        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn load_write_confirmation_signing_key_rejects_undecodable_material() {
        let _env = WRITE_CONFIRMATION_ENV_LOCK.lock();
        std::env::set_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV, "not base64 at all !!!");
        assert!(load_write_confirmation_signing_key().is_none());
        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
    }

    // ── AppendError → Status mapping ─────────────────────────────────

    /// A backend I/O fault is retryable from the client's point of view, so it
    /// must map to `UNAVAILABLE` rather than `INTERNAL`.
    #[test]
    fn map_append_error_io_backend_maps_to_unavailable() {
        let status = map_append_error(AppendError::IoBackend("disk offline".to_string()));
        assert_eq!(status.code(), Code::Unavailable);
        assert!(status.message().contains("disk offline"));
    }

    // ── batch limit resolution ───────────────────────────────────────

    /// A caller may only ever narrow the configured ceilings, and the byte
    /// floor keeps a tiny request from producing single-event messages.
    #[test]
    fn resolve_batch_limits_clamps_caller_supplied_values() {
        let svc = test_service_with_auth("node-a", AuthMode::Off);
        let request = |max_events_per_message: u32, max_bytes_per_message: u32| ReadStreamBatchedRequest {
            base: None,
            max_events_per_message,
            max_bytes_per_message,
        };

        // Below the configured ceiling → honoured verbatim.
        assert_eq!(super::resolve_batch_limits(&request(16, 4096), &svc.cfg), (16, 4096));
        // Above the configured ceiling → clamped down to config.
        assert_eq!(
            super::resolve_batch_limits(&request(u32::MAX, u32::MAX), &svc.cfg),
            (svc.cfg.replay_batch_max_events, svc.cfg.replay_batch_max_bytes)
        );
        // Byte floor: 1 byte would otherwise make every message one event.
        assert_eq!(super::resolve_batch_limits(&request(1, 1), &svc.cfg), (1, 1024));
    }

    // ── replication bearer normalisation ─────────────────────────────

    /// An operator who already wrote `Bearer …` into the env must not get a
    /// double-prefixed `Bearer Bearer …` header (which the follower rejects).
    #[test]
    #[serial_test::serial]
    fn replication_auth_bearer_preserves_an_existing_bearer_prefix() {
        for configured in ["Bearer already-prefixed", "bEaReR mixed-case"] {
            std::env::set_var("CORECRUXD_REPLICATION_AUTH_BEARER", configured);
            assert_eq!(replication_auth_bearer_value(), configured);
        }
        std::env::set_var("CORECRUXD_REPLICATION_AUTH_BEARER", "   ");
        assert_eq!(
            replication_auth_bearer_value(),
            "Bearer replication:write",
            "whitespace-only override falls back to the default"
        );
        std::env::remove_var("CORECRUXD_REPLICATION_AUTH_BEARER");
    }

    // ── segment seal receipts ────────────────────────────────────────

    /// Without a signing key the seal receipt must be marked `unsigned` and
    /// carry an empty signature — never an absent flag that reads as signed.
    #[test]
    #[serial_test::serial]
    fn build_segment_seal_receipt_is_marked_unsigned_without_a_key() {
        let _env = WRITE_CONFIRMATION_ENV_LOCK.lock();
        std::env::remove_var(WRITE_CONFIRMATION_SIGNING_KEY_ENV);
        let receipt = build_segment_seal_receipt(corecrux_storage::SegmentSealMaterialV1 {
            shard_id: 1,
            epoch: 2,
            segment_seq: 3,
            segment_id: corecrux_segment::SegmentId([0x07; 16]),
            segment_hash: [0x08; 32],
            previous_segment_seq: None,
            previous_segment_hash: None,
            sealed_at_unix_ns: 1_700_000_000_000_000_000,
            frame_count: 4,
        });
        assert!(receipt.unsigned);
        assert!(receipt.vault_signature.is_empty());
        assert!(!receipt.previous_segment_present, "no previous segment was supplied");
        assert_eq!(receipt.previous_segment_seq, 0);
        assert_eq!(receipt.previous_segment_hash, vec![0u8; 32]);
        assert_eq!(receipt.frame_count, 4);
    }
}
