// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Community Edition stub — the data-plane store requires the proprietary
//! edition. Only type definitions needed by other modules are retained here.

// ---------------------------------------------------------------------------
// AppendError — used in error handling across grpc.rs, main.rs, http/mod.rs,
//               ops_events.rs
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Type aliases — re-exports from corecrux_storage used by grpc.rs
// ---------------------------------------------------------------------------

pub type AppendOutcome = corecrux_storage::AppendOutcome;
pub type AppendStatus = corecrux_storage::AppendStatus;
pub type AppendStats = corecrux_storage::AppendStatsV1;
pub type StoredEvent = corecrux_storage::StoredEvent;

// ---------------------------------------------------------------------------
// Struct stubs — fields preserved, impls removed (unconstructable in CE)
// ---------------------------------------------------------------------------

/// Result of a force-seal + projection tick operation on a single shard.
#[derive(Debug)]
pub struct ForceSealAndTickResult {
    #[allow(dead_code)]
    pub shard_id: String,
    pub seal_result: corecrux_storage::SealResultV1,
    pub cursor_before: Option<serde_json::Value>,
    pub cursor_after: Option<serde_json::Value>,
    pub projection_frames_processed: u64,
    /// Number of frames processed (used by projections HTTP surface).
    pub frames_processed: u64,
    /// Commit identifier (used by projections HTTP surface).
    pub commit_id: String,
    /// Projection state counts (used by projections HTTP surface).
    pub state_counts: ProjectionStateCounts,
}

/// Projection state counts surfaced in admin/projection responses.
#[derive(Debug, Default)]
pub struct ProjectionStateCounts {
    pub living_rows: u64,
    pub relations_edges: u64,
}

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

/// Community Edition stub — `DataPlaneStore` requires the proprietary edition.
/// The struct is retained (unconstructable) so that `pool.rs` can reference it.
///
/// All methods below are unreachable at runtime — they exist only so that code
/// paths behind `if let Some(pool) = ... { ... }` guards type-check.
pub struct DataPlaneStore {
    _private: (),
}

#[allow(
    dead_code,
    unused_variables,
    clippy::unused_async,
    clippy::unused_self,
    clippy::too_many_arguments
)]
impl DataPlaneStore {
    pub async fn read_stream(
        &self,
        _tenant_id: &str,
        _stream_type: &str,
        _stream_id: &str,
        _from_seq: u64,
        _max_events: u32,
        _hint: Option<u64>,
    ) -> Result<Vec<corecrux_storage::StoredEvent>, AppendError> {
        unreachable!()
    }

    pub async fn read_tail(
        &self,
        _tenant_id: &str,
        _stream_type: &str,
        _stream_id: &str,
        _count: u32,
        _hint: Option<u64>,
    ) -> Result<Vec<corecrux_storage::StoredEvent>, AppendError> {
        unreachable!()
    }

    pub async fn append_batch(
        &self,
        _tenant_id: &str,
        _stream_type: &str,
        _stream_id: &str,
        _expected_next_seq: u64,
        _client_shard_map_version: Option<u64>,
        _events: &[corecrux_proto::dataplane_v1::AppendEvent],
    ) -> Result<(crate::shard_map::RouteDecision, Vec<AppendOutcome>, AppendStats), AppendError> {
        unreachable!()
    }

    pub fn collect_replication_segments(
        &self,
        _shard_id: &str,
        _outcomes: &[AppendOutcome],
    ) -> Result<Vec<ReplicationSegmentPayload>, AppendError> {
        unreachable!()
    }

    pub fn read_frame_bytes(&self, _shard_id: u64, _segment_id: u64, _offset: u64) -> Result<Vec<u8>, AppendError> {
        unreachable!()
    }

    pub async fn apply_replicated_segment(
        &self,
        _shard_id: &str,
        _epoch: u64,
        _bytes: &[u8],
    ) -> Result<ReplicationApplyResult, AppendError> {
        unreachable!()
    }

    pub async fn update_stream_meta(
        &mut self,
        _tenant_id: &str,
        _stream_type: &str,
        _stream_id: &str,
        _min_live_seq: u64,
        _tombstone_seq: u64,
    ) -> Result<(u64, u64), AppendError> {
        unreachable!()
    }

    pub fn verify_receipt_stream_v1(
        &self,
        _shard_id: u32,
        _tenant_id: &str,
        _receipt_id: &str,
    ) -> Result<Option<corecrux_receipts::VerificationReportV1>, AppendError> {
        unreachable!()
    }

    pub fn projections_meta_for_shard(&self, _shard_id: u32) -> Option<corecrux_projections::ProjectionsMetaV1> {
        unreachable!()
    }

    pub fn projections_living_state_row(
        &self,
        _shard_id: u32,
        _tenant_id: &str,
        _artifact_id: u32,
    ) -> Option<corecrux_projections::LivingStateRowV1> {
        unreachable!()
    }

    pub fn projections_list_relations(
        &self,
        _shard_id: u32,
        _tenant_id: &str,
        _artifact_id: u32,
        _direction: &str,
        _relation_type: Option<u8>,
        _limit: usize,
        _offset: usize,
    ) -> Vec<ProjectionRelationRowV1> {
        unreachable!()
    }

    pub fn projections_list_dependents(
        &self,
        _shard_id: u32,
        _tenant_id: &str,
        _artifact_id: u32,
        _dependent_type: Option<u8>,
        _limit: usize,
        _offset: usize,
    ) -> Vec<ProjectionDependentRowV1> {
        unreachable!()
    }

    pub fn projections_list_pressure_events(
        &self,
        _shard_id: u32,
        _tenant_id: &str,
        _artifact_id: u32,
        _open_only: bool,
        _limit: usize,
        _offset: usize,
    ) -> Vec<ProjectionPressureEventRowV1> {
        unreachable!()
    }

    pub fn query_graph_expand(
        &self,
        _tenant_id: &str,
        _seed_artifact_ids: &[u32],
        _edge_types: &[corecrux_projections::RelationTypeV1],
        _max_hops: u32,
        _budget: usize,
        _min_confidence: f32,
        _include_state: bool,
    ) -> corecrux_projections::query::graph_expand::GraphExpandResponse {
        unreachable!()
    }

    pub fn query_time_range(
        &self,
        _tenant_id: &str,
        _start_micros: i64,
        _end_micros: i64,
        _artifact_ids: &[u32],
        _include_relations: bool,
        _limit: usize,
    ) -> corecrux_projections::query::time_range::TimeRangeResponse {
        unreachable!()
    }

    pub fn query_entity_count(&self, _tenant_id: &str, _entity_type: &str, _predicate: &str) -> Vec<String> {
        unreachable!()
    }

    pub fn query_entity_current_state(
        &self,
        _tenant_id: &str,
        _entity_name: &str,
        _predicate: &str,
    ) -> Option<(String, i64, Option<String>, Option<i64>)> {
        unreachable!()
    }

    pub fn query_entity_timeline(
        &self,
        _tenant_id: &str,
        _entity_type: &str,
        _predicate: &str,
    ) -> Vec<(String, String, i64)> {
        unreachable!()
    }

    pub async fn sync_shards(&self) -> Result<(), AppendError> {
        unreachable!()
    }

    pub fn hosted_shards(&self) -> Vec<String> {
        unreachable!()
    }

    pub fn projection_snapshot_issues(&self) -> Vec<ProjectionSnapshotIssue> {
        unreachable!()
    }
}
