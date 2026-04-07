// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Community Edition stub — the data-plane pool requires the proprietary
//! edition. Only type definitions needed by other modules are retained here.

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::dataplane_store::DataPlaneStore;

pub type StoreHandle = Arc<RwLock<DataPlaneStore>>;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReplicatedCommitObservation {
    pub shard_id: String,
    pub epoch: u64,
    pub follower_count: usize,
    pub required_acks: usize,
    pub actual_acks: usize,
    pub result: String,
    pub failure_count: usize,
    pub failure_sample: Option<String>,
    pub observed_unix_ms: u64,
    pub leader_segment_seq: u64,
    pub min_follower_acked_segment_seq: u64,
    pub lag_segments: u64,
}

#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields populated by proprietary edition replication path.
pub struct ReplicatedCommitObservationInput {
    pub shard_id: String,
    pub epoch: u64,
    pub follower_count: usize,
    pub required_acks: usize,
    pub actual_acks: usize,
    pub result: String,
    pub failure_count: usize,
    pub failure_sample: Option<String>,
    pub leader_segment_seq: u64,
    pub min_follower_acked_segment_seq: u64,
}

/// Community Edition stub — `DataPlanePool` requires the proprietary edition.
/// The struct is retained (unconstructable) so that `Option<DataPlanePool>` can
/// be `None` everywhere.
#[derive(Clone)]
pub struct DataPlanePool {
    _private: (),
}

// All methods below are unreachable at runtime because `DataPlanePool` is
// unconstructable in the Community Edition. They exist only so that code
// paths behind `if let Some(pool) = ... { ... }` guards type-check without
// requiring every caller to be gutted.
#[allow(dead_code, unused_variables)]
impl DataPlanePool {
    pub fn default_gpu_id(&self) -> i32 {
        unreachable!()
    }

    pub fn gpu_ids(&self) -> Vec<i32> {
        unreachable!()
    }

    pub async fn projection_snapshot_issues(&self) -> Vec<crate::dataplane_store::ProjectionSnapshotIssue> {
        unreachable!()
    }

    pub async fn store_for_stream(
        &self,
        _tenant_id: &str,
        _stream_type: &str,
        _stream_id: &str,
        _client_shard_map_version: Option<u64>,
    ) -> Result<(crate::shard_map::RouteDecision, StoreHandle), crate::dataplane_store::AppendError> {
        unreachable!()
    }

    pub async fn store_for_stream_read(
        &self,
        _tenant_id: &str,
        _stream_type: &str,
        _stream_id: &str,
        _client_shard_map_version: Option<u64>,
        _min_follower_watermark_segment_seq: Option<u64>,
    ) -> Result<(crate::shard_map::RouteDecision, StoreHandle), crate::dataplane_store::AppendError> {
        unreachable!()
    }

    pub async fn store_for_stream_hash(
        &self,
        _stream_hash: u64,
        _client_shard_map_version: Option<u64>,
    ) -> Result<(crate::shard_map::RouteDecision, StoreHandle), crate::dataplane_store::AppendError> {
        unreachable!()
    }

    pub async fn store_for_shard_id(
        &self,
        _shard_id: &str,
    ) -> Result<(i32, StoreHandle), crate::dataplane_store::AppendError> {
        unreachable!()
    }

    pub async fn store_for_shard_u64_read(
        &self,
        _shard_id_u64: u64,
        _min_follower_watermark_segment_seq: Option<u64>,
    ) -> Result<(i32, StoreHandle), crate::dataplane_store::AppendError> {
        unreachable!()
    }

    pub async fn store_for_replication_shard(
        &self,
        _shard_id: &str,
    ) -> Result<(u64, i32, StoreHandle), crate::dataplane_store::AppendError> {
        unreachable!()
    }

    pub fn store_for_gpu_id(&self, _gpu_id: i32) -> Option<StoreHandle> {
        unreachable!()
    }

    pub async fn followers_for_shard(
        &self,
        _shard_id: &str,
    ) -> Result<Vec<corecrux_types::NodeAddr>, crate::dataplane_store::AppendError> {
        unreachable!()
    }

    pub async fn update_follower_watermark(&self, _shard_id: &str, _segment_seq: u64) {
        unreachable!()
    }

    pub async fn follower_watermarks_snapshot(&self) -> std::collections::HashMap<String, u64> {
        unreachable!()
    }

    pub async fn observe_replicated_commit(&self, _input: ReplicatedCommitObservationInput) {
        unreachable!()
    }

    pub async fn replicated_commit_observations_snapshot(
        &self,
    ) -> std::collections::HashMap<String, ReplicatedCommitObservation> {
        unreachable!()
    }

    pub async fn verify_store_integrity_all(
        &self,
        _full: bool,
        _sample_rate: f64,
        _budget_bytes: usize,
        _include_tail_cache: bool,
    ) -> crate::dataplane_store::VerifyStoreSummary {
        unreachable!()
    }

    pub async fn tick_projections_all(
        &self,
        _max_frames: u32,
    ) -> Vec<(String, Result<crate::dataplane_store::ForceSealAndTickResult, String>)> {
        unreachable!()
    }

    pub async fn force_seal_all_and_tick(
        &self,
        _max_frames: u32,
    ) -> Vec<(String, Result<crate::dataplane_store::ForceSealAndTickResult, String>)> {
        unreachable!()
    }

    pub async fn force_seal_all(&self) -> Vec<(String, Result<corecrux_storage::SealResultV1, String>)> {
        unreachable!()
    }

    pub async fn rebuild_projections_online(
        &self,
        _max_frames: u32,
    ) -> Vec<(String, Result<crate::dataplane_store::ForceSealAndTickResult, String>)> {
        unreachable!()
    }
}
