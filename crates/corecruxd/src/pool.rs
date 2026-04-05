// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::RwLock;

use corecrux_frame::stream_hash_xxhash64;
use corecrux_types::parse_shard_id_u32;
use corecrux_types::NodeAddr;

use crate::dataplane_store::{AppendError, DataPlaneStore};
use crate::shard_map::{RouteDecision, RoutingTable};

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

#[derive(Clone)]
pub struct DataPlanePool {
    node_id: String,
    strict_client_version: bool,
    default_gpu_id: i32,
    follower_reads_enabled: bool,
    routing: Arc<RwLock<RoutingTable>>,
    stores_by_gpu: Arc<BTreeMap<i32, StoreHandle>>,
    follower_watermarks: Arc<RwLock<std::collections::HashMap<String, u64>>>,
    replicated_commit_observations:
        Arc<RwLock<std::collections::HashMap<String, ReplicatedCommitObservation>>>,
}

impl DataPlanePool {
    #[allow(dead_code)]
    pub fn new(
        node_id: String,
        strict_client_version: bool,
        default_gpu_id: i32,
        follower_reads_enabled: bool,
        routing: Arc<RwLock<RoutingTable>>,
        stores_by_gpu: BTreeMap<i32, StoreHandle>,
    ) -> Self {
        Self {
            node_id,
            strict_client_version,
            default_gpu_id,
            follower_reads_enabled,
            routing,
            stores_by_gpu: Arc::new(stores_by_gpu),
            follower_watermarks: Arc::new(RwLock::new(std::collections::HashMap::new())),
            replicated_commit_observations: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub fn gpu_ids(&self) -> Vec<i32> {
        self.stores_by_gpu.keys().copied().collect()
    }

    pub fn default_gpu_id(&self) -> i32 {
        self.default_gpu_id
    }

    pub fn store_for_gpu_id(&self, gpu_id: i32) -> Option<StoreHandle> {
        self.stores_by_gpu.get(&gpu_id).cloned()
    }

    pub async fn store_for_stream(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        client_shard_map_version: Option<u64>,
    ) -> Result<(RouteDecision, StoreHandle), AppendError> {
        let stream_hash = stream_hash_xxhash64(tenant_id, stream_type, stream_id)
            .map_err(|e| AppendError::InvalidArgument(format!("invalid stream key: {e}")))?;
        self.store_for_stream_hash(stream_hash, client_shard_map_version)
            .await
    }

    pub async fn store_for_stream_hash(
        &self,
        stream_hash: u64,
        client_shard_map_version: Option<u64>,
    ) -> Result<(RouteDecision, StoreHandle), AppendError> {
        let routing = self.routing.read().await.clone();
        let current_version = routing.current_version();

        if self.strict_client_version {
            if let Some(client_version) = client_shard_map_version {
                if client_version != current_version {
                    return Err(AppendError::ShardMapVersionMismatch {
                        client_version,
                        current_version,
                    });
                }
            }
        }

        let decision = routing.route_stream_hash(stream_hash).ok_or_else(|| {
            AppendError::Internal("streamHash did not match any shard range".into())
        })?;

        if decision.leader_node_id != self.node_id {
            return Err(AppendError::WrongShard {
                leader_grpc_addr: decision.leader_grpc_addr.clone(),
                current_shard_map_version: current_version,
            });
        }

        let owner_gpu_id = decision.gpu_id.unwrap_or(self.default_gpu_id);
        let store = self
            .stores_by_gpu
            .get(&owner_gpu_id)
            .cloned()
            .ok_or_else(|| AppendError::ShardUnavailable {
                shard_id: decision.shard_id.clone(),
                owner_gpu_id,
                current_shard_map_version: current_version,
            })?;

        Ok((decision, store))
    }

    pub async fn store_for_stream_read(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        client_shard_map_version: Option<u64>,
        min_follower_watermark_segment_seq: Option<u64>,
    ) -> Result<(RouteDecision, StoreHandle), AppendError> {
        let stream_hash = stream_hash_xxhash64(tenant_id, stream_type, stream_id)
            .map_err(|e| AppendError::InvalidArgument(format!("invalid stream key: {e}")))?;
        self.store_for_stream_hash_read(
            stream_hash,
            client_shard_map_version,
            min_follower_watermark_segment_seq,
        )
        .await
    }

    pub async fn store_for_stream_hash_read(
        &self,
        stream_hash: u64,
        client_shard_map_version: Option<u64>,
        min_follower_watermark_segment_seq: Option<u64>,
    ) -> Result<(RouteDecision, StoreHandle), AppendError> {
        let routing = self.routing.read().await.clone();
        let current_version = routing.current_version();

        if self.strict_client_version {
            if let Some(client_version) = client_shard_map_version {
                if client_version != current_version {
                    return Err(AppendError::ShardMapVersionMismatch {
                        client_version,
                        current_version,
                    });
                }
            }
        }

        let decision = routing.route_stream_hash(stream_hash).ok_or_else(|| {
            AppendError::Internal("streamHash did not match any shard range".into())
        })?;

        let shard = routing
            .shard_map
            .shards
            .iter()
            .find(|s| s.shard_id == decision.shard_id)
            .ok_or_else(|| {
                AppendError::Internal("routing decision shard missing from shard map".into())
            })?;

        let owner_gpu_id = decision.gpu_id.unwrap_or(self.default_gpu_id);

        if decision.leader_node_id != self.node_id {
            if !self.follower_reads_enabled {
                return Err(AppendError::WrongShard {
                    leader_grpc_addr: decision.leader_grpc_addr.clone(),
                    current_shard_map_version: current_version,
                });
            }
            let is_follower = shard
                .followers
                .as_ref()
                .is_some_and(|followers| followers.iter().any(|n| n.node_id == self.node_id));
            if !is_follower {
                return Err(AppendError::WrongShard {
                    leader_grpc_addr: decision.leader_grpc_addr.clone(),
                    current_shard_map_version: current_version,
                });
            }

            if let Some(min_wm) = min_follower_watermark_segment_seq {
                let cur_wm = self
                    .follower_watermarks
                    .read()
                    .await
                    .get(&decision.shard_id)
                    .copied()
                    .unwrap_or(0);
                if cur_wm < min_wm {
                    return Err(AppendError::FailedPrecondition(
                        serde_json::json!({
                            "code": "FOLLOWER_WATERMARK_BEHIND",
                            "message": format!("follower watermark behind: have {} need {}", cur_wm, min_wm),
                            "shardId": decision.shard_id,
                            "followerWatermarkSegmentSeq": cur_wm,
                            "requiredMinFollowerWatermarkSegmentSeq": min_wm,
                            "currentShardMapVersion": current_version
                        })
                        .to_string(),
                    ));
                }
            }
        }

        let store = self
            .stores_by_gpu
            .get(&owner_gpu_id)
            .cloned()
            .ok_or_else(|| AppendError::ShardUnavailable {
                shard_id: decision.shard_id.clone(),
                owner_gpu_id,
                current_shard_map_version: current_version,
            })?;

        Ok((decision, store))
    }

    pub async fn store_for_shard_id(
        &self,
        shard_id: &str,
    ) -> Result<(i32, StoreHandle), AppendError> {
        let routing = self.routing.read().await.clone();
        let current_version = routing.current_version();

        let shard = routing
            .shard_map
            .shards
            .iter()
            .find(|s| s.shard_id == shard_id)
            .ok_or_else(|| {
                AppendError::InvalidArgument(format!("unknown shard_id '{shard_id}'"))
            })?;

        if shard.leader.node_id != self.node_id {
            return Err(AppendError::WrongShard {
                leader_grpc_addr: shard.leader.grpc_addr.clone(),
                current_shard_map_version: current_version,
            });
        }

        let owner_gpu_id = shard.gpu_id.unwrap_or(self.default_gpu_id);
        let store = self
            .stores_by_gpu
            .get(&owner_gpu_id)
            .cloned()
            .ok_or_else(|| AppendError::ShardUnavailable {
                shard_id: shard_id.to_string(),
                owner_gpu_id,
                current_shard_map_version: current_version,
            })?;

        Ok((owner_gpu_id, store))
    }

    /// Phase 11: resolve the local worker store for follower replication intake.
    ///
    /// Unlike normal client routing, this allows shards where this node is either the leader
    /// or one of the configured followers.
    pub async fn store_for_replication_shard(
        &self,
        shard_id: &str,
    ) -> Result<(u64, i32, StoreHandle), AppendError> {
        let routing = self.routing.read().await.clone();
        let current_version = routing.current_version();

        let shard = routing
            .shard_map
            .shards
            .iter()
            .find(|s| s.shard_id == shard_id)
            .ok_or_else(|| {
                AppendError::InvalidArgument(format!("unknown shard_id '{shard_id}'"))
            })?;

        let hosted_here = if shard.leader.node_id == self.node_id {
            true
        } else {
            shard
                .followers
                .as_ref()
                .is_some_and(|followers| followers.iter().any(|n| n.node_id == self.node_id))
        };
        if !hosted_here {
            return Err(AppendError::WrongShard {
                leader_grpc_addr: shard.leader.grpc_addr.clone(),
                current_shard_map_version: current_version,
            });
        }

        let owner_gpu_id = shard.gpu_id.unwrap_or(self.default_gpu_id);
        let store = self
            .stores_by_gpu
            .get(&owner_gpu_id)
            .cloned()
            .ok_or_else(|| AppendError::ShardUnavailable {
                shard_id: shard_id.to_string(),
                owner_gpu_id,
                current_shard_map_version: current_version,
            })?;

        Ok((shard.epoch, owner_gpu_id, store))
    }

    #[allow(dead_code)]
    pub async fn store_for_shard_u64(
        &self,
        shard_id_u64: u64,
    ) -> Result<(i32, StoreHandle), AppendError> {
        let shard_id_u32 = u32::try_from(shard_id_u64).map_err(|_| {
            AppendError::InvalidArgument(format!("shard_id out of range: {shard_id_u64}"))
        })?;

        let routing = self.routing.read().await.clone();
        let current_version = routing.current_version();

        let shard = routing.shard_map.shards.iter().find(|s| {
            parse_shard_id_u32(&s.shard_id)
                .ok()
                .is_some_and(|v| v == shard_id_u32)
        });
        let Some(shard) = shard else {
            return Err(AppendError::InvalidArgument(format!(
                "unknown shard_id {shard_id_u64}"
            )));
        };

        if shard.leader.node_id != self.node_id {
            return Err(AppendError::WrongShard {
                leader_grpc_addr: shard.leader.grpc_addr.clone(),
                current_shard_map_version: current_version,
            });
        }

        let owner_gpu_id = shard.gpu_id.unwrap_or(self.default_gpu_id);
        let store = self
            .stores_by_gpu
            .get(&owner_gpu_id)
            .cloned()
            .ok_or_else(|| AppendError::ShardUnavailable {
                shard_id: shard.shard_id.clone(),
                owner_gpu_id,
                current_shard_map_version: current_version,
            })?;

        Ok((owner_gpu_id, store))
    }

    pub async fn store_for_shard_u64_read(
        &self,
        shard_id_u64: u64,
        min_follower_watermark_segment_seq: Option<u64>,
    ) -> Result<(i32, StoreHandle), AppendError> {
        let shard_id_u32 = u32::try_from(shard_id_u64).map_err(|_| {
            AppendError::InvalidArgument(format!("shard_id out of range: {shard_id_u64}"))
        })?;

        let routing = self.routing.read().await.clone();
        let current_version = routing.current_version();

        let shard = routing.shard_map.shards.iter().find(|s| {
            parse_shard_id_u32(&s.shard_id)
                .ok()
                .is_some_and(|v| v == shard_id_u32)
        });
        let Some(shard) = shard else {
            return Err(AppendError::InvalidArgument(format!(
                "unknown shard_id {shard_id_u64}"
            )));
        };

        if shard.leader.node_id != self.node_id {
            if !self.follower_reads_enabled {
                return Err(AppendError::WrongShard {
                    leader_grpc_addr: shard.leader.grpc_addr.clone(),
                    current_shard_map_version: current_version,
                });
            }
            let is_follower = shard
                .followers
                .as_ref()
                .is_some_and(|followers| followers.iter().any(|n| n.node_id == self.node_id));
            if !is_follower {
                return Err(AppendError::WrongShard {
                    leader_grpc_addr: shard.leader.grpc_addr.clone(),
                    current_shard_map_version: current_version,
                });
            }
            if let Some(min_wm) = min_follower_watermark_segment_seq {
                let cur_wm = self
                    .follower_watermarks
                    .read()
                    .await
                    .get(&shard.shard_id)
                    .copied()
                    .unwrap_or(0);
                if cur_wm < min_wm {
                    return Err(AppendError::FailedPrecondition(
                        serde_json::json!({
                            "code": "FOLLOWER_WATERMARK_BEHIND",
                            "message": format!("follower watermark behind: have {} need {}", cur_wm, min_wm),
                            "shardId": shard.shard_id,
                            "followerWatermarkSegmentSeq": cur_wm,
                            "requiredMinFollowerWatermarkSegmentSeq": min_wm,
                            "currentShardMapVersion": current_version
                        })
                        .to_string(),
                    ));
                }
            }
        }

        let owner_gpu_id = shard.gpu_id.unwrap_or(self.default_gpu_id);
        let store = self
            .stores_by_gpu
            .get(&owner_gpu_id)
            .cloned()
            .ok_or_else(|| AppendError::ShardUnavailable {
                shard_id: shard.shard_id.clone(),
                owner_gpu_id,
                current_shard_map_version: current_version,
            })?;

        Ok((owner_gpu_id, store))
    }

    pub async fn followers_for_shard(&self, shard_id: &str) -> Result<Vec<NodeAddr>, AppendError> {
        let routing = self.routing.read().await.clone();
        let current_version = routing.current_version();
        let shard = routing
            .shard_map
            .shards
            .iter()
            .find(|s| s.shard_id == shard_id)
            .ok_or_else(|| {
                AppendError::InvalidArgument(format!("unknown shard_id '{shard_id}'"))
            })?;

        if shard.leader.node_id != self.node_id {
            return Err(AppendError::WrongShard {
                leader_grpc_addr: shard.leader.grpc_addr.clone(),
                current_shard_map_version: current_version,
            });
        }

        let mut out: Vec<NodeAddr> = Vec::new();
        if let Some(followers) = shard.followers.as_ref() {
            for f in followers {
                if f.node_id == self.node_id {
                    continue;
                }
                out.push(f.clone());
            }
        }
        Ok(out)
    }

    pub async fn update_follower_watermark(&self, shard_id: &str, segment_seq: u64) {
        let mut wm = self.follower_watermarks.write().await;
        let cur = wm.get(shard_id).copied().unwrap_or(0);
        if segment_seq > cur {
            wm.insert(shard_id.to_string(), segment_seq);
        }
    }

    pub async fn follower_watermarks_snapshot(&self) -> std::collections::HashMap<String, u64> {
        self.follower_watermarks.read().await.clone()
    }

    pub async fn observe_replicated_commit(&self, input: ReplicatedCommitObservationInput) {
        let observed_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let obs = ReplicatedCommitObservation {
            shard_id: input.shard_id.clone(),
            epoch: input.epoch,
            follower_count: input.follower_count,
            required_acks: input.required_acks,
            actual_acks: input.actual_acks,
            result: input.result,
            failure_count: input.failure_count,
            failure_sample: input.failure_sample,
            observed_unix_ms,
            leader_segment_seq: input.leader_segment_seq,
            min_follower_acked_segment_seq: input.min_follower_acked_segment_seq,
            lag_segments: input
                .leader_segment_seq
                .saturating_sub(input.min_follower_acked_segment_seq),
        };
        self.replicated_commit_observations
            .write()
            .await
            .insert(input.shard_id, obs);
    }

    pub async fn replicated_commit_observations_snapshot(
        &self,
    ) -> std::collections::HashMap<String, ReplicatedCommitObservation> {
        self.replicated_commit_observations.read().await.clone()
    }

    pub async fn tick_projections_all(&self, max_frames: u32) {
        let gpu_ids: Vec<i32> = self.gpu_ids();
        for gpu_id in gpu_ids {
            let Some(store) = self.stores_by_gpu.get(&gpu_id) else {
                continue;
            };
            let guard = store.read().await;
            let results = guard.tick_projections(max_frames);
            for (shard_id, r) in results {
                tracing::info!(
                    shard_id = %shard_id,
                    gpu_id,
                    frames = r.frames_processed,
                    commit_id = r.commit_id,
                    "projection tick committed"
                );
            }
        }
    }

    /// Force-seal head segments on all shards across all GPUs.
    pub async fn force_seal_all(
        &self,
    ) -> Vec<(String, Result<corecrux_storage::SealResultV1, String>)> {
        let mut out = Vec::new();
        let gpu_ids: Vec<i32> = self.gpu_ids();
        for gpu_id in gpu_ids {
            let Some(store) = self.stores_by_gpu.get(&gpu_id) else {
                continue;
            };
            let guard = store.read().await;
            let results = guard.force_seal_all_shards();
            for (shard_id, r) in results {
                if let Ok(ref seal) = r {
                    tracing::info!(
                        shard_id = %shard_id,
                        gpu_id,
                        sealed = seal.sealed,
                        segment_seq = ?seal.segment_seq,
                        frame_count = ?seal.frame_count,
                        "force seal completed"
                    );
                }
                out.push((shard_id, r));
            }
        }
        out
    }

    /// Force-seal all shards and tick projections on each.
    pub async fn force_seal_all_and_tick(
        &self,
        max_frames: u32,
    ) -> Vec<(
        String,
        Result<crate::dataplane_store::ForceSealAndTickResult, String>,
    )> {
        let mut out = Vec::new();
        let gpu_ids: Vec<i32> = self.gpu_ids();
        for gpu_id in gpu_ids {
            let Some(store) = self.stores_by_gpu.get(&gpu_id) else {
                continue;
            };
            let guard = store.read().await;
            let results = guard.force_seal_all_shards_and_tick(max_frames);
            for (shard_id, r) in results {
                if let Ok(ref res) = r {
                    tracing::info!(
                        shard_id = %shard_id,
                        gpu_id,
                        sealed = res.seal_result.sealed,
                        projection_frames = res.projection_frames_processed,
                        "force seal + projection tick completed"
                    );
                }
                out.push((shard_id, r));
            }
        }
        out
    }

    pub async fn projection_snapshot_issues(
        &self,
    ) -> Vec<crate::dataplane_store::ProjectionSnapshotIssue> {
        let mut out = Vec::new();
        for gpu_id in self.gpu_ids() {
            let Some(store) = self.stores_by_gpu.get(&gpu_id) else {
                continue;
            };
            let guard = store.read().await;
            out.extend(guard.projection_snapshot_issues());
        }
        out
    }

    pub async fn verify_store_integrity_all(
        &self,
        full: bool,
        sample_rate: f64,
        budget_bytes: usize,
        is_scrub: bool,
    ) -> crate::dataplane_store::VerifyStoreSummary {
        let mut merged = crate::dataplane_store::VerifyStoreSummary {
            ok: true,
            scanned_shards: 0,
            failed_shards: 0,
            shards: Vec::new(),
        };
        for gpu_id in self.gpu_ids() {
            let Some(store) = self.stores_by_gpu.get(&gpu_id) else {
                continue;
            };
            let guard = store.read().await;
            let res = guard.verify_store_integrity(full, sample_rate, budget_bytes, is_scrub);
            merged.ok &= res.ok;
            merged.scanned_shards = merged.scanned_shards.saturating_add(res.scanned_shards);
            merged.failed_shards = merged.failed_shards.saturating_add(res.failed_shards);
            merged.shards.extend(res.shards);
        }
        merged
    }

    /// Rebuild projections online using daemon-held shard handles.
    /// Returns per-shard results. Safe to call while the daemon is serving reads.
    pub async fn rebuild_projections_online(
        &self,
        batch_frames: u32,
    ) -> Vec<(
        String,
        Result<corecrux_projections::ProjectionsTickResultV1, String>,
    )> {
        let mut all = Vec::new();
        for gpu_id in self.gpu_ids() {
            let Some(store) = self.stores_by_gpu.get(&gpu_id) else {
                continue;
            };
            let guard = store.read().await;
            all.extend(guard.rebuild_projections_pooled(batch_frames));
        }
        all
    }

}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use tokio::sync::RwLock;

    use corecrux_types::{
        compute_shard_map_v1_blake3_hex, HashRange, NodeAddr, ShardDescriptor, ShardMapV1,
        ShardState, SHARDMAP_HASH_FN_V1, SHARDMAP_KEY_ENCODING_V1, SHARDMAP_V1,
    };

    use super::{DataPlanePool, ReplicatedCommitObservationInput};
    use crate::dataplane_store::AppendError;
    use crate::shard_map::{LoadedShardMap, RoutingTable};

    fn test_node(node_id: &str) -> NodeAddr {
        NodeAddr {
            node_id: node_id.to_string(),
            grpc_addr: format!("http://{node_id}.grpc"),
            http_addr: format!("http://{node_id}.http"),
        }
    }

    fn test_routing() -> RoutingTable {
        let mut map = ShardMapV1 {
            v: SHARDMAP_V1,
            cluster_id: "test".to_string(),
            version: 1,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            hash_fn: SHARDMAP_HASH_FN_V1.to_string(),
            key_encoding: SHARDMAP_KEY_ENCODING_V1.to_string(),
            shards: vec![ShardDescriptor {
                shard_id: "shard-0001".to_string(),
                epoch: 3,
                state: ShardState::Active,
                ranges: vec![HashRange {
                    start_inclusive: "0x0000000000000000".to_string(),
                    end_exclusive: "0x0000000000000000".to_string(),
                }],
                leader: test_node("leader-a"),
                followers: Some(vec![test_node("follower-b")]),
                data_dir: Some("/tmp/corecrux-tests/shard-0001".to_string()),
                gpu_id: Some(0),
            }],
            blake3: String::new(),
            prev_blake3: None,
        };
        map.blake3 = compute_shard_map_v1_blake3_hex(&map).expect("compute shardmap hash");
        RoutingTable::new(LoadedShardMap {
            current_version: 1,
            shard_map: map,
        })
        .expect("routing table builds")
    }

    #[tokio::test]
    async fn writes_are_leader_only_even_when_node_is_follower() {
        let pool = DataPlanePool::new(
            "follower-b".to_string(),
            false,
            0,
            true,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );

        let err = match pool.store_for_stream_hash(42, None).await {
            Ok(_) => panic!("follower must not accept writes"),
            Err(err) => err,
        };
        match err {
            AppendError::WrongShard {
                leader_grpc_addr,
                current_shard_map_version,
            } => {
                assert_eq!(leader_grpc_addr, "http://leader-a.grpc");
                assert_eq!(current_shard_map_version, 1);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn follower_reads_require_explicit_enablement() {
        let pool = DataPlanePool::new(
            "follower-b".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );

        let err = match pool.store_for_stream_hash_read(42, None, None).await {
            Ok(_) => panic!("follower reads disabled should reject"),
            Err(err) => err,
        };
        match err {
            AppendError::WrongShard {
                leader_grpc_addr,
                current_shard_map_version,
            } => {
                assert_eq!(leader_grpc_addr, "http://leader-a.grpc");
                assert_eq!(current_shard_map_version, 1);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn follower_reads_enforce_min_watermark_precondition() {
        let pool = DataPlanePool::new(
            "follower-b".to_string(),
            false,
            0,
            true,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );

        let err = match pool.store_for_stream_hash_read(42, None, Some(10)).await {
            Ok(_) => panic!("follower watermark should gate stale reads"),
            Err(err) => err,
        };
        match err {
            AppendError::FailedPrecondition(msg) => {
                let v: serde_json::Value = serde_json::from_str(&msg).expect("json error body");
                assert_eq!(
                    v.get("code").and_then(|v| v.as_str()),
                    Some("FOLLOWER_WATERMARK_BEHIND")
                );
                assert_eq!(
                    v.get("followerWatermarkSegmentSeq")
                        .and_then(|v| v.as_u64()),
                    Some(0)
                );
                assert_eq!(
                    v.get("requiredMinFollowerWatermarkSegmentSeq")
                        .and_then(|v| v.as_u64()),
                    Some(10)
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn replicated_commit_observations_keep_latest() {
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            0,
            true,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );

        pool.observe_replicated_commit(ReplicatedCommitObservationInput {
            shard_id: "shard-0001".to_string(),
            epoch: 3,
            follower_count: 1,
            required_acks: 1,
            actual_acks: 0,
            result: "unmet".to_string(),
            failure_count: 1,
            failure_sample: Some("follower-b timeout".to_string()),
            leader_segment_seq: 100,
            min_follower_acked_segment_seq: 99,
        })
        .await;
        pool.observe_replicated_commit(ReplicatedCommitObservationInput {
            shard_id: "shard-0001".to_string(),
            epoch: 3,
            follower_count: 1,
            required_acks: 1,
            actual_acks: 1,
            result: "ok".to_string(),
            failure_count: 0,
            failure_sample: None,
            leader_segment_seq: 105,
            min_follower_acked_segment_seq: 105,
        })
        .await;

        let snap = pool.replicated_commit_observations_snapshot().await;
        let obs = snap.get("shard-0001").expect("observation exists");
        assert_eq!(obs.required_acks, 1);
        assert_eq!(obs.actual_acks, 1);
        assert_eq!(obs.result, "ok");
        assert_eq!(obs.failure_count, 0);
        assert_eq!(obs.leader_segment_seq, 105);
        assert_eq!(obs.min_follower_acked_segment_seq, 105);
        assert_eq!(obs.lag_segments, 0);
    }

    #[tokio::test]
    async fn follower_watermark_snapshot_returns_latest_max() {
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            0,
            true,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        pool.update_follower_watermark("shard-0001", 10).await;
        pool.update_follower_watermark("shard-0001", 7).await;
        pool.update_follower_watermark("shard-0001", 12).await;

        let snap = pool.follower_watermarks_snapshot().await;
        assert_eq!(snap.get("shard-0001").copied(), Some(12));
    }

    // --- New tests for uncovered pool.rs paths ---

    #[test]
    fn gpu_ids_returns_sorted_keys() {
        let mut stores = BTreeMap::new();
        let store_a = Arc::new(RwLock::new(
            crate::dataplane_store::DataPlaneStore::new_empty_for_test(),
        ));
        let store_b = Arc::new(RwLock::new(
            crate::dataplane_store::DataPlaneStore::new_empty_for_test(),
        ));
        stores.insert(2, store_a);
        stores.insert(0, store_b);
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            stores,
        );
        assert_eq!(pool.gpu_ids(), vec![0, 2]);
    }

    #[test]
    fn default_gpu_id_returns_configured_value() {
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            7,
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        assert_eq!(pool.default_gpu_id(), 7);
    }

    #[test]
    fn store_for_gpu_id_returns_none_for_missing() {
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        assert!(pool.store_for_gpu_id(99).is_none());
    }

    #[test]
    fn store_for_gpu_id_returns_some_for_existing() {
        let mut stores = BTreeMap::new();
        let store = Arc::new(RwLock::new(
            crate::dataplane_store::DataPlaneStore::new_empty_for_test(),
        ));
        stores.insert(0, store);
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            stores,
        );
        assert!(pool.store_for_gpu_id(0).is_some());
    }

    #[tokio::test]
    async fn strict_client_version_rejects_stale_writes() {
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            true, // strict_client_version
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        // shard map version is 1; pass 999
        let err = pool
            .store_for_stream_hash(42, Some(999))
            .await
            .err().expect("stale version must be rejected");
        match err {
            AppendError::ShardMapVersionMismatch {
                client_version,
                current_version,
            } => {
                assert_eq!(client_version, 999);
                assert_eq!(current_version, 1);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn strict_client_version_rejects_stale_reads() {
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            true, // strict_client_version
            0,
            true,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        let err = pool
            .store_for_stream_hash_read(42, Some(999), None)
            .await
            .err().expect("stale version must be rejected");
        match err {
            AppendError::ShardMapVersionMismatch {
                client_version,
                current_version,
            } => {
                assert_eq!(client_version, 999);
                assert_eq!(current_version, 1);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_for_shard_id_rejects_unknown_shard() {
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        let err = pool
            .store_for_shard_id("nonexistent-shard")
            .await
            .err().expect("unknown shard must be rejected");
        match err {
            AppendError::InvalidArgument(msg) => {
                assert!(msg.contains("nonexistent-shard"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_for_shard_id_rejects_wrong_leader() {
        let pool = DataPlanePool::new(
            "follower-b".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        let err = pool
            .store_for_shard_id("shard-0001")
            .await
            .err().expect("wrong leader must be rejected");
        match err {
            AppendError::WrongShard {
                leader_grpc_addr, ..
            } => {
                assert_eq!(leader_grpc_addr, "http://leader-a.grpc");
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_for_shard_id_returns_unavailable_when_gpu_missing() {
        // Leader matches but no store for gpu_id 0
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            99, // default gpu_id = 99, not in stores
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        let err = pool
            .store_for_shard_id("shard-0001")
            .await
            .err().expect("missing gpu store must return ShardUnavailable");
        match err {
            AppendError::ShardUnavailable {
                shard_id,
                owner_gpu_id,
                ..
            } => {
                assert_eq!(shard_id, "shard-0001");
                assert_eq!(owner_gpu_id, 0); // shard has gpu_id=Some(0)
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_for_replication_shard_unknown_shard() {
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        let err = pool
            .store_for_replication_shard("nonexistent")
            .await
            .err().expect("unknown shard must fail");
        match err {
            AppendError::InvalidArgument(msg) => {
                assert!(msg.contains("nonexistent"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_for_replication_shard_rejects_non_hosted_node() {
        let pool = DataPlanePool::new(
            "unrelated-node".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        let err = pool
            .store_for_replication_shard("shard-0001")
            .await
            .err().expect("not hosted here must fail");
        match err {
            AppendError::WrongShard { .. } => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_for_replication_shard_accepts_follower() {
        let mut stores = BTreeMap::new();
        stores.insert(
            0,
            Arc::new(RwLock::new(
                crate::dataplane_store::DataPlaneStore::new_empty_for_test(),
            )),
        );
        let pool = DataPlanePool::new(
            "follower-b".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            stores,
        );
        let (epoch, gpu_id, _store) = pool
            .store_for_replication_shard("shard-0001")
            .await
            .expect("follower should be accepted for replication");
        assert_eq!(epoch, 3);
        assert_eq!(gpu_id, 0);
    }

    #[tokio::test]
    async fn followers_for_shard_unknown_shard() {
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        let err = pool
            .followers_for_shard("nonexistent")
            .await
            .err().expect("unknown shard must fail");
        match err {
            AppendError::InvalidArgument(msg) => {
                assert!(msg.contains("nonexistent"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn followers_for_shard_rejects_non_leader() {
        let pool = DataPlanePool::new(
            "follower-b".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        let err = pool
            .followers_for_shard("shard-0001")
            .await
            .err().expect("non-leader should fail");
        match err {
            AppendError::WrongShard { .. } => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn followers_for_shard_excludes_self() {
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        let followers = pool
            .followers_for_shard("shard-0001")
            .await
            .expect("should succeed");
        // follower-b is the follower, leader-a is self
        assert_eq!(followers.len(), 1);
        assert_eq!(followers[0].node_id, "follower-b");
    }

    #[tokio::test]
    async fn store_for_stream_delegates_to_store_for_stream_hash() {
        let pool = DataPlanePool::new(
            "follower-b".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        // Should return WrongShard because follower-b is not the leader
        let err = pool
            .store_for_stream("tenant-a", "knowledge", "s-1", None)
            .await
            .err().expect("follower write must be rejected");
        match err {
            AppendError::WrongShard { .. } => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_for_stream_read_delegates_correctly() {
        let mut stores = BTreeMap::new();
        stores.insert(
            0,
            Arc::new(RwLock::new(
                crate::dataplane_store::DataPlaneStore::new_empty_for_test(),
            )),
        );
        let pool = DataPlanePool::new(
            "follower-b".to_string(),
            false,
            0,
            true, // follower reads enabled
            Arc::new(RwLock::new(test_routing())),
            stores,
        );
        // follower-b is a follower, reads enabled, no watermark constraint
        let result = pool
            .store_for_stream_read("tenant-a", "knowledge", "s-1", None, None)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn store_for_shard_u64_unknown_shard() {
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        let err = pool
            .store_for_shard_u64(9999)
            .await
            .err().expect("unknown shard u64 must fail");
        match err {
            AppendError::InvalidArgument(msg) => {
                assert!(msg.contains("9999"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_for_shard_u64_overflow() {
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        let err = pool
            .store_for_shard_u64(u64::MAX)
            .await
            .err().expect("shard_id out of u32 range must fail");
        match err {
            AppendError::InvalidArgument(msg) => {
                assert!(msg.contains("out of range"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_for_shard_u64_read_overflow() {
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            0,
            false,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        let err = pool
            .store_for_shard_u64_read(u64::MAX, None)
            .await
            .err().expect("shard_id out of u32 range must fail");
        match err {
            AppendError::InvalidArgument(msg) => {
                assert!(msg.contains("out of range"));
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_for_shard_u64_read_follower_disabled_rejects() {
        let pool = DataPlanePool::new(
            "follower-b".to_string(),
            false,
            0,
            false, // follower reads disabled
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        // shard-0001 has shard_id "shard-0001" which would parse to u32 = 1
        let err = pool
            .store_for_shard_u64_read(1, None)
            .await
            .err().expect("follower reads disabled must reject");
        match err {
            AppendError::WrongShard { .. } => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_for_shard_u64_read_not_a_follower_rejects() {
        let pool = DataPlanePool::new(
            "random-node".to_string(),
            false,
            0,
            true, // follower reads enabled
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        let err = pool
            .store_for_shard_u64_read(1, None)
            .await
            .err().expect("non-follower must be rejected");
        match err {
            AppendError::WrongShard { .. } => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_for_shard_u64_read_watermark_behind() {
        let mut stores = BTreeMap::new();
        stores.insert(
            0,
            Arc::new(RwLock::new(
                crate::dataplane_store::DataPlaneStore::new_empty_for_test(),
            )),
        );
        let pool = DataPlanePool::new(
            "follower-b".to_string(),
            false,
            0,
            true,
            Arc::new(RwLock::new(test_routing())),
            stores,
        );
        // watermark is 0, require 10
        let err = pool
            .store_for_shard_u64_read(1, Some(10))
            .await
            .err().expect("behind watermark must fail");
        match err {
            AppendError::FailedPrecondition(msg) => {
                let v: serde_json::Value =
                    serde_json::from_str(&msg).expect("json error body");
                assert_eq!(
                    v.get("code").and_then(|v| v.as_str()),
                    Some("FOLLOWER_WATERMARK_BEHIND")
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_for_stream_hash_read_follower_not_in_list() {
        let pool = DataPlanePool::new(
            "random-node".to_string(),
            false,
            0,
            true, // follower reads enabled
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        let err = pool
            .store_for_stream_hash_read(42, None, None)
            .await
            .err().expect("not in follower list must fail");
        match err {
            AppendError::WrongShard { .. } => {}
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn replicated_commit_observation_computes_lag() {
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            0,
            true,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        pool.observe_replicated_commit(ReplicatedCommitObservationInput {
            shard_id: "shard-0001".to_string(),
            epoch: 3,
            follower_count: 1,
            required_acks: 1,
            actual_acks: 1,
            result: "ok".to_string(),
            failure_count: 0,
            failure_sample: None,
            leader_segment_seq: 100,
            min_follower_acked_segment_seq: 95,
        })
        .await;

        let snap = pool.replicated_commit_observations_snapshot().await;
        let obs = snap.get("shard-0001").expect("observation exists");
        assert_eq!(obs.lag_segments, 5);
        assert!(obs.observed_unix_ms > 0);
    }

    #[tokio::test]
    async fn follower_watermark_multiple_shards() {
        let pool = DataPlanePool::new(
            "leader-a".to_string(),
            false,
            0,
            true,
            Arc::new(RwLock::new(test_routing())),
            BTreeMap::new(),
        );
        pool.update_follower_watermark("shard-0001", 10).await;
        pool.update_follower_watermark("shard-0002", 20).await;

        let snap = pool.follower_watermarks_snapshot().await;
        assert_eq!(snap.get("shard-0001").copied(), Some(10));
        assert_eq!(snap.get("shard-0002").copied(), Some(20));
        assert_eq!(snap.len(), 2);
    }
}
