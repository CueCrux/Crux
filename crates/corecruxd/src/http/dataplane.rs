// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP dataplane shim — proxies to the gRPC dataplane when a CPU-only build needs an HTTP fallback path.

use std::sync::Arc;

use corecrux_frame::stream_hash_xxhash64;
use corecrux_proto::dataplane_v1::AppendEvent;
use corecrux_receipts::{VerificationReportV1, STREAM_TYPE_RECEIPT};
use corecrux_types::parse_shard_id_u32;

use crate::dataplane_store::{
    AppendError, ForceSealAndTickResult, ProjectionDependentRowV1, ProjectionPressureEventRowV1,
    ProjectionRelationRowV1, StoredEvent,
};

#[derive(Debug)]
pub(crate) enum HttpDataplaneError {
    Disabled,
    Store(AppendError),
}

impl From<AppendError> for HttpDataplaneError {
    fn from(value: AppendError) -> Self {
        Self::Store(value)
    }
}

pub(crate) type SharedHttpDataplane = Arc<dyn HttpDataplane>;

pub(crate) fn pool_backed_http_dataplane(pool: Option<crate::pool::DataPlanePool>) -> SharedHttpDataplane {
    Arc::new(PoolBackedHttpDataplane { pool })
}

#[derive(Debug, Clone)]
pub(crate) struct GraphExpandRequest<'a> {
    pub tenant_id: &'a str,
    pub seed_artifact_ids: &'a [u32],
    pub edge_types: &'a [String],
    pub max_hops: u32,
    pub budget: usize,
    pub min_confidence: f32,
    pub include_state: bool,
}

#[tonic::async_trait]
pub(crate) trait HttpDataplane: Send + Sync {
    fn enabled(&self) -> bool;

    async fn append_batch(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        expected_next_seq: u64,
        events: &[AppendEvent],
    ) -> Result<(), HttpDataplaneError>;

    async fn read_stream(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        from_seq: u64,
        max_events: u32,
    ) -> Result<Vec<StoredEvent>, HttpDataplaneError>;

    async fn read_tail(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        count: u32,
    ) -> Result<Vec<StoredEvent>, HttpDataplaneError>;

    async fn verify_receipt_stream(
        &self,
        tenant_id: &str,
        receipt_id: &str,
        shard_id_hint: Option<u32>,
    ) -> Result<Option<VerificationReportV1>, HttpDataplaneError>;

    async fn graph_expand(
        &self,
        req: GraphExpandRequest<'_>,
    ) -> Result<corecrux_projections::query::graph_expand::GraphExpandResponse, HttpDataplaneError>;

    async fn time_range(
        &self,
        tenant_id: &str,
        start_micros: i64,
        end_micros: i64,
        artifact_ids: &[u32],
        include_relations: bool,
        limit: usize,
    ) -> Result<corecrux_projections::query::time_range::TimeRangeResponse, HttpDataplaneError>;

    async fn projection_meta(
        &self,
        shard_id: &str,
    ) -> Result<Option<corecrux_projections::ProjectionsMetaV1>, HttpDataplaneError>;

    async fn projection_artifact_state(
        &self,
        tenant_id: &str,
        artifact_id: u32,
    ) -> Result<Option<corecrux_projections::LivingStateRowV1>, HttpDataplaneError>;

    async fn projection_relations(
        &self,
        tenant_id: &str,
        artifact_id: u32,
        direction: &str,
        relation_type: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ProjectionRelationRowV1>, HttpDataplaneError>;

    async fn projection_dependents(
        &self,
        tenant_id: &str,
        artifact_id: u32,
        dependent_type: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ProjectionDependentRowV1>, HttpDataplaneError>;

    async fn projection_pressure_events(
        &self,
        tenant_id: &str,
        artifact_id: u32,
        open_only: bool,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ProjectionPressureEventRowV1>, HttpDataplaneError>;

    async fn rebuild_projections_online(
        &self,
        max_frames: u32,
    ) -> Result<Vec<(String, Result<ForceSealAndTickResult, String>)>, HttpDataplaneError>;

    async fn entity_count(
        &self,
        tenant_id: &str,
        entity_type: &str,
        predicate: &str,
    ) -> Result<Vec<String>, HttpDataplaneError>;

    async fn entity_timeline(
        &self,
        tenant_id: &str,
        entity_type: &str,
        predicate: &str,
    ) -> Result<Vec<(String, String, i64)>, HttpDataplaneError>;

    async fn entity_current_state(
        &self,
        tenant_id: &str,
        entity_name: &str,
        predicate: &str,
    ) -> Result<Option<(String, i64, Option<String>, Option<i64>)>, HttpDataplaneError>;
}

#[derive(Clone)]
struct PoolBackedHttpDataplane {
    pool: Option<crate::pool::DataPlanePool>,
}

impl PoolBackedHttpDataplane {
    fn pool(&self) -> Result<&crate::pool::DataPlanePool, HttpDataplaneError> {
        self.pool.as_ref().ok_or(HttpDataplaneError::Disabled)
    }

    async fn store_for_stream(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
    ) -> Result<crate::pool::StoreHandle, HttpDataplaneError> {
        let (_decision, store) = self
            .pool()?
            .store_for_stream(tenant_id, stream_type, stream_id, None)
            .await
            .map_err(HttpDataplaneError::Store)?;
        Ok(store)
    }

    async fn store_for_stream_hash(
        &self,
        stream_hash: u64,
    ) -> Result<(crate::shard_map::RouteDecision, crate::pool::StoreHandle), HttpDataplaneError> {
        self.pool()?
            .store_for_stream_hash(stream_hash, None)
            .await
            .map_err(HttpDataplaneError::Store)
    }
}

#[tonic::async_trait]
impl HttpDataplane for PoolBackedHttpDataplane {
    fn enabled(&self) -> bool {
        self.pool.is_some()
    }

    async fn append_batch(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        expected_next_seq: u64,
        events: &[AppendEvent],
    ) -> Result<(), HttpDataplaneError> {
        let store = self.store_for_stream(tenant_id, stream_type, stream_id).await?;
        let store = store.read().await;
        store
            .append_batch(tenant_id, stream_type, stream_id, expected_next_seq, None, events)
            .await
            .map(|_| ())
            .map_err(HttpDataplaneError::Store)
    }

    async fn read_stream(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        from_seq: u64,
        max_events: u32,
    ) -> Result<Vec<StoredEvent>, HttpDataplaneError> {
        let store = self.store_for_stream(tenant_id, stream_type, stream_id).await?;
        let store = store.read().await;
        store
            .read_stream(tenant_id, stream_type, stream_id, from_seq, max_events, None)
            .await
            .map_err(HttpDataplaneError::Store)
    }

    async fn read_tail(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        count: u32,
    ) -> Result<Vec<StoredEvent>, HttpDataplaneError> {
        let store = self.store_for_stream(tenant_id, stream_type, stream_id).await?;
        let store = store.read().await;
        store
            .read_tail(tenant_id, stream_type, stream_id, count, None)
            .await
            .map_err(HttpDataplaneError::Store)
    }

    async fn verify_receipt_stream(
        &self,
        tenant_id: &str,
        receipt_id: &str,
        shard_id_hint: Option<u32>,
    ) -> Result<Option<VerificationReportV1>, HttpDataplaneError> {
        let stream_hash = stream_hash_xxhash64(tenant_id, STREAM_TYPE_RECEIPT, receipt_id)
            .map_err(|err| HttpDataplaneError::Store(AppendError::InvalidArgument(err.to_string())))?;
        let (decision, store) = self.store_for_stream_hash(stream_hash).await?;
        let shard_id = match shard_id_hint {
            Some(shard_id) => shard_id,
            None => parse_shard_id_u32(&decision.shard_id)
                .map_err(|err| HttpDataplaneError::Store(AppendError::Internal(err.to_string())))?,
        };
        let store = store.read().await;
        store
            .verify_receipt_stream_v1(shard_id, tenant_id, receipt_id)
            .map_err(HttpDataplaneError::Store)
    }

    async fn graph_expand(
        &self,
        req: GraphExpandRequest<'_>,
    ) -> Result<corecrux_projections::query::graph_expand::GraphExpandResponse, HttpDataplaneError> {
        let edge_types: Vec<corecrux_projections::RelationTypeV1> = req
            .edge_types
            .iter()
            .filter_map(|value| corecrux_projections::RelationTypeV1::from_engine_str(value))
            .collect();
        let pool = self.pool()?;
        let mut combined = corecrux_projections::query::graph_expand::GraphExpandResponse {
            artifacts: Vec::new(),
            stats: Default::default(),
        };

        for gpu_id in pool.gpu_ids() {
            let Some(store) = pool.store_for_gpu_id(gpu_id) else {
                continue;
            };
            let store = store.read().await;
            let response = store.query_graph_expand(
                req.tenant_id,
                req.seed_artifact_ids,
                &edge_types,
                req.max_hops,
                req.budget,
                req.min_confidence,
                req.include_state,
            );
            combined.stats.nodes_visited += response.stats.nodes_visited;
            combined.stats.edges_traversed += response.stats.edges_traversed;
            combined.stats.hops_used = combined.stats.hops_used.max(response.stats.hops_used);
            combined.artifacts.extend(response.artifacts);
        }

        combined.artifacts.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        combined.artifacts.dedup_by_key(|artifact| artifact.artifact_id);
        combined.artifacts.truncate(req.budget);
        combined.stats.budget_remaining = req.budget.saturating_sub(combined.artifacts.len());

        Ok(combined)
    }

    async fn time_range(
        &self,
        tenant_id: &str,
        start_micros: i64,
        end_micros: i64,
        artifact_ids: &[u32],
        include_relations: bool,
        limit: usize,
    ) -> Result<corecrux_projections::query::time_range::TimeRangeResponse, HttpDataplaneError> {
        let pool = self.pool()?;
        let mut artifacts = Vec::new();
        let mut stats = corecrux_projections::query::time_range::TimeRangeStats::default();

        for gpu_id in pool.gpu_ids() {
            let Some(store) = pool.store_for_gpu_id(gpu_id) else {
                continue;
            };
            let store = store.read().await;
            let response = store.query_time_range(
                tenant_id,
                start_micros,
                end_micros,
                artifact_ids,
                include_relations,
                limit,
            );
            stats.artifacts_scanned += response.stats.artifacts_scanned;
            stats.relations_scanned += response.stats.relations_scanned;
            stats.total_changes += response.stats.total_changes;
            artifacts.extend(response.artifacts);
        }

        artifacts.sort_by(|left, right| {
            right
                .current_state
                .updated_at_micros
                .cmp(&left.current_state.updated_at_micros)
        });
        artifacts.dedup_by_key(|artifact| artifact.artifact_id);
        artifacts.truncate(limit);

        Ok(corecrux_projections::query::time_range::TimeRangeResponse { artifacts, stats })
    }

    async fn projection_meta(
        &self,
        shard_id: &str,
    ) -> Result<Option<corecrux_projections::ProjectionsMetaV1>, HttpDataplaneError> {
        let (_owner_gpu_id, store) = self
            .pool()?
            .store_for_shard_id(shard_id)
            .await
            .map_err(HttpDataplaneError::Store)?;
        let shard_id_u32 = parse_shard_id_u32(shard_id)
            .map_err(|err| HttpDataplaneError::Store(AppendError::InvalidArgument(err.to_string())))?;
        let store = store.read().await;
        Ok(store.projections_meta_for_shard(shard_id_u32))
    }

    async fn projection_artifact_state(
        &self,
        tenant_id: &str,
        artifact_id: u32,
    ) -> Result<Option<corecrux_projections::LivingStateRowV1>, HttpDataplaneError> {
        let stream_hash = stream_hash_xxhash64(tenant_id, "artifact", &artifact_id.to_string())
            .map_err(|err| HttpDataplaneError::Store(AppendError::InvalidArgument(err.to_string())))?;
        let (decision, store) = self.store_for_stream_hash(stream_hash).await?;
        let shard_id_u32 = parse_shard_id_u32(&decision.shard_id)
            .map_err(|err| HttpDataplaneError::Store(AppendError::Internal(err.to_string())))?;
        let store = store.read().await;
        Ok(store.projections_living_state_row(shard_id_u32, tenant_id, artifact_id))
    }

    async fn projection_relations(
        &self,
        tenant_id: &str,
        artifact_id: u32,
        direction: &str,
        relation_type: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ProjectionRelationRowV1>, HttpDataplaneError> {
        let relation_type_u8 = relation_type.and_then(|value| {
            corecrux_projections::RelationTypeV1::from_engine_str(value).map(|relation| relation.to_u8())
        });
        let stream_hash = stream_hash_xxhash64(tenant_id, "artifact", &artifact_id.to_string())
            .map_err(|err| HttpDataplaneError::Store(AppendError::InvalidArgument(err.to_string())))?;
        let (decision, store) = self.store_for_stream_hash(stream_hash).await?;
        let shard_id_u32 = parse_shard_id_u32(&decision.shard_id)
            .map_err(|err| HttpDataplaneError::Store(AppendError::Internal(err.to_string())))?;
        let store = store.read().await;
        Ok(store.projections_list_relations(
            shard_id_u32,
            tenant_id,
            artifact_id,
            direction,
            relation_type_u8,
            limit,
            offset,
        ))
    }

    async fn projection_dependents(
        &self,
        tenant_id: &str,
        artifact_id: u32,
        dependent_type: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ProjectionDependentRowV1>, HttpDataplaneError> {
        let dependent_type_u8 = dependent_type.and_then(|value| {
            corecrux_projections::DependentTypeV1::from_engine_str(value).map(|dependent| dependent.to_u8())
        });
        let stream_hash = stream_hash_xxhash64(tenant_id, "artifact", &artifact_id.to_string())
            .map_err(|err| HttpDataplaneError::Store(AppendError::InvalidArgument(err.to_string())))?;
        let (decision, store) = self.store_for_stream_hash(stream_hash).await?;
        let shard_id_u32 = parse_shard_id_u32(&decision.shard_id)
            .map_err(|err| HttpDataplaneError::Store(AppendError::Internal(err.to_string())))?;
        let store = store.read().await;
        Ok(store.projections_list_dependents(shard_id_u32, tenant_id, artifact_id, dependent_type_u8, limit, offset))
    }

    async fn projection_pressure_events(
        &self,
        tenant_id: &str,
        artifact_id: u32,
        open_only: bool,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ProjectionPressureEventRowV1>, HttpDataplaneError> {
        let stream_hash = stream_hash_xxhash64(tenant_id, "artifact", &artifact_id.to_string())
            .map_err(|err| HttpDataplaneError::Store(AppendError::InvalidArgument(err.to_string())))?;
        let (decision, store) = self.store_for_stream_hash(stream_hash).await?;
        let shard_id_u32 = parse_shard_id_u32(&decision.shard_id)
            .map_err(|err| HttpDataplaneError::Store(AppendError::Internal(err.to_string())))?;
        let store = store.read().await;
        Ok(store.projections_list_pressure_events(shard_id_u32, tenant_id, artifact_id, open_only, limit, offset))
    }

    async fn rebuild_projections_online(
        &self,
        max_frames: u32,
    ) -> Result<Vec<(String, Result<ForceSealAndTickResult, String>)>, HttpDataplaneError> {
        Ok(self.pool()?.rebuild_projections_online(max_frames).await)
    }

    async fn entity_count(
        &self,
        tenant_id: &str,
        entity_type: &str,
        predicate: &str,
    ) -> Result<Vec<String>, HttpDataplaneError> {
        let pool = self.pool()?;
        let mut items = Vec::new();
        for gpu_id in pool.gpu_ids() {
            let Some(store) = pool.store_for_gpu_id(gpu_id) else {
                continue;
            };
            let store = store.read().await;
            items.extend(store.query_entity_count(tenant_id, entity_type, predicate));
        }
        items.sort();
        items.dedup();
        Ok(items)
    }

    async fn entity_timeline(
        &self,
        tenant_id: &str,
        entity_type: &str,
        predicate: &str,
    ) -> Result<Vec<(String, String, i64)>, HttpDataplaneError> {
        let pool = self.pool()?;
        let mut events = Vec::new();
        for gpu_id in pool.gpu_ids() {
            let Some(store) = pool.store_for_gpu_id(gpu_id) else {
                continue;
            };
            let store = store.read().await;
            events.extend(store.query_entity_timeline(tenant_id, entity_type, predicate));
        }
        Ok(events)
    }

    async fn entity_current_state(
        &self,
        tenant_id: &str,
        entity_name: &str,
        predicate: &str,
    ) -> Result<Option<(String, i64, Option<String>, Option<i64>)>, HttpDataplaneError> {
        let pool = self.pool()?;
        for gpu_id in pool.gpu_ids() {
            let Some(store) = pool.store_for_gpu_id(gpu_id) else {
                continue;
            };
            let store = store.read().await;
            if let Some(row) = store.query_entity_current_state(tenant_id, entity_name, predicate) {
                return Ok(Some(row));
            }
        }
        Ok(None)
    }
}
