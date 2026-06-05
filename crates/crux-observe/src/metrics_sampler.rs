// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Periodic metrics sampler that writes metric snapshots as facts.

use std::sync::Arc;

use chrono::Utc;
use corecrux_memory::fact_store::StoreFact;
use corecrux_memory::FactStore;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::schema::{ops_entity, OpsMetricSnapshot, EVT_OPS_METRIC_V1};

/// A single metric reading to be sampled into the fact store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricSnapshot {
    pub name: String,
    pub value: f64,
    pub labels: Vec<(String, String)>,
}

/// Periodically samples metrics and writes them as facts.
///
/// The actual gathering of metrics from Prometheus (or any other source) happens
/// in `corecruxd`. This sampler accepts pre-gathered [`MetricSnapshot`] values
/// and converts them to facts.
pub struct MetricsSampler {
    fact_store: Arc<RwLock<FactStore>>,
    node_id: String,
    interval_secs: u64,
    enabled: bool,
    allowlist: Vec<String>,
}

/// Default metric names to sample.
const DEFAULT_ALLOWLIST: &[&str] = &[
    "corecrux_query_duration_seconds",
    "corecrux_shard_count",
    "corecrux_fact_count",
    "corecrux_memory_bytes",
    "corecrux_active_sessions",
];

impl MetricsSampler {
    /// Create a new sampler with default configuration.
    pub fn new(fact_store: Arc<RwLock<FactStore>>, node_id: String, enabled: bool) -> Self {
        Self {
            fact_store,
            node_id,
            interval_secs: 30,
            enabled,
            allowlist: DEFAULT_ALLOWLIST.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// Create a sampler with custom interval and allowlist.
    pub fn with_config(
        fact_store: Arc<RwLock<FactStore>>,
        node_id: String,
        enabled: bool,
        interval_secs: u64,
        allowlist: Vec<String>,
    ) -> Self {
        Self {
            fact_store,
            node_id,
            interval_secs,
            enabled,
            allowlist,
        }
    }

    /// Returns the configured sampling interval in seconds.
    pub fn interval_secs(&self) -> u64 {
        self.interval_secs
    }

    /// Returns whether the sampler is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns the allowlist of metric names.
    pub fn allowlist(&self) -> &[String] {
        &self.allowlist
    }

    /// Write one round of metric snapshots as facts.
    ///
    /// Filters the supplied snapshots against the allowlist. Only metrics whose
    /// name appears in the allowlist (or if the allowlist is empty, all metrics)
    /// are written.
    pub async fn sample_once(&self, snapshots: Vec<MetricSnapshot>) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }

        let timestamp = Utc::now();
        let mut fact_ids = Vec::new();

        let filtered: Vec<_> = if self.allowlist.is_empty() {
            snapshots
        } else {
            snapshots
                .into_iter()
                .filter(|s| self.allowlist.contains(&s.name))
                .collect()
        };

        let mut store = self.fact_store.write().await;

        for snapshot in filtered {
            let id = uuid::Uuid::new_v4().to_string();
            let entity = ops_entity("metric", &id);

            let evt = OpsMetricSnapshot {
                event_type: EVT_OPS_METRIC_V1.to_string(),
                node_id: self.node_id.clone(),
                metric_name: snapshot.name.clone(),
                value: snapshot.value,
                labels: snapshot.labels,
                timestamp,
            };

            let value = serde_json::to_string(&evt).unwrap_or_default();
            let fact = store.store(StoreFact {
                entity,
                key: EVT_OPS_METRIC_V1.to_string(),
                value,
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });

            fact_ids.push(fact.fact_id);
        }

        fact_ids
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sample_once_writes_facts() {
        let store = Arc::new(RwLock::new(FactStore::new()));
        let sampler = MetricsSampler::new(Arc::clone(&store), "test-node".to_string(), true);

        let snapshots = vec![
            MetricSnapshot {
                name: "corecrux_query_duration_seconds".to_string(),
                value: 0.025,
                labels: vec![("method".to_string(), "GET".to_string())],
            },
            MetricSnapshot {
                name: "corecrux_shard_count".to_string(),
                value: 4.0,
                labels: vec![],
            },
        ];

        let ids = sampler.sample_once(snapshots).await;
        assert_eq!(ids.len(), 2);

        let s = store.read().await;
        assert_eq!(s.count(), 2);
        for id in &ids {
            let fact = s.get(id).unwrap();
            assert!(fact.entity.starts_with("__ops__::metric:"));
            assert_eq!(fact.key, "ops.metric.v1");
        }
    }

    #[tokio::test]
    async fn sample_once_disabled_writes_nothing() {
        let store = Arc::new(RwLock::new(FactStore::new()));
        let sampler = MetricsSampler::new(Arc::clone(&store), "test-node".to_string(), false);

        let snapshots = vec![MetricSnapshot {
            name: "corecrux_query_duration_seconds".to_string(),
            value: 1.0,
            labels: vec![],
        }];

        let ids = sampler.sample_once(snapshots).await;
        assert!(ids.is_empty());

        let s = store.read().await;
        assert_eq!(s.count(), 0);
    }

    #[tokio::test]
    async fn sample_once_filters_by_allowlist() {
        let store = Arc::new(RwLock::new(FactStore::new()));
        let sampler = MetricsSampler::new(Arc::clone(&store), "test-node".to_string(), true);

        let snapshots = vec![
            MetricSnapshot {
                name: "corecrux_shard_count".to_string(),
                value: 4.0,
                labels: vec![],
            },
            MetricSnapshot {
                name: "not_in_allowlist_metric".to_string(),
                value: 99.0,
                labels: vec![],
            },
        ];

        let ids = sampler.sample_once(snapshots).await;
        // Only the allowlisted metric should be written.
        assert_eq!(ids.len(), 1);
    }

    #[test]
    fn default_config() {
        let store = Arc::new(RwLock::new(FactStore::new()));
        let sampler = MetricsSampler::new(store, "n1".to_string(), true);
        assert_eq!(sampler.interval_secs(), 30);
        assert!(sampler.is_enabled());
        assert_eq!(sampler.allowlist().len(), DEFAULT_ALLOWLIST.len());
    }

    #[test]
    fn custom_config() {
        let store = Arc::new(RwLock::new(FactStore::new()));
        let sampler =
            MetricsSampler::with_config(store, "n2".to_string(), false, 60, vec!["custom_metric".to_string()]);
        assert_eq!(sampler.interval_secs(), 60);
        assert!(!sampler.is_enabled());
        assert_eq!(sampler.allowlist(), &["custom_metric".to_string()]);
    }
}
