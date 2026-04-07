// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Cold gate — pulls bootstrap facts for cold-start queries before any
//! operational data has been accumulated.

use std::sync::Arc;

use tokio::sync::RwLock;

use corecrux_memory::fact_store::{Fact, FactQuery, FactStore};

use crate::schema::BOOTSTRAP_PREFIX;

/// Gate that serves bootstrap-only facts for cold-start scenarios.
pub struct ColdGate {
    fact_store: Arc<RwLock<FactStore>>,
}

/// Result of a cold pull.
pub struct ColdPullResult {
    pub facts: Vec<Fact>,
    pub total_tokens: usize,
    pub source: String,
}

impl ColdGate {
    pub fn new(fact_store: Arc<RwLock<FactStore>>) -> Self {
        Self { fact_store }
    }

    /// Pull bootstrap facts matching the given query. Only returns facts under
    /// the `__bootstrap__::` entity prefix.
    pub async fn pull(&self, query: &str, top_k: usize, token_budget: Option<usize>) -> ColdPullResult {
        let store = self.fact_store.read().await;
        let result = store.query(&FactQuery {
            query: Some(query.to_string()),
            entity: None,
            entity_prefix: Some(BOOTSTRAP_PREFIX.to_string()),
            top_k,
            token_budget,
        });

        ColdPullResult {
            facts: result.facts,
            total_tokens: result.total_tokens,
            source: "__bootstrap__".to_string(),
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::BootstrapSeeder;
    use corecrux_memory::fact_store::StoreFact;

    fn make_store() -> Arc<RwLock<FactStore>> {
        Arc::new(RwLock::new(FactStore::new()))
    }

    #[tokio::test]
    async fn pull_from_empty_store_returns_empty() {
        let store = make_store();
        let gate = ColdGate::new(store);

        let result = gate.pull("anything", 10, None).await;
        assert!(result.facts.is_empty());
        assert_eq!(result.total_tokens, 0);
        assert_eq!(result.source, "__bootstrap__");
    }

    #[tokio::test]
    async fn pull_returns_only_bootstrap_facts() {
        let store = make_store();

        // Seed bootstrap data
        let seeder = BootstrapSeeder::new(Arc::clone(&store));
        seeder.seed().await;

        // Add an ops fact that matches the same query
        {
            let mut s = store.write().await;
            s.store(StoreFact {
                entity: "__ops__::error:e1".to_string(),
                key: "disk error".to_string(),
                value: "Segment file read failed on shard 3".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            });
        }

        let gate = ColdGate::new(Arc::clone(&store));

        // "segment" should match bootstrap resolutions but NOT the ops fact
        let result = gate.pull("segment", 100, None).await;

        assert!(!result.facts.is_empty());
        for fact in &result.facts {
            assert!(
                fact.entity.starts_with("__bootstrap__::"),
                "expected bootstrap entity, got: {}",
                fact.entity
            );
        }
        assert_eq!(result.source, "__bootstrap__");
    }

    #[tokio::test]
    async fn token_budget_limits_results() {
        let store = make_store();

        let seeder = BootstrapSeeder::new(Arc::clone(&store));
        seeder.seed().await;

        let gate = ColdGate::new(Arc::clone(&store));

        // Pull with a very small token budget
        let limited = gate.pull("error", 100, Some(20)).await;
        let unlimited = gate.pull("error", 100, None).await;

        assert!(limited.total_tokens <= 20 || limited.facts.len() == 1);
        // Unlimited should return at least as many facts
        assert!(unlimited.facts.len() >= limited.facts.len());
    }

    #[tokio::test]
    async fn source_is_always_bootstrap() {
        let store = make_store();
        let gate = ColdGate::new(store);

        let result = gate.pull("anything", 10, None).await;
        assert_eq!(result.source, "__bootstrap__");
    }
}
