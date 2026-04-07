// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Receipted key-value entity fact store.
//!
//! Facts are lightweight key-value pairs associated with entities. They carry
//! a source receipt reference and confidence score. The store supports BM25-style
//! keyword search over fact values and soft-delete via tombstone events.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A single fact in the store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fact {
    pub fact_id: String,
    pub entity: String,
    pub key: String,
    pub value: String,
    pub source_receipt: Option<String>,
    pub confidence: f32,
    pub stored_at: DateTime<Utc>,
    pub tokens: usize,
    pub deleted: bool,
    /// Monotonic version number for this (entity, key) pair. Starts at 1.
    #[serde(default = "default_version")]
    pub version: u32,
    /// The fact_id this fact supersedes (previous version of the same entity+key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
}

fn default_version() -> u32 {
    1
}

/// Request to store a new fact.
#[derive(Debug, Deserialize)]
pub struct StoreFact {
    pub entity: String,
    pub key: String,
    pub value: String,
    pub source_receipt: Option<String>,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
}

fn default_confidence() -> f32 {
    1.0
}

/// Query parameters for fact retrieval.
#[derive(Debug, Deserialize)]
pub struct FactQuery {
    pub query: Option<String>,
    pub entity: Option<String>,
    /// Filter entities starting with this prefix (e.g., `__ops__::` or `__bootstrap__::`)
    #[serde(default)]
    pub entity_prefix: Option<String>,
    #[serde(default = "default_top_k")]
    pub top_k: usize,
    pub token_budget: Option<usize>,
}

fn default_top_k() -> usize {
    10
}

/// In-memory fact store with keyword search.
#[derive(Debug, Default)]
pub struct FactStore {
    facts: HashMap<String, Fact>,
    entity_index: HashMap<String, Vec<String>>,
    /// Index of (entity, key) → ordered list of fact_ids (version chain).
    key_index: HashMap<(String, String), Vec<String>>,
}

impl FactStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a fact and return it. If a fact with the same (entity, key) already
    /// exists, the new fact is assigned the next version number and links to the
    /// previous version via `supersedes`.
    pub fn store(&mut self, req: StoreFact) -> Fact {
        let fact_id = format!("f_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
        let tokens = estimate_tokens(&req.value);

        let key_pair = (req.entity.clone(), req.key.clone());
        let (version, supersedes) = match self.key_index.get(&key_pair) {
            Some(chain) => {
                let prev = chain
                    .iter()
                    .rev()
                    .find_map(|id| self.facts.get(id).filter(|f| !f.deleted));
                match prev {
                    Some(prev_fact) => (prev_fact.version + 1, Some(prev_fact.fact_id.clone())),
                    None => (1, None),
                }
            }
            None => (1, None),
        };

        let fact = Fact {
            fact_id: fact_id.clone(),
            entity: req.entity.clone(),
            key: req.key.clone(),
            value: req.value,
            source_receipt: req.source_receipt,
            confidence: req.confidence,
            stored_at: Utc::now(),
            tokens,
            deleted: false,
            version,
            supersedes,
        };

        self.entity_index.entry(req.entity).or_default().push(fact_id.clone());
        self.key_index.entry(key_pair).or_default().push(fact_id.clone());
        self.facts.insert(fact_id, fact.clone());

        fact
    }

    /// Store multiple facts in a batch.
    pub fn store_bulk(&mut self, reqs: Vec<StoreFact>) -> Vec<Fact> {
        reqs.into_iter().map(|r| self.store(r)).collect()
    }

    /// Soft-delete a fact by ID. Returns true if the fact existed.
    pub fn delete(&mut self, fact_id: &str) -> bool {
        if let Some(fact) = self.facts.get_mut(fact_id) {
            fact.deleted = true;
            true
        } else {
            false
        }
    }

    /// Get a single fact by ID.
    pub fn get(&self, fact_id: &str) -> Option<&Fact> {
        self.facts.get(fact_id).filter(|f| !f.deleted)
    }

    /// Get all facts for an entity.
    pub fn get_by_entity(&self, entity: &str) -> Vec<&Fact> {
        self.entity_index
            .get(entity)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.facts.get(id))
                    .filter(|f| !f.deleted)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Query facts by keyword match (simple substring search).
    /// Returns facts sorted by relevance, limited by top_k or token_budget.
    pub fn query(&self, q: &FactQuery) -> FactQueryResult {
        let mut results: Vec<&Fact> = self
            .facts
            .values()
            .filter(|f| !f.deleted)
            .filter(|f| {
                if let Some(prefix) = &q.entity_prefix {
                    if !f.entity.starts_with(prefix.as_str()) {
                        return false;
                    }
                }
                if let Some(entity) = &q.entity {
                    if &f.entity != entity {
                        return false;
                    }
                }
                true
            })
            .filter(|f| {
                if let Some(query) = &q.query {
                    let query_lower = query.to_lowercase();
                    let terms: Vec<&str> = query_lower.split_whitespace().collect();
                    let value_lower = f.value.to_lowercase();
                    let key_lower = f.key.to_lowercase();
                    let entity_lower = f.entity.to_lowercase();
                    terms
                        .iter()
                        .any(|t| value_lower.contains(t) || key_lower.contains(t) || entity_lower.contains(t))
                } else {
                    true
                }
            })
            .collect();

        // Sort by confidence descending, then by stored_at descending
        results.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.stored_at.cmp(&a.stored_at))
        });

        // Apply token budget or top_k
        let (selected, total_tokens) = if let Some(budget) = q.token_budget {
            let mut used = 0usize;
            let mut sel = Vec::new();
            for f in &results {
                if used + f.tokens > budget && !sel.is_empty() {
                    break;
                }
                used += f.tokens;
                sel.push((*f).clone());
                if used >= budget {
                    break;
                }
            }
            let total = used;
            (sel, total)
        } else {
            results.truncate(q.top_k);
            let total: usize = results.iter().map(|f| f.tokens).sum();
            (results.into_iter().cloned().collect(), total)
        };

        FactQueryResult {
            facts: selected,
            total_tokens,
        }
    }

    /// Return all unique entity names from non-deleted facts, sorted.
    pub fn entities(&self) -> Vec<String> {
        let mut ents: Vec<String> = self
            .entity_index
            .keys()
            .filter(|entity| {
                self.entity_index
                    .get(*entity)
                    .map(|ids| ids.iter().any(|id| self.facts.get(id).map_or(false, |f| !f.deleted)))
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        ents.sort();
        ents
    }

    /// Total number of active (non-deleted) facts.
    pub fn count(&self) -> usize {
        self.facts.values().filter(|f| !f.deleted).count()
    }

    /// Return all versions of a fact for a given (entity, key) pair, ordered by
    /// version ascending. Includes deleted (superseded) versions for audit trail.
    pub fn fact_history(&self, entity: &str, key: &str) -> Vec<&Fact> {
        let key_pair = (entity.to_string(), key.to_string());
        match self.key_index.get(&key_pair) {
            Some(chain) => {
                let mut facts: Vec<&Fact> = chain.iter().filter_map(|id| self.facts.get(id)).collect();
                facts.sort_by_key(|f| f.version);
                facts
            }
            None => Vec::new(),
        }
    }
}

/// Result of a fact query.
#[derive(Debug, Serialize)]
pub struct FactQueryResult {
    pub facts: Vec<Fact>,
    pub total_tokens: usize,
}

/// Estimate token count from text (bytes / 4 approximation).
fn estimate_tokens(text: &str) -> usize {
    (text.len() + 3) / 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_and_retrieve_fact() {
        let mut store = FactStore::new();

        let fact = store.store(StoreFact {
            entity: "deployment".to_string(),
            key: "strategy".to_string(),
            value: "canary deployment with evaluator programme".to_string(),
            source_receipt: Some("crx_123".to_string()),
            confidence: 0.95,
        });

        assert!(fact.fact_id.starts_with("f_"));
        assert_eq!(fact.entity, "deployment");
        assert_eq!(store.count(), 1);

        let retrieved = store.get(&fact.fact_id).unwrap();
        assert_eq!(retrieved.value, "canary deployment with evaluator programme");
    }

    #[test]
    fn query_by_keyword() {
        let mut store = FactStore::new();

        store.store(StoreFact {
            entity: "deployment".to_string(),
            key: "strategy".to_string(),
            value: "canary deployment".to_string(),
            source_receipt: None,
            confidence: 0.9,
        });
        store.store(StoreFact {
            entity: "testing".to_string(),
            key: "approach".to_string(),
            value: "integration tests with real database".to_string(),
            source_receipt: None,
            confidence: 0.8,
        });

        let result = store.query(&FactQuery {
            entity_prefix: None,
            query: Some("deployment".to_string()),
            entity: None,
            top_k: 10,
            token_budget: None,
        });

        assert_eq!(result.facts.len(), 1);
        assert_eq!(result.facts[0].entity, "deployment");
    }

    #[test]
    fn soft_delete() {
        let mut store = FactStore::new();

        let fact = store.store(StoreFact {
            entity: "test".to_string(),
            key: "key".to_string(),
            value: "value".to_string(),
            source_receipt: None,
            confidence: 1.0,
        });

        assert_eq!(store.count(), 1);
        store.delete(&fact.fact_id);
        assert_eq!(store.count(), 0);
        assert!(store.get(&fact.fact_id).is_none());
    }

    #[test]
    fn token_budget_limits_results() {
        let mut store = FactStore::new();

        // Each value is ~10 tokens (40 bytes)
        for i in 0..10 {
            store.store(StoreFact {
                entity: "item".to_string(),
                key: format!("key_{}", i),
                value: format!("this is a value with about forty bytes here-{:02}", i),
                source_receipt: None,
                confidence: 1.0,
            });
        }

        let result = store.query(&FactQuery {
            entity_prefix: None,
            query: None,
            entity: Some("item".to_string()),
            top_k: 100,
            token_budget: Some(25),
        });

        assert!(result.total_tokens <= 25 || result.facts.len() == 1);
    }

    #[test]
    fn get_by_entity_nonexistent() {
        let store = FactStore::new();
        let results = store.get_by_entity("no_such_entity");
        assert!(results.is_empty());
    }

    #[test]
    fn get_by_entity_filters_deleted() {
        let mut store = FactStore::new();

        let f1 = store.store(StoreFact {
            entity: "proj".to_string(),
            key: "name".to_string(),
            value: "alpha".to_string(),
            source_receipt: None,
            confidence: 1.0,
        });
        store.store(StoreFact {
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "active".to_string(),
            source_receipt: None,
            confidence: 1.0,
        });

        store.delete(&f1.fact_id);
        let results = store.get_by_entity("proj");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "status");
    }

    #[test]
    fn store_bulk() {
        let mut store = FactStore::new();

        let reqs = vec![
            StoreFact {
                entity: "a".to_string(),
                key: "k1".to_string(),
                value: "v1".to_string(),
                source_receipt: None,
                confidence: 0.5,
            },
            StoreFact {
                entity: "b".to_string(),
                key: "k2".to_string(),
                value: "v2".to_string(),
                source_receipt: Some("rcpt".to_string()),
                confidence: 0.9,
            },
        ];

        let facts = store.store_bulk(reqs);
        assert_eq!(facts.len(), 2);
        assert_eq!(store.count(), 2);
        assert_eq!(facts[0].entity, "a");
        assert_eq!(facts[1].entity, "b");
    }

    #[test]
    fn query_with_entity_filter() {
        let mut store = FactStore::new();

        store.store(StoreFact {
            entity: "alpha".to_string(),
            key: "info".to_string(),
            value: "shared keyword here".to_string(),
            source_receipt: None,
            confidence: 1.0,
        });
        store.store(StoreFact {
            entity: "beta".to_string(),
            key: "info".to_string(),
            value: "shared keyword here".to_string(),
            source_receipt: None,
            confidence: 1.0,
        });

        let result = store.query(&FactQuery {
            entity_prefix: None,
            query: Some("keyword".to_string()),
            entity: Some("alpha".to_string()),
            top_k: 10,
            token_budget: None,
        });

        assert_eq!(result.facts.len(), 1);
        assert_eq!(result.facts[0].entity, "alpha");
    }

    #[test]
    fn query_no_query_returns_all() {
        let mut store = FactStore::new();

        for i in 0..3 {
            store.store(StoreFact {
                entity: format!("e{}", i),
                key: "k".to_string(),
                value: format!("val{}", i),
                source_receipt: None,
                confidence: 1.0,
            });
        }

        let result = store.query(&FactQuery {
            entity_prefix: None,
            query: None,
            entity: None,
            top_k: 100,
            token_budget: None,
        });

        assert_eq!(result.facts.len(), 3);
    }

    #[test]
    fn query_empty_store() {
        let store = FactStore::new();

        let result = store.query(&FactQuery {
            entity_prefix: None,
            query: Some("anything".to_string()),
            entity: None,
            top_k: 10,
            token_budget: None,
        });

        assert!(result.facts.is_empty());
        assert_eq!(result.total_tokens, 0);
    }

    #[test]
    fn delete_nonexistent_returns_false() {
        let mut store = FactStore::new();
        assert!(!store.delete("nonexistent_id"));
    }

    #[test]
    fn count_empty_store() {
        let store = FactStore::new();
        assert_eq!(store.count(), 0);
    }

    #[test]
    fn query_matches_key_and_entity() {
        let mut store = FactStore::new();

        store.store(StoreFact {
            entity: "server".to_string(),
            key: "deployment_strategy".to_string(),
            value: "unrelated text".to_string(),
            source_receipt: None,
            confidence: 1.0,
        });

        // Query matching key name
        let result = store.query(&FactQuery {
            entity_prefix: None,
            query: Some("deployment".to_string()),
            entity: None,
            top_k: 10,
            token_budget: None,
        });
        assert_eq!(result.facts.len(), 1);

        // Query matching entity name
        let result = store.query(&FactQuery {
            entity_prefix: None,
            query: Some("server".to_string()),
            entity: None,
            top_k: 10,
            token_budget: None,
        });
        assert_eq!(result.facts.len(), 1);
    }

    #[test]
    fn query_no_match() {
        let mut store = FactStore::new();

        store.store(StoreFact {
            entity: "alpha".to_string(),
            key: "info".to_string(),
            value: "some value".to_string(),
            source_receipt: None,
            confidence: 1.0,
        });

        let result = store.query(&FactQuery {
            entity_prefix: None,
            query: Some("zzz_nonexistent_zzz".to_string()),
            entity: None,
            top_k: 10,
            token_budget: None,
        });
        assert!(result.facts.is_empty());
    }

    #[test]
    fn query_sorts_by_confidence_then_time() {
        let mut store = FactStore::new();

        store.store(StoreFact {
            entity: "e".to_string(),
            key: "k".to_string(),
            value: "match low".to_string(),
            source_receipt: None,
            confidence: 0.5,
        });
        store.store(StoreFact {
            entity: "e".to_string(),
            key: "k".to_string(),
            value: "match high".to_string(),
            source_receipt: None,
            confidence: 0.9,
        });

        let result = store.query(&FactQuery {
            entity_prefix: None,
            query: Some("match".to_string()),
            entity: None,
            top_k: 10,
            token_budget: None,
        });

        assert_eq!(result.facts.len(), 2);
        assert!(result.facts[0].confidence >= result.facts[1].confidence);
    }

    #[test]
    fn top_k_limits_results() {
        let mut store = FactStore::new();

        for i in 0..5 {
            store.store(StoreFact {
                entity: "e".to_string(),
                key: format!("k{}", i),
                value: format!("shared term {}", i),
                source_receipt: None,
                confidence: 1.0,
            });
        }

        let result = store.query(&FactQuery {
            entity_prefix: None,
            query: Some("shared".to_string()),
            entity: None,
            top_k: 2,
            token_budget: None,
        });

        assert_eq!(result.facts.len(), 2);
    }

    #[test]
    fn token_budget_includes_first_even_if_over() {
        let mut store = FactStore::new();

        // Store one fact with a large value (many tokens)
        store.store(StoreFact {
            entity: "e".to_string(),
            key: "k".to_string(),
            value: "a".repeat(100), // 25 tokens
            source_receipt: None,
            confidence: 1.0,
        });

        // Token budget smaller than the single fact — should still include it
        let result = store.query(&FactQuery {
            entity_prefix: None,
            query: None,
            entity: None,
            top_k: 100,
            token_budget: Some(1),
        });

        assert_eq!(result.facts.len(), 1);
    }

    #[test]
    fn default_confidence_via_serde() {
        let json = r#"{"entity":"e","key":"k","value":"v"}"#;
        let sf: StoreFact = serde_json::from_str(json).unwrap();
        assert_eq!(sf.confidence, 1.0);
    }

    #[test]
    fn default_top_k_via_serde() {
        let json = r#"{}"#;
        let fq: FactQuery = serde_json::from_str(json).unwrap();
        assert_eq!(fq.top_k, 10);
        assert!(fq.query.is_none());
        assert!(fq.entity.is_none());
        assert!(fq.token_budget.is_none());
    }

    #[test]
    fn fact_serde_roundtrip() {
        let mut store = FactStore::new();
        let fact = store.store(StoreFact {
            entity: "e".to_string(),
            key: "k".to_string(),
            value: "v".to_string(),
            source_receipt: Some("r".to_string()),
            confidence: 0.75,
        });

        let json = serde_json::to_string(&fact).unwrap();
        let deserialized: Fact = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.fact_id, fact.fact_id);
        assert_eq!(deserialized.confidence, 0.75);
        assert!(!deserialized.deleted);
    }

    #[test]
    fn estimate_tokens_fn() {
        assert_eq!(estimate_tokens(""), 0); // (0+3)/4 = 0
        assert_eq!(estimate_tokens("a"), 1); // (1+3)/4 = 1
        assert_eq!(estimate_tokens("abcd"), 1); // (4+3)/4 = 1
        assert_eq!(estimate_tokens("abcde"), 2); // (5+3)/4 = 2
    }
}
