// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Receipted key-value entity fact store.
//!
//! Facts are lightweight key-value pairs associated with entities. They carry
//! a source receipt reference and confidence score. The store supports BM25-style
//! keyword search over fact values and soft-delete via tombstone events.

use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Journal event for fact persistence.
#[derive(Serialize, Deserialize)]
#[serde(tag = "op")]
enum JournalEvent {
    #[serde(rename = "store")]
    Store { fact: Fact },
    #[serde(rename = "delete")]
    Delete { fact_id: String, deleted_at: String },
}

/// A single fact in the store.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
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
    /// Private facts are never pushed to a remote during sync.
    #[serde(default)]
    pub private: bool,
}

fn default_version() -> u32 {
    1
}

/// Request to store a new fact.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct StoreFact {
    pub entity: String,
    pub key: String,
    pub value: String,
    pub source_receipt: Option<String>,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    /// If true, this fact will never be pushed to a remote during sync.
    #[serde(default)]
    pub private: bool,
}

fn default_confidence() -> f32 {
    1.0
}

/// Query parameters for fact retrieval.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
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

/// In-memory fact store with keyword search and optional JSONL persistence.
#[derive(Debug, Default)]
pub struct FactStore {
    facts: HashMap<String, Fact>,
    entity_index: HashMap<String, Vec<String>>,
    /// Index of (entity, key) → ordered list of fact_ids (version chain).
    key_index: HashMap<(String, String), Vec<String>>,
    /// Path to the JSONL journal file. `None` for pure in-memory mode.
    journal_path: Option<PathBuf>,
    /// Optional event bus for real-time mutation notifications.
    event_bus: Option<crate::events::EventBus>,
    /// Optional embedding client for dense vector retrieval.
    embedding_client: Option<crate::embeddings::EmbeddingClient>,
    /// Stored embeddings keyed by fact_id.
    embeddings: HashMap<String, Vec<f32>>,
}

impl FactStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach an event bus so that `store()` and `delete()` emit real-time events.
    pub fn set_event_bus(&mut self, bus: crate::events::EventBus) {
        self.event_bus = Some(bus);
    }

    /// Attach an embedding client for dense vector retrieval.
    /// When set, facts are embedded at store time and queries use cosine
    /// similarity blended with keyword matching for ranking.
    pub fn set_embedding_client(&mut self, client: crate::embeddings::EmbeddingClient) {
        tracing::info!(
            model = %client.model(),
            base_url = %client.base_url(),
            "fact-store-embeddings-enabled"
        );
        self.embedding_client = Some(client);
    }

    /// Returns true if an embedding client is configured.
    pub fn embeddings_enabled(&self) -> bool {
        self.embedding_client.is_some()
    }

    /// Create a fact store backed by a JSONL journal in `data_dir`.
    ///
    /// If `data_dir/facts.jsonl` exists, it is replayed to rebuild in-memory
    /// state. Subsequent `store()` and `delete()` calls append to the journal.
    pub fn with_persistence(data_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let journal_path = data_dir.join("facts.jsonl");
        let mut store = Self {
            facts: HashMap::new(),
            entity_index: HashMap::new(),
            key_index: HashMap::new(),
            journal_path: Some(journal_path.clone()),
            event_bus: None,
            embedding_client: None,
            embeddings: HashMap::new(),
        };
        if journal_path.exists() {
            store.replay_journal(&journal_path)?;
        }
        Ok(store)
    }

    /// Append a journal event to the JSONL file. Best-effort: logs a warning
    /// on IO error but never panics or propagates the error.
    fn append_journal(&self, event: &JournalEvent) {
        if let Some(path) = &self.journal_path {
            let result = (|| -> std::io::Result<()> {
                let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
                let line = serde_json::to_string(event).map_err(std::io::Error::other)?;
                writeln!(file, "{}", line)?;
                Ok(())
            })();
            if let Err(err) = result {
                tracing::warn!(?err, path = %path.display(), "fact-journal-append-failed");
            }
        }
    }

    /// Replay a JSONL journal file to rebuild in-memory state.
    /// Corrupted or blank lines are skipped with a warning.
    fn replay_journal(&mut self, path: &Path) -> std::io::Result<()> {
        let file = std::fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        for (line_no, line) in reader.lines().enumerate() {
            let line = line?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<JournalEvent>(trimmed) {
                Ok(JournalEvent::Store { fact }) => {
                    self.replay_journal_insert(fact);
                }
                Ok(JournalEvent::Delete { fact_id, .. }) => {
                    if let Some(fact) = self.facts.get_mut(&fact_id) {
                        fact.deleted = true;
                    }
                }
                Err(err) => {
                    tracing::warn!(line_no = line_no + 1, ?err, "fact-journal-parse-skip");
                }
            }
        }
        Ok(())
    }

    /// Insert a fact directly into the HashMap and indexes WITHOUT appending
    /// to the journal. Used during replay to avoid re-writing events.
    fn replay_journal_insert(&mut self, fact: Fact) {
        let fact_id = fact.fact_id.clone();
        let entity = fact.entity.clone();
        let key = fact.key.clone();
        self.entity_index
            .entry(entity.clone())
            .or_default()
            .push(fact_id.clone());
        self.key_index.entry((entity, key)).or_default().push(fact_id.clone());
        self.facts.insert(fact_id, fact);
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
            private: req.private,
        };

        self.entity_index.entry(req.entity).or_default().push(fact_id.clone());
        self.key_index.entry(key_pair).or_default().push(fact_id.clone());
        self.facts.insert(fact_id, fact.clone());

        self.append_journal(&JournalEvent::Store { fact: fact.clone() });

        // Embed the fact value if an embedding client is configured.
        if let Some(client) = &self.embedding_client {
            let text = format!("{} {} {}", fact.entity, fact.key, fact.value);
            match client.embed_one(&text) {
                Ok(vec) => {
                    self.embeddings.insert(fact.fact_id.clone(), vec);
                }
                Err(err) => {
                    tracing::warn!(?err, fact_id = %fact.fact_id, "fact-embed-failed");
                }
            }
        }

        if let Some(bus) = &self.event_bus {
            bus.emit(crate::events::CruxEvent::FactStored {
                fact_id: fact.fact_id.clone(),
                entity: fact.entity.clone(),
                key: fact.key.clone(),
            });
        }

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
            self.append_journal(&JournalEvent::Delete {
                fact_id: fact_id.to_string(),
                deleted_at: Utc::now().to_rfc3339(),
            });
            if let Some(bus) = &self.event_bus {
                bus.emit(crate::events::CruxEvent::FactDeleted {
                    fact_id: fact_id.to_string(),
                });
            }
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
                // When embeddings are enabled, skip keyword filtering — cosine
                // similarity handles relevance ranking instead.
                if self.embedding_client.is_some() {
                    return true;
                }
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

        // If embeddings are available and a query is provided, compute cosine
        // similarity and blend it with confidence for ranking. Otherwise fall
        // back to confidence + recency.
        let query_embedding = match (&self.embedding_client, &q.query) {
            (Some(client), Some(query_text)) if !query_text.is_empty() => match client.embed_one(query_text) {
                Ok(vec) => Some(vec),
                Err(err) => {
                    tracing::warn!(?err, "query-embed-failed");
                    None
                }
            },
            _ => None,
        };

        if let Some(ref qe) = query_embedding {
            // Score = 0.6 * cosine_similarity + 0.4 * confidence
            results.sort_by(|a, b| {
                let sim_a = self
                    .embeddings
                    .get(&a.fact_id)
                    .map_or(0.0, |v| crate::embeddings::cosine_similarity(v, qe));
                let sim_b = self
                    .embeddings
                    .get(&b.fact_id)
                    .map_or(0.0, |v| crate::embeddings::cosine_similarity(v, qe));
                let score_a = 0.6 * sim_a + 0.4 * a.confidence;
                let score_b = 0.6 * sim_b + 0.4 * b.confidence;
                score_b
                    .partial_cmp(&score_a)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.stored_at.cmp(&a.stored_at))
            });
        } else {
            // Fallback: confidence descending, then recency descending
            results.sort_by(|a, b| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.stored_at.cmp(&a.stored_at))
            });
        }

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
                    .is_some_and(|ids| ids.iter().any(|id| self.facts.get(id).is_some_and(|f| !f.deleted)))
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

    /// Return an iterator over ALL facts (including deleted).
    pub fn all_facts(&self) -> impl Iterator<Item = &Fact> {
        self.facts.values()
    }

    /// Paginated export of ALL facts (including deleted tombstones) for sync.
    ///
    /// Facts are sorted by `(stored_at, fact_id)` ascending. If `since` is set,
    /// only facts with `stored_at >= since` are included. If `cursor` is set,
    /// items are skipped until the fact with `fact_id == cursor` is found, then
    /// the export starts from the next item. Returns at most `limit` facts.
    pub fn export(&self, since: Option<DateTime<Utc>>, cursor: Option<&str>, limit: usize) -> FactExportResult {
        // 1. Collect all facts EXCEPT private ones (private facts never leave this node).
        let mut all: Vec<&Fact> = self.facts.values().filter(|f| !f.private).collect();

        // 2. Sort by (stored_at, fact_id) ascending.
        all.sort_by(|a, b| a.stored_at.cmp(&b.stored_at).then_with(|| a.fact_id.cmp(&b.fact_id)));

        // 3. Filter by `since` if set.
        if let Some(since_dt) = since {
            all.retain(|f| f.stored_at >= since_dt);
        }

        // 4. Skip past cursor if set.
        let start = if let Some(cursor_id) = cursor {
            match all.iter().position(|f| f.fact_id == cursor_id) {
                Some(pos) => pos + 1,
                None => 0, // cursor not found — start from beginning
            }
        } else {
            0
        };

        let remaining = &all[start..];

        // 5. Take `limit` items.
        let has_more = remaining.len() > limit;
        let taken: Vec<Fact> = remaining.iter().take(limit).map(|f| (*f).clone()).collect();
        let next_cursor = if has_more {
            taken.last().map(|f| f.fact_id.clone())
        } else {
            None
        };

        FactExportResult {
            facts: taken,
            next_cursor,
            has_more,
        }
    }

    /// Insert a fact directly with its original identity (fact_id, version,
    /// timestamps). Used for facts arriving from a remote sync — skips version
    /// chain logic but DOES append to the journal for persistence.
    pub fn store_synced(&mut self, fact: Fact) {
        let fact_id = fact.fact_id.clone();
        let entity = fact.entity.clone();
        let key = fact.key.clone();

        self.entity_index
            .entry(entity.clone())
            .or_default()
            .push(fact_id.clone());
        self.key_index.entry((entity, key)).or_default().push(fact_id.clone());
        self.facts.insert(fact_id, fact.clone());

        self.append_journal(&JournalEvent::Store { fact });
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
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FactQueryResult {
    pub facts: Vec<Fact>,
    pub total_tokens: usize,
}

/// Result of a paginated fact export (includes deleted facts for sync tombstones).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FactExportResult {
    pub facts: Vec<Fact>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// Estimate token count from text (bytes / 4 approximation).
fn estimate_tokens(text: &str) -> usize {
    text.len().div_ceil(4)
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
            private: false,
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
            private: false,
        });
        store.store(StoreFact {
            entity: "testing".to_string(),
            key: "approach".to_string(),
            value: "integration tests with real database".to_string(),
            source_receipt: None,
            confidence: 0.8,
            private: false,
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
            private: false,
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
                private: false,
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
            private: false,
        });
        store.store(StoreFact {
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "active".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
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
                private: false,
            },
            StoreFact {
                entity: "b".to_string(),
                key: "k2".to_string(),
                value: "v2".to_string(),
                source_receipt: Some("rcpt".to_string()),
                confidence: 0.9,
                private: false,
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
            private: false,
        });
        store.store(StoreFact {
            entity: "beta".to_string(),
            key: "info".to_string(),
            value: "shared keyword here".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
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
                private: false,
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
            private: false,
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
            private: false,
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
            private: false,
        });
        store.store(StoreFact {
            entity: "e".to_string(),
            key: "k".to_string(),
            value: "match high".to_string(),
            source_receipt: None,
            confidence: 0.9,
            private: false,
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
                private: false,
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
            private: false,
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
        let json = r"{}";
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
            private: false,
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

    // ── Persistence tests ─────────────────────────────────────────

    #[test]
    fn test_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let ids: Vec<String>;

        // Store 3 facts, then drop the store.
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let f1 = store.store(StoreFact {
                entity: "proj".into(),
                key: "name".into(),
                value: "alpha".into(),
                source_receipt: None,
                confidence: 0.9,
                private: false,
            });
            let f2 = store.store(StoreFact {
                entity: "proj".into(),
                key: "status".into(),
                value: "active".into(),
                source_receipt: Some("r1".into()),
                confidence: 1.0,
                private: false,
            });
            let f3 = store.store(StoreFact {
                entity: "other".into(),
                key: "info".into(),
                value: "details".into(),
                source_receipt: None,
                confidence: 0.5,
                private: false,
            });
            ids = vec![f1.fact_id, f2.fact_id, f3.fact_id];
            assert_eq!(store.count(), 3);
        }

        // Rebuild from the same directory.
        {
            let store = FactStore::with_persistence(dir.path()).unwrap();
            assert_eq!(store.count(), 3);
            for id in &ids {
                assert!(store.get(id).is_some(), "fact {} should exist after replay", id);
            }
            let fact = store.get(&ids[0]).unwrap();
            assert_eq!(fact.entity, "proj");
            assert_eq!(fact.key, "name");
            assert_eq!(fact.value, "alpha");
        }
    }

    #[test]
    fn test_persistence_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let fact_id: String;

        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let fact = store.store(StoreFact {
                entity: "e".into(),
                key: "k".into(),
                value: "v".into(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            });
            fact_id = fact.fact_id;
            store.delete(&fact_id);
            assert_eq!(store.count(), 0);
        }

        {
            let store = FactStore::with_persistence(dir.path()).unwrap();
            assert_eq!(store.count(), 0);
            assert!(store.get(&fact_id).is_none());
            // The fact should exist in the map but be deleted.
            assert!(store.facts.get(&fact_id).is_some());
            assert!(store.facts.get(&fact_id).unwrap().deleted);
        }
    }

    #[test]
    fn test_persistence_versioning() {
        let dir = tempfile::tempdir().unwrap();

        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let v1 = store.store(StoreFact {
                entity: "proj".into(),
                key: "status".into(),
                value: "draft".into(),
                source_receipt: None,
                confidence: 0.8,
                private: false,
            });
            let v2 = store.store(StoreFact {
                entity: "proj".into(),
                key: "status".into(),
                value: "active".into(),
                source_receipt: None,
                confidence: 0.9,
                private: false,
            });
            assert_eq!(v1.version, 1);
            assert_eq!(v2.version, 2);
            assert_eq!(v2.supersedes, Some(v1.fact_id.clone()));
        }

        {
            let store = FactStore::with_persistence(dir.path()).unwrap();
            let history = store.fact_history("proj", "status");
            assert_eq!(history.len(), 2);
            assert_eq!(history[0].version, 1);
            assert_eq!(history[0].value, "draft");
            assert_eq!(history[1].version, 2);
            assert_eq!(history[1].value, "active");
            assert_eq!(history[1].supersedes, Some(history[0].fact_id.clone()));
        }
    }

    #[test]
    fn test_in_memory_mode_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("facts.jsonl");

        let mut store = FactStore::new();
        store.store(StoreFact {
            entity: "e".into(),
            key: "k".into(),
            value: "v".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        });
        store.delete("nonexistent");

        assert!(!journal_path.exists(), "in-memory mode should not create journal files");
    }

    // ── Export tests ─────────────────────────────────────────────────

    #[test]
    fn test_export_basic() {
        let mut store = FactStore::new();
        for i in 0..5 {
            store.store(StoreFact {
                entity: format!("e{i}"),
                key: "k".into(),
                value: format!("v{i}"),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            });
        }

        let result = store.export(None, None, 100);
        assert_eq!(result.facts.len(), 5);
        assert!(!result.has_more);
        assert!(result.next_cursor.is_none());

        // Verify ascending stored_at order
        for w in result.facts.windows(2) {
            assert!(w[0].stored_at <= w[1].stored_at);
        }
    }

    #[test]
    fn test_export_with_cursor() {
        let mut store = FactStore::new();
        for i in 0..5 {
            store.store(StoreFact {
                entity: format!("e{i}"),
                key: "k".into(),
                value: format!("v{i}"),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            });
        }

        // First page: get 2
        let page1 = store.export(None, None, 2);
        assert_eq!(page1.facts.len(), 2);
        assert!(page1.has_more);
        assert!(page1.next_cursor.is_some());

        // Second page: use cursor from first page
        let page2 = store.export(None, page1.next_cursor.as_deref(), 2);
        assert_eq!(page2.facts.len(), 2);
        assert!(page2.has_more);

        // Third page: remaining 1
        let page3 = store.export(None, page2.next_cursor.as_deref(), 2);
        assert_eq!(page3.facts.len(), 1);
        assert!(!page3.has_more);
        assert!(page3.next_cursor.is_none());

        // Verify no duplicates across pages
        let all_ids: Vec<String> = page1
            .facts
            .iter()
            .chain(page2.facts.iter())
            .chain(page3.facts.iter())
            .map(|f| f.fact_id.clone())
            .collect();
        assert_eq!(all_ids.len(), 5);
        let deduped: std::collections::HashSet<_> = all_ids.iter().collect();
        assert_eq!(deduped.len(), 5);
    }

    #[test]
    fn test_export_with_since() {
        let mut store = FactStore::new();

        // Store 2 facts, capture a timestamp, then store 3 more
        store.store(StoreFact {
            entity: "e0".into(),
            key: "k".into(),
            value: "v0".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        });
        store.store(StoreFact {
            entity: "e1".into(),
            key: "k".into(),
            value: "v1".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        });

        // All facts stored with Utc::now() so they share the same timestamp
        // (sub-millisecond). To test since filtering properly, we modify
        // stored_at on the first two facts to be in the past.
        let past = Utc::now() - chrono::Duration::hours(1);
        let all_ids: Vec<String> = store.all_facts().map(|f| f.fact_id.clone()).collect();
        for id in &all_ids {
            if let Some(f) = store.facts.get_mut(id) {
                f.stored_at = past;
            }
        }

        let cutoff = Utc::now() - chrono::Duration::minutes(30);

        // Store 3 more (these will have stored_at = now)
        for i in 2..5 {
            store.store(StoreFact {
                entity: format!("e{i}"),
                key: "k".into(),
                value: format!("v{i}"),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            });
        }

        let result = store.export(Some(cutoff), None, 100);
        assert_eq!(result.facts.len(), 3);
        for f in &result.facts {
            assert!(f.stored_at >= cutoff);
        }
    }

    #[test]
    fn test_export_includes_deleted() {
        let mut store = FactStore::new();

        let f1 = store.store(StoreFact {
            entity: "e".into(),
            key: "k1".into(),
            value: "v1".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        });
        store.store(StoreFact {
            entity: "e".into(),
            key: "k2".into(),
            value: "v2".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        });

        store.delete(&f1.fact_id);

        // Export should include the deleted fact as a tombstone
        let result = store.export(None, None, 100);
        assert_eq!(result.facts.len(), 2);

        let deleted_fact = result.facts.iter().find(|f| f.fact_id == f1.fact_id).unwrap();
        assert!(deleted_fact.deleted);

        let live_fact = result.facts.iter().find(|f| f.fact_id != f1.fact_id).unwrap();
        assert!(!live_fact.deleted);
    }
}
