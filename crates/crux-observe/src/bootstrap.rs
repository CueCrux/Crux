// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Bootstrap seeder — loads embedded documentation, patterns, and error
//! resolution guides into the fact store on first run.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::info;

use corecrux_memory::fact_store::{FactQuery, FactStore, StoreFact};

use crate::schema::{bootstrap_entity, BOOTSTRAP_PREFIX};

// ── Embedded bootstrap data ────────────────────────────────────────────────

const BOOTSTRAP_DOCS: &str = include_str!("../bootstrap_data/docs.json");
const BOOTSTRAP_PATTERNS: &str = include_str!("../bootstrap_data/patterns.json");
const BOOTSTRAP_RESOLUTIONS: &str = include_str!("../bootstrap_data/resolutions.json");
const BOOTSTRAP_TOOL_OUTPUTS: &str = include_str!("../bootstrap_data/tool-outputs.json");

// ── JSON shapes ────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct DocEntry {
    slug: String,
    title: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct PatternEntry {
    slug: String,
    title: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ResolutionEntry {
    code: String,
    title: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ToolOutputEntry {
    tool: String,
    output: String,
}

// ── Sentinel key ───────────────────────────────────────────────────────────

const SENTINEL_ENTITY: &str = "__bootstrap__::_meta";
const SENTINEL_KEY: &str = "seeded";

// ── Public types ───────────────────────────────────────────────────────────

/// Seeds the fact store with embedded bootstrap data on first run.
pub struct BootstrapSeeder {
    fact_store: Arc<RwLock<FactStore>>,
}

/// Outcome of a `seed()` call.
pub struct SeedResult {
    pub facts_created: usize,
    pub already_seeded: bool,
}

/// Current bootstrap status.
pub struct BootstrapStatus {
    pub seeded: bool,
    pub fact_count: usize,
    pub categories: HashMap<String, usize>,
    pub last_seed_at: Option<String>,
}

// ── Implementation ─────────────────────────────────────────────────────────

impl BootstrapSeeder {
    pub fn new(fact_store: Arc<RwLock<FactStore>>) -> Self {
        Self { fact_store }
    }

    /// Returns `true` if the sentinel fact exists, meaning bootstrap has run.
    pub async fn is_seeded(&self) -> bool {
        let store = self.fact_store.read().await;
        let result = store.query(&FactQuery {
            query: None,
            entity: Some(SENTINEL_ENTITY.to_string()),
            entity_prefix: None,
            top_k: 1,
            token_budget: None,
        });
        !result.facts.is_empty()
    }

    /// Load embedded data into the fact store. Idempotent — returns early if
    /// the sentinel fact already exists.
    pub async fn seed(&self) -> SeedResult {
        if self.is_seeded().await {
            return SeedResult {
                facts_created: 0,
                already_seeded: true,
            };
        }

        // SAFETY: Bootstrap JSON files are compile-time constants — deserialization cannot fail.
        #[allow(clippy::expect_used)]
        let docs: Vec<DocEntry> = serde_json::from_str(BOOTSTRAP_DOCS).expect("bootstrap docs.json is invalid");
        #[allow(clippy::expect_used)]
        let patterns: Vec<PatternEntry> =
            serde_json::from_str(BOOTSTRAP_PATTERNS).expect("bootstrap patterns.json is invalid");
        #[allow(clippy::expect_used)]
        let resolutions: Vec<ResolutionEntry> =
            serde_json::from_str(BOOTSTRAP_RESOLUTIONS).expect("bootstrap resolutions.json is invalid");
        #[allow(clippy::expect_used)]
        let tool_outputs: Vec<ToolOutputEntry> =
            serde_json::from_str(BOOTSTRAP_TOOL_OUTPUTS).expect("bootstrap tool-outputs.json is invalid");

        let mut reqs: Vec<StoreFact> = Vec::new();

        for doc in &docs {
            reqs.push(StoreFact {
                entity: bootstrap_entity("doc", &doc.slug),
                key: doc.title.clone(),
                value: doc.content.clone(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            });
        }

        for pat in &patterns {
            reqs.push(StoreFact {
                entity: bootstrap_entity("pattern", &pat.slug),
                key: pat.title.clone(),
                value: pat.content.clone(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            });
        }

        for res in &resolutions {
            reqs.push(StoreFact {
                entity: bootstrap_entity("resolution", &res.code),
                key: res.title.clone(),
                value: res.content.clone(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            });
        }

        for to in &tool_outputs {
            reqs.push(StoreFact {
                entity: bootstrap_entity("tool-output", &to.tool),
                key: format!("{} output schema", to.tool),
                value: to.output.clone(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            });
        }

        let count = reqs.len();

        let mut store = self.fact_store.write().await;
        store.store_bulk(reqs);

        // Write sentinel
        store.store(StoreFact {
            entity: SENTINEL_ENTITY.to_string(),
            key: SENTINEL_KEY.to_string(),
            value: Utc::now().to_rfc3339(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
        });

        info!(facts_created = count, "bootstrap seed complete");

        SeedResult {
            facts_created: count,
            already_seeded: false,
        }
    }

    /// Report current bootstrap status including per-category counts.
    pub async fn status(&self) -> BootstrapStatus {
        let store = self.fact_store.read().await;
        let seeded = {
            let result = store.query(&FactQuery {
                query: None,
                entity: Some(SENTINEL_ENTITY.to_string()),
                entity_prefix: None,
                top_k: 1,
                token_budget: None,
            });
            !result.facts.is_empty()
        };

        // Query all bootstrap facts
        let result = store.query(&FactQuery {
            query: None,
            entity: None,
            entity_prefix: Some(BOOTSTRAP_PREFIX.to_string()),
            top_k: 10_000,
            token_budget: None,
        });

        let mut categories: HashMap<String, usize> = HashMap::new();
        let mut last_seed_at: Option<String> = None;

        for fact in &result.facts {
            // Entity format: __bootstrap__::{category}:{slug}
            if let Some(rest) = fact.entity.strip_prefix(BOOTSTRAP_PREFIX) {
                let category = rest.split(':').next().unwrap_or("unknown");
                *categories.entry(category.to_string()).or_insert(0) += 1;
            }

            // The sentinel fact records the seed timestamp as its value
            if fact.entity == SENTINEL_ENTITY && fact.key == SENTINEL_KEY {
                last_seed_at = Some(fact.value.clone());
            }
        }

        BootstrapStatus {
            seeded,
            fact_count: result.facts.len(),
            categories,
            last_seed_at,
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_seeder() -> BootstrapSeeder {
        BootstrapSeeder::new(Arc::new(RwLock::new(FactStore::new())))
    }

    fn bootstrap_counts() -> (usize, usize, usize, usize) {
        let docs: Vec<DocEntry> = serde_json::from_str(BOOTSTRAP_DOCS).unwrap();
        let patterns: Vec<PatternEntry> = serde_json::from_str(BOOTSTRAP_PATTERNS).unwrap();
        let resolutions: Vec<ResolutionEntry> = serde_json::from_str(BOOTSTRAP_RESOLUTIONS).unwrap();
        let tool_outputs: Vec<ToolOutputEntry> = serde_json::from_str(BOOTSTRAP_TOOL_OUTPUTS).unwrap();
        (docs.len(), patterns.len(), resolutions.len(), tool_outputs.len())
    }

    #[test]
    fn bootstrap_docs_deserialises() {
        let docs: Vec<DocEntry> = serde_json::from_str(BOOTSTRAP_DOCS).unwrap();
        assert!(!docs.is_empty());
        for d in &docs {
            assert!(!d.slug.is_empty());
            assert!(!d.title.is_empty());
            assert!(!d.content.is_empty());
        }
    }

    #[test]
    fn bootstrap_patterns_deserialises() {
        let patterns: Vec<PatternEntry> = serde_json::from_str(BOOTSTRAP_PATTERNS).unwrap();
        assert!(!patterns.is_empty());
        for p in &patterns {
            assert!(!p.slug.is_empty());
            assert!(!p.title.is_empty());
            assert!(!p.content.is_empty());
        }
    }

    #[test]
    fn bootstrap_tool_outputs_deserialises() {
        let entries: Vec<ToolOutputEntry> = serde_json::from_str(BOOTSTRAP_TOOL_OUTPUTS).unwrap();
        assert_eq!(entries.len(), 16);
        for e in &entries {
            assert!(!e.tool.is_empty());
            assert!(!e.output.is_empty());
        }
    }

    #[test]
    fn bootstrap_resolutions_deserialises() {
        let resolutions: Vec<ResolutionEntry> = serde_json::from_str(BOOTSTRAP_RESOLUTIONS).unwrap();
        assert!(!resolutions.is_empty());
        for r in &resolutions {
            assert!(!r.code.is_empty());
            assert!(!r.title.is_empty());
            assert!(!r.content.is_empty());
        }
    }

    #[tokio::test]
    async fn seed_creates_facts_on_empty_store() {
        let seeder = make_seeder();
        let result = seeder.seed().await;
        let (docs, patterns, resolutions, tool_outputs) = bootstrap_counts();

        assert!(!result.already_seeded);
        assert!(result.facts_created > 0);

        assert_eq!(result.facts_created, docs + patterns + resolutions + tool_outputs);
    }

    #[tokio::test]
    async fn seed_is_idempotent() {
        let seeder = make_seeder();

        let first = seeder.seed().await;
        assert!(!first.already_seeded);
        assert!(first.facts_created > 0);

        let second = seeder.seed().await;
        assert!(second.already_seeded);
        assert_eq!(second.facts_created, 0);
    }

    #[tokio::test]
    async fn is_seeded_false_before_true_after() {
        let seeder = make_seeder();

        assert!(!seeder.is_seeded().await);
        seeder.seed().await;
        assert!(seeder.is_seeded().await);
    }

    #[tokio::test]
    async fn status_returns_correct_counts() {
        let seeder = make_seeder();
        seeder.seed().await;
        let (docs, patterns, resolutions, tool_outputs) = bootstrap_counts();
        let expected_total = docs + patterns + resolutions + tool_outputs;

        let status = seeder.status().await;
        assert!(status.seeded);
        assert_eq!(status.fact_count, expected_total + 1);
        assert_eq!(status.categories.get("doc"), Some(&docs));
        assert_eq!(status.categories.get("pattern"), Some(&patterns));
        assert_eq!(status.categories.get("resolution"), Some(&resolutions));
        assert_eq!(status.categories.get("tool-output"), Some(&tool_outputs));
        assert!(status.last_seed_at.is_some());
    }
}
