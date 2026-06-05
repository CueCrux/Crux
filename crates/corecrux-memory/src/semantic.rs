// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Semantic profile and rank-safe retrieval contracts.
//!
//! Canonical memory records are model-independent text/structured data. Dense
//! embeddings, BM25 indexes, rerankers, and cloud/local projections are derived
//! score spaces over those records, so mixed-profile retrieval must merge by
//! rank or rerank under one selected profile rather than comparing raw scores.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::embeddings::SemanticProfile;
use crate::fact_store::Fact;

pub const MEMORY_RECORD_SCHEMA_V1: &str = "cuecrux.memory_record.v1";
pub const SEMANTIC_PROFILE_REGISTRY_SCHEMA_V1: &str = "cuecrux.semantic_profile_registry.v1";
pub const RANK_FUSION_SCHEMA_V1: &str = "cuecrux.rank_fusion.v1";

pub const SCORE_SPACE_BM25_LEXICAL: &str = "bm25_lexical";
pub const SCORE_SPACE_DENSE_COSINE: &str = "dense_cosine";
pub const SCORE_SPACE_RERANKER: &str = "reranker";
pub const SCORE_MERGE_RULE_SINGLE_SPACE: &str = "single_score_space";
pub const SCORE_MERGE_RULE_RANK_FUSION: &str = "reciprocal_rank_fusion";
pub const MIXED_PROFILE_MERGE_RULE: &str = "rank_fusion_or_single_profile_rerank_required";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryRecord {
    pub schema: String,
    pub record_id: String,
    pub tenant_id: String,
    pub collection: String,
    pub entity: String,
    pub key: String,
    pub identity_hash: String,
    pub content_hash: String,
    pub updated_at: String,
    pub deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_text: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub structured_fields: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_receipt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_semantic_profile_id: Option<String>,
}

impl MemoryRecord {
    pub fn from_fact(
        tenant_id: &str,
        collection: &str,
        fact: &Fact,
        include_content: bool,
        semantic_profile_id: Option<String>,
        local_semantic_profile_id: Option<String>,
    ) -> Self {
        let identity_hash = memory_identity_hash(tenant_id, collection, &fact.entity, &fact.key);
        let content_hash = memory_content_hash(&fact.value, fact.deleted);
        Self {
            schema: MEMORY_RECORD_SCHEMA_V1.to_string(),
            record_id: fact.fact_id.clone(),
            tenant_id: tenant_id.to_string(),
            collection: collection.to_string(),
            entity: fact.entity.clone(),
            key: fact.key.clone(),
            identity_hash,
            content_hash,
            updated_at: fact.stored_at.to_rfc3339(),
            deleted: fact.deleted,
            canonical_text: include_content.then(|| fact.value.clone()),
            structured_fields: Value::Null,
            source_receipt: fact.source_receipt.clone(),
            semantic_profile_id,
            local_semantic_profile_id,
        }
    }
}

pub fn memory_identity_hash(tenant_id: &str, collection: &str, entity: &str, key: &str) -> String {
    let payload = serde_json::json!({
        "schema": MEMORY_RECORD_SCHEMA_V1,
        "tenant_id": tenant_id,
        "collection": collection,
        "entity": entity,
        "key": key,
    });
    hash_json(&payload)
}

pub fn memory_content_hash(canonical_text: &str, deleted: bool) -> String {
    let payload = serde_json::json!({
        "schema": MEMORY_RECORD_SCHEMA_V1,
        "canonical_text": canonical_text,
        "deleted": deleted,
    });
    hash_json(&payload)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SemanticProfileRegistry {
    pub schema: String,
    #[serde(default)]
    pub profiles: BTreeMap<String, SemanticProfileEntry>,
    #[serde(default)]
    pub tenant_default_profiles: BTreeMap<String, String>,
}

impl Default for SemanticProfileRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticProfileRegistry {
    pub fn new() -> Self {
        Self {
            schema: SEMANTIC_PROFILE_REGISTRY_SCHEMA_V1.to_string(),
            profiles: BTreeMap::new(),
            tenant_default_profiles: BTreeMap::new(),
        }
    }

    pub fn insert_profile(&mut self, profile: SemanticProfile, location: SemanticProfileLocation) {
        self.profiles.insert(
            profile.profile_id.clone(),
            SemanticProfileEntry {
                profile,
                location,
                compatible_score_spaces: vec![SCORE_SPACE_DENSE_COSINE.to_string(), SCORE_SPACE_RERANKER.to_string()],
            },
        );
    }

    pub fn set_tenant_default_profile(&mut self, tenant_id: impl Into<String>, profile_id: impl Into<String>) {
        self.tenant_default_profiles.insert(tenant_id.into(), profile_id.into());
    }

    pub fn tenant_default_profile_id(&self, tenant_id: &str) -> Option<&str> {
        self.tenant_default_profiles.get(tenant_id).map(String::as_str)
    }

    pub fn profile(&self, profile_id: &str) -> Option<&SemanticProfileEntry> {
        self.profiles.get(profile_id)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SemanticProfileEntry {
    pub profile: SemanticProfile,
    pub location: SemanticProfileLocation,
    #[serde(default)]
    pub compatible_score_spaces: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SemanticProfileLocation {
    Local,
    CloudTenantDefault,
    CloudGpu,
    Imported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RankedEvidenceList {
    pub source_label: String,
    pub score_space: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_profile_id: Option<String>,
    pub hits: Vec<RankedEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RankedEvidence {
    pub record_id: String,
    /// One-based rank within this evidence list. Zero means "use input order".
    #[serde(default)]
    pub rank: usize,
    pub raw_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RankFusionResult {
    pub schema: String,
    pub merge_rule: String,
    pub mixed_profile_merge_rule: String,
    pub k: f32,
    pub input_profile_ids: Vec<String>,
    pub results: Vec<FusedEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FusedEvidence {
    pub record_id: String,
    pub fused_score: f32,
    pub best_rank: usize,
    pub contributing_profile_ids: Vec<String>,
    pub source_labels: Vec<String>,
    pub contributions: Vec<RankContribution>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RankContribution {
    pub source_label: String,
    pub score_space: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_profile_id: Option<String>,
    pub rank: usize,
    pub raw_score: f32,
    pub rank_fusion_score: f32,
}

pub fn reciprocal_rank_fusion(lists: &[RankedEvidenceList], k: f32, limit: usize) -> RankFusionResult {
    let k = if k.is_finite() && k > 0.0 { k } else { 60.0 };
    let mut by_record: BTreeMap<String, FusedEvidence> = BTreeMap::new();
    let mut input_profile_ids = BTreeSet::new();

    for list in lists {
        if let Some(profile_id) = &list.semantic_profile_id {
            input_profile_ids.insert(profile_id.clone());
        }
        for (idx, hit) in list.hits.iter().enumerate() {
            let rank = if hit.rank == 0 { idx + 1 } else { hit.rank };
            let rank_fusion_score = 1.0 / (k + rank as f32);
            let entry = by_record.entry(hit.record_id.clone()).or_insert_with(|| FusedEvidence {
                record_id: hit.record_id.clone(),
                fused_score: 0.0,
                best_rank: rank,
                contributing_profile_ids: Vec::new(),
                source_labels: Vec::new(),
                contributions: Vec::new(),
            });
            entry.fused_score += rank_fusion_score;
            entry.best_rank = entry.best_rank.min(rank);
            if let Some(profile_id) = &list.semantic_profile_id {
                if !entry.contributing_profile_ids.contains(profile_id) {
                    entry.contributing_profile_ids.push(profile_id.clone());
                }
            }
            if !entry.source_labels.contains(&list.source_label) {
                entry.source_labels.push(list.source_label.clone());
            }
            entry.contributions.push(RankContribution {
                source_label: list.source_label.clone(),
                score_space: list.score_space.clone(),
                semantic_profile_id: list.semantic_profile_id.clone(),
                rank,
                raw_score: hit.raw_score,
                rank_fusion_score,
            });
        }
    }

    let mut results = by_record.into_values().collect::<Vec<_>>();
    for result in &mut results {
        result.contributing_profile_ids.sort();
        result.source_labels.sort();
        result.contributions.sort_by(|left, right| {
            left.rank
                .cmp(&right.rank)
                .then_with(|| left.source_label.cmp(&right.source_label))
        });
    }
    results.sort_by(|left, right| {
        right
            .fused_score
            .partial_cmp(&left.fused_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.best_rank.cmp(&right.best_rank))
            .then_with(|| left.record_id.cmp(&right.record_id))
    });
    results.truncate(limit);

    RankFusionResult {
        schema: RANK_FUSION_SCHEMA_V1.to_string(),
        merge_rule: SCORE_MERGE_RULE_RANK_FUSION.to_string(),
        mixed_profile_merge_rule: MIXED_PROFILE_MERGE_RULE.to_string(),
        k,
        input_profile_ids: input_profile_ids.into_iter().collect(),
        results,
    }
}

fn hash_json<T: Serialize>(value: &T) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::embeddings::{EmbeddingConfig, SemanticProfile};

    use super::*;

    fn fact(value: &str) -> Fact {
        Fact {
            fact_id: "f_1".to_string(),
            entity: "business::acme::note".to_string(),
            key: "summary".to_string(),
            value: value.to_string(),
            source_receipt: Some("crx_1".to_string()),
            confidence: 1.0,
            stored_at: Utc::now(),
            tokens: 3,
            deleted: false,
            version: 1,
            supersedes: None,
            private: false,
            horizon_class: crate::fact_store::HorizonClass::None,
            reverified_at: None,
            superseded_by: None,
        }
    }

    #[test]
    fn memory_record_identity_is_model_independent_but_content_changes() {
        let first = MemoryRecord::from_fact("business::acme", "facts", &fact("old"), false, None, None);
        let second = MemoryRecord::from_fact("business::acme", "facts", &fact("new"), false, None, None);

        assert_eq!(first.schema, MEMORY_RECORD_SCHEMA_V1);
        assert_eq!(first.identity_hash, second.identity_hash);
        assert_ne!(first.content_hash, second.content_hash);
        assert!(first.canonical_text.is_none());
    }

    #[test]
    fn semantic_profile_registry_tracks_tenant_default() {
        let profile = SemanticProfile::from_embedding_config(
            &EmbeddingConfig {
                base_url: "http://localhost:11434".to_string(),
                model: "nomic-embed-text".to_string(),
                dimensions: 768,
            },
            0,
        );
        let profile_id = profile.profile_id.clone();
        let mut registry = SemanticProfileRegistry::new();

        registry.insert_profile(profile, SemanticProfileLocation::CloudTenantDefault);
        registry.set_tenant_default_profile("business::acme", profile_id.clone());

        assert_eq!(
            registry.tenant_default_profile_id("business::acme"),
            Some(profile_id.as_str())
        );
        assert_eq!(
            registry.profile(&profile_id).unwrap().location,
            SemanticProfileLocation::CloudTenantDefault
        );
    }

    #[test]
    fn reciprocal_rank_fusion_uses_rank_not_raw_score() {
        let result = reciprocal_rank_fusion(
            &[
                RankedEvidenceList {
                    source_label: "local_private".to_string(),
                    score_space: SCORE_SPACE_DENSE_COSINE.to_string(),
                    semantic_profile_id: Some("sp_local".to_string()),
                    hits: vec![RankedEvidence {
                        record_id: "alpha".to_string(),
                        rank: 1,
                        raw_score: 0.01,
                    }],
                },
                RankedEvidenceList {
                    source_label: "cloud_tenant".to_string(),
                    score_space: SCORE_SPACE_DENSE_COSINE.to_string(),
                    semantic_profile_id: Some("sp_cloud".to_string()),
                    hits: vec![RankedEvidence {
                        record_id: "beta".to_string(),
                        rank: 2,
                        raw_score: 1000.0,
                    }],
                },
            ],
            60.0,
            10,
        );

        assert_eq!(result.schema, RANK_FUSION_SCHEMA_V1);
        assert_eq!(result.merge_rule, SCORE_MERGE_RULE_RANK_FUSION);
        assert_eq!(result.results[0].record_id, "alpha");
        assert_eq!(result.results[1].record_id, "beta");
        assert_eq!(
            result.input_profile_ids,
            vec!["sp_cloud".to_string(), "sp_local".to_string()]
        );
    }
}
