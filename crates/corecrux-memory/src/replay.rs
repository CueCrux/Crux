// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Deterministic answer replay capsules.
//!
//! A replay capsule stores the answer the agent/model already produced plus
//! the exact selected evidence and receipt references needed to render that
//! historical answer again without calling the original agent or LLM.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::action_enrichment::hash_json;

pub const ANSWER_REPLAY_CAPSULE_SCHEMA: &str = "crux.answer_replay_capsule.v1";
pub const ANSWER_REPLAY_RESPONSE_SCHEMA: &str = "crux.answer_replay.v1";
pub const ANSWER_REPLAY_VALIDITY_SCHEMA: &str = "crux.answer_replay_validity.v1";
pub const ANSWER_REPLAY_EXPORT_SCHEMA: &str = "crux.answer_replay_export.v1";
pub const ANSWER_REPLAY_CAPSULE_ENTITY_PREFIX: &str = "__answer_replay_capsule__";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnswerReplayCapsule {
    pub schema: String,
    pub answer_id: String,
    pub tenant_id: String,
    pub source: String,
    pub question: String,
    pub stored_answer: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub answer_text: Option<String>,
    pub rendered_answer: String,
    pub answer_hash: String,
    pub evidence: Vec<ReplayEvidenceRef>,
    #[serde(default)]
    pub projection_refs: Vec<ProjectionReplayRef>,
    #[serde(default)]
    pub source_receipts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_pack_receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_semantic_profile_id: Option<String>,
    pub replay_policy: ReplayPolicy,
    pub created_at: String,
    pub capsule_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayEvidenceRef {
    pub record_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_semantic_profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score_space: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectionReplayRef {
    pub module_id: String,
    pub module_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_commit_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_registry_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection_snapshot_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_receipt_id: Option<String>,
    pub availability: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayPolicy {
    pub historical_replay: String,
    pub agent_required: bool,
    pub llm_required: bool,
    pub render_strategy: String,
    pub validity_check: String,
}

impl Default for ReplayPolicy {
    fn default() -> Self {
        Self {
            historical_replay: "stored_answer_value".to_string(),
            agent_required: false,
            llm_required: false,
            render_strategy: "render_stored_answer".to_string(),
            validity_check: "compare_capsule_evidence_to_current_store".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BuildAnswerReplayCapsule {
    pub answer_id: String,
    pub tenant_id: String,
    pub source: String,
    pub question: String,
    pub stored_answer: Value,
    pub evidence: Vec<ReplayEvidenceRef>,
    pub projection_refs: Vec<ProjectionReplayRef>,
    pub source_receipts: Vec<String>,
    pub context_pack_receipt_id: Option<String>,
    pub semantic_profile_id: Option<String>,
    pub local_semantic_profile_id: Option<String>,
    pub created_at: String,
}

impl AnswerReplayCapsule {
    pub fn build(input: BuildAnswerReplayCapsule) -> Self {
        let answer_text = extract_answer_text(&input.stored_answer);
        let rendered_answer = answer_text
            .clone()
            .unwrap_or_else(|| serde_json::to_string(&input.stored_answer).unwrap_or_default());
        let answer_hash = hash_json(&input.stored_answer);
        let mut capsule = Self {
            schema: ANSWER_REPLAY_CAPSULE_SCHEMA.to_string(),
            answer_id: input.answer_id,
            tenant_id: input.tenant_id,
            source: input.source,
            question: input.question,
            stored_answer: input.stored_answer,
            answer_text,
            rendered_answer,
            answer_hash,
            evidence: input.evidence,
            projection_refs: input.projection_refs,
            source_receipts: input.source_receipts,
            context_pack_receipt_id: input.context_pack_receipt_id,
            semantic_profile_id: input.semantic_profile_id,
            local_semantic_profile_id: input.local_semantic_profile_id,
            replay_policy: ReplayPolicy::default(),
            created_at: input.created_at,
            capsule_hash: String::new(),
        };
        capsule.capsule_hash = capsule.compute_hash();
        capsule
    }

    pub fn compute_hash(&self) -> String {
        let mut clone = self.clone();
        clone.capsule_hash.clear();
        serde_json::to_value(clone).map_or_else(|_| "blake3:".to_string(), |value| hash_json(&value))
    }

    pub fn metadata_only(&self) -> Self {
        let mut clone = self.clone();
        clone.stored_answer = Value::Null;
        clone.answer_text = None;
        clone.rendered_answer.clear();
        for evidence in &mut clone.evidence {
            evidence.text = None;
        }
        clone
    }
}

pub fn answer_capsule_entity(tenant_id: &str, answer_id: &str) -> String {
    format!("{ANSWER_REPLAY_CAPSULE_ENTITY_PREFIX}::{tenant_id}::{answer_id}")
}

pub fn hash_text(text: &str) -> String {
    format!("blake3:{}", blake3::hash(text.as_bytes()).to_hex())
}

fn extract_answer_text(value: &Value) -> Option<String> {
    value
        .get("answer")
        .and_then(Value::as_str)
        .or_else(|| value.get("message").and_then(Value::as_str))
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> AnswerReplayCapsule {
        AnswerReplayCapsule::build(BuildAnswerReplayCapsule {
            answer_id: "ans_1".to_string(),
            tenant_id: "tenant-a".to_string(),
            source: "gpu1_answer".to_string(),
            question: "What changed?".to_string(),
            stored_answer: serde_json::json!({ "answer": "Routes changed." }),
            evidence: vec![ReplayEvidenceRef {
                record_id: "f_1".to_string(),
                artifact_id: None,
                source_label: Some("local_tenant_index".to_string()),
                text: Some("Route auth scopes changed.".to_string()),
                text_hash: Some(hash_text("Route auth scopes changed.")),
                content_hash: None,
                semantic_profile_id: None,
                local_semantic_profile_id: Some("sp_local".to_string()),
                score_space: Some("bm25_lexical".to_string()),
                receipt_id: Some("rcpt_1".to_string()),
            }],
            projection_refs: Vec::new(),
            source_receipts: vec!["rcpt_result".to_string()],
            context_pack_receipt_id: Some("ctx_1".to_string()),
            semantic_profile_id: None,
            local_semantic_profile_id: Some("sp_local".to_string()),
            created_at: "2026-05-07T00:00:00Z".to_string(),
        })
    }

    #[test]
    fn capsule_hash_is_stable() {
        let a = fixture();
        let b = fixture();
        assert_eq!(a.capsule_hash, b.capsule_hash);
        assert!(a.capsule_hash.starts_with("blake3:"));
    }

    #[test]
    fn metadata_only_removes_answer_and_evidence_text() {
        let redacted = fixture().metadata_only();
        assert!(redacted.stored_answer.is_null());
        assert!(redacted.answer_text.is_none());
        assert!(redacted.rendered_answer.is_empty());
        assert!(redacted.evidence[0].text.is_none());
    }
}
