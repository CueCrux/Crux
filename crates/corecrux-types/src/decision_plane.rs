// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use serde::{Deserialize, Serialize};

pub const DECISION_EVENT_CONTENT_TYPE_V1: &str = "application/json; profile=corecrux-decision-plane-v1";
pub const EVT_AGENT_DECISION_RECORDED_V1: &str = "agent.decision.recorded.v1";
pub const EVT_AGENT_ACTION_EXECUTED_V1: &str = "agent.action.executed.v1";
pub const EVT_AGENT_ACTION_SUPERSEDED_V1: &str = "agent.action.superseded.v1";
pub const EVT_KNOWLEDGE_STATE_RECONSTRUCTED_V1: &str = "knowledge.state.reconstructed.v1";

// Enrichment receipt events (Agent Enrichment & Orchestration v1.0)
pub const ENRICHMENT_CONTENT_TYPE_V1: &str = "application/json; profile=corecrux-enrichment-v1";
pub const EVT_ENRICHMENT_GAP_EMITTED_V1: &str = "enrichment.gap.emitted.v1";
pub const EVT_ENRICHMENT_VALIDATION_EMITTED_V1: &str = "enrichment.validation.emitted.v1";
pub const EVT_ENRICHMENT_CORRECTION_SUBMITTED_V1: &str = "enrichment.correction.submitted.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionSegmentCursorV1 {
    #[serde(rename = "shardId")]
    pub shard_id: u32,
    pub epoch: u64,
    #[serde(rename = "segmentSeq")]
    pub segment_seq: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionSufficiencySignalV1 {
    Sufficient,
    Thin,
    Contested,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcomeV1 {
    Success,
    Partial,
    Failure,
    Timeout,
    Refused,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionSupersessionReasonV1 {
    StaleContext,
    IncorrectOutput,
    PolicyViolation,
    OperatorCorrection,
    AgentSelfCorrection,
}

/// Sensitivity class for tool parameters in decision events.
///
/// Controls whether the full parameter payload is stored inline in the
/// append-only spine, or only a BLAKE3 digest is retained.
///
/// - `InlineSafe`: Parameters are schema-bounded, non-free-text, and have been
///   reviewed as safe to anchor permanently (e.g. UUIDs, enums, booleans,
///   numeric thresholds, internal IDs).
/// - `HashOnly`: Default. Only the BLAKE3 digest is stored. The parameters
///   themselves are not written to the spine.
/// - `EncryptedRef`: The BLAKE3 digest is stored plus a content-addressed
///   reference to tenant-encrypted mutable storage. For cases where replay
///   of sensitive parameters is needed without anchoring raw content.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolParametersModeV1 {
    InlineSafe,
    HashOnly,
    EncryptedRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentDecisionRecordedV1 {
    pub schema: String,
    #[serde(rename = "decisionId")]
    pub decision_id: String,
    #[serde(rename = "agentId")]
    pub agent_id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "contextReceiptIds", default, skip_serializing_if = "Vec::is_empty")]
    pub context_receipt_ids: Vec<String>,
    #[serde(rename = "knowledgeStateCursor")]
    pub knowledge_state_cursor: DecisionSegmentCursorV1,
    #[serde(rename = "toolCalled")]
    pub tool_called: String,
    #[serde(rename = "toolParametersHash")]
    pub tool_parameters_hash: String,
    #[serde(rename = "toolParametersMode")]
    pub tool_parameters_mode: ToolParametersModeV1,
    #[serde(rename = "toolParametersInline", skip_serializing_if = "Option::is_none")]
    pub tool_parameters_inline: Option<String>,
    #[serde(rename = "toolParametersRef", skip_serializing_if = "Option::is_none")]
    pub tool_parameters_ref: Option<String>,
    #[serde(rename = "toolParametersSchemaVersion")]
    pub tool_parameters_schema_version: String,
    #[serde(rename = "toolParametersPreview", skip_serializing_if = "Option::is_none")]
    pub tool_parameters_preview: Option<String>,
    #[serde(rename = "sufficiencySignal")]
    pub sufficiency_signal: DecisionSufficiencySignalV1,
    #[serde(rename = "confidenceSnapshot")]
    pub confidence_snapshot: f32,
    #[serde(rename = "decisionHash")]
    pub decision_hash: String,
    #[serde(rename = "parentDecisionId", skip_serializing_if = "Option::is_none")]
    pub parent_decision_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentActionExecutedV1 {
    pub schema: String,
    #[serde(rename = "actionId")]
    pub action_id: String,
    #[serde(rename = "decisionId")]
    pub decision_id: String,
    #[serde(rename = "agentId")]
    pub agent_id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub outcome: DecisionOutcomeV1,
    #[serde(rename = "artefactsProduced", default, skip_serializing_if = "Vec::is_empty")]
    pub artefacts_produced: Vec<String>,
    #[serde(rename = "receiptsProduced", default, skip_serializing_if = "Vec::is_empty")]
    pub receipts_produced: Vec<String>,
    #[serde(rename = "errorCode", skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(rename = "durationMs")]
    pub duration_ms: u64,
    #[serde(rename = "actionHash")]
    pub action_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentActionSupersededV1 {
    pub schema: String,
    #[serde(rename = "supersessionId")]
    pub supersession_id: String,
    #[serde(rename = "supersededActionId")]
    pub superseded_action_id: String,
    #[serde(rename = "supersedingDecisionId")]
    pub superseding_decision_id: String,
    pub reason: DecisionSupersessionReasonV1,
    #[serde(rename = "evidenceDrift")]
    pub evidence_drift: bool,
    #[serde(rename = "supersessionHash")]
    pub supersession_hash: String,
}

/// V2 supersession event with explicit tenant_id for tenant-attribution safety.
/// New writes should emit V2. Historical V1 events derive tenant from the parent
/// stream or superseded action's tenant_id; fail closed if tenant cannot be derived.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentActionSupersededV2 {
    pub schema: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "supersessionId")]
    pub supersession_id: String,
    #[serde(rename = "supersededActionId")]
    pub superseded_action_id: String,
    #[serde(rename = "supersedingDecisionId")]
    pub superseding_decision_id: String,
    pub reason: DecisionSupersessionReasonV1,
    #[serde(rename = "evidenceDrift")]
    pub evidence_drift: bool,
    #[serde(rename = "supersessionHash")]
    pub supersession_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeConfidencePointV1 {
    #[serde(rename = "decisionId")]
    pub decision_id: String,
    #[serde(rename = "occurredAt")]
    pub occurred_at: String,
    #[serde(rename = "confidenceSnapshot")]
    pub confidence_snapshot: f32,
    #[serde(rename = "sufficiencySignal")]
    pub sufficiency_signal: DecisionSufficiencySignalV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeStateSnapshotV1 {
    pub schema: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "sessionId", skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "decisionId", skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    #[serde(rename = "atTimestamp")]
    pub at_timestamp: String,
    #[serde(rename = "atCursor")]
    pub at_cursor: DecisionSegmentCursorV1,
    #[serde(rename = "snapshotHash")]
    pub snapshot_hash: String,
    #[serde(rename = "currentArtefacts", default, skip_serializing_if = "Vec::is_empty")]
    pub current_artefacts: Vec<String>,
    #[serde(rename = "supersededArtefacts", default, skip_serializing_if = "Vec::is_empty")]
    pub superseded_artefacts: Vec<String>,
    #[serde(rename = "pendingPressureEvents", default, skip_serializing_if = "Vec::is_empty")]
    pub pending_pressure_events: Vec<String>,
    #[serde(rename = "confidenceLandscape", skip_serializing_if = "Option::is_none")]
    pub confidence_landscape: Option<Vec<KnowledgeConfidencePointV1>>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
    #[serde(rename = "reconstructionReceiptId", skip_serializing_if = "Option::is_none")]
    pub reconstruction_receipt_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KnowledgeStateReconstructedV1 {
    pub schema: String,
    #[serde(rename = "reconstructionId")]
    pub reconstruction_id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "sessionId", skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(rename = "decisionId", skip_serializing_if = "Option::is_none")]
    pub decision_id: Option<String>,
    #[serde(rename = "atTimestamp")]
    pub at_timestamp: String,
    #[serde(rename = "atCursor")]
    pub at_cursor: DecisionSegmentCursorV1,
    #[serde(rename = "includeSuperseded")]
    pub include_superseded: bool,
    #[serde(rename = "includeConfidenceLandscape")]
    pub include_confidence_landscape: bool,
    #[serde(rename = "snapshotHash")]
    pub snapshot_hash: String,
    #[serde(rename = "currentArtefacts", default, skip_serializing_if = "Vec::is_empty")]
    pub current_artefacts: Vec<String>,
    #[serde(rename = "supersededArtefacts", default, skip_serializing_if = "Vec::is_empty")]
    pub superseded_artefacts: Vec<String>,
    #[serde(rename = "pendingPressureEvents", default, skip_serializing_if = "Vec::is_empty")]
    pub pending_pressure_events: Vec<String>,
    #[serde(rename = "confidenceLandscape", skip_serializing_if = "Option::is_none")]
    pub confidence_landscape: Option<Vec<KnowledgeConfidencePointV1>>,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
    #[serde(rename = "reconstructionReceiptId")]
    pub reconstruction_receipt_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditDecisionReportV1 {
    pub schema: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "decisionId")]
    pub decision_id: String,
    #[serde(rename = "agentId")]
    pub agent_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "shadowMode")]
    pub shadow_mode: bool,
    pub authoritative: bool,
    #[serde(rename = "actionId", skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<DecisionOutcomeV1>,
    #[serde(rename = "relatedReceiptIds", default, skip_serializing_if = "Vec::is_empty")]
    pub related_receipt_ids: Vec<String>,
    #[serde(rename = "missingCapabilities", default, skip_serializing_if = "Vec::is_empty")]
    pub missing_capabilities: Vec<String>,
}

// ---------------------------------------------------------------------------
// Enrichment receipt event structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnrichmentGapSubtypeV1 {
    Coverage,
    Enumeration,
}

/// Emitted when a retrieval query produces no or low-confidence results (coverage gap)
/// or when the answerability assessment identifies missing dimensions (enumeration gap).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnrichmentGapEmittedV1 {
    pub schema: String,
    #[serde(rename = "enrichmentReceiptId")]
    pub enrichment_receipt_id: String,
    #[serde(rename = "parentReceiptId", skip_serializing_if = "Option::is_none")]
    pub parent_receipt_id: Option<String>,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "agentId")]
    pub agent_id: String,
    #[serde(rename = "gapSubtype")]
    pub gap_subtype: EnrichmentGapSubtypeV1,
    #[serde(rename = "queryHash")]
    pub query_hash: String,
    #[serde(rename = "resultCount")]
    pub result_count: u32,
    #[serde(rename = "maxConfidence")]
    pub max_confidence: f32,
    #[serde(rename = "missingDimensions", default, skip_serializing_if = "Vec::is_empty")]
    pub missing_dimensions: Vec<String>,
    #[serde(rename = "receiptHash")]
    pub receipt_hash: String,
}

/// Emitted when a deferred validation receipt is processed and either emitted or suppressed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnrichmentValidationEmittedV1 {
    pub schema: String,
    #[serde(rename = "enrichmentReceiptId")]
    pub enrichment_receipt_id: String,
    #[serde(rename = "parentReceiptId")]
    pub parent_receipt_id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "agentId")]
    pub agent_id: String,
    #[serde(rename = "itemIds")]
    pub item_ids: Vec<String>,
    #[serde(rename = "contradictionCheck")]
    pub contradiction_check: String,
    #[serde(rename = "receiptHash")]
    pub receipt_hash: String,
}

/// Emitted when an agent submits a correction for a knowledge item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnrichmentCorrectionSubmittedV1 {
    pub schema: String,
    #[serde(rename = "enrichmentReceiptId")]
    pub enrichment_receipt_id: String,
    #[serde(rename = "parentReceiptId")]
    pub parent_receipt_id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "agentId")]
    pub agent_id: String,
    #[serde(rename = "originalItemId")]
    pub original_item_id: String,
    #[serde(rename = "correctionType")]
    pub correction_type: String,
    #[serde(rename = "receiptHash")]
    pub receipt_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_event_serialization_uses_expected_tags() {
        let decision = AgentDecisionRecordedV1 {
            schema: EVT_AGENT_DECISION_RECORDED_V1.to_string(),
            decision_id: "dec-1".to_string(),
            agent_id: "agent-a".to_string(),
            tenant_id: "tenant-1".to_string(),
            session_id: "session-9".to_string(),
            context_receipt_ids: vec!["rcpt-1".to_string()],
            knowledge_state_cursor: DecisionSegmentCursorV1 {
                shard_id: 1,
                epoch: 2,
                segment_seq: 3,
                offset: 4,
            },
            tool_called: "ship_patch".to_string(),
            tool_parameters_hash: "cd".repeat(32),
            tool_parameters_mode: ToolParametersModeV1::InlineSafe,
            tool_parameters_inline: Some("AQID".to_string()),
            tool_parameters_ref: None,
            tool_parameters_schema_version: "1.0".to_string(),
            tool_parameters_preview: None,
            sufficiency_signal: DecisionSufficiencySignalV1::Thin,
            confidence_snapshot: 0.42,
            decision_hash: "ab".repeat(32),
            parent_decision_id: None,
        };
        let encoded = serde_json::to_value(&decision).expect("encode decision");
        assert_eq!(encoded["schema"], EVT_AGENT_DECISION_RECORDED_V1);
        assert_eq!(encoded["decisionId"], "dec-1");
        assert_eq!(encoded["sufficiencySignal"], "thin");
        assert_eq!(encoded["toolParametersHash"], "cd".repeat(32));
        assert_eq!(encoded["toolParametersMode"], "inline_safe");
        assert_eq!(encoded["toolParametersInline"], "AQID");
        assert_eq!(encoded["toolParametersSchemaVersion"], "1.0");
        assert!(encoded.get("toolParametersRef").is_none());
        assert!(encoded.get("toolParametersPreview").is_none());
    }

    #[test]
    fn hash_only_mode_omits_inline_and_ref_fields() {
        let decision = AgentDecisionRecordedV1 {
            schema: EVT_AGENT_DECISION_RECORDED_V1.to_string(),
            decision_id: "dec-2".to_string(),
            agent_id: "agent-a".to_string(),
            tenant_id: "tenant-1".to_string(),
            session_id: "session-9".to_string(),
            context_receipt_ids: vec![],
            knowledge_state_cursor: DecisionSegmentCursorV1 {
                shard_id: 0,
                epoch: 0,
                segment_seq: 0,
                offset: 0,
            },
            tool_called: "query_knowledge".to_string(),
            tool_parameters_hash: "ab".repeat(32),
            tool_parameters_mode: ToolParametersModeV1::HashOnly,
            tool_parameters_inline: None,
            tool_parameters_ref: None,
            tool_parameters_schema_version: "1.0".to_string(),
            tool_parameters_preview: Some("query: 'architecture overview'".to_string()),
            sufficiency_signal: DecisionSufficiencySignalV1::Sufficient,
            confidence_snapshot: 0.85,
            decision_hash: "ef".repeat(32),
            parent_decision_id: None,
        };
        let encoded = serde_json::to_value(&decision).expect("encode decision");
        assert_eq!(encoded["toolParametersMode"], "hash_only");
        assert!(encoded.get("toolParametersInline").is_none());
        assert!(encoded.get("toolParametersRef").is_none());
        assert_eq!(encoded["toolParametersPreview"], "query: 'architecture overview'");
        assert_eq!(encoded["toolParametersSchemaVersion"], "1.0");
    }

    #[test]
    fn encrypted_ref_mode_stores_ref_field() {
        let decision = AgentDecisionRecordedV1 {
            schema: EVT_AGENT_DECISION_RECORDED_V1.to_string(),
            decision_id: "dec-3".to_string(),
            agent_id: "agent-a".to_string(),
            tenant_id: "tenant-1".to_string(),
            session_id: "session-9".to_string(),
            context_receipt_ids: vec![],
            knowledge_state_cursor: DecisionSegmentCursorV1 {
                shard_id: 0,
                epoch: 0,
                segment_seq: 0,
                offset: 0,
            },
            tool_called: "send_notification".to_string(),
            tool_parameters_hash: "cd".repeat(32),
            tool_parameters_mode: ToolParametersModeV1::EncryptedRef,
            tool_parameters_inline: None,
            tool_parameters_ref: Some("vault://tenant-1/params/dec-3/blake3:cdcdcdcd".to_string()),
            tool_parameters_schema_version: "1.0".to_string(),
            tool_parameters_preview: Some("recipient_count: 1".to_string()),
            sufficiency_signal: DecisionSufficiencySignalV1::Unknown,
            confidence_snapshot: 0.0,
            decision_hash: "ef".repeat(32),
            parent_decision_id: None,
        };
        let encoded = serde_json::to_value(&decision).expect("encode decision");
        assert_eq!(encoded["toolParametersMode"], "encrypted_ref");
        assert!(encoded.get("toolParametersInline").is_none());
        assert!(encoded["toolParametersRef"].as_str().unwrap().starts_with("vault://"));
    }

    #[test]
    fn audit_decision_report_marks_shadow_mode() {
        let report = AuditDecisionReportV1 {
            schema: "corecrux.audit.decision.report.v1".to_string(),
            tenant_id: "tenant-1".to_string(),
            decision_id: "dec-1".to_string(),
            agent_id: "agent-a".to_string(),
            session_id: "session-9".to_string(),
            shadow_mode: true,
            authoritative: false,
            action_id: Some("act-1".to_string()),
            outcome: Some(DecisionOutcomeV1::Success),
            related_receipt_ids: vec!["rcpt-1".to_string()],
            missing_capabilities: vec![
                "knowledge_state_reconstruction".to_string(),
                "decision_causal_chain_projection".to_string(),
            ],
        };
        let encoded = serde_json::to_value(&report).expect("encode report");
        assert_eq!(encoded["shadowMode"], true);
        assert_eq!(encoded["authoritative"], false);
    }

    #[test]
    fn knowledge_state_reconstructed_serializes_expected_fields() {
        let event = KnowledgeStateReconstructedV1 {
            schema: EVT_KNOWLEDGE_STATE_RECONSTRUCTED_V1.to_string(),
            reconstruction_id: "recon-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            session_id: Some("session-9".to_string()),
            decision_id: Some("dec-1".to_string()),
            at_timestamp: "2026-03-06T00:00:00Z".to_string(),
            at_cursor: DecisionSegmentCursorV1 {
                shard_id: 1,
                epoch: 2,
                segment_seq: 3,
                offset: 4,
            },
            include_superseded: true,
            include_confidence_landscape: true,
            snapshot_hash: "ab".repeat(32),
            current_artefacts: vec!["art-1".to_string()],
            superseded_artefacts: vec!["art-0".to_string()],
            pending_pressure_events: vec!["pressure-1".to_string()],
            confidence_landscape: Some(vec![KnowledgeConfidencePointV1 {
                decision_id: "dec-1".to_string(),
                occurred_at: "2026-03-06T00:00:00Z".to_string(),
                confidence_snapshot: 0.9,
                sufficiency_signal: DecisionSufficiencySignalV1::Sufficient,
            }]),
            generated_at: "2026-03-06T00:00:10Z".to_string(),
            reconstruction_receipt_id: "rcpt-1".to_string(),
        };
        let encoded = serde_json::to_value(&event).expect("encode reconstruction");
        assert_eq!(encoded["schema"], EVT_KNOWLEDGE_STATE_RECONSTRUCTED_V1);
        assert_eq!(encoded["reconstructionId"], "recon-1");
        assert_eq!(encoded["includeSuperseded"], true);
        assert_eq!(encoded["reconstructionReceiptId"], "rcpt-1");
    }
}
