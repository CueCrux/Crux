// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Control-plane evidence schemas: admin-action lifecycle events, state mutations, checkpoints. Content-type `corecrux-control-evidence-v1`.

use serde::{Deserialize, Serialize};

use crate::{BuildInfo, EvidenceStatusV1, EvidenceSubjectScopeV1, KnowledgeAuthorityV1};

pub const CONTROL_EVIDENCE_CONTENT_TYPE_V1: &str = "application/json; profile=corecrux-control-evidence-v1";
pub const OPS_EVIDENCE_CONTENT_TYPE_V1: &str = "application/json; profile=corecrux-ops-evidence-v1";

pub const EVT_CONTROL_ADMIN_ACTION_SUBMITTED_V1: &str = "corecrux.control.admin_action_submitted.v1";
pub const EVT_CONTROL_ADMIN_ACTION_FINISHED_V1: &str = "corecrux.control.admin_action_finished.v1";
pub const EVT_CONTROL_STATE_MUTATION_V1: &str = "corecrux.control.state_mutation.v1";
pub const EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1: &str = "corecrux.control.checkpoint_materialized.v1";
pub const EVT_AUDIT_PACK_GENERATED_V1: &str = "corecrux.audit_pack.generated.v1";
pub const EVT_SCHEMA_EVOLUTION_RECORDED_V1: &str = "corecrux.ops.schema_evolution_recorded.v1";
pub const EVT_SHARD_REBALANCE_RECORDED_V1: &str = "corecrux.ops.shard_rebalance_recorded.v1";
pub const EVT_AUTHORITY_STATE_CHANGED_V1: &str = "corecrux.ops.authority_state_changed.v1";
pub const EVT_ROLLBACK_TRIGGERED_V1: &str = "corecrux.ops.rollback_triggered.v1";
pub const EVT_CHAOS_TEST_EXECUTED_V1: &str = "corecrux.ops.chaos_test_executed.v1";
pub const EVT_CAPACITY_THRESHOLD_BREACHED_V1: &str = "corecrux.ops.capacity_threshold_breached.v1";
pub const EVT_SEGMENT_OFFLOADED_V1: &str = "corecrux.ops.segment_offloaded.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceAuthContextV1 {
    pub mode: String,
    #[serde(rename = "subject", skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(rename = "tenantBinding", skip_serializing_if = "Option::is_none")]
    pub tenant_binding: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRequestContextV1 {
    #[serde(rename = "requestId", skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(rename = "traceId", skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub traceparent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceNodeContextV1 {
    #[serde(rename = "nodeId")]
    pub node_id: String,
    pub build: BuildInfo,
    #[serde(rename = "httpListenAddr", skip_serializing_if = "Option::is_none")]
    pub http_listen_addr: Option<String>,
    #[serde(rename = "grpcListenAddr", skip_serializing_if = "Option::is_none")]
    pub grpc_listen_addr: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlValveStateV1 {
    pub enabled: bool,
    pub actor: String,
    pub reason: String,
    #[serde(rename = "updatedAtUnixNs")]
    pub updated_at_unix_ns: u64,
    #[serde(rename = "retryAfterMs", skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u32>,
    #[serde(rename = "eventsPerSec", skip_serializing_if = "Option::is_none")]
    pub events_per_sec: Option<u64>,
    #[serde(rename = "bytesPerSec", skip_serializing_if = "Option::is_none")]
    pub bytes_per_sec: Option<u64>,
    #[serde(rename = "maxInFlight", skip_serializing_if = "Option::is_none")]
    pub max_in_flight: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlStateDigestV1 {
    #[serde(rename = "controlVersion")]
    pub control_version: u32,
    #[serde(rename = "updatedAtUnixNs")]
    pub updated_at_unix_ns: u64,
    #[serde(rename = "controlHashBlake3")]
    pub control_hash_blake3: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValveChangeV1 {
    pub valve: String,
    pub before: ControlValveStateV1,
    pub after: ControlValveStateV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KnowledgeAuthorityChangeV1 {
    pub before: KnowledgeAuthorityV1,
    pub after: KnowledgeAuthorityV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ControlAdminActionSubmittedV1 {
    pub schema: String,
    #[serde(rename = "actionId")]
    pub action_id: String,
    #[serde(rename = "actionType")]
    pub action_type: String,
    #[serde(rename = "submittedAtUnixMs")]
    pub submitted_at_unix_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    pub auth: EvidenceAuthContextV1,
    pub request: EvidenceRequestContextV1,
    pub node: EvidenceNodeContextV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ControlStateMutationV1 {
    pub schema: String,
    #[serde(rename = "actionId")]
    pub action_id: String,
    #[serde(rename = "mutationType")]
    pub mutation_type: String,
    #[serde(rename = "appliedAtUnixMs")]
    pub applied_at_unix_ms: u64,
    pub actor: String,
    pub reason: String,
    pub auth: EvidenceAuthContextV1,
    pub request: EvidenceRequestContextV1,
    pub node: EvidenceNodeContextV1,
    #[serde(rename = "controlBefore")]
    pub control_before: ControlStateDigestV1,
    #[serde(rename = "controlAfter")]
    pub control_after: ControlStateDigestV1,
    #[serde(rename = "valveChanges", default, skip_serializing_if = "Vec::is_empty")]
    pub valve_changes: Vec<ValveChangeV1>,
    #[serde(rename = "knowledgeAuthorityChange", skip_serializing_if = "Option::is_none")]
    pub knowledge_authority_change: Option<KnowledgeAuthorityChangeV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ControlAdminActionFinishedV1 {
    pub schema: String,
    #[serde(rename = "actionId")]
    pub action_id: String,
    #[serde(rename = "actionType")]
    pub action_type: String,
    pub status: String,
    #[serde(rename = "startedAtUnixMs", skip_serializing_if = "Option::is_none")]
    pub started_at_unix_ms: Option<u64>,
    #[serde(rename = "finishedAtUnixMs")]
    pub finished_at_unix_ms: u64,
    #[serde(rename = "mutationEventId", skip_serializing_if = "Option::is_none")]
    pub mutation_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub node: EvidenceNodeContextV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControlCheckpointMaterializedV1 {
    pub schema: String,
    #[serde(rename = "checkpointId")]
    pub checkpoint_id: String,
    #[serde(rename = "materializedAtUnixMs")]
    pub materialized_at_unix_ms: u64,
    pub node: EvidenceNodeContextV1,
    #[serde(rename = "controlState")]
    pub control_state: ControlStateDigestV1,
    #[serde(rename = "checkpointFormat")]
    pub checkpoint_format: String,
    #[serde(rename = "checkpointBlake3")]
    pub checkpoint_blake3: String,
    #[serde(rename = "checkpointSizeBytes")]
    pub checkpoint_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditPackGeneratedV1 {
    pub schema: String,
    #[serde(rename = "generatedAtUnixMs")]
    pub generated_at_unix_ms: u64,
    #[serde(rename = "actionId", skip_serializing_if = "Option::is_none")]
    pub action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub node: EvidenceNodeContextV1,
    pub status: EvidenceStatusV1,
    #[serde(rename = "subjectScope")]
    pub subject_scope: EvidenceSubjectScopeV1,
    #[serde(rename = "manifestBlake3")]
    pub manifest_blake3: String,
    #[serde(rename = "manifestSizeBytes")]
    pub manifest_size_bytes: u64,
    #[serde(rename = "packIndexBlake3")]
    pub pack_index_blake3: String,
    #[serde(rename = "packIndexSizeBytes")]
    pub pack_index_size_bytes: u64,
    #[serde(rename = "missingCapabilities", default, skip_serializing_if = "Vec::is_empty")]
    pub missing_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaEvolutionRecordedV1 {
    pub schema: String,
    #[serde(rename = "recordedAtUnixMs")]
    pub recorded_at_unix_ms: u64,
    #[serde(rename = "schemaFamily")]
    pub schema_family: String,
    #[serde(rename = "schemaVersion")]
    pub schema_version: String,
    pub actor: String,
    pub reason: String,
    pub node: EvidenceNodeContextV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShardRebalanceRecordedV1 {
    pub schema: String,
    #[serde(rename = "recordedAtUnixMs")]
    pub recorded_at_unix_ms: u64,
    #[serde(rename = "shardMapVersion")]
    pub shard_map_version: u64,
    #[serde(rename = "shardMapBlake3")]
    pub shard_map_blake3: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    pub actor: String,
    pub reason: String,
    pub node: EvidenceNodeContextV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorityStateChangedV1 {
    pub schema: String,
    #[serde(rename = "changedAtUnixMs")]
    pub changed_at_unix_ms: u64,
    #[serde(rename = "beforeState")]
    pub before_state: String,
    #[serde(rename = "afterState")]
    pub after_state: String,
    pub actor: String,
    pub reason: String,
    #[serde(rename = "triggerSignal", skip_serializing_if = "Option::is_none")]
    pub trigger_signal: Option<String>,
    pub node: EvidenceNodeContextV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackTriggeredV1 {
    pub schema: String,
    #[serde(rename = "triggeredAtUnixMs")]
    pub triggered_at_unix_ms: u64,
    pub actor: String,
    pub reason: String,
    #[serde(rename = "authorityState")]
    pub authority_state: String,
    #[serde(rename = "triggerSignal")]
    pub trigger_signal: String,
    pub node: EvidenceNodeContextV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChaosTestExecutedV1 {
    pub schema: String,
    #[serde(rename = "executedAtUnixMs")]
    pub executed_at_unix_ms: u64,
    #[serde(rename = "faultType")]
    pub fault_type: String,
    #[serde(rename = "durationSecs")]
    pub duration_secs: u64,
    pub verdict: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub node: EvidenceNodeContextV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SegmentOffloadedV1 {
    pub schema: String,
    #[serde(rename = "offloadedAtUnixMs")]
    pub offloaded_at_unix_ms: u64,
    pub tier: String,
    pub target: String,
    #[serde(rename = "shardId")]
    pub shard_id: u32,
    pub epoch: u64,
    #[serde(rename = "segmentSeq")]
    pub segment_seq: u64,
    #[serde(rename = "segmentId")]
    pub segment_id: String,
    #[serde(rename = "segmentHashBlake3")]
    pub segment_hash_blake3: String,
    #[serde(rename = "sourcePath")]
    pub source_path: String,
    #[serde(rename = "targetPath")]
    pub target_path: String,
    pub verified: bool,
    #[serde(rename = "sourceDeleted")]
    pub source_deleted: bool,
    #[serde(rename = "bytesCopied")]
    pub bytes_copied: u64,
    pub node: EvidenceNodeContextV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapacityThresholdBreachedV1 {
    pub schema: String,
    #[serde(rename = "observedAtUnixMs")]
    pub observed_at_unix_ms: u64,
    #[serde(rename = "thresholdKind")]
    pub threshold_kind: String,
    #[serde(rename = "thresholdRatio")]
    pub threshold_ratio: f64,
    #[serde(rename = "freeRatio")]
    pub free_ratio: f64,
    #[serde(rename = "freeBytes")]
    pub free_bytes: u64,
    #[serde(rename = "totalBytes")]
    pub total_bytes: u64,
    pub action: String,
    #[serde(rename = "pauseIngestActive")]
    pub pause_ingest_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub node: EvidenceNodeContextV1,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn sample_node() -> EvidenceNodeContextV1 {
        EvidenceNodeContextV1 {
            node_id: "node-a".to_string(),
            build: BuildInfo {
                version: "1.2.3".to_string(),
                commit: "abc123".to_string(),
            },
            http_listen_addr: Some("127.0.0.1:8440".to_string()),
            grpc_listen_addr: Some("127.0.0.1:7440".to_string()),
        }
    }

    #[test]
    fn control_mutation_serializes_expected_shape() {
        let mutation = ControlStateMutationV1 {
            schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
            action_id: "act-1".to_string(),
            mutation_type: "set_valves".to_string(),
            applied_at_unix_ms: 42,
            actor: "operator".to_string(),
            reason: "maintenance".to_string(),
            auth: EvidenceAuthContextV1 {
                mode: "jwt_jwks".to_string(),
                subject: Some("alice".to_string()),
                tenant_binding: None,
                scopes: vec!["admin:write".to_string()],
            },
            request: EvidenceRequestContextV1 {
                request_id: Some("req-1".to_string()),
                trace_id: Some("trace-1".to_string()),
                traceparent: None,
            },
            node: sample_node(),
            control_before: ControlStateDigestV1 {
                control_version: 1,
                updated_at_unix_ns: 10,
                control_hash_blake3: "before".to_string(),
            },
            control_after: ControlStateDigestV1 {
                control_version: 1,
                updated_at_unix_ns: 20,
                control_hash_blake3: "after".to_string(),
            },
            valve_changes: vec![ValveChangeV1 {
                valve: "throttle".to_string(),
                before: ControlValveStateV1 {
                    retry_after_ms: Some(50),
                    ..ControlValveStateV1::default()
                },
                after: ControlValveStateV1 {
                    enabled: true,
                    actor: "operator".to_string(),
                    reason: "maintenance".to_string(),
                    updated_at_unix_ns: 20,
                    retry_after_ms: Some(250),
                    events_per_sec: Some(100),
                    bytes_per_sec: Some(2048),
                    max_in_flight: Some(8),
                },
            }],
            knowledge_authority_change: None,
            result: Some(json!({ "changed": true })),
        };

        let encoded = serde_json::to_value(&mutation).expect("serialize");
        assert_eq!(encoded["schema"], EVT_CONTROL_STATE_MUTATION_V1);
        assert_eq!(encoded["actionId"], "act-1");
        assert_eq!(encoded["mutationType"], "set_valves");
        assert_eq!(encoded["controlBefore"]["controlHashBlake3"], "before");
        assert_eq!(encoded["controlAfter"]["controlHashBlake3"], "after");
        assert_eq!(encoded["valveChanges"][0]["before"]["retryAfterMs"], 50);
        assert_eq!(encoded["valveChanges"][0]["after"]["eventsPerSec"], 100);
        assert_eq!(encoded["request"]["requestId"], "req-1");
    }

    #[test]
    fn audit_pack_generated_skips_empty_missing_capabilities() {
        let event = AuditPackGeneratedV1 {
            schema: EVT_AUDIT_PACK_GENERATED_V1.to_string(),
            generated_at_unix_ms: 99,
            action_id: None,
            actor: None,
            reason: None,
            node: sample_node(),
            status: EvidenceStatusV1::Pass,
            subject_scope: EvidenceSubjectScopeV1::default(),
            manifest_blake3: "manifest".to_string(),
            manifest_size_bytes: 10,
            pack_index_blake3: "index".to_string(),
            pack_index_size_bytes: 20,
            missing_capabilities: Vec::new(),
        };

        let encoded = serde_json::to_value(&event).expect("serialize");
        assert!(encoded.get("missingCapabilities").is_none());
        assert_eq!(encoded["packIndexBlake3"], "index");
    }

    #[test]
    fn capacity_threshold_serializes_expected_shape() {
        let event = CapacityThresholdBreachedV1 {
            schema: EVT_CAPACITY_THRESHOLD_BREACHED_V1.to_string(),
            observed_at_unix_ms: 42,
            threshold_kind: "emergency".to_string(),
            threshold_ratio: 0.10,
            free_ratio: 0.08,
            free_bytes: 8,
            total_bytes: 100,
            action: "pause_ingest_enabled".to_string(),
            pause_ingest_active: true,
            detail: Some("auto-pause engaged".to_string()),
            node: sample_node(),
        };

        let encoded = serde_json::to_value(&event).expect("serialize");
        assert_eq!(encoded["schema"], EVT_CAPACITY_THRESHOLD_BREACHED_V1);
        assert_eq!(encoded["thresholdKind"], "emergency");
        assert_eq!(encoded["action"], "pause_ingest_enabled");
        assert_eq!(encoded["pauseIngestActive"], true);
    }

    #[test]
    fn segment_offloaded_serializes_expected_shape() {
        let event = SegmentOffloadedV1 {
            schema: EVT_SEGMENT_OFFLOADED_V1.to_string(),
            offloaded_at_unix_ms: 144,
            tier: "warm".to_string(),
            target: "/mnt/archive".to_string(),
            shard_id: 2,
            epoch: 9,
            segment_seq: 44,
            segment_id: "0123456789abcdef".to_string(),
            segment_hash_blake3: "deadbeef".to_string(),
            source_path: "/data/shards/shard-0002/segments/seg-44.ccxseg".to_string(),
            target_path: "/mnt/archive/shard-0002/segments/seg-44.ccxseg".to_string(),
            verified: true,
            source_deleted: false,
            bytes_copied: 4096,
            node: sample_node(),
        };

        let encoded = serde_json::to_value(&event).expect("serialize");
        assert_eq!(encoded["schema"], EVT_SEGMENT_OFFLOADED_V1);
        assert_eq!(encoded["offloadedAtUnixMs"], 144);
        assert_eq!(encoded["segmentSeq"], 44);
        assert_eq!(encoded["sourceDeleted"], false);
        assert_eq!(encoded["bytesCopied"], 4096);
    }
}
