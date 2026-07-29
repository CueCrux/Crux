// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Evidence-manifest + audit-pack-index schemas exchanged between `corecruxd` and `corecruxctl`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{BuildInfo, CompatContract};

pub const EVIDENCE_MANIFEST_SCHEMA_V1: &str = "corecrux.evidence.manifest.v1";
pub const AUDIT_PACK_INDEX_SCHEMA_V2: &str = "corecrux.audit.pack.index.v2";

fn is_false(v: &bool) -> bool {
    !*v
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStatusV1 {
    Pass,
    Warn,
    Fail,
    Skipped,
}

impl EvidenceStatusV1 {
    pub fn worst(a: Self, b: Self) -> Self {
        match (a, b) {
            (Self::Fail, _) | (_, Self::Fail) => Self::Fail,
            (Self::Warn, _) | (_, Self::Warn) => Self::Warn,
            (Self::Pass, _) | (_, Self::Pass) => Self::Pass,
            _ => Self::Skipped,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceProducerV1 {
    pub name: String,
    pub version: String,
    pub commit: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceSubjectScopeV1 {
    #[serde(rename = "tenantId", skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(rename = "streamType", skip_serializing_if = "Option::is_none")]
    pub stream_type: Option<String>,
    #[serde(rename = "streamId", skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(rename = "receiptId", skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(rename = "shardIds", default, skip_serializing_if = "Vec::is_empty")]
    pub shard_ids: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceProjectionCursorV1 {
    #[serde(rename = "shardId")]
    pub shard_id: u32,
    pub epoch: u64,
    #[serde(rename = "segmentSeq")]
    pub segment_seq: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "refType", rename_all = "snake_case")]
pub enum EvidenceSourceRefV1 {
    Frame {
        #[serde(rename = "tenantId")]
        tenant_id: String,
        #[serde(rename = "streamType")]
        stream_type: String,
        #[serde(rename = "streamId")]
        stream_id: String,
        seq: u64,
        #[serde(rename = "eventId")]
        event_id: String,
        #[serde(rename = "eventType")]
        event_type: String,
        #[serde(rename = "occurredAt")]
        occurred_at: String,
        #[serde(rename = "headerHash")]
        header_hash: String,
        #[serde(rename = "payloadHash")]
        payload_hash: String,
        #[serde(rename = "shardId", skip_serializing_if = "Option::is_none")]
        shard_id: Option<u32>,
        #[serde(rename = "segmentSeq", skip_serializing_if = "Option::is_none")]
        segment_seq: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<u64>,
    },
    Receipt {
        #[serde(rename = "tenantId")]
        tenant_id: String,
        #[serde(rename = "receiptId")]
        receipt_id: String,
        #[serde(rename = "bodyPayloadHash")]
        body_payload_hash: String,
        #[serde(rename = "sigEventRef", skip_serializing_if = "Option::is_none")]
        sig_event_ref: Option<String>,
    },
    ProjectionSnapshot {
        #[serde(rename = "shardId")]
        shard_id: u32,
        projection: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cursor: Option<EvidenceProjectionCursorV1>,
        #[serde(rename = "expectedBlake3", skip_serializing_if = "Option::is_none")]
        expected_blake3: Option<String>,
    },
    ShardMap {
        version: u64,
        blake3: String,
        #[serde(rename = "sourceEventId", skip_serializing_if = "Option::is_none")]
        source_event_id: Option<String>,
    },
    Build {
        version: String,
        commit: String,
        #[serde(rename = "compatRequires", skip_serializing_if = "Option::is_none")]
        compat_requires: Option<String>,
    },
    Runtime {
        #[serde(rename = "nodeId")]
        node_id: String,
        #[serde(rename = "gpuId", skip_serializing_if = "Option::is_none")]
        gpu_id: Option<i32>,
        #[serde(rename = "ioBackend", skip_serializing_if = "Option::is_none")]
        io_backend: Option<String>,
        #[serde(rename = "gdsEnabled", skip_serializing_if = "Option::is_none")]
        gds_enabled: Option<bool>,
        #[serde(rename = "hardwareProfile", skip_serializing_if = "Option::is_none")]
        hardware_profile: Option<String>,
    },
    HttpCapture {
        url: String,
        method: String,
        #[serde(rename = "statusCode", skip_serializing_if = "Option::is_none")]
        status_code: Option<u16>,
        observational: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceArtifactDescriptorV1 {
    pub kind: String,
    #[serde(rename = "mediaType")]
    pub media_type: String,
    pub path: String,
    pub blake3: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: u64,
    pub status: EvidenceStatusV1,
    pub required: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub observational: bool,
    #[serde(rename = "producedBy")]
    pub produced_by: EvidenceProducerV1,
    #[serde(rename = "sourceRefs", default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<EvidenceSourceRefV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceRelationshipV1 {
    pub from: String,
    pub to: String,
    pub relation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceManifestV1 {
    pub schema: String,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
    pub producer: EvidenceProducerV1,
    #[serde(rename = "corecruxBuild")]
    pub corecrux_build: BuildInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compat: Option<CompatContract>,
    #[serde(rename = "subjectScope")]
    pub subject_scope: EvidenceSubjectScopeV1,
    pub status: EvidenceStatusV1,
    pub artifacts: BTreeMap<String, EvidenceArtifactDescriptorV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relationships: Vec<EvidenceRelationshipV1>,
    #[serde(rename = "missingCapabilities", default, skip_serializing_if = "Vec::is_empty")]
    pub missing_capabilities: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditArtifactSummaryV2 {
    pub status: EvidenceStatusV1,
    pub path: String,
    pub blake3: String,
    #[serde(rename = "sizeBytes")]
    pub size_bytes: u64,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditPackIndexV2 {
    pub schema: String,
    #[serde(rename = "formatVersion")]
    pub format_version: u32,
    #[serde(rename = "generatedAt")]
    pub generated_at: String,
    pub producer: EvidenceProducerV1,
    pub status: EvidenceStatusV1,
    #[serde(rename = "manifestPath")]
    pub manifest_path: String,
    #[serde(rename = "manifestBlake3")]
    pub manifest_blake3: String,
    #[serde(rename = "manifestSizeBytes")]
    pub manifest_size_bytes: u64,
    #[serde(rename = "artifactSummary")]
    pub artifact_summary: BTreeMap<String, AuditArtifactSummaryV2>,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn evidence_status_worst_preserves_fail_over_warn_and_pass() {
        assert_eq!(
            EvidenceStatusV1::worst(EvidenceStatusV1::Pass, EvidenceStatusV1::Warn),
            EvidenceStatusV1::Warn
        );
        assert_eq!(
            EvidenceStatusV1::worst(EvidenceStatusV1::Skipped, EvidenceStatusV1::Fail),
            EvidenceStatusV1::Fail
        );
    }

    #[test]
    fn manifest_serializes_tagged_source_refs_and_missing_capabilities() {
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "receipt_bundle".to_string(),
            EvidenceArtifactDescriptorV1 {
                kind: "receipt_export_bundle".to_string(),
                media_type: "application/zip".to_string(),
                path: "receipt/export.zip".to_string(),
                blake3: "deadbeef".to_string(),
                size_bytes: 1024,
                status: EvidenceStatusV1::Pass,
                required: true,
                observational: false,
                produced_by: EvidenceProducerV1 {
                    name: "corecruxctl".to_string(),
                    version: "1.2.3".to_string(),
                    commit: "abc123".to_string(),
                },
                source_refs: vec![
                    EvidenceSourceRefV1::Frame {
                        tenant_id: "tenant-a".to_string(),
                        stream_type: "receipt".to_string(),
                        stream_id: "receipt-1".to_string(),
                        seq: 12,
                        event_id: "evt-12".to_string(),
                        event_type: "receipt.body.v1".to_string(),
                        occurred_at: "2026-03-06T12:00:00Z".to_string(),
                        header_hash: "hdr".to_string(),
                        payload_hash: "payload".to_string(),
                        shard_id: Some(1),
                        segment_seq: Some(2),
                        offset: Some(64),
                    },
                    EvidenceSourceRefV1::Build {
                        version: "1.2.3".to_string(),
                        commit: "abc123".to_string(),
                        compat_requires: Some(">=3.0 <4.0".to_string()),
                    },
                ],
            },
        );

        let manifest = EvidenceManifestV1 {
            schema: EVIDENCE_MANIFEST_SCHEMA_V1.to_string(),
            generated_at: "2026-03-06T12:00:00Z".to_string(),
            producer: EvidenceProducerV1 {
                name: "corecruxctl".to_string(),
                version: "1.2.3".to_string(),
                commit: "abc123".to_string(),
            },
            corecrux_build: BuildInfo {
                version: "1.2.3".to_string(),
                commit: "core-sha".to_string(),
            },
            compat: Some(CompatContract {
                requires: ">=3.0 <4.0".to_string(),
            }),
            subject_scope: EvidenceSubjectScopeV1 {
                tenant_id: Some("tenant-a".to_string()),
                stream_type: Some("receipt".to_string()),
                stream_id: Some("receipt-1".to_string()),
                receipt_id: Some("receipt-1".to_string()),
                shard_ids: vec![1],
            },
            status: EvidenceStatusV1::Pass,
            artifacts,
            relationships: vec![EvidenceRelationshipV1 {
                from: "receipt_bundle".to_string(),
                to: "receipt_bundle".to_string(),
                relation: "packages".to_string(),
            }],
            missing_capabilities: vec!["decision_plane_events".to_string()],
        };

        let encoded = serde_json::to_value(&manifest).expect("serialize");
        assert_eq!(encoded["schema"], EVIDENCE_MANIFEST_SCHEMA_V1);
        assert_eq!(
            encoded["artifacts"]["receipt_bundle"]["sourceRefs"][0]["refType"],
            "frame"
        );
        assert_eq!(
            encoded["artifacts"]["receipt_bundle"]["sourceRefs"][1]["refType"],
            "build"
        );
        assert_eq!(encoded["missingCapabilities"][0], "decision_plane_events");
    }
}
