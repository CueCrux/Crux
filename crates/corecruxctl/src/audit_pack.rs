// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Audit-pack builder — assembles index + receipts + evidence into a portable archive for off-host review.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::{BufRead, BufReader, Cursor, Read};
use std::path::{Path, PathBuf};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};

use crate::{evidence, fixture_digest, parity, snapshot};
use corecrux_projections::load_projections_meta_v1;
use corecrux_receipts::ReplayExportManifestV1;
use corecrux_types::{
    AuditArtifactSummaryV2, AuditPackIndexV2, BuildInfo, CompatContract, EvidenceArtifactDescriptorV1,
    EvidenceManifestV1, EvidenceProducerV1, EvidenceProjectionCursorV1, EvidenceRelationshipV1, EvidenceSourceRefV1,
    EvidenceStatusV1, EvidenceSubjectScopeV1, HealthzResponse, AUDIT_PACK_INDEX_SCHEMA_V2, DEFAULT_COMPAT_REQUIRES,
    EVIDENCE_MANIFEST_SCHEMA_V1,
};

type DynError = Box<dyn std::error::Error + Send + Sync>;
type ComparatorSourceV1 = (String, Vec<ComparatorEventRowV1>);

#[derive(Debug, Clone)]
pub struct AuditPackOptionsV1 {
    pub out_dir: Option<PathBuf>,
    pub offline: bool,
    pub corecrux_base: String,
    pub data_dir: Option<PathBuf>,
    pub tenant_id: Option<String>,
    pub stream_type: Option<String>,
    pub stream_id: Option<String>,
    pub from_seq: u64,
    pub max_events: u32,
    pub v1_events_log: Option<PathBuf>,
    pub v1_stream_jsonl: Option<PathBuf>,
    pub parity_tenant_id: Option<String>,
    pub parity_seed: String,
    pub parity_sample: u32,
    pub engine_base: Option<String>,
    pub engine_api_key: Option<String>,
    pub replay_fixture: String,
    pub device_index: i32,
    pub receipt_id: Option<String>,
    pub answer_id: Option<String>,
    pub action_id: Option<String>,
    pub receipt_keyring: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatusV1 {
    Pass,
    Warn,
    Fail,
    Skipped,
}

impl AuditStatusV1 {
    fn worst(a: Self, b: Self) -> Self {
        match (a, b) {
            (Self::Fail, _) | (_, Self::Fail) => Self::Fail,
            (Self::Warn, _) | (_, Self::Warn) => Self::Warn,
            (Self::Pass, _) | (_, Self::Pass) => Self::Pass,
            _ => Self::Skipped,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuditPackIndexV1 {
    pub schema: String,
    pub generated_at: String,
    pub corecrux_base: String,
    pub out_dir: String,
    pub status: AuditStatusV1,
    pub artifacts: BTreeMap<String, AuditArtifactRefV1>,
}

#[derive(Debug, Serialize)]
pub struct AuditArtifactRefV1 {
    pub status: AuditStatusV1,
    pub file: String,
    pub summary: String,
}

#[derive(Debug, Serialize)]
struct OrderingParityReportV1 {
    pub schema: String,
    pub comparison: String,
    pub status: AuditStatusV1,
    pub total_events: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest_blake3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_system: Option<CrossSystemParityMetaV1>,
    pub issues: Vec<AuditIssueV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
struct IdempotencyParityReportV1 {
    pub schema: String,
    pub comparison: String,
    pub status: AuditStatusV1,
    pub total_events: u64,
    pub unique_event_ids: u64,
    pub duplicate_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cross_system: Option<CrossSystemParityMetaV1>,
    pub issues: Vec<AuditIssueV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
struct CrossSystemParityMetaV1 {
    pub source: String,
    pub v1_total_events: u64,
    pub v3_total_events: u64,
    pub v1_digest_blake3: String,
    pub v3_digest_blake3: String,
    pub digest_match: bool,
}

#[derive(Debug, Serialize)]
struct ProjectionParityReportV1 {
    pub schema: String,
    pub status: AuditStatusV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<parity::ParitySummaryV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<parity::ParityLivingReportV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
struct ReplayDeterminismReportV1 {
    pub schema: String,
    pub status: AuditStatusV1,
    pub fixture: String,
    pub run_a: fixture_digest::FixtureDigestReport,
    pub run_b: fixture_digest::FixtureDigestReport,
    pub digest_match: bool,
    pub frames_match: bool,
}

#[derive(Debug, Serialize)]
struct IntegrityScanReportV1 {
    pub schema: String,
    pub status: AuditStatusV1,
    pub health_ok: bool,
    pub ready_ok: bool,
    pub metrics_build_info_present: bool,
    pub checks: Vec<IntegrityCheckV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
struct IntegrityCheckV1 {
    pub name: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuditIssueV1 {
    pub kind: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StreamHeaderLineV1 {
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
}

#[derive(Debug, Clone)]
struct ComparatorEventRowV1 {
    seq: u64,
    event_id: String,
    event_type: String,
    occurred_at: String,
    header_hash: String,
    payload_hash: String,
}

#[derive(Debug, Deserialize)]
struct ComparatorJsonlLineV1 {
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
}

#[derive(Debug, Deserialize)]
struct Stage1EventEnvelopeV1 {
    #[serde(rename = "eventId")]
    event_id: String,
    #[serde(rename = "tenantId")]
    tenant_id: String,
    #[serde(rename = "streamId")]
    stream_id: String,
    #[serde(rename = "streamType")]
    stream_type: String,
    seq: Option<u64>,
    #[serde(rename = "occurredAt")]
    occurred_at: String,
    #[serde(rename = "eventType")]
    event_type: String,
}

#[derive(Debug, Serialize)]
struct PackBuildInfoV1 {
    pub schema: String,
    #[serde(rename = "corecruxBuild")]
    pub corecrux_build: BuildInfo,
    pub compat: CompatContract,
    pub producer: EvidenceProducerV1,
    #[serde(rename = "corecruxBase")]
    pub corecrux_base: String,
    pub offline: bool,
}

#[derive(Debug)]
struct FileArtifactMeta {
    relative_path: String,
    blake3: String,
    size_bytes: u64,
}

#[derive(Debug)]
struct StreamAuditOutputsV1 {
    ordering: OrderingParityReportV1,
    idempotency: IdempotencyParityReportV1,
    headers: Vec<StreamHeaderLineV1>,
}

#[derive(Debug, Serialize)]
struct LocalEvidenceStatusReportV1 {
    pub schema: String,
    pub status: AuditStatusV1,
    pub mode: String,
    pub note: String,
}

pub fn generate_audit_pack_v1(opts: &AuditPackOptionsV1) -> Result<AuditPackIndexV2, DynError> {
    let out_dir = match opts.out_dir.as_ref() {
        Some(v) => v.clone(),
        None => default_out_dir(),
    };
    std::fs::create_dir_all(&out_dir)?;

    let generated_at = Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true);
    let producer = pack_producer();
    let mut subject_scope = build_subject_scope(opts);
    let (corecrux_build, compat) = observe_corecrux_identity(opts);

    let mut legacy_artifacts: BTreeMap<String, AuditArtifactRefV1> = BTreeMap::new();
    let mut manifest_artifacts: BTreeMap<String, EvidenceArtifactDescriptorV1> = BTreeMap::new();
    let mut artifact_summaries: BTreeMap<String, String> = BTreeMap::new();
    let mut relationships: Vec<EvidenceRelationshipV1> = Vec::new();

    let build_info = PackBuildInfoV1 {
        schema: "corecrux.audit.build_info.v1".to_string(),
        corecrux_build: corecrux_build.clone(),
        compat: compat.clone(),
        producer: producer.clone(),
        corecrux_base: opts.corecrux_base.clone(),
        offline: opts.offline,
    };
    let build_info_path = out_dir.join("build_info.json");
    let build_info_meta = write_pretty_json(&build_info_path, &build_info)?;
    let build_artifact_key = "build_info".to_string();
    register_manifest_artifact(
        &mut manifest_artifacts,
        &mut artifact_summaries,
        build_artifact_key.clone(),
        EvidenceArtifactDescriptorV1 {
            kind: "build_info_json".to_string(),
            media_type: "application/json".to_string(),
            path: build_info_meta.relative_path.clone(),
            blake3: build_info_meta.blake3.clone(),
            size_bytes: build_info_meta.size_bytes,
            status: EvidenceStatusV1::Pass,
            required: true,
            observational: false,
            produced_by: producer.clone(),
            source_refs: vec![EvidenceSourceRefV1::Build {
                version: corecrux_build.version.clone(),
                commit: corecrux_build.commit.clone(),
                compat_requires: Some(compat.requires.clone()),
            }],
        },
        format!("corecrux_version={} compat={}", corecrux_build.version, compat.requires),
    );

    let local_binding_mode = LocalEvidenceStatusReportV1 {
        schema: "corecrux.audit.local_binding_mode.v1".to_string(),
        status: if opts.data_dir.is_some() {
            AuditStatusV1::Pass
        } else {
            AuditStatusV1::Warn
        },
        mode: if opts.data_dir.is_some() {
            "full".to_string()
        } else {
            "remote_compatible".to_string()
        },
        note: if opts.data_dir.is_some() {
            "local artifact binding enabled".to_string()
        } else {
            "full verification-grade audit packs require --data-dir".to_string()
        },
    };
    let local_binding_mode_path = out_dir.join("local_binding_mode.json");
    let local_binding_mode_meta = write_pretty_json(&local_binding_mode_path, &local_binding_mode)?;
    register_manifest_artifact(
        &mut manifest_artifacts,
        &mut artifact_summaries,
        "local_binding_mode".to_string(),
        EvidenceArtifactDescriptorV1 {
            kind: "local_binding_mode_report".to_string(),
            media_type: "application/json".to_string(),
            path: local_binding_mode_meta.relative_path.clone(),
            blake3: local_binding_mode_meta.blake3.clone(),
            size_bytes: local_binding_mode_meta.size_bytes,
            status: audit_status_to_evidence_status(local_binding_mode.status),
            required: true,
            observational: false,
            produced_by: producer.clone(),
            source_refs: Vec::new(),
        },
        local_binding_mode.note.clone(),
    );

    match opts.data_dir.as_ref() {
        Some(data_dir) => {
            let control_bundle = evidence::collect_control_evidence_bundle_v1(&evidence::ControlVerifyOptions {
                data_dir: data_dir.clone(),
                hosted_only: false,
                device_index: opts.device_index,
                batch_frames: 8192,
            })?;
            let control_report_path = out_dir.join("control_verify.json");
            let control_report_meta = write_pretty_json(&control_report_path, &control_bundle.report)?;
            let control_status = control_verify_status(&control_bundle.report);
            register_manifest_artifact(
                &mut manifest_artifacts,
                &mut artifact_summaries,
                "control_verify".to_string(),
                EvidenceArtifactDescriptorV1 {
                    kind: "control_verify_report".to_string(),
                    media_type: "application/json".to_string(),
                    path: control_report_meta.relative_path.clone(),
                    blake3: control_report_meta.blake3.clone(),
                    size_bytes: control_report_meta.size_bytes,
                    status: audit_status_to_evidence_status(control_status),
                    required: true,
                    observational: false,
                    produced_by: producer.clone(),
                    source_refs: control_evidence_source_refs(&control_bundle.evidence_lines),
                },
                format!(
                    "hosted={} ok={} evidence_events={}",
                    control_bundle.report.hosted, control_bundle.report.ok, control_bundle.report.evidence_events
                ),
            );
            if control_bundle.report.hosted {
                let control_checkpoint_path = out_dir.join("control_checkpoint.json");
                let control_checkpoint_meta = write_bytes(&control_checkpoint_path, &control_bundle.checkpoint_bytes)?;
                register_manifest_artifact(
                    &mut manifest_artifacts,
                    &mut artifact_summaries,
                    "control_checkpoint".to_string(),
                    EvidenceArtifactDescriptorV1 {
                        kind: "control_checkpoint_json".to_string(),
                        media_type: "application/json".to_string(),
                        path: control_checkpoint_meta.relative_path.clone(),
                        blake3: control_checkpoint_meta.blake3.clone(),
                        size_bytes: control_checkpoint_meta.size_bytes,
                        status: audit_status_to_evidence_status(control_status),
                        required: true,
                        observational: false,
                        produced_by: producer.clone(),
                        source_refs: Vec::new(),
                    },
                    format!(
                        "blake3={} size_bytes={}",
                        control_bundle.report.expected_checkpoint_blake3,
                        control_bundle.report.expected_checkpoint_size_bytes
                    ),
                );
                let evidence_jsonl = evidence::control_evidence_jsonl(&control_bundle.evidence_lines)?;
                let control_evidence_path = out_dir.join("control_evidence.jsonl");
                let control_evidence_meta = write_bytes(&control_evidence_path, &evidence_jsonl)?;
                register_manifest_artifact(
                    &mut manifest_artifacts,
                    &mut artifact_summaries,
                    "control_evidence_stream".to_string(),
                    EvidenceArtifactDescriptorV1 {
                        kind: "control_evidence_jsonl".to_string(),
                        media_type: "application/jsonl".to_string(),
                        path: control_evidence_meta.relative_path.clone(),
                        blake3: control_evidence_meta.blake3.clone(),
                        size_bytes: control_evidence_meta.size_bytes,
                        status: audit_status_to_evidence_status(control_status),
                        required: true,
                        observational: false,
                        produced_by: producer.clone(),
                        source_refs: control_evidence_source_refs(&control_bundle.evidence_lines),
                    },
                    format!("events={}", control_bundle.evidence_lines.len()),
                );
                relationships.push(EvidenceRelationshipV1 {
                    from: "control_verify".to_string(),
                    to: "control_checkpoint".to_string(),
                    relation: "derived_from".to_string(),
                });
                relationships.push(EvidenceRelationshipV1 {
                    from: "control_verify".to_string(),
                    to: "control_evidence_stream".to_string(),
                    relation: "derived_from".to_string(),
                });
            }
        }
        None => {
            let skipped = LocalEvidenceStatusReportV1 {
                schema: "corecrux.audit.control_verify.v1".to_string(),
                status: AuditStatusV1::Skipped,
                mode: "remote_compatible".to_string(),
                note: "control verification requires --data-dir".to_string(),
            };
            let skipped_path = out_dir.join("control_verify.json");
            let skipped_meta = write_pretty_json(&skipped_path, &skipped)?;
            register_manifest_artifact(
                &mut manifest_artifacts,
                &mut artifact_summaries,
                "control_verify".to_string(),
                EvidenceArtifactDescriptorV1 {
                    kind: "control_verify_report".to_string(),
                    media_type: "application/json".to_string(),
                    path: skipped_meta.relative_path.clone(),
                    blake3: skipped_meta.blake3.clone(),
                    size_bytes: skipped_meta.size_bytes,
                    status: EvidenceStatusV1::Skipped,
                    required: false,
                    observational: false,
                    produced_by: producer.clone(),
                    source_refs: Vec::new(),
                },
                skipped.note,
            );
        }
    }

    // Ordering + idempotency audit from stream export (optionally with v1 comparator input).
    let stream_outputs = build_stream_reports(opts).unwrap_or_else(|err| {
        let msg = err.to_string();
        StreamAuditOutputsV1 {
            ordering: OrderingParityReportV1 {
                schema: "corecrux.audit.ordering_parity.v1".to_string(),
                comparison: "v3_local_only".to_string(),
                status: AuditStatusV1::Fail,
                total_events: 0,
                digest_blake3: None,
                cross_system: None,
                issues: vec![AuditIssueV1 {
                    kind: "stream_export_error".to_string(),
                    message: msg.clone(),
                    seq: None,
                    event_id: None,
                }],
                note: Some("failed to collect stream export headers".to_string()),
            },
            idempotency: IdempotencyParityReportV1 {
                schema: "corecrux.audit.idempotency_parity.v1".to_string(),
                comparison: "v3_local_only".to_string(),
                status: AuditStatusV1::Fail,
                total_events: 0,
                unique_event_ids: 0,
                duplicate_count: 0,
                cross_system: None,
                issues: vec![AuditIssueV1 {
                    kind: "stream_export_error".to_string(),
                    message: msg,
                    seq: None,
                    event_id: None,
                }],
                note: Some("failed to collect stream export headers".to_string()),
            },
            headers: Vec::new(),
        }
    });
    let ordering_report = stream_outputs.ordering;
    let idempotency_report = stream_outputs.idempotency;

    if !stream_outputs.headers.is_empty() {
        let stream_headers_path = out_dir.join("stream_headers.jsonl");
        let headers_bytes = stream_headers_jsonl(&stream_outputs.headers)?;
        let stream_headers_meta = write_bytes(&stream_headers_path, &headers_bytes)?;
        let stream_headers_key = "stream_headers_input".to_string();
        register_manifest_artifact(
            &mut manifest_artifacts,
            &mut artifact_summaries,
            stream_headers_key.clone(),
            EvidenceArtifactDescriptorV1 {
                kind: "stream_headers_input".to_string(),
                media_type: "application/jsonl".to_string(),
                path: stream_headers_meta.relative_path.clone(),
                blake3: stream_headers_meta.blake3.clone(),
                size_bytes: stream_headers_meta.size_bytes,
                status: EvidenceStatusV1::Pass,
                required: true,
                observational: false,
                produced_by: producer.clone(),
                source_refs: stream_header_source_refs(opts, &stream_outputs.headers),
            },
            format!("headers={}", stream_outputs.headers.len()),
        );
        relationships.push(EvidenceRelationshipV1 {
            from: "ordering_parity".to_string(),
            to: stream_headers_key.clone(),
            relation: "derived_from".to_string(),
        });
        relationships.push(EvidenceRelationshipV1 {
            from: "idempotency_parity".to_string(),
            to: stream_headers_key,
            relation: "derived_from".to_string(),
        });
    }

    let ordering_path = out_dir.join("ordering_parity.json");
    let ordering_meta = write_pretty_json(&ordering_path, &ordering_report)?;
    legacy_artifacts.insert(
        "ordering_parity".to_string(),
        AuditArtifactRefV1 {
            status: ordering_report.status,
            file: ordering_meta.relative_path.clone(),
            summary: format!(
                "comparison={} total_events={} issues={}",
                ordering_report.comparison,
                ordering_report.total_events,
                ordering_report.issues.len()
            ),
        },
    );
    register_manifest_artifact(
        &mut manifest_artifacts,
        &mut artifact_summaries,
        "ordering_parity".to_string(),
        EvidenceArtifactDescriptorV1 {
            kind: "ordering_parity_report".to_string(),
            media_type: "application/json".to_string(),
            path: ordering_meta.relative_path.clone(),
            blake3: ordering_meta.blake3.clone(),
            size_bytes: ordering_meta.size_bytes,
            status: audit_status_to_evidence_status(ordering_report.status),
            required: true,
            observational: false,
            produced_by: producer.clone(),
            source_refs: vec![EvidenceSourceRefV1::Build {
                version: corecrux_build.version.clone(),
                commit: corecrux_build.commit.clone(),
                compat_requires: Some(compat.requires.clone()),
            }],
        },
        format!(
            "comparison={} total_events={} issues={}",
            ordering_report.comparison,
            ordering_report.total_events,
            ordering_report.issues.len()
        ),
    );

    let idempotency_path = out_dir.join("idempotency_parity.json");
    let idempotency_meta = write_pretty_json(&idempotency_path, &idempotency_report)?;
    legacy_artifacts.insert(
        "idempotency_parity".to_string(),
        AuditArtifactRefV1 {
            status: idempotency_report.status,
            file: idempotency_meta.relative_path.clone(),
            summary: format!(
                "comparison={} total_events={} duplicates={}",
                idempotency_report.comparison, idempotency_report.total_events, idempotency_report.duplicate_count
            ),
        },
    );
    register_manifest_artifact(
        &mut manifest_artifacts,
        &mut artifact_summaries,
        "idempotency_parity".to_string(),
        EvidenceArtifactDescriptorV1 {
            kind: "idempotency_parity_report".to_string(),
            media_type: "application/json".to_string(),
            path: idempotency_meta.relative_path.clone(),
            blake3: idempotency_meta.blake3.clone(),
            size_bytes: idempotency_meta.size_bytes,
            status: audit_status_to_evidence_status(idempotency_report.status),
            required: true,
            observational: false,
            produced_by: producer.clone(),
            source_refs: vec![EvidenceSourceRefV1::Build {
                version: corecrux_build.version.clone(),
                commit: corecrux_build.commit.clone(),
                compat_requires: Some(compat.requires.clone()),
            }],
        },
        format!(
            "comparison={} total_events={} duplicates={}",
            idempotency_report.comparison, idempotency_report.total_events, idempotency_report.duplicate_count
        ),
    );

    // Projection parity (optional).
    let projection_report = build_projection_parity_report(opts);
    let projection_path = out_dir.join("projection_parity.json");
    let projection_meta = write_pretty_json(&projection_path, &projection_report)?;
    legacy_artifacts.insert(
        "projection_parity".to_string(),
        AuditArtifactRefV1 {
            status: projection_report.status,
            file: projection_meta.relative_path.clone(),
            summary: match projection_report.summary.as_ref() {
                Some(s) => format!(
                    "artifacts_checked={} fail={} warn={} info={}",
                    s.artifacts_checked, s.fail, s.warn, s.info
                ),
                None => projection_report
                    .note
                    .clone()
                    .unwrap_or_else(|| "projection parity skipped".to_string()),
            },
        },
    );
    register_manifest_artifact(
        &mut manifest_artifacts,
        &mut artifact_summaries,
        "projection_parity".to_string(),
        EvidenceArtifactDescriptorV1 {
            kind: "projection_parity_report".to_string(),
            media_type: "application/json".to_string(),
            path: projection_meta.relative_path.clone(),
            blake3: projection_meta.blake3.clone(),
            size_bytes: projection_meta.size_bytes,
            status: audit_status_to_evidence_status(projection_report.status),
            required: true,
            observational: false,
            produced_by: producer.clone(),
            source_refs: projection_source_refs(opts),
        },
        match projection_report.summary.as_ref() {
            Some(s) => format!(
                "artifacts_checked={} fail={} warn={} info={}",
                s.artifacts_checked, s.fail, s.warn, s.info
            ),
            None => projection_report
                .note
                .clone()
                .unwrap_or_else(|| "projection parity skipped".to_string()),
        },
    );

    // Replay determinism (always available offline).
    let replay_report = build_replay_determinism_report(&opts.replay_fixture, opts.device_index)?;
    let replay_path = out_dir.join("replay_determinism.json");
    let replay_meta = write_pretty_json(&replay_path, &replay_report)?;
    legacy_artifacts.insert(
        "replay_determinism".to_string(),
        AuditArtifactRefV1 {
            status: replay_report.status,
            file: replay_meta.relative_path.clone(),
            summary: format!(
                "fixture={} digest_match={} frames_match={}",
                replay_report.fixture, replay_report.digest_match, replay_report.frames_match
            ),
        },
    );
    register_manifest_artifact(
        &mut manifest_artifacts,
        &mut artifact_summaries,
        "replay_determinism".to_string(),
        EvidenceArtifactDescriptorV1 {
            kind: "replay_determinism_report".to_string(),
            media_type: "application/json".to_string(),
            path: replay_meta.relative_path.clone(),
            blake3: replay_meta.blake3.clone(),
            size_bytes: replay_meta.size_bytes,
            status: audit_status_to_evidence_status(replay_report.status),
            required: true,
            observational: false,
            produced_by: producer.clone(),
            source_refs: replay_source_refs(opts),
        },
        format!(
            "fixture={} digest_match={} frames_match={}",
            replay_report.fixture, replay_report.digest_match, replay_report.frames_match
        ),
    );
    let replay_input_path = fixture_digest::fixture_segment_path(&opts.replay_fixture)?;
    let replay_input_bytes = std::fs::read(&replay_input_path)?;
    let replay_input_name = replay_input_path.file_name().map_or_else(
        || format!("{}.ccxseg", opts.replay_fixture),
        |v| v.to_string_lossy().to_string(),
    );
    let replay_input_copy_path = out_dir.join(replay_input_name);
    let replay_input_meta = write_bytes(&replay_input_copy_path, &replay_input_bytes)?;
    register_manifest_artifact(
        &mut manifest_artifacts,
        &mut artifact_summaries,
        "replay_input".to_string(),
        EvidenceArtifactDescriptorV1 {
            kind: "replay_input_segment".to_string(),
            media_type: "application/octet-stream".to_string(),
            path: replay_input_meta.relative_path.clone(),
            blake3: replay_input_meta.blake3.clone(),
            size_bytes: replay_input_meta.size_bytes,
            status: EvidenceStatusV1::Pass,
            required: true,
            observational: false,
            produced_by: producer.clone(),
            source_refs: replay_source_refs(opts),
        },
        format!("fixture={}", opts.replay_fixture),
    );
    relationships.push(EvidenceRelationshipV1 {
        from: "replay_determinism".to_string(),
        to: "replay_input".to_string(),
        relation: "derived_from".to_string(),
    });

    // Integrity endpoint checks (optional in offline mode).
    let integrity_report = build_integrity_scan_report(opts);
    let integrity_path = out_dir.join("integrity_scan.json");
    let integrity_meta = write_pretty_json(&integrity_path, &integrity_report)?;
    legacy_artifacts.insert(
        "integrity_scan".to_string(),
        AuditArtifactRefV1 {
            status: integrity_report.status,
            file: integrity_meta.relative_path.clone(),
            summary: format!(
                "health_ok={} ready_ok={} build_info={}",
                integrity_report.health_ok, integrity_report.ready_ok, integrity_report.metrics_build_info_present
            ),
        },
    );
    register_manifest_artifact(
        &mut manifest_artifacts,
        &mut artifact_summaries,
        "integrity_scan".to_string(),
        EvidenceArtifactDescriptorV1 {
            kind: "integrity_scan_report".to_string(),
            media_type: "application/json".to_string(),
            path: integrity_meta.relative_path.clone(),
            blake3: integrity_meta.blake3.clone(),
            size_bytes: integrity_meta.size_bytes,
            status: audit_status_to_evidence_status(integrity_report.status),
            required: true,
            observational: true,
            produced_by: producer.clone(),
            source_refs: integrity_source_refs(opts),
        },
        format!(
            "health_ok={} ready_ok={} build_info={}",
            integrity_report.health_ok, integrity_report.ready_ok, integrity_report.metrics_build_info_present
        ),
    );

    add_snapshot_evidence_artifacts(
        opts,
        &out_dir,
        &producer,
        &mut manifest_artifacts,
        &mut artifact_summaries,
        &mut relationships,
    )?;

    if let Some(receipt_scope) = add_receipt_evidence_artifacts(
        opts,
        &out_dir,
        &producer,
        &mut manifest_artifacts,
        &mut artifact_summaries,
        &mut relationships,
    )? {
        subject_scope.receipt_id = Some(receipt_scope);
    }

    let mut overall = AuditStatusV1::Skipped;
    for v in legacy_artifacts.values() {
        overall = AuditStatusV1::worst(overall, v.status);
    }

    let legacy_index = AuditPackIndexV1 {
        schema: "corecrux.audit.pack.index.v1".to_string(),
        generated_at: generated_at.clone(),
        corecrux_base: opts.corecrux_base.clone(),
        out_dir: out_dir.display().to_string(),
        status: overall,
        artifacts: legacy_artifacts,
    };

    let legacy_index_path = out_dir.join("audit_pack_index.json");
    let legacy_index_meta = write_pretty_json(&legacy_index_path, &legacy_index)?;
    register_manifest_artifact(
        &mut manifest_artifacts,
        &mut artifact_summaries,
        "legacy_audit_pack_index".to_string(),
        EvidenceArtifactDescriptorV1 {
            kind: "audit_pack_index_v1".to_string(),
            media_type: "application/json".to_string(),
            path: legacy_index_meta.relative_path.clone(),
            blake3: legacy_index_meta.blake3.clone(),
            size_bytes: legacy_index_meta.size_bytes,
            status: audit_status_to_evidence_status(legacy_index.status),
            required: false,
            observational: false,
            produced_by: producer.clone(),
            source_refs: Vec::new(),
        },
        format!("legacy_status={:?}", legacy_index.status).to_lowercase(),
    );

    let manifest_status = manifest_artifacts
        .values()
        .fold(EvidenceStatusV1::Skipped, |acc, artifact| {
            EvidenceStatusV1::worst(acc, artifact.status)
        });

    let manifest = EvidenceManifestV1 {
        schema: EVIDENCE_MANIFEST_SCHEMA_V1.to_string(),
        generated_at: generated_at.clone(),
        producer: producer.clone(),
        corecrux_build,
        compat: Some(compat),
        subject_scope,
        status: manifest_status,
        artifacts: manifest_artifacts,
        relationships,
        missing_capabilities: manifest_missing_capabilities(opts),
    };
    let manifest_path = out_dir.join("evidence_manifest.json");
    let manifest_meta = write_pretty_json(&manifest_path, &manifest)?;

    let index_v2 = AuditPackIndexV2 {
        schema: AUDIT_PACK_INDEX_SCHEMA_V2.to_string(),
        format_version: 1,
        generated_at,
        producer,
        status: manifest.status,
        manifest_path: manifest_meta.relative_path,
        manifest_blake3: manifest_meta.blake3,
        manifest_size_bytes: manifest_meta.size_bytes,
        artifact_summary: build_artifact_summary(&manifest.artifacts, &artifact_summaries),
    };
    let index_v2_path = out_dir.join("audit_pack_index_v2.json");
    let _ = write_pretty_json(&index_v2_path, &index_v2)?;

    Ok(index_v2)
}

fn default_out_dir() -> PathBuf {
    PathBuf::from("reports")
        .join("phase12")
        .join("audit-pack")
        .join(Utc::now().format("%Y%m%dT%H%M%SZ").to_string())
}

fn file_name_string(path: &Path) -> String {
    path.file_name()
        .map_or_else(|| path.display().to_string(), |v| v.to_string_lossy().to_string())
}

fn write_pretty_json<T: Serialize>(path: &Path, value: &T) -> Result<FileArtifactMeta, DynError> {
    let bytes = serde_json::to_vec_pretty(value)?;
    write_bytes(path, &bytes)
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<FileArtifactMeta, DynError> {
    std::fs::write(path, bytes)?;
    Ok(FileArtifactMeta {
        relative_path: file_name_string(path),
        blake3: blake3::hash(bytes).to_hex().to_string(),
        size_bytes: bytes.len() as u64,
    })
}

fn build_stream_reports(opts: &AuditPackOptionsV1) -> Result<StreamAuditOutputsV1, DynError> {
    if opts.offline {
        return Ok(StreamAuditOutputsV1 {
            ordering: OrderingParityReportV1 {
                schema: "corecrux.audit.ordering_parity.v1".to_string(),
                comparison: "v3_local_only".to_string(),
                status: AuditStatusV1::Skipped,
                total_events: 0,
                digest_blake3: None,
                cross_system: None,
                issues: Vec::new(),
                note: Some("offline mode enabled".to_string()),
            },
            idempotency: IdempotencyParityReportV1 {
                schema: "corecrux.audit.idempotency_parity.v1".to_string(),
                comparison: "v3_local_only".to_string(),
                status: AuditStatusV1::Skipped,
                total_events: 0,
                unique_event_ids: 0,
                duplicate_count: 0,
                cross_system: None,
                issues: Vec::new(),
                note: Some("offline mode enabled".to_string()),
            },
            headers: Vec::new(),
        });
    }

    let (tenant_id, stream_type, stream_id) = match (
        opts.tenant_id.as_ref(),
        opts.stream_type.as_ref(),
        opts.stream_id.as_ref(),
    ) {
        (Some(t), Some(st), Some(si)) => (t.as_str(), st.as_str(), si.as_str()),
        _ => {
            return Ok(StreamAuditOutputsV1 {
                ordering: OrderingParityReportV1 {
                    schema: "corecrux.audit.ordering_parity.v1".to_string(),
                    comparison: "v3_local_only".to_string(),
                    status: AuditStatusV1::Skipped,
                    total_events: 0,
                    digest_blake3: None,
                    cross_system: None,
                    issues: Vec::new(),
                    note: Some("stream audit skipped (provide --tenant-id --stream-type --stream-id)".to_string()),
                },
                idempotency: IdempotencyParityReportV1 {
                    schema: "corecrux.audit.idempotency_parity.v1".to_string(),
                    comparison: "v3_local_only".to_string(),
                    status: AuditStatusV1::Skipped,
                    total_events: 0,
                    unique_event_ids: 0,
                    duplicate_count: 0,
                    cross_system: None,
                    issues: Vec::new(),
                    note: Some("stream audit skipped (provide --tenant-id --stream-type --stream-id)".to_string()),
                },
                headers: Vec::new(),
            });
        }
    };

    let max_events = opts.max_events.min(50_000);
    let headers = fetch_stream_headers_v1(
        &opts.corecrux_base,
        tenant_id,
        stream_type,
        stream_id,
        opts.from_seq,
        max_events,
    )?;

    let v1_comparator = load_v1_comparator_source(
        opts.v1_events_log.as_deref(),
        opts.v1_stream_jsonl.as_deref(),
        tenant_id,
        stream_type,
        stream_id,
    )?;
    let (ordering, idempotency) = match v1_comparator {
        Some((source, rows)) => build_cross_system_reports(&headers, &rows, &source),
        None => analyze_stream_headers_local(&headers),
    };
    Ok(StreamAuditOutputsV1 {
        ordering,
        idempotency,
        headers,
    })
}

fn pack_producer() -> EvidenceProducerV1 {
    EvidenceProducerV1 {
        name: "corecruxctl".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: option_env!("CORECRUX_GIT_SHA").unwrap_or("unknown").to_string(),
    }
}

fn observe_corecrux_identity(opts: &AuditPackOptionsV1) -> (BuildInfo, CompatContract) {
    let fallback_build = BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        commit: option_env!("CORECRUX_GIT_SHA").unwrap_or("unknown").to_string(),
    };
    let fallback_compat = CompatContract {
        requires: DEFAULT_COMPAT_REQUIRES.to_string(),
    };
    if opts.offline {
        return (fallback_build, fallback_compat);
    }

    let base = opts.corecrux_base.trim_end_matches('/');
    let health_url = format!("{base}/healthz");
    match ureq::get(&health_url).call() {
        Ok(mut resp) => match resp.body_mut().read_json::<HealthzResponse>() {
            Ok(v) => (v.build, v.compat),
            Err(_) => (fallback_build, fallback_compat),
        },
        Err(_) => (fallback_build, fallback_compat),
    }
}

fn build_subject_scope(opts: &AuditPackOptionsV1) -> EvidenceSubjectScopeV1 {
    EvidenceSubjectScopeV1 {
        tenant_id: opts.tenant_id.clone().or_else(|| opts.parity_tenant_id.clone()),
        stream_type: opts.stream_type.clone(),
        stream_id: opts.stream_id.clone(),
        receipt_id: opts.receipt_id.clone(),
        shard_ids: Vec::new(),
    }
}

fn audit_status_to_evidence_status(status: AuditStatusV1) -> EvidenceStatusV1 {
    match status {
        AuditStatusV1::Pass => EvidenceStatusV1::Pass,
        AuditStatusV1::Warn => EvidenceStatusV1::Warn,
        AuditStatusV1::Fail => EvidenceStatusV1::Fail,
        AuditStatusV1::Skipped => EvidenceStatusV1::Skipped,
    }
}

fn register_manifest_artifact(
    artifacts: &mut BTreeMap<String, EvidenceArtifactDescriptorV1>,
    summaries: &mut BTreeMap<String, String>,
    key: String,
    artifact: EvidenceArtifactDescriptorV1,
    summary: String,
) {
    artifacts.insert(key.clone(), artifact);
    summaries.insert(key, summary);
}

fn build_artifact_summary(
    artifacts: &BTreeMap<String, EvidenceArtifactDescriptorV1>,
    summaries: &BTreeMap<String, String>,
) -> BTreeMap<String, AuditArtifactSummaryV2> {
    let mut out = BTreeMap::new();
    for (key, artifact) in artifacts {
        out.insert(
            key.clone(),
            AuditArtifactSummaryV2 {
                status: artifact.status,
                path: artifact.path.clone(),
                blake3: artifact.blake3.clone(),
                size_bytes: artifact.size_bytes,
                summary: summaries.get(key).cloned().unwrap_or_default(),
            },
        );
    }
    out
}

fn control_verify_status(report: &evidence::ControlVerifyReportV1) -> AuditStatusV1 {
    if report.hosted {
        if report.ok {
            AuditStatusV1::Pass
        } else {
            AuditStatusV1::Fail
        }
    } else {
        AuditStatusV1::Warn
    }
}

fn control_evidence_source_refs(lines: &[evidence::ControlEvidenceJsonLineV1]) -> Vec<EvidenceSourceRefV1> {
    let Some(first) = lines.first() else {
        return Vec::new();
    };
    let mut refs = vec![EvidenceSourceRefV1::Frame {
        tenant_id: "system".to_string(),
        stream_type: "corecrux".to_string(),
        stream_id: "control".to_string(),
        seq: first.seq,
        event_id: first.event_id.clone(),
        event_type: first.event_type.clone(),
        occurred_at: first.occurred_at.clone(),
        header_hash: first.header_hash.clone(),
        payload_hash: first.payload_hash.clone(),
        shard_id: Some(first.shard_id),
        segment_seq: None,
        offset: None,
    }];
    if let Some(last) = lines.last() {
        if last.seq != first.seq || last.shard_id != first.shard_id {
            refs.push(EvidenceSourceRefV1::Frame {
                tenant_id: "system".to_string(),
                stream_type: "corecrux".to_string(),
                stream_id: "control".to_string(),
                seq: last.seq,
                event_id: last.event_id.clone(),
                event_type: last.event_type.clone(),
                occurred_at: last.occurred_at.clone(),
                header_hash: last.header_hash.clone(),
                payload_hash: last.payload_hash.clone(),
                shard_id: Some(last.shard_id),
                segment_seq: None,
                offset: None,
            });
        }
    }
    refs
}

fn default_missing_capabilities() -> Vec<String> {
    vec![
        "decision_plane_events".to_string(),
        "decision_causal_chain_projection".to_string(),
        "temporal_reconstruction_interface".to_string(),
    ]
}

fn manifest_missing_capabilities(opts: &AuditPackOptionsV1) -> Vec<String> {
    let mut out = Vec::new();
    if opts.data_dir.is_none() {
        out.push("current_surface_skipped:control_checkpoint_binding".to_string());
        out.push("current_surface_skipped:projection_snapshot_binding".to_string());
    }
    if (opts.receipt_id.is_some() || opts.answer_id.is_some() || opts.action_id.is_some())
        && opts.receipt_keyring.is_none()
    {
        out.push("current_surface_skipped:receipt_signature_reverify_keyring_missing".to_string());
    }
    out.extend(default_missing_capabilities());
    out
}

fn add_snapshot_evidence_artifacts(
    opts: &AuditPackOptionsV1,
    out_dir: &Path,
    producer: &EvidenceProducerV1,
    artifacts: &mut BTreeMap<String, EvidenceArtifactDescriptorV1>,
    summaries: &mut BTreeMap<String, String>,
    relationships: &mut Vec<EvidenceRelationshipV1>,
) -> Result<(), DynError> {
    let Some(data_dir) = opts.data_dir.as_ref() else {
        let skipped = LocalEvidenceStatusReportV1 {
            schema: "corecrux.audit.snapshot_verify.v1".to_string(),
            status: AuditStatusV1::Skipped,
            mode: "remote_compatible".to_string(),
            note: "projection snapshot binding requires --data-dir".to_string(),
        };
        let skipped_path = out_dir.join("snapshot_verify.json");
        let skipped_meta = write_pretty_json(&skipped_path, &skipped)?;
        register_manifest_artifact(
            artifacts,
            summaries,
            "snapshot_verify".to_string(),
            EvidenceArtifactDescriptorV1 {
                kind: "snapshot_verify_report".to_string(),
                media_type: "application/json".to_string(),
                path: skipped_meta.relative_path.clone(),
                blake3: skipped_meta.blake3.clone(),
                size_bytes: skipped_meta.size_bytes,
                status: EvidenceStatusV1::Skipped,
                required: false,
                observational: false,
                produced_by: producer.clone(),
                source_refs: Vec::new(),
            },
            skipped.note,
        );
        return Ok(());
    };

    let list = snapshot::list_snapshots(&snapshot::SnapshotOptions {
        data_dir: data_dir.clone(),
        shard: None,
    })?;
    let verify = snapshot::verify_snapshots(&snapshot::SnapshotOptions {
        data_dir: data_dir.clone(),
        shard: None,
    })?;
    let verify_path = out_dir.join("snapshot_verify.json");
    let verify_meta = write_pretty_json(&verify_path, &verify)?;
    let verify_status = if verify.ok {
        AuditStatusV1::Pass
    } else {
        AuditStatusV1::Fail
    };
    register_manifest_artifact(
        artifacts,
        summaries,
        "snapshot_verify".to_string(),
        EvidenceArtifactDescriptorV1 {
            kind: "snapshot_verify_report".to_string(),
            media_type: "application/json".to_string(),
            path: verify_meta.relative_path.clone(),
            blake3: verify_meta.blake3.clone(),
            size_bytes: verify_meta.size_bytes,
            status: audit_status_to_evidence_status(verify_status),
            required: true,
            observational: false,
            produced_by: producer.clone(),
            source_refs: Vec::new(),
        },
        format!("failed_shards={}", verify.failed_shards),
    );

    for shard in list.shards {
        let meta_src = data_dir
            .join("shards")
            .join(format!("shard-{:04}", shard.shard_id))
            .join("projections")
            .join("projections.meta.json");
        let meta = load_projections_meta_v1(&meta_src)?;
        let meta_bytes = std::fs::read(&meta_src)?;
        let meta_copy = out_dir.join(format!("shard-{:04}-projections.meta.json", shard.shard_id));
        let meta_copy_meta = write_bytes(&meta_copy, &meta_bytes)?;
        let meta_key = format!("projection_meta_shard_{}", shard.shard_id);
        register_manifest_artifact(
            artifacts,
            summaries,
            meta_key.clone(),
            EvidenceArtifactDescriptorV1 {
                kind: "projection_meta_json".to_string(),
                media_type: "application/json".to_string(),
                path: meta_copy_meta.relative_path.clone(),
                blake3: meta_copy_meta.blake3.clone(),
                size_bytes: meta_copy_meta.size_bytes,
                status: EvidenceStatusV1::Pass,
                required: true,
                observational: false,
                produced_by: producer.clone(),
                source_refs: Vec::new(),
            },
            format!("shard_id={}", shard.shard_id),
        );
        relationships.push(EvidenceRelationshipV1 {
            from: "snapshot_verify".to_string(),
            to: meta_key.clone(),
            relation: "derived_from".to_string(),
        });

        for projection in shard.projections {
            if !projection.exists {
                continue;
            }
            let src = PathBuf::from(&projection.path);
            let bytes = std::fs::read(&src)?;
            let dst = out_dir.join(format!(
                "shard-{:04}-{}",
                shard.shard_id,
                src.file_name()
                    .map_or_else(|| projection.projection.clone(), |v| v.to_string_lossy().to_string())
            ));
            let dst_meta = write_bytes(&dst, &bytes)?;
            let projection_key = format!("projection_snapshot_{}_{}", shard.shard_id, projection.projection);
            register_manifest_artifact(
                artifacts,
                summaries,
                projection_key.clone(),
                EvidenceArtifactDescriptorV1 {
                    kind: "projection_snapshot_ccxs".to_string(),
                    media_type: "application/octet-stream".to_string(),
                    path: dst_meta.relative_path.clone(),
                    blake3: dst_meta.blake3.clone(),
                    size_bytes: dst_meta.size_bytes,
                    status: EvidenceStatusV1::Pass,
                    required: true,
                    observational: false,
                    produced_by: producer.clone(),
                    source_refs: vec![EvidenceSourceRefV1::ProjectionSnapshot {
                        shard_id: shard.shard_id,
                        projection: projection.projection.clone(),
                        cursor: projection_cursor_for_meta(&meta, &projection.projection),
                        expected_blake3: projection.expected_blake3.clone(),
                    }],
                },
                format!(
                    "projection={} expected_blake3={}",
                    projection.projection,
                    projection
                        .expected_blake3
                        .clone()
                        .unwrap_or_else(|| "missing".to_string())
                ),
            );
            relationships.push(EvidenceRelationshipV1 {
                from: "snapshot_verify".to_string(),
                to: projection_key,
                relation: "derived_from".to_string(),
            });
            relationships.push(EvidenceRelationshipV1 {
                from: meta_key.clone(),
                to: format!("projection_snapshot_{}_{}", shard.shard_id, projection.projection),
                relation: "describes".to_string(),
            });
        }
    }
    Ok(())
}

fn add_receipt_evidence_artifacts(
    opts: &AuditPackOptionsV1,
    out_dir: &Path,
    producer: &EvidenceProducerV1,
    artifacts: &mut BTreeMap<String, EvidenceArtifactDescriptorV1>,
    summaries: &mut BTreeMap<String, String>,
    relationships: &mut Vec<EvidenceRelationshipV1>,
) -> Result<Option<String>, DynError> {
    let Some(selector) = receipt_selector(opts)? else {
        return Ok(None);
    };
    if opts.offline {
        return Err("receipt selectors require online CoreCrux access (remove --offline)".into());
    }
    let tenant_id = opts
        .tenant_id
        .as_ref()
        .ok_or_else(|| "receipt selectors require --tenant-id".to_string())?;
    let bundle_bytes = fetch_receipt_export_bundle(opts, tenant_id, &selector)?;
    let mut zip = zip::ZipArchive::new(Cursor::new(bundle_bytes.clone()))?;
    let manifest_json = read_zip_entry(&mut zip, "manifest.json")?;
    let export_manifest: ReplayExportManifestV1 = serde_json::from_slice(&manifest_json)?;
    let receipt_source_ref = EvidenceSourceRefV1::Receipt {
        tenant_id: export_manifest.tenant_id.clone(),
        receipt_id: export_manifest.receipt_id.clone(),
        body_payload_hash: export_manifest.receipt_refs.receipt_body_payload_hash.clone(),
        sig_event_ref: Some(export_manifest.receipt_refs.receipt_sig_event_ref.clone()),
    };

    let bundle_path = out_dir.join("receipt_export.zip");
    let bundle_meta = write_bytes(&bundle_path, &bundle_bytes)?;
    register_manifest_artifact(
        artifacts,
        summaries,
        "receipt_bundle".to_string(),
        EvidenceArtifactDescriptorV1 {
            kind: "receipt_export_bundle".to_string(),
            media_type: "application/zip".to_string(),
            path: bundle_meta.relative_path.clone(),
            blake3: bundle_meta.blake3.clone(),
            size_bytes: bundle_meta.size_bytes,
            status: EvidenceStatusV1::Pass,
            required: true,
            observational: false,
            produced_by: producer.clone(),
            source_refs: vec![receipt_source_ref.clone()],
        },
        format!("selector={} receipt_id={}", selector.kind(), export_manifest.receipt_id),
    );

    let export_manifest_path = out_dir.join("receipt_export_manifest.json");
    let export_manifest_meta = write_bytes(&export_manifest_path, &manifest_json)?;
    register_manifest_artifact(
        artifacts,
        summaries,
        "receipt_export_manifest".to_string(),
        EvidenceArtifactDescriptorV1 {
            kind: "receipt_export_manifest".to_string(),
            media_type: "application/json".to_string(),
            path: export_manifest_meta.relative_path.clone(),
            blake3: export_manifest_meta.blake3.clone(),
            size_bytes: export_manifest_meta.size_bytes,
            status: EvidenceStatusV1::Pass,
            required: true,
            observational: false,
            produced_by: producer.clone(),
            source_refs: vec![receipt_source_ref.clone()],
        },
        format!("included_files={}", export_manifest.included_files.len()),
    );
    relationships.push(EvidenceRelationshipV1 {
        from: "receipt_bundle".to_string(),
        to: "receipt_export_manifest".to_string(),
        relation: "contains".to_string(),
    });

    let verification_json = read_zip_entry(&mut zip, "verification/report.json")?;
    let verification_meta = write_bytes(&out_dir.join("receipt_verification_report.json"), &verification_json)?;
    register_manifest_artifact(
        artifacts,
        summaries,
        "receipt_verification".to_string(),
        EvidenceArtifactDescriptorV1 {
            kind: "receipt_verification_report".to_string(),
            media_type: "application/json".to_string(),
            path: verification_meta.relative_path.clone(),
            blake3: verification_meta.blake3.clone(),
            size_bytes: verification_meta.size_bytes,
            status: EvidenceStatusV1::Pass,
            required: true,
            observational: false,
            produced_by: producer.clone(),
            source_refs: vec![receipt_source_ref.clone()],
        },
        "bundled receipt verification report".to_string(),
    );
    relationships.push(EvidenceRelationshipV1 {
        from: "receipt_verification".to_string(),
        to: "receipt_bundle".to_string(),
        relation: "derived_from".to_string(),
    });

    if let Some(keyring_path) = opts.receipt_keyring.as_ref() {
        let keyring_bytes = std::fs::read(keyring_path)?;
        let keyring_meta = write_bytes(&out_dir.join("receipt_keyring.json"), &keyring_bytes)?;
        register_manifest_artifact(
            artifacts,
            summaries,
            "receipt_keyring".to_string(),
            EvidenceArtifactDescriptorV1 {
                kind: "receipt_keyring_json".to_string(),
                media_type: "application/json".to_string(),
                path: keyring_meta.relative_path.clone(),
                blake3: keyring_meta.blake3.clone(),
                size_bytes: keyring_meta.size_bytes,
                status: EvidenceStatusV1::Pass,
                required: false,
                observational: false,
                produced_by: producer.clone(),
                source_refs: vec![receipt_source_ref.clone()],
            },
            keyring_path.display().to_string(),
        );
        relationships.push(EvidenceRelationshipV1 {
            from: "receipt_verification".to_string(),
            to: "receipt_keyring".to_string(),
            relation: "verified_with".to_string(),
        });
    }

    Ok(Some(export_manifest.receipt_id))
}

fn projection_cursor_for_meta(
    meta: &corecrux_projections::ProjectionsMetaV1,
    projection: &str,
) -> Option<EvidenceProjectionCursorV1> {
    let cursor = match projection {
        "artifact_living_state" => meta.artifact_living_state.cursor.as_ref(),
        "artifact_relations" => meta.artifact_relations.cursor.as_ref(),
        "pressure_events" => meta.pressure_events.cursor.as_ref(),
        "artifact_dependents" => meta.artifact_dependents.cursor.as_ref(),
        _ => None,
    }?;
    Some(EvidenceProjectionCursorV1 {
        shard_id: cursor.shard_id,
        epoch: cursor.epoch,
        segment_seq: cursor.segment_seq,
        offset: cursor.offset,
    })
}

#[derive(Debug, Clone)]
enum ReceiptSelector {
    Receipt(String),
    Answer(String),
    Action(String),
}

impl ReceiptSelector {
    fn kind(&self) -> &'static str {
        match self {
            Self::Receipt(_) => "receipt",
            Self::Answer(_) => "answer",
            Self::Action(_) => "action",
        }
    }

    fn path_component(&self) -> (&'static str, &str) {
        match self {
            Self::Receipt(id) => ("receipts", id.as_str()),
            Self::Answer(id) => ("answers", id.as_str()),
            Self::Action(id) => ("actions", id.as_str()),
        }
    }
}

fn receipt_selector(opts: &AuditPackOptionsV1) -> Result<Option<ReceiptSelector>, DynError> {
    let mut selectors = Vec::new();
    if let Some(id) = opts.receipt_id.as_ref() {
        selectors.push(ReceiptSelector::Receipt(id.clone()));
    }
    if let Some(id) = opts.answer_id.as_ref() {
        selectors.push(ReceiptSelector::Answer(id.clone()));
    }
    if let Some(id) = opts.action_id.as_ref() {
        selectors.push(ReceiptSelector::Action(id.clone()));
    }
    if selectors.len() > 1 {
        return Err("use only one of --receipt-id, --answer-id, or --action-id for audit-pack".into());
    }
    Ok(selectors.into_iter().next())
}

fn fetch_receipt_export_bundle(
    opts: &AuditPackOptionsV1,
    tenant_id: &str,
    selector: &ReceiptSelector,
) -> Result<Vec<u8>, DynError> {
    let base = opts.corecrux_base.trim_end_matches('/');
    let (kind, value) = selector.path_component();
    let url = format!(
        "{base}/v1/replay/exports/{kind}/{value}?tenant_id={tenant_id}&format=zip&redaction=none&include=body,sig,verification,trace_summary,subject_links,linked_receipts"
    );
    let mut resp = ureq::get(&url).call()?;
    let mut bytes = Vec::new();
    resp.body_mut().as_reader().read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn read_zip_entry<R: Read + std::io::Seek>(zip: &mut zip::ZipArchive<R>, path: &str) -> Result<Vec<u8>, DynError> {
    let mut file = zip.by_name(path)?;
    let mut out = Vec::new();
    file.read_to_end(&mut out)?;
    Ok(out)
}

fn stream_headers_jsonl(headers: &[StreamHeaderLineV1]) -> Result<Vec<u8>, DynError> {
    let mut out = Vec::new();
    for header in headers {
        let mut line = serde_json::to_vec(header)?;
        line.push(b'\n');
        out.extend_from_slice(&line);
    }
    Ok(out)
}

#[allow(clippy::unwrap_used)] // SAFETY: .last().expect() is guarded by headers.len() > 1
fn stream_header_source_refs(opts: &AuditPackOptionsV1, headers: &[StreamHeaderLineV1]) -> Vec<EvidenceSourceRefV1> {
    let Some(tenant_id) = opts.tenant_id.as_ref() else {
        return Vec::new();
    };
    let Some(stream_type) = opts.stream_type.as_ref() else {
        return Vec::new();
    };
    let Some(stream_id) = opts.stream_id.as_ref() else {
        return Vec::new();
    };
    if headers.is_empty() {
        return Vec::new();
    }
    let mut refs = Vec::new();
    refs.push(frame_source_ref(tenant_id, stream_type, stream_id, &headers[0]));
    if headers.len() > 1 {
        refs.push(frame_source_ref(
            tenant_id,
            stream_type,
            stream_id,
            // SAFETY: headers.len() > 1 is checked on the line above.
            #[allow(clippy::expect_used)]
            headers.last().expect("last header"),
        ));
    }
    refs
}

fn frame_source_ref(
    tenant_id: &str,
    stream_type: &str,
    stream_id: &str,
    header: &StreamHeaderLineV1,
) -> EvidenceSourceRefV1 {
    EvidenceSourceRefV1::Frame {
        tenant_id: tenant_id.to_string(),
        stream_type: stream_type.to_string(),
        stream_id: stream_id.to_string(),
        seq: header.seq,
        event_id: header.event_id.clone(),
        event_type: header.event_type.clone(),
        occurred_at: header.occurred_at.clone(),
        header_hash: header.header_hash.clone(),
        payload_hash: header.payload_hash.clone(),
        shard_id: None,
        segment_seq: None,
        offset: None,
    }
}

fn replay_source_refs(opts: &AuditPackOptionsV1) -> Vec<EvidenceSourceRefV1> {
    vec![EvidenceSourceRefV1::Runtime {
        node_id: "local-cli".to_string(),
        gpu_id: Some(opts.device_index),
        io_backend: None,
        gds_enabled: None,
        hardware_profile: None,
    }]
}

fn projection_source_refs(opts: &AuditPackOptionsV1) -> Vec<EvidenceSourceRefV1> {
    let _ = opts;
    Vec::new()
}

fn integrity_source_refs(opts: &AuditPackOptionsV1) -> Vec<EvidenceSourceRefV1> {
    let base = opts.corecrux_base.trim_end_matches('/');
    vec![
        EvidenceSourceRefV1::HttpCapture {
            url: format!("{base}/healthz"),
            method: "GET".to_string(),
            status_code: None,
            observational: true,
        },
        EvidenceSourceRefV1::HttpCapture {
            url: format!("{base}/readyz"),
            method: "GET".to_string(),
            status_code: None,
            observational: true,
        },
        EvidenceSourceRefV1::HttpCapture {
            url: format!("{base}/metrics"),
            method: "GET".to_string(),
            status_code: None,
            observational: true,
        },
    ]
}

fn load_v1_comparator_source(
    v1_events_log: Option<&Path>,
    v1_stream_jsonl: Option<&Path>,
    tenant_id: &str,
    stream_type: &str,
    stream_id: &str,
) -> Result<Option<ComparatorSourceV1>, DynError> {
    match (v1_events_log, v1_stream_jsonl) {
        (Some(_), Some(_)) => Err("provide only one comparator source (--v1-events-log OR --v1-stream-jsonl)".into()),
        (Some(path), None) => Ok(Some((
            format!("v1_events_log:{}", path.display()),
            load_v1_events_log_comparator(path, tenant_id, stream_type, stream_id)?,
        ))),
        (None, Some(path)) => Ok(Some((
            format!("v1_stream_jsonl:{}", path.display()),
            load_v1_jsonl_comparator(path)?,
        ))),
        (None, None) => Ok(None),
    }
}

fn load_v1_events_log_comparator(
    events_log: &Path,
    tenant_id: &str,
    stream_type: &str,
    stream_id: &str,
) -> Result<Vec<ComparatorEventRowV1>, DynError> {
    let mut input = BufReader::new(File::open(events_log)?);
    let mut out: Vec<ComparatorEventRowV1> = Vec::new();
    let mut fallback_seq: u64 = 0;

    loop {
        let mut len_buf = [0u8; 4];
        match input.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(err) => return Err(err.into()),
        }

        let len = u32::from_be_bytes(len_buf) as usize;
        if len == 0 || len > 4 * 1024 * 1024 {
            return Err(format!("invalid v1 events.log record length {len}").into());
        }

        let mut payload = vec![0u8; len];
        input.read_exact(&mut payload)?;
        let mut crc_buf = [0u8; 4];
        input.read_exact(&mut crc_buf)?;
        let expected_crc = u32::from_be_bytes(crc_buf);
        let actual_crc = crc32c::crc32c(&payload);
        if expected_crc != actual_crc {
            return Err(format!("crc32c mismatch in v1 events.log: expected {expected_crc}, got {actual_crc}").into());
        }

        let env: Stage1EventEnvelopeV1 = serde_json::from_slice(&payload)?;
        if env.tenant_id != tenant_id || env.stream_type != stream_type || env.stream_id != stream_id {
            continue;
        }

        fallback_seq = fallback_seq.saturating_add(1);
        let seq = env.seq.unwrap_or(fallback_seq);
        let payload_hash = corecrux_frame::compute_payload_hash(&payload);
        let canonical = corecrux_frame::CanonicalHeaderV1 {
            tenant_id: env.tenant_id.clone(),
            stream_id: env.stream_id.clone(),
            stream_type: env.stream_type.clone(),
            seq,
            event_id: env.event_id.clone(),
            occurred_at: env.occurred_at.clone(),
            ingested_at: env.occurred_at.clone(),
            event_type: env.event_type.clone(),
            content_type: "application/json".to_string(),
            payload_len: payload.len() as u32,
            payload_hash,
        };
        let canonical_bytes = corecrux_frame::canonical_header_bytes_v1(&canonical);
        let header_hash = corecrux_frame::compute_header_hash(&canonical_bytes);

        out.push(ComparatorEventRowV1 {
            seq,
            event_id: env.event_id,
            event_type: env.event_type,
            occurred_at: env.occurred_at,
            header_hash: hex32(&header_hash),
            payload_hash: hex32(&payload_hash),
        });
    }

    out.sort_by_key(|row| row.seq);
    Ok(out)
}

fn load_v1_jsonl_comparator(jsonl_path: &Path) -> Result<Vec<ComparatorEventRowV1>, DynError> {
    let input = BufReader::new(File::open(jsonl_path)?);
    let mut out: Vec<ComparatorEventRowV1> = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let row: ComparatorJsonlLineV1 = serde_json::from_str(line).map_err(|err| {
            format!(
                "failed to parse comparator jsonl line {} in {}: {err}",
                idx + 1,
                jsonl_path.display()
            )
        })?;
        out.push(ComparatorEventRowV1 {
            seq: row.seq,
            event_id: row.event_id,
            event_type: row.event_type,
            occurred_at: row.occurred_at,
            header_hash: row.header_hash,
            payload_hash: row.payload_hash,
        });
    }
    out.sort_by_key(|row| row.seq);
    Ok(out)
}

fn fetch_stream_headers_v1(
    corecrux_base: &str,
    tenant_id: &str,
    stream_type: &str,
    stream_id: &str,
    from_seq: u64,
    max_events: u32,
) -> Result<Vec<StreamHeaderLineV1>, DynError> {
    let base = corecrux_base.trim_end_matches('/');
    let url = format!(
        "{base}/v1/replay/exports/streams/{stream_type}/{stream_id}?tenant_id={tenant_id}&fromSeq={from_seq}&maxEvents={max_events}&include=headers&redaction=metadata_only&format=zip"
    );
    let mut resp = ureq::get(&url).call()?;
    let mut zip_bytes: Vec<u8> = Vec::new();
    resp.body_mut().as_reader().read_to_end(&mut zip_bytes)?;

    let mut zip = zip::ZipArchive::new(Cursor::new(zip_bytes))?;
    let mut headers_file = zip.by_name("events/headers.jsonl")?;
    let mut headers_text = String::new();
    headers_file.read_to_string(&mut headers_text)?;

    let mut out: Vec<StreamHeaderLineV1> = Vec::new();
    for (idx, line) in headers_text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let header: StreamHeaderLineV1 = serde_json::from_str(line)
            .map_err(|e| format!("failed to parse events/headers.jsonl line {}: {e}", idx + 1))?;
        out.push(header);
    }

    Ok(out)
}

fn analyze_stream_headers_local(headers: &[StreamHeaderLineV1]) -> (OrderingParityReportV1, IdempotencyParityReportV1) {
    let mut ordering_issues: Vec<AuditIssueV1> = Vec::new();
    let mut idempotency_issues: Vec<AuditIssueV1> = Vec::new();
    let mut seen_event_id: HashMap<&str, u64> = HashMap::new();
    let mut hasher = blake3::Hasher::new();
    let mut prev_seq: Option<u64> = None;

    for h in headers {
        if let Some(prev) = prev_seq {
            if h.seq <= prev {
                ordering_issues.push(AuditIssueV1 {
                    kind: "ORDER_SEQ_NON_MONOTONIC".to_string(),
                    message: format!("seq {} is not greater than previous seq {}", h.seq, prev),
                    seq: Some(h.seq),
                    event_id: Some(h.event_id.clone()),
                });
            }
        }
        prev_seq = Some(h.seq);

        if let Some(first_seq) = seen_event_id.insert(h.event_id.as_str(), h.seq) {
            idempotency_issues.push(AuditIssueV1 {
                kind: "IDEMPOTENCY_DUP_APPEND".to_string(),
                message: format!(
                    "eventId duplicated in export (first seq={}, duplicate seq={})",
                    first_seq, h.seq
                ),
                seq: Some(h.seq),
                event_id: Some(h.event_id.clone()),
            });
        }

        hasher.update(&h.seq.to_le_bytes());
        hasher.update(h.event_id.as_bytes());
        hasher.update(h.header_hash.as_bytes());
        hasher.update(h.payload_hash.as_bytes());
    }

    let ordering_status = if ordering_issues.is_empty() {
        AuditStatusV1::Pass
    } else {
        AuditStatusV1::Fail
    };
    let idempotency_status = if idempotency_issues.is_empty() {
        AuditStatusV1::Pass
    } else {
        AuditStatusV1::Fail
    };

    (
        OrderingParityReportV1 {
            schema: "corecrux.audit.ordering_parity.v1".to_string(),
            comparison: "v3_local_only".to_string(),
            status: ordering_status,
            total_events: headers.len() as u64,
            digest_blake3: Some(hasher.finalize().to_hex().to_string()),
            cross_system: None,
            issues: ordering_issues,
            note: Some(
                "local stream semantic audit; pass --v1-events-log or --v1-stream-jsonl for cross-system parity"
                    .to_string(),
            ),
        },
        IdempotencyParityReportV1 {
            schema: "corecrux.audit.idempotency_parity.v1".to_string(),
            comparison: "v3_local_only".to_string(),
            status: idempotency_status,
            total_events: headers.len() as u64,
            unique_event_ids: seen_event_id.len() as u64,
            duplicate_count: idempotency_issues.len() as u64,
            cross_system: None,
            issues: idempotency_issues,
            note: Some(
                "local stream semantic audit; pass --v1-events-log or --v1-stream-jsonl for cross-system parity"
                    .to_string(),
            ),
        },
    )
}

fn build_cross_system_reports(
    v3_headers: &[StreamHeaderLineV1],
    v1_rows: &[ComparatorEventRowV1],
    source: &str,
) -> (OrderingParityReportV1, IdempotencyParityReportV1) {
    let mut ordering_issues: Vec<AuditIssueV1> = Vec::new();
    let mut idempotency_issues: Vec<AuditIssueV1> = Vec::new();

    let v3_digest = stream_digest_v3(v3_headers);
    let v1_digest = stream_digest_v1(v1_rows);
    let cross_meta = CrossSystemParityMetaV1 {
        source: source.to_string(),
        v1_total_events: v1_rows.len() as u64,
        v3_total_events: v3_headers.len() as u64,
        v1_digest_blake3: v1_digest.clone(),
        v3_digest_blake3: v3_digest.clone(),
        digest_match: v1_digest == v3_digest,
    };

    if v3_headers.len() != v1_rows.len() {
        ordering_issues.push(AuditIssueV1 {
            kind: "ORDER_COUNT_MISMATCH".to_string(),
            message: format!("event count mismatch: v1={} v3={}", v1_rows.len(), v3_headers.len()),
            seq: None,
            event_id: None,
        });
    }

    let mut prev_seq_v3: Option<u64> = None;
    for h in v3_headers {
        if let Some(prev) = prev_seq_v3 {
            if h.seq <= prev {
                ordering_issues.push(AuditIssueV1 {
                    kind: "ORDER_SEQ_NON_MONOTONIC_V3".to_string(),
                    message: format!("v3 seq {} is not greater than previous seq {}", h.seq, prev),
                    seq: Some(h.seq),
                    event_id: Some(h.event_id.clone()),
                });
            }
        }
        prev_seq_v3 = Some(h.seq);
    }
    let mut prev_seq_v1: Option<u64> = None;
    for row in v1_rows {
        if let Some(prev) = prev_seq_v1 {
            if row.seq <= prev {
                ordering_issues.push(AuditIssueV1 {
                    kind: "ORDER_SEQ_NON_MONOTONIC_V1".to_string(),
                    message: format!(
                        "v1 comparator seq {} is not greater than previous seq {}",
                        row.seq, prev
                    ),
                    seq: Some(row.seq),
                    event_id: Some(row.event_id.clone()),
                });
            }
        }
        prev_seq_v1 = Some(row.seq);
    }

    let paired = std::cmp::min(v3_headers.len(), v1_rows.len());
    for idx in 0..paired {
        let v3 = &v3_headers[idx];
        let v1 = &v1_rows[idx];
        if v3.seq != v1.seq
            || v3.event_id != v1.event_id
            || v3.event_type != v1.event_type
            || v3.occurred_at != v1.occurred_at
            || v3.payload_hash != v1.payload_hash
            || v3.header_hash != v1.header_hash
        {
            ordering_issues.push(AuditIssueV1 {
                kind: "ORDER_TUPLE_MISMATCH".to_string(),
                message: format!(
                    "tuple mismatch at ordinal {}: v1(seq={},eventId={}) vs v3(seq={},eventId={})",
                    idx, v1.seq, v1.event_id, v3.seq, v3.event_id
                ),
                seq: Some(v3.seq),
                event_id: Some(v3.event_id.clone()),
            });
        }
    }

    if !cross_meta.digest_match {
        ordering_issues.push(AuditIssueV1 {
            kind: "ORDER_DIGEST_MISMATCH".to_string(),
            message: format!(
                "stream digest mismatch: v1={} v3={}",
                cross_meta.v1_digest_blake3, cross_meta.v3_digest_blake3
            ),
            seq: None,
            event_id: None,
        });
    }

    let mut v3_counts: HashMap<String, (u64, u64)> = HashMap::new();
    for h in v3_headers {
        let entry = v3_counts.entry(h.event_id.clone()).or_insert((0, h.seq));
        entry.0 = entry.0.saturating_add(1);
        if h.seq < entry.1 {
            entry.1 = h.seq;
        }
    }
    let mut v1_counts: HashMap<String, (u64, u64)> = HashMap::new();
    for row in v1_rows {
        let entry = v1_counts.entry(row.event_id.clone()).or_insert((0, row.seq));
        entry.0 = entry.0.saturating_add(1);
        if row.seq < entry.1 {
            entry.1 = row.seq;
        }
    }

    for (event_id, (v1_count, v1_first_seq)) in &v1_counts {
        match v3_counts.get(event_id) {
            Some((v3_count, v3_first_seq)) => {
                if v1_count != v3_count {
                    idempotency_issues.push(AuditIssueV1 {
                        kind: "IDEMPOTENCY_DUP_COUNT_MISMATCH".to_string(),
                        message: format!(
                            "eventId {} duplicate cardinality mismatch: v1={} v3={}",
                            event_id, v1_count, v3_count
                        ),
                        seq: Some(*v3_first_seq),
                        event_id: Some(event_id.clone()),
                    });
                }
                if v1_first_seq != v3_first_seq {
                    idempotency_issues.push(AuditIssueV1 {
                        kind: "IDEMPOTENCY_FIRST_SEQ_MISMATCH".to_string(),
                        message: format!(
                            "eventId {} first-seq mismatch: v1={} v3={}",
                            event_id, v1_first_seq, v3_first_seq
                        ),
                        seq: Some(*v3_first_seq),
                        event_id: Some(event_id.clone()),
                    });
                }
            }
            None => {
                idempotency_issues.push(AuditIssueV1 {
                    kind: "IDEMPOTENCY_EVENT_ID_MISSING_V3".to_string(),
                    message: format!("eventId {} present in v1 comparator but missing in v3", event_id),
                    seq: Some(*v1_first_seq),
                    event_id: Some(event_id.clone()),
                });
            }
        }
    }
    for (event_id, (_v3_count, v3_first_seq)) in &v3_counts {
        if !v1_counts.contains_key(event_id) {
            idempotency_issues.push(AuditIssueV1 {
                kind: "IDEMPOTENCY_EVENT_ID_EXTRA_V3".to_string(),
                message: format!("eventId {} present in v3 but missing in v1 comparator", event_id),
                seq: Some(*v3_first_seq),
                event_id: Some(event_id.clone()),
            });
        }
    }

    let v3_dup_count = v3_counts.values().map(|(count, _)| count.saturating_sub(1)).sum();
    let ordering_status = if ordering_issues.is_empty() {
        AuditStatusV1::Pass
    } else {
        AuditStatusV1::Fail
    };
    let idempotency_status = if idempotency_issues.is_empty() {
        AuditStatusV1::Pass
    } else {
        AuditStatusV1::Fail
    };

    (
        OrderingParityReportV1 {
            schema: "corecrux.audit.ordering_parity.v1".to_string(),
            comparison: "v1_cross_system".to_string(),
            status: ordering_status,
            total_events: v3_headers.len() as u64,
            digest_blake3: Some(v3_digest),
            cross_system: Some(cross_meta.clone()),
            issues: ordering_issues,
            note: Some("cross-system stream parity vs v1 comparator source".to_string()),
        },
        IdempotencyParityReportV1 {
            schema: "corecrux.audit.idempotency_parity.v1".to_string(),
            comparison: "v1_cross_system".to_string(),
            status: idempotency_status,
            total_events: v3_headers.len() as u64,
            unique_event_ids: v3_counts.len() as u64,
            duplicate_count: v3_dup_count,
            cross_system: Some(cross_meta),
            issues: idempotency_issues,
            note: Some("cross-system idempotency parity vs v1 comparator source".to_string()),
        },
    )
}

fn stream_digest_v3(rows: &[StreamHeaderLineV1]) -> String {
    let mut hasher = blake3::Hasher::new();
    for row in rows {
        hasher.update(&row.seq.to_le_bytes());
        hasher.update(row.event_id.as_bytes());
        hasher.update(row.event_type.as_bytes());
        hasher.update(row.occurred_at.as_bytes());
        hasher.update(row.payload_hash.as_bytes());
        hasher.update(row.header_hash.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn stream_digest_v1(rows: &[ComparatorEventRowV1]) -> String {
    let mut hasher = blake3::Hasher::new();
    for row in rows {
        hasher.update(&row.seq.to_le_bytes());
        hasher.update(row.event_id.as_bytes());
        hasher.update(row.event_type.as_bytes());
        hasher.update(row.occurred_at.as_bytes());
        hasher.update(row.payload_hash.as_bytes());
        hasher.update(row.header_hash.as_bytes());
    }
    hasher.finalize().to_hex().to_string()
}

fn hex32(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

fn build_projection_parity_report(opts: &AuditPackOptionsV1) -> ProjectionParityReportV1 {
    if opts.offline {
        return ProjectionParityReportV1 {
            schema: "corecrux.audit.projection_parity.v1".to_string(),
            status: AuditStatusV1::Skipped,
            summary: None,
            report: None,
            note: Some("offline mode enabled".to_string()),
        };
    }

    let tenant_id = match opts.parity_tenant_id.as_deref().or(opts.tenant_id.as_deref()) {
        Some(v) => v,
        None => {
            return ProjectionParityReportV1 {
                schema: "corecrux.audit.projection_parity.v1".to_string(),
                status: AuditStatusV1::Skipped,
                summary: None,
                report: None,
                note: Some("missing parity tenant (--parity-tenant-id or --tenant-id)".to_string()),
            }
        }
    };
    let engine_base = match opts.engine_base.as_deref() {
        Some(v) => v,
        None => {
            return ProjectionParityReportV1 {
                schema: "corecrux.audit.projection_parity.v1".to_string(),
                status: AuditStatusV1::Skipped,
                summary: None,
                report: None,
                note: Some("missing --engine for projection parity".to_string()),
            }
        }
    };
    let engine_api_key = match opts.engine_api_key.as_deref() {
        Some(v) => v,
        None => {
            return ProjectionParityReportV1 {
                schema: "corecrux.audit.projection_parity.v1".to_string(),
                status: AuditStatusV1::Skipped,
                summary: None,
                report: None,
                note: Some("missing --engine-api-key for projection parity".to_string()),
            }
        }
    };

    match parity::parity_living_v1(
        tenant_id,
        &opts.parity_seed,
        opts.parity_sample,
        engine_base,
        engine_api_key,
        &opts.corecrux_base,
    ) {
        Ok(report) => {
            let status = if report.summary.fail > 0 {
                AuditStatusV1::Fail
            } else if report.summary.warn > 0 {
                AuditStatusV1::Warn
            } else {
                AuditStatusV1::Pass
            };
            ProjectionParityReportV1 {
                schema: "corecrux.audit.projection_parity.v1".to_string(),
                status,
                summary: Some(parity::ParitySummaryV1 {
                    artifacts_checked: report.summary.artifacts_checked,
                    fail: report.summary.fail,
                    warn: report.summary.warn,
                    info: report.summary.info,
                }),
                report: Some(report),
                note: None,
            }
        }
        Err(err) => ProjectionParityReportV1 {
            schema: "corecrux.audit.projection_parity.v1".to_string(),
            status: AuditStatusV1::Fail,
            summary: None,
            report: None,
            note: Some(format!("projection parity execution failed: {err}")),
        },
    }
}

fn build_replay_determinism_report(fixture: &str, device_index: i32) -> Result<ReplayDeterminismReportV1, DynError> {
    let run_a = fixture_digest::segment_fixture_replay_digest(fixture, device_index)?;
    let run_b = fixture_digest::segment_fixture_replay_digest(fixture, device_index)?;
    let digest_match = run_a.digest_blake3 == run_b.digest_blake3;
    let frames_match = run_a.total_frames == run_b.total_frames;
    let status = if digest_match && frames_match {
        AuditStatusV1::Pass
    } else {
        AuditStatusV1::Fail
    };

    Ok(ReplayDeterminismReportV1 {
        schema: "corecrux.audit.replay_determinism.v1".to_string(),
        status,
        fixture: fixture.to_string(),
        run_a,
        run_b,
        digest_match,
        frames_match,
    })
}

fn build_integrity_scan_report(opts: &AuditPackOptionsV1) -> IntegrityScanReportV1 {
    if opts.offline {
        return IntegrityScanReportV1 {
            schema: "corecrux.audit.integrity_scan.v1".to_string(),
            status: AuditStatusV1::Skipped,
            health_ok: false,
            ready_ok: false,
            metrics_build_info_present: false,
            checks: vec![IntegrityCheckV1 {
                name: "offline_mode".to_string(),
                ok: true,
                detail: Some("endpoint checks skipped".to_string()),
            }],
            note: Some("offline mode enabled".to_string()),
        };
    }

    let base = opts.corecrux_base.trim_end_matches('/');
    let health_url = format!("{base}/healthz");
    let ready_url = format!("{base}/readyz");
    let metrics_url = format!("{base}/metrics");

    let health_result = ureq::get(&health_url).call();
    let ready_result = ureq::get(&ready_url).call();
    let metrics_result = ureq::get(&metrics_url).call();

    let mut checks: Vec<IntegrityCheckV1> = Vec::new();

    let health_ok = match health_result {
        Ok(mut resp) => match resp.body_mut().read_json::<serde_json::Value>() {
            Ok(v) => {
                let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                let build_ok = v.get("build").is_some();
                let compat_ok = v.get("compat").is_some();
                let sdk_ok = v.get("sdkVersion").is_some();
                let all = ok && build_ok && compat_ok && sdk_ok;
                checks.push(IntegrityCheckV1 {
                    name: "healthz_contract".to_string(),
                    ok: all,
                    detail: Some(format!(
                        "ok={} build={} compat={} sdkVersion={}",
                        ok, build_ok, compat_ok, sdk_ok
                    )),
                });
                all
            }
            Err(err) => {
                checks.push(IntegrityCheckV1 {
                    name: "healthz_parse".to_string(),
                    ok: false,
                    detail: Some(err.to_string()),
                });
                false
            }
        },
        Err(err) => {
            checks.push(IntegrityCheckV1 {
                name: "healthz_fetch".to_string(),
                ok: false,
                detail: Some(err.to_string()),
            });
            false
        }
    };

    let ready_ok = match ready_result {
        Ok(mut resp) => match resp.body_mut().read_json::<serde_json::Value>() {
            Ok(v) => {
                let ok = v.get("ok").and_then(|x| x.as_bool()).unwrap_or(false);
                checks.push(IntegrityCheckV1 {
                    name: "readyz_ok".to_string(),
                    ok,
                    detail: Some(format!("ok={ok}")),
                });
                ok
            }
            Err(err) => {
                checks.push(IntegrityCheckV1 {
                    name: "readyz_parse".to_string(),
                    ok: false,
                    detail: Some(err.to_string()),
                });
                false
            }
        },
        Err(err) => {
            checks.push(IntegrityCheckV1 {
                name: "readyz_fetch".to_string(),
                ok: false,
                detail: Some(err.to_string()),
            });
            false
        }
    };

    let metrics_build_info_present = match metrics_result {
        Ok(mut resp) => {
            let text = resp.body_mut().read_to_string().unwrap_or_default();
            let present = text.lines().any(|l| l.starts_with("build_info"));
            checks.push(IntegrityCheckV1 {
                name: "metrics_build_info".to_string(),
                ok: present,
                detail: Some(format!("build_info_present={present}")),
            });
            present
        }
        Err(err) => {
            checks.push(IntegrityCheckV1 {
                name: "metrics_fetch".to_string(),
                ok: false,
                detail: Some(err.to_string()),
            });
            false
        }
    };

    let status = if health_ok && ready_ok && metrics_build_info_present {
        AuditStatusV1::Pass
    } else {
        AuditStatusV1::Fail
    };

    IntegrityScanReportV1 {
        schema: "corecrux.audit.integrity_scan.v1".to_string(),
        status,
        health_ok,
        ready_ok,
        metrics_build_info_present,
        checks,
        note: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tempfile::tempdir;

    fn h(seq: u64, event_id: &str) -> StreamHeaderLineV1 {
        StreamHeaderLineV1 {
            seq,
            event_id: event_id.to_string(),
            event_type: "evt.test".to_string(),
            occurred_at: "2026-02-11T00:00:00Z".to_string(),
            header_hash: format!("{:064x}", seq + 11),
            payload_hash: format!("{:064x}", seq + 29),
        }
    }

    #[test]
    fn deflated_receipt_export_entry_round_trips() {
        let expected = b"{\"schema\":\"corecrux.receipt_export.v1\"}\n";
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            writer
                .start_file("manifest.json", options)
                .expect("start deflated manifest entry");
            writer.write_all(expected).expect("write deflated manifest");
            writer.finish().expect("finish deflated receipt export");
        }

        let mut archive = zip::ZipArchive::new(Cursor::new(cursor.into_inner())).expect("open deflated receipt export");
        let actual = read_zip_entry(&mut archive, "manifest.json").expect("read deflated receipt export entry");
        assert_eq!(actual, expected);
    }

    #[test]
    fn audit_status_worst_ordering() {
        assert_eq!(
            AuditStatusV1::worst(AuditStatusV1::Pass, AuditStatusV1::Pass),
            AuditStatusV1::Pass
        );
        assert_eq!(
            AuditStatusV1::worst(AuditStatusV1::Pass, AuditStatusV1::Warn),
            AuditStatusV1::Warn
        );
        assert_eq!(
            AuditStatusV1::worst(AuditStatusV1::Warn, AuditStatusV1::Fail),
            AuditStatusV1::Fail
        );
        assert_eq!(
            AuditStatusV1::worst(AuditStatusV1::Fail, AuditStatusV1::Pass),
            AuditStatusV1::Fail
        );
        assert_eq!(
            AuditStatusV1::worst(AuditStatusV1::Skipped, AuditStatusV1::Skipped),
            AuditStatusV1::Skipped
        );
        assert_eq!(
            AuditStatusV1::worst(AuditStatusV1::Skipped, AuditStatusV1::Pass),
            AuditStatusV1::Pass
        );
    }

    #[test]
    fn audit_status_to_evidence_status_mapping() {
        assert_eq!(
            audit_status_to_evidence_status(AuditStatusV1::Pass),
            EvidenceStatusV1::Pass
        );
        assert_eq!(
            audit_status_to_evidence_status(AuditStatusV1::Warn),
            EvidenceStatusV1::Warn
        );
        assert_eq!(
            audit_status_to_evidence_status(AuditStatusV1::Fail),
            EvidenceStatusV1::Fail
        );
        assert_eq!(
            audit_status_to_evidence_status(AuditStatusV1::Skipped),
            EvidenceStatusV1::Skipped
        );
    }

    #[test]
    fn control_verify_status_hosted_ok_is_pass() {
        let report = evidence::ControlVerifyReportV1 {
            schema: "".to_string(),
            ok: true,
            hosted: true,
            data_dir: "".to_string(),
            checkpoint_path: "".to_string(),
            checkpoint_blake3: "".to_string(),
            checkpoint_size_bytes: 0,
            current_control_hash: "".to_string(),
            expected_checkpoint_blake3: "".to_string(),
            expected_checkpoint_size_bytes: 0,
            expected_control_hash: "".to_string(),
            anchor: None,
            anchor_seq: None,
            applied_mutations: 0,
            checkpoint_events: 0,
            mutation_events: 0,
            evidence_events: 0,
            shard_ids: Vec::new(),
            state_matches_evidence: true,
            checkpoint_bytes_match_expected: true,
            error_code: None,
            error_message: None,
        };
        assert_eq!(control_verify_status(&report), AuditStatusV1::Pass);
    }

    #[test]
    fn control_verify_status_hosted_not_ok_is_fail() {
        let report = evidence::ControlVerifyReportV1 {
            schema: "".to_string(),
            ok: false,
            hosted: true,
            data_dir: "".to_string(),
            checkpoint_path: "".to_string(),
            checkpoint_blake3: "".to_string(),
            checkpoint_size_bytes: 0,
            current_control_hash: "".to_string(),
            expected_checkpoint_blake3: "".to_string(),
            expected_checkpoint_size_bytes: 0,
            expected_control_hash: "".to_string(),
            anchor: None,
            anchor_seq: None,
            applied_mutations: 0,
            checkpoint_events: 0,
            mutation_events: 0,
            evidence_events: 0,
            shard_ids: Vec::new(),
            state_matches_evidence: false,
            checkpoint_bytes_match_expected: false,
            error_code: None,
            error_message: None,
        };
        assert_eq!(control_verify_status(&report), AuditStatusV1::Fail);
    }

    #[test]
    fn control_verify_status_not_hosted_is_warn() {
        let report = evidence::ControlVerifyReportV1 {
            schema: "".to_string(),
            ok: true,
            hosted: false,
            data_dir: "".to_string(),
            checkpoint_path: "".to_string(),
            checkpoint_blake3: "".to_string(),
            checkpoint_size_bytes: 0,
            current_control_hash: "".to_string(),
            expected_checkpoint_blake3: "".to_string(),
            expected_checkpoint_size_bytes: 0,
            expected_control_hash: "".to_string(),
            anchor: None,
            anchor_seq: None,
            applied_mutations: 0,
            checkpoint_events: 0,
            mutation_events: 0,
            evidence_events: 0,
            shard_ids: Vec::new(),
            state_matches_evidence: true,
            checkpoint_bytes_match_expected: true,
            error_code: None,
            error_message: None,
        };
        assert_eq!(control_verify_status(&report), AuditStatusV1::Warn);
    }

    #[test]
    fn write_bytes_computes_correct_hash_and_size() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.bin");
        let data = b"hello world";
        let meta = write_bytes(&path, data).expect("write");
        assert_eq!(meta.size_bytes, 11);
        assert_eq!(meta.blake3, blake3::hash(data).to_hex().to_string());
        assert_eq!(meta.relative_path, "test.bin");
    }

    #[test]
    fn file_name_string_extracts_final_component() {
        assert_eq!(file_name_string(std::path::Path::new("/a/b/c.json")), "c.json");
    }

    #[test]
    fn default_out_dir_contains_audit_pack() {
        let out = default_out_dir();
        assert!(out.to_string_lossy().contains("audit-pack"));
    }

    #[test]
    fn build_subject_scope_picks_parity_tenant_fallback() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: None,
            stream_type: Some("knowledge".to_string()),
            stream_id: Some("s1".to_string()),
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: Some("fallback-t".to_string()),
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: None,
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };
        let scope = build_subject_scope(&opts);
        assert_eq!(scope.tenant_id.as_deref(), Some("fallback-t"));
        assert_eq!(scope.stream_type.as_deref(), Some("knowledge"));
        assert_eq!(scope.stream_id.as_deref(), Some("s1"));
    }

    #[test]
    fn manifest_missing_capabilities_includes_defaults() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: None,
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: None,
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };
        let caps = manifest_missing_capabilities(&opts);
        assert!(caps.contains(&"decision_plane_events".to_string()));
        assert!(caps.contains(&"current_surface_skipped:control_checkpoint_binding".to_string()));
    }

    #[test]
    fn receipt_selector_rejects_multiple() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: None,
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: Some("r1".to_string()),
            answer_id: Some("a1".to_string()),
            action_id: None,
            receipt_keyring: None,
        };
        let result = receipt_selector(&opts);
        assert!(result.is_err());
    }

    #[test]
    fn receipt_selector_returns_none_when_empty() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: None,
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: None,
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };
        let result = receipt_selector(&opts).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn receipt_selector_kind_and_path_component() {
        let r = ReceiptSelector::Receipt("r1".to_string());
        assert_eq!(r.kind(), "receipt");
        assert_eq!(r.path_component(), ("receipts", "r1"));

        let a = ReceiptSelector::Answer("a1".to_string());
        assert_eq!(a.kind(), "answer");
        assert_eq!(a.path_component(), ("answers", "a1"));

        let ac = ReceiptSelector::Action("ac1".to_string());
        assert_eq!(ac.kind(), "action");
        assert_eq!(ac.path_component(), ("actions", "ac1"));
    }

    #[test]
    fn hex32_produces_lowercase_64_chars() {
        let bytes = [0u8; 32];
        assert_eq!(hex32(&bytes), "0".repeat(64));
        let bytes2 = [0xffu8; 32];
        assert_eq!(hex32(&bytes2), "f".repeat(64));
    }

    #[test]
    fn stream_digest_v3_is_deterministic() {
        let rows = vec![h(1, "e1"), h(2, "e2")];
        let d1 = stream_digest_v3(&rows);
        let d2 = stream_digest_v3(&rows);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
    }

    #[test]
    fn stream_digest_v3_differs_for_different_input() {
        let a = stream_digest_v3(&[h(1, "e1")]);
        let b = stream_digest_v3(&[h(1, "e2")]);
        assert_ne!(a, b);
    }

    #[test]
    fn build_artifact_summary_maps_all_keys() {
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "k1".to_string(),
            EvidenceArtifactDescriptorV1 {
                kind: "test".to_string(),
                media_type: "application/json".to_string(),
                path: "k1.json".to_string(),
                blake3: "hash".to_string(),
                size_bytes: 42,
                status: EvidenceStatusV1::Pass,
                required: true,
                observational: false,
                produced_by: EvidenceProducerV1 {
                    name: "t".to_string(),
                    version: "0".to_string(),
                    commit: "0".to_string(),
                },
                source_refs: Vec::new(),
            },
        );
        let mut summaries = BTreeMap::new();
        summaries.insert("k1".to_string(), "test summary".to_string());
        let result = build_artifact_summary(&artifacts, &summaries);
        assert!(result.contains_key("k1"));
        assert_eq!(result["k1"].summary, "test summary");
        assert_eq!(result["k1"].size_bytes, 42);
    }

    #[test]
    fn stream_headers_jsonl_round_trip() {
        let headers = vec![h(1, "e1"), h(2, "e2")];
        let bytes = stream_headers_jsonl(&headers).expect("serialize");
        let lines: Vec<&str> = std::str::from_utf8(&bytes).unwrap().lines().collect();
        assert_eq!(lines.len(), 2);
        let parsed: StreamHeaderLineV1 = serde_json::from_str(lines[0]).expect("parse line");
        assert_eq!(parsed.seq, 1);
        assert_eq!(parsed.event_id, "e1");
    }

    #[test]
    fn analyze_stream_headers_empty_input() {
        let (ordering, idempotency) = analyze_stream_headers_local(&[]);
        assert_eq!(ordering.status, AuditStatusV1::Pass);
        assert_eq!(idempotency.status, AuditStatusV1::Pass);
        assert_eq!(ordering.total_events, 0);
        assert_eq!(idempotency.unique_event_ids, 0);
    }

    #[test]
    fn analyze_stream_headers_passes_monotonic_unique_stream() {
        let rows = vec![h(10, "e1"), h(11, "e2"), h(12, "e3")];
        let (ordering, idempotency) = analyze_stream_headers_local(&rows);
        assert_eq!(ordering.status, AuditStatusV1::Pass);
        assert_eq!(idempotency.status, AuditStatusV1::Pass);
        assert_eq!(ordering.total_events, 3);
        assert_eq!(idempotency.duplicate_count, 0);
        assert_eq!(idempotency.unique_event_ids, 3);
        assert!(ordering.digest_blake3.is_some());
    }

    #[test]
    fn analyze_stream_headers_flags_ordering_and_idempotency_failures() {
        let rows = vec![h(20, "e1"), h(19, "e2"), h(21, "e1")];
        let (ordering, idempotency) = analyze_stream_headers_local(&rows);
        assert_eq!(ordering.status, AuditStatusV1::Fail);
        assert_eq!(idempotency.status, AuditStatusV1::Fail);
        assert!(!ordering.issues.is_empty());
        assert_eq!(idempotency.duplicate_count, 1);
    }

    #[test]
    fn cross_system_reports_fail_on_tuple_mismatch() {
        let v3 = vec![h(1, "e1"), h(2, "e2")];
        let v1 = vec![
            ComparatorEventRowV1 {
                seq: 1,
                event_id: "e1".to_string(),
                event_type: "evt.test".to_string(),
                occurred_at: "2026-02-11T00:00:00Z".to_string(),
                header_hash: format!("{:064x}", 1 + 11),
                payload_hash: format!("{:064x}", 1 + 29),
            },
            ComparatorEventRowV1 {
                seq: 2,
                event_id: "DIFF".to_string(),
                event_type: "evt.test".to_string(),
                occurred_at: "2026-02-11T00:00:00Z".to_string(),
                header_hash: format!("{:064x}", 2 + 11),
                payload_hash: format!("{:064x}", 2 + 29),
            },
        ];
        let (ordering, idempotency) = build_cross_system_reports(&v3, &v1, "test");
        assert_eq!(ordering.status, AuditStatusV1::Fail);
        assert_eq!(idempotency.status, AuditStatusV1::Fail);
        assert_eq!(ordering.comparison, "v1_cross_system");
        assert!(ordering.cross_system.is_some());
    }

    #[test]
    fn generate_audit_pack_emits_manifest_and_v2_index() {
        let out = tempdir().expect("tempdir");
        let opts = AuditPackOptionsV1 {
            out_dir: Some(out.path().to_path_buf()),
            offline: true,
            corecrux_base: "http://127.0.0.1:4006".to_string(),
            data_dir: None,
            tenant_id: None,
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 128,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: None,
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };

        let index = generate_audit_pack_v1(&opts).expect("generate audit pack");
        assert_eq!(index.schema, AUDIT_PACK_INDEX_SCHEMA_V2);
        assert_eq!(index.manifest_path, "evidence_manifest.json");

        let manifest_path = out.path().join("evidence_manifest.json");
        let index_v2_path = out.path().join("audit_pack_index_v2.json");
        let legacy_index_path = out.path().join("audit_pack_index.json");

        assert!(manifest_path.exists());
        assert!(index_v2_path.exists());
        assert!(legacy_index_path.exists());

        let manifest: EvidenceManifestV1 =
            serde_json::from_slice(&std::fs::read(&manifest_path).expect("read manifest")).expect("parse manifest");
        assert_eq!(manifest.schema, EVIDENCE_MANIFEST_SCHEMA_V1);
        assert!(manifest.artifacts.contains_key("build_info"));
        assert!(manifest.artifacts.contains_key("local_binding_mode"));
        assert!(manifest.artifacts.contains_key("control_verify"));
        assert!(manifest.artifacts.contains_key("snapshot_verify"));
        assert!(manifest.artifacts.contains_key("replay_input"));
        assert!(manifest.artifacts.contains_key("legacy_audit_pack_index"));
        assert!(manifest
            .missing_capabilities
            .contains(&"current_surface_skipped:control_checkpoint_binding".to_string()));
        assert!(manifest
            .missing_capabilities
            .contains(&"decision_plane_events".to_string()));

        let persisted_index: AuditPackIndexV2 =
            serde_json::from_slice(&std::fs::read(&index_v2_path).expect("read index")).expect("parse index");
        assert_eq!(persisted_index.schema, AUDIT_PACK_INDEX_SCHEMA_V2);
        assert!(persisted_index.artifact_summary.contains_key("build_info"));
        assert!(persisted_index.artifact_summary.contains_key("local_binding_mode"));
        assert!(persisted_index.artifact_summary.contains_key("legacy_audit_pack_index"));
    }

    // ── AuditStatusV1::worst edge cases ────────────────────────────

    #[test]
    fn audit_status_worst_warn_with_skipped() {
        assert_eq!(
            AuditStatusV1::worst(AuditStatusV1::Warn, AuditStatusV1::Skipped),
            AuditStatusV1::Warn
        );
        assert_eq!(
            AuditStatusV1::worst(AuditStatusV1::Skipped, AuditStatusV1::Warn),
            AuditStatusV1::Warn
        );
    }

    #[test]
    fn audit_status_worst_fail_with_skipped() {
        assert_eq!(
            AuditStatusV1::worst(AuditStatusV1::Fail, AuditStatusV1::Skipped),
            AuditStatusV1::Fail
        );
    }

    // ── control_evidence_source_refs ───────────────────────────────

    #[test]
    fn control_evidence_source_refs_empty_input() {
        let refs = control_evidence_source_refs(&[]);
        assert!(refs.is_empty());
    }

    #[test]
    fn control_evidence_source_refs_single_element() {
        let line = evidence::ControlEvidenceJsonLineV1 {
            shard_id: 1,
            seq: 10,
            event_id: "e1".to_string(),
            event_type: "corecrux.control.state_mutation.v1".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:01Z".to_string(),
            header_hash: "aa".repeat(32),
            payload_hash: "bb".repeat(32),
            payload: serde_json::json!({}),
        };
        let refs = control_evidence_source_refs(&[line]);
        // Single element: first == last, so only one ref emitted
        assert_eq!(refs.len(), 1);
    }

    #[test]
    fn control_evidence_source_refs_multi_element() {
        let line1 = evidence::ControlEvidenceJsonLineV1 {
            shard_id: 1,
            seq: 10,
            event_id: "e1".to_string(),
            event_type: "t".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:00Z".to_string(),
            header_hash: "aa".repeat(32),
            payload_hash: "bb".repeat(32),
            payload: serde_json::json!({}),
        };
        let line2 = evidence::ControlEvidenceJsonLineV1 {
            shard_id: 1,
            seq: 20,
            event_id: "e2".to_string(),
            event_type: "t".to_string(),
            occurred_at: "2026-01-02T00:00:00Z".to_string(),
            ingested_at: "2026-01-02T00:00:00Z".to_string(),
            header_hash: "cc".repeat(32),
            payload_hash: "dd".repeat(32),
            payload: serde_json::json!({}),
        };
        let refs = control_evidence_source_refs(&[line1, line2]);
        // Different seq/shard → first + last
        assert_eq!(refs.len(), 2);
    }

    // ── manifest_missing_capabilities edge cases ───────────────────

    #[test]
    fn manifest_missing_capabilities_with_receipt_and_keyring() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: Some(PathBuf::from("/tmp")),
            tenant_id: None,
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: Some("r1".to_string()),
            answer_id: None,
            action_id: None,
            receipt_keyring: Some(PathBuf::from("/tmp/keyring.json")),
        };
        let caps = manifest_missing_capabilities(&opts);
        // data_dir is Some → no control_checkpoint_binding skip
        assert!(!caps.contains(&"current_surface_skipped:control_checkpoint_binding".to_string()));
        // keyring is Some → no receipt_signature skip
        assert!(!caps.contains(&"current_surface_skipped:receipt_signature_reverify_keyring_missing".to_string()));
        // Always includes default capabilities
        assert!(caps.contains(&"decision_plane_events".to_string()));
    }

    #[test]
    fn manifest_missing_capabilities_receipt_without_keyring() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: Some(PathBuf::from("/tmp")),
            tenant_id: None,
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: Some("r1".to_string()),
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };
        let caps = manifest_missing_capabilities(&opts);
        // receipt without keyring → adds keyring missing capability
        assert!(caps.contains(&"current_surface_skipped:receipt_signature_reverify_keyring_missing".to_string()));
    }

    // ── default_missing_capabilities ───────────────────────────────

    #[test]
    fn default_missing_capabilities_contains_expected_items() {
        let caps = default_missing_capabilities();
        assert_eq!(caps.len(), 3);
        assert!(caps.contains(&"decision_plane_events".to_string()));
        assert!(caps.contains(&"decision_causal_chain_projection".to_string()));
        assert!(caps.contains(&"temporal_reconstruction_interface".to_string()));
    }

    // ── stream_digest_v1 ──────────────────────────────────────────

    #[test]
    fn stream_digest_v1_is_deterministic() {
        let rows = vec![
            ComparatorEventRowV1 {
                seq: 1,
                event_id: "e1".to_string(),
                event_type: "evt.test".to_string(),
                occurred_at: "2026-02-11T00:00:00Z".to_string(),
                header_hash: "aa".repeat(32),
                payload_hash: "bb".repeat(32),
            },
            ComparatorEventRowV1 {
                seq: 2,
                event_id: "e2".to_string(),
                event_type: "evt.test".to_string(),
                occurred_at: "2026-02-11T00:00:00Z".to_string(),
                header_hash: "cc".repeat(32),
                payload_hash: "dd".repeat(32),
            },
        ];
        let d1 = stream_digest_v1(&rows);
        let d2 = stream_digest_v1(&rows);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
    }

    #[test]
    fn stream_digest_v1_empty_input() {
        let d = stream_digest_v1(&[]);
        assert_eq!(d.len(), 64);
    }

    // ── write_pretty_json ─────────────────────────────────────────

    #[test]
    fn write_pretty_json_creates_valid_json() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("test.json");
        let data = serde_json::json!({"hello": "world", "num": 42});
        let meta = write_pretty_json(&path, &data).expect("write");
        assert_eq!(meta.relative_path, "test.json");
        assert!(meta.size_bytes > 0);
        let read_back: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(read_back["hello"], "world");
        assert_eq!(read_back["num"], 42);
    }

    // ── build_subject_scope priority ──────────────────────────────

    #[test]
    fn build_subject_scope_tenant_id_takes_priority() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: Some("primary".to_string()),
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: Some("fallback".to_string()),
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: None,
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };
        let scope = build_subject_scope(&opts);
        assert_eq!(scope.tenant_id.as_deref(), Some("primary"));
    }

    #[test]
    fn build_subject_scope_no_tenant() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: None,
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: None,
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };
        let scope = build_subject_scope(&opts);
        assert!(scope.tenant_id.is_none());
        assert!(scope.stream_type.is_none());
    }

    // ── stream_header_source_refs ─────────────────────────────────

    #[test]
    fn stream_header_source_refs_no_tenant() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: None,
            stream_type: Some("knowledge".to_string()),
            stream_id: Some("s1".to_string()),
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: None,
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };
        let refs = stream_header_source_refs(&opts, &[h(1, "e1")]);
        assert!(refs.is_empty());
    }

    #[test]
    fn stream_header_source_refs_empty_headers() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: Some("t1".to_string()),
            stream_type: Some("knowledge".to_string()),
            stream_id: Some("s1".to_string()),
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: None,
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };
        let refs = stream_header_source_refs(&opts, &[]);
        assert!(refs.is_empty());
    }

    #[test]
    fn stream_header_source_refs_single_header() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: Some("t1".to_string()),
            stream_type: Some("knowledge".to_string()),
            stream_id: Some("s1".to_string()),
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: None,
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };
        let refs = stream_header_source_refs(&opts, &[h(1, "e1")]);
        assert_eq!(refs.len(), 1);
    }

    #[test]
    fn stream_header_source_refs_multi_headers() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: Some("t1".to_string()),
            stream_type: Some("knowledge".to_string()),
            stream_id: Some("s1".to_string()),
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: None,
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };
        let refs = stream_header_source_refs(&opts, &[h(1, "e1"), h(2, "e2"), h(3, "e3")]);
        assert_eq!(refs.len(), 2); // first + last
    }

    // ── source ref helpers ────────────────────────────────────────

    #[test]
    fn replay_source_refs_includes_device_index() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: None,
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 3,
            receipt_id: None,
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };
        let refs = replay_source_refs(&opts);
        assert_eq!(refs.len(), 1);
    }

    #[test]
    fn projection_source_refs_is_empty() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: None,
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: None,
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };
        assert!(projection_source_refs(&opts).is_empty());
    }

    #[test]
    fn integrity_source_refs_contains_three_endpoints() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost:14800/".to_string(),
            data_dir: None,
            tenant_id: None,
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: None,
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };
        let refs = integrity_source_refs(&opts);
        assert_eq!(refs.len(), 3);
    }

    // ── load_v1_jsonl_comparator ──────────────────────────────────

    #[test]
    fn load_v1_jsonl_comparator_empty_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("empty.jsonl");
        std::fs::write(&path, "").expect("write");
        let rows = load_v1_jsonl_comparator(&path).expect("parse");
        assert!(rows.is_empty());
    }

    #[test]
    fn load_v1_jsonl_comparator_round_trip() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("data.jsonl");
        let content = r#"{"seq":5,"eventId":"e5","eventType":"t","occurredAt":"2026-01-01T00:00:00Z","headerHash":"aa","payloadHash":"bb"}
{"seq":3,"eventId":"e3","eventType":"t","occurredAt":"2026-01-01T00:00:00Z","headerHash":"cc","payloadHash":"dd"}
"#;
        std::fs::write(&path, content).expect("write");
        let rows = load_v1_jsonl_comparator(&path).expect("parse");
        assert_eq!(rows.len(), 2);
        // Should be sorted by seq
        assert_eq!(rows[0].seq, 3);
        assert_eq!(rows[1].seq, 5);
    }

    // ── cross-system edge cases ───────────────────────────────────

    #[test]
    fn cross_system_reports_pass_on_matching_tuples() {
        let v3 = vec![h(1, "e1"), h(2, "e2")];
        let v1 = vec![
            ComparatorEventRowV1 {
                seq: 1,
                event_id: "e1".to_string(),
                event_type: "evt.test".to_string(),
                occurred_at: "2026-02-11T00:00:00Z".to_string(),
                header_hash: format!("{:064x}", 1 + 11),
                payload_hash: format!("{:064x}", 1 + 29),
            },
            ComparatorEventRowV1 {
                seq: 2,
                event_id: "e2".to_string(),
                event_type: "evt.test".to_string(),
                occurred_at: "2026-02-11T00:00:00Z".to_string(),
                header_hash: format!("{:064x}", 2 + 11),
                payload_hash: format!("{:064x}", 2 + 29),
            },
        ];
        let (ordering, idempotency) = build_cross_system_reports(&v3, &v1, "test");
        assert_eq!(ordering.status, AuditStatusV1::Pass);
        assert_eq!(idempotency.status, AuditStatusV1::Pass);
        assert!(ordering.cross_system.as_ref().unwrap().digest_match);
    }

    #[test]
    fn cross_system_reports_count_mismatch() {
        let v3 = vec![h(1, "e1")];
        let v1 = vec![
            ComparatorEventRowV1 {
                seq: 1,
                event_id: "e1".to_string(),
                event_type: "evt.test".to_string(),
                occurred_at: "2026-02-11T00:00:00Z".to_string(),
                header_hash: format!("{:064x}", 1 + 11),
                payload_hash: format!("{:064x}", 1 + 29),
            },
            ComparatorEventRowV1 {
                seq: 2,
                event_id: "e2".to_string(),
                event_type: "evt.test".to_string(),
                occurred_at: "2026-02-11T00:00:00Z".to_string(),
                header_hash: format!("{:064x}", 2 + 11),
                payload_hash: format!("{:064x}", 2 + 29),
            },
        ];
        let (ordering, _idempotency) = build_cross_system_reports(&v3, &v1, "test");
        assert_eq!(ordering.status, AuditStatusV1::Fail);
        assert!(ordering.issues.iter().any(|i| i.kind == "ORDER_COUNT_MISMATCH"));
    }

    // ── receipt_selector: single selectors ────────────────────────

    #[test]
    fn receipt_selector_action_only() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: None,
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: None,
            answer_id: None,
            action_id: Some("ac1".to_string()),
            receipt_keyring: None,
        };
        let result = receipt_selector(&opts).unwrap();
        assert!(result.is_some());
        let selector = result.unwrap();
        assert_eq!(selector.kind(), "action");
        assert_eq!(selector.path_component(), ("actions", "ac1"));
    }

    // ── register_manifest_artifact ────────────────────────────────

    #[test]
    fn register_manifest_artifact_inserts_both_maps() {
        let mut artifacts = BTreeMap::new();
        let mut summaries = BTreeMap::new();
        register_manifest_artifact(
            &mut artifacts,
            &mut summaries,
            "test_key".to_string(),
            EvidenceArtifactDescriptorV1 {
                kind: "test_kind".to_string(),
                media_type: "application/json".to_string(),
                path: "test.json".to_string(),
                blake3: "hash".to_string(),
                size_bytes: 100,
                status: EvidenceStatusV1::Pass,
                required: true,
                observational: false,
                produced_by: EvidenceProducerV1 {
                    name: "t".to_string(),
                    version: "0".to_string(),
                    commit: "0".to_string(),
                },
                source_refs: Vec::new(),
            },
            "summary text".to_string(),
        );
        assert!(artifacts.contains_key("test_key"));
        assert_eq!(summaries["test_key"], "summary text");
    }

    // ── build_artifact_summary edge cases ─────────────────────────

    #[test]
    fn build_artifact_summary_missing_summary_defaults_empty() {
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "k1".to_string(),
            EvidenceArtifactDescriptorV1 {
                kind: "test".to_string(),
                media_type: "application/json".to_string(),
                path: "k1.json".to_string(),
                blake3: "hash".to_string(),
                size_bytes: 10,
                status: EvidenceStatusV1::Warn,
                required: false,
                observational: true,
                produced_by: EvidenceProducerV1 {
                    name: "t".to_string(),
                    version: "0".to_string(),
                    commit: "0".to_string(),
                },
                source_refs: Vec::new(),
            },
        );
        let summaries = BTreeMap::new(); // no summary for k1
        let result = build_artifact_summary(&artifacts, &summaries);
        assert_eq!(result["k1"].summary, "");
    }

    // ── file_name_string with no file name ────────────────────────

    #[test]
    fn file_name_string_root_path_falls_back() {
        let name = file_name_string(std::path::Path::new("/"));
        // Falls back to display() for root
        assert!(!name.is_empty());
    }

    // ── pack_producer ─────────────────────────────────────────────

    #[test]
    fn pack_producer_has_expected_name() {
        let p = pack_producer();
        assert_eq!(p.name, "corecruxctl");
        assert!(!p.version.is_empty());
    }

    // ── analyze_stream_headers single element ─────────────────────

    #[test]
    fn analyze_stream_headers_single_element_passes() {
        let rows = vec![h(1, "e1")];
        let (ordering, idempotency) = analyze_stream_headers_local(&rows);
        assert_eq!(ordering.status, AuditStatusV1::Pass);
        assert_eq!(idempotency.status, AuditStatusV1::Pass);
        assert_eq!(ordering.total_events, 1);
        assert_eq!(idempotency.unique_event_ids, 1);
    }

    // ── load_v1_comparator_source mutual exclusion ────────────────

    #[test]
    fn load_v1_comparator_source_rejects_both() {
        let result = load_v1_comparator_source(
            Some(std::path::Path::new("/a")),
            Some(std::path::Path::new("/b")),
            "t",
            "s",
            "id",
        );
        assert!(result.is_err());
    }

    #[test]
    fn load_v1_comparator_source_none_returns_none() {
        let result = load_v1_comparator_source(None, None, "t", "s", "id").unwrap();
        assert!(result.is_none());
    }

    // ── analyze_stream_headers_local: equal seq regression ───────

    #[test]
    fn analyze_stream_headers_equal_seq_is_non_monotonic() {
        let rows = vec![h(5, "e1"), h(5, "e2")];
        let (ordering, _idempotency) = analyze_stream_headers_local(&rows);
        assert_eq!(ordering.status, AuditStatusV1::Fail);
        assert!(ordering.issues.iter().any(|i| i.kind == "ORDER_SEQ_NON_MONOTONIC"));
    }

    // ── analyze_stream_headers_local: duplicate event ids ────────

    #[test]
    fn analyze_stream_headers_duplicate_event_ids_only() {
        let rows = vec![h(1, "e1"), h(2, "e1")];
        let (ordering, idempotency) = analyze_stream_headers_local(&rows);
        // Ordering is fine (monotonic), idempotency fails
        assert_eq!(ordering.status, AuditStatusV1::Pass);
        assert_eq!(idempotency.status, AuditStatusV1::Fail);
        assert_eq!(idempotency.duplicate_count, 1);
        assert_eq!(idempotency.unique_event_ids, 1);
    }

    // ── analyze_stream_headers_local: many duplicates ────────────

    #[test]
    fn analyze_stream_headers_many_duplicates() {
        let rows = vec![h(1, "e1"), h(2, "e1"), h(3, "e1"), h(4, "e2")];
        let (_ordering, idempotency) = analyze_stream_headers_local(&rows);
        assert_eq!(idempotency.status, AuditStatusV1::Fail);
        assert_eq!(idempotency.duplicate_count, 2); // e1 appears 3 times, 2 duplicates
        assert_eq!(idempotency.unique_event_ids, 2); // e1, e2
        assert_eq!(idempotency.total_events, 4);
    }

    // ── cross_system: v1 non-monotonic seq ───────────────────────

    #[test]
    fn cross_system_reports_flags_v1_non_monotonic() {
        let v3 = vec![h(1, "e1"), h(2, "e2")];
        let v1 = vec![
            ComparatorEventRowV1 {
                seq: 2,
                event_id: "e2".to_string(),
                event_type: "evt.test".to_string(),
                occurred_at: "2026-02-11T00:00:00Z".to_string(),
                header_hash: format!("{:064x}", 2 + 11),
                payload_hash: format!("{:064x}", 2 + 29),
            },
            ComparatorEventRowV1 {
                seq: 1, // non-monotonic
                event_id: "e1".to_string(),
                event_type: "evt.test".to_string(),
                occurred_at: "2026-02-11T00:00:00Z".to_string(),
                header_hash: format!("{:064x}", 1 + 11),
                payload_hash: format!("{:064x}", 1 + 29),
            },
        ];
        let (ordering, _) = build_cross_system_reports(&v3, &v1, "test");
        assert_eq!(ordering.status, AuditStatusV1::Fail);
        assert!(ordering.issues.iter().any(|i| i.kind == "ORDER_SEQ_NON_MONOTONIC_V1"));
    }

    // ── cross_system: v3 non-monotonic seq ───────────────────────

    #[test]
    fn cross_system_reports_flags_v3_non_monotonic() {
        let v3 = vec![h(5, "e1"), h(3, "e2")]; // non-monotonic
        let v1 = vec![
            ComparatorEventRowV1 {
                seq: 3,
                event_id: "e2".to_string(),
                event_type: "evt.test".to_string(),
                occurred_at: "2026-02-11T00:00:00Z".to_string(),
                header_hash: format!("{:064x}", 3 + 11),
                payload_hash: format!("{:064x}", 3 + 29),
            },
            ComparatorEventRowV1 {
                seq: 5,
                event_id: "e1".to_string(),
                event_type: "evt.test".to_string(),
                occurred_at: "2026-02-11T00:00:00Z".to_string(),
                header_hash: format!("{:064x}", 5 + 11),
                payload_hash: format!("{:064x}", 5 + 29),
            },
        ];
        let (ordering, _) = build_cross_system_reports(&v3, &v1, "test");
        assert_eq!(ordering.status, AuditStatusV1::Fail);
        assert!(ordering.issues.iter().any(|i| i.kind == "ORDER_SEQ_NON_MONOTONIC_V3"));
    }

    // ── cross_system: empty inputs ──────────────────────────────

    #[test]
    fn cross_system_reports_both_empty_passes() {
        let (ordering, idempotency) = build_cross_system_reports(&[], &[], "test");
        assert_eq!(ordering.status, AuditStatusV1::Pass);
        assert_eq!(idempotency.status, AuditStatusV1::Pass);
        assert!(ordering.cross_system.as_ref().unwrap().digest_match);
        assert_eq!(ordering.total_events, 0);
    }

    // ── cross_system: eventId missing in v3 ─────────────────────

    #[test]
    fn cross_system_reports_event_missing_in_v3() {
        let v3 = vec![h(1, "e1")];
        let v1 = vec![
            ComparatorEventRowV1 {
                seq: 1,
                event_id: "e1".to_string(),
                event_type: "evt.test".to_string(),
                occurred_at: "2026-02-11T00:00:00Z".to_string(),
                header_hash: format!("{:064x}", 1 + 11),
                payload_hash: format!("{:064x}", 1 + 29),
            },
            ComparatorEventRowV1 {
                seq: 2,
                event_id: "e_only_in_v1".to_string(),
                event_type: "evt.test".to_string(),
                occurred_at: "2026-02-11T00:00:00Z".to_string(),
                header_hash: "aa".repeat(32),
                payload_hash: "bb".repeat(32),
            },
        ];
        let (_, idempotency) = build_cross_system_reports(&v3, &v1, "test");
        assert_eq!(idempotency.status, AuditStatusV1::Fail);
        assert!(idempotency
            .issues
            .iter()
            .any(|i| i.kind == "IDEMPOTENCY_EVENT_ID_MISSING_V3"));
    }

    // ── cross_system: eventId extra in v3 ────────────────────────

    #[test]
    fn cross_system_reports_event_extra_in_v3() {
        let v3 = vec![h(1, "e1"), h(2, "e_only_in_v3")];
        let v1 = vec![ComparatorEventRowV1 {
            seq: 1,
            event_id: "e1".to_string(),
            event_type: "evt.test".to_string(),
            occurred_at: "2026-02-11T00:00:00Z".to_string(),
            header_hash: format!("{:064x}", 1 + 11),
            payload_hash: format!("{:064x}", 1 + 29),
        }];
        let (_, idempotency) = build_cross_system_reports(&v3, &v1, "test");
        assert_eq!(idempotency.status, AuditStatusV1::Fail);
        assert!(idempotency
            .issues
            .iter()
            .any(|i| i.kind == "IDEMPOTENCY_EVENT_ID_EXTRA_V3"));
    }

    // ── control_evidence_source_refs: same seq and shard ─────────

    #[test]
    fn control_evidence_source_refs_same_seq_same_shard_emits_one() {
        let line1 = evidence::ControlEvidenceJsonLineV1 {
            shard_id: 1,
            seq: 10,
            event_id: "e1".to_string(),
            event_type: "t".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:00Z".to_string(),
            header_hash: "aa".repeat(32),
            payload_hash: "bb".repeat(32),
            payload: serde_json::json!({}),
        };
        let line2 = evidence::ControlEvidenceJsonLineV1 {
            shard_id: 1,
            seq: 10,
            event_id: "e2".to_string(),
            event_type: "t".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:00Z".to_string(),
            header_hash: "cc".repeat(32),
            payload_hash: "dd".repeat(32),
            payload: serde_json::json!({}),
        };
        let refs = control_evidence_source_refs(&[line1, line2]);
        // Same seq AND same shard => only 1 ref (the first)
        assert_eq!(refs.len(), 1);
    }

    // ── observe_corecrux_identity offline ────────────────────────

    #[test]
    fn observe_corecrux_identity_offline_returns_fallback() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://unreachable:99999".to_string(),
            data_dir: None,
            tenant_id: None,
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: None,
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };
        let (build, compat) = observe_corecrux_identity(&opts);
        assert!(!build.version.is_empty());
        assert_eq!(compat.requires, DEFAULT_COMPAT_REQUIRES);
    }

    // ── AuditStatusV1 ordering (Ord/PartialOrd) ─────────────────

    #[test]
    fn audit_status_v1_ordering() {
        assert!(AuditStatusV1::Pass < AuditStatusV1::Warn);
        assert!(AuditStatusV1::Warn < AuditStatusV1::Fail);
        assert!(AuditStatusV1::Fail < AuditStatusV1::Skipped);
        assert!(AuditStatusV1::Pass < AuditStatusV1::Skipped);
    }

    // ── stream_digest_v3 vs stream_digest_v1 matching ────────────

    #[test]
    fn stream_digest_v3_and_v1_match_for_identical_data() {
        let v3 = vec![h(1, "e1"), h(2, "e2")];
        let v1: Vec<ComparatorEventRowV1> = v3
            .iter()
            .map(|row| ComparatorEventRowV1 {
                seq: row.seq,
                event_id: row.event_id.clone(),
                event_type: row.event_type.clone(),
                occurred_at: row.occurred_at.clone(),
                header_hash: row.header_hash.clone(),
                payload_hash: row.payload_hash.clone(),
            })
            .collect();
        let d3 = stream_digest_v3(&v3);
        let d1 = stream_digest_v1(&v1);
        assert_eq!(d3, d1);
    }

    // ── AuditIssueV1 serialization ──────────────────────────────

    #[test]
    fn audit_issue_v1_omits_none_fields() {
        let issue = AuditIssueV1 {
            kind: "test_kind".to_string(),
            message: "test message".to_string(),
            seq: None,
            event_id: None,
        };
        let json = serde_json::to_string(&issue).unwrap();
        assert!(!json.contains("seq"));
        assert!(!json.contains("event_id"));
    }

    #[test]
    fn audit_issue_v1_includes_some_fields() {
        let issue = AuditIssueV1 {
            kind: "test".to_string(),
            message: "msg".to_string(),
            seq: Some(42),
            event_id: Some("e1".to_string()),
        };
        let json = serde_json::to_string(&issue).unwrap();
        assert!(json.contains("\"seq\":42"));
        assert!(json.contains("\"event_id\":\"e1\""));
    }

    // ── StreamHeaderLineV1 serde round-trip ──────────────────────

    #[test]
    fn stream_header_line_v1_round_trip() {
        let header = h(42, "evt-42");
        let json = serde_json::to_string(&header).unwrap();
        let deser: StreamHeaderLineV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.seq, 42);
        assert_eq!(deser.event_id, "evt-42");
        assert_eq!(deser.event_type, "evt.test");
    }

    // ── CrossSystemParityMetaV1 clone ────────────────────────────

    #[test]
    fn cross_system_parity_meta_v1_clone() {
        let meta = CrossSystemParityMetaV1 {
            source: "test".to_string(),
            v1_total_events: 10,
            v3_total_events: 10,
            v1_digest_blake3: "a".repeat(64),
            v3_digest_blake3: "a".repeat(64),
            digest_match: true,
        };
        let cloned = meta.clone();
        assert_eq!(cloned.source, "test");
        assert!(cloned.digest_match);
    }

    // ── write_pretty_json creates human-readable JSON ────────────

    #[test]
    fn write_pretty_json_is_indented() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("pretty.json");
        let data = serde_json::json!({"a": 1, "b": 2});
        write_pretty_json(&path, &data).expect("write");
        let raw = std::fs::read_to_string(&path).unwrap();
        // Pretty JSON contains newlines and indentation
        assert!(raw.contains('\n'));
        assert!(raw.contains("  "));
    }

    // ── build_subject_scope with receipt_id ──────────────────────

    #[test]
    fn build_subject_scope_includes_receipt_id() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: Some("t1".to_string()),
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: Some("r1".to_string()),
            answer_id: None,
            action_id: None,
            receipt_keyring: None,
        };
        let scope = build_subject_scope(&opts);
        assert_eq!(scope.tenant_id.as_deref(), Some("t1"));
        assert_eq!(scope.receipt_id.as_deref(), Some("r1"));
        assert!(scope.shard_ids.is_empty());
    }

    // ── hex32 with mixed bytes ───────────────────────────────────

    #[test]
    fn hex32_mixed_bytes() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xde;
        bytes[1] = 0xad;
        bytes[31] = 0xef;
        let result = hex32(&bytes);
        assert_eq!(result.len(), 64);
        assert!(result.starts_with("dead"));
        assert!(result.ends_with("ef"));
    }

    // ── stream_headers_jsonl empty input ─────────────────────────

    #[test]
    fn stream_headers_jsonl_empty() {
        let bytes = stream_headers_jsonl(&[]).expect("serialize");
        assert!(bytes.is_empty());
    }

    // ── receipt_selector answer variant ──────────────────────────

    #[test]
    fn receipt_selector_answer_only() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: None,
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: None,
            answer_id: Some("a42".to_string()),
            action_id: None,
            receipt_keyring: None,
        };
        let result = receipt_selector(&opts).unwrap().unwrap();
        assert_eq!(result.kind(), "answer");
        assert_eq!(result.path_component(), ("answers", "a42"));
    }

    // ── receipt_selector all three set ────────────────────────────

    #[test]
    fn receipt_selector_all_three_rejects() {
        let opts = AuditPackOptionsV1 {
            out_dir: None,
            offline: true,
            corecrux_base: "http://localhost".to_string(),
            data_dir: None,
            tenant_id: None,
            stream_type: None,
            stream_id: None,
            from_seq: 0,
            max_events: 100,
            v1_events_log: None,
            v1_stream_jsonl: None,
            parity_tenant_id: None,
            parity_seed: "0".to_string(),
            parity_sample: 10,
            engine_base: None,
            engine_api_key: None,
            replay_fixture: "minimal".to_string(),
            device_index: 0,
            receipt_id: Some("r1".to_string()),
            answer_id: Some("a1".to_string()),
            action_id: Some("ac1".to_string()),
            receipt_keyring: None,
        };
        assert!(receipt_selector(&opts).is_err());
    }

    // ── load_v1_jsonl_comparator blank lines skipped ─────────────

    #[test]
    fn load_v1_jsonl_comparator_skips_blank_lines() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("blanks.jsonl");
        let content = r#"
{"seq":1,"eventId":"e1","eventType":"t","occurredAt":"2026-01-01T00:00:00Z","headerHash":"aa","payloadHash":"bb"}

{"seq":2,"eventId":"e2","eventType":"t","occurredAt":"2026-01-01T00:00:00Z","headerHash":"cc","payloadHash":"dd"}

"#;
        std::fs::write(&path, content).expect("write");
        let rows = load_v1_jsonl_comparator(&path).expect("parse");
        assert_eq!(rows.len(), 2);
    }

    // ── load_v1_jsonl_comparator invalid JSON ────────────────────

    #[test]
    fn load_v1_jsonl_comparator_invalid_json_errors() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("bad.jsonl");
        std::fs::write(&path, "not json\n").expect("write");
        assert!(load_v1_jsonl_comparator(&path).is_err());
    }

    // ── AuditStatusV1: serialization ─────────────────────────────────

    #[test]
    fn audit_status_v1_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&AuditStatusV1::Pass).unwrap(), "\"pass\"");
        assert_eq!(serde_json::to_string(&AuditStatusV1::Warn).unwrap(), "\"warn\"");
        assert_eq!(serde_json::to_string(&AuditStatusV1::Fail).unwrap(), "\"fail\"");
        assert_eq!(serde_json::to_string(&AuditStatusV1::Skipped).unwrap(), "\"skipped\"");
    }

    // ── AuditStatusV1::worst: symmetric ──────────────────────────────

    #[test]
    fn audit_status_worst_is_symmetric() {
        let variants = [
            AuditStatusV1::Pass,
            AuditStatusV1::Warn,
            AuditStatusV1::Fail,
            AuditStatusV1::Skipped,
        ];
        for a in &variants {
            for b in &variants {
                assert_eq!(AuditStatusV1::worst(*a, *b), AuditStatusV1::worst(*b, *a));
            }
        }
    }

    // ── AuditStatusV1: clone, copy, eq ───────────────────────────────

    #[test]
    fn audit_status_v1_copy_eq() {
        let a = AuditStatusV1::Fail;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(a, AuditStatusV1::Pass);
    }

    // ── OrderingParityReportV1 serialization ─────────────────────────

    #[test]
    fn ordering_parity_report_omits_none_fields() {
        let report = OrderingParityReportV1 {
            schema: "test".to_string(),
            comparison: "v3_local_only".to_string(),
            status: AuditStatusV1::Pass,
            total_events: 10,
            digest_blake3: None,
            cross_system: None,
            issues: Vec::new(),
            note: None,
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("digest_blake3"));
        assert!(!json.contains("cross_system"));
        assert!(!json.contains("note"));
    }

    #[test]
    fn ordering_parity_report_includes_some_fields() {
        let report = OrderingParityReportV1 {
            schema: "test".to_string(),
            comparison: "v3_local_only".to_string(),
            status: AuditStatusV1::Pass,
            total_events: 10,
            digest_blake3: Some("abc".to_string()),
            cross_system: None,
            issues: Vec::new(),
            note: Some("n".to_string()),
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("digest_blake3"));
        assert!(json.contains("note"));
    }

    // ── IdempotencyParityReportV1 serialization ──────────────────────

    #[test]
    fn idempotency_parity_report_serializes() {
        let report = IdempotencyParityReportV1 {
            schema: "test".to_string(),
            comparison: "v3_local_only".to_string(),
            status: AuditStatusV1::Pass,
            total_events: 5,
            unique_event_ids: 5,
            duplicate_count: 0,
            cross_system: None,
            issues: Vec::new(),
            note: None,
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["total_events"], 5);
        assert_eq!(json["duplicate_count"], 0);
    }

    // ── IntegrityCheckV1 serialization ───────────────────────────────

    #[test]
    fn integrity_check_v1_omits_none_detail() {
        let check = IntegrityCheckV1 {
            name: "health".to_string(),
            ok: true,
            detail: None,
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(!json.contains("detail"));
    }

    #[test]
    fn integrity_check_v1_includes_some_detail() {
        let check = IntegrityCheckV1 {
            name: "health".to_string(),
            ok: false,
            detail: Some("failed".to_string()),
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("\"detail\":\"failed\""));
    }

    // ── PackBuildInfoV1 serialization ────────────────────────────────

    #[test]
    fn pack_build_info_v1_serializes() {
        let info = PackBuildInfoV1 {
            schema: "corecrux.audit_pack.build.v1".to_string(),
            corecrux_build: BuildInfo {
                version: "0.1.0".to_string(),
                commit: "abc".to_string(),
            },
            compat: CompatContract {
                requires: DEFAULT_COMPAT_REQUIRES.to_string(),
            },
            producer: pack_producer(),
            corecrux_base: "http://localhost".to_string(),
            offline: true,
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["schema"], "corecrux.audit_pack.build.v1");
        assert_eq!(json["offline"], true);
    }

    // ── FileArtifactMeta debug ───────────────────────────────────────

    #[test]
    fn file_artifact_meta_debug() {
        let meta = FileArtifactMeta {
            relative_path: "test.json".to_string(),
            blake3: "abc".to_string(),
            size_bytes: 42,
        };
        let dbg = format!("{:?}", meta);
        assert!(dbg.contains("test.json"));
        assert!(dbg.contains("42"));
    }

    // ── ComparatorEventRowV1: clone ──────────────────────────────────

    #[test]
    fn comparator_event_row_v1_clone() {
        let row = ComparatorEventRowV1 {
            seq: 1,
            event_id: "e1".to_string(),
            event_type: "t".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            header_hash: "aa".to_string(),
            payload_hash: "bb".to_string(),
        };
        let cloned = row.clone();
        assert_eq!(cloned.seq, 1);
        assert_eq!(cloned.event_id, "e1");
    }

    // ── analyze_stream_headers: duplicate event_id ───────────────────

    #[test]
    fn analyze_stream_headers_duplicate_event_id() {
        let rows = vec![h(1, "e1"), h(2, "e1")]; // same event_id
        let (_, idempotency) = analyze_stream_headers_local(&rows);
        assert_eq!(idempotency.duplicate_count, 1);
        assert_eq!(idempotency.unique_event_ids, 1);
    }

    // ── analyze_stream_headers: non-monotonic seq ────────────────────

    #[test]
    fn analyze_stream_headers_non_monotonic_seq() {
        let rows = vec![h(5, "e5"), h(3, "e3")]; // seq goes backwards
        let (ordering, _) = analyze_stream_headers_local(&rows);
        assert_eq!(ordering.status, AuditStatusV1::Fail);
        assert!(!ordering.issues.is_empty());
    }

    // ── stream_digest_v1 deterministic ───────────────────────────────

    #[test]
    fn stream_digest_v1_deterministic() {
        let rows = vec![ComparatorEventRowV1 {
            seq: 1,
            event_id: "e1".to_string(),
            event_type: "t".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            header_hash: "aa".to_string(),
            payload_hash: "bb".to_string(),
        }];
        let d1 = stream_digest_v1(&rows);
        let d2 = stream_digest_v1(&rows);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
    }

    // ── file_name_string: no parent ──────────────────────────────────

    #[test]
    fn file_name_string_bare_name() {
        assert_eq!(file_name_string(std::path::Path::new("test.bin")), "test.bin");
    }

    // ── default_missing_capabilities: returns non-empty ──────────────

    #[test]
    fn default_missing_capabilities_non_empty() {
        let caps = default_missing_capabilities();
        assert!(!caps.is_empty());
        assert!(caps.contains(&"decision_plane_events".to_string()));
    }

    // ── pack_producer: returns expected name ──────────────────────────

    #[test]
    fn pack_producer_returns_corecruxctl() {
        let producer = pack_producer();
        assert_eq!(producer.name, "corecruxctl");
        assert!(!producer.version.is_empty());
    }
}
