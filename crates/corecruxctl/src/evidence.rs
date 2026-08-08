// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Evidence verifier — verifies receipts against a keyring, loads projection meta, prints a verification report.

use corecrux_frame::{compute_header_hash, decode_canonical_header_bytes_v1};
use corecrux_projections::{load_projections_meta_v1, CcxsnapSnapshot};
use corecrux_receipts::{
    verify_receipt_v1, Ed25519KeyRingV1, ReplayExportManifestV1, VerificationReportV1, VerifyReceiptInput,
};
use corecrux_segment::decode_frame_v1;
use corecrux_storage::{ShardStorage, ShardStorageOptions};
use corecrux_types::{
    build_info, AuditPackIndexV2, ControlCheckpointMaterializedV1, ControlStateDigestV1, ControlStateMutationV1,
    EvidenceManifestV1, EvidenceSourceRefV1, EvidenceStatusV1, EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1,
    EVT_CONTROL_STATE_MUTATION_V1,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use crate::fixture_digest;

type DynError = Box<dyn std::error::Error + Send + Sync>;

const CONTROL_STREAM_TENANT: &str = "system";
const CONTROL_STREAM_TYPE: &str = "corecrux";
const CONTROL_STREAM_ID: &str = "control";

#[derive(Debug, Clone)]
pub struct ControlVerifyOptions {
    pub data_dir: PathBuf,
    pub hosted_only: bool,
    pub device_index: i32,
    pub batch_frames: u32,
}

#[derive(Debug, Clone)]
pub struct PackVerifyOptions {
    pub pack_dir: PathBuf,
    pub strict: bool,
    pub device_index: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlVerifyReportV1 {
    pub schema: String,
    pub ok: bool,
    pub hosted: bool,
    #[serde(rename = "dataDir")]
    pub data_dir: String,
    #[serde(rename = "checkpointPath")]
    pub checkpoint_path: String,
    #[serde(rename = "checkpointBlake3")]
    pub checkpoint_blake3: String,
    #[serde(rename = "checkpointSizeBytes")]
    pub checkpoint_size_bytes: u64,
    #[serde(rename = "currentControlHash")]
    pub current_control_hash: String,
    #[serde(rename = "expectedCheckpointBlake3")]
    pub expected_checkpoint_blake3: String,
    #[serde(rename = "expectedCheckpointSizeBytes")]
    pub expected_checkpoint_size_bytes: u64,
    #[serde(rename = "expectedControlHash")]
    pub expected_control_hash: String,
    #[serde(rename = "anchor", skip_serializing_if = "Option::is_none")]
    pub anchor: Option<String>,
    #[serde(rename = "anchorSeq", skip_serializing_if = "Option::is_none")]
    pub anchor_seq: Option<u64>,
    #[serde(rename = "appliedMutations")]
    pub applied_mutations: u64,
    #[serde(rename = "checkpointEvents")]
    pub checkpoint_events: u64,
    #[serde(rename = "mutationEvents")]
    pub mutation_events: u64,
    #[serde(rename = "evidenceEvents")]
    pub evidence_events: u64,
    #[serde(rename = "shardIds")]
    pub shard_ids: Vec<u32>,
    #[serde(rename = "stateMatchesEvidence")]
    pub state_matches_evidence: bool,
    #[serde(rename = "checkpointBytesMatchExpected")]
    pub checkpoint_bytes_match_expected: bool,
    #[serde(rename = "errorCode", skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(rename = "errorMessage", skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// Checks that were requested but could not be evaluated.
    ///
    /// With no control evidence there is nothing to replay, yet
    /// `state_matches_evidence` and `checkpoint_bytes_match_expected` both
    /// reported `true` and `ok` was simply `!hosted_only` — verifying nothing
    /// scored the same as verifying a matching stream. `ok` keeps its meaning
    /// (an unhosted deployment is not an error); a caller that needs the
    /// replay to have actually run gates on `checks_skipped.is_empty()`.
    #[serde(rename = "checksSkipped", default)]
    pub checks_skipped: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlEvidenceJsonLineV1 {
    #[serde(rename = "shardId")]
    pub shard_id: u32,
    pub seq: u64,
    #[serde(rename = "eventId")]
    pub event_id: String,
    #[serde(rename = "eventType")]
    pub event_type: String,
    #[serde(rename = "occurredAt")]
    pub occurred_at: String,
    #[serde(rename = "ingestedAt")]
    pub ingested_at: String,
    #[serde(rename = "headerHash")]
    pub header_hash: String,
    #[serde(rename = "payloadHash")]
    pub payload_hash: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceVerifyArtifactCheckV1 {
    pub key: String,
    pub status: EvidenceStatusV1,
    pub ok: bool,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceVerifyCheckV1 {
    pub name: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceVerifyReportV1 {
    pub schema: String,
    pub ok: bool,
    pub strict: bool,
    #[serde(rename = "packDir")]
    pub pack_dir: String,
    #[serde(rename = "checkedArtifacts")]
    pub checked_artifacts: u64,
    #[serde(rename = "failedArtifacts")]
    pub failed_artifacts: u64,
    #[serde(rename = "missingCapabilities", default)]
    pub missing_capabilities: Vec<String>,
    #[serde(rename = "artifactChecks")]
    pub artifact_checks: Vec<EvidenceVerifyArtifactCheckV1>,
    pub checks: Vec<EvidenceVerifyCheckV1>,
    /// Checks that were REQUESTED but could not be evaluated.
    ///
    /// `ok` keeps its meaning, so an operator deliberately verifying a partial
    /// pack is not broken. A caller that needs every requested check to have
    /// actually *run* gates on `ok && checks_skipped.is_empty()`. Same shape as
    /// `X509VerifyReport::checks_skipped` (see `incident:2026-07-28`).
    ///
    /// Deliberately narrow: an artifact class that is wholly absent means the
    /// caller never asked for it and is NOT listed. A field that is non-empty
    /// on every ordinary run is useless as a gate.
    #[serde(rename = "checksSkipped", default)]
    pub checks_skipped: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ControlEvidenceBundleV1 {
    pub report: ControlVerifyReportV1,
    pub checkpoint_bytes: Vec<u8>,
    pub evidence_lines: Vec<ControlEvidenceJsonLineV1>,
}

#[derive(Debug, Clone)]
struct ControlCheckpointRecord {
    seq: u64,
    payload: ControlCheckpointMaterializedV1,
}

#[derive(Debug, Clone)]
struct ControlMutationRecord {
    seq: u64,
    payload: ControlStateMutationV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ControlEvidenceReplayPlan {
    state: LocalControlV1,
    anchor: &'static str,
    anchor_seq: u64,
    applied_mutations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
struct LocalValveV1 {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
struct LocalValvesV1 {
    #[serde(rename = "pauseIngest")]
    pub pause_ingest: LocalValveV1,
    #[serde(rename = "pauseCompaction")]
    pub pause_compaction: LocalValveV1,
    pub throttle: LocalValveV1,
    #[serde(rename = "readOnly")]
    pub read_only: LocalValveV1,
    #[serde(rename = "emergencyBrake")]
    pub emergency_brake: LocalValveV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct LocalControlV1 {
    pub v: u32,
    #[serde(rename = "updatedAtUnixNs")]
    pub updated_at_unix_ns: u64,
    pub valves: LocalValvesV1,
}

impl Default for LocalControlV1 {
    fn default() -> Self {
        Self {
            v: 1,
            updated_at_unix_ns: 0,
            valves: LocalValvesV1::default(),
        }
    }
}

pub fn control_verify(opts: &ControlVerifyOptions) -> Result<ControlVerifyReportV1, DynError> {
    Ok(collect_control_evidence_bundle_v1(opts)?.report)
}

pub fn collect_control_evidence_bundle_v1(opts: &ControlVerifyOptions) -> Result<ControlEvidenceBundleV1, DynError> {
    let control_path = opts.data_dir.join("CONTROL.json");
    let (checkpoint_bytes, _) = load_control_checkpoint(&control_path)?;
    let lines = collect_control_evidence_lines_v1(&opts.data_dir, opts.device_index, opts.batch_frames.max(1))?;
    verify_control_inputs_v1(&opts.data_dir, &control_path, checkpoint_bytes, lines, opts.hosted_only)
}

pub fn verify_evidence_pack(opts: &PackVerifyOptions) -> Result<EvidenceVerifyReportV1, DynError> {
    let manifest_path = opts.pack_dir.join("evidence_manifest.json");
    let manifest_bytes = std::fs::read(&manifest_path)?;
    let manifest: EvidenceManifestV1 = serde_json::from_slice(&manifest_bytes)?;

    let mut artifact_checks = Vec::new();
    let mut checks = Vec::new();
    let mut checks_skipped: Vec<String> = Vec::new();
    let mut failed_artifacts = 0u64;

    let index_path = opts.pack_dir.join("audit_pack_index_v2.json");
    if index_path.exists() {
        let index: AuditPackIndexV2 = serde_json::from_slice(&std::fs::read(&index_path)?)?;
        let manifest_hash = blake3::hash(&manifest_bytes).to_hex().to_string();
        let manifest_size = manifest_bytes.len() as u64;
        let ok = index.manifest_blake3 == manifest_hash && index.manifest_size_bytes == manifest_size;
        checks.push(EvidenceVerifyCheckV1 {
            name: "audit_pack_index_v2".to_string(),
            ok,
            detail: Some(format!(
                "manifest_hash_match={} manifest_size_match={}",
                index.manifest_blake3 == manifest_hash,
                index.manifest_size_bytes == manifest_size
            )),
        });
    }

    for (key, artifact) in &manifest.artifacts {
        let path = opts.pack_dir.join(&artifact.path);
        let result = if !path.exists() {
            EvidenceVerifyArtifactCheckV1 {
                key: key.clone(),
                status: artifact.status,
                ok: !artifact.required && !opts.strict,
                path: artifact.path.clone(),
                detail: Some("artifact missing".to_string()),
            }
        } else {
            let bytes = std::fs::read(&path)?;
            let hash = blake3::hash(&bytes).to_hex().to_string();
            let size = bytes.len() as u64;
            let ok = hash == artifact.blake3 && size == artifact.size_bytes;
            EvidenceVerifyArtifactCheckV1 {
                key: key.clone(),
                status: artifact.status,
                ok,
                path: artifact.path.clone(),
                detail: Some(format!(
                    "hash_match={} size_match={}",
                    hash == artifact.blake3,
                    size == artifact.size_bytes
                )),
            }
        };
        if !result.ok {
            failed_artifacts = failed_artifacts.saturating_add(1);
        }
        artifact_checks.push(result);
    }

    for (checks_part, skipped_part) in [
        verify_control_artifacts(&opts.pack_dir, &manifest, opts.strict)?,
        verify_receipt_artifacts(&opts.pack_dir, &manifest)?,
        verify_replay_artifacts(&opts.pack_dir, &manifest, opts.device_index)?,
        verify_projection_artifacts(&opts.pack_dir, &manifest)?,
    ] {
        checks.extend(checks_part);
        checks_skipped.extend(skipped_part);
    }

    // D-10: a manifest declaring no artifacts verified nothing. It used to
    // report `ok: true` even under `--strict` — identical to a pack whose every
    // artifact was checked and matched.
    if manifest.artifacts.is_empty() {
        checks_skipped.push("artifacts:manifest_declares_none".to_string());
    }

    let verified_nothing = manifest.artifacts.is_empty();
    let ok = failed_artifacts == 0
        && checks.iter().all(|check| check.ok)
        // Under `--strict` the caller has asked for every requested check to
        // have run, so an unevaluable check is a failure rather than a note.
        && !(opts.strict && (verified_nothing || !checks_skipped.is_empty()));
    Ok(EvidenceVerifyReportV1 {
        schema: "corecrux.evidence.verify.v1".to_string(),
        ok,
        strict: opts.strict,
        pack_dir: opts.pack_dir.display().to_string(),
        checked_artifacts: artifact_checks.len() as u64,
        failed_artifacts,
        missing_capabilities: manifest.missing_capabilities.clone(),
        artifact_checks,
        checks,
        checks_skipped,
    })
}

/// Checks produced, plus the names of checks that were requested but could not
/// be evaluated. See `EvidenceVerifyReportV1::checks_skipped`.
type CheckOutcome = (Vec<EvidenceVerifyCheckV1>, Vec<String>);

fn verify_control_artifacts(
    pack_dir: &Path,
    manifest: &EvidenceManifestV1,
    strict: bool,
) -> Result<CheckOutcome, DynError> {
    let checkpoint = artifact_path_by_kind(manifest, "control_checkpoint_json");
    let evidence = artifact_path_by_kind(manifest, "control_evidence_jsonl");
    let report_path = artifact_path_by_kind(manifest, "control_verify_report");

    let mut checks = Vec::new();
    let (Some(checkpoint_path), Some(evidence_path), Some(report_path)) = (checkpoint, evidence, report_path) else {
        // D-12: an absent OR PARTIAL control trio emitted no checks at all, so
        // a pack carrying two of the three verified identically to one carrying
        // all three. A wholly absent trio means the caller never asked; a
        // partial one is a check that could not run.
        let present = [
            ("control_checkpoint_json", checkpoint.is_some()),
            ("control_evidence_jsonl", evidence.is_some()),
            ("control_verify_report", report_path.is_some()),
        ];
        let skipped = if present.iter().any(|(_, is_present)| *is_present) {
            let missing = present
                .iter()
                .filter(|(_, is_present)| !*is_present)
                .map(|(name, _)| *name)
                .collect::<Vec<_>>()
                .join(",");
            vec![format!("control_verify_report:missing_artifacts[{missing}]")]
        } else {
            Vec::new()
        };
        return Ok((checks, skipped));
    };

    let checkpoint_bytes = std::fs::read(pack_dir.join(checkpoint_path))?;
    let evidence_bytes = std::fs::read(pack_dir.join(evidence_path))?;
    let bundled_report: ControlVerifyReportV1 = serde_json::from_slice(&std::fs::read(pack_dir.join(report_path))?)?;
    let lines = parse_control_evidence_jsonl(&evidence_bytes)?;
    let rebuilt = verify_control_inputs_v1(
        Path::new(&bundled_report.data_dir),
        Path::new(&bundled_report.checkpoint_path),
        checkpoint_bytes,
        lines,
        strict,
    )?;
    let ok = rebuilt.report.ok == bundled_report.ok
        && rebuilt.report.expected_control_hash == bundled_report.expected_control_hash
        && rebuilt.report.expected_checkpoint_blake3 == bundled_report.expected_checkpoint_blake3;
    checks.push(EvidenceVerifyCheckV1 {
        name: "control_verify_report".to_string(),
        ok,
        detail: Some(format!(
            "rebuilt_ok={} bundled_ok={} expected_control_hash_match={} expected_checkpoint_hash_match={}",
            rebuilt.report.ok,
            bundled_report.ok,
            rebuilt.report.expected_control_hash == bundled_report.expected_control_hash,
            rebuilt.report.expected_checkpoint_blake3 == bundled_report.expected_checkpoint_blake3
        )),
    });
    Ok((checks, Vec::new()))
}

fn verify_receipt_artifacts(pack_dir: &Path, manifest: &EvidenceManifestV1) -> Result<CheckOutcome, DynError> {
    let bundle = artifact_path_by_kind(manifest, "receipt_export_bundle");
    let keyring = artifact_path_by_kind(manifest, "receipt_keyring_json");
    let verification = artifact_path_by_kind(manifest, "receipt_verification_report");
    let mut checks = Vec::new();

    let Some(bundle_path) = bundle else {
        // No receipt bundle at all: nothing was requested.
        return Ok((checks, Vec::new()));
    };
    let Some(keyring_path) = keyring else {
        // D-11: a bundle WITHOUT a keyring emitted `ok: true` with only a
        // free-text `skipped_signature_verification` detail, so the aggregate
        // `ok` was identical to a pack whose signature actually verified.
        checks.push(EvidenceVerifyCheckV1 {
            name: "receipt_signature_verification".to_string(),
            ok: true,
            detail: Some("skipped_signature_verification".to_string()),
        });
        return Ok((checks, vec!["receipt_signature_verification:no_keyring".to_string()]));
    };

    let bundle_bytes = std::fs::read(pack_dir.join(bundle_path))?;
    let mut zip = zip::ZipArchive::new(Cursor::new(bundle_bytes))?;
    let manifest_json = read_zip_entry(&mut zip, "manifest.json")?;
    let export_manifest: ReplayExportManifestV1 = serde_json::from_slice(&manifest_json)?;
    let body = read_zip_entry(&mut zip, "receipt/body.cbor")?;
    let sig = read_zip_entry(&mut zip, "receipt/sig.cbor")?;
    let bundled_report = match verification {
        Some(path) => {
            let bytes = std::fs::read(pack_dir.join(path))?;
            Some(serde_json::from_slice::<VerificationReportV1>(&bytes)?)
        }
        None => None,
    };

    let keyring_text = std::fs::read_to_string(pack_dir.join(keyring_path))?;
    let keyring = Ed25519KeyRingV1::parse_json(&keyring_text)?;
    let rerun = verify_receipt_v1(VerifyReceiptInput {
        tenant_id: &export_manifest.tenant_id,
        receipt_id: &export_manifest.receipt_id,
        body_bytes: &body,
        stored_body_payload_hash: parse_hex32(&export_manifest.receipt_refs.receipt_body_payload_hash)?,
        sig_bytes: Some(&sig),
        keyring: Some(&keyring),
        verified_at: bundled_report
            .as_ref()
            .map_or("1970-01-01T00:00:00Z", |r| r.verified_at.as_str()),
        verifier_build: &build_info(),
        recompute_candidate_digest: true,
    })?;
    let ok = rerun.signature_valid
        && rerun.error_code == "OK"
        && bundled_report.as_ref().is_none_or(|report| {
            report.error_code == rerun.error_code && report.signature_valid == rerun.signature_valid
        });
    checks.push(EvidenceVerifyCheckV1 {
        name: "receipt_signature_verification".to_string(),
        ok,
        detail: Some(format!(
            "receipt_id={} error_code={} signature_valid={}",
            export_manifest.receipt_id, rerun.error_code, rerun.signature_valid
        )),
    });
    Ok((checks, Vec::new()))
}

fn verify_replay_artifacts(
    pack_dir: &Path,
    manifest: &EvidenceManifestV1,
    device_index: i32,
) -> Result<CheckOutcome, DynError> {
    let replay_input = artifact_path_by_kind(manifest, "replay_input_segment");
    let replay_report = artifact_path_by_kind(manifest, "replay_determinism_report");
    let mut checks = Vec::new();
    let (Some(input_path), Some(report_path)) = (replay_input, replay_report) else {
        // D-13: ONE HALF of the replay pair emitted no determinism check, so a
        // pack with an input segment and no report verified identically to one
        // with neither. Neither half present means nothing was requested.
        let skipped = match (replay_input.is_some(), replay_report.is_some()) {
            (true, false) => vec!["replay_determinism:missing_replay_determinism_report".to_string()],
            (false, true) => vec!["replay_determinism:missing_replay_input_segment".to_string()],
            _ => Vec::new(),
        };
        return Ok((checks, skipped));
    };

    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(pack_dir.join(report_path))?)?;
    let run_a_digest = report
        .get("run_a")
        .and_then(|v| v.get("digest_blake3"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let run_b_digest = report
        .get("run_b")
        .and_then(|v| v.get("digest_blake3"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let replay = fixture_digest::segment_replay_digest_from_segment_path(&pack_dir.join(input_path), device_index)?;
    let ok = replay.digest_blake3 == run_a_digest && replay.digest_blake3 == run_b_digest;
    checks.push(EvidenceVerifyCheckV1 {
        name: "replay_determinism".to_string(),
        ok,
        detail: Some(format!(
            "computed_digest={} expected_run_a={} expected_run_b={}",
            replay.digest_blake3, run_a_digest, run_b_digest
        )),
    });
    Ok((checks, Vec::new()))
}

fn verify_projection_artifacts(pack_dir: &Path, manifest: &EvidenceManifestV1) -> Result<CheckOutcome, DynError> {
    let mut checks = Vec::new();
    let mut skipped = Vec::new();
    for artifact in manifest.artifacts.values() {
        if artifact.kind != "projection_meta_json" {
            continue;
        }
        let meta_path = pack_dir.join(&artifact.path);
        // D-14: `load_projections_meta_v1` returns an EMPTY meta for a missing
        // file, so a declared-but-absent meta produced an all-`None` expectation
        // set — every snapshot then compared against "missing", and a meta with
        // no sibling snapshots emitted no check at all. Declared and absent is a
        // check that could not run.
        if !meta_path.exists() {
            skipped.push(format!("projection_meta:missing[{}]", artifact.path));
            continue;
        }
        let meta = load_projections_meta_v1(&meta_path)?;
        let meta_dir = meta_path
            .parent()
            .ok_or_else(|| format!("projection meta has no parent: {}", meta_path.display()))?;
        for snapshot_artifact in manifest.artifacts.values().filter(|candidate| {
            is_projection_snapshot_kind(&candidate.kind) && pack_dir.join(&candidate.path).parent() == Some(meta_dir)
        }) {
            let snapshot_path = pack_dir.join(&snapshot_artifact.path);
            let projection = projection_name_from_snapshot_artifact(snapshot_artifact)
                .ok_or_else(|| format!("projection snapshot missing source ref: {}", snapshot_artifact.path))?;
            let expected = expected_projection_hash(&meta, &projection);
            let actual = CcxsnapSnapshot::snapshot_blake3_hex(&std::fs::read(&snapshot_path)?);
            checks.push(EvidenceVerifyCheckV1 {
                name: format!("snapshot_hash:{projection}:{}", snapshot_artifact.path),
                ok: expected.as_deref() == Some(actual.as_str()),
                detail: Some(format!(
                    "expected={} actual={}",
                    expected.unwrap_or_else(|| "missing".to_string()),
                    actual
                )),
            });
        }
    }
    Ok((checks, skipped))
}

/// Artifact `kind` emitted for a projection snapshot. The `_ccxs` spelling is the
/// pre-rename name: the projections snapshot vacated the `.ccxs` extension so that
/// `ccx<lane>` stays the CoreCrux segment-companion namespace (ExecPlan
/// `crux-companion-vocabulary-unification-2026-08-08` M1). Verification accepts
/// both spellings so an audit pack issued before the rename still reads; only the
/// new spelling is ever written.
pub(crate) const PROJECTION_SNAPSHOT_KIND: &str = "projection_snapshot_ccxsnap";
const PROJECTION_SNAPSHOT_KIND_LEGACY: &str = "projection_snapshot_ccxs";

fn is_projection_snapshot_kind(kind: &str) -> bool {
    kind == PROJECTION_SNAPSHOT_KIND || kind == PROJECTION_SNAPSHOT_KIND_LEGACY
}

fn projection_name_from_snapshot_artifact(artifact: &corecrux_types::EvidenceArtifactDescriptorV1) -> Option<String> {
    artifact.source_refs.iter().find_map(|source| match source {
        EvidenceSourceRefV1::ProjectionSnapshot { projection, .. } => Some(projection.clone()),
        _ => None,
    })
}

fn expected_projection_hash(meta: &corecrux_projections::ProjectionsMetaV1, projection: &str) -> Option<String> {
    match projection {
        "artifact_living_state" => meta.artifact_living_state.snapshot_blake3.clone(),
        "artifact_relations" => meta.artifact_relations.snapshot_blake3.clone(),
        "pressure_events" => meta.pressure_events.snapshot_blake3.clone(),
        "artifact_dependents" => meta.artifact_dependents.snapshot_blake3.clone(),
        _ => None,
    }
}

fn artifact_path_by_kind<'a>(manifest: &'a EvidenceManifestV1, kind: &str) -> Option<&'a str> {
    manifest
        .artifacts
        .values()
        .find(|artifact| artifact.kind == kind)
        .map(|artifact| artifact.path.as_str())
}

fn read_zip_entry<R: Read + std::io::Seek>(zip: &mut zip::ZipArchive<R>, path: &str) -> Result<Vec<u8>, DynError> {
    let mut file = zip.by_name(path)?;
    let mut out = Vec::new();
    file.read_to_end(&mut out)?;
    Ok(out)
}

pub fn parse_control_evidence_jsonl(bytes: &[u8]) -> Result<Vec<ControlEvidenceJsonLineV1>, DynError> {
    let mut out = Vec::new();
    for line in bytes.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        out.push(serde_json::from_slice::<ControlEvidenceJsonLineV1>(line)?);
    }
    Ok(out)
}

pub fn control_evidence_jsonl(lines: &[ControlEvidenceJsonLineV1]) -> Result<Vec<u8>, DynError> {
    let mut out = Vec::new();
    for line in lines {
        let mut bytes = serde_json::to_vec(line)?;
        bytes.push(b'\n');
        out.extend_from_slice(&bytes);
    }
    Ok(out)
}

fn collect_control_evidence_lines_v1(
    data_dir: &Path,
    _device_index: i32,
    batch_frames: u32,
) -> Result<Vec<ControlEvidenceJsonLineV1>, DynError> {
    let shard_root = data_dir.join("shards");
    if !shard_root.exists() {
        return Ok(Vec::new());
    }

    let shard_ids = list_shards(&shard_root)?;
    if shard_ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut lines = Vec::new();
    for shard_id in shard_ids {
        let epoch = parse_manifest_epoch(&shard_root.join(format!("shard-{shard_id:04}")).join("MANIFEST"))?;
        let storage = ShardStorage::open(&shard_root, shard_id, epoch, ShardStorageOptions::default())?;

        let mut cursor = None;
        loop {
            let (frames, next) = storage.replay_from(cursor, batch_frames)?;
            if frames.is_empty() {
                break;
            }
            for (_loc, frame_bytes) in frames {
                let frame = decode_frame_v1(&frame_bytes)?;
                if frame.header_bytes.len() < 32 {
                    continue;
                }
                let canonical_len = frame.header_bytes.len() - 32;
                let canonical_bytes = &frame.header_bytes[..canonical_len];
                let header = decode_canonical_header_bytes_v1(canonical_bytes)?;
                if header.tenant_id != CONTROL_STREAM_TENANT
                    || header.stream_type != CONTROL_STREAM_TYPE
                    || header.stream_id != CONTROL_STREAM_ID
                {
                    continue;
                }
                if header.event_type != EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1
                    && header.event_type != EVT_CONTROL_STATE_MUTATION_V1
                {
                    continue;
                }
                lines.push(ControlEvidenceJsonLineV1 {
                    shard_id,
                    seq: header.seq,
                    event_id: header.event_id,
                    event_type: header.event_type,
                    occurred_at: header.occurred_at,
                    ingested_at: header.ingested_at,
                    header_hash: hex32(&compute_header_hash(canonical_bytes)),
                    payload_hash: hex32(&header.payload_hash),
                    payload: serde_json::from_slice(&frame.payload_bytes)?,
                });
            }
            cursor = next;
            if cursor.is_none() {
                break;
            }
        }
    }
    lines.sort_by_key(|line| (line.shard_id, line.seq));
    Ok(lines)
}

fn load_control_checkpoint(path: &Path) -> Result<(Vec<u8>, LocalControlV1), DynError> {
    if path.exists() {
        let bytes = std::fs::read(path)?;
        let state = serde_json::from_slice::<LocalControlV1>(&bytes)?;
        Ok((bytes, state))
    } else {
        let state = LocalControlV1::default();
        Ok((checkpoint_control_bytes_v1(&state), state))
    }
}

fn verify_control_inputs_v1(
    data_dir: &Path,
    control_path: &Path,
    checkpoint_bytes: Vec<u8>,
    lines: Vec<ControlEvidenceJsonLineV1>,
    hosted_only: bool,
) -> Result<ControlEvidenceBundleV1, DynError> {
    let (_, current_state) = load_control_checkpoint(control_path)?;
    let current_checkpoint_blake3 = blake3::hash(&checkpoint_bytes).to_hex().to_string();
    let current_checkpoint_size_bytes = checkpoint_bytes.len() as u64;
    let current_control_hash = control_state_digest_v1(&current_state).control_hash_blake3;
    let mut shard_ids = lines
        .iter()
        .map(|line| line.shard_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    if lines.is_empty() {
        let ok = !hosted_only;
        return Ok(ControlEvidenceBundleV1 {
            report: ControlVerifyReportV1 {
                schema: "corecrux.control.verify.v1".to_string(),
                ok,
                hosted: false,
                data_dir: data_dir.display().to_string(),
                checkpoint_path: control_path.display().to_string(),
                checkpoint_blake3: current_checkpoint_blake3.clone(),
                checkpoint_size_bytes: current_checkpoint_size_bytes,
                current_control_hash: current_control_hash.clone(),
                expected_checkpoint_blake3: current_checkpoint_blake3,
                expected_checkpoint_size_bytes: current_checkpoint_size_bytes,
                expected_control_hash: current_control_hash,
                anchor: None,
                anchor_seq: None,
                applied_mutations: 0,
                checkpoint_events: 0,
                mutation_events: 0,
                evidence_events: 0,
                shard_ids: Vec::new(),
                state_matches_evidence: true,
                checkpoint_bytes_match_expected: true,
                error_code: if hosted_only {
                    Some("NOT_HOSTED".to_string())
                } else {
                    None
                },
                error_message: if hosted_only {
                    Some("control evidence stream not hosted locally".to_string())
                } else {
                    None
                },
                // D-17: there were no events, so the replay never ran. Both
                // `*_match*` booleans above are `true` having compared nothing.
                checks_skipped: vec!["control_evidence_replay:no_events".to_string()],
            },
            checkpoint_bytes,
            evidence_lines: lines,
        });
    }

    if shard_ids.len() > 1 {
        return Ok(ControlEvidenceBundleV1 {
            report: ControlVerifyReportV1 {
                schema: "corecrux.control.verify.v1".to_string(),
                ok: false,
                hosted: true,
                data_dir: data_dir.display().to_string(),
                checkpoint_path: control_path.display().to_string(),
                checkpoint_blake3: current_checkpoint_blake3.clone(),
                checkpoint_size_bytes: current_checkpoint_size_bytes,
                current_control_hash: current_control_hash.clone(),
                expected_checkpoint_blake3: current_checkpoint_blake3,
                expected_checkpoint_size_bytes: current_checkpoint_size_bytes,
                expected_control_hash: current_control_hash,
                anchor: None,
                anchor_seq: None,
                applied_mutations: 0,
                checkpoint_events: 0,
                mutation_events: 0,
                evidence_events: lines.len() as u64,
                shard_ids: std::mem::take(&mut shard_ids),
                state_matches_evidence: false,
                checkpoint_bytes_match_expected: false,
                error_code: Some("MULTIPLE_HOSTED_SHARDS".to_string()),
                error_message: Some("control evidence stream should not appear on multiple local shards".to_string()),
                // Refused, not unchecked: `ok: false` is the whole verdict.
                checks_skipped: Vec::new(),
            },
            checkpoint_bytes,
            evidence_lines: lines,
        });
    }

    let mut checkpoints = Vec::new();
    let mut mutations = Vec::new();
    for line in &lines {
        match line.event_type.as_str() {
            EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1 => {
                checkpoints.push(ControlCheckpointRecord {
                    seq: line.seq,
                    payload: serde_json::from_value(line.payload.clone())?,
                });
            }
            EVT_CONTROL_STATE_MUTATION_V1 => {
                mutations.push(ControlMutationRecord {
                    seq: line.seq,
                    payload: serde_json::from_value(line.payload.clone())?,
                });
            }
            _ => {}
        }
    }

    let (ok, anchor, anchor_seq, applied_mutations, expected_state, error_code, error_message) =
        match reconcile_control_from_evidence(&current_state, &checkpoint_bytes, &checkpoints, &mutations) {
            Ok(Some(plan)) => (
                true,
                Some(plan.anchor.to_string()),
                Some(plan.anchor_seq),
                plan.applied_mutations as u64,
                plan.state,
                None,
                None,
            ),
            Ok(None) => (true, None, None, 0, current_state.clone(), None, None),
            Err(err) => (
                false,
                None,
                None,
                0,
                current_state.clone(),
                Some("RECONCILE_FAILED".to_string()),
                Some(err),
            ),
        };

    let expected_checkpoint_bytes = checkpoint_control_bytes_v1(&expected_state);
    let expected_checkpoint_blake3 = blake3::hash(&expected_checkpoint_bytes).to_hex().to_string();
    let expected_checkpoint_size_bytes = expected_checkpoint_bytes.len() as u64;
    let expected_control_hash = control_state_digest_v1(&expected_state).control_hash_blake3;
    let state_matches_evidence = current_state == expected_state;
    let checkpoint_bytes_match_expected = checkpoint_bytes == expected_checkpoint_bytes;
    let final_ok = ok && state_matches_evidence && checkpoint_bytes_match_expected;

    let (error_code, error_message) = if !ok {
        (error_code, error_message)
    } else if !state_matches_evidence {
        (
            Some("CONTROL_STATE_DRIFT".to_string()),
            Some("CONTROL.json state does not match replayed control evidence".to_string()),
        )
    } else if !checkpoint_bytes_match_expected {
        (
            Some("CONTROL_CHECKPOINT_BYTES_DRIFT".to_string()),
            Some("CONTROL.json bytes are not the canonical checkpoint bytes for the replayed state".to_string()),
        )
    } else {
        (None, None)
    };

    Ok(ControlEvidenceBundleV1 {
        report: ControlVerifyReportV1 {
            schema: "corecrux.control.verify.v1".to_string(),
            ok: final_ok,
            hosted: true,
            data_dir: data_dir.display().to_string(),
            checkpoint_path: control_path.display().to_string(),
            checkpoint_blake3: current_checkpoint_blake3,
            checkpoint_size_bytes: current_checkpoint_size_bytes,
            current_control_hash,
            expected_checkpoint_blake3,
            expected_checkpoint_size_bytes,
            expected_control_hash,
            anchor,
            anchor_seq,
            applied_mutations,
            checkpoint_events: checkpoints.len() as u64,
            mutation_events: mutations.len() as u64,
            evidence_events: lines.len() as u64,
            shard_ids,
            state_matches_evidence,
            checkpoint_bytes_match_expected,
            error_code,
            error_message,
            // The replay ran over real events; nothing was left unevaluated.
            checks_skipped: Vec::new(),
        },
        checkpoint_bytes,
        evidence_lines: lines,
    })
}

fn reconcile_control_from_evidence(
    current: &LocalControlV1,
    current_checkpoint_bytes: &[u8],
    checkpoints: &[ControlCheckpointRecord],
    mutations: &[ControlMutationRecord],
) -> Result<Option<ControlEvidenceReplayPlan>, String> {
    if checkpoints.is_empty() && mutations.is_empty() {
        return Ok(None);
    }

    let current_digest = control_state_digest_v1(current);
    let current_checkpoint_hash = blake3::hash(current_checkpoint_bytes).to_hex().to_string();
    let current_checkpoint_size = current_checkpoint_bytes.len() as u64;

    let checkpoint_anchor = checkpoints
        .iter()
        .rev()
        .find(|record| {
            record.payload.control_state == current_digest
                && record.payload.checkpoint_blake3 == current_checkpoint_hash
                && record.payload.checkpoint_size_bytes == current_checkpoint_size
        })
        .map(|record| (record.seq, "checkpoint"));
    let mutation_anchor = mutations
        .iter()
        .rev()
        .find(|record| record.payload.control_after == current_digest)
        .map(|record| (record.seq, "mutation"));

    let (mut rebuilt, anchor, anchor_seq) = match (checkpoint_anchor, mutation_anchor) {
        (Some(left), Some(right)) => {
            if left.0 >= right.0 {
                (current.clone(), left.1, left.0)
            } else {
                (current.clone(), right.1, right.0)
            }
        }
        (Some(found), None) | (None, Some(found)) => (current.clone(), found.1, found.0),
        (None, None) => {
            let Some(first_mutation) = mutations.first() else {
                return Err("control evidence contains no state mutation anchor for CONTROL.json".into());
            };
            let default_state = LocalControlV1::default();
            if first_mutation.payload.control_before != control_state_digest_v1(&default_state) {
                return Err(
                    "CONTROL.json does not match any checkpoint or mutation anchor, and evidence does not start from the default control state".into(),
                );
            }
            (default_state, "default", 0)
        }
    };

    let mut applied_mutations = 0usize;
    for record in mutations.iter().filter(|record| record.seq > anchor_seq) {
        apply_control_state_mutation_v1(&mut rebuilt, &record.payload)?;
        applied_mutations = applied_mutations.saturating_add(1);
    }

    Ok(Some(ControlEvidenceReplayPlan {
        state: rebuilt,
        anchor,
        anchor_seq,
        applied_mutations,
    }))
}

fn checkpoint_control_bytes_v1(state: &LocalControlV1) -> Vec<u8> {
    serde_json::to_vec_pretty(state).unwrap_or_else(|_| b"{}".to_vec())
}

fn control_state_digest_v1(state: &LocalControlV1) -> ControlStateDigestV1 {
    ControlStateDigestV1 {
        control_version: state.v,
        updated_at_unix_ns: state.updated_at_unix_ns,
        control_hash_blake3: blake3::hash(&serde_json::to_vec(state).unwrap_or_default())
            .to_hex()
            .to_string(),
    }
}

fn apply_control_state_mutation_v1(
    state: &mut LocalControlV1,
    mutation: &ControlStateMutationV1,
) -> Result<(), String> {
    let before = control_state_digest_v1(state);
    if before != mutation.control_before {
        return Err(format!(
            "control mutation before digest mismatch: have {} expected {}",
            before.control_hash_blake3, mutation.control_before.control_hash_blake3
        ));
    }

    for change in &mutation.valve_changes {
        let target = match change.valve.as_str() {
            "pause_ingest" => &mut state.valves.pause_ingest,
            "pause_compaction" => &mut state.valves.pause_compaction,
            "throttle" => &mut state.valves.throttle,
            "read_only" => &mut state.valves.read_only,
            "emergency_brake" => &mut state.valves.emergency_brake,
            other => return Err(format!("unknown control valve '{other}'")),
        };
        apply_valve_state(target, &change.after);
    }
    state.updated_at_unix_ns = mutation.control_after.updated_at_unix_ns;
    state.v = mutation.control_after.control_version;

    let after = control_state_digest_v1(state);
    if after != mutation.control_after {
        return Err(format!(
            "control mutation after digest mismatch: have {} expected {}",
            after.control_hash_blake3, mutation.control_after.control_hash_blake3
        ));
    }
    Ok(())
}

fn apply_valve_state(target: &mut LocalValveV1, value: &corecrux_types::ControlValveStateV1) {
    target.enabled = value.enabled;
    target.actor.clone_from(&value.actor);
    target.reason.clone_from(&value.reason);
    target.updated_at_unix_ns = value.updated_at_unix_ns;
    target.retry_after_ms = value.retry_after_ms;
    target.events_per_sec = value.events_per_sec;
    target.bytes_per_sec = value.bytes_per_sec;
    target.max_in_flight = value.max_in_flight;
}

fn parse_hex32(input: &str) -> Result<[u8; 32], DynError> {
    if input.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", input.len()).into());
    }
    let mut out = [0u8; 32];
    for (i, chunk) in input.as_bytes().chunks(2).enumerate() {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, DynError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex byte '{}'", b as char).into()),
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 64];
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    String::from_utf8_lossy(&out).to_string()
}

fn parse_manifest_epoch(path: &Path) -> Result<u64, DynError> {
    let bytes = std::fs::read(path)?;
    if bytes.len() < 24 {
        return Err(format!("manifest header too short: {}", path.display()).into());
    }
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&bytes[16..24]);
    Ok(u64::from_le_bytes(epoch))
}

fn list_shards(shard_root: &Path) -> Result<Vec<u32>, DynError> {
    let mut out = Vec::<u32>::new();
    for ent in std::fs::read_dir(shard_root)? {
        let ent = ent?;
        if !ent.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = ent.file_name().to_str().map(|s| s.to_string()) else {
            continue;
        };
        let Some(rest) = name.strip_prefix("shard-") else {
            continue;
        };
        let Ok(id) = rest.parse::<u32>() else {
            continue;
        };
        out.push(id);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{SecondsFormat, Utc};
    use tempfile::tempdir;

    use super::*;

    fn default_checkpoint_bytes() -> Vec<u8> {
        checkpoint_control_bytes_v1(&LocalControlV1::default())
    }

    fn line_for_mutation(seq: u64, before: &LocalControlV1, after: &LocalControlV1) -> ControlEvidenceJsonLineV1 {
        let mutation = ControlStateMutationV1 {
            schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
            action_id: format!("act-{seq}"),
            mutation_type: "set_valves".to_string(),
            applied_at_unix_ms: seq,
            actor: "operator".to_string(),
            reason: "maintenance".to_string(),
            auth: corecrux_types::EvidenceAuthContextV1 {
                mode: "dev_scopes".to_string(),
                subject: None,
                tenant_binding: None,
                scopes: vec!["admin:write".to_string()],
            },
            request: corecrux_types::EvidenceRequestContextV1::default(),
            node: corecrux_types::EvidenceNodeContextV1 {
                node_id: "node-a".to_string(),
                build: build_info(),
                http_listen_addr: None,
                grpc_listen_addr: None,
            },
            control_before: control_state_digest_v1(before),
            control_after: control_state_digest_v1(after),
            valve_changes: vec![corecrux_types::ValveChangeV1 {
                valve: "read_only".to_string(),
                before: corecrux_types::ControlValveStateV1::default(),
                after: corecrux_types::ControlValveStateV1 {
                    enabled: true,
                    actor: "operator".to_string(),
                    reason: "maintenance".to_string(),
                    updated_at_unix_ns: after.updated_at_unix_ns,
                    retry_after_ms: None,
                    events_per_sec: None,
                    bytes_per_sec: None,
                    max_in_flight: None,
                },
            }],
            knowledge_authority_change: None,
            result: None,
        };
        ControlEvidenceJsonLineV1 {
            shard_id: 1,
            seq,
            event_id: format!("evt-{seq}"),
            event_type: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
            occurred_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            ingested_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            header_hash: "00".repeat(32),
            payload_hash: "11".repeat(32),
            payload: serde_json::to_value(mutation).expect("mutation json"),
        }
    }

    #[test]
    fn local_control_v1_default_is_v1_zeroed() {
        let state = LocalControlV1::default();
        assert_eq!(state.v, 1);
        assert_eq!(state.updated_at_unix_ns, 0);
        assert!(!state.valves.pause_ingest.enabled);
        assert!(!state.valves.pause_compaction.enabled);
        assert!(!state.valves.throttle.enabled);
        assert!(!state.valves.read_only.enabled);
        assert!(!state.valves.emergency_brake.enabled);
    }

    #[test]
    fn control_state_digest_changes_with_state() {
        let default_state = LocalControlV1::default();
        let digest_a = control_state_digest_v1(&default_state);

        let mut modified = default_state.clone();
        modified.updated_at_unix_ns = 42;
        modified.valves.read_only.enabled = true;
        let digest_b = control_state_digest_v1(&modified);

        assert_ne!(digest_a.control_hash_blake3, digest_b.control_hash_blake3);
        assert_eq!(digest_a.control_version, 1);
        assert_eq!(digest_a.updated_at_unix_ns, 0);
        assert_eq!(digest_b.updated_at_unix_ns, 42);
    }

    #[test]
    fn checkpoint_control_bytes_round_trips() {
        let state = LocalControlV1::default();
        let bytes = checkpoint_control_bytes_v1(&state);
        let parsed: LocalControlV1 = serde_json::from_slice(&bytes).expect("deserialize");
        assert_eq!(parsed, state);
    }

    #[test]
    fn parse_control_evidence_jsonl_handles_empty() {
        let lines = parse_control_evidence_jsonl(b"").unwrap();
        assert!(lines.is_empty());
    }

    #[test]
    fn parse_control_evidence_jsonl_round_trips() {
        let line = ControlEvidenceJsonLineV1 {
            shard_id: 1,
            seq: 42,
            event_id: "evt-1".to_string(),
            event_type: "corecrux.control.state_mutation.v1".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:01Z".to_string(),
            header_hash: "aa".repeat(32),
            payload_hash: "bb".repeat(32),
            payload: serde_json::json!({"test": true}),
        };
        let bytes = control_evidence_jsonl(&[line.clone()]).unwrap();
        let parsed = parse_control_evidence_jsonl(&bytes).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].event_id, "evt-1");
        assert_eq!(parsed[0].shard_id, 1);
        assert_eq!(parsed[0].seq, 42);
    }

    #[test]
    fn parse_hex32_valid_input() {
        let hex = "aa".repeat(32);
        let bytes = parse_hex32(&hex).unwrap();
        assert_eq!(bytes, [0xaa; 32]);
    }

    #[test]
    fn parse_hex32_rejects_wrong_length() {
        let result = parse_hex32("aabb");
        assert!(result.is_err());
    }

    #[test]
    fn hex32_produces_lowercase_64_chars() {
        let bytes = [
            0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let hex = hex32(&bytes);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(&hex[..8], "deadbeef");
    }

    #[test]
    fn artifact_path_by_kind_finds_existing_and_returns_none_for_missing() {
        let manifest = EvidenceManifestV1 {
            schema: corecrux_types::EVIDENCE_MANIFEST_SCHEMA_V1.to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            producer: corecrux_types::EvidenceProducerV1 {
                name: "test".to_string(),
                version: "0".to_string(),
                commit: "0".to_string(),
            },
            corecrux_build: build_info(),
            compat: None,
            subject_scope: corecrux_types::EvidenceSubjectScopeV1::default(),
            status: EvidenceStatusV1::Pass,
            artifacts: BTreeMap::from([(
                "control_checkpoint".to_string(),
                corecrux_types::EvidenceArtifactDescriptorV1 {
                    kind: "control_checkpoint_json".to_string(),
                    media_type: "application/json".to_string(),
                    path: "checkpoint.json".to_string(),
                    blake3: "deadbeef".to_string(),
                    size_bytes: 100,
                    status: EvidenceStatusV1::Pass,
                    required: true,
                    observational: false,
                    produced_by: corecrux_types::EvidenceProducerV1 {
                        name: "test".to_string(),
                        version: "0".to_string(),
                        commit: "0".to_string(),
                    },
                    source_refs: Vec::new(),
                },
            )]),
            relationships: Vec::new(),
            missing_capabilities: Vec::new(),
        };
        assert_eq!(
            artifact_path_by_kind(&manifest, "control_checkpoint_json"),
            Some("checkpoint.json")
        );
        assert_eq!(artifact_path_by_kind(&manifest, "nonexistent_kind"), None);
    }

    #[test]
    fn apply_control_state_mutation_succeeds_with_valid_digests() {
        let mut state = LocalControlV1::default();
        let before_digest = control_state_digest_v1(&state);

        let mut after_state = state.clone();
        after_state.updated_at_unix_ns = 100;
        after_state.valves.read_only.enabled = true;
        after_state.valves.read_only.actor = "operator".to_string();
        after_state.valves.read_only.reason = "maintenance".to_string();
        after_state.valves.read_only.updated_at_unix_ns = 100;
        let after_digest = control_state_digest_v1(&after_state);

        let mutation = ControlStateMutationV1 {
            schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
            action_id: "act-1".to_string(),
            mutation_type: "set_valves".to_string(),
            applied_at_unix_ms: 1,
            actor: "operator".to_string(),
            reason: "maintenance".to_string(),
            auth: corecrux_types::EvidenceAuthContextV1 {
                mode: "dev_scopes".to_string(),
                subject: None,
                tenant_binding: None,
                scopes: vec!["admin:write".to_string()],
            },
            request: corecrux_types::EvidenceRequestContextV1::default(),
            node: corecrux_types::EvidenceNodeContextV1 {
                node_id: "n".to_string(),
                build: build_info(),
                http_listen_addr: None,
                grpc_listen_addr: None,
            },
            control_before: before_digest,
            control_after: after_digest,
            valve_changes: vec![corecrux_types::ValveChangeV1 {
                valve: "read_only".to_string(),
                before: corecrux_types::ControlValveStateV1::default(),
                after: corecrux_types::ControlValveStateV1 {
                    enabled: true,
                    actor: "operator".to_string(),
                    reason: "maintenance".to_string(),
                    updated_at_unix_ns: 100,
                    retry_after_ms: None,
                    events_per_sec: None,
                    bytes_per_sec: None,
                    max_in_flight: None,
                },
            }],
            knowledge_authority_change: None,
            result: None,
        };

        apply_control_state_mutation_v1(&mut state, &mutation).unwrap();
        assert!(state.valves.read_only.enabled);
        assert_eq!(state.updated_at_unix_ns, 100);
    }

    #[test]
    fn apply_control_state_mutation_fails_with_wrong_before() {
        let mut state = LocalControlV1::default();
        let wrong_digest = corecrux_types::ControlStateDigestV1 {
            control_version: 1,
            updated_at_unix_ns: 9999,
            control_hash_blake3: "wrong".to_string(),
        };
        let mutation = ControlStateMutationV1 {
            schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
            action_id: "act-1".to_string(),
            mutation_type: "set_valves".to_string(),
            applied_at_unix_ms: 1,
            actor: "test".to_string(),
            reason: "test".to_string(),
            auth: corecrux_types::EvidenceAuthContextV1 {
                mode: "dev_scopes".to_string(),
                subject: None,
                tenant_binding: None,
                scopes: Vec::new(),
            },
            request: corecrux_types::EvidenceRequestContextV1::default(),
            node: corecrux_types::EvidenceNodeContextV1 {
                node_id: "n".to_string(),
                build: build_info(),
                http_listen_addr: None,
                grpc_listen_addr: None,
            },
            control_before: wrong_digest,
            control_after: control_state_digest_v1(&state),
            valve_changes: Vec::new(),
            knowledge_authority_change: None,
            result: None,
        };
        let result = apply_control_state_mutation_v1(&mut state, &mutation);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("before digest mismatch"));
    }

    #[test]
    fn apply_valve_state_sets_all_fields() {
        let mut valve = LocalValveV1::default();
        let new_state = corecrux_types::ControlValveStateV1 {
            enabled: true,
            actor: "admin".to_string(),
            reason: "testing".to_string(),
            updated_at_unix_ns: 12345,
            retry_after_ms: Some(5000),
            events_per_sec: Some(100),
            bytes_per_sec: Some(1_000_000),
            max_in_flight: Some(50),
        };
        apply_valve_state(&mut valve, &new_state);
        assert!(valve.enabled);
        assert_eq!(valve.actor, "admin");
        assert_eq!(valve.reason, "testing");
        assert_eq!(valve.updated_at_unix_ns, 12345);
        assert_eq!(valve.retry_after_ms, Some(5000));
        assert_eq!(valve.events_per_sec, Some(100));
        assert_eq!(valve.bytes_per_sec, Some(1_000_000));
        assert_eq!(valve.max_in_flight, Some(50));
    }

    #[test]
    fn reconcile_control_returns_none_for_empty_evidence() {
        let state = LocalControlV1::default();
        let bytes = checkpoint_control_bytes_v1(&state);
        let result = reconcile_control_from_evidence(&state, &bytes, &[], &[]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn verify_control_inputs_no_evidence_not_hosted() {
        let dir = tempdir().expect("tempdir");
        let control_path = dir.path().join("CONTROL.json");
        let bytes = default_checkpoint_bytes();
        std::fs::write(&control_path, &bytes).expect("write");

        let bundle = verify_control_inputs_v1(dir.path(), &control_path, bytes, Vec::new(), false).expect("verify");
        assert!(bundle.report.ok);
        assert!(!bundle.report.hosted);
        assert!(bundle.report.error_code.is_none());
    }

    #[test]
    fn verify_control_inputs_hosted_only_with_no_evidence_fails() {
        let dir = tempdir().expect("tempdir");
        let control_path = dir.path().join("CONTROL.json");
        let bytes = default_checkpoint_bytes();
        std::fs::write(&control_path, &bytes).expect("write");

        let bundle = verify_control_inputs_v1(dir.path(), &control_path, bytes, Vec::new(), true).expect("verify");
        assert!(!bundle.report.ok);
        assert_eq!(bundle.report.error_code.as_deref(), Some("NOT_HOSTED"));
    }

    #[test]
    fn control_verify_report_serializes_to_json() {
        let report = ControlVerifyReportV1 {
            schema: "corecrux.control.verify.v1".to_string(),
            ok: true,
            hosted: true,
            data_dir: "/tmp".to_string(),
            checkpoint_path: "/tmp/CONTROL.json".to_string(),
            checkpoint_blake3: "a".repeat(64),
            checkpoint_size_bytes: 100,
            current_control_hash: "b".repeat(64),
            expected_checkpoint_blake3: "a".repeat(64),
            expected_checkpoint_size_bytes: 100,
            expected_control_hash: "b".repeat(64),
            anchor: Some("checkpoint".to_string()),
            anchor_seq: Some(5),
            applied_mutations: 0,
            checkpoint_events: 1,
            mutation_events: 0,
            evidence_events: 1,
            shard_ids: vec![1],
            state_matches_evidence: true,
            checkpoint_bytes_match_expected: true,
            error_code: None,
            error_message: None,
            checks_skipped: Vec::new(),
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"ok\":true"));
        assert!(json.contains("\"hosted\":true"));
        assert!(!json.contains("errorCode"));
    }

    #[test]
    fn evidence_verify_report_v1_serializes() {
        let report = EvidenceVerifyReportV1 {
            schema: "corecrux.evidence.verify.v1".to_string(),
            ok: true,
            strict: false,
            pack_dir: "/tmp/pack".to_string(),
            checked_artifacts: 5,
            failed_artifacts: 0,
            missing_capabilities: vec!["decision_plane_events".to_string()],
            artifact_checks: Vec::new(),
            checks: vec![EvidenceVerifyCheckV1 {
                name: "test".to_string(),
                ok: true,
                detail: None,
            }],
            checks_skipped: Vec::new(),
        };
        let json = serde_json::to_value(&report).expect("serialize");
        assert_eq!(json["checkedArtifacts"], 5);
        assert_eq!(json["failedArtifacts"], 0);
    }

    #[test]
    fn verify_control_inputs_detects_checkpoint_drift() {
        let dir = tempdir().expect("tempdir");
        let control_path = dir.path().join("CONTROL.json");

        let before = LocalControlV1::default();
        let mut after = LocalControlV1::default();
        after.updated_at_unix_ns = 42;
        after.valves.read_only.enabled = true;
        after.valves.read_only.actor = "operator".to_string();
        after.valves.read_only.reason = "maintenance".to_string();
        after.valves.read_only.updated_at_unix_ns = 42;

        let checkpoint_bytes = default_checkpoint_bytes();
        std::fs::write(&control_path, &checkpoint_bytes).expect("write checkpoint");

        let bundle = verify_control_inputs_v1(
            dir.path(),
            &control_path,
            checkpoint_bytes,
            vec![line_for_mutation(1, &before, &after)],
            true,
        )
        .expect("verify control inputs");

        assert!(!bundle.report.ok);
        assert_eq!(bundle.report.error_code.as_deref(), Some("CONTROL_STATE_DRIFT"));
        assert!(!bundle.report.state_matches_evidence);
    }

    #[test]
    fn hex_nibble_valid_chars() {
        assert_eq!(super::hex_nibble(b'0').unwrap(), 0);
        assert_eq!(super::hex_nibble(b'9').unwrap(), 9);
        assert_eq!(super::hex_nibble(b'a').unwrap(), 10);
        assert_eq!(super::hex_nibble(b'f').unwrap(), 15);
        assert_eq!(super::hex_nibble(b'A').unwrap(), 10);
        assert_eq!(super::hex_nibble(b'F').unwrap(), 15);
    }

    #[test]
    fn hex_nibble_invalid_char() {
        assert!(super::hex_nibble(b'g').is_err());
        assert!(super::hex_nibble(b'z').is_err());
        assert!(super::hex_nibble(b' ').is_err());
    }

    #[test]
    fn parse_hex32_round_trips() {
        let original = [
            0xdeu8, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44,
            0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10, 0x20, 0x30, 0x40,
        ];
        let hex = hex32(&original);
        let parsed = parse_hex32(&hex).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn parse_hex32_uppercase() {
        let hex = "AA".repeat(32);
        let bytes = parse_hex32(&hex).unwrap();
        assert_eq!(bytes, [0xaa; 32]);
    }

    #[test]
    fn parse_manifest_epoch_from_tempdir() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("MANIFEST");
        let mut data = vec![0u8; 32];
        let epoch: u64 = 99;
        data[16..24].copy_from_slice(&epoch.to_le_bytes());
        std::fs::write(&path, &data).expect("write");
        assert_eq!(parse_manifest_epoch(&path).unwrap(), 99);
    }

    #[test]
    fn parse_manifest_epoch_too_short() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("MANIFEST");
        std::fs::write(&path, [0u8; 10]).expect("write");
        assert!(parse_manifest_epoch(&path).is_err());
    }

    #[test]
    fn list_shards_from_empty_dir() {
        let dir = tempdir().expect("tempdir");
        let shards = list_shards(dir.path()).unwrap();
        assert!(shards.is_empty());
    }

    #[test]
    fn list_shards_finds_shard_dirs() {
        let dir = tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("shard-0001")).unwrap();
        std::fs::create_dir(dir.path().join("shard-0010")).unwrap();
        std::fs::create_dir(dir.path().join("other")).unwrap();
        let shards = list_shards(dir.path()).unwrap();
        assert_eq!(shards, vec![1, 10]);
    }

    #[test]
    fn parse_control_evidence_jsonl_multiple_lines() {
        let line1 = ControlEvidenceJsonLineV1 {
            shard_id: 1,
            seq: 1,
            event_id: "e1".to_string(),
            event_type: "t1".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:00Z".to_string(),
            header_hash: "aa".repeat(32),
            payload_hash: "bb".repeat(32),
            payload: serde_json::json!({"a": 1}),
        };
        let line2 = ControlEvidenceJsonLineV1 {
            shard_id: 1,
            seq: 2,
            event_id: "e2".to_string(),
            event_type: "t2".to_string(),
            occurred_at: "2026-01-02T00:00:00Z".to_string(),
            ingested_at: "2026-01-02T00:00:00Z".to_string(),
            header_hash: "cc".repeat(32),
            payload_hash: "dd".repeat(32),
            payload: serde_json::json!({"b": 2}),
        };
        let bytes = control_evidence_jsonl(&[line1, line2]).unwrap();
        let parsed = parse_control_evidence_jsonl(&bytes).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].event_id, "e1");
        assert_eq!(parsed[1].event_id, "e2");
    }

    #[test]
    fn verify_control_inputs_multi_shard_fails() {
        let dir = tempdir().expect("tempdir");
        let control_path = dir.path().join("CONTROL.json");
        let bytes = default_checkpoint_bytes();
        std::fs::write(&control_path, &bytes).expect("write");

        let line1 = ControlEvidenceJsonLineV1 {
            shard_id: 1,
            seq: 1,
            event_id: "e1".to_string(),
            event_type: EVT_CONTROL_CHECKPOINT_MATERIALIZED_V1.to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:00Z".to_string(),
            header_hash: "aa".repeat(32),
            payload_hash: "bb".repeat(32),
            payload: serde_json::json!({}),
        };
        let mut line2 = line1.clone();
        line2.shard_id = 2; // different shard

        let bundle =
            verify_control_inputs_v1(dir.path(), &control_path, bytes, vec![line1, line2], false).expect("verify");
        assert!(!bundle.report.ok);
        assert_eq!(bundle.report.error_code.as_deref(), Some("MULTIPLE_HOSTED_SHARDS"));
    }

    #[test]
    fn reconcile_control_applies_mutation_from_default() {
        let before = LocalControlV1::default();
        let mut after = before.clone();
        after.updated_at_unix_ns = 100;
        after.valves.read_only.enabled = true;
        after.valves.read_only.actor = "operator".to_string();
        after.valves.read_only.reason = "maintenance".to_string();
        after.valves.read_only.updated_at_unix_ns = 100;

        let mutation = ControlMutationRecord {
            seq: 1,
            payload: ControlStateMutationV1 {
                schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
                action_id: "act-1".to_string(),
                mutation_type: "set_valves".to_string(),
                applied_at_unix_ms: 1,
                actor: "operator".to_string(),
                reason: "maintenance".to_string(),
                auth: corecrux_types::EvidenceAuthContextV1 {
                    mode: "dev_scopes".to_string(),
                    subject: None,
                    tenant_binding: None,
                    scopes: vec!["admin:write".to_string()],
                },
                request: corecrux_types::EvidenceRequestContextV1::default(),
                node: corecrux_types::EvidenceNodeContextV1 {
                    node_id: "n".to_string(),
                    build: build_info(),
                    http_listen_addr: None,
                    grpc_listen_addr: None,
                },
                control_before: control_state_digest_v1(&before),
                control_after: control_state_digest_v1(&after),
                valve_changes: vec![corecrux_types::ValveChangeV1 {
                    valve: "read_only".to_string(),
                    before: corecrux_types::ControlValveStateV1::default(),
                    after: corecrux_types::ControlValveStateV1 {
                        enabled: true,
                        actor: "operator".to_string(),
                        reason: "maintenance".to_string(),
                        updated_at_unix_ns: 100,
                        retry_after_ms: None,
                        events_per_sec: None,
                        bytes_per_sec: None,
                        max_in_flight: None,
                    },
                }],
                knowledge_authority_change: None,
                result: None,
            },
        };

        let checkpoint = checkpoint_control_bytes_v1(&before);
        let plan = reconcile_control_from_evidence(&before, &checkpoint, &[], &[mutation])
            .unwrap()
            .expect("should have a plan");

        assert_eq!(plan.anchor, "default");
        assert_eq!(plan.anchor_seq, 0);
        assert_eq!(plan.applied_mutations, 1);
        assert!(plan.state.valves.read_only.enabled);
    }

    #[test]
    fn apply_control_state_mutation_unknown_valve_fails() {
        let mut state = LocalControlV1::default();
        let digest = control_state_digest_v1(&state);
        let mutation = ControlStateMutationV1 {
            schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
            action_id: "a".to_string(),
            mutation_type: "set_valves".to_string(),
            applied_at_unix_ms: 1,
            actor: "t".to_string(),
            reason: "t".to_string(),
            auth: corecrux_types::EvidenceAuthContextV1 {
                mode: "dev_scopes".to_string(),
                subject: None,
                tenant_binding: None,
                scopes: Vec::new(),
            },
            request: corecrux_types::EvidenceRequestContextV1::default(),
            node: corecrux_types::EvidenceNodeContextV1 {
                node_id: "n".to_string(),
                build: build_info(),
                http_listen_addr: None,
                grpc_listen_addr: None,
            },
            control_before: digest.clone(),
            control_after: digest,
            valve_changes: vec![corecrux_types::ValveChangeV1 {
                valve: "nonexistent_valve".to_string(),
                before: corecrux_types::ControlValveStateV1::default(),
                after: corecrux_types::ControlValveStateV1::default(),
            }],
            knowledge_authority_change: None,
            result: None,
        };
        let result = apply_control_state_mutation_v1(&mut state, &mutation);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown control valve"));
    }

    #[test]
    fn load_control_checkpoint_missing_file_returns_default() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("CONTROL.json");
        let (bytes, state) = load_control_checkpoint(&path).unwrap();
        assert_eq!(state, LocalControlV1::default());
        // Bytes should deserialize back to default
        let parsed: LocalControlV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, LocalControlV1::default());
    }

    #[test]
    fn evidence_verify_artifact_check_serializes() {
        let check = EvidenceVerifyArtifactCheckV1 {
            key: "control".to_string(),
            status: EvidenceStatusV1::Pass,
            ok: true,
            path: "control.json".to_string(),
            detail: Some("hash_match=true size_match=true".to_string()),
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(json.contains("\"key\":\"control\""));
        assert!(json.contains("\"ok\":true"));
    }

    #[test]
    fn evidence_verify_check_omits_none_detail() {
        let check = EvidenceVerifyCheckV1 {
            name: "test".to_string(),
            ok: false,
            detail: None,
        };
        let json = serde_json::to_string(&check).unwrap();
        assert!(!json.contains("detail"));
    }

    #[test]
    fn control_evidence_bundle_report_serializes() {
        let bundle = ControlEvidenceBundleV1 {
            report: ControlVerifyReportV1 {
                schema: "corecrux.control.verify.v1".to_string(),
                ok: true,
                hosted: false,
                data_dir: "/tmp".to_string(),
                checkpoint_path: "/tmp/CONTROL.json".to_string(),
                checkpoint_blake3: "0".repeat(64),
                checkpoint_size_bytes: 42,
                current_control_hash: "1".repeat(64),
                expected_checkpoint_blake3: "0".repeat(64),
                expected_checkpoint_size_bytes: 42,
                expected_control_hash: "1".repeat(64),
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
                checks_skipped: Vec::new(),
            },
            checkpoint_bytes: Vec::new(),
            evidence_lines: Vec::new(),
        };
        let json = serde_json::to_string(&bundle.report).unwrap();
        assert!(json.contains("\"ok\":true"));
    }

    #[test]
    fn verify_pack_flags_artifact_hash_mismatch() {
        let dir = tempdir().expect("tempdir");
        let artifact_path = dir.path().join("artifact.json");
        std::fs::write(&artifact_path, br#"{"ok":true}"#).expect("write artifact");

        let manifest = EvidenceManifestV1 {
            schema: corecrux_types::EVIDENCE_MANIFEST_SCHEMA_V1.to_string(),
            generated_at: "2026-03-06T00:00:00Z".to_string(),
            producer: corecrux_types::EvidenceProducerV1 {
                name: "corecruxctl".to_string(),
                version: "test".to_string(),
                commit: "test".to_string(),
            },
            corecrux_build: build_info(),
            compat: None,
            subject_scope: corecrux_types::EvidenceSubjectScopeV1::default(),
            status: EvidenceStatusV1::Pass,
            artifacts: BTreeMap::from([(
                "artifact".to_string(),
                corecrux_types::EvidenceArtifactDescriptorV1 {
                    kind: "generic".to_string(),
                    media_type: "application/json".to_string(),
                    path: "artifact.json".to_string(),
                    blake3: "deadbeef".to_string(),
                    size_bytes: 5,
                    status: EvidenceStatusV1::Pass,
                    required: true,
                    observational: false,
                    produced_by: corecrux_types::EvidenceProducerV1 {
                        name: "corecruxctl".to_string(),
                        version: "test".to_string(),
                        commit: "test".to_string(),
                    },
                    source_refs: Vec::new(),
                },
            )]),
            relationships: Vec::new(),
            missing_capabilities: Vec::new(),
        };
        std::fs::write(
            dir.path().join("evidence_manifest.json"),
            serde_json::to_vec_pretty(&manifest).expect("manifest bytes"),
        )
        .expect("write manifest");

        let report = verify_evidence_pack(&PackVerifyOptions {
            pack_dir: dir.path().to_path_buf(),
            strict: true,
            device_index: 0,
        })
        .expect("verify pack");

        assert!(!report.ok);
        assert_eq!(report.failed_artifacts, 1);
    }

    // ── apply_valve_state clears values ───────────────────────────

    #[test]
    fn apply_valve_state_clears_optional_fields() {
        let mut valve = LocalValveV1 {
            enabled: true,
            actor: "admin".to_string(),
            reason: "testing".to_string(),
            updated_at_unix_ns: 999,
            retry_after_ms: Some(5000),
            events_per_sec: Some(100),
            bytes_per_sec: Some(1_000_000),
            max_in_flight: Some(50),
        };
        let clear = corecrux_types::ControlValveStateV1::default();
        apply_valve_state(&mut valve, &clear);
        assert!(!valve.enabled);
        assert_eq!(valve.actor, "");
        assert_eq!(valve.reason, "");
        assert_eq!(valve.updated_at_unix_ns, 0);
        assert!(valve.retry_after_ms.is_none());
        assert!(valve.events_per_sec.is_none());
        assert!(valve.bytes_per_sec.is_none());
        assert!(valve.max_in_flight.is_none());
    }

    // ── reconcile_control both checkpoint and mutation anchors ────

    #[test]
    fn reconcile_control_prefers_higher_seq_anchor() {
        let state = LocalControlV1::default();
        let digest = control_state_digest_v1(&state);
        let checkpoint_bytes = checkpoint_control_bytes_v1(&state);
        let checkpoint_hash = blake3::hash(&checkpoint_bytes).to_hex().to_string();
        let checkpoint_size = checkpoint_bytes.len() as u64;

        let checkpoints = vec![ControlCheckpointRecord {
            seq: 5,
            payload: corecrux_types::ControlCheckpointMaterializedV1 {
                schema: "corecrux.control.checkpoint_materialized.v1".to_string(),
                checkpoint_id: "cp-1".to_string(),
                materialized_at_unix_ms: 1000,
                node: corecrux_types::EvidenceNodeContextV1 {
                    node_id: "n".to_string(),
                    build: build_info(),
                    http_listen_addr: None,
                    grpc_listen_addr: None,
                },
                control_state: digest.clone(),
                checkpoint_format: "json".to_string(),
                checkpoint_blake3: checkpoint_hash,
                checkpoint_size_bytes: checkpoint_size,
            },
        }];
        let mutations = vec![ControlMutationRecord {
            seq: 3,
            payload: ControlStateMutationV1 {
                schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
                action_id: "a".to_string(),
                mutation_type: "set_valves".to_string(),
                applied_at_unix_ms: 1,
                actor: "t".to_string(),
                reason: "t".to_string(),
                auth: corecrux_types::EvidenceAuthContextV1 {
                    mode: "dev_scopes".to_string(),
                    subject: None,
                    tenant_binding: None,
                    scopes: Vec::new(),
                },
                request: corecrux_types::EvidenceRequestContextV1::default(),
                node: corecrux_types::EvidenceNodeContextV1 {
                    node_id: "n".to_string(),
                    build: build_info(),
                    http_listen_addr: None,
                    grpc_listen_addr: None,
                },
                control_before: digest.clone(),
                control_after: digest.clone(),
                valve_changes: Vec::new(),
                knowledge_authority_change: None,
                result: None,
            },
        }];

        let plan = reconcile_control_from_evidence(&state, &checkpoint_bytes, &checkpoints, &mutations)
            .unwrap()
            .expect("should have plan");
        // Checkpoint at seq 5 > mutation at seq 3, so checkpoint anchor wins
        assert_eq!(plan.anchor, "checkpoint");
        assert_eq!(plan.anchor_seq, 5);
    }

    // ── reconcile_control error: no anchor ────────────────────────

    #[test]
    fn reconcile_control_error_when_no_anchor_and_bad_first_mutation() {
        // Use a non-default state so neither checkpoint nor mutation anchors match
        let mut state = LocalControlV1::default();
        state.updated_at_unix_ns = 777;
        state.valves.throttle.enabled = true;
        let checkpoint_bytes = checkpoint_control_bytes_v1(&state);

        let bad_before = corecrux_types::ControlStateDigestV1 {
            control_version: 99,
            updated_at_unix_ns: 999,
            control_hash_blake3: "wrong_before".to_string(),
        };
        let bad_after = corecrux_types::ControlStateDigestV1 {
            control_version: 99,
            updated_at_unix_ns: 888,
            control_hash_blake3: "wrong_after".to_string(),
        };
        let mutations = vec![ControlMutationRecord {
            seq: 1,
            payload: ControlStateMutationV1 {
                schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
                action_id: "a".to_string(),
                mutation_type: "set_valves".to_string(),
                applied_at_unix_ms: 1,
                actor: "t".to_string(),
                reason: "t".to_string(),
                auth: corecrux_types::EvidenceAuthContextV1 {
                    mode: "dev_scopes".to_string(),
                    subject: None,
                    tenant_binding: None,
                    scopes: Vec::new(),
                },
                request: corecrux_types::EvidenceRequestContextV1::default(),
                node: corecrux_types::EvidenceNodeContextV1 {
                    node_id: "n".to_string(),
                    build: build_info(),
                    http_listen_addr: None,
                    grpc_listen_addr: None,
                },
                control_before: bad_before,
                control_after: bad_after,
                valve_changes: Vec::new(),
                knowledge_authority_change: None,
                result: None,
            },
        }];

        let result = reconcile_control_from_evidence(&state, &checkpoint_bytes, &[], &mutations);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not match any checkpoint"));
    }

    // ── verify_control_inputs checkpoint bytes drift ──────────────

    #[test]
    fn verify_control_inputs_detects_checkpoint_bytes_drift() {
        let dir = tempdir().expect("tempdir");
        let control_path = dir.path().join("CONTROL.json");

        let state = LocalControlV1::default();
        // Write non-canonical bytes (e.g. with extra whitespace)
        let non_canonical = format!("{}\n", serde_json::to_string_pretty(&state).unwrap());
        std::fs::write(&control_path, &non_canonical).expect("write");

        let bundle = verify_control_inputs_v1(
            dir.path(),
            &control_path,
            non_canonical.as_bytes().to_vec(),
            Vec::new(),
            false,
        )
        .expect("verify");

        // No evidence → ok=true, not hosted, state matches (itself)
        assert!(bundle.report.ok);
        assert!(!bundle.report.hosted);
    }

    // ── expected_projection_hash ──────────────────────────────────

    #[test]
    fn expected_projection_hash_all_known_projections() {
        let mut meta = corecrux_projections::ProjectionsMetaV1::empty_now();
        meta.artifact_living_state.snapshot_blake3 = Some("aaa".to_string());
        meta.artifact_relations.snapshot_blake3 = Some("bbb".to_string());
        meta.pressure_events.snapshot_blake3 = Some("ccc".to_string());
        meta.artifact_dependents.snapshot_blake3 = Some("ddd".to_string());
        assert_eq!(
            expected_projection_hash(&meta, "artifact_living_state"),
            Some("aaa".to_string())
        );
        assert_eq!(
            expected_projection_hash(&meta, "artifact_relations"),
            Some("bbb".to_string())
        );
        assert_eq!(
            expected_projection_hash(&meta, "pressure_events"),
            Some("ccc".to_string())
        );
        assert_eq!(
            expected_projection_hash(&meta, "artifact_dependents"),
            Some("ddd".to_string())
        );
        assert_eq!(expected_projection_hash(&meta, "unknown"), None);
    }

    // ── projection snapshot artifact kind ──────────────────────────

    /// An audit pack issued before the `.ccxs` → `.ccxsnap` rename carries the
    /// old `kind` string. Verification must still read it, or renaming the
    /// artifact kind silently invalidates every previously-issued pack.
    #[test]
    fn projection_snapshot_kind_accepts_legacy_and_current_spellings() {
        assert!(is_projection_snapshot_kind("projection_snapshot_ccxsnap"));
        assert!(is_projection_snapshot_kind("projection_snapshot_ccxs"));
        assert!(!is_projection_snapshot_kind("replay_input_segment"));
        assert!(!is_projection_snapshot_kind("projection_snapshot"));
        // Only the current spelling is ever written.
        assert_eq!(PROJECTION_SNAPSHOT_KIND, "projection_snapshot_ccxsnap");
    }

    /// The block-type ids are serialised *inside* the snapshot, so the rename
    /// was allowed to move their identifiers but never their values. The magic
    /// is the one on-disk value that did change, deliberately.
    #[test]
    fn ccxsnap_rename_preserved_block_ids_and_rotated_magic() {
        use corecrux_projections::{CCXSNAP_BLOCK_HOT_PTRS_V1, CCXSNAP_BLOCK_STATS_V1};
        assert_eq!(CCXSNAP_BLOCK_STATS_V1, 4);
        assert_eq!(CCXSNAP_BLOCK_HOT_PTRS_V1, 6);
    }

    // ── projection_name_from_snapshot_artifact ─────────────────────

    #[test]
    fn projection_name_from_snapshot_artifact_finds_name() {
        let artifact = corecrux_types::EvidenceArtifactDescriptorV1 {
            kind: "projection_snapshot_ccxsnap".to_string(),
            media_type: "application/octet-stream".to_string(),
            path: "snapshot.ccxsnap".to_string(),
            blake3: "hash".to_string(),
            size_bytes: 100,
            status: EvidenceStatusV1::Pass,
            required: true,
            observational: false,
            produced_by: corecrux_types::EvidenceProducerV1 {
                name: "t".to_string(),
                version: "0".to_string(),
                commit: "0".to_string(),
            },
            source_refs: vec![EvidenceSourceRefV1::ProjectionSnapshot {
                shard_id: 1,
                projection: "artifact_living_state".to_string(),
                cursor: None,
                expected_blake3: None,
            }],
        };
        assert_eq!(
            projection_name_from_snapshot_artifact(&artifact),
            Some("artifact_living_state".to_string())
        );
    }

    #[test]
    fn projection_name_from_snapshot_artifact_returns_none_no_refs() {
        let artifact = corecrux_types::EvidenceArtifactDescriptorV1 {
            kind: "generic".to_string(),
            media_type: "application/json".to_string(),
            path: "test.json".to_string(),
            blake3: "hash".to_string(),
            size_bytes: 10,
            status: EvidenceStatusV1::Pass,
            required: false,
            observational: false,
            produced_by: corecrux_types::EvidenceProducerV1 {
                name: "t".to_string(),
                version: "0".to_string(),
                commit: "0".to_string(),
            },
            source_refs: Vec::new(),
        };
        assert!(projection_name_from_snapshot_artifact(&artifact).is_none());
    }

    // ── list_shards with non-parseable dir names ──────────────────

    #[test]
    fn list_shards_ignores_non_shard_names() {
        let dir = tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("shard-0001")).unwrap();
        std::fs::create_dir(dir.path().join("shard-abc")).unwrap(); // non-numeric
        std::fs::create_dir(dir.path().join("notshard-0002")).unwrap(); // wrong prefix
        std::fs::write(dir.path().join("shard-0003"), "file").unwrap(); // file, not dir
        let shards = list_shards(dir.path()).unwrap();
        assert_eq!(shards, vec![1]);
    }

    // ── apply_control_state_mutation after digest mismatch ────────

    #[test]
    fn apply_control_state_mutation_fails_with_wrong_after() {
        let mut state = LocalControlV1::default();
        let before_digest = control_state_digest_v1(&state);
        let wrong_after = corecrux_types::ControlStateDigestV1 {
            control_version: 1,
            updated_at_unix_ns: 9999,
            control_hash_blake3: "wrong_after_hash".to_string(),
        };
        let mutation = ControlStateMutationV1 {
            schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
            action_id: "a".to_string(),
            mutation_type: "set_valves".to_string(),
            applied_at_unix_ms: 1,
            actor: "t".to_string(),
            reason: "t".to_string(),
            auth: corecrux_types::EvidenceAuthContextV1 {
                mode: "dev_scopes".to_string(),
                subject: None,
                tenant_binding: None,
                scopes: Vec::new(),
            },
            request: corecrux_types::EvidenceRequestContextV1::default(),
            node: corecrux_types::EvidenceNodeContextV1 {
                node_id: "n".to_string(),
                build: build_info(),
                http_listen_addr: None,
                grpc_listen_addr: None,
            },
            control_before: before_digest,
            control_after: wrong_after,
            valve_changes: Vec::new(),
            knowledge_authority_change: None,
            result: None,
        };
        let result = apply_control_state_mutation_v1(&mut state, &mutation);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("after digest mismatch"));
    }

    // ── Multiple mutations in sequence ────────────────────────────

    #[test]
    fn reconcile_control_applies_multiple_mutations() {
        let state0 = LocalControlV1::default();
        let digest0 = control_state_digest_v1(&state0);

        // Build mutation 1: enable read_only
        let mut state1 = state0.clone();
        state1.updated_at_unix_ns = 100;
        state1.valves.read_only.enabled = true;
        state1.valves.read_only.actor = "op".to_string();
        state1.valves.read_only.reason = "maint".to_string();
        state1.valves.read_only.updated_at_unix_ns = 100;
        let digest1 = control_state_digest_v1(&state1);

        // Build mutation 2: enable throttle
        let mut state2 = state1.clone();
        state2.updated_at_unix_ns = 200;
        state2.valves.throttle.enabled = true;
        state2.valves.throttle.actor = "op".to_string();
        state2.valves.throttle.reason = "load".to_string();
        state2.valves.throttle.updated_at_unix_ns = 200;
        let digest2 = control_state_digest_v1(&state2);

        let mutations = vec![
            ControlMutationRecord {
                seq: 1,
                payload: ControlStateMutationV1 {
                    schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
                    action_id: "a1".to_string(),
                    mutation_type: "set_valves".to_string(),
                    applied_at_unix_ms: 100,
                    actor: "op".to_string(),
                    reason: "maint".to_string(),
                    auth: corecrux_types::EvidenceAuthContextV1 {
                        mode: "dev_scopes".to_string(),
                        subject: None,
                        tenant_binding: None,
                        scopes: vec!["admin:write".to_string()],
                    },
                    request: corecrux_types::EvidenceRequestContextV1::default(),
                    node: corecrux_types::EvidenceNodeContextV1 {
                        node_id: "n".to_string(),
                        build: build_info(),
                        http_listen_addr: None,
                        grpc_listen_addr: None,
                    },
                    control_before: digest0.clone(),
                    control_after: digest1.clone(),
                    valve_changes: vec![corecrux_types::ValveChangeV1 {
                        valve: "read_only".to_string(),
                        before: corecrux_types::ControlValveStateV1::default(),
                        after: corecrux_types::ControlValveStateV1 {
                            enabled: true,
                            actor: "op".to_string(),
                            reason: "maint".to_string(),
                            updated_at_unix_ns: 100,
                            retry_after_ms: None,
                            events_per_sec: None,
                            bytes_per_sec: None,
                            max_in_flight: None,
                        },
                    }],
                    knowledge_authority_change: None,
                    result: None,
                },
            },
            ControlMutationRecord {
                seq: 2,
                payload: ControlStateMutationV1 {
                    schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
                    action_id: "a2".to_string(),
                    mutation_type: "set_valves".to_string(),
                    applied_at_unix_ms: 200,
                    actor: "op".to_string(),
                    reason: "load".to_string(),
                    auth: corecrux_types::EvidenceAuthContextV1 {
                        mode: "dev_scopes".to_string(),
                        subject: None,
                        tenant_binding: None,
                        scopes: vec!["admin:write".to_string()],
                    },
                    request: corecrux_types::EvidenceRequestContextV1::default(),
                    node: corecrux_types::EvidenceNodeContextV1 {
                        node_id: "n".to_string(),
                        build: build_info(),
                        http_listen_addr: None,
                        grpc_listen_addr: None,
                    },
                    control_before: digest1.clone(),
                    control_after: digest2.clone(),
                    valve_changes: vec![corecrux_types::ValveChangeV1 {
                        valve: "throttle".to_string(),
                        before: corecrux_types::ControlValveStateV1::default(),
                        after: corecrux_types::ControlValveStateV1 {
                            enabled: true,
                            actor: "op".to_string(),
                            reason: "load".to_string(),
                            updated_at_unix_ns: 200,
                            retry_after_ms: None,
                            events_per_sec: None,
                            bytes_per_sec: None,
                            max_in_flight: None,
                        },
                    }],
                    knowledge_authority_change: None,
                    result: None,
                },
            },
        ];

        let checkpoint = checkpoint_control_bytes_v1(&state0);
        let plan = reconcile_control_from_evidence(&state0, &checkpoint, &[], &mutations)
            .unwrap()
            .expect("should have plan");

        assert_eq!(plan.anchor, "default");
        assert_eq!(plan.applied_mutations, 2);
        assert!(plan.state.valves.read_only.enabled);
        assert!(plan.state.valves.throttle.enabled);
        assert_eq!(plan.state.updated_at_unix_ns, 200);
    }

    // ── apply_valve_state with all valve types ────────────────────

    #[test]
    fn apply_control_state_mutation_all_valve_types() {
        let mut state = LocalControlV1::default();
        let before_digest = control_state_digest_v1(&state);

        // Build after state with all valves enabled
        let mut after = state.clone();
        after.updated_at_unix_ns = 500;
        let valves = [
            ("pause_ingest", &mut after.valves.pause_ingest),
            ("pause_compaction", &mut after.valves.pause_compaction),
            ("throttle", &mut after.valves.throttle),
            ("read_only", &mut after.valves.read_only),
            ("emergency_brake", &mut after.valves.emergency_brake),
        ];
        for (_name, valve) in valves {
            valve.enabled = true;
            valve.actor = "op".to_string();
            valve.reason = "test".to_string();
            valve.updated_at_unix_ns = 500;
        }
        let after_digest = control_state_digest_v1(&after);

        let valve_names = [
            "pause_ingest",
            "pause_compaction",
            "throttle",
            "read_only",
            "emergency_brake",
        ];
        let valve_changes: Vec<corecrux_types::ValveChangeV1> = valve_names
            .iter()
            .map(|name| corecrux_types::ValveChangeV1 {
                valve: (*name).to_string(),
                before: corecrux_types::ControlValveStateV1::default(),
                after: corecrux_types::ControlValveStateV1 {
                    enabled: true,
                    actor: "op".to_string(),
                    reason: "test".to_string(),
                    updated_at_unix_ns: 500,
                    retry_after_ms: None,
                    events_per_sec: None,
                    bytes_per_sec: None,
                    max_in_flight: None,
                },
            })
            .collect();

        let mutation = ControlStateMutationV1 {
            schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
            action_id: "a".to_string(),
            mutation_type: "set_valves".to_string(),
            applied_at_unix_ms: 1,
            actor: "op".to_string(),
            reason: "test".to_string(),
            auth: corecrux_types::EvidenceAuthContextV1 {
                mode: "dev_scopes".to_string(),
                subject: None,
                tenant_binding: None,
                scopes: Vec::new(),
            },
            request: corecrux_types::EvidenceRequestContextV1::default(),
            node: corecrux_types::EvidenceNodeContextV1 {
                node_id: "n".to_string(),
                build: build_info(),
                http_listen_addr: None,
                grpc_listen_addr: None,
            },
            control_before: before_digest,
            control_after: after_digest,
            valve_changes,
            knowledge_authority_change: None,
            result: None,
        };

        apply_control_state_mutation_v1(&mut state, &mutation).unwrap();
        assert!(state.valves.pause_ingest.enabled);
        assert!(state.valves.pause_compaction.enabled);
        assert!(state.valves.throttle.enabled);
        assert!(state.valves.read_only.enabled);
        assert!(state.valves.emergency_brake.enabled);
    }

    // ── artifact_path_by_kind with multiple artifacts ──────────────

    #[test]
    fn artifact_path_by_kind_returns_first_match() {
        let manifest = EvidenceManifestV1 {
            schema: corecrux_types::EVIDENCE_MANIFEST_SCHEMA_V1.to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            producer: corecrux_types::EvidenceProducerV1 {
                name: "t".to_string(),
                version: "0".to_string(),
                commit: "0".to_string(),
            },
            corecrux_build: build_info(),
            compat: None,
            subject_scope: corecrux_types::EvidenceSubjectScopeV1::default(),
            status: EvidenceStatusV1::Pass,
            artifacts: BTreeMap::from([
                (
                    "a1".to_string(),
                    corecrux_types::EvidenceArtifactDescriptorV1 {
                        kind: "build_info_json".to_string(),
                        media_type: "application/json".to_string(),
                        path: "build_info.json".to_string(),
                        blake3: "hash".to_string(),
                        size_bytes: 10,
                        status: EvidenceStatusV1::Pass,
                        required: true,
                        observational: false,
                        produced_by: corecrux_types::EvidenceProducerV1 {
                            name: "t".to_string(),
                            version: "0".to_string(),
                            commit: "0".to_string(),
                        },
                        source_refs: Vec::new(),
                    },
                ),
                (
                    "a2".to_string(),
                    corecrux_types::EvidenceArtifactDescriptorV1 {
                        kind: "replay_input_segment".to_string(),
                        media_type: "application/octet-stream".to_string(),
                        path: "replay.ccxseg".to_string(),
                        blake3: "hash2".to_string(),
                        size_bytes: 200,
                        status: EvidenceStatusV1::Pass,
                        required: true,
                        observational: false,
                        produced_by: corecrux_types::EvidenceProducerV1 {
                            name: "t".to_string(),
                            version: "0".to_string(),
                            commit: "0".to_string(),
                        },
                        source_refs: Vec::new(),
                    },
                ),
            ]),
            relationships: Vec::new(),
            missing_capabilities: Vec::new(),
        };
        assert_eq!(
            artifact_path_by_kind(&manifest, "build_info_json"),
            Some("build_info.json")
        );
        assert_eq!(
            artifact_path_by_kind(&manifest, "replay_input_segment"),
            Some("replay.ccxseg")
        );
        assert_eq!(artifact_path_by_kind(&manifest, "missing"), None);
    }

    // ── control_state_digest_v1 deterministic ─────────────────────

    #[test]
    fn control_state_digest_v1_is_deterministic() {
        let state = LocalControlV1::default();
        let d1 = control_state_digest_v1(&state);
        let d2 = control_state_digest_v1(&state);
        assert_eq!(d1.control_hash_blake3, d2.control_hash_blake3);
        assert_eq!(d1.control_version, d2.control_version);
    }

    // ── load_control_checkpoint existing file ─────────────────────

    #[test]
    fn load_control_checkpoint_reads_existing() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("CONTROL.json");
        let mut state = LocalControlV1::default();
        state.updated_at_unix_ns = 42;
        state.valves.throttle.enabled = true;
        let bytes = checkpoint_control_bytes_v1(&state);
        std::fs::write(&path, &bytes).expect("write");

        let (loaded_bytes, loaded_state) = load_control_checkpoint(&path).unwrap();
        assert_eq!(loaded_state.updated_at_unix_ns, 42);
        assert!(loaded_state.valves.throttle.enabled);
        assert_eq!(loaded_bytes, bytes);
    }

    // ── verify_pack with matching hashes passes ───────────────────

    #[test]
    fn verify_pack_passes_with_correct_hashes() {
        let dir = tempdir().expect("tempdir");
        let content = br#"{"test":true}"#;
        let artifact_path = dir.path().join("artifact.json");
        std::fs::write(&artifact_path, content).expect("write");

        let hash = blake3::hash(content).to_hex().to_string();
        let manifest = EvidenceManifestV1 {
            schema: corecrux_types::EVIDENCE_MANIFEST_SCHEMA_V1.to_string(),
            generated_at: "2026-03-06T00:00:00Z".to_string(),
            producer: corecrux_types::EvidenceProducerV1 {
                name: "corecruxctl".to_string(),
                version: "test".to_string(),
                commit: "test".to_string(),
            },
            corecrux_build: build_info(),
            compat: None,
            subject_scope: corecrux_types::EvidenceSubjectScopeV1::default(),
            status: EvidenceStatusV1::Pass,
            artifacts: BTreeMap::from([(
                "artifact".to_string(),
                corecrux_types::EvidenceArtifactDescriptorV1 {
                    kind: "generic".to_string(),
                    media_type: "application/json".to_string(),
                    path: "artifact.json".to_string(),
                    blake3: hash,
                    size_bytes: content.len() as u64,
                    status: EvidenceStatusV1::Pass,
                    required: true,
                    observational: false,
                    produced_by: corecrux_types::EvidenceProducerV1 {
                        name: "corecruxctl".to_string(),
                        version: "test".to_string(),
                        commit: "test".to_string(),
                    },
                    source_refs: Vec::new(),
                },
            )]),
            relationships: Vec::new(),
            missing_capabilities: Vec::new(),
        };
        std::fs::write(
            dir.path().join("evidence_manifest.json"),
            serde_json::to_vec_pretty(&manifest).expect("manifest bytes"),
        )
        .expect("write manifest");

        let report = verify_evidence_pack(&PackVerifyOptions {
            pack_dir: dir.path().to_path_buf(),
            strict: false,
            device_index: 0,
        })
        .expect("verify pack");

        assert!(report.ok);
        assert_eq!(report.failed_artifacts, 0);
    }

    // ── verify_pack missing non-required artifact in non-strict ───

    #[test]
    fn verify_pack_missing_optional_artifact_ok_non_strict() {
        let dir = tempdir().expect("tempdir");
        // Artifact file does NOT exist
        let manifest = EvidenceManifestV1 {
            schema: corecrux_types::EVIDENCE_MANIFEST_SCHEMA_V1.to_string(),
            generated_at: "2026-03-06T00:00:00Z".to_string(),
            producer: corecrux_types::EvidenceProducerV1 {
                name: "corecruxctl".to_string(),
                version: "test".to_string(),
                commit: "test".to_string(),
            },
            corecrux_build: build_info(),
            compat: None,
            subject_scope: corecrux_types::EvidenceSubjectScopeV1::default(),
            status: EvidenceStatusV1::Pass,
            artifacts: BTreeMap::from([(
                "optional_artifact".to_string(),
                corecrux_types::EvidenceArtifactDescriptorV1 {
                    kind: "generic".to_string(),
                    media_type: "application/json".to_string(),
                    path: "missing.json".to_string(),
                    blake3: "deadbeef".to_string(),
                    size_bytes: 10,
                    status: EvidenceStatusV1::Pass,
                    required: false, // NOT required
                    observational: false,
                    produced_by: corecrux_types::EvidenceProducerV1 {
                        name: "corecruxctl".to_string(),
                        version: "test".to_string(),
                        commit: "test".to_string(),
                    },
                    source_refs: Vec::new(),
                },
            )]),
            relationships: Vec::new(),
            missing_capabilities: Vec::new(),
        };
        std::fs::write(
            dir.path().join("evidence_manifest.json"),
            serde_json::to_vec_pretty(&manifest).expect("manifest bytes"),
        )
        .expect("write manifest");

        let report = verify_evidence_pack(&PackVerifyOptions {
            pack_dir: dir.path().to_path_buf(),
            strict: false,
            device_index: 0,
        })
        .expect("verify pack");

        // Non-required + non-strict → ok
        assert!(report.ok);
    }

    // ── M5: verification that verified nothing ────────────────────

    fn manifest_with(artifacts: BTreeMap<String, corecrux_types::EvidenceArtifactDescriptorV1>) -> EvidenceManifestV1 {
        EvidenceManifestV1 {
            schema: corecrux_types::EVIDENCE_MANIFEST_SCHEMA_V1.to_string(),
            generated_at: "2026-07-31T00:00:00Z".to_string(),
            producer: corecrux_types::EvidenceProducerV1 {
                name: "corecruxctl".to_string(),
                version: "test".to_string(),
                commit: "test".to_string(),
            },
            corecrux_build: build_info(),
            compat: None,
            subject_scope: corecrux_types::EvidenceSubjectScopeV1::default(),
            status: EvidenceStatusV1::Pass,
            artifacts,
            relationships: Vec::new(),
            missing_capabilities: Vec::new(),
        }
    }

    fn descriptor(kind: &str, path: &str) -> corecrux_types::EvidenceArtifactDescriptorV1 {
        corecrux_types::EvidenceArtifactDescriptorV1 {
            kind: kind.to_string(),
            media_type: "application/json".to_string(),
            path: path.to_string(),
            // `pack_dir_with` materialises each artifact as a zero-byte file,
            // so the per-artifact hash check passes and these tests isolate the
            // *check-level* behaviour under test.
            blake3: blake3::hash(b"").to_hex().to_string(),
            size_bytes: 0,
            status: EvidenceStatusV1::Pass,
            required: false,
            observational: false,
            produced_by: corecrux_types::EvidenceProducerV1 {
                name: "corecruxctl".to_string(),
                version: "test".to_string(),
                commit: "test".to_string(),
            },
            source_refs: Vec::new(),
        }
    }

    /// Write `manifest` into a fresh pack dir, plus a zero-byte file for each
    /// artifact so the per-artifact hash check is not what fails.
    fn pack_dir_with(manifest: &EvidenceManifestV1) -> tempfile::TempDir {
        let dir = tempdir().expect("tempdir");
        for artifact in manifest.artifacts.values() {
            let path = dir.path().join(&artifact.path);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("mkdir");
            }
            std::fs::write(&path, b"").expect("artifact file");
        }
        std::fs::write(
            dir.path().join("evidence_manifest.json"),
            serde_json::to_vec_pretty(manifest).expect("manifest bytes"),
        )
        .expect("write manifest");
        dir
    }

    fn verify(dir: &tempfile::TempDir, strict: bool) -> EvidenceVerifyReportV1 {
        verify_evidence_pack(&PackVerifyOptions {
            pack_dir: dir.path().to_path_buf(),
            strict,
            device_index: 0,
        })
        .expect("verify pack")
    }

    /// D-10: a manifest declaring zero artifacts verified nothing yet reported
    /// `ok: true`, even under `--strict`.
    #[test]
    fn a_manifest_with_no_artifacts_records_a_skip_and_fails_strict() {
        let dir = pack_dir_with(&manifest_with(BTreeMap::new()));

        let lenient = verify(&dir, false);
        assert!(lenient.ok, "an operator verifying an empty pack is not broken");
        assert!(
            lenient
                .checks_skipped
                .contains(&"artifacts:manifest_declares_none".to_string()),
            "but the report says nothing was verified: {:?}",
            lenient.checks_skipped
        );

        let strict = verify(&dir, true);
        assert!(!strict.ok, "under --strict, verifying nothing is not a pass");
    }

    /// D-12: a PARTIAL control trio emitted no checks, so two of the three
    /// artifacts verified identically to all three.
    #[test]
    fn a_partial_control_trio_records_a_skip() {
        let dir = pack_dir_with(&manifest_with(BTreeMap::from([
            (
                "checkpoint".to_string(),
                descriptor("control_checkpoint_json", "control_checkpoint.json"),
            ),
            (
                "evidence".to_string(),
                descriptor("control_evidence_jsonl", "control_evidence.jsonl"),
            ),
            // `control_verify_report` deliberately absent.
        ])));

        let report = verify(&dir, false);
        assert!(
            report
                .checks_skipped
                .iter()
                .any(|skip| skip.starts_with("control_verify_report:missing_artifacts")),
            "{:?}",
            report.checks_skipped
        );
        assert!(!verify(&dir, true).ok, "--strict refuses an unevaluable check");
    }

    /// Control for D-12: a wholly absent control trio means the caller never
    /// asked, so it is NOT listed. A field that is non-empty on every ordinary
    /// run is useless as a gate.
    #[test]
    fn a_wholly_absent_control_trio_is_not_a_skip() {
        let dir = pack_dir_with(&manifest_with(BTreeMap::from([(
            "generic".to_string(),
            descriptor("generic", "artifact.json"),
        )])));

        let report = verify(&dir, false);
        assert!(
            report.checks_skipped.is_empty(),
            "nothing was requested, so nothing was skipped: {:?}",
            report.checks_skipped
        );
        assert!(verify(&dir, true).ok, "and --strict still passes");
    }

    /// D-13: one half of the replay pair emitted no determinism check.
    #[test]
    fn half_a_replay_pair_records_a_skip() {
        let dir = pack_dir_with(&manifest_with(BTreeMap::from([(
            "replay_input".to_string(),
            descriptor("replay_input_segment", "replay_input.seg"),
        )])));

        let report = verify(&dir, false);
        assert_eq!(
            report.checks_skipped,
            vec!["replay_determinism:missing_replay_determinism_report".to_string()]
        );
    }

    /// D-14: a declared-but-missing `projection_meta_json` was loaded as an
    /// EMPTY meta, so every snapshot compared against an all-`None` expectation
    /// set — and a meta with no sibling snapshots emitted no check at all.
    #[test]
    fn a_declared_but_missing_projection_meta_records_a_skip() {
        let manifest = manifest_with(BTreeMap::from([(
            "projection_meta".to_string(),
            descriptor("projection_meta_json", "projections/projections.meta.json"),
        )]));
        // Build the pack WITHOUT materialising the artifact file.
        let dir = tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("evidence_manifest.json"),
            serde_json::to_vec_pretty(&manifest).expect("manifest bytes"),
        )
        .expect("write manifest");

        let report = verify(&dir, false);
        assert!(
            report
                .checks_skipped
                .iter()
                .any(|skip| skip.starts_with("projection_meta:missing")),
            "{:?}",
            report.checks_skipped
        );
    }

    /// D-11: a receipt bundle WITHOUT a keyring emitted `ok: true` with only a
    /// free-text `skipped_signature_verification` detail, so the aggregate `ok`
    /// was identical to a pack whose signature actually verified.
    #[test]
    fn a_receipt_bundle_without_a_keyring_records_a_skip() {
        let dir = pack_dir_with(&manifest_with(BTreeMap::from([(
            "bundle".to_string(),
            descriptor("receipt_export_bundle", "receipts.zip"),
        )])));

        let report = verify(&dir, false);
        assert!(report.ok, "an operator verifying without a keyring is not broken");
        assert_eq!(
            report.checks_skipped,
            vec!["receipt_signature_verification:no_keyring".to_string()],
            "but the signature was never checked, and the report says so"
        );
        assert!(
            report
                .checks
                .iter()
                .any(|check| check.name == "receipt_signature_verification" && check.ok),
            "the pass-shaped check is still emitted for compatibility"
        );
        assert!(!verify(&dir, true).ok, "--strict refuses an unverified signature");
    }

    /// D-17: with no control evidence there is nothing to replay, yet
    /// `state_matches_evidence` and `checkpoint_bytes_match_expected` both
    /// reported `true` and `ok` was simply `!hosted_only`.
    #[test]
    fn control_verify_with_no_evidence_records_a_skip() {
        let dir = tempdir().expect("tempdir");
        let bundle = verify_control_inputs_v1(
            dir.path(),
            &dir.path().join("CONTROL.json"),
            checkpoint_control_bytes_v1(&LocalControlV1::default()),
            Vec::new(),
            false,
        )
        .expect("verify control inputs");

        assert!(bundle.report.ok, "an unhosted deployment is not an error");
        assert_eq!(
            bundle.report.checks_skipped,
            vec!["control_evidence_replay:no_events".to_string()],
            "but nothing was replayed, and the report says so"
        );
    }

    // ── reconcile_control mutation-only anchor ────────────────────

    #[test]
    fn reconcile_control_mutation_anchor_only() {
        let state = LocalControlV1::default();
        let digest = control_state_digest_v1(&state);
        let checkpoint_bytes = checkpoint_control_bytes_v1(&state);

        let mutations = vec![ControlMutationRecord {
            seq: 7,
            payload: ControlStateMutationV1 {
                schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
                action_id: "a".to_string(),
                mutation_type: "set_valves".to_string(),
                applied_at_unix_ms: 1,
                actor: "t".to_string(),
                reason: "t".to_string(),
                auth: corecrux_types::EvidenceAuthContextV1 {
                    mode: "dev_scopes".to_string(),
                    subject: None,
                    tenant_binding: None,
                    scopes: Vec::new(),
                },
                request: corecrux_types::EvidenceRequestContextV1::default(),
                node: corecrux_types::EvidenceNodeContextV1 {
                    node_id: "n".to_string(),
                    build: build_info(),
                    http_listen_addr: None,
                    grpc_listen_addr: None,
                },
                control_before: digest.clone(),
                control_after: digest.clone(),
                valve_changes: Vec::new(),
                knowledge_authority_change: None,
                result: None,
            },
        }];

        let plan = reconcile_control_from_evidence(&state, &checkpoint_bytes, &[], &mutations)
            .unwrap()
            .expect("should have plan");
        assert_eq!(plan.anchor, "mutation");
        assert_eq!(plan.anchor_seq, 7);
    }

    // ══════════════════════════════════════════════════════════════════
    // Evidence-pack verification: the checks below concentrate on whether
    // MISSING or UNVERIFIABLE evidence is reported as such, rather than
    // silently folded into a clean report.
    // ══════════════════════════════════════════════════════════════════

    fn producer() -> corecrux_types::EvidenceProducerV1 {
        corecrux_types::EvidenceProducerV1 {
            name: "corecruxctl".to_string(),
            version: "test".to_string(),
            commit: "test".to_string(),
        }
    }

    fn descriptor_bytes(
        kind: &str,
        path: &str,
        bytes: &[u8],
        required: bool,
    ) -> corecrux_types::EvidenceArtifactDescriptorV1 {
        corecrux_types::EvidenceArtifactDescriptorV1 {
            kind: kind.to_string(),
            media_type: "application/octet-stream".to_string(),
            path: path.to_string(),
            blake3: blake3::hash(bytes).to_hex().to_string(),
            size_bytes: bytes.len() as u64,
            status: EvidenceStatusV1::Pass,
            required,
            observational: false,
            produced_by: producer(),
            source_refs: Vec::new(),
        }
    }

    fn manifest_with_producer(
        artifacts: BTreeMap<String, corecrux_types::EvidenceArtifactDescriptorV1>,
    ) -> EvidenceManifestV1 {
        EvidenceManifestV1 {
            schema: corecrux_types::EVIDENCE_MANIFEST_SCHEMA_V1.to_string(),
            generated_at: "2026-03-06T00:00:00Z".to_string(),
            producer: producer(),
            corecrux_build: build_info(),
            compat: None,
            subject_scope: corecrux_types::EvidenceSubjectScopeV1::default(),
            status: EvidenceStatusV1::Pass,
            artifacts,
            relationships: Vec::new(),
            missing_capabilities: Vec::new(),
        }
    }

    fn write_manifest(pack_dir: &Path, manifest: &EvidenceManifestV1) {
        std::fs::write(
            pack_dir.join("evidence_manifest.json"),
            serde_json::to_vec_pretty(manifest).expect("manifest bytes"),
        )
        .expect("write manifest");
    }

    fn verify_pack(pack_dir: &Path, strict: bool) -> Result<EvidenceVerifyReportV1, DynError> {
        verify_evidence_pack(&PackVerifyOptions {
            pack_dir: pack_dir.to_path_buf(),
            strict,
            device_index: 0,
        })
    }

    // ── verify_evidence_pack: manifest plumbing ─────────────────────

    /// No manifest at all must be an error. A pack directory that cannot be
    /// read is not a pack that passed.
    #[test]
    fn verify_pack_without_manifest_errors() {
        let dir = tempdir().expect("tempdir");
        assert!(verify_pack(dir.path(), false).is_err());
    }

    #[test]
    fn verify_pack_with_unparsable_manifest_errors() {
        let dir = tempdir().expect("tempdir");
        std::fs::write(dir.path().join("evidence_manifest.json"), b"{ not json").expect("write");
        assert!(verify_pack(dir.path(), false).is_err());
    }

    /// D-10 (pin inverted): a manifest declaring ZERO artifacts used to verify
    /// nothing and still report `ok: true`, even under `--strict`, so an empty
    /// pack was indistinguishable from a fully-verified one. It now records
    /// `artifacts:manifest_declares_none` and fails `--strict`.
    #[test]
    fn verify_pack_with_zero_artifacts_records_a_skip_and_fails_strict() {
        let dir = tempdir().expect("tempdir");
        write_manifest(dir.path(), &manifest_with_producer(BTreeMap::new()));

        let report = verify_pack(dir.path(), true).expect("verify");
        assert!(!report.ok, "under --strict, verifying nothing is not a pass");
        assert_eq!(report.checked_artifacts, 0);
        assert_eq!(report.failed_artifacts, 0);
        assert!(
            report
                .checks_skipped
                .contains(&"artifacts:manifest_declares_none".to_string()),
            "the report must say nothing was verified: {:?}",
            report.checks_skipped
        );
    }

    /// A missing but *required* artifact must fail even without `--strict`.
    #[test]
    fn verify_pack_missing_required_artifact_fails_non_strict() {
        let dir = tempdir().expect("tempdir");
        let mut artifacts = BTreeMap::new();
        artifacts.insert("req".to_string(), descriptor_bytes("generic", "gone.json", b"x", true));
        write_manifest(dir.path(), &manifest_with_producer(artifacts));

        let report = verify_pack(dir.path(), false).expect("verify");
        assert!(!report.ok);
        assert_eq!(report.failed_artifacts, 1);
        assert_eq!(report.artifact_checks[0].detail.as_deref(), Some("artifact missing"));
    }

    /// `--strict` promotes an absent optional artifact from "tolerated" to a
    /// failure — the difference between the two modes must be observable.
    #[test]
    fn verify_pack_missing_optional_artifact_fails_under_strict() {
        let dir = tempdir().expect("tempdir");
        let mut artifacts = BTreeMap::new();
        artifacts.insert("opt".to_string(), descriptor_bytes("generic", "gone.json", b"x", false));
        write_manifest(dir.path(), &manifest_with_producer(artifacts));

        let report = verify_pack(dir.path(), true).expect("verify");
        assert!(!report.ok);
        assert_eq!(report.failed_artifacts, 1);
    }

    /// Right hash, wrong recorded size: the size half of the comparison must
    /// carry weight of its own.
    #[test]
    fn verify_pack_flags_size_mismatch_with_matching_hash() {
        let dir = tempdir().expect("tempdir");
        let bytes = br#"{"ok":true}"#;
        std::fs::write(dir.path().join("a.json"), bytes).expect("write");
        let mut d = descriptor_bytes("generic", "a.json", bytes, true);
        d.size_bytes = bytes.len() as u64 + 1;
        let mut artifacts = BTreeMap::new();
        artifacts.insert("a".to_string(), d);
        write_manifest(dir.path(), &manifest_with_producer(artifacts));

        let report = verify_pack(dir.path(), false).expect("verify");
        assert!(!report.ok);
        assert_eq!(report.failed_artifacts, 1);
        let detail = report.artifact_checks[0].detail.clone().unwrap_or_default();
        assert!(detail.contains("hash_match=true"), "detail={detail}");
        assert!(detail.contains("size_match=false"), "detail={detail}");
    }

    // ── audit_pack_index_v2 cross-check ─────────────────────────────

    fn write_audit_index(pack_dir: &Path, manifest_blake3: String, manifest_size_bytes: u64) {
        let index = AuditPackIndexV2 {
            schema: "corecrux.audit.pack_index.v2".to_string(),
            format_version: 2,
            generated_at: "2026-03-06T00:00:00Z".to_string(),
            producer: producer(),
            status: EvidenceStatusV1::Pass,
            manifest_path: "evidence_manifest.json".to_string(),
            manifest_blake3,
            manifest_size_bytes,
            artifact_summary: BTreeMap::new(),
        };
        std::fs::write(
            pack_dir.join("audit_pack_index_v2.json"),
            serde_json::to_vec_pretty(&index).expect("index bytes"),
        )
        .expect("write index");
    }

    #[test]
    fn verify_pack_audit_index_matching_manifest_passes() {
        let dir = tempdir().expect("tempdir");
        let manifest = manifest_with_producer(BTreeMap::new());
        write_manifest(dir.path(), &manifest);
        let manifest_bytes = std::fs::read(dir.path().join("evidence_manifest.json")).expect("read");
        write_audit_index(
            dir.path(),
            blake3::hash(&manifest_bytes).to_hex().to_string(),
            manifest_bytes.len() as u64,
        );

        let report = verify_pack(dir.path(), false).expect("verify");
        let check = report
            .checks
            .iter()
            .find(|c| c.name == "audit_pack_index_v2")
            .expect("index check present");
        assert!(check.ok);
        assert!(report.ok);
    }

    /// The audit index binds the pack to a specific manifest. A stale index
    /// (built against an earlier manifest) must fail the pack.
    #[test]
    fn verify_pack_audit_index_stale_manifest_hash_fails() {
        let dir = tempdir().expect("tempdir");
        write_manifest(dir.path(), &manifest_with_producer(BTreeMap::new()));
        write_audit_index(dir.path(), "0".repeat(64), 1);

        let report = verify_pack(dir.path(), false).expect("verify");
        let check = report
            .checks
            .iter()
            .find(|c| c.name == "audit_pack_index_v2")
            .expect("index check present");
        assert!(!check.ok);
        assert!(!report.ok);
        let detail = check.detail.clone().unwrap_or_default();
        assert!(detail.contains("manifest_hash_match=false"), "detail={detail}");
        assert!(detail.contains("manifest_size_match=false"), "detail={detail}");
    }

    #[test]
    fn verify_pack_unparsable_audit_index_errors() {
        let dir = tempdir().expect("tempdir");
        write_manifest(dir.path(), &manifest_with_producer(BTreeMap::new()));
        std::fs::write(dir.path().join("audit_pack_index_v2.json"), b"nope").expect("write");
        assert!(verify_pack(dir.path(), false).is_err());
    }

    // ── verify_control_artifacts ────────────────────────────────────

    /// DEFECT PIN (absent signal reads as pass): with none of the three
    /// control artifacts declared, `verify_control_artifacts` emits no checks
    /// at all — so a pack that omits control evidence entirely is scored the
    /// same as one whose control evidence replayed cleanly. Reported, not
    /// fixed.
    #[test]
    fn verify_control_artifacts_absent_emits_no_checks() {
        let manifest = manifest_with_producer(BTreeMap::new());
        let dir = tempdir().expect("tempdir");
        let (checks, checks_skipped) = verify_control_artifacts(dir.path(), &manifest, true).expect("checks");
        assert!(checks.is_empty());
        // A WHOLLY absent trio means the caller never asked, so it is
        // deliberately not a skip either — `a_wholly_absent_control_trio_is_not_a_skip`
        // pins that distinction. A *partial* trio is the one that records a skip.
        assert!(checks_skipped.is_empty());
    }

    /// A partial control trio (checkpoint present, report missing) is also
    /// silently skipped rather than flagged. Same defect class as above.
    #[test]
    fn verify_control_artifacts_partial_trio_emits_no_checks() {
        let dir = tempdir().expect("tempdir");
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "cp".to_string(),
            descriptor_bytes("control_checkpoint_json", "CONTROL.json", b"{}", true),
        );
        let manifest = manifest_with_producer(artifacts);
        let (checks, checks_skipped) = verify_control_artifacts(dir.path(), &manifest, true).expect("checks");
        assert!(checks.is_empty());
        assert!(
            !checks_skipped.is_empty(),
            "a partial control trio must be recorded as skipped"
        );
    }

    /// Full trio: the rebuilt report must agree with the bundled one.
    fn control_trio_pack(bundled_ok: bool, tamper_hash: bool) -> tempfile::TempDir {
        let dir = tempdir().expect("tempdir");
        let checkpoint_bytes = default_checkpoint_bytes();
        std::fs::write(dir.path().join("checkpoint.json"), &checkpoint_bytes).expect("write checkpoint");
        std::fs::write(dir.path().join("evidence.jsonl"), b"").expect("write evidence");

        let state = LocalControlV1::default();
        let control_hash = control_state_digest_v1(&state).control_hash_blake3;
        let checkpoint_hash = blake3::hash(&checkpoint_bytes).to_hex().to_string();
        let bundled = ControlVerifyReportV1 {
            schema: "corecrux.control.verify.v1".to_string(),
            ok: bundled_ok,
            hosted: false,
            data_dir: dir.path().display().to_string(),
            checkpoint_path: dir.path().join("CONTROL.json").display().to_string(),
            checkpoint_blake3: checkpoint_hash.clone(),
            checkpoint_size_bytes: checkpoint_bytes.len() as u64,
            current_control_hash: control_hash.clone(),
            expected_checkpoint_blake3: if tamper_hash { "f".repeat(64) } else { checkpoint_hash },
            expected_checkpoint_size_bytes: checkpoint_bytes.len() as u64,
            expected_control_hash: control_hash,
            anchor: None,
            anchor_seq: None,
            applied_mutations: 0,
            checkpoint_events: 0,
            mutation_events: 0,
            evidence_events: 0,
            shard_ids: Vec::new(),
            state_matches_evidence: true,
            checkpoint_bytes_match_expected: true,
            checks_skipped: Vec::new(),
            error_code: None,
            error_message: None,
        };
        std::fs::write(
            dir.path().join("control_verify.json"),
            serde_json::to_vec_pretty(&bundled).expect("report bytes"),
        )
        .expect("write report");
        dir
    }

    fn control_trio_manifest() -> EvidenceManifestV1 {
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "cp".to_string(),
            descriptor_bytes("control_checkpoint_json", "checkpoint.json", b"", true),
        );
        artifacts.insert(
            "ev".to_string(),
            descriptor_bytes("control_evidence_jsonl", "evidence.jsonl", b"", true),
        );
        artifacts.insert(
            "rp".to_string(),
            descriptor_bytes("control_verify_report", "control_verify.json", b"", true),
        );
        manifest_with_producer(artifacts)
    }

    #[test]
    fn verify_control_artifacts_rebuild_agrees_with_bundled_report() {
        let dir = control_trio_pack(true, false);
        let (checks, _checks_skipped) =
            verify_control_artifacts(dir.path(), &control_trio_manifest(), false).expect("checks");
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name, "control_verify_report");
        assert!(checks[0].ok, "detail={:?}", checks[0].detail);
    }

    /// A bundled report claiming `ok: false` while the rebuild says `ok: true`
    /// is a disagreement and must fail the check.
    #[test]
    fn verify_control_artifacts_flags_bundled_ok_disagreement() {
        let dir = control_trio_pack(false, false);
        let (checks, _checks_skipped) =
            verify_control_artifacts(dir.path(), &control_trio_manifest(), false).expect("checks");
        assert!(!checks[0].ok);
        let detail = checks[0].detail.clone().unwrap_or_default();
        assert!(detail.contains("rebuilt_ok=true"), "detail={detail}");
        assert!(detail.contains("bundled_ok=false"), "detail={detail}");
    }

    /// A tampered `expectedCheckpointBlake3` in the bundled report must not
    /// survive the rebuild.
    #[test]
    fn verify_control_artifacts_flags_expected_checkpoint_hash_drift() {
        let dir = control_trio_pack(true, true);
        let (checks, _checks_skipped) =
            verify_control_artifacts(dir.path(), &control_trio_manifest(), false).expect("checks");
        assert!(!checks[0].ok);
        let detail = checks[0].detail.clone().unwrap_or_default();
        assert!(
            detail.contains("expected_checkpoint_hash_match=false"),
            "detail={detail}"
        );
    }

    // ── verify_receipt_artifacts ────────────────────────────────────

    #[test]
    fn verify_receipt_artifacts_without_bundle_emits_no_checks() {
        let dir = tempdir().expect("tempdir");
        let (checks, _checks_skipped) =
            verify_receipt_artifacts(dir.path(), &manifest_with_producer(BTreeMap::new())).expect("checks");
        assert!(checks.is_empty());
    }

    /// DEFECT PIN (absent signal reads as pass): a receipt bundle with NO
    /// keyring produces a check named `receipt_signature_verification` with
    /// `ok: true` and detail `skipped_signature_verification`. Nothing was
    /// verified, but the pack's aggregate `ok` is unaffected — an unsigned or
    /// unverifiable receipt scores identically to a verified one. Reported,
    /// not fixed.
    #[test]
    fn verify_receipt_artifacts_without_keyring_reports_ok_while_skipping() {
        let dir = tempdir().expect("tempdir");
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "bundle".to_string(),
            descriptor_bytes("receipt_export_bundle", "bundle.zip", b"", true),
        );
        let (checks, checks_skipped) =
            verify_receipt_artifacts(dir.path(), &manifest_with_producer(artifacts)).expect("checks");
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].name, "receipt_signature_verification");
        assert!(checks[0].ok, "skipped verification currently reports ok");
        assert_eq!(checks[0].detail.as_deref(), Some("skipped_signature_verification"));
        assert!(
            !checks_skipped.is_empty(),
            "no keyring means the signature check could not run and must be recorded"
        );
    }

    /// With a keyring declared the bundle is actually opened; a missing or
    /// unreadable bundle must be an error, not a skip.
    #[test]
    fn verify_receipt_artifacts_with_keyring_but_missing_bundle_errors() {
        let dir = tempdir().expect("tempdir");
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "bundle".to_string(),
            descriptor_bytes("receipt_export_bundle", "bundle.zip", b"", true),
        );
        artifacts.insert(
            "kr".to_string(),
            descriptor_bytes("receipt_keyring_json", "keyring.json", b"", true),
        );
        assert!(verify_receipt_artifacts(dir.path(), &manifest_with_producer(artifacts)).is_err());
    }

    #[test]
    fn verify_receipt_artifacts_with_keyring_and_non_zip_bundle_errors() {
        let dir = tempdir().expect("tempdir");
        std::fs::write(dir.path().join("bundle.zip"), b"definitely not a zip").expect("write");
        std::fs::write(dir.path().join("keyring.json"), b"{}").expect("write");
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "bundle".to_string(),
            descriptor_bytes("receipt_export_bundle", "bundle.zip", b"", true),
        );
        artifacts.insert(
            "kr".to_string(),
            descriptor_bytes("receipt_keyring_json", "keyring.json", b"", true),
        );
        assert!(verify_receipt_artifacts(dir.path(), &manifest_with_producer(artifacts)).is_err());
    }

    // ── read_zip_entry ──────────────────────────────────────────────

    fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write as _;
        let mut cursor = Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut cursor);
            let opts = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (name, bytes) in entries {
                writer.start_file(*name, opts).expect("start entry");
                writer.write_all(bytes).expect("write entry");
            }
            writer.finish().expect("finish zip");
        }
        cursor.into_inner()
    }

    #[test]
    fn read_zip_entry_reads_named_entry() {
        let bytes = zip_with(&[("manifest.json", br#"{"a":1}"#)]);
        let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).expect("open zip");
        let out = read_zip_entry(&mut zip, "manifest.json").expect("read entry");
        assert_eq!(out, br#"{"a":1}"#);
    }

    /// A receipt bundle missing `receipt/sig.cbor` must error, not yield an
    /// empty signature that then "verifies".
    #[test]
    fn read_zip_entry_missing_entry_errors() {
        let bytes = zip_with(&[("manifest.json", b"{}")]);
        let mut zip = zip::ZipArchive::new(Cursor::new(bytes)).expect("open zip");
        assert!(read_zip_entry(&mut zip, "receipt/sig.cbor").is_err());
    }

    // ── verify_replay_artifacts ─────────────────────────────────────

    /// DEFECT PIN (absent signal reads as pass): replay determinism is only
    /// checked when BOTH the input segment and the determinism report are
    /// declared. Declaring just one silently emits no check. Reported, not
    /// fixed.
    #[test]
    fn verify_replay_artifacts_with_only_one_half_emits_no_checks() {
        let dir = tempdir().expect("tempdir");
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "seg".to_string(),
            descriptor_bytes("replay_input_segment", "input.ccxseg", b"", true),
        );
        let (checks, _checks_skipped) =
            verify_replay_artifacts(dir.path(), &manifest_with_producer(artifacts), 0).expect("checks");
        assert!(checks.is_empty());

        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "rep".to_string(),
            descriptor_bytes("replay_determinism_report", "replay.json", b"", true),
        );
        let (checks, checks_skipped) =
            verify_replay_artifacts(dir.path(), &manifest_with_producer(artifacts), 0).expect("checks");
        assert!(checks.is_empty());
        assert!(
            !checks_skipped.is_empty(),
            "half a replay pair must be recorded as skipped"
        );
    }

    /// With both halves declared, an unreadable determinism report is an
    /// error rather than a pass with default (empty) digests.
    #[test]
    fn verify_replay_artifacts_unreadable_report_errors() {
        let dir = tempdir().expect("tempdir");
        std::fs::write(dir.path().join("replay.json"), b"not json").expect("write");
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "seg".to_string(),
            descriptor_bytes("replay_input_segment", "input.ccxseg", b"", true),
        );
        artifacts.insert(
            "rep".to_string(),
            descriptor_bytes("replay_determinism_report", "replay.json", b"", true),
        );
        assert!(verify_replay_artifacts(dir.path(), &manifest_with_producer(artifacts), 0).is_err());
    }

    // ── verify_projection_artifacts ─────────────────────────────────

    /// Lay out `<pack>/proj/{projections.meta.json, living.ccxsnap}` and return
    /// the manifest describing both. `snapshot_hash_in_meta` controls whether
    /// the meta records the snapshot's real hash.
    fn projection_pack(dir: &Path, snapshot_hash_in_meta: Option<String>) -> EvidenceManifestV1 {
        let proj_dir = dir.join("proj");
        std::fs::create_dir_all(&proj_dir).expect("mkdir");
        let snapshot_bytes = b"pretend-ccxsnap-snapshot-bytes".to_vec();
        std::fs::write(proj_dir.join("living.ccxsnap"), &snapshot_bytes).expect("write snapshot");

        let mut meta = corecrux_projections::ProjectionsMetaV1::empty_now();
        meta.artifact_living_state.snapshot_blake3 = snapshot_hash_in_meta;
        std::fs::write(
            proj_dir.join("projections.meta.json"),
            serde_json::to_vec_pretty(&meta).expect("meta bytes"),
        )
        .expect("write meta");

        let mut snapshot_desc = descriptor_bytes(
            "projection_snapshot_ccxsnap",
            "proj/living.ccxsnap",
            &snapshot_bytes,
            true,
        );
        snapshot_desc.source_refs = vec![EvidenceSourceRefV1::ProjectionSnapshot {
            shard_id: 1,
            projection: "artifact_living_state".to_string(),
            cursor: None,
            expected_blake3: None,
        }];

        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "meta".to_string(),
            descriptor_bytes("projection_meta_json", "proj/projections.meta.json", b"", true),
        );
        artifacts.insert("snap".to_string(), snapshot_desc);
        manifest_with_producer(artifacts)
    }

    #[test]
    fn verify_projection_artifacts_without_meta_emits_no_checks() {
        let dir = tempdir().expect("tempdir");
        let (checks, _checks_skipped) =
            verify_projection_artifacts(dir.path(), &manifest_with_producer(BTreeMap::new())).expect("checks");
        assert!(checks.is_empty());
    }

    #[test]
    fn verify_projection_artifacts_matching_snapshot_hash_passes() {
        let dir = tempdir().expect("tempdir");
        let expected = CcxsnapSnapshot::snapshot_blake3_hex(b"pretend-ccxsnap-snapshot-bytes");
        let manifest = projection_pack(dir.path(), Some(expected));
        let (checks, _checks_skipped) = verify_projection_artifacts(dir.path(), &manifest).expect("checks");
        assert_eq!(checks.len(), 1);
        assert!(checks[0].ok, "detail={:?}", checks[0].detail);
        assert!(checks[0].name.starts_with("snapshot_hash:artifact_living_state:"));
    }

    /// The snapshot on disk no longer hashes to what `projections.meta.json`
    /// records: the pack must fail, not report the snapshot as authoritative.
    #[test]
    fn verify_projection_artifacts_snapshot_hash_drift_fails() {
        let dir = tempdir().expect("tempdir");
        let manifest = projection_pack(dir.path(), Some("a".repeat(64)));
        let (checks, _checks_skipped) = verify_projection_artifacts(dir.path(), &manifest).expect("checks");
        assert_eq!(checks.len(), 1);
        assert!(!checks[0].ok);
    }

    /// Meta records NO hash for the projection. `expected_projection_hash`
    /// returns `None`, and the check reports `expected=missing` + `ok:false` —
    /// an absent expectation is correctly treated as a failure here.
    #[test]
    fn verify_projection_artifacts_missing_expected_hash_fails() {
        let dir = tempdir().expect("tempdir");
        let manifest = projection_pack(dir.path(), None);
        let (checks, _checks_skipped) = verify_projection_artifacts(dir.path(), &manifest).expect("checks");
        assert_eq!(checks.len(), 1);
        assert!(!checks[0].ok);
        assert!(
            checks[0]
                .detail
                .clone()
                .unwrap_or_default()
                .contains("expected=missing"),
            "detail={:?}",
            checks[0].detail
        );
    }

    /// A snapshot artifact with no `ProjectionSnapshot` source ref cannot be
    /// attributed to a projection, so verification must abort rather than skip.
    #[test]
    fn verify_projection_artifacts_snapshot_without_source_ref_errors() {
        let dir = tempdir().expect("tempdir");
        let mut manifest = projection_pack(dir.path(), Some("a".repeat(64)));
        if let Some(snap) = manifest.artifacts.get_mut("snap") {
            snap.source_refs.clear();
        }
        assert!(verify_projection_artifacts(dir.path(), &manifest).is_err());
    }

    /// DEFECT PIN (absent signal reads as pass): a manifest that declares a
    /// `projection_meta_json` artifact whose FILE is absent does not error.
    /// `load_projections_meta_v1` returns `ProjectionsMetaV1::empty_now()` for
    /// a missing path, so `verify_projection_artifacts` proceeds with an
    /// all-`None` expectation set and emits no checks at all. The pack-level
    /// artifact-existence loop is the only thing that would notice, and only
    /// when the artifact is `required` or `--strict` is set. Reported, not
    /// fixed.
    #[test]
    fn verify_projection_artifacts_missing_meta_file_silently_uses_empty_meta() {
        let dir = tempdir().expect("tempdir");
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "meta".to_string(),
            descriptor_bytes("projection_meta_json", "missing.meta.json", b"", false),
        );
        let (checks, checks_skipped) =
            verify_projection_artifacts(dir.path(), &manifest_with_producer(artifacts)).expect("no error");
        assert!(checks.is_empty(), "missing meta produced no verification at all");
        assert!(
            !checks_skipped.is_empty(),
            "a declared-but-missing projection meta must be recorded as skipped"
        );
    }

    /// A meta file that exists but is not parsable JSON must error.
    #[test]
    fn verify_projection_artifacts_unparsable_meta_errors() {
        let dir = tempdir().expect("tempdir");
        std::fs::write(dir.path().join("bad.meta.json"), b"{ nope").expect("write");
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            "meta".to_string(),
            descriptor_bytes("projection_meta_json", "bad.meta.json", b"", true),
        );
        assert!(verify_projection_artifacts(dir.path(), &manifest_with_producer(artifacts)).is_err());
    }

    // ── control evidence collection ─────────────────────────────────

    /// A data dir with no `shards/` directory yields zero evidence lines. The
    /// caller (`verify_control_inputs_v1`) turns that into `hosted: false`,
    /// which under `--hosted-only` is `NOT_HOSTED` rather than a pass.
    #[test]
    fn collect_control_evidence_lines_without_shards_dir_is_empty() {
        let dir = tempdir().expect("tempdir");
        let lines = collect_control_evidence_lines_v1(dir.path(), 0, 16).expect("collect");
        assert!(lines.is_empty());
    }

    #[test]
    fn collect_control_evidence_lines_with_empty_shards_dir_is_empty() {
        let dir = tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("shards")).expect("mkdir");
        let lines = collect_control_evidence_lines_v1(dir.path(), 0, 16).expect("collect");
        assert!(lines.is_empty());
    }

    #[test]
    fn collect_control_evidence_bundle_on_empty_data_dir_is_not_hosted() {
        let dir = tempdir().expect("tempdir");
        let bundle = collect_control_evidence_bundle_v1(&ControlVerifyOptions {
            data_dir: dir.path().to_path_buf(),
            hosted_only: false,
            device_index: 0,
            batch_frames: 0,
        })
        .expect("bundle");
        assert!(!bundle.report.hosted);
        assert!(bundle.report.ok);
        assert!(bundle.evidence_lines.is_empty());
    }

    #[test]
    fn control_verify_hosted_only_on_empty_data_dir_reports_not_hosted() {
        let dir = tempdir().expect("tempdir");
        let report = control_verify(&ControlVerifyOptions {
            data_dir: dir.path().to_path_buf(),
            hosted_only: true,
            device_index: 0,
            batch_frames: 4,
        })
        .expect("verify");
        assert!(!report.ok);
        assert_eq!(report.error_code.as_deref(), Some("NOT_HOSTED"));
    }

    /// A corrupt `CONTROL.json` must fail the load rather than fall back to
    /// the default state (which would then "match" a default-state evidence
    /// replay).
    #[test]
    fn load_control_checkpoint_unparsable_file_errors() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("CONTROL.json");
        std::fs::write(&path, b"{ this is not control json").expect("write");
        assert!(load_control_checkpoint(&path).is_err());
    }

    // ── parse_control_evidence_jsonl ────────────────────────────────

    #[test]
    fn parse_control_evidence_jsonl_rejects_malformed_line() {
        assert!(parse_control_evidence_jsonl(b"{\"shardId\":1}\n").is_err());
        assert!(parse_control_evidence_jsonl(b"not json\n").is_err());
    }

    #[test]
    fn parse_control_evidence_jsonl_skips_blank_lines() {
        let line = ControlEvidenceJsonLineV1 {
            shard_id: 1,
            seq: 1,
            event_id: "e1".to_string(),
            event_type: "t".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:00Z".to_string(),
            header_hash: "aa".repeat(32),
            payload_hash: "bb".repeat(32),
            payload: serde_json::json!({}),
        };
        let mut bytes = control_evidence_jsonl(&[line]).expect("encode");
        bytes.extend_from_slice(b"\n\n");
        let parsed = parse_control_evidence_jsonl(&bytes).expect("parse");
        assert_eq!(parsed.len(), 1);
    }

    // ── verify_control_inputs_v1: reconcile failure ─────────────────

    /// When the replay cannot be anchored to `CONTROL.json`, the report must
    /// say `RECONCILE_FAILED` — not fall back to trusting the on-disk state.
    #[test]
    fn verify_control_inputs_reports_reconcile_failure() {
        let dir = tempdir().expect("tempdir");
        let control_path = dir.path().join("CONTROL.json");

        // CONTROL.json holds a state no evidence line anchors to.
        let mut current = LocalControlV1::default();
        current.updated_at_unix_ns = 4_242;
        current.valves.emergency_brake.enabled = true;
        let checkpoint_bytes = checkpoint_control_bytes_v1(&current);
        std::fs::write(&control_path, &checkpoint_bytes).expect("write");

        // ...and the only mutation starts from a non-default state.
        let mut other = LocalControlV1::default();
        other.updated_at_unix_ns = 1;
        let mut after = other.clone();
        after.updated_at_unix_ns = 2;
        let line = line_for_mutation(1, &other, &after);

        let bundle =
            verify_control_inputs_v1(dir.path(), &control_path, checkpoint_bytes, vec![line], false).expect("verify");
        assert!(!bundle.report.ok);
        assert_eq!(bundle.report.error_code.as_deref(), Some("RECONCILE_FAILED"));
        assert!(bundle.report.error_message.is_some());
        assert_eq!(bundle.report.mutation_events, 1);
        assert_eq!(bundle.report.evidence_events, 1);
        assert!(bundle.report.hosted);
    }

    /// Evidence lines whose payload does not deserialize into the declared
    /// event type must abort the verify, not be dropped from the replay.
    #[test]
    fn verify_control_inputs_rejects_undeserializable_mutation_payload() {
        let dir = tempdir().expect("tempdir");
        let control_path = dir.path().join("CONTROL.json");
        let checkpoint_bytes = default_checkpoint_bytes();
        std::fs::write(&control_path, &checkpoint_bytes).expect("write");

        let line = ControlEvidenceJsonLineV1 {
            shard_id: 1,
            seq: 1,
            event_id: "e1".to_string(),
            event_type: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:00Z".to_string(),
            header_hash: "aa".repeat(32),
            payload_hash: "bb".repeat(32),
            payload: serde_json::json!({"nope": true}),
        };
        assert!(verify_control_inputs_v1(dir.path(), &control_path, checkpoint_bytes, vec![line], false).is_err());
    }

    /// Evidence lines that are neither checkpoints nor mutations contribute to
    /// `evidence_events` but leave the replay with no anchor, so the report
    /// stays anchorless rather than claiming a clean replay.
    #[test]
    fn verify_control_inputs_ignores_unrelated_event_types() {
        let dir = tempdir().expect("tempdir");
        let control_path = dir.path().join("CONTROL.json");
        let checkpoint_bytes = default_checkpoint_bytes();
        std::fs::write(&control_path, &checkpoint_bytes).expect("write");

        let line = ControlEvidenceJsonLineV1 {
            shard_id: 1,
            seq: 1,
            event_id: "e1".to_string(),
            event_type: "corecrux.something.else.v1".to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:00Z".to_string(),
            header_hash: "aa".repeat(32),
            payload_hash: "bb".repeat(32),
            payload: serde_json::json!({}),
        };
        let bundle =
            verify_control_inputs_v1(dir.path(), &control_path, checkpoint_bytes, vec![line], false).expect("verify");
        assert_eq!(bundle.report.evidence_events, 1);
        assert_eq!(bundle.report.checkpoint_events, 0);
        assert_eq!(bundle.report.mutation_events, 0);
        assert!(bundle.report.anchor.is_none());
        assert!(bundle.report.ok);
    }

    // ── reconcile_control_from_evidence: anchor selection ───────────

    /// The mutation anchor wins when its seq is higher than the checkpoint's,
    /// so mutations recorded after the last checkpoint are not replayed twice.
    #[test]
    fn reconcile_control_prefers_mutation_anchor_when_newer() {
        let state = LocalControlV1::default();
        let digest = control_state_digest_v1(&state);
        let checkpoint_bytes = checkpoint_control_bytes_v1(&state);
        let checkpoint_hash = blake3::hash(&checkpoint_bytes).to_hex().to_string();

        let checkpoints = vec![ControlCheckpointRecord {
            seq: 2,
            payload: ControlCheckpointMaterializedV1 {
                schema: "corecrux.control.checkpoint_materialized.v1".to_string(),
                checkpoint_id: "cp-1".to_string(),
                materialized_at_unix_ms: 1,
                node: corecrux_types::EvidenceNodeContextV1 {
                    node_id: "n".to_string(),
                    build: build_info(),
                    http_listen_addr: None,
                    grpc_listen_addr: None,
                },
                control_state: digest.clone(),
                checkpoint_format: "json".to_string(),
                checkpoint_blake3: checkpoint_hash,
                checkpoint_size_bytes: checkpoint_bytes.len() as u64,
            },
        }];
        let mutations = vec![ControlMutationRecord {
            seq: 9,
            payload: ControlStateMutationV1 {
                schema: EVT_CONTROL_STATE_MUTATION_V1.to_string(),
                action_id: "a".to_string(),
                mutation_type: "set_valves".to_string(),
                applied_at_unix_ms: 1,
                actor: "t".to_string(),
                reason: "t".to_string(),
                auth: corecrux_types::EvidenceAuthContextV1 {
                    mode: "dev_scopes".to_string(),
                    subject: None,
                    tenant_binding: None,
                    scopes: Vec::new(),
                },
                request: corecrux_types::EvidenceRequestContextV1::default(),
                node: corecrux_types::EvidenceNodeContextV1 {
                    node_id: "n".to_string(),
                    build: build_info(),
                    http_listen_addr: None,
                    grpc_listen_addr: None,
                },
                control_before: digest.clone(),
                control_after: digest,
                valve_changes: Vec::new(),
                knowledge_authority_change: None,
                result: None,
            },
        }];

        let plan = reconcile_control_from_evidence(&state, &checkpoint_bytes, &checkpoints, &mutations)
            .expect("reconcile")
            .expect("plan");
        assert_eq!(plan.anchor, "mutation");
        assert_eq!(plan.anchor_seq, 9);
        assert_eq!(plan.applied_mutations, 0);
    }

    /// A checkpoint record whose recorded checkpoint size disagrees with the
    /// on-disk bytes is NOT a valid anchor, even though its state digest
    /// matches.
    #[test]
    fn reconcile_control_rejects_checkpoint_anchor_with_wrong_size() {
        let state = LocalControlV1::default();
        let digest = control_state_digest_v1(&state);
        let checkpoint_bytes = checkpoint_control_bytes_v1(&state);
        let checkpoint_hash = blake3::hash(&checkpoint_bytes).to_hex().to_string();

        let checkpoints = vec![ControlCheckpointRecord {
            seq: 4,
            payload: ControlCheckpointMaterializedV1 {
                schema: "corecrux.control.checkpoint_materialized.v1".to_string(),
                checkpoint_id: "cp-1".to_string(),
                materialized_at_unix_ms: 1,
                node: corecrux_types::EvidenceNodeContextV1 {
                    node_id: "n".to_string(),
                    build: build_info(),
                    http_listen_addr: None,
                    grpc_listen_addr: None,
                },
                control_state: digest,
                checkpoint_format: "json".to_string(),
                checkpoint_blake3: checkpoint_hash,
                checkpoint_size_bytes: checkpoint_bytes.len() as u64 + 1,
            },
        }];

        // No mutations at all -> no anchor of either kind -> hard error.
        let err = reconcile_control_from_evidence(&state, &checkpoint_bytes, &checkpoints, &[])
            .expect_err("size drift must not anchor");
        assert!(err.contains("no state mutation anchor"), "err={err}");
    }

    // ── hex helpers ─────────────────────────────────────────────────

    #[test]
    fn parse_hex32_rejects_non_hex_characters() {
        let input = format!("{}zz", "a".repeat(62));
        assert!(parse_hex32(&input).is_err());
    }

    #[test]
    fn parse_manifest_epoch_missing_file_errors() {
        let dir = tempdir().expect("tempdir");
        assert!(parse_manifest_epoch(&dir.path().join("nope")).is_err());
    }

    #[test]
    fn list_shards_missing_root_errors() {
        let dir = tempdir().expect("tempdir");
        assert!(list_shards(&dir.path().join("nope")).is_err());
    }

    // ── report struct plumbing ──────────────────────────────────────

    #[test]
    fn control_verify_report_round_trips_through_json() {
        let dir = control_trio_pack(true, false);
        let bytes = std::fs::read(dir.path().join("control_verify.json")).expect("read");
        let parsed: ControlVerifyReportV1 = serde_json::from_slice(&bytes).expect("parse");
        assert!(parsed.ok);
        assert!(parsed.error_code.is_none());
        assert!(parsed.shard_ids.is_empty());
    }

    #[test]
    fn evidence_verify_report_carries_missing_capabilities_through_verify() {
        let dir = tempdir().expect("tempdir");
        let mut manifest = manifest_with_producer(BTreeMap::new());
        manifest.missing_capabilities = vec!["decision_plane_events".to_string()];
        write_manifest(dir.path(), &manifest);
        let report = verify_pack(dir.path(), false).expect("verify");
        assert_eq!(report.missing_capabilities, vec!["decision_plane_events".to_string()]);
    }
}
