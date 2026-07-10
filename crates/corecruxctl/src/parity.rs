// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Parity-smoke driver — compares two daemons (or two segments) for byte-equivalent reads under a query set.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use corecrux_types::DRIFT_SOURCE_CHANGE;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct ParityLivingReportV1 {
    pub tenant_id: String,
    pub seed: String,
    pub sample_n: u32,
    pub engine_base: String,
    pub corecrux_base: String,
    pub artifacts: Vec<u32>,
    pub summary: ParitySummaryV1,
    pub mismatches: Vec<ParityMismatchV1>,
}

#[derive(Debug, Default, Serialize)]
pub struct ParitySummaryV1 {
    pub artifacts_checked: u32,
    pub fail: u32,
    pub warn: u32,
    pub info: u32,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParitySeverityV1 {
    Fail,
    Warn,
    Info,
}

#[derive(Debug, Serialize)]
pub struct ParityMismatchV1 {
    pub severity: ParitySeverityV1,
    pub artifact_id: u32,
    pub kind: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corecrux: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EngineSampleResp {
    #[allow(dead_code)]
    tenant_id: String,
    artifacts: Vec<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EngineStateResp {
    tenant_id: String,
    artifact_id: u32,
    present: bool,
    living_status: Option<String>,
    confidence: Option<f32>,
    last_validated_at: Option<String>,
    next_review_at: Option<String>,
    pressure_level: Option<i32>,
    trunk_tier: Option<i32>,
    counts: Option<EngineCounts>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct EngineCounts {
    relations_out: i32,
    relations_in: i32,
    dependents: i32,
}

#[derive(Debug, Serialize, Deserialize)]
struct EngineRelationsResp {
    relations: Vec<EngineRelationRow>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EngineRelationRow {
    src_artifact_id: u32,
    dst_artifact_id: u32,
    relation_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EngineDependentsResp {
    dependents: Vec<EngineDependentRow>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EngineDependentRow {
    dependent_type: String,
    dependent_id: String,
    last_seen_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EnginePressureResp {
    events: Vec<EnginePressureRow>,
}

#[derive(Debug, Serialize, Deserialize)]
struct EnginePressureRow {
    event_id: String,
    pressure_code: String,
    severity: i32,
    observed_at: String,
    acknowledged_at: Option<String>,
    resolved_at: Option<String>,
    receipt_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CoreCruxStateResp {
    tenant_id: String,
    artifact_id: u32,
    present: bool,
    living_status: Option<String>,
    confidence: Option<f32>,
    pressure_level: Option<u8>,
    trunk_tier: Option<u8>,
    counts: Option<EngineCounts>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CoreCruxRelationsResp {
    relations: Vec<CoreCruxRelationRow>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CoreCruxRelationRow {
    src_artifact_id: u32,
    dst_artifact_id: u32,
    relation_type: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CoreCruxDependentsResp {
    dependents: Vec<CoreCruxDependentRow>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CoreCruxDependentRow {
    dependent_type: String,
    dependent_id: String,
    last_seen_at_micros: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct CoreCruxPressureResp {
    events: Vec<CoreCruxPressureRow>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CoreCruxPressureRow {
    event_id: String,
    pressure_code_id: u16,
    severity: i32,
    observed_at_micros: i64,
    acknowledged_at_micros: i64,
    resolved_at_micros: i64,
    receipt_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParityPackOptions {
    pub out_dir: PathBuf,
    pub tenant_id: String,
    pub seed: String,
    pub sample_size: u32,
    pub window_hours: u32,
    pub projections: String,
    pub engine_base: String,
    pub engine_api_key: String,
    pub corecrux_base: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityPackManifestV1 {
    pub pack_type: String,
    pub generated_at: String,
    pub seed: String,
    pub sample_size: u32,
    pub window_hours: u32,
    pub corecrux_version: String,
    pub engine_version: String,
    pub projection_versions: BTreeMap<String, String>,
    pub kernel_versions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityPackSampleRecordV1 {
    pub sample_id: String,
    pub tenant_hash: String,
    pub object_key: String,
    pub stream_hash: u64,
    pub cursor_seq: u64,
    pub cursor_segment_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityPackMismatchExampleV1 {
    pub sample_id: String,
    pub projection_key: String,
    pub expected_hash: String,
    pub actual_hash: String,
    pub drift_class: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityPackReportV1 {
    pub ok: bool,
    pub checked: u32,
    pub mismatches: u32,
    #[serde(rename = "criticalFails")]
    pub critical_fails: u32,
    pub mismatch_examples: Vec<ParityPackMismatchExampleV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParityPackResultV1 {
    pub out_dir: String,
    pub manifest_path: String,
    pub samples_path: String,
    pub report_path: String,
    pub report: ParityPackReportV1,
}

pub fn parity_living_v1(
    tenant_id: &str,
    seed: &str,
    sample_n: u32,
    engine_base: &str,
    engine_api_key: &str,
    corecrux_base: &str,
) -> Result<ParityLivingReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let artifacts = fetch_engine_sample(engine_base, engine_api_key, tenant_id, seed, sample_n)?;

    let mut mismatches: Vec<ParityMismatchV1> = Vec::new();
    let mut summary = ParitySummaryV1::default();

    for &artifact_id in &artifacts {
        summary.artifacts_checked += 1;

        let eng_state: EngineStateResp = get_engine_json(
            engine_base,
            engine_api_key,
            &format!("/internal/living/artifacts/{artifact_id}/state?tenant_id={tenant_id}"),
        )?;
        let ccx_state: CoreCruxStateResp = get_corecrux_json(
            corecrux_base,
            &format!("/v1/admin/projections/artifacts/{artifact_id}/state?tenant_id={tenant_id}"),
        )?;

        if eng_state.present && !ccx_state.present {
            push_mismatch(
                &mut mismatches,
                &mut summary,
                ParitySeverityV1::Fail,
                artifact_id,
                "missing_state",
                "engine present but corecrux missing",
                Some(serde_json::to_value(&eng_state)?),
                Some(serde_json::to_value(&ccx_state)?),
            );
            continue;
        }

        if eng_state.present && ccx_state.present {
            if eng_state.living_status != ccx_state.living_status {
                push_mismatch(
                    &mut mismatches,
                    &mut summary,
                    ParitySeverityV1::Fail,
                    artifact_id,
                    "living_status",
                    "living_status mismatch",
                    Some(serde_json::to_value(&eng_state)?),
                    Some(serde_json::to_value(&ccx_state)?),
                );
            }

            if eng_state.trunk_tier.map(|v| v as i64) != ccx_state.trunk_tier.map(|v| v as i64) {
                push_mismatch(
                    &mut mismatches,
                    &mut summary,
                    ParitySeverityV1::Fail,
                    artifact_id,
                    "trunk_tier",
                    "trunk_tier mismatch",
                    Some(serde_json::to_value(&eng_state)?),
                    Some(serde_json::to_value(&ccx_state)?),
                );
            }

            if eng_state.pressure_level.map(|v| v as i64) != ccx_state.pressure_level.map(|v| v as i64) {
                push_mismatch(
                    &mut mismatches,
                    &mut summary,
                    ParitySeverityV1::Fail,
                    artifact_id,
                    "pressure_level",
                    "pressure_level mismatch",
                    Some(serde_json::to_value(&eng_state)?),
                    Some(serde_json::to_value(&ccx_state)?),
                );
            }

            if eng_state.counts != ccx_state.counts {
                push_mismatch(
                    &mut mismatches,
                    &mut summary,
                    ParitySeverityV1::Fail,
                    artifact_id,
                    "counts",
                    "counts mismatch",
                    Some(serde_json::to_value(&eng_state)?),
                    Some(serde_json::to_value(&ccx_state)?),
                );
            }

            if let (Some(ec), Some(cc)) = (eng_state.confidence, ccx_state.confidence) {
                let diff = (ec - cc).abs();
                if diff > 0.02 {
                    push_mismatch(
                        &mut mismatches,
                        &mut summary,
                        ParitySeverityV1::Warn,
                        artifact_id,
                        "confidence",
                        format!("confidence differs by {diff} (>0.02)"),
                        Some(serde_json::to_value(&eng_state)?),
                        Some(serde_json::to_value(&ccx_state)?),
                    );
                }
            }
        }

        // Relations (out)
        let eng_rel_out: EngineRelationsResp = get_engine_json(
            engine_base,
            engine_api_key,
            &format!("/internal/living/artifacts/{artifact_id}/relations?tenant_id={tenant_id}&direction=out&limit=200&offset=0"),
        )?;
        let ccx_rel_out: CoreCruxRelationsResp = get_corecrux_json(
            corecrux_base,
            &format!("/v1/admin/projections/artifacts/{artifact_id}/relations?tenant_id={tenant_id}&direction=out&limit=200&offset=0"),
        )?;
        compare_relation_keys(
            &mut mismatches,
            &mut summary,
            artifact_id,
            "relations_out",
            &eng_rel_out.relations,
            &ccx_rel_out.relations,
        )?;

        // Relations (in)
        let eng_rel_in: EngineRelationsResp = get_engine_json(
            engine_base,
            engine_api_key,
            &format!("/internal/living/artifacts/{artifact_id}/relations?tenant_id={tenant_id}&direction=in&limit=200&offset=0"),
        )?;
        let ccx_rel_in: CoreCruxRelationsResp = get_corecrux_json(
            corecrux_base,
            &format!("/v1/admin/projections/artifacts/{artifact_id}/relations?tenant_id={tenant_id}&direction=in&limit=200&offset=0"),
        )?;
        compare_relation_keys(
            &mut mismatches,
            &mut summary,
            artifact_id,
            "relations_in",
            &eng_rel_in.relations,
            &ccx_rel_in.relations,
        )?;

        // Dependents
        let eng_deps: EngineDependentsResp = get_engine_json(
            engine_base,
            engine_api_key,
            &format!("/internal/living/artifacts/{artifact_id}/dependents?tenant_id={tenant_id}&limit=200&offset=0"),
        )?;
        let ccx_deps: CoreCruxDependentsResp = get_corecrux_json(
            corecrux_base,
            &format!(
                "/v1/admin/projections/artifacts/{artifact_id}/dependents?tenant_id={tenant_id}&limit=200&offset=0"
            ),
        )?;
        compare_dependent_keys(
            &mut mismatches,
            &mut summary,
            artifact_id,
            &eng_deps.dependents,
            &ccx_deps.dependents,
        )?;

        // Pressure events
        let eng_pressure: EnginePressureResp = get_engine_json(
            engine_base,
            engine_api_key,
            &format!(
                "/internal/living/artifacts/{artifact_id}/pressure-events?tenant_id={tenant_id}&limit=200&offset=0"
            ),
        )?;
        let ccx_pressure: CoreCruxPressureResp = get_corecrux_json(
            corecrux_base,
            &format!("/v1/admin/projections/artifacts/{artifact_id}/pressure-events?tenant_id={tenant_id}&limit=200&offset=0"),
        )?;
        compare_pressure_counts(
            &mut mismatches,
            &mut summary,
            artifact_id,
            &eng_pressure.events,
            &ccx_pressure.events,
        )?;
    }

    Ok(ParityLivingReportV1 {
        tenant_id: tenant_id.to_string(),
        seed: seed.to_string(),
        sample_n,
        engine_base: engine_base.to_string(),
        corecrux_base: corecrux_base.to_string(),
        artifacts: artifacts.clone(),
        summary,
        mismatches,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CanonicalCountsV1 {
    relations_out: i32,
    relations_in: i32,
    dependents: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalRelationKeyV1 {
    src_artifact_id: u32,
    dst_artifact_id: u32,
    relation_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalDependentKeyV1 {
    dependent_type: String,
    dependent_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CanonicalArtifactProjectionStateV1 {
    artifact_id: u32,
    present: bool,
    living_status: Option<String>,
    pressure_level: Option<i64>,
    trunk_tier: Option<i64>,
    counts: Option<CanonicalCountsV1>,
    relations_out: Vec<CanonicalRelationKeyV1>,
    relations_in: Vec<CanonicalRelationKeyV1>,
    dependents: Vec<CanonicalDependentKeyV1>,
    pressure_open_count: u32,
}

fn deterministic_artifact_score(seed: &str, artifact_id: u32) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(seed.as_bytes());
    hasher.update(&artifact_id.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn select_artifact_sample(seed: &str, artifacts: &[u32], sample_size: u32) -> Vec<u32> {
    let mut unique = artifacts.to_vec();
    unique.sort_unstable();
    unique.dedup();
    unique.sort_by(|a, b| {
        deterministic_artifact_score(seed, *a)
            .cmp(&deterministic_artifact_score(seed, *b))
            .then_with(|| a.cmp(b))
    });
    unique.truncate(sample_size.max(1) as usize);
    unique
}

fn hash_hex_bytes(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn hash_hex_json<T: Serialize>(value: &T) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let bytes = serde_json::to_vec(value)?;
    Ok(hash_hex_bytes(&bytes))
}

fn hash_prefix(value: &str, prefix_len: usize) -> String {
    let digest = hash_hex_bytes(value.as_bytes());
    digest.chars().take(prefix_len).collect()
}

fn hash_u64(value: &str) -> u64 {
    let digest = blake3::hash(value.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

fn write_json_file<T: Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    std::fs::write(path, bytes)?;
    Ok(())
}

fn fetch_engine_canonical_artifact(
    engine_base: &str,
    api_key: &str,
    tenant_id: &str,
    artifact_id: u32,
) -> Result<CanonicalArtifactProjectionStateV1, Box<dyn std::error::Error + Send + Sync>> {
    let state: EngineStateResp = get_engine_json(
        engine_base,
        api_key,
        &format!("/internal/living/artifacts/{artifact_id}/state?tenant_id={tenant_id}"),
    )?;
    let rel_out: EngineRelationsResp = get_engine_json(
        engine_base,
        api_key,
        &format!(
            "/internal/living/artifacts/{artifact_id}/relations?tenant_id={tenant_id}&direction=out&limit=200&offset=0"
        ),
    )?;
    let rel_in: EngineRelationsResp = get_engine_json(
        engine_base,
        api_key,
        &format!(
            "/internal/living/artifacts/{artifact_id}/relations?tenant_id={tenant_id}&direction=in&limit=200&offset=0"
        ),
    )?;
    let deps: EngineDependentsResp = get_engine_json(
        engine_base,
        api_key,
        &format!("/internal/living/artifacts/{artifact_id}/dependents?tenant_id={tenant_id}&limit=200&offset=0"),
    )?;
    let pressure: EnginePressureResp = get_engine_json(
        engine_base,
        api_key,
        &format!("/internal/living/artifacts/{artifact_id}/pressure-events?tenant_id={tenant_id}&limit=200&offset=0"),
    )?;

    let mut relations_out: Vec<CanonicalRelationKeyV1> = rel_out
        .relations
        .into_iter()
        .map(|r| CanonicalRelationKeyV1 {
            src_artifact_id: r.src_artifact_id,
            dst_artifact_id: r.dst_artifact_id,
            relation_type: r.relation_type,
        })
        .collect();
    relations_out.sort();

    let mut relations_in: Vec<CanonicalRelationKeyV1> = rel_in
        .relations
        .into_iter()
        .map(|r| CanonicalRelationKeyV1 {
            src_artifact_id: r.src_artifact_id,
            dst_artifact_id: r.dst_artifact_id,
            relation_type: r.relation_type,
        })
        .collect();
    relations_in.sort();

    let mut dependents: Vec<CanonicalDependentKeyV1> = deps
        .dependents
        .into_iter()
        .map(|d| CanonicalDependentKeyV1 {
            dependent_type: d.dependent_type,
            dependent_id: d.dependent_id,
        })
        .collect();
    dependents.sort();

    let counts = state.counts.map(|c| CanonicalCountsV1 {
        relations_out: c.relations_out,
        relations_in: c.relations_in,
        dependents: c.dependents,
    });
    let pressure_open_count = pressure
        .events
        .into_iter()
        .filter(|row| row.resolved_at.is_none())
        .count() as u32;

    Ok(CanonicalArtifactProjectionStateV1 {
        artifact_id,
        present: state.present,
        living_status: state.living_status,
        pressure_level: state.pressure_level.map(i64::from),
        trunk_tier: state.trunk_tier.map(i64::from),
        counts,
        relations_out,
        relations_in,
        dependents,
        pressure_open_count,
    })
}

fn fetch_corecrux_canonical_artifact(
    corecrux_base: &str,
    tenant_id: &str,
    artifact_id: u32,
) -> Result<CanonicalArtifactProjectionStateV1, Box<dyn std::error::Error + Send + Sync>> {
    let state: CoreCruxStateResp = get_corecrux_json(
        corecrux_base,
        &format!("/v1/admin/projections/artifacts/{artifact_id}/state?tenant_id={tenant_id}"),
    )?;
    let rel_out: CoreCruxRelationsResp = get_corecrux_json(
        corecrux_base,
        &format!("/v1/admin/projections/artifacts/{artifact_id}/relations?tenant_id={tenant_id}&direction=out&limit=200&offset=0"),
    )?;
    let rel_in: CoreCruxRelationsResp = get_corecrux_json(
        corecrux_base,
        &format!("/v1/admin/projections/artifacts/{artifact_id}/relations?tenant_id={tenant_id}&direction=in&limit=200&offset=0"),
    )?;
    let deps: CoreCruxDependentsResp = get_corecrux_json(
        corecrux_base,
        &format!("/v1/admin/projections/artifacts/{artifact_id}/dependents?tenant_id={tenant_id}&limit=200&offset=0"),
    )?;
    let pressure: CoreCruxPressureResp = get_corecrux_json(
        corecrux_base,
        &format!(
            "/v1/admin/projections/artifacts/{artifact_id}/pressure-events?tenant_id={tenant_id}&limit=200&offset=0"
        ),
    )?;

    let mut relations_out: Vec<CanonicalRelationKeyV1> = rel_out
        .relations
        .into_iter()
        .map(|r| CanonicalRelationKeyV1 {
            src_artifact_id: r.src_artifact_id,
            dst_artifact_id: r.dst_artifact_id,
            relation_type: r.relation_type,
        })
        .collect();
    relations_out.sort();

    let mut relations_in: Vec<CanonicalRelationKeyV1> = rel_in
        .relations
        .into_iter()
        .map(|r| CanonicalRelationKeyV1 {
            src_artifact_id: r.src_artifact_id,
            dst_artifact_id: r.dst_artifact_id,
            relation_type: r.relation_type,
        })
        .collect();
    relations_in.sort();

    let mut dependents: Vec<CanonicalDependentKeyV1> = deps
        .dependents
        .into_iter()
        .map(|d| CanonicalDependentKeyV1 {
            dependent_type: d.dependent_type,
            dependent_id: d.dependent_id,
        })
        .collect();
    dependents.sort();

    let counts = state.counts.map(|c| CanonicalCountsV1 {
        relations_out: c.relations_out,
        relations_in: c.relations_in,
        dependents: c.dependents,
    });
    let pressure_open_count = pressure
        .events
        .into_iter()
        .filter(|row| row.resolved_at_micros == 0)
        .count() as u32;

    Ok(CanonicalArtifactProjectionStateV1 {
        artifact_id,
        present: state.present,
        living_status: state.living_status,
        pressure_level: state.pressure_level.map(i64::from),
        trunk_tier: state.trunk_tier.map(i64::from),
        counts,
        relations_out,
        relations_in,
        dependents,
        pressure_open_count,
    })
}

fn build_parity_pack_report(checked: u32, mut mismatches: Vec<ParityPackMismatchExampleV1>) -> ParityPackReportV1 {
    let mismatch_total = mismatches.len() as u32;
    if mismatches.len() > 50 {
        mismatches.truncate(50);
    }
    ParityPackReportV1 {
        ok: mismatch_total == 0,
        checked,
        mismatches: mismatch_total,
        critical_fails: mismatch_total,
        mismatch_examples: mismatches,
    }
}

pub fn generate_parity_pack(
    opts: &ParityPackOptions,
) -> Result<ParityPackResultV1, Box<dyn std::error::Error + Send + Sync>> {
    if opts.sample_size == 0 {
        return Err("--sample-size must be >= 1".into());
    }

    std::fs::create_dir_all(opts.out_dir.join("expected"))?;
    std::fs::create_dir_all(opts.out_dir.join("actual"))?;

    let candidate_n = opts.sample_size.saturating_mul(4).max(opts.sample_size).max(1);
    let candidates = fetch_engine_sample(
        &opts.engine_base,
        &opts.engine_api_key,
        &opts.tenant_id,
        &opts.seed,
        candidate_n,
    )?;
    let sampled_artifacts = select_artifact_sample(&opts.seed, &candidates, opts.sample_size);
    if sampled_artifacts.is_empty() {
        return Err("engine sample candidate set is empty".into());
    }

    let generated_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut projection_versions = BTreeMap::new();
    projection_versions.insert("artifact_living_state".to_string(), opts.projections.clone());
    let mut kernel_versions = BTreeMap::new();
    kernel_versions.insert("projection".to_string(), "unknown".to_string());

    let manifest = ParityPackManifestV1 {
        pack_type: "parity_pack_v1".to_string(),
        generated_at,
        seed: opts.seed.clone(),
        sample_size: sampled_artifacts.len() as u32,
        window_hours: opts.window_hours,
        corecrux_version: env!("CARGO_PKG_VERSION").to_string(),
        engine_version: "unknown".to_string(),
        projection_versions,
        kernel_versions,
    };

    let manifest_path = opts.out_dir.join("manifest.json");
    write_json_file(&manifest_path, &manifest)?;

    let samples_path = opts.out_dir.join("samples.jsonl");
    let mut samples_file = File::create(&samples_path)?;
    let tenant_hash = hash_prefix(&opts.tenant_id, 12);
    let mut mismatches = Vec::<ParityPackMismatchExampleV1>::new();

    for (idx, artifact_id) in sampled_artifacts.iter().copied().enumerate() {
        let sample_id = format!("s{:06}", idx + 1);
        let object_key = format!("artifact:{artifact_id}");
        let expected =
            fetch_engine_canonical_artifact(&opts.engine_base, &opts.engine_api_key, &opts.tenant_id, artifact_id)?;
        let actual = fetch_corecrux_canonical_artifact(&opts.corecrux_base, &opts.tenant_id, artifact_id)?;

        let expected_hash = hash_hex_json(&expected)?;
        let actual_hash = hash_hex_json(&actual)?;

        let expected_path = opts.out_dir.join("expected").join(format!("{sample_id}.json"));
        let actual_path = opts.out_dir.join("actual").join(format!("{sample_id}.json"));
        write_json_file(&expected_path, &expected)?;
        write_json_file(&actual_path, &actual)?;

        let sample_record = ParityPackSampleRecordV1 {
            sample_id: sample_id.clone(),
            tenant_hash: tenant_hash.clone(),
            object_key: object_key.clone(),
            stream_hash: hash_u64(&format!("{}\u{0}{object_key}", opts.tenant_id)),
            cursor_seq: 0,
            cursor_segment_id: 0,
        };
        writeln!(samples_file, "{}", serde_json::to_string(&sample_record)?)?;

        if expected_hash != actual_hash {
            mismatches.push(ParityPackMismatchExampleV1 {
                sample_id,
                projection_key: "artifact_living_state".to_string(),
                expected_hash,
                actual_hash,
                drift_class: DRIFT_SOURCE_CHANGE.to_string(),
                detail: format!("hash mismatch for {object_key}"),
            });
        }
    }
    samples_file.flush()?;

    let report = build_parity_pack_report(sampled_artifacts.len() as u32, mismatches);
    let report_path = opts.out_dir.join("report.json");
    write_json_file(&report_path, &report)?;

    // Compatibility alias for migration stage gate scripts.
    let gate_report_path = opts.out_dir.join("parity-pack-report.json");
    write_json_file(&gate_report_path, &report)?;

    Ok(ParityPackResultV1 {
        out_dir: opts.out_dir.display().to_string(),
        manifest_path: manifest_path.display().to_string(),
        samples_path: samples_path.display().to_string(),
        report_path: report_path.display().to_string(),
        report,
    })
}

fn fetch_engine_sample(
    engine_base: &str,
    api_key: &str,
    tenant_id: &str,
    seed: &str,
    n: u32,
) -> Result<Vec<u32>, Box<dyn std::error::Error + Send + Sync>> {
    let path = format!("/internal/living/sample?tenant_id={tenant_id}&seed={seed}&n={n}");
    let resp: EngineSampleResp = get_engine_json(engine_base, api_key, &path)?;
    Ok(resp.artifacts)
}

fn compare_relation_keys(
    mismatches: &mut Vec<ParityMismatchV1>,
    summary: &mut ParitySummaryV1,
    artifact_id: u32,
    label: &str,
    engine: &[EngineRelationRow],
    corecrux: &[CoreCruxRelationRow],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut e_keys: Vec<(u32, u32, String)> = engine
        .iter()
        .map(|r| (r.src_artifact_id, r.dst_artifact_id, r.relation_type.clone()))
        .collect();
    e_keys.sort();
    let mut c_keys: Vec<(u32, u32, String)> = corecrux
        .iter()
        .map(|r| (r.src_artifact_id, r.dst_artifact_id, r.relation_type.clone()))
        .collect();
    c_keys.sort();
    if e_keys != c_keys {
        push_mismatch(
            mismatches,
            summary,
            ParitySeverityV1::Fail,
            artifact_id,
            label,
            "relation key sets differ",
            Some(serde_json::to_value(engine)?),
            Some(serde_json::to_value(corecrux)?),
        );
    }
    Ok(())
}

fn compare_dependent_keys(
    mismatches: &mut Vec<ParityMismatchV1>,
    summary: &mut ParitySummaryV1,
    artifact_id: u32,
    engine: &[EngineDependentRow],
    corecrux: &[CoreCruxDependentRow],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut e_keys: Vec<(String, String)> = engine
        .iter()
        .map(|r| (r.dependent_type.clone(), r.dependent_id.clone()))
        .collect();
    e_keys.sort();
    let mut c_keys: Vec<(String, String)> = corecrux
        .iter()
        .map(|r| (r.dependent_type.clone(), r.dependent_id.clone()))
        .collect();
    c_keys.sort();
    if e_keys != c_keys {
        push_mismatch(
            mismatches,
            summary,
            ParitySeverityV1::Fail,
            artifact_id,
            "dependents",
            "dependent key sets differ",
            Some(serde_json::to_value(engine)?),
            Some(serde_json::to_value(corecrux)?),
        );
    }

    // last_seen_at comparison (stable) on intersection.
    let mut eng_last: BTreeMap<(String, String), i64> = BTreeMap::new();
    for r in engine {
        if let Some(ms) = parse_rfc3339_to_micros(&r.last_seen_at) {
            eng_last.insert((r.dependent_type.clone(), r.dependent_id.clone()), ms);
        }
    }
    let mut ccx_last: BTreeMap<(String, String), i64> = BTreeMap::new();
    for r in corecrux {
        ccx_last.insert(
            (r.dependent_type.clone(), r.dependent_id.clone()),
            r.last_seen_at_micros,
        );
    }

    let mut diffs: Vec<(String, String)> = Vec::new();
    for k in eng_last.keys() {
        if let (Some(e), Some(c)) = (eng_last.get(k), ccx_last.get(k)) {
            if e != c {
                diffs.push((k.0.clone(), k.1.clone()));
            }
        }
    }
    if !diffs.is_empty() {
        push_mismatch(
            mismatches,
            summary,
            ParitySeverityV1::Warn,
            artifact_id,
            "dependents_last_seen_at",
            format!("last_seen_at differs for {} edges", diffs.len()),
            None,
            None,
        );
    }
    Ok(())
}

fn compare_pressure_counts(
    mismatches: &mut Vec<ParityMismatchV1>,
    summary: &mut ParitySummaryV1,
    artifact_id: u32,
    engine: &[EnginePressureRow],
    corecrux: &[CoreCruxPressureRow],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let e_open = engine.iter().filter(|r| r.resolved_at.is_none()).count();
    let c_open = corecrux.iter().filter(|r| r.resolved_at_micros == 0).count();
    if e_open != c_open {
        push_mismatch(
            mismatches,
            summary,
            ParitySeverityV1::Fail,
            artifact_id,
            "pressure_open_count",
            format!("open pressure event count mismatch: engine={e_open} corecrux={c_open}"),
            Some(serde_json::to_value(engine)?),
            Some(serde_json::to_value(corecrux)?),
        );
    }
    Ok(())
}

fn parse_rfc3339_to_micros(input: &str) -> Option<i64> {
    let dt: DateTime<Utc> = DateTime::parse_from_rfc3339(input)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))?;
    Some(dt.timestamp_micros())
}

#[allow(clippy::too_many_arguments)]
fn push_mismatch(
    mismatches: &mut Vec<ParityMismatchV1>,
    summary: &mut ParitySummaryV1,
    severity: ParitySeverityV1,
    artifact_id: u32,
    kind: &str,
    message: impl Into<String>,
    engine: Option<serde_json::Value>,
    corecrux: Option<serde_json::Value>,
) {
    match severity {
        ParitySeverityV1::Fail => summary.fail += 1,
        ParitySeverityV1::Warn => summary.warn += 1,
        ParitySeverityV1::Info => summary.info += 1,
    }
    mismatches.push(ParityMismatchV1 {
        severity,
        artifact_id,
        kind: kind.to_string(),
        message: message.into(),
        engine,
        corecrux,
    });
}

fn get_engine_json<T: for<'de> Deserialize<'de>>(
    engine_base: &str,
    api_key: &str,
    path: &str,
) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("{}{}", engine_base.trim_end_matches('/'), path);
    let mut resp = ureq::get(&url)
        .header("x-api-key", api_key)
        .call()
        .map_err(|e| format!("engine GET {url} failed: {e}"))?;
    Ok(resp.body_mut().read_json()?)
}

fn get_corecrux_json<T: for<'de> Deserialize<'de>>(
    corecrux_base: &str,
    path: &str,
) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("{}{}", corecrux_base.trim_end_matches('/'), path);
    let mut resp = ureq::get(&url)
        .call()
        .map_err(|e| format!("corecrux GET {url} failed: {e}"))?;
    Ok(resp.body_mut().read_json()?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{
        build_parity_pack_report, deterministic_artifact_score, hash_hex_bytes, hash_hex_json, hash_prefix, hash_u64,
        parse_rfc3339_to_micros, push_mismatch, select_artifact_sample, ParityPackMismatchExampleV1, ParitySeverityV1,
        ParitySummaryV1, DRIFT_SOURCE_CHANGE,
    };

    #[test]
    fn deterministic_artifact_score_is_stable() {
        let s1 = deterministic_artifact_score("seed", 42);
        let s2 = deterministic_artifact_score("seed", 42);
        assert_eq!(s1, s2);
        let s3 = deterministic_artifact_score("seed", 43);
        assert_ne!(s1, s3);
        let s4 = deterministic_artifact_score("other", 42);
        assert_ne!(s1, s4);
    }

    #[test]
    fn select_artifact_sample_deduplicates() {
        let artifacts = vec![5, 5, 5, 5, 5];
        let sample = select_artifact_sample("s", &artifacts, 10);
        assert_eq!(sample.len(), 1);
        assert_eq!(sample[0], 5);
    }

    #[test]
    fn select_artifact_sample_truncates_to_sample_size() {
        let artifacts = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let sample = select_artifact_sample("s", &artifacts, 3);
        assert_eq!(sample.len(), 3);
    }

    #[test]
    fn hash_hex_bytes_is_deterministic() {
        let h1 = hash_hex_bytes(b"test");
        let h2 = hash_hex_bytes(b"test");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        let h3 = hash_hex_bytes(b"other");
        assert_ne!(h1, h3);
    }

    #[test]
    fn hash_hex_json_serializes_then_hashes() {
        let v1 = serde_json::json!({"a": 1});
        let v2 = serde_json::json!({"a": 1});
        let h1 = hash_hex_json(&v1).unwrap();
        let h2 = hash_hex_json(&v2).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash_prefix_returns_requested_length() {
        let p = hash_prefix("test", 12);
        assert_eq!(p.len(), 12);
        // Deterministic.
        assert_eq!(p, hash_prefix("test", 12));
    }

    #[test]
    fn hash_u64_is_deterministic() {
        let a = hash_u64("test");
        let b = hash_u64("test");
        assert_eq!(a, b);
        let c = hash_u64("other");
        assert_ne!(a, c);
    }

    #[test]
    fn parse_rfc3339_to_micros_valid() {
        let result = parse_rfc3339_to_micros("2026-01-01T00:00:00Z");
        assert!(result.is_some());
        assert!(result.unwrap() > 0);
    }

    #[test]
    fn parse_rfc3339_to_micros_invalid() {
        assert!(parse_rfc3339_to_micros("not-a-date").is_none());
        assert!(parse_rfc3339_to_micros("").is_none());
    }

    #[test]
    fn push_mismatch_increments_severity_counters() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        push_mismatch(
            &mut mismatches,
            &mut summary,
            ParitySeverityV1::Fail,
            1,
            "test",
            "fail msg",
            None,
            None,
        );
        push_mismatch(
            &mut mismatches,
            &mut summary,
            ParitySeverityV1::Warn,
            2,
            "test",
            "warn msg",
            None,
            None,
        );
        push_mismatch(
            &mut mismatches,
            &mut summary,
            ParitySeverityV1::Info,
            3,
            "test",
            "info msg",
            None,
            None,
        );
        assert_eq!(summary.fail, 1);
        assert_eq!(summary.warn, 1);
        assert_eq!(summary.info, 1);
        assert_eq!(mismatches.len(), 3);
        assert_eq!(mismatches[0].artifact_id, 1);
    }

    #[test]
    fn build_parity_pack_report_ok_when_no_mismatches() {
        let report = build_parity_pack_report(5, Vec::new());
        assert!(report.ok);
        assert_eq!(report.checked, 5);
        assert_eq!(report.mismatches, 0);
        assert_eq!(report.critical_fails, 0);
    }

    #[test]
    fn build_parity_pack_report_truncates_at_50() {
        let mismatches: Vec<ParityPackMismatchExampleV1> = (0..100)
            .map(|i| ParityPackMismatchExampleV1 {
                sample_id: format!("s{i:06}"),
                projection_key: "artifact_living_state".to_string(),
                expected_hash: "a".to_string(),
                actual_hash: "b".to_string(),
                drift_class: DRIFT_SOURCE_CHANGE.to_string(),
                detail: "mismatch".to_string(),
            })
            .collect();
        let report = build_parity_pack_report(100, mismatches);
        assert!(!report.ok);
        assert_eq!(report.mismatches, 100);
        assert_eq!(report.mismatch_examples.len(), 50);
    }

    #[test]
    fn parity_summary_default_is_zeroed() {
        let s = ParitySummaryV1::default();
        assert_eq!(s.artifacts_checked, 0);
        assert_eq!(s.fail, 0);
        assert_eq!(s.warn, 0);
        assert_eq!(s.info, 0);
    }

    #[test]
    fn deterministic_artifact_sampling_is_stable() {
        let artifacts = vec![9, 3, 11, 3, 42, 7, 42, 1];
        let first = select_artifact_sample("seed-a", &artifacts, 4);
        let second = select_artifact_sample("seed-a", &artifacts, 4);
        let third = select_artifact_sample("seed-b", &artifacts, 4);

        assert_eq!(first, second);
        assert_eq!(first.len(), 4);
        assert!(first.iter().all(|id| artifacts.contains(id)));
        assert_ne!(first, third);
    }

    #[test]
    fn parity_pack_report_counts_critical_mismatches() {
        let report = build_parity_pack_report(
            2,
            vec![ParityPackMismatchExampleV1 {
                sample_id: "s000001".to_string(),
                projection_key: "artifact_living_state".to_string(),
                expected_hash: "aaa".to_string(),
                actual_hash: "bbb".to_string(),
                drift_class: DRIFT_SOURCE_CHANGE.to_string(),
                detail: "hash mismatch".to_string(),
            }],
        );

        assert!(!report.ok);
        assert_eq!(report.checked, 2);
        assert_eq!(report.mismatches, 1);
        assert_eq!(report.critical_fails, 1);
        assert_eq!(report.mismatch_examples.len(), 1);
    }

    // ── compare_relation_keys ───────────────────────────────────────

    use super::{
        compare_dependent_keys, compare_pressure_counts, compare_relation_keys, write_json_file,
        CanonicalArtifactProjectionStateV1, CanonicalCountsV1, CanonicalDependentKeyV1, CanonicalRelationKeyV1,
        CoreCruxDependentRow, CoreCruxPressureRow, CoreCruxRelationRow, EngineDependentRow, EnginePressureRow,
        EngineRelationRow, ParityLivingReportV1, ParityMismatchV1, ParityPackManifestV1, ParityPackReportV1,
        ParityPackResultV1, ParityPackSampleRecordV1,
    };

    #[test]
    fn compare_relation_keys_matching_sets_no_mismatch() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        let engine = vec![EngineRelationRow {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: "cites".to_string(),
        }];
        let corecrux = vec![CoreCruxRelationRow {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: "cites".to_string(),
        }];
        compare_relation_keys(&mut mismatches, &mut summary, 100, "relations_out", &engine, &corecrux).unwrap();
        assert!(mismatches.is_empty());
        assert_eq!(summary.fail, 0);
    }

    #[test]
    fn compare_relation_keys_different_sets_produces_fail() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        let engine = vec![EngineRelationRow {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: "cites".to_string(),
        }];
        let corecrux = vec![CoreCruxRelationRow {
            src_artifact_id: 1,
            dst_artifact_id: 3,
            relation_type: "cites".to_string(),
        }];
        compare_relation_keys(&mut mismatches, &mut summary, 100, "relations_out", &engine, &corecrux).unwrap();
        assert_eq!(mismatches.len(), 1);
        assert_eq!(summary.fail, 1);
        assert_eq!(mismatches[0].kind, "relations_out");
    }

    #[test]
    fn compare_relation_keys_empty_sets_no_mismatch() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        compare_relation_keys(&mut mismatches, &mut summary, 1, "relations_in", &[], &[]).unwrap();
        assert!(mismatches.is_empty());
    }

    // ── compare_dependent_keys ──────────────────────────────────────

    #[test]
    fn compare_dependent_keys_matching_no_mismatch() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        let engine = vec![EngineDependentRow {
            dependent_type: "query".to_string(),
            dependent_id: "q1".to_string(),
            last_seen_at: "2026-01-01T00:00:00Z".to_string(),
        }];
        let corecrux = vec![CoreCruxDependentRow {
            dependent_type: "query".to_string(),
            dependent_id: "q1".to_string(),
            last_seen_at_micros: 1767225600000000, // 2026-01-01T00:00:00Z in micros
        }];
        compare_dependent_keys(&mut mismatches, &mut summary, 1, &engine, &corecrux).unwrap();
        assert_eq!(summary.fail, 0);
    }

    #[test]
    fn compare_dependent_keys_different_sets_produces_fail() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        let engine = vec![EngineDependentRow {
            dependent_type: "query".to_string(),
            dependent_id: "q1".to_string(),
            last_seen_at: "2026-01-01T00:00:00Z".to_string(),
        }];
        let corecrux: Vec<CoreCruxDependentRow> = Vec::new();
        compare_dependent_keys(&mut mismatches, &mut summary, 1, &engine, &corecrux).unwrap();
        assert_eq!(summary.fail, 1);
        assert_eq!(mismatches[0].kind, "dependents");
    }

    #[test]
    fn compare_dependent_keys_warns_on_last_seen_at_drift() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        let engine = vec![EngineDependentRow {
            dependent_type: "query".to_string(),
            dependent_id: "q1".to_string(),
            last_seen_at: "2026-01-01T00:00:00Z".to_string(),
        }];
        let corecrux = vec![CoreCruxDependentRow {
            dependent_type: "query".to_string(),
            dependent_id: "q1".to_string(),
            last_seen_at_micros: 9999, // different from engine
        }];
        compare_dependent_keys(&mut mismatches, &mut summary, 1, &engine, &corecrux).unwrap();
        // Key sets match, but last_seen_at differs => warn
        assert_eq!(summary.fail, 0);
        assert_eq!(summary.warn, 1);
        assert_eq!(mismatches[0].kind, "dependents_last_seen_at");
    }

    // ── compare_pressure_counts ─────────────────────────────────────

    #[test]
    fn compare_pressure_counts_matching_no_mismatch() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        let engine = vec![EnginePressureRow {
            event_id: "e1".to_string(),
            pressure_code: "high".to_string(),
            severity: 1,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
            acknowledged_at: None,
            resolved_at: None,
            receipt_id: None,
        }];
        let corecrux = vec![CoreCruxPressureRow {
            event_id: "e1".to_string(),
            pressure_code_id: 1,
            severity: 1,
            observed_at_micros: 0,
            acknowledged_at_micros: 0,
            resolved_at_micros: 0, // 0 means unresolved in corecrux
            receipt_id: None,
        }];
        compare_pressure_counts(&mut mismatches, &mut summary, 1, &engine, &corecrux).unwrap();
        // Both have 1 open event
        assert_eq!(summary.fail, 0);
    }

    #[test]
    fn compare_pressure_counts_mismatch_produces_fail() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        // Engine: 1 open event
        let engine = vec![EnginePressureRow {
            event_id: "e1".to_string(),
            pressure_code: "high".to_string(),
            severity: 1,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
            acknowledged_at: None,
            resolved_at: None,
            receipt_id: None,
        }];
        // CoreCrux: 0 open events (resolved_at_micros != 0)
        let corecrux = vec![CoreCruxPressureRow {
            event_id: "e1".to_string(),
            pressure_code_id: 1,
            severity: 1,
            observed_at_micros: 0,
            acknowledged_at_micros: 0,
            resolved_at_micros: 12345,
            receipt_id: None,
        }];
        compare_pressure_counts(&mut mismatches, &mut summary, 1, &engine, &corecrux).unwrap();
        assert_eq!(summary.fail, 1);
        assert_eq!(mismatches[0].kind, "pressure_open_count");
    }

    // ── write_json_file ─────────────────────────────────────────────

    #[test]
    fn write_json_file_creates_parent_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a").join("b").join("c.json");
        write_json_file(&nested, &serde_json::json!({"ok": true})).unwrap();
        let read: serde_json::Value = serde_json::from_slice(&std::fs::read(&nested).unwrap()).unwrap();
        assert_eq!(read["ok"], true);
    }

    // ── Serde round-trips for data structures ───────────────────────

    #[test]
    fn parity_pack_manifest_v1_serializes() {
        let manifest = ParityPackManifestV1 {
            pack_type: "parity_pack_v1".to_string(),
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            seed: "42".to_string(),
            sample_size: 10,
            window_hours: 24,
            corecrux_version: "0.1.0".to_string(),
            engine_version: "unknown".to_string(),
            projection_versions: std::collections::BTreeMap::new(),
            kernel_versions: std::collections::BTreeMap::new(),
        };
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(json.contains("parity_pack_v1"));
        let deser: ParityPackManifestV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.seed, "42");
        assert_eq!(deser.sample_size, 10);
    }

    #[test]
    fn parity_pack_sample_record_v1_round_trips() {
        let record = ParityPackSampleRecordV1 {
            sample_id: "s000001".to_string(),
            tenant_hash: "abc123".to_string(),
            object_key: "artifact:42".to_string(),
            stream_hash: 12345,
            cursor_seq: 0,
            cursor_segment_id: 0,
        };
        let json = serde_json::to_string(&record).unwrap();
        let deser: ParityPackSampleRecordV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.sample_id, "s000001");
        assert_eq!(deser.stream_hash, 12345);
    }

    #[test]
    fn parity_pack_result_v1_serializes() {
        let result = ParityPackResultV1 {
            out_dir: "/tmp/out".to_string(),
            manifest_path: "/tmp/out/manifest.json".to_string(),
            samples_path: "/tmp/out/samples.jsonl".to_string(),
            report_path: "/tmp/out/report.json".to_string(),
            report: ParityPackReportV1 {
                ok: true,
                checked: 5,
                mismatches: 0,
                critical_fails: 0,
                mismatch_examples: Vec::new(),
            },
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"ok\":true"));
        let deser: ParityPackResultV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.report.checked, 5);
    }

    #[test]
    fn parity_living_report_v1_serializes() {
        let report = ParityLivingReportV1 {
            tenant_id: "t1".to_string(),
            seed: "0".to_string(),
            sample_n: 5,
            engine_base: "http://localhost:3000".to_string(),
            corecrux_base: "http://localhost:4006".to_string(),
            artifacts: vec![1, 2, 3],
            summary: ParitySummaryV1 {
                artifacts_checked: 3,
                fail: 1,
                warn: 0,
                info: 0,
            },
            mismatches: vec![ParityMismatchV1 {
                severity: ParitySeverityV1::Fail,
                artifact_id: 1,
                kind: "living_status".to_string(),
                message: "mismatch".to_string(),
                engine: None,
                corecrux: None,
            }],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"tenant_id\":\"t1\""));
        assert!(json.contains("\"artifacts_checked\":3"));
    }

    #[test]
    fn parity_mismatch_v1_omits_none_fields() {
        let m = ParityMismatchV1 {
            severity: ParitySeverityV1::Info,
            artifact_id: 42,
            kind: "test".to_string(),
            message: "msg".to_string(),
            engine: None,
            corecrux: None,
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("engine"));
        assert!(!json.contains("corecrux"));
    }

    #[test]
    fn canonical_artifact_projection_state_v1_equality() {
        let state = CanonicalArtifactProjectionStateV1 {
            artifact_id: 42,
            present: true,
            living_status: Some("active".to_string()),
            pressure_level: Some(1),
            trunk_tier: Some(2),
            counts: Some(CanonicalCountsV1 {
                relations_out: 3,
                relations_in: 1,
                dependents: 2,
            }),
            relations_out: vec![CanonicalRelationKeyV1 {
                src_artifact_id: 42,
                dst_artifact_id: 43,
                relation_type: "cites".to_string(),
            }],
            relations_in: Vec::new(),
            dependents: vec![CanonicalDependentKeyV1 {
                dependent_type: "query".to_string(),
                dependent_id: "q1".to_string(),
            }],
            pressure_open_count: 1,
        };
        let json = serde_json::to_string(&state).unwrap();
        let deser: CanonicalArtifactProjectionStateV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deser);
    }

    #[test]
    fn select_artifact_sample_handles_single_element() {
        let sample = select_artifact_sample("s", &[42], 10);
        assert_eq!(sample, vec![42]);
    }

    #[test]
    fn select_artifact_sample_handles_empty_input() {
        let sample = select_artifact_sample("s", &[], 10);
        assert!(sample.is_empty());
    }

    #[test]
    fn parse_rfc3339_to_micros_with_offset() {
        let result = parse_rfc3339_to_micros("2026-01-01T01:00:00+01:00");
        assert!(result.is_some());
        // 2026-01-01T00:00:00Z in micros
        let expected = parse_rfc3339_to_micros("2026-01-01T00:00:00Z").unwrap();
        assert_eq!(result.unwrap(), expected);
    }

    #[test]
    fn hash_u64_different_inputs_different_results() {
        let a = hash_u64("alpha");
        let b = hash_u64("beta");
        let c = hash_u64("gamma");
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn hash_prefix_shorter_than_digest() {
        let short = hash_prefix("test", 4);
        assert_eq!(short.len(), 4);
        let long = hash_prefix("test", 32);
        assert_eq!(long.len(), 32);
        assert!(long.starts_with(&short));
    }

    // ── select_artifact_sample with sample_size=0 ─────────────────

    #[test]
    fn select_artifact_sample_zero_sample_size_uses_one() {
        // sample_size.max(1) means 0 becomes 1
        let sample = select_artifact_sample("s", &[10, 20, 30], 0);
        assert_eq!(sample.len(), 1);
    }

    // ── compare_pressure_counts both empty ────────────────────────

    #[test]
    fn compare_pressure_counts_both_empty_no_mismatch() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        compare_pressure_counts(&mut mismatches, &mut summary, 1, &[], &[]).unwrap();
        assert_eq!(summary.fail, 0);
        assert!(mismatches.is_empty());
    }

    // ── compare_pressure_counts both resolved ─────────────────────

    #[test]
    fn compare_pressure_counts_both_resolved_no_mismatch() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        let engine = vec![EnginePressureRow {
            event_id: "e1".to_string(),
            pressure_code: "high".to_string(),
            severity: 1,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
            acknowledged_at: None,
            resolved_at: Some("2026-01-02T00:00:00Z".to_string()),
            receipt_id: None,
        }];
        let corecrux = vec![CoreCruxPressureRow {
            event_id: "e1".to_string(),
            pressure_code_id: 1,
            severity: 1,
            observed_at_micros: 0,
            acknowledged_at_micros: 0,
            resolved_at_micros: 12345, // non-zero = resolved
            receipt_id: None,
        }];
        compare_pressure_counts(&mut mismatches, &mut summary, 1, &engine, &corecrux).unwrap();
        // Both resolved → 0 open each → no mismatch
        assert_eq!(summary.fail, 0);
    }

    // ── compare_dependent_keys both empty ─────────────────────────

    #[test]
    fn compare_dependent_keys_both_empty_no_mismatch() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        compare_dependent_keys(&mut mismatches, &mut summary, 1, &[], &[]).unwrap();
        assert_eq!(summary.fail, 0);
        assert_eq!(summary.warn, 0);
        assert!(mismatches.is_empty());
    }

    // ── compare_relation_keys order-independent ───────────────────

    #[test]
    fn compare_relation_keys_order_independent() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        let engine = vec![
            EngineRelationRow {
                src_artifact_id: 1,
                dst_artifact_id: 2,
                relation_type: "cites".to_string(),
            },
            EngineRelationRow {
                src_artifact_id: 3,
                dst_artifact_id: 4,
                relation_type: "references".to_string(),
            },
        ];
        // Reversed order in corecrux
        let corecrux = vec![
            CoreCruxRelationRow {
                src_artifact_id: 3,
                dst_artifact_id: 4,
                relation_type: "references".to_string(),
            },
            CoreCruxRelationRow {
                src_artifact_id: 1,
                dst_artifact_id: 2,
                relation_type: "cites".to_string(),
            },
        ];
        compare_relation_keys(&mut mismatches, &mut summary, 100, "relations_out", &engine, &corecrux).unwrap();
        // Same set, different order → should be no mismatch
        assert!(mismatches.is_empty());
        assert_eq!(summary.fail, 0);
    }

    // ── hash_hex_json edge cases ──────────────────────────────────

    #[test]
    fn hash_hex_json_array_input() {
        let arr = serde_json::json!([1, 2, 3]);
        let h = hash_hex_json(&arr).unwrap();
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn hash_hex_json_null_input() {
        let null = serde_json::json!(null);
        let h = hash_hex_json(&null).unwrap();
        assert_eq!(h.len(), 64);
    }

    // ── build_parity_pack_report boundary: exactly 50 ─────────────

    #[test]
    fn build_parity_pack_report_exactly_50_no_truncation() {
        let mismatches: Vec<ParityPackMismatchExampleV1> = (0..50)
            .map(|i| ParityPackMismatchExampleV1 {
                sample_id: format!("s{i:06}"),
                projection_key: "artifact_living_state".to_string(),
                expected_hash: "a".to_string(),
                actual_hash: "b".to_string(),
                drift_class: DRIFT_SOURCE_CHANGE.to_string(),
                detail: "mismatch".to_string(),
            })
            .collect();
        let report = build_parity_pack_report(50, mismatches);
        assert!(!report.ok);
        assert_eq!(report.mismatches, 50);
        assert_eq!(report.mismatch_examples.len(), 50);
    }

    #[test]
    fn build_parity_pack_report_51_truncates() {
        let mismatches: Vec<ParityPackMismatchExampleV1> = (0..51)
            .map(|i| ParityPackMismatchExampleV1 {
                sample_id: format!("s{i:06}"),
                projection_key: "artifact_living_state".to_string(),
                expected_hash: "a".to_string(),
                actual_hash: "b".to_string(),
                drift_class: DRIFT_SOURCE_CHANGE.to_string(),
                detail: "mismatch".to_string(),
            })
            .collect();
        let report = build_parity_pack_report(51, mismatches);
        assert_eq!(report.mismatches, 51);
        assert_eq!(report.mismatch_examples.len(), 50);
    }

    // ── ParitySeverityV1 serialization ────────────────────────────

    #[test]
    fn parity_severity_v1_serializes_to_snake_case() {
        let fail = serde_json::to_string(&ParitySeverityV1::Fail).unwrap();
        assert_eq!(fail, "\"fail\"");
        let warn = serde_json::to_string(&ParitySeverityV1::Warn).unwrap();
        assert_eq!(warn, "\"warn\"");
        let info = serde_json::to_string(&ParitySeverityV1::Info).unwrap();
        assert_eq!(info, "\"info\"");
    }

    // ── hash_hex_bytes empty input ────────────────────────────────

    #[test]
    fn hash_hex_bytes_empty_input() {
        let h = hash_hex_bytes(b"");
        assert_eq!(h.len(), 64);
        // blake3 of empty is deterministic
        assert_eq!(h, hash_hex_bytes(b""));
    }

    // ── push_mismatch with values ─────────────────────────────────

    #[test]
    fn push_mismatch_stores_engine_and_corecrux_values() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        let engine_val = serde_json::json!({"status": "active"});
        let corecrux_val = serde_json::json!({"status": "inactive"});
        push_mismatch(
            &mut mismatches,
            &mut summary,
            ParitySeverityV1::Fail,
            42,
            "living_status",
            "status mismatch",
            Some(engine_val.clone()),
            Some(corecrux_val.clone()),
        );
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].engine, Some(engine_val));
        assert_eq!(mismatches[0].corecrux, Some(corecrux_val));
        assert_eq!(mismatches[0].artifact_id, 42);
        assert_eq!(mismatches[0].kind, "living_status");
    }

    // ── ParityMismatchV1 includes engine/corecrux when Some ───────

    #[test]
    fn parity_mismatch_v1_includes_some_fields() {
        let m = ParityMismatchV1 {
            severity: ParitySeverityV1::Fail,
            artifact_id: 1,
            kind: "test".to_string(),
            message: "msg".to_string(),
            engine: Some(serde_json::json!("eng")),
            corecrux: Some(serde_json::json!("ccx")),
        };
        let json = serde_json::to_string(&m).unwrap();
        assert!(json.contains("engine"));
        assert!(json.contains("corecrux"));
    }

    // ── write_json_file overwrites existing ───────────────────────

    #[test]
    fn write_json_file_overwrites_existing() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("data.json");
        write_json_file(&path, &serde_json::json!({"v": 1})).unwrap();
        write_json_file(&path, &serde_json::json!({"v": 2})).unwrap();
        let read: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(read["v"], 2);
    }

    // ── compare_dependent_keys multiple matching deps ─────────────

    #[test]
    fn compare_dependent_keys_multiple_matching_no_mismatch() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        let ts_micros = 1767225600000000i64; // 2026-01-01T00:00:00Z
        let engine = vec![
            EngineDependentRow {
                dependent_type: "query".to_string(),
                dependent_id: "q1".to_string(),
                last_seen_at: "2026-01-01T00:00:00Z".to_string(),
            },
            EngineDependentRow {
                dependent_type: "query".to_string(),
                dependent_id: "q2".to_string(),
                last_seen_at: "2026-01-01T00:00:00Z".to_string(),
            },
        ];
        let corecrux = vec![
            CoreCruxDependentRow {
                dependent_type: "query".to_string(),
                dependent_id: "q2".to_string(),
                last_seen_at_micros: ts_micros,
            },
            CoreCruxDependentRow {
                dependent_type: "query".to_string(),
                dependent_id: "q1".to_string(),
                last_seen_at_micros: ts_micros,
            },
        ];
        compare_dependent_keys(&mut mismatches, &mut summary, 1, &engine, &corecrux).unwrap();
        assert_eq!(summary.fail, 0);
        assert_eq!(summary.warn, 0);
    }

    // ── compare_dependent_keys: multiple drifted timestamps ──────

    #[test]
    fn compare_dependent_keys_multiple_last_seen_at_drifts() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        let engine = vec![
            EngineDependentRow {
                dependent_type: "query".to_string(),
                dependent_id: "q1".to_string(),
                last_seen_at: "2026-01-01T00:00:00Z".to_string(),
            },
            EngineDependentRow {
                dependent_type: "query".to_string(),
                dependent_id: "q2".to_string(),
                last_seen_at: "2026-01-02T00:00:00Z".to_string(),
            },
        ];
        let corecrux = vec![
            CoreCruxDependentRow {
                dependent_type: "query".to_string(),
                dependent_id: "q1".to_string(),
                last_seen_at_micros: 999, // differs
            },
            CoreCruxDependentRow {
                dependent_type: "query".to_string(),
                dependent_id: "q2".to_string(),
                last_seen_at_micros: 888, // differs
            },
        ];
        compare_dependent_keys(&mut mismatches, &mut summary, 1, &engine, &corecrux).unwrap();
        // Key sets match, but last_seen_at differs for 2 edges => single warn
        assert_eq!(summary.fail, 0);
        assert_eq!(summary.warn, 1);
        assert!(mismatches[0].message.contains("2 edges"));
    }

    // ── compare_dependent_keys: invalid engine timestamp ─────────

    #[test]
    fn compare_dependent_keys_unparseable_engine_timestamp_no_drift_warn() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        let engine = vec![EngineDependentRow {
            dependent_type: "query".to_string(),
            dependent_id: "q1".to_string(),
            last_seen_at: "not-a-date".to_string(),
        }];
        let corecrux = vec![CoreCruxDependentRow {
            dependent_type: "query".to_string(),
            dependent_id: "q1".to_string(),
            last_seen_at_micros: 12345,
        }];
        compare_dependent_keys(&mut mismatches, &mut summary, 1, &engine, &corecrux).unwrap();
        // Key sets match, engine timestamp unparseable => no drift warn
        assert_eq!(summary.fail, 0);
        assert_eq!(summary.warn, 0);
    }

    // ── compare_pressure_counts: multiple mixed events ───────────

    #[test]
    fn compare_pressure_counts_multiple_events_mixed_resolved() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        // Engine: 2 open (resolved_at=None), 1 resolved
        let engine = vec![
            EnginePressureRow {
                event_id: "e1".to_string(),
                pressure_code: "high".to_string(),
                severity: 1,
                observed_at: "2026-01-01T00:00:00Z".to_string(),
                acknowledged_at: None,
                resolved_at: None,
                receipt_id: None,
            },
            EnginePressureRow {
                event_id: "e2".to_string(),
                pressure_code: "low".to_string(),
                severity: 2,
                observed_at: "2026-01-01T00:00:00Z".to_string(),
                acknowledged_at: None,
                resolved_at: Some("2026-01-02T00:00:00Z".to_string()),
                receipt_id: None,
            },
            EnginePressureRow {
                event_id: "e3".to_string(),
                pressure_code: "medium".to_string(),
                severity: 1,
                observed_at: "2026-01-01T00:00:00Z".to_string(),
                acknowledged_at: None,
                resolved_at: None,
                receipt_id: None,
            },
        ];
        // CoreCrux: 2 open (resolved_at_micros=0), 1 resolved
        let corecrux = vec![
            CoreCruxPressureRow {
                event_id: "e1".to_string(),
                pressure_code_id: 1,
                severity: 1,
                observed_at_micros: 0,
                acknowledged_at_micros: 0,
                resolved_at_micros: 0,
                receipt_id: None,
            },
            CoreCruxPressureRow {
                event_id: "e2".to_string(),
                pressure_code_id: 2,
                severity: 2,
                observed_at_micros: 0,
                acknowledged_at_micros: 0,
                resolved_at_micros: 1000,
                receipt_id: None,
            },
            CoreCruxPressureRow {
                event_id: "e3".to_string(),
                pressure_code_id: 3,
                severity: 1,
                observed_at_micros: 0,
                acknowledged_at_micros: 0,
                resolved_at_micros: 0,
                receipt_id: None,
            },
        ];
        compare_pressure_counts(&mut mismatches, &mut summary, 1, &engine, &corecrux).unwrap();
        // Both have 2 open events
        assert_eq!(summary.fail, 0);
        assert!(mismatches.is_empty());
    }

    // ── compare_relation_keys: larger sets with duplicates ────────

    #[test]
    fn compare_relation_keys_multiple_relations_with_reordering() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        let engine = vec![
            EngineRelationRow {
                src_artifact_id: 1,
                dst_artifact_id: 2,
                relation_type: "cites".to_string(),
            },
            EngineRelationRow {
                src_artifact_id: 1,
                dst_artifact_id: 3,
                relation_type: "references".to_string(),
            },
            EngineRelationRow {
                src_artifact_id: 1,
                dst_artifact_id: 4,
                relation_type: "depends_on".to_string(),
            },
        ];
        let corecrux = vec![
            CoreCruxRelationRow {
                src_artifact_id: 1,
                dst_artifact_id: 4,
                relation_type: "depends_on".to_string(),
            },
            CoreCruxRelationRow {
                src_artifact_id: 1,
                dst_artifact_id: 2,
                relation_type: "cites".to_string(),
            },
            CoreCruxRelationRow {
                src_artifact_id: 1,
                dst_artifact_id: 3,
                relation_type: "references".to_string(),
            },
        ];
        compare_relation_keys(&mut mismatches, &mut summary, 1, "relations_out", &engine, &corecrux).unwrap();
        assert!(mismatches.is_empty());
    }

    // ── compare_relation_keys: extra in engine only ──────────────

    #[test]
    fn compare_relation_keys_extra_in_engine_produces_fail() {
        let mut mismatches = Vec::new();
        let mut summary = ParitySummaryV1::default();
        let engine = vec![
            EngineRelationRow {
                src_artifact_id: 1,
                dst_artifact_id: 2,
                relation_type: "cites".to_string(),
            },
            EngineRelationRow {
                src_artifact_id: 1,
                dst_artifact_id: 3,
                relation_type: "extra".to_string(),
            },
        ];
        let corecrux = vec![CoreCruxRelationRow {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: "cites".to_string(),
        }];
        compare_relation_keys(&mut mismatches, &mut summary, 1, "relations_in", &engine, &corecrux).unwrap();
        assert_eq!(summary.fail, 1);
        assert_eq!(mismatches[0].kind, "relations_in");
    }

    // ── write_json_file with large nested structure ──────────────

    #[test]
    fn write_json_file_preserves_nested_structure() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested.json");
        let value = serde_json::json!({
            "a": { "b": { "c": [1, 2, 3] } },
            "d": null,
            "e": true
        });
        write_json_file(&path, &value).unwrap();
        let read: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(read["a"]["b"]["c"][1], 2);
        assert_eq!(read["d"], serde_json::Value::Null);
        assert_eq!(read["e"], true);
    }

    // ── hash_hex_bytes with large input ��─────────────────────────

    #[test]
    fn hash_hex_bytes_large_input() {
        let data = vec![0xABu8; 10_000];
        let h = hash_hex_bytes(&data);
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_hex_bytes(&data));
    }

    // ── hash_hex_json different key order same result ─────────────

    #[test]
    fn hash_hex_json_different_values_different_hashes() {
        let v1 = serde_json::json!({"a": 1, "b": 2});
        let v2 = serde_json::json!({"a": 1, "b": 3});
        let h1 = hash_hex_json(&v1).unwrap();
        let h2 = hash_hex_json(&v2).unwrap();
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_hex_json_nested_structure() {
        let v = serde_json::json!({"nested": {"deep": true}, "list": [1, 2]});
        let h = hash_hex_json(&v).unwrap();
        assert_eq!(h.len(), 64);
        assert_eq!(h, hash_hex_json(&v).unwrap());
    }

    // ��─ select_artifact_sample stable across larger set ──────────

    #[test]
    fn select_artifact_sample_stable_ordering_large_set() {
        let artifacts: Vec<u32> = (1..=100).collect();
        let s1 = select_artifact_sample("deterministic", &artifacts, 10);
        let s2 = select_artifact_sample("deterministic", &artifacts, 10);
        assert_eq!(s1.len(), 10);
        assert_eq!(s1, s2);
        // Different seed should produce different sample
        let s3 = select_artifact_sample("other-seed", &artifacts, 10);
        assert_ne!(s1, s3);
    }

    // ── ParityPackMismatchExampleV1 round-trip ───────────────────

    #[test]
    fn parity_pack_mismatch_example_v1_round_trips() {
        use corecrux_types::DRIFT_SOURCE_CHANGE;
        let example = ParityPackMismatchExampleV1 {
            sample_id: "s000042".to_string(),
            projection_key: "artifact_living_state".to_string(),
            expected_hash: "abc".to_string(),
            actual_hash: "def".to_string(),
            drift_class: DRIFT_SOURCE_CHANGE.to_string(),
            detail: "hash mismatch for artifact:42".to_string(),
        };
        let json = serde_json::to_string(&example).unwrap();
        let deser: ParityPackMismatchExampleV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.sample_id, "s000042");
        assert_eq!(deser.drift_class, DRIFT_SOURCE_CHANGE);
    }

    // ── CanonicalRelationKeyV1 sort order ────────────────────────

    #[test]
    fn canonical_relation_key_v1_sort_order() {
        let mut keys = [
            CanonicalRelationKeyV1 {
                src_artifact_id: 2,
                dst_artifact_id: 3,
                relation_type: "cites".to_string(),
            },
            CanonicalRelationKeyV1 {
                src_artifact_id: 1,
                dst_artifact_id: 5,
                relation_type: "depends".to_string(),
            },
            CanonicalRelationKeyV1 {
                src_artifact_id: 1,
                dst_artifact_id: 3,
                relation_type: "cites".to_string(),
            },
        ];
        keys.sort();
        assert_eq!(keys[0].src_artifact_id, 1);
        assert_eq!(keys[0].dst_artifact_id, 3);
        assert_eq!(keys[1].src_artifact_id, 1);
        assert_eq!(keys[1].dst_artifact_id, 5);
        assert_eq!(keys[2].src_artifact_id, 2);
    }

    // ── CanonicalDependentKeyV1 sort order ───────────────────��───

    #[test]
    fn canonical_dependent_key_v1_sort_order() {
        let mut keys = [
            CanonicalDependentKeyV1 {
                dependent_type: "query".to_string(),
                dependent_id: "q2".to_string(),
            },
            CanonicalDependentKeyV1 {
                dependent_type: "answer".to_string(),
                dependent_id: "a1".to_string(),
            },
            CanonicalDependentKeyV1 {
                dependent_type: "query".to_string(),
                dependent_id: "q1".to_string(),
            },
        ];
        keys.sort();
        assert_eq!(keys[0].dependent_type, "answer");
        assert_eq!(keys[1].dependent_id, "q1");
        assert_eq!(keys[2].dependent_id, "q2");
    }

    // ── CanonicalCountsV1 equality ───────────────────────────────

    #[test]
    fn canonical_counts_v1_equality() {
        let a = CanonicalCountsV1 {
            relations_out: 3,
            relations_in: 1,
            dependents: 2,
        };
        let b = CanonicalCountsV1 {
            relations_out: 3,
            relations_in: 1,
            dependents: 2,
        };
        assert_eq!(a, b);
        let c = CanonicalCountsV1 {
            relations_out: 0,
            relations_in: 0,
            dependents: 0,
        };
        assert_ne!(a, c);
    }

    // ── ParityPackOptions clone ───��──────────────────────────────

    #[test]
    fn parity_pack_options_clone() {
        let opts = super::ParityPackOptions {
            out_dir: std::path::PathBuf::from("/tmp/out"),
            tenant_id: "t1".to_string(),
            seed: "42".to_string(),
            sample_size: 10,
            window_hours: 24,
            projections: "v1".to_string(),
            engine_base: "http://engine".to_string(),
            engine_api_key: "key".to_string(),
            corecrux_base: "http://corecrux".to_string(),
        };
        let cloned = opts.clone();
        assert_eq!(cloned.tenant_id, "t1");
        assert_eq!(cloned.sample_size, 10);
    }

    // ── EngineCounts: equality ───────────────────────────────────────

    #[test]
    fn engine_counts_equality() {
        let a = super::EngineCounts {
            relations_out: 1,
            relations_in: 2,
            dependents: 3,
        };
        let b = super::EngineCounts {
            relations_out: 1,
            relations_in: 2,
            dependents: 3,
        };
        assert_eq!(a, b);
        let c = super::EngineCounts {
            relations_out: 0,
            relations_in: 0,
            dependents: 0,
        };
        assert_ne!(a, c);
    }

    // ── EngineCounts: serde round-trip ───────────────────────────────

    #[test]
    fn engine_counts_serde_round_trip() {
        let counts = super::EngineCounts {
            relations_out: 5,
            relations_in: 3,
            dependents: 2,
        };
        let json = serde_json::to_string(&counts).unwrap();
        let deser: super::EngineCounts = serde_json::from_str(&json).unwrap();
        assert_eq!(counts, deser);
    }

    // ── EngineRelationRow serde round-trip ────────────────────────────

    #[test]
    fn engine_relation_row_serde_round_trip() {
        let row = EngineRelationRow {
            src_artifact_id: 1,
            dst_artifact_id: 2,
            relation_type: "cites".to_string(),
        };
        let json = serde_json::to_string(&row).unwrap();
        let deser: EngineRelationRow = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.src_artifact_id, 1);
        assert_eq!(deser.relation_type, "cites");
    }

    // ── CoreCruxRelationRow serde round-trip ─────────────────────────

    #[test]
    fn corecrux_relation_row_serde_round_trip() {
        let row = CoreCruxRelationRow {
            src_artifact_id: 10,
            dst_artifact_id: 20,
            relation_type: "references".to_string(),
        };
        let json = serde_json::to_string(&row).unwrap();
        let deser: CoreCruxRelationRow = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.dst_artifact_id, 20);
    }

    // ── EngineDependentRow serde round-trip ───────────────────────────

    #[test]
    fn engine_dependent_row_serde_round_trip() {
        let row = EngineDependentRow {
            dependent_type: "query".to_string(),
            dependent_id: "q1".to_string(),
            last_seen_at: "2026-01-01T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&row).unwrap();
        let deser: EngineDependentRow = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.dependent_type, "query");
    }

    // ── CoreCruxPressureRow serde round-trip ─────────────────────────

    #[test]
    fn corecrux_pressure_row_serde_round_trip() {
        let row = CoreCruxPressureRow {
            event_id: "e1".to_string(),
            pressure_code_id: 42,
            severity: 3,
            observed_at_micros: 100,
            acknowledged_at_micros: 200,
            resolved_at_micros: 0,
            receipt_id: Some("r1".to_string()),
        };
        let json = serde_json::to_string(&row).unwrap();
        let deser: CoreCruxPressureRow = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.pressure_code_id, 42);
        assert_eq!(deser.receipt_id, Some("r1".to_string()));
    }

    // ── EnginePressureRow serde round-trip ────────────────────────────

    #[test]
    fn engine_pressure_row_serde_round_trip() {
        let row = EnginePressureRow {
            event_id: "e1".to_string(),
            pressure_code: "high".to_string(),
            severity: 2,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
            acknowledged_at: Some("2026-01-02T00:00:00Z".to_string()),
            resolved_at: None,
            receipt_id: None,
        };
        let json = serde_json::to_string(&row).unwrap();
        let deser: EnginePressureRow = serde_json::from_str(&json).unwrap();
        assert_eq!(deser.pressure_code, "high");
        assert!(deser.acknowledged_at.is_some());
        assert!(deser.resolved_at.is_none());
    }

    // ── ParityPackManifestV1: clone ──────────────────────────────────

    #[test]
    fn parity_pack_manifest_v1_clone() {
        let manifest = ParityPackManifestV1 {
            pack_type: "t".to_string(),
            generated_at: "now".to_string(),
            seed: "0".to_string(),
            sample_size: 5,
            window_hours: 24,
            corecrux_version: "v".to_string(),
            engine_version: "e".to_string(),
            projection_versions: std::collections::BTreeMap::new(),
            kernel_versions: std::collections::BTreeMap::new(),
        };
        let cloned = manifest.clone();
        assert_eq!(cloned.seed, "0");
    }

    // ── hash_prefix zero length ──────────────────────────────────────

    #[test]
    fn hash_prefix_zero_length() {
        let p = hash_prefix("test", 0);
        assert!(p.is_empty());
    }

    // ── hash_prefix larger than digest ───────────────────────────────

    #[test]
    fn hash_prefix_larger_than_digest_truncates() {
        let p = hash_prefix("test", 128);
        assert_eq!(p.len(), 64); // blake3 hex is 64 chars
    }

    // ── parse_rfc3339_to_micros: sub-second precision ────────────────

    #[test]
    fn parse_rfc3339_to_micros_sub_second() {
        let micros = parse_rfc3339_to_micros("2026-01-01T00:00:00.123456Z").unwrap();
        // Should end in 123456 micros past the second
        assert_eq!(micros % 1_000_000, 123456);
    }

    // ── CanonicalArtifactProjectionStateV1: not present ──────────────

    #[test]
    fn canonical_artifact_projection_state_not_present() {
        let state = CanonicalArtifactProjectionStateV1 {
            artifact_id: 99,
            present: false,
            living_status: None,
            pressure_level: None,
            trunk_tier: None,
            counts: None,
            relations_out: Vec::new(),
            relations_in: Vec::new(),
            dependents: Vec::new(),
            pressure_open_count: 0,
        };
        let json = serde_json::to_string(&state).unwrap();
        let deser: CanonicalArtifactProjectionStateV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deser);
        assert!(!deser.present);
    }

    // ── ParityLivingReportV1: debug ──────────────────────────────────

    #[test]
    fn parity_living_report_v1_debug() {
        let report = ParityLivingReportV1 {
            tenant_id: "t".to_string(),
            seed: "0".to_string(),
            sample_n: 1,
            engine_base: "e".to_string(),
            corecrux_base: "c".to_string(),
            artifacts: vec![],
            summary: ParitySummaryV1::default(),
            mismatches: vec![],
        };
        let dbg = format!("{:?}", report);
        assert!(dbg.contains("tenant_id"));
    }
}
