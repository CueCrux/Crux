// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::path::{Path, PathBuf};

use corecrux_storage::{ShardStorage, ShardStorageOptions, MANIFEST_HEADER_LEN};

#[derive(Debug, serde::Serialize)]
pub struct ProjectionsRebuildReportV1 {
    pub data_dir: String,
    pub shard_root: String,
    pub cuda_enabled: bool,
    pub cuda_driver_version: Option<String>,
    pub device_index: i32,
    pub device_name: Option<String>,
    pub shards: Vec<ShardRebuildReportV1>,
}

#[derive(Debug, serde::Serialize)]
pub struct ShardRebuildReportV1 {
    pub shard_id: u32,
    pub epoch: u64,
    pub projections_dir: String,
    pub frames_processed: u64,
    pub commit_id: u64,
    pub living_rows: u64,
    pub relations_edges: u64,
    pub dependents_edges: u64,
    pub pressure_rows: u64,
}

#[derive(Debug, serde::Serialize)]
pub struct ProjectionsColdGcReportV1 {
    pub data_dir: String,
    pub shard_root: String,
    pub dry_run: bool,
    pub min_age_seconds: u64,
    pub max_delete: u64,
    pub shards: Vec<corecrux_projections::ColdSegmentGcReportV1>,
}

#[derive(Debug, serde::Serialize)]
pub struct ProjectionsSeedReportV1 {
    pub data_dir: String,
    pub shard_root: String,
    pub shard_id: u32,
    pub epoch: u64,
    pub tenant_id: String,
    pub stream_type: String,
    pub stream_id: String,
    pub stream_hash: String,
    pub device_index: i32,
    pub cuda_enabled: bool,
    pub cuda_driver_version: Option<String>,
    pub device_name: Option<String>,
    pub segments_written: u64,
    pub frames_written: u64,
    pub batches: Vec<SeedBatchReportV1>,
}

#[derive(Debug, serde::Serialize)]
pub struct SeedBatchReportV1 {
    pub batch_index: u32,
    pub events: u32,
    pub appended: u32,
    pub duplicate_committed: u32,
    pub duplicate_in_batch: u32,
    pub rejected: u32,
}

pub fn rebuild_projections_v1(
    data_dir: &Path,
    shard: Option<u32>,
    _device_index: i32,
    batch_frames: u32,
) -> Result<ProjectionsRebuildReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let shard_root = data_dir.join("shards");
    if !shard_root.exists() {
        return Err(format!("shard root not found: {}", shard_root.display()).into());
    }

    let mut shard_dirs: Vec<(u32, PathBuf)> = Vec::new();
    for e in std::fs::read_dir(&shard_root)? {
        let e = e?;
        if !e.file_type()?.is_dir() {
            continue;
        }
        let name = e.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("shard-") {
            continue;
        }
        let Some((_prefix, digits)) = name.rsplit_once('-') else {
            continue;
        };
        let Ok(id) = digits.parse::<u32>() else {
            continue;
        };
        if let Some(only) = shard {
            if id != only {
                continue;
            }
        }
        shard_dirs.push((id, e.path()));
    }
    shard_dirs.sort_by_key(|(id, _)| *id);

    let mut reports = Vec::new();
    for (shard_id, shard_dir) in shard_dirs {
        let epoch = read_epoch_from_manifest(&shard_dir.join("MANIFEST"))?;

        let storage = ShardStorage::open(&shard_root, shard_id, epoch, ShardStorageOptions::default())?;

        let mut proj = corecrux_projections::ProjectionStoreV1::load_or_init(&shard_dir, shard_id, epoch)?;
        let r = proj.rebuild_from_genesis(&storage, batch_frames)?;
        reports.push(ShardRebuildReportV1 {
            shard_id,
            epoch,
            projections_dir: proj.files.projections_dir.display().to_string(),
            frames_processed: r.frames_processed,
            commit_id: r.commit_id,
            living_rows: r.state_counts.living_rows,
            relations_edges: r.state_counts.relations_edges,
            dependents_edges: r.state_counts.dependents_edges,
            pressure_rows: r.state_counts.pressure_rows,
        });
    }

    Ok(ProjectionsRebuildReportV1 {
        data_dir: data_dir.display().to_string(),
        shard_root: shard_root.display().to_string(),
        cuda_enabled: false,
        cuda_driver_version: None,
        device_index: 0,
        device_name: None,
        shards: reports,
    })
}

pub fn seed_minimal_projection_events_v1(
    data_dir: &Path,
    shard_id: u32,
    tenant_id: &str,
    artifact_id: u32,
    _device_index: i32,
) -> Result<ProjectionsSeedReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let shard_root = data_dir.join("shards");
    std::fs::create_dir_all(&shard_root)?;

    let epoch = 1u64;
    let mut storage = ShardStorage::open(&shard_root, shard_id, epoch, ShardStorageOptions::default())?;

    let stream_type = "artifact";
    let stream_id = artifact_id.to_string();
    let stream_hash =
        corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, &stream_id).map_err(|e| e.to_string())?;

    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let living = corecrux_projections::LivingStateUpdateV1 {
        fields_mask: corecrux_projections::LivingStateUpdateV1::MASK_LIVING_STATUS
            | corecrux_projections::LivingStateUpdateV1::MASK_CONFIDENCE
            | corecrux_projections::LivingStateUpdateV1::MASK_TRUNK_TIER
            | corecrux_projections::LivingStateUpdateV1::MASK_UPDATED_AT,
        artifact_id,
        living_status: 1,
        confidence_q16: 40000,
        last_validated_at_micros: 0,
        next_review_at_micros: 0,
        trunk_tier: 2,
        updated_at_micros: 10,
    };
    let rel_up_1 = corecrux_projections::RelationUpsertV1 {
        src_artifact_id: artifact_id,
        dst_artifact_id: 2,
        relation_type: 0,
        confidence_q16: 50000,
        evidence_ref_hash16: [7u8; 16],
        created_at_micros: 10,
        updated_at_micros: 11,
    };
    let rel_del_1 = corecrux_projections::RelationDeleteV1 {
        src_artifact_id: artifact_id,
        dst_artifact_id: 2,
        relation_type: 0,
    };
    let rel_up_2 = corecrux_projections::RelationUpsertV1 {
        src_artifact_id: artifact_id,
        dst_artifact_id: 3,
        relation_type: 1,
        confidence_q16: 60000,
        evidence_ref_hash16: [9u8; 16],
        created_at_micros: 12,
        updated_at_micros: 13,
    };

    let mut segments_written = 0u64;
    let mut frames_written = 0u64;
    let mut batches = Vec::new();

    for (batch_index, events) in [
        vec![
            (corecrux_projections::EVT_LIVING_STATE_UPDATE_V1, living.encode_bin()),
            (corecrux_projections::EVT_RELATION_UPSERT_V1, rel_up_1.encode_bin()),
        ],
        vec![
            (corecrux_projections::EVT_RELATION_DELETE_V1, rel_del_1.encode_bin()),
            (corecrux_projections::EVT_RELATION_UPSERT_V1, rel_up_2.encode_bin()),
        ],
    ]
    .into_iter()
    .enumerate()
    {
        let mut event_ids: Vec<String> = Vec::new();
        let mut payloads: Vec<Vec<u8>> = Vec::new();
        for (_et, payload) in &events {
            event_ids.push(format!(
                "seed:{}:{}:{}",
                shard_id,
                batch_index,
                uuid::Uuid::new_v4().to_string().replace('-', "")
            ));
            payloads.push(payload.clone());
        }

        let mut inputs: Vec<corecrux_storage::AppendEventInput<'_>> = Vec::new();
        for (idx, (et, _payload)) in events.iter().enumerate() {
            inputs.push(corecrux_storage::AppendEventInput {
                event_id: &event_ids[idx],
                occurred_at: &now,
                event_type: et,
                content_type: corecrux_projections::CONTENT_TYPE_PROJ_BIN_V1,
                payload_bytes: &payloads[idx],
            });
        }

        let outcomes = storage.append_batch(stream_hash, 0, tenant_id, stream_type, &stream_id, &now, &inputs)?;

        segments_written = segments_written.saturating_add(1);
        frames_written = frames_written.saturating_add(outcomes.len() as u64);

        let mut appended = 0u32;
        let mut duplicate_committed = 0u32;
        let mut duplicate_in_batch = 0u32;
        let mut rejected = 0u32;
        for o in outcomes {
            match o.status {
                corecrux_storage::AppendStatus::Appended => appended += 1,
                corecrux_storage::AppendStatus::DuplicateCommitted => duplicate_committed += 1,
                corecrux_storage::AppendStatus::DuplicateInBatch => duplicate_in_batch += 1,
                corecrux_storage::AppendStatus::Rejected => rejected += 1,
            }
        }
        batches.push(SeedBatchReportV1 {
            batch_index: batch_index as u32,
            events: inputs.len() as u32,
            appended,
            duplicate_committed,
            duplicate_in_batch,
            rejected,
        });
    }

    Ok(ProjectionsSeedReportV1 {
        data_dir: data_dir.display().to_string(),
        shard_root: shard_root.display().to_string(),
        shard_id,
        epoch,
        tenant_id: tenant_id.to_string(),
        stream_type: "artifact".to_string(),
        stream_id: artifact_id.to_string(),
        stream_hash: format!("{stream_hash:#x}"),
        device_index: 0,
        cuda_enabled: false,
        cuda_driver_version: None,
        device_name: None,
        segments_written,
        frames_written,
        batches,
    })
}

pub fn gc_orphan_cold_segments_v1(
    data_dir: &Path,
    shard: Option<u32>,
    dry_run: bool,
    min_age_seconds: u64,
    max_delete: u64,
) -> Result<ProjectionsColdGcReportV1, Box<dyn std::error::Error + Send + Sync>> {
    let shard_root = data_dir.join("shards");
    if !shard_root.exists() {
        return Err(format!("shard root not found: {}", shard_root.display()).into());
    }

    let mut shard_dirs: Vec<(u32, PathBuf)> = Vec::new();
    for e in std::fs::read_dir(&shard_root)? {
        let e = e?;
        if !e.file_type()?.is_dir() {
            continue;
        }
        let name = e.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("shard-") {
            continue;
        }
        let Some((_prefix, digits)) = name.rsplit_once('-') else {
            continue;
        };
        let Ok(id) = digits.parse::<u32>() else {
            continue;
        };
        if let Some(only) = shard {
            if id != only {
                continue;
            }
        }
        shard_dirs.push((id, e.path()));
    }
    shard_dirs.sort_by_key(|(id, _)| *id);

    let mut reports: Vec<corecrux_projections::ColdSegmentGcReportV1> = Vec::new();
    for (shard_id, shard_dir) in shard_dirs {
        let epoch = read_epoch_from_manifest(&shard_dir.join("MANIFEST"))?;

        let mut proj = corecrux_projections::ProjectionStoreV1::load_or_init(&shard_dir, shard_id, epoch)?;
        let r = proj.gc_orphan_cold_segments_v1(corecrux_projections::ColdSegmentGcOptionsV1 {
            dry_run,
            min_age_seconds,
            max_delete,
        })?;
        reports.push(r);
    }

    Ok(ProjectionsColdGcReportV1 {
        data_dir: data_dir.display().to_string(),
        shard_root: shard_root.display().to_string(),
        dry_run,
        min_age_seconds,
        max_delete,
        shards: reports,
    })
}

fn read_epoch_from_manifest(path: &Path) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let bytes = std::fs::read(path)?;
    if bytes.len() < MANIFEST_HEADER_LEN {
        return Err(format!("manifest too small: {}", path.display()).into());
    }
    let epoch = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
    Ok(epoch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ── read_epoch_from_manifest ─────────────────────────────────────

    #[test]
    fn read_epoch_valid() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("MANIFEST");
        let mut data = vec![0u8; MANIFEST_HEADER_LEN];
        let epoch: u64 = 99;
        data[16..24].copy_from_slice(&epoch.to_le_bytes());
        fs::write(&path, &data).unwrap();

        assert_eq!(read_epoch_from_manifest(&path).unwrap(), 99);
    }

    #[test]
    fn read_epoch_too_small() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("MANIFEST");
        fs::write(&path, [0u8; 10]).unwrap();

        let err = read_epoch_from_manifest(&path).unwrap_err();
        assert!(err.to_string().contains("manifest too small"));
    }

    #[test]
    fn read_epoch_missing_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("MANIFEST");
        assert!(read_epoch_from_manifest(&path).is_err());
    }

    // ── Data structure serialization ─────────────────────────────────

    #[test]
    fn projections_rebuild_report_serializes() {
        let report = ProjectionsRebuildReportV1 {
            data_dir: "/data".to_string(),
            shard_root: "/data/shards".to_string(),
            cuda_enabled: false,
            cuda_driver_version: None,
            device_index: 0,
            device_name: None,
            shards: vec![ShardRebuildReportV1 {
                shard_id: 0,
                epoch: 1,
                projections_dir: "/data/shards/shard-0000/projections".to_string(),
                frames_processed: 100,
                commit_id: 42,
                living_rows: 10,
                relations_edges: 5,
                dependents_edges: 3,
                pressure_rows: 7,
            }],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["cuda_enabled"], false);
        assert_eq!(json["shards"][0]["shard_id"], 0);
        assert_eq!(json["shards"][0]["frames_processed"], 100);
        assert_eq!(json["shards"][0]["living_rows"], 10);
    }

    #[test]
    fn projections_cold_gc_report_serializes() {
        let report = ProjectionsColdGcReportV1 {
            data_dir: "/data".to_string(),
            shard_root: "/data/shards".to_string(),
            dry_run: true,
            min_age_seconds: 3600,
            max_delete: 100,
            shards: vec![],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["dry_run"], true);
        assert_eq!(json["min_age_seconds"], 3600);
        assert_eq!(json["max_delete"], 100);
    }

    #[test]
    fn projections_seed_report_serializes() {
        let report = ProjectionsSeedReportV1 {
            data_dir: "/data".to_string(),
            shard_root: "/data/shards".to_string(),
            shard_id: 1,
            epoch: 1,
            tenant_id: "tenant-1".to_string(),
            stream_type: "artifact".to_string(),
            stream_id: "42".to_string(),
            stream_hash: "0xabcd".to_string(),
            device_index: 0,
            cuda_enabled: false,
            cuda_driver_version: None,
            device_name: None,
            segments_written: 2,
            frames_written: 4,
            batches: vec![SeedBatchReportV1 {
                batch_index: 0,
                events: 2,
                appended: 2,
                duplicate_committed: 0,
                duplicate_in_batch: 0,
                rejected: 0,
            }],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["shard_id"], 1);
        assert_eq!(json["tenant_id"], "tenant-1");
        assert_eq!(json["segments_written"], 2);
        assert_eq!(json["batches"][0]["appended"], 2);
    }

    #[test]
    fn seed_batch_report_fields() {
        let batch = SeedBatchReportV1 {
            batch_index: 3,
            events: 10,
            appended: 8,
            duplicate_committed: 1,
            duplicate_in_batch: 0,
            rejected: 1,
        };
        let json = serde_json::to_value(&batch).unwrap();
        assert_eq!(json["batch_index"], 3);
        assert_eq!(json["events"], 10);
        assert_eq!(json["appended"], 8);
        assert_eq!(json["duplicate_committed"], 1);
        assert_eq!(json["rejected"], 1);
    }

    // ── rebuild_projections_v1 missing shard root ────────────────────

    #[test]
    fn rebuild_projections_missing_shard_root() {
        let tmp = TempDir::new().unwrap();
        let result = rebuild_projections_v1(tmp.path(), None, 0, 100);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("shard root not found"));
    }

    #[test]
    fn rebuild_projections_empty_shard_root() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("shards")).unwrap();
        let report = rebuild_projections_v1(tmp.path(), None, 0, 100).unwrap();
        assert!(report.shards.is_empty());
        assert!(!report.cuda_enabled);
    }

    // ── gc_orphan_cold_segments_v1 missing shard root ────────────────

    #[test]
    fn gc_orphan_cold_missing_shard_root() {
        let tmp = TempDir::new().unwrap();
        let result = gc_orphan_cold_segments_v1(tmp.path(), None, true, 3600, 10);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("shard root not found"));
    }

    #[test]
    fn gc_orphan_cold_empty_shard_root() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("shards")).unwrap();
        let report = gc_orphan_cold_segments_v1(tmp.path(), None, true, 3600, 10).unwrap();
        assert!(report.shards.is_empty());
        assert!(report.dry_run);
    }

    // ── rebuild_projections_v1: shard filter ────────────────────────

    #[test]
    fn rebuild_projections_shard_filter_empty_result() {
        let tmp = TempDir::new().unwrap();
        let shards_dir = tmp.path().join("shards");
        fs::create_dir(&shards_dir).unwrap();
        // Create a shard dir that doesn't match the filter
        fs::create_dir(shards_dir.join("shard-0001")).unwrap();
        // Filter for shard 9999 which doesn't exist
        let report = rebuild_projections_v1(tmp.path(), Some(9999), 0, 100).unwrap();
        assert!(report.shards.is_empty());
    }

    // ── gc_orphan_cold: shard filter ────────────────────────────────

    #[test]
    fn gc_orphan_cold_shard_filter_no_match() {
        let tmp = TempDir::new().unwrap();
        let shards_dir = tmp.path().join("shards");
        fs::create_dir(&shards_dir).unwrap();
        fs::create_dir(shards_dir.join("shard-0001")).unwrap();
        let report = gc_orphan_cold_segments_v1(tmp.path(), Some(9999), true, 3600, 10).unwrap();
        assert!(report.shards.is_empty());
    }

    // ── shard directory scanning: non-shard dirs skipped ────────────

    #[test]
    fn rebuild_projections_ignores_non_shard_dirs() {
        let tmp = TempDir::new().unwrap();
        let shards_dir = tmp.path().join("shards");
        fs::create_dir(&shards_dir).unwrap();
        fs::create_dir(shards_dir.join("not-a-shard")).unwrap();
        fs::create_dir(shards_dir.join("shard-")).unwrap(); // no digits
                                                            // Create a file, not a directory
        fs::write(shards_dir.join("shard-0001"), "file not dir").unwrap();
        let report = rebuild_projections_v1(tmp.path(), None, 0, 100).unwrap();
        assert!(report.shards.is_empty());
    }

    // ── read_epoch: larger than minimum ─────────────────────────────

    #[test]
    fn read_epoch_exact_minimum_size() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("MANIFEST");
        let mut data = vec![0u8; MANIFEST_HEADER_LEN];
        let epoch: u64 = u64::MAX;
        data[16..24].copy_from_slice(&epoch.to_le_bytes());
        fs::write(&path, &data).unwrap();
        assert_eq!(read_epoch_from_manifest(&path).unwrap(), u64::MAX);
    }

    #[test]
    fn read_epoch_larger_file_works() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("MANIFEST");
        let mut data = vec![0u8; MANIFEST_HEADER_LEN + 1024];
        let epoch: u64 = 42;
        data[16..24].copy_from_slice(&epoch.to_le_bytes());
        fs::write(&path, &data).unwrap();
        assert_eq!(read_epoch_from_manifest(&path).unwrap(), 42);
    }

    // ── Report serde: field name coverage ───────────────────────────

    #[test]
    fn shard_rebuild_report_all_fields_serialized() {
        let report = ShardRebuildReportV1 {
            shard_id: 3,
            epoch: 5,
            projections_dir: "/proj".to_string(),
            frames_processed: 1000,
            commit_id: 77,
            living_rows: 50,
            relations_edges: 25,
            dependents_edges: 12,
            pressure_rows: 8,
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["shard_id"], 3);
        assert_eq!(json["epoch"], 5);
        assert_eq!(json["projections_dir"], "/proj");
        assert_eq!(json["frames_processed"], 1000);
        assert_eq!(json["commit_id"], 77);
        assert_eq!(json["living_rows"], 50);
        assert_eq!(json["relations_edges"], 25);
        assert_eq!(json["dependents_edges"], 12);
        assert_eq!(json["pressure_rows"], 8);
    }

    #[test]
    fn projections_rebuild_report_with_cuda_fields() {
        let report = ProjectionsRebuildReportV1 {
            data_dir: "/data".to_string(),
            shard_root: "/data/shards".to_string(),
            cuda_enabled: true,
            cuda_driver_version: Some("12.0".to_string()),
            device_index: 1,
            device_name: Some("RTX 4090".to_string()),
            shards: vec![],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["cuda_enabled"], true);
        assert_eq!(json["cuda_driver_version"], "12.0");
        assert_eq!(json["device_index"], 1);
        assert_eq!(json["device_name"], "RTX 4090");
    }

    #[test]
    fn projections_seed_report_with_cuda() {
        let report = ProjectionsSeedReportV1 {
            data_dir: "/data".to_string(),
            shard_root: "/data/shards".to_string(),
            shard_id: 1,
            epoch: 1,
            tenant_id: "t".to_string(),
            stream_type: "artifact".to_string(),
            stream_id: "42".to_string(),
            stream_hash: "0xabcd".to_string(),
            device_index: 2,
            cuda_enabled: true,
            cuda_driver_version: Some("11.8".to_string()),
            device_name: Some("A100".to_string()),
            segments_written: 0,
            frames_written: 0,
            batches: vec![],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["cuda_enabled"], true);
        assert_eq!(json["device_index"], 2);
        assert_eq!(json["cuda_driver_version"], "11.8");
        assert_eq!(json["device_name"], "A100");
    }

    // ── rebuild_projections_v1: non-shard file entries ───────────────

    #[test]
    fn rebuild_projections_skips_files_not_dirs() {
        let tmp = TempDir::new().unwrap();
        let shards_dir = tmp.path().join("shards");
        fs::create_dir(&shards_dir).unwrap();
        // Create file (not dir) with shard-like name
        fs::write(shards_dir.join("shard-0001"), b"not a dir").unwrap();
        // Create directory without shard prefix
        fs::create_dir(shards_dir.join("notashard")).unwrap();
        let report = rebuild_projections_v1(tmp.path(), None, 0, 100).unwrap();
        assert!(report.shards.is_empty());
    }

    // ── gc_orphan_cold_segments_v1: shard filter with valid dir ──────

    #[test]
    fn gc_orphan_cold_shard_filter_file_skipped() {
        let tmp = TempDir::new().unwrap();
        let shards_dir = tmp.path().join("shards");
        fs::create_dir(&shards_dir).unwrap();
        // A file named shard-0001 (not a directory)
        fs::write(shards_dir.join("shard-0001"), b"not a dir").unwrap();
        let report = gc_orphan_cold_segments_v1(tmp.path(), None, true, 3600, 10).unwrap();
        assert!(report.shards.is_empty());
    }

    // ── read_epoch_from_manifest: zero epoch ────────────────────────

    #[test]
    fn read_epoch_zero_value() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("MANIFEST");
        let data = vec![0u8; MANIFEST_HEADER_LEN];
        fs::write(&path, &data).unwrap();
        // epoch bytes at [16..24] are all zero
        assert_eq!(read_epoch_from_manifest(&path).unwrap(), 0);
    }

    // ── ProjectionsRebuildReportV1: empty shards ────────────────────

    #[test]
    fn projections_rebuild_report_empty_shards_serializes() {
        let report = ProjectionsRebuildReportV1 {
            data_dir: "/d".to_string(),
            shard_root: "/d/shards".to_string(),
            cuda_enabled: false,
            cuda_driver_version: None,
            device_index: 0,
            device_name: None,
            shards: vec![],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert!(json["shards"].as_array().unwrap().is_empty());
    }

    // ── SeedBatchReportV1: all zeros ────────────────────────────────

    #[test]
    fn seed_batch_report_all_zeros() {
        let batch = SeedBatchReportV1 {
            batch_index: 0,
            events: 0,
            appended: 0,
            duplicate_committed: 0,
            duplicate_in_batch: 0,
            rejected: 0,
        };
        let json = serde_json::to_value(&batch).unwrap();
        assert_eq!(json["events"], 0);
        assert_eq!(json["appended"], 0);
    }

    // ── ProjectionsColdGcReportV1: field coverage ───────────────────

    // ── seed_minimal_projection_events_v1 ────────────────────────────

    #[test]
    fn seed_minimal_projection_events_creates_data() {
        let tmp = TempDir::new().unwrap();
        let report = seed_minimal_projection_events_v1(tmp.path(), 1, "tenant-test", 42, 0).unwrap();
        assert_eq!(report.shard_id, 1);
        assert_eq!(report.tenant_id, "tenant-test");
        assert_eq!(report.stream_type, "artifact");
        assert_eq!(report.stream_id, "42");
        assert!(report.stream_hash.contains("0x"));
        assert_eq!(report.batches.len(), 2);
        assert!(report.frames_written > 0);
        assert!(report.segments_written > 0);
        // All events should be appended
        for batch in &report.batches {
            assert_eq!(batch.rejected, 0);
            assert_eq!(batch.appended, batch.events);
        }
    }

    // ── rebuild_projections_v1 with seeded data ─────────────────────

    #[test]
    fn rebuild_projections_after_seed() {
        let tmp = TempDir::new().unwrap();
        // Seed some projection events
        let _seed = seed_minimal_projection_events_v1(tmp.path(), 1, "t", 1, 0).unwrap();
        // Now rebuild projections
        let report = rebuild_projections_v1(tmp.path(), Some(1), 0, 100).unwrap();
        assert_eq!(report.shards.len(), 1);
        assert_eq!(report.shards[0].shard_id, 1);
        assert!(report.shards[0].frames_processed > 0);
    }

    // ── gc_orphan_cold with seeded data ─────────────────────────────

    #[test]
    fn gc_orphan_cold_after_seed_and_rebuild() {
        let tmp = TempDir::new().unwrap();
        let _seed = seed_minimal_projection_events_v1(tmp.path(), 1, "t", 1, 0).unwrap();
        let _rebuild = rebuild_projections_v1(tmp.path(), Some(1), 0, 100).unwrap();
        // GC should run without error
        let report = gc_orphan_cold_segments_v1(tmp.path(), Some(1), true, 0, 100).unwrap();
        assert_eq!(report.shards.len(), 1);
        assert!(report.dry_run);
    }

    #[test]
    fn projections_cold_gc_report_all_fields() {
        let report = ProjectionsColdGcReportV1 {
            data_dir: "/data".to_string(),
            shard_root: "/data/shards".to_string(),
            dry_run: false,
            min_age_seconds: 0,
            max_delete: 0,
            shards: vec![],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["dry_run"], false);
        assert_eq!(json["min_age_seconds"], 0);
        assert_eq!(json["max_delete"], 0);
        assert!(json["shards"].as_array().unwrap().is_empty());
    }
}
