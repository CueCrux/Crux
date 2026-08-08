// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Manifest repair driver — finds MANIFEST entries whose segment file is gone and tombstones them.
//!
//! A shard whose manifest references a deleted segment cannot be opened at all:
//! `ShardStorage::open` does `File::open` on every referenced segment, so one
//! dangling entry fails every write. Reads are unaffected (they scan the
//! `segments/` dir), which is why this failure mode is silent — host `crux` ran
//! 38 hours with all ingest returning 500 and `/readyz` green.
//!
//! Repair is an append, never a rewrite: the removals go on the end of the
//! manifest log as `RemoveSegment` tombstones, so no existing record or checksum
//! is touched and the worst case of a bad run is the state the shard is already
//! in. See ExecPlan `crux-erasure-manifest-repair-2026-08-08`.

use std::path::{Path, PathBuf};

use corecrux_storage::{load_manifest_segment_catalog, retire_segments_in_manifest};
use serde::Serialize;

type DynError = Box<dyn std::error::Error + Send + Sync>;

const REPAIR_SCHEMA_V1: &str = "corecruxctl.repair_manifest.v1";

#[derive(Debug, Clone)]
pub struct RepairManifestOptions {
    pub data_dir: PathBuf,
    /// Repair only this shard. `None` scans every shard under `shards/`.
    pub shard: Option<u32>,
    /// Append the tombstones. Without it the command only reports.
    pub apply: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DanglingSegment {
    pub shard_id: u32,
    pub segment_seq: u64,
    pub relative_path: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ShardRepairReport {
    pub shard_id: u32,
    /// Segments the MANIFEST references.
    pub manifest_segments: usize,
    /// Of those, how many are missing from disk.
    pub dangling: usize,
    pub dangling_segments: Vec<DanglingSegment>,
    pub manifest_end_before: u64,
    pub manifest_end_after: u64,
    pub retired: Vec<u64>,
    pub applied: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RepairManifestReport {
    pub schema: String,
    pub data_dir: String,
    pub applied: bool,
    /// True when every scanned shard's manifest agrees with its `segments/` dir.
    pub healthy: bool,
    pub shards: Vec<ShardRepairReport>,
}

pub fn repair_manifest(opts: &RepairManifestOptions) -> Result<RepairManifestReport, DynError> {
    let shards_root = opts.data_dir.join("shards");
    let shard_ids = list_shards(&shards_root)?;
    if shard_ids.is_empty() {
        return Err(format!(
            "no shards under {}: nothing was scanned, so a clean report would not mean a healthy store",
            shards_root.display()
        )
        .into());
    }

    let mut shards = Vec::new();
    for shard_id in shard_ids {
        if opts.shard.is_some_and(|wanted| wanted != shard_id) {
            continue;
        }
        shards.push(repair_one_shard(&shards_root, shard_id, opts.apply)?);
    }
    if shards.is_empty() {
        return Err(format!("shard {:?} not found under {}", opts.shard, shards_root.display()).into());
    }

    Ok(RepairManifestReport {
        schema: REPAIR_SCHEMA_V1.to_string(),
        data_dir: opts.data_dir.display().to_string(),
        applied: opts.apply,
        healthy: shards.iter().all(|s| s.dangling == 0),
        shards,
    })
}

fn repair_one_shard(shards_root: &Path, shard_id: u32, apply: bool) -> Result<ShardRepairReport, DynError> {
    let shard_dir = shards_root.join(format!("shard-{shard_id:04}"));
    let catalog = load_manifest_segment_catalog(&shard_dir)?;

    let mut dangling_segments = Vec::new();
    for segment in &catalog.segments {
        if shard_dir.join(&segment.relative_path).exists() {
            continue;
        }
        dangling_segments.push(DanglingSegment {
            shard_id,
            segment_seq: segment.segment_seq,
            relative_path: segment.relative_path.clone(),
        });
    }

    let mut report = ShardRepairReport {
        shard_id,
        manifest_segments: catalog.segments.len(),
        dangling: dangling_segments.len(),
        manifest_end_before: catalog.manifest_end,
        manifest_end_after: catalog.manifest_end,
        retired: Vec::new(),
        applied: false,
        dangling_segments,
    };

    if !apply || report.dangling == 0 {
        return Ok(report);
    }

    let seqs: Vec<u64> = report.dangling_segments.iter().map(|d| d.segment_seq).collect();
    let outcome = retire_segments_in_manifest(shards_root, shard_id, &seqs)?;
    report.manifest_end_after = outcome.manifest_end;
    report.retired = outcome.retired;
    report.applied = true;
    Ok(report)
}

fn list_shards(shards_root: &Path) -> Result<Vec<u32>, DynError> {
    let mut shard_ids = Vec::new();
    for entry in std::fs::read_dir(shards_root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let Some(rest) = name.strip_prefix("shard-") else {
            continue;
        };
        let Ok(shard_id) = rest.parse::<u32>() else {
            continue;
        };
        shard_ids.push(shard_id);
    }
    shard_ids.sort_unstable();
    shard_ids.dedup();
    Ok(shard_ids)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::{repair_manifest, RepairManifestOptions};
    use std::path::Path;

    /// Build a shard with `count` sealed segments through the real append path,
    /// so the MANIFEST is byte-real rather than hand-assembled.
    fn build_shard(root: &Path, count: u64) {
        use corecrux_storage::{AppendEventInput, ShardStorage, ShardStorageOptions};
        let options = ShardStorageOptions {
            head_max_record_bytes: 0,
            ..Default::default()
        };
        for i in 0..count {
            let mut storage = ShardStorage::open(root, 0, 1, options.clone()).unwrap();
            let stream_hash = corecrux_frame::stream_hash_xxhash64("t", "corpus", &format!("doc-{i}")).unwrap();
            storage
                .append_batch(
                    stream_hash,
                    0,
                    "t",
                    "corpus",
                    &format!("doc-{i}"),
                    "2026-01-01T00:00:00Z",
                    &[AppendEventInput {
                        event_id: &format!("evt-{i}"),
                        occurred_at: "2026-01-01T00:00:00Z",
                        event_type: "test.event",
                        content_type: "text/plain",
                        payload_bytes: b"hello",
                    }],
                )
                .unwrap();
            storage.force_seal_head().unwrap();
        }
    }

    /// Delete a segment's file group behind the manifest's back — exactly what
    /// tenant-erasure reclaim did on host `crux`.
    fn unlink_segment_group(shard_dir: &Path, segment_seq: u64) {
        let segments = shard_dir.join("segments");
        let prefix = format!("seg-{segment_seq:020}-");
        for entry in std::fs::read_dir(&segments).unwrap().flatten() {
            let name = entry.file_name().to_str().unwrap().to_string();
            if name.starts_with(&prefix) {
                std::fs::remove_file(entry.path()).unwrap();
            }
        }
    }

    fn opts(dir: &Path, apply: bool) -> RepairManifestOptions {
        RepairManifestOptions {
            data_dir: dir.to_path_buf(),
            shard: Some(0),
            apply,
        }
    }

    #[test]
    fn healthy_shard_reports_no_dangling_entries() {
        let tmp = tempfile::TempDir::new().unwrap();
        build_shard(&tmp.path().join("shards"), 3);
        let report = repair_manifest(&opts(tmp.path(), false)).unwrap();
        assert!(report.healthy);
        assert_eq!(report.shards[0].manifest_segments, 3);
        assert_eq!(report.shards[0].dangling, 0);
    }

    #[test]
    fn dry_run_finds_the_dangling_entry_without_touching_the_manifest() {
        let tmp = tempfile::TempDir::new().unwrap();
        let shards = tmp.path().join("shards");
        build_shard(&shards, 3);
        let shard_dir = shards.join("shard-0000");
        unlink_segment_group(&shard_dir, 2);

        let before = std::fs::read(shard_dir.join("MANIFEST")).unwrap();
        let report = repair_manifest(&opts(tmp.path(), false)).unwrap();

        assert!(!report.healthy);
        assert_eq!(report.shards[0].dangling, 1);
        assert_eq!(report.shards[0].dangling_segments[0].segment_seq, 2);
        assert!(!report.shards[0].applied);
        assert_eq!(
            std::fs::read(shard_dir.join("MANIFEST")).unwrap(),
            before,
            "a dry run must not write"
        );
    }

    /// The point of the whole exercise: a shard that could not be opened at all
    /// opens again after the repair, and the repair only appends.
    #[test]
    fn apply_restores_a_shard_that_could_not_be_opened() {
        use corecrux_storage::{ShardStorage, ShardStorageOptions};
        let tmp = tempfile::TempDir::new().unwrap();
        let shards = tmp.path().join("shards");
        build_shard(&shards, 4);
        let shard_dir = shards.join("shard-0000");
        unlink_segment_group(&shard_dir, 2);

        let before = std::fs::read(shard_dir.join("MANIFEST")).unwrap();
        assert!(
            ShardStorage::open(&shards, 0, 1, ShardStorageOptions::default()).is_err(),
            "precondition: the dangling entry must break open()"
        );

        let report = repair_manifest(&opts(tmp.path(), true)).unwrap();
        assert_eq!(report.shards[0].retired, vec![2]);
        assert!(report.shards[0].manifest_end_after > report.shards[0].manifest_end_before);

        let after = std::fs::read(shard_dir.join("MANIFEST")).unwrap();
        assert_eq!(&after[..before.len()], &before[..], "repair must append, never rewrite");

        ShardStorage::open(&shards, 0, 1, ShardStorageOptions::default()).expect("shard opens after repair");

        let rescan = repair_manifest(&opts(tmp.path(), false)).unwrap();
        assert!(rescan.healthy);
        assert_eq!(rescan.shards[0].manifest_segments, 3, "the retired segment is gone");
    }

    #[test]
    fn apply_is_idempotent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let shards = tmp.path().join("shards");
        build_shard(&shards, 3);
        unlink_segment_group(&shards.join("shard-0000"), 2);

        repair_manifest(&opts(tmp.path(), true)).unwrap();
        let second = repair_manifest(&opts(tmp.path(), true)).unwrap();
        assert!(second.healthy);
        assert_eq!(second.shards[0].dangling, 0);
        assert!(second.shards[0].retired.is_empty());
    }

    #[test]
    fn an_empty_shards_dir_is_an_error_not_a_clean_bill_of_health() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("shards")).unwrap();
        let err = repair_manifest(&opts(tmp.path(), false)).expect_err("no shards scanned is not healthy");
        assert!(err.to_string().contains("no shards"), "{err}");
    }
}
