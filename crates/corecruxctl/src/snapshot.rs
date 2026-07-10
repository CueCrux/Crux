// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Snapshot loader — opens a `.ccxs` snapshot via `corecrux-projections` and prints its contents.

use std::path::{Path, PathBuf};

use corecrux_projections::{load_projections_meta_v1, CcxsSnapshot};

#[derive(Debug, Clone)]
pub struct SnapshotOptions {
    pub data_dir: PathBuf,
    pub shard: Option<u32>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotProjectionListItem {
    pub projection: String,
    pub path: String,
    pub exists: bool,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_blake3: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotShardListItem {
    #[serde(rename = "shardId")]
    pub shard_id: u32,
    pub projections: Vec<SnapshotProjectionListItem>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotListReport {
    #[serde(rename = "dataDir")]
    pub data_dir: String,
    pub shards: Vec<SnapshotShardListItem>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotProjectionVerifyItem {
    pub projection: String,
    pub path: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_blake3: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual_blake3: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotShardVerifyItem {
    #[serde(rename = "shardId")]
    pub shard_id: u32,
    pub ok: bool,
    pub projections: Vec<SnapshotProjectionVerifyItem>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotVerifyReport {
    pub ok: bool,
    #[serde(rename = "dataDir")]
    pub data_dir: String,
    #[serde(rename = "failedShards")]
    pub failed_shards: u64,
    pub shards: Vec<SnapshotShardVerifyItem>,
}

fn list_shards(shard_root: &Path) -> Result<Vec<u32>, Box<dyn std::error::Error + Send + Sync>> {
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

#[derive(Debug, Clone, Copy)]
struct ProjectionDef {
    key: &'static str,
    file: &'static str,
}

const PROJECTIONS: [ProjectionDef; 4] = [
    ProjectionDef {
        key: "artifact_living_state",
        file: "artifact_living_state.snapshot.ccxs",
    },
    ProjectionDef {
        key: "artifact_relations",
        file: "artifact_relations.snapshot.ccxs",
    },
    ProjectionDef {
        key: "pressure_events",
        file: "pressure_events.snapshot.ccxs",
    },
    ProjectionDef {
        key: "artifact_dependents",
        file: "artifact_dependents.snapshot.ccxs",
    },
];

fn expected_hash_for_projection(meta: &corecrux_projections::ProjectionsMetaV1, key: &str) -> Option<String> {
    match key {
        "artifact_living_state" => meta.artifact_living_state.snapshot_blake3.clone(),
        "artifact_relations" => meta.artifact_relations.snapshot_blake3.clone(),
        "pressure_events" => meta.pressure_events.snapshot_blake3.clone(),
        "artifact_dependents" => meta.artifact_dependents.snapshot_blake3.clone(),
        _ => None,
    }
}

fn shard_ids(opts: &SnapshotOptions) -> Result<Vec<u32>, Box<dyn std::error::Error + Send + Sync>> {
    let shard_root = opts.data_dir.join("shards");
    let ids = if let Some(id) = opts.shard {
        vec![id]
    } else {
        list_shards(&shard_root)?
    };
    Ok(ids)
}

pub fn list_snapshots(opts: &SnapshotOptions) -> Result<SnapshotListReport, Box<dyn std::error::Error + Send + Sync>> {
    let mut shards: Vec<SnapshotShardListItem> = Vec::new();
    for shard_id in shard_ids(opts)? {
        let shard_dir = opts.data_dir.join("shards").join(format!("shard-{shard_id:04}"));
        let projections_dir = shard_dir.join("projections");
        let meta_path = projections_dir.join("projections.meta.json");
        let meta = load_projections_meta_v1(&meta_path)?;

        let mut projections = Vec::new();
        for p in PROJECTIONS {
            let path = projections_dir.join(p.file);
            let exists = path.exists();
            let bytes = if exists {
                std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0)
            } else {
                0
            };
            projections.push(SnapshotProjectionListItem {
                projection: p.key.to_string(),
                path: path.display().to_string(),
                exists,
                bytes,
                expected_blake3: expected_hash_for_projection(&meta, p.key),
            });
        }

        shards.push(SnapshotShardListItem { shard_id, projections });
    }

    Ok(SnapshotListReport {
        data_dir: opts.data_dir.display().to_string(),
        shards,
    })
}

pub fn verify_snapshots(
    opts: &SnapshotOptions,
) -> Result<SnapshotVerifyReport, Box<dyn std::error::Error + Send + Sync>> {
    let mut failed_shards = 0u64;
    let mut out_shards = Vec::new();

    for shard_id in shard_ids(opts)? {
        let shard_dir = opts.data_dir.join("shards").join(format!("shard-{shard_id:04}"));
        let projections_dir = shard_dir.join("projections");
        let meta_path = projections_dir.join("projections.meta.json");
        let meta = load_projections_meta_v1(&meta_path)?;

        let mut projection_reports = Vec::new();
        let mut shard_ok = true;
        for p in PROJECTIONS {
            let path = projections_dir.join(p.file);
            let expected = expected_hash_for_projection(&meta, p.key);
            let mut item = SnapshotProjectionVerifyItem {
                projection: p.key.to_string(),
                path: path.display().to_string(),
                ok: true,
                reason: None,
                expected_blake3: expected.clone(),
                actual_blake3: None,
            };

            if expected.is_none() || !path.exists() {
                item.ok = false;
                item.reason = Some("MISSING_SNAPSHOT".to_string());
            } else {
                let bytes = std::fs::read(&path)?;
                let actual = CcxsSnapshot::snapshot_blake3_hex(&bytes);
                item.actual_blake3 = Some(actual.clone());
                if Some(actual) != expected {
                    item.ok = false;
                    item.reason = Some("SNAPSHOT_HASH_MISMATCH".to_string());
                }
            }

            if !item.ok {
                shard_ok = false;
            }
            projection_reports.push(item);
        }

        if !shard_ok {
            failed_shards = failed_shards.saturating_add(1);
        }
        out_shards.push(SnapshotShardVerifyItem {
            shard_id,
            ok: shard_ok,
            projections: projection_reports,
        });
    }

    Ok(SnapshotVerifyReport {
        ok: failed_shards == 0,
        data_dir: opts.data_dir.display().to_string(),
        failed_shards,
        shards: out_shards,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ── list_shards ──────────────────────────────────────────────────

    #[test]
    fn list_shards_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let ids = list_shards(tmp.path()).unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn list_shards_sorted_and_deduped() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir(tmp.path().join("shard-0002")).unwrap();
        fs::create_dir(tmp.path().join("shard-0000")).unwrap();
        fs::create_dir(tmp.path().join("shard-0005")).unwrap();
        // Non-shard entries
        fs::create_dir(tmp.path().join("other")).unwrap();
        fs::write(tmp.path().join("shard-file"), b"nope").unwrap();

        let ids = list_shards(tmp.path()).unwrap();
        assert_eq!(ids, vec![0, 2, 5]);
    }

    // ── PROJECTIONS constant ─────────────────────────────────────────

    #[test]
    fn projections_constant_has_four_entries() {
        assert_eq!(PROJECTIONS.len(), 4);
        let keys: Vec<&str> = PROJECTIONS.iter().map(|p| p.key).collect();
        assert!(keys.contains(&"artifact_living_state"));
        assert!(keys.contains(&"artifact_relations"));
        assert!(keys.contains(&"pressure_events"));
        assert!(keys.contains(&"artifact_dependents"));
    }

    // ── expected_hash_for_projection ─────────────────────────────────

    #[test]
    fn expected_hash_known_keys() {
        let mut meta = corecrux_projections::ProjectionsMetaV1::empty_now();
        meta.artifact_living_state.snapshot_blake3 = Some("abc123".to_string());
        meta.artifact_relations.snapshot_blake3 = Some("def456".to_string());
        meta.pressure_events.snapshot_blake3 = Some("ghi789".to_string());
        meta.artifact_dependents.snapshot_blake3 = Some("jkl012".to_string());

        assert_eq!(
            expected_hash_for_projection(&meta, "artifact_living_state"),
            Some("abc123".to_string())
        );
        assert_eq!(
            expected_hash_for_projection(&meta, "artifact_relations"),
            Some("def456".to_string())
        );
        assert_eq!(
            expected_hash_for_projection(&meta, "pressure_events"),
            Some("ghi789".to_string())
        );
        assert_eq!(
            expected_hash_for_projection(&meta, "artifact_dependents"),
            Some("jkl012".to_string())
        );
    }

    #[test]
    fn expected_hash_unknown_key_returns_none() {
        let meta = corecrux_projections::ProjectionsMetaV1::empty_now();
        assert_eq!(expected_hash_for_projection(&meta, "nonexistent"), None);
    }

    // ── shard_ids helper ─────────────────────────────────────────────

    #[test]
    fn shard_ids_explicit_shard() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("shards")).unwrap();
        let opts = SnapshotOptions {
            data_dir: tmp.path().to_path_buf(),
            shard: Some(42),
        };
        let ids = shard_ids(&opts).unwrap();
        assert_eq!(ids, vec![42]);
    }

    #[test]
    fn shard_ids_scans_dir() {
        let tmp = TempDir::new().unwrap();
        let shards_dir = tmp.path().join("shards");
        fs::create_dir_all(shards_dir.join("shard-0001")).unwrap();
        fs::create_dir_all(shards_dir.join("shard-0003")).unwrap();
        let opts = SnapshotOptions {
            data_dir: tmp.path().to_path_buf(),
            shard: None,
        };
        let ids = shard_ids(&opts).unwrap();
        assert_eq!(ids, vec![1, 3]);
    }

    // ── Data structure serialization ─────────────────────────────────

    #[test]
    fn snapshot_list_report_roundtrip() {
        let report = SnapshotListReport {
            data_dir: "/data".to_string(),
            shards: vec![SnapshotShardListItem {
                shard_id: 0,
                projections: vec![SnapshotProjectionListItem {
                    projection: "artifact_living_state".to_string(),
                    path: "/data/shards/shard-0000/projections/artifact_living_state.snapshot.ccxs".to_string(),
                    exists: true,
                    bytes: 1024,
                    expected_blake3: Some("abc".to_string()),
                }],
            }],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: SnapshotListReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.data_dir, "/data");
        assert_eq!(parsed.shards.len(), 1);
        assert_eq!(parsed.shards[0].shard_id, 0);
        assert_eq!(parsed.shards[0].projections.len(), 1);
        assert_eq!(parsed.shards[0].projections[0].bytes, 1024);
    }

    #[test]
    fn snapshot_verify_report_roundtrip() {
        let report = SnapshotVerifyReport {
            ok: false,
            data_dir: "/data".to_string(),
            failed_shards: 1,
            shards: vec![SnapshotShardVerifyItem {
                shard_id: 0,
                ok: false,
                projections: vec![SnapshotProjectionVerifyItem {
                    projection: "artifact_living_state".to_string(),
                    path: "/p".to_string(),
                    ok: false,
                    reason: Some("MISSING_SNAPSHOT".to_string()),
                    expected_blake3: None,
                    actual_blake3: None,
                }],
            }],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: SnapshotVerifyReport = serde_json::from_str(&json).unwrap();
        assert!(!parsed.ok);
        assert_eq!(parsed.failed_shards, 1);
    }

    #[test]
    fn snapshot_projection_verify_item_omits_none_fields() {
        let item = SnapshotProjectionVerifyItem {
            projection: "x".to_string(),
            path: "/x".to_string(),
            ok: true,
            reason: None,
            expected_blake3: None,
            actual_blake3: None,
        };
        let json = serde_json::to_string(&item).unwrap();
        assert!(!json.contains("reason"));
        assert!(!json.contains("expected_blake3"));
        assert!(!json.contains("actual_blake3"));
    }

    // ── list_snapshots with meta file ────────────────────────────────

    #[test]
    fn list_snapshots_no_shard_dirs() {
        let tmp = TempDir::new().unwrap();
        fs::create_dir_all(tmp.path().join("shards")).unwrap();
        let opts = SnapshotOptions {
            data_dir: tmp.path().to_path_buf(),
            shard: None,
        };
        let report = list_snapshots(&opts).unwrap();
        assert!(report.shards.is_empty());
    }

    #[test]
    fn list_snapshots_reads_meta_and_files() {
        let tmp = TempDir::new().unwrap();
        let shard_dir = tmp.path().join("shards").join("shard-0000");
        let proj_dir = shard_dir.join("projections");
        fs::create_dir_all(&proj_dir).unwrap();

        // Write empty meta (will use defaults)
        let meta = corecrux_projections::ProjectionsMetaV1::empty_now();
        let meta_json = serde_json::to_vec_pretty(&meta).unwrap();
        fs::write(proj_dir.join("projections.meta.json"), &meta_json).unwrap();

        // Create one snapshot file
        fs::write(
            proj_dir.join("artifact_living_state.snapshot.ccxs"),
            b"fake snapshot data",
        )
        .unwrap();

        let opts = SnapshotOptions {
            data_dir: tmp.path().to_path_buf(),
            shard: Some(0),
        };
        let report = list_snapshots(&opts).unwrap();
        assert_eq!(report.shards.len(), 1);
        assert_eq!(report.shards[0].shard_id, 0);
        assert_eq!(report.shards[0].projections.len(), 4);

        // The one we created should exist
        let als = &report.shards[0].projections[0];
        assert_eq!(als.projection, "artifact_living_state");
        assert!(als.exists);
        assert!(als.bytes > 0);

        // The others should not exist
        assert!(!report.shards[0].projections[1].exists);
    }
}
