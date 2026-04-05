// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt as _;

use corecrux_types::{
    compute_shard_map_v1_blake3_hex, format_u64_hex, parse_shard_id_u32, parse_u64_hex,
    validate_shard_map_v1, HashRange, NodeAddr, ShardDescriptor, ShardMapV1, ShardState,
    SHARDMAP_HASH_FN_V1, SHARDMAP_KEY_ENCODING_V1,
};

pub fn init_dev_shard_map_v1(
    shard_count: u32,
    cluster_id: &str,
    node_id: &str,
    http_addr: &str,
    grpc_addr: &str,
    data_dir: Option<&Path>,
) -> corecrux_types::ShardMapResult<ShardMapV1> {
    let shard_count = shard_count.max(1);
    let created_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let ring_end: u128 = 1u128 << 64;
    let step: u128 = ring_end / (shard_count as u128);

    let mut shards: Vec<ShardDescriptor> = Vec::with_capacity(shard_count as usize);
    for i in 0..shard_count {
        let shard_num = i + 1;
        let shard_id = format!("shard-{shard_num:04}");

        let start = (step * (i as u128)) as u64;
        let end = if i == shard_count - 1 {
            0u64
        } else {
            (step * ((i + 1) as u128)) as u64
        };

        let data_dir =
            data_dir.map(|root| root.join("shards").join(&shard_id).display().to_string());

        shards.push(ShardDescriptor {
            shard_id,
            epoch: 1,
            state: ShardState::Active,
            ranges: vec![HashRange {
                start_inclusive: format_u64_hex(start),
                end_exclusive: format_u64_hex(end),
            }],
            leader: NodeAddr {
                node_id: node_id.to_string(),
                grpc_addr: grpc_addr.to_string(),
                http_addr: http_addr.to_string(),
            },
            followers: None,
            data_dir,
            gpu_id: None,
        });
    }

    let mut map = ShardMapV1 {
        v: 1,
        cluster_id: cluster_id.to_string(),
        version: 1,
        created_at,
        hash_fn: SHARDMAP_HASH_FN_V1.to_string(),
        key_encoding: SHARDMAP_KEY_ENCODING_V1.to_string(),
        shards,
        blake3: String::new(),
        prev_blake3: None,
    };
    map.blake3 = compute_shard_map_v1_blake3_hex(&map)?;
    validate_shard_map_v1(&map)?;
    Ok(map)
}

pub fn split_shard_map_v1(
    input: &ShardMapV1,
    shard_id: &str,
    at_hex: &str,
    new_shard_id: Option<String>,
) -> corecrux_types::ShardMapResult<ShardMapV1> {
    let mut out = input.clone();

    let at = parse_u64_hex(at_hex)?;

    let target_idx = out
        .shards
        .iter()
        .position(|s| s.shard_id == shard_id)
        .ok_or_else(|| corecrux_types::ShardMapError::Invalid {
            msg: format!("unknown shardId '{shard_id}'"),
        })?;

    // Allocate new shardId if not provided.
    let mut max_id: u32 = 0;
    for s in &out.shards {
        if let Ok(n) = parse_shard_id_u32(&s.shard_id) {
            max_id = max_id.max(n);
        }
    }
    let new_shard_id =
        new_shard_id.unwrap_or_else(|| format!("shard-{max_id_plus:04}", max_id_plus = max_id + 1));

    // Determine split range and snapshot target metadata before taking a mutable borrow.
    let (split_range_idx, old_end) = {
        let target = &out.shards[target_idx];
        let mut split_idx: Option<usize> = None;
        let mut old_end: u64 = 0;
        for (i, r) in target.ranges.iter().enumerate() {
            let start = parse_u64_hex(&r.start_inclusive)?;
            let end = parse_u64_hex(&r.end_exclusive)?;
            if start >= end {
                continue; // Skip wrap ranges for Phase 3 CLI.
            }
            if at > start && at < end {
                split_idx = Some(i);
                old_end = end;
                break;
            }
        }
        let Some(i) = split_idx else {
            return Err(corecrux_types::ShardMapError::Invalid {
                msg: format!(
                    "no splittable non-wrap range found in shard '{shard_id}' for at={at_hex}"
                ),
            });
        };
        (i, old_end)
    };

    let leader = out.shards[target_idx].leader.clone();
    let gpu_id = out.shards[target_idx].gpu_id;
    let target_data_dir = out.shards[target_idx].data_dir.clone();

    // Derive dataDir, if possible.
    let new_data_dir = target_data_dir.as_ref().and_then(|s| {
        let p = PathBuf::from(s);
        let base = p.parent()?;
        Some(base.join(&new_shard_id).display().to_string())
    });

    // Mutate the original range endExclusive to the split point.
    {
        let target = &mut out.shards[target_idx];
        target.ranges[split_range_idx].end_exclusive = format_u64_hex(at);
    }

    // New shard inherits leader addresses; epoch defaults to 1.
    let new_shard = ShardDescriptor {
        shard_id: new_shard_id,
        epoch: 1,
        state: ShardState::Active,
        ranges: vec![HashRange {
            start_inclusive: format_u64_hex(at),
            end_exclusive: format_u64_hex(old_end),
        }],
        leader,
        followers: None,
        data_dir: new_data_dir,
        gpu_id,
    };

    out.shards.push(new_shard);
    out.version = out.version.saturating_add(1);
    out.prev_blake3 = Some(input.blake3.clone());
    out.created_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    out.blake3 = compute_shard_map_v1_blake3_hex(&out)?;
    validate_shard_map_v1(&out)?;
    Ok(out)
}

pub fn set_shard_gpu_id_v1(
    input: &ShardMapV1,
    shard_id: &str,
    gpu_id: i32,
) -> corecrux_types::ShardMapResult<ShardMapV1> {
    if gpu_id < 0 {
        return Err(corecrux_types::ShardMapError::Invalid {
            msg: format!("gpu_id must be >= 0 (got {gpu_id})"),
        });
    }

    let mut out = input.clone();
    let mut found = false;
    for s in &mut out.shards {
        if s.shard_id == shard_id {
            s.gpu_id = Some(gpu_id);
            found = true;
        }
    }
    if !found {
        return Err(corecrux_types::ShardMapError::Invalid {
            msg: format!("unknown shardId '{shard_id}'"),
        });
    }

    out.version = out.version.saturating_add(1);
    out.prev_blake3 = Some(input.blake3.clone());
    out.created_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    out.blake3 = compute_shard_map_v1_blake3_hex(&out)?;
    validate_shard_map_v1(&out)?;
    Ok(out)
}

pub fn read_shard_map_v1(path: &Path) -> std::io::Result<ShardMapV1> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

pub fn write_shard_map_v1(path: &Path, map: &ShardMapV1) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(map)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    std::fs::write(path, bytes)?;
    Ok(())
}

pub fn publish_shard_map_v1(data_dir: &Path, map: &ShardMapV1) -> std::io::Result<()> {
    validate_shard_map_v1(map)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))?;

    let routing_dir = data_dir.join("meta").join("routing");
    let tmp_dir = routing_dir.join("tmp");
    create_dir_all(&tmp_dir)?;

    let lock_path = routing_dir.join("LOCK");
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)?;
    lock_file.lock_exclusive()?;

    let current_path = routing_dir.join("current");
    let current_version = if current_path.exists() {
        read_current_version(&current_path)?
    } else {
        0u64
    };

    if map.version != current_version + 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "shardmap version {} is not next version (current is {current_version})",
                map.version
            ),
        ));
    }

    if current_version > 0 {
        let prev_path = routing_dir.join(format!("shardmap.v{current_version:08}.json"));
        let prev = read_shard_map_v1(&prev_path)?;
        validate_shard_map_v1(&prev)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))?;
        if map.prev_blake3.as_deref() != Some(prev.blake3.as_str()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "prevBlake3 mismatch: expected {}, got {:?}",
                    prev.blake3, map.prev_blake3
                ),
            ));
        }
    }

    let bytes = serde_json::to_vec_pretty(map)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

    let version = map.version;
    let tmp_path = tmp_dir.join(format!("shardmap.v{version:08}.json.tmp"));
    let final_path = routing_dir.join(format!("shardmap.v{version:08}.json"));
    write_new_file_atomic(&tmp_path, &bytes)?;
    std::fs::rename(&tmp_path, &final_path)?;
    fsync_dir(&routing_dir);

    let current_tmp = tmp_dir.join("current.tmp");
    let current_bytes = format!("{version}\n").into_bytes();
    write_new_file_atomic(&current_tmp, &current_bytes)?;
    std::fs::rename(&current_tmp, &current_path)?;
    fsync_dir(&routing_dir);

    drop(lock_file);
    Ok(())
}

fn write_new_file_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)?;
    f.write_all(bytes)?;
    f.flush()?;
    f.sync_all()?;
    Ok(())
}

fn read_current_version(path: &Path) -> std::io::Result<u64> {
    let mut buf = String::new();
    File::open(path)?.read_to_string(&mut buf)?;
    let s = buf.trim();
    s.parse::<u64>().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid current version '{s}': {e}"),
        )
    })
}

fn fsync_dir(path: &Path) {
    #[cfg(unix)]
    {
        let Ok(dir) = File::open(path) else {
            return;
        };
        let _ = dir.sync_all();
    }
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_dev_shard_map_single_shard_covers_full_ring() {
        let map = init_dev_shard_map_v1(
            1,
            "dev",
            "node-dev",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            None,
        )
        .unwrap();
        assert_eq!(map.v, 1);
        assert_eq!(map.version, 1);
        assert_eq!(map.cluster_id, "dev");
        assert_eq!(map.shards.len(), 1);
        assert_eq!(map.shards[0].shard_id, "shard-0001");
        assert_eq!(map.shards[0].epoch, 1);
        assert_eq!(map.shards[0].ranges[0].start_inclusive, "0x0000000000000000");
        assert_eq!(map.shards[0].ranges[0].end_exclusive, "0x0000000000000000");
        assert!(map.prev_blake3.is_none());
        assert!(!map.blake3.is_empty());
        assert_eq!(map.shards[0].leader.node_id, "node-dev");
        assert_eq!(map.shards[0].leader.http_addr, "127.0.0.1:4006");
        assert_eq!(map.shards[0].leader.grpc_addr, "127.0.0.1:4007");
        assert!(map.shards[0].data_dir.is_none());
        assert!(map.shards[0].gpu_id.is_none());
    }

    #[test]
    fn init_dev_shard_map_multiple_shards_partition_ring() {
        let map = init_dev_shard_map_v1(
            4,
            "test-cluster",
            "node-1",
            "10.0.0.1:4006",
            "10.0.0.1:4007",
            None,
        )
        .unwrap();
        assert_eq!(map.shards.len(), 4);
        for (i, s) in map.shards.iter().enumerate() {
            assert_eq!(s.shard_id, format!("shard-{:04}", i + 1));
            assert_eq!(s.state, ShardState::Active);
            assert_eq!(s.epoch, 1);
        }
        // First shard starts at 0.
        assert_eq!(map.shards[0].ranges[0].start_inclusive, "0x0000000000000000");
        // Last shard wraps to 0.
        assert_eq!(
            map.shards[3].ranges[0].end_exclusive,
            "0x0000000000000000"
        );
        // Validation passes.
        validate_shard_map_v1(&map).unwrap();
    }

    #[test]
    fn init_dev_shard_map_with_data_dir() {
        let map = init_dev_shard_map_v1(
            2,
            "dev",
            "node-dev",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            Some(Path::new("/data/corecrux")),
        )
        .unwrap();
        assert_eq!(
            map.shards[0].data_dir.as_deref(),
            Some("/data/corecrux/shards/shard-0001")
        );
        assert_eq!(
            map.shards[1].data_dir.as_deref(),
            Some("/data/corecrux/shards/shard-0002")
        );
    }

    #[test]
    fn init_dev_shard_map_zero_count_becomes_one() {
        let map = init_dev_shard_map_v1(
            0,
            "dev",
            "node-dev",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            None,
        )
        .unwrap();
        assert_eq!(map.shards.len(), 1);
    }

    #[test]
    fn split_shard_map_creates_new_shard() {
        // For a 1-shard map, we need a 2-shard base to split (non-wrap range).
        let two = init_dev_shard_map_v1(
            2,
            "dev",
            "node-dev",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            Some(Path::new("/data")),
        )
        .unwrap();
        // shard-0001 range is [0, 0x8000000000000000). Split at midpoint.
        let split = split_shard_map_v1(&two, "shard-0001", "0x4000000000000000", None).unwrap();
        assert_eq!(split.shards.len(), 3);
        assert_eq!(split.version, 2);
        assert!(split.prev_blake3.is_some());
        // New shard should be shard-0003.
        let new_shard = split
            .shards
            .iter()
            .find(|s| s.shard_id == "shard-0003")
            .expect("new shard exists");
        assert_eq!(
            new_shard.ranges[0].start_inclusive,
            "0x4000000000000000"
        );
        assert_eq!(
            new_shard.ranges[0].end_exclusive,
            "0x8000000000000000"
        );
        // New shard inherits data_dir in correct location.
        assert!(new_shard.data_dir.as_ref().unwrap().contains("shard-0003"));
        validate_shard_map_v1(&split).unwrap();
    }

    #[test]
    fn split_shard_map_custom_new_shard_id() {
        let two = init_dev_shard_map_v1(
            2,
            "dev",
            "node-dev",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            None,
        )
        .unwrap();
        let split = split_shard_map_v1(
            &two,
            "shard-0001",
            "0x4000000000000000",
            Some("custom-shard".to_string()),
        )
        .unwrap();
        assert!(split
            .shards
            .iter()
            .any(|s| s.shard_id == "custom-shard"));
    }

    #[test]
    fn split_shard_map_unknown_shard_returns_error() {
        let map = init_dev_shard_map_v1(
            2,
            "dev",
            "node-dev",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            None,
        )
        .unwrap();
        let result = split_shard_map_v1(&map, "nonexistent", "0x4000000000000000", None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("nonexistent"));
    }

    #[test]
    fn split_shard_map_out_of_range_returns_error() {
        let two = init_dev_shard_map_v1(
            2,
            "dev",
            "node-dev",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            None,
        )
        .unwrap();
        // shard-0001 range is [0, 0x8000000000000000). 0xF... is out of this range.
        let result =
            split_shard_map_v1(&two, "shard-0001", "0xF000000000000000", None);
        assert!(result.is_err());
    }

    #[test]
    fn set_gpu_unknown_shard_returns_error() {
        let map = init_dev_shard_map_v1(
            1,
            "dev",
            "node-dev",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            None,
        )
        .unwrap();
        let result = set_shard_gpu_id_v1(&map, "nonexistent", 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonexistent"));
    }

    #[test]
    fn set_gpu_negative_returns_error() {
        let map = init_dev_shard_map_v1(
            1,
            "dev",
            "node-dev",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            None,
        )
        .unwrap();
        let result = set_shard_gpu_id_v1(&map, "shard-0001", -1);
        assert!(result.is_err());
    }

    #[test]
    fn write_and_read_shard_map_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("shard-map.json");
        let map = init_dev_shard_map_v1(
            2,
            "dev",
            "node-dev",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            None,
        )
        .unwrap();
        write_shard_map_v1(&path, &map).unwrap();
        let loaded = read_shard_map_v1(&path).unwrap();
        assert_eq!(loaded.blake3, map.blake3);
        assert_eq!(loaded.version, map.version);
        assert_eq!(loaded.shards.len(), map.shards.len());
    }

    #[test]
    fn publish_shard_map_writes_versioned_file_and_current() {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path();
        let map = init_dev_shard_map_v1(
            2,
            "dev",
            "node-dev",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            None,
        )
        .unwrap();
        publish_shard_map_v1(data_dir, &map).unwrap();
        let routing_dir = data_dir.join("meta").join("routing");
        let versioned = routing_dir.join("shardmap.v00000001.json");
        let current = routing_dir.join("current");
        assert!(versioned.exists());
        assert!(current.exists());
        let current_text = std::fs::read_to_string(&current).unwrap();
        assert_eq!(current_text.trim(), "1");
    }

    #[test]
    fn publish_shard_map_rejects_wrong_version() {
        let dir = tempfile::tempdir().expect("tempdir");
        let data_dir = dir.path();
        let mut map = init_dev_shard_map_v1(
            2,
            "dev",
            "node-dev",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            None,
        )
        .unwrap();
        // Version 1 should succeed, version 3 (skipping 2) should fail.
        publish_shard_map_v1(data_dir, &map).unwrap();
        map.version = 3;
        map.prev_blake3 = Some(map.blake3.clone());
        map.blake3 = corecrux_types::compute_shard_map_v1_blake3_hex(&map).unwrap();
        let result = publish_shard_map_v1(data_dir, &map);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not next version"));
    }

    #[test]
    fn set_gpu_bumps_version_and_sets_prev_hash() {
        let map = init_dev_shard_map_v1(
            2,
            "dev",
            "node-dev",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            None,
        )
        .unwrap();
        assert_eq!(map.version, 1);
        assert!(map.prev_blake3.is_none());
        assert!(map.blake3.len() >= 16);

        let out = set_shard_gpu_id_v1(&map, "shard-0001", 1).unwrap();
        assert_eq!(out.version, 2);
        assert_eq!(out.prev_blake3.as_deref(), Some(map.blake3.as_str()));

        let shard = out
            .shards
            .iter()
            .find(|s| s.shard_id == "shard-0001")
            .unwrap();
        assert_eq!(shard.gpu_id, Some(1));

        validate_shard_map_v1(&out).unwrap();
        assert_ne!(out.blake3, map.blake3);
    }
}
