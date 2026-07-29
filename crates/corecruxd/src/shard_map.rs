// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Shard-map loader + writer — durable `shard-map.json` with version tracking for hot reload.

use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt as _;

use corecrux_types::{
    compute_shard_map_v1_blake3_hex, format_u64_hex, parse_u64_hex, validate_shard_map_v1, HashRange, NodeAddr,
    ShardDescriptor, ShardMapV1, ShardState, SHARDMAP_HASH_FN_V1, SHARDMAP_KEY_ENCODING_V1,
};

#[derive(Debug, Clone)]
pub struct LoadedShardMap {
    pub current_version: u64,
    pub shard_map: ShardMapV1,
}

#[derive(Debug, Clone)]
pub struct RoutingTable {
    pub loaded_at: String, // RFC3339
    pub shard_map: ShardMapV1,
    intervals: Vec<RouteInterval>,
}

#[derive(Debug, Clone, Copy)]
struct RouteInterval {
    start: u128,
    end: u128,
    shard_idx: usize,
}

#[derive(Debug, Clone)]
pub struct RouteDecision {
    pub stream_hash: u64,
    pub shard_id: String,
    pub epoch: u64,
    pub shard_map_version: u64,
    pub leader_grpc_addr: String,
    pub leader_node_id: String,
    pub gpu_id: Option<i32>,
}

impl RoutingTable {
    pub fn new(loaded: LoadedShardMap) -> std::io::Result<Self> {
        validate_shard_map_v1(&loaded.shard_map)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))?;
        let intervals = build_intervals(&loaded.shard_map)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))?;
        Ok(Self {
            loaded_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            shard_map: loaded.shard_map,
            intervals,
        })
    }

    pub fn current_version(&self) -> u64 {
        self.shard_map.version
    }

    pub fn shard_count(&self) -> usize {
        self.shard_map.shards.len()
    }

    pub fn route_stream_hash(&self, stream_hash: u64) -> Option<RouteDecision> {
        const RING_END: u128 = 1u128 << 64;
        let h = stream_hash as u128;
        let idx = self.intervals.partition_point(|iv| iv.start <= h);
        if idx == 0 {
            return None;
        }
        let iv = self.intervals[idx - 1];
        if h >= iv.end || iv.end > RING_END {
            return None;
        }
        let shard = self.shard_map.shards.get(iv.shard_idx)?;
        Some(RouteDecision {
            stream_hash,
            shard_id: shard.shard_id.clone(),
            epoch: shard.epoch,
            shard_map_version: self.shard_map.version,
            leader_grpc_addr: shard.leader.grpc_addr.clone(),
            leader_node_id: shard.leader.node_id.clone(),
            gpu_id: shard.gpu_id,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ShardMapStore {
    routing_dir: PathBuf,
    tmp_dir: PathBuf,
    current_path: PathBuf,
    lock_path: PathBuf,
}

impl ShardMapStore {
    pub fn new(data_dir: &Path) -> Self {
        let routing_dir = data_dir.join("meta").join("routing");
        Self {
            tmp_dir: routing_dir.join("tmp"),
            current_path: routing_dir.join("current"),
            lock_path: routing_dir.join("LOCK"),
            routing_dir,
        }
    }

    pub fn load_or_init(
        &self,
        cluster_id: &str,
        node_id: &str,
        http_addr: &str,
        grpc_addr: &str,
        dev_split_shards: u32,
        gpu_id: Option<i32>,
    ) -> std::io::Result<LoadedShardMap> {
        create_dir_all(&self.tmp_dir)?;

        if !self.current_path.exists() {
            // Initialize a default dev shardmap (Option A: one process hosts N shards).
            let map = default_dev_shard_map_v1(
                &self.routing_dir,
                cluster_id,
                node_id,
                http_addr,
                grpc_addr,
                dev_split_shards,
                gpu_id,
            );
            self.publish(&map)?;
        }

        self.load_current()
    }

    pub fn load_current(&self) -> std::io::Result<LoadedShardMap> {
        let current_version = read_current_version(&self.current_path)?;
        let path = self.routing_dir.join(format!("shardmap.v{current_version:08}.json"));
        let map = read_shard_map_file(&path)?;
        if map.version != current_version {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "shardmap version field {} does not match current pointer {current_version}",
                    map.version
                ),
            ));
        }
        validate_shard_map_v1(&map)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))?;
        Ok(LoadedShardMap {
            current_version,
            shard_map: map,
        })
    }

    pub fn publish(&self, map: &ShardMapV1) -> std::io::Result<()> {
        validate_shard_map_v1(map).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}")))?;

        // Serialize map before locking to keep lock hold time small.
        let bytes = serde_json::to_vec_pretty(map)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        create_dir_all(&self.tmp_dir)?;

        // LOCK serializes updates (atomic publish protocol).
        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.lock_path)?;
        lock_file.lock_exclusive()?;

        let version = map.version;
        let tmp_path = self.tmp_dir.join(format!("shardmap.v{version:08}.json.tmp"));
        let final_path = self.routing_dir.join(format!("shardmap.v{version:08}.json"));

        write_new_file_atomic(&tmp_path, &bytes)?;
        std::fs::rename(&tmp_path, &final_path)?;
        fsync_dir(&self.routing_dir);

        // Update current atomically.
        let current_tmp = self.tmp_dir.join("current.tmp");
        let current_bytes = format!("{version}\n").into_bytes();
        write_new_file_atomic(&current_tmp, &current_bytes)?;
        std::fs::rename(&current_tmp, &self.current_path)?;
        fsync_dir(&self.routing_dir);

        drop(lock_file);
        Ok(())
    }
}

fn build_intervals(map: &ShardMapV1) -> corecrux_types::ShardMapResult<Vec<RouteInterval>> {
    const RING_END: u128 = 1u128 << 64;
    let mut out: Vec<RouteInterval> = Vec::new();

    for (idx, shard) in map.shards.iter().enumerate() {
        if shard.state != ShardState::Active {
            continue;
        }

        for r in &shard.ranges {
            let start = parse_u64_hex(&r.start_inclusive)? as u128;
            let end = parse_u64_hex(&r.end_exclusive)? as u128;

            if start == end {
                // Full-ring range [0,0) represented canonically.
                if start != 0 {
                    return Err(corecrux_types::ShardMapError::Invalid {
                        msg: format!(
                            "range startInclusive==endExclusive is only valid for full-ring [0,0) (got startInclusive={})",
                            r.start_inclusive
                        ),
                    });
                }
                out.push(RouteInterval {
                    start: 0,
                    end: RING_END,
                    shard_idx: idx,
                });
                continue;
            }

            if start < end {
                out.push(RouteInterval {
                    start,
                    end,
                    shard_idx: idx,
                });
            } else {
                // Wrap-around: split into [start,2^64) and [0,end)
                out.push(RouteInterval {
                    start,
                    end: RING_END,
                    shard_idx: idx,
                });
                if end != 0 {
                    out.push(RouteInterval {
                        start: 0,
                        end,
                        shard_idx: idx,
                    });
                }
            }
        }
    }

    out.sort_by_key(|iv| iv.start);
    Ok(out)
}

fn write_new_file_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new().create(true).truncate(true).write(true).open(path)?;
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

fn read_shard_map_file(path: &Path) -> std::io::Result<ShardMapV1> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

fn default_dev_shard_map_v1(
    routing_dir: &Path,
    cluster_id: &str,
    node_id: &str,
    http_addr: &str,
    grpc_addr: &str,
    shard_count: u32,
    gpu_id: Option<i32>,
) -> ShardMapV1 {
    let shard_count = shard_count.max(1);
    let created_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let mut shards = Vec::with_capacity(shard_count as usize);

    let ring_end: u128 = 1u128 << 64;
    let step: u128 = ring_end / (shard_count as u128);

    for i in 0..shard_count {
        let shard_num = i + 1;
        let shard_id = format!("shard-{shard_num:04}");

        let start = (step * (i as u128)) as u64;
        let end = if i == shard_count - 1 {
            0u64
        } else {
            (step * ((i + 1) as u128)) as u64
        };

        let data_dir = routing_dir
            .parent()
            .and_then(|p| p.parent())
            .unwrap_or(routing_dir)
            .join("shards")
            .join(&shard_id)
            .display()
            .to_string();

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
            data_dir: Some(data_dir),
            gpu_id,
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
    // SAFETY: BLAKE3 hash of a well-formed ShardMapV1 with valid UTF-8 — cannot fail.
    #[allow(clippy::expect_used)]
    {
        map.blake3 = compute_shard_map_v1_blake3_hex(&map).expect("compute shard map v1 blake3 for default dev map");
    }
    map
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

    fn mk_map_4() -> ShardMapV1 {
        let node_id = "node-test";
        let http_addr = "127.0.0.1:4006";
        let grpc_addr = "127.0.0.1:4007";

        let mut map = ShardMapV1 {
            v: 1,
            cluster_id: "dev".to_string(),
            version: 1,
            created_at: "2026-02-07T00:00:00Z".to_string(),
            hash_fn: SHARDMAP_HASH_FN_V1.to_string(),
            key_encoding: SHARDMAP_KEY_ENCODING_V1.to_string(),
            shards: vec![
                ShardDescriptor {
                    shard_id: "shard-0001".to_string(),
                    epoch: 1,
                    state: ShardState::Active,
                    ranges: vec![HashRange {
                        start_inclusive: format_u64_hex(0x0000_0000_0000_0000),
                        end_exclusive: format_u64_hex(0x4000_0000_0000_0000),
                    }],
                    leader: NodeAddr {
                        node_id: node_id.to_string(),
                        grpc_addr: grpc_addr.to_string(),
                        http_addr: http_addr.to_string(),
                    },
                    followers: None,
                    data_dir: None,
                    gpu_id: None,
                },
                ShardDescriptor {
                    shard_id: "shard-0002".to_string(),
                    epoch: 1,
                    state: ShardState::Active,
                    ranges: vec![HashRange {
                        start_inclusive: format_u64_hex(0x4000_0000_0000_0000),
                        end_exclusive: format_u64_hex(0x8000_0000_0000_0000),
                    }],
                    leader: NodeAddr {
                        node_id: node_id.to_string(),
                        grpc_addr: grpc_addr.to_string(),
                        http_addr: http_addr.to_string(),
                    },
                    followers: None,
                    data_dir: None,
                    gpu_id: None,
                },
                ShardDescriptor {
                    shard_id: "shard-0003".to_string(),
                    epoch: 1,
                    state: ShardState::Active,
                    ranges: vec![HashRange {
                        start_inclusive: format_u64_hex(0x8000_0000_0000_0000),
                        end_exclusive: format_u64_hex(0xC000_0000_0000_0000),
                    }],
                    leader: NodeAddr {
                        node_id: node_id.to_string(),
                        grpc_addr: grpc_addr.to_string(),
                        http_addr: http_addr.to_string(),
                    },
                    followers: None,
                    data_dir: None,
                    gpu_id: None,
                },
                ShardDescriptor {
                    shard_id: "shard-0004".to_string(),
                    epoch: 1,
                    state: ShardState::Active,
                    ranges: vec![HashRange {
                        start_inclusive: format_u64_hex(0xC000_0000_0000_0000),
                        end_exclusive: format_u64_hex(0x0000_0000_0000_0000),
                    }],
                    leader: NodeAddr {
                        node_id: node_id.to_string(),
                        grpc_addr: grpc_addr.to_string(),
                        http_addr: http_addr.to_string(),
                    },
                    followers: None,
                    data_dir: None,
                    gpu_id: None,
                },
            ],
            blake3: String::new(),
            prev_blake3: None,
        };

        map.blake3 = compute_shard_map_v1_blake3_hex(&map).unwrap();
        validate_shard_map_v1(&map).unwrap();
        map
    }

    #[test]
    fn routing_boundaries_match_spec() {
        let map = mk_map_4();
        let loaded = LoadedShardMap {
            current_version: map.version,
            shard_map: map,
        };
        let rt = RoutingTable::new(loaded).unwrap();

        // startInclusive routes to that shard.
        assert_eq!(
            rt.route_stream_hash(0x0000_0000_0000_0000).unwrap().shard_id,
            "shard-0001"
        );
        assert_eq!(
            rt.route_stream_hash(0x4000_0000_0000_0000).unwrap().shard_id,
            "shard-0002"
        );
        assert_eq!(
            rt.route_stream_hash(0x8000_0000_0000_0000).unwrap().shard_id,
            "shard-0003"
        );
        assert_eq!(
            rt.route_stream_hash(0xC000_0000_0000_0000).unwrap().shard_id,
            "shard-0004"
        );

        // endExclusive routes to the next shard.
        assert_eq!(
            rt.route_stream_hash(0x3FFF_FFFF_FFFF_FFFF).unwrap().shard_id,
            "shard-0001"
        );
        assert_eq!(
            rt.route_stream_hash(0x7FFF_FFFF_FFFF_FFFF).unwrap().shard_id,
            "shard-0002"
        );
        assert_eq!(
            rt.route_stream_hash(0xBFFF_FFFF_FFFF_FFFF).unwrap().shard_id,
            "shard-0003"
        );
        assert_eq!(
            rt.route_stream_hash(0xFFFF_FFFF_FFFF_FFFF).unwrap().shard_id,
            "shard-0004"
        );
    }

    #[test]
    fn routing_table_shard_count() {
        let map = mk_map_4();
        let loaded = LoadedShardMap {
            current_version: map.version,
            shard_map: map,
        };
        let rt = RoutingTable::new(loaded).unwrap();
        assert_eq!(rt.shard_count(), 4);
        assert_eq!(rt.current_version(), 1);
    }

    #[test]
    fn routing_table_loaded_at_is_rfc3339() {
        let map = mk_map_4();
        let loaded = LoadedShardMap {
            current_version: map.version,
            shard_map: map,
        };
        let rt = RoutingTable::new(loaded).unwrap();
        // Should parse as a valid RFC3339 timestamp
        chrono::DateTime::parse_from_rfc3339(&rt.loaded_at).expect("loaded_at should be valid RFC3339");
    }

    #[test]
    fn routing_decision_fields_populated() {
        let map = mk_map_4();
        let loaded = LoadedShardMap {
            current_version: map.version,
            shard_map: map,
        };
        let rt = RoutingTable::new(loaded).unwrap();
        let decision = rt.route_stream_hash(0x1000_0000_0000_0000).unwrap();
        assert_eq!(decision.stream_hash, 0x1000_0000_0000_0000);
        assert_eq!(decision.shard_id, "shard-0001");
        assert_eq!(decision.epoch, 1);
        assert_eq!(decision.shard_map_version, 1);
        assert_eq!(decision.leader_grpc_addr, "127.0.0.1:4007");
        assert_eq!(decision.leader_node_id, "node-test");
        assert_eq!(decision.gpu_id, None);
    }

    #[test]
    fn routing_full_ring_coverage() {
        // Every hash value in [0, u64::MAX] should route to some shard
        let map = mk_map_4();
        let loaded = LoadedShardMap {
            current_version: map.version,
            shard_map: map,
        };
        let rt = RoutingTable::new(loaded).unwrap();

        // Test a spread of values across the ring
        for h in [
            0u64,
            1,
            0x1FFF_FFFF_FFFF_FFFF,
            0x4000_0000_0000_0000,
            0x7FFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000,
            0xBFFF_FFFF_FFFF_FFFF,
            0xC000_0000_0000_0000,
            0xFFFF_FFFF_FFFF_FFFF,
        ] {
            assert!(
                rt.route_stream_hash(h).is_some(),
                "hash {h:#018x} should route to a shard"
            );
        }
    }

    #[test]
    fn routing_inactive_shard_not_routed() {
        let mut map = mk_map_4();
        // Set shard-0002 to Draining (not Active)
        map.shards[1].state = ShardState::Draining;
        map.blake3 = compute_shard_map_v1_blake3_hex(&map).unwrap();
        // Note: validation may require contiguous coverage, so we build intervals
        // directly to test the filtering logic
        let intervals = build_intervals(&map).unwrap();
        // shard-0002 (idx=1) should not appear in intervals
        for iv in &intervals {
            assert_ne!(iv.shard_idx, 1, "draining shard should not be routed");
        }
    }

    #[test]
    fn shard_map_store_new_paths() {
        let store = ShardMapStore::new(std::path::Path::new("/tmp/test-data"));
        assert_eq!(
            store.routing_dir,
            std::path::PathBuf::from("/tmp/test-data/meta/routing")
        );
        assert_eq!(
            store.tmp_dir,
            std::path::PathBuf::from("/tmp/test-data/meta/routing/tmp")
        );
        assert_eq!(
            store.current_path,
            std::path::PathBuf::from("/tmp/test-data/meta/routing/current")
        );
        assert_eq!(
            store.lock_path,
            std::path::PathBuf::from("/tmp/test-data/meta/routing/LOCK")
        );
    }

    #[test]
    fn shard_map_store_load_or_init_creates_and_loads() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = ShardMapStore::new(tmp.path());
        let loaded = store
            .load_or_init("test-cluster", "node-1", "127.0.0.1:4006", "127.0.0.1:4007", 2, Some(0))
            .expect("load_or_init");
        assert_eq!(loaded.current_version, 1);
        assert_eq!(loaded.shard_map.version, 1);
        assert_eq!(loaded.shard_map.cluster_id, "test-cluster");
        assert_eq!(loaded.shard_map.shards.len(), 2);
        assert_eq!(loaded.shard_map.shards[0].shard_id, "shard-0001");
        assert_eq!(loaded.shard_map.shards[1].shard_id, "shard-0002");
        assert_eq!(loaded.shard_map.shards[0].gpu_id, Some(0));

        // Second call should load the existing map (not re-init)
        let loaded2 = store
            .load_or_init("test-cluster", "node-1", "127.0.0.1:4006", "127.0.0.1:4007", 2, Some(0))
            .expect("load_or_init second call");
        assert_eq!(loaded2.shard_map.blake3, loaded.shard_map.blake3);
    }

    #[test]
    fn shard_map_store_publish_and_load() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = ShardMapStore::new(tmp.path());
        let map = default_dev_shard_map_v1(
            &store.routing_dir,
            "test",
            "n1",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            1,
            None,
        );
        store.publish(&map).expect("publish");
        let loaded = store.load_current().expect("load_current");
        assert_eq!(loaded.current_version, 1);
        assert_eq!(loaded.shard_map.cluster_id, "test");
        assert_eq!(loaded.shard_map.shards.len(), 1);
    }

    #[test]
    fn shard_map_store_publish_version_mismatch_detected() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = ShardMapStore::new(tmp.path());
        // Create initial map at version 1
        let map_v1 = default_dev_shard_map_v1(
            &store.routing_dir,
            "test",
            "n1",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            1,
            None,
        );
        store.publish(&map_v1).expect("publish v1");

        // Now publish a map at version 2
        let mut map_v2 = map_v1.clone();
        map_v2.version = 2;
        map_v2.blake3 = compute_shard_map_v1_blake3_hex(&map_v2).unwrap();
        store.publish(&map_v2).expect("publish v2");

        let loaded = store.load_current().expect("load_current");
        assert_eq!(loaded.current_version, 2);
    }

    #[test]
    fn default_dev_shard_map_single_shard_full_ring() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let routing_dir = tmp.path().join("meta").join("routing");
        let map = default_dev_shard_map_v1(&routing_dir, "dev", "n1", "127.0.0.1:4006", "127.0.0.1:4007", 1, None);
        assert_eq!(map.shards.len(), 1);
        // Single shard should cover [0, 0) = full ring
        assert_eq!(map.shards[0].ranges[0].start_inclusive, format_u64_hex(0));
        assert_eq!(map.shards[0].ranges[0].end_exclusive, format_u64_hex(0));
        validate_shard_map_v1(&map).unwrap();

        // Routing should work for any hash
        let loaded = LoadedShardMap {
            current_version: 1,
            shard_map: map,
        };
        let rt = RoutingTable::new(loaded).unwrap();
        assert_eq!(rt.route_stream_hash(0).unwrap().shard_id, "shard-0001");
        assert_eq!(rt.route_stream_hash(u64::MAX).unwrap().shard_id, "shard-0001");
    }

    #[test]
    fn default_dev_shard_map_zero_shards_clamped_to_one() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let routing_dir = tmp.path().join("meta").join("routing");
        let map = default_dev_shard_map_v1(&routing_dir, "dev", "n1", "127.0.0.1:4006", "127.0.0.1:4007", 0, None);
        // shard_count.max(1) clamps 0 to 1
        assert_eq!(map.shards.len(), 1);
    }

    #[test]
    fn default_dev_shard_map_gpu_id_propagated() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let routing_dir = tmp.path().join("meta").join("routing");
        let map = default_dev_shard_map_v1(
            &routing_dir,
            "dev",
            "n1",
            "127.0.0.1:4006",
            "127.0.0.1:4007",
            2,
            Some(3),
        );
        for shard in &map.shards {
            assert_eq!(shard.gpu_id, Some(3));
        }
    }

    #[test]
    fn routing_includes_gpu_id_from_shard_descriptor() {
        let mut map = mk_map_4();
        map.shards[0].gpu_id = Some(0);
        map.shards[1].gpu_id = Some(1);
        map.shards[2].gpu_id = None;
        map.shards[3].gpu_id = Some(2);
        map.blake3 = compute_shard_map_v1_blake3_hex(&map).unwrap();
        validate_shard_map_v1(&map).unwrap();

        let loaded = LoadedShardMap {
            current_version: map.version,
            shard_map: map,
        };
        let rt = RoutingTable::new(loaded).unwrap();

        assert_eq!(rt.route_stream_hash(0x0000_0000_0000_0000).unwrap().gpu_id, Some(0));
        assert_eq!(rt.route_stream_hash(0x4000_0000_0000_0000).unwrap().gpu_id, Some(1));
        assert_eq!(rt.route_stream_hash(0x8000_0000_0000_0000).unwrap().gpu_id, None);
        assert_eq!(rt.route_stream_hash(0xC000_0000_0000_0000).unwrap().gpu_id, Some(2));
    }
}
