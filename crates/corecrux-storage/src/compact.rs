// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Directory LSM compaction — merges DirExtent runs, emits `DirCompactionEventV1`, maintains directory-level stats.

use super::{
    decode_dir_run_v1, fsync_dir, io_err, merge_dir_extents_partition_sorted_unique_cpu, BTreeMap,
    DirCompactionEventV1, DirExtentV1, DirRunKey, DirRunMeta, DirectoryLevelStatsV1, DirectoryLsmStatsV1, Result,
    ShardStorage, StorageError, DIRRUN_PARTITIONS_V1,
};

impl ShardStorage {
    pub fn directory_lsm_stats_v1(&self) -> DirectoryLsmStatsV1 {
        let mut by_level: BTreeMap<u32, (u32, u64)> = BTreeMap::new();
        for r in self.dir_runs.values() {
            let e = by_level.entry(r.key.level).or_insert((0, 0));
            e.0 = e.0.saturating_add(1);
            e.1 = e.1.saturating_add(r.file_len);
        }

        let mut levels: Vec<DirectoryLevelStatsV1> = Vec::with_capacity(by_level.len());
        for (level, (run_count, bytes)) in by_level {
            levels.push(DirectoryLevelStatsV1 {
                level,
                run_count,
                bytes,
            });
        }
        DirectoryLsmStatsV1 { levels }
    }

    #[allow(clippy::unused_self)] // Method on ShardStorage for API consistency; will use self in future compaction state
    pub(crate) fn derive_compacted_run_id_v1(&self, level_out: u32, a: DirRunKey, b: DirRunKey) -> u64 {
        let (k1, k2) = if (a.level, a.run_id) <= (b.level, b.run_id) {
            (a, b)
        } else {
            (b, a)
        };
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"corecrux-dirrun-merge-v1");
        hasher.update(&level_out.to_le_bytes());
        hasher.update(&k1.level.to_le_bytes());
        hasher.update(&k1.run_id.to_le_bytes());
        hasher.update(&k2.level.to_le_bytes());
        hasher.update(&k2.run_id.to_le_bytes());
        let digest = hasher.finalize();
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&digest.as_bytes()[0..8]);
        u64::from_le_bytes(buf)
    }

    pub fn compact_directory_until_within_limits(&mut self) -> Result<Vec<DirCompactionEventV1>> {
        if !self.options.enable_directory_compaction {
            return Ok(Vec::new());
        }
        let max_runs_per_level = self.options.dir_l0_max_runs.max(1);
        let mut events: Vec<DirCompactionEventV1> = Vec::new();
        loop {
            let mut levels: Vec<u32> = self.dir_runs.keys().map(|k| k.level).collect();
            levels.sort_unstable();
            levels.dedup();

            let mut did_work = false;
            for level in levels {
                let mut runs: Vec<DirRunMeta> = self
                    .dir_runs
                    .values()
                    .filter(|r| r.key.level == level)
                    .cloned()
                    .collect();
                if runs.len() <= max_runs_per_level {
                    continue;
                }
                if runs.len() < 2 {
                    continue;
                }
                runs.sort_by_key(|r| r.key.run_id);
                let a = runs[0].clone();
                let b = runs[1].clone();
                events.push(self.compact_dir_run_pair_v1(&a, &b)?);
                did_work = true;
                break;
            }
            if !did_work {
                break;
            }
        }

        if !events.is_empty() {
            let _ = self.rebuild_directory_from_runs()?;
        }
        Ok(events)
    }

    pub(crate) fn compact_dir_run_pair_v1(&mut self, a: &DirRunMeta, b: &DirRunMeta) -> Result<DirCompactionEventV1> {
        let start = std::time::Instant::now();
        if a.key.level != b.key.level {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "dirrun compaction requires same-level inputs".to_string(),
            });
        }
        let level_out = a.key.level.saturating_add(1);

        let a_path = self.paths.shard_dir.join(&a.relative_path);
        let b_path = self.paths.shard_dir.join(&b.relative_path);
        let a_bytes = std::fs::read(&a_path).map_err(io_err)?;
        let b_bytes = std::fs::read(&b_path).map_err(io_err)?;
        let a_dec = decode_dir_run_v1(&a_bytes)?;
        let b_dec = decode_dir_run_v1(&b_bytes)?;

        let mut merged_all: Vec<DirExtentV1> = Vec::new();
        let mut input_extents: u64 = 0;
        let mut dropped_extents: u64 = 0;
        for pid in 0..DIRRUN_PARTITIONS_V1 {
            let pa = &a_dec.partitions[pid];
            let pb = &b_dec.partitions[pid];
            let mut merged = merge_dir_extents_partition_sorted_unique_cpu(pa, pb);
            let before = merged.len() as u64;
            merged.retain(|e| e.max_seq >= self.stream_cut_seq(e.stream_hash));
            let after = merged.len() as u64;
            input_extents = input_extents.saturating_add(before);
            dropped_extents = dropped_extents.saturating_add(before.saturating_sub(after));
            merged_all.extend_from_slice(&merged);
        }

        let created_at_unix_ns = a.created_at_unix_ns.max(b.created_at_unix_ns);
        let bytes_in = a.file_len.saturating_add(b.file_len);
        let mut bytes_out: u64 = 0;
        if !merged_all.is_empty() {
            let mut run_id = self.derive_compacted_run_id_v1(level_out, a.key, b.key);
            // Deterministic collision resolution (extremely unlikely).
            while self.dir_runs.contains_key(&DirRunKey {
                level: level_out,
                run_id,
            }) {
                run_id = run_id.wrapping_add(1);
            }
            let out_key = DirRunKey {
                level: level_out,
                run_id,
            };
            if let Some(meta) = self.publish_dir_run_v1(out_key, created_at_unix_ns, &merged_all)? {
                bytes_out = meta.file_len;
            }
        }

        // Publish removals after the replacement run is durable+referenced.
        self.append_manifest_remove_dir_run(a.key)?;
        self.append_manifest_remove_dir_run(b.key)?;
        self.dir_runs.remove(&a.key);
        self.dir_runs.remove(&b.key);

        // Best-effort cleanup of old files.
        let _ = std::fs::remove_file(&a_path);
        let _ = std::fs::remove_file(&b_path);
        let _ = fsync_dir(&self.paths.directory_dir);

        Ok(DirCompactionEventV1 {
            level_from: a.key.level,
            level_to: level_out,
            duration_ns: start.elapsed().as_nanos().min(u64::MAX as u128) as u64,
            bytes_in,
            bytes_out,
            input_extents,
            dropped_extents,
        })
    }
}
