// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Index manager — loads .ccxi files and maintains a tiered index for query.
//!
//! Tiers:
//! - Hot: most recent segments, held in memory
//! - Warm: older segments, held in host RAM
//! - Cold: superseded segments on NVMe, loaded on demand

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use corecrux_index::CcxiReader;

/// Memory tier for a loaded segment index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexTier {
    /// Most recent segments — kept in hot tier for fast access.
    Hot,
    /// Older segments — host RAM only.
    Warm,
    /// On-disk, load on demand (not yet loaded).
    Cold,
}

/// Manages loaded .ccxi indexes across multiple sealed segments.
pub struct IndexManager {
    /// segment_seq → loaded CcxiReader
    segments: BTreeMap<u64, LoadedSegment>,
    /// Maximum bytes of index data to keep in hot tier (memory budget).
    hot_budget_bytes: usize,
    /// Current hot tier usage in bytes.
    hot_bytes: usize,
    /// Minimum time a segment must stay in Hot tier before eviction (prevents thrashing).
    min_residency: std::time::Duration,
    /// Count of evictions since startup (for metrics).
    eviction_count: u64,
}

struct LoadedSegment {
    reader: CcxiReader,
    /// Source `.ccxi` path. Empty for segments loaded from bytes.
    path: PathBuf,
    tier: IndexTier,
    size_bytes: usize,
    /// When this segment was last promoted to Hot tier.
    promoted_at: Option<Instant>,
}

impl IndexManager {
    pub fn new() -> Self {
        Self {
            segments: BTreeMap::new(),
            hot_budget_bytes: 4 * 1024 * 1024 * 1024, // 4GB default
            hot_bytes: 0,
            min_residency: std::time::Duration::from_secs(60),
            eviction_count: 0,
        }
    }

    /// Set the minimum residency time for hot-tier segments (prevents thrashing).
    pub fn set_min_residency(&mut self, dur: std::time::Duration) {
        self.min_residency = dur;
    }

    /// Number of evictions since startup (for Prometheus metrics).
    pub fn eviction_count(&self) -> u64 {
        self.eviction_count
    }

    /// Set the memory budget for hot tier (bytes).
    pub fn set_hot_budget(&mut self, bytes: usize) {
        self.hot_budget_bytes = bytes;
        self.rebalance_tiers();
    }

    /// Load a .ccxi file from disk.
    pub fn load_ccxi(&mut self, path: &Path) -> crate::Result<u64> {
        let data = std::fs::read(path)?;
        let size = data.len();
        let reader = CcxiReader::from_bytes(&data)?;
        let seq = reader.header.segment_seq;

        let (tier, promoted_at) = if self.hot_bytes + size <= self.hot_budget_bytes {
            self.hot_bytes += size;
            (IndexTier::Hot, Some(Instant::now()))
        } else {
            (IndexTier::Warm, None)
        };

        self.segments.insert(
            seq,
            LoadedSegment {
                reader,
                path: path.to_path_buf(),
                tier,
                size_bytes: size,
                promoted_at,
            },
        );
        Ok(seq)
    }

    /// Load a .ccxi from raw bytes (for testing).
    pub fn load_ccxi_bytes(&mut self, data: &[u8]) -> crate::Result<u64> {
        let size = data.len();
        let reader = CcxiReader::from_bytes(data)?;
        let seq = reader.header.segment_seq;
        self.segments.insert(
            seq,
            LoadedSegment {
                reader,
                path: PathBuf::new(),
                tier: IndexTier::Hot,
                size_bytes: size,
                promoted_at: Some(Instant::now()),
            },
        );
        self.hot_bytes += size;
        Ok(seq)
    }

    /// Get all loaded readers (for multi-segment scoring).
    pub fn readers(&self) -> Vec<&CcxiReader> {
        self.segments.values().map(|s| &s.reader).collect()
    }

    /// Get readers filtered by tier.
    pub fn readers_by_tier(&self, tier: IndexTier) -> Vec<&CcxiReader> {
        self.segments
            .values()
            .filter(|s| s.tier == tier)
            .map(|s| &s.reader)
            .collect()
    }

    /// Total number of documents across all loaded segments.
    pub fn total_docs(&self) -> usize {
        self.segments.values().map(|s| s.reader.docs.len()).sum()
    }

    /// Number of loaded segments.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Tier statistics.
    pub fn tier_stats(&self) -> TierStats {
        let mut stats = TierStats::default();
        for seg in self.segments.values() {
            match seg.tier {
                IndexTier::Hot => {
                    stats.hot_segments += 1;
                    stats.hot_docs += seg.reader.docs.len();
                    stats.hot_bytes += seg.size_bytes;
                }
                IndexTier::Warm => {
                    stats.warm_segments += 1;
                    stats.warm_docs += seg.reader.docs.len();
                    stats.warm_bytes += seg.size_bytes;
                }
                IndexTier::Cold => {
                    stats.cold_segments += 1;
                }
            }
        }
        stats.hot_budget_bytes = self.hot_budget_bytes;
        stats
    }

    /// Scan a directory for .ccxi files and load them all.
    pub fn scan_and_load(&mut self, dir: &Path) -> crate::Result<usize> {
        let mut count = 0;
        if !dir.exists() {
            return Ok(0);
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "ccxi") {
                // Skip if already loaded
                if let Some(seq_str) = path.file_stem().and_then(|s| s.to_str()) {
                    if let Some(seq) = extract_segment_seq(seq_str) {
                        if self.segments.contains_key(&seq) {
                            continue;
                        }
                    }
                }
                match self.load_ccxi(&path) {
                    Ok(_) => count += 1,
                    Err(e) => {
                        tracing::warn!("failed to load .ccxi {:?}: {}", path, e);
                    }
                }
            }
        }
        Ok(count)
    }

    /// Rebalance tiers based on hot tier memory budget.
    /// Newest segments get Hot priority, oldest get demoted to Warm.
    /// Segments promoted within `min_residency` are protected from eviction.
    fn rebalance_tiers(&mut self) {
        let now = Instant::now();

        // Reset hot bytes counter
        self.hot_bytes = 0;

        // Iterate segments newest-first (BTreeMap is ordered by key = segment_seq)
        let seqs: Vec<u64> = self.segments.keys().rev().copied().collect();
        for seq in seqs {
            if let Some(seg) = self.segments.get_mut(&seq) {
                if self.hot_bytes + seg.size_bytes <= self.hot_budget_bytes {
                    if seg.tier != IndexTier::Hot {
                        seg.promoted_at = Some(now);
                    }
                    seg.tier = IndexTier::Hot;
                    self.hot_bytes += seg.size_bytes;
                } else {
                    // Cooldown: don't evict segments that were recently promoted
                    let protected = seg.tier == IndexTier::Hot
                        && seg
                            .promoted_at
                            .is_some_and(|t| now.duration_since(t) < self.min_residency);
                    if protected {
                        // Keep in hot tier despite budget pressure
                        self.hot_bytes += seg.size_bytes;
                    } else {
                        if seg.tier == IndexTier::Hot {
                            self.eviction_count += 1;
                        }
                        seg.tier = IndexTier::Warm;
                        seg.promoted_at = None;
                    }
                }
            }
        }
    }
}

/// One segment's contribution to a tenant's on-disk corpus footprint.
///
/// Tenant membership is read from the `.ccxi` doc table (`tenant_hash_full`),
/// so a footprint never touches segment frames.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SegmentFootprint {
    pub segment_seq: u64,
    pub docs_total: usize,
    pub docs_tenant: usize,
    /// Size of the whole segment file group — every file sharing the `.ccxi`
    /// stem (`.ccxseg`, `.ccxi`, `.ccxv`, `.ccxp`). Zero for segments loaded
    /// from bytes rather than from disk.
    pub bytes: u64,
    /// Every doc in the segment belongs to this tenant — the precondition for
    /// reclaiming the file group wholesale.
    pub whole_tenant: bool,
}

/// A tenant's retrieval-corpus footprint across all loaded segments.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TenantFootprint {
    pub segments: Vec<SegmentFootprint>,
    pub docs: usize,
    pub bytes: u64,
    /// Segments the tenant shares with at least one other tenant. These cannot
    /// be reclaimed by deleting the file group.
    pub mixed_segments: usize,
}

impl IndexManager {
    /// Read-only inventory of the segments holding `tenant_hash`'s documents.
    ///
    /// Segments with no docs for the tenant are omitted. `bytes` is the size of
    /// the on-disk file group, so the reported total is what a reclaim would
    /// actually free.
    pub fn tenant_footprint(&self, tenant_hash: u64) -> TenantFootprint {
        let mut out = TenantFootprint::default();
        let mut hits: Vec<(u64, usize, usize, Option<PathBuf>)> = Vec::new();
        for (&seq, seg) in &self.segments {
            let docs_total = seg.reader.docs.len();
            let docs_tenant = seg
                .reader
                .docs
                .iter()
                .filter(|d| d.tenant_hash_full == tenant_hash)
                .count();
            if docs_tenant == 0 {
                continue;
            }
            let path = (!seg.path.as_os_str().is_empty()).then(|| seg.path.clone());
            hits.push((seq, docs_total, docs_tenant, path));
        }

        let group_sizes = segment_group_sizes(hits.iter().filter_map(|(_, _, _, p)| p.as_deref()));
        for (segment_seq, docs_total, docs_tenant, path) in hits {
            let bytes = path.as_deref().and_then(|p| group_sizes.get(p).copied()).unwrap_or(0);
            let whole_tenant = docs_tenant == docs_total;
            if !whole_tenant {
                out.mixed_segments += 1;
            }
            out.docs += docs_tenant;
            out.bytes += bytes;
            out.segments.push(SegmentFootprint {
                segment_seq,
                docs_total,
                docs_tenant,
                bytes,
                whole_tenant,
            });
        }
        out
    }
}

/// Total bytes of each segment's file group, keyed by its `.ccxi` path.
///
/// One `read_dir` per distinct parent directory rather than per segment — a
/// footprint over a 47-segment corpus is a single directory listing.
fn segment_group_sizes<'a, I: Iterator<Item = &'a Path>>(paths: I) -> std::collections::HashMap<PathBuf, u64> {
    let mut wanted: std::collections::HashMap<PathBuf, Vec<(PathBuf, String)>> = std::collections::HashMap::new();
    for path in paths {
        let (Some(dir), Some(stem)) = (path.parent(), path.file_stem().and_then(|s| s.to_str())) else {
            continue;
        };
        wanted
            .entry(dir.to_path_buf())
            .or_default()
            .push((path.to_path_buf(), stem.to_string()));
    }

    let mut out = std::collections::HashMap::new();
    for (dir, members) in wanted {
        let mut by_stem: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                // `.ccxv.partial` and friends stem to "seg-…-….ccxv"; take the
                // leading segment stem so partials count against their group.
                let stem = stem.split_once(".ccx").map_or(stem, |(head, _)| head);
                let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                *by_stem.entry(stem.to_string()).or_default() += len;
            }
        }
        for (path, stem) in members {
            out.insert(path, by_stem.get(&stem).copied().unwrap_or(0));
        }
    }
    out
}

impl Default for IndexManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for IndexManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexManager")
            .field("segments", &self.segments.len())
            .field("hot_bytes", &self.hot_bytes)
            .field("hot_budget_bytes", &self.hot_budget_bytes)
            .field("eviction_count", &self.eviction_count)
            .finish_non_exhaustive()
    }
}

/// Extract segment_seq from a filename like "seg-00000000000000000001-abcdef.ccxi"
fn extract_segment_seq(stem: &str) -> Option<u64> {
    let parts: Vec<&str> = stem.split('-').collect();
    if parts.len() >= 2 {
        parts[1].parse().ok()
    } else {
        None
    }
}

/// Tier statistics for monitoring.
#[derive(Debug, Clone, Default)]
pub struct TierStats {
    pub hot_segments: usize,
    pub hot_docs: usize,
    pub hot_bytes: usize,
    pub warm_segments: usize,
    pub warm_docs: usize,
    pub warm_bytes: usize,
    pub cold_segments: usize,
    pub hot_budget_bytes: usize,
}

// Implement From<std::io::Error> for RetrievalError
impl From<std::io::Error> for crate::RetrievalError {
    fn from(e: std::io::Error) -> Self {
        crate::RetrievalError::Internal { msg: e.to_string() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_index::CcxiBuilder;
    use tempfile::TempDir;

    fn build_test_ccxi(shard_id: u32, segment_seq: u64) -> Vec<u8> {
        let mut builder = CcxiBuilder::new(shard_id, segment_seq, 100);
        builder.add_document(0, "terraform module drift detection", 0, 0x1234);
        builder.add_document(1, "kubernetes deployment strategy", 100, 0x1234);
        builder.build()
    }

    // ── IndexManager::new defaults ───────────────────────────────────

    #[test]
    fn new_manager_is_empty() {
        let mgr = IndexManager::new();
        assert_eq!(mgr.segment_count(), 0);
        assert_eq!(mgr.total_docs(), 0);
        assert_eq!(mgr.eviction_count(), 0);
        assert!(mgr.readers().is_empty());
    }

    #[test]
    fn default_matches_new() {
        let a = IndexManager::new();
        let b = IndexManager::default();
        assert_eq!(a.segment_count(), b.segment_count());
        assert_eq!(a.total_docs(), b.total_docs());
    }

    // ── load_ccxi_bytes ──────────────────────────────────────────────

    #[test]
    fn load_ccxi_bytes_single_segment() {
        let mut mgr = IndexManager::new();
        let data = build_test_ccxi(0, 1);
        let seq = mgr.load_ccxi_bytes(&data).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(mgr.segment_count(), 1);
        assert_eq!(mgr.total_docs(), 2);
    }

    #[test]
    fn load_ccxi_bytes_multiple_segments() {
        let mut mgr = IndexManager::new();
        mgr.load_ccxi_bytes(&build_test_ccxi(0, 1)).unwrap();
        mgr.load_ccxi_bytes(&build_test_ccxi(0, 2)).unwrap();
        mgr.load_ccxi_bytes(&build_test_ccxi(0, 3)).unwrap();

        assert_eq!(mgr.segment_count(), 3);
        assert_eq!(mgr.total_docs(), 6); // 2 docs per segment
        assert_eq!(mgr.readers().len(), 3);
    }

    #[test]
    fn load_ccxi_bytes_returns_segment_seq() {
        let mut mgr = IndexManager::new();
        let seq = mgr.load_ccxi_bytes(&build_test_ccxi(0, 42)).unwrap();
        assert_eq!(seq, 42);
    }

    // ── readers / readers_by_tier ────────────────────────────────────

    #[test]
    fn readers_returns_all_loaded() {
        let mut mgr = IndexManager::new();
        mgr.load_ccxi_bytes(&build_test_ccxi(0, 1)).unwrap();
        mgr.load_ccxi_bytes(&build_test_ccxi(0, 2)).unwrap();

        let readers = mgr.readers();
        assert_eq!(readers.len(), 2);
    }

    #[test]
    fn readers_by_tier_hot() {
        let mut mgr = IndexManager::new();
        // Default budget is 4GB, these tiny indexes stay in Hot
        mgr.load_ccxi_bytes(&build_test_ccxi(0, 1)).unwrap();
        let hot = mgr.readers_by_tier(IndexTier::Hot);
        assert_eq!(hot.len(), 1);
        let warm = mgr.readers_by_tier(IndexTier::Warm);
        assert!(warm.is_empty());
    }

    // ── total_docs ───────────────────────────────────────────────────

    #[test]
    fn total_docs_accumulates() {
        let mut mgr = IndexManager::new();
        assert_eq!(mgr.total_docs(), 0);
        mgr.load_ccxi_bytes(&build_test_ccxi(0, 1)).unwrap();
        assert_eq!(mgr.total_docs(), 2);
        mgr.load_ccxi_bytes(&build_test_ccxi(0, 2)).unwrap();
        assert_eq!(mgr.total_docs(), 4);
    }

    // ── tier_stats ───────────────────────────────────────────────────

    #[test]
    fn tier_stats_empty() {
        let mgr = IndexManager::new();
        let stats = mgr.tier_stats();
        assert_eq!(stats.hot_segments, 0);
        assert_eq!(stats.warm_segments, 0);
        assert_eq!(stats.cold_segments, 0);
        assert_eq!(stats.hot_docs, 0);
        assert_eq!(stats.hot_bytes, 0);
    }

    #[test]
    fn tier_stats_reflects_loaded_segments() {
        let mut mgr = IndexManager::new();
        mgr.load_ccxi_bytes(&build_test_ccxi(0, 1)).unwrap();
        let stats = mgr.tier_stats();
        assert_eq!(stats.hot_segments, 1);
        assert_eq!(stats.hot_docs, 2);
        assert!(stats.hot_bytes > 0);
        assert_eq!(stats.warm_segments, 0);
    }

    // ── set_hot_budget / tier eviction ───────────────────────────────

    #[test]
    fn set_hot_budget_demotes_to_warm() {
        let mut mgr = IndexManager::new();
        mgr.set_min_residency(std::time::Duration::ZERO);
        mgr.load_ccxi_bytes(&build_test_ccxi(0, 1)).unwrap();
        mgr.load_ccxi_bytes(&build_test_ccxi(0, 2)).unwrap();

        // Set budget to 0 — everything should demote to Warm
        mgr.set_hot_budget(0);

        let stats = mgr.tier_stats();
        assert_eq!(stats.hot_segments, 0);
        assert_eq!(stats.warm_segments, 2);
        assert!(mgr.eviction_count() >= 2);
    }

    #[test]
    fn set_hot_budget_keeps_newest_in_hot() {
        let mut mgr = IndexManager::new();
        mgr.set_min_residency(std::time::Duration::ZERO);
        let data1 = build_test_ccxi(0, 1);
        let data2 = build_test_ccxi(0, 2);
        mgr.load_ccxi_bytes(&data1).unwrap();
        mgr.load_ccxi_bytes(&data2).unwrap();

        // Set budget to fit exactly one segment — newest should stay hot
        let single_size = data1.len();
        mgr.set_hot_budget(single_size);

        let stats = mgr.tier_stats();
        assert_eq!(stats.hot_segments, 1);
        assert_eq!(stats.warm_segments, 1);

        // The hot reader should be segment_seq=2 (newest)
        let hot_readers = mgr.readers_by_tier(IndexTier::Hot);
        assert_eq!(hot_readers[0].header.segment_seq, 2);
    }

    // ── load_ccxi (from file) ────────────────────────────────────────

    #[test]
    fn load_ccxi_from_file() {
        let tmp = TempDir::new().unwrap();
        let data = build_test_ccxi(0, 5);
        let path = tmp.path().join("seg-00000000000000000005-abcdef.ccxi");
        std::fs::write(&path, &data).unwrap();

        let mut mgr = IndexManager::new();
        let seq = mgr.load_ccxi(&path).unwrap();
        assert_eq!(seq, 5);
        assert_eq!(mgr.segment_count(), 1);
        assert_eq!(mgr.total_docs(), 2);
    }

    // ── scan_and_load ────────────────────────────────────────────────

    #[test]
    fn scan_and_load_nonexistent_dir() {
        let mut mgr = IndexManager::new();
        let count = mgr
            .scan_and_load(Path::new("/tmp/definitely-does-not-exist-corecrux"))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn scan_and_load_empty_dir() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = IndexManager::new();
        let count = mgr.scan_and_load(tmp.path()).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn scan_and_load_finds_ccxi_files() {
        let tmp = TempDir::new().unwrap();

        // Write two .ccxi files
        for seq in [1u64, 2] {
            let data = build_test_ccxi(0, seq);
            let path = tmp.path().join(format!("seg-{seq:020}-abcdef.ccxi"));
            std::fs::write(&path, &data).unwrap();
        }

        // Write a non-.ccxi file (should be ignored)
        std::fs::write(tmp.path().join("readme.txt"), b"not an index").unwrap();

        let mut mgr = IndexManager::new();
        let count = mgr.scan_and_load(tmp.path()).unwrap();
        assert_eq!(count, 2);
        assert_eq!(mgr.segment_count(), 2);
        assert_eq!(mgr.total_docs(), 4);
    }

    #[test]
    fn scan_and_load_skips_already_loaded() {
        let tmp = TempDir::new().unwrap();
        let data = build_test_ccxi(0, 1);
        let path = tmp.path().join("seg-00000000000000000001-abcdef.ccxi");
        std::fs::write(&path, &data).unwrap();

        let mut mgr = IndexManager::new();
        let count1 = mgr.scan_and_load(tmp.path()).unwrap();
        assert_eq!(count1, 1);

        // Second scan should skip the already-loaded segment
        let count2 = mgr.scan_and_load(tmp.path()).unwrap();
        assert_eq!(count2, 0);
        assert_eq!(mgr.segment_count(), 1); // still just 1
    }

    // ── extract_segment_seq ──────────────────────────────────────────

    #[test]
    fn extract_segment_seq_valid() {
        assert_eq!(extract_segment_seq("seg-00000000000000000001-abcdef"), Some(1));
        assert_eq!(extract_segment_seq("seg-00000000000000000042-xyz"), Some(42));
    }

    #[test]
    fn extract_segment_seq_invalid() {
        assert_eq!(extract_segment_seq("nosep"), None);
        assert_eq!(extract_segment_seq("seg-notanumber-x"), None);
    }

    #[test]
    fn extract_segment_seq_single_dash() {
        // "seg-123" → parts = ["seg", "123"], parts[1] = "123"
        assert_eq!(extract_segment_seq("seg-123"), Some(123));
    }

    // ── Debug impl ───────────────────────────────────────────────────

    #[test]
    fn debug_impl_works() {
        let mgr = IndexManager::new();
        let dbg = format!("{:?}", mgr);
        assert!(dbg.contains("IndexManager"));
        assert!(dbg.contains("segments"));
    }

    // ── tenant_footprint ─────────────────────────────────────────────

    fn build_ccxi_for(segment_seq: u64, tenants: &[u64]) -> Vec<u8> {
        let mut builder = CcxiBuilder::new(0, segment_seq, 100);
        for (i, &th) in tenants.iter().enumerate() {
            builder.add_document(i as u32, "terraform drift detection", (i * 100) as u32, th);
        }
        builder.build()
    }

    #[test]
    fn footprint_of_unknown_tenant_is_empty() {
        let mut mgr = IndexManager::new();
        mgr.load_ccxi_bytes(&build_ccxi_for(1, &[0xAAAA])).unwrap();
        let fp = mgr.tenant_footprint(0xBBBB);
        assert!(fp.segments.is_empty());
        assert_eq!(fp.docs, 0);
        assert_eq!(fp.bytes, 0);
        assert_eq!(fp.mixed_segments, 0);
    }

    #[test]
    fn footprint_counts_only_the_named_tenant() {
        let mut mgr = IndexManager::new();
        mgr.load_ccxi_bytes(&build_ccxi_for(1, &[0xAAAA, 0xAAAA])).unwrap();
        mgr.load_ccxi_bytes(&build_ccxi_for(2, &[0xBBBB])).unwrap();

        let fp = mgr.tenant_footprint(0xAAAA);
        assert_eq!(fp.segments.len(), 1, "segment 2 holds no docs for this tenant");
        assert_eq!(fp.segments[0].segment_seq, 1);
        assert_eq!(fp.docs, 2);
        assert!(fp.segments[0].whole_tenant);
        assert_eq!(fp.mixed_segments, 0);
    }

    #[test]
    fn footprint_flags_mixed_segments() {
        let mut mgr = IndexManager::new();
        mgr.load_ccxi_bytes(&build_ccxi_for(1, &[0xAAAA, 0xBBBB])).unwrap();

        let fp = mgr.tenant_footprint(0xAAAA);
        assert_eq!(fp.segments.len(), 1);
        assert_eq!(fp.segments[0].docs_total, 2);
        assert_eq!(fp.segments[0].docs_tenant, 1);
        assert!(!fp.segments[0].whole_tenant, "shared segment is not reclaimable");
        assert_eq!(fp.mixed_segments, 1);
        assert_eq!(fp.docs, 1);
    }

    #[test]
    fn footprint_bytes_cover_the_whole_file_group() {
        let tmp = TempDir::new().unwrap();
        let stem = "seg-00000000000000000007-abcdef";
        let ccxi = build_ccxi_for(7, &[0xAAAA]);
        std::fs::write(tmp.path().join(format!("{stem}.ccxi")), &ccxi).unwrap();
        // Siblings written by the seal path — they are what a reclaim frees too.
        std::fs::write(tmp.path().join(format!("{stem}.ccxseg")), vec![0u8; 500]).unwrap();
        std::fs::write(tmp.path().join(format!("{stem}.ccxv")), vec![0u8; 250]).unwrap();
        std::fs::write(tmp.path().join(format!("{stem}.ccxp")), vec![0u8; 50]).unwrap();
        // A different segment in the same directory must not be counted.
        std::fs::write(
            tmp.path().join("seg-00000000000000000008-fedcba.ccxseg"),
            vec![0u8; 999],
        )
        .unwrap();

        let mut mgr = IndexManager::new();
        mgr.scan_and_load(tmp.path()).unwrap();

        let fp = mgr.tenant_footprint(0xAAAA);
        assert_eq!(fp.segments.len(), 1);
        assert_eq!(fp.bytes, ccxi.len() as u64 + 500 + 250 + 50);
    }

    #[test]
    fn footprint_bytes_are_zero_for_in_memory_segments() {
        let mut mgr = IndexManager::new();
        mgr.load_ccxi_bytes(&build_ccxi_for(1, &[0xAAAA])).unwrap();
        assert_eq!(mgr.tenant_footprint(0xAAAA).bytes, 0);
    }

    // ── min_residency protection ─────────────────────────────────────

    #[test]
    fn min_residency_protects_recently_promoted() {
        let mut mgr = IndexManager::new();
        // Set a very long residency so segments can't be evicted
        mgr.set_min_residency(std::time::Duration::from_secs(3600));
        mgr.load_ccxi_bytes(&build_test_ccxi(0, 1)).unwrap();
        mgr.load_ccxi_bytes(&build_test_ccxi(0, 2)).unwrap();

        // Try to shrink budget to 0 — segments should remain hot due to residency protection
        mgr.set_hot_budget(0);

        let stats = mgr.tier_stats();
        // Both should remain in hot tier (protected by min_residency)
        assert_eq!(stats.hot_segments, 2);
        assert_eq!(stats.warm_segments, 0);
    }
}
