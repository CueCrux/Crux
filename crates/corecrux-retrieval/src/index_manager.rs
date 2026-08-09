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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

use corecrux_index::CcxiReader;

use corecrux_index::Provenance;

use crate::segment_attestation::AttestationPolicy;
use crate::segment_tenants::{read_segment_membership, SegmentMembership};

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

/// A tenant whose retrieval corpus has been erased, and the segment sequence
/// at which the erasure happened.
///
/// Segments sealed at or below `watermark_segment_seq` are invisible to this
/// tenant; anything ingested afterwards is served normally, so a corpus can be
/// erased and then re-paved under the same tenant id.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ForgottenTenant {
    pub tenant_id: String,
    pub tenant_hash: u64,
    pub watermark_segment_seq: u64,
    /// RFC3339. Supplied by the caller — this crate has no clock.
    pub forgotten_at: String,
    /// Segment file groups physically deleted (Layer 2). Zero while the
    /// erasure is mask-only and therefore still reversible.
    #[serde(default)]
    pub segments_reclaimed: usize,
}

/// Manages sealed segments: their `.ccxi` indexes where one exists, and their
/// identity and tenant membership where one does not.
///
/// Discovery keys off `.ccxseg` — the segment file itself — not off `.ccxi`.
/// A `.ccxi` is a *companion*: a fact-only segment cannot have one (there is no
/// prose for a BM25-over-text extractor to index), and keying discovery off it
/// left such segments permanently invisible **and permanently un-erasable**.
pub struct IndexManager {
    /// segment_seq → discovered segment
    segments: BTreeMap<u64, LoadedSegment>,
    /// tenant_hash → erasure record. Consulted on every tenant-scoped query.
    forgotten: BTreeMap<u64, ForgottenTenant>,
    /// Directories handed to [`IndexManager::scan_and_load`], re-read by
    /// [`IndexManager::refresh_from_disk`] so erasure enumerates from disk
    /// rather than trusting whatever the last scan happened to load.
    scanned_dirs: BTreeSet<PathBuf>,
    /// Companion provenance policy. `None` means verification is not configured
    /// at all (unit tests, embedded uses); the daemon always configures one.
    attestation: Option<AttestationPolicy>,
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
    /// `None` for a segment with no `.ccxi` companion — discovered, attributable
    /// and erasable, but contributing nothing to the BM25 lane.
    reader: Option<CcxiReader>,
    /// Tenant membership read from the segment's own frame headers, derived on
    /// first use and only for segments with no `.ccxi` to read it from.
    ///
    /// Lazy on purpose: deriving it means reading the whole segment, and
    /// discovery runs on the ingest path after every seal. Doing it eagerly
    /// would put a full re-read of a just-sealed segment into that path — and
    /// nothing there needs the answer. Attribution is an admin-time question, so
    /// it is paid for at admin time.
    ///
    /// The inner `None` is "could not be read", which is *not* the same as
    /// empty; see [`TenantFootprint::unattributable_segments`].
    membership: std::sync::OnceLock<Option<SegmentMembership>>,
    /// A path in the segment's on-disk file group; only the stem is load-bearing
    /// (`.ccxseg` when discovered by scan, `.ccxi` when loaded directly). Empty
    /// for segments loaded from bytes.
    path: PathBuf,
    tier: IndexTier,
    size_bytes: usize,
    /// When this segment was last promoted to Hot tier.
    promoted_at: Option<Instant>,
    /// Companion provenance as resolved at scan time. `None` when no policy is
    /// configured, or for a segment loaded from bytes.
    provenance: Option<Provenance>,
    /// Set when provenance refused this segment its lanes. It is still
    /// discovered, attributable and erasable — only unserved.
    refused: bool,
}

impl LoadedSegment {
    /// Tenant membership from the segment's frames, reading it if this is the
    /// first ask. `None` when the segment could not be read.
    fn membership(&self) -> Option<&SegmentMembership> {
        self.membership
            .get_or_init(|| {
                if self.path.as_os_str().is_empty() {
                    return None;
                }
                match read_segment_membership(&self.path) {
                    Ok(m) => Some(m),
                    Err(e) => {
                        tracing::error!(
                            path = %self.path.display(),
                            error = %e,
                            "segment-membership-unreadable: segment is discovered but cannot be \
                             attributed to a tenant"
                        );
                        None
                    }
                }
            })
            .as_ref()
    }

    /// Documents in the segment, from whichever source attributes it.
    fn docs_total(&self) -> usize {
        match &self.reader {
            Some(reader) => reader.docs.len(),
            None => self.membership().map_or(0, |m| m.docs_total),
        }
    }

    /// Documents belonging to `tenant_hash`, or `None` when the segment cannot
    /// be attributed at all.
    fn docs_for_tenant(&self, tenant_hash: u64) -> Option<usize> {
        match &self.reader {
            Some(reader) => Some(reader.docs.iter().filter(|d| d.tenant_hash_full == tenant_hash).count()),
            None => self.membership().map(|m| m.docs_for(tenant_hash)),
        }
    }
}

impl IndexManager {
    pub fn new() -> Self {
        Self {
            segments: BTreeMap::new(),
            forgotten: BTreeMap::new(),
            scanned_dirs: BTreeSet::new(),
            attestation: None,
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
                reader: Some(reader),
                membership: std::sync::OnceLock::new(),
                path: path.to_path_buf(),
                tier,
                size_bytes: size,
                promoted_at,
                provenance: None,
                refused: false,
            },
        );
        Ok(seq)
    }

    /// Register a sealed segment that carries no `.ccxi` companion.
    ///
    /// It serves no BM25 lane, so it costs no hot-tier budget and stays `Cold`.
    /// What it gains is identity and attribution: it appears in
    /// [`IndexManager::tenant_footprint`] and can be reclaimed.
    ///
    /// A segment whose contents cannot be read is still registered, with no
    /// membership. Refusing to register it would put it back where this change
    /// found it — invisible and un-erasable — so instead it is visible and
    /// reported as unattributable, which is loud rather than silent.
    ///
    /// Only the segment's 4 KiB header is read here — discovery runs on the
    /// ingest path after every seal, so it must not read a whole segment.
    /// Tenant membership is derived from the segment's frames on first use, by
    /// [`IndexManager::tenant_footprint`].
    pub fn register_segment_without_ccxi(&mut self, ccxseg_path: &Path) -> crate::Result<u64> {
        let Some(seq) = segment_seq_of(ccxseg_path) else {
            return Err(crate::RetrievalError::Internal {
                msg: format!("cannot determine segment_seq for {}", ccxseg_path.display()),
            });
        };
        self.segments.insert(
            seq,
            LoadedSegment {
                reader: None,
                membership: std::sync::OnceLock::new(),
                path: ccxseg_path.to_path_buf(),
                tier: IndexTier::Cold,
                size_bytes: 0,
                promoted_at: None,
                provenance: None,
                refused: false,
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
                reader: Some(reader),
                membership: std::sync::OnceLock::new(),
                path: PathBuf::new(),
                tier: IndexTier::Hot,
                size_bytes: size,
                promoted_at: Some(Instant::now()),
                provenance: None,
                refused: false,
            },
        );
        self.hot_bytes += size;
        Ok(seq)
    }

    /// Get all loaded readers (for multi-segment scoring).
    ///
    /// Segments with no `.ccxi` are absent by construction — they have no doc
    /// table to score against. They are still discovered and erasable; see
    /// [`IndexManager::segment_seqs`].
    pub fn readers(&self) -> Vec<&CcxiReader> {
        self.segments.values().filter_map(|s| s.reader.as_ref()).collect()
    }

    /// Get readers filtered by tier.
    pub fn readers_by_tier(&self, tier: IndexTier) -> Vec<&CcxiReader> {
        self.segments
            .values()
            .filter(|s| s.tier == tier)
            .filter_map(|s| s.reader.as_ref())
            .collect()
    }

    /// Total number of documents across all discovered segments.
    pub fn total_docs(&self) -> usize {
        self.segments.values().map(LoadedSegment::docs_total).sum()
    }

    /// Number of discovered segments, `.ccxi` or not.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Every discovered segment's sequence, ascending — including those with no
    /// `.ccxi`.
    pub fn segment_seqs(&self) -> Vec<u64> {
        self.segments.keys().copied().collect()
    }

    /// Install the companion-provenance policy consulted by every scan.
    ///
    /// Set before the first `scan_and_load`: it governs what those segments are
    /// permitted to serve, and a scan that ran without it has already decided.
    pub fn set_attestation_policy(&mut self, policy: AttestationPolicy) {
        self.attestation = Some(policy);
    }

    /// Segments per provenance state, keyed by [`Provenance::slug`].
    ///
    /// Drives the `/v1/version` capability and the startup summary. Segments
    /// scanned with no policy configured are absent, not counted as `none` —
    /// "we did not check" and "we checked and found nothing" are different
    /// claims.
    pub fn provenance_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut out = BTreeMap::new();
        for seg in self.segments.values() {
            if let Some(p) = seg.provenance {
                *out.entry(p.slug()).or_insert(0) += 1;
            }
        }
        out
    }

    /// Segments whose provenance cost them their lanes. Still discovered,
    /// attributable and erasable.
    pub fn refused_segments(&self) -> Vec<u64> {
        self.segments
            .iter()
            .filter(|(_, s)| s.refused)
            .map(|(&seq, _)| seq)
            .collect()
    }

    /// Provenance of one discovered segment, if a policy resolved it.
    pub fn segment_provenance(&self, segment_seq: u64) -> Option<Provenance> {
        self.segments.get(&segment_seq).and_then(|s| s.provenance)
    }

    /// Discovered segments carrying no `.ccxi` companion.
    pub fn segments_without_ccxi(&self) -> Vec<u64> {
        self.segments
            .iter()
            .filter(|(_, s)| s.reader.is_none())
            .map(|(&seq, _)| seq)
            .collect()
    }

    /// Tier statistics.
    pub fn tier_stats(&self) -> TierStats {
        let mut stats = TierStats::default();
        for seg in self.segments.values() {
            match seg.tier {
                IndexTier::Hot => {
                    stats.hot_segments += 1;
                    stats.hot_docs += seg.docs_total();
                    stats.hot_bytes += seg.size_bytes;
                }
                IndexTier::Warm => {
                    stats.warm_segments += 1;
                    stats.warm_docs += seg.docs_total();
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

    /// Discover a directory's sealed segments and load what each one offers.
    ///
    /// Keyed off `.ccxseg`, the segment file itself: present by definition, it
    /// *is* the segment's identity, and it couples to nothing. A segment with a
    /// `.ccxi` loads its index as before; one without is registered for
    /// attribution and erasure.
    ///
    /// A `.ccxi` with no `.ccxseg` beside it is still loaded. That is a broken
    /// on-disk state, but it is one the previous scan served, and refusing it
    /// here would silently drop a corpus rather than report a problem.
    ///
    /// Returns the number of segments newly discovered, or upgraded from
    /// companion-less to indexed.
    pub fn scan_and_load(&mut self, dir: &Path) -> crate::Result<usize> {
        self.scanned_dirs.insert(dir.to_path_buf());
        if !dir.exists() {
            return Ok(0);
        }

        // One pass to group the directory by segment stem, so a segment is
        // considered once with everything it has, rather than once per file.
        let mut groups: BTreeMap<String, SegmentGroup> = BTreeMap::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()).map(str::to_string) else {
                continue;
            };
            match path.extension().and_then(|e| e.to_str()) {
                Some("ccxseg") => groups.entry(stem).or_default().ccxseg = Some(path),
                Some("ccxi") => groups.entry(stem).or_default().ccxi = Some(path),
                _ => {}
            }
        }

        let mut count = 0;
        let mut without_ccxi = 0;
        for (stem, group) in groups {
            // Cheap pre-check against the filename before any file is read.
            if let Some(seq) = extract_segment_seq(&stem) {
                if let Some(existing) = self.segments.get(&seq) {
                    // Already known — but a segment scanned in the window
                    // between the `.ccxseg` rename and the companion write is
                    // registered without a reader, and skipping it forever
                    // would cost it its BM25 lane permanently. Revisit it once
                    // its `.ccxi` appears.
                    if existing.reader.is_some() || group.ccxi.is_none() {
                        continue;
                    }
                }
            }
            // Resolve provenance before deciding what this segment gets. A
            // refusal costs it its lanes, never its visibility: discovery is
            // also the erasure enumeration, so dropping a refused segment here
            // would make it un-erasable — reopening the exact hole keying
            // discovery off `.ccxseg` was meant to close. Refused means
            // *unserved*, not *unseen*.
            let (provenance, permitted, reason_code) = match self.attestation.as_ref() {
                Some(policy) => {
                    // Resolved once: verification hashes every covered companion,
                    // so asking twice would double the cost of every scan.
                    let resolved = policy.resolve(dir, &stem);
                    (
                        Some(resolved.provenance),
                        policy.permits(resolved.provenance),
                        resolved.reason_code,
                    )
                }
                None => (None, true, None),
            };

            let outcome = match (&group.ccxi, &group.ccxseg, permitted) {
                (Some(ccxi), _, true) => self.load_ccxi(ccxi).map(|seq| (seq, false)),
                (None, Some(ccxseg), true) => self.register_segment_without_ccxi(ccxseg).map(|seq| (seq, true)),
                // Refused: register it for attribution and erasure only.
                (_, Some(ccxseg), false) => self.register_segment_without_ccxi(ccxseg).map(|seq| (seq, true)),
                (Some(ccxi), None, false) => self.register_segment_without_ccxi(ccxi).map(|seq| (seq, true)),
                (None, None, _) => continue,
            };

            match outcome {
                Ok((seq, lane_less)) => {
                    count += 1;
                    if lane_less && permitted {
                        without_ccxi += 1;
                    }
                    if let Some(seg) = self.segments.get_mut(&seq) {
                        seg.provenance = provenance;
                        seg.refused = !permitted;
                    }
                    if !permitted {
                        tracing::error!(
                            segment_seq = seq,
                            provenance = provenance.map_or("unknown", Provenance::slug),
                            reason_code = reason_code.unwrap_or("companion_unattested"),
                            stem = %stem,
                            "companion-provenance-refused: segment discovered and erasable, but its \
                             lanes are withheld"
                        );
                    }
                }
                Err(e) => tracing::warn!(stem = %stem, error = %e, "segment-load-failed"),
            }
        }
        if without_ccxi > 0 {
            // These are discovered and erasable but serve no BM25 lane. Saying
            // so is what stops it being diagnosed later as missing recall.
            tracing::warn!(
                segments = without_ccxi,
                dir = %dir.display(),
                "segments-without-ccxi: discovered and erasable, but they contribute no BM25 lane"
            );
        }
        Ok(count)
    }

    /// Re-read every directory ever passed to [`IndexManager::scan_and_load`].
    ///
    /// Erasure calls this first so it enumerates from **disk**, not from
    /// whatever the last scan happened to load: a segment sealed since then is
    /// otherwise absent from the loaded set, and `reclaim_segment` would report
    /// `Ok(0)` and leave its files in place.
    ///
    /// Returns the number of segments newly discovered. A directory that has
    /// since become unreadable is logged and skipped rather than failing the
    /// refresh — a partial refresh still erases more than no refresh.
    pub fn refresh_from_disk(&mut self) -> usize {
        let dirs: Vec<PathBuf> = self.scanned_dirs.iter().cloned().collect();
        let mut found = 0;
        for dir in dirs {
            match self.scan_and_load(&dir) {
                Ok(n) => found += n,
                Err(e) => tracing::warn!(?dir, error = %e, "segment-refresh-scan-failed"),
            }
        }
        found
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
                // A segment with no `.ccxi` holds no index in memory, so it is
                // not a tier candidate: promoting it would report hot segments
                // that cost nothing and serve nothing.
                if seg.reader.is_none() {
                    seg.tier = IndexTier::Cold;
                    seg.promoted_at = None;
                    continue;
                }
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
    /// stem (`.ccxseg`, `.ccxi`, `.ccxe`, `.ccxprof`). Zero for segments loaded
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
    /// Segments that were discovered on disk but could not be attributed to any
    /// tenant, because neither a `.ccxi` doc table nor readable frame headers
    /// were available. A non-zero count means an erasure cannot be claimed
    /// complete: these are excluded from the reclaim set, since deleting a
    /// segment you cannot attribute risks a co-tenant's data.
    pub unattributable_segments: usize,
}

/// File name of the erasure mask inside the daemon's data dir.
pub const FORGOTTEN_TENANTS_FILE: &str = "forgotten-tenants.json";

impl IndexManager {
    /// The querying tenant's erasure watermark, or `None` if it has never been
    /// forgotten. Pass the result straight to the BM25 scorers.
    pub fn forgotten_watermark(&self, tenant_hash: u64) -> Option<u64> {
        self.forgotten.get(&tenant_hash).map(|f| f.watermark_segment_seq)
    }

    /// Highest loaded segment sequence — the watermark a fresh erasure takes.
    pub fn max_segment_seq(&self) -> Option<u64> {
        self.segments.keys().next_back().copied()
    }

    /// Mask a tenant's corpus. Reversible until the segment files are reclaimed.
    /// Returns the previous record when the tenant was already forgotten.
    pub fn forget_tenant(&mut self, record: ForgottenTenant) -> Option<ForgottenTenant> {
        self.forgotten.insert(record.tenant_hash, record)
    }

    /// Lift a mask. Layer-1 rollback; meaningless once the files are gone,
    /// which is why the caller must refuse it for a reclaimed tenant.
    pub fn unforget_tenant(&mut self, tenant_hash: u64) -> Option<ForgottenTenant> {
        self.forgotten.remove(&tenant_hash)
    }

    pub fn forgotten_tenant(&self, tenant_hash: u64) -> Option<&ForgottenTenant> {
        self.forgotten.get(&tenant_hash)
    }

    pub fn forgotten_tenants(&self) -> Vec<&ForgottenTenant> {
        self.forgotten.values().collect()
    }

    /// Persist the mask atomically (tmp + rename).
    ///
    /// Ordering contract: this must succeed *before* any segment file is
    /// deleted. A crash between the two then leaves a tenant masked with its
    /// files intact — recoverable — rather than files gone with no mask.
    pub fn save_forgotten(&self, path: &Path) -> crate::Result<()> {
        let json = serde_json::to_vec_pretty(&self.forgotten.values().collect::<Vec<_>>())
            .map_err(|e| crate::RetrievalError::Internal { msg: e.to_string() })?;
        let tmp = path.with_extension("json.partial");
        std::fs::write(&tmp, &json)?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Load the mask at startup. A missing file is not an error (no tenant has
    /// ever been forgotten); an unreadable one is, because silently serving an
    /// erased corpus is the failure this whole surface exists to prevent.
    pub fn load_forgotten(&mut self, path: &Path) -> crate::Result<usize> {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        let records: Vec<ForgottenTenant> =
            serde_json::from_slice(&bytes).map_err(|e| crate::RetrievalError::Internal { msg: e.to_string() })?;
        let count = records.len();
        self.forgotten = records.into_iter().map(|r| (r.tenant_hash, r)).collect();
        Ok(count)
    }

    /// Physically reclaim one segment: evict it from the index, then delete its
    /// whole file group. Returns the bytes freed (0 if the segment was not
    /// loaded or was loaded from bytes rather than from disk).
    ///
    /// **Irreversible.** The ordering is the contract: the reader is dropped
    /// before the files go, so the daemon can never serve a segment whose files
    /// have already been deleted. A crash in the window leaves files on disk
    /// under a persisted mask — inert, and reclaimable again later.
    ///
    /// Only call this for a segment whose documents all belong to the tenant
    /// being erased ([`SegmentFootprint::whole_tenant`]); deleting a shared
    /// segment would erase a co-tenant's data.
    pub fn reclaim_segment(&mut self, segment_seq: u64) -> crate::Result<u64> {
        let Some(seg) = self.segments.remove(&segment_seq) else {
            return Ok(0);
        };
        if seg.tier == IndexTier::Hot {
            self.hot_bytes = self.hot_bytes.saturating_sub(seg.size_bytes);
        }
        let path = seg.path.clone();
        drop(seg); // reader released before any unlink
        if path.as_os_str().is_empty() {
            return Ok(0);
        }
        delete_segment_group(&path)
    }

    /// Read-only inventory of the segments holding `tenant_hash`'s documents.
    ///
    /// Segments with no docs for the tenant are omitted. `bytes` is the size of
    /// the on-disk file group, so the reported total is what a reclaim would
    /// actually free.
    pub fn tenant_footprint(&self, tenant_hash: u64) -> TenantFootprint {
        let mut out = TenantFootprint::default();
        let mut hits: Vec<(u64, usize, usize, Option<PathBuf>)> = Vec::new();
        for (&seq, seg) in &self.segments {
            let docs_total = seg.docs_total();
            let Some(docs_tenant) = seg.docs_for_tenant(tenant_hash) else {
                // Discovered but unreadable: it may or may not hold this
                // tenant's data, and guessing either way is wrong. Report it.
                out.unattributable_segments += 1;
                continue;
            };
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

/// Delete every file sharing the segment's stem (`.ccxseg`, `.ccxi`, `.ccxe`,
/// `.ccxprof`, and any `.partial` left by an interrupted write) and return the
/// bytes freed. The `stem.` prefix is exact, so a neighbouring segment in the
/// same directory is never touched.
fn delete_segment_group(ccxi_path: &Path) -> crate::Result<u64> {
    let (Some(dir), Some(stem)) = (ccxi_path.parent(), ccxi_path.file_stem().and_then(|s| s.to_str())) else {
        return Ok(0);
    };
    let prefix = format!("{stem}.");
    let mut freed = 0u64;
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(&prefix) {
            continue;
        }
        let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
        std::fs::remove_file(entry.path())?;
        freed += len;
    }
    Ok(freed)
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
                // `.ccxe.partial` and friends stem to "seg-…-….ccxe"; take the
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
/// The files of one segment found by a directory scan, grouped by stem.
#[derive(Default)]
struct SegmentGroup {
    ccxseg: Option<PathBuf>,
    ccxi: Option<PathBuf>,
}

/// The leading `SEGMENT_HEADER_LEN` bytes of a segment file, or `None` if it is
/// unreadable or shorter than a header.
fn read_segment_header_bytes(ccxseg_path: &Path) -> Option<Vec<u8>> {
    use std::io::Read as _;

    let mut buf = vec![0u8; corecrux_segment::SEGMENT_HEADER_LEN];
    let mut file = std::fs::File::open(ccxseg_path).ok()?;
    file.read_exact(&mut buf).ok()?;
    Some(buf)
}

/// A segment's sequence, preferring the sealed header over the filename.
///
/// The header is authoritative — the filename is a convention, and a renamed or
/// hand-copied file would otherwise be registered under the wrong sequence and
/// erased in someone else's place. The filename is the fallback so a segment
/// whose header will not decode is still discovered rather than dropped.
fn segment_seq_of(ccxseg_path: &Path) -> Option<u64> {
    let from_name = ccxseg_path
        .file_stem()
        .and_then(|s| s.to_str())
        .and_then(extract_segment_seq);

    // Header only — discovery runs after every seal, so it must not read a
    // whole segment to learn its number.
    let from_header = read_segment_header_bytes(ccxseg_path)
        .and_then(|bytes| corecrux_segment::decode_segment_header_v1(&bytes).ok())
        .map(|header| header.segment_seq);

    if let (Some(name), Some(header)) = (from_name, from_header) {
        if name != header {
            tracing::warn!(
                path = ?ccxseg_path,
                filename_seq = name,
                header_seq = header,
                "segment-seq-mismatch: trusting the sealed header"
            );
        }
    }
    from_header.or(from_name)
}

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
        std::fs::write(tmp.path().join(format!("{stem}.ccxe")), vec![0u8; 250]).unwrap();
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

    // ── forgotten-tenant mask (Layer 1) ──────────────────────────────

    fn record(tenant_id: &str, tenant_hash: u64, watermark: u64) -> ForgottenTenant {
        ForgottenTenant {
            tenant_id: tenant_id.to_string(),
            tenant_hash,
            watermark_segment_seq: watermark,
            forgotten_at: "2026-08-06T00:00:00Z".to_string(),
            segments_reclaimed: 0,
        }
    }

    #[test]
    fn watermark_is_none_until_a_tenant_is_forgotten() {
        let mut mgr = IndexManager::new();
        mgr.load_ccxi_bytes(&build_ccxi_for(1, &[0xAAAA])).unwrap();
        assert_eq!(mgr.forgotten_watermark(0xAAAA), None);

        mgr.forget_tenant(record("acme", 0xAAAA, 1));
        assert_eq!(mgr.forgotten_watermark(0xAAAA), Some(1));
        assert_eq!(mgr.forgotten_watermark(0xBBBB), None, "sibling tenant unaffected");
    }

    #[test]
    fn unforget_lifts_the_mask() {
        let mut mgr = IndexManager::new();
        mgr.forget_tenant(record("acme", 0xAAAA, 4));
        assert!(mgr.unforget_tenant(0xAAAA).is_some());
        assert_eq!(mgr.forgotten_watermark(0xAAAA), None);
        assert!(mgr.unforget_tenant(0xAAAA).is_none(), "second lift is a no-op");
    }

    #[test]
    fn max_segment_seq_picks_the_watermark() {
        let mut mgr = IndexManager::new();
        assert_eq!(mgr.max_segment_seq(), None);
        mgr.load_ccxi_bytes(&build_ccxi_for(3, &[0xAAAA])).unwrap();
        mgr.load_ccxi_bytes(&build_ccxi_for(11, &[0xAAAA])).unwrap();
        mgr.load_ccxi_bytes(&build_ccxi_for(7, &[0xAAAA])).unwrap();
        assert_eq!(mgr.max_segment_seq(), Some(11));
    }

    #[test]
    fn mask_survives_a_save_load_round_trip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(FORGOTTEN_TENANTS_FILE);

        let mut mgr = IndexManager::new();
        mgr.forget_tenant(record("acme", 0xAAAA, 18));
        mgr.forget_tenant(record("globex", 0xBBBB, 4));
        mgr.save_forgotten(&path).unwrap();

        // Simulate a daemon restart.
        let mut cold = IndexManager::new();
        assert_eq!(cold.load_forgotten(&path).unwrap(), 2);
        assert_eq!(cold.forgotten_watermark(0xAAAA), Some(18));
        assert_eq!(cold.forgotten_watermark(0xBBBB), Some(4));
        assert_eq!(cold.forgotten_tenant(0xAAAA).unwrap().tenant_id, "acme");
    }

    #[test]
    fn missing_mask_file_is_not_an_error() {
        let tmp = TempDir::new().unwrap();
        let mut mgr = IndexManager::new();
        assert_eq!(mgr.load_forgotten(&tmp.path().join(FORGOTTEN_TENANTS_FILE)).unwrap(), 0);
    }

    #[test]
    fn corrupt_mask_file_is_an_error_not_an_empty_mask() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(FORGOTTEN_TENANTS_FILE);
        std::fs::write(&path, b"{ not json").unwrap();
        let mut mgr = IndexManager::new();
        assert!(
            mgr.load_forgotten(&path).is_err(),
            "an unreadable mask must never degrade to 'nothing is forgotten'"
        );
    }

    #[test]
    fn save_leaves_no_partial_file_behind() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join(FORGOTTEN_TENANTS_FILE);
        let mut mgr = IndexManager::new();
        mgr.forget_tenant(record("acme", 0xAAAA, 1));
        mgr.save_forgotten(&path).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains("partial"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "tmp file must be renamed, not left: {leftovers:?}"
        );
    }

    // ── reclaim_segment (Layer 2) ────────────────────────────────────

    fn write_group(dir: &Path, seq: u64, tenants: &[u64]) -> u64 {
        let stem = format!("seg-{seq:020}-abcdef");
        let ccxi = build_ccxi_for(seq, tenants);
        std::fs::write(dir.join(format!("{stem}.ccxi")), &ccxi).unwrap();
        std::fs::write(dir.join(format!("{stem}.ccxseg")), vec![0u8; 400]).unwrap();
        std::fs::write(dir.join(format!("{stem}.ccxe")), vec![0u8; 100]).unwrap();
        ccxi.len() as u64 + 400 + 100
    }

    #[test]
    fn reclaim_evicts_then_deletes_the_whole_group() {
        let tmp = TempDir::new().unwrap();
        let expected = write_group(tmp.path(), 1, &[0xAAAA]);
        write_group(tmp.path(), 2, &[0xBBBB]);

        let mut mgr = IndexManager::new();
        mgr.scan_and_load(tmp.path()).unwrap();
        assert_eq!(mgr.segment_count(), 2);

        let freed = mgr.reclaim_segment(1).unwrap();
        assert_eq!(freed, expected);
        assert_eq!(mgr.segment_count(), 1, "evicted before the unlink");
        assert_eq!(mgr.tenant_footprint(0xAAAA).segments.len(), 0);

        let left: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(left.len(), 3, "only segment 2's group survives: {left:?}");
        assert!(left.iter().all(|n| n.contains("00000000000000000002")));

        // A cold rescan must not resurrect the deleted segment.
        let mut cold = IndexManager::new();
        assert_eq!(cold.scan_and_load(tmp.path()).unwrap(), 1);
    }

    #[test]
    fn reclaim_of_an_unloaded_segment_is_a_no_op() {
        let mut mgr = IndexManager::new();
        assert_eq!(mgr.reclaim_segment(42).unwrap(), 0);
    }

    #[test]
    fn reclaim_of_an_in_memory_segment_frees_nothing_but_still_evicts() {
        let mut mgr = IndexManager::new();
        mgr.load_ccxi_bytes(&build_ccxi_for(1, &[0xAAAA])).unwrap();
        assert_eq!(mgr.reclaim_segment(1).unwrap(), 0);
        assert_eq!(mgr.segment_count(), 0);
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
