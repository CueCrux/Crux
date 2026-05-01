// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecrux-storage` — Shard storage engine for CoreCrux.
//!
//! This crate implements the core append-only storage layer. Events are hash-partitioned
//! across shards, written to active segments, and sealed when full. Each shard
//! maintains its own directory, manifest, and commit markers for crash recovery.
//!
//! Key types:
//! - `ShardStore` — top-level store managing multiple shards
//! - `Shard` — single shard with append, read, seal, and replay
//! - `CommitMarker` — tracks the last durable write position for crash recovery
//!
//! The storage engine provides:
//! - Append with backpressure (rejects writes when behind)
//! - Deterministic replay (re-read all events in commit order)
//! - Integrity verification (`verify-store` walks all segments and checks BLAKE3 hashes)
//! - Epoch-based shard ownership for safe rebalancing

#![deny(clippy::unwrap_used)]

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(unix)]
use std::os::unix::fs::FileExt as _;
#[cfg(windows)]
use std::os::windows::fs::FileExt as _;
use std::path::{Path, PathBuf};

use fs2::FileExt as _;
use thiserror::Error;

use corecrux_frame::decode_canonical_header_bytes_v1;
use corecrux_segment::{
    bloom_maybe_contains_stream_hash_v1, decode_frame_v1, decode_segment_v1, decode_trailer_index_v1, BlockMetaV1,
    SegmentId, TocByOffsetEntryV1, TrailerIndexV1,
};

pub const MANIFEST_MAGIC_CCMF: u32 = 0x464D_4343; // "CCMF"
pub const MANIFEST_VERSION_V1: u16 = 1;
pub const MANIFEST_HEADER_LEN: usize = 256;

// Phase 6: on-disk shard directory runs (LSM-style).
pub const DIRRUN_MAGIC_CCDR: u32 = 0x5244_4343; // "CCDR"
pub const DIRRUN_VERSION_V1: u16 = 1;
pub const DIRRUN_HEADER_LEN: usize = 4096;
pub const DIRRUN_PARTITIONS_V1: usize = 256;
pub const DIRRUN_PARTITION_TABLE_OFFSET_V1: usize = 64;
pub const DIRRUN_PARTITION_ENTRY_LEN_V1: usize = 12; // (offset:u64, count:u32)
pub const DIREXTENT_LEN_V1: usize = 32; // 4x u64
const STARTUP_DIRRUN_BOOTSTRAP_SEGMENT_LIMIT_V1: usize = 4096;

// Phase 4: active-segment commit markers (CCMT) for crash-safe commit boundaries.
const COMMIT_FRAME_MAGIC_CCMT: u32 = 0x544D_4343; // "CCMT"
const COMMIT_FRAME_VERSION_V1: u16 = 1;
const COMMIT_FRAME_LEN_V1: usize = 64;
const COMMIT_FRAME_SCAN_WINDOW_BYTES: usize = 1024 * 1024;

fn should_skip_startup_dirrun_bootstrap(dir_runs_empty: bool, segment_count: usize) -> bool {
    dir_runs_empty && segment_count > STARTUP_DIRRUN_BOOTSTRAP_SEGMENT_LIMIT_V1
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("invalid argument ({code}): {msg}")]
    InvalidArgument { code: String, msg: String },
    #[error("failed precondition ({code}): {msg}")]
    FailedPrecondition { code: String, msg: String },
    #[error("resource exhausted ({code}): {msg}")]
    ResourceExhausted {
        code: String,
        msg: String,
        retry_after_ms: Option<u32>,
    },
    #[error("internal error: {msg}")]
    Internal { msg: String },
    #[error("io error: {msg}")]
    Io { msg: String },
    #[error("manifest header invalid: {msg}")]
    ManifestHeaderInvalid { msg: String },
    #[error("manifest crc mismatch: expected {expected:#x}, got {actual:#x}")]
    ManifestCrcMismatch { expected: u32, actual: u32 },
    #[error("manifest record crc mismatch: expected {expected:#x}, got {actual:#x}")]
    ManifestRecordCrcMismatch { expected: u32, actual: u32 },
    #[error("manifest record invalid: {msg}")]
    ManifestRecordInvalid { msg: String },
    #[error("segment error: {0}")]
    Segment(#[from] corecrux_segment::SegmentError),
}

pub type Result<T> = std::result::Result<T, StorageError>;

#[derive(Debug, Clone)]
pub struct ShardStorageOptions {
    /// Hard limit on events per AppendBatch. Exceeding this returns BACKPRESSURE_MAX_EVENTS.
    pub max_events_per_batch: usize,
    /// Hard limit on total batch bytes (payload + event_id bytes). Exceeding this returns
    /// BACKPRESSURE_MAX_BATCH_BYTES.
    pub max_batch_bytes: usize,
    /// Hard limit on event_id byte length. Oversize event_ids are rejected per-event.
    pub max_event_id_bytes: usize,

    /// Maximum number of idempotency entries kept hot in memory (bounded).
    pub idem_hot_capacity_entries: usize,
    /// Number of bytes of BLAKE3(event_id) used for the hot key (1..=16). Smaller values are useful
    /// for collision simulation in tests; correctness still relies on verify-on-hit.
    pub event_id_hash_prefix_len: usize,
    /// Bound for cold idempotency lookup (segments scanned from newest to oldest).
    pub cold_scan_max_segments: usize,

    /// When non-zero, AppendBatch writes into a currently-appending "head" segment on disk
    /// (`.ccxhead`) and only seals+publishes to MANIFEST once this many record bytes are reached.
    /// This enables Phase 5 "head segment support" for reads.
    ///
    /// When zero, AppendBatch uses the Phase 2 behavior: seal+commit one segment per batch.
    pub head_max_record_bytes: usize,

    /// Codec used for sealed record blocks inside `.ccxseg` files.
    /// 0 = none, 1 = lz4 (Phase 5).
    pub record_block_codec: u32,

    /// Phase 6: enable directory LSM compaction (directory run merge/publish).
    pub enable_directory_compaction: bool,
    /// Phase 6: L0 run threshold that triggers compaction.
    pub dir_l0_max_runs: usize,

    /// Phase 12 perf tuning: coalesce head-segment durability fences across append batches.
    ///
    /// `1` preserves strict per-append durability (fsync every append). Values `>1`
    /// coalesce fsyncs and establish durability every N append batches (or earlier if
    /// `append_group_commit_max_delay_ms` expires).
    pub append_group_commit_batches: usize,
    /// Max age for a coalesced durability boundary. `0` disables age-based forcing and fences
    /// only on `append_group_commit_batches`.
    pub append_group_commit_max_delay_ms: u64,

    /// CoreCrux v5: build `.ccxi` companion inverted index at seal time.
    /// When enabled, each sealed segment produces a co-located `.ccxi` file
    /// for BM25 text retrieval. The index is BLAKE3-hashed and logged.
    pub build_ccxi: bool,
}

impl Default for ShardStorageOptions {
    fn default() -> Self {
        Self {
            max_events_per_batch: 1024,
            max_batch_bytes: 16 * 1024 * 1024,
            max_event_id_bytes: 128,
            idem_hot_capacity_entries: 100_000,
            event_id_hash_prefix_len: 16,
            cold_scan_max_segments: 256,
            head_max_record_bytes: 0,
            record_block_codec: corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1,
            enable_directory_compaction: false,
            dir_l0_max_runs: 8,
            append_group_commit_batches: 1,
            append_group_commit_max_delay_ms: 0,
            build_ccxi: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShardPaths {
    pub shard_dir: PathBuf,
    pub lock_path: PathBuf,
    pub manifest_path: PathBuf,
    pub segments_dir: PathBuf,
    pub directory_dir: PathBuf,
    pub projections_dir: PathBuf,
    pub tmp_dir: PathBuf,
    pub quarantine_dir: PathBuf,
}

impl ShardPaths {
    pub fn for_root(root: &Path, shard_id: u32) -> Self {
        // Phase 3 convention: shard directories are `shard-0001`, `shard-0002`, ...
        let shard_dir = root.join(format!("shard-{shard_id:04}"));
        Self {
            lock_path: shard_dir.join("LOCK"),
            manifest_path: shard_dir.join("MANIFEST"),
            segments_dir: shard_dir.join("segments"),
            directory_dir: shard_dir.join("directory"),
            projections_dir: shard_dir.join("projections"),
            tmp_dir: shard_dir.join("tmp"),
            quarantine_dir: shard_dir.join("quarantine"),
            shard_dir,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SegmentMeta {
    pub level: u32,
    pub shard_id: u32,
    pub epoch: u64,
    pub segment_seq: u64,
    pub segment_id: SegmentId,
    pub relative_path: String,
    pub file_len: u64,
    pub created_at_unix_ns: u64,
    pub sealed_at_unix_ns: u64,
    pub toc_offset: u64,
    pub toc_len: u64,
    pub toc_entry_count: u64,
    pub min_stream_hash: u64,
    pub min_seq: u64,
    pub max_stream_hash: u64,
    pub max_seq: u64,
    pub segment_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct ManifestSegmentCatalogV1 {
    pub shard_id: u32,
    pub epoch: u64,
    pub manifest_end: u64,
    pub segments: Vec<SegmentMeta>,
}

#[derive(Debug, Clone)]
pub struct ReplicatedSegmentApplyResultV1 {
    pub applied: bool,
    pub shard_id: u32,
    pub epoch: u64,
    pub segment_seq: u64,
    pub segment_id: SegmentId,
    pub segment_hash: [u8; 32],
    pub file_len: u64,
}

/// Result of a force-seal operation on the head segment.
#[derive(Debug, Clone)]
pub struct SealResultV1 {
    /// True if a segment was actually sealed; false if there was no head segment.
    pub sealed: bool,
    pub segment_seq: Option<u64>,
    pub frame_count: Option<u64>,
    /// Seal duration in seconds (0.0 if not sealed).
    pub seal_duration_secs: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct StreamSegmentRef {
    pub segment_seq: u64,
    pub min_seq: u64,
    pub max_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DirRunKey {
    level: u32,
    run_id: u64,
}

#[derive(Debug, Clone)]
struct DirRunMeta {
    key: DirRunKey,
    relative_path: String,
    file_len: u64,
    created_at_unix_ns: u64,
    record_count: u64,
}

#[derive(Debug, Clone)]
pub struct DirectoryLevelStatsV1 {
    pub level: u32,
    pub run_count: u32,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub struct DirectoryLsmStatsV1 {
    pub levels: Vec<DirectoryLevelStatsV1>,
}

#[derive(Debug, Clone)]
pub struct DirCompactionEventV1 {
    pub level_from: u32,
    pub level_to: u32,
    pub duration_ns: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub input_extents: u64,
    pub dropped_extents: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
struct DirExtentV1 {
    stream_hash: u64,
    min_seq: u64,
    max_seq: u64,
    segment_seq: u64,
}

#[derive(Debug, Clone, Copy, Default)]
struct StreamMeta {
    min_live_seq: u64,  // checkpoint cut (seq < min_live_seq hidden)
    tombstone_seq: u64, // tombstone cut (seq < tombstone_seq hidden)
}

fn dirrun_partition_v1(stream_hash: u64) -> usize {
    // Phase 6 v1: shard directory runs are partitioned by the low 8 bits of stream_hash.
    // This keeps the partition key stable across platforms and easy to compute in kernels.
    (stream_hash & 0xFF) as usize
}

fn dir_extent_key_cmp(a: &DirExtentV1, b: &DirExtentV1) -> std::cmp::Ordering {
    // Stable merge key: (stream_hash, segment_seq).
    a.stream_hash
        .cmp(&b.stream_hash)
        .then_with(|| a.segment_seq.cmp(&b.segment_seq))
}

fn encode_dir_extent_v1(e: DirExtentV1) -> [u8; DIREXTENT_LEN_V1] {
    let mut out = [0u8; DIREXTENT_LEN_V1];
    out[0..8].copy_from_slice(&e.stream_hash.to_le_bytes());
    out[8..16].copy_from_slice(&e.min_seq.to_le_bytes());
    out[16..24].copy_from_slice(&e.max_seq.to_le_bytes());
    out[24..32].copy_from_slice(&e.segment_seq.to_le_bytes());
    out
}

// SAFETY: All try_into().unwrap() convert fixed-size byte slices to arrays of matching length.
#[allow(clippy::unwrap_used)]
fn decode_dir_extent_v1(bytes: &[u8]) -> Result<DirExtentV1> {
    if bytes.len() < DIREXTENT_LEN_V1 {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "dir extent too small".to_string(),
        });
    }
    Ok(DirExtentV1 {
        stream_hash: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        min_seq: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        max_seq: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        segment_seq: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    })
}

#[derive(Debug)]
struct DirRunDecodedV1 {
    created_at_unix_ns: u64,
    partitions: Vec<Vec<DirExtentV1>>,
    record_count: u64,
    file_len: u64,
}

fn encode_dir_run_v1(created_at_unix_ns: u64, extents: &[DirExtentV1]) -> Result<Vec<u8>> {
    // Partition extents and ensure each partition is sorted and key-deduped.
    let mut parts: Vec<Vec<DirExtentV1>> = vec![Vec::new(); DIRRUN_PARTITIONS_V1];
    for &e in extents {
        let p = dirrun_partition_v1(e.stream_hash);
        if p >= DIRRUN_PARTITIONS_V1 {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "dirrun partition out of bounds".to_string(),
            });
        }
        parts[p].push(e);
    }

    let mut record_count: u64 = 0;
    for p in &mut parts {
        p.sort_by(dir_extent_key_cmp);
        // Deduplicate by key; if duplicates disagree, merge conservatively.
        let mut out: Vec<DirExtentV1> = Vec::with_capacity(p.len());
        for &e in p.iter() {
            if let Some(last) = out.last_mut() {
                if last.stream_hash == e.stream_hash && last.segment_seq == e.segment_seq {
                    last.min_seq = last.min_seq.min(e.min_seq);
                    last.max_seq = last.max_seq.max(e.max_seq);
                    continue;
                }
            }
            out.push(e);
        }
        record_count = record_count.saturating_add(out.len() as u64);
        *p = out;
    }

    // Compute file layout.
    let mut offsets: Vec<(u64, u32)> = Vec::with_capacity(DIRRUN_PARTITIONS_V1);
    let mut cursor = DIRRUN_HEADER_LEN as u64;
    for p in &parts {
        offsets.push((cursor, p.len() as u32));
        cursor = cursor.saturating_add((p.len() * DIREXTENT_LEN_V1) as u64);
    }

    let file_len = cursor as usize;
    let mut out = Vec::with_capacity(file_len);

    // Header (fixed 4096 bytes) + partition table.
    let mut hdr = [0u8; DIRRUN_HEADER_LEN];
    hdr[0..4].copy_from_slice(&DIRRUN_MAGIC_CCDR.to_le_bytes());
    hdr[4..6].copy_from_slice(&DIRRUN_VERSION_V1.to_le_bytes());
    hdr[6..8].copy_from_slice(&(DIRRUN_HEADER_LEN as u16).to_le_bytes());
    hdr[12..16].copy_from_slice(&(DIRRUN_PARTITIONS_V1 as u32).to_le_bytes());
    hdr[16..20].copy_from_slice(&(DIREXTENT_LEN_V1 as u32).to_le_bytes());
    hdr[24..32].copy_from_slice(&created_at_unix_ns.to_le_bytes());
    hdr[32..40].copy_from_slice(&record_count.to_le_bytes());

    let mut pt_cur = DIRRUN_PARTITION_TABLE_OFFSET_V1;
    for (off, cnt) in offsets {
        let end = pt_cur
            .checked_add(DIRRUN_PARTITION_ENTRY_LEN_V1)
            .ok_or(StorageError::ManifestRecordInvalid {
                msg: "dirrun partition table cursor overflow".to_string(),
            })?;
        if end > DIRRUN_HEADER_LEN {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "dirrun partition table exceeds header".to_string(),
            });
        }
        hdr[pt_cur..pt_cur + 8].copy_from_slice(&off.to_le_bytes());
        hdr[pt_cur + 8..pt_cur + 12].copy_from_slice(&cnt.to_le_bytes());
        pt_cur = end;
    }

    let crc = crc32c::crc32c(&hdr[..DIRRUN_HEADER_LEN - 4]);
    hdr[DIRRUN_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());

    out.extend_from_slice(&hdr);

    // Records.
    for p in &parts {
        for &e in p {
            out.extend_from_slice(&encode_dir_extent_v1(e));
        }
    }

    // Phase 9: pad directory run files to 4KiB so they can be written via O_DIRECT / cuFile.
    let rem = out.len() % 4096;
    if rem != 0 {
        out.resize(out.len() + (4096 - rem), 0u8);
    }
    Ok(out)
}

// SAFETY: All try_into().unwrap() convert fixed-size byte slices to arrays of matching length.
#[allow(clippy::unwrap_used)]
fn decode_dir_run_v1(bytes: &[u8]) -> Result<DirRunDecodedV1> {
    if bytes.len() < DIRRUN_HEADER_LEN {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "dirrun file too small".to_string(),
        });
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if magic != DIRRUN_MAGIC_CCDR {
        return Err(StorageError::ManifestRecordInvalid {
            msg: format!("dirrun bad magic: {magic:#x}"),
        });
    }
    let ver = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    if ver != DIRRUN_VERSION_V1 {
        return Err(StorageError::ManifestRecordInvalid {
            msg: format!("dirrun bad version: {ver}"),
        });
    }
    let header_len = u16::from_le_bytes(bytes[6..8].try_into().unwrap()) as usize;
    if header_len != DIRRUN_HEADER_LEN {
        return Err(StorageError::ManifestRecordInvalid {
            msg: format!("dirrun bad header_len: {header_len}"),
        });
    }
    let partitions = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    if partitions != DIRRUN_PARTITIONS_V1 {
        return Err(StorageError::ManifestRecordInvalid {
            msg: format!("dirrun bad partitions: {partitions}"),
        });
    }
    let extent_len = u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
    if extent_len != DIREXTENT_LEN_V1 {
        return Err(StorageError::ManifestRecordInvalid {
            msg: format!("dirrun bad extent_len: {extent_len}"),
        });
    }

    let expected_crc = u32::from_le_bytes(bytes[DIRRUN_HEADER_LEN - 4..DIRRUN_HEADER_LEN].try_into().unwrap());
    let actual_crc = crc32c::crc32c(&bytes[..DIRRUN_HEADER_LEN - 4]);
    if expected_crc != actual_crc {
        return Err(StorageError::ManifestRecordInvalid {
            msg: format!("dirrun header crc mismatch: expected={expected_crc:#x} actual={actual_crc:#x}"),
        });
    }

    let created_at_unix_ns = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let record_count = u64::from_le_bytes(bytes[32..40].try_into().unwrap());

    let mut parts: Vec<Vec<DirExtentV1>> = vec![Vec::new(); DIRRUN_PARTITIONS_V1];
    let mut total: u64 = 0;

    let mut pt_cur = DIRRUN_PARTITION_TABLE_OFFSET_V1;
    for part in &mut parts {
        let end = pt_cur
            .checked_add(DIRRUN_PARTITION_ENTRY_LEN_V1)
            .ok_or(StorageError::ManifestRecordInvalid {
                msg: "dirrun partition table cursor overflow".to_string(),
            })?;
        if end > DIRRUN_HEADER_LEN {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "dirrun partition table exceeds header".to_string(),
            });
        }
        let off = u64::from_le_bytes(bytes[pt_cur..pt_cur + 8].try_into().unwrap());
        let cnt = u32::from_le_bytes(bytes[pt_cur + 8..pt_cur + 12].try_into().unwrap()) as usize;
        pt_cur = end;

        if cnt == 0 {
            continue;
        }
        if off < DIRRUN_HEADER_LEN as u64 {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "dirrun partition offset points into header".to_string(),
            });
        }
        let start = usize::try_from(off).map_err(|_| StorageError::ManifestRecordInvalid {
            msg: "dirrun partition offset overflow".to_string(),
        })?;
        let len = cnt
            .checked_mul(DIREXTENT_LEN_V1)
            .ok_or(StorageError::ManifestRecordInvalid {
                msg: "dirrun partition length overflow".to_string(),
            })?;
        let end = start.checked_add(len).ok_or(StorageError::ManifestRecordInvalid {
            msg: "dirrun partition end overflow".to_string(),
        })?;
        if end > bytes.len() {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "dirrun partition out of bounds".to_string(),
            });
        }

        let mut v: Vec<DirExtentV1> = Vec::with_capacity(cnt);
        let mut cur = start;
        while cur < end {
            v.push(decode_dir_extent_v1(&bytes[cur..cur + DIREXTENT_LEN_V1])?);
            cur += DIREXTENT_LEN_V1;
        }
        v.sort_by(dir_extent_key_cmp);
        *part = v;
        total = total.saturating_add(cnt as u64);
    }

    if record_count != total {
        return Err(StorageError::ManifestRecordInvalid {
            msg: format!("dirrun record_count mismatch: header={record_count} actual={total}"),
        });
    }

    Ok(DirRunDecodedV1 {
        created_at_unix_ns,
        partitions: parts,
        record_count,
        file_len: bytes.len() as u64,
    })
}

fn dir_run_relative_path_v1(level: u32, run_id: u64) -> String {
    // Phase 6 v1 naming: stable and lexicographically sortable.
    format!("directory/dirrun-l{level}-r{run_id:020}.ccxdir")
}

#[allow(clippy::many_single_char_names)] // Merge loop: a/b inputs, i/j cursors, e entry — standard naming
fn merge_dir_extents_partition_sorted_unique_cpu(a: &[DirExtentV1], b: &[DirExtentV1]) -> Vec<DirExtentV1> {
    let mut out: Vec<DirExtentV1> = Vec::with_capacity(a.len().saturating_add(b.len()));
    let mut i = 0usize;
    let mut j = 0usize;
    while i < a.len() || j < b.len() {
        let take_a = if j >= b.len() {
            true
        } else if i >= a.len() {
            false
        } else {
            dir_extent_key_cmp(&a[i], &b[j]).is_lt()
        };
        if take_a {
            let e = a[i];
            i += 1;
            if let Some(last) = out.last_mut() {
                if last.stream_hash == e.stream_hash && last.segment_seq == e.segment_seq {
                    last.min_seq = last.min_seq.min(e.min_seq);
                    last.max_seq = last.max_seq.max(e.max_seq);
                    continue;
                }
            }
            out.push(e);
            continue;
        }

        if i >= a.len() {
            let e = b[j];
            j += 1;
            if let Some(last) = out.last_mut() {
                if last.stream_hash == e.stream_hash && last.segment_seq == e.segment_seq {
                    last.min_seq = last.min_seq.min(e.min_seq);
                    last.max_seq = last.max_seq.max(e.max_seq);
                    continue;
                }
            }
            out.push(e);
            continue;
        }

        let cmp = dir_extent_key_cmp(&a[i], &b[j]);
        if cmp.is_gt() {
            let e = b[j];
            j += 1;
            if let Some(last) = out.last_mut() {
                if last.stream_hash == e.stream_hash && last.segment_seq == e.segment_seq {
                    last.min_seq = last.min_seq.min(e.min_seq);
                    last.max_seq = last.max_seq.max(e.max_seq);
                    continue;
                }
            }
            out.push(e);
        } else {
            // Equal key: prefer b's fields but merge min/max conservatively.
            let mut e = b[j];
            e.min_seq = e.min_seq.min(a[i].min_seq);
            e.max_seq = e.max_seq.max(a[i].max_seq);
            i += 1;
            j += 1;
            if let Some(last) = out.last_mut() {
                if last.stream_hash == e.stream_hash && last.segment_seq == e.segment_seq {
                    last.min_seq = last.min_seq.min(e.min_seq);
                    last.max_seq = last.max_seq.max(e.max_seq);
                    continue;
                }
            }
            out.push(e);
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLocation {
    pub shard_id: u64,
    pub epoch: u64,
    pub segment_seq: u64,
    pub offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayCursor {
    pub segment_seq: u64,
    pub offset: u64,
}

pub type ReplayFrames = Vec<(FrameLocation, Vec<u8>)>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadFrameBatchPackedV1 {
    pub frames_blob: Vec<u8>,
    pub frame_offsets: Vec<u32>,
    pub frame_lens: Vec<u32>,
    pub frame_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayScanStats {
    pub total_segments: u64,
    pub total_blocks: u64,
    pub total_frames: u64,
    pub total_compressed_bytes: u64,
    pub total_uncompressed_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReadStatsV1 {
    pub segments_touched: u32,
    pub blocks_touched: u32,
    pub frames_selected: u32,
    pub disk_bytes_estimate: u64,
    pub frame_bytes: u64,
    pub index_lookup_nanos: u64,
    pub io_nanos: u64,
    pub decode_nanos: u64,
    pub total_nanos: u64,
    pub head_frames_scanned: u32,
    pub head_tail_fastpath_hits: u32,
    pub head_tail_fastpath_misses: u32,
    pub locator_fully_satisfied_hits: u32,
    pub locator_fully_satisfied_misses: u32,
}

impl ReadStatsV1 {
    #[inline]
    fn add_index_elapsed(&mut self, elapsed: std::time::Duration) {
        self.index_lookup_nanos = self
            .index_lookup_nanos
            .saturating_add(elapsed.as_nanos().min(u64::MAX as u128) as u64);
    }

    #[inline]
    fn add_io_elapsed(&mut self, elapsed: std::time::Duration) {
        self.io_nanos = self
            .io_nanos
            .saturating_add(elapsed.as_nanos().min(u64::MAX as u128) as u64);
    }

    #[inline]
    fn add_decode_elapsed(&mut self, elapsed: std::time::Duration) {
        self.decode_nanos = self
            .decode_nanos
            .saturating_add(elapsed.as_nanos().min(u64::MAX as u128) as u64);
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriteConfirmationMaterialV1 {
    pub commit_seq: u64,
    pub segment_id: u64,
    pub receipt_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AppendStatsV1 {
    pub idempotency_check_nanos: u64,
    pub index_update_nanos: u64,
    pub io_write_nanos: u64,
    pub fence_wait_nanos: u64,
    pub fence_fsync_nanos: u64,
    pub fence_nanos: u64,
    pub total_nanos: u64,
    pub write_confirmation: Option<WriteConfirmationMaterialV1>,
}

impl AppendStatsV1 {
    #[inline]
    fn add_idempotency_elapsed(&mut self, elapsed: std::time::Duration) {
        self.idempotency_check_nanos = self
            .idempotency_check_nanos
            .saturating_add(elapsed.as_nanos().min(u64::MAX as u128) as u64);
    }

    #[inline]
    fn add_index_elapsed(&mut self, elapsed: std::time::Duration) {
        self.index_update_nanos = self
            .index_update_nanos
            .saturating_add(elapsed.as_nanos().min(u64::MAX as u128) as u64);
    }

    #[inline]
    fn add_io_write_elapsed(&mut self, elapsed: std::time::Duration) {
        self.io_write_nanos = self
            .io_write_nanos
            .saturating_add(elapsed.as_nanos().min(u64::MAX as u128) as u64);
    }

    #[inline]
    #[allow(dead_code)]
    fn add_fence_wait_elapsed(&mut self, elapsed: std::time::Duration) {
        let nanos = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        self.fence_wait_nanos = self.fence_wait_nanos.saturating_add(nanos);
        self.fence_nanos = self.fence_nanos.saturating_add(nanos);
    }

    #[inline]
    fn add_fence_fsync_elapsed(&mut self, elapsed: std::time::Duration) {
        let nanos = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        self.fence_fsync_nanos = self.fence_fsync_nanos.saturating_add(nanos);
        self.fence_nanos = self.fence_nanos.saturating_add(nanos);
    }
}

fn add_selected_entries_stats(
    stats: &mut ReadStatsV1,
    blocks: &[BlockMetaV1],
    selected: &[TocByOffsetEntryV1],
) -> Result<u64> {
    if selected.is_empty() {
        return Ok(0);
    }

    stats.frames_selected = stats
        .frames_selected
        .saturating_add(selected.len().min(u32::MAX as usize) as u32);
    stats.frame_bytes = stats.frame_bytes.saturating_add(
        selected
            .iter()
            .map(|e| e.frame_len as u64)
            .fold(0u64, |acc, v| acc.saturating_add(v)),
    );

    let mut block_ids: Vec<u32> = selected.iter().map(|e| e.block_id).collect();
    block_ids.sort_unstable();
    block_ids.dedup();
    stats.blocks_touched = stats
        .blocks_touched
        .saturating_add(block_ids.len().min(u32::MAX as usize) as u32);

    let mut disk_bytes = 0u64;
    for block_id in block_ids {
        let block = blocks
            .get(block_id as usize)
            .ok_or_else(|| StorageError::ManifestRecordInvalid {
                msg: format!("toc block_id {} out of range", block_id),
            })?;
        let physical_len = if block.physical_len == 0 {
            block.compressed_len
        } else {
            block.physical_len
        };
        disk_bytes = disk_bytes.saturating_add(physical_len as u64);
    }
    stats.disk_bytes_estimate = stats.disk_bytes_estimate.saturating_add(disk_bytes);
    Ok(disk_bytes)
}

#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub seq: u64,
    pub event_id: String,
    pub occurred_at: String,
    pub ingested_at: String,
    pub event_type: String,
    pub content_type: String,
    pub payload: Vec<u8>,
    pub location: FrameLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendStatus {
    Appended,
    DuplicateCommitted,
    DuplicateInBatch,
    Rejected,
}

#[derive(Debug, Clone)]
pub struct AppendOutcome {
    pub status: AppendStatus,
    pub seq: u64,
    pub location: Option<FrameLocation>,
    pub payload_hash: [u8; 32],
    pub header_hash: [u8; 32],
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IdemKey {
    stream_hash: u64,
    event_id_hash16: [u8; 16],
}

#[derive(Debug, Clone, Copy)]
struct IdemEntry {
    seq: u64,
    loc: FrameLocation,
}

#[derive(Debug, Clone, Copy)]
struct IdemOrderEntry {
    key: IdemKey,
    seq: u64,
}

#[derive(Debug, Clone)]
struct ColdBatchMatch {
    event_id: String,
    outcome: AppendOutcome,
}

#[derive(Debug, Default)]
struct ColdBatchLookup {
    by_prefix: HashMap<[u8; 16], Vec<ColdBatchMatch>>,
    scanned_all: bool,
    scanned_segments: usize,
    total_segments: usize,
}

impl ColdBatchLookup {
    fn find(&self, prefix: [u8; 16], event_id: &str) -> Option<AppendOutcome> {
        self.by_prefix.get(&prefix).and_then(|candidates| {
            candidates
                .iter()
                .find(|c| c.event_id == event_id)
                .map(|c| c.outcome.clone())
        })
    }
}

#[derive(Debug)]
struct IdemHotCache {
    cap: usize,
    by_key: HashMap<IdemKey, Vec<IdemEntry>>,
    order: VecDeque<IdemOrderEntry>,
    total_entries: usize,
    incomplete: bool,
}

impl IdemHotCache {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            by_key: HashMap::new(),
            order: VecDeque::new(),
            total_entries: 0,
            incomplete: false,
        }
    }

    fn is_incomplete(&self) -> bool {
        self.incomplete
    }

    fn candidates(&self, key: &IdemKey) -> Option<&[IdemEntry]> {
        self.by_key.get(key).map(|v| v.as_slice())
    }

    fn insert(&mut self, key: IdemKey, entry: IdemEntry) {
        if self.cap == 0 {
            self.incomplete = true;
            return;
        }

        self.by_key.entry(key).or_default().push(entry);
        self.order.push_back(IdemOrderEntry { key, seq: entry.seq });
        self.total_entries += 1;

        while self.total_entries > self.cap {
            self.evict_one();
        }
    }

    fn evict_one(&mut self) {
        let Some(oldest) = self.order.pop_front() else {
            return;
        };
        if let Some(v) = self.by_key.get_mut(&oldest.key) {
            if let Some(idx) = v.iter().position(|e| e.seq == oldest.seq) {
                v.swap_remove(idx);
                self.total_entries = self.total_entries.saturating_sub(1);
            }
            if v.is_empty() {
                self.by_key.remove(&oldest.key);
            }
        }
        self.incomplete = true;
    }
}

#[derive(Debug, Clone)]
struct HeadFrameMeta {
    stream_hash: u64,
    seq: u64,
    record_off: u32,
    frame_len: u32,
    payload_len: u32,
    event_id_hash16: [u8; 16],
    header_digest8: [u8; 8],
    payload_digest8: [u8; 8],
    block_id: u32,
    in_block_offset: u32,
}

const STREAM_TAIL_LOCATOR_MAX_EVENTS: usize = 64;
const FRAME_WINDOW_COALESCE_GAP_BYTES: u64 = 4096;
const HEAD_STREAM_TAIL_INDEX_MAX_EVENTS: usize = 256;

#[derive(Debug, Clone, Copy)]
struct StreamTailLocatorEntry {
    segment_seq: u64,
    entry: TocByOffsetEntryV1,
}

#[derive(Debug, Clone)]
struct StreamTailLocator {
    entries_asc: Vec<StreamTailLocatorEntry>,
}

#[derive(Debug, Clone)]
struct StreamTailPointer {
    latest_segment_seq: u64,
    latest_seq: u64,
    entries_desc: Vec<StreamTailLocatorEntry>,
    grouped_desc: Vec<StreamTailPointerGroup>,
}

#[derive(Debug, Clone)]
struct StreamTailPointerGroup {
    segment_seq: u64,
    entries_desc: Vec<TocByOffsetEntryV1>,
}

#[derive(Debug, Clone, Copy)]
struct CommitFrameV1 {
    commit_id: u64,
    commit_seq: u64,
    commit_offset: u64,
    crc32c_committed_region: u32,
}

#[derive(Debug)]
struct HeadSegment {
    segment_seq: u64,
    segment_id: SegmentId,
    created_at_unix_ns: u64,
    relative_path: String,
    file: File,
    record_len: u64,
    frames: Vec<HeadFrameMeta>,
    blocks: Vec<BlockMetaV1>, // last block is the currently-appending block
    stream_min_max: HashMap<u64, (u64, u64)>,
    stream_tail_idx_by_stream: HashMap<u64, Vec<HeadTailFrameRef>>,
    committed_region_crc32c: u32,
    commit_frame_count: u64,
    last_commit_id: u64,
}

#[derive(Debug, Clone, Copy)]
struct HeadTailFrameRef {
    frame_idx: usize,
    seq: u64,
}

fn build_head_stream_tail_index(frames: &[HeadFrameMeta]) -> HashMap<u64, Vec<HeadTailFrameRef>> {
    let mut by_stream: HashMap<u64, Vec<HeadTailFrameRef>> = HashMap::new();
    for (idx, frame) in frames.iter().enumerate() {
        let bucket = by_stream.entry(frame.stream_hash).or_default();
        bucket.push(HeadTailFrameRef {
            frame_idx: idx,
            seq: frame.seq,
        });
        if bucket.len() > HEAD_STREAM_TAIL_INDEX_MAX_EVENTS {
            let drop_n = bucket.len().saturating_sub(HEAD_STREAM_TAIL_INDEX_MAX_EVENTS);
            bucket.drain(0..drop_n);
        }
    }
    by_stream
}

fn push_head_stream_tail_index(
    by_stream: &mut HashMap<u64, Vec<HeadTailFrameRef>>,
    stream_hash: u64,
    frame_idx: usize,
    seq: u64,
) {
    let bucket = by_stream.entry(stream_hash).or_default();
    bucket.push(HeadTailFrameRef { frame_idx, seq });
    if bucket.len() > HEAD_STREAM_TAIL_INDEX_MAX_EVENTS {
        let drop_n = bucket.len().saturating_sub(HEAD_STREAM_TAIL_INDEX_MAX_EVENTS);
        bucket.drain(0..drop_n);
    }
}

fn encode_commit_frame_v1(
    commit_id: u64,
    commit_seq: u64,
    commit_offset: u64,
    crc32c_committed_region: u32,
) -> [u8; COMMIT_FRAME_LEN_V1] {
    let mut out = [0u8; COMMIT_FRAME_LEN_V1];
    out[0..4].copy_from_slice(&COMMIT_FRAME_MAGIC_CCMT.to_le_bytes());
    out[4..6].copy_from_slice(&COMMIT_FRAME_VERSION_V1.to_le_bytes());
    out[6..8].copy_from_slice(&(COMMIT_FRAME_LEN_V1 as u16).to_le_bytes());
    out[8..16].copy_from_slice(&commit_id.to_le_bytes());
    out[16..24].copy_from_slice(&commit_seq.to_le_bytes());
    out[24..32].copy_from_slice(&commit_offset.to_le_bytes());
    out[32..36].copy_from_slice(&crc32c_committed_region.to_le_bytes());
    out[36..40].copy_from_slice(&0u32.to_le_bytes()); // reserved
                                                      // [40..56] toc digest partial (unused in v1): zeros
                                                      // [56..60] reserved bytes: zeros
    let hdr_crc = crc32c::crc32c(&out[..COMMIT_FRAME_LEN_V1 - 4]);
    out[COMMIT_FRAME_LEN_V1 - 4..].copy_from_slice(&hdr_crc.to_le_bytes());
    out
}

// SAFETY: All try_into().unwrap() convert fixed-size byte slices to arrays of matching length.
#[allow(clippy::unwrap_used)]
fn decode_commit_frame_v1(bytes: &[u8]) -> Result<CommitFrameV1> {
    if bytes.len() < COMMIT_FRAME_LEN_V1 {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "commit frame too small".to_string(),
        });
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if magic != COMMIT_FRAME_MAGIC_CCMT {
        return Err(StorageError::ManifestRecordInvalid {
            msg: format!("invalid commit frame magic: {magic:#x}"),
        });
    }
    let ver = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    if ver != COMMIT_FRAME_VERSION_V1 {
        return Err(StorageError::ManifestRecordInvalid {
            msg: format!("unsupported commit frame version: {ver}"),
        });
    }
    let header_len = u16::from_le_bytes(bytes[6..8].try_into().unwrap()) as usize;
    if header_len != COMMIT_FRAME_LEN_V1 {
        return Err(StorageError::ManifestRecordInvalid {
            msg: format!("invalid commit frame header_len: {header_len}"),
        });
    }
    let expected = u32::from_le_bytes(bytes[COMMIT_FRAME_LEN_V1 - 4..COMMIT_FRAME_LEN_V1].try_into().unwrap());
    let actual = crc32c::crc32c(&bytes[..COMMIT_FRAME_LEN_V1 - 4]);
    if expected != actual {
        return Err(StorageError::ManifestRecordInvalid {
            msg: format!("commit frame header crc mismatch: expected={expected:#x} actual={actual:#x}"),
        });
    }

    Ok(CommitFrameV1 {
        commit_id: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        commit_seq: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        commit_offset: u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
        crc32c_committed_region: u32::from_le_bytes(bytes[32..36].try_into().unwrap()),
    })
}

fn parse_head_record_len(bytes: &[u8], offset: usize) -> Option<usize> {
    if offset.checked_add(4)? > bytes.len() {
        return None;
    }
    let magic = u32::from_le_bytes(bytes[offset..offset + 4].try_into().ok()?);
    if magic == corecrux_segment::FRAME_MAGIC_CRX1 {
        return frame_len_at(bytes, offset as u64);
    }
    if magic == COMMIT_FRAME_MAGIC_CCMT {
        if offset.checked_add(COMMIT_FRAME_LEN_V1)? > bytes.len() {
            return None;
        }
        if decode_commit_frame_v1(&bytes[offset..offset + COMMIT_FRAME_LEN_V1]).is_ok() {
            return Some(COMMIT_FRAME_LEN_V1);
        }
    }
    None
}

fn compute_write_confirmation_receipt_hash(frame_bytes: &[Vec<u8>]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for frame in frame_bytes {
        let frame_hash = blake3::hash(frame);
        hasher.update(frame_hash.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn validate_commit_frame_candidate(bytes: &[u8], marker_off: usize) -> Option<CommitFrameV1> {
    if marker_off < corecrux_segment::SEGMENT_HEADER_LEN {
        return None;
    }
    let end = marker_off.checked_add(COMMIT_FRAME_LEN_V1)?;
    if end > bytes.len() {
        return None;
    }
    let frame = decode_commit_frame_v1(&bytes[marker_off..end]).ok()?;
    if frame.commit_offset != end as u64 {
        return None;
    }
    let region_crc = crc32c::crc32c(&bytes[corecrux_segment::SEGMENT_HEADER_LEN..marker_off]);
    if region_crc != frame.crc32c_committed_region {
        return None;
    }
    Some(frame)
}

fn find_last_valid_commit_frame(bytes: &[u8]) -> Option<CommitFrameV1> {
    if bytes.len() < corecrux_segment::SEGMENT_HEADER_LEN + COMMIT_FRAME_LEN_V1 {
        return None;
    }
    let magic = COMMIT_FRAME_MAGIC_CCMT.to_le_bytes();
    let mut scan_end = bytes.len();
    while scan_end > corecrux_segment::SEGMENT_HEADER_LEN {
        let scan_start = scan_end
            .saturating_sub(COMMIT_FRAME_SCAN_WINDOW_BYTES)
            .max(corecrux_segment::SEGMENT_HEADER_LEN);
        let window = &bytes[scan_start..scan_end];
        if window.len() < 4 {
            break;
        }
        let mut idx = window.len() - 4;
        loop {
            if window[idx..idx + 4] == magic {
                let abs_off = scan_start + idx;
                if let Some(frame) = validate_commit_frame_candidate(bytes, abs_off) {
                    return Some(frame);
                }
            }
            if idx == 0 {
                break;
            }
            idx -= 1;
        }
        if scan_start == corecrux_segment::SEGMENT_HEADER_LEN {
            break;
        }
        // 3-byte overlap to avoid missing a magic split across chunk boundaries.
        scan_end = scan_start + 3;
    }
    None
}

fn append_head_record_to_blocks(
    blocks: &mut Vec<BlockMetaV1>,
    record_off: u64,
    record_bytes: &[u8],
    stream_hash_for_bloom: Option<u64>,
) -> Result<(u32, u32)> {
    let max_len = corecrux_segment::RECORD_BLOCK_UNCOMPRESSED_MAX_LEN_V1 as usize;
    if blocks.is_empty() {
        blocks.push(BlockMetaV1 {
            block_id: 0,
            codec: 0,
            file_offset: (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(record_off),
            compressed_len: 0,
            physical_len: 0,
            uncompressed_len: 0,
            crc32c: 0,
            bloom: [0u8; corecrux_segment::BLOOM_BYTES_PER_BLOCK_V1],
        });
    }

    let cur_block_len = blocks.last().map_or(0, |b| b.uncompressed_len as usize);
    if cur_block_len > 0 && cur_block_len.saturating_add(record_bytes.len()) > max_len {
        let next_id = blocks.len() as u32;
        blocks.push(BlockMetaV1 {
            block_id: next_id,
            codec: 0,
            file_offset: (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(record_off),
            compressed_len: 0,
            physical_len: 0,
            uncompressed_len: 0,
            crc32c: 0,
            bloom: [0u8; corecrux_segment::BLOOM_BYTES_PER_BLOCK_V1],
        });
    }

    let rec_len_u32 = u32::try_from(record_bytes.len()).map_err(|_| StorageError::ManifestRecordInvalid {
        msg: "record length exceeds u32".to_string(),
    })?;

    // SAFETY: blocks is guaranteed non-empty — we push at least one entry above.
    #[allow(clippy::expect_used)]
    let block = blocks.last_mut().expect("blocks non-empty");
    let in_block_offset = block.uncompressed_len;
    if let Some(stream_hash) = stream_hash_for_bloom {
        corecrux_segment::bloom_insert_stream_hash_v1(&mut block.bloom, corecrux_segment::BLOOM_HASH_K_V1, stream_hash);
    }
    block.crc32c = crc32c::crc32c_append(block.crc32c, record_bytes);
    block.uncompressed_len = block.uncompressed_len.saturating_add(rec_len_u32);
    block.compressed_len = block.uncompressed_len;
    block.physical_len = block.compressed_len;
    Ok((block.block_id, in_block_offset))
}

pub struct ShardStorage {
    options: ShardStorageOptions,
    shard_id: u32,
    epoch: u64,
    paths: ShardPaths,
    _lock_file: File,

    manifest: File,
    manifest_end: u64,

    segments_by_seq: HashMap<u64, SegmentMeta>,
    segment_files_by_seq: HashMap<u64, File>,
    segments_in_order: Vec<SegmentMeta>,
    directory_by_stream: HashMap<u64, Vec<StreamSegmentRef>>,
    segment_trailers_by_seq: HashMap<u64, TrailerIndexV1>,
    segment_stream_ranges_by_seq: HashMap<u64, HashMap<u64, (u32, u32)>>,
    tail_locator_by_stream: HashMap<u64, StreamTailLocator>,
    tail_pointer_by_stream: HashMap<u64, StreamTailPointer>,
    dir_runs: HashMap<DirRunKey, DirRunMeta>,
    stream_meta: HashMap<u64, StreamMeta>,

    // Persistent-ish in-memory state rebuilt at startup (Phase 2).
    next_seq_by_stream: HashMap<u64, u64>,
    idem_hot: IdemHotCache,
    idem_prefix_seen: HashSet<IdemKey>,

    next_segment_seq: u64,
    next_head_commit_id: u64,

    head: Option<HeadSegment>,
}

mod append;
mod compact;
mod companions;
mod integrity;
mod manifest;
mod read;
mod replication;
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests;

// Re-export manifest items that were previously pub at crate root.
pub use manifest::{
    encode_manifest_add_segment_v1, encode_manifest_header_v1, frame_manifest_record, load_manifest_segment_catalog,
};
// Manifest internals used by ShardStorage::open().
use manifest::load_manifest_records;
impl ShardStorage {
    pub fn open(root: &Path, shard_id: u32, epoch: u64, options: ShardStorageOptions) -> Result<Self> {
        if options.event_id_hash_prefix_len == 0 || options.event_id_hash_prefix_len > 16 {
            return Err(StorageError::InvalidArgument {
                code: "CONFIG_INVALID".to_string(),
                msg: format!(
                    "event_id_hash_prefix_len must be within 1..=16, got {}",
                    options.event_id_hash_prefix_len
                ),
            });
        }

        let paths = ShardPaths::for_root(root, shard_id);
        create_dir_all(&paths.segments_dir).map_err(io_err)?;
        create_dir_all(&paths.directory_dir).map_err(io_err)?;
        create_dir_all(&paths.projections_dir).map_err(io_err)?;
        create_dir_all(&paths.tmp_dir).map_err(io_err)?;
        create_dir_all(&paths.quarantine_dir).map_err(io_err)?;

        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&paths.lock_path)
            .map_err(io_err)?;
        lock_file.try_lock_exclusive().map_err(io_err)?;

        let mut manifest = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&paths.manifest_path)
            .map_err(io_err)?;

        if manifest.metadata().map_err(io_err)?.len() == 0 {
            let hdr = encode_manifest_header_v1(shard_id, epoch, now_unix_ns())?;
            manifest.write_all(&hdr).map_err(io_err)?;
            manifest.sync_all().map_err(io_err)?;
        }

        let (state, manifest_end) = load_manifest_records(&mut manifest)?;

        // Move tmp tails and orphaned segments out of the active directory to avoid collisions on
        // restart (crash before MANIFEST commit boundary).
        let mut referenced: HashSet<String> = HashSet::new();
        for s in state.segments_by_seq.values() {
            referenced.insert(s.relative_path.clone());
        }
        for r in state.dir_runs.values() {
            referenced.insert(r.relative_path.clone());
        }
        let mut max_seg_seq_on_disk = 0u64;

        if let Ok(rd) = std::fs::read_dir(&paths.tmp_dir) {
            for e in rd.flatten() {
                let p = e.path();
                if !p.is_file() {
                    continue;
                }
                let name = match p.file_name().and_then(|s| s.to_str()) {
                    Some(s) => s,
                    None => continue,
                };
                if let Some(seq) = parse_segment_seq_from_filename(name) {
                    max_seg_seq_on_disk = max_seg_seq_on_disk.max(seq);
                }
                let dst = paths.quarantine_dir.join(format!("tmp-{}-{name}", now_unix_ns()));
                std::fs::rename(&p, &dst).map_err(io_err)?;
            }
        }

        if let Ok(rd) = std::fs::read_dir(&paths.segments_dir) {
            for e in rd.flatten() {
                let p = e.path();
                if !p.is_file() {
                    continue;
                }
                let name = match p.file_name().and_then(|s| s.to_str()) {
                    Some(s) => s,
                    None => continue,
                };
                if name.ends_with(".ccxhead") {
                    // Head segments are not tracked by MANIFEST; keep for Phase 5 reads/writes.
                    continue;
                }
                if let Some(seq) = parse_segment_seq_from_filename(name) {
                    max_seg_seq_on_disk = max_seg_seq_on_disk.max(seq);
                }
                let rel = format!("segments/{name}");
                if referenced.contains(&rel) {
                    continue;
                }
                let dst = paths.quarantine_dir.join(format!("orphan-{}-{name}", now_unix_ns()));
                std::fs::rename(&p, &dst).map_err(io_err)?;
            }
        }
        if let Ok(rd) = std::fs::read_dir(&paths.directory_dir) {
            for e in rd.flatten() {
                let p = e.path();
                if !p.is_file() {
                    continue;
                }
                let name = match p.file_name().and_then(|s| s.to_str()) {
                    Some(s) => s,
                    None => continue,
                };
                let rel = format!("directory/{name}");
                if referenced.contains(&rel) {
                    continue;
                }
                let dst = paths
                    .quarantine_dir
                    .join(format!("dirrun-orphan-{}-{name}", now_unix_ns()));
                std::fs::rename(&p, &dst).map_err(io_err)?;
            }
        }
        fsync_dir(&paths.segments_dir)?;
        fsync_dir(&paths.directory_dir)?;
        fsync_dir(&paths.tmp_dir)?;
        fsync_dir(&paths.quarantine_dir)?;

        // Validate segments and rebuild state.
        let mut segments_by_seq = HashMap::new();
        let mut segment_files_by_seq = HashMap::new();
        let mut segments_in_order = Vec::new();
        let mut directory_by_stream: HashMap<u64, Vec<StreamSegmentRef>> = HashMap::new();
        let mut segment_trailers_by_seq: HashMap<u64, TrailerIndexV1> = HashMap::new();
        let mut segment_stream_ranges_by_seq: HashMap<u64, HashMap<u64, (u32, u32)>> = HashMap::new();
        let mut extents_by_segment: HashMap<u64, Vec<DirExtentV1>> = HashMap::new();

        let mut next_seq_by_stream: HashMap<u64, u64> = HashMap::new();
        let mut idem_hot = IdemHotCache::new(options.idem_hot_capacity_entries);
        let mut idem_prefix_seen: HashSet<IdemKey> = HashSet::new();

        let mut segments: Vec<SegmentMeta> = state.segments_by_seq.values().cloned().collect();
        segments.sort_by_key(|s| s.segment_seq);
        let dir_runs = state.dir_runs;
        let stream_meta = state.stream_meta;

        // Startup performance guard:
        // Rebuild idempotency hot state only for the most recent bounded segment window.
        // Older duplicates still follow the existing bounded cold-scan path.
        let idem_rebuild_cap = options.cold_scan_max_segments;
        let recent_segment_floor_seq = if idem_rebuild_cap == 0 || segments.is_empty() {
            u64::MAX
        } else {
            let keep = idem_rebuild_cap.min(segments.len());
            segments[segments.len() - keep].segment_seq
        };

        let mut max_seg_seq = max_seg_seq_on_disk;
        for seg in segments {
            max_seg_seq = max_seg_seq.max(seg.segment_seq);
            let seg_path = paths.shard_dir.join(&seg.relative_path);
            let seg_file = File::open(&seg_path).map_err(io_err)?;
            segment_files_by_seq.insert(seg.segment_seq, seg_file);
            let bytes = std::fs::read(&seg_path).map_err(io_err)?;
            let (_h, toc_h, entries, f) = decode_segment_v1(&bytes)?;
            let toc_off = f.toc_offset as usize;
            let toc_len = f.toc_len as usize;
            if toc_off + toc_len > bytes.len() {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: "toc area out of bounds".to_string(),
                });
            }
            let toc_area = &bytes[toc_off..toc_off + toc_len];
            if let Some(ti) = decode_trailer_index_v1(toc_area, &toc_h)? {
                let ranges = build_trailer_stream_ranges(&ti);
                segment_trailers_by_seq.insert(seg.segment_seq, ti);
                segment_stream_ranges_by_seq.insert(seg.segment_seq, ranges);
            }

            // Build shard directory refs for range/tail reads.
            let mut seg_extents: Vec<DirExtentV1> = Vec::new();
            let mut i = 0usize;
            while i < entries.len() {
                let sh = entries[i].stream_hash;
                let min_seq = entries[i].seq;
                let mut max_seq = min_seq;
                i += 1;
                while i < entries.len() && entries[i].stream_hash == sh {
                    max_seq = entries[i].seq;
                    i += 1;
                }
                directory_by_stream.entry(sh).or_default().push(StreamSegmentRef {
                    segment_seq: seg.segment_seq,
                    min_seq,
                    max_seq,
                });
                next_seq_by_stream
                    .entry(sh)
                    .and_modify(|v| *v = (*v).max(max_seq + 1))
                    .or_insert(max_seq + 1);
                seg_extents.push(DirExtentV1 {
                    stream_hash: sh,
                    min_seq,
                    max_seq,
                    segment_seq: seg.segment_seq,
                });
            }
            extents_by_segment.insert(seg.segment_seq, seg_extents);

            // Rebuild idempotency hot state only for recent segments.
            // This keeps startup bounded while preserving the existing bounded cold-scan semantics.
            if seg.segment_seq >= recent_segment_floor_seq {
                for e in entries {
                    let stream_hash = e.stream_hash;
                    let seq = e.seq;

                    // event_id_hash16 is sufficient for Phase 2 rebuild; verify-on-hit is Phase 4.
                    let mut h16 = [0u8; 16];
                    h16.copy_from_slice(&e.event_id_hash16);
                    let loc = FrameLocation {
                        shard_id: seg.shard_id as u64,
                        epoch: seg.epoch,
                        segment_seq: seg.segment_seq,
                        offset: e.file_offset as u64,
                    };
                    let key = IdemKey {
                        stream_hash,
                        event_id_hash16: normalize_hash16_prefix(h16, options.event_id_hash_prefix_len),
                    };
                    idem_prefix_seen.insert(key);
                    idem_hot.insert(key, IdemEntry { seq, loc });
                }
            }

            segments_by_seq.insert(seg.segment_seq, seg.clone());
            segments_in_order.push(seg);
        }
        segments_in_order.sort_by_key(|s| s.segment_seq);
        for refs in directory_by_stream.values_mut() {
            refs.sort_by_key(|r| r.segment_seq);
        }

        let mut out = Self {
            options,
            shard_id,
            epoch,
            paths,
            _lock_file: lock_file,
            manifest_end,
            manifest,
            segments_by_seq,
            segment_files_by_seq,
            segments_in_order,
            directory_by_stream,
            segment_trailers_by_seq,
            segment_stream_ranges_by_seq,
            tail_locator_by_stream: HashMap::new(),
            tail_pointer_by_stream: HashMap::new(),
            dir_runs,
            stream_meta,
            next_seq_by_stream,
            idem_hot,
            idem_prefix_seen,
            next_segment_seq: max_seg_seq + 1,
            next_head_commit_id: 1,
            head: None,
        };

        out.load_head_segment_from_disk()?;
        if out.options.head_max_record_bytes == 0 {
            // Preserve Phase 2 behavior: no head segments. If we find one on disk (from a prior
            // run), seal+publish it now so we don't strand committed bytes outside MANIFEST.
            out.seal_head_segment_if_any()?;
        }

        // Phase 6: ensure shard directory runs are present and rebuild the in-memory directory
        // from them. This is recoverable state derived from sealed segment TOCs.
        //
        // Guard startup time on large legacy data dirs: if no dir-runs exist and segment count is
        // very large, skip immediate run publishing and continue with the in-memory directory that
        // was already rebuilt from TOCs above.
        let skip_bootstrap_dirruns =
            should_skip_startup_dirrun_bootstrap(out.dir_runs.is_empty(), out.segments_in_order.len());
        if !skip_bootstrap_dirruns {
            out.bootstrap_directory_runs_on_open(&extents_by_segment)?;
        }
        out.rebuild_tail_locator_from_directory()?;

        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct AppendEventInput<'a> {
    pub event_id: &'a str,
    pub occurred_at: &'a str,
    pub event_type: &'a str,
    pub content_type: &'a str,
    pub payload_bytes: &'a [u8],
}

#[derive(Debug)]
struct NewFrameMeta<'a> {
    event_id: &'a str,
    payload_bytes: &'a [u8],
    payload_hash: [u8; 32],
    header_hash: [u8; 32],
    seq: u64,
    header_buf_idx: usize,
}

/// Write bytes to a file at a specific offset using positional write.
fn write_at_file(file: &File, offset: u64, data: &[u8]) -> Result<()> {
    let mut written = 0usize;
    while written < data.len() {
        let n = {
            #[cfg(unix)]
            {
                std::os::unix::fs::FileExt::write_at(file, &data[written..], offset + written as u64).map_err(io_err)?
            }
            #[cfg(windows)]
            {
                std::os::windows::fs::FileExt::seek_write(file, &data[written..], offset + written as u64)
                    .map_err(io_err)?
            }
        };
        if n == 0 {
            return Err(StorageError::Io {
                msg: "short write".to_string(),
            });
        }
        written += n;
    }
    Ok(())
}

/// Write bytes to a new file with fsync.
fn write_new_file_host(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent).map_err(io_err)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(path)
        .map_err(io_err)?;
    file.write_all(bytes).map_err(io_err)?;
    file.sync_all().map_err(io_err)?;
    Ok(())
}

/// CPU-only block reader: reads, decompresses and validates blocks from a segment file.
fn read_blocks_cpu(file: &File, blocks: &[BlockMetaV1], block_ids: &[u32]) -> Result<Vec<Option<Vec<u8>>>> {
    if blocks.is_empty() {
        return Ok(Vec::new());
    }
    let mut out: Vec<Option<Vec<u8>>> = vec![None; blocks.len()];
    if block_ids.is_empty() {
        return Ok(out);
    }

    let mut reqs: Vec<&BlockMetaV1> = Vec::with_capacity(block_ids.len());
    for &id in block_ids {
        let idx = id as usize;
        let b = blocks.get(idx).ok_or_else(|| StorageError::ManifestRecordInvalid {
            msg: format!("block_id {id} out of bounds"),
        })?;
        reqs.push(b);
    }
    reqs.sort_by_key(|b| b.file_offset);

    let mut plans: Vec<CoalescedReadPlan> = Vec::new();
    for b in reqs {
        let disk_len = b.physical_len as usize;
        let compressed_len = b.compressed_len as usize;
        if compressed_len == 0 {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "block compressed_len=0".to_string(),
            });
        }
        if disk_len == 0 {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "block physical_len=0".to_string(),
            });
        }
        if disk_len < compressed_len {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "block physical_len < compressed_len".to_string(),
            });
        }
        if let Some(cur) = plans.last_mut() {
            let expected_next = cur.start.saturating_add(cur.len as u64);
            if b.file_offset == expected_next {
                let rel_off = b.file_offset.checked_sub(cur.start).unwrap_or_default() as usize;
                cur.parts.push((b.block_id, rel_off, disk_len, compressed_len));
                cur.len = cur.len.saturating_add(disk_len);
                continue;
            }
        }
        plans.push(CoalescedReadPlan {
            start: b.file_offset,
            len: disk_len,
            parts: vec![(b.block_id, 0, disk_len, compressed_len)],
        });
    }

    read_blocks_uncompressed_host(file, blocks, &plans, &mut out)?;
    Ok(out)
}

/// CPU-only reader for codec=none frames: builds read plans from entries, then reads host-side.
fn read_selected_frames_codec_none_from_entries(
    file: &File,
    blocks: &[BlockMetaV1],
    entries: &[TocByOffsetEntryV1],
) -> Result<ReadSelectedFramesResult> {
    if entries.is_empty() {
        return Ok(ReadSelectedFramesResult {
            frames: Vec::new(),
            disk_bytes_read: 0,
        });
    }

    let mut reqs: Vec<(usize, u64, usize)> = Vec::with_capacity(entries.len());
    for (entry_index, e) in entries.iter().enumerate() {
        let block = blocks
            .get(e.block_id as usize)
            .ok_or_else(|| StorageError::ManifestRecordInvalid {
                msg: format!("block_id {} out of bounds", e.block_id),
            })?;
        if block.codec != corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1 {
            return Err(StorageError::ManifestRecordInvalid {
                msg: format!("codec {} requires block decode path", block.codec),
            });
        }
        if block.compressed_len != block.uncompressed_len {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "codec=none requires compressed_len==uncompressed_len".to_string(),
            });
        }
        let start_in_block = e.in_block_offset as usize;
        let frame_len = e.frame_len as usize;
        let end_in_block = start_in_block
            .checked_add(frame_len)
            .ok_or(StorageError::ManifestRecordInvalid {
                msg: "frame slice overflow".to_string(),
            })?;
        if end_in_block > block.uncompressed_len as usize {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "frame points outside codec=none block".to_string(),
            });
        }
        let file_off =
            block
                .file_offset
                .checked_add(start_in_block as u64)
                .ok_or(StorageError::ManifestRecordInvalid {
                    msg: "frame file offset overflow".to_string(),
                })?;
        reqs.push((entry_index, file_off, frame_len));
    }

    reqs.sort_by_key(|(_, file_off, _)| *file_off);

    let mut plans: Vec<FrameWindowReadPlan> = Vec::new();
    for (entry_index, file_off, frame_len) in reqs {
        if let Some(cur) = plans.last_mut() {
            let cur_end = cur.start.saturating_add(cur.len as u64);
            if file_off <= cur_end.saturating_add(FRAME_WINDOW_COALESCE_GAP_BYTES) {
                let rel_off = file_off.checked_sub(cur.start).unwrap_or_default() as usize;
                cur.parts.push(FrameWindowPart {
                    entry_index,
                    rel_off,
                    frame_len,
                });
                let needed_end = rel_off.saturating_add(frame_len);
                if needed_end > cur.len {
                    cur.len = needed_end;
                }
                continue;
            }
        }
        plans.push(FrameWindowReadPlan {
            start: file_off,
            len: frame_len,
            parts: vec![FrameWindowPart {
                entry_index,
                rel_off: 0,
                frame_len,
            }],
        });
    }

    read_selected_frames_codec_none_host(file, &plans, entries.len())
}

// SAFETY: All try_into().unwrap() convert fixed-size byte slices to arrays of matching length.
#[allow(clippy::unwrap_used)]
fn read_frame_bytes_physical(path: &Path, offset: u64) -> Result<Vec<u8>> {
    let mut file = File::open(path).map_err(io_err)?;
    file.seek(SeekFrom::Start(offset)).map_err(io_err)?;
    let mut prefix = [0u8; 12];
    file.read_exact(&mut prefix).map_err(io_err)?;
    let header_len = u16::from_le_bytes(prefix[6..8].try_into().unwrap()) as usize;
    let payload_len = u32::from_le_bytes(prefix[8..12].try_into().unwrap()) as usize;
    let frame_len = 12usize
        .checked_add(header_len)
        .and_then(|v| v.checked_add(payload_len))
        .and_then(|v| v.checked_add(4))
        .ok_or(StorageError::Io {
            msg: "frame length overflow".to_string(),
        })?;

    file.seek(SeekFrom::Start(offset)).map_err(io_err)?;
    let mut buf = vec![0u8; frame_len];
    file.read_exact(&mut buf).map_err(io_err)?;
    Ok(buf)
}

fn fsync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let dir = File::open(path).map_err(io_err)?;
        dir.sync_all().map_err(io_err)?;
    }
    let _ = path;
    Ok(())
}

fn now_unix_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

fn deterministic_segment_id(epoch: u64, segment_seq: u64) -> SegmentId {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&epoch.to_le_bytes());
    out[8..16].copy_from_slice(&segment_seq.to_le_bytes());
    SegmentId(out)
}

fn rejected_outcome(code: &str, msg: String) -> AppendOutcome {
    AppendOutcome {
        status: AppendStatus::Rejected,
        seq: 0,
        location: None,
        payload_hash: [0u8; 32],
        header_hash: [0u8; 32],
        error_code: Some(code.to_string()),
        error_message: Some(msg),
    }
}

fn blake3_hash16(bytes: &[u8]) -> [u8; 16] {
    let h = blake3::hash(bytes);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.as_bytes()[0..16]);
    out
}

fn normalize_hash16_prefix(mut h16: [u8; 16], prefix_len: usize) -> [u8; 16] {
    let keep = prefix_len.min(16);
    for b in h16.iter_mut().skip(keep) {
        *b = 0;
    }
    h16
}

fn parse_segment_seq_from_filename(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("seg-")?;
    let (seq_str, _) = rest.split_once('-')?;
    if seq_str.len() != 20 {
        return None;
    }
    seq_str.parse::<u64>().ok()
}

#[cfg(test)]
thread_local! {
    static TEST_FAILPOINT: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
}

#[cfg(test)]
fn set_test_failpoint(name: &str) {
    TEST_FAILPOINT.with(|failpoint| {
        *failpoint.borrow_mut() = Some(name.to_string());
    });
}

#[cfg(test)]
fn clear_test_failpoint() {
    TEST_FAILPOINT.with(|failpoint| {
        *failpoint.borrow_mut() = None;
    });
}

#[cfg(not(test))]
fn failpoint_active(name: &str) -> bool {
    std::env::var("CORECRUX_STORAGE_FAILPOINT")
        .ok()
        .is_some_and(|v| v == name)
}

#[cfg(test)]
fn failpoint_active(name: &str) -> bool {
    TEST_FAILPOINT.with(|failpoint| failpoint.borrow().as_deref() == Some(name))
}

fn decode_stored_event_from_frame_bytes(
    shard_id: u64,
    epoch: u64,
    segment_seq: u64,
    frame_offset: u64,
    frame_bytes: &[u8],
) -> Result<StoredEvent> {
    let decoded = decode_frame_v1(frame_bytes)?;
    if decoded.header_bytes.len() < 32 {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "stored frame header_bytes too small".to_string(),
        });
    }

    let canonical_len = decoded.header_bytes.len() - 32;
    let canonical_bytes = &decoded.header_bytes[..canonical_len];
    let header =
        decode_canonical_header_bytes_v1(canonical_bytes).map_err(|e| StorageError::ManifestRecordInvalid {
            msg: format!("failed to parse stored canonical header bytes: {e}"),
        })?;

    Ok(StoredEvent {
        seq: header.seq,
        event_id: header.event_id,
        occurred_at: header.occurred_at,
        ingested_at: header.ingested_at,
        event_type: header.event_type,
        content_type: header.content_type,
        payload: decoded.payload_bytes,
        location: FrameLocation {
            shard_id,
            epoch,
            segment_seq,
            offset: frame_offset,
        },
    })
}

fn select_stream_range_from_trailer_sorted(
    ti: &TrailerIndexV1,
    stream_hash: u64,
    from_seq_inclusive: u64,
    limit: usize,
) -> Vec<TocByOffsetEntryV1> {
    if limit == 0 {
        return Vec::new();
    }
    let (start, end) = trailer_sorted_stream_range(ti, stream_hash);
    if start == end {
        return Vec::new();
    }
    let rel =
        ti.toc_sorted_idx[start..end].partition_point(|&idx| ti.toc_by_offset[idx as usize].seq < from_seq_inclusive);
    let mut pos = start + rel;
    let mut out = Vec::new();
    while pos < end && out.len() < limit {
        let idx = ti.toc_sorted_idx[pos] as usize;
        out.push(ti.toc_by_offset[idx]);
        pos += 1;
    }
    out
}

fn select_stream_tail_from_trailer_sorted(
    ti: &TrailerIndexV1,
    stream_hash: u64,
    limit: usize,
) -> Vec<TocByOffsetEntryV1> {
    select_stream_tail_from_trailer_sorted_from_seq_with_range(ti, None, stream_hash, 0, limit)
}

fn select_stream_tail_from_trailer_sorted_from_seq_with_range(
    ti: &TrailerIndexV1,
    range_hint: Option<(usize, usize)>,
    stream_hash: u64,
    min_seq_inclusive: u64,
    limit: usize,
) -> Vec<TocByOffsetEntryV1> {
    if limit == 0 {
        return Vec::new();
    }
    let (start, end) = range_hint.unwrap_or_else(|| trailer_sorted_stream_range(ti, stream_hash));
    if start == end {
        return Vec::new();
    }
    let rel =
        ti.toc_sorted_idx[start..end].partition_point(|&idx| ti.toc_by_offset[idx as usize].seq < min_seq_inclusive);
    let start = start.saturating_add(rel);
    if start == end {
        return Vec::new();
    }
    let mut out = Vec::new();
    for pos in (start..end).rev() {
        if out.len() >= limit {
            break;
        }
        let idx = ti.toc_sorted_idx[pos] as usize;
        out.push(ti.toc_by_offset[idx]);
    }
    out
}

fn build_trailer_stream_ranges(ti: &TrailerIndexV1) -> HashMap<u64, (u32, u32)> {
    let mut out: HashMap<u64, (u32, u32)> = HashMap::new();
    let n = ti.toc_sorted_idx.len();
    if n == 0 {
        return out;
    }

    let mut start = 0usize;
    while start < n {
        let idx = ti.toc_sorted_idx[start] as usize;
        let stream_hash = ti.toc_by_offset[idx].stream_hash;
        let mut end = start + 1;
        while end < n {
            let idx_e = ti.toc_sorted_idx[end] as usize;
            if ti.toc_by_offset[idx_e].stream_hash != stream_hash {
                break;
            }
            end += 1;
        }
        if let (Ok(s), Ok(e)) = (u32::try_from(start), u32::try_from(end)) {
            out.insert(stream_hash, (s, e));
        }
        start = end;
    }
    out
}

fn toc_by_offset_ranges_by_block(ti: &TrailerIndexV1) -> Result<Vec<(usize, usize)>> {
    let nblocks = ti.blocks.len();
    if nblocks == 0 {
        return Ok(Vec::new());
    }
    if ti.toc_by_offset.is_empty() {
        return Ok(vec![(0, 0); nblocks]);
    }

    let mut ranges = vec![(0usize, 0usize); nblocks];
    let mut cur_block = ti.toc_by_offset[0].block_id as usize;
    if cur_block >= nblocks {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "toc_by_offset block_id out of bounds".to_string(),
        });
    }
    let mut start = 0usize;

    for (i, e) in ti.toc_by_offset.iter().enumerate() {
        let bid = e.block_id as usize;
        if bid >= nblocks {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "toc_by_offset block_id out of bounds".to_string(),
            });
        }
        if bid < cur_block {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "toc_by_offset not grouped by nondecreasing block_id".to_string(),
            });
        }
        if bid != cur_block {
            ranges[cur_block] = (start, i);
            cur_block = bid;
            start = i;
        }
    }

    ranges[cur_block] = (start, ti.toc_by_offset.len());
    Ok(ranges)
}

fn select_stream_tail_from_trailer_bloom(
    ti: &TrailerIndexV1,
    stream_hash: u64,
    limit: usize,
) -> Result<Vec<TocByOffsetEntryV1>> {
    if limit == 0 || ti.blocks.is_empty() {
        return Ok(Vec::new());
    }
    let ranges = toc_by_offset_ranges_by_block(ti)?;

    let mut out: Vec<TocByOffsetEntryV1> = Vec::new();
    for b in ti.blocks.iter().rev() {
        if out.len() >= limit {
            break;
        }
        if !bloom_maybe_contains_stream_hash_v1(&b.bloom, ti.bloom_hash_k, stream_hash) {
            continue;
        }
        let (start, end) = ranges.get(b.block_id as usize).copied().unwrap_or((0, 0));
        if start >= end || end > ti.toc_by_offset.len() {
            continue;
        }
        for idx in (start..end).rev() {
            if out.len() >= limit {
                break;
            }
            let e = ti.toc_by_offset[idx];
            if e.stream_hash == stream_hash {
                out.push(e);
            }
        }
    }
    Ok(out)
}

fn trailer_sorted_stream_range(ti: &TrailerIndexV1, stream_hash: u64) -> (usize, usize) {
    let start = ti
        .toc_sorted_idx
        .partition_point(|&idx| ti.toc_by_offset[idx as usize].stream_hash < stream_hash);
    let end = ti
        .toc_sorted_idx
        .partition_point(|&idx| ti.toc_by_offset[idx as usize].stream_hash <= stream_hash);
    (start, end)
}

fn block_logical_starts(blocks: &[BlockMetaV1]) -> Result<Vec<u64>> {
    let mut out: Vec<u64> = Vec::with_capacity(blocks.len());
    let mut cur: u64 = 0;
    for (i, b) in blocks.iter().enumerate() {
        if b.block_id as usize != i {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "block_id does not match blocks[] index".to_string(),
            });
        }
        out.push(cur);
        cur = cur
            .checked_add(b.uncompressed_len as u64)
            .ok_or(StorageError::ManifestRecordInvalid {
                msg: "block logical offset overflow".to_string(),
            })?;
    }
    Ok(out)
}

fn logical_offset_to_block(blocks: &[BlockMetaV1], logical_offset: u64) -> Result<(usize, u32)> {
    if logical_offset < corecrux_segment::SEGMENT_HEADER_LEN as u64 {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "logical offset before record area".to_string(),
        });
    }
    let mut rel = logical_offset - (corecrux_segment::SEGMENT_HEADER_LEN as u64);
    for (i, b) in blocks.iter().enumerate() {
        let len = b.uncompressed_len as u64;
        if rel < len {
            return Ok((i, rel as u32));
        }
        rel = rel.saturating_sub(len);
    }
    Err(StorageError::ManifestRecordInvalid {
        msg: "logical offset past end of record area".to_string(),
    })
}

#[derive(Debug)]
struct CoalescedReadPlan {
    start: u64,
    len: usize,
    // (block_id, rel_off, disk_len, compressed_len)
    parts: Vec<(u32, usize, usize, usize)>,
}

// SAFETY: All try_into().unwrap() convert fixed-size byte slices to arrays of matching length.
#[allow(clippy::unwrap_used)]
fn scan_frames_v1_block_bytes(block: &[u8]) -> Result<u32> {
    let mut pos: usize = 0;
    let mut frames: u32 = 0;
    while pos < block.len() {
        if block.len().saturating_sub(pos) < 4 {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "truncated frame header prefix in block".to_string(),
            });
        }
        let magic = u32::from_le_bytes(block[pos..pos + 4].try_into().unwrap());
        if magic == COMMIT_FRAME_MAGIC_CCMT {
            let end = pos
                .checked_add(COMMIT_FRAME_LEN_V1)
                .ok_or(StorageError::ManifestRecordInvalid {
                    msg: "commit frame length overflow in block".to_string(),
                })?;
            if end > block.len() {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: "commit frame extends beyond end of block".to_string(),
                });
            }
            let _ = decode_commit_frame_v1(&block[pos..end])?;
            pos = end;
            continue;
        }

        if block.len().saturating_sub(pos) < 16 {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "invalid frame magic in block".to_string(),
            });
        }
        if magic != corecrux_segment::FRAME_MAGIC_CRX1 {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "invalid frame magic in block".to_string(),
            });
        }
        let ver = u16::from_le_bytes(block[pos + 4..pos + 6].try_into().unwrap());
        if ver != corecrux_segment::FRAME_VERSION_V1 {
            return Err(StorageError::ManifestRecordInvalid {
                msg: format!("unsupported frame version in block: {ver}"),
            });
        }

        let header_len = u16::from_le_bytes(block[pos + 6..pos + 8].try_into().unwrap()) as usize;
        let payload_len = u32::from_le_bytes(block[pos + 8..pos + 12].try_into().unwrap()) as usize;
        let frame_len = 12usize
            .checked_add(header_len)
            .and_then(|v| v.checked_add(payload_len))
            .and_then(|v| v.checked_add(4))
            .ok_or(StorageError::ManifestRecordInvalid {
                msg: "frame length overflow in block".to_string(),
            })?;

        let end = pos.checked_add(frame_len).ok_or(StorageError::ManifestRecordInvalid {
            msg: "frame slice overflow in block".to_string(),
        })?;
        if end > block.len() {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "frame extends beyond end of block".to_string(),
            });
        }
        pos = end;
        frames = frames.saturating_add(1);
    }
    if pos != block.len() {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "block does not end on a frame boundary".to_string(),
        });
    }
    Ok(frames)
}

fn decode_blocks_from_plan_parts(
    out: &mut [Option<Vec<u8>>],
    blocks: &[BlockMetaV1],
    parts: &[(u32, usize, usize, usize)],
    buf: &[u8],
) -> Result<()> {
    for (block_id, rel_off, disk_len, compressed_len) in parts {
        let idx = *block_id as usize;
        let meta = blocks.get(idx).ok_or_else(|| StorageError::ManifestRecordInvalid {
            msg: "block meta missing".to_string(),
        })?;
        let disk_end = rel_off
            .checked_add(*disk_len)
            .ok_or(StorageError::ManifestRecordInvalid {
                msg: "block slice overflow".to_string(),
            })?;
        if disk_end > buf.len() {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "block slice out of bounds".to_string(),
            });
        }

        let comp_end = rel_off
            .checked_add(*compressed_len)
            .ok_or(StorageError::ManifestRecordInvalid {
                msg: "block compressed slice overflow".to_string(),
            })?;
        if comp_end > buf.len() {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "block compressed slice out of bounds".to_string(),
            });
        }

        let compressed = &buf[*rel_off..comp_end];
        let bytes = match meta.codec {
            0 => {
                if meta.compressed_len != meta.uncompressed_len {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "block len mismatch for codec=none".to_string(),
                    });
                }
                compressed.to_vec()
            }
            1 => {
                let want = meta.uncompressed_len as usize;
                let out =
                    lz4_flex::block::decompress(compressed, want).map_err(|e| StorageError::ManifestRecordInvalid {
                        msg: format!("block lz4 decompress error: {e}"),
                    })?;
                if out.len() != want {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "block lz4 decompressed_len mismatch".to_string(),
                    });
                }
                out
            }
            other => {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: format!("unsupported block codec {other}"),
                });
            }
        };
        if bytes.len() != meta.uncompressed_len as usize {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "block uncompressed_len mismatch".to_string(),
            });
        }
        let actual_crc = crc32c::crc32c(&bytes);
        if actual_crc != meta.crc32c {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "block crc32c mismatch".to_string(),
            });
        }
        out[idx] = Some(bytes);
    }
    Ok(())
}

fn read_blocks_uncompressed_host(
    file: &File,
    blocks: &[BlockMetaV1],
    plans: &[CoalescedReadPlan],
    out: &mut [Option<Vec<u8>>],
) -> Result<()> {
    for p in plans {
        let mut buf = vec![0u8; p.len];
        read_exact_file_at(file, p.start, &mut buf)?;
        decode_blocks_from_plan_parts(out, blocks, &p.parts, &buf)?;
    }
    Ok(())
}

#[derive(Debug)]
struct FrameWindowPart {
    entry_index: usize,
    rel_off: usize,
    frame_len: usize,
}

#[derive(Debug)]
struct FrameWindowReadPlan {
    start: u64,
    len: usize,
    parts: Vec<FrameWindowPart>,
}

#[derive(Debug)]
struct ReadSelectedFramesResult {
    frames: Vec<Vec<u8>>,
    disk_bytes_read: u64,
}

fn read_selected_frames_codec_none_host(
    file: &File,
    plans: &[FrameWindowReadPlan],
    entry_count: usize,
) -> Result<ReadSelectedFramesResult> {
    let mut out: Vec<Vec<u8>> = vec![Vec::new(); entry_count];
    let mut disk_bytes_read = 0u64;

    for plan in plans {
        let mut buf = vec![0u8; plan.len];
        read_exact_file_at(file, plan.start, &mut buf)?;
        disk_bytes_read = disk_bytes_read.saturating_add(plan.len as u64);
        for part in &plan.parts {
            let end = part
                .rel_off
                .checked_add(part.frame_len)
                .ok_or(StorageError::ManifestRecordInvalid {
                    msg: "frame window slice overflow".to_string(),
                })?;
            if end > buf.len() {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: "frame window slice out of bounds".to_string(),
                });
            }
            out[part.entry_index] = buf[part.rel_off..end].to_vec();
        }
    }

    Ok(ReadSelectedFramesResult {
        frames: out,
        disk_bytes_read,
    })
}

fn read_exact_file_at(file: &File, mut offset: u64, mut dst: &mut [u8]) -> Result<()> {
    while !dst.is_empty() {
        let n = {
            #[cfg(unix)]
            {
                file.read_at(dst, offset).map_err(io_err)?
            }
            #[cfg(windows)]
            {
                file.seek_read(dst, offset).map_err(io_err)?
            }
        };
        if n == 0 {
            return Err(StorageError::Io {
                msg: "short read".to_string(),
            });
        }
        offset = offset.saturating_add(n as u64);
        dst = &mut dst[n..];
    }
    Ok(())
}

fn toc_lower_bound(entries: &[corecrux_segment::TocEntryV1], stream_hash: u64, seq: u64) -> usize {
    let mut lo = 0usize;
    let mut hi = entries.len();
    while lo < hi {
        let mid = lo.midpoint(hi);
        let e = entries[mid];
        let less = e.stream_hash < stream_hash || (e.stream_hash == stream_hash && e.seq < seq);
        if less {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

fn toc_stream_range(entries: &[corecrux_segment::TocEntryV1], stream_hash: u64) -> (usize, usize) {
    let start = {
        // lower bound on stream_hash
        let mut lo = 0usize;
        let mut hi = entries.len();
        while lo < hi {
            let mid = lo.midpoint(hi);
            if entries[mid].stream_hash < stream_hash {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    };

    let end = {
        // upper bound on stream_hash
        let mut lo = start;
        let mut hi = entries.len();
        while lo < hi {
            let mid = lo.midpoint(hi);
            if entries[mid].stream_hash <= stream_hash {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        lo
    };

    (start, end)
}

fn frame_len_at(bytes: &[u8], offset: u64) -> Option<usize> {
    let off = usize::try_from(offset).ok()?;
    if off.checked_add(12)? > bytes.len() {
        return None;
    }
    let header_len = u16::from_le_bytes(bytes[off + 6..off + 8].try_into().ok()?) as usize;
    let payload_len = u32::from_le_bytes(bytes[off + 8..off + 12].try_into().ok()?) as usize;
    12usize
        .checked_add(header_len)?
        .checked_add(payload_len)?
        .checked_add(4)
}

fn hex16(bytes: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; 32];
    for (i, b) in bytes.iter().enumerate() {
        out[i * 2] = HEX[(b >> 4) as usize];
        out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
    }
    String::from_utf8_lossy(&out).to_string()
}

fn read_u16(bytes: &[u8], cur: &mut usize) -> Result<u16> {
    let end = cur.checked_add(2).ok_or_else(|| StorageError::ManifestRecordInvalid {
        msg: "cursor overflow".to_string(),
    })?;
    if end > bytes.len() {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "buffer too small".to_string(),
        });
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[*cur..end]);
    *cur = end;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32(bytes: &[u8], cur: &mut usize) -> Result<u32> {
    let end = cur.checked_add(4).ok_or_else(|| StorageError::ManifestRecordInvalid {
        msg: "cursor overflow".to_string(),
    })?;
    if end > bytes.len() {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "buffer too small".to_string(),
        });
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[*cur..end]);
    *cur = end;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64(bytes: &[u8], cur: &mut usize) -> Result<u64> {
    let end = cur.checked_add(8).ok_or_else(|| StorageError::ManifestRecordInvalid {
        msg: "cursor overflow".to_string(),
    })?;
    if end > bytes.len() {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "buffer too small".to_string(),
        });
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[*cur..end]);
    *cur = end;
    Ok(u64::from_le_bytes(buf))
}

fn read_bytes<'a>(bytes: &'a [u8], cur: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = cur
        .checked_add(len)
        .ok_or_else(|| StorageError::ManifestRecordInvalid {
            msg: "cursor overflow".to_string(),
        })?;
    if end > bytes.len() {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "buffer too small".to_string(),
        });
    }
    let out = &bytes[*cur..end];
    *cur = end;
    Ok(out)
}

fn io_err(e: std::io::Error) -> StorageError {
    StorageError::Io { msg: e.to_string() }
}
