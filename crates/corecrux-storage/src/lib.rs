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

use corecrux_frame::{
    canonical_header_bytes_v1, compute_header_hash, compute_payload_hash,
    decode_canonical_header_bytes_v1, CanonicalHeaderV1,
};
use corecrux_segment::{
    bloom_maybe_contains_stream_hash_v1, decode_frame_v1, decode_segment_v1,
    decode_trailer_index_v1, encode_frame_v1, BlockMetaV1, FrameInput, SegmentId,
    TocByOffsetEntryV1, TrailerIndexV1,
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
        let end = pt_cur.checked_add(DIRRUN_PARTITION_ENTRY_LEN_V1).ok_or(
            StorageError::ManifestRecordInvalid {
                msg: "dirrun partition table cursor overflow".to_string(),
            },
        )?;
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

    let expected_crc = u32::from_le_bytes(
        bytes[DIRRUN_HEADER_LEN - 4..DIRRUN_HEADER_LEN]
            .try_into()
            .unwrap(),
    );
    let actual_crc = crc32c::crc32c(&bytes[..DIRRUN_HEADER_LEN - 4]);
    if expected_crc != actual_crc {
        return Err(StorageError::ManifestRecordInvalid {
            msg: format!(
                "dirrun header crc mismatch: expected={expected_crc:#x} actual={actual_crc:#x}"
            ),
        });
    }

    let created_at_unix_ns = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let record_count = u64::from_le_bytes(bytes[32..40].try_into().unwrap());

    let mut parts: Vec<Vec<DirExtentV1>> = vec![Vec::new(); DIRRUN_PARTITIONS_V1];
    let mut total: u64 = 0;

    let mut pt_cur = DIRRUN_PARTITION_TABLE_OFFSET_V1;
    for part in parts.iter_mut() {
        let end = pt_cur.checked_add(DIRRUN_PARTITION_ENTRY_LEN_V1).ok_or(
            StorageError::ManifestRecordInvalid {
                msg: "dirrun partition table cursor overflow".to_string(),
            },
        )?;
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
        let end = start
            .checked_add(len)
            .ok_or(StorageError::ManifestRecordInvalid {
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

fn merge_dir_extents_partition_sorted_unique_cpu(
    a: &[DirExtentV1],
    b: &[DirExtentV1],
) -> Vec<DirExtentV1> {
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
        let block =
            blocks
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
        self.order.push_back(IdemOrderEntry {
            key,
            seq: entry.seq,
        });
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
            let drop_n = bucket
                .len()
                .saturating_sub(HEAD_STREAM_TAIL_INDEX_MAX_EVENTS);
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
        let drop_n = bucket
            .len()
            .saturating_sub(HEAD_STREAM_TAIL_INDEX_MAX_EVENTS);
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
    let expected = u32::from_le_bytes(
        bytes[COMMIT_FRAME_LEN_V1 - 4..COMMIT_FRAME_LEN_V1]
            .try_into()
            .unwrap(),
    );
    let actual = crc32c::crc32c(&bytes[..COMMIT_FRAME_LEN_V1 - 4]);
    if expected != actual {
        return Err(StorageError::ManifestRecordInvalid {
            msg: format!(
                "commit frame header crc mismatch: expected={expected:#x} actual={actual:#x}"
            ),
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

    let cur_block_len = blocks
        .last()
        .map(|b| b.uncompressed_len as usize)
        .unwrap_or(0);
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

    let rec_len_u32 =
        u32::try_from(record_bytes.len()).map_err(|_| StorageError::ManifestRecordInvalid {
            msg: "record length exceeds u32".to_string(),
        })?;

    let block = blocks.last_mut().expect("blocks non-empty");
    let in_block_offset = block.uncompressed_len;
    if let Some(stream_hash) = stream_hash_for_bloom {
        corecrux_segment::bloom_insert_stream_hash_v1(
            &mut block.bloom,
            corecrux_segment::BLOOM_HASH_K_V1,
            stream_hash,
        );
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

impl ShardStorage {
    pub fn open(
        root: &Path,
        shard_id: u32,
        epoch: u64,
        options: ShardStorageOptions,
    ) -> Result<Self> {
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
                let dst = paths
                    .quarantine_dir
                    .join(format!("tmp-{}-{name}", now_unix_ns()));
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
                let dst = paths
                    .quarantine_dir
                    .join(format!("orphan-{}-{name}", now_unix_ns()));
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
        let mut segment_stream_ranges_by_seq: HashMap<u64, HashMap<u64, (u32, u32)>> =
            HashMap::new();
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
                directory_by_stream
                    .entry(sh)
                    .or_default()
                    .push(StreamSegmentRef {
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
                        event_id_hash16: normalize_hash16_prefix(
                            h16,
                            options.event_id_hash_prefix_len,
                        ),
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
        let skip_bootstrap_dirruns = should_skip_startup_dirrun_bootstrap(
            out.dir_runs.is_empty(),
            out.segments_in_order.len(),
        );
        if !skip_bootstrap_dirruns {
            out.bootstrap_directory_runs_on_open(&extents_by_segment)?;
        }
        out.rebuild_tail_locator_from_directory()?;

        Ok(out)
    }

    fn load_head_segment_from_disk(&mut self) -> Result<()> {
        let mut candidates: Vec<(u64, PathBuf, String)> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&self.paths.segments_dir) {
            for e in rd.flatten() {
                let p = e.path();
                if !p.is_file() {
                    continue;
                }
                let name = match p.file_name().and_then(|s| s.to_str()) {
                    Some(s) => s.to_string(),
                    None => continue,
                };
                if !name.ends_with(".ccxhead") {
                    continue;
                }
                let Some(seq) = parse_segment_seq_from_filename(&name) else {
                    continue;
                };
                candidates.push((seq, p, name));
            }
        }
        if candidates.is_empty() {
            return Ok(());
        }

        // Keep the newest head by segment_seq; quarantine the rest.
        candidates.sort_by_key(|(seq, _, _)| *seq);
        let (keep_seq, keep_path, keep_name) = candidates
            .pop()
            .expect("candidates non-empty after is_empty check");
        for (_seq, path, name) in candidates {
            let dst = self
                .paths
                .quarantine_dir
                .join(format!("head-orphan-{}-{name}", now_unix_ns()));
            std::fs::rename(&path, &dst).map_err(io_err)?;
        }
        fsync_dir(&self.paths.segments_dir)?;
        fsync_dir(&self.paths.quarantine_dir)?;

        let bytes = std::fs::read(&keep_path).map_err(io_err)?;
        if bytes.len() < corecrux_segment::SEGMENT_HEADER_LEN {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "head segment file too small".to_string(),
            });
        }
        let seg_header = corecrux_segment::decode_segment_header_v1(
            &bytes[..corecrux_segment::SEGMENT_HEADER_LEN],
        )?;
        if seg_header.shard_id != self.shard_id || seg_header.epoch != self.epoch {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "head segment header shard_id/epoch mismatch".to_string(),
            });
        }
        if seg_header.segment_seq != keep_seq {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "head segment filename seq does not match header".to_string(),
            });
        }

        // Phase 4 recovery: only bytes up to the last valid commit-frame boundary are durable.
        let recovered_commit = find_last_valid_commit_frame(&bytes);
        if let Some(cf) = recovered_commit {
            self.next_head_commit_id = self.next_head_commit_id.max(cf.commit_id.saturating_add(1));
        }

        let committed_end = recovered_commit
            .map(|cf| cf.commit_offset as usize)
            .unwrap_or(corecrux_segment::SEGMENT_HEADER_LEN);
        let mut truncate_to = committed_end;

        let mut cur = corecrux_segment::SEGMENT_HEADER_LEN;
        let mut record_len: u64 = 0;
        let mut blocks: Vec<BlockMetaV1> = Vec::new();
        let mut frames: Vec<HeadFrameMeta> = Vec::new();
        let mut stream_min_max: HashMap<u64, (u64, u64)> = HashMap::new();
        let mut commit_frame_count: u64 = 0;
        let mut last_commit_id: u64 = 0;

        while cur < committed_end {
            let Some(record_len_at_cur) = parse_head_record_len(&bytes, cur) else {
                truncate_to = cur;
                break;
            };
            let Some(end) = cur.checked_add(record_len_at_cur) else {
                truncate_to = cur;
                break;
            };
            if end > committed_end {
                truncate_to = cur;
                break;
            }

            let magic = u32::from_le_bytes(bytes[cur..cur + 4].try_into().unwrap());
            if magic == COMMIT_FRAME_MAGIC_CCMT {
                let commit_frame = decode_commit_frame_v1(&bytes[cur..end])?;
                if commit_frame.commit_offset != end as u64 {
                    truncate_to = cur;
                    break;
                }
                append_head_record_to_blocks(&mut blocks, record_len, &bytes[cur..end], None)?;
                record_len = record_len.saturating_add(record_len_at_cur as u64);
                commit_frame_count = commit_frame_count.saturating_add(1);
                last_commit_id = last_commit_id.max(commit_frame.commit_id);
                let _ = commit_frame.commit_seq;
                cur = end;
                continue;
            }

            let frame_bytes = &bytes[cur..end];
            let decoded = match decode_frame_v1(frame_bytes) {
                Ok(v) => v,
                Err(_) => {
                    truncate_to = cur;
                    break;
                }
            };
            if decoded.header_bytes.len() < 32 {
                truncate_to = cur;
                break;
            }
            let canonical_len = decoded.header_bytes.len() - 32;
            let canonical_bytes = &decoded.header_bytes[..canonical_len];
            let hdr = match decode_canonical_header_bytes_v1(canonical_bytes) {
                Ok(h) => h,
                Err(_) => {
                    truncate_to = cur;
                    break;
                }
            };
            let stream_hash = corecrux_frame::stream_hash_xxhash64(
                &hdr.tenant_id,
                &hdr.stream_type,
                &hdr.stream_id,
            )
            .map_err(|e| StorageError::ManifestRecordInvalid {
                msg: format!("invalid stream key in head segment: {e}"),
            })?;

            let record_off_u64 = record_len;
            let record_off_u32 =
                u32::try_from(record_off_u64).map_err(|_| StorageError::ManifestRecordInvalid {
                    msg: "head segment record_off exceeds u32".to_string(),
                })?;
            let (block_id, in_block_offset) = append_head_record_to_blocks(
                &mut blocks,
                record_len,
                frame_bytes,
                Some(stream_hash),
            )?;

            let event_id_hash = blake3_hash16(hdr.event_id.as_bytes());
            let mut header_digest8 = [0u8; 8];
            header_digest8.copy_from_slice(&decoded.header_bytes[canonical_len..canonical_len + 8]);
            let payload_hash = compute_payload_hash(&decoded.payload_bytes);
            let mut payload_digest8 = [0u8; 8];
            payload_digest8.copy_from_slice(&payload_hash[0..8]);

            frames.push(HeadFrameMeta {
                stream_hash,
                seq: hdr.seq,
                record_off: record_off_u32,
                frame_len: record_len_at_cur as u32,
                payload_len: decoded.payload_bytes.len() as u32,
                event_id_hash16: event_id_hash,
                header_digest8,
                payload_digest8,
                block_id,
                in_block_offset,
            });

            stream_min_max
                .entry(stream_hash)
                .and_modify(|v| {
                    v.0 = v.0.min(hdr.seq);
                    v.1 = v.1.max(hdr.seq);
                })
                .or_insert((hdr.seq, hdr.seq));

            self.next_seq_by_stream
                .entry(stream_hash)
                .and_modify(|v| *v = (*v).max(hdr.seq + 1))
                .or_insert(hdr.seq + 1);

            let key = IdemKey {
                stream_hash,
                event_id_hash16: normalize_hash16_prefix(
                    event_id_hash,
                    self.options.event_id_hash_prefix_len,
                ),
            };
            let loc = FrameLocation {
                shard_id: self.shard_id as u64,
                epoch: self.epoch,
                segment_seq: seg_header.segment_seq,
                offset: (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                    .saturating_add(record_off_u64),
            };
            self.idem_prefix_seen.insert(key);
            self.idem_hot.insert(key, IdemEntry { seq: hdr.seq, loc });

            record_len = record_len.saturating_add(record_len_at_cur as u64);
            cur = end;
        }

        if last_commit_id > 0 {
            self.next_head_commit_id = self
                .next_head_commit_id
                .max(last_commit_id.saturating_add(1));
        }

        let expected_end = (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(record_len);
        if truncate_to > expected_end as usize {
            truncate_to = expected_end as usize;
        }
        if truncate_to < bytes.len() {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&keep_path)
                .map_err(io_err)?;
            file.set_len(truncate_to as u64).map_err(io_err)?;
            file.sync_all().map_err(io_err)?;
        }

        if frames.is_empty() {
            // No committed frames; remove the empty head segment.
            std::fs::remove_file(&keep_path).map_err(io_err)?;
            fsync_dir(&self.paths.segments_dir)?;
            return Ok(());
        }

        let stream_tail_idx_by_stream = build_head_stream_tail_index(&frames);
        let committed_region_crc32c =
            crc32c::crc32c(&bytes[corecrux_segment::SEGMENT_HEADER_LEN..(expected_end as usize)]);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&keep_path)
            .map_err(io_err)?;
        self.head = Some(HeadSegment {
            segment_seq: seg_header.segment_seq,
            segment_id: seg_header.segment_id,
            created_at_unix_ns: seg_header.created_at_unix_ns,
            relative_path: format!("segments/{keep_name}"),
            file,
            record_len,
            frames,
            blocks,
            stream_min_max,
            stream_tail_idx_by_stream,
            committed_region_crc32c,
            commit_frame_count,
            last_commit_id,
        });
        Ok(())
    }

    fn seal_head_segment_if_any(&mut self) -> Result<()> {
        if self.head.is_some() {
            let _ = self.seal_head_segment()?;
        }
        Ok(())
    }

    fn seal_head_segment(&mut self) -> Result<SealResultV1> {
        let _seal_start = std::time::Instant::now();

        let Some(head) = self.head.take() else {
            return Ok(SealResultV1 {
                sealed: false,
                segment_seq: None,
                frame_count: None,
                seal_duration_secs: 0.0,
            });
        };

        let seal_frame_count = head.frames.len() as u64;

        let head_path = self.paths.shard_dir.join(&head.relative_path);
        let bytes = std::fs::read(&head_path).map_err(io_err)?;
        if bytes.len() < corecrux_segment::SEGMENT_HEADER_LEN {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "head segment file too small".to_string(),
            });
        }
        let sealed_at = now_unix_ns();
        let mut record_area: Vec<u8> = Vec::with_capacity(head.record_len as usize);
        let mut metas: Vec<corecrux_segment::FrameMetaV1> = Vec::with_capacity(head.frames.len());
        for f in &head.frames {
            let src_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                .saturating_add(f.record_off as u64) as usize;
            let src_end = src_off.saturating_add(f.frame_len as usize);
            if src_end > bytes.len() {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: "head frame points outside segment bytes during seal".to_string(),
                });
            }
            let dst_off_u32 = u32::try_from(record_area.len()).map_err(|_| {
                StorageError::ManifestRecordInvalid {
                    msg: "sealed record_off exceeds u32".to_string(),
                }
            })?;
            record_area.extend_from_slice(&bytes[src_off..src_end]);

            metas.push(corecrux_segment::FrameMetaV1 {
                stream_hash: f.stream_hash,
                seq: f.seq,
                record_off: dst_off_u32,
                frame_len: f.frame_len,
                payload_len: f.payload_len,
                event_id_hash16: f.event_id_hash16,
                header_digest8: f.header_digest8,
                payload_digest8: f.payload_digest8,
            });
        }

        let seg = corecrux_segment::seal_segment_v1_from_record_area_with_block_codec(
            self.shard_id,
            self.epoch,
            head.segment_seq,
            head.segment_id,
            head.created_at_unix_ns,
            sealed_at,
            self.options.record_block_codec,
            &record_area,
            &metas,
        )?;

        let segment_seq = head.segment_seq;
        let segment_id = head.segment_id;

        let tmp_rel = format!("tmp/seg-{segment_seq:020}-{}.partial", hex16(&segment_id.0));
        let final_rel = format!(
            "segments/seg-{segment_seq:020}-{}.ccxseg",
            hex16(&segment_id.0)
        );
        let tmp_path = self.paths.shard_dir.join(&tmp_rel);
        let final_path = self.paths.shard_dir.join(&final_rel);

        write_new_file_host(&tmp_path, &seg.bytes)?;

        if failpoint_active("after_write_tmp") {
            return Err(StorageError::Internal {
                msg: "failpoint: after_write_tmp".to_string(),
            });
        }

        std::fs::rename(&tmp_path, &final_path).map_err(io_err)?;
        fsync_dir(&self.paths.segments_dir)?;

        // CoreCrux v5: build .ccxi companion inverted index from sealed segment content.
        if self.options.build_ccxi {
            if let Err(err) = build_ccxi_companion(
                &self.paths.shard_dir,
                self.shard_id,
                self.epoch,
                segment_seq,
                &segment_id,
                &record_area,
                &metas,
            ) {
                tracing::warn!(?err, segment_seq, "ccxi-companion-build-failed");
                // Non-fatal: segment is sealed, just no companion index for this one.
            }
        }

        if failpoint_active("after_rename_before_manifest") {
            return Err(StorageError::Internal {
                msg: "failpoint: after_rename_before_manifest".to_string(),
            });
        }

        let seg_meta = SegmentMeta {
            level: 0,
            shard_id: self.shard_id,
            epoch: self.epoch,
            segment_seq,
            segment_id,
            relative_path: final_rel.clone(),
            file_len: seg.footer.file_len,
            created_at_unix_ns: head.created_at_unix_ns,
            sealed_at_unix_ns: sealed_at,
            toc_offset: seg.footer.toc_offset,
            toc_len: seg.footer.toc_len,
            toc_entry_count: seg.footer.toc_entry_count,
            min_stream_hash: seg.footer.min_stream_hash,
            min_seq: seg.footer.min_seq,
            max_stream_hash: seg.footer.max_stream_hash,
            max_seq: seg.footer.max_seq,
            segment_hash: seg.footer.segment_hash,
        };

        self.append_manifest_add_segment(&seg_meta)?;

        if failpoint_active("after_manifest_commit") {
            return Err(StorageError::Internal {
                msg: "failpoint: after_manifest_commit".to_string(),
            });
        }

        // Cache trailer index and update derived shard directory.
        let toc_off = seg.footer.toc_offset as usize;
        let toc_len = seg.footer.toc_len as usize;
        if toc_off + toc_len > seg.bytes.len() {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "toc area out of bounds".to_string(),
            });
        }
        let toc_area = &seg.bytes[toc_off..toc_off + toc_len];
        if let Some(ti) = decode_trailer_index_v1(toc_area, &seg.toc_header)? {
            let ranges = build_trailer_stream_ranges(&ti);
            self.segment_trailers_by_seq.insert(segment_seq, ti);
            self.segment_stream_ranges_by_seq
                .insert(segment_seq, ranges);
        }
        let seg_file = File::open(&final_path).map_err(io_err)?;
        self.segment_files_by_seq.insert(segment_seq, seg_file);

        let entries = &seg.toc_entries;
        let mut dir_extents: Vec<DirExtentV1> = Vec::new();
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
            self.directory_by_stream
                .entry(sh)
                .or_default()
                .push(StreamSegmentRef {
                    segment_seq,
                    min_seq,
                    max_seq,
                });
            dir_extents.push(DirExtentV1 {
                stream_hash: sh,
                min_seq,
                max_seq,
                segment_seq,
            });
        }
        for refs in self.directory_by_stream.values_mut() {
            refs.sort_by_key(|r| r.segment_seq);
        }

        // Phase 6: publish an L0 directory run for this sealed segment (derived from TOC).
        let live = self.filter_extents_live(&dir_extents);
        let key = DirRunKey {
            level: 0,
            run_id: segment_seq,
        };
        let _ = self.publish_dir_run_v1(key, sealed_at, &live)?;

        self.segments_by_seq.insert(segment_seq, seg_meta.clone());
        self.segments_in_order.push(seg_meta);
        self.segments_in_order.sort_by_key(|s| s.segment_seq);
        self.rebuild_tail_locator_from_directory()?;

        // Remove the head file now that the sealed segment is committed.
        std::fs::remove_file(&head_path).map_err(io_err)?;
        fsync_dir(&self.paths.segments_dir)?;

        let seal_elapsed = _seal_start.elapsed();
        tracing::info!(
            segment_seq,
            frame_count = seal_frame_count,
            seal_duration_ms = seal_elapsed.as_millis() as u64,
            "seal-head-segment-complete"
        );

        Ok(SealResultV1 {
            sealed: true,
            segment_seq: Some(segment_seq),
            frame_count: Some(seal_frame_count),
            seal_duration_secs: seal_elapsed.as_secs_f64(),
        })
    }

    /// Force-seal the active head segment using the normal seal code path.
    ///
    /// Returns `SealResultV1 { sealed: false, .. }` if there is no active head.
    /// All invariants (TOC, BLAKE3, fsync, manifest append) are enforced.
    pub fn force_seal_head(&mut self) -> Result<SealResultV1> {
        self.seal_head_segment()
    }

    fn ensure_head_open(&mut self) -> Result<()> {
        if self.head.is_some() {
            return Ok(());
        }

        let segment_seq = self.next_segment_seq;
        self.next_segment_seq += 1;
        let segment_id = deterministic_segment_id(self.epoch, segment_seq);
        let created_at = now_unix_ns();

        let rel = format!(
            "segments/seg-{segment_seq:020}-{}.ccxhead",
            hex16(&segment_id.0)
        );
        let path = self.paths.shard_dir.join(&rel);

        let mut file = OpenOptions::new()
            .create_new(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(io_err)?;

        let header = corecrux_segment::SegmentHeaderV1 {
            flags: 1, // little_endian
            shard_id: self.shard_id,
            epoch: self.epoch,
            segment_seq,
            segment_id,
            created_at_unix_ns: created_at,
        };
        let header_bytes = corecrux_segment::encode_segment_header_v1(&header)?;

        // Establish durability for the header.
        file.write_all(&header_bytes).map_err(io_err)?;
        file.sync_all().map_err(io_err)?;
        fsync_dir(&self.paths.segments_dir)?;

        // Re-open the file handle without O_TRUNC semantics (paranoia).
        drop(file);
        file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(io_err)?;

        self.head = Some(HeadSegment {
            segment_seq,
            segment_id,
            created_at_unix_ns: created_at,
            relative_path: rel,
            file,
            record_len: 0,
            frames: Vec::new(),
            blocks: Vec::new(),
            stream_min_max: HashMap::new(),
            stream_tail_idx_by_stream: HashMap::new(),
            committed_region_crc32c: 0,
            commit_frame_count: 0,
            last_commit_id: 0,
        });
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(
        level = "info",
        skip(self, events),
        fields(
            stream_hash,
            expected_next_seq,
            tenant_id = %tenant_id,
            stream_type = %stream_type,
            stream_id = %stream_id,
            events_len = events.len()
        )
    )]
    pub fn append_batch(
        &mut self,
        stream_hash: u64,
        expected_next_seq: u64,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        ingested_at_rfc3339: &str,
        events: &[AppendEventInput<'_>],
    ) -> Result<Vec<AppendOutcome>> {
        Ok(self
            .append_batch_with_stats(
                stream_hash,
                expected_next_seq,
                tenant_id,
                stream_type,
                stream_id,
                ingested_at_rfc3339,
                events,
            )?
            .0)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_batch_with_stats(
        &mut self,
        stream_hash: u64,
        expected_next_seq: u64,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        ingested_at_rfc3339: &str,
        events: &[AppendEventInput<'_>],
    ) -> Result<(Vec<AppendOutcome>, AppendStatsV1)> {
        let total_start = std::time::Instant::now();
        let mut stats = AppendStatsV1::default();

        // Host-level admission checks: explicit and bounded.
        if events.len() > self.options.max_events_per_batch {
            return Err(StorageError::ResourceExhausted {
                code: "BACKPRESSURE_MAX_EVENTS".to_string(),
                msg: format!(
                    "events.len={} exceeds max_events_per_batch={}",
                    events.len(),
                    self.options.max_events_per_batch
                ),
                retry_after_ms: Some(50),
            });
        }
        let mut batch_bytes: usize = 0;
        for ev in events {
            batch_bytes = batch_bytes.saturating_add(ev.payload_bytes.len());
            // event_id bytes are bounded independently; don't let a single oversize id turn into a
            // request-level backpressure when we can reject it per-event.
            batch_bytes =
                batch_bytes.saturating_add(ev.event_id.len().min(self.options.max_event_id_bytes));
        }
        if batch_bytes > self.options.max_batch_bytes {
            return Err(StorageError::ResourceExhausted {
                code: "BACKPRESSURE_MAX_BATCH_BYTES".to_string(),
                msg: format!(
                    "batch_bytes={} exceeds max_batch_bytes={}",
                    batch_bytes, self.options.max_batch_bytes
                ),
                retry_after_ms: Some(50),
            });
        }

        let current_next = *self.next_seq_by_stream.get(&stream_hash).unwrap_or(&1);
        if expected_next_seq != 0 && expected_next_seq != current_next {
            return Err(StorageError::ManifestRecordInvalid {
                msg: format!(
                    "expected_next_seq={expected_next_seq} does not match current_next_seq={current_next}"
                ),
            });
        }

        if let Some(m) = self.stream_meta.get(&stream_hash) {
            if m.tombstone_seq > 0 {
                return Err(StorageError::FailedPrecondition {
                    code: "STREAM_TOMBSTONED".to_string(),
                    msg: format!("stream is tombstoned (tombstone_seq={})", m.tombstone_seq),
                });
            }
        }

        let mut header_bufs: Vec<Vec<u8>> = Vec::new();
        let mut new_frames: Vec<NewFrameMeta<'_>> = Vec::new();
        let mut outcomes: Vec<AppendOutcome> = Vec::with_capacity(events.len());
        let mut seq_cursor = current_next;
        let mut seen_in_batch: HashMap<&str, usize> = HashMap::new();
        let mut cold_lookup_cache: Option<ColdBatchLookup> = None;
        let cold_batch_prefixes: HashSet<[u8; 16]> = if self.idem_hot.is_incomplete() {
            events
                .iter()
                .filter_map(|ev| {
                    if ev.event_id.is_empty() || ev.event_id.len() > self.options.max_event_id_bytes
                    {
                        return None;
                    }
                    Some(normalize_hash16_prefix(
                        blake3_hash16(ev.event_id.as_bytes()),
                        self.options.event_id_hash_prefix_len,
                    ))
                })
                .collect()
        } else {
            HashSet::new()
        };

        // Precompute outcomes and build frames for new events.
        for ev in events {
            let event_id = ev.event_id; // bytes-first: do not trim or normalize
            if event_id.is_empty() {
                outcomes.push(rejected_outcome(
                    "EVENT_ID_EMPTY",
                    "event_id is empty".to_string(),
                ));
                continue;
            }
            if event_id.len() > self.options.max_event_id_bytes {
                outcomes.push(rejected_outcome(
                    "EVENT_ID_TOO_LARGE",
                    format!(
                        "event_id is {} bytes (max {})",
                        event_id.len(),
                        self.options.max_event_id_bytes
                    ),
                ));
                continue;
            }

            if let Some(&first_idx) = seen_in_batch.get(event_id) {
                let first =
                    outcomes
                        .get(first_idx)
                        .cloned()
                        .ok_or_else(|| StorageError::Internal {
                            msg: "intra-batch alias index out of bounds".to_string(),
                        })?;
                if first.status == AppendStatus::Rejected {
                    outcomes.push(first);
                } else {
                    outcomes.push(AppendOutcome {
                        status: AppendStatus::DuplicateInBatch,
                        ..first
                    });
                }
                continue;
            }

            // First time we've seen this event_id in the request; stash the outcome index.
            seen_in_batch.insert(event_id, outcomes.len());

            let idempotency_start = std::time::Instant::now();
            let full_h16 = blake3_hash16(event_id.as_bytes());
            let key = IdemKey {
                stream_hash,
                event_id_hash16: normalize_hash16_prefix(
                    full_h16,
                    self.options.event_id_hash_prefix_len,
                ),
            };

            // Hot lookup (bounded) + verify-on-hit (bytes-first).
            if let Some(found) = self.lookup_duplicate_hot(&key, event_id)? {
                stats.add_idempotency_elapsed(idempotency_start.elapsed());
                outcomes.push(found);
                continue;
            }

            // Cold lookup is required when the hot cache is incomplete (evicted/truncated), but
            // only when this (stream_hash, event_id_hash_prefix) has been seen before.
            if self.idem_hot.is_incomplete() && self.idem_prefix_seen.contains(&key) {
                if cold_lookup_cache.is_none() {
                    cold_lookup_cache =
                        Some(self.lookup_duplicate_cold_batch(stream_hash, &cold_batch_prefixes)?);
                }
                let cold = cold_lookup_cache
                    .as_ref()
                    .expect("cold lookup cache initialized");
                if let Some(found) = cold.find(key.event_id_hash16, event_id) {
                    // Warm the hot cache on cold hit.
                    self.idem_prefix_seen.insert(key);
                    self.idem_hot.insert(
                        key,
                        IdemEntry {
                            seq: found.seq,
                            loc: found.location.ok_or_else(|| StorageError::Internal {
                                msg: "cold duplicate missing location".to_string(),
                            })?,
                        },
                    );
                    stats.add_idempotency_elapsed(idempotency_start.elapsed());
                    outcomes.push(found);
                    continue;
                }
                if !cold.scanned_all {
                    return Err(StorageError::ResourceExhausted {
                        code: "BACKPRESSURE_COLD_IDEMPOTENCY".to_string(),
                        msg: format!(
                            "cold idempotency scan exceeded limit (scanned {} of {} segments)",
                            cold.scanned_segments, cold.total_segments
                        ),
                        retry_after_ms: Some(100),
                    });
                }
            }
            stats.add_idempotency_elapsed(idempotency_start.elapsed());

            let payload_hash = compute_payload_hash(ev.payload_bytes);
            let canonical = CanonicalHeaderV1 {
                tenant_id: tenant_id.to_string(),
                stream_id: stream_id.to_string(),
                stream_type: stream_type.to_string(),
                seq: seq_cursor,
                event_id: event_id.to_string(),
                occurred_at: ev.occurred_at.to_string(),
                ingested_at: ingested_at_rfc3339.to_string(),
                event_type: ev.event_type.to_string(),
                content_type: ev.content_type.to_string(),
                payload_len: ev.payload_bytes.len() as u32,
                payload_hash,
            };
            let canonical_bytes = canonical_header_bytes_v1(&canonical);
            let header_hash = compute_header_hash(&canonical_bytes);

            outcomes.push(AppendOutcome {
                status: AppendStatus::Appended,
                seq: seq_cursor,
                location: None, // patched after segment build
                payload_hash,
                header_hash,
                error_code: None,
                error_message: None,
            });

            let mut header_bytes_for_frame = Vec::with_capacity(canonical_bytes.len() + 32);
            header_bytes_for_frame.extend_from_slice(&canonical_bytes);
            header_bytes_for_frame.extend_from_slice(&header_hash);
            header_bufs.push(header_bytes_for_frame);
            new_frames.push(NewFrameMeta {
                event_id,
                payload_bytes: ev.payload_bytes,
                payload_hash,
                header_hash,
                seq: seq_cursor,
                header_buf_idx: header_bufs.len() - 1,
            });

            seq_cursor += 1;
        }

        if new_frames.is_empty() {
            stats.total_nanos = total_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            return Ok((outcomes, stats));
        }

        if failpoint_active("after_seq_assignment") {
            return Err(StorageError::Internal {
                msg: "failpoint: after_seq_assignment".to_string(),
            });
        }

        let mut frames: Vec<FrameInput<'_>> = Vec::with_capacity(new_frames.len());
        for nf in &new_frames {
            frames.push(FrameInput {
                stream_hash,
                seq: nf.seq,
                event_id: nf.event_id,
                header_hash: nf.header_hash,
                payload_hash: nf.payload_hash,
                header_bytes: header_bufs[nf.header_buf_idx].as_slice(),
                payload_bytes: nf.payload_bytes,
            });
        }

        if self.options.head_max_record_bytes > 0 {
            // Phase 5: append into a currently-open head segment and only seal when the head
            // exceeds a bounded record-area threshold. This allows tail/range reads to include
            // not-yet-sealed bytes.

            #[derive(Debug)]
            struct EncodedNewFrame {
                seq: u64,
                frame_bytes: Vec<u8>,
                payload_len: u32,
                event_id_hash16: [u8; 16],
                header_digest8: [u8; 8],
                payload_digest8: [u8; 8],
            }

            let mut encoded: Vec<EncodedNewFrame> = Vec::with_capacity(new_frames.len());
            let mut encoded_frame_bytes: Vec<Vec<u8>> = Vec::with_capacity(new_frames.len());
            let mut total_bytes: usize = 0;
            for nf in &new_frames {
                let hb = header_bufs[nf.header_buf_idx].as_slice();
                let fb = encode_frame_v1(hb, nf.payload_bytes)?;
                total_bytes = total_bytes.saturating_add(fb.len());
                encoded_frame_bytes.push(fb.clone());

                let event_id_hash16 = blake3_hash16(nf.event_id.as_bytes());

                let mut header_digest8 = [0u8; 8];
                header_digest8.copy_from_slice(&nf.header_hash[0..8]);
                let mut payload_digest8 = [0u8; 8];
                payload_digest8.copy_from_slice(&nf.payload_hash[0..8]);

                encoded.push(EncodedNewFrame {
                    seq: nf.seq,
                    frame_bytes: fb,
                    payload_len: nf.payload_bytes.len() as u32,
                    event_id_hash16,
                    header_digest8,
                    payload_digest8,
                });
            }

            if encoded.is_empty() {
                stats.total_nanos = total_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
                return Ok((outcomes, stats));
            }

            let batch_record_len = total_bytes.saturating_add(COMMIT_FRAME_LEN_V1);
            let max_head = self.options.head_max_record_bytes as u64;
            if let Some(h) = self.head.as_ref() {
                if h.record_len > 0
                    && h.record_len.saturating_add(batch_record_len as u64) > max_head
                {
                    // Keep head sizes bounded by sealing before a large append.
                    let _ = self.seal_head_segment()?;
                }
            }

            self.ensure_head_open()?;

            let (head_segment_seq, base_record_len, base_region_crc32c, commit_id) = {
                let head = self.head.as_ref().expect("head open");
                (
                    head.segment_seq,
                    head.record_len,
                    head.committed_region_crc32c,
                    self.next_head_commit_id,
                )
            };
            self.next_head_commit_id = self.next_head_commit_id.saturating_add(1);

            let commit_seq = encoded
                .last()
                .map(|e| e.seq)
                .unwrap_or_else(|| seq_cursor.saturating_sub(1));
            let mut pre_commit_crc32c = base_region_crc32c;
            for e in &encoded {
                pre_commit_crc32c = crc32c::crc32c_append(pre_commit_crc32c, &e.frame_bytes);
            }
            let commit_offset = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                .saturating_add(base_record_len)
                .saturating_add(total_bytes as u64)
                .saturating_add(COMMIT_FRAME_LEN_V1 as u64);
            let commit_frame =
                encode_commit_frame_v1(commit_id, commit_seq, commit_offset, pre_commit_crc32c);
            let committed_region_crc32c = crc32c::crc32c_append(pre_commit_crc32c, &commit_frame);

            let write_offset =
                (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(base_record_len);
            let mut append_bytes: Vec<u8> = Vec::with_capacity(batch_record_len);
            for e in &encoded {
                append_bytes.extend_from_slice(&e.frame_bytes);
            }
            append_bytes.extend_from_slice(&commit_frame);

            // Durably append event frames + commit frame, then fence before publishing outcomes.
            let io_write_start = std::time::Instant::now();
            {
                let head_file = &self.head.as_ref().expect("head open").file;
                write_at_file(head_file, write_offset, &append_bytes)?;
                head_file.sync_all().map_err(io_err)?;
                stats.add_io_write_elapsed(io_write_start.elapsed());

                if failpoint_active("after_head_commit_frame_write_before_fence") {
                    return Err(StorageError::Internal {
                        msg: "failpoint: after_head_commit_frame_write_before_fence".to_string(),
                    });
                }

                if failpoint_active("after_head_commit_fence_before_ack") {
                    return Err(StorageError::Internal {
                        msg: "failpoint: after_head_commit_fence_before_ack".to_string(),
                    });
                }
            }

            // Publish locations + update derived head indexes + idempotency state.
            let index_update_start = std::time::Instant::now();
            let mut record_cursor = base_record_len;
            let mut new_head_entries_asc: Vec<TocByOffsetEntryV1> =
                Vec::with_capacity(encoded.len());
            {
                let head = self.head.as_mut().expect("head open");

                for e in &encoded {
                    let frame_len_u32 = u32::try_from(e.frame_bytes.len()).map_err(|_| {
                        StorageError::ManifestRecordInvalid {
                            msg: "frame too large".to_string(),
                        }
                    })?;
                    let record_off_u32 = u32::try_from(record_cursor).map_err(|_| {
                        StorageError::ManifestRecordInvalid {
                            msg: "head record_off exceeds u32".to_string(),
                        }
                    })?;
                    let (block_id, in_block_offset) = append_head_record_to_blocks(
                        &mut head.blocks,
                        record_cursor,
                        &e.frame_bytes,
                        Some(stream_hash),
                    )?;

                    head.frames.push(HeadFrameMeta {
                        stream_hash,
                        seq: e.seq,
                        record_off: record_off_u32,
                        frame_len: frame_len_u32,
                        payload_len: e.payload_len,
                        event_id_hash16: e.event_id_hash16,
                        header_digest8: e.header_digest8,
                        payload_digest8: e.payload_digest8,
                        block_id,
                        in_block_offset,
                    });
                    let frame_idx = head.frames.len().saturating_sub(1);
                    push_head_stream_tail_index(
                        &mut head.stream_tail_idx_by_stream,
                        stream_hash,
                        frame_idx,
                        e.seq,
                    );
                    new_head_entries_asc.push(TocByOffsetEntryV1 {
                        stream_hash,
                        seq: e.seq,
                        block_id,
                        in_block_offset,
                        frame_len: frame_len_u32,
                        flags: 0,
                        event_id_hash16: e.event_id_hash16,
                        header_digest8: e.header_digest8,
                        payload_digest8: e.payload_digest8,
                    });

                    head.stream_min_max
                        .entry(stream_hash)
                        .and_modify(|v| {
                            v.0 = v.0.min(e.seq);
                            v.1 = v.1.max(e.seq);
                        })
                        .or_insert((e.seq, e.seq));

                    record_cursor = record_cursor.saturating_add(e.frame_bytes.len() as u64);
                }

                append_head_record_to_blocks(&mut head.blocks, record_cursor, &commit_frame, None)?;
                record_cursor = record_cursor.saturating_add(COMMIT_FRAME_LEN_V1 as u64);
                head.record_len = record_cursor;
                head.committed_region_crc32c = committed_region_crc32c;
                head.commit_frame_count = head.commit_frame_count.saturating_add(1);
                head.last_commit_id = commit_id;
            }

            // Patch outcomes + idempotency table now that locations are durable.
            record_cursor = base_record_len;
            for e in &encoded {
                let loc = FrameLocation {
                    shard_id: self.shard_id as u64,
                    epoch: self.epoch,
                    segment_seq: head_segment_seq,
                    offset: (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                        .saturating_add(record_cursor),
                };

                let key = IdemKey {
                    stream_hash,
                    event_id_hash16: normalize_hash16_prefix(
                        e.event_id_hash16,
                        self.options.event_id_hash_prefix_len,
                    ),
                };
                self.idem_prefix_seen.insert(key);
                self.idem_hot.insert(key, IdemEntry { seq: e.seq, loc });

                for o in outcomes
                    .iter_mut()
                    .filter(|o| o.seq == e.seq && o.location.is_none())
                {
                    o.location = Some(loc);
                }

                record_cursor = record_cursor.saturating_add(e.frame_bytes.len() as u64);
            }

            self.next_seq_by_stream.insert(stream_hash, seq_cursor);
            self.update_tail_locator_for_stream_entries(
                stream_hash,
                head_segment_seq,
                &new_head_entries_asc,
            );
            stats.add_index_elapsed(index_update_start.elapsed());

            // Seal the head once it reaches the configured threshold.
            let should_seal = self
                .head
                .as_ref()
                .map(|h| h.record_len >= max_head)
                .unwrap_or(false);
            if should_seal {
                let _ = self.seal_head_segment()?;
            }

            stats.write_confirmation = Some(WriteConfirmationMaterialV1 {
                commit_seq,
                segment_id: head_segment_seq,
                receipt_hash: compute_write_confirmation_receipt_hash(&encoded_frame_bytes),
            });
            stats.total_nanos = total_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            return Ok((outcomes, stats));
        }

        // Phase 2: seal+commit one segment per AppendBatch (correctness first).
        let segment_seq = self.next_segment_seq;
        self.next_segment_seq += 1;
        let segment_id = deterministic_segment_id(self.epoch, segment_seq);
        let phase2_frame_bytes: Vec<Vec<u8>> = new_frames
            .iter()
            .map(|nf| {
                encode_frame_v1(header_bufs[nf.header_buf_idx].as_slice(), nf.payload_bytes)
                    .map_err(StorageError::Segment)
            })
            .collect::<Result<Vec<_>>>()?;

        let created_at = now_unix_ns();
        let sealed_at = created_at;

        let seg = corecrux_segment::build_segment_v1_with_block_codec(
            self.shard_id,
            self.epoch,
            segment_seq,
            segment_id,
            created_at,
            sealed_at,
            self.options.record_block_codec,
            &frames,
        )?;

        // Write to tmp file and fsync.
        let tmp_rel = format!("tmp/seg-{segment_seq:020}-{}.partial", hex16(&segment_id.0));
        let final_rel = format!(
            "segments/seg-{segment_seq:020}-{}.ccxseg",
            hex16(&segment_id.0)
        );
        let tmp_path = self.paths.shard_dir.join(&tmp_rel);
        let final_path = self.paths.shard_dir.join(&final_rel);

        {
            let io_write_start = std::time::Instant::now();
            write_new_file_host(&tmp_path, &seg.bytes)?;
            stats.add_io_write_elapsed(io_write_start.elapsed());
        }

        if failpoint_active("after_write_tmp") {
            return Err(StorageError::Internal {
                msg: "failpoint: after_write_tmp".to_string(),
            });
        }

        // Atomically move into segments/ before manifest publish.
        std::fs::rename(&tmp_path, &final_path).map_err(io_err)?;
        let fence_fsync_start = std::time::Instant::now();
        fsync_dir(&self.paths.segments_dir)?;
        stats.add_fence_fsync_elapsed(fence_fsync_start.elapsed());

        // CoreCrux v5: build .ccxi companion index (Phase 2 seal path).
        // Use the uncompressed frame bytes directly since the record area in seg.bytes
        // may be block-compressed (LZ4) and not directly parseable.
        if self.options.build_ccxi && !phase2_frame_bytes.is_empty() {
            // Concatenate frame bytes into a flat record area
            let mut flat_record: Vec<u8> = Vec::new();
            let mut phase2_metas: Vec<corecrux_segment::FrameMetaV1> = Vec::new();
            for (i, fb) in phase2_frame_bytes.iter().enumerate() {
                let record_off = flat_record.len() as u32;
                flat_record.extend_from_slice(fb);
                if let Some(toc_entry) = seg.toc_entries.get(i) {
                    phase2_metas.push(corecrux_segment::FrameMetaV1 {
                        stream_hash: toc_entry.stream_hash,
                        seq: toc_entry.seq,
                        record_off,
                        frame_len: fb.len() as u32,
                        payload_len: toc_entry.payload_len,
                        event_id_hash16: toc_entry.event_id_hash16,
                        header_digest8: toc_entry.header_digest8,
                        payload_digest8: toc_entry.payload_digest8,
                    });
                }
            }
            if let Err(err) = build_ccxi_companion(
                &self.paths.shard_dir,
                self.shard_id,
                self.epoch,
                segment_seq,
                &segment_id,
                &flat_record,
                &phase2_metas,
            ) {
                tracing::warn!(?err, segment_seq, "ccxi-companion-build-failed-phase2");
            }
        }

        if failpoint_active("after_rename_before_manifest") {
            return Err(StorageError::Internal {
                msg: "failpoint: after_rename_before_manifest".to_string(),
            });
        }

        // Append AddSegment record to MANIFEST as commit boundary.
        let seg_meta = SegmentMeta {
            level: 0,
            shard_id: self.shard_id,
            epoch: self.epoch,
            segment_seq,
            segment_id,
            relative_path: final_rel.clone(),
            file_len: seg.footer.file_len,
            created_at_unix_ns: created_at,
            sealed_at_unix_ns: sealed_at,
            toc_offset: seg.footer.toc_offset,
            toc_len: seg.footer.toc_len,
            toc_entry_count: seg.footer.toc_entry_count,
            min_stream_hash: seg.footer.min_stream_hash,
            min_seq: seg.footer.min_seq,
            max_stream_hash: seg.footer.max_stream_hash,
            max_seq: seg.footer.max_seq,
            segment_hash: seg.footer.segment_hash,
        };

        self.append_manifest_add_segment_with_stats(&seg_meta, Some(&mut stats))?;

        if failpoint_active("after_manifest_commit") {
            // Simulate crash after durable commit but before response/state publish.
            return Err(StorageError::Internal {
                msg: "failpoint: after_manifest_commit".to_string(),
            });
        }

        // Now we can publish locations and update in-memory state.
        let index_update_start = std::time::Instant::now();
        // We can recover file offsets by re-parsing the committed segment.
        let (_h, toc_h, entries, f) = decode_segment_v1(&seg.bytes)?;
        let toc_off = f.toc_offset as usize;
        let toc_len = f.toc_len as usize;
        if toc_off + toc_len > seg.bytes.len() {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "toc area out of bounds".to_string(),
            });
        }
        let toc_area = &seg.bytes[toc_off..toc_off + toc_len];
        let mut stream_tail_entries_asc: Vec<TocByOffsetEntryV1> = Vec::new();
        if let Some(ti) = decode_trailer_index_v1(toc_area, &toc_h)? {
            let mut tail = select_stream_tail_from_trailer_sorted(
                &ti,
                stream_hash,
                STREAM_TAIL_LOCATOR_MAX_EVENTS,
            );
            tail.reverse();
            stream_tail_entries_asc = tail;
            let ranges = build_trailer_stream_ranges(&ti);
            self.segment_trailers_by_seq.insert(segment_seq, ti);
            self.segment_stream_ranges_by_seq
                .insert(segment_seq, ranges);
        }
        // Update shard directory for range/tail reads (derived index).
        let mut dir_extents: Vec<DirExtentV1> = Vec::new();
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
            self.directory_by_stream
                .entry(sh)
                .or_default()
                .push(StreamSegmentRef {
                    segment_seq,
                    min_seq,
                    max_seq,
                });
            dir_extents.push(DirExtentV1 {
                stream_hash: sh,
                min_seq,
                max_seq,
                segment_seq,
            });
        }
        for refs in self.directory_by_stream.values_mut() {
            refs.sort_by_key(|r| r.segment_seq);
        }

        // Phase 6: publish an L0 directory run for this sealed segment (derived from TOC).
        let live = self.filter_extents_live(&dir_extents);
        let key = DirRunKey {
            level: 0,
            run_id: segment_seq,
        };
        let _ = self.publish_dir_run_v1(key, sealed_at, &live)?;

        // Update idempotency hot cache and patch response locations by matching on (stream_hash, seq).
        let mut by_seq: HashMap<u64, &NewFrameMeta<'_>> = HashMap::new();
        for nf in &new_frames {
            by_seq.insert(nf.seq, nf);
        }
        for e in &entries {
            if e.stream_hash != stream_hash {
                continue;
            }
            let Some(nf) = by_seq.get(&e.seq) else {
                continue;
            };

            let loc = FrameLocation {
                shard_id: self.shard_id as u64,
                epoch: self.epoch,
                segment_seq,
                offset: e.file_offset as u64,
            };

            let full_h16 = blake3_hash16(nf.event_id.as_bytes());
            let key = IdemKey {
                stream_hash,
                event_id_hash16: normalize_hash16_prefix(
                    full_h16,
                    self.options.event_id_hash_prefix_len,
                ),
            };
            self.idem_prefix_seen.insert(key);
            self.idem_hot.insert(key, IdemEntry { seq: nf.seq, loc });

            // Patch the corresponding outcomes (Appended + any intra-batch aliases) by seq.
            for o in outcomes
                .iter_mut()
                .filter(|o| o.seq == nf.seq && o.location.is_none())
            {
                o.location = Some(loc);
            }
        }
        self.next_seq_by_stream.insert(stream_hash, seq_cursor);
        self.update_tail_locator_for_stream_entries(
            stream_hash,
            segment_seq,
            &stream_tail_entries_asc,
        );

        self.segments_by_seq.insert(segment_seq, seg_meta.clone());
        let seg_file = File::open(&final_path).map_err(io_err)?;
        self.segment_files_by_seq.insert(segment_seq, seg_file);
        self.segments_in_order.push(seg_meta.clone());
        self.segments_in_order.sort_by_key(|s| s.segment_seq);
        stats.write_confirmation = Some(WriteConfirmationMaterialV1 {
            commit_seq: seg.footer.max_seq,
            segment_id: segment_seq,
            receipt_hash: compute_write_confirmation_receipt_hash(&phase2_frame_bytes),
        });
        stats.add_index_elapsed(index_update_start.elapsed());
        stats.total_nanos = total_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;

        Ok((outcomes, stats))
    }

    /// Phase 11: install a sealed segment received from a leader onto a follower shard.
    ///
    /// This preserves the same durability boundary as local append:
    /// write segment bytes -> rename into `segments/` -> append MANIFEST AddSegment record.
    pub fn apply_replicated_segment_v1(
        &mut self,
        segment_bytes: &[u8],
    ) -> Result<ReplicatedSegmentApplyResultV1> {
        // Followers should not have local head writes, but sealing here keeps state transitions
        // deterministic if a host is repurposed.
        self.seal_head_segment_if_any()?;

        let (_hdr, toc_hdr, entries, footer) = decode_segment_v1(segment_bytes)?;

        if footer.shard_id != self.shard_id {
            return Err(StorageError::FailedPrecondition {
                code: "REPLICATION_SHARD_MISMATCH".to_string(),
                msg: format!(
                    "replicated segment shard_id={} does not match local shard_id={}",
                    footer.shard_id, self.shard_id
                ),
            });
        }
        if footer.epoch != self.epoch {
            return Err(StorageError::FailedPrecondition {
                code: "REPLICATION_EPOCH_MISMATCH".to_string(),
                msg: format!(
                    "replicated segment epoch={} does not match local epoch={}",
                    footer.epoch, self.epoch
                ),
            });
        }

        let segment_seq = footer.segment_seq;
        let segment_id = footer.segment_id;

        if let Some(existing) = self.segments_by_seq.get(&segment_seq) {
            if existing.segment_hash == footer.segment_hash
                && existing.file_len == footer.file_len
                && existing.segment_id == segment_id
            {
                return Ok(ReplicatedSegmentApplyResultV1 {
                    applied: false,
                    shard_id: self.shard_id,
                    epoch: self.epoch,
                    segment_seq,
                    segment_id,
                    segment_hash: footer.segment_hash,
                    file_len: footer.file_len,
                });
            }
            return Err(StorageError::FailedPrecondition {
                code: "REPLICATION_SEGMENT_CONFLICT".to_string(),
                msg: format!(
                    "segment_seq={} already committed with different identity/hash",
                    segment_seq
                ),
            });
        }

        let tmp_rel = format!("tmp/seg-{segment_seq:020}-{}.partial", hex16(&segment_id.0));
        let final_rel = format!(
            "segments/seg-{segment_seq:020}-{}.ccxseg",
            hex16(&segment_id.0)
        );
        let tmp_path = self.paths.shard_dir.join(&tmp_rel);
        let final_path = self.paths.shard_dir.join(&final_rel);

        if final_path.exists() {
            let existing = std::fs::read(&final_path).map_err(io_err)?;
            let (_eh, _etoc_h, _eentries, existing_footer) = decode_segment_v1(&existing)?;
            if existing_footer.segment_hash != footer.segment_hash
                || existing_footer.file_len != footer.file_len
                || existing_footer.segment_seq != segment_seq
                || existing_footer.segment_id != segment_id
            {
                return Err(StorageError::FailedPrecondition {
                    code: "REPLICATION_FILE_CONFLICT".to_string(),
                    msg: format!("existing segment file conflicts for segment_seq={segment_seq}"),
                });
            }
        } else {
            write_new_file_host(&tmp_path, segment_bytes)?;
            std::fs::rename(&tmp_path, &final_path).map_err(io_err)?;
            fsync_dir(&self.paths.segments_dir)?;
        }

        let seg_meta = SegmentMeta {
            level: 0,
            shard_id: self.shard_id,
            epoch: self.epoch,
            segment_seq,
            segment_id,
            relative_path: final_rel.clone(),
            file_len: footer.file_len,
            created_at_unix_ns: footer.created_at_unix_ns,
            sealed_at_unix_ns: footer.sealed_at_unix_ns,
            toc_offset: footer.toc_offset,
            toc_len: footer.toc_len,
            toc_entry_count: footer.toc_entry_count,
            min_stream_hash: footer.min_stream_hash,
            min_seq: footer.min_seq,
            max_stream_hash: footer.max_stream_hash,
            max_seq: footer.max_seq,
            segment_hash: footer.segment_hash,
        };

        // MANIFEST append is the durable visibility boundary.
        self.append_manifest_add_segment(&seg_meta)?;

        let toc_off = footer.toc_offset as usize;
        let toc_len = footer.toc_len as usize;
        if toc_off + toc_len > segment_bytes.len() {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "toc area out of bounds".to_string(),
            });
        }
        let toc_area = &segment_bytes[toc_off..toc_off + toc_len];
        if let Some(ti) = decode_trailer_index_v1(toc_area, &toc_hdr)? {
            let ranges = build_trailer_stream_ranges(&ti);
            self.segment_trailers_by_seq.insert(segment_seq, ti);
            self.segment_stream_ranges_by_seq
                .insert(segment_seq, ranges);
        }
        let seg_file = File::open(&final_path).map_err(io_err)?;
        self.segment_files_by_seq.insert(segment_seq, seg_file);

        let mut dir_extents: Vec<DirExtentV1> = Vec::new();
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
            self.directory_by_stream
                .entry(sh)
                .or_default()
                .push(StreamSegmentRef {
                    segment_seq,
                    min_seq,
                    max_seq,
                });
            dir_extents.push(DirExtentV1 {
                stream_hash: sh,
                min_seq,
                max_seq,
                segment_seq,
            });
        }
        for refs in self.directory_by_stream.values_mut() {
            refs.sort_by_key(|r| r.segment_seq);
        }

        // Rebuild next_seq + idempotency hot entries from the replicated TOC.
        for e in &entries {
            let stream_hash = e.stream_hash;
            let seq = e.seq;
            self.next_seq_by_stream
                .entry(stream_hash)
                .and_modify(|v| *v = (*v).max(seq.saturating_add(1)))
                .or_insert(seq.saturating_add(1));

            let mut h16 = [0u8; 16];
            h16.copy_from_slice(&e.event_id_hash16);
            let key = IdemKey {
                stream_hash,
                event_id_hash16: normalize_hash16_prefix(
                    h16,
                    self.options.event_id_hash_prefix_len,
                ),
            };
            let loc = FrameLocation {
                shard_id: self.shard_id as u64,
                epoch: self.epoch,
                segment_seq,
                offset: e.file_offset as u64,
            };
            self.idem_prefix_seen.insert(key);
            self.idem_hot.insert(key, IdemEntry { seq, loc });
        }

        let key = DirRunKey {
            level: 0,
            run_id: segment_seq,
        };
        let live = self.filter_extents_live(&dir_extents);
        let _ = self.publish_dir_run_v1(key, footer.sealed_at_unix_ns, &live)?;

        self.segments_by_seq.insert(segment_seq, seg_meta.clone());
        self.segments_in_order.push(seg_meta);
        self.segments_in_order.sort_by_key(|s| s.segment_seq);
        self.next_segment_seq = self.next_segment_seq.max(segment_seq.saturating_add(1));
        self.rebuild_tail_locator_from_directory()?;

        Ok(ReplicatedSegmentApplyResultV1 {
            applied: true,
            shard_id: self.shard_id,
            epoch: self.epoch,
            segment_seq,
            segment_id,
            segment_hash: footer.segment_hash,
            file_len: footer.file_len,
        })
    }

    fn lookup_duplicate_hot(&self, key: &IdemKey, event_id: &str) -> Result<Option<AppendOutcome>> {
        let Some(candidates) = self.idem_hot.candidates(key) else {
            return Ok(None);
        };

        for e in candidates {
            let (hdr, payload_hash, header_hash) =
                self.read_canonical_and_hashes_for_location(e.loc)?;
            if hdr.event_id == event_id {
                return Ok(Some(AppendOutcome {
                    status: AppendStatus::DuplicateCommitted,
                    seq: e.seq,
                    location: Some(e.loc),
                    payload_hash,
                    header_hash,
                    error_code: None,
                    error_message: None,
                }));
            }
        }
        Ok(None)
    }

    fn lookup_duplicate_cold_batch(
        &self,
        stream_hash: u64,
        needed_prefixes: &HashSet<[u8; 16]>,
    ) -> Result<ColdBatchLookup> {
        if needed_prefixes.is_empty() {
            return Ok(ColdBatchLookup {
                scanned_all: true,
                ..ColdBatchLookup::default()
            });
        }

        let mut out = ColdBatchLookup::default();

        // Head segments are not tracked by MANIFEST. Include head bytes in the cold path so
        // idempotency remains correct when the hot cache is incomplete.
        if let Some(head) = self.head.as_ref() {
            if head.stream_min_max.contains_key(&stream_hash) {
                for f in head.frames.iter().rev() {
                    if f.stream_hash != stream_hash {
                        continue;
                    }
                    let norm = normalize_hash16_prefix(
                        f.event_id_hash16,
                        self.options.event_id_hash_prefix_len,
                    );
                    if !needed_prefixes.contains(&norm) {
                        continue;
                    }
                    let loc = FrameLocation {
                        shard_id: self.shard_id as u64,
                        epoch: self.epoch,
                        segment_seq: head.segment_seq,
                        offset: (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                            .saturating_add(f.record_off as u64),
                    };
                    let (hdr, payload_hash, header_hash) =
                        self.read_canonical_and_hashes_for_location(loc)?;
                    out.by_prefix.entry(norm).or_default().push(ColdBatchMatch {
                        event_id: hdr.event_id.clone(),
                        outcome: AppendOutcome {
                            status: AppendStatus::DuplicateCommitted,
                            seq: hdr.seq,
                            location: Some(loc),
                            payload_hash,
                            header_hash,
                            error_code: None,
                            error_message: None,
                        },
                    });
                }
            }
        }

        let total = self.segments_in_order.len();
        out.total_segments = total;
        if total == 0 {
            out.scanned_all = true;
            return Ok(out);
        }

        let cap = self.options.cold_scan_max_segments;
        if cap == 0 {
            return Err(StorageError::ResourceExhausted {
                code: "BACKPRESSURE_COLD_IDEMPOTENCY".to_string(),
                msg: "cold idempotency lookup disabled (cold_scan_max_segments=0)".to_string(),
                retry_after_ms: Some(100),
            });
        }

        let limit = total.min(cap);
        out.scanned_segments = limit;
        out.scanned_all = limit == total;

        for seg in self.segments_in_order.iter().rev().take(limit) {
            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            let bytes = std::fs::read(&seg_path).map_err(io_err)?;
            let (_h, _toc_h, entries, _f) = decode_segment_v1(&bytes)?;

            for e in entries {
                if e.stream_hash != stream_hash {
                    continue;
                }

                let mut h16 = [0u8; 16];
                h16.copy_from_slice(&e.event_id_hash16);
                let norm = normalize_hash16_prefix(h16, self.options.event_id_hash_prefix_len);
                if !needed_prefixes.contains(&norm) {
                    continue;
                }

                let off = e.file_offset as usize;
                let len = e.frame_len as usize;
                if off.saturating_add(len) > bytes.len() {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "toc frame points outside file".to_string(),
                    });
                }

                let decoded = decode_frame_v1(&bytes[off..off + len])?;
                if decoded.header_bytes.len() < 32 {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "stored frame header_bytes too small".to_string(),
                    });
                }
                let canonical_len = decoded.header_bytes.len() - 32;
                let canonical_bytes = &decoded.header_bytes[..canonical_len];
                let header = decode_canonical_header_bytes_v1(canonical_bytes).map_err(|err| {
                    StorageError::ManifestRecordInvalid {
                        msg: format!("failed to parse stored canonical header bytes: {err}"),
                    }
                })?;
                let header_hash = compute_header_hash(canonical_bytes);
                let payload_hash = compute_payload_hash(&decoded.payload_bytes);
                let loc = FrameLocation {
                    shard_id: self.shard_id as u64,
                    epoch: seg.epoch,
                    segment_seq: seg.segment_seq,
                    offset: e.file_offset as u64,
                };
                out.by_prefix.entry(norm).or_default().push(ColdBatchMatch {
                    event_id: header.event_id.clone(),
                    outcome: AppendOutcome {
                        status: AppendStatus::DuplicateCommitted,
                        seq: header.seq,
                        location: Some(loc),
                        payload_hash,
                        header_hash,
                        error_code: None,
                        error_message: None,
                    },
                });
            }
        }

        Ok(out)
    }

    #[allow(dead_code)]
    fn lookup_duplicate_cold(
        &self,
        key: &IdemKey,
        event_id: &str,
    ) -> Result<Option<AppendOutcome>> {
        // Head segments are not tracked by MANIFEST. If our hot cache is incomplete, we must
        // include head bytes in the cold path to preserve idempotency correctness.
        if let Some(head) = self.head.as_ref() {
            if head.stream_min_max.contains_key(&key.stream_hash) {
                for f in head.frames.iter().rev() {
                    if f.stream_hash != key.stream_hash {
                        continue;
                    }
                    let norm = normalize_hash16_prefix(
                        f.event_id_hash16,
                        self.options.event_id_hash_prefix_len,
                    );
                    if norm != key.event_id_hash16 {
                        continue;
                    }
                    let loc = FrameLocation {
                        shard_id: self.shard_id as u64,
                        epoch: self.epoch,
                        segment_seq: head.segment_seq,
                        offset: (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                            .saturating_add(f.record_off as u64),
                    };
                    let (hdr, payload_hash, header_hash) =
                        self.read_canonical_and_hashes_for_location(loc)?;
                    if hdr.event_id != event_id {
                        continue;
                    }
                    return Ok(Some(AppendOutcome {
                        status: AppendStatus::DuplicateCommitted,
                        seq: hdr.seq,
                        location: Some(loc),
                        payload_hash,
                        header_hash,
                        error_code: None,
                        error_message: None,
                    }));
                }
            }
        }

        let total = self.segments_in_order.len();
        if total == 0 {
            return Ok(None);
        }

        let cap = self.options.cold_scan_max_segments;
        if cap == 0 {
            return Err(StorageError::ResourceExhausted {
                code: "BACKPRESSURE_COLD_IDEMPOTENCY".to_string(),
                msg: "cold idempotency lookup disabled (cold_scan_max_segments=0)".to_string(),
                retry_after_ms: Some(100),
            });
        }

        let limit = total.min(cap);
        let scanned_all = limit == total;

        for seg in self.segments_in_order.iter().rev().take(limit) {
            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            let bytes = std::fs::read(&seg_path).map_err(io_err)?;
            let (_h, _toc_h, entries, _f) = decode_segment_v1(&bytes)?;

            for e in entries {
                if e.stream_hash != key.stream_hash {
                    continue;
                }

                let mut h16 = [0u8; 16];
                h16.copy_from_slice(&e.event_id_hash16);
                let norm = normalize_hash16_prefix(h16, self.options.event_id_hash_prefix_len);
                if norm != key.event_id_hash16 {
                    continue;
                }

                let frame = self.read_frame_bytes(seg.segment_seq, e.file_offset as u64)?;
                let decoded = decode_frame_v1(&frame)?;
                if decoded.header_bytes.len() < 32 {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "stored frame header_bytes too small".to_string(),
                    });
                }

                let canonical_len = decoded.header_bytes.len() - 32;
                let canonical_bytes = &decoded.header_bytes[..canonical_len];
                let header = decode_canonical_header_bytes_v1(canonical_bytes).map_err(|err| {
                    StorageError::ManifestRecordInvalid {
                        msg: format!("failed to parse stored canonical header bytes: {err}"),
                    }
                })?;

                if header.event_id != event_id {
                    continue;
                }

                let header_hash = compute_header_hash(canonical_bytes);
                let payload_hash = compute_payload_hash(&decoded.payload_bytes);
                let loc = FrameLocation {
                    shard_id: self.shard_id as u64,
                    epoch: seg.epoch,
                    segment_seq: seg.segment_seq,
                    offset: e.file_offset as u64,
                };
                return Ok(Some(AppendOutcome {
                    status: AppendStatus::DuplicateCommitted,
                    seq: header.seq,
                    location: Some(loc),
                    payload_hash,
                    header_hash,
                    error_code: None,
                    error_message: None,
                }));
            }
        }

        if scanned_all {
            Ok(None)
        } else {
            Err(StorageError::ResourceExhausted {
                code: "BACKPRESSURE_COLD_IDEMPOTENCY".to_string(),
                msg: format!(
                    "cold idempotency scan exceeded limit (scanned {limit} of {total} segments)"
                ),
                retry_after_ms: Some(100),
            })
        }
    }

    fn read_canonical_and_hashes_for_location(
        &self,
        loc: FrameLocation,
    ) -> Result<(CanonicalHeaderV1, [u8; 32], [u8; 32])> {
        let frame = self.read_frame_bytes(loc.segment_seq, loc.offset)?;
        let decoded = decode_frame_v1(&frame)?;
        if decoded.header_bytes.len() < 32 {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "stored frame header_bytes too small".to_string(),
            });
        }

        let canonical_len = decoded.header_bytes.len() - 32;
        let canonical_bytes = &decoded.header_bytes[..canonical_len];
        let header_hash = compute_header_hash(canonical_bytes);
        let payload_hash = compute_payload_hash(&decoded.payload_bytes);

        // Sanity: verify canonical parses (helps detect format drift).
        let header = decode_canonical_header_bytes_v1(canonical_bytes).map_err(|e| {
            StorageError::ManifestRecordInvalid {
                msg: format!("failed to parse stored canonical header bytes: {e}"),
            }
        })?;

        Ok((header, payload_hash, header_hash))
    }

    fn append_manifest_add_segment(&mut self, seg: &SegmentMeta) -> Result<()> {
        self.append_manifest_add_segment_with_stats(seg, None)
    }

    fn append_manifest_add_segment_with_stats(
        &mut self,
        seg: &SegmentMeta,
        stats: Option<&mut AppendStatsV1>,
    ) -> Result<()> {
        let rec = encode_manifest_add_segment_v1(seg)?;
        let framed = frame_manifest_record(&rec);

        self.append_manifest_framed_with_stats(&framed, stats)
    }

    fn append_manifest_framed(&mut self, framed: &[u8]) -> Result<()> {
        self.append_manifest_framed_with_stats(framed, None)
    }

    fn append_manifest_framed_with_stats(
        &mut self,
        framed: &[u8],
        stats: Option<&mut AppendStatsV1>,
    ) -> Result<()> {
        // Manifest is control-plane state (small, append-only). Keep it on a plain fsync() path
        // so gpu-gds can remain strict about 4KiB alignment for segment IO without forcing a
        // manifest format/version bump.
        self.manifest
            .seek(SeekFrom::Start(self.manifest_end))
            .map_err(io_err)?;
        self.manifest.write_all(framed).map_err(io_err)?;
        let fence_fsync_start = std::time::Instant::now();
        self.manifest.sync_all().map_err(io_err)?;
        if let Some(s) = stats {
            s.add_fence_fsync_elapsed(fence_fsync_start.elapsed());
        }

        self.manifest_end += framed.len() as u64;
        Ok(())
    }

    fn append_manifest_add_dir_run(&mut self, run: &DirRunMeta) -> Result<()> {
        let rec = encode_manifest_add_dir_run_v1(self.shard_id, self.epoch, run)?;
        let framed = frame_manifest_record(&rec);
        self.append_manifest_framed(&framed)
    }

    fn append_manifest_remove_dir_run(&mut self, key: DirRunKey) -> Result<()> {
        let rec = encode_manifest_remove_dir_run_v1(key);
        let framed = frame_manifest_record(&rec);
        self.append_manifest_framed(&framed)
    }

    fn append_manifest_stream_meta_update(&mut self, upd: StreamMetaUpdateV1) -> Result<()> {
        let rec = encode_manifest_stream_meta_update_v1(upd);
        let framed = frame_manifest_record(&rec);
        self.append_manifest_framed(&framed)
    }

    fn stream_cut_seq(&self, stream_hash: u64) -> u64 {
        let m = self
            .stream_meta
            .get(&stream_hash)
            .copied()
            .unwrap_or_default();
        m.min_live_seq.max(m.tombstone_seq)
    }

    fn filter_extents_live(&self, extents: &[DirExtentV1]) -> Vec<DirExtentV1> {
        let mut out: Vec<DirExtentV1> = Vec::with_capacity(extents.len());
        for &e in extents {
            let cut = self.stream_cut_seq(e.stream_hash);
            if e.max_seq < cut {
                continue;
            }
            out.push(e);
        }
        out
    }

    fn publish_dir_run_v1(
        &mut self,
        key: DirRunKey,
        created_at_unix_ns: u64,
        extents: &[DirExtentV1],
    ) -> Result<Option<DirRunMeta>> {
        if extents.is_empty() {
            return Ok(None);
        }
        let bytes = encode_dir_run_v1(created_at_unix_ns, extents)?;
        // Phase 12 hardening:
        // avoid aborting append/compaction when a stale on-disk dirrun path already exists.
        // Keep run-id resolution deterministic by incrementing within the same level.
        let mut run_id = key.run_id;
        for _ in 0..1024 {
            let candidate_key = DirRunKey {
                level: key.level,
                run_id,
            };

            if self.dir_runs.contains_key(&candidate_key) {
                run_id = run_id.wrapping_add(1);
                continue;
            }

            let tmp_rel = format!(
                "tmp/dirrun-l{}-r{:020}.partial",
                candidate_key.level, candidate_key.run_id
            );
            let final_rel = dir_run_relative_path_v1(candidate_key.level, candidate_key.run_id);
            let tmp_path = self.paths.shard_dir.join(&tmp_rel);
            let final_path = self.paths.shard_dir.join(&final_rel);

            if final_path.exists() {
                run_id = run_id.wrapping_add(1);
                continue;
            }

            // Defensive cleanup of abandoned tmp files from interrupted runs.
            if tmp_path.exists() {
                let _ = std::fs::remove_file(&tmp_path);
            }

            write_new_file_host(&tmp_path, &bytes)?;

            std::fs::rename(&tmp_path, &final_path).map_err(io_err)?;
            fsync_dir(&self.paths.directory_dir)?;

            let meta = DirRunMeta {
                key: candidate_key,
                relative_path: final_rel,
                file_len: bytes.len() as u64,
                created_at_unix_ns,
                record_count: extents.len() as u64,
            };

            self.append_manifest_add_dir_run(&meta)?;
            self.dir_runs.insert(candidate_key, meta.clone());
            return Ok(Some(meta));
        }

        Err(StorageError::ManifestRecordInvalid {
            msg: format!(
                "unable to allocate dirrun output path after collision retries (level={}, run_id_start={})",
                key.level, key.run_id
            ),
        })
    }

    fn rebuild_directory_from_runs(&mut self) -> Result<HashSet<u64>> {
        let mut present_segments: HashSet<u64> = HashSet::new();
        let mut out: HashMap<u64, Vec<StreamSegmentRef>> = HashMap::new();

        let mut runs: Vec<DirRunMeta> = self.dir_runs.values().cloned().collect();
        runs.sort_by(|a, b| {
            a.key
                .level
                .cmp(&b.key.level)
                .then_with(|| a.key.run_id.cmp(&b.key.run_id))
        });

        for run in runs {
            let path = self.paths.shard_dir.join(&run.relative_path);
            let bytes = std::fs::read(&path).map_err(io_err)?;
            let decoded = decode_dir_run_v1(&bytes)?;

            if decoded.file_len != run.file_len {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: format!("dirrun file_len mismatch for {}", run.relative_path),
                });
            }
            if decoded.record_count != run.record_count {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: format!("dirrun record_count mismatch for {}", run.relative_path),
                });
            }
            if decoded.created_at_unix_ns != run.created_at_unix_ns {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: format!("dirrun created_at mismatch for {}", run.relative_path),
                });
            }

            for part in decoded.partitions {
                for e in part {
                    if !self.segments_by_seq.contains_key(&e.segment_seq) {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: format!("dirrun references missing segment_seq {}", e.segment_seq),
                        });
                    }

                    let cut = self.stream_cut_seq(e.stream_hash);
                    if e.max_seq < cut {
                        continue;
                    }

                    out.entry(e.stream_hash)
                        .or_default()
                        .push(StreamSegmentRef {
                            segment_seq: e.segment_seq,
                            min_seq: e.min_seq,
                            max_seq: e.max_seq,
                        });
                    present_segments.insert(e.segment_seq);
                }
            }
        }

        for refs in out.values_mut() {
            refs.sort_by_key(|r| r.segment_seq);
        }
        self.directory_by_stream = out;
        Ok(present_segments)
    }

    fn bootstrap_directory_runs_on_open(
        &mut self,
        extents_by_segment: &HashMap<u64, Vec<DirExtentV1>>,
    ) -> Result<()> {
        // Ensure we have at least L0 runs for any sealed segments that are missing from directory
        // state (e.g. crash between AddSegment and AddDirRun records, or older data dirs).
        if self.dir_runs.is_empty() && !self.segments_in_order.is_empty() {
            let segs: Vec<(u64, u64)> = self
                .segments_in_order
                .iter()
                .map(|s| (s.segment_seq, s.sealed_at_unix_ns))
                .collect();
            for (segment_seq, sealed_at_unix_ns) in segs {
                let extents = extents_by_segment
                    .get(&segment_seq)
                    .map(|v| v.as_slice())
                    .unwrap_or(&[]);
                let live = self.filter_extents_live(extents);
                let key = DirRunKey {
                    level: 0,
                    run_id: segment_seq,
                };
                let _ = self.publish_dir_run_v1(key, sealed_at_unix_ns, &live)?;
            }
        }

        let present = self.rebuild_directory_from_runs()?;

        let segs: Vec<(u64, u64)> = self
            .segments_in_order
            .iter()
            .map(|s| (s.segment_seq, s.sealed_at_unix_ns))
            .collect();
        for (segment_seq, sealed_at_unix_ns) in segs {
            if present.contains(&segment_seq) {
                continue;
            }
            let extents = extents_by_segment
                .get(&segment_seq)
                .map(|v| v.as_slice())
                .unwrap_or(&[]);
            let live = self.filter_extents_live(extents);
            if live.is_empty() {
                continue;
            }
            let key = DirRunKey {
                level: 0,
                run_id: segment_seq,
            };
            if self.dir_runs.contains_key(&key) {
                continue;
            }
            let _ = self.publish_dir_run_v1(key, sealed_at_unix_ns, &live)?;
        }

        let _ = self.rebuild_directory_from_runs()?;
        Ok(())
    }

    pub fn update_stream_meta(
        &mut self,
        stream_hash: u64,
        min_live_seq: u64,
        tombstone_seq: u64,
    ) -> Result<(u64, u64)> {
        let cur = self
            .stream_meta
            .get(&stream_hash)
            .copied()
            .unwrap_or_default();
        if min_live_seq != 0 && min_live_seq < cur.min_live_seq {
            return Err(StorageError::InvalidArgument {
                code: "CHECKPOINT_NON_MONOTONIC".to_string(),
                msg: format!(
                    "min_live_seq must be monotonic (current={}, requested={})",
                    cur.min_live_seq, min_live_seq
                ),
            });
        }
        if tombstone_seq != 0 && tombstone_seq < cur.tombstone_seq {
            return Err(StorageError::InvalidArgument {
                code: "TOMBSTONE_NON_MONOTONIC".to_string(),
                msg: format!(
                    "tombstone_seq must be monotonic (current={}, requested={})",
                    cur.tombstone_seq, tombstone_seq
                ),
            });
        }

        let next_min_live_seq = cur.min_live_seq.max(min_live_seq);
        let next_tombstone_seq = cur.tombstone_seq.max(tombstone_seq);

        if next_min_live_seq == cur.min_live_seq && next_tombstone_seq == cur.tombstone_seq {
            return Ok((cur.min_live_seq, cur.tombstone_seq));
        }

        let upd = StreamMetaUpdateV1 {
            stream_hash,
            min_live_seq: next_min_live_seq,
            tombstone_seq: next_tombstone_seq,
            gen: now_unix_ns(),
        };
        self.append_manifest_stream_meta_update(upd)?;

        let cut = {
            let e = self.stream_meta.entry(stream_hash).or_default();
            e.min_live_seq = next_min_live_seq;
            e.tombstone_seq = next_tombstone_seq;
            e.min_live_seq.max(e.tombstone_seq)
        };

        // Drop fully-dead extents from the in-memory directory for this stream (best-effort).
        if let Some(refs) = self.directory_by_stream.get_mut(&stream_hash) {
            refs.retain(|r| r.max_seq >= cut);
        }

        let e = self
            .stream_meta
            .get(&stream_hash)
            .copied()
            .unwrap_or_default();
        Ok((e.min_live_seq, e.tombstone_seq))
    }

    pub fn stream_meta_v1(&self, stream_hash: u64) -> (u64, u64) {
        let m = self
            .stream_meta
            .get(&stream_hash)
            .copied()
            .unwrap_or_default();
        (m.min_live_seq, m.tombstone_seq)
    }

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

    fn derive_compacted_run_id_v1(&self, level_out: u32, a: DirRunKey, b: DirRunKey) -> u64 {
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

    fn compact_dir_run_pair_v1(
        &mut self,
        a: &DirRunMeta,
        b: &DirRunMeta,
    ) -> Result<DirCompactionEventV1> {
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
            let mut merged =
                merge_dir_extents_partition_sorted_unique_cpu(pa, pb)
            ;
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

    fn rebuild_tail_locator_from_directory(&mut self) -> Result<()> {
        self.tail_locator_by_stream.clear();
        self.tail_pointer_by_stream.clear();
        let mut pointer_rebuild_streams: Vec<u64> = Vec::new();
        for (&stream_hash, refs) in self.directory_by_stream.iter() {
            let cut = self.stream_cut_seq(stream_hash);
            let mut desc: Vec<StreamTailLocatorEntry> = Vec::new();
            for r in refs.iter().rev() {
                if desc.len() >= STREAM_TAIL_LOCATOR_MAX_EVENTS {
                    break;
                }
                if r.max_seq < cut {
                    continue;
                }
                let Some(ti) = self.segment_trailers_by_seq.get(&r.segment_seq) else {
                    continue;
                };
                let need = STREAM_TAIL_LOCATOR_MAX_EVENTS.saturating_sub(desc.len());
                let range_hint = self
                    .segment_stream_ranges_by_seq
                    .get(&r.segment_seq)
                    .and_then(|m| m.get(&stream_hash))
                    .copied()
                    .map(|(a, b)| (a as usize, b as usize));
                let mut selected = select_stream_tail_from_trailer_sorted_from_seq_with_range(
                    ti,
                    range_hint,
                    stream_hash,
                    cut,
                    need,
                );
                selected.retain(|e| e.seq >= cut);
                for e in selected {
                    if desc.len() >= STREAM_TAIL_LOCATOR_MAX_EVENTS {
                        break;
                    }
                    desc.push(StreamTailLocatorEntry {
                        segment_seq: r.segment_seq,
                        entry: e,
                    });
                }
            }
            if desc.is_empty() {
                continue;
            }
            desc.reverse(); // keep ascending for stable append/update behavior
            self.tail_locator_by_stream
                .insert(stream_hash, StreamTailLocator { entries_asc: desc });
            pointer_rebuild_streams.push(stream_hash);
        }
        for stream_hash in pointer_rebuild_streams {
            self.rebuild_tail_pointer_for_stream(stream_hash);
        }
        Ok(())
    }

    fn rebuild_tail_pointer_for_stream(&mut self, stream_hash: u64) {
        let Some(locator) = self.tail_locator_by_stream.get(&stream_hash) else {
            self.tail_pointer_by_stream.remove(&stream_hash);
            return;
        };

        let mut entries_desc = locator.entries_asc.clone();
        entries_desc.reverse();
        let latest_segment_seq = entries_desc.first().map(|e| e.segment_seq).unwrap_or(0);
        let latest_seq = entries_desc.first().map(|e| e.entry.seq).unwrap_or(0);
        let mut grouped_desc: Vec<StreamTailPointerGroup> = Vec::new();
        for entry in &entries_desc {
            if let Some(group) = grouped_desc
                .iter_mut()
                .find(|group| group.segment_seq == entry.segment_seq)
            {
                group.entries_desc.push(entry.entry);
            } else {
                grouped_desc.push(StreamTailPointerGroup {
                    segment_seq: entry.segment_seq,
                    entries_desc: vec![entry.entry],
                });
            }
        }
        self.tail_pointer_by_stream.insert(
            stream_hash,
            StreamTailPointer {
                latest_segment_seq,
                latest_seq,
                entries_desc,
                grouped_desc,
            },
        );
    }

    fn locator_tail_segments_desc(
        &self,
        stream_hash: u64,
        cut: u64,
        limit: usize,
    ) -> (Vec<(u64, Vec<TocByOffsetEntryV1>)>, bool) {
        if limit == 0 {
            return (Vec::new(), false);
        }

        if let Some(ptr) = self.tail_pointer_by_stream.get(&stream_hash) {
            if cut <= ptr.latest_seq {
                let mut groups: Vec<(u64, Vec<TocByOffsetEntryV1>)> = Vec::new();
                let mut taken = 0usize;
                for g in &ptr.grouped_desc {
                    if taken >= limit {
                        break;
                    }
                    let mut selected: Vec<TocByOffsetEntryV1> = Vec::new();
                    for entry in &g.entries_desc {
                        if entry.seq < cut {
                            continue;
                        }
                        selected.push(*entry);
                        taken = taken.saturating_add(1);
                        if taken >= limit {
                            break;
                        }
                    }
                    if !selected.is_empty() {
                        groups.push((g.segment_seq, selected));
                    }
                }
                return (groups, taken >= limit);
            }
        }

        let mut groups: Vec<(u64, Vec<TocByOffsetEntryV1>)> = Vec::new();
        let mut taken = 0usize;
        for e in self.locator_tail_entries_desc(stream_hash, cut, limit) {
            if taken >= limit {
                break;
            }
            if e.entry.seq < cut {
                continue;
            }
            if let Some(group) = groups
                .iter_mut()
                .find(|(segment_seq, _)| *segment_seq == e.segment_seq)
            {
                group.1.push(e.entry);
            } else {
                groups.push((e.segment_seq, vec![e.entry]));
            }
            taken = taken.saturating_add(1);
        }
        (groups, taken >= limit)
    }

    fn update_tail_locator_for_stream_entries(
        &mut self,
        stream_hash: u64,
        segment_seq: u64,
        entries_asc: &[TocByOffsetEntryV1],
    ) {
        if entries_asc.is_empty() {
            return;
        }
        let locator = self
            .tail_locator_by_stream
            .entry(stream_hash)
            .or_insert(StreamTailLocator {
                entries_asc: Vec::new(),
            });
        locator.entries_asc.extend(
            entries_asc
                .iter()
                .copied()
                .map(|entry| StreamTailLocatorEntry { segment_seq, entry }),
        );
        if locator.entries_asc.len() > STREAM_TAIL_LOCATOR_MAX_EVENTS {
            let drop_n = locator
                .entries_asc
                .len()
                .saturating_sub(STREAM_TAIL_LOCATOR_MAX_EVENTS);
            locator.entries_asc.drain(0..drop_n);
        }
        self.rebuild_tail_pointer_for_stream(stream_hash);
    }

    fn locator_tail_entries_desc(
        &self,
        stream_hash: u64,
        cut: u64,
        limit: usize,
    ) -> Vec<StreamTailLocatorEntry> {
        if limit == 0 {
            return Vec::new();
        }

        if let Some(ptr) = self.tail_pointer_by_stream.get(&stream_hash) {
            if cut <= ptr.latest_seq {
                let _latest_segment_seq = ptr.latest_segment_seq;
                let mut out: Vec<StreamTailLocatorEntry> =
                    Vec::with_capacity(limit.min(ptr.entries_desc.len()));
                for e in &ptr.entries_desc {
                    if e.entry.seq < cut {
                        continue;
                    }
                    out.push(*e);
                    if out.len() >= limit {
                        break;
                    }
                }
                return out;
            }
        }

        let Some(locator) = self.tail_locator_by_stream.get(&stream_hash) else {
            return Vec::new();
        };
        let mut out: Vec<StreamTailLocatorEntry> =
            Vec::with_capacity(limit.min(locator.entries_asc.len()));
        for e in locator.entries_asc.iter().rev() {
            if e.entry.seq < cut {
                continue;
            }
            out.push(*e);
            if out.len() >= limit {
                break;
            }
        }
        out
    }

    fn read_selected_tail_entries_from_trailer(
        &self,
        seg: &SegmentMeta,
        ti: &TrailerIndexV1,
        selected: &[TocByOffsetEntryV1],
        stats: &mut ReadStatsV1,
        out: &mut Vec<StoredEvent>,
        limit: usize,
    ) -> Result<()> {
        if selected.is_empty() {
            return Ok(());
        }

        let seg_path = self.paths.shard_dir.join(&seg.relative_path);
        let file_fallback: File;
        let file_ref: &File = if let Some(cached) = self.segment_files_by_seq.get(&seg.segment_seq)
        {
            cached
        } else {
            file_fallback = File::open(&seg_path).map_err(io_err)?;
            &file_fallback
        };
        stats.segments_touched = stats.segments_touched.saturating_add(1);
        let estimated_disk_bytes = add_selected_entries_stats(stats, &ti.blocks, selected)?;
        let block_starts = block_logical_starts(&ti.blocks)?;
        let can_frame_window_read = selected.iter().all(|e| {
            let Some(meta) = ti.blocks.get(e.block_id as usize) else {
                return false;
            };
            meta.codec == corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1
                && meta.compressed_len == meta.uncompressed_len
        });

        if can_frame_window_read {
            let io_start = std::time::Instant::now();
            let read = read_selected_frames_codec_none_from_entries(file_ref,
                &ti.blocks,
                selected,
            )?;
            stats.add_io_elapsed(io_start.elapsed());
            stats.disk_bytes_estimate = stats
                .disk_bytes_estimate
                .saturating_sub(estimated_disk_bytes)
                .saturating_add(read.disk_bytes_read);

            let decode_start = std::time::Instant::now();
            for (e, frame) in selected.iter().zip(read.frames.iter()) {
                let bid = e.block_id as usize;
                let block_start =
                    block_starts
                        .get(bid)
                        .copied()
                        .ok_or(StorageError::ManifestRecordInvalid {
                            msg: "block start missing".to_string(),
                        })?;
                let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                    .checked_add(block_start)
                    .and_then(|v| v.checked_add(e.in_block_offset as u64))
                    .ok_or(StorageError::ManifestRecordInvalid {
                        msg: "frame offset overflow".to_string(),
                    })?;

                let ev = decode_stored_event_from_frame_bytes(
                    self.shard_id as u64,
                    seg.epoch,
                    seg.segment_seq,
                    frame_off,
                    frame,
                )?;
                out.push(ev);
                if out.len() >= limit {
                    break;
                }
            }
            stats.add_decode_elapsed(decode_start.elapsed());
        } else {
            let mut block_ids: Vec<u32> = selected.iter().map(|e| e.block_id).collect();
            block_ids.sort_unstable();
            block_ids.dedup();

            let io_start = std::time::Instant::now();
            let blocks = read_blocks_cpu(file_ref,
                &ti.blocks,
                &block_ids,
            )?;
            stats.add_io_elapsed(io_start.elapsed());

            let decode_start = std::time::Instant::now();
            for e in selected.iter() {
                let bid = e.block_id as usize;
                let Some(buf) = blocks.get(bid).and_then(|v| v.as_ref()) else {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "block buffer missing".to_string(),
                    });
                };
                let start = e.in_block_offset as usize;
                let len = e.frame_len as usize;
                let end = start
                    .checked_add(len)
                    .ok_or(StorageError::ManifestRecordInvalid {
                        msg: "frame slice overflow".to_string(),
                    })?;
                if end > buf.len() {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "frame points outside uncompressed block".to_string(),
                    });
                }
                let block_start =
                    block_starts
                        .get(bid)
                        .copied()
                        .ok_or(StorageError::ManifestRecordInvalid {
                            msg: "block start missing".to_string(),
                        })?;
                let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                    .checked_add(block_start)
                    .and_then(|v| v.checked_add(e.in_block_offset as u64))
                    .ok_or(StorageError::ManifestRecordInvalid {
                        msg: "frame offset overflow".to_string(),
                    })?;

                let ev = decode_stored_event_from_frame_bytes(
                    self.shard_id as u64,
                    seg.epoch,
                    seg.segment_seq,
                    frame_off,
                    &buf[start..end],
                )?;
                out.push(ev);
                if out.len() >= limit {
                    break;
                }
            }
            stats.add_decode_elapsed(decode_start.elapsed());
        }

        Ok(())
    }

    pub fn read_stream(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        stream_hash: u64,
        from_seq_inclusive: u64,
        max_events: u32,
    ) -> Result<Vec<StoredEvent>> {
        Ok(self
            .read_stream_with_stats(
                tenant_id,
                stream_type,
                stream_id,
                stream_hash,
                from_seq_inclusive,
                max_events,
            )?
            .0)
    }

    pub fn read_stream_with_stats(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        stream_hash: u64,
        from_seq_inclusive: u64,
        max_events: u32,
    ) -> Result<(Vec<StoredEvent>, ReadStatsV1)> {
        let _ = (tenant_id, stream_type, stream_id);
        let from_seq_inclusive = from_seq_inclusive.max(self.stream_cut_seq(stream_hash));
        let limit = if max_events == 0 {
            usize::MAX
        } else {
            max_events as usize
        };

        let mut stats = ReadStatsV1::default();
        let mut out: Vec<StoredEvent> = Vec::new();
        if let Some(refs) = self.directory_by_stream.get(&stream_hash) {
            for r in refs {
                if r.max_seq < from_seq_inclusive {
                    continue;
                }
                let seg = self.segments_by_seq.get(&r.segment_seq).ok_or_else(|| {
                    StorageError::ManifestRecordInvalid {
                        msg: "segment referenced by directory missing from segments_by_seq"
                            .to_string(),
                    }
                })?;

                let seg_path = self.paths.shard_dir.join(&seg.relative_path);
                if let Some(ti) = self.segment_trailers_by_seq.get(&r.segment_seq) {
                    let file = File::open(&seg_path).map_err(io_err)?;
                    let remaining = limit.saturating_sub(out.len());
                    let selected =
                        select_stream_range_from_trailer_sorted(
                            ti,
                            stream_hash,
                            from_seq_inclusive,
                            remaining,
                        )
                    ;
                    if selected.is_empty() {
                        continue;
                    }
                    stats.segments_touched = stats.segments_touched.saturating_add(1);

                    let block_starts = block_logical_starts(&ti.blocks)?;
                        let mut block_ids: Vec<u32> = selected.iter().map(|e| e.block_id).collect();
                        block_ids.sort_unstable();
                        block_ids.dedup();

                        let blocks = read_blocks_cpu(&file,
                            &ti.blocks,
                            &block_ids,
                        )?;

                        for e in selected {
                            let bid = e.block_id as usize;
                            let Some(buf) = blocks.get(bid).and_then(|v| v.as_ref()) else {
                                return Err(StorageError::ManifestRecordInvalid {
                                    msg: "block buffer missing".to_string(),
                                });
                            };
                            let start = e.in_block_offset as usize;
                            let len = e.frame_len as usize;
                            let end = start.checked_add(len).ok_or(
                                StorageError::ManifestRecordInvalid {
                                    msg: "frame slice overflow".to_string(),
                                },
                            )?;
                            if end > buf.len() {
                                return Err(StorageError::ManifestRecordInvalid {
                                    msg: "frame points outside uncompressed block".to_string(),
                                });
                            }
                            let block_start = block_starts.get(bid).copied().ok_or(
                                StorageError::ManifestRecordInvalid {
                                    msg: "block start missing".to_string(),
                                },
                            )?;
                            let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                                .checked_add(block_start)
                                .and_then(|v| v.checked_add(e.in_block_offset as u64))
                                .ok_or(StorageError::ManifestRecordInvalid {
                                    msg: "frame offset overflow".to_string(),
                                })?;

                            let ev = decode_stored_event_from_frame_bytes(
                                self.shard_id as u64,
                                seg.epoch,
                                seg.segment_seq,
                                frame_off,
                                &buf[start..end],
                            )?;
                            out.push(ev);
                            if out.len() >= limit {
                                return Ok((out, stats));
                            }
                        }
                    
                    continue;
                }

                // Fallback: Phase 2 reader (no trailer indexes present).
                let bytes = std::fs::read(&seg_path).map_err(io_err)?;
                let (_h, _toc_h, entries, _f) = decode_segment_v1(&bytes)?;

                let start = toc_lower_bound(&entries, stream_hash, from_seq_inclusive);
                let mut touched = false;
                for e in entries.iter().skip(start) {
                    if e.stream_hash != stream_hash {
                        break;
                    }
                    let off = e.file_offset as usize;
                    let len = e.frame_len as usize;
                    if off.saturating_add(len) > bytes.len() {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "toc frame points outside file".to_string(),
                        });
                    }

                    let frame_off = e.file_offset as u64;
                    let ev = decode_stored_event_from_frame_bytes(
                        self.shard_id as u64,
                        seg.epoch,
                        seg.segment_seq,
                        frame_off,
                        &bytes[off..off + len],
                    )?;
                    if !touched {
                        stats.segments_touched = stats.segments_touched.saturating_add(1);
                        touched = true;
                    }
                    out.push(ev);
                    if out.len() >= limit {
                        return Ok((out, stats));
                    }
                }
            }
        }

        // Head segment support: include not-yet-sealed bytes (Phase 5).
        if out.len() < limit {
            if let Some(head) = self.head.as_ref() {
                let Some((_min, max)) = head.stream_min_max.get(&stream_hash) else {
                    return Ok((out, stats));
                };
                if *max >= from_seq_inclusive {
                    let remaining = limit.saturating_sub(out.len());
                    let selected: Vec<&HeadFrameMeta> = head
                        .frames
                        .iter()
                        .filter(|f| f.stream_hash == stream_hash && f.seq >= from_seq_inclusive)
                        .take(remaining)
                        .collect();
                    if !selected.is_empty() {
                        stats.segments_touched = stats.segments_touched.saturating_add(1);
                            let mut block_ids: Vec<u32> =
                                selected.iter().map(|f| f.block_id).collect();
                            block_ids.sort_unstable();
                            block_ids.dedup();

                            let blocks = read_blocks_cpu(&head.file,
                                &head.blocks,
                                &block_ids,
                            )?;

                            for f in selected {
                                let bid = f.block_id as usize;
                                let Some(buf) = blocks.get(bid).and_then(|v| v.as_ref()) else {
                                    return Err(StorageError::ManifestRecordInvalid {
                                        msg: "head block buffer missing".to_string(),
                                    });
                                };
                                let start = f.in_block_offset as usize;
                                let len = f.frame_len as usize;
                                let end = start.checked_add(len).ok_or(
                                    StorageError::ManifestRecordInvalid {
                                        msg: "head frame slice overflow".to_string(),
                                    },
                                )?;
                                if end > buf.len() {
                                    return Err(StorageError::ManifestRecordInvalid {
                                        msg: "head frame points outside uncompressed block"
                                            .to_string(),
                                    });
                                }

                                let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                                    .saturating_add(f.record_off as u64);
                                let ev = decode_stored_event_from_frame_bytes(
                                    self.shard_id as u64,
                                    self.epoch,
                                    head.segment_seq,
                                    frame_off,
                                    &buf[start..end],
                                )?;
                                out.push(ev);
                                if out.len() >= limit {
                                    break;
                                }
                            }
                        
                    }
                }
            }
        }
        Ok((out, stats))
    }

    pub fn read_tail(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        stream_hash: u64,
        tail_events: u32,
    ) -> Result<Vec<StoredEvent>> {
        Ok(self
            .read_tail_with_stats(tenant_id, stream_type, stream_id, stream_hash, tail_events)?
            .0)
    }

    pub fn read_tail_with_stats(
        &self,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        stream_hash: u64,
        tail_events: u32,
    ) -> Result<(Vec<StoredEvent>, ReadStatsV1)> {
        let _ = (tenant_id, stream_type, stream_id);
        let cut = self.stream_cut_seq(stream_hash);
        let limit = tail_events as usize;
        if limit == 0 {
            return Ok((Vec::new(), ReadStatsV1::default()));
        }

        let total_start = std::time::Instant::now();
        let mut stats = ReadStatsV1::default();
        let mut out: Vec<StoredEvent> = Vec::new();
        // Head segment support: tail begins at the currently-appending segment.
        if let Some(head) = self.head.as_ref() {
            if head.stream_min_max.contains_key(&stream_hash) {
                let index_start = std::time::Instant::now();
                let remaining = limit.saturating_sub(out.len());
                let mut selected_idx_desc: Vec<usize> = Vec::new();
                let mut used_fastpath = false;

                if let Some(tail_idx) = head.stream_tail_idx_by_stream.get(&stream_hash) {
                    used_fastpath = true;
                    for ref_entry in tail_idx.iter().rev() {
                        stats.head_frames_scanned = stats.head_frames_scanned.saturating_add(1);
                        if ref_entry.seq < cut {
                            continue;
                        }
                        if ref_entry.frame_idx >= head.frames.len() {
                            continue;
                        }
                        selected_idx_desc.push(ref_entry.frame_idx);
                        if selected_idx_desc.len() >= remaining {
                            break;
                        }
                    }
                }

                if used_fastpath {
                    stats.head_tail_fastpath_hits = stats.head_tail_fastpath_hits.saturating_add(1);
                } else {
                    stats.head_tail_fastpath_misses =
                        stats.head_tail_fastpath_misses.saturating_add(1);
                }

                if selected_idx_desc.len() < remaining {
                    let mut seen: HashSet<usize> = selected_idx_desc.iter().copied().collect();
                    for (idx, f) in head.frames.iter().enumerate().rev() {
                        stats.head_frames_scanned = stats.head_frames_scanned.saturating_add(1);
                        if f.stream_hash != stream_hash || f.seq < cut {
                            continue;
                        }
                        if !seen.insert(idx) {
                            continue;
                        }
                        selected_idx_desc.push(idx);
                        if selected_idx_desc.len() >= remaining {
                            break;
                        }
                    }
                }

                let selected: Vec<&HeadFrameMeta> = selected_idx_desc
                    .iter()
                    .filter_map(|idx| head.frames.get(*idx))
                    .collect();
                stats.add_index_elapsed(index_start.elapsed());

                if !selected.is_empty() {
                    stats.segments_touched = stats.segments_touched.saturating_add(1);
                    let mut entries: Vec<TocByOffsetEntryV1> = Vec::with_capacity(selected.len());
                    for f in &selected {
                        entries.push(TocByOffsetEntryV1 {
                            stream_hash: f.stream_hash,
                            seq: f.seq,
                            block_id: f.block_id,
                            in_block_offset: f.in_block_offset,
                            frame_len: f.frame_len,
                            flags: 0,
                            event_id_hash16: f.event_id_hash16,
                            header_digest8: f.header_digest8,
                            payload_digest8: f.payload_digest8,
                        });
                    }
                    let estimated_disk_bytes =
                        add_selected_entries_stats(&mut stats, &head.blocks, &entries)?;
                    let can_frame_window_read = selected.iter().all(|f| {
                        let Some(meta) = head.blocks.get(f.block_id as usize) else {
                            return false;
                        };
                        meta.codec == corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1
                            && meta.compressed_len == meta.uncompressed_len
                    });
                    if can_frame_window_read {
                        let io_start = std::time::Instant::now();
                        let read = read_selected_frames_codec_none_from_entries(&head.file,
                            &head.blocks,
                            &entries,
                        )?;
                        stats.add_io_elapsed(io_start.elapsed());
                        stats.disk_bytes_estimate = stats
                            .disk_bytes_estimate
                            .saturating_sub(estimated_disk_bytes)
                            .saturating_add(read.disk_bytes_read);

                        let decode_start = std::time::Instant::now();
                        for (f, frame) in selected.iter().zip(read.frames.iter()) {
                            let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                                .saturating_add(f.record_off as u64);
                            let ev = decode_stored_event_from_frame_bytes(
                                self.shard_id as u64,
                                self.epoch,
                                head.segment_seq,
                                frame_off,
                                frame,
                            )?;
                            out.push(ev);
                            if out.len() >= limit {
                                break;
                            }
                        }
                        stats.add_decode_elapsed(decode_start.elapsed());
                    } else {
                        let mut block_ids: Vec<u32> = entries.iter().map(|e| e.block_id).collect();
                        block_ids.sort_unstable();
                        block_ids.dedup();

                        let io_start = std::time::Instant::now();
                        let blocks = read_blocks_cpu(&head.file,
                            &head.blocks,
                            &block_ids,
                        )?;
                        stats.add_io_elapsed(io_start.elapsed());

                        let decode_start = std::time::Instant::now();
                        for f in &selected {
                            let bid = f.block_id as usize;
                            let Some(buf) = blocks.get(bid).and_then(|v| v.as_ref()) else {
                                return Err(StorageError::ManifestRecordInvalid {
                                    msg: "head block buffer missing".to_string(),
                                });
                            };
                            let start = f.in_block_offset as usize;
                            let len = f.frame_len as usize;
                            let end = start.checked_add(len).ok_or(
                                StorageError::ManifestRecordInvalid {
                                    msg: "head frame slice overflow".to_string(),
                                },
                            )?;
                            if end > buf.len() {
                                return Err(StorageError::ManifestRecordInvalid {
                                    msg: "head frame points outside uncompressed block".to_string(),
                                });
                            }
                            let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                                .saturating_add(f.record_off as u64);
                            let ev = decode_stored_event_from_frame_bytes(
                                self.shard_id as u64,
                                self.epoch,
                                head.segment_seq,
                                frame_off,
                                &buf[start..end],
                            )?;
                            out.push(ev);
                            if out.len() >= limit {
                                break;
                            }
                        }
                        stats.add_decode_elapsed(decode_start.elapsed());
                    }
                }
            }
        }

        let Some(refs) = self.directory_by_stream.get(&stream_hash) else {
            out.reverse(); // ascending seq
            stats.total_nanos = total_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            return Ok((out, stats));
        };
        let index_start = std::time::Instant::now();
        let (locator_selected_by_segment_desc, locator_can_fully_satisfy) =
            self.locator_tail_segments_desc(stream_hash, cut, limit);
        stats.add_index_elapsed(index_start.elapsed());
        if locator_can_fully_satisfy {
            stats.locator_fully_satisfied_hits =
                stats.locator_fully_satisfied_hits.saturating_add(1);
        } else {
            stats.locator_fully_satisfied_misses =
                stats.locator_fully_satisfied_misses.saturating_add(1);
        }

        // Fast path for cache-neutral tails: when the locator already has enough entries,
        // skip scanning directory refs entirely and read only locator-selected segments.
        if locator_can_fully_satisfy {
            for (seg_seq, mut selected) in locator_selected_by_segment_desc {
                if out.len() >= limit {
                    break;
                }
                let Some(seg) = self.segments_by_seq.get(&seg_seq) else {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "segment referenced by locator missing from segments_by_seq"
                            .to_string(),
                    });
                };
                let Some(ti) = self.segment_trailers_by_seq.get(&seg_seq) else {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "segment referenced by locator missing trailer index".to_string(),
                    });
                };
                let remaining = limit.saturating_sub(out.len());
                let index_start = std::time::Instant::now();
                if selected.len() > remaining {
                    selected.truncate(remaining);
                }
                selected.retain(|e| e.seq >= cut);
                stats.add_index_elapsed(index_start.elapsed());
                if selected.is_empty() {
                    continue;
                }
                self.read_selected_tail_entries_from_trailer(
                    seg, ti, &selected, &mut stats, &mut out, limit,
                )?;
            }
            out.reverse(); // ascending seq
            stats.total_nanos = total_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
            return Ok((out, stats));
        }

        let mut locator_desc_by_segment: HashMap<u64, Vec<TocByOffsetEntryV1>> =
            locator_selected_by_segment_desc.into_iter().collect();

        for r in refs.iter().rev() {
            if r.max_seq < cut {
                continue;
            }
            let seg = self.segments_by_seq.get(&r.segment_seq).ok_or_else(|| {
                StorageError::ManifestRecordInvalid {
                    msg: "segment referenced by directory missing from segments_by_seq".to_string(),
                }
            })?;

            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            if let Some(ti) = self.segment_trailers_by_seq.get(&r.segment_seq) {
                let remaining = limit.saturating_sub(out.len());
                let index_start = std::time::Instant::now();
                let mut selected = locator_desc_by_segment
                    .remove(&r.segment_seq)
                    .unwrap_or_default();
                if selected.len() > remaining {
                    selected.truncate(remaining);
                }
                if selected.len() < remaining && !locator_can_fully_satisfy {
                    let need = remaining.saturating_sub(selected.len());
                    let range_hint = self
                        .segment_stream_ranges_by_seq
                        .get(&r.segment_seq)
                        .and_then(|m| m.get(&stream_hash))
                        .copied()
                        .map(|(a, b)| (a as usize, b as usize));
                    let mut extra = select_stream_tail_from_trailer_sorted_from_seq_with_range(
                        ti,
                        range_hint,
                        stream_hash,
                        cut,
                        need,
                    );
                    if extra.is_empty() && need <= 128 {
                        // Keep bloom as fallback only. Sorted-index-first avoids reverse block scans
                        // for sparse streams in large blocks.
                        extra = select_stream_tail_from_trailer_bloom(ti, stream_hash, need)?;
                    }
                    extra.retain(|e| e.seq >= cut);
                    if selected.is_empty() {
                        selected = extra;
                    } else {
                        for e in extra {
                            if selected.iter().any(|s| s.seq == e.seq) {
                                continue;
                            }
                            selected.push(e);
                            if selected.len() >= remaining {
                                break;
                            }
                        }
                    }
                }
                selected.retain(|e| e.seq >= cut);
                stats.add_index_elapsed(index_start.elapsed());
                if selected.is_empty() {
                    continue;
                }
                self.read_selected_tail_entries_from_trailer(
                    seg, ti, &selected, &mut stats, &mut out, limit,
                )?;

                if out.len() >= limit {
                    break;
                }
                continue;
            }

            // Fallback: Phase 2 reader (no trailer indexes present).
            let io_start = std::time::Instant::now();
            let bytes = std::fs::read(&seg_path).map_err(io_err)?;
            stats.add_io_elapsed(io_start.elapsed());
            stats.disk_bytes_estimate =
                stats.disk_bytes_estimate.saturating_add(bytes.len() as u64);
            let index_start = std::time::Instant::now();
            let (_h, _toc_h, entries, _f) = decode_segment_v1(&bytes)?;
            let (start, end) = toc_stream_range(&entries, stream_hash);
            stats.add_index_elapsed(index_start.elapsed());
            if start == end {
                continue;
            }

            let decode_start = std::time::Instant::now();
            let mut idx = end;
            while idx > start && out.len() < limit {
                idx -= 1;
                let e = entries[idx];
                let off = e.file_offset as usize;
                let len = e.frame_len as usize;
                if off.saturating_add(len) > bytes.len() {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "toc frame points outside file".to_string(),
                    });
                }

                let frame_off = e.file_offset as u64;
                let ev = decode_stored_event_from_frame_bytes(
                    self.shard_id as u64,
                    seg.epoch,
                    seg.segment_seq,
                    frame_off,
                    &bytes[off..off + len],
                )?;
                if ev.seq >= cut {
                    stats.frames_selected = stats.frames_selected.saturating_add(1);
                    stats.frame_bytes = stats.frame_bytes.saturating_add(len as u64);
                    out.push(ev);
                }
            }
            stats.add_decode_elapsed(decode_start.elapsed());

            if out.len() >= limit {
                break;
            }
        }

        out.reverse(); // ascending seq
        stats.total_nanos = total_start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        Ok((out, stats))
    }

    /// Replay frames from sealed segments only (manifest-committed).
    ///
    /// This is the correct source for derived state (e.g. projections) because the "head"
    /// segment is not crash-stable until it is sealed and referenced by the MANIFEST.
    #[tracing::instrument(
        level = "info",
        skip(self),
        fields(has_cursor = cursor.is_some(), max_frames)
    )]
    pub fn replay_from_sealed(
        &self,
        cursor: Option<ReplayCursor>,
        max_frames: u32,
    ) -> Result<(ReplayFrames, Option<ReplayCursor>)> {
        let limit = if max_frames == 0 {
            usize::MAX
        } else {
            max_frames as usize
        };

        let sealed_len = self.segments_in_order.len();
        if sealed_len == 0 {
            return Ok((Vec::new(), None));
        }

        let (mut seg_idx, mut offset) = match cursor {
            None => (0usize, corecrux_segment::SEGMENT_HEADER_LEN as u64),
            Some(c) => {
                if let Some(idx) = self
                    .segments_in_order
                    .iter()
                    .position(|s| s.segment_seq == c.segment_seq)
                {
                    (idx, c.offset)
                } else {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: format!("cursor segment_seq {} not found", c.segment_seq),
                    });
                }
            }
        };

        let mut out: ReplayFrames = Vec::new();
        while seg_idx < sealed_len && out.len() < limit {
            let seg = &self.segments_in_order[seg_idx];
            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            let record_end: u64;

            if let Some(ti) = self.segment_trailers_by_seq.get(&seg.segment_seq) {
                let block_starts = block_logical_starts(&ti.blocks)?;
                let total_uncompressed_len = ti
                    .blocks
                    .iter()
                    .try_fold(0u64, |acc, b| acc.checked_add(b.uncompressed_len as u64))
                    .ok_or(StorageError::ManifestRecordInvalid {
                        msg: "block uncompressed_len overflow".to_string(),
                    })?;
                record_end = (corecrux_segment::SEGMENT_HEADER_LEN as u64) + total_uncompressed_len;

                let file = File::open(&seg_path).map_err(io_err)?;
                let start_pos = ti.toc_by_offset.partition_point(|e| {
                    let bid = e.block_id as usize;
                    let Some(block_start) = block_starts.get(bid) else {
                        return true;
                    };
                    let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                        .saturating_add(*block_start)
                        .saturating_add(e.in_block_offset as u64);
                    frame_off < offset
                });

                if start_pos >= ti.toc_by_offset.len() {
                    seg_idx += 1;
                    offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
                    continue;
                }

                let remaining = limit.saturating_sub(out.len());
                let take = remaining.min(ti.toc_by_offset.len() - start_pos);
                let slice = &ti.toc_by_offset[start_pos..start_pos + take];
                    let mut block_ids: Vec<u32> = slice.iter().map(|e| e.block_id).collect();
                    block_ids.sort_unstable();
                    block_ids.dedup();
                    let blocks = read_blocks_cpu(&file,
                        &ti.blocks,
                        &block_ids,
                    )?;

                    for e in slice {
                        if out.len() >= limit {
                            break;
                        }
                        let bid = e.block_id as usize;
                        let Some(buf) = blocks.get(bid).and_then(|v| v.as_ref()) else {
                            return Err(StorageError::ManifestRecordInvalid {
                                msg: "block buffer missing".to_string(),
                            });
                        };
                        let start = e.in_block_offset as usize;
                        let len = e.frame_len as usize;
                        let end =
                            start
                                .checked_add(len)
                                .ok_or(StorageError::ManifestRecordInvalid {
                                    msg: "frame slice overflow".to_string(),
                                })?;
                        if end > buf.len() {
                            return Err(StorageError::ManifestRecordInvalid {
                                msg: "replay frame points outside uncompressed block".to_string(),
                            });
                        }

                        let block_start = block_starts.get(bid).copied().ok_or(
                            StorageError::ManifestRecordInvalid {
                                msg: "block start missing".to_string(),
                            },
                        )?;
                        let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                            .checked_add(block_start)
                            .and_then(|v| v.checked_add(e.in_block_offset as u64))
                            .ok_or(StorageError::ManifestRecordInvalid {
                                msg: "frame offset overflow".to_string(),
                            })?;

                        let frame = buf[start..end].to_vec();
                        let _ = decode_frame_v1(&frame)?;
                        let loc = FrameLocation {
                            shard_id: self.shard_id as u64,
                            epoch: seg.epoch,
                            segment_seq: seg.segment_seq,
                            offset: frame_off,
                        };
                        out.push((loc, frame));
                        offset = frame_off.saturating_add(e.frame_len as u64);
                    }
                
            } else {
                // Fallback: Phase 2 scan.
                let bytes = std::fs::read(&seg_path).map_err(io_err)?;
                let (_h, _toc_h, _entries, footer) = decode_segment_v1(&bytes)?;
                let record_start = footer.record_area_offset;
                record_end = footer.toc_offset;

                if offset < record_start {
                    offset = record_start;
                }

                while offset < record_end && out.len() < limit {
                    let frame_len = frame_len_at(&bytes, offset).ok_or_else(|| {
                        StorageError::ManifestRecordInvalid {
                            msg: "failed to compute frame length at replay cursor".to_string(),
                        }
                    })?;
                    let end = offset.saturating_add(frame_len as u64);
                    if end > record_end || end as usize > bytes.len() {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "replay frame extends past record area".to_string(),
                        });
                    }

                    let frame = bytes[offset as usize..end as usize].to_vec();
                    let _ = decode_frame_v1(&frame)?;
                    let loc = FrameLocation {
                        shard_id: self.shard_id as u64,
                        epoch: seg.epoch,
                        segment_seq: seg.segment_seq,
                        offset,
                    };
                    out.push((loc, frame));
                    offset = end;
                }
            }

            if out.len() >= limit {
                if offset >= record_end {
                    seg_idx += 1;
                    if seg_idx >= sealed_len {
                        return Ok((out, None));
                    }
                    let next_seg = &self.segments_in_order[seg_idx];
                    return Ok((
                        out,
                        Some(ReplayCursor {
                            segment_seq: next_seg.segment_seq,
                            offset: corecrux_segment::SEGMENT_HEADER_LEN as u64,
                        }),
                    ));
                }
                return Ok((
                    out,
                    Some(ReplayCursor {
                        segment_seq: seg.segment_seq,
                        offset,
                    }),
                ));
            }

            seg_idx += 1;
            offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
        }

        Ok((out, None))
    }


    #[tracing::instrument(
        level = "info",
        skip(self),
        fields(has_cursor = cursor.is_some(), max_frames)
    )]
    pub fn replay_from(
        &self,
        cursor: Option<ReplayCursor>,
        max_frames: u32,
    ) -> Result<(ReplayFrames, Option<ReplayCursor>)> {
        let limit = if max_frames == 0 {
            usize::MAX
        } else {
            max_frames as usize
        };

        let sealed_len = self.segments_in_order.len();
        let has_head = self.head.is_some();
        let total_segments = sealed_len + if has_head { 1 } else { 0 };

        let (mut seg_idx, mut offset) = match cursor {
            None => {
                if sealed_len > 0 {
                    (0usize, corecrux_segment::SEGMENT_HEADER_LEN as u64)
                } else if has_head {
                    (sealed_len, corecrux_segment::SEGMENT_HEADER_LEN as u64)
                } else {
                    return Ok((Vec::new(), None));
                }
            }
            Some(c) => {
                if let Some(idx) = self
                    .segments_in_order
                    .iter()
                    .position(|s| s.segment_seq == c.segment_seq)
                {
                    (idx, c.offset)
                } else if let Some(head) = self.head.as_ref() {
                    if head.segment_seq == c.segment_seq {
                        (sealed_len, c.offset)
                    } else {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: format!("cursor segment_seq {} not found", c.segment_seq),
                        });
                    }
                } else {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: format!("cursor segment_seq {} not found", c.segment_seq),
                    });
                }
            }
        };

        let mut out: ReplayFrames = Vec::new();
        while seg_idx < total_segments && out.len() < limit {
            // Special final "segment": the currently-appending head segment (if enabled).
            if seg_idx == sealed_len {
                let head = self
                    .head
                    .as_ref()
                    .expect("head exists when seg_idx==sealed_len");
                let record_end =
                    (corecrux_segment::SEGMENT_HEADER_LEN as u64).saturating_add(head.record_len);

                if offset < corecrux_segment::SEGMENT_HEADER_LEN as u64 {
                    offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
                }
                if offset >= record_end {
                    seg_idx += 1;
                    offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
                    continue;
                }

                let start_pos = head.frames.partition_point(|f| {
                    let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                        .saturating_add(f.record_off as u64);
                    frame_off < offset
                });
                if start_pos >= head.frames.len() {
                    seg_idx += 1;
                    offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
                    continue;
                }

                let remaining = limit.saturating_sub(out.len());
                let take = remaining.min(head.frames.len() - start_pos);
                let slice = &head.frames[start_pos..start_pos + take];
                    let mut block_ids: Vec<u32> = slice.iter().map(|f| f.block_id).collect();
                    block_ids.sort_unstable();
                    block_ids.dedup();
                    let blocks = read_blocks_cpu(&head.file,
                        &head.blocks,
                        &block_ids,
                    )?;

                    for f in slice {
                        if out.len() >= limit {
                            break;
                        }
                        let bid = f.block_id as usize;
                        let Some(buf) = blocks.get(bid).and_then(|v| v.as_ref()) else {
                            return Err(StorageError::ManifestRecordInvalid {
                                msg: "head block buffer missing".to_string(),
                            });
                        };
                        let start = f.in_block_offset as usize;
                        let len = f.frame_len as usize;
                        let end =
                            start
                                .checked_add(len)
                                .ok_or(StorageError::ManifestRecordInvalid {
                                    msg: "head replay frame slice overflow".to_string(),
                                })?;
                        if end > buf.len() {
                            return Err(StorageError::ManifestRecordInvalid {
                                msg: "head replay frame points outside uncompressed block"
                                    .to_string(),
                            });
                        }

                        let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                            .saturating_add(f.record_off as u64);
                        let frame = buf[start..end].to_vec();
                        let _ = decode_frame_v1(&frame)?;
                        let loc = FrameLocation {
                            shard_id: self.shard_id as u64,
                            epoch: self.epoch,
                            segment_seq: head.segment_seq,
                            offset: frame_off,
                        };
                        out.push((loc, frame));
                        offset = frame_off.saturating_add(f.frame_len as u64);
                    }
                

                if out.len() >= limit {
                    if offset >= record_end {
                        return Ok((out, None));
                    }
                    return Ok((
                        out,
                        Some(ReplayCursor {
                            segment_seq: head.segment_seq,
                            offset,
                        }),
                    ));
                }

                seg_idx += 1;
                offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
                continue;
            }

            let seg = &self.segments_in_order[seg_idx];
            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            let record_end: u64;

            if let Some(ti) = self.segment_trailers_by_seq.get(&seg.segment_seq) {
                let block_starts = block_logical_starts(&ti.blocks)?;
                let total_uncompressed_len = ti
                    .blocks
                    .iter()
                    .try_fold(0u64, |acc, b| acc.checked_add(b.uncompressed_len as u64))
                    .ok_or(StorageError::ManifestRecordInvalid {
                        msg: "block uncompressed_len overflow".to_string(),
                    })?;
                record_end = (corecrux_segment::SEGMENT_HEADER_LEN as u64) + total_uncompressed_len;

                let file = File::open(&seg_path).map_err(io_err)?;
                let start_pos = ti.toc_by_offset.partition_point(|e| {
                    let bid = e.block_id as usize;
                    let Some(block_start) = block_starts.get(bid) else {
                        return true;
                    };
                    let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                        .saturating_add(*block_start)
                        .saturating_add(e.in_block_offset as u64);
                    frame_off < offset
                });

                if start_pos >= ti.toc_by_offset.len() {
                    seg_idx += 1;
                    offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
                    continue;
                }

                let remaining = limit.saturating_sub(out.len());
                let take = remaining.min(ti.toc_by_offset.len() - start_pos);
                let slice = &ti.toc_by_offset[start_pos..start_pos + take];
                    let mut block_ids: Vec<u32> = slice.iter().map(|e| e.block_id).collect();
                    block_ids.sort_unstable();
                    block_ids.dedup();
                    let blocks = read_blocks_cpu(&file,
                        &ti.blocks,
                        &block_ids,
                    )?;

                    for e in slice {
                        if out.len() >= limit {
                            break;
                        }
                        let bid = e.block_id as usize;
                        let Some(buf) = blocks.get(bid).and_then(|v| v.as_ref()) else {
                            return Err(StorageError::ManifestRecordInvalid {
                                msg: "block buffer missing".to_string(),
                            });
                        };
                        let start = e.in_block_offset as usize;
                        let len = e.frame_len as usize;
                        let end =
                            start
                                .checked_add(len)
                                .ok_or(StorageError::ManifestRecordInvalid {
                                    msg: "frame slice overflow".to_string(),
                                })?;
                        if end > buf.len() {
                            return Err(StorageError::ManifestRecordInvalid {
                                msg: "replay frame points outside uncompressed block".to_string(),
                            });
                        }

                        let block_start = block_starts.get(bid).copied().ok_or(
                            StorageError::ManifestRecordInvalid {
                                msg: "block start missing".to_string(),
                            },
                        )?;
                        let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                            .checked_add(block_start)
                            .and_then(|v| v.checked_add(e.in_block_offset as u64))
                            .ok_or(StorageError::ManifestRecordInvalid {
                                msg: "frame offset overflow".to_string(),
                            })?;

                        let frame = buf[start..end].to_vec();
                        let _ = decode_frame_v1(&frame)?;
                        let loc = FrameLocation {
                            shard_id: self.shard_id as u64,
                            epoch: seg.epoch,
                            segment_seq: seg.segment_seq,
                            offset: frame_off,
                        };
                        out.push((loc, frame));
                        offset = frame_off.saturating_add(e.frame_len as u64);
                    }
                
            } else {
                // Fallback: Phase 2 scan.
                let bytes = std::fs::read(&seg_path).map_err(io_err)?;
                let (_h, _toc_h, _entries, footer) = decode_segment_v1(&bytes)?;
                let record_start = footer.record_area_offset;
                record_end = footer.toc_offset;

                if offset < record_start {
                    offset = record_start;
                }

                while offset < record_end && out.len() < limit {
                    let frame_len = frame_len_at(&bytes, offset).ok_or_else(|| {
                        StorageError::ManifestRecordInvalid {
                            msg: "failed to compute frame length at replay cursor".to_string(),
                        }
                    })?;
                    let end = offset.saturating_add(frame_len as u64);
                    if end > record_end || end as usize > bytes.len() {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "replay frame extends past record area".to_string(),
                        });
                    }

                    let frame = bytes[offset as usize..end as usize].to_vec();
                    let _ = decode_frame_v1(&frame)?;
                    let loc = FrameLocation {
                        shard_id: self.shard_id as u64,
                        epoch: seg.epoch,
                        segment_seq: seg.segment_seq,
                        offset,
                    };
                    out.push((loc, frame));
                    offset = end;
                }
            }

            if out.len() >= limit {
                if offset >= record_end {
                    seg_idx += 1;
                    if seg_idx >= total_segments {
                        return Ok((out, None));
                    }
                    if seg_idx == sealed_len {
                        let head = self.head.as_ref().expect("head exists");
                        return Ok((
                            out,
                            Some(ReplayCursor {
                                segment_seq: head.segment_seq,
                                offset: corecrux_segment::SEGMENT_HEADER_LEN as u64,
                            }),
                        ));
                    }
                    let next_seg = &self.segments_in_order[seg_idx];
                    return Ok((
                        out,
                        Some(ReplayCursor {
                            segment_seq: next_seg.segment_seq,
                            offset: corecrux_segment::SEGMENT_HEADER_LEN as u64,
                        }),
                    ));
                }
                return Ok((
                    out,
                    Some(ReplayCursor {
                        segment_seq: seg.segment_seq,
                        offset,
                    }),
                ));
            }

            seg_idx += 1;
            offset = corecrux_segment::SEGMENT_HEADER_LEN as u64;
        }

        Ok((out, None))
    }

    /// Phase 5 performance helper: read record blocks in physical order and ensure the bytes are
    /// device-visible via a GPU "touch" kernel in CUDA builds.
    ///
    /// NOTE: this does not perform per-frame validation in the CUDA path (the sealed segment
    /// hashes are already validated on open). The CPU fallback path retains the stricter scan.
    ///
    /// The `budget_bytes` parameter bounds per-batch IO + decompression working set; smaller
    /// values are safer on constrained device pools but reduce throughput.
    pub fn replay_scan_stats_all(&self, budget_bytes: usize) -> Result<ReplayScanStats> {
        if budget_bytes == 0 {
            return Err(StorageError::InvalidArgument {
                code: "BUDGET_BYTES_ZERO".to_string(),
                msg: "budget_bytes must be > 0".to_string(),
            });
        }

        let mut stats = ReplayScanStats {
            total_segments: 0,
            total_blocks: 0,
            total_frames: 0,
            total_compressed_bytes: 0,
            total_uncompressed_bytes: 0,
        };

        // Sealed segments (manifest order).
        for seg in &self.segments_in_order {
            let Some(ti) = self.segment_trailers_by_seq.get(&seg.segment_seq) else {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: "missing trailer index for sealed segment".to_string(),
                });
            };
            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            let file = File::open(&seg_path).map_err(io_err)?;

            stats.total_segments += 1;

            stats.total_compressed_bytes += ti
                .blocks
                .iter()
                .map(|b| b.compressed_len as u64)
                .sum::<u64>();
            stats.total_uncompressed_bytes += ti
                .blocks
                .iter()
                .map(|b| b.uncompressed_len as u64)
                .sum::<u64>();

            let mut i = 0usize;
            while i < ti.blocks.len() {
                let mut batch_ids: Vec<u32> = Vec::new();
                let mut batch_comp: usize = 0;
                let mut batch_uncomp: usize = 0;

                while i < ti.blocks.len() {
                    let b = &ti.blocks[i];
                    let blen_c = b.compressed_len as usize;
                    let blen_u = b.uncompressed_len as usize;
                    if !batch_ids.is_empty()
                        && (batch_comp.saturating_add(blen_c) > budget_bytes
                            || batch_uncomp.saturating_add(blen_u) > budget_bytes)
                    {
                        break;
                    }
                    batch_ids.push(b.block_id);
                    batch_comp = batch_comp.saturating_add(blen_c);
                    batch_uncomp = batch_uncomp.saturating_add(blen_u);
                    i += 1;
                }

                if batch_ids.is_empty() {
                    // Single oversized block; force progress.
                    batch_ids.push(ti.blocks[i].block_id);
                    i += 1;
                }
                    let blocks = read_blocks_cpu(&file,
                        &ti.blocks,
                        &batch_ids,
                    )?;
                    for bid in &batch_ids {
                        let idx = *bid as usize;
                        let Some(buf) = blocks.get(idx).and_then(|v| v.as_ref()) else {
                            return Err(StorageError::ManifestRecordInvalid {
                                msg: "block buffer missing during replay scan".to_string(),
                            });
                        };
                        let frames = scan_frames_v1_block_bytes(buf)?;
                        stats.total_frames = stats.total_frames.saturating_add(frames as u64);
                    }
                
            }
        }

        // Head segment (currently-appending), if present.
        if let Some(head) = self.head.as_ref() {
            stats.total_segments += 1;

            stats.total_compressed_bytes += head
                .blocks
                .iter()
                .map(|b| b.compressed_len as u64)
                .sum::<u64>();
            stats.total_uncompressed_bytes += head
                .blocks
                .iter()
                .map(|b| b.uncompressed_len as u64)
                .sum::<u64>();

            let mut i = 0usize;
            while i < head.blocks.len() {
                let mut batch_ids: Vec<u32> = Vec::new();
                let mut batch_comp: usize = 0;
                let mut batch_uncomp: usize = 0;

                while i < head.blocks.len() {
                    let b = &head.blocks[i];
                    let blen_c = b.compressed_len as usize;
                    let blen_u = b.uncompressed_len as usize;
                    if !batch_ids.is_empty()
                        && (batch_comp.saturating_add(blen_c) > budget_bytes
                            || batch_uncomp.saturating_add(blen_u) > budget_bytes)
                    {
                        break;
                    }
                    batch_ids.push(b.block_id);
                    batch_comp = batch_comp.saturating_add(blen_c);
                    batch_uncomp = batch_uncomp.saturating_add(blen_u);
                    i += 1;
                }
                if batch_ids.is_empty() {
                    batch_ids.push(head.blocks[i].block_id);
                    i += 1;
                }
                    let blocks = read_blocks_cpu(&head.file,
                        &head.blocks,
                        &batch_ids,
                    )?;
                    for bid in &batch_ids {
                        let idx = *bid as usize;
                        let Some(buf) = blocks.get(idx).and_then(|v| v.as_ref()) else {
                            return Err(StorageError::ManifestRecordInvalid {
                                msg: "head block buffer missing during replay scan".to_string(),
                            });
                        };
                        let frames = scan_frames_v1_block_bytes(buf)?;
                        stats.total_frames = stats.total_frames.saturating_add(frames as u64);
                    }
                
            }
        }

        Ok(stats)
    }

    /// Phase 5 hardening helper: validate per-block CRC32C and frame boundary correctness by
    /// scanning all record blocks in physical order.
    ///
    /// This is intentionally separate from `replay_scan_stats_all` (which is throughput-oriented)
    /// so replay SLO floors are not affected by extra validation work.
    pub fn integrity_scan_stats_all(&self, budget_bytes: usize) -> Result<ReplayScanStats> {
        if budget_bytes == 0 {
            return Err(StorageError::InvalidArgument {
                code: "BUDGET_BYTES_ZERO".to_string(),
                msg: "budget_bytes must be > 0".to_string(),
            });
        }

        let mut stats = ReplayScanStats {
            total_segments: 0,
            total_blocks: 0,
            total_frames: 0,
            total_compressed_bytes: 0,
            total_uncompressed_bytes: 0,
        };

        // Sealed segments (manifest order).
        for seg in &self.segments_in_order {
            let Some(ti) = self.segment_trailers_by_seq.get(&seg.segment_seq) else {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: "missing trailer index for sealed segment".to_string(),
                });
            };
            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            let file = File::open(&seg_path).map_err(io_err)?;

            stats.total_segments += 1;
            stats.total_blocks += ti.blocks.len() as u64;
            stats.total_compressed_bytes += ti
                .blocks
                .iter()
                .map(|b| b.compressed_len as u64)
                .sum::<u64>();
            stats.total_uncompressed_bytes += ti
                .blocks
                .iter()
                .map(|b| b.uncompressed_len as u64)
                .sum::<u64>();

            let mut seg_frames: u64 = 0;
            let mut i = 0usize;
            while i < ti.blocks.len() {
                let mut batch_ids: Vec<u32> = Vec::new();
                let mut batch_comp: usize = 0;
                let mut batch_uncomp: usize = 0;

                while i < ti.blocks.len() {
                    let b = &ti.blocks[i];
                    let blen_c = b.compressed_len as usize;
                    let blen_u = b.uncompressed_len as usize;
                    if !batch_ids.is_empty()
                        && (batch_comp.saturating_add(blen_c) > budget_bytes
                            || batch_uncomp.saturating_add(blen_u) > budget_bytes)
                    {
                        break;
                    }
                    batch_ids.push(b.block_id);
                    batch_comp = batch_comp.saturating_add(blen_c);
                    batch_uncomp = batch_uncomp.saturating_add(blen_u);
                    i += 1;
                }

                if batch_ids.is_empty() {
                    // Single oversized block; force progress.
                    batch_ids.push(ti.blocks[i].block_id);
                    i += 1;
                }
                    let blocks = read_blocks_cpu(&file,
                        &ti.blocks,
                        &batch_ids,
                    )?;
                    for bid in &batch_ids {
                        let idx = *bid as usize;
                        let Some(buf) = blocks.get(idx).and_then(|v| v.as_ref()) else {
                            return Err(StorageError::ManifestRecordInvalid {
                                msg: "block buffer missing during integrity scan".to_string(),
                            });
                        };
                        let frames = scan_frames_v1_block_bytes(buf)?;
                        seg_frames = seg_frames.saturating_add(frames as u64);
                    }
                
            }

            if seg_frames != seg.toc_entry_count {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: format!(
                        "integrity scan frame count mismatch for segment_seq {}: toc_entry_count={} scanned={seg_frames}",
                        seg.segment_seq, seg.toc_entry_count
                    ),
                });
            }
            stats.total_frames = stats.total_frames.saturating_add(seg_frames);
        }

        // Head segment (currently-appending), if present.
        if let Some(head) = self.head.as_ref() {
            stats.total_segments += 1;
            stats.total_blocks += head.blocks.len() as u64;
            stats.total_compressed_bytes += head
                .blocks
                .iter()
                .map(|b| b.compressed_len as u64)
                .sum::<u64>();
            stats.total_uncompressed_bytes += head
                .blocks
                .iter()
                .map(|b| b.uncompressed_len as u64)
                .sum::<u64>();

            let expected = head.frames.len() as u64;
            let mut scanned: u64 = 0;

            let mut i = 0usize;
            while i < head.blocks.len() {
                let mut batch_ids: Vec<u32> = Vec::new();
                let mut batch_comp: usize = 0;
                let mut batch_uncomp: usize = 0;

                while i < head.blocks.len() {
                    let b = &head.blocks[i];
                    let blen_c = b.compressed_len as usize;
                    let blen_u = b.uncompressed_len as usize;
                    if !batch_ids.is_empty()
                        && (batch_comp.saturating_add(blen_c) > budget_bytes
                            || batch_uncomp.saturating_add(blen_u) > budget_bytes)
                    {
                        break;
                    }
                    batch_ids.push(b.block_id);
                    batch_comp = batch_comp.saturating_add(blen_c);
                    batch_uncomp = batch_uncomp.saturating_add(blen_u);
                    i += 1;
                }
                if batch_ids.is_empty() {
                    batch_ids.push(head.blocks[i].block_id);
                    i += 1;
                }
                    let blocks = read_blocks_cpu(&head.file,
                        &head.blocks,
                        &batch_ids,
                    )?;
                    for bid in &batch_ids {
                        let idx = *bid as usize;
                        let Some(buf) = blocks.get(idx).and_then(|v| v.as_ref()) else {
                            return Err(StorageError::ManifestRecordInvalid {
                                msg: "head block buffer missing during integrity scan".to_string(),
                            });
                        };
                        let frames = scan_frames_v1_block_bytes(buf)?;
                        scanned = scanned.saturating_add(frames as u64);
                    }
                
            }

            if scanned != expected {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: format!(
                        "integrity scan frame count mismatch for head segment_seq {}: expected={} scanned={scanned}",
                        head.segment_seq, expected
                    ),
                });
            }
            stats.total_frames = stats.total_frames.saturating_add(scanned);
        }

        Ok(stats)
    }

    pub fn read_frame_bytes(&self, segment_seq: u64, offset: u64) -> Result<Vec<u8>> {
        if let Some(head) = self.head.as_ref() {
            if head.segment_seq == segment_seq {
                let (block_idx, in_block_offset) = logical_offset_to_block(&head.blocks, offset)?;
                let blocks = read_blocks_cpu(&head.file,
                    &head.blocks,
                    &[block_idx as u32],
                )?;
                let Some(buf) = blocks.get(block_idx).and_then(|v| v.as_ref()) else {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "head block buffer missing".to_string(),
                    });
                };
                let frame_len =
                    frame_len_at(buf, in_block_offset as u64).ok_or(StorageError::Io {
                        msg: "failed to compute head frame length for logical offset".to_string(),
                    })?;
                let start = in_block_offset as usize;
                let end = start.saturating_add(frame_len);
                if end > buf.len() {
                    return Err(StorageError::ManifestRecordInvalid {
                        msg: "head frame points outside uncompressed block".to_string(),
                    });
                }
                return Ok(buf[start..end].to_vec());
            }
        }

        let seg = self.segments_by_seq.get(&segment_seq).ok_or_else(|| {
            StorageError::ManifestRecordInvalid {
                msg: format!("segment_seq {segment_seq} not found"),
            }
        })?;
        let seg_path = self.paths.shard_dir.join(&seg.relative_path);
        if let Some(ti) = self.segment_trailers_by_seq.get(&segment_seq) {
            let file = File::open(&seg_path).map_err(io_err)?;
            let (block_idx, in_block_offset) = logical_offset_to_block(&ti.blocks, offset)?;
            let blocks = read_blocks_cpu(&file,
                &ti.blocks,
                &[block_idx as u32],
            )?;
            let Some(buf) = blocks.get(block_idx).and_then(|v| v.as_ref()) else {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: "block buffer missing".to_string(),
                });
            };
            let frame_len = frame_len_at(buf, in_block_offset as u64).ok_or(StorageError::Io {
                msg: "failed to compute frame length for logical offset".to_string(),
            })?;
            let start = in_block_offset as usize;
            let end = start.saturating_add(frame_len);
            if end > buf.len() {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: "frame points outside uncompressed block".to_string(),
                });
            }
            return Ok(buf[start..end].to_vec());
        }

        read_frame_bytes_physical(&seg_path, offset)
    }

    pub fn read_frame_bytes_batch(&self, locations: &[FrameLocation]) -> Result<Vec<Vec<u8>>> {
        let packed = self.read_frame_bytes_batch_packed(locations)?;
        let mut out = Vec::with_capacity(packed.frame_lens.len());
        for (off, len) in packed
            .frame_offsets
            .iter()
            .copied()
            .zip(packed.frame_lens.iter().copied())
        {
            let start = off as usize;
            let end = start.saturating_add(len as usize);
            if end > packed.frames_blob.len() {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: "packed frame range exceeds blob bounds".to_string(),
                });
            }
            out.push(packed.frames_blob[start..end].to_vec());
        }
        Ok(out)
    }

    pub fn read_frame_bytes_batch_packed(
        &self,
        locations: &[FrameLocation],
    ) -> Result<ReadFrameBatchPackedV1> {
        fn extract_frame(buf: &[u8], in_block_offset: usize, context: &str) -> Result<Vec<u8>> {
            let frame_len = frame_len_at(buf, in_block_offset as u64).ok_or(StorageError::Io {
                msg: format!("failed to compute {context} frame length for logical offset"),
            })?;
            let start = in_block_offset;
            let end = start.saturating_add(frame_len);
            if end > buf.len() {
                return Err(StorageError::ManifestRecordInvalid {
                    msg: format!("{context} frame points outside uncompressed block"),
                });
            }
            Ok(buf[start..end].to_vec())
        }

        if locations.is_empty() {
            return Ok(ReadFrameBatchPackedV1 {
                frames_blob: Vec::new(),
                frame_offsets: Vec::new(),
                frame_lens: Vec::new(),
                frame_bytes: 0,
            });
        }

        let mut frames_blob = Vec::new();
        let mut frame_offsets = Vec::with_capacity(locations.len());
        let mut frame_lens = Vec::with_capacity(locations.len());
        let mut frame_bytes = 0u64;
        let mut cached_head_block: Option<(u32, Vec<u8>)> = None;
        let mut cached_sealed_block: Option<(u64, u32, Vec<u8>)> = None;
        let mut cached_sealed_file: Option<(u64, File)> = None;

        for loc in locations {
            let push_frame = |frame: &[u8],
                              frames_blob: &mut Vec<u8>,
                              frame_offsets: &mut Vec<u32>,
                              frame_lens: &mut Vec<u32>,
                              frame_bytes: &mut u64|
             -> Result<()> {
                let off = u32::try_from(frames_blob.len()).map_err(|_| StorageError::Io {
                    msg: "packed frame offset overflow".to_string(),
                })?;
                let len = u32::try_from(frame.len()).map_err(|_| StorageError::Io {
                    msg: "packed frame length overflow".to_string(),
                })?;
                frame_offsets.push(off);
                frame_lens.push(len);
                *frame_bytes = frame_bytes.saturating_add(frame.len() as u64);
                frames_blob.extend_from_slice(frame);
                Ok(())
            };

            if let Some(head) = self.head.as_ref() {
                if head.segment_seq == loc.segment_seq {
                    let (block_idx, in_block_offset) =
                        logical_offset_to_block(&head.blocks, loc.offset)?;
                    let needs_reload = cached_head_block
                        .as_ref()
                        .map(|(cached_idx, _)| *cached_idx != block_idx as u32)
                        .unwrap_or(true);
                    if needs_reload {
                        let blocks = read_blocks_cpu(&head.file,
                            &head.blocks,
                            &[block_idx as u32],
                        )?;
                        let Some(buf) = blocks.get(block_idx).and_then(|v| v.as_ref()) else {
                            return Err(StorageError::ManifestRecordInvalid {
                                msg: "head block buffer missing".to_string(),
                            });
                        };
                        cached_head_block = Some((block_idx as u32, buf.clone()));
                    }
                    let frame = extract_frame(
                        &cached_head_block
                            .as_ref()
                            .expect("cached head block just loaded")
                            .1,
                        in_block_offset as usize,
                        "head",
                    )?;
                    push_frame(
                        &frame,
                        &mut frames_blob,
                        &mut frame_offsets,
                        &mut frame_lens,
                        &mut frame_bytes,
                    )?;
                    continue;
                }
            }

            let seg = self.segments_by_seq.get(&loc.segment_seq).ok_or_else(|| {
                StorageError::ManifestRecordInvalid {
                    msg: format!("segment_seq {} not found", loc.segment_seq),
                }
            })?;
            let seg_path = self.paths.shard_dir.join(&seg.relative_path);
            if let Some(ti) = self.segment_trailers_by_seq.get(&loc.segment_seq) {
                let (block_idx, in_block_offset) = logical_offset_to_block(&ti.blocks, loc.offset)?;
                let block_idx_u32 = block_idx as u32;
                let needs_reload = cached_sealed_block
                    .as_ref()
                    .map(|(cached_seg, cached_block, _)| {
                        *cached_seg != loc.segment_seq || *cached_block != block_idx_u32
                    })
                    .unwrap_or(true);
                if needs_reload {
                    let file_seq = cached_sealed_file.as_ref().map(|(seq, _)| *seq);
                    if file_seq != Some(loc.segment_seq) {
                        let file = File::open(&seg_path).map_err(io_err)?;
                        cached_sealed_file = Some((loc.segment_seq, file));
                    }
                    let file_ref = &cached_sealed_file
                        .as_ref()
                        .expect("cached sealed file just loaded")
                        .1;
                    let blocks = read_blocks_cpu(file_ref,
                        &ti.blocks,
                        &[block_idx_u32],
                    )?;
                    let Some(buf) = blocks.get(block_idx).and_then(|v| v.as_ref()) else {
                        return Err(StorageError::ManifestRecordInvalid {
                            msg: "block buffer missing".to_string(),
                        });
                    };
                    cached_sealed_block = Some((loc.segment_seq, block_idx_u32, buf.clone()));
                }
                let frame = extract_frame(
                    &cached_sealed_block
                        .as_ref()
                        .expect("cached sealed block just loaded")
                        .2,
                    in_block_offset as usize,
                    "sealed",
                )?;
                push_frame(
                    &frame,
                    &mut frames_blob,
                    &mut frame_offsets,
                    &mut frame_lens,
                    &mut frame_bytes,
                )?;
            } else {
                let frame = read_frame_bytes_physical(&seg_path, loc.offset)?;
                push_frame(
                    &frame,
                    &mut frames_blob,
                    &mut frame_offsets,
                    &mut frame_lens,
                    &mut frame_bytes,
                )?;
            }
        }

        Ok(ReadFrameBatchPackedV1 {
            frames_blob,
            frame_offsets,
            frame_lens,
            frame_bytes,
        })
    }

    /// Read a committed sealed segment payload for replication shipping.
    ///
    /// Returns the exact on-disk bytes and the canonical segment hash recorded in MANIFEST.
    pub fn read_segment_bytes_for_replication(
        &self,
        segment_seq: u64,
    ) -> Result<(Vec<u8>, [u8; 32])> {
        let seg = self.segments_by_seq.get(&segment_seq).ok_or_else(|| {
            StorageError::ManifestRecordInvalid {
                msg: format!("segment_seq {segment_seq} not found"),
            }
        })?;
        let seg_path = self.paths.shard_dir.join(&seg.relative_path);
        let bytes = std::fs::read(&seg_path).map_err(io_err)?;
        let (_hdr, _toc, _entries, footer) = decode_segment_v1(&bytes)?;
        if footer.segment_hash != seg.segment_hash {
            return Err(StorageError::ManifestRecordInvalid {
                msg: format!(
                    "segment hash mismatch for segment_seq {segment_seq}: manifest={:?} footer={:?}",
                    seg.segment_hash,
                    footer.segment_hash
                ),
            });
        }
        Ok((bytes, seg.segment_hash))
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

const MANIFEST_RECORD_TYPE_ADD_SEGMENT_V1: u8 = 1;
const MANIFEST_RECORD_TYPE_ADD_DIR_RUN_V1: u8 = 10;
const MANIFEST_RECORD_TYPE_REMOVE_DIR_RUN_V1: u8 = 11;
const MANIFEST_RECORD_TYPE_STREAM_META_UPDATE_V1: u8 = 20;

#[derive(Debug, Clone, Copy)]
struct StreamMetaUpdateV1 {
    stream_hash: u64,
    min_live_seq: u64,
    tombstone_seq: u64,
    gen: u64,
}

#[derive(Debug, Clone)]
enum ManifestRecord {
    AddSegment(SegmentMeta),
    AddDirRun(DirRunMeta),
    RemoveDirRun(DirRunKey),
    StreamMetaUpdate(StreamMetaUpdateV1),
}

#[derive(Debug, Default)]
struct ManifestState {
    segments_by_seq: HashMap<u64, SegmentMeta>,
    dir_runs: HashMap<DirRunKey, DirRunMeta>,
    stream_meta: HashMap<u64, StreamMeta>,
}

impl ManifestState {
    fn apply(&mut self, rec: ManifestRecord) {
        match rec {
            ManifestRecord::AddSegment(seg) => {
                self.segments_by_seq.insert(seg.segment_seq, seg);
            }
            ManifestRecord::AddDirRun(run) => {
                self.dir_runs.insert(run.key, run);
            }
            ManifestRecord::RemoveDirRun(key) => {
                self.dir_runs.remove(&key);
            }
            ManifestRecord::StreamMetaUpdate(upd) => {
                let e = self.stream_meta.entry(upd.stream_hash).or_default();
                e.min_live_seq = e.min_live_seq.max(upd.min_live_seq);
                e.tombstone_seq = e.tombstone_seq.max(upd.tombstone_seq);
            }
        }
    }
}

pub fn encode_manifest_header_v1(
    shard_id: u32,
    epoch: u64,
    created_at_unix_ns: u64,
) -> Result<[u8; MANIFEST_HEADER_LEN]> {
    let mut out = [0u8; MANIFEST_HEADER_LEN];
    out[0..4].copy_from_slice(&MANIFEST_MAGIC_CCMF.to_le_bytes());
    out[4..6].copy_from_slice(&MANIFEST_VERSION_V1.to_le_bytes());
    out[8..12].copy_from_slice(&(MANIFEST_HEADER_LEN as u32).to_le_bytes());
    out[12..16].copy_from_slice(&shard_id.to_le_bytes());
    out[16..24].copy_from_slice(&epoch.to_le_bytes());
    out[24..32].copy_from_slice(&created_at_unix_ns.to_le_bytes());

    let crc = crc32c::crc32c(&out[..MANIFEST_HEADER_LEN - 4]);
    out[MANIFEST_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
    Ok(out)
}

pub fn load_manifest_segment_catalog(shard_dir: &Path) -> Result<ManifestSegmentCatalogV1> {
    let manifest_path = shard_dir.join("MANIFEST");
    let mut manifest = File::open(&manifest_path).map_err(io_err)?;

    let mut header = [0u8; MANIFEST_HEADER_LEN];
    manifest.read_exact(&mut header).map_err(io_err)?;
    validate_manifest_header(&header)?;

    let mut shard_id_bytes = [0u8; 4];
    shard_id_bytes.copy_from_slice(&header[12..16]);
    let mut epoch_bytes = [0u8; 8];
    epoch_bytes.copy_from_slice(&header[16..24]);

    manifest.seek(SeekFrom::Start(0)).map_err(io_err)?;
    let (state, manifest_end) = load_manifest_records(&mut manifest)?;
    let mut segments: Vec<SegmentMeta> = state.segments_by_seq.into_values().collect();
    segments.sort_by_key(|segment| segment.segment_seq);

    Ok(ManifestSegmentCatalogV1 {
        shard_id: u32::from_le_bytes(shard_id_bytes),
        epoch: u64::from_le_bytes(epoch_bytes),
        manifest_end,
        segments,
    })
}

fn load_manifest_records(manifest: &mut File) -> Result<(ManifestState, u64)> {
    manifest.seek(SeekFrom::Start(0)).map_err(io_err)?;
    let mut hdr = [0u8; MANIFEST_HEADER_LEN];
    manifest.read_exact(&mut hdr).map_err(io_err)?;
    validate_manifest_header(&hdr)?;

    let mut state = ManifestState::default();

    let mut offset = MANIFEST_HEADER_LEN as u64;
    loop {
        let mut len_buf = [0u8; 8];
        match manifest.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) => {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(io_err(e));
            }
        }
        let record_len = u32::from_le_bytes(len_buf[0..4].try_into().unwrap()) as usize;
        let expected_crc = u32::from_le_bytes(len_buf[4..8].try_into().unwrap());

        if record_len == 0 || record_len > 64 * 1024 * 1024 {
            break;
        }

        let mut rec = vec![0u8; record_len];
        if let Err(e) = manifest.read_exact(&mut rec) {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                break;
            }
            return Err(io_err(e));
        }
        let actual_crc = crc32c::crc32c(&rec);
        if actual_crc != expected_crc {
            // Tail is corrupt; stop and allow truncation.
            break;
        }

        if let Some(seg) = parse_manifest_record(&rec)? {
            state.apply(seg);
        }

        offset += 8 + (record_len as u64);
    }

    // If file has a junk tail, truncate to last good offset.
    let meta_len = manifest.metadata().map_err(io_err)?.len();
    if meta_len > offset {
        manifest.set_len(offset).map_err(io_err)?;
        manifest.sync_all().map_err(io_err)?;
    }

    Ok((state, offset))
}

fn validate_manifest_header(bytes: &[u8]) -> Result<()> {
    if bytes.len() < MANIFEST_HEADER_LEN {
        return Err(StorageError::ManifestHeaderInvalid {
            msg: "too small".to_string(),
        });
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    if magic != MANIFEST_MAGIC_CCMF {
        return Err(StorageError::ManifestHeaderInvalid {
            msg: format!("bad magic: {magic:#x}"),
        });
    }
    let ver = u16::from_le_bytes(bytes[4..6].try_into().unwrap());
    if ver != MANIFEST_VERSION_V1 {
        return Err(StorageError::ManifestHeaderInvalid {
            msg: format!("bad version: {ver}"),
        });
    }
    let header_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if header_len != MANIFEST_HEADER_LEN {
        return Err(StorageError::ManifestHeaderInvalid {
            msg: format!("bad header_len: {header_len}"),
        });
    }
    let expected = u32::from_le_bytes(bytes[MANIFEST_HEADER_LEN - 4..].try_into().unwrap());
    let actual = crc32c::crc32c(&bytes[..MANIFEST_HEADER_LEN - 4]);
    if expected != actual {
        return Err(StorageError::ManifestCrcMismatch { expected, actual });
    }
    Ok(())
}

pub fn frame_manifest_record(record_bytes: &[u8]) -> Vec<u8> {
    let len = record_bytes.len() as u32;
    let crc = crc32c::crc32c(record_bytes);
    let mut out = Vec::with_capacity(8 + record_bytes.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(record_bytes);
    out
}

fn parse_manifest_record(bytes: &[u8]) -> Result<Option<ManifestRecord>> {
    if bytes.len() < 4 {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "too small".to_string(),
        });
    }
    let record_type = bytes[0];
    let record_version = bytes[1];
    if record_version != 1 {
        return Ok(None);
    }
    match record_type {
        MANIFEST_RECORD_TYPE_ADD_SEGMENT_V1 => Ok(Some(ManifestRecord::AddSegment(
            parse_add_segment_v1(bytes)?,
        ))),
        MANIFEST_RECORD_TYPE_ADD_DIR_RUN_V1 => Ok(Some(ManifestRecord::AddDirRun(
            parse_add_dir_run_v1(bytes)?,
        ))),
        MANIFEST_RECORD_TYPE_REMOVE_DIR_RUN_V1 => Ok(Some(ManifestRecord::RemoveDirRun(
            parse_remove_dir_run_v1(bytes)?,
        ))),
        MANIFEST_RECORD_TYPE_STREAM_META_UPDATE_V1 => Ok(Some(ManifestRecord::StreamMetaUpdate(
            parse_stream_meta_update_v1(bytes)?,
        ))),
        _ => Ok(None),
    }
}

fn parse_add_segment_v1(bytes: &[u8]) -> Result<SegmentMeta> {
    let mut cur = 4usize;
    let level = read_u32(bytes, &mut cur)?;
    let shard_id = read_u32(bytes, &mut cur)?;
    let epoch = read_u64(bytes, &mut cur)?;
    let segment_seq = read_u64(bytes, &mut cur)?;
    let mut segment_id = [0u8; 16];
    segment_id.copy_from_slice(read_bytes(bytes, &mut cur, 16)?);
    let file_len = read_u64(bytes, &mut cur)?;
    let path_len = read_u16(bytes, &mut cur)? as usize;
    let path = read_bytes(bytes, &mut cur, path_len)?;
    let relative_path = std::str::from_utf8(path)
        .map_err(|e| StorageError::ManifestRecordInvalid { msg: e.to_string() })?
        .to_string();
    let created_at_unix_ns = read_u64(bytes, &mut cur)?;
    let sealed_at_unix_ns = read_u64(bytes, &mut cur)?;
    let toc_offset = read_u64(bytes, &mut cur)?;
    let toc_len = read_u64(bytes, &mut cur)?;
    let toc_entry_count = read_u64(bytes, &mut cur)?;
    let min_stream_hash = read_u64(bytes, &mut cur)?;
    let min_seq = read_u64(bytes, &mut cur)?;
    let max_stream_hash = read_u64(bytes, &mut cur)?;
    let max_seq = read_u64(bytes, &mut cur)?;
    let mut segment_hash = [0u8; 32];
    segment_hash.copy_from_slice(read_bytes(bytes, &mut cur, 32)?);

    Ok(SegmentMeta {
        level,
        shard_id,
        epoch,
        segment_seq,
        segment_id: SegmentId(segment_id),
        relative_path,
        file_len,
        created_at_unix_ns,
        sealed_at_unix_ns,
        toc_offset,
        toc_len,
        toc_entry_count,
        min_stream_hash,
        min_seq,
        max_stream_hash,
        max_seq,
        segment_hash,
    })
}

pub fn encode_manifest_add_segment_v1(seg: &SegmentMeta) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    out.push(MANIFEST_RECORD_TYPE_ADD_SEGMENT_V1); // record_type
    out.push(1u8); // record_version
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&seg.level.to_le_bytes());
    out.extend_from_slice(&seg.shard_id.to_le_bytes());
    out.extend_from_slice(&seg.epoch.to_le_bytes());
    out.extend_from_slice(&seg.segment_seq.to_le_bytes());
    out.extend_from_slice(&seg.segment_id.0);
    out.extend_from_slice(&seg.file_len.to_le_bytes());
    if seg.relative_path.len() > u16::MAX as usize {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "path too long".to_string(),
        });
    }
    out.extend_from_slice(&(seg.relative_path.len() as u16).to_le_bytes());
    out.extend_from_slice(seg.relative_path.as_bytes());
    out.extend_from_slice(&seg.created_at_unix_ns.to_le_bytes());
    out.extend_from_slice(&seg.sealed_at_unix_ns.to_le_bytes());
    out.extend_from_slice(&seg.toc_offset.to_le_bytes());
    out.extend_from_slice(&seg.toc_len.to_le_bytes());
    out.extend_from_slice(&seg.toc_entry_count.to_le_bytes());
    out.extend_from_slice(&seg.min_stream_hash.to_le_bytes());
    out.extend_from_slice(&seg.min_seq.to_le_bytes());
    out.extend_from_slice(&seg.max_stream_hash.to_le_bytes());
    out.extend_from_slice(&seg.max_seq.to_le_bytes());
    out.extend_from_slice(&seg.segment_hash);
    Ok(out)
}

fn parse_add_dir_run_v1(bytes: &[u8]) -> Result<DirRunMeta> {
    let mut cur = 4usize;
    let level = read_u32(bytes, &mut cur)?;
    let _shard_id = read_u32(bytes, &mut cur)?;
    let _epoch = read_u64(bytes, &mut cur)?;
    let run_id = read_u64(bytes, &mut cur)?;
    let file_len = read_u64(bytes, &mut cur)?;
    let path_len = read_u16(bytes, &mut cur)? as usize;
    let path = read_bytes(bytes, &mut cur, path_len)?;
    let relative_path = std::str::from_utf8(path)
        .map_err(|e| StorageError::ManifestRecordInvalid { msg: e.to_string() })?
        .to_string();
    let created_at_unix_ns = read_u64(bytes, &mut cur)?;
    let record_count = read_u64(bytes, &mut cur)?;

    Ok(DirRunMeta {
        key: DirRunKey { level, run_id },
        relative_path,
        file_len,
        created_at_unix_ns,
        record_count,
    })
}

fn parse_remove_dir_run_v1(bytes: &[u8]) -> Result<DirRunKey> {
    let mut cur = 4usize;
    let level = read_u32(bytes, &mut cur)?;
    let run_id = read_u64(bytes, &mut cur)?;
    Ok(DirRunKey { level, run_id })
}

fn parse_stream_meta_update_v1(bytes: &[u8]) -> Result<StreamMetaUpdateV1> {
    let mut cur = 4usize;
    let stream_hash = read_u64(bytes, &mut cur)?;
    let min_live_seq = read_u64(bytes, &mut cur)?;
    let tombstone_seq = read_u64(bytes, &mut cur)?;
    let gen = read_u64(bytes, &mut cur)?;
    Ok(StreamMetaUpdateV1 {
        stream_hash,
        min_live_seq,
        tombstone_seq,
        gen,
    })
}

fn encode_manifest_add_dir_run_v1(shard_id: u32, epoch: u64, run: &DirRunMeta) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    out.push(MANIFEST_RECORD_TYPE_ADD_DIR_RUN_V1); // record_type
    out.push(1u8); // record_version
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&run.key.level.to_le_bytes());
    out.extend_from_slice(&shard_id.to_le_bytes());
    out.extend_from_slice(&epoch.to_le_bytes());
    out.extend_from_slice(&run.key.run_id.to_le_bytes());
    out.extend_from_slice(&run.file_len.to_le_bytes());
    if run.relative_path.len() > u16::MAX as usize {
        return Err(StorageError::ManifestRecordInvalid {
            msg: "dir run path too long".to_string(),
        });
    }
    out.extend_from_slice(&(run.relative_path.len() as u16).to_le_bytes());
    out.extend_from_slice(run.relative_path.as_bytes());
    out.extend_from_slice(&run.created_at_unix_ns.to_le_bytes());
    out.extend_from_slice(&run.record_count.to_le_bytes());
    Ok(out)
}

fn encode_manifest_remove_dir_run_v1(key: DirRunKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    out.push(MANIFEST_RECORD_TYPE_REMOVE_DIR_RUN_V1); // record_type
    out.push(1u8); // record_version
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&key.level.to_le_bytes());
    out.extend_from_slice(&key.run_id.to_le_bytes());
    out
}

fn encode_manifest_stream_meta_update_v1(upd: StreamMetaUpdateV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(MANIFEST_RECORD_TYPE_STREAM_META_UPDATE_V1); // record_type
    out.push(1u8); // record_version
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&upd.stream_hash.to_le_bytes());
    out.extend_from_slice(&upd.min_live_seq.to_le_bytes());
    out.extend_from_slice(&upd.tombstone_seq.to_le_bytes());
    out.extend_from_slice(&upd.gen.to_le_bytes());
    out
}

/// Write bytes to a file at a specific offset using positional write.
fn write_at_file(file: &File, offset: u64, data: &[u8]) -> Result<()> {
    let mut written = 0usize;
    while written < data.len() {
        let n = {
            #[cfg(unix)]
            {
                std::os::unix::fs::FileExt::write_at(file, &data[written..], offset + written as u64)
                    .map_err(io_err)?
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
fn read_blocks_cpu(
    file: &File,
    blocks: &[BlockMetaV1],
    block_ids: &[u32],
) -> Result<Vec<Option<Vec<u8>>>> {
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
        let b = blocks
            .get(idx)
            .ok_or_else(|| StorageError::ManifestRecordInvalid {
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
                cur.parts
                    .push((b.block_id, rel_off, disk_len, compressed_len));
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
        let block =
            blocks
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
        let end_in_block =
            start_in_block
                .checked_add(frame_len)
                .ok_or(StorageError::ManifestRecordInvalid {
                    msg: "frame slice overflow".to_string(),
                })?;
        if end_in_block > block.uncompressed_len as usize {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "frame points outside codec=none block".to_string(),
            });
        }
        let file_off = block.file_offset.checked_add(start_in_block as u64).ok_or(
            StorageError::ManifestRecordInvalid {
                msg: "frame file offset overflow".to_string(),
            },
        )?;
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

fn failpoint_active(name: &str) -> bool {
    std::env::var("CORECRUX_STORAGE_FAILPOINT")
        .ok()
        .map(|v| v == name)
        .unwrap_or(false)
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
    let header = decode_canonical_header_bytes_v1(canonical_bytes).map_err(|e| {
        StorageError::ManifestRecordInvalid {
            msg: format!("failed to parse stored canonical header bytes: {e}"),
        }
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
    let rel = ti.toc_sorted_idx[start..end]
        .partition_point(|&idx| ti.toc_by_offset[idx as usize].seq < from_seq_inclusive);
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
    let rel = ti.toc_sorted_idx[start..end]
        .partition_point(|&idx| ti.toc_by_offset[idx as usize].seq < min_seq_inclusive);
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
        cur = cur.checked_add(b.uncompressed_len as u64).ok_or(
            StorageError::ManifestRecordInvalid {
                msg: "block logical offset overflow".to_string(),
            },
        )?;
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
            let end = pos.checked_add(COMMIT_FRAME_LEN_V1).ok_or(
                StorageError::ManifestRecordInvalid {
                    msg: "commit frame length overflow in block".to_string(),
                },
            )?;
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

        let end = pos
            .checked_add(frame_len)
            .ok_or(StorageError::ManifestRecordInvalid {
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
        let meta = blocks
            .get(idx)
            .ok_or_else(|| StorageError::ManifestRecordInvalid {
                msg: "block meta missing".to_string(),
            })?;
        let disk_end =
            rel_off
                .checked_add(*disk_len)
                .ok_or(StorageError::ManifestRecordInvalid {
                    msg: "block slice overflow".to_string(),
                })?;
        if disk_end > buf.len() {
            return Err(StorageError::ManifestRecordInvalid {
                msg: "block slice out of bounds".to_string(),
            });
        }

        let comp_end =
            rel_off
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
                let out = lz4_flex::block::decompress(compressed, want).map_err(|e| {
                    StorageError::ManifestRecordInvalid {
                        msg: format!("block lz4 decompress error: {e}"),
                    }
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
            let end = part.rel_off.checked_add(part.frame_len).ok_or(
                StorageError::ManifestRecordInvalid {
                    msg: "frame window slice overflow".to_string(),
                },
            )?;
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
        let mid = (lo + hi) / 2;
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
            let mid = (lo + hi) / 2;
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
            let mid = (lo + hi) / 2;
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
    let end = cur
        .checked_add(2)
        .ok_or_else(|| StorageError::ManifestRecordInvalid {
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
    let end = cur
        .checked_add(4)
        .ok_or_else(|| StorageError::ManifestRecordInvalid {
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
    let end = cur
        .checked_add(8)
        .ok_or_else(|| StorageError::ManifestRecordInvalid {
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

// ---------------------------------------------------------------------------
// CoreCrux v5: .ccxi companion index builder (called at seal time)
// ---------------------------------------------------------------------------

/// Build a `.ccxi` companion inverted index from a sealed segment's record area.
///
/// Iterates all frames in the segment, decodes each frame to extract the payload,
/// tokenizes the payload text, and feeds it to [`CcxiBuilder`]. The resulting
/// `.ccxi` file is written atomically alongside the `.ccxseg` file.
///
/// Non-fatal: returns `Err` on failure but the sealed segment remains valid.
fn build_ccxi_companion(
    shard_dir: &Path,
    shard_id: u32,
    epoch: u64,
    segment_seq: u64,
    segment_id: &corecrux_segment::SegmentId,
    record_area: &[u8],
    metas: &[corecrux_segment::FrameMetaV1],
) -> Result<()> {
    use corecrux_index::CcxiBuilder;

    let mut builder = CcxiBuilder::new(shard_id, segment_seq, epoch);
    let mut indexed_count = 0u32;

    for (doc_id, meta) in metas.iter().enumerate() {
        let off = meta.record_off as usize;
        let end = off + meta.frame_len as usize;
        if end > record_area.len() {
            continue; // skip malformed frame
        }
        let frame_bytes = &record_area[off..end];

        // Decode frame to extract payload bytes.
        // Frame layout: magic(4) + ver(2) + header_len(2) + payload_len(4) + header + payload + crc(4)
        if frame_bytes.len() < 12 {
            continue;
        }
        let header_len = u16::from_le_bytes([frame_bytes[6], frame_bytes[7]]) as usize;
        let payload_len = u32::from_le_bytes([
            frame_bytes[8], frame_bytes[9], frame_bytes[10], frame_bytes[11],
        ]) as usize;
        let payload_start = 12 + header_len;
        let payload_end = payload_start + payload_len;
        if payload_end > frame_bytes.len() {
            continue;
        }
        let payload = &frame_bytes[payload_start..payload_end];

        // Attempt to interpret payload as UTF-8 text for indexing.
        // Binary/CBOR payloads are silently skipped (non-indexable).
        let text = match std::str::from_utf8(payload) {
            Ok(t) if !t.is_empty() => t,
            _ => continue,
        };

        // Extract tenant_id from frame header, hash it for .ccxi tenant filter.
        // This ensures query-time xxh64(tenant_id) matches the stored lo16 bits.
        let header_bytes = &frame_bytes[12..12 + header_len];
        let tenant_hash = match corecrux_frame::decode_canonical_header_bytes_v1(header_bytes) {
            Ok(hdr) => xxhash_rust::xxh64::xxh64(hdr.tenant_id.as_bytes(), 0),
            Err(_) => meta.stream_hash, // fallback to stream_hash if header decode fails
        };

        builder.add_document(doc_id as u32, text, meta.record_off, tenant_hash);
        indexed_count += 1;
    }

    if indexed_count == 0 {
        tracing::debug!(segment_seq, "ccxi-companion-skip-no-indexable-frames");
        return Ok(());
    }

    let ccxi_bytes = builder.build();
    let ccxi_hash = *blake3::hash(&ccxi_bytes).as_bytes();

    // Atomic write: tmp → final
    let id_hex = hex16(&segment_id.0);
    let tmp_path = shard_dir.join(format!("tmp/seg-{segment_seq:020}-{id_hex}.ccxi.partial"));
    let final_path = shard_dir.join(format!("segments/seg-{segment_seq:020}-{id_hex}.ccxi"));

    std::fs::write(&tmp_path, &ccxi_bytes).map_err(io_err)?;
    std::fs::rename(&tmp_path, &final_path).map_err(io_err)?;
    fsync_dir(&shard_dir.join("segments"))?;

    tracing::info!(
        segment_seq,
        indexed_count,
        vocab_size = builder.vocab_size(),
        ccxi_bytes = ccxi_bytes.len(),
        ccxi_hash = %format!("{:016x}{:016x}", u64::from_le_bytes(ccxi_hash[0..8].try_into().unwrap()), u64::from_le_bytes(ccxi_hash[8..16].try_into().unwrap())),
        "ccxi-companion-built"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // ── ShardPaths::for_root ────────────────────────────────────────

    #[test]
    fn shard_paths_for_root_layout() {
        let paths = ShardPaths::for_root(Path::new("/data"), 7);
        assert_eq!(paths.shard_dir, PathBuf::from("/data/shard-0007"));
        assert_eq!(paths.lock_path, PathBuf::from("/data/shard-0007/LOCK"));
        assert_eq!(paths.manifest_path, PathBuf::from("/data/shard-0007/MANIFEST"));
        assert_eq!(paths.segments_dir, PathBuf::from("/data/shard-0007/segments"));
        assert_eq!(paths.directory_dir, PathBuf::from("/data/shard-0007/directory"));
        assert_eq!(paths.projections_dir, PathBuf::from("/data/shard-0007/projections"));
        assert_eq!(paths.tmp_dir, PathBuf::from("/data/shard-0007/tmp"));
        assert_eq!(paths.quarantine_dir, PathBuf::from("/data/shard-0007/quarantine"));
    }

    #[test]
    fn shard_paths_for_root_zero_padded() {
        let paths = ShardPaths::for_root(Path::new("/x"), 1);
        assert_eq!(paths.shard_dir, PathBuf::from("/x/shard-0001"));
        let paths = ShardPaths::for_root(Path::new("/x"), 9999);
        assert_eq!(paths.shard_dir, PathBuf::from("/x/shard-9999"));
    }

    // ── ShardStorageOptions defaults ─────────────────────────────────

    #[test]
    fn shard_storage_options_default_values() {
        let opts = ShardStorageOptions::default();
        assert_eq!(opts.max_events_per_batch, 1024);
        assert_eq!(opts.max_batch_bytes, 16 * 1024 * 1024);
        assert_eq!(opts.max_event_id_bytes, 128);
        assert_eq!(opts.idem_hot_capacity_entries, 100_000);
        assert_eq!(opts.event_id_hash_prefix_len, 16);
        assert_eq!(opts.cold_scan_max_segments, 256);
        assert_eq!(opts.head_max_record_bytes, 0);
        assert_eq!(opts.record_block_codec, corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1);
        assert!(!opts.enable_directory_compaction);
        assert_eq!(opts.dir_l0_max_runs, 8);
        assert_eq!(opts.append_group_commit_batches, 1);
        assert_eq!(opts.append_group_commit_max_delay_ms, 0);
        assert!(!opts.build_ccxi);
    }

    // ── Manifest constants ──────────────────────────────────────────

    #[test]
    fn manifest_constants_stable() {
        assert_eq!(MANIFEST_MAGIC_CCMF, 0x464D_4343);
        assert_eq!(MANIFEST_VERSION_V1, 1);
        assert_eq!(MANIFEST_HEADER_LEN, 256);
    }

    // ── Dirrun constants ────────────────────────────────────────────

    #[test]
    fn dirrun_constants_stable() {
        assert_eq!(DIRRUN_MAGIC_CCDR, 0x5244_4343);
        assert_eq!(DIRRUN_VERSION_V1, 1);
        assert_eq!(DIRRUN_HEADER_LEN, 4096);
        assert_eq!(DIRRUN_PARTITIONS_V1, 256);
        assert_eq!(DIRRUN_PARTITION_TABLE_OFFSET_V1, 64);
        assert_eq!(DIRRUN_PARTITION_ENTRY_LEN_V1, 12);
        assert_eq!(DIREXTENT_LEN_V1, 32);
    }

    // ── encode/decode dir extent roundtrip ──────────────────────────

    #[test]
    fn encode_decode_dir_extent_roundtrip() {
        let extent = DirExtentV1 {
            stream_hash: 0xDEAD_BEEF_1234_5678,
            min_seq: 10,
            max_seq: 99,
            segment_seq: 42,
        };
        let bytes = encode_dir_extent_v1(extent);
        assert_eq!(bytes.len(), DIREXTENT_LEN_V1);
        let decoded = decode_dir_extent_v1(&bytes).unwrap();
        assert_eq!(decoded, extent);
    }

    // ── encode/decode dir run roundtrip ─────────────────────────────

    #[test]
    fn encode_decode_dir_run_empty_roundtrip() {
        let bytes = encode_dir_run_v1(12345, &[]).unwrap();
        let decoded = decode_dir_run_v1(&bytes).unwrap();
        assert_eq!(decoded.created_at_unix_ns, 12345);
        assert_eq!(decoded.record_count, 0);
        for part in &decoded.partitions {
            assert!(part.is_empty());
        }
    }

    #[test]
    fn encode_decode_dir_run_with_extents_roundtrip() {
        let extents = vec![
            DirExtentV1 { stream_hash: 0x00, min_seq: 1, max_seq: 5, segment_seq: 1 },
            DirExtentV1 { stream_hash: 0x01, min_seq: 1, max_seq: 3, segment_seq: 2 },
            DirExtentV1 { stream_hash: 0xFF, min_seq: 10, max_seq: 20, segment_seq: 3 },
        ];
        let bytes = encode_dir_run_v1(99999, &extents).unwrap();
        let decoded = decode_dir_run_v1(&bytes).unwrap();
        assert_eq!(decoded.created_at_unix_ns, 99999);
        assert_eq!(decoded.record_count, 3);
    }

    #[test]
    fn encode_dir_run_deduplicates_same_key_extents() {
        let extents = vec![
            DirExtentV1 { stream_hash: 0x42, min_seq: 10, max_seq: 20, segment_seq: 1 },
            DirExtentV1 { stream_hash: 0x42, min_seq: 5, max_seq: 25, segment_seq: 1 },
        ];
        let bytes = encode_dir_run_v1(0, &extents).unwrap();
        let decoded = decode_dir_run_v1(&bytes).unwrap();
        // Should deduplicate: merged min_seq=5, max_seq=25
        assert_eq!(decoded.record_count, 1);
        let partition = dirrun_partition_v1(0x42);
        assert_eq!(decoded.partitions[partition].len(), 1);
        assert_eq!(decoded.partitions[partition][0].min_seq, 5);
        assert_eq!(decoded.partitions[partition][0].max_seq, 25);
    }

    // ── dirrun_partition_v1 masks low 8 bits ────────────────────────

    #[test]
    fn dirrun_partition_v1_range() {
        // All values should be in 0..256
        for i in 0u64..=512 {
            let p = dirrun_partition_v1(i);
            assert!(p < DIRRUN_PARTITIONS_V1, "partition {p} out of range for hash {i}");
        }
        assert_eq!(dirrun_partition_v1(0x00), 0);
        assert_eq!(dirrun_partition_v1(0xFF), 255);
        assert_eq!(dirrun_partition_v1(0x100), 0);
        assert_eq!(dirrun_partition_v1(0x1FF), 255);
    }

    // ── dir_extent_key_cmp ordering ─────────────────────────────────

    #[test]
    fn dir_extent_key_cmp_equal_elements() {
        let a = DirExtentV1 { stream_hash: 1, min_seq: 0, max_seq: 0, segment_seq: 5 };
        let b = DirExtentV1 { stream_hash: 1, min_seq: 99, max_seq: 99, segment_seq: 5 };
        assert_eq!(dir_extent_key_cmp(&a, &b), std::cmp::Ordering::Equal);
    }

    #[test]
    fn dir_extent_key_cmp_different_stream_hash() {
        let a = DirExtentV1 { stream_hash: 1, min_seq: 0, max_seq: 0, segment_seq: 1 };
        let b = DirExtentV1 { stream_hash: 2, min_seq: 0, max_seq: 0, segment_seq: 1 };
        assert_eq!(dir_extent_key_cmp(&a, &b), std::cmp::Ordering::Less);
        assert_eq!(dir_extent_key_cmp(&b, &a), std::cmp::Ordering::Greater);
    }

    // ── should_skip_startup_dirrun_bootstrap ─────────────────────────

    #[test]
    fn should_skip_startup_dirrun_bootstrap_cases() {
        assert!(!should_skip_startup_dirrun_bootstrap(false, 0));
        assert!(!should_skip_startup_dirrun_bootstrap(false, 999_999));
        assert!(!should_skip_startup_dirrun_bootstrap(true, 0));
        assert!(!should_skip_startup_dirrun_bootstrap(true, STARTUP_DIRRUN_BOOTSTRAP_SEGMENT_LIMIT_V1));
        assert!(should_skip_startup_dirrun_bootstrap(true, STARTUP_DIRRUN_BOOTSTRAP_SEGMENT_LIMIT_V1 + 1));
    }

    // ── StorageError display strings ────────────────────────────────

    #[test]
    fn storage_error_display_variants() {
        let err = StorageError::InvalidArgument {
            code: "BAD".to_string(),
            msg: "bad input".to_string(),
        };
        assert!(err.to_string().contains("invalid argument"));
        assert!(err.to_string().contains("BAD"));

        let err = StorageError::FailedPrecondition {
            code: "PRE".to_string(),
            msg: "not ready".to_string(),
        };
        assert!(err.to_string().contains("failed precondition"));

        let err = StorageError::ResourceExhausted {
            code: "RES".to_string(),
            msg: "too many".to_string(),
            retry_after_ms: Some(1000),
        };
        assert!(err.to_string().contains("resource exhausted"));

        let err = StorageError::Internal { msg: "oops".to_string() };
        assert!(err.to_string().contains("internal error"));

        let err = StorageError::Io { msg: "disk fail".to_string() };
        assert!(err.to_string().contains("io error"));

        let err = StorageError::ManifestHeaderInvalid { msg: "corrupt".to_string() };
        assert!(err.to_string().contains("manifest header invalid"));

        let err = StorageError::ManifestCrcMismatch { expected: 0xAA, actual: 0xBB };
        assert!(err.to_string().contains("manifest crc mismatch"));

        let err = StorageError::ManifestRecordCrcMismatch { expected: 0xCC, actual: 0xDD };
        assert!(err.to_string().contains("manifest record crc mismatch"));

        let err = StorageError::ManifestRecordInvalid { msg: "bad record".to_string() };
        assert!(err.to_string().contains("manifest record invalid"));
    }

    // ── SegmentMeta fields ──────────────────────────────────────────

    #[test]
    fn segment_meta_clone_and_debug() {
        let meta = SegmentMeta {
            level: 0,
            shard_id: 1,
            epoch: 1,
            segment_seq: 42,
            segment_id: corecrux_segment::SegmentId([0u8; 16]),
            relative_path: "segments/seg.ccxseg".to_string(),
            file_len: 1024,
            created_at_unix_ns: 100,
            sealed_at_unix_ns: 200,
            toc_offset: 512,
            toc_len: 64,
            toc_entry_count: 5,
            min_stream_hash: 0,
            min_seq: 1,
            max_stream_hash: u64::MAX,
            max_seq: 10,
            segment_hash: [0xAA; 32],
        };
        let cloned = meta.clone();
        assert_eq!(cloned.segment_seq, 42);
        assert_eq!(cloned.file_len, 1024);
        let dbg = format!("{:?}", meta);
        assert!(dbg.contains("segment_seq: 42"));
    }

    // ── parse_segment_seq_from_filename ──────────────────────────────

    #[test]
    fn parse_segment_seq_from_filename_various_valid() {
        // Format: seg-<20-digit-padded-seq>-<hash>.ccxseg
        assert_eq!(parse_segment_seq_from_filename("seg-00000000000000000042-abcd.ccxseg"), Some(42));
        assert_eq!(parse_segment_seq_from_filename("seg-00000000000000000001-efgh.ccxseg"), Some(1));
        assert_eq!(parse_segment_seq_from_filename("seg-00000000000000999999-ijkl.ccxseg"), Some(999999));
    }

    #[test]
    fn parse_segment_seq_from_filename_various_invalid() {
        assert_eq!(parse_segment_seq_from_filename("not-a-segment.txt"), None);
        assert_eq!(parse_segment_seq_from_filename("abc.ccxseg"), None);
        assert_eq!(parse_segment_seq_from_filename(""), None);
        assert_eq!(parse_segment_seq_from_filename("seg-short-hash.ccxseg"), None);
    }

    // ── deterministic_segment_id ────────────────────────────────────

    #[test]
    fn deterministic_segment_id_is_deterministic() {
        let a = deterministic_segment_id(1, 42);
        let b = deterministic_segment_id(1, 42);
        assert_eq!(a.0, b.0);
    }

    #[test]
    fn deterministic_segment_id_differs_for_different_inputs() {
        let a = deterministic_segment_id(1, 42);
        let b = deterministic_segment_id(1, 43);
        assert_ne!(a.0, b.0);
        let c = deterministic_segment_id(2, 42);
        assert_ne!(a.0, c.0);
    }

    // ── rejected_outcome ────────────────────────────────────────────

    #[test]
    fn rejected_outcome_fields() {
        let o = rejected_outcome("DUP", "duplicate event".to_string());
        assert_eq!(o.status, AppendStatus::Rejected);
        assert_eq!(o.error_code.as_deref(), Some("DUP"));
        assert_eq!(o.error_message.as_deref(), Some("duplicate event"));
        assert_eq!(o.seq, 0);
    }

    // ── compute_write_confirmation_receipt_hash ─────────────────────

    #[test]
    fn write_confirmation_receipt_hash_is_deterministic() {
        let frames = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let h1 = compute_write_confirmation_receipt_hash(&frames);
        let h2 = compute_write_confirmation_receipt_hash(&frames);
        assert_eq!(h1, h2);
    }

    #[test]
    fn write_confirmation_receipt_hash_varies_with_input() {
        let a = compute_write_confirmation_receipt_hash(&[vec![1, 2, 3]]);
        let b = compute_write_confirmation_receipt_hash(&[vec![4, 5, 6]]);
        assert_ne!(a, b);
    }

    // ── SealResultV1 ────────────────────────────────────────────────

    #[test]
    fn seal_result_v1_fields() {
        let r = SealResultV1 {
            sealed: true,
            segment_seq: Some(42),
            frame_count: Some(100),
            seal_duration_secs: 0.5,
        };
        assert!(r.sealed);
        assert_eq!(r.segment_seq, Some(42));

        let not_sealed = SealResultV1 {
            sealed: false,
            segment_seq: None,
            frame_count: None,
            seal_duration_secs: 0.0,
        };
        assert!(!not_sealed.sealed);
    }

    // ── ManifestSegmentCatalogV1 ────────────────────────────────────

    #[test]
    fn manifest_segment_catalog_v1_empty() {
        let cat = ManifestSegmentCatalogV1 {
            shard_id: 1,
            epoch: 1,
            manifest_end: 256,
            segments: Vec::new(),
        };
        assert!(cat.segments.is_empty());
        assert_eq!(cat.manifest_end, 256);
    }

    // ── decode_dir_run_v1 bad version ──────────────────────────────

    #[test]
    fn decode_dir_run_v1_bad_version() {
        let mut bytes = encode_dir_run_v1(0, &[]).unwrap();
        // Corrupt version at offset 4..6
        bytes[4] = 99;
        bytes[5] = 0;
        let err = decode_dir_run_v1(&bytes).unwrap_err();
        assert!(err.to_string().contains("bad version"));
    }

    #[test]
    fn decode_dir_run_v1_bad_partitions() {
        let mut bytes = encode_dir_run_v1(0, &[]).unwrap();
        // Corrupt partitions at offset 12..16
        bytes[12] = 1;
        bytes[13] = 0;
        bytes[14] = 0;
        bytes[15] = 0;
        // Also fix the CRC
        let crc = crc32c::crc32c(&bytes[..DIRRUN_HEADER_LEN - 4]);
        bytes[DIRRUN_HEADER_LEN - 4..DIRRUN_HEADER_LEN].copy_from_slice(&crc.to_le_bytes());
        let err = decode_dir_run_v1(&bytes).unwrap_err();
        assert!(err.to_string().contains("bad partitions"));
    }

    fn open_test_storage(options: ShardStorageOptions) -> (tempfile::TempDir, ShardStorage) {
        let dir = tempfile::tempdir().unwrap();

        let storage =
            ShardStorage::open(dir.path(), 1, 1, options).unwrap();

        (dir, storage)
    }

    #[test]
    fn startup_dirrun_bootstrap_skip_gate_is_stable() {
        let _g = TEST_LOCK.lock().unwrap();

        assert!(!should_skip_startup_dirrun_bootstrap(false, 10_000));
        assert!(!should_skip_startup_dirrun_bootstrap(
            true,
            STARTUP_DIRRUN_BOOTSTRAP_SEGMENT_LIMIT_V1
        ));
        assert!(should_skip_startup_dirrun_bootstrap(
            true,
            STARTUP_DIRRUN_BOOTSTRAP_SEGMENT_LIMIT_V1 + 1
        ));
    }

    #[allow(clippy::too_many_arguments)]
    fn build_test_replicated_segment(
        shard_id: u32,
        epoch: u64,
        segment_seq: u64,
        tenant_id: &str,
        stream_type: &str,
        stream_id: &str,
        seq: u64,
        event_id: &str,
        payload: &[u8],
    ) -> corecrux_segment::SegmentBuildOutput {
        let payload_hash = compute_payload_hash(payload);
        let canonical = CanonicalHeaderV1 {
            tenant_id: tenant_id.to_string(),
            stream_id: stream_id.to_string(),
            stream_type: stream_type.to_string(),
            seq,
            event_id: event_id.to_string(),
            occurred_at: "2026-01-01T00:00:00Z".to_string(),
            ingested_at: "2026-01-01T00:00:00Z".to_string(),
            event_type: "evt".to_string(),
            content_type: "application/octet-stream".to_string(),
            payload_len: payload.len() as u32,
            payload_hash,
        };
        let canonical_bytes = canonical_header_bytes_v1(&canonical);
        let header_hash = compute_header_hash(&canonical_bytes);
        let mut header_bytes = canonical_bytes.clone();
        header_bytes.extend_from_slice(&header_hash);
        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id)
            .expect("stream hash");

        let frame = corecrux_segment::FrameInput {
            stream_hash,
            seq,
            event_id,
            header_hash,
            payload_hash,
            header_bytes: &header_bytes,
            payload_bytes: payload,
        };

        corecrux_segment::build_segment_v1_with_block_codec(
            shard_id,
            epoch,
            segment_seq,
            deterministic_segment_id(epoch, segment_seq),
            1,
            2,
            corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1,
            &[frame],
        )
        .expect("build segment")
    }


    #[test]
    fn apply_replicated_segment_roundtrip_and_idempotent() {
        let _g = TEST_LOCK.lock().unwrap();
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "tenant-a";
        let stream_type = "artifact";
        let stream_id = "1";
        let payload = b"replicated-payload".to_vec();
        let seg = build_test_replicated_segment(
            1,
            1,
            77,
            tenant_id,
            stream_type,
            stream_id,
            1,
            "evt-1",
            &payload,
        );

        let applied = storage
            .apply_replicated_segment_v1(&seg.bytes)
            .expect("apply replicated segment");
        assert!(applied.applied);
        assert_eq!(applied.segment_seq, 77);

        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();
        let got = storage
            .read_stream(tenant_id, stream_type, stream_id, stream_hash, 0, 32)
            .expect("read stream");
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].seq, 1);
        assert_eq!(got[0].event_id, "evt-1");
        assert_eq!(got[0].payload, payload);

        let second = storage
            .apply_replicated_segment_v1(&seg.bytes)
            .expect("re-apply replicated segment");
        assert!(!second.applied);
        assert_eq!(second.segment_seq, 77);
    }

    #[test]
    fn apply_replicated_segment_conflict_rejected() {
        let _g = TEST_LOCK.lock().unwrap();
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "tenant-a";
        let stream_type = "artifact";
        let stream_id = "1";

        let seg_ok = build_test_replicated_segment(
            1,
            1,
            88,
            tenant_id,
            stream_type,
            stream_id,
            1,
            "evt-1",
            b"payload-a",
        );
        storage
            .apply_replicated_segment_v1(&seg_ok.bytes)
            .expect("initial apply");

        let seg_conflict = build_test_replicated_segment(
            1,
            1,
            88, // same segment_seq, different contents -> conflict
            tenant_id,
            stream_type,
            stream_id,
            1,
            "evt-1",
            b"payload-b",
        );
        let err = storage
            .apply_replicated_segment_v1(&seg_conflict.bytes)
            .expect_err("expected conflict");
        match err {
            StorageError::FailedPrecondition { code, .. } => {
                assert_eq!(code, "REPLICATION_SEGMENT_CONFLICT");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn manifest_tail_truncation_ignores_partial_record() {
        let _g = TEST_LOCK.lock().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("MANIFEST");

        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        let hdr = encode_manifest_header_v1(0, 1, 123).unwrap();
        f.write_all(&hdr).unwrap();

        let seg = SegmentMeta {
            level: 0,
            shard_id: 0,
            epoch: 1,
            segment_seq: 1,
            segment_id: SegmentId([1u8; 16]),
            relative_path:
                "segments/seg-00000000000000000001-00000000000000000000000000000000.ccxseg"
                    .to_string(),
            file_len: 999,
            created_at_unix_ns: 1,
            sealed_at_unix_ns: 2,
            toc_offset: 4096,
            toc_len: 128,
            toc_entry_count: 0,
            min_stream_hash: 0,
            min_seq: 0,
            max_stream_hash: 0,
            max_seq: 0,
            segment_hash: [2u8; 32],
        };
        let rec = encode_manifest_add_segment_v1(&seg).unwrap();
        let framed = frame_manifest_record(&rec);
        f.write_all(&framed).unwrap();

        // Write a partial trailing record (len+crc but missing body).
        f.write_all(&1234u32.to_le_bytes()).unwrap();
        f.write_all(&0u32.to_le_bytes()).unwrap();
        f.sync_all().unwrap();

        let (segs, end) = load_manifest_records(&mut f).unwrap();
        assert_eq!(segs.segments_by_seq.len(), 1);
        assert_eq!(end, (MANIFEST_HEADER_LEN + framed.len()) as u64);

        let len = f.metadata().unwrap().len();
        assert_eq!(len, end);
    }

    #[test]
    fn dirrun_encode_decode_roundtrip_v1() {
        let extents = vec![
            DirExtentV1 {
                stream_hash: 0x11,
                min_seq: 10,
                max_seq: 20,
                segment_seq: 7,
            },
            DirExtentV1 {
                stream_hash: 0x22,
                min_seq: 1,
                max_seq: 1,
                segment_seq: 8,
            },
            // Duplicate key should be merged deterministically.
            DirExtentV1 {
                stream_hash: 0x11,
                min_seq: 9,
                max_seq: 21,
                segment_seq: 7,
            },
        ];
        let bytes = encode_dir_run_v1(123, &extents).unwrap();
        let decoded = decode_dir_run_v1(&bytes).unwrap();
        assert_eq!(decoded.file_len as usize, bytes.len());
        assert_eq!(decoded.record_count, 2);

        // CRC mismatch should be detected.
        let mut bad = bytes.clone();
        bad[0] ^= 0xFF;
        assert!(decode_dir_run_v1(&bad).is_err());
    }

    #[test]
    fn directory_compaction_keeps_l0_runs_bounded() {
        let _g = TEST_LOCK.lock().unwrap();

        let opts = ShardStorageOptions {
            enable_directory_compaction: true,
            dir_l0_max_runs: 2,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        for i in 0..10u32 {
            let eid = format!("e{i}");
            let payload = format!("p{i}").into_bytes();
            let events = [AppendEventInput {
                event_id: &eid,
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: payload.as_slice(),
            }];

            storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    &events,
                )
                .unwrap();
            storage.compact_directory_until_within_limits().unwrap();
        }

        let l0 = storage
            .dir_runs
            .values()
            .filter(|r| r.key.level == 0)
            .count();
        assert!(l0 <= 2, "expected l0<=2, got {l0}");

        let got = storage
            .read_stream(tenant_id, stream_type, stream_id, stream_hash, 1, 0)
            .unwrap();
        assert_eq!(got.len(), 10);
    }

    #[test]
    #[ignore]
    fn soak_ingest_under_compaction_pressure() {
        let _g = TEST_LOCK.lock().unwrap();

        let secs: u64 = std::env::var("CORECRUX_SOAK_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(2);
        let max_events: u64 = std::env::var("CORECRUX_SOAK_MAX_EVENTS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(50_000);
        let streams: u64 = std::env::var("CORECRUX_SOAK_STREAMS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(16);
        let log_every: u64 = std::env::var("CORECRUX_SOAK_LOG_EVERY")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5_000);
        let eq_check_every: u64 = std::env::var("CORECRUX_SOAK_EQ_CHECK_EVERY")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1_024);

        let opts = ShardStorageOptions {
            enable_directory_compaction: true,
            dir_l0_max_runs: 8,
            ..Default::default()
        };
        let l0_max = opts.dir_l0_max_runs;
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";

        let start = std::time::Instant::now();
        let mut i: u64 = 0;
        let mut compaction_events_seen: u64 = 0;
        let mut eq_checks: u64 = 0;
        let mut eq_mismatches: u64 = 0;

        let tail_digest = |storage: &ShardStorage, stream_id: &str, stream_hash: u64| -> String {
            let events = storage
                .read_tail(tenant_id, stream_type, stream_id, stream_hash, 16)
                .unwrap_or_default();
            let mut h = blake3::Hasher::new();
            for e in &events {
                h.update(&e.seq.to_le_bytes());
                h.update(&(e.event_id.len() as u32).to_le_bytes());
                h.update(e.event_id.as_bytes());
                let ph = blake3::hash(&e.payload);
                h.update(ph.as_bytes());
                h.update(&e.location.shard_id.to_le_bytes());
                h.update(&e.location.epoch.to_le_bytes());
                h.update(&e.location.segment_seq.to_le_bytes());
                h.update(&e.location.offset.to_le_bytes());
            }
            h.finalize().to_hex().to_string()
        };
        while start.elapsed() < std::time::Duration::from_secs(secs) && i < max_events {
            let stream_id = format!("stream-{}", i % streams);
            let stream_hash =
                corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, &stream_id).unwrap();

            let eid = format!("e{i}");
            let mut payload = vec![0u8; 32];
            payload[0..8].copy_from_slice(&i.to_le_bytes());
            let events = [AppendEventInput {
                event_id: &eid,
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: payload.as_slice(),
            }];

            storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    &stream_id,
                    "2026-02-06T00:00:01Z",
                    &events,
                )
                .unwrap();
            let do_eq = eq_check_every > 0 && i > 0 && i.is_multiple_of(eq_check_every);
            let before = if do_eq {
                Some(tail_digest(&storage, &stream_id, stream_hash))
            } else {
                None
            };
            let compaction_events = storage.compact_directory_until_within_limits().unwrap();
            compaction_events_seen += compaction_events.len() as u64;
            if do_eq && !compaction_events.is_empty() {
                let after = tail_digest(&storage, &stream_id, stream_hash);
                eq_checks += 1;
                if before.expect("before digest") != after {
                    eq_mismatches += 1;
                }
            }
            i += 1;

            if log_every > 0 && i.is_multiple_of(log_every) {
                eprintln!(
                    "soak progress: events={} elapsed_s={:.1}",
                    i,
                    start.elapsed().as_secs_f64()
                );
            }
        }

        let l0 = storage
            .dir_runs
            .values()
            .filter(|r| r.key.level == 0)
            .count();
        assert!(l0 <= l0_max, "expected l0<={l0_max}, got {l0}");

        // Quick correctness smoke: at least one stream has readable tail bytes.
        let stream_id = "stream-0";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();
        let got = storage
            .read_tail(tenant_id, stream_type, stream_id, stream_hash, 16)
            .unwrap();
        assert!(!got.is_empty());

        // Checkpoint correctness sampling: install a cut (min_live_seq) and verify reads filter.
        let mut checkpoint_ok = true;
        let mut checkpoint_min_live_seq = 0u64;
        let events = storage
            .read_stream(tenant_id, stream_type, stream_id, stream_hash, 1, 0)
            .unwrap();
        let checkpoint_stream_len = events.len();
        if events.len() >= 4 {
            checkpoint_min_live_seq = events[events.len() / 2].seq;
            storage
                .update_stream_meta(stream_hash, checkpoint_min_live_seq, 0)
                .unwrap();
            storage.compact_directory_until_within_limits().unwrap();
            let after = storage
                .read_stream(tenant_id, stream_type, stream_id, stream_hash, 1, 0)
                .unwrap();
            checkpoint_ok = after.iter().all(|e| e.seq >= checkpoint_min_live_seq);
        }
        assert!(checkpoint_ok, "checkpoint sampling failed");
        assert_eq!(eq_mismatches, 0, "compaction equivalence mismatches");

        // Emit a stable JSON summary when run with `-- --nocapture` so soak workflows can archive it.
        eprintln!(
            "{}",
            serde_json::json!({
              "ok": true,
              "duration_secs": (start.elapsed().as_secs_f64() * 100.0).round() / 100.0,
              "events_appended": i,
              "streams": streams,
              "dir_l0_max_runs": l0_max,
              "dir_l0_runs_observed": l0,
              "compaction_events_seen": compaction_events_seen,
              "compaction_equivalence_checks": eq_checks,
              "compaction_equivalence_mismatches": eq_mismatches,
              "checkpoint_sampling_ok": checkpoint_ok,
              "checkpoint_sampling_min_live_seq": checkpoint_min_live_seq,
              "checkpoint_sampling_stream_events": checkpoint_stream_len,
            })
        );
    }

    #[test]
    fn tombstone_and_checkpoint_filter_reads_deterministically() {
        let _g = TEST_LOCK.lock().unwrap();

        let opts = ShardStorageOptions {
            enable_directory_compaction: true,
            dir_l0_max_runs: 2,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        // 6 segments, 1 event each (seq 1..=6).
        for i in 0..6u32 {
            let eid = format!("e{i}");
            let payload = b"x";
            let events = [AppendEventInput {
                event_id: &eid,
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: payload,
            }];
            storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    &events,
                )
                .unwrap();
        }
        storage.compact_directory_until_within_limits().unwrap();

        // Tombstone hides seq < 5; checkpoint hides seq < 6; combined cut=6.
        storage.update_stream_meta(stream_hash, 6, 5).unwrap();
        storage.compact_directory_until_within_limits().unwrap();

        let got = storage
            .read_stream(tenant_id, stream_type, stream_id, stream_hash, 1, 0)
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].seq, 6);
    }

    #[test]
    fn tombstoned_stream_rejects_appends() {
        let _g = TEST_LOCK.lock().unwrap();

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        storage.update_stream_meta(stream_hash, 0, 5).unwrap();

        let ev = AppendEventInput {
            event_id: "e1",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"hello",
        };

        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                std::slice::from_ref(&ev),
            )
            .unwrap_err();
        match err {
            StorageError::FailedPrecondition { code, .. } => {
                assert_eq!(code, "STREAM_TOMBSTONED");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn stream_meta_updates_are_monotonic() {
        let _g = TEST_LOCK.lock().unwrap();

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        storage.update_stream_meta(stream_hash, 10, 20).unwrap();

        let err = storage.update_stream_meta(stream_hash, 9, 0).unwrap_err();
        assert!(matches!(
            err,
            StorageError::InvalidArgument { code, .. } if code == "CHECKPOINT_NON_MONOTONIC"
        ));

        let err = storage.update_stream_meta(stream_hash, 0, 19).unwrap_err();
        assert!(matches!(
            err,
            StorageError::InvalidArgument { code, .. } if code == "TOMBSTONE_NON_MONOTONIC"
        ));
    }

    #[test]
    fn append_batch_dedupes_within_batch() {
        let _g = TEST_LOCK.lock().unwrap();

        let (dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let payload = b"hello";
        let events = [
            AppendEventInput {
                event_id: "e1",
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: payload,
            },
            AppendEventInput {
                event_id: "e1",
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: payload,
            },
        ];

        let outcomes = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &events,
            )
            .unwrap();
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].status, AppendStatus::Appended);
        assert_eq!(outcomes[1].status, AppendStatus::DuplicateInBatch);
        assert_eq!(outcomes[0].seq, outcomes[1].seq);
        assert_eq!(outcomes[0].location, outcomes[1].location);

        assert_eq!(storage.segments_in_order.len(), 1);
        let seg = &storage.segments_in_order[0];
        let bytes = std::fs::read(storage.paths.shard_dir.join(&seg.relative_path)).unwrap();
        let (_h, _toc_h, entries, _f) = decode_segment_v1(&bytes).unwrap();
        assert_eq!(entries.len(), 1);

        drop(dir);
    }

    #[test]
    fn append_batch_with_stats_reports_stage_timings() {
        let _g = TEST_LOCK.lock().unwrap();

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let events = [AppendEventInput {
            event_id: "e1",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"hello",
        }];

        let (outcomes, stats) = storage
            .append_batch_with_stats(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &events,
            )
            .unwrap();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].status, AppendStatus::Appended);

        assert!(stats.total_nanos > 0);
        assert!(stats.total_nanos >= stats.idempotency_check_nanos);
        assert!(stats.total_nanos >= stats.index_update_nanos);
        assert!(stats.total_nanos >= stats.io_write_nanos);
        assert!(stats.total_nanos >= stats.fence_wait_nanos);
        assert!(stats.total_nanos >= stats.fence_fsync_nanos);
        assert!(stats.total_nanos >= stats.fence_nanos);
        assert!(
            stats.fence_nanos
                >= stats
                    .fence_wait_nanos
                    .saturating_add(stats.fence_fsync_nanos)
        );
        assert!(stats.io_write_nanos.saturating_add(stats.fence_nanos) > 0);
    }

    #[test]
    fn append_batch_with_stats_reports_write_confirmation_hash() {
        let _g = TEST_LOCK.lock().unwrap();

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let events = [
            AppendEventInput {
                event_id: "e1",
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: b"hello",
            },
            AppendEventInput {
                event_id: "e2",
                occurred_at: "2026-02-06T00:00:02Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: b"world",
            },
        ];

        let (outcomes, stats) = storage
            .append_batch_with_stats(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:03Z",
                &events,
            )
            .unwrap();
        let confirmation = stats.write_confirmation.expect("write confirmation");

        let mut hasher = blake3::Hasher::new();
        for outcome in outcomes.iter() {
            let loc = outcome.location.expect("appended frame location");
            let frame = storage
                .read_frame_bytes(loc.segment_seq, loc.offset)
                .expect("read stored frame bytes");
            hasher.update(blake3::hash(&frame).as_bytes());
        }

        assert_eq!(
            confirmation.commit_seq,
            outcomes.last().expect("outcome").seq
        );
        assert_eq!(
            confirmation.segment_id,
            outcomes
                .last()
                .and_then(|outcome| outcome.location.map(|loc| loc.segment_seq))
                .expect("segment id")
        );
        assert_eq!(confirmation.receipt_hash, *hasher.finalize().as_bytes());
    }

    #[test]
    fn load_manifest_segment_catalog_returns_sorted_segments() {
        let _g = TEST_LOCK.lock().unwrap();

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());
        let tenant_id = "tenant-a";
        let stream_type = "answers";
        let stream_id = "stream-a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();
        let occurred_at = "2026-03-07T00:00:00Z";
        let events = [
            AppendEventInput {
                event_id: "evt-1",
                occurred_at,
                event_type: "evt",
                content_type: "application/json",
                payload_bytes: br#"{"n":1}"#,
            },
            AppendEventInput {
                event_id: "evt-2",
                occurred_at,
                event_type: "evt",
                content_type: "application/json",
                payload_bytes: br#"{"n":2}"#,
            },
        ];
        storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                occurred_at,
                &events,
            )
            .expect("append batch");

        let catalog =
            load_manifest_segment_catalog(&storage.paths.shard_dir).expect("manifest catalog");
        assert_eq!(catalog.shard_id, 1);
        assert_eq!(catalog.epoch, 1);
        assert!(!catalog.segments.is_empty());
        assert!(catalog.manifest_end >= MANIFEST_HEADER_LEN as u64);
        assert!(catalog
            .segments
            .windows(2)
            .all(|window| window[0].segment_seq <= window[1].segment_seq));
    }

    #[test]
    fn duplicate_committed_returns_existing_seq_and_location() {
        let _g = TEST_LOCK.lock().unwrap();

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let ev = AppendEventInput {
            event_id: "e1",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"hello",
        };

        let first = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                std::slice::from_ref(&ev),
            )
            .unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].status, AppendStatus::Appended);
        assert_eq!(storage.segments_in_order.len(), 1);

        let second = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                std::slice::from_ref(&ev),
            )
            .unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].status, AppendStatus::DuplicateCommitted);
        assert_eq!(second[0].seq, first[0].seq);
        assert_eq!(second[0].location, first[0].location);
        assert_eq!(storage.segments_in_order.len(), 1);
    }

    #[test]
    fn hash_collision_does_not_cause_false_dedupe() {
        let _g = TEST_LOCK.lock().unwrap();

        let opts = ShardStorageOptions {
            event_id_hash_prefix_len: 1,
            idem_hot_capacity_entries: 1024,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        // Find two different eventIds that collide on the first hash byte.
        let (a, b) = {
            let mut seen: HashMap<u8, String> = HashMap::new();
            let mut out: Option<(String, String)> = None;
            for i in 0..10_000u32 {
                let s = format!("ev-{i}");
                let h = blake3::hash(s.as_bytes());
                let k = h.as_bytes()[0];
                if let Some(prev) = seen.insert(k, s.clone()) {
                    out = Some((prev, s));
                    break;
                }
            }
            out.expect("expected to find a collision")
        };

        let ev_a = AppendEventInput {
            event_id: &a,
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"a",
        };
        let ev_b = AppendEventInput {
            event_id: &b,
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"b",
        };

        let r1 = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                std::slice::from_ref(&ev_a),
            )
            .unwrap();
        assert_eq!(r1[0].status, AppendStatus::Appended);

        let r2 = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[ev_b],
            )
            .unwrap();
        assert_eq!(r2[0].status, AppendStatus::Appended);
        assert_ne!(r2[0].seq, r1[0].seq);

        // Retry A must still be treated as committed duplicate.
        let r3 = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:03Z",
                &[ev_a],
            )
            .unwrap();
        assert_eq!(r3[0].status, AppendStatus::DuplicateCommitted);
        assert_eq!(r3[0].seq, r1[0].seq);
    }

    #[test]
    fn eviction_falls_back_to_cold_scan_for_correctness() {
        let _g = TEST_LOCK.lock().unwrap();

        let opts = ShardStorageOptions {
            idem_hot_capacity_entries: 1,
            cold_scan_max_segments: 32,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let ev_a = AppendEventInput {
            event_id: "a",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"a",
        };
        let ev_b = AppendEventInput {
            event_id: "b",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"b",
        };

        let r1 = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                std::slice::from_ref(&ev_a),
            )
            .unwrap();
        assert_eq!(r1[0].status, AppendStatus::Appended);
        assert_eq!(storage.segments_in_order.len(), 1);

        let _ = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[ev_b],
            )
            .unwrap();
        assert_eq!(storage.segments_in_order.len(), 2);

        // A was evicted from hot cache but must still dedupe via cold scan.
        let r3 = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:03Z",
                &[ev_a],
            )
            .unwrap();
        assert_eq!(r3[0].status, AppendStatus::DuplicateCommitted);
        assert_eq!(r3[0].seq, r1[0].seq);
        assert_eq!(storage.segments_in_order.len(), 2);
    }

    #[test]
    fn event_id_too_large_is_rejected_and_does_not_consume_seq() {
        let _g = TEST_LOCK.lock().unwrap();

        let opts = ShardStorageOptions {
            max_event_id_bytes: 3,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let oversize = AppendEventInput {
            event_id: "abcd",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"x",
        };
        let r1 = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[oversize],
            )
            .unwrap();
        assert_eq!(r1[0].status, AppendStatus::Rejected);
        assert_eq!(r1[0].seq, 0);
        assert_eq!(r1[0].error_code.as_deref(), Some("EVENT_ID_TOO_LARGE"));
        assert_eq!(storage.segments_in_order.len(), 0);

        let ok = AppendEventInput {
            event_id: "ok",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"y",
        };
        let r2 = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[ok],
            )
            .unwrap();
        assert_eq!(r2[0].status, AppendStatus::Appended);
        assert_eq!(r2[0].seq, 1);
    }

    #[test]
    fn backpressure_max_events_rejects_entire_request() {
        let _g = TEST_LOCK.lock().unwrap();

        let opts = ShardStorageOptions {
            max_events_per_batch: 1,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let events = [
            AppendEventInput {
                event_id: "a",
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: b"a",
            },
            AppendEventInput {
                event_id: "b",
                occurred_at: "2026-02-06T00:00:00Z",
                event_type: "t",
                content_type: "application/octet-stream",
                payload_bytes: b"b",
            },
        ];

        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &events,
            )
            .unwrap_err();
        match err {
            StorageError::ResourceExhausted { code, .. } => {
                assert_eq!(code, "BACKPRESSURE_MAX_EVENTS");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn crash_after_manifest_commit_is_idempotent_on_restart() {
        let _g = TEST_LOCK.lock().unwrap();

        let opts = ShardStorageOptions {
            idem_hot_capacity_entries: 4,
            ..Default::default()
        };
        let (dir, mut storage) = open_test_storage(opts.clone());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        std::env::set_var("CORECRUX_STORAGE_FAILPOINT", "after_manifest_commit");
        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap_err();
        assert!(format!("{err}").contains("after_manifest_commit"));
        std::env::remove_var("CORECRUX_STORAGE_FAILPOINT");
        drop(storage);

        let mut reopened =
            ShardStorage::open(dir.path(), 1, 1, opts).unwrap();

        let retry = reopened
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].status, AppendStatus::DuplicateCommitted);
        assert_eq!(retry[0].seq, 1);
        assert!(retry[0].location.is_some());
    }

    #[test]
    fn crash_after_manifest_commit_keeps_replay_digest_stable_after_retry() {
        let _g = TEST_LOCK.lock().unwrap();

        let opts = ShardStorageOptions {
            idem_hot_capacity_entries: 4,
            ..Default::default()
        };
        let (dir, mut storage) = open_test_storage(opts.clone());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        std::env::set_var("CORECRUX_STORAGE_FAILPOINT", "after_manifest_commit");
        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap_err();
        assert!(format!("{err}").contains("after_manifest_commit"));
        std::env::remove_var("CORECRUX_STORAGE_FAILPOINT");
        drop(storage);

        let mut reopened =
            ShardStorage::open(dir.path(), 1, 1, opts).unwrap();

        let (before_frames, before_end) = reopened.replay_from(None, 0).unwrap();
        assert_eq!(before_end, None);
        let (before_total, before_digest) = replay_digest(&before_frames);
        assert_eq!(before_total, 1);

        let retry = reopened
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].status, AppendStatus::DuplicateCommitted);

        let (after_frames, after_end) = reopened.replay_from(None, 0).unwrap();
        assert_eq!(after_end, None);
        let (after_total, after_digest) = replay_digest(&after_frames);
        assert_eq!(after_total, 1);
        assert_eq!(before_digest, after_digest);
    }

    #[test]
    fn crash_after_rename_before_manifest_quarantines_orphan_and_avoids_seq_reuse() {
        let _g = TEST_LOCK.lock().unwrap();

        let opts = ShardStorageOptions::default();
        let (dir, mut storage) = open_test_storage(opts.clone());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        std::env::set_var("CORECRUX_STORAGE_FAILPOINT", "after_rename_before_manifest");
        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap_err();
        assert!(format!("{err}").contains("after_rename_before_manifest"));
        std::env::remove_var("CORECRUX_STORAGE_FAILPOINT");
        drop(storage);

        let mut reopened =
            ShardStorage::open(dir.path(), 1, 1, opts).unwrap();

        assert_eq!(reopened.segments_in_order.len(), 0);
        let out = reopened
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[AppendEventInput {
                    event_id: "e2",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"y",
                }],
            )
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].status, AppendStatus::Appended);
        assert_eq!(reopened.segments_in_order.len(), 1);
        assert_eq!(reopened.segments_in_order[0].segment_seq, 2);
    }

    #[test]
    fn commit_frame_roundtrip_and_crc_validation() {
        let _g = TEST_LOCK.lock().unwrap();

        let frame = encode_commit_frame_v1(7, 42, 8192, 0xAABB_CCDD);
        let parsed = decode_commit_frame_v1(&frame).expect("commit frame decode");
        assert_eq!(parsed.commit_id, 7);
        assert_eq!(parsed.commit_seq, 42);
        assert_eq!(parsed.commit_offset, 8192);
        assert_eq!(parsed.crc32c_committed_region, 0xAABB_CCDD);

        let mut corrupted = frame;
        corrupted[16] ^= 0xFF; // mutate commit_seq field
        let err = decode_commit_frame_v1(&corrupted).expect_err("crc must fail");
        assert!(
            format!("{err}").contains("commit frame header crc mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn head_recovery_truncates_tail_to_last_commit_frame_boundary() {
        let _g = TEST_LOCK.lock().unwrap();

        let opts = ShardStorageOptions {
            head_max_record_bytes: 1024 * 1024,
            ..Default::default()
        };
        let (dir, mut storage) = open_test_storage(opts.clone());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let out = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].status, AppendStatus::Appended);

        let rel = storage
            .head
            .as_ref()
            .expect("head exists")
            .relative_path
            .clone();
        let head_path = storage.paths.shard_dir.join(rel);
        let committed_len = std::fs::metadata(&head_path).unwrap().len();
        {
            let mut f = OpenOptions::new().append(true).open(&head_path).unwrap();
            f.write_all(b"garbage-tail-without-commit-frame").unwrap();
            f.sync_all().unwrap();
        }
        let len_with_garbage = std::fs::metadata(&head_path).unwrap().len();
        assert!(len_with_garbage > committed_len);
        drop(storage);

        let reopened =
            ShardStorage::open(dir.path(), 1, 1, opts).unwrap();

        let len_recovered = std::fs::metadata(&head_path).unwrap().len();
        assert_eq!(len_recovered, committed_len);
        let tail = reopened
            .read_tail(tenant_id, stream_type, stream_id, stream_hash, 8)
            .unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].event_id, "e1");
    }

    #[test]
    fn crash_after_head_commit_fence_before_ack_is_idempotent_after_restart() {
        let _g = TEST_LOCK.lock().unwrap();

        let opts = ShardStorageOptions {
            head_max_record_bytes: 1024 * 1024,
            idem_hot_capacity_entries: 4,
            ..Default::default()
        };
        let (dir, mut storage) = open_test_storage(opts.clone());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        std::env::set_var(
            "CORECRUX_STORAGE_FAILPOINT",
            "after_head_commit_fence_before_ack",
        );
        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap_err();
        assert!(format!("{err}").contains("after_head_commit_fence_before_ack"));
        std::env::remove_var("CORECRUX_STORAGE_FAILPOINT");
        drop(storage);

        let mut reopened =
            ShardStorage::open(dir.path(), 1, 1, opts).unwrap();

        let retry = reopened
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:02Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap();
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].status, AppendStatus::DuplicateCommitted);
        assert_eq!(retry[0].seq, 1);
        assert!(retry[0].location.is_some());
    }

    #[test]
    fn read_tail_returns_last_n_across_segments() {
        let _g = TEST_LOCK.lock().unwrap();

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        for i in 1..=5 {
            let event_id = format!("e{i}");
            let out = storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    std::slice::from_ref(&AppendEventInput {
                        event_id: &event_id,
                        occurred_at: "2026-02-06T00:00:00Z",
                        event_type: "t",
                        content_type: "application/octet-stream",
                        payload_bytes: b"x",
                    }),
                )
                .unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].status, AppendStatus::Appended);
        }

        let tail = storage
            .read_tail(tenant_id, stream_type, stream_id, stream_hash, 3)
            .unwrap();
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].seq, 3);
        assert_eq!(tail[1].seq, 4);
        assert_eq!(tail[2].seq, 5);
        assert_eq!(tail[0].event_id, "e3");
        assert_eq!(tail[1].event_id, "e4");
        assert_eq!(tail[2].event_id, "e5");
    }

    #[test]
    fn read_stream_range_respects_from_seq_and_limit() {
        let _g = TEST_LOCK.lock().unwrap();

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        for i in 1..=5 {
            let event_id = format!("e{i}");
            let _ = storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    std::slice::from_ref(&AppendEventInput {
                        event_id: &event_id,
                        occurred_at: "2026-02-06T00:00:00Z",
                        event_type: "t",
                        content_type: "application/octet-stream",
                        payload_bytes: b"x",
                    }),
                )
                .unwrap();
        }

        let got = storage
            .read_stream(tenant_id, stream_type, stream_id, stream_hash, 4, 2)
            .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].seq, 4);
        assert_eq!(got[1].seq, 5);
        assert_eq!(got[0].event_id, "e4");
        assert_eq!(got[1].event_id, "e5");
    }

    #[test]
    fn replay_from_cursor_continues_deterministically() {
        let _g = TEST_LOCK.lock().unwrap();

        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        for i in 1..=3 {
            let event_id = format!("e{i}");
            let _ = storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    std::slice::from_ref(&AppendEventInput {
                        event_id: &event_id,
                        occurred_at: "2026-02-06T00:00:00Z",
                        event_type: "t",
                        content_type: "application/octet-stream",
                        payload_bytes: b"x",
                    }),
                )
                .unwrap();
        }

        let (all, end) = storage.replay_from(None, 0).unwrap();
        assert_eq!(end, None);
        assert_eq!(all.len(), 3);

        let (part, cursor) = storage.replay_from(None, 1).unwrap();
        assert_eq!(part.len(), 1);
        let cursor = cursor.expect("cursor after partial replay");
        let (rest, end2) = storage.replay_from(Some(cursor), 0).unwrap();
        assert_eq!(end2, None);

        let mut combined: Vec<(FrameLocation, Vec<u8>)> = Vec::new();
        combined.extend_from_slice(&part);
        combined.extend_from_slice(&rest);

        assert_eq!(combined.len(), all.len());
        for (a, b) in combined.iter().zip(all.iter()) {
            assert_eq!(a.0, b.0);
            assert_eq!(a.1, b.1);
        }
    }

    #[test]
    fn head_segment_serves_reads_before_seal() {
        let _g = TEST_LOCK.lock().unwrap();

        let opts = ShardStorageOptions {
            head_max_record_bytes: 1024 * 1024, // large enough to avoid sealing during test
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let mut locs: Vec<FrameLocation> = Vec::new();
        for i in 1..=5 {
            let event_id = format!("e{i}");
            let out = storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    std::slice::from_ref(&AppendEventInput {
                        event_id: &event_id,
                        occurred_at: "2026-02-06T00:00:00Z",
                        event_type: "t",
                        content_type: "application/octet-stream",
                        payload_bytes: b"x",
                    }),
                )
                .unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].status, AppendStatus::Appended);
            locs.push(out[0].location.expect("location"));
        }

        // Head mode should avoid sealing a segment per append.
        assert_eq!(storage.segments_in_order.len(), 0);
        assert!(storage.head.is_some());

        // Locations should all refer to the same head segment seq.
        for w in locs.windows(2) {
            assert_eq!(w[0].segment_seq, w[1].segment_seq);
        }

        // Tail and range must include head bytes.
        let tail = storage
            .read_tail(tenant_id, stream_type, stream_id, stream_hash, 3)
            .unwrap();
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].seq, 3);
        assert_eq!(tail[1].seq, 4);
        assert_eq!(tail[2].seq, 5);

        let got = storage
            .read_stream(tenant_id, stream_type, stream_id, stream_hash, 4, 2)
            .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].seq, 4);
        assert_eq!(got[1].seq, 5);

        // replay_from must include head frames.
        let (frames, end) = storage.replay_from(None, 0).unwrap();
        assert_eq!(end, None);
        assert_eq!(frames.len(), 5);

        // read_frame_bytes must work against head locations.
        let frame = storage
            .read_frame_bytes(locs[0].segment_seq, locs[0].offset)
            .unwrap();
        let _ = decode_frame_v1(&frame).unwrap();
    }

    #[test]
    fn head_segment_is_sealed_on_restart_when_disabled() {
        let _g = TEST_LOCK.lock().unwrap();

        let opts = ShardStorageOptions {
            head_max_record_bytes: 1024 * 1024,
            ..Default::default()
        };
        let (dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let _ = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &[AppendEventInput {
                    event_id: "e1",
                    occurred_at: "2026-02-06T00:00:00Z",
                    event_type: "t",
                    content_type: "application/octet-stream",
                    payload_bytes: b"x",
                }],
            )
            .unwrap();
        drop(storage);

        // Reopen with head disabled; startup should seal any head file.

        let reopened = ShardStorage::open(
            dir.path(),
            1,
            1,
            ShardStorageOptions::default(),
        )
        .unwrap();

        assert_eq!(reopened.segments_in_order.len(), 1);
        assert!(reopened.head.is_none());
        let tail = reopened
            .read_tail(tenant_id, stream_type, stream_id, stream_hash, 1)
            .unwrap();
        assert_eq!(tail.len(), 1);
        assert_eq!(tail[0].event_id, "e1");

        drop(dir);
    }

    #[test]
    fn read_blocks_supports_lz4_codec() {
        let _g = TEST_LOCK.lock().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("block.bin");

        let uncompressed = b"hello world hello world hello world";
        let compressed = lz4_flex::block::compress(uncompressed);

        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        f.write_all(&compressed).unwrap();
        f.sync_all().unwrap();

        let meta = BlockMetaV1 {
            block_id: 0,
            codec: 1,
            file_offset: 0,
            compressed_len: compressed.len() as u32,
            physical_len: compressed.len() as u32,
            uncompressed_len: uncompressed.len() as u32,
            crc32c: crc32c::crc32c(uncompressed),
            bloom: [0u8; corecrux_segment::BLOOM_BYTES_PER_BLOCK_V1],
        };


        let blocks = read_blocks_cpu(
            &f,
            std::slice::from_ref(&meta),
            &[0],
        )
        .unwrap();
        let got = blocks[0].as_ref().unwrap();
        assert_eq!(got, uncompressed);
    }

    #[test]
    fn sealed_segments_with_lz4_blocks_support_tail_and_range_reads() {
        let _g = TEST_LOCK.lock().unwrap();

        let opts = ShardStorageOptions {
            record_block_codec: corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1,
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        for i in 1..=5 {
            let event_id = format!("e{i}");
            let out = storage
                .append_batch(
                    stream_hash,
                    0,
                    tenant_id,
                    stream_type,
                    stream_id,
                    "2026-02-06T00:00:01Z",
                    std::slice::from_ref(&AppendEventInput {
                        event_id: &event_id,
                        occurred_at: "2026-02-06T00:00:00Z",
                        event_type: "t",
                        content_type: "application/octet-stream",
                        payload_bytes: b"x",
                    }),
                )
                .unwrap();
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].status, AppendStatus::Appended);
        }

        // Assert codec=1 was actually used for sealed blocks.
        for ti in storage.segment_trailers_by_seq.values() {
            assert!(!ti.blocks.is_empty());
            for b in &ti.blocks {
                assert_eq!(b.codec, corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1);
            }
        }

        let tail = storage
            .read_tail(tenant_id, stream_type, stream_id, stream_hash, 3)
            .unwrap();
        assert_eq!(tail.len(), 3);
        assert_eq!(tail[0].seq, 3);
        assert_eq!(tail[1].seq, 4);
        assert_eq!(tail[2].seq, 5);

        let got = storage
            .read_stream(tenant_id, stream_type, stream_id, stream_hash, 4, 2)
            .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].seq, 4);
        assert_eq!(got[1].seq, 5);

        let (frames, end) = storage.replay_from(None, 0).unwrap();
        assert_eq!(end, None);
        assert_eq!(frames.len(), 5);
        for (_loc, bytes) in frames {
            let _ = decode_frame_v1(&bytes).unwrap();
        }
    }

    fn repo_root() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .expect("repo root")
    }

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    struct ExpectedReplayDigest {
        total_frames: u64,
        digest_blake3: String,
    }

    fn replay_digest(frames: &ReplayFrames) -> (u64, String) {
        let mut hasher = blake3::Hasher::new();
        for (loc, frame) in frames {
            let decoded = decode_frame_v1(frame).expect("decode frame");
            if decoded.header_bytes.len() < 32 {
                panic!("stored frame header_bytes too small");
            }
            let canonical_len = decoded.header_bytes.len() - 32;
            let canonical_bytes = &decoded.header_bytes[..canonical_len];
            let header_hash = compute_header_hash(canonical_bytes);
            let payload_hash = compute_payload_hash(&decoded.payload_bytes);

            hasher.update(&header_hash);
            hasher.update(&payload_hash);
            hasher.update(&loc.shard_id.to_le_bytes());
            hasher.update(&loc.segment_seq.to_le_bytes());
            hasher.update(&loc.offset.to_le_bytes());
        }
        (frames.len() as u64, hasher.finalize().to_hex().to_string())
    }

    #[test]
    fn replay_golden_segment_fixture_digest_matches_expected() {
        let _g = TEST_LOCK.lock().unwrap();

        let fixture_dir = repo_root().join("tests/fixtures_segments/minimal");
        let fixture_seg = fixture_dir.join("minimal.ccxseg");
        let expected_path = fixture_dir.join("expected_replay_digest.json");

        let seg_bytes = std::fs::read(&fixture_seg).expect("read fixture segment");
        let (_h, _toc_h, _entries, footer) =
            corecrux_segment::decode_segment_v1(&seg_bytes).expect("decode segment");

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();

        let shard_id = footer.shard_id;
        let epoch = footer.epoch;
        let paths = ShardPaths::for_root(root, shard_id);
        std::fs::create_dir_all(&paths.segments_dir).expect("create segments dir");

        let rel = "segments/minimal.ccxseg";
        let dst = paths.shard_dir.join(rel);
        std::fs::copy(&fixture_seg, &dst).expect("copy fixture segment");

        // Write MANIFEST referencing the fixture segment (Phase 2/3 layout).
        let mut mf = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&paths.manifest_path)
            .expect("create MANIFEST");
        let hdr = encode_manifest_header_v1(shard_id, epoch, 123).expect("manifest header");
        mf.write_all(&hdr).expect("write manifest header");

        let seg_meta = SegmentMeta {
            level: 0,
            shard_id,
            epoch,
            segment_seq: footer.segment_seq,
            segment_id: footer.segment_id,
            relative_path: rel.to_string(),
            file_len: footer.file_len,
            created_at_unix_ns: footer.created_at_unix_ns,
            sealed_at_unix_ns: footer.sealed_at_unix_ns,
            toc_offset: footer.toc_offset,
            toc_len: footer.toc_len,
            toc_entry_count: footer.toc_entry_count,
            min_stream_hash: footer.min_stream_hash,
            min_seq: footer.min_seq,
            max_stream_hash: footer.max_stream_hash,
            max_seq: footer.max_seq,
            segment_hash: footer.segment_hash,
        };
        let rec = encode_manifest_add_segment_v1(&seg_meta).expect("encode add segment");
        let framed = frame_manifest_record(&rec);
        mf.write_all(&framed).expect("write manifest record");
        mf.sync_all().expect("sync manifest");

        // Now open storage and replay on the same path (GPU-first in CUDA builds).

        let storage = ShardStorage::open(
            root,
            shard_id,
            epoch,
            ShardStorageOptions::default(),
        )
        .expect("open storage");

        let (frames, end) = storage.replay_from(None, 0).expect("replay fixture");
        assert_eq!(end, None);
        let (total_frames, digest_blake3) = replay_digest(&frames);

        let expected_str = match std::fs::read_to_string(&expected_path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let json = serde_json::to_string_pretty(&ExpectedReplayDigest {
                    total_frames,
                    digest_blake3: digest_blake3.clone(),
                })
                .expect("serialize expected digest");
                panic!(
                    "expected digest missing at {}. Create it with:\n{}",
                    expected_path.display(),
                    json
                );
            }
            Err(e) => panic!("read expected digest: {e}"),
        };
        let expected: ExpectedReplayDigest =
            serde_json::from_str(&expected_str).expect("parse expected digest");

        assert_eq!(total_frames, expected.total_frames);
        assert_eq!(digest_blake3, expected.digest_blake3);
    }

    #[test]
    fn integrity_scan_golden_segment_fixture_matches_expected_frame_count() {
        let _g = TEST_LOCK.lock().unwrap();

        let fixture_dir = repo_root().join("tests/fixtures_segments/minimal");
        let fixture_seg = fixture_dir.join("minimal.ccxseg");
        let expected_path = fixture_dir.join("expected_replay_digest.json");

        let seg_bytes = std::fs::read(&fixture_seg).expect("read fixture segment");
        let (_h, _toc_h, _entries, footer) =
            corecrux_segment::decode_segment_v1(&seg_bytes).expect("decode segment");

        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();

        let shard_id = footer.shard_id;
        let epoch = footer.epoch;
        let paths = ShardPaths::for_root(root, shard_id);
        std::fs::create_dir_all(&paths.segments_dir).expect("create segments dir");

        let rel = "segments/minimal.ccxseg";
        let dst = paths.shard_dir.join(rel);
        std::fs::copy(&fixture_seg, &dst).expect("copy fixture segment");

        // Write MANIFEST referencing the fixture segment (Phase 2/3 layout).
        let mut mf = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&paths.manifest_path)
            .expect("create MANIFEST");
        let hdr = encode_manifest_header_v1(shard_id, epoch, 123).expect("manifest header");
        mf.write_all(&hdr).expect("write manifest header");

        let seg_meta = SegmentMeta {
            level: 0,
            shard_id,
            epoch,
            segment_seq: footer.segment_seq,
            segment_id: footer.segment_id,
            relative_path: rel.to_string(),
            file_len: footer.file_len,
            created_at_unix_ns: footer.created_at_unix_ns,
            sealed_at_unix_ns: footer.sealed_at_unix_ns,
            toc_offset: footer.toc_offset,
            toc_len: footer.toc_len,
            toc_entry_count: footer.toc_entry_count,
            min_stream_hash: footer.min_stream_hash,
            min_seq: footer.min_seq,
            max_stream_hash: footer.max_stream_hash,
            max_seq: footer.max_seq,
            segment_hash: footer.segment_hash,
        };
        let rec = encode_manifest_add_segment_v1(&seg_meta).expect("encode add segment");
        let framed = frame_manifest_record(&rec);
        mf.write_all(&framed).expect("write manifest record");
        mf.sync_all().expect("sync manifest");

        let storage = ShardStorage::open(
            root,
            shard_id,
            epoch,
            ShardStorageOptions::default(),
        )
        .expect("open storage");

        let stats = storage
            .integrity_scan_stats_all(8 * 1024 * 1024)
            .expect("integrity scan");

        let expected_str = std::fs::read_to_string(&expected_path).expect("read expected digest");
        let expected: ExpectedReplayDigest =
            serde_json::from_str(&expected_str).expect("parse expected digest");

        assert_eq!(stats.total_frames, expected.total_frames);
    }

    #[test]
    fn tail_and_range_match_cpu_reference_scan_on_interleaved_segments() {
        let _g = TEST_LOCK.lock().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let shard_id = 1u32;
        let epoch = 1u64;
        let paths = ShardPaths::for_root(root, shard_id);
        std::fs::create_dir_all(&paths.segments_dir).unwrap();

        let tenant_id = "t1";
        let stream_type = "s";
        let occurred_at = "2026-02-06T00:00:00Z";
        let ingested_at = "2026-02-06T00:00:01Z";
        let event_type = "t";
        let content_type = "application/octet-stream";

        let streams = ["a", "b", "c"];
        let mut stream_hashes: std::collections::HashMap<&str, u64> =
            std::collections::HashMap::new();
        for s in &streams {
            let h = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, s).unwrap();
            stream_hashes.insert(s, h);
        }

        #[allow(clippy::too_many_arguments)]
        fn build_segment_for_events(
            shard_id: u32,
            epoch: u64,
            segment_seq: u64,
            record_block_codec: u32,
            tenant_id: &str,
            stream_type: &str,
            occurred_at: &str,
            ingested_at: &str,
            event_type: &str,
            content_type: &str,
            events: &[(&str, u64, &str, &'static [u8])], // (stream_id, seq, event_id, payload)
        ) -> corecrux_segment::SegmentBuildOutput {
            use corecrux_frame::{
                canonical_header_bytes_v1, compute_header_hash, compute_payload_hash,
                CanonicalHeaderV1,
            };

            let segment_id = deterministic_segment_id(epoch, segment_seq);
            let created_at = 100 + segment_seq;
            let sealed_at = 200 + segment_seq;

            let n = events.len();
            let mut stream_hashes: Vec<u64> = Vec::with_capacity(n);
            let mut seqs: Vec<u64> = Vec::with_capacity(n);
            let mut event_ids: Vec<String> = Vec::with_capacity(n);
            let mut payload_hashes: Vec<[u8; 32]> = Vec::with_capacity(n);
            let mut header_hashes: Vec<[u8; 32]> = Vec::with_capacity(n);
            let mut payload_bufs: Vec<Vec<u8>> = Vec::with_capacity(n);
            let mut header_bufs: Vec<Vec<u8>> = Vec::with_capacity(n);

            for (stream_id, seq, event_id, payload) in events {
                let stream_hash =
                    corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id)
                        .unwrap();
                stream_hashes.push(stream_hash);
                seqs.push(*seq);
                event_ids.push((*event_id).to_string());
                payload_bufs.push(payload.to_vec());
                let payload_hash = compute_payload_hash(payload_bufs.last().unwrap().as_slice());

                let canonical = CanonicalHeaderV1 {
                    tenant_id: tenant_id.to_string(),
                    stream_id: (*stream_id).to_string(),
                    stream_type: stream_type.to_string(),
                    seq: *seq,
                    event_id: event_ids.last().unwrap().clone(),
                    occurred_at: occurred_at.to_string(),
                    ingested_at: ingested_at.to_string(),
                    event_type: event_type.to_string(),
                    content_type: content_type.to_string(),
                    payload_len: payload.len() as u32,
                    payload_hash,
                };
                let canonical_bytes = canonical_header_bytes_v1(&canonical);
                let header_hash = compute_header_hash(&canonical_bytes);

                let mut hb = Vec::with_capacity(canonical_bytes.len() + 32);
                hb.extend_from_slice(&canonical_bytes);
                hb.extend_from_slice(&header_hash);
                header_bufs.push(hb);

                payload_hashes.push(payload_hash);
                header_hashes.push(header_hash);
            }

            // Build FrameInput after buffers are stable (avoids borrow/realloc hazards).
            let mut frames: Vec<corecrux_segment::FrameInput<'_>> = Vec::with_capacity(n);
            for i in 0..n {
                frames.push(corecrux_segment::FrameInput {
                    stream_hash: stream_hashes[i],
                    seq: seqs[i],
                    event_id: event_ids[i].as_str(),
                    header_hash: header_hashes[i],
                    payload_hash: payload_hashes[i],
                    header_bytes: header_bufs[i].as_slice(),
                    payload_bytes: payload_bufs[i].as_slice(),
                });
            }

            corecrux_segment::build_segment_v1_with_block_codec(
                shard_id,
                epoch,
                segment_seq,
                segment_id,
                created_at,
                sealed_at,
                record_block_codec,
                &frames,
            )
            .unwrap()
        }

        // Two segments with three interleaved streams.
        let seg1 = build_segment_for_events(
            shard_id,
            epoch,
            1,
            corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1,
            tenant_id,
            stream_type,
            occurred_at,
            ingested_at,
            event_type,
            content_type,
            &[
                ("a", 1, "a1", b"x"),
                ("b", 1, "b1", b"y"),
                ("a", 2, "a2", b"z"),
                ("c", 1, "c1", b"q"),
                ("b", 2, "b2", b"w"),
            ],
        );
        let seg2 = build_segment_for_events(
            shard_id,
            epoch,
            2,
            corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1,
            tenant_id,
            stream_type,
            occurred_at,
            ingested_at,
            event_type,
            content_type,
            &[
                ("a", 3, "a3", b"x"),
                ("b", 3, "b3", b"y"),
                ("c", 2, "c2", b"z"),
                ("c", 3, "c3", b"q"),
                ("a", 4, "a4", b"w"),
            ],
        );

        let seg_metas = [
            (1u64, seg1.footer, seg1.bytes),
            (2u64, seg2.footer, seg2.bytes),
        ];

        let mut manifest = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&paths.manifest_path)
            .unwrap();
        let hdr = encode_manifest_header_v1(shard_id, epoch, 123).unwrap();
        manifest.write_all(&hdr).unwrap();

        let mut metas: Vec<SegmentMeta> = Vec::new();
        for (segment_seq, footer, bytes) in seg_metas {
            let segment_id = footer.segment_id;
            let rel = format!(
                "segments/seg-{segment_seq:020}-{}.ccxseg",
                hex16(&segment_id.0)
            );
            let path = paths.shard_dir.join(&rel);
            std::fs::write(&path, &bytes).unwrap();

            let meta = SegmentMeta {
                level: 0,
                shard_id,
                epoch,
                segment_seq,
                segment_id,
                relative_path: rel,
                file_len: footer.file_len,
                created_at_unix_ns: footer.created_at_unix_ns,
                sealed_at_unix_ns: footer.sealed_at_unix_ns,
                toc_offset: footer.toc_offset,
                toc_len: footer.toc_len,
                toc_entry_count: footer.toc_entry_count,
                min_stream_hash: footer.min_stream_hash,
                min_seq: footer.min_seq,
                max_stream_hash: footer.max_stream_hash,
                max_seq: footer.max_seq,
                segment_hash: footer.segment_hash,
            };
            let rec = encode_manifest_add_segment_v1(&meta).unwrap();
            let framed = frame_manifest_record(&rec);
            manifest.write_all(&framed).unwrap();
            metas.push(meta);
        }
        manifest.sync_all().unwrap();

        // Open storage (GPU-first in CUDA builds).
        let storage = ShardStorage::open(
            root,
            shard_id,
            epoch,
            ShardStorageOptions::default(),
        )
        .unwrap();

        // CPU reference scan of the on-disk bytes (ignores directory + TOC sorted index).
        let mut scanned: Vec<(u64, StoredEvent)> = Vec::new();
        for seg in &metas {
            let seg_path = paths.shard_dir.join(&seg.relative_path);
            let bytes = std::fs::read(&seg_path).unwrap();
            let (_h, toc_h, _entries, footer) =
                corecrux_segment::decode_segment_v1(&bytes).unwrap();
            let toc_off = footer.toc_offset as usize;
            let toc_len = footer.toc_len as usize;
            let toc_area = &bytes[toc_off..toc_off + toc_len];
            let ti = corecrux_segment::decode_trailer_index_v1(toc_area, &toc_h)
                .unwrap()
                .expect("trailer index");
            let block_starts = block_logical_starts(&ti.blocks).unwrap();

            // Decompress all blocks once on CPU.
            let mut blocks_uncompressed: Vec<Vec<u8>> = vec![Vec::new(); ti.blocks.len()];
            for b in &ti.blocks {
                let off = b.file_offset as usize;
                let len = b.compressed_len as usize;
                let end = off + len;
                let compressed = &bytes[off..end];
                let mut out = match b.codec {
                    corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1 => {
                        assert_eq!(b.compressed_len, b.uncompressed_len);
                        compressed.to_vec()
                    }
                    corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1 => {
                        let want = b.uncompressed_len as usize;
                        let out = lz4_flex::block::decompress(compressed, want).unwrap();
                        assert_eq!(out.len(), want);
                        out
                    }
                    other => panic!("unsupported codec {other} in fixture"),
                };
                let actual_crc = crc32c::crc32c(&out);
                assert_eq!(actual_crc, b.crc32c);
                blocks_uncompressed[b.block_id as usize].append(&mut out);
            }

            for e in &ti.toc_by_offset {
                let bid = e.block_id as usize;
                let buf = &blocks_uncompressed[bid];
                let start = e.in_block_offset as usize;
                let end = start + (e.frame_len as usize);
                let frame = &buf[start..end];
                let block_start = block_starts[bid];
                let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                    .saturating_add(block_start)
                    .saturating_add(e.in_block_offset as u64);
                let ev = decode_stored_event_from_frame_bytes(
                    seg.shard_id as u64,
                    seg.epoch,
                    seg.segment_seq,
                    frame_off,
                    frame,
                )
                .unwrap();
                scanned.push((e.stream_hash, ev));
            }
        }

        // Compare tail/range against CPU truth for each stream.
        for s in &streams {
            let sh = *stream_hashes.get(s).unwrap();
            let mut truth: Vec<StoredEvent> = scanned
                .iter()
                .filter(|(h, _)| *h == sh)
                .map(|(_, ev)| ev.clone())
                .collect();
            truth.sort_by_key(|e| e.seq);

            let tail = storage.read_tail(tenant_id, stream_type, s, sh, 2).unwrap();
            let want_tail: Vec<StoredEvent> = truth
                .iter()
                .rev()
                .take(2)
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            assert_eq!(tail.len(), want_tail.len());
            for (a, b) in tail.iter().zip(want_tail.iter()) {
                assert_eq!(a.seq, b.seq);
                assert_eq!(a.event_id, b.event_id);
                assert_eq!(a.payload, b.payload);
            }

            let got = storage
                .read_stream(tenant_id, stream_type, s, sh, 2, 10)
                .unwrap();
            let want_range: Vec<StoredEvent> = truth
                .iter()
                .filter(|e| e.seq >= 2)
                .take(10)
                .cloned()
                .collect();
            assert_eq!(got.len(), want_range.len());
            for (a, b) in got.iter().zip(want_range.iter()) {
                assert_eq!(a.seq, b.seq);
                assert_eq!(a.event_id, b.event_id);
                assert_eq!(a.payload, b.payload);
            }
        }
    }

    #[test]
    fn randomized_tail_and_range_match_cpu_reference_scan() {
        let _g = TEST_LOCK.lock().unwrap();

        #[derive(Debug)]
        struct SplitMix64 {
            state: u64,
        }

        impl SplitMix64 {
            fn new(seed: u64) -> Self {
                Self { state: seed }
            }

            fn next_u64(&mut self) -> u64 {
                let mut z = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
                self.state = z;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^ (z >> 31)
            }

            fn gen_range_u32(&mut self, upper: u32) -> u32 {
                if upper == 0 {
                    return 0;
                }
                (self.next_u64() % upper as u64) as u32
            }

            fn fill_bytes(&mut self, out: &mut [u8]) {
                for b in out {
                    *b = (self.next_u64() & 0xFF) as u8;
                }
            }
        }

        let tenant_id = "t-prop";
        let stream_type = "s-prop";
        let occurred_at = "2026-02-06T00:00:00Z";
        let ingested_at = "2026-02-06T00:00:01Z";
        let event_type = "t-prop";
        let content_type = "application/octet-stream";

        for seed in 1u64..=10u64 {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            let shard_id = 1u32;
            let epoch = 1u64;
            let paths = ShardPaths::for_root(root, shard_id);
            std::fs::create_dir_all(&paths.segments_dir).unwrap();

            let mut rng = SplitMix64::new(seed);
            let num_streams = 1 + rng.gen_range_u32(5); // 1..=5
            let num_segments = 1 + rng.gen_range_u32(4); // 1..=4

            let mut stream_ids: Vec<String> = Vec::new();
            let mut stream_hashes: Vec<u64> = Vec::new();
            for i in 0..num_streams {
                let sid = format!("s{i}");
                let h = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, &sid).unwrap();
                stream_ids.push(sid);
                stream_hashes.push(h);
            }

            // Generate per-stream monotonically increasing seq.
            let mut next_seq: Vec<u64> = vec![1u64; num_streams as usize];

            let mut manifest = OpenOptions::new()
                .create(true)
                .truncate(true)
                .read(true)
                .write(true)
                .open(&paths.manifest_path)
                .unwrap();
            let hdr = encode_manifest_header_v1(shard_id, epoch, 123).unwrap();
            manifest.write_all(&hdr).unwrap();

            let mut metas: Vec<SegmentMeta> = Vec::new();

            for seg_idx in 0..num_segments {
                let segment_seq = (seg_idx as u64) + 1;
                let segment_id = deterministic_segment_id(epoch, segment_seq);
                let created_at = 100 + segment_seq;
                let sealed_at = 200 + segment_seq;

                let codec = if (rng.next_u64() & 1) == 0 {
                    corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1
                } else {
                    corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1
                };

                let frames_in_seg = 20 + rng.gen_range_u32(180); // 20..=199
                let mut events: Vec<(u64, u64, String, Vec<u8>)> =
                    Vec::with_capacity(frames_in_seg as usize);
                for _ in 0..frames_in_seg {
                    let sidx = rng.gen_range_u32(num_streams) as usize;
                    let seq = next_seq[sidx];
                    next_seq[sidx] = seq + 1;
                    let event_id = format!("evt-{seed}-{sidx}-{seq}");
                    let payload_len = rng.gen_range_u32(256) as usize;
                    let mut payload = vec![0u8; payload_len];
                    rng.fill_bytes(&mut payload);
                    events.push((stream_hashes[sidx], seq, event_id, payload));
                }

                // Build canonical headers + frames referencing stable buffers.
                let n = events.len();
                let mut event_ids: Vec<String> = Vec::with_capacity(n);
                let mut payload_hashes: Vec<[u8; 32]> = Vec::with_capacity(n);
                let mut header_hashes: Vec<[u8; 32]> = Vec::with_capacity(n);
                let mut payload_bufs: Vec<Vec<u8>> = Vec::with_capacity(n);
                let mut header_bufs: Vec<Vec<u8>> = Vec::with_capacity(n);
                let mut stream_hashes_for_frames: Vec<u64> = Vec::with_capacity(n);
                let mut seqs: Vec<u64> = Vec::with_capacity(n);

                for (sh, seq, event_id, payload) in events {
                    stream_hashes_for_frames.push(sh);
                    seqs.push(seq);
                    event_ids.push(event_id);
                    payload_bufs.push(payload);
                    let payload_hash =
                        compute_payload_hash(payload_bufs.last().unwrap().as_slice());

                    // stream_id is not used for hashing at this point; it is payload for header.
                    // Use a deterministic placeholder derived from stream_hash.
                    let stream_id = format!("stream-{sh:016x}");
                    let canonical = CanonicalHeaderV1 {
                        tenant_id: tenant_id.to_string(),
                        stream_id,
                        stream_type: stream_type.to_string(),
                        seq,
                        event_id: event_ids.last().unwrap().clone(),
                        occurred_at: occurred_at.to_string(),
                        ingested_at: ingested_at.to_string(),
                        event_type: event_type.to_string(),
                        content_type: content_type.to_string(),
                        payload_len: payload_bufs.last().unwrap().len() as u32,
                        payload_hash,
                    };
                    let canonical_bytes = canonical_header_bytes_v1(&canonical);
                    let header_hash = compute_header_hash(&canonical_bytes);

                    let mut hb = Vec::with_capacity(canonical_bytes.len() + 32);
                    hb.extend_from_slice(&canonical_bytes);
                    hb.extend_from_slice(&header_hash);
                    header_bufs.push(hb);

                    payload_hashes.push(payload_hash);
                    header_hashes.push(header_hash);
                }

                let mut frames: Vec<corecrux_segment::FrameInput<'_>> = Vec::with_capacity(n);
                for i in 0..n {
                    frames.push(corecrux_segment::FrameInput {
                        stream_hash: stream_hashes_for_frames[i],
                        seq: seqs[i],
                        event_id: event_ids[i].as_str(),
                        header_hash: header_hashes[i],
                        payload_hash: payload_hashes[i],
                        header_bytes: header_bufs[i].as_slice(),
                        payload_bytes: payload_bufs[i].as_slice(),
                    });
                }

                let seg = corecrux_segment::build_segment_v1_with_block_codec(
                    shard_id,
                    epoch,
                    segment_seq,
                    segment_id,
                    created_at,
                    sealed_at,
                    codec,
                    &frames,
                )
                .unwrap();

                let rel = format!(
                    "segments/seg-{segment_seq:020}-{}.ccxseg",
                    hex16(&segment_id.0)
                );
                let path = paths.shard_dir.join(&rel);
                std::fs::write(&path, &seg.bytes).unwrap();

                let meta = SegmentMeta {
                    level: 0,
                    shard_id,
                    epoch,
                    segment_seq,
                    segment_id,
                    relative_path: rel,
                    file_len: seg.footer.file_len,
                    created_at_unix_ns: seg.footer.created_at_unix_ns,
                    sealed_at_unix_ns: seg.footer.sealed_at_unix_ns,
                    toc_offset: seg.footer.toc_offset,
                    toc_len: seg.footer.toc_len,
                    toc_entry_count: seg.footer.toc_entry_count,
                    min_stream_hash: seg.footer.min_stream_hash,
                    min_seq: seg.footer.min_seq,
                    max_stream_hash: seg.footer.max_stream_hash,
                    max_seq: seg.footer.max_seq,
                    segment_hash: seg.footer.segment_hash,
                };
                let rec = encode_manifest_add_segment_v1(&meta).unwrap();
                let framed = frame_manifest_record(&rec);
                manifest.write_all(&framed).unwrap();
                metas.push(meta);
            }
            manifest.sync_all().unwrap();

            // Open storage (GPU-first in CUDA builds).
            let storage = ShardStorage::open(
                root,
                shard_id,
                epoch,
                ShardStorageOptions::default(),
            )
            .unwrap();

            // CPU truth scan.
            let mut truth_by_stream: std::collections::HashMap<u64, Vec<StoredEvent>> =
                std::collections::HashMap::new();
            for seg in &metas {
                let seg_path = paths.shard_dir.join(&seg.relative_path);
                let bytes = std::fs::read(&seg_path).unwrap();
                let (_h, toc_h, _entries, footer) =
                    corecrux_segment::decode_segment_v1(&bytes).unwrap();
                let toc_off = footer.toc_offset as usize;
                let toc_len = footer.toc_len as usize;
                let toc_area = &bytes[toc_off..toc_off + toc_len];
                let ti = corecrux_segment::decode_trailer_index_v1(toc_area, &toc_h)
                    .unwrap()
                    .expect("trailer index");
                let block_starts = block_logical_starts(&ti.blocks).unwrap();

                let mut blocks_uncompressed: Vec<Vec<u8>> = vec![Vec::new(); ti.blocks.len()];
                for b in &ti.blocks {
                    let off = b.file_offset as usize;
                    let len = b.compressed_len as usize;
                    let end = off + len;
                    let compressed = &bytes[off..end];
                    let mut out = match b.codec {
                        corecrux_segment::RECORD_BLOCK_CODEC_NONE_V1 => compressed.to_vec(),
                        corecrux_segment::RECORD_BLOCK_CODEC_LZ4_V1 => {
                            let want = b.uncompressed_len as usize;
                            let out = lz4_flex::block::decompress(compressed, want).unwrap();
                            assert_eq!(out.len(), want);
                            out
                        }
                        other => panic!("unsupported codec {other} in prop fixture"),
                    };
                    let actual_crc = crc32c::crc32c(&out);
                    assert_eq!(actual_crc, b.crc32c);
                    blocks_uncompressed[b.block_id as usize].append(&mut out);
                }

                for e in &ti.toc_by_offset {
                    let bid = e.block_id as usize;
                    let buf = &blocks_uncompressed[bid];
                    let start = e.in_block_offset as usize;
                    let end = start + (e.frame_len as usize);
                    let frame = &buf[start..end];
                    let block_start = block_starts[bid];
                    let frame_off = (corecrux_segment::SEGMENT_HEADER_LEN as u64)
                        .saturating_add(block_start)
                        .saturating_add(e.in_block_offset as u64);
                    let ev = decode_stored_event_from_frame_bytes(
                        seg.shard_id as u64,
                        seg.epoch,
                        seg.segment_seq,
                        frame_off,
                        frame,
                    )
                    .unwrap();
                    truth_by_stream.entry(e.stream_hash).or_default().push(ev);
                }
            }
            for v in truth_by_stream.values_mut() {
                v.sort_by_key(|e| e.seq);
            }

            // Random queries vs truth.
            for _ in 0..200 {
                let sidx = rng.gen_range_u32(num_streams) as usize;
                let sid = &stream_ids[sidx];
                let sh = stream_hashes[sidx];
                let truth = truth_by_stream.get(&sh).cloned().unwrap_or_default();

                // Tail.
                let tail_limit = rng.gen_range_u32(25);
                let got_tail = storage
                    .read_tail(tenant_id, stream_type, sid, sh, tail_limit)
                    .unwrap();
                let want_tail: Vec<StoredEvent> = truth
                    .iter()
                    .rev()
                    .take(tail_limit as usize)
                    .cloned()
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                assert_eq!(got_tail.len(), want_tail.len());
                for (a, b) in got_tail.iter().zip(want_tail.iter()) {
                    assert_eq!(a.seq, b.seq);
                    assert_eq!(a.event_id, b.event_id);
                    assert_eq!(a.payload, b.payload);
                }

                // Range.
                let max_seq = truth.last().map(|e| e.seq).unwrap_or(0);
                let from_seq = (rng.gen_range_u32((max_seq as u32).saturating_add(5)) as u64) + 1;
                let limit = rng.gen_range_u32(40);
                let got = storage
                    .read_stream(tenant_id, stream_type, sid, sh, from_seq, limit)
                    .unwrap();
                let take = if limit == 0 {
                    usize::MAX
                } else {
                    limit as usize
                };
                let want: Vec<StoredEvent> = truth
                    .iter()
                    .filter(|e| e.seq >= from_seq)
                    .take(take)
                    .cloned()
                    .collect();
                assert_eq!(got.len(), want.len());
                for (a, b) in got.iter().zip(want.iter()) {
                    assert_eq!(a.seq, b.seq);
                    assert_eq!(a.event_id, b.event_id);
                    assert_eq!(a.payload, b.payload);
                }
            }
        }
    }

    /// Regression test: opening a second ShardStorage on the same shard while the
    /// first is held must fail with EAGAIN / WouldBlock, NOT silently succeed.
    /// This validates that the flock-based exclusive lock prevents self-lock reentry,
    /// which was the root cause of the decision-plane 500 bug (2026-03-24).
    #[test]
    fn second_open_on_locked_shard_returns_would_block() {
        let _g = TEST_LOCK.lock().unwrap();
        let (dir, _storage) = open_test_storage(ShardStorageOptions::default());

        // Attempt to open the same shard while the first handle is live.

        let result = ShardStorage::open(
            dir.path(),
            1,
            1,
            ShardStorageOptions::default(),
        );

        let err = match result {
            Ok(_) => panic!("second open should fail while first holds flock"),
            Err(e) => e,
        };
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("temporarily unavailable")
                || err_msg.contains("Would block")
                || err_msg.contains("os error 11")
                || err_msg.contains("WouldBlock"),
            "error should indicate lock contention, got: {err_msg}"
        );
    }

    // ── Pure function coverage: encode/decode helpers ──────────────────

    #[test]
    fn dir_extent_encode_decode_roundtrip() {
        let e = DirExtentV1 {
            stream_hash: 0xDEAD_BEEF_CAFE_BABE,
            min_seq: 42,
            max_seq: 99,
            segment_seq: 7,
        };
        let bytes = encode_dir_extent_v1(e);
        let decoded = decode_dir_extent_v1(&bytes).unwrap();
        assert_eq!(decoded.stream_hash, e.stream_hash);
        assert_eq!(decoded.min_seq, e.min_seq);
        assert_eq!(decoded.max_seq, e.max_seq);
        assert_eq!(decoded.segment_seq, e.segment_seq);
    }

    #[test]
    fn decode_dir_extent_v1_too_small() {
        let err = decode_dir_extent_v1(&[0u8; 16]).unwrap_err();
        assert!(err.to_string().contains("dir extent too small"));
    }

    #[test]
    fn dirrun_partition_v1_stable() {
        assert_eq!(dirrun_partition_v1(0x00), 0);
        assert_eq!(dirrun_partition_v1(0xFF), 255);
        assert_eq!(dirrun_partition_v1(0x1234_5678_9ABC_DEF0), 0xF0);
    }

    #[test]
    fn dir_extent_key_cmp_orders_by_stream_hash_then_segment_seq() {
        let a = DirExtentV1 { stream_hash: 1, min_seq: 0, max_seq: 0, segment_seq: 10 };
        let b = DirExtentV1 { stream_hash: 2, min_seq: 0, max_seq: 0, segment_seq: 5 };
        assert!(dir_extent_key_cmp(&a, &b).is_lt());

        let c = DirExtentV1 { stream_hash: 1, min_seq: 0, max_seq: 0, segment_seq: 20 };
        assert!(dir_extent_key_cmp(&a, &c).is_lt());

        assert!(dir_extent_key_cmp(&a, &a).is_eq());
    }

    #[test]
    fn dir_run_relative_path_v1_format() {
        assert_eq!(
            dir_run_relative_path_v1(0, 42),
            "directory/dirrun-l0-r00000000000000000042.ccxdir"
        );
        assert_eq!(
            dir_run_relative_path_v1(3, 0),
            "directory/dirrun-l3-r00000000000000000000.ccxdir"
        );
    }

    #[test]
    fn merge_dir_extents_empty_inputs() {
        let result = merge_dir_extents_partition_sorted_unique_cpu(&[], &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn merge_dir_extents_one_empty() {
        let a = vec![DirExtentV1 { stream_hash: 1, min_seq: 5, max_seq: 10, segment_seq: 1 }];
        let result = merge_dir_extents_partition_sorted_unique_cpu(&a, &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].stream_hash, 1);

        let result2 = merge_dir_extents_partition_sorted_unique_cpu(&[], &a);
        assert_eq!(result2.len(), 1);
        assert_eq!(result2[0].stream_hash, 1);
    }

    #[test]
    fn merge_dir_extents_deduplicates_same_key() {
        let a = vec![DirExtentV1 { stream_hash: 1, min_seq: 5, max_seq: 10, segment_seq: 1 }];
        let b = vec![DirExtentV1 { stream_hash: 1, min_seq: 3, max_seq: 12, segment_seq: 1 }];
        let result = merge_dir_extents_partition_sorted_unique_cpu(&a, &b);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].min_seq, 3);
        assert_eq!(result[0].max_seq, 12);
    }

    #[test]
    fn merge_dir_extents_interleaved() {
        let a = vec![
            DirExtentV1 { stream_hash: 1, min_seq: 1, max_seq: 5, segment_seq: 1 },
            DirExtentV1 { stream_hash: 3, min_seq: 1, max_seq: 3, segment_seq: 1 },
        ];
        let b = vec![
            DirExtentV1 { stream_hash: 2, min_seq: 1, max_seq: 2, segment_seq: 1 },
            DirExtentV1 { stream_hash: 4, min_seq: 1, max_seq: 4, segment_seq: 1 },
        ];
        let result = merge_dir_extents_partition_sorted_unique_cpu(&a, &b);
        assert_eq!(result.len(), 4);
        assert_eq!(result[0].stream_hash, 1);
        assert_eq!(result[1].stream_hash, 2);
        assert_eq!(result[2].stream_hash, 3);
        assert_eq!(result[3].stream_hash, 4);
    }

    // ── Commit frame edge cases ────────────────────────────────────────

    #[test]
    fn decode_commit_frame_v1_too_small() {
        let err = decode_commit_frame_v1(&[0u8; 10]).unwrap_err();
        assert!(err.to_string().contains("commit frame too small"));
    }

    #[test]
    fn decode_commit_frame_v1_bad_magic() {
        let mut frame = encode_commit_frame_v1(1, 2, 3, 4);
        frame[0] = 0xFF; // corrupt magic
        let err = decode_commit_frame_v1(&frame).unwrap_err();
        assert!(err.to_string().contains("invalid commit frame magic"));
    }

    #[test]
    fn decode_commit_frame_v1_bad_version() {
        let mut frame = encode_commit_frame_v1(1, 2, 3, 4);
        frame[4] = 99; // corrupt version
        // Recalculate CRC so it passes the CRC check
        let crc = crc32c::crc32c(&frame[..COMMIT_FRAME_LEN_V1 - 4]);
        frame[COMMIT_FRAME_LEN_V1 - 4..].copy_from_slice(&crc.to_le_bytes());
        let err = decode_commit_frame_v1(&frame).unwrap_err();
        assert!(err.to_string().contains("unsupported commit frame version"));
    }

    #[test]
    fn decode_commit_frame_v1_bad_header_len() {
        let mut frame = encode_commit_frame_v1(1, 2, 3, 4);
        frame[6] = 128; // corrupt header_len
        let crc = crc32c::crc32c(&frame[..COMMIT_FRAME_LEN_V1 - 4]);
        frame[COMMIT_FRAME_LEN_V1 - 4..].copy_from_slice(&crc.to_le_bytes());
        let err = decode_commit_frame_v1(&frame).unwrap_err();
        assert!(err.to_string().contains("invalid commit frame header_len"));
    }

    // ── Manifest header validation ─────────────────────────────────────

    #[test]
    fn validate_manifest_header_too_small() {
        let err = validate_manifest_header(&[0u8; 10]).unwrap_err();
        assert!(err.to_string().contains("too small"));
    }

    #[test]
    fn validate_manifest_header_bad_magic() {
        let mut hdr = encode_manifest_header_v1(0, 1, 100).unwrap();
        hdr[0] = 0xFF;
        let err = validate_manifest_header(&hdr).unwrap_err();
        assert!(err.to_string().contains("bad magic"));
    }

    #[test]
    fn validate_manifest_header_bad_version() {
        let mut hdr = encode_manifest_header_v1(0, 1, 100).unwrap();
        hdr[4] = 99;
        let crc = crc32c::crc32c(&hdr[..MANIFEST_HEADER_LEN - 4]);
        hdr[MANIFEST_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        let err = validate_manifest_header(&hdr).unwrap_err();
        assert!(err.to_string().contains("bad version"));
    }

    #[test]
    fn validate_manifest_header_bad_header_len() {
        let mut hdr = encode_manifest_header_v1(0, 1, 100).unwrap();
        hdr[8..12].copy_from_slice(&999u32.to_le_bytes());
        let crc = crc32c::crc32c(&hdr[..MANIFEST_HEADER_LEN - 4]);
        hdr[MANIFEST_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
        let err = validate_manifest_header(&hdr).unwrap_err();
        assert!(err.to_string().contains("bad header_len"));
    }

    #[test]
    fn validate_manifest_header_crc_mismatch() {
        let mut hdr = encode_manifest_header_v1(0, 1, 100).unwrap();
        hdr[MANIFEST_HEADER_LEN - 4..].copy_from_slice(&0xDEADu32.to_le_bytes());
        let err = validate_manifest_header(&hdr).unwrap_err();
        match err {
            StorageError::ManifestCrcMismatch { .. } => {},
            other => panic!("expected ManifestCrcMismatch, got {other:?}"),
        }
    }

    #[test]
    fn validate_manifest_header_valid_roundtrip() {
        let hdr = encode_manifest_header_v1(42, 7, 12345).unwrap();
        validate_manifest_header(&hdr).expect("valid manifest header");
    }

    // ── Pure helpers ───────────────────────────────────────────────────

    #[test]
    fn blake3_hash16_produces_16_byte_prefix() {
        let h = blake3_hash16(b"hello");
        assert_eq!(h.len(), 16);
        let full = blake3::hash(b"hello");
        assert_eq!(&h[..], &full.as_bytes()[..16]);
    }

    #[test]
    fn normalize_hash16_prefix_zeroes_beyond_keep() {
        let h = [0xFFu8; 16];
        let result = normalize_hash16_prefix(h, 4);
        assert_eq!(&result[..4], &[0xFF; 4]);
        assert_eq!(&result[4..], &[0u8; 12]);
    }

    #[test]
    fn normalize_hash16_prefix_zero_zeroes_all() {
        let h = [0xAB; 16];
        let result = normalize_hash16_prefix(h, 0);
        assert_eq!(result, [0u8; 16]);
    }

    #[test]
    fn normalize_hash16_prefix_16_keeps_all() {
        let h = [0xAB; 16];
        let result = normalize_hash16_prefix(h, 16);
        assert_eq!(result, h);
    }

    #[test]
    fn normalize_hash16_prefix_beyond_16_keeps_all() {
        let h = [0xAB; 16];
        let result = normalize_hash16_prefix(h, 32);
        assert_eq!(result, h);
    }

    #[test]
    fn parse_segment_seq_from_filename_valid() {
        assert_eq!(
            parse_segment_seq_from_filename("seg-00000000000000000042-abc.ccxseg"),
            Some(42)
        );
        assert_eq!(
            parse_segment_seq_from_filename("seg-00000000000000000001-deadbeef.ccxseg"),
            Some(1)
        );
    }

    #[test]
    fn parse_segment_seq_from_filename_invalid() {
        assert_eq!(parse_segment_seq_from_filename("not-a-segment"), None);
        assert_eq!(parse_segment_seq_from_filename("seg-short-x"), None);
        assert_eq!(parse_segment_seq_from_filename(""), None);
    }

    #[test]
    fn deterministic_segment_id_encodes_epoch_and_seq() {
        let id = deterministic_segment_id(7, 42);
        assert_eq!(&id.0[0..8], &7u64.to_le_bytes());
        assert_eq!(&id.0[8..16], &42u64.to_le_bytes());
    }

    #[test]
    fn rejected_outcome_sets_fields() {
        let o = rejected_outcome("MY_CODE", "my message".to_string());
        assert_eq!(o.status, AppendStatus::Rejected);
        assert_eq!(o.seq, 0);
        assert!(o.location.is_none());
        assert_eq!(o.error_code.as_deref(), Some("MY_CODE"));
        assert_eq!(o.error_message.as_deref(), Some("my message"));
    }

    #[test]
    fn compute_write_confirmation_receipt_hash_deterministic() {
        let frames = vec![b"frame1".to_vec(), b"frame2".to_vec()];
        let h1 = compute_write_confirmation_receipt_hash(&frames);
        let h2 = compute_write_confirmation_receipt_hash(&frames);
        assert_eq!(h1, h2);

        let frames2 = vec![b"frame2".to_vec(), b"frame1".to_vec()];
        let h3 = compute_write_confirmation_receipt_hash(&frames2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn compute_write_confirmation_receipt_hash_empty() {
        let h = compute_write_confirmation_receipt_hash(&[]);
        // Empty hasher produces the BLAKE3 empty-input hash
        assert_eq!(h, *blake3::Hasher::new().finalize().as_bytes());
    }

    #[test]
    fn failpoint_active_returns_false_by_default() {
        std::env::remove_var("CORECRUX_STORAGE_FAILPOINT");
        assert!(!failpoint_active("whatever"));
    }

    // ── Dirrun decode error paths ─────────────────────────────────────

    #[test]
    fn decode_dir_run_v1_too_small() {
        let err = decode_dir_run_v1(&[0u8; 100]).unwrap_err();
        assert!(err.to_string().contains("dirrun file too small"));
    }

    #[test]
    fn decode_dir_run_v1_bad_magic() {
        let bytes = encode_dir_run_v1(0, &[]).unwrap();
        let mut bad = bytes.clone();
        bad[0] = 0xFF;
        let err = decode_dir_run_v1(&bad).unwrap_err();
        assert!(err.to_string().contains("dirrun bad magic"));
    }

    #[test]
    fn dirrun_empty_extents_roundtrip() {
        let bytes = encode_dir_run_v1(42, &[]).unwrap();
        let decoded = decode_dir_run_v1(&bytes).unwrap();
        assert_eq!(decoded.created_at_unix_ns, 42);
        assert_eq!(decoded.record_count, 0);
        for p in &decoded.partitions {
            assert!(p.is_empty());
        }
    }

    // ── IdemHotCache edge cases ───────────────────────────────────────

    #[test]
    fn idem_hot_cache_zero_capacity() {
        let mut cache = IdemHotCache::new(0);
        let key = IdemKey {
            stream_hash: 1,
            event_id_hash16: [0u8; 16],
        };
        let entry = IdemEntry {
            seq: 1,
            loc: FrameLocation { shard_id: 0, epoch: 0, segment_seq: 0, offset: 0 },
        };
        cache.insert(key, entry);
        assert!(cache.is_incomplete());
        assert!(cache.candidates(&key).is_none());
    }

    #[test]
    fn idem_hot_cache_eviction() {
        let mut cache = IdemHotCache::new(2);
        let key1 = IdemKey { stream_hash: 1, event_id_hash16: [1u8; 16] };
        let key2 = IdemKey { stream_hash: 2, event_id_hash16: [2u8; 16] };
        let key3 = IdemKey { stream_hash: 3, event_id_hash16: [3u8; 16] };
        let loc = FrameLocation { shard_id: 0, epoch: 0, segment_seq: 0, offset: 0 };

        cache.insert(key1, IdemEntry { seq: 1, loc });
        cache.insert(key2, IdemEntry { seq: 2, loc });
        assert!(!cache.is_incomplete());

        cache.insert(key3, IdemEntry { seq: 3, loc });
        assert!(cache.is_incomplete());
        // key1 should have been evicted
        assert!(cache.candidates(&key1).is_none());
        assert!(cache.candidates(&key3).is_some());
    }

    // ── ColdBatchLookup ───────────────────────────────────────────────

    #[test]
    fn cold_batch_lookup_find_works() {
        let mut lookup = ColdBatchLookup::default();
        let prefix = [0xAAu8; 16];
        let outcome = AppendOutcome {
            status: AppendStatus::DuplicateCommitted,
            seq: 42,
            location: None,
            payload_hash: [0u8; 32],
            header_hash: [0u8; 32],
            error_code: None,
            error_message: None,
        };
        lookup.by_prefix.entry(prefix).or_default().push(ColdBatchMatch {
            event_id: "evt-1".to_string(),
            outcome: outcome.clone(),
        });
        let found = lookup.find(prefix, "evt-1").unwrap();
        assert_eq!(found.seq, 42);
        assert!(lookup.find(prefix, "evt-2").is_none());
        assert!(lookup.find([0xBBu8; 16], "evt-1").is_none());
    }

    // ── frame_manifest_record ─────────────────────────────────────────

    #[test]
    fn frame_manifest_record_structure() {
        let data = b"test record";
        let framed = frame_manifest_record(data);
        assert_eq!(framed.len(), 8 + data.len());
        let len = u32::from_le_bytes(framed[0..4].try_into().unwrap());
        assert_eq!(len, data.len() as u32);
        let crc = u32::from_le_bytes(framed[4..8].try_into().unwrap());
        assert_eq!(crc, crc32c::crc32c(data));
        assert_eq!(&framed[8..], data);
    }

    // ── encode_manifest_header_v1 deterministic ───────────────────────

    #[test]
    fn encode_manifest_header_v1_fields() {
        let hdr = encode_manifest_header_v1(42, 7, 999).unwrap();
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        assert_eq!(magic, MANIFEST_MAGIC_CCMF);
        let ver = u16::from_le_bytes(hdr[4..6].try_into().unwrap());
        assert_eq!(ver, MANIFEST_VERSION_V1);
        let shard_id = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
        assert_eq!(shard_id, 42);
        let epoch = u64::from_le_bytes(hdr[16..24].try_into().unwrap());
        assert_eq!(epoch, 7);
        let created = u64::from_le_bytes(hdr[24..32].try_into().unwrap());
        assert_eq!(created, 999);
    }

    // ── ShardStorageOptions invalid hash prefix ───────────────────────

    #[test]
    fn open_rejects_invalid_hash_prefix_len() {
        let _g = TEST_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let opts = ShardStorageOptions {
            event_id_hash_prefix_len: 0,
            ..Default::default()
        };
        match ShardStorage::open(dir.path(), 1, 1, opts) {
            Err(StorageError::InvalidArgument { code, .. }) => {
                assert_eq!(code, "CONFIG_INVALID");
            }
            Err(other) => panic!("expected InvalidArgument, got: {other}"),
            Ok(_) => panic!("expected error, got Ok"),
        }

        let opts17 = ShardStorageOptions {
            event_id_hash_prefix_len: 17,
            ..Default::default()
        };
        match ShardStorage::open(dir.path(), 1, 1, opts17) {
            Err(StorageError::InvalidArgument { code, .. }) => {
                assert_eq!(code, "CONFIG_INVALID");
            }
            Err(other) => panic!("expected InvalidArgument, got: {other}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    // ── ReadStatsV1 / AppendStatsV1 accumulator methods ───────────────

    #[test]
    fn read_stats_accumulates_durations() {
        let mut stats = ReadStatsV1::default();
        stats.add_index_elapsed(std::time::Duration::from_nanos(100));
        stats.add_io_elapsed(std::time::Duration::from_nanos(200));
        stats.add_decode_elapsed(std::time::Duration::from_nanos(300));
        assert_eq!(stats.index_lookup_nanos, 100);
        assert_eq!(stats.io_nanos, 200);
        assert_eq!(stats.decode_nanos, 300);

        // Accumulates, doesn't replace
        stats.add_index_elapsed(std::time::Duration::from_nanos(50));
        assert_eq!(stats.index_lookup_nanos, 150);
    }

    #[test]
    fn append_stats_accumulates_durations() {
        let mut stats = AppendStatsV1::default();
        stats.add_idempotency_elapsed(std::time::Duration::from_nanos(10));
        stats.add_index_elapsed(std::time::Duration::from_nanos(20));
        stats.add_io_write_elapsed(std::time::Duration::from_nanos(30));
        stats.add_fence_fsync_elapsed(std::time::Duration::from_nanos(40));
        assert_eq!(stats.idempotency_check_nanos, 10);
        assert_eq!(stats.index_update_nanos, 20);
        assert_eq!(stats.io_write_nanos, 30);
        assert_eq!(stats.fence_fsync_nanos, 40);
        assert_eq!(stats.fence_nanos, 40); // fence_fsync adds to fence_nanos too
    }

    // ── ShardPaths ────────────────────────────────────────────────────

    #[test]
    fn shard_paths_for_root_format() {
        let paths = ShardPaths::for_root(std::path::Path::new("/data"), 42);
        assert!(paths.shard_dir.to_str().unwrap().contains("shard-0042"));
        assert!(paths.lock_path.to_str().unwrap().ends_with("LOCK"));
        assert!(paths.manifest_path.to_str().unwrap().ends_with("MANIFEST"));
        assert!(paths.segments_dir.to_str().unwrap().ends_with("segments"));
        assert!(paths.directory_dir.to_str().unwrap().ends_with("directory"));
        assert!(paths.projections_dir.to_str().unwrap().ends_with("projections"));
        assert!(paths.tmp_dir.to_str().unwrap().ends_with("tmp"));
        assert!(paths.quarantine_dir.to_str().unwrap().ends_with("quarantine"));
    }

    // ── StorageError Display ──────────────────────────────────────────

    #[test]
    fn storage_error_display_includes_codes() {
        let e = StorageError::InvalidArgument { code: "X".into(), msg: "Y".into() };
        assert!(e.to_string().contains("X"));
        assert!(e.to_string().contains("Y"));

        let e2 = StorageError::ResourceExhausted {
            code: "BP".into(), msg: "full".into(), retry_after_ms: Some(500),
        };
        assert!(e2.to_string().contains("BP"));

        let e3 = StorageError::ManifestCrcMismatch { expected: 0xAA, actual: 0xBB };
        assert!(e3.to_string().contains("0xaa"));
        assert!(e3.to_string().contains("0xbb"));
    }

    // ── head_stream_tail_index ────────────────────────────────────────

    #[test]
    fn build_head_stream_tail_index_groups_by_stream() {
        let frames = vec![
            HeadFrameMeta {
                stream_hash: 1, seq: 1, record_off: 0, frame_len: 10,
                payload_len: 5, event_id_hash16: [0u8; 16], header_digest8: [0u8; 8],
                payload_digest8: [0u8; 8], block_id: 0, in_block_offset: 0,
            },
            HeadFrameMeta {
                stream_hash: 2, seq: 1, record_off: 10, frame_len: 10,
                payload_len: 5, event_id_hash16: [0u8; 16], header_digest8: [0u8; 8],
                payload_digest8: [0u8; 8], block_id: 0, in_block_offset: 10,
            },
            HeadFrameMeta {
                stream_hash: 1, seq: 2, record_off: 20, frame_len: 10,
                payload_len: 5, event_id_hash16: [0u8; 16], header_digest8: [0u8; 8],
                payload_digest8: [0u8; 8], block_id: 0, in_block_offset: 20,
            },
        ];
        let idx = build_head_stream_tail_index(&frames);
        assert_eq!(idx.len(), 2);
        assert_eq!(idx[&1].len(), 2);
        assert_eq!(idx[&2].len(), 1);
    }

    #[test]
    fn push_head_stream_tail_index_caps_at_max() {
        let mut idx: HashMap<u64, Vec<HeadTailFrameRef>> = HashMap::new();
        for i in 0..HEAD_STREAM_TAIL_INDEX_MAX_EVENTS + 10 {
            push_head_stream_tail_index(&mut idx, 1, i, i as u64);
        }
        assert_eq!(idx[&1].len(), HEAD_STREAM_TAIL_INDEX_MAX_EVENTS);
    }

    // ── should_skip_startup_dirrun_bootstrap boundary ─────────────────

    #[test]
    fn should_skip_dirrun_bootstrap_boundaries() {
        // dir_runs_empty=false always returns false
        assert!(!should_skip_startup_dirrun_bootstrap(false, 0));
        assert!(!should_skip_startup_dirrun_bootstrap(false, usize::MAX));

        // At the limit: not skipped
        assert!(!should_skip_startup_dirrun_bootstrap(true, STARTUP_DIRRUN_BOOTSTRAP_SEGMENT_LIMIT_V1));
        // One over: skipped
        assert!(should_skip_startup_dirrun_bootstrap(true, STARTUP_DIRRUN_BOOTSTRAP_SEGMENT_LIMIT_V1 + 1));
    }

    // ── Manifest with CRC mismatch ───────────────────────────────────

    #[test]
    fn manifest_record_crc_mismatch_truncates_gracefully() {
        let _g = TEST_LOCK.lock().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("MANIFEST");

        let mut f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        let hdr = encode_manifest_header_v1(0, 1, 100).unwrap();
        f.write_all(&hdr).unwrap();

        // Write a record with wrong CRC
        let data = b"fake record";
        let len = data.len() as u32;
        f.write_all(&len.to_le_bytes()).unwrap();
        f.write_all(&0xDEADu32.to_le_bytes()).unwrap(); // wrong CRC
        f.write_all(data).unwrap();
        f.sync_all().unwrap();

        let (state, end) = load_manifest_records(&mut f).unwrap();
        // Should have truncated to just the header
        assert_eq!(end, MANIFEST_HEADER_LEN as u64);
        assert!(state.segments_by_seq.is_empty());
    }

    // ── Backpressure max batch bytes ─────────────────────────────────

    #[test]
    fn backpressure_max_batch_bytes_rejects() {
        let _g = TEST_LOCK.lock().unwrap();

        let opts = ShardStorageOptions {
            max_batch_bytes: 1, // extremely small
            ..Default::default()
        };
        let (_dir, mut storage) = open_test_storage(opts);

        let tenant_id = "t1";
        let stream_type = "s";
        let stream_id = "a";
        let stream_hash =
            corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id).unwrap();

        let events = [AppendEventInput {
            event_id: "e1",
            occurred_at: "2026-02-06T00:00:00Z",
            event_type: "t",
            content_type: "application/octet-stream",
            payload_bytes: b"hello world",
        }];

        let err = storage
            .append_batch(
                stream_hash,
                0,
                tenant_id,
                stream_type,
                stream_id,
                "2026-02-06T00:00:01Z",
                &events,
            )
            .unwrap_err();
        match err {
            StorageError::ResourceExhausted { code, .. } => {
                assert_eq!(code, "BACKPRESSURE_MAX_BATCH_BYTES");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // ── Replay from sealed ──────────────────────────────────────────

    #[test]
    fn replay_from_sealed_empty_store() {
        let _g = TEST_LOCK.lock().unwrap();
        let (_dir, storage) = open_test_storage(ShardStorageOptions::default());
        let (frames, cursor) = storage.replay_from_sealed(None, 100).unwrap();
        assert!(frames.is_empty());
        assert!(cursor.is_none());
    }

    // ── Force seal with no head ──────────────────────────────────────

    #[test]
    fn force_seal_head_with_no_head() {
        let _g = TEST_LOCK.lock().unwrap();
        let (_dir, mut storage) = open_test_storage(ShardStorageOptions::default());
        let result = storage.force_seal_head().unwrap();
        assert!(!result.sealed);
        assert!(result.segment_seq.is_none());
        assert!(result.frame_count.is_none());
    }

    // ── DirectoryLsmStats ─────────────────────────────────────────────

    #[test]
    fn directory_lsm_stats_empty() {
        let _g = TEST_LOCK.lock().unwrap();
        let (_dir, storage) = open_test_storage(ShardStorageOptions::default());
        let stats = storage.directory_lsm_stats_v1();
        assert!(stats.levels.is_empty());
    }
}
