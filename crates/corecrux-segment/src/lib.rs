// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecrux-segment` — Sealed segment format for CoreCrux.
//!
//! Spec source: PlanCrux `CoreCrux-V3-Phase-2.md`.
//!
//! Segments are the fundamental storage unit. An active (unsealed) segment accepts
//! appended frames. Once it reaches its size threshold, it is **sealed**: a table
//! of contents is written, a BLAKE3 integrity hash covers the entire file, and
//! the segment becomes immutable.
//!
//! Key types:
//! - `ActiveSegment` — accepts frame writes until sealed
//! - `SealedSegment` — immutable, integrity-verified, companion-indexed
//! - `SegmentManifest` — tracks segment metadata (seq, epoch, byte ranges)
//!
//! Sealed segments use LZ4 frame compression and are paired with `.ccxi` companion
//! indexes built by `corecrux-index`.

use blake3::Hasher as Blake3;
use thiserror::Error;
use xxhash_rust::xxh64::xxh64;

pub const SEGMENT_MAGIC_CCS3: u32 = 0x3353_4343; // "CCS3"
pub const SEGMENT_MAGIC_CCF3: u32 = 0x3346_4343; // "CCF3"
pub const TOC_MAGIC_TOC1: u32 = 0x3143_4F54; // "TOC1"

pub const FRAME_MAGIC_CRX1: u32 = 0x4352_5831; // "CRX1"
pub const FRAME_VERSION_V1: u16 = 1;

pub const SEGMENT_MAJOR: u16 = 3;
pub const SEGMENT_MINOR: u16 = 0;

pub const SEGMENT_HEADER_LEN: usize = 4096;
pub const SEGMENT_FOOTER_LEN: usize = 256;

pub const TOC_HEADER_LEN: usize = 128;
pub const TOC_ENTRY_LEN: usize = 64;

pub const DEFAULT_RECORD_BLOCK_SIZE: u32 = 64 * 1024;
pub const DEFAULT_TOC_BLOCK_SIZE: u32 = 64 * 1024;

// Phase 5 (Read Engine v1) trailer index extensions.
pub const RECORD_BLOCK_UNCOMPRESSED_MAX_LEN_V1: u32 = 4 * 1024 * 1024; // 4 MiB
pub const BLOOM_BYTES_PER_BLOCK_V1: usize = 256; // 2 Kibit
pub const BLOOM_HASH_K_V1: u32 = 6;

pub const TRAILER_SECTION_HEADER_LEN_V1: usize = 32;
pub const TRAILER_MAGIC_BLK1: u32 = 0x314B_4C42; // "BLK1"
pub const TRAILER_MAGIC_TBO1: u32 = 0x314F_4254; // "TBO1"
pub const TRAILER_MAGIC_TSI1: u32 = 0x3149_5354; // "TSI1"

pub const BLOCK_META_V1_LEN: usize = 288;
pub const TOC_BY_OFFSET_ENTRY_V1_LEN: usize = 64;

#[derive(Debug, Error)]
pub enum SegmentError {
    #[error("buffer too small")]
    BufferTooSmall,
    #[error("invalid magic: expected {expected:#x}, got {actual:#x}")]
    InvalidMagic { expected: u32, actual: u32 },
    #[error("unsupported segment version {major}.{minor}")]
    UnsupportedSegmentVersion { major: u16, minor: u16 },
    #[error("unsupported toc version {version}")]
    UnsupportedTocVersion { version: u16 },
    #[error("crc mismatch: expected {expected:#x}, got {actual:#x}")]
    CrcMismatch { expected: u32, actual: u32 },
    #[error("length out of range: {msg}")]
    LengthOutOfRange { msg: String },
    #[error("footer says file_len={declared}, but actual={actual}")]
    FileLenMismatch { declared: u64, actual: u64 },
    #[error("segment not sealed")]
    NotSealed,
    #[error("hash mismatch: {msg}")]
    HashMismatch { msg: String },
    #[error("toc entries not sorted by (stream_hash, seq)")]
    TocNotSorted,
    #[error("trailer section invalid: {msg}")]
    TrailerSectionInvalid { msg: String },
}

pub type Result<T> = std::result::Result<T, SegmentError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentId(pub [u8; 16]);

#[derive(Debug, Clone)]
pub struct SegmentHeaderV1 {
    pub flags: u32,
    pub shard_id: u32,
    pub epoch: u64,
    pub segment_seq: u64,
    pub segment_id: SegmentId,
    pub created_at_unix_ns: u64,
}

#[derive(Debug, Clone)]
pub struct TocHeaderV1 {
    pub entry_count: u64,
    pub record_block_size: u32,
    pub toc_block_size: u32,
    pub record_area_offset: u64,
    pub record_area_len: u64,
    pub toc_payload_len: u64,
    pub crc_tables_len: u64,
    pub sort_order: u64,
    pub toc_payload_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TocEntryV1 {
    pub stream_hash: u64,
    pub seq: u64,
    pub file_offset: u32,
    pub frame_len: u32,
    pub payload_len: u32,
    pub flags: u32,
    pub event_id_hash16: [u8; 16],
    pub header_digest8: [u8; 8],
    pub payload_digest8: [u8; 8],
}

#[derive(Debug, Clone)]
pub struct SegmentFooterV1 {
    pub flags: u32,
    pub shard_id: u32,
    pub epoch: u64,
    pub segment_seq: u64,
    pub segment_id: SegmentId,
    pub created_at_unix_ns: u64,
    pub sealed_at_unix_ns: u64,
    pub file_len: u64,
    pub record_area_offset: u64,
    pub record_area_len: u64,
    pub toc_offset: u64,
    pub toc_len: u64,
    pub toc_entry_count: u64,
    pub min_stream_hash: u64,
    pub min_seq: u64,
    pub max_stream_hash: u64,
    pub max_seq: u64,
    pub header_hash: [u8; 32],
    pub record_hash: [u8; 32],
    pub toc_payload_hash: [u8; 32],
    pub segment_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SegmentBuildOutput {
    pub bytes: Vec<u8>,
    pub header: SegmentHeaderV1,
    pub toc_header: TocHeaderV1,
    pub toc_entries: Vec<TocEntryV1>,
    pub footer: SegmentFooterV1,
    pub record_crc32c_table: Vec<u32>,
    pub toc_crc32c_table: Vec<u32>,
}

#[derive(Debug, Clone, Copy)]
struct FrameMetaTmp {
    stream_hash: u64,
    seq: u64,
    event_id_hash16: [u8; 16],
    header_digest8: [u8; 8],
    payload_digest8: [u8; 8],
    record_off: u32,
    frame_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TocByOffsetEntryV1 {
    pub stream_hash: u64,
    pub seq: u64,
    pub block_id: u32,
    pub in_block_offset: u32,
    pub frame_len: u32,
    pub flags: u32,
    pub event_id_hash16: [u8; 16],
    pub header_digest8: [u8; 8],
    pub payload_digest8: [u8; 8],
}

// Record block codecs for BlockMetaV1.codec.
pub const RECORD_BLOCK_CODEC_NONE_V1: u32 = 0;
pub const RECORD_BLOCK_CODEC_LZ4_V1: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockMetaV1 {
    pub block_id: u32,
    pub codec: u32, // RECORD_BLOCK_CODEC_*_V1
    pub file_offset: u64,
    pub compressed_len: u32,
    /// Physical bytes on disk for this block payload (may include padding for alignment).
    ///
    /// Backwards-compat: older segments may encode this as 0; readers should treat 0 as
    /// `compressed_len`.
    pub physical_len: u32,
    pub uncompressed_len: u32,
    pub crc32c: u32,
    pub bloom: [u8; BLOOM_BYTES_PER_BLOCK_V1],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailerIndexV1 {
    pub record_block_uncompressed_max_len: u32,
    pub bloom_bytes_per_block: u32,
    pub bloom_hash_k: u32,
    pub blocks: Vec<BlockMetaV1>,
    pub toc_by_offset: Vec<TocByOffsetEntryV1>,
    pub toc_sorted_idx: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct FrameInput<'a> {
    pub stream_hash: u64,
    pub seq: u64,
    pub event_id: &'a str,
    pub header_hash: [u8; 32],
    pub payload_hash: [u8; 32],
    pub header_bytes: &'a [u8],
    pub payload_bytes: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct FrameMetaV1 {
    pub stream_hash: u64,
    pub seq: u64,
    pub record_off: u32,
    pub frame_len: u32,
    pub payload_len: u32,
    pub event_id_hash16: [u8; 16],
    pub header_digest8: [u8; 8],
    pub payload_digest8: [u8; 8],
}

pub fn encode_frame_v1(header_bytes: &[u8], payload_bytes: &[u8]) -> Result<Vec<u8>> {
    if header_bytes.len() > u16::MAX as usize {
        return Err(SegmentError::LengthOutOfRange {
            msg: format!("header too large: {} bytes", header_bytes.len()),
        });
    }
    if payload_bytes.len() > u32::MAX as usize {
        return Err(SegmentError::LengthOutOfRange {
            msg: format!("payload too large: {} bytes", payload_bytes.len()),
        });
    }

    let header_len = header_bytes.len() as u16;
    let payload_len = payload_bytes.len() as u32;

    let mut out = Vec::with_capacity(4 + 2 + 2 + 4 + header_bytes.len() + payload_bytes.len() + 4);
    out.extend_from_slice(&FRAME_MAGIC_CRX1.to_le_bytes());
    out.extend_from_slice(&FRAME_VERSION_V1.to_le_bytes());
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(header_bytes);
    out.extend_from_slice(payload_bytes);

    let crc = crc32fast::hash(payload_bytes);
    out.extend_from_slice(&crc.to_le_bytes());
    Ok(out)
}

#[derive(Debug, Clone)]
pub struct FrameV1Decoded {
    pub header_bytes: Vec<u8>,
    pub payload_bytes: Vec<u8>,
}

pub fn decode_frame_v1(frame_bytes: &[u8]) -> Result<FrameV1Decoded> {
    if frame_bytes.len() < 4 + 2 + 2 + 4 + 4 {
        return Err(SegmentError::BufferTooSmall);
    }
    let magic = read_u32(frame_bytes, 0)?;
    if magic != FRAME_MAGIC_CRX1 {
        return Err(SegmentError::InvalidMagic {
            expected: FRAME_MAGIC_CRX1,
            actual: magic,
        });
    }
    let ver = read_u16(frame_bytes, 4)?;
    if ver != FRAME_VERSION_V1 {
        return Err(SegmentError::LengthOutOfRange {
            msg: format!("unsupported frame version: {ver}"),
        });
    }

    let header_len = read_u16(frame_bytes, 6)? as usize;
    let payload_len = read_u32(frame_bytes, 8)? as usize;

    let header_off = 12usize;
    let payload_off = header_off.checked_add(header_len).ok_or(SegmentError::BufferTooSmall)?;
    let crc_off = payload_off
        .checked_add(payload_len)
        .ok_or(SegmentError::BufferTooSmall)?;
    let end = crc_off.checked_add(4).ok_or(SegmentError::BufferTooSmall)?;
    if end > frame_bytes.len() {
        return Err(SegmentError::BufferTooSmall);
    }

    let header_bytes = frame_bytes[header_off..payload_off].to_vec();
    let payload_bytes = frame_bytes[payload_off..crc_off].to_vec();
    let crc = read_u32(frame_bytes, crc_off)?;
    let expected = crc32fast::hash(&payload_bytes);
    if crc != expected {
        return Err(SegmentError::CrcMismatch { expected, actual: crc });
    }

    Ok(FrameV1Decoded {
        header_bytes,
        payload_bytes,
    })
}

pub fn build_segment_v1(
    shard_id: u32,
    epoch: u64,
    segment_seq: u64,
    segment_id: SegmentId,
    created_at_unix_ns: u64,
    sealed_at_unix_ns: u64,
    frames: &[FrameInput<'_>],
) -> Result<SegmentBuildOutput> {
    let header = SegmentHeaderV1 {
        flags: 1, // little_endian
        shard_id,
        epoch,
        segment_seq,
        segment_id,
        created_at_unix_ns,
    };

    let header_bytes = encode_segment_header_v1(&header)?;

    let mut record_area: Vec<u8> = Vec::new();
    let mut toc_entries: Vec<TocEntryV1> = Vec::with_capacity(frames.len());
    let mut frames_by_offset: Vec<FrameMetaTmp> = Vec::with_capacity(frames.len());

    for f in frames {
        let record_off = record_area.len() as u64;
        if record_off > u32::MAX as u64 {
            return Err(SegmentError::LengthOutOfRange {
                msg: "record offset exceeds u32".to_string(),
            });
        }

        let file_offset = (SEGMENT_HEADER_LEN + record_area.len()) as u64;
        if file_offset > u32::MAX as u64 {
            return Err(SegmentError::LengthOutOfRange {
                msg: "file offset exceeds u32".to_string(),
            });
        }

        let frame_bytes = encode_frame_v1(f.header_bytes, f.payload_bytes)?;
        if frame_bytes.len() > u32::MAX as usize {
            return Err(SegmentError::LengthOutOfRange {
                msg: "frame too large".to_string(),
            });
        }
        let frame_len = frame_bytes.len() as u32;
        let payload_len = f.payload_bytes.len() as u32;

        let event_id_hash = blake3::hash(f.event_id.as_bytes());
        let mut event_id_hash16 = [0u8; 16];
        event_id_hash16.copy_from_slice(&event_id_hash.as_bytes()[0..16]);

        let mut header_digest8 = [0u8; 8];
        header_digest8.copy_from_slice(&f.header_hash[0..8]);
        let mut payload_digest8 = [0u8; 8];
        payload_digest8.copy_from_slice(&f.payload_hash[0..8]);

        toc_entries.push(TocEntryV1 {
            stream_hash: f.stream_hash,
            seq: f.seq,
            file_offset: file_offset as u32,
            frame_len,
            payload_len,
            flags: 0,
            event_id_hash16,
            header_digest8,
            payload_digest8,
        });

        frames_by_offset.push(FrameMetaTmp {
            stream_hash: f.stream_hash,
            seq: f.seq,
            event_id_hash16,
            header_digest8,
            payload_digest8,
            record_off: record_off as u32,
            frame_len,
        });

        record_area.extend_from_slice(&frame_bytes);
    }

    // TOC entries are stored sorted by (stream_hash, seq).
    toc_entries.sort_by(|a, b| match a.stream_hash.cmp(&b.stream_hash) {
        std::cmp::Ordering::Equal => a.seq.cmp(&b.seq),
        other => other,
    });
    if !is_sorted_toc(&toc_entries) {
        return Err(SegmentError::TocNotSorted);
    }

    let record_area_offset = SEGMENT_HEADER_LEN as u64;
    let record_area_len = record_area.len() as u64;
    if record_area_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "record area exceeds 4GiB; not supported in v1 footer encoding".to_string(),
        });
    }

    let toc_payload_len = (TOC_HEADER_LEN + toc_entries.len() * TOC_ENTRY_LEN) as u64;
    let record_crc32c_table = block_crc32c(&record_area, DEFAULT_RECORD_BLOCK_SIZE as usize);
    let toc_payload = encode_toc_payload_v1(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        (record_crc32c_table.len() * 4) as u64, // placeholder; fixed below
        &toc_entries,
    )?;

    let toc_crc32c_table = block_crc32c(&toc_payload, DEFAULT_TOC_BLOCK_SIZE as usize);

    let crc_tables_len = (record_crc32c_table.len() as u64 * 4) + (toc_crc32c_table.len() as u64 * 4);

    // Re-encode toc header now that we have the full crc_tables_len.
    let toc_payload = encode_toc_payload_v1(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        &toc_entries,
    )?;

    let toc_payload_hash = compute_toc_payload_hash(&toc_payload)?;

    let toc_payload = encode_toc_payload_v1_with_hash(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        toc_payload_hash,
        &toc_entries,
    )?;

    let toc_crc32c_table = block_crc32c(&toc_payload, DEFAULT_TOC_BLOCK_SIZE as usize);
    let crc_tables_len = (record_crc32c_table.len() as u64 * 4) + (toc_crc32c_table.len() as u64 * 4);

    let toc_header = TocHeaderV1 {
        entry_count: toc_entries.len() as u64,
        record_block_size: DEFAULT_RECORD_BLOCK_SIZE,
        toc_block_size: DEFAULT_TOC_BLOCK_SIZE,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        sort_order: 1,
        toc_payload_hash,
    };

    // Assemble TocArea bytes.
    let mut toc_area: Vec<u8> = Vec::with_capacity(toc_payload.len() + (crc_tables_len as usize));
    toc_area.extend_from_slice(&toc_payload);
    for c in &record_crc32c_table {
        toc_area.extend_from_slice(&c.to_le_bytes());
    }
    for c in &toc_crc32c_table {
        toc_area.extend_from_slice(&c.to_le_bytes());
    }

    // Phase 5: trailer extension sections (block index + toc-by-offset + sorted idx).
    let trailer_ext = encode_trailer_index_v1(&record_area, &frames_by_offset)?;
    toc_area.extend_from_slice(&trailer_ext);

    let toc_offset = record_area_offset + record_area_len;
    let toc_len = toc_area.len() as u64;

    if toc_offset > u32::MAX as u64 || toc_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "toc offsets exceed u32".to_string(),
        });
    }

    // Bounds.
    let (min_stream_hash, min_seq, max_stream_hash, max_seq) = if toc_entries.is_empty() {
        (0, 0, 0, 0)
    } else {
        let first = toc_entries[0];
        let last = toc_entries[toc_entries.len() - 1];
        (first.stream_hash, first.seq, last.stream_hash, last.seq)
    };

    // Strong hashes.
    let header_hash = blake3::hash(&header_bytes);
    let record_hash = blake3::hash(&record_area);
    let segment_hash = {
        let mut h = Blake3::new();
        h.update(header_hash.as_bytes());
        h.update(record_hash.as_bytes());
        h.update(&toc_payload_hash);
        *h.finalize().as_bytes()
    };

    let file_len = (SEGMENT_HEADER_LEN as u64) + record_area_len + toc_len + (SEGMENT_FOOTER_LEN as u64);
    if file_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "segment file exceeds 4GiB; not supported in v1 footer encoding".to_string(),
        });
    }

    let footer = SegmentFooterV1 {
        flags: 0x3, // SEALED|HAS_TOC
        shard_id,
        epoch,
        segment_seq,
        segment_id,
        created_at_unix_ns,
        sealed_at_unix_ns,
        file_len,
        record_area_offset,
        record_area_len,
        toc_offset,
        toc_len,
        toc_entry_count: toc_entries.len() as u64,
        min_stream_hash,
        min_seq,
        max_stream_hash,
        max_seq,
        header_hash: *header_hash.as_bytes(),
        record_hash: *record_hash.as_bytes(),
        toc_payload_hash,
        segment_hash,
    };
    let footer_bytes = encode_segment_footer_v1(&footer)?;

    // Final file assembly.
    let mut bytes = Vec::with_capacity(file_len as usize);
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(&record_area);
    bytes.extend_from_slice(&toc_area);
    bytes.extend_from_slice(&footer_bytes);

    Ok(SegmentBuildOutput {
        bytes,
        header,
        toc_header,
        toc_entries,
        footer,
        record_crc32c_table,
        toc_crc32c_table,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn build_segment_v1_with_block_codec(
    shard_id: u32,
    epoch: u64,
    segment_seq: u64,
    segment_id: SegmentId,
    created_at_unix_ns: u64,
    sealed_at_unix_ns: u64,
    record_block_codec: u32,
    frames: &[FrameInput<'_>],
) -> Result<SegmentBuildOutput> {
    if record_block_codec == RECORD_BLOCK_CODEC_NONE_V1 {
        return build_segment_v1(
            shard_id,
            epoch,
            segment_seq,
            segment_id,
            created_at_unix_ns,
            sealed_at_unix_ns,
            frames,
        );
    }

    let header = SegmentHeaderV1 {
        flags: 1, // little_endian
        shard_id,
        epoch,
        segment_seq,
        segment_id,
        created_at_unix_ns,
    };
    let header_bytes = encode_segment_header_v1(&header)?;

    // Build uncompressed record area + canonical v1 TOC entries (sorted by stream_hash, seq).
    let mut record_area_uncompressed: Vec<u8> = Vec::new();
    let mut toc_entries: Vec<TocEntryV1> = Vec::with_capacity(frames.len());
    let mut frames_by_offset: Vec<FrameMetaTmp> = Vec::with_capacity(frames.len());

    for f in frames {
        let record_off = record_area_uncompressed.len() as u64;
        if record_off > u32::MAX as u64 {
            return Err(SegmentError::LengthOutOfRange {
                msg: "record offset exceeds u32".to_string(),
            });
        }

        // IMPORTANT: TocEntryV1.file_offset is a *logical* offset into the uncompressed record
        // stream (header_len + record_off). Reads translate logical offsets via the block index.
        let file_offset = (SEGMENT_HEADER_LEN as u64)
            .checked_add(record_area_uncompressed.len() as u64)
            .ok_or(SegmentError::BufferTooSmall)?;
        if file_offset > u32::MAX as u64 {
            return Err(SegmentError::LengthOutOfRange {
                msg: "file offset exceeds u32".to_string(),
            });
        }

        let frame_bytes = encode_frame_v1(f.header_bytes, f.payload_bytes)?;
        if frame_bytes.len() > u32::MAX as usize {
            return Err(SegmentError::LengthOutOfRange {
                msg: "frame too large".to_string(),
            });
        }
        let frame_len = frame_bytes.len() as u32;
        let payload_len = f.payload_bytes.len() as u32;

        let event_id_hash = blake3::hash(f.event_id.as_bytes());
        let mut event_id_hash16 = [0u8; 16];
        event_id_hash16.copy_from_slice(&event_id_hash.as_bytes()[0..16]);

        let mut header_digest8 = [0u8; 8];
        header_digest8.copy_from_slice(&f.header_hash[0..8]);
        let mut payload_digest8 = [0u8; 8];
        payload_digest8.copy_from_slice(&f.payload_hash[0..8]);

        toc_entries.push(TocEntryV1 {
            stream_hash: f.stream_hash,
            seq: f.seq,
            file_offset: file_offset as u32,
            frame_len,
            payload_len,
            flags: 0,
            event_id_hash16,
            header_digest8,
            payload_digest8,
        });

        frames_by_offset.push(FrameMetaTmp {
            stream_hash: f.stream_hash,
            seq: f.seq,
            event_id_hash16,
            header_digest8,
            payload_digest8,
            record_off: record_off as u32,
            frame_len,
        });

        record_area_uncompressed.extend_from_slice(&frame_bytes);
    }

    toc_entries.sort_by(|a, b| match a.stream_hash.cmp(&b.stream_hash) {
        std::cmp::Ordering::Equal => a.seq.cmp(&b.seq),
        other => other,
    });
    if !is_sorted_toc(&toc_entries) {
        return Err(SegmentError::TocNotSorted);
    }

    // Build compressed physical record bytes + Phase 5 trailer index.
    let RecordBlocksAndTrailerIndexPartsV1 {
        record_area,
        blocks,
        toc_by_offset,
        toc_sorted_idx,
    } = build_record_blocks_and_trailer_index_parts_v1(
        &record_area_uncompressed,
        &frames_by_offset,
        record_block_codec,
    )?;
    let trailer_ext = encode_trailer_index_v1_from_parts(&blocks, &toc_by_offset, &toc_sorted_idx)?;

    let record_area_offset = SEGMENT_HEADER_LEN as u64;
    let record_area_len = record_area.len() as u64;
    if record_area_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "record area exceeds 4GiB; not supported in v1 footer encoding".to_string(),
        });
    }

    let toc_payload_len = (TOC_HEADER_LEN + toc_entries.len() * TOC_ENTRY_LEN) as u64;
    let record_crc32c_table = block_crc32c(&record_area, DEFAULT_RECORD_BLOCK_SIZE as usize);
    let toc_payload = encode_toc_payload_v1(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        (record_crc32c_table.len() * 4) as u64, // placeholder; fixed below
        &toc_entries,
    )?;

    let toc_crc32c_table = block_crc32c(&toc_payload, DEFAULT_TOC_BLOCK_SIZE as usize);

    let crc_tables_len = (record_crc32c_table.len() as u64 * 4) + (toc_crc32c_table.len() as u64 * 4);

    // Re-encode toc header now that we have the full crc_tables_len.
    let toc_payload = encode_toc_payload_v1(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        &toc_entries,
    )?;

    let toc_payload_hash = compute_toc_payload_hash(&toc_payload)?;

    let toc_payload = encode_toc_payload_v1_with_hash(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        toc_payload_hash,
        &toc_entries,
    )?;

    let toc_crc32c_table = block_crc32c(&toc_payload, DEFAULT_TOC_BLOCK_SIZE as usize);
    let crc_tables_len = (record_crc32c_table.len() as u64 * 4) + (toc_crc32c_table.len() as u64 * 4);

    let toc_header = TocHeaderV1 {
        entry_count: toc_entries.len() as u64,
        record_block_size: DEFAULT_RECORD_BLOCK_SIZE,
        toc_block_size: DEFAULT_TOC_BLOCK_SIZE,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        sort_order: 1,
        toc_payload_hash,
    };

    let mut toc_area: Vec<u8> = Vec::with_capacity(toc_payload.len() + (crc_tables_len as usize));
    toc_area.extend_from_slice(&toc_payload);
    for c in &record_crc32c_table {
        toc_area.extend_from_slice(&c.to_le_bytes());
    }
    for c in &toc_crc32c_table {
        toc_area.extend_from_slice(&c.to_le_bytes());
    }
    toc_area.extend_from_slice(&trailer_ext);

    // Phase 9: pad TOC area with trailing zeros so (toc_len + footer_len) is 4KiB-aligned.
    // Header and record area are already 4KiB-aligned, so this makes the full file length aligned.
    let want = toc_area
        .len()
        .checked_add(SEGMENT_FOOTER_LEN)
        .ok_or(SegmentError::BufferTooSmall)?;
    let aligned = align_up(want, 4096);
    let pad = aligned.saturating_sub(want);
    if pad > 0 {
        toc_area.resize(toc_area.len().saturating_add(pad), 0u8);
    }

    let toc_offset = record_area_offset + record_area_len;
    let toc_len = toc_area.len() as u64;

    if toc_offset > u32::MAX as u64 || toc_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "toc offsets exceed u32".to_string(),
        });
    }

    let (min_stream_hash, min_seq, max_stream_hash, max_seq) = if toc_entries.is_empty() {
        (0, 0, 0, 0)
    } else {
        let first = toc_entries[0];
        let last = toc_entries[toc_entries.len() - 1];
        (first.stream_hash, first.seq, last.stream_hash, last.seq)
    };

    let header_hash = blake3::hash(&header_bytes);
    let record_hash = blake3::hash(&record_area);
    let segment_hash = {
        let mut h = Blake3::new();
        h.update(header_hash.as_bytes());
        h.update(record_hash.as_bytes());
        h.update(&toc_payload_hash);
        *h.finalize().as_bytes()
    };

    let file_len = (SEGMENT_HEADER_LEN as u64) + record_area_len + toc_len + (SEGMENT_FOOTER_LEN as u64);
    if file_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "segment file exceeds 4GiB; not supported in v1 footer encoding".to_string(),
        });
    }

    let footer = SegmentFooterV1 {
        flags: 0x3, // SEALED|HAS_TOC
        shard_id,
        epoch,
        segment_seq,
        segment_id,
        created_at_unix_ns,
        sealed_at_unix_ns,
        file_len,
        record_area_offset,
        record_area_len,
        toc_offset,
        toc_len,
        toc_entry_count: toc_entries.len() as u64,
        min_stream_hash,
        min_seq,
        max_stream_hash,
        max_seq,
        header_hash: *header_hash.as_bytes(),
        record_hash: *record_hash.as_bytes(),
        toc_payload_hash,
        segment_hash,
    };
    let footer_bytes = encode_segment_footer_v1(&footer)?;

    let mut bytes = Vec::with_capacity(file_len as usize);
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(&record_area);
    bytes.extend_from_slice(&toc_area);
    bytes.extend_from_slice(&footer_bytes);

    Ok(SegmentBuildOutput {
        bytes,
        header,
        toc_header,
        toc_entries,
        footer,
        record_crc32c_table,
        toc_crc32c_table,
    })
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    level = "info",
    skip(record_area, frames_by_offset),
    fields(
        shard_id,
        epoch,
        segment_seq,
        record_area_len = record_area.len(),
        frame_count = frames_by_offset.len()
    )
)]
pub fn seal_segment_v1_from_record_area(
    shard_id: u32,
    epoch: u64,
    segment_seq: u64,
    segment_id: SegmentId,
    created_at_unix_ns: u64,
    sealed_at_unix_ns: u64,
    record_area: &[u8],
    frames_by_offset: &[FrameMetaV1],
) -> Result<SegmentBuildOutput> {
    let header = SegmentHeaderV1 {
        flags: 1, // little_endian
        shard_id,
        epoch,
        segment_seq,
        segment_id,
        created_at_unix_ns,
    };
    let header_bytes = encode_segment_header_v1(&header)?;

    // Validate and build TOC/trailer metadata.
    let mut toc_entries: Vec<TocEntryV1> = Vec::with_capacity(frames_by_offset.len());
    let mut tmp: Vec<FrameMetaTmp> = Vec::with_capacity(frames_by_offset.len());

    let mut expected_off: u32 = 0;
    for f in frames_by_offset {
        if f.record_off != expected_off {
            return Err(SegmentError::LengthOutOfRange {
                msg: "frames_by_offset record_off is not contiguous".to_string(),
            });
        }
        let end = f
            .record_off
            .checked_add(f.frame_len)
            .ok_or(SegmentError::BufferTooSmall)? as usize;
        if end > record_area.len() {
            return Err(SegmentError::LengthOutOfRange {
                msg: "frames_by_offset points outside record area".to_string(),
            });
        }

        let file_offset = (SEGMENT_HEADER_LEN as u64)
            .checked_add(f.record_off as u64)
            .ok_or(SegmentError::BufferTooSmall)?;
        if file_offset > u32::MAX as u64 {
            return Err(SegmentError::LengthOutOfRange {
                msg: "file offset exceeds u32".to_string(),
            });
        }

        toc_entries.push(TocEntryV1 {
            stream_hash: f.stream_hash,
            seq: f.seq,
            file_offset: file_offset as u32,
            frame_len: f.frame_len,
            payload_len: f.payload_len,
            flags: 0,
            event_id_hash16: f.event_id_hash16,
            header_digest8: f.header_digest8,
            payload_digest8: f.payload_digest8,
        });

        tmp.push(FrameMetaTmp {
            stream_hash: f.stream_hash,
            seq: f.seq,
            event_id_hash16: f.event_id_hash16,
            header_digest8: f.header_digest8,
            payload_digest8: f.payload_digest8,
            record_off: f.record_off,
            frame_len: f.frame_len,
        });

        expected_off = expected_off.saturating_add(f.frame_len);
    }
    if expected_off as usize != record_area.len() {
        return Err(SegmentError::LengthOutOfRange {
            msg: "frames_by_offset does not cover record area".to_string(),
        });
    }

    // TOC entries are stored sorted by (stream_hash, seq).
    toc_entries.sort_by(|a, b| match a.stream_hash.cmp(&b.stream_hash) {
        std::cmp::Ordering::Equal => a.seq.cmp(&b.seq),
        other => other,
    });
    if !is_sorted_toc(&toc_entries) {
        return Err(SegmentError::TocNotSorted);
    }

    let record_area_offset = SEGMENT_HEADER_LEN as u64;
    let record_area_len = record_area.len() as u64;
    if record_area_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "record area exceeds 4GiB; not supported in v1 footer encoding".to_string(),
        });
    }

    let toc_payload_len = (TOC_HEADER_LEN + toc_entries.len() * TOC_ENTRY_LEN) as u64;
    let record_crc32c_table = block_crc32c(record_area, DEFAULT_RECORD_BLOCK_SIZE as usize);
    let toc_payload = encode_toc_payload_v1(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        (record_crc32c_table.len() * 4) as u64, // placeholder; fixed below
        &toc_entries,
    )?;

    let toc_crc32c_table = block_crc32c(&toc_payload, DEFAULT_TOC_BLOCK_SIZE as usize);

    let crc_tables_len = (record_crc32c_table.len() as u64 * 4) + (toc_crc32c_table.len() as u64 * 4);

    // Re-encode toc header now that we have the full crc_tables_len.
    let toc_payload = encode_toc_payload_v1(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        &toc_entries,
    )?;

    let toc_payload_hash = compute_toc_payload_hash(&toc_payload)?;

    let toc_payload = encode_toc_payload_v1_with_hash(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        toc_payload_hash,
        &toc_entries,
    )?;

    let toc_crc32c_table = block_crc32c(&toc_payload, DEFAULT_TOC_BLOCK_SIZE as usize);
    let crc_tables_len = (record_crc32c_table.len() as u64 * 4) + (toc_crc32c_table.len() as u64 * 4);

    let toc_header = TocHeaderV1 {
        entry_count: toc_entries.len() as u64,
        record_block_size: DEFAULT_RECORD_BLOCK_SIZE,
        toc_block_size: DEFAULT_TOC_BLOCK_SIZE,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        sort_order: 1,
        toc_payload_hash,
    };

    // Assemble TocArea bytes.
    let mut toc_area: Vec<u8> = Vec::with_capacity(toc_payload.len() + (crc_tables_len as usize));
    toc_area.extend_from_slice(&toc_payload);
    for c in &record_crc32c_table {
        toc_area.extend_from_slice(&c.to_le_bytes());
    }
    for c in &toc_crc32c_table {
        toc_area.extend_from_slice(&c.to_le_bytes());
    }

    // Phase 5: trailer extension sections (block index + toc-by-offset + sorted idx).
    let trailer_ext = encode_trailer_index_v1(record_area, &tmp)?;
    toc_area.extend_from_slice(&trailer_ext);

    let toc_offset = record_area_offset + record_area_len;
    let toc_len = toc_area.len() as u64;

    if toc_offset > u32::MAX as u64 || toc_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "toc offsets exceed u32".to_string(),
        });
    }

    // Bounds.
    let (min_stream_hash, min_seq, max_stream_hash, max_seq) = if toc_entries.is_empty() {
        (0, 0, 0, 0)
    } else {
        let first = toc_entries[0];
        let last = toc_entries[toc_entries.len() - 1];
        (first.stream_hash, first.seq, last.stream_hash, last.seq)
    };

    // Strong hashes.
    let header_hash = blake3::hash(&header_bytes);
    let record_hash = blake3::hash(record_area);
    let segment_hash = {
        let mut h = Blake3::new();
        h.update(header_hash.as_bytes());
        h.update(record_hash.as_bytes());
        h.update(&toc_payload_hash);
        *h.finalize().as_bytes()
    };

    let file_len = (SEGMENT_HEADER_LEN as u64) + record_area_len + toc_len + (SEGMENT_FOOTER_LEN as u64);
    if file_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "segment file exceeds 4GiB; not supported in v1 footer encoding".to_string(),
        });
    }

    let footer = SegmentFooterV1 {
        flags: 0x3, // SEALED|HAS_TOC
        shard_id,
        epoch,
        segment_seq,
        segment_id,
        created_at_unix_ns,
        sealed_at_unix_ns,
        file_len,
        record_area_offset,
        record_area_len,
        toc_offset,
        toc_len,
        toc_entry_count: toc_entries.len() as u64,
        min_stream_hash,
        min_seq,
        max_stream_hash,
        max_seq,
        header_hash: *header_hash.as_bytes(),
        record_hash: *record_hash.as_bytes(),
        toc_payload_hash,
        segment_hash,
    };
    let footer_bytes = encode_segment_footer_v1(&footer)?;

    // Final file assembly.
    let mut bytes = Vec::with_capacity(file_len as usize);
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(record_area);
    bytes.extend_from_slice(&toc_area);
    bytes.extend_from_slice(&footer_bytes);

    Ok(SegmentBuildOutput {
        bytes,
        header,
        toc_header,
        toc_entries,
        footer,
        record_crc32c_table,
        toc_crc32c_table,
    })
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    level = "info",
    skip(record_area, frames_by_offset),
    fields(
        shard_id,
        epoch,
        segment_seq,
        record_block_codec,
        record_area_len = record_area.len(),
        frame_count = frames_by_offset.len()
    )
)]
pub fn seal_segment_v1_from_record_area_with_block_codec(
    shard_id: u32,
    epoch: u64,
    segment_seq: u64,
    segment_id: SegmentId,
    created_at_unix_ns: u64,
    sealed_at_unix_ns: u64,
    record_block_codec: u32,
    record_area: &[u8],
    frames_by_offset: &[FrameMetaV1],
) -> Result<SegmentBuildOutput> {
    if record_block_codec == RECORD_BLOCK_CODEC_NONE_V1 {
        return seal_segment_v1_from_record_area(
            shard_id,
            epoch,
            segment_seq,
            segment_id,
            created_at_unix_ns,
            sealed_at_unix_ns,
            record_area,
            frames_by_offset,
        );
    }

    let header = SegmentHeaderV1 {
        flags: 1, // little_endian
        shard_id,
        epoch,
        segment_seq,
        segment_id,
        created_at_unix_ns,
    };
    let header_bytes = encode_segment_header_v1(&header)?;

    // Validate and build TOC/trailer metadata.
    let mut toc_entries: Vec<TocEntryV1> = Vec::with_capacity(frames_by_offset.len());
    let mut tmp: Vec<FrameMetaTmp> = Vec::with_capacity(frames_by_offset.len());

    let mut expected_off: u32 = 0;
    for f in frames_by_offset {
        if f.record_off != expected_off {
            return Err(SegmentError::LengthOutOfRange {
                msg: "frames_by_offset record_off is not contiguous".to_string(),
            });
        }
        let end = f
            .record_off
            .checked_add(f.frame_len)
            .ok_or(SegmentError::BufferTooSmall)? as usize;
        if end > record_area.len() {
            return Err(SegmentError::LengthOutOfRange {
                msg: "frames_by_offset points outside record area".to_string(),
            });
        }

        let file_offset = (SEGMENT_HEADER_LEN as u64)
            .checked_add(f.record_off as u64)
            .ok_or(SegmentError::BufferTooSmall)?;
        if file_offset > u32::MAX as u64 {
            return Err(SegmentError::LengthOutOfRange {
                msg: "file offset exceeds u32".to_string(),
            });
        }

        toc_entries.push(TocEntryV1 {
            stream_hash: f.stream_hash,
            seq: f.seq,
            file_offset: file_offset as u32,
            frame_len: f.frame_len,
            payload_len: f.payload_len,
            flags: 0,
            event_id_hash16: f.event_id_hash16,
            header_digest8: f.header_digest8,
            payload_digest8: f.payload_digest8,
        });

        tmp.push(FrameMetaTmp {
            stream_hash: f.stream_hash,
            seq: f.seq,
            event_id_hash16: f.event_id_hash16,
            header_digest8: f.header_digest8,
            payload_digest8: f.payload_digest8,
            record_off: f.record_off,
            frame_len: f.frame_len,
        });

        expected_off = expected_off.saturating_add(f.frame_len);
    }
    if expected_off as usize != record_area.len() {
        return Err(SegmentError::LengthOutOfRange {
            msg: "frames_by_offset does not cover record area".to_string(),
        });
    }

    toc_entries.sort_by(|a, b| match a.stream_hash.cmp(&b.stream_hash) {
        std::cmp::Ordering::Equal => a.seq.cmp(&b.seq),
        other => other,
    });
    if !is_sorted_toc(&toc_entries) {
        return Err(SegmentError::TocNotSorted);
    }

    let RecordBlocksAndTrailerIndexPartsV1 {
        record_area,
        blocks,
        toc_by_offset,
        toc_sorted_idx,
    } = build_record_blocks_and_trailer_index_parts_v1(record_area, &tmp, record_block_codec)?;
    let trailer_ext = encode_trailer_index_v1_from_parts(&blocks, &toc_by_offset, &toc_sorted_idx)?;

    let record_area_offset = SEGMENT_HEADER_LEN as u64;
    let record_area_len = record_area.len() as u64;
    if record_area_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "record area exceeds 4GiB; not supported in v1 footer encoding".to_string(),
        });
    }

    let toc_payload_len = (TOC_HEADER_LEN + toc_entries.len() * TOC_ENTRY_LEN) as u64;
    let record_crc32c_table = block_crc32c(&record_area, DEFAULT_RECORD_BLOCK_SIZE as usize);
    let toc_payload = encode_toc_payload_v1(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        (record_crc32c_table.len() * 4) as u64, // placeholder; fixed below
        &toc_entries,
    )?;

    let toc_crc32c_table = block_crc32c(&toc_payload, DEFAULT_TOC_BLOCK_SIZE as usize);

    let crc_tables_len = (record_crc32c_table.len() as u64 * 4) + (toc_crc32c_table.len() as u64 * 4);

    let toc_payload = encode_toc_payload_v1(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        &toc_entries,
    )?;

    let toc_payload_hash = compute_toc_payload_hash(&toc_payload)?;

    let toc_payload = encode_toc_payload_v1_with_hash(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        toc_payload_hash,
        &toc_entries,
    )?;

    let toc_crc32c_table = block_crc32c(&toc_payload, DEFAULT_TOC_BLOCK_SIZE as usize);
    let crc_tables_len = (record_crc32c_table.len() as u64 * 4) + (toc_crc32c_table.len() as u64 * 4);

    let toc_header = TocHeaderV1 {
        entry_count: toc_entries.len() as u64,
        record_block_size: DEFAULT_RECORD_BLOCK_SIZE,
        toc_block_size: DEFAULT_TOC_BLOCK_SIZE,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        sort_order: 1,
        toc_payload_hash,
    };

    let mut toc_area: Vec<u8> = Vec::with_capacity(toc_payload.len() + (crc_tables_len as usize));
    toc_area.extend_from_slice(&toc_payload);
    for c in &record_crc32c_table {
        toc_area.extend_from_slice(&c.to_le_bytes());
    }
    for c in &toc_crc32c_table {
        toc_area.extend_from_slice(&c.to_le_bytes());
    }
    toc_area.extend_from_slice(&trailer_ext);

    // Phase 9: pad TOC area with trailing zeros so (toc_len + footer_len) is 4KiB-aligned.
    // Header and record area are already 4KiB-aligned, so this makes the full file length aligned.
    let want = toc_area
        .len()
        .checked_add(SEGMENT_FOOTER_LEN)
        .ok_or(SegmentError::BufferTooSmall)?;
    let aligned = align_up(want, 4096);
    let pad = aligned.saturating_sub(want);
    if pad > 0 {
        toc_area.resize(toc_area.len().saturating_add(pad), 0u8);
    }

    let toc_offset = record_area_offset + record_area_len;
    let toc_len = toc_area.len() as u64;
    if toc_offset > u32::MAX as u64 || toc_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "toc offsets exceed u32".to_string(),
        });
    }

    let (min_stream_hash, min_seq, max_stream_hash, max_seq) = if toc_entries.is_empty() {
        (0, 0, 0, 0)
    } else {
        let first = toc_entries[0];
        let last = toc_entries[toc_entries.len() - 1];
        (first.stream_hash, first.seq, last.stream_hash, last.seq)
    };

    let header_hash = blake3::hash(&header_bytes);
    let record_hash = blake3::hash(&record_area);
    let segment_hash = {
        let mut h = Blake3::new();
        h.update(header_hash.as_bytes());
        h.update(record_hash.as_bytes());
        h.update(&toc_payload_hash);
        *h.finalize().as_bytes()
    };

    let file_len = (SEGMENT_HEADER_LEN as u64) + record_area_len + toc_len + (SEGMENT_FOOTER_LEN as u64);
    if file_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "segment file exceeds 4GiB; not supported in v1 footer encoding".to_string(),
        });
    }

    let footer = SegmentFooterV1 {
        flags: 0x3, // SEALED|HAS_TOC
        shard_id,
        epoch,
        segment_seq,
        segment_id,
        created_at_unix_ns,
        sealed_at_unix_ns,
        file_len,
        record_area_offset,
        record_area_len,
        toc_offset,
        toc_len,
        toc_entry_count: toc_entries.len() as u64,
        min_stream_hash,
        min_seq,
        max_stream_hash,
        max_seq,
        header_hash: *header_hash.as_bytes(),
        record_hash: *record_hash.as_bytes(),
        toc_payload_hash,
        segment_hash,
    };
    let footer_bytes = encode_segment_footer_v1(&footer)?;

    let mut bytes = Vec::with_capacity(file_len as usize);
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(&record_area);
    bytes.extend_from_slice(&toc_area);
    bytes.extend_from_slice(&footer_bytes);

    Ok(SegmentBuildOutput {
        bytes,
        header,
        toc_header,
        toc_entries,
        footer,
        record_crc32c_table,
        toc_crc32c_table,
    })
}

pub fn decode_trailer_index_v1(toc_area: &[u8], toc_header: &TocHeaderV1) -> Result<Option<TrailerIndexV1>> {
    let payload_len = toc_header.toc_payload_len as usize;
    let crc_tables_len = toc_header.crc_tables_len as usize;
    let ext_off = payload_len
        .checked_add(crc_tables_len)
        .ok_or(SegmentError::BufferTooSmall)?;
    if ext_off > toc_area.len() {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "toc header extension offset out of bounds".to_string(),
        });
    }
    let ext = &toc_area[ext_off..];
    if ext.is_empty() {
        return Ok(None);
    }

    let mut cursor = 0usize;

    let mut blk_section: Option<(u32, u32, u32, Vec<BlockMetaV1>)> = None;
    let mut tbo_section: Option<Vec<TocByOffsetEntryV1>> = None;
    let mut tsi_section: Option<Vec<u32>> = None;

    while cursor < ext.len() {
        // Phase 9: allow trailing zero padding in the TOC extension area so the overall segment
        // file length can be 4KiB-aligned for GPUDirect Storage (O_DIRECT) without changing the
        // footer layout. Padding bytes must be all zero.
        if ext[cursor..].iter().all(|&b| b == 0) {
            break;
        }
        if ext.len() - cursor < TRAILER_SECTION_HEADER_LEN_V1 {
            return Err(SegmentError::TrailerSectionInvalid {
                msg: "trailer section header truncated".to_string(),
            });
        }
        let hdr = &ext[cursor..cursor + TRAILER_SECTION_HEADER_LEN_V1];
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let version = u16::from_le_bytes(hdr[4..6].try_into().unwrap());
        let header_len = u16::from_le_bytes(hdr[6..8].try_into().unwrap()) as usize;
        if version != 1 || header_len != TRAILER_SECTION_HEADER_LEN_V1 {
            return Err(SegmentError::TrailerSectionInvalid {
                msg: format!("unsupported trailer section header (magic={magic:#x})"),
            });
        }
        let payload_len = u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as usize;
        let expected_crc = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
        cursor += header_len;
        let end = cursor.checked_add(payload_len).ok_or(SegmentError::BufferTooSmall)?;
        if end > ext.len() {
            return Err(SegmentError::TrailerSectionInvalid {
                msg: "trailer section payload out of bounds".to_string(),
            });
        }
        let payload = &ext[cursor..end];
        let actual_crc = crc32c::crc32c(payload);
        if actual_crc != expected_crc {
            return Err(SegmentError::TrailerSectionInvalid {
                msg: format!("trailer section crc mismatch (magic={magic:#x})"),
            });
        }
        cursor = end;

        match magic {
            TRAILER_MAGIC_BLK1 => {
                blk_section = Some(decode_blk1_payload(payload)?);
            }
            TRAILER_MAGIC_TBO1 => {
                tbo_section = Some(decode_tbo1_payload(payload)?);
            }
            TRAILER_MAGIC_TSI1 => {
                tsi_section = Some(decode_tsi1_payload(payload)?);
            }
            _ => {
                // Unknown section; ignore for forward compatibility.
            }
        }
    }

    let Some((record_block_uncompressed_max_len, bloom_bytes_per_block, bloom_hash_k, blocks)) = blk_section else {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "missing BLK1 section".to_string(),
        });
    };
    let Some(toc_by_offset) = tbo_section else {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "missing TBO1 section".to_string(),
        });
    };
    let Some(toc_sorted_idx) = tsi_section else {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "missing TSI1 section".to_string(),
        });
    };

    if toc_sorted_idx.len() != toc_by_offset.len() {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "toc_sorted_idx length does not match toc_by_offset length".to_string(),
        });
    }
    for &idx in &toc_sorted_idx {
        if idx as usize >= toc_by_offset.len() {
            return Err(SegmentError::TrailerSectionInvalid {
                msg: "toc_sorted_idx contains out-of-bounds index".to_string(),
            });
        }
    }

    Ok(Some(TrailerIndexV1 {
        record_block_uncompressed_max_len,
        bloom_bytes_per_block,
        bloom_hash_k,
        blocks,
        toc_by_offset,
        toc_sorted_idx,
    }))
}

fn encode_trailer_index_v1(record_area: &[u8], frames: &[FrameMetaTmp]) -> Result<Vec<u8>> {
    let mut block_starts: Vec<usize> = Vec::new();
    let mut block_lens: Vec<usize> = Vec::new();
    let mut block_blooms: Vec<[u8; BLOOM_BYTES_PER_BLOCK_V1]> = Vec::new();

    let mut frame_block_id: Vec<u32> = vec![0u32; frames.len()];

    let max_len = RECORD_BLOCK_UNCOMPRESSED_MAX_LEN_V1 as usize;
    let mut cur_start: Option<usize> = None;
    let mut cur_len: usize = 0;
    let mut cur_bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];

    for (i, f) in frames.iter().enumerate() {
        let flen = f.frame_len as usize;
        if cur_len > 0 && cur_len.saturating_add(flen) > max_len {
            // Finalize current block.
            block_starts.push(cur_start.unwrap_or(0));
            block_lens.push(cur_len);
            block_blooms.push(cur_bloom);
            cur_start = None;
            cur_len = 0;
            cur_bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];
        }
        if cur_len == 0 {
            cur_start = Some(f.record_off as usize);
        }
        let block_id = block_starts.len() as u32;
        frame_block_id[i] = block_id;
        bloom_insert_stream_hash_v1(&mut cur_bloom, BLOOM_HASH_K_V1, f.stream_hash);
        cur_len = cur_len.saturating_add(flen);
    }
    if cur_len > 0 {
        block_starts.push(cur_start.unwrap_or(0));
        block_lens.push(cur_len);
        block_blooms.push(cur_bloom);
    }

    // Encode BLK1.
    let mut blocks: Vec<BlockMetaV1> = Vec::with_capacity(block_starts.len());
    for (i, (&start, &len)) in block_starts.iter().zip(block_lens.iter()).enumerate() {
        let file_offset = (SEGMENT_HEADER_LEN + start) as u64;
        let end = start.checked_add(len).ok_or(SegmentError::BufferTooSmall)?;
        if end > record_area.len() {
            return Err(SegmentError::TrailerSectionInvalid {
                msg: "block spans past record area".to_string(),
            });
        }
        let bytes = &record_area[start..end];
        let crc32c = crc32c::crc32c(bytes);
        blocks.push(BlockMetaV1 {
            block_id: i as u32,
            codec: 0,
            file_offset,
            compressed_len: len as u32,
            physical_len: 0, // legacy: encode as 0 (meaning "same as compressed_len")
            uncompressed_len: len as u32,
            crc32c,
            bloom: block_blooms[i],
        });
    }

    let blk_payload = encode_blk1_payload(&blocks)?;
    let blk_section = encode_trailer_section_v1(TRAILER_MAGIC_BLK1, &blk_payload);

    // Encode TBO1.
    let mut toc_by_offset: Vec<TocByOffsetEntryV1> = Vec::with_capacity(frames.len());
    for (i, f) in frames.iter().enumerate() {
        let bid = frame_block_id[i] as usize;
        let block_start = block_starts.get(bid).copied().unwrap_or(0) as u32;
        let in_block_offset = f.record_off.saturating_sub(block_start);
        toc_by_offset.push(TocByOffsetEntryV1 {
            stream_hash: f.stream_hash,
            seq: f.seq,
            block_id: frame_block_id[i],
            in_block_offset,
            frame_len: f.frame_len,
            flags: 0,
            event_id_hash16: f.event_id_hash16,
            header_digest8: f.header_digest8,
            payload_digest8: f.payload_digest8,
        });
    }

    let tbo_payload = encode_tbo1_payload(&toc_by_offset)?;
    let tbo_section = encode_trailer_section_v1(TRAILER_MAGIC_TBO1, &tbo_payload);

    // Encode TSI1.
    let mut sorted_idx: Vec<u32> = (0..toc_by_offset.len() as u32).collect();
    sorted_idx.sort_by(|&a, &b| {
        let ea = toc_by_offset[a as usize];
        let eb = toc_by_offset[b as usize];
        (ea.stream_hash, ea.seq, ea.block_id, ea.in_block_offset).cmp(&(
            eb.stream_hash,
            eb.seq,
            eb.block_id,
            eb.in_block_offset,
        ))
    });

    let tsi_payload = encode_tsi1_payload(&sorted_idx)?;
    let tsi_section = encode_trailer_section_v1(TRAILER_MAGIC_TSI1, &tsi_payload);

    let mut out = Vec::with_capacity(blk_section.len() + tbo_section.len() + tsi_section.len());
    out.extend_from_slice(&blk_section);
    out.extend_from_slice(&tbo_section);
    out.extend_from_slice(&tsi_section);
    Ok(out)
}

#[derive(Debug)]
struct RecordBlocksAndTrailerIndexPartsV1 {
    record_area: Vec<u8>,
    blocks: Vec<BlockMetaV1>,
    toc_by_offset: Vec<TocByOffsetEntryV1>,
    toc_sorted_idx: Vec<u32>,
}

fn build_record_blocks_and_trailer_index_parts_v1(
    record_area_uncompressed: &[u8],
    frames: &[FrameMetaTmp],
    record_block_codec: u32,
) -> Result<RecordBlocksAndTrailerIndexPartsV1> {
    if record_block_codec != RECORD_BLOCK_CODEC_NONE_V1 && record_block_codec != RECORD_BLOCK_CODEC_LZ4_V1 {
        return Err(SegmentError::LengthOutOfRange {
            msg: format!("unsupported record_block_codec {record_block_codec}"),
        });
    }

    let mut block_starts: Vec<usize> = Vec::new();
    let mut block_lens: Vec<usize> = Vec::new();
    let mut block_blooms: Vec<[u8; BLOOM_BYTES_PER_BLOCK_V1]> = Vec::new();

    let mut frame_block_id: Vec<u32> = vec![0u32; frames.len()];

    let max_len = RECORD_BLOCK_UNCOMPRESSED_MAX_LEN_V1 as usize;
    let mut cur_start: Option<usize> = None;
    let mut cur_len: usize = 0;
    let mut cur_bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];

    for (i, f) in frames.iter().enumerate() {
        let flen = f.frame_len as usize;
        if cur_len > 0 && cur_len.saturating_add(flen) > max_len {
            // Finalize current block.
            block_starts.push(cur_start.unwrap_or(0));
            block_lens.push(cur_len);
            block_blooms.push(cur_bloom);
            cur_start = None;
            cur_len = 0;
            cur_bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];
        }
        if cur_len == 0 {
            cur_start = Some(f.record_off as usize);
        }
        let block_id = block_starts.len() as u32;
        frame_block_id[i] = block_id;
        bloom_insert_stream_hash_v1(&mut cur_bloom, BLOOM_HASH_K_V1, f.stream_hash);
        cur_len = cur_len.saturating_add(flen);
    }
    if cur_len > 0 {
        block_starts.push(cur_start.unwrap_or(0));
        block_lens.push(cur_len);
        block_blooms.push(cur_bloom);
    }

    // Build physical record bytes and BLK1 metadata.
    let mut record_area: Vec<u8> = Vec::new();
    let mut blocks: Vec<BlockMetaV1> = Vec::with_capacity(block_starts.len());
    for (i, (&start, &len)) in block_starts.iter().zip(block_lens.iter()).enumerate() {
        let end = start.checked_add(len).ok_or(SegmentError::BufferTooSmall)?;
        if end > record_area_uncompressed.len() {
            return Err(SegmentError::TrailerSectionInvalid {
                msg: "block spans past uncompressed record area".to_string(),
            });
        }
        let uncompressed = &record_area_uncompressed[start..end];
        let crc32c = crc32c::crc32c(uncompressed);

        let (codec, compressed_bytes) = match record_block_codec {
            RECORD_BLOCK_CODEC_NONE_V1 => (RECORD_BLOCK_CODEC_NONE_V1, uncompressed.to_vec()),
            RECORD_BLOCK_CODEC_LZ4_V1 => (RECORD_BLOCK_CODEC_LZ4_V1, lz4_flex::block::compress(uncompressed)),
            _ => unreachable!("validated above"),
        };

        if compressed_bytes.len() > u32::MAX as usize {
            return Err(SegmentError::LengthOutOfRange {
                msg: "compressed block len exceeds u32".to_string(),
            });
        }
        if len > u32::MAX as usize {
            return Err(SegmentError::LengthOutOfRange {
                msg: "uncompressed block len exceeds u32".to_string(),
            });
        }

        // Phase 9: pad physical record bytes so each block begins on a 4KiB boundary (GPU-direct IO).
        let aligned = align_up(record_area.len(), 4096);
        if aligned != record_area.len() {
            record_area.resize(aligned, 0u8);
        }
        let file_offset = (SEGMENT_HEADER_LEN as u64)
            .checked_add(record_area.len() as u64)
            .ok_or(SegmentError::BufferTooSmall)?;

        record_area.extend_from_slice(&compressed_bytes);
        let physical_len = align_up(compressed_bytes.len(), 4096);
        if physical_len > u32::MAX as usize {
            return Err(SegmentError::LengthOutOfRange {
                msg: "physical block len exceeds u32".to_string(),
            });
        }
        if physical_len != compressed_bytes.len() {
            record_area.resize(record_area.len() + (physical_len - compressed_bytes.len()), 0u8);
        }

        blocks.push(BlockMetaV1 {
            block_id: i as u32,
            codec,
            file_offset,
            compressed_len: compressed_bytes.len() as u32,
            physical_len: physical_len as u32,
            uncompressed_len: len as u32,
            crc32c,
            bloom: block_blooms[i],
        });
    }

    // Build TBO1/TSI1.
    let mut toc_by_offset: Vec<TocByOffsetEntryV1> = Vec::with_capacity(frames.len());
    for (i, f) in frames.iter().enumerate() {
        let bid = frame_block_id[i] as usize;
        let block_start = block_starts.get(bid).copied().unwrap_or(0) as u32;
        let in_block_offset = f.record_off.saturating_sub(block_start);
        toc_by_offset.push(TocByOffsetEntryV1 {
            stream_hash: f.stream_hash,
            seq: f.seq,
            block_id: frame_block_id[i],
            in_block_offset,
            frame_len: f.frame_len,
            flags: 0,
            event_id_hash16: f.event_id_hash16,
            header_digest8: f.header_digest8,
            payload_digest8: f.payload_digest8,
        });
    }

    let mut toc_sorted_idx: Vec<u32> = (0..toc_by_offset.len() as u32).collect();
    toc_sorted_idx.sort_by(|&a, &b| {
        let ea = toc_by_offset[a as usize];
        let eb = toc_by_offset[b as usize];
        (ea.stream_hash, ea.seq, ea.block_id, ea.in_block_offset).cmp(&(
            eb.stream_hash,
            eb.seq,
            eb.block_id,
            eb.in_block_offset,
        ))
    });

    Ok(RecordBlocksAndTrailerIndexPartsV1 {
        record_area,
        blocks,
        toc_by_offset,
        toc_sorted_idx,
    })
}

fn encode_trailer_index_v1_from_parts(
    blocks: &[BlockMetaV1],
    toc_by_offset: &[TocByOffsetEntryV1],
    toc_sorted_idx: &[u32],
) -> Result<Vec<u8>> {
    let blk_payload = encode_blk1_payload(blocks)?;
    let blk_section = encode_trailer_section_v1(TRAILER_MAGIC_BLK1, &blk_payload);

    let tbo_payload = encode_tbo1_payload(toc_by_offset)?;
    let tbo_section = encode_trailer_section_v1(TRAILER_MAGIC_TBO1, &tbo_payload);

    let tsi_payload = encode_tsi1_payload(toc_sorted_idx)?;
    let tsi_section = encode_trailer_section_v1(TRAILER_MAGIC_TSI1, &tsi_payload);

    let mut out = Vec::with_capacity(blk_section.len() + tbo_section.len() + tsi_section.len());
    out.extend_from_slice(&blk_section);
    out.extend_from_slice(&tbo_section);
    out.extend_from_slice(&tsi_section);
    Ok(out)
}

fn encode_trailer_section_v1(magic: u32, payload: &[u8]) -> Vec<u8> {
    let mut hdr = [0u8; TRAILER_SECTION_HEADER_LEN_V1];
    hdr[0..4].copy_from_slice(&magic.to_le_bytes());
    hdr[4..6].copy_from_slice(&1u16.to_le_bytes()); // version
    hdr[6..8].copy_from_slice(&(TRAILER_SECTION_HEADER_LEN_V1 as u16).to_le_bytes());
    hdr[8..12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    let crc = crc32c::crc32c(payload);
    hdr[12..16].copy_from_slice(&crc.to_le_bytes());
    // reserved left zero
    let mut out = Vec::with_capacity(hdr.len() + payload.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(payload);
    out
}

pub fn bloom_insert_stream_hash_v1(bits: &mut [u8; BLOOM_BYTES_PER_BLOCK_V1], bloom_hash_k: u32, stream_hash: u64) {
    let key = stream_hash.to_le_bytes();
    let m = (BLOOM_BYTES_PER_BLOCK_V1 as u64) * 8;
    for seed in 0..bloom_hash_k {
        let h = xxh64(&key, seed as u64);
        let bit = (h % m) as usize;
        let byte = bit / 8;
        let mask = 1u8 << (bit % 8);
        bits[byte] |= mask;
    }
}

pub fn bloom_maybe_contains_stream_hash_v1(
    bits: &[u8; BLOOM_BYTES_PER_BLOCK_V1],
    bloom_hash_k: u32,
    stream_hash: u64,
) -> bool {
    let key = stream_hash.to_le_bytes();
    let m = (BLOOM_BYTES_PER_BLOCK_V1 as u64) * 8;
    for seed in 0..bloom_hash_k {
        let h = xxh64(&key, seed as u64);
        let bit = (h % m) as usize;
        let byte = bit / 8;
        let mask = 1u8 << (bit % 8);
        if (bits[byte] & mask) == 0 {
            return false;
        }
    }
    true
}

fn encode_blk1_payload(blocks: &[BlockMetaV1]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(16 + blocks.len() * BLOCK_META_V1_LEN);
    out.extend_from_slice(&RECORD_BLOCK_UNCOMPRESSED_MAX_LEN_V1.to_le_bytes());
    out.extend_from_slice(&(BLOOM_BYTES_PER_BLOCK_V1 as u32).to_le_bytes());
    out.extend_from_slice(&BLOOM_HASH_K_V1.to_le_bytes());
    out.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
    for b in blocks {
        out.extend_from_slice(&encode_block_meta_v1(b));
    }
    Ok(out)
}

fn decode_blk1_payload(payload: &[u8]) -> Result<(u32, u32, u32, Vec<BlockMetaV1>)> {
    if payload.len() < 16 {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "BLK1 payload too small".to_string(),
        });
    }
    let record_block_uncompressed_max_len = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    let bloom_bytes_per_block = u32::from_le_bytes(payload[4..8].try_into().unwrap());
    let bloom_hash_k = u32::from_le_bytes(payload[8..12].try_into().unwrap());
    let block_count = u32::from_le_bytes(payload[12..16].try_into().unwrap()) as usize;
    if bloom_bytes_per_block as usize != BLOOM_BYTES_PER_BLOCK_V1 {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "unsupported bloom_bytes_per_block".to_string(),
        });
    }
    let expected = 16usize
        .checked_add(
            block_count
                .checked_mul(BLOCK_META_V1_LEN)
                .ok_or(SegmentError::BufferTooSmall)?,
        )
        .ok_or(SegmentError::BufferTooSmall)?;
    if payload.len() != expected {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "BLK1 payload length mismatch".to_string(),
        });
    }
    let mut blocks = Vec::with_capacity(block_count);
    let mut off = 16usize;
    for _ in 0..block_count {
        let end = off + BLOCK_META_V1_LEN;
        blocks.push(decode_block_meta_v1(&payload[off..end])?);
        off = end;
    }
    Ok((
        record_block_uncompressed_max_len,
        bloom_bytes_per_block,
        bloom_hash_k,
        blocks,
    ))
}

fn encode_tbo1_payload(entries: &[TocByOffsetEntryV1]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + entries.len().checked_mul(TOC_BY_OFFSET_ENTRY_V1_LEN).unwrap_or(0));
    out.extend_from_slice(&(TOC_BY_OFFSET_ENTRY_V1_LEN as u32).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        out.extend_from_slice(&encode_toc_by_offset_entry_v1(e));
    }
    Ok(out)
}

fn decode_tbo1_payload(payload: &[u8]) -> Result<Vec<TocByOffsetEntryV1>> {
    if payload.len() < 8 {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "TBO1 payload too small".to_string(),
        });
    }
    let entry_len = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    if entry_len != TOC_BY_OFFSET_ENTRY_V1_LEN {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "unsupported toc_by_offset entry_len".to_string(),
        });
    }
    let count = u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;
    let expected = 8usize
        .checked_add(count.checked_mul(entry_len).ok_or(SegmentError::BufferTooSmall)?)
        .ok_or(SegmentError::BufferTooSmall)?;
    if payload.len() != expected {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "TBO1 payload length mismatch".to_string(),
        });
    }
    let mut entries = Vec::with_capacity(count);
    let mut off = 8usize;
    for _ in 0..count {
        let end = off + entry_len;
        entries.push(decode_toc_by_offset_entry_v1(&payload[off..end])?);
        off = end;
    }
    Ok(entries)
}

fn encode_tsi1_payload(sorted_idx: &[u32]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + sorted_idx.len() * 4);
    out.extend_from_slice(&(sorted_idx.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved
    for &v in sorted_idx {
        out.extend_from_slice(&v.to_le_bytes());
    }
    Ok(out)
}

fn decode_tsi1_payload(payload: &[u8]) -> Result<Vec<u32>> {
    if payload.len() < 8 {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "TSI1 payload too small".to_string(),
        });
    }
    let count = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    let expected = 8usize
        .checked_add(count.checked_mul(4).ok_or(SegmentError::BufferTooSmall)?)
        .ok_or(SegmentError::BufferTooSmall)?;
    if payload.len() != expected {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "TSI1 payload length mismatch".to_string(),
        });
    }
    let mut out = Vec::with_capacity(count);
    let mut off = 8usize;
    for _ in 0..count {
        out.push(u32::from_le_bytes(payload[off..off + 4].try_into().unwrap()));
        off += 4;
    }
    Ok(out)
}

pub fn encode_block_meta_v1(b: &BlockMetaV1) -> [u8; BLOCK_META_V1_LEN] {
    let mut out = [0u8; BLOCK_META_V1_LEN];
    out[0..4].copy_from_slice(&b.block_id.to_le_bytes());
    out[4..8].copy_from_slice(&b.codec.to_le_bytes());
    out[8..16].copy_from_slice(&b.file_offset.to_le_bytes());
    out[16..20].copy_from_slice(&b.compressed_len.to_le_bytes());
    out[20..24].copy_from_slice(&b.uncompressed_len.to_le_bytes());
    out[24..28].copy_from_slice(&b.crc32c.to_le_bytes());
    // reserved [28..32] used for physical_len (0 means "same as compressed_len" for legacy blocks)
    out[28..32].copy_from_slice(&b.physical_len.to_le_bytes());
    out[32..32 + BLOOM_BYTES_PER_BLOCK_V1].copy_from_slice(&b.bloom);
    out
}

fn decode_block_meta_v1(bytes: &[u8]) -> Result<BlockMetaV1> {
    if bytes.len() != BLOCK_META_V1_LEN {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "block meta length mismatch".to_string(),
        });
    }
    let block_id = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let codec = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let file_offset = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let compressed_len = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let uncompressed_len = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    let crc32c = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
    let physical_len = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
    let mut bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];
    bloom.copy_from_slice(&bytes[32..32 + BLOOM_BYTES_PER_BLOCK_V1]);
    let physical_len = if physical_len == 0 {
        compressed_len
    } else {
        physical_len
    };
    Ok(BlockMetaV1 {
        block_id,
        codec,
        file_offset,
        compressed_len,
        physical_len,
        uncompressed_len,
        crc32c,
        bloom,
    })
}

pub fn encode_toc_by_offset_entry_v1(e: &TocByOffsetEntryV1) -> [u8; TOC_BY_OFFSET_ENTRY_V1_LEN] {
    let mut out = [0u8; TOC_BY_OFFSET_ENTRY_V1_LEN];
    out[0..8].copy_from_slice(&e.stream_hash.to_le_bytes());
    out[8..16].copy_from_slice(&e.seq.to_le_bytes());
    out[16..20].copy_from_slice(&e.block_id.to_le_bytes());
    out[20..24].copy_from_slice(&e.in_block_offset.to_le_bytes());
    out[24..28].copy_from_slice(&e.frame_len.to_le_bytes());
    out[28..32].copy_from_slice(&e.flags.to_le_bytes());
    out[32..48].copy_from_slice(&e.event_id_hash16);
    out[48..56].copy_from_slice(&e.header_digest8);
    out[56..64].copy_from_slice(&e.payload_digest8);
    out
}

fn decode_toc_by_offset_entry_v1(bytes: &[u8]) -> Result<TocByOffsetEntryV1> {
    if bytes.len() != TOC_BY_OFFSET_ENTRY_V1_LEN {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "toc_by_offset entry length mismatch".to_string(),
        });
    }
    let stream_hash = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let seq = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let block_id = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let in_block_offset = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    let frame_len = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
    let flags = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
    let mut event_id_hash16 = [0u8; 16];
    event_id_hash16.copy_from_slice(&bytes[32..48]);
    let mut header_digest8 = [0u8; 8];
    header_digest8.copy_from_slice(&bytes[48..56]);
    let mut payload_digest8 = [0u8; 8];
    payload_digest8.copy_from_slice(&bytes[56..64]);
    Ok(TocByOffsetEntryV1 {
        stream_hash,
        seq,
        block_id,
        in_block_offset,
        frame_len,
        flags,
        event_id_hash16,
        header_digest8,
        payload_digest8,
    })
}

pub fn decode_segment_v1(bytes: &[u8]) -> Result<(SegmentHeaderV1, TocHeaderV1, Vec<TocEntryV1>, SegmentFooterV1)> {
    if bytes.len() < SEGMENT_HEADER_LEN + SEGMENT_FOOTER_LEN {
        return Err(SegmentError::BufferTooSmall);
    }
    let header_bytes = &bytes[..SEGMENT_HEADER_LEN];
    let header = decode_segment_header_v1(header_bytes)?;

    let footer_bytes = &bytes[bytes.len() - SEGMENT_FOOTER_LEN..];
    let footer = decode_segment_footer_v1(footer_bytes)?;

    if footer.flags & 0x1 == 0 {
        return Err(SegmentError::NotSealed);
    }
    if footer.file_len != bytes.len() as u64 {
        return Err(SegmentError::FileLenMismatch {
            declared: footer.file_len,
            actual: bytes.len() as u64,
        });
    }
    if footer.segment_id != header.segment_id
        || footer.segment_seq != header.segment_seq
        || footer.epoch != header.epoch
        || footer.shard_id != header.shard_id
    {
        return Err(SegmentError::HashMismatch {
            msg: "identity mismatch between header and footer".to_string(),
        });
    }

    // Validate header crc already checked; validate footer crc already checked. Verify strong hashes.
    let header_hash = blake3::hash(header_bytes);
    if *header_hash.as_bytes() != footer.header_hash {
        return Err(SegmentError::HashMismatch {
            msg: "header_hash mismatch".to_string(),
        });
    }

    let record_off = footer.record_area_offset as usize;
    let record_len = footer.record_area_len as usize;
    if record_off + record_len > bytes.len() {
        return Err(SegmentError::BufferTooSmall);
    }
    let record_area = &bytes[record_off..record_off + record_len];
    let record_hash = blake3::hash(record_area);
    if *record_hash.as_bytes() != footer.record_hash {
        return Err(SegmentError::HashMismatch {
            msg: "record_hash mismatch".to_string(),
        });
    }

    let toc_off = footer.toc_offset as usize;
    let toc_len = footer.toc_len as usize;
    if toc_off + toc_len + SEGMENT_FOOTER_LEN != bytes.len() {
        return Err(SegmentError::LengthOutOfRange {
            msg: "toc/record/footer lengths do not line up".to_string(),
        });
    }
    let toc_area = &bytes[toc_off..toc_off + toc_len];
    if toc_area.len() < TOC_HEADER_LEN {
        return Err(SegmentError::BufferTooSmall);
    }
    let toc_payload_len = read_u64(toc_area, 40)?; // toc_payload_len field offset
    let toc_payload_len = toc_payload_len as usize;
    if toc_payload_len > toc_area.len() {
        return Err(SegmentError::BufferTooSmall);
    }
    let toc_payload = &toc_area[..toc_payload_len];
    let toc_header = decode_toc_header_v1(&toc_payload[..TOC_HEADER_LEN])?;

    if toc_header.toc_payload_hash != footer.toc_payload_hash {
        return Err(SegmentError::HashMismatch {
            msg: "toc_payload_hash mismatch between toc header and footer".to_string(),
        });
    }

    // Verify toc_payload_hash.
    let computed_toc_payload_hash = compute_toc_payload_hash(toc_payload)?;
    if computed_toc_payload_hash != toc_header.toc_payload_hash {
        return Err(SegmentError::HashMismatch {
            msg: "toc_payload_hash mismatch".to_string(),
        });
    }

    // Verify segment_hash.
    let seg_hash = {
        let mut h = Blake3::new();
        h.update(&footer.header_hash);
        h.update(&footer.record_hash);
        h.update(&footer.toc_payload_hash);
        *h.finalize().as_bytes()
    };
    if seg_hash != footer.segment_hash {
        return Err(SegmentError::HashMismatch {
            msg: "segment_hash mismatch".to_string(),
        });
    }

    // Decode entries.
    let entry_count = toc_header.entry_count as usize;
    let entries_off = TOC_HEADER_LEN;
    let entries_len = entry_count
        .checked_mul(TOC_ENTRY_LEN)
        .ok_or(SegmentError::BufferTooSmall)?;
    if entries_off + entries_len > toc_payload.len() {
        return Err(SegmentError::BufferTooSmall);
    }
    let mut entries = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let start = entries_off + i * TOC_ENTRY_LEN;
        let end = start + TOC_ENTRY_LEN;
        entries.push(decode_toc_entry_v1(&toc_payload[start..end])?);
    }
    if !is_sorted_toc(&entries) {
        return Err(SegmentError::TocNotSorted);
    }

    Ok((header, toc_header, entries, footer))
}

pub fn encode_segment_header_v1(h: &SegmentHeaderV1) -> Result<Vec<u8>> {
    let mut out = vec![0u8; SEGMENT_HEADER_LEN];
    out[0..4].copy_from_slice(&SEGMENT_MAGIC_CCS3.to_le_bytes());
    out[4..6].copy_from_slice(&SEGMENT_MAJOR.to_le_bytes());
    out[6..8].copy_from_slice(&SEGMENT_MINOR.to_le_bytes());
    out[8..12].copy_from_slice(&(SEGMENT_HEADER_LEN as u32).to_le_bytes());
    out[12..16].copy_from_slice(&h.flags.to_le_bytes());
    out[16..20].copy_from_slice(&h.shard_id.to_le_bytes());
    out[20..28].copy_from_slice(&h.epoch.to_le_bytes());
    out[28..36].copy_from_slice(&h.segment_seq.to_le_bytes());
    out[36..52].copy_from_slice(&h.segment_id.0);
    out[52..60].copy_from_slice(&h.created_at_unix_ns.to_le_bytes());

    let crc = crc32c::crc32c(&out[..SEGMENT_HEADER_LEN - 4]);
    out[SEGMENT_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
    Ok(out)
}

pub fn decode_segment_header_v1(bytes: &[u8]) -> Result<SegmentHeaderV1> {
    if bytes.len() < SEGMENT_HEADER_LEN {
        return Err(SegmentError::BufferTooSmall);
    }
    let magic = read_u32(bytes, 0)?;
    if magic != SEGMENT_MAGIC_CCS3 {
        return Err(SegmentError::InvalidMagic {
            expected: SEGMENT_MAGIC_CCS3,
            actual: magic,
        });
    }
    let major = read_u16(bytes, 4)?;
    let minor = read_u16(bytes, 6)?;
    if major != SEGMENT_MAJOR || minor != SEGMENT_MINOR {
        return Err(SegmentError::UnsupportedSegmentVersion { major, minor });
    }
    let header_len = read_u32(bytes, 8)? as usize;
    if header_len != SEGMENT_HEADER_LEN {
        return Err(SegmentError::LengthOutOfRange {
            msg: format!("header_len expected {SEGMENT_HEADER_LEN}, got {header_len}"),
        });
    }

    let expected = read_u32(bytes, SEGMENT_HEADER_LEN - 4)?;
    let actual = crc32c::crc32c(&bytes[..SEGMENT_HEADER_LEN - 4]);
    if expected != actual {
        return Err(SegmentError::CrcMismatch { expected, actual });
    }

    let flags = read_u32(bytes, 12)?;
    let shard_id = read_u32(bytes, 16)?;
    let epoch = read_u64(bytes, 20)?;
    let segment_seq = read_u64(bytes, 28)?;
    let mut seg_id = [0u8; 16];
    seg_id.copy_from_slice(&bytes[36..52]);
    let created_at_unix_ns = read_u64(bytes, 52)?;

    Ok(SegmentHeaderV1 {
        flags,
        shard_id,
        epoch,
        segment_seq,
        segment_id: SegmentId(seg_id),
        created_at_unix_ns,
    })
}

fn encode_toc_payload_v1(
    entry_count: u64,
    record_area_offset: u64,
    record_area_len: u64,
    toc_payload_len: u64,
    crc_tables_len: u64,
    entries: &[TocEntryV1],
) -> Result<Vec<u8>> {
    encode_toc_payload_v1_with_hash(
        entry_count,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        [0u8; 32],
        entries,
    )
}

fn encode_toc_payload_v1_with_hash(
    entry_count: u64,
    record_area_offset: u64,
    record_area_len: u64,
    toc_payload_len: u64,
    crc_tables_len: u64,
    toc_payload_hash: [u8; 32],
    entries: &[TocEntryV1],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(toc_payload_len as usize);

    let mut hdr = [0u8; TOC_HEADER_LEN];
    hdr[0..4].copy_from_slice(&TOC_MAGIC_TOC1.to_le_bytes());
    hdr[4..6].copy_from_slice(&1u16.to_le_bytes());
    hdr[6..8].copy_from_slice(&(TOC_ENTRY_LEN as u16).to_le_bytes());
    hdr[8..16].copy_from_slice(&entry_count.to_le_bytes());
    hdr[16..20].copy_from_slice(&DEFAULT_RECORD_BLOCK_SIZE.to_le_bytes());
    hdr[20..24].copy_from_slice(&DEFAULT_TOC_BLOCK_SIZE.to_le_bytes());
    hdr[24..32].copy_from_slice(&record_area_offset.to_le_bytes());
    hdr[32..40].copy_from_slice(&record_area_len.to_le_bytes());
    hdr[40..48].copy_from_slice(&toc_payload_len.to_le_bytes());
    hdr[48..56].copy_from_slice(&crc_tables_len.to_le_bytes());
    hdr[56..64].copy_from_slice(&1u64.to_le_bytes()); // sort order
                                                      // reserved0 [64..72] left zero
    hdr[72..104].copy_from_slice(&toc_payload_hash);
    // reserved padding [104..120] left zero
    // reserved1 at [120..124] left zero

    let crc = crc32c::crc32c(&hdr[..TOC_HEADER_LEN - 4]);
    hdr[TOC_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());

    out.extend_from_slice(&hdr);
    for e in entries {
        out.extend_from_slice(&encode_toc_entry_v1(e));
    }
    Ok(out)
}

fn compute_toc_payload_hash(toc_payload_bytes: &[u8]) -> Result<[u8; 32]> {
    if toc_payload_bytes.len() < TOC_HEADER_LEN {
        return Err(SegmentError::BufferTooSmall);
    }
    let mut tmp = toc_payload_bytes.to_vec();
    // Exclude the toc_payload_hash field itself from the hash by treating it as all zeros.
    for b in &mut tmp[72..104] {
        *b = 0;
    }
    // Also ignore toc_header_crc32c while hashing.
    for b in &mut tmp[TOC_HEADER_LEN - 4..TOC_HEADER_LEN] {
        *b = 0;
    }
    Ok(*blake3::hash(&tmp).as_bytes())
}

pub fn decode_toc_header_v1(bytes: &[u8]) -> Result<TocHeaderV1> {
    if bytes.len() < TOC_HEADER_LEN {
        return Err(SegmentError::BufferTooSmall);
    }
    let magic = read_u32(bytes, 0)?;
    if magic != TOC_MAGIC_TOC1 {
        return Err(SegmentError::InvalidMagic {
            expected: TOC_MAGIC_TOC1,
            actual: magic,
        });
    }
    let ver = read_u16(bytes, 4)?;
    if ver != 1 {
        return Err(SegmentError::UnsupportedTocVersion { version: ver });
    }
    let entry_size = read_u16(bytes, 6)? as usize;
    if entry_size != TOC_ENTRY_LEN {
        return Err(SegmentError::LengthOutOfRange {
            msg: format!("entry_size expected {TOC_ENTRY_LEN}, got {entry_size}"),
        });
    }

    let expected = read_u32(bytes, TOC_HEADER_LEN - 4)?;
    let mut tmp = bytes.to_vec();
    for b in &mut tmp[TOC_HEADER_LEN - 4..] {
        *b = 0;
    }
    let actual = crc32c::crc32c(&tmp[..TOC_HEADER_LEN - 4]);
    if expected != actual {
        return Err(SegmentError::CrcMismatch { expected, actual });
    }

    let entry_count = read_u64(bytes, 8)?;
    let record_block_size = read_u32(bytes, 16)?;
    let toc_block_size = read_u32(bytes, 20)?;
    let record_area_offset = read_u64(bytes, 24)?;
    let record_area_len = read_u64(bytes, 32)?;
    let toc_payload_len = read_u64(bytes, 40)?;
    let crc_tables_len = read_u64(bytes, 48)?;
    let sort_order = read_u64(bytes, 56)?;
    let mut toc_payload_hash = [0u8; 32];
    toc_payload_hash.copy_from_slice(&bytes[72..104]);

    Ok(TocHeaderV1 {
        entry_count,
        record_block_size,
        toc_block_size,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        sort_order,
        toc_payload_hash,
    })
}

fn encode_toc_entry_v1(e: &TocEntryV1) -> [u8; TOC_ENTRY_LEN] {
    let mut out = [0u8; TOC_ENTRY_LEN];
    out[0..8].copy_from_slice(&e.stream_hash.to_le_bytes());
    out[8..16].copy_from_slice(&e.seq.to_le_bytes());
    out[16..20].copy_from_slice(&e.file_offset.to_le_bytes());
    out[20..24].copy_from_slice(&e.frame_len.to_le_bytes());
    out[24..28].copy_from_slice(&e.payload_len.to_le_bytes());
    out[28..32].copy_from_slice(&e.flags.to_le_bytes());
    out[32..48].copy_from_slice(&e.event_id_hash16);
    out[48..56].copy_from_slice(&e.header_digest8);
    out[56..64].copy_from_slice(&e.payload_digest8);
    out
}

fn decode_toc_entry_v1(bytes: &[u8]) -> Result<TocEntryV1> {
    if bytes.len() < TOC_ENTRY_LEN {
        return Err(SegmentError::BufferTooSmall);
    }
    let stream_hash = read_u64(bytes, 0)?;
    let seq = read_u64(bytes, 8)?;
    let file_offset = read_u32(bytes, 16)?;
    let frame_len = read_u32(bytes, 20)?;
    let payload_len = read_u32(bytes, 24)?;
    let flags = read_u32(bytes, 28)?;
    let mut event_id_hash16 = [0u8; 16];
    event_id_hash16.copy_from_slice(&bytes[32..48]);
    let mut header_digest8 = [0u8; 8];
    header_digest8.copy_from_slice(&bytes[48..56]);
    let mut payload_digest8 = [0u8; 8];
    payload_digest8.copy_from_slice(&bytes[56..64]);

    Ok(TocEntryV1 {
        stream_hash,
        seq,
        file_offset,
        frame_len,
        payload_len,
        flags,
        event_id_hash16,
        header_digest8,
        payload_digest8,
    })
}

pub fn encode_segment_footer_v1(f: &SegmentFooterV1) -> Result<[u8; SEGMENT_FOOTER_LEN]> {
    if f.file_len > u32::MAX as u64
        || f.record_area_offset > u32::MAX as u64
        || f.record_area_len > u32::MAX as u64
        || f.toc_offset > u32::MAX as u64
        || f.toc_len > u32::MAX as u64
        || f.toc_entry_count > u32::MAX as u64
    {
        return Err(SegmentError::LengthOutOfRange {
            msg: "footer v1 encodes offsets/lengths as u32; value exceeds 4GiB".to_string(),
        });
    }

    let mut out = [0u8; SEGMENT_FOOTER_LEN];
    out[0..4].copy_from_slice(&SEGMENT_MAGIC_CCF3.to_le_bytes());
    out[4..6].copy_from_slice(&SEGMENT_MAJOR.to_le_bytes());
    out[6..8].copy_from_slice(&SEGMENT_MINOR.to_le_bytes());
    out[8..12].copy_from_slice(&(SEGMENT_FOOTER_LEN as u32).to_le_bytes());
    out[12..16].copy_from_slice(&f.flags.to_le_bytes());
    out[16..20].copy_from_slice(&f.shard_id.to_le_bytes());
    out[20..28].copy_from_slice(&f.epoch.to_le_bytes());
    out[28..36].copy_from_slice(&f.segment_seq.to_le_bytes());
    out[36..52].copy_from_slice(&f.segment_id.0);
    out[52..60].copy_from_slice(&f.created_at_unix_ns.to_le_bytes());
    out[60..68].copy_from_slice(&f.sealed_at_unix_ns.to_le_bytes());

    out[68..72].copy_from_slice(&(f.file_len as u32).to_le_bytes());
    out[72..76].copy_from_slice(&(f.record_area_offset as u32).to_le_bytes());
    out[76..80].copy_from_slice(&(f.record_area_len as u32).to_le_bytes());
    out[80..84].copy_from_slice(&(f.toc_offset as u32).to_le_bytes());
    out[84..88].copy_from_slice(&(f.toc_len as u32).to_le_bytes());
    out[88..92].copy_from_slice(&(f.toc_entry_count as u32).to_le_bytes());

    out[92..100].copy_from_slice(&f.min_stream_hash.to_le_bytes());
    out[100..108].copy_from_slice(&f.min_seq.to_le_bytes());
    out[108..116].copy_from_slice(&f.max_stream_hash.to_le_bytes());
    out[116..124].copy_from_slice(&f.max_seq.to_le_bytes());

    out[124..156].copy_from_slice(&f.header_hash);
    out[156..188].copy_from_slice(&f.record_hash);
    out[188..220].copy_from_slice(&f.toc_payload_hash);
    out[220..252].copy_from_slice(&f.segment_hash);

    let crc = crc32c::crc32c(&out[..SEGMENT_FOOTER_LEN - 4]);
    out[SEGMENT_FOOTER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());

    Ok(out)
}

pub fn decode_segment_footer_v1(bytes: &[u8]) -> Result<SegmentFooterV1> {
    if bytes.len() < SEGMENT_FOOTER_LEN {
        return Err(SegmentError::BufferTooSmall);
    }

    let magic = read_u32(bytes, 0)?;
    if magic != SEGMENT_MAGIC_CCF3 {
        return Err(SegmentError::InvalidMagic {
            expected: SEGMENT_MAGIC_CCF3,
            actual: magic,
        });
    }
    let major = read_u16(bytes, 4)?;
    let minor = read_u16(bytes, 6)?;
    if major != SEGMENT_MAJOR || minor != SEGMENT_MINOR {
        return Err(SegmentError::UnsupportedSegmentVersion { major, minor });
    }
    let footer_len = read_u32(bytes, 8)? as usize;
    if footer_len != SEGMENT_FOOTER_LEN {
        return Err(SegmentError::LengthOutOfRange {
            msg: format!("footer_len expected {SEGMENT_FOOTER_LEN}, got {footer_len}"),
        });
    }

    let expected = read_u32(bytes, SEGMENT_FOOTER_LEN - 4)?;
    let actual = crc32c::crc32c(&bytes[..SEGMENT_FOOTER_LEN - 4]);
    if expected != actual {
        return Err(SegmentError::CrcMismatch { expected, actual });
    }

    let flags = read_u32(bytes, 12)?;
    let shard_id = read_u32(bytes, 16)?;
    let epoch = read_u64(bytes, 20)?;
    let segment_seq = read_u64(bytes, 28)?;
    let mut seg_id = [0u8; 16];
    seg_id.copy_from_slice(&bytes[36..52]);
    let created_at_unix_ns = read_u64(bytes, 52)?;
    let sealed_at_unix_ns = read_u64(bytes, 60)?;

    let file_len = read_u32(bytes, 68)? as u64;
    let record_area_offset = read_u32(bytes, 72)? as u64;
    let record_area_len = read_u32(bytes, 76)? as u64;
    let toc_offset = read_u32(bytes, 80)? as u64;
    let toc_len = read_u32(bytes, 84)? as u64;
    let toc_entry_count = read_u32(bytes, 88)? as u64;

    let min_stream_hash = read_u64(bytes, 92)?;
    let min_seq = read_u64(bytes, 100)?;
    let max_stream_hash = read_u64(bytes, 108)?;
    let max_seq = read_u64(bytes, 116)?;

    let mut header_hash = [0u8; 32];
    header_hash.copy_from_slice(&bytes[124..156]);
    let mut record_hash = [0u8; 32];
    record_hash.copy_from_slice(&bytes[156..188]);
    let mut toc_payload_hash = [0u8; 32];
    toc_payload_hash.copy_from_slice(&bytes[188..220]);
    let mut segment_hash = [0u8; 32];
    segment_hash.copy_from_slice(&bytes[220..252]);

    Ok(SegmentFooterV1 {
        flags,
        shard_id,
        epoch,
        segment_seq,
        segment_id: SegmentId(seg_id),
        created_at_unix_ns,
        sealed_at_unix_ns,
        file_len,
        record_area_offset,
        record_area_len,
        toc_offset,
        toc_len,
        toc_entry_count,
        min_stream_hash,
        min_seq,
        max_stream_hash,
        max_seq,
        header_hash,
        record_hash,
        toc_payload_hash,
        segment_hash,
    })
}

fn block_crc32c(bytes: &[u8], block_size: usize) -> Vec<u32> {
    if block_size == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        let end = (off + block_size).min(bytes.len());
        out.push(crc32c::crc32c(&bytes[off..end]));
        off = end;
    }
    out
}

fn is_sorted_toc(entries: &[TocEntryV1]) -> bool {
    entries
        .windows(2)
        .all(|w| (w[0].stream_hash, w[0].seq) <= (w[1].stream_hash, w[1].seq))
}

fn align_up(v: usize, align: usize) -> usize {
    if align == 0 {
        return v;
    }
    let rem = v % align;
    if rem == 0 {
        v
    } else {
        v + (align - rem)
    }
}

fn read_u16(bytes: &[u8], off: usize) -> Result<u16> {
    let end = off.checked_add(2).ok_or(SegmentError::BufferTooSmall)?;
    if end > bytes.len() {
        return Err(SegmentError::BufferTooSmall);
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[off..end]);
    Ok(u16::from_le_bytes(buf))
}

fn read_u32(bytes: &[u8], off: usize) -> Result<u32> {
    let end = off.checked_add(4).ok_or(SegmentError::BufferTooSmall)?;
    if end > bytes.len() {
        return Err(SegmentError::BufferTooSmall);
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[off..end]);
    Ok(u32::from_le_bytes(buf))
}

fn read_u64(bytes: &[u8], off: usize) -> Result<u64> {
    let end = off.checked_add(8).ok_or(SegmentError::BufferTooSmall)?;
    if end > bytes.len() {
        return Err(SegmentError::BufferTooSmall);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[off..end]);
    Ok(u64::from_le_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_frame::{canonical_header_bytes_v1, compute_header_hash, compute_payload_hash};

    // For `env!("CARGO_MANIFEST_DIR")` (CoreCrux/crates/corecrux-segment), this reaches CoreCrux/tests.
    const MIN_FIXTURE_REL: &str = "../../tests/fixtures_segments/minimal/minimal.ccxseg";

    fn build_minimal_segment_bytes() -> Vec<u8> {
        let shard_id = 0;
        let epoch = 1;
        let segment_seq = 1;
        let segment_id = SegmentId([1u8; 16]);
        let created_at = 1_700_000_000_000_000_000;
        let sealed_at = created_at + 1;

        let make_frame = |seq: u64, event_id: &str, payload: &[u8]| -> (Vec<u8>, [u8; 32], [u8; 32]) {
            let payload_hash = compute_payload_hash(payload);
            let canonical = corecrux_frame::CanonicalHeaderV1 {
                tenant_id: "tenant-a".to_string(),
                stream_id: "stream-1".to_string(),
                stream_type: "answers".to_string(),
                seq,
                event_id: event_id.to_string(),
                occurred_at: "2026-02-07T00:00:00Z".to_string(),
                ingested_at: "2026-02-07T00:00:00Z".to_string(),
                event_type: "test.event".to_string(),
                content_type: "application/octet-stream".to_string(),
                payload_len: payload.len() as u32,
                payload_hash,
            };
            let canonical_bytes = canonical_header_bytes_v1(&canonical);
            let header_hash = compute_header_hash(&canonical_bytes);
            let mut header_bytes = Vec::with_capacity(canonical_bytes.len() + 32);
            header_bytes.extend_from_slice(&canonical_bytes);
            header_bytes.extend_from_slice(&header_hash);
            (header_bytes, payload_hash, header_hash)
        };

        let stream_hash = 0x0102_0304_0506_0708u64;

        let (hdr1, payload_hash1, header_hash1) = make_frame(1, "evt-1", b"hello");
        let (hdr2, payload_hash2, header_hash2) = make_frame(2, "evt-2", b"world");

        let out = build_segment_v1(
            shard_id,
            epoch,
            segment_seq,
            segment_id,
            created_at,
            sealed_at,
            &[
                FrameInput {
                    stream_hash,
                    seq: 1,
                    event_id: "evt-1",
                    header_hash: header_hash1,
                    payload_hash: payload_hash1,
                    header_bytes: &hdr1,
                    payload_bytes: b"hello",
                },
                FrameInput {
                    stream_hash,
                    seq: 2,
                    event_id: "evt-2",
                    header_hash: header_hash2,
                    payload_hash: payload_hash2,
                    header_bytes: &hdr2,
                    payload_bytes: b"world",
                },
            ],
        )
        .unwrap();

        out.bytes
    }

    #[test]
    fn frame_roundtrip() {
        let hdr = b"header-bytes";
        let payload = b"payload";
        let enc = encode_frame_v1(hdr, payload).unwrap();
        let dec = decode_frame_v1(&enc).unwrap();
        assert_eq!(dec.header_bytes, hdr);
        assert_eq!(dec.payload_bytes, payload);
    }

    #[test]
    fn segment_build_and_decode() {
        let shard_id = 0;
        let epoch = 1;
        let segment_seq = 1;
        let segment_id = SegmentId([7u8; 16]);

        let payload_a = b"hello";
        let payload_hash_a = *blake3::hash(payload_a).as_bytes();
        let header_hash_a = *blake3::hash(b"hdr-a").as_bytes();

        let payload_b = b"world";
        let payload_hash_b = *blake3::hash(payload_b).as_bytes();
        let header_hash_b = *blake3::hash(b"hdr-b").as_bytes();

        let out = build_segment_v1(
            shard_id,
            epoch,
            segment_seq,
            segment_id,
            1_700_000_000_000_000_000,
            1_700_000_000_000_000_001,
            &[
                FrameInput {
                    stream_hash: 10,
                    seq: 2,
                    event_id: "evt-a",
                    header_hash: header_hash_a,
                    payload_hash: payload_hash_a,
                    header_bytes: b"hdr-a",
                    payload_bytes: payload_a,
                },
                FrameInput {
                    stream_hash: 10,
                    seq: 1,
                    event_id: "evt-b",
                    header_hash: header_hash_b,
                    payload_hash: payload_hash_b,
                    header_bytes: b"hdr-b",
                    payload_bytes: payload_b,
                },
            ],
        )
        .unwrap();

        let (h, toc_h, entries, f) = decode_segment_v1(&out.bytes).unwrap();
        assert_eq!(h.segment_seq, segment_seq);
        assert_eq!(f.segment_seq, segment_seq);
        assert_eq!(toc_h.entry_count, 2);
        assert_eq!(entries.len(), 2);
        assert!(is_sorted_toc(&entries));

        // Phase 5 trailer index must decode and be consistent with the TOC.
        let toc_off = f.toc_offset as usize;
        let toc_len = f.toc_len as usize;
        let toc_area = &out.bytes[toc_off..toc_off + toc_len];
        let trailer = decode_trailer_index_v1(toc_area, &toc_h).unwrap().unwrap();
        assert_eq!(trailer.toc_by_offset.len(), entries.len());
        assert_eq!(trailer.toc_sorted_idx.len(), entries.len());
        assert_eq!(trailer.blocks.len(), 1);
        assert_eq!(
            trailer.record_block_uncompressed_max_len,
            RECORD_BLOCK_UNCOMPRESSED_MAX_LEN_V1
        );
        assert_eq!(trailer.bloom_bytes_per_block as usize, BLOOM_BYTES_PER_BLOCK_V1);

        use std::collections::HashMap;
        let mut by_key: HashMap<(u64, u64), u32> = HashMap::new();
        for e in &entries {
            by_key.insert((e.stream_hash, e.seq), e.file_offset);
        }
        for e in &trailer.toc_by_offset {
            let block = &trailer.blocks[e.block_id as usize];
            let file_off = block.file_offset as u32 + e.in_block_offset;
            assert_eq!(Some(&file_off), by_key.get(&(e.stream_hash, e.seq)));
        }

        // toc_sorted_idx must order toc_by_offset entries by (stream_hash, seq).
        let mut last = (0u64, 0u64);
        for &idx in &trailer.toc_sorted_idx {
            let e = trailer.toc_by_offset[idx as usize];
            assert!((e.stream_hash, e.seq) >= last);
            last = (e.stream_hash, e.seq);
        }
    }

    #[test]
    fn detects_footer_corruption() {
        let out = build_segment_v1(
            0,
            1,
            1,
            SegmentId([1u8; 16]),
            1,
            2,
            &[FrameInput {
                stream_hash: 1,
                seq: 1,
                event_id: "evt",
                header_hash: [2u8; 32],
                payload_hash: [3u8; 32],
                header_bytes: b"hdr",
                payload_bytes: b"payload",
            }],
        )
        .unwrap();

        let mut bytes = out.bytes.clone();
        // Flip a bit in the footer.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;

        let err = decode_segment_v1(&bytes).unwrap_err();
        assert!(matches!(err, SegmentError::CrcMismatch { .. }));
    }

    #[test]
    fn minimal_fixture_is_stable() {
        let bytes = build_minimal_segment_bytes();
        let expected = include_bytes!("../../../tests/fixtures_segments/minimal/minimal.ccxseg");
        assert_eq!(bytes, expected);
    }

    #[test]
    #[ignore]
    fn write_minimal_fixture() {
        let bytes = build_minimal_segment_bytes();
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(MIN_FIXTURE_REL)
            .canonicalize()
            .unwrap_or_else(|_| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(MIN_FIXTURE_REL));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, bytes).unwrap();
    }

    // --- New tests for uncovered paths ---

    #[test]
    fn frame_decode_buffer_too_small() {
        let err = decode_frame_v1(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, SegmentError::BufferTooSmall));
    }

    #[test]
    fn frame_decode_bad_magic() {
        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let err = decode_frame_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::InvalidMagic { .. }));
    }

    #[test]
    fn frame_decode_bad_version() {
        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(&FRAME_MAGIC_CRX1.to_le_bytes());
        buf[4..6].copy_from_slice(&99u16.to_le_bytes()); // bad version
        let err = decode_frame_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::LengthOutOfRange { .. }));
    }

    #[test]
    fn frame_decode_crc_mismatch() {
        let encoded = encode_frame_v1(b"hdr", b"payload").unwrap();
        let mut corrupted = encoded.clone();
        // Corrupt a payload byte (payload starts at offset 12 + header_len = 12 + 3 = 15)
        corrupted[15] ^= 0xFF;
        let err = decode_frame_v1(&corrupted).unwrap_err();
        assert!(matches!(err, SegmentError::CrcMismatch { .. }));
    }

    #[test]
    fn frame_decode_truncated_payload() {
        let encoded = encode_frame_v1(b"hdr", b"long payload here!").unwrap();
        let truncated = &encoded[..encoded.len() - 8];
        let err = decode_frame_v1(truncated).unwrap_err();
        assert!(matches!(err, SegmentError::BufferTooSmall));
    }

    #[test]
    fn encode_frame_rejects_oversized_header() {
        let header = vec![0u8; (u16::MAX as usize) + 1];
        let err = encode_frame_v1(&header, b"payload").unwrap_err();
        assert!(matches!(err, SegmentError::LengthOutOfRange { .. }));
    }

    #[test]
    fn segment_header_roundtrip() {
        let hdr = SegmentHeaderV1 {
            flags: 1,
            shard_id: 42,
            epoch: 7,
            segment_seq: 99,
            segment_id: SegmentId([0xAA; 16]),
            created_at_unix_ns: 1_700_000_000_000_000_000,
        };
        let bytes = encode_segment_header_v1(&hdr).unwrap();
        assert_eq!(bytes.len(), SEGMENT_HEADER_LEN);
        let decoded = decode_segment_header_v1(&bytes).unwrap();
        assert_eq!(decoded.flags, 1);
        assert_eq!(decoded.shard_id, 42);
        assert_eq!(decoded.epoch, 7);
        assert_eq!(decoded.segment_seq, 99);
        assert_eq!(decoded.segment_id, SegmentId([0xAA; 16]));
        assert_eq!(decoded.created_at_unix_ns, 1_700_000_000_000_000_000);
    }

    #[test]
    fn segment_header_decode_bad_magic() {
        let mut buf = vec![0u8; SEGMENT_HEADER_LEN];
        buf[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let err = decode_segment_header_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::InvalidMagic { .. }));
    }

    #[test]
    fn segment_header_decode_bad_version() {
        let mut buf = vec![0u8; SEGMENT_HEADER_LEN];
        buf[0..4].copy_from_slice(&SEGMENT_MAGIC_CCS3.to_le_bytes());
        buf[4..6].copy_from_slice(&99u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        let err = decode_segment_header_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::UnsupportedSegmentVersion { .. }));
    }

    #[test]
    fn segment_header_decode_crc_mismatch() {
        let hdr = SegmentHeaderV1 {
            flags: 1,
            shard_id: 0,
            epoch: 1,
            segment_seq: 1,
            segment_id: SegmentId([1u8; 16]),
            created_at_unix_ns: 1,
        };
        let mut bytes = encode_segment_header_v1(&hdr).unwrap();
        // Corrupt a byte in the header body
        bytes[20] ^= 0xFF;
        let err = decode_segment_header_v1(&bytes).unwrap_err();
        assert!(matches!(err, SegmentError::CrcMismatch { .. }));
    }

    #[test]
    fn segment_footer_roundtrip() {
        let footer = SegmentFooterV1 {
            flags: 0x3,
            shard_id: 5,
            epoch: 10,
            segment_seq: 20,
            segment_id: SegmentId([0xBB; 16]),
            created_at_unix_ns: 100,
            sealed_at_unix_ns: 200,
            file_len: 8192,
            record_area_offset: 4096,
            record_area_len: 1024,
            toc_offset: 5120,
            toc_len: 512,
            toc_entry_count: 3,
            min_stream_hash: 1,
            min_seq: 1,
            max_stream_hash: 100,
            max_seq: 50,
            header_hash: [0x11; 32],
            record_hash: [0x22; 32],
            toc_payload_hash: [0x33; 32],
            segment_hash: [0x44; 32],
        };
        let bytes = encode_segment_footer_v1(&footer).unwrap();
        assert_eq!(bytes.len(), SEGMENT_FOOTER_LEN);
        let decoded = decode_segment_footer_v1(&bytes).unwrap();
        assert_eq!(decoded.flags, 0x3);
        assert_eq!(decoded.shard_id, 5);
        assert_eq!(decoded.epoch, 10);
        assert_eq!(decoded.segment_seq, 20);
        assert_eq!(decoded.segment_id, SegmentId([0xBB; 16]));
        assert_eq!(decoded.file_len, 8192);
        assert_eq!(decoded.header_hash, [0x11; 32]);
        assert_eq!(decoded.segment_hash, [0x44; 32]);
    }

    #[test]
    fn segment_footer_encode_rejects_oversized() {
        let footer = SegmentFooterV1 {
            flags: 0x3,
            shard_id: 0,
            epoch: 1,
            segment_seq: 1,
            segment_id: SegmentId([0; 16]),
            created_at_unix_ns: 0,
            sealed_at_unix_ns: 0,
            file_len: u64::MAX, // exceeds u32
            record_area_offset: 0,
            record_area_len: 0,
            toc_offset: 0,
            toc_len: 0,
            toc_entry_count: 0,
            min_stream_hash: 0,
            min_seq: 0,
            max_stream_hash: 0,
            max_seq: 0,
            header_hash: [0; 32],
            record_hash: [0; 32],
            toc_payload_hash: [0; 32],
            segment_hash: [0; 32],
        };
        let err = encode_segment_footer_v1(&footer).unwrap_err();
        assert!(matches!(err, SegmentError::LengthOutOfRange { .. }));
    }

    #[test]
    fn segment_footer_decode_bad_magic() {
        let mut buf = [0u8; SEGMENT_FOOTER_LEN];
        buf[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let err = decode_segment_footer_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::InvalidMagic { .. }));
    }

    #[test]
    fn toc_header_decode_bad_magic() {
        let mut buf = [0u8; TOC_HEADER_LEN];
        buf[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let err = decode_toc_header_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::InvalidMagic { .. }));
    }

    #[test]
    fn toc_header_decode_bad_version() {
        let mut buf = [0u8; TOC_HEADER_LEN];
        buf[0..4].copy_from_slice(&TOC_MAGIC_TOC1.to_le_bytes());
        buf[4..6].copy_from_slice(&99u16.to_le_bytes()); // bad version
        let err = decode_toc_header_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::UnsupportedTocVersion { .. }));
    }

    #[test]
    fn toc_entry_roundtrip() {
        let entry = TocEntryV1 {
            stream_hash: 0x123456789ABCDEF0,
            seq: 42,
            file_offset: 4096,
            frame_len: 256,
            payload_len: 128,
            flags: 0,
            event_id_hash16: [0xAA; 16],
            header_digest8: [0xBB; 8],
            payload_digest8: [0xCC; 8],
        };
        let bytes = encode_toc_entry_v1(&entry);
        assert_eq!(bytes.len(), TOC_ENTRY_LEN);
        let decoded = decode_toc_entry_v1(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn block_meta_v1_roundtrip() {
        let meta = BlockMetaV1 {
            block_id: 3,
            codec: RECORD_BLOCK_CODEC_LZ4_V1,
            file_offset: 8192,
            compressed_len: 1024,
            physical_len: 4096,
            uncompressed_len: 2048,
            crc32c: 0xAABBCCDD,
            bloom: [0x55; BLOOM_BYTES_PER_BLOCK_V1],
        };
        let bytes = encode_block_meta_v1(&meta);
        assert_eq!(bytes.len(), BLOCK_META_V1_LEN);
        let decoded = decode_block_meta_v1(&bytes).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn block_meta_v1_physical_len_zero_fallback() {
        let meta = BlockMetaV1 {
            block_id: 0,
            codec: RECORD_BLOCK_CODEC_NONE_V1,
            file_offset: 4096,
            compressed_len: 512,
            physical_len: 0, // legacy: 0 means "same as compressed_len"
            uncompressed_len: 512,
            crc32c: 0x12345678,
            bloom: [0; BLOOM_BYTES_PER_BLOCK_V1],
        };
        let bytes = encode_block_meta_v1(&meta);
        let decoded = decode_block_meta_v1(&bytes).unwrap();
        // physical_len=0 decodes as compressed_len
        assert_eq!(decoded.physical_len, 512);
    }

    #[test]
    fn toc_by_offset_entry_roundtrip() {
        let entry = TocByOffsetEntryV1 {
            stream_hash: 0xDEAD,
            seq: 7,
            block_id: 2,
            in_block_offset: 128,
            frame_len: 64,
            flags: 0,
            event_id_hash16: [0x11; 16],
            header_digest8: [0x22; 8],
            payload_digest8: [0x33; 8],
        };
        let bytes = encode_toc_by_offset_entry_v1(&entry);
        assert_eq!(bytes.len(), TOC_BY_OFFSET_ENTRY_V1_LEN);
        let decoded = decode_toc_by_offset_entry_v1(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn bloom_insert_and_query() {
        let mut bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];
        bloom_insert_stream_hash_v1(&mut bloom, BLOOM_HASH_K_V1, 0x12345);
        bloom_insert_stream_hash_v1(&mut bloom, BLOOM_HASH_K_V1, 0xABCDE);

        assert!(bloom_maybe_contains_stream_hash_v1(&bloom, BLOOM_HASH_K_V1, 0x12345));
        assert!(bloom_maybe_contains_stream_hash_v1(&bloom, BLOOM_HASH_K_V1, 0xABCDE));
        // Empty bloom should not match a random hash (with high probability)
        let empty_bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];
        assert!(!bloom_maybe_contains_stream_hash_v1(
            &empty_bloom,
            BLOOM_HASH_K_V1,
            0x12345
        ));
    }

    #[test]
    fn is_sorted_toc_validates() {
        let sorted = vec![
            TocEntryV1 {
                stream_hash: 1,
                seq: 1,
                file_offset: 0,
                frame_len: 0,
                payload_len: 0,
                flags: 0,
                event_id_hash16: [0; 16],
                header_digest8: [0; 8],
                payload_digest8: [0; 8],
            },
            TocEntryV1 {
                stream_hash: 1,
                seq: 2,
                file_offset: 0,
                frame_len: 0,
                payload_len: 0,
                flags: 0,
                event_id_hash16: [0; 16],
                header_digest8: [0; 8],
                payload_digest8: [0; 8],
            },
            TocEntryV1 {
                stream_hash: 2,
                seq: 1,
                file_offset: 0,
                frame_len: 0,
                payload_len: 0,
                flags: 0,
                event_id_hash16: [0; 16],
                header_digest8: [0; 8],
                payload_digest8: [0; 8],
            },
        ];
        assert!(is_sorted_toc(&sorted));

        let unsorted = vec![sorted[2], sorted[0]];
        assert!(!is_sorted_toc(&unsorted));

        assert!(is_sorted_toc(&[]));
        assert!(is_sorted_toc(&[sorted[0]]));
    }

    #[test]
    fn align_up_works() {
        assert_eq!(align_up(0, 4096), 0);
        assert_eq!(align_up(1, 4096), 4096);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
        assert_eq!(align_up(100, 0), 100); // align=0 returns value unchanged
    }

    #[test]
    fn block_crc32c_empty() {
        assert!(block_crc32c(&[], 64).is_empty());
        assert!(block_crc32c(&[1, 2, 3], 0).is_empty());
    }

    #[test]
    fn block_crc32c_single_block() {
        let data = vec![0xAA; 100];
        let crcs = block_crc32c(&data, 200);
        assert_eq!(crcs.len(), 1);
        assert_eq!(crcs[0], crc32c::crc32c(&data));
    }

    #[test]
    fn block_crc32c_multiple_blocks() {
        let data = vec![0xBB; 256];
        let crcs = block_crc32c(&data, 100);
        assert_eq!(crcs.len(), 3); // 100 + 100 + 56
        assert_eq!(crcs[0], crc32c::crc32c(&data[0..100]));
        assert_eq!(crcs[1], crc32c::crc32c(&data[100..200]));
        assert_eq!(crcs[2], crc32c::crc32c(&data[200..256]));
    }

    #[test]
    fn decode_segment_v1_rejects_too_small() {
        let buf = vec![0u8; 100];
        let err = decode_segment_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::BufferTooSmall));
    }

    #[test]
    fn decode_segment_v1_rejects_unsealed() {
        // Build a valid segment, then clear the SEALED flag in footer
        let out = build_segment_v1(
            0,
            1,
            1,
            SegmentId([1u8; 16]),
            1,
            2,
            &[FrameInput {
                stream_hash: 1,
                seq: 1,
                event_id: "evt",
                header_hash: [2u8; 32],
                payload_hash: [3u8; 32],
                header_bytes: b"hdr",
                payload_bytes: b"payload",
            }],
        )
        .unwrap();

        // Create a footer with flags=0 (not sealed)
        let mut footer = out.footer.clone();
        footer.flags = 0; // clear SEALED
        let footer_bytes = encode_segment_footer_v1(&footer).unwrap();

        let mut bytes = out.bytes.clone();
        let footer_start = bytes.len() - SEGMENT_FOOTER_LEN;
        bytes[footer_start..].copy_from_slice(&footer_bytes);

        let err = decode_segment_v1(&bytes).unwrap_err();
        // Could be NotSealed or CrcMismatch/HashMismatch due to footer change
        match err {
            SegmentError::NotSealed | SegmentError::CrcMismatch { .. } | SegmentError::HashMismatch { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn build_segment_with_lz4_codec_roundtrips() {
        let payload_a = b"hello world compressed";
        let payload_hash_a = compute_payload_hash(payload_a);
        let header_hash_a = compute_header_hash(b"hdr-a");

        let out = build_segment_v1_with_block_codec(
            0,
            1,
            1,
            SegmentId([5u8; 16]),
            1,
            2,
            RECORD_BLOCK_CODEC_LZ4_V1,
            &[FrameInput {
                stream_hash: 10,
                seq: 1,
                event_id: "evt-lz4",
                header_hash: header_hash_a,
                payload_hash: payload_hash_a,
                header_bytes: b"hdr-a",
                payload_bytes: payload_a,
            }],
        )
        .unwrap();

        // File length should be 4KiB aligned (Phase 9 padding)
        assert_eq!(out.bytes.len() % 4096, 0);

        // Footer should decode
        let footer_bytes = &out.bytes[out.bytes.len() - SEGMENT_FOOTER_LEN..];
        let footer = decode_segment_footer_v1(footer_bytes).unwrap();
        assert_eq!(footer.toc_entry_count, 1);
        assert_eq!(footer.flags & 0x1, 1); // SEALED

        // Trailer index should decode with LZ4 codec
        let toc_off = footer.toc_offset as usize;
        let toc_len = footer.toc_len as usize;
        let toc_area = &out.bytes[toc_off..toc_off + toc_len];
        let toc_payload_len_raw = u64::from_le_bytes(toc_area[40..48].try_into().unwrap()) as usize;
        let toc_payload = &toc_area[..toc_payload_len_raw];
        let toc_header = decode_toc_header_v1(&toc_payload[..TOC_HEADER_LEN]).unwrap();
        let trailer = decode_trailer_index_v1(toc_area, &toc_header)
            .unwrap()
            .expect("trailer should exist");
        assert_eq!(trailer.blocks.len(), 1);
        assert_eq!(trailer.blocks[0].codec, RECORD_BLOCK_CODEC_LZ4_V1);
        // Note: LZ4 may expand small data, so we do not assert compressed <= uncompressed.
        assert!(trailer.blocks[0].uncompressed_len > 0);
    }

    #[test]
    fn build_segment_empty_frames() {
        let out = build_segment_v1(0, 1, 1, SegmentId([0u8; 16]), 1, 2, &[]).unwrap();

        let (hdr, toc_h, entries, footer) = decode_segment_v1(&out.bytes).unwrap();
        assert_eq!(hdr.segment_seq, 1);
        assert_eq!(toc_h.entry_count, 0);
        assert!(entries.is_empty());
        assert_eq!(footer.min_stream_hash, 0);
        assert_eq!(footer.max_stream_hash, 0);
    }

    #[test]
    fn seal_segment_from_record_area_validates_contiguity() {
        let err = seal_segment_v1_from_record_area(
            0,
            1,
            1,
            SegmentId([0u8; 16]),
            1,
            2,
            &[0u8; 100],
            &[FrameMetaV1 {
                stream_hash: 1,
                seq: 1,
                record_off: 10, // should be 0
                frame_len: 50,
                payload_len: 20,
                event_id_hash16: [0; 16],
                header_digest8: [0; 8],
                payload_digest8: [0; 8],
            }],
        )
        .unwrap_err();
        assert!(matches!(err, SegmentError::LengthOutOfRange { .. }));
    }

    #[test]
    fn read_u16_out_of_bounds() {
        let err = read_u16(&[0u8; 1], 0).unwrap_err();
        assert!(matches!(err, SegmentError::BufferTooSmall));
    }

    #[test]
    fn read_u32_out_of_bounds() {
        let err = read_u32(&[0u8; 3], 0).unwrap_err();
        assert!(matches!(err, SegmentError::BufferTooSmall));
    }

    #[test]
    fn read_u64_out_of_bounds() {
        let err = read_u64(&[0u8; 7], 0).unwrap_err();
        assert!(matches!(err, SegmentError::BufferTooSmall));
    }
}

#[cfg(test)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn frame_encode_decode_roundtrip(
            header_bytes in prop::collection::vec(any::<u8>(), 0..512),
            payload_bytes in prop::collection::vec(any::<u8>(), 0..1024),
        ) {
            let encoded = encode_frame_v1(&header_bytes, &payload_bytes).unwrap();
            let decoded = decode_frame_v1(&encoded).unwrap();
            prop_assert_eq!(&decoded.header_bytes, &header_bytes);
            prop_assert_eq!(&decoded.payload_bytes, &payload_bytes);
        }

        #[test]
        fn segment_header_encode_decode_roundtrip(
            flags in any::<u32>(),
            shard_id in any::<u32>(),
            epoch in any::<u64>(),
            segment_seq in any::<u64>(),
            segment_id_bytes in prop::array::uniform16(any::<u8>()),
            created_at_unix_ns in any::<u64>(),
        ) {
            let header = SegmentHeaderV1 {
                flags,
                shard_id,
                epoch,
                segment_seq,
                segment_id: SegmentId(segment_id_bytes),
                created_at_unix_ns,
            };
            let encoded = encode_segment_header_v1(&header).unwrap();
            let decoded = decode_segment_header_v1(&encoded).unwrap();
            prop_assert_eq!(decoded.flags, header.flags);
            prop_assert_eq!(decoded.shard_id, header.shard_id);
            prop_assert_eq!(decoded.epoch, header.epoch);
            prop_assert_eq!(decoded.segment_seq, header.segment_seq);
            prop_assert_eq!(decoded.segment_id, header.segment_id);
            prop_assert_eq!(decoded.created_at_unix_ns, header.created_at_unix_ns);
        }

        #[test]
        fn segment_footer_encode_decode_roundtrip(
            flags in any::<u32>(),
            shard_id in any::<u32>(),
            epoch in any::<u64>(),
            segment_seq in any::<u64>(),
            segment_id_bytes in prop::array::uniform16(any::<u8>()),
            created_at in any::<u64>(),
            sealed_at in any::<u64>(),
            // Footer v1 encodes offsets as u32, so keep values in u32 range
            file_len in 0u64..u32::MAX as u64,
            record_area_offset in 0u64..u32::MAX as u64,
            record_area_len in 0u64..u32::MAX as u64,
            toc_offset in 0u64..u32::MAX as u64,
            toc_len in 0u64..u32::MAX as u64,
            toc_entry_count in 0u64..u32::MAX as u64,
            min_stream_hash in any::<u64>(),
            min_seq in any::<u64>(),
            max_stream_hash in any::<u64>(),
            max_seq in any::<u64>(),
            header_hash in prop::array::uniform32(any::<u8>()),
            record_hash in prop::array::uniform32(any::<u8>()),
            toc_payload_hash in prop::array::uniform32(any::<u8>()),
            segment_hash in prop::array::uniform32(any::<u8>()),
        ) {
            let footer = SegmentFooterV1 {
                flags,
                shard_id,
                epoch,
                segment_seq,
                segment_id: SegmentId(segment_id_bytes),
                created_at_unix_ns: created_at,
                sealed_at_unix_ns: sealed_at,
                file_len,
                record_area_offset,
                record_area_len,
                toc_offset,
                toc_len,
                toc_entry_count,
                min_stream_hash,
                min_seq,
                max_stream_hash,
                max_seq,
                header_hash,
                record_hash,
                toc_payload_hash,
                segment_hash,
            };
            let encoded = encode_segment_footer_v1(&footer).unwrap();
            let decoded = decode_segment_footer_v1(&encoded).unwrap();
            prop_assert_eq!(decoded.flags, footer.flags);
            prop_assert_eq!(decoded.shard_id, footer.shard_id);
            prop_assert_eq!(decoded.epoch, footer.epoch);
            prop_assert_eq!(decoded.segment_seq, footer.segment_seq);
            prop_assert_eq!(decoded.segment_id, footer.segment_id);
            prop_assert_eq!(decoded.created_at_unix_ns, footer.created_at_unix_ns);
            prop_assert_eq!(decoded.sealed_at_unix_ns, footer.sealed_at_unix_ns);
            prop_assert_eq!(decoded.file_len, footer.file_len);
            prop_assert_eq!(decoded.record_area_offset, footer.record_area_offset);
            prop_assert_eq!(decoded.record_area_len, footer.record_area_len);
            prop_assert_eq!(decoded.toc_offset, footer.toc_offset);
            prop_assert_eq!(decoded.toc_len, footer.toc_len);
            prop_assert_eq!(decoded.toc_entry_count, footer.toc_entry_count);
            prop_assert_eq!(decoded.min_stream_hash, footer.min_stream_hash);
            prop_assert_eq!(decoded.min_seq, footer.min_seq);
            prop_assert_eq!(decoded.max_stream_hash, footer.max_stream_hash);
            prop_assert_eq!(decoded.max_seq, footer.max_seq);
            prop_assert_eq!(decoded.header_hash, footer.header_hash);
            prop_assert_eq!(decoded.record_hash, footer.record_hash);
            prop_assert_eq!(decoded.toc_payload_hash, footer.toc_payload_hash);
            prop_assert_eq!(decoded.segment_hash, footer.segment_hash);
        }

        #[test]
        fn block_meta_encode_length(
            block_id in any::<u32>(),
            codec in any::<u32>(),
            file_offset in any::<u64>(),
            compressed_len in any::<u32>(),
            physical_len in any::<u32>(),
            uncompressed_len in any::<u32>(),
            crc32c in any::<u32>(),
        ) {
            let mut bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];
            // Fill bloom with deterministic pattern from block_id
            for (i, b) in bloom.iter_mut().enumerate() {
                *b = ((block_id as usize).wrapping_add(i) & 0xFF) as u8;
            }
            let meta = BlockMetaV1 {
                block_id,
                codec,
                file_offset,
                compressed_len,
                physical_len,
                uncompressed_len,
                crc32c,
                bloom,
            };
            let encoded = encode_block_meta_v1(&meta);
            // Verify encoded length matches expected constant
            prop_assert_eq!(encoded.len(), BLOCK_META_V1_LEN);
        }

        #[test]
        fn toc_by_offset_entry_encode_length(
            stream_hash in any::<u64>(),
            seq in any::<u64>(),
            block_id in any::<u32>(),
            in_block_offset in any::<u32>(),
            frame_len in any::<u32>(),
            flags in any::<u32>(),
            event_id_hash16 in prop::array::uniform16(any::<u8>()),
            header_digest8 in prop::array::uniform8(any::<u8>()),
            payload_digest8 in prop::array::uniform8(any::<u8>()),
        ) {
            let entry = TocByOffsetEntryV1 {
                stream_hash,
                seq,
                block_id,
                in_block_offset,
                frame_len,
                flags,
                event_id_hash16,
                header_digest8,
                payload_digest8,
            };
            let encoded = encode_toc_by_offset_entry_v1(&entry);
            prop_assert_eq!(encoded.len(), TOC_BY_OFFSET_ENTRY_V1_LEN);
        }
    }
}
