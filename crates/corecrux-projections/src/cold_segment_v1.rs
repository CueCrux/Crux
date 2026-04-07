// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use crate::{ProjectionError, Result};

pub const CCXC_MAGIC: [u8; 4] = *b"CCXC";
pub const CCXC_V1: u32 = 1;
pub const CCXC_INDEX_MAGIC: [u8; 4] = *b"CCXI";
pub const CCXC_INDEX_V1: u32 = 1;

// Fixed-size header to keep parsing simple and allow future extensions without breaking reads.
pub const CCXC_HEADER_LEN_V1: usize = 128;

// Block entry in a cold segment index. Each block is content-addressed by its BLAKE3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColdSegmentIndexEntryV1 {
    pub block_blake3: [u8; 32],
    pub offset: u64,
    pub len: u32,
    pub codec: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColdBlockLocV1 {
    pub segment_blake3: [u8; 32],
    pub offset: u64,
    pub len: u32,
    pub codec: u32,
}

// Snapshot block payload: segment_id (== segment BLAKE3) + file length. Sorted lexicographically
// by segment_id for deterministic encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColdSegmentDirEntryV1 {
    pub segment_blake3: [u8; 32],
    pub file_len: u64,
}

pub fn encode_cold_segment_dir_v1(segs: &BTreeMap<[u8; 32], u64>) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(segs.len() * 40);
    for (h, file_len) in segs {
        out.extend_from_slice(h);
        out.extend_from_slice(&file_len.to_le_bytes());
    }
    out
}

pub fn decode_cold_segment_dir_v1(input: &[u8]) -> Result<Vec<ColdSegmentDirEntryV1>> {
    if !input.len().is_multiple_of(40) {
        return Err(ProjectionError::InvalidEvent {
            msg: "cold segment dir block length is not a multiple of entry stride".to_string(),
        });
    }
    let mut out = Vec::with_capacity(input.len() / 40);
    for chunk in input.chunks_exact(40) {
        let mut seg = [0u8; 32];
        seg.copy_from_slice(&chunk[0..32]);
        let file_len = u64::from_le_bytes(chunk[32..40].try_into().unwrap());
        out.push(ColdSegmentDirEntryV1 {
            segment_blake3: seg,
            file_len,
        });
    }
    Ok(out)
}

pub fn cold_segment_path_v1(segments_dir: &Path, segment_blake3: &[u8; 32]) -> PathBuf {
    let hex = blake3::Hash::from(*segment_blake3).to_hex().to_string();
    let prefix = &hex[0..2];
    segments_dir.join(prefix).join(format!("{hex}.ccxcseg"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColdSegmentHeaderV1 {
    pub block_count: u32,
    pub index_offset: u64,
    pub index_len: u64,
}

pub fn build_cold_segment_v1(
    blocks: &BTreeMap<[u8; 32], Vec<u8>>,
) -> (Vec<u8>, [u8; 32], Vec<ColdSegmentIndexEntryV1>) {
    // Header layout (little-endian):
    // 0..4   magic "CCXC"
    // 4..8   version (u32)
    // 8..12  block_count (u32)
    // 12..16 reserved
    // 16..24 index_offset (u64)
    // 24..32 index_len (u64)
    // 32..128 reserved/padding
    let mut out: Vec<u8> = vec![0u8; CCXC_HEADER_LEN_V1];
    out[0..4].copy_from_slice(&CCXC_MAGIC);
    out[4..8].copy_from_slice(&CCXC_V1.to_le_bytes());
    out[8..12].copy_from_slice(&(blocks.len() as u32).to_le_bytes());

    // Data region: concatenated block bytes in lexicographic hash order (BTreeMap order).
    let mut index_entries: Vec<ColdSegmentIndexEntryV1> = Vec::with_capacity(blocks.len());
    let mut cursor = CCXC_HEADER_LEN_V1 as u64;
    for (block_blake3, bytes) in blocks {
        let off = cursor;
        out.extend_from_slice(bytes);
        cursor = cursor.saturating_add(bytes.len() as u64);
        index_entries.push(ColdSegmentIndexEntryV1 {
            block_blake3: *block_blake3,
            offset: off,
            len: bytes.len() as u32,
            codec: 0,
        });
    }

    // Index region.
    let index_offset = cursor;
    let mut idx: Vec<u8> = Vec::with_capacity(16 + index_entries.len() * 48);
    idx.extend_from_slice(&CCXC_INDEX_MAGIC);
    idx.extend_from_slice(&CCXC_INDEX_V1.to_le_bytes());
    idx.extend_from_slice(&(index_entries.len() as u32).to_le_bytes());
    idx.extend_from_slice(&0u32.to_le_bytes()); // reserved
    for e in &index_entries {
        idx.extend_from_slice(&e.block_blake3);
        idx.extend_from_slice(&e.offset.to_le_bytes());
        idx.extend_from_slice(&e.len.to_le_bytes());
        idx.extend_from_slice(&e.codec.to_le_bytes());
    }
    let index_len = idx.len() as u64;
    out.extend_from_slice(&idx);

    // Fill in header offsets.
    out[16..24].copy_from_slice(&index_offset.to_le_bytes());
    out[24..32].copy_from_slice(&index_len.to_le_bytes());

    let h = blake3::hash(&out);
    (out, *h.as_bytes(), index_entries)
}

pub fn read_and_verify_cold_segment_index_v1(
    path: &Path,
    expected_blake3: &[u8; 32],
    expected_len: u64,
) -> Result<(ColdSegmentHeaderV1, Vec<ColdSegmentIndexEntryV1>)> {
    let meta = std::fs::metadata(path)?;
    if meta.len() != expected_len {
        return Err(ProjectionError::InvalidEvent {
            msg: format!(
                "cold segment length mismatch at {}: expected {} got {}",
                path.display(),
                expected_len,
                meta.len()
            ),
        });
    }

    // Verify hash by streaming the file.
    let mut f = std::fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 256 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = hasher.finalize();
    if actual.as_bytes() != expected_blake3 {
        return Err(ProjectionError::InvalidEvent {
            msg: format!(
                "cold segment blake3 mismatch at {}: expected {} got {}",
                path.display(),
                blake3::Hash::from(*expected_blake3).to_hex(),
                actual.to_hex()
            ),
        });
    }

    // Parse header + index.
    f.seek(SeekFrom::Start(0))?;
    let mut header_bytes = [0u8; CCXC_HEADER_LEN_V1];
    f.read_exact(&mut header_bytes)?;
    if header_bytes[0..4] != CCXC_MAGIC {
        return Err(ProjectionError::InvalidEvent {
            msg: "cold segment invalid magic".to_string(),
        });
    }
    let v = u32::from_le_bytes(header_bytes[4..8].try_into().unwrap());
    if v != CCXC_V1 {
        return Err(ProjectionError::InvalidEvent {
            msg: format!("unsupported cold segment version {}", v),
        });
    }
    let block_count = u32::from_le_bytes(header_bytes[8..12].try_into().unwrap());
    let index_offset = u64::from_le_bytes(header_bytes[16..24].try_into().unwrap());
    let index_len = u64::from_le_bytes(header_bytes[24..32].try_into().unwrap());
    if index_offset < (CCXC_HEADER_LEN_V1 as u64) {
        return Err(ProjectionError::InvalidEvent {
            msg: "cold segment index_offset points into header".to_string(),
        });
    }
    if index_offset.saturating_add(index_len).saturating_add(0) != expected_len {
        return Err(ProjectionError::InvalidEvent {
            msg: "cold segment index_offset/index_len do not match file length".to_string(),
        });
    }

    f.seek(SeekFrom::Start(index_offset))?;
    let mut idx = vec![0u8; index_len as usize];
    f.read_exact(&mut idx)?;
    if idx.len() < 16 {
        return Err(ProjectionError::InvalidEvent {
            msg: "cold segment index too small".to_string(),
        });
    }
    if idx[0..4] != CCXC_INDEX_MAGIC {
        return Err(ProjectionError::InvalidEvent {
            msg: "cold segment index invalid magic".to_string(),
        });
    }
    let iv = u32::from_le_bytes(idx[4..8].try_into().unwrap());
    if iv != CCXC_INDEX_V1 {
        return Err(ProjectionError::InvalidEvent {
            msg: format!("unsupported cold segment index version {}", iv),
        });
    }
    let entry_count = u32::from_le_bytes(idx[8..12].try_into().unwrap()) as usize;
    let expected_index_len = 16usize + entry_count * 48usize;
    if expected_index_len != idx.len() {
        return Err(ProjectionError::InvalidEvent {
            msg: "cold segment index length does not match entry_count".to_string(),
        });
    }
    if entry_count != (block_count as usize) {
        return Err(ProjectionError::InvalidEvent {
            msg: "cold segment header block_count != index entry_count".to_string(),
        });
    }

    let mut entries = Vec::with_capacity(entry_count);
    let mut cursor = 16usize;
    let mut last_hash: Option<[u8; 32]> = None;
    for _ in 0..entry_count {
        let mut h = [0u8; 32];
        h.copy_from_slice(&idx[cursor..cursor + 32]);
        cursor += 32;
        let offset = u64::from_le_bytes(idx[cursor..cursor + 8].try_into().unwrap());
        cursor += 8;
        let len = u32::from_le_bytes(idx[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;
        let codec = u32::from_le_bytes(idx[cursor..cursor + 4].try_into().unwrap());
        cursor += 4;

        if let Some(prev) = last_hash {
            if h <= prev {
                return Err(ProjectionError::InvalidEvent {
                    msg: "cold segment index entries are not strictly increasing by blake3".to_string(),
                });
            }
        }
        last_hash = Some(h);

        entries.push(ColdSegmentIndexEntryV1 {
            block_blake3: h,
            offset,
            len,
            codec,
        });
    }

    Ok((
        ColdSegmentHeaderV1 {
            block_count,
            index_offset,
            index_len,
        },
        entries,
    ))
}

pub fn read_cold_segment_block_v1(path: &Path, offset: u64, len: u32) -> Result<Vec<u8>> {
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut out = vec![0u8; len as usize];
    f.read_exact(&mut out)?;
    Ok(out)
}
