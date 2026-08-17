// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `.ccxf` file format — per-segment reverse-frame companion. Reader only.
//!
//! Stores "reverse frames" — short canonical-form questions a session can answer —
//! keyed back to the parent `(session_id, doc_id)` tuple.
//!
//! The motivating problem: BM25, dense and sparse all rank a session by its *dominant
//! topic*, so a session about gaming PCs that incidentally mentions finishing a game
//! last weekend ranks the gaming-PC topic high and the buried fact low. Reverse frames
//! invert that — at ingest the producer emits a handful of short questions the session
//! uniquely answers, and the lane matches the query against those instead.
//!
//! Layout (little-endian):
//!   `CcxfHeader`              — 40 bytes
//!   `FrameEntry` × N          — 40 bytes each
//!   `ArgsTable`               — variable, contiguous `(u32 heap_offset, u32 heap_len)`
//!                              pairs; each frame points at a `[start, start+n_args)` slice
//!   `StringHeap`              — variable, UTF-8 (frame texts + arg strings)
//!   Footer                    — 4 bytes, CRC32C over the preceding bytes
//!
//! **Reader half only** (ExecPlan constraint C7). See `VENDORED_FROM.md`.

use crate::le::{crc32c, read_u16, read_u32, read_u64};
use crate::IndexError;

pub const CCXF_MAGIC: u32 = 0x4343_5846; // "CCXF"
pub const CCXF_VERSION: u8 = 1;
pub const CCXF_SCHEMA_VERSION: u8 = 1;

const HEADER_LEN: usize = 40;
const FRAME_ENTRY_LEN: usize = 40;
const ARG_PAIR_LEN: usize = 8; // (u32 offset, u32 len)
const FOOTER_LEN: usize = 4;

/// One reverse-frame record: a short canonical-form question a session uniquely
/// answers, plus optional structured args and provenance metadata.
#[derive(Debug, Clone)]
pub struct ReverseFrame {
    /// `xxh64(stream_id)` of the parent session this frame answers.
    pub session_id: u64,
    /// Segment-local doc id of the source chunk. Keys back into the same
    /// `(seg_idx, doc_id)` space the BM25 and dense lanes operate in.
    pub doc_id: u32,
    /// When the frame was emitted (Unix seconds). `0` means "unknown".
    pub generated_at_unix_secs: u64,
    /// Optional byte offset into the source chunk text; `0` when untracked.
    pub source_chunk_offset: u32,
    /// The frame text — a short, canonical-form question.
    pub frame_text: String,
    /// Optional structured args in a normalised `key=value` shape, e.g.
    /// `["item=Hollow Knight", "time=last_weekend"]`. The lane's primary surface is
    /// `frame_text`; args are observability and future per-class fusion fuel.
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CcxfHeader {
    pub magic: u32,
    pub version: u8,
    pub schema_version: u8,
    pub flags: u16,
    pub shard_id: u32,
    pub segment_seq: u64,
    pub epoch: u64,
    pub frame_count: u32,
    pub string_heap_len: u32,
    pub args_table_pairs: u32,
}

/// Reader: parses a `.ccxf` file from a byte slice. Validates magic, version and the
/// footer CRC32C before exposing any accessor.
#[derive(Debug)]
pub struct CcxfReader<'a> {
    header: CcxfHeader,
    frame_area: &'a [u8],
    args_table: &'a [u8],
    string_heap: &'a [u8],
}

impl<'a> CcxfReader<'a> {
    pub fn new(data: &'a [u8]) -> crate::Result<Self> {
        if data.len() < HEADER_LEN + FOOTER_LEN {
            return Err(IndexError::BufferTooSmall);
        }

        let magic = read_u32(data, 0);
        if magic != CCXF_MAGIC {
            return Err(IndexError::InvalidMagic {
                expected: CCXF_MAGIC,
                actual: magic,
            });
        }
        let version = data[4];
        if version != CCXF_VERSION {
            return Err(IndexError::UnsupportedVersion {
                version: u16::from(version),
            });
        }
        let schema_version = data[5];
        let flags = read_u16(data, 6);
        let shard_id = read_u32(data, 8);
        let segment_seq = read_u64(data, 12);
        let epoch = read_u64(data, 20);
        let frame_count = read_u32(data, 28);
        let string_heap_len = read_u32(data, 32);
        let args_table_pairs = read_u32(data, 36);

        let frame_area_len = (frame_count as usize) * FRAME_ENTRY_LEN;
        let args_table_len = (args_table_pairs as usize) * ARG_PAIR_LEN;
        let body_end = HEADER_LEN
            .checked_add(frame_area_len)
            .and_then(|n| n.checked_add(args_table_len))
            .and_then(|n| n.checked_add(string_heap_len as usize))
            .ok_or(IndexError::BufferTooSmall)?;
        let expected_total = body_end.checked_add(FOOTER_LEN).ok_or(IndexError::BufferTooSmall)?;
        if data.len() < expected_total {
            return Err(IndexError::BufferTooSmall);
        }

        let stored_crc = read_u32(data, body_end);
        let computed_crc = crc32c(&data[..body_end]);
        if stored_crc != computed_crc {
            return Err(IndexError::IntegrityFailure {
                msg: format!("CRC32C mismatch: stored {stored_crc:#x}, computed {computed_crc:#x}"),
            });
        }

        let frame_area = &data[HEADER_LEN..HEADER_LEN + frame_area_len];
        let args_start = HEADER_LEN + frame_area_len;
        let args_table = &data[args_start..args_start + args_table_len];
        let heap_start = args_start + args_table_len;
        let string_heap = &data[heap_start..heap_start + string_heap_len as usize];

        Ok(Self {
            header: CcxfHeader {
                magic,
                version,
                schema_version,
                flags,
                shard_id,
                segment_seq,
                epoch,
                frame_count,
                string_heap_len,
                args_table_pairs,
            },
            frame_area,
            args_table,
            string_heap,
        })
    }

    pub fn header(&self) -> &CcxfHeader {
        &self.header
    }

    pub fn frame_count(&self) -> u32 {
        self.header.frame_count
    }

    pub fn schema_version(&self) -> u8 {
        self.header.schema_version
    }

    /// Decode the frame at the given local index. `None` when the index is out of
    /// range or the entry's payload is corrupt.
    pub fn get(&self, frame_idx: u32) -> Option<ReverseFrame> {
        if frame_idx >= self.header.frame_count {
            return None;
        }
        let off = (frame_idx as usize) * FRAME_ENTRY_LEN;
        let entry = &self.frame_area[off..off + FRAME_ENTRY_LEN];
        let session_id = read_u64(entry, 0);
        let doc_id = read_u32(entry, 8);
        let generated_at_unix_secs = read_u64(entry, 12);
        let source_chunk_offset = read_u32(entry, 20);
        let ft_off = read_u32(entry, 24) as usize;
        let ft_len = read_u32(entry, 28) as usize;
        let args_idx = read_u32(entry, 32) as usize;
        let n_args = entry[36];

        let frame_text_bytes = self.string_heap.get(ft_off..ft_off.checked_add(ft_len)?)?;
        let frame_text = String::from_utf8(frame_text_bytes.to_vec()).ok()?;

        let mut args: Vec<String> = Vec::with_capacity(n_args as usize);
        for i in 0..n_args as usize {
            let pair_off = args_idx.checked_add(i)?.checked_mul(ARG_PAIR_LEN)?;
            let pair = self.args_table.get(pair_off..pair_off.checked_add(ARG_PAIR_LEN)?)?;
            let heap_off = read_u32(pair, 0) as usize;
            let heap_len = read_u32(pair, 4) as usize;
            let a_bytes = self.string_heap.get(heap_off..heap_off.checked_add(heap_len)?)?;
            args.push(String::from_utf8(a_bytes.to_vec()).ok()?);
        }

        Some(ReverseFrame {
            session_id,
            doc_id,
            generated_at_unix_secs,
            source_chunk_offset,
            frame_text,
            args,
        })
    }

    /// Iterate every frame in the file. Entries with corrupt string offsets are
    /// skipped — defensive; a CRC-clean file should have none.
    pub fn iter(&self) -> impl Iterator<Item = ReverseFrame> + '_ {
        (0..self.header.frame_count).filter_map(|i| self.get(i))
    }

    /// Iterate `(session_id, doc_id, frame_text)` triples without allocating a full
    /// [`ReverseFrame`]. The lane's search loop only needs the text plus parent keys
    /// per scoring iteration.
    pub fn iter_text<'b>(&'b self) -> impl Iterator<Item = (u64, u32, &'b str)> + 'b
    where
        'a: 'b,
    {
        (0..self.header.frame_count as usize).filter_map(move |i| {
            let off = i * FRAME_ENTRY_LEN;
            let entry = &self.frame_area[off..off + FRAME_ENTRY_LEN];
            let session_id = read_u64(entry, 0);
            let doc_id = read_u32(entry, 8);
            let ft_off = read_u32(entry, 24) as usize;
            let ft_len = read_u32(entry, 28) as usize;
            let bytes = self.string_heap.get(ft_off..ft_off.checked_add(ft_len)?)?;
            let text = std::str::from_utf8(bytes).ok()?;
            Some((session_id, doc_id, text))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_truncated_buffer_is_rejected_not_indexed() {
        assert!(matches!(CcxfReader::new(&[0u8; 8]), Err(IndexError::BufferTooSmall)));
    }

    #[test]
    fn a_foreign_magic_is_rejected() {
        let mut data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        data[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(matches!(CcxfReader::new(&data), Err(IndexError::InvalidMagic { .. })));
    }

    #[test]
    fn an_unsupported_version_is_rejected() {
        let mut data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        data[0..4].copy_from_slice(&CCXF_MAGIC.to_le_bytes());
        data[4] = CCXF_VERSION + 1;
        assert!(matches!(
            CcxfReader::new(&data),
            Err(IndexError::UnsupportedVersion { .. })
        ));
    }

    /// An empty file is well-formed: a segment can legitimately carry no frames.
    /// It must open and report zero, not fail.
    #[test]
    fn an_empty_frame_file_opens_and_reports_zero() {
        let mut data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        data[0..4].copy_from_slice(&CCXF_MAGIC.to_le_bytes());
        data[4] = CCXF_VERSION;
        let crc = crc32c(&data[..HEADER_LEN]);
        data[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&crc.to_le_bytes());
        let reader = CcxfReader::new(&data).expect("an empty .ccxf is valid");
        assert_eq!(reader.frame_count(), 0);
        assert_eq!(reader.iter().count(), 0);
        assert!(reader.get(0).is_none());
    }
}
