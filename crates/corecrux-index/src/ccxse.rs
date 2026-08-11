// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `.ccxse` file format — per-segment **subject-trait embeddings** companion. Reader only.
//!
//! Sibling to [`crate::ccxs`]: where `.ccxs` carries a subject's rolled-up
//! `(predicate, object)` traits, `.ccxse` carries the corresponding **embeddings** —
//! one vector per trait, in the embed space the cosine lane uses. At query time the
//! daemon embeds the query, sweeps a tenant's trait embeddings, and picks the top-K
//! aligned traits.
//!
//! The two files are keyed the same way — `xxh64(kind_byte || subject_id_bytes)`, seed
//! 0 — so a `.ccxs` lookup and a `.ccxse` lookup for one subject use one hash. The
//! header's `source_ccxs_crc` records the CRC32C of the `.ccxs` these embeddings were
//! built from, so a mismatched pair is detectable rather than silently mis-aligned.
//!
//! Layout (little-endian):
//!   `CcxseHeader`             — 44 bytes
//!   `SubjectEntry` × N        — 24 bytes each, sorted ascending by `subject_hash`
//!   `EmbeddingArea`           — variable, `embeddings_total × embedding_dim` elements
//!                              of [`CcxseDtype`]
//!   Footer                    — 4 bytes, CRC32C over the preceding bytes
//!
//! **Reader half only** (ExecPlan constraint C7). See `VENDORED_FROM.md`.

use crate::le::{crc32c, read_u16, read_u32, read_u64};
use crate::IndexError;
use half::f16;

pub const CCXSE_MAGIC: u32 = 0x4343_5345; // "CCSE"
pub const CCXSE_VERSION: u8 = 1;
pub const CCXSE_SCHEMA_VERSION: u8 = 1;

const HEADER_LEN: usize = 44;
const SUBJECT_ENTRY_LEN: usize = 24;
const FOOTER_LEN: usize = 4;

/// Per-embedding dtype tag. The platform ships fp16; the reserved values let it swap
/// to another width without rev'ing the file version.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CcxseDtype {
    #[default]
    Fp16 = 0,
    Fp32 = 1,
}

impl CcxseDtype {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Fp16),
            1 => Some(Self::Fp32),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn bytes_per_element(self) -> usize {
        match self {
            Self::Fp16 => 2,
            Self::Fp32 => 4,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CcxseHeader {
    pub magic: u32,
    pub version: u8,
    pub schema_version: u8,
    pub flags: u16,
    pub shard_id: u32,
    pub segment_seq: u64,
    pub epoch: u64,
    pub subject_count: u32,
    pub embeddings_total: u32,
    pub embedding_dim: u16,
    pub dtype: CcxseDtype,
    /// CRC32C of the `.ccxs` these embeddings were built from.
    pub source_ccxs_crc: u32,
}

/// Reader: parses a `.ccxse` file from a byte slice. Validates magic, version, the
/// dtype tag and the footer CRC32C before exposing any accessor.
#[derive(Debug)]
pub struct CcxseReader<'a> {
    header: CcxseHeader,
    entry_area: &'a [u8],
    embedding_area: &'a [u8],
}

/// Result of a subject lookup. Borrowed slice into the reader's underlying bytes.
/// Use [`EmbeddingSlice::iter`] to decode trait by trait, or
/// [`EmbeddingSlice::vector_at`] for an indexed read.
#[derive(Debug, Clone, Copy)]
pub struct EmbeddingSlice<'a> {
    pub subject_hash: u64,
    pub n_embeddings: u32,
    pub embedding_dim: u16,
    pub dtype: CcxseDtype,
    bytes: &'a [u8],
}

impl<'a> EmbeddingSlice<'a> {
    pub fn n_embeddings(&self) -> u32 {
        self.n_embeddings
    }

    pub fn embedding_dim(&self) -> u16 {
        self.embedding_dim
    }

    pub fn raw_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Decode the embedding at index `i` into an owned `Vec<f32>`. `None` when
    /// `i >= n_embeddings`.
    pub fn vector_at(&self, i: usize) -> Option<Vec<f32>> {
        if i >= self.n_embeddings as usize {
            return None;
        }
        let dim = self.embedding_dim as usize;
        let elem = self.dtype.bytes_per_element();
        let off = i.checked_mul(dim)?.checked_mul(elem)?;
        let end = off.checked_add(dim.checked_mul(elem)?)?;
        if end > self.bytes.len() {
            return None;
        }
        Some(decode_vec(&self.bytes[off..end], dim, self.dtype))
    }

    /// Iterate every embedding for this subject, decoding each to a `Vec<f32>`.
    pub fn iter(&self) -> impl Iterator<Item = Vec<f32>> + 'a {
        let bytes = self.bytes;
        let dim = self.embedding_dim as usize;
        let elem = self.dtype.bytes_per_element();
        let dtype = self.dtype;
        let n = self.n_embeddings as usize;
        (0..n).filter_map(move |i| {
            let off = i * dim * elem;
            let end = off + dim * elem;
            if end > bytes.len() {
                return None;
            }
            Some(decode_vec(&bytes[off..end], dim, dtype))
        })
    }
}

fn decode_vec(slab: &[u8], dim: usize, dtype: CcxseDtype) -> Vec<f32> {
    let mut out = Vec::with_capacity(dim);
    match dtype {
        CcxseDtype::Fp16 => {
            for chunk in slab.chunks_exact(2) {
                out.push(f16::from_bits(u16::from_le_bytes([chunk[0], chunk[1]])).to_f32());
            }
        }
        CcxseDtype::Fp32 => {
            for chunk in slab.chunks_exact(4) {
                out.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
        }
    }
    out
}

impl<'a> CcxseReader<'a> {
    pub fn new(data: &'a [u8]) -> crate::Result<Self> {
        if data.len() < HEADER_LEN + FOOTER_LEN {
            return Err(IndexError::BufferTooSmall);
        }

        let magic = read_u32(data, 0);
        if magic != CCXSE_MAGIC {
            return Err(IndexError::InvalidMagic {
                expected: CCXSE_MAGIC,
                actual: magic,
            });
        }
        let version = data[4];
        if version != CCXSE_VERSION {
            return Err(IndexError::UnsupportedVersion {
                version: u16::from(version),
            });
        }
        let schema_version = data[5];
        let flags = read_u16(data, 6);
        let shard_id = read_u32(data, 8);
        let segment_seq = read_u64(data, 12);
        let epoch = read_u64(data, 20);
        let subject_count = read_u32(data, 28);
        let embeddings_total = read_u32(data, 32);
        let embedding_dim = read_u16(data, 36);
        let dtype_byte = data[38];
        let dtype = CcxseDtype::from_u8(dtype_byte).ok_or_else(|| IndexError::IntegrityFailure {
            msg: format!("unknown .ccxse dtype tag {dtype_byte}"),
        })?;
        // data[39] reserved
        let source_ccxs_crc = read_u32(data, 40);

        let entry_area_len = (subject_count as usize) * SUBJECT_ENTRY_LEN;
        let elem_bytes = dtype.bytes_per_element();
        let embedding_area_len = (embeddings_total as usize) * (embedding_dim as usize) * elem_bytes;
        let body_end = HEADER_LEN
            .checked_add(entry_area_len)
            .and_then(|n| n.checked_add(embedding_area_len))
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

        let entry_area = &data[HEADER_LEN..HEADER_LEN + entry_area_len];
        let emb_start = HEADER_LEN + entry_area_len;
        let embedding_area = &data[emb_start..emb_start + embedding_area_len];

        Ok(Self {
            header: CcxseHeader {
                magic,
                version,
                schema_version,
                flags,
                shard_id,
                segment_seq,
                epoch,
                subject_count,
                embeddings_total,
                embedding_dim,
                dtype,
                source_ccxs_crc,
            },
            entry_area,
            embedding_area,
        })
    }

    pub fn header(&self) -> &CcxseHeader {
        &self.header
    }

    pub fn subject_count(&self) -> u32 {
        self.header.subject_count
    }

    pub fn embeddings_total(&self) -> u32 {
        self.header.embeddings_total
    }

    pub fn embedding_dim(&self) -> u16 {
        self.header.embedding_dim
    }

    pub fn dtype(&self) -> CcxseDtype {
        self.header.dtype
    }

    pub fn source_ccxs_crc(&self) -> u32 {
        self.header.source_ccxs_crc
    }

    fn entry_at(&self, i: usize) -> Option<EmbeddingSlice<'a>> {
        if i >= self.header.subject_count as usize {
            return None;
        }
        let off = i * SUBJECT_ENTRY_LEN;
        let entry = &self.entry_area[off..off + SUBJECT_ENTRY_LEN];
        let subject_hash = read_u64(entry, 0);
        let emb_offset = read_u32(entry, 8) as usize;
        let n_embeddings = read_u32(entry, 12);
        let dim = self.header.embedding_dim as usize;
        let elem = self.header.dtype.bytes_per_element();
        let byte_off = emb_offset.checked_mul(dim)?.checked_mul(elem)?;
        let byte_len = (n_embeddings as usize).checked_mul(dim)?.checked_mul(elem)?;
        let bytes = self.embedding_area.get(byte_off..byte_off.checked_add(byte_len)?)?;
        Some(EmbeddingSlice {
            subject_hash,
            n_embeddings,
            embedding_dim: self.header.embedding_dim,
            dtype: self.header.dtype,
            bytes,
        })
    }

    /// Look up a subject by its pre-computed `xxh64(kind || subject_id)`.
    /// `O(log N)` binary search; mirrors `.ccxs`.
    pub fn lookup_by_hash(&self, subject_hash: u64) -> Option<EmbeddingSlice<'a>> {
        if self.header.subject_count == 0 {
            return None;
        }
        let mut lo = 0usize;
        let mut hi = self.header.subject_count as usize;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let mid_hash = read_u64(self.entry_area, mid * SUBJECT_ENTRY_LEN);
            match mid_hash.cmp(&subject_hash) {
                std::cmp::Ordering::Equal => return self.entry_at(mid),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    /// Iterate every subject in the file.
    pub fn iter(&self) -> impl Iterator<Item = EmbeddingSlice<'a>> + '_ {
        (0..self.header.subject_count as usize).filter_map(move |i| self.entry_at(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dtype_round_trips_via_u8() {
        for d in [CcxseDtype::Fp16, CcxseDtype::Fp32] {
            assert_eq!(CcxseDtype::from_u8(d.as_u8()), Some(d));
        }
        assert_eq!(CcxseDtype::from_u8(7), None);
    }

    #[test]
    fn dtype_element_widths_are_the_on_disk_ones() {
        assert_eq!(CcxseDtype::Fp16.bytes_per_element(), 2);
        assert_eq!(CcxseDtype::Fp32.bytes_per_element(), 4);
    }

    #[test]
    fn a_truncated_buffer_is_rejected_not_indexed() {
        assert!(matches!(CcxseReader::new(&[0u8; 8]), Err(IndexError::BufferTooSmall)));
    }

    #[test]
    fn a_foreign_magic_is_rejected() {
        let mut data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        data[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(matches!(CcxseReader::new(&data), Err(IndexError::InvalidMagic { .. })));
    }

    /// An unknown dtype tag must fail loudly. Reading it as fp16 would decode every
    /// vector at the wrong stride and return plausible-looking noise.
    #[test]
    fn an_unknown_dtype_tag_is_an_integrity_failure() {
        let mut data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        data[0..4].copy_from_slice(&CCXSE_MAGIC.to_le_bytes());
        data[4] = CCXSE_VERSION;
        data[38] = 9;
        assert!(matches!(
            CcxseReader::new(&data),
            Err(IndexError::IntegrityFailure { .. })
        ));
    }

    #[test]
    fn fp32_decode_reads_little_endian_floats() {
        let mut slab = Vec::new();
        for v in [1.0f32, -2.5, 0.25] {
            slab.extend_from_slice(&v.to_le_bytes());
        }
        assert_eq!(decode_vec(&slab, 3, CcxseDtype::Fp32), vec![1.0, -2.5, 0.25]);
    }

    #[test]
    fn fp16_decode_widens_to_f32() {
        let mut slab = Vec::new();
        for v in [1.0f32, -2.5] {
            slab.extend_from_slice(&f16::from_f32(v).to_bits().to_le_bytes());
        }
        let out = decode_vec(&slab, 2, CcxseDtype::Fp16);
        assert_eq!(out.len(), 2);
        assert!((out[0] - 1.0).abs() < 1e-3);
        assert!((out[1] - -2.5).abs() < 1e-3);
    }
}
