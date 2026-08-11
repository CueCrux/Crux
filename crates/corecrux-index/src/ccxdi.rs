// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `.ccxdi` file format — per-segment document-index companion. Reader only.
//!
//! Stores per-document read-pointers `(doc_id, region_id, byte_offset, surface_text,
//! kind)` for the indexing retrieval lane. Built by the platform at seal time
//! alongside `.ccxi` / `.ccxe`. Doc-grain: it returns verbatim read-pointers rather
//! than boost weights.
//!
//! Layout:
//!   Header (32 bytes)
//!   Doc-table (`doc_count` × 32 bytes), sorted ascending by `doc_id`
//!   Region table (`region_count` × 24 bytes)
//!   Pointer table (`pointer_count` × 32 bytes)
//!   Strings pool (length-prefixed UTF-8, deduplicated by the builder)
//!   Footer (4 bytes, CRC32C over everything before it)
//!
//! **Reader half only** (ExecPlan constraint C7). See `VENDORED_FROM.md`.

use crate::le::{crc32c, read_u16, read_u32, read_u64};

/// Magic bytes that identify a `.ccxdi` file.
pub const CCXDI_MAGIC: [u8; 5] = *b"CCXDI";

/// Current `.ccxdi` file-format version.
///
/// **Stable across schema-version bumps.** The v1 and v2 wire-byte layouts are
/// byte-identical; the only difference is what the previously-reserved 8 trailing
/// bytes of each [`DocTableEntry`] mean. Readers always parse the same wire shape and
/// branch on `schema_version`.
pub const CCXDI_VERSION: u8 = 1;

/// Current `.ccxdi` logical schema version.
///
/// * `1` — no per-doc `tenant_hash`; the trailing 8 bytes of each doc-table entry are
///   zero padding.
/// * `2` — per-doc `tenant_hash: u64` (first 8 bytes of SHA-256 of the tenant id)
///   overlaid onto those reserved bytes. Wire layout unchanged, so an old binary on a
///   new file still passes CRC; only [`DocTableEntry::tenant_hash`] changes from
///   `None` to `Some(_)`.
pub const CCXDI_SCHEMA_VERSION: u8 = 2;

/// Schema version that introduced per-doc `tenant_hash`. Readers branch on
/// `header.schema_version >= CCXDI_SCHEMA_VERSION_TENANT_HASH` to decide whether the
/// 8 trailing bytes of each doc-table entry hold a real hash or are padding.
pub const CCXDI_SCHEMA_VERSION_TENANT_HASH: u8 = 2;

const HEADER_LEN: usize = 32;
const DOC_ENTRY_LEN: usize = 32;
const REGION_ENTRY_LEN: usize = 24;
const POINTER_ENTRY_LEN: usize = 32;
const FOOTER_LEN: usize = 4;

/// Sentinel offset meaning "this region has no header text".
pub const NO_HEADER: u32 = u32::MAX;

/// Region-kind enum values.
pub mod region_kind {
    /// Markdown header-elevated section.
    pub const SECTION: u8 = 1;
    /// Blank-line-bounded paragraph (the default).
    pub const PARAGRAPH: u8 = 2;
    /// List block.
    pub const LIST: u8 = 3;
    /// Block quote.
    pub const QUOTE: u8 = 4;
    /// Code fence or indented code block.
    pub const CODE: u8 = 5;
}

/// Pointer-kind enum values.
pub mod pointer_kind {
    /// Entity occurrence (sourced from `.ccxn`).
    pub const ENTITY: u8 = 1;
    /// Topical-shift pointer.
    pub const TOPIC: u8 = 2;
    /// Subject-profile fact (sourced from `.ccxs`).
    pub const KEY_FACT: u8 = 3;
}

/// Decoded `.ccxdi` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcxdiHeader {
    /// File-format version.
    pub version: u8,
    /// Logical schema version.
    pub schema_version: u8,
    /// Number of doc-table entries.
    pub doc_count: u32,
    /// Sum of regions across all docs.
    pub region_count: u32,
    /// Sum of pointers across all docs.
    pub pointer_count: u32,
    /// Reserved flags.
    pub flags: u16,
    /// Absolute byte offset from file start to the strings pool.
    pub strings_offset: u32,
    /// Length of the strings pool in bytes.
    pub strings_len: u32,
}

/// Decoded doc-table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocTableEntry {
    /// Segment-scoped document identifier.
    pub doc_id: u64,
    /// Number of regions for this doc.
    pub region_count: u32,
    /// Number of pointers for this doc.
    pub pointer_count: u32,
    /// Index into the global region table (not a byte offset).
    pub region_offset: u32,
    /// Index into the global pointer table.
    pub pointer_offset: u32,
    /// Per-doc tenant hash (first 8 bytes of SHA-256 of the tenant id).
    ///
    /// `Some(_)` at schema version >= [`CCXDI_SCHEMA_VERSION_TENANT_HASH`]; `None` at
    /// schema version 1, which a consumer must treat as "unknown", never as a match.
    pub tenant_hash: Option<u64>,
}

/// Decoded region entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionEntry {
    /// Doc-local region identifier.
    pub region_id: u32,
    /// Byte offset of the region's start in the source doc text.
    pub byte_start: u32,
    /// Byte offset of the region's end, exclusive.
    pub byte_end: u32,
    /// Region kind; see [`region_kind`].
    pub kind: u8,
    /// Header text, `None` when the region has none.
    pub header: Option<String>,
}

/// Decoded pointer entry.
#[derive(Debug, Clone, PartialEq)]
pub struct PointerEntry {
    /// Pointer kind; see [`pointer_kind`].
    pub kind: u8,
    /// Owning doc id.
    pub doc_id: u64,
    /// Containing region within the doc.
    pub region_id: u32,
    /// Byte offset of the pointer in the source doc text.
    pub byte_offset: u32,
    /// Surface text (canonical entity, topic label, or predicate name).
    pub surface: String,
    /// Salience score in `[0.0, ~256.0)`. Q8.8 fixed-point on disk.
    pub score: f32,
}

/// Errors returned by [`CcxdiReader`].
#[derive(Debug, thiserror::Error)]
pub enum CcxdiError {
    /// Magic bytes did not match `b"CCXDI"`.
    #[error("bad ccxdi magic")]
    BadMagic,
    /// Unsupported file-format version.
    #[error("bad ccxdi version: {0}")]
    BadVersion(u8),
    /// CRC32C footer did not match the recomputed checksum.
    #[error("ccxdi checksum mismatch: stored {stored:#010x} computed {computed:#010x}")]
    BadChecksum {
        /// Footer-stored checksum.
        stored: u32,
        /// Checksum recomputed over the body.
        computed: u32,
    },
    /// Buffer ended before the expected payload.
    #[error("ccxdi truncated")]
    Truncated,
    /// Strings-pool offset out of range, or a string length crossing the pool bounds.
    #[error("ccxdi bad string offset: {0}")]
    BadStringOffset(u32),
}

/// Reader: parses a `.ccxdi` byte slice into doc / region / pointer accessors.
///
/// Validates magic, version and the CRC32C footer on construction. Accessors borrow
/// from the original slice; the reader itself allocates nothing.
#[derive(Debug)]
pub struct CcxdiReader<'a> {
    data: &'a [u8],
    header: CcxdiHeader,
    doc_table_offset: usize,
    regions_offset: usize,
    pointers_offset: usize,
    strings_offset: usize,
    strings_len: usize,
}

impl<'a> CcxdiReader<'a> {
    /// Parse from a byte slice. Validates magic, version and checksum.
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, CcxdiError> {
        if data.len() < HEADER_LEN + FOOTER_LEN {
            return Err(CcxdiError::Truncated);
        }
        if data[..5] != CCXDI_MAGIC {
            return Err(CcxdiError::BadMagic);
        }
        let version = data[5];
        if version != CCXDI_VERSION {
            return Err(CcxdiError::BadVersion(version));
        }
        let schema_version = data[6];
        let doc_count = read_u32(data, 7);
        let region_count = read_u32(data, 11);
        let pointer_count = read_u32(data, 15);
        let flags = read_u16(data, 19);
        let strings_offset = read_u32(data, 21);
        let strings_len = read_u32(data, 25);
        // bytes 29..32 are padding.

        let doc_table_offset = HEADER_LEN;
        let regions_offset = doc_table_offset
            .checked_add(
                (doc_count as usize)
                    .checked_mul(DOC_ENTRY_LEN)
                    .ok_or(CcxdiError::Truncated)?,
            )
            .ok_or(CcxdiError::Truncated)?;
        let pointers_offset = regions_offset
            .checked_add(
                (region_count as usize)
                    .checked_mul(REGION_ENTRY_LEN)
                    .ok_or(CcxdiError::Truncated)?,
            )
            .ok_or(CcxdiError::Truncated)?;
        let expected_strings_offset = pointers_offset
            .checked_add(
                (pointer_count as usize)
                    .checked_mul(POINTER_ENTRY_LEN)
                    .ok_or(CcxdiError::Truncated)?,
            )
            .ok_or(CcxdiError::Truncated)?;
        if (strings_offset as usize) != expected_strings_offset {
            return Err(CcxdiError::Truncated);
        }
        let total_len = expected_strings_offset
            .checked_add(strings_len as usize)
            .and_then(|n| n.checked_add(FOOTER_LEN))
            .ok_or(CcxdiError::Truncated)?;
        if data.len() < total_len {
            return Err(CcxdiError::Truncated);
        }

        // CRC32C over header + body — everything except the footer.
        let body_end = total_len - FOOTER_LEN;
        let stored = read_u32(data, body_end);
        let computed = crc32c(&data[..body_end]);
        if stored != computed {
            return Err(CcxdiError::BadChecksum { stored, computed });
        }

        Ok(Self {
            data,
            header: CcxdiHeader {
                version,
                schema_version,
                doc_count,
                region_count,
                pointer_count,
                flags,
                strings_offset,
                strings_len,
            },
            doc_table_offset,
            regions_offset,
            pointers_offset,
            strings_offset: strings_offset as usize,
            strings_len: strings_len as usize,
        })
    }

    /// The decoded header.
    pub fn header(&self) -> &CcxdiHeader {
        &self.header
    }

    /// Number of docs in this companion.
    pub fn doc_count(&self) -> u32 {
        self.header.doc_count
    }

    /// Iterate every doc-table entry, in `doc_id`-ascending order.
    pub fn iter_docs(&self) -> DocIter<'_, 'a> {
        DocIter { reader: self, next: 0 }
    }

    /// Look up a doc-table entry by `doc_id`. The doc table is written sorted, so
    /// this binary-searches.
    pub fn find_doc(&self, doc_id: u64) -> Option<DocTableEntry> {
        let (mut lo, mut hi) = (0u32, self.header.doc_count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let entry = self.read_doc_entry(mid);
            match entry.doc_id.cmp(&doc_id) {
                std::cmp::Ordering::Equal => return Some(entry),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    fn read_doc_entry(&self, idx: u32) -> DocTableEntry {
        let off = self.doc_table_offset + idx as usize * DOC_ENTRY_LEN;
        let s = &self.data[off..off + DOC_ENTRY_LEN];
        // v1 leaves bytes 24..32 as zero padding; v2 stores `tenant_hash` there. The
        // wire shape is identical, so the branch is on `schema_version`, and v1 must
        // surface `None` rather than a zero hash — a consumer that read zero as a
        // real tenant would match every doc whose slot happened to be empty.
        let tenant_hash = if self.header.schema_version >= CCXDI_SCHEMA_VERSION_TENANT_HASH {
            Some(read_u64(s, 24))
        } else {
            None
        };
        DocTableEntry {
            doc_id: read_u64(s, 0),
            region_count: read_u32(s, 8),
            pointer_count: read_u32(s, 12),
            region_offset: read_u32(s, 16),
            pointer_offset: read_u32(s, 20),
            tenant_hash,
        }
    }

    /// Every region for `doc_id`, or an empty vec when the doc is absent.
    pub fn regions_for_doc(&self, doc_id: u64) -> Result<Vec<RegionEntry>, CcxdiError> {
        let Some(entry) = self.find_doc(doc_id) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(entry.region_count as usize);
        for i in 0..entry.region_count {
            out.push(self.read_region(entry.region_offset + i)?);
        }
        Ok(out)
    }

    /// Every pointer for `doc_id`, or an empty vec when the doc is absent.
    pub fn pointers_for_doc(&self, doc_id: u64) -> Result<Vec<PointerEntry>, CcxdiError> {
        let Some(entry) = self.find_doc(doc_id) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(entry.pointer_count as usize);
        for i in 0..entry.pointer_count {
            out.push(self.read_pointer(entry.pointer_offset + i)?);
        }
        Ok(out)
    }

    fn read_region(&self, idx: u32) -> Result<RegionEntry, CcxdiError> {
        let off = self.regions_offset + idx as usize * REGION_ENTRY_LEN;
        if off + REGION_ENTRY_LEN > self.data.len() {
            return Err(CcxdiError::Truncated);
        }
        let s = &self.data[off..off + REGION_ENTRY_LEN];
        let region_id = read_u32(s, 0);
        let byte_start = read_u32(s, 4);
        let byte_end = read_u32(s, 8);
        let kind = s[12];
        // s[13..16] padding
        let header_offset = read_u32(s, 16);
        // s[20..24] padding
        let header = if header_offset == NO_HEADER {
            None
        } else {
            Some(self.read_string(header_offset)?)
        };
        Ok(RegionEntry {
            region_id,
            byte_start,
            byte_end,
            kind,
            header,
        })
    }

    fn read_pointer(&self, idx: u32) -> Result<PointerEntry, CcxdiError> {
        let off = self.pointers_offset + idx as usize * POINTER_ENTRY_LEN;
        if off + POINTER_ENTRY_LEN > self.data.len() {
            return Err(CcxdiError::Truncated);
        }
        let s = &self.data[off..off + POINTER_ENTRY_LEN];
        let kind = s[0];
        // s[1] padding, s[2..4] a redundant surface length the strings pool also carries
        let surface_offset = read_u32(s, 4);
        let doc_id = read_u64(s, 8);
        let region_id = read_u32(s, 16);
        let byte_offset = read_u32(s, 20);
        let score_raw = read_u16(s, 24);
        // s[26..32] padding
        let surface = self.read_string(surface_offset)?;
        Ok(PointerEntry {
            kind,
            doc_id,
            region_id,
            byte_offset,
            surface,
            score: q8_8_to_f32(score_raw),
        })
    }

    fn read_string(&self, offset: u32) -> Result<String, CcxdiError> {
        let off = offset as usize;
        if off + 2 > self.strings_len {
            return Err(CcxdiError::BadStringOffset(offset));
        }
        let pool_start = self.strings_offset;
        let len = read_u16(self.data, pool_start + off) as usize;
        if off + 2 + len > self.strings_len {
            return Err(CcxdiError::BadStringOffset(offset));
        }
        let bytes = &self.data[pool_start + off + 2..pool_start + off + 2 + len];
        String::from_utf8(bytes.to_vec()).map_err(|_| CcxdiError::BadStringOffset(offset))
    }
}

/// Iterator over `.ccxdi` doc-table entries.
pub struct DocIter<'r, 'a> {
    reader: &'r CcxdiReader<'a>,
    next: u32,
}

impl Iterator for DocIter<'_, '_> {
    type Item = DocTableEntry;
    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.reader.header.doc_count {
            return None;
        }
        let e = self.reader.read_doc_entry(self.next);
        self.next += 1;
        Some(e)
    }
}

/// Convert a Q8.8 fixed-point `u16` salience back to `f32`.
pub fn q8_8_to_f32(v: u16) -> f32 {
    f32::from(v) / 256.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn q8_8_decodes_the_scale_the_builder_encoded() {
        assert!((q8_8_to_f32(0x0100) - 1.0).abs() < f32::EPSILON);
        assert!((q8_8_to_f32(0x0140) - 1.25).abs() < f32::EPSILON);
        assert!((q8_8_to_f32(0) - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn a_truncated_buffer_is_rejected_not_indexed() {
        assert!(matches!(CcxdiReader::from_bytes(&[0u8; 8]), Err(CcxdiError::Truncated)));
    }

    #[test]
    fn a_foreign_magic_is_rejected() {
        let data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        assert!(matches!(CcxdiReader::from_bytes(&data), Err(CcxdiError::BadMagic)));
    }

    #[test]
    fn an_unsupported_version_is_rejected() {
        let mut data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        data[..5].copy_from_slice(&CCXDI_MAGIC);
        data[5] = CCXDI_VERSION + 1;
        assert!(matches!(CcxdiReader::from_bytes(&data), Err(CcxdiError::BadVersion(_))));
    }

    /// A declared strings offset that disagrees with the section arithmetic means the
    /// tables and the pool cannot both be where the header says. Trusting either one
    /// would read pointer bytes as strings.
    #[test]
    fn a_strings_offset_that_disagrees_with_the_sections_is_rejected() {
        let mut data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        data[..5].copy_from_slice(&CCXDI_MAGIC);
        data[5] = CCXDI_VERSION;
        data[21..25].copy_from_slice(&999u32.to_le_bytes());
        assert!(matches!(CcxdiReader::from_bytes(&data), Err(CcxdiError::Truncated)));
    }
}
