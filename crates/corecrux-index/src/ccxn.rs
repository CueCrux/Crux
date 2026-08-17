// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `.ccxn` file format — per-segment entity-matrix companion. Reader only.
//!
//! Inverts a segment's named entities into a `canonical_name → Vec<(session_id,
//! doc_id, frame_offset)>` map plus a `canonical_name → EntityType` map, so the entity
//! lane can answer named-entity questions where the answer-bearing chunk shares a
//! product / person / org / location name with the query.
//!
//! Canonicalisation: the format is bytes-blind — it sorts and binary-searches by
//! `xxh64` of the canonical string with seed 0. [`canonicalise`] is the shared
//! normaliser both the producer and the query side must run inputs through, or the
//! binary search misses.
//!
//! Layout (little-endian):
//!   `CcxnHeader`              — 40 bytes
//!   `EntityEntry` × N         — 32 bytes each, sorted ascending by `canonical_hash`
//!   `OccurrencesArea`         — variable, contiguous 16-byte
//!                              `(u64 session_id, u32 doc_id, u32 frame_offset)` triples
//!   `StringHeap`              — variable, UTF-8 canonical names
//!   Footer                    — 4 bytes, CRC32C over the preceding bytes
//!
//! **Reader half only** (ExecPlan constraint C7). See `VENDORED_FROM.md`.

use crate::le::{crc32c, read_u16, read_u32, read_u64};
use crate::IndexError;
use xxhash_rust::xxh64::xxh64;

pub const CCXN_MAGIC: u32 = 0x4343_584E; // "CCXN"
pub const CCXN_VERSION: u8 = 1;
pub const CCXN_SCHEMA_VERSION: u8 = 1;

const HEADER_LEN: usize = 40;
const ENTITY_ENTRY_LEN: usize = 32;
const OCCURRENCE_LEN: usize = 16; // (u64 session_id, u32 doc_id, u32 frame_offset)
const FOOTER_LEN: usize = 4;

/// Entity type tag. Stored as `u8` on disk; `repr(u8)` makes the integer values part
/// of the wire format.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityType {
    /// Named individual.
    Person = 0,
    /// Company, institution, band, team.
    Organization = 1,
    /// Branded product, model name, software or hardware identifier.
    Product = 2,
    /// City, country, venue, region.
    Location = 3,
    /// A proper noun worth indexing that fits none of the four primary types.
    /// Lowest priority for query-side disambiguation.
    Misc = 4,
}

impl EntityType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Person),
            1 => Some(Self::Organization),
            2 => Some(Self::Product),
            3 => Some(Self::Location),
            4 => Some(Self::Misc),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// One frame in which an entity was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntityOccurrence {
    pub session_id: u64,
    pub doc_id: u32,
    pub frame_offset: u32,
}

/// One entity record, materialised.
#[derive(Debug, Clone)]
pub struct EntityRecord {
    pub canonical: String,
    pub entity_type: EntityType,
    pub occurrences: Vec<EntityOccurrence>,
}

#[derive(Debug, Clone)]
pub struct CcxnHeader {
    pub magic: u32,
    pub version: u8,
    pub schema_version: u8,
    pub flags: u16,
    pub shard_id: u32,
    pub segment_seq: u64,
    pub epoch: u64,
    pub entity_count: u32,
    pub string_heap_len: u32,
    pub occurrences_total: u32,
}

/// Reference normaliser — lower-cases and applies a light Unicode normalisation
/// (collapse whitespace, strip trailing punctuation) without pulling in a full NFKC
/// dependency.
///
/// The producer and the query side must both canonicalise through this function
/// before hashing, or the binary search misses. Changing it orphans every `.ccxn`
/// already written, so a change belongs with a `CCXN_SCHEMA_VERSION` bump.
pub fn canonicalise(s: &str) -> String {
    let trimmed = s
        .trim()
        .trim_matches(|c: char| matches!(c, ',' | '.' | '!' | '?' | ';' | ':' | '"' | '\''));
    let mut out = String::with_capacity(trimmed.len());
    let mut prev_space = false;
    for ch in trimmed.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            for low in ch.to_lowercase() {
                out.push(low);
            }
            prev_space = false;
        }
    }
    out
}

/// Reader: parses a `.ccxn` file from a byte slice. Validates magic, version and the
/// footer CRC32C before exposing any accessor.
#[derive(Debug)]
pub struct CcxnReader<'a> {
    header: CcxnHeader,
    entry_area: &'a [u8],
    occurrences_area: &'a [u8],
    string_heap: &'a [u8],
}

/// Result of an entity lookup. Borrowed slices into the reader's underlying bytes —
/// no allocation on the hot path.
#[derive(Debug, Clone, Copy)]
pub struct EntityHits<'a> {
    pub canonical_hash: u64,
    pub entity_type: EntityType,
    canonical_bytes: &'a [u8],
    occurrences_bytes: &'a [u8],
    n_occurrences: u32,
}

impl<'a> EntityHits<'a> {
    pub fn canonical(&self) -> &'a str {
        // The producer writes valid UTF-8 and the CRC plus bounds checks gate the
        // slice. Surface invalid bytes as empty rather than panicking.
        std::str::from_utf8(self.canonical_bytes).unwrap_or("")
    }

    pub fn n_occurrences(&self) -> u32 {
        self.n_occurrences
    }

    /// Iterate every recorded occurrence for this entity.
    pub fn iter(&self) -> impl Iterator<Item = EntityOccurrence> + 'a {
        let bytes = self.occurrences_bytes;
        (0..self.n_occurrences as usize).map(move |i| {
            let off = i * OCCURRENCE_LEN;
            EntityOccurrence {
                session_id: read_u64(bytes, off),
                doc_id: read_u32(bytes, off + 8),
                frame_offset: read_u32(bytes, off + 12),
            }
        })
    }

    /// Materialise this entity into an owned [`EntityRecord`].
    pub fn to_record(&self) -> EntityRecord {
        EntityRecord {
            canonical: self.canonical().to_string(),
            entity_type: self.entity_type,
            occurrences: self.iter().collect(),
        }
    }
}

impl<'a> CcxnReader<'a> {
    pub fn new(data: &'a [u8]) -> crate::Result<Self> {
        if data.len() < HEADER_LEN + FOOTER_LEN {
            return Err(IndexError::BufferTooSmall);
        }

        let magic = read_u32(data, 0);
        if magic != CCXN_MAGIC {
            return Err(IndexError::InvalidMagic {
                expected: CCXN_MAGIC,
                actual: magic,
            });
        }
        let version = data[4];
        if version != CCXN_VERSION {
            return Err(IndexError::UnsupportedVersion {
                version: u16::from(version),
            });
        }
        let schema_version = data[5];
        let flags = read_u16(data, 6);
        let shard_id = read_u32(data, 8);
        let segment_seq = read_u64(data, 12);
        let epoch = read_u64(data, 20);
        let entity_count = read_u32(data, 28);
        let string_heap_len = read_u32(data, 32);
        let occurrences_total = read_u32(data, 36);

        let entry_area_len = (entity_count as usize) * ENTITY_ENTRY_LEN;
        let occurrences_area_len = (occurrences_total as usize) * OCCURRENCE_LEN;
        let body_end = HEADER_LEN
            .checked_add(entry_area_len)
            .and_then(|n| n.checked_add(occurrences_area_len))
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

        let entry_area = &data[HEADER_LEN..HEADER_LEN + entry_area_len];
        let occ_start = HEADER_LEN + entry_area_len;
        let occurrences_area = &data[occ_start..occ_start + occurrences_area_len];
        let heap_start = occ_start + occurrences_area_len;
        let string_heap = &data[heap_start..heap_start + string_heap_len as usize];

        Ok(Self {
            header: CcxnHeader {
                magic,
                version,
                schema_version,
                flags,
                shard_id,
                segment_seq,
                epoch,
                entity_count,
                string_heap_len,
                occurrences_total,
            },
            entry_area,
            occurrences_area,
            string_heap,
        })
    }

    pub fn header(&self) -> &CcxnHeader {
        &self.header
    }

    pub fn entity_count(&self) -> u32 {
        self.header.entity_count
    }

    pub fn occurrences_total(&self) -> u32 {
        self.header.occurrences_total
    }

    pub fn schema_version(&self) -> u8 {
        self.header.schema_version
    }

    /// The entity entry at index `i`, without copying. `None` when `i` is out of range
    /// or the entry's payload is corrupt.
    fn entry_at(&self, i: usize) -> Option<EntityHits<'a>> {
        if i >= self.header.entity_count as usize {
            return None;
        }
        let off = i * ENTITY_ENTRY_LEN;
        let entry = &self.entry_area[off..off + ENTITY_ENTRY_LEN];
        let canonical_hash = read_u64(entry, 0);
        let canon_off = read_u32(entry, 8) as usize;
        let canon_len = read_u32(entry, 12) as usize;
        let entity_type = EntityType::from_u8(entry[16])?;
        let occ_off = read_u32(entry, 20) as usize;
        let n_occ = read_u32(entry, 24);

        let canonical_bytes = self.string_heap.get(canon_off..canon_off.checked_add(canon_len)?)?;
        let occ_byte_start = occ_off.checked_mul(OCCURRENCE_LEN)?;
        let occ_byte_end = occ_byte_start.checked_add((n_occ as usize).checked_mul(OCCURRENCE_LEN)?)?;
        let occurrences_bytes = self.occurrences_area.get(occ_byte_start..occ_byte_end)?;

        Some(EntityHits {
            canonical_hash,
            entity_type,
            canonical_bytes,
            occurrences_bytes,
            n_occurrences: n_occ,
        })
    }

    /// Look up entity occurrences by canonical hash. `O(log N)` binary search.
    pub fn lookup_by_canonical_hash(&self, canonical_hash: u64) -> Option<EntityHits<'a>> {
        if self.header.entity_count == 0 {
            return None;
        }
        let mut lo = 0usize;
        let mut hi = self.header.entity_count as usize;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let mid_hash = read_u64(self.entry_area, mid * ENTITY_ENTRY_LEN);
            match mid_hash.cmp(&canonical_hash) {
                std::cmp::Ordering::Equal => return self.entry_at(mid),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    /// Look up entity occurrences by canonical string. Applies [`canonicalise`] before
    /// hashing, so the query side does not have to.
    pub fn lookup_by_canonical(&self, canonical: &str) -> Option<EntityHits<'a>> {
        let canon = canonicalise(canonical);
        if canon.is_empty() {
            return None;
        }
        self.lookup_by_canonical_hash(xxh64(canon.as_bytes(), 0))
    }

    /// Iterate every entity in the file. Entries with an unknown type tag are skipped,
    /// for forward compatibility.
    pub fn iter(&self) -> impl Iterator<Item = EntityHits<'a>> + '_ {
        (0..self.header.entity_count as usize).filter_map(move |i| self.entry_at(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_type_round_trips_via_u8() {
        for t in [
            EntityType::Person,
            EntityType::Organization,
            EntityType::Product,
            EntityType::Location,
            EntityType::Misc,
        ] {
            assert_eq!(EntityType::from_u8(t.as_u8()), Some(t));
        }
        assert_eq!(EntityType::from_u8(5), None);
    }

    /// The producer and the query side must agree byte-for-byte on this, or every
    /// lookup silently misses. Pin the transformations it performs.
    #[test]
    fn canonicalise_lowercases_collapses_space_and_strips_edge_punctuation() {
        assert_eq!(canonicalise("  Mac   Studio. "), "mac studio");
        assert_eq!(canonicalise("MAC studio"), "mac studio");
        assert_eq!(canonicalise("\"Hollow Knight\""), "hollow knight");
        assert_eq!(canonicalise("   "), "");
    }

    #[test]
    fn canonicalise_keeps_interior_punctuation() {
        assert_eq!(canonicalise("A.C.M.E"), "a.c.m.e");
        assert_eq!(canonicalise("cuecrux-ltd"), "cuecrux-ltd");
        // Only the edges are trimmed, and they are trimmed repeatedly.
        assert_eq!(canonicalise("...acme!!!"), "acme");
    }

    #[test]
    fn a_truncated_buffer_is_rejected_not_indexed() {
        assert!(matches!(CcxnReader::new(&[0u8; 8]), Err(IndexError::BufferTooSmall)));
    }

    #[test]
    fn a_foreign_magic_is_rejected() {
        let mut data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        data[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(matches!(CcxnReader::new(&data), Err(IndexError::InvalidMagic { .. })));
    }

    #[test]
    fn an_unsupported_version_is_rejected() {
        let mut data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        data[0..4].copy_from_slice(&CCXN_MAGIC.to_le_bytes());
        data[4] = CCXN_VERSION + 1;
        assert!(matches!(
            CcxnReader::new(&data),
            Err(IndexError::UnsupportedVersion { .. })
        ));
    }
}
