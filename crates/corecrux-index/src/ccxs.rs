// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `.ccxs` file format — per-segment **subject profile** companion. Reader only.
//!
//! Rolls up profile-trait facts into a `(subject_kind, subject_id) → Vec<(predicate,
//! object_value)>` map stored alongside a sealed `.ccxseg`, so the traits lane can
//! fetch a subject's traits at retrieval time without a database round-trip.
//!
//! Subject binding: `subject_kind = tenant | passport`, `subject_id` is the tenant id
//! or passport UUID. The hash is `xxh64(kind_byte || subject_id_bytes)` so a
//! passport-subject "abc" and a tenant-subject "abc" never collide. Hash seed is 0,
//! matching `.ccxn`.
//!
//! Layout (little-endian):
//!   `CcxsHeader`              — 40 bytes
//!   `SubjectEntry` × N        — 32 bytes each, **sorted ascending by
//!                              `subject_hash`** so the reader can binary-search
//!                              without building a `HashMap` at load.
//!   `TraitsArea`              — variable, contiguous `(u32 predicate_offset,
//!                              u32 predicate_len, u32 object_offset,
//!                              u32 object_len)` quadruples (16 bytes each). Each
//!                              `SubjectEntry` points at a `[start, start+count)` slice.
//!   `StringHeap`              — variable, UTF-8 (subject ids + predicates + objects)
//!   Footer                    — 4 bytes, CRC32C over the preceding bytes
//!
//! Each `SubjectEntry`:
//!   `subject_hash` u64        — `xxh64(kind_byte || subject_id_bytes)`
//!   `subject_id_offset` u32   — offset into `StringHeap`
//!   `subject_id_len` u32      — length in `StringHeap`
//!   `subject_kind` u8         — [`SubjectKind`] repr-u8 (0 = tenant, 1 = passport)
//!   `evidence_flags` u8       — bit 0 = claimed-but-unverified
//!   `_reserved` u16           — pad
//!   `traits_offset` u32       — index into `TraitsArea`, in trait quadruples
//!   `traits_count` u32        — how many traits this subject has
//!
//! **Reader half only** (ExecPlan constraint C7): the CE opens `.ccxs` companions the
//! platform computed for it and never authors one. See `VENDORED_FROM.md`.

use crate::le::{crc32c, read_u16, read_u32, read_u64};
use crate::IndexError;
use xxhash_rust::xxh64::xxh64;

pub const CCXS_MAGIC: u32 = 0x4343_5853; // "CCXS"
pub const CCXS_VERSION: u8 = 1;
pub const CCXS_SCHEMA_VERSION: u8 = 1;

const HEADER_LEN: usize = 40;
const SUBJECT_ENTRY_LEN: usize = 32;
const TRAIT_LEN: usize = 16; // (u32 pred_off, u32 pred_len, u32 obj_off, u32 obj_len)
const FOOTER_LEN: usize = 4;

/// Subject binding tag. Mirrors the producer's `subject_kind` column.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubjectKind {
    /// Tenant fallback — the default when there is no verified speaker claim.
    Tenant = 0,
    /// Verified RCX passport.
    Passport = 1,
}

impl SubjectKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Tenant),
            1 => Some(Self::Passport),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Wire string used by the producer's `subject_kind` column.
    pub fn from_sql(s: &str) -> Option<Self> {
        match s {
            "tenant" => Some(Self::Tenant),
            "passport" => Some(Self::Passport),
            _ => None,
        }
    }

    pub fn as_sql(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Passport => "passport",
        }
    }
}

/// One trait line: a `(predicate, object_value)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileTrait {
    pub predicate: String,
    pub object: String,
}

#[derive(Debug, Clone)]
pub struct CcxsHeader {
    pub magic: u32,
    pub version: u8,
    pub schema_version: u8,
    pub flags: u16,
    pub shard_id: u32,
    pub segment_seq: u64,
    pub epoch: u64,
    pub subject_count: u32,
    pub string_heap_len: u32,
    pub traits_total: u32,
}

/// Hash key for a subject. Includes `kind` so passport-id and tenant-id strings of
/// the same value never collide. Seed 0, matching `.ccxn`.
pub fn subject_hash(kind: SubjectKind, subject_id: &str) -> u64 {
    let mut buf = Vec::with_capacity(subject_id.len() + 1);
    buf.push(kind.as_u8());
    buf.extend_from_slice(subject_id.as_bytes());
    xxh64(&buf, 0)
}

const EVIDENCE_FLAG_UNVERIFIED: u8 = 0b0000_0001;

/// Reader: parses a `.ccxs` file from a byte slice. Validates magic, version and
/// footer CRC32C before exposing any accessor.
#[derive(Debug)]
pub struct CcxsReader<'a> {
    header: CcxsHeader,
    entry_area: &'a [u8],
    traits_area: &'a [u8],
    string_heap: &'a [u8],
}

/// Result of a subject lookup. Borrowed slices into the reader's underlying bytes —
/// no allocation on the hot path.
#[derive(Debug, Clone, Copy)]
pub struct SubjectHits<'a> {
    pub subject_hash: u64,
    pub subject_kind: SubjectKind,
    pub evidence_unverified: bool,
    sid_bytes: &'a [u8],
    traits_area: &'a [u8],
    string_heap: &'a [u8],
    n_traits: u32,
}

impl<'a> SubjectHits<'a> {
    pub fn subject_id(&self) -> &'a str {
        std::str::from_utf8(self.sid_bytes).unwrap_or("")
    }

    pub fn n_traits(&self) -> u32 {
        self.n_traits
    }

    /// Iterate every trait `(predicate, object)` recorded for this subject.
    pub fn iter(&self) -> impl Iterator<Item = (&'a str, &'a str)> + 'a {
        let traits_area = self.traits_area;
        let heap = self.string_heap;
        (0..self.n_traits as usize).filter_map(move |i| {
            let off = i * TRAIT_LEN;
            if off + TRAIT_LEN > traits_area.len() {
                return None;
            }
            let p_off = read_u32(traits_area, off) as usize;
            let p_len = read_u32(traits_area, off + 4) as usize;
            let o_off = read_u32(traits_area, off + 8) as usize;
            let o_len = read_u32(traits_area, off + 12) as usize;
            let pred = std::str::from_utf8(heap.get(p_off..p_off.checked_add(p_len)?)?).ok()?;
            let obj = std::str::from_utf8(heap.get(o_off..o_off.checked_add(o_len)?)?).ok()?;
            Some((pred, obj))
        })
    }

    pub fn collect_traits(&self) -> Vec<ProfileTrait> {
        self.iter()
            .map(|(p, o)| ProfileTrait {
                predicate: p.to_string(),
                object: o.to_string(),
            })
            .collect()
    }
}

impl<'a> CcxsReader<'a> {
    pub fn new(data: &'a [u8]) -> crate::Result<Self> {
        if data.len() < HEADER_LEN + FOOTER_LEN {
            return Err(IndexError::BufferTooSmall);
        }

        let magic = read_u32(data, 0);
        if magic != CCXS_MAGIC {
            return Err(IndexError::InvalidMagic {
                expected: CCXS_MAGIC,
                actual: magic,
            });
        }
        let version = data[4];
        if version != CCXS_VERSION {
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
        let string_heap_len = read_u32(data, 32);
        let traits_total = read_u32(data, 36);

        let entry_area_len = (subject_count as usize) * SUBJECT_ENTRY_LEN;
        let traits_area_len = (traits_total as usize) * TRAIT_LEN;
        let body_end = HEADER_LEN
            .checked_add(entry_area_len)
            .and_then(|n| n.checked_add(traits_area_len))
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
        let traits_start = HEADER_LEN + entry_area_len;
        let traits_area = &data[traits_start..traits_start + traits_area_len];
        let heap_start = traits_start + traits_area_len;
        let string_heap = &data[heap_start..heap_start + string_heap_len as usize];

        Ok(Self {
            header: CcxsHeader {
                magic,
                version,
                schema_version,
                flags,
                shard_id,
                segment_seq,
                epoch,
                subject_count,
                string_heap_len,
                traits_total,
            },
            entry_area,
            traits_area,
            string_heap,
        })
    }

    pub fn header(&self) -> &CcxsHeader {
        &self.header
    }

    pub fn subject_count(&self) -> u32 {
        self.header.subject_count
    }

    pub fn traits_total(&self) -> u32 {
        self.header.traits_total
    }

    pub fn schema_version(&self) -> u8 {
        self.header.schema_version
    }

    fn entry_at(&self, i: usize) -> Option<SubjectHits<'a>> {
        if i >= self.header.subject_count as usize {
            return None;
        }
        let off = i * SUBJECT_ENTRY_LEN;
        let entry = &self.entry_area[off..off + SUBJECT_ENTRY_LEN];
        let subject_hash = read_u64(entry, 0);
        let sid_off = read_u32(entry, 8) as usize;
        let sid_len = read_u32(entry, 12) as usize;
        let subject_kind = SubjectKind::from_u8(entry[16])?;
        let evidence_flags = entry[17];
        let traits_offset = read_u32(entry, 20) as usize;
        let n_traits = read_u32(entry, 24);

        let sid_bytes = self.string_heap.get(sid_off..sid_off.checked_add(sid_len)?)?;
        let t_byte_start = traits_offset.checked_mul(TRAIT_LEN)?;
        let t_byte_end = t_byte_start.checked_add((n_traits as usize).checked_mul(TRAIT_LEN)?)?;
        let traits_area = self.traits_area.get(t_byte_start..t_byte_end)?;

        Some(SubjectHits {
            subject_hash,
            subject_kind,
            evidence_unverified: (evidence_flags & EVIDENCE_FLAG_UNVERIFIED) != 0,
            sid_bytes,
            traits_area,
            string_heap: self.string_heap,
            n_traits,
        })
    }

    /// Look up a subject by `(kind, subject_id)`. `O(log N)` binary search.
    pub fn lookup(&self, kind: SubjectKind, subject_id: &str) -> Option<SubjectHits<'a>> {
        self.lookup_by_hash(subject_hash(kind, subject_id))
    }

    pub fn lookup_by_hash(&self, subject_hash: u64) -> Option<SubjectHits<'a>> {
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

    /// Iterate every subject in the file. Entries with an unknown kind tag are
    /// skipped, for forward compatibility.
    pub fn iter(&self) -> impl Iterator<Item = SubjectHits<'a>> + '_ {
        (0..self.header.subject_count as usize).filter_map(move |i| self.entry_at(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_kind_round_trips_via_u8() {
        for k in [SubjectKind::Tenant, SubjectKind::Passport] {
            assert_eq!(SubjectKind::from_u8(k.as_u8()), Some(k));
        }
        assert_eq!(SubjectKind::from_u8(2), None);
    }

    #[test]
    fn subject_kind_round_trips_via_sql_string() {
        for k in [SubjectKind::Tenant, SubjectKind::Passport] {
            assert_eq!(SubjectKind::from_sql(k.as_sql()), Some(k));
        }
        assert_eq!(SubjectKind::from_sql("service"), None);
    }

    /// The whole point of hashing the kind byte in: the same id string under two
    /// bindings must not collide, or one subject's traits are served for another's.
    #[test]
    fn subject_hash_separates_kinds_for_the_same_id() {
        assert_ne!(
            subject_hash(SubjectKind::Tenant, "abc"),
            subject_hash(SubjectKind::Passport, "abc")
        );
    }

    #[test]
    fn a_truncated_buffer_is_rejected_not_indexed() {
        assert!(matches!(CcxsReader::new(&[0u8; 8]), Err(IndexError::BufferTooSmall)));
    }

    #[test]
    fn a_foreign_magic_is_rejected() {
        let mut data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        data[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(matches!(CcxsReader::new(&data), Err(IndexError::InvalidMagic { .. })));
    }

    #[test]
    fn an_unsupported_version_is_rejected() {
        let mut data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        data[0..4].copy_from_slice(&CCXS_MAGIC.to_le_bytes());
        data[4] = CCXS_VERSION + 1;
        assert!(matches!(
            CcxsReader::new(&data),
            Err(IndexError::UnsupportedVersion { .. })
        ));
    }
}
