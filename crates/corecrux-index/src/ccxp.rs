// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `.ccxp` file format — per-segment structured-fact projection companion. Reader only.
//!
//! Stores structured facts ("projections") extracted from session text at ingest time,
//! keyed by the parent `(session_id, doc_id, frame_offset)`. The projection lane uses
//! them for the temporal / count / "I bought X" question shapes that BM25 and dense
//! routinely under-rank.
//!
//! Note this extension collided with the CE's old embedder-profile sidecar; the CE
//! vacated it to `.ccxprof` at M2 of the vocabulary-unification ExecPlan, so `.ccxp`
//! now means only what it means in CoreCrux.
//!
//! Layout (little-endian):
//!   `CcxpHeader`              — 40 bytes
//!   `FactEntry` × N           — 32 bytes each
//!   `ArgsTable`               — variable, contiguous `(u32 heap_offset, u32 heap_len)`
//!                              pairs; entries reference it by **byte** offset
//!   `StringHeap`              — variable, UTF-8 (arg strings + source patterns)
//!   Footer                    — 4 bytes, CRC32C over the preceding bytes
//!
//! **Reader half only** (ExecPlan constraint C7). See `VENDORED_FROM.md`.

use crate::le::{crc32c, read_f32, read_u16, read_u32, read_u64};
use crate::IndexError;

pub const CCXP_MAGIC: u32 = 0x4343_5850; // "CCXP"
pub const CCXP_VERSION: u8 = 1;
pub const CCXP_SCHEMA_VERSION: u8 = 1;

const HEADER_LEN: usize = 40;
const FACT_ENTRY_LEN: usize = 32;
const ARG_PAIR_LEN: usize = 8; // (u32 offset, u32 len)
const FOOTER_LEN: usize = 4;

/// `source_pattern` sentinel meaning "the producer recorded none".
pub const NO_SOURCE_PATTERN: u32 = u32::MAX;

/// Predicate class of a projected fact. `repr(u8)` makes the discriminants part of the
/// wire format.
///
/// Tag `5` is reserved upstream for a business-object dispatch variant that `.ccxp`
/// encoders never emit — the data lives in a different companion. This reader rejects
/// it, which keeps the wire format strict and preserves the forward-compat hook.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProjectionPredicate {
    /// "I bought X today" / "spent $Y on Z" / "completed game W last weekend".
    UserAction = 0,
    /// "I'm using Fitbit Charge 3" / "I live in Boston" / "wake at 7 AM".
    UserAttribute = 1,
    /// "Sarah's wedding is May 14" / "the Mars launch is October 2026".
    TemporalEvent = 2,
    /// "I have 47 books on my shelf" / "5 cats" / "3 marathons this year".
    CountState = 3,
    /// Profile-preference intent. Classification only — the data itself lives in the
    /// `.ccxs` subject-profile companion.
    UserPreference = 4,
}

impl ProjectionPredicate {
    /// Round-trip from the on-disk byte tag. `.ccxp` stores only variants `0..=4`.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::UserAction),
            1 => Some(Self::UserAttribute),
            2 => Some(Self::TemporalEvent),
            3 => Some(Self::CountState),
            4 => Some(Self::UserPreference),
            _ => None,
        }
    }

    /// Wire-format tag.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// One structured fact projected from a session frame.
///
/// Args are predicate-shape dependent; the producer picks the order:
///   - `UserAction(verb, object[, time])`
///   - `UserAttribute(predicate, value[, time])`
///   - `TemporalEvent(event, date)`
///   - `CountState(category, count[, time])`
///
/// `confidence` is in `[0.0, 1.0]`; the lane scales the fact's boost by it, so a
/// high-precision extractor outranks a noisier fallback.
#[derive(Debug, Clone)]
pub struct ProjectionFact {
    pub predicate: ProjectionPredicate,
    pub session_id: u64,
    pub doc_id: u32,
    pub frame_offset: u32,
    pub confidence: f32,
    pub args: Vec<String>,
    /// Human-readable pointer to the extractor that produced this fact, e.g.
    /// `"regex:bought-today/v1"`. Debugging aid; never used at retrieval time.
    pub source_pattern: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CcxpHeader {
    pub magic: u32,
    pub version: u8,
    pub schema_version: u8,
    pub flags: u16,
    pub shard_id: u32,
    pub segment_seq: u64,
    pub epoch: u64,
    pub fact_count: u32,
    pub string_heap_len: u32,
    pub args_table_len: u32,
}

/// Reader: parses a `.ccxp` file from a byte slice. Validates magic, version and the
/// footer CRC32C before exposing any accessor.
#[derive(Debug)]
pub struct CcxpReader<'a> {
    header: CcxpHeader,
    fact_area: &'a [u8],
    args_table: &'a [u8],
    string_heap: &'a [u8],
}

impl<'a> CcxpReader<'a> {
    pub fn new(data: &'a [u8]) -> crate::Result<Self> {
        if data.len() < HEADER_LEN + FOOTER_LEN {
            return Err(IndexError::BufferTooSmall);
        }

        let magic = read_u32(data, 0);
        if magic != CCXP_MAGIC {
            return Err(IndexError::InvalidMagic {
                expected: CCXP_MAGIC,
                actual: magic,
            });
        }
        let version = data[4];
        if version != CCXP_VERSION {
            return Err(IndexError::UnsupportedVersion {
                version: u16::from(version),
            });
        }
        let schema_version = data[5];
        let flags = read_u16(data, 6);
        let shard_id = read_u32(data, 8);
        let segment_seq = read_u64(data, 12);
        let epoch = read_u64(data, 20);
        let fact_count = read_u32(data, 28);
        let string_heap_len = read_u32(data, 32);
        let args_table_len = read_u32(data, 36);

        let fact_area_len = (fact_count as usize) * FACT_ENTRY_LEN;
        let body_end = HEADER_LEN
            .checked_add(fact_area_len)
            .and_then(|n| n.checked_add(args_table_len as usize))
            .and_then(|n| n.checked_add(string_heap_len as usize))
            .ok_or(IndexError::BufferTooSmall)?;
        let expected_total = body_end.checked_add(FOOTER_LEN).ok_or(IndexError::BufferTooSmall)?;
        if data.len() < expected_total {
            return Err(IndexError::BufferTooSmall);
        }

        // CRC over header + body; the footer itself is excluded.
        let stored_crc = read_u32(data, body_end);
        let computed_crc = crc32c(&data[..body_end]);
        if stored_crc != computed_crc {
            return Err(IndexError::IntegrityFailure {
                msg: format!("CRC32C mismatch: stored {stored_crc:#x}, computed {computed_crc:#x}"),
            });
        }

        let fact_area = &data[HEADER_LEN..HEADER_LEN + fact_area_len];
        let args_table_start = HEADER_LEN + fact_area_len;
        let args_table = &data[args_table_start..args_table_start + args_table_len as usize];
        let string_heap_start = args_table_start + args_table_len as usize;
        let string_heap = &data[string_heap_start..string_heap_start + string_heap_len as usize];

        Ok(Self {
            header: CcxpHeader {
                magic,
                version,
                schema_version,
                flags,
                shard_id,
                segment_seq,
                epoch,
                fact_count,
                string_heap_len,
                args_table_len,
            },
            fact_area,
            args_table,
            string_heap,
        })
    }

    pub fn header(&self) -> &CcxpHeader {
        &self.header
    }

    pub fn fact_count(&self) -> u32 {
        self.header.fact_count
    }

    pub fn schema_version(&self) -> u8 {
        self.header.schema_version
    }

    /// Decode the fact at the given local index. `None` when the index is out of range
    /// or the predicate tag is unknown to this build — the forward-compat hook.
    pub fn get(&self, fact_idx: u32) -> Option<ProjectionFact> {
        if fact_idx >= self.header.fact_count {
            return None;
        }
        let off = (fact_idx as usize) * FACT_ENTRY_LEN;
        let entry = &self.fact_area[off..off + FACT_ENTRY_LEN];
        let predicate = ProjectionPredicate::from_u8(entry[0])?;
        let n_args = entry[1];
        let session_id = read_u64(entry, 4);
        let doc_id = read_u32(entry, 12);
        let frame_offset = read_u32(entry, 16);
        let confidence = read_f32(entry, 20);
        let args_off = read_u32(entry, 24) as usize;
        let src_off = read_u32(entry, 28);

        let mut args: Vec<String> = Vec::with_capacity(n_args as usize);
        for i in 0..n_args as usize {
            // `args_off` is a byte offset into the args table, not a pair index.
            let pair_off = args_off.checked_add(i.checked_mul(ARG_PAIR_LEN)?)?;
            args.push(self.read_heap_string(pair_off)?);
        }

        let source_pattern = if src_off == NO_SOURCE_PATTERN {
            None
        } else {
            Some(self.read_heap_string(src_off as usize)?)
        };

        Some(ProjectionFact {
            predicate,
            session_id,
            doc_id,
            frame_offset,
            confidence,
            args,
            source_pattern,
        })
    }

    /// Resolve one `(offset, len)` pair at `pair_off` bytes into the args table.
    fn read_heap_string(&self, pair_off: usize) -> Option<String> {
        let pair = self.args_table.get(pair_off..pair_off.checked_add(ARG_PAIR_LEN)?)?;
        let heap_off = read_u32(pair, 0) as usize;
        let heap_len = read_u32(pair, 4) as usize;
        let bytes = self.string_heap.get(heap_off..heap_off.checked_add(heap_len)?)?;
        String::from_utf8(bytes.to_vec()).ok()
    }

    /// Iterate every fact in the file. Entries whose predicate tag this build does not
    /// know are skipped.
    pub fn iter(&self) -> impl Iterator<Item = ProjectionFact> + '_ {
        (0..self.header.fact_count).filter_map(|i| self.get(i))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn predicate_tags_round_trip_over_the_wire_range() {
        for p in [
            ProjectionPredicate::UserAction,
            ProjectionPredicate::UserAttribute,
            ProjectionPredicate::TemporalEvent,
            ProjectionPredicate::CountState,
            ProjectionPredicate::UserPreference,
        ] {
            assert_eq!(ProjectionPredicate::from_u8(p.as_u8()), Some(p));
        }
    }

    /// Tag 5 is reserved upstream and never written into `.ccxp`. Accepting it would
    /// let a hand-built file inject a fact class the lane has no handling for.
    #[test]
    fn the_reserved_business_object_tag_is_rejected() {
        assert_eq!(ProjectionPredicate::from_u8(5), None);
        assert_eq!(ProjectionPredicate::from_u8(255), None);
    }

    #[test]
    fn a_truncated_buffer_is_rejected_not_indexed() {
        assert!(matches!(CcxpReader::new(&[0u8; 8]), Err(IndexError::BufferTooSmall)));
    }

    #[test]
    fn a_foreign_magic_is_rejected() {
        let mut data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        data[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert!(matches!(CcxpReader::new(&data), Err(IndexError::InvalidMagic { .. })));
    }

    #[test]
    fn an_unsupported_version_is_rejected() {
        let mut data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        data[0..4].copy_from_slice(&CCXP_MAGIC.to_le_bytes());
        data[4] = CCXP_VERSION + 1;
        assert!(matches!(
            CcxpReader::new(&data),
            Err(IndexError::UnsupportedVersion { .. })
        ));
    }
}
