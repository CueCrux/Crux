// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `.ccxev` file format — per-segment extracted-event companion. Reader only.
//!
//! Stores verb-anchored events extracted from session content by an offline pass. The
//! event lane is a **scoring signal**, not a candidate generator: it re-ranks hits the
//! prose lanes produced.
//!
//! Layout (little-endian):
//!   `CcxevHeader`             — 32 bytes
//!   Vocab                     — `vocab_count` length-prefixed UTF-8 terms (verb
//!                              classes and object categories share one vocab)
//!   Event entries             — 40 bytes at v1, 44 at v2 (trailing `record_off`)
//!   `CatTable`                — `u32` length, then that many `u32` vocab ids
//!   `StringHeap`              — `u32` length, then UTF-8 object phrases
//!   Footer                    — 4 bytes, CRC32C over everything before it
//!
//! v2 added `record_off`, the source frame's offset in the segment's uncompressed
//! record area. It is the stable physical join key: the load path re-resolves a
//! `doc_id` from it against the live `.ccxi` doc table, because a doc id alone is only
//! meaningful against the companion it was built with.
//!
//! **Reader half only** (ExecPlan constraint C7). See `VENDORED_FROM.md`.

use crate::le::{crc32c, read_u16, read_u32, read_u64};
use crate::IndexError;

pub const CCXEV_MAGIC: u32 = 0x5645_5843;

/// Current `.ccxev` file-format version. v1 files are still readable.
pub const CCXEV_VERSION: u8 = 2;
pub const CCXEV_SCHEMA_VERSION: u8 = 1;

/// `record_off` sentinel for v1 files and unattributable frames.
pub const CCXEV_RECORD_OFF_UNKNOWN: u32 = u32::MAX;

/// Sentinel for "the extractor could not resolve a time".
pub const CCXEV_NO_TIME: i64 = i64::MIN;

const HEADER_LEN: usize = 32;
const EVENT_ENTRY_LEN: usize = 40;
const EVENT_ENTRY_LEN_V2: usize = 44;
const FOOTER_LEN: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CcxevModality {
    Factual = 0,
    Future = 1,
    Hypothetical = 2,
    Uncertain = 3,
}

impl CcxevModality {
    fn from_bits(b: u8) -> Self {
        match b & 0b11 {
            0 => Self::Factual,
            1 => Self::Future,
            2 => Self::Hypothetical,
            _ => Self::Uncertain,
        }
    }
}

/// One extracted event.
#[derive(Debug, Clone)]
pub struct ExtractedEvent {
    /// `xxh64(stream_id)` of the source session.
    pub session_id: u64,
    /// Segment-local doc id of the chunk the event came from. Authoritative only when
    /// [`Self::record_off`] is unknown; otherwise the load path re-resolves it from
    /// `record_off` against the live `.ccxi` doc table.
    pub doc_id: u32,
    /// The source frame's offset in the segment's uncompressed record area — the
    /// stable physical join key. [`CCXEV_RECORD_OFF_UNKNOWN`] on v1 files.
    pub record_off: u32,
    /// Short canonical verb class, matched against the query's verb-class set.
    pub verb_class: String,
    /// Free-form object phrase.
    pub object: String,
    /// Short lowercase category labels for the object.
    pub object_categories: Vec<String>,
    /// Unix seconds, or [`CCXEV_NO_TIME`] when unresolved.
    pub time_unix_secs: i64,
    /// True when the event is about the user rather than another person.
    pub agent_is_user: bool,
    /// True when the event was flagged as negated. Negated events are filtered out at
    /// scoring time, so reading this bit wrong scores evidence for the opposite claim.
    pub negation: bool,
    pub modality: CcxevModality,
    /// Confidence in `[0.0, 1.0]`. Scaled to `u16` on disk.
    pub confidence: f32,
}

#[derive(Debug, Clone)]
pub struct CcxevHeader {
    pub magic: u32,
    pub version: u8,
    pub schema_version: u8,
    pub flags: u16,
    pub segment_seq: u64,
    pub epoch: u64,
    pub event_count: u32,
    pub vocab_count: u32,
}

#[derive(Debug, Clone)]
struct DecodedEvent {
    session_id: u64,
    doc_id: u32,
    verb_class_id: u32,
    time_unix_secs: i64,
    n_cats: u8,
    flags: u8,
    confidence_u16: u16,
    object_offset: u32,
    object_len: u16,
    cats_offset: u32,
    record_off: u32,
}

/// Reader: parses a `.ccxev` file from a byte slice. Validates the footer CRC, magic
/// and version, then decodes the fixed-width event entries eagerly; the object phrases
/// and category lists stay in the borrowed buffer until [`CcxevReader::events`].
///
/// **Divergence from the CoreCrux source**, recorded in `VENDORED_FROM.md`: upstream's
/// reader owns no buffer and its `events(&self, data)` takes the bytes back as an
/// argument, so handing it a *different* buffer decodes silently wrong objects and
/// categories rather than failing. The CE reader borrows the slice it parsed, and
/// `events()` takes no argument, which makes that mismatch unrepresentable.
#[derive(Debug)]
pub struct CcxevReader<'a> {
    data: &'a [u8],
    header: CcxevHeader,
    vocab: Vec<String>,
    events: Vec<DecodedEvent>,
    cat_table_start: usize,
    heap_start: usize,
    heap_len: usize,
}

fn corrupt(msg: &str) -> IndexError {
    IndexError::IntegrityFailure { msg: msg.to_string() }
}

impl<'a> CcxevReader<'a> {
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, IndexError> {
        if data.len() < HEADER_LEN + FOOTER_LEN {
            return Err(corrupt("ccxev: too small"));
        }
        let body_end = data.len() - FOOTER_LEN;
        let footer_crc = read_u32(data, body_end);
        if crc32c(&data[..body_end]) != footer_crc {
            return Err(corrupt("ccxev: crc mismatch"));
        }

        let magic = read_u32(data, 0);
        if magic != CCXEV_MAGIC {
            return Err(corrupt("ccxev: bad magic"));
        }
        let version = data[4];
        if version != 1 && version != CCXEV_VERSION {
            return Err(IndexError::IntegrityFailure {
                msg: format!("ccxev: unsupported version {version}"),
            });
        }
        let schema_version = data[5];
        let flags = read_u16(data, 6);
        let segment_seq = read_u64(data, 8);
        let epoch = read_u64(data, 16);
        let event_count = read_u32(data, 24);
        let vocab_count = read_u32(data, 28);

        let mut off = HEADER_LEN;

        // Vocab — length-prefixed UTF-8 terms.
        let mut vocab: Vec<String> = Vec::with_capacity(vocab_count as usize);
        for _ in 0..vocab_count {
            if off + 2 > body_end {
                return Err(corrupt("ccxev: vocab overflow"));
            }
            let n = read_u16(data, off) as usize;
            off += 2;
            if off + n > body_end {
                return Err(corrupt("ccxev: vocab term overflow"));
            }
            let term = std::str::from_utf8(&data[off..off + n]).map_err(|_| corrupt("ccxev: vocab utf-8"))?;
            vocab.push(term.to_string());
            off += n;
        }

        // Event entries — 40 bytes at v1, 44 at v2 (trailing `record_off`).
        let has_record_off = version >= 2;
        let on_disk_event_len = if has_record_off {
            EVENT_ENTRY_LEN_V2
        } else {
            EVENT_ENTRY_LEN
        };
        let mut events: Vec<DecodedEvent> = Vec::with_capacity(event_count as usize);
        for _ in 0..event_count {
            if off + on_disk_event_len > body_end {
                return Err(corrupt("ccxev: event overflow"));
            }
            let session_id = read_u64(data, off);
            let doc_id = read_u32(data, off + 8);
            let verb_class_id = read_u32(data, off + 12);
            let time_unix_secs = read_u64(data, off + 16) as i64;
            let n_cats = data[off + 24];
            let entry_flags = data[off + 25];
            // off + 26..28 reserved
            let confidence_u16 = read_u16(data, off + 28);
            let object_offset = read_u32(data, off + 30);
            let object_len = read_u16(data, off + 34);
            let cats_offset = read_u32(data, off + 36);
            let record_off = if has_record_off {
                read_u32(data, off + 40)
            } else {
                CCXEV_RECORD_OFF_UNKNOWN
            };
            off += on_disk_event_len;
            events.push(DecodedEvent {
                session_id,
                doc_id,
                verb_class_id,
                time_unix_secs,
                n_cats,
                flags: entry_flags,
                confidence_u16,
                object_offset,
                object_len,
                cats_offset,
                record_off,
            });
        }

        // CatTable — u32 length, then that many u32 vocab ids.
        if off + 4 > body_end {
            return Err(corrupt("ccxev: missing cat_table_len"));
        }
        let cat_table_len = read_u32(data, off) as usize;
        off += 4;
        let cat_table_bytes = cat_table_len
            .checked_mul(4)
            .ok_or_else(|| corrupt("ccxev: cat_table overflow"))?;
        if off + cat_table_bytes > body_end {
            return Err(corrupt("ccxev: cat_table overflow"));
        }
        let cat_table_start = off;
        off += cat_table_bytes;

        // StringHeap — u32 length, then the object phrases.
        if off + 4 > body_end {
            return Err(corrupt("ccxev: missing heap_len"));
        }
        let heap_len = read_u32(data, off) as usize;
        off += 4;
        if off + heap_len > body_end {
            return Err(corrupt("ccxev: heap overflow"));
        }
        let heap_start = off;

        Ok(Self {
            data,
            header: CcxevHeader {
                magic,
                version,
                schema_version,
                flags,
                segment_seq,
                epoch,
                event_count,
                vocab_count,
            },
            vocab,
            events,
            cat_table_start,
            heap_start,
            heap_len,
        })
    }

    pub fn header(&self) -> &CcxevHeader {
        &self.header
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// The shared vocab of verb classes and object categories.
    pub fn vocab(&self) -> &[String] {
        &self.vocab
    }

    /// Materialise every event, resolving vocab ids and heap offsets.
    pub fn events(&self) -> Result<Vec<ExtractedEvent>, IndexError> {
        let mut out: Vec<ExtractedEvent> = Vec::with_capacity(self.events.len());
        for de in &self.events {
            let verb_class = self.vocab.get(de.verb_class_id as usize).cloned().unwrap_or_default();

            let mut cats: Vec<String> = Vec::with_capacity(de.n_cats as usize);
            for i in 0..de.n_cats as usize {
                let cat_off = self
                    .cat_table_start
                    .checked_add(
                        (de.cats_offset as usize)
                            .checked_add(i)
                            .ok_or_else(|| corrupt("ccxev: cats index"))?
                            * 4,
                    )
                    .ok_or_else(|| corrupt("ccxev: cats index"))?;
                if cat_off + 4 > self.heap_start {
                    return Err(corrupt("ccxev: cats out of table"));
                }
                let cat_id = read_u32(self.data, cat_off);
                if let Some(c) = self.vocab.get(cat_id as usize) {
                    cats.push(c.clone());
                }
            }

            let obj_start = self
                .heap_start
                .checked_add(de.object_offset as usize)
                .ok_or_else(|| corrupt("ccxev: object offset"))?;
            let obj_end = obj_start
                .checked_add(de.object_len as usize)
                .ok_or_else(|| corrupt("ccxev: object length"))?;
            if obj_end > self.heap_start + self.heap_len {
                return Err(corrupt("ccxev: object past heap"));
            }
            let object = std::str::from_utf8(&self.data[obj_start..obj_end])
                .map_err(|_| corrupt("ccxev: object utf-8"))?
                .to_string();

            out.push(ExtractedEvent {
                session_id: de.session_id,
                doc_id: de.doc_id,
                record_off: de.record_off,
                verb_class,
                object,
                object_categories: cats,
                time_unix_secs: de.time_unix_secs,
                // Bit 3 is set for a non-user agent, so "is user" is its absence.
                agent_is_user: (de.flags & 0b1000) == 0,
                negation: (de.flags & 0b1) != 0,
                modality: CcxevModality::from_bits(de.flags >> 1),
                confidence: f32::from(de.confidence_u16) / 65535.0,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modality_decodes_from_the_two_flag_bits() {
        assert_eq!(CcxevModality::from_bits(0), CcxevModality::Factual);
        assert_eq!(CcxevModality::from_bits(1), CcxevModality::Future);
        assert_eq!(CcxevModality::from_bits(2), CcxevModality::Hypothetical);
        assert_eq!(CcxevModality::from_bits(3), CcxevModality::Uncertain);
        // Higher bits belong to other flags and must not leak into the modality.
        assert_eq!(CcxevModality::from_bits(0b1111_1100), CcxevModality::Factual);
    }

    #[test]
    fn a_truncated_buffer_is_rejected_not_indexed() {
        assert!(CcxevReader::from_bytes(&[0u8; 8]).is_err());
    }

    /// The CRC is checked before the magic, so a buffer that is not a `.ccxev` at all
    /// still fails closed rather than being parsed.
    #[test]
    fn a_buffer_with_no_valid_footer_is_rejected() {
        let data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        assert!(CcxevReader::from_bytes(&data).is_err());
    }

    #[test]
    fn an_unsupported_version_is_rejected() {
        let mut data = vec![0u8; HEADER_LEN + FOOTER_LEN];
        data[0..4].copy_from_slice(&CCXEV_MAGIC.to_le_bytes());
        data[4] = 9;
        let crc = crc32c(&data[..HEADER_LEN]);
        data[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(&crc.to_le_bytes());
        let err = CcxevReader::from_bytes(&data).expect_err("version 9 is not readable");
        assert!(format!("{err}").contains("unsupported version 9"));
    }
}
