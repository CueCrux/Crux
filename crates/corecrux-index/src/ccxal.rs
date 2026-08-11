// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `.ccxal` file format — per-segment vernacular companion. Reader only.
//!
//! The vernacular retrieval lane matches queries via a deterministic byte-coded graph
//! walk over agent-emitted atoms, with no model call in the hot path. `.ccxal` is the
//! per-segment artefact that holds those atoms.
//!
//! ## File layout
//!
//!   Header (96 bytes)
//!   Doc table (`doc_count` × 24 bytes)
//!   D0 atoms (`d0_atom_count` × 48 bytes) — pointer crystals back to source spans
//!   D1 atoms (`d1_atom_count` × 32 bytes) — claim-graph atoms
//!   Strings pool (null-terminated UTF-8 OOV surfaces)
//!   Footer (4 bytes, CRC32C over everything before it)
//!
//! Every offset lives in [`offsets`], which is the single source of truth: nothing
//! computes an offset ad hoc. The `const { assert!(...) }` blocks below fail
//! compilation if any struct's `size_of` drifts from the spec, so the structs, the
//! offsets and the on-disk layout stay locked together.
//!
//! **Reader half only** (ExecPlan constraint C7). The per-entry `decode_*` functions
//! live in this file rather than the upstream's separate `vernacular_atom` module,
//! because only the decode half ports and three functions do not need a module of
//! their own — see `VENDORED_FROM.md`.

use crate::le::crc32c;
use std::mem::size_of;

/// Magic bytes that identify a `.ccxal` file.
pub const CCXAL_MAGIC: [u8; 5] = *b"CCXAL";

/// Current `.ccxal` file-format version.
pub const CCXAL_VERSION: u8 = 1;

/// Current `.ccxal` logical schema version.
pub const CCXAL_SCHEMA_VERSION: u8 = 1;

/// Confidence floor (Q8.8 = 0.30). The producer drops D1 atoms whose calibrated
/// confidence falls below this at seal time.
pub const CONFIDENCE_FLOOR_Q8_8: u16 = 0x004C;

/// Byte offsets and sizes for every section of a `.ccxal` file. Changing any value
/// here is a schema break.
pub mod offsets {
    /// Header field offsets and total size (96 bytes).
    pub mod header {
        pub const MAGIC: usize = 0;
        pub const VERSION: usize = 5;
        pub const SCHEMA_VERSION: usize = 6;
        pub const _PAD1: usize = 7;
        pub const VOCAB_VERSION: usize = 8;
        pub const _PAD2: usize = 10;
        pub const DOC_COUNT: usize = 12;
        pub const ATOM_COUNT: usize = 16;
        pub const D0_ATOM_COUNT: usize = 20;
        pub const D1_ATOM_COUNT: usize = 24;
        pub const D2_ATOM_COUNT: usize = 28;
        pub const D3_ATOM_COUNT: usize = 32;
        pub const D4_ATOM_COUNT: usize = 36;
        pub const INGEST_AGENT_ID: usize = 40;
        pub const INGEST_MODEL_SHA: usize = 56;
        pub const SEALED_AT: usize = 72;
        pub const FLAGS: usize = 80;
        pub const _PAD3: usize = 82;
        /// Total header size in bytes.
        pub const SIZE: usize = 96;
    }

    /// Doc-table entry field offsets and size (24 bytes per doc).
    pub mod doc_table_entry {
        pub const DOC_ID: usize = 0;
        pub const D0_COUNT: usize = 8;
        pub const D1_COUNT: usize = 10;
        pub const D0_OFFSET: usize = 12;
        pub const D1_OFFSET: usize = 16;
        pub const _PAD: usize = 20;
        /// Total doc-table-entry size in bytes.
        pub const SIZE: usize = 24;
    }

    /// D0 atom field offsets and size (48 bytes per atom).
    pub mod d0_atom {
        pub const DOC_ID: usize = 0;
        pub const REGION_ID: usize = 8;
        pub const BYTE_START: usize = 12;
        pub const BYTE_END: usize = 16;
        pub const CONTENT_HASH: usize = 20;
        pub const PROVENANCE_TRIAD: usize = 36;
        /// Total `D0Atom` size in bytes.
        pub const SIZE: usize = 48;
    }

    /// D1 atom field offsets and size (32 bytes per atom).
    pub mod d1_atom {
        pub const ACTOR_CLASS: usize = 0;
        pub const OBJECT_CLASS: usize = 1;
        pub const TEMPORAL_ANCHOR_TYPE: usize = 2;
        pub const _PAD1: usize = 3;
        pub const ACTOR_CODE: usize = 4;
        pub const OBJECT_CODE: usize = 8;
        pub const VIA_OBJECT_CODE: usize = 12;
        pub const PREDICATE_CODE: usize = 16;
        pub const VIA_PREDICATE: usize = 18;
        pub const CONF_Q8_8: usize = 20;
        pub const _PAD2: usize = 22;
        pub const TEMPORAL_VALUE: usize = 24;
        pub const EVID_D0_IDX: usize = 28;
        /// Total `D1Atom` size in bytes.
        pub const SIZE: usize = 32;
    }

    /// Footer size — a little-endian CRC32C `u32`.
    pub const FOOTER_SIZE: usize = 4;
}

/// `.ccxal` decode errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CcxalError {
    #[error("input shorter than {expected} bytes (got {actual})")]
    Truncated { expected: usize, actual: usize },
    #[error("bad magic: expected {expected:?}, got {actual:?}")]
    BadMagic { expected: [u8; 5], actual: [u8; 5] },
    #[error("unsupported version {version} (this decoder handles {supported})")]
    UnsupportedVersion { version: u8, supported: u8 },
    #[error("unsupported schema version {schema_version} (this decoder handles {supported})")]
    UnsupportedSchemaVersion { schema_version: u8, supported: u8 },
    #[error("CRC32C mismatch: expected {expected:#010x}, computed {computed:#010x}")]
    ChecksumMismatch { expected: u32, computed: u32 },
}

/// `.ccxal` header (96 bytes). `#[repr(C)]` so `size_of` and field offsets match the
/// on-disk layout exactly.
///
/// The `_pad*` fields are on-disk padding and are **private**, which diverges from the
/// CoreCrux source where they are `pub`. Two reasons: `clippy::pub_underscore_fields`
/// is denied here, and a reader-only crate has no caller that should be constructing a
/// header — these types are only ever handed out by the decoders below. The fields stay
/// in the struct because the `size_of` assertions depend on them.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub magic: [u8; 5],
    pub version: u8,
    pub schema_version: u8,
    _pad1: u8,
    pub vocab_version: u16,
    _pad2: [u8; 2],
    pub doc_count: u32,
    pub atom_count: u32,
    pub d0_atom_count: u32,
    pub d1_atom_count: u32,
    pub d2_atom_count: u32,
    pub d3_atom_count: u32,
    pub d4_atom_count: u32,
    pub ingest_agent_id: [u8; 16],
    pub ingest_model_sha: [u8; 16],
    pub sealed_at: u64,
    pub flags: u16,
    _pad3: [u8; 14],
}

/// Doc-table entry (24 bytes). Indexed by segment-local sequential `doc_idx`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DocTableEntry {
    pub doc_id: u64,
    pub d0_count: u16,
    pub d1_count: u16,
    pub d0_offset: u32,
    pub d1_offset: u32,
    _pad: [u8; 4],
}

/// D0 atom (48 bytes) — pointer crystal back to a verbatim source span.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct D0Atom {
    pub doc_id: u64,
    pub region_id: u32,
    pub byte_start: u32,
    pub byte_end: u32,
    pub content_hash: [u8; 16],
    pub provenance_triad: [u8; 12],
}

/// D1 atom (32 bytes) — claim-graph atom: predicate, actor, object, via, anchor, conf.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct D1Atom {
    pub actor_class: u8,
    pub object_class: u8,
    pub temporal_anchor_type: u8,
    _pad1: u8,
    pub actor_code: u32,
    pub object_code: u32,
    pub via_object_code: u32,
    pub predicate_code: u16,
    pub via_predicate: u16,
    pub conf_q8_8: u16,
    _pad2: [u8; 2],
    pub temporal_value: i32,
    pub evid_d0_idx: u32,
}

// Compile-time size guards: an edit that changes a struct without changing the
// offsets module (or vice versa) fails to build rather than mis-decoding at runtime.
const _: () = {
    assert!(size_of::<Header>() == offsets::header::SIZE);
    assert!(size_of::<DocTableEntry>() == offsets::doc_table_entry::SIZE);
    assert!(size_of::<D0Atom>() == offsets::d0_atom::SIZE);
    assert!(size_of::<D1Atom>() == offsets::d1_atom::SIZE);
};

const _: () = {
    assert!(offsets::header::VERSION == 5);
    assert!(offsets::header::VOCAB_VERSION == 8);
    assert!(offsets::header::DOC_COUNT == 12);
    assert!(offsets::header::INGEST_AGENT_ID == 40);
    assert!(offsets::header::SEALED_AT == 72);
    assert!(offsets::header::FLAGS == 80);
    assert!(offsets::header::SIZE == 96);

    assert!(offsets::d1_atom::PREDICATE_CODE == 16);
    assert!(offsets::d1_atom::CONF_Q8_8 == 20);
    assert!(offsets::d1_atom::TEMPORAL_VALUE == 24);
    assert!(offsets::d1_atom::EVID_D0_IDX == 28);
    assert!(offsets::d1_atom::SIZE == 32);
};

/// Convert a Q8.8 fixed-point `u16` to `f32`. `0x0100` → `1.0`; `0x004C` → `0.296875`.
pub fn q8_8_to_f32(q: u16) -> f32 {
    f32::from(q) / 256.0
}

// ─── Per-entry decoders ──────────────────────────────────────────────────────
//
// Byte-slice in, struct out. Short input yields `Truncated`; nothing here panics or
// reads past the slice end.

fn le_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn le_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn le_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
        bytes[at + 4],
        bytes[at + 5],
        bytes[at + 6],
        bytes[at + 7],
    ])
}

/// Decode a 24-byte doc-table entry.
pub fn decode_doc_table_entry(bytes: &[u8]) -> Result<DocTableEntry, CcxalError> {
    use offsets::doc_table_entry as o;
    if bytes.len() < o::SIZE {
        return Err(CcxalError::Truncated {
            expected: o::SIZE,
            actual: bytes.len(),
        });
    }
    Ok(DocTableEntry {
        doc_id: le_u64(bytes, o::DOC_ID),
        d0_count: le_u16(bytes, o::D0_COUNT),
        d1_count: le_u16(bytes, o::D1_COUNT),
        d0_offset: le_u32(bytes, o::D0_OFFSET),
        d1_offset: le_u32(bytes, o::D1_OFFSET),
        _pad: [
            bytes[o::_PAD],
            bytes[o::_PAD + 1],
            bytes[o::_PAD + 2],
            bytes[o::_PAD + 3],
        ],
    })
}

/// Decode a 48-byte D0 pointer-crystal atom.
pub fn decode_d0_atom(bytes: &[u8]) -> Result<D0Atom, CcxalError> {
    use offsets::d0_atom as o;
    if bytes.len() < o::SIZE {
        return Err(CcxalError::Truncated {
            expected: o::SIZE,
            actual: bytes.len(),
        });
    }
    let mut content_hash = [0u8; 16];
    content_hash.copy_from_slice(&bytes[o::CONTENT_HASH..o::CONTENT_HASH + 16]);
    let mut provenance_triad = [0u8; 12];
    provenance_triad.copy_from_slice(&bytes[o::PROVENANCE_TRIAD..o::PROVENANCE_TRIAD + 12]);
    Ok(D0Atom {
        doc_id: le_u64(bytes, o::DOC_ID),
        region_id: le_u32(bytes, o::REGION_ID),
        byte_start: le_u32(bytes, o::BYTE_START),
        byte_end: le_u32(bytes, o::BYTE_END),
        content_hash,
        provenance_triad,
    })
}

/// Decode a 32-byte D1 claim-graph atom.
pub fn decode_d1_atom(bytes: &[u8]) -> Result<D1Atom, CcxalError> {
    use offsets::d1_atom as o;
    if bytes.len() < o::SIZE {
        return Err(CcxalError::Truncated {
            expected: o::SIZE,
            actual: bytes.len(),
        });
    }
    Ok(D1Atom {
        actor_class: bytes[o::ACTOR_CLASS],
        object_class: bytes[o::OBJECT_CLASS],
        temporal_anchor_type: bytes[o::TEMPORAL_ANCHOR_TYPE],
        _pad1: bytes[o::_PAD1],
        actor_code: le_u32(bytes, o::ACTOR_CODE),
        object_code: le_u32(bytes, o::OBJECT_CODE),
        via_object_code: le_u32(bytes, o::VIA_OBJECT_CODE),
        predicate_code: le_u16(bytes, o::PREDICATE_CODE),
        via_predicate: le_u16(bytes, o::VIA_PREDICATE),
        conf_q8_8: le_u16(bytes, o::CONF_Q8_8),
        _pad2: [bytes[o::_PAD2], bytes[o::_PAD2 + 1]],
        temporal_value: le_u32(bytes, o::TEMPORAL_VALUE) as i32,
        evid_d0_idx: le_u32(bytes, o::EVID_D0_IDX),
    })
}

/// Decode a `.ccxal` header from a little-endian byte slice.
pub fn decode_header(bytes: &[u8]) -> Result<Header, CcxalError> {
    use offsets::header as h;
    if bytes.len() < h::SIZE {
        return Err(CcxalError::Truncated {
            expected: h::SIZE,
            actual: bytes.len(),
        });
    }
    let mut magic = [0u8; 5];
    magic.copy_from_slice(&bytes[h::MAGIC..h::MAGIC + 5]);
    if magic != CCXAL_MAGIC {
        return Err(CcxalError::BadMagic {
            expected: CCXAL_MAGIC,
            actual: magic,
        });
    }
    let version = bytes[h::VERSION];
    if version != CCXAL_VERSION {
        return Err(CcxalError::UnsupportedVersion {
            version,
            supported: CCXAL_VERSION,
        });
    }
    let schema_version = bytes[h::SCHEMA_VERSION];
    if schema_version != CCXAL_SCHEMA_VERSION {
        return Err(CcxalError::UnsupportedSchemaVersion {
            schema_version,
            supported: CCXAL_SCHEMA_VERSION,
        });
    }
    let mut ingest_agent_id = [0u8; 16];
    ingest_agent_id.copy_from_slice(&bytes[h::INGEST_AGENT_ID..h::INGEST_AGENT_ID + 16]);
    let mut ingest_model_sha = [0u8; 16];
    ingest_model_sha.copy_from_slice(&bytes[h::INGEST_MODEL_SHA..h::INGEST_MODEL_SHA + 16]);
    let mut pad3 = [0u8; 14];
    pad3.copy_from_slice(&bytes[h::_PAD3..h::_PAD3 + 14]);

    Ok(Header {
        magic,
        version,
        schema_version,
        _pad1: bytes[h::_PAD1],
        vocab_version: le_u16(bytes, h::VOCAB_VERSION),
        _pad2: [bytes[h::_PAD2], bytes[h::_PAD2 + 1]],
        doc_count: le_u32(bytes, h::DOC_COUNT),
        atom_count: le_u32(bytes, h::ATOM_COUNT),
        d0_atom_count: le_u32(bytes, h::D0_ATOM_COUNT),
        d1_atom_count: le_u32(bytes, h::D1_ATOM_COUNT),
        d2_atom_count: le_u32(bytes, h::D2_ATOM_COUNT),
        d3_atom_count: le_u32(bytes, h::D3_ATOM_COUNT),
        d4_atom_count: le_u32(bytes, h::D4_ATOM_COUNT),
        ingest_agent_id,
        ingest_model_sha,
        sealed_at: le_u64(bytes, h::SEALED_AT),
        flags: le_u16(bytes, h::FLAGS),
        _pad3: pad3,
    })
}

/// Reader: borrows a byte slice and lazily decodes entries.
///
/// [`CcxalReader::from_bytes`] validates magic, version, schema version, the section
/// layout and the CRC32C footer. Subsequent atom lookups are `O(1)` per index with no
/// allocation.
#[derive(Debug)]
pub struct CcxalReader<'a> {
    data: &'a [u8],
    header: Header,
    doc_table_offset: usize,
    d0_section_offset: usize,
    d1_section_offset: usize,
    strings_offset: usize,
    strings_len: usize,
}

impl<'a> CcxalReader<'a> {
    /// Parse and validate a `.ccxal` byte slice, verifying the CRC32C footer.
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, CcxalError> {
        let header = decode_header(data)?;
        let truncated = || CcxalError::Truncated {
            expected: data.len() + 1,
            actual: data.len(),
        };

        let doc_table_offset = offsets::header::SIZE;
        let d0_section_offset = (header.doc_count as usize)
            .checked_mul(offsets::doc_table_entry::SIZE)
            .and_then(|n| doc_table_offset.checked_add(n))
            .ok_or_else(truncated)?;
        let d1_section_offset = (header.d0_atom_count as usize)
            .checked_mul(offsets::d0_atom::SIZE)
            .and_then(|n| d0_section_offset.checked_add(n))
            .ok_or_else(truncated)?;
        let strings_offset = (header.d1_atom_count as usize)
            .checked_mul(offsets::d1_atom::SIZE)
            .and_then(|n| d1_section_offset.checked_add(n))
            .ok_or_else(truncated)?;

        // The file is body (strings_offset + strings_len) plus a 4-byte CRC footer.
        if data.len() < strings_offset + offsets::FOOTER_SIZE {
            return Err(CcxalError::Truncated {
                expected: strings_offset + offsets::FOOTER_SIZE,
                actual: data.len(),
            });
        }
        let strings_len = data.len() - strings_offset - offsets::FOOTER_SIZE;
        let body_end = strings_offset + strings_len;

        let stored = le_u32(data, body_end);
        let computed = crc32c(&data[..body_end]);
        if stored != computed {
            return Err(CcxalError::ChecksumMismatch {
                expected: stored,
                computed,
            });
        }

        Ok(Self {
            data,
            header,
            doc_table_offset,
            d0_section_offset,
            d1_section_offset,
            strings_offset,
            strings_len,
        })
    }

    /// Borrow the decoded header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Number of docs in this segment.
    pub fn doc_count(&self) -> u32 {
        self.header.doc_count
    }

    /// Number of D0 (pointer crystal) atoms.
    pub fn d0_atom_count(&self) -> u32 {
        self.header.d0_atom_count
    }

    /// Number of D1 (claim graph) atoms.
    pub fn d1_atom_count(&self) -> u32 {
        self.header.d1_atom_count
    }

    /// Decode the doc-table entry at `idx` (0-based, `< doc_count()`).
    pub fn doc(&self, idx: u32) -> Result<DocTableEntry, CcxalError> {
        if idx >= self.header.doc_count {
            return Err(CcxalError::Truncated {
                expected: ((idx as usize) + 1) * offsets::doc_table_entry::SIZE,
                actual: self.header.doc_count as usize * offsets::doc_table_entry::SIZE,
            });
        }
        let start = self.doc_table_offset + idx as usize * offsets::doc_table_entry::SIZE;
        decode_doc_table_entry(&self.data[start..start + offsets::doc_table_entry::SIZE])
    }

    /// Decode the D0 atom at the given segment-local index (`< d0_atom_count()`).
    pub fn d0_atom(&self, idx: u32) -> Result<D0Atom, CcxalError> {
        if idx >= self.header.d0_atom_count {
            return Err(CcxalError::Truncated {
                expected: ((idx as usize) + 1) * offsets::d0_atom::SIZE,
                actual: self.header.d0_atom_count as usize * offsets::d0_atom::SIZE,
            });
        }
        let start = self.d0_section_offset + idx as usize * offsets::d0_atom::SIZE;
        decode_d0_atom(&self.data[start..start + offsets::d0_atom::SIZE])
    }

    /// Decode the D1 atom at the given segment-local index (`< d1_atom_count()`).
    pub fn d1_atom(&self, idx: u32) -> Result<D1Atom, CcxalError> {
        if idx >= self.header.d1_atom_count {
            return Err(CcxalError::Truncated {
                expected: ((idx as usize) + 1) * offsets::d1_atom::SIZE,
                actual: self.header.d1_atom_count as usize * offsets::d1_atom::SIZE,
            });
        }
        let start = self.d1_section_offset + idx as usize * offsets::d1_atom::SIZE;
        decode_d1_atom(&self.data[start..start + offsets::d1_atom::SIZE])
    }

    /// Borrow the raw strings pool (null-terminated UTF-8 OOV surface entries).
    pub fn strings_pool(&self) -> &'a [u8] {
        &self.data[self.strings_offset..self.strings_offset + self.strings_len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_sizes_match_the_on_disk_spec() {
        assert_eq!(size_of::<Header>(), 96);
        assert_eq!(size_of::<DocTableEntry>(), 24);
        assert_eq!(size_of::<D0Atom>(), 48);
        assert_eq!(size_of::<D1Atom>(), 32);
    }

    #[test]
    fn q8_8_decodes_the_documented_values() {
        assert!((q8_8_to_f32(0x0100) - 1.0).abs() < f32::EPSILON);
        assert!((q8_8_to_f32(CONFIDENCE_FLOOR_Q8_8) - 0.296_875).abs() < f32::EPSILON);
    }

    #[test]
    fn a_short_header_is_truncated_not_indexed() {
        assert!(matches!(decode_header(&[0u8; 4]), Err(CcxalError::Truncated { .. })));
    }

    #[test]
    fn a_foreign_magic_is_rejected() {
        let data = vec![0u8; offsets::header::SIZE];
        assert!(matches!(decode_header(&data), Err(CcxalError::BadMagic { .. })));
    }

    #[test]
    fn an_unsupported_schema_version_is_rejected() {
        let mut data = vec![0u8; offsets::header::SIZE];
        data[..5].copy_from_slice(&CCXAL_MAGIC);
        data[offsets::header::VERSION] = CCXAL_VERSION;
        data[offsets::header::SCHEMA_VERSION] = CCXAL_SCHEMA_VERSION + 1;
        assert!(matches!(
            decode_header(&data),
            Err(CcxalError::UnsupportedSchemaVersion { .. })
        ));
    }

    /// `temporal_value` is the one signed field in the atom set; decoding it as
    /// unsigned turns "900 seconds before the anchor" into ~4.29 billion after it.
    #[test]
    fn d1_temporal_value_decodes_as_signed() {
        let mut bytes = [0u8; offsets::d1_atom::SIZE];
        bytes[offsets::d1_atom::TEMPORAL_VALUE..offsets::d1_atom::TEMPORAL_VALUE + 4]
            .copy_from_slice(&(-900i32).to_le_bytes());
        let atom = decode_d1_atom(&bytes).expect("decode");
        assert_eq!(atom.temporal_value, -900);
    }

    #[test]
    fn short_entry_buffers_are_truncated_not_panics() {
        assert!(matches!(
            decode_doc_table_entry(&[0u8; 8]),
            Err(CcxalError::Truncated { .. })
        ));
        assert!(matches!(decode_d0_atom(&[0u8; 8]), Err(CcxalError::Truncated { .. })));
        assert!(matches!(decode_d1_atom(&[0u8; 8]), Err(CcxalError::Truncated { .. })));
    }
}
