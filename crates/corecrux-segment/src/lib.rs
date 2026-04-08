// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

#![deny(clippy::unwrap_used)]

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

use thiserror::Error;

// ── Sub-modules ──────────────────────────────────────────────────────────────

pub mod block;
pub mod bloom;
pub mod builder;
pub mod decoder;
pub mod footer;
pub mod frame;
pub mod header;
pub mod sealer;
pub mod toc;
pub mod trailer;
pub(crate) mod types;
pub(crate) mod util;

// ── Constants ────────────────────────────────────────────────────────────────

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

// Record block codecs for BlockMetaV1.codec.
pub const RECORD_BLOCK_CODEC_NONE_V1: u32 = 0;
pub const RECORD_BLOCK_CODEC_LZ4_V1: u32 = 1;

// ── Error type ───────────────────────────────────────────────────────────────

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

// ── Re-exports ───────────────────────────────────────────────────────────────

// Types (from types.rs)
pub use types::{
    BlockMetaV1, FrameInput, FrameMetaV1, FrameV1Decoded, SegmentBuildOutput, SegmentFooterV1, SegmentHeaderV1,
    SegmentId, TocByOffsetEntryV1, TocEntryV1, TocHeaderV1, TrailerIndexV1,
};

// Frame encode/decode
pub use frame::{decode_frame_v1, encode_frame_v1};

// Header encode/decode
pub use header::{decode_segment_header_v1, encode_segment_header_v1};

// Footer encode/decode
pub use footer::{decode_segment_footer_v1, encode_segment_footer_v1};

// TOC
pub use toc::decode_toc_header_v1;

// Block meta
pub use block::{encode_block_meta_v1, encode_toc_by_offset_entry_v1};

// Bloom filters
pub use bloom::{bloom_insert_stream_hash_v1, bloom_maybe_contains_stream_hash_v1};

// Trailer index
pub use trailer::decode_trailer_index_v1;

// Builder
pub use builder::{build_segment_v1, build_segment_v1_with_block_codec};

// Sealer
pub use sealer::{seal_segment_v1_from_record_area, seal_segment_v1_from_record_area_with_block_codec};

// Decoder
pub use decoder::decode_segment_v1;
