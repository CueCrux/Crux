// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Public segment types: `SegmentId`, `SegmentHeaderV1`, `SegmentFooterV1`, `TocEntryV1`, `BlockMetaV1`.

use crate::BLOOM_BYTES_PER_BLOCK_V1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentId(pub [u8; 16]);

#[derive(Debug, Clone)]
pub struct SegmentHeaderV1 {
    pub flags: u32,
    pub shard_id: u32,
    pub epoch: u64,
    pub segment_seq: u64,
    pub segment_id: SegmentId,
    pub created_at_unix_ns: u64,
}

#[derive(Debug, Clone)]
pub struct TocHeaderV1 {
    pub entry_count: u64,
    pub record_block_size: u32,
    pub toc_block_size: u32,
    pub record_area_offset: u64,
    pub record_area_len: u64,
    pub toc_payload_len: u64,
    pub crc_tables_len: u64,
    pub sort_order: u64,
    pub toc_payload_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TocEntryV1 {
    pub stream_hash: u64,
    pub seq: u64,
    pub file_offset: u32,
    pub frame_len: u32,
    pub payload_len: u32,
    pub flags: u32,
    pub event_id_hash16: [u8; 16],
    pub header_digest8: [u8; 8],
    pub payload_digest8: [u8; 8],
}

#[derive(Debug, Clone)]
pub struct SegmentFooterV1 {
    pub flags: u32,
    pub shard_id: u32,
    pub epoch: u64,
    pub segment_seq: u64,
    pub segment_id: SegmentId,
    pub created_at_unix_ns: u64,
    pub sealed_at_unix_ns: u64,
    pub file_len: u64,
    pub record_area_offset: u64,
    pub record_area_len: u64,
    pub toc_offset: u64,
    pub toc_len: u64,
    pub toc_entry_count: u64,
    pub min_stream_hash: u64,
    pub min_seq: u64,
    pub max_stream_hash: u64,
    pub max_seq: u64,
    pub header_hash: [u8; 32],
    pub record_hash: [u8; 32],
    pub toc_payload_hash: [u8; 32],
    pub segment_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct SegmentBuildOutput {
    pub bytes: Vec<u8>,
    pub header: SegmentHeaderV1,
    pub toc_header: TocHeaderV1,
    pub toc_entries: Vec<TocEntryV1>,
    pub footer: SegmentFooterV1,
    pub record_crc32c_table: Vec<u32>,
    pub toc_crc32c_table: Vec<u32>,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct FrameMetaTmp {
    pub(crate) stream_hash: u64,
    pub(crate) seq: u64,
    pub(crate) event_id_hash16: [u8; 16],
    pub(crate) header_digest8: [u8; 8],
    pub(crate) payload_digest8: [u8; 8],
    pub(crate) record_off: u32,
    pub(crate) frame_len: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TocByOffsetEntryV1 {
    pub stream_hash: u64,
    pub seq: u64,
    pub block_id: u32,
    pub in_block_offset: u32,
    pub frame_len: u32,
    pub flags: u32,
    pub event_id_hash16: [u8; 16],
    pub header_digest8: [u8; 8],
    pub payload_digest8: [u8; 8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockMetaV1 {
    pub block_id: u32,
    pub codec: u32, // RECORD_BLOCK_CODEC_*_V1
    pub file_offset: u64,
    pub compressed_len: u32,
    /// Physical bytes on disk for this block payload (may include padding for alignment).
    ///
    /// Backwards-compat: older segments may encode this as 0; readers should treat 0 as
    /// `compressed_len`.
    pub physical_len: u32,
    pub uncompressed_len: u32,
    pub crc32c: u32,
    pub bloom: [u8; BLOOM_BYTES_PER_BLOCK_V1],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailerIndexV1 {
    pub record_block_uncompressed_max_len: u32,
    pub bloom_bytes_per_block: u32,
    pub bloom_hash_k: u32,
    pub blocks: Vec<BlockMetaV1>,
    pub toc_by_offset: Vec<TocByOffsetEntryV1>,
    pub toc_sorted_idx: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct FrameInput<'a> {
    pub stream_hash: u64,
    pub seq: u64,
    pub event_id: &'a str,
    pub header_hash: [u8; 32],
    pub payload_hash: [u8; 32],
    pub header_bytes: &'a [u8],
    pub payload_bytes: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct FrameMetaV1 {
    pub stream_hash: u64,
    pub seq: u64,
    pub record_off: u32,
    pub frame_len: u32,
    pub payload_len: u32,
    pub event_id_hash16: [u8; 16],
    pub header_digest8: [u8; 8],
    pub payload_digest8: [u8; 8],
}

#[derive(Debug, Clone)]
pub struct FrameV1Decoded {
    pub header_bytes: Vec<u8>,
    pub payload_bytes: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct RecordBlocksAndTrailerIndexPartsV1 {
    pub(crate) record_area: Vec<u8>,
    pub(crate) blocks: Vec<BlockMetaV1>,
    pub(crate) toc_by_offset: Vec<TocByOffsetEntryV1>,
    pub(crate) toc_sorted_idx: Vec<u32>,
}
