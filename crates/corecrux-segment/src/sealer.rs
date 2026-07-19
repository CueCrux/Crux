// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Sealer entry-point — consumes record-block bytes + trailer index parts, produces a fully sealed segment.

use blake3::Hasher as Blake3;

use crate::footer::encode_segment_footer_v1;
use crate::header::encode_segment_header_v1;
use crate::toc::{compute_toc_payload_hash, encode_toc_payload_v1, encode_toc_payload_v1_with_hash};
use crate::trailer::{
    build_record_blocks_and_trailer_index_parts_v1, encode_trailer_index_v1, encode_trailer_index_v1_from_parts,
};
use crate::types::FrameMetaTmp;
use crate::util::{align_up, block_crc32c, is_sorted_toc};
use crate::{
    FrameMetaV1, Result, SegmentBuildOutput, SegmentError, SegmentFooterV1, SegmentHeaderV1, SegmentId, TocEntryV1,
    TocHeaderV1, DEFAULT_RECORD_BLOCK_SIZE, DEFAULT_TOC_BLOCK_SIZE, RECORD_BLOCK_CODEC_NONE_V1, SEGMENT_FOOTER_LEN,
    SEGMENT_HEADER_LEN, TOC_ENTRY_LEN, TOC_HEADER_LEN,
};

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    level = "info",
    skip(record_area, frames_by_offset),
    fields(
        shard_id,
        epoch,
        segment_seq,
        record_area_len = record_area.len(),
        frame_count = frames_by_offset.len()
    )
)]
pub fn seal_segment_v1_from_record_area(
    shard_id: u32,
    epoch: u64,
    segment_seq: u64,
    segment_id: SegmentId,
    created_at_unix_ns: u64,
    sealed_at_unix_ns: u64,
    record_area: &[u8],
    frames_by_offset: &[FrameMetaV1],
) -> Result<SegmentBuildOutput> {
    let header = SegmentHeaderV1 {
        flags: 1, // little_endian
        shard_id,
        epoch,
        segment_seq,
        segment_id,
        created_at_unix_ns,
    };
    let header_bytes = encode_segment_header_v1(&header)?;

    // Validate and build TOC/trailer metadata.
    let mut toc_entries: Vec<TocEntryV1> = Vec::with_capacity(frames_by_offset.len());
    let mut tmp: Vec<FrameMetaTmp> = Vec::with_capacity(frames_by_offset.len());

    let mut expected_off: u32 = 0;
    for f in frames_by_offset {
        if f.record_off != expected_off {
            return Err(SegmentError::LengthOutOfRange {
                msg: "frames_by_offset record_off is not contiguous".to_string(),
            });
        }
        let end = f
            .record_off
            .checked_add(f.frame_len)
            .ok_or(SegmentError::BufferTooSmall)? as usize;
        if end > record_area.len() {
            return Err(SegmentError::LengthOutOfRange {
                msg: "frames_by_offset points outside record area".to_string(),
            });
        }

        let file_offset = (SEGMENT_HEADER_LEN as u64)
            .checked_add(f.record_off as u64)
            .ok_or(SegmentError::BufferTooSmall)?;
        if file_offset > u32::MAX as u64 {
            return Err(SegmentError::LengthOutOfRange {
                msg: "file offset exceeds u32".to_string(),
            });
        }

        toc_entries.push(TocEntryV1 {
            stream_hash: f.stream_hash,
            seq: f.seq,
            file_offset: file_offset as u32,
            frame_len: f.frame_len,
            payload_len: f.payload_len,
            flags: 0,
            event_id_hash16: f.event_id_hash16,
            header_digest8: f.header_digest8,
            payload_digest8: f.payload_digest8,
        });

        tmp.push(FrameMetaTmp {
            stream_hash: f.stream_hash,
            seq: f.seq,
            event_id_hash16: f.event_id_hash16,
            header_digest8: f.header_digest8,
            payload_digest8: f.payload_digest8,
            record_off: f.record_off,
            frame_len: f.frame_len,
        });

        expected_off = expected_off.saturating_add(f.frame_len);
    }
    if expected_off as usize != record_area.len() {
        return Err(SegmentError::LengthOutOfRange {
            msg: "frames_by_offset does not cover record area".to_string(),
        });
    }

    // TOC entries are stored sorted by (stream_hash, seq).
    toc_entries.sort_by(|a, b| match a.stream_hash.cmp(&b.stream_hash) {
        std::cmp::Ordering::Equal => a.seq.cmp(&b.seq),
        other => other,
    });
    if !is_sorted_toc(&toc_entries) {
        return Err(SegmentError::TocNotSorted);
    }

    let record_area_offset = SEGMENT_HEADER_LEN as u64;
    let record_area_len = record_area.len() as u64;
    if record_area_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "record area exceeds 4GiB; not supported in v1 footer encoding".to_string(),
        });
    }

    let toc_payload_len = (TOC_HEADER_LEN + toc_entries.len() * TOC_ENTRY_LEN) as u64;
    let record_crc32c_table = block_crc32c(record_area, DEFAULT_RECORD_BLOCK_SIZE as usize);
    let toc_payload = encode_toc_payload_v1(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        (record_crc32c_table.len() * 4) as u64, // placeholder; fixed below
        &toc_entries,
    )?;

    let toc_crc32c_table = block_crc32c(&toc_payload, DEFAULT_TOC_BLOCK_SIZE as usize);

    let crc_tables_len = (record_crc32c_table.len() as u64 * 4) + (toc_crc32c_table.len() as u64 * 4);

    // Re-encode toc header now that we have the full crc_tables_len.
    let toc_payload = encode_toc_payload_v1(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        &toc_entries,
    )?;

    let toc_payload_hash = compute_toc_payload_hash(&toc_payload)?;

    let toc_payload = encode_toc_payload_v1_with_hash(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        toc_payload_hash,
        &toc_entries,
    )?;

    let toc_crc32c_table = block_crc32c(&toc_payload, DEFAULT_TOC_BLOCK_SIZE as usize);
    let crc_tables_len = (record_crc32c_table.len() as u64 * 4) + (toc_crc32c_table.len() as u64 * 4);

    let toc_header = TocHeaderV1 {
        entry_count: toc_entries.len() as u64,
        record_block_size: DEFAULT_RECORD_BLOCK_SIZE,
        toc_block_size: DEFAULT_TOC_BLOCK_SIZE,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        sort_order: 1,
        toc_payload_hash,
    };

    // Assemble TocArea bytes.
    let mut toc_area: Vec<u8> = Vec::with_capacity(toc_payload.len() + (crc_tables_len as usize));
    toc_area.extend_from_slice(&toc_payload);
    for c in &record_crc32c_table {
        toc_area.extend_from_slice(&c.to_le_bytes());
    }
    for c in &toc_crc32c_table {
        toc_area.extend_from_slice(&c.to_le_bytes());
    }

    // Phase 5: trailer extension sections (block index + toc-by-offset + sorted idx).
    let trailer_ext = encode_trailer_index_v1(record_area, &tmp)?;
    toc_area.extend_from_slice(&trailer_ext);

    let toc_offset = record_area_offset + record_area_len;
    let toc_len = toc_area.len() as u64;

    if toc_offset > u32::MAX as u64 || toc_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "toc offsets exceed u32".to_string(),
        });
    }

    // Bounds.
    let (min_stream_hash, min_seq, max_stream_hash, max_seq) = if toc_entries.is_empty() {
        (0, 0, 0, 0)
    } else {
        let first = toc_entries[0];
        let last = toc_entries[toc_entries.len() - 1];
        (first.stream_hash, first.seq, last.stream_hash, last.seq)
    };

    // Strong hashes.
    let header_hash = blake3::hash(&header_bytes);
    let record_hash = blake3::hash(record_area);
    let segment_hash = {
        let mut h = Blake3::new();
        h.update(header_hash.as_bytes());
        h.update(record_hash.as_bytes());
        h.update(&toc_payload_hash);
        *h.finalize().as_bytes()
    };

    let file_len = (SEGMENT_HEADER_LEN as u64) + record_area_len + toc_len + (SEGMENT_FOOTER_LEN as u64);
    if file_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "segment file exceeds 4GiB; not supported in v1 footer encoding".to_string(),
        });
    }

    let footer = SegmentFooterV1 {
        flags: 0x3, // SEALED|HAS_TOC
        shard_id,
        epoch,
        segment_seq,
        segment_id,
        created_at_unix_ns,
        sealed_at_unix_ns,
        file_len,
        record_area_offset,
        record_area_len,
        toc_offset,
        toc_len,
        toc_entry_count: toc_entries.len() as u64,
        min_stream_hash,
        min_seq,
        max_stream_hash,
        max_seq,
        header_hash: *header_hash.as_bytes(),
        record_hash: *record_hash.as_bytes(),
        toc_payload_hash,
        segment_hash,
    };
    let footer_bytes = encode_segment_footer_v1(&footer)?;

    // Final file assembly.
    let mut bytes = Vec::with_capacity(file_len as usize);
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(record_area);
    bytes.extend_from_slice(&toc_area);
    bytes.extend_from_slice(&footer_bytes);

    Ok(SegmentBuildOutput {
        bytes,
        header,
        toc_header,
        toc_entries,
        footer,
        record_crc32c_table,
        toc_crc32c_table,
    })
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    level = "info",
    skip(record_area, frames_by_offset),
    fields(
        shard_id,
        epoch,
        segment_seq,
        record_block_codec,
        record_area_len = record_area.len(),
        frame_count = frames_by_offset.len()
    )
)]
pub fn seal_segment_v1_from_record_area_with_block_codec(
    shard_id: u32,
    epoch: u64,
    segment_seq: u64,
    segment_id: SegmentId,
    created_at_unix_ns: u64,
    sealed_at_unix_ns: u64,
    record_block_codec: u32,
    record_area: &[u8],
    frames_by_offset: &[FrameMetaV1],
) -> Result<SegmentBuildOutput> {
    if record_block_codec == RECORD_BLOCK_CODEC_NONE_V1 {
        return seal_segment_v1_from_record_area(
            shard_id,
            epoch,
            segment_seq,
            segment_id,
            created_at_unix_ns,
            sealed_at_unix_ns,
            record_area,
            frames_by_offset,
        );
    }

    let header = SegmentHeaderV1 {
        flags: 1, // little_endian
        shard_id,
        epoch,
        segment_seq,
        segment_id,
        created_at_unix_ns,
    };
    let header_bytes = encode_segment_header_v1(&header)?;

    // Validate and build TOC/trailer metadata.
    let mut toc_entries: Vec<TocEntryV1> = Vec::with_capacity(frames_by_offset.len());
    let mut tmp: Vec<FrameMetaTmp> = Vec::with_capacity(frames_by_offset.len());

    let mut expected_off: u32 = 0;
    for f in frames_by_offset {
        if f.record_off != expected_off {
            return Err(SegmentError::LengthOutOfRange {
                msg: "frames_by_offset record_off is not contiguous".to_string(),
            });
        }
        let end = f
            .record_off
            .checked_add(f.frame_len)
            .ok_or(SegmentError::BufferTooSmall)? as usize;
        if end > record_area.len() {
            return Err(SegmentError::LengthOutOfRange {
                msg: "frames_by_offset points outside record area".to_string(),
            });
        }

        let file_offset = (SEGMENT_HEADER_LEN as u64)
            .checked_add(f.record_off as u64)
            .ok_or(SegmentError::BufferTooSmall)?;
        if file_offset > u32::MAX as u64 {
            return Err(SegmentError::LengthOutOfRange {
                msg: "file offset exceeds u32".to_string(),
            });
        }

        toc_entries.push(TocEntryV1 {
            stream_hash: f.stream_hash,
            seq: f.seq,
            file_offset: file_offset as u32,
            frame_len: f.frame_len,
            payload_len: f.payload_len,
            flags: 0,
            event_id_hash16: f.event_id_hash16,
            header_digest8: f.header_digest8,
            payload_digest8: f.payload_digest8,
        });

        tmp.push(FrameMetaTmp {
            stream_hash: f.stream_hash,
            seq: f.seq,
            event_id_hash16: f.event_id_hash16,
            header_digest8: f.header_digest8,
            payload_digest8: f.payload_digest8,
            record_off: f.record_off,
            frame_len: f.frame_len,
        });

        expected_off = expected_off.saturating_add(f.frame_len);
    }
    if expected_off as usize != record_area.len() {
        return Err(SegmentError::LengthOutOfRange {
            msg: "frames_by_offset does not cover record area".to_string(),
        });
    }

    toc_entries.sort_by(|a, b| match a.stream_hash.cmp(&b.stream_hash) {
        std::cmp::Ordering::Equal => a.seq.cmp(&b.seq),
        other => other,
    });
    if !is_sorted_toc(&toc_entries) {
        return Err(SegmentError::TocNotSorted);
    }

    let crate::types::RecordBlocksAndTrailerIndexPartsV1 {
        record_area,
        blocks,
        toc_by_offset,
        toc_sorted_idx,
    } = build_record_blocks_and_trailer_index_parts_v1(record_area, &tmp, record_block_codec)?;
    let trailer_ext = encode_trailer_index_v1_from_parts(&blocks, &toc_by_offset, &toc_sorted_idx)?;

    let record_area_offset = SEGMENT_HEADER_LEN as u64;
    let record_area_len = record_area.len() as u64;
    if record_area_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "record area exceeds 4GiB; not supported in v1 footer encoding".to_string(),
        });
    }

    let toc_payload_len = (TOC_HEADER_LEN + toc_entries.len() * TOC_ENTRY_LEN) as u64;
    let record_crc32c_table = block_crc32c(&record_area, DEFAULT_RECORD_BLOCK_SIZE as usize);
    let toc_payload = encode_toc_payload_v1(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        (record_crc32c_table.len() * 4) as u64, // placeholder; fixed below
        &toc_entries,
    )?;

    let toc_crc32c_table = block_crc32c(&toc_payload, DEFAULT_TOC_BLOCK_SIZE as usize);

    let crc_tables_len = (record_crc32c_table.len() as u64 * 4) + (toc_crc32c_table.len() as u64 * 4);

    let toc_payload = encode_toc_payload_v1(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        &toc_entries,
    )?;

    let toc_payload_hash = compute_toc_payload_hash(&toc_payload)?;

    let toc_payload = encode_toc_payload_v1_with_hash(
        toc_entries.len() as u64,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        toc_payload_hash,
        &toc_entries,
    )?;

    let toc_crc32c_table = block_crc32c(&toc_payload, DEFAULT_TOC_BLOCK_SIZE as usize);
    let crc_tables_len = (record_crc32c_table.len() as u64 * 4) + (toc_crc32c_table.len() as u64 * 4);

    let toc_header = TocHeaderV1 {
        entry_count: toc_entries.len() as u64,
        record_block_size: DEFAULT_RECORD_BLOCK_SIZE,
        toc_block_size: DEFAULT_TOC_BLOCK_SIZE,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        sort_order: 1,
        toc_payload_hash,
    };

    let mut toc_area: Vec<u8> = Vec::with_capacity(toc_payload.len() + (crc_tables_len as usize));
    toc_area.extend_from_slice(&toc_payload);
    for c in &record_crc32c_table {
        toc_area.extend_from_slice(&c.to_le_bytes());
    }
    for c in &toc_crc32c_table {
        toc_area.extend_from_slice(&c.to_le_bytes());
    }
    toc_area.extend_from_slice(&trailer_ext);

    // Phase 9: pad TOC area with trailing zeros so (toc_len + footer_len) is 4KiB-aligned.
    // Header and record area are already 4KiB-aligned, so this makes the full file length aligned.
    let want = toc_area
        .len()
        .checked_add(SEGMENT_FOOTER_LEN)
        .ok_or(SegmentError::BufferTooSmall)?;
    let aligned = align_up(want, 4096);
    let pad = aligned.saturating_sub(want);
    if pad > 0 {
        toc_area.resize(toc_area.len().saturating_add(pad), 0u8);
    }

    let toc_offset = record_area_offset + record_area_len;
    let toc_len = toc_area.len() as u64;
    if toc_offset > u32::MAX as u64 || toc_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "toc offsets exceed u32".to_string(),
        });
    }

    let (min_stream_hash, min_seq, max_stream_hash, max_seq) = if toc_entries.is_empty() {
        (0, 0, 0, 0)
    } else {
        let first = toc_entries[0];
        let last = toc_entries[toc_entries.len() - 1];
        (first.stream_hash, first.seq, last.stream_hash, last.seq)
    };

    let header_hash = blake3::hash(&header_bytes);
    let record_hash = blake3::hash(&record_area);
    let segment_hash = {
        let mut h = Blake3::new();
        h.update(header_hash.as_bytes());
        h.update(record_hash.as_bytes());
        h.update(&toc_payload_hash);
        *h.finalize().as_bytes()
    };

    let file_len = (SEGMENT_HEADER_LEN as u64) + record_area_len + toc_len + (SEGMENT_FOOTER_LEN as u64);
    if file_len > u32::MAX as u64 {
        return Err(SegmentError::LengthOutOfRange {
            msg: "segment file exceeds 4GiB; not supported in v1 footer encoding".to_string(),
        });
    }

    let footer = SegmentFooterV1 {
        flags: 0x3, // SEALED|HAS_TOC
        shard_id,
        epoch,
        segment_seq,
        segment_id,
        created_at_unix_ns,
        sealed_at_unix_ns,
        file_len,
        record_area_offset,
        record_area_len,
        toc_offset,
        toc_len,
        toc_entry_count: toc_entries.len() as u64,
        min_stream_hash,
        min_seq,
        max_stream_hash,
        max_seq,
        header_hash: *header_hash.as_bytes(),
        record_hash: *record_hash.as_bytes(),
        toc_payload_hash,
        segment_hash,
    };
    let footer_bytes = encode_segment_footer_v1(&footer)?;

    let mut bytes = Vec::with_capacity(file_len as usize);
    bytes.extend_from_slice(&header_bytes);
    bytes.extend_from_slice(&record_area);
    bytes.extend_from_slice(&toc_area);
    bytes.extend_from_slice(&footer_bytes);

    Ok(SegmentBuildOutput {
        bytes,
        header,
        toc_header,
        toc_entries,
        footer,
        record_crc32c_table,
        toc_crc32c_table,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::decoder::decode_segment_v1;
    use crate::trailer::decode_trailer_index_v1;
    use crate::RECORD_BLOCK_CODEC_LZ4_V1;

    /// A record-area frame whose `frame_len` bytes span `[record_off, record_off+frame_len)`.
    /// `payload_len` and the digests are opaque to the sealer, so they carry marker values.
    fn frame(stream_hash: u64, seq: u64, record_off: u32, frame_len: u32) -> FrameMetaV1 {
        FrameMetaV1 {
            stream_hash,
            seq,
            record_off,
            frame_len,
            payload_len: frame_len.saturating_sub(4),
            event_id_hash16: [seq as u8; 16],
            header_digest8: [stream_hash as u8; 8],
            payload_digest8: [(seq + 1) as u8; 8],
        }
    }

    /// Three contiguous 40-byte frames covering a 120-byte record area. Deliberately
    /// stored out of `(stream_hash, seq)` order so the TOC sort and min/max bounds are
    /// exercised: record order is (9,1),(1,2),(1,1); sorted order is (1,1),(1,2),(9,1).
    fn sample_layout() -> (Vec<u8>, Vec<FrameMetaV1>) {
        let record_area = vec![0xABu8; 120];
        let frames = vec![frame(9, 1, 0, 40), frame(1, 2, 40, 40), frame(1, 1, 80, 40)];
        (record_area, frames)
    }

    // Existing constants used across assertions.
    const HDR: u64 = SEGMENT_HEADER_LEN as u64;

    #[test]
    fn seal_segment_from_record_area_validates_contiguity() {
        let err = seal_segment_v1_from_record_area(
            0,
            1,
            1,
            SegmentId([0u8; 16]),
            1,
            2,
            &[0u8; 100],
            &[FrameMetaV1 {
                stream_hash: 1,
                seq: 1,
                record_off: 10, // should be 0
                frame_len: 50,
                payload_len: 20,
                event_id_hash16: [0; 16],
                header_digest8: [0; 8],
                payload_digest8: [0; 8],
            }],
        )
        .unwrap_err();
        assert!(matches!(err, SegmentError::LengthOutOfRange { .. }));
    }

    /// Full sealed-segment round-trip for the uncompressed path. This pins every
    /// structural invariant of `seal_segment_v1_from_record_area`: the segment must
    /// decode, the TOC must be sorted, offsets/lengths must line up, the footer bounds
    /// (min/max stream_hash + seq) must reflect the sorted TOC, per-entry file offsets
    /// must equal `header_len + record_off`, the embedded `crc_tables_len` must match the
    /// builder's own accounting, and the Phase-5 trailer index must decode from it.
    ///
    /// Any arithmetic/comparison mutation that shifts a length, offset, bound, or guard
    /// produces a segment that fails one of these checks (or fails to decode at all).
    #[test]
    fn seal_uncompressed_roundtrip_preserves_invariants() {
        let (record_area, frames) = sample_layout();
        let out = seal_segment_v1_from_record_area(
            7,
            3,
            11,
            SegmentId([0xA5; 16]),
            1_700_000_000_000_000_000,
            1_700_000_000_000_000_999,
            &record_area,
            &frames,
        )
        .unwrap();

        // Decodes cleanly and the decoded shape matches the builder output.
        let (header, toc_h, entries, footer) = decode_segment_v1(&out.bytes).unwrap();
        assert_eq!(header.segment_seq, 11);
        assert_eq!(header.epoch, 3);
        assert_eq!(header.shard_id, 7);
        assert_eq!(footer.sealed_at_unix_ns, 1_700_000_000_000_000_999);
        assert_eq!(entries.len(), 3);
        assert_eq!(toc_h.entry_count, 3);
        assert!(is_sorted_toc(&entries));

        // Offsets/lengths line up exactly: header | record | toc | footer.
        assert_eq!(footer.record_area_offset, HDR);
        assert_eq!(footer.record_area_len, 120);
        assert_eq!(footer.toc_offset, HDR + 120);
        assert_eq!(footer.toc_offset, footer.record_area_offset + footer.record_area_len);
        assert_eq!(footer.file_len, out.bytes.len() as u64);
        assert_eq!(
            footer.file_len,
            HDR + footer.record_area_len + footer.toc_len + SEGMENT_FOOTER_LEN as u64
        );

        // Footer bounds reflect the *sorted* TOC (min = first, max = last).
        assert_eq!((footer.min_stream_hash, footer.min_seq), (1, 1));
        assert_eq!((footer.max_stream_hash, footer.max_seq), (9, 1));

        // Sorted TOC order and per-entry logical file offset (= header_len + record_off).
        assert_eq!((entries[0].stream_hash, entries[0].seq), (1, 1));
        assert_eq!((entries[1].stream_hash, entries[1].seq), (1, 2));
        assert_eq!((entries[2].stream_hash, entries[2].seq), (9, 1));
        assert_eq!(entries[0].file_offset as u64, HDR + 80); // (1,1) stored at record_off 80
        assert_eq!(entries[1].file_offset as u64, HDR + 40); // (1,2) stored at record_off 40
        assert_eq!(entries[2].file_offset as u64, HDR); //      (9,1) stored at record_off 0

        // `crc_tables_len` embedded in the on-disk TOC header must equal the builder's
        // own count (record CRC table + TOC CRC table, 4 bytes each).
        assert_eq!(toc_h.crc_tables_len, out.toc_header.crc_tables_len);
        assert_eq!(
            toc_h.crc_tables_len,
            (out.record_crc32c_table.len() + out.toc_crc32c_table.len()) as u64 * 4
        );

        // The Phase-5 trailer index must be locatable and decode consistently — this only
        // works when `crc_tables_len` (and thus the extension offset) is correct.
        let toc_area = &out.bytes[footer.toc_offset as usize..(footer.toc_offset + footer.toc_len) as usize];
        let trailer = decode_trailer_index_v1(toc_area, &toc_h).unwrap().unwrap();
        assert_eq!(trailer.toc_by_offset.len(), 3);
        assert_eq!(trailer.toc_sorted_idx.len(), 3);
        assert_eq!(trailer.blocks.len(), 1);
    }

    #[test]
    fn seal_uncompressed_rejects_frame_past_record_area() {
        // Single frame claims 50 bytes but the record area is only 40 — the frame end
        // (50) exceeds the record area length.
        let err =
            seal_segment_v1_from_record_area(0, 1, 1, SegmentId([0u8; 16]), 1, 2, &[0u8; 40], &[frame(1, 1, 0, 50)])
                .unwrap_err();
        assert!(matches!(err, SegmentError::LengthOutOfRange { .. }), "got {err:?}");
    }

    #[test]
    fn seal_uncompressed_rejects_non_covering_frames() {
        // Frames cover only 80 of the 100 record-area bytes → not fully covered.
        let err = seal_segment_v1_from_record_area(
            0,
            1,
            1,
            SegmentId([0u8; 16]),
            1,
            2,
            &[0u8; 100],
            &[frame(1, 1, 0, 40), frame(1, 2, 40, 40)],
        )
        .unwrap_err();
        assert!(matches!(err, SegmentError::LengthOutOfRange { .. }), "got {err:?}");
    }

    /// With `record_block_codec == NONE`, the codec entry point must delegate byte-for-byte
    /// to the uncompressed sealer. If the dispatch comparison is inverted the block path
    /// runs instead and produces a differently-structured (4KiB-padded) segment.
    #[test]
    fn seal_block_codec_none_matches_uncompressed_seal() {
        let (record_area, frames) = sample_layout();
        let direct =
            seal_segment_v1_from_record_area(2, 4, 6, SegmentId([0x11; 16]), 10, 20, &record_area, &frames).unwrap();
        let via_codec = seal_segment_v1_from_record_area_with_block_codec(
            2,
            4,
            6,
            SegmentId([0x11; 16]),
            10,
            20,
            RECORD_BLOCK_CODEC_NONE_V1,
            &record_area,
            &frames,
        )
        .unwrap();
        assert_eq!(via_codec.bytes, direct.bytes);
    }

    /// Full round-trip for the LZ4 block-codec path. Beyond the shared structural
    /// invariants, this pins the Phase-9 4KiB alignment (footer padding), that the
    /// trailer records the LZ4 codec, and that logical TOC offsets survive block
    /// compression.
    #[test]
    fn seal_block_codec_lz4_roundtrip_preserves_invariants() {
        let (record_area, frames) = sample_layout();
        let out = seal_segment_v1_from_record_area_with_block_codec(
            7,
            3,
            11,
            SegmentId([0x5A; 16]),
            1_700_000_000_000_000_000,
            1_700_000_000_000_000_999,
            RECORD_BLOCK_CODEC_LZ4_V1,
            &record_area,
            &frames,
        )
        .unwrap();

        // Phase-9: the whole file is 4KiB-aligned.
        assert_eq!(out.bytes.len() % 4096, 0);

        let (header, toc_h, entries, footer) = decode_segment_v1(&out.bytes).unwrap();
        assert_eq!(header.segment_seq, 11);
        assert_eq!(footer.sealed_at_unix_ns, 1_700_000_000_000_000_999);
        assert_eq!(entries.len(), 3);
        assert!(is_sorted_toc(&entries));

        // Offsets/lengths line up (record area here is the *physical*, compressed area).
        assert_eq!(footer.record_area_offset, HDR);
        assert_eq!(footer.toc_offset, footer.record_area_offset + footer.record_area_len);
        assert_eq!(footer.file_len, out.bytes.len() as u64);
        assert_eq!(
            footer.file_len,
            HDR + footer.record_area_len + footer.toc_len + SEGMENT_FOOTER_LEN as u64
        );

        // Bounds reflect the sorted TOC.
        assert_eq!((footer.min_stream_hash, footer.min_seq), (1, 1));
        assert_eq!((footer.max_stream_hash, footer.max_seq), (9, 1));

        // Logical TOC file offsets are header_len + uncompressed record_off, unchanged by
        // block compression.
        assert_eq!(entries[0].file_offset as u64, HDR + 80);
        assert_eq!(entries[1].file_offset as u64, HDR + 40);
        assert_eq!(entries[2].file_offset as u64, HDR);

        assert_eq!(toc_h.crc_tables_len, out.toc_header.crc_tables_len);

        // Trailer index decodes and records the LZ4 codec.
        let toc_area = &out.bytes[footer.toc_offset as usize..(footer.toc_offset + footer.toc_len) as usize];
        let trailer = decode_trailer_index_v1(toc_area, &toc_h).unwrap().unwrap();
        assert_eq!(trailer.toc_by_offset.len(), 3);
        assert_eq!(trailer.blocks.len(), 1);
        assert_eq!(trailer.blocks[0].codec, RECORD_BLOCK_CODEC_LZ4_V1);
    }

    #[test]
    fn seal_block_codec_lz4_rejects_non_covering_frames() {
        let err = seal_segment_v1_from_record_area_with_block_codec(
            0,
            1,
            1,
            SegmentId([0u8; 16]),
            1,
            2,
            RECORD_BLOCK_CODEC_LZ4_V1,
            &[0u8; 100],
            &[frame(1, 1, 0, 40), frame(1, 2, 40, 40)],
        )
        .unwrap_err();
        assert!(matches!(err, SegmentError::LengthOutOfRange { .. }), "got {err:?}");
    }
}
