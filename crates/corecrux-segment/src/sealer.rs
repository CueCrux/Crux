// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use blake3::Hasher as Blake3;

use crate::footer::encode_segment_footer_v1;
use crate::header::encode_segment_header_v1;
use crate::toc::{compute_toc_payload_hash, encode_toc_payload_v1, encode_toc_payload_v1_with_hash};
use crate::trailer::{
    build_record_blocks_and_trailer_index_parts_v1, encode_trailer_index_v1,
    encode_trailer_index_v1_from_parts,
};
use crate::types::FrameMetaTmp;
use crate::util::{align_up, block_crc32c, is_sorted_toc};
use crate::{
    FrameMetaV1, Result, SegmentBuildOutput, SegmentError, SegmentFooterV1, SegmentHeaderV1,
    SegmentId, TocEntryV1, TocHeaderV1,
    DEFAULT_RECORD_BLOCK_SIZE, DEFAULT_TOC_BLOCK_SIZE, RECORD_BLOCK_CODEC_NONE_V1,
    SEGMENT_FOOTER_LEN, SEGMENT_HEADER_LEN, TOC_ENTRY_LEN, TOC_HEADER_LEN,
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
}
