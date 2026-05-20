// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Segment builder — assembles header + frames + TOC + trailer + footer into a sealed `.ccxseg` byte stream.

use blake3::Hasher as Blake3;

use crate::footer::encode_segment_footer_v1;
use crate::frame::encode_frame_v1;
use crate::header::encode_segment_header_v1;
use crate::toc::{compute_toc_payload_hash, encode_toc_payload_v1, encode_toc_payload_v1_with_hash};
use crate::trailer::{
    build_record_blocks_and_trailer_index_parts_v1, encode_trailer_index_v1, encode_trailer_index_v1_from_parts,
};
use crate::types::FrameMetaTmp;
use crate::util::{block_crc32c, is_sorted_toc};
use crate::{
    FrameInput, Result, SegmentBuildOutput, SegmentError, SegmentFooterV1, SegmentHeaderV1, SegmentId, TocEntryV1,
    TocHeaderV1, DEFAULT_RECORD_BLOCK_SIZE, DEFAULT_TOC_BLOCK_SIZE, RECORD_BLOCK_CODEC_NONE_V1, SEGMENT_FOOTER_LEN,
    SEGMENT_HEADER_LEN, TOC_ENTRY_LEN, TOC_HEADER_LEN,
};

pub fn build_segment_v1(
    shard_id: u32,
    epoch: u64,
    segment_seq: u64,
    segment_id: SegmentId,
    created_at_unix_ns: u64,
    sealed_at_unix_ns: u64,
    frames: &[FrameInput<'_>],
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

    let mut record_area: Vec<u8> = Vec::new();
    let mut toc_entries: Vec<TocEntryV1> = Vec::with_capacity(frames.len());
    let mut frames_by_offset: Vec<FrameMetaTmp> = Vec::with_capacity(frames.len());

    for f in frames {
        let record_off = record_area.len() as u64;
        if record_off > u32::MAX as u64 {
            return Err(SegmentError::LengthOutOfRange {
                msg: "record offset exceeds u32".to_string(),
            });
        }

        let file_offset = (SEGMENT_HEADER_LEN + record_area.len()) as u64;
        if file_offset > u32::MAX as u64 {
            return Err(SegmentError::LengthOutOfRange {
                msg: "file offset exceeds u32".to_string(),
            });
        }

        let frame_bytes = encode_frame_v1(f.header_bytes, f.payload_bytes)?;
        if frame_bytes.len() > u32::MAX as usize {
            return Err(SegmentError::LengthOutOfRange {
                msg: "frame too large".to_string(),
            });
        }
        let frame_len = frame_bytes.len() as u32;
        let payload_len = f.payload_bytes.len() as u32;

        let event_id_hash = blake3::hash(f.event_id.as_bytes());
        let mut event_id_hash16 = [0u8; 16];
        event_id_hash16.copy_from_slice(&event_id_hash.as_bytes()[0..16]);

        let mut header_digest8 = [0u8; 8];
        header_digest8.copy_from_slice(&f.header_hash[0..8]);
        let mut payload_digest8 = [0u8; 8];
        payload_digest8.copy_from_slice(&f.payload_hash[0..8]);

        toc_entries.push(TocEntryV1 {
            stream_hash: f.stream_hash,
            seq: f.seq,
            file_offset: file_offset as u32,
            frame_len,
            payload_len,
            flags: 0,
            event_id_hash16,
            header_digest8,
            payload_digest8,
        });

        frames_by_offset.push(FrameMetaTmp {
            stream_hash: f.stream_hash,
            seq: f.seq,
            event_id_hash16,
            header_digest8,
            payload_digest8,
            record_off: record_off as u32,
            frame_len,
        });

        record_area.extend_from_slice(&frame_bytes);
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
    let trailer_ext = encode_trailer_index_v1(&record_area, &frames_by_offset)?;
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

    // Final file assembly.
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

#[allow(clippy::too_many_arguments)]
pub fn build_segment_v1_with_block_codec(
    shard_id: u32,
    epoch: u64,
    segment_seq: u64,
    segment_id: SegmentId,
    created_at_unix_ns: u64,
    sealed_at_unix_ns: u64,
    record_block_codec: u32,
    frames: &[FrameInput<'_>],
) -> Result<SegmentBuildOutput> {
    if record_block_codec == RECORD_BLOCK_CODEC_NONE_V1 {
        return build_segment_v1(
            shard_id,
            epoch,
            segment_seq,
            segment_id,
            created_at_unix_ns,
            sealed_at_unix_ns,
            frames,
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

    // Build uncompressed record area + canonical v1 TOC entries (sorted by stream_hash, seq).
    let mut record_area_uncompressed: Vec<u8> = Vec::new();
    let mut toc_entries: Vec<TocEntryV1> = Vec::with_capacity(frames.len());
    let mut frames_by_offset: Vec<FrameMetaTmp> = Vec::with_capacity(frames.len());

    for f in frames {
        let record_off = record_area_uncompressed.len() as u64;
        if record_off > u32::MAX as u64 {
            return Err(SegmentError::LengthOutOfRange {
                msg: "record offset exceeds u32".to_string(),
            });
        }

        // IMPORTANT: TocEntryV1.file_offset is a *logical* offset into the uncompressed record
        // stream (header_len + record_off). Reads translate logical offsets via the block index.
        let file_offset = (SEGMENT_HEADER_LEN as u64)
            .checked_add(record_area_uncompressed.len() as u64)
            .ok_or(SegmentError::BufferTooSmall)?;
        if file_offset > u32::MAX as u64 {
            return Err(SegmentError::LengthOutOfRange {
                msg: "file offset exceeds u32".to_string(),
            });
        }

        let frame_bytes = encode_frame_v1(f.header_bytes, f.payload_bytes)?;
        if frame_bytes.len() > u32::MAX as usize {
            return Err(SegmentError::LengthOutOfRange {
                msg: "frame too large".to_string(),
            });
        }
        let frame_len = frame_bytes.len() as u32;
        let payload_len = f.payload_bytes.len() as u32;

        let event_id_hash = blake3::hash(f.event_id.as_bytes());
        let mut event_id_hash16 = [0u8; 16];
        event_id_hash16.copy_from_slice(&event_id_hash.as_bytes()[0..16]);

        let mut header_digest8 = [0u8; 8];
        header_digest8.copy_from_slice(&f.header_hash[0..8]);
        let mut payload_digest8 = [0u8; 8];
        payload_digest8.copy_from_slice(&f.payload_hash[0..8]);

        toc_entries.push(TocEntryV1 {
            stream_hash: f.stream_hash,
            seq: f.seq,
            file_offset: file_offset as u32,
            frame_len,
            payload_len,
            flags: 0,
            event_id_hash16,
            header_digest8,
            payload_digest8,
        });

        frames_by_offset.push(FrameMetaTmp {
            stream_hash: f.stream_hash,
            seq: f.seq,
            event_id_hash16,
            header_digest8,
            payload_digest8,
            record_off: record_off as u32,
            frame_len,
        });

        record_area_uncompressed.extend_from_slice(&frame_bytes);
    }

    toc_entries.sort_by(|a, b| match a.stream_hash.cmp(&b.stream_hash) {
        std::cmp::Ordering::Equal => a.seq.cmp(&b.seq),
        other => other,
    });
    if !is_sorted_toc(&toc_entries) {
        return Err(SegmentError::TocNotSorted);
    }

    // Build compressed physical record bytes + Phase 5 trailer index.
    let crate::types::RecordBlocksAndTrailerIndexPartsV1 {
        record_area,
        blocks,
        toc_by_offset,
        toc_sorted_idx,
    } = build_record_blocks_and_trailer_index_parts_v1(
        &record_area_uncompressed,
        &frames_by_offset,
        record_block_codec,
    )?;
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
    let aligned = crate::util::align_up(want, 4096);
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
    use crate::footer::decode_segment_footer_v1;
    use crate::toc::decode_toc_header_v1;
    use crate::trailer::decode_trailer_index_v1;
    use crate::util::is_sorted_toc;
    use crate::{
        BLOOM_BYTES_PER_BLOCK_V1, RECORD_BLOCK_CODEC_LZ4_V1, RECORD_BLOCK_UNCOMPRESSED_MAX_LEN_V1, TOC_HEADER_LEN,
    };
    use corecrux_frame::{compute_header_hash, compute_payload_hash};

    #[test]
    fn segment_build_and_decode() {
        let shard_id = 0;
        let epoch = 1;
        let segment_seq = 1;
        let segment_id = SegmentId([7u8; 16]);

        let payload_a = b"hello";
        let payload_hash_a = *blake3::hash(payload_a).as_bytes();
        let header_hash_a = *blake3::hash(b"hdr-a").as_bytes();

        let payload_b = b"world";
        let payload_hash_b = *blake3::hash(payload_b).as_bytes();
        let header_hash_b = *blake3::hash(b"hdr-b").as_bytes();

        let out = build_segment_v1(
            shard_id,
            epoch,
            segment_seq,
            segment_id,
            1_700_000_000_000_000_000,
            1_700_000_000_000_000_001,
            &[
                FrameInput {
                    stream_hash: 10,
                    seq: 2,
                    event_id: "evt-a",
                    header_hash: header_hash_a,
                    payload_hash: payload_hash_a,
                    header_bytes: b"hdr-a",
                    payload_bytes: payload_a,
                },
                FrameInput {
                    stream_hash: 10,
                    seq: 1,
                    event_id: "evt-b",
                    header_hash: header_hash_b,
                    payload_hash: payload_hash_b,
                    header_bytes: b"hdr-b",
                    payload_bytes: payload_b,
                },
            ],
        )
        .unwrap();

        let (h, toc_h, entries, f) = decode_segment_v1(&out.bytes).unwrap();
        assert_eq!(h.segment_seq, segment_seq);
        assert_eq!(f.segment_seq, segment_seq);
        assert_eq!(toc_h.entry_count, 2);
        assert_eq!(entries.len(), 2);
        assert!(is_sorted_toc(&entries));

        // Phase 5 trailer index must decode and be consistent with the TOC.
        let toc_off = f.toc_offset as usize;
        let toc_len = f.toc_len as usize;
        let toc_area = &out.bytes[toc_off..toc_off + toc_len];
        let trailer = decode_trailer_index_v1(toc_area, &toc_h).unwrap().unwrap();
        assert_eq!(trailer.toc_by_offset.len(), entries.len());
        assert_eq!(trailer.toc_sorted_idx.len(), entries.len());
        assert_eq!(trailer.blocks.len(), 1);
        assert_eq!(
            trailer.record_block_uncompressed_max_len,
            RECORD_BLOCK_UNCOMPRESSED_MAX_LEN_V1
        );
        assert_eq!(trailer.bloom_bytes_per_block as usize, BLOOM_BYTES_PER_BLOCK_V1);

        use std::collections::HashMap;
        let mut by_key: HashMap<(u64, u64), u32> = HashMap::new();
        for e in &entries {
            by_key.insert((e.stream_hash, e.seq), e.file_offset);
        }
        for e in &trailer.toc_by_offset {
            let block = &trailer.blocks[e.block_id as usize];
            let file_off = block.file_offset as u32 + e.in_block_offset;
            assert_eq!(Some(&file_off), by_key.get(&(e.stream_hash, e.seq)));
        }

        // toc_sorted_idx must order toc_by_offset entries by (stream_hash, seq).
        let mut last = (0u64, 0u64);
        for &idx in &trailer.toc_sorted_idx {
            let e = trailer.toc_by_offset[idx as usize];
            assert!((e.stream_hash, e.seq) >= last);
            last = (e.stream_hash, e.seq);
        }
    }

    #[test]
    fn build_segment_empty_frames() {
        let out = build_segment_v1(0, 1, 1, SegmentId([0u8; 16]), 1, 2, &[]).unwrap();

        let (hdr, toc_h, entries, footer) = decode_segment_v1(&out.bytes).unwrap();
        assert_eq!(hdr.segment_seq, 1);
        assert_eq!(toc_h.entry_count, 0);
        assert!(entries.is_empty());
        assert_eq!(footer.min_stream_hash, 0);
        assert_eq!(footer.max_stream_hash, 0);
    }

    #[test]
    fn build_segment_with_lz4_codec_roundtrips() {
        let payload_a = b"hello world compressed";
        let payload_hash_a = compute_payload_hash(payload_a);
        let header_hash_a = compute_header_hash(b"hdr-a");

        let out = build_segment_v1_with_block_codec(
            0,
            1,
            1,
            SegmentId([5u8; 16]),
            1,
            2,
            RECORD_BLOCK_CODEC_LZ4_V1,
            &[FrameInput {
                stream_hash: 10,
                seq: 1,
                event_id: "evt-lz4",
                header_hash: header_hash_a,
                payload_hash: payload_hash_a,
                header_bytes: b"hdr-a",
                payload_bytes: payload_a,
            }],
        )
        .unwrap();

        // File length should be 4KiB aligned (Phase 9 padding)
        assert_eq!(out.bytes.len() % 4096, 0);

        // Footer should decode
        let footer_bytes = &out.bytes[out.bytes.len() - SEGMENT_FOOTER_LEN..];
        let footer = decode_segment_footer_v1(footer_bytes).unwrap();
        assert_eq!(footer.toc_entry_count, 1);
        assert_eq!(footer.flags & 0x1, 1); // SEALED

        // Trailer index should decode with LZ4 codec
        let toc_off = footer.toc_offset as usize;
        let toc_len = footer.toc_len as usize;
        let toc_area = &out.bytes[toc_off..toc_off + toc_len];
        let toc_payload_len_raw = u64::from_le_bytes(toc_area[40..48].try_into().unwrap()) as usize;
        let toc_payload = &toc_area[..toc_payload_len_raw];
        let toc_header = decode_toc_header_v1(&toc_payload[..TOC_HEADER_LEN]).unwrap();
        let trailer = decode_trailer_index_v1(toc_area, &toc_header)
            .unwrap()
            .expect("trailer should exist");
        assert_eq!(trailer.blocks.len(), 1);
        assert_eq!(trailer.blocks[0].codec, RECORD_BLOCK_CODEC_LZ4_V1);
        // Note: LZ4 may expand small data, so we do not assert compressed <= uncompressed.
        assert!(trailer.blocks[0].uncompressed_len > 0);
    }

    // --- Fixture tests ---

    fn build_minimal_segment_bytes() -> Vec<u8> {
        use corecrux_frame::canonical_header_bytes_v1;

        let shard_id = 0;
        let epoch = 1;
        let segment_seq = 1;
        let segment_id = SegmentId([1u8; 16]);
        let created_at = 1_700_000_000_000_000_000;
        let sealed_at = created_at + 1;

        let make_frame = |seq: u64, event_id: &str, payload: &[u8]| -> (Vec<u8>, [u8; 32], [u8; 32]) {
            let payload_hash = compute_payload_hash(payload);
            let canonical = corecrux_frame::CanonicalHeaderV1 {
                tenant_id: "tenant-a".to_string(),
                stream_id: "stream-1".to_string(),
                stream_type: "answers".to_string(),
                seq,
                event_id: event_id.to_string(),
                occurred_at: "2026-02-07T00:00:00Z".to_string(),
                ingested_at: "2026-02-07T00:00:00Z".to_string(),
                event_type: "test.event".to_string(),
                content_type: "application/octet-stream".to_string(),
                payload_len: payload.len() as u32,
                payload_hash,
            };
            let canonical_bytes = canonical_header_bytes_v1(&canonical);
            let header_hash = compute_header_hash(&canonical_bytes);
            let mut header_bytes = Vec::with_capacity(canonical_bytes.len() + 32);
            header_bytes.extend_from_slice(&canonical_bytes);
            header_bytes.extend_from_slice(&header_hash);
            (header_bytes, payload_hash, header_hash)
        };

        let stream_hash = 0x0102_0304_0506_0708u64;

        let (hdr1, payload_hash1, header_hash1) = make_frame(1, "evt-1", b"hello");
        let (hdr2, payload_hash2, header_hash2) = make_frame(2, "evt-2", b"world");

        let out = build_segment_v1(
            shard_id,
            epoch,
            segment_seq,
            segment_id,
            created_at,
            sealed_at,
            &[
                FrameInput {
                    stream_hash,
                    seq: 1,
                    event_id: "evt-1",
                    header_hash: header_hash1,
                    payload_hash: payload_hash1,
                    header_bytes: &hdr1,
                    payload_bytes: b"hello",
                },
                FrameInput {
                    stream_hash,
                    seq: 2,
                    event_id: "evt-2",
                    header_hash: header_hash2,
                    payload_hash: payload_hash2,
                    header_bytes: &hdr2,
                    payload_bytes: b"world",
                },
            ],
        )
        .unwrap();

        out.bytes
    }

    #[test]
    fn minimal_fixture_is_stable() {
        let bytes = build_minimal_segment_bytes();
        let expected = include_bytes!("../../../tests/fixtures_segments/minimal/minimal.ccxseg");
        assert_eq!(bytes, expected);
    }

    #[test]
    #[ignore]
    fn write_minimal_fixture() {
        let bytes = build_minimal_segment_bytes();
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures_segments/minimal/minimal.ccxseg")
            .canonicalize()
            .unwrap_or_else(|_| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../tests/fixtures_segments/minimal/minimal.ccxseg")
            });
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, bytes).unwrap();
    }
}
