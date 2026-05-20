// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! v1 trailer-index codec — per-block bloom + sorted stream-range tables for tail-locator + range-scan queries.

use crate::block::{
    decode_block_meta_v1, decode_toc_by_offset_entry_v1, encode_block_meta_v1, encode_toc_by_offset_entry_v1,
};
use crate::bloom::bloom_insert_stream_hash_v1;
use crate::types::{FrameMetaTmp, RecordBlocksAndTrailerIndexPartsV1};
use crate::util::align_up;
use crate::{
    BlockMetaV1, Result, SegmentError, TocByOffsetEntryV1, TocHeaderV1, TrailerIndexV1, BLOCK_META_V1_LEN,
    BLOOM_BYTES_PER_BLOCK_V1, BLOOM_HASH_K_V1, RECORD_BLOCK_CODEC_LZ4_V1, RECORD_BLOCK_CODEC_NONE_V1,
    RECORD_BLOCK_UNCOMPRESSED_MAX_LEN_V1, SEGMENT_HEADER_LEN, TOC_BY_OFFSET_ENTRY_V1_LEN, TRAILER_MAGIC_BLK1,
    TRAILER_MAGIC_TBO1, TRAILER_MAGIC_TSI1, TRAILER_SECTION_HEADER_LEN_V1,
};

#[allow(clippy::unwrap_used)] // SAFETY: all try_into().unwrap() are on fixed-size slices after bounds checks
pub fn decode_trailer_index_v1(toc_area: &[u8], toc_header: &TocHeaderV1) -> Result<Option<TrailerIndexV1>> {
    let payload_len = toc_header.toc_payload_len as usize;
    let crc_tables_len = toc_header.crc_tables_len as usize;
    let ext_off = payload_len
        .checked_add(crc_tables_len)
        .ok_or(SegmentError::BufferTooSmall)?;
    if ext_off > toc_area.len() {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "toc header extension offset out of bounds".to_string(),
        });
    }
    let ext = &toc_area[ext_off..];
    if ext.is_empty() {
        return Ok(None);
    }

    let mut cursor = 0usize;

    let mut blk_section: Option<(u32, u32, u32, Vec<BlockMetaV1>)> = None;
    let mut tbo_section: Option<Vec<TocByOffsetEntryV1>> = None;
    let mut tsi_section: Option<Vec<u32>> = None;

    while cursor < ext.len() {
        // Phase 9: allow trailing zero padding in the TOC extension area so the overall segment
        // file length can be 4KiB-aligned for GPUDirect Storage (O_DIRECT) without changing the
        // footer layout. Padding bytes must be all zero.
        if ext[cursor..].iter().all(|&b| b == 0) {
            break;
        }
        if ext.len() - cursor < TRAILER_SECTION_HEADER_LEN_V1 {
            return Err(SegmentError::TrailerSectionInvalid {
                msg: "trailer section header truncated".to_string(),
            });
        }
        let hdr = &ext[cursor..cursor + TRAILER_SECTION_HEADER_LEN_V1];
        let magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
        let version = u16::from_le_bytes(hdr[4..6].try_into().unwrap());
        let header_len = u16::from_le_bytes(hdr[6..8].try_into().unwrap()) as usize;
        if version != 1 || header_len != TRAILER_SECTION_HEADER_LEN_V1 {
            return Err(SegmentError::TrailerSectionInvalid {
                msg: format!("unsupported trailer section header (magic={magic:#x})"),
            });
        }
        let payload_len = u32::from_le_bytes(hdr[8..12].try_into().unwrap()) as usize;
        let expected_crc = u32::from_le_bytes(hdr[12..16].try_into().unwrap());
        cursor += header_len;
        let end = cursor.checked_add(payload_len).ok_or(SegmentError::BufferTooSmall)?;
        if end > ext.len() {
            return Err(SegmentError::TrailerSectionInvalid {
                msg: "trailer section payload out of bounds".to_string(),
            });
        }
        let payload = &ext[cursor..end];
        let actual_crc = crc32c::crc32c(payload);
        if actual_crc != expected_crc {
            return Err(SegmentError::TrailerSectionInvalid {
                msg: format!("trailer section crc mismatch (magic={magic:#x})"),
            });
        }
        cursor = end;

        match magic {
            TRAILER_MAGIC_BLK1 => {
                blk_section = Some(decode_blk1_payload(payload)?);
            }
            TRAILER_MAGIC_TBO1 => {
                tbo_section = Some(decode_tbo1_payload(payload)?);
            }
            TRAILER_MAGIC_TSI1 => {
                tsi_section = Some(decode_tsi1_payload(payload)?);
            }
            _ => {
                // Unknown section; ignore for forward compatibility.
            }
        }
    }

    let Some((record_block_uncompressed_max_len, bloom_bytes_per_block, bloom_hash_k, blocks)) = blk_section else {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "missing BLK1 section".to_string(),
        });
    };
    let Some(toc_by_offset) = tbo_section else {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "missing TBO1 section".to_string(),
        });
    };
    let Some(toc_sorted_idx) = tsi_section else {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "missing TSI1 section".to_string(),
        });
    };

    if toc_sorted_idx.len() != toc_by_offset.len() {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "toc_sorted_idx length does not match toc_by_offset length".to_string(),
        });
    }
    for &idx in &toc_sorted_idx {
        if idx as usize >= toc_by_offset.len() {
            return Err(SegmentError::TrailerSectionInvalid {
                msg: "toc_sorted_idx contains out-of-bounds index".to_string(),
            });
        }
    }

    Ok(Some(TrailerIndexV1 {
        record_block_uncompressed_max_len,
        bloom_bytes_per_block,
        bloom_hash_k,
        blocks,
        toc_by_offset,
        toc_sorted_idx,
    }))
}

pub(crate) fn encode_trailer_index_v1(record_area: &[u8], frames: &[FrameMetaTmp]) -> Result<Vec<u8>> {
    let mut block_starts: Vec<usize> = Vec::new();
    let mut block_lens: Vec<usize> = Vec::new();
    let mut block_blooms: Vec<[u8; BLOOM_BYTES_PER_BLOCK_V1]> = Vec::new();

    let mut frame_block_id: Vec<u32> = vec![0u32; frames.len()];

    let max_len = RECORD_BLOCK_UNCOMPRESSED_MAX_LEN_V1 as usize;
    let mut cur_start: Option<usize> = None;
    let mut cur_len: usize = 0;
    let mut cur_bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];

    for (i, f) in frames.iter().enumerate() {
        let flen = f.frame_len as usize;
        if cur_len > 0 && cur_len.saturating_add(flen) > max_len {
            // Finalize current block.
            block_starts.push(cur_start.unwrap_or(0));
            block_lens.push(cur_len);
            block_blooms.push(cur_bloom);
            cur_start = None;
            cur_len = 0;
            cur_bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];
        }
        if cur_len == 0 {
            cur_start = Some(f.record_off as usize);
        }
        let block_id = block_starts.len() as u32;
        frame_block_id[i] = block_id;
        bloom_insert_stream_hash_v1(&mut cur_bloom, BLOOM_HASH_K_V1, f.stream_hash);
        cur_len = cur_len.saturating_add(flen);
    }
    if cur_len > 0 {
        block_starts.push(cur_start.unwrap_or(0));
        block_lens.push(cur_len);
        block_blooms.push(cur_bloom);
    }

    // Encode BLK1.
    let mut blocks: Vec<BlockMetaV1> = Vec::with_capacity(block_starts.len());
    for (i, (&start, &len)) in block_starts.iter().zip(block_lens.iter()).enumerate() {
        let file_offset = (SEGMENT_HEADER_LEN + start) as u64;
        let end = start.checked_add(len).ok_or(SegmentError::BufferTooSmall)?;
        if end > record_area.len() {
            return Err(SegmentError::TrailerSectionInvalid {
                msg: "block spans past record area".to_string(),
            });
        }
        let bytes = &record_area[start..end];
        let crc32c = crc32c::crc32c(bytes);
        blocks.push(BlockMetaV1 {
            block_id: i as u32,
            codec: 0,
            file_offset,
            compressed_len: len as u32,
            physical_len: 0, // legacy: encode as 0 (meaning "same as compressed_len")
            uncompressed_len: len as u32,
            crc32c,
            bloom: block_blooms[i],
        });
    }

    let blk_payload = encode_blk1_payload(&blocks)?;
    let blk_section = encode_trailer_section_v1(TRAILER_MAGIC_BLK1, &blk_payload);

    // Encode TBO1.
    let mut toc_by_offset: Vec<TocByOffsetEntryV1> = Vec::with_capacity(frames.len());
    for (i, f) in frames.iter().enumerate() {
        let bid = frame_block_id[i] as usize;
        let block_start = block_starts.get(bid).copied().unwrap_or(0) as u32;
        let in_block_offset = f.record_off.saturating_sub(block_start);
        toc_by_offset.push(TocByOffsetEntryV1 {
            stream_hash: f.stream_hash,
            seq: f.seq,
            block_id: frame_block_id[i],
            in_block_offset,
            frame_len: f.frame_len,
            flags: 0,
            event_id_hash16: f.event_id_hash16,
            header_digest8: f.header_digest8,
            payload_digest8: f.payload_digest8,
        });
    }

    let tbo_payload = encode_tbo1_payload(&toc_by_offset)?;
    let tbo_section = encode_trailer_section_v1(TRAILER_MAGIC_TBO1, &tbo_payload);

    // Encode TSI1.
    let mut sorted_idx: Vec<u32> = (0..toc_by_offset.len() as u32).collect();
    sorted_idx.sort_by(|&a, &b| {
        let ea = toc_by_offset[a as usize];
        let eb = toc_by_offset[b as usize];
        (ea.stream_hash, ea.seq, ea.block_id, ea.in_block_offset).cmp(&(
            eb.stream_hash,
            eb.seq,
            eb.block_id,
            eb.in_block_offset,
        ))
    });

    let tsi_payload = encode_tsi1_payload(&sorted_idx)?;
    let tsi_section = encode_trailer_section_v1(TRAILER_MAGIC_TSI1, &tsi_payload);

    let mut out = Vec::with_capacity(blk_section.len() + tbo_section.len() + tsi_section.len());
    out.extend_from_slice(&blk_section);
    out.extend_from_slice(&tbo_section);
    out.extend_from_slice(&tsi_section);
    Ok(out)
}

pub(crate) fn build_record_blocks_and_trailer_index_parts_v1(
    record_area_uncompressed: &[u8],
    frames: &[FrameMetaTmp],
    record_block_codec: u32,
) -> Result<RecordBlocksAndTrailerIndexPartsV1> {
    if record_block_codec != RECORD_BLOCK_CODEC_NONE_V1 && record_block_codec != RECORD_BLOCK_CODEC_LZ4_V1 {
        return Err(SegmentError::LengthOutOfRange {
            msg: format!("unsupported record_block_codec {record_block_codec}"),
        });
    }

    let mut block_starts: Vec<usize> = Vec::new();
    let mut block_lens: Vec<usize> = Vec::new();
    let mut block_blooms: Vec<[u8; BLOOM_BYTES_PER_BLOCK_V1]> = Vec::new();

    let mut frame_block_id: Vec<u32> = vec![0u32; frames.len()];

    let max_len = RECORD_BLOCK_UNCOMPRESSED_MAX_LEN_V1 as usize;
    let mut cur_start: Option<usize> = None;
    let mut cur_len: usize = 0;
    let mut cur_bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];

    for (i, f) in frames.iter().enumerate() {
        let flen = f.frame_len as usize;
        if cur_len > 0 && cur_len.saturating_add(flen) > max_len {
            // Finalize current block.
            block_starts.push(cur_start.unwrap_or(0));
            block_lens.push(cur_len);
            block_blooms.push(cur_bloom);
            cur_start = None;
            cur_len = 0;
            cur_bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];
        }
        if cur_len == 0 {
            cur_start = Some(f.record_off as usize);
        }
        let block_id = block_starts.len() as u32;
        frame_block_id[i] = block_id;
        bloom_insert_stream_hash_v1(&mut cur_bloom, BLOOM_HASH_K_V1, f.stream_hash);
        cur_len = cur_len.saturating_add(flen);
    }
    if cur_len > 0 {
        block_starts.push(cur_start.unwrap_or(0));
        block_lens.push(cur_len);
        block_blooms.push(cur_bloom);
    }

    // Build physical record bytes and BLK1 metadata.
    let mut record_area: Vec<u8> = Vec::new();
    let mut blocks: Vec<BlockMetaV1> = Vec::with_capacity(block_starts.len());
    for (i, (&start, &len)) in block_starts.iter().zip(block_lens.iter()).enumerate() {
        let end = start.checked_add(len).ok_or(SegmentError::BufferTooSmall)?;
        if end > record_area_uncompressed.len() {
            return Err(SegmentError::TrailerSectionInvalid {
                msg: "block spans past uncompressed record area".to_string(),
            });
        }
        let uncompressed = &record_area_uncompressed[start..end];
        let crc32c = crc32c::crc32c(uncompressed);

        let (codec, compressed_bytes) = match record_block_codec {
            RECORD_BLOCK_CODEC_NONE_V1 => (RECORD_BLOCK_CODEC_NONE_V1, uncompressed.to_vec()),
            RECORD_BLOCK_CODEC_LZ4_V1 => (RECORD_BLOCK_CODEC_LZ4_V1, lz4_flex::block::compress(uncompressed)),
            _ => unreachable!("validated above"),
        };

        if compressed_bytes.len() > u32::MAX as usize {
            return Err(SegmentError::LengthOutOfRange {
                msg: "compressed block len exceeds u32".to_string(),
            });
        }
        if len > u32::MAX as usize {
            return Err(SegmentError::LengthOutOfRange {
                msg: "uncompressed block len exceeds u32".to_string(),
            });
        }

        // Phase 9: pad physical record bytes so each block begins on a 4KiB boundary (GPU-direct IO).
        let aligned = align_up(record_area.len(), 4096);
        if aligned != record_area.len() {
            record_area.resize(aligned, 0u8);
        }
        let file_offset = (SEGMENT_HEADER_LEN as u64)
            .checked_add(record_area.len() as u64)
            .ok_or(SegmentError::BufferTooSmall)?;

        record_area.extend_from_slice(&compressed_bytes);
        let physical_len = align_up(compressed_bytes.len(), 4096);
        if physical_len > u32::MAX as usize {
            return Err(SegmentError::LengthOutOfRange {
                msg: "physical block len exceeds u32".to_string(),
            });
        }
        if physical_len != compressed_bytes.len() {
            record_area.resize(record_area.len() + (physical_len - compressed_bytes.len()), 0u8);
        }

        blocks.push(BlockMetaV1 {
            block_id: i as u32,
            codec,
            file_offset,
            compressed_len: compressed_bytes.len() as u32,
            physical_len: physical_len as u32,
            uncompressed_len: len as u32,
            crc32c,
            bloom: block_blooms[i],
        });
    }

    // Build TBO1/TSI1.
    let mut toc_by_offset: Vec<TocByOffsetEntryV1> = Vec::with_capacity(frames.len());
    for (i, f) in frames.iter().enumerate() {
        let bid = frame_block_id[i] as usize;
        let block_start = block_starts.get(bid).copied().unwrap_or(0) as u32;
        let in_block_offset = f.record_off.saturating_sub(block_start);
        toc_by_offset.push(TocByOffsetEntryV1 {
            stream_hash: f.stream_hash,
            seq: f.seq,
            block_id: frame_block_id[i],
            in_block_offset,
            frame_len: f.frame_len,
            flags: 0,
            event_id_hash16: f.event_id_hash16,
            header_digest8: f.header_digest8,
            payload_digest8: f.payload_digest8,
        });
    }

    let mut toc_sorted_idx: Vec<u32> = (0..toc_by_offset.len() as u32).collect();
    toc_sorted_idx.sort_by(|&a, &b| {
        let ea = toc_by_offset[a as usize];
        let eb = toc_by_offset[b as usize];
        (ea.stream_hash, ea.seq, ea.block_id, ea.in_block_offset).cmp(&(
            eb.stream_hash,
            eb.seq,
            eb.block_id,
            eb.in_block_offset,
        ))
    });

    Ok(RecordBlocksAndTrailerIndexPartsV1 {
        record_area,
        blocks,
        toc_by_offset,
        toc_sorted_idx,
    })
}

pub(crate) fn encode_trailer_index_v1_from_parts(
    blocks: &[BlockMetaV1],
    toc_by_offset: &[TocByOffsetEntryV1],
    toc_sorted_idx: &[u32],
) -> Result<Vec<u8>> {
    let blk_payload = encode_blk1_payload(blocks)?;
    let blk_section = encode_trailer_section_v1(TRAILER_MAGIC_BLK1, &blk_payload);

    let tbo_payload = encode_tbo1_payload(toc_by_offset)?;
    let tbo_section = encode_trailer_section_v1(TRAILER_MAGIC_TBO1, &tbo_payload);

    let tsi_payload = encode_tsi1_payload(toc_sorted_idx)?;
    let tsi_section = encode_trailer_section_v1(TRAILER_MAGIC_TSI1, &tsi_payload);

    let mut out = Vec::with_capacity(blk_section.len() + tbo_section.len() + tsi_section.len());
    out.extend_from_slice(&blk_section);
    out.extend_from_slice(&tbo_section);
    out.extend_from_slice(&tsi_section);
    Ok(out)
}

pub(crate) fn encode_trailer_section_v1(magic: u32, payload: &[u8]) -> Vec<u8> {
    let mut hdr = [0u8; TRAILER_SECTION_HEADER_LEN_V1];
    hdr[0..4].copy_from_slice(&magic.to_le_bytes());
    hdr[4..6].copy_from_slice(&1u16.to_le_bytes()); // version
    hdr[6..8].copy_from_slice(&(TRAILER_SECTION_HEADER_LEN_V1 as u16).to_le_bytes());
    hdr[8..12].copy_from_slice(&(payload.len() as u32).to_le_bytes());
    let crc = crc32c::crc32c(payload);
    hdr[12..16].copy_from_slice(&crc.to_le_bytes());
    // reserved left zero
    let mut out = Vec::with_capacity(hdr.len() + payload.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(payload);
    out
}

#[allow(clippy::unnecessary_wraps)] // Result return kept for consistency with other encode_*_payload fns
fn encode_blk1_payload(blocks: &[BlockMetaV1]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(16 + blocks.len() * BLOCK_META_V1_LEN);
    out.extend_from_slice(&RECORD_BLOCK_UNCOMPRESSED_MAX_LEN_V1.to_le_bytes());
    out.extend_from_slice(&(BLOOM_BYTES_PER_BLOCK_V1 as u32).to_le_bytes());
    out.extend_from_slice(&BLOOM_HASH_K_V1.to_le_bytes());
    out.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
    for b in blocks {
        out.extend_from_slice(&encode_block_meta_v1(b));
    }
    Ok(out)
}

#[allow(clippy::unwrap_used)] // SAFETY: all try_into().unwrap() are on fixed-size slices after bounds checks
fn decode_blk1_payload(payload: &[u8]) -> Result<(u32, u32, u32, Vec<BlockMetaV1>)> {
    if payload.len() < 16 {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "BLK1 payload too small".to_string(),
        });
    }
    let record_block_uncompressed_max_len = u32::from_le_bytes(payload[0..4].try_into().unwrap());
    let bloom_bytes_per_block = u32::from_le_bytes(payload[4..8].try_into().unwrap());
    let bloom_hash_k = u32::from_le_bytes(payload[8..12].try_into().unwrap());
    let block_count = u32::from_le_bytes(payload[12..16].try_into().unwrap()) as usize;
    if bloom_bytes_per_block as usize != BLOOM_BYTES_PER_BLOCK_V1 {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "unsupported bloom_bytes_per_block".to_string(),
        });
    }
    let expected = 16usize
        .checked_add(
            block_count
                .checked_mul(BLOCK_META_V1_LEN)
                .ok_or(SegmentError::BufferTooSmall)?,
        )
        .ok_or(SegmentError::BufferTooSmall)?;
    if payload.len() != expected {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "BLK1 payload length mismatch".to_string(),
        });
    }
    let mut blocks = Vec::with_capacity(block_count);
    let mut off = 16usize;
    for _ in 0..block_count {
        let end = off + BLOCK_META_V1_LEN;
        blocks.push(decode_block_meta_v1(&payload[off..end])?);
        off = end;
    }
    Ok((
        record_block_uncompressed_max_len,
        bloom_bytes_per_block,
        bloom_hash_k,
        blocks,
    ))
}

#[allow(clippy::unnecessary_wraps)] // Result return kept for consistency with other encode_*_payload fns
fn encode_tbo1_payload(entries: &[TocByOffsetEntryV1]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + entries.len().checked_mul(TOC_BY_OFFSET_ENTRY_V1_LEN).unwrap_or(0));
    out.extend_from_slice(&(TOC_BY_OFFSET_ENTRY_V1_LEN as u32).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        out.extend_from_slice(&encode_toc_by_offset_entry_v1(e));
    }
    Ok(out)
}

#[allow(clippy::unwrap_used)] // SAFETY: all try_into().unwrap() are on fixed-size slices after bounds checks
fn decode_tbo1_payload(payload: &[u8]) -> Result<Vec<TocByOffsetEntryV1>> {
    if payload.len() < 8 {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "TBO1 payload too small".to_string(),
        });
    }
    let entry_len = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    if entry_len != TOC_BY_OFFSET_ENTRY_V1_LEN {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "unsupported toc_by_offset entry_len".to_string(),
        });
    }
    let count = u32::from_le_bytes(payload[4..8].try_into().unwrap()) as usize;
    let expected = 8usize
        .checked_add(count.checked_mul(entry_len).ok_or(SegmentError::BufferTooSmall)?)
        .ok_or(SegmentError::BufferTooSmall)?;
    if payload.len() != expected {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "TBO1 payload length mismatch".to_string(),
        });
    }
    let mut entries = Vec::with_capacity(count);
    let mut off = 8usize;
    for _ in 0..count {
        let end = off + entry_len;
        entries.push(decode_toc_by_offset_entry_v1(&payload[off..end])?);
        off = end;
    }
    Ok(entries)
}

#[allow(clippy::unnecessary_wraps)] // Result return kept for consistency with other encode_*_payload fns
fn encode_tsi1_payload(sorted_idx: &[u32]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + sorted_idx.len() * 4);
    out.extend_from_slice(&(sorted_idx.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved
    for &v in sorted_idx {
        out.extend_from_slice(&v.to_le_bytes());
    }
    Ok(out)
}

#[allow(clippy::unwrap_used)] // SAFETY: all try_into().unwrap() are on fixed-size slices after bounds checks
fn decode_tsi1_payload(payload: &[u8]) -> Result<Vec<u32>> {
    if payload.len() < 8 {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "TSI1 payload too small".to_string(),
        });
    }
    let count = u32::from_le_bytes(payload[0..4].try_into().unwrap()) as usize;
    let expected = 8usize
        .checked_add(count.checked_mul(4).ok_or(SegmentError::BufferTooSmall)?)
        .ok_or(SegmentError::BufferTooSmall)?;
    if payload.len() != expected {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "TSI1 payload length mismatch".to_string(),
        });
    }
    let mut out = Vec::with_capacity(count);
    let mut off = 8usize;
    for _ in 0..count {
        out.push(u32::from_le_bytes(payload[off..off + 4].try_into().unwrap()));
        off += 4;
    }
    Ok(out)
}
