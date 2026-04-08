// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use blake3::Hasher as Blake3;

use crate::footer::decode_segment_footer_v1;
use crate::header::decode_segment_header_v1;
use crate::toc::{compute_toc_payload_hash, decode_toc_entry_v1, decode_toc_header_v1};
use crate::util::{is_sorted_toc, read_u64};
use crate::{
    Result, SegmentError, SegmentFooterV1, SegmentHeaderV1, TocEntryV1, TocHeaderV1,
    SEGMENT_FOOTER_LEN, SEGMENT_HEADER_LEN, TOC_ENTRY_LEN, TOC_HEADER_LEN,
};

pub fn decode_segment_v1(bytes: &[u8]) -> Result<(SegmentHeaderV1, TocHeaderV1, Vec<TocEntryV1>, SegmentFooterV1)> {
    if bytes.len() < SEGMENT_HEADER_LEN + SEGMENT_FOOTER_LEN {
        return Err(SegmentError::BufferTooSmall);
    }
    let header_bytes = &bytes[..SEGMENT_HEADER_LEN];
    let header = decode_segment_header_v1(header_bytes)?;

    let footer_bytes = &bytes[bytes.len() - SEGMENT_FOOTER_LEN..];
    let footer = decode_segment_footer_v1(footer_bytes)?;

    if footer.flags & 0x1 == 0 {
        return Err(SegmentError::NotSealed);
    }
    if footer.file_len != bytes.len() as u64 {
        return Err(SegmentError::FileLenMismatch {
            declared: footer.file_len,
            actual: bytes.len() as u64,
        });
    }
    if footer.segment_id != header.segment_id
        || footer.segment_seq != header.segment_seq
        || footer.epoch != header.epoch
        || footer.shard_id != header.shard_id
    {
        return Err(SegmentError::HashMismatch {
            msg: "identity mismatch between header and footer".to_string(),
        });
    }

    // Validate header crc already checked; validate footer crc already checked. Verify strong hashes.
    let header_hash = blake3::hash(header_bytes);
    if *header_hash.as_bytes() != footer.header_hash {
        return Err(SegmentError::HashMismatch {
            msg: "header_hash mismatch".to_string(),
        });
    }

    let record_off = footer.record_area_offset as usize;
    let record_len = footer.record_area_len as usize;
    if record_off + record_len > bytes.len() {
        return Err(SegmentError::BufferTooSmall);
    }
    let record_area = &bytes[record_off..record_off + record_len];
    let record_hash = blake3::hash(record_area);
    if *record_hash.as_bytes() != footer.record_hash {
        return Err(SegmentError::HashMismatch {
            msg: "record_hash mismatch".to_string(),
        });
    }

    let toc_off = footer.toc_offset as usize;
    let toc_len = footer.toc_len as usize;
    if toc_off + toc_len + SEGMENT_FOOTER_LEN != bytes.len() {
        return Err(SegmentError::LengthOutOfRange {
            msg: "toc/record/footer lengths do not line up".to_string(),
        });
    }
    let toc_area = &bytes[toc_off..toc_off + toc_len];
    if toc_area.len() < TOC_HEADER_LEN {
        return Err(SegmentError::BufferTooSmall);
    }
    let toc_payload_len = read_u64(toc_area, 40)?; // toc_payload_len field offset
    let toc_payload_len = toc_payload_len as usize;
    if toc_payload_len > toc_area.len() {
        return Err(SegmentError::BufferTooSmall);
    }
    let toc_payload = &toc_area[..toc_payload_len];
    let toc_header = decode_toc_header_v1(&toc_payload[..TOC_HEADER_LEN])?;

    if toc_header.toc_payload_hash != footer.toc_payload_hash {
        return Err(SegmentError::HashMismatch {
            msg: "toc_payload_hash mismatch between toc header and footer".to_string(),
        });
    }

    // Verify toc_payload_hash.
    let computed_toc_payload_hash = compute_toc_payload_hash(toc_payload)?;
    if computed_toc_payload_hash != toc_header.toc_payload_hash {
        return Err(SegmentError::HashMismatch {
            msg: "toc_payload_hash mismatch".to_string(),
        });
    }

    // Verify segment_hash.
    let seg_hash = {
        let mut h = Blake3::new();
        h.update(&footer.header_hash);
        h.update(&footer.record_hash);
        h.update(&footer.toc_payload_hash);
        *h.finalize().as_bytes()
    };
    if seg_hash != footer.segment_hash {
        return Err(SegmentError::HashMismatch {
            msg: "segment_hash mismatch".to_string(),
        });
    }

    // Decode entries.
    let entry_count = toc_header.entry_count as usize;
    let entries_off = TOC_HEADER_LEN;
    let entries_len = entry_count
        .checked_mul(TOC_ENTRY_LEN)
        .ok_or(SegmentError::BufferTooSmall)?;
    if entries_off + entries_len > toc_payload.len() {
        return Err(SegmentError::BufferTooSmall);
    }
    let mut entries = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let start = entries_off + i * TOC_ENTRY_LEN;
        let end = start + TOC_ENTRY_LEN;
        entries.push(decode_toc_entry_v1(&toc_payload[start..end])?);
    }
    if !is_sorted_toc(&entries) {
        return Err(SegmentError::TocNotSorted);
    }

    Ok((header, toc_header, entries, footer))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::builder::build_segment_v1;
    use crate::footer::encode_segment_footer_v1;
    use crate::{FrameInput, SegmentId, SEGMENT_FOOTER_LEN};

    #[test]
    fn detects_footer_corruption() {
        let out = build_segment_v1(
            0,
            1,
            1,
            SegmentId([1u8; 16]),
            1,
            2,
            &[FrameInput {
                stream_hash: 1,
                seq: 1,
                event_id: "evt",
                header_hash: [2u8; 32],
                payload_hash: [3u8; 32],
                header_bytes: b"hdr",
                payload_bytes: b"payload",
            }],
        )
        .unwrap();

        let mut bytes = out.bytes.clone();
        // Flip a bit in the footer.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;

        let err = decode_segment_v1(&bytes).unwrap_err();
        assert!(matches!(err, SegmentError::CrcMismatch { .. }));
    }

    #[test]
    fn decode_segment_v1_rejects_too_small() {
        let buf = vec![0u8; 100];
        let err = decode_segment_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::BufferTooSmall));
    }

    #[test]
    fn decode_segment_v1_rejects_unsealed() {
        // Build a valid segment, then clear the SEALED flag in footer
        let out = build_segment_v1(
            0,
            1,
            1,
            SegmentId([1u8; 16]),
            1,
            2,
            &[FrameInput {
                stream_hash: 1,
                seq: 1,
                event_id: "evt",
                header_hash: [2u8; 32],
                payload_hash: [3u8; 32],
                header_bytes: b"hdr",
                payload_bytes: b"payload",
            }],
        )
        .unwrap();

        // Create a footer with flags=0 (not sealed)
        let mut footer = out.footer.clone();
        footer.flags = 0; // clear SEALED
        let footer_bytes = encode_segment_footer_v1(&footer).unwrap();

        let mut bytes = out.bytes.clone();
        let footer_start = bytes.len() - SEGMENT_FOOTER_LEN;
        bytes[footer_start..].copy_from_slice(&footer_bytes);

        let err = decode_segment_v1(&bytes).unwrap_err();
        // Could be NotSealed or CrcMismatch/HashMismatch due to footer change
        match err {
            SegmentError::NotSealed | SegmentError::CrcMismatch { .. } | SegmentError::HashMismatch { .. } => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
