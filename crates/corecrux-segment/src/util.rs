// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Byte-decode helpers (`read_u16`, `read_u32`, `read_u64`) + TOC sorted-order check + `align_up`.

use crate::{Result, SegmentError, TocEntryV1};

pub(crate) fn read_u16(bytes: &[u8], off: usize) -> Result<u16> {
    let end = off.checked_add(2).ok_or(SegmentError::BufferTooSmall)?;
    if end > bytes.len() {
        return Err(SegmentError::BufferTooSmall);
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&bytes[off..end]);
    Ok(u16::from_le_bytes(buf))
}

pub(crate) fn read_u32(bytes: &[u8], off: usize) -> Result<u32> {
    let end = off.checked_add(4).ok_or(SegmentError::BufferTooSmall)?;
    if end > bytes.len() {
        return Err(SegmentError::BufferTooSmall);
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[off..end]);
    Ok(u32::from_le_bytes(buf))
}

pub(crate) fn read_u64(bytes: &[u8], off: usize) -> Result<u64> {
    let end = off.checked_add(8).ok_or(SegmentError::BufferTooSmall)?;
    if end > bytes.len() {
        return Err(SegmentError::BufferTooSmall);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[off..end]);
    Ok(u64::from_le_bytes(buf))
}

pub(crate) fn align_up(v: usize, align: usize) -> usize {
    if align == 0 {
        return v;
    }
    let rem = v % align;
    if rem == 0 {
        v
    } else {
        v + (align - rem)
    }
}

pub(crate) fn is_sorted_toc(entries: &[TocEntryV1]) -> bool {
    entries
        .windows(2)
        .all(|w| (w[0].stream_hash, w[0].seq) <= (w[1].stream_hash, w[1].seq))
}

pub(crate) fn block_crc32c(bytes: &[u8], block_size: usize) -> Vec<u32> {
    if block_size == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        let end = (off + block_size).min(bytes.len());
        out.push(crc32c::crc32c(&bytes[off..end]));
        off = end;
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::TocEntryV1;

    #[test]
    fn is_sorted_toc_validates() {
        let sorted = vec![
            TocEntryV1 {
                stream_hash: 1,
                seq: 1,
                file_offset: 0,
                frame_len: 0,
                payload_len: 0,
                flags: 0,
                event_id_hash16: [0; 16],
                header_digest8: [0; 8],
                payload_digest8: [0; 8],
            },
            TocEntryV1 {
                stream_hash: 1,
                seq: 2,
                file_offset: 0,
                frame_len: 0,
                payload_len: 0,
                flags: 0,
                event_id_hash16: [0; 16],
                header_digest8: [0; 8],
                payload_digest8: [0; 8],
            },
            TocEntryV1 {
                stream_hash: 2,
                seq: 1,
                file_offset: 0,
                frame_len: 0,
                payload_len: 0,
                flags: 0,
                event_id_hash16: [0; 16],
                header_digest8: [0; 8],
                payload_digest8: [0; 8],
            },
        ];
        assert!(is_sorted_toc(&sorted));

        let unsorted = vec![sorted[2], sorted[0]];
        assert!(!is_sorted_toc(&unsorted));

        assert!(is_sorted_toc(&[]));
        assert!(is_sorted_toc(&[sorted[0]]));
    }

    #[test]
    fn align_up_works() {
        assert_eq!(align_up(0, 4096), 0);
        assert_eq!(align_up(1, 4096), 4096);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
        assert_eq!(align_up(100, 0), 100); // align=0 returns value unchanged
    }

    #[test]
    fn block_crc32c_empty() {
        assert!(block_crc32c(&[], 64).is_empty());
        assert!(block_crc32c(&[1, 2, 3], 0).is_empty());
    }

    #[test]
    fn block_crc32c_single_block() {
        let data = vec![0xAA; 100];
        let crcs = block_crc32c(&data, 200);
        assert_eq!(crcs.len(), 1);
        assert_eq!(crcs[0], crc32c::crc32c(&data));
    }

    #[test]
    fn block_crc32c_multiple_blocks() {
        let data = vec![0xBB; 256];
        let crcs = block_crc32c(&data, 100);
        assert_eq!(crcs.len(), 3); // 100 + 100 + 56
        assert_eq!(crcs[0], crc32c::crc32c(&data[0..100]));
        assert_eq!(crcs[1], crc32c::crc32c(&data[100..200]));
        assert_eq!(crcs[2], crc32c::crc32c(&data[200..256]));
    }

    #[test]
    fn read_u16_out_of_bounds() {
        let err = read_u16(&[0u8; 1], 0).unwrap_err();
        assert!(matches!(err, SegmentError::BufferTooSmall));
    }

    #[test]
    fn read_u32_out_of_bounds() {
        let err = read_u32(&[0u8; 3], 0).unwrap_err();
        assert!(matches!(err, SegmentError::BufferTooSmall));
    }

    #[test]
    fn read_u64_out_of_bounds() {
        let err = read_u64(&[0u8; 7], 0).unwrap_err();
        assert!(matches!(err, SegmentError::BufferTooSmall));
    }
}
