// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! v1 TOC codec (`TOC_MAGIC_TOC1`) — table of contents header + per-entry stride for record-block + frame lookups.

use crate::util::{read_u16, read_u32, read_u64};
use crate::{
    Result, SegmentError, TocEntryV1, TocHeaderV1, DEFAULT_RECORD_BLOCK_SIZE, DEFAULT_TOC_BLOCK_SIZE, TOC_ENTRY_LEN,
    TOC_HEADER_LEN, TOC_MAGIC_TOC1,
};

pub(crate) fn encode_toc_payload_v1(
    entry_count: u64,
    record_area_offset: u64,
    record_area_len: u64,
    toc_payload_len: u64,
    crc_tables_len: u64,
    entries: &[TocEntryV1],
) -> Result<Vec<u8>> {
    encode_toc_payload_v1_with_hash(
        entry_count,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        [0u8; 32],
        entries,
    )
}

#[allow(clippy::unnecessary_wraps)] // Result return kept for consistency with other encode_*_payload fns
pub(crate) fn encode_toc_payload_v1_with_hash(
    entry_count: u64,
    record_area_offset: u64,
    record_area_len: u64,
    toc_payload_len: u64,
    crc_tables_len: u64,
    toc_payload_hash: [u8; 32],
    entries: &[TocEntryV1],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(toc_payload_len as usize);

    let mut hdr = [0u8; TOC_HEADER_LEN];
    hdr[0..4].copy_from_slice(&TOC_MAGIC_TOC1.to_le_bytes());
    hdr[4..6].copy_from_slice(&1u16.to_le_bytes());
    hdr[6..8].copy_from_slice(&(TOC_ENTRY_LEN as u16).to_le_bytes());
    hdr[8..16].copy_from_slice(&entry_count.to_le_bytes());
    hdr[16..20].copy_from_slice(&DEFAULT_RECORD_BLOCK_SIZE.to_le_bytes());
    hdr[20..24].copy_from_slice(&DEFAULT_TOC_BLOCK_SIZE.to_le_bytes());
    hdr[24..32].copy_from_slice(&record_area_offset.to_le_bytes());
    hdr[32..40].copy_from_slice(&record_area_len.to_le_bytes());
    hdr[40..48].copy_from_slice(&toc_payload_len.to_le_bytes());
    hdr[48..56].copy_from_slice(&crc_tables_len.to_le_bytes());
    hdr[56..64].copy_from_slice(&1u64.to_le_bytes()); // sort order
                                                      // reserved0 [64..72] left zero
    hdr[72..104].copy_from_slice(&toc_payload_hash);
    // reserved padding [104..120] left zero
    // reserved1 at [120..124] left zero

    let crc = crc32c::crc32c(&hdr[..TOC_HEADER_LEN - 4]);
    hdr[TOC_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());

    out.extend_from_slice(&hdr);
    for e in entries {
        out.extend_from_slice(&encode_toc_entry_v1(e));
    }
    Ok(out)
}

pub(crate) fn compute_toc_payload_hash(toc_payload_bytes: &[u8]) -> Result<[u8; 32]> {
    if toc_payload_bytes.len() < TOC_HEADER_LEN {
        return Err(SegmentError::BufferTooSmall);
    }
    let mut tmp = toc_payload_bytes.to_vec();
    // Exclude the toc_payload_hash field itself from the hash by treating it as all zeros.
    for b in &mut tmp[72..104] {
        *b = 0;
    }
    // Also ignore toc_header_crc32c while hashing.
    for b in &mut tmp[TOC_HEADER_LEN - 4..TOC_HEADER_LEN] {
        *b = 0;
    }
    Ok(*blake3::hash(&tmp).as_bytes())
}

pub fn decode_toc_header_v1(bytes: &[u8]) -> Result<TocHeaderV1> {
    if bytes.len() < TOC_HEADER_LEN {
        return Err(SegmentError::BufferTooSmall);
    }
    let magic = read_u32(bytes, 0)?;
    if magic != TOC_MAGIC_TOC1 {
        return Err(SegmentError::InvalidMagic {
            expected: TOC_MAGIC_TOC1,
            actual: magic,
        });
    }
    let ver = read_u16(bytes, 4)?;
    if ver != 1 {
        return Err(SegmentError::UnsupportedTocVersion { version: ver });
    }
    let entry_size = read_u16(bytes, 6)? as usize;
    if entry_size != TOC_ENTRY_LEN {
        return Err(SegmentError::LengthOutOfRange {
            msg: format!("entry_size expected {TOC_ENTRY_LEN}, got {entry_size}"),
        });
    }

    let expected = read_u32(bytes, TOC_HEADER_LEN - 4)?;
    let mut tmp = bytes.to_vec();
    for b in &mut tmp[TOC_HEADER_LEN - 4..] {
        *b = 0;
    }
    let actual = crc32c::crc32c(&tmp[..TOC_HEADER_LEN - 4]);
    if expected != actual {
        return Err(SegmentError::CrcMismatch { expected, actual });
    }

    let entry_count = read_u64(bytes, 8)?;
    let record_block_size = read_u32(bytes, 16)?;
    let toc_block_size = read_u32(bytes, 20)?;
    let record_area_offset = read_u64(bytes, 24)?;
    let record_area_len = read_u64(bytes, 32)?;
    let toc_payload_len = read_u64(bytes, 40)?;
    let crc_tables_len = read_u64(bytes, 48)?;
    let sort_order = read_u64(bytes, 56)?;
    let mut toc_payload_hash = [0u8; 32];
    toc_payload_hash.copy_from_slice(&bytes[72..104]);

    Ok(TocHeaderV1 {
        entry_count,
        record_block_size,
        toc_block_size,
        record_area_offset,
        record_area_len,
        toc_payload_len,
        crc_tables_len,
        sort_order,
        toc_payload_hash,
    })
}

pub(crate) fn encode_toc_entry_v1(e: &TocEntryV1) -> [u8; TOC_ENTRY_LEN] {
    let mut out = [0u8; TOC_ENTRY_LEN];
    out[0..8].copy_from_slice(&e.stream_hash.to_le_bytes());
    out[8..16].copy_from_slice(&e.seq.to_le_bytes());
    out[16..20].copy_from_slice(&e.file_offset.to_le_bytes());
    out[20..24].copy_from_slice(&e.frame_len.to_le_bytes());
    out[24..28].copy_from_slice(&e.payload_len.to_le_bytes());
    out[28..32].copy_from_slice(&e.flags.to_le_bytes());
    out[32..48].copy_from_slice(&e.event_id_hash16);
    out[48..56].copy_from_slice(&e.header_digest8);
    out[56..64].copy_from_slice(&e.payload_digest8);
    out
}

pub(crate) fn decode_toc_entry_v1(bytes: &[u8]) -> Result<TocEntryV1> {
    if bytes.len() < TOC_ENTRY_LEN {
        return Err(SegmentError::BufferTooSmall);
    }
    let stream_hash = read_u64(bytes, 0)?;
    let seq = read_u64(bytes, 8)?;
    let file_offset = read_u32(bytes, 16)?;
    let frame_len = read_u32(bytes, 20)?;
    let payload_len = read_u32(bytes, 24)?;
    let flags = read_u32(bytes, 28)?;
    let mut event_id_hash16 = [0u8; 16];
    event_id_hash16.copy_from_slice(&bytes[32..48]);
    let mut header_digest8 = [0u8; 8];
    header_digest8.copy_from_slice(&bytes[48..56]);
    let mut payload_digest8 = [0u8; 8];
    payload_digest8.copy_from_slice(&bytes[56..64]);

    Ok(TocEntryV1 {
        stream_hash,
        seq,
        file_offset,
        frame_len,
        payload_len,
        flags,
        event_id_hash16,
        header_digest8,
        payload_digest8,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn toc_header_decode_bad_magic() {
        let mut buf = [0u8; TOC_HEADER_LEN];
        buf[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let err = decode_toc_header_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::InvalidMagic { .. }));
    }

    #[test]
    fn toc_header_decode_bad_version() {
        let mut buf = [0u8; TOC_HEADER_LEN];
        buf[0..4].copy_from_slice(&TOC_MAGIC_TOC1.to_le_bytes());
        buf[4..6].copy_from_slice(&99u16.to_le_bytes()); // bad version
        let err = decode_toc_header_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::UnsupportedTocVersion { .. }));
    }

    #[test]
    fn toc_entry_roundtrip() {
        let entry = TocEntryV1 {
            stream_hash: 0x123456789ABCDEF0,
            seq: 42,
            file_offset: 4096,
            frame_len: 256,
            payload_len: 128,
            flags: 0,
            event_id_hash16: [0xAA; 16],
            header_digest8: [0xBB; 8],
            payload_digest8: [0xCC; 8],
        };
        let bytes = encode_toc_entry_v1(&entry);
        assert_eq!(bytes.len(), TOC_ENTRY_LEN);
        let decoded = decode_toc_entry_v1(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }
}
