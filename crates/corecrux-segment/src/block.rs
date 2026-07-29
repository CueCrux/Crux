// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Record-block metadata + TOC-by-offset entry codecs (`BlockMetaV1`, `TocByOffsetEntryV1`).

use crate::{
    BlockMetaV1, Result, SegmentError, TocByOffsetEntryV1, BLOCK_META_V1_LEN, BLOOM_BYTES_PER_BLOCK_V1,
    TOC_BY_OFFSET_ENTRY_V1_LEN,
};

pub fn encode_block_meta_v1(b: &BlockMetaV1) -> [u8; BLOCK_META_V1_LEN] {
    let mut out = [0u8; BLOCK_META_V1_LEN];
    out[0..4].copy_from_slice(&b.block_id.to_le_bytes());
    out[4..8].copy_from_slice(&b.codec.to_le_bytes());
    out[8..16].copy_from_slice(&b.file_offset.to_le_bytes());
    out[16..20].copy_from_slice(&b.compressed_len.to_le_bytes());
    out[20..24].copy_from_slice(&b.uncompressed_len.to_le_bytes());
    out[24..28].copy_from_slice(&b.crc32c.to_le_bytes());
    // reserved [28..32] used for physical_len (0 means "same as compressed_len" for legacy blocks)
    out[28..32].copy_from_slice(&b.physical_len.to_le_bytes());
    out[32..32 + BLOOM_BYTES_PER_BLOCK_V1].copy_from_slice(&b.bloom);
    out
}

#[allow(clippy::unwrap_used)] // SAFETY: all try_into().unwrap() are on fixed-size slices after exact-length check
pub(crate) fn decode_block_meta_v1(bytes: &[u8]) -> Result<BlockMetaV1> {
    if bytes.len() != BLOCK_META_V1_LEN {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "block meta length mismatch".to_string(),
        });
    }
    let block_id = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let codec = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let file_offset = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let compressed_len = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let uncompressed_len = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    let crc32c = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
    let physical_len = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
    let mut bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];
    bloom.copy_from_slice(&bytes[32..32 + BLOOM_BYTES_PER_BLOCK_V1]);
    let physical_len = if physical_len == 0 {
        compressed_len
    } else {
        physical_len
    };
    Ok(BlockMetaV1 {
        block_id,
        codec,
        file_offset,
        compressed_len,
        physical_len,
        uncompressed_len,
        crc32c,
        bloom,
    })
}

pub fn encode_toc_by_offset_entry_v1(e: &TocByOffsetEntryV1) -> [u8; TOC_BY_OFFSET_ENTRY_V1_LEN] {
    let mut out = [0u8; TOC_BY_OFFSET_ENTRY_V1_LEN];
    out[0..8].copy_from_slice(&e.stream_hash.to_le_bytes());
    out[8..16].copy_from_slice(&e.seq.to_le_bytes());
    out[16..20].copy_from_slice(&e.block_id.to_le_bytes());
    out[20..24].copy_from_slice(&e.in_block_offset.to_le_bytes());
    out[24..28].copy_from_slice(&e.frame_len.to_le_bytes());
    out[28..32].copy_from_slice(&e.flags.to_le_bytes());
    out[32..48].copy_from_slice(&e.event_id_hash16);
    out[48..56].copy_from_slice(&e.header_digest8);
    out[56..64].copy_from_slice(&e.payload_digest8);
    out
}

#[allow(clippy::unwrap_used)] // SAFETY: all try_into().unwrap() are on fixed-size slices after exact-length check
pub(crate) fn decode_toc_by_offset_entry_v1(bytes: &[u8]) -> Result<TocByOffsetEntryV1> {
    if bytes.len() != TOC_BY_OFFSET_ENTRY_V1_LEN {
        return Err(SegmentError::TrailerSectionInvalid {
            msg: "toc_by_offset entry length mismatch".to_string(),
        });
    }
    let stream_hash = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let seq = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let block_id = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    let in_block_offset = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
    let frame_len = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
    let flags = u32::from_le_bytes(bytes[28..32].try_into().unwrap());
    let mut event_id_hash16 = [0u8; 16];
    event_id_hash16.copy_from_slice(&bytes[32..48]);
    let mut header_digest8 = [0u8; 8];
    header_digest8.copy_from_slice(&bytes[48..56]);
    let mut payload_digest8 = [0u8; 8];
    payload_digest8.copy_from_slice(&bytes[56..64]);
    Ok(TocByOffsetEntryV1 {
        stream_hash,
        seq,
        block_id,
        in_block_offset,
        frame_len,
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
    use crate::RECORD_BLOCK_CODEC_LZ4_V1;
    use crate::RECORD_BLOCK_CODEC_NONE_V1;

    #[test]
    fn block_meta_v1_roundtrip() {
        let meta = BlockMetaV1 {
            block_id: 3,
            codec: RECORD_BLOCK_CODEC_LZ4_V1,
            file_offset: 8192,
            compressed_len: 1024,
            physical_len: 4096,
            uncompressed_len: 2048,
            crc32c: 0xAABBCCDD,
            bloom: [0x55; BLOOM_BYTES_PER_BLOCK_V1],
        };
        let bytes = encode_block_meta_v1(&meta);
        assert_eq!(bytes.len(), BLOCK_META_V1_LEN);
        let decoded = decode_block_meta_v1(&bytes).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn block_meta_v1_physical_len_zero_fallback() {
        let meta = BlockMetaV1 {
            block_id: 0,
            codec: RECORD_BLOCK_CODEC_NONE_V1,
            file_offset: 4096,
            compressed_len: 512,
            physical_len: 0, // legacy: 0 means "same as compressed_len"
            uncompressed_len: 512,
            crc32c: 0x12345678,
            bloom: [0; BLOOM_BYTES_PER_BLOCK_V1],
        };
        let bytes = encode_block_meta_v1(&meta);
        let decoded = decode_block_meta_v1(&bytes).unwrap();
        // physical_len=0 decodes as compressed_len
        assert_eq!(decoded.physical_len, 512);
    }

    #[test]
    fn toc_by_offset_entry_roundtrip() {
        let entry = TocByOffsetEntryV1 {
            stream_hash: 0xDEAD,
            seq: 7,
            block_id: 2,
            in_block_offset: 128,
            frame_len: 64,
            flags: 0,
            event_id_hash16: [0x11; 16],
            header_digest8: [0x22; 8],
            payload_digest8: [0x33; 8],
        };
        let bytes = encode_toc_by_offset_entry_v1(&entry);
        assert_eq!(bytes.len(), TOC_BY_OFFSET_ENTRY_V1_LEN);
        let decoded = decode_toc_by_offset_entry_v1(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn block_meta_encode_length(
            block_id in any::<u32>(),
            codec in any::<u32>(),
            file_offset in any::<u64>(),
            compressed_len in any::<u32>(),
            physical_len in any::<u32>(),
            uncompressed_len in any::<u32>(),
            crc32c in any::<u32>(),
        ) {
            let mut bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];
            // Fill bloom with deterministic pattern from block_id
            for (i, b) in bloom.iter_mut().enumerate() {
                *b = ((block_id as usize).wrapping_add(i) & 0xFF) as u8;
            }
            let meta = BlockMetaV1 {
                block_id,
                codec,
                file_offset,
                compressed_len,
                physical_len,
                uncompressed_len,
                crc32c,
                bloom,
            };
            let encoded = encode_block_meta_v1(&meta);
            // Verify encoded length matches expected constant
            prop_assert_eq!(encoded.len(), BLOCK_META_V1_LEN);
        }

        #[test]
        fn toc_by_offset_entry_encode_length(
            stream_hash in any::<u64>(),
            seq in any::<u64>(),
            block_id in any::<u32>(),
            in_block_offset in any::<u32>(),
            frame_len in any::<u32>(),
            flags in any::<u32>(),
            event_id_hash16 in prop::array::uniform16(any::<u8>()),
            header_digest8 in prop::array::uniform8(any::<u8>()),
            payload_digest8 in prop::array::uniform8(any::<u8>()),
        ) {
            let entry = TocByOffsetEntryV1 {
                stream_hash,
                seq,
                block_id,
                in_block_offset,
                frame_len,
                flags,
                event_id_hash16,
                header_digest8,
                payload_digest8,
            };
            let encoded = encode_toc_by_offset_entry_v1(&entry);
            prop_assert_eq!(encoded.len(), TOC_BY_OFFSET_ENTRY_V1_LEN);
        }
    }
}
