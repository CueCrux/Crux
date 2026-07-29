// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! v1 segment footer codec — magic `CCF3`, file length, content offsets; the canonical "sealed" marker.

use crate::util::{read_u16, read_u32, read_u64};
use crate::{
    Result, SegmentError, SegmentFooterV1, SegmentId, SEGMENT_FOOTER_LEN, SEGMENT_MAGIC_CCF3, SEGMENT_MAJOR,
    SEGMENT_MINOR,
};

pub fn encode_segment_footer_v1(f: &SegmentFooterV1) -> Result<[u8; SEGMENT_FOOTER_LEN]> {
    if f.file_len > u32::MAX as u64
        || f.record_area_offset > u32::MAX as u64
        || f.record_area_len > u32::MAX as u64
        || f.toc_offset > u32::MAX as u64
        || f.toc_len > u32::MAX as u64
        || f.toc_entry_count > u32::MAX as u64
    {
        return Err(SegmentError::LengthOutOfRange {
            msg: "footer v1 encodes offsets/lengths as u32; value exceeds 4GiB".to_string(),
        });
    }

    let mut out = [0u8; SEGMENT_FOOTER_LEN];
    out[0..4].copy_from_slice(&SEGMENT_MAGIC_CCF3.to_le_bytes());
    out[4..6].copy_from_slice(&SEGMENT_MAJOR.to_le_bytes());
    out[6..8].copy_from_slice(&SEGMENT_MINOR.to_le_bytes());
    out[8..12].copy_from_slice(&(SEGMENT_FOOTER_LEN as u32).to_le_bytes());
    out[12..16].copy_from_slice(&f.flags.to_le_bytes());
    out[16..20].copy_from_slice(&f.shard_id.to_le_bytes());
    out[20..28].copy_from_slice(&f.epoch.to_le_bytes());
    out[28..36].copy_from_slice(&f.segment_seq.to_le_bytes());
    out[36..52].copy_from_slice(&f.segment_id.0);
    out[52..60].copy_from_slice(&f.created_at_unix_ns.to_le_bytes());
    out[60..68].copy_from_slice(&f.sealed_at_unix_ns.to_le_bytes());

    out[68..72].copy_from_slice(&(f.file_len as u32).to_le_bytes());
    out[72..76].copy_from_slice(&(f.record_area_offset as u32).to_le_bytes());
    out[76..80].copy_from_slice(&(f.record_area_len as u32).to_le_bytes());
    out[80..84].copy_from_slice(&(f.toc_offset as u32).to_le_bytes());
    out[84..88].copy_from_slice(&(f.toc_len as u32).to_le_bytes());
    out[88..92].copy_from_slice(&(f.toc_entry_count as u32).to_le_bytes());

    out[92..100].copy_from_slice(&f.min_stream_hash.to_le_bytes());
    out[100..108].copy_from_slice(&f.min_seq.to_le_bytes());
    out[108..116].copy_from_slice(&f.max_stream_hash.to_le_bytes());
    out[116..124].copy_from_slice(&f.max_seq.to_le_bytes());

    out[124..156].copy_from_slice(&f.header_hash);
    out[156..188].copy_from_slice(&f.record_hash);
    out[188..220].copy_from_slice(&f.toc_payload_hash);
    out[220..252].copy_from_slice(&f.segment_hash);

    let crc = crc32c::crc32c(&out[..SEGMENT_FOOTER_LEN - 4]);
    out[SEGMENT_FOOTER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());

    Ok(out)
}

pub fn decode_segment_footer_v1(bytes: &[u8]) -> Result<SegmentFooterV1> {
    if bytes.len() < SEGMENT_FOOTER_LEN {
        return Err(SegmentError::BufferTooSmall);
    }

    let magic = read_u32(bytes, 0)?;
    if magic != SEGMENT_MAGIC_CCF3 {
        return Err(SegmentError::InvalidMagic {
            expected: SEGMENT_MAGIC_CCF3,
            actual: magic,
        });
    }
    let major = read_u16(bytes, 4)?;
    let minor = read_u16(bytes, 6)?;
    if major != SEGMENT_MAJOR || minor != SEGMENT_MINOR {
        return Err(SegmentError::UnsupportedSegmentVersion { major, minor });
    }
    let footer_len = read_u32(bytes, 8)? as usize;
    if footer_len != SEGMENT_FOOTER_LEN {
        return Err(SegmentError::LengthOutOfRange {
            msg: format!("footer_len expected {SEGMENT_FOOTER_LEN}, got {footer_len}"),
        });
    }

    let expected = read_u32(bytes, SEGMENT_FOOTER_LEN - 4)?;
    let actual = crc32c::crc32c(&bytes[..SEGMENT_FOOTER_LEN - 4]);
    if expected != actual {
        return Err(SegmentError::CrcMismatch { expected, actual });
    }

    let flags = read_u32(bytes, 12)?;
    let shard_id = read_u32(bytes, 16)?;
    let epoch = read_u64(bytes, 20)?;
    let segment_seq = read_u64(bytes, 28)?;
    let mut seg_id = [0u8; 16];
    seg_id.copy_from_slice(&bytes[36..52]);
    let created_at_unix_ns = read_u64(bytes, 52)?;
    let sealed_at_unix_ns = read_u64(bytes, 60)?;

    let file_len = read_u32(bytes, 68)? as u64;
    let record_area_offset = read_u32(bytes, 72)? as u64;
    let record_area_len = read_u32(bytes, 76)? as u64;
    let toc_offset = read_u32(bytes, 80)? as u64;
    let toc_len = read_u32(bytes, 84)? as u64;
    let toc_entry_count = read_u32(bytes, 88)? as u64;

    let min_stream_hash = read_u64(bytes, 92)?;
    let min_seq = read_u64(bytes, 100)?;
    let max_stream_hash = read_u64(bytes, 108)?;
    let max_seq = read_u64(bytes, 116)?;

    let mut header_hash = [0u8; 32];
    header_hash.copy_from_slice(&bytes[124..156]);
    let mut record_hash = [0u8; 32];
    record_hash.copy_from_slice(&bytes[156..188]);
    let mut toc_payload_hash = [0u8; 32];
    toc_payload_hash.copy_from_slice(&bytes[188..220]);
    let mut segment_hash = [0u8; 32];
    segment_hash.copy_from_slice(&bytes[220..252]);

    Ok(SegmentFooterV1 {
        flags,
        shard_id,
        epoch,
        segment_seq,
        segment_id: SegmentId(seg_id),
        created_at_unix_ns,
        sealed_at_unix_ns,
        file_len,
        record_area_offset,
        record_area_len,
        toc_offset,
        toc_len,
        toc_entry_count,
        min_stream_hash,
        min_seq,
        max_stream_hash,
        max_seq,
        header_hash,
        record_hash,
        toc_payload_hash,
        segment_hash,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn segment_footer_roundtrip() {
        let footer = SegmentFooterV1 {
            flags: 0x3,
            shard_id: 5,
            epoch: 10,
            segment_seq: 20,
            segment_id: SegmentId([0xBB; 16]),
            created_at_unix_ns: 100,
            sealed_at_unix_ns: 200,
            file_len: 8192,
            record_area_offset: 4096,
            record_area_len: 1024,
            toc_offset: 5120,
            toc_len: 512,
            toc_entry_count: 3,
            min_stream_hash: 1,
            min_seq: 1,
            max_stream_hash: 100,
            max_seq: 50,
            header_hash: [0x11; 32],
            record_hash: [0x22; 32],
            toc_payload_hash: [0x33; 32],
            segment_hash: [0x44; 32],
        };
        let bytes = encode_segment_footer_v1(&footer).unwrap();
        assert_eq!(bytes.len(), SEGMENT_FOOTER_LEN);
        let decoded = decode_segment_footer_v1(&bytes).unwrap();
        assert_eq!(decoded.flags, 0x3);
        assert_eq!(decoded.shard_id, 5);
        assert_eq!(decoded.epoch, 10);
        assert_eq!(decoded.segment_seq, 20);
        assert_eq!(decoded.segment_id, SegmentId([0xBB; 16]));
        assert_eq!(decoded.file_len, 8192);
        assert_eq!(decoded.header_hash, [0x11; 32]);
        assert_eq!(decoded.segment_hash, [0x44; 32]);
    }

    #[test]
    fn segment_footer_encode_rejects_oversized() {
        let footer = SegmentFooterV1 {
            flags: 0x3,
            shard_id: 0,
            epoch: 1,
            segment_seq: 1,
            segment_id: SegmentId([0; 16]),
            created_at_unix_ns: 0,
            sealed_at_unix_ns: 0,
            file_len: u64::MAX, // exceeds u32
            record_area_offset: 0,
            record_area_len: 0,
            toc_offset: 0,
            toc_len: 0,
            toc_entry_count: 0,
            min_stream_hash: 0,
            min_seq: 0,
            max_stream_hash: 0,
            max_seq: 0,
            header_hash: [0; 32],
            record_hash: [0; 32],
            toc_payload_hash: [0; 32],
            segment_hash: [0; 32],
        };
        let err = encode_segment_footer_v1(&footer).unwrap_err();
        assert!(matches!(err, SegmentError::LengthOutOfRange { .. }));
    }

    #[test]
    fn segment_footer_decode_bad_magic() {
        let mut buf = [0u8; SEGMENT_FOOTER_LEN];
        buf[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let err = decode_segment_footer_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::InvalidMagic { .. }));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn segment_footer_encode_decode_roundtrip(
            flags in any::<u32>(),
            shard_id in any::<u32>(),
            epoch in any::<u64>(),
            segment_seq in any::<u64>(),
            segment_id_bytes in prop::array::uniform16(any::<u8>()),
            created_at in any::<u64>(),
            sealed_at in any::<u64>(),
            // Footer v1 encodes offsets as u32, so keep values in u32 range
            file_len in 0u64..u32::MAX as u64,
            record_area_offset in 0u64..u32::MAX as u64,
            record_area_len in 0u64..u32::MAX as u64,
            toc_offset in 0u64..u32::MAX as u64,
            toc_len in 0u64..u32::MAX as u64,
            toc_entry_count in 0u64..u32::MAX as u64,
            min_stream_hash in any::<u64>(),
            min_seq in any::<u64>(),
            max_stream_hash in any::<u64>(),
            max_seq in any::<u64>(),
            header_hash in prop::array::uniform32(any::<u8>()),
            record_hash in prop::array::uniform32(any::<u8>()),
            toc_payload_hash in prop::array::uniform32(any::<u8>()),
            segment_hash in prop::array::uniform32(any::<u8>()),
        ) {
            let footer = SegmentFooterV1 {
                flags,
                shard_id,
                epoch,
                segment_seq,
                segment_id: SegmentId(segment_id_bytes),
                created_at_unix_ns: created_at,
                sealed_at_unix_ns: sealed_at,
                file_len,
                record_area_offset,
                record_area_len,
                toc_offset,
                toc_len,
                toc_entry_count,
                min_stream_hash,
                min_seq,
                max_stream_hash,
                max_seq,
                header_hash,
                record_hash,
                toc_payload_hash,
                segment_hash,
            };
            let encoded = encode_segment_footer_v1(&footer).unwrap();
            let decoded = decode_segment_footer_v1(&encoded).unwrap();
            prop_assert_eq!(decoded.flags, footer.flags);
            prop_assert_eq!(decoded.shard_id, footer.shard_id);
            prop_assert_eq!(decoded.epoch, footer.epoch);
            prop_assert_eq!(decoded.segment_seq, footer.segment_seq);
            prop_assert_eq!(decoded.segment_id, footer.segment_id);
            prop_assert_eq!(decoded.created_at_unix_ns, footer.created_at_unix_ns);
            prop_assert_eq!(decoded.sealed_at_unix_ns, footer.sealed_at_unix_ns);
            prop_assert_eq!(decoded.file_len, footer.file_len);
            prop_assert_eq!(decoded.record_area_offset, footer.record_area_offset);
            prop_assert_eq!(decoded.record_area_len, footer.record_area_len);
            prop_assert_eq!(decoded.toc_offset, footer.toc_offset);
            prop_assert_eq!(decoded.toc_len, footer.toc_len);
            prop_assert_eq!(decoded.toc_entry_count, footer.toc_entry_count);
            prop_assert_eq!(decoded.min_stream_hash, footer.min_stream_hash);
            prop_assert_eq!(decoded.min_seq, footer.min_seq);
            prop_assert_eq!(decoded.max_stream_hash, footer.max_stream_hash);
            prop_assert_eq!(decoded.max_seq, footer.max_seq);
            prop_assert_eq!(decoded.header_hash, footer.header_hash);
            prop_assert_eq!(decoded.record_hash, footer.record_hash);
            prop_assert_eq!(decoded.toc_payload_hash, footer.toc_payload_hash);
            prop_assert_eq!(decoded.segment_hash, footer.segment_hash);
        }
    }
}
