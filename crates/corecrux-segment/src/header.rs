// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! v1 segment header codec — magic `CCS3`, segment id, version (`SEGMENT_MAJOR/MINOR`), flags.

use crate::util::{read_u16, read_u32, read_u64};
use crate::{
    Result, SegmentError, SegmentHeaderV1, SegmentId, SEGMENT_HEADER_LEN, SEGMENT_MAGIC_CCS3, SEGMENT_MAJOR,
    SEGMENT_MINOR,
};

pub fn encode_segment_header_v1(h: &SegmentHeaderV1) -> Result<Vec<u8>> {
    let mut out = vec![0u8; SEGMENT_HEADER_LEN];
    out[0..4].copy_from_slice(&SEGMENT_MAGIC_CCS3.to_le_bytes());
    out[4..6].copy_from_slice(&SEGMENT_MAJOR.to_le_bytes());
    out[6..8].copy_from_slice(&SEGMENT_MINOR.to_le_bytes());
    out[8..12].copy_from_slice(&(SEGMENT_HEADER_LEN as u32).to_le_bytes());
    out[12..16].copy_from_slice(&h.flags.to_le_bytes());
    out[16..20].copy_from_slice(&h.shard_id.to_le_bytes());
    out[20..28].copy_from_slice(&h.epoch.to_le_bytes());
    out[28..36].copy_from_slice(&h.segment_seq.to_le_bytes());
    out[36..52].copy_from_slice(&h.segment_id.0);
    out[52..60].copy_from_slice(&h.created_at_unix_ns.to_le_bytes());

    let crc = crc32c::crc32c(&out[..SEGMENT_HEADER_LEN - 4]);
    out[SEGMENT_HEADER_LEN - 4..].copy_from_slice(&crc.to_le_bytes());
    Ok(out)
}

pub fn decode_segment_header_v1(bytes: &[u8]) -> Result<SegmentHeaderV1> {
    if bytes.len() < SEGMENT_HEADER_LEN {
        return Err(SegmentError::BufferTooSmall);
    }
    let magic = read_u32(bytes, 0)?;
    if magic != SEGMENT_MAGIC_CCS3 {
        return Err(SegmentError::InvalidMagic {
            expected: SEGMENT_MAGIC_CCS3,
            actual: magic,
        });
    }
    let major = read_u16(bytes, 4)?;
    let minor = read_u16(bytes, 6)?;
    if major != SEGMENT_MAJOR || minor != SEGMENT_MINOR {
        return Err(SegmentError::UnsupportedSegmentVersion { major, minor });
    }
    let header_len = read_u32(bytes, 8)? as usize;
    if header_len != SEGMENT_HEADER_LEN {
        return Err(SegmentError::LengthOutOfRange {
            msg: format!("header_len expected {SEGMENT_HEADER_LEN}, got {header_len}"),
        });
    }

    let expected = read_u32(bytes, SEGMENT_HEADER_LEN - 4)?;
    let actual = crc32c::crc32c(&bytes[..SEGMENT_HEADER_LEN - 4]);
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

    Ok(SegmentHeaderV1 {
        flags,
        shard_id,
        epoch,
        segment_seq,
        segment_id: SegmentId(seg_id),
        created_at_unix_ns,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn segment_header_roundtrip() {
        let hdr = SegmentHeaderV1 {
            flags: 1,
            shard_id: 42,
            epoch: 7,
            segment_seq: 99,
            segment_id: SegmentId([0xAA; 16]),
            created_at_unix_ns: 1_700_000_000_000_000_000,
        };
        let bytes = encode_segment_header_v1(&hdr).unwrap();
        assert_eq!(bytes.len(), SEGMENT_HEADER_LEN);
        let decoded = decode_segment_header_v1(&bytes).unwrap();
        assert_eq!(decoded.flags, 1);
        assert_eq!(decoded.shard_id, 42);
        assert_eq!(decoded.epoch, 7);
        assert_eq!(decoded.segment_seq, 99);
        assert_eq!(decoded.segment_id, SegmentId([0xAA; 16]));
        assert_eq!(decoded.created_at_unix_ns, 1_700_000_000_000_000_000);
    }

    #[test]
    fn segment_header_decode_bad_magic() {
        let mut buf = vec![0u8; SEGMENT_HEADER_LEN];
        buf[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        let err = decode_segment_header_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::InvalidMagic { .. }));
    }

    #[test]
    fn segment_header_decode_bad_version() {
        let mut buf = vec![0u8; SEGMENT_HEADER_LEN];
        buf[0..4].copy_from_slice(&SEGMENT_MAGIC_CCS3.to_le_bytes());
        buf[4..6].copy_from_slice(&99u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0u16.to_le_bytes());
        let err = decode_segment_header_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::UnsupportedSegmentVersion { .. }));
    }

    #[test]
    fn segment_header_decode_crc_mismatch() {
        let hdr = SegmentHeaderV1 {
            flags: 1,
            shard_id: 0,
            epoch: 1,
            segment_seq: 1,
            segment_id: SegmentId([1u8; 16]),
            created_at_unix_ns: 1,
        };
        let mut bytes = encode_segment_header_v1(&hdr).unwrap();
        // Corrupt a byte in the header body
        bytes[20] ^= 0xFF;
        let err = decode_segment_header_v1(&bytes).unwrap_err();
        assert!(matches!(err, SegmentError::CrcMismatch { .. }));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn segment_header_encode_decode_roundtrip(
            flags in any::<u32>(),
            shard_id in any::<u32>(),
            epoch in any::<u64>(),
            segment_seq in any::<u64>(),
            segment_id_bytes in prop::array::uniform16(any::<u8>()),
            created_at_unix_ns in any::<u64>(),
        ) {
            let header = SegmentHeaderV1 {
                flags,
                shard_id,
                epoch,
                segment_seq,
                segment_id: SegmentId(segment_id_bytes),
                created_at_unix_ns,
            };
            let encoded = encode_segment_header_v1(&header).unwrap();
            let decoded = decode_segment_header_v1(&encoded).unwrap();
            prop_assert_eq!(decoded.flags, header.flags);
            prop_assert_eq!(decoded.shard_id, header.shard_id);
            prop_assert_eq!(decoded.epoch, header.epoch);
            prop_assert_eq!(decoded.segment_seq, header.segment_seq);
            prop_assert_eq!(decoded.segment_id, header.segment_id);
            prop_assert_eq!(decoded.created_at_unix_ns, header.created_at_unix_ns);
        }
    }
}
