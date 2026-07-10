// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! v1 frame codec (`FRAME_MAGIC_CRX1`) — header-bytes + payload-bytes wrapped with magic, version, and lengths.

use crate::util::{read_u16, read_u32};
use crate::{FrameV1Decoded, Result, SegmentError, FRAME_MAGIC_CRX1, FRAME_VERSION_V1};

pub fn encode_frame_v1(header_bytes: &[u8], payload_bytes: &[u8]) -> Result<Vec<u8>> {
    if header_bytes.len() > u16::MAX as usize {
        return Err(SegmentError::LengthOutOfRange {
            msg: format!("header too large: {} bytes", header_bytes.len()),
        });
    }
    if payload_bytes.len() > u32::MAX as usize {
        return Err(SegmentError::LengthOutOfRange {
            msg: format!("payload too large: {} bytes", payload_bytes.len()),
        });
    }

    let header_len = header_bytes.len() as u16;
    let payload_len = payload_bytes.len() as u32;

    let mut out = Vec::with_capacity(4 + 2 + 2 + 4 + header_bytes.len() + payload_bytes.len() + 4);
    out.extend_from_slice(&FRAME_MAGIC_CRX1.to_le_bytes());
    out.extend_from_slice(&FRAME_VERSION_V1.to_le_bytes());
    out.extend_from_slice(&header_len.to_le_bytes());
    out.extend_from_slice(&payload_len.to_le_bytes());
    out.extend_from_slice(header_bytes);
    out.extend_from_slice(payload_bytes);

    let crc = crc32fast::hash(payload_bytes);
    out.extend_from_slice(&crc.to_le_bytes());
    Ok(out)
}

pub fn decode_frame_v1(frame_bytes: &[u8]) -> Result<FrameV1Decoded> {
    if frame_bytes.len() < 4 + 2 + 2 + 4 + 4 {
        return Err(SegmentError::BufferTooSmall);
    }
    let magic = read_u32(frame_bytes, 0)?;
    if magic != FRAME_MAGIC_CRX1 {
        return Err(SegmentError::InvalidMagic {
            expected: FRAME_MAGIC_CRX1,
            actual: magic,
        });
    }
    let ver = read_u16(frame_bytes, 4)?;
    if ver != FRAME_VERSION_V1 {
        return Err(SegmentError::LengthOutOfRange {
            msg: format!("unsupported frame version: {ver}"),
        });
    }

    let header_len = read_u16(frame_bytes, 6)? as usize;
    let payload_len = read_u32(frame_bytes, 8)? as usize;

    let header_off = 12usize;
    let payload_off = header_off.checked_add(header_len).ok_or(SegmentError::BufferTooSmall)?;
    let crc_off = payload_off
        .checked_add(payload_len)
        .ok_or(SegmentError::BufferTooSmall)?;
    let end = crc_off.checked_add(4).ok_or(SegmentError::BufferTooSmall)?;
    if end > frame_bytes.len() {
        return Err(SegmentError::BufferTooSmall);
    }

    let header_bytes = frame_bytes[header_off..payload_off].to_vec();
    let payload_bytes = frame_bytes[payload_off..crc_off].to_vec();
    let crc = read_u32(frame_bytes, crc_off)?;
    let expected = crc32fast::hash(&payload_bytes);
    if crc != expected {
        return Err(SegmentError::CrcMismatch { expected, actual: crc });
    }

    Ok(FrameV1Decoded {
        header_bytes,
        payload_bytes,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::FRAME_MAGIC_CRX1;

    #[test]
    fn frame_roundtrip() {
        let hdr = b"header-bytes";
        let payload = b"payload";
        let enc = encode_frame_v1(hdr, payload).unwrap();
        let dec = decode_frame_v1(&enc).unwrap();
        assert_eq!(dec.header_bytes, hdr);
        assert_eq!(dec.payload_bytes, payload);
    }

    #[test]
    fn frame_decode_buffer_too_small() {
        let err = decode_frame_v1(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, SegmentError::BufferTooSmall));
    }

    #[test]
    fn frame_decode_bad_magic() {
        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let err = decode_frame_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::InvalidMagic { .. }));
    }

    #[test]
    fn frame_decode_bad_version() {
        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(&FRAME_MAGIC_CRX1.to_le_bytes());
        buf[4..6].copy_from_slice(&99u16.to_le_bytes()); // bad version
        let err = decode_frame_v1(&buf).unwrap_err();
        assert!(matches!(err, SegmentError::LengthOutOfRange { .. }));
    }

    #[test]
    fn frame_decode_crc_mismatch() {
        let encoded = encode_frame_v1(b"hdr", b"payload").unwrap();
        let mut corrupted = encoded.clone();
        // Corrupt a payload byte (payload starts at offset 12 + header_len = 12 + 3 = 15)
        corrupted[15] ^= 0xFF;
        let err = decode_frame_v1(&corrupted).unwrap_err();
        assert!(matches!(err, SegmentError::CrcMismatch { .. }));
    }

    #[test]
    fn frame_decode_truncated_payload() {
        let encoded = encode_frame_v1(b"hdr", b"long payload here!").unwrap();
        let truncated = &encoded[..encoded.len() - 8];
        let err = decode_frame_v1(truncated).unwrap_err();
        assert!(matches!(err, SegmentError::BufferTooSmall));
    }

    #[test]
    fn encode_frame_rejects_oversized_header() {
        let header = vec![0u8; (u16::MAX as usize) + 1];
        let err = encode_frame_v1(&header, b"payload").unwrap_err();
        assert!(matches!(err, SegmentError::LengthOutOfRange { .. }));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod proptest_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn frame_encode_decode_roundtrip(
            header_bytes in prop::collection::vec(any::<u8>(), 0..512),
            payload_bytes in prop::collection::vec(any::<u8>(), 0..1024),
        ) {
            let encoded = encode_frame_v1(&header_bytes, &payload_bytes).unwrap();
            let decoded = decode_frame_v1(&encoded).unwrap();
            prop_assert_eq!(&decoded.header_bytes, &header_bytes);
            prop_assert_eq!(&decoded.payload_bytes, &payload_bytes);
        }
    }
}
