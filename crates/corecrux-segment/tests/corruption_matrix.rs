// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Whole-segment corruption matrix (ExecPlan `crux-storage-fault-hardening-2026-06-11`, M1).
//!
//! Every case must yield a **typed `SegmentError`** from `decode_segment_v1` —
//! never a panic and never a silent success. Unit-level codec negatives
//! (header/frame/footer magic, version, CRC, truncation) live next to their
//! codecs in `src/`; this suite attacks the assembled `.ccxseg` byte stream
//! the way on-disk corruption would.

#![allow(clippy::unwrap_used, clippy::panic)]

use corecrux_segment::{
    build_segment_v1, decode_segment_v1, encode_segment_footer_v1, FrameInput, SegmentBuildOutput, SegmentError,
    SegmentId, SEGMENT_FOOTER_LEN, SEGMENT_HEADER_LEN,
};

fn sample_segment() -> SegmentBuildOutput {
    build_segment_v1(
        7,
        3,
        11,
        SegmentId([0xA5; 16]),
        1_700_000_000_000_000_000,
        1_700_000_000_000_000_999,
        &[
            FrameInput {
                stream_hash: 1,
                seq: 1,
                event_id: "evt-1",
                header_hash: [0x11; 32],
                payload_hash: [0x21; 32],
                header_bytes: b"hdr-1",
                payload_bytes: b"payload-one",
            },
            FrameInput {
                stream_hash: 1,
                seq: 2,
                event_id: "evt-2",
                header_hash: [0x12; 32],
                payload_hash: [0x22; 32],
                header_bytes: b"hdr-2",
                payload_bytes: b"payload-two-longer",
            },
            FrameInput {
                stream_hash: 9,
                seq: 1,
                event_id: "evt-3",
                header_hash: [0x13; 32],
                payload_hash: [0x23; 32],
                header_bytes: b"hdr-3",
                payload_bytes: b"payload-three",
            },
        ],
    )
    .unwrap()
}

/// Re-encode a (possibly tampered) footer with a *valid* CRC and splice it in,
/// so checks deeper than the footer CRC are exercised.
fn splice_footer(bytes: &mut [u8], footer: &corecrux_segment::SegmentFooterV1) {
    let encoded = encode_segment_footer_v1(footer).unwrap();
    let start = bytes.len() - SEGMENT_FOOTER_LEN;
    bytes[start..].copy_from_slice(&encoded);
}

// ── Header attacks ───────────────────────────────────────────────────────────

#[test]
fn segment_header_magic_corruption_is_invalid_magic() {
    let out = sample_segment();
    let mut bytes = out.bytes.clone();
    bytes[0] ^= 0xFF;
    let err = decode_segment_v1(&bytes).unwrap_err();
    assert!(matches!(err, SegmentError::InvalidMagic { .. }), "got {err:?}");
}

#[test]
fn segment_header_version_corruption_is_unsupported_version() {
    let out = sample_segment();
    let mut bytes = out.bytes.clone();
    // major version lives at header offset 4..6 and is checked before the header CRC.
    bytes[4] = 0x63;
    bytes[5] = 0x00;
    let err = decode_segment_v1(&bytes).unwrap_err();
    assert!(
        matches!(err, SegmentError::UnsupportedSegmentVersion { .. }),
        "got {err:?}"
    );
}

#[test]
fn segment_header_field_corruption_is_crc_mismatch() {
    let out = sample_segment();
    let mut bytes = out.bytes.clone();
    // created_at_unix_ns (offset 52..60): CRC-covered, not part of magic/version/len.
    bytes[53] ^= 0xFF;
    let err = decode_segment_v1(&bytes).unwrap_err();
    assert!(matches!(err, SegmentError::CrcMismatch { .. }), "got {err:?}");
}

// ── Record-area / TOC attacks ────────────────────────────────────────────────

#[test]
fn record_area_corruption_is_record_hash_mismatch() {
    let out = sample_segment();
    let mut bytes = out.bytes.clone();
    let record_off = out.footer.record_area_offset as usize;
    let record_len = out.footer.record_area_len as usize;
    // Flip first, middle, and last record byte — each must surface record_hash mismatch.
    for &delta in &[0usize, record_len / 2, record_len - 1] {
        let mut b = bytes.clone();
        b[record_off + delta] ^= 0xFF;
        let err = decode_segment_v1(&b).unwrap_err();
        match err {
            SegmentError::HashMismatch { ref msg } => assert!(msg.contains("record_hash"), "msg={msg}"),
            other => panic!("expected record_hash mismatch at +{delta}, got {other:?}"),
        }
    }
    // Sanity: untouched bytes still decode.
    bytes[0] ^= 0;
    decode_segment_v1(&bytes).unwrap();
}

#[test]
fn toc_payload_corruption_is_typed_error() {
    let out = sample_segment();
    let toc_off = out.footer.toc_offset as usize;
    let toc_payload_len = out.toc_header.toc_payload_len as usize;
    for &delta in &[0usize, toc_payload_len / 2, toc_payload_len - 1] {
        let mut b = out.bytes.clone();
        b[toc_off + delta] ^= 0xFF;
        let err = decode_segment_v1(&b).unwrap_err();
        // Depending on which TOC byte is hit this is a hash mismatch, a TOC-header
        // decode error, or a sort violation — all typed, none a panic or Ok.
        match err {
            SegmentError::HashMismatch { .. }
            | SegmentError::InvalidMagic { .. }
            | SegmentError::UnsupportedTocVersion { .. }
            | SegmentError::LengthOutOfRange { .. }
            | SegmentError::BufferTooSmall
            | SegmentError::CrcMismatch { .. }
            | SegmentError::TocNotSorted => {}
            other => panic!("unexpected error class at toc+{delta}: {other:?}"),
        }
    }
}

// ── Truncation / inflation ───────────────────────────────────────────────────

#[test]
fn truncated_segment_is_typed_error_at_every_cut() {
    let out = sample_segment();
    let n = out.bytes.len();
    // Cut points: 1 byte, mid-footer, whole footer, mid-TOC, mid-record, just past header.
    let cuts = [
        n - 1,
        n - SEGMENT_FOOTER_LEN / 2,
        n - SEGMENT_FOOTER_LEN,
        out.footer.toc_offset as usize + 3,
        SEGMENT_HEADER_LEN + 3,
        SEGMENT_HEADER_LEN,
    ];
    for &cut in &cuts {
        let truncated = &out.bytes[..cut];
        match decode_segment_v1(truncated) {
            Err(_) => {} // any typed SegmentError is acceptable; panics/Ok are not
            Ok(_) => panic!("truncation to {cut} bytes decoded successfully"),
        }
    }
}

#[test]
fn inflated_segment_is_file_len_mismatch() {
    let out = sample_segment();
    let mut bytes = out.bytes.clone();
    bytes.extend_from_slice(b"junk-appended-after-seal");
    let err = decode_segment_v1(&bytes).unwrap_err();
    // Appending bytes shifts where the footer is read from, so either the footer
    // no longer parses (magic/CRC) or the declared file_len disagrees.
    match err {
        SegmentError::FileLenMismatch { .. } | SegmentError::InvalidMagic { .. } | SegmentError::CrcMismatch { .. } => {
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

// ── Footer-forgery attacks (valid CRC, lying content) ────────────────────────

#[test]
fn footer_identity_forgery_is_hash_mismatch() {
    let out = sample_segment();
    let mut footer = out.footer.clone();
    footer.segment_id = SegmentId([0xEE; 16]);
    let mut bytes = out.bytes.clone();
    splice_footer(&mut bytes, &footer);
    let err = decode_segment_v1(&bytes).unwrap_err();
    match err {
        SegmentError::HashMismatch { ref msg } => assert!(msg.contains("identity"), "msg={msg}"),
        other => panic!("expected identity mismatch, got {other:?}"),
    }
}

#[test]
fn footer_file_len_forgery_is_file_len_mismatch() {
    let out = sample_segment();
    let mut footer = out.footer.clone();
    footer.file_len += 1;
    let mut bytes = out.bytes.clone();
    splice_footer(&mut bytes, &footer);
    let err = decode_segment_v1(&bytes).unwrap_err();
    assert!(matches!(err, SegmentError::FileLenMismatch { .. }), "got {err:?}");
}

#[test]
fn footer_record_hash_forgery_is_hash_mismatch() {
    let out = sample_segment();
    let mut footer = out.footer.clone();
    footer.record_hash[0] ^= 0xFF;
    let mut bytes = out.bytes.clone();
    splice_footer(&mut bytes, &footer);
    let err = decode_segment_v1(&bytes).unwrap_err();
    assert!(matches!(err, SegmentError::HashMismatch { .. }), "got {err:?}");
}

// ── Exhaustive single-byte-flip sweep ────────────────────────────────────────

/// Flip every byte of a sealed segment one at a time. For every byte that
/// `decode_segment_v1` integrity-covers, decoding must fail with a typed error.
///
/// Known, intentional exception: the CRC-table + trailer-extension region of the
/// TOC area (`toc_offset + toc_payload_len .. file_len - footer_len`) is *not*
/// hashed by `decode_segment_v1`; those bytes are validated lazily by the block
/// readers (`TrailerSectionInvalid` / per-block CRC paths). This test pins that
/// boundary exactly: if integrity coverage ever shrinks below today's envelope,
/// the sweep fails.
#[test]
fn single_byte_flip_sweep_never_panics_and_only_trailer_region_survives() {
    let out = sample_segment();
    let n = out.bytes.len();
    let uncovered_start = out.footer.toc_offset as usize + out.toc_header.toc_payload_len as usize;
    let uncovered_end = n - SEGMENT_FOOTER_LEN;
    assert!(uncovered_start <= uncovered_end);

    let mut survived: Vec<usize> = Vec::new();
    for i in 0..n {
        let mut b = out.bytes.clone();
        b[i] ^= 0xFF;
        if decode_segment_v1(&b).is_ok() {
            survived.push(i);
        }
    }

    for &i in &survived {
        assert!(
            (uncovered_start..uncovered_end).contains(&i),
            "byte {i} outside the documented trailer/crc-table region [{uncovered_start},{uncovered_end}) \
             survived a flip — integrity coverage regressed"
        );
    }
}
