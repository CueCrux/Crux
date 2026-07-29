// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Companion-file builders (`.ccxi` inverted index, etc.) invoked at seal time alongside `.ccxseg`.

use super::{fsync_dir, hex16, io_err, Result};
use std::path::Path;

// ---------------------------------------------------------------------------
// CoreCrux v5: .ccxi companion index builder (called at seal time)
// ---------------------------------------------------------------------------

/// Build a `.ccxi` companion inverted index from a sealed segment's record area.
///
/// Iterates all frames in the segment, decodes each frame to extract the payload,
/// tokenizes the payload text, and feeds it to [`CcxiBuilder`]. The resulting
/// `.ccxi` file is written atomically alongside the `.ccxseg` file.
///
/// Non-fatal: returns `Err` on failure but the sealed segment remains valid.
// SAFETY: try_into().unwrap() on fixed-size byte slices with matching array length.
#[allow(clippy::unwrap_used)]
pub(crate) fn build_ccxi_companion(
    shard_dir: &Path,
    shard_id: u32,
    epoch: u64,
    segment_seq: u64,
    segment_id: &corecrux_segment::SegmentId,
    record_area: &[u8],
    metas: &[corecrux_segment::FrameMetaV1],
) -> Result<()> {
    use corecrux_index::CcxiBuilder;

    let mut builder = CcxiBuilder::new(shard_id, segment_seq, epoch);
    let mut indexed_count = 0u32;

    for (doc_id, meta) in metas.iter().enumerate() {
        let off = meta.record_off as usize;
        let end = off + meta.frame_len as usize;
        if end > record_area.len() {
            continue; // skip malformed frame
        }
        let frame_bytes = &record_area[off..end];

        // Decode frame to extract payload bytes.
        // Frame layout: magic(4) + ver(2) + header_len(2) + payload_len(4) + header + payload + crc(4)
        if frame_bytes.len() < 12 {
            continue;
        }
        let header_len = u16::from_le_bytes([frame_bytes[6], frame_bytes[7]]) as usize;
        let payload_len =
            u32::from_le_bytes([frame_bytes[8], frame_bytes[9], frame_bytes[10], frame_bytes[11]]) as usize;
        let payload_start = 12 + header_len;
        let payload_end = payload_start + payload_len;
        if payload_end > frame_bytes.len() {
            continue;
        }
        let payload = &frame_bytes[payload_start..payload_end];

        // Attempt to interpret payload as UTF-8 text for indexing.
        // Binary/CBOR payloads are silently skipped (non-indexable).
        let text = match std::str::from_utf8(payload) {
            Ok(t) if !t.is_empty() => t,
            _ => continue,
        };

        // Extract tenant_id from frame header, hash it for .ccxi tenant filter.
        // This ensures query-time xxh64(tenant_id) matches the stored lo16 bits.
        let header_bytes = &frame_bytes[12..12 + header_len];
        let tenant_hash = match corecrux_frame::decode_canonical_header_bytes_v1(header_bytes) {
            Ok(hdr) => xxhash_rust::xxh64::xxh64(hdr.tenant_id.as_bytes(), 0),
            Err(_) => meta.stream_hash, // fallback to stream_hash if header decode fails
        };

        builder.add_document(doc_id as u32, text, meta.record_off, tenant_hash);
        indexed_count += 1;
    }

    if indexed_count == 0 {
        tracing::debug!(segment_seq, "ccxi-companion-skip-no-indexable-frames");
        return Ok(());
    }

    let ccxi_bytes = builder.build();
    let ccxi_hash = *blake3::hash(&ccxi_bytes).as_bytes();

    // Atomic write: tmp → final
    let id_hex = hex16(&segment_id.0);
    let tmp_path = shard_dir.join(format!("tmp/seg-{segment_seq:020}-{id_hex}.ccxi.partial"));
    let final_path = shard_dir.join(format!("segments/seg-{segment_seq:020}-{id_hex}.ccxi"));

    std::fs::write(&tmp_path, &ccxi_bytes).map_err(io_err)?;
    std::fs::rename(&tmp_path, &final_path).map_err(io_err)?;
    fsync_dir(&shard_dir.join("segments"))?;

    tracing::info!(
        segment_seq,
        indexed_count,
        vocab_size = builder.vocab_size(),
        ccxi_bytes = ccxi_bytes.len(),
        ccxi_hash = %format!("{:016x}{:016x}", u64::from_le_bytes(ccxi_hash[0..8].try_into().unwrap()), u64::from_le_bytes(ccxi_hash[8..16].try_into().unwrap())),
        "ccxi-companion-built"
    );

    Ok(())
}
