// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! PForDelta compression for posting list doc_ids.
//!
//! Block size: 128 elements. Delta-encoded doc_ids compressed with a fixed bit-width
//! per block, with exceptions stored as (index, value) pairs after the block.
//!
//! On-disk format (per block):
//!   [bit_width: u8] [num_exceptions: u8] [packed_bits: ceil(128 * bit_width / 8) bytes]
//!   [exceptions: num_exceptions × (index: u8, value: u32)]
//!
//! At load time (M0-M2), we decompress fully to u32 arrays on CPU.
//! GPU-side decode is a future optimisation.

const BLOCK_SIZE: usize = 128;

/// Encode a sorted slice of doc_ids using PForDelta.
/// Returns compressed bytes.
pub fn pfordelta_encode(doc_ids: &[u32]) -> Vec<u8> {
    if doc_ids.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::with_capacity(doc_ids.len()); // rough estimate

    // Write total count as u32 LE header
    out.extend_from_slice(&(doc_ids.len() as u32).to_le_bytes());

    // Delta encode
    let mut deltas = Vec::with_capacity(doc_ids.len());
    deltas.push(doc_ids[0]);
    for i in 1..doc_ids.len() {
        deltas.push(doc_ids[i].saturating_sub(doc_ids[i - 1]));
    }

    // Process in blocks of BLOCK_SIZE
    for chunk in deltas.chunks(BLOCK_SIZE) {
        encode_block(chunk, &mut out);
    }

    out
}

/// Decode PForDelta compressed data back to sorted doc_ids.
pub fn pfordelta_decode(data: &[u8]) -> Vec<u32> {
    if data.len() < 4 {
        return Vec::new();
    }

    // SAFETY: data[0..4] is a 4-byte slice — try_into to [u8; 4] is infallible.
    #[allow(clippy::unwrap_used)]
    let declared = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;

    // `declared` is the first four bytes of whatever we were handed, so a
    // corrupt or hostile `.ccxi` can ask for `u32::MAX` values — about 17 GB —
    // straight into `Vec::with_capacity`. Clamp it to what the remaining bytes
    // could conceivably encode: a value occupies at least one bit, so
    // `8 * remaining` is a hard upper bound and a well-formed stream is always
    // far under it.
    let max_encodable = data.len().saturating_sub(4).saturating_mul(8);
    let count = declared.min(max_encodable);

    let mut deltas = Vec::with_capacity(count);
    let mut cursor = 4usize;

    while deltas.len() < count {
        let before = deltas.len();
        let remaining = count - before;
        let block_len = remaining.min(BLOCK_SIZE);
        cursor = decode_block(data, cursor, block_len, &mut deltas);

        // `decode_block` reports truncation by returning `data.len()` without
        // pushing anything, and a zero `block_len` byte likewise decodes no
        // values. Either way the loop condition cannot change, so without this
        // check a single truncated posting list spins forever and takes every
        // query on the index down with it. Stop on no progress and return what
        // decoded cleanly.
        if deltas.len() == before {
            break;
        }
    }

    // Un-delta: prefix sum
    let mut doc_ids = deltas;
    for i in 1..doc_ids.len() {
        doc_ids[i] = doc_ids[i].wrapping_add(doc_ids[i - 1]);
    }
    doc_ids
}

fn encode_block(deltas: &[u32], out: &mut Vec<u8>) {
    let block_len = deltas.len(); // may be < BLOCK_SIZE for last block

    // Find the bit width that covers 90% of values (10th percentile exception rate)
    let mut sorted = deltas.to_vec();
    sorted.sort_unstable();
    let p90_idx = (block_len * 9) / 10;
    let p90_val = sorted.get(p90_idx).copied().unwrap_or(0);
    let bit_width = if p90_val == 0 { 1 } else { 32 - p90_val.leading_zeros() } as u8;

    let max_val = if bit_width >= 32 {
        u32::MAX
    } else {
        (1u32 << bit_width) - 1
    };

    // Identify exceptions
    let mut exceptions: Vec<(u8, u32)> = Vec::new();
    for (i, &d) in deltas.iter().enumerate() {
        if d > max_val {
            exceptions.push((i as u8, d));
        }
    }

    // Write block header
    out.push(bit_width);
    out.push(exceptions.len() as u8);
    out.push(block_len as u8); // actual count in this block

    // Bit-pack the values (exceptions stored as 0 in the packed array)
    let packed_bytes = ((block_len as u32) * (bit_width as u32)).div_ceil(8);
    let pack_start = out.len();
    out.resize(pack_start + packed_bytes as usize, 0);

    for (i, &d) in deltas.iter().enumerate() {
        let val = if d > max_val { 0 } else { d };
        let bit_offset = i as u32 * bit_width as u32;
        let byte_offset = (bit_offset / 8) as usize;
        let bit_shift = bit_offset % 8;

        // Write value across potentially multiple bytes
        let mut remaining_bits = bit_width as u32;
        let mut v = val;
        let mut bo = byte_offset;
        let mut bs = bit_shift;

        while remaining_bits > 0 {
            let bits_in_byte = remaining_bits.min(8 - bs);
            let mask = ((1u32 << bits_in_byte) - 1) as u8;
            out[pack_start + bo] |= ((v as u8) & mask) << bs;
            v >>= bits_in_byte;
            remaining_bits -= bits_in_byte;
            bo += 1;
            bs = 0;
        }
    }

    // Write exceptions
    for (idx, val) in &exceptions {
        out.push(*idx);
        out.extend_from_slice(&val.to_le_bytes());
    }
}

fn decode_block(data: &[u8], mut cursor: usize, expected: usize, deltas: &mut Vec<u32>) -> usize {
    if cursor + 3 > data.len() {
        return data.len();
    }

    let bit_width = data[cursor] as u32;
    let num_exceptions = data[cursor + 1] as usize;
    let block_len = data[cursor + 2] as usize;
    cursor += 3;

    let block_len = block_len.min(expected);
    let packed_bytes = ((block_len as u32) * bit_width).div_ceil(8);

    if cursor + packed_bytes as usize > data.len() {
        return data.len();
    }

    let pack_start = cursor;

    // Unpack values
    let mut values = Vec::with_capacity(block_len);
    for i in 0..block_len {
        let bit_offset = i as u32 * bit_width;
        let byte_offset = (bit_offset / 8) as usize;
        let bit_shift = bit_offset % 8;

        let mut val = 0u32;
        let mut remaining_bits = bit_width;
        let mut bo = byte_offset;
        let mut bs = bit_shift;
        let mut shift = 0u32;

        while remaining_bits > 0 {
            let bits_in_byte = remaining_bits.min(8 - bs);
            let mask = (1u32 << bits_in_byte) - 1;
            let byte_val = if pack_start + bo < data.len() {
                data[pack_start + bo]
            } else {
                0
            };
            val |= (((byte_val >> bs) as u32) & mask) << shift;
            remaining_bits -= bits_in_byte;
            shift += bits_in_byte;
            bo += 1;
            bs = 0;
        }
        values.push(val);
    }

    cursor += packed_bytes as usize;

    // Apply exceptions
    for _ in 0..num_exceptions {
        if cursor + 5 > data.len() {
            break;
        }
        let idx = data[cursor] as usize;
        // SAFETY: data[cursor+1..cursor+5] is a 4-byte slice — try_into to [u8; 4] is infallible.
        #[allow(clippy::unwrap_used)]
        let val = u32::from_le_bytes(data[cursor + 1..cursor + 5].try_into().unwrap());
        cursor += 5;
        if idx < values.len() {
            values[idx] = val;
        }
    }

    deltas.extend_from_slice(&values);
    cursor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_empty() {
        let encoded = pfordelta_encode(&[]);
        let decoded = pfordelta_decode(&encoded);
        assert!(decoded.is_empty());
    }

    #[test]
    fn round_trip_small() {
        let ids = vec![1, 5, 10, 15, 20];
        let encoded = pfordelta_encode(&ids);
        let decoded = pfordelta_decode(&encoded);
        assert_eq!(decoded, ids);
    }

    #[test]
    fn round_trip_exact_block() {
        let ids: Vec<u32> = (0..128).map(|i| i * 3).collect();
        let encoded = pfordelta_encode(&ids);
        let decoded = pfordelta_decode(&encoded);
        assert_eq!(decoded, ids);
    }

    #[test]
    fn round_trip_multi_block() {
        let ids: Vec<u32> = (0..300).map(|i| i * 7 + 1).collect();
        let encoded = pfordelta_encode(&ids);
        let decoded = pfordelta_decode(&encoded);
        assert_eq!(decoded, ids);
    }

    #[test]
    fn round_trip_with_large_gaps() {
        // Large gaps create exceptions
        let ids = vec![1, 2, 3, 4, 5, 1000000, 1000001, 1000002];
        let encoded = pfordelta_encode(&ids);
        let decoded = pfordelta_decode(&encoded);
        assert_eq!(decoded, ids);
    }

    #[test]
    fn compression_ratio() {
        // Sequential IDs should compress well (delta=1 for most)
        let ids: Vec<u32> = (0..1000).collect();
        let encoded = pfordelta_encode(&ids);
        let raw_size = ids.len() * 4;
        assert!(
            encoded.len() < raw_size / 2,
            "expected >2x compression, got {}/{} = {:.1}x",
            raw_size,
            encoded.len(),
            raw_size as f64 / encoded.len() as f64
        );
    }

    /// A truncated posting list used to hang the whole index: `decode_block`
    /// signals truncation by returning `data.len()` and pushing nothing, so
    /// `deltas.len() < count` stayed true forever. Any query touching the
    /// segment wedged its thread.
    #[test]
    fn truncated_stream_terminates_instead_of_spinning() {
        // Header claims 500 values; the body carries one 3-byte block header
        // and then stops.
        let mut data = 500u32.to_le_bytes().to_vec();
        data.extend_from_slice(&[8, 0, 100]);
        let decoded = pfordelta_decode(&data);
        assert!(decoded.len() < 500, "a truncated stream must not report a full decode");
    }

    /// A block-length byte of zero decodes no values while still advancing the
    /// cursor — the other route to a loop that cannot make progress.
    #[test]
    fn zero_block_len_terminates() {
        let mut data = 64u32.to_le_bytes().to_vec();
        data.extend_from_slice(&[8, 0, 0, 0, 0, 0, 0]);
        let _ = pfordelta_decode(&data);
    }

    /// The header is attacker-controlled and used to reach `with_capacity`
    /// unclamped, so eleven bytes of input could reserve ~17 GB.
    ///
    /// This asserts the *capacity*, not the length or a crash. Linux overcommit
    /// happily hands back a 17 GB reservation without touching a page, so an
    /// unclamped decode returns a perfectly ordinary-looking empty Vec and any
    /// test phrased as "it didn't abort" passes with the bug still in place.
    /// The reservation itself is the observable.
    #[test]
    fn absurd_declared_count_does_not_reserve_wildly() {
        let mut data = u32::MAX.to_le_bytes().to_vec();
        data.extend_from_slice(&[8, 0, 4, 1, 1, 1, 1]);
        let decoded = pfordelta_decode(&data);
        assert!(
            decoded.capacity() <= data.len() * 8,
            "capacity {} must stay bounded by what {} bytes can encode",
            decoded.capacity(),
            data.len()
        );
    }

    /// Positive control: the guards must not change well-formed decoding.
    #[test]
    fn round_trip_survives_the_truncation_guards() {
        let ids: Vec<u32> = (0..300).map(|i| i * 7 + 1).collect();
        let encoded = pfordelta_encode(&ids);
        assert_eq!(pfordelta_decode(&encoded), ids);
    }
}
