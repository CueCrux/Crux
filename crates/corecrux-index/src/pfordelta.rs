// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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

    let count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut deltas = Vec::with_capacity(count);
    let mut cursor = 4usize;

    while deltas.len() < count {
        let remaining = count - deltas.len();
        let block_len = remaining.min(BLOCK_SIZE);
        cursor = decode_block(data, cursor, block_len, &mut deltas);
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
    let packed_bytes = ((block_len as u32) * (bit_width as u32) + 7) / 8;
    let pack_start = out.len();
    out.resize(pack_start + packed_bytes as usize, 0);

    for (i, &d) in deltas.iter().enumerate() {
        let val = if d > max_val { 0 } else { d };
        let bit_offset = i as u32 * bit_width as u32;
        let byte_offset = (bit_offset / 8) as usize;
        let bit_shift = (bit_offset % 8) as u32;

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
    let packed_bytes = ((block_len as u32) * bit_width + 7) / 8;

    if cursor + packed_bytes as usize > data.len() {
        return data.len();
    }

    let pack_start = cursor;

    // Unpack values
    let mut values = Vec::with_capacity(block_len);
    for i in 0..block_len {
        let bit_offset = i as u32 * bit_width;
        let byte_offset = (bit_offset / 8) as usize;
        let bit_shift = (bit_offset % 8) as u32;

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
}
