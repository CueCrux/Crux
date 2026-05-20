// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Per-block bloom-filter helpers — inserts/queries stream-hashes for fast segment-skip during retrieval.

use xxhash_rust::xxh64::xxh64;

use crate::BLOOM_BYTES_PER_BLOCK_V1;

pub fn bloom_insert_stream_hash_v1(bits: &mut [u8; BLOOM_BYTES_PER_BLOCK_V1], bloom_hash_k: u32, stream_hash: u64) {
    let key = stream_hash.to_le_bytes();
    let m = (BLOOM_BYTES_PER_BLOCK_V1 as u64) * 8;
    for seed in 0..bloom_hash_k {
        let h = xxh64(&key, seed as u64);
        let bit = (h % m) as usize;
        let byte = bit / 8;
        let mask = 1u8 << (bit % 8);
        bits[byte] |= mask;
    }
}

pub fn bloom_maybe_contains_stream_hash_v1(
    bits: &[u8; BLOOM_BYTES_PER_BLOCK_V1],
    bloom_hash_k: u32,
    stream_hash: u64,
) -> bool {
    let key = stream_hash.to_le_bytes();
    let m = (BLOOM_BYTES_PER_BLOCK_V1 as u64) * 8;
    for seed in 0..bloom_hash_k {
        let h = xxh64(&key, seed as u64);
        let bit = (h % m) as usize;
        let byte = bit / 8;
        let mask = 1u8 << (bit % 8);
        if (bits[byte] & mask) == 0 {
            return false;
        }
    }
    true
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::BLOOM_HASH_K_V1;

    #[test]
    fn bloom_insert_and_query() {
        let mut bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];
        bloom_insert_stream_hash_v1(&mut bloom, BLOOM_HASH_K_V1, 0x12345);
        bloom_insert_stream_hash_v1(&mut bloom, BLOOM_HASH_K_V1, 0xABCDE);

        assert!(bloom_maybe_contains_stream_hash_v1(&bloom, BLOOM_HASH_K_V1, 0x12345));
        assert!(bloom_maybe_contains_stream_hash_v1(&bloom, BLOOM_HASH_K_V1, 0xABCDE));
        // Empty bloom should not match a random hash (with high probability)
        let empty_bloom = [0u8; BLOOM_BYTES_PER_BLOCK_V1];
        assert!(!bloom_maybe_contains_stream_hash_v1(
            &empty_bloom,
            BLOOM_HASH_K_V1,
            0x12345
        ));
    }
}
