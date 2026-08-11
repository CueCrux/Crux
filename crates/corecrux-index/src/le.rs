// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Little-endian scalar reads and CRC32C, shared by the ported companion readers.
//!
//! Every CoreCrux `ccx*.rs` container carries its own private copy of `crc32c` and
//! parses scalars with `u32::from_le_bytes(data[a..b].try_into().unwrap())`. Neither
//! form survives the port unchanged:
//!
//! - `unwrap()` is `clippy::unwrap_used` (warn, and CI is `-D warnings`) and counts
//!   against this crate's `scripts/unwrap-baseline.txt` ratchet, which allows 3
//!   production sites for the whole crate. Seven readers' worth of `try_into().unwrap()`
//!   would be several hundred.
//! - Eight byte-identical copies of a CRC routine is eight places for a
//!   transcription slip to hide, in the function that decides whether a companion
//!   is trusted at all.
//!
//! The readers bounds-check their whole buffer against the header's declared section
//! lengths before touching any of these, so the slice indexing here is reached only
//! with an offset the caller has already proven in range.

/// Read a little-endian `u16` at `offset`.
pub(crate) fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Read a little-endian `u32` at `offset`.
pub(crate) fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

/// Read a little-endian `u64` at `offset`.
pub(crate) fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
        data[offset + 4],
        data[offset + 5],
        data[offset + 6],
        data[offset + 7],
    ])
}

/// Read a little-endian `f32` at `offset`.
pub(crate) fn read_f32(data: &[u8], offset: usize) -> f32 {
    f32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

/// CRC32C (Castagnoli, reversed polynomial `0x82F6_3B78`).
///
/// The footer checksum of every ported companion container. Bit-for-bit the
/// routine each CoreCrux `ccx*.rs` carries privately; the fixtures in
/// `tests/fixtures/` are what prove the two still agree.
pub(crate) fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F6_3B78;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_reads_are_little_endian() {
        let data = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u16(&data, 0), 0x0201);
        assert_eq!(read_u32(&data, 0), 0x0403_0201);
        assert_eq!(read_u64(&data, 0), 0x0807_0605_0403_0201);
    }

    #[test]
    fn scalar_reads_honour_the_offset() {
        let data = [0xFFu8, 0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_u16(&data, 1), 0x0201);
        assert_eq!(read_u32(&data, 1), 0x0403_0201);
    }

    /// CRC32C check value: the Castagnoli residue of "123456789" is `0xE3069283`.
    /// Pinning the standard vector is what makes the shared copy provably the same
    /// function the eight CoreCrux containers each carry.
    #[test]
    fn crc32c_matches_the_standard_check_vector() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn crc32c_of_empty_input_is_zero() {
        assert_eq!(crc32c(b""), 0);
    }
}
