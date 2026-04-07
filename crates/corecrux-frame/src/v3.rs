// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! CoreCrux v3 frame encoding and decoding.
//!
//! ## Architecture
//!
//! The v3 frame format is the on-disk encoding for all CoreCrux events. Each frame
//! contains a header (with BLAKE3 integrity hashes) and an LZ4-compressed payload.
//!
//! Key types:
//! - [`EventHeaderV3`] — per-event header with tenant, stream, sequence, and hashes
//! - [`CanonicalHeaderV1`] — deterministic header encoding for receipt signing
//!
//! Frame layout on disk:
//! ```text
//! ┌──────────────┬───────────┬──────────┐
//! │ CRX1 magic   │ Header    │ Payload  │
//! │ (4 bytes)    │ (var len) │ (LZ4)    │
//! └──────────────┴───────────┴──────────┘
//! ```
//!
//! Segments (`CCS3` magic) aggregate frames and are sealed with a table of contents
//! (`TOC1`). Sealed segments are immutable and get a companion `.ccxi` index.

use thiserror::Error;
use xxhash_rust::xxh64::xxh64;

pub const CANONICAL_HEADER_V1_TAG: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventHeaderV3 {
    pub tenant_id: String,
    pub stream_id: String,
    pub stream_type: String,
    pub seq: u64,
    pub event_id: String,
    pub occurred_at: String,
    pub ingested_at: String,
    pub event_type: String,
    pub content_type: String,
    pub payload_len: u32,
    pub payload_hash: [u8; 32],
    pub header_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalHeaderV1 {
    pub tenant_id: String,
    pub stream_id: String,
    pub stream_type: String,
    pub seq: u64,
    pub event_id: String,
    pub occurred_at: String,
    pub ingested_at: String,
    pub event_type: String,
    pub content_type: String,
    pub payload_len: u32,
    pub payload_hash: [u8; 32],
}

#[derive(Debug, Error)]
pub enum DecodeHeaderError {
    #[error("buffer too small")]
    BufferTooSmall,
    #[error("unsupported canonical header tag {tag}")]
    UnsupportedTag { tag: u16 },
    #[error("invalid utf-8 in field {field}")]
    InvalidUtf8 { field: &'static str },
    #[error("declared length out of bounds for field {field}")]
    DeclaredLenOutOfBounds { field: &'static str },
}

#[derive(Debug, Error)]
pub enum StreamHashError {
    #[error("input contains NUL byte in field {field}")]
    NulByte { field: &'static str },
    #[error("input is empty in field {field}")]
    Empty { field: &'static str },
    #[error("input has leading/trailing whitespace in field {field}")]
    Whitespace { field: &'static str },
}

pub fn compute_payload_hash(payload: &[u8]) -> [u8; 32] {
    *blake3::hash(payload).as_bytes()
}

pub fn compute_header_hash(canonical_header_bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(canonical_header_bytes).as_bytes()
}

pub fn canonical_header_bytes_v1(header: &CanonicalHeaderV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&CANONICAL_HEADER_V1_TAG.to_le_bytes());

    // Fixed field order. Strings are u32_le length + UTF-8 bytes.
    write_str(&mut out, &header.tenant_id);
    write_str(&mut out, &header.stream_id);
    write_str(&mut out, &header.stream_type);

    out.extend_from_slice(&header.seq.to_le_bytes());

    write_str(&mut out, &header.event_id);
    write_str(&mut out, &header.occurred_at);
    write_str(&mut out, &header.ingested_at);
    write_str(&mut out, &header.event_type);
    write_str(&mut out, &header.content_type);

    out.extend_from_slice(&header.payload_len.to_le_bytes());
    out.extend_from_slice(&header.payload_hash);

    out
}

pub fn decode_canonical_header_bytes_v1(input: &[u8]) -> Result<CanonicalHeaderV1, DecodeHeaderError> {
    let mut cursor = 0usize;
    let tag = read_u16(input, &mut cursor)?;
    if tag != CANONICAL_HEADER_V1_TAG {
        return Err(DecodeHeaderError::UnsupportedTag { tag });
    }

    let tenant_id = read_str(input, &mut cursor, "tenant_id")?;
    let stream_id = read_str(input, &mut cursor, "stream_id")?;
    let stream_type = read_str(input, &mut cursor, "stream_type")?;

    let seq = read_u64(input, &mut cursor)?;

    let event_id = read_str(input, &mut cursor, "event_id")?;
    let occurred_at = read_str(input, &mut cursor, "occurred_at")?;
    let ingested_at = read_str(input, &mut cursor, "ingested_at")?;
    let event_type = read_str(input, &mut cursor, "event_type")?;
    let content_type = read_str(input, &mut cursor, "content_type")?;

    let payload_len = read_u32(input, &mut cursor)?;
    let payload_hash = read_32(input, &mut cursor)?;

    Ok(CanonicalHeaderV1 {
        tenant_id,
        stream_id,
        stream_type,
        seq,
        event_id,
        occurred_at,
        ingested_at,
        event_type,
        content_type,
        payload_len,
        payload_hash,
    })
}

pub fn stream_hash_xxhash64(tenant_id: &str, stream_type: &str, stream_id: &str) -> Result<u64, StreamHashError> {
    if tenant_id.is_empty() {
        return Err(StreamHashError::Empty { field: "tenant_id" });
    }
    if stream_type.is_empty() {
        return Err(StreamHashError::Empty { field: "stream_type" });
    }
    if stream_id.is_empty() {
        return Err(StreamHashError::Empty { field: "stream_id" });
    }

    if tenant_id.trim() != tenant_id {
        return Err(StreamHashError::Whitespace { field: "tenant_id" });
    }
    if stream_type.trim() != stream_type {
        return Err(StreamHashError::Whitespace { field: "stream_type" });
    }
    if stream_id.trim() != stream_id {
        return Err(StreamHashError::Whitespace { field: "stream_id" });
    }

    if tenant_id.as_bytes().contains(&0) {
        return Err(StreamHashError::NulByte { field: "tenant_id" });
    }
    if stream_type.as_bytes().contains(&0) {
        return Err(StreamHashError::NulByte { field: "stream_type" });
    }
    if stream_id.as_bytes().contains(&0) {
        return Err(StreamHashError::NulByte { field: "stream_id" });
    }

    let mut key = Vec::with_capacity(tenant_id.len() + stream_type.len() + stream_id.len() + 2);
    key.extend_from_slice(tenant_id.as_bytes());
    key.push(0);
    key.extend_from_slice(stream_type.as_bytes());
    key.push(0);
    key.extend_from_slice(stream_id.as_bytes());

    Ok(xxh64(&key, 0))
}

fn write_str(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let len = bytes.len() as u32;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

fn read_u16(input: &[u8], cursor: &mut usize) -> Result<u16, DecodeHeaderError> {
    let end = cursor.checked_add(2).ok_or(DecodeHeaderError::BufferTooSmall)?;
    if end > input.len() {
        return Err(DecodeHeaderError::BufferTooSmall);
    }
    let mut buf = [0u8; 2];
    buf.copy_from_slice(&input[*cursor..end]);
    *cursor = end;
    Ok(u16::from_le_bytes(buf))
}

fn read_u32(input: &[u8], cursor: &mut usize) -> Result<u32, DecodeHeaderError> {
    let end = cursor.checked_add(4).ok_or(DecodeHeaderError::BufferTooSmall)?;
    if end > input.len() {
        return Err(DecodeHeaderError::BufferTooSmall);
    }
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&input[*cursor..end]);
    *cursor = end;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64(input: &[u8], cursor: &mut usize) -> Result<u64, DecodeHeaderError> {
    let end = cursor.checked_add(8).ok_or(DecodeHeaderError::BufferTooSmall)?;
    if end > input.len() {
        return Err(DecodeHeaderError::BufferTooSmall);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&input[*cursor..end]);
    *cursor = end;
    Ok(u64::from_le_bytes(buf))
}

fn read_32(input: &[u8], cursor: &mut usize) -> Result<[u8; 32], DecodeHeaderError> {
    let end = cursor.checked_add(32).ok_or(DecodeHeaderError::BufferTooSmall)?;
    if end > input.len() {
        return Err(DecodeHeaderError::BufferTooSmall);
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&input[*cursor..end]);
    *cursor = end;
    Ok(buf)
}

fn read_str(input: &[u8], cursor: &mut usize, field: &'static str) -> Result<String, DecodeHeaderError> {
    let len = read_u32(input, cursor)? as usize;
    let end = cursor
        .checked_add(len)
        .ok_or(DecodeHeaderError::DeclaredLenOutOfBounds { field })?;
    if end > input.len() {
        return Err(DecodeHeaderError::DeclaredLenOutOfBounds { field });
    }
    let bytes = &input[*cursor..end];
    let value = std::str::from_utf8(bytes).map_err(|_| DecodeHeaderError::InvalidUtf8 { field })?;
    *cursor = end;
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_hash_is_stable() {
        let a = stream_hash_xxhash64("tenant", "answers", "stream-1").unwrap();
        let b = stream_hash_xxhash64("tenant", "answers", "stream-1").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn stream_hash_rejects_nul() {
        let err = stream_hash_xxhash64("te\0nant", "answers", "stream-1").unwrap_err();
        assert!(matches!(err, StreamHashError::NulByte { field: "tenant_id" }));
    }

    #[test]
    fn stream_hash_rejects_empty() {
        let err = stream_hash_xxhash64("", "answers", "stream-1").unwrap_err();
        assert!(matches!(err, StreamHashError::Empty { field: "tenant_id" }));
    }

    #[test]
    fn stream_hash_rejects_leading_whitespace() {
        let err = stream_hash_xxhash64(" tenant", "answers", "stream-1").unwrap_err();
        assert!(matches!(err, StreamHashError::Whitespace { field: "tenant_id" }));
    }

    #[test]
    fn canonical_header_roundtrip_is_stable() {
        let payload_hash = compute_payload_hash(b"payload-bytes");
        let header = CanonicalHeaderV1 {
            tenant_id: "tenant-a".to_string(),
            stream_id: "stream-1".to_string(),
            stream_type: "answers".to_string(),
            seq: 42,
            event_id: "evt-1".to_string(),
            occurred_at: "2026-02-07T00:00:00Z".to_string(),
            ingested_at: "2026-02-07T00:00:00Z".to_string(),
            event_type: "test.event".to_string(),
            content_type: "application/octet-stream".to_string(),
            payload_len: 12,
            payload_hash,
        };

        let bytes = canonical_header_bytes_v1(&header);
        let decoded = decode_canonical_header_bytes_v1(&bytes).unwrap();
        let bytes2 = canonical_header_bytes_v1(&decoded);
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn stream_hash_golden_vectors() {
        let vectors: [(&str, &str, &str, u64); 5] = [
            ("tenant", "answers", "stream-1", 0x20466e5a67246fcc),
            ("system", "corecrux", "routing", 0xa1bd681575d90236),
            ("tenant-a", "receipt", "REC_0001", 0x0becae63d4163ce5),
            ("t", "s", "i", 0xc914fbcba10ad4bc),
            ("tenant-123", "events", "stream-00000001", 0x7742a907f2ffad91),
        ];

        for (tenant, stype, sid, expected) in vectors {
            let got = stream_hash_xxhash64(tenant, stype, sid).unwrap();
            assert_eq!(got, expected, "golden mismatch for {tenant}|{stype}|{sid}");
        }
    }
}
