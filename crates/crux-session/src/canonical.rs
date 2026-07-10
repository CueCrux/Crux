// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Hand-rolled canonical CBOR encoder per RFC 8949 §4.2.1 (Core Deterministic
//! Encoding). Scope is intentionally narrow: only the types reachable from
//! [`crate::plan::SessionPlan`].
//!
//! We do not use a generic CBOR library here because the TypeScript mirror
//! must produce **byte-identical** output, and stock CBOR encoders vary in
//! their map-key ordering rules and their choice of length-head encoding for
//! boundary cases.

use crate::error::SessionError;

/// Major types (RFC 8949 §3.1).
const MAJOR_UINT: u8 = 0;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;

/// Simple values (RFC 8949 §3.3).
const SIMPLE_FALSE: u8 = 0xF4;
const SIMPLE_TRUE: u8 = 0xF5;
const SIMPLE_NULL: u8 = 0xF6;

/// A canonical-CBOR value restricted to the subset our schema needs.
///
/// We build a tree of `CborValue` (no floats, no negative ints, no tags) and
/// then serialise it deterministically. The TypeScript mirror builds the same
/// tree shape and serialises with the same rules.
#[derive(Debug, Clone)]
pub enum CborValue {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    /// Ordered list of (key, value) pairs. Keys are always text strings for
    /// this schema. Caller supplies pairs in any order; `encode` sorts them
    /// canonically.
    Map(Vec<(String, CborValue)>),
    Bool(bool),
    Null,
}

impl CborValue {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        write_value(self, &mut out);
        out
    }
}

fn write_value(value: &CborValue, out: &mut Vec<u8>) {
    match value {
        CborValue::Uint(n) => write_head(MAJOR_UINT, *n, out),
        CborValue::Bytes(b) => {
            write_head(MAJOR_BYTES, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        CborValue::Text(s) => {
            let bytes = s.as_bytes();
            write_head(MAJOR_TEXT, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        CborValue::Array(items) => {
            write_head(MAJOR_ARRAY, items.len() as u64, out);
            for item in items {
                write_value(item, out);
            }
        }
        CborValue::Map(pairs) => {
            write_head(MAJOR_MAP, pairs.len() as u64, out);
            let mut indices: Vec<usize> = (0..pairs.len()).collect();
            // RFC 8949 §4.2.1: keys sorted by bytewise lex of their canonical encoding.
            // Since all keys in this schema are text, we precompute each key's encoding.
            let encoded_keys: Vec<Vec<u8>> = pairs
                .iter()
                .map(|(k, _)| {
                    let mut buf = Vec::with_capacity(k.len() + 2);
                    let bytes = k.as_bytes();
                    write_head(MAJOR_TEXT, bytes.len() as u64, &mut buf);
                    buf.extend_from_slice(bytes);
                    buf
                })
                .collect();
            indices.sort_by(|&a, &b| encoded_keys[a].cmp(&encoded_keys[b]));
            for idx in indices {
                out.extend_from_slice(&encoded_keys[idx]);
                write_value(&pairs[idx].1, out);
            }
        }
        CborValue::Bool(true) => out.push(SIMPLE_TRUE),
        CborValue::Bool(false) => out.push(SIMPLE_FALSE),
        CborValue::Null => out.push(SIMPLE_NULL),
    }
}

/// RFC 8949 §3: shortest-form head encoding. For deterministic encoding we
/// always pick the minimum-width head.
fn write_head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let prefix = major << 5;
    if arg < 24 {
        out.push(prefix | (arg as u8));
    } else if arg <= 0xFF {
        out.push(prefix | 24);
        out.push(arg as u8);
    } else if arg <= 0xFFFF {
        out.push(prefix | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xFFFF_FFFF {
        out.push(prefix | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(prefix | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

/// Minimal decoder used by tests and verifiers to re-parse canonical CBOR
/// bytes into a `CborValue` tree. Does not accept any non-canonical input:
/// indefinite-length, non-shortest heads, and tags all error.
pub fn decode(bytes: &[u8]) -> Result<CborValue, SessionError> {
    let mut cursor = Cursor { bytes, pos: 0 };
    let value = read_value(&mut cursor)?;
    if cursor.pos != bytes.len() {
        return Err(SessionError::Decode(format!("trailing bytes at offset {}", cursor.pos)));
    }
    Ok(value)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], SessionError> {
        // Overflow-safe: `n` derives from an attacker-controlled CBOR length
        // prefix and can be near usize::MAX, so `self.pos + n` would overflow
        // (a panic under overflow checks). Compare against bytes remaining.
        if n > self.remaining() {
            return Err(SessionError::Decode("unexpected eof".to_string()));
        }
        let slice = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8, SessionError> {
        Ok(self.take(1)?[0])
    }

    /// Bytes left to read. Used to bound pre-allocation against an
    /// attacker-controlled length prefix (a CBOR array/map count cannot
    /// legitimately exceed the bytes remaining in the input).
    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }
}

fn read_value(c: &mut Cursor) -> Result<CborValue, SessionError> {
    let first = c.take_u8()?;
    let major = first >> 5;
    let info = first & 0x1F;

    if first == SIMPLE_TRUE {
        return Ok(CborValue::Bool(true));
    }
    if first == SIMPLE_FALSE {
        return Ok(CborValue::Bool(false));
    }
    if first == SIMPLE_NULL {
        return Ok(CborValue::Null);
    }

    let arg = read_arg(c, info)?;
    match major {
        MAJOR_UINT => Ok(CborValue::Uint(arg)),
        MAJOR_BYTES => {
            let slice = c.take(arg as usize)?.to_vec();
            Ok(CborValue::Bytes(slice))
        }
        MAJOR_TEXT => {
            let slice = c.take(arg as usize)?.to_vec();
            let s = String::from_utf8(slice).map_err(|e| SessionError::Decode(format!("invalid utf8: {e}")))?;
            Ok(CborValue::Text(s))
        }
        MAJOR_ARRAY => {
            // Bound pre-allocation by remaining input: each element needs >=1 byte,
            // so a valid length prefix cannot exceed the bytes left. Without this an
            // attacker-controlled length prefix triggers an unbounded alloc (OOM).
            let cap = (arg as usize).min(c.remaining());
            let mut items = Vec::with_capacity(cap);
            for _ in 0..arg {
                items.push(read_value(c)?);
            }
            Ok(CborValue::Array(items))
        }
        MAJOR_MAP => {
            // Each entry needs >=2 bytes (text key + value), so bound by remaining/2.
            let cap = (arg as usize).min(c.remaining() / 2);
            let mut pairs = Vec::with_capacity(cap);
            for _ in 0..arg {
                let key = read_value(c)?;
                let value = read_value(c)?;
                match key {
                    CborValue::Text(s) => pairs.push((s, value)),
                    _ => {
                        return Err(SessionError::Decode(
                            "non-text map key not supported in this schema".to_string(),
                        ))
                    }
                }
            }
            Ok(CborValue::Map(pairs))
        }
        _ => Err(SessionError::Decode(format!("unsupported major type {major}"))),
    }
}

fn read_arg(c: &mut Cursor, info: u8) -> Result<u64, SessionError> {
    match info {
        0..=23 => Ok(u64::from(info)),
        24 => Ok(u64::from(c.take_u8()?)),
        25 => {
            let bytes = c.take(2)?;
            Ok(u64::from(u16::from_be_bytes([bytes[0], bytes[1]])))
        }
        26 => {
            let bytes = c.take(4)?;
            Ok(u64::from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])))
        }
        27 => {
            let bytes = c.take(8)?;
            Ok(u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]))
        }
        _ => Err(SessionError::Decode(format!(
            "reserved info value {info} not allowed in canonical cbor"
        ))),
    }
}

/// JSON mirror (RFC 8785 JCS). We canonicalise by sorting object keys
/// lexicographically (UTF-16 code unit order, per JCS) and emitting with
/// `serde_json` compact form.
///
/// Bytes are rendered as lowercase hex strings in JSON — the schema's
/// `bytes(N)` fields are always fixed-width and the hex form is unambiguous.
pub fn to_canonical_json(value: &CborValue) -> String {
    let json = to_json_value(value);
    // serde_json with preserve_order keeps our ordered-map order; the caller
    // is responsible for supplying keys already sorted per JCS (UTF-16 order).
    // For the ASCII-only keys in our schema, UTF-16 order equals bytewise
    // order, so the same sort we use for CBOR works here.
    #[allow(clippy::expect_used)] // serialization invariant: JSON values have string keys and String output cannot fail
    let out = serde_json::to_string(&json).expect("serde_json never fails on known value tree");
    out
}

fn to_json_value(value: &CborValue) -> serde_json::Value {
    match value {
        CborValue::Uint(n) => serde_json::Value::Number((*n).into()),
        CborValue::Bytes(b) => serde_json::Value::String(hex::encode(b)),
        CborValue::Text(s) => serde_json::Value::String(s.clone()),
        CborValue::Array(items) => serde_json::Value::Array(items.iter().map(to_json_value).collect()),
        CborValue::Map(pairs) => {
            let mut sorted: Vec<(&String, &CborValue)> = pairs.iter().map(|(k, v)| (k, v)).collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let mut map = serde_json::Map::with_capacity(sorted.len());
            for (k, v) in sorted {
                map.insert(k.clone(), to_json_value(v));
            }
            serde_json::Value::Object(map)
        }
        CborValue::Bool(b) => serde_json::Value::Bool(*b),
        CborValue::Null => serde_json::Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_encodes_shortest_form() {
        let mut out = Vec::new();
        write_head(MAJOR_UINT, 0, &mut out);
        assert_eq!(out, vec![0x00]);

        out.clear();
        write_head(MAJOR_UINT, 23, &mut out);
        assert_eq!(out, vec![0x17]);

        out.clear();
        write_head(MAJOR_UINT, 24, &mut out);
        assert_eq!(out, vec![0x18, 0x18]);

        out.clear();
        write_head(MAJOR_UINT, 255, &mut out);
        assert_eq!(out, vec![0x18, 0xff]);

        out.clear();
        write_head(MAJOR_UINT, 256, &mut out);
        assert_eq!(out, vec![0x19, 0x01, 0x00]);

        out.clear();
        write_head(MAJOR_UINT, 0xFFFF_FFFF, &mut out);
        assert_eq!(out, vec![0x1a, 0xff, 0xff, 0xff, 0xff]);

        out.clear();
        write_head(MAJOR_UINT, 0x1_0000_0000, &mut out);
        assert_eq!(out, vec![0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn decode_rejects_oversized_length_prefix_without_oom() {
        // Array header (major 4) with a u64::MAX element count but no elements.
        // Pre-fix this pre-allocated u64::MAX capacity and OOM-aborted; now the
        // pre-alloc is bounded by remaining input and decode returns Err cleanly.
        let mut arr = vec![0x80 | 0x1B]; // major 4, info 27 => 8-byte length follows
        arr.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(decode(&arr).is_err());

        // Same for a map header (major 5).
        let mut map = vec![0xA0 | 0x1B];
        map.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(decode(&map).is_err());
    }

    #[test]
    fn decode_rejects_oversized_byte_and_text_length_without_overflow() {
        // Byte-string (major 2) / text (major 3) headers with a near-usize::MAX
        // length but no payload. Pre-fix, `Cursor::take`'s `self.pos + n` bounds
        // check overflowed and panicked (found by the rcx_canonical_token fuzz
        // target); now it compares against `remaining()` and returns Err cleanly.
        let mut bytes = vec![0x40 | 0x1B]; // major 2, info 27 => 8-byte length
        bytes.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(decode(&bytes).is_err());

        let mut text = vec![0x60 | 0x1B]; // major 3, info 27 => 8-byte length
        text.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(decode(&text).is_err());
    }

    #[test]
    fn map_keys_sort_by_encoded_bytes() {
        let value = CborValue::Map(vec![
            ("shape".to_string(), CborValue::Text("S".to_string())),
            ("cap".to_string(), CborValue::Text("C".to_string())),
            ("prefer".to_string(), CborValue::Text("P".to_string())),
        ]);
        let encoded = value.encode();
        // Expected order: "cap" (len 3) < "shape" (len 5); "prefer" (len 6) last.
        // map head (3 pairs) = 0xa3, then "cap" (0x63 'c''a''p') "C" (0x61 'C')
        // then "shape" (0x65 ...) "S" then "prefer" (0x66 ...) "P"
        assert_eq!(encoded[0], 0xa3);
        assert_eq!(encoded[1], 0x63); // text(3)
        assert_eq!(&encoded[2..5], b"cap");
    }

    #[test]
    fn round_trip_basic() {
        let original = CborValue::Map(vec![
            ("a".to_string(), CborValue::Uint(42)),
            (
                "b".to_string(),
                CborValue::Array(vec![CborValue::Bool(true), CborValue::Null]),
            ),
            ("c".to_string(), CborValue::Bytes(vec![0xde, 0xad, 0xbe, 0xef])),
        ]);
        let encoded = original.encode();
        let decoded = decode(&encoded).unwrap();
        let re_encoded = decoded.encode();
        assert_eq!(encoded, re_encoded);
    }
}
