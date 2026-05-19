// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecrux-frame` — canonical frame encoding for CoreCrux on-disk data.
//!
//! Defines the v1 header layout (`canonical_header_bytes_v1`), hash
//! helpers (`compute_header_hash`, `compute_payload_hash`), and the
//! encoder/decoder used by `corecrux-segment` and downstream replay /
//! receipt machinery. Pure types + bit-level layout; no I/O.

mod v3;

pub use v3::{
    canonical_header_bytes_v1, compute_header_hash, compute_payload_hash, decode_canonical_header_bytes_v1,
    stream_hash_xxhash64, CanonicalHeaderV1, DecodeHeaderError, EventHeaderV3, StreamHashError,
};
