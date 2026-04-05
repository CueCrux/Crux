// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

mod v3;

pub use v3::{
    canonical_header_bytes_v1, compute_header_hash, compute_payload_hash,
    decode_canonical_header_bytes_v1, stream_hash_xxhash64, CanonicalHeaderV1, DecodeHeaderError,
    EventHeaderV3, StreamHashError,
};
