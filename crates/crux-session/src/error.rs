// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Error type for the `crux-session` crate (CBOR/JSON encode/decode failures, signature errors).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("canonical cbor encode failed: {0}")]
    Encode(String),

    #[error("canonical cbor decode failed: {0}")]
    Decode(String),

    #[error("json decode failed: {0}")]
    Json(#[from] serde_json::Error),

    #[error("hex decode failed: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("ed25519 verification failed")]
    BadSignature,

    #[error("signature field missing; plan is not in verified mode")]
    SignatureAbsent,

    #[error("unsupported receipt mode: {0}")]
    UnsupportedMode(String),

    #[error("hash length mismatch: expected 32 bytes, got {0}")]
    HashLength(usize),

    #[error("signature length mismatch: expected 64 bytes, got {0}")]
    SignatureLength(usize),

    #[error("public key length mismatch: expected 32 bytes, got {0}")]
    PublicKeyLength(usize),

    #[error("byte-array length mismatch for field {field}: expected {expected}, got {actual}")]
    ByteArrayLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
}
