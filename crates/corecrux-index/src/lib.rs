// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! CoreCrux companion index (.ccxi) — seal-time inverted index for GPU-native retrieval.
//!
//! Built as a companion file alongside sealed `.ccxseg` segments. Contains:
//! - Per-token posting lists (PForDelta compressed on disk)
//! - Per-document metadata (length, tenant hash)
//! - Vocabulary table for token→postings lookup
//!
//! The index is built on CPU at seal time and loaded (decompressed) to GPU device memory at query time.

mod ccxatt;
mod ccxe;
mod ccxi;
mod pfordelta;
mod tokenizer;
mod turboquant;

pub use ccxatt::{
    collect_companion_digests, companion_digest, decode_attestation, encode_attestation, verify_attestation,
    verify_parsed, write_local_attestation, AttestationBody, AttestationFailure, AttestationMode, CompanionDigest,
    LocalAttestationRequest, ParsedAttestation, Provenance, TrustRoots, CCXATT_EXT, CCXATT_SCHEMA_V1,
};
pub use ccxe::{
    configured_turbo_seed, model_id_file_key, verify_footer_hashes, CcxeBuildFingerprint, CcxeBuilder, CcxeReader,
    Quantization, CCXE_HEADER_LEN, CCXE_VERSION, CCXE_VERSION_V1, CCXE_VERSION_V2,
};
pub use ccxi::{CcxiBuilder, CcxiHeader, CcxiReader, DocEntry, VocabEntry, CCXI_MAGIC, CCXI_VERSION};
pub use pfordelta::{pfordelta_decode, pfordelta_encode};
pub use tokenizer::{tokenize, Token};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum IndexError {
    #[error("buffer too small")]
    BufferTooSmall,
    #[error("invalid magic: expected {expected:#x}, got {actual:#x}")]
    InvalidMagic { expected: u32, actual: u32 },
    #[error("unsupported version: {version}")]
    UnsupportedVersion { version: u16 },
    #[error("integrity check failed: {msg}")]
    IntegrityFailure { msg: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, IndexError>;
