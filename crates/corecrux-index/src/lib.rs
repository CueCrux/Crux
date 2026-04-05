// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! CoreCrux companion index (.ccxi) — seal-time inverted index for GPU-native retrieval.
//!
//! Built as a companion file alongside sealed `.ccxseg` segments. Contains:
//! - Per-token posting lists (PForDelta compressed on disk)
//! - Per-document metadata (length, tenant hash)
//! - Vocabulary table for token→postings lookup
//!
//! The index is built on CPU at seal time and loaded (decompressed) to GPU device memory at query time.

mod tokenizer;
mod pfordelta;
mod ccxi;

pub use tokenizer::{tokenize, Token};
pub use pfordelta::{pfordelta_encode, pfordelta_decode};
pub use ccxi::{
    CcxiBuilder, CcxiReader, CcxiHeader, DocEntry, VocabEntry,
    CCXI_MAGIC, CCXI_VERSION,
};

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
