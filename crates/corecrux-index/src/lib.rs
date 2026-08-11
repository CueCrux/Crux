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
//!
//! # Companion containers
//!
//! Alongside `.ccxi` this crate carries the on-disk companion vocabulary shared with CoreCrux:
//! `.ccxe` (dense vectors), `.ccxs` / `.ccxse` (subject traits and their embeddings), `.ccxdi`
//! (document index), `.ccxal` (vernacular atoms), `.ccxn` (entity matrix), `.ccxf` (reverse frames),
//! `.ccxev` (extracted events), `.ccxp` (structured-fact projections), and `.ccxatt` (the CROWN
//! attestation covering a segment's whole bundle).
//!
//! Everything except `.ccxi` and `.ccxe` is **reader-only**: this daemon opens companions the
//! platform computed for it and never authors one. That is constraint C7 of ExecPlan
//! `crux-companion-vocabulary-unification-2026-08-08`, enforced in CI by
//! `scripts/assert-reader-only-companions.sh`. Port provenance and every divergence from the
//! CoreCrux source are recorded in this crate's `VENDORED_FROM.md`.
//!
//! The parsers are stateless and borrow the caller's byte slice. None of them is wired into
//! startup: when to load a companion, and whether to keep it resident, is a lane-wiring decision
//! that does not belong to the format layer.

pub mod ccxal;
mod ccxatt;
mod ccxdi;
mod ccxe;
mod ccxev;
mod ccxf;
mod ccxi;
mod ccxn;
mod ccxp;
mod ccxs;
mod ccxse;
mod le;
mod pfordelta;
mod tokenizer;
mod turboquant;

pub use ccxal::{CcxalError, CcxalReader, CCXAL_MAGIC, CCXAL_SCHEMA_VERSION, CCXAL_VERSION};
pub use ccxatt::{
    collect_companion_digests, companion_digest, decode_attestation, encode_attestation, verify_attestation,
    verify_parsed, write_local_attestation, AttestationBody, AttestationFailure, AttestationMode, CompanionDigest,
    LocalAttestationRequest, ParsedAttestation, Provenance, TrustRoots, CCXATT_EXT, CCXATT_SCHEMA_V1,
};
pub use ccxdi::{
    pointer_kind as ccxdi_pointer_kind, q8_8_to_f32 as ccxdi_q8_8_to_f32, region_kind as ccxdi_region_kind, CcxdiError,
    CcxdiHeader, CcxdiReader, DocTableEntry as CcxdiDocTableEntry, PointerEntry, RegionEntry, CCXDI_MAGIC,
    CCXDI_SCHEMA_VERSION, CCXDI_SCHEMA_VERSION_TENANT_HASH, CCXDI_VERSION, NO_HEADER,
};
pub use ccxe::{
    configured_turbo_seed, model_id_file_key, model_id_from_header_bytes, read_model_id_from_path,
    verify_footer_hashes, CcxeBuildFingerprint, CcxeBuilder, CcxeReader, Quantization, CCXE_HEADER_LEN, CCXE_VERSION,
    CCXE_VERSION_V1, CCXE_VERSION_V2,
};
pub use ccxev::{
    CcxevHeader, CcxevModality, CcxevReader, ExtractedEvent, CCXEV_MAGIC, CCXEV_NO_TIME, CCXEV_RECORD_OFF_UNKNOWN,
    CCXEV_SCHEMA_VERSION, CCXEV_VERSION,
};
pub use ccxf::{CcxfHeader, CcxfReader, ReverseFrame, CCXF_MAGIC, CCXF_SCHEMA_VERSION, CCXF_VERSION};
pub use ccxi::{CcxiBuilder, CcxiHeader, CcxiReader, DocEntry, VocabEntry, CCXI_MAGIC, CCXI_VERSION};
pub use ccxn::{
    canonicalise as canonicalise_entity, CcxnHeader, CcxnReader, EntityHits, EntityOccurrence, EntityRecord,
    EntityType, CCXN_MAGIC, CCXN_SCHEMA_VERSION, CCXN_VERSION,
};
pub use ccxp::{
    CcxpHeader, CcxpReader, ProjectionFact, ProjectionPredicate, CCXP_MAGIC, CCXP_SCHEMA_VERSION, CCXP_VERSION,
    NO_SOURCE_PATTERN,
};
pub use ccxs::{
    subject_hash, CcxsHeader, CcxsReader, ProfileTrait, SubjectHits, SubjectKind, CCXS_MAGIC, CCXS_SCHEMA_VERSION,
    CCXS_VERSION,
};
pub use ccxse::{
    CcxseDtype, CcxseHeader, CcxseReader, EmbeddingSlice, CCXSE_MAGIC, CCXSE_SCHEMA_VERSION, CCXSE_VERSION,
};
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
