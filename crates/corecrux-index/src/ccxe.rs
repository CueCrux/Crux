// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.
//! `.ccxe` file format — per-segment dense vector companion.
//!
//! Stores pre-computed embeddings for every document in a sealed segment.
//! Built at seal time via EmbedderCrux (local GPU, nomic-embed-text-v1.5 768d).
//!
//! Layout:
//!   CcxeHeader (256 bytes, page-aligned)
//!   CcxeV2Metadata (optional, version >= 2, length stored in header)
//!   VectorArray (total_frames × dim × sizeof(element))
//!   DocIdTable (total_frames × 4 bytes)
//!   CcxeFooter (64 bytes — BLAKE3 hashes)
//!
//! Quantization modes:
//!   float32:    4 bytes per dim (highest precision)
//!   float16:    2 bytes per dim (good balance)
//!   int8:       1 byte per dim  (4x on-disk; dequantised to f32 RESIDENT — no RAM win)
//!   int8packed: 1 byte per dim, kept PACKED resident — recall-neutral ~4x RAM win
//!   turbo4/2:   4-/2-bit TurboQuant, packed resident — bigger RAM win, recall trade
//!               (see `crate::turboquant` + docs/turboquant-cutover-runbook.md)

use std::path::Path;

use crate::turboquant::{self, TurboParams};
use crate::IndexError;

pub const CCXE_MAGIC: u32 = 0x4343_5845; // "CCXE"

/// Backing store for a `.ccxe` vector area (the packed-resident modes —
/// `Int8Packed` + TurboQuant — whose resident representation is raw codes).
///
/// - `Owned` — codes copied onto the heap (anonymous memory). `O(N)` resident
///   and NOT reclaimable.
///
/// **CE port note.** Upstream also carries a `Mapped` variant backed by a
/// read-only `mmap`, which is what makes the dataplane's dense lane structurally
/// OOM-proof (`corecrux-dense-lane-mmap-tiering-2026-06-17`). It cannot come
/// here: `memmap2::Mmap::map` is `unsafe`, and this workspace sets
/// `unsafe_code = "forbid"` — a level `allow` cannot override. So the CE reads
/// dense companions eagerly. See VENDORED_FROM.md.
#[derive(Clone)]
pub enum VectorBytes {
    Owned(Vec<u8>),
}

impl VectorBytes {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        match self {
            VectorBytes::Owned(v) => v.as_slice(),
        }
    }

    /// True when the codes are file-backed rather than heap-resident. Always
    /// `false` in the CE — there is no mmap backing here (see the type docs). Kept as
    /// an associated fn so call sites read the same as upstream.
    #[inline]
    pub fn is_mapped() -> bool {
        false
    }

    /// Heap-resident byte count. Used by the RAM budget.
    #[inline]
    pub fn resident_len(&self) -> usize {
        match self {
            VectorBytes::Owned(v) => v.len(),
        }
    }
}

impl std::ops::Deref for VectorBytes {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl std::fmt::Debug for VectorBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VectorBytes::Owned(v) => f.debug_struct("VectorBytes::Owned").field("len", &v.len()).finish(),
        }
    }
}

/// Filesystem-safe key derived from an embedder `model_id`, used to name a
/// model-keyed dense companion `<segment>.ccxe@<key>` (and the sparse twin
/// `<segment>.ccxl@<key>`). Model ids carry `/` (e.g. `BAAI/bge-m3`) which is
/// illegal in a filename, so the suffix is a sanitised, lowercased rendering:
/// any char outside `[a-z0-9._-]` collapses to `-`, runs of `-` coalesce, and
/// edge `-` are trimmed.
///
/// The suffix only disambiguates files on disk — the **authoritative** model_id
/// is always read back from the loaded `.ccxe` header, never parsed from the
/// filename. So a (vanishingly unlikely) sanitisation collision between two
/// distinct model ids degrades to "one file wins on disk", never to a wrong
/// model_id being served.
pub fn model_id_file_key(model_id: &str) -> String {
    let mut out = String::with_capacity(model_id.len());
    let mut last_dash = false;
    for ch in model_id.trim().chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
            out.push(c);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed
    }
}

pub const CCXE_VERSION_V1: u16 = 1;
pub const CCXE_VERSION_V2: u16 = 2;
pub const CCXE_VERSION: u16 = CCXE_VERSION_V2;
pub const CCXE_HEADER_LEN: usize = 256;
pub const CCXE_FOOTER_LEN: usize = 64;
const CCXE_MODEL_ID_OFFSET: usize = 35;
const CCXE_MODEL_ID_MAX_LEN: usize = 128;
const CCXE_V2_METADATA_LEN_OFFSET: usize = CCXE_MODEL_ID_OFFSET + CCXE_MODEL_ID_MAX_LEN;
const CCXE_V2_METADATA_MAGIC: &[u8; 8] = b"CCXEMT01";
const CCXE_V2_FLAG_FINGERPRINT: u8 = 0x01;
const CCXE_V2_FLAG_CALIBRATION_VECTOR: u8 = 0x02;
const CCXE_V2_FLAG_TURBOQUANT: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Quantization {
    Float32 = 0,
    Float16 = 1,
    Int8 = 2,
    /// TurboQuant 4-bit packed-resident (2× denser than int8). Vectors are stored
    /// rotated+quantised and kept PACKED in RAM (decode-in-scoring) — the resident
    /// RAM win. See the `turboquant` module.
    TurboQuant4 = 3,
    /// TurboQuant 2-bit packed-resident (4× denser than int8).
    TurboQuant2 = 4,
    /// int8 kept PACKED resident (1 byte/dim) and decoded (`q/127`) in scoring —
    /// the **recall-neutral** RAM win (~4× smaller resident than f32 at int8's
    /// accuracy). Same on-disk bytes as [`Self::Int8`]; differs only in that the
    /// reader does NOT expand to `Vec<Vec<f32>>`. See `Int8PackedVectors`.
    Int8Packed = 5,
}

impl Quantization {
    /// Bytes per dim for the per-element layouts (float/int8). TurboQuant modes are
    /// sub-byte and byte-packed PER VECTOR, not per dim — callers must branch on
    /// [`Self::is_turbo`] and use `turboquant::packed_vector_len` instead.
    pub fn bytes_per_dim(self) -> usize {
        match self {
            Self::Float32 => 4,
            Self::Float16 => 2,
            Self::Int8 | Self::Int8Packed => 1,
            Self::TurboQuant4 | Self::TurboQuant2 => 0,
        }
    }

    /// True for the packed-resident int8 mode (decoded in scoring, not expanded).
    pub fn is_int8_packed(self) -> bool {
        matches!(self, Self::Int8Packed)
    }

    /// Bit width of a TurboQuant code, or `None` for the per-element layouts.
    pub fn turbo_bits(self) -> Option<u8> {
        match self {
            Self::TurboQuant4 => Some(4),
            Self::TurboQuant2 => Some(2),
            _ => None,
        }
    }

    pub fn is_turbo(self) -> bool {
        self.turbo_bits().is_some()
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Float32),
            1 => Some(Self::Float16),
            2 => Some(Self::Int8),
            3 => Some(Self::TurboQuant4),
            4 => Some(Self::TurboQuant2),
            5 => Some(Self::Int8Packed),
            _ => None,
        }
    }

    /// Parse a config string (`CORECRUXD_CCXE_QUANT`): `int8` | `int8packed` |
    /// `float32` | `float16` | `turbo4` | `turbo2`. Case-insensitive. `None` if
    /// unrecognised.
    pub fn from_config_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "float32" | "f32" => Some(Self::Float32),
            "float16" | "f16" => Some(Self::Float16),
            "int8" | "i8" => Some(Self::Int8),
            "int8packed" | "i8p" | "int8-packed" => Some(Self::Int8Packed),
            "turbo4" | "turboquant4" | "tq4" => Some(Self::TurboQuant4),
            "turbo2" | "turboquant2" | "tq2" => Some(Self::TurboQuant2),
            _ => None,
        }
    }
}

/// Deterministic rotation seed for a TurboQuant segment at a given seq. Stored in
/// metadata and reproduced at read.
///
/// **CE port note.** Upstream also exposes `configured_quantization()`, which reads
/// `CORECRUXD_CCXE_QUANT` to choose the on-disk mode for newly built segments. That
/// is a platform-builder policy knob and is deliberately absent here: constraint C7
/// of ExecPlan `crux-companion-vocabulary-unification-2026-08-08` keeps the CE from
/// being *steered* into authoring the companions the platform sells, and the CE's
/// writer picks [`Quantization::Float32`] unconditionally.
///
/// This seed helper stays because encoding is how the crate self-tests its own
/// decoder — the round-trip tests build TurboQuant data in order to read it back.
/// It grants no capability `CcxeBuilder::set_turbo_seed` did not already have.
pub fn configured_turbo_seed(segment_seq: u64) -> u64 {
    segment_seq ^ 0x7551_B0A7_C0DE_5EED
}

#[derive(Debug, Clone)]
pub struct CcxeHeader {
    pub magic: u32,
    pub version: u16,
    pub shard_id: u32,
    pub segment_seq: u64,
    pub epoch: u64,
    pub dim: u16,
    pub quantization: Quantization,
    pub total_frames: u32,
    pub model_id_len: u16,
    pub model_id: String, // e.g. "nomic-embed-text-v1.5"
}

/// Build-time identity for the vector space that produced a `.ccxe` file.
///
/// `model_id` historically captured only a human-facing model name. This
/// fingerprint records the serving surface that actually produced vectors so
/// operators can detect same-name drift across dimensions, dtype, batch, or
/// backend version changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CcxeBuildFingerprint {
    pub served_model_name: String,
    pub dim: u16,
    pub dtype: String,
    pub batch_size: u32,
    pub embedder_version: String,
}

/// Builder: accumulates document vectors and produces a complete .ccxe file.
pub struct CcxeBuilder {
    shard_id: u32,
    segment_seq: u64,
    epoch: u64,
    dim: u16,
    quantization: Quantization,
    model_id: String,
    build_fingerprint: Option<CcxeBuildFingerprint>,
    calibration_vector: Option<Vec<f32>>,
    /// Caller-chosen rotation seed for TurboQuant modes (default 0). Levels are
    /// fit from the accumulated vectors at build() time.
    turbo_seed: u64,
    /// Vectors stored as f32 internally, quantized on build().
    vectors: Vec<Vec<f32>>,
    doc_ids: Vec<u32>,
}

impl CcxeBuilder {
    pub fn new(shard_id: u32, segment_seq: u64, epoch: u64, dim: u16, model_id: &str) -> Self {
        Self {
            shard_id,
            segment_seq,
            epoch,
            dim,
            quantization: Quantization::Int8, // default: 4x compression
            model_id: model_id.to_string(),
            build_fingerprint: None,
            calibration_vector: None,
            turbo_seed: 0,
            vectors: Vec::new(),
            doc_ids: Vec::new(),
        }
    }

    pub fn set_quantization(&mut self, q: Quantization) {
        self.quantization = q;
    }

    /// Rotation seed for TurboQuant modes (stored in metadata; reproduced at read).
    pub fn set_turbo_seed(&mut self, seed: u64) {
        self.turbo_seed = seed;
    }

    pub fn with_build_fingerprint(mut self, fp: CcxeBuildFingerprint) -> Self {
        self.build_fingerprint = Some(fp);
        self
    }

    pub fn set_build_fingerprint(&mut self, fp: CcxeBuildFingerprint) {
        self.build_fingerprint = Some(fp);
    }

    pub fn with_calibration_vector(mut self, vector: Vec<f32>) -> Self {
        self.set_calibration_vector(vector);
        self
    }

    pub fn set_calibration_vector(&mut self, vector: Vec<f32>) {
        assert_eq!(vector.len(), self.dim as usize, "calibration vector dim mismatch");
        self.calibration_vector = Some(vector);
    }

    /// Add a document's embedding vector.
    /// `doc_id` is the local index within this segment (0-based).
    /// `vector` must have exactly `dim` elements.
    pub fn add_vector(&mut self, doc_id: u32, vector: Vec<f32>) {
        assert_eq!(vector.len(), self.dim as usize, "vector dim mismatch");
        self.vectors.push(vector);
        self.doc_ids.push(doc_id);
    }

    pub fn doc_count(&self) -> u32 {
        self.doc_ids.len() as u32
    }

    /// Build the complete .ccxe file bytes.
    pub fn build(&self) -> Vec<u8> {
        let total_frames = self.doc_ids.len() as u32;
        // TurboQuant: fit the rotation+levels once from the accumulated vectors.
        let turbo = self
            .quantization
            .turbo_bits()
            .map(|bits| turboquant::fit(&self.vectors, self.dim as usize, bits, self.turbo_seed));
        let metadata = self.build_v2_metadata(turbo.as_ref());
        let version = if metadata.is_empty() {
            CCXE_VERSION_V1
        } else {
            CCXE_VERSION_V2
        };
        let vector_area_len = match &turbo {
            Some(p) => total_frames as usize * turboquant::packed_vector_len(p.padded_dim, p.bits),
            None => total_frames as usize * self.dim as usize * self.quantization.bytes_per_dim(),
        };
        let doc_id_table_len = total_frames as usize * 4;
        let total_len = CCXE_HEADER_LEN + metadata.len() + vector_area_len + doc_id_table_len + CCXE_FOOTER_LEN;

        let mut out = Vec::with_capacity(total_len);

        // === Header (256 bytes, zero-padded) ===
        let mut header = vec![0u8; CCXE_HEADER_LEN];
        write_u32(&mut header, 0, CCXE_MAGIC);
        write_u16(&mut header, 4, version);
        write_u32(&mut header, 6, self.shard_id);
        write_u64(&mut header, 10, self.segment_seq);
        write_u64(&mut header, 18, self.epoch);
        write_u16(&mut header, 26, self.dim);
        header[28] = self.quantization as u8;
        write_u32(&mut header, 29, total_frames);
        let model_bytes = self.model_id.as_bytes();
        let model_len = model_bytes.len().min(CCXE_MODEL_ID_MAX_LEN) as u16;
        write_u16(&mut header, 33, model_len);
        header[CCXE_MODEL_ID_OFFSET..CCXE_MODEL_ID_OFFSET + model_len as usize]
            .copy_from_slice(&model_bytes[..model_len as usize]);
        if version >= CCXE_VERSION_V2 {
            write_u32(&mut header, CCXE_V2_METADATA_LEN_OFFSET, metadata.len() as u32);
        }
        out.extend_from_slice(&header);
        out.extend_from_slice(&metadata);

        // === Vector Array ===
        if let Some(params) = &turbo {
            for vec in &self.vectors {
                out.extend_from_slice(&turboquant::encode_vector(vec, params));
            }
        } else {
            for vec in &self.vectors {
                match self.quantization {
                    Quantization::TurboQuant4 | Quantization::TurboQuant2 => {
                        unreachable!("turbo handled above")
                    }
                    Quantization::Float32 => {
                        for &v in vec {
                            out.extend_from_slice(&v.to_le_bytes());
                        }
                    }
                    Quantization::Float16 => {
                        for &v in vec {
                            out.extend_from_slice(&f32_to_f16(v).to_le_bytes());
                        }
                    }
                    Quantization::Int8 | Quantization::Int8Packed => {
                        // Quantize to [-127,127] by per-vector absmax. Int8 and Int8Packed
                        // share the on-disk encoding — they differ only in the resident
                        // representation the reader keeps.
                        let max_abs = vec.iter().map(|v| v.abs()).fold(0.0f32, f32::max).max(1e-10);
                        for &v in vec {
                            let quantized = (v / max_abs * 127.0).round().clamp(-127.0, 127.0) as i8;
                            out.push(quantized as u8);
                        }
                    }
                }
            }
        }

        // === Doc ID Table ===
        for &id in &self.doc_ids {
            out.extend_from_slice(&id.to_le_bytes());
        }

        // === Footer (64 bytes: BLAKE3 of vector area + BLAKE3 of doc table) ===
        let vector_start = CCXE_HEADER_LEN + metadata.len();
        let vector_end = vector_start + vector_area_len;
        let doc_start = vector_end;
        let doc_end = doc_start + doc_id_table_len;

        let vector_hash = blake3::hash(&out[vector_start..vector_end]);
        let doc_hash = blake3::hash(&out[doc_start..doc_end]);

        let mut footer = vec![0u8; CCXE_FOOTER_LEN];
        footer[0..32].copy_from_slice(vector_hash.as_bytes());
        footer[32..64].copy_from_slice(doc_hash.as_bytes());
        out.extend_from_slice(&footer);

        out
    }

    fn build_v2_metadata(&self, turbo: Option<&TurboParams>) -> Vec<u8> {
        let mut flags = 0u8;
        if self.build_fingerprint.is_some() {
            flags |= CCXE_V2_FLAG_FINGERPRINT;
        }
        if self.calibration_vector.is_some() {
            flags |= CCXE_V2_FLAG_CALIBRATION_VECTOR;
        }
        if turbo.is_some() {
            flags |= CCXE_V2_FLAG_TURBOQUANT;
        }
        if flags == 0 {
            return Vec::new();
        }

        let mut out = Vec::new();
        out.extend_from_slice(CCXE_V2_METADATA_MAGIC);
        out.push(flags);

        if let Some(fp) = &self.build_fingerprint {
            write_leb128_string(&mut out, &fp.served_model_name);
            out.extend_from_slice(&fp.dim.to_le_bytes());
            write_leb128_string(&mut out, &fp.dtype);
            out.extend_from_slice(&fp.batch_size.to_le_bytes());
            write_leb128_string(&mut out, &fp.embedder_version);
        }
        if let Some(vector) = &self.calibration_vector {
            write_leb128_u32(&mut out, vector.len() as u32);
            for &value in vector {
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
        if let Some(p) = turbo {
            out.extend_from_slice(&p.seed.to_le_bytes());
            out.extend_from_slice(&(p.orig_dim as u32).to_le_bytes());
            out.extend_from_slice(&(p.padded_dim as u32).to_le_bytes());
            out.push(p.bits);
            write_leb128_u32(&mut out, p.levels.len() as u32);
            for &lvl in &p.levels {
                out.extend_from_slice(&lvl.to_le_bytes());
            }
        }

        out
    }
}

/// TurboQuant packed-resident vectors: the codes stay packed in RAM (the resident
/// RAM win) and decode on demand during scoring.
#[derive(Debug, Clone)]
pub struct PackedVectors {
    /// TurboQuant codes — heap-resident (`Owned`) or mmap file-backed (`Mapped`).
    pub codes: VectorBytes,
    pub params: TurboParams,
    /// Bytes per packed vector (`packed_vector_len(padded_dim, bits)`).
    pub stride: usize,
}

impl PackedVectors {
    #[inline]
    pub fn len(&self) -> usize {
        self.codes.len().checked_div(self.stride).unwrap_or(0)
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Decode vector `i` to its f32 ROTATED-space representation (internal scoring
    /// space — the query is rotated to match).
    #[inline]
    pub fn decode(&self, i: usize) -> Vec<f32> {
        let codes: &[u8] = &self.codes;
        let s = i * self.stride;
        turboquant::decode_vector(&codes[s..s + self.stride], &self.params)
    }

    /// Decode vector `i` to ORIGINAL (model-embedding) space — inverse-rotated and
    /// truncated to `orig_dim`. This is the unit-direction original vector; consumers
    /// outside the turbo scoring path (compaction re-encode, navtree clustering)
    /// must use this, not [`Self::decode`], to avoid double-rotation on re-encode.
    #[inline]
    pub fn decode_orig(&self, i: usize) -> Vec<f32> {
        turboquant::inverse_rotate_to_orig(&self.decode(i), &self.params)
    }
}

/// Packed-resident int8 vectors: the int8 codes stay resident (1 byte/dim) and
/// decode (`q/127`) on demand in scoring — the recall-neutral RAM win.
#[derive(Debug, Clone)]
pub struct Int8PackedVectors {
    /// int8 codes as bytes, `dim` per vector, row-major. Heap-resident (`Owned`)
    /// or mmap file-backed (`Mapped`).
    pub codes: VectorBytes,
    pub dim: usize,
}

impl Int8PackedVectors {
    #[inline]
    pub fn len(&self) -> usize {
        self.codes.len().checked_div(self.dim).unwrap_or(0)
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Decode vector `i` to f32 (`q/127`, same as the int8 dequant).
    #[inline]
    pub fn decode(&self, i: usize) -> Vec<f32> {
        let codes: &[u8] = &self.codes;
        let s = i * self.dim;
        codes[s..s + self.dim]
            .iter()
            .map(|&b| (b as i8) as f32 / 127.0)
            .collect()
    }
}

/// CC9 — verify a `.ccxe` buffer's footer BLAKE3 hashes (vector area + doc-id
/// table) against the recomputed values.
///
/// The writer has always stamped these hashes ([`CcxeBuilder::build`] footer),
/// but `CcxeReader::parse` never checks them: parse validates structure and
/// sizing only, so truncation is caught while **in-place bit corruption inside
/// the vector area or doc table is served silently** (and companion staleness
/// still reports `Current` — the fingerprint lives in the unhashed metadata).
///
/// This check is deliberately NOT wired into `parse`: hashing the whole vector
/// area on every load would tax the daemon hot path. Offline tools opt in —
/// `corecruxctl ccxe verify-companions`, or `CORECRUXCTL_CCXE_VERIFY_HASH=1`
/// at the offline parse sites.
/// Read a `.ccxe`'s authoritative `model_id` **without parsing its vectors**.
///
/// The `@<key>` filename suffix is a disambiguator, never the model identity —
/// the header is. But the query path has to answer "is this companion mine?"
/// for every segment on every query, and `CcxeReader::from_path` reads the whole
/// file to answer it, which on a corpus with two keyed companions per segment
/// would mean loading (and caching) the vectors of a model the caller is about
/// to reject. This reads the first [`CCXE_HEADER_LEN`] bytes and stops.
///
/// An empty string means the header carries no model id (legacy/unlabelled), a
/// distinct case from "the file is unreadable", which is an `Err`.
pub fn read_model_id_from_path<P: AsRef<Path>>(path: P) -> crate::Result<String> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path.as_ref())?;
    let mut header = [0u8; CCXE_HEADER_LEN];
    file.read_exact(&mut header)?;
    model_id_from_header_bytes(&header)
}

/// The `model_id` field of an already-read `.ccxe` header block.
///
/// Same magic and version gating as the full parser, so a file this accepts is
/// one [`CcxeReader`] will also accept — the selection step must not admit a
/// companion the load step would then reject.
pub fn model_id_from_header_bytes(header: &[u8]) -> crate::Result<String> {
    if header.len() < CCXE_HEADER_LEN {
        return Err(IndexError::BufferTooSmall);
    }
    let magic = read_u32(header, 0);
    if magic != CCXE_MAGIC {
        return Err(IndexError::InvalidMagic {
            expected: CCXE_MAGIC,
            actual: magic,
        });
    }
    let version = read_u16(header, 4);
    if version != CCXE_VERSION_V1 && version != CCXE_VERSION_V2 {
        return Err(IndexError::UnsupportedVersion { version });
    }
    let model_id_len = read_u16(header, 33) as usize;
    if model_id_len == 0
        || model_id_len > CCXE_MODEL_ID_MAX_LEN
        || CCXE_MODEL_ID_OFFSET + model_id_len > CCXE_HEADER_LEN
    {
        return Ok(String::new());
    }
    Ok(String::from_utf8_lossy(&header[CCXE_MODEL_ID_OFFSET..CCXE_MODEL_ID_OFFSET + model_id_len]).to_string())
}

pub fn verify_footer_hashes(data: &[u8]) -> crate::Result<()> {
    if data.len() < CCXE_HEADER_LEN + CCXE_FOOTER_LEN {
        return Err(IndexError::BufferTooSmall);
    }
    let magic = read_u32(data, 0);
    if magic != CCXE_MAGIC {
        return Err(IndexError::InvalidMagic {
            expected: CCXE_MAGIC,
            actual: magic,
        });
    }
    let version = read_u16(data, 4);
    if version != CCXE_VERSION_V1 && version != CCXE_VERSION_V2 {
        return Err(IndexError::UnsupportedVersion { version });
    }
    let dim = read_u16(data, 26);
    let quant_byte = data[28];
    let quantization = Quantization::from_u8(quant_byte).ok_or(IndexError::IntegrityFailure {
        msg: format!("unknown quantization {quant_byte}"),
    })?;
    let total_frames = read_u32(data, 29) as usize;
    let metadata_len = if version >= CCXE_VERSION_V2 {
        read_u32(data, CCXE_V2_METADATA_LEN_OFFSET) as usize
    } else {
        0
    };
    let metadata_end = CCXE_HEADER_LEN
        .checked_add(metadata_len)
        .ok_or(IndexError::BufferTooSmall)?;
    if metadata_end > data.len().saturating_sub(CCXE_FOOTER_LEN) {
        return Err(IndexError::BufferTooSmall);
    }
    // Turbo modes size the vector area from the metadata params — mirror `parse`.
    let turbo_params = if version >= CCXE_VERSION_V2 && metadata_len > 0 {
        parse_v2_metadata(&data[CCXE_HEADER_LEN..metadata_end])
            .map(|m| m.turbo_params)
            .unwrap_or(None)
    } else {
        None
    };
    if quantization.is_turbo() && turbo_params.is_none() {
        return Err(IndexError::IntegrityFailure {
            msg: format!("turbo quant {quant_byte} without metadata params"),
        });
    }
    let vector_area_len = match &turbo_params {
        Some(p) => total_frames
            .checked_mul(turboquant::packed_vector_len(p.padded_dim, p.bits))
            .ok_or(IndexError::BufferTooSmall)?,
        None => total_frames
            .checked_mul(dim as usize)
            .and_then(|n| n.checked_mul(quantization.bytes_per_dim()))
            .ok_or(IndexError::BufferTooSmall)?,
    };
    let doc_table_len = total_frames.checked_mul(4).ok_or(IndexError::BufferTooSmall)?;
    let vector_start = metadata_end;
    let vector_end = vector_start
        .checked_add(vector_area_len)
        .ok_or(IndexError::BufferTooSmall)?;
    let doc_end = vector_end
        .checked_add(doc_table_len)
        .ok_or(IndexError::BufferTooSmall)?;
    let footer_end = doc_end.checked_add(CCXE_FOOTER_LEN).ok_or(IndexError::BufferTooSmall)?;
    if data.len() < footer_end {
        return Err(IndexError::BufferTooSmall);
    }

    let footer = &data[doc_end..footer_end];
    let vector_hash = blake3::hash(&data[vector_start..vector_end]);
    if footer[0..32] != vector_hash.as_bytes()[..] {
        return Err(IndexError::IntegrityFailure {
            msg: format!(
                "ccxe footer vector-area BLAKE3 mismatch (stored {}…, computed {}…) — \
                 the vector area is corrupt (in-place bit corruption or partial \
                 overwrite); rebuild the dense companion",
                hex_prefix(&footer[0..32]),
                hex_prefix(vector_hash.as_bytes()),
            ),
        });
    }
    let doc_hash = blake3::hash(&data[vector_end..doc_end]);
    if footer[32..64] != doc_hash.as_bytes()[..] {
        return Err(IndexError::IntegrityFailure {
            msg: format!(
                "ccxe footer doc-table BLAKE3 mismatch (stored {}…, computed {}…) — \
                 the doc-id table is corrupt; rebuild the dense companion",
                hex_prefix(&footer[32..64]),
                hex_prefix(doc_hash.as_bytes()),
            ),
        });
    }
    Ok(())
}

/// First 8 bytes as lowercase hex — enough to identify a hash in an error
/// message without dumping 64 chars.
fn hex_prefix(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().take(8).fold(String::with_capacity(16), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

/// Reader: loads a .ccxe file and provides access to vectors and doc table.
pub struct CcxeReader {
    pub header: CcxeHeader,
    build_fingerprint: Option<CcxeBuildFingerprint>,
    calibration_vector: Option<Vec<f32>>,
    /// Vectors stored as f32 (dequantized on load) for the per-element modes.
    /// EMPTY for the packed-resident modes (TurboQuant, Int8Packed).
    pub vectors: Vec<Vec<f32>>,
    /// Packed-resident TurboQuant vectors (the RAM win). `None` for non-turbo modes.
    pub packed: Option<PackedVectors>,
    /// Packed-resident int8 vectors (recall-neutral RAM win). `None` otherwise.
    pub int8_packed: Option<Int8PackedVectors>,
    pub doc_ids: Vec<u32>,
}

impl CcxeReader {
    /// Parse a `.ccxe` from an in-memory buffer — the historical heap-resident
    /// path. Packed-mode vector codes are copied onto the heap (`Owned`).
    pub fn from_bytes(data: &[u8]) -> crate::Result<Self> {
        Self::parse(data)
    }

    /// Read a `.ccxe` companion from disk.
    ///
    /// The CE reads eagerly. Upstream offers an `mmap` variant that makes packed
    /// vector codes file-backed and reclaimable under memory pressure; it needs
    /// `unsafe`, which this workspace forbids at the lint level, so it is absent
    /// here (see `VectorBytes` and VENDORED_FROM.md). A large dense companion
    /// is therefore fully resident once loaded.
    pub fn from_path<P: AsRef<Path>>(path: P) -> crate::Result<Self> {
        let data = std::fs::read(path.as_ref())?;
        Self::parse(&data)
    }

    /// Core parser. Packed vector codes are copied onto the heap.
    fn parse(data: &[u8]) -> crate::Result<Self> {
        if data.len() < CCXE_HEADER_LEN + CCXE_FOOTER_LEN {
            return Err(IndexError::BufferTooSmall);
        }

        let magic = read_u32(data, 0);
        if magic != CCXE_MAGIC {
            return Err(IndexError::InvalidMagic {
                expected: CCXE_MAGIC,
                actual: magic,
            });
        }
        let version = read_u16(data, 4);
        if version != CCXE_VERSION_V1 && version != CCXE_VERSION_V2 {
            return Err(IndexError::UnsupportedVersion { version });
        }

        let shard_id = read_u32(data, 6);
        let segment_seq = read_u64(data, 10);
        let epoch = read_u64(data, 18);
        let dim = read_u16(data, 26);
        let quant_byte = data[28];
        let quantization = Quantization::from_u8(quant_byte).ok_or(IndexError::IntegrityFailure {
            msg: format!("unknown quantization {quant_byte}"),
        })?;
        let total_frames = read_u32(data, 29);
        let model_id_len = read_u16(data, 33) as usize;
        let model_id = if model_id_len > 0
            && model_id_len <= CCXE_MODEL_ID_MAX_LEN
            && CCXE_MODEL_ID_OFFSET + model_id_len <= CCXE_HEADER_LEN
        {
            String::from_utf8_lossy(&data[CCXE_MODEL_ID_OFFSET..CCXE_MODEL_ID_OFFSET + model_id_len]).to_string()
        } else {
            String::new()
        };
        let metadata_len = if version >= CCXE_VERSION_V2 {
            read_u32(data, CCXE_V2_METADATA_LEN_OFFSET) as usize
        } else {
            0
        };
        let metadata_end = CCXE_HEADER_LEN
            .checked_add(metadata_len)
            .ok_or(IndexError::BufferTooSmall)?;
        if metadata_end > data.len().saturating_sub(CCXE_FOOTER_LEN) {
            return Err(IndexError::BufferTooSmall);
        }
        let (build_fingerprint, calibration_vector, turbo_params) = if version >= CCXE_VERSION_V2 && metadata_len > 0 {
            parse_v2_metadata(&data[CCXE_HEADER_LEN..metadata_end])
                .map(|m| (m.build_fingerprint, m.calibration_vector, m.turbo_params))
                .unwrap_or((None, None, None))
        } else {
            (None, None, None)
        };

        // A turbo-mode header MUST carry turbo params, else the segment is corrupt.
        if quantization.is_turbo() && turbo_params.is_none() {
            return Err(IndexError::IntegrityFailure {
                msg: format!("turbo quant {quant_byte} without metadata params"),
            });
        }

        let vector_area_len = match &turbo_params {
            Some(p) => total_frames as usize * turboquant::packed_vector_len(p.padded_dim, p.bits),
            None => total_frames as usize * dim as usize * quantization.bytes_per_dim(),
        };
        let doc_table_len = total_frames as usize * 4;

        if data.len() < metadata_end + vector_area_len + doc_table_len + CCXE_FOOTER_LEN {
            return Err(IndexError::BufferTooSmall);
        }

        // TurboQuant: keep the codes PACKED resident (the RAM win); do NOT expand
        // to Vec<Vec<f32>>. Scoring decodes per-doc on demand.
        if let Some(params) = turbo_params {
            let stride = turboquant::packed_vector_len(params.padded_dim, params.bits);
            let codes = build_vector_bytes(data, metadata_end, vector_area_len);
            let mut offset = metadata_end + vector_area_len;
            let mut doc_ids = Vec::with_capacity(total_frames as usize);
            for _ in 0..total_frames {
                doc_ids.push(read_u32(data, offset));
                offset += 4;
            }
            return Ok(Self {
                header: CcxeHeader {
                    magic,
                    version,
                    shard_id,
                    segment_seq,
                    epoch,
                    dim,
                    quantization,
                    total_frames,
                    model_id_len: model_id_len as u16,
                    model_id,
                },
                build_fingerprint,
                calibration_vector,
                vectors: Vec::new(),
                packed: Some(PackedVectors { codes, params, stride }),
                int8_packed: None,
                doc_ids,
            });
        }

        // Int8Packed always keeps the int8 codes resident (1 byte/dim) and decodes
        // q/127 in scoring. Plain Int8 does the SAME when mmap-loaded (issue #195):
        // keep the raw i8 codes file-backed (`VectorBytes::Mapped`) and decode
        // q/127 per-vector in scoring, instead of eagerly dequantising to a
        // resident `Vec<Vec<f32>>`. The decode (`(b as i8) as f32 / 127.0`) and the
        // downstream cosine math are byte-identical to the eager per-element Int8
        // path below, so scores are bit-exact — but the codes become reclaimable
        // page cache, not anonymous heap. Heap-loaded Int8 (`from_bytes`,
        // `mmap == None`) keeps the historical eager f32 expansion so non-mmap
        // callers are unchanged.
        let int8_decode_in_scoring = quantization.is_int8_packed();
        if int8_decode_in_scoring {
            let codes = build_vector_bytes(data, metadata_end, vector_area_len);
            let mut offset = metadata_end + vector_area_len;
            let mut doc_ids = Vec::with_capacity(total_frames as usize);
            for _ in 0..total_frames {
                doc_ids.push(read_u32(data, offset));
                offset += 4;
            }
            return Ok(Self {
                header: CcxeHeader {
                    magic,
                    version,
                    shard_id,
                    segment_seq,
                    epoch,
                    dim,
                    quantization,
                    total_frames,
                    model_id_len: model_id_len as u16,
                    model_id,
                },
                build_fingerprint,
                calibration_vector,
                vectors: Vec::new(),
                packed: None,
                int8_packed: Some(Int8PackedVectors {
                    codes,
                    dim: dim as usize,
                }),
                doc_ids,
            });
        }

        // Decode vectors (per-element modes)
        let mut vectors = Vec::with_capacity(total_frames as usize);
        let mut offset = metadata_end;
        for _ in 0..total_frames {
            let mut vec = Vec::with_capacity(dim as usize);
            for _ in 0..dim {
                let val = match quantization {
                    Quantization::TurboQuant4 | Quantization::TurboQuant2 | Quantization::Int8Packed => {
                        unreachable!("packed-resident modes handled above")
                    }
                    Quantization::Float32 => {
                        let v =
                            f32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
                        offset += 4;
                        v
                    }
                    Quantization::Float16 => {
                        let bits = u16::from_le_bytes([data[offset], data[offset + 1]]);
                        offset += 2;
                        f16_to_f32(bits)
                    }
                    Quantization::Int8 => {
                        let q = data[offset] as i8;
                        offset += 1;
                        q as f32 / 127.0 // dequantize to [-1, 1] range
                    }
                };
                vec.push(val);
            }
            vectors.push(vec);
        }

        // Decode doc IDs
        let mut doc_ids = Vec::with_capacity(total_frames as usize);
        for _ in 0..total_frames {
            doc_ids.push(read_u32(data, offset));
            offset += 4;
        }

        Ok(Self {
            header: CcxeHeader {
                magic,
                version,
                shard_id,
                segment_seq,
                epoch,
                dim,
                quantization,
                total_frames,
                model_id_len: model_id_len as u16,
                model_id,
            },
            build_fingerprint,
            calibration_vector,
            vectors,
            packed: None,
            int8_packed: None,
            doc_ids,
        })
    }

    pub fn header_version(&self) -> u16 {
        self.header.version
    }

    pub fn build_fingerprint(&self) -> Option<&CcxeBuildFingerprint> {
        self.build_fingerprint.as_ref()
    }

    pub fn calibration_vector(&self) -> Option<&[f32]> {
        self.calibration_vector.as_deref()
    }

    /// Cosine similarity between a query vector and all stored vectors.
    /// Returns (doc_id, score) sorted by score descending.
    pub fn cosine_search(&self, query: &[f32], top_k: usize) -> Vec<(u32, f32)> {
        self.cosine_search_filtered(query, top_k, |_| true)
    }

    /// Cosine similarity with a per-doc filter applied before scoring.
    ///
    /// Originally added for tenant isolation — `IndexManager::cosine_search`
    /// passes a closure that checks each doc's `tenant_hash_full` against the
    /// caller's tenant. Without this, the dense lane scans all stored vectors
    /// globally and can return foreign-tenant docs at the top of the result
    /// set whenever the BM25 lane (which does have a tenant filter) ties or
    /// scores low. See `cosine-tenant-filter-gap-2026-05-04.md`.
    ///
    /// `keep` is invoked once per doc; only docs for which it returns `true`
    /// participate in the cosine computation. Returning `|_| true` is
    /// equivalent to the unfiltered `cosine_search`.
    pub fn cosine_search_filtered<F>(&self, query: &[f32], top_k: usize, keep: F) -> Vec<(u32, f32)>
    where
        F: Fn(u32) -> bool,
    {
        if query.len() != self.header.dim as usize {
            return Vec::new();
        }
        let query_norm = query.iter().map(|v| v * v).sum::<f32>().sqrt().max(1e-10);

        // TurboQuant: rotate the query ONCE into the packed/rotated space, then
        // decode each kept doc on demand and length-renormalise (the rotation is
        // orthonormal so cosine is preserved). Tenant `keep` still gates every doc.
        let mut scores: Vec<(u32, f32)> = if let Some(p) = &self.packed {
            if p.is_empty() {
                return Vec::new();
            }
            let rq = turboquant::rotate_padded(query, &p.params);
            self.doc_ids
                .iter()
                .enumerate()
                .filter(|(_, &doc_id)| keep(doc_id))
                .map(|(i, &doc_id)| {
                    let decoded = p.decode(i);
                    (doc_id, turboquant::cosine_rotated(&decoded, &rq, query_norm))
                })
                .collect()
        } else if let Some(ip) = &self.int8_packed {
            // Int8Packed: decode q/127 per doc on demand (no rotation). Recall-neutral.
            if ip.is_empty() {
                return Vec::new();
            }
            self.doc_ids
                .iter()
                .enumerate()
                .filter(|(_, &doc_id)| keep(doc_id))
                .map(|(i, &doc_id)| {
                    let vec = ip.decode(i);
                    let dot: f32 = query.iter().zip(vec.iter()).map(|(a, b)| a * b).sum();
                    let vec_norm = vec.iter().map(|v| v * v).sum::<f32>().sqrt().max(1e-10);
                    (doc_id, dot / (query_norm * vec_norm))
                })
                .collect()
        } else {
            if self.vectors.is_empty() {
                return Vec::new();
            }
            self.vectors
                .iter()
                .zip(self.doc_ids.iter())
                .filter(|(_, &doc_id)| keep(doc_id))
                .map(|(vec, &doc_id)| {
                    let dot: f32 = query.iter().zip(vec.iter()).map(|(a, b)| a * b).sum();
                    let vec_norm = vec.iter().map(|v| v * v).sum::<f32>().sqrt().max(1e-10);
                    (doc_id, dot / (query_norm * vec_norm))
                })
                .collect()
        };

        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scores.truncate(top_k);
        scores
    }

    /// Score ONLY the given segment-local STORAGE INDICES against `query` and
    /// return `(doc_id, score)` capped to `top_k` — the IVF-Flat re-rank stage.
    ///
    /// `indices` are positions into this `.ccxe`'s vector array (the values an
    /// `.ccxann` companion stores in its inverted lists). The cosine math is
    /// byte-identical to [`Self::cosine_search_filtered`], so an *exhaustive*
    /// candidate set (every index) yields the same result as the full scan —
    /// the ANN path is exact up to which indices it selects. Cost is
    /// `O(candidates × dim)`, not `O(N × dim)`: that is the sublinear win that
    /// lets the dense lane serve a corpus far larger than a per-query full scan
    /// can. `keep` gates by resolved `doc_id` (tenant isolation), exactly as the
    /// scan path does; out-of-range indices are skipped.
    pub fn cosine_search_indices<F>(&self, query: &[f32], top_k: usize, indices: &[u32], keep: F) -> Vec<(u32, f32)>
    where
        F: Fn(u32) -> bool,
    {
        if query.len() != self.header.dim as usize {
            return Vec::new();
        }
        let n = self.num_vectors();
        let query_norm = query.iter().map(|v| v * v).sum::<f32>().sqrt().max(1e-10);
        // TurboQuant: rotate the query ONCE (orthonormal rotation preserves cosine).
        // Carried together with the packed set so "rotated query exists iff packed
        // exists" is a property of the type rather than an assertion in the loop.
        let packed_rq = self
            .packed
            .as_ref()
            .map(|p| (p, turboquant::rotate_padded(query, &p.params)));

        let mut scores: Vec<(u32, f32)> = Vec::with_capacity(indices.len());
        for &idx in indices {
            let i = idx as usize;
            if i >= n {
                continue;
            }
            let Some(&doc_id) = self.doc_ids.get(i) else {
                continue;
            };
            if !keep(doc_id) {
                continue;
            }
            let score = if let Some((p, rq)) = &packed_rq {
                let decoded = p.decode(i);
                turboquant::cosine_rotated(&decoded, rq, query_norm)
            } else if let Some(ip) = &self.int8_packed {
                let vec = ip.decode(i);
                let dot: f32 = query.iter().zip(vec.iter()).map(|(a, b)| a * b).sum();
                let vec_norm = vec.iter().map(|v| v * v).sum::<f32>().sqrt().max(1e-10);
                dot / (query_norm * vec_norm)
            } else {
                let Some(vec) = self.vectors.get(i) else {
                    continue;
                };
                let dot: f32 = query.iter().zip(vec.iter()).map(|(a, b)| a * b).sum();
                let vec_norm = vec.iter().map(|v| v * v).sum::<f32>().sqrt().max(1e-10);
                dot / (query_norm * vec_norm)
            };
            scores.push((doc_id, score));
        }
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scores.truncate(top_k);
        scores
    }

    /// Number of stored vectors regardless of representation (f32 or packed).
    pub fn num_vectors(&self) -> usize {
        if let Some(p) = &self.packed {
            p.len()
        } else if let Some(ip) = &self.int8_packed {
            ip.len()
        } else {
            self.vectors.len()
        }
    }

    /// True when this reader's packed vector codes are file-backed rather than
    /// heap-resident — i.e. the dense bytes are reclaimable page cache, not
    /// anonymous RAM.
    ///
    /// **Always `false` in the CE.** Upstream this reports the mmap backing that
    /// lets the dataplane's RAM budget reclaim dense bytes; there is no mmap here
    /// (`unsafe_code = "forbid"`), so every reader is heap-resident. Retained so
    /// call sites and tests read the same as upstream.
    pub fn dense_is_file_backed(&self) -> bool {
        VectorBytes::is_mapped()
    }

    /// True when reloading this reader via [`Self::from_path`] WOULD make its
    /// dense codes file-backed — i.e. the on-disk mode decodes-in-scoring
    /// (TurboQuant, Int8Packed, or Int8 post-#195). The per-element
    /// `Float32`/`Float16` modes dequantise to a resident `Vec<Vec<f32>>` under
    /// mmap too, so mapping them frees nothing. The M2 RAM-budget enforcer uses
    /// this to SKIP a throwaway reload of an unconvertible heap reader (which
    /// would otherwise re-mmap + re-dequantise the same f32 payload every tick).
    pub fn dense_mmap_convertible(&self) -> bool {
        match self.header.quantization {
            Quantization::Float32 | Quantization::Float16 => false,
            Quantization::Int8 | Quantization::Int8Packed | Quantization::TurboQuant4 | Quantization::TurboQuant2 => {
                true
            }
        }
    }

    /// Decode all vectors to f32. For per-element modes this clones `vectors`; for
    /// TurboQuant modes it decodes from the packed codes (rotated space). Used by
    /// the rebuild path, which needs f32 vectors regardless of on-disk mode.
    pub fn decoded_vectors(&self) -> Vec<Vec<f32>> {
        if let Some(p) = &self.packed {
            (0..p.len()).map(|i| p.decode_orig(i)).collect()
        } else if let Some(ip) = &self.int8_packed {
            (0..ip.len()).map(|i| ip.decode(i)).collect()
        } else {
            self.vectors.clone()
        }
    }

    /// Decode a single vector by index, regardless of on-disk mode. Returns `None`
    /// if `i` is out of range. Used by the compaction merge path (which copies
    /// source-segment vectors one at a time). For TurboQuant the returned vector is
    /// in the rotated space — re-encoding through `CcxeBuilder` re-normalises and
    /// re-rotates, so this round-trips correctly through compaction.
    pub fn vector_at(&self, i: usize) -> Option<Vec<f32>> {
        if let Some(p) = &self.packed {
            (i < p.len()).then(|| p.decode_orig(i))
        } else if let Some(ip) = &self.int8_packed {
            (i < ip.len()).then(|| ip.decode(i))
        } else {
            self.vectors.get(i).cloned()
        }
    }
}

impl CcxeReader {
    /// Anonymous-heap bytes held by this dense reader: vector codes plus the
    /// small heap sidecars (TurboQuant levels, doc-id table, expanded f32).
    ///
    /// **CE port note.** Upstream derives this from
    /// `corecrux_memreport::MemoryReporter`, a dataplane-only crate that also
    /// carries the human-readable breakdown and the mmap/heap split. Neither the
    /// crate nor the mmap backing exists here, so this is computed directly and
    /// everything it reports is anonymous heap. There is no `dense_mapped_bytes`
    /// in the CE — it would be constant zero.
    pub fn dense_heap_bytes(&self) -> u64 {
        let doc_ids = (self.doc_ids.len() as u64) * 4;
        if let Some(p) = &self.packed {
            let levels = (p.params.levels.len() as u64) * 4;
            return p.codes.resident_len() as u64 + levels + doc_ids;
        }
        if let Some(ip) = &self.int8_packed {
            return ip.codes.resident_len() as u64 + doc_ids;
        }
        let vectors: u64 = self.vectors.iter().map(|v| (v.len() as u64) * 4).sum();
        vectors + doc_ids
    }
}

// ── Helper functions ──

/// Build the backing for a packed vector area: a heap copy (`Owned`) when there
/// is no mapping, or a zero-copy reference into the shared `mmap` (`Mapped`).
fn build_vector_bytes(data: &[u8], offset: usize, len: usize) -> VectorBytes {
    VectorBytes::Owned(data[offset..offset + len].to_vec())
}

fn write_u16(buf: &mut [u8], offset: usize, val: u16) {
    buf[offset..offset + 2].copy_from_slice(&val.to_le_bytes());
}

fn write_u32(buf: &mut [u8], offset: usize, val: u32) {
    buf[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64(buf: &mut [u8], offset: usize, val: u64) {
    buf[offset..offset + 8].copy_from_slice(&val.to_le_bytes());
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
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

fn write_leb128_string(out: &mut Vec<u8>, value: &str) {
    write_leb128_u32(out, value.len() as u32);
    out.extend_from_slice(value.as_bytes());
}

fn write_leb128_u32(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

#[derive(Default)]
struct CcxeV2Metadata {
    build_fingerprint: Option<CcxeBuildFingerprint>,
    calibration_vector: Option<Vec<f32>>,
    turbo_params: Option<TurboParams>,
}

fn parse_v2_metadata(data: &[u8]) -> Result<CcxeV2Metadata, ()> {
    if data.len() < CCXE_V2_METADATA_MAGIC.len() + 1 {
        return Err(());
    }
    if &data[..CCXE_V2_METADATA_MAGIC.len()] != CCXE_V2_METADATA_MAGIC {
        return Err(());
    }

    let mut offset = CCXE_V2_METADATA_MAGIC.len();
    let flags = data[offset];
    offset += 1;

    let mut metadata = CcxeV2Metadata::default();

    if flags & CCXE_V2_FLAG_FINGERPRINT != 0 {
        let served_model_name = read_leb128_string(data, &mut offset)?;
        let dim = read_u16_checked(data, &mut offset)?;
        let dtype = read_leb128_string(data, &mut offset)?;
        let batch_size = read_u32_checked(data, &mut offset)?;
        let embedder_version = read_leb128_string(data, &mut offset)?;

        metadata.build_fingerprint = Some(CcxeBuildFingerprint {
            served_model_name,
            dim,
            dtype,
            batch_size,
            embedder_version,
        });
    }

    if flags & CCXE_V2_FLAG_CALIBRATION_VECTOR != 0 {
        let len = read_leb128_u32(data, &mut offset)? as usize;
        let bytes_len = len.checked_mul(4).ok_or(())?;
        let end = offset.checked_add(bytes_len).ok_or(())?;
        if end > data.len() {
            return Err(());
        }
        let mut vector = Vec::with_capacity(len);
        while offset < end {
            vector.push(f32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]));
            offset += 4;
        }
        metadata.calibration_vector = Some(vector);
    }

    if flags & CCXE_V2_FLAG_TURBOQUANT != 0 {
        let seed = read_u64_checked(data, &mut offset)?;
        let orig_dim = read_u32_checked(data, &mut offset)? as usize;
        let padded_dim = read_u32_checked(data, &mut offset)? as usize;
        if offset >= data.len() {
            return Err(());
        }
        let bits = data[offset];
        offset += 1;
        let nlevels = read_leb128_u32(data, &mut offset)? as usize;
        let bytes_len = nlevels.checked_mul(4).ok_or(())?;
        let end = offset.checked_add(bytes_len).ok_or(())?;
        if end > data.len() {
            return Err(());
        }
        let mut levels = Vec::with_capacity(nlevels);
        while offset < end {
            levels.push(f32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]));
            offset += 4;
        }
        metadata.turbo_params = Some(TurboParams {
            seed,
            orig_dim,
            padded_dim,
            bits,
            levels,
        });
    }

    Ok(metadata)
}

fn read_leb128_string(data: &[u8], offset: &mut usize) -> Result<String, ()> {
    let len = read_leb128_u32(data, offset)? as usize;
    let end = offset.checked_add(len).ok_or(())?;
    if end > data.len() {
        return Err(());
    }
    let s = std::str::from_utf8(&data[*offset..end]).map_err(|_| ())?;
    *offset = end;
    Ok(s.to_string())
}

fn read_leb128_u32(data: &[u8], offset: &mut usize) -> Result<u32, ()> {
    let mut value = 0u32;
    let mut shift = 0u32;
    loop {
        if *offset >= data.len() || shift >= 35 {
            return Err(());
        }
        let byte = data[*offset];
        *offset += 1;
        value |= ((byte & 0x7f) as u32) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn read_u16_checked(data: &[u8], offset: &mut usize) -> Result<u16, ()> {
    let end = offset.checked_add(2).ok_or(())?;
    if end > data.len() {
        return Err(());
    }
    let value = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
    *offset = end;
    Ok(value)
}

fn read_u32_checked(data: &[u8], offset: &mut usize) -> Result<u32, ()> {
    let end = offset.checked_add(4).ok_or(())?;
    if end > data.len() {
        return Err(());
    }
    let value = u32::from_le_bytes([data[*offset], data[*offset + 1], data[*offset + 2], data[*offset + 3]]);
    *offset = end;
    Ok(value)
}

fn read_u64_checked(data: &[u8], offset: &mut usize) -> Result<u64, ()> {
    let end = offset.checked_add(8).ok_or(())?;
    if end > data.len() {
        return Err(());
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[*offset..end]);
    *offset = end;
    Ok(u64::from_le_bytes(b))
}

/// Convert f32 to f16 (IEEE 754 half precision).
fn f32_to_f16(val: f32) -> u16 {
    let bits = val.to_bits();
    let sign = (bits >> 16) & 0x8000;
    let exponent = ((bits >> 23) & 0xFF) as i32;
    let mantissa = bits & 0x7FFFFF;

    if exponent == 0xFF {
        // Inf/NaN
        return (sign | 0x7C00 | if mantissa != 0 { 0x200 } else { 0 }) as u16;
    }

    let new_exp = exponent - 127 + 15;
    if new_exp >= 31 {
        return (sign | 0x7C00) as u16; // overflow → Inf
    }
    if new_exp <= 0 {
        return sign as u16; // underflow → 0
    }

    (sign | ((new_exp as u32) << 10) | (mantissa >> 13)) as u16
}

/// Convert f16 to f32.
fn f16_to_f32(bits: u16) -> f32 {
    let sign = ((bits & 0x8000) as u32) << 16;
    let exponent = ((bits >> 10) & 0x1F) as u32;
    let mantissa = (bits & 0x3FF) as u32;

    if exponent == 0 {
        if mantissa == 0 {
            return f32::from_bits(sign);
        }
        // Subnormal
        let mut e = 1u32;
        let mut m = mantissa;
        while (m & 0x400) == 0 {
            m <<= 1;
            e += 1;
        }
        let exp = (127 - 15 - e + 1) << 23;
        let man = (m & 0x3FF) << 13;
        return f32::from_bits(sign | exp | man);
    }
    if exponent == 31 {
        let f32_exp = 0xFF << 23;
        let f32_man = mantissa << 13;
        return f32::from_bits(sign | f32_exp | f32_man);
    }

    let f32_exp = (exponent + 127 - 15) << 23;
    let f32_man = mantissa << 13;
    f32::from_bits(sign | f32_exp | f32_man)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drift guard (corecrux-memory-manager-2026-07-05): destructure every
    /// field of `CcxeReader` so a new heap-holding field fails compilation
    /// until dense heap/mapped accounting is updated. Each field is mapped to
    /// how the ledger accounts it.
    #[test]
    fn ccxe_reader_accounting_field_checklist() {
        let mut b = CcxeBuilder::new(0, 1, 100, 8, "drift-guard-embedder");
        b.set_quantization(Quantization::Float32);
        b.add_vector(0, vec![0.0f32; 8]);
        let reader = CcxeReader::from_bytes(&b.build()).expect("from_bytes");
        let CcxeReader {
            header,
            build_fingerprint,
            calibration_vector,
            vectors,
            packed,
            int8_packed,
            doc_ids,
        } = &reader;
        // header / build_fingerprint → identity, no heap attribution.
        // vectors / packed / int8_packed / calibration_vector / doc_ids →
        //   folded into dense_heap_bytes (via report_memory).
        // packed / int8_packed mapped codes → dense_mapped_bytes.
        let _ = (header.dim, build_fingerprint.is_some());
        let _ = (
            vectors.len(),
            packed.is_some(),
            int8_packed.is_some(),
            calibration_vector.is_some(),
            doc_ids.len(),
        );
        assert!(reader.dense_heap_bytes() > 0, "f32 vectors are heap-resident");
    }

    #[test]
    fn model_id_file_key_sanitises() {
        // The slash (illegal in a filename) and case collapse to a safe key.
        assert_eq!(model_id_file_key("BAAI/bge-m3"), "baai-bge-m3");
        assert_eq!(model_id_file_key("nomic-embed-text-v1.5"), "nomic-embed-text-v1.5");
        // Runs of unsafe chars coalesce; edges trim; never empty.
        assert_eq!(model_id_file_key("  weird@@name!! "), "weird-name");
        assert_eq!(model_id_file_key("///"), "unknown");
        assert_eq!(model_id_file_key(""), "unknown");
        // Two distinct ids that sanitise apart stay apart (the common case).
        assert_ne!(model_id_file_key("BAAI/bge-m3"), model_id_file_key("intfloat/e5-large"));
    }

    /// CC9 — the footer BLAKE3 hashes verify clean on a well-formed build, and
    /// a single flipped bit in the vector area or the doc table fails LOUDLY,
    /// while `from_bytes` (structure-only) still parses the corrupted buffer —
    /// which is exactly why the verify pass exists.
    #[test]
    fn verify_footer_hashes_catches_bit_flips() {
        for quant in [
            Quantization::Float32,
            Quantization::Float16,
            Quantization::Int8,
            Quantization::Int8Packed,
        ] {
            let mut builder = CcxeBuilder::new(1, 9, 100, 4, "test-model");
            builder.set_quantization(quant);
            builder.add_vector(10, vec![0.5, -0.3, 0.8, -0.1]);
            builder.add_vector(11, vec![-0.2, 0.6, -0.4, 0.9]);
            let bytes = builder.build();

            // Pristine bytes verify clean.
            verify_footer_hashes(&bytes).unwrap();

            // Locate the areas (v1 file: no metadata).
            let dim = 4usize;
            let vec_len = 2 * dim * quant.bytes_per_dim();
            let vector_start = CCXE_HEADER_LEN;
            let doc_start = vector_start + vec_len;

            // Bit-flip inside the vector area.
            let mut corrupt = bytes.clone();
            corrupt[vector_start + vec_len / 2] ^= 0x01;
            let err = verify_footer_hashes(&corrupt).unwrap_err();
            assert!(
                err.to_string().contains("vector-area"),
                "{quant:?}: expected a vector-area mismatch, got: {err}"
            );
            // The structural parser accepts the corrupted buffer — silent-serve
            // hazard the verify pass closes.
            CcxeReader::from_bytes(&corrupt).expect("structure-only parse must still succeed on bit rot");

            // Bit-flip inside the doc-id table.
            let mut corrupt_doc = bytes.clone();
            corrupt_doc[doc_start + 2] ^= 0x80;
            let err = verify_footer_hashes(&corrupt_doc).unwrap_err();
            assert!(
                err.to_string().contains("doc-table"),
                "{quant:?}: expected a doc-table mismatch, got: {err}"
            );
        }
    }

    /// CC9 — verification is layout-aware for v2 metadata (fingerprint +
    /// calibration) and the turbo packed modes.
    #[test]
    fn verify_footer_hashes_v2_and_turbo() {
        let fp = CcxeBuildFingerprint {
            served_model_name: "BAAI/bge-m3".to_string(),
            dim: 8,
            dtype: "float16".to_string(),
            batch_size: 32,
            embedder_version: "tei-1.9".to_string(),
        };
        let mut builder = CcxeBuilder::new(2, 21, 100, 8, "BAAI/bge-m3");
        builder.set_build_fingerprint(fp);
        builder.set_calibration_vector(vec![0.25; 8]);
        builder.set_quantization(Quantization::TurboQuant4);
        builder.set_turbo_seed(configured_turbo_seed(21));
        for i in 0..5u32 {
            let v: Vec<f32> = (0..8).map(|j| ((i + j) as f32 * 0.11).sin()).collect();
            builder.add_vector(i, v);
        }
        let bytes = builder.build();
        verify_footer_hashes(&bytes).unwrap();

        // Any vector-area flip is caught under turbo layout too.
        let mut corrupt = bytes.clone();
        let flip_at = bytes.len() - CCXE_FOOTER_LEN - 5 * 4 - 1; // last vector byte
        corrupt[flip_at] ^= 0x10;
        assert!(verify_footer_hashes(&corrupt).is_err());

        // Truncated buffer errors as too-small, not a hash mismatch panic.
        let truncated = &bytes[..bytes.len() - CCXE_FOOTER_LEN - 1];
        assert!(matches!(
            verify_footer_hashes(truncated),
            Err(IndexError::BufferTooSmall)
        ));
    }

    #[test]
    fn round_trip_float32() {
        let mut builder = CcxeBuilder::new(0, 1, 100, 4, "test-model");
        builder.set_quantization(Quantization::Float32);
        builder.add_vector(0, vec![0.1, 0.2, 0.3, 0.4]);
        builder.add_vector(1, vec![0.5, 0.6, 0.7, 0.8]);

        let bytes = builder.build();
        let reader = CcxeReader::from_bytes(&bytes).unwrap();

        assert_eq!(reader.header_version(), CCXE_VERSION_V1);
        assert_eq!(reader.header.total_frames, 2);
        assert_eq!(reader.header.dim, 4);
        assert_eq!(reader.header.model_id, "test-model");
        assert_eq!(reader.build_fingerprint(), None);
        assert_eq!(reader.calibration_vector(), None);
        assert_eq!(reader.doc_ids, vec![0, 1]);
        assert!((reader.vectors[0][0] - 0.1).abs() < 1e-6);
    }

    #[test]
    fn round_trip_v2_fingerprint() {
        let fp = CcxeBuildFingerprint {
            served_model_name: "BAAI/bge-m3".to_string(),
            dim: 1024,
            dtype: "float32".to_string(),
            batch_size: 128,
            embedder_version: "tei-test-sha".to_string(),
        };
        let mut builder = CcxeBuilder::new(7, 42, 100, 4, "BAAI/bge-m3").with_build_fingerprint(fp.clone());
        builder.set_quantization(Quantization::Float32);
        builder.add_vector(3, vec![0.1, 0.2, 0.3, 0.4]);

        let bytes = builder.build();
        let reader = CcxeReader::from_bytes(&bytes).unwrap();

        assert_eq!(reader.header_version(), CCXE_VERSION_V2);
        assert_eq!(reader.header.shard_id, 7);
        assert_eq!(reader.header.segment_seq, 42);
        assert_eq!(reader.header.total_frames, 1);
        assert_eq!(reader.doc_ids, vec![3]);
        assert_eq!(reader.build_fingerprint(), Some(&fp));
        assert_eq!(reader.calibration_vector(), None);
        assert!((reader.vectors[0][2] - 0.3).abs() < 1e-6);
    }

    #[test]
    fn round_trip_v2_fingerprint_and_calibration_vector() {
        let fp = CcxeBuildFingerprint {
            served_model_name: "BAAI/bge-m3".to_string(),
            dim: 4,
            dtype: "float32".to_string(),
            batch_size: 128,
            embedder_version: "tei-test-sha".to_string(),
        };
        let calibration = vec![0.25, 0.5, 0.75, 1.0];
        let mut builder = CcxeBuilder::new(7, 43, 100, 4, "BAAI/bge-m3")
            .with_build_fingerprint(fp.clone())
            .with_calibration_vector(calibration.clone());
        builder.set_quantization(Quantization::Float32);
        builder.add_vector(3, vec![0.1, 0.2, 0.3, 0.4]);

        let bytes = builder.build();
        let reader = CcxeReader::from_bytes(&bytes).unwrap();

        assert_eq!(reader.header_version(), CCXE_VERSION_V2);
        assert_eq!(reader.build_fingerprint(), Some(&fp));
        assert_eq!(reader.calibration_vector(), Some(calibration.as_slice()));
        assert_eq!(reader.doc_ids, vec![3]);
    }

    #[test]
    fn malformed_v2_metadata_keeps_vectors_with_unknown_fingerprint() {
        let fp = CcxeBuildFingerprint {
            served_model_name: "BAAI/bge-m3".to_string(),
            dim: 1024,
            dtype: "float32".to_string(),
            batch_size: 64,
            embedder_version: "tei-test-sha".to_string(),
        };
        let mut builder = CcxeBuilder::new(0, 1, 100, 3, "BAAI/bge-m3").with_build_fingerprint(fp);
        builder.set_quantization(Quantization::Float32);
        builder.add_vector(0, vec![1.0, 0.0, 0.0]);

        let mut bytes = builder.build();
        bytes[CCXE_HEADER_LEN] = b'X';

        let reader = CcxeReader::from_bytes(&bytes).unwrap();
        assert_eq!(reader.header_version(), CCXE_VERSION_V2);
        assert_eq!(reader.build_fingerprint(), None);
        assert_eq!(reader.calibration_vector(), None);
        assert_eq!(reader.cosine_search(&[1.0, 0.0, 0.0], 1)[0].0, 0);
    }

    #[test]
    fn round_trip_int8() {
        let mut builder = CcxeBuilder::new(0, 1, 100, 4, "nomic");
        // default is int8
        builder.add_vector(0, vec![0.5, -0.3, 0.8, -0.1]);

        let bytes = builder.build();
        let reader = CcxeReader::from_bytes(&bytes).unwrap();

        assert_eq!(reader.header.quantization, Quantization::Int8);
        // int8 loses precision but direction is preserved
        assert!(reader.vectors[0][0] > 0.0);
        assert!(reader.vectors[0][1] < 0.0);
        assert!(reader.vectors[0][2] > 0.0);
    }

    #[test]
    fn cosine_search_finds_nearest() {
        let mut builder = CcxeBuilder::new(0, 1, 100, 3, "test");
        builder.set_quantization(Quantization::Float32);
        builder.add_vector(0, vec![1.0, 0.0, 0.0]); // x-axis
        builder.add_vector(1, vec![0.0, 1.0, 0.0]); // y-axis
        builder.add_vector(2, vec![0.7, 0.7, 0.0]); // between x and y

        let bytes = builder.build();
        let reader = CcxeReader::from_bytes(&bytes).unwrap();

        // Query close to x-axis
        let results = reader.cosine_search(&[0.9, 0.1, 0.0], 3);
        assert_eq!(results[0].0, 0); // x-axis doc should be top
    }

    #[test]
    fn cosine_search_indices_exhaustive_equals_full_scan() {
        // The exactness guarantee the IVF-Flat re-rank relies on: scoring ALL
        // storage indices via cosine_search_indices == the full cosine_search,
        // for every quantization mode. (Stable sort + identical iteration order
        // ⇒ byte-identical result, ties included.)
        for q in [Quantization::Float32, Quantization::Int8, Quantization::Int8Packed] {
            let mut builder = CcxeBuilder::new(0, 1, 100, 4, "test");
            builder.set_quantization(q);
            let vecs = [
                [1.0, 0.0, 0.0, 0.0],
                [0.0, 1.0, 0.0, 0.0],
                [0.7, 0.7, 0.0, 0.0],
                [0.1, 0.2, 0.9, 0.0],
                [0.0, 0.0, 0.0, 1.0],
            ];
            for (i, v) in vecs.iter().enumerate() {
                builder.add_vector(i as u32, v.to_vec());
            }
            let reader = CcxeReader::from_bytes(&builder.build()).unwrap();
            let query = [0.6, 0.5, 0.1, 0.0];
            let full = reader.cosine_search(&query, 5);
            let all_idx: Vec<u32> = (0..reader.num_vectors() as u32).collect();
            let via_idx = reader.cosine_search_indices(&query, 5, &all_idx, |_| true);
            assert_eq!(full, via_idx, "mode {q:?}: exhaustive indices must equal full scan");
        }
    }

    #[test]
    fn cosine_search_indices_subset_keep_and_bounds() {
        let mut builder = CcxeBuilder::new(0, 1, 100, 3, "test");
        builder.set_quantization(Quantization::Float32);
        builder.add_vector(10, vec![1.0, 0.0, 0.0]);
        builder.add_vector(11, vec![0.0, 1.0, 0.0]);
        builder.add_vector(12, vec![0.9, 0.1, 0.0]);
        let reader = CcxeReader::from_bytes(&builder.build()).unwrap();
        // Score only storage indices 0 and 2 (doc_ids 10, 12); index 1 excluded.
        let r = reader.cosine_search_indices(&[1.0, 0.0, 0.0], 5, &[0, 2], |_| true);
        let ids: Vec<u32> = r.iter().map(|(id, _)| *id).collect();
        assert!(ids.contains(&10) && ids.contains(&12) && !ids.contains(&11));
        // keep filter drops doc_id 12.
        let r2 = reader.cosine_search_indices(&[1.0, 0.0, 0.0], 5, &[0, 2], |id| id != 12);
        let ids2: Vec<u32> = r2.iter().map(|(id, _)| *id).collect();
        assert!(ids2.contains(&10) && !ids2.contains(&12));
        // out-of-range index skipped (no panic).
        let r3 = reader.cosine_search_indices(&[1.0, 0.0, 0.0], 5, &[0, 99], |_| true);
        assert_eq!(r3.len(), 1);
    }

    #[test]
    fn memreport_reports_nonzero_bytes() {
        let mut builder = CcxeBuilder::new(0, 1, 100, 3, "test-model");
        builder.add_vector(0, vec![1.0, 0.0, 0.0]);
        builder.add_vector(1, vec![0.0, 1.0, 0.0]);
        builder.add_vector(2, vec![0.0, 0.0, 1.0]);
        let bytes = builder.build();
        let reader = CcxeReader::from_bytes(&bytes).unwrap();
        let resident = reader.dense_heap_bytes();
        assert!(resident > 0, "got {resident}");
        assert_eq!(reader.num_vectors(), 3);
    }

    // ── TurboQuant (M1 encode + M2 packed-resident decode-in-scoring) ──

    fn turbo_corpus(n: usize, dim: usize, seed: &mut u64) -> Vec<Vec<f32>> {
        (0..n)
            .map(|_| {
                (0..dim)
                    .map(|_| {
                        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                        ((*seed >> 33) as f64 / (1u64 << 31) as f64 - 1.0) as f32
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn turboquant4_roundtrips_and_is_packed_resident() {
        let mut s = 5u64;
        let dim = 64;
        let vecs = turbo_corpus(300, dim, &mut s);
        let mut b = CcxeBuilder::new(0, 1, 100, dim as u16, "nomic-embed-text-v1.5");
        b.set_quantization(Quantization::TurboQuant4);
        b.set_turbo_seed(777);
        for (i, v) in vecs.iter().enumerate() {
            b.add_vector(i as u32, v.clone());
        }
        let bytes = b.build();
        let reader = CcxeReader::from_bytes(&bytes).unwrap();

        // Packed-resident: vectors NOT expanded to f32; codes held packed.
        assert_eq!(reader.header.quantization, Quantization::TurboQuant4);
        assert!(reader.vectors.is_empty(), "turbo must not expand to Vec<Vec<f32>>");
        assert_eq!(reader.num_vectors(), 300);
        let packed = reader.packed.as_ref().unwrap();
        assert_eq!(packed.params.bits, 4);
        assert_eq!(
            packed.stride,
            crate::turboquant::packed_vector_len(packed.params.padded_dim, 4)
        );

        // RAM win: report ~< 1/4 of the f32 payload (4-bit on a pow2-padded 64-dim).
        let resident = reader.dense_heap_bytes();
        let f32_payload = (300 * dim * 4) as u64;
        assert!(
            resident * 4 < f32_payload,
            "no RAM win: {} vs f32 {f32_payload}",
            resident
        );
        assert_eq!(reader.num_vectors(), 300);
    }

    #[test]
    fn turboquant_search_is_recall_neutral_vs_f32() {
        let mut s = 21u64;
        let dim = 96;
        let vecs = turbo_corpus(250, dim, &mut s);

        // f32 reference reader
        let mut bf = CcxeBuilder::new(0, 1, 100, dim as u16, "m");
        bf.set_quantization(Quantization::Float32);
        for (i, v) in vecs.iter().enumerate() {
            bf.add_vector(i as u32, v.clone());
        }
        let rf = CcxeReader::from_bytes(&bf.build()).unwrap();

        // turbo4 reader
        let mut bt = CcxeBuilder::new(0, 1, 100, dim as u16, "m");
        bt.set_quantization(Quantization::TurboQuant4);
        bt.set_turbo_seed(31);
        for (i, v) in vecs.iter().enumerate() {
            bt.add_vector(i as u32, v.clone());
        }
        let rt = CcxeReader::from_bytes(&bt.build()).unwrap();

        let mut agree = 0;
        for q in vecs.iter().take(40) {
            let top_f32 = rf.cosine_search(q, 1)[0].0;
            let top_turbo = rt.cosine_search(q, 1)[0].0;
            if top_f32 == top_turbo {
                agree += 1;
            }
        }
        assert!(agree >= 37, "turbo top-1 recall vs f32 too low: {agree}/40");
    }

    #[test]
    fn turboquant2_builds_and_searches() {
        let mut s = 3u64;
        let dim = 32;
        let vecs = turbo_corpus(128, dim, &mut s);
        let mut b = CcxeBuilder::new(0, 1, 100, dim as u16, "m");
        b.set_quantization(Quantization::TurboQuant2);
        for (i, v) in vecs.iter().enumerate() {
            b.add_vector(i as u32, v.clone());
        }
        let reader = CcxeReader::from_bytes(&b.build()).unwrap();
        assert_eq!(reader.packed.as_ref().unwrap().params.bits, 2);
        assert_eq!(reader.cosine_search(&vecs[0], 5).len(), 5);
    }

    #[test]
    fn turbo_tenant_keep_filter_is_honoured() {
        // T.1: the keep closure must gate every scored doc even in turbo mode.
        let mut s = 9u64;
        let vecs = turbo_corpus(50, 16, &mut s);
        let mut b = CcxeBuilder::new(0, 1, 100, 16, "m");
        b.set_quantization(Quantization::TurboQuant4);
        for (i, v) in vecs.iter().enumerate() {
            b.add_vector(i as u32, v.clone());
        }
        let reader = CcxeReader::from_bytes(&b.build()).unwrap();
        // keep only even doc_ids
        let res = reader.cosine_search_filtered(&vecs[0], 50, |id| id % 2 == 0);
        assert!(res.iter().all(|(id, _)| id % 2 == 0), "keep filter leaked odd docs");
    }

    #[test]
    fn config_str_parses_modes() {
        assert_eq!(Quantization::from_config_str("int8"), Some(Quantization::Int8));
        assert_eq!(Quantization::from_config_str("TURBO4"), Some(Quantization::TurboQuant4));
        assert_eq!(Quantization::from_config_str(" tq2 "), Some(Quantization::TurboQuant2));
        assert_eq!(Quantization::from_config_str("nope"), None);
        // seed is deterministic + segment-varied
        assert_ne!(configured_turbo_seed(1), configured_turbo_seed(2));
        assert_eq!(configured_turbo_seed(7), configured_turbo_seed(7));
    }

    #[test]
    fn vector_at_returns_original_space_and_survives_recompaction() {
        // M4 compaction path: vector_at must return ORIGINAL-space (inverse-rotated)
        // vectors so re-encoding through the builder does not double-rotate. A second
        // generation must still find the right neighbour.
        let mut s = 4u64;
        let dim = 48;
        let vecs = turbo_corpus(200, dim, &mut s);
        let mut b1 = CcxeBuilder::new(0, 1, 100, dim as u16, "m");
        b1.set_quantization(Quantization::TurboQuant4);
        for (i, v) in vecs.iter().enumerate() {
            b1.add_vector(i as u32, v.clone());
        }
        let r1 = CcxeReader::from_bytes(&b1.build()).unwrap();

        // re-compact: pull original-space vectors out and re-encode (new generation)
        let mut b2 = CcxeBuilder::new(0, 2, 101, dim as u16, "m");
        b2.set_quantization(Quantization::TurboQuant4);
        for i in 0..r1.num_vectors() {
            b2.add_vector(i as u32, r1.vector_at(i).unwrap());
        }
        let r2 = CcxeReader::from_bytes(&b2.build()).unwrap();

        // gen-2 turbo search still agrees with the raw f32 nearest on most queries
        let mut bf = CcxeBuilder::new(0, 3, 102, dim as u16, "m");
        bf.set_quantization(Quantization::Float32);
        for (i, v) in vecs.iter().enumerate() {
            bf.add_vector(i as u32, v.clone());
        }
        let rf = CcxeReader::from_bytes(&bf.build()).unwrap();
        let mut agree = 0;
        for q in vecs.iter().take(30) {
            if rf.cosine_search(q, 1)[0].0 == r2.cosine_search(q, 1)[0].0 {
                agree += 1;
            }
        }
        assert!(agree >= 26, "gen-2 turbo recall too low after recompaction: {agree}/30");
    }

    #[test]
    fn int8_packed_is_recall_neutral_and_4x_smaller() {
        // Int8Packed must rank identically to plain Int8 (same on-disk codes, same
        // q/127 decode) while keeping codes resident at 1 byte/dim — the recall-
        // neutral RAM win. report_memory must be ~4x smaller than the f32 payload.
        let mut s = 8u64;
        let dim = 96;
        let vecs = turbo_corpus(300, dim, &mut s);

        let mut bi = CcxeBuilder::new(0, 1, 100, dim as u16, "m");
        bi.set_quantization(Quantization::Int8);
        for (i, v) in vecs.iter().enumerate() {
            bi.add_vector(i as u32, v.clone());
        }
        let ri = CcxeReader::from_bytes(&bi.build()).unwrap();

        let mut bp = CcxeBuilder::new(0, 1, 100, dim as u16, "m");
        bp.set_quantization(Quantization::Int8Packed);
        for (i, v) in vecs.iter().enumerate() {
            bp.add_vector(i as u32, v.clone());
        }
        let rp = CcxeReader::from_bytes(&bp.build()).unwrap();

        // packed-resident: no f32 expansion
        assert!(rp.vectors.is_empty());
        assert_eq!(rp.num_vectors(), 300);
        assert!(rp.int8_packed.is_some());

        // recall-neutral: identical top-5 ranking to plain int8 on every query
        for q in vecs.iter().take(40) {
            let a: Vec<u32> = ri.cosine_search(q, 5).into_iter().map(|(id, _)| id).collect();
            let b: Vec<u32> = rp.cosine_search(q, 5).into_iter().map(|(id, _)| id).collect();
            assert_eq!(a, b, "Int8Packed must rank identically to Int8");
        }

        // ~4x smaller resident than f32 (1 B/dim vs 4 B/dim).
        let f32_payload = (300 * dim * 4) as u64;
        let bytes = rp.dense_heap_bytes();
        assert!(
            bytes * 3 < f32_payload,
            "int8-packed not ~4x smaller: {bytes} vs {f32_payload}"
        );
    }

    #[test]
    fn unknown_quant_byte_fails_closed() {
        // Compat: an old-binary-style unknown quant byte must error, not mis-decode.
        let mut b = CcxeBuilder::new(0, 1, 100, 4, "m");
        b.set_quantization(Quantization::Float32);
        b.add_vector(0, vec![1.0, 0.0, 0.0, 0.0]);
        let mut bytes = b.build();
        bytes[28] = 99; // unknown quantization
        assert!(
            CcxeReader::from_bytes(&bytes).is_err(),
            "unknown quant must fail closed"
        );
    }

    /// Write `bytes` to a temp `.ccxe` and return (dir, path). The dir must be
    /// kept alive for the mmap to stay valid.
    fn write_temp_ccxe(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg.ccxe");
        std::fs::write(&path, bytes).unwrap();
        (dir, path)
    }

    #[test]
    fn from_path_per_element_float_mode_stays_resident() {
        // Float32/Float16 have no packed codes to map — `from_path` still
        // parses them correctly (dequantised resident), just without the RAM win.
        // Parity with the heap path must hold. (Int8 is now decode-in-scoring under
        // mmap; see `from_path_int8_is_file_backed_and_bit_exact`.)
        for quant in [Quantization::Float32, Quantization::Float16] {
            let mut b = CcxeBuilder::new(0, 1, 100, 3, "m");
            b.set_quantization(quant);
            b.add_vector(0, vec![1.0, 0.0, 0.0]);
            b.add_vector(1, vec![0.0, 1.0, 0.0]);
            let built = b.build();

            let (_dir, path) = write_temp_ccxe(&built);
            let mapped = CcxeReader::from_path(&path).unwrap();
            assert!(!mapped.dense_is_file_backed(), "{quant:?} dequant is resident");
            assert!(!mapped.dense_mmap_convertible(), "{quant:?} is not mmap-convertible");
            assert_eq!(mapped.num_vectors(), 2);
            assert_eq!(
                mapped.cosine_search(&[1.0, 0.0, 0.0], 1)[0].0,
                CcxeReader::from_bytes(&built)
                    .unwrap()
                    .cosine_search(&[1.0, 0.0, 0.0], 1)[0]
                    .0
            );
        }
    }

    /// A plain `Int8` `.ccxe` read from disk scores BIT-EXACTLY the same as the
    /// same bytes parsed in memory, across randomized vectors and queries, on both
    /// the full scan and the IVF-Flat re-rank path.
    ///
    /// **CE port note.** Upstream also asserts the from-path reader keeps its i8
    /// codes file-backed (`mmap`, decode-in-scoring) with resident heap ≈ 0 — the
    /// property behind `CORECRUXD_DENSE_RAM_BUDGET`. There is no mmap backing in
    /// the CE (`unsafe_code = "forbid"`), so plain `Int8` takes the eager f32
    /// expansion on both paths and the backing/heap-delta assertions are dropped.
    /// What survives is the half that still holds and still matters: reading from
    /// disk must not change a score.
    #[test]
    fn from_path_int8_scores_bit_exactly_like_in_memory() {
        let mut s = 42u64;
        let dim = 128usize;
        let n = 400usize;
        let vecs = turbo_corpus(n, dim, &mut s);

        let mut b = CcxeBuilder::new(0, 7, 100, dim as u16, "nomic-embed-text-v1.5");
        b.set_quantization(Quantization::Int8); // plain int8 — the on-disk gpu-1 layout
        for (i, v) in vecs.iter().enumerate() {
            b.add_vector(i as u32, v.clone());
        }
        let built = b.build();

        let heap = CcxeReader::from_bytes(&built).unwrap(); // eager f32 expansion
        let (_dir, path) = write_temp_ccxe(&built);
        let mapped = CcxeReader::from_path(&path).unwrap(); // decode-in-scoring

        // Identity and shape survive the disk round-trip.
        assert!(!heap.vectors.is_empty(), "int8 stays eagerly expanded");
        assert_eq!(mapped.header.quantization, Quantization::Int8, "identity kept");
        assert_eq!(mapped.num_vectors(), n);
        assert_eq!(mapped.doc_ids, heap.doc_ids);

        // (b) BIT-EXACT scores across randomized queries, both the full scan and the
        // IVF-Flat re-rank (indices) path, ties included.
        let mut qs = 999u64;
        let queries = turbo_corpus(60, dim, &mut qs);
        let all_idx: Vec<u32> = (0..n as u32).collect();
        for q in &queries {
            assert_eq!(
                heap.cosine_search(q, 10),
                mapped.cosine_search(q, 10),
                "from-disk cosine_search must be bit-identical to in-memory"
            );
            assert_eq!(
                heap.cosine_search_indices(q, 10, &all_idx, |_| true),
                mapped.cosine_search_indices(q, 10, &all_idx, |_| true),
                "from-disk re-rank must be bit-identical to in-memory"
            );
        }
        // Same bytes, same backing, so the same heap footprint.
        assert_eq!(mapped.dense_heap_bytes(), heap.dense_heap_bytes());
    }

    /// Perf sanity (#195): mmap-Int8 (decode-in-scoring) vs eager-f32 scan on ~100k
    /// synthetic vectors. mmap reads 4× fewer bytes but pays the q/127 dequant per
    /// score; this reports the measured ratio. `#[ignore]` — timing is environment-
    /// dependent and must not gate CI; run with `--ignored --nocapture` for the
    /// number.
    #[test]
    #[ignore]
    fn perf_int8_mmap_vs_eager_scan() {
        let mut s = 7u64;
        let dim = 128usize;
        let n = 100_000usize;
        let vecs = turbo_corpus(n, dim, &mut s);
        let mut b = CcxeBuilder::new(0, 1, 100, dim as u16, "m");
        b.set_quantization(Quantization::Int8);
        for (i, v) in vecs.iter().enumerate() {
            b.add_vector(i as u32, v.clone());
        }
        let built = b.build();
        let (_dir, path) = write_temp_ccxe(&built);
        let eager = CcxeReader::from_bytes(&built).unwrap();
        let mapped = CcxeReader::from_path(&path).unwrap();
        // Touch every mapped page once so we time steady-state scoring, not first
        // fault-in.
        let _ = mapped.cosine_search(&vecs[0], 10);

        let iters = 20;
        let t0 = std::time::Instant::now();
        for q in vecs.iter().take(iters) {
            std::hint::black_box(eager.cosine_search(q, 10));
        }
        let eager_ns = t0.elapsed().as_nanos() as f64 / iters as f64;
        let t1 = std::time::Instant::now();
        for q in vecs.iter().take(iters) {
            std::hint::black_box(mapped.cosine_search(q, 10));
        }
        let mmap_ns = t1.elapsed().as_nanos() as f64 / iters as f64;
        eprintln!(
            "int8 scan {n}×{dim}: eager-f32 {:.2} ms/query, mmap-int8 {:.2} ms/query, ratio {:.2}x",
            eager_ns / 1e6,
            mmap_ns / 1e6,
            mmap_ns / eager_ns
        );
    }

    #[test]
    fn from_path_missing_file_errors() {
        let err = CcxeReader::from_path("/no/such/path.ccxe");
        assert!(err.is_err(), "missing file must surface an IO error");
    }
}
