// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Local prose-ingest door (CPU-only).
//!
//! Seals pre-formatted prose payloads (chunks + metadata) into a local
//! `corecrux-storage` segment and builds the `.ccxi` BM25 companion at seal
//! time, so the corpus can be served by the ordinary retrieval path — **without**
//! the GPU-gated `DataPlaneStore`/`DataPlanePool` and **without** a GPU.
//!
//! This is the CPU "store + serve" half of the "process in the platform, serve on
//! your node" split. Metered GPU processing (embed/extract/format) stays in
//! CruxEngine; this door only accepts an already-formatted prose payload.
//!
//! ExecPlan: `cpu-prose-ingest-door-2026-07-01`.
//! - M0: CPU seal spike (this module's `seal_prose_documents` + roundtrip test).
//! - M2: consumed by the `/v1/local/ingest` handler for the real write path.
//!
//! ExecPlan `crux-integrations-and-template-library-2026-07-25` (I4) adds two
//! reusable pieces on top, so an in-process producer (the vault watcher) writes
//! through exactly the same path as an HTTP caller:
//! - [`chunk_markdown`] / [`chunk_plain_text`] — the document chunker.
//! - [`ingest_prose_documents`] — seal + timeline + index-reload, shared with
//!   the `POST /v1/local/ingest` handler.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use corecrux_storage::{AppendEventInput, ShardStorage, ShardStorageOptions, StorageError};
use tokio::sync::{Mutex, RwLock};

/// Single-node local ingest writes to shard 0 at a fixed epoch. Segment
/// sequence auto-increments within the shard and persists via the MANIFEST.
pub const LOCAL_INGEST_SHARD_ID: u32 = 0;
/// Epoch stamped on every locally-sealed prose segment.
pub const LOCAL_INGEST_EPOCH: u64 = 1;

/// Chunker target size, in characters. Matches `corecruxctl::ingest` (the
/// `crux-ingest` CLI that feeds `POST /v1/local/ingest`) so a note ingested by
/// the watcher and the same note ingested by the CLI produce identical chunks.
const CHUNK_TARGET_CHARS: usize = 1_800;
/// Earliest character offset a chunk boundary may be pulled back to.
const CHUNK_MIN_BOUNDARY_CHARS: usize = 1_200;
/// Characters of overlap carried into the next window.
const CHUNK_OVERLAP_CHARS: usize = 180;

/// Event type stamped on every sealed prose chunk frame.
pub const PROSE_CHUNK_EVENT_TYPE: &str = "corecrux.prose.chunk.v1";
/// Content type for prose chunk payloads (raw UTF-8 text, tokenized into BM25).
pub const PROSE_CHUNK_CONTENT_TYPE: &str = "text/plain; charset=utf-8";

/// A single prose chunk: raw text that becomes one indexed frame (BM25 document).
#[derive(Debug, Clone)]
pub struct ProseChunk {
    /// Stable chunk identity; doubles as the storage `event_id` (idempotency key).
    pub chunk_id: String,
    /// The chunk text. Stored verbatim as the frame payload and tokenized for BM25.
    pub text: String,
    /// Optional precomputed dense vector (from CruxEngine). When present, persisted
    /// as the `.ccxe` companion and served via `CosineDenseProvider` (M3). All
    /// vectors in one ingest must share a dimension.
    pub dense_vector: Option<Vec<f32>>,
}

/// A prose document: an ordered set of chunks written under one stream.
#[derive(Debug, Clone)]
pub struct ProseDocument {
    /// Stable document identity; used as the storage `stream_id`.
    pub doc_id: String,
    /// Ordered chunks. Empty documents are skipped.
    pub chunks: Vec<ProseChunk>,
}

/// Result of a completed local seal.
#[derive(Debug, Clone)]
pub struct SealSummary {
    /// Sequence of the sealed segment (`None`-collapsed to 0 when nothing sealed).
    pub segment_seq: u64,
    /// Number of frames (chunks) sealed into the segment.
    pub frame_count: u64,
    /// Number of documents accepted (non-empty).
    pub documents: usize,
    /// Number of chunks accepted across all documents.
    pub chunks: usize,
    /// Whether a segment was actually sealed (false when all documents were empty).
    pub sealed: bool,
    /// The sealed segment's receipt material hash (T.4 integrity receipt), if a
    /// segment was sealed. Hex-encoded and surfaced as `receipt_id` to callers.
    pub receipt_material_hash: Option<[u8; 32]>,
    /// Dense vector dimension, if any chunk carried a `dense_vector` (M3).
    pub dense_dim: Option<usize>,
    /// Number of dense vectors persisted to the `.ccxe` companion (M3).
    pub dense_vectors: usize,
}

/// Errors from the local seal path.
#[derive(Debug)]
pub enum LocalIngestError {
    /// A stream hash could not be derived from the (tenant, corpus, doc) triple.
    StreamHash(String),
    /// Dense vectors in the batch disagree on dimension (`expected` vs `found`).
    DenseDimMismatch { expected: usize, found: usize },
    /// The underlying `corecrux-storage` append/seal path failed.
    Storage(StorageError),
    /// Persisting the `.ccxe` dense companion failed.
    DenseIo(String),
}

impl std::fmt::Display for LocalIngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalIngestError::StreamHash(msg) => write!(f, "stream hash error: {msg}"),
            LocalIngestError::DenseDimMismatch { expected, found } => {
                write!(f, "dense vector dimension mismatch: expected {expected}, found {found}")
            }
            LocalIngestError::Storage(err) => write!(f, "storage error: {err:?}"),
            LocalIngestError::DenseIo(msg) => write!(f, "dense companion write failed: {msg}"),
        }
    }
}

impl std::error::Error for LocalIngestError {}

impl From<StorageError> for LocalIngestError {
    fn from(err: StorageError) -> Self {
        LocalIngestError::Storage(err)
    }
}

/// Upper bound on the head segment before an automatic seal. All documents in one
/// `seal_prose_documents` call accumulate into a single head and are force-sealed
/// together (one segment + one `.ccxi`), unless the batch is very large.
const HEAD_MAX_RECORD_BYTES: usize = 256 * 1024 * 1024;

/// Seal a batch of prose documents into a local CPU segment under
/// `<data_dir>/shards/shard-<shard_id:04>/segments/`, building the `.ccxi` BM25
/// companion at seal time. Returns a [`SealSummary`].
///
/// CPU-only: uses `corecrux-storage`'s `ShardStorage` append+seal path. No
/// `DataPlaneStore`/`DataPlanePool` is referenced. The written `.ccxi` is
/// discoverable by `IndexManager::scan_and_load` over the shard's `segments` dir,
/// which is exactly what the daemon's retrieval index reloads.
///
/// The `.ccxi` tenant filter is keyed on `xxh64(tenant_id)` (computed inside the
/// companion builder from each frame's canonical header), matching the tenant
/// filter used by `bm25_search`.
#[allow(clippy::too_many_arguments)] // cohesive seal params; bundling them is churn for no clarity
pub fn seal_prose_documents(
    data_dir: &Path,
    shard_id: u32,
    epoch: u64,
    tenant_id: &str,
    corpus_id: &str,
    ingested_at_rfc3339: &str,
    documents: &[ProseDocument],
    dense_profile: Option<&corecrux_memory::embeddings::SemanticProfile>,
) -> Result<SealSummary, LocalIngestError> {
    let shards_root = data_dir.join("shards");
    let options = ShardStorageOptions {
        head_max_record_bytes: HEAD_MAX_RECORD_BYTES,
        build_ccxi: true,
        ..Default::default()
    };
    // Pre-pass: validate dense vectors and collect (doc_id, vector) entries.
    // `doc_id` is the frame index in append order (skipping empty documents),
    // matching the `.ccxi` doc ordering (`build_ccxi_companion` iterates frames
    // in the same order) and therefore the `(doc_id, segment_index)` keying the
    // dense lane uses at query time.
    let mut dense_dim: Option<usize> = None;
    let mut dense_entries: Vec<(u32, Vec<f32>)> = Vec::new();
    {
        let mut next_doc_id: u32 = 0;
        for doc in documents {
            if doc.chunks.is_empty() {
                continue;
            }
            for chunk in &doc.chunks {
                let this_doc_id = next_doc_id;
                next_doc_id += 1;
                if let Some(v) = &chunk.dense_vector {
                    match dense_dim {
                        None => dense_dim = Some(v.len()),
                        Some(d) if d != v.len() => {
                            return Err(LocalIngestError::DenseDimMismatch {
                                expected: d,
                                found: v.len(),
                            });
                        }
                        _ => {}
                    }
                    dense_entries.push((this_doc_id, v.clone()));
                }
            }
        }
    }

    let mut storage = ShardStorage::open(&shards_root, shard_id, epoch, options)?;

    let mut total_chunks = 0usize;
    let mut accepted_docs = 0usize;

    for doc in documents {
        // The corpus is the stream_type; the document id is the stream_id.
        let stream_type = corpus_id;
        let stream_id = doc.doc_id.as_str();

        let events: Vec<AppendEventInput<'_>> = doc
            .chunks
            .iter()
            .map(|c| AppendEventInput {
                event_id: c.chunk_id.as_str(),
                occurred_at: ingested_at_rfc3339,
                event_type: PROSE_CHUNK_EVENT_TYPE,
                content_type: PROSE_CHUNK_CONTENT_TYPE,
                payload_bytes: c.text.as_bytes(),
            })
            .collect();

        if events.is_empty() {
            continue;
        }

        let stream_hash = corecrux_frame::stream_hash_xxhash64(tenant_id, stream_type, stream_id)
            .map_err(|e| LocalIngestError::StreamHash(format!("{e:?}")))?;

        // Fresh stream per document → expected_next_seq starts at 0.
        storage.append_batch(
            stream_hash,
            0,
            tenant_id,
            stream_type,
            stream_id,
            ingested_at_rfc3339,
            &events,
        )?;

        total_chunks += events.len();
        accepted_docs += 1;
    }

    let seal = storage.force_seal_head()?;

    // Persist the dense companion (`.ccxe`) alongside the sealed segment, named
    // with the same stem as its `.ccxseg` so the loader can find it by seq. The
    // format is the CoreCrux one, so a companion the platform computed and one
    // this daemon built locally are the same bytes on disk.
    //
    // The `.ccxprof` sidecar records the SemanticProfile that produced these
    // vectors, so the query path can refuse to score a segment whose embedding
    // fingerprint differs from the query embedder's rather than silently scoring
    // across incompatible vector spaces.
    let mut dense_written = 0usize;
    if seal.sealed && !dense_entries.is_empty() {
        if let (Some(receipt), Some(dim)) = (seal.seal_receipt.as_ref(), dense_dim) {
            let segments_dir = shards_root.join(format!("shard-{shard_id:04}")).join("segments");
            let stem = format!("seg-{:020}-{}", receipt.segment_seq, hex16(&receipt.segment_id.0));
            let path = segments_dir.join(format!("{stem}.ccxe"));
            let model_id = dense_profile.as_ref().map_or("unknown", |p| p.model.as_str());
            write_ccxe(
                &path,
                shard_id,
                receipt.segment_seq,
                dim as u16,
                model_id,
                &dense_entries,
            )
            .map_err(|e| LocalIngestError::DenseIo(e.to_string()))?;
            dense_written = dense_entries.len();
            if let Some(profile) = dense_profile {
                let profile_path = segments_dir.join(format!("{stem}.ccxprof"));
                write_ccxprof(&profile_path, profile).map_err(|e| LocalIngestError::DenseIo(e.to_string()))?;
            }
        }
    }

    // Self-sign whatever companions this seal produced, so a locally-built
    // segment resolves to provenance `local` rather than `none`. Deliberately
    // outside the dense branch above: the `.ccxi` written by the storage seal
    // path needs covering just as much, and a segment with no dense lane is not
    // a segment with no provenance.
    //
    // Never fails the ingest — see `companion_attestation`.
    if let Some(receipt) = seal.seal_receipt.as_ref().filter(|_| seal.sealed) {
        let segments_dir = shards_root.join(format!("shard-{shard_id:04}")).join("segments");
        let id_hex = hex16(&receipt.segment_id.0);
        let stem = format!("seg-{:020}-{}", receipt.segment_seq, id_hex);
        crate::companion_attestation::write_local_attestation(
            data_dir,
            &segments_dir,
            &stem,
            crate::companion_attestation::SealedSegmentRef {
                shard_id,
                segment_seq: receipt.segment_seq,
                segment_id_hex: &id_hex,
                tenant_id,
                issued_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs()),
            },
        );
    }

    Ok(SealSummary {
        segment_seq: seal.segment_seq.unwrap_or(0),
        frame_count: seal.frame_count.unwrap_or(0),
        documents: accepted_docs,
        chunks: total_chunks,
        sealed: seal.sealed,
        receipt_material_hash: seal.seal_receipt.as_ref().map(|r| r.material_hash()),
        dense_dim: if dense_written > 0 { dense_dim } else { None },
        dense_vectors: dense_written,
    })
}

// ── `.ccxe` dense companion ─────────────────────────────────────────────────
//
// The CoreCrux dense-companion format, ported into `corecrux-index` (see that
// crate's VENDORED_FROM.md). The CE used to write a bespoke `.ccxe` here; sharing
// the platform's format is what lets a daemon read a companion CueCrux computed
// for it and one it embedded locally through the same reader.
//
// The CE always writes `Quantization::Float32`. It READS every mode the platform
// emits, including the packed TurboQuant ones.

/// `(doc_id, vector)` entries read from a `.ccxe` companion.
type DenseEntries = Vec<(u32, Vec<f32>)>;

/// Write a `.ccxe` dense companion atomically (tmp → rename).
fn write_ccxe(
    path: &Path,
    shard_id: u32,
    segment_seq: u64,
    dim: u16,
    model_id: &str,
    entries: &[(u32, Vec<f32>)],
) -> std::io::Result<()> {
    // `epoch` is a dataplane compaction generation the CE does not track; 0 is the
    // "unversioned" value and is what the reader expects when it is absent.
    let mut builder = corecrux_index::CcxeBuilder::new(shard_id, segment_seq, 0, dim, model_id);
    for (doc_id, vector) in entries {
        builder.add_vector(*doc_id, vector.clone());
    }
    let tmp = path.with_extension("ccxe.partial");
    std::fs::write(&tmp, builder.build())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Write the `.ccxprof` profile sidecar (JSON [`corecrux_memory::embeddings::SemanticProfile`])
/// atomically alongside a segment's `.ccxe`. Records which embedder produced the
/// segment's vectors so the query path can refuse to score an incompatible vector
/// space.
///
/// This deliberately stayed a sidecar rather than folding into the `.ccxe` header.
/// The header carries `model_id`, but the strict-profile check also compares
/// `tokenizer`, `prompt_template_version`, `normalisation` and the derived
/// fingerprint, and the V2 metadata block's flags are POSITIONAL — an unknown flag
/// desyncs every field after it, so the CE cannot extend the format without
/// coordinating with CoreCrux. The extension moved off `.ccxprof` (which is CoreCrux's
/// structured-fact projection companion) to `.ccxprof`, which claims nothing in the
/// `ccx<lane>` namespace.
fn write_ccxprof(path: &Path, profile: &corecrux_memory::embeddings::SemanticProfile) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(profile).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("ccxprof.partial");
    std::fs::write(&tmp, &json)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Read a `.ccxprof` profile sidecar. Returns `None` when absent or unparsable
/// (treated as an unknown/legacy profile rather than fatal).
fn read_ccxprof(path: &Path) -> Option<corecrux_memory::embeddings::SemanticProfile> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Read a `.ccxe` companion → (dim, [(doc_id, vector)]). Returns `None` on a bad
/// magic/version or a truncated file (treated as absent rather than fatal).
///
/// Serve-side (consumed by [`build_dense_provider`]): live on the prose text-search
/// query path when a node embedder is configured. Packed modes are decoded here so
/// a platform-built quantised companion serves through the same path as a locally
/// built f32 one.
fn read_ccxe(path: &Path) -> Option<(u32, DenseEntries)> {
    let reader = corecrux_index::CcxeReader::from_path(path).ok()?;
    let dim = u32::from(reader.header.dim);
    let vectors = reader.decoded_vectors();
    if vectors.len() != reader.doc_ids.len() {
        return None;
    }
    Some((dim, reader.doc_ids.iter().copied().zip(vectors).collect()))
}

/// Parsed dense data for one sealed segment (buyer-fit FU3 cache). Sealed
/// segments are immutable — written once via atomic rename and never modified —
/// so a per-`(shards_dir, segment_seq)` cache entry never goes stale; new
/// segments only add entries.
struct CachedDenseSegment {
    dimension: usize,
    entries: DenseEntries,
    profile: Option<corecrux_memory::embeddings::SemanticProfile>,
}

/// Cache map: `(shards_dir, segment_seq)` → parsed dense segment.
type DenseSegmentCache = std::collections::HashMap<(std::path::PathBuf, u64), std::sync::Arc<CachedDenseSegment>>;

/// Process-wide cache of parsed `.ccxe`/`.ccxprof` companions so the prose
/// query-dense path does not re-read (and re-`read_dir`) every companion from
/// disk on every query (buyer-fit FU3). Keyed by `(shards_dir, segment_seq)`:
/// the shards dir disambiguates otherwise-colliding seqs across data dirs (and
/// across tests). Pruned to the live segment set of the queried shards dir on
/// each build, so it stays bounded by the corpus and drops erased segments.
static DENSE_SEGMENT_CACHE: std::sync::LazyLock<std::sync::Mutex<DenseSegmentCache>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Why a delegated query cannot safely score a persisted dense segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenseProfileCompatibilityError {
    /// The segment predates semantic-profile sidecars, so its model identity
    /// cannot be proven even if the vector dimension happens to match.
    MissingProfile { segment_seq: u64 },
    /// The persisted vectors were produced in a different semantic space.
    FingerprintMismatch { segment_seq: u64 },
    /// The profile sidecar's derived ids/hash do not match its declared fields.
    InvalidProfile { segment_seq: u64 },
    /// The vector companion, profile, and query do not share one dimension.
    DimensionMismatch { segment_seq: u64 },
    /// The vector companion is malformed or contains non-finite values.
    InvalidVectorCompanion { segment_seq: u64 },
}

/// Build a [`corecrux_retrieval::CosineDenseProvider`] over all sealed `.ccxe` companions, keyed by
/// `(doc_id, segment_index)` to match [`corecrux_retrieval::fused::fused_retrieve`]'s
/// enumeration (`segment_index` = position in `index_mgr.readers()`, which is
/// ascending `segment_seq`). Returns `None` when no dense vectors are stored, so
/// the caller leaves the dense lane inert.
///
/// Consumed live by the prose text-search query path (buyer-fit M3.2): when a
/// node embedder is configured the query is embedded and this builds the
/// `CosineDenseProvider` over the corpus `.ccxe` companions for dense re-rank.
/// `expected_fingerprint` (buyer-fit M3.3): when `Some`, a segment whose `.ccxprof`
/// profile records a DIFFERENT embedding fingerprint is skipped — its vectors
/// live in an incompatible space and must not be cosine-scored against this
/// query. A segment with no `.ccxprof` (legacy) is included; the `CosineDenseProvider`
/// still guards on dimension. `None` includes every segment (fixture callers).
pub fn build_dense_provider(
    index_mgr: &corecrux_retrieval::IndexManager,
    data_dir: &Path,
    query_embedding: &[f32],
    expected_fingerprint: Option<&str>,
) -> Option<corecrux_retrieval::CosineDenseProvider> {
    build_dense_provider_inner(index_mgr, data_dir, query_embedding, expected_fingerprint, false)
        .ok()
        .flatten()
}

/// Delegation-specific dense provider construction. Unlike the legacy/local
/// path, every stored vector segment must prove the same semantic fingerprint;
/// an incompatible or unlabelled segment is an error, never a BM25-only 200.
pub fn build_dense_provider_strict(
    index_mgr: &corecrux_retrieval::IndexManager,
    data_dir: &Path,
    query_embedding: &[f32],
    expected_fingerprint: &str,
) -> Result<Option<corecrux_retrieval::CosineDenseProvider>, DenseProfileCompatibilityError> {
    build_dense_provider_inner(index_mgr, data_dir, query_embedding, Some(expected_fingerprint), true)
}

fn build_dense_provider_inner(
    index_mgr: &corecrux_retrieval::IndexManager,
    data_dir: &Path,
    query_embedding: &[f32],
    expected_fingerprint: Option<&str>,
    strict_profile: bool,
) -> Result<Option<corecrux_retrieval::CosineDenseProvider>, DenseProfileCompatibilityError> {
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    let shards_dir = data_dir.join("shards");
    let readers = index_mgr.readers();

    // Recover from a poisoned lock rather than panic (a panicking holder would
    // only have left a partially-updated cache, which is safe to reuse).
    let mut cache = DENSE_SEGMENT_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    // Bound the cache to this shards dir's live segment set; leave other data
    // dirs' entries untouched.
    let live: HashSet<u64> = readers.iter().map(|r| r.header.segment_seq).collect();
    cache.retain(|(sd, seq), _| sd != &shards_dir || live.contains(seq));

    let mut vectors: HashMap<(u32, usize), Vec<f32>> = HashMap::new();
    for (segment_index, reader) in readers.iter().enumerate() {
        let seq = reader.header.segment_seq;
        let cached = if let Some(c) = cache.get(&(shards_dir.clone(), seq)) {
            Arc::clone(c)
        } else {
            let Some(path) = find_ccxe_for_seq(&shards_dir, seq) else {
                continue;
            };
            let Some((dimension, entries)) = read_ccxe(&path) else {
                if strict_profile {
                    return Err(DenseProfileCompatibilityError::InvalidVectorCompanion { segment_seq: seq });
                }
                continue;
            };
            let profile = read_ccxprof(&path.with_extension("ccxprof"));
            let c = Arc::new(CachedDenseSegment {
                dimension: dimension as usize,
                entries,
                profile,
            });
            cache.insert((shards_dir.clone(), seq), Arc::clone(&c));
            c
        };
        // Local/generic embedders retain the existing compatible-subset
        // behavior. Authenticated daemon delegation is strict: silently
        // dropping a mismatched segment would turn a semantic query into an
        // apparently successful sparse-only result.
        if strict_profile
            && cached
                .entries
                .iter()
                .any(|(_, vector)| vector.len() != cached.dimension || vector.iter().any(|value| !value.is_finite()))
        {
            return Err(DenseProfileCompatibilityError::InvalidVectorCompanion { segment_seq: seq });
        }
        if let Some(expected) = expected_fingerprint {
            match &cached.profile {
                Some(profile) => {
                    if strict_profile {
                        let canonical = corecrux_memory::embeddings::SemanticProfile::from_parts(
                            &profile.model,
                            profile.dimensions,
                            &profile.tokenizer,
                            &profile.prompt_template_version,
                            &profile.normalisation,
                        );
                        if profile != &canonical {
                            return Err(DenseProfileCompatibilityError::InvalidProfile { segment_seq: seq });
                        }
                        if cached.dimension != profile.dimensions || cached.dimension != query_embedding.len() {
                            return Err(DenseProfileCompatibilityError::DimensionMismatch { segment_seq: seq });
                        }
                    }
                    if profile.embedding_fingerprint.hash != expected {
                        if strict_profile {
                            return Err(DenseProfileCompatibilityError::FingerprintMismatch { segment_seq: seq });
                        }
                        continue;
                    }
                }
                None if strict_profile => {
                    return Err(DenseProfileCompatibilityError::MissingProfile { segment_seq: seq });
                }
                _ => {}
            }
        }
        for (doc_id, v) in &cached.entries {
            vectors.insert((*doc_id, segment_index), v.clone());
        }
    }

    if vectors.is_empty() {
        return Ok(None);
    }
    Ok(Some(corecrux_retrieval::CosineDenseProvider::new(
        query_embedding,
        vectors,
    )))
}

/// Locate the `.ccxe` companion for a segment sequence across all shards.
fn find_ccxe_for_seq(shards_dir: &Path, seq: u64) -> Option<std::path::PathBuf> {
    let prefix = format!("seg-{seq:020}-");
    let shard_entries = std::fs::read_dir(shards_dir).ok()?;
    for shard in shard_entries.flatten() {
        let segments = shard.path().join("segments");
        let Ok(files) = std::fs::read_dir(&segments) else {
            continue;
        };
        for f in files.flatten() {
            let name = f.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&prefix) && name.ends_with(".ccxe") {
                return Some(f.path());
            }
        }
    }
    None
}

/// Lower-hex encode a 16-byte segment id (matches the storage filename scheme).
fn hex16(bytes: &[u8; 16]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(32);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ── Chunking ─────────────────────────────────────────────────────────────
//
// `POST /v1/local/ingest` takes chunks pre-split by the caller; the reference
// splitter has always lived in `corecruxctl::ingest` (`crux-ingest`). The
// vault watcher is the first *in-process* producer, so the splitter is
// restated here as the daemon-side reusable function rather than open-coded
// inside the watcher. Algorithm + constants are identical to
// `corecruxctl::ingest::{chunk_markdown, chunk_plain_text}`; a shared crate
// would be the next step if a third producer appears (the two binaries have no
// common library crate that owns text processing today).

/// True when `line` opens an ATX markdown heading (`# ` … `###### `).
fn markdown_heading(line: &str) -> bool {
    let trimmed = line.trim_start();
    let hashes = trimmed.bytes().take_while(|byte| *byte == b'#').count();
    (1..=6).contains(&hashes) && trimmed.as_bytes().get(hashes).is_some_and(u8::is_ascii_whitespace)
}

/// Chunk Markdown at ATX headings, then window unusually long sections.
pub fn chunk_markdown(input: &str) -> Vec<String> {
    let mut sections = Vec::new();
    let mut current = String::new();
    for line in input.split_inclusive('\n') {
        if markdown_heading(line) && !current.trim().is_empty() {
            sections.push(std::mem::take(&mut current));
        }
        current.push_str(line);
    }
    if !current.trim().is_empty() {
        sections.push(current);
    }
    sections
        .into_iter()
        .flat_map(|section| chunk_plain_text(&section))
        .collect()
}

/// Paragraph-aware sliding windows of approximately 1,800 characters.
pub fn chunk_plain_text(input: &str) -> Vec<String> {
    let text = input.trim();
    if text.is_empty() {
        return Vec::new();
    }
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= CHUNK_TARGET_CHARS {
        return vec![text.to_string()];
    }

    let mut chunks = Vec::new();
    let mut start = 0usize;
    while start < chars.len() {
        let ideal_end = (start + CHUNK_TARGET_CHARS).min(chars.len());
        let mut end = ideal_end;
        if ideal_end < chars.len() {
            let minimum = (start + CHUNK_MIN_BOUNDARY_CHARS).min(ideal_end);
            for candidate in (minimum..=ideal_end).rev() {
                if candidate >= 2 && chars[candidate - 2] == '\n' && chars[candidate - 1] == '\n' {
                    end = candidate;
                    break;
                }
            }
            if end == ideal_end {
                for candidate in (minimum..=ideal_end).rev() {
                    if chars[candidate - 1].is_whitespace() {
                        end = candidate;
                        break;
                    }
                }
            }
        }
        let chunk: String = chars[start..end].iter().collect::<String>().trim().to_string();
        if !chunk.is_empty() {
            chunks.push(chunk);
        }
        if end == chars.len() {
            break;
        }
        let next = end.saturating_sub(CHUNK_OVERLAP_CHARS);
        start = if next > start { next } else { end };
    }
    chunks
}

// ── Shared write path ────────────────────────────────────────────────────

/// The pieces of `AppState` the local-ingest write path needs. Carried as its
/// own struct so an in-process producer (the vault watcher) can drive the same
/// path without an `AppState`, and so this module keeps no dependency on the
/// HTTP layer.
#[derive(Clone)]
pub struct LocalIngestHandles {
    pub data_dir: PathBuf,
    /// Serializes seals — each one takes the shard's exclusive lock.
    pub ingest_lock: Arc<Mutex<()>>,
    /// Hot-reloaded after every seal so the fresh `.ccxi` is queryable.
    pub retrieval_index: Arc<RwLock<corecrux_retrieval::IndexManager>>,
}

/// Seal `documents`, record the console timeline rows, and hot-reload the
/// retrieval index — the durable tail shared by `POST /v1/local/ingest` and the
/// vault watcher.
///
/// Callers own policy (auth, payload validation, dense-vector/profile
/// negotiation) and hand over documents that are ready to seal. Returns the
/// seal summary, or a human-readable error string; timeline-index failures are
/// logged and never fail an otherwise-durable ingest.
pub async fn ingest_prose_documents(
    handles: &LocalIngestHandles,
    tenant_id: &str,
    corpus_id: &str,
    documents: Vec<ProseDocument>,
    dense_profile: Option<corecrux_memory::embeddings::SemanticProfile>,
) -> Result<SealSummary, String> {
    let data_dir = handles.data_dir.clone();
    let tenant = tenant_id.to_string();
    let corpus = corpus_id.to_string();
    let ingested_at = chrono::Utc::now().to_rfc3339();
    let now_ms = crate::ops_events::now_unix_ms();

    let _guard = handles.ingest_lock.lock().await;
    let sealed = tokio::task::spawn_blocking(move || -> Result<SealSummary, String> {
        let summary = seal_prose_documents(
            &data_dir,
            LOCAL_INGEST_SHARD_ID,
            LOCAL_INGEST_EPOCH,
            &tenant,
            &corpus,
            &ingested_at,
            &documents,
            dense_profile.as_ref(),
        )
        .map_err(|e| e.to_string())?;

        // T.4: record a timeline row per document (same console index the
        // `/v1/append` path writes). Best-effort — a timeline miss never fails
        // an otherwise-durable ingest.
        for doc in &documents {
            let events: Vec<corecrux_proto::dataplane_v1::AppendEvent> = doc
                .chunks
                .iter()
                .map(|c| corecrux_proto::dataplane_v1::AppendEvent {
                    event_id: c.chunk_id.clone(),
                    occurred_at: ingested_at.clone(),
                    event_type: PROSE_CHUNK_EVENT_TYPE.to_string(),
                    content_type: PROSE_CHUNK_CONTENT_TYPE.to_string(),
                    payload: c.text.as_bytes().to_vec(),
                })
                .collect();
            if let Err(err) = crate::console_index::record_appended_events(
                &data_dir,
                &tenant,
                &corpus,
                &doc.doc_id,
                0,
                &events,
                now_ms,
            ) {
                tracing::warn!(?err, doc_id = %doc.doc_id, "local-ingest timeline indexing failed");
            }
        }
        Ok(summary)
    })
    .await;

    let summary = match sealed {
        Ok(Ok(summary)) => summary,
        Ok(Err(msg)) => return Err(msg),
        Err(join_err) => return Err(format!("local ingest seal task failed: {join_err}")),
    };

    // Load-at-runtime wiring: hot-reload the retrieval index so the freshly
    // sealed `.ccxi` is queryable immediately (idempotent — scan skips
    // already-loaded segments).
    {
        let mut guard = handles.retrieval_index.write().await;
        let shards_dir = handles.data_dir.join("shards");
        if let Ok(entries) = std::fs::read_dir(&shards_dir) {
            for entry in entries.flatten() {
                let seg_dir = entry.path().join("segments");
                if let Err(err) = guard.scan_and_load(&seg_dir) {
                    tracing::warn!(?err, dir = ?seg_dir, "local-ingest ccxi reload failed");
                }
            }
        }
    }
    drop(_guard);

    Ok(summary)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use corecrux_retrieval::bm25::{bm25_search, Bm25Params};
    use corecrux_retrieval::IndexManager;

    // ── Chunker parity with `corecruxctl::ingest` ────────────────────────
    //
    // These mirror `corecruxctl::ingest::tests::{markdown_chunks_start_at_headings,
    // text_windows_have_bounded_size_and_overlap}` assertion-for-assertion. The
    // two chunkers are separate copies of one algorithm (no shared library crate
    // between the two binaries yet), so parity is asserted, not assumed.

    #[test]
    fn markdown_chunks_start_at_headings() {
        let input = format!("# First\n\n{}\n\n## Second\n\nshort ending", "alpha ".repeat(400));
        let chunks = chunk_markdown(&input);
        assert!(chunks.first().unwrap().starts_with("# First"));
        assert!(chunks.iter().any(|chunk| chunk.starts_with("## Second")));
        assert!(chunks
            .iter()
            .all(|chunk| !(chunk.contains("# First") && chunk.contains("## Second"))));
    }

    #[test]
    fn text_windows_have_bounded_size_and_overlap() {
        let input = (0..900).map(|index| format!("word{index:04} ")).collect::<String>();
        let chunks = chunk_plain_text(&input);
        assert!(chunks.len() > 2);
        assert!(chunks.iter().all(|chunk| chunk.chars().count() <= CHUNK_TARGET_CHARS));
        for pair in chunks.windows(2) {
            let left: Vec<char> = pair[0].chars().collect();
            let right: Vec<char> = pair[1].chars().collect();
            let mut overlap = 0;
            let max = CHUNK_OVERLAP_CHARS.min(left.len()).min(right.len());
            for length in 1..=max {
                if left[left.len() - length..] == right[..length] {
                    overlap = length;
                }
            }
            assert!(overlap > 0);
            assert!(overlap <= CHUNK_OVERLAP_CHARS);
        }
    }

    #[test]
    fn chunker_handles_empty_and_short_input() {
        assert!(chunk_markdown("").is_empty());
        assert!(chunk_markdown("   \n\n  ").is_empty());
        assert!(chunk_plain_text("").is_empty());
        assert_eq!(chunk_plain_text("  hello  "), vec!["hello".to_string()]);
        // A short note is exactly one chunk, verbatim (trimmed).
        assert_eq!(chunk_markdown("# Title\n\nbody\n"), vec!["# Title\n\nbody".to_string()]);
    }

    // These tests seal through `corecrux-storage`, whose seal/append path reads a
    // process-global env var (`CORECRUX_STORAGE_FAILPOINT`) in non-test builds —
    // and this crate builds `corecrux-storage` as a normal (non-test) dependency.
    // Many other corecruxd tests mutate process env via `set_var` under
    // `#[serial_test::serial]`; running these seal tests concurrently with those
    // raced the env read and intermittently failed the seal (flaky
    // `m5_tenant_isolation` / `m5_idempotent_reingest_is_noop` in the merge queue).
    // Join the default serial group so they never overlap env-mutating tests.
    // (Mirrors `corecrux-storage`'s own `TEST_LOCK`-serialised seal tests.)

    fn tenant_hash(tenant_id: &str) -> u64 {
        xxhash_rust::xxh64::xxh64(tenant_id.as_bytes(), 0)
    }

    /// Locate the single `.ccxatt` under a data dir, if one was written.
    fn find_ccxatt(data_dir: &std::path::Path) -> Option<std::path::PathBuf> {
        std::fs::read_dir(data_dir.join("shards").join("shard-0000").join("segments"))
            .ok()?
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().and_then(|e| e.to_str()) == Some("ccxatt"))
    }

    fn seal_one(data_dir: &std::path::Path, tenant: &str) {
        seal_prose_documents(
            data_dir,
            0,
            1,
            tenant,
            "corpus",
            "2026-08-09T00:00:00Z",
            &[ProseDocument {
                doc_id: "doc-1".to_string(),
                chunks: vec![ProseChunk {
                    chunk_id: "doc-1::0".to_string(),
                    text: "the peregrine falcon is the fastest animal on earth".to_string(),
                    dense_vector: None,
                }],
            }],
            None,
        )
        .expect("seal");
    }

    /// The false-positive guard, and the reason self-signing exists at all: a
    /// segment this daemon built resolves to `local`, not `none`.
    ///
    /// If this ever fails, every ordinary local ingest trips the missing-provenance
    /// alarm, operators learn to ignore it, and the whole control is worth nothing.
    #[test]
    #[serial_test::serial]
    fn a_locally_sealed_segment_self_signs_and_verifies_as_local() {
        use corecrux_index::{decode_attestation, verify_parsed, Provenance, TrustRoots};

        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        // The daemon mints this at startup; a bare temp dir has none yet.
        let key = crux_session::passport::LocalPassportKey::from_data_dir(data_dir).expect("passport key");

        seal_one(data_dir, "tenant-attest");

        let att_path = find_ccxatt(data_dir).expect("a .ccxatt must be written beside the companions");
        let stem = att_path.file_stem().and_then(|s| s.to_str()).expect("stem").to_string();
        let segment_id_hex = stem.rsplit('-').next().expect("id").to_string();

        let parsed = decode_attestation(&std::fs::read(&att_path).unwrap()).expect("parse");
        assert_eq!(parsed.body.provenance, "local");
        assert_eq!(parsed.body.tenant_id.as_deref(), Some("tenant-attest"));
        assert!(
            parsed.body.companions.iter().any(|c| c.ext == "ccxi"),
            "the BM25 companion is written by the seal path and must be covered: {:?}",
            parsed.body.companions
        );

        let roots = TrustRoots::new().with_local_device(key.passport_fpr(), key.verifying_key_bytes());
        let segments_dir = att_path.parent().unwrap().to_path_buf();
        let provenance = verify_parsed(&parsed, &roots, &segment_id_hex, |ext, key| {
            let name = match key {
                Some(k) => format!("{stem}.{ext}@{k}"),
                None => format!("{stem}.{ext}"),
            };
            std::fs::read(segments_dir.join(name)).ok()
        })
        .expect("must verify against this daemon's own device key");
        assert_eq!(provenance, Provenance::Local);
    }

    /// Attestation is a control layered on the write path, not part of it. With
    /// no passport key there is no stamp — and the ingest still succeeds.
    #[test]
    #[serial_test::serial]
    fn a_missing_passport_key_skips_the_stamp_and_never_fails_the_ingest() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        // No `LocalPassportKey::from_data_dir` call: the key genuinely does not exist.
        seal_one(data_dir, "tenant-nokey");

        assert!(
            find_ccxatt(data_dir).is_none(),
            "no key means no stamp — and emphatically not a minted one"
        );
        assert!(
            !data_dir.join("passport.key").exists(),
            "sealing must never mint a signing identity as a side effect"
        );
        // The corpus is intact regardless: the segment and its companion are there.
        let segments = data_dir.join("shards").join("shard-0000").join("segments");
        let names: Vec<String> = std::fs::read_dir(&segments)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(names.iter().any(|n| n.ends_with(".ccxseg")), "{names:?}");
        assert!(names.iter().any(|n| n.ends_with(".ccxi")), "{names:?}");
    }

    /// The `.ccxseg` frame headers and the `.ccxi` doc table must attribute a
    /// segment identically.
    ///
    /// This is what licenses reading tenancy from the segment when a `.ccxi` is
    /// absent (M4). If the two sources could disagree, the fallback would not be
    /// a fallback — it would be a second, quietly different answer to "whose
    /// data is this", on the path that decides what an erasure deletes.
    #[test]
    #[serial_test::serial]
    fn segment_frame_headers_attribute_the_same_tenants_as_the_ccxi() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();

        for (tenant, text) in [
            ("tenant-parity-a", "the peregrine falcon is the fastest animal"),
            ("tenant-parity-b", "kubernetes ingress controllers and routing"),
        ] {
            seal_prose_documents(
                data_dir,
                0,
                1,
                tenant,
                "corpus",
                "2026-08-09T00:00:00Z",
                &[ProseDocument {
                    doc_id: format!("doc-{tenant}"),
                    chunks: vec![ProseChunk {
                        chunk_id: format!("doc-{tenant}::0"),
                        text: text.to_string(),
                        dense_vector: None,
                    }],
                }],
                None,
            )
            .expect("seal");
        }

        let segments_dir = data_dir.join("shards").join("shard-0000").join("segments");
        let mut checked = 0;
        for entry in std::fs::read_dir(&segments_dir).expect("read segments dir") {
            let path = entry.expect("entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("ccxseg") {
                continue;
            }
            let ccxi_path = path.with_extension("ccxi");
            let ccxi = corecrux_index::CcxiReader::from_bytes(&std::fs::read(&ccxi_path).expect("read ccxi"))
                .expect("parse ccxi");

            // What the `.ccxi` doc table says.
            let mut from_ccxi: std::collections::BTreeMap<u64, usize> = std::collections::BTreeMap::new();
            for doc in &ccxi.docs {
                *from_ccxi.entry(doc.tenant_hash_full).or_insert(0) += 1;
            }

            // What the segment's own frame headers say.
            let membership = corecrux_retrieval::read_segment_membership(&path).expect("membership");

            assert_eq!(membership.tenants, from_ccxi, "{path:?}");
            assert_eq!(membership.docs_total, ccxi.docs.len(), "{path:?}");
            checked += 1;
        }
        assert_eq!(checked, 2, "both sealed segments must have been compared");
    }

    /// M0 gate: seal a 1-doc / 1-chunk segment to a temp data_dir entirely on CPU
    /// (no `DataPlaneStore`), then BM25-retrieve it via the ordinary retrieval path.
    #[test]
    #[serial_test::serial]
    fn m0_seal_one_chunk_and_bm25_retrieve() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let tenant = "tenant-m0";

        let docs = vec![ProseDocument {
            doc_id: "doc-1".to_string(),
            chunks: vec![ProseChunk {
                chunk_id: "doc-1::0".to_string(),
                text: "the peregrine falcon is the fastest animal on earth".to_string(),
                dense_vector: None,
            }],
        }];

        let summary = seal_prose_documents(
            data_dir,
            0,
            1,
            tenant,
            "mediacrux-archive",
            "2026-07-01T00:00:00Z",
            &docs,
            None,
        )
        .expect("seal should succeed on CPU");

        assert!(summary.sealed, "a segment must have been sealed");
        assert_eq!(summary.documents, 1);
        assert_eq!(summary.chunks, 1);
        assert_eq!(summary.frame_count, 1);

        // The .ccxi must be discoverable exactly where the daemon's retrieval
        // index scans: <data_dir>/shards/shard-0000/segments/.
        let segments_dir = data_dir.join("shards").join("shard-0000").join("segments");
        let mut mgr = IndexManager::new();
        let loaded = mgr.scan_and_load(&segments_dir).expect("scan_and_load");
        assert_eq!(loaded, 1, "exactly one .ccxi companion should load");
        assert_eq!(mgr.total_docs(), 1);

        // BM25 retrieval returns the chunk, scoped to the ingesting tenant.
        let readers = mgr.readers();
        let result = bm25_search(
            &readers,
            "peregrine falcon",
            10,
            Some(tenant_hash(tenant)),
            &Bm25Params::default(),
            None,
            None,
        );
        assert_eq!(result.hits.len(), 1, "the sealed chunk must be retrievable");

        // A different tenant must not see it (T.1 smoke check).
        let other = bm25_search(
            &readers,
            "peregrine falcon",
            10,
            Some(tenant_hash("someone-else")),
            &Bm25Params::default(),
            None,
            None,
        );
        assert_eq!(other.hits.len(), 0, "cross-tenant query must not match");
    }

    /// M2 probe: two sequential ingests into the SAME data_dir/shard must both
    /// survive — i.e. reopening the shard for the 2nd seal must not quarantine
    /// the 1st segment's `.ccxi` companion (the R2 quarantine-on-restart class).
    #[test]
    #[serial_test::serial]
    fn m2_two_ingests_both_survive_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let tenant = "tenant-m2";

        let batch = |doc_id: &str, text: &str| {
            vec![ProseDocument {
                doc_id: doc_id.to_string(),
                chunks: vec![ProseChunk {
                    chunk_id: format!("{doc_id}::0"),
                    text: text.to_string(),
                    dense_vector: None,
                }],
            }]
        };

        seal_prose_documents(
            data_dir,
            0,
            1,
            tenant,
            "corpus",
            "2026-07-01T00:00:00Z",
            &batch("d1", "alpha centauri star system"),
            None,
        )
        .expect("first seal");
        seal_prose_documents(
            data_dir,
            0,
            1,
            tenant,
            "corpus",
            "2026-07-01T00:00:01Z",
            &batch("d2", "betelgeuse red supergiant"),
            None,
        )
        .expect("second seal");

        // Simulate daemon restart: fresh IndexManager scanning the segments dir.
        let segments_dir = data_dir.join("shards").join("shard-0000").join("segments");
        let mut mgr = IndexManager::new();
        mgr.scan_and_load(&segments_dir).expect("scan_and_load");

        // Both documents must still be present and retrievable.
        assert_eq!(mgr.total_docs(), 2, "both segments' docs must survive reopen");
        let readers = mgr.readers();
        let th = Some(tenant_hash(tenant));
        let p = Bm25Params::default();
        assert_eq!(
            bm25_search(&readers, "alpha centauri", 10, th, &p, None, None)
                .hits
                .len(),
            1,
            "first ingest must survive the second ingest's shard reopen"
        );
        assert_eq!(
            bm25_search(&readers, "betelgeuse", 10, th, &p, None, None).hits.len(),
            1,
            "second ingest must be retrievable"
        );
    }

    use corecrux_retrieval::fused::{fused_retrieve, FusedRetrieveRequest, FusionWeights};

    fn fused_req(tenant: &str, query: &str, embedding: Vec<f32>, weights: FusionWeights) -> FusedRetrieveRequest {
        FusedRetrieveRequest {
            tenant_id: tenant.to_string(),
            query: query.to_string(),
            query_embedding: Some(embedding),
            top_k: 10,
            weights,
            graph_hops: 0,
            min_confidence: 0.0,
            include_state: false,
            graph_node_count: 0,
            graph_cold_start_threshold: 100,
        }
    }

    fn dense_chunk(id: &str, text: &str, v: Vec<f32>) -> ProseChunk {
        ProseChunk {
            chunk_id: id.to_string(),
            text: text.to_string(),
            dense_vector: Some(v),
        }
    }

    /// M3 gate (a): ingest-with-vectors → fused retrieval returns the expected
    /// top-k. Both docs match the BM25 query equally; the dense lane (query
    /// aligned to doc B) decides the ranking.
    #[test]
    #[serial_test::serial]
    fn m3_dense_fusion_returns_expected_topk() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let tenant = "tenant-m3";

        let docs = vec![
            ProseDocument {
                doc_id: "doc-a".to_string(),
                chunks: vec![dense_chunk("doc-a::0", "shared keyword alpha", vec![1.0, 0.0])],
            },
            ProseDocument {
                doc_id: "doc-b".to_string(),
                chunks: vec![dense_chunk("doc-b::0", "shared keyword beta", vec![0.0, 1.0])],
            },
        ];
        let summary = seal_prose_documents(data_dir, 0, 1, tenant, "corpus", "2026-07-01T00:00:00Z", &docs, None)
            .expect("seal with vectors");
        assert_eq!(summary.dense_dim, Some(2));
        assert_eq!(summary.dense_vectors, 2);

        let segments_dir = data_dir.join("shards").join("shard-0000").join("segments");
        let mut mgr = IndexManager::new();
        mgr.scan_and_load(&segments_dir).expect("scan");

        // Query embedding aligned to doc B (doc_id 1). Weight dense heavily.
        let provider = build_dense_provider(&mgr, data_dir, &[0.0, 1.0], None).expect("provider from .ccxe");
        assert_eq!(provider.len(), 2);
        let weights = FusionWeights {
            bm25: 0.1,
            graph: 0.0,
            dense: 0.9,
            sparse: 0.0,
        };
        let req = fused_req(tenant, "shared keyword", vec![0.0, 1.0], weights);

        let resp = fused_retrieve(&mgr, &req, None, Some(&provider)).expect("fused");
        assert!(resp.stats.dense_lane_active, "dense lane must be active");
        assert_eq!(resp.results.len(), 2);
        // doc-b is the 2nd appended frame → doc_id 1, and is query-aligned.
        assert_eq!(resp.results[0].doc_id, 1, "query-aligned doc must rank first");
        assert!(resp.results[0].score_breakdown.dense > 0.99, "top hit dense score ~1.0");
    }

    #[test]
    #[serial_test::serial]
    fn delegated_dense_provider_rejects_mismatched_or_unlabelled_stored_vectors() {
        let matching_profile =
            corecrux_memory::embeddings::SemanticProfile::from_parts("delegate-model", 2, "tokenizer-a", "none", "l2");
        let wrong_profile =
            corecrux_memory::embeddings::SemanticProfile::from_parts("other-model", 2, "tokenizer-b", "none", "l2");
        let docs = vec![ProseDocument {
            doc_id: "profiled".to_string(),
            chunks: vec![dense_chunk("profiled::0", "profiled vector", vec![1.0, 0.0])],
        }];

        let profiled = tempfile::tempdir().unwrap();
        seal_prose_documents(
            profiled.path(),
            0,
            1,
            "tenant",
            "corpus",
            "2026-07-01T00:00:00Z",
            &docs,
            Some(&matching_profile),
        )
        .expect("seal profiled vectors");
        let mut profiled_index = IndexManager::new();
        profiled_index
            .scan_and_load(&profiled.path().join("shards").join("shard-0000").join("segments"))
            .expect("scan profiled vectors");
        assert!(build_dense_provider_strict(
            &profiled_index,
            profiled.path(),
            &[1.0, 0.0],
            &matching_profile.embedding_fingerprint.hash,
        )
        .expect("matching profile")
        .is_some());
        assert!(matches!(
            build_dense_provider_strict(
                &profiled_index,
                profiled.path(),
                &[1.0, 0.0],
                &wrong_profile.embedding_fingerprint.hash,
            ),
            Err(DenseProfileCompatibilityError::FingerprintMismatch { .. })
        ));

        let unlabelled = tempfile::tempdir().unwrap();
        seal_prose_documents(
            unlabelled.path(),
            0,
            1,
            "tenant",
            "corpus",
            "2026-07-01T00:00:00Z",
            &docs,
            None,
        )
        .expect("seal legacy vectors");
        let mut unlabelled_index = IndexManager::new();
        unlabelled_index
            .scan_and_load(&unlabelled.path().join("shards").join("shard-0000").join("segments"))
            .expect("scan legacy vectors");
        assert!(matches!(
            build_dense_provider_strict(
                &unlabelled_index,
                unlabelled.path(),
                &[1.0, 0.0],
                &matching_profile.embedding_fingerprint.hash,
            ),
            Err(DenseProfileCompatibilityError::MissingProfile { .. })
        ));

        let forged = tempfile::tempdir().unwrap();
        seal_prose_documents(
            forged.path(),
            0,
            1,
            "tenant",
            "corpus",
            "2026-07-01T00:00:00Z",
            &docs,
            Some(&matching_profile),
        )
        .expect("seal vectors with profile to forge");
        let forged_segments = forged.path().join("shards").join("shard-0000").join("segments");
        let profile_path = std::fs::read_dir(&forged_segments)
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .find(|path| path.extension().and_then(|ext| ext.to_str()) == Some("ccxprof"))
            .expect("profile companion");
        let mut forged_profile = matching_profile.clone();
        forged_profile.profile_id = "sp_forged".to_string();
        std::fs::write(&profile_path, serde_json::to_vec(&forged_profile).unwrap()).expect("forge profile sidecar");
        let mut forged_index = IndexManager::new();
        forged_index
            .scan_and_load(&forged_segments)
            .expect("scan forged profile vectors");
        assert!(matches!(
            build_dense_provider_strict(
                &forged_index,
                forged.path(),
                &[1.0, 0.0],
                &matching_profile.embedding_fingerprint.hash,
            ),
            Err(DenseProfileCompatibilityError::InvalidProfile { .. })
        ));

        let wrong_dimension = tempfile::tempdir().unwrap();
        seal_prose_documents(
            wrong_dimension.path(),
            0,
            1,
            "tenant",
            "corpus",
            "2026-07-01T00:00:00Z",
            &docs,
            Some(&matching_profile),
        )
        .expect("seal vectors with dimension to forge");
        let dimension_segments = wrong_dimension
            .path()
            .join("shards")
            .join("shard-0000")
            .join("segments");
        let vector_path = std::fs::read_dir(&dimension_segments)
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .find(|path| path.extension().and_then(|ext| ext.to_str()) == Some("ccxe"))
            .expect("vector companion");
        let mut vector_bytes = std::fs::read(&vector_path).expect("read vector companion");
        // Forge the stored dimension so it disagrees with the profile. `.ccxe` keeps
        // `dim` as a u16 at offset 26 of its 256-byte header (the old `.ccxv` layout
        // had it as a u32 at offset 6). `parse` does not verify the footer hashes —
        // that is `verify_footer_hashes`, called explicitly — so the forgery reaches
        // the dimension check rather than tripping an integrity error first.
        vector_bytes[26..28].copy_from_slice(&1u16.to_le_bytes());
        std::fs::write(&vector_path, vector_bytes).expect("forge vector dimension");
        let mut dimension_index = IndexManager::new();
        dimension_index
            .scan_and_load(&dimension_segments)
            .expect("scan wrong-dimension vectors");
        assert!(matches!(
            build_dense_provider_strict(
                &dimension_index,
                wrong_dimension.path(),
                &[1.0, 0.0],
                &matching_profile.embedding_fingerprint.hash,
            ),
            Err(DenseProfileCompatibilityError::DimensionMismatch { .. })
        ));
    }

    /// FU3: `build_dense_provider` caches parsed companions per `(shards_dir,
    /// seq)`. Repeated builds return identical scores (cache hit), and a
    /// different data dir reusing the same `segment_seq` does NOT read the first
    /// corpus's cached vectors.
    #[test]
    #[serial_test::serial]
    fn build_dense_provider_cache_is_consistent_and_dir_scoped() {
        use corecrux_retrieval::dense::DenseProvider;

        // Corpus A (seq 0): vector aligned to [1, 0].
        let tmp_a = tempfile::tempdir().unwrap();
        let docs_a = vec![ProseDocument {
            doc_id: "a".to_string(),
            chunks: vec![dense_chunk("a::0", "alpha", vec![1.0, 0.0])],
        }];
        seal_prose_documents(
            tmp_a.path(),
            0,
            1,
            "ta",
            "corpus",
            "2026-07-01T00:00:00Z",
            &docs_a,
            None,
        )
        .unwrap();
        let mut mgr_a = IndexManager::new();
        mgr_a
            .scan_and_load(&tmp_a.path().join("shards").join("shard-0000").join("segments"))
            .unwrap();

        // Two builds: the second is a cache hit and must match the first.
        let p1 = build_dense_provider(&mgr_a, tmp_a.path(), &[1.0, 0.0], None).expect("provider a1");
        let p2 = build_dense_provider(&mgr_a, tmp_a.path(), &[1.0, 0.0], None).expect("provider a2");
        assert_eq!(p1.len(), 1);
        assert_eq!(
            p1.dense_score(0, 0),
            p2.dense_score(0, 0),
            "cached build matches fresh build"
        );
        assert!(
            p2.dense_score(0, 0).unwrap() > 0.99,
            "aligned vector scores ~1.0 from cache"
        );

        // Corpus B in a DIFFERENT data dir, same seq 0, ORTHOGONAL vector.
        let tmp_b = tempfile::tempdir().unwrap();
        let docs_b = vec![ProseDocument {
            doc_id: "b".to_string(),
            chunks: vec![dense_chunk("b::0", "beta", vec![0.0, 1.0])],
        }];
        seal_prose_documents(
            tmp_b.path(),
            0,
            1,
            "tb",
            "corpus",
            "2026-07-01T00:00:00Z",
            &docs_b,
            None,
        )
        .unwrap();
        let mut mgr_b = IndexManager::new();
        mgr_b
            .scan_and_load(&tmp_b.path().join("shards").join("shard-0000").join("segments"))
            .unwrap();

        // Query [1, 0] against corpus B's orthogonal doc → 0.0. If the cache
        // collided on seq 0 it would wrongly return corpus A's ~1.0.
        let pb = build_dense_provider(&mgr_b, tmp_b.path(), &[1.0, 0.0], None).expect("provider b");
        assert_eq!(
            pb.dense_score(0, 0),
            Some(0.0),
            "a different data dir must not read the first corpus's cached vectors"
        );
    }

    /// M3 gate (c): dimension mismatch is rejected cleanly (no partial write).
    #[test]
    #[serial_test::serial]
    fn m3_dense_dim_mismatch_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let docs = vec![
            ProseDocument {
                doc_id: "d1".to_string(),
                chunks: vec![dense_chunk("d1::0", "text one", vec![1.0, 0.0])],
            },
            ProseDocument {
                doc_id: "d2".to_string(),
                chunks: vec![dense_chunk("d2::0", "text two", vec![1.0, 0.0, 0.0])],
            },
        ];
        let err = seal_prose_documents(tmp.path(), 0, 1, "t", "corpus", "2026-07-01T00:00:00Z", &docs, None)
            .expect_err("dim mismatch must be rejected");
        match err {
            LocalIngestError::DenseDimMismatch { expected, found } => {
                assert_eq!(expected, 2);
                assert_eq!(found, 3);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// M3 gate (b): ingest-without-vectors writes no `.ccxe`, the provider is
    /// absent, and BM25-only fused retrieval still serves.
    #[test]
    #[serial_test::serial]
    fn m3_no_vectors_serves_bm25_only() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let tenant = "tenant-m3b";
        let docs = vec![ProseDocument {
            doc_id: "d1".to_string(),
            chunks: vec![ProseChunk {
                chunk_id: "d1::0".to_string(),
                text: "plain bm25 only document".to_string(),
                dense_vector: None,
            }],
        }];
        let summary = seal_prose_documents(data_dir, 0, 1, tenant, "corpus", "2026-07-01T00:00:00Z", &docs, None)
            .expect("seal no vectors");
        assert_eq!(summary.dense_vectors, 0);
        assert_eq!(summary.dense_dim, None);

        let segments_dir = data_dir.join("shards").join("shard-0000").join("segments");
        let mut mgr = IndexManager::new();
        mgr.scan_and_load(&segments_dir).expect("scan");

        // No .ccxe → no provider.
        assert!(build_dense_provider(&mgr, data_dir, &[0.0, 1.0], None).is_none());

        // BM25-only fused retrieval still returns the doc (dense lane inert).
        let req = fused_req(tenant, "bm25 document", vec![0.0], FusionWeights::default());
        let resp = fused_retrieve(&mgr, &req, None, None).expect("fused bm25-only");
        assert!(!resp.stats.dense_lane_active);
        assert_eq!(resp.results.len(), 1);
    }

    /// M5: re-ingesting the same document (same `chunk_id` = storage `event_id`)
    /// is a no-op — the storage idempotency layer dedups the frame on the cold
    /// segment scan, so no duplicate is indexed. (The MediaCrux client also
    /// filters `cruxPushedAt IS NULL`, so this is defence-in-depth.)
    #[test]
    #[serial_test::serial]
    fn m5_idempotent_reingest_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let tenant = "tenant-m5";
        let docs = vec![ProseDocument {
            doc_id: "dup-doc".to_string(),
            chunks: vec![ProseChunk {
                chunk_id: "dup-doc::0".to_string(),
                text: "idempotent supersession target document".to_string(),
                dense_vector: None,
            }],
        }];

        let s1 = seal_prose_documents(data_dir, 0, 1, tenant, "corpus", "2026-07-01T00:00:00Z", &docs, None)
            .expect("first ingest");
        assert!(s1.sealed);
        let s2 = seal_prose_documents(data_dir, 0, 1, tenant, "corpus", "2026-07-01T00:00:05Z", &docs, None)
            .expect("second ingest of the same doc");

        // The second ingest must not produce a second live frame: either it seals
        // nothing (all events deduped) — the expected outcome.
        assert!(!s2.sealed, "duplicate re-ingest must dedup and seal nothing");

        let segments_dir = data_dir.join("shards").join("shard-0000").join("segments");
        let mut mgr = IndexManager::new();
        mgr.scan_and_load(&segments_dir).expect("scan");
        assert_eq!(mgr.total_docs(), 1, "no duplicate document after re-ingest");
        let readers = mgr.readers();
        let hits = bm25_search(
            &readers,
            "supersession",
            10,
            Some(tenant_hash(tenant)),
            &Bm25Params::default(),
            None,
            None,
        );
        assert_eq!(hits.hits.len(), 1, "exactly one copy served");
    }

    /// M5 (T.1): two tenants ingest documents sharing query terms; each tenant's
    /// query returns only its own documents.
    #[test]
    #[serial_test::serial]
    fn m5_tenant_isolation() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();

        let mk = |txt: &str| {
            vec![ProseDocument {
                doc_id: "shared-id".to_string(),
                chunks: vec![ProseChunk {
                    chunk_id: "shared-id::0".to_string(),
                    text: txt.to_string(),
                    dense_vector: None,
                }],
            }]
        };
        seal_prose_documents(
            data_dir,
            0,
            1,
            "tenant-a",
            "corpus",
            "2026-07-01T00:00:00Z",
            &mk("common secret alpha-only"),
            None,
        )
        .expect("tenant a");
        seal_prose_documents(
            data_dir,
            0,
            1,
            "tenant-b",
            "corpus",
            "2026-07-01T00:00:01Z",
            &mk("common secret beta-only"),
            None,
        )
        .expect("tenant b");

        let segments_dir = data_dir.join("shards").join("shard-0000").join("segments");
        let mut mgr = IndexManager::new();
        mgr.scan_and_load(&segments_dir).expect("scan");
        let readers = mgr.readers();
        let p = Bm25Params::default();

        // Tenant A sees only its own doc for the shared term.
        let a = bm25_search(
            &readers,
            "common secret",
            10,
            Some(tenant_hash("tenant-a")),
            &p,
            None,
            None,
        );
        assert_eq!(a.hits.len(), 1, "tenant-a sees exactly its own doc");
        // Tenant B likewise.
        let b = bm25_search(
            &readers,
            "common secret",
            10,
            Some(tenant_hash("tenant-b")),
            &p,
            None,
            None,
        );
        assert_eq!(b.hits.len(), 1, "tenant-b sees exactly its own doc");
        // A third tenant sees nothing.
        let c = bm25_search(
            &readers,
            "common secret",
            10,
            Some(tenant_hash("tenant-c")),
            &p,
            None,
            None,
        );
        assert_eq!(c.hits.len(), 0, "unrelated tenant sees nothing");
    }
}
