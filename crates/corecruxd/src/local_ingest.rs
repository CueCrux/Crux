// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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

use std::path::Path;

use corecrux_storage::{AppendEventInput, ShardStorage, ShardStorageOptions, StorageError};

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
    /// as the `.ccxv` companion and served via `CosineDenseProvider` (M3). All
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
    /// Number of dense vectors persisted to the `.ccxv` companion (M3).
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
    /// Persisting the `.ccxv` dense companion failed.
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
pub fn seal_prose_documents(
    data_dir: &Path,
    shard_id: u32,
    epoch: u64,
    tenant_id: &str,
    corpus_id: &str,
    ingested_at_rfc3339: &str,
    documents: &[ProseDocument],
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

    // M3: persist the dense companion (`.ccxv`) alongside the sealed segment,
    // named with the same stem as its `.ccxseg` so the loader can find it by seq.
    let mut dense_written = 0usize;
    if seal.sealed && !dense_entries.is_empty() {
        if let (Some(receipt), Some(dim)) = (seal.seal_receipt.as_ref(), dense_dim) {
            let segments_dir = shards_root.join(format!("shard-{shard_id:04}")).join("segments");
            let stem = format!("seg-{:020}-{}", receipt.segment_seq, hex16(&receipt.segment_id.0));
            let path = segments_dir.join(format!("{stem}.ccxv"));
            write_ccxv(&path, dim as u32, &dense_entries).map_err(|e| LocalIngestError::DenseIo(e.to_string()))?;
            dense_written = dense_entries.len();
        }
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

// ── `.ccxv` dense companion (CPU `.ccxe`-equivalent) ────────────────────────
//
// Minimal, deterministic on-disk format co-located with a sealed segment:
//   magic:  u32 LE = "CCXV"
//   version:u16 LE = 1
//   dim:    u32 LE  (all vectors share this dimension)
//   count:  u32 LE
//   count × { doc_id: u32 LE, dim × f32 LE }
//
// `doc_id` is the segment-local frame index (matches the `.ccxi` doc ordering).
// This is the free CPU counterpart to the paid GPU `.ccxe`; both are consumed
// behind the `DenseProvider` trait.

const CCXV_MAGIC: u32 = 0x5643_5843; // "CXCV"-ish tag; version-guarded below.
const CCXV_VERSION: u16 = 1;

/// `(doc_id, vector)` entries read from a `.ccxv` companion.
type DenseEntries = Vec<(u32, Vec<f32>)>;

fn write_ccxv(path: &Path, dim: u32, entries: &[(u32, Vec<f32>)]) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(16 + entries.len() * (4 + dim as usize * 4));
    buf.extend_from_slice(&CCXV_MAGIC.to_le_bytes());
    buf.extend_from_slice(&CCXV_VERSION.to_le_bytes());
    buf.extend_from_slice(&dim.to_le_bytes());
    buf.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (doc_id, vec) in entries {
        buf.extend_from_slice(&doc_id.to_le_bytes());
        for &f in vec {
            buf.extend_from_slice(&f.to_le_bytes());
        }
    }
    // Atomic write: tmp → rename.
    let tmp = path.with_extension("ccxv.partial");
    std::fs::write(&tmp, &buf)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Read a `.ccxv` companion → (dim, [(doc_id, vector)]). Returns `None` on a bad
/// magic/version or a truncated file (treated as absent rather than fatal).
///
/// Serve-side (consumed by [`build_dense_provider`]): exercised by M3 tests and
/// the deferred query-embedding track; not on the daemon's default query path.
#[allow(dead_code)]
fn read_ccxv(path: &Path) -> Option<(u32, DenseEntries)> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() < 14 {
        return None;
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
    let version = u16::from_le_bytes(bytes[4..6].try_into().ok()?);
    if magic != CCXV_MAGIC || version != CCXV_VERSION {
        return None;
    }
    let dim = u32::from_le_bytes(bytes[6..10].try_into().ok()?);
    let count = u32::from_le_bytes(bytes[10..14].try_into().ok()?) as usize;
    let stride = 4 + dim as usize * 4;
    let mut off = 14;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if off + stride > bytes.len() {
            return None;
        }
        let doc_id = u32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
        let mut v = Vec::with_capacity(dim as usize);
        let mut p = off + 4;
        for _ in 0..dim {
            v.push(f32::from_le_bytes(bytes[p..p + 4].try_into().ok()?));
            p += 4;
        }
        out.push((doc_id, v));
        off += stride;
    }
    Some((dim, out))
}

/// Build a [`corecrux_retrieval::CosineDenseProvider`] over all sealed `.ccxv` companions, keyed by
/// `(doc_id, segment_index)` to match [`corecrux_retrieval::fused::fused_retrieve`]'s
/// enumeration (`segment_index` = position in `index_mgr.readers()`, which is
/// ascending `segment_seq`). Returns `None` when no dense vectors are stored, so
/// the caller leaves the dense lane inert.
///
/// Consumed by the M3 fusion fixture tests and by the deferred query-embedding
/// track (`cruxengine-prose-payload-processor`); the daemon does not embed queries.
#[allow(dead_code)]
pub fn build_dense_provider(
    index_mgr: &corecrux_retrieval::IndexManager,
    data_dir: &Path,
    query_embedding: &[f32],
) -> Option<corecrux_retrieval::CosineDenseProvider> {
    use std::collections::HashMap;

    let shards_dir = data_dir.join("shards");
    let mut vectors: HashMap<(u32, usize), Vec<f32>> = HashMap::new();

    for (segment_index, reader) in index_mgr.readers().iter().enumerate() {
        let seq = reader.header.segment_seq;
        let Some(path) = find_ccxv_for_seq(&shards_dir, seq) else {
            continue;
        };
        let Some((_dim, entries)) = read_ccxv(&path) else {
            continue;
        };
        for (doc_id, v) in entries {
            vectors.insert((doc_id, segment_index), v);
        }
    }

    if vectors.is_empty() {
        return None;
    }
    Some(corecrux_retrieval::CosineDenseProvider::new(query_embedding, vectors))
}

/// Locate the `.ccxv` companion for a segment sequence across all shards.
#[allow(dead_code)]
fn find_ccxv_for_seq(shards_dir: &Path, seq: u64) -> Option<std::path::PathBuf> {
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
            if name.starts_with(&prefix) && name.ends_with(".ccxv") {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use corecrux_retrieval::bm25::{bm25_search, Bm25Params};
    use corecrux_retrieval::IndexManager;

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
            bm25_search(&readers, "alpha centauri", 10, th, &p, None).hits.len(),
            1,
            "first ingest must survive the second ingest's shard reopen"
        );
        assert_eq!(
            bm25_search(&readers, "betelgeuse", 10, th, &p, None).hits.len(),
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
        let summary = seal_prose_documents(data_dir, 0, 1, tenant, "corpus", "2026-07-01T00:00:00Z", &docs)
            .expect("seal with vectors");
        assert_eq!(summary.dense_dim, Some(2));
        assert_eq!(summary.dense_vectors, 2);

        let segments_dir = data_dir.join("shards").join("shard-0000").join("segments");
        let mut mgr = IndexManager::new();
        mgr.scan_and_load(&segments_dir).expect("scan");

        // Query embedding aligned to doc B (doc_id 1). Weight dense heavily.
        let provider = build_dense_provider(&mgr, data_dir, &[0.0, 1.0]).expect("provider from .ccxv");
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
        let err = seal_prose_documents(tmp.path(), 0, 1, "t", "corpus", "2026-07-01T00:00:00Z", &docs)
            .expect_err("dim mismatch must be rejected");
        match err {
            LocalIngestError::DenseDimMismatch { expected, found } => {
                assert_eq!(expected, 2);
                assert_eq!(found, 3);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// M3 gate (b): ingest-without-vectors writes no `.ccxv`, the provider is
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
        let summary = seal_prose_documents(data_dir, 0, 1, tenant, "corpus", "2026-07-01T00:00:00Z", &docs)
            .expect("seal no vectors");
        assert_eq!(summary.dense_vectors, 0);
        assert_eq!(summary.dense_dim, None);

        let segments_dir = data_dir.join("shards").join("shard-0000").join("segments");
        let mut mgr = IndexManager::new();
        mgr.scan_and_load(&segments_dir).expect("scan");

        // No .ccxv → no provider.
        assert!(build_dense_provider(&mgr, data_dir, &[0.0, 1.0]).is_none());

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

        let s1 = seal_prose_documents(data_dir, 0, 1, tenant, "corpus", "2026-07-01T00:00:00Z", &docs)
            .expect("first ingest");
        assert!(s1.sealed);
        let s2 = seal_prose_documents(data_dir, 0, 1, tenant, "corpus", "2026-07-01T00:00:05Z", &docs)
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
        )
        .expect("tenant b");

        let segments_dir = data_dir.join("shards").join("shard-0000").join("segments");
        let mut mgr = IndexManager::new();
        mgr.scan_and_load(&segments_dir).expect("scan");
        let readers = mgr.readers();
        let p = Bm25Params::default();

        // Tenant A sees only its own doc for the shared term.
        let a = bm25_search(&readers, "common secret", 10, Some(tenant_hash("tenant-a")), &p, None);
        assert_eq!(a.hits.len(), 1, "tenant-a sees exactly its own doc");
        // Tenant B likewise.
        let b = bm25_search(&readers, "common secret", 10, Some(tenant_hash("tenant-b")), &p, None);
        assert_eq!(b.hits.len(), 1, "tenant-b sees exactly its own doc");
        // A third tenant sees nothing.
        let c = bm25_search(&readers, "common secret", 10, Some(tenant_hash("tenant-c")), &p, None);
        assert_eq!(c.hits.len(), 0, "unrelated tenant sees nothing");
    }
}
