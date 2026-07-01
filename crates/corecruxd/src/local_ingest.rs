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

// M0 spike: the seal core is exercised by tests only until the M2 HTTP handler
// calls it. Removed once the flagged endpoint wires these in.
#![allow(dead_code)]

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
}

/// Errors from the local seal path.
#[derive(Debug)]
pub enum LocalIngestError {
    /// A stream hash could not be derived from the (tenant, corpus, doc) triple.
    StreamHash(String),
    /// The underlying `corecrux-storage` append/seal path failed.
    Storage(StorageError),
}

impl std::fmt::Display for LocalIngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalIngestError::StreamHash(msg) => write!(f, "stream hash error: {msg}"),
            LocalIngestError::Storage(err) => write!(f, "storage error: {err:?}"),
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

    Ok(SealSummary {
        segment_seq: seal.segment_seq.unwrap_or(0),
        frame_count: seal.frame_count.unwrap_or(0),
        documents: accepted_docs,
        chunks: total_chunks,
        sealed: seal.sealed,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use corecrux_retrieval::bm25::{bm25_search, Bm25Params};
    use corecrux_retrieval::IndexManager;

    fn tenant_hash(tenant_id: &str) -> u64 {
        xxhash_rust::xxh64::xxh64(tenant_id.as_bytes(), 0)
    }

    /// M0 gate: seal a 1-doc / 1-chunk segment to a temp data_dir entirely on CPU
    /// (no `DataPlaneStore`), then BM25-retrieve it via the ordinary retrieval path.
    #[test]
    fn m0_seal_one_chunk_and_bm25_retrieve() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();
        let tenant = "tenant-m0";

        let docs = vec![ProseDocument {
            doc_id: "doc-1".to_string(),
            chunks: vec![ProseChunk {
                chunk_id: "doc-1::0".to_string(),
                text: "the peregrine falcon is the fastest animal on earth".to_string(),
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
}
