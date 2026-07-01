// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `POST /v1/local/ingest` — local CPU prose-ingest door.
//!
//! Accepts a pre-formatted prose payload (chunks + optional precomputed dense
//! vectors + metadata) and seals it into a local `corecrux-storage` segment
//! served over BM25 — **without** the GPU-gated `DataPlaneStore`/`DataPlanePool`
//! and **without** a GPU. This is the CPU "store + serve" half of the
//! "process in the platform, serve on your node" split.
//!
//! Gating: `CORECRUXD_LOCAL_INGEST=1`, default OFF. When off the route returns
//! 404 so the surface is invisible rather than half-alive (same convention as
//! the coord/context-surface planes). `/v1/append` behaviour is unchanged.
//!
//! ExecPlan `cpu-prose-ingest-door-2026-07-01`:
//! - M1: payload contract + flagged endpoint skeleton (validate + tenant-scope
//!   auth + 202 stub; NO write yet).

use super::{problem_response, AppState, HeaderMap, IntoResponse, Json, Response, State, StatusCode};
use crate::local_ingest::{seal_prose_documents, ProseChunk, ProseDocument};

/// Single-node local ingest writes to shard 0 at a fixed epoch. Segment
/// sequence auto-increments within the shard and persists via the MANIFEST.
const LOCAL_INGEST_SHARD_ID: u32 = 0;
const LOCAL_INGEST_EPOCH: u64 = 1;

/// Max documents accepted in a single request.
const MAX_DOCUMENTS_PER_REQUEST: usize = 4096;
/// Max chunks accepted across a single request.
const MAX_CHUNKS_PER_REQUEST: usize = 65_536;
/// Max bytes for a single chunk's text (guards against pathological payloads).
const MAX_CHUNK_TEXT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, serde::Deserialize)]
pub(super) struct LocalIngestBody {
    pub(super) tenant_id: String,
    pub(super) corpus_id: String,
    pub(super) documents: Vec<LocalIngestDocument>,
}

// `title`/`url`/`source_timestamp` are threaded into frame metadata in M2;
// `chunk_index`/`dense_vector`/`metadata` are consumed in M2/M3.
#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub(super) struct LocalIngestDocument {
    pub(super) doc_id: String,
    #[serde(default)]
    pub(super) title: Option<String>,
    #[serde(default)]
    pub(super) url: Option<String>,
    #[serde(default)]
    pub(super) source_timestamp: Option<String>,
    pub(super) chunks: Vec<LocalIngestChunk>,
}

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub(super) struct LocalIngestChunk {
    pub(super) chunk_id: String,
    pub(super) text: String,
    #[serde(default)]
    pub(super) chunk_index: Option<u32>,
    /// Precomputed dense vector (from CruxEngine). Omit for BM25-only. Consumed
    /// in M3; validated-but-ignored in M1/M2.
    #[serde(default)]
    pub(super) dense_vector: Option<Vec<f32>>,
    #[serde(default)]
    pub(super) metadata: Option<serde_json::Value>,
}

/// Accepted counts, computed during validation. Fields are asserted in tests;
/// the handler gates on validation success and reports authoritative counts from
/// the seal outcome.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AcceptedCounts {
    pub(super) documents: usize,
    pub(super) chunks: usize,
}

/// Validate the payload shape and limits. Pure (no auth, no I/O) so it can be
/// unit-tested directly. Returns the accepted counts or a `(status, detail)`.
pub(super) fn validate_payload(body: &LocalIngestBody) -> Result<AcceptedCounts, (StatusCode, String)> {
    if body.tenant_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "tenant_id must not be empty".to_string()));
    }
    if body.corpus_id.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "corpus_id must not be empty".to_string()));
    }
    if body.documents.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "documents must not be empty".to_string()));
    }
    if body.documents.len() > MAX_DOCUMENTS_PER_REQUEST {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("max {MAX_DOCUMENTS_PER_REQUEST} documents per request"),
        ));
    }

    let mut total_chunks = 0usize;
    let mut dense_dim: Option<usize> = None;
    for doc in &body.documents {
        if doc.doc_id.trim().is_empty() {
            return Err((StatusCode::BAD_REQUEST, "document doc_id must not be empty".to_string()));
        }
        if doc.chunks.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("document `{}` has no chunks", doc.doc_id),
            ));
        }
        for chunk in &doc.chunks {
            if chunk.chunk_id.trim().is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("chunk_id must not be empty in document `{}`", doc.doc_id),
                ));
            }
            if chunk.text.trim().is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("chunk `{}` text must not be empty", chunk.chunk_id),
                ));
            }
            if chunk.text.len() > MAX_CHUNK_TEXT_BYTES {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("chunk `{}` text exceeds {MAX_CHUNK_TEXT_BYTES} bytes", chunk.chunk_id),
                ));
            }
            // M3: all dense vectors in a request must share a dimension, and an
            // empty vector is a client error. Reject cleanly before any write.
            if let Some(v) = &chunk.dense_vector {
                if v.is_empty() {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        format!("chunk `{}` dense_vector must not be empty", chunk.chunk_id),
                    ));
                }
                match dense_dim {
                    None => dense_dim = Some(v.len()),
                    Some(d) if d != v.len() => {
                        return Err((
                            StatusCode::BAD_REQUEST,
                            format!(
                                "chunk `{}` dense_vector dimension {} != {} (all vectors must match)",
                                chunk.chunk_id,
                                v.len(),
                                d
                            ),
                        ));
                    }
                    _ => {}
                }
            }
            total_chunks += 1;
        }
    }

    if total_chunks > MAX_CHUNKS_PER_REQUEST {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("max {MAX_CHUNKS_PER_REQUEST} chunks per request"),
        ));
    }

    Ok(AcceptedCounts {
        documents: body.documents.len(),
        chunks: total_chunks,
    })
}

fn local_ingest_disabled_response() -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        "local ingest disabled (set CORECRUXD_LOCAL_INGEST=1)".to_string(),
    )
}

#[tracing::instrument(level = "info", skip(state, headers, body), fields(tenant_id = %body.tenant_id, corpus_id = %body.corpus_id))]
pub(super) async fn post_local_ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LocalIngestBody>,
) -> Response {
    // Flag gate: invisible when off.
    if !state.local_ingest_enabled {
        return local_ingest_disabled_response();
    }

    // T.1: admin:write scope, checked against the payload tenant. A caller
    // scoped to tenant A cannot ingest under tenant B.
    if let Err(problem) =
        crate::auth::require_http_scopes_for_tenant(&state.auth, &headers, &["admin:write"], &body.tenant_id)
    {
        return problem.into_response();
    }

    if let Err((status, detail)) = validate_payload(&body) {
        return problem_response(status, detail);
    }

    // Map the wire payload to the seal-core document model.
    let documents: Vec<ProseDocument> = body
        .documents
        .iter()
        .map(|d| ProseDocument {
            doc_id: d.doc_id.clone(),
            chunks: d
                .chunks
                .iter()
                .map(|c| ProseChunk {
                    chunk_id: c.chunk_id.clone(),
                    text: c.text.clone(),
                    dense_vector: c.dense_vector.clone(),
                })
                .collect(),
        })
        .collect();

    let data_dir = state.data_dir.clone();
    let tenant = body.tenant_id.clone();
    let corpus = body.corpus_id.clone();
    let ingested_at = chrono::Utc::now().to_rfc3339();
    let now_ms = crate::ops_events::now_unix_ms();

    // Serialize ingests (each seal takes the shard's exclusive lock), then run
    // the blocking seal + timeline write off the async runtime.
    let _guard = state.local_ingest_lock.lock().await;
    let seal_result = tokio::task::spawn_blocking(move || -> Result<SealOutcome, String> {
        let summary = seal_prose_documents(
            &data_dir,
            LOCAL_INGEST_SHARD_ID,
            LOCAL_INGEST_EPOCH,
            &tenant,
            &corpus,
            &ingested_at,
            &documents,
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
                    event_type: crate::local_ingest::PROSE_CHUNK_EVENT_TYPE.to_string(),
                    content_type: crate::local_ingest::PROSE_CHUNK_CONTENT_TYPE.to_string(),
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

        Ok(SealOutcome {
            segment_seq: summary.segment_seq,
            frame_count: summary.frame_count,
            documents: summary.documents,
            chunks: summary.chunks,
            sealed: summary.sealed,
            receipt_id: summary.receipt_material_hash.map(hex32),
            dense_dim: summary.dense_dim,
            dense_vectors: summary.dense_vectors,
        })
    })
    .await;

    let outcome = match seal_result {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(msg)) => {
            tracing::error!(error = %msg, "local-ingest seal failed");
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("local ingest seal failed: {msg}"),
            );
        }
        Err(join_err) => {
            tracing::error!(error = %join_err, "local-ingest seal task panicked");
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "local ingest seal task failed".to_string(),
            );
        }
    };

    // Load-at-runtime wiring: hot-reload the retrieval index so the freshly
    // sealed `.ccxi` is queryable immediately (idempotent — scan skips
    // already-loaded segments).
    {
        let mut guard = state.retrieval_index.write().await;
        let shards_dir = state.data_dir.join("shards");
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

    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "ingested": outcome.chunks,
            "documents": outcome.documents,
            "frame_count": outcome.frame_count,
            "sealed": outcome.sealed,
            "segment_seq": outcome.segment_seq,
            "receipt_id": outcome.receipt_id,
            "dense_vectors": outcome.dense_vectors,
            "dense_dim": outcome.dense_dim,
        })),
    )
        .into_response()
}

/// Handler-local seal outcome (owned, `Send` across the blocking boundary).
struct SealOutcome {
    segment_seq: u64,
    frame_count: u64,
    documents: usize,
    chunks: usize,
    sealed: bool,
    receipt_id: Option<String>,
    dense_dim: Option<usize>,
    dense_vectors: usize,
}

/// Lower-hex encode a 32-byte digest.
fn hex32(bytes: [u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn chunk(id: &str, text: &str) -> LocalIngestChunk {
        LocalIngestChunk {
            chunk_id: id.to_string(),
            text: text.to_string(),
            chunk_index: None,
            dense_vector: None,
            metadata: None,
        }
    }

    fn valid_body() -> LocalIngestBody {
        LocalIngestBody {
            tenant_id: "t1".to_string(),
            corpus_id: "mediacrux-archive".to_string(),
            documents: vec![LocalIngestDocument {
                doc_id: "doc-1".to_string(),
                title: Some("A title".to_string()),
                url: None,
                source_timestamp: None,
                chunks: vec![chunk("doc-1::0", "hello world"), chunk("doc-1::1", "second chunk")],
            }],
        }
    }

    #[test]
    fn validate_accepts_well_formed_payload() {
        let counts = validate_payload(&valid_body()).unwrap();
        assert_eq!(counts.documents, 1);
        assert_eq!(counts.chunks, 2);
    }

    #[test]
    fn validate_rejects_empty_documents() {
        let mut b = valid_body();
        b.documents.clear();
        let (status, _) = validate_payload(&b).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_rejects_empty_tenant() {
        let mut b = valid_body();
        b.tenant_id = "  ".to_string();
        assert_eq!(validate_payload(&b).unwrap_err().0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_rejects_document_without_chunks() {
        let mut b = valid_body();
        b.documents[0].chunks.clear();
        assert_eq!(validate_payload(&b).unwrap_err().0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_rejects_empty_chunk_text() {
        let mut b = valid_body();
        b.documents[0].chunks[0].text = "   ".to_string();
        assert_eq!(validate_payload(&b).unwrap_err().0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_rejects_dense_dim_mismatch() {
        let mut b = valid_body();
        b.documents[0].chunks[0].dense_vector = Some(vec![1.0, 0.0]);
        b.documents[0].chunks[1].dense_vector = Some(vec![1.0, 0.0, 0.0]);
        assert_eq!(validate_payload(&b).unwrap_err().0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn validate_accepts_consistent_dense_dims() {
        let mut b = valid_body();
        b.documents[0].chunks[0].dense_vector = Some(vec![1.0, 0.0]);
        b.documents[0].chunks[1].dense_vector = Some(vec![0.0, 1.0]);
        assert!(validate_payload(&b).is_ok());
    }

    #[tokio::test]
    async fn flag_off_returns_404() {
        // Default test auth mode is Off; flag defaults off.
        let state = super::super::tests::test_app_state(16);
        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(valid_body()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn flag_on_valid_returns_202() {
        // AuthMode::Off short-circuits scope/tenant checks.
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(valid_body()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn flag_on_invalid_returns_400() {
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        let mut body = valid_body();
        body.documents.clear();
        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// T.1 wiring: under an enforcing auth mode, a request with no scopes is
    /// rejected before any write — the handler goes through tenant-scoped auth.
    /// (The deep JWT cross-tenant isolation test lands at M5.)
    #[tokio::test]
    async fn flag_on_missing_scope_is_forbidden() {
        let mut state = super::super::tests::test_app_state_with_auth(16, crate::auth::AuthMode::DevScopes);
        state.local_ingest_enabled = true;
        // Present a scope set that lacks admin:write → tenant-scoped auth 403s
        // before any write happens.
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", "receipts:read".parse().unwrap());
        let resp = post_local_ingest(State(state), headers, Json(valid_body()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    use corecrux_retrieval::bm25::{bm25_search, Bm25Params};
    use corecrux_retrieval::IndexManager;

    fn tenant_hash(tenant_id: &str) -> u64 {
        xxhash_rust::xxh64::xxh64(tenant_id.as_bytes(), 0)
    }

    fn body_with(tenant: &str, corpus: &str, docs: &[(&str, &str)]) -> LocalIngestBody {
        LocalIngestBody {
            tenant_id: tenant.to_string(),
            corpus_id: corpus.to_string(),
            documents: docs
                .iter()
                .map(|(doc_id, text)| LocalIngestDocument {
                    doc_id: doc_id.to_string(),
                    title: None,
                    url: None,
                    source_timestamp: None,
                    chunks: vec![chunk(&format!("{doc_id}::0"), text)],
                })
                .collect(),
        }
    }

    /// M2 core: ingest through the handler, then the in-process retrieval index
    /// serves the prose over BM25 immediately (hot reload).
    #[tokio::test]
    async fn m2_ingest_writes_and_serves_in_process() {
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        let data_dir = state.data_dir.clone();
        let idx = state.retrieval_index.clone();

        let body = body_with(
            "tenant-m2h",
            "mediacrux-archive",
            &[
                ("a1", "the aurora borealis over norway"),
                ("a2", "deep sea anglerfish biology"),
            ],
        );
        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Served immediately from the hot-reloaded index.
        let guard = idx.read().await;
        let readers = guard.readers();
        assert_eq!(guard.total_docs(), 2);
        let th = Some(tenant_hash("tenant-m2h"));
        let p = Bm25Params::default();
        assert_eq!(bm25_search(&readers, "aurora borealis", 10, th, &p, None).hits.len(), 1);
        assert_eq!(bm25_search(&readers, "anglerfish", 10, th, &p, None).hits.len(), 1);

        // The .ccxi landed exactly where the daemon startup scan looks.
        let seg_dir = data_dir.join("shards").join("shard-0000").join("segments");
        assert!(seg_dir.exists(), "segments dir must exist after ingest");
    }

    /// M2 restart survival: after ingest, a cold IndexManager scanning the data
    /// dir (as the daemon does at startup) still serves the prose — no quarantine.
    #[tokio::test]
    async fn m2_ingest_survives_restart() {
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        let data_dir = state.data_dir.clone();

        // Two separate ingests → two segments → exercises the reopen sweep.
        for (i, doc) in [
            ("r1", "quartz crystal lattice structure"),
            ("r2", "migratory patterns of arctic terns"),
        ]
        .into_iter()
        .enumerate()
        {
            let body = body_with("tenant-restart", "corpus", &[doc]);
            let s = state.clone();
            let resp = post_local_ingest(State(s), HeaderMap::new(), Json(body))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::ACCEPTED, "ingest {i} must be accepted");
        }

        // Cold restart: brand-new index, scan all shards as main.rs does at boot.
        let mut cold = IndexManager::new();
        let shards_dir = data_dir.join("shards");
        for entry in std::fs::read_dir(&shards_dir).unwrap().flatten() {
            let _ = cold.scan_and_load(&entry.path().join("segments"));
        }
        assert_eq!(
            cold.total_docs(),
            2,
            "both segments must survive restart (no quarantine)"
        );
        let readers = cold.readers();
        let th = Some(tenant_hash("tenant-restart"));
        let p = Bm25Params::default();
        assert_eq!(bm25_search(&readers, "quartz", 10, th, &p, None).hits.len(), 1);
        assert_eq!(bm25_search(&readers, "arctic terns", 10, th, &p, None).hits.len(), 1);
    }
}
