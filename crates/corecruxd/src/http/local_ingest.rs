// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `POST /v1/local/ingest` — local CPU prose-ingest door.
//!
//! Accepts a pre-formatted prose payload (chunks + optional precomputed dense
//! vectors + metadata) and seals it into a local `corecrux-storage` segment
//! served over BM25 — **without** the GPU-gated `DataPlaneStore`/`DataPlanePool`
//! and **without** a GPU. This is the CPU "store + serve" half of the
//! "process in the platform, serve on your node" split.
//!
//! Gating: default ON; `CORECRUXD_LOCAL_INGEST=0` or `false` disables the
//! route. When off it returns 404 so the surface is invisible rather than
//! half-alive (same convention as the coord/context-surface planes).
//! `/v1/append` behaviour is unchanged.
//!
//! ExecPlan `cpu-prose-ingest-door-2026-07-01`:
//! - M1: payload contract + flagged endpoint skeleton (validate + tenant-scope
//!   auth + 202 stub; NO write yet).

use super::{
    problem_response, AppState, HeaderMap, IntoResponse, Json, ProblemDetails, ProblemResponse, Response, State,
    StatusCode,
};
use crate::local_ingest::{ingest_prose_documents, LocalIngestHandles, ProseChunk, ProseDocument};
use corecrux_memory::embeddings::SemanticProfile;

/// Whether this ingest's dense lane came out whole, and if not, how it failed.
///
/// ExecPlan `corecrux-ingest-dense-silent-failure-2026-08-07` (B1): before this,
/// an embed failure was a WARN in the daemon log and nothing else — the response
/// was an ordinary 202 with `sealed: true`, a full `frame_count` and
/// `dense_vectors: 0`. BM25 still indexes, so the tenant looked healthy while
/// retrieval had silently degraded to lexical-only. A caller can now assert
/// `dense_status == "ok"` (or compare `dense_vectors` to `dense_expected`)
/// without knowing anything about this node's embedder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DenseStatus {
    /// Every chunk that should carry a vector has one.
    Ok,
    /// Some chunks were embedded and some were not.
    Partial,
    /// Vectors were expected for this ingest and none were written — the embed
    /// step failed (see the `local-ingest-embedding-failed` WARN for the cause).
    Skipped,
    /// No vectors were expected: the caller supplied none and the node has no
    /// embedder. A BM25-only corpus by configuration, not by failure.
    NotConfigured,
    /// Nothing was sealed (an idempotent re-ingest of already-stored chunks), so
    /// there are no new frames whose dense lane could be whole or missing.
    NotApplicable,
}

impl DenseStatus {
    fn as_str(self) -> &'static str {
        match self {
            DenseStatus::Ok => "ok",
            DenseStatus::Partial => "partial",
            DenseStatus::Skipped => "skipped",
            DenseStatus::NotConfigured => "not_configured",
            DenseStatus::NotApplicable => "not_applicable",
        }
    }
}

/// Classify the dense outcome of one ingest. `expected` is how many chunks
/// should carry a vector (every chunk for a server-embedded ingest; the chunks
/// that carried one for a caller-supplied batch; zero otherwise), `written` is
/// how many the seal actually persisted to the `.ccxv` companion.
pub(super) fn dense_status(sealed: bool, expected: usize, written: usize) -> DenseStatus {
    if !sealed {
        return DenseStatus::NotApplicable;
    }
    match (expected, written) {
        (0, _) => DenseStatus::NotConfigured,
        (e, w) if w == e => DenseStatus::Ok,
        (_, 0) => DenseStatus::Skipped,
        _ => DenseStatus::Partial,
    }
}

/// Request-body ceiling for this route, matching the daemon-wide
/// `CORECRUXD_MAX_REQUEST_BODY_BYTES` default that the 413 problem response
/// names ([`crate::http::ingress`]).
///
/// Without this the route inherits axum's 2 MiB `DefaultBodyLimit`, so an ingest
/// of ~2 MiB was refused with a 413 whose detail claimed a 16 MiB limit — the
/// numbers a harness author reads to size their batches were wrong by 8×.
pub(super) const LOCAL_INGEST_MAX_REQUEST_BYTES: usize = crate::config::DEFAULT_MAX_REQUEST_BODY_BYTES;

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
    /// Optional declared [`SemanticProfile`] for caller-supplied `dense_vector`s
    /// (buyer-fit M3.3). When present and the node has a dense embedder whose
    /// fingerprint differs, the ingest is refused (422) rather than storing an
    /// unqueryable, silently mismatched vector space. Ignored for server-embedded
    /// or BM25-only ingests.
    #[serde(default)]
    pub(super) semantic_profile: Option<SemanticProfile>,
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

/// Project the request state onto the handles the shared write path needs.
fn local_ingest_handles(state: &AppState) -> LocalIngestHandles {
    LocalIngestHandles {
        data_dir: state.data_dir.clone(),
        ingest_lock: state.local_ingest_lock.clone(),
        retrieval_index: state.retrieval_index.clone(),
    }
}

fn local_ingest_disabled_response() -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        "local ingest disabled by CORECRUXD_LOCAL_INGEST=0/false".to_string(),
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

    // Server-side local embedding (buyer-fit M3.2): when the caller supplied no
    // dense vectors at all and the node has an embedder (the pure-Rust
    // LocalHashEmbedder by default), embed every chunk here so the `.ccxv`
    // companion is written and prose dense recall works offline with zero
    // external service. If the caller supplied ANY vector we respect theirs and
    // do not mix a local 256-dim vector into a foreign-dimension batch (the seal
    // path rejects mixed dimensions).
    let has_client_vectors = body
        .documents
        .iter()
        .flat_map(|d| &d.chunks)
        .any(|c| c.dense_vector.is_some());
    let (node_profile, delegate_selected) = {
        let store = state.fact_store.read().await;
        (store.semantic_profile(), store.delegation_status().is_some())
    };
    let server_embed = !has_client_vectors && node_profile.is_some();

    // M3.3 fingerprint refusal: a caller-supplied vector batch that DECLARES a
    // semantic profile whose embedding fingerprint differs from this node's dense
    // profile lives in an incompatible vector space — the query path embeds with
    // the node embedder and would silently skip it. Refuse loudly (422) so the
    // caller reindexes or configures a matching embedder, rather than storing
    // dead vectors.
    if has_client_vectors {
        if delegate_selected {
            return ProblemResponse(
                ProblemDetails::new(
                    StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                    "https://errors.cuecrux.com/delegated_client_vectors_unsupported",
                    "Delegated Ingest Requires Provider Embeddings",
                )
                .with_detail(
                    "Caller-supplied dense vectors are not accepted while daemon delegation is configured; omit dense_vector so the provider produces a verified semantic profile.",
                )
                .with_extensions(serde_json::json!({
                    "code": "DELEGATED_CLIENT_VECTORS_UNSUPPORTED",
                    "capability": "embedding_delegation",
                })),
            )
            .into_response();
        }
        if let Some(declared) = body.semantic_profile.as_ref() {
            let canonical = SemanticProfile::from_parts(
                &declared.model,
                declared.dimensions,
                &declared.tokenizer,
                &declared.prompt_template_version,
                &declared.normalisation,
            );
            if declared != &canonical {
                return ProblemResponse(
                    ProblemDetails::new(
                        StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                        "https://errors.cuecrux.com/invalid_semantic_profile",
                        "Invalid Semantic Profile",
                    )
                    .with_detail(
                        "semantic_profile identifiers and embedding fingerprint must be canonical for the declared model parameters.",
                    )
                    .with_extensions(serde_json::json!({
                        "code": "INVALID_SEMANTIC_PROFILE",
                    })),
                )
                .into_response();
            }
        }
        if let (Some(declared), Some(node)) = (body.semantic_profile.as_ref(), node_profile.as_ref()) {
            if declared.embedding_fingerprint.hash != node.embedding_fingerprint.hash {
                return problem_response(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    format!(
                        "dense_vector embedding fingerprint {} is incompatible with this node's embedding profile {} \
                         (model {}); reindex against the node embedder or configure a matching one",
                        declared.embedding_fingerprint.fingerprint_id,
                        node.embedding_fingerprint.fingerprint_id,
                        node.model,
                    ),
                );
            }
        }
    }

    if delegate_selected && server_embed {
        let chunks = body.documents.iter().flat_map(|document| &document.chunks);
        let chunk_count = chunks.clone().count();
        let total_bytes = chunks
            .clone()
            .fold(0usize, |total, chunk| total.saturating_add(chunk.text.len()));
        let item_too_large = chunks
            .clone()
            .any(|chunk| chunk.text.len() > corecrux_memory::embeddings::DELEGATION_MAX_TEXT_BYTES);
        if chunk_count > corecrux_memory::embeddings::DELEGATION_MAX_TEXTS_PER_REQUEST
            || total_bytes > corecrux_memory::embeddings::DELEGATION_MAX_TEXT_BYTES_PER_REQUEST
            || item_too_large
        {
            return ProblemResponse(
                ProblemDetails::new(
                    StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
                    "https://errors.cuecrux.com/embedding_delegation_request_too_large",
                    "Embedding Delegation Request Too Large",
                )
                .with_detail(
                    "Delegated local ingest must fit one bounded provider call; split this ingest into smaller requests.",
                )
                .with_extensions(serde_json::json!({
                    "code": "EMBEDDING_DELEGATION_REQUEST_TOO_LARGE",
                    "capability": "embedding_delegation",
                    "max_texts": corecrux_memory::embeddings::DELEGATION_MAX_TEXTS_PER_REQUEST,
                    "max_text_bytes": corecrux_memory::embeddings::DELEGATION_MAX_TEXT_BYTES,
                    "max_total_text_bytes": corecrux_memory::embeddings::DELEGATION_MAX_TEXT_BYTES_PER_REQUEST,
                })),
            )
            .into_response();
        }
    }

    // The profile to persist alongside the `.ccxv` companion: the node embedder's
    // for server-embedded ingests; the caller's declared profile for supplied
    // vectors (or a dimension-only marker when undeclared, so a later query with a
    // different embedder can still tell the space apart).
    let mut dense_profile: Option<SemanticProfile> = if server_embed {
        node_profile.clone()
    } else if has_client_vectors {
        body.semantic_profile.clone().or_else(|| {
            body.documents
                .iter()
                .flat_map(|d| &d.chunks)
                .find_map(|c| c.dense_vector.as_ref())
                .map(|v| SemanticProfile::from_parts("client-unspecified", v.len(), "unknown", "none", "unknown"))
        })
    } else {
        None
    };

    // A delegated batch is all-or-nothing and happens before sealing. If the
    // remote capability is degraded, return an explicit 503 rather than
    // silently persisting a BM25-only corpus under a dense semantic profile.
    let (server_embeddings, refreshed_server_profile, delegation_configured) = if server_embed {
        let texts = body
            .documents
            .iter()
            .flat_map(|document| &document.chunks)
            .map(|chunk| chunk.text.as_str())
            .collect::<Vec<_>>();
        let store = state.fact_store.read().await;
        let embeddings = match store.try_embed_texts(&texts) {
            Ok(embeddings) => embeddings,
            Err(err) => {
                tracing::warn!(error = %err, chunk_count = texts.len(), "local-ingest-embedding-failed");
                if let Some(status) = store.delegation_status() {
                    return super::embedding_delegation_degraded_response(&status);
                }
                // Retain the existing sparse-only behavior for local and
                // generic external embedders; authenticated Crux delegation
                // has an explicit no-fallback contract above.
                None
            }
        };
        (
            embeddings,
            store.semantic_profile(),
            store.delegation_status().is_some(),
        )
    } else {
        (None, None, false)
    };
    if server_embeddings.is_some() {
        // Delegation pins the provider's complete semantic profile only after
        // the first successful response. Persist that refreshed fingerprint
        // beside the vectors, not the preflight model/dimension placeholder.
        dense_profile = refreshed_server_profile;
    }
    if delegation_configured {
        let (Some(embeddings), Some(profile)) = (server_embeddings.as_ref(), dense_profile.as_ref()) else {
            return super::embedding_semantic_profile_mismatch_response(
                "Remote embedding delegation did not produce a verifiable semantic profile.",
            );
        };
        let Some(probe_embedding) = embeddings.first() else {
            return super::embedding_semantic_profile_mismatch_response(
                "Remote embedding delegation did not produce a verifiable embedding batch.",
            );
        };
        let compatibility = {
            let index = state.retrieval_index.read().await;
            crate::local_ingest::build_dense_provider_strict(
                &index,
                &state.data_dir,
                probe_embedding,
                &profile.embedding_fingerprint.hash,
            )
        };
        match compatibility {
            Ok(_) => state.fact_store.read().await.clear_semantic_profile_mismatch(),
            Err(error) => {
                tracing::warn!(?error, "delegated-ingest-stored-semantic-profile-mismatch");
                state.fact_store.read().await.report_semantic_profile_mismatch();
                return super::embedding_semantic_profile_mismatch_response(
                    "The remote provider semantic profile is incompatible with stored dense vectors; reindex with the configured model.",
                );
            }
        }
    }

    // B1: how many chunks this ingest expects to carry a vector — every chunk
    // when the node embeds server-side, the caller-vectored subset otherwise.
    // Compared against what the seal actually wrote, this is what turns a silent
    // dense gap into a reported one.
    let dense_expected = if server_embed {
        body.documents.iter().map(|d| d.chunks.len()).sum::<usize>()
    } else {
        body.documents
            .iter()
            .flat_map(|d| &d.chunks)
            .filter(|c| c.dense_vector.is_some())
            .count()
    };

    // Map the wire payload to the seal-core document model.
    let documents: Vec<ProseDocument> = if server_embed {
        let mut embeddings = server_embeddings.unwrap_or_default().into_iter();
        body.documents
            .iter()
            .map(|d| ProseDocument {
                doc_id: d.doc_id.clone(),
                chunks: d
                    .chunks
                    .iter()
                    .map(|c| ProseChunk {
                        chunk_id: c.chunk_id.clone(),
                        text: c.text.clone(),
                        dense_vector: embeddings.next(),
                    })
                    .collect(),
            })
            .collect()
    } else {
        body.documents
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
            .collect()
    };

    // Seal + timeline + index reload run through the shared write path so the
    // in-process producers (the vault watcher) are byte-identical to this route.
    let summary = match ingest_prose_documents(
        &local_ingest_handles(&state),
        &body.tenant_id,
        &body.corpus_id,
        documents,
        dense_profile,
    )
    .await
    {
        Ok(summary) => {
            let mut streak = state.seal_failed_streak.write().await;
            *streak = (0, None);
            summary
        }
        Err(msg) => {
            // Count the streak so `/readyz` can report a dead write path. A 500
            // per request and nothing else is what let host `crux` sit broken
            // for 38 hours: reads were fine, so every probe stayed green.
            let streak = {
                let mut streak = state.seal_failed_streak.write().await;
                streak.0 = streak.0.saturating_add(1);
                streak.1 = Some(msg.clone());
                streak.0
            };
            state.metrics.inc_local_ingest_seal_failed();
            tracing::error!(
                error = %msg,
                consecutive_failures = streak,
                "local-ingest seal failed"
            );
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("local ingest seal failed: {msg}"),
            );
        }
    };
    let dense = dense_status(summary.sealed, dense_expected, summary.dense_vectors);
    // A segment must never seal with a silent dense gap: the response says so
    // (below) and the daemon says so here, at WARN, with the numbers that let an
    // operator find the affected segment.
    if matches!(dense, DenseStatus::Skipped | DenseStatus::Partial) {
        tracing::warn!(
            tenant_id = %body.tenant_id,
            corpus_id = %body.corpus_id,
            segment_seq = summary.segment_seq,
            dense_status = dense.as_str(),
            dense_expected,
            dense_written = summary.dense_vectors,
            "local-ingest-dense-gap-sealed"
        );
    }
    let outcome = SealOutcome {
        segment_seq: summary.segment_seq,
        frame_count: summary.frame_count,
        documents: summary.documents,
        chunks: summary.chunks,
        sealed: summary.sealed,
        receipt_id: summary.receipt_material_hash.map(hex32),
        dense_dim: summary.dense_dim,
        dense_vectors: summary.dense_vectors,
        dense_expected,
        dense_status: dense,
    };

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
            "dense_expected": outcome.dense_expected,
            "dense_status": outcome.dense_status.as_str(),
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
    dense_expected: usize,
    dense_status: DenseStatus,
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

    /// A configured, NON-delegating embedder that always fails — an Ollama-style
    /// [`corecrux_memory::embeddings::EmbeddingClient`] whose service is down, or
    /// (the B1 case) whose response overflowed the client's body limit. This path
    /// keeps its sparse-only fallback by contract; the point of the assertions
    /// below is that the fallback is now *reported*.
    #[derive(Debug)]
    struct FailingLocalEmbedder;

    impl corecrux_memory::embeddings::Embedder for FailingLocalEmbedder {
        fn embed_batch(&self, _texts: &[&str]) -> Result<Vec<Vec<f32>>, corecrux_memory::embeddings::EmbeddingError> {
            Err(corecrux_memory::embeddings::EmbeddingError::Deserialize(
                "json: the response body is larger than request limit: 10485760".to_string(),
            ))
        }

        fn dimensions(&self) -> usize {
            1024
        }

        fn model(&self) -> &str {
            "bge-m3"
        }

        fn semantic_profile(&self) -> SemanticProfile {
            SemanticProfile::from_parts("bge-m3", 1024, "model_default", "none", "none")
        }
    }

    #[derive(Debug)]
    struct DegradedDelegation;

    #[derive(Debug)]
    struct SuccessfulDelegation;

    impl corecrux_memory::embeddings::Embedder for DegradedDelegation {
        fn embed_batch(&self, _texts: &[&str]) -> Result<Vec<Vec<f32>>, corecrux_memory::embeddings::EmbeddingError> {
            Err(corecrux_memory::embeddings::EmbeddingError::Network(
                "mock delegate unavailable".to_string(),
            ))
        }

        fn dimensions(&self) -> usize {
            2
        }

        fn model(&self) -> &str {
            "mock-delegate"
        }

        fn semantic_profile(&self) -> SemanticProfile {
            SemanticProfile::from_parts("mock-delegate", 2, "mock", "none", "l2")
        }

        fn delegation_status(&self) -> Option<corecrux_memory::embeddings::DelegationStatus> {
            Some(corecrux_memory::embeddings::DelegationStatus {
                availability: corecrux_memory::embeddings::DelegationAvailability::Degraded,
                circuit_state: corecrux_memory::embeddings::DelegationCircuitState::Open,
                reason_code: "embedding_delegate_circuit_open",
                reason: "mock circuit open",
                consecutive_failures: 3,
            })
        }
    }

    impl corecrux_memory::embeddings::Embedder for SuccessfulDelegation {
        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, corecrux_memory::embeddings::EmbeddingError> {
            Ok(texts.iter().map(|_| vec![1.0, 0.0]).collect())
        }

        fn dimensions(&self) -> usize {
            2
        }

        fn model(&self) -> &str {
            "new-delegate"
        }

        fn semantic_profile(&self) -> SemanticProfile {
            SemanticProfile::from_parts("new-delegate", 2, "new-tokenizer", "none", "l2")
        }

        fn delegation_status(&self) -> Option<corecrux_memory::embeddings::DelegationStatus> {
            Some(corecrux_memory::embeddings::DelegationStatus {
                availability: corecrux_memory::embeddings::DelegationAvailability::Available,
                circuit_state: corecrux_memory::embeddings::DelegationCircuitState::Closed,
                reason_code: "available",
                reason: "mock delegate available",
                consecutive_failures: 0,
            })
        }
    }

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
            semantic_profile: None,
        }
    }

    /// The route must accept a body up to the daemon-wide limit its own 413
    /// message advertises. Without the explicit `DefaultBodyLimit` the route
    /// inherited axum's 2 MiB default and refused a 3 MiB ingest while claiming
    /// a 16 MiB ceiling — mis-sizing every harness that reads that number.
    #[tokio::test]
    async fn ingest_route_accepts_a_body_over_the_axum_default_limit() {
        use tower::ServiceExt as _;

        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        let app = super::super::router(state, super::super::tests::test_case_store());

        // ~3 MiB of payload: over axum's 2 MiB default, under the 16 MiB
        // daemon limit.
        let filler = "lorem ipsum dolor sit amet ".repeat(4_000);
        let body = serde_json::json!({
            "tenant_id": "tenant-bodylimit",
            "corpus_id": "docs",
            "documents": [{
                "doc_id": "big",
                "chunks": (0..30)
                    .map(|i| serde_json::json!({
                        "chunk_id": format!("big::{i}"),
                        "text": format!("{i} {filler}"),
                    }))
                    .collect::<Vec<_>>(),
            }],
        })
        .to_string();
        assert!(
            body.len() > 2 * 1024 * 1024 && body.len() < LOCAL_INGEST_MAX_REQUEST_BYTES,
            "fixture must straddle the two limits (was {} bytes)",
            body.len()
        );

        let resp = app
            .oneshot(
                axum::http::Request::post("/v1/local/ingest")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::ACCEPTED,
            "a 3 MiB ingest must not be refused as payload-too-large"
        );
    }

    // ── B1: dense outcome reporting ──────────────────────────────────────

    #[test]
    fn dense_status_classifies_every_outcome() {
        assert_eq!(dense_status(true, 10, 10), DenseStatus::Ok);
        assert_eq!(dense_status(true, 10, 0), DenseStatus::Skipped);
        assert_eq!(dense_status(true, 10, 4), DenseStatus::Partial);
        assert_eq!(dense_status(true, 0, 0), DenseStatus::NotConfigured);
        // An idempotent re-ingest seals nothing, so there is no gap to report.
        assert_eq!(dense_status(false, 10, 0), DenseStatus::NotApplicable);
    }

    /// B1 negative: a configured embedder that fails keeps the sparse-only
    /// fallback — but the response now says `skipped`, carries `dense_expected`,
    /// and never looks like a healthy dense ingest.
    #[tokio::test]
    #[serial_test::serial]
    async fn failed_embedding_reports_skipped_dense_status() {
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        state
            .fact_store
            .write()
            .await
            .set_embedder(Box::new(FailingLocalEmbedder));

        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(valid_body()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED, "sparse fallback still seals");
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["sealed"], serde_json::json!(true));
        assert_eq!(json["dense_vectors"], serde_json::json!(0));
        assert_eq!(
            json["dense_expected"],
            serde_json::json!(2),
            "both chunks were expected to embed"
        );
        assert_eq!(
            json["dense_status"], "skipped",
            "a silent dense gap must be reported to the caller"
        );
    }

    /// B1 positive: a healthy server-embedded ingest reports `ok`, and
    /// `dense_expected` equals the chunks sent — the equality a harness asserts.
    #[tokio::test]
    #[serial_test::serial]
    async fn server_embedded_ingest_reports_ok_dense_status() {
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        state
            .fact_store
            .write()
            .await
            .set_embedder(Box::new(corecrux_memory::embeddings::LocalHashEmbedder::default()));

        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(valid_body()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["dense_status"], "ok");
        assert_eq!(json["dense_expected"], serde_json::json!(2));
        assert_eq!(json["dense_vectors"], serde_json::json!(2));
    }

    /// A node with no embedder is BM25-only by configuration, not by failure —
    /// it must not be reported as a dense gap.
    #[tokio::test]
    #[serial_test::serial]
    async fn no_embedder_reports_not_configured_not_a_gap() {
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;

        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(valid_body()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["dense_status"], "not_configured");
        assert_eq!(json["dense_expected"], serde_json::json!(0));
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
    #[serial_test::serial]
    async fn default_config_accepts_ingest() {
        std::env::remove_var("CORECRUXD_LOCAL_INGEST");
        let config = crate::config::load_config();
        assert!(config.local_ingest_enabled);

        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = config.local_ingest_enabled;
        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(valid_body()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn explicit_zero_disables_ingest_with_404() {
        std::env::set_var("CORECRUXD_LOCAL_INGEST", "0");
        let config = crate::config::load_config();
        assert!(!config.local_ingest_enabled);

        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = config.local_ingest_enabled;
        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(valid_body()))
            .await
            .into_response();
        std::env::remove_var("CORECRUXD_LOCAL_INGEST");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn enabled_state_valid_returns_202() {
        // AuthMode::Off short-circuits scope/tenant checks.
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(valid_body()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn delegated_embedding_failure_returns_explicit_503_without_sparse_fallback() {
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        state
            .fact_store
            .write()
            .await
            .set_embedder(Box::new(DegradedDelegation));
        let index = state.retrieval_index.clone();

        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(valid_body()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read problem response");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("decode problem response");
        assert_eq!(body["code"], "EMBEDDING_DELEGATION_DEGRADED");
        assert_eq!(body["reason_code"], "embedding_delegate_circuit_open");
        assert_eq!(
            index.read().await.total_docs(),
            0,
            "failed delegation must not seal sparse data"
        );
    }

    #[tokio::test]
    async fn delegated_ingest_rejects_unverified_caller_vectors_without_sealing() {
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        state
            .fact_store
            .write()
            .await
            .set_embedder(Box::new(SuccessfulDelegation));
        let index = state.retrieval_index.clone();
        let mut body = valid_body();
        for chunk in &mut body.documents[0].chunks {
            chunk.dense_vector = Some(vec![1.0, 0.0]);
        }

        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read problem response");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("decode problem response");
        assert_eq!(body["code"], "DELEGATED_CLIENT_VECTORS_UNSUPPORTED");
        assert_eq!(index.read().await.total_docs(), 0);
    }

    #[tokio::test]
    async fn delegated_ingest_rejects_oversized_logical_call_without_degrading_breaker() {
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        state
            .fact_store
            .write()
            .await
            .set_embedder(Box::new(SuccessfulDelegation));
        let store = state.fact_store.clone();
        let index = state.retrieval_index.clone();
        let mut body = valid_body();
        body.documents[0].chunks = (0..=corecrux_memory::embeddings::DELEGATION_MAX_TEXTS_PER_REQUEST)
            .map(|index| chunk(&format!("doc-1::{index}"), "bounded text"))
            .collect();

        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read problem response");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("decode problem response");
        assert_eq!(body["code"], "EMBEDDING_DELEGATION_REQUEST_TOO_LARGE");
        assert_eq!(index.read().await.total_docs(), 0);
        assert_eq!(
            store.read().await.delegation_status().map(|status| status.availability),
            Some(corecrux_memory::embeddings::DelegationAvailability::Available)
        );
    }

    #[tokio::test]
    async fn client_supplied_semantic_profile_must_be_canonical() {
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        let mut body = valid_body();
        for chunk in &mut body.documents[0].chunks {
            chunk.dense_vector = Some(vec![1.0, 0.0]);
        }
        let mut forged = SemanticProfile::from_parts("client-model", 2, "client-tokenizer", "none", "l2");
        forged.profile_id = "sp_forged".to_string();
        body.semantic_profile = Some(forged);

        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read problem response");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("decode problem response");
        assert_eq!(body["code"], "INVALID_SEMANTIC_PROFILE");
    }

    #[tokio::test]
    async fn delegated_ingest_rejects_provider_profile_incompatible_with_stored_vectors() {
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        let existing_profile = SemanticProfile::from_parts("old-model", 2, "old-tokenizer", "none", "l2");
        let existing_documents = vec![ProseDocument {
            doc_id: "existing-doc".to_string(),
            chunks: vec![ProseChunk {
                chunk_id: "existing-doc::0".to_string(),
                text: "existing dense content".to_string(),
                dense_vector: Some(vec![0.0, 1.0]),
            }],
        }];
        crate::local_ingest::seal_prose_documents(
            &state.data_dir,
            crate::local_ingest::LOCAL_INGEST_SHARD_ID,
            crate::local_ingest::LOCAL_INGEST_EPOCH,
            "t1",
            "mediacrux-archive",
            "2026-07-20T00:00:00Z",
            &existing_documents,
            Some(&existing_profile),
        )
        .expect("seal existing profiled vectors");
        state
            .retrieval_index
            .write()
            .await
            .scan_and_load(&state.data_dir.join("shards").join("shard-0000").join("segments"))
            .expect("load existing profiled vectors");
        state
            .fact_store
            .write()
            .await
            .set_embedder(Box::new(SuccessfulDelegation));
        let index = state.retrieval_index.clone();

        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(valid_body()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
            .await
            .expect("read problem response");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("decode problem response");
        assert_eq!(body["code"], "EMBEDDING_SEMANTIC_PROFILE_MISMATCH");
        assert_eq!(
            index.read().await.total_docs(),
            1,
            "incompatible delegated vectors must not be sealed"
        );
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
            semantic_profile: None,
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
        assert_eq!(
            bm25_search(&readers, "aurora borealis", 10, th, &p, None, None)
                .hits
                .len(),
            1
        );
        assert_eq!(
            bm25_search(&readers, "anglerfish", 10, th, &p, None, None).hits.len(),
            1
        );

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
        assert_eq!(bm25_search(&readers, "quartz", 10, th, &p, None, None).hits.len(), 1);
        assert_eq!(
            bm25_search(&readers, "arctic terns", 10, th, &p, None, None).hits.len(),
            1
        );
    }

    /// M4 (daemon side): a MediaCrux-scale backfill — 357 prose documents in one
    /// request — is accepted and all documents are BM25-served. This proves the
    /// door handles the archive size; the live MediaCrux client + backfill run
    /// happens where that repo and a Linux daemon exist (see plan M4 blocker).
    #[tokio::test]
    async fn m4_backfill_357_docs_all_served() {
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        let idx = state.retrieval_index.clone();

        // Simulate the MediaCrux `articles` table: unique per-doc token so each
        // is individually retrievable.
        let documents: Vec<LocalIngestDocument> = (0..357)
            .map(|i| LocalIngestDocument {
                doc_id: format!("article-{i}"),
                title: Some(format!("Essay {i}")),
                url: Some(format!("https://example.substack.com/p/essay-{i}")),
                source_timestamp: Some("2026-01-01T00:00:00Z".to_string()),
                chunks: vec![chunk(
                    &format!("article-{i}::0"),
                    &format!("newsletter essay body number articletoken{i} shared corpus prose"),
                )],
            })
            .collect();
        let body = LocalIngestBody {
            tenant_id: "mediacrux".to_string(),
            corpus_id: "mediacrux-archive".to_string(),
            documents,
            semantic_profile: None,
        };

        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let guard = idx.read().await;
        assert_eq!(guard.total_docs(), 357, "all 357 articles must be indexed");
        let readers = guard.readers();
        let th = Some(tenant_hash("mediacrux"));
        let p = Bm25Params::default();
        // Spot-check a few individual articles are retrievable by their token.
        for i in [0usize, 42, 200, 356] {
            let hits = bm25_search(&readers, &format!("articletoken{i}"), 10, th, &p, None, None).hits;
            assert_eq!(hits.len(), 1, "article {i} must be BM25-served");
        }
    }

    /// M5 (T.4): a successful ingest returns a non-null `receipt_id` and writes a
    /// timeline row discoverable via the console chunk index.
    #[tokio::test]
    async fn m5_receipt_and_timeline_emitted() {
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        let data_dir = state.data_dir.clone();

        let body = body_with(
            "tenant-t4",
            "mediacrux-archive",
            &[("a1", "auditable receipt and timeline row")],
        );
        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Receipt present in the response body.
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            json["receipt_id"].as_str().is_some_and(|s| !s.is_empty()),
            "receipt_id must be present"
        );
        assert_eq!(json["sealed"], serde_json::json!(true));

        // Timeline row recorded in the console chunk index for this tenant.
        let page = crate::console_index::list_chunks(&data_dir, "tenant-t4", 100, None).unwrap();
        assert!(!page.chunks.is_empty(), "a timeline row must be recorded (T.4)");
    }

    /// buyer-fit M3.2 (Track B): with the node's local embedder wired and NO
    /// client-supplied vectors, ingest embeds every chunk server-side, writes the
    /// `.ccxv` companion, and the prose text-search path dense-re-ranks the query
    /// — all with no external embedding service.
    #[tokio::test]
    #[serial_test::serial]
    async fn m3_server_side_local_embedding_writes_ccxv_and_query_dense_reranks() {
        std::env::remove_var("CORECRUXD_QUERY_TEXT_SEARCH");
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        // Wire the pure-Rust default embedder — the "works offline by default" path.
        state
            .fact_store
            .write()
            .await
            .set_embedder(Box::new(corecrux_memory::embeddings::LocalHashEmbedder::default()));
        let data_dir = state.data_dir.clone();

        // No dense_vector on any chunk → the handler embeds them server-side.
        let body = body_with(
            "tenant-m3",
            "docs",
            &[
                ("d1", "terraform module drift detection for cloud infrastructure"),
                ("d2", "developer onboarding and local setup instructions"),
            ],
        );
        let resp = post_local_ingest(State(state.clone()), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json["dense_vectors"],
            serde_json::json!(2),
            "both chunks embedded server-side"
        );
        assert_eq!(
            json["dense_dim"],
            serde_json::json!(256),
            "local embedder dimension persisted"
        );

        // The `.ccxv` companion landed next to the sealed segment.
        let seg_dir = data_dir.join("shards").join("shard-0000").join("segments");
        let has_ccxv = std::fs::read_dir(&seg_dir)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().ends_with(".ccxv"));
        assert!(has_ccxv, ".ccxv dense companion must be written at ingest");

        // Text-search now dense-re-ranks: the fused score space is reported and
        // the dense lane is active — with no external embedder configured.
        let ts_body = crate::http::query::TextSearchBody {
            tenant_id: "tenant-m3".to_string(),
            query: "terraform infrastructure drift".to_string(),
            limit: 10,
            token_budget: None,
            min_score: None,
            mode: None,
            include_receipt: None,
        };
        let qresp = crate::http::query::post_query_text_search(State(state), HeaderMap::new(), Json(ts_body))
            .await
            .into_response();
        assert_eq!(qresp.status(), StatusCode::OK);
        let qbytes = axum::body::to_bytes(qresp.into_body(), usize::MAX).await.unwrap();
        let qjson: serde_json::Value = serde_json::from_slice(&qbytes).unwrap();
        assert_eq!(
            qjson["meta"]["dense_lane_active"],
            serde_json::json!(true),
            "dense lane active on the offline local path"
        );
        assert_eq!(
            qjson["meta"]["score_space"], "bm25_dense_fused",
            "query reports the fused score space"
        );
        assert!(
            qjson["results"].as_array().is_some_and(|r| !r.is_empty()),
            "dense-reranked query returns results"
        );
    }

    /// A prose ingest with NO embedder wired stays BM25-only: no `.ccxv`, and the
    /// query path leaves the dense lane inert (bit-identical to the prior path).
    #[tokio::test]
    #[serial_test::serial]
    async fn m3_no_embedder_leaves_prose_bm25_only() {
        std::env::remove_var("CORECRUXD_QUERY_TEXT_SEARCH");
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true; // no embedder wired
        let data_dir = state.data_dir.clone();

        let body = body_with("tenant-noemb", "docs", &[("d1", "plain prose without any vectors")]);
        let resp = post_local_ingest(State(state.clone()), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["dense_vectors"], serde_json::json!(0), "no embedder ⇒ no vectors");

        let seg_dir = data_dir.join("shards").join("shard-0000").join("segments");
        let has_ccxv = std::fs::read_dir(&seg_dir)
            .unwrap()
            .flatten()
            .any(|e| e.file_name().to_string_lossy().ends_with(".ccxv"));
        assert!(!has_ccxv, "no .ccxv without an embedder");

        let ts_body = crate::http::query::TextSearchBody {
            tenant_id: "tenant-noemb".to_string(),
            query: "plain prose".to_string(),
            limit: 10,
            token_budget: None,
            min_score: None,
            mode: None,
            include_receipt: None,
        };
        let qresp = crate::http::query::post_query_text_search(State(state), HeaderMap::new(), Json(ts_body))
            .await
            .into_response();
        assert_eq!(qresp.status(), StatusCode::OK);
        let qbytes = axum::body::to_bytes(qresp.into_body(), usize::MAX).await.unwrap();
        let qjson: serde_json::Value = serde_json::from_slice(&qbytes).unwrap();
        assert_eq!(qjson["meta"]["dense_lane_active"], serde_json::json!(false));
        assert_eq!(qjson["meta"]["score_space"], "bm25_lexical");
    }

    /// buyer-fit M3.3: a caller-supplied dense_vector that declares an embedding
    /// profile whose fingerprint differs from the node's is refused (422) — the
    /// refusal is fingerprint-based, not merely dimension-based (dims match here).
    #[tokio::test]
    #[serial_test::serial]
    async fn m3_incompatible_client_vector_fingerprint_refused_422() {
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        // Node embedder: crux-local-hash-v1 @ 256 dims.
        state
            .fact_store
            .write()
            .await
            .set_embedder(Box::new(corecrux_memory::embeddings::LocalHashEmbedder::default()));

        // Client supplies a 256-dim vector (dimension MATCHES the node) but
        // declares a foreign model → different fingerprint → must be refused.
        let body = LocalIngestBody {
            tenant_id: "tenant-fp".to_string(),
            corpus_id: "docs".to_string(),
            documents: vec![LocalIngestDocument {
                doc_id: "d1".to_string(),
                title: None,
                url: None,
                source_timestamp: None,
                chunks: vec![LocalIngestChunk {
                    chunk_id: "d1::0".to_string(),
                    text: "some prose".to_string(),
                    chunk_index: None,
                    dense_vector: Some(vec![0.1_f32; 256]),
                    metadata: None,
                }],
            }],
            semantic_profile: Some(SemanticProfile::from_parts(
                "someone-elses-model",
                256,
                "unknown",
                "none",
                "unknown",
            )),
        };
        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "foreign fingerprint refused"
        );
    }

    /// buyer-fit M3.3: a server-embedded ingest writes the `.ccxp` profile sidecar
    /// recording the node embedder, next to the `.ccxv`.
    #[tokio::test]
    #[serial_test::serial]
    async fn m3_ccxp_profile_sidecar_written_on_server_embed() {
        let mut state = super::super::tests::test_app_state(16);
        state.local_ingest_enabled = true;
        state
            .fact_store
            .write()
            .await
            .set_embedder(Box::new(corecrux_memory::embeddings::LocalHashEmbedder::default()));
        let data_dir = state.data_dir.clone();

        let body = body_with("tenant-ccxp", "docs", &[("d1", "profile sidecar coverage prose")]);
        let resp = post_local_ingest(State(state), HeaderMap::new(), Json(body))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let seg_dir = data_dir.join("shards").join("shard-0000").join("segments");
        let ccxp = std::fs::read_dir(&seg_dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|x| x == "ccxp"))
            .expect(".ccxp sidecar must be written");
        let profile: corecrux_memory::embeddings::SemanticProfile =
            serde_json::from_slice(&std::fs::read(&ccxp).unwrap()).unwrap();
        assert_eq!(profile.model, corecrux_memory::embeddings::LOCAL_HASH_EMBEDDER_MODEL);
        assert_eq!(profile.dimensions, 256);
    }
}
