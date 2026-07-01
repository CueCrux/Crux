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

/// Accepted counts, computed during validation.
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

    let counts = match validate_payload(&body) {
        Ok(c) => c,
        Err((status, detail)) => return problem_response(status, detail),
    };

    // M1 stub: no write yet. M2 replaces this with the real seal + reload.
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "ingested": counts.chunks,
            "documents": counts.documents,
            "segment_seq": serde_json::Value::Null,
            "receipt_id": serde_json::Value::Null,
            "note": "accepted (M1 stub — write path lands in M2)",
        })),
    )
        .into_response()
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
    async fn flag_on_valid_returns_202_stub() {
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
}
