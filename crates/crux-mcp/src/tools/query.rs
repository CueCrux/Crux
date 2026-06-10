// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Retrieval tool handlers: `query`, `query_scan`, `query_expand`.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};

use corecrux_memory::semantic::{MIXED_PROFILE_MERGE_RULE, SCORE_MERGE_RULE_SINGLE_SPACE, SCORE_SPACE_BM25_LEXICAL};
use corecrux_retrieval::bm25::{self, Bm25Params};

/// `query` — BM25 + graph fusion search with optional token budget and min_score.
pub async fn handle_query(params: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let tenant_hash = require_tenant_hash(params)?;
    let query = require_str(params, "query")?;
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let min_score = params.get("min_score").and_then(|v| v.as_f64()).map(|f| f as f32);
    let token_budget = params.get("token_budget").and_then(|v| v.as_u64()).map(|v| v as usize);
    let semantic_profile = ctx.fact_store.read().await.semantic_profile();
    let local_semantic_profile_id = semantic_profile.as_ref().map(|profile| profile.profile_id.clone());
    let embedding_fingerprint = semantic_profile
        .as_ref()
        .map(|profile| profile.embedding_fingerprint.clone());

    let index = ctx.retrieval_index.read().await;
    if index.total_docs() == 0 {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": "index is empty — ingest data first"
            }]
        }));
    }

    let readers = index.readers();
    let result = bm25::bm25_search(
        &readers,
        query,
        limit,
        Some(tenant_hash),
        &Bm25Params::default(),
        min_score,
    );

    // Apply token budget: trim results if cumulative doc tokens exceed budget.
    let hits = if let Some(budget) = token_budget {
        let mut cumulative = 0usize;
        result
            .hits
            .into_iter()
            .take_while(|h| {
                cumulative += h.doc_length_tokens as usize;
                cumulative <= budget
            })
            .collect::<Vec<_>>()
    } else {
        result.hits
    };

    let results_json: Vec<Value> = hits
        .iter()
        .enumerate()
        .map(|(idx, h)| {
            json!({
                "result_id": format!("{}:{}", h.segment_index, h.doc_id),
                "rank": idx + 1,
                "score": h.score,
                "source_label": "local_tenant_index",
                "score_space": SCORE_SPACE_BM25_LEXICAL,
                "semantic_profile_id": null,
                "local_semantic_profile_id": local_semantic_profile_id.clone(),
                "segment_index": h.segment_index,
                "doc_id": h.doc_id,
                "doc_length_tokens": h.doc_length_tokens,
            })
        })
        .collect();

    let mut inner = json!({
        "results": results_json,
        "total_candidates": result.total_candidates,
        "coverage": {
            "score": result.coverage.score,
            "missing_tokens": result.coverage.missing_tokens,
            "below_floor": result.coverage.below_floor,
        },
        "meta": {
            "source_label": "local_tenant_index",
            "score_space": SCORE_SPACE_BM25_LEXICAL,
            "score_merge_rule": SCORE_MERGE_RULE_SINGLE_SPACE,
            "mixed_profile_merge_rule": MIXED_PROFILE_MERGE_RULE,
            "semantic_profile_id": null,
            "local_semantic_profile_id": local_semantic_profile_id.clone(),
            "local_semantic_profile": semantic_profile.clone(),
            "embedding_fingerprint": embedding_fingerprint.clone(),
        }
    });
    // CRC-v1: reshape into the pointer-first envelope when negotiated; absent →
    // legacy payload unchanged.
    if crate::crc_v1::enabled(params) {
        inner = crate::crc_v1::wrap_query(inner);
    }
    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&inner).unwrap_or_default()
        }]
    }))
}

/// `query_scan` — metadata-only scan (no full content).
pub async fn handle_query_scan(params: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let tenant_hash = require_tenant_hash(params)?;
    let query = require_str(params, "query")?;
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    let semantic_profile = ctx.fact_store.read().await.semantic_profile();
    let local_semantic_profile_id = semantic_profile.as_ref().map(|profile| profile.profile_id.clone());
    let embedding_fingerprint = semantic_profile
        .as_ref()
        .map(|profile| profile.embedding_fingerprint.clone());

    let index = ctx.retrieval_index.read().await;
    if index.total_docs() == 0 {
        return Ok(json!({
            "content": [{ "type": "text", "text": "index is empty" }]
        }));
    }

    let readers = index.readers();
    let result = bm25::bm25_search(&readers, query, limit, Some(tenant_hash), &Bm25Params::default(), None);

    let scan: Vec<Value> = result
        .hits
        .iter()
        .enumerate()
        .map(|(idx, h)| {
            json!({
                "result_id": format!("{}:{}", h.segment_index, h.doc_id),
                "rank": idx + 1,
                "score": h.score,
                "source_label": "local_tenant_index",
                "score_space": SCORE_SPACE_BM25_LEXICAL,
                "semantic_profile_id": null,
                "local_semantic_profile_id": local_semantic_profile_id.clone(),
                "segment_index": h.segment_index,
                "doc_id": h.doc_id,
                "doc_length_tokens": h.doc_length_tokens,
            })
        })
        .collect();

    let mut inner = json!({
        "scan": scan,
        "total_candidates": result.total_candidates,
        "meta": {
            "source_label": "local_tenant_index",
            "score_space": SCORE_SPACE_BM25_LEXICAL,
            "score_merge_rule": SCORE_MERGE_RULE_SINGLE_SPACE,
            "mixed_profile_merge_rule": MIXED_PROFILE_MERGE_RULE,
            "semantic_profile_id": null,
            "local_semantic_profile_id": local_semantic_profile_id.clone(),
            "local_semantic_profile": semantic_profile.clone(),
            "embedding_fingerprint": embedding_fingerprint.clone(),
        }
    });
    if crate::crc_v1::enabled(params) {
        inner = crate::crc_v1::wrap_scan(inner);
    }
    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&inner).unwrap_or_default()
        }]
    }))
}

/// `query_expand` — expand previously retrieved results by segment:doc_id.
///
/// The response matches the HTTP endpoint (`POST /v1/query/text-search/expand`):
/// each expanded result is returned as a chunk with `segment_index`, `doc_id`,
/// `frame_offset`, and `token_count`, plus a `tokens_loaded` total.
pub async fn handle_query_expand(params: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let tenant_hash = require_tenant_hash(params)?;
    let result_ids = params
        .get("result_ids")
        .and_then(|v| v.as_array())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "missing required param: result_ids".to_string(),
            data: Some(json!({"param": "result_ids", "required": true})),
        })?;
    let semantic_profile = ctx.fact_store.read().await.semantic_profile();
    let local_semantic_profile_id = semantic_profile.as_ref().map(|profile| profile.profile_id.clone());
    let embedding_fingerprint = semantic_profile
        .as_ref()
        .map(|profile| profile.embedding_fingerprint.clone());

    let index = ctx.retrieval_index.read().await;
    let readers = index.readers();

    let mut tokens_loaded: usize = 0;
    let mut chunks: Vec<Value> = Vec::new();
    let mut errors: Vec<Value> = Vec::new();

    for rid in result_ids {
        let id_str = rid.as_str().unwrap_or_default();
        let parts: Vec<&str> = id_str.split(':').collect();
        if parts.len() != 2 {
            errors.push(json!({ "result_id": id_str, "error": "invalid result_id format" }));
            continue;
        }

        let seg_idx: usize = parts[0].parse().unwrap_or(usize::MAX);
        let doc_id: usize = parts[1].parse().unwrap_or(usize::MAX);

        if seg_idx >= readers.len() {
            errors.push(json!({ "result_id": id_str, "error": "segment not found" }));
            continue;
        }

        let reader = readers[seg_idx];
        if doc_id >= reader.docs.len() {
            errors.push(json!({ "result_id": id_str, "error": "doc_id out of range" }));
            continue;
        }

        let doc = &reader.docs[doc_id];
        if doc.tenant_hash_full != tenant_hash {
            errors.push(json!({ "result_id": id_str, "error": "tenant mismatch" }));
            continue;
        }
        tokens_loaded += doc.doc_length_tokens as usize;

        chunks.push(json!({
            "segment_index": seg_idx,
            "doc_id": doc_id,
            "source_label": "local_tenant_index",
            "score_space": SCORE_SPACE_BM25_LEXICAL,
            "semantic_profile_id": null,
            "local_semantic_profile_id": local_semantic_profile_id.clone(),
            "frame_offset": doc.frame_offset,
            "token_count": doc.doc_length_tokens,
        }));
    }

    let mut response = json!({
        "chunks": chunks,
        "tokens_loaded": tokens_loaded,
        "meta": {
            "source_label": "local_tenant_index",
            "score_space": SCORE_SPACE_BM25_LEXICAL,
            "semantic_profile_id": null,
            "local_semantic_profile_id": local_semantic_profile_id.clone(),
            "local_semantic_profile": semantic_profile.clone(),
            "embedding_fingerprint": embedding_fingerprint.clone(),
        }
    });

    if !errors.is_empty() {
        response["errors"] = json!(errors);
    }
    // CRC-v1: pointer-first envelope (kind=addressed) when negotiated.
    if crate::crc_v1::enabled(params) {
        response = crate::crc_v1::wrap_expand(response);
    }

    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&response).unwrap_or_default()
        }]
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Extract a required string parameter or return an `INVALID_PARAMS` error.
fn require_str<'a>(params: &'a Value, field: &str) -> Result<&'a str, JsonRpcError> {
    params.get(field).and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing required param: {field}"),
        data: Some(json!({"param": field, "required": true})),
    })
}

fn require_tenant_hash(params: &Value) -> Result<u64, JsonRpcError> {
    let tenant_id = require_str(params, "tenant_id")?.trim();
    if tenant_id.is_empty() || tenant_id == "*" {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "tenant_id must name one concrete tenant".to_string(),
            data: Some(json!({"param": "tenant_id", "required": true, "allow_wildcard": false})),
        });
    }
    Ok(xxhash_rust::xxh64::xxh64(tenant_id.as_bytes(), 0))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    #[tokio::test]
    async fn query_empty_index() {
        let ctx = test_ctx();
        let result = handle_query(&json!({"tenant_id": "t1", "query": "hello"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("empty"));
    }

    #[tokio::test]
    async fn query_missing_tenant() {
        let ctx = test_ctx();
        let err = handle_query(&json!({"query": "hello"}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn query_rejects_empty_or_wildcard_tenant() {
        let ctx = test_ctx();
        let empty = handle_query(&json!({"tenant_id": "", "query": "hello"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(empty.code, INVALID_PARAMS);

        let wildcard = handle_query(&json!({"tenant_id": "*", "query": "hello"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(wildcard.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn query_missing_query() {
        let ctx = test_ctx();
        let err = handle_query(&json!({"tenant_id": "t1"}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn query_scan_empty_index() {
        let ctx = test_ctx();
        let result = handle_query_scan(&json!({"tenant_id": "t1", "query": "hello"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("empty"));
    }

    #[tokio::test]
    async fn query_expand_missing_result_ids() {
        let ctx = test_ctx();
        let err = handle_query_expand(&json!({"tenant_id": "t1"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn query_expand_invalid_id_format() {
        let ctx = test_ctx();
        let result = handle_query_expand(
            &json!({"tenant_id": "t1", "result_ids": ["bad_format"], "contract": "legacy"}),
            &ctx,
        )
        .await
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("invalid result_id"));
        // Verify the new response shape: chunks + tokens_loaded + errors
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert!(parsed.get("chunks").is_some());
        assert_eq!(parsed["tokens_loaded"], 0);
        assert!(parsed["errors"].as_array().unwrap().len() == 1);
    }

    #[tokio::test]
    async fn query_expand_response_matches_http_shape() {
        let ctx = test_ctx();
        // With an empty index, valid IDs will produce segment-not-found errors.
        let result = handle_query_expand(
            &json!({"tenant_id": "t1", "result_ids": ["0:0", "1:5"], "contract": "legacy"}),
            &ctx,
        )
        .await
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert!(parsed.get("chunks").is_some());
        assert!(parsed.get("tokens_loaded").is_some());
        assert_eq!(parsed["meta"]["score_space"], SCORE_SPACE_BM25_LEXICAL);
        assert!(parsed["meta"]["semantic_profile_id"].is_null());
    }

    #[tokio::test]
    async fn query_missing_tenant_has_structured_data() {
        let ctx = test_ctx();
        let err = handle_query(&json!({"query": "hello"}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        let data = err.data.unwrap();
        assert_eq!(data["param"], "tenant_id");
        assert_eq!(data["required"], true);
    }

    #[tokio::test]
    async fn query_expand_missing_result_ids_has_structured_data() {
        let ctx = test_ctx();
        let err = handle_query_expand(&json!({"tenant_id": "t1"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        let data = err.data.unwrap();
        assert_eq!(data["param"], "result_ids");
        assert_eq!(data["required"], true);
    }
}
