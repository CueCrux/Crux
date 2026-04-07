// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Retrieval tool handlers: `query`, `query_scan`, `query_expand`.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};

use corecrux_retrieval::bm25::{self, Bm25Params};

/// `query` — BM25 + graph fusion search with optional token budget and min_score.
pub async fn handle_query(params: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let _tenant_id = require_str(params, "tenant_id")?;
    let query = require_str(params, "query")?;
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let min_score = params.get("min_score").and_then(|v| v.as_f64()).map(|f| f as f32);
    let token_budget = params.get("token_budget").and_then(|v| v.as_u64()).map(|v| v as usize);

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
        None, // tenant hash filter deferred
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
        .map(|h| {
            json!({
                "result_id": format!("{}:{}", h.segment_index, h.doc_id),
                "score": h.score,
                "segment_index": h.segment_index,
                "doc_id": h.doc_id,
                "doc_length_tokens": h.doc_length_tokens,
            })
        })
        .collect();

    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&json!({
                "results": results_json,
                "total_candidates": result.total_candidates,
                "coverage": {
                    "score": result.coverage.score,
                    "missing_tokens": result.coverage.missing_tokens,
                    "below_floor": result.coverage.below_floor,
                }
            })).unwrap_or_default()
        }]
    }))
}

/// `query_scan` — metadata-only scan (no full content).
pub async fn handle_query_scan(params: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let _tenant_id = require_str(params, "tenant_id")?;
    let query = require_str(params, "query")?;
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;

    let index = ctx.retrieval_index.read().await;
    if index.total_docs() == 0 {
        return Ok(json!({
            "content": [{ "type": "text", "text": "index is empty" }]
        }));
    }

    let readers = index.readers();
    let result = bm25::bm25_search(&readers, query, limit, None, &Bm25Params::default(), None);

    let scan: Vec<Value> = result
        .hits
        .iter()
        .map(|h| {
            json!({
                "result_id": format!("{}:{}", h.segment_index, h.doc_id),
                "score": h.score,
                "segment_index": h.segment_index,
                "doc_id": h.doc_id,
                "doc_length_tokens": h.doc_length_tokens,
            })
        })
        .collect();

    Ok(json!({
        "content": [{
            "type": "text",
            "text": serde_json::to_string_pretty(&json!({
                "scan": scan,
                "total_candidates": result.total_candidates,
            })).unwrap_or_default()
        }]
    }))
}

/// `query_expand` — expand previously retrieved results by segment:doc_id.
///
/// The response matches the HTTP endpoint (`POST /v1/query/text-search/expand`):
/// each expanded result is returned as a chunk with `segment_index`, `doc_id`,
/// `frame_offset`, and `token_count`, plus a `tokens_loaded` total.
pub async fn handle_query_expand(params: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let _tenant_id = require_str(params, "tenant_id")?;
    let result_ids = params
        .get("result_ids")
        .and_then(|v| v.as_array())
        .ok_or_else(|| JsonRpcError {
            code: INVALID_PARAMS,
            message: "missing required param: result_ids".to_string(),
            data: Some(json!({"param": "result_ids", "required": true})),
        })?;

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
        tokens_loaded += doc.doc_length_tokens as usize;

        chunks.push(json!({
            "segment_index": seg_idx,
            "doc_id": doc_id,
            "frame_offset": doc.frame_offset,
            "token_count": doc.doc_length_tokens,
        }));
    }

    let mut response = json!({
        "chunks": chunks,
        "tokens_loaded": tokens_loaded,
    });

    if !errors.is_empty() {
        response["errors"] = json!(errors);
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

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
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
        let result = handle_query_expand(&json!({"tenant_id": "t1", "result_ids": ["bad_format"]}), &ctx)
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
        let result = handle_query_expand(&json!({"tenant_id": "t1", "result_ids": ["0:0", "1:5"]}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert!(parsed.get("chunks").is_some());
        assert!(parsed.get("tokens_loaded").is_some());
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
