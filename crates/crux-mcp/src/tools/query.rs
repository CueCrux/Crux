// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
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

    // Apply token budget. M1 reversible overflow (unconditional since CO-5): the
    // response is pointer-only, so budget the *emitted* pointer tier — admit
    // `budget / POINTER_TOKENS` hits — instead of charging the *full-doc*
    // hydration cost and dropping the overflow. Far more candidates fit the same
    // budget (the full price stays in `cost_estimate.full`; `total_candidates`
    // discloses any capped remainder; expand via `result_id`).
    // CO-4 live holdout: a sampled fraction of requests run UNSHAPED (control) so
    // savings are measured against a live control. When unshaped, fall back to the
    // legacy `take_while`-drop + pretty serialization. No-op (always shaped) when
    // CRUX_OUTPUT_HOLDOUT is 0 (the default).
    let unshaped = crate::holdout::request_is_control(&params.to_string());
    let reversible = !unshaped;
    let hits = match token_budget {
        Some(budget) if reversible => {
            let max_pointers = crate::budget::pointers_within_budget(budget);
            result.hits.into_iter().take(max_pointers).collect::<Vec<_>>()
        }
        Some(budget) => {
            let mut cumulative = 0usize;
            result
                .hits
                .into_iter()
                .take_while(|h| {
                    cumulative += h.doc_length_tokens as usize;
                    cumulative <= budget
                })
                .collect::<Vec<_>>()
        }
        None => result.hits,
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
    // M3: minified unconditionally (since CO-5). CO-4 holdout: the unshaped
    // control arm forces pretty so it pays the full (unshaped) cost.
    let compact = !unshaped;
    let text = crate::payload::serialize_with(&inner, compact);
    crate::holdout::record_sample(unshaped, crate::token_estimate::estimate_tokens_str(&text));
    crate::holdout::sample_compaction(&params.to_string(), &inner); // CO-5 compaction-only
    Ok(json!({ "content": [{ "type": "text", "text": text }] }))
}

/// `query_scan` — metadata-only scan (no full content).
pub async fn handle_query_scan(params: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let tenant_hash = require_tenant_hash(params)?;
    let query = require_str(params, "query")?;
    let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    // buyer-fit M4: mandatory-when-set token_budget caps the returned scan by
    // cumulative doc tokens (honest, bounded cost), mirroring `query`.
    let token_budget = params.get("token_budget").and_then(|v| v.as_u64()).map(|v| v as usize);
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

    let mut tokens_returned = 0usize;
    let mut budget_truncated = false;
    let mut scan: Vec<Value> = Vec::new();
    for (idx, h) in result.hits.iter().enumerate() {
        let doc_tokens = h.doc_length_tokens as usize;
        if let Some(budget) = token_budget {
            // Always return at least one hit; then stop before exceeding budget.
            if !scan.is_empty() && tokens_returned + doc_tokens > budget {
                budget_truncated = true;
                break;
            }
        }
        tokens_returned += doc_tokens;
        scan.push(json!({
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
        }));
    }

    let mut inner = json!({
        "scan": scan,
        "total_candidates": result.total_candidates,
        "tokens_returned": tokens_returned,
        "budget_truncated": budget_truncated,
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
    // CO-4 live holdout: unshaped control arm forces pretty; record the cost.
    let unshaped = crate::holdout::request_is_control(&params.to_string());
    let compact = !unshaped;
    let text = crate::payload::serialize_with(&inner, compact);
    crate::holdout::record_sample(unshaped, crate::token_estimate::estimate_tokens_str(&text));
    crate::holdout::sample_compaction(&params.to_string(), &inner); // CO-5 compaction-only
    Ok(json!({ "content": [{ "type": "text", "text": text }] }))
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
            errors.push(
                json!({ "result_id": id_str, "error": "invalid result_id format", "error_kind": "invalid_format" }),
            );
            continue;
        }

        let seg_idx: usize = parts[0].parse().unwrap_or(usize::MAX);
        let doc_id: usize = parts[1].parse().unwrap_or(usize::MAX);

        // T.2: a handle whose segment is gone (forgotten / re-paved / not yet
        // loaded) is `evicted` — the agent must re-query, not retry. Typed so a
        // client distinguishes a stale handle from a malformed one.
        if seg_idx >= readers.len() {
            errors.push(json!({ "result_id": id_str, "error": "segment not found", "error_kind": "evicted" }));
            continue;
        }

        let reader = readers[seg_idx];
        if doc_id >= reader.docs.len() {
            errors.push(json!({ "result_id": id_str, "error": "doc_id out of range", "error_kind": "evicted" }));
            continue;
        }

        let doc = &reader.docs[doc_id];
        if doc.tenant_hash_full != tenant_hash {
            errors.push(json!({ "result_id": id_str, "error": "tenant mismatch", "error_kind": "tenant_mismatch" }));
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

    // CO-4 live holdout: unshaped control arm forces pretty; record the cost.
    let unshaped = crate::holdout::request_is_control(&params.to_string());
    let compact = !unshaped;
    let text = crate::payload::serialize_with(&response, compact);
    crate::holdout::record_sample(unshaped, crate::token_estimate::estimate_tokens_str(&text));
    crate::holdout::sample_compaction(&params.to_string(), &response); // CO-5 compaction-only
    Ok(json!({ "content": [{ "type": "text", "text": text }] }))
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

    // ── M1: reversible overflow (unconditional since CO-5) ────────────────────

    /// Seed an index with `n` docs of varied length, all matching "alpha".
    async fn seed_alpha_index(ctx: &McpContext, tenant: &str, n: u32) {
        use corecrux_index::CcxiBuilder;
        let th = xxhash_rust::xxh64::xxh64(tenant.as_bytes(), 0);
        let mut b = CcxiBuilder::new(0, 1, 1);
        for i in 0..n {
            // ~100 tokens each: "alpha" repeated so BM25 returns every doc.
            let text = std::iter::repeat("alpha").take(100).collect::<Vec<_>>().join(" ");
            b.add_document(i, &text, i * 1000, th);
        }
        let bytes = b.build();
        ctx.retrieval_index.write().await.load_ccxi_bytes(&bytes).unwrap();
    }

    fn pointer_count(resp: &serde_json::Value) -> usize {
        let text = resp["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        // CRC-v1 default → pointers[]; count them.
        parsed["pointers"].as_array().map(Vec::len).unwrap_or(0)
    }

    /// The headline parity: the unshaped (holdout-control) path drops at full-doc
    /// cost; the shaped (default) path budgets the emitted pointer tier and admits
    /// strictly more candidates for the SAME budget — while staying within
    /// `budget / POINTER_TOKENS` pointers (QC.2). Since CO-5 removed the
    /// `CRUX_BUDGET_REVERSIBLE` flag, the shaped/unshaped lever is the holdout
    /// fraction: `=1` ⇒ every request is control (unshaped/legacy), `=0` ⇒ shaped.
    #[tokio::test]
    async fn reversible_admits_more_than_full_doc_drop() {
        let _g = crate::test_env_lock().lock().await;
        let ctx = test_ctx();
        seed_alpha_index(&ctx, "t1", 30).await;
        let budget = 200u64; // 200/40 = 5 pointers when reversible.

        // Unshaped (holdout=1 ⇒ every request is control): legacy take_while over
        // ~100-tok docs → at most 2 fit 200.
        std::env::set_var(crate::holdout::HOLDOUT_ENV, "1");
        let off = handle_query(
            &json!({"tenant_id": "t1", "query": "alpha", "limit": 50, "token_budget": budget}),
            &ctx,
        )
        .await
        .unwrap();
        let off_n = pointer_count(&off);

        // Shaped (holdout=0 ⇒ reversible): pointer-budgeted → exactly 5.
        std::env::set_var(crate::holdout::HOLDOUT_ENV, "0");
        let on = handle_query(
            &json!({"tenant_id": "t1", "query": "alpha", "limit": 50, "token_budget": budget}),
            &ctx,
        )
        .await
        .unwrap();
        let on_n = pointer_count(&on);
        std::env::remove_var(crate::holdout::HOLDOUT_ENV);
        crate::holdout::accumulator().lock().unwrap().clear_for_test();

        assert_eq!(
            on_n,
            crate::budget::pointers_within_budget(budget as usize),
            "ON admits budget/POINTER_TOKENS"
        );
        assert!(on_n > off_n, "reversible recall lift: ON {on_n} !> OFF {off_n}");
        // Disclosure intact: total_candidates still reports the full set.
        let on_text = on["content"][0]["text"].as_str().unwrap();
        let on_parsed: Value = serde_json::from_str(on_text).unwrap();
        assert_eq!(on_parsed["meta"]["total_candidates"], 30);
    }

    /// T.2: an expand handle whose segment is gone returns a typed `evicted`
    /// error (not a malformed/format error) so the caller re-queries.
    #[tokio::test]
    async fn query_expand_evicted_error_kind() {
        let ctx = test_ctx();
        let result = handle_query_expand(
            &json!({"tenant_id": "t1", "result_ids": ["9:9"], "contract": "legacy"}),
            &ctx,
        )
        .await
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed["errors"][0]["error_kind"], "evicted");
    }
}
