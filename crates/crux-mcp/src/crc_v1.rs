// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Crux Response Contract v1 (CRC-v1) — daemon-side negotiated reshapers.
//!
//! Mirrors `CoreCrux/crates/corecruxd/src/crc_v1.rs` for the Crux daemon's MCP
//! tools. CRC-v1 is opt-in per call (`contract: "v1"` arg); absent → the tool's
//! legacy payload, unchanged. `default-on` is the ExecPlan M6 operator gate.
//!
//! The daemon's `query`/`query_scan` already return metadata-only pointers and
//! `query_expand` returns chunk metadata, so these are pure relabelers into the
//! unified envelope (`docs/contracts/crc-v1.schema.json` is the oracle): they
//! add `cost_estimate`, `agent_decision`, `envelope`, and `next` affordances and
//! fold every legacy key under `meta` (nothing is dropped).

use serde_json::{json, Map, Value};

/// True when the caller negotiated CRC-v1 via a `contract` tool arg
/// (`"v1"`/`"crc-v1"`). Session-level negotiation (`cuecrux_session`) is a
/// follow-up (M4); absent → false → legacy payload.
pub fn requested(params: &Value) -> bool {
    params
        .get("contract")
        .and_then(|v| v.as_str())
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "v1" || v == "crc-v1"
        })
        .unwrap_or(false)
}

fn shared_envelope() -> Value {
    json!({
        "freshness": Value::Null,
        "receipts_used": [],
        "memories_used": [],
        "autonomy_consumed": {"capability": "retrieve:read", "cost_credits": 0, "scope": "agent"},
        "links": {}
    })
}

/// Build a pointer from a daemon hit object (`result_id` or `segment_index`+`doc_id`).
fn hit_to_pointer(h: &Value) -> Option<Value> {
    let id = h
        .get("result_id")
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .or_else(|| {
            let seg = h.get("segment_index").and_then(Value::as_u64)?;
            let doc = h.get("doc_id").and_then(Value::as_u64)?;
            Some(format!("{seg}:{doc}"))
        })?;
    let mut p = Map::new();
    p.insert("id".into(), Value::String(id));
    p.insert("score".into(), h.get("score").cloned().unwrap_or(Value::Null));
    Some(Value::Object(p))
}

/// Sum `doc_length_tokens`/`token_count` across hits → the `full` cost tier.
fn full_cost(hits: &[Value]) -> u64 {
    hits.iter()
        .filter_map(|h| {
            h.get("doc_length_tokens")
                .or_else(|| h.get("token_count"))
                .and_then(Value::as_u64)
        })
        .sum()
}

fn search_envelope(kind: &str, hits: Vec<Value>, mut meta: Map<String, Value>, next_expand: Value) -> Value {
    let pointers: Vec<Value> = hits.iter().filter_map(hit_to_pointer).collect();
    let n = pointers.len() as u64;
    let cost = json!({
        "pointer": n.saturating_mul(40),
        "summary": n.saturating_mul(150),
        "full": full_cost(&hits),
    });
    // The daemon's BM25+graph search is lexical; agent_decision is honest-minimal.
    let agent_decision = if kind == "search" {
        json!({
            "load_bearing_lane": "Bm25",
            "fused_confidence": Value::Null,
            "suggested_next_lane": "None",
            "lane_attribution": {"bm25": {"share": 1.0, "confidence": Value::Null}},
            "read_pointers": []
        })
    } else {
        Value::Null
    };
    meta.entry("score_space".to_string()).or_insert(json!("bm25_lexical"));
    let mut out = Map::new();
    out.insert("contract".into(), json!("crc-v1"));
    out.insert("kind".into(), json!(kind));
    out.insert("hydrate_tier".into(), json!("pointer")); // daemon tools are metadata-only
    out.insert("pointers".into(), Value::Array(pointers));
    out.insert("cost_estimate".into(), cost);
    out.insert("agent_decision".into(), agent_decision);
    out.insert("envelope".into(), shared_envelope());
    out.insert(
        "next".into(),
        json!({"expand": next_expand, "resolution_pointer": Value::Null}),
    );
    out.insert("meta".into(), Value::Object(meta));
    Value::Object(out)
}

/// Reshape a `query` inner payload (`{results, coverage, total_candidates, meta}`)
/// into CRC-v1 `kind:"search"`.
pub fn wrap_query(inner: Value) -> Value {
    let mut src = match inner {
        Value::Object(m) => m,
        other => return other,
    };
    let hits = match src.remove("results") {
        Some(Value::Array(a)) => a,
        _ => Vec::new(),
    };
    let mut meta = match src.remove("meta") {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    };
    for (k, v) in src.into_iter() {
        meta.entry(k).or_insert(v); // coverage, total_candidates, … preserved
    }
    search_envelope(
        "search",
        hits,
        meta,
        json!("query_expand {result_ids:[\"<seg>:<doc>\"...]}"),
    )
}

/// Reshape a `query_scan` inner payload (`{scan, total_candidates, meta}`) into
/// CRC-v1 `kind:"search"`.
pub fn wrap_scan(inner: Value) -> Value {
    let mut src = match inner {
        Value::Object(m) => m,
        other => return other,
    };
    let hits = match src.remove("scan") {
        Some(Value::Array(a)) => a,
        _ => Vec::new(),
    };
    let mut meta = match src.remove("meta") {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    };
    for (k, v) in src.into_iter() {
        meta.entry(k).or_insert(v);
    }
    search_envelope(
        "search",
        hits,
        meta,
        json!("query_expand {result_ids:[\"<seg>:<doc>\"...]}"),
    )
}

/// Reshape a `query_expand` inner payload (`{chunks, tokens_loaded, meta, errors?}`)
/// into CRC-v1 `kind:"addressed"` (content-pointer hydration; agent_decision null).
pub fn wrap_expand(inner: Value) -> Value {
    let mut src = match inner {
        Value::Object(m) => m,
        other => return other,
    };
    let hits = match src.remove("chunks") {
        Some(Value::Array(a)) => a,
        _ => Vec::new(),
    };
    let mut meta = match src.remove("meta") {
        Some(Value::Object(m)) => m,
        _ => Map::new(),
    };
    for (k, v) in src.into_iter() {
        meta.entry(k).or_insert(v); // tokens_loaded, errors, … preserved
    }
    search_envelope("addressed", hits, meta, Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requested_reads_contract_arg() {
        assert!(requested(&json!({"contract": "v1"})));
        assert!(requested(&json!({"contract": "crc-v1"})));
        assert!(requested(&json!({"contract": "V1"})));
        assert!(!requested(&json!({})));
        assert!(!requested(&json!({"contract": "legacy"})));
    }

    #[test]
    fn wrap_query_is_search_with_pointers() {
        let inner = json!({
            "results": [
                {"result_id": "3:8801", "rank": 1, "score": 12.4, "doc_length_tokens": 100},
                {"result_id": "7:2140", "rank": 2, "score": 9.1, "doc_length_tokens": 50}
            ],
            "total_candidates": 2,
            "coverage": {"score": 0.9},
            "meta": {"score_space": "bm25_lexical"}
        });
        let out = wrap_query(inner);
        assert_eq!(out["contract"], "crc-v1");
        assert_eq!(out["kind"], "search");
        assert_eq!(out["hydrate_tier"], "pointer");
        assert_eq!(out["pointers"].as_array().unwrap().len(), 2);
        assert_eq!(out["pointers"][0]["id"], "3:8801");
        assert_eq!(out["cost_estimate"]["full"], 150); // 100 + 50
        assert!(!out["agent_decision"].is_null());
        // nothing lost: coverage + total_candidates folded into meta
        assert!(out["meta"].get("coverage").is_some());
        assert!(out["meta"].get("total_candidates").is_some());
        // INV-1: pointer tier → no content key
        assert!(out.get("content").is_none());
    }

    #[test]
    fn wrap_expand_is_addressed_null_decision() {
        let inner = json!({
            "chunks": [{"segment_index": 3, "doc_id": 8801, "token_count": 80}],
            "tokens_loaded": 80,
            "meta": {}
        });
        let out = wrap_expand(inner);
        assert_eq!(out["kind"], "addressed");
        assert!(out["agent_decision"].is_null());
        assert_eq!(out["pointers"][0]["id"], "3:8801");
        assert_eq!(out["meta"]["tokens_loaded"], 80);
    }

    #[test]
    fn non_object_passes_through() {
        let v = json!("index is empty");
        assert_eq!(wrap_query(v.clone()), v);
    }
}
