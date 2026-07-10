// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Crux Response Contract v1 (CRC-v1) — daemon-side negotiated reshapers.
//!
//! Mirrors the CoreCrux daemon's CRC-v1 reshaper for the Crux daemon's MCP
//! tools. CRC-v1 is the DEFAULT; a caller opts out to the legacy payload with
//! `contract: "legacy"` (see [`enabled`]).
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
    params.get("contract").and_then(|v| v.as_str()).is_some_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        v == "v1" || v == "crc-v1"
    })
}

/// CRC-v1 is the **default** for the daemon tools. Returns `true` unless the
/// caller explicitly opts out to the legacy payload with `contract:"legacy"`
/// (also `v0`/`none`/`off`). Absent => CRC-v1. The legacy escape is the door for
/// any consumer that can't yet parse the pointer-first envelope.
pub fn enabled(params: &Value) -> bool {
    !params
        .get("contract")
        .and_then(|v| v.as_str())
        .is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "legacy" | "v0" | "none" | "off"))
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
    for (k, v) in src {
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
    for (k, v) in src {
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
    for (k, v) in src {
        meta.entry(k).or_insert(v); // tokens_loaded, errors, … preserved
    }
    search_envelope("addressed", hits, meta, Value::Null)
}

/// Stringify a fact value for the epitome/content (values are usually short
/// strings; objects are JSON-encoded).
fn value_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Reshape `query_facts` rows into a CRC-v1 `kind:"fact"` envelope. This is the
/// addressed-recall surface: it is NOT routed through the BM25 ranker, it echoes
/// `next.canonical_slug` so the next turn re-addresses by key, and it carries
/// `envelope.freshness` inline (effective_confidence / age / supersession) so a
/// re-verify turn is unnecessary — the agent-query-eval "freshness on addressed
/// recall" win.
///
/// Composition note: the caller keeps the legacy `structuredContent.rows` and
/// nests this under `structuredContent.crc_v1` so the daemon's audit-envelope
/// wrapper (which overwrites `structuredContent.envelope`) does NOT collide.
pub fn wrap_facts(rows: &[Value], entity: Option<&str>, query: Option<&str>) -> Value {
    // No demotion, no cap: every row is hydrated full and nothing is dropped
    // (byte-identical to pre-M1-part-2).
    wrap_facts_tiered(rows, entity, query, rows.len(), rows.len())
}

/// As [`wrap_facts`], but the first `full_count` rows (ranked order) are
/// hydrated **full** (epitome pointer + inline `content`) and the rest are
/// **demoted** to an epitome-only pointer — no inline `content`, a `reason` of
/// `"Demoted"`, and a `content_hash` (OD-A) so the caller can detect staleness
/// when it re-addresses the fact by entity+key. This is M1 part 2's reversible
/// overflow on the fact path: over-budget facts are demoted, not dropped, and
/// the emitted payload pays the epitome price for them, not the full price.
///
/// **M1 part 3 (CO-6) — budget cap.** `rows` is the *already-capped* emitted set
/// (≤ the budget's pointer tier); `total_candidates` is the full ranked-set size
/// before the cap, so `meta` can disclose how many facts were dropped beyond the
/// budget (`capped`) — the agent re-queries (entity+key) for the rest. Callers
/// that don't cap pass `total_candidates == rows.len()`.
///
/// **Byte-identical guarantee:** when `full_count >= rows.len()` AND
/// `total_candidates == rows.len()` there is no demotion or cap — no
/// `content_hash`, no `"Demoted"` reason, `content[]` carries every row,
/// `hydrate_tier` stays `"full"`, and `meta` gains no demotion/cap keys — so the
/// output is identical to the pre-M1-part-2 `wrap_facts`.
pub fn wrap_facts_tiered(
    rows: &[Value],
    entity: Option<&str>,
    query: Option<&str>,
    full_count: usize,
    total_candidates: usize,
) -> Value {
    let mut pointers = Vec::with_capacity(rows.len());
    let mut content = Vec::with_capacity(rows.len());
    let mut memories_used = Vec::with_capacity(rows.len());
    let mut full_cost: u64 = 0;
    let mut demoted: u64 = 0;
    let mut emitted_ix: usize = 0; // index among non-empty-fid rows
    for r in rows {
        let fid = r.get("fact_id").and_then(Value::as_str).unwrap_or("");
        if fid.is_empty() {
            continue;
        }
        let ent = r.get("entity").and_then(Value::as_str).unwrap_or("");
        let key = r.get("key").and_then(Value::as_str).unwrap_or("");
        let val = r.get("value").map(value_str).unwrap_or_default();
        let mut epitome: String = format!("{ent} {key} = {val}");
        if epitome.len() > 80 {
            epitome.truncate(80);
        }
        full_cost += (val.len() / 4) as u64;
        let is_demoted = emitted_ix >= full_count;
        if is_demoted {
            demoted += 1;
            // Epitome-only pointer: no inline content, carry the content hash so
            // a re-address (entity+key) can detect a changed/forgotten value.
            pointers.push(json!({
                "id": fid,
                "score": r.get("effective_confidence").cloned().unwrap_or(Value::Null),
                "epitome": epitome,
                "reason": "Demoted",
                "content_hash": crate::budget::content_hash(&val),
            }));
        } else {
            pointers.push(json!({
                "id": fid,
                "score": r.get("effective_confidence").cloned().unwrap_or(Value::Null),
                "epitome": epitome,
                "reason": "Exact",
            }));
            content.push(json!({"id": fid, "text": val}));
        }
        memories_used.push(json!({
            "fact_id": fid,
            "topic": ent,
            "freshness": r.get("freshness").cloned().unwrap_or(Value::Null),
        }));
        emitted_ix += 1;
    }
    let n = pointers.len() as u64;
    // Freshness summarised from the top (most-relevant / highest-confidence) row;
    // a present-but-null object when there are no rows (INV-4: fact => freshness).
    let top = rows.first();
    let freshness = json!({
        "effective_confidence": top.and_then(|r| r.get("effective_confidence")).cloned().unwrap_or(Value::Null),
        "age_hours": top.and_then(|r| r.get("age_hours")).cloned().unwrap_or(Value::Null),
        "horizon_class": top.and_then(|r| r.get("horizon_class")).cloned().unwrap_or(Value::Null),
        "superseded_by": top.and_then(|r| r.get("superseded_by")).cloned().unwrap_or(Value::Null),
    });
    let canonical_slug = entity.map(|s| s.to_string()).or_else(|| {
        top.and_then(|r| r.get("entity"))
            .and_then(Value::as_str)
            .map(|s| s.to_string())
    });
    let addressed = entity.is_some();

    let mut out = Map::new();
    out.insert("contract".into(), json!("crc-v1"));
    out.insert("kind".into(), json!("fact"));
    // `full` when nothing demoted (byte-identical to pre-M1-part-2); `mixed`
    // once the reversible budget demotes overflow facts to epitome-only.
    out.insert(
        "hydrate_tier".into(),
        json!(if demoted == 0 { "full" } else { "mixed" }),
    );
    out.insert("pointers".into(), Value::Array(pointers));
    out.insert("content".into(), Value::Array(content));
    out.insert(
        "cost_estimate".into(),
        json!({"pointer": n.saturating_mul(40), "summary": n.saturating_mul(150), "full": full_cost}),
    );
    out.insert("agent_decision".into(), Value::Null);
    out.insert(
        "envelope".into(),
        json!({
            "freshness": freshness,
            "receipts_used": [],
            "memories_used": memories_used,
            "autonomy_consumed": {"capability": "facts:read", "cost_credits": 0, "scope": "agent"},
            "links": {"open_in_console": "https://crux.cuecrux.com/console#/facts"}
        }),
    );
    out.insert(
        "next".into(),
        json!({
            "canonical_slug": canonical_slug,
            "resolution_pointer": Value::Null,
            "expand": Value::Null,
        }),
    );
    let mut meta = json!({
        "resolved_by": if addressed { "entity+key" } else { "query" },
        "ranked": query.is_some() && !addressed,
    });
    let total = total_candidates as u64;
    let capped = total.saturating_sub(n); // facts dropped beyond the budget cap
    if demoted > 0 || capped > 0 {
        // Disclosure (additive): how many facts were demoted to epitome-only,
        // how many were dropped beyond the budget cap, and the full candidate
        // count — so nothing is silently lost (re-query entity+key for the rest).
        if let Some(m) = meta.as_object_mut() {
            m.insert("demoted".into(), json!(demoted));
            m.insert("total_candidates".into(), json!(total));
            m.insert("emitted_full".into(), json!(n - demoted));
            if capped > 0 {
                m.insert("capped".into(), json!(capped));
            }
        }
    }
    out.insert("meta".into(), meta);
    Value::Object(out)
}

// ── M4: self-describing schema layer ────────────────────────────────────────

/// Canonical URL of the CRC-v1 schema (the conformance oracle in
/// `docs/contracts/crc-v1.schema.json`).
pub const SCHEMA_URL: &str = "https://cuecrux.com/contracts/crc-v1.schema.json";

/// The CRC-v1 `kind` a tool emits when negotiated, or `None` for tools that
/// stay legacy-only.
fn tool_output_kind(tool: &str) -> Option<&'static str> {
    match tool {
        "query" | "query_scan" => Some("search"),
        "query_expand" => Some("addressed"),
        "query_facts" => Some("fact"),
        _ => None,
    }
}

/// The `x-crux-output-schema` advertisement attached to a tool's `tools/list`
/// entry (MCP has no native `outputSchema`). `None` for non-CRC-v1 tools.
/// Tells a client what shape to expect IF it negotiates `contract:"v1"`.
pub fn output_schema_advert(tool: &str) -> Option<Value> {
    let kind = tool_output_kind(tool)?;
    Some(json!({
        "$ref": SCHEMA_URL,
        "contract": "crc-v1",
        "kind": kind,
        "when": "negotiated via contract:\"v1\"; absent => legacy shape (byte-identical)",
    }))
}

/// Synthesized `__bootstrap__::tool-output:*` entries served by
/// `get_bootstrap("tool-output")` — the self-describing schema layer, computed
/// on demand (no persisted boot-seed required). Each entry is `(entity, key,
/// value)`, matching the shape `get_bootstrap` already renders.
pub fn tool_output_catalogue() -> Vec<(String, String, Value)> {
    let mut out = vec![(
        "__bootstrap__::tool-output:_contract".to_string(),
        "crc-v1".to_string(),
        json!({
            "schema": SCHEMA_URL,
            "negotiate": "contract:\"v1\" arg (MCP) | Accept-Contract: crc-v1 (HTTP)",
            "envelope": "pointers + cost_estimate + agent_decision + envelope{freshness,receipts,links} + next",
            "default_when_negotiated": "hydrate=pointer (cheap); expand via next.expand",
        }),
    )];
    for tool in ["query", "query_scan", "query_expand", "query_facts"] {
        if let Some(kind) = tool_output_kind(tool) {
            out.push((
                format!("__bootstrap__::tool-output:{tool}"),
                tool.to_string(),
                json!({"contract": "crc-v1", "kind": kind, "schema": SCHEMA_URL}),
            ));
        }
    }
    out
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
    fn enabled_defaults_on_and_opts_out_to_legacy() {
        // Default: no contract arg => CRC-v1 enabled.
        assert!(enabled(&json!({})));
        // Explicit crc-v1 or unknown => still enabled (default).
        assert!(enabled(&json!({"contract": "v1"})));
        assert!(enabled(&json!({"contract": "whatever"})));
        // Explicit opt-out to legacy (synonyms, any case).
        assert!(!enabled(&json!({"contract": "legacy"})));
        assert!(!enabled(&json!({"contract": "V0"})));
        assert!(!enabled(&json!({"contract": "none"})));
        assert!(!enabled(&json!({"contract": " off "})));
    }

    #[test]
    fn m4_output_schema_advert_and_catalogue() {
        // Advertised only for CRC-v1 tools; carries the schema ref + kind.
        let adv = output_schema_advert("query_facts").unwrap();
        assert_eq!(adv["kind"], "fact");
        assert_eq!(adv["contract"], "crc-v1");
        assert!(adv["$ref"].as_str().unwrap().ends_with("crc-v1.schema.json"));
        assert_eq!(output_schema_advert("query").unwrap()["kind"], "search");
        assert_eq!(output_schema_advert("query_expand").unwrap()["kind"], "addressed");
        assert!(output_schema_advert("store_fact").is_none());
        // Bootstrap catalogue: a _contract entry + one per CRC-v1 tool.
        let cat = tool_output_catalogue();
        assert!(cat.iter().any(|(e, _, _)| e == "__bootstrap__::tool-output:_contract"));
        assert!(cat
            .iter()
            .any(|(e, _, _)| e == "__bootstrap__::tool-output:query_facts"));
        assert!(cat.iter().all(|(_, _, v)| v.get("schema").is_some()));
    }

    #[test]
    fn wrap_facts_is_fact_kind_with_inline_freshness() {
        let rows = vec![json!({
            "fact_id": "f_abc", "entity": "bench:q500", "key": "baseline",
            "value": "89.3%", "effective_confidence": 1.0, "freshness": "fresh",
            "age_hours": 6, "horizon_class": "medium", "superseded_by": null
        })];
        let out = wrap_facts(&rows, Some("bench:q500"), None);
        assert_eq!(out["kind"], "fact");
        assert!(out["agent_decision"].is_null());
        assert_eq!(out["pointers"][0]["id"], "f_abc");
        assert_eq!(out["pointers"][0]["reason"], "Exact");
        assert_eq!(out["content"][0]["text"], "89.3%");
        // INV-4: kind=fact => envelope.freshness present + canonical_slug echoed
        assert!(!out["envelope"]["freshness"].is_null());
        assert_eq!(out["envelope"]["freshness"]["effective_confidence"], 1.0);
        assert_eq!(out["next"]["canonical_slug"], "bench:q500");
        assert_eq!(out["meta"]["resolved_by"], "entity+key");
        // addressed recall is not ranked
        assert_eq!(out["meta"]["ranked"], false);
    }

    // ---- M1 part 2 — fact-path reversible overflow (tiered demotion) --------

    fn fact_row(id: &str, val: &str) -> Value {
        json!({
            "fact_id": id, "entity": "proj", "key": id, "value": val,
            "effective_confidence": 1.0, "freshness": "fresh",
            "age_hours": 1, "horizon_class": "medium", "superseded_by": null
        })
    }

    #[test]
    fn wrap_facts_no_demotion_is_byte_identical_to_full() {
        // full_count == rows.len() must equal the plain wrap_facts (the OFF net).
        let rows = vec![fact_row("a", "alpha"), fact_row("b", "beta")];
        let full = wrap_facts(&rows, Some("proj"), None);
        let tiered = wrap_facts_tiered(&rows, Some("proj"), None, rows.len(), rows.len());
        assert_eq!(full, tiered);
        // …and neither leaks demotion fields.
        assert_eq!(full["hydrate_tier"], "full");
        assert!(full["pointers"][0].get("content_hash").is_none());
        assert!(full["meta"].get("demoted").is_none());
    }

    #[test]
    fn wrap_facts_tiered_demotes_overflow_to_epitome_only() {
        let rows = vec![fact_row("a", "alpha"), fact_row("b", "beta"), fact_row("c", "gamma")];
        // Keep 1 full, demote the other 2 (all 3 emitted, so total == n, no cap).
        let out = wrap_facts_tiered(&rows, Some("proj"), None, 1, rows.len());
        assert_eq!(out["hydrate_tier"], "mixed");
        // Only the first fact carries inline content.
        assert_eq!(out["content"].as_array().unwrap().len(), 1);
        assert_eq!(out["content"][0]["id"], "a");
        // All three remain as pointers; the demoted ones carry content_hash +
        // reason "Demoted" so nothing is dropped and staleness is detectable.
        assert_eq!(out["pointers"].as_array().unwrap().len(), 3);
        assert_eq!(out["pointers"][0]["reason"], "Exact");
        assert!(out["pointers"][0].get("content_hash").is_none());
        assert_eq!(out["pointers"][1]["reason"], "Demoted");
        assert_eq!(out["pointers"][1]["content_hash"], crate::budget::content_hash("beta"));
        assert_eq!(out["pointers"][2]["reason"], "Demoted");
        // Disclosure: nothing silently lost.
        assert_eq!(out["meta"]["demoted"], 2);
        assert_eq!(out["meta"]["total_candidates"], 3);
        assert_eq!(out["meta"]["emitted_full"], 1);
        assert!(out["meta"].get("capped").is_none(), "nothing dropped beyond the cap");
    }

    #[test]
    fn wrap_facts_tiered_caps_to_budget_and_discloses() {
        // M1 part 3: the emitted set is capped (2 of 5 candidates); meta discloses
        // the 3 dropped beyond the budget so the agent can re-query for them.
        let rows = vec![fact_row("a", "alpha"), fact_row("b", "beta")];
        let out = wrap_facts_tiered(&rows, Some("proj"), None, 1, 5);
        assert_eq!(
            out["pointers"].as_array().unwrap().len(),
            2,
            "only the budgeted tier is emitted"
        );
        assert_eq!(out["meta"]["total_candidates"], 5);
        assert_eq!(out["meta"]["emitted_full"], 1);
        assert_eq!(out["meta"]["demoted"], 1);
        assert_eq!(out["meta"]["capped"], 3, "5 candidates − 2 emitted = 3 dropped");
        assert_eq!(out["hydrate_tier"], "mixed");
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
