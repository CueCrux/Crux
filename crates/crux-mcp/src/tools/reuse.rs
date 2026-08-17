// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `reuse_check` — the code-minimalism ladder's "does this already exist?"
//! rung as a substrate lookup (minimalism plane M3).
//!
//! The agent describes what it is about to build; the daemon answers with
//! ranked reuse candidates from two sources in one call:
//!
//! 1. the tenant's retrieval index (BM25 over ingested code/docs), and
//! 2. the Features lens (capability entities + their `files` lists).
//!
//! A prompt-only skill can only tell the agent to grep. This tool has the
//! daemon do the looking, so "search before you write" becomes one call with
//! receipts-grade pointers (`result_id`s expandable via `query_expand`).
//!
//! Contract (minimalism plane M3): the response carries a unified ranked
//! `candidates` list `{kind, path, file_line, score, …}`. `file_line` comes
//! from the Features lens half (`files` entries with a `<path>:<line>`
//! suffix); retrieval candidates are pointer-only (`path`/`file_line` null)
//! because the `.ccxi` index stores no path provenance. An optional
//! `token_budget` (QC.2) caps the emitted rows; `tokens_returned` and
//! `budget_truncated` report what the cap did.
//!
//! Flag-gated via `CORECRUXD_FEATURE_REUSE_CHECK` (enabled in production
//! since the 2026-07-24 flag rollout; the env-var default remains OFF).

use serde_json::{json, Value};

use crate::dispatch::{McpContext, CAPABILITY_DENIED};
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use crate::tools::query::{require_str, require_tenant_hash};

use corecrux_memory::EntityQuery;
use corecrux_retrieval::bm25::{self, Bm25Params};
use crux_lens_features::CAPABILITY_KIND;

pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_REUSE_CHECK";

/// Returns true if the reuse-check surface is enabled.
///
/// Default-off (opt-in): an unset env var means disabled. Any value other
/// than `""`/`0`/`false`/`off` (case-insensitive) enables it.
pub fn reuse_check_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off")
        }
        Err(_) => false,
    }
}

fn feature_disabled_error() -> JsonRpcError {
    JsonRpcError {
        code: CAPABILITY_DENIED,
        message: format!("reuse_check disabled (set {FEATURE_FLAG_ENV}=1 to enable; it is off by default)"),
        data: Some(json!({"flag": FEATURE_FLAG_ENV})),
    }
}

pub async fn handle_reuse_check(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    if !reuse_check_enabled() {
        return Err(feature_disabled_error());
    }
    handle_inner(args, ctx).await
}

/// Flag-free core, separated so tests can drive it without process-global
/// env-var races.
async fn handle_inner(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let tenant_hash = require_tenant_hash(args)?;
    let description = require_str(args, "description")?;
    let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(5) as usize;
    let min_score = args.get("min_score").and_then(|v| v.as_f64()).map(|f| f as f32);
    // QC.2: optional token ceiling on the emitted candidate rows. Zero is a
    // client error (an unbudgeted call omits the field instead).
    let token_budget = match args.get("token_budget") {
        None => None,
        Some(v) => match v.as_u64() {
            Some(n) if n > 0 => Some(n),
            _ => {
                return Err(JsonRpcError {
                    code: INVALID_PARAMS,
                    message: "token_budget must be a positive integer".to_string(),
                    data: Some(json!({"param": "token_budget"})),
                })
            }
        },
    };

    // Source 1: the retrieval index (BM25 over whatever this tenant ingested).
    // Pointer contract: the `.ccxi` doc entries carry no path/line provenance
    // (frame_offset + token counts only), so retrieval candidates are honest
    // pointers — `path`/`file_line` are null and the content is one
    // `query_expand` away. `file_line` on this surface comes from the Features
    // lens half below.
    // crux-min: pointer-only retrieval provenance; ceiling = no `file_line` on
    // BM25 candidates. Upgrade trigger: a doc-provenance companion (path +
    // line span per doc) lands in corecrux-index — then join it here.
    let index = ctx.retrieval_index.read().await;
    let retrieval_hits: Vec<Value> = if index.total_docs() == 0 {
        Vec::new()
    } else {
        let readers = index.readers();
        let result = bm25::bm25_search(
            &readers,
            description,
            limit,
            Some(tenant_hash),
            &Bm25Params::default(),
            min_score,
            index.forgotten_watermark(tenant_hash),
        );
        result
            .hits
            .iter()
            .enumerate()
            .map(|(idx, h)| {
                json!({
                    "kind": "retrieval_pointer",
                    "result_id": format!("{}:{}", h.segment_index, h.doc_id),
                    "rank": idx + 1,
                    "score": h.score,
                    "doc_length_tokens": h.doc_length_tokens,
                    "path": Value::Null,
                    "file_line": Value::Null,
                })
            })
            .collect()
    };
    drop(index);

    // Source 2: the Features lens — capability name/description/files overlap.
    // NOTE: capability entities are workspace-global by design (EntityQuery has
    // no tenant dimension; feature_file_search behaves the same), so
    // capability_candidates are NOT tenant-scoped even though the retrieval
    // half above is. The response labels them accordingly.
    let terms = tokenize(description);
    // Score borrowing under the read guard (no awaits inside); deep-clone only
    // the few fields of the survivors.
    let capability_hits: Vec<Value> = {
        let store = ctx.entity_store.read().await;
        let q = EntityQuery {
            kind: Some(CAPABILITY_KIND.into()),
            limit: None,
            include_deleted: false,
        };
        let records = store.list(&q);
        let mut cap_matches: Vec<(usize, &Value)> = records
            .iter()
            .filter_map(|r| {
                let overlap = capability_overlap(&terms, &r.payload);
                (overlap >= MIN_OVERLAP_TERMS).then_some((overlap, &r.payload))
            })
            .collect();
        cap_matches.sort_by(|a, b| b.0.cmp(&a.0));
        cap_matches
            .into_iter()
            .take(limit)
            .map(|(overlap, c)| {
                let (path, file_line) = primary_file_pointer(c.get("files"));
                json!({
                    "kind": "capability",
                    "id": c.get("id"),
                    "name": c.get("name"),
                    "system": c.get("system"),
                    "maturity": c.get("maturity"),
                    "files": c.get("files"),
                    "overlap_terms": overlap,
                    "path": path,
                    "file_line": file_line,
                })
            })
            .collect()
    };

    // Unified ranked list (design contract `{path, file_line?, capability?,
    // kind, score}`): path-bearing capability candidates first (overlap-desc),
    // then retrieval pointers (BM25-desc). The two scorers are not comparable,
    // so ranking is within-source, capability-first.
    let mut candidates: Vec<Value> = capability_hits.iter().chain(retrieval_hits.iter()).cloned().collect();

    // QC.2: enforce the declared token budget on the emitted rows. The first
    // candidate is always admitted (a budget too small for one row still gets
    // an answer, flagged as truncated) — mirrors `query_scan` semantics.
    let mut tokens_returned: u64 = 0;
    let mut budget_truncated = false;
    if let Some(budget) = token_budget {
        let mut kept: Vec<Value> = Vec::new();
        for cand in candidates.drain(..) {
            let row_tokens =
                crate::token_estimate::estimate_tokens_str(&serde_json::to_string(&cand).unwrap_or_default());
            if !kept.is_empty() && tokens_returned + row_tokens > budget {
                budget_truncated = true;
                break;
            }
            tokens_returned += row_tokens;
            kept.push(cand);
        }
        if budget_truncated {
            crate::ledger::record_truncation("reuse_check", "token_budget");
        }
        candidates = kept;
    } else {
        for cand in &candidates {
            tokens_returned +=
                crate::token_estimate::estimate_tokens_str(&serde_json::to_string(cand).unwrap_or_default());
        }
    }

    // Keep the two per-source arrays consistent with the budgeted unified list
    // (a truncated response must not resurrect dropped rows in a legacy field).
    let capability_survivors: Vec<Value> = candidates
        .iter()
        .filter(|c| c.get("kind").and_then(|k| k.as_str()) == Some("capability"))
        .cloned()
        .collect();
    let retrieval_survivors: Vec<Value> = candidates
        .iter()
        .filter(|c| c.get("kind").and_then(|k| k.as_str()) == Some("retrieval_pointer"))
        .cloned()
        .collect();

    let verdict = if candidates.is_empty() {
        "nothing-found"
    } else {
        "reuse-candidate-found"
    };
    let guidance = match verdict {
        "reuse-candidate-found" => {
            "Inspect candidates before writing new code: open capability `file_line`/`path` pointers \
             directly; expand retrieval result_ids via query_expand. Reuse beats reimplementation \
             (code-minimalism rung 2)."
        }
        _ => "No reuse candidates in the index or Features lens. Note: an empty index only proves nothing was ingested — grep the tree before concluding the helper does not exist.",
    };

    let text = serde_json::to_string(&json!({
        "schema": "crux.mcp.reuse_check.v1",
        "verdict": verdict,
        "candidates": candidates,
        "retrieval_candidates": retrieval_survivors,
        "capability_candidates": capability_survivors,
        "capability_scope": "workspace-global",
        "token_budget": token_budget,
        "tokens_returned": tokens_returned,
        "budget_truncated": budget_truncated,
        "guidance": guidance,
    }))
    .unwrap_or_default();
    Ok(json!({ "content": [{ "type": "text", "text": text }] }))
}

/// Extract the primary `(path, file_line)` pointer from a capability's `files`
/// list. A `<path>:<line>` entry (trailing all-digit suffix after the last
/// colon) yields both; the first such entry wins. Otherwise the first plain
/// entry yields `path` with a null `file_line` — a line number is never
/// invented for a path that does not carry one.
fn primary_file_pointer(files: Option<&Value>) -> (Value, Value) {
    let Some(entries) = files.and_then(|f| f.as_array()) else {
        return (Value::Null, Value::Null);
    };
    let mut first_plain: Option<&str> = None;
    for entry in entries.iter().filter_map(|e| e.as_str()) {
        if let Some((path, line)) = split_file_line(entry) {
            return (json!(path), json!(format!("{path}:{line}")));
        }
        if first_plain.is_none() {
            first_plain = Some(entry);
        }
    }
    match first_plain {
        Some(p) => (json!(p), Value::Null),
        None => (Value::Null, Value::Null),
    }
}

/// Split `<path>:<line>` on the last colon when the suffix is a positive
/// integer. Returns `None` for plain paths (no colon, or non-numeric suffix,
/// e.g. Windows drive letters or scoped ids).
fn split_file_line(entry: &str) -> Option<(&str, u32)> {
    let (path, suffix) = entry.rsplit_once(':')?;
    if path.is_empty() {
        return None;
    }
    let line: u32 = suffix.parse().ok().filter(|l| *l > 0)?;
    Some((path, line))
}

/// A capability needs at least this many distinct matching terms to count as
/// a reuse candidate — one shared common word ("for", "add") is noise and
/// must not flip the verdict.
const MIN_OVERLAP_TERMS: usize = 2;

/// Lowercased distinct tokens (>= 3 chars) of a text, split on
/// non-alphanumerics. Whole-token matching, so "add" cannot match "address".
fn tokenize(text: &str) -> std::collections::BTreeSet<String> {
    text.to_ascii_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 3)
        .map(|t| t.to_string())
        .collect()
}

/// Count description terms appearing as whole tokens in the capability's
/// name, description, or file paths.
// crux-min: naive term-overlap scoring; swap for the retrieval stack's scorer
// if capability counts grow past a few hundred or precision complaints appear.
fn capability_overlap(terms: &std::collections::BTreeSet<String>, capability: &Value) -> usize {
    let hay = format!(
        "{} {} {}",
        capability.get("name").and_then(|v| v.as_str()).unwrap_or(""),
        capability.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        capability
            .get("files")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|f| f.as_str()).collect::<Vec<_>>().join(" "))
            .unwrap_or_default()
    );
    let hay_tokens = tokenize(&hay);
    terms.intersection(&hay_tokens).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_defaults_off() {
        assert!(!reuse_check_enabled());
    }

    #[test]
    fn overlap_counts_distinct_whole_tokens_only() {
        let cap = json!({
            "name": "config-hot-reload",
            "description": "Debounced file watcher that reloads configuration",
            "files": ["crates/crux-observe/src/watch.rs"]
        });
        assert_eq!(
            capability_overlap(&tokenize("debounced file watcher for config reload"), &cap),
            5
        );
        assert_eq!(capability_overlap(&tokenize("gpu kernel scheduler"), &cap), 0);
        // Repeated terms count once.
        assert_eq!(capability_overlap(&tokenize("watcher watcher watcher"), &cap), 1);
        // Whole-token boundary: "add" must not match inside "address".
        let addr = json!({"name": "address-book", "description": "Postal address storage", "files": []});
        assert_eq!(capability_overlap(&tokenize("add a user record"), &addr), 0);
    }

    /// Parse the tool's `content[0].text` JSON payload.
    fn payload(out: &Value) -> Value {
        serde_json::from_str(out["content"][0]["text"].as_str().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn empty_stores_yield_nothing_found() {
        let ctx = McpContext::new_default("t");
        let out = handle_inner(
            &json!({"tenant_id": "t", "description": "anything at all", "token_budget": 500}),
            &ctx,
        )
        .await
        .expect("ok");
        let p = payload(&out);
        assert_eq!(p["verdict"], "nothing-found");
        assert!(p["guidance"].as_str().unwrap().contains("grep the tree"));
        assert_eq!(p["candidates"].as_array().unwrap().len(), 0);
        assert_eq!(p["token_budget"], 500);
        assert_eq!(p["tokens_returned"], 0);
        assert_eq!(p["budget_truncated"], false);
    }

    #[tokio::test]
    async fn token_budget_zero_rejected() {
        let ctx = McpContext::new_default("t");
        let err = handle_inner(&json!({"tenant_id": "t", "description": "x", "token_budget": 0}), &ctx)
            .await
            .unwrap_err();
        assert!(err.message.contains("token_budget"));
    }

    #[tokio::test]
    async fn capability_match_yields_candidate() {
        let ctx = McpContext::new_default("t");
        {
            let mut s = ctx.entity_store.write().await;
            s.upsert(
                CAPABILITY_KIND,
                "cap-slugify",
                json!({
                    "id": "cap-slugify",
                    "name": "slugify-helper",
                    "system": "engine",
                    "maturity": "shipped",
                    "description": "Shared slug generation helper with accent folding",
                    "files": ["src/utils/slugify.ts"]
                }),
                "test",
                None,
            )
            .unwrap();
        }
        let out = handle_inner(
            &json!({"tenant_id": "t", "description": "shared slug generation helper"}),
            &ctx,
        )
        .await
        .expect("ok");
        let text = out["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"verdict\":\"reuse-candidate-found\""));
        assert!(text.contains("cap-slugify"));

        // A single shared common term stays below MIN_OVERLAP_TERMS — no
        // candidate, no verdict flip.
        let out = handle_inner(&json!({"tenant_id": "t", "description": "helper for cron jobs"}), &ctx)
            .await
            .expect("ok");
        let text = out["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"verdict\":\"nothing-found\""));
    }

    #[tokio::test]
    async fn tenant_id_is_required() {
        let ctx = McpContext::new_default("t");
        let err = handle_inner(&json!({"description": "x"}), &ctx).await.unwrap_err();
        assert!(err.message.contains("tenant_id"));
    }

    #[test]
    fn split_file_line_accepts_only_positive_line_suffixes() {
        assert_eq!(split_file_line("src/a.rs:12"), Some(("src/a.rs", 12)));
        assert_eq!(split_file_line("src/a.rs"), None);
        assert_eq!(split_file_line("src/a.rs:0"), None);
        assert_eq!(split_file_line("src/a.rs:l2"), None);
        assert_eq!(split_file_line(":12"), None);
        // Only the LAST colon splits, so scoped paths still parse.
        assert_eq!(split_file_line("pkg:src/a.rs:7"), Some(("pkg:src/a.rs", 7)));
    }

    /// Register a matching capability; `files` controls the pointer shape.
    async fn install_capability(ctx: &McpContext, id: &str, files: Value) {
        let mut s = ctx.entity_store.write().await;
        s.upsert(
            CAPABILITY_KIND,
            id,
            json!({
                "id": id,
                "name": "slugify-helper",
                "system": "engine",
                "maturity": "shipped",
                "description": "Shared slug generation helper with accent folding",
                "files": files,
            }),
            "test",
            None,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn capability_file_line_parsed_from_files_entry() {
        let ctx = McpContext::new_default("t");
        install_capability(&ctx, "cap-line", json!(["src/utils/slugify.ts:42"])).await;
        let out = handle_inner(
            &json!({"tenant_id": "t", "description": "shared slug generation helper", "token_budget": 500}),
            &ctx,
        )
        .await
        .expect("ok");
        let p = payload(&out);
        assert_eq!(p["verdict"], "reuse-candidate-found");
        let cand = &p["candidates"][0];
        assert_eq!(cand["kind"], "capability");
        assert_eq!(cand["path"], "src/utils/slugify.ts");
        assert_eq!(cand["file_line"], "src/utils/slugify.ts:42");
        assert_eq!(p["budget_truncated"], false);
        let returned = p["tokens_returned"].as_u64().unwrap();
        assert!(returned > 0 && returned <= 500);
    }

    #[tokio::test]
    async fn plain_path_yields_path_with_null_file_line() {
        let ctx = McpContext::new_default("t");
        install_capability(&ctx, "cap-plain", json!(["src/utils/slugify.ts"])).await;
        let out = handle_inner(
            &json!({"tenant_id": "t", "description": "shared slug generation helper"}),
            &ctx,
        )
        .await
        .expect("ok");
        let cand = payload(&out)["candidates"][0].clone();
        assert_eq!(cand["path"], "src/utils/slugify.ts");
        assert!(cand["file_line"].is_null(), "a line number must never be invented");
    }

    #[tokio::test]
    async fn token_budget_respected_and_truncates() {
        let ctx = McpContext::new_default("t");
        for i in 0..4 {
            install_capability(
                &ctx,
                &format!("cap-{i}"),
                json!([format!("src/helpers/h{i}.rs:{}", i + 1)]),
            )
            .await;
        }
        let args_unbudgeted = json!({"tenant_id": "t", "description": "shared slug generation helper"});
        let all = payload(&handle_inner(&args_unbudgeted, &ctx).await.expect("ok"));
        let cands = all["candidates"].as_array().unwrap();
        assert_eq!(cands.len(), 4);
        assert_eq!(all["budget_truncated"], false);

        // Budget for exactly the first two rows → exactly two survive, and the
        // legacy per-source array stays consistent with the unified list.
        let two_rows: u64 = cands
            .iter()
            .take(2)
            .map(|c| crate::token_estimate::estimate_tokens_str(&serde_json::to_string(c).unwrap()))
            .sum();
        let p = payload(
            &handle_inner(
                &json!({"tenant_id": "t", "description": "shared slug generation helper", "token_budget": two_rows}),
                &ctx,
            )
            .await
            .expect("ok"),
        );
        assert_eq!(p["candidates"].as_array().unwrap().len(), 2);
        assert_eq!(p["capability_candidates"].as_array().unwrap().len(), 2);
        assert_eq!(p["budget_truncated"], true);
        assert!(p["tokens_returned"].as_u64().unwrap() <= two_rows);

        // A budget below one row still answers with the first candidate,
        // honestly flagged as truncated (minimum-one semantics).
        let p = payload(
            &handle_inner(
                &json!({"tenant_id": "t", "description": "shared slug generation helper", "token_budget": 1}),
                &ctx,
            )
            .await
            .expect("ok"),
        );
        assert_eq!(p["candidates"].as_array().unwrap().len(), 1);
        assert_eq!(p["budget_truncated"], true);
    }

    #[tokio::test]
    async fn retrieval_hits_are_pointer_only_and_rank_after_capabilities() {
        use corecrux_index::CcxiBuilder;
        let ctx = McpContext::new_default("t");
        let th = xxhash_rust::xxh64::xxh64(b"t", 0);
        let mut b = CcxiBuilder::new(0, 1, 1);
        b.add_document(0, "shared slug generation helper with accent folding", 0, th);
        let bytes = b.build();
        ctx.retrieval_index.write().await.load_ccxi_bytes(&bytes).unwrap();
        install_capability(&ctx, "cap-slug", json!(["src/utils/slugify.ts:42"])).await;

        let out = handle_inner(
            &json!({"tenant_id": "t", "description": "shared slug generation helper", "token_budget": 2000}),
            &ctx,
        )
        .await
        .expect("ok");
        let p = payload(&out);
        let cands = p["candidates"].as_array().unwrap();
        assert_eq!(cands.len(), 2);
        assert_eq!(cands[0]["kind"], "capability");
        assert_eq!(cands[1]["kind"], "retrieval_pointer");
        assert_eq!(cands[1]["result_id"], "0:0");
        assert!(cands[1]["path"].is_null());
        assert!(cands[1]["file_line"].is_null());
        assert_eq!(p["retrieval_candidates"].as_array().unwrap().len(), 1);
    }
}
