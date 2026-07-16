// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
//! Flag-gated OFF by default via `CORECRUXD_FEATURE_REUSE_CHECK`.

use serde_json::{json, Value};

use crate::dispatch::{McpContext, CAPABILITY_DENIED};
use crate::protocol::JsonRpcError;
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

    // Source 1: the retrieval index (BM25 over whatever this tenant ingested).
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
        );
        result
            .hits
            .iter()
            .enumerate()
            .map(|(idx, h)| {
                json!({
                    "result_id": format!("{}:{}", h.segment_index, h.doc_id),
                    "rank": idx + 1,
                    "score": h.score,
                    "doc_length_tokens": h.doc_length_tokens,
                })
            })
            .collect()
    };
    drop(index);

    // Source 2: the Features lens — capability name/description/files overlap.
    let caps: Vec<Value> = {
        let store = ctx.entity_store.read().await;
        let q = EntityQuery {
            kind: Some(CAPABILITY_KIND.into()),
            limit: None,
            include_deleted: false,
        };
        store.list(&q).into_iter().map(|e| e.payload.clone()).collect()
    };
    let mut cap_matches: Vec<(usize, &Value)> = caps
        .iter()
        .filter_map(|c| {
            let overlap = capability_overlap(description, c);
            (overlap > 0).then_some((overlap, c))
        })
        .collect();
    cap_matches.sort_by(|a, b| b.0.cmp(&a.0));
    let capability_hits: Vec<Value> = cap_matches
        .into_iter()
        .take(limit)
        .map(|(overlap, c)| {
            json!({
                "id": c.get("id"),
                "name": c.get("name"),
                "system": c.get("system"),
                "maturity": c.get("maturity"),
                "files": c.get("files"),
                "overlap_terms": overlap,
            })
        })
        .collect();

    let verdict = if retrieval_hits.is_empty() && capability_hits.is_empty() {
        "nothing-found"
    } else {
        "reuse-candidate-found"
    };
    let guidance = match verdict {
        "reuse-candidate-found" => {
            "Inspect candidates before writing new code: expand retrieval result_ids via query_expand; \
             open capability files directly. Reuse beats reimplementation (code-minimalism rung 2)."
        }
        _ => "No reuse candidates in the index or Features lens. Note: an empty index only proves nothing was ingested — grep the tree before concluding the helper does not exist.",
    };

    let text = serde_json::to_string(&json!({
        "schema": "crux.mcp.reuse_check.v1",
        "verdict": verdict,
        "retrieval_candidates": retrieval_hits,
        "capability_candidates": capability_hits,
        "guidance": guidance,
    }))
    .unwrap_or_default();
    Ok(json!({ "content": [{ "type": "text", "text": text }] }))
}

/// Count description terms (>= 3 chars, lowercased) appearing in the
/// capability's name, description, or file paths.
// crux-min: naive term-overlap scoring; swap for the retrieval stack's scorer
// if capability counts grow past a few hundred or precision complaints appear.
fn capability_overlap(description: &str, capability: &Value) -> usize {
    let hay = format!(
        "{} {} {}",
        capability.get("name").and_then(|v| v.as_str()).unwrap_or(""),
        capability.get("description").and_then(|v| v.as_str()).unwrap_or(""),
        capability
            .get("files")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|f| f.as_str()).collect::<Vec<_>>().join(" "))
            .unwrap_or_default()
    )
    .to_ascii_lowercase();
    let mut seen = std::collections::BTreeSet::new();
    description
        .to_ascii_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() >= 3 && seen.insert((*t).to_string()))
        .filter(|t| hay.contains(*t))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flag_defaults_off() {
        assert!(!reuse_check_enabled());
    }

    #[test]
    fn overlap_counts_distinct_terms_only() {
        let cap = json!({
            "name": "config-hot-reload",
            "description": "Debounced file watcher that reloads configuration",
            "files": ["crates/crux-observe/src/watch.rs"]
        });
        assert_eq!(capability_overlap("debounced file watcher for config reload", &cap), 5);
        assert_eq!(capability_overlap("gpu kernel scheduler", &cap), 0);
        // Repeated terms count once.
        assert_eq!(capability_overlap("watcher watcher watcher", &cap), 1);
    }

    #[tokio::test]
    async fn empty_stores_yield_nothing_found() {
        let ctx = McpContext::new_default("t");
        let out = handle_inner(&json!({"tenant_id": "t", "description": "anything at all"}), &ctx)
            .await
            .expect("ok");
        let text = out["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"verdict\":\"nothing-found\""));
        assert!(text.contains("grep the tree"));
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
            &json!({"tenant_id": "t", "description": "generate a URL slug from a title"}),
            &ctx,
        )
        .await
        .expect("ok");
        let text = out["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"verdict\":\"reuse-candidate-found\""));
        assert!(text.contains("cap-slugify"));
    }

    #[tokio::test]
    async fn tenant_id_is_required() {
        let ctx = McpContext::new_default("t");
        let err = handle_inner(&json!({"description": "x"}), &ctx).await.unwrap_err();
        assert!(err.message.contains("tenant_id"));
    }
}
