// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Observability tool handlers: `get_gaps`.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::JsonRpcError;
use corecrux_memory::fact_store::FactQuery;

/// Entity prefix used by the ops observation layer to record coverage gaps.
const OPS_COVERAGE_PREFIX: &str = "__ops__::coverage";

/// `get_gaps` — retrieve known knowledge gaps from the observation layer.
///
/// Queries the fact store for entities prefixed with `__ops__::coverage`. These
/// facts are written by `crux-observe` when it detects coverage holes,
/// unanswered queries, or low-confidence retrieval passes.
pub async fn handle_get_gaps(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let filter = args.get("query").and_then(|v| v.as_str()).map(|s| s.to_string());

    let q = FactQuery {
        query: filter.clone(),
        entity: None,
        entity_prefix: Some(OPS_COVERAGE_PREFIX.to_string()),
        top_k: 50,
        token_budget: None,
    };

    let store = ctx.fact_store.read().await;
    let result = store.query(&q);

    if result.facts.is_empty() {
        let msg = match filter {
            Some(f) => format!("no gaps matching '{f}'"),
            None => "no knowledge gaps recorded".to_string(),
        };
        return Ok(json!({
            "content": [{ "type": "text", "text": msg }]
        }));
    }

    let text = result
        .facts
        .iter()
        .map(|f| format!("[{}] {} = {}", f.entity, f.key, f.value))
        .collect::<Vec<_>>()
        .join("\n");

    Ok(json!({
        "content": [{ "type": "text", "text": text }]
    }))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;
    use corecrux_memory::fact_store::StoreFact;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    #[tokio::test]
    async fn get_gaps_empty() {
        let ctx = test_ctx();
        let result = handle_get_gaps(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no knowledge gaps"));
    }

    #[tokio::test]
    async fn get_gaps_with_filter_empty() {
        let ctx = test_ctx();
        let result = handle_get_gaps(&json!({"query": "terraform"}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no gaps matching 'terraform'"));
    }

    #[tokio::test]
    async fn get_gaps_returns_ops_facts() {
        let ctx = test_ctx();

        // Seed an ops coverage gap fact.
        {
            let mut store = ctx.fact_store.write().await;
            store.store(StoreFact {
                entity: "__ops__::coverage::retrieval".to_string(),
                key: "gap_query".to_string(),
                value: "no results for terraform drift detection".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            });
            // A non-ops fact should not appear.
            store.store(StoreFact {
                entity: "project".to_string(),
                key: "name".to_string(),
                value: "CueCrux".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            });
        }

        let result = handle_get_gaps(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("terraform drift"));
        assert!(!text.contains("CueCrux"));
    }

    #[tokio::test]
    async fn get_gaps_filtered() {
        let ctx = test_ctx();

        {
            let mut store = ctx.fact_store.write().await;
            store.store(StoreFact {
                entity: "__ops__::coverage::retrieval".to_string(),
                key: "gap".to_string(),
                value: "terraform drift missing".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            });
            store.store(StoreFact {
                entity: "__ops__::coverage::retrieval".to_string(),
                key: "gap".to_string(),
                value: "kubernetes scheduling unindexed".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
            });
        }

        let result = handle_get_gaps(&json!({"query": "terraform"}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("terraform"));
        assert!(!text.contains("kubernetes"));
    }
}
