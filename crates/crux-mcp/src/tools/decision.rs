// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Decision recording tool: `record_decision`.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use corecrux_memory::fact_store::StoreFact;

/// `record_decision` — record why a decision was made.
///
/// Stores an append-only, BLAKE3-hashed decision record as a fact under the
/// `__decisions::{session_id}` entity. Queryable via `query_facts` with entity
/// prefix `__decisions__::`.
pub async fn handle_record_decision(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    // Required fields
    let action = require_str(args, "action")?;
    let rationale = require_str(args, "rationale")?;

    // Optional fields
    let alternatives: Vec<String> = args
        .get("alternatives")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let confidence = args.get("confidence").and_then(|v| v.as_f64()).unwrap_or(1.0) as f32;
    let session_id = args.get("session_id").and_then(|v| v.as_str()).unwrap_or("_default");
    let context_refs: Vec<String> = args
        .get("context_refs")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    // Build decision record
    let decision_id = format!("d_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
    let record = json!({
        "decision_id": decision_id,
        "action": action,
        "rationale": rationale,
        "alternatives": alternatives,
        "confidence": confidence,
        "session_id": session_id,
        "context_refs": context_refs,
        "recorded_at": chrono::Utc::now().to_rfc3339(),
    });

    // Compute BLAKE3 hash of canonical JSON
    let canonical = serde_json::to_string(&record).unwrap_or_default();
    let decision_hash = blake3::hash(canonical.as_bytes()).to_hex().to_string();

    // Store as a fact under __decisions__::{session_id}
    let entity = format!("__decisions__::{session_id}");
    let req = StoreFact {
        entity: entity.clone(),
        key: decision_id.clone(),
        value: canonical,
        source_receipt: None,
        confidence,
        private: false,
        horizon_class: None,
        actor: None,
    };

    let mut store = ctx.fact_store.write().await;
    store.store(req);

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "decision recorded: {} (hash={}, entity={}, action={})",
                decision_id,
                &decision_hash[..16],
                entity,
                action
            )
        }]
    }))
}

/// Extract a required string parameter or return an INVALID_PARAMS error.
fn require_str<'a>(args: &'a Value, field: &str) -> Result<&'a str, JsonRpcError> {
    args.get(field).and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing required field: {field}"),
        data: None,
    })
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;
    use crate::tools::call_tool;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    #[tokio::test]
    async fn record_decision_required_fields_only() {
        let ctx = test_ctx();
        let result = handle_record_decision(&json!({"action": "Use Postgres", "rationale": "Need ACID"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("decision recorded: d_"));
        assert!(text.contains("entity=__decisions__::_default"));
        assert!(text.contains("action=Use Postgres"));
        assert!(text.contains("hash="));
    }

    #[tokio::test]
    async fn record_decision_all_fields() {
        let ctx = test_ctx();
        let result = handle_record_decision(
            &json!({
                "action": "Chose PostgreSQL over MongoDB",
                "rationale": "Need ACID transactions",
                "alternatives": ["MongoDB", "SQLite"],
                "confidence": 0.9,
                "session_id": "sess-42",
                "context_refs": ["f_abc123", "r_def456"]
            }),
            &ctx,
        )
        .await
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("decision recorded: d_"));
        assert!(text.contains("entity=__decisions__::sess-42"));
        assert!(text.contains("action=Chose PostgreSQL over MongoDB"));
    }

    #[tokio::test]
    async fn record_decision_missing_action() {
        let ctx = test_ctx();
        let err = handle_record_decision(&json!({"rationale": "some reason"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("action"));
    }

    #[tokio::test]
    async fn record_decision_missing_rationale() {
        let ctx = test_ctx();
        let err = handle_record_decision(&json!({"action": "do something"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.message.contains("rationale"));
    }

    #[tokio::test]
    async fn decisions_queryable_via_query_facts() {
        let ctx = test_ctx();

        // Record a decision
        handle_record_decision(
            &json!({
                "action": "Use Redis for caching",
                "rationale": "Low latency reads",
                "session_id": "test-session"
            }),
            &ctx,
        )
        .await
        .unwrap();

        // Query it via query_facts using entity filter
        let result = call_tool("query_facts", &json!({"entity": "__decisions__::test-session"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("Use Redis for caching"));
    }

    #[tokio::test]
    async fn record_decision_via_call_tool() {
        let ctx = test_ctx();
        let result = call_tool(
            "record_decision",
            &json!({"action": "Pick Rust", "rationale": "Performance"}),
            &ctx,
        )
        .await
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("decision recorded: d_"));
    }
}
