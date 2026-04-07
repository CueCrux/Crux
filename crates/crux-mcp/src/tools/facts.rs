// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Fact store tool handlers: `store_fact`, `query_facts`, `delete_fact`,
//! `list_entities`, `get_bootstrap`.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INVALID_PARAMS};
use corecrux_memory::fact_store::{FactQuery, StoreFact};

/// Private-fact entity prefix. When `private: true` and an agent identity is
/// present, the entity is prefixed with `__agent::{name}::` so that only the
/// owning agent can see it.
const AGENT_PREFIX: &str = "__agent::";

/// `store_fact` — persist a key-value fact against an entity.
///
/// If `private: true` and the caller has an authenticated agent identity, the
/// entity is automatically prefixed with `__agent::{agent_name}::` to scope
/// visibility.
pub async fn handle_store_fact(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let entity_raw = require_str(args, "entity")?;
    let key = require_str(args, "key")?;
    let value = require_str(args, "value")?;
    let source_receipt = args
        .get("source_receipt")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let confidence = args.get("confidence").and_then(|v| v.as_f64()).unwrap_or(1.0) as f32;
    let private = args.get("private").and_then(|v| v.as_bool()).unwrap_or(false);

    // Apply agent-scoped entity prefix for private facts.
    let entity = if private {
        if let Some(ref agent) = ctx.agent {
            format!("{AGENT_PREFIX}{}::{entity_raw}", agent.name)
        } else {
            entity_raw.to_string()
        }
    } else {
        entity_raw.to_string()
    };

    let req = StoreFact {
        entity,
        key: key.to_string(),
        value: value.to_string(),
        source_receipt,
        confidence,
    };

    let mut store = ctx.fact_store.write().await;
    let fact = store.store(req);

    let supersedes_msg = match &fact.supersedes {
        Some(prev) => format!(", supersedes={prev}, version={}", fact.version),
        None => format!(", version={}", fact.version),
    };

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!("stored fact {} (entity={}, key={}{})", fact.fact_id, fact.entity, fact.key, supersedes_msg)
        }]
    }))
}

/// `fact_history` — return the full version chain for a given (entity, key) pair.
pub async fn handle_fact_history(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let entity = require_str(args, "entity")?;
    let key = require_str(args, "key")?;

    let store = ctx.fact_store.read().await;
    let history = store.fact_history(entity, key);

    if history.is_empty() {
        return Ok(json!({
            "content": [{ "type": "text", "text": format!("no history for entity={entity}, key={key}") }]
        }));
    }

    let text = history
        .iter()
        .map(|f| {
            let status = if f.deleted { " [deleted]" } else { "" };
            let sup = f.supersedes.as_deref().unwrap_or("-");
            format!(
                "v{}: {} = {} (confidence={:.2}, stored_at={}, supersedes={}){}",
                f.version, f.fact_id, f.value, f.confidence, f.stored_at, sup, status
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    Ok(json!({
        "content": [{ "type": "text", "text": text }]
    }))
}

/// `query_facts` — search the fact store by keyword, entity, or both.
///
/// Results are filtered to exclude private facts owned by other agents.
pub async fn handle_query_facts(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let query = args.get("query").and_then(|v| v.as_str()).map(|s| s.to_string());
    let entity = args.get("entity").and_then(|v| v.as_str()).map(|s| s.to_string());
    let top_k = args.get("top_k").and_then(|v| v.as_u64()).unwrap_or(10) as usize;
    let token_budget = args.get("token_budget").and_then(|v| v.as_u64()).map(|v| v as usize);

    let q = FactQuery {
        query,
        entity,
        entity_prefix: None,
        top_k,
        token_budget,
    };

    let store = ctx.fact_store.read().await;
    let result = store.query(&q);

    // Filter out private facts not owned by the requesting agent.
    let agent_name = ctx.agent.as_ref().map(|a| a.name.as_str());
    let visible: Vec<_> = result
        .facts
        .iter()
        .filter(|f| {
            if f.entity.starts_with(AGENT_PREFIX) {
                // Extract owner name from "__agent::{name}::..."
                let rest = &f.entity[AGENT_PREFIX.len()..];
                if let Some(owner) = rest.split("::").next() {
                    return agent_name == Some(owner);
                }
                false
            } else {
                true
            }
        })
        .collect();

    if visible.is_empty() {
        return Ok(json!({
            "content": [{ "type": "text", "text": "no facts found" }]
        }));
    }

    let text = visible
        .iter()
        .map(|f| {
            format!(
                "[{}] {} = {} (confidence={:.2})",
                f.entity, f.key, f.value, f.confidence
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    Ok(json!({
        "content": [{ "type": "text", "text": text }]
    }))
}

/// `delete_fact` — soft-delete a fact by its ID.
pub async fn handle_delete_fact(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let fact_id = require_str(args, "fact_id")?;

    let mut store = ctx.fact_store.write().await;
    let deleted = store.delete(fact_id);

    if deleted {
        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("deleted fact {fact_id}")
            }]
        }))
    } else {
        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("fact not found: {fact_id}")
            }],
            "isError": false
        }))
    }
}

/// `list_entities` — discover all entity names in the fact store.
pub async fn handle_list_entities(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let store = ctx.fact_store.read().await;
    let entities = store.entities();

    if entities.is_empty() {
        return Ok(json!({
            "content": [{ "type": "text", "text": "no entities found" }]
        }));
    }

    let text = entities.join("\n");
    Ok(json!({
        "content": [{
            "type": "text",
            "text": text
        }]
    }))
}

/// Bootstrap entity prefix.
const BOOTSTRAP_PREFIX: &str = "__bootstrap__::";

/// `get_bootstrap` — query bootstrap knowledge at runtime.
///
/// Accepts an optional `topic` parameter ("patterns", "docs", "errors") to
/// filter bootstrap facts by sub-entity.
pub async fn handle_get_bootstrap(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let topic = args.get("topic").and_then(|v| v.as_str()).map(|s| s.to_string());

    let prefix = match &topic {
        Some(t) => format!("{BOOTSTRAP_PREFIX}{t}"),
        None => BOOTSTRAP_PREFIX.to_string(),
    };

    let q = FactQuery {
        query: None,
        entity: None,
        entity_prefix: Some(prefix),
        top_k: 100,
        token_budget: None,
    };

    let store = ctx.fact_store.read().await;
    let result = store.query(&q);

    if result.facts.is_empty() {
        let msg = match &topic {
            Some(t) => format!("no bootstrap knowledge for topic '{t}'"),
            None => "no bootstrap knowledge found".to_string(),
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

/// Extract a required string parameter or return an INVALID_PARAMS error.
fn require_str<'a>(args: &'a Value, field: &str) -> Result<&'a str, JsonRpcError> {
    args.get(field).and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing required param: {field}"),
        data: Some(json!({"param": field, "required": true})),
    })
}

// ── Tests ────────────────────────────────────────────���────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::dispatch::McpContext;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    #[tokio::test]
    async fn store_fact_basic() {
        let ctx = test_ctx();
        let result = handle_store_fact(&json!({"entity": "proj", "key": "name", "value": "CueCrux"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("stored fact f_"));
        assert!(text.contains("entity=proj"));
    }

    #[tokio::test]
    async fn store_fact_missing_entity() {
        let ctx = test_ctx();
        let err = handle_store_fact(&json!({"key": "k", "value": "v"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn store_and_query_roundtrip() {
        let ctx = test_ctx();
        handle_store_fact(&json!({"entity": "alpha", "key": "status", "value": "active"}), &ctx)
            .await
            .unwrap();

        let result = handle_query_facts(&json!({"query": "active", "entity": "alpha"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("active"));
    }

    #[tokio::test]
    async fn query_facts_empty_store() {
        let ctx = test_ctx();
        let result = handle_query_facts(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "no facts found");
    }

    #[tokio::test]
    async fn private_fact_scoped_to_agent() {
        let ctx = test_ctx();
        let agent_ctx = ctx.with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });

        // Store a private fact as alice.
        handle_store_fact(
            &json!({"entity": "notes", "key": "secret", "value": "hidden", "private": true}),
            &agent_ctx,
        )
        .await
        .unwrap();

        // alice can see it.
        let result = handle_query_facts(&json!({"query": "hidden"}), &agent_ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("hidden"));

        // Bob cannot see it.
        let bob_ctx = ctx.with_agent(AgentIdentity {
            name: "bob".to_string(),
            token_hash: [1u8; 32],
        });
        let result = handle_query_facts(&json!({"query": "hidden"}), &bob_ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "no facts found");
    }

    #[tokio::test]
    async fn private_fact_without_agent_uses_raw_entity() {
        let ctx = test_ctx(); // no agent
        handle_store_fact(
            &json!({"entity": "notes", "key": "k", "value": "v", "private": true}),
            &ctx,
        )
        .await
        .unwrap();

        // Should be stored with un-prefixed entity.
        let result = handle_query_facts(&json!({"entity": "notes"}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("notes"));
    }

    // ── delete_fact tests ───────────────────────────────────────────

    #[tokio::test]
    async fn delete_fact_existing() {
        let ctx = test_ctx();
        let result = handle_store_fact(&json!({"entity": "e", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        // Extract fact_id from "stored fact f_..."
        let fact_id = text.split_whitespace().nth(2).unwrap();

        let result = handle_delete_fact(&json!({"fact_id": fact_id}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("deleted fact"));
    }

    #[tokio::test]
    async fn delete_fact_nonexistent() {
        let ctx = test_ctx();
        let result = handle_delete_fact(&json!({"fact_id": "f_nope"}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("fact not found"));
    }

    #[tokio::test]
    async fn delete_fact_missing_param() {
        let ctx = test_ctx();
        let err = handle_delete_fact(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.data.is_some());
        assert_eq!(err.data.unwrap()["param"], "fact_id");
    }

    // ── list_entities tests ─────────────────────────────────────────

    #[tokio::test]
    async fn list_entities_empty_store() {
        let ctx = test_ctx();
        let result = handle_list_entities(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "no entities found");
    }

    #[tokio::test]
    async fn list_entities_returns_sorted_unique() {
        let ctx = test_ctx();
        handle_store_fact(&json!({"entity": "beta", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        handle_store_fact(&json!({"entity": "alpha", "key": "k", "value": "v"}), &ctx)
            .await
            .unwrap();
        handle_store_fact(&json!({"entity": "alpha", "key": "k2", "value": "v2"}), &ctx)
            .await
            .unwrap();

        let result = handle_list_entities(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines, vec!["alpha", "beta"]);
    }

    // ── get_bootstrap tests ─────────────────────────────────────────

    #[tokio::test]
    async fn get_bootstrap_empty() {
        let ctx = test_ctx();
        let result = handle_get_bootstrap(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no bootstrap knowledge found"));
    }

    #[tokio::test]
    async fn get_bootstrap_with_topic_empty() {
        let ctx = test_ctx();
        let result = handle_get_bootstrap(&json!({"topic": "patterns"}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no bootstrap knowledge for topic 'patterns'"));
    }

    #[tokio::test]
    async fn get_bootstrap_returns_matching_facts() {
        let ctx = test_ctx();
        // Store bootstrap facts.
        handle_store_fact(
            &json!({"entity": "__bootstrap__::patterns", "key": "retry", "value": "exponential backoff"}),
            &ctx,
        )
        .await
        .unwrap();
        handle_store_fact(
            &json!({"entity": "__bootstrap__::errors", "key": "oom", "value": "increase memory"}),
            &ctx,
        )
        .await
        .unwrap();
        // Non-bootstrap fact should not appear.
        handle_store_fact(&json!({"entity": "project", "key": "name", "value": "CueCrux"}), &ctx)
            .await
            .unwrap();

        // Query all bootstrap.
        let result = handle_get_bootstrap(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("exponential backoff"));
        assert!(text.contains("increase memory"));
        assert!(!text.contains("CueCrux"));

        // Query filtered by topic.
        let result = handle_get_bootstrap(&json!({"topic": "patterns"}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("exponential backoff"));
        assert!(!text.contains("increase memory"));
    }

    // ── structured error data test ──────────────────────────────────

    #[tokio::test]
    async fn store_fact_missing_entity_has_structured_data() {
        let ctx = test_ctx();
        let err = handle_store_fact(&json!({"key": "k", "value": "v"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        let data = err.data.unwrap();
        assert_eq!(data["param"], "entity");
        assert_eq!(data["required"], true);
    }
}
