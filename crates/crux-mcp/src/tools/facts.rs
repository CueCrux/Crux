// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Fact store tool handlers: `store_fact`, `query_facts`, `delete_fact`,
//! `list_entities`, `get_bootstrap`.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};
use crate::scope;
use corecrux_memory::fact_store::{Fact, FactQuery, StoreFact};

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
    let agent_name = scope::agent_name(ctx.agent.as_ref());

    let entity = match (private, agent_name) {
        (true, Some(agent_name)) => scope::private_entity_for_agent(agent_name, entity_raw),
        (true, None) => {
            return Err(JsonRpcError {
                code: INVALID_PARAMS,
                message: "private facts require an authenticated agent identity".to_string(),
                data: Some(json!({"param": "private", "requires_agent_identity": true})),
            });
        }
        (false, _) => entity_raw.to_string(),
    };

    let req = StoreFact {
        entity,
        key: key.to_string(),
        value: value.to_string(),
        source_receipt,
        confidence,
        private,
        horizon_class: None,
    };

    let mut store = ctx.fact_store.write().await;
    // M3.5 NOTE: We deliberately do NOT call
    // `category_enforce::check_passport_can_write_entity` here yet. The check
    // requires an identifiable passport_id, but on prod the MCP agent names
    // (`windows-host`, `openai`, `anthropic`, `tailnet`) don't match any
    // passport_id (`agent-claude`, `personal-default`). There is no agent→passport
    // mapping at this layer — sessions resolve passports via category-default
    // (`session_bindings::resolve`), but `handle_store_fact` carries no session
    // context. Wiring the check naively would 403 every operator MCP write after
    // deploy. Designing the agent→passport resolution is a separate ExecPlan.
    // The follow-up design must define a stable agent-to-passport mapping
    // before this layer can enforce tenant-category writes safely.
    let fact = store.try_store(req).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: "fact journal append failed".to_string(),
        data: Some(json!({"error": err.to_string()})),
    })?;
    let display_entity = scope::visible_entity_for_agent(&fact, agent_name).unwrap_or_else(|| fact.entity.clone());

    let supersedes_msg = match &fact.supersedes {
        Some(prev) => format!(", supersedes={prev}, version={}", fact.version),
        None => format!(", version={}", fact.version),
    };

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "stored fact {} (entity={}, key={}{})",
                fact.fact_id, display_entity, fact.key, supersedes_msg
            )
        }]
    }))
}

/// `fact_history` — return the full version chain for a given (entity, key) pair.
pub async fn handle_fact_history(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let entity = require_str(args, "entity")?;
    let key = require_str(args, "key")?;
    let agent_name = scope::agent_name(ctx.agent.as_ref());

    let store = ctx.fact_store.read().await;
    let mut history: Vec<&Fact> = store
        .all_facts()
        .filter(|fact| fact.key == key)
        .filter(|fact| scope::entity_matches_for_agent(fact, entity, agent_name))
        .filter(|fact| scope::fact_visible_to_agent(fact, agent_name))
        .collect();
    history.sort_by_key(|fact| fact.version);

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
            let display_entity = scope::visible_entity_for_agent(f, agent_name).unwrap_or_else(|| f.entity.clone());
            format!(
                "v{}: [{}] {} = {} (confidence={:.2}, stored_at={}, supersedes={}){}",
                f.version, display_entity, f.fact_id, f.value, f.confidence, f.stored_at, sup, status
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
    let agent_name = scope::agent_name(ctx.agent.as_ref());

    let q = FactQuery {
        query,
        entity,
        entity_prefix: None,
        top_k,
        token_budget,
    };

    let store = ctx.fact_store.read().await;
    let visible = query_visible_facts(&store, &q, agent_name);

    if visible.is_empty() {
        return Ok(json!({
            "content": [{ "type": "text", "text": "no facts found" }]
        }));
    }

    let text = visible
        .into_iter()
        .map(|f| {
            let entity = scope::visible_entity_for_agent(&f, agent_name).unwrap_or_else(|| f.entity.clone());
            format!("[{}] {} = {} (confidence={:.2})", entity, f.key, f.value, f.confidence)
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
    let agent_name = scope::agent_name(ctx.agent.as_ref());

    let mut store = ctx.fact_store.write().await;
    let deleted = store
        .get(fact_id)
        .is_some_and(|fact| scope::fact_visible_to_agent(fact, agent_name))
        && store.try_delete(fact_id).map_err(|err| JsonRpcError {
            code: INTERNAL_ERROR,
            message: "fact journal append failed".to_string(),
            data: Some(json!({"error": err.to_string()})),
        })?;

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
    let agent_name = scope::agent_name(ctx.agent.as_ref());
    let entities: Vec<String> = store
        .all_facts()
        .filter(|fact| !fact.deleted)
        .filter_map(|fact| scope::visible_entity_for_agent(fact, agent_name))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

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

/// Crate-internal alias of [`query_visible_facts`] reused by
/// [`crate::envelope`] so the envelope builder applies exactly the same
/// visibility + budget rules as the real `query_facts` handler (no extra
/// surface, no chance of leaking facts the caller couldn't query
/// directly).
pub(crate) fn envelope_query_visible_facts(
    store: &corecrux_memory::FactStore,
    q: &FactQuery,
    agent_name: Option<&str>,
) -> Vec<Fact> {
    query_visible_facts(store, q, agent_name)
}

fn query_visible_facts(store: &corecrux_memory::FactStore, q: &FactQuery, agent_name: Option<&str>) -> Vec<Fact> {
    let mut results: Vec<&Fact> = store
        .all_facts()
        .filter(|fact| !fact.deleted)
        .filter(|fact| scope::fact_visible_to_agent(fact, agent_name))
        .filter(|fact| {
            q.entity_prefix
                .as_ref()
                .is_none_or(|prefix| scope::entity_prefix_matches_for_agent(fact, prefix, agent_name))
        })
        .filter(|fact| {
            q.entity
                .as_ref()
                .is_none_or(|entity| scope::entity_matches_for_agent(fact, entity, agent_name))
        })
        .filter(|fact| match &q.query {
            Some(query) => fact_matches_query(fact, query, agent_name),
            None => true,
        })
        .collect();

    results.sort_by(|left, right| {
        right
            .confidence
            .partial_cmp(&left.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.stored_at.cmp(&left.stored_at))
    });

    if let Some(budget) = q.token_budget {
        let mut used = 0usize;
        let mut selected = Vec::new();
        for fact in results {
            if used + fact.tokens > budget && !selected.is_empty() {
                break;
            }
            used += fact.tokens;
            selected.push(fact.clone());
            if used >= budget {
                break;
            }
        }
        return selected;
    }

    results.truncate(q.top_k);
    results.into_iter().cloned().collect()
}

fn fact_matches_query(fact: &Fact, query: &str, agent_name: Option<&str>) -> bool {
    let query_lower = query.to_lowercase();
    let terms: Vec<&str> = query_lower.split_whitespace().collect();
    let value_lower = fact.value.to_lowercase();
    let key_lower = fact.key.to_lowercase();
    let entity_lower = scope::visible_entity_for_agent(fact, agent_name)
        .unwrap_or_else(|| fact.entity.clone())
        .to_lowercase();

    terms
        .iter()
        .any(|term| value_lower.contains(term) || key_lower.contains(term) || entity_lower.contains(term))
}

/// Bootstrap entity prefix.
const BOOTSTRAP_PREFIX: &str = "__bootstrap__::";

/// `get_bootstrap` — query bootstrap knowledge at runtime.
///
/// Accepts an optional `topic` parameter ("patterns", "docs", "errors") to
/// filter bootstrap facts by sub-entity, plus an optional `query` term to
/// narrow the result set.
pub async fn handle_get_bootstrap(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let topic = args.get("topic").and_then(|v| v.as_str()).map(|s| s.to_string());
    let query = args.get("query").and_then(|v| v.as_str()).map(|s| s.to_string());

    let prefix = match &topic {
        Some(t) => format!("{BOOTSTRAP_PREFIX}{}:", normalize_bootstrap_topic(t)),
        None => BOOTSTRAP_PREFIX.to_string(),
    };

    let q = FactQuery {
        query,
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

fn normalize_bootstrap_topic(topic: &str) -> String {
    let trimmed = topic.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "doc" | "docs" => "doc".to_string(),
        "pattern" | "patterns" => "pattern".to_string(),
        "error" | "errors" | "resolution" | "resolutions" => "resolution".to_string(),
        "tool" | "tool-output" | "tool-outputs" => "tool-output".to_string(),
        _ => trimmed.to_string(),
    }
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
#[allow(clippy::unwrap_used)]
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
        assert!(text.contains("[notes]"));

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
    async fn private_fact_without_agent_is_rejected() {
        let ctx = test_ctx(); // no agent
        let err = handle_store_fact(
            &json!({"entity": "notes", "key": "k", "value": "v", "private": true}),
            &ctx,
        )
        .await
        .unwrap_err();

        assert_eq!(err.code, INVALID_PARAMS);
        assert_eq!(err.data.unwrap()["requires_agent_identity"], true);
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

    #[tokio::test]
    async fn list_entities_hides_other_agents_private_entities() {
        let ctx = test_ctx();
        let alice_ctx = ctx.with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });
        let bob_ctx = ctx.with_agent(AgentIdentity {
            name: "bob".to_string(),
            token_hash: [1u8; 32],
        });

        handle_store_fact(
            &json!({"entity": "notes", "key": "secret", "value": "hidden", "private": true}),
            &alice_ctx,
        )
        .await
        .unwrap();

        let alice = handle_list_entities(&json!({}), &alice_ctx).await.unwrap();
        assert_eq!(alice["content"][0]["text"].as_str().unwrap(), "notes");

        let bob = handle_list_entities(&json!({}), &bob_ctx).await.unwrap();
        assert_eq!(bob["content"][0]["text"].as_str().unwrap(), "no entities found");
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
            &json!({"entity": "__bootstrap__::pattern:retry", "key": "Retry Pattern", "value": "exponential backoff"}),
            &ctx,
        )
        .await
        .unwrap();
        handle_store_fact(
            &json!({"entity": "__bootstrap__::resolution:oom", "key": "OOM Recovery", "value": "increase memory"}),
            &ctx,
        )
        .await
        .unwrap();
        handle_store_fact(
            &json!({"entity": "__bootstrap__::doc:onboarding", "key": "Human-Assisted Integration", "value": "share the HTTP and MCP endpoints with the operator"}),
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

        let result = handle_get_bootstrap(&json!({"topic": "docs", "query": "Human-Assisted"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("Human-Assisted Integration"));
        assert!(!text.contains("exponential backoff"));
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
