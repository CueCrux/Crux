// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Session state tool handlers: `get_session`, `save_session`,
//! `session_checkpoint`, `list_sessions`, `delete_session`.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};
use crate::scope;

/// `get_session` — retrieve session state by ID.
pub async fn handle_get_session(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let session_id = require_str(args, "session_id")?;
    let stored_session_id = scope::scoped_session_id(scope::agent_name(ctx.agent.as_ref()), session_id);

    let store = ctx.session_store.read().await;
    match store.get(&stored_session_id) {
        Some(session) => Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&session.state).unwrap_or_default()
            }]
        })),
        None => Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("no session found: {session_id}")
            }],
            "isError": false
        })),
    }
}

/// `save_session` — create or update session state.
pub async fn handle_save_session(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let session_id = require_str(args, "session_id")?;
    let state = args.get("state").cloned().ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "missing required param: state".to_string(),
        data: Some(json!({"param": "state", "required": true})),
    })?;

    let ttl_seconds = args.get("ttl_seconds").and_then(|v| v.as_u64());
    let stored_session_id = scope::scoped_session_id(scope::agent_name(ctx.agent.as_ref()), session_id);

    let mut store = ctx.session_store.write().await;
    let session = store
        .try_put(&stored_session_id, state, ttl_seconds)
        .map_err(|err| JsonRpcError {
            code: INTERNAL_ERROR,
            message: "session journal append failed".to_string(),
            data: Some(json!({"error": err.to_string()})),
        })?;

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!("saved session {} ({} tokens)", session_id, session.total_tokens)
        }]
    }))
}

/// `session_checkpoint` — store a compact, typed resumability checkpoint.
pub async fn handle_session_checkpoint(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let session_id = require_str(args, "session_id")?;
    let token_budget = require_u64(args, "token_budget")?;
    if token_budget == 0 {
        return Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: "token_budget must be greater than zero".to_string(),
            data: Some(json!({"param": "token_budget"})),
        });
    }
    let ttl_seconds = args.get("ttl_seconds").and_then(|v| v.as_u64());
    let stored_session_id = scope::scoped_session_id(scope::agent_name(ctx.agent.as_ref()), session_id);
    let state = json!({
        "schema": "crux.session_checkpoint.v1",
        "session_id": session_id,
        "agent": ctx.scope_identity(),
        "updated_at": chrono::Utc::now().to_rfc3339(),
        "objective": args.get("objective").cloned().unwrap_or(Value::Null),
        "current_milestone": args.get("current_milestone").cloned().unwrap_or(Value::Null),
        "decisions": args.get("decisions").cloned().unwrap_or_else(|| json!([])),
        "open_questions": args.get("open_questions").cloned().unwrap_or_else(|| json!([])),
        "files_touched": args.get("files_touched").cloned().unwrap_or_else(|| json!([])),
        "commands_run": args.get("commands_run").cloned().unwrap_or_else(|| json!([])),
        "test_status": args.get("test_status").cloned().unwrap_or(Value::Null),
        "next_action": args.get("next_action").cloned().unwrap_or(Value::Null),
        "token_budget": token_budget,
    });

    let mut store = ctx.session_store.write().await;
    let session = store
        .try_put(&stored_session_id, state, ttl_seconds)
        .map_err(|err| JsonRpcError {
            code: INTERNAL_ERROR,
            message: "session journal append failed".to_string(),
            data: Some(json!({"error": err.to_string()})),
        })?;

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!("checkpointed session {} ({} tokens)", session_id, session.total_tokens)
        }],
        "structuredContent": {
            "session_id": session_id,
            "updated_at": session.updated_at,
            "total_tokens": session.total_tokens
        }
    }))
}

/// `list_sessions` — list session IDs. Archived sessions are hidden unless
/// `include_archived` is true.
pub async fn handle_list_sessions(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let include_archived = args.get("include_archived").and_then(Value::as_bool).unwrap_or(false);
    let store = ctx.session_store.read().await;
    let mut ids = store
        .list_filtered(include_archived)
        .into_iter()
        .filter_map(|session_id| scope::visible_session_for_agent(session_id, scope::agent_name(ctx.agent.as_ref())))
        .collect::<Vec<_>>();
    ids.sort();

    if ids.is_empty() {
        return Ok(json!({
            "content": [{ "type": "text", "text": "no sessions" }]
        }));
    }

    let text = ids.join("\n");
    Ok(json!({
        "content": [{ "type": "text", "text": text }]
    }))
}

/// `delete_session` — delete a session by ID.
pub async fn handle_delete_session(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let session_id = require_str(args, "session_id")?;
    let stored_session_id = scope::scoped_session_id(scope::agent_name(ctx.agent.as_ref()), session_id);

    let mut store = ctx.session_store.write().await;
    let deleted = store.try_delete(&stored_session_id).map_err(|err| JsonRpcError {
        code: INTERNAL_ERROR,
        message: "session journal append failed".to_string(),
        data: Some(json!({"error": err.to_string()})),
    })?;

    if deleted {
        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("deleted session {session_id}")
            }]
        }))
    } else {
        Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("session not found: {session_id}")
            }],
            "isError": false
        }))
    }
}

/// `archive_session` — archive a session by ID (soft, reversible; preserves state).
pub async fn handle_archive_session(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    set_session_archived(args, ctx, true).await
}

/// `unarchive_session` — restore a previously archived session by ID.
pub async fn handle_unarchive_session(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    set_session_archived(args, ctx, false).await
}

async fn set_session_archived(args: &Value, ctx: &McpContext, archived: bool) -> Result<Value, JsonRpcError> {
    let session_id = require_str(args, "session_id")?;
    let reason = args.get("reason").and_then(Value::as_str).map(str::to_string);
    let stored_session_id = scope::scoped_session_id(scope::agent_name(ctx.agent.as_ref()), session_id);

    let mut store = ctx.session_store.write().await;
    let result = store
        .try_set_archived(&stored_session_id, archived, reason)
        .map_err(|err| JsonRpcError {
            code: INTERNAL_ERROR,
            message: "session journal append failed".to_string(),
            data: Some(json!({"error": err.to_string()})),
        })?;

    let verb = if archived { "archived" } else { "restored" };
    match result {
        Some(_) => Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("{verb} session {session_id}")
            }]
        })),
        None => Ok(json!({
            "content": [{
                "type": "text",
                "text": format!("session not found: {session_id}")
            }],
            "isError": false
        })),
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

fn require_u64(args: &Value, field: &str) -> Result<u64, JsonRpcError> {
    args.get(field).and_then(Value::as_u64).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing required param: {field}"),
        data: Some(json!({"param": field, "required": true})),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

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
    async fn get_session_not_found() {
        let ctx = test_ctx();
        let result = handle_get_session(&json!({"session_id": "nonexistent"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no session found"));
    }

    #[tokio::test]
    async fn get_session_missing_id() {
        let ctx = test_ctx();
        let err = handle_get_session(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn save_and_get_roundtrip() {
        let ctx = test_ctx();

        // Save
        let result = handle_save_session(&json!({"session_id": "s1", "state": {"step": 1, "done": false}}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("saved session s1"));

        // Get
        let result = handle_get_session(&json!({"session_id": "s1"}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"step\": 1"));
    }

    #[tokio::test]
    async fn save_session_missing_state() {
        let ctx = test_ctx();
        let err = handle_save_session(&json!({"session_id": "s1"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn session_checkpoint_requires_and_stores_token_budget() {
        let ctx = test_ctx();
        let err = handle_session_checkpoint(&json!({"session_id": "s1"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);

        let result = handle_session_checkpoint(
            &json!({
                "session_id": "s1",
                "current_milestone": "M2",
                "next_action": "run tests",
                "token_budget": 500
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(result["structuredContent"]["session_id"], "s1");

        let stored = handle_get_session(&json!({"session_id": "s1"}), &ctx).await.unwrap();
        let text = stored["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"schema\": \"crux.session_checkpoint.v1\""));
        assert!(text.contains("\"token_budget\": 500"));
    }

    #[tokio::test]
    async fn save_session_overwrites() {
        let ctx = test_ctx();

        handle_save_session(&json!({"session_id": "s1", "state": {"v": 1}}), &ctx)
            .await
            .unwrap();

        handle_save_session(&json!({"session_id": "s1", "state": {"v": 2, "extra": true}}), &ctx)
            .await
            .unwrap();

        let result = handle_get_session(&json!({"session_id": "s1"}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"v\": 2"));
        assert!(text.contains("\"extra\": true"));
    }

    #[tokio::test]
    async fn sessions_are_scoped_per_agent() {
        let ctx = test_ctx();
        let alice_ctx = ctx.with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });
        let bob_ctx = ctx.with_agent(AgentIdentity {
            name: "bob".to_string(),
            token_hash: [1u8; 32],
        });

        handle_save_session(
            &json!({"session_id": "shared", "state": {"owner": "alice"}}),
            &alice_ctx,
        )
        .await
        .unwrap();

        let alice = handle_get_session(&json!({"session_id": "shared"}), &alice_ctx)
            .await
            .unwrap();
        assert!(alice["content"][0]["text"].as_str().unwrap().contains("alice"));

        let bob = handle_get_session(&json!({"session_id": "shared"}), &bob_ctx)
            .await
            .unwrap();
        assert_eq!(bob["content"][0]["text"].as_str().unwrap(), "no session found: shared");
    }

    // ── list_sessions tests ─────────────────────────────────────────

    #[tokio::test]
    async fn list_sessions_empty() {
        let ctx = test_ctx();
        let result = handle_list_sessions(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "no sessions");
    }

    #[tokio::test]
    async fn list_sessions_returns_sorted() {
        let ctx = test_ctx();
        handle_save_session(&json!({"session_id": "z_sess", "state": {}}), &ctx)
            .await
            .unwrap();
        handle_save_session(&json!({"session_id": "a_sess", "state": {}}), &ctx)
            .await
            .unwrap();

        let result = handle_list_sessions(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines, vec!["a_sess", "z_sess"]);
    }

    // ── delete_session tests ────────────────────────────────────────

    #[tokio::test]
    async fn delete_session_existing() {
        let ctx = test_ctx();
        handle_save_session(&json!({"session_id": "s1", "state": {"x": 1}}), &ctx)
            .await
            .unwrap();

        let result = handle_delete_session(&json!({"session_id": "s1"}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("deleted session s1"));

        // Verify it's gone.
        let result = handle_get_session(&json!({"session_id": "s1"}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no session found"));
    }

    #[tokio::test]
    async fn delete_session_nonexistent() {
        let ctx = test_ctx();
        let result = handle_delete_session(&json!({"session_id": "nope"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("session not found"));
    }

    // ── archive_session tests ───────────────────────────────────────

    #[tokio::test]
    async fn archive_hides_from_list_but_keeps_state() {
        let ctx = test_ctx();
        handle_save_session(&json!({"session_id": "s1", "state": {"keep": 1}}), &ctx)
            .await
            .unwrap();

        let result = handle_archive_session(&json!({"session_id": "s1", "reason": "shipped"}), &ctx)
            .await
            .unwrap();
        assert!(result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("archived session s1"));

        // Hidden from default list_sessions...
        let listed = handle_list_sessions(&json!({}), &ctx).await.unwrap();
        assert_eq!(listed["content"][0]["text"].as_str().unwrap(), "no sessions");
        // ...but visible with include_archived...
        let listed_all = handle_list_sessions(&json!({"include_archived": true}), &ctx)
            .await
            .unwrap();
        assert!(listed_all["content"][0]["text"].as_str().unwrap().contains("s1"));
        // ...and state is preserved (not destroyed like delete).
        let got = handle_get_session(&json!({"session_id": "s1"}), &ctx).await.unwrap();
        assert!(got["content"][0]["text"].as_str().unwrap().contains("\"keep\": 1"));
    }

    #[tokio::test]
    async fn unarchive_restores_to_default_list() {
        let ctx = test_ctx();
        handle_save_session(&json!({"session_id": "s1", "state": {}}), &ctx)
            .await
            .unwrap();
        handle_archive_session(&json!({"session_id": "s1"}), &ctx)
            .await
            .unwrap();

        let result = handle_unarchive_session(&json!({"session_id": "s1"}), &ctx)
            .await
            .unwrap();
        assert!(result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("restored session s1"));
        let listed = handle_list_sessions(&json!({}), &ctx).await.unwrap();
        assert!(listed["content"][0]["text"].as_str().unwrap().contains("s1"));
    }

    #[tokio::test]
    async fn archive_nonexistent_returns_not_found() {
        let ctx = test_ctx();
        let result = handle_archive_session(&json!({"session_id": "nope"}), &ctx)
            .await
            .unwrap();
        assert!(result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("session not found"));
    }

    #[tokio::test]
    async fn delete_session_missing_param() {
        let ctx = test_ctx();
        let err = handle_delete_session(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.data.is_some());
        assert_eq!(err.data.unwrap()["param"], "session_id");
    }

    // ── structured error data ───────────────────────────────────────

    #[tokio::test]
    async fn save_session_missing_state_has_structured_data() {
        let ctx = test_ctx();
        let err = handle_save_session(&json!({"session_id": "s1"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
        assert!(err.data.is_some());
        assert_eq!(err.data.unwrap()["param"], "state");
    }
}
