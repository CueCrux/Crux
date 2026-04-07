// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Handoff tool handlers: `create_handoff`, `accept_handoff`.

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::handoff;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};

/// `create_handoff` — package session state (and optionally facts) into a
/// signed handoff bundle for another agent.
pub async fn handle_create_handoff(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let session_id = require_str(args, "session_id")?;
    let include_facts = args.get("include_facts").and_then(|v| v.as_bool()).unwrap_or(false);
    let message = args.get("message").and_then(|v| v.as_str()).map(|s| s.to_string());

    let agent_name = ctx.agent.as_ref().map_or("anonymous", |a| a.name.as_str());

    let session_store = ctx.session_store.read().await;
    let fact_store = ctx.fact_store.read().await;

    let signed = handoff::create_handoff(
        &session_store,
        &fact_store,
        session_id,
        include_facts,
        agent_name,
        message,
    )
    .map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("handoff creation failed: {e}"),
        data: None,
    })?;

    let package_json = serde_json::to_string(&signed).map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("failed to serialize handoff package: {e}"),
        data: None,
    })?;

    Ok(json!({
        "content": [{
            "type": "text",
            "text": package_json
        }]
    }))
}

/// `accept_handoff` — accept a signed handoff package, verify it, and load
/// session state and facts into local stores.
pub async fn handle_accept_handoff(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let package_str = require_str(args, "package")?;

    let signed: handoff::SignedHandoff = serde_json::from_str(package_str).map_err(|e| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("invalid handoff package JSON: {e}"),
        data: None,
    })?;

    let agent_name = ctx.agent.as_ref().map_or("anonymous", |a| a.name.as_str());

    let mut session_store = ctx.session_store.write().await;
    let mut fact_store = ctx.fact_store.write().await;

    let result = handoff::accept_handoff(&mut session_store, &mut fact_store, &signed, agent_name).map_err(|e| {
        JsonRpcError {
            code: INTERNAL_ERROR,
            message: format!("handoff acceptance failed: {e}"),
            data: None,
        }
    })?;

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "handoff accepted: session_loaded={}, facts_loaded={}, verified={}",
                result.session_loaded, result.facts_loaded, result.verified
            )
        }]
    }))
}

/// Extract a required string parameter or return an `INVALID_PARAMS` error.
fn require_str<'a>(args: &'a Value, field: &str) -> Result<&'a str, JsonRpcError> {
    args.get(field).and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing required param: {field}"),
        data: None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dispatch::McpContext;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    #[tokio::test]
    async fn create_handoff_missing_session_id() {
        let ctx = test_ctx();
        let err = handle_create_handoff(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn accept_handoff_missing_package() {
        let ctx = test_ctx();
        let err = handle_accept_handoff(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn accept_handoff_invalid_json() {
        let ctx = test_ctx();
        let err = handle_accept_handoff(&json!({"package": "not valid json"}), &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn create_and_accept_roundtrip() {
        let ctx = test_ctx();

        // Save a session first.
        crate::tools::sessions::handle_save_session(
            &json!({"session_id": "ho_test", "state": {"task": "handoff roundtrip"}}),
            &ctx,
        )
        .await
        .unwrap();

        // Create handoff.
        let result = handle_create_handoff(
            &json!({
                "session_id": "ho_test",
                "include_facts": false,
                "message": "take over"
            }),
            &ctx,
        )
        .await
        .unwrap();

        let package_json = result["content"][0]["text"].as_str().unwrap();

        // Accept handoff into the same context (stores are shared, but the
        // test validates the full dispatch path).
        let result = handle_accept_handoff(&json!({"package": package_json}), &ctx)
            .await
            .unwrap();

        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("session_loaded=true"));
        assert!(text.contains("verified=true"));
    }
}
