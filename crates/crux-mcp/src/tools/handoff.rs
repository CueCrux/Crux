// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Handoff tool handlers: `create_handoff`, `accept_handoff`.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use tracing::warn;

use crate::dispatch::McpContext;
use crate::handoff;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS};
use crate::scope;

const HANDOFF_OBSERVATIONS_ENV: &str = "CORECRUXD_HANDOFF_OBSERVATIONS";
const HANDOFF_OBSERVATION_PROVIDER: &str = "crux-handoff";
const HANDOFF_OBSERVATION_KIND: &str = "handoff";
const HANDOFF_OBSERVATION_SCHEMA: &str = "crux.s1.handoff_observation.v1";

/// `create_handoff` — package session state (and optionally facts) into a
/// signed handoff bundle for another agent.
pub async fn handle_create_handoff(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let session_id = require_str(args, "session_id")?;
    let include_facts = args.get("include_facts").and_then(|v| v.as_bool()).unwrap_or(false);
    let message = args.get("message").and_then(|v| v.as_str()).map(|s| s.to_string());
    let target_agent = args.get("target_agent").and_then(|v| v.as_str()).map(|s| s.to_string());
    let target_agent_for_observation = target_agent.clone();
    let task_record = match args.get("task_record") {
        Some(v) if !v.is_null() => {
            Some(
                serde_json::from_value::<handoff::TaskRecord>(v.clone()).map_err(|e| JsonRpcError {
                    code: INVALID_PARAMS,
                    message: format!("invalid task_record: {e}"),
                    data: None,
                })?,
            )
        }
        _ => None,
    };

    let agent_name = ctx.agent.as_ref().map_or("anonymous", |a| a.name.as_str());
    let stored_session_id = scope::scoped_session_id(scope::agent_name(ctx.agent.as_ref()), session_id);

    let session_store = ctx.session_store.read().await;
    let fact_store = ctx.fact_store.read().await;

    let signed = handoff::create_handoff_for_tenant(
        &session_store,
        &fact_store,
        handoff::CreateHandoffRequest {
            session_id,
            stored_session_id: &stored_session_id,
            include_facts,
            source_agent: agent_name,
            target_agent,
            message,
            task_record,
        },
        &ctx.scope_tenant(),
        &ctx.handoff_key,
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

    maybe_emit_handoff_observation(
        ctx,
        "create",
        "mcp_create_handoff",
        session_id,
        Some(agent_name),
        target_agent_for_observation.as_deref(),
        &signed.content_hash,
    );

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

    let receiver_agent = scope::agent_name(ctx.agent.as_ref());

    let mut session_store = ctx.session_store.write().await;
    let mut fact_store = ctx.fact_store.write().await;

    let result = handoff::accept_handoff_for_tenant(
        &mut session_store,
        &mut fact_store,
        &signed,
        receiver_agent,
        &ctx.scope_tenant(),
        &ctx.handoff_key,
    )
    .map_err(|e| JsonRpcError {
        code: INTERNAL_ERROR,
        message: format!("handoff acceptance failed: {e}"),
        data: None,
    })?;

    match decode_package_for_observation(&signed) {
        Ok(package) => {
            let target_agent = package.target_agent.as_deref().or(receiver_agent);
            maybe_emit_handoff_observation(
                ctx,
                "accept",
                "mcp_accept_handoff",
                &package.session_id,
                Some(package.source_agent.as_str()),
                target_agent,
                &signed.content_hash,
            );
        }
        Err(err) => {
            warn!(error = %err, "handoff observation: verified payload could not be decoded");
        }
    }

    let mut text = format!(
        "handoff accepted: session_loaded={}, facts_loaded={}, verified={}",
        result.session_loaded, result.facts_loaded, result.verified
    );
    // Surface the structured intent to the receiver so it does not have to
    // re-derive the task from the bundled facts blob.
    if let Some(record) = &result.task_record {
        if let Ok(pretty) = serde_json::to_string_pretty(record) {
            text.push_str("\ntask_record:\n");
            text.push_str(&pretty);
        }
    }

    Ok(json!({
        "content": [{
            "type": "text",
            "text": text
        }]
    }))
}

/// Extract a required string parameter or return an `INVALID_PARAMS` error.
fn require_str<'a>(args: &'a Value, field: &str) -> Result<&'a str, JsonRpcError> {
    args.get(field).and_then(|v| v.as_str()).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: format!("missing required param: {field}"),
        data: Some(json!({"param": field, "required": true})),
    })
}

fn maybe_emit_handoff_observation(
    ctx: &McpContext,
    action: &str,
    surface: &str,
    session_id: &str,
    source_agent: Option<&str>,
    target_agent: Option<&str>,
    content_hash: &str,
) {
    if !handoff_observations_enabled() {
        return;
    }
    let passport = observation_passport(ctx);
    let body = build_handoff_observation_body(
        ctx,
        HandoffObservationRecord {
            action,
            surface,
            session_id,
            source_agent,
            target_agent,
            content_hash,
        },
    );
    crate::ledger::emit(ctx.daemon_base_url.clone(), &passport, body);
}

fn handoff_observations_enabled() -> bool {
    env_truthy(HANDOFF_OBSERVATIONS_ENV)
}

fn env_truthy(var: &str) -> bool {
    match std::env::var(var) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

fn observation_passport(ctx: &McpContext) -> String {
    ctx.scope_identity().unwrap_or_else(|| "__anon__".to_string())
}

struct HandoffObservationRecord<'a> {
    action: &'a str,
    surface: &'a str,
    session_id: &'a str,
    source_agent: Option<&'a str>,
    target_agent: Option<&'a str>,
    content_hash: &'a str,
}

fn build_handoff_observation_body(ctx: &McpContext, rec: HandoffObservationRecord<'_>) -> Value {
    let source_agent = normalize_handoff_agent(rec.source_agent);
    let target_agent = normalize_handoff_agent(rec.target_agent);
    let source_passport = source_agent
        .as_deref()
        .and_then(|agent| resolve_handoff_agent_passport(ctx, agent));
    let target_passport = target_agent
        .as_deref()
        .and_then(|agent| resolve_handoff_agent_passport(ctx, agent));
    let cross_vendor = match (&source_passport, &target_passport) {
        (Some(source), Some(target)) => Some(source != target),
        _ => None,
    };
    json!({
        "kind": HANDOFF_OBSERVATION_KIND,
        "provider": HANDOFF_OBSERVATION_PROVIDER,
        "payload": {
            "schema": HANDOFF_OBSERVATION_SCHEMA,
            "action": rec.action,
            "surface": rec.surface,
            "session_id": rec.session_id,
            "source_agent": source_agent,
            "target_agent": target_agent,
            "source_passport": source_passport,
            "target_passport": target_passport,
            "cross_vendor": cross_vendor,
            "handoff_payload_hash": normalized_handoff_hash(rec.content_hash),
            "handoff_content_hash": rec.content_hash,
        },
    })
}

fn normalize_handoff_agent(agent: Option<&str>) -> Option<String> {
    let trimmed = agent?.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_ascii_lowercase())
    }
}

fn handoff_agent_lookup_key(agent: &str) -> &str {
    match agent {
        "claude" | "claude-code" | "anthropic" => "anthropic",
        "codex" | "codex-cli" | "openai" => "openai",
        other => other,
    }
}

fn resolve_handoff_agent_passport(ctx: &McpContext, agent: &str) -> Option<String> {
    let key = handoff_agent_lookup_key(agent);
    if ctx.agent_passports_enabled {
        crate::agent_passport::resolve_agent_passport(key, &ctx.agent_passport_map)
    } else {
        None
    }
    .or_else(|| {
        let env_map = crate::agent_passport::AgentPassportMap::from_env_or_default();
        crate::agent_passport::resolve_agent_passport(key, &env_map)
    })
}

fn normalized_handoff_hash(content_hash: &str) -> String {
    if content_hash.starts_with("blake3:") {
        content_hash.to_string()
    } else {
        format!("blake3:{content_hash}")
    }
}

fn decode_package_for_observation(
    signed: &handoff::SignedHandoff,
) -> Result<handoff::HandoffPackage, handoff::HandoffError> {
    let payload_bytes = B64.decode(&signed.payload_b64)?;
    Ok(serde_json::from_slice(&payload_bytes)?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::agent_passport::AgentPassportMap;
    use crate::dispatch::McpContext;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    fn test_ctx_with_agent(name: &str) -> McpContext {
        test_ctx()
            .with_agent(AgentIdentity {
                name: name.to_string(),
                token_hash: [0_u8; 32],
            })
            .with_agent_passports(true, AgentPassportMap::builtin_default())
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

    #[test]
    fn handoff_observation_body_marks_cross_vendor_passports() {
        let ctx = test_ctx_with_agent("anthropic");
        let body = build_handoff_observation_body(
            &ctx,
            HandoffObservationRecord {
                action: "create",
                surface: "mcp_create_handoff",
                session_id: "ho_test",
                source_agent: Some("Claude-Code"),
                target_agent: Some("codex"),
                content_hash: "abc123",
            },
        );

        assert_eq!(body["kind"], HANDOFF_OBSERVATION_KIND);
        assert_eq!(body["provider"], HANDOFF_OBSERVATION_PROVIDER);
        assert_eq!(body["payload"]["schema"], HANDOFF_OBSERVATION_SCHEMA);
        assert_eq!(body["payload"]["action"], "create");
        assert_eq!(body["payload"]["surface"], "mcp_create_handoff");
        assert_eq!(body["payload"]["source_agent"], "claude-code");
        assert_eq!(body["payload"]["target_agent"], "codex");
        assert_eq!(body["payload"]["source_passport"], "claude-work");
        assert_eq!(body["payload"]["target_passport"], "codex-work");
        assert_eq!(body["payload"]["cross_vendor"], true);
        assert_eq!(body["payload"]["handoff_payload_hash"], "blake3:abc123");
        assert_eq!(body["payload"]["handoff_content_hash"], "abc123");
    }

    #[test]
    fn handoff_observation_body_marks_same_vendor_and_unknown_targets() {
        let ctx = test_ctx_with_agent("anthropic");
        let same_vendor = build_handoff_observation_body(
            &ctx,
            HandoffObservationRecord {
                action: "accept",
                surface: "mcp_accept_handoff",
                session_id: "ho_test",
                source_agent: Some("anthropic"),
                target_agent: Some("claude"),
                content_hash: "blake3:def456",
            },
        );
        assert_eq!(same_vendor["payload"]["action"], "accept");
        assert_eq!(same_vendor["payload"]["cross_vendor"], false);
        assert_eq!(same_vendor["payload"]["handoff_payload_hash"], "blake3:def456");

        let unknown_target = build_handoff_observation_body(
            &ctx,
            HandoffObservationRecord {
                action: "accept",
                surface: "mcp_accept_handoff",
                session_id: "ho_test",
                source_agent: Some("anthropic"),
                target_agent: Some("unknown-agent"),
                content_hash: "def456",
            },
        );
        assert!(unknown_target["payload"]["target_passport"].is_null());
        assert!(unknown_target["payload"]["cross_vendor"].is_null());
    }

    #[tokio::test]
    async fn accept_observation_decodes_verified_package_metadata() {
        let ctx = test_ctx_with_agent("anthropic");

        crate::tools::sessions::handle_save_session(
            &json!({"session_id": "ho_decode", "state": {"task": "decode metadata"}}),
            &ctx,
        )
        .await
        .unwrap();

        let result = handle_create_handoff(
            &json!({
                "session_id": "ho_decode",
                "include_facts": false,
                "target_agent": "openai"
            }),
            &ctx,
        )
        .await
        .unwrap();

        let signed: handoff::SignedHandoff =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        let package = decode_package_for_observation(&signed).unwrap();

        assert_eq!(package.session_id, "ho_decode");
        assert_eq!(package.source_agent, "anthropic");
        assert_eq!(package.target_agent.as_deref(), Some("openai"));
    }

    #[tokio::test]
    async fn observation_transport_failure_does_not_fail_handoff_tools() {
        std::env::set_var(HANDOFF_OBSERVATIONS_ENV, "1");
        let ctx = test_ctx_with_agent("anthropic").with_daemon_base_url("http://127.0.0.1:9");

        crate::tools::sessions::handle_save_session(
            &json!({"session_id": "ho_emit_noop", "state": {"task": "emit failure"}}),
            &ctx,
        )
        .await
        .unwrap();

        let result = handle_create_handoff(
            &json!({
                "session_id": "ho_emit_noop",
                "include_facts": false,
                "target_agent": "anthropic"
            }),
            &ctx,
        )
        .await
        .unwrap();
        let package_json = result["content"][0]["text"].as_str().unwrap();

        let result = handle_accept_handoff(&json!({"package": package_json}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("session_loaded=true"));
        assert!(text.contains("verified=true"));
        std::env::remove_var(HANDOFF_OBSERVATIONS_ENV);
    }
}
