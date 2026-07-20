// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Self-scoped passport-mint request filing.
//!
//! This tool writes only a pending operator-approval record. Passport creation
//! and request resolution remain outside M1.

use std::time::{SystemTime, UNIX_EPOCH};

use corecrux_memory::mint_request::file_mint_request;
use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::{JsonRpcError, INTERNAL_ERROR, INVALID_PARAMS, METHOD_NOT_FOUND};
use crate::tenant_category::TenantCategory;

use super::passport::{agent_tenant_group, passport_key_name};

fn feature_disabled_error() -> JsonRpcError {
    JsonRpcError {
        code: METHOD_NOT_FOUND,
        message: "unknown tool: request_passport_mint (feature disabled)".to_string(),
        data: Some(json!({
            "feature_flag": "CORECRUXD_FEATURE_PASSPORT_MINT_REQUESTS",
            "enabled": false,
        })),
    }
}

fn optional_string(args: &Value, field: &str) -> Result<Option<String>, JsonRpcError> {
    match args.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok((!value.trim().is_empty()).then(|| value.trim().to_string())),
        Some(_) => Err(JsonRpcError {
            code: INVALID_PARAMS,
            message: format!("request_passport_mint: '{field}' must be a string"),
            data: Some(json!({"param": field, "expected": "string"})),
        }),
    }
}

fn resolve_requested_category(args: &Value, ctx: &McpContext) -> Result<Option<String>, JsonRpcError> {
    if let Some(category) = optional_string(args, "requested_category")? {
        return TenantCategory::parse_user_input(&category)
            .map(|parsed| Some(parsed.as_str().to_string()))
            .map_err(|err| JsonRpcError {
                code: INVALID_PARAMS,
                message: format!("request_passport_mint: {err}"),
                data: Some(json!({
                    "param": "requested_category",
                    "accepted": ["personal", "work", "public"],
                })),
            });
    }

    Ok(agent_tenant_group(ctx)
        .and_then(|group| TenantCategory::parse_user_input(group.trim()).ok())
        .map(|category| category.as_str().to_string()))
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// File a pending passport-mint request for the authenticated caller.
///
/// The caller identity is derived from the request context. There is no target
/// identity argument, so callers cannot request a passport for another agent.
pub async fn handle_request_passport_mint(args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    // Load-bearing: a direct call must fail before it can acquire the store or
    // construct a request when the independently configured flag is off.
    if !ctx.passport_mint_requests_enabled {
        return Err(feature_disabled_error());
    }

    let requester_id = passport_key_name(ctx).ok_or_else(|| JsonRpcError {
        code: INVALID_PARAMS,
        message: "request_passport_mint requires an authenticated agent identity".to_string(),
        data: Some(json!({"requires_agent_identity": true})),
    })?;
    let requested_category = resolve_requested_category(args, ctx)?;
    let reason = optional_string(args, "reason")?;

    let request = {
        let mut store = ctx.fact_store.write().await;
        file_mint_request(
            &mut store,
            requester_id.clone(),
            requester_id,
            requested_category,
            reason,
            now_unix_ms(),
        )
        .map_err(|err| JsonRpcError {
            code: INTERNAL_ERROR,
            message: format!("request_passport_mint: failed to file request: {err}"),
            data: None,
        })?
    };

    Ok(json!({
        "content": [{
            "type": "text",
            "text": format!(
                "passport mint request filed: {} for {} (status={})",
                request.request_id, request.requester_id, request.status,
            ),
        }],
        "request_id": request.request_id,
        "requester_id": request.requester_id,
        "requested_category": request.requested_category,
        "status": request.status,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use corecrux_memory::mint_request::list_pending_mint_requests;

    use super::*;
    use crate::agent::AgentIdentity;
    use crate::agent_passport::AgentPassportMap;

    fn openai_ctx(enabled: bool) -> McpContext {
        McpContext::new_default("test-node")
            .with_agent_passports(true, AgentPassportMap::builtin_default())
            .with_passport_mint_requests(enabled)
            .with_agent(AgentIdentity {
                name: "openai".to_string(),
                token_hash: [0u8; 32],
            })
    }

    #[tokio::test]
    async fn files_pending_self_scoped_request_and_mints_nothing() {
        let ctx = openai_ctx(true);
        let result = handle_request_passport_mint(
            &json!({
                "requester_id": "someone-else",
                "reason": "Need a work passport",
            }),
            &ctx,
        )
        .await
        .unwrap();

        assert_eq!(result["requester_id"], "codex-work");
        assert_eq!(result["requested_category"], "work");
        assert_eq!(result["status"], "pending");
        assert!(result["request_id"].as_str().is_some_and(|id| id.starts_with("mr_")));

        let store = ctx.fact_store.read().await;
        let pending = list_pending_mint_requests(&store);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].requester_id, "codex-work");
        assert_eq!(pending[0].requested_by_passport, "codex-work");
        assert_eq!(pending[0].requested_category.as_deref(), Some("work"));
        assert_eq!(pending[0].reason.as_deref(), Some("Need a work passport"));
        assert!(
            !store.all_facts().any(|fact| fact.entity.starts_with("__passport__::")),
            "filing a mint request must never create a passport fact"
        );
    }

    #[tokio::test]
    async fn explicit_category_is_validated_and_normalized() {
        let ctx = openai_ctx(true);
        let result = handle_request_passport_mint(
            &json!({"requested_category": "PUBLIC", "reason": "Publish receipts"}),
            &ctx,
        )
        .await
        .unwrap();

        assert_eq!(result["requested_category"], "public");
        let store = ctx.fact_store.read().await;
        let pending = list_pending_mint_requests(&store);
        assert_eq!(pending[0].requested_category.as_deref(), Some("public"));
    }

    #[tokio::test]
    async fn custom_group_does_not_default_to_a_non_category() {
        let ctx = McpContext::new_default("test-node")
            .with_agent_passports(true, AgentPassportMap::from_pairs_str("openai:codex-research:research"))
            .with_passport_mint_requests(true)
            .with_agent(AgentIdentity {
                name: "openai".to_string(),
                token_hash: [0u8; 32],
            });

        let result = handle_request_passport_mint(&json!({}), &ctx).await.unwrap();
        assert!(result["requested_category"].is_null());
    }

    #[tokio::test]
    async fn flag_off_returns_method_not_found_without_filing() {
        let ctx = openai_ctx(false);
        let err = handle_request_passport_mint(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, METHOD_NOT_FOUND);

        let store = ctx.fact_store.read().await;
        assert!(list_pending_mint_requests(&store).is_empty());
        assert!(!store
            .all_facts()
            .any(|fact| fact.entity.starts_with("__mint_request__::")));
    }

    #[tokio::test]
    async fn anonymous_caller_is_rejected_without_filing() {
        let ctx = McpContext::new_default("test-node").with_passport_mint_requests(true);
        let err = handle_request_passport_mint(&json!({}), &ctx).await.unwrap_err();
        assert_eq!(err.code, INVALID_PARAMS);

        let store = ctx.fact_store.read().await;
        assert!(list_pending_mint_requests(&store).is_empty());
    }
}
