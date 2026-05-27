// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Dynamic MCP surface for installed community extensions.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::JsonRpcError;
use crate::tools::ToolDefinition;

const EXTENSION_ENTITY_PREFIX: &str = "__extension__::";
const EXTENSION_RECORD_KEY: &str = "record";
const GRANT_ENTITY_PREFIX: &str = "__extension_grant__::";
const GRANT_RECORD_KEY: &str = "record";

#[derive(Debug, Clone, Deserialize)]
struct InstalledExtension {
    manifest: crux_integrations::IntegrationManifest,
    manifest_hash: String,
    trust_tier: crux_integrations::TrustTier,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExtensionGrant {
    extension_id: String,
    passport_fpr: String,
    #[serde(default)]
    allowed_tool_names: Vec<String>,
    #[serde(default)]
    allowed_prefixes_read: Vec<String>,
    #[serde(default)]
    allowed_prefixes_write: Vec<String>,
}

pub async fn list_extension_tools(ctx: &McpContext) -> Vec<ToolDefinition> {
    let Some(passport_fpr) = calling_passport_fpr(ctx) else {
        return Vec::new();
    };
    let store = ctx.fact_store.read().await;
    let installed = installed_extensions(&store);
    let grants = grants_for_passport(&store, &passport_fpr);
    drop(store);

    let mut tools = Vec::new();
    for grant in grants {
        let Some(extension) = installed.iter().find(|e| e.manifest.id == grant.extension_id) else {
            continue;
        };
        for tool in &extension.manifest.tools {
            if !grant.allowed_tool_names.is_empty() && !grant.allowed_tool_names.iter().any(|name| name == &tool.name) {
                continue;
            }
            let mut input_schema = tool.input_schema.clone();
            if let Some(schema) = input_schema.as_object_mut() {
                schema.insert(
                    "x-crux-extension".to_string(),
                    json!({
                        "extension_id": extension.manifest.id,
                        "manifest_hash": extension.manifest_hash,
                        "trust_tier": trust_tier_slug(extension.trust_tier),
                        "rcx_capability": rcx_capability_name(&tool.name),
                    }),
                );
                schema.insert(
                    "x-crux-consequence-metadata".to_string(),
                    tool.consequence_metadata
                        .clone()
                        .unwrap_or_else(|| corecrux_memory::action_enrichment::metadata_for_tool_value(&tool.name)),
                );
            }
            tools.push(ToolDefinition {
                name: tool.name.clone(),
                description: format!(
                    "[local][extension:{}][trust:{:?}] {}",
                    extension.manifest.id, extension.trust_tier, tool.description
                ),
                input_schema,
            });
        }
    }
    tools.sort_by(|a, b| a.name.cmp(&b.name));
    tools
}

pub async fn call_extension_tool(name: &str, args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let Some(passport_fpr) = calling_passport_fpr(ctx) else {
        return Err(JsonRpcError {
            code: crate::protocol::INVALID_PARAMS,
            message: "extension tool call requires an RCX passport-bound context".to_string(),
            data: None,
        });
    };
    let store = ctx.fact_store.read().await;
    let installed = installed_extensions(&store);
    let extension_id = installed
        .iter()
        .find(|extension| extension.manifest.tools.iter().any(|tool| tool.name == name))
        .map(|extension| extension.manifest.id.clone());
    drop(store);
    let Some(extension_id) = extension_id else {
        return Err(JsonRpcError {
            code: crate::protocol::METHOD_NOT_FOUND,
            message: format!("unknown extension tool: {name}"),
            data: None,
        });
    };
    let Some(base_url) = ctx.daemon_base_url.clone() else {
        return Err(JsonRpcError {
            code: crate::protocol::METHOD_NOT_FOUND,
            message: "daemon loopback URL is not configured for extension dispatch".to_string(),
            data: None,
        });
    };
    let url = format!(
        "{}/v1/extensions/{}/tools/{}/invoke",
        base_url.trim_end_matches('/'),
        extension_id,
        name
    );
    let body = json!({
        "passport_fpr": passport_fpr,
        "args": args,
    });
    let bearer = crate::tools::loopback_auth::loopback_bearer_token();
    let response = tokio::task::spawn_blocking(move || {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .build()
            .into();
        let mut req = agent
            .post(&url)
            // `X-Corecrux-Scopes` covers `AuthMode::DevScopes`; bearer covers
            // JWT modes (see `tools::loopback_auth`).
            .header("X-Corecrux-Scopes", "admin:read facts:write")
            .header("Content-Type", "application/json");
        if let Some(token) = &bearer {
            req = req.header("Authorization", &format!("Bearer {token}"));
        }
        req.send_json(body)
            .map_err(|err| err.to_string())
            .and_then(|mut resp| resp.body_mut().read_json::<Value>().map_err(|err| err.to_string()))
    })
    .await
    .map_err(|err| JsonRpcError {
        code: crate::protocol::INTERNAL_ERROR,
        message: format!("extension dispatch join error: {err}"),
        data: None,
    })?;

    match response {
        Ok(value) => Ok(json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string()),
            }],
            "_meta": {
                "crux": {
                    "extension_id": extension_id,
                    "rcx_capability": rcx_capability_name(name),
                }
            }
        })),
        Err(message) => Err(JsonRpcError {
            code: crate::protocol::INTERNAL_ERROR,
            message: format!("extension dispatch failed: {message}"),
            data: None,
        }),
    }
}

pub fn rcx_capability_name(tool_name: &str) -> String {
    format!("crux-extension.{tool_name}")
}

pub fn is_extension_tool_name(tool_name: &str) -> bool {
    tool_name.starts_with("ext.")
}

fn trust_tier_slug(tier: crux_integrations::TrustTier) -> &'static str {
    match tier {
        crux_integrations::TrustTier::FirstParty => "first_party",
        crux_integrations::TrustTier::LocallySigned => "locally_signed",
        crux_integrations::TrustTier::CommunityReviewed => "community_reviewed",
        crux_integrations::TrustTier::Unknown => "unknown",
    }
}

fn calling_passport_fpr(ctx: &McpContext) -> Option<String> {
    ctx.rcx_router
        .as_ref()
        .map(|router| router.token().subject.passport_fpr.clone())
        .or_else(|| ctx.agent.as_ref().map(|agent| agent.name.clone()))
        .filter(|value| !value.trim().is_empty())
}

fn installed_extensions(store: &corecrux_memory::FactStore) -> Vec<InstalledExtension> {
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        query: None,
        entity: None,
        entity_prefix: Some(EXTENSION_ENTITY_PREFIX.to_string()),
        top_k: 500,
        token_budget: None,
    });
    dedup_latest(result.facts)
        .into_iter()
        .filter(|fact| fact.key == EXTENSION_RECORD_KEY && !fact.value.is_empty())
        .filter_map(|fact| serde_json::from_str::<InstalledExtension>(&fact.value).ok())
        .collect()
}

fn grants_for_passport(store: &corecrux_memory::FactStore, passport_fpr: &str) -> Vec<ExtensionGrant> {
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        query: None,
        entity: None,
        entity_prefix: Some(GRANT_ENTITY_PREFIX.to_string()),
        top_k: 5_000,
        token_budget: None,
    });
    dedup_latest(result.facts)
        .into_iter()
        .filter(|fact| fact.key == GRANT_RECORD_KEY && !fact.value.is_empty())
        .filter_map(|fact| serde_json::from_str::<ExtensionGrant>(&fact.value).ok())
        .filter(|grant| grant.passport_fpr == passport_fpr)
        .collect()
}

fn dedup_latest(facts: Vec<corecrux_memory::fact_store::Fact>) -> Vec<corecrux_memory::fact_store::Fact> {
    let mut by_key = std::collections::BTreeMap::<(String, String), corecrux_memory::fact_store::Fact>::new();
    for fact in facts {
        let key = (fact.entity.clone(), fact.key.clone());
        let replace = by_key
            .get(&key)
            .is_none_or(|existing| fact.stored_at >= existing.stored_at);
        if replace {
            by_key.insert(key, fact);
        }
    }
    by_key.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use corecrux_memory::fact_store::StoreFact;
    use crux_router::{mint_free_local_token, RcxRouter};
    use rcx_capability_token::RCX_CT_SIGNATURE_LEN;

    const TEST_PASSPORT: &str = "p_0123456789abcdef0123456789abcdef";

    #[test]
    fn rcx_capability_name_is_stable() {
        assert_eq!(
            rcx_capability_name("ext.example.quote.daily"),
            "crux-extension.ext.example.quote.daily"
        );
    }

    #[tokio::test]
    async fn dynamic_extension_tools_are_grant_and_rcx_filtered() {
        let ctx = rcx_ctx(vec!["crux-extension.ext.example.quote.daily"]);
        seed_extension_and_grant(&ctx).await;

        let listed = crate::tools::list_tools_json_for_context(&ctx, 1_776_989_601).await;
        let tools = listed["tools"].as_array().expect("tools array");
        assert!(tools.iter().any(|tool| {
            tool["name"] == "ext.example.quote.daily"
                && tool["inputSchema"]["x-crux-extension"]["extension_id"] == "ext.example.quote"
                && tool["inputSchema"]["x-crux-extension"]["trust_tier"] == "locally_signed"
                && tool["inputSchema"]["x-crux-extension"]["rcx_capability"] == "crux-extension.ext.example.quote.daily"
        }));
        assert!(!tools.iter().any(|tool| tool["name"] == "ext.example.quote.admin"));
    }

    fn rcx_ctx(capabilities: Vec<&str>) -> McpContext {
        McpContext::new_default("test-node").with_rcx_router(RcxRouter::new(mint_free_local_token(
            TEST_PASSPORT,
            "daemon_01HV0000000000000000000000",
            "default",
            capabilities.into_iter().map(str::to_string).collect(),
            1_776_989_000,
            1_776_990_000,
            [0x22; RCX_CT_SIGNATURE_LEN],
        )))
    }

    async fn seed_extension_and_grant(ctx: &McpContext) {
        let installed = json!({
            "manifest": {
                "schema": crux_integrations::INTEGRATION_SCHEMA_V1,
                "id": "ext.example.quote",
                "name": "Quote Example",
                "version": "1.0.0",
                "publisher_passport_fpr": "p_publisher",
                "summary": "Test extension",
                "entry": {
                    "kind": "external_tool",
                    "path": "https://example.invalid/invoke"
                },
                "external_tool_endpoint": "https://example.invalid/invoke",
                "tools": [
                    {
                        "name": "ext.example.quote.daily",
                        "description": "Daily quote",
                        "input_schema": {"type": "object", "properties": {}}
                    },
                    {
                        "name": "ext.example.quote.admin",
                        "description": "Admin quote",
                        "input_schema": {"type": "object", "properties": {}}
                    }
                ]
            },
            "manifest_hash": "blake3:test",
            "trust_tier": "locally_signed",
            "installed_at_unix_ms": 1
        });
        let grant = json!({
            "extension_id": "ext.example.quote",
            "passport_fpr": TEST_PASSPORT,
            "allowed_tool_names": ["ext.example.quote.daily"],
            "allowed_prefixes_read": [],
            "allowed_prefixes_write": [],
            "granted_at_unix_ms": 1
        });
        let mut store = ctx.fact_store.write().await;
        store.store(StoreFact {
            entity: "__extension__::ext.example.quote".to_string(),
            key: "record".to_string(),
            value: serde_json::to_string(&installed).expect("installed json"),
            source_receipt: Some("test".to_string()),
            confidence: 1.0,
            private: true,
        });
        store.store(StoreFact {
            entity: format!("__extension_grant__::ext.example.quote::{TEST_PASSPORT}"),
            key: "record".to_string(),
            value: serde_json::to_string(&grant).expect("grant json"),
            source_receipt: Some("test".to_string()),
            confidence: 1.0,
            private: true,
        });
    }
}
