// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! MCP method dispatcher — routes JSON-RPC requests to handlers.

use std::sync::Arc;

use base64::Engine as _;
use rand::RngCore;
use serde_json::json;
use tokio::sync::RwLock;
use tracing::warn;

use corecrux_memory::{FactStore, SessionStore};
use corecrux_retrieval::IndexManager;
use corecrux_types::UpdateStatus;

use crate::agent::{AgentIdentity, AgentRegistry};
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, INVALID_PARAMS, METHOD_NOT_FOUND};
use crate::tools;

/// Shared state passed to every MCP handler.
pub struct McpContext {
    /// Entity fact store.
    pub fact_store: Arc<RwLock<FactStore>>,
    /// Session state store.
    pub session_store: Arc<RwLock<SessionStore>>,
    /// Retrieval index (BM25 + graph fusion).
    pub retrieval_index: Arc<RwLock<IndexManager>>,
    /// Cached git-based update posture shared with HTTP surfaces.
    pub update_status: Arc<RwLock<UpdateStatus>>,
    /// Agent token registry for bearer-token auth.
    pub agent_registry: AgentRegistry,
    /// Identity of the calling agent for the current request (if authenticated).
    pub agent: Option<AgentIdentity>,
    /// Node identifier for this server instance.
    pub node_id: String,
    /// Server-local MAC key used to authenticate handoff packages.
    pub handoff_key: [u8; 32],
}

impl McpContext {
    /// Create a context with default (empty) stores — useful for tests.
    pub fn new_default(node_id: impl Into<String>) -> Self {
        let node_id = node_id.into();
        Self {
            fact_store: Arc::new(RwLock::new(FactStore::new())),
            session_store: Arc::new(RwLock::new(SessionStore::new())),
            retrieval_index: Arc::new(RwLock::new(IndexManager::new())),
            update_status: Arc::new(RwLock::new(UpdateStatus::default())),
            agent_registry: AgentRegistry::empty(),
            agent: None,
            handoff_key: default_handoff_key(&node_id),
            node_id,
        }
    }

    /// Create a context backed by shared stores from another runtime.
    pub fn new_shared(
        node_id: impl Into<String>,
        fact_store: Arc<RwLock<FactStore>>,
        session_store: Arc<RwLock<SessionStore>>,
        retrieval_index: Arc<RwLock<IndexManager>>,
        update_status: Arc<RwLock<UpdateStatus>>,
        agent_registry: AgentRegistry,
    ) -> Self {
        let node_id = node_id.into();
        Self {
            fact_store,
            session_store,
            retrieval_index,
            update_status,
            agent_registry,
            agent: None,
            handoff_key: default_handoff_key(&node_id),
            node_id,
        }
    }

    /// Return a copy of this context with the given agent identity attached.
    pub fn with_agent(&self, agent: AgentIdentity) -> Self {
        Self {
            fact_store: Arc::clone(&self.fact_store),
            session_store: Arc::clone(&self.session_store),
            retrieval_index: Arc::clone(&self.retrieval_index),
            update_status: Arc::clone(&self.update_status),
            agent_registry: self.agent_registry.clone(),
            agent: Some(agent),
            node_id: self.node_id.clone(),
            handoff_key: self.handoff_key,
        }
    }
}

impl std::fmt::Debug for McpContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpContext")
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
}

fn default_handoff_key(node_id: &str) -> [u8; 32] {
    if let Ok(secret) = std::env::var("CRUX_MCP_HANDOFF_SECRET") {
        return blake3::hash(secret.as_bytes()).into();
    }

    let mut seed = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let material = format!(
        "crux-mcp-handoff:{node_id}:{}",
        base64::engine::general_purpose::STANDARD.encode(seed)
    );
    blake3::hash(material.as_bytes()).into()
}

/// Protocol version advertised in `initialize` response.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// Server name returned in `initialize`.
pub const SERVER_NAME: &str = "crux";

/// Server version returned in `initialize`.
pub const SERVER_VERSION: &str = "0.1.0";

/// Route a JSON-RPC request to the appropriate handler.
pub async fn dispatch(req: JsonRpcRequest, ctx: &McpContext, _agent: Option<&AgentIdentity>) -> JsonRpcResponse {
    match req.method.as_str() {
        // ── MCP lifecycle ──────────────────────────────────────────────
        "initialize" => JsonRpcResponse::success(
            req.id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": SERVER_NAME,
                    "version": SERVER_VERSION
                },
                "_welcome": {
                    "hint": "Call get_bootstrap(\"patterns\") to learn usage patterns, then sync_status() before remote integration work and update_status() before maintenance work.",
                    "quickstart": [
                        "get_bootstrap(\"patterns\") — learn usage patterns",
                        "sync_status() — check whether this node is local-only or remote-sync capable",
                        "update_status() — check whether this checkout is behind or diverged before an upgrade",
                        "store_fact(entity, key, value) — store a fact",
                        "query_facts(query) — search facts"
                    ],
                    "docs": "https://github.com/CueCrux/Crux/blob/main/docs/agent-guide.md"
                }
            }),
        ),

        // Notification — no response required, but we return null result
        // so the HTTP layer can still send a 200.
        "notifications/initialized" => JsonRpcResponse::success(req.id, json!(null)),

        // ── Tool surface ───────────────────────────────────────────────
        "tools/list" => JsonRpcResponse::success(req.id, tools::list_tools_json()),

        "tools/call" => dispatch_tool_call(req.id.clone(), &req.params, ctx).await,

        // ── Fallback ───────────────────────────────────────────────────
        other => {
            warn!(method = other, "unknown MCP method");
            JsonRpcResponse::error(req.id, METHOD_NOT_FOUND, format!("method not found: {other}"))
        }
    }
}

/// Extract tool name + arguments from `tools/call` params and delegate.
async fn dispatch_tool_call(
    id: Option<serde_json::Value>,
    params: &serde_json::Value,
    ctx: &McpContext,
) -> JsonRpcResponse {
    let name = match params.get("name").and_then(|v| v.as_str()) {
        Some(n) => n,
        None => {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "tools/call requires a \"name\" parameter");
        }
    };

    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

    match tools::call_tool(name, &args, ctx).await {
        Ok(result) => JsonRpcResponse::success(id, result),
        Err(e) => JsonRpcResponse::error(id, e.code, e.message),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    fn rpc(method: &str, params: serde_json::Value) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: method.to_string(),
            params,
        }
    }

    #[tokio::test]
    async fn initialize_returns_protocol_version() {
        let ctx = test_ctx();
        let resp = dispatch(rpc("initialize", json!({})), &ctx, None).await;
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(result["serverInfo"]["name"], SERVER_NAME);
        assert_eq!(result["serverInfo"]["version"], SERVER_VERSION);
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[tokio::test]
    async fn notifications_initialized_returns_null() {
        let ctx = test_ctx();
        let resp = dispatch(rpc("notifications/initialized", json!(null)), &ctx, None).await;
        assert!(resp.error.is_none());
        assert_eq!(resp.result, Some(json!(null)));
    }

    #[tokio::test]
    async fn tools_list_returns_tools() {
        let ctx = test_ctx();
        let resp = dispatch(rpc("tools/list", json!({})), &ctx, None).await;
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(!tools.is_empty());

        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"query"));
        assert!(names.contains(&"store_fact"));
        assert!(names.contains(&"query_facts"));
        assert!(names.contains(&"get_session"));
        assert!(names.contains(&"update_status"));
    }

    #[tokio::test]
    async fn unknown_method_returns_error() {
        let ctx = test_ctx();
        let resp = dispatch(rpc("bogus/method", json!({})), &ctx, None).await;
        assert!(resp.result.is_none());
        let err = resp.error.unwrap();
        assert_eq!(err.code, METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn tools_call_get_gaps() {
        let ctx = test_ctx();
        let resp = dispatch(rpc("tools/call", json!({"name": "get_gaps"})), &ctx, None).await;
        // get_gaps on empty store returns no-gaps message.
        assert!(resp.error.is_none());
    }

    #[tokio::test]
    async fn tools_call_missing_name() {
        let ctx = test_ctx();
        let resp = dispatch(rpc("tools/call", json!({})), &ctx, None).await;
        let err = resp.error.unwrap();
        assert_eq!(err.code, INVALID_PARAMS);
    }

    #[tokio::test]
    async fn tools_call_unknown_tool() {
        let ctx = test_ctx();
        let resp = dispatch(rpc("tools/call", json!({"name": "nonexistent"})), &ctx, None).await;
        let err = resp.error.unwrap();
        assert_eq!(err.code, METHOD_NOT_FOUND);
        assert!(err.message.contains("unknown tool"));
    }

    #[tokio::test]
    async fn tools_call_store_and_query_facts() {
        let ctx = test_ctx();

        // Store a fact
        let resp = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "store_fact",
                    "arguments": {
                        "entity": "project",
                        "key": "name",
                        "value": "CueCrux"
                    }
                }),
            ),
            &ctx,
            None,
        )
        .await;
        assert!(resp.error.is_none());
        let text = resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
        assert!(text.starts_with("stored fact f_"));

        // Query it
        let resp = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "query_facts",
                    "arguments": {
                        "query": "CueCrux",
                        "entity": "project"
                    }
                }),
            ),
            &ctx,
            None,
        )
        .await;
        assert!(resp.error.is_none());
        let text = resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
        assert!(text.contains("CueCrux"));
    }
}
