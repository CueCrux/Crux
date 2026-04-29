// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! MCP method dispatcher — routes JSON-RPC requests to handlers.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use crux_router::{CallContext, RcxRouter};
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

pub const CAPABILITY_DENIED: i32 = -32030;

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
    /// Loopback URL of the corecruxd daemon for internal HTTP calls
    /// (currently only the `cuecrux_session` tool in M3). `None` disables
    /// loopback and the tool reports `service_unavailable`.
    pub daemon_base_url: Option<String>,
    /// Optional RCX router for token-gated MCP catalogue and tool dispatch.
    pub rcx_router: Option<Arc<RcxRouter>>,
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
            daemon_base_url: None,
            rcx_router: None,
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
            daemon_base_url: None,
            rcx_router: None,
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
            daemon_base_url: self.daemon_base_url.clone(),
            rcx_router: self.rcx_router.clone(),
        }
    }

    /// Configure the loopback URL used by tools that call back into the
    /// corecruxd HTTP server (e.g., `cuecrux_session`).
    pub fn with_daemon_base_url(mut self, url: impl Into<String>) -> Self {
        self.daemon_base_url = Some(url.into());
        self
    }

    pub fn with_rcx_router(mut self, router: RcxRouter) -> Self {
        self.rcx_router = Some(Arc::new(router));
        self
    }

    pub fn with_shared_rcx_router(mut self, router: Arc<RcxRouter>) -> Self {
        self.rcx_router = Some(router);
        self
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
        "tools/list" => {
            let result = ctx.rcx_router.as_ref().map_or_else(tools::list_tools_json, |router| {
                tools::list_tools_json_for_rcx_router(router, current_unix_seconds())
            });
            JsonRpcResponse::success(req.id, result)
        }

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

    if let Some(resp) = enforce_rcx_tool_capability(id.clone(), name, ctx) {
        return resp;
    }

    let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));

    match tools::call_tool(name, &args, ctx).await {
        Ok(result) => JsonRpcResponse::success(id, result),
        Err(e) => JsonRpcResponse::error(id, e.code, e.message),
    }
}

fn enforce_rcx_tool_capability(id: Option<serde_json::Value>, name: &str, ctx: &McpContext) -> Option<JsonRpcResponse> {
    let router = ctx.rcx_router.as_ref()?;
    let tool = tools::rcx_mcp_tool_capability(name);
    let decision = router.decide(
        &CallContext {
            capability: tool.capability,
            preferred_backend: Some(tool.backend_id),
            data_egress_classes: tool.data_egress_classes,
            estimated_credit_cost: 0,
            backend_reachable: true,
        },
        current_unix_seconds(),
    );

    if decision.authorised {
        return None;
    }

    let refusal_receipt = decision.refusal_receipt.as_ref().map(|receipt| {
        json!({
            "event_type": &receipt.event_type,
            "token_id": &receipt.token_id,
            "token_hash": &receipt.token_hash,
            "capability": &receipt.capability,
            "backend_id": &receipt.backend_id,
            "data_egress_classes": &receipt.data_egress_classes,
            "reason_code": &receipt.reason_code,
            "receipt_class": &receipt.receipt_class,
        })
    });
    Some(JsonRpcResponse::error_with_data(
        id,
        CAPABILITY_DENIED,
        format!(
            "RCX capability denied: {}",
            decision.reason_code.as_deref().unwrap_or("denied:unknown")
        ),
        json!({
            "reason_code": decision.reason_code,
            "mode": decision.mode.as_str(),
            "token_id": decision.token_id,
            "token_hash": decision.token_hash,
            "stamp": {
                "header": &decision.stamp.header_name,
                "mode": &decision.stamp.mode,
                "reason_code": &decision.stamp.reason_code,
                "token_id": &decision.stamp.token_id,
                "token_hash": &decision.stamp.token_hash,
                "queue_ttl_seconds": &decision.stamp.queue_ttl_seconds,
            },
            "refusal_receipt": refusal_receipt,
        }),
    ))
}

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crux_router::{mint_free_local_token, RcxRouter};
    use rcx_capability_token::RCX_CT_SIGNATURE_LEN;
    use serde_json::json;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    fn rcx_ctx_with_capabilities(capabilities: Vec<&str>) -> McpContext {
        let now = current_unix_seconds();
        McpContext::new_default("test-node").with_rcx_router(RcxRouter::new(mint_free_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "default",
            capabilities.into_iter().map(str::to_string).collect(),
            now.saturating_sub(60),
            now.saturating_add(3600),
            [0x22; RCX_CT_SIGNATURE_LEN],
        )))
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
    async fn tools_list_filters_through_rcx_router() {
        let ctx = rcx_ctx_with_capabilities(vec!["crux-mcp.store_fact"]);
        let resp = dispatch(rpc("tools/list", json!({})), &ctx, None).await;
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();

        assert_eq!(names, vec!["store_fact"]);
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
    async fn tools_call_denied_by_rcx_router_returns_refusal_receipt() {
        let ctx = rcx_ctx_with_capabilities(vec!["crux-mcp.store_fact"]);
        let resp = dispatch(rpc("tools/call", json!({"name": "sync_status"})), &ctx, None).await;
        let err = resp.error.unwrap();

        assert_eq!(err.code, CAPABILITY_DENIED);
        let data = err.data.unwrap();
        assert_eq!(data["reason_code"], "denied:capability_not_permitted");
        assert_eq!(data["stamp"]["header"], "X-Crux-Mode");
        assert_eq!(data["stamp"]["mode"], "refused");
        assert_eq!(
            data["refusal_receipt"]["event_type"],
            "rcx.capability_token.call_refused.v1"
        );
        assert_eq!(data["refusal_receipt"]["capability"], "crux-mcp.sync_status");
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
