// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! MCP method dispatcher — routes JSON-RPC requests to handlers.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use crux_router::{CallContext, RcxRouter};
use rand::Rng;
use serde_json::json;
use tokio::sync::RwLock;
use tracing::warn;

use corecrux_memory::{EdgeStore, EntityStore, FactStore, KindRegistry, SessionStore};
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
    /// Daemon data directory — needed by tools that read on-disk artifacts
    /// the HTTP routes produced (e.g. observation JSONL files). `None` in
    /// test contexts; populated by `corecruxd::main` from `AppState.data_dir`.
    pub data_dir: Option<PathBuf>,
    /// Daemon's Ed25519 passport public key (hex). Needed by tools that
    /// verify signatures (e.g. `verify_observation`). `None` in test
    /// contexts; populated by `corecruxd::main` from `AppState.passport_public_key_hex`.
    pub passport_public_key_hex: Option<String>,
    /// Substrate entity store (Crux domain substrate, M1).
    pub entity_store: Arc<RwLock<EntityStore>>,
    /// Substrate edge store (Crux domain substrate, M1).
    pub edge_store: Arc<RwLock<EdgeStore>>,
    /// Substrate kind registry — populated at startup by lens crates.
    pub kind_registry: Arc<RwLock<KindRegistry>>,
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
            data_dir: None,
            passport_public_key_hex: None,
            entity_store: Arc::new(RwLock::new(EntityStore::new())),
            edge_store: Arc::new(RwLock::new(EdgeStore::new())),
            kind_registry: Arc::new(RwLock::new(KindRegistry::new())),
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
            data_dir: None,
            passport_public_key_hex: None,
            entity_store: Arc::new(RwLock::new(EntityStore::new())),
            edge_store: Arc::new(RwLock::new(EdgeStore::new())),
            kind_registry: Arc::new(RwLock::new(KindRegistry::new())),
        }
    }

    /// Attach shared substrate stores (entity / edge / kind registry).
    pub fn with_substrate(
        mut self,
        entity_store: Arc<RwLock<EntityStore>>,
        edge_store: Arc<RwLock<EdgeStore>>,
        kind_registry: Arc<RwLock<KindRegistry>>,
    ) -> Self {
        self.entity_store = entity_store;
        self.edge_store = edge_store;
        self.kind_registry = kind_registry;
        self
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
            data_dir: self.data_dir.clone(),
            passport_public_key_hex: self.passport_public_key_hex.clone(),
            entity_store: Arc::clone(&self.entity_store),
            edge_store: Arc::clone(&self.edge_store),
            kind_registry: Arc::clone(&self.kind_registry),
        }
    }

    /// Configure the loopback URL used by tools that call back into the
    /// corecruxd HTTP server (e.g., `cuecrux_session`).
    pub fn with_daemon_base_url(mut self, url: impl Into<String>) -> Self {
        self.daemon_base_url = Some(url.into());
        self
    }

    /// Configure the daemon data directory (used by observation-reading
    /// tools to locate the on-disk JSONL files).
    pub fn with_data_dir(mut self, data_dir: impl Into<PathBuf>) -> Self {
        self.data_dir = Some(data_dir.into());
        self
    }

    /// Configure the daemon's Ed25519 passport public key (hex). Used by
    /// signature-verifying tools.
    pub fn with_passport_public_key(mut self, hex: impl Into<String>) -> Self {
        self.passport_public_key_hex = Some(hex.into());
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
    rand::rng().fill_bytes(&mut seed);
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
            let result = tools::list_tools_json_for_context(ctx, current_unix_seconds()).await;
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
        Ok(result) => {
            let result = maybe_wrap_with_envelope(name, &args, ctx, result).await;
            JsonRpcResponse::success(id, result)
        }
        Err(e) => JsonRpcResponse::error(id, e.code, e.message),
    }
}

/// Conditionally wrap `payload` into the per-turn audit envelope.
///
/// Returns the raw `payload` unchanged unless ALL three conditions hold:
///
/// 1. [`crate::envelope::envelope_enabled`] (i.e. the
///    `CORECRUXD_FEATURE_AUDIT_ENVELOPE` flag is on).
/// 2. The tool is registered in
///    [`crate::tools::tool_emits_envelope`].
/// 3. A builder exists in
///    [`crate::envelope::build_envelope_for_tool`] for this tool.
///
/// Older agents that don't read `envelope` see exactly the legacy payload
/// shape any time any of these three conditions fails, preserving
/// backwards-compat (master-plan §11 — "Backwards compat. Older agents
/// that don't read the envelope field continue to work").
async fn maybe_wrap_with_envelope(
    name: &str,
    args: &serde_json::Value,
    ctx: &McpContext,
    payload: serde_json::Value,
) -> serde_json::Value {
    if !crate::envelope::envelope_enabled() {
        return payload;
    }
    if !tools::tool_emits_envelope(name) {
        return payload;
    }
    match crate::envelope::build_envelope_for_tool(name, args, ctx).await {
        Some(env) => env.wrap_payload(payload),
        None => payload,
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
            present_attestations: Vec::new(),
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
            "required_attestations": &receipt.required_attestations,
            "present_attestations": &receipt.present_attestations,
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

    // ── audit envelope (master ExecPlan agent-ux-best-in-class-master M2) ──

    /// Serialize all envelope-related dispatch tests so the process-wide
    /// `CORECRUXD_FEATURE_AUDIT_ENVELOPE` env var doesn't race between
    /// concurrent tokio tests. `tokio::sync::Mutex` is used so the guard
    /// can be safely held across `.await` boundaries.
    fn envelope_env_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    #[tokio::test]
    async fn envelope_off_query_facts_response_has_no_envelope_field() {
        let _guard = envelope_env_lock().lock().await;
        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
        let ctx = test_ctx();

        // Seed one fact so query_facts has something to return.
        dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "store_fact",
                    "arguments": {"entity": "p", "key": "k", "value": "v"}
                }),
            ),
            &ctx,
            None,
        )
        .await;

        let resp = dispatch(
            rpc(
                "tools/call",
                json!({"name": "query_facts", "arguments": {"query": "v"}}),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        // Backwards-compat: no envelope, payload shape unchanged
        // (content/text directly at the top level).
        assert!(
            result.get("envelope").is_none(),
            "envelope must be absent when flag is off"
        );
        assert!(
            result.get("payload").is_none(),
            "payload wrapper must be absent when flag is off"
        );
        assert!(result["content"][0]["text"].as_str().unwrap().contains('v'));
    }

    #[tokio::test]
    async fn envelope_on_query_facts_response_has_payload_and_envelope() {
        let _guard = envelope_env_lock().lock().await;
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        let ctx = test_ctx();

        dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "store_fact",
                    "arguments": {"entity": "alpha", "key": "status", "value": "shipped",
                                  "source_receipt": "r_test_001"}
                }),
            ),
            &ctx,
            None,
        )
        .await;

        let resp = dispatch(
            rpc(
                "tools/call",
                json!({"name": "query_facts", "arguments": {"query": "shipped"}}),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        // Both payload and envelope are present.
        assert!(result["payload"].is_object());
        assert!(result["envelope"].is_object());
        // Payload preserves the original tool response shape.
        assert!(result["payload"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("shipped"));
        // Envelope is populated.
        let env = &result["envelope"];
        assert_eq!(env["memories_used"][0]["topic"], "alpha");
        assert_eq!(env["memories_used"][0]["freshness"], "fresh");
        assert_eq!(env["receipts_used"][0], "r_test_001");
        assert_eq!(env["autonomy_consumed"]["capability"], "facts:read");
        assert_eq!(env["autonomy_consumed"]["cost_credits"], 0);
        assert!(env["predicted_effects"].as_array().unwrap().is_empty());
        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn envelope_on_other_tools_remain_unwrapped() {
        let _guard = envelope_env_lock().lock().await;
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        let ctx = test_ctx();

        // store_fact is NOT opted into envelope — must keep legacy shape.
        let resp = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "store_fact",
                    "arguments": {"entity": "p", "key": "k", "value": "v"}
                }),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        assert!(result.get("envelope").is_none());
        assert!(result.get("payload").is_none());
        assert!(result["content"][0]["text"]
            .as_str()
            .unwrap()
            .starts_with("stored fact"));
        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn envelope_on_query_facts_omits_reserved_prefix_entries() {
        let _guard = envelope_env_lock().lock().await;
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        let ctx = test_ctx();

        // Public + reserved-prefix facts both matching the query.
        for (entity, key) in [
            ("project-x", "status"),
            ("__ops::config-audit", "sha256:abc"),
            ("__bootstrap__::pattern:x", "Retry"),
        ] {
            dispatch(
                rpc(
                    "tools/call",
                    json!({
                        "name": "store_fact",
                        "arguments": {"entity": entity, "key": key, "value": "shipped"}
                    }),
                ),
                &ctx,
                None,
            )
            .await;
        }

        let resp = dispatch(
            rpc(
                "tools/call",
                json!({"name": "query_facts", "arguments": {"query": "shipped"}}),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        let env = &result["envelope"];
        let memories = env["memories_used"].as_array().unwrap();
        assert_eq!(
            memories.len(),
            1,
            "reserved-prefix entries must not be exposed in the envelope"
        );
        assert_eq!(memories[0]["topic"], "project-x");
        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn tools_call_store_and_query_facts() {
        // Share the envelope env-var lock so this test isn't racy with the
        // envelope_on_* tests that mutate CORECRUXD_FEATURE_AUDIT_ENVELOPE.
        let _guard = envelope_env_lock().lock().await;
        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
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
