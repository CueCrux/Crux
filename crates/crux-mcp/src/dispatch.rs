// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
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

use corecrux_memory::{ArtefactStore, EdgeStore, EntityStore, FactStore, KindRegistry, SessionStore};
use corecrux_retrieval::IndexManager;
use corecrux_types::UpdateStatus;

use crate::agent::{AgentIdentity, AgentRegistry};
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, INVALID_PARAMS, METHOD_NOT_FOUND};
use crate::tools;

pub const CAPABILITY_DENIED: i32 = -32030;

/// Shared state passed to every MCP handler.
///
/// `Clone` is shallow: all stores are `Arc`-shared handles, so a clone is a
/// second view onto the same state (used by `corecruxd` to hand one context
/// to both the MCP router and the HTTP OpenAI tools shim — single source).
#[derive(Clone)]
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
    /// Content-addressed artefact store (agent-ux-12, calm deferred output).
    /// In-memory; opt-in for tools that want to park large payloads off-chat.
    pub artefact_store: Arc<RwLock<ArtefactStore>>,
    /// Feature flag (`CORECRUXD_AGENT_PASSPORTS`, default OFF): when true,
    /// `store_fact` resolves the calling agent's token-name to a passport_id
    /// via [`McpContext::agent_passport_map`] and stamps it as the fact's
    /// `actor` (agent-passport M1). When false, behaviour is byte-for-byte
    /// the pre-M1 path (no actor written, no mapping applied).
    pub agent_passports_enabled: bool,
    /// Feature flag (`CORECRUXD_FEATURE_PASSPORT_MINT_REQUESTS`, default OFF):
    /// exposes the self-scoped `request_passport_mint` tool and permits it to
    /// file a pending operator-approval request. Independent from
    /// `agent_passports_enabled`; it never mints a passport itself.
    pub passport_mint_requests_enabled: bool,
    /// Agent→passport mapping consulted only when `agent_passports_enabled`
    /// is true. Empty by default so a stray value cannot change behaviour
    /// while the flag is off.
    pub agent_passport_map: crate::agent_passport::AgentPassportMap,
    /// passport-revocation M3: when true, `call_tool` refuses calls from a
    /// REVOKED passport (except a tiny read-only allowlist so the agent can
    /// learn it was revoked — M4). Wired from `corecruxd::main` off
    /// `CRUX_PASSPORT_REVOCATION` — **launch default ON**; `=0` disables enforcement.
    pub revocation_enforced: bool,
}

/// passport-revocation M3: read the `CRUX_PASSPORT_REVOCATION` flag. Launch
/// default ON (proven live) — a revoked passport is reduced to read-only.
/// On a fresh install nothing is revoked, so enforcement is a no-op until a
/// revocation is issued. Explicit `CRUX_PASSPORT_REVOCATION=0` disables it.
/// `corecruxd::main` threads the result into
/// [`McpContext::with_revocation_enforced`].
pub fn revocation_enforced_from_env() -> bool {
    std::env::var("CRUX_PASSPORT_REVOCATION")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
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
            artefact_store: Arc::new(RwLock::new(ArtefactStore::new())),
            // Flag OFF + empty map by default: every existing test sees the
            // pre-M1 behaviour (no actor stamped) unless it opts in via
            // `with_agent_passports`.
            agent_passports_enabled: false,
            passport_mint_requests_enabled: false,
            agent_passport_map: crate::agent_passport::AgentPassportMap::empty(),
            revocation_enforced: false,
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
            artefact_store: Arc::new(RwLock::new(ArtefactStore::new())),
            agent_passports_enabled: false,
            passport_mint_requests_enabled: false,
            agent_passport_map: crate::agent_passport::AgentPassportMap::empty(),
            revocation_enforced: false,
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

    /// Attach a shared artefact store (agent-ux-12). When unset the context
    /// uses its own in-process instance, which is fine for tests but means
    /// HTTP and MCP would see different stores in prod — `corecruxd::main`
    /// is the wiring point.
    pub fn with_artefact_store(mut self, artefact_store: Arc<RwLock<ArtefactStore>>) -> Self {
        self.artefact_store = artefact_store;
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
            artefact_store: Arc::clone(&self.artefact_store),
            agent_passports_enabled: self.agent_passports_enabled,
            passport_mint_requests_enabled: self.passport_mint_requests_enabled,
            agent_passport_map: self.agent_passport_map.clone(),
            revocation_enforced: self.revocation_enforced,
        }
    }

    /// Configure the agent→passport feature (agent-passport M1). When
    /// `enabled` is true, `store_fact` resolves the calling agent name to a
    /// passport_id via `map` and stamps it as the fact `actor`. Wired from
    /// `corecruxd::main` off the `CORECRUXD_AGENT_PASSPORTS` flag; tests use
    /// it directly to exercise the flag-ON path.
    pub fn with_agent_passports(mut self, enabled: bool, map: crate::agent_passport::AgentPassportMap) -> Self {
        self.agent_passports_enabled = enabled;
        self.agent_passport_map = map;
        self
    }

    /// Configure filing of self-scoped passport-mint approval requests.
    /// The default is OFF; tests and daemon startup wire it explicitly.
    pub fn with_passport_mint_requests(mut self, enabled: bool) -> Self {
        self.passport_mint_requests_enabled = enabled;
        self
    }

    /// passport-revocation M3: enable/disable refusal of revoked passports'
    /// calls. Wired from `corecruxd::main` off `CRUX_PASSPORT_REVOCATION`; tests
    /// use it directly to exercise the flag-ON path without a process-global env.
    pub fn with_revocation_enforced(mut self, enabled: bool) -> Self {
        self.revocation_enforced = enabled;
        self
    }

    /// Resolve the *scope identity* used for private-fact ownership and
    /// visibility (agent-passport M5). This is the single string threaded into
    /// every `scope::*` call.
    ///
    /// * **Flag OFF (default):** the raw agent token-name (`anthropic`,
    ///   `alice`, …) — byte-for-byte the pre-M5 behaviour. `scope::*` keys
    ///   private facts under `__agent::<name>::` exactly as before.
    /// * **Flag ON:** the resolved passport_id (`anthropic` → `claude-work`),
    ///   so a private fact's owner key agrees with the M1 `actor` stamp and the
    ///   M4 tenant-group. An unmapped name falls back to the raw name so a
    ///   flag-ON private write is never keyed wrongly (mirrors the QC.3
    ///   never-anonymous rule on `actor`).
    ///
    /// Returns `None` for an unauthenticated caller (no agent identity) under
    /// either flag state — anonymous callers have no private scope.
    pub fn scope_identity(&self) -> Option<String> {
        let name = self.agent.as_ref()?.name.as_str();
        if self.agent_passports_enabled {
            Some(
                crate::agent_passport::resolve_agent_passport(name, &self.agent_passport_map)
                    .unwrap_or_else(|| name.to_string()),
            )
        } else {
            Some(name.to_string())
        }
    }

    /// Back-compat alias names for the caller's private-fact ownership under
    /// flag-ON (agent-passport M5). Empty when the flag is off (no rekeying
    /// happened, so no alias is needed).
    ///
    /// When the flag is ON the *current* writes are keyed by [`Self::scope_identity`]
    /// (the passport_id). But private facts written while the flag was OFF were
    /// keyed by the raw agent token-name. To keep those legacy private facts
    /// visible to their original owner (and ONLY their original owner) after the
    /// flag flips, the raw token-name is returned here as an alias. The read
    /// helpers (`scope::*_for_identity`) match a private fact's owner against the
    /// identity OR any alias.
    ///
    /// The alias is the caller's OWN raw name only — never another agent's — so
    /// it can never widen visibility to a different principal.
    pub fn scope_aliases(&self) -> Vec<String> {
        match (&self.agent, self.agent_passports_enabled) {
            (Some(agent), true) => {
                // Only an alias when the resolved identity actually differs
                // from the raw name (i.e. the name was remapped). When the
                // name is unmapped, identity == raw name and no alias is
                // needed.
                let raw = agent.name.as_str();
                match self.scope_identity() {
                    Some(id) if id != raw => vec![raw.to_string()],
                    _ => Vec::new(),
                }
            }
            _ => Vec::new(),
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

/// Server version returned in `initialize`. Sourced from the crate version
/// (`[workspace.package].version`), which is kept in lock-step with the release
/// tag — so MCP `initialize`, `/v1/version`, and the agent card all report the
/// same release version instead of three drifting strings.
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Route a JSON-RPC request to the appropriate handler.
pub async fn dispatch(req: JsonRpcRequest, ctx: &McpContext, _agent: Option<&AgentIdentity>) -> JsonRpcResponse {
    match req.method.as_str() {
        // ── MCP lifecycle ──────────────────────────────────────────────
        "initialize" => JsonRpcResponse::success(
            req.id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {
                    // `listChanged` (M3.5): the server can push
                    // `notifications/tools/list_changed` over an SSE stream
                    // (GET /mcp, Accept: text/event-stream) when the dynamic
                    // surface is reshaped. Additive — clients that ignore it
                    // simply re-list on their own cadence.
                    "tools": { "listChanged": true }
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

        // Notification — no response is required. The HTTP layer
        // (`handle_mcp_post`) short-circuits notifications (`id` is `None`) to an
        // empty `202 Accepted` before dispatch is reached, so this arm is a
        // defensive fallback for any non-HTTP caller; it returns a null result.
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
    let turn_id = args.get("turn_id").and_then(|v| v.as_str()).map(|s| s.to_string());

    // Emit an OTel-bridged tracing span around the dispatch when enabled
    // (agent-ux-06 M4). The bridging via `tracing-opentelemetry` is wired
    // in `corecruxd::main`; we keep this side lightweight (no direct
    // `opentelemetry` dep in crux-mcp) so the MCP crate stays sync-able.
    crate::otel::record_tool_span_start(name, ctx.agent.as_ref().map(|a| a.name.as_str()));

    let started = std::time::Instant::now();
    let outcome = tools::call_tool(name, &args, ctx).await;
    let latency = started.elapsed();

    // agent-ux-06 M2/M3: record into the per-passport trace ring.
    let trace_outcome = if outcome.is_ok() {
        crate::traces::TraceOutcome::Ok
    } else {
        crate::traces::TraceOutcome::Error
    };
    let passport = crate::scope::agent_name(ctx.agent.as_ref())
        .unwrap_or(crate::traces::ANON_PASSPORT)
        .to_string();
    let predicted = build_predicted_effects(name, &args);

    // action-ledger M1: per-passport token accounting. Estimates ride a
    // counting writer (no allocation) so this stays cheap on the hot path.
    let est_in = crate::token_estimate::estimate_tokens(&args);
    let (est_out, result_bytes) = match &outcome {
        Ok(v) => (
            crate::token_estimate::estimate_tokens(v),
            crate::token_estimate::serialized_len(v),
        ),
        Err(e) => (
            crate::token_estimate::estimate_tokens_str(&e.message),
            e.message.len() as u64,
        ),
    };
    let declared_budget = args.get("token_budget").and_then(|v| v.as_u64());
    crate::token_accounting::record_usage(&passport, est_in, est_out, declared_budget).await;

    // action-ledger M2: per-tool metrics (always on; tool label is
    // cardinality-guarded — unresolved names collapse to "unknown") and
    // the durable agent.tool_invocation.v1 ledger event (flag-gated,
    // fire-and-forget on the observations stream).
    let known_tool = !matches!(&outcome, Err(e) if e.code == crate::protocol::METHOD_NOT_FOUND);
    let metric_tool = if known_tool { name } else { "unknown" };
    crate::ledger::record_dispatch_metrics(metric_tool, outcome.is_ok(), latency, est_in + est_out);
    if crate::ledger::ledger_enabled() {
        let body = crate::ledger::build_event_body(&crate::ledger::InvocationRecord {
            tool: metric_tool,
            passport: &passport,
            turn_id: turn_id.as_deref(),
            args: &args,
            est_tokens_in: est_in,
            est_tokens_out: est_out,
            result_bytes,
            token_budget_in: declared_budget,
            latency_ms: latency.as_millis() as u64,
            outcome_ok: outcome.is_ok(),
            request_id: id.as_ref(),
            predicted_effects: &predicted,
        });
        crate::ledger::emit(ctx.daemon_base_url.clone(), &passport, body);
    }

    // M4: record the canonical signature + response-token estimate alongside the
    // trace so `crux learn` can mine the ring for looping re-fetches. Both ride
    // data already computed on this path (`args`, `est_out`).
    let learn_signature = crate::learn::canonical_signature(name, &args);
    crate::traces::record_dispatch_metered(
        &passport,
        name,
        turn_id.as_deref(),
        Some(learn_signature),
        Some(est_out),
        predicted,
        trace_outcome,
    )
    .await;

    match outcome {
        Ok(result) => {
            let result = maybe_wrap_with_envelope(name, &args, ctx, result).await;
            // MCP-spec guard (agent-ux M3 bugfix): every tools/call result
            // must keep `result.content` at the top level. `wrap_payload`
            // already emits the spec shape, but normalise defensively here
            // so any residual legacy `{payload, envelope}` value is lifted
            // (and never double-wrapped) before it reaches the client.
            let result = crate::envelope::normalize_result_shape(result);
            JsonRpcResponse::success(id, result)
        }
        Err(e) => JsonRpcResponse::error(id, e.code, e.message),
    }
}

/// Synthesise typed predicted effects for the trace ring based on
/// well-known tool names + their args. Read-only tools emit a
/// `fact_read`/`tool_dispatch` entry; mutating tools emit `fact_write`,
/// `forget`, or `receipt_emit`. This stays a cheap lookup — the trace
/// ring's purpose is observability, not full IR analysis.
fn build_predicted_effects(name: &str, args: &serde_json::Value) -> Vec<crate::envelope::PredictedEffect> {
    use crate::envelope::PredictedEffect;
    let entity = args.get("entity").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let key = args.get("key").and_then(|v| v.as_str()).unwrap_or("").to_string();
    match name {
        "store_fact" | "entity_upsert" | "edge_upsert" | "save_session" | "archive_session" | "unarchive_session" => {
            vec![PredictedEffect::now("fact_write", entity, key)]
        }
        "delete_fact" | "entity_delete" | "edge_delete" | "delete_session" => {
            vec![PredictedEffect::now("forget", entity, key)]
        }
        "memory_forget" | "memory_forget_dry_run" => {
            vec![PredictedEffect::now("forget", entity, key)]
        }
        "memory_acknowledge_use" | "create_handoff" | "accept_handoff" | "record_decision" => {
            vec![PredictedEffect::now("receipt_emit", entity, key)]
        }
        "query_facts" | "query" | "query_scan" | "query_expand" | "fact_history" => {
            vec![PredictedEffect::now("fact_read", entity, key)]
        }
        _ => vec![PredictedEffect::now("tool_dispatch", entity, key)],
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
    // Capture the capability before it moves into CallContext so a denial of a
    // metered service scope can carry an upsell hint (M3). Free local lanes are
    // never service scopes, so this is null for ordinary denials.
    let denied_capability = tool.capability.clone();
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
                "revocation_checked": decision.stamp.revocation_checked,
            },
            "refusal_receipt": refusal_receipt,
            // Metered-service denials carry an upsell; null for free/local lanes (M3).
            "upgrade_hint": crate::tools::upsell::upgrade_hint(&denied_capability),
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
    use ed25519_dalek::{Signer, SigningKey};
    use rcx_capability_token::RCX_CT_SIGNATURE_LEN;
    use serde_json::json;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    fn rcx_ctx_with_capabilities(capabilities: Vec<&str>) -> McpContext {
        let now = current_unix_seconds();
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let mut token = mint_free_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "default",
            capabilities.into_iter().map(str::to_string).collect(),
            now.saturating_sub(60),
            now.saturating_add(3600),
            [0x22; RCX_CT_SIGNATURE_LEN],
        );
        token.signature.sig = signing.sign(&token.token_hash()).to_bytes();
        McpContext::new_default("test-node").with_rcx_router(RcxRouter::new_with_trusted_issuer_pubkey(
            token,
            signing.verifying_key().to_bytes(),
        ))
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
    async fn shaped_out_tool_is_still_dispatchable_c3() {
        // C3 (dynamic-tool-surface): a tool absent from the `minimal` advertised
        // surface stays callable via `tools/call` — dispatch is by-name and
        // never consults the surface mode. `list_sessions` is deliberately NOT
        // in CORE_FLOOR, yet must still route (not "unknown tool"). This is the
        // safety property that makes surface truncation lossless.
        use crate::tools::surface::{apply_surface_mode, ToolSurfaceMode, CORE_FLOOR};
        assert!(
            !CORE_FLOOR.contains(&"list_sessions"),
            "test premise: list_sessions must be a non-floor tool"
        );
        let minimal = apply_surface_mode(crate::tools::list_tools(), ToolSurfaceMode::Minimal);
        assert!(
            !minimal.iter().any(|t| t.name == "list_sessions"),
            "list_sessions should be shaped out of the minimal surface"
        );
        let ctx = test_ctx();
        let resp = dispatch(
            rpc("tools/call", json!({ "name": "list_sessions", "arguments": {} })),
            &ctx,
            None,
        )
        .await;
        if let Some(err) = resp.error {
            assert!(
                !err.message.contains("unknown tool"),
                "dispatch must still route a shaped-out tool, got: {}",
                err.message
            );
        }
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
    /// concurrent tokio tests. Delegates to [`crate::test_env_lock`] so
    /// every env-mutating test in this crate shares one process-wide
    /// `tokio::sync::Mutex` (see that function's doc for the rationale).
    fn envelope_env_lock() -> &'static tokio::sync::Mutex<()> {
        crate::test_env_lock()
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
    async fn envelope_on_query_facts_response_is_spec_shaped_and_carries_envelope() {
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
        // MCP-spec shape: top-level `content` must be present and non-empty
        // (the bug placed the receipt at the top level and left no
        // top-level content, making the tool invisible to clients).
        assert!(
            result.get("payload").is_none(),
            "result must NOT use the non-standard top-level payload wrapper"
        );
        assert!(
            result.get("envelope").is_none(),
            "envelope must NOT sit at the top level shadowing content"
        );
        assert!(
            result["content"].as_array().map(|a| !a.is_empty()).unwrap_or(false),
            "result.content must be a non-empty array; got {result:#?}"
        );
        assert!(result["content"][0]["text"].as_str().unwrap().contains("shipped"));
        // The audit envelope is preserved under structuredContent.envelope
        // (and mirrored under _meta.envelope).
        let env = &result["structuredContent"]["envelope"];
        assert!(env.is_object(), "envelope must be folded into structuredContent");
        assert_eq!(env["memories_used"][0]["topic"], "alpha");
        assert_eq!(env["memories_used"][0]["freshness"], "fresh");
        assert_eq!(env["receipts_used"][0], "r_test_001");
        assert_eq!(env["autonomy_consumed"]["capability"], "facts:read");
        assert_eq!(env["autonomy_consumed"]["cost_credits"], 0);
        assert!(env["predicted_effects"].as_array().unwrap().is_empty());
        // Mirrored under _meta for audit consumers that look there.
        assert_eq!(result["_meta"]["envelope"]["receipts_used"][0], "r_test_001");
        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
    }

    /// Cross-PR envelope-contract sibling for agent-ux-11. The
    /// `audit_export_bundle` tool is an audit-export surface — the bundle
    /// IS the receipts artefact. The per-turn envelope (which is a
    /// memory-query rationale) doesn't naturally apply, so the master
    /// plan asks us to explicitly assert the negative: even with the
    /// feature flag ON, `audit_export_bundle` must NOT emit an
    /// `envelope` field.
    #[tokio::test]
    async fn envelope_omits_for_audit_export() {
        let _guard = envelope_env_lock().lock().await;
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        std::env::set_var(crate::tools::audit_export::FEATURE_FLAG_ENV, "1");
        let td = tempfile::tempdir().unwrap();
        std::env::set_var(crate::tools::audit_export::EXPORT_DIR_ENV, td.path());

        let ctx = test_ctx().with_agent(AgentIdentity {
            name: "operator-1".to_string(),
            token_hash: [0u8; 32],
        });

        // Seed one fact so the export has something to write.
        dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "store_fact",
                    "arguments": {"entity": "project-x", "key": "k", "value": "v"}
                }),
            ),
            &ctx,
            None,
        )
        .await;

        let resp = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "audit_export_bundle",
                    "arguments": {"token_budget": 1000}
                }),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.expect("audit_export_bundle returned no result");
        assert!(
            result.get("envelope").is_none(),
            "audit_export_bundle MUST NOT emit envelope (the bundle IS the receipts) — got {result:#?}"
        );
        assert!(
            result.get("payload").is_none(),
            "audit_export_bundle MUST NOT be wrapped in payload (the bundle IS the receipts) — got {result:#?}"
        );
        // The raw response shape stays intact.
        assert!(result["bundle_id"].is_string());
        assert!(result["bytes_path"].is_string());

        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
        std::env::remove_var(crate::tools::audit_export::FEATURE_FLAG_ENV);
        std::env::remove_var(crate::tools::audit_export::EXPORT_DIR_ENV);
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

    /// `autonomy_contract` (agent-ux-10) is metadata-only — it MUST NOT
    /// participate in the audit-envelope wrapper. Pinning this with a
    /// dispatch-level test makes any accidental opt-in (e.g. someone adds
    /// "autonomy_contract" to `tool_emits_envelope`) fail loud, matching
    /// the child plan's "cross-PR envelope-test interaction" gate.
    #[tokio::test]
    async fn envelope_omits_for_autonomy_contract() {
        let _guard = envelope_env_lock().lock().await;
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        std::env::set_var(crate::tools::autonomy::FEATURE_FLAG_ENV, "1");
        let ctx = test_ctx();

        let resp = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "autonomy_contract",
                    "arguments": {"token_budget": 4000}
                }),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        assert!(
            result.get("envelope").is_none(),
            "autonomy_contract must NOT emit an envelope (metadata-only tool); got {result}"
        );
        assert!(
            result.get("payload").is_none(),
            "autonomy_contract must NOT use the payload/envelope wrapper shape"
        );
        // Tool still returns its own structuredContent under the legacy
        // shape — assert the matrix made it through.
        assert!(result["structuredContent"].is_object());

        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
        std::env::remove_var(crate::tools::autonomy::FEATURE_FLAG_ENV);
    }

    // Sibling envelope-omits tests for agent-ux-05 (risk-tiered HITL).
    // Both `approval_request` and `approval_decide` are write tools that
    // must NOT opt into `tool_emits_envelope` — verifying via dispatch
    // keeps the cross-PR contract green if a future change ever flips
    // the registry by accident.
    #[tokio::test]
    async fn envelope_omits_for_approval_request() {
        // Single crate-wide env lock — every per-module lock helper in
        // this crate now delegates to `crate::test_env_lock`, so the
        // single `envelope_env_lock` acquisition also serialises against
        // approvals/freshness/artefacts/identity/output_attest tests.
        let _guard = envelope_env_lock().lock().await;
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        std::env::set_var(crate::tools::approvals::FEATURE_FLAG_ENV, "1");
        crate::tools::approvals::_reset_requests_buffer_for_tests().await;

        // approval_request requires an authenticated passport; attach an
        // agent identity exactly the way the memory_acknowledge_use test
        // does (master plan sibling).
        let ctx = test_ctx().with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });

        let resp = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "approval_request",
                    "arguments": {
                        "action_summary": "drop fixtures",
                        "risk_tier": "high",
                        "scope": "tenant-env",
                        "tenant_id": "tenant-env",
                        "token_budget": 500
                    }
                }),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        assert!(
            result.get("envelope").is_none(),
            "approval_request MUST NOT emit envelope (write tool)"
        );
        assert!(
            result.get("payload").is_none(),
            "approval_request MUST NOT wrap response in payload"
        );
        std::env::remove_var(crate::tools::approvals::FEATURE_FLAG_ENV);
        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn envelope_omits_for_approval_decide() {
        // Single crate-wide env lock; see the sibling
        // `envelope_omits_for_approval_request` comment for rationale.
        let _guard = envelope_env_lock().lock().await;
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        std::env::set_var(crate::tools::approvals::FEATURE_FLAG_ENV, "1");
        crate::tools::approvals::_reset_requests_buffer_for_tests().await;

        let ctx = test_ctx().with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });

        // Seed a request so approval_decide has a target.
        let req_resp = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "approval_request",
                    "arguments": {
                        "action_summary": "drop fixtures",
                        "risk_tier": "high",
                        "scope": "tenant-env-2",
                        "tenant_id": "tenant-env-2",
                        "token_budget": 500
                    }
                }),
            ),
            &ctx,
            None,
        )
        .await;
        let rid = req_resp.result.unwrap()["request_id"].as_str().unwrap().to_string();

        let resp = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "approval_decide",
                    "arguments": {
                        "request_id": rid,
                        "decision": "approve",
                        "reviewer_tier": "elite",
                        "reviewer_tenant_id": "tenant-env-2"
                    }
                }),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        assert!(
            result.get("envelope").is_none(),
            "approval_decide MUST NOT emit envelope (write tool)"
        );
        assert!(
            result.get("payload").is_none(),
            "approval_decide MUST NOT wrap response in payload"
        );
        std::env::remove_var(crate::tools::approvals::FEATURE_FLAG_ENV);
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
        let env = &result["structuredContent"]["envelope"];
        let memories = env["memories_used"].as_array().unwrap();
        assert_eq!(
            memories.len(),
            1,
            "reserved-prefix entries must not be exposed in the envelope"
        );
        assert_eq!(memories[0]["topic"], "project-x");
        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
    }

    /// Sibling envelope-filter contract for `memory_acknowledge_use`
    /// (agent-ux-02). Mirrors the contract enforced by
    /// `envelope_on_query_facts_omits_reserved_prefix_entries` so the
    /// merge-result test the master plan asks every new envelope-emitting
    /// tool to honour stays green for this surface too.
    #[tokio::test]
    async fn envelope_on_memory_acknowledge_use_omits_reserved_prefix_entries() {
        let _guard = envelope_env_lock().lock().await;
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        std::env::set_var(crate::tools::memory_use::FEATURE_FLAG_ENV, "1");
        crate::tools::memory_use::_reset_ack_buffer_for_tests().await;

        // memory_acknowledge_use requires a passport — attach an agent.
        let ctx = test_ctx().with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });

        // Seed one public + two reserved-prefix facts. Capture each fact_id
        // so we can pass them into the ack tool.
        let mut ids: Vec<String> = Vec::new();
        for (entity, key) in [
            ("project-y", "status"),
            ("__ops::config-audit", "sha256:ack"),
            ("__bootstrap__::pattern:retry", "Retry"),
        ] {
            let resp = dispatch(
                rpc(
                    "tools/call",
                    json!({
                        "name": "store_fact",
                        "arguments": {"entity": entity, "key": key, "value": "shipped-ack"}
                    }),
                ),
                &ctx,
                None,
            )
            .await;
            let text = resp.result.unwrap()["content"][0]["text"].as_str().unwrap().to_string();
            // "stored fact f_xxx (entity=..., key=..., ..."
            let id = text
                .trim_start_matches("stored fact ")
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            ids.push(id);
        }

        let resp = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "memory_acknowledge_use",
                    "arguments": {
                        "turn_id": "turn-envtest",
                        "intent": "answer",
                        "fact_ids": ids,
                    }
                }),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        // The envelope wrapper engages because (a) feature flag on, (b) the
        // tool is in `tool_emits_envelope`, (c) the per-tool builder is
        // registered. After M3 normalisation the result is MCP-spec shaped:
        // content at the top level, envelope folded under structuredContent.
        assert!(
            result["content"].as_array().map(|a| !a.is_empty()).unwrap_or(false),
            "ack result.content must be a non-empty array; got {result:#?}"
        );
        let env = &result["structuredContent"]["envelope"];
        let memories = env["memories_used"].as_array().unwrap();
        assert_eq!(
            memories.len(),
            1,
            "ack envelope must strip reserved-prefix entries (got {} entries)",
            memories.len()
        );
        assert_eq!(memories[0]["topic"], "project-y");
        for m in memories {
            let topic = m["topic"].as_str().unwrap();
            assert!(!topic.starts_with("__"), "ack envelope leaked reserved entity {topic}");
        }
        // autonomy_consumed identifies the capability as memory:acknowledge,
        // not facts:read — proves the per-tool envelope builder ran (not the
        // query_facts one).
        assert_eq!(env["autonomy_consumed"]["capability"], "memory:acknowledge");

        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
        std::env::remove_var(crate::tools::memory_use::FEATURE_FLAG_ENV);
    }

    /// Sibling envelope-filter contract for `receipt_verify` (agent-ux-04).
    ///
    /// `receipt_verify` is intentionally NOT in
    /// [`crate::tools::tool_emits_envelope`] — it's a verifier, not a memory
    /// retrieval, so it has no `memories_used[]` to filter. This test pins
    /// that contract so a future change that flips the opt-in must also
    /// rewire the envelope builder.
    ///
    /// Symmetric to `envelope_on_query_facts_omits_reserved_prefix_entries`
    /// and `envelope_on_memory_acknowledge_use_omits_reserved_prefix_entries`:
    /// every new envelope-eligible tool the master plan adds gets its own
    /// reserved-prefix sibling, even if that tool's contract is "no
    /// envelope at all".
    #[tokio::test]
    async fn envelope_on_receipt_verify_omits_reserved_prefix_entries() {
        let _guard = envelope_env_lock().lock().await;
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        // Receipt-verify flag stays OFF — the handler must short-circuit to
        // a "feature disabled" payload without hitting the loopback, AND the
        // dispatcher must NOT wrap the response in an envelope (because the
        // tool isn't opted in).
        std::env::remove_var(crate::tools::receipt_verify::FEATURE_FLAG_ENV);
        let ctx = test_ctx().with_agent(crate::agent::AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });

        // Seed a reserved-prefix fact in the store. If the dispatcher ever
        // wrongly opts receipt_verify into the envelope, the reserved-prefix
        // filter contract would have to apply here too — but the envelope
        // must not appear in the first place.
        dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "store_fact",
                    "arguments": {"entity": "__ops::config-audit", "key": "sha256:abc", "value": "x"}
                }),
            ),
            &ctx,
            None,
        )
        .await;

        let resp = dispatch(
            rpc(
                "tools/call",
                json!({"name": "receipt_verify", "arguments": {"receipt_id": "r_does_not_matter"}}),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        // Contract 1: no envelope wrapper (tool is not opted in).
        assert!(
            result.get("envelope").is_none(),
            "receipt_verify must not be wrapped in an envelope (got {result:?})"
        );
        assert!(
            result.get("payload").is_none(),
            "receipt_verify response must keep the legacy unwrapped shape"
        );
        // Contract 2: with the flag off, payload is the disabled stub.
        assert_eq!(result["feature_enabled"], false);
        assert_eq!(result["verified"], false);
        assert_eq!(result["errors"][0], "FEATURE_DISABLED");
        // Contract 3: the response never carries an entity name from the
        // reserved-prefix fact we seeded (defence in depth — the tool has
        // nothing to do with the fact store, but proving it stays that way
        // pins the invariant).
        let payload_str = result.to_string();
        assert!(
            !payload_str.contains("__ops::"),
            "receipt_verify response leaked reserved-prefix entity name: {payload_str}"
        );

        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn envelope_on_memory_freshness_omits_reserved_prefix_entries() {
        // Sibling test for agent-ux-03 M3: memory_freshness is the second
        // tool opted into the envelope. Same reserved-prefix filter must
        // apply or the envelope leaks ops/agent state. See
        // dispatch::tests::envelope_on_query_facts_omits_reserved_prefix_entries
        // for the original spike contract.
        //
        // Single crate-wide env lock — `freshness::tests_support_flag_lock`
        // now delegates to `crate::test_env_lock`, the same mutex as
        // `envelope_env_lock`, so one acquisition suffices.
        let _guard = envelope_env_lock().lock().await;
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        std::env::set_var(crate::tools::freshness::FEATURE_FLAG_ENV, "1");
        let ctx = test_ctx();
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
                json!({"name": "memory_freshness", "arguments": {"top_k": 50, "token_budget": 1000}}),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        // MCP-spec shape after the M3 normalisation: content lives at the
        // top level, the envelope is folded under structuredContent.envelope.
        assert!(
            result["content"].as_array().map(|a| !a.is_empty()).unwrap_or(false),
            "memory_freshness result.content must be a non-empty array; got {result:#?}"
        );
        let env = &result["structuredContent"]["envelope"];
        let memories = env["memories_used"].as_array().unwrap();
        assert_eq!(
            memories.len(),
            1,
            "memory_freshness envelope must filter reserved-prefix entries"
        );
        assert_eq!(memories[0]["topic"], "project-x");

        // The tool payload (now lifted to the top level) must also not leak
        // reserved entries.
        let rows = result["structuredContent"]["rows"].as_array().unwrap();
        for r in rows {
            let ent = r["entity"].as_str().unwrap();
            assert!(
                !ent.starts_with("__ops::") && !ent.starts_with("__bootstrap__::") && !ent.starts_with("__agent::"),
                "payload leaked reserved entity {ent}"
            );
        }
        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
        std::env::remove_var(crate::tools::freshness::FEATURE_FLAG_ENV);
    }

    /// Sibling envelope-filter contract for `artefact_list` (agent-ux-12).
    /// Mirrors `envelope_on_query_facts_omits_reserved_prefix_entries`: the
    /// envelope's `memories_used[]` must never expose a reserved-prefix
    /// mime_type, even though the underlying artefact store can hold them
    /// (reserved-prefix mime entries are filtered at list time too — this
    /// test is the master-plan-mandated defence-in-depth probe).
    #[tokio::test]
    async fn envelope_on_artefact_list_omits_reserved_prefix_entries() {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;

        // Single crate-wide env lock — `artefacts::artefact_flag_lock`
        // now delegates to `crate::test_env_lock`, same mutex as
        // `envelope_env_lock`, so one acquisition suffices.
        let _guard = envelope_env_lock().lock().await;
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        std::env::set_var(crate::tools::artefacts::FEATURE_FLAG_ENV, "1");

        let ctx = test_ctx().with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });

        // One public + two reserved-prefix mime artefacts under the same
        // passport. Only the public one may appear in the envelope.
        for (mime, body) in [
            ("text/plain", "alpha"),
            ("__ops::secret", "must-not-leak"),
            ("__bootstrap__::seed", "must-not-leak-either"),
        ] {
            let resp = dispatch(
                rpc(
                    "tools/call",
                    json!({
                        "name": "artefact_put",
                        "arguments": {
                            "mime_type": mime,
                            "content_bytes_base64": B64.encode(body.as_bytes()),
                        }
                    }),
                ),
                &ctx,
                None,
            )
            .await;
            assert!(resp.error.is_none(), "artefact_put err: {:?}", resp.error);
        }

        let resp = dispatch(
            rpc(
                "tools/call",
                json!({"name": "artefact_list", "arguments": {"top_k": 20}}),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        // Envelope wrapper engaged because (a) flag on, (b) opted in via
        // tool_emits_envelope, (c) per-tool builder is registered. After M3
        // normalisation the result is MCP-spec shaped: content at the top
        // level, envelope folded under structuredContent.
        assert!(
            result["content"].as_array().map(|a| !a.is_empty()).unwrap_or(false),
            "artefact_list result.content must be a non-empty array; got {result:#?}"
        );
        let env = &result["structuredContent"]["envelope"];
        let memories = env["memories_used"].as_array().unwrap();
        assert_eq!(
            memories.len(),
            1,
            "artefact_list envelope must strip reserved-prefix mime entries (got {} entries)",
            memories.len()
        );
        assert_eq!(memories[0]["topic"], "text/plain");
        for m in memories {
            let topic = m["topic"].as_str().unwrap();
            assert!(
                !topic.starts_with("__"),
                "artefact_list envelope leaked reserved mime {topic}"
            );
        }
        assert_eq!(env["autonomy_consumed"]["capability"], "artefacts:read");

        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
        std::env::remove_var(crate::tools::artefacts::FEATURE_FLAG_ENV);
    }

    /// Sibling omit-test: artefact_put and artefact_get do NOT opt into the
    /// envelope wrapper. They handle opaque bytes (writes/reads of
    /// arbitrary content) and would emit too much chatter if wrapped — the
    /// envelope is for memory-adjacent surfaces only.
    #[tokio::test]
    async fn envelope_on_artefact_put_get_remain_unwrapped() {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;

        // Single crate-wide env lock; see the sibling
        // `envelope_on_artefact_list_omits_reserved_prefix_entries` comment.
        let _guard = envelope_env_lock().lock().await;
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        std::env::set_var(crate::tools::artefacts::FEATURE_FLAG_ENV, "1");

        let ctx = test_ctx().with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });

        // artefact_put — must keep legacy shape.
        let resp = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "artefact_put",
                    "arguments": {
                        "mime_type": "text/plain",
                        "content_bytes_base64": B64.encode(b"no-envelope-here"),
                    }
                }),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        assert!(
            result.get("envelope").is_none(),
            "artefact_put must NOT carry an envelope wrapper"
        );
        assert!(result.get("payload").is_none());
        let id = result["structuredContent"]["artefact_id"].as_str().unwrap().to_string();

        // artefact_get — also must keep legacy shape.
        let resp = dispatch(
            rpc(
                "tools/call",
                json!({"name": "artefact_get", "arguments": {"artefact_id": id}}),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        assert!(
            result.get("envelope").is_none(),
            "artefact_get must NOT carry an envelope wrapper"
        );
        assert!(result.get("payload").is_none());

        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
        std::env::remove_var(crate::tools::artefacts::FEATURE_FLAG_ENV);
    }

    /// Sibling envelope-omission test for `output_attest` (agent-ux-07).
    /// The attestation tool is a write of a NEW receipt class — it must
    /// NOT opt into the per-turn audit envelope, mirroring the rule the
    /// master ExecPlan documents in §"Cross-PR envelope-test interaction".
    #[tokio::test]
    async fn envelope_omits_for_output_attest() {
        // Single crate-wide env lock — `output_attest::tests::flag_lock`
        // now delegates to `crate::test_env_lock`, the same mutex as
        // `envelope_env_lock`. The resolver tests in `tools::output_attest`
        // also serialise on the same lock, so the cross-suite race that
        // used to require two acquisitions is now covered by one.
        let _guard = envelope_env_lock().lock().await;
        // Defensive belt-and-braces: clear the signer resolver inputs
        // in case any earlier test panicked between set and reset.
        std::env::remove_var("CORECRUX_C2PA_SIGNER");
        std::env::remove_var(crate::tools::output_attest::X509_FEATURE_FLAG_ENV);
        std::env::remove_var(crate::tools::output_attest::BACKEND_ENV);
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        std::env::set_var(crate::tools::output_attest::FEATURE_FLAG_ENV, "1");
        // Provide a signer key + key id for the round-trip path.
        let secret = [0x22u8; 32];
        std::env::set_var(
            "CORECRUXD_WRITE_CONFIRMATION_SIGNING_KEY_B64",
            base64::engine::general_purpose::STANDARD.encode(secret),
        );
        std::env::set_var("CORECRUXD_WRITE_CONFIRMATION_KEY_ID", "envtest-key");

        let ctx = test_ctx().with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });
        let payload_b64 = base64::engine::general_purpose::STANDARD.encode(b"some-attested-bytes");
        let resp = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "output_attest",
                    "arguments": {
                        "content_bytes_base64": payload_b64,
                        "receipt_id": "r_envtest",
                        "content_type": "image/png"
                    }
                }),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        // output_attest is NOT in tool_emits_envelope → response shape stays legacy.
        assert!(
            result.get("envelope").is_none(),
            "output_attest must not emit an envelope: got {result}"
        );
        assert!(
            result.get("payload").is_none(),
            "output_attest must not be wrapped: got {result}"
        );
        // The manifest payload is still present at the top level.
        assert!(result["manifest"]["manifest_id"].is_string());
        assert_eq!(result["manifest"]["crown_receipt_id"], "r_envtest");

        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
        std::env::remove_var(crate::tools::output_attest::FEATURE_FLAG_ENV);
        std::env::remove_var("CORECRUXD_WRITE_CONFIRMATION_SIGNING_KEY_B64");
        std::env::remove_var("CORECRUXD_WRITE_CONFIRMATION_KEY_ID");
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

    // ── agent-ux-06: typed action traces ─────────────────────────────────
    //
    // Sibling tests to `envelope_on_query_facts_omits_reserved_prefix_entries`
    // (cross-PR envelope contract). Both assertions in the master plan's
    // acceptance criteria — reserved-prefix filtering + per-passport
    // isolation — exercised end-to-end through `dispatch_tool_call`.

    #[tokio::test]
    async fn envelope_traces_filter_reserved_prefixes() {
        let _g = crate::traces::test_env_lock().lock().await;
        std::env::set_var(crate::traces::FEATURE_FLAG_ENV, "1");

        // Unique passport — tokio tests share the trace store; isolating
        // by passport prevents cross-test pollution.
        let ctx = test_ctx().with_agent(AgentIdentity {
            name: "dispatch-envelope-traces-filter".to_string(),
            token_hash: [0u8; 32],
        });

        // Write to a reserved-prefix entity through the real dispatch path.
        let _ = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "store_fact",
                    "arguments": {"entity": "__ops::config-audit", "key": "sha256:abc", "value": "v"}
                }),
            ),
            &ctx,
            None,
        )
        .await;
        // And one public write so the trace ring has at least one survivor.
        let _ = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "store_fact",
                    "arguments": {"entity": "project-traces", "key": "status", "value": "v"}
                }),
            ),
            &ctx,
            None,
        )
        .await;

        let resp = dispatch(
            rpc(
                "tools/call",
                json!({"name": "tool_trace_recent", "arguments": {"top_k": 50, "token_budget": 2000}}),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        let traces = result["traces"].as_array().unwrap();
        // Every recorded predicted_effect must NOT be a reserved-prefix entity.
        for t in traces {
            for eff in t["predicted_effects"].as_array().unwrap_or(&Vec::new()) {
                let entity = eff["entity"].as_str().unwrap_or("");
                assert!(
                    !crate::envelope::is_reserved_entity(entity),
                    "trace leaked reserved entity {entity}"
                );
            }
        }
        std::env::remove_var(crate::traces::FEATURE_FLAG_ENV);
    }

    #[tokio::test]
    async fn envelope_traces_per_passport_isolated() {
        let _g = crate::traces::test_env_lock().lock().await;
        std::env::set_var(crate::traces::FEATURE_FLAG_ENV, "1");

        let alice = test_ctx().with_agent(AgentIdentity {
            name: "dispatch-envelope-traces-alice".to_string(),
            token_hash: [0u8; 32],
        });
        let bob = test_ctx().with_agent(AgentIdentity {
            name: "dispatch-envelope-traces-bob".to_string(),
            token_hash: [0u8; 32],
        });

        // Alice writes one fact; Bob writes another.
        let _ = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "store_fact",
                    "arguments": {"entity": "alice-only", "key": "k", "value": "v"}
                }),
            ),
            &alice,
            None,
        )
        .await;
        let _ = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "store_fact",
                    "arguments": {"entity": "bob-only", "key": "k", "value": "v"}
                }),
            ),
            &bob,
            None,
        )
        .await;

        // Alice reads traces — should not see Bob's entries.
        let resp = dispatch(
            rpc("tools/call", json!({"name": "tool_trace_recent", "arguments": {}})),
            &alice,
            None,
        )
        .await;
        let traces = resp.result.unwrap()["traces"].as_array().unwrap().clone();
        for t in &traces {
            for eff in t["predicted_effects"].as_array().unwrap_or(&Vec::new()) {
                let entity = eff["entity"].as_str().unwrap_or("");
                assert_ne!(entity, "bob-only", "alice leaked bob's trace");
            }
        }
        // Bob symmetric check.
        let resp = dispatch(
            rpc("tools/call", json!({"name": "tool_trace_recent", "arguments": {}})),
            &bob,
            None,
        )
        .await;
        let traces = resp.result.unwrap()["traces"].as_array().unwrap().clone();
        for t in &traces {
            for eff in t["predicted_effects"].as_array().unwrap_or(&Vec::new()) {
                let entity = eff["entity"].as_str().unwrap_or("");
                assert_ne!(entity, "alice-only", "bob leaked alice's trace");
            }
        }
        std::env::remove_var(crate::traces::FEATURE_FLAG_ENV);
    }

    // ── envelope opt-out for identity-continuity (agent-ux-08) ──
    //
    // The three identity-continuity tools (passport_split, passport_merge,
    // passport_link_device) MUST NOT be opted into the audit-envelope
    // wrapper — they are writes, not reads, so the envelope (which is
    // shaped for memory-use accountability) would be inappropriate. The
    // tests below assert the dispatcher leaves their responses unwrapped
    // even when CORECRUXD_FEATURE_AUDIT_ENVELOPE=1.
    //
    // Each tool can short-circuit before the dispatcher runs the envelope
    // logic (e.g. feature flag off, missing token_budget). What matters
    // for the envelope contract is the JsonRpcResponse SHAPE: when the
    // tool returns successfully, the response MUST NOT carry `envelope`
    // or `payload` wrappers.

    #[tokio::test]
    async fn envelope_omits_for_passport_split() {
        // Single crate-wide env lock — `identity::tests::flag_lock`
        // now delegates to `crate::test_env_lock`, same mutex as
        // `envelope_env_lock`, so one acquisition suffices.
        let _guard = envelope_env_lock().lock().await;
        // Use the explicit env var name to avoid taking another import.
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        std::env::set_var("CORECRUXD_FEATURE_IDENTITY_CONTINUITY", "1");

        let ctx = test_ctx().with_agent(AgentIdentity {
            name: "personal::alice".to_string(),
            token_hash: [0u8; 32],
        });
        // Promote to operator-tier (trusted) by issuing a passport then
        // seeding 500 receipt-backed facts.
        dispatch(
            rpc("tools/call", json!({"name": "issue_passport", "arguments": {}})),
            &ctx,
            None,
        )
        .await;
        {
            let mut store = ctx.fact_store.write().await;
            for i in 0..500 {
                store.store(corecrux_memory::fact_store::StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: format!("seed-{i}"),
                    key: "k".to_string(),
                    value: "v".to_string(),
                    source_receipt: Some(format!("receipt-{i}")),
                    confidence: 1.0,
                    private: false,
                    horizon_class: None,
                    actor: None,
                });
            }
        }
        // Refresh tier.
        dispatch(
            rpc("tools/call", json!({"name": "get_passport", "arguments": {}})),
            &ctx,
            None,
        )
        .await;

        let resp = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "passport_split",
                    "arguments": {
                        "target_passport": "personal::alice",
                        "new_passport_name": "personal::alice-work",
                        "reason": "envelope opt-out test",
                        "token_budget": 500,
                    }
                }),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        assert!(
            result.get("envelope").is_none(),
            "passport_split must not be wrapped in audit envelope"
        );
        assert!(
            result.get("payload").is_none(),
            "passport_split must keep legacy payload shape"
        );
        // Sanity: real handler ran.
        assert_eq!(result["new_passport_id"], "personal::alice-work");

        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
        std::env::remove_var("CORECRUXD_FEATURE_IDENTITY_CONTINUITY");
    }

    #[tokio::test]
    async fn envelope_omits_for_passport_merge() {
        // Single crate-wide env lock; see the sibling
        // `envelope_omits_for_passport_split` comment for rationale.
        let _guard = envelope_env_lock().lock().await;
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        std::env::set_var("CORECRUXD_FEATURE_IDENTITY_CONTINUITY", "1");

        let ctx = test_ctx().with_agent(AgentIdentity {
            name: "personal::alice".to_string(),
            token_hash: [0u8; 32],
        });
        dispatch(
            rpc("tools/call", json!({"name": "issue_passport", "arguments": {}})),
            &ctx,
            None,
        )
        .await;
        {
            let mut store = ctx.fact_store.write().await;
            for i in 0..500 {
                store.store(corecrux_memory::fact_store::StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: format!("seed-{i}"),
                    key: "k".to_string(),
                    value: "v".to_string(),
                    source_receipt: Some(format!("receipt-{i}")),
                    confidence: 1.0,
                    private: false,
                    horizon_class: None,
                    actor: None,
                });
            }
            // Pre-seed the source passport under the same tenant so the
            // merge call succeeds.
            use crate::tools::passport::PassportRecord;
            store.store(corecrux_memory::fact_store::StoreFact {
                tenant_hash: "default".to_string(),
                entity: "__passport__::personal::alice-old".to_string(),
                key: "passport".to_string(),
                value: serde_json::to_string(&PassportRecord {
                    principal_id: "personal::alice-old".to_string(),
                    sponsor_id: None,
                    reputation_tier: "trusted".to_string(),
                    receipt_count: 500,
                    issued_at: "2026-05-28T00:00:00Z".to_string(),
                    passport_hash: "deadbeef".to_string(),
                    tenant_group: None,
                    revoked_at: None,
                    revoked_reason: None,
                })
                .unwrap(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }
        dispatch(
            rpc("tools/call", json!({"name": "get_passport", "arguments": {}})),
            &ctx,
            None,
        )
        .await;

        let resp = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "passport_merge",
                    "arguments": {
                        "source_passport": "personal::alice-old",
                        "target_passport": "personal::alice",
                        "conflict_policy": "prefer_target",
                        "reason": "envelope opt-out test",
                        "token_budget": 500,
                    }
                }),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        assert!(
            result.get("envelope").is_none(),
            "passport_merge must not be wrapped in audit envelope"
        );
        assert!(
            result.get("payload").is_none(),
            "passport_merge must keep legacy payload shape"
        );
        assert_eq!(result["merged_passport_id"], "personal::alice");

        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
        std::env::remove_var("CORECRUXD_FEATURE_IDENTITY_CONTINUITY");
    }

    #[tokio::test]
    async fn envelope_omits_for_passport_link_device() {
        // Single crate-wide env lock; see the sibling
        // `envelope_omits_for_passport_split` comment for rationale.
        let _guard = envelope_env_lock().lock().await;
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        std::env::set_var("CORECRUXD_FEATURE_IDENTITY_CONTINUITY", "1");

        let ctx = test_ctx().with_agent(AgentIdentity {
            name: "personal::alice".to_string(),
            token_hash: [0u8; 32],
        });
        dispatch(
            rpc("tools/call", json!({"name": "issue_passport", "arguments": {}})),
            &ctx,
            None,
        )
        .await;
        {
            let mut store = ctx.fact_store.write().await;
            for i in 0..500 {
                store.store(corecrux_memory::fact_store::StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: format!("seed-{i}"),
                    key: "k".to_string(),
                    value: "v".to_string(),
                    source_receipt: Some(format!("receipt-{i}")),
                    confidence: 1.0,
                    private: false,
                    horizon_class: None,
                    actor: None,
                });
            }
        }
        dispatch(
            rpc("tools/call", json!({"name": "get_passport", "arguments": {}})),
            &ctx,
            None,
        )
        .await;

        let fp = blake3::hash(b"laptop-envelope-test").to_hex().to_string();
        let resp = dispatch(
            rpc(
                "tools/call",
                json!({
                    "name": "passport_link_device",
                    "arguments": {
                        "device_fingerprint": fp,
                        "capabilities_subset": ["facts:read"],
                        "token_budget": 500,
                    }
                }),
            ),
            &ctx,
            None,
        )
        .await;
        let result = resp.result.unwrap();
        assert!(
            result.get("envelope").is_none(),
            "passport_link_device must not be wrapped in audit envelope"
        );
        assert!(
            result.get("payload").is_none(),
            "passport_link_device must keep legacy payload shape"
        );
        assert_eq!(result["passport_id"], "personal::alice");

        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
        std::env::remove_var("CORECRUXD_FEATURE_IDENTITY_CONTINUITY");
    }

    // ── MCP response-shape contract (CI guard) ──────────────────────────
    //
    // Drives EVERY registered MCP tool through `dispatch` (hermetic, no
    // live daemon) and asserts the JSON-RPC `result` is spec-shaped:
    // a non-empty top-level `content` array with NO top-level `payload`
    // or `envelope` keys. This is the regression guard for the bug class
    // fixed in `envelope.rs::normalize_result_shape` (the
    // `{payload, envelope}` legacy wrapper that left no top-level
    // `content` and made the tool invisible to MCP clients).

    /// Pure shape-check used by the contract test AND unit-tested directly
    /// on a known-good and a deliberately-broken value (so the guard is
    /// proven able to fail). A spec-shaped `tools/call` result has a
    /// non-empty top-level `content` array and carries neither a top-level
    /// `payload` nor a top-level `envelope` key.
    fn result_is_spec_shaped(result: &serde_json::Value) -> Result<(), String> {
        if result.get("payload").is_some() {
            return Err("has top-level `payload` (legacy wrapper)".to_string());
        }
        if result.get("envelope").is_some() {
            return Err("has top-level `envelope` (shadows content)".to_string());
        }
        match result.get("content").and_then(|c| c.as_array()) {
            Some(arr) if !arr.is_empty() => Ok(()),
            Some(_) => Err("top-level `content` array is empty".to_string()),
            None => Err("missing top-level `content` array".to_string()),
        }
    }

    /// Minimal, valid-shaped stub arguments per tool. The goal is NOT to
    /// make every tool succeed (many require real state and will return a
    /// JSON-RPC error with these stubs — that's allowed by the contract);
    /// the goal is to drive each handler far enough to exercise its
    /// success path where it can, and to never panic. Required fields are
    /// taken from each tool's `input_schema.required`.
    fn stub_args_for(name: &str) -> serde_json::Value {
        match name {
            "query" | "query_scan" => json!({"tenant_id": "t", "query": "q", "token_budget": 1000}),
            "engram_resolve" => json!({"model_id": "claude-opus-4-8"}),
            "reuse_check" => json!({"tenant_id": "t", "description": "d"}),
            "query_expand" => json!({"tenant_id": "t", "result_ids": []}),
            "store_fact" => json!({"entity": "e", "key": "k", "value": "v"}),
            "query_facts" => json!({"query": "v", "token_budget": 1000}),
            "delete_fact" | "memory_history" | "memory_reverify" => json!({"fact_id": "f_stub"}),
            "get_bootstrap" => json!({"topic": "patterns", "token_budget": 500}),
            "fact_history" => json!({"entity": "e", "key": "k"}),
            "memory_acknowledge_use" => json!({"turn_id": "turn_stub"}),
            "output_attest" => json!({"receipt_id": "r_stub"}),
            "memory_forget" => json!({"scope": [{"type": "key_glob", "value": "*"}], "reason": "test"}),
            "memory_forget_dry_run" => json!({"scope": [{"type": "key_glob", "value": "*"}]}),
            "memory_edit" => json!({"fact_id": "f_stub", "new_value": "v2"}),
            "memory_pin" => json!({"fact_id": "f_stub"}),
            "memory_set_horizon" => json!({"fact_id": "f_stub", "horizon_class": "standard"}),
            "memory_freshness" => json!({"query": "v", "token_budget": 1000}),
            "memory_contradictions" => json!({"token_budget": 1000}),
            "memory_consolidate" => json!({
                "entity": "e", "key": "k", "canonical_value": "v", "target_fact_ids": ["f_stub"]
            }),
            "artefact_put" => json!({"content_bytes_base64": "AAAA", "mime_type": "text/plain"}),
            "artefact_get" => json!({"artefact_id": "a_stub"}),
            "get_session" | "list_observations" | "delete_session" | "archive_session" | "unarchive_session" => {
                json!({"session_id": "s_stub"})
            }
            "save_session" => json!({"session_id": "s_stub", "state": {}}),
            "get_observation" | "verify_observation" => {
                json!({"session_id": "s_stub", "observation_id": "o_stub"})
            }
            "receipt_verify" => json!({"receipt_id": "r_stub"}),
            "create_handoff" => json!({"session_id": "s_stub"}),
            "accept_handoff" => json!({"package": {}}),
            "record_decision" => json!({"action": "do thing", "rationale": "because"}),
            "declare_constraint" => json!({"constraint_type": "policy", "assertion": "must hold"}),
            "audit_config" => json!({"path": "/tmp/x", "sha256": "0".repeat(64), "auditor": "p_stub"}),
            "check_config_audit" => json!({"paths": ["/tmp/x"]}),
            "enrich_action" => json!({"tool_name": "query"}),
            "get_passport" => json!({"token_budget": 500}),
            "passport_split" => {
                json!({"target_passport": "p_a", "new_passport_name": "p_b", "token_budget": 500})
            }
            "passport_merge" => json!({
                "source_passport": "p_a", "target_passport": "p_b",
                "conflict_policy": "prefer_target", "token_budget": 500
            }),
            "passport_link_device" => json!({"device_fingerprint": "fp_stub", "token_budget": 500}),
            "get_project_context" => json!({"project_id": "proj_stub"}),
            "create_work" => json!({"project_id": "proj_stub", "title": "t", "created_by_passport": "p_stub"}),
            "update_work_state" => json!({"work_id": "w_stub", "state": "in_progress", "by_passport": "p_stub"}),
            "comment_on_work" => json!({"work_id": "w_stub", "author_passport": "p_stub", "body": "hi"}),
            "github_search" => json!({"query": "q"}),
            "github_recent_commits" | "github_open_prs" | "github_open_issues" => json!({"repo": "owner/repo"}),
            "entity_upsert" => json!({"kind": "capability", "id": "X", "payload": {}}),
            "entity_get" | "entity_delete" | "entity_history" => json!({"kind": "capability", "id": "X"}),
            "edge_upsert" | "edge_get" | "edge_delete" => json!({
                "from_kind": "capability", "from_id": "A", "edge_kind": "depends_on",
                "to_kind": "capability", "to_id": "B"
            }),
            "feature_file_search" => json!({"path": "src"}),
            "feature_trigger_audit" => json!({"id": "X", "status": "passed"}),
            "kind_get" => json!({"kind": "capability"}),
            "approval_request" => json!({
                "action_summary": "do thing", "risk_tier": "low", "scope": "test", "token_budget": 500
            }),
            "create_orchestrator" => json!({"name": "orch", "created_by_passport": "p_stub"}),
            "approval_decide" => json!({"request_id": "req_stub", "decision": "approve"}),
            "attach_to_orchestrator" | "detach_from_orchestrator" => {
                json!({"orchestrator_id": "orch_stub", "member_ref": "m_stub"})
            }
            "update_orchestrator" => json!({"orchestrator_id": "orch_stub", "state": "archived"}),
            "punch_in" | "punch_out" => json!({"resource": "res", "holder_passport": "p_stub"}),
            "check_punchcard" | "force_release" => json!({"resource": "res"}),
            "list_punchcards" => json!({"punchcard_id": "pc_stub", "confirm": true}),
            // Tools with no required fields default to an empty object.
            _ => json!({}),
        }
    }

    /// Core hermetic sweep: run every tool through dispatch with stub args
    /// and collect any spec-shape violation. Caller controls the env-flag
    /// state. Returns the list of human-readable violations (empty == pass).
    async fn collect_spec_shape_violations(ctx: &McpContext, flag_on: bool) -> Vec<String> {
        let mut violations = Vec::new();
        for tool in tools::list_tools() {
            let name = tool.name.clone();
            let args = stub_args_for(&name);
            let resp = dispatch(rpc("tools/call", json!({"name": name, "arguments": args})), ctx, None).await;

            match (resp.result, resp.error) {
                // Error responses are allowed (stub args), but must be
                // well-formed JSON-RPC errors with a message and no result.
                (None, Some(err)) => {
                    if err.message.is_empty() {
                        violations.push(format!("{name}: JSON-RPC error with empty message"));
                    }
                }
                (Some(result), None) => {
                    if let Err(why) = result_is_spec_shaped(&result) {
                        violations.push(format!("{name}: {why}"));
                    }
                    // When the flag is ON and the tool opts into envelopes,
                    // any envelope must live under structuredContent.envelope
                    // (never top-level — already covered above — but assert
                    // the positive placement so a regression that drops the
                    // fold is caught here too).
                    if flag_on && tools::tool_emits_envelope(&name) {
                        let folded = result
                            .get("structuredContent")
                            .and_then(|s| s.get("envelope"))
                            .is_some();
                        if result.get("structuredContent").is_some() && !folded {
                            violations.push(format!(
                                "{name}: structuredContent present but envelope not folded under it"
                            ));
                        }
                    }
                }
                (Some(_), Some(_)) => {
                    violations.push(format!("{name}: response has BOTH result and error set"));
                }
                (None, None) => {
                    violations.push(format!("{name}: response has neither result nor error"));
                }
            }
        }
        violations
    }

    #[tokio::test]
    async fn all_tools_spec_shaped_envelope_off() {
        let _guard = envelope_env_lock().lock().await;
        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
        let ctx = test_ctx();
        let violations = collect_spec_shape_violations(&ctx, false).await;
        assert!(
            violations.is_empty(),
            "MCP response-shape contract violated (envelope OFF) by {} tool(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        );
    }

    #[tokio::test]
    async fn all_tools_spec_shaped_envelope_on() {
        let _guard = envelope_env_lock().lock().await;
        std::env::set_var(crate::envelope::FEATURE_FLAG_ENV, "1");
        let ctx = test_ctx();
        let violations = collect_spec_shape_violations(&ctx, true).await;
        // Always clear the process-wide flag before asserting so a failure
        // doesn't leak the env var into sibling tests.
        std::env::remove_var(crate::envelope::FEATURE_FLAG_ENV);
        assert!(
            violations.is_empty(),
            "MCP response-shape contract violated (envelope ON) by {} tool(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        );
    }

    /// Proves the contract CAN fail: the shape-check rejects a deliberately
    /// broken legacy-shaped value and accepts a known-good one. This is the
    /// hermetic stand-in for the test-plan's "deliberately break one tool's
    /// shape" requirement.
    #[test]
    fn result_is_spec_shaped_rejects_legacy_wrapper() {
        // Good: top-level content, no payload/envelope.
        let good = json!({"content": [{"type": "text", "text": "ok"}]});
        assert!(result_is_spec_shaped(&good).is_ok());

        // Bad: legacy `{payload, envelope}` shape with no top-level content.
        let legacy = json!({
            "payload": {"content": [{"type": "text", "text": "x"}]},
            "envelope": {"memories_used": []}
        });
        assert!(result_is_spec_shaped(&legacy).is_err());

        // Bad: empty content array.
        let empty = json!({"content": []});
        assert!(result_is_spec_shaped(&empty).is_err());

        // Bad: top-level envelope shadowing content.
        let shadowed = json!({"content": [{"text": "x"}], "envelope": {}});
        assert!(result_is_spec_shaped(&shadowed).is_err());
    }
}
