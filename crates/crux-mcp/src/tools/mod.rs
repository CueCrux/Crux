// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! MCP tool definitions and sub-module dispatch.
//!
//! Each tool is described by a [`ToolDefinition`] with a JSON Schema input
//! specification. [`list_tools`] returns the full catalogue advertised to
//! MCP clients via the `tools/list` response.

pub mod constraint;
pub mod cuecrux_session;
pub mod decision;
pub mod facts;
pub mod handoff;
pub mod observe;
pub mod passport;
pub mod query;
pub mod sessions;
pub mod sync;
pub mod update;

use serde_json::{json, Value};
use std::collections::HashSet;

use crate::dispatch::McpContext;
use crate::protocol::JsonRpcError;
use crux_router::{McpToolCapability, RcxRouter};
use rcx_capability_token::{DataEgressClass, RcxCapabilityToken};

/// Describes a single MCP tool for the `tools/list` response.
#[derive(Debug, Clone)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Non-breaking pointer added to every legacy tool's description at
/// `list_tools()` time (master-plan §6.4 + Phase 10). Tools remain
/// functionally identical — agents that call them directly still work.
/// The hint exists so agents browsing the catalogue see the collapsed
/// entry point. Deprecation timeline is not set here; it's a separate
/// decision.
const CUECRUX_SESSION_HINT: &str =
    "\n\nTip: `cuecrux_session` returns a typed capability plan that includes this tool's \
preferred routing, min-tier, and cost class. Call it once per session for the collapsed surface.";

/// Return the full tool catalogue advertised to MCP clients.
///
/// `cuecrux_session` is listed first per master-plan §6.3 so agents that
/// stop reading at the top of the list still discover the collapsed-surface
/// entry point. Every OTHER tool is augmented at emit time with the
/// `CUECRUX_SESSION_HINT` (module-private) so the pointer is visible in
/// each tool's description — cheap affordance for agents that skip the
/// hint at the head of the list.
pub fn list_tools() -> Vec<ToolDefinition> {
    vec![
        // ── Session Handshake (master-plan §6) ────────────────────
        ToolDefinition {
            name: "cuecrux_session".to_string(),
            description: cuecrux_session::CUECRUX_SESSION_DESCRIPTION.to_string(),
            input_schema: cuecrux_session::tool_input_schema(),
        },
        // ── Retrieval ──────────────────────────────────────────────
        ToolDefinition {
            name: "query".to_string(),
            description: "Search the retrieval index using BM25 + graph fusion. Returns \
                          scored results with query coverage. Use `token_budget` to cap \
                          results by token count (60-80% cost reduction vs top-K)."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "tenant_id":    { "type": "string",  "description": "Tenant identifier for scoped search" },
                    "query":        { "type": "string",  "description": "Natural-language search query" },
                    "limit":        { "type": "integer", "description": "Maximum results to return", "default": 10 },
                    "token_budget": { "type": "integer", "description": "Optional token budget for result trimming" },
                    "min_score":    { "type": "number",  "description": "Minimum relevance score threshold" }
                },
                "required": ["tenant_id", "query"],
                "examples": [
                    { "tenant_id": "my-project", "query": "deployment strategy", "token_budget": 4000 },
                    { "tenant_id": "my-project", "query": "error handling patterns", "limit": 5, "min_score": 0.3 }
                ]
            }),
        },
        ToolDefinition {
            name: "query_scan".to_string(),
            description: "Lightweight scan returning metadata only (no content). Useful for \
                          checking what exists before expanding. Returns scores and token \
                          counts per result. Use to decide what to expand."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "tenant_id": { "type": "string",  "description": "Tenant identifier" },
                    "query":     { "type": "string",  "description": "Search query" },
                    "limit":     { "type": "integer", "description": "Maximum results", "default": 20 }
                },
                "required": ["tenant_id", "query"],
                "examples": [
                    { "tenant_id": "my-project", "query": "authentication flow", "limit": 20 }
                ]
            }),
        },
        ToolDefinition {
            name: "query_expand".to_string(),
            description: "Expand previously retrieved results by segment/doc IDs to get full \
                          content."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "tenant_id":  { "type": "string", "description": "Tenant identifier" },
                    "result_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Result IDs from a prior query/query_scan to expand"
                    }
                },
                "required": ["tenant_id", "result_ids"],
                "examples": [
                    { "tenant_id": "my-project", "result_ids": ["r_01J_abc", "r_01J_def"] }
                ]
            }),
        },
        // ── Facts ──────────────────────────────────────────────────
        ToolDefinition {
            name: "store_fact".to_string(),
            description: "Store a key-value fact against an entity. Facts carry optional \
                          receipt references and confidence scores. Set `private: true` to \
                          scope the fact to your agent identity only."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "entity":         { "type": "string",  "description": "Entity the fact belongs to" },
                    "key":            { "type": "string",  "description": "Fact key" },
                    "value":          { "type": "string",  "description": "Fact value" },
                    "source_receipt": { "type": "string",  "description": "CROWN receipt reference" },
                    "confidence":     { "type": "number",  "description": "Confidence score 0..1", "default": 1.0 },
                    "private":        { "type": "boolean", "description": "If true, scoped to the calling agent", "default": false }
                },
                "required": ["entity", "key", "value"],
                "examples": [
                    { "entity": "project-alpha", "key": "status", "value": "Phase 1 complete", "confidence": 0.95 },
                    { "entity": "my-agent", "key": "internal_state", "value": "Waiting for confirmation", "private": true }
                ]
            }),
        },
        ToolDefinition {
            name: "query_facts".to_string(),
            description: "Query the fact store by keyword, entity, or both. Results are \
                          ranked by confidence. Private facts are visible only to \
                          their owning agent."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query":        { "type": "string",  "description": "Keyword search across fact values, keys, and entities" },
                    "entity":       { "type": "string",  "description": "Filter to a specific entity" },
                    "top_k":        { "type": "integer", "description": "Maximum facts to return", "default": 10 },
                    "token_budget": { "type": "integer", "description": "Optional token budget" }
                },
                "examples": [
                    { "query": "deployment strategy", "token_budget": 2000 },
                    { "entity": "project-alpha", "top_k": 5 }
                ]
            }),
        },
        ToolDefinition {
            name: "delete_fact".to_string(),
            description: "Soft-delete a fact by its ID. The fact's receipt is preserved.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "fact_id": { "type": "string", "description": "ID of the fact to delete" }
                },
                "required": ["fact_id"],
                "examples": [
                    { "fact_id": "f_01J_abc123" }
                ]
            }),
        },
        ToolDefinition {
            name: "list_entities".to_string(),
            description: "Discover all entity names in the fact store. Returns a sorted, \
                          deduplicated list of entity names with at least one active fact."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "examples": [{}]
            }),
        },
        ToolDefinition {
            name: "get_bootstrap".to_string(),
            description: "Query bootstrap knowledge at runtime. Returns facts stored under \
                          the `__bootstrap__::` entity prefix. Use `topic` to filter by \
                          sub-category (e.g. \"patterns\", \"docs\", \"errors\") and \
                          `query` to narrow onboarding or troubleshooting guidance."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "topic": {
                        "type": "string",
                        "description": "Optional topic filter: \"patterns\", \"docs\", \"errors\", etc."
                    },
                    "query": {
                        "type": "string",
                        "description": "Optional search term to narrow the matching bootstrap facts."
                    }
                },
                "examples": [
                    { "topic": "patterns" },
                    { "topic": "docs", "query": "integration" },
                    { "topic": "errors" }
                ]
            }),
        },
        ToolDefinition {
            name: "fact_history".to_string(),
            description: "Return the full version chain for a given (entity, key) pair. \
                          Shows how a fact evolved over time, including superseded versions."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "entity": { "type": "string", "description": "Entity name" },
                    "key":    { "type": "string", "description": "Fact key" }
                },
                "required": ["entity", "key"],
                "examples": [
                    { "entity": "project-alpha", "key": "status" }
                ]
            }),
        },
        // ── Sessions ───────────────────────────────────────────────
        ToolDefinition {
            name: "get_session".to_string(),
            description: "Retrieve your session state by ID. Authenticated agents see \
                          only their own session namespace."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string", "description": "Session identifier" }
                },
                "required": ["session_id"],
                "examples": [
                    { "session_id": "session-42" }
                ]
            }),
        },
        ToolDefinition {
            name: "save_session".to_string(),
            description: "Create or update your session state. Authenticated agents write \
                          into their own session namespace."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id":   { "type": "string",  "description": "Session identifier" },
                    "state":        { "type": "object",  "description": "Arbitrary JSON state to persist" },
                    "ttl_seconds":  { "type": "integer", "description": "Optional time-to-live in seconds. Session expires after this duration." }
                },
                "required": ["session_id", "state"],
                "examples": [
                    { "session_id": "session-42", "state": { "decisions": ["Use PostgreSQL"], "open_questions": ["Which cache?"] } },
                    { "session_id": "session-42", "state": { "step": 1 }, "ttl_seconds": 3600 }
                ]
            }),
        },
        ToolDefinition {
            name: "list_sessions".to_string(),
            description: "List active session IDs visible to you. Returns a sorted list.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "examples": [{}]
            }),
        },
        ToolDefinition {
            name: "delete_session".to_string(),
            description: "Delete one of your sessions by ID. Returns confirmation or not-found.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string", "description": "Session identifier to delete" }
                },
                "required": ["session_id"],
                "examples": [
                    { "session_id": "session-42" }
                ]
            }),
        },
        // ── Observability ──────────────────────────────────────────
        ToolDefinition {
            name: "get_gaps".to_string(),
            description: "Retrieve known knowledge gaps from the ops observation layer. \
                          Check after low-coverage queries. Returns aggregated gap data \
                          from ops observations."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string", "description": "Optional keyword filter for gap descriptions" }
                },
                "examples": [
                    { "query": "quantum physics" },
                    {}
                ]
            }),
        },
        // ── Agent ──────────────────────────────────────────────────
        ToolDefinition {
            name: "get_agent_identity".to_string(),
            description: "Return the calling agent's name. Returns \"anonymous\" if no \
                          agent identity is authenticated."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "examples": [{}]
            }),
        },
        // ── Handoff ────────────────────────────────────────────────
        ToolDefinition {
            name: "create_handoff".to_string(),
            description: "Package session state and relevant non-private facts into a \
                          server-authenticated handoff bundle for another agent."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id":    { "type": "string",  "description": "Session to hand off" },
                    "include_facts": { "type": "boolean", "description": "Include relevant facts in the package", "default": false },
                    "target_agent":  { "type": "string",  "description": "Optional receiving agent name. If set, only that agent may accept the package." },
                    "message":       { "type": "string",  "description": "Free-text message for the receiving agent" }
                },
                "required": ["session_id"],
                "examples": [
                    { "session_id": "session-42", "include_facts": true, "target_agent": "implementer", "message": "Architecture review complete, one open question." }
                ]
            }),
        },
        ToolDefinition {
            name: "accept_handoff".to_string(),
            description: "Accept a server-authenticated handoff package from another \
                          agent, restoring session state and facts into your namespace."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "package": { "type": "string", "description": "JSON-encoded handoff package returned by create_handoff" }
                },
                "required": ["package"],
                "examples": [
                    { "package": "eyJoYW5kb2ZmX2lkIjoiaG9fMDFKLi4uIn0=" }
                ]
            }),
        },
        // ── Decisions ─────────────────────────────────────────────
        ToolDefinition {
            name: "record_decision".to_string(),
            description: "Record why a decision was made. Stores an append-only, \
                          BLAKE3-hashed decision record as a fact. Queryable via \
                          query_facts with entity prefix __decisions__::."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action":       { "type": "string",  "description": "What was decided / what action was taken" },
                    "rationale":    { "type": "string",  "description": "Why this decision was made" },
                    "alternatives": { "type": "array",   "items": { "type": "string" }, "description": "Other options that were considered" },
                    "confidence":   { "type": "number",  "description": "Confidence in this decision (0..1)", "default": 1.0 },
                    "session_id":   { "type": "string",  "description": "Session to associate this decision with", "default": "_default" },
                    "context_refs": { "type": "array",   "items": { "type": "string" }, "description": "References to facts or receipts that informed this decision" }
                },
                "required": ["action", "rationale"],
                "examples": [
                    {
                        "action": "Chose PostgreSQL over MongoDB for the metadata store",
                        "rationale": "Need ACID transactions for receipt chains; document flexibility not required",
                        "alternatives": ["MongoDB", "SQLite"],
                        "confidence": 0.9
                    }
                ]
            }),
        },
        // ── Constraints ────────────────────────────────────────────
        ToolDefinition {
            name: "declare_constraint".to_string(),
            description: "Declare an organisational constraint (boundary, relationship, \
                          policy, or context flag) that agents must respect. Constraints \
                          are stored as facts and queryable via get_constraints."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "constraint_type": {
                        "type": "string",
                        "enum": ["boundary", "relationship", "policy", "context_flag"],
                        "description": "The kind of constraint"
                    },
                    "assertion": {
                        "type": "string",
                        "description": "The constraint statement in natural language"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                        "description": "Severity level. Critical constraints block actions.",
                        "default": "medium"
                    }
                },
                "required": ["constraint_type", "assertion"],
                "examples": [
                    { "constraint_type": "policy", "assertion": "All API keys must be rotated every 90 days", "severity": "high" },
                    { "constraint_type": "boundary", "assertion": "No direct database access from application code", "severity": "critical" }
                ]
            }),
        },
        ToolDefinition {
            name: "get_constraints".to_string(),
            description: "List active organisational constraints, optionally filtered by \
                          type or status. Returns constraints sorted by severity."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "constraint_type": {
                        "type": "string",
                        "enum": ["boundary", "relationship", "policy", "context_flag"],
                        "description": "Filter by constraint type"
                    },
                    "status": {
                        "type": "string",
                        "enum": ["active", "suspended"],
                        "description": "Filter by status",
                        "default": "active"
                    }
                },
                "examples": [
                    {},
                    { "constraint_type": "policy" },
                    { "status": "active" }
                ]
            }),
        },
        ToolDefinition {
            name: "check_constraints".to_string(),
            description: "Check a proposed action against all active constraints. Returns \
                          a verdict (pass, warn, or block) based on keyword matching \
                          against constraint assertions. Critical matches block, high \
                          matches warn."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action_description": {
                        "type": "string",
                        "description": "Description of the action to check against constraints"
                    }
                },
                "required": ["action_description"],
                "examples": [
                    { "action_description": "Delete all user records from the production database" },
                    { "action_description": "Deploy updated API to staging environment" }
                ]
            }),
        },
        // ── Passport ───────────────────────────────────────────────
        ToolDefinition {
            name: "issue_passport".to_string(),
            description: "Issue an agent passport for the calling agent. Requires an \
                          authenticated agent identity. The passport tracks lineage \
                          (sponsor), reputation tier, and receipt count. Sync operations \
                          require a minimum tier."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "sponsor_id": {
                        "type": "string",
                        "description": "Optional sponsor/voucher for this agent"
                    }
                },
                "examples": [
                    {},
                    { "sponsor_id": "platform-admin" }
                ]
            }),
        },
        ToolDefinition {
            name: "get_passport".to_string(),
            description: "Return the calling agent's passport with current reputation \
                          tier and receipt count. Automatically upgrades the tier if \
                          new receipt thresholds are met. Tiers: unverified, basic (10+), \
                          established (100+), trusted (500+), elite (2000+)."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "examples": [{}]
            }),
        },
        // ── Sync ──────────────────────────────────────────────────
        ToolDefinition {
            name: "sync_pull".to_string(),
            description: "Pull latest facts from a remote CoreCrux instance. Resumes \
                          from the last pull cursor. Requires CORECRUXD_SYNC_REMOTE_URL \
                          and CORECRUXD_SYNC_API_KEY to be configured."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "entity_prefix": {
                        "type": "string",
                        "description": "Optional entity prefix filter (reserved for future use)"
                    }
                },
                "examples": [{}]
            }),
        },
        ToolDefinition {
            name: "sync_push".to_string(),
            description: "Push local facts to a remote CoreCrux instance. Only pushes \
                          facts that were created locally (not previously synced). \
                          Private facts and sensitive entity prefixes are never pushed. \
                          Call without confirm=true to preview what would be pushed. \
                          Requires CORECRUXD_SYNC_REMOTE_URL and CORECRUXD_SYNC_API_KEY."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "confirm": { "type": "boolean", "description": "Set to true to actually push. Without this, returns a preview of facts that would be pushed.", "default": false }
                },
                "examples": [{}, { "confirm": true }]
            }),
        },
        ToolDefinition {
            name: "sync_status".to_string(),
            description: "Show whether this node is running local-only, manual sync, \
                          full background sync, or degraded sync. Includes remote reachability, \
                          pull/push timestamps, and local fact count."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "examples": [{}]
            }),
        },
        ToolDefinition {
            name: "update_status".to_string(),
            description: "Show whether this checkout is current, behind, ahead, \
                          diverged, disabled, or unavailable relative to the tracked \
                          git branch. Includes an upgrade hint plus backup playbook pointers."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "examples": [{}]
            }),
        },
    ]
    .into_iter()
    .map(|mut t: ToolDefinition| {
        let marker = vaultcrux_local::tool_surface::marker_for_tool(&t.name);
        if !t.description.starts_with(marker) {
            t.description = format!("{marker} {}", t.description);
        }
        if t.name != "cuecrux_session" {
            t.description.push_str(CUECRUX_SESSION_HINT);
        }
        t
    })
    .collect()
}

/// Serialise the tool list into the MCP `tools/list` response shape.
pub fn list_tools_json() -> Value {
    tools_to_json(list_tools(), None)
}

pub fn list_tools_json_for_rcx_router(router: &RcxRouter, now_unix_seconds: u64) -> Value {
    tools_to_json(
        list_tools_for_rcx_router(router, now_unix_seconds),
        Some(ToolAuthMetadata::from_token(router.token())),
    )
}

#[derive(Debug, Clone)]
struct ToolAuthMetadata {
    token_id: String,
    token_hash: String,
    receipt_class: String,
    tier: String,
}

impl ToolAuthMetadata {
    fn from_token(token: &RcxCapabilityToken) -> Self {
        Self {
            token_id: token.token_id.clone(),
            token_hash: token.token_hash_hex(),
            receipt_class: token.receipt_class.as_str().to_string(),
            tier: token.tier.as_str().to_string(),
        }
    }
}

fn tools_to_json(tools: Vec<ToolDefinition>, auth: Option<ToolAuthMetadata>) -> Value {
    let tools: Vec<Value> = tools
        .into_iter()
        .map(|t| {
            let mut input_schema = t.input_schema;
            if let Some(auth) = &auth {
                if let Some(schema) = input_schema.as_object_mut() {
                    schema.insert(
                        "x-crux-token-ref".to_string(),
                        json!({
                            "token_id": &auth.token_id,
                            "token_hash": &auth.token_hash,
                        }),
                    );
                    schema.insert("x-crux-receipt-class".to_string(), json!(&auth.receipt_class));
                    schema.insert("x-crux-tier".to_string(), json!(&auth.tier));
                }
            }
            let meta = auth.as_ref().map(|auth| {
                json!({
                    "crux": {
                        "filtered_by": "rcx-capability-token",
                        "token_ref": {
                            "token_id": &auth.token_id,
                            "token_hash": &auth.token_hash,
                        },
                        "receipt_class": &auth.receipt_class,
                        "tier": &auth.tier,
                    }
                })
            });
            let mut tool = json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": input_schema,
            });
            if let Some(meta) = meta {
                tool["_meta"] = meta;
            }
            tool
        })
        .collect();
    let mut response = json!({ "tools": tools });
    if let Some(auth) = auth {
        response["_meta"] = json!({
            "crux": {
                "filtered_by": "rcx-capability-token",
                "token_ref": {
                    "token_id": auth.token_id,
                    "token_hash": auth.token_hash,
                },
                "receipt_class": auth.receipt_class,
                "tier": auth.tier,
            }
        });
    }
    response
}

/// Return the MCP catalogue after applying an RCX Capability Token matrix.
pub fn list_tools_for_rcx_token(token: &RcxCapabilityToken, now_unix_seconds: u64) -> Vec<ToolDefinition> {
    let router = RcxRouter::new(token.clone());
    list_tools_for_rcx_router(&router, now_unix_seconds)
}

pub fn list_tools_for_rcx_router(router: &RcxRouter, now_unix_seconds: u64) -> Vec<ToolDefinition> {
    let tools = list_tools();
    let capabilities: Vec<McpToolCapability> = tools.iter().map(|tool| rcx_mcp_tool_capability(&tool.name)).collect();
    let allowed: HashSet<String> = router
        .filter_mcp_tools(&capabilities, now_unix_seconds)
        .into_iter()
        .collect();
    tools.into_iter().filter(|tool| allowed.contains(&tool.name)).collect()
}

pub fn rcx_mcp_tool_capability(tool_name: &str) -> McpToolCapability {
    let capability = rcx_capability_for_tool(tool_name);
    if vaultcrux_local::tool_surface::is_hosted_gated_tool(tool_name) {
        return McpToolCapability {
            tool_name: tool_name.to_string(),
            capability,
            backend_id: vaultcrux_local::tool_surface::HOSTED_BACKEND_ID.to_string(),
            data_egress_classes: vec![DataEgressClass::None],
        };
    }
    McpToolCapability::local_none(tool_name, capability)
}

pub fn rcx_local_capabilities() -> Vec<String> {
    let mut seen = HashSet::new();
    list_tools()
        .into_iter()
        .filter_map(|tool| {
            if !vaultcrux_local::tool_surface::is_local_tool(&tool.name) {
                return None;
            }
            let capability = rcx_capability_for_tool(&tool.name);
            seen.insert(capability.clone()).then_some(capability)
        })
        .collect()
}

fn rcx_capability_for_tool(tool_name: &str) -> String {
    match tool_name {
        "query" | "query_scan" | "query_expand" => "corecrux.query.local".to_string(),
        other => format!("crux-mcp.{other}"),
    }
}

/// Return documentation of each tool's output format.
///
/// The MCP spec does not support `outputSchema` in tool definitions, so this
/// function provides a standalone JSON document describing each tool's response
/// shape. Included in the `get_bootstrap` response for agent discoverability.
pub fn tool_output_docs() -> Value {
    json!([
        { "tool": "cuecrux_session",    "output": "SessionPlan (see agents.cuecrux.com/schemas/SessionPlan.v1). Contains plan_id, session_id, passport, channels {bulk?, mcp}, capability_graph[], receipt {hash, signature?, signer_kid?, mode}, budget, minted_at, session_ttl_s." },
        { "tool": "query",              "output": "{ results: [{doc_id, score, segment_index, token_count}], coverage: {score, gaps, below_floor}, meta: {backend, took_ms, segments_searched} }" },
        { "tool": "query_scan",         "output": "{ results: [{doc_id, score, token_count}], meta: {took_ms, segments_searched} }" },
        { "tool": "query_expand",       "output": "{ results: [{doc_id, content, token_count}] }" },
        { "tool": "store_fact",         "output": "{ fact_id, entity, key, value, stored_at, tokens, confidence }" },
        { "tool": "query_facts",        "output": "{ facts: [{fact_id, entity, key, value, confidence, stored_at}], total_tokens }" },
        { "tool": "delete_fact",        "output": "{ deleted: bool, fact_id }" },
        { "tool": "list_entities",      "output": "{ entities: [string] }" },
        { "tool": "get_bootstrap",      "output": "{ facts: [{entity, key, value}], total_tokens }" },
        { "tool": "fact_history",       "output": "{ versions: [{fact_id, value, version, supersedes, confidence, stored_at, deleted}] }" },
        { "tool": "get_session",        "output": "{ session_id, state, updated_at, total_tokens }" },
        { "tool": "save_session",       "output": "{ session_id, updated_at }" },
        { "tool": "list_sessions",      "output": "{ sessions: [string] }" },
        { "tool": "delete_session",     "output": "{ deleted: bool, session_id }" },
        { "tool": "get_gaps",           "output": "{ gaps: [{entity, key, value, stored_at}], total_tokens }" },
        { "tool": "get_agent_identity", "output": "{ agent_name: string }" },
        { "tool": "create_handoff",     "output": "{ package_json, content_hash, signature, relevant_fact_count }" },
        { "tool": "accept_handoff",     "output": "{ session_loaded, facts_loaded, verified: bool }" },
        { "tool": "record_decision",    "output": "{ decision_id, decision_hash, entity, action }" },
        { "tool": "declare_constraint", "output": "{ constraint_id, constraint_hash, constraint_type, assertion }" },
        { "tool": "get_constraints",    "output": "{ constraints: [{constraint_id, constraint_type, assertion, severity, status, created_at}], count }" },
        { "tool": "check_constraints",  "output": "{ verdict: pass|warn|block, matched_constraints: [{constraint_id, assertion, severity, match_score}] }" },
        { "tool": "issue_passport",     "output": "{ principal_id, reputation_tier, receipt_count, sponsor_id }" },
        { "tool": "get_passport",       "output": "{ principal_id, reputation_tier, receipt_count, sponsor_id, issued_at, passport_hash }" },
        { "tool": "sync_pull",          "output": "{ facts_pulled, cursor, total_pull_count }" },
        { "tool": "sync_push",          "output": "{ facts_pushed, total_push_count }" },
        { "tool": "sync_status",        "output": "{ mode, configured, background_sync_enabled, remote_url, api_key_configured, platform_online, degraded, degraded_reason, onboarding_hint, last_pull_at, last_push_at, pull_count, push_count, local_fact_count }" },
        { "tool": "update_status",      "output": "{ enabled, state, tracking_ref, current_commit, latest_commit, ahead_by, behind_by, checked_at, error, upgrade_hint, upgrade_playbook_query, backup_playbook_query }" }
    ])
}

/// `get_agent_identity` — return the calling agent's name.
#[allow(clippy::unused_async)] // Async required by MCP tool dispatch signature.
pub async fn handle_get_agent_identity(_args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    let name = ctx
        .agent
        .as_ref()
        .map_or_else(|| "anonymous".to_string(), |a| a.name.clone());

    Ok(json!({
        "content": [{
            "type": "text",
            "text": name
        }]
    }))
}

/// Dispatch a tool call by name. Returns the MCP `content` array.
pub async fn call_tool(name: &str, args: &Value, ctx: &McpContext) -> Result<Value, JsonRpcError> {
    match name {
        "cuecrux_session" => cuecrux_session::handle_cuecrux_session(args, ctx).await,
        "query" => query::handle_query(args, ctx).await,
        "query_scan" => query::handle_query_scan(args, ctx).await,
        "query_expand" => query::handle_query_expand(args, ctx).await,
        "store_fact" => facts::handle_store_fact(args, ctx).await,
        "query_facts" => facts::handle_query_facts(args, ctx).await,
        "delete_fact" => facts::handle_delete_fact(args, ctx).await,
        "list_entities" => facts::handle_list_entities(args, ctx).await,
        "get_bootstrap" => facts::handle_get_bootstrap(args, ctx).await,
        "fact_history" => facts::handle_fact_history(args, ctx).await,
        "get_session" => sessions::handle_get_session(args, ctx).await,
        "save_session" => sessions::handle_save_session(args, ctx).await,
        "list_sessions" => sessions::handle_list_sessions(args, ctx).await,
        "delete_session" => sessions::handle_delete_session(args, ctx).await,
        "get_gaps" => observe::handle_get_gaps(args, ctx).await,
        "get_agent_identity" => handle_get_agent_identity(args, ctx).await,
        "create_handoff" => handoff::handle_create_handoff(args, ctx).await,
        "accept_handoff" => handoff::handle_accept_handoff(args, ctx).await,
        "record_decision" => decision::handle_record_decision(args, ctx).await,
        "declare_constraint" => constraint::handle_declare_constraint(args, ctx).await,
        "get_constraints" => constraint::handle_get_constraints(args, ctx).await,
        "check_constraints" => constraint::handle_check_constraints(args, ctx).await,
        "issue_passport" => passport::handle_issue_passport(args, ctx).await,
        "get_passport" => passport::handle_get_passport(args, ctx).await,
        "sync_pull" => sync::handle_sync_pull(args, ctx).await,
        "sync_push" => sync::handle_sync_push(args, ctx).await,
        "sync_status" => sync::handle_sync_status(args, ctx).await,
        "update_status" => update::handle_update_status(args, ctx).await,
        _ => Err(JsonRpcError {
            code: crate::protocol::METHOD_NOT_FOUND,
            message: format!("unknown tool: {name}"),
            data: None,
        }),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) fn clear_sync_env() {
        std::env::remove_var("CORECRUXD_SYNC_REMOTE_URL");
        std::env::remove_var("CORECRUXD_SYNC_API_KEY");
        std::env::remove_var("CORECRUXD_DATA_DIR");
    }

    pub(crate) fn sync_env_lock() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::dispatch::McpContext;
    use crate::tools::test_support::{clear_sync_env, sync_env_lock};
    use crux_router::{mint_free_local_token, RcxRouter};
    use rcx_capability_token::{
        Backend, CreditCost, CreditCostUnit, CreditRefill, Credits, FallbackAction, FallbackPolicy, OverdraftPolicy,
        PermittedCapability, RcxTier, RCX_CT_SIGNATURE_LEN,
    };

    const TOOL_COUNT: usize = 28; // 27 pre-M3 tools + cuecrux_session

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    #[test]
    fn list_tools_returns_expected_count() {
        let tools = list_tools();
        assert_eq!(tools.len(), TOOL_COUNT);
    }

    #[test]
    fn all_tools_have_names() {
        for tool in list_tools() {
            assert!(!tool.name.is_empty(), "tool name must not be empty");
        }
    }

    #[test]
    fn all_tools_have_descriptions() {
        for tool in list_tools() {
            assert!(
                !tool.description.is_empty(),
                "tool '{}' must have a description",
                tool.name
            );
        }
    }

    #[test]
    fn all_schemas_are_objects() {
        for tool in list_tools() {
            assert_eq!(
                tool.input_schema["type"], "object",
                "tool '{}' schema must be type: object",
                tool.name
            );
            assert!(
                tool.input_schema.get("properties").is_some(),
                "tool '{}' schema must have properties",
                tool.name
            );
        }
    }

    #[test]
    fn tool_names_unique() {
        let tools = list_tools();
        let mut names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), TOOL_COUNT, "tool names must be unique");
    }

    #[test]
    fn list_tools_json_has_tools_array() {
        let v = list_tools_json();
        let arr = v["tools"].as_array().unwrap();
        assert_eq!(arr.len(), TOOL_COUNT);
        assert!(arr[0].get("name").is_some());
        assert!(arr[0].get("inputSchema").is_some());
    }

    #[test]
    fn expected_tool_names() {
        let names: Vec<String> = list_tools().into_iter().map(|t| t.name).collect();
        // Original 10
        assert!(names.contains(&"query".to_string()));
        assert!(names.contains(&"query_scan".to_string()));
        assert!(names.contains(&"query_expand".to_string()));
        assert!(names.contains(&"store_fact".to_string()));
        assert!(names.contains(&"query_facts".to_string()));
        assert!(names.contains(&"get_session".to_string()));
        assert!(names.contains(&"save_session".to_string()));
        assert!(names.contains(&"get_gaps".to_string()));
        assert!(names.contains(&"create_handoff".to_string()));
        assert!(names.contains(&"accept_handoff".to_string()));
        // New 6
        assert!(names.contains(&"delete_fact".to_string()));
        assert!(names.contains(&"list_entities".to_string()));
        assert!(names.contains(&"get_bootstrap".to_string()));
        assert!(names.contains(&"list_sessions".to_string()));
        assert!(names.contains(&"delete_session".to_string()));
        assert!(names.contains(&"get_agent_identity".to_string()));
        // Constraint tools (3)
        assert!(names.contains(&"declare_constraint".to_string()));
        assert!(names.contains(&"get_constraints".to_string()));
        assert!(names.contains(&"check_constraints".to_string()));
        // Passport tools (2)
        assert!(names.contains(&"issue_passport".to_string()));
        assert!(names.contains(&"get_passport".to_string()));
        // Sync + update tools (4)
        assert!(names.contains(&"sync_pull".to_string()));
        assert!(names.contains(&"sync_push".to_string()));
        assert!(names.contains(&"sync_status".to_string()));
        assert!(names.contains(&"update_status".to_string()));
    }

    #[test]
    fn all_schemas_have_examples() {
        for tool in list_tools() {
            assert!(
                tool.input_schema.get("examples").is_some(),
                "tool '{}' schema must have examples",
                tool.name
            );
            let examples = tool.input_schema["examples"].as_array().unwrap();
            assert!(
                !examples.is_empty(),
                "tool '{}' must have at least one example",
                tool.name
            );
        }
    }

    #[test]
    fn tool_output_docs_covers_all_tools() {
        let docs = tool_output_docs();
        let arr = docs.as_array().unwrap();
        let tool_names: Vec<String> = list_tools().into_iter().map(|t| t.name).collect();
        let doc_names: Vec<String> = arr.iter().map(|d| d["tool"].as_str().unwrap().to_string()).collect();
        for name in &tool_names {
            assert!(
                doc_names.contains(name),
                "tool_output_docs missing entry for tool '{}'",
                name
            );
        }
    }

    #[test]
    fn expanded_descriptions_contain_hints() {
        let tools = list_tools();
        let by_name = |n: &str| tools.iter().find(|t| t.name == n).unwrap();

        assert!(by_name("query").description.contains("token_budget"));
        assert!(by_name("query_scan").description.contains("scores and token counts"));
        assert!(by_name("get_gaps").description.contains("low-coverage queries"));
        assert!(by_name("store_fact").description.contains("private: true"));
    }

    #[test]
    fn legacy_tools_carry_cuecrux_session_hint_but_session_tool_does_not() {
        // M10 gate: every legacy tool's description points at
        // cuecrux_session; the collapsed entry tool does NOT hint at
        // itself (would be tautological + drown out its own description).
        let tools = list_tools();
        let by_name = |n: &str| tools.iter().find(|t| t.name == n).expect(n);
        let hint_fragment = "cuecrux_session";

        assert!(
            !by_name("cuecrux_session").description.ends_with(CUECRUX_SESSION_HINT),
            "cuecrux_session must not hint at itself"
        );
        for legacy in [
            "query",
            "query_scan",
            "store_fact",
            "query_facts",
            "get_session",
            "list_sessions",
            "get_agent_identity",
            "create_handoff",
            "record_decision",
            "declare_constraint",
            "issue_passport",
            "sync_pull",
            "update_status",
        ] {
            let desc = &by_name(legacy).description;
            assert!(
                desc.contains(hint_fragment),
                "`{legacy}` description missing cuecrux_session hint"
            );
            assert!(desc.ends_with(CUECRUX_SESSION_HINT));
        }
    }

    #[test]
    fn list_tools_marks_local_and_hosted_gated_surfaces() {
        let tools = list_tools();
        let by_name = |n: &str| tools.iter().find(|t| t.name == n).unwrap();

        assert!(by_name("query").description.starts_with("[local]"));
        assert!(by_name("sync_status").description.starts_with("[local]"));
        assert!(by_name("issue_passport").description.starts_with("[hosted]"));
        assert!(by_name("sync_pull").description.starts_with("[hosted]"));
        assert!(by_name("sync_push").description.starts_with("[hosted]"));
    }

    #[test]
    fn rcx_local_capabilities_excludes_hosted_gated_tools() {
        let capabilities = rcx_local_capabilities();

        assert!(capabilities.contains(&"corecrux.query.local".to_string()));
        assert!(capabilities.contains(&"crux-mcp.sync_status".to_string()));
        assert!(!capabilities.contains(&"crux-mcp.issue_passport".to_string()));
        assert!(!capabilities.contains(&"crux-mcp.sync_pull".to_string()));
        assert!(!capabilities.contains(&"crux-mcp.sync_push".to_string()));
    }

    #[test]
    fn hosted_gated_tool_capability_uses_hosted_backend() {
        let capability = rcx_mcp_tool_capability("sync_pull");

        assert_eq!(capability.backend_id, vaultcrux_local::tool_surface::HOSTED_BACKEND_ID);
        assert_eq!(capability.data_egress_classes, vec![DataEgressClass::None]);
    }

    #[test]
    fn pro_hosted_token_lists_hosted_gated_tools() {
        let mut token = mint_free_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "default",
            rcx_local_capabilities(),
            1_776_989_600,
            1_780_143_200,
            [0x11; RCX_CT_SIGNATURE_LEN],
        );
        token.tier = RcxTier::Pro;
        token.credits = Credits {
            balance: Some(100),
            refill: CreditRefill {
                period: rcx_capability_token::RefillPeriod::Monthly,
                amount: Some(100),
            },
            overdraft: OverdraftPolicy::Forbid,
            overdraft_limit: None,
        };
        token.fallback = FallbackPolicy {
            on_backend_unreachable: FallbackAction::Queue,
            on_credits_exhausted: FallbackAction::Refuse,
            on_expiry: FallbackAction::Refuse,
            queue_ttl_seconds: Some(120),
        };
        token.backends.push(Backend {
            backend_id: vaultcrux_local::tool_surface::HOSTED_BACKEND_ID.to_string(),
            trust_root_kid: "vaultcrux-hosted-root-v1".to_string(),
            endpoint_url: Some("https://hosted.vaultcrux.com".to_string()),
            permitted_capabilities: vaultcrux_local::tool_surface::hosted_gated_tool_names()
                .into_iter()
                .map(|tool_name| {
                    let tool = rcx_mcp_tool_capability(tool_name);
                    PermittedCapability {
                        capability: tool.capability,
                        data_egress_classes: tool.data_egress_classes,
                        required_attestations: Vec::new(),
                        credit_cost: Some(CreditCost {
                            unit: CreditCostUnit::Call,
                            cost: 1,
                        }),
                    }
                })
                .collect(),
        });

        let names: Vec<String> = list_tools_for_rcx_token(&token, 1_776_989_601)
            .into_iter()
            .map(|tool| tool.name)
            .collect();

        assert!(names.contains(&"issue_passport".to_string()));
        assert!(names.contains(&"sync_pull".to_string()));
        assert!(names.contains(&"sync_push".to_string()));
    }

    #[test]
    fn list_tools_for_rcx_token_filters_unpermitted_tools() {
        let token = mint_free_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "default",
            vec!["corecrux.query.local".to_string(), "crux-mcp.store_fact".to_string()],
            1_776_989_600,
            1_780_143_200,
            [0x11; RCX_CT_SIGNATURE_LEN],
        );
        let names: Vec<String> = list_tools_for_rcx_token(&token, 1_776_989_601)
            .into_iter()
            .map(|tool| tool.name)
            .collect();

        assert!(names.contains(&"query".to_string()));
        assert!(names.contains(&"query_scan".to_string()));
        assert!(names.contains(&"query_expand".to_string()));
        assert!(names.contains(&"store_fact".to_string()));
        assert!(!names.contains(&"sync_pull".to_string()));
    }

    #[test]
    fn list_tools_json_for_rcx_router_includes_token_metadata() {
        let token = mint_free_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "default",
            vec!["corecrux.query.local".to_string()],
            1_776_989_600,
            1_780_143_200,
            [0x11; RCX_CT_SIGNATURE_LEN],
        );
        let token_id = token.token_id.clone();
        let token_hash = token.token_hash_hex();
        let router = RcxRouter::new(token);

        let listed = list_tools_json_for_rcx_router(&router, 1_776_989_601);
        assert_eq!(listed["_meta"]["crux"]["token_ref"]["token_id"], token_id);
        assert_eq!(listed["_meta"]["crux"]["token_ref"]["token_hash"], token_hash);
        assert_eq!(listed["_meta"]["crux"]["receipt_class"], "verified");

        let first_tool = listed["tools"].as_array().unwrap().first().unwrap();
        assert_eq!(first_tool["_meta"]["crux"]["token_ref"]["token_id"], token_id);
        assert_eq!(first_tool["inputSchema"]["x-crux-receipt-class"], "verified");
    }

    // ── get_agent_identity tests ────────────────────────────────────

    #[tokio::test]
    async fn get_agent_identity_anonymous() {
        let ctx = test_ctx();
        let result = handle_get_agent_identity(&json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "anonymous");
    }

    #[tokio::test]
    async fn get_agent_identity_with_agent() {
        let ctx = test_ctx();
        let agent_ctx = ctx.with_agent(AgentIdentity {
            name: "alice".to_string(),
            token_hash: [0u8; 32],
        });
        let result = handle_get_agent_identity(&json!({}), &agent_ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "alice");
    }

    // ── dispatch integration tests for new tools ────────────────────

    #[tokio::test]
    async fn call_tool_delete_fact() {
        let ctx = test_ctx();
        let result = call_tool("delete_fact", &json!({"fact_id": "f_nope"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("fact not found"));
    }

    #[tokio::test]
    async fn call_tool_list_entities() {
        let ctx = test_ctx();
        let result = call_tool("list_entities", &json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "no entities found");
    }

    #[tokio::test]
    async fn call_tool_get_bootstrap() {
        let ctx = test_ctx();
        let result = call_tool("get_bootstrap", &json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no bootstrap"));
    }

    #[tokio::test]
    async fn call_tool_list_sessions() {
        let ctx = test_ctx();
        let result = call_tool("list_sessions", &json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "no sessions");
    }

    #[tokio::test]
    async fn call_tool_delete_session() {
        let ctx = test_ctx();
        let result = call_tool("delete_session", &json!({"session_id": "nope"}), &ctx)
            .await
            .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("session not found"));
    }

    #[tokio::test]
    async fn call_tool_get_agent_identity() {
        let ctx = test_ctx();
        let result = call_tool("get_agent_identity", &json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "anonymous");
    }

    // ── passport dispatch integration tests ─────────────────────────

    #[tokio::test]
    async fn call_tool_issue_passport_requires_agent() {
        let ctx = test_ctx();
        let result = call_tool("issue_passport", &json!({}), &ctx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn call_tool_get_passport() {
        let ctx = test_ctx();
        let result = call_tool("get_passport", &json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("no agent identity"));
    }

    // ── constraint dispatch integration tests ───────────────────────

    #[tokio::test]
    async fn call_tool_declare_constraint() {
        let ctx = test_ctx();
        let result = call_tool(
            "declare_constraint",
            &json!({"constraint_type": "policy", "assertion": "Rotate API keys"}),
            &ctx,
        )
        .await
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.starts_with("constraint declared: c_"));
    }

    #[tokio::test]
    async fn call_tool_get_constraints() {
        let ctx = test_ctx();
        let result = call_tool("get_constraints", &json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(text, "no constraints found");
    }

    #[tokio::test]
    async fn call_tool_check_constraints() {
        let ctx = test_ctx();
        let result = call_tool(
            "check_constraints",
            &json!({"action_description": "Deploy to production"}),
            &ctx,
        )
        .await
        .unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("verdict: pass"));
    }

    // ── sync dispatch integration tests ────────────────────────────

    #[tokio::test]
    async fn call_tool_sync_pull_requires_passport() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();
        let ctx = test_ctx();
        let result = call_tool("sync_pull", &json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("authenticated agent identity"));
    }

    #[tokio::test]
    async fn call_tool_sync_push_requires_passport() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();
        let ctx = test_ctx();
        let result = call_tool("sync_push", &json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("authenticated agent identity"));
    }

    #[tokio::test]
    async fn call_tool_sync_status() {
        let _guard = sync_env_lock().lock().await;
        clear_sync_env();
        let ctx = test_ctx();
        let result = call_tool("sync_status", &json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"configured\": false"));
    }

    #[tokio::test]
    async fn call_tool_update_status() {
        let ctx = test_ctx();
        let result = call_tool("update_status", &json!({}), &ctx).await.unwrap();
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"state\": \"disabled\""));
    }
}
