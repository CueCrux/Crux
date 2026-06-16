// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! MCP tool definitions and sub-module dispatch.
//!
//! Each tool is described by a [`ToolDefinition`] with a JSON Schema input
//! specification. [`list_tools`] returns the full catalogue advertised to
//! MCP clients via the `tools/list` response.

pub mod action;
pub mod approvals;
pub mod artefacts;
pub mod audit;
pub mod audit_export;
pub mod autonomy;
pub mod constraint;
pub mod coordination;
pub mod cuecrux_session;
pub mod decision;
pub mod edges;
pub mod entities;
pub mod extensions;
pub mod facts;
pub mod features;
pub mod forget;
pub mod freshness;
pub mod github;
pub mod handoff;
pub mod hardening;
pub mod identity;
pub mod kinds;
pub mod loopback_auth;
pub mod memory;
pub mod memory_use;
pub mod observations;
pub mod observe;
pub mod orchestrators;
pub mod output_attest;
pub mod passport;
pub mod punchcards;
pub mod query;
pub mod receipt_verify;
pub mod resolve_principal;
pub mod sessions;
pub mod storyline;
pub mod surface;
pub mod sync;
pub mod token_usage;
pub mod traces;
pub mod update;

use serde_json::{json, Value};
use std::collections::HashSet;

use crate::dispatch::McpContext;
use crate::protocol::JsonRpcError;
use crux_router::{McpToolCapability, RcxRouter, FEDERATION_READ_CAPABILITY};
use rcx_capability_token::{DataEgressClass, RcxCapabilityToken};

/// Describes a single MCP tool for the `tools/list` response.
///
/// The struct intentionally has only the three "wire-shape" fields. The
/// per-tool **audit-envelope opt-in** is registered separately in
/// [`tool_emits_envelope`] so adding new envelope-aware tools doesn't
/// require touching every legacy `ToolDefinition { … }` literal in
/// [`list_tools`]. See the docs on [`tool_emits_envelope`] for the opt-in
/// pattern.
#[derive(Debug, Clone)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Per-tool audit-envelope opt-in registry (master ExecPlan
/// `agent-ux-best-in-class-master-2026-05-27`, M2).
///
/// Returns `true` iff the tool's responses should be wrapped with the
/// per-turn audit envelope when the `CORECRUXD_FEATURE_AUDIT_ENVELOPE`
/// feature flag is on. Wave-1 child plans #2 and #3 will add their new
/// tools here; Wave-2 plans extend it further. Every entry MUST also have
/// a matching arm in [`crate::envelope::build_envelope_for_tool`].
///
/// Default `false` for every tool not listed — older agents that ignore
/// `envelope` and never-listed tools always see the unchanged `payload`
/// shape.
pub fn tool_emits_envelope(name: &str) -> bool {
    // `memory_freshness` (agent-ux-03 M3) opts in to expose freshness info
    // alongside the envelope-style memories_used[] view.
    // `artefact_list` (agent-ux-12) is memory-adjacent — it surfaces parked
    // artefact ids as the `memories_used[]` envelope entries so the host can
    // render "I parked this for you" affordances next to the chat turn.
    // `artefact_put` + `artefact_get` are opaque-byte read/write and do NOT
    // opt in (no envelope on either).
    matches!(
        name,
        "query_facts" | "memory_acknowledge_use" | "memory_freshness" | "artefact_list"
    )
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
    list_tools_local_surface(false)
}

/// Like [`list_tools`], but flag-aware for the agent-passport feature
/// (`CORECRUXD_AGENT_PASSPORTS`).
///
/// When `agent_passports_enabled` is true, `issue_passport` is promoted to the
/// **local** tool surface (marker `[local]`, no `[hosted]`) so a mapped agent
/// on a local-tier install can reach it to bootstrap its passport + tier
/// ladder (agent-passport M2). This is the ONLY behaviour the flag changes
/// here; every other tool keeps its static surface tier from
/// [`vaultcrux_local::tool_surface`]. With the flag off this is byte-for-byte
/// identical to the pre-M2 `list_tools()` (the two gating assertions in this
/// module's tests still hold).
pub fn list_tools_local_surface(agent_passports_enabled: bool) -> Vec<ToolDefinition> {
    vec![
        // ── Session Handshake (master-plan §6) ────────────────────
        ToolDefinition {
            name: "cuecrux_session".to_string(),
            description: cuecrux_session::CUECRUX_SESSION_DESCRIPTION.to_string(),
            input_schema: cuecrux_session::tool_input_schema(),
        },
        // ── Autonomy contract (agent-ux-10) ────────────────────────
        ToolDefinition {
            name: "autonomy_contract".to_string(),
            description: autonomy::AUTONOMY_CONTRACT_DESCRIPTION.to_string(),
            input_schema: autonomy::tool_input_schema(),
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
                    "private":        { "type": "boolean", "description": "If true, scoped to the calling agent", "default": false },
                    "horizon_class":  { "type": "string", "enum": ["volatile", "medium", "stable", "none"], "description": "Freshness decay class set at write time (no second memory_set_horizon call needed). Omit to use the entity-prefix default." },
                    "freshness_horizon": { "type": "string", "description": "Free-text horizon line (e.g. 're-verify before relying after 7 days'); parsed to a horizon_class when horizon_class is omitted." },
                    "supersedes":     {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional fact_ids this new fact EXPLICITLY retires (cross-entity supersession). Each must exist and be visible to you, else the call is rejected. Retired facts are hidden from query_facts by default. Reversible."
                    }
                },
                "required": ["entity", "key", "value"],
                "examples": [
                    { "entity": "project-alpha", "key": "status", "value": "Phase 1 complete", "confidence": 0.95 },
                    { "entity": "my-agent", "key": "internal_state", "value": "Waiting for confirmation", "private": true },
                    { "entity": "bench:lme-s", "key": "baseline", "value": "90.0%", "horizon_class": "volatile", "supersedes": ["f_oldbaseline86"] }
                ]
            }),
        },
        ToolDefinition {
            name: "query_facts".to_string(),
            description: "Query the fact store by keyword, entity, or both. Results are \
                          ranked by time-decayed effective confidence (stale facts are \
                          demoted; stored confidence is preserved). Private facts are \
                          visible only to their owning agent."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query":        { "type": "string",  "description": "Keyword search across fact values, keys, and entities" },
                    "entity":       { "type": "string",  "description": "Filter to a specific entity" },
                    "top_k":        { "type": "integer", "description": "Maximum facts to return", "default": 10 },
                    "token_budget": { "type": "integer", "description": "Optional token budget" },
                    "include_superseded": { "type": "boolean", "description": "If true, also return facts explicitly retired via cross-entity supersession (their `superseded_by` is exposed). Default false (retired facts are hidden).", "default": false }
                },
                "examples": [
                    { "query": "deployment strategy", "token_budget": 2000 },
                    { "entity": "project-alpha", "top_k": 5 },
                    { "entity": "bench:lme-s", "include_superseded": true }
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
        // ── Acknowledged memory use (agent-ux-02) ────────────────────
        ToolDefinition {
            name: "memory_acknowledge_use".to_string(),
            description: "Declare which stored fact ids were consulted while producing the \
                          current turn. Requires an authenticated passport. Reserved-prefix \
                          entries (__agent::*, __ops::*, __bootstrap__::*) are stripped from \
                          the acknowledgement. Per-turn audit envelope surfaces the filtered \
                          list to the host so the consumer can render \"I used this\" \
                          annotations. Gated by CORECRUXD_FEATURE_MEMORY_ACK=1 (default off)."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "turn_id":  { "type": "string", "description": "Opaque per-host turn identifier" },
                    "fact_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Stored fact ids the agent consulted in producing this turn"
                    },
                    "intent": {
                        "type": "string",
                        "description": "answer | decision | tool_call | implicit (default: answer)"
                    },
                    "retrieved_chunk_ids": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Paid tier: chunks from memory-core retrieval. Free tier: ignored."
                    },
                    "confidence": { "type": "number", "description": "Optional 0..1 confidence" },
                    "note":       { "type": "string", "description": "Optional free-form note" }
                },
                "required": ["turn_id"],
                "examples": [
                    { "turn_id": "turn-42", "fact_ids": ["f_01J_abc", "f_01J_def"], "intent": "answer" }
                ]
            }),
        },
        // ── Verifiable output receipts (agent-ux-07 — EU AI Act Art. 50) ─
        ToolDefinition {
            name: "output_attest".to_string(),
            description: "Emit a C2PA-shaped Content Credentials manifest binding `content_bytes` to a \
                          CROWN receipt id. The returned `manifest_jumbf_base64` is verifiable offline by \
                          `corecruxctl output-verify` and online via the daemon `/v1/output/verify` route. \
                          Reuses the daemon's existing Ed25519 CROWN signer (no new key class). \
                          Requires an authenticated passport. Gated by CORECRUXD_FEATURE_C2PA_OUTPUT=1 \
                          (default off). Engineering scaffolding aligned with EU AI Act Art. 50; legal \
                          conformity assessment remains the operator's responsibility."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "content_bytes_base64": { "type": "string", "description": "Base64-encoded content bytes (one of content_bytes_base64 or content_path required)" },
                    "content_path":         { "type": "string", "description": "Local file path the daemon reads (alternative to content_bytes_base64)" },
                    "content_type":         { "type": "string", "description": "Optional MIME type (e.g. image/png)" },
                    "receipt_id":           { "type": "string", "description": "CROWN receipt id this artefact is bound to" },
                    "claim_generator":      { "type": "string", "description": "Optional claim_generator override (defaults to cuecrux/<version>)" },
                    "token_budget":         { "type": "integer", "description": "Soft cap on content size in tokens (~bytes/4)" }
                },
                "required": ["receipt_id"],
                "examples": [
                    { "content_bytes_base64": "iVBORw0KGgo...", "receipt_id": "r_01J_abc", "content_type": "image/png", "token_budget": 4000 }
                ]
            }),
        },
        // ── Scoped forget (agent-ux-09 — GDPR Art. 17) ─────────────
        ToolDefinition {
            name: "memory_forget".to_string(),
            description: "GDPR Art. 17 scoped erasure. Soft-deletes every fact matching a \
                          TYPED scope ({entity_prefix|key_glob|passport_id|before_timestamp|\
                          tenant_id}), filters out reserved prefixes, emits a signed `Forget` \
                          receipt that names the initiating passport. Requires authenticated \
                          agent identity and feature flag CORECRUXD_FEATURE_SCOPED_FORGET=1. \
                          Use `memory_forget_dry_run` first to preview affected facts."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "object",
                        "description": "Typed scope selector. `type` must be one of entity_prefix, key_glob, passport_id, before_timestamp, tenant_id.",
                        "oneOf": [
                            {"properties": {"type": {"const": "entity_prefix"}, "value": {"type": "string"}}, "required": ["type", "value"]},
                            {"properties": {"type": {"const": "key_glob"},      "value": {"type": "string"}}, "required": ["type", "value"]},
                            {"properties": {"type": {"const": "passport_id"},   "value": {"type": "string"}}, "required": ["type", "value"]},
                            {"properties": {"type": {"const": "before_timestamp"}, "value": {"type": "string", "format": "date-time"}}, "required": ["type", "value"]},
                            {"properties": {"type": {"const": "tenant_id"},     "value": {"type": "string"}}, "required": ["type", "value"]}
                        ]
                    },
                    "reason":       { "type": "string", "description": "Human-readable reason for the forget (audit-record requirement)." },
                    "tenant_id":    { "type": "string", "description": "Tenant the receipt is attributed to. Defaults to 'default'." },
                    "token_budget": { "type": "integer", "description": "Optional cap on the number of facts the resolver will touch (QC.2)." }
                },
                "required": ["scope", "reason"],
                "examples": [
                    { "scope": {"type": "entity_prefix", "value": "test-fixture-"}, "reason": "cleanup after benchmark" },
                    { "scope": {"type": "before_timestamp", "value": "2026-01-01T00:00:00Z"}, "reason": "annual purge", "tenant_id": "personal::myles" }
                ]
            }),
        },
        ToolDefinition {
            name: "memory_forget_dry_run".to_string(),
            description: "Preview a scoped-forget without mutating the store. Returns the \
                          count + list of facts that WOULD be soft-deleted. Reserved \
                          prefixes (`__agent::`, `__ops::`, `__bootstrap__::`, `__agent_session::`) \
                          are excluded. Respects `token_budget` (QC.2). Always available — \
                          does not require the feature flag."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "object",
                        "description": "Same typed scope as memory_forget."
                    },
                    "token_budget": { "type": "integer" }
                },
                "required": ["scope"],
                "examples": [
                    { "scope": {"type": "entity_prefix", "value": "test-fixture-"} },
                    { "scope": {"type": "key_glob", "value": "secret*"}, "token_budget": 500 }
                ]
            }),
        },
        // ── Memory panel (agent-ux-01) ──────────────────────────────
        ToolDefinition {
            name: "memory_view".to_string(),
            description: "Read consumer memory in a paginated, narrative-friendly shape. \
                          Returns facts grouped by entity with version + confidence + pin \
                          state. Reserved-prefix entries (__agent::*, __ops::*, \
                          __bootstrap__::*, __memory_pin::*) are filtered out. Honours \
                          `token_budget` (default 2000). Enabled by default; set \
                          CORECRUXD_FEATURE_MEMORY_PANEL=0 to disable."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "entity":       { "type": "string",  "description": "Filter to a specific entity" },
                    "key":          { "type": "string",  "description": "Filter to a specific key within the entity" },
                    "top_k":        { "type": "integer", "description": "Maximum facts to return", "default": 20 },
                    "token_budget": { "type": "integer", "description": "Total token budget across returned facts (default 2000)" }
                },
                "examples": [
                    { "token_budget": 2000, "top_k": 20 },
                    { "entity": "person:alice", "token_budget": 500 }
                ]
            }),
        },
        ToolDefinition {
            name: "memory_edit".to_string(),
            description: "Update the value of an existing fact. Creates a new version that \
                          supersedes the prior fact; the audit trail (`memory_history` / \
                          `fact_history`) preserves the chain. Requires an authenticated \
                          agent identity. The optional `reason` is embedded in the new \
                          fact's source_receipt as `memory_edit:<reason>`. Reserved-prefix \
                          entities are refused."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "fact_id":   { "type": "string", "description": "Existing fact id to update" },
                    "new_value": { "type": "string", "description": "Replacement value" },
                    "reason":    { "type": "string", "description": "Why the edit was made (becomes the receipt note)" }
                },
                "required": ["fact_id", "new_value"],
                "examples": [
                    { "fact_id": "f_01J_abc", "new_value": "Munich", "reason": "moved 2026-04" }
                ]
            }),
        },
        ToolDefinition {
            name: "memory_pin".to_string(),
            description: "Mark a fact as user-pinned (or unpin it). Pinned facts survive \
                          decay (#3) and scoped-forget (#9). Pin state is per-agent and is \
                          stored under the reserved `__memory_pin::<agent>::*` entity, so \
                          it never leaks across agents."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "fact_id": { "type": "string",  "description": "Fact id to (un)pin" },
                    "pinned":  { "type": "boolean", "description": "True to pin, false to unpin", "default": true }
                },
                "required": ["fact_id"],
                "examples": [
                    { "fact_id": "f_01J_abc", "pinned": true },
                    { "fact_id": "f_01J_abc", "pinned": false }
                ]
            }),
        },
        ToolDefinition {
            name: "memory_history".to_string(),
            description: "Walk the version chain for a memory entry, returned in \
                          consumer-friendly shape. Accepts either {entity, key} or \
                          {fact_id}. Reserved-prefix entries are refused; the operator-side \
                          `fact_history` tool still covers those."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "entity":  { "type": "string", "description": "Entity to walk" },
                    "key":     { "type": "string", "description": "Key within the entity" },
                    "fact_id": { "type": "string", "description": "Resolve (entity, key) via this fact id" }
                },
                "examples": [
                    { "entity": "person:carol", "key": "city" },
                    { "fact_id": "f_01J_abc" }
                ]
            }),
        },
        // ── Freshness + decay (agent-ux-03 M3) ─────────────────────
        ToolDefinition {
            name: "memory_freshness".to_string(),
            description: "Freshness: list facts with their per-fact decay state \
                          ({fresh|stale|unknown}) under the deterministic decay policy. \
                          Reserved-prefix facts (__agent::, __ops::, __bootstrap__::) are \
                          filtered. Read-only; pass `token_budget` (default 500) per QC.2. \
                          Enabled by default; set CORECRUXD_FEATURE_FRESHNESS=0 to disable."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "entity":       { "type": "string", "description": "Optional entity filter" },
                    "key":          { "type": "string", "description": "Optional key filter" },
                    "top_k":        { "type": "integer", "description": "Maximum rows", "default": 20 },
                    "token_budget": { "type": "integer", "description": "Token budget cap", "default": 500 }
                },
                "examples": [
                    { "token_budget": 500 },
                    { "entity": "execplan:agent-ux-03-freshness-decay-2026-05-27", "top_k": 50, "token_budget": 1000 }
                ]
            }),
        },
        ToolDefinition {
            name: "memory_sweep_candidates".to_string(),
            description: "Janitor (read-only): list facts that are EITHER stale (per the \
                          deterministic decay policy) OR explicitly cross-entity superseded \
                          (retired by a newer fact), as archive/reverify candidates. \
                          NON-mutating — like memory_forget_dry_run, nothing is changed. \
                          Reserved-prefix facts are filtered. Each row carries a `reason` \
                          ({stale|superseded|stale+superseded}). Pass `token_budget` \
                          (default 500) per QC.2. Enabled by default; set \
                          CORECRUXD_FEATURE_FRESHNESS=0 to disable."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "top_k":        { "type": "integer", "description": "Maximum candidate rows", "default": 50 },
                    "token_budget": { "type": "integer", "description": "Token budget cap", "default": 500 }
                },
                "examples": [
                    { "token_budget": 500 },
                    { "top_k": 100, "token_budget": 2000 }
                ]
            }),
        },
        ToolDefinition {
            name: "memory_set_horizon".to_string(),
            description: "Freshness: pin or override the horizon_class on a fact \
                          (`volatile`, `medium`, `stable`, `none`). Requires an \
                          authenticated passport. Reserved-prefix facts cannot be \
                          re-classified through this surface. Enabled by default; \
                          set CORECRUXD_FEATURE_FRESHNESS=0 to disable."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "fact_id":        { "type": "string", "description": "Target fact id (f_…)" },
                    "horizon_class":  { "type": "string", "enum": ["volatile", "medium", "stable", "none"] }
                },
                "required": ["fact_id", "horizon_class"],
                "examples": [
                    { "fact_id": "f_01J_abc", "horizon_class": "stable" }
                ]
            }),
        },
        ToolDefinition {
            name: "memory_reverify".to_string(),
            description: "Freshness: re-anchor a fact's decay clock without rewriting the \
                          value, recording a CROWN-verifiable `Reverify` receipt under \
                          `__reverify_receipts__::<fact_id>`. Requires an authenticated \
                          passport. Enabled by default; set CORECRUXD_FEATURE_FRESHNESS=0 \
                          to disable."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "fact_id": { "type": "string", "description": "Target fact id (f_…)" }
                },
                "required": ["fact_id"],
                "examples": [
                    { "fact_id": "f_01J_abc" }
                ]
            }),
        },
        // ── Artefacts (agent-ux-12 — calm deferred output) ────────
        ToolDefinition {
            name: "artefact_put".to_string(),
            description: "Park a large byte payload under a passport-owned, BLAKE3-keyed id. \
                          Returns `{artefact_id, size_bytes, mime_type, created_at, expires_at}` — \
                          the content itself is fetched separately via `artefact_get`. Identical \
                          bytes always produce the same id (content-addressed). Default TTL 7 days, \
                          max 90 days. Requires an authenticated passport. Gated by \
                          CORECRUXD_FEATURE_ARTEFACTS=1 (default off)."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "content_bytes_base64": { "type": "string",  "description": "Base64-encoded content bytes (required for inline put)." },
                    "mime_type":             { "type": "string",  "description": "Free-form MIME label (e.g. application/json, application/x-c2pa-manifest)." },
                    "tool_origin":           { "type": "string",  "description": "Optional 'which tool produced this' label, surfaced in artefact_list." },
                    "ttl_seconds":           { "type": "integer", "description": "Optional TTL in seconds. Default 7d. Max 90d. 0 = no expiry." },
                    "token_budget":          { "type": "integer", "description": "Mandatory output-token cap (QC.2). Honoured by the response shape." }
                },
                "required": ["content_bytes_base64", "mime_type"],
                "examples": [
                    { "content_bytes_base64": "eyJzaGEyNTYiOiJhYmMifQ==", "mime_type": "application/json", "tool_origin": "audit_export_bundle", "token_budget": 500 }
                ]
            }),
        },
        ToolDefinition {
            name: "artefact_get".to_string(),
            description: "Fetch a previously-put artefact by id. Returns `{content_base64, mime_type, \
                          size_bytes, created_at, expires_at}`. Cross-passport reads return \
                          CAPABILITY_DENIED so the operator can audit. Reserved-prefix mime entries \
                          are still readable by their owner — filtering only applies to list output. \
                          Gated by CORECRUXD_FEATURE_ARTEFACTS=1."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "artefact_id":  { "type": "string",  "description": "Content-addressed id returned by artefact_put." },
                    "token_budget": { "type": "integer", "description": "Mandatory output-token cap (QC.2)." }
                },
                "required": ["artefact_id"],
                "examples": [
                    { "artefact_id": "art_0123abcd…", "token_budget": 4000 }
                ]
            }),
        },
        ToolDefinition {
            name: "artefact_list".to_string(),
            description: "List metadata for artefacts owned by the calling passport. Reserved-prefix \
                          mime entries are filtered out (T.1). Cross-passport entries are never \
                          included. Newest-first, capped at `top_k`. Optional `scope` substring \
                          filters by mime_type or tool_origin. This is the read surface the console \
                          /artefacts panel calls. Gated by CORECRUXD_FEATURE_ARTEFACTS=1."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "top_k":        { "type": "integer", "description": "Max artefacts to return (default 20).", "default": 20 },
                    "scope":        { "type": "string",  "description": "Optional mime_type / tool_origin substring filter." },
                    "token_budget": { "type": "integer", "description": "Mandatory output-token cap (QC.2)." }
                },
                "examples": [
                    { "token_budget": 500 },
                    { "top_k": 50, "scope": "audit_export_bundle", "token_budget": 2000 }
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
            name: "session_checkpoint".to_string(),
            description: "Store a compact, typed checkpoint for resuming an agent session. \
                          Requires token_budget so checkpoint output stays bounded."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id":        { "type": "string",  "description": "Session identifier" },
                    "objective":         { "type": "string",  "description": "Current concrete objective" },
                    "current_milestone": { "type": "string",  "description": "Current milestone or gate" },
                    "decisions":         { "type": "array",   "items": {}, "description": "Key decisions made" },
                    "open_questions":    { "type": "array",   "items": {}, "description": "Known blockers or questions" },
                    "files_touched":     { "type": "array",   "items": { "type": "string" }, "description": "Files touched or expected" },
                    "commands_run":      { "type": "array",   "items": { "type": "string" }, "description": "Important verification commands" },
                    "test_status":       { "description": "Current test/gate status" },
                    "next_action":       { "type": "string",  "description": "Next concrete action" },
                    "ttl_seconds":       { "type": "integer", "description": "Optional time-to-live in seconds" },
                    "token_budget":      { "type": "integer", "description": "Mandatory output-token cap" }
                },
                "required": ["session_id", "token_budget"],
                "examples": [
                    { "session_id": "audit-1", "current_milestone": "M2", "next_action": "run focused tests", "token_budget": 500 }
                ]
            }),
        },
        ToolDefinition {
            name: "list_sessions".to_string(),
            description: "List active session IDs visible to you. Returns a sorted list. Archived sessions are hidden unless include_archived=true.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "include_archived": { "type": "boolean", "description": "Include archived sessions in the listing (default false)" }
                },
                "examples": [{}, { "include_archived": true }]
            }),
        },
        ToolDefinition {
            name: "delete_session".to_string(),
            description: "Delete one of your sessions by ID. Returns confirmation or not-found. Destructive — prefer archive_session to preserve the session for reference.".to_string(),
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
        ToolDefinition {
            name: "archive_session".to_string(),
            description: "Archive one of your sessions by ID — preserves its state in full but hides it from the default list_sessions view. Reversible via unarchive_session.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string", "description": "Session identifier to archive" },
                    "reason":     { "type": "string", "description": "Optional reason for archiving (e.g. 'shipped', 'parked')" }
                },
                "required": ["session_id"],
                "examples": [
                    { "session_id": "session-42", "reason": "shipped" }
                ]
            }),
        },
        ToolDefinition {
            name: "unarchive_session".to_string(),
            description: "Restore a previously archived session by ID — returns it to the default list_sessions view.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string", "description": "Session identifier to restore" }
                },
                "required": ["session_id"],
                "examples": [
                    { "session_id": "session-42" }
                ]
            }),
        },
        ToolDefinition {
            name: "route_access_matrix".to_string(),
            description: "Return the current high-risk HTTP route access matrix used by agent hardening checks."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "examples": [{}]
            }),
        },
        ToolDefinition {
            name: "execplan_gate".to_string(),
            description: "Record an ExecPlan milestone gate as a stable fact under execplan:<slug>."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "slug":          { "type": "string",  "description": "ExecPlan slug without execplan: prefix" },
                    "milestone":     { "type": "string",  "description": "Milestone id, e.g. M2 or gate:M2" },
                    "status":        { "type": "string",  "enum": ["passed", "failed", "blocked", "skipped"] },
                    "commit_sha":    { "type": "string",  "description": "Source commit SHA for the gate" },
                    "tests_passing": { "type": "boolean", "description": "Whether relevant tests passed" },
                    "artifacts":     { "type": "array",   "items": { "type": "string" }, "description": "Related files, logs, or PR links" },
                    "notes":         { "type": "string",  "description": "Short gate note" },
                    "token_budget":  { "type": "integer", "description": "Mandatory output-token cap" }
                },
                "required": ["slug", "milestone", "status", "commit_sha", "token_budget"],
                "examples": [
                    { "slug": "crux-daemon-hardening", "milestone": "M2", "status": "passed", "commit_sha": "abc1234", "token_budget": 500 }
                ]
            }),
        },
        ToolDefinition {
            name: "auth_posture_audit".to_string(),
            description: "Return a compact local auth-posture checklist for the current MCP daemon context."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "examples": [{}]
            }),
        },
        ToolDefinition {
            name: "egress_policy_check".to_string(),
            description: "Check whether a proposed URL egress target matches the local conservative egress policy."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target":              { "type": "string",  "description": "Target URL to check" },
                    "purpose":             { "type": "string",  "description": "Audit purpose for the egress" },
                    "allow_loopback_http": { "type": "boolean", "description": "Allow http:// loopback targets", "default": true },
                    "allow_plain_http":    { "type": "boolean", "description": "Allow external plain HTTP", "default": false }
                },
                "required": ["target"],
                "examples": [
                    { "target": "https://api.example.com/v1", "purpose": "metadata lookup" },
                    { "target": "http://127.0.0.1:14800/readyz", "purpose": "local readiness probe" }
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
        // ── Session observations (multi-provider capture) ──────────
        ToolDefinition {
            name: "list_observations".to_string(),
            description: "List signed observations captured for a session. Each record \
                          carries an Ed25519 receipt verifiable against the daemon's \
                          published passport public key. Optional `since` (RFC3339), \
                          `provider`, and `limit` filters."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id": { "type": "string", "description": "Session whose observations to list" },
                    "since":      { "type": "string", "description": "RFC3339 lower bound on observation ts" },
                    "provider":   { "type": "string", "description": "Filter by capture provider (claude-code, openai, anthropic, codex-cli, openclaw)" },
                    "limit":      { "type": "integer", "description": "Max records to return (default 50, max 500)" }
                },
                "required": ["session_id"],
                "examples": [
                    { "session_id": "my-session" },
                    { "session_id": "my-session", "provider": "claude-code", "limit": 20 }
                ]
            }),
        },
        ToolDefinition {
            name: "get_observation".to_string(),
            description: "Fetch a single observation by id from a given session.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id":     { "type": "string", "description": "Session id" },
                    "observation_id": { "type": "string", "description": "Observation UUID" }
                },
                "required": ["session_id", "observation_id"],
                "examples": [
                    { "session_id": "my-session", "observation_id": "01HXXXXXXXXX" }
                ]
            }),
        },
        ToolDefinition {
            name: "verify_observation".to_string(),
            description: "Re-canonicalise an observation, recompute its BLAKE3 body hash, \
                          and verify the Ed25519 signature against the daemon's published \
                          passport public key. Returns `{ok, hash_match, signature_valid}`."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id":     { "type": "string", "description": "Session id" },
                    "observation_id": { "type": "string", "description": "Observation UUID to verify" }
                },
                "required": ["session_id", "observation_id"],
                "examples": [
                    { "session_id": "my-session", "observation_id": "01HXXXXXXXXX" }
                ]
            }),
        },
        // ── Receipt verification (agent-ux-04 source-linked traceability) ──
        ToolDefinition {
            name: "receipt_verify".to_string(),
            description: "Re-verify a CROWN receipt by id via the daemon's existing \
                          /v1/receipts/{id}/verification route. Returns \
                          `{verified, signer_passport, errors[]}` so a host IDE can render \
                          a one-click verify badge next to receipt ids in chat. Requires an \
                          authenticated agent identity (audit pattern: only the signer or an \
                          operator should re-verify). Gated by \
                          CORECRUXD_FEATURE_RECEIPT_VERIFY=1 (default off)."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "receipt_id": { "type": "string", "description": "Receipt id to verify (e.g. r_01JXXXXXX)" },
                    "tenant_id":  { "type": "string", "description": "Tenant id the receipt belongs to (default: \"default\")" }
                },
                "required": ["receipt_id"],
                "examples": [
                    { "receipt_id": "r_01JABC" },
                    { "receipt_id": "r_01JABC", "tenant_id": "personal::myles" }
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
        ToolDefinition {
            name: "resolve_principal".to_string(),
            description: resolve_principal::RESOLVE_PRINCIPAL_DESCRIPTION.to_string(),
            input_schema: resolve_principal::tool_input_schema(),
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
                        "enum": ["boundary", "relationship", "policy", "context_flag", "shell_pattern"],
                        "description": "The kind of constraint. `shell_pattern` treats the assertion as a regex matched against `tool_parameters.command` for Bash/shell calls."
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
                          matches warn. If tool_name/tool_parameters are supplied, the \
                          action is deterministically enriched before matching."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action_description": {
                        "type": "string",
                        "description": "Description of the action to check against constraints"
                    },
                    "tool_name": {
                        "type": "string",
                        "description": "Optional tool name to enrich into a structured action proposal before constraint matching"
                    },
                    "tool_parameters": {
                        "type": "object",
                        "description": "Optional tool parameters used by deterministic basic action enrichment"
                    },
                    "tenant_id": {
                        "type": "string",
                        "description": "Optional tenant identifier to include in the enrichment receipt"
                    }
                },
                "examples": [
                    { "action_description": "Delete all user records from the production database" },
                    { "action_description": "Deploy updated API to staging environment" },
                    { "tenant_id": "business::acme", "tool_name": "calendar.move_event", "tool_parameters": { "event_id": "evt_1", "attendees": ["customer@example.com"], "new_time": "2026-05-08T16:00:00Z" } }
                ]
            }),
        },
        ToolDefinition {
            name: "audit_config".to_string(),
            description: "Record an attestation that a config file's content hash has been \
                          reviewed. Idempotent on sha256 — re-auditing the same hash updates \
                          the record's path/auditor/timestamp. Records live under \
                          `__ops::config-audit` keyed by `sha256:<hash>`, so the SessionStart \
                          hook (or any caller) can ask `check_config_audit` which paths still \
                          need review."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path observed at audit time (advisory; the hash is canonical identity)"
                    },
                    "sha256": {
                        "type": "string",
                        "description": "Lowercase 64-char hex SHA-256 digest of the file contents"
                    },
                    "auditor": {
                        "type": "string",
                        "description": "Passport id, email, or free-text identifier of the auditor"
                    },
                    "note": {
                        "type": "string",
                        "description": "Optional context (PR link, ticket, rationale)"
                    }
                },
                "required": ["path", "sha256", "auditor"],
                "examples": [
                    {
                        "path": "/home/u/.claude/settings.json",
                        "sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                        "auditor": "passport:ops-2026",
                        "note": "reviewed for PR #42"
                    }
                ]
            }),
        },
        ToolDefinition {
            name: "check_config_audit".to_string(),
            description: "Given a list of {path, sha256} pairs, return which entries are \
                          unaudited. Typical caller: SessionStart hook that has just hashed \
                          settings.json / .mcp.json / CLAUDE.md and wants a warn-only signal \
                          surfaced via additionalContext."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "paths": {
                        "type": "array",
                        "description": "Array of {path, sha256} objects to check",
                        "items": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                                "sha256": {"type": "string"}
                            },
                            "required": ["path", "sha256"]
                        }
                    }
                },
                "required": ["paths"],
                "examples": [
                    {
                        "paths": [
                            {"path": "/home/u/.claude/settings.json", "sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"},
                            {"path": "/home/u/.mcp.json", "sha256": "deadbeef0000000000000000000000000000000000000000000000000000cafe"}
                        ]
                    }
                ]
            }),
        },
        ToolDefinition {
            name: "enrich_action".to_string(),
            description: "Build a deterministic EnrichedActionProposal from a raw tool call. \
                          This is the Free/basic local path: it records consequence metadata, \
                          affected principals/resources, a narrative for constraint matching, \
                          and a local enrichment receipt. Pro first-party enrichers are exposed \
                          on the daemon HTTP route POST /v1/actions/enrich."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "tenant_id": {
                        "type": "string",
                        "description": "Optional tenant identifier for the enrichment receipt"
                    },
                    "tool_name": {
                        "type": "string",
                        "description": "Tool being considered"
                    },
                    "tool_parameters": {
                        "type": "object",
                        "description": "Structured parameters for the proposed tool call",
                        "default": {}
                    },
                    "action_description": {
                        "type": "string",
                        "description": "Optional natural-language action description"
                    }
                },
                "required": ["tool_name"],
                "examples": [
                    { "tenant_id": "business::acme", "tool_name": "calendar.move_event", "tool_parameters": { "event_id": "evt_1", "attendees": ["customer@example.com"], "new_time": "2026-05-08T16:00:00Z" }, "action_description": "Move customer meeting to Friday at 4pm" },
                    { "tool_name": "github.deploy", "tool_parameters": { "repo": "CueCrux/Crux", "environment": "production" } }
                ]
            }),
        },
        // ── BYO audit trail (agent-ux-11) ──────────────────────────
        ToolDefinition {
            name: "audit_export_bundle".to_string(),
            description: "Bring-Your-Own audit-trail export (EU AI Act Art. 12). Builds a \
                          self-contained, signed `tar.zst` bundle of every fact-event in \
                          the time window plus the cross-references to source receipts. \
                          The bundle re-verifies OFFLINE via `corecruxctl audit-verify` — \
                          no daemon, no network. Reserved prefixes (__agent::*, __ops::*, \
                          __bootstrap__::*) are filtered out unless the caller is \
                          operator-tier (authenticated passport + scope.include_reserved). \
                          REQUIRES `token_budget` (QC.2). Gated by \
                          CORECRUXD_FEATURE_AUDIT_EXPORT=1 (default off)."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "since_ts":     { "type": "string",  "description": "RFC3339 lower bound, inclusive (optional)" },
                    "until_ts":     { "type": "string",  "description": "RFC3339 upper bound, exclusive (optional; defaults to now)" },
                    "scope": {
                        "type": "object",
                        "description": "Optional scope filter.",
                        "properties": {
                            "entity_prefix":    { "type": "string",  "description": "Restrict to entities matching this prefix" },
                            "include_reserved": { "type": "boolean", "description": "Operator-only: include reserved-prefix entries. Silently ignored for non-operator callers.", "default": false }
                        }
                    },
                    "token_budget": { "type": "integer", "description": "REQUIRED — caps total tokens swept (QC.2)" }
                },
                "required": ["token_budget"],
                "examples": [
                    { "token_budget": 4000, "since_ts": "2026-05-01T00:00:00Z" },
                    { "token_budget": 8000, "since_ts": "2026-01-01T00:00:00Z", "until_ts": "2026-06-01T00:00:00Z", "scope": {"entity_prefix": "project-"} }
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
        // ── Identity continuity (agent-ux-08) ──────────────────────
        ToolDefinition {
            name: "passport_split".to_string(),
            description: "Fork a passport into a new identity that inherits the source's \
                          facts via lineage read-through; future writes diverge to the new \
                          id. Caller must own the source passport AND hold operator-tier \
                          (trusted+). Cross-tenant splits are forbidden (T.1). Emits a \
                          PassportSplit CROWN receipt. NOT REVERSIBLE at the fact level. \
                          Gated behind CORECRUXD_FEATURE_IDENTITY_CONTINUITY=1."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target_passport": {
                        "type": "string",
                        "description": "Passport id to fork. Must equal the calling agent's passport."
                    },
                    "new_passport_name": {
                        "type": "string",
                        "description": "Name for the new passport. Must share the source's tenant prefix."
                    },
                    "reason": {
                        "type": "string",
                        "description": "Human-readable rationale recorded in the receipt body."
                    },
                    "token_budget": {
                        "type": "integer",
                        "description": "Required positive cap on resolver work (QC.2).",
                        "minimum": 1
                    }
                },
                "required": ["target_passport", "new_passport_name", "token_budget"],
                "examples": [
                    {
                        "target_passport": "personal::alice",
                        "new_passport_name": "personal::alice-work",
                        "reason": "separate work persona",
                        "token_budget": 500
                    }
                ]
            }),
        },
        ToolDefinition {
            name: "passport_merge".to_string(),
            description: "Collapse two passports under one identity. Caller must own \
                          the source OR target passport AND hold operator-tier (trusted+). \
                          Cross-tenant merges are forbidden (T.1). `conflict_policy` is \
                          MANDATORY and EXPLICIT: prefer_source | prefer_target | \
                          error_on_conflict — never silently chosen. Emits a PassportMerge \
                          CROWN receipt. The source passport is retired (sessions become \
                          read-only references). NOT REVERSIBLE at the fact level. Gated \
                          behind CORECRUXD_FEATURE_IDENTITY_CONTINUITY=1."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "source_passport": {
                        "type": "string",
                        "description": "Passport to retire into the target."
                    },
                    "target_passport": {
                        "type": "string",
                        "description": "Surviving passport id."
                    },
                    "conflict_policy": {
                        "type": "string",
                        "enum": ["prefer_source", "prefer_target", "error_on_conflict"],
                        "description": "How to resolve (entity, key) conflicts. Required; never silent."
                    },
                    "reason": {
                        "type": "string",
                        "description": "Human-readable rationale recorded in the receipt body."
                    },
                    "token_budget": {
                        "type": "integer",
                        "description": "Required positive cap on conflict-detection work (QC.2).",
                        "minimum": 1
                    }
                },
                "required": ["source_passport", "target_passport", "conflict_policy", "token_budget"],
                "examples": [
                    {
                        "source_passport": "personal::alice-old",
                        "target_passport": "personal::alice",
                        "conflict_policy": "prefer_target",
                        "reason": "consolidate after device retirement",
                        "token_budget": 500
                    }
                ]
            }),
        },
        ToolDefinition {
            name: "passport_link_device".to_string(),
            description: "Bind an additional device fingerprint to the calling agent's \
                          passport with a capability subset (defaults to facts:read). \
                          Requires operator-tier (trusted+) on the calling passport. \
                          Fingerprint MUST be a 64-char lowercase BLAKE3 hex digest \
                          over the device's canonical attestation blob — raw attestations \
                          are never stored. Emits a PassportLinkDevice CROWN receipt. \
                          Gated behind CORECRUXD_FEATURE_IDENTITY_CONTINUITY=1."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "device_fingerprint": {
                        "type": "string",
                        "description": "64-char lowercase BLAKE3 hex digest of the device attestation."
                    },
                    "capabilities_subset": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Capability strings propagated to the linked device. Defaults to [facts:read]."
                    },
                    "token_budget": {
                        "type": "integer",
                        "description": "Required positive token budget (QC.2).",
                        "minimum": 1
                    }
                },
                "required": ["device_fingerprint", "token_budget"],
                "examples": [
                    {
                        "device_fingerprint": "af2c4e3b6d8a9c1e0f7b5a3d2c1e8f4a9d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a",
                        "capabilities_subset": ["facts:read"],
                        "token_budget": 500
                    }
                ]
            }),
        },
        // ── Sync ──────────────────────────────────────────────────
        ToolDefinition {
            name: "sync_pull".to_string(),
            description: "Pull shared cloud tenant facts into this local-first daemon's \
                          mirror. Resumes from the last pull cursor; local private memory \
                          stays local. Requires CORECRUXD_SYNC_REMOTE_URL and \
                          CORECRUXD_SYNC_API_KEY to be configured."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "entity_prefix": {
                        "type": "string",
                        "description": "Optional entity prefix filter (reserved for future use)"
                    },
                    "tenant_id": {
                        "type": "string",
                        "description": "When set, pull the collection-aware mirror for this personal/business tenant instead of using the legacy all-facts export."
                    }
                },
                "examples": [{}, { "tenant_id": "personal::myles" }, { "tenant_id": "business::acme" }]
            }),
        },
        ToolDefinition {
            name: "sync_push".to_string(),
            description: "Promote selected local facts to the shared cloud tenant. Only \
                          pushes facts that were created locally (not previously synced). \
                          Private facts and sensitive entity prefixes are never pushed. \
                          Call without confirm=true to preview what would be promoted. \
                          Requires CORECRUXD_SYNC_REMOTE_URL and CORECRUXD_SYNC_API_KEY."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "confirm": { "type": "boolean", "description": "Set to true to actually push. Without this, returns a preview of facts that would be pushed.", "default": false },
                    "tenant_id": { "type": "string", "description": "When set, use collection-aware tenant promotion instead of the legacy all-facts push." },
                    "allowlist": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Tenant promotion allowlist entries such as facts, constraints, plans, collection:facts, entity:business::acme::public, or *."
                    }
                },
                "examples": [{}, { "confirm": true }, { "tenant_id": "business::acme", "allowlist": ["facts", "constraints"] }, { "tenant_id": "business::acme", "allowlist": ["facts", "constraints"], "confirm": true }]
            }),
        },
        ToolDefinition {
            name: "sync_status".to_string(),
            description: "Show whether this node is local-only, cloud-mirror configured, \
                          full background sync, or degraded. Includes remote reachability, \
                          pull/push timestamps, local fact count, and onboarding guidance \
                          for local-first or hosted Pro setups."
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
        // ── Coordination (Plan A M5) ───────────────────────────
        ToolDefinition {
            name: "list_projects".to_string(),
            description: coordination::LIST_PROJECTS_DESCRIPTION.to_string(),
            input_schema: json!({ "type": "object", "properties": {}, "examples": [{}] }),
        },
        ToolDefinition {
            name: "get_project_context".to_string(),
            description: coordination::GET_PROJECT_CONTEXT_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": { "project_id": { "type": "string" } },
                "required": ["project_id"],
                "examples": [{ "project_id": "default" }]
            }),
        },
        ToolDefinition {
            name: "list_work".to_string(),
            description: coordination::LIST_WORK_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id":        { "type": "string" },
                    "state":             { "type": "string", "enum": ["planned", "in_progress", "blocked", "archive", "complete", "deployed"] },
                    "tenant_id":         { "type": "string" },
                    "assignee_passport": { "type": "string" }
                },
                "examples": [
                    { "state": "in_progress" },
                    { "project_id": "default", "state": "planned" }
                ]
            }),
        },
        ToolDefinition {
            name: "create_work".to_string(),
            description: coordination::CREATE_WORK_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id":           { "type": "string", "description": "An EXISTING project id (from list_projects). There is no implicit 'default' project; an unknown id returns 'project not found'." },
                    "title":                { "type": "string" },
                    "body":                 { "type": "string" },
                    "state":                { "type": "string", "enum": ["planned", "in_progress", "blocked", "archive", "complete", "deployed"] },
                    "assignee_passport":    { "type": "string" },
                    "tenant_id":            { "type": "string" },
                    "linked_pr":            { "type": "string" },
                    "linked_issue":         { "type": "string" },
                    "created_by_passport":  { "type": "string", "description": "The passport authoring this work item — typically your bound session passport." }
                },
                "required": ["project_id", "title", "created_by_passport"],
                "examples": [
                    { "project_id": "<an-existing-project-id>", "title": "fix flaky test", "created_by_passport": "personal-default" }
                ]
            }),
        },
        ToolDefinition {
            name: "update_work_state".to_string(),
            description: coordination::UPDATE_WORK_STATE_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "work_id":         { "type": "string" },
                    "state":           { "type": "string", "enum": ["planned", "in_progress", "blocked", "archive", "complete", "deployed"] },
                    "by_passport":     { "type": "string" },
                    "blocker_reason":  { "type": "string", "description": "Required when transitioning to 'blocked'." }
                },
                "required": ["work_id", "state", "by_passport"],
                "examples": [
                    { "work_id": "w_abc123", "state": "in_progress", "by_passport": "personal-default" },
                    { "work_id": "w_abc123", "state": "blocked", "by_passport": "personal-default", "blocker_reason": "waiting on infra rotation" }
                ]
            }),
        },
        ToolDefinition {
            name: "comment_on_work".to_string(),
            description: coordination::COMMENT_ON_WORK_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "work_id":          { "type": "string" },
                    "author_passport":  { "type": "string" },
                    "body":             { "type": "string" }
                },
                "required": ["work_id", "author_passport", "body"],
                "examples": [
                    { "work_id": "w_abc123", "author_passport": "personal-default", "body": "tried option A; fails on env reload — recommending option B" }
                ]
            }),
        },
        ToolDefinition {
            name: "coord_status".to_string(),
            description: coordination::COORD_STATUS_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "project_id": { "type": "string", "description": "Optional project filter; sessions bound to no project are always included." }
                },
                "examples": [ {}, { "project_id": "default" } ]
            }),
        },
        ToolDefinition {
            name: "coord_announce".to_string(),
            description: coordination::COORD_ANNOUNCE_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id":    { "type": "string", "description": "Your bound session id (hex) — the one cuecrux_session minted." },
                    "project_id":    { "type": "string" },
                    "by_passport":   { "type": "string", "description": "Optional; the session binding's passport wins when the session is bound." },
                    "execplan_slug": { "type": "string" },
                    "milestone":     { "type": "string" },
                    "paths":         { "type": "array", "items": { "type": "string" }, "description": "Repo-relative files/dirs you expect to touch (informational; use punch_in for an enforceable lease)." },
                    "note":          { "type": "string" },
                    "ttl_seconds":   { "type": "integer", "description": "Intent lifetime (default 14400 = 4h, max 86400). 0 clears your intent." }
                },
                "required": ["session_id", "project_id"],
                "examples": [
                    { "session_id": "deadbeefcafe", "project_id": "default", "execplan_slug": "crux-agent-presence-coordination-2026-06-11", "milestone": "M3", "paths": ["crates/crux-mcp/src/tools/coordination.rs"] },
                    { "session_id": "deadbeefcafe", "project_id": "default", "ttl_seconds": 0 }
                ]
            }),
        },
        // ── GitHub indexed corpus (Plan B G5) ───────────────────
        ToolDefinition {
            name: "github_search".to_string(),
            description: github::GITHUB_SEARCH_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "repo":  { "type": "string", "description": "Optional `owner/repo` filter" },
                    "top_k": { "type": "integer", "default": 20 }
                },
                "required": ["query"],
                "examples": [
                    { "query": "auth rotation", "top_k": 10 },
                    { "query": "deploy", "repo": "cuecrux/Crux", "top_k": 20 }
                ]
            }),
        },
        ToolDefinition {
            name: "github_recent_commits".to_string(),
            description: github::GITHUB_RECENT_COMMITS_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo":  { "type": "string", "description": "owner/repo" },
                    "limit": { "type": "integer", "default": 20 }
                },
                "required": ["repo"],
                "examples": [{ "repo": "cuecrux/Crux", "limit": 10 }]
            }),
        },
        ToolDefinition {
            name: "github_open_prs".to_string(),
            description: github::GITHUB_OPEN_PRS_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo":  { "type": "string" },
                    "limit": { "type": "integer", "default": 20 }
                },
                "required": ["repo"],
                "examples": [{ "repo": "cuecrux/Crux" }]
            }),
        },
        ToolDefinition {
            name: "github_open_issues".to_string(),
            description: github::GITHUB_OPEN_ISSUES_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "repo":  { "type": "string" },
                    "label": { "type": "string", "description": "Filter by exact label match" },
                    "limit": { "type": "integer", "default": 20 }
                },
                "required": ["repo"],
                "examples": [{ "repo": "cuecrux/Crux", "label": "bug" }]
            }),
        },
        ToolDefinition {
            name: "github_comments_since".to_string(),
            description: github::GITHUB_COMMENTS_SINCE_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "default": 50 }
                },
                "examples": [{ "limit": 30 }]
            }),
        },
        // ── Workspace storyline ──────────────────────────────────────
        ToolDefinition {
            name: "get_workspace_storyline".to_string(),
            description: storyline::description().to_string(),
            input_schema: storyline::input_schema(),
        },
        // ── Substrate: entities / edges / kinds (M1) ──────────────
        ToolDefinition {
            name: "entity_upsert".to_string(),
            description: "Substrate: upsert an entity in the domain substrate. `kind` must \
                          be a registered KindRegistry kind (lens crates register at \
                          startup). `payload` is validated against the kind's JSON-Schema."
                .to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "kind":{"type":"string","description":"Entity kind (e.g. 'capability', 'repo')"},
                    "id":{"type":"string","description":"Entity ID within its kind"},
                    "payload":{"type":"object","description":"Domain payload (kind-specific schema)"}
                },
                "required":["kind","id","payload"],
                "examples":[{"kind":"capability","id":"CORECRUX-RECEIPTS","payload":{"name":"Receipts","system":"CoreCrux","maturity":"shipped"}}]
            }),
        },
        ToolDefinition {
            name: "entity_get".to_string(),
            description: "Substrate: fetch one entity by (kind, id). Returns null payload if missing.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "kind":{"type":"string"},
                    "id":{"type":"string"},
                    "include_deleted":{"type":"boolean","default":false}
                },
                "required":["kind","id"],
                "examples":[{"kind":"capability","id":"CORECRUX-RECEIPTS"}]
            }),
        },
        ToolDefinition {
            name: "entity_list".to_string(),
            description: "Substrate: list entities, optionally filtered by kind. Sorted by (kind, id).".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "kind":{"type":"string"},
                    "limit":{"type":"integer"},
                    "include_deleted":{"type":"boolean","default":false}
                },
                "examples":[{"kind":"capability","limit":100},{}]
            }),
        },
        ToolDefinition {
            name: "entity_delete".to_string(),
            description: "Substrate: soft-delete an entity. The version chain is preserved.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "kind":{"type":"string"},
                    "id":{"type":"string"}
                },
                "required":["kind","id"],
                "examples":[{"kind":"capability","id":"OBSOLETE-FOO"}]
            }),
        },
        ToolDefinition {
            name: "entity_history".to_string(),
            description: "Substrate: return the full version chain (oldest → newest) for an entity. M2: receipt-grade audit trail.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "kind":{"type":"string"},
                    "id":{"type":"string"}
                },
                "required":["kind","id"],
                "examples":[{"kind":"capability","id":"CORECRUX-RECEIPTS"}]
            }),
        },
        ToolDefinition {
            name: "edge_upsert".to_string(),
            description: "Substrate: upsert a labelled directed edge between two entities.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "from_kind":{"type":"string"},
                    "from_id":{"type":"string"},
                    "edge_kind":{"type":"string"},
                    "to_kind":{"type":"string"},
                    "to_id":{"type":"string"},
                    "payload":{"type":"object"}
                },
                "required":["from_kind","from_id","edge_kind","to_kind","to_id"],
                "examples":[{"from_kind":"capability","from_id":"A","edge_kind":"depends_on","to_kind":"capability","to_id":"B"}]
            }),
        },
        ToolDefinition {
            name: "edge_get".to_string(),
            description: "Substrate: fetch one edge by its full five-tuple.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "from_kind":{"type":"string"},
                    "from_id":{"type":"string"},
                    "edge_kind":{"type":"string"},
                    "to_kind":{"type":"string"},
                    "to_id":{"type":"string"}
                },
                "required":["from_kind","from_id","edge_kind","to_kind","to_id"],
                "examples":[{"from_kind":"capability","from_id":"A","edge_kind":"depends_on","to_kind":"capability","to_id":"B"}]
            }),
        },
        ToolDefinition {
            name: "edge_list".to_string(),
            description: "Substrate: list edges by any prefix of (from_kind, from_id), (to_kind, to_id), or edge_kind.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "from_kind":{"type":"string"},
                    "from_id":{"type":"string"},
                    "to_kind":{"type":"string"},
                    "to_id":{"type":"string"},
                    "edge_kind":{"type":"string"},
                    "limit":{"type":"integer"},
                    "include_deleted":{"type":"boolean","default":false}
                },
                "examples":[{"from_kind":"capability","from_id":"A"},{"edge_kind":"depends_on","limit":50}]
            }),
        },
        ToolDefinition {
            name: "edge_delete".to_string(),
            description: "Substrate: soft-delete an edge by its full five-tuple.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "from_kind":{"type":"string"},
                    "from_id":{"type":"string"},
                    "edge_kind":{"type":"string"},
                    "to_kind":{"type":"string"},
                    "to_id":{"type":"string"}
                },
                "required":["from_kind","from_id","edge_kind","to_kind","to_id"],
                "examples":[{"from_kind":"capability","from_id":"A","edge_kind":"depends_on","to_kind":"capability","to_id":"B"}]
            }),
        },
        // ── Features lens (M3) ─────────────────────────────────────
        ToolDefinition {
            name: "feature_file_search".to_string(),
            description: "Features lens: find capabilities whose `files` list contains the given substring.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{"path":{"type":"string"}},
                "required":["path"],
                "examples":[{"path":"src/foo.rs"}]
            }),
        },
        ToolDefinition {
            name: "feature_coverage_report".to_string(),
            description: "Features lens: per-system coverage report (totals, tested, audited, shipped, maturity breakdown).".to_string(),
            input_schema: json!({"type":"object","properties":{},"examples":[{}]}),
        },
        ToolDefinition {
            name: "feature_trigger_audit".to_string(),
            description: "Features lens: record an audit on a capability. Status must be one of audited|gap|waived|blocked.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{
                    "id":{"type":"string"},
                    "status":{"type":"string","enum":["audited","gap","waived","blocked"]},
                    "auditor":{"type":"string"},
                    "notes":{"type":"string"}
                },
                "required":["id","status"],
                "examples":[{"id":"CORECRUX-RECEIPTS","status":"audited","auditor":"qa"}]
            }),
        },
        ToolDefinition {
            name: "feature_suggest_next".to_string(),
            description: "Features lens: suggest next-best capabilities to work on, derived from gap analysis + weakest promise.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{"limit":{"type":"integer","default":5}},
                "examples":[{},{"limit":10}]
            }),
        },
        ToolDefinition {
            name: "kind_list".to_string(),
            description: "Substrate: list all registered kinds (entity types) with their description and allowed edges.".to_string(),
            input_schema: json!({"type":"object","properties":{},"examples":[{}]}),
        },
        ToolDefinition {
            name: "kind_get".to_string(),
            description: "Substrate: fetch the registration for one kind, including its JSON-Schema.".to_string(),
            input_schema: json!({
                "type":"object",
                "properties":{"kind":{"type":"string"}},
                "required":["kind"],
                "examples":[{"kind":"capability"}]
            }),
        },
        // ── Typed action traces (agent-ux-06) ────────────────────────────
        ToolDefinition {
            name: "tool_trace_recent".to_string(),
            description: traces::TOOL_DESCRIPTION.to_string(),
            input_schema: traces::tool_input_schema(),
        },
        // ── Token accounting (action-ledger M1) ──────────────────────────
        ToolDefinition {
            name: "session_token_usage".to_string(),
            description: token_usage::TOOL_DESCRIPTION.to_string(),
            input_schema: token_usage::tool_input_schema(),
        },
        // ── Risk-tiered HITL (agent-ux-05) ───────────────────────
        ToolDefinition {
            name: "approval_request".to_string(),
            description: "Risk-tiered HITL: queue an action for operator approval. Required: \
                          action_summary, risk_tier (low|medium|high), scope (tenant_id or \
                          resource path), token_budget. Optional: tenant_id, payload. Returns \
                          immediately with {request_id, status: 'pending'|'feature_disabled', \
                          risk_tier}. High-tier requests BLOCK on operator decision; medium/low \
                          may auto-approve per tenant policy (out of scope for the M3 free tier). \
                          Pending entries appear in list_work(state='pending_approval'). \
                          Gated by CORECRUXD_FEATURE_APPROVAL_QUEUE=1 (default off)."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action_summary": { "type": "string", "description": "Human-readable description of the action being requested." },
                    "risk_tier":      { "type": "string", "enum": ["low", "medium", "high"], "description": "Risk classification." },
                    "scope":           { "type": "string", "description": "Tenant id or scoped resource path the action targets." },
                    "tenant_id":      { "type": "string", "description": "Tenant the request is raised in (defaults to scope when omitted)." },
                    "payload":        { "type": "object", "description": "Optional structured payload (e.g. predicted_effects, original tool call)." },
                    "token_budget":   { "type": "integer", "description": "QC.2 — required. Caps response size. Pass any positive integer." }
                },
                "required": ["action_summary", "risk_tier", "scope", "token_budget"],
                "examples": [
                    { "action_summary": "delete tenant prod fixtures", "risk_tier": "high", "scope": "business::acme", "tenant_id": "business::acme", "token_budget": 500 }
                ]
            }),
        },
        // ── Orchestrators (Package S scaffold) ─────────────────────
        ToolDefinition {
            name: "create_orchestrator".to_string(),
            description: orchestrators::CREATE_ORCHESTRATOR_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name":                { "type": "string" },
                    "created_by_passport": { "type": "string", "description": "The passport authoring this orchestrator." },
                    "assignee_passport":   { "type": "string" },
                    "tenant_id":           { "type": "string" },
                    "state":               { "type": "string", "enum": ["planned","active","done","archived"] }
                },
                "required": ["name", "created_by_passport"],
                "examples": [
                    { "name": "Q500 lift squad", "created_by_passport": "personal-default" }
                ]
            }),
        },
        ToolDefinition {
            name: "approval_decide".to_string(),
            description: "Risk-tiered HITL: operator decision on a pending approval. Requires \
                          OPERATOR-tier passport (elite/operator). Forwards the request through \
                          the cross-tenant guard (T.1) — reviewer in tenant A cannot decide for \
                          tenant B. Emits an ApprovalDecision CROWN receipt (the daemon HTTP \
                          layer attaches the Ed25519 signature). Returns {ok, status, \
                          reviewer_passport, decided_at, receipt_id, receipt_body_hash_hex}. \
                          Non-operator callers receive a 403-style JSON-RPC error with \
                          `why_denied` explaining the missing tier."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "request_id":         { "type": "string", "description": "Opaque request id minted by approval_request." },
                    "decision":           { "type": "string", "enum": ["approve", "reject"], "description": "Operator decision." },
                    "reviewer_notes":     { "type": "string", "description": "Optional free-text justification (embedded in the receipt body)." },
                    "reviewer_tier":      { "type": "string", "description": "Reviewer's passport tier — forwarded by the daemon HTTP layer; tests pass 'elite' or 'operator'." },
                    "reviewer_tenant_id": { "type": "string", "description": "Reviewer's tenant id — used to enforce the cross-tenant guard (T.1)." }
                },
                "required": ["request_id", "decision"],
                "examples": [
                    { "request_id": "ar_abcd1234", "decision": "approve", "reviewer_tier": "elite", "reviewer_tenant_id": "business::acme", "reviewer_notes": "approved per ticket #42" }
                ]
            }),
        },
        ToolDefinition {
            name: "attach_to_orchestrator".to_string(),
            description: orchestrators::ATTACH_TO_ORCHESTRATOR_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "orchestrator_id": { "type": "string" },
                    "member_ref":      { "type": "string", "description": "A work item id (w_…), execplan id (execplan:…), handoff id (ho_…), or passport (id like `claude-work` or principal_id like `ce:…:local`)." },
                    "member_type":     { "type": "string", "enum": ["passport","work","execplan","handoff"], "description": "Optional explicit member type; inferred from member_ref when omitted." }
                },
                "required": ["orchestrator_id", "member_ref"],
                "examples": [
                    { "orchestrator_id": "orc_abc123", "member_ref": "w_def456" },
                    { "orchestrator_id": "orc_abc123", "member_ref": "claude-work", "member_type": "passport" }
                ]
            }),
        },
        ToolDefinition {
            name: "detach_from_orchestrator".to_string(),
            description: orchestrators::DETACH_FROM_ORCHESTRATOR_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "orchestrator_id": { "type": "string" },
                    "member_ref":      { "type": "string" }
                },
                "required": ["orchestrator_id", "member_ref"],
                "examples": [
                    { "orchestrator_id": "orc_abc123", "member_ref": "w_def456" }
                ]
            }),
        },
        ToolDefinition {
            name: "list_orchestrators".to_string(),
            description: orchestrators::LIST_ORCHESTRATORS_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "tenant_id": { "type": "string" },
                    "state":     { "type": "string", "enum": ["planned","active","done","archived"] }
                },
                "examples": [ {}, { "state": "active" } ]
            }),
        },
        ToolDefinition {
            name: "update_orchestrator".to_string(),
            description: orchestrators::UPDATE_ORCHESTRATOR_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "orchestrator_id":   { "type": "string" },
                    "name":              { "type": "string" },
                    "assignee_passport": { "type": "string" },
                    "state":             { "type": "string", "enum": ["planned","active","done","archived"] }
                },
                "required": ["orchestrator_id"],
                "examples": [
                    { "orchestrator_id": "orc_abc123", "state": "archived" }
                ]
            }),
        },
        // ── Punchcards (Package S scaffold) ────────────────────────
        ToolDefinition {
            name: "punch_in".to_string(),
            description: punchcards::PUNCH_IN_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "resource":           { "type": "string", "description": "Resource to lease, e.g. file:///path or a deploy-target id." },
                    "holder_passport":    { "type": "string", "description": "The passport acquiring the lease." },
                    "mode":               { "type": "string", "enum": ["modify","deploy"] },
                    "tenant_id":          { "type": "string" },
                    "reason":             { "type": "string" },
                    "expires_at_unix_ms": { "type": "integer" }
                },
                "required": ["resource", "holder_passport"],
                "examples": [
                    { "resource": "file:///home/x/main.rs", "holder_passport": "personal-default", "mode": "modify" }
                ]
            }),
        },
        ToolDefinition {
            name: "punch_out".to_string(),
            description: punchcards::PUNCH_OUT_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "resource":           { "type": "string" },
                    "holder_passport":    { "type": "string" },
                    "release_commit_sha": { "type": "string" },
                    "tenant_id":          { "type": "string" }
                },
                "required": ["resource", "holder_passport"],
                "examples": [
                    { "resource": "file:///home/x/main.rs", "holder_passport": "personal-default" }
                ]
            }),
        },
        ToolDefinition {
            name: "list_punchcards".to_string(),
            description: punchcards::LIST_PUNCHCARDS_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "resource":        { "type": "string" },
                    "holder_passport": { "type": "string" },
                    "tenant_id":       { "type": "string" },
                    "status":          { "type": "string", "enum": ["held","released","expired","force_released"] }
                },
                "examples": [ {}, { "status": "held" } ]
            }),
        },
        ToolDefinition {
            name: "force_release".to_string(),
            description: punchcards::FORCE_RELEASE_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "punchcard_id": { "type": "string" },
                    "confirm":      { "type": "boolean", "description": "Required true — force-release is destructive (Art.14)." },
                    "reason":       { "type": "string" },
                    "by_passport":  { "type": "string", "description": "Operator passport performing the override." }
                },
                "required": ["punchcard_id", "confirm"],
                "examples": [
                    { "punchcard_id": "pc_abc123", "confirm": true, "reason": "stale lease, holder offline" }
                ]
            }),
        },
        ToolDefinition {
            name: "check_punchcard".to_string(),
            description: punchcards::CHECK_PUNCHCARD_DESCRIPTION.to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "resource": { "type": "string", "description": "Resource URI: file://<path>, tree://<subtree>, or service://<name>." },
                    "mode":     { "type": "string", "enum": ["modify","deploy"] },
                    "passport": { "type": "string", "description": "Probing passport; defaults to the calling passport." }
                },
                "required": ["resource"],
                "examples": [
                    { "resource": "file:///home/x/main.rs", "mode": "modify" }
                ]
            }),
        },
    ]
    .into_iter()
    .map(|mut t: ToolDefinition| {
        // agent-passport M2: when the flag is on, `issue_passport` is reachable
        // on a local-tier install, so it is marked `[local]` rather than the
        // static `[hosted]` from the tool-surface table. No other tool is
        // affected, and flag-off uses the static marker unchanged.
        let marker = if agent_passports_enabled && t.name == "issue_passport" {
            "[local]"
        } else {
            vaultcrux_local::tool_surface::marker_for_tool(&t.name)
        };
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

pub async fn list_tools_json_for_context(ctx: &McpContext, now_unix_seconds: u64) -> Value {
    // The surface mode is a process flag (`CORECRUXD_TOOL_SURFACE`); the core
    // takes it explicitly so tests can drive a mode without mutating env.
    list_tools_json_for_context_with_mode(ctx, now_unix_seconds, surface::ToolSurfaceMode::from_env()).await
}

pub(crate) async fn list_tools_json_for_context_with_mode(
    ctx: &McpContext,
    now_unix_seconds: u64,
    mode: surface::ToolSurfaceMode,
) -> Value {
    let auth = ctx
        .rcx_router
        .as_ref()
        .map(|router| ToolAuthMetadata::from_token(router.token()));
    let mut tools = ctx.rcx_router.as_ref().map_or_else(
        // Local-tier install (no RCX capability token): the agent-passport
        // flag promotes `issue_passport` into the local surface (M2).
        || list_tools_local_surface(ctx.agent_passports_enabled),
        |router| list_tools_for_rcx_router(router, now_unix_seconds),
    );
    let mut extension_tools = extensions::list_extension_tools(ctx).await;
    if let Some(router) = ctx.rcx_router.as_ref() {
        let capabilities: Vec<McpToolCapability> = extension_tools
            .iter()
            .map(|tool| rcx_mcp_tool_capability(&tool.name))
            .collect();
        let allowed: HashSet<String> = router
            .filter_mcp_tools(&capabilities, now_unix_seconds)
            .into_iter()
            .collect();
        extension_tools.retain(|tool| allowed.contains(&tool.name));
    }
    tools.extend(extension_tools);
    // Surface shaping (dynamic-tool-surface M1/M3) runs LAST, after authz
    // filtering + extension merge, so it only ever narrows the already-authorised
    // set — it cannot widen authorisation. `Full` (the default) is the identity,
    // so flag-off is byte-for-byte the pre-M1 surface. Tools shaped out stay
    // callable via `tools/call` (dispatch is by-name) and discoverable through
    // the `cuecrux_session` capability graph.
    let tools = match mode {
        // M3/M4: `dynamic` = floor + top-N tools scored by the agent's declared
        // intent (M2/M3) blended with recent tool-use from the trace ring (M4).
        // No intent and no recent activity ⇒ floor only (identical to `minimal`).
        surface::ToolSurfaceMode::Dynamic => {
            let passport_key =
                passport::passport_key_name(ctx).unwrap_or_else(|| crate::traces::ANON_PASSPORT.to_string());
            let intent = surface::current_intent(&passport_key);
            // M4: blend the declared intent with the agent's recent tool-use.
            // Empty when tool-traces are disabled → intent-only behaviour.
            let trace_boosts = if crate::traces::traces_enabled() {
                let recent = crate::traces::global().lock().await.recent(&passport_key, 20);
                surface::trace_boosts_from_recent(&recent)
            } else {
                std::collections::HashMap::new()
            };
            surface::shape_dynamic_weighted(tools, intent.as_deref(), &trace_boosts, surface::DYNAMIC_TOP_N)
        }
        other => surface::apply_surface_mode(tools, other),
    };
    tools_to_json(tools, auth)
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
            let consequence_metadata = corecrux_memory::action_enrichment::metadata_for_tool_value(&t.name);
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
            let mut crux_meta = json!({
                "consequence_metadata": consequence_metadata,
            });
            if let Some(auth) = &auth {
                crux_meta["filtered_by"] = json!("rcx-capability-token");
                crux_meta["token_ref"] = json!({
                    "token_id": &auth.token_id,
                    "token_hash": &auth.token_hash,
                });
                crux_meta["receipt_class"] = json!(&auth.receipt_class);
                crux_meta["tier"] = json!(&auth.tier);
            }
            // Upgrade-aware catalogue annotation: hosted/metered tools are
            // already listed (not hidden) on local installs with a `[hosted]`
            // description marker. Mirror that decision as structured metadata
            // so agents don't have to parse description prefixes. Honest
            // signpost only — no filtering or dispatch change.
            if t.description.starts_with("[hosted]") {
                crux_meta["upgrade"] = json!({
                    "platform_available": true,
                    "requires": "rcx_capability_token",
                    "docs": format!("https://crux.cuecrux.com/docs/platform/{}", t.name),
                });
            }
            // M4 (CRC-v1 self-describing): advertise the negotiated output shape.
            // MCP has no native `outputSchema`, so attach the CRC-v1 schema ref
            // under an `x-crux-output-schema` extension for tools that emit it.
            let output_advert = crate::crc_v1::output_schema_advert(&t.name);
            let mut tool = json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": input_schema,
                "_meta": { "crux": crux_meta },
            });
            if let Some(adv) = output_advert {
                tool["x-crux-output-schema"] = adv;
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
    rcx_local_capabilities_with_flag(false)
}

/// Flag-aware local capability surface for agent-passport M2.
///
/// When `agent_passports_enabled` is true, `issue_passport` is included in the
/// local capability set so a mapped agent on a local-tier install can reach it
/// (see [`list_tools_local_surface`]). Flag-off is identical to
/// [`rcx_local_capabilities`] — the static `[hosted]` tier excludes it.
pub fn rcx_local_capabilities_with_flag(agent_passports_enabled: bool) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut capabilities: Vec<String> = list_tools()
        .into_iter()
        .filter_map(|tool| {
            let promoted_local = agent_passports_enabled && tool.name == "issue_passport";
            if !promoted_local && !vaultcrux_local::tool_surface::is_local_tool(&tool.name) {
                return None;
            }
            let capability = rcx_capability_for_tool(&tool.name);
            seen.insert(capability.clone()).then_some(capability)
        })
        .collect();
    if seen.insert(FEDERATION_READ_CAPABILITY.to_string()) {
        capabilities.push(FEDERATION_READ_CAPABILITY.to_string());
    }
    capabilities
}

fn rcx_capability_for_tool(tool_name: &str) -> String {
    if extensions::is_extension_tool_name(tool_name) {
        return extensions::rcx_capability_name(tool_name);
    }
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
        { "tool": "autonomy_contract",  "output": "{ feature_enabled, passport_id, tier, token_id, token_hash, capabilities: [{name, allowed, scope, backend_id, mode, cost_credits, why_denied?}], summary: {total_tools, returned, allowed, denied, truncated_by_token_budget} }. Disabled when CORECRUXD_FEATURE_AUTONOMY_CONTRACT is off (feature_enabled=false, empty capabilities)." },
        { "tool": "query",              "output": "{ results: [{doc_id, score, segment_index, token_count}], coverage: {score, gaps, below_floor}, meta: {backend, took_ms, segments_searched} }" },
        { "tool": "query_scan",         "output": "{ results: [{doc_id, score, token_count}], meta: {took_ms, segments_searched} }" },
        { "tool": "query_expand",       "output": "{ results: [{doc_id, content, token_count}] }" },
        { "tool": "store_fact",         "output": "{ fact_id, entity, key, version, superseded_fact_ids: [string] }. `superseded_fact_ids` lists facts this write explicitly retired via the `supersedes` param (M6 cross-entity supersession)." },
        { "tool": "query_facts",        "output": "{ rows: [{fact_id, entity, key, value, confidence, effective_confidence, horizon_class, freshness, age_hours, superseded_by?}] }. Superseded (retired) facts are excluded by default; pass include_superseded=true to include them (then `superseded_by` is populated)." },
        { "tool": "delete_fact",        "output": "{ deleted: bool, fact_id }" },
        { "tool": "memory_forget",         "output": "{ content: [...], forget_receipt_id, facts_affected, recovery_window_seconds, recovery_window_ends_at, receipt_body_cbor_hex, receipt_body_hash_hex, scope, passport_id }" },
        { "tool": "memory_forget_dry_run", "output": "{ content: [...], scope, count, facts_that_would_be_affected: [{fact_id, entity, key, stored_at, tokens}], dry_run: true }" },
        { "tool": "list_entities",      "output": "{ entities: [string] }" },
        { "tool": "get_bootstrap",      "output": "{ facts: [{entity, key, value}], total_tokens }" },
        { "tool": "fact_history",       "output": "{ versions: [{fact_id, value, version, supersedes, confidence, stored_at, deleted}] }" },
        { "tool": "memory_acknowledge_use", "output": "{ turn_id, intent, feature_enabled, receipt_ref, memories_used: [{fact_id, topic, age_days}], filtered_count, redacted_count, not_found_count, not_visible_count }" },
        { "tool": "output_attest",          "output": "{ content: [...], manifest: { manifest_id, spec_version, manifest_jumbf_base64, content_hash_blake3_hex, crown_receipt_id, signer_key_id, signer_passport, verify_url, verify_command, ai_act_notice } } — agent-ux-07 C2PA Content Credentials emitter." },
        { "tool": "memory_view",        "output": "{ content: [...], structuredContent: { facts: [{id, entity, key, value, version, stored_at, confidence, pinned, source_receipt}], total_tokens, returned } } — agent-ux-01 consumer surface; reserved prefixes filtered." },
        { "tool": "memory_edit",        "output": "{ content: [...], structuredContent: { old_fact_id, new_fact: MemoryFact, reason } } — new fact supersedes old; reason embedded as `memory_edit:<reason>` source_receipt." },
        { "tool": "memory_pin",         "output": "{ content: [...], structuredContent: { fact_id, pinned: bool } } — pin state stored under reserved __memory_pin::<agent>::*." },
        { "tool": "memory_history",     "output": "{ content: [...], structuredContent: { versions: [{id, value, version, stored_at, supersedes, deleted, source_receipt}] } } — consumer-friendly version chain (excludes reserved prefixes)." },
        { "tool": "memory_freshness",   "output": "{ rows: [{fact_id, entity, key, horizon_class, freshness, age_hours, stored_at, reverified_at?}], policy: {volatile_stale_hours, medium_stale_days, stable_stale_days}, now }" },
        { "tool": "memory_sweep_candidates", "output": "{ content: [...], structuredContent: { rows: [{fact_id, entity, key, reason: 'stale'|'superseded'|'stale+superseded', freshness, horizon_class, age_hours, superseded_by?, stored_at}], dry_run: true, now } } — read-only janitor; nothing mutated." },
        { "tool": "memory_set_horizon", "output": "{ fact_id, horizon_class, ok: bool }" },
        { "tool": "memory_reverify",    "output": "{ fact_id, receipt_id, receipt_class: 'Reverify', reverified_at }" },
        { "tool": "artefact_put",       "output": "{ content: [...], structuredContent: { artefact_id, mime_type, tool_origin, size_bytes, created_at, expires_at } } — id is `art_<blake3_hex>`; identical bytes coalesce." },
        { "tool": "artefact_get",       "output": "{ content: [...], structuredContent: { artefact_id, mime_type, tool_origin, size_bytes, created_at, expires_at, content_base64 } } — cross-passport reads return CAPABILITY_DENIED." },
        { "tool": "artefact_list",      "output": "{ content: [...], structuredContent: { artefacts: [{artefact_id, mime_type, tool_origin, size_bytes, created_at, expires_at}], count } } — passport-scoped, reserved-prefix mime entries filtered." },
        { "tool": "get_session",        "output": "{ session_id, state, updated_at, total_tokens }" },
        { "tool": "save_session",       "output": "{ session_id, updated_at }" },
        { "tool": "session_checkpoint", "output": "{ content: [...], structuredContent: { session_id, updated_at, total_tokens } } — stores a compact crux.session_checkpoint.v1 state (objective, current_milestone, decisions, open_questions, files_touched, commands_run, test_status, next_action) scoped to the calling agent; requires token_budget>0." },
        { "tool": "list_sessions",      "output": "{ sessions: [string] } — archived sessions hidden unless include_archived=true." },
        { "tool": "delete_session",     "output": "{ deleted: bool, session_id }" },
        { "tool": "archive_session",    "output": "{ content: [{type:'text', text}] } — archives the session (soft, reversible; state preserved, hidden from default list_sessions). Confirms archived or not-found." },
        { "tool": "unarchive_session",  "output": "{ content: [{type:'text', text}] } — restores an archived session to the default listing." },
        { "tool": "route_access_matrix", "output": "{ content: [...], structuredContent: { routes: [{route, required_any_scope: [string], passport_binding, tenant_binding, notes}] } } — static high-risk HTTP route gate matrix used by agent hardening checks." },
        { "tool": "execplan_gate",       "output": "{ content: [...], structuredContent: { fact_id, entity, key, commit_sha, status } } — records a milestone gate as a stable fact under execplan:<slug> key gate:<milestone>; status one of passed|failed|blocked|skipped; requires token_budget>0." },
        { "tool": "auth_posture_audit",  "output": "{ content: [...], structuredContent: { schema: 'crux.auth_posture_audit.v1', checked_at, mcp_agent, daemon_loopback_configured: bool, rcx_router_configured: bool, agent_passports_enabled: bool, data_dir_configured: bool, notes: [string], recommended_checks: [string] } } — local auth-posture checklist; HTTP auth mode is not exposed through MCP." },
        { "tool": "egress_policy_check", "output": "{ content: [...], structuredContent: { schema: 'crux.egress_policy_check.v1', target, purpose, allowed: bool, scheme, host, reasons: [string] } } — checks a URL against the conservative egress policy (https allowed; http only loopback or explicit allow_plain_http)." },
        { "tool": "get_gaps",           "output": "{ gaps: [{entity, key, value, stored_at}], total_tokens }" },
        { "tool": "list_observations",  "output": "{ session_id, count, observations: [{ observation_id, session_id, ts, provider, principal, kind, payload, receipt: {alg, signed_by, body_hash, signature} }] }" },
        { "tool": "get_observation",    "output": "Single observation record (same shape as list_observations entries), or a not-found text response." },
        { "tool": "verify_observation", "output": "{ observation_id, ok: bool, hash_match: bool, signature_valid: bool, recomputed_hash, receipt_hash, reason?: string }" },
        { "tool": "receipt_verify", "output": "{ content: [...], receipt_id, tenant_id, feature_enabled: bool, verified: bool, signer_passport: string|null, errors: [string], http_status: int, report: VerificationReportV1 } — when feature off, omits report and returns errors:[FEATURE_DISABLED]. agent-ux-04 source-linked traceability." },
        { "tool": "get_agent_identity", "output": "{ agent_name: string }" },
        { "tool": "resolve_principal",  "output": "{ content: [...], principal: { passport_id, category, tier, tier_rank: int, capabilities: [string], tenant_id, agent_work_gate: bool, resolved_via: 'session'|'passport'|'identity_link:<id>', federation_grant?: { capability, scope, allowed_capabilities } }, resolved_param: 'session_id'|'passport_id' } — loopback to GET /v1/principal/resolve; tenant-scoped server-side. agent→passport resolution parity for the MCP surface." },
        { "tool": "create_handoff",     "output": "{ package_json, content_hash, signature, relevant_fact_count }" },
        { "tool": "accept_handoff",     "output": "{ session_loaded, facts_loaded, verified: bool }" },
        { "tool": "record_decision",    "output": "{ decision_id, decision_hash, entity, action }" },
        { "tool": "declare_constraint", "output": "{ constraint_id, constraint_hash, constraint_type, assertion }" },
        { "tool": "get_constraints",    "output": "{ constraints: [{constraint_id, constraint_type, assertion, severity, status, created_at}], count }" },
        { "tool": "check_constraints",  "output": "{ verdict: pass|warn|block, matched_constraints: [{constraint_id, assertion, severity, match_score}] }" },
        { "tool": "audit_config",        "output": "{ content: [{type:'text', text:'config audited: path=… sha256=… auditor=…'}] } — fact written under __ops::config-audit key=sha256:<hash>." },
        { "tool": "check_config_audit",  "output": "{ content: [...], unaudited: [{path, sha256}], audited: [{path, sha256, audited_at, auditor, audited_path}] }" },
        { "tool": "enrich_action",      "output": "EnrichedActionProposal { schema, tenant_id, enrichment_mode, tool_call, narrative, affected_principals, affected_resources, state_diff, consequences, relationship_hits, consequence_metadata, enrichment_receipt }" },
        { "tool": "audit_export_bundle", "output": "{ content: [...], bundle_id, bytes_path, manifest_signature_b64, fact_count, receipt_count, scope, since, until, events_jsonl_sha256, receipts_cbor_sha256 } — bundle persisted to CORECRUXD_AUDIT_EXPORT_DIR; verify offline via `corecruxctl audit-verify`. agent-ux-11 (EU AI Act Art. 12)." },
        { "tool": "issue_passport",     "output": "{ principal_id, reputation_tier, receipt_count, sponsor_id }" },
        { "tool": "get_passport",       "output": "{ principal_id, reputation_tier, receipt_count, sponsor_id, issued_at, passport_hash }" },
        { "tool": "passport_split",        "output": "{ content: [...], new_passport_id, split_receipt_id, receipt_body_cbor_hex, receipt_body_hash_hex, tenant_id }" },
        { "tool": "passport_merge",        "output": "{ content: [...], merged_passport_id, merge_receipt_id, conflicts_resolved, conflict_policy, receipt_body_cbor_hex, receipt_body_hash_hex, tenant_id, retired_passport_id }" },
        { "tool": "passport_link_device",  "output": "{ content: [...], link_receipt_id, passport_id, device_fingerprint, capabilities_subset, receipt_body_cbor_hex, receipt_body_hash_hex, tenant_id }" },
        { "tool": "sync_pull",          "output": "{ tenant_id?, facts_pulled, cursor, total_pull_count, collection_cursor_count }" },
        { "tool": "sync_push",          "output": "{ mode?='tenant_promotion_preview', tenant_id?, facts_pushed?|would_promote?, preview_hash?, skipped_private?, skipped_synced?, skipped_not_allowlisted?, total_push_count?, collection_cursor_count? }" },
        { "tool": "sync_status",        "output": "{ mode, configured, background_sync_enabled, remote_url, api_key_configured, platform_online, degraded, degraded_reason, onboarding_hint, last_pull_at, last_push_at, pull_count, push_count, collection_pull_cursor_count, collection_push_cursor_count, tenant_manifest_supported, local_fact_count }" },
        { "tool": "update_status",      "output": "{ enabled, state, tracking_ref, current_commit, latest_commit, ahead_by, behind_by, checked_at, error, upgrade_hint, upgrade_playbook_query, backup_playbook_query }" },
        { "tool": "list_projects",      "output": "{ projects: [{ id, name, planning_target?, default_passport_id, created_at_unix_ms }] }" },
        { "tool": "get_project_context","output": "{ id, name, planning_target?, default_passport_id, members: [{ passport_id, role }], tenants: [{ tenant_id, default_passport_id? }] }" },
        { "tool": "list_work",          "output": "{ count, work: [{ id, project_id, state, title, body, assignee_passport?, tenant_id?, linked_pr?, linked_issue?, blocker_reason?, created_by_passport, created_at_unix_ms, updated_at_unix_ms }] }" },
        { "tool": "create_work",        "output": "WorkItem record (same shape as list_work entries, includes the freshly minted id)." },
        { "tool": "update_work_state",  "output": "{ applied: bool, work?: WorkItem, queued?: { action_id, work_id, requested_by_passport, target_state, status: 'pending', requested_at_unix_ms } }" },
        { "tool": "comment_on_work",    "output": "{ id, work_id, author_passport, body, posted_at_unix_ms }" },
        { "tool": "coord_status",       "output": "{ now_unix_ms, presence_ttl_secs, project_id?, active_sessions: [{ session_id_hex, passport_id, tenant_id, project_id?, bound_at_unix_ms, last_seen_at_unix_ms, active_until_unix_ms, intent?: { execplan_slug?, milestone?, paths, note?, announced_at_unix_ms, expires_at_unix_ms }, leases?: [{ punchcard_id, resource, mode, holder_passport, expires_at_unix_ms }] }], work_in_flight: [WorkItem] }" },
        { "tool": "coord_announce",     "output": "{ intent: { project_id, session_id_hex, passport_id, execplan_slug?, milestone?, paths, note?, announced_at_unix_ms, expires_at_unix_ms }, cleared: bool, live_peer_intents: n, overlaps: [{ peer_session_id_hex, peer_passport_id, kind: execplan|intent_path|lease, theirs, yours }] } — surface any overlaps to the operator and coordinate before editing those paths" },
        { "tool": "github_search",         "output": "{ count, facts: [{ entity, key, value, ... }] } — value strings hold JSON-encoded CommitRecord / PrRecord / IssueRecord / CommentRecord depending on the entity prefix." },
        { "tool": "github_recent_commits", "output": "{ count, facts: [Fact] } — entities are `github::owner/repo::commit/{sha}`; value JSON contains sha, message, author_name, author_login?, committed_at, parents[], html_url." },
        { "tool": "github_open_prs",       "output": "{ count, facts: [Fact] } — entities are `github::owner/repo::pr/{number}`; value JSON contains title, state, author_login?, head_sha, base_branch, body, merged_at?, closed_at?, html_url." },
        { "tool": "github_open_issues",    "output": "{ count, facts: [Fact] } — entities are `github::owner/repo::issue/{number}`; value JSON contains title, state, labels[], body, closed_at?, html_url." },
        { "tool": "github_comments_since", "output": "{ count, facts: [Fact] } — entities are `github::owner/repo::comment/{id}`; value JSON contains author_login?, body, posted_at, parent_number, html_url." },
        { "tool": "get_workspace_storyline", "output": "When format='tree': plaintext ASCII tree-art (one tree per route, or one if endpoint set), `text/plain`. When format='json': { files: [{p, c, m, d, f, t}], edges: [[from_id, to_id, count, to_symbol]], routes: [{m, p, h, f, chain: [file_ids]}] }." },
        { "tool": "entity_upsert", "output": "{ content: [...], entity: EntityRecord { kind, id, payload, created_at, updated_at, version, deleted, actor } }" },
        { "tool": "entity_get",    "output": "{ content: [...], entity: EntityRecord | null }" },
        { "tool": "entity_list",   "output": "{ content: [...], entities: [EntityRecord], count }" },
        { "tool": "entity_delete", "output": "{ content: [...], entity: EntityRecord (deleted=true) }" },
        { "tool": "entity_history", "output": "{ content: [...], versions: [EntityRecord], count } — oldest first; last entry has deleted=true if the entity has been deleted." },
        { "tool": "edge_upsert",   "output": "{ content: [...], edge: EdgeRecord { edge_id, from_kind, from_id, edge_kind, to_kind, to_id, payload, created_at, updated_at, version, deleted, actor } }" },
        { "tool": "edge_get",      "output": "{ content: [...], edge: EdgeRecord | null }" },
        { "tool": "edge_list",     "output": "{ content: [...], edges: [EdgeRecord], count }" },
        { "tool": "edge_delete",   "output": "{ content: [...], edge: EdgeRecord (deleted=true) }" },
        { "tool": "kind_list",     "output": "{ content: [...], kinds: [{ kind, description, allowed_outgoing_edges, allowed_incoming_edges }], count }" },
        { "tool": "kind_get",      "output": "{ content: [...], registration: KindRegistration | null }" },
        { "tool": "feature_file_search",     "output": "{ content: [...], capabilities: [{id, name, system, files}], count }" },
        { "tool": "feature_coverage_report", "output": "{ content: [...], report: CoverageReport { total_capabilities, total_tested, total_audited, maturity, systems } }" },
        { "tool": "feature_trigger_audit",   "output": "{ content: [...], capability: <updated payload>, version }" },
        { "tool": "feature_suggest_next",    "output": "{ content: [...], suggestions: [{kind, capability_id?, gap_type?, severity?, promise?, rationale}], count }" },
        { "tool": "tool_trace_recent",       "output": "{ content: [...], traces: [{tool, ts_us, turn_id?, predicted_effects: [{kind, entity, key, ts_us?}], outcome}], count, feature_disabled? } — per-passport; reserved-prefix effects stripped." },
        { "tool": "session_token_usage",     "output": "{ content: [...], passport, used, tokens_in, tokens_out, declared_budget_in, calls, estimator, limit?, pct? } — per-passport estimated token spend (~4 chars/token); limit/pct only when CORECRUXD_SESSION_TOKEN_BUDGET is set." },
        { "tool": "approval_request",        "output": "{ content: [...], request_id, status: 'pending'|'feature_disabled', risk_tier, tenant_id, feature_enabled } — pending entries also visible via list_work(state='pending_approval')." },
        { "tool": "approval_decide",         "output": "{ content: [...], ok, request_id, status: 'approved'|'rejected', reviewer_passport, decided_at, receipt_id, receipt_body_hash_hex, tenant_id, risk_tier } — non-operator callers receive a 403-style JSON-RPC error with `why_denied`." },
        { "tool": "create_orchestrator",      "output": "Orchestrator record { id, name, assignee_passport, created_by_passport, tenant_id, state, members[], created_at_unix_ms, updated_at_unix_ms }. (Package S scaffold: daemon endpoint stubbed → 501 until the orchestrators plan ships.)" },
        { "tool": "attach_to_orchestrator",   "output": "Updated orchestrator record with the member added. (Package S scaffold: 501 until shipped.)" },
        { "tool": "detach_from_orchestrator", "output": "Updated orchestrator record with the member removed. (Package S scaffold: 501 until shipped.)" },
        { "tool": "list_orchestrators",       "output": "{ count, orchestrators: [Orchestrator] }. (Package S scaffold: 501 until shipped.)" },
        { "tool": "update_orchestrator",      "output": "Updated orchestrator record { id, name, assignee_passport, state, members[], … } after a name/assignee/state change (state=archived closes it out)." },
        { "tool": "punch_in",                 "output": "Punchcard lease record { id, resource, mode, holder_passport, tenant_id, status, acquired_at_unix_ms, expires_at_unix_ms?, receipt_acquire }. (Package S scaffold: 501 until the punchcard plan ships.)" },
        { "tool": "punch_out",                "output": "Released punchcard record (status=released, released_at_unix_ms, release_commit_sha?, receipt_release). (Package S scaffold: 501 until shipped.)" },
        { "tool": "list_punchcards",          "output": "{ count, punchcards: [Punchcard] }. (Package S scaffold: 501 until shipped.)" },
        { "tool": "force_release",            "output": "Force-released punchcard record (status=force_released, force_released_by, receipt_release). Requires confirm=true (Art.14)." },
        { "tool": "check_punchcard",          "output": "Lease probe { held_by_other, enforce, holder_passport, resource, mode, expires_at_unix_ms }. Always 200 (fail-open); the PreToolUse hook denies only when held_by_other && enforce." }
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
        "autonomy_contract" => autonomy::handle_autonomy_contract(args, ctx).await,
        "query" => query::handle_query(args, ctx).await,
        "query_scan" => query::handle_query_scan(args, ctx).await,
        "query_expand" => query::handle_query_expand(args, ctx).await,
        "store_fact" => facts::handle_store_fact(args, ctx).await,
        "query_facts" => facts::handle_query_facts(args, ctx).await,
        "delete_fact" => facts::handle_delete_fact(args, ctx).await,
        "memory_forget" => forget::handle_memory_forget(args, ctx).await,
        "memory_forget_dry_run" => forget::handle_memory_forget_dry_run(args, ctx).await,
        "list_entities" => facts::handle_list_entities(args, ctx).await,
        "get_bootstrap" => facts::handle_get_bootstrap(args, ctx).await,
        "fact_history" => facts::handle_fact_history(args, ctx).await,
        "memory_acknowledge_use" => memory_use::handle_memory_acknowledge_use(args, ctx).await,
        // C2PA Content Credentials emitter (agent-ux-07).
        "output_attest" => output_attest::handle_output_attest(args, ctx).await,
        // Memory panel (agent-ux-01).
        "memory_view" => memory::handle_memory_view(args, ctx).await,
        "memory_edit" => memory::handle_memory_edit(args, ctx).await,
        "memory_pin" => memory::handle_memory_pin(args, ctx).await,
        "memory_history" => memory::handle_memory_history(args, ctx).await,
        // Freshness + decay (agent-ux-03 M3).
        "memory_freshness" => freshness::handle_memory_freshness(args, ctx).await,
        "memory_sweep_candidates" => freshness::handle_memory_sweep_candidates(args, ctx).await,
        "memory_set_horizon" => freshness::handle_memory_set_horizon(args, ctx).await,
        "memory_reverify" => freshness::handle_memory_reverify(args, ctx).await,
        // Artefacts (agent-ux-12).
        "artefact_put" => artefacts::handle_artefact_put(args, ctx).await,
        "artefact_get" => artefacts::handle_artefact_get(args, ctx).await,
        "artefact_list" => artefacts::handle_artefact_list(args, ctx).await,
        "get_session" => sessions::handle_get_session(args, ctx).await,
        "save_session" => sessions::handle_save_session(args, ctx).await,
        "session_checkpoint" => sessions::handle_session_checkpoint(args, ctx).await,
        "list_sessions" => sessions::handle_list_sessions(args, ctx).await,
        "delete_session" => sessions::handle_delete_session(args, ctx).await,
        "archive_session" => sessions::handle_archive_session(args, ctx).await,
        "unarchive_session" => sessions::handle_unarchive_session(args, ctx).await,
        "route_access_matrix" => hardening::handle_route_access_matrix(args, ctx).await,
        "execplan_gate" => hardening::handle_execplan_gate(args, ctx).await,
        "auth_posture_audit" => hardening::handle_auth_posture_audit(args, ctx).await,
        "egress_policy_check" => hardening::handle_egress_policy_check(args, ctx).await,
        "get_gaps" => observe::handle_get_gaps(args, ctx).await,
        "list_observations" => observations::handle_list_observations(args, ctx).await,
        "get_observation" => observations::handle_get_observation(args, ctx).await,
        "verify_observation" => observations::handle_verify_observation(args, ctx).await,
        "receipt_verify" => receipt_verify::handle_receipt_verify(args, ctx).await,
        "get_agent_identity" => handle_get_agent_identity(args, ctx).await,
        "resolve_principal" => resolve_principal::handle_resolve_principal(args, ctx).await,
        "create_handoff" => handoff::handle_create_handoff(args, ctx).await,
        "accept_handoff" => handoff::handle_accept_handoff(args, ctx).await,
        "record_decision" => decision::handle_record_decision(args, ctx).await,
        "declare_constraint" => constraint::handle_declare_constraint(args, ctx).await,
        "get_constraints" => constraint::handle_get_constraints(args, ctx).await,
        "check_constraints" => constraint::handle_check_constraints(args, ctx).await,
        "audit_config" => audit::handle_audit_config(args, ctx).await,
        "check_config_audit" => audit::handle_check_config_audit(args, ctx).await,
        "audit_export_bundle" => audit_export::handle_audit_export_bundle(args, ctx).await,
        "enrich_action" => action::handle_enrich_action(args, ctx).await,
        "issue_passport" => passport::handle_issue_passport(args, ctx).await,
        "get_passport" => passport::handle_get_passport(args, ctx).await,
        // Identity continuity (agent-ux-08).
        "passport_split" => identity::handle_passport_split(args, ctx).await,
        "passport_merge" => identity::handle_passport_merge(args, ctx).await,
        "passport_link_device" => identity::handle_passport_link_device(args, ctx).await,
        "sync_pull" => sync::handle_sync_pull(args, ctx).await,
        "sync_push" => sync::handle_sync_push(args, ctx).await,
        "sync_status" => sync::handle_sync_status(args, ctx).await,
        "update_status" => update::handle_update_status(args, ctx).await,
        // Coordination — projects + work kanban (Plan A M5).
        "list_projects" => coordination::handle_list_projects(args, ctx).await,
        "get_project_context" => coordination::handle_get_project_context(args, ctx).await,
        "list_work" => coordination::handle_list_work(args, ctx).await,
        "create_work" => coordination::handle_create_work(args, ctx).await,
        "update_work_state" => coordination::handle_update_work_state(args, ctx).await,
        "comment_on_work" => coordination::handle_comment_on_work(args, ctx).await,
        // Coordination plane — live-session board (presence-coordination plan).
        "coord_status" => coordination::handle_coord_status(args, ctx).await,
        "coord_announce" => coordination::handle_coord_announce(args, ctx).await,
        // Orchestrators (Package S scaffold).
        "create_orchestrator" => orchestrators::handle_create_orchestrator(args, ctx).await,
        "attach_to_orchestrator" => orchestrators::handle_attach_to_orchestrator(args, ctx).await,
        "detach_from_orchestrator" => orchestrators::handle_detach_from_orchestrator(args, ctx).await,
        "list_orchestrators" => orchestrators::handle_list_orchestrators(args, ctx).await,
        "update_orchestrator" => orchestrators::handle_update_orchestrator(args, ctx).await,
        // Punchcards (Package S scaffold).
        "punch_in" => punchcards::handle_punch_in(args, ctx).await,
        "punch_out" => punchcards::handle_punch_out(args, ctx).await,
        "list_punchcards" => punchcards::handle_list_punchcards(args, ctx).await,
        "force_release" => punchcards::handle_force_release(args, ctx).await,
        "check_punchcard" => punchcards::handle_check_punchcard(args, ctx).await,
        // GitHub (Plan B G5).
        "github_search" => github::handle_github_search(args, ctx).await,
        "github_recent_commits" => github::handle_github_recent_commits(args, ctx).await,
        "github_open_prs" => github::handle_github_open_prs(args, ctx).await,
        "github_open_issues" => github::handle_github_open_issues(args, ctx).await,
        "github_comments_since" => github::handle_github_comments_since(args, ctx).await,
        // Workspace storyline (HTTP loopback to corecruxd).
        "get_workspace_storyline" => storyline::handle_get_workspace_storyline(args, ctx).await,
        // Substrate (M1).
        "entity_upsert" => entities::handle_entity_upsert(args, ctx).await,
        "entity_get" => entities::handle_entity_get(args, ctx).await,
        "entity_list" => entities::handle_entity_list(args, ctx).await,
        "entity_delete" => entities::handle_entity_delete(args, ctx).await,
        "entity_history" => entities::handle_entity_history(args, ctx).await,
        "edge_upsert" => edges::handle_edge_upsert(args, ctx).await,
        "edge_get" => edges::handle_edge_get(args, ctx).await,
        "edge_list" => edges::handle_edge_list(args, ctx).await,
        "edge_delete" => edges::handle_edge_delete(args, ctx).await,
        "kind_list" => kinds::handle_kind_list(args, ctx).await,
        "kind_get" => kinds::handle_kind_get(args, ctx).await,
        // Features lens (M3).
        "feature_file_search" => features::handle_feature_file_search(args, ctx).await,
        "feature_coverage_report" => features::handle_feature_coverage_report(args, ctx).await,
        "feature_trigger_audit" => features::handle_feature_trigger_audit(args, ctx).await,
        "feature_suggest_next" => features::handle_feature_suggest_next(args, ctx).await,
        // Typed action traces (agent-ux-06).
        "tool_trace_recent" => traces::handle_tool_trace_recent(args, ctx).await,
        // Token accounting (action-ledger M1).
        "session_token_usage" => token_usage::handle_session_token_usage(args, ctx).await,
        // Risk-tiered HITL (agent-ux-05).
        "approval_request" => approvals::handle_approval_request(args, ctx).await,
        "approval_decide" => approvals::handle_approval_decide(args, ctx).await,
        name if extensions::is_extension_tool_name(name) => extensions::call_extension_tool(name, args, ctx).await,
        _ => Err(JsonRpcError {
            code: crate::protocol::METHOD_NOT_FOUND,
            message: format!("unknown tool: {name}"),
            data: None,
        }),
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    /// Read one full HTTP request (headers + `Content-Length` body) from an
    /// accepted loopback-mock stream.
    ///
    /// Accepted sockets inherit `O_NONBLOCK` from a nonblocking listener on
    /// BSD/macOS (not on Linux), so a bare `read()` can return `WouldBlock`
    /// and look like an empty request; replying and closing at that point
    /// races the client's in-flight request write and surfaces as EINVAL
    /// (os error 22) on macOS arm64 — broke the `aarch64-apple-darwin`
    /// release builds (incident 2026-06-12). Every loopback mock must read
    /// through this helper rather than a single `read()`.
    pub(crate) fn read_full_request(stream: &mut std::net::TcpStream) -> String {
        use std::io::Read;
        stream.set_nonblocking(false).ok();
        stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).ok();
        let mut data = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break, // EOF or timeout
                Ok(n) => {
                    data.extend_from_slice(&buf[..n]);
                    if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&data[..pos]);
                        let content_len = headers
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    v.trim().parse::<usize>().ok()
                                } else {
                                    None
                                }
                            })
                            .unwrap_or(0);
                        if data.len() >= pos + 4 + content_len {
                            break;
                        }
                    }
                    if data.len() > (1 << 20) {
                        break;
                    }
                }
            }
        }
        String::from_utf8_lossy(&data).into_owned()
    }

    pub(crate) fn clear_sync_env() {
        std::env::remove_var("CORECRUXD_SYNC_REMOTE_URL");
        std::env::remove_var("CORECRUXD_SYNC_API_KEY");
        std::env::remove_var("CORECRUXD_DATA_DIR");
    }

    pub(crate) fn sync_env_lock() -> &'static tokio::sync::Mutex<()> {
        // Delegate to the crate-wide test env lock so sync-tests serialise
        // against every other env-mutating test in this crate. Per-module
        // locks don't prevent concurrent writes to `environ` from sibling
        // threads holding a different module's lock (see
        // `crate::test_env_lock` for the full rationale).
        crate::test_env_lock()
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
    use ed25519_dalek::{Signer, SigningKey};
    use rcx_capability_token::{
        Backend, CreditCost, CreditCostUnit, CreditRefill, Credits, FallbackAction, FallbackPolicy, OverdraftPolicy,
        PermittedCapability, RcxTier, RCX_CT_SIGNATURE_LEN,
    };

    const TOOL_COUNT: usize = 106; // main 94 (agent-ux + identity-continuity + memory_sweep_candidates + resolve_principal (B1 mediator parity) + 5 audit-hardening: session_checkpoint + route_access_matrix + execplan_gate + auth_posture_audit + egress_policy_check + 2 coord-plane: coord_status + coord_announce + session_token_usage (action-ledger M1)) + 2 session-archive (archive_session + unarchive_session) + 10 backend (5 orchestrator + 4 punchcard + check_punchcard).

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    /// M3 end-to-end (race-free — drives the mode-parameterised core directly,
    /// no env mutation): an anon agent that declared `audit_review` gets a
    /// surface = floor + audit-relevant tools, with irrelevant tools shaped out
    /// and the full set still far larger.
    #[tokio::test]
    async fn dynamic_listing_reshapes_by_declared_intent() {
        // This test asserts the *intent-only* dynamic shape. The trace
        // ring records by default since action-ledger M4, and other
        // tests dispatching as __anon__ feed trace boosts into the
        // surface — pin the flag off (env-lock per crate rules).
        let _g = crate::test_env_lock().lock().await;
        std::env::set_var(crate::traces::FEATURE_FLAG_ENV, "0");
        let pk = crate::traces::ANON_PASSPORT;
        surface::clear_intent_for_test(pk);
        surface::record_intent(pk, "audit_review");

        let ctx = test_ctx();
        let json = list_tools_json_for_context_with_mode(&ctx, 0, surface::ToolSurfaceMode::Dynamic).await;
        let names: Vec<&str> = json["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();

        assert!(names.contains(&"cuecrux_session"), "floor present");
        assert!(names.contains(&"audit_config"), "audit intent surfaces audit tools");
        assert!(
            !names.contains(&"github_search"),
            "irrelevant tool shaped out under dynamic"
        );
        assert!(names.len() < list_tools().len(), "dynamic surface smaller than full");

        // With no intent, the same path collapses to the floor.
        surface::clear_intent_for_test(pk);
        let json2 = list_tools_json_for_context_with_mode(&ctx, 0, surface::ToolSurfaceMode::Dynamic).await;
        let n2 = json2["tools"].as_array().expect("tools array").len();
        assert_eq!(n2, surface::CORE_FLOOR.len(), "no intent ⇒ floor only");
        std::env::remove_var(crate::traces::FEATURE_FLAG_ENV);
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
        assert!(names.contains(&"enrich_action".to_string()));
        // Passport tools (2)
        assert!(names.contains(&"issue_passport".to_string()));
        assert!(names.contains(&"get_passport".to_string()));
        // Sync + update tools (4)
        assert!(names.contains(&"sync_pull".to_string()));
        assert!(names.contains(&"sync_push".to_string()));
        assert!(names.contains(&"sync_status".to_string()));
        assert!(names.contains(&"update_status".to_string()));
        // Coordination plane (2)
        assert!(names.contains(&"coord_status".to_string()));
        assert!(names.contains(&"coord_announce".to_string()));
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
        // Flag-OFF (the default `list_tools()` surface): issue_passport stays
        // [hosted]-gated exactly as before agent-passport M2.
        let tools = list_tools();
        let by_name = |n: &str| tools.iter().find(|t| t.name == n).unwrap();

        assert!(by_name("query").description.starts_with("[local]"));
        assert!(by_name("enrich_action").description.starts_with("[local]"));
        assert!(by_name("sync_status").description.starts_with("[local]"));
        assert!(by_name("issue_passport").description.starts_with("[hosted]"));
        assert!(by_name("sync_pull").description.starts_with("[hosted]"));
        assert!(by_name("sync_push").description.starts_with("[hosted]"));
    }

    #[test]
    fn agent_passport_flag_promotes_issue_passport_to_local() {
        // Flag-ON: issue_passport is reachable on a local-tier install, so it
        // is marked [local]. The two sync tools stay [hosted] (M2 is scoped to
        // issue_passport only).
        let tools = list_tools_local_surface(true);
        let by_name = |n: &str| tools.iter().find(|t| t.name == n).unwrap();

        assert!(by_name("issue_passport").description.starts_with("[local]"));
        assert!(by_name("sync_pull").description.starts_with("[hosted]"));
        assert!(by_name("sync_push").description.starts_with("[hosted]"));
    }

    #[test]
    fn list_tools_json_includes_consequence_metadata() {
        let listed = list_tools_json();
        let tools = listed["tools"].as_array().unwrap();
        let enrich = tools
            .iter()
            .find(|tool| tool["name"] == "enrich_action")
            .expect("enrich_action listed");

        assert_eq!(
            enrich["_meta"]["crux"]["consequence_metadata"]["schema"],
            "crux.tool_consequence_metadata.v1"
        );
        assert_eq!(
            enrich["_meta"]["crux"]["consequence_metadata"]["reversibility"],
            "unknown"
        );
    }

    #[test]
    fn list_tools_json_annotates_hosted_tools_with_upgrade_metadata() {
        // Upgrade-aware catalogue: every `[hosted]`-marked tool carries a
        // structured `_meta.crux.upgrade` signpost; local tools carry none.
        let listed = list_tools_json();
        let tools = listed["tools"].as_array().unwrap();

        let sync_pull = tools
            .iter()
            .find(|tool| tool["name"] == "sync_pull")
            .expect("sync_pull listed");
        let upgrade = &sync_pull["_meta"]["crux"]["upgrade"];
        assert_eq!(upgrade["platform_available"], true);
        assert_eq!(upgrade["requires"], "rcx_capability_token");
        assert_eq!(upgrade["docs"], "https://crux.cuecrux.com/docs/platform/sync_pull");

        let query = tools.iter().find(|tool| tool["name"] == "query").expect("query listed");
        assert!(
            query["_meta"]["crux"]["upgrade"].is_null(),
            "local tool must not carry an upgrade annotation"
        );
    }

    #[test]
    fn rcx_local_capabilities_excludes_hosted_gated_tools() {
        // Flag-OFF: hosted-gated tools (including issue_passport) absent from
        // the local capability surface — unchanged from before M2.
        let capabilities = rcx_local_capabilities();

        assert!(capabilities.contains(&"corecrux.query.local".to_string()));
        assert!(capabilities.contains(&FEDERATION_READ_CAPABILITY.to_string()));
        assert!(capabilities.contains(&"crux-mcp.sync_status".to_string()));
        assert!(!capabilities.contains(&"crux-mcp.issue_passport".to_string()));
        assert!(!capabilities.contains(&"crux-mcp.sync_pull".to_string()));
        assert!(!capabilities.contains(&"crux-mcp.sync_push".to_string()));
    }

    #[test]
    fn agent_passport_flag_includes_issue_passport_capability() {
        // Flag-ON: issue_passport joins the local capability surface; the sync
        // tools stay hosted-gated.
        let capabilities = rcx_local_capabilities_with_flag(true);

        assert!(capabilities.contains(&"crux-mcp.issue_passport".to_string()));
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

        let signing = SigningKey::from_bytes(&[42u8; 32]);
        token.signature.sig = signing.sign(&token.token_hash()).to_bytes();
        let router = RcxRouter::new_with_trusted_issuer_pubkey(token, signing.verifying_key().to_bytes());

        let names: Vec<String> = list_tools_for_rcx_router(&router, 1_776_989_601)
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

    #[tokio::test]
    async fn call_tool_enrich_action() {
        let ctx = test_ctx();
        let result = call_tool(
            "enrich_action",
            &json!({
                "tenant_id": "business::acme",
                "tool_name": "calendar.move_event",
                "tool_parameters": {
                    "event_id": "evt_1",
                    "attendees": ["customer@example.com"],
                    "new_time": "2026-05-08T16:00:00Z"
                }
            }),
            &ctx,
        )
        .await
        .unwrap();
        assert_eq!(
            result["structuredContent"]["schema"],
            corecrux_memory::action_enrichment::ACTION_ENRICHMENT_SCHEMA
        );
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
