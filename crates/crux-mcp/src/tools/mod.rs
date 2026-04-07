// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! MCP tool definitions and sub-module dispatch.
//!
//! Each tool is described by a [`ToolDefinition`] with a JSON Schema input
//! specification. [`list_tools`] returns the full catalogue advertised to
//! MCP clients via the `tools/list` response.

pub mod decision;
pub mod facts;
pub mod handoff;
pub mod observe;
pub mod query;
pub mod sessions;

use serde_json::{json, Value};

use crate::dispatch::McpContext;
use crate::protocol::JsonRpcError;

/// Describes a single MCP tool for the `tools/list` response.
#[derive(Debug, Clone)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Return the full tool catalogue (17 tools) advertised to MCP clients.
pub fn list_tools() -> Vec<ToolDefinition> {
    vec![
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
                          ranked by confidence."
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
                          sub-category (e.g. \"patterns\", \"docs\", \"errors\")."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "topic": {
                        "type": "string",
                        "description": "Optional topic filter: \"patterns\", \"docs\", \"errors\", etc."
                    }
                },
                "examples": [
                    { "topic": "patterns" },
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
            description: "Retrieve session state by ID. Returns the full JSON state object.".to_string(),
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
            description: "Create or update session state. Overwrites the previous state.".to_string(),
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
            description: "List all active session IDs. Returns a sorted list.".to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {},
                "examples": [{}]
            }),
        },
        ToolDefinition {
            name: "delete_session".to_string(),
            description: "Delete a session by ID. Returns confirmation or not-found.".to_string(),
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
            description: "Package session state (and optionally facts) into a handoff \
                          bundle for another agent."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "session_id":    { "type": "string",  "description": "Session to hand off" },
                    "include_facts": { "type": "boolean", "description": "Include relevant facts in the package", "default": false },
                    "message":       { "type": "string",  "description": "Free-text message for the receiving agent" }
                },
                "required": ["session_id"],
                "examples": [
                    { "session_id": "session-42", "include_facts": true, "message": "Architecture review complete, one open question." }
                ]
            }),
        },
        ToolDefinition {
            name: "accept_handoff".to_string(),
            description: "Accept a handoff package from another agent, restoring session \
                          state and facts."
                .to_string(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "package": { "type": "string", "description": "Base64-encoded handoff package" }
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
    ]
}

/// Serialise the tool list into the MCP `tools/list` response shape.
pub fn list_tools_json() -> Value {
    let tools: Vec<Value> = list_tools()
        .into_iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            })
        })
        .collect();
    json!({ "tools": tools })
}

/// Return documentation of each tool's output format.
///
/// The MCP spec does not support `outputSchema` in tool definitions, so this
/// function provides a standalone JSON document describing each tool's response
/// shape. Included in the `get_bootstrap` response for agent discoverability.
pub fn tool_output_docs() -> Value {
    json!([
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
        { "tool": "create_handoff",     "output": "{ handoff_id, content_hash, signature, facts_count, total_tokens }" },
        { "tool": "accept_handoff",     "output": "{ session_id, facts_imported, verified: bool }" },
        { "tool": "record_decision",    "output": "{ decision_id, decision_hash, entity, action }" }
    ])
}

/// `get_agent_identity` — return the calling agent's name.
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
        _ => Err(JsonRpcError {
            code: crate::protocol::METHOD_NOT_FOUND,
            message: format!("unknown tool: {name}"),
            data: None,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentIdentity;
    use crate::dispatch::McpContext;

    const TOOL_COUNT: usize = 18;

    fn test_ctx() -> McpContext {
        McpContext::new_default("test-node")
    }

    #[test]
    fn list_tools_returns_sixteen() {
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
}
