// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! OpenAI function-calling shim over the MCP tool surface.
//!
//! ExecPlan `provider-integration-surfaces-2026-06-11` M2 (G1b). Two routes:
//!
//! - `GET /v1/openai/tools.json` — the **token-filtered** MCP tool surface
//!   (same shaping path as `tools/list`: RCX authz filter + dynamic-surface
//!   weighting from `crux-mcp-dynamic-tool-surface-2026-06-08`) re-emitted as
//!   OpenAI function-calling schemas. Generated from the MCP registry at
//!   request time — never hand-maintained (single source; plan risk #1).
//! - `POST /v1/openai/invoke` — execute one tool. Delegates to the SAME
//!   JSON-RPC `tools/call` dispatch the MCP server uses (capability
//!   enforcement, traces, envelopes included), then records a mediation
//!   receipt through the signed-observation path (T.4).
//!
//! Any OpenAI-SDK agent loop can attach Crux tools with ~10 lines of glue:
//! fetch `tools.json`, pass it as `tools=[...]`, POST each `tool_call` the
//! model emits to `/v1/openai/invoke`, feed the result back.
//!
//! This shim is NOT a chat-completions proxy: the model call never routes
//! through Crux (manifesto anti-pattern; see plan G1 scoping note).
//!
//! Gating: `CORECRUXD_OPENAI_SHIM=1`, default OFF → 404. Requires the MCP
//! surface to be enabled (`AppState.mcp_context`); otherwise 503.

use std::sync::Arc;

use serde_json::{json, Value};

use super::observations::{append_one, PostObservationBody};
use super::{
    problem_response, require_http_any_scope, AppState, HeaderMap, IntoResponse, Json, Response, State, StatusCode,
};

/// Transport-level scopes accepted on the shim. Per-tool authorization is
/// enforced inside MCP dispatch (RCX capability ladder) — this gate only
/// establishes "an authenticated daemon principal" (T.3, no new auth scheme).
const SHIM_SCOPES: &[&str] = &[
    "query:read",
    "facts:write",
    "sessions:write",
    "admin:read",
    "admin:write",
];

#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub(super) struct InvokeBody {
    /// Tool name (MCP name == OpenAI function name).
    #[serde(default)]
    pub name: Option<String>,
    /// Tool arguments as a JSON object.
    #[serde(default)]
    pub arguments: Option<Value>,
    /// Alternative: a raw OpenAI `tool_call.function` fragment
    /// (`{"name": "...", "arguments": "<json-encoded string>"}`), so SDK
    /// loops can forward `tool_call.function` verbatim.
    #[serde(default)]
    pub function: Option<Value>,
}

fn shim_disabled_response() -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        "openai shim disabled (set CORECRUXD_OPENAI_SHIM=1)".to_string(),
    )
    .into_response()
}

fn mcp_unavailable_response() -> Response {
    problem_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "MCP surface unavailable (daemon started with MCP disabled)".to_string(),
    )
    .into_response()
}

/// Per-request MCP context: the shared shim context, bound to the caller's
/// passport identity when one is bound to the request (scoping for private
/// facts / actor stamping rides the same path as MCP bearer auth).
fn request_context(
    base: &Arc<crux_mcp::dispatch::McpContext>,
    ctx: &crate::auth::HttpScopeContext,
) -> crux_mcp::dispatch::McpContext {
    match ctx.passport_id.as_deref() {
        Some(passport) => base.with_agent(crux_mcp::agent::AgentIdentity {
            name: passport.to_string(),
            token_hash: *blake3::hash(passport.as_bytes()).as_bytes(),
        }),
        None => base.as_ref().clone(),
    }
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Map one MCP tool entry (`{name, description, inputSchema}`) to the OpenAI
/// function-calling shape. Unknown/missing schemas degrade to an empty
/// object schema (valid per OpenAI: "no parameters").
fn mcp_tool_to_openai(tool: &Value) -> Value {
    let parameters = tool
        .get("inputSchema")
        .cloned()
        .unwrap_or_else(|| json!({"type": "object", "properties": {}}));
    json!({
        "type": "function",
        "function": {
            "name": tool.get("name").cloned().unwrap_or(Value::Null),
            "description": tool.get("description").cloned().unwrap_or(Value::Null),
            "parameters": parameters,
        }
    })
}

/// Best-effort mediation receipt for one shim invoke (T.4). Mirrors the
/// `/v1/mediation/receipts` observation shape so receipt consumers see one
/// schema regardless of mediator.
fn mint_invoke_receipt(
    state: &AppState,
    principal: &str,
    tool: &str,
    args: &Value,
    outcome: &str,
) -> Result<String, String> {
    let args_sha = format!(
        "blake3:{}",
        blake3::hash(&serde_json::to_vec(args).unwrap_or_default()).to_hex()
    );
    let body = PostObservationBody {
        kind: "tool_mediation".to_string(),
        provider: "openai-shim".to_string(),
        client_ts: None,
        payload: json!({
            "tool_server": "crux-mcp",
            "tool": tool,
            "args_sha": args_sha,
            "decision": "allow",
            "outcome": outcome,
            "mediator": "openai-shim",
        }),
    };
    let scoped = format!("openai-shim::{principal}");
    append_one(state, &scoped, principal, body, None)
        .map(|(resp, _tip)| resp.observation_id)
        .map_err(|(_, msg)| msg)
}

/// `GET /v1/openai/tools.json` — the active (token-filtered) MCP tool
/// surface as OpenAI function-calling JSON schemas.
#[utoipa::path(
    get,
    path = "/v1/openai/tools.json",
    tag = "OpenAI Shim",
    responses(
        (status = 200, description = "OpenAI function-calling tool schemas generated from the MCP registry"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Shim disabled (CORECRUXD_OPENAI_SHIM unset)"),
        (status = 503, description = "MCP surface unavailable"),
    ),
    security(("bearer_auth" = []))
)]
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_tools_json(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !state.openai_shim_enabled {
        return shim_disabled_response();
    }
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, SHIM_SCOPES) {
        return problem.into_response();
    }
    let ctx = match crate::auth::http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };
    let Some(base) = state.mcp_context.as_ref() else {
        return mcp_unavailable_response();
    };

    let mcp_ctx = request_context(base, &ctx);
    let listing = crux_mcp::tools::list_tools_json_for_context(&mcp_ctx, current_unix_seconds()).await;
    let tools: Vec<Value> = listing
        .get("tools")
        .and_then(Value::as_array)
        .map(|tools| tools.iter().map(mcp_tool_to_openai).collect())
        .unwrap_or_default();

    (
        StatusCode::OK,
        Json(json!({
            "source": "crux-mcp",
            "generated_from": "mcp tools/list (token-filtered surface, request-time)",
            "count": tools.len(),
            "tools": tools,
        })),
    )
        .into_response()
}

/// `POST /v1/openai/invoke` — execute one tool through MCP dispatch.
#[utoipa::path(
    post,
    path = "/v1/openai/invoke",
    tag = "OpenAI Shim",
    request_body = InvokeBody,
    responses(
        (status = 200, description = "Tool executed; MCP result + mediation receipt ref"),
        (status = 400, description = "Bad request / tool error"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Capability denied for this tool"),
        (status = 404, description = "Shim disabled (CORECRUXD_OPENAI_SHIM unset)"),
        (status = 503, description = "MCP surface unavailable"),
    ),
    security(("bearer_auth" = []))
)]
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_invoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<InvokeBody>,
) -> Response {
    if !state.openai_shim_enabled {
        return shim_disabled_response();
    }
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, SHIM_SCOPES) {
        return problem.into_response();
    }
    let ctx = match crate::auth::http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };
    let Some(base) = state.mcp_context.as_ref() else {
        return mcp_unavailable_response();
    };

    // Accept either {name, arguments} or an OpenAI tool_call.function
    // fragment whose `arguments` is a JSON-encoded string.
    let (name, args) = match (&body.name, &body.function) {
        (Some(name), _) => (name.clone(), body.arguments.clone().unwrap_or_else(|| json!({}))),
        (None, Some(function)) => {
            let Some(name) = function.get("name").and_then(Value::as_str) else {
                return problem_response(StatusCode::BAD_REQUEST, "function.name is required".to_string())
                    .into_response();
            };
            let args = match function.get("arguments") {
                Some(Value::String(s)) if !s.trim().is_empty() => match serde_json::from_str::<Value>(s) {
                    Ok(v) => v,
                    Err(e) => {
                        return problem_response(
                            StatusCode::BAD_REQUEST,
                            format!("function.arguments is not valid JSON: {e}"),
                        )
                        .into_response();
                    }
                },
                Some(Value::Object(map)) => Value::Object(map.clone()),
                _ => json!({}),
            };
            (name.to_string(), args)
        }
        (None, None) => {
            return problem_response(
                StatusCode::BAD_REQUEST,
                "pass {name, arguments} or an OpenAI tool_call {function} fragment".to_string(),
            )
            .into_response();
        }
    };
    if name.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "tool name must not be empty".to_string()).into_response();
    }

    // Same dispatch path as MCP `tools/call`: RCX capability enforcement,
    // per-passport traces, result envelopes — single source of behaviour.
    let mcp_ctx = request_context(base, &ctx);
    let request = crux_mcp::protocol::JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: json!({"name": name, "arguments": args}),
    };
    let response = crux_mcp::dispatch::dispatch(request, &mcp_ctx, None).await;

    let outcome = if response.error.is_none() { "ok" } else { "error" };
    let principal = ctx.passport_id.clone().unwrap_or_else(|| "operator".to_string());
    let (receipt_ref, receipt_error) = match mint_invoke_receipt(&state, &principal, &name, &args, outcome) {
        Ok(id) => (Some(id), None),
        Err(e) => (None, Some(e)),
    };

    if let Some(err) = response.error {
        let status = if err.code == crux_mcp::dispatch::CAPABILITY_DENIED {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::BAD_REQUEST
        };
        let mut body = json!({
            "name": name,
            "error": {"code": err.code, "message": err.message},
            "receipt_ref": receipt_ref,
        });
        if let Some(re) = receipt_error {
            body["receipt_error"] = Value::String(re);
        }
        return (status, Json(body)).into_response();
    }

    let mut body = json!({
        "name": name,
        "result": response.result,
        "receipt_ref": receipt_ref,
    });
    if let Some(re) = receipt_error {
        body["receipt_error"] = Value::String(re);
    }
    (StatusCode::OK, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthMode;
    use crate::http::tests::{test_app_state, test_app_state_with_auth};
    use axum::body::to_bytes;
    use axum::extract::{Json as JsonExtract, State as StateExtract};

    async fn body_json(resp: Response) -> Value {
        let bytes = to_bytes(resp.into_body(), 1 << 22).await.expect("read body");
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    }

    /// A shim-enabled state whose MCP context SHARES the state's stores —
    /// the same wiring `main.rs` performs.
    fn shim_state() -> AppState {
        let mut state = test_app_state(1);
        state.openai_shim_enabled = true;
        let mcp = crux_mcp::dispatch::McpContext::new_shared(
            state.node_id.clone(),
            state.fact_store.clone(),
            state.session_store.clone(),
            state.retrieval_index.clone(),
            state.update_status.clone(),
            crux_mcp::agent::AgentRegistry::empty(),
        );
        state.mcp_context = Some(Arc::new(mcp));
        state
    }

    fn invoke_body(name: &str, arguments: Value) -> InvokeBody {
        InvokeBody {
            name: Some(name.to_string()),
            arguments: Some(arguments),
            function: None,
        }
    }

    async fn invoke(state: &AppState, body: InvokeBody) -> (StatusCode, Value) {
        let resp = post_invoke(StateExtract(state.clone()), HeaderMap::new(), JsonExtract(body))
            .await
            .into_response();
        let status = resp.status();
        (status, body_json(resp).await)
    }

    #[tokio::test]
    async fn disabled_flag_returns_404() {
        let mut state = shim_state();
        state.openai_shim_enabled = false;
        let resp = get_tools_json(StateExtract(state.clone()), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let (status, _) = invoke(&state, invoke_body("query_facts", json!({}))).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unauthenticated_returns_401_when_auth_on() {
        let mut state = test_app_state_with_auth(1, AuthMode::DevScopes);
        state.openai_shim_enabled = true;
        let resp = get_tools_json(StateExtract(state.clone()), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let resp = post_invoke(
            StateExtract(state),
            HeaderMap::new(),
            JsonExtract(invoke_body("query_facts", json!({}))),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mcp_disabled_returns_503() {
        let mut state = test_app_state(1);
        state.openai_shim_enabled = true;
        state.mcp_context = None;
        let resp = get_tools_json(StateExtract(state.clone()), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn tools_json_mirrors_mcp_surface_single_source() {
        let state = shim_state();
        let resp = get_tools_json(StateExtract(state.clone()), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        let tools = body["tools"].as_array().expect("tools array");
        assert!(!tools.is_empty(), "tool surface must not be empty");
        assert_eq!(body["count"], tools.len() as u64);

        // Every entry is a well-formed OpenAI function schema.
        for tool in tools {
            assert_eq!(tool["type"], "function");
            assert!(tool["function"]["name"].as_str().is_some());
            assert!(tool["function"]["parameters"].is_object());
        }

        // Single-source check: the OpenAI name set equals the MCP tools/list
        // name set for the same context (generated, never hand-maintained).
        let mcp_ctx = state.mcp_context.as_ref().unwrap();
        let mcp_listing = crux_mcp::tools::list_tools_json_for_context(mcp_ctx, 0).await;
        let mcp_names: std::collections::BTreeSet<&str> = mcp_listing["tools"]
            .as_array()
            .expect("mcp tools")
            .iter()
            .filter_map(|t| t["name"].as_str())
            .collect();
        let shim_names: std::collections::BTreeSet<&str> =
            tools.iter().filter_map(|t| t["function"]["name"].as_str()).collect();
        assert_eq!(mcp_names, shim_names, "OpenAI surface must mirror the MCP surface");
    }

    /// The M2 smoke, minus the LLM: an OpenAI-SDK-shaped loop that stores a
    /// fact and recalls it through the shim (list → call → call), proving
    /// tools.json + invoke compose into a working agent loop.
    #[tokio::test]
    async fn openai_loop_stores_then_recalls_a_fact() {
        let state = shim_state();

        // The "model" picked store_fact from tools.json.
        let (status, stored) = invoke(
            &state,
            invoke_body(
                "store_fact",
                json!({"entity": "openai-loop", "key": "harness", "value": "codex-smoke-ok"}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "store_fact failed: {stored}");
        assert!(stored["result"].is_object(), "missing MCP result: {stored}");

        // Then recalls it.
        let (status, recalled) = invoke(&state, invoke_body("query_facts", json!({"entity": "openai-loop"}))).await;
        assert_eq!(status, StatusCode::OK);
        let as_text = serde_json::to_string(&recalled).expect("serialize");
        assert!(
            as_text.contains("codex-smoke-ok"),
            "stored fact must be recallable through the shim: {recalled}"
        );

        // Receipt trail: every invoke carries a receipt ref or an explicit
        // minting error — never silence (T.4).
        for body in [&stored, &recalled] {
            assert!(
                body["receipt_ref"].is_string() || body["receipt_error"].is_string(),
                "invoke must report receipt_ref or receipt_error: {body}"
            );
        }
    }

    #[tokio::test]
    async fn invoke_accepts_openai_tool_call_fragment() {
        let state = shim_state();
        let body = InvokeBody {
            name: None,
            arguments: None,
            function: Some(json!({
                "name": "store_fact",
                "arguments": "{\"entity\": \"frag\", \"key\": \"k\", \"value\": \"v\"}",
            })),
        };
        let (status, resp) = invoke(&state, body).await;
        assert_eq!(status, StatusCode::OK, "fragment invoke failed: {resp}");
        let store = state.fact_store.clone();
        let s = store.read().await;
        assert!(
            s.all_facts().any(|f| f.entity == "frag" && f.value == "v"),
            "fact written through the fragment path"
        );
    }

    #[tokio::test]
    async fn invoke_unknown_tool_maps_to_400() {
        let state = shim_state();
        let (status, body) = invoke(&state, invoke_body("not_a_tool", json!({}))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"]["message"].as_str().is_some());
    }

    #[tokio::test]
    async fn invoke_without_name_or_function_is_rejected() {
        let state = shim_state();
        let (status, _) = invoke(
            &state,
            InvokeBody {
                name: None,
                arguments: None,
                function: None,
            },
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn invoke_with_invalid_fragment_arguments_is_rejected() {
        let state = shim_state();
        let body = InvokeBody {
            name: None,
            arguments: None,
            function: Some(json!({"name": "store_fact", "arguments": "{not json"})),
        };
        let (status, _) = invoke(&state, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
