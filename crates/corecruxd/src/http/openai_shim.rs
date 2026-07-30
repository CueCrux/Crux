// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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
//! Verified HTTP scopes are an additional exact-name ceiling over RCX:
//! `query:read` is read-only, `facts:write` and `sessions:write` expose only
//! their narrow mutation groups, and identity-bound `admin:write` receives
//! only the audited tenant-aware union of those groups plus safe admin reads.
//! New tools are default-denied for every authenticated HTTP scope.

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

/// Principal bound by the authenticating HTTP transport. Local development
/// assertions are namespaced so they cannot collide with a verified passport.
fn request_principal(ctx: &crate::auth::HttpScopeContext) -> Result<Option<String>, Box<crate::http::ProblemResponse>> {
    principal_for_request(
        ctx.passport_id.as_deref(),
        ctx.local_unverified_identity(),
        ctx.auth_enforced(),
    )
}

fn principal_for_request(
    passport_id: Option<&str>,
    local_unverified_identity: bool,
    auth_enforced: bool,
) -> Result<Option<String>, Box<crate::http::ProblemResponse>> {
    const LOCAL_PREFIX: &str = "local-unverified:";
    const UNBOUND_SENTINEL: &str = "authenticated-unbound";

    if !local_unverified_identity
        && passport_id.is_some_and(|passport| passport == UNBOUND_SENTINEL || passport.starts_with(LOCAL_PREFIX))
    {
        return Err(Box::new(crate::http::ProblemResponse(
            corecrux_types::ProblemDetails::forbidden("passport id uses a reserved OpenAI-shim identity namespace")
                .with_extensions(json!({"code": "SHIM_PASSPORT_RESERVED"})),
        )));
    }

    match passport_id {
        Some(passport) if local_unverified_identity => Ok(Some(format!("{LOCAL_PREFIX}{passport}"))),
        Some(passport) => Ok(Some(passport.to_string())),
        None if !auth_enforced => Ok(Some(format!("{LOCAL_PREFIX}openai-shim"))),
        None => Ok(None),
    }
}

/// Per-request MCP context: intersect the shared daemon RCX surface with the
/// verified HTTP scopes, and bind the transport-resolved principal + tenant
/// directly so they are never reinterpreted as MCP agent aliases.
fn request_context(
    base: &Arc<crux_mcp::dispatch::McpContext>,
    ctx: &crate::auth::HttpScopeContext,
) -> Result<crux_mcp::dispatch::McpContext, Box<crate::http::ProblemResponse>> {
    request_context_for_tenant(base, ctx, None)
}

fn request_context_for_tenant(
    base: &Arc<crux_mcp::dispatch::McpContext>,
    ctx: &crate::auth::HttpScopeContext,
    requested_tenant: Option<&str>,
) -> Result<crux_mcp::dispatch::McpContext, Box<crate::http::ProblemResponse>> {
    let tenant = ctx.resolve_authorized_tenant(requested_tenant).map_err(Box::new)?;
    let principal = request_principal(ctx)?;
    let mut request = match principal.as_deref() {
        Some(principal) => base.with_agent(crux_mcp::agent::AgentIdentity {
            name: principal.to_string(),
            token_hash: *blake3::hash(principal.as_bytes()).as_bytes(),
        }),
        None => base.as_ref().clone(),
    }
    .with_request_authority(principal.clone(), tenant);

    if ctx.auth_enforced() {
        let crux_mcp::tools::HttpScopeToolPolicy::AllowOnly(tool_names) =
            crux_mcp::tools::tool_policy_for_http_scopes(&ctx.scopes, principal.is_some());
        request = request.with_tool_name_allowlist(tool_names);
    }
    Ok(request)
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
    tenant: &str,
    tool: &str,
    args: &Value,
    decision: &str,
    outcome: &str,
) -> Result<String, String> {
    let body = invoke_receipt_body(tenant, tool, args, decision, outcome);
    let scoped = invoke_receipt_scope(principal, tenant);
    append_one(state, &scoped, principal, body, None)
        .map(|(resp, _tip)| resp.observation_id)
        .map_err(|(_, msg)| msg)
}

fn invoke_receipt_scope(principal: &str, tenant: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"openai-shim-receipt-scope-v1");
    hasher.update(&(principal.len() as u64).to_le_bytes());
    hasher.update(principal.as_bytes());
    hasher.update(&(tenant.len() as u64).to_le_bytes());
    hasher.update(tenant.as_bytes());
    format!("openai-shim::{}", hasher.finalize().to_hex())
}

fn invoke_receipt_body(tenant: &str, tool: &str, args: &Value, decision: &str, outcome: &str) -> PostObservationBody {
    let args_sha = format!(
        "blake3:{}",
        blake3::hash(&serde_json::to_vec(args).unwrap_or_default()).to_hex()
    );
    PostObservationBody {
        kind: "tool_mediation".to_string(),
        provider: "openai-shim".to_string(),
        client_ts: None,
        payload: json!({
            "tool_server": "crux-mcp",
            "tool": tool,
            "tenant_id": tenant,
            "args_sha": args_sha,
            "decision": decision,
            "outcome": outcome,
            "mediator": "openai-shim",
        }),
    }
}

fn receipt_principal(ctx: &crux_mcp::dispatch::McpContext) -> String {
    ctx.scope_identity()
        .unwrap_or_else(|| "authenticated-unbound".to_string())
}

fn passport_override_response(ctx: &crate::auth::HttpScopeContext) -> Option<Response> {
    ctx.passport_override_used().then(|| {
        problem_response(
            StatusCode::FORBIDDEN,
            "passport impersonation is not permitted on the OpenAI shim".to_string(),
        )
        .into_response()
    })
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
    if let Some(response) = passport_override_response(&ctx) {
        return response;
    }
    let Some(base) = state.mcp_context.as_ref() else {
        return mcp_unavailable_response();
    };

    let mcp_ctx = match request_context(base, &ctx) {
        Ok(ctx) => ctx,
        Err(problem) => return (*problem).into_response(),
    };
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
    if let Some(response) = passport_override_response(&ctx) {
        return response;
    }
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
    let requested_tenant = args.get("tenant_id").and_then(Value::as_str);
    let mcp_ctx = match request_context_for_tenant(base, &ctx, requested_tenant) {
        Ok(ctx) => ctx,
        Err(problem) => return (*problem).into_response(),
    };
    let request = crux_mcp::protocol::JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: json!({"name": name, "arguments": args}),
    };
    let response = crux_mcp::dispatch::dispatch(request, &mcp_ctx, None).await;

    let capability_denied = response
        .error
        .as_ref()
        .is_some_and(|error| error.code == crux_mcp::dispatch::CAPABILITY_DENIED);
    let decision = if capability_denied { "deny" } else { "allow" };
    let outcome = if capability_denied {
        "denied"
    } else if response.error.is_none() {
        "ok"
    } else {
        "error"
    };
    let principal = receipt_principal(&mcp_ctx);
    let tenant = mcp_ctx.scope_tenant();
    let (receipt_ref, receipt_error) =
        match mint_invoke_receipt(&state, &principal, &tenant, &name, &args, decision, outcome) {
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
    fn enable_shim(mut state: AppState) -> AppState {
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

    fn shim_state() -> AppState {
        enable_shim(test_app_state(1))
    }

    fn shim_state_with_auth(mode: AuthMode) -> AppState {
        enable_shim(test_app_state_with_auth(1, mode))
    }

    fn invoke_body(name: &str, arguments: Value) -> InvokeBody {
        InvokeBody {
            name: Some(name.to_string()),
            arguments: Some(arguments),
            function: None,
        }
    }

    async fn invoke(state: &AppState, body: InvokeBody) -> (StatusCode, Value) {
        invoke_with_headers(state, HeaderMap::new(), body).await
    }

    async fn invoke_with_headers(state: &AppState, headers: HeaderMap, body: InvokeBody) -> (StatusCode, Value) {
        let resp = post_invoke(StateExtract(state.clone()), headers, JsonExtract(body))
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

    fn scoped_headers(scopes: &str, passport: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-scopes", scopes.parse().expect("valid scopes header"));
        if let Some(passport) = passport {
            headers.insert(
                "x-corecrux-passport-id",
                passport.parse().expect("valid passport header"),
            );
        }
        headers
    }

    #[tokio::test]
    async fn query_read_listing_and_direct_calls_are_write_denied() {
        let state = shim_state_with_auth(AuthMode::DevScopes);
        let headers = scoped_headers("query:read", None);

        let listed = get_tools_json(StateExtract(state.clone()), headers.clone())
            .await
            .into_response();
        assert_eq!(listed.status(), StatusCode::OK);
        let body = body_json(listed).await;
        let names: std::collections::BTreeSet<&str> = body["tools"]
            .as_array()
            .expect("tools")
            .iter()
            .filter_map(|tool| tool["function"]["name"].as_str())
            .collect();
        assert!(names.contains("query_facts"));
        assert!(!names.contains("store_fact"));
        assert!(!names.contains("save_session"));
        assert!(!names.contains("punch_in"));
        assert!(!names.contains("get_session"));
        assert!(!names.contains("list_sessions"));
        assert!(!names.contains("receipt_verify"));
        assert!(!names.contains("sync_status"));
        assert!(!names.contains("coord_status"));
        assert!(!names.contains("get_bootstrap"));

        let before = state.fact_store.read().await.count();
        let (status, denied) = invoke_with_headers(
            &state,
            headers.clone(),
            invoke_body("store_fact", json!({"entity": "blocked", "key": "k", "value": "v"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(denied["error"]["code"], crux_mcp::dispatch::CAPABILITY_DENIED);

        let fragment = InvokeBody {
            name: None,
            arguments: None,
            function: Some(json!({
                "name": "store_fact",
                "arguments": "{\"entity\":\"blocked-fragment\",\"key\":\"k\",\"value\":\"v\"}",
            })),
        };
        let (status, _) = invoke_with_headers(&state, headers.clone(), fragment).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = invoke_with_headers(&state, headers, invoke_body("punch_in", json!({}))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(state.fact_store.read().await.count(), before);
    }

    #[tokio::test]
    async fn fact_and_session_write_scopes_do_not_cross_authorize() {
        let state = shim_state_with_auth(AuthMode::DevScopes);
        let fact_headers = scoped_headers("facts:write", Some("writer"));
        let session_headers = scoped_headers("sessions:write", Some("writer"));

        let (status, _) =
            invoke_with_headers(&state, fact_headers.clone(), invoke_body("save_session", json!({}))).await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = invoke_with_headers(
            &state,
            session_headers.clone(),
            invoke_body("cuecrux_session", json!({})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, _) = invoke_with_headers(
            &state,
            session_headers,
            invoke_body("store_fact", json!({"entity": "blocked", "key": "k", "value": "v"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, stored) = invoke_with_headers(
            &state,
            fact_headers,
            invoke_body("store_fact", json!({"entity": "allowed", "key": "k", "value": "v"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "bound fact write failed: {stored}");
        let store = state.fact_store.read().await;
        let fact = store
            .all_facts()
            .find(|fact| fact.entity == "allowed")
            .expect("stored fact");
        assert_eq!(fact.actor.as_deref(), Some("local-unverified:writer"));
        assert_eq!(fact.tenant_hash, "default");
    }

    #[tokio::test]
    async fn admin_read_cannot_invoke_tools_with_hidden_writes() {
        let state = shim_state_with_auth(AuthMode::DevScopes);
        let headers = scoped_headers("admin:read", Some("reader"));
        let before = state.fact_store.read().await.count();

        for tool in ["audit_config", "get_passport"] {
            let (status, body) = invoke_with_headers(&state, headers.clone(), invoke_body(tool, json!({}))).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{tool}: {body}");
            assert_eq!(body["error"]["code"], crux_mcp::dispatch::CAPABILITY_DENIED);
        }
        assert_eq!(state.fact_store.read().await.count(), before);
    }

    #[tokio::test]
    async fn admin_write_is_an_exact_tenant_aware_subset() {
        let state = shim_state_with_auth(AuthMode::DevScopes);
        let headers = scoped_headers("admin:write", Some("admin"));

        for tool in ["entity_get", "punch_in", "audit_config", "cuecrux_session"] {
            let (status, body) = invoke_with_headers(&state, headers.clone(), invoke_body(tool, json!({}))).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{tool}: {body}");
            assert_eq!(body["error"]["code"], crux_mcp::dispatch::CAPABILITY_DENIED);
        }

        let (status, stored) = invoke_with_headers(
            &state,
            headers,
            invoke_body("store_fact", json!({"entity": "admin-safe", "key": "k", "value": "v"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{stored}");
        let store = state.fact_store.read().await;
        let fact = store
            .all_facts()
            .find(|fact| fact.entity == "admin-safe")
            .expect("stored fact");
        assert_eq!(fact.actor.as_deref(), Some("local-unverified:admin"));
    }

    #[tokio::test]
    async fn authenticated_unbound_write_is_denied_without_operator_attribution() {
        let state = shim_state_with_auth(AuthMode::DevScopes);
        let headers = scoped_headers("facts:write", None);
        let before = state.fact_store.read().await.count();

        let (status, body) = invoke_with_headers(
            &state,
            headers,
            invoke_body("store_fact", json!({"entity": "blocked", "key": "k", "value": "v"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], crux_mcp::dispatch::CAPABILITY_DENIED);
        assert_eq!(state.fact_store.read().await.count(), before);

        let auth_ctx = crate::auth::http_scope_context(&state.auth, &scoped_headers("facts:write", None))
            .expect("HTTP scope context");
        let mcp_ctx =
            request_context(state.mcp_context.as_ref().expect("MCP context"), &auth_ctx).expect("request context");
        assert_eq!(receipt_principal(&mcp_ctx), "authenticated-unbound");
        let receipt = invoke_receipt_body("default", "store_fact", &json!({}), "deny", "denied");
        assert_eq!(receipt.payload["decision"], "deny");
        assert_eq!(receipt.payload["tenant_id"], "default");
        assert_ne!(receipt_principal(&mcp_ctx), "operator");
        let legacy_operator_path =
            crate::http::observations::observation_file_path(&state.data_dir, "openai-shim::operator");
        assert!(!legacy_operator_path.exists());
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn verified_http_tenant_rejects_cross_tenant_query_arguments() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        const SECRET: &str = "0123456789abcdef0123456789abcdef";

        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", SECRET);
        std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-test");
        std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");
        let state = shim_state_with_auth(AuthMode::JwtHs256);

        #[derive(serde::Serialize)]
        struct Claims<'a> {
            exp: usize,
            iss: &'a str,
            aud: &'a str,
            scope: &'a str,
            tenant_id: &'a str,
            passport_id: &'a str,
        }
        let claims = Claims {
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_secs()
                + 3600) as usize,
            iss: "corecrux-test",
            aud: "corecrux",
            scope: "query:read",
            tenant_id: "tenant-a",
            passport_id: "verified-openai",
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .expect("jwt");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("authorization header"),
        );

        let (status, _) = invoke_with_headers(
            &state,
            headers.clone(),
            invoke_body(
                "query",
                json!({"tenant_id": "tenant-b", "query": "blocked", "token_budget": 500}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let (status, body) = invoke_with_headers(
            &state,
            headers,
            invoke_body(
                "query",
                json!({"tenant_id": "tenant-a", "query": "allowed", "token_budget": 500}),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "same-tenant query failed: {body}");

        std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
        std::env::remove_var("CORECRUXD_JWT_ISS");
        std::env::remove_var("CORECRUXD_JWT_AUD");
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn verified_admin_cannot_override_shim_attribution() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        const SECRET: &str = "0123456789abcdef0123456789abcdef";

        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", SECRET);
        std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-test");
        std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");
        let state = shim_state_with_auth(AuthMode::JwtHs256);

        #[derive(serde::Serialize)]
        struct Claims<'a> {
            exp: usize,
            iss: &'a str,
            aud: &'a str,
            scope: &'a str,
            tenant_id: &'a str,
            passport_id: &'a str,
        }
        let claims = Claims {
            exp: (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_secs()
                + 3600) as usize,
            iss: "corecrux-test",
            aud: "corecrux",
            scope: "admin:write",
            tenant_id: "tenant-a",
            passport_id: "admin-real",
        };
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .expect("jwt");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("authorization header"),
        );
        headers.insert("x-corecrux-passport-id", "victim".parse().expect("passport header"));

        let before = state.fact_store.read().await.count();
        let (status, _) = invoke_with_headers(
            &state,
            headers,
            invoke_body("store_fact", json!({"entity": "blocked", "key": "k", "value": "v"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(state.fact_store.read().await.count(), before);

        std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
        std::env::remove_var("CORECRUXD_JWT_ISS");
        std::env::remove_var("CORECRUXD_JWT_AUD");
    }

    #[test]
    fn invoke_receipts_are_tenant_distinct() {
        let tenant_a = invoke_receipt_body("tenant-a", "query", &json!({}), "allow", "ok");
        let tenant_b = invoke_receipt_body("tenant-b", "query", &json!({}), "allow", "ok");
        assert_eq!(tenant_a.payload["tenant_id"], "tenant-a");
        assert_eq!(tenant_b.payload["tenant_id"], "tenant-b");
        assert_ne!(
            invoke_receipt_scope("same-passport", "tenant-a"),
            invoke_receipt_scope("same-passport", "tenant-b")
        );
    }

    #[test]
    fn local_and_verified_principal_namespaces_cannot_collide() {
        assert_eq!(
            principal_for_request(Some("alice"), true, true)
                .expect("local assertion")
                .as_deref(),
            Some("local-unverified:alice")
        );
        assert_eq!(
            principal_for_request(Some("alice"), false, true)
                .expect("verified passport")
                .as_deref(),
            Some("alice")
        );
        assert!(principal_for_request(Some("local-unverified:alice"), false, true).is_err());
        assert!(principal_for_request(Some("authenticated-unbound"), false, true).is_err());
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
