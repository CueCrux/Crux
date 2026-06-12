// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! axum HTTP server for the MCP Streamable HTTP endpoint.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use serde_json::json;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_stream::StreamExt;
use tracing::{info, warn};

use crate::dispatch::{self, McpContext, PROTOCOL_VERSION, SERVER_NAME, SERVER_VERSION};
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, PARSE_ERROR};

/// MCP Streamable HTTP session-correlation header.
const MCP_SESSION_HEADER: &str = "mcp-session-id";

/// True when the request is a `tools/call` for `cuecrux_session` carrying a
/// non-empty `intent` — the trigger that reshapes the `dynamic` surface and so
/// warrants a `tools/list_changed` push (M3.5).
fn is_cuecrux_session_with_intent(req: &JsonRpcRequest) -> bool {
    if req.method != "tools/call" {
        return false;
    }
    req.params.get("name").and_then(|v| v.as_str()) == Some("cuecrux_session")
        && req
            .params
            .get("arguments")
            .and_then(|a| a.get("intent"))
            .and_then(|i| i.as_str())
            .is_some_and(|s| !s.trim().is_empty())
}

/// Build the axum router with MCP endpoints.
pub fn router(ctx: McpContext) -> axum::Router {
    let state = Arc::new(ctx);
    axum::Router::new()
        .route("/mcp", post(handle_mcp_post))
        .route("/mcp", get(handle_mcp_get))
        .with_state(state)
}

/// `POST /mcp` — JSON-RPC 2.0 endpoint (MCP Streamable HTTP).
async fn handle_mcp_post(State(ctx): State<Arc<McpContext>>, headers: HeaderMap, body: String) -> Response {
    // Extract optional bearer token for agent lookup.
    let agent = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .and_then(|token| ctx.agent_registry.lookup(token).cloned());

    if !ctx.agent_registry.is_empty() && agent.is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "unauthorized",
                "hint": "set Authorization: Bearer <CRUX_AGENT_TOKEN>"
            })),
        )
            .into_response();
    }

    // Build a per-request context with the agent identity attached (if any).
    let req_ctx = if let Some(identity) = agent {
        ctx.with_agent(identity)
    } else {
        McpContext {
            fact_store: Arc::clone(&ctx.fact_store),
            session_store: Arc::clone(&ctx.session_store),
            retrieval_index: Arc::clone(&ctx.retrieval_index),
            update_status: Arc::clone(&ctx.update_status),
            agent_registry: ctx.agent_registry.clone(),
            agent: None,
            node_id: ctx.node_id.clone(),
            handoff_key: ctx.handoff_key,
            daemon_base_url: ctx.daemon_base_url.clone(),
            rcx_router: ctx.rcx_router.clone(),
            data_dir: ctx.data_dir.clone(),
            passport_public_key_hex: ctx.passport_public_key_hex.clone(),
            entity_store: Arc::clone(&ctx.entity_store),
            edge_store: Arc::clone(&ctx.edge_store),
            kind_registry: Arc::clone(&ctx.kind_registry),
            artefact_store: Arc::clone(&ctx.artefact_store),
            agent_passports_enabled: ctx.agent_passports_enabled,
            agent_passport_map: ctx.agent_passport_map.clone(),
        }
    };

    // Parse the JSON-RPC request.
    let req: JsonRpcRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            // serde_json errors can echo request-body fragments; truncate and
            // redact before logging or returning them (ExecPlan
            // crux-log-redaction-2026-06-11 M3).
            let scrubbed = crux_observe::redact::global().scrub_error_echo(&e.to_string());
            warn!(error = %scrubbed, "failed to parse JSON-RPC request");
            let resp = JsonRpcResponse::error(None, PARSE_ERROR, format!("invalid JSON: {scrubbed}"));
            return (StatusCode::OK, Json(resp)).into_response();
        }
    };

    info!(method = %req.method, id = ?req.id, "mcp request");

    // M3.5 session correlation: capture what we need before `dispatch` consumes
    // `req`. The session id is echoed (or minted on `initialize`) so the client
    // can open a matching SSE stream; an intent-bearing `cuecrux_session` call
    // triggers a `tools/list_changed` push to that session's stream (if open).
    let is_initialize = req.method == "initialize";
    let push_list_changed = is_cuecrux_session_with_intent(&req);
    let incoming_session = headers
        .get(MCP_SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    let resp = dispatch::dispatch(req, &req_ctx, None).await;

    let session_id = incoming_session.unwrap_or_else(|| {
        if is_initialize {
            uuid::Uuid::new_v4().simple().to_string()
        } else {
            String::new()
        }
    });
    if !session_id.is_empty() && push_list_changed {
        crate::sse::notify_list_changed(&session_id);
    }

    let mut response = json_rpc_response_with_crux_mode(resp);
    if !session_id.is_empty() {
        if let Ok(value) = HeaderValue::from_str(&session_id) {
            response
                .headers_mut()
                .insert(HeaderName::from_static(MCP_SESSION_HEADER), value);
        }
    }
    response
}

/// `GET /mcp` — dual purpose (MCP Streamable HTTP spec):
/// - `Accept: text/event-stream` → open a server→client SSE stream for
///   notifications (M3.5: `tools/list_changed`), keyed by `Mcp-Session-Id`.
/// - otherwise → static server-info discovery (unchanged).
async fn handle_mcp_get(State(_ctx): State<Arc<McpContext>>, headers: HeaderMap) -> Response {
    let wants_sse = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/event-stream"));

    if !wants_sse {
        return Json(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "serverInfo": {
                "name": SERVER_NAME,
                "version": SERVER_VERSION
            }
        }))
        .into_response();
    }

    let session_id = headers
        .get(MCP_SESSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .map_or_else(|| uuid::Uuid::new_v4().simple().to_string(), str::to_string);

    let rx = crate::sse::register(&session_id);
    let stream =
        UnboundedReceiverStream::new(rx).map(|data| Ok::<Event, std::convert::Infallible>(Event::default().data(data)));

    let mut response = Sse::new(stream).keep_alive(KeepAlive::default()).into_response();
    if let Ok(value) = HeaderValue::from_str(&session_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(MCP_SESSION_HEADER), value);
    }
    response
}

fn json_rpc_response_with_crux_mode(resp: JsonRpcResponse) -> Response {
    let crux_mode = resp
        .error
        .as_ref()
        .and_then(|error| error.data.as_ref())
        .and_then(|data| data.get("stamp"))
        .and_then(|stamp| stamp.get("mode"))
        .and_then(|mode| mode.as_str())
        .and_then(|mode| HeaderValue::from_str(mode).ok());
    let mut response = (StatusCode::OK, Json(resp)).into_response();
    if let Some(crux_mode) = crux_mode {
        response
            .headers_mut()
            .insert(HeaderName::from_static("x-crux-mode"), crux_mode);
    }
    response
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use crux_router::{mint_free_local_token, RcxRouter};
    use http_body_util::BodyExt;
    use rcx_capability_token::RCX_CT_SIGNATURE_LEN;
    use tower::ServiceExt;

    fn test_app() -> axum::Router {
        router(McpContext::new_default("test-node"))
    }

    fn test_app_with_ctx(ctx: McpContext) -> axum::Router {
        router(ctx)
    }

    #[tokio::test]
    async fn post_valid_jsonrpc() {
        let app = test_app();
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let rpc_resp: JsonRpcResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert!(rpc_resp.error.is_none());
        assert_eq!(rpc_resp.result.as_ref().unwrap()["protocolVersion"], PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn post_invalid_json() {
        let app = test_app();
        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from("not json"))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let rpc_resp: JsonRpcResponse = serde_json::from_slice(&body_bytes).unwrap();
        let err = rpc_resp.error.unwrap();
        assert_eq!(err.code, PARSE_ERROR);
    }

    #[tokio::test]
    async fn get_returns_server_info() {
        let app = test_app();
        let req = Request::builder()
            .method("GET")
            .uri("/mcp")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let info: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(info["serverInfo"]["name"], SERVER_NAME);
        assert_eq!(info["protocolVersion"], PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn initialize_advertises_list_changed_and_mints_session() {
        let app = test_app();
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}
        }))
        .unwrap();
        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // M3.5: initialize mints + echoes a session id and advertises listChanged.
        assert!(
            resp.headers().get("mcp-session-id").is_some(),
            "initialize must mint a session id"
        );
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let rpc: JsonRpcResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(rpc.result.unwrap()["capabilities"]["tools"]["listChanged"], true);
    }

    #[tokio::test]
    async fn get_with_event_stream_accept_opens_sse() {
        let app = test_app();
        let req = Request::builder()
            .method("GET")
            .uri("/mcp")
            .header("accept", "text/event-stream")
            .header("mcp-session-id", "test-sse-session")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("text/event-stream"),
            "expected SSE content-type, got `{ct}`"
        );
        assert_eq!(
            resp.headers().get("mcp-session-id").and_then(|v| v.to_str().ok()),
            Some("test-sse-session"),
            "SSE stream echoes the session id"
        );
        // Do NOT read the long-lived body. Clean up the registry entry.
        drop(resp);
        crate::sse::unregister("test-sse-session");
    }

    #[tokio::test]
    async fn post_requires_auth_when_registry_configured() {
        let mut ctx = McpContext::new_default("test-node");
        ctx.agent_registry = crate::agent::AgentRegistry::from_single_token("secret-token");
        let app = test_app_with_ctx(ctx);
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn post_accepts_valid_token_when_registry_configured() {
        let mut ctx = McpContext::new_default("test-node");
        ctx.agent_registry = crate::agent::AgentRegistry::from_single_token("secret-token");
        let app = test_app_with_ctx(ctx);
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .header("authorization", "Bearer secret-token")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn post_denied_tool_sets_crux_mode_header() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = mint_free_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "default",
            vec!["crux-mcp.store_fact".to_string()],
            now.saturating_sub(60),
            now.saturating_add(3600),
            [0x22; RCX_CT_SIGNATURE_LEN],
        );
        let ctx = McpContext::new_default("test-node").with_rcx_router(RcxRouter::new(token));
        let app = test_app_with_ctx(ctx);
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "sync_status", "arguments": {}}
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("x-crux-mode").unwrap(), "refused");

        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let rpc_resp: JsonRpcResponse = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(rpc_resp.error.unwrap().data.unwrap()["mode"], "refused");
    }
}
