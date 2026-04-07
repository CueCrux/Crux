// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! axum HTTP server for the MCP Streamable HTTP endpoint.

use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Json;
use serde_json::json;
use tracing::{info, warn};

use crate::dispatch::{self, McpContext, PROTOCOL_VERSION, SERVER_NAME, SERVER_VERSION};
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, PARSE_ERROR};

/// Build the axum router with MCP endpoints.
pub fn router(ctx: McpContext) -> axum::Router {
    let state = Arc::new(ctx);
    axum::Router::new()
        .route("/mcp", post(handle_mcp_post))
        .route("/mcp", get(handle_mcp_get))
        .with_state(state)
}

/// `POST /mcp` — JSON-RPC 2.0 endpoint (MCP Streamable HTTP).
async fn handle_mcp_post(State(ctx): State<Arc<McpContext>>, headers: HeaderMap, body: String) -> impl IntoResponse {
    // Extract optional bearer token for agent lookup.
    let agent = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
        .and_then(|token| ctx.agent_registry.lookup(token).cloned());

    // Build a per-request context with the agent identity attached (if any).
    let req_ctx = if let Some(identity) = agent {
        ctx.with_agent(identity)
    } else {
        McpContext {
            fact_store: Arc::clone(&ctx.fact_store),
            session_store: Arc::clone(&ctx.session_store),
            retrieval_index: Arc::clone(&ctx.retrieval_index),
            agent_registry: ctx.agent_registry.clone(),
            agent: None,
            node_id: ctx.node_id.clone(),
        }
    };

    // Parse the JSON-RPC request.
    let req: JsonRpcRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "failed to parse JSON-RPC request");
            let resp = JsonRpcResponse::error(None, PARSE_ERROR, format!("invalid JSON: {e}"));
            return (StatusCode::OK, Json(resp));
        }
    };

    info!(method = %req.method, id = ?req.id, "mcp request");

    let resp = dispatch::dispatch(req, &req_ctx, None).await;
    (StatusCode::OK, Json(resp))
}

/// `GET /mcp` — server info discovery (MCP Streamable HTTP spec).
async fn handle_mcp_get(State(_ctx): State<Arc<McpContext>>) -> impl IntoResponse {
    Json(json!({
        "protocolVersion": PROTOCOL_VERSION,
        "serverInfo": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION
        }
    }))
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_app() -> axum::Router {
        let ctx = McpContext::new_default("test-node");
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
}
