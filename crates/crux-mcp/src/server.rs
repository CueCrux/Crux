// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! axum HTTP server for the MCP Streamable HTTP endpoint.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Json;
use serde_json::json;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tokio_stream::StreamExt;
use tracing::{info, warn};

use crate::agent::AgentIdentity;
use crate::dispatch::{self, McpContext, PROTOCOL_VERSION, SERVER_NAME, SERVER_VERSION};
use crate::protocol::{JsonRpcRequest, JsonRpcResponse, METHOD_NOT_FOUND, PARSE_ERROR};
use crate::sse::{RegisterError, Registration};

/// MCP Streamable HTTP session-correlation header.
const MCP_SESSION_HEADER: &str = "mcp-session-id";
const MCP_SESSION_ID_MAX_LEN: usize = 128;

/// HTTP transport state captures the authentication posture once at router
/// construction. Tests can inject OAuth-only posture without mutating the
/// process-wide introspector, while production uses the actual configured
/// introspector.
struct McpHttpState {
    ctx: McpContext,
    oauth_introspection_enabled: bool,
}

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
    router_with_auth_posture(ctx, crate::oauth::introspection_enabled())
}

fn router_with_auth_posture(ctx: McpContext, oauth_introspection_enabled: bool) -> axum::Router {
    let state = Arc::new(McpHttpState {
        ctx,
        oauth_introspection_enabled,
    });
    axum::Router::new()
        .route("/mcp", post(handle_mcp_post))
        .route("/mcp", get(handle_mcp_get))
        .route(
            "/.well-known/oauth-protected-resource",
            get(handle_oauth_protected_resource),
        )
        .route("/.well-known/agent-card", get(handle_agent_card))
        .with_state(state)
}

/// `GET /.well-known/oauth-protected-resource` — RFC 9728 Protected Resource
/// Metadata. Lets hosted MCP clients discover the Authorization Server
/// (VaultCrux) that fronts this daemon. Returns `404` when OAuth is not
/// configured for this daemon (`CRUX_MCP_RESOURCE_URL` unset).
async fn handle_oauth_protected_resource() -> Response {
    match crate::oauth::ResourceConfig::from_env() {
        Some(cfg) => (StatusCode::OK, Json(cfg.protected_resource_document())).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `GET /.well-known/agent-card` — A2A / GB-Z-185.4-style discovery card
/// (agent-card M6). PUBLIC (no bearer) so external agents can discover this
/// daemon. **Launch default ON** — served unless `CRUX_AGENT_CARD=0`; the card
/// describes the service only (no caller passport, no private facts), so it is
/// safe to expose out of the box.
async fn handle_agent_card(State(state): State<Arc<McpHttpState>>) -> Response {
    if !agent_card_enabled() {
        return StatusCode::NOT_FOUND.into_response();
    }
    (
        StatusCode::OK,
        Json(crate::agent_card::build_agent_card_with_auth_posture(
            &state.ctx,
            state.oauth_introspection_enabled,
        )),
    )
        .into_response()
}

/// agent-card M6: discovery-endpoint flag (`CRUX_AGENT_CARD`). Launch default
/// ON — `/.well-known/agent-card` is exposed for A2A discovery. Explicit
/// `CRUX_AGENT_CARD=0` disables it.
pub(crate) fn agent_card_enabled() -> bool {
    std::env::var("CRUX_AGENT_CARD")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

/// `POST /mcp` — JSON-RPC 2.0 endpoint (MCP Streamable HTTP).
async fn handle_mcp_post(State(state): State<Arc<McpHttpState>>, headers: HeaderMap, body: String) -> Response {
    let ctx = &state.ctx;
    let outcome = match authenticate_agent(ctx, &headers, state.oauth_introspection_enabled).await {
        Ok(outcome) => outcome,
        Err(problem) => return problem.into_response(),
    };
    let oauth_read_only = outcome.is_oauth();
    let static_agent_bearer = if outcome.is_agent() {
        bearer_token(&headers).map(str::to_string)
    } else {
        None
    };
    let agent = outcome.into_identity();
    let incoming_session = match mcp_session_id_from_headers(&headers) {
        Ok(session_id) => session_id,
        Err(problem) => return problem.into_response(),
    };

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
            tool_name_allowlist: ctx.tool_name_allowlist.clone(),
            bound_request_principal: ctx.bound_request_principal.clone(),
            bound_request_principal_is_canonical_passport: ctx.bound_request_principal_is_canonical_passport,
            request_authority_bound: ctx.request_authority_bound,
            request_tenant: ctx.request_tenant.clone(),
            request_loopback_bearer_token: ctx.request_loopback_bearer_token.clone(),
            data_dir: ctx.data_dir.clone(),
            passport_public_key_hex: ctx.passport_public_key_hex.clone(),
            entity_store: Arc::clone(&ctx.entity_store),
            edge_store: Arc::clone(&ctx.edge_store),
            kind_registry: Arc::clone(&ctx.kind_registry),
            artefact_store: Arc::clone(&ctx.artefact_store),
            agent_passports_enabled: ctx.agent_passports_enabled,
            passport_mint_requests_enabled: ctx.passport_mint_requests_enabled,
            agent_passport_map: ctx.agent_passport_map.clone(),
            revocation_enforced: ctx.revocation_enforced,
            dense_provider_factory: ctx.dense_provider_factory.clone(),
        }
    }
    .with_request_loopback_bearer_token(static_agent_bearer);

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

    // JSON-RPC notifications carry no `id` and, per the MCP Streamable HTTP
    // spec, receive no response body — the server acknowledges with an empty
    // `202 Accepted`. The previous behaviour (a `{"jsonrpc":"2.0","id":null,
    // "result":null}` body with `200 OK`) is not a valid `JsonRpcMessage`, so
    // strict native-HTTP clients such as Codex's `rmcp` transport reject it
    // ("data did not match any variant of untagged enum JsonRpcMessage, when
    // send initialized notification") — which forced those clients onto a stdio
    // shim. Ack-and-return keeps native HTTP MCP seamless for any spec-compliant
    // client. Requests (with an `id`) fall through to dispatch unchanged.
    if req.id.is_none() {
        info!(method = %req.method, "mcp notification (202 ack)");
        let mut response = StatusCode::ACCEPTED.into_response();
        if let Some(session_id) = &incoming_session {
            if let Ok(value) = HeaderValue::from_str(session_id) {
                response
                    .headers_mut()
                    .insert(HeaderName::from_static(MCP_SESSION_HEADER), value);
            }
        }
        return response;
    }

    // M3.3: hosted-client OAuth callers (mcp:read) are restricted to the
    // read-only method-allowlist — reject writes before dispatch (default-deny).
    if oauth_read_only {
        let tool = if req.method == "tools/call" {
            req.params.get("name").and_then(|v| v.as_str())
        } else {
            None
        };
        if !crate::oauth::oauth_request_allowed(&req.method, tool) {
            let denied = tool.unwrap_or(req.method.as_str()).to_string();
            let resp = JsonRpcResponse::error(
                req.id.clone(),
                METHOD_NOT_FOUND,
                format!("'{denied}' is not available to read-only OAuth callers (mcp:read scope)"),
            );
            return (StatusCode::OK, Json(resp)).into_response();
        }
    }

    info!(method = %req.method, id = ?req.id, "mcp request");

    // M3.5 session correlation: capture what we need before `dispatch` consumes
    // `req`. The session id is echoed (or minted on `initialize`) so the client
    // can open a matching SSE stream; an intent-bearing `cuecrux_session` call
    // triggers a `tools/list_changed` push to that session's stream (if open).
    let is_initialize = req.method == "initialize";
    let push_list_changed = is_cuecrux_session_with_intent(&req);

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
async fn handle_mcp_get(State(state): State<Arc<McpHttpState>>, req: axum::extract::Request) -> Response {
    let ctx = &state.ctx;
    let headers = req.headers();
    let peer_ip = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|ci| ci.0.ip());
    let wants_sse = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|a| a.contains("text/event-stream"));

    // Authenticate BEFORE branching. The discovery banner used to answer any
    // non-SSE GET unconditionally, which meant two things on an authenticated
    // daemon: it disclosed server identity to an unauthenticated caller, and —
    // worse for interoperability — a client probing with a plain GET got a 200
    // and therefore never saw the `WWW-Authenticate` challenge that tells it
    // where the Authorization Server is. Discovery has to be reachable, but the
    // challenge is the thing a probing client actually needs.
    let auth = match authenticate_agent(ctx, headers, state.oauth_introspection_enabled).await {
        Ok(outcome) => outcome,
        Err(problem) => return problem.into_response(),
    };

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

    let agent = auth.into_identity();
    let session_id = match mcp_session_id_from_headers(headers) {
        Ok(Some(session_id)) => session_id,
        Ok(None) => uuid::Uuid::new_v4().simple().to_string(),
        Err(problem) => return problem.into_response(),
    };
    let owner_key = sse_owner_key(agent.as_ref(), peer_ip);

    let registered = match crate::sse::register(&session_id, &owner_key) {
        Ok(registered) => registered,
        Err(err) => return sse_register_error_response(err),
    };
    let registration = registered.registration();
    let rx = registered.into_receiver();
    let cleanup = SseCleanupGuard(registration);
    let stream = UnboundedReceiverStream::new(rx).map(move |data| {
        let _cleanup = &cleanup;
        Ok::<Event, std::convert::Infallible>(Event::default().data(data))
    });

    let mut response = Sse::new(stream).keep_alive(KeepAlive::default()).into_response();
    if let Ok(value) = HeaderValue::from_str(&session_id) {
        response
            .headers_mut()
            .insert(HeaderName::from_static(MCP_SESSION_HEADER), value);
    }
    response
}

struct SseCleanupGuard(Registration);

impl Drop for SseCleanupGuard {
    fn drop(&mut self) {
        crate::sse::unregister_registration(&self.0);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct InvalidMcpSessionId;

impl IntoResponse for InvalidMcpSessionId {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_mcp_session_id",
                "hint": format!("Mcp-Session-Id must be 1..={MCP_SESSION_ID_MAX_LEN} ASCII chars from [A-Za-z0-9._:-]")
            })),
        )
            .into_response()
    }
}

/// Why a request was refused, mapped to its RFC 6750 wire form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthDenial {
    /// No `Authorization` header on a daemon that requires one. RFC 6750 §3:
    /// a challenge with no `error` — nothing was wrong, nothing was offered.
    MissingToken,
    /// A credential was presented and is not usable: unknown to the registry,
    /// inactive per introspection, or issued for another resource.
    InvalidToken,
    /// The caller authenticated, but the token does not carry `mcp:read`.
    InsufficientScope,
}

impl AuthDenial {
    /// (status, RFC 6750 error code, human description).
    ///
    /// `insufficient_scope` is a 403, not a 401 — re-authenticating with the
    /// same rights changes nothing, and a 401 would invite exactly that loop.
    fn rfc6750(self) -> (StatusCode, Option<&'static str>, &'static str) {
        match self {
            AuthDenial::MissingToken => (
                StatusCode::UNAUTHORIZED,
                None,
                "no bearer token on a daemon that requires one",
            ),
            AuthDenial::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                Some("invalid_token"),
                "the bearer token is not recognised, has expired, or was issued for a different resource",
            ),
            AuthDenial::InsufficientScope => (
                StatusCode::FORBIDDEN,
                Some("insufficient_scope"),
                "the bearer token does not carry the 'mcp:read' scope",
            ),
        }
    }
}

impl From<crate::oauth::OauthDenial> for AuthDenial {
    fn from(denial: crate::oauth::OauthDenial) -> Self {
        match denial {
            crate::oauth::OauthDenial::InsufficientScope => AuthDenial::InsufficientScope,
            // Inactive and wrong-audience are both "this credential cannot be
            // used here" — RFC 6750 gives them the same code.
            crate::oauth::OauthDenial::Inactive | crate::oauth::OauthDenial::WrongAudience => AuthDenial::InvalidToken,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct UnauthorizedAgent(AuthDenial);

impl IntoResponse for UnauthorizedAgent {
    fn into_response(self) -> Response {
        auth_challenge_response(self.0)
    }
}

/// Outcome of authenticating an MCP request.
enum AuthOutcome {
    /// No credentials presented and none required (no-auth daemon).
    Anonymous,
    /// A registered static agent token (Desktop, `gemini-prod`, …) — full access.
    Agent(AgentIdentity),
    /// A valid hosted-client OAuth token — read-only (`mcp:read`).
    OAuth(AgentIdentity),
}

impl AuthOutcome {
    fn is_oauth(&self) -> bool {
        matches!(self, AuthOutcome::OAuth(_))
    }
    fn is_agent(&self) -> bool {
        matches!(self, AuthOutcome::Agent(_))
    }
    fn into_identity(self) -> Option<AgentIdentity> {
        match self {
            AuthOutcome::Anonymous => None,
            AuthOutcome::Agent(id) | AuthOutcome::OAuth(id) => Some(id),
        }
    }
}

/// Authenticate an MCP request. Order: (1) registered static agent token
/// (unchanged legacy path), (2) hosted-client OAuth bearer via introspection
/// (opt-in; only when configured), (3) reject unless this is a no-auth daemon.
async fn authenticate_agent(
    ctx: &McpContext,
    headers: &HeaderMap,
    oauth_introspection_enabled: bool,
) -> Result<AuthOutcome, UnauthorizedAgent> {
    let authentication_configured =
        crate::agent::mcp_authentication_configured(&ctx.agent_registry, oauth_introspection_enabled);
    let Some(token) = bearer_token(headers) else {
        return if authentication_configured {
            Err(UnauthorizedAgent(AuthDenial::MissingToken))
        } else {
            Ok(AuthOutcome::Anonymous)
        };
    };

    // 1. Registered static agent token — exact pre-OAuth behaviour. This is an
    //    opaque-string registry lookup, NOT a JWT verification: a token on this
    //    rail is never parsed, so its iss/aud/scope/kid are irrelevant here.
    if let Some(agent) = ctx.agent_registry.lookup(token).cloned() {
        return Ok(AuthOutcome::Agent(agent));
    }

    // 2. Hosted-client OAuth bearer. Introspection is blocking (ureq) so it runs
    //    on a blocking thread; the ≤60s cache keeps the common case off the wire.
    //    A denial here is specific (inactive / wrong scope / wrong audience) and
    //    is reported as such rather than folded into a bare 401.
    let mut oauth_denial = None;
    if oauth_introspection_enabled {
        let token_owned = token.to_string();
        let introspection = tokio::task::spawn_blocking(move || {
            crate::oauth::shared_introspector().map(|i| i.introspect_cached(&token_owned))
        })
        .await
        .ok()
        .flatten();
        if let Some(intro) = introspection {
            if let Some(resource) = crate::oauth::ResourceConfig::from_env() {
                match crate::oauth::authorize_oauth_detailed(
                    &intro,
                    &resource.resource_url,
                    &crate::oauth::oauth_tenant(),
                    crate::oauth::require_resource_aud(),
                ) {
                    Ok(identity) => return Ok(AuthOutcome::OAuth(identity)),
                    Err(denial) => oauth_denial = Some(AuthDenial::from(denial)),
                }
            }
        }
    }

    // 3. Unknown bearer: anonymous only on a no-auth daemon, else refuse — with
    //    the OAuth reason when we have one, otherwise "this token is not valid".
    if authentication_configured {
        Err(UnauthorizedAgent(oauth_denial.unwrap_or(AuthDenial::InvalidToken)))
    } else {
        Ok(AuthOutcome::Anonymous)
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|auth| auth.strip_prefix("Bearer "))
}

/// Build the 401/403 for a refused request, carrying the RFC 6750 `error` code
/// that says *which* kind of refusal it was.
///
/// Without the code, a client cannot distinguish "your token is junk" from "your
/// token is fine but lacks `mcp:read`" — the two demand opposite responses, and
/// the ambiguity costs a human three probes to characterise.
fn auth_challenge_response(denial: AuthDenial) -> Response {
    let oauth = crate::oauth::ResourceConfig::from_env();
    let (status, error, description) = denial.rfc6750();

    // The body hint must not contradict the challenge beside it. When this
    // daemon fronts OAuth, naming only CRUX_AGENT_TOKEN sends a client down the
    // static-token path the same response is telling it not to use.
    let hint = match (&oauth, denial) {
        (Some(_), AuthDenial::InsufficientScope) => {
            "the token is valid but lacks the 'mcp:read' scope; request it from the authorization \
             server named in WWW-Authenticate"
        }
        (Some(_), _) => {
            "authenticate via the authorization server named in WWW-Authenticate, or send a \
             registered agent token as Authorization: Bearer <token>"
        }
        (None, _) => "set Authorization: Bearer <CRUX_AGENT_TOKEN>",
    };

    let mut response = (
        status,
        Json(json!({
            "error": error.unwrap_or("unauthorized"),
            "error_description": description,
            "hint": hint,
        })),
    )
        .into_response();

    // RFC 9728 challenge so claude.ai / ChatGPT can discover the Authorization
    // Server, now carrying the RFC 6750 error code too.
    if let Some(cfg) = oauth {
        if let Ok(value) = HeaderValue::from_str(&cfg.www_authenticate_error(error, description)) {
            response
                .headers_mut()
                .insert(axum::http::header::WWW_AUTHENTICATE, value);
        }
    }
    response
}

fn mcp_session_id_from_headers(headers: &HeaderMap) -> Result<Option<String>, InvalidMcpSessionId> {
    let mut values = headers.get_all(MCP_SESSION_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(InvalidMcpSessionId);
    }
    let raw = value.to_str().map_err(|_| InvalidMcpSessionId)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > MCP_SESSION_ID_MAX_LEN || !trimmed.bytes().all(is_safe_session_id_byte) {
        return Err(InvalidMcpSessionId);
    }
    Ok(Some(trimmed.to_string()))
}

fn is_safe_session_id_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
}

fn sse_owner_key(agent: Option<&AgentIdentity>, peer_ip: Option<IpAddr>) -> String {
    if let Some(agent) = agent {
        format!("agent:{}", agent.name)
    } else if let Some(ip) = peer_ip {
        format!("ip:{ip}")
    } else {
        "anonymous".to_string()
    }
}

fn sse_register_error_response(err: RegisterError) -> Response {
    match err {
        RegisterError::GlobalLimit { max } => sse_session_limit_response("global", max),
        RegisterError::OwnerLimit { max } => sse_session_limit_response("owner", max),
        RegisterError::OwnerMismatch => (
            StatusCode::FORBIDDEN,
            Json(json!({
                "error": "sse_session_owner_mismatch",
                "detail": "session id is owned by a different caller; only the original owner may replace it"
            })),
        )
            .into_response(),
    }
}

fn sse_session_limit_response(scope: &str, limit: usize) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(json!({
            "error": "sse_session_limit",
            "scope": scope,
            "limit": limit
        })),
    )
        .into_response()
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
    use ed25519_dalek::{Signer, SigningKey};
    use http_body_util::BodyExt;
    use rcx_capability_token::RCX_CT_SIGNATURE_LEN;
    use tower::ServiceExt;

    const TEST_AGENT_TOKEN: &str = "crux_at_0123456789abcdef01234567";

    fn test_app() -> axum::Router {
        router_with_auth_posture(McpContext::new_default("test-node"), false)
    }

    fn test_app_with_ctx(ctx: McpContext) -> axum::Router {
        router_with_auth_posture(ctx, false)
    }

    fn test_app_oauth_only() -> axum::Router {
        router_with_auth_posture(McpContext::new_default("test-node"), true)
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
    async fn post_notification_returns_202_empty() {
        // A JSON-RPC notification (no `id`) must get an empty `202 Accepted`,
        // per the MCP Streamable HTTP spec. The old `200 {id:null,result:null}`
        // reply broke strict native-HTTP clients (Codex `rmcp`) and is the reason
        // a stdio shim was needed; this test guards the seamless native path.
        let app = test_app();
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }))
        .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/mcp")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(body_bytes.is_empty(), "notification ack must have an empty body");
    }

    #[tokio::test]
    async fn well_known_agent_card_flag_gated() {
        // agent-card M6. This is the only test that touches CRUX_AGENT_CARD, and
        // it sets+clears within itself, so there is no cross-test env race.
        // Launch default is ON: with the flag unset the endpoint serves.
        std::env::remove_var("CRUX_AGENT_CARD");
        let resp = test_app()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/.well-known/agent-card")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "default-on => 200");

        // Explicit opt-out still disables the endpoint.
        std::env::set_var("CRUX_AGENT_CARD", "0");
        let resp = test_app()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/.well-known/agent-card")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "explicit off => 404");

        std::env::set_var("CRUX_AGENT_CARD", "1");
        let resp = test_app()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/.well-known/agent-card")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "flag-on => 200, no bearer");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["schema"], crate::agent_card::AGENT_CARD_SCHEMA);
        assert!(v["access"]["wellKnown"].as_str().unwrap().contains("agent-card"));
        std::env::remove_var("CRUX_AGENT_CARD");
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

    /// The discovery banner used to answer ANY non-SSE GET with a 200 before
    /// authentication ran, so a probing client on an authenticated daemon never
    /// saw the challenge and could not discover the Authorization Server.
    #[tokio::test]
    async fn get_banner_requires_bearer_when_registry_configured() {
        let mut ctx = McpContext::new_default("test-node");
        ctx.agent_registry = crate::agent::AgentRegistry::from_single_token(TEST_AGENT_TOKEN);
        let app = test_app_with_ctx(ctx);
        let req = Request::builder()
            .method("GET")
            .uri("/mcp")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "an unauthenticated GET must be challenged, not handed serverInfo"
        );
    }

    #[tokio::test]
    async fn oauth_only_get_banner_requires_bearer() {
        let resp = test_app_oauth_only()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/mcp")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "OAuth-only MCP must not expose authenticated discovery anonymously"
        );
    }

    #[tokio::test]
    async fn oauth_only_sse_requires_bearer() {
        let session_id = "oauth-only-missing-bearer";
        let resp = test_app_oauth_only()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/mcp")
                    .header("accept", "text/event-stream")
                    .header("mcp-session-id", session_id)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(!crate::sse::is_registered(session_id));
    }

    #[tokio::test]
    async fn oauth_only_post_requires_bearer() {
        let body = serde_json::to_string(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "store_fact",
                "arguments": {
                    "entity": "test:oauth-only",
                    "key": "must-not-write",
                    "value": "blocked"
                }
            }
        }))
        .unwrap();
        let resp = test_app_oauth_only()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "OAuth-only MCP must challenge before the full dispatcher"
        );
    }

    #[tokio::test]
    async fn oauth_only_unknown_bearer_is_invalid_token() {
        let resp = test_app_oauth_only()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/mcp")
                    .header("authorization", "Bearer unknown-oauth-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            body["error"], "invalid_token",
            "OAuth availability or token validation failures must never fall back to anonymous"
        );
    }

    /// ...but it must still answer an AUTHENTICATED GET, and must stay open on a
    /// no-auth daemon (covered by `get_returns_server_info`).
    #[tokio::test]
    async fn get_banner_served_to_authenticated_caller() {
        let mut ctx = McpContext::new_default("test-node");
        ctx.agent_registry = crate::agent::AgentRegistry::from_single_token(TEST_AGENT_TOKEN);
        let app = test_app_with_ctx(ctx);
        let req = Request::builder()
            .method("GET")
            .uri("/mcp")
            .header("authorization", format!("Bearer {TEST_AGENT_TOKEN}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let info: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(info["serverInfo"]["name"], SERVER_NAME);
    }

    /// The RFC 6750 codes. Without these a client cannot tell a wrong-scope
    /// token from garbage — the ambiguity that cost three probes to diagnose.
    #[test]
    fn auth_denial_maps_to_rfc6750_codes() {
        assert_eq!(AuthDenial::MissingToken.rfc6750().0, StatusCode::UNAUTHORIZED);
        // RFC 6750 §3: no `error` when the request carried no credentials.
        assert_eq!(AuthDenial::MissingToken.rfc6750().1, None);

        let (status, code, _) = AuthDenial::InvalidToken.rfc6750();
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(code, Some("invalid_token"));

        // 403, not 401 — re-authenticating with the same rights would loop.
        let (status, code, _) = AuthDenial::InsufficientScope.rfc6750();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(code, Some("insufficient_scope"));
    }

    #[tokio::test]
    async fn unknown_bearer_is_labelled_invalid_token() {
        let mut ctx = McpContext::new_default("test-node");
        ctx.agent_registry = crate::agent::AgentRegistry::from_single_token(TEST_AGENT_TOKEN);
        let app = test_app_with_ctx(ctx);
        let req = Request::builder()
            .method("GET")
            .uri("/mcp")
            .header("authorization", "Bearer not-the-registered-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(
            body["error"], "invalid_token",
            "a presented-but-unusable token is invalid_token, not a bare 'unauthorized'"
        );
    }

    #[tokio::test]
    async fn sse_requires_bearer_when_registry_configured() {
        let mut ctx = McpContext::new_default("test-node");
        ctx.agent_registry = crate::agent::AgentRegistry::from_single_token(TEST_AGENT_TOKEN);
        let app = test_app_with_ctx(ctx);
        let req = Request::builder()
            .method("GET")
            .uri("/mcp")
            .header("accept", "text/event-stream")
            .header("mcp-session-id", "test-auth-sse-session")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(!crate::sse::is_registered("test-auth-sse-session"));
    }

    #[tokio::test]
    async fn sse_accepts_bearer_when_registry_configured() {
        let mut ctx = McpContext::new_default("test-node");
        ctx.agent_registry = crate::agent::AgentRegistry::from_single_token(TEST_AGENT_TOKEN);
        let app = test_app_with_ctx(ctx);
        let req = Request::builder()
            .method("GET")
            .uri("/mcp")
            .header("accept", "text/event-stream")
            .header("authorization", format!("Bearer {TEST_AGENT_TOKEN}"))
            .header("mcp-session-id", "test-auth-sse-session-ok")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(crate::sse::is_registered("test-auth-sse-session-ok"));
        drop(resp);
        tokio::task::yield_now().await;
        assert!(!crate::sse::is_registered("test-auth-sse-session-ok"));
    }

    #[tokio::test]
    async fn sse_unregisters_on_stream_end() {
        let app = test_app();
        let session_id = "test-sse-cleanup-session";
        let req = Request::builder()
            .method("GET")
            .uri("/mcp")
            .header("accept", "text/event-stream")
            .header("mcp-session-id", session_id)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(crate::sse::is_registered(session_id));
        drop(resp);
        tokio::task::yield_now().await;
        assert!(!crate::sse::is_registered(session_id));
    }

    #[tokio::test]
    async fn sse_session_id_limits() {
        let app = test_app();
        let too_long = "a".repeat(MCP_SESSION_ID_MAX_LEN + 1);
        let req = Request::builder()
            .method("GET")
            .uri("/mcp")
            .header("accept", "text/event-stream")
            .header("mcp-session-id", too_long)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

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
            .header("mcp-session-id", "bad/session")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_requires_auth_when_registry_configured() {
        let mut ctx = McpContext::new_default("test-node");
        ctx.agent_registry = crate::agent::AgentRegistry::from_single_token(TEST_AGENT_TOKEN);
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
        ctx.agent_registry = crate::agent::AgentRegistry::from_single_token(TEST_AGENT_TOKEN);
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
            .header("authorization", format!("Bearer {TEST_AGENT_TOKEN}"))
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
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let mut token = mint_free_local_token(
            "p_0123456789abcdef0123456789abcdef",
            "daemon_01HV0000000000000000000000",
            "default",
            vec!["crux-mcp.store_fact".to_string()],
            now.saturating_sub(60),
            now.saturating_add(3600),
            [0x22; RCX_CT_SIGNATURE_LEN],
        );
        token.signature.sig = signing.sign(&token.token_hash()).to_bytes();
        let ctx = McpContext::new_default("test-node").with_rcx_router(RcxRouter::new_with_trusted_issuer_pubkey(
            token,
            signing.verifying_key().to_bytes(),
        ));
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
