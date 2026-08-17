// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `GET /v1/policy/capabilities` — the canonical tool tier/capability policy
//! (B3). The single source the gateway and daemon authorize against, so the
//! gateway fetches it instead of hard-coding a ladder that can drift from the
//! daemon's `resolve_principal` capability tokens.

use super::{require_http_any_scope, AppState, HeaderMap, IntoResponse, Json, State, StatusCode};

/// Return the canonical tool-capability policy document
/// (`crate::policy::policy_document`). Non-sensitive, but gated behind a low
/// read scope so it isn't world-readable on an authenticated daemon.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_policy_capabilities(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["query:read", "facts:read", "admin:read"]) {
        return p.into_response();
    }
    (StatusCode::OK, Json(crate::policy::policy_document())).into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::auth::AuthMode;
    use crate::http::tests::{dev_scope_headers, test_app_state_with_auth};
    use axum::body::to_bytes;
    use axum::response::Response;

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("read body");
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    async fn get(headers: HeaderMap) -> Response {
        let state = test_app_state_with_auth(1, AuthMode::DevScopes);
        get_policy_capabilities(State(state), headers).await.into_response()
    }

    /// The policy document is what the gateway authorizes against, so an
    /// unauthenticated daemon must not serve it (the doc comment's own claim).
    #[tokio::test]
    async fn unauthenticated_read_is_rejected() {
        assert_eq!(get(HeaderMap::new()).await.status(), StatusCode::UNAUTHORIZED);
    }

    /// All three scopes named in `require_http_any_scope` must actually work —
    /// an `any_scope` list is easy to narrow by accident.
    #[tokio::test]
    async fn every_documented_read_scope_is_accepted() {
        for scope in ["query:read", "facts:read", "admin:read"] {
            let resp = get(dev_scope_headers(scope)).await;
            assert_eq!(resp.status(), StatusCode::OK, "scope {scope} should be accepted");
        }
    }

    /// Authenticated but unrelated scope is 403, not 200 — proves the gate
    /// discriminates rather than merely requiring *some* credential.
    #[tokio::test]
    async fn an_unrelated_scope_is_forbidden() {
        assert_eq!(
            get(dev_scope_headers("receipts:read")).await.status(),
            StatusCode::FORBIDDEN
        );
    }

    /// The served body must be the canonical document verbatim. This is the
    /// load-bearing assertion: the whole point of B3 is that the gateway does
    /// not maintain its own copy of the ladder, so any transform here would
    /// reintroduce the drift the endpoint exists to prevent.
    #[tokio::test]
    async fn body_is_the_canonical_policy_document_verbatim() {
        let resp = get(dev_scope_headers("query:read")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body, crate::policy::policy_document());
        assert_eq!(body["schema"], "crux.tool_policy.v1");
    }
}
