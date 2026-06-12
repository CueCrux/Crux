// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Ingress hardening layers for the HTTP planes (`:14800` API, `:14801` MCP).
//!
//! ExecPlan `crux-http-ingress-hardening-2026-06-11` M1: request-body size
//! limit with RFC-7807 `413` responses. Applied in `main.rs` to both the
//! daemon API router and the MCP router so route-level tests exercise the
//! un-hardened router unchanged.
//!
//! Layer ordering note: `Router::layer` wraps outside-in as calls accumulate,
//! so the problem-decorator is added *after* (= outside) the body-limit layer
//! and therefore sees the bare `413` responses the limit layer produces.

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use corecrux_types::ProblemDetails;
use tower_http::limit::RequestBodyLimitLayer;

use crate::config::IngressConfig;
use crate::problem::ProblemResponse;

/// Applies the M1 ingress limits to a fully-built router.
///
/// With `max_request_body_bytes == 0` the router is returned untouched
/// (emergency-rollback path: limits can be disabled by env without a code
/// change).
pub fn apply_ingress_limits(router: Router, cfg: &IngressConfig) -> Router {
    if cfg.max_request_body_bytes == 0 {
        return router;
    }
    let limit = cfg.max_request_body_bytes;
    router
        .layer(RequestBodyLimitLayer::new(limit))
        .layer(axum::middleware::map_response(move |resp: Response| async move {
            decorate_payload_too_large(resp, limit)
        }))
}

/// Rewrites bare `413 Payload Too Large` responses (as emitted by
/// `RequestBodyLimitLayer` on a Content-Length overrun, or by extractors
/// hitting the `Limited` body mid-stream) into RFC-7807 problem+json.
/// Responses that already carry `application/problem+json` pass through.
fn decorate_payload_too_large(resp: Response, limit: usize) -> Response {
    if resp.status() != StatusCode::PAYLOAD_TOO_LARGE {
        return resp;
    }
    let already_problem = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/problem+json"));
    if already_problem {
        return resp;
    }
    let mut pd = ProblemDetails::new(
        StatusCode::PAYLOAD_TOO_LARGE.as_u16(),
        "https://errors.cuecrux.com/payload-too-large",
        "Payload Too Large",
    );
    pd.detail = Some(format!(
        "request body exceeds the configured limit of {limit} bytes (CORECRUXD_MAX_REQUEST_BODY_BYTES)"
    ));
    ProblemResponse(pd).into_response()
}

#[cfg(test)]
mod tests {
    use axum::body::{to_bytes, Body, Bytes};
    use axum::http::{Request, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use tower::util::ServiceExt as _;

    use super::apply_ingress_limits;
    use crate::config::IngressConfig;

    fn test_router() -> Router {
        Router::new().route("/echo", post(|body: Bytes| async move { format!("{} bytes", body.len()) }))
    }

    fn cfg(limit: usize) -> IngressConfig {
        IngressConfig {
            max_request_body_bytes: limit,
            ..IngressConfig::default()
        }
    }

    async fn problem_json(resp: axum::response::Response) -> serde_json::Value {
        assert_eq!(
            resp.headers().get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/problem+json")
        );
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn oversize_body_with_content_length_is_413_problem_json() {
        let app = apply_ingress_limits(test_router(), &cfg(1024));
        let resp = app
            .oneshot(
                Request::post("/echo")
                    .header("content-length", "4096")
                    .body(Body::from(vec![0u8; 4096]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let json = problem_json(resp).await;
        assert_eq!(json["type"], "https://errors.cuecrux.com/payload-too-large");
        assert_eq!(json["status"], 413);
        assert!(json["detail"].as_str().unwrap().contains("1024"));
    }

    #[tokio::test]
    async fn oversize_streaming_body_without_content_length_is_413_problem_json() {
        let app = apply_ingress_limits(test_router(), &cfg(1024));
        // A streamed body advertises no Content-Length, so the limit layer
        // cannot reject up front; the `Limited` body errors mid-read instead.
        let chunks: Vec<Result<Bytes, std::io::Error>> =
            vec![Ok(Bytes::from(vec![0u8; 800])), Ok(Bytes::from(vec![0u8; 800]))];
        let stream = tokio_stream::iter(chunks);
        let resp = app
            .oneshot(Request::post("/echo").body(Body::from_stream(stream)).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let json = problem_json(resp).await;
        assert_eq!(json["type"], "https://errors.cuecrux.com/payload-too-large");
    }

    #[tokio::test]
    async fn under_limit_body_passes_through() {
        let app = apply_ingress_limits(test_router(), &cfg(1024));
        let resp = app
            .oneshot(Request::post("/echo").body(Body::from(vec![0u8; 512])).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"512 bytes");
    }

    #[tokio::test]
    async fn zero_limit_disables_body_limiting() {
        let app = apply_ingress_limits(test_router(), &cfg(0));
        let resp = app
            .oneshot(Request::post("/echo").body(Body::from(vec![0u8; 8192])).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn non_413_responses_are_untouched() {
        let app = apply_ingress_limits(test_router(), &cfg(1024));
        let resp = app
            .oneshot(Request::get("/missing").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_ne!(
            resp.headers().get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/problem+json")
        );
    }
}
