// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Ingress hardening layers for the HTTP planes (`:14800` API, `:14801` MCP).
//!
//! ExecPlan `crux-http-ingress-hardening-2026-06-11`:
//! - M1: request-body size limit with RFC-7807 `413` responses.
//! - M2: in-flight concurrency cap + load shed (`503` problem+json) and the
//!   `corecrux_http_inflight` gauge.
//!
//! Applied in `main.rs` to both the daemon API router and the MCP router so
//! route-level tests exercise the un-hardened router unchanged.
//!
//! Layer ordering note: `Router::layer` wraps outside-in as calls accumulate,
//! so layers added *later* run *earlier* on the request path. Final order:
//! load-shed/concurrency gate → inflight gauge → 413 decorator → body limit
//! → routes. Shedding happens before any body byte is read; the gauge counts
//! only admitted requests.

use axum::error_handling::HandleErrorLayer;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use corecrux_types::ProblemDetails;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;

use crate::config::IngressConfig;
use crate::metrics::Metrics;
use crate::problem::ProblemResponse;

/// Applies the ingress limits to a fully-built router.
///
/// Each mechanism is independently disabled by its `0` env value
/// (emergency-rollback path: limits can be turned off without a redeploy).
/// `metrics: None` (route-level tests) skips the inflight gauge.
pub fn apply_ingress_limits(router: Router, cfg: &IngressConfig, metrics: Option<&Metrics>) -> Router {
    let mut router = router;

    // M1 — request body limit + problem+json 413s.
    if cfg.max_request_body_bytes > 0 {
        let limit = cfg.max_request_body_bytes;
        router = router
            .layer(RequestBodyLimitLayer::new(limit))
            .layer(axum::middleware::map_response(move |resp: Response| async move {
                decorate_payload_too_large(resp, limit)
            }));
    }

    // M2 — inflight gauge (admitted requests only, so added before = inside
    // the concurrency gate).
    if let Some(metrics) = metrics {
        let gauge = metrics.http_inflight_gauge();
        router = router.layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let gauge = gauge.clone();
                async move {
                    let _guard = InflightGuard::new(gauge);
                    next.run(req).await
                }
            },
        ));
    }

    // M2 — concurrency cap + load shed. `Router::layer` applies a layer to
    // every route *individually*, so the cap must be a
    // `GlobalConcurrencyLimitLayer` (one shared semaphore) — a plain
    // `concurrency_limit` would mint a fresh semaphore per route and turn
    // the global cap into a per-route cap. `LoadShed` converts
    // at-capacity (inner not-ready) into an `Overloaded` error;
    // `HandleErrorLayer` maps that to a 503 problem+json (axum requires the
    // final service to be infallible).
    if cfg.max_inflight > 0 {
        router = router.layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_ingress_error))
                .load_shed()
                .layer(tower::limit::GlobalConcurrencyLimitLayer::new(cfg.max_inflight)),
        );
    }

    router
}

/// RAII guard so the inflight gauge stays correct even if the inner future
/// is cancelled (client disconnect, shutdown drain cap).
struct InflightGuard(prometheus::Gauge);

impl InflightGuard {
    fn new(gauge: prometheus::Gauge) -> Self {
        gauge.inc();
        Self(gauge)
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.dec();
    }
}

/// Maps tower middleware errors surfaced by `LoadShedLayer` /
/// `ConcurrencyLimitLayer` into RFC-7807 responses. Shed requests get a
/// `503` with `Retry-After: 1`; anything unexpected becomes a `500`.
async fn handle_ingress_error(err: tower::BoxError) -> Response {
    if err.is::<tower::load_shed::error::Overloaded>() {
        let mut pd = ProblemDetails::new(
            StatusCode::SERVICE_UNAVAILABLE.as_u16(),
            "https://errors.cuecrux.com/overloaded",
            "Service Overloaded",
        );
        pd.detail = Some(
            "server is at its in-flight request capacity (CORECRUXD_MAX_INFLIGHT); retry shortly".to_string(),
        );
        let mut resp = ProblemResponse(pd).into_response();
        resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        return resp;
    }
    tracing::error!(%err, "unexpected ingress middleware error");
    ProblemResponse(ProblemDetails::new(
        StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
        "https://errors.cuecrux.com/internal",
        "Internal Server Error",
    ))
    .into_response()
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
        let app = apply_ingress_limits(test_router(), &cfg(1024), None);
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
        let app = apply_ingress_limits(test_router(), &cfg(1024), None);
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
        let app = apply_ingress_limits(test_router(), &cfg(1024), None);
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
        let app = apply_ingress_limits(test_router(), &cfg(0), None);
        let resp = app
            .oneshot(Request::post("/echo").body(Body::from(vec![0u8; 8192])).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn non_413_responses_are_untouched() {
        let app = apply_ingress_limits(test_router(), &cfg(1024), None);
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

    // ── M2: concurrency cap + load shed + inflight gauge ──────────────

    fn test_metrics() -> crate::metrics::Metrics {
        let build = corecrux_types::BuildInfo {
            version: "0.0.0-test".to_string(),
            commit: "test".to_string(),
        };
        crate::metrics::Metrics::new(&build, "test-ingress")
    }

    /// Router with two slow routes so the tests also prove the cap is
    /// global across routes (not per-route).
    fn slow_router(release: std::sync::Arc<tokio::sync::Notify>) -> Router {
        let r2 = release.clone();
        Router::new()
            .route(
                "/slow-a",
                axum::routing::get(move || {
                    let release = release.clone();
                    async move {
                        release.notified().await;
                        "a done"
                    }
                }),
            )
            .route(
                "/slow-b",
                axum::routing::get(move || {
                    let release = r2.clone();
                    async move {
                        release.notified().await;
                        "b done"
                    }
                }),
            )
    }

    #[tokio::test]
    async fn load_shed_returns_503_problem_json_with_retry_after() {
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let cfg = IngressConfig {
            max_inflight: 1,
            ..IngressConfig::default()
        };
        let app = apply_ingress_limits(slow_router(release.clone()), &cfg, None);

        // Park one request inside /slow-a, occupying the single permit.
        let first = tokio::spawn(app.clone().oneshot(Request::get("/slow-a").body(Body::empty()).unwrap()));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // A second request — on a DIFFERENT route — must shed: the cap is
        // global, not per-route.
        let resp = app
            .clone()
            .oneshot(Request::get("/slow-b").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers().get("retry-after").and_then(|v| v.to_str().ok()),
            Some("1")
        );
        let json = problem_json(resp).await;
        assert_eq!(json["type"], "https://errors.cuecrux.com/overloaded");
        assert_eq!(json["status"], 503);

        // Release the parked request; afterwards capacity is available again.
        release.notify_waiters();
        let first = first.await.unwrap().unwrap();
        assert_eq!(first.status(), StatusCode::OK);

        let parked = tokio::spawn(app.clone().oneshot(Request::get("/slow-a").body(Body::empty()).unwrap()));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        release.notify_waiters();
        assert_eq!(parked.await.unwrap().unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn zero_max_inflight_disables_load_shedding() {
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let cfg = IngressConfig {
            max_inflight: 0,
            ..IngressConfig::default()
        };
        let app = apply_ingress_limits(slow_router(release.clone()), &cfg, None);

        let first = tokio::spawn(app.clone().oneshot(Request::get("/slow-a").body(Body::empty()).unwrap()));
        let second = tokio::spawn(app.clone().oneshot(Request::get("/slow-b").body(Body::empty()).unwrap()));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        release.notify_waiters();
        assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
        assert_eq!(second.await.unwrap().unwrap().status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn inflight_gauge_tracks_admitted_requests() {
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let metrics = test_metrics();
        let app = apply_ingress_limits(slow_router(release.clone()), &IngressConfig::default(), Some(&metrics));

        let first = tokio::spawn(app.clone().oneshot(Request::get("/slow-a").body(Body::empty()).unwrap()));
        let second = tokio::spawn(app.clone().oneshot(Request::get("/slow-b").body(Body::empty()).unwrap()));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let rendered = metrics.render().unwrap();
        assert!(
            rendered.contains("corecrux_http_inflight 2"),
            "expected 2 inflight, got: {}",
            rendered
                .lines()
                .find(|l| l.starts_with("corecrux_http_inflight"))
                .unwrap_or("<missing>")
        );

        release.notify_waiters();
        assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
        assert_eq!(second.await.unwrap().unwrap().status(), StatusCode::OK);

        let rendered = metrics.render().unwrap();
        assert!(
            rendered.contains("corecrux_http_inflight 0"),
            "expected 0 inflight after completion, got: {}",
            rendered
                .lines()
                .find(|l| l.starts_with("corecrux_http_inflight"))
                .unwrap_or("<missing>")
        );
    }

    #[tokio::test]
    async fn shed_requests_do_not_touch_the_inflight_gauge() {
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let metrics = test_metrics();
        let cfg = IngressConfig {
            max_inflight: 1,
            ..IngressConfig::default()
        };
        let app = apply_ingress_limits(slow_router(release.clone()), &cfg, Some(&metrics));

        let first = tokio::spawn(app.clone().oneshot(Request::get("/slow-a").body(Body::empty()).unwrap()));
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let shed = app
            .clone()
            .oneshot(Request::get("/slow-b").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);

        // The shed request never crossed the gauge middleware: still 1.
        let rendered = metrics.render().unwrap();
        assert!(rendered.contains("corecrux_http_inflight 1"));

        release.notify_waiters();
        assert_eq!(first.await.unwrap().unwrap().status(), StatusCode::OK);
    }
}
