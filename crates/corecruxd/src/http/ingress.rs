// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Ingress hardening layers for the HTTP planes (`:14800` API, `:14801` MCP).
//!
//! ExecPlan `crux-http-ingress-hardening-2026-06-11`:
//! - M1: request-body size limit with RFC-7807 `413` responses.
//! - M2: in-flight concurrency cap + load shed (`503` problem+json) and the
//!   `corecrux_http_inflight` gauge.
//! - M3: keyed rate limiting (passport → client-IP fallback) with `429` +
//!   `Retry-After`, loopback exempt by default, and the
//!   `corecrux_http_rate_limited_total{key_kind}` counter.
//!
//! Applied in `main.rs` to both the daemon API router and the MCP router so
//! route-level tests exercise the un-hardened router unchanged.
//!
//! Layer ordering note: `Router::layer` wraps outside-in as calls accumulate,
//! so layers added *later* run *earlier* on the request path. Final order:
//! rate limiter → load-shed/concurrency gate → inflight gauge →
//! 413 decorator → body limit → routes. A flood is 429'd before it can
//! occupy an inflight slot, and shedding happens before any body byte is
//! read; the gauge counts only admitted requests.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::error_handling::HandleErrorLayer;
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use corecrux_types::ProblemDetails;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;

use crate::config::IngressConfig;
use crate::metrics::Metrics;
use crate::problem::ProblemResponse;

/// Passport header reused as the rate-limit key when present (matches the
/// presence middleware in `http/mod.rs`).
const PASSPORT_HEADER: &str = "x-corecrux-passport-id";
/// Bucket-map size that triggers an inline idle-entry sweep — bounds memory
/// under spoofed-source floods.
const BUCKET_SWEEP_THRESHOLD: usize = 10_000;
/// Idle horizon for the sweep: an idle bucket is fully refilled anyway, so
/// dropping it loses nothing.
const BUCKET_IDLE_SECS: u64 = 60;

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

    // M3 — keyed rate limiting, outermost: a flood is rejected before it
    // can occupy an inflight slot or read a body byte.
    if cfg.rate_limit_rps > 0 {
        let limiter = Arc::new(HttpRateLimiter::new(cfg, metrics.cloned()));
        router = router.layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| {
                let limiter = limiter.clone();
                async move {
                    match limiter.check_request(&req) {
                        Ok(()) => next.run(req).await,
                        Err(denied) => denied.into_response(),
                    }
                }
            },
        ));
    }

    router
}

/// Keyed token-bucket rate limiter for the HTTP planes.
///
/// Keying: per passport when `X-Corecrux-Passport-Id` is present, else per
/// client IP (`ConnectInfo`). Client IPs inside an exempt CIDR (loopback by
/// default — console SPA + local agents) bypass limiting entirely.
///
/// Deliberately in-crate rather than the `governor` crate: the daemon
/// already ships a proven token-bucket (per-tenant gRPC throttle,
/// `grpc.rs`), and supply-chain policy files (`deny.toml`) are owned by a
/// concurrent workstream — no new dependency for ~100 lines of arithmetic.
pub struct HttpRateLimiter {
    rps: u64,
    burst: u64,
    exempt_cidrs: Vec<(IpAddr, u8)>,
    buckets: Mutex<HashMap<String, RateBucket>>,
    metrics: Option<Metrics>,
}

struct RateBucket {
    tokens: f64,
    last_touch: Instant,
}

/// A denied request: status 429 + `Retry-After`.
#[derive(Debug, PartialEq, Eq)]
pub struct RateLimited {
    retry_after_secs: u64,
    key_kind: &'static str,
}

impl IntoResponse for RateLimited {
    fn into_response(self) -> Response {
        let mut pd = ProblemDetails::new(
            StatusCode::TOO_MANY_REQUESTS.as_u16(),
            "https://errors.cuecrux.com/rate-limited",
            "Too Many Requests",
        );
        pd.detail = Some(format!(
            "request rate exceeds the per-{} limit (CORECRUXD_RATE_LIMIT_RPS); retry after {}s",
            self.key_kind, self.retry_after_secs
        ));
        let mut resp = ProblemResponse(pd).into_response();
        if let Ok(v) = HeaderValue::from_str(&self.retry_after_secs.to_string()) {
            resp.headers_mut().insert(header::RETRY_AFTER, v);
        }
        resp
    }
}

impl HttpRateLimiter {
    pub fn new(cfg: &IngressConfig, metrics: Option<Metrics>) -> Self {
        Self {
            rps: cfg.rate_limit_rps,
            burst: cfg.rate_limit_burst.max(cfg.rate_limit_rps).max(1),
            exempt_cidrs: parse_cidrs(&cfg.rate_limit_exempt_cidrs),
            buckets: Mutex::new(HashMap::new()),
            metrics,
        }
    }

    /// Derives the key from the request and consumes one token.
    fn check_request(&self, req: &axum::extract::Request) -> Result<(), RateLimited> {
        let passport = req
            .headers()
            .get(PASSPORT_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let client_ip = req
            .extensions()
            .get::<ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| normalize_ip(ci.0.ip()));
        self.check(passport, client_ip, Instant::now())
    }

    /// Core decision, separated for deterministic tests. Exemption is by
    /// client IP and wins over passport keying (a loopback console session
    /// is never limited, passport or not). A request with neither passport
    /// nor `ConnectInfo` fails open — that's a wiring bug, not an attack,
    /// and limiting everything under one shared key would let any client
    /// starve all others.
    fn check(&self, passport: Option<&str>, client_ip: Option<IpAddr>, now: Instant) -> Result<(), RateLimited> {
        if let Some(ip) = client_ip {
            if self.exempt_cidrs.iter().any(|cidr| cidr_contains(cidr, ip)) {
                return Ok(());
            }
        }
        let (key_kind, key): (&'static str, String) = match (passport, client_ip) {
            (Some(p), _) => ("passport", format!("p:{p}")),
            (None, Some(ip)) => ("ip", format!("ip:{ip}")),
            (None, None) => {
                tracing::debug!("rate limiter saw a request with no passport and no ConnectInfo; failing open");
                return Ok(());
            }
        };

        // SAFETY-ish: a poisoned mutex here means another limiter call
        // panicked mid-update; failing open is the availability-preserving
        // choice for a guardrail.
        let Ok(mut buckets) = self.buckets.lock() else {
            return Ok(());
        };

        // Bound the map under spoofed-source floods: idle buckets are fully
        // refilled anyway, so dropping them is lossless.
        if buckets.len() >= BUCKET_SWEEP_THRESHOLD {
            buckets.retain(|_, b| now.duration_since(b.last_touch).as_secs() < BUCKET_IDLE_SECS);
        }

        let burst = self.burst as f64;
        let bucket = buckets.entry(key).or_insert(RateBucket {
            tokens: burst,
            last_touch: now,
        });
        let elapsed = now.duration_since(bucket.last_touch).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rps as f64).min(burst);
        bucket.last_touch = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(());
        }

        let deficit = 1.0 - bucket.tokens;
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let retry_after_secs = (deficit / self.rps as f64).ceil().max(1.0) as u64;
        drop(buckets);

        if let Some(metrics) = &self.metrics {
            metrics.inc_http_rate_limited(key_kind);
        }
        Err(RateLimited {
            retry_after_secs,
            key_kind,
        })
    }
}

/// Maps IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) back to IPv4 so
/// dual-stack listeners match IPv4 CIDRs.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

/// Parses `addr/prefix` strings; invalid entries are logged and skipped
/// (a typo in the exempt list must not take rate limiting down with it).
fn parse_cidrs(specs: &[String]) -> Vec<(IpAddr, u8)> {
    specs
        .iter()
        .filter_map(|spec| {
            let parsed = parse_cidr(spec);
            if parsed.is_none() {
                tracing::warn!(%spec, "ignoring invalid CIDR in CORECRUXD_RATE_LIMIT_EXEMPT_CIDRS");
            }
            parsed
        })
        .collect()
}

fn parse_cidr(spec: &str) -> Option<(IpAddr, u8)> {
    let spec = spec.trim();
    let (addr, prefix) = match spec.split_once('/') {
        Some((addr, prefix)) => (addr, prefix.parse::<u8>().ok()?),
        None => (spec, u8::MAX), // bare address = host route
    };
    let addr: IpAddr = addr.parse().ok()?;
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    let prefix = if prefix == u8::MAX { max } else { prefix };
    (prefix <= max).then_some((addr, prefix))
}

fn cidr_contains(cidr: &(IpAddr, u8), ip: IpAddr) -> bool {
    let (net, prefix) = *cidr;
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            (u32::from(net) & mask) == (u32::from(ip) & mask)
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            (u128::from(net) & mask) == (u128::from(ip) & mask)
        }
        _ => false,
    }
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
        pd.detail =
            Some("server is at its in-flight request capacity (CORECRUXD_MAX_INFLIGHT); retry shortly".to_string());
        let mut resp = ProblemResponse(pd).into_response();
        resp.headers_mut()
            .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
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
        Router::new().route(
            "/echo",
            post(|body: Bytes| async move { format!("{} bytes", body.len()) }),
        )
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
        let first = tokio::spawn(
            app.clone()
                .oneshot(Request::get("/slow-a").body(Body::empty()).unwrap()),
        );
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

        let parked = tokio::spawn(
            app.clone()
                .oneshot(Request::get("/slow-a").body(Body::empty()).unwrap()),
        );
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

        let first = tokio::spawn(
            app.clone()
                .oneshot(Request::get("/slow-a").body(Body::empty()).unwrap()),
        );
        let second = tokio::spawn(
            app.clone()
                .oneshot(Request::get("/slow-b").body(Body::empty()).unwrap()),
        );
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

        let first = tokio::spawn(
            app.clone()
                .oneshot(Request::get("/slow-a").body(Body::empty()).unwrap()),
        );
        let second = tokio::spawn(
            app.clone()
                .oneshot(Request::get("/slow-b").body(Body::empty()).unwrap()),
        );
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

        let first = tokio::spawn(
            app.clone()
                .oneshot(Request::get("/slow-a").body(Body::empty()).unwrap()),
        );
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

    // ── M3: keyed rate limiting ────────────────────────────────────────

    use std::net::{IpAddr, SocketAddr};
    use std::time::{Duration, Instant};

    use axum::extract::ConnectInfo;

    use super::{normalize_ip, parse_cidr, HttpRateLimiter};

    fn rate_cfg(rps: u64, burst: u64) -> IngressConfig {
        IngressConfig {
            rate_limit_rps: rps,
            rate_limit_burst: burst,
            ..IngressConfig::default()
        }
    }

    /// Builds a request carrying a synthetic peer address, mirroring what
    /// `into_make_service_with_connect_info` injects in `main.rs`.
    fn request_from(addr: &str, passport: Option<&str>) -> Request<Body> {
        let mut builder = Request::post("/echo");
        if let Some(p) = passport {
            builder = builder.header("x-corecrux-passport-id", p);
        }
        let mut req = builder.body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(addr.parse::<SocketAddr>().unwrap()));
        req
    }

    #[tokio::test]
    async fn passport_key_enforced_with_429_retry_after_and_metric() {
        let metrics = test_metrics();
        let app = apply_ingress_limits(test_router(), &rate_cfg(1, 1), Some(&metrics));

        // First request consumes the single-token burst.
        let ok = app
            .clone()
            .oneshot(request_from("203.0.113.7:5000", Some("passport-a")))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);

        // Second request on the same passport is limited.
        let limited = app
            .clone()
            .oneshot(request_from("203.0.113.7:5000", Some("passport-a")))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        let retry_after: u64 = limited
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .expect("429 must carry a numeric Retry-After");
        assert!(retry_after >= 1);
        let json = problem_json(limited).await;
        assert_eq!(json["type"], "https://errors.cuecrux.com/rate-limited");
        assert_eq!(json["status"], 429);

        let rendered = metrics.render().unwrap();
        assert!(
            rendered.contains("corecrux_http_rate_limited_total{key_kind=\"passport\"} 1"),
            "expected passport-keyed rate-limited counter, got: {}",
            rendered
                .lines()
                .filter(|l| l.contains("rate_limited"))
                .collect::<Vec<_>>()
                .join("\n")
        );

        // A different passport from the same IP has its own bucket.
        let other = app
            .clone()
            .oneshot(request_from("203.0.113.7:5000", Some("passport-b")))
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ip_fallback_key_when_no_passport() {
        let metrics = test_metrics();
        let app = apply_ingress_limits(test_router(), &rate_cfg(1, 1), Some(&metrics));

        let ok = app
            .clone()
            .oneshot(request_from("203.0.113.9:6000", None))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);

        let limited = app
            .clone()
            .oneshot(request_from("203.0.113.9:6000", None))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

        let rendered = metrics.render().unwrap();
        assert!(rendered.contains("corecrux_http_rate_limited_total{key_kind=\"ip\"} 1"));

        // A different source IP is an independent bucket.
        let other = app
            .clone()
            .oneshot(request_from("203.0.113.10:6000", None))
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn loopback_is_exempt_by_default_even_with_passport() {
        let app = apply_ingress_limits(test_router(), &rate_cfg(1, 1), None);
        for _ in 0..20 {
            let resp = app
                .clone()
                .oneshot(request_from("127.0.0.1:9000", Some("console-passport")))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "loopback must never be limited");
        }
    }

    #[tokio::test]
    async fn zero_rps_disables_rate_limiting() {
        let app = apply_ingress_limits(test_router(), &rate_cfg(0, 0), None);
        for _ in 0..20 {
            let resp = app
                .clone()
                .oneshot(request_from("203.0.113.20:7000", Some("p")))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[test]
    fn bucket_refills_at_rps_deterministically() {
        let limiter = HttpRateLimiter::new(
            &IngressConfig {
                rate_limit_rps: 2,
                rate_limit_burst: 2,
                rate_limit_exempt_cidrs: vec![],
                ..IngressConfig::default()
            },
            None,
        );
        let t0 = Instant::now();
        let ip: Option<IpAddr> = Some("203.0.113.1".parse().unwrap());

        // Burst of 2 admitted, third denied.
        assert!(limiter.check(Some("p"), ip, t0).is_ok());
        assert!(limiter.check(Some("p"), ip, t0).is_ok());
        let denied = limiter.check(Some("p"), ip, t0).unwrap_err();
        assert_eq!(denied.key_kind, "passport");
        assert!(denied.retry_after_secs >= 1);

        // After 1s at 2 rps, two tokens refill.
        let t1 = t0 + Duration::from_secs(1);
        assert!(limiter.check(Some("p"), ip, t1).is_ok());
        assert!(limiter.check(Some("p"), ip, t1).is_ok());
        assert!(limiter.check(Some("p"), ip, t1).is_err());
    }

    #[test]
    fn missing_passport_and_connect_info_fails_open() {
        let limiter = HttpRateLimiter::new(&rate_cfg(1, 1), None);
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(limiter.check(None, None, t0).is_ok());
        }
    }

    #[test]
    fn cidr_parsing_and_matching() {
        // Bare address = host route.
        let host = parse_cidr("203.0.113.5").unwrap();
        assert!(super::cidr_contains(&host, "203.0.113.5".parse().unwrap()));
        assert!(!super::cidr_contains(&host, "203.0.113.6".parse().unwrap()));

        let net = parse_cidr("10.0.0.0/8").unwrap();
        assert!(super::cidr_contains(&net, "10.255.1.2".parse().unwrap()));
        assert!(!super::cidr_contains(&net, "11.0.0.1".parse().unwrap()));

        let v6 = parse_cidr("::1/128").unwrap();
        assert!(super::cidr_contains(&v6, "::1".parse().unwrap()));
        assert!(!super::cidr_contains(&v6, "::2".parse().unwrap()));

        // Invalid specs are rejected, not panicking.
        assert!(parse_cidr("not-an-ip").is_none());
        assert!(parse_cidr("10.0.0.0/33").is_none());
        assert!(parse_cidr("").is_none());
    }

    #[test]
    fn ipv4_mapped_ipv6_normalizes_to_v4_for_exemption() {
        // Dual-stack listeners report loopback as ::ffff:127.0.0.1.
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert_eq!(normalize_ip(mapped), "127.0.0.1".parse::<IpAddr>().unwrap());

        let limiter = HttpRateLimiter::new(&rate_cfg(1, 1), None);
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(limiter.check(None, Some(normalize_ip(mapped)), t0).is_ok());
        }
    }
}
