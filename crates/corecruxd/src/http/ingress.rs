// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Ingress hardening layers for the HTTP planes (`:14800` API, `:14801` MCP).
//!
//! ExecPlan `crux-http-ingress-hardening-2026-06-11`:
//! - M1: request-body size limit with RFC-7807 `413` responses.
//! - M2: in-flight concurrency cap + load shed (`503` problem+json) and the
//!   `corecrux_http_inflight` gauge.
//! - M3: client-IP keyed rate limiting with `429` + `Retry-After`, loopback
//!   exempt by default, trusted-proxy forwarded-header handling, and the
//!   `corecrux_http_rate_limited_total{key_kind}` counter.
//!
//! Applied in `main.rs` to both the daemon API router and the MCP router so
//! route-level tests exercise the un-hardened router unchanged.
//!
//! Layer ordering note: `Router::layer` wraps outside-in as calls accumulate,
//! so layers added *later* run *earlier* on the request path. Final order:
//! passport-header validator → rate limiter → load-shed/concurrency gate →
//! inflight gauge → 413 decorator → body limit → routes. A flood is 429'd
//! before it can occupy an inflight slot, and shedding happens before any body
//! byte is read; the gauge counts only admitted requests.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::error_handling::HandleErrorLayer;
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use corecrux_types::ProblemDetails;
use tower::ServiceBuilder;

use crate::config::IngressConfig;
use crate::metrics::Metrics;
use crate::problem::ProblemResponse;

/// Passport header validated at ingress before route-level auth binds it.
const PASSPORT_HEADER: &str = "x-corecrux-passport-id";
const X_FORWARDED_FOR_HEADER: &str = "x-forwarded-for";
const FORWARDED_HEADER: &str = "forwarded";
const PASSPORT_HEADER_MAX_LEN: usize = 128;
/// Bucket-map size that triggers an inline idle-entry sweep — bounds memory
/// under spoofed-source floods.
const BUCKET_SWEEP_THRESHOLD: usize = 10_000;
/// Idle horizon for the sweep: an idle bucket is fully refilled anyway, so
/// dropping it loses nothing.
const BUCKET_IDLE_SECS: u64 = 60;
const LARGE_ROUTE_BODY_LIMIT_BYTES: usize = 64 * 1024 * 1024;
const LARGE_BODY_ROUTES: &[&str] = &[
    "/v1/append",
    "/v1/admin/append",
    "/v1/memory/import",
    "/v1/result-envelope/import",
];

/// Applies the ingress limits to a fully-built router.
///
/// Each mechanism is independently disabled by its `0` env value
/// (emergency-rollback path: limits can be turned off without a redeploy).
/// `metrics: None` (route-level tests) skips the inflight gauge.
pub fn apply_ingress_limits(router: Router, cfg: &IngressConfig, metrics: Option<&Metrics>) -> Router {
    let mut router = router;

    // M1 — request body limit + problem+json 413s.
    if cfg.max_request_body_bytes > 0 {
        let default_limit = cfg.max_request_body_bytes;
        router = router.layer(axum::middleware::from_fn(
            move |req: axum::extract::Request, next: axum::middleware::Next| async move {
                let limit = request_body_limit_for_path(req.uri().path(), default_limit);
                if content_length_exceeds(req.headers(), limit) {
                    return payload_too_large_response(limit);
                }
                let (parts, body) = req.into_parts();
                let limited = http_body_util::Limited::new(body, limit);
                let req = Request::from_parts(parts, axum::body::Body::new(limited));
                decorate_payload_too_large(next.run(req).await, limit)
            },
        ));
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

    // M3 — keyed rate limiting: a flood is rejected before it
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

    // Validate caller-supplied passport shape at ingress regardless of
    // whether rate limiting is enabled; route-level auth still proves
    // ownership before handlers trust the value.
    router = router.layer(axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| async move {
            match validate_passport_header(req.headers()) {
                Ok(()) => next.run(req).await,
                Err(problem) => problem.into_response(),
            }
        },
    ));

    router
}

/// Keyed token-bucket rate limiter for the HTTP planes.
///
/// Keying: per effective client IP. `X-Corecrux-Passport-Id` is only validated
/// here; route-level auth must prove passport ownership before any handler
/// trusts it. Direct client IPs inside an exempt CIDR (loopback by default —
/// console SPA + local agents) bypass limiting entirely unless untrusted
/// forwarded headers are present.
///
/// Deliberately in-crate rather than the `governor` crate: the daemon
/// already ships a proven token-bucket (per-tenant gRPC throttle,
/// `grpc.rs`), and supply-chain policy files (`deny.toml`) are owned by a
/// concurrent workstream — no new dependency for ~100 lines of arithmetic.
pub struct HttpRateLimiter {
    rps: u64,
    burst: u64,
    exempt_cidrs: Vec<(IpAddr, u8)>,
    trusted_proxy_cidrs: Vec<(IpAddr, u8)>,
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

#[derive(Debug, PartialEq, Eq)]
struct InvalidPassportHeader;

impl IntoResponse for InvalidPassportHeader {
    fn into_response(self) -> Response {
        let mut pd = ProblemDetails::new(
            StatusCode::BAD_REQUEST.as_u16(),
            "https://errors.cuecrux.com/invalid-passport-header",
            "Invalid X-Corecrux-Passport-Id",
        );
        pd.detail = Some(format!(
            "X-Corecrux-Passport-Id must be 1..={PASSPORT_HEADER_MAX_LEN} ASCII chars from [A-Za-z0-9._:-]"
        ));
        ProblemResponse(pd).into_response()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ClientIpDecision {
    pub(crate) key_ip: Option<IpAddr>,
    pub(crate) exempt_ip: Option<IpAddr>,
}

impl HttpRateLimiter {
    pub fn new(cfg: &IngressConfig, metrics: Option<Metrics>) -> Self {
        Self {
            rps: cfg.rate_limit_rps,
            burst: cfg.rate_limit_burst.max(cfg.rate_limit_rps).max(1),
            exempt_cidrs: parse_cidrs(&cfg.rate_limit_exempt_cidrs),
            trusted_proxy_cidrs: parse_cidrs_with_label(&cfg.trusted_proxy_cidrs, "CORECRUXD_TRUSTED_PROXY_CIDRS"),
            buckets: Mutex::new(HashMap::new()),
            metrics,
        }
    }

    /// Derives the key from the request and consumes one token.
    fn check_request(&self, req: &axum::extract::Request) -> Result<(), RateLimited> {
        let client_ip = req
            .extensions()
            .get::<ConnectInfo<std::net::SocketAddr>>()
            .map(|ci| normalize_ip(ci.0.ip()));
        let decision = self.client_ip_decision(req.headers(), client_ip);
        self.check(decision.key_ip, decision.exempt_ip, Instant::now())
    }

    /// Core decision, separated for deterministic tests. Exemption is applied
    /// only to the effective client IP. A request with no `ConnectInfo` fails
    /// open — that's a wiring bug, not an attack,
    /// and limiting everything under one shared key would let any client
    /// starve all others.
    fn check(&self, key_ip: Option<IpAddr>, exempt_ip: Option<IpAddr>, now: Instant) -> Result<(), RateLimited> {
        if let Some(ip) = exempt_ip {
            if self.exempt_cidrs.iter().any(|cidr| cidr_contains(cidr, ip)) {
                return Ok(());
            }
        }
        let (key_kind, key): (&'static str, String) = match key_ip {
            Some(ip) => ("ip", format!("ip:{ip}")),
            None => {
                tracing::debug!("rate limiter saw a request with no ConnectInfo; failing open");
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

    fn client_ip_decision(&self, headers: &HeaderMap, peer_ip: Option<IpAddr>) -> ClientIpDecision {
        client_ip_decision_with_parsed(headers, peer_ip, &self.trusted_proxy_cidrs)
    }
}

/// Resolve the same effective client IP and trust posture used by the global
/// rate limiter. Forwarded chains are walked from the trusted socket peer
/// toward the client, stopping at the first untrusted hop.
pub(crate) fn parse_trusted_proxy_cidrs(values: &[String]) -> Vec<(IpAddr, u8)> {
    parse_cidrs_with_label(values, "CORECRUXD_TRUSTED_PROXY_CIDRS")
}

pub(crate) fn effective_client_ip(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_proxy_cidrs: &[(IpAddr, u8)],
) -> ClientIpDecision {
    client_ip_decision_with_parsed(headers, peer_ip.map(normalize_ip), trusted_proxy_cidrs)
}

/// Anonymous bootstrap is intentionally narrower than forwarded-IP trust:
/// only a direct loopback socket with no forwarding assertion is local.
/// Reverse-proxied callers must authenticate even when the proxy is trusted.
pub(crate) fn is_direct_loopback_request(headers: &HeaderMap, peer_ip: Option<IpAddr>) -> bool {
    !has_forwarded_headers(headers) && peer_ip.map(normalize_ip).is_some_and(|ip| ip.is_loopback())
}

fn client_ip_decision_with_parsed(
    headers: &HeaderMap,
    peer_ip: Option<IpAddr>,
    trusted_proxy_cidrs: &[(IpAddr, u8)],
) -> ClientIpDecision {
    let Some(peer_ip) = peer_ip else {
        return ClientIpDecision {
            key_ip: None,
            exempt_ip: None,
        };
    };
    let peer_is_trusted_proxy = trusted_proxy_cidrs.iter().any(|cidr| cidr_contains(cidr, peer_ip));
    let forwarded_present = has_forwarded_headers(headers);

    if peer_is_trusted_proxy {
        if let Some(client_ip) = forwarded_client_ip(headers, peer_ip, trusted_proxy_cidrs) {
            return ClientIpDecision {
                key_ip: Some(client_ip),
                exempt_ip: Some(client_ip),
            };
        }
        return ClientIpDecision {
            key_ip: Some(peer_ip),
            // A configured proxy with absent/malformed forwarded headers is
            // bucketed by proxy IP, but the proxy IP itself is not exempted.
            exempt_ip: None,
        };
    }

    ClientIpDecision {
        key_ip: Some(peer_ip),
        // Forwarded headers from untrusted peers are ignored and also
        // suppress loopback/private exemptions. A same-host reverse proxy
        // that is not in CORECRUXD_TRUSTED_PROXY_CIDRS gets one shared
        // bucket instead of an unlimited loopback bypass.
        exempt_ip: (!forwarded_present).then_some(peer_ip),
    }
}

fn validate_passport_header(headers: &HeaderMap) -> Result<(), InvalidPassportHeader> {
    for value in headers.get_all(PASSPORT_HEADER) {
        let raw = value.to_str().map_err(|_| InvalidPassportHeader)?;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > PASSPORT_HEADER_MAX_LEN || !trimmed.bytes().all(is_safe_passport_byte)
        {
            return Err(InvalidPassportHeader);
        }
    }
    Ok(())
}

fn is_safe_passport_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
}

fn has_forwarded_headers(headers: &HeaderMap) -> bool {
    headers.contains_key(FORWARDED_HEADER) || headers.contains_key(X_FORWARDED_FOR_HEADER)
}

fn forwarded_client_ip(headers: &HeaderMap, peer_ip: IpAddr, trusted_proxy_cidrs: &[(IpAddr, u8)]) -> Option<IpAddr> {
    let chain = forwarded_ip_chain(headers)?;
    let mut current = peer_ip;
    let mut advanced = false;
    for candidate in chain.into_iter().rev() {
        if !trusted_proxy_cidrs.iter().any(|cidr| cidr_contains(cidr, current)) {
            break;
        }
        current = candidate;
        advanced = true;
    }
    advanced.then_some(normalize_ip(current))
}

fn forwarded_ip_chain(headers: &HeaderMap) -> Option<Vec<IpAddr>> {
    let has_forwarded = headers.contains_key(FORWARDED_HEADER);
    let has_x_forwarded_for = headers.contains_key(X_FORWARDED_FOR_HEADER);
    // Two independently generated chains are ambiguous. Fail closed to the
    // socket-peer bucket rather than choosing the more favorable assertion.
    if has_forwarded == has_x_forwarded_for {
        return None;
    }

    let mut chain = Vec::new();
    if has_forwarded {
        for value in headers.get_all(FORWARDED_HEADER) {
            chain.extend(parse_forwarded_header_chain(value.to_str().ok()?)?);
        }
    } else {
        for value in headers.get_all(X_FORWARDED_FOR_HEADER) {
            chain.extend(parse_x_forwarded_for_chain(value.to_str().ok()?)?);
        }
    }
    (!chain.is_empty()).then_some(chain)
}

fn parse_forwarded_header_chain(value: &str) -> Option<Vec<IpAddr>> {
    let mut chain = Vec::new();
    for element in value.split(',') {
        let mut element_ip = None;
        for part in element.split(';') {
            let Some((name, value)) = part.trim().split_once('=') else {
                continue;
            };
            if name.trim().eq_ignore_ascii_case("for") {
                if element_ip.is_some() {
                    return None;
                }
                element_ip = Some(parse_forwarded_ip(value.trim())?);
            }
        }
        chain.push(element_ip?);
    }
    Some(chain)
}

#[cfg(test)]
fn parse_forwarded_header(value: &str) -> Option<IpAddr> {
    parse_forwarded_header_chain(value)?.into_iter().next()
}

#[cfg(test)]
fn parse_x_forwarded_for(value: &str) -> Option<IpAddr> {
    parse_x_forwarded_for_chain(value)?.into_iter().next()
}

fn parse_x_forwarded_for_chain(value: &str) -> Option<Vec<IpAddr>> {
    value.split(',').map(|part| parse_forwarded_ip(part.trim())).collect()
}

fn parse_forwarded_ip(raw: &str) -> Option<IpAddr> {
    let raw = raw.trim().trim_matches('"');
    if raw.is_empty() || raw.eq_ignore_ascii_case("unknown") {
        return None;
    }
    if let Ok(ip) = raw.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some(rest) = raw.strip_prefix('[') {
        let (inside, _) = rest.split_once(']')?;
        return inside.parse::<IpAddr>().ok();
    }
    let colon_count = raw.bytes().filter(|b| *b == b':').count();
    if colon_count == 1 {
        let (host, _) = raw.rsplit_once(':')?;
        return host.parse::<IpAddr>().ok();
    }
    None
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
    parse_cidrs_with_label(specs, "CORECRUXD_RATE_LIMIT_EXEMPT_CIDRS")
}

fn parse_cidrs_with_label(specs: &[String], env_name: &'static str) -> Vec<(IpAddr, u8)> {
    specs
        .iter()
        .filter_map(|spec| {
            let parsed = parse_cidr(spec);
            if parsed.is_none() {
                tracing::warn!(%spec, env_name, "ignoring invalid CIDR in ingress config");
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
    payload_too_large_response(limit)
}

fn payload_too_large_response(limit: usize) -> Response {
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

fn request_body_limit_for_path(path: &str, default_limit: usize) -> usize {
    if LARGE_BODY_ROUTES.contains(&path) {
        default_limit.max(LARGE_ROUTE_BODY_LIMIT_BYTES)
    } else {
        default_limit
    }
}

fn content_length_exceeds(headers: &HeaderMap, limit: usize) -> bool {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|len| len > limit)
}

#[cfg(test)]
mod tests {
    use axum::body::{to_bytes, Body, Bytes};
    use axum::http::{HeaderMap, HeaderValue, Request, StatusCode};
    use axum::routing::post;
    use axum::Router;
    use tower::util::ServiceExt as _;

    use super::apply_ingress_limits;
    use crate::config::IngressConfig;

    fn test_router() -> Router {
        let echo = post(|body: Bytes| async move { format!("{} bytes", body.len()) });
        Router::new()
            .route("/echo", echo.clone())
            .route("/v1/admin/append", echo.clone())
            .route("/v1/admin/actions", echo)
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
    async fn route_specific_body_limits() {
        let app = apply_ingress_limits(test_router(), &cfg(1024), None);
        let resp = app
            .oneshot(
                Request::post("/v1/admin/append")
                    .header("content-length", "2048")
                    .body(Body::from(vec![0u8; 2048]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"2048 bytes");
    }

    #[tokio::test]
    async fn admin_routes_reject_large_bodies() {
        let app = apply_ingress_limits(test_router(), &cfg(1024), None);
        let resp = app
            .oneshot(
                Request::post("/v1/admin/actions")
                    .header("content-length", "2048")
                    .body(Body::from(vec![0u8; 2048]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let json = problem_json(resp).await;
        assert!(json["detail"].as_str().unwrap().contains("1024"));
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

    use super::{
        effective_client_ip, normalize_ip, parse_cidr, parse_forwarded_header, parse_forwarded_ip,
        parse_x_forwarded_for, HttpRateLimiter,
    };

    fn rate_cfg(rps: u64, burst: u64) -> IngressConfig {
        IngressConfig {
            rate_limit_rps: rps,
            rate_limit_burst: burst,
            ..IngressConfig::default()
        }
    }

    fn rate_cfg_with_trusted_proxy(rps: u64, burst: u64, trusted_proxy_cidrs: Vec<String>) -> IngressConfig {
        IngressConfig {
            rate_limit_rps: rps,
            rate_limit_burst: burst,
            trusted_proxy_cidrs,
            ..IngressConfig::default()
        }
    }

    /// Builds a request carrying a synthetic peer address, mirroring what
    /// `into_make_service_with_connect_info` injects in `main.rs`.
    fn request_from(addr: &str, passport: Option<&str>) -> Request<Body> {
        request_from_with_headers(addr, passport, &[])
    }

    fn request_from_with_headers(addr: &str, passport: Option<&str>, headers: &[(&str, &str)]) -> Request<Body> {
        let mut builder = Request::post("/echo");
        if let Some(p) = passport {
            builder = builder.header("x-corecrux-passport-id", p);
        }
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let mut req = builder.body(Body::empty()).unwrap();
        req.extensions_mut()
            .insert(ConnectInfo(addr.parse::<SocketAddr>().unwrap()));
        req
    }

    #[tokio::test]
    async fn unauthenticated_rotating_passports_rate_limit_by_ip() {
        let metrics = test_metrics();
        let app = apply_ingress_limits(test_router(), &rate_cfg(1, 1), Some(&metrics));

        // First request consumes the single-token burst.
        let ok = app
            .clone()
            .oneshot(request_from("203.0.113.7:5000", Some("passport-a")))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);

        // Rotating unauthenticated passport IDs from the same IP still hits
        // the IP bucket.
        let limited = app
            .clone()
            .oneshot(request_from("203.0.113.7:5000", Some("passport-b")))
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
            rendered.contains("corecrux_http_rate_limited_total{key_kind=\"ip\"} 1"),
            "expected ip-keyed rate-limited counter, got: {}",
            rendered
                .lines()
                .filter(|l| l.contains("rate_limited"))
                .collect::<Vec<_>>()
                .join("\n")
        );

        // A different source IP has its own bucket.
        let other = app
            .clone()
            .oneshot(request_from("203.0.113.8:5000", Some("passport-c")))
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn passport_header_rejects_unsafe_values() {
        let app = apply_ingress_limits(test_router(), &rate_cfg(1, 1), None);
        let resp = app
            .oneshot(request_from("203.0.113.7:5000", Some("bad/passport")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn passport_header_rejected_when_rate_limiting_disabled() {
        let app = apply_ingress_limits(test_router(), &rate_cfg(0, 0), None);
        let resp = app
            .oneshot(request_from("203.0.113.7:5000", Some("bad/passport")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
    async fn trusted_proxy_rate_limit_keying() {
        let metrics = test_metrics();
        let cfg = rate_cfg_with_trusted_proxy(1, 1, vec!["127.0.0.1/32".to_string()]);
        let app = apply_ingress_limits(test_router(), &cfg, Some(&metrics));

        let ok = app
            .clone()
            .oneshot(request_from_with_headers(
                "127.0.0.1:9000",
                None,
                &[("x-forwarded-for", "203.0.113.30")],
            ))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);

        let limited = app
            .clone()
            .oneshot(request_from_with_headers(
                "127.0.0.1:9000",
                None,
                &[("x-forwarded-for", "203.0.113.30")],
            ))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

        let other = app
            .clone()
            .oneshot(request_from_with_headers(
                "127.0.0.1:9000",
                None,
                &[("x-forwarded-for", "203.0.113.31")],
            ))
            .await
            .unwrap();
        assert_eq!(other.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn untrusted_forwarded_for_is_ignored() {
        let app = apply_ingress_limits(test_router(), &rate_cfg(1, 1), None);

        let ok = app
            .clone()
            .oneshot(request_from_with_headers(
                "198.51.100.9:9000",
                None,
                &[("x-forwarded-for", "203.0.113.40")],
            ))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);

        let limited = app
            .clone()
            .oneshot(request_from_with_headers(
                "198.51.100.9:9000",
                None,
                &[("x-forwarded-for", "203.0.113.41")],
            ))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn untrusted_loopback_forwarded_for_is_not_exempt() {
        let app = apply_ingress_limits(test_router(), &rate_cfg(1, 1), None);

        let ok = app
            .clone()
            .oneshot(request_from_with_headers(
                "127.0.0.1:9000",
                None,
                &[("x-forwarded-for", "203.0.113.50")],
            ))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::OK);

        let limited = app
            .clone()
            .oneshot(request_from_with_headers(
                "127.0.0.1:9000",
                None,
                &[("x-forwarded-for", "203.0.113.51")],
            ))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
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
        assert!(limiter.check(ip, ip, t0).is_ok());
        assert!(limiter.check(ip, ip, t0).is_ok());
        let denied = limiter.check(ip, ip, t0).unwrap_err();
        assert_eq!(denied.key_kind, "ip");
        assert!(denied.retry_after_secs >= 1);

        // After 1s at 2 rps, two tokens refill.
        let t1 = t0 + Duration::from_secs(1);
        assert!(limiter.check(ip, ip, t1).is_ok());
        assert!(limiter.check(ip, ip, t1).is_ok());
        assert!(limiter.check(ip, ip, t1).is_err());
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
            let ip = Some(normalize_ip(mapped));
            assert!(limiter.check(ip, ip, t0).is_ok());
        }
    }

    #[test]
    fn forwarded_header_parsing() {
        assert_eq!(
            parse_forwarded_header(r"for=203.0.113.60;proto=https;by=127.0.0.1"),
            Some("203.0.113.60".parse().unwrap())
        );
        assert_eq!(
            parse_forwarded_header(r#"for="[2001:db8::1]:443";proto=https"#),
            Some("2001:db8::1".parse().unwrap())
        );
        assert_eq!(parse_forwarded_header("for=unknown"), None);
        assert_eq!(
            parse_x_forwarded_for("203.0.113.70, 198.51.100.1"),
            Some("203.0.113.70".parse().unwrap())
        );
        assert_eq!(
            parse_forwarded_ip("203.0.113.71:1234"),
            Some("203.0.113.71".parse().unwrap())
        );
    }

    #[test]
    fn trusted_proxy_walks_forwarded_chains_right_to_left() {
        let trusted = vec![parse_cidr("127.0.0.1/32").unwrap()];
        let peer = Some("127.0.0.1".parse().unwrap());
        let expected = Some("203.0.113.44".parse().unwrap());

        for (name, value) in [
            ("x-forwarded-for", "127.0.0.1, 203.0.113.44"),
            ("forwarded", "for=127.0.0.1, for=203.0.113.44"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
            let decision = effective_client_ip(&headers, peer, &trusted);
            assert_eq!(decision.key_ip, expected, "{name}");
            assert_eq!(decision.exempt_ip, expected, "{name}");
        }
    }
}
