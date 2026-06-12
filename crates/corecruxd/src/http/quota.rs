// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! G20 daemon wiring — `GET /v1/quota` + per-surface request-quota
//! middleware over [`crux_router::quota::QuotaLedger`].
//!
//! ExecPlan `context-mediation-injection-2026-06-11`, deferred-by-claim
//! follow-up (plan §GATE PACKAGE item 2). Normative spec:
//! `Quota-Rate-Limit-Spec.md` (planning monorepo, shared plane) — this
//! module is gate 3 of the unified ladder (capability → credit → bucket).
//!
//! Free-tier posture (normative, enforced in the type system by
//! `SurfaceClass::LocalCompute`): **local compute is never rate-limited** —
//! it is the user's CPU. A request is classified `Hosted` only when its
//! path matches one of the operator-configured hosted-surface prefixes
//! (`CORECRUXD_QUOTA_HOSTED_SURFACES`, comma-separated). With the default
//! empty list every surface is local compute, so even with the flag ON a
//! free local daemon stays unlimited — the bucket only ever engages on
//! deployments that declare hosted surfaces.
//!
//! Backpressure: `429` + `Retry-After` + `X-Crux-Quota-*` headers
//! (emitted by [`crux_router::quota::QuotaDecision::headers`]); quota
//! state is queryable via `GET /v1/quota`.
//!
//! Gating: `CORECRUXD_QUOTA=1`, default OFF. When off the middleware is a
//! pass-through and the route returns 404 (surface invisible rather than
//! half-alive — same convention as the coord plane).

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use crux_router::quota::SurfaceClass;
use serde_json::json;

use super::{problem_response, AppState, HeaderMap, Request};

/// Bucket identity for callers that present no passport header. Anonymous
/// callers share one bucket per surface — deliberately: an unidentified
/// runaway loop is exactly what the daemon-protection bucket is for.
const ANONYMOUS_PASSPORT: &str = "anonymous";

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn caller_passport(headers: &HeaderMap) -> String {
    crate::auth::http_passport_id(headers).unwrap_or_else(|| ANONYMOUS_PASSPORT.to_string())
}

/// Classify a request path against the configured hosted-surface prefixes.
/// Returns the matched prefix (the surface name) for hosted requests,
/// `None` for local compute.
fn hosted_surface_for(path: &str, prefixes: &[String]) -> Option<String> {
    prefixes.iter().find(|p| !p.is_empty() && path.starts_with(p.as_str())).cloned()
}

/// Per-surface request-quota middleware (gate 3). Pass-through when
/// `CORECRUXD_QUOTA` is off; `LocalCompute` requests are admitted with no
/// accounting; hosted requests draw one token and carry the quota headers
/// on the response, or are refused with `429` + `Retry-After`.
pub(super) async fn quota_middleware(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if !state.quota_enabled {
        return next.run(req).await;
    }
    let path = req.uri().path();
    let Some(surface) = hosted_surface_for(path, &state.quota_hosted_surfaces) else {
        // LocalCompute: never rate-limited (normative). No bucket state is
        // created, no headers are emitted.
        return next.run(req).await;
    };
    let passport = caller_passport(req.headers());
    let decision = {
        let mut ledger = state.quota_ledger.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        ledger.check(&passport, &surface, SurfaceClass::Hosted, now_secs())
    };
    let header_pairs = decision.headers();
    if decision.is_allowed() {
        let mut response = next.run(req).await;
        for (name, value) in header_pairs {
            if let Ok(v) = value.parse() {
                response.headers_mut().insert(name, v);
            }
        }
        response
    } else {
        // 429 never spends credit (the bucket sits before any metered
        // execution) and never reaches the inner handler.
        let mut response = problem_response(
            StatusCode::TOO_MANY_REQUESTS,
            format!("request quota exceeded on surface '{surface}'"),
        );
        for (name, value) in header_pairs {
            if let Ok(v) = value.parse() {
                response.headers_mut().insert(name, v);
            }
        }
        response
    }
}

/// `GET /v1/quota` — the caller's per-surface quota state. Surfaces the
/// caller has never touched report a full bucket; local compute is reported
/// as unlimited (no entries — there is nothing to back off from).
#[utoipa::path(
    get,
    path = "/v1/quota",
    tag = "Quota",
    responses(
        (status = 200, description = "Per-surface quota state for the calling passport"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Surface disabled (CORECRUXD_QUOTA unset)"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn get_quota(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !state.quota_enabled {
        return problem_response(
            StatusCode::NOT_FOUND,
            "quota surface disabled (set CORECRUXD_QUOTA=1)".to_string(),
        );
    }
    // Read-only diagnostics, but still behind the existing auth model
    // (401 unauthenticated — a new surface must never be an open read).
    let ctx = match super::facts::require_fact_read_ctx(&state, &headers) {
        Ok(ctx) => ctx,
        Err(resp) => return resp,
    };
    let passport = ctx.passport_id.clone().unwrap_or_else(|| caller_passport(&headers));
    let snapshot = {
        let mut ledger = state.quota_ledger.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        ledger.snapshot(&passport, now_secs())
    };
    let surfaces: Vec<serde_json::Value> = snapshot
        .iter()
        .map(|e| {
            json!({
                "surface": e.surface,
                "limit": e.limit,
                "remaining": e.remaining,
                "refill_per_minute": e.refill_per_minute,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(json!({
            "passport": passport,
            // Normative (spec + QuotaLedger type system): local compute is
            // never rate-limited on the free tier.
            "local_compute": "unlimited",
            "hosted_surfaces": *state.quota_hosted_surfaces,
            "surfaces": surfaces,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::tests::test_app_state;
    use axum::body::{to_bytes, Body};
    use axum::http::Request as HttpRequest;
    use crux_router::quota::QuotaPolicy;
    use tower::ServiceExt as _;

    fn quota_state(hosted: &[&str]) -> AppState {
        let mut state = test_app_state(1);
        state.quota_enabled = true;
        state.quota_hosted_surfaces = std::sync::Arc::new(hosted.iter().map(|s| (*s).to_string()).collect());
        state
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.expect("read body");
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    #[tokio::test]
    async fn get_quota_404_when_flag_off() {
        let mut state = test_app_state(1);
        state.quota_enabled = false;
        let resp = get_quota(State(state), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_quota_reports_per_surface_state() {
        let state = quota_state(&["/v1/hosted-offload"]);
        {
            let mut ledger = state.quota_ledger.lock().expect("lock");
            ledger.set_policy(
                "/v1/hosted-offload",
                QuotaPolicy {
                    capacity: 5,
                    refill_per_minute: 60,
                },
            );
        }
        let resp = get_quota(State(state), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["local_compute"], "unlimited");
        assert_eq!(body["surfaces"][0]["surface"], "/v1/hosted-offload");
        assert_eq!(body["surfaces"][0]["limit"], 5);
        assert_eq!(body["surfaces"][0]["remaining"], 5, "untouched surface reports a full bucket");
    }

    /// Drive the real router so the middleware layer is exercised
    /// end-to-end. `/healthz` stands in for an arbitrary surface: it is
    /// classified hosted only when configured as such.
    async fn router_status(state: &AppState, path: &str) -> (StatusCode, HeaderMap) {
        let app = crate::http::router(state.clone());
        let resp = app
            .oneshot(HttpRequest::get(path).body(Body::empty()).expect("request"))
            .await
            .expect("infallible");
        (resp.status(), resp.headers().clone())
    }

    #[tokio::test]
    async fn middleware_is_inert_when_flag_off() {
        let mut state = test_app_state(1);
        state.quota_enabled = false;
        state.quota_hosted_surfaces = std::sync::Arc::new(vec!["/healthz".to_string()]);
        for _ in 0..5 {
            let (status, headers) = router_status(&state, "/healthz").await;
            assert_eq!(status, StatusCode::OK);
            assert!(headers.get("X-Crux-Quota-Limit").is_none(), "flag off emits no quota headers");
        }
    }

    #[tokio::test]
    async fn local_compute_surfaces_are_unlimited_even_with_flag_on() {
        // Flag ON, but /healthz is not declared hosted → LocalCompute →
        // never limited, no headers, no bucket state.
        let state = quota_state(&["/v1/hosted-offload"]);
        for _ in 0..50 {
            let (status, headers) = router_status(&state, "/healthz").await;
            assert_eq!(status, StatusCode::OK);
            assert!(headers.get("X-Crux-Quota-Limit").is_none());
        }
    }

    #[tokio::test]
    async fn hosted_surface_drains_to_429_with_retry_after() {
        let state = quota_state(&["/healthz"]);
        {
            let mut ledger = state.quota_ledger.lock().expect("lock");
            ledger.set_policy(
                "/healthz",
                QuotaPolicy {
                    capacity: 2,
                    refill_per_minute: 1,
                },
            );
        }
        let (status, headers) = router_status(&state, "/healthz").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get("X-Crux-Quota-Limit").and_then(|v| v.to_str().ok()), Some("2"));
        assert_eq!(headers.get("X-Crux-Quota-Remaining").and_then(|v| v.to_str().ok()), Some("1"));

        let (status, _) = router_status(&state, "/healthz").await;
        assert_eq!(status, StatusCode::OK);

        let (status, headers) = router_status(&state, "/healthz").await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(headers.get("X-Crux-Quota-Remaining").and_then(|v| v.to_str().ok()), Some("0"));
        assert!(
            headers.get("Retry-After").is_some(),
            "429 must carry Retry-After (spec backpressure contract)"
        );
    }

    #[tokio::test]
    async fn buckets_are_per_passport() {
        let state = quota_state(&["/healthz"]);
        {
            let mut ledger = state.quota_ledger.lock().expect("lock");
            ledger.set_policy(
                "/healthz",
                QuotaPolicy {
                    capacity: 1,
                    refill_per_minute: 1,
                },
            );
        }
        let app = crate::http::router(state.clone());
        let send = |passport: &'static str| {
            let app = app.clone();
            async move {
                app.oneshot(
                    HttpRequest::get("/healthz")
                        .header("x-corecrux-passport-id", passport)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("infallible")
                .status()
            }
        };
        assert_eq!(send("alpha").await, StatusCode::OK);
        assert_eq!(send("alpha").await, StatusCode::TOO_MANY_REQUESTS);
        // A different passport has its own bucket.
        assert_eq!(send("beta").await, StatusCode::OK);
    }
}
