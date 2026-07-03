// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Engine mediation group — read-only, customer-safe (`/v1/console/engine/*`).
//!
//! The unified-shell console never talks to CruxEngine directly. Three GET
//! routes let the daemon fetch a small, curated set of Engine summaries on the
//! browser's behalf, so the Engine's base URL and API key stay in daemon env
//! only (never in the bundle) and the browser only ever addresses this origin.
//! Mounting **only** `get(...)` for each path means axum answers 405 for any
//! POST/PUT/DELETE — there is no mutating Engine route to call.
//!
//! ## Upstream ground truth (`CruxEngine/apps/api/openapi.json`)
//!
//! | local route                     | upstream GET                    | why |
//! |---------------------------------|---------------------------------|-----|
//! | `/v1/console/engine/summary`    | `/healthz`                      | liveness probe (no security); we add engine reachability + latency ms |
//! | `/v1/console/engine/bench`      | `/v1/benchmarks/manifest`       | the GET under `/v1/benchmarks` — "List public benchmark sets" |
//! | `/v1/console/engine/spend`      | `/v1/economy/escrow-holds`      | see economy-GET selection below |
//!
//! Economy/credits read GETs that exist upstream: `/v1/economy/pricing`
//! (pricing catalogue — not spend), `/v1/economy/escrow-holds` (active CRUX
//! escrow holds for the tenant — committed spend, parameter-free),
//! `/v1/economy/dashboard/{agentId}` and `/v1/credits/{agentId}` (the richest
//! spend/credits summaries, but both require an `agentId` path param the fixed
//! proxy route cannot supply). Among the parameter-free economy GETs,
//! `escrow-holds` is the most spend-representative summary, so `spend` proxies
//! it.
//!
//! ## Auth header injected upstream
//!
//! Grounded from `components.securitySchemes` in the Engine's openapi.json:
//! `ApiKeyAuth = { type: apiKey, in: header, name: "x-api-key" }`. When
//! `CORECRUXD_ENGINE_API_KEY` is set we inject `x-api-key: <key>` on the
//! upstream request. (`TenantHeader` / `x-tenant-id` is a tenant selector, not
//! an auth header, and is not injected in v1.) The key is never echoed in the
//! downstream response and upstream response headers are never forwarded.
//!
//! ## Config / posture
//!
//! - `CORECRUXD_ENGINE_BASE_URL` — trimmed; empty/unset ⇒ all three routes
//!   return 404 with a terse feature-off body (same "hide the panes" semantics
//!   as the coord plane), so the UI renders nothing rather than a dead pane.
//! - `CORECRUXD_ENGINE_API_KEY` — optional (see above).
//! - Upstream call: same-crate `ureq` client as `gpu1.rs`, hard 5s timeout,
//!   run on a blocking task. Upstream non-200 (or any transport error) ⇒ 502
//!   `{ "error": "engine upstream unavailable" }` with the upstream body/headers
//!   dropped entirely. 200 ⇒ pass the JSON body through plus a
//!   `{ "mediated": true, "fetched_at_unix_ms": … }` envelope (summary also adds
//!   `engine_reachable` + `engine_latency_ms`).
//! - Daemon-side auth mirrors `/v1/console/summary`: `admin:read`.
//!
//! ## Access trail (Art. 12 record-keeping)
//!
//! Every successful proxied read writes one fact via the AppState fact store —
//! entity `__ops::engine-proxy`, key `access:<local-path>`, value
//! `{route, status, at_unix_ms}`. `__ops::` is a born-private reserved prefix
//! (see `fact_privacy`), and every fact-store write mints a CROWN receipt by
//! construction. The write is fire-and-forget so it never blocks the response.

use super::*;
use corecrux_memory::fact_store::StoreFact;
use serde_json::{json, Value};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const ENGINE_BASE_URL_ENV: &str = "CORECRUXD_ENGINE_BASE_URL";
const ENGINE_API_KEY_ENV: &str = "CORECRUXD_ENGINE_API_KEY";
/// Grounded from CruxEngine openapi.json `securitySchemes.ApiKeyAuth.name`.
const ENGINE_API_KEY_HEADER: &str = "x-api-key";
const ENGINE_TIMEOUT_SECS: u64 = 5;
/// Born-private reserved prefix (see `crate::fact_privacy`).
const ACCESS_TRAIL_ENTITY: &str = "__ops::engine-proxy";

/// The three read-only mediation routes. Each maps a stable daemon-local path
/// to the grounded upstream GET (see module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EngineRoute {
    Summary,
    Bench,
    Spend,
}

impl EngineRoute {
    fn local_path(self) -> &'static str {
        match self {
            Self::Summary => "/v1/console/engine/summary",
            Self::Bench => "/v1/console/engine/bench",
            Self::Spend => "/v1/console/engine/spend",
        }
    }

    fn upstream_path(self) -> &'static str {
        match self {
            Self::Summary => "/healthz",
            Self::Bench => "/v1/benchmarks/manifest",
            Self::Spend => "/v1/economy/escrow-holds",
        }
    }

    /// The summary route surfaces engine reachability + latency; the others
    /// only pass the upstream body through with the mediated envelope.
    fn reports_reachability(self) -> bool {
        matches!(self, Self::Summary)
    }
}

pub(super) async fn get_engine_summary(State(state): State<AppState>, headers: HeaderMap) -> Response {
    proxy(state, headers, EngineRoute::Summary).await
}

pub(super) async fn get_engine_bench(State(state): State<AppState>, headers: HeaderMap) -> Response {
    proxy(state, headers, EngineRoute::Bench).await
}

pub(super) async fn get_engine_spend(State(state): State<AppState>, headers: HeaderMap) -> Response {
    proxy(state, headers, EngineRoute::Spend).await
}

fn engine_base_url() -> Option<String> {
    std::env::var(ENGINE_BASE_URL_ENV)
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
}

fn engine_api_key() -> Option<String> {
    std::env::var(ENGINE_API_KEY_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn feature_off_response() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": "engine mediation not configured" })),
    )
        .into_response()
}

fn upstream_unavailable() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        Json(json!({ "error": "engine upstream unavailable" })),
    )
        .into_response()
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0)
}

/// A successful (2xx) upstream read: decoded JSON body + measured latency.
struct Upstream {
    body: Value,
    latency_ms: u128,
}

async fn proxy(state: AppState, headers: HeaderMap, route: EngineRoute) -> Response {
    // Daemon-side auth mirrors `/v1/console/summary` (see `require_console_read`).
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    // Env-gated: unset ⇒ 404 feature-off (the UI hides the pane, no dead pane).
    let Some(base_url) = engine_base_url() else {
        return feature_off_response();
    };
    let url = format!("{base_url}{}", route.upstream_path());
    let api_key = engine_api_key();

    let fetched = tokio::task::spawn_blocking(move || fetch_upstream(&url, api_key.as_deref())).await;

    let upstream = match fetched {
        Ok(Ok(upstream)) => upstream,
        // Transport error, non-2xx upstream, or join failure — never leak the
        // upstream body, headers, or the key.
        Ok(Err(())) | Err(_) => return upstream_unavailable(),
    };

    let at_unix_ms = now_unix_ms();
    write_access_trail(&state, route, StatusCode::OK.as_u16(), at_unix_ms);

    let reachability = route.reports_reachability().then_some((true, upstream.latency_ms));
    Json(with_envelope(upstream.body, at_unix_ms, reachability)).into_response()
}

/// Blocking upstream GET with a hard timeout. Returns `Err(())` on any
/// transport error, decode failure, or non-2xx status — the caller maps that to
/// a terse 502 so no upstream detail (body, headers, or key) can escape.
fn fetch_upstream(url: &str, api_key: Option<&str>) -> Result<Upstream, ()> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .timeout_global(Some(Duration::from_secs(ENGINE_TIMEOUT_SECS)))
        .build()
        .into();

    let mut request = agent.get(url).header("Accept", "application/json");
    if let Some(key) = api_key {
        request = request.header(ENGINE_API_KEY_HEADER, key);
    }

    let started = Instant::now();
    let mut response = request.call().map_err(|_| ())?;
    let latency_ms = started.elapsed().as_millis();

    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        // Do not read or forward the upstream error body.
        return Err(());
    }

    let text = response.body_mut().read_to_string().map_err(|_| ())?;
    let body = if text.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str::<Value>(&text).map_err(|_| ())?
    };
    Ok(Upstream { body, latency_ms })
}

/// Pass the upstream JSON body through with the mediation envelope merged in.
/// Object bodies get the envelope keys added at the top level; non-object
/// bodies (arrays, scalars) are nested under `upstream` so the envelope shape
/// is always uniform.
fn with_envelope(body: Value, at_unix_ms: u128, reachability: Option<(bool, u128)>) -> Value {
    let mut envelope = serde_json::Map::new();
    envelope.insert("mediated".to_string(), json!(true));
    envelope.insert("fetched_at_unix_ms".to_string(), json!(at_unix_ms as u64));
    if let Some((reachable, latency_ms)) = reachability {
        envelope.insert("engine_reachable".to_string(), json!(reachable));
        envelope.insert("engine_latency_ms".to_string(), json!(latency_ms as u64));
    }
    match body {
        Value::Object(mut map) => {
            for (key, value) in envelope {
                map.insert(key, value);
            }
            Value::Object(map)
        }
        other => {
            envelope.insert("upstream".to_string(), other);
            Value::Object(envelope)
        }
    }
}

/// Fire-and-forget access-trail write. `__ops::` is born-private and every
/// fact-store write mints a CROWN receipt by construction. The response never
/// waits on this.
fn write_access_trail(state: &AppState, route: EngineRoute, status: u16, at_unix_ms: u128) {
    let state = state.clone();
    let route_path = route.local_path();
    tokio::spawn(async move {
        let value = serde_json::to_string(&json!({
            "route": route_path,
            "status": status,
            "at_unix_ms": at_unix_ms as u64,
        }))
        .unwrap_or_default();
        let mut fact = StoreFact {
            entity: ACCESS_TRAIL_ENTITY.to_string(),
            key: format!("access:{route_path}"),
            value,
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        };
        crate::fact_privacy::enforce(&state.privacy_policy, &mut fact);
        state.fact_store.write().await.store(fact);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::routing::get;
    use axum::Router;
    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn st() -> AppState {
        super::super::tests::test_app_state(16)
    }

    /// A router that mounts the three engine routes exactly as `mod.rs` does —
    /// GET only. Any other method must therefore 405 at the routing layer.
    fn engine_router(state: AppState) -> Router {
        Router::new()
            .route("/v1/console/engine/summary", get(get_engine_summary))
            .route("/v1/console/engine/bench", get(get_engine_bench))
            .route("/v1/console/engine/spend", get(get_engine_spend))
            .with_state(state)
    }

    async fn json_body(resp: Response) -> Value {
        let bytes = to_bytes(resp.into_body(), 1_048_576).await.expect("read body");
        serde_json::from_slice(&bytes).expect("json body")
    }

    async fn raw_body(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), 1_048_576).await.expect("read body");
        String::from_utf8_lossy(&bytes).to_string()
    }

    fn clear_engine_env() {
        std::env::remove_var(ENGINE_BASE_URL_ENV);
        std::env::remove_var(ENGINE_API_KEY_ENV);
    }

    // ── Minimal one-shot HTTP stub upstream (mirrors the console proxy tests) ──
    fn read_request(stream: &mut std::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buf = [0u8; 1024];
        loop {
            let n = stream.read(&mut buf).expect("read request");
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buf[..n]);
            if bytes.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&bytes).to_string()
    }

    fn write_response(stream: &mut std::net::TcpStream, status_line: &str, body: &str) {
        write!(
            stream,
            "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        )
        .expect("write mock response");
    }

    /// Spawn a single-shot stub that answers one request with `status_line` +
    /// `body`, returning the captured request headers over the channel.
    fn spawn_stub(status_line: &'static str, body: &'static str) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub engine");
        let base_url = format!("http://{}", listener.local_addr().expect("addr"));
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept stub request");
            let header = read_request(&mut stream);
            let _ = tx.send(header);
            write_response(&mut stream, status_line, body);
        });
        (base_url, rx)
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn env_unset_all_three_routes_404_feature_off() {
        clear_engine_env();
        let state = st();
        for route in [EngineRoute::Summary, EngineRoute::Bench, EngineRoute::Spend] {
            let resp = proxy(state.clone(), HeaderMap::new(), route).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
            let body = json_body(resp).await;
            assert_eq!(body["error"], "engine mediation not configured");
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn non_get_methods_405_customer_safe() {
        use tower::ServiceExt as _;
        clear_engine_env();
        let paths = [
            "/v1/console/engine/summary",
            "/v1/console/engine/bench",
            "/v1/console/engine/spend",
        ];
        for path in paths {
            for method in ["POST", "PUT", "DELETE"] {
                let app = engine_router(st());
                let resp = app
                    .oneshot(
                        axum::http::Request::builder()
                            .method(method)
                            .uri(path)
                            .body(axum::body::Body::empty())
                            .expect("build request"),
                    )
                    .await
                    .expect("router response");
                assert_eq!(
                    resp.status(),
                    StatusCode::METHOD_NOT_ALLOWED,
                    "{method} {path} must be 405 (no mutating engine route is mounted)"
                );
            }
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn summary_200_passthrough_with_mediated_envelope() {
        let (base_url, _rx) = spawn_stub("200 OK", r#"{"status":"ok","service":"cruxengine"}"#);
        std::env::set_var(ENGINE_BASE_URL_ENV, &base_url);
        std::env::remove_var(ENGINE_API_KEY_ENV);

        let resp = get_engine_summary(State(st()), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        // Upstream body passed through …
        assert_eq!(body["status"], "ok");
        assert_eq!(body["service"], "cruxengine");
        // … plus the mediated envelope + reachability (summary route only).
        assert_eq!(body["mediated"], true);
        assert!(body["fetched_at_unix_ms"].as_u64().is_some());
        assert_eq!(body["engine_reachable"], true);
        assert!(body["engine_latency_ms"].as_u64().is_some());
        clear_engine_env();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn upstream_500_maps_to_terse_502_no_body_leak() {
        // The upstream error body must NEVER reach the client.
        let (base_url, _rx) = spawn_stub("500 Internal Server Error", r#"{"secret_upstream_detail":"leak-me"}"#);
        std::env::set_var(ENGINE_BASE_URL_ENV, &base_url);
        std::env::remove_var(ENGINE_API_KEY_ENV);

        let resp = get_engine_bench(State(st()), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        let raw = raw_body(resp).await;
        assert!(raw.contains("engine upstream unavailable"), "terse 502 body: {raw}");
        assert!(
            !raw.contains("secret_upstream_detail") && !raw.contains("leak-me"),
            "upstream error body must not be forwarded: {raw}"
        );
        clear_engine_env();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn api_key_injected_upstream_never_in_downstream_response() {
        const KEY: &str = "sk-engine-test-supersecret";
        let (base_url, rx) = spawn_stub("200 OK", r#"{"status":"ok"}"#);
        std::env::set_var(ENGINE_BASE_URL_ENV, &base_url);
        std::env::set_var(ENGINE_API_KEY_ENV, KEY);

        let resp = get_engine_summary(State(st()), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = raw_body(resp).await;

        // Key was injected on the UPSTREAM request …
        let upstream_headers = rx.recv().expect("captured upstream request");
        let lower = upstream_headers.to_ascii_lowercase();
        assert!(
            lower.contains(&format!("{ENGINE_API_KEY_HEADER}: {KEY}").to_ascii_lowercase()),
            "x-api-key must be injected upstream; got headers: {upstream_headers}"
        );
        // … and NEVER echoed downstream.
        assert!(
            !raw.contains(KEY) && !raw.to_ascii_lowercase().contains(ENGINE_API_KEY_HEADER),
            "downstream response must not carry the key or its header name: {raw}"
        );
        clear_engine_env();
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn access_trail_fact_written_on_success() {
        let (base_url, _rx) = spawn_stub("200 OK", r#"{"status":"ok"}"#);
        std::env::set_var(ENGINE_BASE_URL_ENV, &base_url);
        std::env::remove_var(ENGINE_API_KEY_ENV);
        let state = st();

        let resp = get_engine_summary(State(state.clone()), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // The write is fire-and-forget; poll the store until the spawned task lands.
        let mut found: Option<Value> = None;
        for _ in 0..500 {
            let query = corecrux_memory::fact_store::FactQuery {
                query: None,
                entity: Some(ACCESS_TRAIL_ENTITY.to_string()),
                entity_prefix: None,
                top_k: 16,
                token_budget: None,
            };
            let hit = {
                let store = state.fact_store.read().await;
                store
                    .query(&query)
                    .facts
                    .into_iter()
                    .find(|f| f.key == "access:/v1/console/engine/summary")
            };
            if let Some(fact) = hit {
                found = Some(serde_json::from_str::<Value>(&fact.value).expect("fact value json"));
                break;
            }
            tokio::task::yield_now().await;
        }
        let value = found.expect("access-trail fact written for summary route");
        assert_eq!(value["route"], "/v1/console/engine/summary");
        assert_eq!(value["status"], 200);
        assert!(value["at_unix_ms"].as_u64().is_some());
        clear_engine_env();
    }
}
