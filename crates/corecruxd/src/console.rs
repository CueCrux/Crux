// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Embedded console HTML asset server — small static-file router for the in-process console.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use axum::extract::{Path as AxumPath, Request};
use axum::http::{header, HeaderName, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};

// Unified Shell Console v2 (ExecPlan unified-shell-console-2026-07-03). The
// self-contained, no-build shell served unconditionally at `/console` — the
// sole console surface now that the legacy console has been removed. Same
// embedded, no-on-disk-dependency posture as the sibling `console-3d/*` assets.
const CONSOLE_V2_HTML: &str = include_str!("../console/v2/shell.html");
// Unified Shell Console v2 — no-build module split (M1). The shell references
// these same-origin at `/console-v2/pages.js` / `/console-v2/render.js`. Same
// embedded, dev-overridable posture as the shell itself. `pages.js` is the
// ported 26-page registry; `render.js` is the DSL renderer.
const CONSOLE_V2_PAGES_JS: &str = include_str!("../console/v2/pages.js");
const CONSOLE_V2_RENDER_JS: &str = include_str!("../console/v2/render.js");
// Generated read-only fetch client (M2): produced from the ROUTES manifest by
// `cargo test -p corecruxd --test route_spec_drift -- --ignored regen_api_js`.
// GET routes only — the customer-safe posture holds at the client layer too.
const CONSOLE_V2_API_JS: &str = include_str!("../console/v2/api.js");
// Link-graph pane WebGL renderer (ExecPlan wikicrux-link-graph-explorer M4). A
// client-only ESM module (custom three.js r165) served at
// `/console-v2/linkgraph-renderer.mjs`; render.js dynamically imports it when the
// Link graph pane opens. `three` resolves via the shell import map to the vendored
// r165 — zero new vendored files (T.5). Same embedded, dev-overridable posture.
const CONSOLE_V2_LINKGRAPH_MJS: &str = include_str!("../console/v2/linkgraph-renderer.mjs");
// PWA app-shell assets (M5). Served same-origin at `/console-v2/{name}` alongside
// the JS modules. `sw.js` is the app-shell service worker (never caches `/v1/*`);
// `manifest.webmanifest` is the install manifest; `icon.svg` is the app icon.
// `sw.js` is served with `Service-Worker-Allowed: /console` so a script under
// `/console-v2/` may control the `/console` scope (see `serve_console_v2_asset`).
const CONSOLE_V2_SW_JS: &str = include_str!("../console/v2/sw.js");
const CONSOLE_V2_MANIFEST: &str = include_str!("../console/v2/manifest.webmanifest");
const CONSOLE_V2_ICON_SVG: &str = include_str!("../console/v2/icon.svg");
const CONSOLE_DEV_PATH_ENV: &str = "CORECRUXD_CONSOLE_DEV_PATH";

// CORS allowlist for the console asset routes (ExecPlan
// crux-console-public-exposure-2026-05-17, M5). The console is publicly exposed
// behind oauth2-proxy, so the daemon must not answer cross-origin requests with
// a wildcard `Access-Control-Allow-Origin`. Origins are configured via
// `CORECRUXD_CONSOLE_ALLOWED_ORIGINS` (comma-separated); when unset (or empty
// after trimming) the production defaults below apply.
const CONSOLE_ALLOWED_ORIGINS_ENV: &str = "CORECRUXD_CONSOLE_ALLOWED_ORIGINS";

// Browser hardening for every document and static asset served by the daemon.
// The console intentionally uses same-origin frames for its 3D view and Studio
// web tiles, so frame-src/frame-ancestors and X-Frame-Options permit only that
// same origin rather than denying framing outright. Inline script/style remain
// necessary for the embedded, no-build shell and `/activate`; eval is not.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; base-uri 'none'; object-src 'none'; frame-src 'self'; frame-ancestors 'self'; form-action 'self'; connect-src 'self'; img-src 'self' data: blob:; font-src 'self' data:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; worker-src 'self'; manifest-src 'self'";
const BROWSER_SECURITY_HEADERS: [(&str, &str); 7] = [
    ("content-security-policy", CONTENT_SECURITY_POLICY),
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "SAMEORIGIN"),
    ("referrer-policy", "no-referrer"),
    (
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()",
    ),
    ("cross-origin-opener-policy", "same-origin"),
    ("cross-origin-resource-policy", "same-origin"),
];

// Default allowlist when `CORECRUXD_CONSOLE_ALLOWED_ORIGINS` is unset: the
// public console origin plus the two Tailnet-facing origins the daemon is
// reachable on (host `crux` / its Tailscale IP). Matches the M5 plan intent.
const DEFAULT_CONSOLE_ALLOWED_ORIGINS: &[&str] = &["https://crux.cuecrux.com", "http://100.70.12.73", "http://crux"];

// Bundled PNG assets — embedded so the binary can serve them with no on-disk
// dependency. Dev override (CORECRUXD_CONSOLE_DEV_PATH) falls back to reading
// from `<dev>/assets/<name>` so design iterations don't need a rebuild.
const ASSET_LOGO_DARK: &[u8] = include_bytes!("../console/assets/CueCrux-Arc-Loop.png");
const ASSET_LOGO_WHITE: &[u8] = include_bytes!("../console/assets/CueCrux-Arc-Loop-White.png");

// Embedded 3D substrate view (the `2D | 3D` toolbar switch in the console
// loads `console-3d/index.html?embed=1` in an iframe). Same in-binary,
// no-on-disk-dependency story as the console itself.
const CONSOLE3D_HTML: &str = include_str!("../console/console-3d/index.html");
const CONSOLE3D_CSS: &str = include_str!("../console/console-3d/css/console3d.css");
const CONSOLE3D_JS_DATA: &str = include_str!("../console/console-3d/js/data.js");
const CONSOLE3D_JS_WORLD: &str = include_str!("../console/console-3d/js/world.js");
const CONSOLE3D_JS_MAIN: &str = include_str!("../console/console-3d/js/main.js");
const CONSOLE3D_VENDOR_THREE: &str = include_str!("../console/console-3d/vendor/three.module.min.js");
const CONSOLE3D_VENDOR_ORBIT: &str = include_str!("../console/console-3d/vendor/OrbitControls.js");
const CONSOLE3D_VENDOR_ROUNDED: &str = include_str!("../console/console-3d/vendor/RoundedBoxGeometry.js");

// Claude Desktop connector bundle, offered as a one-click download from the
// console's Connections page. An `.mcpb` is a zip of `manifest.json` plus the
// server it runs; Desktop's `server.type` accepts only node/python/binary, so a
// remote HTTP daemon has to ship a local stdio shim — here a pinned, vendored
// `mcp-remote`. The artifact is PREBUILT and committed (rebuild with
// `console/mcpb/build.sh`) so a `cargo build` never needs npm and can never
// resolve a different dependency version.
//
// It carries no per-install state: the endpoint URL and agent token are mcpb
// `user_config` fields that Desktop prompts for at install time, so every
// operator downloads identical bytes.
const ASSET_CLAUDE_DESKTOP_MCPB: &[u8] = include_bytes!("../console/assets/crux.mcpb");

fn embedded_asset(name: &str) -> Option<&'static [u8]> {
    match name {
        "CueCrux-Arc-Loop.png" => Some(ASSET_LOGO_DARK),
        "CueCrux-Arc-Loop-White.png" => Some(ASSET_LOGO_WHITE),
        "crux.mcpb" => Some(ASSET_CLAUDE_DESKTOP_MCPB),
        _ => None,
    }
}

async fn serve_console() -> impl IntoResponse {
    Html(resolve_console_body().into_owned())
}

async fn redirect_to_console() -> impl IntoResponse {
    Redirect::to("/console")
}

/// Embedded v2 module + PWA assets (`pages.js`, `render.js`, `api.js`, plus the
/// M5 `sw.js` / `manifest.webmanifest` / `icon.svg`), served same-origin at
/// `/console-v2/{name}`. A dev override (`CORECRUXD_CONSOLE_DEV_PATH`) reads
/// `v2/<name>` next to the console index so the assets can be iterated without a
/// rebuild — same resolve-then-rewrite pattern as the shell override.
async fn serve_console_v2_asset(AxumPath(name): AxumPath<String>) -> Response {
    // Single path segment; be paranoid about traversal anyway.
    if name.contains('/') || name.contains("..") {
        return (axum::http::StatusCode::BAD_REQUEST, "invalid asset name").into_response();
    }
    // (embedded body, content-type). The three JS modules keep `text/javascript`;
    // the PWA assets carry their own content-types. `sw.js` additionally gets a
    // `Service-Worker-Allowed: /console` header in `console_v2_asset_response`.
    let (embedded, content_type): (&'static str, &'static str) = match name.as_str() {
        "pages.js" => (CONSOLE_V2_PAGES_JS, "text/javascript; charset=utf-8"),
        "render.js" => (CONSOLE_V2_RENDER_JS, "text/javascript; charset=utf-8"),
        "api.js" => (CONSOLE_V2_API_JS, "text/javascript; charset=utf-8"),
        "linkgraph-renderer.mjs" => (CONSOLE_V2_LINKGRAPH_MJS, "text/javascript; charset=utf-8"),
        "sw.js" => (CONSOLE_V2_SW_JS, "application/javascript; charset=utf-8"),
        "manifest.webmanifest" => (CONSOLE_V2_MANIFEST, "application/manifest+json; charset=utf-8"),
        "icon.svg" => (CONSOLE_V2_ICON_SVG, "image/svg+xml; charset=utf-8"),
        _ => return (axum::http::StatusCode::NOT_FOUND, "no such console-v2 asset").into_response(),
    };
    // Dev override wins when present.
    let body = console_v2_dev_asset(&name).unwrap_or_else(|| embedded.to_string());
    console_v2_asset_response(&name, content_type, body)
}

/// Read `v2/<name>` under the `CORECRUXD_CONSOLE_DEV_PATH` dir, if set + readable.
fn console_v2_dev_asset(name: &str) -> Option<String> {
    let raw = std::env::var(CONSOLE_DEV_PATH_ENV).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let file_path = resolve_dev_html_path(Path::new(trimmed))
        .with_file_name("v2")
        .join(name);
    std::fs::read_to_string(&file_path).ok()
}

fn console_v2_asset_response(name: &str, content_type: &'static str, body: String) -> Response {
    let mut resp = (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response();
    // The service-worker script lives under `/console-v2/`, but it registers for
    // the `/console` scope; without this header the browser rejects that scope.
    if name == "sw.js" {
        resp.headers_mut().insert(
            header::HeaderName::from_static("service-worker-allowed"),
            header::HeaderValue::from_static("/console"),
        );
    }
    resp
}

async fn serve_console_asset(AxumPath(name): AxumPath<String>) -> Response {
    // Reject path traversal — `Path` matches a single segment, but be paranoid.
    if name.contains('/') || name.contains("..") {
        return (axum::http::StatusCode::BAD_REQUEST, "invalid asset name").into_response();
    }
    // Dev override wins when present so designers can drop new PNG / SVG /
    // WebP files in without a rebuild.
    if let Some(dev_path) = std::env::var(CONSOLE_DEV_PATH_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        let file_path = resolve_dev_html_path(Path::new(dev_path.trim()))
            .with_file_name("assets")
            .join(&name);
        if let Ok(bytes) = std::fs::read(&file_path) {
            return asset_response(&name, bytes);
        }
    }
    match embedded_asset(&name) {
        Some(bytes) => asset_response(&name, bytes.to_vec()),
        None => (axum::http::StatusCode::NOT_FOUND, "no such console asset").into_response(),
    }
}

fn asset_response(name: &str, bytes: Vec<u8>) -> Response {
    let ext_eq = |want: &str| {
        Path::new(name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case(want))
    };
    let content_type = if ext_eq("png") {
        "image/png"
    } else if ext_eq("svg") {
        "image/svg+xml"
    } else if ext_eq("webp") {
        "image/webp"
    } else {
        "application/octet-stream"
    };
    let mut response = (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        bytes,
    )
        .into_response();
    // Connector bundles are downloads, not things to render. Without an
    // attachment disposition a browser hands the octet-stream to its own
    // save-file guesswork and the operator ends up with `download` or
    // `crux.mcpb.zip` — Claude Desktop only accepts the `.mcpb` extension.
    if ext_eq("mcpb") {
        if let Ok(value) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\"")) {
            response.headers_mut().insert(header::CONTENT_DISPOSITION, value);
        }
    }
    response
}

/// Embedded 3D substrate assets, keyed by their path under `/console-3d/`.
async fn serve_console3d(AxumPath(path): AxumPath<String>) -> Response {
    let (body, content_type): (&'static str, &'static str) = match path.as_str() {
        "" | "index.html" => (CONSOLE3D_HTML, "text/html; charset=utf-8"),
        "css/console3d.css" => (CONSOLE3D_CSS, "text/css; charset=utf-8"),
        "js/data.js" => (CONSOLE3D_JS_DATA, "text/javascript; charset=utf-8"),
        "js/world.js" => (CONSOLE3D_JS_WORLD, "text/javascript; charset=utf-8"),
        "js/main.js" => (CONSOLE3D_JS_MAIN, "text/javascript; charset=utf-8"),
        "vendor/three.module.min.js" => (CONSOLE3D_VENDOR_THREE, "text/javascript; charset=utf-8"),
        "vendor/OrbitControls.js" => (CONSOLE3D_VENDOR_ORBIT, "text/javascript; charset=utf-8"),
        "vendor/RoundedBoxGeometry.js" => (CONSOLE3D_VENDOR_ROUNDED, "text/javascript; charset=utf-8"),
        _ => return (axum::http::StatusCode::NOT_FOUND, "no such console-3d asset").into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        body,
    )
        .into_response()
}

/// An allowlist entry is only accepted if it looks like a browser Origin: an
/// `http`/`https` scheme (case-insensitive) followed by a non-empty host. This
/// is deliberately strict — it drops `*`, `null`, and non-web schemes so a
/// misconfigured env var cannot re-introduce a permissive or opaque-origin match.
fn is_allowlistable_origin(entry: &str) -> bool {
    let lower = entry.to_ascii_lowercase();
    ["https://", "http://"]
        .into_iter()
        .find_map(|scheme| lower.strip_prefix(scheme))
        .is_some_and(|host| !host.is_empty())
}

/// Parse the comma-separated `CORECRUXD_CONSOLE_ALLOWED_ORIGINS` value into a
/// validated list of allowed origins. Entries are trimmed; empty entries (so a
/// trailing comma or `"a, ,b"`) are dropped; entries that are not a valid HTTP
/// header value (control chars, etc.) are skipped rather than aborting startup.
/// When the input yields no usable origins, the production defaults apply — the
/// console is never left with an empty allowlist by accident, and never falls
/// back to a permissive wildcard.
fn resolve_allowed_origins(raw: &str) -> Vec<HeaderValue> {
    let parsed: Vec<HeaderValue> = raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        // Only accept real `http(s)://<host>` origins. This rejects a literal
        // wildcard (`*` would defeat the allowlist and panics `AllowOrigin::list`)
        // AND opaque-origin values like `null`, `file:` or `data:` — a configured
        // `null` would otherwise match the `Origin: null` that sandboxed iframes
        // and local-file contexts send, silently re-opening the hole M5 closes.
        .filter(|entry| is_allowlistable_origin(entry))
        .filter_map(|entry| HeaderValue::from_str(entry).ok())
        .collect();
    if parsed.is_empty() {
        DEFAULT_CONSOLE_ALLOWED_ORIGINS
            .iter()
            .filter_map(|origin| HeaderValue::from_str(origin).ok())
            .collect()
    } else {
        parsed
    }
}

/// Resolve the console CORS allowlist from the environment (or the defaults).
fn console_allowed_origins() -> Vec<HeaderValue> {
    let raw = std::env::var(CONSOLE_ALLOWED_ORIGINS_ENV).unwrap_or_default();
    resolve_allowed_origins(&raw)
}

/// Build the explicit-allowlist CORS layer for the console asset routes. Replaces
/// the previous `CorsLayer::permissive()` (which reflected any origin with a
/// wildcard `Access-Control-Allow-Origin`) now that the console is publicly
/// exposed. Origins come from `console_allowed_origins`; methods are restricted
/// to the read-only verbs these static-asset routes actually serve. Request
/// headers are named explicitly rather than `Any`: the CORS spec's `*` header
/// wildcard does NOT cover `Authorization`, so it must be listed by name for the
/// console's localStorage-JWT (`Authorization` header) flow to survive preflight.
/// Credentials are intentionally NOT allowed — the JWT rides an `Authorization`
/// header, never a cookie, so cookie/credential mode stays off.
fn console_cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(console_allowed_origins()))
        .allow_methods([Method::GET, Method::HEAD, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
}

/// Replace any route-local browser policy with the daemon's canonical policy.
/// This layer sits outside CORS so its headers also cover CORS-generated
/// preflight responses.
async fn add_browser_security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    for (name, value) in BROWSER_SECURITY_HEADERS {
        response
            .headers_mut()
            .insert(HeaderName::from_static(name), HeaderValue::from_static(value));
    }
    response
}

pub fn routes(enabled: bool) -> Router {
    if !enabled {
        return Router::new();
    }

    Router::new()
        .route("/", get(redirect_to_console))
        .route("/console", get(serve_console))
        .route("/console-assets/{name}", get(serve_console_asset))
        .route("/console-v2/{name}", get(serve_console_v2_asset))
        .route("/console-3d/{*path}", get(serve_console3d))
        // Device-grant approval page (ExecPlan crux-unified-login-rails, M3).
        .route("/activate", get(serve_activate))
        .layer(console_cors_layer())
        .layer(axum::middleware::from_fn(add_browser_security_headers))
}

/// `/activate` — operator approval page for the device-authorization grant.
/// The form POSTs to `/v1/auth/device/approve` on the same origin; that endpoint
/// is gated to an authenticated console admin (`admin:write`) and the
/// selected tenant + scopes are minted only after the server proves they are a
/// subset of the approver's verified grants (threat ref T.1).
async fn serve_activate() -> impl IntoResponse {
    Html(ACTIVATE_HTML)
}

const ACTIVATE_HTML: &str = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Crux — Approve device login</title>
<style>
  :root {
    --blue: #0369a1; --blue-dark: #075985; --sky: #0ea5e9;
    --green: #15803d; --green-dark: #166534;
    --bg: #f0f9ff; --card: #ffffff; --text: #0c4a6e; --muted: #475569;
    --border: #cfe2f0; --border-strong: #94c2e0;
    --danger: #b42318; --danger-bg: #fef3f2; --danger-border: #f1c4bf;
    --ok-bg: #ecfdf3; --ok-border: #abefc6; --ok-text: #067647;
    --code-bg: #eef6fc; --radius: 10px;
    --font: Inter, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  body { font-family: var(--font); color: var(--text); background: var(--bg); margin: 0; min-height: 100vh;
         display: flex; align-items: flex-start; justify-content: center; padding: 2.5rem 1rem; line-height: 1.5;
         -webkit-font-smoothing: antialiased; }
  .card { width: 100%; max-width: 30rem; background: var(--card); border: 1px solid var(--border); border-radius: 14px;
          box-shadow: 0 1px 2px rgba(12,74,110,.06), 0 10px 28px rgba(12,74,110,.09); padding: 1.5rem 1.5rem 1.75rem; }
  .head { display: flex; align-items: center; gap: .65rem; }
  .badge { width: 34px; height: 34px; flex: none; border-radius: 9px; background: var(--blue);
           display: flex; align-items: center; justify-content: center; }
  .badge svg { width: 19px; height: 19px; color: #fff; }
  h1 { font-size: 1.15rem; font-weight: 700; margin: 0; letter-spacing: -.01em; }
  .sub { color: var(--muted); font-size: .83rem; margin: .55rem 0 1.3rem; }
  label.lbl { display: block; margin: 0 0 .3rem; font-weight: 600; font-size: .82rem; }
  .field { margin-bottom: 1rem; }
  input[type=text], select { width: 100%; padding: .55rem .65rem; font-size: .95rem; font-family: var(--font);
          color: var(--text); background: #fff; border: 1px solid var(--border-strong); border-radius: var(--radius);
          transition: border-color .15s, box-shadow .15s; }
  input::placeholder { color: #93a7b5; }
  input:focus, select:focus, button:focus-visible { outline: none; border-color: var(--sky);
          box-shadow: 0 0 0 3px rgba(14,165,233,.28); }
  .mono { font-family: var(--mono); letter-spacing: .02em; }
  .scopes { border: 1px solid var(--border); border-radius: var(--radius); padding: 0 .55rem; background: #fbfdff; }
  .scopes label { display: flex; align-items: flex-start; gap: .55rem; font-weight: 500; font-size: .85rem;
          margin: 0; padding: .55rem .15rem; cursor: pointer; border-bottom: 1px solid var(--border); }
  .scopes label:last-child { border-bottom: 0; }
  .scopes input { width: 18px; height: 18px; margin-top: 1px; flex: none; accent-color: var(--blue); cursor: pointer; }
  .scopes code { font-family: var(--mono); font-size: .8rem; background: var(--code-bg); color: var(--blue-dark);
          padding: .05rem .35rem; border-radius: 5px; }
  .scopes .desc { color: var(--muted); }
  .tip { font-size: .78rem; color: var(--muted); margin: .55rem 0 0; }
  .tip code { font-family: var(--mono); background: var(--code-bg); color: var(--blue-dark); padding: 0 .25rem; border-radius: 4px; }
  .row { display: flex; gap: .65rem; margin-top: 1.4rem; }
  button { flex: 1; min-height: 44px; padding: .65rem 1rem; font-size: .95rem; font-weight: 600; font-family: var(--font);
          cursor: pointer; border-radius: var(--radius); border: 1px solid transparent;
          transition: background .15s, border-color .15s, opacity .15s; }
  button:disabled { opacity: .6; cursor: default; }
  .approve { background: var(--green); color: #fff; }
  .approve:hover:not(:disabled) { background: var(--green-dark); }
  .deny { background: #fff; color: var(--danger); border-color: var(--danger-border); }
  .deny:hover:not(:disabled) { background: var(--danger-bg); }
  #result { margin-top: 1.1rem; padding: .7rem .8rem; border-radius: var(--radius); white-space: pre-wrap;
          font-size: .82rem; font-family: var(--mono); display: none; word-break: break-word; }
  #result.show { display: block; }
  #result.ok { background: var(--ok-bg); border: 1px solid var(--ok-border); color: var(--ok-text); }
  #result.err { background: var(--danger-bg); border: 1px solid var(--danger-border); color: var(--danger); }
  .signin { display: none; text-align: center; padding: 1rem 0 .5rem; }
  .signin.show { display: block; }
  .signin p { color: var(--muted); font-size: .88rem; margin: .25rem 0 1rem; }
  .signin a { display: inline-flex; align-items: center; gap: .5rem; min-height: 44px; padding: 0 1.1rem;
          background: var(--text); color: #fff; text-decoration: none; border-radius: var(--radius); font-weight: 600; font-size: .9rem; }
  .signin a:hover { background: #0b3a56; }
  .newrow { display: none; margin-top: .5rem; }
  .newrow.show { display: block; }
  @media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
</style>
</head>
<body>
  <main class="card">
    <div class="head">
      <span class="badge" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></span>
      <h1>Approve a device login</h1>
    </div>
    <p class="sub">A client is requesting access. Grant a tenant and only the scopes it needs, then approve. Only approve a code you initiated.</p>

    <div id="signin" class="signin">
      <p>Your session has expired or you are not signed in. Sign in to approve this device.</p>
      <a id="signin_link" href="/oauth2/sign_in">Sign in with GitHub</a>
    </div>

    <form id="form" onsubmit="return false">
      <div class="field">
        <label class="lbl" for="user_code">User code</label>
        <input type="text" id="user_code" class="mono" placeholder="ABCD-2345" autocomplete="off" autocapitalize="characters" spellcheck="false" />
      </div>
      <div class="field">
        <label class="lbl" for="tenant_sel">Tenant</label>
        <select id="tenant_sel" onchange="onTenantChange()"></select>
        <div id="newrow" class="newrow">
          <input type="text" id="tenant_new" class="mono" placeholder="new-tenant-id" autocomplete="off" spellcheck="false" />
        </div>
      </div>
      <div class="field">
        <label class="lbl">Scopes</label>
        <div id="scopes" class="scopes">
          <label><input type="checkbox" value="query:read" /><span><code>query:read</code><span class="desc"> — run retrieval / text-search queries</span></span></label>
          <label><input type="checkbox" value="facts:read" /><span><code>facts:read</code><span class="desc"> — read stored facts</span></span></label>
          <label><input type="checkbox" value="facts:write" /><span><code>facts:write</code><span class="desc"> — append facts</span></span></label>
          <label><input type="checkbox" value="admin:read" /><span><code>admin:read</code><span class="desc"> — read tenant config</span></span></label>
          <label><input type="checkbox" value="admin:write" /><span><code>admin:write</code><span class="desc"> — ingest / append content &amp; manage the tenant</span></span></label>
        </div>
        <p class="tip">Content ingest needs <code>admin:write</code> + <code>query:read</code>. Grant only what the client needs.</p>
      </div>
      <div class="row">
        <button type="button" class="approve" id="approve_btn" onclick="decide(false)">Approve</button>
        <button type="button" class="deny" id="deny_btn" onclick="decide(true)">Deny</button>
      </div>
      <div id="result" role="status" aria-live="polite"></div>
    </form>
  </main>
<script>
var ADD_NEW = '__add_new__';
function el(id) { return document.getElementById(id); }
function isAddNewSelected() {
  var select = el('tenant_sel');
  var option = select.options[select.selectedIndex];
  return Boolean(option && option.dataset.tenantAction === 'add');
}
function onTenantChange() {
  var add = isAddNewSelected();
  el('newrow').classList.toggle('show', add);
  if (add) el('tenant_new').focus();
}
function showSignin() {
  el('form').style.display = 'none';
  el('signin').classList.add('show');
  el('signin_link').href = '/oauth2/sign_in?rd=' + encodeURIComponent(location.href);
}
async function loadTenants() {
  try {
    var r = await fetch('/v1/console/tenants', { credentials: 'same-origin', headers: { accept: 'application/json' } });
    var ct = r.headers.get('content-type') || '';
    if (r.redirected || !r.ok || ct.indexOf('application/json') < 0) { showSignin(); return; }
    var j = await r.json();
    var list = (j.tenants || (Array.isArray(j) ? j : [])).map(function (t) { return typeof t === 'string' ? t : t.tenant_id; }).filter(Boolean);
    var select = el('tenant_sel');
    select.replaceChildren();
    if (!list.length) appendTenantOption(select, '', 'No tenants yet — add one', true, true, false);
    list.forEach(function (t) { appendTenantOption(select, t, t, false, false, false); });
    appendTenantOption(select, ADD_NEW, '+ Add new tenant…', false, false, true);
    onTenantChange();
  } catch (e) { showSignin(); }
}
function appendTenantOption(select, value, label, disabled, selected, addNew) {
  var option = document.createElement('option');
  option.value = value;
  option.textContent = label;
  option.disabled = disabled;
  option.selected = selected;
  if (addNew) option.dataset.tenantAction = 'add';
  select.appendChild(option);
}
function currentTenant() {
  var v = el('tenant_sel').value;
  return isAddNewSelected() ? el('tenant_new').value.trim() : v;
}
async function decide(deny) {
  var out = el('result'), a = el('approve_btn'), d = el('deny_btn');
  var scopes = Array.prototype.slice.call(document.querySelectorAll('#scopes input:checked')).map(function (c) { return c.value; });
  var tenant = currentTenant();
  function fail(msg) { out.className = 'show err'; out.textContent = msg; }
  if (!el('user_code').value.trim()) return fail('Enter the user code shown by the client.');
  if (!deny && !tenant) return fail('Choose or enter a tenant.');
  if (!deny && !scopes.length) return fail('Select at least one scope.');
  a.disabled = true; d.disabled = true;
  out.className = 'show'; out.textContent = deny ? 'Denying…' : 'Approving…';
  try {
    var resp = await fetch('/v1/auth/device/approve', {
      method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'same-origin',
      body: JSON.stringify({ user_code: el('user_code').value.trim(), tenant_id: tenant, scopes: scopes, deny: deny }),
    });
    var text = await resp.text();
    if (resp.redirected || text.trim().charAt(0) === '<') { showSignin(); return; }
    out.className = 'show ' + (resp.ok ? 'ok' : 'err');
    out.textContent = (resp.ok ? 'OK — ' : ('HTTP ' + resp.status + ' — ')) + text;
  } catch (e) {
    out.className = 'show err'; out.textContent = String(e);
  } finally {
    a.disabled = false; d.disabled = false;
  }
}
loadTenants();
</script>
</body>
</html>"#;

/// The `/console` body: the unified v2 shell, unconditionally. The legacy
/// console has been removed — v2 is the sole surface. A dev override
/// (`CORECRUXD_CONSOLE_DEV_PATH`) hot-serves `v2/shell.html` from disk (stamped
/// with the dev flag so the service worker steps aside); otherwise the embedded
/// `CONSOLE_V2_HTML` is served.
fn resolve_console_body() -> Cow<'static, str> {
    match console_v2_dev_override() {
        Some(html) => Cow::Owned(inject_console_dev_flag(html)),
        None => Cow::Borrowed(CONSOLE_V2_HTML),
    }
}

/// Dev-only marker: stamp the shell so the client skips PWA service-worker
/// registration (and tears down any existing worker + its caches). This ONLY
/// runs on the `console_v2_dev_override` path — i.e. when the shell is being
/// hot-served from `CORECRUXD_CONSOLE_DEV_PATH` — so an edit under the dev dir
/// shows on a plain refresh instead of being shadowed by a cached shell. The
/// embedded (production) `CONSOLE_V2_HTML` never passes through here, so the
/// shipped console keeps its service worker byte-for-byte.
fn inject_console_dev_flag(html: String) -> String {
    const MARK: &str = "<script>window.__CRUX_CONSOLE_DEV__=1;</script>";
    if html.contains(MARK) {
        html
    } else if html.contains("<head>") {
        html.replacen("<head>", &format!("<head>{MARK}"), 1)
    } else {
        format!("{MARK}{html}")
    }
}

/// Dev override for the v2 shell: reads `v2/shell.html` relative to the
/// `CORECRUXD_CONSOLE_DEV_PATH` dir (same resolve-then-rewrite pattern as the
/// sibling `activity.html` override) so the shell can be iterated without a
/// rebuild. Unreadable/unset ⇒ fall back to the embedded `CONSOLE_V2_HTML`.
fn console_v2_dev_override() -> Option<String> {
    let raw = std::env::var(CONSOLE_DEV_PATH_ENV).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let html_path = resolve_dev_html_path(Path::new(trimmed))
        .with_file_name("v2")
        .join("shell.html");
    match std::fs::read_to_string(&html_path) {
        Ok(contents) => Some(contents),
        Err(err) => {
            tracing::warn!(
                target: "corecruxd::console",
                path = %html_path.display(),
                error = %err,
                "console v2 dev override unreadable; falling back to embedded HTML"
            );
            None
        }
    }
}

fn resolve_dev_html_path(base: &Path) -> PathBuf {
    if base.is_dir() {
        base.join("index.html")
    } else {
        base.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        resolve_console_body, ACTIVATE_HTML, BROWSER_SECURITY_HEADERS, CONSOLE_DEV_PATH_ENV, CONSOLE_V2_API_JS,
        CONSOLE_V2_HTML, CONSOLE_V2_ICON_SVG, CONSOLE_V2_LINKGRAPH_MJS, CONSOLE_V2_MANIFEST, CONSOLE_V2_PAGES_JS,
        CONSOLE_V2_RENDER_JS, CONSOLE_V2_SW_JS, CONTENT_SECURITY_POLICY,
    };
    use std::sync::Mutex;

    const DESKTOP_PROXY_SOURCE: &str = include_str!("../../../shells/desktop/connection/src/proxy.rs");

    // The dev-path / v2 flag env vars are process-global; serialise tests that
    // mutate either of them. Recover a poisoned lock so one failing env test
    // does not cascade into the others.
    static ENV_LOCK: Mutex<()> = Mutex::new(());
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    fn assert_browser_security_headers(headers: &axum::http::HeaderMap) {
        for (name, expected) in BROWSER_SECURITY_HEADERS {
            assert_eq!(
                headers.get_all(name).iter().count(),
                1,
                "{name} must occur exactly once"
            );
            assert_eq!(
                headers.get(name).and_then(|value| value.to_str().ok()),
                Some(expected),
                "{name} must match the canonical browser policy"
            );
        }
        assert!(CONTENT_SECURITY_POLICY.contains("frame-src 'self'"));
        assert!(CONTENT_SECURITY_POLICY.contains("frame-ancestors 'self'"));
        assert!(!CONTENT_SECURITY_POLICY.contains("'unsafe-eval'"));
        assert!(!CONTENT_SECURITY_POLICY.contains("'wasm-unsafe-eval'"));
    }

    #[tokio::test]
    async fn browser_security_headers_cover_all_console_responses() {
        use tower::ServiceExt;

        let _guard = env_lock();
        std::env::remove_var(CONSOLE_DEV_PATH_ENV);
        std::env::remove_var(super::CONSOLE_ALLOWED_ORIGINS_ENV);

        for (method, uri, expected_status) in [
            (axum::http::Method::GET, "/", axum::http::StatusCode::SEE_OTHER),
            (axum::http::Method::GET, "/console", axum::http::StatusCode::OK),
            (axum::http::Method::HEAD, "/console", axum::http::StatusCode::OK),
            (
                axum::http::Method::GET,
                "/console-assets/CueCrux-Arc-Loop.png",
                axum::http::StatusCode::OK,
            ),
            (
                axum::http::Method::GET,
                "/console-assets/missing.png",
                axum::http::StatusCode::NOT_FOUND,
            ),
            (axum::http::Method::GET, "/console-v2/sw.js", axum::http::StatusCode::OK),
            (
                axum::http::Method::GET,
                "/console-v2/missing.js",
                axum::http::StatusCode::NOT_FOUND,
            ),
            (
                axum::http::Method::GET,
                "/console-v2/%2E%2E",
                axum::http::StatusCode::BAD_REQUEST,
            ),
            (
                axum::http::Method::GET,
                "/console-3d/index.html",
                axum::http::StatusCode::OK,
            ),
            (
                axum::http::Method::GET,
                "/console-3d/missing.js",
                axum::http::StatusCode::NOT_FOUND,
            ),
            (axum::http::Method::GET, "/activate", axum::http::StatusCode::OK),
        ] {
            let response = super::routes(true)
                .oneshot(
                    axum::http::Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(axum::body::Body::empty())
                        .expect("build request"),
                )
                .await
                .expect("router response");
            assert_eq!(response.status(), expected_status, "unexpected status for {uri}");
            assert_browser_security_headers(response.headers());
        }

        let preflight = super::routes(true)
            .oneshot(
                axum::http::Request::builder()
                    .method("OPTIONS")
                    .uri("/console")
                    .header(axum::http::header::ORIGIN, "https://crux.cuecrux.com")
                    .header(axum::http::header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .header(axum::http::header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
                    .body(axum::body::Body::empty())
                    .expect("build preflight request"),
            )
            .await
            .expect("preflight response");
        assert_eq!(preflight.status(), axum::http::StatusCode::OK);
        assert_browser_security_headers(preflight.headers());
        assert_eq!(
            preflight
                .headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|value| value.to_str().ok()),
            Some("https://crux.cuecrux.com"),
            "security middleware must preserve CORS preflight headers"
        );
    }

    #[test]
    fn desktop_proxy_browser_security_policy_matches_daemon() {
        let normalized_desktop = DESKTOP_PROXY_SOURCE
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        let normalized_csp = CONTENT_SECURITY_POLICY
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>()
            .to_ascii_lowercase();
        assert!(
            normalized_desktop.contains(&format!("constcontent_security_policy:&str=\"{normalized_csp}\";")),
            "desktop proxy CSP must match the daemon policy byte-for-byte"
        );
        assert!(
            normalized_desktop.contains("constbrowser_security_headers:[(&str,&str);7]"),
            "desktop proxy must expose the same seven canonical headers"
        );
        assert!(
            normalized_desktop.contains("(\"content-security-policy\",content_security_policy)"),
            "desktop proxy must source CSP from its parity-checked constant"
        );
        for (name, value) in BROWSER_SECURITY_HEADERS.into_iter().skip(1) {
            let normalized_value = value
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect::<String>()
                .to_ascii_lowercase();
            let compact = format!("(\"{name}\",\"{normalized_value}\")");
            let compact_with_trailing_comma = format!("(\"{name}\",\"{normalized_value}\",)");
            assert!(
                normalized_desktop.contains(&compact) || normalized_desktop.contains(&compact_with_trailing_comma),
                "desktop proxy header {name} must match the daemon value"
            );
        }
    }

    #[test]
    fn console_serves_v2_shell_unconditionally() {
        // The legacy console is removed; `/console` always serves the v2 shell
        // (embedded, no dev-path override in effect).
        let _guard = env_lock();
        std::env::remove_var(CONSOLE_DEV_PATH_ENV);
        let body = resolve_console_body();
        assert_eq!(&*body, CONSOLE_V2_HTML, "/console must serve the v2 shell");
    }

    // Locate `node` for the console-smoke runner: PATH first (CI + most dev
    // machines), then a couple of common absolute locations.
    fn find_node() -> Option<std::path::PathBuf> {
        use std::process::Command;
        let on_path = Command::new("node")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if on_path {
            return Some(std::path::PathBuf::from("node"));
        }
        ["/usr/bin/node", "/usr/local/bin/node"]
            .into_iter()
            .map(std::path::PathBuf::from)
            .find(|p| p.exists())
    }

    // Run the console v2 node/jsdom smoke (console/v2/smoke.cjs) as part of the
    // ordinary `cargo test` gate. The smoke asserts runtime behaviour the
    // include_str! structural tests cannot — the capability-descriptor
    // conformance, two-profile anti-501 guard, plan-tree honesty, and the
    // gated-mutation choke point. It was previously NOT enforced by CI (it is a
    // standalone node script), which let two console regressions ship on
    // additive daemon changes (the M5b Settings under-render and the
    // runtime-capability schema over-bump). Wiring it here makes it mandatory
    // wherever `node` is available (every dev machine and the node-capable CI
    // runner). It graceful-skips when node is absent so a node-less runner never
    // falsely blocks — the eprintln documents how to make it hard-mandatory.
    #[test]
    fn console_v2_smoke_cjs_passes() {
        use std::process::Command;
        let Some(node) = find_node() else {
            eprintln!(
                "SKIP console_v2_smoke_cjs_passes: `node` not found on PATH. The console \
                 smoke is enforced on every machine with node; to make it mandatory in CI, \
                 ensure the Rust test runner has node available (e.g. actions/setup-node)."
            );
            return;
        };
        let smoke = concat!(env!("CARGO_MANIFEST_DIR"), "/console/v2/smoke.cjs");
        let output = match Command::new(node).arg(smoke).output() {
            Ok(output) => output,
            Err(err) => panic!("failed to spawn node for the console v2 smoke: {err}"),
        };
        assert!(
            output.status.success(),
            "console/v2/smoke.cjs failed (exit {:?}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn activate_tenant_options_are_text_only() {
        use std::io::Write;
        use std::process::{Command, Stdio};

        assert!(
            !ACTIVATE_HTML.contains("innerHTML"),
            "/activate must not parse tenant-controlled values as HTML"
        );
        for required in [
            "document.createElement('option')",
            "option.textContent = label",
            "select.replaceChildren()",
        ] {
            assert!(
                ACTIVATE_HTML.contains(required),
                "/activate safe option construction is missing: {required}"
            );
        }

        let Some(node) = find_node() else {
            eprintln!(
                "SKIP activate_tenant_options_are_text_only runtime smoke: `node` not found on PATH. \
                 The structural no-innerHTML assertion still ran; install node to exercise hostile \
                 tenant values against the mock DOM."
            );
            return;
        };
        let smoke = concat!(env!("CARGO_MANIFEST_DIR"), "/console/activate-dom-smoke.cjs");
        let mut child = Command::new(node)
            .arg(smoke)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|err| panic!("failed to spawn node for the /activate DOM smoke: {err}"));
        child
            .stdin
            .take()
            .expect("node smoke stdin")
            .write_all(ACTIVATE_HTML.as_bytes())
            .expect("write /activate HTML to node smoke");
        let output = child.wait_with_output().expect("wait for /activate DOM smoke");
        assert!(
            output.status.success(),
            "console/activate-dom-smoke.cjs failed (exit {:?}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn console_v2_shell_has_licence_header_and_no_external_runtime_deps() {
        // Apache-2.0 licence header carried in the leading HTML comment.
        assert!(
            CONSOLE_V2_HTML.contains("Licensed under the Apache License, Version 2.0."),
            "v2 shell must carry the Apache-2.0 licence header"
        );
        // Same no-external-runtime-deps posture as the console shell.
        for blocked in [
            r#"<script src="http"#,
            r#"<link rel="stylesheet" href="http"#,
            r#"<iframe src="http"#,
            "unpkg.com",
            "jsdelivr.net",
            "cdnjs.cloudflare",
            "cdn.jsdelivr",
            "fonts.googleapis",
        ] {
            assert!(
                !CONSOLE_V2_HTML.contains(blocked),
                "v2 shell has external runtime dependency: {blocked}"
            );
        }
        // Same-origin plan-driven boot + a11y guardrails are present.
        for required in [
            "/v1/console/summary",
            "/v1/version",
            "crux.console.theme",
            "data-requires=\"operator\"",
            "prefers-reduced-motion",
            "focus-visible",
            // M5 PWA + phone tier.
            "rel=\"manifest\"",
            "/console-v2/manifest.webmanifest",
            "name=\"theme-color\"",
            "serviceWorker.register('/console-v2/sw.js",
            "id=\"tabbar\"",
            "SW_REV",
            "safe-area-inset",
            "min-height: 44px",
        ] {
            assert!(
                CONSOLE_V2_HTML.contains(required),
                "v2 shell missing expected marker: {required}"
            );
        }
        // The module split is wired: the shell loads the same-origin modules
        // (api.js first — pages/render read window.CruxApi).
        for required in ["/console-v2/api.js", "/console-v2/pages.js", "/console-v2/render.js"] {
            assert!(
                CONSOLE_V2_HTML.contains(required),
                "v2 shell must load the module: {required}"
            );
        }
    }

    // ---- Unified Shell Console v2 modules (M1) -----------------------------

    #[test]
    fn console_v2_modules_carry_licence_and_no_external_runtime_deps() {
        // Every v2 file keeps the Apache-2.0 header + the no-external-runtime-deps posture.
        for (name, body) in [
            ("pages.js", CONSOLE_V2_PAGES_JS),
            ("render.js", CONSOLE_V2_RENDER_JS),
            ("api.js", CONSOLE_V2_API_JS),
        ] {
            assert!(
                body.contains("Licensed under the Apache License, Version 2.0."),
                "{name} must carry the Apache-2.0 licence header"
            );
            // Block remote loaders + CDN hosts. Bare http(s) literals are NOT
            // blocked — the embedding-endpoint placeholder (`http://localhost:…`)
            // is display text, not a runtime dependency (same as the legacy console).
            for blocked in [
                "src=\"http",
                "from \"http",
                "from 'http",
                "import(\"http",
                "import('http",
                "unpkg.com",
                "jsdelivr.net",
                "cdnjs.cloudflare",
                "cdn.jsdelivr",
                "fonts.googleapis",
            ] {
                assert!(
                    !body.contains(blocked),
                    "{name} has an external runtime dependency marker: {blocked}"
                );
            }
        }
    }

    #[test]
    fn console_v2_modules_expose_the_expected_surface() {
        // pages.js carries all 26 legacy ids + the mutating-action gate list.
        for id in [
            "cx-overview",
            "cx-activity",
            "cx-cost",
            "cx-projects",
            "cx-work",
            "cx-usage",
            "cx-documents",
            "cx-gates",
            "cx-review",
            "cx-coord",
            "cx-sessions",
            "cx-orchestrators",
            "cx-punchcards",
            "cx-passport",
            "cx-identity",
            "cx-receipts",
            "cx-mediation",
            "cx-workbench",
            "cx-integrations",
            "cx-extensions",
            "cx-facts",
            "cx-memory",
            "cx-tenants",
            "cx-lane-weights",
            "cx-settings",
            "cx-raw",
        ] {
            assert!(CONSOLE_V2_PAGES_JS.contains(id), "pages.js missing legacy id: {id}");
        }
        assert!(
            CONSOLE_V2_PAGES_JS.contains("MUTATING_ACTIONS"),
            "pages.js must expose MUTATING_ACTIONS as the posture-gate source of truth"
        );
        // render.js implements the DSL control types + the posture gate.
        for required in ["CONTROL_TYPES", "applyMutationGate", "wired in M3+", "data-requires"] {
            assert!(
                CONSOLE_V2_RENDER_JS.contains(required),
                "render.js missing expected marker: {required}"
            );
        }
    }

    #[test]
    fn console_v2_linkgraph_renderer_module_is_self_contained() {
        // ExecPlan wikicrux-link-graph-explorer M4: the renderer is a client-only
        // ESM module (custom three.js r165). Apache-2.0 header + public API + the vendored
        // three specifier + zero external runtime deps (T.5).
        assert!(
            CONSOLE_V2_LINKGRAPH_MJS.contains("Licensed under the Apache License, Version 2.0."),
            "linkgraph-renderer.mjs must carry the Apache-2.0 licence header"
        );
        assert!(
            CONSOLE_V2_LINKGRAPH_MJS.contains("import * as THREE from 'three'"),
            "renderer must import the bare `three` specifier (resolved by the shell import map to the vendored r165)"
        );
        for api in ["mount", "setData", "expandData", "setTheme", "onNodeClick", "destroy"] {
            assert!(
                CONSOLE_V2_LINKGRAPH_MJS.contains(api),
                "renderer must expose the shared public API method: {api}"
            );
        }
        // No external runtime deps: no remote loader / CDN host / http(s) import.
        for blocked in [
            "from \"http",
            "from 'http",
            "import(\"http",
            "import('http",
            "unpkg.com",
            "jsdelivr.net",
            "cdnjs.cloudflare",
            "cdn.jsdelivr",
            "fonts.googleapis",
        ] {
            assert!(
                !CONSOLE_V2_LINKGRAPH_MJS.contains(blocked),
                "linkgraph-renderer.mjs has an external runtime dependency marker: {blocked}"
            );
        }
    }

    #[test]
    fn console_v2_shell_wires_the_link_graph_import_map() {
        // The import map maps `three` to the already-vendored r165 (same-origin,
        // no CDN) and must precede any module load (it lives in <head>).
        assert!(
            CONSOLE_V2_HTML.contains(r#"<script type="importmap">"#),
            "shell must carry an import map for the link-graph renderer"
        );
        assert!(
            CONSOLE_V2_HTML.contains("/console-3d/vendor/three.module.min.js"),
            "shell import map must point `three` at the vendored r165"
        );
        assert!(
            CONSOLE_V2_HTML.contains("destId === 'linkgraph'") && CONSOLE_V2_HTML.contains("renderLinkGraph"),
            "shell must route the linkgraph destination to render.renderLinkGraph"
        );
    }

    #[tokio::test]
    async fn console_v2_asset_route_serves_the_modules() {
        use tower::ServiceExt;
        let _guard = env_lock();
        std::env::remove_var(CONSOLE_DEV_PATH_ENV);
        for (uri, needle) in [
            ("/console-v2/pages.js", "MUTATING_ACTIONS"),
            ("/console-v2/render.js", "CONTROL_TYPES"),
            ("/console-v2/linkgraph-renderer.mjs", "createLinkGraphRenderer"),
        ] {
            let resp = super::routes(true)
                .oneshot(
                    axum::http::Request::builder()
                        .method("GET")
                        .uri(uri)
                        .body(axum::body::Body::empty())
                        .expect("build request"),
                )
                .await
                .expect("router response");
            assert_eq!(resp.status(), axum::http::StatusCode::OK, "{uri} should be served");
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .expect("read body");
            assert!(
                String::from_utf8(bytes.to_vec()).expect("utf8 body").contains(needle),
                "{uri} body should contain {needle}"
            );
        }
    }

    // ---- Unified Shell Console v2 PWA + phone tier (M5) --------------------

    /// Pull the `SW_REV = '<value>'` literal from a source string (matches both
    /// `const SW_REV = '…'` in sw.js and `var SW_REV = '…'` in shell.html).
    fn sw_rev(src: &str) -> Option<&str> {
        let marker = "SW_REV = '";
        let start = src.find(marker)? + marker.len();
        let rest = &src[start..];
        let end = rest.find('\'')?;
        Some(&rest[..end])
    }

    #[test]
    fn console_v2_pwa_assets_carry_licence_and_markers() {
        // sw.js + icon.svg can carry the Apache-2.0 header as a comment; assert it plus
        // their structural markers. (manifest.webmanifest is pure JSON — no
        // comments — so its header is intentionally absent; markers checked below.)
        for (name, body) in [("sw.js", CONSOLE_V2_SW_JS), ("icon.svg", CONSOLE_V2_ICON_SVG)] {
            assert!(
                body.contains("Licensed under the Apache License, Version 2.0."),
                "{name} must carry the Apache-2.0 licence header"
            );
        }
        for required in [
            "const SW_REV",
            "const CACHE_NAME",
            "const APP_SHELL",
            "addEventListener('fetch'",
            "/v1/",
        ] {
            assert!(CONSOLE_V2_SW_JS.contains(required), "sw.js missing marker: {required}");
        }
        for required in ["viewBox=\"0 0 512 512\"", "#060A12", "Crux Console"] {
            assert!(
                CONSOLE_V2_ICON_SVG.contains(required),
                "icon.svg missing marker: {required}"
            );
        }
        for required in [
            "\"name\"",
            "\"Crux Console\"",
            "\"start_url\"",
            "\"/console\"",
            "\"standalone\"",
            "\"icons\"",
        ] {
            assert!(
                CONSOLE_V2_MANIFEST.contains(required),
                "manifest missing marker: {required}"
            );
        }
    }

    #[test]
    fn console_v2_sw_rev_matches_shell() {
        // Bump-together discipline: the no-build cache key lives in two files; a
        // drift between them means the cache never invalidates. Assert equality.
        let sw = sw_rev(CONSOLE_V2_SW_JS).expect("sw.js SW_REV literal");
        let shell = sw_rev(CONSOLE_V2_HTML).expect("shell.html SW_REV literal");
        assert_eq!(
            sw, shell,
            "sw.js and shell.html SW_REV must be bumped together (sw={sw} shell={shell})"
        );
    }

    #[test]
    fn console_v2_sw_never_caches_control_plane() {
        // Compliance invariant: /v1/* is network-only, never cached. The SW must
        // bypass it, and no cache write (addAll / .put) may target a /v1/ path.
        assert!(
            CONSOLE_V2_SW_JS.contains("startsWith('/v1/')"),
            "sw.js must bypass /v1/ (network-only passthrough)"
        );
        for line in CONSOLE_V2_SW_JS.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue; // comments may legitimately mention /v1/ and cache.put
            }
            let is_cache_write = trimmed.contains("addAll(") || trimmed.contains(".put(");
            assert!(
                !(is_cache_write && trimmed.contains("/v1/")),
                "sw.js must never cache a /v1/ path: {line}"
            );
        }
    }

    #[tokio::test]
    async fn console_v2_pwa_asset_routes_serve_with_content_types() {
        use tower::ServiceExt;
        let _guard = env_lock();
        std::env::remove_var(CONSOLE_DEV_PATH_ENV);
        for (uri, content_type, needle) in [
            (
                "/console-v2/sw.js",
                "application/javascript; charset=utf-8",
                "APP_SHELL",
            ),
            (
                "/console-v2/manifest.webmanifest",
                "application/manifest+json; charset=utf-8",
                "\"standalone\"",
            ),
            ("/console-v2/icon.svg", "image/svg+xml; charset=utf-8", "<svg"),
        ] {
            let resp = super::routes(true)
                .oneshot(
                    axum::http::Request::builder()
                        .method("GET")
                        .uri(uri)
                        .body(axum::body::Body::empty())
                        .expect("build request"),
                )
                .await
                .expect("router response");
            assert_eq!(resp.status(), axum::http::StatusCode::OK, "{uri} should be served");
            assert_eq!(
                resp.headers()
                    .get(axum::http::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok()),
                Some(content_type),
                "{uri} should carry content-type {content_type}"
            );
            // The service worker needs the scope-widening header.
            if uri.ends_with("sw.js") {
                assert_eq!(
                    resp.headers()
                        .get("service-worker-allowed")
                        .and_then(|v| v.to_str().ok()),
                    Some("/console"),
                    "sw.js must be served with Service-Worker-Allowed: /console"
                );
            }
            let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .expect("read body");
            assert!(
                String::from_utf8(bytes.to_vec()).expect("utf8 body").contains(needle),
                "{uri} body should contain {needle}"
            );
        }
    }

    // ---- CORS allowlist (ExecPlan crux-console-public-exposure, M5) --------

    // Render a `Vec<HeaderValue>` origin list back to comparable strings.
    fn origin_strings(origins: &[axum::http::HeaderValue]) -> Vec<String> {
        origins
            .iter()
            .map(|v| v.to_str().expect("origin is ascii").to_string())
            .collect()
    }

    #[test]
    fn claude_desktop_bundle_is_embedded_and_is_a_zip() {
        // The bundle is a committed build artifact, so a truncated or
        // LFS-pointer-shaped checkout would otherwise only surface as a
        // Claude Desktop install failure on someone's laptop.
        let bytes = super::embedded_asset("crux.mcpb").expect("crux.mcpb is embedded");
        assert_eq!(
            &bytes[..4],
            b"PK\x03\x04",
            "an .mcpb is a zip archive; got magic {:?}",
            &bytes[..4]
        );
        assert!(
            bytes.len() > 500_000,
            "bundle vendors mcp-remote and should be ~1.5MB, got {} bytes",
            bytes.len()
        );
    }

    #[test]
    fn mcpb_asset_is_served_as_a_named_download() {
        // Desktop only accepts the `.mcpb` extension, so the filename has to
        // survive the download — an octet-stream with no disposition leaves the
        // browser to guess and it guesses wrong.
        let response = super::asset_response("crux.mcpb", vec![b'P', b'K', 3, 4]);
        let headers = response.headers();
        assert_eq!(
            headers.get(super::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
            Some("application/octet-stream")
        );
        assert_eq!(
            headers
                .get(super::header::CONTENT_DISPOSITION)
                .and_then(|v| v.to_str().ok()),
            Some("attachment; filename=\"crux.mcpb\"")
        );
        // Images keep rendering inline — the disposition is mcpb-only.
        let png = super::asset_response("CueCrux-Arc-Loop.png", vec![0x89, b'P', b'N', b'G']);
        assert!(png.headers().get(super::header::CONTENT_DISPOSITION).is_none());
    }

    #[test]
    fn allowed_origins_empty_input_falls_back_to_defaults() {
        // Unset / blank / comma-and-whitespace-only all resolve to the
        // production defaults — never an empty (deny-all) or wildcard list.
        for raw in ["", "   ", ",", " , , ", "\t,\n"] {
            let origins = origin_strings(&super::resolve_allowed_origins(raw));
            assert_eq!(
                origins,
                vec![
                    "https://crux.cuecrux.com".to_string(),
                    "http://100.70.12.73".to_string(),
                    "http://crux".to_string(),
                ],
                "input {raw:?} should fall back to the default allowlist"
            );
        }
    }

    #[test]
    fn allowed_origins_parses_and_trims_a_custom_list() {
        // Trimming, dropped empty entries (leading/trailing/interior commas),
        // and order preservation.
        let origins = origin_strings(&super::resolve_allowed_origins(
            "  https://a.example.com ,http://localhost:5173, ,https://b.example.com,",
        ));
        assert_eq!(
            origins,
            vec![
                "https://a.example.com".to_string(),
                "http://localhost:5173".to_string(),
                "https://b.example.com".to_string(),
            ]
        );
    }

    #[test]
    fn allowed_origins_skips_invalid_entries_but_keeps_valid_ones() {
        // A control char makes an invalid HeaderValue; it is dropped, the valid
        // neighbour survives, and the list does not collapse to the defaults.
        let origins = origin_strings(&super::resolve_allowed_origins(
            "https://ok.example.com,bad\u{7f}origin",
        ));
        assert_eq!(origins, vec!["https://ok.example.com".to_string()]);
    }

    #[test]
    fn allowed_origins_never_contains_wildcard() {
        // The whole point of M5: the resolver must never emit a `*` origin,
        // whatever the input.
        for raw in ["", "*", "https://x.example.com,*", "  *  "] {
            let origins = origin_strings(&super::resolve_allowed_origins(raw));
            assert!(
                !origins.iter().any(|o| o == "*"),
                "input {raw:?} must not yield a wildcard origin (got {origins:?})"
            );
        }
    }

    #[test]
    fn allowed_origins_rejects_opaque_and_non_web_schemes() {
        // `null`, `file:`, `data:`, bare hosts, and scheme-only strings are all
        // dropped — a configured `null` would otherwise match `Origin: null`
        // from sandboxed iframes / local-file contexts. A well-formed http(s)
        // neighbour in the same list survives.
        for bad in [
            "null",
            "file://x",
            "data:text/html",
            "example.com",
            "https://",
            "ftp://x.example.com",
        ] {
            let origins = origin_strings(&super::resolve_allowed_origins(bad));
            // Sole bad entry => empty parse => defaults; assert the bad token
            // itself never appears.
            assert!(
                !origins.iter().any(|o| o == bad),
                "input {bad:?} must not appear in the resolved allowlist (got {origins:?})"
            );
        }
        // Bad entry dropped, good neighbour kept (no collapse to defaults).
        let mixed = origin_strings(&super::resolve_allowed_origins("null, https://ok.example.com"));
        assert_eq!(mixed, vec!["https://ok.example.com".to_string()]);
    }

    // Parses the configured list directly instead of round-tripping through the
    // process environment.
    //
    // This test used to `set_var` the allowlist and read it back through
    // `console_allowed_origins()`, and flaked: it observed the built-in defaults
    // instead of the value it had just set, *while holding `env_lock()`*. The
    // mutex is not the problem. `setenv` may reallocate the environment block, and
    // a concurrent `getenv` anywhere in this 2000-plus-test binary can then read a
    // stale pointer — a hazard no Rust-level lock can fence, and precisely why
    // `std::env::set_var` is `unsafe` from the 2024 edition. Serialising the
    // handful of tests that opt into `env_lock()` never covered the other
    // thousands that merely read env vars of their own.
    //
    // `console_allowed_origins()` is a one-line wrapper — `std::env::var(..)
    // .unwrap_or_default()` feeding this parser — so the parsing contract is fully
    // covered here, and the wrapper carries no logic worth a flaky test.
    #[test]
    fn allowed_origins_parses_a_configured_list() {
        let origins = origin_strings(&super::resolve_allowed_origins(
            "https://console.example.test, http://localhost:3000",
        ));
        assert_eq!(
            origins,
            vec![
                "https://console.example.test".to_string(),
                "http://localhost:3000".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn cors_reflects_allowlisted_origin_and_rejects_others() {
        use tower::ServiceExt;
        let _guard = env_lock();
        // Use the built-in defaults for a deterministic allowlist.
        std::env::remove_var(super::CONSOLE_ALLOWED_ORIGINS_ENV);

        // An allowlisted origin is reflected in Access-Control-Allow-Origin...
        let resp = super::routes(true)
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/console")
                    .header(axum::http::header::ORIGIN, "https://crux.cuecrux.com")
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router response");
        assert_eq!(
            resp.headers()
                .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("https://crux.cuecrux.com"),
            "an allowlisted origin must be reflected exactly (never a wildcard)"
        );

        // ...and a non-allowlisted origin gets NO allow-origin header at all,
        // and certainly not a wildcard.
        let resp = super::routes(true)
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/console")
                    .header(axum::http::header::ORIGIN, "https://evil.example.com")
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router response");
        let allow_origin = resp
            .headers()
            .get(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .and_then(|v| v.to_str().ok());
        assert!(
            allow_origin.is_none(),
            "a non-allowlisted origin must not receive an Access-Control-Allow-Origin header (got {allow_origin:?})"
        );
    }

    #[tokio::test]
    async fn cors_preflight_names_authorization_header() {
        use tower::ServiceExt;
        let _guard = env_lock();
        std::env::remove_var(super::CONSOLE_ALLOWED_ORIGINS_ENV);
        // Preflight from an allowlisted origin requesting an Authorization header:
        // the `*` header wildcard would NOT satisfy the browser here, so assert
        // `Authorization` is named explicitly in Access-Control-Allow-Headers.
        let resp = super::routes(true)
            .oneshot(
                axum::http::Request::builder()
                    .method("OPTIONS")
                    .uri("/console")
                    .header(axum::http::header::ORIGIN, "https://crux.cuecrux.com")
                    .header(axum::http::header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .header(axum::http::header::ACCESS_CONTROL_REQUEST_HEADERS, "authorization")
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router response");
        let allow_headers = resp
            .headers()
            .get(axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        assert!(
            allow_headers.contains("authorization"),
            "preflight must name `authorization` explicitly (got {allow_headers:?})"
        );
    }
}
