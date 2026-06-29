// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Embedded console HTML asset server — small static-file router for the in-process console.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use axum::extract::Path as AxumPath;
use axum::http::header;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use tower_http::cors::CorsLayer;

const CONSOLE_HTML: &str = include_str!("../console/index.html");
// Activity log human lane (ExecPlan crux-dual-surface-activity-log-2026-06-18,
// M3). A new self-contained page on the embedded console, served at
// `/console/activity`. The page itself is inert unless the daemon has
// `CORECRUXD_FEATURE_ACTIVITY_LOG=1` (its API calls 404 otherwise).
const ACTIVITY_HTML: &str = include_str!("../console/activity.html");
const CONSOLE_DEV_PATH_ENV: &str = "CORECRUXD_CONSOLE_DEV_PATH";

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

fn embedded_asset(name: &str) -> Option<&'static [u8]> {
    match name {
        "CueCrux-Arc-Loop.png" => Some(ASSET_LOGO_DARK),
        "CueCrux-Arc-Loop-White.png" => Some(ASSET_LOGO_WHITE),
        _ => None,
    }
}

async fn serve_console() -> impl IntoResponse {
    Html(resolve_console_html().into_owned())
}

/// Activity log human-lane page (M3), served at `/console/activity`. A dev
/// override (`CORECRUXD_CONSOLE_DEV_PATH`) reads `activity.html` next to the
/// console index so the page can be iterated without a rebuild.
async fn serve_activity() -> impl IntoResponse {
    if let Some(dev_path) = std::env::var(CONSOLE_DEV_PATH_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        let file_path = resolve_dev_html_path(Path::new(dev_path.trim())).with_file_name("activity.html");
        if let Ok(contents) = std::fs::read_to_string(&file_path) {
            return Html(contents).into_response();
        }
    }
    Html(ACTIVITY_HTML).into_response()
}

async fn redirect_to_console() -> impl IntoResponse {
    Redirect::to("/console")
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
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        bytes,
    )
        .into_response()
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

pub fn routes(enabled: bool) -> Router {
    if !enabled {
        return Router::new();
    }

    Router::new()
        .route("/", get(redirect_to_console))
        .route("/console", get(serve_console))
        .route("/console/activity", get(serve_activity))
        .route("/console-assets/{name}", get(serve_console_asset))
        .route("/console-3d/{*path}", get(serve_console3d))
        // Device-grant approval page (ExecPlan crux-unified-login-rails, M3).
        .route("/activate", get(serve_activate))
        .layer(CorsLayer::permissive())
}

/// `/activate` — operator approval page for the device-authorization grant.
/// The form POSTs to `/v1/auth/device/approve` on the same origin; that endpoint
/// is gated to an authenticated console admin (`admin:write`) and the
/// approver-chosen tenant + scopes are what get minted (threat ref T.1).
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
  body { font-family: system-ui, sans-serif; max-width: 32rem; margin: 3rem auto; padding: 0 1rem; }
  h1 { font-size: 1.3rem; }
  label { display: block; margin: 0.75rem 0 0.25rem; font-weight: 600; }
  input { width: 100%; padding: 0.5rem; font-size: 1rem; box-sizing: border-box; }
  .row { display: flex; gap: 0.75rem; margin-top: 1.25rem; }
  button { flex: 1; padding: 0.6rem; font-size: 1rem; cursor: pointer; border-radius: 6px; border: 1px solid #888; }
  button.approve { background: #1a7f37; color: #fff; border-color: #1a7f37; }
  button.deny { background: #fff; color: #b00; border-color: #b00; }
  #result { margin-top: 1rem; padding: 0.75rem; border-radius: 6px; white-space: pre-wrap; }
  .ok { background: #e6ffed; } .err { background: #ffeef0; }
  small { color: #555; }
</style>
</head>
<body>
  <h1>Approve a device login</h1>
  <p><small>Enter the code shown by the client, choose the tenant and scopes to
  grant, then approve. Only approve codes you initiated.</small></p>
  <label for="user_code">User code</label>
  <input id="user_code" placeholder="ABCD-2345" autocomplete="off" />
  <label for="tenant_id">Tenant</label>
  <input id="tenant_id" placeholder="acme" autocomplete="off" />
  <label for="scopes">Scopes (space or comma separated)</label>
  <input id="scopes" placeholder="query:read facts:write" autocomplete="off" />
  <div class="row">
    <button class="approve" onclick="decide(false)">Approve</button>
    <button class="deny" onclick="decide(true)">Deny</button>
  </div>
  <div id="result" hidden></div>
<script>
async function decide(deny) {
  const out = document.getElementById('result');
  const scopes = document.getElementById('scopes').value.split(/[\s,]+/).filter(Boolean);
  const body = {
    user_code: document.getElementById('user_code').value.trim(),
    tenant_id: document.getElementById('tenant_id').value.trim(),
    scopes: scopes,
    deny: deny,
  };
  try {
    const resp = await fetch('/v1/auth/device/approve', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify(body),
    });
    const text = await resp.text();
    out.hidden = false;
    out.className = resp.ok ? 'ok' : 'err';
    out.textContent = (resp.ok ? 'OK — ' : ('HTTP ' + resp.status + ' — ')) + text;
  } catch (e) {
    out.hidden = false; out.className = 'err'; out.textContent = String(e);
  }
}
</script>
</body>
</html>"#;

fn resolve_console_html() -> Cow<'static, str> {
    match dev_html_override() {
        Some(html) => Cow::Owned(html),
        None => Cow::Borrowed(CONSOLE_HTML),
    }
}

fn dev_html_override() -> Option<String> {
    let raw = std::env::var(CONSOLE_DEV_PATH_ENV).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let html_path = resolve_dev_html_path(Path::new(trimmed));
    match std::fs::read_to_string(&html_path) {
        Ok(contents) => Some(contents),
        Err(err) => {
            tracing::warn!(
                target: "corecruxd::console",
                path = %html_path.display(),
                error = %err,
                "console dev override unreadable; falling back to embedded HTML"
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
    use super::{dev_html_override, resolve_console_html, CONSOLE_DEV_PATH_ENV, CONSOLE_HTML};
    use std::sync::Mutex;

    // The dev-path env var is process-global; serialise tests that mutate it.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn console_asset_budget_stays_lightweight() {
        // Budget history: 100KB → 200KB (Plan A: Projects/Work/multi-passport) →
        // 320KB (DX/GX scopes, OpenAI integration, docs panel, Vision/Goals layers) →
        // 480KB (AX scope: 20-feature agent cockpit). Still tiny by SPA standards;
        // the guard exists to catch unbounded growth, not to enforce a product
        // constraint.
        assert!(
            CONSOLE_HTML.len() < 480 * 1024,
            "embedded console shell should stay below 480KB raw HTML/CSS/JS (currently {} bytes)",
            CONSOLE_HTML.len()
        );
    }

    #[test]
    fn console_shell_has_accessibility_guardrails() {
        for required in [
            r#"<meta name="viewport" content="width=device-width, initial-scale=1">"#,
            "Skip to console content",
            "aria-live=\"polite\"",
            "prefers-reduced-motion",
            "focus-visible",
            "min-height: 44px",
        ] {
            assert!(
                CONSOLE_HTML.contains(required),
                "missing accessibility marker: {required}"
            );
        }
    }

    #[test]
    fn console_shell_has_no_external_runtime_dependencies() {
        // Block runtime-loading of external assets (scripts/styles/iframes from
        // CDNs or any remote host). Documentation `<a href="https://...">` links
        // to ecosystem sites (cuecrux.com, vaultcrux.com, memorycrux.com, etc.)
        // are FINE — they don't load anything until the user clicks them.
        for blocked in [
            r#"<script src="http"#,
            r#"<link rel="stylesheet" href="http"#,
            r#"<iframe src="http"#,
            "unpkg.com",
            "jsdelivr.net",
            "cdnjs.cloudflare",
            "cdn.jsdelivr",
        ] {
            assert!(
                !CONSOLE_HTML.contains(blocked),
                "external runtime dependency marker found: {blocked}"
            );
        }
    }

    #[test]
    fn console_lane_weights_has_deeplink_dropdown_presets_and_scoped_reset() {
        for required in [
            "function laneWeightsDeepLink()",
            "#/lane-weights",
            "tenant_id",
            "tenant_pick",
            "api('/v1/console/tenants')",
            "Stage preset",
            "Baseline defaults",
            "Graph/topology trial",
            "Reset lane weights",
            "deleteApi(path)",
            "putApi('/v1/console/corecrux/lane-weights'",
        ] {
            assert!(
                CONSOLE_HTML.contains(required),
                "missing lane-weight console marker: {required}"
            );
        }
    }

    #[test]
    fn activity_page_wires_both_lanes_and_stays_dependency_free() {
        // Capture/agent-lane endpoints + live stream are wired.
        for required in [
            "/v1/activity?",
            "/v1/activity/turn/",
            "/v1/events/stream?types=activity.appended",
            "/verify", // M2 ✓verify cross-walk badge (embedded-receipt verify endpoint)
            "token_budget",
            "CORECRUXD_FEATURE_ACTIVITY_LOG",
        ] {
            assert!(
                super::ACTIVITY_HTML.contains(required),
                "activity page missing wiring: {required}"
            );
        }
        // Same security posture as the console shell — no external runtime deps.
        for blocked in [
            r#"<script src="http"#,
            r#"<link rel="stylesheet" href="http"#,
            r#"<iframe src="http"#,
            "unpkg.com",
            "jsdelivr.net",
            "cdnjs.cloudflare",
        ] {
            assert!(
                !super::ACTIVITY_HTML.contains(blocked),
                "activity page has external runtime dependency: {blocked}"
            );
        }
        // The main console links to the new page.
        assert!(
            super::CONSOLE_HTML.contains(r#"href="/console/activity""#),
            "console shell should link to the activity page"
        );
    }

    #[test]
    fn dev_override_unset_returns_embedded_html() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var(CONSOLE_DEV_PATH_ENV);
        let html = resolve_console_html();
        assert_eq!(&*html, CONSOLE_HTML);
    }

    #[test]
    fn dev_override_reads_file_when_path_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |duration| duration.as_nanos());
        let dir = std::env::temp_dir().join(format!("corecruxd-console-dev-{nanos}"));
        std::fs::create_dir_all(&dir).expect("create dev dir");
        let html_path = dir.join("index.html");
        std::fs::write(&html_path, "<html>dev override</html>").expect("write dev html");

        std::env::set_var(CONSOLE_DEV_PATH_ENV, &dir);
        let resolved = resolve_console_html();
        std::env::remove_var(CONSOLE_DEV_PATH_ENV);

        assert_eq!(&*resolved, "<html>dev override</html>");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dev_override_falls_back_when_path_unreadable() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var(CONSOLE_DEV_PATH_ENV, "/this/path/does/not/exist/index.html");
        let result = dev_html_override();
        std::env::remove_var(CONSOLE_DEV_PATH_ENV);
        assert!(result.is_none(), "missing dev path should fall back to embedded HTML");
    }
}
