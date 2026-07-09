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
// Receipts-vs-console side-by-side demo (roadmap Production-Cutover Phase T /
// the F3 test). A self-contained page served at `/console/receipts-vs-console`:
// the left column reuses the activity-log receipt timeline (with an
// observation-feed fallback when `CORECRUXD_FEATURE_ACTIVITY_LOG` is off) and
// the right column is a clearly-labelled static mock of a typical vendor
// console. No external runtime deps, same posture as the console shell.
const RECEIPTS_VS_CONSOLE_HTML: &str = include_str!("../console/receipts-vs-console.html");
// Code-structure graph view (ExecPlan ast-polyglot-code-graph-and-repo-watch-2026-07-08,
// M8). A self-contained page served at `/console/codegraph` that renders the real
// typed code+claim graph from `/v1/projects/{id}/context-graph`. Reuses the console
// design tokens; falls back to a demo graph when the daemon endpoint is unavailable.
const CODEGRAPH_HTML: &str = include_str!("../console/codegraph.html");
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

/// Receipts-vs-console side-by-side demo, served at
/// `/console/receipts-vs-console`. Same dev-override story as the activity
/// page so the page can be iterated without a rebuild.
async fn serve_receipts_vs_console() -> impl IntoResponse {
    if let Some(dev_path) = std::env::var(CONSOLE_DEV_PATH_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        let file_path = resolve_dev_html_path(Path::new(dev_path.trim())).with_file_name("receipts-vs-console.html");
        if let Ok(contents) = std::fs::read_to_string(&file_path) {
            return Html(contents).into_response();
        }
    }
    Html(RECEIPTS_VS_CONSOLE_HTML).into_response()
}

/// Code-structure graph view (M8), served at `/console/codegraph`. Same
/// dev-override story as the activity page so the page can be iterated
/// without a rebuild.
async fn serve_codegraph() -> impl IntoResponse {
    if let Some(dev_path) = std::env::var(CONSOLE_DEV_PATH_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
    {
        let file_path = resolve_dev_html_path(Path::new(dev_path.trim())).with_file_name("codegraph.html");
        if let Ok(contents) = std::fs::read_to_string(&file_path) {
            return Html(contents).into_response();
        }
    }
    Html(CODEGRAPH_HTML).into_response()
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
        .route("/console/receipts-vs-console", get(serve_receipts_vs_console))
        .route("/console/codegraph", get(serve_codegraph))
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
function onTenantChange() {
  var add = el('tenant_sel').value === ADD_NEW;
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
    var html = list.length ? '' : '<option value="" disabled selected>No tenants yet — add one</option>';
    list.forEach(function (t) { html += '<option value="' + t + '">' + t + '</option>'; });
    html += '<option value="' + ADD_NEW + '">+ Add new tenant…</option>';
    el('tenant_sel').innerHTML = html;
    onTenantChange();
  } catch (e) { showSignin(); }
}
function currentTenant() {
  var v = el('tenant_sel').value;
  return v === ADD_NEW ? el('tenant_new').value.trim() : v;
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
    fn receipts_vs_console_demo_wires_both_columns_and_stays_dependency_free() {
        // Left column reuses the receipt-timeline + verify wiring and the
        // observation-feed fallback; right column is the labelled vendor mock.
        for required in [
            "/v1/activity?",                             // left: backfill the receipt timeline
            "/v1/activity/turn/",                        // left: row-expand to verbatim
            "/verify",                                   // left: Ed25519 verify cross-walk badge
            "/v1/observations/aggregate",                // left: fallback when the flag is off
            "/v1/events/stream?types=activity.appended", // left: live tail
            "token_budget",
            "CORECRUXD_FEATURE_ACTIVITY_LOG",  // caveat surfaced to the operator
            "CueCrux — receipts as debugging", // left column heading
            "Your vendor's free console",      // right column heading
            "No signature to verify",          // honest contrast callouts
            "No cross-agent handoff",
            "No cost-per-agent attribution",
            "Gone when you rotate the key",
        ] {
            assert!(
                super::RECEIPTS_VS_CONSOLE_HTML.contains(required),
                "receipts-vs-console page missing wiring: {required}"
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
            "cdn.jsdelivr",
        ] {
            assert!(
                !super::RECEIPTS_VS_CONSOLE_HTML.contains(blocked),
                "receipts-vs-console page has external runtime dependency: {blocked}"
            );
        }
    }

    #[tokio::test]
    async fn receipts_vs_console_route_serves_the_demo_page() {
        use tower::ServiceExt;

        let resp = super::routes(true)
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/console/receipts-vs-console")
                    .body(axum::body::Body::empty())
                    .expect("build request"),
            )
            .await
            .expect("router response");
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("read body");
        let body = String::from_utf8(bytes.to_vec()).expect("utf8 body");
        assert!(
            body.contains("CueCrux — receipts as debugging") && body.contains("Your vendor's free console"),
            "served page should contain both column headings"
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
