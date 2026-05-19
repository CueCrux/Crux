// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Embedded `/playground` HTML asset server — small static-file router for the in-process console.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use axum::extract::Path as AxumPath;
use axum::http::header;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use tower_http::cors::CorsLayer;

const PLAYGROUND_HTML: &str = include_str!("../playground/index.html");
const CONSOLE_DEV_PATH_ENV: &str = "CORECRUXD_CONSOLE_DEV_PATH";

// Bundled PNG assets — embedded so the binary can serve them with no on-disk
// dependency. Dev override (CORECRUXD_CONSOLE_DEV_PATH) falls back to reading
// from `<dev>/assets/<name>` so design iterations don't need a rebuild.
const ASSET_LOGO_DARK: &[u8] = include_bytes!("../playground/assets/CueCrux-Arc-Loop.png");
const ASSET_LOGO_WHITE: &[u8] = include_bytes!("../playground/assets/CueCrux-Arc-Loop-White.png");

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

pub fn routes(enabled: bool) -> Router {
    if !enabled {
        return Router::new();
    }

    Router::new()
        .route("/", get(redirect_to_console))
        .route("/console", get(serve_console))
        .route("/playground", get(serve_console))
        .route("/console-assets/{name}", get(serve_console_asset))
        .layer(CorsLayer::permissive())
}

fn resolve_console_html() -> Cow<'static, str> {
    match dev_html_override() {
        Some(html) => Cow::Owned(html),
        None => Cow::Borrowed(PLAYGROUND_HTML),
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
                target: "corecruxd::playground",
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
    use super::{dev_html_override, resolve_console_html, CONSOLE_DEV_PATH_ENV, PLAYGROUND_HTML};
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
            PLAYGROUND_HTML.len() < 480 * 1024,
            "embedded console shell should stay below 480KB raw HTML/CSS/JS (currently {} bytes)",
            PLAYGROUND_HTML.len()
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
                PLAYGROUND_HTML.contains(required),
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
                !PLAYGROUND_HTML.contains(blocked),
                "external runtime dependency marker found: {blocked}"
            );
        }
    }

    #[test]
    fn dev_override_unset_returns_embedded_html() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var(CONSOLE_DEV_PATH_ENV);
        let html = resolve_console_html();
        assert_eq!(&*html, PLAYGROUND_HTML);
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
