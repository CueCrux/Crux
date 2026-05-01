// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::get;
use axum::Router;
use tower_http::cors::CorsLayer;

const PLAYGROUND_HTML: &str = include_str!("../playground/index.html");

async fn serve_console() -> impl IntoResponse {
    Html(PLAYGROUND_HTML)
}

async fn redirect_to_console() -> impl IntoResponse {
    Redirect::to("/console")
}

pub fn routes(enabled: bool) -> Router {
    if !enabled {
        return Router::new();
    }

    Router::new()
        .route("/", get(redirect_to_console))
        .route("/console", get(serve_console))
        .route("/playground", get(serve_console))
        .layer(CorsLayer::permissive())
}

#[cfg(test)]
mod tests {
    use super::PLAYGROUND_HTML;

    #[test]
    fn console_asset_budget_stays_lightweight() {
        assert!(
            PLAYGROUND_HTML.len() < 100 * 1024,
            "embedded console shell should stay below 100KB raw HTML/CSS/JS"
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
        for blocked in ["https://", "http://cdn", "unpkg.com", "jsdelivr.net"] {
            assert!(
                !PLAYGROUND_HTML.contains(blocked),
                "external dependency marker found: {blocked}"
            );
        }
    }
}
