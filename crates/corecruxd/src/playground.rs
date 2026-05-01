// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use tower_http::cors::CorsLayer;

const PLAYGROUND_HTML: &str = include_str!("../playground/index.html");

async fn serve_console() -> impl IntoResponse {
    Html(PLAYGROUND_HTML)
}

pub fn routes(enabled: bool) -> Router {
    if !enabled {
        return Router::new();
    }

    Router::new()
        .route("/console", get(serve_console))
        .route("/playground", get(serve_console))
        .layer(CorsLayer::permissive())
}
