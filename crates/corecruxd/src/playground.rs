// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use tower_http::cors::CorsLayer;

const PLAYGROUND_HTML: &str = include_str!("../playground/index.html");

async fn serve_playground() -> impl IntoResponse {
    Html(PLAYGROUND_HTML)
}

pub fn routes() -> Router {
    Router::new()
        .route("/playground", get(serve_playground))
        .layer(CorsLayer::permissive())
}
