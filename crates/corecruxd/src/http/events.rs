// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Server-Sent Events endpoint for real-time store mutation streaming.

use std::collections::HashSet;
use std::convert::Infallible;

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::auth::require_http_scopes;

use super::AppState;

#[derive(serde::Deserialize, Default)]
pub(super) struct EventStreamParams {
    /// Comma-separated event types to filter (e.g., `fact.stored,session.stored`).
    /// If omitted, all events are streamed.
    types: Option<String>,
}

/// Stream real-time mutation events via Server-Sent Events.
#[utoipa::path(
    get,
    path = "/v1/events/stream",
    tag = "Events",
    params(
        ("types" = Option<String>, Query, description = "Comma-separated event types to filter")
    ),
    responses(
        (status = 200, description = "SSE event stream"),
        (status = 401, description = "Unauthorized"),
    ),
    security(("bearer_auth" = []))
)]
pub(super) async fn event_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<EventStreamParams>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        return problem.into_response();
    }

    let filter: Option<HashSet<String>> = params
        .types
        .map(|t| t.split(',').map(|s| s.trim().to_string()).collect());

    let rx = state.event_bus.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |result| {
        let filter = filter.clone();
        match result {
            Ok(event) => {
                let event_type = match &event {
                    corecrux_memory::events::CruxEvent::FactStored { .. } => "fact.stored",
                    corecrux_memory::events::CruxEvent::FactDeleted { .. } => "fact.deleted",
                    corecrux_memory::events::CruxEvent::SessionStored { .. } => "session.stored",
                    corecrux_memory::events::CruxEvent::SessionDeleted { .. } => "session.deleted",
                };
                if let Some(ref f) = filter {
                    if !f.contains(event_type) {
                        return None;
                    }
                }
                let data = serde_json::to_string(&event).ok()?;
                Some(Ok::<_, Infallible>(Event::default().event(event_type).data(data)))
            }
            Err(_lagged) => {
                // Subscriber fell behind — skip lost events and continue.
                None
            }
        }
    });

    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(std::time::Duration::from_secs(15)))
        .into_response()
}
