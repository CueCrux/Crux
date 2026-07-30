// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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

/// SSE `event:` name for a mutation event.
///
/// This MUST stay identical to the variant's `#[serde(tag = "type")]` rename in
/// [`corecrux_memory::events::CruxEvent`]: the same string travels twice on the
/// wire — once as the SSE event name and once inside the JSON `data:` payload —
/// and a client that subscribes by name would silently stop matching if the two
/// drifted. `tests::sse_names_match_the_serde_tags` pins them together.
fn event_type_name(event: &corecrux_memory::events::CruxEvent) -> &'static str {
    use corecrux_memory::events::CruxEvent;
    match event {
        CruxEvent::FactStored { .. } => "fact.stored",
        CruxEvent::FactDeleted { .. } => "fact.deleted",
        CruxEvent::SessionStored { .. } => "session.stored",
        CruxEvent::SessionDeleted { .. } => "session.deleted",
        CruxEvent::SessionArchived { .. } => "session.archived",
        CruxEvent::AuditStep { .. } => "observe.audit_step",
        CruxEvent::OrchestratorChanged { .. } => "orchestrator.changed",
        CruxEvent::PunchcardChanged { .. } => "punchcard.changed",
        CruxEvent::ActivityAppended { .. } => "activity.appended",
    }
}

/// Parse the `types=` query filter into a set of event names.
///
/// `None` (parameter omitted) means "stream everything" and is distinct from
/// `Some(empty set)`: an explicit `types=` with no names filters everything out
/// rather than falling back to unfiltered, so a client cannot accidentally
/// widen its subscription by sending a blank filter.
fn parse_type_filter(types: Option<&str>) -> Option<HashSet<String>> {
    types.map(|t| {
        t.split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    })
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
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn event_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<EventStreamParams>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["query:read"]) {
        return problem.into_response();
    }

    let filter: Option<HashSet<String>> = parse_type_filter(params.types.as_deref());

    // G19 (`Streaming-Receipts-Spec` §3/§5): the SSE event stream is
    // infinite, so every teardown is a client disconnect — the guard mints
    // a `stream_aborted` receipt on drop. Inert unless
    // CORECRUXD_STREAM_RECEIPTS=1.
    let abort_guard = super::stream_receipts::SseAbortGuard::new(&state, &headers, "v1/events/stream");

    let rx = state.event_bus.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |result| {
        let _hold_until_stream_drop = &abort_guard;
        let filter = filter.clone();
        match result {
            Ok(event) => {
                let event_type = event_type_name(&event);
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::auth::AuthMode;
    use crate::http::tests::{dev_scope_headers, test_app_state, test_app_state_with_auth};
    use axum::http::StatusCode;
    use corecrux_memory::events::CruxEvent;
    use http_body_util::BodyExt as _;
    use std::time::Duration;

    /// One of every variant, so a newly added variant fails to compile here
    /// (the match in `event_type_name` is exhaustive) and shows up in the
    /// serde-tag agreement test below.
    fn all_variants() -> Vec<CruxEvent> {
        vec![
            CruxEvent::FactStored {
                fact_id: "f_1".into(),
                entity: "e".into(),
                key: "k".into(),
            },
            CruxEvent::FactDeleted { fact_id: "f_1".into() },
            CruxEvent::SessionStored {
                session_id: "s_1".into(),
            },
            CruxEvent::SessionDeleted {
                session_id: "s_1".into(),
            },
            CruxEvent::SessionArchived {
                session_id: "s_1".into(),
                archived: true,
            },
            CruxEvent::AuditStep {
                node_id: "n".into(),
                session_id: "s_1".into(),
                seq: 3,
            },
            CruxEvent::OrchestratorChanged { id: "o_1".into() },
            CruxEvent::PunchcardChanged {
                id: "p_1".into(),
                status: "held".into(),
            },
            CruxEvent::ActivityAppended {
                entry_id: "a_1".into(),
                session_id: "s_1".into(),
                kind: "note".into(),
            },
        ]
    }

    fn params(types: Option<&str>) -> Query<EventStreamParams> {
        Query(EventStreamParams {
            types: types.map(str::to_string),
        })
    }

    /// Read the next non-empty SSE chunk, or `None` if nothing arrives. The
    /// keep-alive cadence is 15s, so a 2s ceiling cannot mistake a keep-alive
    /// comment for a real event.
    async fn next_chunk(body: &mut axum::body::Body) -> Option<String> {
        loop {
            let frame = tokio::time::timeout(Duration::from_secs(2), body.frame())
                .await
                .ok()??;
            let frame = frame.ok()?;
            if let Some(chunk) = frame.data_ref() {
                let text = String::from_utf8_lossy(chunk).to_string();
                if !text.trim().is_empty() {
                    return Some(text);
                }
            }
        }
    }

    // ── Wire contract ─────────────────────────────────────────────────────

    /// The load-bearing test: the SSE event name and the serde `type` tag are
    /// two hand-maintained copies of one wire string. Renaming a variant's
    /// serde tag without touching `event_type_name` would ship a stream whose
    /// `event:` line and `data.type` disagree, and every name-based subscriber
    /// would go quiet without any error.
    #[test]
    fn sse_names_match_the_serde_tags() {
        for event in all_variants() {
            let json = serde_json::to_value(&event).expect("serialize event");
            let tag = json["type"].as_str().expect("adjacently tagged 'type'");
            assert_eq!(
                event_type_name(&event),
                tag,
                "SSE event name and serde tag disagree for {event:?}"
            );
        }
    }

    #[test]
    fn every_variant_has_a_distinct_name() {
        let names: HashSet<&str> = all_variants().iter().map(|e| event_type_name(e)).collect();
        assert_eq!(names.len(), all_variants().len(), "duplicate SSE event name");
    }

    // ── Filter parsing ────────────────────────────────────────────────────

    #[test]
    fn an_omitted_filter_means_stream_everything() {
        assert!(parse_type_filter(None).is_none());
    }

    #[test]
    fn filter_entries_are_split_and_trimmed() {
        let filter = parse_type_filter(Some("fact.stored , session.stored")).expect("filter");
        assert!(filter.contains("fact.stored"));
        assert!(filter.contains("session.stored"));
        assert_eq!(filter.len(), 2);
    }

    /// An explicit blank filter must NOT silently widen to unfiltered.
    #[test]
    fn a_blank_filter_is_an_empty_set_not_unfiltered() {
        let filter = parse_type_filter(Some("")).expect("still Some");
        assert!(filter.is_empty());
        let filter = parse_type_filter(Some(" , ")).expect("still Some");
        assert!(filter.is_empty());
    }

    // ── Auth gate ─────────────────────────────────────────────────────────

    /// The stream carries entity + key names, so it is a `query:read` surface
    /// and must not be readable unauthenticated.
    #[tokio::test]
    async fn unauthenticated_stream_is_rejected() {
        let state = test_app_state_with_auth(1, AuthMode::DevScopes);
        let resp = event_stream(State(state), HeaderMap::new(), params(None))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn query_read_scope_opens_an_event_stream() {
        let state = test_app_state_with_auth(1, AuthMode::DevScopes);
        let resp = event_stream(State(state), dev_scope_headers("query:read"), params(None))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(
            content_type.starts_with("text/event-stream"),
            "expected an SSE content-type, got {content_type}"
        );
    }

    // ── End-to-end streaming ──────────────────────────────────────────────

    /// Subscribe, then emit: proves the handler is actually wired to the bus
    /// and frames the event with both the SSE name and the JSON payload.
    #[tokio::test]
    async fn an_emitted_event_reaches_an_unfiltered_subscriber() {
        let state = test_app_state(1);
        let bus = state.event_bus.clone();
        let resp = event_stream(State(state), HeaderMap::new(), params(None))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let mut body = resp.into_body();

        bus.emit(CruxEvent::FactStored {
            fact_id: "f_abc".into(),
            entity: "execplan:demo".into(),
            key: "milestone:M1".into(),
        });

        let chunk = next_chunk(&mut body).await.expect("an SSE frame");
        assert!(chunk.contains("event: fact.stored"), "missing SSE event name: {chunk}");
        assert!(chunk.contains("f_abc"), "missing payload: {chunk}");
    }

    /// A `types=` filter must drop non-matching events entirely rather than
    /// forwarding them — the filter is the whole point of the parameter.
    #[tokio::test]
    async fn a_filter_excludes_non_matching_events() {
        let state = test_app_state(1);
        let bus = state.event_bus.clone();
        let resp = event_stream(State(state), HeaderMap::new(), params(Some("session.stored")))
            .await
            .into_response();
        let mut body = resp.into_body();

        // Not in the filter — must never be framed.
        bus.emit(CruxEvent::FactStored {
            fact_id: "f_excluded".into(),
            entity: "e".into(),
            key: "k".into(),
        });
        // In the filter — must arrive, and must be the FIRST thing to arrive.
        bus.emit(CruxEvent::SessionStored {
            session_id: "s_included".into(),
        });

        let chunk = next_chunk(&mut body).await.expect("an SSE frame");
        assert!(
            !chunk.contains("f_excluded"),
            "filtered-out event was streamed: {chunk}"
        );
        assert!(chunk.contains("event: session.stored"), "missing wanted event: {chunk}");
        assert!(chunk.contains("s_included"), "missing wanted payload: {chunk}");
    }

    /// An explicit blank `types=` filters everything out; nothing should be
    /// framed within the read window.
    #[tokio::test]
    async fn a_blank_filter_streams_nothing() {
        let state = test_app_state(1);
        let bus = state.event_bus.clone();
        let resp = event_stream(State(state), HeaderMap::new(), params(Some("")))
            .await
            .into_response();
        let mut body = resp.into_body();

        bus.emit(CruxEvent::FactStored {
            fact_id: "f_1".into(),
            entity: "e".into(),
            key: "k".into(),
        });

        assert!(
            next_chunk(&mut body).await.is_none(),
            "a blank types= filter must not stream events"
        );
    }
}
