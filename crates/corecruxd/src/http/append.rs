// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! HTTP append surface — `POST /v1/events` writes events through the append lane.

use super::*;

#[derive(serde::Deserialize)]
pub(super) struct AppendBody {
    pub(super) tenant_id: String,
    pub(super) stream_type: String,
    pub(super) stream_id: String,
    #[serde(default)]
    pub(super) expected_next_seq: u64,
    pub(super) events: Vec<AppendEventBody>,
}

#[derive(serde::Deserialize)]
pub(super) struct AppendEventBody {
    pub(super) event_id: String,
    pub(super) occurred_at: String,
    pub(super) event_type: String,
    #[serde(default = "default_content_type")]
    pub(super) content_type: String,
    /// Payload as raw UTF-8 string (JSON). Stored as-is in the frame.
    pub(super) payload: String,
}

pub(super) fn default_content_type() -> String {
    "application/json".to_string()
}

#[tracing::instrument(level = "info", skip(state, headers, body), fields(tenant_id = %body.tenant_id, stream_type = %body.stream_type))]
pub(super) async fn post_admin_append(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<AppendBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }

    if !state.http_dataplane.enabled() {
        return platform_upgrade_response("admin_append");
    }

    if body.events.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "events must not be empty");
    }
    if body.events.len() > 1024 {
        return problem_response(StatusCode::BAD_REQUEST, "max 1024 events per batch");
    }

    let events: Vec<AppendEvent> = body
        .events
        .iter()
        .map(|e| AppendEvent {
            event_id: e.event_id.clone(),
            occurred_at: e.occurred_at.clone(),
            event_type: e.event_type.clone(),
            content_type: e.content_type.clone(),
            payload: e.payload.as_bytes().to_vec(),
        })
        .collect();

    if let Err(err) = state
        .http_dataplane
        .append_batch(
            &body.tenant_id,
            &body.stream_type,
            &body.stream_id,
            body.expected_next_seq,
            &events,
        )
        .await
    {
        return map_http_dataplane_error(err);
    }

    if let Err(err) = crate::console_index::record_appended_events(
        &state.data_dir,
        &body.tenant_id,
        &body.stream_type,
        &body.stream_id,
        body.expected_next_seq,
        &events,
        crate::ops_events::now_unix_ms(),
    ) {
        tracing::warn!(?err, "console chunk metadata indexing failed");
    }

    // stateful-extraction-flywheel M1.b — feed the extraction-cache materializer
    // inline for any `corecrux.proj.extraction.*` events in this batch. This is
    // the CE-friendly path: events are still persisted in the stream log, but
    // we materialize in-process for immediate lookup availability. Proprietary
    // deployments can upgrade to event-sourced replay from the sealed segments
    // without changing the HTTP contract.
    {
        let mut cache = state.extraction_cache.write().await;
        for event in &body.events {
            let payload_bytes = event.payload.as_bytes();
            match event.event_type.as_str() {
                corecrux_projections::EVT_EXTRACTION_CACHE_INSERT_V1 => {
                    if let Ok(ev) = corecrux_projections::ExtractionCacheInsertV1::decode_json(payload_bytes) {
                        cache.apply_insert(&ev);
                    }
                }
                corecrux_projections::EVT_EXTRACTION_CACHE_HIT_V1 => {
                    if let Ok(ev) = corecrux_projections::ExtractionCacheHitV1::decode_json(payload_bytes) {
                        cache.apply_hit(&ev);
                    }
                }
                corecrux_projections::EVT_EXTRACTION_VERIFIER_SCORED_V1 => {
                    if let Ok(ev) = corecrux_projections::ExtractionVerifierScoredV1::decode_json(payload_bytes) {
                        cache.apply_verifier(&ev);
                    }
                }
                corecrux_projections::EVT_EXTRACTION_CONFIDENCE_DELTA_V1 => {
                    if let Ok(ev) = corecrux_projections::ExtractionConfidenceDeltaV1::decode_json(payload_bytes) {
                        cache.apply_confidence(&ev);
                    }
                }
                corecrux_projections::EVT_EXTRACTION_CACHE_INVALIDATE_V1 => {
                    if let Ok(ev) = corecrux_projections::ExtractionCacheInvalidateV1::decode_json(payload_bytes) {
                        cache.apply_invalidate(&ev);
                    }
                }
                _ => {}
            }
        }
    }

    // Reload .ccxi indexes after append (seal + ccxi build happens synchronously in Phase 2 mode).
    {
        let idx = state.retrieval_index.clone();
        let data_dir = state.data_dir.clone();
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let mut guard = idx.write().await;
            let shards_dir = data_dir.join("shards");
            if let Ok(entries) = std::fs::read_dir(&shards_dir) {
                for entry in entries.flatten() {
                    let seg_dir = entry.path().join("segments");
                    let _ = guard.scan_and_load(&seg_dir);
                }
            }
        });
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "appended": body.events.len(),
            "stream_id": body.stream_id,
        })),
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod append_tests {
    use super::*;

    fn enabled_state() -> AppState {
        let mut s = super::super::tests::test_app_state(16);
        s.http_dataplane = super::super::tests::enabled_dataplane(vec![], None);
        s
    }

    fn body(n: usize) -> AppendBody {
        AppendBody {
            tenant_id: "t1".to_string(),
            stream_type: "artifact".to_string(),
            stream_id: "s1".to_string(),
            expected_next_seq: 0,
            events: (0..n)
                .map(|i| AppendEventBody {
                    event_id: format!("e{i}"),
                    occurred_at: "2026-06-17T00:00:00Z".to_string(),
                    event_type: "evt.created".to_string(),
                    content_type: "application/json".to_string(),
                    payload: "{}".to_string(),
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn disabled_dataplane_returns_upgrade_501() {
        // Default test state has the dataplane disabled (CE build).
        let state = super::super::tests::test_app_state(16);
        let resp = post_admin_append(State(state), HeaderMap::new(), Json(body(1)))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn empty_events_rejected() {
        let resp = post_admin_append(State(enabled_state()), HeaderMap::new(), Json(body(0)))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn too_many_events_rejected() {
        let resp = post_admin_append(State(enabled_state()), HeaderMap::new(), Json(body(1025)))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn happy_path_appends_and_returns_created() {
        let resp = post_admin_append(State(enabled_state()), HeaderMap::new(), Json(body(2)))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }
}

// ── v5 text retrieval ────────────────────────────────────────────────
