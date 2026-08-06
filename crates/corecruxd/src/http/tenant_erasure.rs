// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Tenant **corpus** erasure — `GET /v1/admin/tenants/{tenantId}/footprint`
//! and `POST /v1/admin/forget-tenants`.
//!
//! Scope: the retrieval corpus (sealed segments + their `.ccxi`/`.ccxv`/`.ccxp`
//! companions) ONLY. A tenant also owns facts, sessions and activity rows,
//! which this surface does not touch — hence the response key `corpus_erased`,
//! never `tenant_forgotten`.
//!
//! Gating: `CORECRUXD_TENANT_ERASURE=1`, default OFF → the routes 404.
//!
//! The route name, body and response keys mirror CoreCrux's
//! `POST /v1/admin/forget-tenants` so operators running both daemons keep one
//! runbook; the internals differ because Crux's corpus is sealed files on disk
//! rather than in-memory projection state across a GPU dataplane.

use corecrux_projections::tenant_hash_xxhash64;

use super::{problem_response, AppState, HeaderMap, IntoResponse, Json, Path, Response, State, StatusCode};

pub(super) fn tenant_erasure_disabled_response() -> Response {
    problem_response(
        StatusCode::NOT_FOUND,
        "tenant corpus erasure disabled (set CORECRUXD_TENANT_ERASURE=1)".to_string(),
    )
    .into_response()
}

/// `GET /v1/admin/tenants/{tenantId}/footprint` — read-only inventory of the
/// segments holding a tenant's documents. The blast radius of a `forget` is
/// inspectable *before* anything is erased.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_tenant_footprint(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !state.tenant_erasure_enabled {
        return tenant_erasure_disabled_response();
    }
    if let Err(problem) =
        crate::auth::require_http_scopes_for_tenant(&state.auth, &headers, &["admin:read"], &tenant_id)
    {
        return problem.into_response();
    }

    let tenant_hash = tenant_hash_xxhash64(&tenant_id);
    let footprint = state.retrieval_index.read().await.tenant_footprint(tenant_hash);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "schema": "crux.admin.tenant_footprint.v1",
            "tenant_id": tenant_id,
            "tenant_hash": format!("{tenant_hash:#018x}"),
            "segment_count": footprint.segments.len(),
            "docs": footprint.docs,
            "bytes": footprint.bytes,
            "mixed_segments": footprint.mixed_segments,
            "segments": footprint.segments,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::tests::test_app_state;

    /// A single-segment `.ccxi` holding one doc per named tenant.
    pub(super) fn segment_bytes(tenants: &[&str], segment_seq: u64) -> Vec<u8> {
        let mut builder = corecrux_index::CcxiBuilder::new(0, segment_seq, 100);
        for (i, t) in tenants.iter().enumerate() {
            builder.add_document(
                i as u32,
                "terraform drift detection",
                (i * 100) as u32,
                tenant_hash_xxhash64(t),
            );
        }
        builder.build()
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    async fn footprint_json(state: &AppState, tenant_id: &str) -> (StatusCode, serde_json::Value) {
        let resp = get_tenant_footprint(State(state.clone()), Path(tenant_id.to_string()), HeaderMap::new()).await;
        let status = resp.status();
        (status, body_json(resp).await)
    }

    #[tokio::test]
    async fn footprint_404s_when_the_flag_is_off() {
        let mut state = test_app_state(1);
        state.tenant_erasure_enabled = false;
        let (status, _) = footprint_json(&state, "acme").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn footprint_reports_segments_docs_and_mixed_count() {
        let state = test_app_state(1);
        {
            let mut idx = state.retrieval_index.write().await;
            idx.load_ccxi_bytes(&segment_bytes(&["acme", "acme"], 1)).unwrap();
            idx.load_ccxi_bytes(&segment_bytes(&["acme", "globex"], 2)).unwrap();
            idx.load_ccxi_bytes(&segment_bytes(&["globex"], 3)).unwrap();
        }

        let (status, body) = footprint_json(&state, "acme").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["segment_count"], 2, "seg 3 holds no acme docs");
        assert_eq!(body["docs"], 3);
        assert_eq!(body["mixed_segments"], 1);
        assert_eq!(body["segments"][0]["segment_seq"], 1);
        assert_eq!(body["segments"][0]["whole_tenant"], true);
        assert_eq!(body["segments"][1]["whole_tenant"], false);
    }

    #[tokio::test]
    async fn footprint_of_an_unknown_tenant_is_zero_not_an_error() {
        let state = test_app_state(1);
        let (status, body) = footprint_json(&state, "never-ingested").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["segment_count"], 0);
        assert_eq!(body["docs"], 0);
        assert_eq!(body["bytes"], 0);
    }
}
