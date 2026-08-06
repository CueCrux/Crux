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
use corecrux_retrieval::index_manager::{ForgottenTenant, FORGOTTEN_TENANTS_FILE};

use super::{problem_response, AppState, HeaderMap, IntoResponse, Json, Path, Response, State, StatusCode};

/// Batch cap, mirroring CoreCrux's `MAX_FORGET_TENANTS`. Bounds how long one
/// request can hold the retrieval index write lock.
const MAX_FORGET_TENANTS: usize = 4096;

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

/// Normalize a `forget-tenants` batch: drop empty ids and de-dup while
/// preserving first-seen order, so the response rows line up with the caller's
/// intent and no tenant is erased twice in one pass. Same semantics as
/// CoreCrux's `normalize_forget_tenant_ids`.
fn normalize_forget_tenant_ids(raw: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    raw.into_iter()
        .filter(|t| !t.trim().is_empty())
        .filter(|t| seen.insert(t.clone()))
        .collect()
}

/// Reserved/system tenant namespaces. Erasing one would delete the daemon's own
/// state, so the whole batch is refused. Matching the `__` convention rather
/// than a fixed list (`__agent`, `__ops`, `__bootstrap__`, `__coord__`, …)
/// means a future reserved namespace is refused the day it is introduced, not
/// the day someone remembers to update this file.
fn is_reserved_tenant_id(tenant_id: &str) -> bool {
    tenant_id.starts_with("__")
}

/// Request body for `POST /v1/admin/forget-tenants`.
///
/// `tenant_id` is the singular alias's field; both routes share one handler.
#[derive(Debug, Default, serde::Deserialize)]
pub(super) struct ForgetTenantsBody {
    #[serde(default, alias = "tenantIds")]
    tenant_ids: Vec<String>,
    #[serde(default, alias = "tenantId")]
    tenant_id: Option<String>,
}

/// Signed erasure receipt — counts, the watermark, and the erasure's scope.
/// Carries no document content and no caller free-text by construction.
#[derive(serde::Serialize)]
struct TenantCorpusErasureReceiptV1<'a> {
    schema: &'a str,
    op: &'a str,
    tenant_id: &'a str,
    tenant_hash: String,
    watermark_segment_seq: u64,
    segments_masked: usize,
    docs_masked: usize,
    mixed_segments_retained: usize,
    /// Names what was erased. The corpus only — a tenant's facts, sessions and
    /// activity rows are untouched, so this is not a full Art.17 erasure.
    scope: &'a str,
    recorded_at: String,
}

/// One tenant's outcome, in the response and in the receipt.
struct ErasureOutcome {
    tenant_id: String,
    tenant_hash: u64,
    watermark_segment_seq: u64,
    segments_scanned: usize,
    docs_masked: usize,
    mixed_segments_retained: usize,
}

/// `POST /v1/admin/forget-tenants` — erase the named tenants' retrieval corpora.
///
/// Layer 1 only: the segments are masked and the mask is persisted, so the
/// operation is reversible via `DELETE /v1/admin/forget-tenants/{tenantId}`
/// until the files are reclaimed.
///
/// Auth is `admin:write` **per named tenant**; the whole batch is rejected if
/// any tenant fails, and nothing is masked (CoreCrux audit Finding #5 parity —
/// no batch back-door around the per-tenant binding).
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_forget_tenants(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ForgetTenantsBody>,
) -> Response {
    if !state.tenant_erasure_enabled {
        return tenant_erasure_disabled_response();
    }

    let mut raw = body.tenant_ids;
    raw.extend(body.tenant_id);
    let tenant_ids = normalize_forget_tenant_ids(raw);

    if tenant_ids.is_empty() {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "tenant_ids must be a non-empty array of non-empty strings",
        )
        .into_response();
    }
    if tenant_ids.len() > MAX_FORGET_TENANTS {
        return problem_response(
            StatusCode::BAD_REQUEST,
            format!(
                "tenant_ids has {} entries; max is {MAX_FORGET_TENANTS}",
                tenant_ids.len()
            ),
        )
        .into_response();
    }
    if let Some(reserved) = tenant_ids.iter().find(|t| is_reserved_tenant_id(t)) {
        return problem_response(
            StatusCode::BAD_REQUEST,
            format!("tenant id {reserved:?} is a reserved daemon namespace and cannot be erased"),
        )
        .into_response();
    }

    // Authorise every tenant BEFORE mutating anything: a partially-authorised
    // batch must leave no mask behind.
    for tenant_id in &tenant_ids {
        if let Err(problem) =
            crate::auth::require_http_scopes_for_tenant(&state.auth, &headers, &["admin:write"], tenant_id)
        {
            return problem.into_response();
        }
    }

    let recorded_at = chrono::Utc::now().to_rfc3339();
    let forgotten_path = state.data_dir.join(FORGOTTEN_TENANTS_FILE);

    let outcomes = {
        let mut index = state.retrieval_index.write().await;
        // One watermark for the whole batch: every segment sealed so far is
        // erased, anything ingested afterwards is not.
        let watermark = index.max_segment_seq().unwrap_or(0);
        let mut outcomes = Vec::with_capacity(tenant_ids.len());
        let mut previous = Vec::with_capacity(tenant_ids.len());

        for tenant_id in &tenant_ids {
            let tenant_hash = tenant_hash_xxhash64(tenant_id);
            let footprint = index.tenant_footprint(tenant_hash);
            previous.push((
                tenant_hash,
                index.forget_tenant(ForgottenTenant {
                    tenant_id: tenant_id.clone(),
                    tenant_hash,
                    watermark_segment_seq: watermark,
                    forgotten_at: recorded_at.clone(),
                    segments_reclaimed: 0,
                }),
            ));
            outcomes.push(ErasureOutcome {
                tenant_id: tenant_id.clone(),
                tenant_hash,
                watermark_segment_seq: watermark,
                segments_scanned: footprint.segments.len(),
                docs_masked: footprint.docs,
                mixed_segments_retained: footprint.mixed_segments,
            });
        }

        // Tombstone-then-erase: the mask must be durable before anything else
        // happens. If it cannot be persisted, undo the in-memory masks so the
        // process and the disk never disagree.
        if let Err(err) = index.save_forgotten(&forgotten_path) {
            for (tenant_hash, prior) in previous {
                match prior {
                    Some(record) => {
                        index.forget_tenant(record);
                    }
                    None => {
                        index.unforget_tenant(tenant_hash);
                    }
                }
            }
            tracing::error!(?err, path=?forgotten_path, "tenant-erasure-mask-persist-failed");
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("erasure mask could not be persisted ({err}); nothing was erased"),
            )
            .into_response();
        }
        outcomes
    };

    let actor = crate::auth::describe_http_evidence(&state.auth, &headers)
        .ok()
        .and_then(|evidence| evidence.subject)
        .unwrap_or_else(|| state.passport_fpr.clone());

    let per_tenant: Vec<serde_json::Value> = outcomes
        .iter()
        .map(|outcome| {
            let receipt_id = super::observations::mint_governance_receipt(
                &state,
                "__governance__::erasure",
                &actor,
                "erasure.forget_tenant_corpus",
                &TenantCorpusErasureReceiptV1 {
                    schema: "crux.tenant_corpus_erasure.v1",
                    op: "forget_tenant_corpus",
                    tenant_id: &outcome.tenant_id,
                    tenant_hash: format!("{:#018x}", outcome.tenant_hash),
                    watermark_segment_seq: outcome.watermark_segment_seq,
                    segments_masked: outcome.segments_scanned,
                    docs_masked: outcome.docs_masked,
                    mixed_segments_retained: outcome.mixed_segments_retained,
                    scope: "retrieval_corpus",
                    recorded_at: recorded_at.clone(),
                },
            );
            tracing::info!(
                tenant_id = %outcome.tenant_id,
                op = "erasure.forget_tenant_corpus",
                watermark_segment_seq = outcome.watermark_segment_seq,
                segments = outcome.segments_scanned,
                docs = outcome.docs_masked,
                mixed_segments_retained = outcome.mixed_segments_retained,
                receipt_id = ?receipt_id,
                "tenant-corpus-erased"
            );
            serde_json::json!({
                "tenant_id": outcome.tenant_id,
                "corpus_erased": true,
                "masked": true,
                "watermark_segment_seq": outcome.watermark_segment_seq,
                "segments_scanned": outcome.segments_scanned,
                "docs_masked": outcome.docs_masked,
                "segments_reclaimed": 0,
                "bytes_reclaimed": 0,
                "mixed_segments_retained": outcome.mixed_segments_retained,
                "receipt_id": receipt_id,
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "schema": "crux.admin.forget_tenants.v1",
            "tenants": per_tenant.len(),
            "per_tenant": per_tenant,
            "scope": "retrieval_corpus",
            "durability": "mask persisted; segment files retained (reversible until reclaimed)",
        })),
    )
        .into_response()
}

/// `DELETE /v1/admin/forget-tenants/{tenantId}` — lift a Layer-1 mask.
///
/// The documented rollback for a mask-only erasure. Refused once the segment
/// files have been reclaimed, because there is nothing left to unmask.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn delete_forget_tenant(
    State(state): State<AppState>,
    Path(tenant_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    if !state.tenant_erasure_enabled {
        return tenant_erasure_disabled_response();
    }
    if let Err(problem) =
        crate::auth::require_http_scopes_for_tenant(&state.auth, &headers, &["admin:write"], &tenant_id)
    {
        return problem.into_response();
    }

    let tenant_hash = tenant_hash_xxhash64(&tenant_id);
    let forgotten_path = state.data_dir.join(FORGOTTEN_TENANTS_FILE);

    let mut index = state.retrieval_index.write().await;
    let Some(record) = index.forgotten_tenant(tenant_hash).cloned() else {
        return problem_response(StatusCode::NOT_FOUND, format!("tenant {tenant_id:?} is not forgotten"))
            .into_response();
    };
    if record.segments_reclaimed > 0 {
        return problem_response(
            StatusCode::CONFLICT,
            format!(
                "tenant {tenant_id:?} had {} segment file group(s) reclaimed; the mask cannot be lifted because the data is gone",
                record.segments_reclaimed
            ),
        )
        .into_response();
    }

    index.unforget_tenant(tenant_hash);
    if let Err(err) = index.save_forgotten(&forgotten_path) {
        index.forget_tenant(record);
        return problem_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("erasure mask could not be persisted ({err}); the tenant is still masked"),
        )
        .into_response();
    }

    tracing::info!(tenant_id = %tenant_id, op = "erasure.unforget_tenant_corpus", "tenant-corpus-mask-lifted");
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "schema": "crux.admin.unforget_tenant.v1",
            "tenant_id": tenant_id,
            "masked": false,
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

    // ── forget-tenants ───────────────────────────────────────────────

    async fn seeded_state() -> AppState {
        let state = test_app_state(1);
        let mut idx = state.retrieval_index.write().await;
        idx.load_ccxi_bytes(&segment_bytes(&["acme", "acme"], 1)).unwrap();
        idx.load_ccxi_bytes(&segment_bytes(&["acme", "globex"], 2)).unwrap();
        idx.load_ccxi_bytes(&segment_bytes(&["globex"], 3)).unwrap();
        drop(idx);
        state
    }

    async fn forget(state: &AppState, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let body: ForgetTenantsBody = serde_json::from_value(body).expect("body");
        let resp = post_forget_tenants(State(state.clone()), HeaderMap::new(), Json(body)).await;
        let status = resp.status();
        (status, body_json(resp).await)
    }

    #[tokio::test]
    async fn forget_404s_when_the_flag_is_off() {
        let mut state = seeded_state().await;
        state.tenant_erasure_enabled = false;
        let (status, _) = forget(&state, serde_json::json!({ "tenant_ids": ["acme"] })).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn forget_masks_persists_and_reports_counts() {
        let state = seeded_state().await;
        let (status, body) = forget(&state, serde_json::json!({ "tenant_ids": ["acme"] })).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["tenants"], 1);
        let row = &body["per_tenant"][0];
        assert_eq!(row["corpus_erased"], true);
        assert_eq!(row["segments_scanned"], 2);
        assert_eq!(row["docs_masked"], 3);
        assert_eq!(row["mixed_segments_retained"], 1);
        assert_eq!(row["watermark_segment_seq"], 3, "highest sealed segment at erase time");
        assert_eq!(row["segments_reclaimed"], 0, "Layer 1 leaves the files alone");

        // Mask is live in-process...
        let index = state.retrieval_index.read().await;
        assert_eq!(index.forgotten_watermark(tenant_hash_xxhash64("acme")), Some(3));
        assert_eq!(
            index.forgotten_watermark(tenant_hash_xxhash64("globex")),
            None,
            "sibling tenant unaffected"
        );
        drop(index);

        // ...and durable on disk before the response was written.
        let persisted = std::fs::read(state.data_dir.join(FORGOTTEN_TENANTS_FILE)).expect("mask file");
        let records: Vec<ForgottenTenant> = serde_json::from_slice(&persisted).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].tenant_id, "acme");
    }

    #[tokio::test]
    async fn forget_of_an_unknown_tenant_is_idempotent_not_an_error() {
        let state = seeded_state().await;
        let (status, body) = forget(&state, serde_json::json!({ "tenant_ids": ["never-ingested"] })).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["per_tenant"][0]["segments_scanned"], 0);
        assert_eq!(body["per_tenant"][0]["docs_masked"], 0);
    }

    #[tokio::test]
    async fn forget_accepts_the_singular_alias_field() {
        let state = seeded_state().await;
        let (status, body) = forget(&state, serde_json::json!({ "tenant_id": "acme" })).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["per_tenant"][0]["tenant_id"], "acme");
    }

    #[tokio::test]
    async fn forget_collapses_duplicates_and_drops_empties() {
        let state = seeded_state().await;
        let (status, body) = forget(
            &state,
            serde_json::json!({ "tenant_ids": ["acme", "", "acme", "globex", "acme"] }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["tenants"], 2, "duplicates collapse, empties drop");
        assert_eq!(body["per_tenant"][0]["tenant_id"], "acme", "first-seen order preserved");
        assert_eq!(body["per_tenant"][1]["tenant_id"], "globex");
    }

    #[tokio::test]
    async fn forget_rejects_an_empty_batch() {
        let state = seeded_state().await;
        let (status, _) = forget(&state, serde_json::json!({ "tenant_ids": ["", "  "] })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn forget_rejects_an_oversized_batch() {
        let state = seeded_state().await;
        let ids: Vec<String> = (0..MAX_FORGET_TENANTS + 1).map(|i| format!("t{i}")).collect();
        let (status, _) = forget(&state, serde_json::json!({ "tenant_ids": ids })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn forget_refuses_a_reserved_tenant_and_masks_nothing() {
        let state = seeded_state().await;
        let (status, _) = forget(&state, serde_json::json!({ "tenant_ids": ["acme", "__ops"] })).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            state
                .retrieval_index
                .read()
                .await
                .forgotten_watermark(tenant_hash_xxhash64("acme")),
            None,
            "the authorised tenant in the batch must not be erased either"
        );
    }

    #[tokio::test]
    async fn unforget_lifts_the_mask_and_restores_retrieval() {
        let state = seeded_state().await;
        forget(&state, serde_json::json!({ "tenant_ids": ["acme"] })).await;

        let resp = delete_forget_tenant(State(state.clone()), Path("acme".to_string()), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            state
                .retrieval_index
                .read()
                .await
                .forgotten_watermark(tenant_hash_xxhash64("acme")),
            None
        );

        let records: Vec<ForgottenTenant> =
            serde_json::from_slice(&std::fs::read(state.data_dir.join(FORGOTTEN_TENANTS_FILE)).unwrap()).unwrap();
        assert!(records.is_empty(), "the lift is persisted too");
    }

    #[tokio::test]
    async fn unforget_of_a_tenant_that_was_never_forgotten_is_404() {
        let state = seeded_state().await;
        let resp = delete_forget_tenant(State(state.clone()), Path("acme".to_string()), HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// A batch where one tenant is outside the caller's binding must be
    /// rejected whole — no per-tenant partial erasure back-door (CoreCrux audit
    /// Finding #5 parity).
    #[tokio::test]
    async fn a_partially_authorised_batch_is_rejected_and_masks_nothing() {
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        const TEST_HS256_SECRET: &str = "0123456789abcdef0123456789abcdef";

        std::env::set_var("CORECRUXD_JWT_HS256_SECRET", TEST_HS256_SECRET);
        std::env::set_var("CORECRUXD_JWT_ISS", "corecrux-test");
        std::env::set_var("CORECRUXD_JWT_AUD", "corecrux");

        let mut state = crate::http::tests::test_app_state_with_auth(1, crate::auth::AuthMode::JwtHs256);
        state.tenant_erasure_enabled = true;
        {
            let mut idx = state.retrieval_index.write().await;
            idx.load_ccxi_bytes(&segment_bytes(&["acme"], 1)).unwrap();
            idx.load_ccxi_bytes(&segment_bytes(&["globex"], 2)).unwrap();
        }

        let claims = serde_json::json!({
            "exp": (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 3600),
            "iss": "corecrux-test",
            "aud": "corecrux",
            "scope": "admin:write",
            "tenant_id": "acme",
        });
        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(TEST_HS256_SECRET.as_bytes()),
        )
        .expect("jwt");
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("header"),
        );

        let body: ForgetTenantsBody = serde_json::from_value(serde_json::json!({
            "tenant_ids": ["acme", "globex"]
        }))
        .unwrap();
        let resp = post_forget_tenants(State(state.clone()), headers.clone(), Json(body)).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let index = state.retrieval_index.read().await;
        assert_eq!(
            index.forgotten_watermark(tenant_hash_xxhash64("acme")),
            None,
            "the authorised half of the batch must not be erased"
        );
        assert_eq!(index.forgotten_watermark(tenant_hash_xxhash64("globex")), None);
        drop(index);
        assert!(
            !state.data_dir.join(FORGOTTEN_TENANTS_FILE).exists(),
            "a rejected batch writes no mask file at all"
        );

        // Control: the same caller may erase the tenant it is bound to.
        let ok_body: ForgetTenantsBody = serde_json::from_value(serde_json::json!({
            "tenant_ids": ["acme"]
        }))
        .unwrap();
        let ok = post_forget_tenants(State(state.clone()), headers, Json(ok_body)).await;
        assert_eq!(ok.status(), StatusCode::OK);

        std::env::remove_var("CORECRUXD_JWT_HS256_SECRET");
        std::env::remove_var("CORECRUXD_JWT_ISS");
        std::env::remove_var("CORECRUXD_JWT_AUD");
    }

    #[test]
    fn normalize_preserves_first_seen_order() {
        let out = normalize_forget_tenant_ids(vec![
            "b".into(),
            "".into(),
            "a".into(),
            "b".into(),
            "   ".into(),
            "c".into(),
        ]);
        assert_eq!(out, vec!["b", "a", "c"]);
    }

    #[test]
    fn reserved_tenant_ids_are_refusable() {
        for id in ["__agent", "__ops", "__bootstrap__", "__coord__::live"] {
            assert!(is_reserved_tenant_id(id), "{id} must be reserved");
        }
        for id in ["acme", "MarketResearch", "_leading-single-underscore"] {
            assert!(!is_reserved_tenant_id(id), "{id} must not be reserved");
        }
    }
}
