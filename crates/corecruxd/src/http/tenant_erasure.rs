// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Tenant **corpus** erasure — `GET /v1/admin/tenants/{tenantId}/footprint`
//! and `POST /v1/admin/forget-tenants`.
//!
//! Scope: the retrieval corpus (sealed segments + their `.ccxi`/`.ccxe`/`.ccxprof`
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
    // Enumerate from disk first: a footprint is the blast radius an operator
    // decides on, so it must not omit a segment that was sealed since the last
    // scan. This takes the write lock, unlike the read-only inventory itself.
    state.retrieval_index.write().await.refresh_from_disk();
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
            "unattributable_segments": footprint.unattributable_segments,
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
    /// Layer 2 — delete the segment files of every whole-tenant segment.
    /// **Irreversible**, so it is opt-in: the default leaves an erasure
    /// reversible via `DELETE /v1/admin/forget-tenants/{tenantId}`.
    #[serde(default)]
    reclaim: bool,
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
    /// Segment file groups deleted. Non-zero means the erasure is no longer
    /// reversible.
    segments_reclaimed: usize,
    bytes_reclaimed: u64,
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
    /// Segment sequences whose every document belongs to this tenant — the
    /// only ones a reclaim may delete.
    reclaimable: Vec<u64>,
    segments_reclaimed: usize,
    bytes_reclaimed: u64,
}

/// `POST /v1/admin/forget-tenants` — erase the named tenants' retrieval corpora.
///
/// Two layers, in this order. Layer 1 masks the segments and persists the mask,
/// which is reversible via `DELETE /v1/admin/forget-tenants/{tenantId}`. Layer 2
/// (`"reclaim": true`, opt-in) then deletes the file group of every whole-tenant
/// segment and is **irreversible** — recovery is restore-from-backup only.
/// Mixed-tenant segments are never deleted; they stay masked and are reported
/// as `mixed_segments_retained`.
///
/// The mask is made durable before any file is unlinked, so a crash in between
/// leaves files on disk under a live mask — inert, and reclaimable again — never
/// files deleted with no mask.
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

    let reclaim = body.reclaim;
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

    let (outcomes, manifest_retire_failed, unattributable) = {
        let mut index = state.retrieval_index.write().await;
        // Enumerate from disk, not from the loaded set. A segment sealed since
        // the last scan is otherwise absent from `self.segments`, and the
        // reclaim below would report `Ok(0)` and leave its files in place —
        // erasure silently failing is the one outcome this surface may not have.
        let discovered = index.refresh_from_disk();
        if discovered > 0 {
            tracing::info!(discovered, "tenant-erasure-discovered-segments-before-erasing");
        }
        // One watermark for the whole batch: every segment sealed so far is
        // erased, anything ingested afterwards is not.
        let watermark = index.max_segment_seq().unwrap_or(0);
        let mut outcomes = Vec::with_capacity(tenant_ids.len());
        let mut previous = Vec::with_capacity(tenant_ids.len());

        let mut unattributable = 0usize;
        for tenant_id in &tenant_ids {
            let tenant_hash = tenant_hash_xxhash64(tenant_id);
            let footprint = index.tenant_footprint(tenant_hash);
            // A corpus-wide property, identical for every tenant in the batch.
            unattributable = unattributable.max(footprint.unattributable_segments);
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
                reclaimable: footprint
                    .segments
                    .iter()
                    .filter(|s| s.whole_tenant)
                    .map(|s| s.segment_seq)
                    .collect(),
                segments_reclaimed: 0,
                bytes_reclaimed: 0,
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

        // ── Layer 2 (irreversible) — only after the mask is durable ─────────
        //
        // MANIFEST before unlink. Until 2026-08-08 this loop went straight to
        // `reclaim_segment`, which unlinks the file group and never touches the
        // shard manifest. The manifest kept referencing 17 deleted segments, so
        // every later `ShardStorage::open` failed on `File::open` and took the
        // whole write path down — reads were unaffected, `/readyz` stayed green,
        // and nobody noticed for 38 hours. See ExecPlan
        // `crux-erasure-manifest-repair-2026-08-08`.
        //
        // If the manifest cannot be updated, nothing is unlinked. The mask is
        // already durable, so the corpus is still correctly hidden; the disk
        // space simply is not freed, which is the same outcome as `reclaim=false`
        // and is recoverable by re-running the forget.
        let mut manifest_retired: std::collections::HashSet<u64> = std::collections::HashSet::new();
        let mut manifest_retire_failed: Option<String> = None;
        if reclaim {
            let wanted: Vec<u64> = outcomes.iter().flat_map(|o| o.reclaimable.iter().copied()).collect();
            match corecrux_storage::retire_segments_in_manifest(
                &state.data_dir.join("shards"),
                crate::local_ingest::LOCAL_INGEST_SHARD_ID,
                &wanted,
            ) {
                Ok(retire) => {
                    // `not_present` joins `retired`: a segment the manifest never
                    // referenced is an orphan, and unlinking it is still correct.
                    manifest_retired.extend(retire.retired.iter().copied());
                    manifest_retired.extend(retire.not_present.iter().copied());
                }
                Err(err) => {
                    tracing::error!(
                        ?err,
                        segments = wanted.len(),
                        "tenant-erasure-manifest-retire-failed; segment files retained (masked, not reclaimed)"
                    );
                    manifest_retire_failed = Some(err.to_string());
                }
            }
        }
        if reclaim && manifest_retire_failed.is_none() {
            for outcome in &mut outcomes {
                for &segment_seq in &outcome.reclaimable {
                    if !manifest_retired.contains(&segment_seq) {
                        continue;
                    }
                    match index.reclaim_segment(segment_seq) {
                        Ok(bytes) => {
                            outcome.segments_reclaimed += 1;
                            outcome.bytes_reclaimed += bytes;
                        }
                        Err(err) => {
                            // The mask still hides the segment, so retrieval
                            // stays correct; the disk space is simply not
                            // freed. Loud, not fatal.
                            tracing::error!(
                                tenant_id = %outcome.tenant_id,
                                segment_seq,
                                ?err,
                                "tenant-erasure-segment-reclaim-failed"
                            );
                        }
                    }
                }
                if outcome.segments_reclaimed > 0 {
                    if let Some(mut record) = index.forgotten_tenant(outcome.tenant_hash).cloned() {
                        record.segments_reclaimed = outcome.segments_reclaimed;
                        index.forget_tenant(record);
                    }
                }
            }
            // Re-persist so a later unmask attempt sees that the files are gone.
            // The erasure itself already succeeded; a failure here is audit
            // debt, never a rollback.
            if let Err(err) = index.save_forgotten(&forgotten_path) {
                tracing::error!(
                    ?err,
                    path = ?forgotten_path,
                    "AUDIT DEBT: reclaim counts not persisted; segment files are already deleted"
                );
            }
        }
        if unattributable > 0 {
            // Not a failure of this request, but the erasure cannot be called
            // complete: these segments hold data nobody can assign an owner to.
            tracing::error!(
                unattributable,
                "tenant-erasure-unattributable-segments: discovered segments could not be attributed to \
                 any tenant and were neither masked nor reclaimed"
            );
        }
        (outcomes, manifest_retire_failed, unattributable)
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
                    segments_reclaimed: outcome.segments_reclaimed,
                    bytes_reclaimed: outcome.bytes_reclaimed,
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
                segments_reclaimed = outcome.segments_reclaimed,
                bytes_reclaimed = outcome.bytes_reclaimed,
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
                "segments_reclaimed": outcome.segments_reclaimed,
                "bytes_reclaimed": outcome.bytes_reclaimed,
                "mixed_segments_retained": outcome.mixed_segments_retained,
                "receipt_id": receipt_id,
            })
        })
        .collect();

    let durability = {
        let base = match (reclaim, manifest_retire_failed.as_deref()) {
            (true, None) => "mask persisted; whole-tenant segment files deleted (irreversible)",
            // Reclaim was asked for and refused. Saying "deleted" here would be
            // a lie the operator could only catch by listing the shard.
            (true, Some(_)) => {
                "mask persisted; segment files retained because the MANIFEST could not be updated (see manifest_error)"
            }
            (false, _) => "mask persisted; segment files retained (reversible until reclaimed)",
        };
        // The completeness caveat belongs in the sentence an operator actually
        // reads, not only in a count they have to interpret.
        if unattributable > 0 {
            format!(
                "{base}. INCOMPLETE: {unattributable} segment(s) on disk could not be attributed to any \
                 tenant and were neither masked nor reclaimed"
            )
        } else {
            base.to_string()
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "schema": "crux.admin.forget_tenants.v1",
            "tenants": per_tenant.len(),
            "per_tenant": per_tenant,
            "scope": "retrieval_corpus",
            // Non-zero means the corpus holds segments no tenant could be
            // assigned to; they were neither masked nor reclaimed.
            "unattributable_segments": unattributable,
            "reclaimed": reclaim && manifest_retire_failed.is_none(),
            "durability": durability,
            "manifest_error": manifest_retire_failed,
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

    // ── Layer 2 physical reclaim ─────────────────────────────────────

    /// Seed `data_dir/shards/shard-0000/segments` with real segment file groups
    /// and load them, so `path` is set and a reclaim has something to delete.
    async fn on_disk_state() -> (AppState, std::path::PathBuf) {
        let state = test_app_state(1);
        let segments = state.data_dir.join("shards").join("shard-0000").join("segments");
        std::fs::create_dir_all(&segments).unwrap();

        for (seq, tenants) in [
            (1u64, vec!["acme", "acme"]),
            (2, vec!["acme", "globex"]),
            (3, vec!["globex"]),
        ] {
            let stem = format!("seg-{seq:020}-abcdef{seq}");
            std::fs::write(segments.join(format!("{stem}.ccxi")), segment_bytes(&tenants, seq)).unwrap();
            std::fs::write(segments.join(format!("{stem}.ccxseg")), vec![0u8; 400]).unwrap();
            std::fs::write(segments.join(format!("{stem}.ccxe")), vec![0u8; 100]).unwrap();
        }
        state.retrieval_index.write().await.scan_and_load(&segments).unwrap();
        (state, segments)
    }

    fn segment_files(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        names.sort();
        names
    }

    /// End-to-end M4 gate: a real sealed segment with **no `.ccxi`** is
    /// discovered, attributed to its tenant, and removed completely by the
    /// erasure route.
    ///
    /// All four fail on the pre-M4 daemon: the scan matched `.ccxi`, so the
    /// segment was never loaded; `tenant_footprint` read tenancy from the doc
    /// table it does not have; and `reclaim_segment` returned `Ok(0)` for a
    /// segment absent from the loaded set, leaving the subject's data on disk
    /// while reporting a successful erasure.
    #[tokio::test]
    #[serial_test::serial]
    async fn erasure_reclaims_a_segment_that_has_no_ccxi() {
        use crate::local_ingest::{seal_prose_documents, ProseChunk, ProseDocument};

        let state = test_app_state(1);
        let data_dir = state.data_dir.clone();
        for (tenant, text) in [
            ("acme", "the peregrine falcon is the fastest animal"),
            ("globex", "kubernetes ingress controllers and routing"),
        ] {
            seal_prose_documents(
                &data_dir,
                crate::local_ingest::LOCAL_INGEST_SHARD_ID,
                1,
                tenant,
                "corpus",
                "2026-08-09T00:00:00Z",
                &[ProseDocument {
                    doc_id: format!("doc-{tenant}"),
                    chunks: vec![ProseChunk {
                        chunk_id: format!("doc-{tenant}::0"),
                        text: text.to_string(),
                        dense_vector: None,
                    }],
                }],
                None,
            )
            .expect("seal");
        }

        // Strip acme's BM25 companion: what remains is exactly the shape of a
        // fact-only segment, which cannot have one at all.
        let segments = data_dir.join("shards").join("shard-0000").join("segments");
        let acme_stem = std::fs::read_dir(&segments)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| {
                p.extension().and_then(|e| e.to_str()) == Some("ccxi")
                    && corecrux_index::CcxiReader::from_bytes(&std::fs::read(p).unwrap())
                        .map(|r| {
                            r.docs
                                .iter()
                                .any(|d| d.tenant_hash_full == tenant_hash_xxhash64("acme"))
                        })
                        .unwrap_or(false)
            })
            .expect("acme .ccxi");
        std::fs::remove_file(&acme_stem).expect("remove ccxi");
        let acme_ccxseg = acme_stem.with_extension("ccxseg");
        assert!(acme_ccxseg.exists());

        state.retrieval_index.write().await.scan_and_load(&segments).unwrap();
        assert_eq!(
            state.retrieval_index.read().await.segments_without_ccxi().len(),
            1,
            "discovered despite having no .ccxi"
        );

        let (status, body) = forget(&state, serde_json::json!({ "tenant_ids": ["acme"], "reclaim": true })).await;
        assert_eq!(status, StatusCode::OK);

        let row = &body["per_tenant"][0];
        assert_eq!(row["docs_masked"], 1, "attributed from the segment's frame headers");
        assert_eq!(row["segments_reclaimed"], 1);
        assert_eq!(row["mixed_segments_retained"], 0);
        assert_eq!(body["unattributable_segments"], 0);

        assert!(!acme_ccxseg.exists(), "the subject's segment must actually be gone");
        // The co-tenant's segment and its companion are untouched.
        let remaining = segment_files(&segments);
        assert!(
            remaining.iter().any(|n| n.ends_with(".ccxi")),
            "globex's companion should survive: {remaining:?}"
        );
    }

    #[tokio::test]
    async fn reclaim_deletes_whole_tenant_segments_and_keeps_mixed_ones() {
        let (state, segments) = on_disk_state().await;

        let footprint_bytes = state
            .retrieval_index
            .read()
            .await
            .tenant_footprint(tenant_hash_xxhash64("acme"))
            .segments
            .iter()
            .filter(|s| s.whole_tenant)
            .map(|s| s.bytes)
            .sum::<u64>();

        let (status, body) = forget(&state, serde_json::json!({ "tenant_ids": ["acme"], "reclaim": true })).await;
        assert_eq!(status, StatusCode::OK);

        let row = &body["per_tenant"][0];
        assert_eq!(row["segments_reclaimed"], 1, "only the whole-tenant segment goes");
        assert_eq!(row["mixed_segments_retained"], 1);
        assert_eq!(
            row["bytes_reclaimed"].as_u64().unwrap(),
            footprint_bytes,
            "bytes freed match what the footprint promised"
        );

        // Segment 1's whole file group is gone; 2 and 3 are untouched.
        let remaining = segment_files(&segments);
        assert!(
            !remaining.iter().any(|n| n.starts_with("seg-00000000000000000001-")),
            "reclaimed group still on disk: {remaining:?}"
        );
        for seq in ["seg-00000000000000000002-", "seg-00000000000000000003-"] {
            assert_eq!(
                remaining.iter().filter(|n| n.starts_with(seq)).count(),
                3,
                "co-tenant segment files must survive: {remaining:?}"
            );
        }

        // The daemon no longer holds a reader for the deleted segment, so a
        // restart-equivalent rescan finds nothing dangling.
        let index = state.retrieval_index.read().await;
        assert_eq!(index.segment_count(), 2);
        drop(index);
        let mut cold = corecrux_retrieval::IndexManager::new();
        assert_eq!(cold.scan_and_load(&segments).unwrap(), 2, "clean restart");
    }

    #[tokio::test]
    async fn a_reclaimed_mask_cannot_be_lifted() {
        let (state, _) = on_disk_state().await;
        forget(&state, serde_json::json!({ "tenant_ids": ["acme"], "reclaim": true })).await;

        let resp = delete_forget_tenant(State(state.clone()), Path("acme".to_string()), HeaderMap::new()).await;
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "there is nothing to unmask once the files are deleted"
        );
        assert!(state
            .retrieval_index
            .read()
            .await
            .forgotten_watermark(tenant_hash_xxhash64("acme"))
            .is_some());
    }

    #[tokio::test]
    async fn reclaim_is_opt_in() {
        let (state, segments) = on_disk_state().await;
        let before = segment_files(&segments);

        let (_, body) = forget(&state, serde_json::json!({ "tenant_ids": ["acme"] })).await;
        assert_eq!(body["per_tenant"][0]["segments_reclaimed"], 0);
        assert_eq!(body["reclaimed"], false);
        assert_eq!(segment_files(&segments), before, "no file touched without reclaim=true");
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
