// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `POST /v1/memory/import` — apply a verified `.cruxpack` to the live
//! stores (ExecPlan `identity-memory-portability-2026-06-11`, M4; spec:
//! `PlanCrux docs/master-plan/shared/Memory-Portability-v1.md` §6).
//!
//! Hard rejects, in order, before any write: flag off (404), unauthenticated
//! / wrong scope (401/403), pack verification failure (400), tenant mismatch
//! (403, T.1), private facts without operator-level auth (403). Then every
//! fact is written through `FactStore::try_store_bulk` — the same journaled
//! bulk path `PUT /v1/facts/bulk` uses — never a raw filesystem write (T.4).
//! Imports never overwrite: collisions land as new versions and the PR #140
//! supersession machinery flags them for review.

use std::collections::BTreeMap;

use corecrux_memory::cruxpack::{self, CruxPack, ImportOptions, PackVerifyError};

use super::{
    http_scope_context, problem_response, require_http_any_scope, require_http_any_scope_for_tenant, AppState,
    HeaderMap, IntoResponse, Json, Response, State, StatusCode,
};

/// Request wrapper produced by `corecruxctl memory import`.
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
pub(super) struct MemoryImportRequest {
    /// The tenant the caller is importing into — must equal the pack
    /// manifest's `tenant_id` (T.1; no override in v1).
    pub tenant_id: String,
    /// Verify + plan only; write nothing.
    #[serde(default)]
    pub dry_run: bool,
    /// Principal remap table (`src` actor → `dst` actor).
    #[serde(default)]
    pub principal_map: BTreeMap<String, String>,
    pub pack: CruxPack,
}

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub(super) struct MemoryImportResponse {
    pub ok: bool,
    pub dry_run: bool,
    pub pack_hash: String,
    pub pack_passport_fpr: String,
    pub imported_facts: usize,
    /// Facts that superseded an existing live `(entity, key)` — reviewable
    /// via `memory_sweep_candidates`, reversible via standard fact retirement.
    pub collisions_superseded: usize,
    pub skipped_duplicate_facts: usize,
    pub imported_sessions: usize,
    pub skipped_sessions: usize,
    pub private_facts: usize,
}

fn verify_status(err: &PackVerifyError) -> StatusCode {
    match err {
        PackVerifyError::TenantMismatch { .. } => StatusCode::FORBIDDEN,
        _ => StatusCode::BAD_REQUEST,
    }
}

#[utoipa::path(
    post,
    path = "/v1/memory/import",
    tag = "Memory",
    request_body = MemoryImportRequest,
    responses(
        (status = 200, description = "Pack imported (or dry-run planned)", body = MemoryImportResponse),
        (status = 400, description = "Pack failed verification"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Tenant mismatch or private facts without operator auth"),
        (status = 404, description = "Import surface disabled (set CRUX_MEMORY_IMPORT=1)"),
    ),
    security(("bearer_auth" = []))
)]
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_memory_import(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<MemoryImportRequest>,
) -> Response {
    // Flag gate — same pattern as /v1/context.
    if !state.memory_import_enabled {
        return problem_response(
            StatusCode::NOT_FOUND,
            "memory import disabled (set CRUX_MEMORY_IMPORT=1)",
        )
        .into_response();
    }

    // T.3: authenticated, fact-write-scoped caller.
    if let Err(problem) = require_http_any_scope(&state.auth, &headers, &["facts:write", "admin:write"]) {
        return problem.into_response();
    }
    let ctx = match http_scope_context(&state.auth, &headers) {
        Ok(ctx) => ctx,
        Err(problem) => return problem.into_response(),
    };
    // T.1: the caller must be allowed the tenant it is importing into (the
    // pack↔tenant equality is enforced again inside `plan_import`).
    if let Err(problem) =
        require_http_any_scope_for_tenant(&state.auth, &headers, &["facts:write", "admin:write"], &body.tenant_id)
    {
        return problem.into_response();
    }

    let import_opts = ImportOptions {
        tenant_id: body.tenant_id.clone(),
        principal_map: body.principal_map.clone(),
    };

    let mut store = state.fact_store.write().await;
    let sessions = state.session_store.read().await;
    let mut plan = match cruxpack::plan_import(&body.pack, &store, Some(&sessions), &import_opts) {
        Ok(plan) => plan,
        Err(err) => return problem_response(verify_status(&err), err.to_string()).into_response(),
    };
    drop(sessions);

    // Private facts ride only under operator-level (raw admin:write) auth —
    // a passport-bound agent cannot smuggle private records in via a pack,
    // mirroring the `PUT /v1/facts` private=true rejection.
    let operator = ctx.passport_id.is_none() && ctx.has_scope("admin:write");
    if plan.private_facts > 0 && !operator {
        return problem_response(
            StatusCode::FORBIDDEN,
            "pack contains private facts — importing them requires operator admin:write auth",
        )
        .into_response();
    }

    let response = |imported_facts: usize, imported_sessions: usize, plan: &cruxpack::ImportPlan, dry_run: bool| {
        Json(MemoryImportResponse {
            ok: true,
            dry_run,
            pack_hash: body.pack.blake3_content_hash.clone(),
            pack_passport_fpr: body.pack.manifest.passport_fpr.clone(),
            imported_facts,
            collisions_superseded: plan.collisions,
            skipped_duplicate_facts: plan.skipped_duplicates,
            imported_sessions,
            skipped_sessions: plan.sessions_skipped,
            private_facts: plan.private_facts,
        })
        .into_response()
    };

    if body.dry_run {
        let resp = response(plan.to_store.len(), plan.sessions_to_add.len(), &plan, true);
        drop(store);
        return resp;
    }

    // Apply facts through the journaled bulk path (privacy policy re-runs at
    // ingest; it can only ever flip private *on*).
    let to_store = std::mem::take(&mut plan.to_store);
    let mut checked = Vec::with_capacity(to_store.len());
    for mut fact in to_store {
        crate::fact_privacy::enforce(&state.privacy_policy, &mut fact);
        if let Err(e) = crux_mcp::category_enforce::check_passport_can_write_entity(
            &store,
            ctx.passport_id.as_deref(),
            &fact.entity,
        ) {
            return problem_response(StatusCode::FORBIDDEN, e.to_string()).into_response();
        }
        checked.push(fact);
    }
    let stored = match store.try_store_bulk(checked) {
        Ok(stored) => stored,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response(),
    };
    drop(store);

    // Sessions: add-only (never overwrite an existing session id).
    let mut imported_sessions = 0_usize;
    if !plan.sessions_to_add.is_empty() {
        let mut session_store = state.session_store.write().await;
        for s in &plan.sessions_to_add {
            if session_store.get(&s.session_id).is_none() {
                session_store.put(&s.session_id, s.state.clone(), None);
                imported_sessions += 1;
            }
        }
    }

    tracing::info!(
        pack_hash = %body.pack.blake3_content_hash,
        pack_passport_fpr = %body.pack.manifest.passport_fpr,
        tenant_id = %body.tenant_id,
        imported_facts = stored.len(),
        collisions = plan.collisions,
        imported_sessions,
        "cruxpack-import-applied"
    );

    response(stored.len(), imported_sessions, &plan, false)
}
