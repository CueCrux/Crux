// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Projection-query routes — `/v1/projections/entity/{count,timeline,current-state}` + admin rebuild.

use super::{
    hex16, map_http_dataplane_error, platform_upgrade_response, problem_response, require_http_scopes, AppState,
    DependentsQuery, HeaderMap, IntoResponse, Json, Path, PressureQuery, ProjMetaQuery, Query, RelationsQuery, State,
    StatusCode, TenantQuery,
};

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_proj_meta(
    State(state): State<AppState>,
    Query(q): Query<ProjMetaQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    if !state.http_dataplane.enabled() {
        return platform_upgrade_response("projections_meta");
    }
    let meta = match state.http_dataplane.projection_meta(&q.shard_id).await {
        Ok(meta) => meta,
        Err(err) => return map_http_dataplane_error(err),
    };
    match meta {
        Some(m) => (StatusCode::OK, Json(m)).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, "projection meta not found"),
    }
}

/// Online projection rebuild — uses daemon-held shard handles, no downtime.
/// POST /v1/admin/projections/rebuild
#[tracing::instrument(level = "info", skip(state, headers))]
pub(super) async fn post_projection_rebuild(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:write"]) {
        return problem.into_response();
    }

    if !state.http_dataplane.enabled() {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    }

    let results = match state.http_dataplane.rebuild_projections_online(1024).await {
        Ok(results) => results,
        Err(err) => return map_http_dataplane_error(err),
    };
    let mut shards = Vec::new();
    let mut any_failed = false;
    for (shard_label, result) in results {
        match result {
            Ok(r) => {
                shards.push(serde_json::json!({
                    "shard": shard_label,
                    "status": "ok",
                    "frames_processed": r.frames_processed,
                    "commit_id": r.commit_id,
                    "living_rows": r.state_counts.living_rows,
                    "relations_edges": r.state_counts.relations_edges,
                }));
            }
            Err(err) => {
                any_failed = true;
                shards.push(serde_json::json!({
                    "shard": shard_label,
                    "status": "error",
                    "error": err,
                }));
            }
        }
    }

    let status = if any_failed {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::OK
    };
    (status, Json(serde_json::json!({ "shards": shards }))).into_response()
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ProjectionModulesQuery {
    #[serde(default)]
    pub shard_id: Option<String>,
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_projection_modules(
    State(state): State<AppState>,
    Query(q): Query<ProjectionModulesQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let current_modules = corecrux_projections::current_projection_module_versions_v1();
    let mut source = "runtime_current";
    let mut commit_id = serde_json::Value::Null;
    let mut module_refs = serde_json::Value::Null;
    let modules = if let Some(shard_id) = q.shard_id.as_deref().filter(|value| !value.trim().is_empty()) {
        if state.http_dataplane.enabled() {
            match state.http_dataplane.projection_meta(shard_id).await {
                Ok(Some(meta)) => {
                    source = "projection_meta";
                    commit_id = serde_json::json!(meta.commit_id);
                    module_refs = serde_json::json!({
                        "artifact_living_state": meta.artifact_living_state.module,
                        "artifact_relations": meta.artifact_relations.module,
                        "pressure_events": meta.pressure_events.module,
                        "artifact_dependents": meta.artifact_dependents.module,
                    });
                    if meta.projection_module_registry.is_empty() {
                        current_modules.clone()
                    } else {
                        meta.projection_module_registry
                    }
                }
                Ok(None) => return problem_response(StatusCode::NOT_FOUND, "projection meta not found"),
                Err(err) => return map_http_dataplane_error(err),
            }
        } else {
            current_modules.clone()
        }
    } else {
        current_modules.clone()
    };

    let replay_availability = modules
        .iter()
        .map(|module| {
            serde_json::json!({
                "module_id": &module.module_id,
                "module_version": &module.module_version,
                "code_hash": &module.code_hash,
                "config_hash": &module.config_hash,
                "status": module.status.as_str(),
                "historical_replay_available": module.status.replay_available(),
            })
        })
        .collect::<Vec<_>>();

    Json(serde_json::json!({
        "schema": corecrux_projections::PROJECTION_MODULES_LIST_SCHEMA_V1,
        "dataplane_enabled": state.http_dataplane.enabled(),
        "source": source,
        "shard_id": q.shard_id,
        "commit_id": commit_id,
        "module_refs": module_refs,
        "modules": modules,
        "current_modules": current_modules,
        "replay_availability": replay_availability,
    }))
    .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(artifact_id, tenant_id = %q.tenant_id))]
pub(super) async fn get_proj_artifact_state(
    State(state): State<AppState>,
    Path(artifact_id): Path<u32>,
    Query(q): Query<TenantQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    if !state.http_dataplane.enabled() {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    }
    let row = match state
        .http_dataplane
        .projection_artifact_state(&q.tenant_id, artifact_id)
        .await
    {
        Ok(row) => row,
        Err(err) => return map_http_dataplane_error(err),
    };

    #[derive(serde::Serialize)]
    struct Resp {
        tenant_id: String,
        artifact_id: u32,
        present: bool,
        living_status: Option<String>,
        confidence: Option<f32>,
        last_validated_at_micros: Option<i64>,
        next_review_at_micros: Option<i64>,
        pressure_level: Option<u8>,
        pressure_reasons_mask: Option<u32>,
        trunk_tier: Option<u8>,
        counts: Option<Counts>,
        updated_at_micros: Option<i64>,
    }
    #[derive(serde::Serialize)]
    struct Counts {
        relations_out: i32,
        relations_in: i32,
        dependents: i32,
    }

    if let Some(row) = row {
        return (
            StatusCode::OK,
            Json(Resp {
                tenant_id: q.tenant_id,
                artifact_id,
                present: true,
                living_status: Some(row.living_status.as_engine_str().to_string()),
                confidence: Some(corecrux_projections::dequantize_confidence_f32(row.confidence_q16)),
                last_validated_at_micros: Some(row.last_validated_at_micros),
                next_review_at_micros: Some(row.next_review_at_micros),
                pressure_level: Some(row.pressure_level),
                pressure_reasons_mask: Some(row.pressure_reasons_mask),
                trunk_tier: Some(row.trunk_tier),
                counts: Some(Counts {
                    relations_out: row.relations_out_count,
                    relations_in: row.relations_in_count,
                    dependents: row.dependents_count,
                }),
                updated_at_micros: Some(row.updated_at_micros),
            }),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        Json(Resp {
            tenant_id: q.tenant_id,
            artifact_id,
            present: false,
            living_status: None,
            confidence: None,
            last_validated_at_micros: None,
            next_review_at_micros: None,
            pressure_level: None,
            pressure_reasons_mask: None,
            trunk_tier: None,
            counts: None,
            updated_at_micros: None,
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(artifact_id, tenant_id = %q.tenant_id))]
pub(super) async fn get_proj_artifact_relations(
    State(state): State<AppState>,
    Path(artifact_id): Path<u32>,
    Query(q): Query<RelationsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    if !state.http_dataplane.enabled() {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    }
    let tenant_id = q.tenant_id.clone();
    let direction = q.direction.as_deref().unwrap_or("out");
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0);

    let rows = match state
        .http_dataplane
        .projection_relations(
            &tenant_id,
            artifact_id,
            direction,
            q.relation_type.as_deref(),
            limit,
            offset,
        )
        .await
    {
        Ok(rows) => rows,
        Err(err) => return map_http_dataplane_error(err),
    };

    #[derive(serde::Serialize)]
    struct Resp {
        tenant_id: String,
        artifact_id: u32,
        direction: String,
        relations: Vec<Rel>,
        page: Page,
    }
    #[derive(serde::Serialize)]
    struct Rel {
        src_artifact_id: u32,
        dst_artifact_id: u32,
        relation_type: String,
        confidence: f32,
        evidence_ref_hash16: String,
        created_at_micros: i64,
        updated_at_micros: i64,
    }
    #[derive(serde::Serialize)]
    struct Page {
        limit: usize,
        offset: usize,
        next_offset: usize,
    }

    let rels = rows
        .into_iter()
        .map(|r| {
            let rt = corecrux_projections::RelationTypeV1::from_u8(r.relation_type).map_or_else(
                || format!("unknown({})", r.relation_type),
                |t| t.as_engine_str().to_string(),
            );
            Rel {
                src_artifact_id: r.src_artifact_id,
                dst_artifact_id: r.dst_artifact_id,
                relation_type: rt,
                confidence: corecrux_projections::dequantize_confidence_f32(r.confidence_q16),
                evidence_ref_hash16: hex16(&r.evidence_ref_hash16),
                created_at_micros: r.created_at_micros,
                updated_at_micros: r.updated_at_micros,
            }
        })
        .collect();

    (
        StatusCode::OK,
        Json(Resp {
            tenant_id,
            artifact_id,
            direction: direction.to_string(),
            relations: rels,
            page: Page {
                limit,
                offset,
                next_offset: offset + limit,
            },
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%artifact_id, tenant_id = %q.tenant_id))]
pub(super) async fn get_proj_artifact_dependents(
    State(state): State<AppState>,
    Path(artifact_id): Path<u32>,
    Query(q): Query<DependentsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    if !state.http_dataplane.enabled() {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    }
    let tenant_id = q.tenant_id.clone();
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0);

    let rows = match state
        .http_dataplane
        .projection_dependents(&tenant_id, artifact_id, q.dependent_type.as_deref(), limit, offset)
        .await
    {
        Ok(rows) => rows,
        Err(err) => return map_http_dataplane_error(err),
    };

    #[derive(serde::Serialize)]
    struct Resp {
        tenant_id: String,
        artifact_id: u32,
        dependents: Vec<Dep>,
        page: Page,
    }
    #[derive(serde::Serialize)]
    struct Dep {
        dependent_type: String,
        dependent_id: String,
        last_seen_at_micros: i64,
        usage_weight: f32,
    }
    #[derive(serde::Serialize)]
    struct Page {
        limit: usize,
        offset: usize,
        next_offset: usize,
    }

    let dependents = rows
        .into_iter()
        .map(|r| Dep {
            dependent_type: corecrux_projections::DependentTypeV1::from_u8(r.dependent_type).map_or_else(
                || format!("unknown({})", r.dependent_type),
                |t| t.as_engine_str().to_string(),
            ),
            dependent_id: r.dependent_id,
            last_seen_at_micros: r.last_seen_at_micros,
            usage_weight: corecrux_projections::dequantize_confidence_f32(r.usage_weight_q16),
        })
        .collect();

    (
        StatusCode::OK,
        Json(Resp {
            tenant_id,
            artifact_id,
            dependents,
            page: Page {
                limit,
                offset,
                next_offset: offset + limit,
            },
        }),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip(state, headers), fields(%artifact_id, tenant_id = %q.tenant_id))]
pub(super) async fn get_proj_artifact_pressure_events(
    State(state): State<AppState>,
    Path(artifact_id): Path<u32>,
    Query(q): Query<PressureQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    if !state.http_dataplane.enabled() {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    }
    let tenant_id = q.tenant_id.clone();
    let open_only = q.open_only.unwrap_or(false);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0);

    let rows = match state
        .http_dataplane
        .projection_pressure_events(&tenant_id, artifact_id, open_only, limit, offset)
        .await
    {
        Ok(rows) => rows,
        Err(err) => return map_http_dataplane_error(err),
    };

    #[derive(serde::Serialize)]
    struct Resp {
        tenant_id: String,
        artifact_id: u32,
        open_only: bool,
        events: Vec<Ev>,
        page: Page,
    }
    #[derive(serde::Serialize)]
    struct Ev {
        event_id: String,
        pressure_code_id: u16,
        severity: u8,
        observed_at_micros: i64,
        acknowledged_at_micros: i64,
        resolved_at_micros: i64,
        receipt_id: Option<String>,
    }
    #[derive(serde::Serialize)]
    struct Page {
        limit: usize,
        offset: usize,
        next_offset: usize,
    }

    let events = rows
        .into_iter()
        .map(|r| Ev {
            event_id: r.event_id.to_string(),
            pressure_code_id: r.pressure_code_id,
            severity: r.severity,
            observed_at_micros: r.observed_at_micros,
            acknowledged_at_micros: r.acknowledged_at_micros,
            resolved_at_micros: r.resolved_at_micros,
            receipt_id: r.receipt_id.map(|u| u.to_string()),
        })
        .collect();

    (
        StatusCode::OK,
        Json(Resp {
            tenant_id,
            artifact_id,
            open_only,
            events,
            page: Page {
                limit,
                offset,
                next_offset: offset + limit,
            },
        }),
    )
        .into_response()
}

// ── Phase 7: Entity projection HTTP handlers ────────────────────────────

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_entity_count(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }

    let tenant_id = params.get("tenant_id").cloned().unwrap_or_default();
    let entity_type = params.get("entity_type").cloned().unwrap_or_default();
    let predicate = params.get("predicate").cloned().unwrap_or_default();

    if !state.http_dataplane.enabled() {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    }

    let all_items = match state
        .http_dataplane
        .entity_count(&tenant_id, &entity_type, &predicate)
        .await
    {
        Ok(items) => items,
        Err(err) => return map_http_dataplane_error(err),
    };

    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "entity_type": entity_type,
        "predicate": predicate,
        "count": all_items.len(),
        "items": all_items,
    }))
    .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_entity_timeline(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }

    let tenant_id = params.get("tenant_id").cloned().unwrap_or_default();
    let entity_type = params.get("entity_type").cloned().unwrap_or_default();
    let predicate = params.get("predicate").cloned().unwrap_or_default();

    if !state.http_dataplane.enabled() {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    }

    let mut all_events: Vec<serde_json::Value> = Vec::new();
    let events = match state
        .http_dataplane
        .entity_timeline(&tenant_id, &entity_type, &predicate)
        .await
    {
        Ok(events) => events,
        Err(err) => return map_http_dataplane_error(err),
    };
    for (name, value, micros) in events {
        let ts_secs = micros / 1_000_000;
        let date_str = chrono::DateTime::from_timestamp(ts_secs, 0)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_default();
        all_events.push(serde_json::json!({
            "entity_name": name,
            "object_value": value,
            "occurred_at": date_str,
        }));
    }

    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "entity_type": entity_type,
        "predicate": predicate,
        "event_count": all_events.len(),
        "timeline": all_events,
    }))
    .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_entity_current_state(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    if require_http_scopes(&state.auth, &headers, &["query:read"]).is_err() {
        if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
            return problem.into_response();
        }
    }

    let tenant_id = params.get("tenant_id").cloned().unwrap_or_default();
    let entity_name = params.get("entity_name").cloned().unwrap_or_default();
    let predicate = params.get("predicate").cloned().unwrap_or_default();

    if !state.http_dataplane.enabled() {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    }

    if let Some((current_value, occurred_at_micros, previous_value, _prev_at)) = match state
        .http_dataplane
        .entity_current_state(&tenant_id, &entity_name, &predicate)
        .await
    {
        Ok(row) => row,
        Err(err) => return map_http_dataplane_error(err),
    } {
        let ts_secs = occurred_at_micros / 1_000_000;
        let date_str = chrono::DateTime::from_timestamp(ts_secs, 0)
            .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
            .unwrap_or_default();
        return Json(serde_json::json!({
            "tenant_id": tenant_id,
            "entity_name": entity_name,
            "predicate": predicate,
            "current_value": current_value,
            "occurred_at": date_str,
            "previous_value": previous_value,
        }))
        .into_response();
    }

    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "entity_name": entity_name,
        "predicate": predicate,
        "current_value": serde_json::Value::Null,
        "not_found": true,
    }))
    .into_response()
}

// ── stateful-extraction-flywheel M1 — chunk extraction cache lookup ────────

/// Request body for `POST /v1/projections/lookup`.
///
/// `mode` = "key" is the only supported value in M1; "vector" and "key_or_vector"
/// are reserved for optional M13 (semantic near-hit cache) and return 400 until
/// that flag ships.
///
/// Fields marked `#[allow(dead_code)]` are intentionally unused in the M1 stub
/// — they're part of the stable contract that VaultCrux clients write against,
/// and ship alongside the materializer in M1.b.
#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
pub(super) struct LookupRequest {
    /// Projection name. Only "extraction_cache_current" is recognized today.
    pub projection: String,
    /// Lookup mode — "key" | "vector" | "key_or_vector".
    #[serde(default = "default_mode")]
    pub mode: String,
    /// Hex-encoded cache_key (required for mode=key and mode=key_or_vector).
    #[serde(default)]
    pub key: Option<String>,
    /// Embedding vector (required for mode=vector and mode=key_or_vector).
    /// Rejected in M1 because semantic near-hit is gated by M13.
    #[serde(default)]
    pub vector: Option<Vec<f32>>,
    /// Cosine-similarity threshold for vector modes. Defaults to 0.98.
    #[serde(default = "default_threshold")]
    pub similarity_threshold: f32,
}

fn default_mode() -> String {
    "key".to_string()
}

fn default_threshold() -> f32 {
    0.98
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct BatchLookupRequest {
    pub projection: String,
    /// List of hex-encoded cache_keys. Batched to amortize HTTP overhead when
    /// a session ingests multiple chunks at once.
    pub keys: Vec<String>,
}

/// `POST /v1/projections/lookup` — key-based projection read.
///
/// Reads from `state.extraction_cache` — an in-memory `ExtractionCacheMaterializer`
/// fed by the append handler when it observes `corecrux.proj.extraction.*` events.
///
/// Scopes: `admin:read` (tenant-agnostic by design; the cache stream is `__global__`).
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_projection_lookup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LookupRequest>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    if req.projection != "extraction_cache_current" {
        return problem_response(StatusCode::NOT_FOUND, format!("unknown projection: {}", req.projection));
    }

    match req.mode.as_str() {
        "key" => {
            let Some(key) = req.key.as_ref() else {
                return problem_response(StatusCode::BAD_REQUEST, "mode=key requires 'key' field");
            };
            let cache = state.extraction_cache.read().await;
            match cache.get(key) {
                Some(row) => Json(serde_json::json!({
                    "hit": true,
                    "materialized": true,
                    "projection": req.projection,
                    "cache_key": row.cache_key,
                    "chunk_hash": row.chunk_hash,
                    "prompt_hash": row.prompt_hash,
                    "model": row.model,
                    "grammar_version": row.grammar_version,
                    "entities": row.entities,
                    "verifier_score": row.verifier_score,
                    "verifier_model": row.verifier_model,
                    "confidence_mean": row.confidence_mean,
                    "source_tenant_id": row.source_tenant_id,
                    "hit_count": row.hit_count,
                    "created_at_micros": row.created_at_micros,
                    "last_hit_at_micros": row.last_hit_at_micros,
                }))
                .into_response(),
                None => Json(serde_json::json!({
                    "hit": false,
                    "materialized": true,
                    "projection": req.projection,
                    "total_rows": cache.len(),
                }))
                .into_response(),
            }
        }
        "vector" | "key_or_vector" => problem_response(
            StatusCode::BAD_REQUEST,
            "vector lookup is gated by M13 (semantic near-hit cache). Use mode=key in M1.",
        ),
        other => problem_response(StatusCode::BAD_REQUEST, format!("unknown mode: {other}")),
    }
}

/// `POST /v1/projections/batch_lookup` — N-key projection read in one round-trip.
#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_projection_batch_lookup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BatchLookupRequest>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    if req.projection != "extraction_cache_current" {
        return problem_response(StatusCode::NOT_FOUND, format!("unknown projection: {}", req.projection));
    }

    let cache = state.extraction_cache.read().await;
    let results: Vec<serde_json::Value> = req
        .keys
        .iter()
        .map(|k| match cache.get(k) {
            Some(row) => serde_json::json!({
                "hit": true,
                "materialized": true,
                "cache_key": row.cache_key,
                "entities": row.entities,
                "model": row.model,
                "grammar_version": row.grammar_version,
                "verifier_score": row.verifier_score,
                "confidence_mean": row.confidence_mean,
            }),
            None => serde_json::json!({
                "hit": false,
                "materialized": true,
            }),
        })
        .collect();

    let hits = results
        .iter()
        .filter(|r| r["hit"] == serde_json::Value::Bool(true))
        .count();

    Json(serde_json::json!({
        "projection": req.projection,
        "materialized": true,
        "count": req.keys.len(),
        "hits": hits,
        "misses": req.keys.len() - hits,
        "results": results,
    }))
    .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod projections_tests {
    use super::super::tests::{enabled_dataplane, test_app_state};
    use super::*;
    use std::collections::HashMap;

    fn enabled() -> AppState {
        let mut s = test_app_state(16);
        s.http_dataplane = enabled_dataplane(vec![], None);
        s
    }

    fn params(pairs: &[(&str, &str)]) -> axum::extract::Query<HashMap<String, String>> {
        axum::extract::Query(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
    }

    #[tokio::test]
    async fn proj_meta_disabled_and_not_found() {
        let q = ProjMetaQuery {
            shard_id: "0".to_string(),
        };
        let resp = get_proj_meta(State(test_app_state(16)), Query(q), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        let q = ProjMetaQuery {
            shard_id: "0".to_string(),
        };
        let resp = get_proj_meta(State(enabled()), Query(q), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND); // stub returns None
    }

    #[tokio::test]
    async fn rebuild_disabled_and_ok() {
        let resp = post_projection_rebuild(State(test_app_state(16)), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        let resp = post_projection_rebuild(State(enabled()), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK); // empty results, no failures
    }

    #[tokio::test]
    async fn projection_modules_runtime_path_no_shard() {
        let q = ProjectionModulesQuery { shard_id: None };
        let resp = get_projection_modules(State(test_app_state(16)), Query(q), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn artifact_state_disabled_and_absent() {
        let resp = get_proj_artifact_state(
            State(test_app_state(16)),
            Path(7u32),
            Query(TenantQuery {
                tenant_id: "t1".to_string(),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);

        // Enabled but the stub returns None → 200 with present:false.
        let resp = get_proj_artifact_state(
            State(enabled()),
            Path(7u32),
            Query(TenantQuery {
                tenant_id: "t1".to_string(),
            }),
            HeaderMap::new(),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn artifact_relations_ok_when_enabled() {
        let q = RelationsQuery {
            tenant_id: "t1".to_string(),
            direction: Some("out".to_string()),
            relation_type: None,
            limit: Some(10),
            offset: Some(0),
        };
        let resp = get_proj_artifact_relations(State(enabled()), Path(1u32), Query(q), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn pressure_events_disabled_and_ok() {
        let q = PressureQuery {
            tenant_id: "t1".to_string(),
            open_only: Some(true),
            limit: Some(25),
            offset: Some(0),
        };
        let resp = get_proj_artifact_pressure_events(State(test_app_state(16)), Path(1u32), Query(q), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        let q = PressureQuery {
            tenant_id: "t1".to_string(),
            open_only: None,
            limit: None,
            offset: None,
        };
        let resp = get_proj_artifact_pressure_events(State(enabled()), Path(1u32), Query(q), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn entity_count_timeline_current_state() {
        // disabled → 501.
        let resp = get_entity_count(
            State(test_app_state(16)),
            HeaderMap::new(),
            params(&[("tenant_id", "t1")]),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);

        // enabled → 200 with canned data.
        let resp = get_entity_count(
            State(enabled()),
            HeaderMap::new(),
            params(&[
                ("tenant_id", "t1"),
                ("entity_type", "person"),
                ("predicate", "lives_in"),
            ]),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = get_entity_timeline(
            State(enabled()),
            HeaderMap::new(),
            params(&[
                ("tenant_id", "t1"),
                ("entity_type", "person"),
                ("predicate", "lives_in"),
            ]),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = get_entity_current_state(
            State(enabled()),
            HeaderMap::new(),
            params(&[("tenant_id", "t1"), ("entity_name", "alice"), ("predicate", "lives_in")]),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
