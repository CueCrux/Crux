// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use super::{
    hex16, map_store_error_http, parse_shard_id_u32, problem_response, require_http_scopes, stream_hash_xxhash64,
    AppState, DependentsQuery, HeaderMap, IntoResponse, Json, Path, PressureQuery, ProjMetaQuery, Query,
    RelationsQuery, State, StatusCode, TenantQuery,
};

pub(super) async fn get_proj_meta(
    State(state): State<AppState>,
    Query(q): Query<ProjMetaQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };
    let shard_id_u32 = match parse_shard_id_u32(&q.shard_id) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let (_owner_gpu_id, store) = match pool.store_for_shard_id(&q.shard_id).await {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let guard = store.read().await;
    let meta = guard.projections_meta_for_shard(shard_id_u32);
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

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let results = pool.rebuild_projections_online(1024).await;
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

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let stream_hash = match stream_hash_xxhash64(&q.tenant_id, "artifact", &artifact_id.to_string()) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let (decision, store) = match pool.store_for_stream_hash(stream_hash, None).await {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let shard_id_u32 = match parse_shard_id_u32(&decision.shard_id) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let guard = store.read().await;
    let row = guard.projections_living_state_row(shard_id_u32, &q.tenant_id, artifact_id);

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

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };
    let tenant_id = q.tenant_id.clone();
    let direction = q.direction.as_deref().unwrap_or("out");
    let relation_type_u8 = q
        .relation_type
        .as_deref()
        .and_then(|s| corecrux_projections::RelationTypeV1::from_engine_str(s).map(|t| t.to_u8()));
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0);

    let stream_hash = match stream_hash_xxhash64(&tenant_id, "artifact", &artifact_id.to_string()) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let (decision, store) = match pool.store_for_stream_hash(stream_hash, None).await {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let shard_id_u32 = match parse_shard_id_u32(&decision.shard_id) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let guard = store.read().await;
    let rows = guard.projections_list_relations(
        shard_id_u32,
        &tenant_id,
        artifact_id,
        direction,
        relation_type_u8,
        limit,
        offset,
    );

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

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };
    let tenant_id = q.tenant_id.clone();
    let dt_u8 = q
        .dependent_type
        .as_deref()
        .and_then(|s| corecrux_projections::DependentTypeV1::from_engine_str(s).map(|t| t.to_u8()));
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0);

    let stream_hash = match stream_hash_xxhash64(&tenant_id, "artifact", &artifact_id.to_string()) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let (decision, store) = match pool.store_for_stream_hash(stream_hash, None).await {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let shard_id_u32 = match parse_shard_id_u32(&decision.shard_id) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let guard = store.read().await;
    let rows = guard.projections_list_dependents(shard_id_u32, &tenant_id, artifact_id, dt_u8, limit, offset);

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

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };
    let tenant_id = q.tenant_id.clone();
    let open_only = q.open_only.unwrap_or(false);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0);

    let stream_hash = match stream_hash_xxhash64(&tenant_id, "artifact", &artifact_id.to_string()) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    };
    let (decision, store) = match pool.store_for_stream_hash(stream_hash, None).await {
        Ok(ok) => ok,
        Err(err) => {
            return map_store_error_http(err).into_response();
        }
    };
    let shard_id_u32 = match parse_shard_id_u32(&decision.shard_id) {
        Ok(v) => v,
        Err(e) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    let guard = store.read().await;
    let rows = guard.projections_list_pressure_events(shard_id_u32, &tenant_id, artifact_id, open_only, limit, offset);

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

pub(super) async fn get_entity_count(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let tenant_id = params.get("tenant_id").cloned().unwrap_or_default();
    let entity_type = params.get("entity_type").cloned().unwrap_or_default();
    let predicate = params.get("predicate").cloned().unwrap_or_default();

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let mut all_items: Vec<String> = Vec::new();
    for gpu_id in pool.gpu_ids() {
        let Some(store) = pool.store_for_gpu_id(gpu_id) else {
            continue;
        };
        let guard = store.read().await;
        let items = guard.query_entity_count(&tenant_id, &entity_type, &predicate);
        all_items.extend(items);
    }
    all_items.sort();
    all_items.dedup();

    Json(serde_json::json!({
        "tenant_id": tenant_id,
        "entity_type": entity_type,
        "predicate": predicate,
        "count": all_items.len(),
        "items": all_items,
    }))
    .into_response()
}

pub(super) async fn get_entity_timeline(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let tenant_id = params.get("tenant_id").cloned().unwrap_or_default();
    let entity_type = params.get("entity_type").cloned().unwrap_or_default();
    let predicate = params.get("predicate").cloned().unwrap_or_default();

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    let mut all_events: Vec<serde_json::Value> = Vec::new();
    for gpu_id in pool.gpu_ids() {
        let Some(store) = pool.store_for_gpu_id(gpu_id) else {
            continue;
        };
        let guard = store.read().await;
        let events = guard.query_entity_timeline(&tenant_id, &entity_type, &predicate);
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

pub(super) async fn get_entity_current_state(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let tenant_id = params.get("tenant_id").cloned().unwrap_or_default();
    let entity_name = params.get("entity_name").cloned().unwrap_or_default();
    let predicate = params.get("predicate").cloned().unwrap_or_default();

    let Some(pool) = state.dataplane_pool.as_ref() else {
        return problem_response(StatusCode::NOT_IMPLEMENTED, "dataplane disabled");
    };

    for gpu_id in pool.gpu_ids() {
        let Some(store) = pool.store_for_gpu_id(gpu_id) else {
            continue;
        };
        let guard = store.read().await;
        if let Some((current_value, occurred_at_micros, previous_value, _prev_at)) =
            guard.query_entity_current_state(&tenant_id, &entity_name, &predicate)
        {
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
