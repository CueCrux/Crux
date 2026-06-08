// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP surface for the in-process relation graph.
//!
//! Crux Daemon's open distribution provides a usable graph by hand-feeding
//! edges through these endpoints. The graph is held in `AppState.projection_state`
//! and persisted to `data_dir/relations.jsonl`.

use super::{
    problem_response, require_http_any_scope_for_tenant, require_http_scopes, AppState, HeaderMap, IntoResponse, Json,
    Query, State, StatusCode,
};
use corecrux_projections::query::graph_expand::{graph_expand, GraphExpandRequest};
use corecrux_projections::{dequantize_confidence_f32, tenant_hash_xxhash64, RelationTypeV1};

#[derive(Debug, serde::Deserialize)]
pub(super) struct PutRelationBody {
    pub tenant_id: String,
    pub from_id: u32,
    pub to_id: u32,
    pub edge_type: String,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    #[serde(default)]
    pub created_at_micros: Option<i64>,
    #[serde(default)]
    pub updated_at_micros: Option<i64>,
}

fn default_confidence() -> f32 {
    1.0
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ListRelationsQuery {
    pub tenant_id: String,
    pub from_id: u32,
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct ExpandRelationsBody {
    pub tenant_id: String,
    pub seed_artifact_ids: Vec<u32>,
    #[serde(default)]
    pub edge_types: Vec<String>,
    #[serde(default = "default_max_hops")]
    pub max_hops: u32,
    #[serde(default = "default_budget")]
    pub budget: usize,
    #[serde(default)]
    pub min_confidence: f32,
}

fn default_max_hops() -> u32 {
    2
}
fn default_budget() -> usize {
    50
}

pub(super) async fn post_relation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PutRelationBody>,
) -> impl IntoResponse {
    let tenant_id = body.tenant_id.trim().to_string();
    if tenant_id.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id must not be empty");
    }
    if let Err(problem) =
        require_http_any_scope_for_tenant(&state.auth, &headers, &["facts:write", "admin:write"], &tenant_id)
    {
        return problem.into_response();
    }
    if !(0.0..=1.0).contains(&body.confidence) {
        return problem_response(StatusCode::BAD_REQUEST, "confidence must be in [0.0, 1.0]");
    }
    if RelationTypeV1::from_engine_str(body.edge_type.trim().to_ascii_lowercase().as_str()).is_none() {
        return problem_response(
            StatusCode::BAD_REQUEST,
            format!(
                "edge_type must be one of {} (got '{}')",
                crate::relations::supported_edge_types().join(", "),
                body.edge_type
            ),
        );
    }
    let now = current_micros();
    let record = crate::relations::RelationRecord {
        tenant_id,
        from_id: body.from_id,
        to_id: body.to_id,
        edge_type: body.edge_type.trim().to_ascii_lowercase(),
        confidence_bp: (body.confidence.clamp(0.0, 1.0) * 10_000.0) as u16,
        created_at_micros: body.created_at_micros.unwrap_or(now),
        updated_at_micros: body.updated_at_micros.unwrap_or(now),
    };

    if let Err(err) = crate::relations::append_record(&state.data_dir, &record) {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    let mut ps = state.projection_state.write().await;
    if let Err(err) = crate::relations::apply_record(&mut ps, &record) {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err.to_string());
    }
    drop(ps);

    (StatusCode::CREATED, Json(record)).into_response()
}

pub(super) async fn get_relations(
    State(state): State<AppState>,
    Query(query): Query<ListRelationsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    if query.tenant_id.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id must not be empty");
    }
    let tenant_hash = tenant_hash_xxhash64(query.tenant_id.trim());
    let ps = state.projection_state.read().await;
    let edges: Vec<_> = crate::relations::list_outgoing(&ps, tenant_hash, query.from_id)
        .into_iter()
        .filter_map(|((_, _from, to_id, etype_u8), edge)| {
            RelationTypeV1::from_u8(etype_u8).map(|etype| {
                serde_json::json!({
                    "to_id": to_id,
                    "edge_type": etype.as_engine_str(),
                    "confidence": dequantize_confidence_f32(edge.confidence_q16),
                    "created_at_micros": edge.created_at_micros,
                    "updated_at_micros": edge.updated_at_micros,
                })
            })
        })
        .collect();
    drop(ps);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "tenant_id": query.tenant_id,
            "from_id": query.from_id,
            "edges": edges,
        })),
    )
        .into_response()
}

pub(super) async fn post_expand(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<ExpandRelationsBody>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    if body.tenant_id.trim().is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "tenant_id must not be empty");
    }
    if body.seed_artifact_ids.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "seed_artifact_ids must not be empty");
    }
    let mut edge_types = Vec::with_capacity(body.edge_types.len());
    for raw in &body.edge_types {
        match RelationTypeV1::from_engine_str(raw.trim().to_ascii_lowercase().as_str()) {
            Some(t) => edge_types.push(t),
            None => {
                return problem_response(StatusCode::BAD_REQUEST, format!("unknown edge_type '{raw}'"));
            }
        }
    }

    let req = GraphExpandRequest {
        tenant_hash: tenant_hash_xxhash64(body.tenant_id.trim()),
        seed_artifact_ids: body.seed_artifact_ids,
        edge_types,
        max_hops: body.max_hops,
        budget: body.budget,
        min_confidence: body.min_confidence,
        include_state: false,
    };

    let ps = state.projection_state.read().await;
    let resp = graph_expand(&ps, &req);
    drop(ps);

    let artifacts: Vec<_> = resp
        .artifacts
        .iter()
        .map(|a| {
            serde_json::json!({
                "artifact_id": a.artifact_id,
                "score": a.score,
                "hop_distance": a.hop_distance,
                "edge_types_used": a.edge_types_used.iter().map(|t| t.as_engine_str()).collect::<Vec<_>>(),
            })
        })
        .collect();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "artifacts": artifacts,
            "stats": {
                "nodes_visited": resp.stats.nodes_visited,
                "hops_used": resp.stats.hops_used,
                "budget_remaining": resp.stats.budget_remaining,
                "edges_traversed": resp.stats.edges_traversed,
            }
        })),
    )
        .into_response()
}

fn current_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}
