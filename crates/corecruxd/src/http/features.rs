// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP surface for the Features lens (M3): `/v1/features/capabilities/*` +
//! `/v1/features/capabilities/analysis/*` + `POST audit`.
//!
//! Implementation is a thin shim that reads from the substrate's
//! `EntityStore` (kind=`capability`) and runs the pure analytics functions
//! from the `crux-lens-features` crate.

use super::{
    problem_response, require_http_any_scope, AppState, HeaderMap, IntoResponse, Json, Path, Query, State, StatusCode,
};
use corecrux_memory::EntityQuery;
use crux_lens_features::{compute_coverage_report, compute_gaps, compute_promise_coverage, CAPABILITY_KIND};
use serde::Deserialize;
use serde_json::{json, Value};

fn load_capabilities(state: &AppState) -> impl std::future::Future<Output = Vec<Value>> + '_ {
    async move {
        let store = state.entity_store.read().await;
        let q = EntityQuery {
            kind: Some(CAPABILITY_KIND.into()),
            limit: None,
            include_deleted: false,
        };
        store.list(&q).into_iter().map(|e| e.payload.clone()).collect()
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ListCapabilitiesQuery {
    pub system: Option<String>,
    pub maturity: Option<String>,
    pub audit: Option<String>,
    pub promise: Option<u64>,
    pub search: Option<String>,
}

fn payload_matches(p: &Value, q: &ListCapabilitiesQuery) -> bool {
    if let Some(s) = &q.system {
        if p.get("system").and_then(|v| v.as_str()) != Some(s.as_str()) {
            return false;
        }
    }
    if let Some(m) = &q.maturity {
        if p.get("maturity").and_then(|v| v.as_str()) != Some(m.as_str()) {
            return false;
        }
    }
    if let Some(a) = &q.audit {
        let aud = p
            .get("audit")
            .and_then(|v| v.get("status"))
            .and_then(|v| v.as_str())
            .unwrap_or("gap");
        if aud != a.as_str() {
            return false;
        }
    }
    if let Some(p_promise) = q.promise {
        let aligned = p
            .get("promise_alignment")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_u64()).any(|x| x == p_promise))
            .unwrap_or(false);
        if !aligned {
            return false;
        }
    }
    if let Some(needle) = &q.search {
        let haystack = format!(
            "{} {} {}",
            p.get("id").and_then(|v| v.as_str()).unwrap_or(""),
            p.get("name").and_then(|v| v.as_str()).unwrap_or(""),
            p.get("description").and_then(|v| v.as_str()).unwrap_or("")
        );
        if !haystack.to_lowercase().contains(&needle.to_lowercase()) {
            return false;
        }
    }
    true
}

pub(super) async fn list_capabilities(
    State(state): State<AppState>,
    Query(q): Query<ListCapabilitiesQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
    let caps = load_capabilities(&state).await;
    let items: Vec<_> = caps.into_iter().filter(|p| payload_matches(p, &q)).collect();
    let count = items.len();
    (StatusCode::OK, Json(json!({"items": items, "count": count}))).into_response()
}

pub(super) async fn get_capability(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
    let store = state.entity_store.read().await;
    match store.get(CAPABILITY_KIND, &id) {
        Some(rec) => (StatusCode::OK, Json(rec.payload.clone())).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, format!("capability {id} not found")),
    }
}

pub(super) async fn get_dependency_tree(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
    let store = state.entity_store.read().await;
    let root = match store.get(CAPABILITY_KIND, &id) {
        Some(r) => r.payload.clone(),
        None => return problem_response(StatusCode::NOT_FOUND, format!("capability {id} not found")),
    };
    drop(store);

    let edges = state.edge_store.read().await;
    let from_q = corecrux_memory::EdgeQuery {
        from_kind: Some(CAPABILITY_KIND.into()),
        from_id: Some(id.clone()),
        edge_kind: Some("depends_on".into()),
        ..Default::default()
    };
    let to_q = corecrux_memory::EdgeQuery {
        to_kind: Some(CAPABILITY_KIND.into()),
        to_id: Some(id.clone()),
        edge_kind: Some("depends_on".into()),
        ..Default::default()
    };

    let mut upstream = Vec::new();
    let mut queue: Vec<String> = edges.list(&from_q).into_iter().map(|e| e.to_id.clone()).collect();
    while let Some(next) = queue.pop() {
        if upstream.contains(&next) {
            continue;
        }
        upstream.push(next.clone());
        let q = corecrux_memory::EdgeQuery {
            from_kind: Some(CAPABILITY_KIND.into()),
            from_id: Some(next),
            edge_kind: Some("depends_on".into()),
            ..Default::default()
        };
        for e in edges.list(&q) {
            queue.push(e.to_id.clone());
        }
    }

    let mut downstream = Vec::new();
    let mut queue: Vec<String> = edges.list(&to_q).into_iter().map(|e| e.from_id.clone()).collect();
    while let Some(next) = queue.pop() {
        if downstream.contains(&next) {
            continue;
        }
        downstream.push(next.clone());
        let q = corecrux_memory::EdgeQuery {
            to_kind: Some(CAPABILITY_KIND.into()),
            to_id: Some(next),
            edge_kind: Some("depends_on".into()),
            ..Default::default()
        };
        for e in edges.list(&q) {
            queue.push(e.from_id.clone());
        }
    }

    (
        StatusCode::OK,
        Json(json!({"root": root, "upstream": upstream, "downstream": downstream})),
    )
        .into_response()
}

pub(super) async fn analysis_gaps(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
    let caps = load_capabilities(&state).await;
    let r = compute_gaps(&caps);
    (StatusCode::OK, Json(json!(r))).into_response()
}

pub(super) async fn analysis_promises(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
    let caps = load_capabilities(&state).await;
    let r = compute_promise_coverage(&caps);
    (StatusCode::OK, Json(json!(r))).into_response()
}

pub(super) async fn analysis_coverage(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:read", "admin:read"]) {
        return p.into_response();
    }
    let caps = load_capabilities(&state).await;
    let r = compute_coverage_report(&caps);
    (StatusCode::OK, Json(json!(r))).into_response()
}

#[derive(Debug, Deserialize)]
pub(super) struct AuditBody {
    pub status: String,
    pub auditor: Option<String>,
    pub notes: Option<String>,
}

pub(super) async fn post_audit(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<AuditBody>,
) -> impl IntoResponse {
    if let Err(p) = require_http_any_scope(&state.auth, &headers, &["facts:write", "admin:write"]) {
        return p.into_response();
    }
    if !matches!(body.status.as_str(), "audited" | "gap" | "waived" | "blocked") {
        return problem_response(
            StatusCode::BAD_REQUEST,
            "status must be one of audited|gap|waived|blocked",
        );
    }
    let actor = crate::auth::http_scope_context(&state.auth, &headers)
        .ok()
        .and_then(|c| c.passport_id)
        .unwrap_or_else(|| "anonymous".into());

    let mut store = state.entity_store.write().await;
    let current = match store.get(CAPABILITY_KIND, &id) {
        Some(r) => r.payload.clone(),
        None => return problem_response(StatusCode::NOT_FOUND, format!("capability {id} not found")),
    };
    let mut payload = current;
    let now = chrono::Utc::now().to_rfc3339();
    let audit_obj = json!({
        "status": body.status,
        "last_audited": if body.status == "audited" { Some(now) } else { None },
        "auditor": body.auditor,
        "notes": body.notes,
    });
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("audit".into(), audit_obj);
    }
    let reg = state.kind_registry.read().await;
    let reg_opt = if reg.is_registered(CAPABILITY_KIND) {
        Some(&*reg)
    } else {
        None
    };
    match store.upsert(CAPABILITY_KIND, &id, payload, &actor, reg_opt) {
        Ok(rec) => (StatusCode::OK, Json(rec.payload.clone())).into_response(),
        Err(e) => problem_response(StatusCode::BAD_REQUEST, e.to_string()),
    }
}
