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

async fn load_capabilities(state: &AppState) -> Vec<Value> {
    let store = state.entity_store.read().await;
    let q = EntityQuery {
        kind: Some(CAPABILITY_KIND.into()),
        limit: None,
        include_deleted: false,
    };
    store.list(&q).into_iter().map(|e| e.payload.clone()).collect()
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
            .is_some_and(|a| a.iter().filter_map(serde_json::Value::as_u64).any(|x| x == p_promise));
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn state() -> AppState {
        super::super::tests::test_app_state(16)
    }

    async fn seed_cap(state: &AppState, id: &str, payload: Value) {
        let mut store = state.entity_store.write().await;
        store.upsert(CAPABILITY_KIND, id, payload, "tester", None).unwrap();
    }

    async fn seed_edge(state: &AppState, from: &str, to: &str) {
        let mut store = state.edge_store.write().await;
        store
            .upsert(
                CAPABILITY_KIND,
                from,
                "depends_on",
                CAPABILITY_KIND,
                to,
                json!({}),
                "tester",
            )
            .unwrap();
    }

    async fn parts(resp: axum::response::Response) -> (StatusCode, Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    fn cap(id: &str, system: &str, maturity: &str) -> Value {
        json!({
            "id": id,
            "name": format!("Capability {id}"),
            "description": "does something useful",
            "system": system,
            "maturity": maturity,
            "promise_alignment": [1, 2],
            "audit": { "status": "gap" },
        })
    }

    #[test]
    fn payload_matches_each_filter_dimension() {
        let p = cap("c1", "billing", "ga");
        // system
        assert!(payload_matches(
            &p,
            &ListCapabilitiesQuery {
                system: Some("billing".into()),
                maturity: None,
                audit: None,
                promise: None,
                search: None
            }
        ));
        assert!(!payload_matches(
            &p,
            &ListCapabilitiesQuery {
                system: Some("other".into()),
                maturity: None,
                audit: None,
                promise: None,
                search: None
            }
        ));
        // maturity
        assert!(payload_matches(
            &p,
            &ListCapabilitiesQuery {
                system: None,
                maturity: Some("ga".into()),
                audit: None,
                promise: None,
                search: None
            }
        ));
        assert!(!payload_matches(
            &p,
            &ListCapabilitiesQuery {
                system: None,
                maturity: Some("beta".into()),
                audit: None,
                promise: None,
                search: None
            }
        ));
        // audit status (defaults to "gap" when absent)
        assert!(payload_matches(
            &p,
            &ListCapabilitiesQuery {
                system: None,
                maturity: None,
                audit: Some("gap".into()),
                promise: None,
                search: None
            }
        ));
        assert!(!payload_matches(
            &p,
            &ListCapabilitiesQuery {
                system: None,
                maturity: None,
                audit: Some("audited".into()),
                promise: None,
                search: None
            }
        ));
        // promise alignment membership
        assert!(payload_matches(
            &p,
            &ListCapabilitiesQuery {
                system: None,
                maturity: None,
                audit: None,
                promise: Some(2),
                search: None
            }
        ));
        assert!(!payload_matches(
            &p,
            &ListCapabilitiesQuery {
                system: None,
                maturity: None,
                audit: None,
                promise: Some(99),
                search: None
            }
        ));
        // search (case-insensitive over id/name/description)
        assert!(payload_matches(
            &p,
            &ListCapabilitiesQuery {
                system: None,
                maturity: None,
                audit: None,
                promise: None,
                search: Some("USEFUL".into())
            }
        ));
        assert!(!payload_matches(
            &p,
            &ListCapabilitiesQuery {
                system: None,
                maturity: None,
                audit: None,
                promise: None,
                search: Some("nonexistent".into())
            }
        ));
    }

    #[tokio::test]
    async fn list_capabilities_filters_and_counts() {
        let st = state();
        seed_cap(&st, "c1", cap("c1", "billing", "ga")).await;
        seed_cap(&st, "c2", cap("c2", "search", "beta")).await;

        let (status, body) = parts(
            list_capabilities(
                State(st.clone()),
                Query(ListCapabilitiesQuery {
                    system: None,
                    maturity: None,
                    audit: None,
                    promise: None,
                    search: None,
                }),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], 2);

        let (_, body) = parts(
            list_capabilities(
                State(st.clone()),
                Query(ListCapabilitiesQuery {
                    system: Some("billing".into()),
                    maturity: None,
                    audit: None,
                    promise: None,
                    search: None,
                }),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(body["count"], 1);
    }

    #[tokio::test]
    async fn get_capability_found_and_missing() {
        let st = state();
        seed_cap(&st, "c1", cap("c1", "billing", "ga")).await;
        let (status, body) = parts(
            get_capability(State(st.clone()), Path("c1".into()), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], "c1");

        let (status, _) = parts(
            get_capability(State(st.clone()), Path("missing".into()), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn dependency_tree_walks_both_directions() {
        let st = state();
        for id in ["a", "b", "c"] {
            seed_cap(&st, id, cap(id, "sys", "ga")).await;
        }
        // a → b → c
        seed_edge(&st, "a", "b").await;
        seed_edge(&st, "b", "c").await;

        let (status, body) = parts(
            get_dependency_tree(State(st.clone()), Path("b".into()), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let upstream: Vec<String> = body["upstream"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let downstream: Vec<String> = body["downstream"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        assert!(upstream.contains(&"c".to_string()), "b depends on c (upstream)");
        assert!(downstream.contains(&"a".to_string()), "a depends on b (downstream)");

        // Missing root → 404.
        let (status, _) = parts(
            get_dependency_tree(State(st.clone()), Path("zzz".into()), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn analysis_endpoints_return_ok() {
        let st = state();
        seed_cap(&st, "c1", cap("c1", "billing", "ga")).await;
        for resp in [
            analysis_gaps(State(st.clone()), HeaderMap::new()).await.into_response(),
            analysis_promises(State(st.clone()), HeaderMap::new())
                .await
                .into_response(),
            analysis_coverage(State(st.clone()), HeaderMap::new())
                .await
                .into_response(),
        ] {
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn post_audit_validates_status_and_updates_payload() {
        let st = state();
        seed_cap(&st, "c1", cap("c1", "billing", "ga")).await;

        // Invalid status → 400.
        let (status, _) = parts(
            post_audit(
                State(st.clone()),
                Path("c1".into()),
                HeaderMap::new(),
                Json(AuditBody {
                    status: "bogus".into(),
                    auditor: None,
                    notes: None,
                }),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Valid "audited" → 200, payload carries audit block + timestamp.
        let (status, body) = parts(
            post_audit(
                State(st.clone()),
                Path("c1".into()),
                HeaderMap::new(),
                Json(AuditBody {
                    status: "audited".into(),
                    auditor: Some("ops".into()),
                    notes: Some("ok".into()),
                }),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["audit"]["status"], "audited");
        assert!(body["audit"]["last_audited"].is_string());

        // Missing capability → 404.
        let (status, _) = parts(
            post_audit(
                State(st.clone()),
                Path("missing".into()),
                HeaderMap::new(),
                Json(AuditBody {
                    status: "gap".into(),
                    auditor: None,
                    notes: None,
                }),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
