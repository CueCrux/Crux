// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! HTTP routes for agent dossier exchange (Phase 4 of the context graph).
//!
//! - `POST /v1/projects/{id}/dossiers/auto`         — daemon auto-generates a dossier from current state
//! - `POST /v1/projects/{id}/dossiers`              — agent publishes its own dossier
//! - `GET  /v1/projects/{id}/dossiers`              — list saved dossiers (newest first)
//! - `GET  /v1/projects/{id}/dossiers/{dossier_id}` — fetch one
//! - `GET  /v1/projects/{id}/dossiers/diff?a=&b=`   — diff two dossiers
//! - `GET  /v1/projects/{id}/dossiers/reconcile`    — combine all dossiers
//!
//! Each dossier is persisted as a private fact under
//! `__dossier__::{project_id}::{dossier_id}` key=`content`. The privacy gate
//! covers `__dossier__::*` so dossiers are never push-eligible.

use super::{
    problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Path, Query, State, StatusCode,
};

const DOSSIER_PREFIX: &str = "__dossier__";
const DOSSIER_KEY: &str = "content";

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn entity_for(project_id: &str, dossier_id: &str) -> String {
    format!("{DOSSIER_PREFIX}::{project_id}::{dossier_id}")
}

fn extract_passport_id(headers: &HeaderMap) -> String {
    headers
        .get("x-corecrux-passport-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "anonymous".to_string())
}

async fn persist_dossier(
    fact_store: &std::sync::Arc<tokio::sync::RwLock<corecrux_memory::FactStore>>,
    dossier: &crate::dossier::Dossier,
) -> Result<String, String> {
    let value = serde_json::to_string(dossier).map_err(|e| format!("encode: {e}"))?;
    let entity = entity_for(&dossier.project_id, &dossier.dossier_id);
    let mut store = fact_store.write().await;
    let mut sf = corecrux_memory::fact_store::StoreFact {
        tenant_hash: "default".to_string(),
        entity,
        key: DOSSIER_KEY.to_string(),
        value,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    Ok(dossier.dossier_id.clone())
}

pub(super) async fn post_auto(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let agent = extract_passport_id(&headers);
    let now = now_unix_ms();
    let store = state.fact_store.read().await;
    let dossier = match crate::dossier::generate_auto(
        &store,
        crate::dossier::AutoInput {
            project_id: &project_id,
            agent_passport: &agent,
            now_unix_ms: now,
        },
    ) {
        Some(d) => d,
        None => return problem_response(StatusCode::NOT_FOUND, format!("project '{project_id}' not found")),
    };
    drop(store);
    if let Err(err) = persist_dossier(&state.fact_store, &dossier).await {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err);
    }
    (StatusCode::OK, Json(dossier)).into_response()
}

pub(super) async fn post_publish(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
    Json(mut dossier): Json<crate::dossier::Dossier>,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    let agent = extract_passport_id(&headers);
    if dossier.agent_passport.is_empty() {
        dossier.agent_passport = agent;
    }
    if dossier.project_id != project_id {
        return problem_response(
            StatusCode::BAD_REQUEST,
            format!(
                "dossier project_id '{}' does not match URL '{project_id}'",
                dossier.project_id
            ),
        );
    }
    if dossier.dossier_id.is_empty() {
        return problem_response(StatusCode::BAD_REQUEST, "dossier_id is required");
    }
    if dossier.generated_at_unix_ms == 0 {
        dossier.generated_at_unix_ms = now_unix_ms();
    }
    if let Err(err) = persist_dossier(&state.fact_store, &dossier).await {
        return problem_response(StatusCode::INTERNAL_SERVER_ERROR, err);
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "stored": true,
            "dossier_id": dossier.dossier_id,
            "agent": dossier.agent_passport,
            "claim_count": dossier.claims.len(),
        })),
    )
        .into_response()
}

async fn list_dossier_ids_internal(
    fact_store: &std::sync::Arc<tokio::sync::RwLock<corecrux_memory::FactStore>>,
    project_id: &str,
) -> Vec<(String, u64, String)> {
    // Returns (dossier_id, generated_at_unix_ms, agent_passport).
    let store = fact_store.read().await;
    let prefix = format!("{DOSSIER_PREFIX}::{project_id}::");
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        tenant_hash: None,
        query: Some(prefix.clone()),
        entity: None,
        entity_prefix: None,
        top_k: 500,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    let mut out: Vec<(String, u64, String)> = latest
        .into_iter()
        .filter(|f| f.entity.starts_with(&prefix) && f.key == DOSSIER_KEY && !f.value.is_empty())
        .filter_map(|f| {
            let id = f.entity[prefix.len()..].to_string();
            let parsed: serde_json::Value = serde_json::from_str(&f.value).ok()?;
            let ts = parsed.get("generated_at_unix_ms").and_then(|v| v.as_u64()).unwrap_or(0);
            let agent = parsed
                .get("agent_passport")
                .and_then(|v| v.as_str())
                .unwrap_or("anonymous")
                .to_string();
            Some((id, ts, agent))
        })
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1));
    out
}

async fn load_dossier(
    fact_store: &std::sync::Arc<tokio::sync::RwLock<corecrux_memory::FactStore>>,
    project_id: &str,
    dossier_id: &str,
) -> Option<crate::dossier::Dossier> {
    let store = fact_store.read().await;
    let entity = entity_for(project_id, dossier_id);
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        tenant_hash: None,
        query: None,
        entity: Some(entity.clone()),
        entity_prefix: None,
        top_k: 8,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    let fact = latest
        .into_iter()
        .find(|f| f.entity == entity && f.key == DOSSIER_KEY)?;
    serde_json::from_str::<crate::dossier::Dossier>(&fact.value).ok()
}

pub(super) async fn list_dossiers(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let ids = list_dossier_ids_internal(&state.fact_store, &project_id).await;
    let summaries: Vec<serde_json::Value> = ids
        .into_iter()
        .map(|(id, ts, agent)| {
            serde_json::json!({
                "dossier_id": id,
                "generated_at_unix_ms": ts,
                "agent_passport": agent,
            })
        })
        .collect();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "project_id": project_id,
            "count": summaries.len(),
            "dossiers": summaries,
        })),
    )
        .into_response()
}

pub(super) async fn get_dossier(
    State(state): State<AppState>,
    Path((project_id, dossier_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    match load_dossier(&state.fact_store, &project_id, &dossier_id).await {
        Some(d) => (StatusCode::OK, Json(d)).into_response(),
        None => problem_response(StatusCode::NOT_FOUND, "dossier not found"),
    }
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct DiffQuery {
    pub a: String,
    pub b: String,
}

pub(super) async fn get_diff(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    Query(q): Query<DiffQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let a = match load_dossier(&state.fact_store, &project_id, &q.a).await {
        Some(d) => d,
        None => return problem_response(StatusCode::NOT_FOUND, format!("dossier 'a' ({}) not found", q.a)),
    };
    let b = match load_dossier(&state.fact_store, &project_id, &q.b).await {
        Some(d) => d,
        None => return problem_response(StatusCode::NOT_FOUND, format!("dossier 'b' ({}) not found", q.b)),
    };
    let diff = crate::dossier::diff_dossiers(&a, &b);
    (StatusCode::OK, Json(diff)).into_response()
}

pub(super) async fn get_reconciliation(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    // For reconciliation, prefer the LATEST dossier per agent (so an agent
    // that re-published after learning more wins over its older self).
    let ids = list_dossier_ids_internal(&state.fact_store, &project_id).await;
    let mut latest_per_agent: std::collections::BTreeMap<String, (String, u64)> = std::collections::BTreeMap::new();
    for (id, ts, agent) in ids {
        latest_per_agent
            .entry(agent.clone())
            .and_modify(|v| {
                if ts > v.1 {
                    *v = (id.clone(), ts);
                }
            })
            .or_insert((id, ts));
    }
    let mut dossiers: Vec<crate::dossier::Dossier> = Vec::new();
    for (id, _) in latest_per_agent.values() {
        if let Some(d) = load_dossier(&state.fact_store, &project_id, id).await {
            dossiers.push(d);
        }
    }
    let report = crate::dossier::reconcile(&dossiers, now_unix_ms());
    (StatusCode::OK, Json(report)).into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dossier::{Claim, Dossier};

    fn state() -> AppState {
        super::super::tests::test_app_state(16)
    }

    fn claim(id: &str) -> Claim {
        Claim {
            claim_id: id.to_string(),
            kind: "implements".to_string(),
            subject: "plane:a:b".to_string(),
            object: Some("module:x".to_string()),
            confidence: 0.9,
            evidence: vec!["ev1".to_string()],
            rationale: Some("because".to_string()),
        }
    }

    fn dossier(id: &str, project: &str, agent: &str, ts: u64, claims: Vec<Claim>) -> Dossier {
        Dossier {
            dossier_id: id.to_string(),
            project_id: project.to_string(),
            agent_passport: agent.to_string(),
            generated_at_unix_ms: ts,
            based_on: Default::default(),
            claims,
            uncertainties: vec![],
            contradictions: vec![],
            open_questions: vec![],
            stats: Default::default(),
        }
    }

    async fn parts(resp: axum::response::Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    async fn publish(st: &AppState, d: Dossier) -> StatusCode {
        post_publish(State(st.clone()), Path(d.project_id.clone()), HeaderMap::new(), Json(d))
            .await
            .into_response()
            .status()
    }

    #[test]
    fn entity_and_passport_helpers() {
        assert_eq!(entity_for("proj", "d1"), "__dossier__::proj::d1");
        let mut headers = HeaderMap::new();
        assert_eq!(extract_passport_id(&headers), "anonymous");
        headers.insert("x-corecrux-passport-id", "p_abc".parse().unwrap());
        assert_eq!(extract_passport_id(&headers), "p_abc");
    }

    #[tokio::test]
    async fn publish_then_list_get_roundtrip() {
        let st = state();
        let status = publish(
            &st,
            dossier("d1", "proj", "agent-1", 1000, vec![claim("c1"), claim("c2")]),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, body) = parts(
            list_dossiers(State(st.clone()), Path("proj".into()), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], 1);
        assert_eq!(body["dossiers"][0]["dossier_id"], "d1");

        let (status, body) = parts(
            get_dossier(State(st.clone()), Path(("proj".into(), "d1".into())), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["claims"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn publish_fills_defaults_and_validates() {
        let st = state();
        // project_id mismatch → 400.
        let status = post_publish(
            State(st.clone()),
            Path("urlproj".into()),
            HeaderMap::new(),
            Json(dossier("d1", "otherproj", "a", 1, vec![])),
        )
        .await
        .into_response()
        .status();
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // empty dossier_id → 400.
        let status = post_publish(
            State(st.clone()),
            Path("proj".into()),
            HeaderMap::new(),
            Json(dossier("", "proj", "a", 1, vec![])),
        )
        .await
        .into_response()
        .status();
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // empty agent + zero ts get filled from headers/clock.
        let mut headers = HeaderMap::new();
        headers.insert("x-corecrux-passport-id", "p_filled".parse().unwrap());
        let (status, body) = parts(
            post_publish(
                State(st.clone()),
                Path("proj".into()),
                headers,
                Json(dossier("d2", "proj", "", 0, vec![claim("c1")])),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["agent"], "p_filled");
        assert_eq!(body["claim_count"], 1);
    }

    #[tokio::test]
    async fn get_dossier_missing_is_404() {
        let st = state();
        let (status, _) = parts(
            get_dossier(State(st), Path(("proj".into(), "nope".into())), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn diff_two_dossiers_and_missing_arms() {
        let st = state();
        publish(&st, dossier("a", "proj", "agent-1", 1000, vec![claim("c1")])).await;
        publish(
            &st,
            dossier("b", "proj", "agent-1", 2000, vec![claim("c1"), claim("c2")]),
        )
        .await;

        let (status, _) = parts(
            get_diff(
                State(st.clone()),
                Path("proj".into()),
                Query(DiffQuery {
                    a: "a".into(),
                    b: "b".into(),
                }),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Missing 'a'.
        let (status, _) = parts(
            get_diff(
                State(st.clone()),
                Path("proj".into()),
                Query(DiffQuery {
                    a: "ghost".into(),
                    b: "b".into(),
                }),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Missing 'b'.
        let (status, _) = parts(
            get_diff(
                State(st.clone()),
                Path("proj".into()),
                Query(DiffQuery {
                    a: "a".into(),
                    b: "ghost".into(),
                }),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn reconciliation_prefers_latest_per_agent() {
        let st = state();
        // Same agent publishes twice; reconcile should pull only the latest.
        publish(&st, dossier("old", "proj", "agent-1", 1000, vec![claim("c1")])).await;
        publish(
            &st,
            dossier("new", "proj", "agent-1", 2000, vec![claim("c1"), claim("c2")]),
        )
        .await;
        publish(&st, dossier("other", "proj", "agent-2", 1500, vec![claim("c3")])).await;

        let (status, _) = parts(
            get_reconciliation(State(st.clone()), Path("proj".into()), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn post_auto_missing_project_is_404() {
        let st = state();
        let (status, _) = parts(
            post_auto(State(st), Path("no-such-project".into()), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
