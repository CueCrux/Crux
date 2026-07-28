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
//!
//! ## Reading less than the whole dossier
//!
//! A dossier's claim list grows with the workspace, so both reads accept
//! `?token_budget=`. Claims are dropped **lowest-confidence-first**: a caller
//! working to a small budget should get the things the producing agent was most
//! sure of. `stats` always describes the *stored* dossier, not the trimmed one,
//! so `claim_count` stays comparable across budgets; what this response actually
//! carries is reported separately as `claims_omitted`.

use super::context_budget::{payload_budget, serialised_tokens};
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
    // Stats are derived, never asserted. A publisher that sends a stale or
    // hand-written `stats` block would otherwise make `claim_count` disagree
    // with `claims` — and the budgeted read reports `stats` as the stored total,
    // so the disagreement would surface as a wrong number rather than an error.
    dossier.stats = crate::dossier::compute_stats(
        &dossier.claims,
        dossier.uncertainties.len(),
        dossier.contradictions.len(),
        dossier.open_questions.len(),
    );
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
        min_effective_confidence: None,
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
        min_effective_confidence: None,
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

/// Token ceiling for the whole serialised response. Absent = no budget.
#[derive(Debug, Default, serde::Deserialize)]
pub(super) struct BudgetQuery {
    pub token_budget: Option<usize>,
}

/// One dossier, plus what a budget dropped on the way out.
///
/// `#[serde(flatten)]` keeps every `Dossier` field where it already was, so
/// this is additive for clients written against the raw shape.
#[derive(Debug, serde::Serialize)]
pub(super) struct DossierResponse {
    #[serde(flatten)]
    pub dossier: crate::dossier::Dossier,
    pub truncated: bool,
    /// Claims present in the stored dossier but absent from this response.
    /// `stats.claim_count` still reports the stored total.
    pub claims_omitted: usize,
}

/// Trim a dossier's claim list to fit `token_budget`.
///
/// Lowest confidence goes first: the budget is a limit on how much the caller
/// reads, and what it should spend that on is what the producing agent was most
/// certain of. Ties break on `claim_id` so the trim is deterministic — two
/// identical requests must not disagree about which claims exist.
fn budget_dossier(mut d: crate::dossier::Dossier, token_budget: Option<usize>) -> DossierResponse {
    let Some(budget) = token_budget else {
        return DossierResponse {
            dossier: d,
            truncated: false,
            claims_omitted: 0,
        };
    };

    let total = d.claims.len();
    let mut ranked: Vec<crate::dossier::Claim> = std::mem::take(&mut d.claims);

    // Measure the worst-case envelope: every field except the claim list, with
    // the claim list empty and `claims_omitted` at its maximum. Everything that
    // is not a claim is non-negotiable — the anchors, uncertainties and
    // contradictions are what make a partial read safe to act on, and they are
    // small — so they are charged here rather than competing with claims.
    // Admitting claims against this can only end under budget, because each
    // admission also decrements the `claims_omitted` it is charged against.
    let probe = DossierResponse {
        dossier: crate::dossier::Dossier {
            claims: Vec::new(),
            ..d.clone()
        },
        truncated: true,
        claims_omitted: total,
    };
    let mut remaining = payload_budget(budget, serialised_tokens(&probe));
    ranked.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.claim_id.cmp(&b.claim_id))
    });

    let mut kept: Vec<crate::dossier::Claim> = Vec::new();
    for claim in ranked {
        let cost = serialised_tokens(&claim);
        if cost > remaining {
            continue;
        }
        remaining -= cost;
        kept.push(claim);
    }
    // Restore the stored ordering among survivors so a budgeted read reads like
    // a prefix of the full one rather than a re-sorted document.
    kept.sort_by(|a, b| a.claim_id.cmp(&b.claim_id));
    let claims_omitted = total - kept.len();
    d.claims = kept;

    DossierResponse {
        dossier: d,
        truncated: claims_omitted > 0,
        claims_omitted,
    }
}

pub(super) async fn list_dossiers(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    Query(q): Query<BudgetQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    let ids = list_dossier_ids_internal(&state.fact_store, &project_id).await;
    let total = ids.len();
    let mut summaries: Vec<serde_json::Value> = ids
        .into_iter()
        .map(|(id, ts, agent)| {
            serde_json::json!({
                "dossier_id": id,
                "generated_at_unix_ms": ts,
                "agent_passport": agent,
            })
        })
        .collect();
    // Summaries are already newest-first, and newest is what a budget should
    // buy: trim from the tail. The envelope is measured with an empty list, the
    // same worst-case-probe discipline the single-dossier read uses.
    if let Some(budget) = q.token_budget {
        let probe = serde_json::json!({
            "project_id": project_id,
            "count": total,
            "returned": 0,
            "truncated": true,
            "dossiers_omitted": total,
            "dossiers": [],
        });
        let mut remaining = payload_budget(budget, serialised_tokens(&probe));
        let mut keep = 0usize;
        for s in &summaries {
            let cost = serialised_tokens(s);
            if cost > remaining {
                break;
            }
            remaining -= cost;
            keep += 1;
        }
        summaries.truncate(keep);
    }
    let omitted = total - summaries.len();
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "project_id": project_id,
            "count": total,
            "returned": summaries.len(),
            "truncated": omitted > 0,
            "dossiers_omitted": omitted,
            "dossiers": summaries,
        })),
    )
        .into_response()
}

pub(super) async fn get_dossier(
    State(state): State<AppState>,
    Path((project_id, dossier_id)): Path<(String, String)>,
    Query(q): Query<BudgetQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    match load_dossier(&state.fact_store, &project_id, &dossier_id).await {
        Some(d) => (StatusCode::OK, Json(budget_dossier(d, q.token_budget))).into_response(),
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

/// A reconciliation report, plus what a budget dropped.
#[derive(Debug, serde::Serialize)]
pub(super) struct ReconciliationResponse {
    #[serde(flatten)]
    pub report: crate::dossier::ReconciliationReport,
    pub truncated: bool,
    pub disagreements_omitted: usize,
    pub agreements_omitted: usize,
    pub unique_omitted: usize,
}

/// Trim a reconciliation report to fit `token_budget`.
///
/// Disagreement is admitted first, then agreement, then unique. That order is
/// the point of the endpoint: agreement between agents is reassuring but
/// derivable from any one dossier, whereas a disagreement is a fact about the
/// *fleet* that exists nowhere else, and it is what an operator needs to see
/// before trusting either side. `stats` continues to describe the full report,
/// so the counts stay comparable across budgets.
fn budget_reconciliation(
    mut report: crate::dossier::ReconciliationReport,
    token_budget: Option<usize>,
) -> ReconciliationResponse {
    let Some(budget) = token_budget else {
        return ReconciliationResponse {
            report,
            truncated: false,
            disagreements_omitted: 0,
            agreements_omitted: 0,
            unique_omitted: 0,
        };
    };

    let (dis, agr, uni) = (
        std::mem::take(&mut report.disagreement),
        std::mem::take(&mut report.agreement),
        std::mem::take(&mut report.unique),
    );
    let probe = ReconciliationResponse {
        report: report.clone(),
        truncated: true,
        disagreements_omitted: dis.len(),
        agreements_omitted: agr.len(),
        unique_omitted: uni.len(),
    };
    let mut remaining = payload_budget(budget, serialised_tokens(&probe));

    let mut kept_dis = Vec::new();
    for item in dis {
        let cost = serialised_tokens(&item);
        if cost > remaining {
            break;
        }
        remaining -= cost;
        kept_dis.push(item);
    }
    let mut kept_agr = Vec::new();
    for item in agr {
        let cost = serialised_tokens(&item);
        if cost > remaining {
            break;
        }
        remaining -= cost;
        kept_agr.push(item);
    }
    let mut kept_uni = Vec::new();
    for item in uni {
        let cost = serialised_tokens(&item);
        if cost > remaining {
            break;
        }
        remaining -= cost;
        kept_uni.push(item);
    }

    let disagreements_omitted = report.stats.disagreement_count - kept_dis.len();
    let agreements_omitted = report.stats.agreement_count - kept_agr.len();
    let unique_omitted = report.stats.unique_count - kept_uni.len();
    report.disagreement = kept_dis;
    report.agreement = kept_agr;
    report.unique = kept_uni;

    ReconciliationResponse {
        report,
        truncated: disagreements_omitted + agreements_omitted + unique_omitted > 0,
        disagreements_omitted,
        agreements_omitted,
        unique_omitted,
    }
}

pub(super) async fn get_reconciliation(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    Query(q): Query<BudgetQuery>,
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
    (StatusCode::OK, Json(budget_reconciliation(report, q.token_budget))).into_response()
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
            list_dossiers(
                State(st.clone()),
                Path("proj".into()),
                Query(BudgetQuery::default()),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], 1);
        assert_eq!(body["dossiers"][0]["dossier_id"], "d1");

        let (status, body) = parts(
            get_dossier(
                State(st.clone()),
                Path(("proj".into(), "d1".into())),
                Query(BudgetQuery::default()),
                HeaderMap::new(),
            )
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
            get_dossier(
                State(st),
                Path(("proj".into(), "nope".into())),
                Query(BudgetQuery::default()),
                HeaderMap::new(),
            )
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
            get_reconciliation(
                State(st.clone()),
                Path("proj".into()),
                Query(BudgetQuery::default()),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    /// A claim big enough that a budget has to choose between them.
    fn fat_claim(id: &str, confidence: f32) -> Claim {
        Claim {
            claim_id: id.to_string(),
            kind: "module_exists".to_string(),
            subject: format!("module:{}", "m".repeat(120)),
            object: Some("crate:corecruxd".to_string()),
            confidence,
            evidence: vec!["e".repeat(200)],
            rationale: Some("r".repeat(200)),
        }
    }

    #[test]
    fn no_budget_returns_every_claim() {
        let d = dossier("d1", "proj", "a", 1, vec![fat_claim("c1", 0.9), fat_claim("c2", 0.2)]);
        let out = budget_dossier(d, None);
        assert!(!out.truncated);
        assert_eq!(out.claims_omitted, 0);
        assert_eq!(out.dossier.claims.len(), 2);
    }

    #[test]
    fn budget_drops_lowest_confidence_first() {
        let d = dossier(
            "d1",
            "proj",
            "a",
            1,
            vec![fat_claim("c1", 0.3), fat_claim("c2", 0.95), fat_claim("c3", 0.6)],
        );
        // Room for the envelope plus roughly one fat claim.
        let out = budget_dossier(d, Some(300));
        assert!(out.truncated);
        assert_eq!(out.dossier.claims.len(), 1);
        assert_eq!(out.dossier.claims[0].claim_id, "c2");
        assert_eq!(out.claims_omitted, 2);
    }

    #[test]
    fn survivors_keep_stored_order_not_confidence_order() {
        let d = dossier(
            "d1",
            "proj",
            "a",
            1,
            vec![fat_claim("c1", 0.4), fat_claim("c2", 0.9), fat_claim("c3", 0.7)],
        );
        let out = budget_dossier(d, Some(500));
        let ids: Vec<&str> = out.dossier.claims.iter().map(|c| c.claim_id.as_str()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "budgeted read must read like a prefix, not a re-sort");
    }

    /// The budget is a contract: the bytes actually sent must fit it.
    #[test]
    fn serialised_dossier_fits_the_budget() {
        let claims: Vec<Claim> = (0..40)
            .map(|i| fat_claim(&format!("c{i:03}"), 0.1 + (i as f32) / 100.0))
            .collect();
        for budget in [200usize, 500, 2000, 8000] {
            let out = budget_dossier(dossier("d1", "proj", "a", 1, claims.clone()), Some(budget));
            let bytes = serde_json::to_string(&out).unwrap().len();
            assert!(
                bytes.div_ceil(4) <= budget,
                "overshot: budget {budget}, sent {bytes} bytes (~{} tokens)",
                bytes.div_ceil(4)
            );
        }
    }

    #[test]
    fn stats_still_describe_the_stored_dossier() {
        let mut d = dossier("d1", "proj", "a", 1, vec![fat_claim("c1", 0.9), fat_claim("c2", 0.2)]);
        d.stats.claim_count = 2;
        let out = budget_dossier(d, Some(300));
        assert_eq!(out.dossier.claims.len(), 1);
        assert_eq!(
            out.dossier.stats.claim_count, 2,
            "stats describe what is stored, so claim_count stays comparable across budgets"
        );
    }

    #[tokio::test]
    async fn list_dossiers_reports_total_and_what_it_trimmed() {
        let st = state();
        for i in 0..12 {
            publish(
                &st,
                dossier(&format!("d{i:02}"), "proj", &format!("agent-{i}"), 1000 + i, vec![]),
            )
            .await;
        }
        let (status, body) = parts(
            list_dossiers(
                State(st.clone()),
                Path("proj".into()),
                Query(BudgetQuery {
                    token_budget: Some(160),
                }),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], 12, "count is the total, not the page");
        let returned = body["returned"].as_u64().unwrap();
        assert!(returned < 12, "a 160-token budget must not fit 12 summaries");
        assert_eq!(body["truncated"], true);
        assert_eq!(body["dossiers_omitted"].as_u64().unwrap(), 12 - returned);
        // Newest first: what survives is the newest.
        assert_eq!(body["dossiers"][0]["dossier_id"], "d11");
    }

    #[tokio::test]
    async fn get_dossier_honours_the_budget_over_http() {
        let st = state();
        let claims: Vec<Claim> = (0..20)
            .map(|i| fat_claim(&format!("c{i:03}"), 0.1 + (i as f32) / 100.0))
            .collect();
        publish(&st, dossier("d1", "proj", "agent-1", 1000, claims)).await;

        let (status, body) = parts(
            get_dossier(
                State(st),
                Path(("proj".into(), "d1".into())),
                Query(BudgetQuery {
                    token_budget: Some(600),
                }),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["truncated"], true);
        assert!(body["claims"].as_array().unwrap().len() < 20);
        assert!(body["claims_omitted"].as_u64().unwrap() > 0);
        assert_eq!(body["dossier_id"], "d1", "flattened fields stay at the top level");
    }

    /// Disagreement is what reconciliation exists to surface, so a budget too
    /// small for the whole report must spend itself on disagreement first.
    #[tokio::test]
    async fn reconciliation_budget_spends_on_disagreement_first() {
        let st = state();
        // Two agents that agree on 12 subjects and disagree on 3.
        let agree: Vec<Claim> = (0..12)
            .map(|i| Claim {
                claim_id: format!("agree{i:02}"),
                kind: "module_exists".into(),
                subject: format!("module:{}{}", "s".repeat(60), i),
                object: Some("crate:corecruxd".into()),
                confidence: 0.9,
                evidence: vec!["e".repeat(80)],
                rationale: None,
            })
            .collect();
        let disagree = |object: &str| -> Vec<Claim> {
            (0..3)
                .map(|i| Claim {
                    claim_id: format!("dis{i}"),
                    kind: "implements".into(),
                    subject: format!("plane:contested{i}"),
                    object: Some(object.to_string()),
                    confidence: 0.8,
                    evidence: vec!["e".repeat(80)],
                    rationale: None,
                })
                .collect()
        };
        let mut a = agree.clone();
        a.extend(disagree("crate:alpha"));
        let mut b = agree.clone();
        b.extend(disagree("crate:beta"));
        publish(&st, dossier("da", "proj", "agent-a", 1000, a)).await;
        publish(&st, dossier("db", "proj", "agent-b", 1000, b)).await;

        let (status, body) = parts(
            get_reconciliation(
                State(st),
                Path("proj".into()),
                Query(BudgetQuery {
                    token_budget: Some(300),
                }),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["truncated"], true, "300 tokens must not fit 15 subjects");
        assert_eq!(
            body["disagreement"].as_array().unwrap().len(),
            3,
            "every disagreement must survive before any agreement is admitted"
        );
        assert_eq!(body["disagreements_omitted"], 0);
        assert!(
            body["agreements_omitted"].as_u64().unwrap() > 0,
            "agreement is what should have been trimmed"
        );
        assert_eq!(
            body["stats"]["agreement_count"], 12,
            "stats describe the full report, not the trimmed one"
        );

        let bytes = serde_json::to_string(&body).unwrap().len();
        assert!(
            bytes.div_ceil(4) <= 300,
            "overshot: sent {bytes} bytes for a 300-token budget"
        );
    }

    /// An agent should be able to publish the minimum that means something —
    /// an id and some claims — without hand-filling every derived container.
    #[tokio::test]
    async fn publish_accepts_a_minimal_dossier_and_recomputes_stats() {
        let st = state();
        let body: serde_json::Value = serde_json::json!({
            "dossier_id": "d-minimal",
            "project_id": "proj",
            "claims": [
                { "claim_id": "c1", "kind": "implements", "subject": "plane:a", "confidence": 0.9,
                  "evidence": ["src/lib.rs:1"] },
                // No confidence, no evidence: accepted, and confidence defaults
                // to 0.5 rather than 1.0 so it cannot outrank a measured claim.
                { "claim_id": "c2", "kind": "owns", "subject": "plane:b" }
            ]
        });
        let dossier: Dossier = serde_json::from_value(body).expect("minimal dossier must deserialise");
        assert_eq!(dossier.claims[1].confidence, 0.5);
        assert!(
            dossier.stats.claim_count == 0,
            "stats start empty; the handler fills them"
        );

        let status = publish(&st, dossier).await;
        assert_eq!(status, StatusCode::CREATED);

        let (status, stored) = parts(
            get_dossier(
                State(st),
                Path(("proj".into(), "d-minimal".into())),
                Query(BudgetQuery::default()),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            stored["stats"]["claim_count"], 2,
            "stats are derived server-side, never taken on trust"
        );
        assert_eq!(stored["stats"]["claims_by_kind"]["implements"], 1);
        assert_eq!(stored["stats"]["claims_by_confidence_bucket"]["high"], 1);
        assert_eq!(stored["stats"]["claims_by_confidence_bucket"]["med"], 1);
    }

    /// A client-asserted `stats` block never survives: it is recomputed.
    #[tokio::test]
    async fn publish_overwrites_client_asserted_stats() {
        let st = state();
        let mut d = dossier("d-lying", "proj", "agent-1", 1000, vec![claim("c1")]);
        d.stats.claim_count = 999;
        assert_eq!(publish(&st, d).await, StatusCode::CREATED);

        let (_, stored) = parts(
            get_dossier(
                State(st),
                Path(("proj".into(), "d-lying".into())),
                Query(BudgetQuery::default()),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(stored["stats"]["claim_count"], 1);
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
