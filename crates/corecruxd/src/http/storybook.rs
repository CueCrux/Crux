// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! HTTP routes for the storybook readout (Phase 3 of the context graph).
//!
//! - `POST /v1/projects/{id}/storybook`               — generate a fresh readout
//! - `GET  /v1/projects/{id}/storybook`               — return the latest
//! - `GET  /v1/projects/{id}/storybook/versions`      — list saved readouts
//! - `GET  /v1/projects/{id}/storybook/{ts}`          — fetch one specific
//! - `GET  /v1/projects/{id}/storybook/diff?a=&b=`    — diff two readouts
//!
//! Each readout is persisted as a single private fact under
//! `__storybook__::{project_id}::{ts}` key=`content`. The privacy gate covers
//! `__storybook__::*` so they're never push-eligible without explicit opt-in.
//!
//! ## Selecting less than the whole readout
//!
//! A storybook grows with the workspace it describes, so both single-document
//! reads accept `?section=` (comma-separated prefix match against the section
//! keys) and `?token_budget=`. Without either, the response is the document
//! exactly as generated. With either, `markdown` is rebuilt from the sections
//! that survived and the response reports `truncated` plus `sections_omitted`,
//! so a caller never has to infer whether it saw everything.

use super::context_budget::{
    parse_section_filter, payload_budget, section_matches, section_order_key, serialised_tokens, PRIORITY_SECTIONS,
};
use super::{
    problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, Path, Query, State, StatusCode,
};

const STORYBOOK_PREFIX: &str = "__storybook__";
const STORYBOOK_KEY: &str = "content";

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn entity_for(project_id: &str, ts: u64) -> String {
    format!("{STORYBOOK_PREFIX}::{project_id}::{ts}")
}

fn extract_passport_id(headers: &HeaderMap) -> String {
    headers
        .get("x-corecrux-passport-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "anonymous".to_string())
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn post_generate(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read", "facts:write"]) {
        return problem.into_response();
    }
    if let Err(problem) = super::workspace::require_workspace_scan_global_authority(&state, &headers) {
        return problem.into_response();
    }
    let by_passport = extract_passport_id(&headers);
    let now_ms = now_unix_ms();

    // The same window /v1/code-intel/dead-code answers from, so the readout and
    // the code-intel route cannot disagree about the same symbols.
    // Scoped to this daemon's own capture tenant. This surface has no tenant
    // binding of its own (it authorises with `require_http_scopes`, not the
    // per-tenant variant), so there is no requester tenant to honour. Pinning it
    // to the capture tenant preserves single-tenant behaviour exactly and fails
    // closed if this daemon ever holds more than one tenant's spans — it will
    // simply not see them. Giving this surface real tenant binding is a
    // prerequisite for hosting it (crux-code-intel-pro-hosted-surface M3).
    let spans = super::traces::load_spans(&state, &crate::trace_store::TraceStore::capture_tenant());
    let store = state.fact_store.read().await;
    let doc = match crate::storybook::generate(
        &store,
        crate::storybook::GenerateInput {
            project_id: &project_id,
            by_passport: &by_passport,
            now_unix_ms: now_ms,
            spans: &spans,
        },
    ) {
        Some(d) => d,
        None => return problem_response(StatusCode::NOT_FOUND, format!("project '{project_id}' not found")),
    };
    drop(store);

    let value = match serde_json::to_string(&doc) {
        Ok(v) => v,
        Err(err) => return problem_response(StatusCode::INTERNAL_SERVER_ERROR, format!("encode: {err}")),
    };
    {
        let mut store = state.fact_store.write().await;
        let mut sf = corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity_for(&project_id, now_ms),
            key: STORYBOOK_KEY.to_string(),
            value,
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };
        crate::fact_privacy::enforce_global(&mut sf);
        store.store(sf);
    }

    let summary = serde_json::json!({
        "project_id": doc.project_id,
        "generated_at_unix_ms": doc.generated_at_unix_ms,
        "generated_by_passport": doc.generated_by_passport,
        "stats": doc.stats,
        "bytes": doc.markdown.len(),
        "section_count": doc.sections.len(),
    });
    (StatusCode::OK, Json(summary)).into_response()
}

async fn list_storybook_versions_internal(
    fact_store: &std::sync::Arc<tokio::sync::RwLock<corecrux_memory::FactStore>>,
    project_id: &str,
) -> Vec<u64> {
    let store = fact_store.read().await;
    let prefix = format!("{STORYBOOK_PREFIX}::{project_id}::");
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix.clone()),
        top_k: 200,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    let mut tss: Vec<u64> = latest
        .into_iter()
        .filter(|f| f.entity.starts_with(&prefix) && f.key == STORYBOOK_KEY && !f.value.is_empty())
        .filter_map(|f| f.entity[prefix.len()..].parse::<u64>().ok())
        .collect();
    tss.sort_by(|a, b| b.cmp(a));
    tss
}

async fn load_storybook(
    fact_store: &std::sync::Arc<tokio::sync::RwLock<corecrux_memory::FactStore>>,
    project_id: &str,
    ts: u64,
) -> Option<crate::storybook::StorybookDocument> {
    let store = fact_store.read().await;
    let entity = entity_for(project_id, ts);
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
        .find(|f| f.entity == entity && f.key == STORYBOOK_KEY)?;
    serde_json::from_str::<crate::storybook::StorybookDocument>(&fact.value).ok()
}

/// Query params shared by the two single-document reads.
#[derive(Debug, Default, serde::Deserialize)]
pub(super) struct SelectQuery {
    /// Comma-separated section-key prefixes, e.g. `50` or `30_plane_,60`.
    pub section: Option<String>,
    /// Token ceiling for the whole serialised response.
    pub token_budget: Option<usize>,
}

/// A storybook read, plus what the caller needs to know about what it did not get.
///
/// `#[serde(flatten)]` keeps `project_id` / `markdown` / `sections` / `stats` at
/// the top level, so this is additive: a client written against the raw
/// `StorybookDocument` sees the same fields in the same places.
#[derive(Debug, serde::Serialize)]
pub(super) struct StorybookResponse {
    #[serde(flatten)]
    pub document: crate::storybook::StorybookDocument,
    /// True when `section` or `token_budget` dropped at least one section.
    pub truncated: bool,
    /// Section keys present in the stored readout but absent from this response.
    pub sections_omitted: Vec<String>,
    /// Every saved readout's timestamp, newest first — so a caller can page
    /// back through history without a second round trip to `/versions`.
    pub available_versions: Vec<u64>,
}

/// Apply the `section` filter and the token budget to a loaded document.
///
/// Order of operations matters and is deliberate:
///   1. the explicit `section` filter wins — a caller who names a section gets
///      that section, and the budget only trims within the named set;
///   2. priority sections (front matter, alerts) are admitted first, because a
///      budget too small for everything should still say what this is a readout
///      of and what is wrong with it;
///   3. the remainder is admitted in canonical render order until the budget is
///      spent, and nothing is admitted partially — half a markdown table is
///      worse than an honest omission.
///
/// `available_versions` is an input rather than something the caller stitches on
/// afterwards because it is part of the response and therefore part of what the
/// budget has to pay for.
fn select_sections(
    mut doc: crate::storybook::StorybookDocument,
    q: &SelectQuery,
    available_versions: Vec<u64>,
) -> StorybookResponse {
    let filter = parse_section_filter(q.section.as_deref());
    if filter.is_empty() && q.token_budget.is_none() {
        return StorybookResponse {
            document: doc,
            truncated: false,
            sections_omitted: Vec::new(),
            available_versions,
        };
    }

    let all_keys: Vec<String> = doc.sections.keys().cloned().collect();
    let mut candidates: Vec<String> = all_keys
        .iter()
        .filter(|k| section_matches(k, &filter))
        .cloned()
        .collect();
    candidates.sort_by_key(|k| section_order_key(k));

    let kept: Vec<String> = match q.token_budget {
        None => candidates,
        Some(budget) => {
            // Measure the worst-case envelope: no payload at all, every section
            // reported as omitted. Admitting sections against that can only end
            // under budget, because each admission also shortens the omission
            // list it is being charged against.
            let probe = StorybookResponse {
                document: crate::storybook::StorybookDocument {
                    markdown: String::new(),
                    sections: Default::default(),
                    ..doc.clone()
                },
                truncated: true,
                sections_omitted: all_keys.clone(),
                available_versions: available_versions.clone(),
            };
            let mut remaining = payload_budget(budget, serialised_tokens(&probe));

            let mut kept: Vec<String> = Vec::new();
            let (priority, rest): (Vec<String>, Vec<String>) = candidates
                .into_iter()
                .partition(|k| PRIORITY_SECTIONS.contains(&k.as_str()));
            for key in priority.into_iter().chain(rest) {
                // A kept section is sent TWICE: once as a `sections` map entry
                // and once inside the rebuilt `markdown`. Charge both, in their
                // JSON encoding — escaped newlines and quotes are bytes the
                // caller pays for.
                let cost = doc
                    .sections
                    .get(&key)
                    .map_or(0, |s| serialised_tokens(&(&key, s)) + serialised_tokens(s));
                if cost > remaining {
                    continue;
                }
                remaining -= cost;
                kept.push(key);
            }
            kept.sort_by_key(|k| section_order_key(k));
            kept
        }
    };

    let kept_set: std::collections::BTreeSet<&String> = kept.iter().collect();
    let sections_omitted: Vec<String> = all_keys.into_iter().filter(|k| !kept_set.contains(k)).collect();

    doc.markdown = kept
        .iter()
        .filter_map(|k| doc.sections.get(k))
        .map(String::as_str)
        .collect::<String>();
    doc.sections.retain(|k, _| kept_set.contains(k));
    doc.stats.bytes = doc.markdown.len();

    StorybookResponse {
        truncated: !sections_omitted.is_empty(),
        sections_omitted,
        available_versions,
        document: doc,
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_latest(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    Query(q): Query<SelectQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    if let Err(problem) = super::workspace::require_workspace_scan_global_authority(&state, &headers) {
        return problem.into_response();
    }
    let versions = list_storybook_versions_internal(&state.fact_store, &project_id).await;
    let latest_ts = match versions.first() {
        Some(t) => *t,
        None => {
            return problem_response(
                StatusCode::NOT_FOUND,
                "no readout yet — POST /v1/projects/{id}/storybook to generate one",
            )
        }
    };
    match load_storybook(&state.fact_store, &project_id, latest_ts).await {
        Some(d) => (StatusCode::OK, Json(select_sections(d, &q, versions))).into_response(),
        None => problem_response(StatusCode::INTERNAL_SERVER_ERROR, "failed to load latest readout"),
    }
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn list_versions(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    if let Err(problem) = super::workspace::require_workspace_scan_global_authority(&state, &headers) {
        return problem.into_response();
    }
    let versions = list_storybook_versions_internal(&state.fact_store, &project_id).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "project_id": project_id,
            "count": versions.len(),
            "versions": versions,
        })),
    )
        .into_response()
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_version(
    State(state): State<AppState>,
    Path((project_id, ts)): Path<(String, u64)>,
    Query(q): Query<SelectQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    if let Err(problem) = super::workspace::require_workspace_scan_global_authority(&state, &headers) {
        return problem.into_response();
    }
    match load_storybook(&state.fact_store, &project_id, ts).await {
        Some(d) => {
            let versions = list_storybook_versions_internal(&state.fact_store, &project_id).await;
            (StatusCode::OK, Json(select_sections(d, &q, versions))).into_response()
        }
        None => problem_response(StatusCode::NOT_FOUND, "no readout with that timestamp"),
    }
}

#[derive(Debug, serde::Deserialize)]
pub(super) struct DiffQuery {
    pub a: u64,
    pub b: u64,
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_diff(
    State(state): State<AppState>,
    Path(project_id): Path<String>,
    Query(q): Query<DiffQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    if let Err(problem) = super::workspace::require_workspace_scan_global_authority(&state, &headers) {
        return problem.into_response();
    }
    let a = match load_storybook(&state.fact_store, &project_id, q.a).await {
        Some(d) => d,
        None => return problem_response(StatusCode::NOT_FOUND, format!("readout 'a' (ts={}) not found", q.a)),
    };
    let b = match load_storybook(&state.fact_store, &project_id, q.b).await {
        Some(d) => d,
        None => return problem_response(StatusCode::NOT_FOUND, format!("readout 'b' (ts={}) not found", q.b)),
    };
    let diff = crate::storybook::diff_documents(&a, &b);
    (StatusCode::OK, Json(diff)).into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::storybook::{StorybookDocument, StorybookStats};
    use std::collections::BTreeMap;

    fn state() -> AppState {
        super::super::tests::test_app_state(16)
    }

    /// A document whose sections are big enough that a budget has to choose.
    fn doc(project: &str, ts: u64) -> StorybookDocument {
        let mut sections: BTreeMap<String, String> = BTreeMap::new();
        sections.insert("00_front".into(), format!("# front {}\n\n", "f".repeat(200)));
        sections.insert("10_vision".into(), format!("## vision\n\n{}\n\n", "v".repeat(400)));
        sections.insert("20_goals".into(), format!("## goals\n\n{}\n\n", "g".repeat(400)));
        sections.insert("30_planes_intro".into(), "## Planes\n\n".to_string());
        sections.insert("30_plane_alpha".into(), format!("### alpha\n\n{}\n\n", "a".repeat(400)));
        sections.insert(
            "50_workspace_health".into(),
            format!("## health\n\n{}\n\n", "h".repeat(400)),
        );
        sections.insert(
            "60_alerts".into(),
            format!("## Gaps & alerts\n\n{}\n\n", "x".repeat(120)),
        );
        let markdown = sections.values().cloned().collect::<Vec<_>>().join("");
        StorybookDocument {
            project_id: project.to_string(),
            generated_at_unix_ms: ts,
            generated_by_passport: "p_test".to_string(),
            stats: StorybookStats {
                bytes: markdown.len(),
                ..Default::default()
            },
            markdown,
            sections,
        }
    }

    async fn persist(st: &AppState, d: &StorybookDocument) {
        let mut store = st.fact_store.write().await;
        let mut sf = corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity_for(&d.project_id, d.generated_at_unix_ms),
            key: STORYBOOK_KEY.to_string(),
            value: serde_json::to_string(d).unwrap(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };
        crate::fact_privacy::enforce_global(&mut sf);
        store.store(sf);
    }

    async fn parts(resp: axum::response::Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    #[test]
    fn entity_and_passport_helpers() {
        assert_eq!(entity_for("proj", 42), "__storybook__::proj::42");
        let mut headers = HeaderMap::new();
        assert_eq!(extract_passport_id(&headers), "anonymous");
        headers.insert("x-corecrux-passport-id", "p_abc".parse().unwrap());
        assert_eq!(extract_passport_id(&headers), "p_abc");
    }

    #[test]
    fn no_params_returns_the_document_untouched() {
        let d = doc("proj", 1000);
        let before = d.clone();
        let out = select_sections(d, &SelectQuery::default(), vec![2000, 1000]);
        assert!(!out.truncated);
        assert!(out.sections_omitted.is_empty());
        assert_eq!(out.document.markdown, before.markdown);
        assert_eq!(out.document.sections.len(), before.sections.len());
    }

    #[test]
    fn section_filter_prefix_matches_and_reports_omissions() {
        let out = select_sections(
            doc("proj", 1000),
            &SelectQuery {
                section: Some("30_plane".into()),
                token_budget: None,
            },
            vec![1000],
        );
        assert!(out.truncated);
        let kept: Vec<&String> = out.document.sections.keys().collect();
        assert_eq!(kept, vec!["30_plane_alpha", "30_planes_intro"]);
        // The intro heading precedes the plane it introduces in the rebuilt
        // markdown, even though it sorts after it as a BTreeMap key.
        let intro_at = out.document.markdown.find("## Planes").unwrap();
        let alpha_at = out.document.markdown.find("### alpha").unwrap();
        assert!(intro_at < alpha_at, "planes intro must precede plane detail");
        assert!(out.sections_omitted.contains(&"10_vision".to_string()));
        assert_eq!(out.document.stats.bytes, out.document.markdown.len());
    }

    #[test]
    fn budget_keeps_front_and_alerts_first() {
        // Enough for the envelope, front matter and alerts, but not the 400-char
        // body sections — so the two priority sections must be what survives.
        let out = select_sections(
            doc("proj", 1000),
            &SelectQuery {
                section: None,
                token_budget: Some(340),
            },
            vec![1000],
        );
        assert!(out.truncated);
        let kept: Vec<&str> = out.document.sections.keys().map(String::as_str).collect();
        assert!(kept.contains(&"00_front"), "front matter must survive: {kept:?}");
        assert!(kept.contains(&"60_alerts"), "alerts must survive: {kept:?}");
        for big in ["10_vision", "20_goals", "30_plane_alpha", "50_workspace_health"] {
            assert!(!kept.contains(&big), "{big} must not fit: {kept:?}");
        }
    }

    /// A section too large for the remaining budget is skipped, not fatal: the
    /// fill continues so a small section behind it still gets in.
    #[test]
    fn a_section_that_does_not_fit_does_not_stop_the_fill() {
        let out = select_sections(
            doc("proj", 1000),
            &SelectQuery {
                section: None,
                token_budget: Some(340),
            },
            vec![1000],
        );
        assert!(
            out.document.sections.contains_key("30_planes_intro"),
            "a tiny section behind an oversized one must still be admitted"
        );
    }

    /// The budget is a contract: the bytes actually sent must fit it.
    #[test]
    fn serialised_response_fits_the_budget() {
        for budget in [200usize, 500, 2000, 8000] {
            let out = select_sections(
                doc("proj", 1000),
                &SelectQuery {
                    section: None,
                    token_budget: Some(budget),
                },
                vec![3000, 2000, 1000],
            );
            let bytes = serde_json::to_string(&out).unwrap().len();
            assert!(
                bytes.div_ceil(4) <= budget,
                "overshot: budget {budget}, sent {bytes} bytes (~{} tokens)",
                bytes.div_ceil(4)
            );
        }
    }

    #[test]
    fn a_budget_below_the_envelope_returns_an_honest_empty_payload() {
        let out = select_sections(
            doc("proj", 1000),
            &SelectQuery {
                section: None,
                token_budget: Some(10),
            },
            vec![1000],
        );
        assert!(out.truncated);
        assert!(out.document.sections.is_empty());
        assert_eq!(out.sections_omitted.len(), 7);
        assert_eq!(out.document.markdown, "");
    }

    #[tokio::test]
    async fn get_latest_picks_the_newest_and_lists_versions() {
        let st = state();
        persist(&st, &doc("proj", 1000)).await;
        persist(&st, &doc("proj", 2000)).await;

        let (status, body) = parts(
            get_latest(
                State(st.clone()),
                Path("proj".into()),
                Query(SelectQuery::default()),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["generated_at_unix_ms"], 2000);
        assert_eq!(body["truncated"], false);
        assert_eq!(body["available_versions"], serde_json::json!([2000, 1000]));
        // Flattened: the document's own fields stay where they were.
        assert!(body["markdown"].as_str().unwrap().contains("# front"));
    }

    #[tokio::test]
    async fn get_latest_without_any_readout_is_404() {
        let st = state();
        let (status, _) = parts(
            get_latest(
                State(st),
                Path("proj".into()),
                Query(SelectQuery::default()),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_version_honours_section_and_missing_ts_is_404() {
        let st = state();
        persist(&st, &doc("proj", 1000)).await;

        let (status, body) = parts(
            get_version(
                State(st.clone()),
                Path(("proj".into(), 1000)),
                Query(SelectQuery {
                    section: Some("60".into()),
                    token_budget: None,
                }),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["truncated"], true);
        assert_eq!(body["sections"].as_object().unwrap().len(), 1);
        assert!(body["markdown"].as_str().unwrap().starts_with("## Gaps & alerts"));

        let (status, _) = parts(
            get_version(
                State(st),
                Path(("proj".into(), 9999)),
                Query(SelectQuery::default()),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_versions_is_newest_first() {
        let st = state();
        persist(&st, &doc("proj", 1000)).await;
        persist(&st, &doc("proj", 3000)).await;
        persist(&st, &doc("proj", 2000)).await;
        let (status, body) = parts(
            list_versions(State(st), Path("proj".into()), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["count"], 3);
        assert_eq!(body["versions"], serde_json::json!([3000, 2000, 1000]));
    }

    #[tokio::test]
    async fn diff_reports_added_and_changed_sections() {
        let st = state();
        persist(&st, &doc("proj", 1000)).await;
        let mut newer = doc("proj", 2000);
        newer.sections.insert("40_coverage".into(), "## coverage\n\n".into());
        newer
            .sections
            .insert("10_vision".into(), "## vision\n\nchanged\n\n".into());
        persist(&st, &newer).await;

        let (status, body) = parts(
            get_diff(
                State(st.clone()),
                Path("proj".into()),
                Query(DiffQuery { a: 1000, b: 2000 }),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.get("added_sections").is_some(), "diff shape: {body}");

        // Either side missing is a 404, not a silent empty diff.
        let (status, _) = parts(
            get_diff(
                State(st),
                Path("proj".into()),
                Query(DiffQuery { a: 1000, b: 4242 }),
                HeaderMap::new(),
            )
            .await
            .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn post_generate_missing_project_is_404() {
        let st = state();
        let (status, _) = parts(
            post_generate(State(st), Path("no-such-project".into()), HeaderMap::new())
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
}
