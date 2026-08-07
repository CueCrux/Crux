// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `GET /v1/work/graph` — the spatial projection of the open ExecPlan board.
//!
//! Same source and the same `admin:read` scope as `/v1/work`; this endpoint adds
//! only the three fields a canvas needs that a list does not: which system a plan
//! changes, which shared services it touches, and a one-line blurb. Classifiers
//! live in [`crate::work_graph`]; edges come from the parser's *declared*
//! `Depends on [[…]]` / `Extended by [[…]]` lines, never from prose mentions.
//!
//! Open work only. A closed plan is not on the board, so it is not on the canvas,
//! and an edge pointing at one is dropped rather than drawn as a dangling stub.

use super::{problem_response, require_http_scopes, AppState, HeaderMap, IntoResponse, Json, State};
use crate::work_graph::{self, PlanFacets};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Per-plan facet cache, keyed by slug and validated by `(mtime, len)`.
///
/// ONLY file-derived facets are cached. A plan's state and milestone counts come
/// from the fact store, and a `gate:M<n>` write changes them without touching the
/// file — so a whole-response cache keyed off mtimes would serve a board that
/// silently lied about progress. Those fields are re-read on every request; what
/// is cached is the expensive half (classification, blurb, declared edges) that
/// genuinely cannot change unless the file does.
///
/// Process-global because there is one plan root per daemon. Bounded by the
/// number of plan files, and entries for deleted plans are dropped each pass.
type FacetCache = HashMap<String, (u64, u64, PlanFacets)>;
static FACETS: OnceLock<Mutex<FacetCache>> = OnceLock::new();

fn facet_cache() -> &'static Mutex<FacetCache> {
    FACETS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[derive(Debug, Serialize)]
pub(super) struct GraphPlan {
    /// Namespaced work id (`execplan:<slug>`), matching `/v1/work`.
    id: String,
    slug: String,
    title: String,
    state: String,
    /// The system this plan predominantly changes — the canvas groups by this.
    plane: &'static str,
    /// Shared services the plan touches, most-referenced first.
    services: Vec<&'static str>,
    /// Declared dependency edges, narrowed to plans that are still open.
    links: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blurb: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_milestone: Option<String>,
    milestones_done: u32,
    milestones_total: u32,
    /// When the plan FILE last changed. On a host whose plan root is an rsync or
    /// git target this is the sync time, not an edit time — on prod every plan
    /// shares it to the millisecond — so it is NOT a recency signal.
    updated_at_unix_ms: u64,
    /// When the plan was last actually worked on: the newest fact written
    /// against it (gate / milestone / decision). This is the honest recency
    /// signal. Absent when a plan has no facts yet — an unworked plan should
    /// read as unworked, not as freshly touched.
    #[serde(skip_serializing_if = "Option::is_none")]
    last_activity_unix_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(super) struct GraphPlane {
    key: &'static str,
    n: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct GraphService {
    key: &'static str,
    /// Perimeter rail the console places this on: top/bottom/left/right.
    side: &'static str,
    n: usize,
}

#[derive(Debug, Serialize)]
pub(super) struct WorkGraph {
    plans: Vec<GraphPlan>,
    /// Planes that actually carry work, largest first. Empty planes are omitted
    /// so the canvas never draws a ring with nothing in it.
    planes: Vec<GraphPlane>,
    /// Services at least one open plan touches, in rail order.
    services: Vec<GraphService>,
    /// Total declared edges between open plans — lets a caller sanity-check a
    /// render without walking every plan.
    link_count: usize,
    generated_at_unix_ms: u64,
}

#[tracing::instrument(level = "info", skip_all)]
pub(super) async fn get_work_graph(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Err(problem) = require_http_scopes(&state.auth, &headers, &["admin:read"]) {
        return problem.into_response();
    }
    // No root configured = the ExecPlan aggregator is off on this daemon. An
    // empty graph is the honest answer; the console dark-checks on `plans`.
    let Some(root) = crate::work_execplans::execplans_root_from_env() else {
        return Json(WorkGraph {
            plans: Vec::new(),
            planes: Vec::new(),
            services: Vec::new(),
            link_count: 0,
            generated_at_unix_ms: now_unix_ms(),
        })
        .into_response();
    };

    let now = now_unix_ms();
    let store = state.fact_store.read().await;
    let items = match crate::work_execplans::list_execplans(&store, &root, now) {
        Ok(items) => items,
        Err(err) => {
            tracing::warn!(error = %err, root = %root.display(), "execplan-aggregator-io-error");
            return problem_response(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "could not read the ExecPlan root".to_string(),
            );
        }
    };
    drop(store);

    // File-derived facets. Stat the directory first and read only the plans
    // whose `(mtime, len)` no longer matches the cache — a board where nothing
    // has been edited does no file reads and no classification at all here.
    let stats = match work_graph::stat_execplans_root(&root) {
        Ok(s) => s,
        Err(err) => {
            tracing::warn!(error = %err, root = %root.display(), "execplan-stat-io-error");
            Vec::new()
        }
    };
    let mut facets: HashMap<String, PlanFacets> = HashMap::with_capacity(stats.len());
    let (mut hits, mut misses) = (0usize, 0usize);
    {
        let mut cache = match facet_cache().lock() {
            Ok(g) => g,
            // A panic in another request must not wedge this endpoint; the cache
            // holds only derived data, so continuing on the recovered map is safe.
            Err(poisoned) => poisoned.into_inner(),
        };
        for st in &stats {
            if let Some((m, l, f)) = cache.get(&st.slug) {
                if *m == st.mtime_unix_ms && *l == st.len {
                    hits += 1;
                    facets.insert(st.slug.clone(), f.clone());
                    continue;
                }
            }
            let Ok(body) = std::fs::read_to_string(&st.path) else {
                tracing::warn!(path = %st.path.display(), "execplan-read-io-error");
                continue;
            };
            let f = work_graph::facets_for(&st.slug, &body);
            misses += 1;
            cache.insert(st.slug.clone(), (st.mtime_unix_ms, st.len, f.clone()));
            facets.insert(st.slug.clone(), f);
        }
        // Drop entries for plans that no longer exist so the map cannot grow
        // without bound across renames.
        if cache.len() > stats.len() {
            let live: std::collections::HashSet<&str> = stats.iter().map(|s| s.slug.as_str()).collect();
            cache.retain(|slug, _| live.contains(slug.as_str()));
        }
    }
    tracing::debug!(hits, misses, plans = stats.len(), "work-graph-facet-cache");

    // Open work only, and the open set is what an edge may point at.
    let open: Vec<&crate::work::WorkItem> = items
        .iter()
        .filter(|w| crate::work_execplans::is_open_state(&w.state))
        .collect();
    let open_slugs: std::collections::HashSet<String> = open.iter().map(|w| slug_of(&w.id).to_string()).collect();

    let mut plans: Vec<GraphPlan> = Vec::with_capacity(open.len());
    let mut plane_counts: HashMap<&'static str, usize> = HashMap::new();
    let mut service_counts: HashMap<&'static str, usize> = HashMap::new();
    let mut link_count = 0usize;

    let empty_facets = PlanFacets {
        plane: work_graph::plane_for("", "", ""),
        services: Vec::new(),
        blurb: None,
        risk: None,
        declared: Vec::new(),
    };
    for w in &open {
        let slug = slug_of(&w.id);
        let f = facets.get(slug).unwrap_or(&empty_facets);

        // Declared edges only — `depends_on` ∪ `extended_by`, both of which the
        // parser sources from declaration lines, never from prose.
        let links = work_graph::narrow_links(&f.declared, &|s| open_slugs.contains(s), slug);
        link_count += links.len();

        let plane = f.plane;
        *plane_counts.entry(plane).or_insert(0) += 1;

        let services = f.services.clone();
        for s in &services {
            *service_counts.entry(*s).or_insert(0) += 1;
        }

        plans.push(GraphPlan {
            id: w.id.clone(),
            slug: slug.to_string(),
            title: w.title.clone(),
            state: w.state.clone(),
            plane,
            services,
            links,
            blurb: f.blurb.clone(),
            risk: f.risk.clone(),
            current_milestone: w.current_milestone.clone(),
            milestones_done: w.milestones_done.unwrap_or(0),
            milestones_total: w.milestones_total.unwrap_or(0),
            updated_at_unix_ms: w.updated_at_unix_ms,
            last_activity_unix_ms: w
                .provenance
                .as_ref()
                .map(|p| p.last_activity_unix_ms)
                .filter(|t| *t > 0),
        });
    }

    // Deterministic order: biggest plane first, then slug. The canvas lays rings
    // out from this, so a stable order keeps the layout stable between loads.
    let mut planes: Vec<GraphPlane> = plane_counts.into_iter().map(|(key, n)| GraphPlane { key, n }).collect();
    planes.sort_by(|a, b| b.n.cmp(&a.n).then_with(|| a.key.cmp(b.key)));
    plans.sort_by(|a, b| a.plane.cmp(b.plane).then_with(|| a.slug.cmp(&b.slug)));

    // Rail order comes from the service table, not from hit counts, so the
    // perimeter is laid out the same way every time.
    let services: Vec<GraphService> = work_graph::all_services()
        .into_iter()
        .filter_map(|(key, side)| service_counts.get(key).map(|n| GraphService { key, side, n: *n }))
        .collect();

    Json(WorkGraph {
        plans,
        planes,
        services,
        link_count,
        generated_at_unix_ms: now,
    })
    .into_response()
}

/// `execplan:<slug>` → `<slug>`; anything else is already a bare id.
fn slug_of(id: &str) -> &str {
    id.strip_prefix("execplan:").unwrap_or(id)
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}
