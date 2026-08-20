// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Context graph — canonical {nodes, edges} representation of "what an agent
//! knows about this project right now". The agent-native description language
//! the operator asked for.
//!
//! ## Schema
//!
//! Every edge carries a `confidence` tier inspired by graphify:
//! - `extracted`  = found directly in source/data (no guessing)
//! - `inferred`   = derived with reasoning, includes a 0.0–1.0 confidence
//! - `ambiguous`  = surfaced for human review
//!
//! Phase 1A (this revision) only emits `extracted` edges from existing fact
//! store data: project record, project members/tenants, planes, plane
//! members/tenants, project layers, plane layers, indexed GitHub commits.
//! Source-tree extraction and vision↔module inference land in Phase 2.

#![allow(dead_code)] // graph-fold helpers staged for the AX Graph panel — kept for symmetry with sibling renderers

use corecrux_memory::fact_store::{FactQuery, FactStore};
use crux_observe::span_layer::OutcomeExt;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Project,
    Plane,
    Tenant,
    Passport,
    Layer,
    GithubRepo,
    GithubCommit,
    Vision,
    Goal,
    Module,
    File,
    Symbol,
    Claim,
}

impl NodeKind {
    fn snake(&self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::Plane => "plane",
            Self::Tenant => "tenant",
            Self::Passport => "passport",
            Self::Layer => "layer",
            Self::GithubRepo => "github_repo",
            Self::GithubCommit => "github_commit",
            Self::Vision => "vision",
            Self::Goal => "goal",
            Self::Module => "module",
            Self::File => "file",
            Self::Symbol => "symbol",
            Self::Claim => "claim",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    BelongsTo,
    Implements,
    DependsOn,
    References,
    Stubs,
    DeadCode,
    Member,
    Tenant,
    Layer,
    PlanningTarget,
    ClaimAbout,
}

impl EdgeKind {
    fn snake(&self) -> &'static str {
        match self {
            Self::BelongsTo => "belongs_to",
            Self::Implements => "implements",
            Self::DependsOn => "depends_on",
            Self::References => "references",
            Self::Stubs => "stubs",
            Self::DeadCode => "dead_code",
            Self::Member => "member",
            Self::Tenant => "tenant",
            Self::Layer => "layer",
            Self::PlanningTarget => "planning_target",
            Self::ClaimAbout => "claim_about",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Extracted,
    Inferred(f32),
    Ambiguous,
}

#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sublabel: Option<String>,
    /// Free-form metadata for the side panel (size in bytes, version, etc.).
    pub meta: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
    pub kind: EdgeKind,
    pub confidence: Confidence,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ContextGraph {
    pub project_id: String,
    pub generated_at_unix_ms: u64,
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
    pub stats: GraphStats,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct GraphStats {
    pub node_count_by_kind: BTreeMap<String, usize>,
    pub edge_count_by_kind: BTreeMap<String, usize>,
    pub edge_count_by_confidence: BTreeMap<String, usize>,
    pub orphans: Vec<String>,
}

/// Options for [`build_for_project`].
#[derive(Debug, Clone, Default)]
pub struct GraphOptions {
    /// When `true`, fold the latest workspace scan into the graph
    /// (modules, files, deps, stubs, dead-code). Adds a few hundred nodes;
    /// the renderer uses kind filters to keep the view manageable.
    pub include_workspace: bool,
    /// When `true`, include per-symbol nodes (otherwise scan resolution stops
    /// at the file level). Heavy — only enable when an operator wants depth.
    pub include_symbols: bool,
}

/// Build the context graph for a single project from the fact store.
/// Convenience wrapper that uses the default (extracted-only) options.
pub fn build_for_project(store: &FactStore, project_id: &str) -> ContextGraph {
    build_for_project_with_opts(store, project_id, &GraphOptions::default())
}

pub fn build_for_project_with_opts(store: &FactStore, project_id: &str, opts: &GraphOptions) -> ContextGraph {
    let mut g = ContextGraph {
        project_id: project_id.to_string(),
        generated_at_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64),
        ..Default::default()
    };

    // ── Project node ───────────────────────────────────────────────────
    let project = match crate::projects::get_project_detail(store, project_id) {
        Some(p) => p,
        None => return g, // unknown project → empty graph
    };
    let project_node_id = format!("project:{project_id}");
    g.nodes.push(Node {
        id: project_node_id.clone(),
        kind: NodeKind::Project,
        label: project.record.name.clone(),
        sublabel: Some(format!("project · {}", project.record.id)),
        meta: serde_json::json!({
            "default_passport_id": project.record.default_passport_id,
            "planning_target": project.record.planning_target,
            "created_at_unix_ms": project.record.created_at_unix_ms,
        }),
    });

    // Members of the project.
    for m in &project.members {
        let pid = format!("passport:{}", m.passport_id);
        if !g.nodes.iter().any(|n| n.id == pid) {
            g.nodes.push(Node {
                id: pid.clone(),
                kind: NodeKind::Passport,
                label: m.passport_id.clone(),
                sublabel: Some(format!("passport · {}", m.role)),
                meta: serde_json::json!({"role": m.role}),
            });
        }
        g.edges.push(Edge {
            from: pid,
            to: project_node_id.clone(),
            kind: EdgeKind::Member,
            confidence: Confidence::Extracted,
            label: Some(m.role.clone()),
        });
    }

    // Tenants of the project.
    for t in &project.tenants {
        let tid = format!("tenant:{}", t.tenant_id);
        if !g.nodes.iter().any(|n| n.id == tid) {
            g.nodes.push(Node {
                id: tid.clone(),
                kind: NodeKind::Tenant,
                label: t.tenant_id.clone(),
                sublabel: Some("tenant".to_string()),
                meta: serde_json::json!({"default_passport_id": t.default_passport_id}),
            });
        }
        g.edges.push(Edge {
            from: project_node_id.clone(),
            to: tid,
            kind: EdgeKind::Tenant,
            confidence: Confidence::Extracted,
            label: None,
        });
    }

    // Planning target — if it's a github repo, surface as a node.
    if let Some(target) = project.record.planning_target.as_deref() {
        if let Some(slug) = target.strip_prefix("github://") {
            let repo_id = format!("github_repo:{slug}");
            g.nodes.push(Node {
                id: repo_id.clone(),
                kind: NodeKind::GithubRepo,
                label: slug.to_string(),
                sublabel: Some("github repo".to_string()),
                meta: serde_json::json!({"target": target}),
            });
            g.edges.push(Edge {
                from: project_node_id.clone(),
                to: repo_id.clone(),
                kind: EdgeKind::PlanningTarget,
                confidence: Confidence::Extracted,
                label: None,
            });
            // Count indexed commits for this repo.
            let commit_prefix = format!("github::{slug}::commit/");
            let commit_count = count_facts_with_prefix(store, &commit_prefix);
            if commit_count > 0 {
                let cn = format!("{repo_id}#commits");
                g.nodes.push(Node {
                    id: cn.clone(),
                    kind: NodeKind::GithubCommit,
                    label: format!("{commit_count} commits indexed"),
                    sublabel: Some("github commits".to_string()),
                    meta: serde_json::json!({"count": commit_count, "prefix": commit_prefix}),
                });
                g.edges.push(Edge {
                    from: repo_id,
                    to: cn,
                    kind: EdgeKind::References,
                    confidence: Confidence::Extracted,
                    label: None,
                });
            }
        }
    }

    // Project layers.
    let project_layer_prefix = format!("__project_layer__::{project_id}::");
    let layer_facts = query_prefix(store, &project_layer_prefix, 200);
    let latest_layers = crate::fact_helpers::dedup_latest(layer_facts);
    for fact in latest_layers {
        if fact.key != "content" || fact.value.is_empty() {
            continue;
        }
        let name = fact.entity[project_layer_prefix.len()..].to_string();
        let layer_node_id = format!("layer:{project_id}:{name}");
        g.nodes.push(Node {
            id: layer_node_id.clone(),
            kind: NodeKind::Layer,
            label: name.clone(),
            sublabel: Some(format!("layer · v{}", fact.version)),
            meta: serde_json::json!({
                "bytes": fact.value.len(),
                "version": fact.version,
                "fact_id": fact.fact_id,
                "stored_at": fact.stored_at.to_rfc3339(),
            }),
        });
        g.edges.push(Edge {
            from: project_node_id.clone(),
            to: layer_node_id,
            kind: EdgeKind::Layer,
            confidence: Confidence::Extracted,
            label: Some(name),
        });
    }

    // ── Planes + their members/tenants/layers ─────────────────────────
    let planes = crate::planes::list_planes(store, project_id);
    for plane in &planes {
        let plane_node_id = format!("plane:{project_id}:{}", plane.id);
        g.nodes.push(Node {
            id: plane_node_id.clone(),
            kind: NodeKind::Plane,
            label: plane.name.clone(),
            sublabel: Some(format!("plane · {}", plane.id)),
            meta: serde_json::json!({
                "id": plane.id,
                "description": plane.description,
                "default_passport_id": plane.default_passport_id,
            }),
        });
        g.edges.push(Edge {
            from: plane_node_id.clone(),
            to: project_node_id.clone(),
            kind: EdgeKind::BelongsTo,
            confidence: Confidence::Extracted,
            label: None,
        });

        for m in crate::planes::list_members(store, project_id, &plane.id) {
            let pid = format!("passport:{}", m.passport_id);
            if !g.nodes.iter().any(|n| n.id == pid) {
                g.nodes.push(Node {
                    id: pid.clone(),
                    kind: NodeKind::Passport,
                    label: m.passport_id.clone(),
                    sublabel: Some(format!("passport · {}", m.role)),
                    meta: serde_json::json!({"role": m.role}),
                });
            }
            g.edges.push(Edge {
                from: pid,
                to: plane_node_id.clone(),
                kind: EdgeKind::Member,
                confidence: Confidence::Extracted,
                label: Some(m.role.clone()),
            });
        }

        for t in crate::planes::list_tenants(store, project_id, &plane.id) {
            let tid = format!("tenant:{}", t.tenant_id);
            if !g.nodes.iter().any(|n| n.id == tid) {
                g.nodes.push(Node {
                    id: tid.clone(),
                    kind: NodeKind::Tenant,
                    label: t.tenant_id.clone(),
                    sublabel: Some("tenant".to_string()),
                    meta: serde_json::json!({"default_passport_id": t.default_passport_id}),
                });
            }
            g.edges.push(Edge {
                from: plane_node_id.clone(),
                to: tid,
                kind: EdgeKind::Tenant,
                confidence: Confidence::Extracted,
                label: None,
            });
        }

        // Plane layers.
        let plane_layer_prefix = format!("__plane_layer__::{project_id}::{}::", plane.id);
        let plane_layer_facts = query_prefix(store, &plane_layer_prefix, 200);
        let latest_plane_layers = crate::fact_helpers::dedup_latest(plane_layer_facts);
        for fact in latest_plane_layers {
            if fact.key != "content" || fact.value.is_empty() {
                continue;
            }
            let name = fact.entity[plane_layer_prefix.len()..].to_string();
            let layer_node_id = format!("plane_layer:{project_id}:{}:{name}", plane.id);
            g.nodes.push(Node {
                id: layer_node_id.clone(),
                kind: NodeKind::Layer,
                label: name.clone(),
                sublabel: Some(format!("plane layer · v{}", fact.version)),
                meta: serde_json::json!({
                    "bytes": fact.value.len(),
                    "version": fact.version,
                    "fact_id": fact.fact_id,
                    "stored_at": fact.stored_at.to_rfc3339(),
                }),
            });
            g.edges.push(Edge {
                from: plane_node_id.clone(),
                to: layer_node_id,
                kind: EdgeKind::Layer,
                confidence: Confidence::Extracted,
                label: Some(name),
            });
        }
    }

    // ── Workspace scan fold-in (opt-in via opts.include_workspace) ────
    if opts.include_workspace {
        if let Some(scan) = load_latest_workspace_blocking(store) {
            fold_workspace_into_graph(&mut g, &scan, opts.include_symbols);
        }
    }

    // ── Stats + orphan detection ──────────────────────────────────────
    for n in &g.nodes {
        *g.stats
            .node_count_by_kind
            .entry(n.kind.snake().to_string())
            .or_insert(0) += 1;
    }
    for e in &g.edges {
        *g.stats
            .edge_count_by_kind
            .entry(e.kind.snake().to_string())
            .or_insert(0) += 1;
        let conf_key = match &e.confidence {
            Confidence::Extracted => "extracted",
            Confidence::Inferred(_) => "inferred",
            Confidence::Ambiguous => "ambiguous",
        };
        *g.stats
            .edge_count_by_confidence
            .entry(conf_key.to_string())
            .or_insert(0) += 1;
    }
    let mut connected: std::collections::HashSet<String> = std::collections::HashSet::new();
    for e in &g.edges {
        connected.insert(e.from.clone());
        connected.insert(e.to.clone());
    }
    g.stats.orphans = g
        .nodes
        .iter()
        .filter(|n| !connected.contains(&n.id))
        .map(|n| n.id.clone())
        .collect();

    g
}

fn query_prefix(store: &FactStore, prefix: &str, top_k: usize) -> Vec<corecrux_memory::fact_store::Fact> {
    store
        .query(&FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            query: None,
            entity: None,
            entity_prefix: Some(prefix.to_string()),
            top_k,
            token_budget: None,
        })
        .facts
        .into_iter()
        .filter(|f| f.entity.starts_with(prefix))
        .collect()
}

/// Synchronous variant of [`crate::workspace_scan::load_latest`] for use
/// inside the (synchronous) `build_for_project_with_opts`. Public so the
/// storybook generator can read the same data.
pub fn load_latest_workspace_blocking_pub(store: &FactStore) -> Option<crate::workspace_scan::WorkspaceScan> {
    load_latest_workspace_blocking(store)
}

/// Records `crux.outcome` (ExecPlan `crux-code-intel-silent-empty-outcomes`, M2).
///
/// This function *is* the first motivating bug. It ran on every storybook
/// generation and returned `None`, so the storybook reported 0 LOC, 0 stubs and
/// 0 dead code — a result indistinguishable from "no scan has ever been run".
/// `liveness` said `executed: true`, which was correct and useless. The lookup
/// is fixed (`20ba145`), but the *class* is only observable if the site says
/// whether its work came back empty.
///
/// Admission bar: if this returned `None` on every call, that would be a bug —
/// a daemon with a workspace scan on disk must be able to read it back.
#[tracing::instrument(level = "info", skip_all, fields(crux.outcome = tracing::field::Empty))]
fn load_latest_workspace_blocking(store: &FactStore) -> Option<crate::workspace_scan::WorkspaceScan> {
    // Exact-entity lookup, NOT a `query:` text search.
    //
    // `query:` is not a prefix scan and not BM25 — an earlier version of this
    // comment said length normalisation buried the fact, which was wrong about
    // the mechanism though right that the lookup failed. What `query:` actually
    // does (`corecrux_memory::fact_store::query_inner`) is one of two things:
    // a lowercase SUBSTRING match over value/key/entity, or — when a dense
    // provider is configured — nothing at all, because keyword filtering is
    // skipped and every fact is ranked by cosine similarity instead. Either way
    // the result is then truncated to `top_k`, so a specific entity can be
    // ranked out by unrelated facts and the caller sees an empty result rather
    // than an error.
    //
    // There is exactly one entity to fetch and its id is a constant. Asking for
    // it by name cannot be ranked out.
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: Some(crate::workspace_scan::LATEST_SCAN_ENTITY.to_string()),
        entity_prefix: None,
        top_k: 8,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    // `and_then` rather than `?`: the outcome must be recorded on the
    // not-found path too, which is the whole point of the dimension.
    latest
        .into_iter()
        .find(|f| f.entity == crate::workspace_scan::LATEST_SCAN_ENTITY && f.key == crate::workspace_scan::SCAN_KEY)
        .and_then(|fact| serde_json::from_str::<crate::workspace_scan::WorkspaceScan>(&fact.value).ok())
        .record_outcome_through()
}

/// Fold a workspace scan into the project graph. Adds module / file (and
/// optionally symbol) nodes plus depends_on / stubs / dead_code edges.
fn fold_workspace_into_graph(g: &mut ContextGraph, scan: &crate::workspace_scan::WorkspaceScan, include_symbols: bool) {
    use std::collections::HashSet;
    let module_node = |crate_name: &str| format!("module:{crate_name}");
    let file_node = |rel: &str| format!("file:{rel}");
    let stub_node = |rel: &str, line: usize| format!("stub:{rel}:{line}");

    let mut module_ids: HashSet<String> = HashSet::new();
    // Crates as modules.
    for c in &scan.crates {
        let id = module_node(&c.name);
        if module_ids.insert(id.clone()) {
            g.nodes.push(Node {
                id,
                kind: NodeKind::Module,
                label: c.name.clone(),
                sublabel: Some(format!("crate · {} files · {} loc", c.file_count, c.total_loc)),
                meta: serde_json::json!({
                    "rel_path": c.rel_path,
                    "internal_deps": c.internal_deps,
                    "file_count": c.file_count,
                    "total_loc": c.total_loc,
                }),
            });
        }
        // Edges between crates from internal_deps.
        for dep in &c.internal_deps {
            // Only emit if the target is a known crate in this scan.
            if scan.crates.iter().any(|x| &x.name == dep) {
                g.edges.push(Edge {
                    from: module_node(&c.name),
                    to: module_node(dep),
                    kind: EdgeKind::DependsOn,
                    confidence: Confidence::Extracted,
                    label: Some("Cargo".to_string()),
                });
            }
        }
    }

    // Files belong-to crate.
    for f in &scan.files {
        let id = file_node(&f.rel_path);
        g.nodes.push(Node {
            id: id.clone(),
            kind: NodeKind::File,
            label: f.rel_path.rsplit('/').next().unwrap_or(&f.rel_path).to_string(),
            sublabel: Some(format!(
                "{} · {} loc · {} symbols",
                f.module_path, f.loc, f.symbol_count
            )),
            meta: serde_json::json!({
                "rel_path": f.rel_path,
                "module_path": f.module_path,
                "loc": f.loc,
                "symbol_count": f.symbol_count,
                "stub_count": f.stub_count,
            }),
        });
        g.edges.push(Edge {
            from: id.clone(),
            to: module_node(&f.crate_name),
            kind: EdgeKind::BelongsTo,
            confidence: Confidence::Extracted,
            label: None,
        });
    }

    // Per-symbol nodes (gated; off by default).
    if include_symbols {
        for s in &scan.symbols {
            let id = format!("symbol:{}:{}", s.file_rel_path, s.line);
            g.nodes.push(Node {
                id: id.clone(),
                kind: NodeKind::Symbol,
                label: s.name.clone(),
                sublabel: Some(format!("{} · {}:{}", s.kind, s.file_rel_path, s.line)),
                meta: serde_json::json!({
                    "kind": s.kind,
                    "is_pub": s.is_pub,
                    "module_path": s.module_path,
                    "file_rel_path": s.file_rel_path,
                    "line": s.line,
                }),
            });
            g.edges.push(Edge {
                from: id,
                to: file_node(&s.file_rel_path),
                kind: EdgeKind::BelongsTo,
                confidence: Confidence::Extracted,
                label: None,
            });
        }
    }

    // depends_on edges between crates (file-level resolution would explode
    // the edge count; we collapse by rolling up to to_crate when the use
    // target's first segment matches a known crate).
    let crate_name_set: HashSet<String> = scan.crates.iter().map(|c| c.name.replace('-', "_")).collect();
    let mut emitted_crate_deps: HashSet<(String, String)> = HashSet::new();
    for d in &scan.deps {
        let target_first = d.to_module.split("::").next().unwrap_or("");
        if !crate_name_set.contains(target_first) {
            continue;
        }
        let from_crate_norm = d.from_crate.replace('-', "_");
        if from_crate_norm == target_first {
            continue;
        }
        // Find the original crate name (with hyphens) for the edge.
        let to_crate_orig = scan
            .crates
            .iter()
            .find(|c| c.name.replace('-', "_") == target_first)
            .map_or_else(|| target_first.to_string(), |c| c.name.clone());
        let key = (d.from_crate.clone(), to_crate_orig.clone());
        if emitted_crate_deps.insert(key.clone()) {
            g.edges.push(Edge {
                from: module_node(&d.from_crate),
                to: module_node(&to_crate_orig),
                kind: EdgeKind::DependsOn,
                confidence: Confidence::Extracted,
                label: Some("use".to_string()),
            });
        }
    }

    // Stubs: synthetic nodes per hit, edge file → stub.
    for s in &scan.stubs {
        let sn = stub_node(&s.file_rel_path, s.line);
        g.nodes.push(Node {
            id: sn.clone(),
            kind: NodeKind::Symbol, // reuse symbol kind; tagged via sublabel
            label: format!("{} · L{}", s.kind, s.line),
            sublabel: Some(format!("stub · {}", s.snippet)),
            meta: serde_json::json!({
                "stub_kind": s.kind,
                "snippet": s.snippet,
                "file_rel_path": s.file_rel_path,
                "line": s.line,
            }),
        });
        g.edges.push(Edge {
            from: file_node(&s.file_rel_path),
            to: sn,
            kind: EdgeKind::Stubs,
            confidence: Confidence::Extracted,
            label: Some(s.kind.clone()),
        });
    }

    // Dead-code: edge file → symbol with confidence.
    for d in &scan.dead_code {
        let sym_id = format!("symbol:{}:{}", d.file_rel_path, d.line);
        // Add a lightweight symbol node if we didn't fold per-symbol earlier.
        if !g.nodes.iter().any(|n| n.id == sym_id) {
            g.nodes.push(Node {
                id: sym_id.clone(),
                kind: NodeKind::Symbol,
                label: d.name.clone(),
                sublabel: Some(format!("{} · {}:{}", d.kind, d.file_rel_path, d.line)),
                meta: serde_json::json!({
                    "kind": d.kind,
                    "is_pub": true,
                    "module_path": d.module_path,
                    "file_rel_path": d.file_rel_path,
                    "line": d.line,
                    "dead_code_note": d.note,
                }),
            });
        }
        g.edges.push(Edge {
            from: file_node(&d.file_rel_path),
            to: sym_id,
            kind: EdgeKind::DeadCode,
            confidence: Confidence::Inferred(d.confidence),
            label: Some(d.note.clone()),
        });
    }
}

fn count_facts_with_prefix(store: &FactStore, prefix: &str) -> usize {
    let result = store.query(&FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix.to_string()),
        top_k: 5000,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    latest.iter().filter(|f| f.entity.starts_with(prefix)).count()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use corecrux_memory::FactStore;

    /// The scan fact must be found however large it is, and however many other
    /// facts share its vocabulary.
    ///
    /// Regression: this loader used `query:` over `top_k: 16`. That is a
    /// substring filter, or — with a dense provider configured — no filter at
    /// all, since keyword matching is skipped and every fact is ranked by
    /// cosine similarity. Either way the result is truncated to `top_k`, so the
    /// one entity being sought can be ranked out by unrelated facts and the
    /// lookup returns None — reported to the operator as a workspace with zero
    /// LOC, zero stubs and zero dead code, indistinguishable from never having
    /// scanned.
    #[test]
    fn a_large_scan_fact_is_still_found_among_competing_facts() {
        let mut store = FactStore::new();

        let mut scan = crate::workspace_scan::WorkspaceScan::default();
        scan.scan_id = "ws_test".into();
        scan.stats.total_loc = 9151;
        scan.stats.crate_count = 8;
        // Pad the value so BM25 length normalisation has something to punish.
        scan.root_path = format!("/{}", "workspace_scan_latest_padding/".repeat(4000));
        let value = serde_json::to_string(&scan).expect("encode");
        assert!(value.len() > 100_000, "the point of the test is a large value");

        // Decoys that share the query's whole vocabulary and are far shorter,
        // so a text search ranks every one of them above the real fact.
        for i in 0..40 {
            store.store(corecrux_memory::fact_store::StoreFact {
                tenant_hash: "default".to_string(),
                entity: format!("__workspace_scan__::decoy_{i}"),
                key: "content".to_string(),
                value: "workspace scan latest".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: crate::workspace_scan::LATEST_SCAN_ENTITY.to_string(),
            key: crate::workspace_scan::SCAN_KEY.to_string(),
            value,
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

        let found = load_latest_workspace_blocking(&store).expect("the scan must be found");
        assert_eq!(found.scan_id, "ws_test");
        assert_eq!(found.stats.total_loc, 9151);
        assert_eq!(found.stats.crate_count, 8);
    }

    #[test]
    fn unknown_project_returns_empty_graph() {
        let store = FactStore::new();
        let g = build_for_project(&store, "ghost");
        assert_eq!(g.nodes.len(), 0);
        assert_eq!(g.edges.len(), 0);
    }

    #[test]
    fn project_with_planes_yields_connected_graph() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        crate::passports::seed_defaults_if_missing(dir.path(), &mut store, 1).expect("seed");
        // Seed a project + a plane with one member and one tenant.
        crate::projects::create_project(
            &mut store,
            crate::projects::CreateProjectInput {
                id: "p".into(),
                name: "P".into(),
                planning_target: Some("github://owner/repo".into()),
                default_passport_id: "personal-default".into(),
                working_tenants: vec![],
            },
            1_000,
        )
        .unwrap();
        crate::planes::create_plane(
            &mut store,
            crate::planes::CreatePlaneInput {
                project_id: "p".into(),
                id: "x".into(),
                name: "Plane X".into(),
                description: None,
                default_passport_id: None,
            },
            2_000,
        )
        .unwrap();
        crate::planes::add_member(&mut store, "p", "x", "agent-claude", "owner", 3_000).unwrap();
        crate::planes::add_tenant(&mut store, "p", "x", "work::p::x", None, 4_000).unwrap();

        let g = build_for_project(&store, "p");
        assert!(g
            .nodes
            .iter()
            .any(|n| matches!(n.kind, NodeKind::Project) && n.label == "P"));
        assert!(g
            .nodes
            .iter()
            .any(|n| matches!(n.kind, NodeKind::Plane) && n.label == "Plane X"));
        assert!(g
            .nodes
            .iter()
            .any(|n| matches!(n.kind, NodeKind::Passport) && n.label == "agent-claude"));
        assert!(g.nodes.iter().any(|n| matches!(n.kind, NodeKind::Tenant)));
        assert!(g.nodes.iter().any(|n| matches!(n.kind, NodeKind::GithubRepo)));
        // Plane belongs_to project.
        assert!(g
            .edges
            .iter()
            .any(|e| matches!(e.kind, EdgeKind::BelongsTo) && e.from.starts_with("plane:")));
        // Project planning_target -> github_repo.
        assert!(g.edges.iter().any(|e| matches!(e.kind, EdgeKind::PlanningTarget)));
        // Stats are populated.
        assert!(g.stats.node_count_by_kind.contains_key("project"));
        assert!(g.stats.edge_count_by_kind.contains_key("belongs_to"));
        // No orphans on a connected setup.
        assert!(g.stats.orphans.is_empty(), "orphans: {:?}", g.stats.orphans);
    }

    // ────────────────────────── Fixtures ──────────────────────────

    fn put_fact(store: &mut FactStore, entity: &str, key: &str, value: &str) {
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: corecrux_memory::fact_store::default_tenant_hash(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
    }

    fn put_scan(store: &mut FactStore, scan: &crate::workspace_scan::WorkspaceScan) {
        put_fact(
            store,
            crate::workspace_scan::LATEST_SCAN_ENTITY,
            crate::workspace_scan::SCAN_KEY,
            &serde_json::to_string(scan).expect("encode scan"),
        );
    }

    fn crate_info(name: &str, internal_deps: &[&str]) -> crate::workspace_scan::CrateInfo {
        crate::workspace_scan::CrateInfo {
            name: name.to_string(),
            rel_path: format!("crates/{name}"),
            internal_deps: internal_deps.iter().map(|d| (*d).to_string()).collect(),
            file_count: 1,
            total_loc: 10,
        }
    }

    fn file_info(crate_name: &str, rel_path: &str) -> crate::workspace_scan::FileInfo {
        crate::workspace_scan::FileInfo {
            rel_path: rel_path.to_string(),
            crate_name: crate_name.to_string(),
            module_path: format!("{}::lib", crate_name.replace('-', "_")),
            loc: 10,
            symbol_count: 1,
            stub_count: 0,
            doc_summary: None,
            doc_full: None,
            defines: Vec::new(),
            references: Vec::new(),
            referenced_by: Vec::new(),
            is_test_file: false,
        }
    }

    /// `create_project` refuses a default passport the store has never seen, so
    /// every fixture starts from the seeded defaults.
    fn store_with_passports() -> FactStore {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = FactStore::new();
        crate::passports::seed_defaults_if_missing(dir.path(), &mut store, 1).expect("seed passports");
        store
    }

    /// A project whose only member is the creating passport, plus a stored scan.
    fn project_with_scan(scan: &crate::workspace_scan::WorkspaceScan) -> FactStore {
        let mut store = store_with_passports();
        crate::projects::create_project(
            &mut store,
            crate::projects::CreateProjectInput {
                id: "p".into(),
                name: "P".into(),
                planning_target: None,
                default_passport_id: "personal-default".into(),
                working_tenants: vec![],
            },
            1_000,
        )
        .expect("create project");
        put_scan(&mut store, scan);
        store
    }

    fn workspace_opts(include_symbols: bool) -> GraphOptions {
        GraphOptions {
            include_workspace: true,
            include_symbols,
        }
    }

    // ────────────────────────── Schema vocabulary ──────────────────────────

    /// Both `snake()` maps are the graph's wire vocabulary: the renderer's kind
    /// filters and the stats histograms key off them. A renamed or duplicated
    /// arm silently drops a filter's contents rather than erroring.
    #[test]
    fn every_node_and_edge_kind_has_a_distinct_snake_name() {
        let nodes = [
            (NodeKind::Project, "project"),
            (NodeKind::Plane, "plane"),
            (NodeKind::Tenant, "tenant"),
            (NodeKind::Passport, "passport"),
            (NodeKind::Layer, "layer"),
            (NodeKind::GithubRepo, "github_repo"),
            (NodeKind::GithubCommit, "github_commit"),
            (NodeKind::Vision, "vision"),
            (NodeKind::Goal, "goal"),
            (NodeKind::Module, "module"),
            (NodeKind::File, "file"),
            (NodeKind::Symbol, "symbol"),
            (NodeKind::Claim, "claim"),
        ];
        for (kind, expected) in &nodes {
            assert_eq!(kind.snake(), *expected);
        }
        let node_names: std::collections::BTreeSet<&str> = nodes.iter().map(|(_, n)| *n).collect();
        assert_eq!(node_names.len(), nodes.len(), "node kind names must be distinct");

        let edges = [
            (EdgeKind::BelongsTo, "belongs_to"),
            (EdgeKind::Implements, "implements"),
            (EdgeKind::DependsOn, "depends_on"),
            (EdgeKind::References, "references"),
            (EdgeKind::Stubs, "stubs"),
            (EdgeKind::DeadCode, "dead_code"),
            (EdgeKind::Member, "member"),
            (EdgeKind::Tenant, "tenant"),
            (EdgeKind::Layer, "layer"),
            (EdgeKind::PlanningTarget, "planning_target"),
            (EdgeKind::ClaimAbout, "claim_about"),
        ];
        for (kind, expected) in &edges {
            assert_eq!(kind.snake(), *expected);
        }
        let edge_names: std::collections::BTreeSet<&str> = edges.iter().map(|(_, n)| *n).collect();
        assert_eq!(edge_names.len(), edges.len(), "edge kind names must be distinct");
    }

    /// The JSON shape is a consumed contract (console renderer + agent parsers),
    /// and the confidence tier is the thing a consumer must be able to branch on.
    #[test]
    fn the_serialised_confidence_tier_names_itself() {
        assert_eq!(serde_json::to_value(Confidence::Extracted).unwrap(), "extracted");
        assert_eq!(serde_json::to_value(Confidence::Ambiguous).unwrap(), "ambiguous");
        assert_eq!(
            serde_json::to_value(Confidence::Inferred(0.5)).unwrap(),
            serde_json::json!({"inferred": 0.5})
        );
        let node = Node {
            id: "n".into(),
            kind: NodeKind::GithubRepo,
            label: "l".into(),
            sublabel: None,
            meta: serde_json::json!({}),
        };
        let v = serde_json::to_value(&node).unwrap();
        assert_eq!(v["kind"], "github_repo");
        assert!(v.get("sublabel").is_none(), "a None sublabel is omitted, not null");
    }

    // ────────────────────────── Store reads ──────────────────────────

    #[test]
    fn query_prefix_returns_only_facts_under_the_prefix() {
        let mut store = FactStore::new();
        put_fact(&mut store, "__project_layer__::p::vision", "content", "v");
        put_fact(&mut store, "__project_layer__::p::goals", "content", "g");
        put_fact(&mut store, "__project_layer__::other::vision", "content", "x");
        let hits = query_prefix(&store, "__project_layer__::p::", 100);
        let mut entities: Vec<String> = hits.into_iter().map(|f| f.entity).collect();
        entities.sort();
        assert_eq!(
            entities,
            vec![
                "__project_layer__::p::goals".to_string(),
                "__project_layer__::p::vision".to_string()
            ]
        );
        assert!(query_prefix(&store, "__nothing__::", 100).is_empty());
    }

    // ── outcome dimension (ExecPlan crux-code-intel-silent-empty-outcomes, M2) ──

    /// The loader must say *which* case it was: found, or came back empty.
    /// Before the dimension existed, an always-`None` lookup was
    /// indistinguishable from a workspace nobody had ever scanned — the exact
    /// confusion that let the `20ba145` bug run on every storybook generation
    /// while `liveness` reported `executed: true`.
    ///
    /// This is also the guard for the design's one sharp edge: a site that
    /// loses its `fields(crux.outcome = tracing::field::Empty)` declaration
    /// records **nothing**, silently. Drop that clause from the loader and both
    /// observations below read `Unrecorded`, and this fails.
    #[test]
    fn the_workspace_scan_loader_records_whether_it_found_anything() {
        use crux_observe::span_layer::SpanOutcome;

        let ((), spans) = crate::span_capture_test_support::capture_spans(16, || {
            // Empty path: nothing stored at all.
            assert!(load_latest_workspace_blocking(&FactStore::new()).is_none());
            // Non-empty path: a scan is present and parses.
            let mut store = FactStore::new();
            let mut scan = crate::workspace_scan::WorkspaceScan::default();
            scan.scan_id = "ws_outcome".into();
            put_scan(&mut store, &scan);
            assert!(load_latest_workspace_blocking(&store).is_some());
        });

        assert_eq!(
            crate::span_capture_test_support::outcomes_of(&spans, "load_latest_workspace_blocking"),
            vec![SpanOutcome::Empty, SpanOutcome::NonEmpty],
            "the loader must declare an outcome on both paths, in order"
        );
    }

    /// A stored-but-unparseable scan is still an empty *result*: the caller gets
    /// `None` and renders a zero-LOC workspace either way. Recording it as
    /// non-empty because a fact happened to exist would put the dimension's
    /// blind spot exactly where the bug was.
    #[test]
    fn a_corrupt_scan_fact_records_empty_not_found() {
        use crux_observe::span_layer::SpanOutcome;

        let ((), spans) = crate::span_capture_test_support::capture_spans(8, || {
            let mut store = FactStore::new();
            put_fact(
                &mut store,
                crate::workspace_scan::LATEST_SCAN_ENTITY,
                crate::workspace_scan::SCAN_KEY,
                "{ not json",
            );
            assert!(load_latest_workspace_blocking(&store).is_none());
        });

        assert_eq!(
            crate::span_capture_test_support::outcomes_of(&spans, "load_latest_workspace_blocking"),
            vec![SpanOutcome::Empty],
            "a fact that will not parse is an empty result, not a found one"
        );
    }

    #[test]
    fn count_facts_with_prefix_counts_each_entity_once() {
        let mut store = FactStore::new();
        for i in 0..3 {
            put_fact(&mut store, &format!("github::o/r::commit/{i}"), "content", "c");
        }
        // A second version of the same entity must not double-count.
        put_fact(&mut store, "github::o/r::commit/0", "content", "c-updated");
        put_fact(&mut store, "github::other/r::commit/9", "content", "c");
        assert_eq!(count_facts_with_prefix(&store, "github::o/r::commit/"), 3);
        assert_eq!(count_facts_with_prefix(&store, "github::absent/"), 0);
    }

    /// Pins current behaviour: a scan fact whose JSON no longer decodes is
    /// reported as "no scan", identical to never having scanned. The caller in
    /// `build_for_project_with_opts` then skips the workspace fold silently.
    #[test]
    fn a_corrupt_scan_fact_reads_as_no_scan_at_all() {
        let mut store = FactStore::new();
        put_fact(
            &mut store,
            crate::workspace_scan::LATEST_SCAN_ENTITY,
            crate::workspace_scan::SCAN_KEY,
            "{not json at all",
        );
        assert!(load_latest_workspace_blocking(&store).is_none());
        assert!(load_latest_workspace_blocking_pub(&store).is_none());

        // Right entity, wrong key: also None.
        let mut store = FactStore::new();
        put_fact(
            &mut store,
            crate::workspace_scan::LATEST_SCAN_ENTITY,
            "some-other-key",
            "{}",
        );
        assert!(load_latest_workspace_blocking(&store).is_none());
    }

    // ────────────────────────── Layers + planning target ──────────────────────────

    #[test]
    fn project_and_plane_layers_become_layer_nodes_and_skip_non_content_facts() {
        let mut store = store_with_passports();
        crate::projects::create_project(
            &mut store,
            crate::projects::CreateProjectInput {
                id: "p".into(),
                name: "P".into(),
                planning_target: None,
                default_passport_id: "personal-default".into(),
                working_tenants: vec![],
            },
            1_000,
        )
        .unwrap();
        crate::planes::create_plane(
            &mut store,
            crate::planes::CreatePlaneInput {
                project_id: "p".into(),
                id: "x".into(),
                name: "X".into(),
                description: None,
                default_passport_id: None,
            },
            2_000,
        )
        .unwrap();
        put_fact(&mut store, "__project_layer__::p::vision", "content", "project vision");
        put_fact(&mut store, "__project_layer__::p::empty", "content", "");
        put_fact(&mut store, "__project_layer__::p::meta", "not_content", "ignored");
        put_fact(&mut store, "__plane_layer__::p::x::goals", "content", "plane goals");
        put_fact(&mut store, "__plane_layer__::p::x::blank", "content", "");

        let g = build_for_project(&store, "p");
        let layer_labels: std::collections::BTreeSet<&str> = g
            .nodes
            .iter()
            .filter(|n| matches!(n.kind, NodeKind::Layer))
            .map(|n| n.label.as_str())
            .collect();
        assert_eq!(
            layer_labels,
            ["goals", "vision"]
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
            "empty values and non-content keys must not become nodes"
        );
        assert!(g.nodes.iter().any(|n| n.id == "layer:p:vision"));
        assert!(g.nodes.iter().any(|n| n.id == "plane_layer:p:x:goals"));
        assert_eq!(g.stats.edge_count_by_kind.get("layer"), Some(&2));
        // Layer nodes carry byte size + version for the side panel.
        let vision = g.nodes.iter().find(|n| n.id == "layer:p:vision").unwrap();
        assert_eq!(vision.meta["bytes"], "project vision".len());
    }

    #[test]
    fn a_non_github_planning_target_adds_no_repo_node() {
        let mut store = store_with_passports();
        crate::projects::create_project(
            &mut store,
            crate::projects::CreateProjectInput {
                id: "p".into(),
                name: "P".into(),
                planning_target: Some("tenant://p-planning".into()),
                default_passport_id: "personal-default".into(),
                working_tenants: vec![],
            },
            1_000,
        )
        .unwrap();
        let g = build_for_project(&store, "p");
        assert!(!g.nodes.iter().any(|n| matches!(n.kind, NodeKind::GithubRepo)));
        assert!(!g.edges.iter().any(|e| matches!(e.kind, EdgeKind::PlanningTarget)));
    }

    /// A github planning target only grows a commits node once commits are
    /// actually indexed — a zero count must not render as an empty node.
    #[test]
    fn indexed_commits_become_a_counted_node_only_when_there_are_any() {
        let mut store = store_with_passports();
        crate::projects::create_project(
            &mut store,
            crate::projects::CreateProjectInput {
                id: "p".into(),
                name: "P".into(),
                planning_target: Some("github://owner/repo".into()),
                default_passport_id: "personal-default".into(),
                working_tenants: vec![],
            },
            1_000,
        )
        .unwrap();

        let g = build_for_project(&store, "p");
        assert!(g.nodes.iter().any(|n| n.id == "github_repo:owner/repo"));
        assert!(!g.nodes.iter().any(|n| matches!(n.kind, NodeKind::GithubCommit)));

        for i in 0..4 {
            put_fact(
                &mut store,
                &format!("github::owner/repo::commit/{i}"),
                "content",
                "commit",
            );
        }
        let g = build_for_project(&store, "p");
        let commits = g
            .nodes
            .iter()
            .find(|n| matches!(n.kind, NodeKind::GithubCommit))
            .expect("commits node");
        assert_eq!(commits.label, "4 commits indexed");
        assert_eq!(commits.meta["count"], 4);
        assert!(g
            .edges
            .iter()
            .any(|e| matches!(e.kind, EdgeKind::References) && e.from == "github_repo:owner/repo"));
    }

    /// A passport on both the project and a plane must be one node with two
    /// membership edges — duplicating it would double-count the graph's people.
    #[test]
    fn a_passport_shared_by_project_and_plane_is_one_node() {
        let mut store = store_with_passports();
        crate::projects::create_project(
            &mut store,
            crate::projects::CreateProjectInput {
                id: "p".into(),
                name: "P".into(),
                planning_target: None,
                default_passport_id: "personal-default".into(),
                working_tenants: vec![],
            },
            1_000,
        )
        .unwrap();
        crate::projects::add_member(&mut store, "p", "work-default", "owner", 1_100).unwrap();
        crate::projects::add_tenant(&mut store, "p", "shared-tenant", None, 1_150).unwrap();
        crate::planes::create_plane(
            &mut store,
            crate::planes::CreatePlaneInput {
                project_id: "p".into(),
                id: "x".into(),
                name: "X".into(),
                description: None,
                default_passport_id: None,
            },
            2_000,
        )
        .unwrap();
        crate::planes::add_member(&mut store, "p", "x", "work-default", "contributor", 2_100).unwrap();
        crate::planes::add_tenant(&mut store, "p", "x", "shared-tenant", None, 2_200).unwrap();

        let g = build_for_project(&store, "p");
        assert_eq!(
            g.nodes.iter().filter(|n| n.id == "passport:work-default").count(),
            1,
            "one node for a passport that appears twice"
        );
        assert_eq!(
            g.edges
                .iter()
                .filter(|e| e.from == "passport:work-default" && matches!(e.kind, EdgeKind::Member))
                .count(),
            2,
            "but one membership edge per attachment"
        );
        // `create_project` also enrols the creating passport, so two in total.
        assert_eq!(g.stats.node_count_by_kind.get("passport"), Some(&2));
        assert_eq!(g.stats.edge_count_by_kind.get("member"), Some(&3));
        assert_eq!(g.nodes.iter().filter(|n| n.id == "tenant:shared-tenant").count(), 1);
        assert_eq!(g.stats.edge_count_by_kind.get("tenant"), Some(&2));
    }

    // ────────────────────────── Workspace fold ──────────────────────────

    /// The workspace fold is opt-in on both axes. Defaulting either on would
    /// add hundreds of nodes to every graph read.
    #[test]
    fn the_workspace_fold_is_opt_in() {
        let mut scan = crate::workspace_scan::WorkspaceScan::default();
        scan.crates = vec![crate_info("alpha", &[])];
        let store = project_with_scan(&scan);

        let default_graph = build_for_project(&store, "p");
        assert!(!default_graph.nodes.iter().any(|n| matches!(n.kind, NodeKind::Module)));
        assert!(!GraphOptions::default().include_workspace);
        assert!(!GraphOptions::default().include_symbols);

        let folded = build_for_project_with_opts(&store, "p", &workspace_opts(false));
        assert!(folded.nodes.iter().any(|n| n.id == "module:alpha"));
    }

    /// Pins current behaviour: asking for the workspace when no scan fact exists
    /// yields a graph indistinguishable from `include_workspace: false`. The
    /// caller gets no signal that the fold was requested and did nothing.
    #[test]
    fn requesting_the_workspace_with_no_scan_present_is_silently_a_no_op() {
        let mut store = store_with_passports();
        crate::projects::create_project(
            &mut store,
            crate::projects::CreateProjectInput {
                id: "p".into(),
                name: "P".into(),
                planning_target: None,
                default_passport_id: "personal-default".into(),
                working_tenants: vec![],
            },
            1_000,
        )
        .unwrap();
        let with = build_for_project_with_opts(&store, "p", &workspace_opts(true));
        let without = build_for_project(&store, "p");
        assert_eq!(with.nodes.len(), without.nodes.len());
        assert_eq!(with.edges.len(), without.edges.len());
    }

    /// The whole fold in one pass: crate modules, file belongs-to edges, both
    /// kinds of depends-on edge, stub nodes and the lazily-created dead-code
    /// symbol node with its inferred confidence.
    #[test]
    fn the_workspace_fold_adds_modules_files_deps_stubs_and_dead_code() {
        let mut scan = crate::workspace_scan::WorkspaceScan::default();
        scan.crates = vec![
            // `ghost-crate` is not in this scan — a Cargo dep on it must not
            // create a dangling edge to a node that does not exist.
            crate_info("corecrux-retrieval", &["corecrux-index", "ghost-crate"]),
            crate_info("corecrux-index", &[]),
        ];
        scan.files = vec![
            file_info("corecrux-retrieval", "crates/corecrux-retrieval/src/lib.rs"),
            file_info("corecrux-index", "crates/corecrux-index/src/lib.rs"),
        ];
        scan.deps = vec![
            // Hyphen/underscore normalisation: `corecrux_index` resolves back to
            // the hyphenated crate name.
            crate::workspace_scan::DepEdge {
                from_crate: "corecrux-retrieval".into(),
                from_file: "crates/corecrux-retrieval/src/lib.rs".into(),
                to_module: "corecrux_index::api".into(),
                raw: "use corecrux_index::api".into(),
            },
            // Duplicate of the above — must be emitted once.
            crate::workspace_scan::DepEdge {
                from_crate: "corecrux-retrieval".into(),
                from_file: "crates/corecrux-retrieval/src/other.rs".into(),
                to_module: "corecrux_index::other".into(),
                raw: "use corecrux_index::other".into(),
            },
            // Self-dependency — skipped.
            crate::workspace_scan::DepEdge {
                from_crate: "corecrux-index".into(),
                from_file: "crates/corecrux-index/src/lib.rs".into(),
                to_module: "corecrux_index::inner".into(),
                raw: "use crate::inner".into(),
            },
            // Target is not a workspace crate — skipped.
            crate::workspace_scan::DepEdge {
                from_crate: "corecrux-index".into(),
                from_file: "crates/corecrux-index/src/lib.rs".into(),
                to_module: "serde::Deserialize".into(),
                raw: "use serde::Deserialize".into(),
            },
        ];
        scan.stubs = vec![crate::workspace_scan::StubHit {
            crate_name: "corecrux-retrieval".into(),
            file_rel_path: "crates/corecrux-retrieval/src/lib.rs".into(),
            line: 42,
            kind: "todo".into(),
            snippet: "todo!()".into(),
        }];
        scan.dead_code = vec![crate::workspace_scan::DeadSymbol {
            crate_name: "corecrux-index".into(),
            module_path: "corecrux_index::lib".into(),
            file_rel_path: "crates/corecrux-index/src/lib.rs".into(),
            line: 7,
            kind: "fn".into(),
            name: "unused".into(),
            confidence: 0.42,
            note: "no references".into(),
        }];

        let store = project_with_scan(&scan);
        let g = build_for_project_with_opts(&store, "p", &workspace_opts(false));

        // Modules + files.
        assert_eq!(g.stats.node_count_by_kind.get("module"), Some(&2));
        assert_eq!(g.stats.node_count_by_kind.get("file"), Some(&2));
        let lib = g
            .nodes
            .iter()
            .find(|n| n.id == "file:crates/corecrux-retrieval/src/lib.rs")
            .expect("file node");
        assert_eq!(lib.label, "lib.rs", "the file label is the basename");

        // depends_on: one Cargo edge (ghost-crate dropped) + one deduplicated use edge.
        let cargo_edges: Vec<&Edge> = g
            .edges
            .iter()
            .filter(|e| matches!(e.kind, EdgeKind::DependsOn) && e.label.as_deref() == Some("Cargo"))
            .collect();
        assert_eq!(cargo_edges.len(), 1, "the unknown Cargo dep is dropped");
        assert_eq!(cargo_edges[0].to, "module:corecrux-index");
        let use_edges: Vec<&Edge> = g
            .edges
            .iter()
            .filter(|e| matches!(e.kind, EdgeKind::DependsOn) && e.label.as_deref() == Some("use"))
            .collect();
        assert_eq!(
            use_edges.len(),
            1,
            "self and external deps skipped, duplicates collapsed"
        );
        assert_eq!(use_edges[0].from, "module:corecrux-retrieval");
        assert_eq!(use_edges[0].to, "module:corecrux-index");

        // Stubs.
        assert!(g
            .nodes
            .iter()
            .any(|n| n.id == "stub:crates/corecrux-retrieval/src/lib.rs:42"));
        assert_eq!(g.stats.edge_count_by_kind.get("stubs"), Some(&1));

        // Dead code: a symbol node is created on demand and the edge is inferred.
        let sym = g
            .nodes
            .iter()
            .find(|n| n.id == "symbol:crates/corecrux-index/src/lib.rs:7")
            .expect("dead-code symbol node");
        assert_eq!(sym.label, "unused");
        assert_eq!(sym.meta["dead_code_note"], "no references");
        let dead_edge = g
            .edges
            .iter()
            .find(|e| matches!(e.kind, EdgeKind::DeadCode))
            .expect("dead_code edge");
        assert!(matches!(dead_edge.confidence, Confidence::Inferred(c) if (c - 0.42).abs() < 1e-6));
        assert_eq!(g.stats.edge_count_by_confidence.get("inferred"), Some(&1));
        assert!(g.stats.edge_count_by_confidence.get("extracted").is_some());
    }

    /// With `include_symbols` the per-symbol nodes land first, and the dead-code
    /// pass must reuse the existing node rather than adding a duplicate id.
    #[test]
    fn include_symbols_adds_symbol_nodes_and_dead_code_reuses_them() {
        let mut scan = crate::workspace_scan::WorkspaceScan::default();
        scan.crates = vec![crate_info("alpha", &[])];
        scan.files = vec![file_info("alpha", "crates/alpha/src/lib.rs")];
        scan.symbols = vec![crate::workspace_scan::SymbolInfo {
            crate_name: "alpha".into(),
            module_path: "alpha::lib".into(),
            file_rel_path: "crates/alpha/src/lib.rs".into(),
            line: 7,
            kind: "fn".into(),
            name: "unused".into(),
            is_pub: true,
        }];
        scan.dead_code = vec![crate::workspace_scan::DeadSymbol {
            crate_name: "alpha".into(),
            module_path: "alpha::lib".into(),
            file_rel_path: "crates/alpha/src/lib.rs".into(),
            line: 7,
            kind: "fn".into(),
            name: "unused".into(),
            confidence: 0.5,
            note: "no references".into(),
        }];
        let store = project_with_scan(&scan);

        let g = build_for_project_with_opts(&store, "p", &workspace_opts(true));
        assert_eq!(
            g.nodes
                .iter()
                .filter(|n| n.id == "symbol:crates/alpha/src/lib.rs:7")
                .count(),
            1,
            "the dead-code pass must not duplicate an existing symbol node"
        );
        // The symbol belongs to its file, and the dead-code edge points at it.
        assert!(g.edges.iter().any(|e| e.from == "symbol:crates/alpha/src/lib.rs:7"
            && e.to == "file:crates/alpha/src/lib.rs"
            && matches!(e.kind, EdgeKind::BelongsTo)));
        assert_eq!(g.stats.edge_count_by_kind.get("dead_code"), Some(&1));
    }

    /// A crate with no files, no deps and no findings has no edges at all, and
    /// must be reported as an orphan rather than quietly padding the node count.
    #[test]
    fn a_crate_with_no_edges_is_reported_as_an_orphan() {
        let mut scan = crate::workspace_scan::WorkspaceScan::default();
        scan.crates = vec![crate_info("lonely", &[])];
        let store = project_with_scan(&scan);
        let g = build_for_project_with_opts(&store, "p", &workspace_opts(false));
        assert_eq!(g.stats.orphans, vec!["module:lonely".to_string()]);
    }

    /// Duplicate crate entries in one scan must fold to a single module node —
    /// the id set is what the renderer keys on.
    #[test]
    fn duplicate_crate_entries_fold_to_one_module_node() {
        let mut scan = crate::workspace_scan::WorkspaceScan::default();
        scan.crates = vec![crate_info("alpha", &[]), crate_info("alpha", &[])];
        let store = project_with_scan(&scan);
        let g = build_for_project_with_opts(&store, "p", &workspace_opts(false));
        assert_eq!(g.nodes.iter().filter(|n| n.id == "module:alpha").count(), 1);
    }

    /// `build_for_project` stamps a generation time; an unknown project short
    /// circuits before any store read but must still carry its own id.
    #[test]
    fn an_unknown_project_still_reports_its_id_and_a_timestamp() {
        let store = FactStore::new();
        let g = build_for_project(&store, "ghost");
        assert_eq!(g.project_id, "ghost");
        assert!(g.generated_at_unix_ms > 0);
        assert!(g.stats.node_count_by_kind.is_empty());
        assert!(g.stats.orphans.is_empty());
    }
}
