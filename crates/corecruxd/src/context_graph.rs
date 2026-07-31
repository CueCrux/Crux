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
    let fact = latest
        .into_iter()
        .find(|f| f.entity == crate::workspace_scan::LATEST_SCAN_ENTITY && f.key == crate::workspace_scan::SCAN_KEY)?;
    let mut scan = serde_json::from_str::<crate::workspace_scan::WorkspaceScan>(&fact.value).ok()?;
    crate::workspace_scan::redact_self_workspace_paths(&mut scan);
    Some(scan)
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
}
