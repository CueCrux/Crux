// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Storybook readout — Phase 3 of the context graph.
//!
//! Generates a markdown narrative ("a coherent description of where the
//! project is right now") by walking project → planes → layers → workspace
//! scan + a lightweight vision↔module mapping (Phase 2B-lite, keyword
//! overlap). Saved as a private fact `__storybook__::{project_id}::{ts}` so
//! readouts diff over time and the operator can see drift.
//!
//! Output is a single markdown document. Both human and agent friendly:
//! - Operator: read it like a project brief.
//! - Agent: parse the section headers + tables to update its mental model.

#![allow(clippy::format_push_string)] // markdown-narrative builder — heavy push_str(&format!(...)) usage by design
#![allow(clippy::unwrap_used)] // narrative-builder code on data we just constructed; .unwrap() panic is impossible by construction
#![allow(clippy::unnecessary_get_then_check)] // minor stylistic, builder-local

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorybookDocument {
    pub project_id: String,
    pub generated_at_unix_ms: u64,
    pub generated_by_passport: String,
    pub markdown: String,
    pub sections: BTreeMap<String, String>, // section_id → md text (for diff)
    pub stats: StorybookStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorybookStats {
    pub plane_count: usize,
    pub planes_with_vision: usize,
    pub planes_with_mapped_modules: usize,
    pub orphan_planes: Vec<String>, // plane ids with no mapped modules
    pub workspace_loc: usize,
    pub stub_count: usize,
    pub dead_code_count: usize,
    pub bytes: usize,
}

pub struct GenerateInput<'a> {
    pub project_id: &'a str,
    pub by_passport: &'a str,
    pub now_unix_ms: u64,
    /// Runtime spans for the dead-code tier. Empty is the normal case —
    /// `CORECRUXD_TRACE_CAPTURE` is default-off — and the readout then says
    /// exactly what it said before the runtime tier existed.
    pub spans: &'a [crate::trace_store::StoredSpan],
}

/// Build the storybook from current store state. Synchronous; no LLM calls.
pub fn generate(store: &corecrux_memory::FactStore, input: GenerateInput<'_>) -> Option<StorybookDocument> {
    let project = crate::projects::get_project_detail(store, input.project_id)?;
    let planes = crate::planes::list_planes(store, input.project_id);
    let project_layers = read_project_layers(store, input.project_id);
    let workspace_scan = crate::context_graph::load_latest_workspace_blocking_pub(store);

    let mut sections: BTreeMap<String, String> = BTreeMap::new();
    let mut md = String::new();

    // ── Front matter ──────────────────────────────────────────────────
    let now_iso = unix_ms_to_iso(input.now_unix_ms);
    let header = format!(
        "# Storybook · {} · {}\n\n\
         > **Generated** {} by `{}`\n\
         > **Project** `{}`\n\
         > **Planning target** `{}`\n\
         > **Members** {}\n\
         > **Tenants** {}\n\
         > **Planes** {}\n\
         > **Workspace scan** {}\n\n",
        input.project_id,
        truncate_iso(&now_iso),
        now_iso,
        input.by_passport,
        project.record.id,
        project.record.planning_target.as_deref().unwrap_or("(none)"),
        if project.members.is_empty() {
            "(none)".into()
        } else {
            project
                .members
                .iter()
                .map(|m| format!("`{}` ({})", m.passport_id, m.role))
                .collect::<Vec<_>>()
                .join(", ")
        },
        if project.tenants.is_empty() {
            "(none)".into()
        } else {
            project
                .tenants
                .iter()
                .map(|t| format!("`{}`", t.tenant_id))
                .collect::<Vec<_>>()
                .join(", ")
        },
        planes.len(),
        match &workspace_scan {
            Some(ws) => format!(
                "{} crates · {} files · {} loc · {} pub symbols · {} stubs · {} dead-code candidates · scan {} ({})",
                ws.stats.crate_count,
                ws.stats.file_count,
                ws.stats.total_loc,
                ws.stats.symbol_count,
                ws.stats.stub_count,
                ws.stats.dead_code_count,
                ws.scan_id,
                truncate_iso(&unix_ms_to_iso(ws.started_at_unix_ms)),
            ),
            None => "(no scan run yet — POST /v1/workspace/scan to populate)".into(),
        },
    );
    md.push_str(&header);
    sections.insert("00_front".into(), header);

    // ── What this project is (Vision) ─────────────────────────────────
    let mut vision_section = String::from("## What this project is\n\n");
    if let Some(v) = project_layers.get("vision") {
        vision_section.push_str(v);
        vision_section.push_str("\n\n");
    } else {
        vision_section.push_str("*No vision layer set. Add one with `PUT /v1/projects/{id}/layers/vision` so the storybook has something to anchor to.*\n\n");
    }
    md.push_str(&vision_section);
    sections.insert("10_vision".into(), vision_section);

    // ── What it's trying to achieve (Goals) ──────────────────────────
    let mut goals_section = String::from("## What it's trying to achieve\n\n");
    if let Some(g) = project_layers.get("goals") {
        goals_section.push_str(g);
        goals_section.push_str("\n\n");
    } else {
        goals_section.push_str("*No goals layer set.*\n\n");
    }
    md.push_str(&goals_section);
    sections.insert("20_goals".into(), goals_section);

    // ── Planes ───────────────────────────────────────────────────────
    let vision_keywords = match project_layers.get("vision") {
        Some(v) => extract_keywords(v),
        None => Default::default(),
    };

    let mut planes_section = String::from("## Planes\n\n");
    if planes.is_empty() {
        planes_section.push_str("*No planes provisioned. Add planes via `POST /v1/projects/{id}/planes` to break the project into sub-units.*\n\n");
    }
    let mut planes_with_vision = 0usize;
    let mut planes_with_modules = 0usize;
    let mut orphan_planes: Vec<String> = Vec::new();
    let mut plane_module_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for plane in &planes {
        let detail = crate::planes::get_plane_detail(store, input.project_id, &plane.id);
        let plane_layers = read_plane_layers(store, input.project_id, &plane.id);
        let plane_vision_text = plane_layers.get("vision").cloned();
        if plane_vision_text.is_some() {
            planes_with_vision += 1;
        }
        // Keyword pool for module matching: plane id + name + description + plane vision text + project vision keywords.
        let mut pool = String::new();
        pool.push_str(&plane.id);
        pool.push(' ');
        pool.push_str(&plane.name);
        pool.push(' ');
        if let Some(d) = &plane.description {
            pool.push_str(d);
            pool.push(' ');
        }
        if let Some(v) = &plane_vision_text {
            pool.push_str(v);
        }
        let plane_kws = extract_keywords(&pool);

        let (candidate_modules, module_source) = match &workspace_scan {
            Some(ws) => resolve_plane_modules(&plane_layers, &plane_kws, ws),
            None => (Vec::new(), ModuleSource::KeywordOverlap),
        };
        if !candidate_modules.is_empty() {
            planes_with_modules += 1;
            plane_module_map.insert(plane.id.clone(), candidate_modules.clone());
        } else {
            orphan_planes.push(plane.id.clone());
        }

        // Stubs and dead-code in matching modules.
        let mut stubs_in_match = 0usize;
        let mut dead_in_match = 0usize;
        if let Some(ws) = &workspace_scan {
            let crate_set: HashSet<&str> = candidate_modules.iter().map(|s| s.as_str()).collect();
            stubs_in_match = ws
                .stubs
                .iter()
                .filter(|s| crate_set.contains(s.crate_name.as_str()))
                .count();
            dead_in_match = ws
                .dead_code
                .iter()
                .filter(|d| crate_set.contains(d.crate_name.as_str()))
                .count();
        }

        let members_str = match &detail {
            Some(d) if !d.members.is_empty() => d
                .members
                .iter()
                .map(|m| format!("`{}` ({})", m.passport_id, m.role))
                .collect::<Vec<_>>()
                .join(", "),
            _ => "(none)".into(),
        };
        let tenants_str = match &detail {
            Some(d) if !d.tenants.is_empty() => d
                .tenants
                .iter()
                .map(|t| format!("`{}`", t.tenant_id))
                .collect::<Vec<_>>()
                .join(", "),
            _ => "(none)".into(),
        };

        // Vision overlap with project vision (signal of how aligned the plane is to the parent goal).
        let overlap = jaccard(&plane_kws, &vision_keywords);
        let alignment_marker = if overlap >= 0.10 {
            format!(" · vision-aligned ({:.2})", overlap)
        } else {
            String::new()
        };

        let mut sec = format!(
            "### {} `{}`{}\n\n\
             - **Description**: {}\n\
             - **Members**: {}\n\
             - **Tenants**: {}\n",
            plane.name,
            plane.id,
            alignment_marker,
            plane.description.as_deref().unwrap_or("*(none)*"),
            members_str,
            tenants_str,
        );
        if let Some(v) = &plane_vision_text {
            sec.push_str("- **Plane vision** (truncated):\n  > ");
            sec.push_str(&truncate_for_quote(v, 280));
            sec.push('\n');
        } else {
            sec.push_str(
                "- **Plane vision**: *(none — set with `PUT /v1/projects/{id}/planes/{plane}/layers/vision`)*\n",
            );
        }
        if !candidate_modules.is_empty() {
            sec.push_str(&format!(
                "- **{}**: {}\n",
                if module_source == ModuleSource::Declared {
                    "Declared crates (plane `modules` layer)"
                } else {
                    "Inferred matching crates (keyword overlap, confidence ~0.5)"
                },
                candidate_modules
                    .iter()
                    .map(|m| format!("`{m}`"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            sec.push_str(&format!(
                "- **Stubs in matching crates**: {} · **Dead-code candidates**: {}\n",
                stubs_in_match, dead_in_match
            ));
        } else if workspace_scan.is_some() {
            sec.push_str("- **Inferred matching crates**: *none — this plane has no source mapping yet (gap)*\n");
        }
        sec.push('\n');
        md.push_str(&sec);
        sections.insert(format!("30_plane_{}", plane.id), sec);
    }
    sections.insert("30_planes_intro".into(), planes_section.clone());
    md.insert_str(md.find("### ").unwrap_or(md.len()), &planes_section);

    // ── Coverage matrix ──────────────────────────────────────────────
    if !planes.is_empty() && workspace_scan.is_some() {
        let mut tab = String::from("## Coverage matrix\n\n");
        tab.push_str("| Plane | Vision | Goals | Mapped crates | Stubs | Dead code | Gap |\n");
        tab.push_str("|-------|--------|-------|---------------|-------|-----------|-----|\n");
        let ws = workspace_scan.as_ref().unwrap();
        for plane in &planes {
            let plane_layers = read_plane_layers(store, input.project_id, &plane.id);
            let v = if plane_layers.contains_key("vision") {
                "✓"
            } else {
                "—"
            };
            let g = if plane_layers.contains_key("goals") {
                "✓"
            } else {
                "—"
            };
            let mods = plane_module_map.get(&plane.id).cloned().unwrap_or_default();
            let crate_set: HashSet<&str> = mods.iter().map(|s| s.as_str()).collect();
            let stubs = ws
                .stubs
                .iter()
                .filter(|s| crate_set.contains(s.crate_name.as_str()))
                .count();
            let dead = ws
                .dead_code
                .iter()
                .filter(|d| crate_set.contains(d.crate_name.as_str()))
                .count();
            let gap = if mods.is_empty() {
                "**no crates mapped**".to_string()
            } else if v == "—" && g == "—" {
                "no vision/goals set".to_string()
            } else {
                String::new()
            };
            tab.push_str(&format!(
                "| `{}` | {} | {} | {} | {} | {} | {} |\n",
                plane.id,
                v,
                g,
                if mods.is_empty() {
                    "—".into()
                } else {
                    mods.iter().map(|m| format!("`{}`", m)).collect::<Vec<_>>().join(", ")
                },
                stubs,
                dead,
                gap,
            ));
        }
        tab.push('\n');
        md.push_str(&tab);
        sections.insert("40_coverage".into(), tab);
    }

    // ── Workspace health ─────────────────────────────────────────────
    if let Some(ws) = &workspace_scan {
        let mut hs = String::from("## Workspace health\n\n");
        hs.push_str(&format!(
            "**{}** crates · **{}** files · **{}** LOC · **{}** pub symbols · **{}** internal use deps\n\n",
            ws.stats.crate_count, ws.stats.file_count, ws.stats.total_loc, ws.stats.symbol_count, ws.stats.dep_count,
        ));

        // Stubs grouped by crate.
        if !ws.stubs.is_empty() {
            let mut by_crate: BTreeMap<String, Vec<&crate::workspace_scan::StubHit>> = BTreeMap::new();
            for s in &ws.stubs {
                by_crate.entry(s.crate_name.clone()).or_default().push(s);
            }
            hs.push_str(&format!("### Stubs ({})\n\n", ws.stats.stub_count));
            for (cname, items) in by_crate.iter().take(10) {
                hs.push_str(&format!("- **`{}`** ({}):\n", cname, items.len()));
                for s in items.iter().take(5) {
                    hs.push_str(&format!(
                        "  - `{}:{}` [{}] — `{}`\n",
                        s.file_rel_path,
                        s.line,
                        s.kind,
                        truncate_for_quote(&s.snippet, 80)
                    ));
                }
            }
            hs.push('\n');
        }

        // Dead-code grouped by crate, top 10 crates.
        if !ws.dead_code.is_empty() {
            let mut by_crate: BTreeMap<String, Vec<&crate::workspace_scan::DeadSymbol>> = BTreeMap::new();
            for d in &ws.dead_code {
                by_crate.entry(d.crate_name.clone()).or_default().push(d);
            }
            let mut crates: Vec<_> = by_crate.iter().collect();
            crates.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
            // The heading grades the count across tiers when a runtime window
            // exists. Previously it carried a permanent hedge — "Regex-based;
            // may miss macro / dynamic-dispatch usages" — which is true of the
            // static tier alone and stops being the whole story once runtime
            // evidence is available. A caveat that never changes is one a
            // reader learns to skip.
            let verdicts = crate::code_intel::dead_code_verdicts(ws, input.spans);
            let actionable = verdicts.iter().filter(|v| v.actionable).count();
            let false_positives = verdicts
                .iter()
                .filter(|v| v.verdict == "extractor_false_positive__static_dead_but_executed")
                .count();
            if input.spans.is_empty() {
                hs.push_str(&format!(
                    "### Dead-code candidates ({}, static tier only)\n\n*One static tier: regex reachability, which does not read macro bodies or resolve method calls. No runtime window to corroborate it — none of these is safe to act on alone. Enable `CORECRUXD_TRACE_CAPTURE` to grade them.*\n\n",
                    ws.stats.dead_code_count
                ));
            } else {
                let w = crate::code_intel::Window::of(input.spans);
                hs.push_str(&format!(
                    "### Dead-code candidates ({} static · **{} actionable** · {} refuted)\n\n*Graded over a window of {} spans across {} traces. **Actionable** means two independent tiers agree AND the symbol's own file executed — a runtime negative from a file that never ran is not evidence. **Refuted** means the static tier flagged it and it was observed running.*\n\n",
                    ws.stats.dead_code_count, actionable, false_positives,
                    w.spans_examined, w.traces_examined
                ));
            }
            for (cname, items) in crates.iter().take(10) {
                hs.push_str(&format!("- **`{}`** ({}):\n", cname, items.len()));
                for d in items.iter().take(6) {
                    hs.push_str(&format!(
                        "  - `{}` `{}` at `{}:{}`\n",
                        d.kind, d.name, d.file_rel_path, d.line
                    ));
                }
                if items.len() > 6 {
                    hs.push_str(&format!("  - …and {} more\n", items.len() - 6));
                }
            }
            hs.push('\n');
        }

        md.push_str(&hs);
        sections.insert("50_workspace_health".into(), hs);
    }

    // ── Gaps & alerts (the bit a human / agent skims first) ──────────
    let mut alerts = String::from("## Gaps & alerts\n\n");
    let mut alert_count = 0;
    if project_layers.get("vision").is_none() {
        alerts.push_str("- ❗ Project has no **vision layer** set.\n");
        alert_count += 1;
    }
    if project_layers.get("goals").is_none() {
        alerts.push_str("- ❗ Project has no **goals layer** set.\n");
        alert_count += 1;
    }
    if !orphan_planes.is_empty() && workspace_scan.is_some() {
        alerts.push_str(&format!(
            "- ⚠ **{} planes have no mapped crates** (no keyword overlap with workspace modules): {}\n",
            orphan_planes.len(),
            orphan_planes
                .iter()
                .map(|p| format!("`{p}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        alert_count += orphan_planes.len();
    }
    let planes_without_vision = planes
        .iter()
        .filter(|p| {
            let pl = read_plane_layers(store, input.project_id, &p.id);
            !pl.contains_key("vision")
        })
        .count();
    if planes_without_vision > 0 {
        alerts.push_str(&format!(
            "- ⚠ **{} planes have no vision layer** — the storybook can't describe them in their own terms.\n",
            planes_without_vision
        ));
        alert_count += planes_without_vision;
    }
    if let Some(ws) = &workspace_scan {
        if ws.stats.dead_code_count > 50 {
            alerts.push_str(&format!(
                "- ⚠ **{} dead-code candidates** across the workspace (heuristic). Review for cleanup or document why they exist.\n",
                ws.stats.dead_code_count
            ));
            alert_count += 1;
        }
    } else {
        alerts.push_str("- ⚠ No workspace scan has been run. POST `/v1/workspace/scan` to populate the structural side of the readout.\n");
        alert_count += 1;
    }
    if alert_count == 0 {
        alerts.push_str("- ✓ No structural gaps detected.\n");
    }
    alerts.push('\n');
    md.push_str(&alerts);
    sections.insert("60_alerts".into(), alerts);

    // ── Footer ───────────────────────────────────────────────────────
    let footer = format!(
        "---\n*Storybook v1 — generated deterministically from the local fact store + workspace scan. No LLM calls. Saved as `__storybook__::{}::{}`. Diff against earlier readouts via `GET /v1/projects/{}/storybook/diff?a=<ts>&b=<ts>`.*\n",
        input.project_id, input.now_unix_ms, input.project_id,
    );
    md.push_str(&footer);
    sections.insert("99_footer".into(), footer);

    let stats = StorybookStats {
        plane_count: planes.len(),
        planes_with_vision,
        planes_with_mapped_modules: planes_with_modules,
        orphan_planes,
        workspace_loc: workspace_scan.as_ref().map_or(0, |w| w.stats.total_loc),
        stub_count: workspace_scan.as_ref().map_or(0, |w| w.stats.stub_count),
        dead_code_count: workspace_scan.as_ref().map_or(0, |w| w.stats.dead_code_count),
        bytes: md.len(),
    };

    Some(StorybookDocument {
        project_id: input.project_id.to_string(),
        generated_at_unix_ms: input.now_unix_ms,
        generated_by_passport: input.by_passport.to_string(),
        markdown: md,
        sections,
        stats,
    })
}

/// Diff two storybook documents — surface added/removed/changed sections so
/// the operator can see drift over time.
#[derive(Debug, Clone, Serialize)]
pub struct StorybookDiff {
    pub from_ts: u64,
    pub to_ts: u64,
    pub added_sections: Vec<String>,
    pub removed_sections: Vec<String>,
    pub changed_sections: Vec<String>,
    pub bytes_delta: i64,
}

pub fn diff_documents(a: &StorybookDocument, b: &StorybookDocument) -> StorybookDiff {
    let a_keys: BTreeSet<&String> = a.sections.keys().collect();
    let b_keys: BTreeSet<&String> = b.sections.keys().collect();
    let added: Vec<String> = b_keys.difference(&a_keys).map(|s| (*s).clone()).collect();
    let removed: Vec<String> = a_keys.difference(&b_keys).map(|s| (*s).clone()).collect();
    let mut changed: Vec<String> = Vec::new();
    for k in a_keys.intersection(&b_keys) {
        if a.sections.get(*k) != b.sections.get(*k) {
            changed.push((*k).clone());
        }
    }
    StorybookDiff {
        from_ts: a.generated_at_unix_ms,
        to_ts: b.generated_at_unix_ms,
        added_sections: added,
        removed_sections: removed,
        changed_sections: changed,
        bytes_delta: (b.markdown.len() as i64) - (a.markdown.len() as i64),
    }
}

// ────────────────────────── Public re-exports (Phase 4) ──────────────

/// Public alias for [`extract_keywords`] so the dossier auto-generator can
/// reuse the exact same tokeniser the storybook uses (so claims and
/// readouts agree on what counts as a keyword).
pub fn extract_keywords_pub(text: &str) -> HashSet<String> {
    extract_keywords(text)
}

/// How a plane's crate set was arrived at. The two are not interchangeable and
/// a consumer must be able to tell them apart: one is a statement by whoever
/// owns the plane, the other is a guess from word overlap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleSource {
    /// Read from the plane's `modules` layer.
    Declared,
    /// Derived from keyword overlap between the plane's prose and crate names.
    KeywordOverlap,
}

/// Resolve a plane's crates, preferring a declaration over inference.
///
/// Replaces the old `match_plane_to_modules_pub` alias, which could only ever
/// return the guess. The storybook and the dossier both call this, so their
/// `implements` claims stay identical — that was the alias's purpose and it is
/// preserved.
///
/// The plane-layer key is free-form (`PUT .../planes/{plane}/layers/{layer}`
/// validates only non-empty and no `::`), so `modules` needs no schema change —
/// it is a layer like `vision` and `goals`. An assessment of this join recorded
/// it as blocked on "a plane→route schema decision"; that was wrong, the
/// mechanism was already there.
///
/// Accepts comma-, newline- or whitespace-separated crate names, and keeps only
/// names the scan actually knows so a typo cannot invent a crate. A declaration
/// that matches nothing falls through to inference rather than silently
/// emptying the plane: an all-typo declaration is a mistake, not an assertion
/// that the plane owns no code.
pub fn resolve_plane_modules(
    plane_layers: &BTreeMap<String, String>,
    plane_kws: &HashSet<String>,
    scan: &crate::workspace_scan::WorkspaceScan,
) -> (Vec<String>, ModuleSource) {
    if let Some(raw) = plane_layers.get("modules") {
        let known: BTreeSet<&str> = scan.crates.iter().map(|c| c.name.as_str()).collect();
        let mut declared: Vec<String> = raw
            .split([',', '\n', '\r', ' ', '\t'])
            .map(str::trim)
            .filter(|t| !t.is_empty() && known.contains(t))
            .map(str::to_string)
            .collect();
        declared.sort();
        declared.dedup();
        if !declared.is_empty() {
            return (declared, ModuleSource::Declared);
        }
    }
    (match_plane_to_modules(plane_kws, scan), ModuleSource::KeywordOverlap)
}

// ────────────────────────── Helpers ──────────────────────────

fn read_project_layers(store: &corecrux_memory::FactStore, project_id: &str) -> BTreeMap<String, String> {
    let prefix = format!("__project_layer__::{project_id}::");
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
    let mut out = BTreeMap::new();
    for fact in latest {
        if !fact.entity.starts_with(&prefix) || fact.key != "content" || fact.value.is_empty() {
            continue;
        }
        let name = fact.entity[prefix.len()..].to_string();
        out.insert(name, fact.value);
    }
    out
}

fn read_plane_layers(store: &corecrux_memory::FactStore, project_id: &str, plane_id: &str) -> BTreeMap<String, String> {
    let prefix = format!("__plane_layer__::{project_id}::{plane_id}::");
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: None,
        entity: None,
        entity_prefix: Some(prefix.clone()),
        top_k: 100,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    let mut out = BTreeMap::new();
    for fact in latest {
        if !fact.entity.starts_with(&prefix) || fact.key != "content" || fact.value.is_empty() {
            continue;
        }
        let name = fact.entity[prefix.len()..].to_string();
        out.insert(name, fact.value);
    }
    out
}

const STOPWORDS: &[&str] = &[
    "the",
    "and",
    "for",
    "with",
    "this",
    "that",
    "from",
    "into",
    "are",
    "was",
    "have",
    "has",
    "you",
    "your",
    "our",
    "their",
    "but",
    "not",
    "all",
    "any",
    "can",
    "will",
    "just",
    "yet",
    "one",
    "two",
    "more",
    "less",
    "must",
    "may",
    "would",
    "should",
    "could",
    "what",
    "where",
    "when",
    "which",
    "who",
    "why",
    "how",
    "between",
    "across",
    "every",
    "some",
    "those",
    "these",
    "such",
    "rather",
    "than",
    "also",
    "they",
    "them",
    "his",
    "her",
    "its",
    "about",
    "over",
    "under",
    "out",
    "off",
    "very",
    "much",
    "still",
    "even",
    "only",
    "now",
    "here",
    "there",
    "then",
    "than",
    "into",
    "onto",
    "upon",
    "without",
    "within",
    "while",
    "until",
    "since",
    "because",
    "though",
    "although",
    "however",
    "moreover",
    "therefore",
    "hence",
    "into",
    "have",
    "had",
    "been",
    "being",
    "does",
    "did",
    "doing",
    "done",
    "make",
    "made",
    "making",
    "use",
    "used",
    "using",
    "uses",
    "get",
    "got",
    "getting",
    "set",
    "setting",
    "let",
    "letting",
    "see",
    "seen",
    "saw",
    "look",
    "looking",
    "looked",
    "find",
    "found",
    "finding",
    "give",
    "given",
    "giving",
    "take",
    "taken",
    "taking",
    "come",
    "coming",
    "came",
    "go",
    "going",
    "went",
    "gone",
    "one",
    "two",
    "three",
];

fn extract_keywords(text: &str) -> HashSet<String> {
    let lower = text.to_lowercase();
    let mut out: HashSet<String> = HashSet::new();
    for token in lower.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-') {
        if token.len() < 4 {
            continue;
        }
        if STOPWORDS.contains(&token) {
            continue;
        }
        // Drop pure numbers.
        if token.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        out.insert(token.to_string());
    }
    out
}

fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f32 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let intersection = a.intersection(b).count();
    let union = a.union(b).count();
    if union == 0 {
        0.0
    } else {
        intersection as f32 / union as f32
    }
}

/// For each crate in the workspace, score it against the plane's keyword set
/// using overlap with the crate name + tokenized module paths. Return crate
/// names whose overlap is meaningful (>= 2 shared keywords with normalised
/// score >= 0.05).
fn match_plane_to_modules(plane_kws: &HashSet<String>, scan: &crate::workspace_scan::WorkspaceScan) -> Vec<String> {
    if plane_kws.is_empty() {
        return Vec::new();
    }
    let mut crate_keywords: BTreeMap<String, HashSet<String>> = BTreeMap::new();
    for c in &scan.crates {
        let mut kws: HashSet<String> = HashSet::new();
        for tok in c.name.split(['-', '_']) {
            if tok.len() >= 3 {
                kws.insert(tok.to_lowercase());
            }
        }
        crate_keywords.insert(c.name.clone(), kws);
    }
    for f in &scan.files {
        if let Some(set) = crate_keywords.get_mut(&f.crate_name) {
            for tok in f.module_path.split("::") {
                for sub in tok.split('_') {
                    if sub.len() >= 3 && !STOPWORDS.contains(&sub.to_lowercase().as_str()) {
                        set.insert(sub.to_lowercase());
                    }
                }
            }
        }
    }
    // Use overlap coefficient (intersection / min(|A|,|B|)) — Jaccard breaks
    // down when |plane_kws| ≫ |crate_kws|, which is the common case after
    // a large vision-doc ingest. Overlap coefficient asks: "what fraction of
    // the crate's identity keywords show up in the plane?", which is what
    // we actually want.
    let mut scored: Vec<(String, f32, usize)> = Vec::new();
    for (cname, kws) in &crate_keywords {
        if kws.is_empty() {
            continue;
        }
        let intersection = plane_kws.intersection(kws).count();
        if intersection < 2 {
            continue;
        }
        let denom = kws.len().min(plane_kws.len()).max(1);
        let coverage = intersection as f32 / denom as f32;
        // Coverage >= 0.30 means at least 30% of the crate's identity
        // keywords appear in the plane's vision text — strong signal.
        if coverage < 0.30 {
            continue;
        }
        scored.push((cname.clone(), coverage, intersection));
    }
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    scored.into_iter().take(8).map(|(c, _, _)| c).collect()
}

fn unix_ms_to_iso(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let nanos = ((ms % 1000) * 1_000_000) as u32;
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nanos)
        .map_or_else(|| format!("{ms}ms-since-epoch"), |d| d.to_rfc3339())
}

fn truncate_iso(iso: &str) -> String {
    iso.split('T').next().unwrap_or(iso).to_string()
}

fn truncate_for_quote(s: &str, max: usize) -> String {
    let cleaned: String = s.lines().take(3).collect::<Vec<_>>().join(" ");
    if cleaned.len() <= max {
        return cleaned;
    }
    // `max` is a byte budget, but slicing at it directly panics when a
    // multi-byte character straddles the limit. Callers pass operator-supplied
    // plane-vision text and source snippets, so an em-dash in a comment used
    // to take down the whole readout. Retreat to the nearest char boundary at
    // or below the budget.
    let mut end = max;
    while end > 0 && !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &cleaned[..end])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn extracts_keywords_drops_short_and_stopwords() {
        let kws = extract_keywords("the daemon is local-first and offline-first for agents");
        assert!(kws.contains("daemon"));
        assert!(kws.contains("local-first"));
        assert!(kws.contains("offline-first"));
        assert!(kws.contains("agents"));
        assert!(!kws.contains("the")); // stopword
        assert!(!kws.contains("is")); // too short
        assert!(!kws.contains("for")); // stopword
    }

    #[test]
    fn jaccard_basic() {
        let a: HashSet<String> = ["x", "y", "z"].iter().map(|s| (*s).to_string()).collect();
        let b: HashSet<String> = ["y", "z", "w"].iter().map(|s| (*s).to_string()).collect();
        // intersection {y,z}=2, union {x,y,z,w}=4 → 0.5
        assert_eq!(jaccard(&a, &b), 0.5);
        let empty: HashSet<String> = HashSet::new();
        assert_eq!(jaccard(&a, &empty), 0.0);
    }

    #[test]
    fn generate_e2e_renders_markdown_with_required_sections() {
        // End-to-end coverage lift: build a project + a plane + a layer, then
        // call generate() and assert the markdown comes back with the
        // expected section anchors. Hits the front-matter, project section,
        // planes section, layer section, and stats roll-up — coverage gain
        // ~ 200+ lines on storybook.rs.
        use corecrux_memory::FactStore;
        let mut store = FactStore::new();

        // Seed a project (record stored under __project__::p1).
        let project_record = serde_json::to_string(&serde_json::json!({
            "id": "p1",
            "name": "Project One",
            "planning_target": "tenant://p1-planning",
            "default_passport_id": "personal-default",
            "created_at_unix_ms": 1u64,
            "archived": false,
            "is_default": false,
        }))
        .unwrap();
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "__project__::p1".to_string(),
            key: "record".to_string(),
            value: project_record,
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

        // Seed a plane.
        let plane_record = serde_json::to_string(&serde_json::json!({
            "project_id": "p1",
            "id": "daemon",
            "name": "Crux Daemon",
            "description": "the daemon plane",
            "created_at_unix_ms": 1u64,
        }))
        .unwrap();
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "__plane__::p1::daemon".to_string(),
            key: "record".to_string(),
            value: plane_record,
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

        // Seed a vision layer for the project.
        store.store(corecrux_memory::fact_store::StoreFact {
            tenant_hash: "default".to_string(),
            entity: "__project_layer__::p1::vision".to_string(),
            key: "content".to_string(),
            value: "Local-first daemon for agent memory.".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

        let doc = generate(
            &store,
            GenerateInput {
                project_id: "p1",
                by_passport: "personal-default",
                now_unix_ms: 1_700_000_000_000,
                spans: &[],
            },
        )
        .expect("storybook should generate when project exists");

        // Front matter
        assert!(doc.markdown.contains("# Storybook"));
        assert!(doc.markdown.contains("p1"));
        // Sections map populated
        assert!(!doc.sections.is_empty());
        // Stats roll-up
        assert_eq!(doc.stats.plane_count, 1);
        assert!(doc.stats.bytes > 0);
    }

    #[test]
    fn generate_returns_none_for_unknown_project() {
        use corecrux_memory::FactStore;
        let store = FactStore::new();
        let doc = generate(
            &store,
            GenerateInput {
                project_id: "nope",
                by_passport: "x",
                now_unix_ms: 1,
                spans: &[],
            },
        );
        assert!(doc.is_none());
    }

    #[test]
    fn match_plane_to_modules_via_pub_alias() {
        let scan = crate::workspace_scan::WorkspaceScan::default();
        let kws: HashSet<String> = ["daemon".to_string()].into_iter().collect();
        let _ = match_plane_to_modules(&kws, &scan);
        let _ = extract_keywords_pub("hello daemon world");
    }

    #[test]
    fn diff_detects_added_removed_changed_sections() {
        let mut a_sections = BTreeMap::new();
        a_sections.insert("00_front".to_string(), "old front".to_string());
        a_sections.insert("10_vision".to_string(), "vision text".to_string());
        let mut b_sections = BTreeMap::new();
        b_sections.insert("00_front".to_string(), "new front".to_string());
        b_sections.insert("10_vision".to_string(), "vision text".to_string());
        b_sections.insert("20_goals".to_string(), "added goals".to_string());
        let a = StorybookDocument {
            project_id: "p".into(),
            generated_at_unix_ms: 1,
            generated_by_passport: "x".into(),
            markdown: "abc".into(),
            sections: a_sections,
            stats: Default::default(),
        };
        let b = StorybookDocument {
            project_id: "p".into(),
            generated_at_unix_ms: 2,
            generated_by_passport: "x".into(),
            markdown: "abcdefgh".into(),
            sections: b_sections,
            stats: Default::default(),
        };
        let d = diff_documents(&a, &b);
        assert!(d.added_sections.contains(&"20_goals".to_string()));
        assert!(d.changed_sections.contains(&"00_front".to_string()));
        assert_eq!(d.bytes_delta, 5);
    }

    /// The workspace-health caveat must state which tiers actually spoke.
    ///
    /// Before the runtime join it carried a permanent hedge — "Regex-based; may
    /// miss macro / dynamic-dispatch usages" — on every readout forever. A
    /// caveat that never changes is one a reader learns to skip, and it
    /// understates the answer once a runtime tier is available.
    #[test]
    fn the_dead_code_caveat_reflects_which_tiers_spoke() {
        let mut ws = crate::workspace_scan::WorkspaceScan::default();
        ws.scan_id = "ws_t".into();
        ws.stats.dead_code_count = 1;
        ws.dead_code = vec![crate::workspace_scan::DeadSymbol {
            crate_name: "c".into(),
            module_path: "m".into(),
            file_rel_path: "src/quiet.rs".into(),
            line: 3,
            kind: "fn".into(),
            name: "orphan".into(),
            confidence: 0.6,
            note: "no references".into(),
        }];

        // No window: one tier, and the readout says so.
        let none = crate::code_intel::dead_code_verdicts(&ws, &[]);
        assert_eq!(none[0].verdict, "dead_candidate__static_only");
        assert!(!none[0].actionable);

        // A window that exercised the symbol's own file: the negative counts.
        let spans = vec![crate::trace_store::StoredSpan {
            span: crux_observe::span_layer::SpanRecord {
                trace_id: 7,
                span_id: 8,
                parent_span_id: None,
                name: "neighbour".into(),
                target: "t".into(),
                file: Some("src/quiet.rs".into()),
                line: Some(1),
                module_path: None,
                duration_ns: 5,
                depth: 0,
                had_error: false,
                outcome: Default::default(),
            },
            symbol_id: None,
            join: "extracted".into(),
            tenant_id: String::new(),
            release: String::new(),
            stored_at_unix_ms: 10,
        }];
        let graded = crate::code_intel::dead_code_verdicts(&ws, &spans);
        assert_eq!(graded[0].verdict, "dead_candidate__static_and_runtime_agree");
        assert!(graded[0].actionable, "the symbol's file ran and it did not");

        // And the window the grading rests on is reportable.
        let w = crate::code_intel::Window::of(&spans);
        assert_eq!(w.spans_examined, 1);
        assert_eq!(w.traces_examined, 1);
    }

    /// A plane that declares its crates must not be treated as a guess.
    ///
    /// The join assessment recorded this as blocked on "a plane→route schema
    /// decision". It was not: the plane-layer key is free-form, so `modules` is
    /// a layer like `vision` and no schema change was needed. Recorded here
    /// because a wrong "blocked" conclusion is the kind that stays believed.
    #[test]
    fn a_declared_modules_layer_outranks_keyword_overlap() {
        let mut scan = crate::workspace_scan::WorkspaceScan::default();
        scan.crates = vec![
            crate::workspace_scan::CrateInfo {
                name: "corecrux-retrieval".into(),
                rel_path: "crates/corecrux-retrieval".into(),
                internal_deps: vec![],
                file_count: 1,
                total_loc: 10,
            },
            crate::workspace_scan::CrateInfo {
                name: "corecrux-index".into(),
                rel_path: "crates/corecrux-index".into(),
                internal_deps: vec![],
                file_count: 1,
                total_loc: 10,
            },
        ];
        let kws = extract_keywords("nothing here matches any crate name at all");
        let mut layers: BTreeMap<String, String> = BTreeMap::new();

        // No declaration ⇒ inference.
        assert_eq!(
            resolve_plane_modules(&layers, &kws, &scan).1,
            ModuleSource::KeywordOverlap
        );

        // Declared ⇒ used verbatim, and marked as declared.
        layers.insert("modules".into(), "corecrux-index, corecrux-retrieval".into());
        let (mods, src) = resolve_plane_modules(&layers, &kws, &scan);
        assert_eq!(src, ModuleSource::Declared);
        assert_eq!(mods, vec!["corecrux-index", "corecrux-retrieval"]);

        // Newlines and stray whitespace: an operator writes this by hand.
        layers.insert("modules".into(), "corecrux-index\n  corecrux-retrieval\n".into());
        assert_eq!(resolve_plane_modules(&layers, &kws, &scan).0.len(), 2);

        // A typo cannot invent a crate the scan has never seen. Built by
        // transposition rather than written out, so the repo's spell-checker
        // does not have to be taught to ignore a deliberate misspelling.
        let transposed = "corecrux-retrieval".replace("ie", "ei");
        layers.insert("modules".into(), format!("corecrux-index, {transposed}"));
        let (mods, src) = resolve_plane_modules(&layers, &kws, &scan);
        assert_eq!(src, ModuleSource::Declared);
        assert_eq!(mods, vec!["corecrux-index"], "the misspelling is dropped, not invented");

        // An all-typo declaration falls back rather than emptying the plane.
        layers.insert("modules".into(), "not-a-crate, also-not-a-crate".into());
        assert_eq!(
            resolve_plane_modules(&layers, &kws, &scan).1,
            ModuleSource::KeywordOverlap
        );
    }

    // ────────────────────────── Fixtures ──────────────────────────

    fn put_fact(store: &mut corecrux_memory::FactStore, entity: &str, key: &str, value: &str) {
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

    fn put_project_layer(store: &mut corecrux_memory::FactStore, project: &str, layer: &str, value: &str) {
        put_fact(
            store,
            &format!("__project_layer__::{project}::{layer}"),
            "content",
            value,
        );
    }

    fn put_plane_layer(store: &mut corecrux_memory::FactStore, project: &str, plane: &str, layer: &str, value: &str) {
        put_fact(
            store,
            &format!("__plane_layer__::{project}::{plane}::{layer}"),
            "content",
            value,
        );
    }

    fn put_workspace_scan(store: &mut corecrux_memory::FactStore, scan: &crate::workspace_scan::WorkspaceScan) {
        put_fact(
            store,
            crate::workspace_scan::LATEST_SCAN_ENTITY,
            crate::workspace_scan::SCAN_KEY,
            &serde_json::to_string(scan).expect("encode scan"),
        );
    }

    fn crate_info(name: &str) -> crate::workspace_scan::CrateInfo {
        crate::workspace_scan::CrateInfo {
            name: name.to_string(),
            rel_path: format!("crates/{name}"),
            internal_deps: Vec::new(),
            file_count: 1,
            total_loc: 100,
        }
    }

    fn dead_symbol(crate_name: &str, name: &str, line: usize) -> crate::workspace_scan::DeadSymbol {
        crate::workspace_scan::DeadSymbol {
            crate_name: crate_name.to_string(),
            module_path: format!("{crate_name}::quiet"),
            file_rel_path: format!("crates/{crate_name}/src/quiet.rs"),
            line,
            kind: "fn".into(),
            name: name.to_string(),
            confidence: 0.6,
            note: "no references".into(),
        }
    }

    /// A scan with two crates, a stub and seven dead symbols in one crate — the
    /// seventh forces the "…and N more" roll-up in the workspace-health tier.
    fn populated_scan() -> crate::workspace_scan::WorkspaceScan {
        let mut scan = crate::workspace_scan::WorkspaceScan {
            scan_id: "ws_fixture".into(),
            root_path: "/repo".into(),
            started_at_unix_ms: 1_700_000_000_000,
            crates: vec![crate_info("corecrux-retrieval"), crate_info("corecrux-index")],
            ..Default::default()
        };
        scan.stubs = vec![crate::workspace_scan::StubHit {
            crate_name: "corecrux-retrieval".into(),
            file_rel_path: "crates/corecrux-retrieval/src/lib.rs".into(),
            line: 12,
            kind: "todo".into(),
            // Long enough to exercise the snippet truncation in the readout.
            snippet: format!("todo!(\"{}\")", "x".repeat(200)),
        }];
        scan.dead_code = (0..7)
            .map(|i| dead_symbol("corecrux-retrieval", &format!("orphan_{i}"), 10 + i))
            .collect();
        scan.stats.crate_count = 2;
        scan.stats.file_count = 2;
        scan.stats.total_loc = 200;
        scan.stats.symbol_count = 9;
        scan.stats.dep_count = 1;
        scan.stats.stub_count = scan.stubs.len();
        scan.stats.dead_code_count = scan.dead_code.len();
        scan
    }

    fn seeded_project(dir: &std::path::Path) -> corecrux_memory::FactStore {
        let mut store = corecrux_memory::FactStore::new();
        crate::passports::seed_defaults_if_missing(dir, &mut store, 1).expect("seed passports");
        crate::projects::create_project(
            &mut store,
            crate::projects::CreateProjectInput {
                id: "p".into(),
                name: "Project P".into(),
                planning_target: Some("github://owner/repo".into()),
                default_passport_id: "personal-default".into(),
                working_tenants: vec![],
            },
            1_000,
        )
        .expect("create project");
        store
    }

    fn generated(store: &corecrux_memory::FactStore, spans: &[crate::trace_store::StoredSpan]) -> StorybookDocument {
        generate(
            store,
            GenerateInput {
                project_id: "p",
                by_passport: "personal-default",
                now_unix_ms: 1_700_000_000_000,
                spans,
            },
        )
        .expect("project exists so a storybook must generate")
    }

    // ────────────────────────── Full readout ──────────────────────────

    /// The whole readout in one pass: front matter with a scan summary, member
    /// and tenant rollups, a plane that declares its crates, an orphan plane,
    /// the coverage matrix, the workspace-health tier and the gap list.
    ///
    /// Guards the readout's structural promise — an operator reads it by section
    /// header, so a section silently disappearing (rather than saying "none")
    /// is the regression that matters.
    #[test]
    fn a_full_readout_renders_every_section() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = seeded_project(dir.path());
        crate::projects::add_member(&mut store, "p", "work-default", "owner", 2_000).expect("member");
        crate::projects::add_tenant(&mut store, "p", "work::p", None, 2_000).expect("tenant");
        put_project_layer(&mut store, "p", "vision", "A local-first retrieval daemon for agents.");
        // No project `goals` layer: the goals section must degrade to a notice
        // and raise its own alert rather than vanishing.

        crate::planes::create_plane(
            &mut store,
            crate::planes::CreatePlaneInput {
                project_id: "p".into(),
                id: "retrieval".into(),
                name: "Retrieval".into(),
                description: Some("retrieval and index plane".into()),
                default_passport_id: None,
            },
            3_000,
        )
        .expect("plane");
        crate::planes::add_member(&mut store, "p", "retrieval", "work-default", "owner", 3_100).expect("plane member");
        crate::planes::add_tenant(&mut store, "p", "retrieval", "work::p::retrieval", None, 3_200)
            .expect("plane tenant");
        put_plane_layer(
            &mut store,
            "p",
            "retrieval",
            "vision",
            &format!("Retrieval plane vision. {}", "detail ".repeat(80)),
        );
        put_plane_layer(&mut store, "p", "retrieval", "goals", "Ship the dense lane.");
        put_plane_layer(&mut store, "p", "retrieval", "modules", "corecrux-retrieval");

        crate::planes::create_plane(
            &mut store,
            crate::planes::CreatePlaneInput {
                project_id: "p".into(),
                id: "orphan".into(),
                name: "Orphan".into(),
                description: None,
                default_passport_id: None,
            },
            4_000,
        )
        .expect("orphan plane");

        put_workspace_scan(&mut store, &populated_scan());

        let doc = generated(&store, &[]);
        let md = &doc.markdown;

        // Front matter: the scan summary line, members and tenants.
        assert!(md.starts_with("# Storybook · p ·"), "front matter: {}", &md[..64]);
        assert!(md.contains("2 crates · 2 files · 200 loc"), "scan summary missing");
        assert!(md.contains("`work-default` (owner)"));
        assert!(md.contains("`work::p`"));

        // Narrative sections.
        assert!(md.contains("## What this project is"));
        assert!(md.contains("A local-first retrieval daemon for agents."));
        assert!(md.contains("## What it's trying to achieve"));
        assert!(md.contains("*No goals layer set.*"));

        // Planes: the declared-crates wording must differ from the inferred one.
        assert!(md.contains("## Planes"));
        assert!(md.contains("### Retrieval `retrieval`"));
        assert!(md.contains("**Declared crates (plane `modules` layer)**: `corecrux-retrieval`"));
        assert!(md.contains("**Stubs in matching crates**: 1 · **Dead-code candidates**: 7"));
        assert!(md.contains("- **Plane vision** (truncated):"));
        assert!(md.contains('…'), "the long plane vision is truncated");
        assert!(md.contains("### Orphan `orphan`"));
        assert!(md.contains("- **Description**: *(none)*"));
        assert!(md.contains("*none — this plane has no source mapping yet (gap)*"));

        // Coverage matrix.
        assert!(md.contains("## Coverage matrix"));
        assert!(md.contains("| `retrieval` | ✓ | ✓ | `corecrux-retrieval` | 1 | 7 |"));
        assert!(md.contains("| `orphan` | — | — | — | 0 | 0 | **no crates mapped** |"));

        // Workspace health.
        assert!(md.contains("## Workspace health"));
        assert!(md.contains("### Stubs (1)"));
        assert!(md.contains("### Dead-code candidates (7, static tier only)"));
        assert!(md.contains("…and 1 more"), "the 7th dead symbol rolls up");

        // Gaps.
        assert!(md.contains("- ❗ Project has no **goals layer** set."));
        assert!(!md.contains("- ❗ Project has no **vision layer** set."));
        assert!(md.contains("- ⚠ **1 planes have no mapped crates**"));
        assert!(md.contains("- ⚠ **1 planes have no vision layer**"));

        // Footer + section index.
        assert!(md.contains("*Storybook v1 — generated deterministically"));
        for section in [
            "00_front",
            "10_vision",
            "20_goals",
            "30_planes_intro",
            "30_plane_retrieval",
            "30_plane_orphan",
            "40_coverage",
            "50_workspace_health",
            "60_alerts",
            "99_footer",
        ] {
            assert!(doc.sections.contains_key(section), "missing section {section}");
        }

        // Stats roll-up.
        assert_eq!(doc.stats.plane_count, 2);
        assert_eq!(doc.stats.planes_with_vision, 1);
        assert_eq!(doc.stats.planes_with_mapped_modules, 1);
        assert_eq!(doc.stats.orphan_planes, vec!["orphan".to_string()]);
        assert_eq!(doc.stats.workspace_loc, 200);
        assert_eq!(doc.stats.stub_count, 1);
        assert_eq!(doc.stats.dead_code_count, 7);
        assert_eq!(doc.stats.bytes, md.len());
        assert_eq!(doc.project_id, "p");
        assert_eq!(doc.generated_by_passport, "personal-default");
    }

    /// With a runtime window the dead-code heading must grade the candidates
    /// instead of repeating the permanent static-only hedge.
    #[test]
    fn the_readout_grades_dead_code_when_a_runtime_window_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = seeded_project(dir.path());
        put_workspace_scan(&mut store, &populated_scan());

        let spans = vec![crate::trace_store::StoredSpan {
            span: crux_observe::span_layer::SpanRecord {
                trace_id: 1,
                span_id: 2,
                parent_span_id: None,
                name: "neighbour".into(),
                target: "t".into(),
                file: Some("crates/corecrux-retrieval/src/quiet.rs".into()),
                line: Some(1),
                module_path: None,
                duration_ns: 5,
                depth: 0,
                had_error: false,
                outcome: Default::default(),
            },
            symbol_id: None,
            join: "extracted".into(),
            tenant_id: String::new(),
            release: String::new(),
            stored_at_unix_ms: 10,
        }];

        let md = generated(&store, &spans).markdown;
        assert!(
            md.contains("### Dead-code candidates (7 static · **7 actionable** · 0 refuted)"),
            "graded heading missing: {md}"
        );
        assert!(md.contains("Graded over a window of 1 spans across 1 traces"));
        assert!(!md.contains("static tier only"));
    }

    /// A bare project must still produce a readout, and every missing input has
    /// to show up as a named gap rather than as a silently absent section.
    #[test]
    fn an_empty_project_lists_every_gap_it_has() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = seeded_project(dir.path());

        let doc = generated(&store, &[]);
        let md = &doc.markdown;
        assert!(md.contains("(no scan run yet — POST /v1/workspace/scan to populate)"));
        assert!(md.contains("*No vision layer set."));
        assert!(md.contains("*No goals layer set.*"));
        assert!(md.contains("*No planes provisioned."));
        assert!(md.contains("- ❗ Project has no **vision layer** set."));
        assert!(md.contains("- ❗ Project has no **goals layer** set."));
        assert!(md.contains("- ⚠ No workspace scan has been run."));
        // Without a scan there is nothing to build a coverage matrix from.
        assert!(!md.contains("## Coverage matrix"));
        assert!(!md.contains("## Workspace health"));
        assert!(!doc.sections.contains_key("40_coverage"));
        assert_eq!(doc.stats.plane_count, 0);
        assert_eq!(doc.stats.workspace_loc, 0);
        assert!(doc.stats.orphan_planes.is_empty());
    }

    /// The clean-bill-of-health branch: vision + goals set, a scan present and
    /// no planes to orphan. Untested, "no gaps detected" would be indefinitely
    /// unreachable without anyone noticing.
    #[test]
    fn a_project_with_no_gaps_says_so_explicitly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = seeded_project(dir.path());
        put_project_layer(&mut store, "p", "vision", "Vision text.");
        put_project_layer(&mut store, "p", "goals", "Goals text.");
        let mut scan = crate::workspace_scan::WorkspaceScan::default();
        scan.scan_id = "ws_clean".into();
        scan.stats.crate_count = 1;
        put_workspace_scan(&mut store, &scan);

        let md = generated(&store, &[]).markdown;
        assert!(md.contains("- ✓ No structural gaps detected."));
        assert!(!md.contains("❗"));
        // No stubs and no dead code ⇒ those sub-tiers are omitted, but the
        // health section itself still renders.
        assert!(md.contains("## Workspace health"));
        assert!(!md.contains("### Stubs ("));
        assert!(!md.contains("### Dead-code candidates"));
    }

    /// The >50 dead-code alert is its own tier and fires independently of the
    /// per-plane gap alerts.
    #[test]
    fn a_large_dead_code_count_raises_its_own_alert() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut store = seeded_project(dir.path());
        put_project_layer(&mut store, "p", "vision", "Vision text.");
        put_project_layer(&mut store, "p", "goals", "Goals text.");
        let mut scan = populated_scan();
        scan.stats.dead_code_count = 51;
        put_workspace_scan(&mut store, &scan);

        let md = generated(&store, &[]).markdown;
        assert!(md.contains("- ⚠ **51 dead-code candidates** across the workspace"));

        // At exactly 50 the alert must not fire — the threshold is `> 50`.
        let mut store = seeded_project(dir.path());
        put_project_layer(&mut store, "p", "vision", "Vision text.");
        put_project_layer(&mut store, "p", "goals", "Goals text.");
        let mut scan = populated_scan();
        scan.stats.dead_code_count = 50;
        put_workspace_scan(&mut store, &scan);
        assert!(!generated(&store, &[])
            .markdown
            .contains("dead-code candidates** across"));
    }

    /// A plane whose prose overlaps the project vision is marked aligned. The
    /// marker is the only signal in the readout that a plane is pulling in the
    /// same direction as the project, so it must be threshold-driven, not
    /// always-on.
    #[test]
    fn the_vision_alignment_marker_is_threshold_driven() {
        let dir = tempfile::tempdir().expect("tempdir");

        let mut aligned = seeded_project(dir.path());
        put_project_layer(&mut aligned, "p", "vision", "retrieval dense lane reranking");
        crate::planes::create_plane(
            &mut aligned,
            crate::planes::CreatePlaneInput {
                project_id: "p".into(),
                id: "retrieval".into(),
                name: "retrieval dense lane reranking".into(),
                description: None,
                default_passport_id: None,
            },
            3_000,
        )
        .expect("plane");
        assert!(
            generated(&aligned, &[]).markdown.contains("· vision-aligned ("),
            "a plane echoing the project vision is marked aligned"
        );

        let mut unaligned = seeded_project(dir.path());
        put_project_layer(&mut unaligned, "p", "vision", "retrieval dense lane reranking");
        crate::planes::create_plane(
            &mut unaligned,
            crate::planes::CreatePlaneInput {
                project_id: "p".into(),
                id: "billing".into(),
                name: "invoicing subscriptions".into(),
                description: None,
                default_passport_id: None,
            },
            3_000,
        )
        .expect("plane");
        assert!(!generated(&unaligned, &[]).markdown.contains("vision-aligned"));
    }

    // ────────────────────────── Layer reads ──────────────────────────

    /// Layer reads must ignore every fact that is not a non-empty `content`
    /// value, and must take the newest version of the ones that are. A stale
    /// version winning here means the readout describes a project as it was.
    #[test]
    fn layer_reads_take_the_latest_content_fact_and_ignore_the_rest() {
        let mut store = corecrux_memory::FactStore::new();
        put_project_layer(&mut store, "p", "vision", "first");
        put_project_layer(&mut store, "p", "vision", "second");
        put_project_layer(&mut store, "p", "empty", "");
        put_fact(&mut store, "__project_layer__::p::meta", "not_content", "ignored");
        put_plane_layer(&mut store, "p", "x", "vision", "plane first");
        put_plane_layer(&mut store, "p", "x", "vision", "plane second");
        put_plane_layer(&mut store, "p", "x", "blank", "");
        put_fact(&mut store, "__plane_layer__::p::x::meta", "not_content", "ignored");

        let project_layers = read_project_layers(&store, "p");
        assert_eq!(project_layers.get("vision").map(String::as_str), Some("second"));
        assert!(!project_layers.contains_key("empty"), "empty values are dropped");
        assert!(!project_layers.contains_key("meta"), "non-content keys are dropped");

        let plane_layers = read_plane_layers(&store, "p", "x");
        assert_eq!(plane_layers.get("vision").map(String::as_str), Some("plane second"));
        assert!(!plane_layers.contains_key("blank"));
        assert!(!plane_layers.contains_key("meta"));

        // A different plane's layers must not leak in.
        assert!(read_plane_layers(&store, "p", "other").is_empty());
    }

    // ────────────────────────── Matching + helpers ──────────────────────────

    /// The inference gate is deliberately narrow: at least two shared keywords
    /// AND at least 30% of the crate's identity keywords present. Loosening
    /// either turns the readout's "inferred crates" line into noise.
    #[test]
    fn module_inference_needs_two_shared_keywords_and_thirty_percent_coverage() {
        let mut scan = crate::workspace_scan::WorkspaceScan::default();
        scan.crates = vec![crate_info("corecrux-dense-retrieval"), crate_info("corecrux-index")];

        // Only one shared keyword ("retrieval") ⇒ no match.
        let one = extract_keywords("retrieval work happens somewhere else entirely");
        assert!(match_plane_to_modules(&one, &scan).is_empty());

        // Two shared keywords out of three crate tokens (dense, retrieval of
        // {corecrux, dense, retrieval}) ⇒ 0.66 coverage ⇒ matched.
        let two = extract_keywords("dense retrieval lane");
        assert_eq!(match_plane_to_modules(&two, &scan), vec!["corecrux-dense-retrieval"]);

        // An empty keyword set can never match anything.
        assert!(match_plane_to_modules(&HashSet::new(), &scan).is_empty());

        // A crate whose name yields no keywords is skipped rather than divided by zero.
        let mut tiny = crate::workspace_scan::WorkspaceScan::default();
        tiny.crates = vec![crate_info("ab")];
        assert!(match_plane_to_modules(&two, &tiny).is_empty());
    }

    /// Module paths from the scan's files widen a crate's keyword identity, so
    /// a plane can match a crate by what is inside it, not just by its name.
    #[test]
    fn module_paths_contribute_to_a_crates_keyword_identity() {
        let mut scan = crate::workspace_scan::WorkspaceScan::default();
        scan.crates = vec![crate_info("aaa")];
        scan.files = vec![crate::workspace_scan::FileInfo {
            rel_path: "crates/aaa/src/rerank_pipeline.rs".into(),
            crate_name: "aaa".into(),
            module_path: "aaa::rerank_pipeline".into(),
            loc: 10,
            symbol_count: 1,
            stub_count: 0,
            doc_summary: None,
            doc_full: None,
            defines: Vec::new(),
            references: Vec::new(),
            referenced_by: Vec::new(),
            is_test_file: false,
        }];
        let kws = extract_keywords("rerank pipeline work");
        assert_eq!(match_plane_to_modules(&kws, &scan), vec!["aaa"]);
    }

    #[test]
    fn extract_keywords_drops_pure_numbers_but_keeps_symbol_shaped_tokens() {
        let kws = extract_keywords("Release 2026 of corecrux_memory and dense-lane v2");
        assert!(kws.contains("release"));
        assert!(kws.contains("corecrux_memory"), "underscores are word characters");
        assert!(kws.contains("dense-lane"), "hyphens are word characters");
        assert!(!kws.contains("2026"), "pure numbers are dropped");
        assert!(!kws.contains("v2"), "too short");
    }

    #[test]
    fn truncate_for_quote_joins_the_first_three_lines_and_elides_the_rest() {
        assert_eq!(truncate_for_quote("one\ntwo\nthree\nfour", 100), "one two three");
        assert_eq!(truncate_for_quote("short", 100), "short");
        let long = "a".repeat(50);
        let out = truncate_for_quote(&long, 10);
        assert_eq!(out, format!("{}…", "a".repeat(10)));
    }

    /// D-4 (inverted pin): `truncate_for_quote` sliced by byte index, so a
    /// multi-byte character straddling the limit panicked rather than
    /// truncating. `generate` calls it on operator-supplied plane-vision text
    /// (limit 280) and on scan snippets (limit 80), so non-ASCII prose of the
    /// wrong length took the whole readout down.
    #[test]
    fn truncate_for_quote_retreats_to_a_char_boundary_instead_of_panicking() {
        // Nine 'é' (2 bytes each) = 18 bytes; byte 9 lands mid-character, so
        // the cut retreats to byte 8 — four whole characters.
        assert_eq!(truncate_for_quote(&"é".repeat(9), 9), format!("{}…", "é".repeat(4)));

        // A budget that lands exactly on a boundary is unchanged.
        assert_eq!(truncate_for_quote(&"é".repeat(9), 8), format!("{}…", "é".repeat(4)));

        // Wider characters, and a budget smaller than the first character:
        // the result is the ellipsis alone, never a panic and never invalid
        // UTF-8.
        assert_eq!(truncate_for_quote("日本語テキスト", 2), "…");
        assert_eq!(truncate_for_quote("日本語テキスト", 3), "日…");

        // The real caller budgets, over text that straddles them.
        for max in [80usize, 280] {
            let text = "—".repeat(max);
            let out = truncate_for_quote(&text, max);
            assert!(out.ends_with('…'));
            assert!(out.len() <= max + '…'.len_utf8());
        }
    }

    #[test]
    fn unix_ms_to_iso_falls_back_when_the_timestamp_is_out_of_range() {
        assert!(unix_ms_to_iso(0).starts_with("1970-01-01T00:00:00"));
        assert_eq!(truncate_iso(&unix_ms_to_iso(0)), "1970-01-01");
        let out_of_range = unix_ms_to_iso(u64::MAX);
        assert!(
            out_of_range.ends_with("ms-since-epoch"),
            "an unrepresentable timestamp degrades to a literal, not a panic: {out_of_range}"
        );
        // `truncate_iso` on a value with no `T` returns it unchanged.
        assert_eq!(truncate_iso("no-separator"), "no-separator");
    }

    #[test]
    fn diff_reports_removed_sections_and_a_negative_byte_delta() {
        let mut a_sections = BTreeMap::new();
        a_sections.insert("00_front".to_string(), "front".to_string());
        a_sections.insert("40_coverage".to_string(), "matrix".to_string());
        let mut b_sections = BTreeMap::new();
        b_sections.insert("00_front".to_string(), "front".to_string());
        let doc = |sections: BTreeMap<String, String>, ts: u64, md: &str| StorybookDocument {
            project_id: "p".into(),
            generated_at_unix_ms: ts,
            generated_by_passport: "x".into(),
            markdown: md.into(),
            sections,
            stats: Default::default(),
        };
        let d = diff_documents(&doc(a_sections, 1, "abcdefgh"), &doc(b_sections, 2, "abc"));
        assert_eq!(d.removed_sections, vec!["40_coverage".to_string()]);
        assert!(d.added_sections.is_empty());
        assert!(d.changed_sections.is_empty(), "identical sections are not 'changed'");
        assert_eq!(d.bytes_delta, -5);
        assert_eq!((d.from_ts, d.to_ts), (1, 2));
    }
}
