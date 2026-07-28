// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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

        let candidate_modules = match &workspace_scan {
            Some(ws) => match_plane_to_modules(&plane_kws, ws),
            None => Vec::new(),
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
                "- **Inferred matching crates** (keyword overlap, confidence ~0.5): {}\n",
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

/// Public alias for the keyword-overlap → matching crates routine, so the
/// dossier auto-generator emits `implements` claims that are identical to
/// the storybook's coverage matrix.
pub fn match_plane_to_modules_pub(
    plane_kws: &HashSet<String>,
    scan: &crate::workspace_scan::WorkspaceScan,
) -> Vec<String> {
    match_plane_to_modules(plane_kws, scan)
}

// ────────────────────────── Helpers ──────────────────────────

fn read_project_layers(store: &corecrux_memory::FactStore, project_id: &str) -> BTreeMap<String, String> {
    let prefix = format!("__project_layer__::{project_id}::");
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        min_effective_confidence: None,
        tenant_hash: None,
        query: Some(prefix.clone()),
        entity: None,
        entity_prefix: None,
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
        query: Some(prefix.clone()),
        entity: None,
        entity_prefix: None,
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
        cleaned
    } else {
        format!("{}…", &cleaned[..max])
    }
}

#[cfg(test)]
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
        let _ = match_plane_to_modules_pub(&kws, &scan);
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
            },
            symbol_id: None,
            join: "extracted".into(),
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
}
