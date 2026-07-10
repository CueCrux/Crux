// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Deterministic context-bundle assembler (`context_bundle/v1`).
//!
//! ExecPlan `context-mediation-injection-2026-06-11` M2 (G21a). Normative
//! spec: `Context-Bundle-v1-Spec` (planning monorepo, shared plane).
//!
//! ## What this is
//!
//! A pure, deterministic assembler that turns pre-fetched, pre-scoped
//! memory rows (facts, dossier, session state, work table, coord) into a
//! versioned injection payload with an explicit **stable region** and a
//! `blake3` stable hash. Renderers: markdown (boot-banner shape), JSON,
//! OpenAI-messages fragment.
//!
//! ## Why pure
//!
//! Same discipline as [`crate::decay`]: no I/O, no `Instant::now()`, no
//! random. Callers pass `now_ms` explicitly. Given an unchanged input set
//! (and no freshness-class flips), repeated assembly produces
//! **byte-identical** stable regions — that byte-stability is the
//! provider-prompt-cache lever (TokenBurn: prefix = 54.8% of carried
//! tokens, cache_read 369x output), worth more than any server cache.
//!
//! ## What this is NOT
//!
//! Not a retrieval client and not an HTTP surface. Fetching (tenant- and
//! passport-scoped) happens in the daemon; the `/v1/context` transport is
//! plan A (`provider-integration-surfaces-2026-06-11`, flag
//! `CORECRUXD_CONTEXT_SURFACE`, default-OFF). This module carries no
//! runtime behavior change on its own.

use std::fmt::Write as _;

use crate::decay::{apply_at, DecayPolicy, Freshness, HorizonClass};
use serde::{Deserialize, Serialize};

/// Bundle contract version. The only field consumers may dispatch on.
pub const BUNDLE_VERSION: &str = "context_bundle/v1";

/// Default budget when the caller omits `requested` (house ladder: scans).
pub const DEFAULT_REQUESTED_BUDGET: usize = 2_000;
/// Free-tier hard ceiling (spec §5).
pub const FREE_TIER_CEILING: usize = 8_000;

/// Section kinds in normative stable-prefix order (spec §2/§4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SectionKind {
    Facts,
    Dossier,
    SessionState,
    WorkTable,
    Coord,
}

impl SectionKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Facts => "facts",
            Self::Dossier => "dossier",
            Self::SessionState => "session_state",
            Self::WorkTable => "work_table",
            Self::Coord => "coord",
        }
    }

    /// Normative section order (spec §4): facts, dossier, session_state,
    /// work_table, coord.
    fn order(&self) -> u8 {
        match self {
            Self::Facts => 0,
            Self::Dossier => 1,
            Self::SessionState => 2,
            Self::WorkTable => 3,
            Self::Coord => 4,
        }
    }
}

/// A candidate fact row, pre-fetched and pre-scoped by the caller.
///
/// Mirrors the fields of `corecrux_memory::fact_store::Fact` this module
/// needs, kept local so the pure crate takes no runtime dependency on the
/// memory crate (same pattern as [`crate::decay::HorizonClass`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactInput {
    pub fact_id: String,
    pub entity: String,
    pub key: String,
    pub value: String,
    /// Stored confidence 0..1.
    pub confidence: f64,
    /// Write (or re-verify) timestamp, unix millis — decay anchor.
    pub written_ms: i64,
    pub horizon_class: HorizonClass,
    /// Monotonic version within (entity, key); highest wins.
    pub version: u32,
    /// Cross-entity supersession marker — superseded facts never enter a
    /// bundle (spec §4.2).
    pub superseded: bool,
    /// Private facts enter a bundle only for their owning actor (spec §4.6).
    pub private: bool,
    /// Owning actor for private facts.
    pub owner: Option<String>,
    /// Pre-computed token estimate; when absent a deterministic heuristic
    /// applies.
    pub est_tokens: Option<usize>,
    /// True when this row was resolved from a typed address
    /// (`entity`/`execplan:<slug>`/...) rather than keyword recall.
    /// Addressed rows are selected first (spec §4.1).
    pub addressed: bool,
}

/// A pre-rendered item for the non-fact sections (dossier, session_state,
/// work_table, coord). `id` is the deterministic sort key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuxItem {
    pub id: String,
    pub text: String,
    pub est_tokens: Option<usize>,
}

/// Pre-fetched input for one non-fact section.
#[derive(Debug, Clone)]
pub struct AuxSection {
    pub kind: SectionKind,
    pub items: Vec<AuxItem>,
}

/// Assembly request. All scoping (tenant, passport) has already been
/// enforced at fetch time; `actor` is re-checked here for private facts as
/// defense in depth.
#[derive(Debug, Clone)]
pub struct BundleRequest {
    /// Passport fingerprint / actor identity of the consumer.
    pub actor: String,
    pub tenant_id: String,
    pub session_id: Option<String>,
    /// Caller `token_budget` (mandatory on the transport, QC.2).
    pub requested_budget: usize,
    /// Per-tier hard ceiling (spec §5).
    pub ceiling: usize,
    /// Explicit clock for deterministic freshness evaluation.
    pub now_ms: i64,
    pub policy: DecayPolicy,
}

/// One fact item inside the stable region. Field order here IS the wire
/// order (serde preserves struct order); nothing volatile may be added —
/// in particular no ages, no timestamps, no receipt ids (spec §6).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StableFactItem {
    pub fact_id: String,
    pub entity: String,
    pub key: String,
    pub value: String,
    pub confidence: f64,
    pub horizon_class: HorizonClass,
    /// Freshness *class* only (fresh/stale/unknown). Flips only when a
    /// fact crosses its horizon — the one sanctioned source of stable-region
    /// change without a fact write. Stale items are annotated, not dropped
    /// (spec §4.2).
    pub freshness: Freshness,
    pub est_tokens: usize,
}

/// One section of the stable region.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StableSection {
    pub kind: SectionKind,
    /// Fact items (facts section) — presentation-ordered by
    /// (entity, key, fact_id), never by retrieval score (spec §6).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub facts: Vec<StableFactItem>,
    /// Aux items (other sections) — ordered by id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<AuxItem>,
    pub est_tokens: usize,
}

/// The stable region: the byte-stable prompt prefix. `stable_hash` is
/// blake3 over the canonical JSON serialization of exactly this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StableRegion {
    pub bundle_version: String,
    pub sections: Vec<StableSection>,
}

/// Items that did not make the budget — truncation is explicit, never
/// silent (spec §2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DroppedReport {
    pub kind: SectionKind,
    pub count: usize,
    pub reason: String,
}

/// Budget accounting (volatile — lives outside the stable region).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetReport {
    pub requested: usize,
    pub ceiling: usize,
    pub spent_est: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dropped: Vec<DroppedReport>,
}

/// The assembled bundle: stable region + hash + volatile metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextBundle {
    pub stable: StableRegion,
    /// `blake3:<hex>` of the canonical stable-region bytes — the cache key
    /// and the mediation receipt's content address.
    pub stable_hash: String,
    // ---- volatile (excluded from stable_hash) ----
    pub actor: String,
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub assembled_at_ms: i64,
    pub budget: BudgetReport,
}

/// Deterministic token estimate when none is provided: ~4 bytes/token over
/// the row's text payload, with a small fixed framing overhead, min 1.
fn estimate_tokens(text_len: usize) -> usize {
    (text_len / 4).max(1) + 8
}

fn fact_est_tokens(f: &FactInput) -> usize {
    f.est_tokens
        .unwrap_or_else(|| estimate_tokens(f.entity.len() + f.key.len() + f.value.len()))
}

fn aux_est_tokens(i: &AuxItem) -> usize {
    i.est_tokens.unwrap_or_else(|| estimate_tokens(i.text.len()))
}

/// Assemble a `context_bundle/v1` from pre-fetched inputs.
///
/// Selection (what fits the budget): addressed facts first, then remaining
/// facts by time-decayed effective confidence, then aux sections in
/// normative order (spec §4). Presentation (byte order on the wire):
/// sections in normative order; facts by `(entity, key, fact_id)`; aux
/// items by `id` (spec §6).
pub fn assemble(req: &BundleRequest, facts: Vec<FactInput>, aux: Vec<AuxSection>) -> ContextBundle {
    let effective_budget = req.requested_budget.min(req.ceiling);
    let mut spent: usize = 0;
    let mut dropped: Vec<DroppedReport> = Vec::new();

    // ---- facts: dedup latest version per (entity, key), drop superseded,
    // enforce the private-fact ownership rule (defense in depth). ----
    let mut latest: std::collections::BTreeMap<(String, String), FactInput> = std::collections::BTreeMap::new();
    for f in facts {
        if f.superseded {
            continue;
        }
        if f.private && f.owner.as_deref() != Some(req.actor.as_str()) {
            continue;
        }
        let key = (f.entity.clone(), f.key.clone());
        match latest.get(&key) {
            Some(existing) if existing.version >= f.version => {}
            _ => {
                latest.insert(key, f);
            }
        }
    }

    // Selection order: addressed first, then effective-confidence rank;
    // deterministic tie-break on (entity, key, fact_id).
    let mut candidates: Vec<FactInput> = latest.into_values().collect();
    candidates.sort_by(|a, b| {
        let fa = apply_at(a.horizon_class, a.written_ms, req.now_ms, req.policy);
        let fb = apply_at(b.horizon_class, b.written_ms, req.now_ms, req.policy);
        let ea = crate::decay::effective_confidence(a.confidence, fa);
        let eb = crate::decay::effective_confidence(b.confidence, fb);
        b.addressed
            .cmp(&a.addressed)
            .then(eb.partial_cmp(&ea).unwrap_or(std::cmp::Ordering::Equal))
            .then_with(|| (&a.entity, &a.key, &a.fact_id).cmp(&(&b.entity, &b.key, &b.fact_id)))
    });

    let mut selected_facts: Vec<StableFactItem> = Vec::new();
    let mut facts_dropped = 0usize;
    for f in candidates {
        let est = fact_est_tokens(&f);
        if spent + est > effective_budget {
            facts_dropped += 1;
            continue;
        }
        spent += est;
        let freshness = apply_at(f.horizon_class, f.written_ms, req.now_ms, req.policy);
        selected_facts.push(StableFactItem {
            fact_id: f.fact_id,
            entity: f.entity,
            key: f.key,
            value: f.value,
            confidence: f.confidence,
            horizon_class: f.horizon_class,
            freshness,
            est_tokens: est,
        });
    }
    if facts_dropped > 0 {
        dropped.push(DroppedReport {
            kind: SectionKind::Facts,
            count: facts_dropped,
            reason: "budget".to_string(),
        });
    }
    // Presentation order: (entity, key, fact_id) — spec §6.
    selected_facts.sort_by(|a, b| (&a.entity, &a.key, &a.fact_id).cmp(&(&b.entity, &b.key, &b.fact_id)));

    let mut sections: Vec<StableSection> = Vec::new();
    if !selected_facts.is_empty() {
        let est: usize = selected_facts.iter().map(|f| f.est_tokens).sum();
        sections.push(StableSection {
            kind: SectionKind::Facts,
            facts: selected_facts,
            items: Vec::new(),
            est_tokens: est,
        });
    }

    // ---- aux sections, normative order, budget permitting ----
    let mut aux = aux;
    aux.sort_by_key(|s| s.kind.order());
    for section in aux {
        if section.kind == SectionKind::Facts {
            // Facts arrive via the typed path only.
            continue;
        }
        let mut items = section.items;
        items.sort_by(|a, b| a.id.cmp(&b.id));
        let mut kept: Vec<AuxItem> = Vec::new();
        let mut section_dropped = 0usize;
        let mut section_est = 0usize;
        for item in items {
            let est = aux_est_tokens(&item);
            if spent + est > effective_budget {
                section_dropped += 1;
                continue;
            }
            spent += est;
            section_est += est;
            kept.push(item);
        }
        if section_dropped > 0 {
            dropped.push(DroppedReport {
                kind: section.kind,
                count: section_dropped,
                reason: "budget".to_string(),
            });
        }
        if !kept.is_empty() {
            sections.push(StableSection {
                kind: section.kind,
                facts: Vec::new(),
                items: kept,
                est_tokens: section_est,
            });
        }
    }

    let stable = StableRegion {
        bundle_version: BUNDLE_VERSION.to_string(),
        sections,
    };
    let stable_hash = hash_stable_region(&stable);

    ContextBundle {
        stable,
        stable_hash,
        actor: req.actor.clone(),
        tenant_id: req.tenant_id.clone(),
        session_id: req.session_id.clone(),
        assembled_at_ms: req.now_ms,
        budget: BudgetReport {
            requested: req.requested_budget,
            ceiling: req.ceiling,
            spent_est: spent,
            dropped,
        },
    }
}

/// Canonical stable-region bytes: serde_json over the struct (field order
/// fixed by struct definition; vectors pre-sorted by the assembler).
// expect: serde_json over a plain derive(Serialize) struct (no maps with
// non-string keys, no fallible custom impls) cannot fail; a default-empty
// fallback would silently corrupt the stable hash, so assert instead.
#[allow(clippy::expect_used)]
pub fn stable_region_bytes(stable: &StableRegion) -> Vec<u8> {
    serde_json::to_vec(stable).expect("stable region serializes")
}

/// `blake3:<hex>` of the canonical stable-region bytes.
pub fn hash_stable_region(stable: &StableRegion) -> String {
    let bytes = stable_region_bytes(stable);
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

// ---------------------------------------------------------------------------
// Renderers (spec §7). Parity obligation: the stable-region content is the
// same across renderers; volatile material always trails.
// ---------------------------------------------------------------------------

/// Markdown renderer — the boot-banner shape. Stable region first
/// (prompt prefix), volatile trailer last.
pub fn render_markdown(bundle: &ContextBundle) -> String {
    let mut out = render_markdown_stable(&bundle.stable);
    let _ = writeln!(
        out,
        "\n---\n_volatile: assembled_at_ms={} actor={} tenant={} session={} budget {}/{} (ceiling {}) hash={}_",
        bundle.assembled_at_ms,
        bundle.actor,
        bundle.tenant_id,
        bundle.session_id.as_deref().unwrap_or("-"),
        bundle.budget.spent_est,
        bundle.budget.requested,
        bundle.budget.ceiling,
        bundle.stable_hash,
    );
    out
}

/// The stable (cacheable) markdown prefix only — shared verbatim by the
/// markdown and openai-messages renderers.
pub fn render_markdown_stable(stable: &StableRegion) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "## Crux Context ({})", stable.bundle_version);
    for section in &stable.sections {
        let _ = writeln!(out, "\n### {}", section.kind.as_str());
        if !section.facts.is_empty() {
            out.push_str("| entity | key | value | conf | freshness |\n|---|---|---|---|---|\n");
            for f in &section.facts {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {:.2} | {} |",
                    md_cell(&f.entity),
                    md_cell(&f.key),
                    md_cell(&f.value),
                    f.confidence,
                    f.freshness.as_str(),
                );
            }
        }
        for item in &section.items {
            let _ = writeln!(out, "- **{}** — {}", md_cell(&item.id), md_cell(&item.text));
        }
    }
    out
}

fn md_cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

/// JSON renderer — the full bundle shape verbatim.
// expect: same rationale as stable_region_bytes — plain derive(Serialize)
// over the bundle cannot fail.
#[allow(clippy::expect_used)]
pub fn render_json(bundle: &ContextBundle) -> String {
    serde_json::to_string(bundle).expect("bundle serializes")
}

/// OpenAI-messages fragment: one system message carrying the stable
/// markdown prefix; volatile metadata in a sibling field, never inside the
/// message content (spec §7.3).
pub fn render_openai_messages(bundle: &ContextBundle) -> serde_json::Value {
    serde_json::json!({
        "messages": [
            {"role": "system", "content": render_markdown_stable(&bundle.stable)}
        ],
        "crux_context": {
            "bundle_version": bundle.stable.bundle_version,
            "stable_hash": bundle.stable_hash,
            "assembled_at_ms": bundle.assembled_at_ms,
            "budget": bundle.budget,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR_MS: i64 = 3_600_000;

    fn req(now_ms: i64, budget: usize) -> BundleRequest {
        BundleRequest {
            actor: "passport:alpha".to_string(),
            tenant_id: "work".to_string(),
            session_id: Some("s-1".to_string()),
            requested_budget: budget,
            ceiling: FREE_TIER_CEILING,
            now_ms,
            policy: DecayPolicy::default(),
        }
    }

    fn fact(id: &str, entity: &str, key: &str, value: &str) -> FactInput {
        FactInput {
            fact_id: id.to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            confidence: 0.9,
            written_ms: 0,
            horizon_class: HorizonClass::None,
            version: 1,
            superseded: false,
            private: false,
            owner: None,
            est_tokens: Some(20),
            addressed: false,
        }
    }

    #[test]
    fn byte_stability_repeated_assembly() {
        let inputs = || {
            vec![
                fact("f2", "execplan:x", "gate:M1", "passed"),
                fact("f1", "bench:lme", "baseline", "89.3"),
            ]
        };
        let r = req(HOUR_MS, 2000);
        let a = assemble(&r, inputs(), vec![]);
        let b = assemble(&r, inputs(), vec![]);
        assert_eq!(stable_region_bytes(&a.stable), stable_region_bytes(&b.stable));
        assert_eq!(a.stable_hash, b.stable_hash);
    }

    #[test]
    fn volatile_fields_do_not_move_the_hash() {
        // Two assemblies at different times (same freshness class for all
        // items: HorizonClass::None never decays) → different assembled_at,
        // identical stable hash.
        let inputs = || vec![fact("f1", "e", "k", "v")];
        let a = assemble(&req(HOUR_MS, 2000), inputs(), vec![]);
        let b = assemble(&req(HOUR_MS * 500, 2000), inputs(), vec![]);
        assert_ne!(a.assembled_at_ms, b.assembled_at_ms);
        assert_eq!(a.stable_hash, b.stable_hash);
        // And the hash genuinely covers the stable bytes.
        assert_eq!(a.stable_hash, hash_stable_region(&a.stable));
    }

    #[test]
    fn presentation_order_independent_of_input_order() {
        let r = req(HOUR_MS, 2000);
        let a = assemble(&r, vec![fact("f1", "b", "k", "v"), fact("f2", "a", "k", "v")], vec![]);
        let b = assemble(&r, vec![fact("f2", "a", "k", "v"), fact("f1", "b", "k", "v")], vec![]);
        assert_eq!(a.stable_hash, b.stable_hash);
        let facts = &a.stable.sections[0].facts;
        assert_eq!(facts[0].entity, "a");
        assert_eq!(facts[1].entity, "b");
    }

    #[test]
    fn budget_ceiling_enforced_with_explicit_dropped() {
        let mut r = req(HOUR_MS, 50);
        r.ceiling = 50;
        let inputs = vec![
            fact("f1", "a", "k", "v"),
            fact("f2", "b", "k", "v"),
            fact("f3", "c", "k", "v"),
        ];
        let bundle = assemble(&r, inputs, vec![]);
        assert!(bundle.budget.spent_est <= 50);
        let dropped: usize = bundle.budget.dropped.iter().map(|d| d.count).sum();
        let kept = bundle.stable.sections.first().map(|s| s.facts.len()).unwrap_or(0);
        assert_eq!(kept + dropped, 3);
        assert!(dropped > 0, "truncation must be explicit");
    }

    #[test]
    fn requested_budget_capped_by_ceiling() {
        let mut r = req(HOUR_MS, 1_000_000);
        r.ceiling = 50;
        let bundle = assemble(
            &r,
            vec![
                fact("f1", "a", "k", "v"),
                fact("f2", "b", "k", "v"),
                fact("f3", "c", "k", "v"),
            ],
            vec![],
        );
        assert!(bundle.budget.spent_est <= 50);
    }

    #[test]
    fn superseded_facts_never_enter() {
        let mut dead = fact("f1", "a", "k", "old");
        dead.superseded = true;
        let live = fact("f2", "b", "k", "new");
        let bundle = assemble(&req(HOUR_MS, 2000), vec![dead, live], vec![]);
        let facts = &bundle.stable.sections[0].facts;
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].fact_id, "f2");
    }

    #[test]
    fn latest_version_wins_within_entity_key() {
        let mut v1 = fact("f1", "a", "k", "v1");
        v1.version = 1;
        let mut v2 = fact("f2", "a", "k", "v2");
        v2.version = 2;
        let bundle = assemble(&req(HOUR_MS, 2000), vec![v1, v2], vec![]);
        let facts = &bundle.stable.sections[0].facts;
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].value, "v2");
    }

    #[test]
    fn stale_is_annotated_not_dropped() {
        let mut old = fact("f1", "bench:x", "metric", "408/500");
        old.horizon_class = HorizonClass::Volatile;
        old.written_ms = HOUR_MS; // written_ms must be positive (<=0 means Unknown)
                                  // Far past any volatile horizon.
        let bundle = assemble(&req(HOUR_MS * 24 * 365, 2000), vec![old], vec![]);
        let facts = &bundle.stable.sections[0].facts;
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].freshness, Freshness::Stale);
    }

    #[test]
    fn private_facts_owner_only() {
        let mut mine = fact("f1", "a", "k", "secret-mine");
        mine.private = true;
        mine.owner = Some("passport:alpha".to_string());
        let mut theirs = fact("f2", "b", "k", "secret-theirs");
        theirs.private = true;
        theirs.owner = Some("passport:beta".to_string());
        let bundle = assemble(&req(HOUR_MS, 2000), vec![mine, theirs], vec![]);
        let facts = &bundle.stable.sections[0].facts;
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].fact_id, "f1");
        assert!(!render_json(&bundle).contains("secret-theirs"));
    }

    #[test]
    fn addressed_rows_selected_first_under_budget() {
        let mut r = req(HOUR_MS, 25);
        r.ceiling = 25;
        let mut addressed = fact("f-addr", "execplan:x", "gate:M1", "passed");
        addressed.addressed = true;
        addressed.confidence = 0.1; // low score — would lose a pure ranking
        let ranked = fact("f-rank", "a", "k", "v");
        let bundle = assemble(&r, vec![ranked, addressed], vec![]);
        let facts = &bundle.stable.sections[0].facts;
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].fact_id, "f-addr");
    }

    #[test]
    fn sections_follow_normative_order() {
        let aux = vec![
            AuxSection {
                kind: SectionKind::Coord,
                items: vec![AuxItem {
                    id: "peer-1".into(),
                    text: "editing crates/x".into(),
                    est_tokens: Some(10),
                }],
            },
            AuxSection {
                kind: SectionKind::SessionState,
                items: vec![AuxItem {
                    id: "s-1".into(),
                    text: "resume at M2".into(),
                    est_tokens: Some(10),
                }],
            },
        ];
        let bundle = assemble(&req(HOUR_MS, 2000), vec![fact("f1", "a", "k", "v")], aux);
        let kinds: Vec<&str> = bundle.stable.sections.iter().map(|s| s.kind.as_str()).collect();
        assert_eq!(kinds, vec!["facts", "session_state", "coord"]);
    }

    #[test]
    fn renderer_parity_stable_prefix() {
        let bundle = assemble(&req(HOUR_MS, 2000), vec![fact("f1", "a", "k", "v")], vec![]);
        let md = render_markdown(&bundle);
        let stable_md = render_markdown_stable(&bundle.stable);
        assert!(md.starts_with(&stable_md), "markdown must lead with the stable prefix");
        let openai = render_openai_messages(&bundle);
        assert_eq!(
            openai["messages"][0]["content"].as_str().unwrap(),
            stable_md,
            "openai system content must equal the stable markdown prefix"
        );
        // Volatile material never leaks into the stable prefix.
        assert!(!stable_md.contains("assembled_at"));
        assert!(!stable_md.contains(&bundle.stable_hash));
        // JSON renderer round-trips.
        let parsed: ContextBundle = serde_json::from_str(&render_json(&bundle)).unwrap();
        assert_eq!(parsed.stable_hash, bundle.stable_hash);
    }

    #[test]
    fn markdown_cells_are_escaped() {
        let bundle = assemble(
            &req(HOUR_MS, 2000),
            vec![fact("f1", "a", "k", "pipe | and\nnewline")],
            vec![],
        );
        let md = render_markdown_stable(&bundle.stable);
        assert!(md.contains("pipe \\| and newline"));
    }
}
