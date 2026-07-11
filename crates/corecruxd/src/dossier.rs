// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Agent dossier exchange — Phase 4 of the context graph.
//!
//! A *dossier* is one agent's structured snapshot of "what I currently
//! believe about this project". Other agents (and a future-self of the same
//! agent) consume the dossier to skip work the producer already did. This is
//! the multi-session-drift fix the operator asked for: the agent-native
//! description language that the UI translates back to human-readable views.
//!
//! ## Schema
//!
//! - `claims[]` — explicit statements with confidence (0..1) + evidence list
//! - `uncertainties[]` — known unknowns with best-guess + confidence
//! - `contradictions[]` — places where two claims / signals conflict
//! - `open_questions[]` — what the agent would investigate next
//!
//! ## Two channels for producing a dossier
//!
//! 1. **Auto-generate** (`generate_auto`) — deterministic walk over the
//!    storybook + workspace scan + project graph. Produces high-confidence
//!    claims for things we can prove (members, stubs, file existence) and
//!    medium-confidence INFERRED claims for things derived (vision↔code
//!    mapping, dead-code candidates).
//! 2. **Publish from agent** (`POST /v1/projects/{id}/dossier`) — an external
//!    agent submits its own dossier (typically built by calling `auto` and
//!    layering explicit overrides on top).
//!
//! Reconciliation across agents groups claims by (kind, subject, object) →
//! `agreement` (multiple agents concur), `disagreement` (multiple agents,
//! conflicting object for same subject), or `unique` (only one agent has it).

#![allow(clippy::struct_field_names)] // narrow API; field names are part of the JSON shape contract
#![allow(clippy::unwrap_used)] // .unwrap on data we constructed in the same fn — panic-free by construction

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dossier {
    pub dossier_id: String,
    pub project_id: String,
    pub agent_passport: String,
    pub generated_at_unix_ms: u64,
    /// Anchors so consumers know which underlying state this dossier reflects.
    pub based_on: BasedOn,
    pub claims: Vec<Claim>,
    pub uncertainties: Vec<Uncertainty>,
    pub contradictions: Vec<Contradiction>,
    pub open_questions: Vec<String>,
    pub stats: DossierStats,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BasedOn {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storybook_ts: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_scan_id: Option<String>,
    pub plane_count: usize,
    pub graph_node_count: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DossierStats {
    pub claim_count: usize,
    pub claims_by_kind: BTreeMap<String, usize>,
    pub claims_by_confidence_bucket: BTreeMap<String, usize>, // "high" | "med" | "low"
    pub uncertainty_count: usize,
    pub contradiction_count: usize,
    pub open_question_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Claim {
    pub claim_id: String,
    pub kind: String, // implements / owns / stub / dead_code_likely / member / module_exists / planning_target / vision_set / contradiction_with / ...
    pub subject: String, // canonical id like "plane:plancrux:corecrux"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    pub confidence: f32,
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Uncertainty {
    pub topic: String,
    pub question: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub best_guess: Option<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contradiction {
    pub claim_a: String,
    pub claim_b: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
}

pub struct AutoInput<'a> {
    pub project_id: &'a str,
    pub agent_passport: &'a str,
    pub now_unix_ms: u64,
}

/// Build a dossier deterministically by walking the storybook (if present),
/// the latest workspace scan (if present), and the context graph. No LLM
/// calls — every claim has explicit evidence.
pub fn generate_auto(store: &corecrux_memory::FactStore, input: AutoInput<'_>) -> Option<Dossier> {
    let project = crate::projects::get_project_detail(store, input.project_id)?;
    let planes = crate::planes::list_planes(store, input.project_id);
    let workspace = crate::context_graph::load_latest_workspace_blocking_pub(store);
    let storybook_ts = latest_storybook_ts(store, input.project_id);
    let graph = crate::context_graph::build_for_project_with_opts(
        store,
        input.project_id,
        &crate::context_graph::GraphOptions {
            include_workspace: true,
            include_symbols: false,
        },
    );

    let dossier_id = format!("dsr_{}_{}", input.now_unix_ms, sanitise_id_token(input.agent_passport),);
    let mut d = Dossier {
        dossier_id: dossier_id.clone(),
        project_id: input.project_id.to_string(),
        agent_passport: input.agent_passport.to_string(),
        generated_at_unix_ms: input.now_unix_ms,
        based_on: BasedOn {
            storybook_ts,
            workspace_scan_id: workspace.as_ref().map(|w| w.scan_id.clone()),
            plane_count: planes.len(),
            graph_node_count: graph.nodes.len(),
        },
        claims: Vec::new(),
        uncertainties: Vec::new(),
        contradictions: Vec::new(),
        open_questions: Vec::new(),
        stats: DossierStats::default(),
    };

    let mut claim_seq = 0u64;
    let mut next_claim_id = || {
        claim_seq += 1;
        format!("{dossier_id}#cl{claim_seq:03}")
    };

    // ── Project membership claims (extracted, conf 1.0) ────────────────
    for m in &project.members {
        d.claims.push(Claim {
            claim_id: next_claim_id(),
            kind: "owns".into(),
            subject: format!("passport:{}", m.passport_id),
            object: Some(format!("project:{}", project.record.id)),
            confidence: 1.0,
            evidence: vec![format!("project_member_record(role={})", m.role)],
            rationale: None,
        });
    }
    if let Some(target) = project.record.planning_target.as_deref() {
        d.claims.push(Claim {
            claim_id: next_claim_id(),
            kind: "planning_target".into(),
            subject: format!("project:{}", project.record.id),
            object: Some(target.to_string()),
            confidence: 1.0,
            evidence: vec!["project_record".into()],
            rationale: None,
        });
    }

    // ── Plane membership + plane→crate mapping ────────────────────────
    for plane in &planes {
        let plane_subject = format!("plane:{}:{}", input.project_id, plane.id);
        d.claims.push(Claim {
            claim_id: next_claim_id(),
            kind: "plane_exists".into(),
            subject: plane_subject.clone(),
            object: Some(format!("project:{}", project.record.id)),
            confidence: 1.0,
            evidence: vec!["plane_record".into()],
            rationale: None,
        });
        let plane_layers = read_plane_layers(store, input.project_id, &plane.id);
        if plane_layers.contains_key("vision") {
            d.claims.push(Claim {
                claim_id: next_claim_id(),
                kind: "vision_set".into(),
                subject: plane_subject.clone(),
                object: None,
                confidence: 1.0,
                evidence: vec![format!("__plane_layer__::{}::{}::vision", input.project_id, plane.id)],
                rationale: None,
            });
        } else {
            d.uncertainties.push(Uncertainty {
                topic: plane.id.clone(),
                question: format!("What is the canonical vision for plane '{}'?", plane.id),
                best_guess: None,
                confidence: 0.0,
            });
        }
        for m in crate::planes::list_members(store, input.project_id, &plane.id) {
            d.claims.push(Claim {
                claim_id: next_claim_id(),
                kind: "owns".into(),
                subject: format!("passport:{}", m.passport_id),
                object: Some(plane_subject.clone()),
                confidence: 1.0,
                evidence: vec![format!("plane_member_record(role={})", m.role)],
                rationale: None,
            });
        }
        for t in crate::planes::list_tenants(store, input.project_id, &plane.id) {
            d.claims.push(Claim {
                claim_id: next_claim_id(),
                kind: "binds_tenant".into(),
                subject: plane_subject.clone(),
                object: Some(format!("tenant:{}", t.tenant_id)),
                confidence: 1.0,
                evidence: vec!["plane_tenant_record".into()],
                rationale: None,
            });
        }

        // Inferred plane→crate from storybook keyword overlap. If storybook
        // wasn't generated, derive on the fly.
        if let Some(ws) = &workspace {
            let pool_text = build_plane_text_pool(plane, &plane_layers);
            let plane_kws = crate::storybook::extract_keywords_pub(&pool_text);
            let candidates = crate::storybook::match_plane_to_modules_pub(&plane_kws, ws);
            for cname in candidates {
                d.claims.push(Claim {
                    claim_id: next_claim_id(),
                    kind: "implements".into(),
                    subject: plane_subject.clone(),
                    object: Some(format!("module:{cname}")),
                    confidence: 0.55,
                    evidence: vec![
                        "keyword_overlap_coefficient_>=0.30".into(),
                        format!("workspace_scan({})", ws.scan_id),
                    ],
                    rationale: Some("inferred from plane vision-text overlap with crate identity tokens".into()),
                });
            }
        }
    }

    // ── Stubs (extracted, conf 1.0 for the existence; the concept of "stub" itself is the inference) ─
    if let Some(ws) = &workspace {
        for stub in &ws.stubs {
            d.claims.push(Claim {
                claim_id: next_claim_id(),
                kind: "stub".into(),
                subject: format!("file:{}:{}", stub.file_rel_path, stub.line),
                object: None,
                confidence: 0.95,
                evidence: vec![
                    format!("stub_kind={}", stub.kind),
                    format!("workspace_scan({})", ws.scan_id),
                ],
                rationale: Some(stub.snippet.clone()),
            });
        }
        // Dead-code candidates as inferred claims with the scanner's own
        // confidence (currently 0.6 with a warning).
        for dc in &ws.dead_code {
            d.claims.push(Claim {
                claim_id: next_claim_id(),
                kind: "dead_code_likely".into(),
                subject: format!("symbol:{}:{}", dc.file_rel_path, dc.line),
                object: None,
                confidence: dc.confidence,
                evidence: vec![
                    format!("regex_zero_references_in_workspace({})", dc.name),
                    format!("workspace_scan({})", ws.scan_id),
                ],
                rationale: Some(dc.note.clone()),
            });
        }
    }

    // ── Open questions: structural gaps that future work could close ──
    if workspace.is_none() {
        d.open_questions
            .push("No workspace scan present. POST /v1/workspace/scan to enable workspace-aware claims.".into());
    }
    if storybook_ts.is_none() {
        d.open_questions.push(
            "No storybook readout yet. POST /v1/projects/{id}/storybook to anchor the dossier to a narrative.".into(),
        );
    }
    let planes_no_vision = planes
        .iter()
        .filter(|p| {
            let pl = read_plane_layers(store, input.project_id, &p.id);
            !pl.contains_key("vision")
        })
        .count();
    if planes_no_vision > 0 {
        d.open_questions.push(format!(
            "{planes_no_vision} planes have no vision layer. Run POST /v1/projects/{}/planes/sync-layers to import from a mounted source.",
            input.project_id
        ));
    }

    // ── Stats roll-up ──────────────────────────────────────────────────
    d.stats = compute_stats(
        &d.claims,
        d.uncertainties.len(),
        d.contradictions.len(),
        d.open_questions.len(),
    );
    Some(d)
}

fn compute_stats(claims: &[Claim], uncert: usize, contr: usize, open: usize) -> DossierStats {
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_conf: BTreeMap<String, usize> = BTreeMap::new();
    for c in claims {
        *by_kind.entry(c.kind.clone()).or_insert(0) += 1;
        let bucket = if c.confidence >= 0.85 {
            "high"
        } else if c.confidence >= 0.50 {
            "med"
        } else {
            "low"
        };
        *by_conf.entry(bucket.to_string()).or_insert(0) += 1;
    }
    DossierStats {
        claim_count: claims.len(),
        claims_by_kind: by_kind,
        claims_by_confidence_bucket: by_conf,
        uncertainty_count: uncert,
        contradiction_count: contr,
        open_question_count: open,
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DossierDiff {
    pub from_dossier_id: String,
    pub to_dossier_id: String,
    pub added_claims: Vec<Claim>,
    pub removed_claims: Vec<Claim>,
    pub confidence_changes: Vec<ClaimConfidenceChange>,
    pub stats_delta: DossierStatsDelta,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClaimConfidenceChange {
    pub kind: String,
    pub subject: String,
    pub object: Option<String>,
    pub from_confidence: f32,
    pub to_confidence: f32,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DossierStatsDelta {
    pub claim_delta: i64,
    pub uncertainty_delta: i64,
    pub open_question_delta: i64,
}

pub fn diff_dossiers(a: &Dossier, b: &Dossier) -> DossierDiff {
    let key = |c: &Claim| (c.kind.clone(), c.subject.clone(), c.object.clone());
    let a_index: BTreeMap<_, &Claim> = a.claims.iter().map(|c| (key(c), c)).collect();
    let b_index: BTreeMap<_, &Claim> = b.claims.iter().map(|c| (key(c), c)).collect();

    let added: Vec<Claim> = b
        .claims
        .iter()
        .filter(|c| !a_index.contains_key(&key(c)))
        .cloned()
        .collect();
    let removed: Vec<Claim> = a
        .claims
        .iter()
        .filter(|c| !b_index.contains_key(&key(c)))
        .cloned()
        .collect();
    let mut conf_changes: Vec<ClaimConfidenceChange> = Vec::new();
    for (k, ac) in &a_index {
        if let Some(bc) = b_index.get(k) {
            if (ac.confidence - bc.confidence).abs() > 0.001 {
                conf_changes.push(ClaimConfidenceChange {
                    kind: ac.kind.clone(),
                    subject: ac.subject.clone(),
                    object: ac.object.clone(),
                    from_confidence: ac.confidence,
                    to_confidence: bc.confidence,
                });
            }
        }
    }

    DossierDiff {
        from_dossier_id: a.dossier_id.clone(),
        to_dossier_id: b.dossier_id.clone(),
        added_claims: added,
        removed_claims: removed,
        confidence_changes: conf_changes,
        stats_delta: DossierStatsDelta {
            claim_delta: (b.claims.len() as i64) - (a.claims.len() as i64),
            uncertainty_delta: (b.uncertainties.len() as i64) - (a.uncertainties.len() as i64),
            open_question_delta: (b.open_questions.len() as i64) - (a.open_questions.len() as i64),
        },
    }
}

// ── Reconciliation across all dossiers for a project ─────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ReconciliationReport {
    pub project_id: String,
    pub generated_at_unix_ms: u64,
    pub dossier_count: usize,
    pub agents: Vec<String>,
    pub agreement: Vec<ReconciledClaim>,
    pub disagreement: Vec<DisagreementGroup>,
    pub unique: Vec<UniqueClaim>,
    pub stats: ReconciliationStats,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ReconciliationStats {
    pub agreement_count: usize,
    pub disagreement_count: usize,
    pub unique_count: usize,
    pub total_distinct_subjects: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReconciledClaim {
    pub kind: String,
    pub subject: String,
    pub object: Option<String>,
    pub agreed_by_agents: Vec<String>,
    pub max_confidence: f32,
    pub avg_confidence: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisagreementGroup {
    pub kind: String,
    pub subject: String,
    /// Each variant: object → list of (agent, confidence) supporting it.
    pub variants: Vec<DisagreementVariant>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DisagreementVariant {
    pub object: Option<String>,
    pub agents: Vec<String>,
    pub max_confidence: f32,
}

#[derive(Debug, Clone, Serialize)]
pub struct UniqueClaim {
    pub kind: String,
    pub subject: String,
    pub object: Option<String>,
    pub by_agent: String,
    pub confidence: f32,
}

pub fn reconcile(dossiers: &[Dossier], now_unix_ms: u64) -> ReconciliationReport {
    if dossiers.is_empty() {
        return ReconciliationReport {
            project_id: String::new(),
            generated_at_unix_ms: now_unix_ms,
            dossier_count: 0,
            agents: vec![],
            agreement: vec![],
            disagreement: vec![],
            unique: vec![],
            stats: Default::default(),
        };
    }
    let project_id = dossiers[0].project_id.clone();
    let agents: Vec<String> = dossiers.iter().map(|d| d.agent_passport.clone()).collect();
    let agents_distinct: BTreeSet<String> = agents.iter().cloned().collect();

    // Each logical claim is a (kind, subject, object) triple. A claim
    // is `agreement` when multiple agents independently assert the SAME
    // triple; `unique` when only one agent does. Disagreement is a separate,
    // computed signal: for any (kind, subject) where the set of objects
    // claimed differs between agents (e.g., agent-A says implements:{X,Y};
    // agent-B says implements:{X,W}), surface the asymmetric objects.
    type TripleKey = (String, String, Option<String>);
    let mut by_triple: BTreeMap<TripleKey, Vec<(String, &Claim)>> = BTreeMap::new();
    for d in dossiers {
        for c in &d.claims {
            by_triple
                .entry((c.kind.clone(), c.subject.clone(), c.object.clone()))
                .or_default()
                .push((d.agent_passport.clone(), c));
        }
    }

    let mut agreement: Vec<ReconciledClaim> = Vec::new();
    let mut unique: Vec<UniqueClaim> = Vec::new();

    // Map (kind, subject) → set of agents who asserted *some* object for it,
    // and per-agent set of objects they asserted. Used to compute the
    // disagreement set below.
    type SubjectKey = (String, String);
    let mut per_agent_objects: BTreeMap<SubjectKey, BTreeMap<String, BTreeSet<Option<String>>>> = BTreeMap::new();
    let mut max_conf_for: BTreeMap<TripleKey, f32> = BTreeMap::new();

    for ((kind, subject, object), entries) in &by_triple {
        let agents: BTreeSet<String> = entries.iter().map(|(a, _)| a.clone()).collect();
        let max_c = entries.iter().map(|(_, c)| c.confidence).fold(0.0_f32, f32::max);
        max_conf_for.insert((kind.clone(), subject.clone(), object.clone()), max_c);
        for (agent, _) in entries {
            per_agent_objects
                .entry((kind.clone(), subject.clone()))
                .or_default()
                .entry(agent.clone())
                .or_default()
                .insert(object.clone());
        }
        if agents.len() >= 2 {
            let avg_c = entries.iter().map(|(_, c)| c.confidence).sum::<f32>() / entries.len() as f32;
            agreement.push(ReconciledClaim {
                kind: kind.clone(),
                subject: subject.clone(),
                object: object.clone(),
                agreed_by_agents: agents.into_iter().collect(),
                max_confidence: max_c,
                avg_confidence: avg_c,
            });
        } else {
            let (agent, claim) = entries.iter().next().unwrap();
            unique.push(UniqueClaim {
                kind: kind.clone(),
                subject: subject.clone(),
                object: object.clone(),
                by_agent: agent.clone(),
                confidence: claim.confidence,
            });
        }
    }

    // Disagreement: for each (kind, subject) where >= 2 agents asserted but
    // the per-agent object sets differ, surface the *symmetric difference*
    // (objects only one agent claimed).
    let mut disagreement: Vec<DisagreementGroup> = Vec::new();
    for ((kind, subject), agent_to_objs) in &per_agent_objects {
        if agent_to_objs.len() < 2 {
            continue;
        }
        // Compute objects that aren't asserted by every agent.
        let all_objects: BTreeSet<Option<String>> = agent_to_objs.values().flatten().cloned().collect();
        let agreed_objects: BTreeSet<Option<String>> = all_objects
            .iter()
            .filter(|obj| agent_to_objs.values().all(|set| set.contains(*obj)))
            .cloned()
            .collect();
        let asymmetric: BTreeSet<Option<String>> = all_objects.difference(&agreed_objects).cloned().collect();
        if asymmetric.is_empty() {
            continue;
        }
        let mut variants: Vec<DisagreementVariant> = Vec::new();
        for object in &asymmetric {
            let supporting: BTreeSet<String> = agent_to_objs
                .iter()
                .filter(|(_, set)| set.contains(object))
                .map(|(agent, _)| agent.clone())
                .collect();
            let max_c = max_conf_for
                .get(&(kind.clone(), subject.clone(), object.clone()))
                .copied()
                .unwrap_or(0.0);
            variants.push(DisagreementVariant {
                object: object.clone(),
                agents: supporting.into_iter().collect(),
                max_confidence: max_c,
            });
        }
        disagreement.push(DisagreementGroup {
            kind: kind.clone(),
            subject: subject.clone(),
            variants,
        });
    }

    let stats = ReconciliationStats {
        agreement_count: agreement.len(),
        disagreement_count: disagreement.len(),
        unique_count: unique.len(),
        total_distinct_subjects: per_agent_objects.len(),
    };

    ReconciliationReport {
        project_id,
        generated_at_unix_ms: now_unix_ms,
        dossier_count: dossiers.len(),
        agents: agents_distinct.into_iter().collect(),
        agreement,
        disagreement,
        unique,
        stats,
    }
}

// ────────────────────────── Helpers ──────────────────────────

fn read_plane_layers(store: &corecrux_memory::FactStore, project_id: &str, plane_id: &str) -> BTreeMap<String, String> {
    let prefix = format!("__plane_layer__::{project_id}::{plane_id}::");
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
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

fn build_plane_text_pool(plane: &crate::planes::PlaneRecord, plane_layers: &BTreeMap<String, String>) -> String {
    let mut pool = String::new();
    pool.push_str(&plane.id);
    pool.push(' ');
    pool.push_str(&plane.name);
    pool.push(' ');
    if let Some(d) = &plane.description {
        pool.push_str(d);
        pool.push(' ');
    }
    if let Some(v) = plane_layers.get("vision") {
        pool.push_str(v);
    }
    pool
}

fn latest_storybook_ts(store: &corecrux_memory::FactStore, project_id: &str) -> Option<u64> {
    let prefix = format!("__storybook__::{project_id}::");
    let result = store.query(&corecrux_memory::fact_store::FactQuery {
        tenant_hash: None,
        query: Some(prefix.clone()),
        entity: None,
        entity_prefix: None,
        top_k: 100,
        token_budget: None,
    });
    let latest = crate::fact_helpers::dedup_latest(result.facts);
    let mut tss: Vec<u64> = latest
        .into_iter()
        .filter(|f| f.entity.starts_with(&prefix) && f.key == "content" && !f.value.is_empty())
        .filter_map(|f| f.entity[prefix.len()..].parse::<u64>().ok())
        .collect();
    tss.sort_by(|a, b| b.cmp(a));
    tss.into_iter().next()
}

fn sanitise_id_token(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(kind: &str, subject: &str, object: Option<&str>, confidence: f32) -> Claim {
        Claim {
            claim_id: format!("test_{}_{}", kind, subject),
            kind: kind.to_string(),
            subject: subject.to_string(),
            object: object.map(String::from),
            confidence,
            evidence: vec![],
            rationale: None,
        }
    }

    fn make_dossier(agent: &str, claims: Vec<Claim>) -> Dossier {
        let stats = compute_stats(&claims, 0, 0, 0);
        Dossier {
            dossier_id: format!("dsr_{agent}"),
            project_id: "p".into(),
            agent_passport: agent.into(),
            generated_at_unix_ms: 1_000,
            based_on: BasedOn::default(),
            claims,
            uncertainties: vec![],
            contradictions: vec![],
            open_questions: vec![],
            stats,
        }
    }

    #[test]
    fn reconcile_identifies_agreement_when_two_agents_concur() {
        let a = make_dossier("alpha", vec![claim("implements", "plane:p:x", Some("module:foo"), 0.8)]);
        let b = make_dossier("beta", vec![claim("implements", "plane:p:x", Some("module:foo"), 0.9)]);
        let r = reconcile(&[a, b], 2_000);
        assert_eq!(r.agreement.len(), 1);
        assert_eq!(r.agreement[0].agreed_by_agents.len(), 2);
        assert!((r.agreement[0].max_confidence - 0.9).abs() < 0.001);
        assert_eq!(r.disagreement.len(), 0);
        assert_eq!(r.unique.len(), 0);
    }

    #[test]
    fn reconcile_identifies_disagreement_when_objects_differ() {
        let a = make_dossier("alpha", vec![claim("implements", "plane:p:x", Some("module:foo"), 0.8)]);
        let b = make_dossier("beta", vec![claim("implements", "plane:p:x", Some("module:bar"), 0.7)]);
        let r = reconcile(&[a, b], 2_000);
        // Each (kind, subject, object) is a logical claim; since neither
        // overlaps, both become `unique`. The disagreement group is a
        // *separate* signal: same (kind, subject), differing object SETS.
        assert_eq!(r.agreement.len(), 0);
        assert_eq!(r.unique.len(), 2);
        assert_eq!(r.disagreement.len(), 1);
        assert_eq!(r.disagreement[0].variants.len(), 2);
    }

    #[test]
    fn reconcile_partial_overlap_detects_only_asymmetric_objects() {
        // alpha: implements x → {foo, bar}; beta: implements x → {foo, baz}.
        // foo is agreed; bar + baz each unique to one agent and surface as
        // a single disagreement group with 2 asymmetric variants.
        let a = make_dossier(
            "alpha",
            vec![
                claim("implements", "plane:p:x", Some("module:foo"), 0.8),
                claim("implements", "plane:p:x", Some("module:bar"), 0.6),
            ],
        );
        let b = make_dossier(
            "beta",
            vec![
                claim("implements", "plane:p:x", Some("module:foo"), 0.9),
                claim("implements", "plane:p:x", Some("module:baz"), 0.7),
            ],
        );
        let r = reconcile(&[a, b], 1);
        assert_eq!(r.agreement.len(), 1, "agreement on foo expected");
        assert_eq!(r.agreement[0].object.as_deref(), Some("module:foo"));
        assert_eq!(r.unique.len(), 2, "bar + baz are each unique");
        assert_eq!(r.disagreement.len(), 1);
        assert_eq!(r.disagreement[0].variants.len(), 2);
        // Variants must NOT include foo (which is agreed).
        let var_objects: BTreeSet<Option<String>> =
            r.disagreement[0].variants.iter().map(|v| v.object.clone()).collect();
        assert!(!var_objects.contains(&Some("module:foo".to_string())));
    }

    #[test]
    fn reconcile_marks_single_agent_claim_as_unique() {
        let a = make_dossier(
            "alpha",
            vec![
                claim("stub", "file:foo.rs:42", None, 0.95),
                claim("implements", "plane:p:x", Some("module:foo"), 0.8),
            ],
        );
        let b = make_dossier("beta", vec![claim("implements", "plane:p:x", Some("module:foo"), 0.8)]);
        let r = reconcile(&[a, b], 2_000);
        assert_eq!(r.agreement.len(), 1);
        assert_eq!(r.unique.len(), 1);
        assert_eq!(r.unique[0].subject, "file:foo.rs:42");
        assert_eq!(r.unique[0].by_agent, "alpha");
    }

    #[test]
    fn diff_finds_added_removed_and_confidence_changes() {
        let a = make_dossier(
            "a",
            vec![
                claim("stub", "f:1", None, 0.9),
                claim("implements", "p:x", Some("m:foo"), 0.8),
            ],
        );
        let b = make_dossier(
            "a",
            vec![
                claim("stub", "f:1", None, 0.9),                 // same
                claim("implements", "p:x", Some("m:foo"), 0.95), // confidence ↑
                claim("dead_code_likely", "s:1", None, 0.6),     // added
            ],
        );
        let d = diff_dossiers(&a, &b);
        assert_eq!(d.added_claims.len(), 1);
        assert_eq!(d.added_claims[0].kind, "dead_code_likely");
        assert_eq!(d.removed_claims.len(), 0);
        assert_eq!(d.confidence_changes.len(), 1);
        assert_eq!(d.stats_delta.claim_delta, 1);
    }

    #[test]
    fn confidence_buckets_split_at_85_and_50() {
        let claims = vec![
            claim("a", "1", None, 0.95),
            claim("a", "2", None, 0.85),
            claim("a", "3", None, 0.6),
            claim("a", "4", None, 0.4),
        ];
        let s = compute_stats(&claims, 0, 0, 0);
        assert_eq!(*s.claims_by_confidence_bucket.get("high").unwrap(), 2);
        assert_eq!(*s.claims_by_confidence_bucket.get("med").unwrap(), 1);
        assert_eq!(*s.claims_by_confidence_bucket.get("low").unwrap(), 1);
    }
}
