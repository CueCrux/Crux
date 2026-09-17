// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Curated memory tier and the always-loaded memory digest.
//!
//! ExecPlan `crux-memory-parity-and-codex-bridge-2026-09-17`, **M2**
//! ("curated tier populated") and **M3** ("digest delivered to both
//! harnesses").
//!
//! ## Why this exists
//!
//! Measured on corpus `drivew-host-memory-gold-v1` (84 curated harness-native
//! memories plus 14 real topic searches, read 2026-09-17): the daemon held
//! ~14,800 facts against the native store's 84 files, and recovered a
//! distinctive-term recall of 0.327 with zero honest misses in 98 queries. The
//! native store wins for one structural reason — **its index is in context
//! every session and never needs a tool call**. This module builds the
//! daemon's equivalent:
//!
//! 1. [`seed_engrams`] turns the harness-native memory projection into engrams,
//!    one per memory, description-first and body-free.
//! 2. [`distill_proposals`] proposes further engrams from the fact store.
//!    **Proposals only.** Each carries the `fact_id` and date it came from, and
//!    an operator accepts them; nothing is auto-promoted, because the whole
//!    point of the tier is curation.
//! 3. [`render_digest`] renders the catalog as one line per entry, under a hard
//!    token budget, byte-stably.
//!
//! ## Byte-stability is the load-bearing property
//!
//! The digest is prompt-prefix content in `CLAUDE.md` and `AGENTS.md`. Cached
//! prefix bytes are cheap; churning ones are re-billed at write price on every
//! session. [`render_digest`] is therefore a pure function of `(catalog,
//! budget)`: ordering is total, no timestamp, no run count and no "generated
//! at" line enters the output, and the identity written into the body is the
//! catalog's `manifest_hash`. Two renders of an unchanged catalog are
//! byte-identical, and `digest_render_is_byte_stable` pins that.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use corecrux_memory::engrams::{
    build_engram_manifest, squeeze_whitespace, validate_local_engram, LocalEngram, ENGRAM_ENTITY_PREFIX,
};
use corecrux_projections::native_memory::{redact_secret_shaped, NativeMemoryIngestV1};

use crate::memory::MemoryFact;

/// Hard ceiling for the rendered digest, in estimated tokens. The harness-native
/// index it replaces is 19,284 bytes (~4,800 tokens by the same estimator) on
/// corpus `drivew-host-memory-gold-v1`; the digest has to carry comparable
/// coverage for a quarter of that.
pub const DIGEST_TOKEN_BUDGET: usize = 2_000;

/// Workspace-relative path the wizard reads the rendered digest fragment from.
pub const DIGEST_FRAGMENT_PATH: &str = ".crux/memory-digest.md";

/// Every engram this module mints is `v1`; a later revision of the seeding
/// rules mints `v2` rather than silently changing what `v1` means.
pub const ENGRAM_VERSION: &str = "v1";

/// Catalog size band from the plan's constraints: the harness-native store's
/// order of magnitude, not the fact store's.
pub const CATALOG_MIN_ENTRIES: usize = 100;
/// Upper end of the same band.
pub const CATALOG_MAX_ENTRIES: usize = 250;

/// Descending ladder of per-entry description allowances, in characters. The
/// renderer takes the **first** rung whose full render fits the budget, so the
/// chosen rung is a pure function of the catalog and the budget. A ladder
/// rather than a computed division because a computed allowance would move by
/// one character whenever any description changed length, and every entry's
/// line would then re-wrap — exactly the prefix churn the digest exists to
/// avoid.
const ALLOWANCE_LADDER: &[usize] = &[
    240, 200, 170, 150, 130, 115, 100, 90, 80, 72, 64, 56, 48, 42, 36, 30, 24, 18,
];

/// Tenant and capability class the digest's `manifest_hash` is computed under.
/// Fixed so the identity depends on the catalog alone.
const DIGEST_TENANT: &str = "digest";
const DIGEST_CAPABILITY_CLASS: &str = "capable";

/// Estimated tokens for `text`, as `ceil(chars / 4)`.
///
/// Deliberately the same crude estimator the recall harness
/// (`07-recall-bench.py`) uses, so the budget here and the measurement there
/// are the same number. It is conservative for prose and optimistic for the
/// hyphenated slugs that dominate the digest, which is the direction that
/// matters: the budget is a ceiling, not a target.
pub fn estimate_tokens(text: &str) -> usize {
    text.chars().count().div_ceil(4)
}

// ── Intent buckets ───────────────────────────────────────────────────────────

/// Bucket an engram from its `MEMORY.md` group heading, falling back to the
/// frontmatter `metadata.type` and then to `unfiled`.
///
/// The result satisfies the engram identifier rules (ASCII alphanumerics plus
/// `-_.:`), so a group heading with punctuation — `Retired / archived — do NOT
/// target` — still yields a usable bucket.
pub fn intent_bucket(group: Option<&str>, memory_type: Option<&str>) -> String {
    for candidate in [group, memory_type] {
        let Some(raw) = candidate.map(str::trim).filter(|s| !s.is_empty()) else {
            continue;
        };
        let bucket = sanitise_bucket(raw);
        if !bucket.is_empty() {
            return bucket;
        }
    }
    "unfiled".to_string()
}

fn sanitise_bucket(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut pending_sep = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            if pending_sep && !out.is_empty() {
                out.push('_');
            }
            pending_sep = false;
            out.extend(ch.to_lowercase());
        } else {
            pending_sep = true;
        }
        if out.len() >= 48 {
            break;
        }
    }
    out.trim_matches('_').to_string()
}

/// Reduce an arbitrary string to a valid engram name, or `None` when nothing
/// usable survives.
pub fn sanitise_name(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut pending_sep = false;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            if pending_sep && !out.is_empty() {
                out.push('-');
            }
            pending_sep = false;
            out.extend(ch.to_lowercase());
        } else {
            pending_sep = true;
        }
        if out.len() >= 120 {
            break;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    (!trimmed.is_empty()).then_some(trimmed)
}

// ── M2a: seed the catalog from the harness-native memory store ───────────────

/// Turn the read-only native-memory projection into seed engrams — one per
/// memory, in slug order.
///
/// The frontmatter `description` becomes the recall line; the `MEMORY.md` group
/// (falling back to `metadata.type`) becomes the intent bucket; the
/// `[[wikilinks]]` become relations. **The body is not copied.** Per the
/// workspace memory-practices rule the memory file *is* the body, so `content`
/// carries the description, a `memory_md_ref` pointer and the link graph, and
/// an agent that wants the prose opens the file.
///
/// Memories with no `description:` are skipped rather than given a fabricated
/// one: the M2 gate requires every catalog entry to carry a real recall line,
/// and inventing one would be the failure this tier exists to prevent.
pub fn seed_engrams(ingest: &NativeMemoryIngestV1, created_at_unix_ms: u64) -> Vec<LocalEngram> {
    let mut out = Vec::new();
    for entry in ingest.entries.values() {
        let Some(name) = sanitise_name(&entry.slug) else {
            continue;
        };
        let description = squeeze_whitespace(&entry.description);
        if description.is_empty() {
            continue;
        }
        let mut content = String::new();
        content.push_str(&description);
        content.push('\n');
        // `writeln!` into a String is infallible; the Results are discarded
        // deliberately rather than unwrapped.
        let _ = writeln!(content, "memory_md_ref: {}", entry.file_name);
        if let Some(group) = entry.group.as_deref() {
            let _ = writeln!(content, "group: {group}");
        }
        if let Some(hook) = entry
            .index_hook
            .as_deref()
            .map(squeeze_whitespace)
            .filter(|h| !h.is_empty())
        {
            let _ = writeln!(content, "index_hook: {hook}");
        }
        if !entry.links.is_empty() {
            let _ = writeln!(content, "links: {}", entry.links.join(", "));
        }
        if let Some(modified) = entry.modified.as_deref() {
            let _ = writeln!(content, "modified: {modified}");
        }
        let (content, _) = redact_secret_shaped(&content);
        let engram = LocalEngram {
            id: format!("eng_seed_{}", short_hash(&name)),
            name,
            version: ENGRAM_VERSION.to_string(),
            intent_bucket: intent_bucket(entry.group.as_deref(), entry.memory_type.as_deref()),
            query_pattern: None,
            description: Some(clip_to_single_line(&description)),
            source_fact_id: None,
            source_fact_date: None,
            content,
            applicable_why: Some(format!(
                "Seeded from the harness-native memory store ({}); the memory file is the body.",
                entry.file_name
            )),
            capability_class_min: None,
            capability_class_max: None,
            generated_class: Some("native_memory_seed".to_string()),
            source_chunk_hashes: Vec::new(),
            source_chunk_set_hash: Some(entry.content_hash.clone()),
            inherited_reason: Some("native_memory_seed".to_string()),
            policy_hash: None,
            enabled: true,
            created_at_unix_ms,
        };
        if validate_local_engram(&engram).is_ok() {
            out.push(engram);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn clip_to_single_line(text: &str) -> String {
    let squeezed = squeeze_whitespace(text);
    if squeezed.chars().count() <= 1_000 {
        return squeezed;
    }
    squeezed.chars().take(1_000).collect()
}

fn short_hash(seed: &str) -> String {
    blake3::hash(seed.as_bytes()).to_hex()[..16].to_string()
}

// ── M2b: distil proposals from the fact store ────────────────────────────────

/// Why a fact was proposed for the curated tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistillSignal {
    /// An `incident:<date>` fact — a symptom/cause/fix record, the highest
    /// value shape in the store because it is already written as a lesson.
    Incident,
    /// A `decision::<topic>` family whose topic recurs across dated entities
    /// or accumulates several keys: a choice that kept having to be re-made.
    RecurringDecision,
    /// A contradiction candidate: two active facts on one `(entity, key)` with
    /// opposite polarity. The lesson is that the pair disagrees.
    Contradiction,
    /// A `gate:M<n>` lesson repeated across ExecPlans.
    RepeatedGate,
}

impl DistillSignal {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Incident => "incident",
            Self::RecurringDecision => "recurring_decision",
            Self::Contradiction => "contradiction",
            Self::RepeatedGate => "repeated_gate",
        }
    }

    /// Rank used to order proposals for review. Incidents first: they are
    /// already written as lessons and need the least editing.
    fn rank(self) -> u8 {
        match self {
            Self::Incident => 0,
            Self::Contradiction => 1,
            Self::RecurringDecision => 2,
            Self::RepeatedGate => 3,
        }
    }
}

/// One candidate for the curated tier. A proposal is not an engram: it becomes
/// one only when a review step accepts it ([`proposal_to_engram`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DistillProposal {
    /// Proposed engram name.
    pub name: String,
    /// Proposed intent bucket.
    pub intent_bucket: String,
    /// Proposed one-line recall description.
    pub description: String,
    /// Proposed engram body.
    pub content: String,
    /// The fact this came from. Required — a distilled entry without
    /// provenance fails the M2 gate.
    pub fact_id: String,
    /// `YYYY-MM-DD` of that fact, from `stored_at`.
    pub fact_date: String,
    /// Fact entity, for the reviewer.
    pub entity: String,
    /// Which signal proposed it.
    pub signal: DistillSignal,
    /// How many facts backed the signal (1 for a single incident).
    pub support: usize,
}

/// Options for one distillation pass.
#[derive(Debug, Clone)]
pub struct DistillOptions {
    /// Skip a proposal whose name or description substantially restates one of
    /// these already-catalogued entries.
    pub existing: Vec<LocalEngram>,
    /// How many keys a `decision::` entity needs, or how many dated siblings
    /// its topic stem needs, before the topic counts as recurring.
    pub recurrence_threshold: usize,
    /// Stop after this many proposals (deterministic: the ranked prefix).
    pub max_proposals: usize,
}

impl Default for DistillOptions {
    fn default() -> Self {
        Self {
            existing: Vec::new(),
            recurrence_threshold: 2,
            max_proposals: 200,
        }
    }
}

/// Propose curated-tier entries from a slice of facts.
///
/// Pure: it reads facts and returns candidates, and writes nothing. The caller
/// decides what to accept. Ordering is total — `(signal rank, name)` — so the
/// same fact slice always yields the same proposal list, which is what makes
/// the fixture test in this module meaningful.
pub fn distill_proposals(facts: &[MemoryFact], options: &DistillOptions) -> Vec<DistillProposal> {
    let mut proposals: Vec<DistillProposal> = Vec::new();

    // Signal 1 — incidents. One proposal per incident fact.
    for fact in facts.iter().filter(|f| f.entity.starts_with("incident:")) {
        if let Some(proposal) = incident_proposal(fact) {
            proposals.push(proposal);
        }
    }

    // Signal 2 — recurring decisions. Group `decision::<topic>-<date>` by the
    // topic stem; a stem is recurring when it was decided on more than one date
    // or accumulated several keys under one entity.
    let mut decisions: BTreeMap<String, Vec<&MemoryFact>> = BTreeMap::new();
    for fact in facts.iter().filter(|f| f.entity.starts_with("decision:")) {
        decisions
            .entry(decision_topic_stem(&fact.entity))
            .or_default()
            .push(fact);
    }
    for (stem, group) in &decisions {
        let dates: BTreeSet<&str> = group.iter().map(|f| date_of(&f.stored_at)).collect();
        let support = dates.len().max(group.len());
        if dates.len() < options.recurrence_threshold && group.len() < options.recurrence_threshold {
            continue;
        }
        if let Some(proposal) = decision_proposal(stem, group, support) {
            proposals.push(proposal);
        }
    }

    // Signal 3 — repeated gate lessons: one `gate:M<n>` key seen on several
    // ExecPlans is a lesson about the gate, not about any one plan.
    let mut gates: BTreeMap<String, Vec<&MemoryFact>> = BTreeMap::new();
    for fact in facts.iter().filter(|f| f.key.starts_with("gate:")) {
        gates.entry(fact.key.clone()).or_default().push(fact);
    }
    for (key, group) in &gates {
        if group.len() < options.recurrence_threshold.max(3) {
            continue;
        }
        if let Some(proposal) = gate_proposal(key, group) {
            proposals.push(proposal);
        }
    }

    dedupe_and_rank(proposals, options)
}

/// Fold contradiction candidates into proposals. Kept separate from
/// [`distill_proposals`] because contradictions arrive from a different daemon
/// route (`/v1/console/review/contradictions`) rather than from `/v1/facts`.
pub fn contradiction_proposals(
    candidates: &[crate::memory::ContradictionCandidate],
    facts_by_id: &BTreeMap<String, MemoryFact>,
    options: &DistillOptions,
) -> Vec<DistillProposal> {
    let mut proposals = Vec::new();
    for candidate in candidates {
        let Some(fact) = candidate.fact_ids.iter().find_map(|id| facts_by_id.get(id)) else {
            continue;
        };
        let Some(name) = sanitise_name(&format!("contradiction-{}-{}", candidate.entity, candidate.key)) else {
            continue;
        };
        let description = squeeze_whitespace(&format!(
            "Two active facts disagree on {}/{}: {} vs {} — check which is current before relying on either.",
            candidate.entity, candidate.key, candidate.polarity_a, candidate.polarity_b
        ));
        proposals.push(DistillProposal {
            name,
            intent_bucket: "contradiction".to_string(),
            description,
            content: squeeze_whitespace(&candidate.reason),
            fact_id: fact.fact_id.clone(),
            fact_date: date_of(&fact.stored_at).to_string(),
            entity: candidate.entity.clone(),
            signal: DistillSignal::Contradiction,
            support: candidate.fact_ids.len(),
        });
    }
    dedupe_and_rank(proposals, options)
}

fn dedupe_and_rank(mut proposals: Vec<DistillProposal>, options: &DistillOptions) -> Vec<DistillProposal> {
    let existing_names: BTreeSet<&str> = options.existing.iter().map(|e| e.name.as_str()).collect();
    let existing_terms: Vec<BTreeSet<String>> = options
        .existing
        .iter()
        .map(|e| distinctive_terms(&format!("{} {}", e.name.replace('-', " "), e.digest_description())))
        .collect();

    proposals.sort_by(|a, b| {
        a.signal
            .rank()
            .cmp(&b.signal.rank())
            .then_with(|| b.support.cmp(&a.support))
            .then_with(|| a.name.cmp(&b.name))
    });

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut accepted_terms: Vec<BTreeSet<String>> = Vec::new();
    let mut out = Vec::new();
    for proposal in proposals {
        if proposal.description.trim().is_empty() || existing_names.contains(proposal.name.as_str()) {
            continue;
        }
        if !seen.insert(proposal.name.clone()) {
            continue;
        }
        let terms = distinctive_terms(&format!("{} {}", proposal.name.replace('-', " "), proposal.description));
        let duplicate = existing_terms
            .iter()
            .chain(accepted_terms.iter())
            .any(|other| jaccard(&terms, other) >= 0.5);
        if duplicate {
            continue;
        }
        accepted_terms.push(terms);
        out.push(proposal);
        if out.len() >= options.max_proposals {
            break;
        }
    }
    out
}

/// Content-bearing terms of 4+ characters, lowercased. Used only for
/// duplicate detection against already-catalogued entries.
fn distinctive_terms(text: &str) -> BTreeSet<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 4)
        .map(str::to_ascii_lowercase)
        .collect()
}

fn jaccard(a: &BTreeSet<String>, b: &BTreeSet<String>) -> f32 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let intersection = a.intersection(b).count() as f32;
    let union = a.union(b).count() as f32;
    if union == 0.0 {
        0.0
    } else {
        intersection / union
    }
}

fn date_of(stored_at: &str) -> &str {
    stored_at.split('T').next().unwrap_or(stored_at)
}

/// `decision::lme-m-ingest-root-cause-2026-05-15` -> `lme-m-ingest-root-cause`.
fn decision_topic_stem(entity: &str) -> String {
    let tail = entity.rsplit(':').next().unwrap_or(entity);
    let trimmed = tail.trim_matches('-');
    // Strip a trailing ISO date, which is what makes two records of the same
    // topic look like two topics.
    let parts: Vec<&str> = trimmed.split('-').collect();
    if parts.len() > 3 {
        let tail3 = &parts[parts.len() - 3..];
        let is_date = tail3[0].len() == 4
            && tail3.iter().all(|p| p.chars().all(|c| c.is_ascii_digit()))
            && tail3[1].len() == 2
            && tail3[2].len() == 2;
        if is_date {
            return parts[..parts.len() - 3].join("-");
        }
    }
    trimmed.to_string()
}

fn incident_proposal(fact: &MemoryFact) -> Option<DistillProposal> {
    let name = sanitise_name(&format!("incident-{}", fact.key))?;
    let parsed: serde_json::Value = serde_json::from_str(&fact.value).unwrap_or(serde_json::Value::Null);
    let field = |key: &str| {
        parsed
            .get(key)
            .and_then(|v| v.as_str())
            .map(squeeze_whitespace)
            .filter(|s| !s.is_empty())
    };
    let symptom = field("symptom");
    let cause = field("cause");
    let fix = field("fix_sha").or_else(|| field("fix"));
    // The recall line is "what you will see" then "what it actually is" — the
    // shape that makes the native store's descriptions work.
    let description = match (&symptom, &cause) {
        (Some(symptom), Some(cause)) => format!("{} — {}", first_clause(symptom), first_clause(cause)),
        (Some(symptom), None) => first_clause(symptom),
        (None, Some(cause)) => first_clause(cause),
        // An `incident:` fact that carries neither a symptom nor a cause is a
        // bag of fields, not a lesson. Dumping its JSON into a recall line
        // would spend digest budget on something no agent can act on, so it is
        // left for a human to rewrite rather than auto-proposed.
        (None, None) => return None,
    };
    let description = squeeze_whitespace(&description);
    if description.is_empty() {
        return None;
    }
    let mut content = String::new();
    for (label, value) in [("symptom", &symptom), ("cause", &cause), ("fix", &fix)] {
        if let Some(value) = value {
            let _ = writeln!(content, "{label}: {value}");
        }
    }
    if content.is_empty() {
        content.push_str(&squeeze_whitespace(&fact.value));
    }
    Some(DistillProposal {
        name,
        intent_bucket: "incident".to_string(),
        description: clip_to_single_line(&description),
        content,
        fact_id: fact.fact_id.clone(),
        fact_date: date_of(&fact.stored_at).to_string(),
        entity: fact.entity.clone(),
        signal: DistillSignal::Incident,
        support: 1,
    })
}

fn decision_proposal(stem: &str, group: &[&MemoryFact], support: usize) -> Option<DistillProposal> {
    let name = sanitise_name(&format!("decision-{stem}"))?;
    // The provenance fact is the newest one in the family whose value actually
    // reads like a lesson. A family of paths and status blobs yields no
    // proposal at all, which is the correct outcome.
    let mut ordered: Vec<&&MemoryFact> = group.iter().collect();
    ordered.sort_by(|a, b| b.stored_at.cmp(&a.stored_at));
    let newest = ordered.into_iter().find(|f| is_prose_lesson(&f.value))?;
    let keys: Vec<&str> = {
        let mut keys: Vec<&str> = group.iter().map(|f| f.key.as_str()).collect();
        keys.sort_unstable();
        keys.dedup();
        keys.into_iter().take(6).collect()
    };
    let gist = first_clause(&squeeze_whitespace(&newest.value));
    if gist.is_empty() {
        return None;
    }
    let description = squeeze_whitespace(&format!("Recurring decision on {stem}: {gist}"));
    let content = format!(
        "topic: {stem}\nrecurred_across: {support}\nkeys: {}\nlatest: {}\n",
        keys.join(", "),
        squeeze_whitespace(&newest.value)
    );
    Some(DistillProposal {
        name,
        intent_bucket: "decision".to_string(),
        description: clip_to_single_line(&description),
        content,
        fact_id: newest.fact_id.clone(),
        fact_date: date_of(&newest.stored_at).to_string(),
        entity: newest.entity.clone(),
        signal: DistillSignal::RecurringDecision,
        support,
    })
}

fn gate_proposal(key: &str, group: &[&MemoryFact]) -> Option<DistillProposal> {
    let name = sanitise_name(&format!("gate-lesson-{key}"))?;
    let mut ordered: Vec<&&MemoryFact> = group.iter().collect();
    ordered.sort_by(|a, b| b.stored_at.cmp(&a.stored_at));
    // A `gate:M<n>` fact is normally a JSON status record for one plan, not a
    // lesson about the gate. Only a prose value earns a proposal.
    let newest = ordered.into_iter().find(|f| is_prose_lesson(&f.value))?;
    let gist = first_clause(&squeeze_whitespace(&newest.value));
    if gist.is_empty() {
        return None;
    }
    Some(DistillProposal {
        name,
        intent_bucket: "execplan_gate".to_string(),
        description: clip_to_single_line(&squeeze_whitespace(&format!(
            "{key} recurs across {} plans: {gist}",
            group.len()
        ))),
        content: format!("key: {key}\nplans: {}\nlatest: {gist}\n", group.len()),
        fact_id: newest.fact_id.clone(),
        fact_date: date_of(&newest.stored_at).to_string(),
        entity: newest.entity.clone(),
        signal: DistillSignal::RepeatedGate,
        support: group.len(),
    })
}

/// True when a fact value reads like a lesson rather than a record.
///
/// The fact store is full of machine-shaped values — `gate:M<n>` status blobs,
/// artefact paths, URLs — that are perfectly good ledger entries and useless as
/// recall lines. Proposing one would spend digest budget on something no agent
/// can act on, and would be the "distillation manufactures plausible memories"
/// failure the plan calls out. A candidate has to be prose to get proposed.
fn is_prose_lesson(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < 40 {
        return false;
    }
    if trimmed.starts_with('{') || trimmed.starts_with('[') || trimmed.starts_with('/') {
        return false;
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return false;
    }
    if serde_json::from_str::<serde_json::Value>(trimmed).is_ok_and(|v| !v.is_string()) {
        return false;
    }
    trimmed.split_whitespace().count() >= 6
}

/// First sentence-ish clause of `text`, so a recall line does not drag a whole
/// incident write-up into the digest.
fn first_clause(text: &str) -> String {
    let squeezed = squeeze_whitespace(text);
    for (idx, _) in squeezed.char_indices() {
        let rest = &squeezed[idx..];
        if rest.starts_with(". ") || rest.starts_with("; ") {
            return squeezed[..idx].to_string();
        }
    }
    squeezed
}

/// Accept one proposal into the catalog.
///
/// This is the review step: nothing reaches the catalog without a caller
/// running it explicitly. The resulting engram carries `source_fact_id` and
/// `source_fact_date`, which the M2 gate checks on every non-seed entry.
pub fn proposal_to_engram(proposal: &DistillProposal, created_at_unix_ms: u64) -> Result<LocalEngram, String> {
    let (description, _) = redact_secret_shaped(&proposal.description);
    let (content, _) = redact_secret_shaped(&proposal.content);
    let engram = LocalEngram {
        id: format!("eng_distilled_{}", short_hash(&proposal.name)),
        name: proposal.name.clone(),
        version: ENGRAM_VERSION.to_string(),
        intent_bucket: sanitise_bucket(&proposal.intent_bucket),
        query_pattern: None,
        description: Some(clip_to_single_line(&description)),
        source_fact_id: Some(proposal.fact_id.clone()),
        source_fact_date: Some(proposal.fact_date.clone()),
        content: if content.trim().is_empty() {
            description.clone()
        } else {
            content
        },
        applicable_why: Some(format!(
            "Distilled from fact {} ({}) on entity {} via the {} signal; {} fact(s) backed it.",
            proposal.fact_id,
            proposal.fact_date,
            proposal.entity,
            proposal.signal.as_str(),
            proposal.support
        )),
        capability_class_min: None,
        capability_class_max: None,
        generated_class: Some("fact_distilled".to_string()),
        source_chunk_hashes: Vec::new(),
        source_chunk_set_hash: None,
        inherited_reason: Some(format!("distill:{}", proposal.signal.as_str())),
        policy_hash: None,
        enabled: true,
        created_at_unix_ms,
    };
    validate_local_engram(&engram)?;
    Ok(engram)
}

// ── M3: render the digest ────────────────────────────────────────────────────

/// One rendered line's inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestEntry {
    pub slug: String,
    pub intent_bucket: String,
    pub description: String,
}

/// A rendered digest plus everything needed to audit it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DigestRender {
    /// The fragment body, exactly as it goes between the managed markers.
    pub body: String,
    /// Catalog identity. Two renders of one catalog share it.
    pub manifest_hash: String,
    /// `ceil(chars/4)` over `body`.
    pub token_estimate: usize,
    /// Budget the render was made against.
    pub token_budget: usize,
    /// Entries that got a line.
    pub rendered: usize,
    /// Entries dropped because even the shortest rung would not fit.
    pub omitted: usize,
    /// Ladder rung chosen, in characters of description.
    pub description_allowance: usize,
    /// Entries whose text tripped the credential-shaped filter.
    pub redacted: usize,
}

/// Catalog entries eligible for the digest, in render order.
///
/// Filters, in order: disabled engrams; names in the reserved daemon-owned
/// namespace, which is never user content; entries with no recall line, which
/// the M2 gate forbids anyway.
pub fn digest_entries(catalog: &[LocalEngram]) -> Vec<DigestEntry> {
    let mut out: Vec<DigestEntry> = catalog
        .iter()
        .filter(|engram| engram.enabled && !is_reserved_engram_name(&engram.name))
        .filter_map(|engram| {
            let description = engram.digest_description();
            (!description.trim().is_empty()).then(|| DigestEntry {
                slug: engram.name.clone(),
                intent_bucket: engram.intent_bucket.clone(),
                description,
            })
        })
        .collect();
    out.sort_by(|a, b| a.intent_bucket.cmp(&b.intent_bucket).then_with(|| a.slug.cmp(&b.slug)));
    out.dedup_by(|a, b| a.slug == b.slug);
    out
}

/// True when the engram name sits in a reserved, daemon-owned namespace.
///
/// Engrams are addressed as `__engram__::<name>`, so every reserved prefix in
/// `crux_mcp::envelope::RESERVED_PREFIXES` and
/// [`crate::memory::RESERVED_ENTITY_PREFIXES`] opens with `__`. Matching that
/// marker on the name covers all of them without pulling `crux-mcp` into the
/// CLI, and the assertion below pins the two lists to that shape.
fn is_reserved_engram_name(name: &str) -> bool {
    debug_assert!(
        crate::memory::RESERVED_ENTITY_PREFIXES
            .iter()
            .all(|prefix| prefix.starts_with("__")),
        "reserved-prefix filter assumes every reserved entity prefix opens with '__'"
    );
    debug_assert!(ENGRAM_ENTITY_PREFIX.starts_with("__"));
    name.starts_with("__")
}

const DIGEST_HEADER: &str = "\
## Crux Memory Digest

Curated memory, always loaded — the daemon's equivalent of a native memory index.
One line per entry, grouped by intent bucket: `slug — recall line`, clipped to fit.
A line is a pointer, not the memory: call `engram_resolve` with
`names: [\"<slug>@v1\"]` for the body, and treat what you recall as dated.
Distilled entries name the fact they came from; seeded ones name a memory file.
";

/// Render the digest fragment body from `entries`, under `budget` tokens.
///
/// Pure in `(entries, budget)`. Ordering is total, the allowance comes off a
/// fixed ladder, and nothing time-varying is written, so the same catalog
/// renders the same bytes every time — the M3 byte-stability gate.
///
/// The budget is enforced here, not assumed: the renderer walks the ladder down
/// until the whole body fits, and if the shortest rung still does not fit it
/// drops entries from the end of the sorted order and reports how many in
/// [`DigestRender::omitted`] rather than emitting an over-budget prefix.
pub fn render_digest(entries: &[DigestEntry], manifest_hash: &str, budget: usize) -> DigestRender {
    let mut redacted = 0usize;
    let safe: Vec<DigestEntry> = entries
        .iter()
        .map(|entry| {
            let (description, hit) = redact_secret_shaped(&entry.description);
            if hit {
                redacted += 1;
            }
            DigestEntry {
                slug: entry.slug.clone(),
                intent_bucket: entry.intent_bucket.clone(),
                description: squeeze_whitespace(&description),
            }
        })
        .collect();

    for &allowance in ALLOWANCE_LADDER {
        let body = compose_body(&safe, manifest_hash, allowance);
        let tokens = estimate_tokens(&body);
        if tokens <= budget {
            return DigestRender {
                body,
                manifest_hash: manifest_hash.to_string(),
                token_estimate: tokens,
                token_budget: budget,
                rendered: safe.len(),
                omitted: 0,
                description_allowance: allowance,
                redacted,
            };
        }
    }

    // Still over at the shortest rung: shed entries from the tail of the sorted
    // order until it fits. Deterministic, and the shed entries stay reachable
    // through `engram_resolve`.
    let allowance = ALLOWANCE_LADDER.last().copied().unwrap_or(18);
    let mut kept = safe.len();
    while kept > 0 {
        let body = compose_body(&safe[..kept], manifest_hash, allowance);
        let tokens = estimate_tokens(&body);
        if tokens <= budget {
            return DigestRender {
                body,
                manifest_hash: manifest_hash.to_string(),
                token_estimate: tokens,
                token_budget: budget,
                rendered: kept,
                omitted: safe.len() - kept,
                description_allowance: allowance,
                redacted,
            };
        }
        kept -= 1;
    }
    let body = compose_body(&[], manifest_hash, allowance);
    let tokens = estimate_tokens(&body);
    DigestRender {
        body,
        manifest_hash: manifest_hash.to_string(),
        token_estimate: tokens,
        token_budget: budget,
        rendered: 0,
        omitted: safe.len(),
        description_allowance: allowance,
        redacted,
    }
}

fn compose_body(entries: &[DigestEntry], manifest_hash: &str, allowance: usize) -> String {
    let mut body = String::with_capacity(DIGEST_HEADER.len() + entries.len() * (allowance + 48));
    body.push_str(DIGEST_HEADER);
    body.push_str("\ndigest-identity: ");
    body.push_str(manifest_hash);
    body.push('\n');
    let mut current_bucket: Option<&str> = None;
    for entry in entries {
        if current_bucket != Some(entry.intent_bucket.as_str()) {
            body.push_str("\n### ");
            body.push_str(&entry.intent_bucket);
            body.push('\n');
            current_bucket = Some(entry.intent_bucket.as_str());
        }
        body.push_str("- ");
        body.push_str(&entry.slug);
        body.push_str(" — ");
        body.push_str(&clip_words(&entry.description, allowance));
        body.push('\n');
    }
    body
}

/// Clip to at most `allowance` characters on a word boundary, trimming the
/// dangling punctuation a mid-sentence cut leaves behind.
fn clip_words(text: &str, allowance: usize) -> String {
    if text.chars().count() <= allowance {
        return text.to_string();
    }
    let cut: String = text.chars().take(allowance).collect();
    let trimmed = match cut.rfind(' ') {
        Some(idx) if idx >= allowance / 3 => &cut[..idx],
        _ => cut.as_str(),
    };
    trimmed
        .trim_end_matches(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | ':' | '-' | '—' | '(' | '['))
        .to_string()
}

/// The catalog identity the digest body carries. Computed at a fixed tenant and
/// capability class so it depends on the catalog alone.
pub fn digest_manifest_hash(catalog: &[LocalEngram]) -> String {
    build_engram_manifest(catalog, DIGEST_TENANT, DIGEST_CAPABILITY_CLASS)["manifest_hash"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// Render a whole catalog in one call: the ordinary entry point.
pub fn render_catalog_digest(catalog: &[LocalEngram], budget: usize) -> DigestRender {
    let hash = digest_manifest_hash(catalog);
    render_digest(&digest_entries(catalog), &hash, budget)
}

// ── Catalog assembly and the operator-facing passes ──────────────────────────

/// Where the entries in an assembled catalog came from.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CatalogBuild {
    /// The assembled catalog, name-ordered.
    pub catalog: Vec<LocalEngram>,
    /// Entries seeded from the harness-native memory store.
    pub seeded: usize,
    /// Entries accepted from distillation proposals.
    pub distilled: usize,
    /// Proposals that were produced but not accepted — the review queue.
    pub pending: Vec<DistillProposal>,
}

/// Assemble a catalog from native-memory seeds plus accepted proposals.
///
/// `accept_top` takes the first N of the ranked proposal list; `accept_names`
/// takes specific proposals by name. Both are explicit caller decisions: with
/// neither set, nothing is distilled into the catalog and the tier is the seed
/// set alone. That is the curation rule from the plan — 14,800 facts do not get
/// to promote themselves.
pub fn build_catalog(
    ingest: &NativeMemoryIngestV1,
    facts: &[MemoryFact],
    accept_top: usize,
    accept_names: &[String],
    now_unix_ms: u64,
) -> CatalogBuild {
    let seeds = seed_engrams(ingest, now_unix_ms);
    let options = DistillOptions {
        existing: seeds.clone(),
        ..DistillOptions::default()
    };
    let proposals = distill_proposals(facts, &options);
    let wanted: BTreeSet<&str> = accept_names.iter().map(String::as_str).collect();

    let mut catalog = seeds.clone();
    let mut pending = Vec::new();
    let mut accepted = 0usize;
    for (idx, proposal) in proposals.into_iter().enumerate() {
        let take = idx < accept_top || wanted.contains(proposal.name.as_str());
        if !take {
            pending.push(proposal);
            continue;
        }
        match proposal_to_engram(&proposal, now_unix_ms) {
            Ok(engram) => {
                catalog.push(engram);
                accepted += 1;
            }
            Err(_) => pending.push(proposal),
        }
    }
    catalog.sort_by(|a, b| a.name.cmp(&b.name));
    CatalogBuild {
        seeded: seeds.len(),
        distilled: accepted,
        catalog,
        pending,
    }
}

/// Machine-readable outcome of `corecruxctl memory digest`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DigestReport {
    /// Corpus the numbers belong to. A recall figure without its corpus is
    /// worthless, so the report carries one by construction.
    pub corpus: String,
    pub native_roots: Vec<String>,
    pub memories_projected: usize,
    pub seeded: usize,
    pub distilled: usize,
    pub pending_proposals: usize,
    pub catalog_entries: usize,
    /// True when the catalog sits inside the plan's 100–250 band.
    pub within_target_band: bool,
    pub manifest_hash: String,
    pub token_estimate: usize,
    pub token_budget: usize,
    pub rendered: usize,
    pub omitted: usize,
    pub description_allowance: usize,
    pub redacted: usize,
    pub fragment_path: Option<String>,
}

/// Build the report for an assembled catalog and its render.
pub fn digest_report(
    build: &CatalogBuild,
    render: &DigestRender,
    ingest: &NativeMemoryIngestV1,
    fragment_path: Option<String>,
) -> DigestReport {
    DigestReport {
        corpus: "drivew-host-memory-gold-v1".to_string(),
        native_roots: ingest.roots.clone(),
        memories_projected: ingest.memories,
        seeded: build.seeded,
        distilled: build.distilled,
        pending_proposals: build.pending.len(),
        catalog_entries: build.catalog.len(),
        within_target_band: (CATALOG_MIN_ENTRIES..=CATALOG_MAX_ENTRIES).contains(&build.catalog.len()),
        manifest_hash: render.manifest_hash.clone(),
        token_estimate: render.token_estimate,
        token_budget: render.token_budget,
        rendered: render.rendered,
        omitted: render.omitted,
        description_allowance: render.description_allowance,
        redacted: render.redacted,
        fragment_path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(entity: &str, key: &str, value: &str, stored_at: &str) -> MemoryFact {
        MemoryFact {
            fact_id: format!("f_{}", short_hash(&format!("{entity}{key}{stored_at}"))),
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            version: 1,
            confidence: 1.0,
            stored_at: stored_at.to_string(),
            source_receipt: None,
            deleted: false,
        }
    }

    fn engram(name: &str, bucket: &str, description: &str) -> LocalEngram {
        LocalEngram {
            id: format!("eng_{name}"),
            name: name.to_string(),
            version: ENGRAM_VERSION.to_string(),
            intent_bucket: bucket.to_string(),
            query_pattern: None,
            description: Some(description.to_string()),
            source_fact_id: None,
            source_fact_date: None,
            content: format!("{description}\nmemory_md_ref: {name}.md\n"),
            applicable_why: None,
            capability_class_min: None,
            capability_class_max: None,
            generated_class: None,
            source_chunk_hashes: Vec::new(),
            source_chunk_set_hash: None,
            inherited_reason: None,
            policy_hash: None,
            enabled: true,
            created_at_unix_ms: 1,
        }
    }

    fn synthetic_catalog(n: usize) -> Vec<LocalEngram> {
        (0..n)
            .map(|i| {
                engram(
                    &format!("synthetic-memory-entry-{i:03}"),
                    &format!("bucket-{}", i % 9),
                    "A curated lesson about a recurring trap in this workspace, with enough prose to need clipping at every rung of the ladder.",
                )
            })
            .collect()
    }

    #[test]
    fn intent_bucket_survives_punctuated_headings() {
        assert_eq!(
            intent_bucket(Some("Retired / archived — do NOT target"), None),
            "retired_archived_do_not_target"
        );
        assert_eq!(intent_bucket(Some("CI / merge queue"), None), "ci_merge_queue");
        assert_eq!(intent_bucket(None, Some("project")), "project");
        assert_eq!(intent_bucket(None, None), "unfiled");
        assert_eq!(intent_bucket(Some("———"), Some("project")), "project");
    }

    /// The whole cost model of the digest rests on this: an unchanged catalog
    /// must render the same bytes, or every session re-bills the prompt prefix
    /// at write price instead of reading it from cache.
    #[test]
    fn digest_render_is_byte_stable() {
        let catalog = synthetic_catalog(120);
        let a = render_catalog_digest(&catalog, DIGEST_TOKEN_BUDGET);
        let b = render_catalog_digest(&catalog, DIGEST_TOKEN_BUDGET);
        assert_eq!(a.body, b.body, "two renders of one catalog must be byte-identical");
        assert_eq!(a.manifest_hash, b.manifest_hash);
        assert!(!a.manifest_hash.is_empty());
        // Nothing time-varying may appear in prompt-prefix content.
        for forbidden in ["generated at", "generated_at", "rendered at", "entries)", "total:"] {
            assert!(
                !a.body.to_lowercase().contains(forbidden),
                "digest body must not carry '{forbidden}'"
            );
        }
    }

    #[test]
    fn digest_identity_changes_only_when_the_catalog_changes() {
        let catalog = synthetic_catalog(20);
        let before = render_catalog_digest(&catalog, DIGEST_TOKEN_BUDGET);
        let mut changed = catalog.clone();
        changed[3].description = Some("A different recall line entirely.".to_string());
        let after = render_catalog_digest(&changed, DIGEST_TOKEN_BUDGET);
        assert_ne!(before.manifest_hash, after.manifest_hash);
        assert_ne!(before.body, after.body);
    }

    /// The cap is enforced in the renderer, not hoped for: a catalog far past
    /// the plan's 250-entry ceiling still has to come in under budget.
    #[test]
    fn digest_respects_the_token_budget_at_every_catalog_size() {
        for n in [1usize, 84, 100, 250, 900] {
            let render = render_catalog_digest(&synthetic_catalog(n), DIGEST_TOKEN_BUDGET);
            assert!(
                render.token_estimate <= DIGEST_TOKEN_BUDGET,
                "n={n} rendered {} tokens, over the {DIGEST_TOKEN_BUDGET} budget",
                render.token_estimate
            );
            assert_eq!(render.rendered + render.omitted, n);
        }
    }

    #[test]
    fn digest_sheds_entries_rather_than_exceeding_the_budget() {
        let render = render_catalog_digest(&synthetic_catalog(4_000), DIGEST_TOKEN_BUDGET);
        assert!(render.token_estimate <= DIGEST_TOKEN_BUDGET);
        assert!(render.omitted > 0, "an impossible catalog must shed, not overflow");
    }

    /// A rule keying on a bare credential prefix swallows prose that merely
    /// *names* one. The workspace's own memory contains exactly that sentence,
    /// and losing it would gut the entry.
    #[test]
    fn digest_redacts_credentials_without_eating_prose_that_names_a_prefix() {
        let catalog = vec![
            engram(
                "crux-two-planes-two-credentials",
                "crux",
                "The agent token is the fact plane; the secret is `base64:`-prefixed when re-minting.",
            ),
            engram(
                "leaky-entry",
                "crux",
                "The token is glpat-AAAAAAAAAAAAAAAAAAAA and must never be pasted into a file.",
            ),
        ];
        let render = render_catalog_digest(&catalog, DIGEST_TOKEN_BUDGET);
        assert!(
            render.body.contains("`base64:`-prefixed"),
            "prose naming a prefix must survive: {}",
            render.body
        );
        assert!(!render.body.contains("glpat-AAAAAAAAAAAAAAAAAAAA"));
        assert_eq!(render.redacted, 1);
    }

    #[test]
    fn digest_skips_reserved_and_descriptionless_entries() {
        let mut catalog = vec![engram("real-entry", "crux", "A real recall line.")];
        catalog.push(engram("__ops::internal", "crux", "Daemon bookkeeping."));
        let mut blank = engram("blank-entry", "crux", "x");
        blank.description = Some("   ".to_string());
        blank.content = "   ".to_string();
        catalog.push(blank);
        let entries = digest_entries(&catalog);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].slug, "real-entry");
    }

    #[test]
    fn distillation_is_deterministic_and_carries_provenance() {
        let facts = vec![
            fact(
                "incident:2026-09-17",
                "ci-wedged-by-advisory-db-drift",
                r#"{"symptom":"All open PRs blocked; cargo-deny red. Nothing changed in the repo.","cause":"The advisory DB drifts daily, so a quiet repo goes red on its own.","fix_sha":"abc1234"}"#,
                "2026-09-17T12:38:40Z",
            ),
            fact(
                "decision::ingest-root-cause-2026-05-15",
                "chosen",
                "Use streaming ingest. The readFileSync limit blocks the audit path.",
                "2026-05-15T10:00:00Z",
            ),
            fact(
                "decision::ingest-root-cause-2026-06-02",
                "revisited",
                "Streaming ingest confirmed; the limit is still the blocker.",
                "2026-06-02T10:00:00Z",
            ),
        ];
        let options = DistillOptions::default();
        let first = distill_proposals(&facts, &options);
        let second = distill_proposals(&facts, &options);
        assert_eq!(first, second, "the same facts must yield the same proposals");
        assert_eq!(first.len(), 2);
        assert_eq!(first[0].signal, DistillSignal::Incident);
        assert!(first[0].description.contains("advisory DB drifts daily"));
        for proposal in &first {
            assert!(!proposal.fact_id.is_empty());
            assert_eq!(proposal.fact_date.len(), 10);
        }
        let engram = proposal_to_engram(&first[0], 1).expect("accepts");
        assert_eq!(engram.source_fact_id.as_deref(), Some(first[0].fact_id.as_str()));
        assert_eq!(engram.source_fact_date.as_deref(), Some("2026-09-17"));
        assert_eq!(engram.generated_class.as_deref(), Some("fact_distilled"));
    }

    #[test]
    fn distillation_does_not_re_propose_what_the_seeds_already_hold() {
        let facts = vec![fact(
            "incident:2026-09-17",
            "advisory-db-drift-wedges-quiet-repos",
            r#"{"symptom":"A repo with no merges for weeks goes red on its own","cause":"advisory db drift wedges quiet repos and blocks all PRs"}"#,
            "2026-09-17T12:38:40Z",
        )];
        let seeded = vec![engram(
            "advisory-db-drift-wedges-quiet-repos",
            "ci_merge_queue",
            "A repo with no merges for weeks goes red on its own: advisory db drift wedges quiet repos and blocks all PRs.",
        )];
        let options = DistillOptions {
            existing: seeded,
            ..DistillOptions::default()
        };
        assert!(
            distill_proposals(&facts, &options).is_empty(),
            "a lesson the seeds already carry must not be re-proposed"
        );
    }

    #[test]
    fn decision_topic_stem_strips_the_trailing_date() {
        assert_eq!(
            decision_topic_stem("decision::lme-m-ingest-root-cause-2026-05-15"),
            "lme-m-ingest-root-cause"
        );
        assert_eq!(decision_topic_stem("decision::no-date-here"), "no-date-here");
    }

    #[test]
    fn a_single_decision_record_is_not_a_recurring_topic() {
        let facts = vec![fact(
            "decision::one-off-2026-05-15",
            "chosen",
            "A single decision, never revisited.",
            "2026-05-15T10:00:00Z",
        )];
        assert!(distill_proposals(&facts, &DistillOptions::default()).is_empty());
    }

    #[test]
    fn seeded_and_distilled_entries_both_render_a_recall_line() {
        let proposal = DistillProposal {
            name: "incident-runner-disk-full".to_string(),
            intent_bucket: "incident".to_string(),
            description: "Integration tests all fail with a bare timeout — the data partition is full.".to_string(),
            content: "symptom: bare timeout\ncause: full disk\n".to_string(),
            fact_id: "f_deadbeef".to_string(),
            fact_date: "2026-09-09".to_string(),
            entity: "incident:2026-09-09".to_string(),
            signal: DistillSignal::Incident,
            support: 1,
        };
        let distilled = proposal_to_engram(&proposal, 1).expect("accepts");
        let catalog = vec![engram("seeded-one", "traps", "A seeded recall line."), distilled];
        let render = render_catalog_digest(&catalog, DIGEST_TOKEN_BUDGET);
        assert!(render.body.contains("- seeded-one — A seeded recall line."));
        assert!(render.body.contains("- incident-runner-disk-full — "));
        assert_eq!(render.omitted, 0);
    }
}
