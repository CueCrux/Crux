// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Shadow-corpus staging + replay harness —
//! `proof-carrying-adaptive-packs-2026-07-13` M1.
//!
//! ## What this adds to the seam below it
//!
//! [`crate::pack_conformance`] replays a staged pack's declared operations
//! and reports **evidence**: what each one returned, what it would have
//! written, what the grant filter dropped. It deliberately reaches no
//! verdict. [`crate::pack_lifecycle`] gives the pack a state to be replayed
//! in — `staged` runs and commits nothing.
//!
//! This module is the half that judges. It takes two conformance runs, a
//! local shadow corpus, and the pack's signed `pack.conformance.v1`
//! declaration, and produces a [`ReplayRecord`]: the observed mutations,
//! recall and citation behaviour, token cost, contradiction rate and
//! rollback result, measured against the declared [`BehaviouralEnvelope`]
//! and invariants, ending in a [`ReplayVerdict`]. A pack whose observed
//! behaviour leaves its declared envelope is refused activation before it
//! ever goes live.
//!
//! ## The corpus is bytes, not a filename
//!
//! The declaration content-addresses its corpus (`replay_corpus.sha256`,
//! inside the publisher's signature). [`load_corpus`] therefore takes the
//! corpus **bytes** and refuses anything that does not hash to the declared
//! digest, refuses a corpus naming a different `corpus_id`, and refuses one
//! whose cases disagree with the cases the manifest declares under
//! signature. "Replayed against corpus X" then names bytes rather than a
//! file someone can swap between the declaration and the run.
//!
//! The corpus is local and offline by construction: it is a document of
//! seed facts, recall probes and cases, replayed into an in-memory
//! [`FactStore`] this module creates and drops. No network, no customer
//! data, and nothing from the operator's real store is read or touched.
//!
//! ## Determinism, and where wall-clock time is allowed to live
//!
//! A replay has to be reproducible bit-for-bit given the same pack and the
//! same corpus, or the receipt M2 signs over it attests to nothing. Two
//! consequences run through this module:
//!
//! 1. [`ReplayRecord::record_digest`] is computed over an explicit
//!    projection that excludes every clock-derived value. Timings live in
//!    their own [`TimingMeasurements`] field so the exclusion is structural
//!    rather than a filter someone has to remember to update.
//! 2. A latency bound cannot decide a verdict. A wall-clock number differs
//!    on every run of even a perfectly deterministic pack, so a latency
//!    violation is recorded as an **advisory** and never blocks; the right
//!    instrument for cost drift is the distribution over many runs, which
//!    is M3's continuous score. Every bound that *is* a function of the
//!    pack's behaviour — writes, response bytes, token cost, decay class,
//!    contradiction rate, undo cost — blocks.
//!
//! ## Corpus identity travels with every number
//!
//! [`ReplayRecord`] carries `corpus_id` and `corpus_sha256` beside the
//! measurements, and the audit row and the stored record carry them too. A
//! behavioural number whose corpus is unknown cannot be compared to a later
//! one, and that misattribution is not recoverable after the fact.

use crate::extension_registry::{PackAttribution, EXTENSION_ENTITY_PREFIX};
use crate::pack_conformance::{ConformanceCase, ConformanceObservation, ConformanceRun};
use crate::pack_lifecycle::{ObservedFactWrite, PackLifecycleState};
use corecrux_memory::fact_store::{polarity_class_v1, FactQuery, FactStore, HorizonClass, StoreFact};
use crux_integrations::conformance::{
    BehaviouralEnvelope, ExpectedFactMutation, InvariantKind, PackConformance, ReplayCorpus, PPM_DENOMINATOR,
};
use crux_integrations::IntegrationManifest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema tag every shadow-corpus document carries.
pub const SHADOW_CORPUS_SCHEMA_V1: &str = "crux.pack.shadow_corpus.v1";

/// Schema tag of the record one replay produces.
pub const REPLAY_RECORD_SCHEMA_V1: &str = "crux.pack.replay_record.v1";

/// Operator switch deciding whether a failed replay actually **blocks**
/// activation. Off by default: per the plan's rollout the behavioural trust
/// surface is advisory first and only becomes the default enablement gate
/// after M6's go/no-go, and turning a behaviour on is an operator decision
/// rather than an upgrade side effect. The record, the verdict and the
/// audit row are produced either way — only the refusal is gated.
pub const REPLAY_GATE_ENV: &str = "CORECRUXD_PACK_REPLAY_GATE";

/// Key of the stored replay record, under the same
/// `__extension__::{id}` entity the install record uses.
pub const REPLAY_RECORD_KEY: &str = "replay";

/// Bytes per token in the replay's cost estimate.
///
/// The daemon has no tokenizer and must not acquire one for this: a signed
/// envelope needs a cost that is a pure, reproducible function of the bytes
/// observed, and a tokenizer is a model-specific dependency whose output
/// changes under it. Four bytes per token is the conventional English
/// approximation; it is documented as an estimate and used identically on
/// every run, which is what the envelope comparison actually requires.
pub const BYTES_PER_TOKEN: usize = 4;

/// Tenant the shadow store runs in. The corpus is synthetic and lives only
/// in memory, but the fact store's contradiction pass is tenant-scoped, so
/// the seeds and the pack's writes have to share one stamp.
const SHADOW_TENANT: &str = "default";

/// How many facts a recall probe considers.
const PROBE_TOP_K: usize = 16;

// ── The shadow corpus ────────────────────────────────────────────────────

/// A local, reproducible shadow corpus: the memory a pack's declared
/// operations are replayed against.
///
/// `cases` is duplicated between this document and the manifest's signed
/// `replay_corpus.cases` on purpose. The manifest's copy is what the
/// publisher signed; this copy is what an implementer reads. [`load_corpus`]
/// refuses them when they disagree, so the duplication is checked rather
/// than trusted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShadowCorpus {
    pub schema: String,
    pub corpus_id: String,
    #[serde(default)]
    pub description: String,
    /// Facts the shadow store is seeded with before the pack runs. This is
    /// the memory the pack's recall is measured against and the memory its
    /// writes are applied to.
    #[serde(default)]
    pub seed_facts: Vec<SeedFact>,
    /// Recall/citation probes — see [`RecallProbe`].
    #[serde(default)]
    pub probes: Vec<RecallProbe>,
    pub cases: Vec<ConformanceCase>,
}

/// One seeded fact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SeedFact {
    pub entity: String,
    pub key: String,
    pub value: String,
    #[serde(default = "full_confidence")]
    pub confidence: f32,
    /// A private seed exists so the replay can check that private content
    /// does not come back out through the pack — see
    /// [`InvariantKind::NoPrivateFactAccess`].
    #[serde(default)]
    pub private: bool,
}

fn full_confidence() -> f32 {
    1.0
}

/// One recall/citation probe.
///
/// A probe is run against the shadow store twice: before the pack's writes
/// are applied and after. It is *satisfied* when every entity in
/// `expect_entities` is among the facts the query returns — that is, when
/// the corpus's own facts are still citable. A pack that buries them under
/// its own writes regresses the probe, which is the observable form of
/// "this pack damaged recall", and it is caught before the pack is live.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecallProbe {
    pub probe_id: String,
    pub query: String,
    pub expect_entities: Vec<String>,
}

/// A corpus that has been checked against the signed declaration.
///
/// Constructed only by [`load_corpus`], so a `LoadedCorpus` in hand is
/// proof the bytes hashed to the declared digest.
#[derive(Debug, Clone)]
pub struct LoadedCorpus {
    pub corpus: ShadowCorpus,
    /// The digest actually computed over the submitted bytes.
    pub sha256: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplayError {
    #[error("pack '{0}' ships no pack.conformance.v1 declaration: there is no declared envelope to replay against")]
    NoDeclaration(String),
    #[error(
        "a replay runs against a staged pack; '{0}' is {1} — stage it first via POST /v1/extensions/{0}/lifecycle"
    )]
    NotStaged(String, &'static str),
    #[error(
        "corpus digest mismatch: the submitted bytes hash to {actual}, but the signed manifest declares {declared}"
    )]
    CorpusDigestMismatch { declared: String, actual: String },
    #[error("shadow corpus schema '{0}': expected {SHADOW_CORPUS_SCHEMA_V1}")]
    CorpusSchema(String),
    #[error("the corpus names '{actual}' but the signed manifest declares corpus '{declared}'")]
    CorpusIdMismatch { declared: String, actual: String },
    #[error(
        "the corpus file's cases do not match the cases the manifest declares under signature: a replay would prove the pack against operations it never promised"
    )]
    CorpusCasesMismatch,
    #[error("malformed shadow corpus: {0}")]
    CorpusMalformed(String),
    #[error("a replay compares two runs of the same corpus; got {first} and {second} observations")]
    RunLengthMismatch { first: usize, second: usize },
    #[error("the two runs replayed different corpora ('{first}' and '{second}')")]
    RunCorpusMismatch { first: String, second: String },
}

/// Parse and check a shadow corpus against what the manifest declared.
///
/// Takes bytes rather than a parsed value because the declared digest is
/// over bytes: re-serialising a `serde_json::Value` and hashing that would
/// compare a normalisation of the corpus to the publisher's original, and
/// the two differ on whitespace alone.
pub fn load_corpus(bytes: &[u8], declared: &ReplayCorpus) -> Result<LoadedCorpus, ReplayError> {
    let sha256 = hex::encode(Sha256::digest(bytes));
    if sha256 != declared.sha256 {
        return Err(ReplayError::CorpusDigestMismatch {
            declared: declared.sha256.clone(),
            actual: sha256,
        });
    }
    let corpus: ShadowCorpus =
        serde_json::from_slice(bytes).map_err(|err| ReplayError::CorpusMalformed(err.to_string()))?;
    if corpus.schema != SHADOW_CORPUS_SCHEMA_V1 {
        return Err(ReplayError::CorpusSchema(corpus.schema));
    }
    if corpus.corpus_id != declared.corpus_id {
        return Err(ReplayError::CorpusIdMismatch {
            declared: declared.corpus_id.clone(),
            actual: corpus.corpus_id,
        });
    }
    if corpus.cases.len() != declared.cases.len()
        || corpus.cases.iter().zip(&declared.cases).any(|(have, want)| {
            have.case_id != want.case_id || have.tool_name != want.tool_name || have.args != want.args
        })
    {
        return Err(ReplayError::CorpusCasesMismatch);
    }
    Ok(LoadedCorpus { corpus, sha256 })
}

// ── What a replay measures ───────────────────────────────────────────────

/// Everything a replay measures that is a function of the pack's behaviour
/// rather than of the machine it ran on. Digested.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayMeasurements {
    pub observed_fact_writes: usize,
    pub max_fact_writes_in_a_call: u32,
    /// Writes the grant filter refused. Non-zero means the pack attempted a
    /// write outside the scope it holds.
    pub dropped_fact_writes: usize,
    pub tokens_total: u32,
    pub max_tokens_in_a_call: u32,
    pub max_response_bytes_in_a_call: u32,
    /// Shortest freshness half-life among the facts the pack would write,
    /// in seconds. `u64::MAX` means every write is in a never-decaying
    /// class, which satisfies any declared floor.
    pub min_half_life_seconds: u64,
    /// Freshness refreshes the pack performed on facts it did not write.
    ///
    /// Always zero, and recorded rather than skipped: the staged
    /// external-tool response shape carries `fact_writes` and nothing else,
    /// so a pack has no channel through which to refresh someone else's
    /// fact. Stating the observed value keeps the declared bound evaluable
    /// instead of quietly unchecked.
    pub refreshes_per_call: u32,
    /// Unresolved contradiction candidates the store's own pass reports
    /// before and after the pack's writes are applied. This catches the
    /// coexisting-conflict shape (two active facts under one `(entity, key)`
    /// with opposite polarity).
    pub contradiction_candidates_before: usize,
    pub contradiction_candidates_after: usize,
    /// Writes that reverse the polarity of the fact they displace — the
    /// pack asserting the opposite of what the corpus held, under the same
    /// `(entity, key)`. The store's contradiction pass cannot see this one:
    /// a same-key write supersedes its predecessor, so the two never
    /// coexist, and a silent rewrite would otherwise read as clean.
    pub polarity_flips: usize,
    /// New contradictions — candidates plus silent rewrites — per million
    /// facts written, matching the envelope's unit. Zero when the pack
    /// writes nothing.
    pub contradiction_rate_ppm: u32,
    pub recall: RecallOutcome,
    pub rollback: RollbackOutcome,
}

/// Wall-clock values. Reported because the declared envelope bounds
/// latency; kept out of [`ReplayRecord::record_digest`] and out of the
/// verdict because they differ on every run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimingMeasurements {
    pub max_latency_ms_in_a_call: u64,
    pub latency_ms_total: u64,
    /// Wall-clock cost of reversing the pack's writes in the shadow store.
    pub undo_latency_ms: u64,
}

/// Recall and citation behaviour over the corpus's probes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecallOutcome {
    pub probes: usize,
    pub satisfied_before: usize,
    pub satisfied_after: usize,
    /// Probes satisfied before the pack's writes and not after — the
    /// citations the pack cost the corpus.
    pub regressed: Vec<String>,
}

/// What reversing the pack's writes cost, and whether it worked.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackOutcome {
    /// One supersession per observed write. A write that displaced an
    /// existing version is reversed by retiring the pack's version and
    /// un-retiring the one it displaced; a write that created a new
    /// `(entity, key)` is reversed by a tombstone. Both are one reversal of
    /// one write, which is the unit the declared `undo` bound counts.
    pub operations: usize,
    pub max_operations_in_a_call: u32,
    /// Whether the shadow store's active projection came back to exactly
    /// what it was before the pack's writes were applied.
    pub restored: bool,
    /// Entities still differing from the seeded projection after the
    /// reversal. Empty when `restored`.
    pub residual_entities: Vec<String>,
}

// ── Findings and verdict ─────────────────────────────────────────────────

/// One declared bound the observed behaviour left.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvelopeViolation {
    /// Dotted path of the bound in `pack.conformance.v1`, e.g.
    /// `envelope.max_fact_writes_per_call`.
    pub bound: String,
    pub declared: u64,
    pub observed: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
}

/// Whether one declared invariant held, and why not when it did not.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvariantResult {
    pub invariant_id: String,
    pub kind: InvariantKind,
    pub held: bool,
    /// Deterministic explanation. Carries the observed value, never a
    /// timestamp or a pointer, so two runs of the same pack produce the
    /// same text.
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReplayVerdict {
    /// Observed behaviour stayed inside the declared envelope, every
    /// declared invariant held, and the replay was stable.
    Pass,
    /// At least one of those failed. The pack does not go live.
    Blocked,
}

impl ReplayVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Blocked => "blocked",
        }
    }
}

/// The complete, reproducible record of one shadow replay.
///
/// `PartialEq` without `Eq` because a carried observation's fact writes
/// hold a confidence float; equality here is used to compare records, never
/// to key them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayRecord {
    pub schema: String,
    pub pack: PackAttribution,
    /// Always [`PackLifecycleState::Staged`] — carried so a stored record is
    /// self-describing rather than relying on the reader knowing the
    /// precondition.
    pub lifecycle: PackLifecycleState,
    pub corpus_id: String,
    pub corpus_sha256: String,
    pub started_at_unix_ms: u64,
    /// [`ConformanceRun::observed_digest`] of the first run — the identity
    /// of the behaviour that was judged.
    pub observed_digest: String,
    /// Whether the second run reproduced the first bit-for-bit.
    pub replay_stable: bool,
    /// Every observation, in declaration order: the complete observed
    /// behaviour, not a summary of it.
    pub observations: Vec<ConformanceObservation>,
    pub measurements: ReplayMeasurements,
    pub timings: TimingMeasurements,
    /// Blocking findings: bounds that are functions of behaviour.
    pub violations: Vec<EnvelopeViolation>,
    /// Non-blocking findings: wall-clock bounds. See the module docs.
    pub advisories: Vec<EnvelopeViolation>,
    pub invariant_results: Vec<InvariantResult>,
    pub verdict: ReplayVerdict,
    /// BLAKE3 over everything above except the clock-derived values.
    pub record_digest: String,
}

impl ReplayRecord {
    /// Why the verdict is what it is, in a form an operator and an audit row
    /// can both read. Deterministic and ordered.
    pub fn verdict_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if !self.replay_stable {
            reasons.push(
                "replay was not reproducible: two runs of the same pack against the same corpus disagreed".to_string(),
            );
        }
        for violation in &self.violations {
            reasons.push(match &violation.case_id {
                Some(case_id) => format!(
                    "{} declared {} but case '{}' observed {}",
                    violation.bound, violation.declared, case_id, violation.observed
                ),
                None => format!(
                    "{} declared {} but the run observed {}",
                    violation.bound, violation.declared, violation.observed
                ),
            });
        }
        for result in self.invariant_results.iter().filter(|r| !r.held) {
            reasons.push(format!(
                "invariant '{}' ({}) failed: {}",
                result.invariant_id,
                result.kind.as_str(),
                result.detail
            ));
        }
        reasons
    }
}

// ── The harness ──────────────────────────────────────────────────────────

/// Everything one evaluation needs. Two conformance runs, because
/// reproducibility is a property of the pack that can only be observed by
/// running it twice.
pub struct ReplayInput<'a> {
    pub pack: PackAttribution,
    pub manifest: &'a IntegrationManifest,
    pub corpus: &'a LoadedCorpus,
    pub first: &'a ConformanceRun,
    pub second: &'a ConformanceRun,
    pub started_at_unix_ms: u64,
}

/// Judge a staged pack's replayed behaviour against what it declared.
///
/// Pure apart from the in-memory shadow store it builds and drops: given
/// the same runs and the same corpus it returns the same record, which is
/// what makes [`ReplayRecord::record_digest`] worth signing in M2.
pub fn evaluate(input: ReplayInput<'_>) -> Result<ReplayRecord, ReplayError> {
    let ReplayInput {
        pack,
        manifest,
        corpus,
        first,
        second,
        started_at_unix_ms,
    } = input;

    let declaration = manifest
        .conformance
        .as_ref()
        .ok_or_else(|| ReplayError::NoDeclaration(manifest.id.clone()))?;
    if first.lifecycle != PackLifecycleState::Staged {
        return Err(ReplayError::NotStaged(manifest.id.clone(), first.lifecycle.as_str()));
    }
    if first.observations.len() != second.observations.len() {
        return Err(ReplayError::RunLengthMismatch {
            first: first.observations.len(),
            second: second.observations.len(),
        });
    }
    if first.corpus_id != second.corpus_id {
        return Err(ReplayError::RunCorpusMismatch {
            first: first.corpus_id.clone(),
            second: second.corpus_id.clone(),
        });
    }

    let replay_stable = first.observed_digest == second.observed_digest;
    let (measurements, timings) = measure(&corpus.corpus, first);
    let mut violations = envelope_violations(&declaration.envelope, first, &measurements);
    violations.sort_by(|a, b| (&a.bound, &a.case_id).cmp(&(&b.bound, &b.case_id)));
    let advisories = timing_advisories(&declaration.envelope, first, &timings);
    let invariant_results = evaluate_invariants(declaration, manifest, &corpus.corpus, first, second, &measurements);

    let verdict = if violations.is_empty() && replay_stable && invariant_results.iter().all(|result| result.held) {
        ReplayVerdict::Pass
    } else {
        ReplayVerdict::Blocked
    };

    let mut record = ReplayRecord {
        schema: REPLAY_RECORD_SCHEMA_V1.to_string(),
        pack,
        lifecycle: PackLifecycleState::Staged,
        corpus_id: corpus.corpus.corpus_id.clone(),
        corpus_sha256: corpus.sha256.clone(),
        started_at_unix_ms,
        observed_digest: first.observed_digest.clone(),
        replay_stable,
        observations: first.observations.clone(),
        measurements,
        timings,
        violations,
        advisories,
        invariant_results,
        verdict,
        record_digest: String::new(),
    };
    record.record_digest = record_digest(&record);
    Ok(record)
}

/// BLAKE3 over the reproducible half of the record.
///
/// Built from an explicit projection rather than from the serialized
/// record, so a later reporting field cannot silently change every
/// previously computed digest — adding one here has to be a deliberate,
/// reviewable diff. `started_at_unix_ms`, `timings`, `advisories` and the
/// per-observation `duration_ms` are excluded because they are properties
/// of the machine, not of the pack.
fn record_digest(record: &ReplayRecord) -> String {
    let observations: Vec<serde_json::Value> = record
        .observations
        .iter()
        .map(|observation| {
            serde_json::json!({
                "case_id": observation.case_id,
                "tool_name": observation.tool_name,
                "status": observation.status,
                "observed_fact_writes": observation.observed_fact_writes,
                "dropped_fact_writes": observation.dropped_fact_writes,
                "result_hash": observation.result_hash,
                "result_bytes": observation.result_bytes,
                "error": observation.error,
            })
        })
        .collect();
    let projection = serde_json::json!({
        "schema": record.schema,
        "pack": record.pack,
        "lifecycle": record.lifecycle,
        "corpus_id": record.corpus_id,
        "corpus_sha256": record.corpus_sha256,
        "observed_digest": record.observed_digest,
        "replay_stable": record.replay_stable,
        "observations": observations,
        "measurements": record.measurements,
        "violations": record.violations,
        "invariant_results": record.invariant_results,
        "verdict": record.verdict,
    });
    let bytes = serde_json::to_vec(&projection).unwrap_or_default();
    format!("blake3:{}", blake3::hash(&bytes).to_hex())
}

/// Seed an in-memory store from the corpus. Local, offline, dropped when
/// the replay ends.
fn seed_store(corpus: &ShadowCorpus) -> FactStore {
    let mut store = FactStore::new();
    for seed in &corpus.seed_facts {
        store.store(StoreFact {
            tenant_hash: SHADOW_TENANT.to_string(),
            entity: seed.entity.clone(),
            key: seed.key.clone(),
            value: seed.value.clone(),
            source_receipt: None,
            confidence: seed.confidence,
            private: seed.private,
            horizon_class: None,
            actor: None,
        });
    }
    store
}

/// The store's active facts, as a sorted, comparable projection. Fact ids
/// and versions are deliberately excluded: an append-only store cannot
/// return to a previous *fact id* after a reversal, and demanding that
/// would make every rollback look broken. What must come back is the
/// visible content.
fn active_projection(store: &FactStore) -> Vec<String> {
    let mut rows: Vec<String> = store
        .all_facts()
        .filter(|fact| !fact.deleted && fact.superseded_by.is_none() && fact.tenant_hash == SHADOW_TENANT)
        .map(|fact| {
            format!(
                "{}\u{1f}{}\u{1f}{}\u{1f}{:.6}\u{1f}{}",
                fact.entity, fact.key, fact.value, fact.confidence, fact.private
            )
        })
        .collect();
    rows.sort();
    rows
}

fn store_fact_from(observed: &ObservedFactWrite) -> StoreFact {
    StoreFact {
        tenant_hash: SHADOW_TENANT.to_string(),
        entity: observed.entity.clone(),
        key: observed.key.clone(),
        value: observed.value.clone(),
        source_receipt: None,
        confidence: observed.confidence,
        private: observed.private,
        horizon_class: None,
        actor: observed.actor.clone(),
    }
}

/// Freshness half-life of a fact the pack would write, in seconds.
///
/// The staged write path sets no explicit horizon class, so a live write
/// would take the entity-derived default — which is what is measured here,
/// rather than a value the replay invents.
fn half_life_seconds(entity: &str) -> u64 {
    let policy = corecrux_projections::decay::DecayPolicy::default_const();
    match HorizonClass::default_for_entity(entity) {
        HorizonClass::Volatile => policy.volatile_stale_hours.max(0) as u64 * 3_600,
        HorizonClass::Medium => policy.medium_stale_days.max(0) as u64 * 86_400,
        HorizonClass::Stable => policy.stable_stale_days.max(0) as u64 * 86_400,
        HorizonClass::None => u64::MAX,
    }
}

fn estimated_tokens(bytes: usize) -> u32 {
    u32::try_from(bytes.div_ceil(BYTES_PER_TOKEN)).unwrap_or(u32::MAX)
}

fn count_contradictions(store: &FactStore) -> usize {
    store.contradiction_candidates_v1(SHADOW_TENANT, 0).len()
}

/// Writes that reverse the polarity of the value they are about to displace.
///
/// Counted *before* the writes land, because the store chains a same-key
/// write onto its predecessor and retires it — so afterwards the two never
/// coexist and the store's own contradiction pass, which looks for two
/// active facts under one `(entity, key)`, correctly reports nothing. A
/// pack that silently rewrites `active` to `inactive` has still contradicted
/// memory, and that is the shape this catches.
fn count_polarity_flips(store: &FactStore, writes: &[StoreFact]) -> usize {
    writes
        .iter()
        .filter(|write| {
            let Some(incoming) = polarity_class_v1(&write.value) else {
                return false;
            };
            let existing = store.query(&FactQuery {
                query: None,
                entity: Some(write.entity.clone()),
                tenant_hash: Some(SHADOW_TENANT.to_string()),
                entity_prefix: None,
                top_k: PROBE_TOP_K,
                token_budget: None,
                min_effective_confidence: None,
            });
            existing
                .facts
                .iter()
                .filter(|fact| fact.key == write.key && fact.superseded_by.is_none())
                .filter_map(|fact| polarity_class_v1(&fact.value))
                .any(|held| held != incoming)
        })
        .count()
}

fn satisfied_probes(store: &FactStore, probes: &[RecallProbe]) -> Vec<String> {
    probes
        .iter()
        .filter(|probe| {
            let result = store.query(&FactQuery {
                query: Some(probe.query.clone()),
                entity: None,
                tenant_hash: Some(SHADOW_TENANT.to_string()),
                entity_prefix: None,
                top_k: PROBE_TOP_K,
                token_budget: None,
                min_effective_confidence: None,
            });
            probe.expect_entities.iter().all(|expected| {
                // Latest-version-wins and never-private, mirroring what the
                // recall surfaces (`query_facts`, `GET /v1/facts`) return.
                // `FactStore::query` keeps superseded versions so a caller
                // can badge them; a probe that counted one would report a
                // fact as citable after the pack had overwritten it.
                result
                    .facts
                    .iter()
                    .any(|fact| &fact.entity == expected && !fact.private && fact.superseded_by.is_none())
            })
        })
        .map(|probe| probe.probe_id.clone())
        .collect()
}

/// Run the corpus through a shadow store and measure what the pack did to
/// it: recall before and after, contradictions introduced, and whether the
/// writes reverse cleanly.
fn measure(corpus: &ShadowCorpus, run: &ConformanceRun) -> (ReplayMeasurements, TimingMeasurements) {
    let mut store = seed_store(corpus);
    let before_projection = active_projection(&store);
    let contradiction_candidates_before = count_contradictions(&store);
    let satisfied_before = satisfied_probes(&store, &corpus.probes);

    let mut max_fact_writes_in_a_call = 0u32;
    let mut tokens_total = 0u32;
    let mut max_tokens_in_a_call = 0u32;
    let mut max_response_bytes_in_a_call = 0u32;
    let mut max_latency_ms_in_a_call = 0u64;
    let mut min_half_life_seconds = u64::MAX;
    let mut writes: Vec<StoreFact> = Vec::new();

    for observation in &run.observations {
        let per_call = u32::try_from(observation.observed_fact_writes.len()).unwrap_or(u32::MAX);
        max_fact_writes_in_a_call = max_fact_writes_in_a_call.max(per_call);
        let tokens = estimated_tokens(observation.result_bytes);
        tokens_total = tokens_total.saturating_add(tokens);
        max_tokens_in_a_call = max_tokens_in_a_call.max(tokens);
        max_response_bytes_in_a_call =
            max_response_bytes_in_a_call.max(u32::try_from(observation.result_bytes).unwrap_or(u32::MAX));
        max_latency_ms_in_a_call = max_latency_ms_in_a_call.max(observation.duration_ms);
        for write in &observation.observed_fact_writes {
            min_half_life_seconds = min_half_life_seconds.min(half_life_seconds(&write.entity));
            writes.push(store_fact_from(write));
        }
    }

    let observed_fact_writes = writes.len();
    let polarity_flips = count_polarity_flips(&store, &writes);
    let applied = store.store_bulk(writes);
    let contradiction_candidates_after = count_contradictions(&store);
    let satisfied_after = satisfied_probes(&store, &corpus.probes);

    // Reverse, newest first, using the substrate's own primitives: retire
    // the pack's version and un-retire whatever it displaced, or tombstone
    // a write that displaced nothing.
    let undo_started = std::time::Instant::now();
    for fact in applied.iter().rev() {
        match &fact.supersedes {
            Some(prior) => {
                store.mark_superseded(SHADOW_TENANT, &fact.fact_id, prior);
                store.clear_superseded(SHADOW_TENANT, prior);
            }
            None => {
                store.delete(SHADOW_TENANT, &fact.fact_id);
            }
        }
    }
    let undo_latency_ms = undo_started.elapsed().as_millis() as u64;

    let after_projection = active_projection(&store);
    let residual_entities = projection_difference(&before_projection, &after_projection);

    let regressed: Vec<String> = satisfied_before
        .iter()
        .filter(|probe_id| !satisfied_after.contains(*probe_id))
        .cloned()
        .collect();

    let new_contradictions = contradiction_candidates_after
        .saturating_sub(contradiction_candidates_before)
        .saturating_add(polarity_flips);
    let contradiction_rate_ppm = if observed_fact_writes == 0 {
        0
    } else {
        u32::try_from((new_contradictions as u64 * u64::from(PPM_DENOMINATOR)) / observed_fact_writes as u64)
            .unwrap_or(u32::MAX)
    };

    let measurements = ReplayMeasurements {
        observed_fact_writes,
        max_fact_writes_in_a_call,
        dropped_fact_writes: run.totals.dropped_fact_writes,
        tokens_total,
        max_tokens_in_a_call,
        max_response_bytes_in_a_call,
        min_half_life_seconds,
        refreshes_per_call: 0,
        contradiction_candidates_before,
        contradiction_candidates_after,
        polarity_flips,
        contradiction_rate_ppm,
        recall: RecallOutcome {
            probes: corpus.probes.len(),
            satisfied_before: satisfied_before.len(),
            satisfied_after: satisfied_after.len(),
            regressed,
        },
        rollback: RollbackOutcome {
            operations: observed_fact_writes,
            max_operations_in_a_call: max_fact_writes_in_a_call,
            restored: residual_entities.is_empty(),
            residual_entities,
        },
    };
    let timings = TimingMeasurements {
        max_latency_ms_in_a_call,
        latency_ms_total: run.totals.duration_ms,
        undo_latency_ms,
    };
    (measurements, timings)
}

/// Entities present in exactly one of the two projections, sorted and
/// deduplicated — the residue a reversal left behind.
fn projection_difference(before: &[String], after: &[String]) -> Vec<String> {
    let before_set: std::collections::BTreeSet<&String> = before.iter().collect();
    let after_set: std::collections::BTreeSet<&String> = after.iter().collect();
    let mut entities: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for row in before_set.symmetric_difference(&after_set) {
        let entity = row.split('\u{1f}').next().unwrap_or_default();
        entities.insert(entity.to_string());
    }
    entities.into_iter().collect()
}

fn violation(bound: &str, declared: u64, observed: u64, case_id: Option<&str>) -> EnvelopeViolation {
    EnvelopeViolation {
        bound: bound.to_string(),
        declared,
        observed,
        case_id: case_id.map(str::to_string),
    }
}

/// Bounds that are functions of the pack's behaviour. These block.
fn envelope_violations(
    envelope: &BehaviouralEnvelope,
    run: &ConformanceRun,
    measurements: &ReplayMeasurements,
) -> Vec<EnvelopeViolation> {
    let mut violations = Vec::new();

    for observation in &run.observations {
        let tokens = estimated_tokens(observation.result_bytes);
        if tokens > envelope.max_tokens_per_call {
            violations.push(violation(
                "envelope.max_tokens_per_call",
                u64::from(envelope.max_tokens_per_call),
                u64::from(tokens),
                Some(&observation.case_id),
            ));
        }
        let bytes = u64::try_from(observation.result_bytes).unwrap_or(u64::MAX);
        if bytes > u64::from(envelope.max_response_bytes_per_call) {
            violations.push(violation(
                "envelope.max_response_bytes_per_call",
                u64::from(envelope.max_response_bytes_per_call),
                bytes,
                Some(&observation.case_id),
            ));
        }
        let writes = u64::try_from(observation.observed_fact_writes.len()).unwrap_or(u64::MAX);
        if writes > u64::from(envelope.max_fact_writes_per_call) {
            violations.push(violation(
                "envelope.max_fact_writes_per_call",
                u64::from(envelope.max_fact_writes_per_call),
                writes,
                Some(&observation.case_id),
            ));
        }
    }

    if measurements.tokens_total > envelope.max_tokens_per_run {
        violations.push(violation(
            "envelope.max_tokens_per_run",
            u64::from(envelope.max_tokens_per_run),
            u64::from(measurements.tokens_total),
            None,
        ));
    }
    if measurements.min_half_life_seconds < envelope.decay.min_half_life_seconds {
        violations.push(violation(
            "envelope.decay.min_half_life_seconds",
            envelope.decay.min_half_life_seconds,
            measurements.min_half_life_seconds,
            None,
        ));
    }
    if measurements.refreshes_per_call > envelope.decay.max_refreshes_per_call {
        violations.push(violation(
            "envelope.decay.max_refreshes_per_call",
            u64::from(envelope.decay.max_refreshes_per_call),
            u64::from(measurements.refreshes_per_call),
            None,
        ));
    }
    if measurements.contradiction_rate_ppm > envelope.max_contradiction_rate_ppm {
        violations.push(violation(
            "envelope.max_contradiction_rate_ppm",
            u64::from(envelope.max_contradiction_rate_ppm),
            u64::from(measurements.contradiction_rate_ppm),
            None,
        ));
    }
    if measurements.rollback.max_operations_in_a_call > envelope.undo.max_operations_per_call {
        violations.push(violation(
            "envelope.undo.max_operations_per_call",
            u64::from(envelope.undo.max_operations_per_call),
            u64::from(measurements.rollback.max_operations_in_a_call),
            None,
        ));
    }
    violations
}

/// Wall-clock bounds. Reported, never blocking — see the module docs.
fn timing_advisories(
    envelope: &BehaviouralEnvelope,
    run: &ConformanceRun,
    timings: &TimingMeasurements,
) -> Vec<EnvelopeViolation> {
    let mut advisories = Vec::new();
    for observation in &run.observations {
        if observation.duration_ms > u64::from(envelope.max_latency_ms_per_call) {
            advisories.push(violation(
                "envelope.max_latency_ms_per_call",
                u64::from(envelope.max_latency_ms_per_call),
                observation.duration_ms,
                Some(&observation.case_id),
            ));
        }
    }
    if timings.latency_ms_total > u64::from(envelope.max_latency_ms_per_run) {
        advisories.push(violation(
            "envelope.max_latency_ms_per_run",
            u64::from(envelope.max_latency_ms_per_run),
            timings.latency_ms_total,
            None,
        ));
    }
    if timings.undo_latency_ms > u64::from(envelope.undo.max_latency_ms) {
        advisories.push(violation(
            "envelope.undo.max_latency_ms",
            u64::from(envelope.undo.max_latency_ms),
            timings.undo_latency_ms,
            None,
        ));
    }
    advisories
}

/// Observations of the cases one invariant applies to. An empty
/// `applies_to_cases` means every case.
fn cases_in_scope<'a>(invariant_cases: &[String], run: &'a ConformanceRun) -> Vec<&'a ConformanceObservation> {
    run.observations
        .iter()
        .filter(|observation| invariant_cases.is_empty() || invariant_cases.contains(&observation.case_id))
        .collect()
}

/// Does this write fall under a declared fact mutation?
fn write_is_declared(write: &ObservedFactWrite, declared: &[ExpectedFactMutation]) -> bool {
    declared.iter().any(|mutation| {
        write.entity.starts_with(&mutation.entity_prefix)
            && (mutation.keys.is_empty() || mutation.keys.contains(&write.key))
            && write.private == mutation.private
    })
}

fn evaluate_invariants(
    declaration: &PackConformance,
    manifest: &IntegrationManifest,
    corpus: &ShadowCorpus,
    first: &ConformanceRun,
    second: &ConformanceRun,
    measurements: &ReplayMeasurements,
) -> Vec<InvariantResult> {
    declaration
        .invariants
        .iter()
        .map(|invariant| {
            let scope = cases_in_scope(&invariant.applies_to_cases, first);
            let (held, detail) = match invariant.kind {
                InvariantKind::NoUndeclaredFactWrites => {
                    let undeclared: Vec<String> = scope
                        .iter()
                        .flat_map(|observation| observation.observed_fact_writes.iter())
                        .filter(|write| !write_is_declared(write, &declaration.expected_mutations.facts))
                        .map(|write| format!("{}::{}", write.entity, write.key))
                        .collect();
                    if undeclared.is_empty() {
                        (true, "every observed write fell under a declared prefix".to_string())
                    } else {
                        (false, format!("undeclared writes: {}", undeclared.join(", ")))
                    }
                }
                InvariantKind::NoPrivateFactAccess => {
                    // Two checkable halves. The pack must not hold the
                    // data-access grant that would let the daemon hand it a
                    // private fact, and no private seed's content may come
                    // back out through a write. What happens inside the
                    // pack is not observable from here; what leaves it is.
                    if manifest.data_access.private_facts {
                        (
                            false,
                            "manifest data_access.private_facts is true, so the pack can be handed private facts"
                                .to_string(),
                        )
                    } else {
                        let leaked: Vec<String> = corpus
                            .seed_facts
                            .iter()
                            .filter(|seed| seed.private)
                            .filter(|seed| {
                                scope.iter().any(|observation| {
                                    observation
                                        .observed_fact_writes
                                        .iter()
                                        .any(|write| write.value.contains(&seed.value))
                                })
                            })
                            .map(|seed| format!("{}::{}", seed.entity, seed.key))
                            .collect();
                        if leaked.is_empty() {
                            (
                                true,
                                "no private-facts grant, and no private seed re-surfaced in a write".to_string(),
                            )
                        } else {
                            (false, format!("private seed content re-surfaced: {}", leaked.join(", ")))
                        }
                    }
                }
                InvariantKind::NoUndeclaredCapabilityUse => {
                    let dropped: usize = scope.iter().map(|observation| observation.dropped_fact_writes).sum();
                    if dropped == 0 {
                        (true, "the grant filter refused nothing".to_string())
                    } else {
                        (
                            false,
                            format!("{dropped} write(s) refused by the grant filter: the pack reached outside its scope"),
                        )
                    }
                }
                InvariantKind::NoEgressOutsideAllowlist => {
                    // The transport refuses an off-allowlist host before the
                    // call leaves, so a replay cannot observe a violation
                    // directly. What it can establish is that the allowlist
                    // is a real constraint: non-empty, and covering the
                    // pack's own endpoint rather than being widened past it.
                    let endpoint_host = manifest
                        .external_tool_endpoint
                        .as_deref()
                        .and_then(host_of)
                        .unwrap_or_default();
                    if manifest.network.allowed_hosts.is_empty() {
                        (false, "network.allowed_hosts is empty, so no egress is pinned".to_string())
                    } else if !endpoint_host.is_empty() && !manifest.network.allowed_hosts.iter().any(|host| host == endpoint_host) {
                        (
                            false,
                            format!("endpoint host '{endpoint_host}' is not in network.allowed_hosts"),
                        )
                    } else {
                        (
                            true,
                            format!(
                                "egress pinned to {} host(s); the transport refuses anything else",
                                manifest.network.allowed_hosts.len()
                            ),
                        )
                    }
                }
                InvariantKind::DeterministicReplay => {
                    let differing: Vec<String> = first
                        .observations
                        .iter()
                        .zip(&second.observations)
                        .filter(|(a, _)| invariant.applies_to_cases.is_empty() || invariant.applies_to_cases.contains(&a.case_id))
                        .filter(|(a, b)| !observations_agree(a, b))
                        .map(|(a, _)| a.case_id.clone())
                        .collect();
                    if differing.is_empty() {
                        (true, "both runs observed the same behaviour".to_string())
                    } else {
                        (false, format!("cases differed between runs: {}", differing.join(", ")))
                    }
                }
                InvariantKind::ReversibleWrites => {
                    if measurements.rollback.restored {
                        (
                            true,
                            format!(
                                "{} write(s) reversed; the shadow store returned to its seeded state",
                                measurements.rollback.operations
                            ),
                        )
                    } else {
                        (
                            false,
                            format!(
                                "reversal left residue in: {}",
                                measurements.rollback.residual_entities.join(", ")
                            ),
                        )
                    }
                }
                InvariantKind::NoNewContradictions => {
                    let new_candidates = measurements
                        .contradiction_candidates_after
                        .saturating_sub(measurements.contradiction_candidates_before);
                    if new_candidates == 0 && measurements.polarity_flips == 0 {
                        (
                            true,
                            format!(
                                "contradiction candidates unchanged at {}, no write reversed a stored value",
                                measurements.contradiction_candidates_before
                            ),
                        )
                    } else {
                        (
                            false,
                            format!(
                                "{new_candidates} new contradiction candidate(s) and {} silent rewrite(s), {} ppm of writes",
                                measurements.polarity_flips, measurements.contradiction_rate_ppm
                            ),
                        )
                    }
                }
            };
            InvariantResult {
                invariant_id: invariant.id.clone(),
                kind: invariant.kind,
                held,
                detail,
            }
        })
        .collect()
}

/// Two observations of the same case agree when everything except the
/// clock does.
fn observations_agree(a: &ConformanceObservation, b: &ConformanceObservation) -> bool {
    a.case_id == b.case_id
        && a.tool_name == b.tool_name
        && a.status == b.status
        && a.observed_fact_writes == b.observed_fact_writes
        && a.dropped_fact_writes == b.dropped_fact_writes
        && a.result_hash == b.result_hash
        && a.result_bytes == b.result_bytes
        && a.error == b.error
}

/// Host of a URL, without pulling in a URL parser for one field.
fn host_of(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host.split_once(':').map_or(host, |(h, _)| h);
    (!host.is_empty()).then_some(host)
}

// ── Storage ──────────────────────────────────────────────────────────────

fn replay_entity_for(extension_id: &str) -> String {
    format!("{EXTENSION_ENTITY_PREFIX}::{extension_id}")
}

/// Persist the record beside the pack's install record.
///
/// One `store` of `__extension__::{id}` / `replay`, which is a new *version*
/// of the same fact — so a re-replay leaves the previous verdict in the
/// supersession chain rather than erasing it, and the `__extension__::`
/// prefix carries the reserved-prefix privacy posture the install record
/// already has. No new on-disk artifact type, so no four-point wiring.
pub fn put_replay_record(store: &mut FactStore, record: &ReplayRecord) -> Result<(), serde_json::Error> {
    let mut sf = StoreFact {
        tenant_hash: SHADOW_TENANT.to_string(),
        entity: replay_entity_for(&record.pack.extension_id),
        key: REPLAY_RECORD_KEY.to_string(),
        value: serde_json::to_string(record)?,
        source_receipt: None,
        confidence: 1.0,
        private: false,
        horizon_class: None,
        actor: None,
    };
    crate::fact_privacy::enforce_global(&mut sf);
    store.store(sf);
    Ok(())
}

/// The most recent replay record for a pack, if one exists.
pub fn get_replay_record(store: &FactStore, extension_id: &str) -> Option<ReplayRecord> {
    let result = store.query(&FactQuery {
        query: None,
        entity: Some(replay_entity_for(extension_id)),
        tenant_hash: Some(SHADOW_TENANT.to_string()),
        entity_prefix: None,
        top_k: 8,
        token_budget: None,
        min_effective_confidence: None,
    });
    result
        .facts
        .iter()
        .filter(|fact| fact.key == REPLAY_RECORD_KEY && !fact.deleted)
        .max_by_key(|fact| fact.version)
        .and_then(|fact| serde_json::from_str(&fact.value).ok())
}

// ── The pre-enable gate ──────────────────────────────────────────────────

/// Whether a failed replay refuses activation or merely reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivationGate {
    /// Refuse to take a pack live when its replay did not pass.
    Enforced,
    /// Report and permit. The default, per the plan's advisory-first
    /// rollout.
    Advisory,
}

impl ActivationGate {
    /// Read `CORECRUXD_PACK_REPLAY_GATE`. Called at the HTTP boundary
    /// (mirroring [`crate::pack_lifecycle::default_install_state`]) so the
    /// domain functions stay pure functions of their arguments and tests
    /// never race on process env.
    pub fn from_env() -> Self {
        let enforced = std::env::var(REPLAY_GATE_ENV)
            .map(|value| matches!(value.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        if enforced {
            Self::Enforced
        } else {
            Self::Advisory
        }
    }
}

/// Why activation was refused.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[error("pack '{extension_id}' cannot go live: {reason}")]
pub struct ActivationBlocked {
    pub extension_id: String,
    pub reason: String,
    /// The record the refusal is based on, when there was one. Absent when
    /// the pack has never been replayed.
    pub record_digest: Option<String>,
}

/// Decide whether a declaring pack has earned the right to be enabled.
///
/// A pack that ships no `pack.conformance.v1` block is never blocked: it
/// declared no envelope, so there is nothing a replay could contradict, and
/// blocking it would change the behaviour of every pack installed before
/// this milestone. A *declaring* pack must have a passing replay of the
/// exact build being enabled — matching by `manifest_hash`, not by version,
/// because a version can be re-cut with different bytes.
pub fn check_activation(
    store: &FactStore,
    extension_id: &str,
    manifest: &IntegrationManifest,
    manifest_hash: &str,
) -> Result<(), ActivationBlocked> {
    if manifest.conformance.is_none() {
        return Ok(());
    }
    let blocked = |reason: String, record_digest: Option<String>| ActivationBlocked {
        extension_id: extension_id.to_string(),
        reason,
        record_digest,
    };
    let Some(record) = get_replay_record(store, extension_id) else {
        return Err(blocked(
            "it declares a conformance envelope but has never been replayed against its shadow corpus — \
             run POST /v1/extensions/{id}/replay while it is staged"
                .to_string(),
            None,
        ));
    };
    if record.pack.manifest_hash != manifest_hash {
        return Err(blocked(
            format!(
                "the replay on record is of a different build ({}, not {})",
                record.pack.manifest_hash, manifest_hash
            ),
            Some(record.record_digest.clone()),
        ));
    }
    if record.verdict != ReplayVerdict::Pass {
        return Err(blocked(
            format!(
                "its replay against corpus '{}' was blocked: {}",
                record.corpus_id,
                record.verdict_reasons().join("; ")
            ),
            Some(record.record_digest.clone()),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack_conformance::{build_run, observe, StagedOperationOutcome};
    use crux_integrations::conformance::{
        CompatibilityAssertions, DecayEnvelope, DeclaredCase, ExpectedMutations, ExpectedReceiptMutation,
        FactMutationOp, InvariantTest, ReceiptMutationKind, UndoEnvelope, PACK_CONFORMANCE_SCHEMA_V1,
    };
    use crux_integrations::{
        DataAccess, EntryKind, ExternalToolDefinition, IntegrationEntry, ManifestHashes, NetworkAccess, SafetyPolicy,
        INTEGRATION_SCHEMA_V1,
    };

    const CORPUS_ID: &str = "shadow-notes-v1";
    const PREFIX: &str = "ext.example.notes::notes::";

    fn tool(name: &str) -> ExternalToolDefinition {
        ExternalToolDefinition {
            name: name.to_string(),
            description: String::new(),
            input_schema: serde_json::json!({}),
            consequence_metadata: None,
            auth_shared_secret_id: None,
        }
    }

    fn attribution() -> PackAttribution {
        PackAttribution::new(
            "ext.example.notes",
            "0.1.0",
            "blake3:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
        )
    }

    fn declared_cases() -> Vec<DeclaredCase> {
        vec![
            DeclaredCase {
                case_id: "recall".to_string(),
                tool_name: "ext.example.notes.recall".to_string(),
                args: serde_json::json!({}),
            },
            DeclaredCase {
                case_id: "remember".to_string(),
                tool_name: "ext.example.notes.remember".to_string(),
                args: serde_json::json!({ "note": "a pack proves what it does" }),
            },
        ]
    }

    fn corpus_document() -> serde_json::Value {
        serde_json::json!({
            "schema": SHADOW_CORPUS_SCHEMA_V1,
            "corpus_id": CORPUS_ID,
            "description": "Two seeded notes, one private, and a probe that must stay citable.",
            "seed_facts": [
                { "entity": "ext.example.notes::notes::seed-1", "key": "content", "value": "the kettle boils at 100C", "confidence": 1.0, "private": false },
                { "entity": "ext.example.notes::notes::seed-2", "key": "content", "value": "the shed door sticks", "confidence": 0.9, "private": false },
                { "entity": "personal::diary::2026-01-01", "key": "content", "value": "sealed-diary-line", "confidence": 1.0, "private": true }
            ],
            "probes": [
                { "probe_id": "kettle", "query": "kettle", "expect_entities": ["ext.example.notes::notes::seed-1"] }
            ],
            "cases": declared_cases(),
        })
    }

    /// Corpus bytes exactly as they would sit on disk, plus their digest.
    fn corpus_bytes() -> (Vec<u8>, String) {
        let mut bytes = serde_json::to_vec_pretty(&corpus_document()).expect("encode corpus");
        bytes.push(b'\n');
        let digest = hex::encode(Sha256::digest(&bytes));
        (bytes, digest)
    }

    fn loaded_corpus() -> LoadedCorpus {
        let (bytes, digest) = corpus_bytes();
        load_corpus(&bytes, &replay_corpus(digest)).expect("the fixture corpus must load")
    }

    fn replay_corpus(sha256: String) -> ReplayCorpus {
        ReplayCorpus {
            corpus_id: CORPUS_ID.to_string(),
            path: "replay-corpus.json".to_string(),
            sha256,
            cases: declared_cases(),
        }
    }

    fn declaration(sha256: String) -> PackConformance {
        PackConformance {
            schema: PACK_CONFORMANCE_SCHEMA_V1.to_string(),
            claimed_capabilities: vec!["facts:read".to_string(), "facts:write".to_string()],
            expected_mutations: ExpectedMutations {
                facts: vec![ExpectedFactMutation {
                    entity_prefix: PREFIX.to_string(),
                    keys: vec!["content".to_string()],
                    operation: FactMutationOp::Write,
                    private: false,
                    max_per_call: 1,
                }],
                receipts: vec![ExpectedReceiptMutation {
                    receipt_kind: ReceiptMutationKind::Dispatch,
                    max_per_call: 1,
                }],
            },
            replay_corpus: replay_corpus(sha256),
            invariants: vec![
                InvariantTest {
                    id: "writes-stay-in-namespace".to_string(),
                    description: "Every write lands under the declared prefix.".to_string(),
                    kind: InvariantKind::NoUndeclaredFactWrites,
                    applies_to_cases: Vec::new(),
                },
                InvariantTest {
                    id: "no-private-reads".to_string(),
                    description: "No private fact reaches the pack.".to_string(),
                    kind: InvariantKind::NoPrivateFactAccess,
                    applies_to_cases: Vec::new(),
                },
                InvariantTest {
                    id: "scope-respected".to_string(),
                    description: "The pack uses no capability it did not claim.".to_string(),
                    kind: InvariantKind::NoUndeclaredCapabilityUse,
                    applies_to_cases: Vec::new(),
                },
                InvariantTest {
                    id: "egress-pinned".to_string(),
                    description: "Egress stays on the allowlist.".to_string(),
                    kind: InvariantKind::NoEgressOutsideAllowlist,
                    applies_to_cases: Vec::new(),
                },
                InvariantTest {
                    id: "reads-are-deterministic".to_string(),
                    description: "Replaying a read twice yields the same behaviour.".to_string(),
                    kind: InvariantKind::DeterministicReplay,
                    applies_to_cases: Vec::new(),
                },
                InvariantTest {
                    id: "writes-are-reversible".to_string(),
                    description: "Every write reverses by supersession.".to_string(),
                    kind: InvariantKind::ReversibleWrites,
                    applies_to_cases: Vec::new(),
                },
                InvariantTest {
                    id: "no-new-contradictions".to_string(),
                    description: "The pack introduces no contradiction.".to_string(),
                    kind: InvariantKind::NoNewContradictions,
                    applies_to_cases: Vec::new(),
                },
            ],
            envelope: BehaviouralEnvelope {
                max_tokens_per_call: 512,
                max_tokens_per_run: 2_048,
                max_latency_ms_per_call: 2_000,
                max_latency_ms_per_run: 8_000,
                max_response_bytes_per_call: 16_384,
                max_fact_writes_per_call: 1,
                decay: DecayEnvelope {
                    min_half_life_seconds: 604_800,
                    max_refreshes_per_call: 0,
                },
                max_contradiction_rate_ppm: 0,
                undo: UndoEnvelope {
                    max_operations_per_call: 1,
                    max_latency_ms: 500,
                },
            },
            compatibility: CompatibilityAssertions {
                min_daemon_version: "0.5.0".to_string(),
                manifest_schema: INTEGRATION_SCHEMA_V1.to_string(),
                supersedes: Vec::new(),
                migrations: Vec::new(),
                rollback_safe: true,
            },
        }
    }

    fn manifest_with(declaration: Option<PackConformance>) -> IntegrationManifest {
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: "ext.example.notes".to_string(),
            name: "Notes".to_string(),
            version: "0.1.0".to_string(),
            publisher_passport_fpr: "p_alice".to_string(),
            summary: "Remembers notes.".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::ExternalTool,
                path: "tools/notes.json".to_string(),
            },
            capabilities: vec!["facts:read".to_string(), "facts:write".to_string()],
            network: NetworkAccess {
                allowed_hosts: vec!["notes.pack.invalid".to_string()],
                requires_user_token: false,
            },
            data_access: DataAccess {
                tenant_scopes: vec!["selected".to_string()],
                content_preview: false,
                private_facts: false,
            },
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
            external_tool_endpoint: Some("https://notes.pack.invalid/tools".to_string()),
            tools: vec![tool("ext.example.notes.recall"), tool("ext.example.notes.remember")],
            wasm_module_path: None,
            wasm_module_url: None,
            wasm_module_sha256: None,
            conformance: declaration,
        }
    }

    fn conforming_manifest() -> IntegrationManifest {
        let (_, digest) = corpus_bytes();
        manifest_with(Some(declaration(digest)))
    }

    fn case(id: &str, tool_name: &str) -> ConformanceCase {
        ConformanceCase {
            case_id: id.to_string(),
            tool_name: tool_name.to_string(),
            args: serde_json::json!({}),
        }
    }

    fn write(entity: &str, key: &str, value: &str) -> ObservedFactWrite {
        ObservedFactWrite {
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            confidence: 0.9,
            private: false,
            actor: Some(attribution().actor()),
        }
    }

    fn outcome(result: serde_json::Value, writes: Vec<ObservedFactWrite>, duration_ms: u64) -> StagedOperationOutcome {
        StagedOperationOutcome {
            result,
            observed_fact_writes: writes,
            dropped_fact_writes: 0,
            duration_ms,
        }
    }

    /// A well-behaved run: one read returning corpus content, one write
    /// landing inside the declared namespace.
    fn clean_run(duration_ms: u64, started_at: u64) -> ConformanceRun {
        let recall = case("recall", "ext.example.notes.recall");
        let remember = case("remember", "ext.example.notes.remember");
        build_run(
            attribution(),
            PackLifecycleState::Staged,
            CORPUS_ID,
            started_at,
            vec![
                observe(
                    &recall,
                    Ok(outcome(
                        serde_json::json!({ "notes": ["the kettle boils at 100C"] }),
                        Vec::new(),
                        duration_ms,
                    )),
                ),
                observe(
                    &remember,
                    Ok(outcome(
                        serde_json::json!({ "stored": true }),
                        vec![write(
                            "ext.example.notes::notes::2026-01-02",
                            "content",
                            "a pack proves what it does",
                        )],
                        duration_ms,
                    )),
                ),
            ],
        )
    }

    fn evaluate_runs(manifest: &IntegrationManifest, first: &ConformanceRun, second: &ConformanceRun) -> ReplayRecord {
        let corpus = loaded_corpus();
        evaluate(ReplayInput {
            pack: attribution(),
            manifest,
            corpus: &corpus,
            first,
            second,
            started_at_unix_ms: 17_700_000_000_000,
        })
        .expect("evaluation must run")
    }

    // ── Gate clause 1: a pack stages + replays deterministically ─────────

    /// The load-bearing determinism claim: the same pack replayed against
    /// the same corpus produces a bit-for-bit identical record, even when
    /// the two evaluations were minutes apart and every call took a
    /// different amount of wall-clock time.
    #[test]
    fn the_same_pack_and_corpus_replay_bit_for_bit() {
        let manifest = conforming_manifest();
        let fast = clean_run(3, 1);
        let slow = clean_run(941, 17_700_000_000_000);
        assert_ne!(
            fast.totals.duration_ms, slow.totals.duration_ms,
            "the two runs really did take different wall-clock time"
        );

        let first = evaluate_runs(&manifest, &fast, &fast);
        let second = evaluate_runs(&manifest, &slow, &slow);

        assert_eq!(
            first.record_digest, second.record_digest,
            "the replay record must be a function of the pack and the corpus, not of the clock"
        );
        assert_eq!(first.verdict, ReplayVerdict::Pass);
        assert_eq!(second.verdict, ReplayVerdict::Pass);
        assert!(first.replay_stable);
        assert_ne!(
            first.timings.latency_ms_total, second.timings.latency_ms_total,
            "the timings are still reported, they are simply not part of the identity"
        );
    }

    /// The digest is a statement about behaviour, so a behaviour change has
    /// to move it.
    #[test]
    fn a_behaviour_change_moves_the_replay_digest() {
        let manifest = conforming_manifest();
        let baseline = evaluate_runs(&manifest, &clean_run(3, 1), &clean_run(3, 1));

        let recall = case("recall", "ext.example.notes.recall");
        let remember = case("remember", "ext.example.notes.remember");
        let drifted = build_run(
            attribution(),
            PackLifecycleState::Staged,
            CORPUS_ID,
            1,
            vec![
                observe(
                    &recall,
                    Ok(outcome(
                        serde_json::json!({ "notes": ["something else"] }),
                        Vec::new(),
                        3,
                    )),
                ),
                observe(
                    &remember,
                    Ok(outcome(
                        serde_json::json!({ "stored": true }),
                        vec![write(
                            "ext.example.notes::notes::2026-01-02",
                            "content",
                            "a pack proves what it does",
                        )],
                        3,
                    )),
                ),
            ],
        );
        let after = evaluate_runs(&manifest, &drifted, &drifted);
        assert_ne!(baseline.record_digest, after.record_digest);
    }

    /// A pack that does not reproduce itself cannot carry a proof — and it
    /// is caught without any envelope bound being exceeded.
    #[test]
    fn an_unstable_replay_is_blocked() {
        let manifest = conforming_manifest();
        let recall = case("recall", "ext.example.notes.recall");
        let remember = case("remember", "ext.example.notes.remember");
        let second_run = build_run(
            attribution(),
            PackLifecycleState::Staged,
            CORPUS_ID,
            2,
            vec![
                observe(
                    &recall,
                    // Same case, different answer: the pack is not a function
                    // of its inputs.
                    Ok(outcome(
                        serde_json::json!({ "notes": ["a different note"] }),
                        Vec::new(),
                        3,
                    )),
                ),
                observe(
                    &remember,
                    Ok(outcome(
                        serde_json::json!({ "stored": true }),
                        vec![write(
                            "ext.example.notes::notes::2026-01-02",
                            "content",
                            "a pack proves what it does",
                        )],
                        3,
                    )),
                ),
            ],
        );

        let record = evaluate_runs(&manifest, &clean_run(3, 1), &second_run);
        assert!(!record.replay_stable);
        assert!(record.violations.is_empty(), "no numeric bound was exceeded");
        assert_eq!(record.verdict, ReplayVerdict::Blocked);
        let determinism = record
            .invariant_results
            .iter()
            .find(|result| result.kind == InvariantKind::DeterministicReplay)
            .expect("the declaration carries a determinism invariant");
        assert!(!determinism.held);
        assert!(determinism.detail.contains("recall"));
    }

    /// A replay must run against a staged pack. Replaying a live one would
    /// prove nothing about what enabling it costs.
    #[test]
    fn a_live_pack_cannot_be_replayed() {
        let manifest = conforming_manifest();
        let corpus = loaded_corpus();
        let mut run = clean_run(3, 1);
        run.lifecycle = PackLifecycleState::Active;
        let error = evaluate(ReplayInput {
            pack: attribution(),
            manifest: &manifest,
            corpus: &corpus,
            first: &run,
            second: &run,
            started_at_unix_ms: 1,
        })
        .expect_err("a live pack must be refused");
        assert_eq!(error, ReplayError::NotStaged("ext.example.notes".to_string(), "active"));
    }

    // ── Gate clause 2: envelope violations are caught before going live ──

    /// A pack that writes more per call than it declared is blocked, and
    /// the finding names the bound, the declared value, the observed value
    /// and the case.
    #[test]
    fn an_envelope_violating_pack_is_blocked_before_it_goes_live() {
        let manifest = conforming_manifest();
        let remember = case("remember", "ext.example.notes.remember");
        let greedy = build_run(
            attribution(),
            PackLifecycleState::Staged,
            CORPUS_ID,
            1,
            vec![observe(
                &remember,
                Ok(outcome(
                    serde_json::json!({ "stored": true }),
                    vec![
                        write("ext.example.notes::notes::a", "content", "one"),
                        write("ext.example.notes::notes::b", "content", "two"),
                    ],
                    3,
                )),
            )],
        );

        let record = evaluate_runs(&manifest, &greedy, &greedy);
        assert_eq!(record.verdict, ReplayVerdict::Blocked);
        let finding = record
            .violations
            .iter()
            .find(|v| v.bound == "envelope.max_fact_writes_per_call")
            .expect("the write-budget violation must be reported");
        assert_eq!(finding.declared, 1);
        assert_eq!(finding.observed, 2);
        assert_eq!(finding.case_id.as_deref(), Some("remember"));

        // And the gate refuses to take it live.
        let mut store = FactStore::new();
        put_replay_record(&mut store, &record).expect("store record");
        let blocked = check_activation(&store, "ext.example.notes", &manifest, &attribution().manifest_hash)
            .expect_err("a blocked replay must refuse activation");
        assert!(blocked.reason.contains("max_fact_writes_per_call"), "{blocked}");
        assert_eq!(blocked.record_digest.as_deref(), Some(record.record_digest.as_str()));
    }

    /// A write outside the declared namespace is an undeclared mutation,
    /// caught by the invariant rather than by a numeric bound.
    #[test]
    fn a_write_outside_the_declared_namespace_is_blocked() {
        let manifest = conforming_manifest();
        let remember = case("remember", "ext.example.notes.remember");
        let sneaky = build_run(
            attribution(),
            PackLifecycleState::Staged,
            CORPUS_ID,
            1,
            vec![observe(
                &remember,
                Ok(outcome(
                    serde_json::json!({ "stored": true }),
                    vec![write("personal::secrets::exfiltrated", "content", "oops")],
                    3,
                )),
            )],
        );

        let record = evaluate_runs(&manifest, &sneaky, &sneaky);
        assert_eq!(record.verdict, ReplayVerdict::Blocked);
        let finding = record
            .invariant_results
            .iter()
            .find(|result| result.kind == InvariantKind::NoUndeclaredFactWrites)
            .expect("declared invariant");
        assert!(!finding.held);
        assert!(finding.detail.contains("personal::secrets::exfiltrated"));
    }

    /// A pack that contradicts the corpus it was replayed against is caught
    /// by the contradiction rate, in the envelope's own parts-per-million
    /// unit, and by the invariant.
    #[test]
    fn a_contradiction_generating_pack_is_blocked() {
        let manifest = conforming_manifest();
        let remember = case("remember", "ext.example.notes.remember");
        // The corpus seeds `notes::polarity = active`; the pack writes the
        // opposite polarity under the same (entity, key).
        let contradicting = build_run(
            attribution(),
            PackLifecycleState::Staged,
            CORPUS_ID,
            1,
            vec![observe(
                &remember,
                Ok(outcome(
                    serde_json::json!({ "stored": true }),
                    vec![write("ext.example.notes::notes::seed-1", "state", "false")],
                    3,
                )),
            )],
        );
        let mut corpus = loaded_corpus();
        corpus.corpus.seed_facts.push(SeedFact {
            entity: "ext.example.notes::notes::seed-1".to_string(),
            key: "state".to_string(),
            value: "true".to_string(),
            confidence: 1.0,
            private: false,
        });

        let record = evaluate(ReplayInput {
            pack: attribution(),
            manifest: &manifest,
            corpus: &corpus,
            first: &contradicting,
            second: &contradicting,
            started_at_unix_ms: 1,
        })
        .expect("evaluate");

        assert!(
            record.measurements.contradiction_rate_ppm > 0,
            "the pack contradicted corpus '{}' and the rate must say so",
            record.corpus_id
        );
        assert_eq!(record.verdict, ReplayVerdict::Blocked);
        assert!(record
            .violations
            .iter()
            .any(|v| v.bound == "envelope.max_contradiction_rate_ppm"));
    }

    /// A latency blowup is reported but never blocks: a wall-clock number
    /// cannot be a deterministic verdict criterion.
    #[test]
    fn a_latency_overrun_is_advisory_not_blocking() {
        let manifest = conforming_manifest();
        let slow = clean_run(9_000, 1);
        let record = evaluate_runs(&manifest, &slow, &slow);

        assert_eq!(record.verdict, ReplayVerdict::Pass);
        assert!(record.violations.is_empty());
        assert!(
            record
                .advisories
                .iter()
                .any(|a| a.bound == "envelope.max_latency_ms_per_call"),
            "the overrun must still be reported"
        );

        // And it does not change the record's identity.
        let quick = clean_run(3, 1);
        assert_eq!(
            record.record_digest,
            evaluate_runs(&manifest, &quick, &quick).record_digest
        );
    }

    /// A pack the grant filter had to refuse writes for has reached outside
    /// its declared scope, even though nothing landed.
    #[test]
    fn refused_writes_fail_the_capability_invariant() {
        let manifest = conforming_manifest();
        let remember = case("remember", "ext.example.notes.remember");
        let mut over_scope = outcome(
            serde_json::json!({ "stored": true }),
            vec![write("ext.example.notes::notes::a", "content", "one")],
            3,
        );
        over_scope.dropped_fact_writes = 2;
        let run = build_run(
            attribution(),
            PackLifecycleState::Staged,
            CORPUS_ID,
            1,
            vec![observe(&remember, Ok(over_scope))],
        );

        let record = evaluate_runs(&manifest, &run, &run);
        assert_eq!(record.measurements.dropped_fact_writes, 2);
        let finding = record
            .invariant_results
            .iter()
            .find(|result| result.kind == InvariantKind::NoUndeclaredCapabilityUse)
            .expect("declared invariant");
        assert!(!finding.held);
        assert_eq!(record.verdict, ReplayVerdict::Blocked);
    }

    // ── Gate clause 3: the observed record is complete and reproducible ──

    /// The record has to carry the whole observed behaviour — every case,
    /// every measurement the milestone names — not a summary of it.
    #[test]
    fn the_observed_behaviour_record_is_complete() {
        let manifest = conforming_manifest();
        let run = clean_run(7, 1);
        let record = evaluate_runs(&manifest, &run, &run);

        assert_eq!(record.schema, REPLAY_RECORD_SCHEMA_V1);
        assert_eq!(record.lifecycle, PackLifecycleState::Staged);
        assert_eq!(record.corpus_id, CORPUS_ID);
        assert_eq!(
            record.corpus_sha256,
            corpus_bytes().1,
            "the corpus is named by its bytes"
        );
        assert_eq!(record.observations.len(), run.observations.len());
        for (recorded, observed) in record.observations.iter().zip(&run.observations) {
            assert_eq!(recorded, observed, "every observation is carried verbatim");
        }

        // Observed mutations.
        assert_eq!(record.measurements.observed_fact_writes, 1);
        assert_eq!(record.measurements.max_fact_writes_in_a_call, 1);
        // Recall / citation behaviour, named against its corpus.
        assert_eq!(record.measurements.recall.probes, 1);
        assert_eq!(record.measurements.recall.satisfied_before, 1);
        assert_eq!(record.measurements.recall.satisfied_after, 1);
        assert!(record.measurements.recall.regressed.is_empty());
        // Token cost.
        assert!(record.measurements.tokens_total > 0);
        assert_eq!(
            record.measurements.max_tokens_in_a_call,
            estimated_tokens(
                run.observations
                    .iter()
                    .map(|o| o.result_bytes)
                    .max()
                    .unwrap_or_default()
            )
        );
        // Contradiction rate.
        assert_eq!(record.measurements.contradiction_rate_ppm, 0);
        // Rollback result.
        assert!(record.measurements.rollback.restored);
        assert_eq!(record.measurements.rollback.operations, 1);
        // Every declared invariant is answered, none silently skipped.
        assert_eq!(record.invariant_results.len(), 7);
        assert!(record.invariant_results.iter().all(|result| result.held));
        // Decay behaviour was measured, not assumed.
        assert!(record.measurements.min_half_life_seconds >= 604_800);
    }

    /// Reproducible means re-derivable: the digest recomputes from the
    /// stored record, and a tampered field is detectable without the
    /// daemon that produced it.
    #[test]
    fn the_record_digest_re_derives_from_the_stored_record() {
        let manifest = conforming_manifest();
        let run = clean_run(3, 1);
        let record = evaluate_runs(&manifest, &run, &run);

        let round_tripped: ReplayRecord =
            serde_json::from_str(&serde_json::to_string(&record).expect("encode")).expect("decode");
        assert_eq!(round_tripped, record);
        assert_eq!(record_digest(&round_tripped), record.record_digest);

        let mut tampered = round_tripped;
        tampered.verdict = ReplayVerdict::Pass;
        tampered.measurements.observed_fact_writes += 1;
        assert_ne!(
            record_digest(&tampered),
            record.record_digest,
            "an edited record must not keep its digest"
        );
    }

    /// A rollback that leaves residue is a rollback that did not happen.
    /// Recorded from the shadow store rather than asserted.
    #[test]
    fn the_rollback_result_is_measured_against_the_shadow_store() {
        let manifest = conforming_manifest();
        let remember = case("remember", "ext.example.notes.remember");
        // Overwrite an existing seed: the reversal has to un-retire what
        // the pack displaced, not merely tombstone what it wrote.
        let run = build_run(
            attribution(),
            PackLifecycleState::Staged,
            CORPUS_ID,
            1,
            vec![observe(
                &remember,
                Ok(outcome(
                    serde_json::json!({ "stored": true }),
                    vec![write(
                        "ext.example.notes::notes::seed-1",
                        "content",
                        "the kettle boils at 90C",
                    )],
                    3,
                )),
            )],
        );

        let record = evaluate_runs(&manifest, &run, &run);
        assert!(
            record.measurements.rollback.restored,
            "residue: {:?}",
            record.measurements.rollback.residual_entities
        );
        assert_eq!(record.measurements.rollback.operations, 1);
        let reversible = record
            .invariant_results
            .iter()
            .find(|result| result.kind == InvariantKind::ReversibleWrites)
            .expect("declared invariant");
        assert!(reversible.held);
    }

    /// A pack that buries the corpus's own facts regresses a probe, and the
    /// regression is named per probe rather than as a score.
    #[test]
    fn recall_regression_is_captured_per_probe() {
        let manifest = conforming_manifest();
        let remember = case("remember", "ext.example.notes.remember");
        // Rewrite the probed seed so its content no longer answers the
        // probe: the corpus fact stops being citable.
        let run = build_run(
            attribution(),
            PackLifecycleState::Staged,
            CORPUS_ID,
            1,
            vec![observe(
                &remember,
                Ok(outcome(
                    serde_json::json!({ "stored": true }),
                    vec![write("ext.example.notes::notes::seed-1", "content", "redacted")],
                    3,
                )),
            )],
        );

        let record = evaluate_runs(&manifest, &run, &run);
        assert_eq!(record.measurements.recall.satisfied_before, 1);
        assert_eq!(record.measurements.recall.satisfied_after, 0);
        assert_eq!(record.measurements.recall.regressed, vec!["kettle".to_string()]);
    }

    // ── The corpus is content-addressed, local and reproducible ──────────

    #[test]
    fn a_corpus_that_does_not_hash_to_the_declaration_is_refused() {
        let (bytes, digest) = corpus_bytes();
        let mut declared = replay_corpus(digest);
        declared.sha256 = "0".repeat(64);
        let error = load_corpus(&bytes, &declared).expect_err("digest mismatch must be refused");
        assert!(matches!(error, ReplayError::CorpusDigestMismatch { .. }));

        // And a corpus edited after the manifest was signed no longer hashes
        // to the declaration.
        let (bytes, digest) = corpus_bytes();
        let declared = replay_corpus(digest);
        let mut edited = corpus_document();
        edited["seed_facts"][0]["value"] = serde_json::json!("the kettle boils at 90C");
        let mut edited_bytes = serde_json::to_vec_pretty(&edited).expect("encode");
        edited_bytes.push(b'\n');
        assert_ne!(edited_bytes, bytes);
        assert!(matches!(
            load_corpus(&edited_bytes, &declared),
            Err(ReplayError::CorpusDigestMismatch { .. })
        ));
    }

    #[test]
    fn a_corpus_whose_cases_disagree_with_the_signed_manifest_is_refused() {
        let mut document = corpus_document();
        document["cases"][0]["args"] = serde_json::json!({ "topic": "something-else" });
        let mut bytes = serde_json::to_vec_pretty(&document).expect("encode");
        bytes.push(b'\n');
        let digest = hex::encode(Sha256::digest(&bytes));
        // The digest matches the bytes, so only the case comparison can
        // catch this.
        let error = load_corpus(&bytes, &replay_corpus(digest)).expect_err("case mismatch must be refused");
        assert_eq!(error, ReplayError::CorpusCasesMismatch);
    }

    #[test]
    fn a_corpus_under_the_wrong_schema_or_name_is_refused() {
        let mut document = corpus_document();
        document["schema"] = serde_json::json!("crux.pack.shadow_corpus.v99");
        let mut bytes = serde_json::to_vec_pretty(&document).expect("encode");
        bytes.push(b'\n');
        let digest = hex::encode(Sha256::digest(&bytes));
        assert!(matches!(
            load_corpus(&bytes, &replay_corpus(digest)),
            Err(ReplayError::CorpusSchema(_))
        ));

        let mut document = corpus_document();
        document["corpus_id"] = serde_json::json!("some-other-corpus");
        let mut bytes = serde_json::to_vec_pretty(&document).expect("encode");
        bytes.push(b'\n');
        let digest = hex::encode(Sha256::digest(&bytes));
        assert!(matches!(
            load_corpus(&bytes, &replay_corpus(digest)),
            Err(ReplayError::CorpusIdMismatch { .. })
        ));
    }

    // ── The pre-enable gate ─────────────────────────────────────────────

    /// The gate is about the build, not the name: a passing replay of a
    /// different manifest hash does not license this one.
    #[test]
    fn activation_needs_a_passing_replay_of_this_exact_build() {
        let manifest = conforming_manifest();
        let run = clean_run(3, 1);
        let record = evaluate_runs(&manifest, &run, &run);
        assert_eq!(record.verdict, ReplayVerdict::Pass);

        let mut store = FactStore::new();
        // Never replayed.
        let never = check_activation(&store, "ext.example.notes", &manifest, &attribution().manifest_hash)
            .expect_err("an unreplayed declaring pack must not go live");
        assert!(never.reason.contains("never been replayed"), "{never}");
        assert!(never.record_digest.is_none());

        put_replay_record(&mut store, &record).expect("store record");
        check_activation(&store, "ext.example.notes", &manifest, &attribution().manifest_hash)
            .expect("a passing replay of this build licenses activation");

        let other_build = check_activation(&store, "ext.example.notes", &manifest, "blake3:cafebabe")
            .expect_err("a replay of another build must not license this one");
        assert!(other_build.reason.contains("different build"), "{other_build}");
    }

    /// A pack that declares nothing is never blocked. It made no promise, so
    /// there is nothing a replay could contradict — and every pack installed
    /// before this milestone is in exactly that position.
    #[test]
    fn a_pack_without_a_declaration_is_never_gated() {
        let store = FactStore::new();
        check_activation(&store, "ext.example.notes", &manifest_with(None), "blake3:whatever")
            .expect("a non-declaring pack must be unaffected");
    }

    /// The stored record survives a round trip through the fact store and
    /// re-reads as the same record — the evidence has to outlive the request
    /// that produced it.
    #[test]
    fn the_replay_record_round_trips_through_the_fact_store() {
        let manifest = conforming_manifest();
        let run = clean_run(3, 1);
        let record = evaluate_runs(&manifest, &run, &run);

        let mut store = FactStore::new();
        assert!(get_replay_record(&store, "ext.example.notes").is_none());
        put_replay_record(&mut store, &record).expect("store record");
        let read_back = get_replay_record(&store, "ext.example.notes").expect("record must be readable");
        assert_eq!(read_back, record);

        // A re-replay supersedes rather than erases: the newest version wins.
        let greedy = build_run(
            attribution(),
            PackLifecycleState::Staged,
            CORPUS_ID,
            2,
            vec![observe(
                &case("remember", "ext.example.notes.remember"),
                Ok(outcome(
                    serde_json::json!({ "stored": true }),
                    vec![
                        write("ext.example.notes::notes::a", "content", "one"),
                        write("ext.example.notes::notes::b", "content", "two"),
                    ],
                    3,
                )),
            )],
        );
        let second = evaluate_runs(&manifest, &greedy, &greedy);
        put_replay_record(&mut store, &second).expect("store record");
        assert_eq!(
            get_replay_record(&store, "ext.example.notes").expect("record").verdict,
            ReplayVerdict::Blocked,
            "the latest replay is the one the gate reads"
        );
    }

    #[test]
    fn the_gate_flag_is_off_by_default() {
        // The env var is not set in a clean test process, which is the
        // shipped default: report, do not refuse.
        std::env::remove_var(REPLAY_GATE_ENV);
        assert_eq!(ActivationGate::from_env(), ActivationGate::Advisory);
    }

    // ── The committed reference pack ────────────────────────────────────

    fn reference_pack_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../integrations/community/ext.conformance.reference/0.2.0")
    }

    fn read_reference_manifest() -> IntegrationManifest {
        let path = reference_pack_dir().join("manifest.json");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        serde_json::from_str(&text).unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
    }

    /// The shipped artefact and this harness have to agree. The corpus file
    /// committed beside the reference manifest must load through the same
    /// path a real replay uses — same schema tag, same digest, same cases —
    /// or the worked example is a document rather than a fixture.
    #[test]
    fn the_committed_reference_corpus_loads_through_the_harness() {
        let manifest = read_reference_manifest();
        let declaration = manifest
            .conformance
            .as_ref()
            .expect("the reference pack declares conformance");
        let path = reference_pack_dir().join(&declaration.replay_corpus.path);
        let bytes = std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));

        let loaded = load_corpus(&bytes, &declaration.replay_corpus).expect("the committed corpus must load");
        assert_eq!(loaded.sha256, declaration.replay_corpus.sha256);
        assert_eq!(loaded.corpus.schema, SHADOW_CORPUS_SCHEMA_V1);
        assert_eq!(loaded.corpus.corpus_id, declaration.replay_corpus.corpus_id);
        assert!(
            !loaded.corpus.seed_facts.is_empty(),
            "the corpus seeds the shadow store"
        );
        assert!(!loaded.corpus.probes.is_empty(), "the corpus measures recall");
        assert_eq!(
            loaded.corpus.cases,
            crate::pack_conformance::cases_from_manifest(&manifest),
            "the cases the hook would replay are the cases the corpus describes"
        );
    }

    /// A replay of the reference pack against its own corpus, driven from
    /// the harness end to end. The pack's endpoint is an RFC 2606 `.invalid`
    /// host that can never resolve, so every case is observed as an error —
    /// which is itself the finding, and is exactly what a pre-enable replay
    /// exists to surface. What matters here is that the record comes out
    /// complete, corpus-named and reproducible, and that a pack whose own
    /// declared operations do not run is not silently waved through.
    #[test]
    fn the_reference_pack_replays_against_its_own_corpus() {
        let manifest = read_reference_manifest();
        let declaration = manifest.conformance.as_ref().expect("declaration");
        let path = reference_pack_dir().join(&declaration.replay_corpus.path);
        let bytes = std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        let corpus = load_corpus(&bytes, &declaration.replay_corpus).expect("load");

        let pack = PackAttribution::new(
            manifest.id.clone(),
            manifest.version.clone(),
            manifest.hashes.manifest.clone().unwrap_or_default(),
        );
        let cases = crate::pack_conformance::cases_from_manifest(&manifest);
        let run_once = || {
            let observations: Vec<ConformanceObservation> = cases
                .iter()
                .map(|case| {
                    observe(
                        case,
                        Err("dns error: failed to lookup address information for reference.pack.invalid".to_string()),
                    )
                })
                .collect();
            build_run(
                pack.clone(),
                PackLifecycleState::Staged,
                declaration.replay_corpus.corpus_id.clone(),
                1,
                observations,
            )
        };
        let first = run_once();
        let second = run_once();

        let record = evaluate(ReplayInput {
            pack: pack.clone(),
            manifest: &manifest,
            corpus: &corpus,
            first: &first,
            second: &second,
            started_at_unix_ms: 17_700_000_000_000,
        })
        .expect("evaluate");

        assert_eq!(record.corpus_id, "conformance-reference-v1");
        assert_eq!(record.corpus_sha256, declaration.replay_corpus.sha256);
        assert_eq!(record.observations.len(), declaration.replay_corpus.cases.len());
        assert!(record.replay_stable, "an unreachable endpoint fails the same way twice");
        // Recall over the seeded corpus was measured, and the pack that
        // never ran did not damage it.
        assert_eq!(record.measurements.recall.probes, corpus.corpus.probes.len());
        assert_eq!(
            record.measurements.recall.satisfied_before, record.measurements.recall.satisfied_after,
            "a pack that wrote nothing cannot have moved recall"
        );
        assert!(record.measurements.rollback.restored);
        // Every invariant the pack declared is answered.
        assert_eq!(record.invariant_results.len(), declaration.invariants.len());
        assert!(record
            .invariant_results
            .iter()
            .any(|result| result.kind == InvariantKind::NoEgressOutsideAllowlist && result.held));
        assert_eq!(record.verdict, ReplayVerdict::Pass);
        // And it is reproducible.
        let again = evaluate(ReplayInput {
            pack,
            manifest: &manifest,
            corpus: &corpus,
            first: &second,
            second: &first,
            started_at_unix_ms: 42,
        })
        .expect("evaluate");
        assert_eq!(again.record_digest, record.record_digest);
    }

    #[test]
    fn a_url_host_is_extracted_without_a_url_parser() {
        assert_eq!(host_of("https://notes.pack.invalid/tools"), Some("notes.pack.invalid"));
        assert_eq!(
            host_of("https://user@notes.pack.invalid:8443/x"),
            Some("notes.pack.invalid")
        );
        assert_eq!(host_of("notes.pack.invalid"), Some("notes.pack.invalid"));
        assert_eq!(host_of(""), None);
    }
}
