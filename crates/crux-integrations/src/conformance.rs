// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.
//
// NOTE ON LICENSING: this source file is Apache-2.0 like the rest of the
// crate, but the *schema document* it emits — `docs/spec/pack.conformance.v1.schema.json`,
// produced by [`json_schema`] — is published under the MIT Licence so a
// third party can implement `pack.conformance.v1` (or vendor the schema into
// a differently-licensed registry, linter, or SDK) without taking on
// Apache-2.0 obligations. The format is meant to be copied; the daemon that
// enforces it is not.

//! `pack.conformance.v1` — the block a memory pack uses to **declare what it
//! does**, so a replay can later prove whether it did that.
//!
//! ## Why a declaration, and why it is signed
//!
//! Every plugin ecosystem decides trust from a static scan plus a download
//! count. Neither survives the pack's next release. This block is the first
//! half of a different answer: the pack states, in advance and under its
//! publisher's signature, the capabilities it claims, the fact and receipt
//! mutations it expects to make, the corpus its declared operations should be
//! replayed against, the invariants that must hold while they run, the
//! numeric envelope its behaviour must stay inside, and what upgrading to or
//! rolling back from it costs. `proof-carrying-adaptive-packs-2026-07-13` M1
//! replays that declaration against a local shadow corpus and blocks a pack
//! whose observed behaviour leaves the envelope; M2 signs the verdict into a
//! CROWN receipt.
//!
//! The block is inside [`crate::IntegrationManifest::signing_payload`], not
//! beside it. A declaration an attacker can edit after signing is not
//! evidence of anything — it is a second, softer manifest. Adding the field
//! to the signing payload is what makes "the pack promised this" checkable
//! offline, and it is why the tamper test in this module is load-bearing
//! rather than decorative.
//!
//! ## Every bound is an integer, deliberately
//!
//! Rates are parts-per-million and costs are whole units because the block is
//! signed. JSON has no canonical form for a float: `0.1`, `1e-1` and
//! `0.1000000000000000055511151231257827` are the same IEEE-754 double and
//! different bytes, so a `f64` bound would make a signature depend on which
//! serialiser wrote it. Integers have exactly one representation, so a
//! verifier that re-serialises the block gets the publisher's bytes back.
//!
//! ## The declaration must account for the whole pack
//!
//! [`PackConformance::validate`] refuses a block that is narrower than the
//! manifest it sits in: claimed capabilities must equal declared
//! capabilities, declared fact writes must fit the envelope's write bound,
//! and a case may only name a tool the manifest exposes. A conformance block
//! that silently omits half the pack's surface would let a pack carry a clean
//! replay result for the part it chose to show, which is the scan-once-and-hope
//! failure in a new costume.

use serde::{Deserialize, Serialize};

use crate::{EntryKind, IntegrationManifest};

/// Schema tag every `pack.conformance.v1` block carries.
pub const PACK_CONFORMANCE_SCHEMA_V1: &str = "pack.conformance.v1";

/// Repo-relative path of the published, MIT-licensed schema document.
pub const SCHEMA_DOCUMENT_PATH: &str = "docs/spec/pack.conformance.v1.schema.json";

/// Canonical `$id` of the published schema.
pub const SCHEMA_DOCUMENT_ID: &str = "https://cuecrux.com/spec/pack.conformance.v1.schema.json";

/// Upper bound on declared replay cases.
///
/// Mirrors `corecruxd::pack_conformance::MAX_CASES_PER_RUN`: a corpus a pack
/// declares but the hook would refuse to run is a declaration that can never
/// be proved, so the two caps are pinned equal by a test on the daemon side.
pub const MAX_DECLARED_CASES: usize = 64;

/// A rate of one, expressed in the parts-per-million the envelope uses.
pub const PPM_DENOMINATOR: u32 = 1_000_000;

/// The signed conformance declaration a pack carries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackConformance {
    pub schema: String,
    /// Capabilities the pack claims conformance for. Must equal the
    /// manifest's declared capability set — see the module docs.
    pub claimed_capabilities: Vec<String>,
    pub expected_mutations: ExpectedMutations,
    pub replay_corpus: ReplayCorpus,
    pub invariants: Vec<InvariantTest>,
    pub envelope: BehaviouralEnvelope,
    pub compatibility: CompatibilityAssertions,
}

/// What the pack expects to change in the store, stated before it runs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpectedMutations {
    pub facts: Vec<ExpectedFactMutation>,
    pub receipts: Vec<ExpectedReceiptMutation>,
}

/// One namespace the pack writes facts into.
///
/// Declared as a prefix plus an optional key list rather than as literal
/// entities because a pack's entities are usually data-dependent
/// (`personal::quotes::<date>`). A prefix is still a bound: a write outside
/// every declared prefix is an undeclared write, and that is exactly what the
/// replay looks for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpectedFactMutation {
    pub entity_prefix: String,
    /// Keys written under the prefix. Empty means any key.
    pub keys: Vec<String>,
    pub operation: FactMutationOp,
    /// Whether writes here are private facts. Requires the manifest's
    /// `data_access.private_facts`; a pack cannot declare a private write it
    /// has no data-access grant to make.
    pub private: bool,
    pub max_per_call: u32,
}

/// The two things a pack can do to a fact.
///
/// There is no `delete`: the store is append-only and reversal is
/// supersession, so a delete variant would name an operation the substrate
/// cannot perform and let a pack declare an irreversible write that is not
/// possible.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FactMutationOp {
    Write,
    Supersede,
}

impl FactMutationOp {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Write => "write",
            Self::Supersede => "supersede",
        }
    }
}

/// One receipt kind the pack causes to be emitted, and how many per call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpectedReceiptMutation {
    pub receipt_kind: ReceiptMutationKind,
    pub max_per_call: u32,
}

/// Receipt kinds a pack can actually cause.
///
/// Closed rather than free-form: a declaration naming a receipt kind nothing
/// emits cannot be checked against a replay, and an unverifiable claim in a
/// proof-carrying format is worse than no claim.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptMutationKind {
    /// The outbound tool-call receipt, carrying the pack's `PackAttribution`.
    Dispatch,
    /// The CROWN receipt for a fact the pack wrote.
    FactWrite,
    /// The receipt for a supersession the pack caused.
    Supersession,
}

impl ReceiptMutationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dispatch => "dispatch",
            Self::FactWrite => "fact_write",
            Self::Supersession => "supersession",
        }
    }
}

/// Where the pack's declared operations come from, and what they are.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayCorpus {
    /// Operator-readable name of the shadow corpus. Mandatory: a behavioural
    /// number whose corpus is unnamed cannot be compared to a later one, and
    /// the mismatch is not recoverable after the fact.
    pub corpus_id: String,
    /// Path to the corpus file, relative to the pack directory.
    pub path: String,
    /// SHA-256 of the corpus file, 64 lowercase hex characters. The corpus is
    /// content-addressed so "replayed against corpus X" names bytes rather
    /// than a filename someone can swap.
    pub sha256: String,
    pub cases: Vec<DeclaredCase>,
}

/// One declared operation, replayed by the daemon's conformance hook.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeclaredCase {
    /// Stable identity, so an observation matches its declaration across runs
    /// and across daemon versions. Ordinal position would break the moment
    /// the corpus gains a case in the middle.
    pub case_id: String,
    pub tool_name: String,
    pub args: serde_json::Value,
}

/// One property that must hold while the declared cases run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InvariantTest {
    pub id: String,
    pub description: String,
    pub kind: InvariantKind,
    /// Cases this applies to. Empty means every declared case.
    pub applies_to_cases: Vec<String>,
}

/// The checkable invariants.
///
/// Closed, and deliberately without an escape hatch: a `custom` variant would
/// carry a sentence no harness can evaluate, and a pack whose declared
/// invariants are prose is back to being trusted on assertion. Adding a
/// property means a new schema version, which is a reviewable diff.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum InvariantKind {
    /// Every observed fact write falls under a declared `entity_prefix`.
    NoUndeclaredFactWrites,
    /// The pack reads no private facts.
    NoPrivateFactAccess,
    /// The pack exercises no capability outside `claimed_capabilities`.
    NoUndeclaredCapabilityUse,
    /// The pack reaches no host outside the manifest's `network.allowed_hosts`.
    NoEgressOutsideAllowlist,
    /// Replaying a case twice yields the same observed behaviour.
    DeterministicReplay,
    /// Every write the pack makes can be reversed by supersession.
    ReversibleWrites,
    /// The pack introduces no new contradictions into the store.
    NoNewContradictions,
}

impl InvariantKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoUndeclaredFactWrites => "no_undeclared_fact_writes",
            Self::NoPrivateFactAccess => "no_private_fact_access",
            Self::NoUndeclaredCapabilityUse => "no_undeclared_capability_use",
            Self::NoEgressOutsideAllowlist => "no_egress_outside_allowlist",
            Self::DeterministicReplay => "deterministic_replay",
            Self::ReversibleWrites => "reversible_writes",
            Self::NoNewContradictions => "no_new_contradictions",
        }
    }

    pub const ALL: &'static [InvariantKind] = &[
        Self::NoUndeclaredFactWrites,
        Self::NoPrivateFactAccess,
        Self::NoUndeclaredCapabilityUse,
        Self::NoEgressOutsideAllowlist,
        Self::DeterministicReplay,
        Self::ReversibleWrites,
        Self::NoNewContradictions,
    ];
}

/// The numeric bounds observed behaviour must stay inside.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BehaviouralEnvelope {
    pub max_tokens_per_call: u32,
    pub max_tokens_per_run: u32,
    pub max_latency_ms_per_call: u32,
    pub max_latency_ms_per_run: u32,
    pub max_response_bytes_per_call: u32,
    pub max_fact_writes_per_call: u32,
    pub decay: DecayEnvelope,
    /// Contradictions the pack may introduce, per million facts written.
    /// Parts-per-million rather than a ratio so the bound is an exact integer
    /// under signing.
    pub max_contradiction_rate_ppm: u32,
    pub undo: UndoEnvelope,
}

/// How the pack interacts with freshness decay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecayEnvelope {
    /// Shortest half-life, in seconds, of any fact the pack writes. Zero is
    /// only valid for a pack that writes no facts: a write with no declared
    /// half-life is a fact that never gets stale, and a memory pack that can
    /// mint permanent memories should have to say so.
    pub min_half_life_seconds: u64,
    /// Freshness refreshes one call may perform on facts the pack did not
    /// write. Refreshing someone else's fact hides its age, so it is bounded
    /// separately from writing.
    pub max_refreshes_per_call: u32,
}

/// What reversing one call costs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UndoEnvelope {
    /// Supersession operations needed to fully reverse one call's writes.
    /// Must be non-zero exactly when the pack declares fact writes: a pack
    /// that writes and claims a zero-operation undo is claiming its writes
    /// need no reversal, which is the one thing a reversal bound exists to
    /// forbid.
    pub max_operations_per_call: u32,
    pub max_latency_ms: u32,
}

/// What this build is compatible with, and what moving to it costs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompatibilityAssertions {
    /// Oldest daemon this declaration holds against, as `MAJOR.MINOR.PATCH`.
    pub min_daemon_version: String,
    /// Manifest schema the block was written against. Pinned so a manifest
    /// format change cannot silently reinterpret an old declaration.
    pub manifest_schema: String,
    /// Prior pack versions this build can take over from.
    pub supersedes: Vec<String>,
    pub migrations: Vec<MigrationAssertion>,
    /// Whether rolling back to any superseded version loses no data. Declared
    /// rather than assumed: `pack_rollback` restores bytes atomically, but
    /// only the publisher knows whether the *facts* the new version wrote can
    /// be read by the old one.
    pub rollback_safe: bool,
}

/// One declared upgrade step.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationAssertion {
    pub from_version: String,
    pub to_version: String,
    pub kind: MigrationKind,
    pub reversible: bool,
    pub description: String,
}

/// What an upgrade does to already-stored state.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MigrationKind {
    /// Nothing stored changes shape.
    None,
    /// Existing facts are superseded by re-derived ones.
    SupersedeFacts,
    /// Entities move to new keys; the old ones are superseded.
    RekeyEntities,
    /// Companion indexes are rebuilt; no fact content changes.
    Reindex,
}

impl MigrationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SupersedeFacts => "supersede_facts",
            Self::RekeyEntities => "rekey_entities",
            Self::Reindex => "reindex",
        }
    }
}

/// Why a conformance declaration was refused.
///
/// Each variant names the field and the rule, because these are read by pack
/// authors at submission time, not by the daemon at runtime.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConformanceDeclarationError {
    #[error("invalid conformance schema '{0}': expected {PACK_CONFORMANCE_SCHEMA_V1}")]
    InvalidSchema(String),
    #[error(
        "a conformance block declares replayable operations, so it is only valid when entry.kind is external_tool or wasm, got {0:?}"
    )]
    NonExecutingKind(EntryKind),
    #[error("conformance field '{0}' is required and must not be empty")]
    MissingField(&'static str),
    #[error(
        "claimed_capabilities {claimed:?} does not equal the manifest's declared capabilities {declared:?}: a conformance block must account for every capability the pack holds"
    )]
    CapabilityMismatch {
        claimed: Vec<String>,
        declared: Vec<String>,
    },
    #[error("replay_corpus.sha256 must be 64 lowercase hex characters, got '{0}'")]
    InvalidCorpusDigest(String),
    #[error("replay_corpus.path must be a relative path inside the pack directory, got '{0}'")]
    InvalidCorpusPath(String),
    #[error("replay_corpus.cases has {0} entries, exceeding the {MAX_DECLARED_CASES}-case cap the conformance hook enforces")]
    TooManyCases(usize),
    #[error("duplicate case_id '{0}': ids identify observations, so they must be unique")]
    DuplicateCaseId(String),
    #[error("case '{case_id}' names tool '{tool_name}', which the manifest does not declare")]
    UnknownCaseTool { case_id: String, tool_name: String },
    #[error("duplicate invariant id '{0}'")]
    DuplicateInvariantId(String),
    #[error("invariant '{invariant_id}' applies to case '{case_id}', which is not declared")]
    UnknownInvariantCase { invariant_id: String, case_id: String },
    #[error("duplicate receipt_kind '{0}': declare one bound per kind")]
    DuplicateReceiptKind(&'static str),
    #[error("envelope bound '{field}' must be at least {minimum}, got {value}")]
    BoundTooLow {
        field: &'static str,
        minimum: u64,
        value: u64,
    },
    #[error("envelope bound '{field}' must be at most {maximum}, got {value}")]
    BoundTooHigh {
        field: &'static str,
        maximum: u64,
        value: u64,
    },
    #[error("envelope '{per_run}' ({run_value}) must be at least '{per_call}' ({call_value}): a run contains at least one call")]
    RunBoundBelowCallBound {
        per_run: &'static str,
        run_value: u64,
        per_call: &'static str,
        call_value: u64,
    },
    #[error(
        "declared fact writes total {declared} per call but envelope.max_fact_writes_per_call is {bound}: the envelope must cover what the pack says it writes"
    )]
    WriteBudgetExceeded { declared: u64, bound: u32 },
    #[error("expected_mutations.facts declares writes, so the manifest must declare the '{0}' capability")]
    WritesWithoutCapability(&'static str),
    #[error(
        "expected_mutations.facts declares a private write, but the manifest's data_access.private_facts is false"
    )]
    PrivateWriteWithoutAccess,
    #[error("{field} must be {expected} when the pack declares {condition}, got {value}")]
    InconsistentWithWrites {
        field: &'static str,
        expected: &'static str,
        condition: &'static str,
        value: u64,
    },
    #[error("compatibility.manifest_schema '{declared}' does not match the manifest's schema '{actual}'")]
    ManifestSchemaMismatch { declared: String, actual: String },
    #[error("compatibility.min_daemon_version must be MAJOR.MINOR.PATCH, got '{0}'")]
    InvalidDaemonVersion(String),
    #[error("compatibility.supersedes lists '{0}', which is this pack's own version")]
    SupersedesSelf(String),
    #[error("migration to_version '{declared}' must be this pack's version '{actual}'")]
    MigrationTargetMismatch { declared: String, actual: String },
    #[error("migration from_version '{0}' is not listed in compatibility.supersedes")]
    MigrationSourceNotSuperseded(String),
}

impl PackConformance {
    /// Check the declaration against the manifest that carries it.
    ///
    /// Called from [`crate::IntegrationManifest::validate`] after the
    /// entry-kind rules, so capability names and tool shapes are already
    /// known good and the errors here are about the *declaration*, not about
    /// the manifest.
    pub fn validate(&self, manifest: &IntegrationManifest) -> Result<(), ConformanceDeclarationError> {
        if self.schema != PACK_CONFORMANCE_SCHEMA_V1 {
            return Err(ConformanceDeclarationError::InvalidSchema(self.schema.clone()));
        }
        if !matches!(manifest.entry.kind, EntryKind::ExternalTool | EntryKind::Wasm) {
            return Err(ConformanceDeclarationError::NonExecutingKind(manifest.entry.kind));
        }

        self.validate_capabilities(manifest)?;
        let case_ids = self.validate_replay_corpus(manifest)?;
        self.validate_invariants(&case_ids)?;
        self.validate_envelope()?;
        self.validate_mutations(manifest)?;
        self.validate_compatibility(manifest)?;
        Ok(())
    }

    fn validate_capabilities(&self, manifest: &IntegrationManifest) -> Result<(), ConformanceDeclarationError> {
        let claimed = sorted_unique(&self.claimed_capabilities);
        let declared = sorted_unique(&manifest.capabilities);
        if claimed != declared {
            return Err(ConformanceDeclarationError::CapabilityMismatch { claimed, declared });
        }
        Ok(())
    }

    fn validate_replay_corpus(
        &self,
        manifest: &IntegrationManifest,
    ) -> Result<Vec<String>, ConformanceDeclarationError> {
        let corpus = &self.replay_corpus;
        if corpus.corpus_id.trim().is_empty() {
            return Err(ConformanceDeclarationError::MissingField("replay_corpus.corpus_id"));
        }
        if corpus.path.trim().is_empty() {
            return Err(ConformanceDeclarationError::MissingField("replay_corpus.path"));
        }
        if !is_safe_relative_path(&corpus.path) {
            return Err(ConformanceDeclarationError::InvalidCorpusPath(corpus.path.clone()));
        }
        if !is_lowercase_hex(&corpus.sha256, 64) {
            return Err(ConformanceDeclarationError::InvalidCorpusDigest(corpus.sha256.clone()));
        }
        if corpus.cases.is_empty() {
            return Err(ConformanceDeclarationError::MissingField("replay_corpus.cases"));
        }
        if corpus.cases.len() > MAX_DECLARED_CASES {
            return Err(ConformanceDeclarationError::TooManyCases(corpus.cases.len()));
        }

        let tool_names: Vec<&str> = manifest.tools.iter().map(|tool| tool.name.as_str()).collect();
        let mut seen = std::collections::BTreeSet::new();
        let mut case_ids = Vec::with_capacity(corpus.cases.len());
        for case in &corpus.cases {
            if case.case_id.trim().is_empty() {
                return Err(ConformanceDeclarationError::MissingField(
                    "replay_corpus.cases[].case_id",
                ));
            }
            if !seen.insert(case.case_id.as_str()) {
                return Err(ConformanceDeclarationError::DuplicateCaseId(case.case_id.clone()));
            }
            if !tool_names.contains(&case.tool_name.as_str()) {
                return Err(ConformanceDeclarationError::UnknownCaseTool {
                    case_id: case.case_id.clone(),
                    tool_name: case.tool_name.clone(),
                });
            }
            case_ids.push(case.case_id.clone());
        }
        Ok(case_ids)
    }

    fn validate_invariants(&self, case_ids: &[String]) -> Result<(), ConformanceDeclarationError> {
        if self.invariants.is_empty() {
            return Err(ConformanceDeclarationError::MissingField("invariants"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for invariant in &self.invariants {
            if invariant.id.trim().is_empty() {
                return Err(ConformanceDeclarationError::MissingField("invariants[].id"));
            }
            if invariant.description.trim().is_empty() {
                return Err(ConformanceDeclarationError::MissingField("invariants[].description"));
            }
            if !seen.insert(invariant.id.as_str()) {
                return Err(ConformanceDeclarationError::DuplicateInvariantId(invariant.id.clone()));
            }
            for case_id in &invariant.applies_to_cases {
                if !case_ids.iter().any(|declared| declared == case_id) {
                    return Err(ConformanceDeclarationError::UnknownInvariantCase {
                        invariant_id: invariant.id.clone(),
                        case_id: case_id.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_envelope(&self) -> Result<(), ConformanceDeclarationError> {
        let envelope = &self.envelope;
        for (field, value) in [
            ("envelope.max_tokens_per_call", envelope.max_tokens_per_call),
            ("envelope.max_latency_ms_per_call", envelope.max_latency_ms_per_call),
            (
                "envelope.max_response_bytes_per_call",
                envelope.max_response_bytes_per_call,
            ),
        ] {
            // A zero bound on a cost every call pays is not a tight bound, it
            // is an unsatisfiable one: the replay would fail the pack on its
            // first operation, so the declaration could never be proved.
            if value == 0 {
                return Err(ConformanceDeclarationError::BoundTooLow {
                    field,
                    minimum: 1,
                    value: 0,
                });
            }
        }
        if envelope.max_tokens_per_run < envelope.max_tokens_per_call {
            return Err(ConformanceDeclarationError::RunBoundBelowCallBound {
                per_run: "envelope.max_tokens_per_run",
                run_value: u64::from(envelope.max_tokens_per_run),
                per_call: "envelope.max_tokens_per_call",
                call_value: u64::from(envelope.max_tokens_per_call),
            });
        }
        if envelope.max_latency_ms_per_run < envelope.max_latency_ms_per_call {
            return Err(ConformanceDeclarationError::RunBoundBelowCallBound {
                per_run: "envelope.max_latency_ms_per_run",
                run_value: u64::from(envelope.max_latency_ms_per_run),
                per_call: "envelope.max_latency_ms_per_call",
                call_value: u64::from(envelope.max_latency_ms_per_call),
            });
        }
        if envelope.max_contradiction_rate_ppm > PPM_DENOMINATOR {
            return Err(ConformanceDeclarationError::BoundTooHigh {
                field: "envelope.max_contradiction_rate_ppm",
                maximum: u64::from(PPM_DENOMINATOR),
                value: u64::from(envelope.max_contradiction_rate_ppm),
            });
        }
        Ok(())
    }

    fn validate_mutations(&self, manifest: &IntegrationManifest) -> Result<(), ConformanceDeclarationError> {
        let mutations = &self.expected_mutations;
        let mut declared_writes: u64 = 0;
        for fact in &mutations.facts {
            if fact.entity_prefix.trim().is_empty() {
                return Err(ConformanceDeclarationError::MissingField(
                    "expected_mutations.facts[].entity_prefix",
                ));
            }
            if fact.keys.iter().any(|key| key.trim().is_empty()) {
                return Err(ConformanceDeclarationError::MissingField(
                    "expected_mutations.facts[].keys[]",
                ));
            }
            if fact.max_per_call == 0 {
                return Err(ConformanceDeclarationError::BoundTooLow {
                    field: "expected_mutations.facts[].max_per_call",
                    minimum: 1,
                    value: 0,
                });
            }
            if fact.private && !manifest.data_access.private_facts {
                return Err(ConformanceDeclarationError::PrivateWriteWithoutAccess);
            }
            declared_writes += u64::from(fact.max_per_call);
        }

        let mut seen_kinds = std::collections::BTreeSet::new();
        for receipt in &mutations.receipts {
            if !seen_kinds.insert(receipt.receipt_kind) {
                return Err(ConformanceDeclarationError::DuplicateReceiptKind(
                    receipt.receipt_kind.as_str(),
                ));
            }
            if receipt.max_per_call == 0 {
                return Err(ConformanceDeclarationError::BoundTooLow {
                    field: "expected_mutations.receipts[].max_per_call",
                    minimum: 1,
                    value: 0,
                });
            }
        }

        let writes = !mutations.facts.is_empty();
        if writes
            && !manifest
                .capabilities
                .iter()
                .any(|capability| capability == "facts:write")
        {
            return Err(ConformanceDeclarationError::WritesWithoutCapability("facts:write"));
        }
        if declared_writes > u64::from(self.envelope.max_fact_writes_per_call) {
            return Err(ConformanceDeclarationError::WriteBudgetExceeded {
                declared: declared_writes,
                bound: self.envelope.max_fact_writes_per_call,
            });
        }
        // The three cross-checks below are what stop an envelope from being
        // decoration: a pack that writes must declare a half-life, a
        // non-zero undo cost, and a write budget; a pack that does not write
        // must declare all three as zero, so "writes nothing" is a claim the
        // replay can falsify rather than a field left blank.
        let (expected, condition) = if writes {
            ("non-zero", "fact writes")
        } else {
            ("zero", "no fact writes")
        };
        let consistent = |value: u64| if writes { value > 0 } else { value == 0 };
        if !consistent(self.envelope.decay.min_half_life_seconds) {
            return Err(ConformanceDeclarationError::InconsistentWithWrites {
                field: "envelope.decay.min_half_life_seconds",
                expected,
                condition,
                value: self.envelope.decay.min_half_life_seconds,
            });
        }
        if !consistent(u64::from(self.envelope.undo.max_operations_per_call)) {
            return Err(ConformanceDeclarationError::InconsistentWithWrites {
                field: "envelope.undo.max_operations_per_call",
                expected,
                condition,
                value: u64::from(self.envelope.undo.max_operations_per_call),
            });
        }
        if !consistent(u64::from(self.envelope.max_fact_writes_per_call)) {
            return Err(ConformanceDeclarationError::InconsistentWithWrites {
                field: "envelope.max_fact_writes_per_call",
                expected,
                condition,
                value: u64::from(self.envelope.max_fact_writes_per_call),
            });
        }
        Ok(())
    }

    fn validate_compatibility(&self, manifest: &IntegrationManifest) -> Result<(), ConformanceDeclarationError> {
        let compatibility = &self.compatibility;
        if compatibility.manifest_schema != manifest.schema {
            return Err(ConformanceDeclarationError::ManifestSchemaMismatch {
                declared: compatibility.manifest_schema.clone(),
                actual: manifest.schema.clone(),
            });
        }
        if !is_dotted_triple(&compatibility.min_daemon_version) {
            return Err(ConformanceDeclarationError::InvalidDaemonVersion(
                compatibility.min_daemon_version.clone(),
            ));
        }
        for version in &compatibility.supersedes {
            if version.trim().is_empty() {
                return Err(ConformanceDeclarationError::MissingField("compatibility.supersedes[]"));
            }
            if version == &manifest.version {
                return Err(ConformanceDeclarationError::SupersedesSelf(version.clone()));
            }
        }
        for migration in &compatibility.migrations {
            if migration.description.trim().is_empty() {
                return Err(ConformanceDeclarationError::MissingField(
                    "compatibility.migrations[].description",
                ));
            }
            if migration.to_version != manifest.version {
                return Err(ConformanceDeclarationError::MigrationTargetMismatch {
                    declared: migration.to_version.clone(),
                    actual: manifest.version.clone(),
                });
            }
            if !compatibility.supersedes.contains(&migration.from_version) {
                return Err(ConformanceDeclarationError::MigrationSourceNotSuperseded(
                    migration.from_version.clone(),
                ));
            }
        }
        Ok(())
    }
}

fn sorted_unique(values: &[String]) -> Vec<String> {
    let mut out = values.to_vec();
    out.sort();
    out.dedup();
    out
}

fn is_lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length && value.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn is_safe_relative_path(value: &str) -> bool {
    let path = std::path::Path::new(value);
    !path.is_absolute()
        && !value.is_empty()
        && !path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
}

fn is_dotted_triple(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()))
}

// ── Published schema document ───────────────────────────────────────────

/// The MIT-licensed JSON Schema for `pack.conformance.v1`.
///
/// Generated from this module rather than hand-maintained beside it. A
/// hand-written schema and a Rust type drift the first time a field is added
/// on one side only, and a stale schema is worse than none: an implementer
/// validates against it, passes, and is then rejected by the daemon. The
/// committed copy at [`SCHEMA_DOCUMENT_PATH`] is asserted byte-equal to this
/// function's output by `published_schema_document_matches_the_generator`, so
/// the file and the code cannot separate.
pub fn json_schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SCHEMA_DOCUMENT_ID,
        "title": PACK_CONFORMANCE_SCHEMA_V1,
        "description": "Signed conformance declaration carried inside a crux.integration.v1 pack manifest: what the pack claims to do, the corpus its declared operations are replayed against, the invariants that must hold, the numeric envelope its behaviour must stay inside, and what upgrading to or rolling back from it costs.",
        "$comment": "Copyright (c) 2026 CueCrux Ltd. SPDX-License-Identifier: MIT. This schema document is published under the MIT Licence so it can be implemented and vendored freely; the full notice is in docs/spec/pack-conformance-v1.md. The Crux daemon that enforces it remains Apache-2.0.",
        "license": {
            "spdx": "MIT",
            "url": "https://opensource.org/licenses/MIT",
            "notice": "docs/spec/pack-conformance-v1.md#licence"
        },
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema",
            "claimed_capabilities",
            "expected_mutations",
            "replay_corpus",
            "invariants",
            "envelope",
            "compatibility"
        ],
        "properties": {
            "schema": { "type": "string", "const": PACK_CONFORMANCE_SCHEMA_V1 },
            "claimed_capabilities": {
                "type": "array",
                "description": "Must equal the manifest's declared capability set.",
                "items": { "type": "string" }
            },
            "expected_mutations": { "$ref": "#/$defs/expected_mutations" },
            "replay_corpus": { "$ref": "#/$defs/replay_corpus" },
            "invariants": {
                "type": "array",
                "minItems": 1,
                "items": { "$ref": "#/$defs/invariant_test" }
            },
            "envelope": { "$ref": "#/$defs/behavioural_envelope" },
            "compatibility": { "$ref": "#/$defs/compatibility_assertions" }
        },
        "$defs": {
            "expected_mutations": {
                "type": "object",
                "additionalProperties": false,
                "required": ["facts", "receipts"],
                "properties": {
                    "facts": { "type": "array", "items": { "$ref": "#/$defs/expected_fact_mutation" } },
                    "receipts": { "type": "array", "items": { "$ref": "#/$defs/expected_receipt_mutation" } }
                }
            },
            "expected_fact_mutation": {
                "type": "object",
                "additionalProperties": false,
                "required": ["entity_prefix", "keys", "operation", "private", "max_per_call"],
                "properties": {
                    "entity_prefix": { "type": "string", "minLength": 1 },
                    "keys": {
                        "type": "array",
                        "description": "Keys written under the prefix; empty means any key.",
                        "items": { "type": "string", "minLength": 1 }
                    },
                    "operation": {
                        "type": "string",
                        "enum": [FactMutationOp::Write.as_str(), FactMutationOp::Supersede.as_str()]
                    },
                    "private": { "type": "boolean" },
                    "max_per_call": { "type": "integer", "minimum": 1 }
                }
            },
            "expected_receipt_mutation": {
                "type": "object",
                "additionalProperties": false,
                "required": ["receipt_kind", "max_per_call"],
                "properties": {
                    "receipt_kind": {
                        "type": "string",
                        "enum": [
                            ReceiptMutationKind::Dispatch.as_str(),
                            ReceiptMutationKind::FactWrite.as_str(),
                            ReceiptMutationKind::Supersession.as_str()
                        ]
                    },
                    "max_per_call": { "type": "integer", "minimum": 1 }
                }
            },
            "replay_corpus": {
                "type": "object",
                "additionalProperties": false,
                "required": ["corpus_id", "path", "sha256", "cases"],
                "properties": {
                    "corpus_id": {
                        "type": "string",
                        "minLength": 1,
                        "description": "Operator-readable corpus name. Mandatory: a behavioural number whose corpus is unnamed cannot be compared to a later one."
                    },
                    "path": { "type": "string", "minLength": 1, "description": "Relative to the pack directory." },
                    "sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
                    "cases": {
                        "type": "array",
                        "minItems": 1,
                        "maxItems": MAX_DECLARED_CASES,
                        "items": { "$ref": "#/$defs/declared_case" }
                    }
                }
            },
            "declared_case": {
                "type": "object",
                "additionalProperties": false,
                "required": ["case_id", "tool_name", "args"],
                "properties": {
                    "case_id": { "type": "string", "minLength": 1 },
                    "tool_name": { "type": "string", "minLength": 1 },
                    "args": { "description": "Arguments passed to the tool; any JSON value." }
                }
            },
            "invariant_test": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "description", "kind", "applies_to_cases"],
                "properties": {
                    "id": { "type": "string", "minLength": 1 },
                    "description": { "type": "string", "minLength": 1 },
                    "kind": {
                        "type": "string",
                        "enum": InvariantKind::ALL.iter().map(|kind| kind.as_str()).collect::<Vec<_>>()
                    },
                    "applies_to_cases": {
                        "type": "array",
                        "description": "Case ids this applies to; empty means every declared case.",
                        "items": { "type": "string", "minLength": 1 }
                    }
                }
            },
            "behavioural_envelope": {
                "type": "object",
                "additionalProperties": false,
                "description": "Every bound is an integer: JSON has no canonical form for a float, and this block is signed.",
                "required": [
                    "max_tokens_per_call",
                    "max_tokens_per_run",
                    "max_latency_ms_per_call",
                    "max_latency_ms_per_run",
                    "max_response_bytes_per_call",
                    "max_fact_writes_per_call",
                    "decay",
                    "max_contradiction_rate_ppm",
                    "undo"
                ],
                "properties": {
                    "max_tokens_per_call": { "type": "integer", "minimum": 1 },
                    "max_tokens_per_run": { "type": "integer", "minimum": 1 },
                    "max_latency_ms_per_call": { "type": "integer", "minimum": 1 },
                    "max_latency_ms_per_run": { "type": "integer", "minimum": 1 },
                    "max_response_bytes_per_call": { "type": "integer", "minimum": 1 },
                    "max_fact_writes_per_call": { "type": "integer", "minimum": 0 },
                    "decay": { "$ref": "#/$defs/decay_envelope" },
                    "max_contradiction_rate_ppm": {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": PPM_DENOMINATOR,
                        "description": "Contradictions the pack may introduce, per million facts written."
                    },
                    "undo": { "$ref": "#/$defs/undo_envelope" }
                }
            },
            "decay_envelope": {
                "type": "object",
                "additionalProperties": false,
                "required": ["min_half_life_seconds", "max_refreshes_per_call"],
                "properties": {
                    "min_half_life_seconds": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Zero is only valid for a pack that writes no facts."
                    },
                    "max_refreshes_per_call": { "type": "integer", "minimum": 0 }
                }
            },
            "undo_envelope": {
                "type": "object",
                "additionalProperties": false,
                "required": ["max_operations_per_call", "max_latency_ms"],
                "properties": {
                    "max_operations_per_call": {
                        "type": "integer",
                        "minimum": 0,
                        "description": "Non-zero exactly when the pack declares fact writes."
                    },
                    "max_latency_ms": { "type": "integer", "minimum": 0 }
                }
            },
            "compatibility_assertions": {
                "type": "object",
                "additionalProperties": false,
                "required": ["min_daemon_version", "manifest_schema", "supersedes", "migrations", "rollback_safe"],
                "properties": {
                    "min_daemon_version": { "type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$" },
                    "manifest_schema": { "type": "string", "const": crate::INTEGRATION_SCHEMA_V1 },
                    "supersedes": { "type": "array", "items": { "type": "string", "minLength": 1 } },
                    "migrations": { "type": "array", "items": { "$ref": "#/$defs/migration_assertion" } },
                    "rollback_safe": { "type": "boolean" }
                }
            },
            "migration_assertion": {
                "type": "object",
                "additionalProperties": false,
                "required": ["from_version", "to_version", "kind", "reversible", "description"],
                "properties": {
                    "from_version": { "type": "string", "minLength": 1 },
                    "to_version": { "type": "string", "minLength": 1 },
                    "kind": {
                        "type": "string",
                        "enum": [
                            MigrationKind::None.as_str(),
                            MigrationKind::SupersedeFacts.as_str(),
                            MigrationKind::RekeyEntities.as_str(),
                            MigrationKind::Reindex.as_str()
                        ]
                    },
                    "reversible": { "type": "boolean" },
                    "description": { "type": "string", "minLength": 1 }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DataAccess, ExternalToolDefinition, IntegrationEntry, ManifestHashes, NetworkAccess, SafetyPolicy,
        INTEGRATION_SCHEMA_V1,
    };

    fn tool(name: &str) -> ExternalToolDefinition {
        ExternalToolDefinition {
            name: name.to_string(),
            description: "reference tool".to_string(),
            input_schema: serde_json::json!({ "type": "object" }),
            consequence_metadata: None,
            auth_shared_secret_id: None,
        }
    }

    fn manifest() -> IntegrationManifest {
        IntegrationManifest {
            schema: INTEGRATION_SCHEMA_V1.to_string(),
            id: "ext.example.reference".to_string(),
            name: "Reference".to_string(),
            version: "0.2.0".to_string(),
            publisher_passport_fpr: "p_example".to_string(),
            summary: "Reference pack.".to_string(),
            entry: IntegrationEntry {
                kind: EntryKind::ExternalTool,
                path: "tools/reference.json".to_string(),
            },
            capabilities: vec!["facts:read".to_string(), "facts:write".to_string()],
            network: NetworkAccess::default(),
            data_access: DataAccess::default(),
            safety: SafetyPolicy::default(),
            hashes: ManifestHashes::default(),
            signature: None,
            external_tool_endpoint: Some("https://reference.pack.invalid/tools".to_string()),
            tools: vec![tool("ext.example.reference.read"), tool("ext.example.reference.write")],
            wasm_module_path: None,
            wasm_module_url: None,
            wasm_module_sha256: None,
            conformance: None,
        }
    }

    fn declaration() -> PackConformance {
        PackConformance {
            schema: PACK_CONFORMANCE_SCHEMA_V1.to_string(),
            claimed_capabilities: vec!["facts:read".to_string(), "facts:write".to_string()],
            expected_mutations: ExpectedMutations {
                facts: vec![ExpectedFactMutation {
                    entity_prefix: "ext.example.reference::notes::".to_string(),
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
            replay_corpus: ReplayCorpus {
                corpus_id: "reference-v1".to_string(),
                path: "replay-corpus.json".to_string(),
                sha256: "a".repeat(64),
                cases: vec![DeclaredCase {
                    case_id: "read-default".to_string(),
                    tool_name: "ext.example.reference.read".to_string(),
                    args: serde_json::json!({}),
                }],
            },
            invariants: vec![InvariantTest {
                id: "no-undeclared-writes".to_string(),
                description: "Writes stay under the declared prefix.".to_string(),
                kind: InvariantKind::NoUndeclaredFactWrites,
                applies_to_cases: Vec::new(),
            }],
            envelope: BehaviouralEnvelope {
                max_tokens_per_call: 512,
                max_tokens_per_run: 2048,
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

    #[test]
    fn a_well_formed_declaration_validates() {
        declaration().validate(&manifest()).expect("declaration must validate");
    }

    #[test]
    fn declaration_round_trips_through_json() {
        let declaration = declaration();
        let encoded = serde_json::to_string(&declaration).expect("encode");
        let decoded: PackConformance = serde_json::from_str(&encoded).expect("decode");
        assert_eq!(declaration, decoded);
    }

    #[test]
    fn claimed_capabilities_must_equal_the_manifests_declared_set() {
        let mut declaration = declaration();
        declaration.claimed_capabilities = vec!["facts:read".to_string()];
        assert!(matches!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::CapabilityMismatch { .. })
        ));
    }

    #[test]
    fn a_case_may_only_name_a_tool_the_manifest_declares() {
        let mut declaration = declaration();
        declaration.replay_corpus.cases[0].tool_name = "ext.example.reference.undeclared".to_string();
        assert!(matches!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::UnknownCaseTool { .. })
        ));
    }

    #[test]
    fn a_corpus_without_a_name_is_refused() {
        let mut declaration = declaration();
        declaration.replay_corpus.corpus_id = "  ".to_string();
        assert_eq!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::MissingField("replay_corpus.corpus_id"))
        );
    }

    #[test]
    fn a_corpus_digest_that_is_not_lowercase_sha256_is_refused() {
        let mut declaration = declaration();
        declaration.replay_corpus.sha256 = "A".repeat(64);
        assert!(matches!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::InvalidCorpusDigest(_))
        ));
    }

    #[test]
    fn a_corpus_path_escaping_the_pack_directory_is_refused() {
        let mut declaration = declaration();
        declaration.replay_corpus.path = "../../etc/passwd".to_string();
        assert!(matches!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::InvalidCorpusPath(_))
        ));
    }

    #[test]
    fn more_cases_than_the_hook_will_run_is_refused() {
        let mut declaration = declaration();
        let template = declaration.replay_corpus.cases[0].clone();
        declaration.replay_corpus.cases = (0..=MAX_DECLARED_CASES)
            .map(|index| DeclaredCase {
                case_id: format!("case-{index}"),
                ..template.clone()
            })
            .collect();
        assert_eq!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::TooManyCases(MAX_DECLARED_CASES + 1))
        );
    }

    #[test]
    fn duplicate_case_ids_are_refused() {
        let mut declaration = declaration();
        let duplicate = declaration.replay_corpus.cases[0].clone();
        declaration.replay_corpus.cases.push(duplicate);
        assert!(matches!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::DuplicateCaseId(_))
        ));
    }

    #[test]
    fn an_invariant_scoped_to_an_undeclared_case_is_refused() {
        let mut declaration = declaration();
        declaration.invariants[0].applies_to_cases = vec!["no-such-case".to_string()];
        assert!(matches!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::UnknownInvariantCase { .. })
        ));
    }

    #[test]
    fn a_declaration_with_no_invariants_is_refused() {
        let mut declaration = declaration();
        declaration.invariants.clear();
        assert_eq!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::MissingField("invariants"))
        );
    }

    #[test]
    fn a_run_bound_below_its_call_bound_is_refused() {
        let mut declaration = declaration();
        declaration.envelope.max_tokens_per_run = declaration.envelope.max_tokens_per_call - 1;
        assert!(matches!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::RunBoundBelowCallBound { .. })
        ));
    }

    #[test]
    fn a_contradiction_rate_above_one_hundred_percent_is_refused() {
        let mut declaration = declaration();
        declaration.envelope.max_contradiction_rate_ppm = PPM_DENOMINATOR + 1;
        assert!(matches!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::BoundTooHigh { .. })
        ));
    }

    #[test]
    fn declared_writes_must_fit_the_envelopes_write_bound() {
        let mut declaration = declaration();
        declaration.expected_mutations.facts[0].max_per_call = 2;
        assert_eq!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::WriteBudgetExceeded { declared: 2, bound: 1 })
        );
    }

    #[test]
    fn declaring_writes_without_the_write_capability_is_refused() {
        let mut manifest = manifest();
        manifest.capabilities = vec!["facts:read".to_string()];
        let mut declaration = declaration();
        declaration.claimed_capabilities = vec!["facts:read".to_string()];
        assert_eq!(
            declaration.validate(&manifest),
            Err(ConformanceDeclarationError::WritesWithoutCapability("facts:write"))
        );
    }

    #[test]
    fn declaring_a_private_write_without_private_data_access_is_refused() {
        let mut declaration = declaration();
        declaration.expected_mutations.facts[0].private = true;
        assert_eq!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::PrivateWriteWithoutAccess)
        );
    }

    #[test]
    fn a_writing_pack_must_declare_a_half_life_and_an_undo_cost() {
        for mutate in [
            (|declaration: &mut PackConformance| declaration.envelope.decay.min_half_life_seconds = 0)
                as fn(&mut PackConformance),
            |declaration: &mut PackConformance| declaration.envelope.undo.max_operations_per_call = 0,
        ] {
            let mut declaration = declaration();
            mutate(&mut declaration);
            assert!(matches!(
                declaration.validate(&manifest()),
                Err(ConformanceDeclarationError::InconsistentWithWrites { .. })
            ));
        }
    }

    #[test]
    fn a_non_writing_pack_must_declare_zero_write_bounds() {
        let mut declaration = declaration();
        declaration.expected_mutations.facts.clear();
        let mut manifest = manifest();
        manifest.capabilities = vec!["facts:read".to_string()];
        declaration.claimed_capabilities = vec!["facts:read".to_string()];
        // Half-life, undo cost and the write bound all still claim writes.
        assert!(matches!(
            declaration.validate(&manifest),
            Err(ConformanceDeclarationError::InconsistentWithWrites { .. })
        ));

        declaration.envelope.decay.min_half_life_seconds = 0;
        declaration.envelope.undo.max_operations_per_call = 0;
        declaration.envelope.max_fact_writes_per_call = 0;
        declaration
            .validate(&manifest)
            .expect("a read-only declaration validates");
    }

    #[test]
    fn a_duplicate_receipt_kind_is_refused() {
        let mut declaration = declaration();
        declaration.expected_mutations.receipts.push(ExpectedReceiptMutation {
            receipt_kind: ReceiptMutationKind::Dispatch,
            max_per_call: 2,
        });
        assert_eq!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::DuplicateReceiptKind("dispatch"))
        );
    }

    #[test]
    fn a_conformance_block_on_a_non_executing_kind_is_refused() {
        let mut manifest = manifest();
        manifest.entry.kind = EntryKind::McpConfig;
        manifest.external_tool_endpoint = None;
        manifest.tools.clear();
        assert_eq!(
            declaration().validate(&manifest),
            Err(ConformanceDeclarationError::NonExecutingKind(EntryKind::McpConfig))
        );
    }

    #[test]
    fn a_migration_must_target_this_version_and_come_from_a_superseded_one() {
        let mut declaration = declaration();
        declaration.compatibility.migrations = vec![MigrationAssertion {
            from_version: "0.1.0".to_string(),
            to_version: "9.9.9".to_string(),
            kind: MigrationKind::SupersedeFacts,
            reversible: true,
            description: "Re-derive notes.".to_string(),
        }];
        assert!(matches!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::MigrationTargetMismatch { .. })
        ));

        declaration.compatibility.migrations[0].to_version = "0.2.0".to_string();
        assert!(matches!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::MigrationSourceNotSuperseded(_))
        ));

        declaration.compatibility.supersedes = vec!["0.1.0".to_string()];
        declaration.validate(&manifest()).expect("declared migration validates");
    }

    #[test]
    fn superseding_this_packs_own_version_is_refused() {
        let mut declaration = declaration();
        declaration.compatibility.supersedes = vec!["0.2.0".to_string()];
        assert!(matches!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::SupersedesSelf(_))
        ));
    }

    #[test]
    fn a_non_numeric_minimum_daemon_version_is_refused() {
        let mut declaration = declaration();
        declaration.compatibility.min_daemon_version = "v0.5".to_string();
        assert!(matches!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::InvalidDaemonVersion(_))
        ));
    }

    #[test]
    fn a_wrong_schema_tag_is_refused() {
        let mut declaration = declaration();
        declaration.schema = "pack.conformance.v2".to_string();
        assert!(matches!(
            declaration.validate(&manifest()),
            Err(ConformanceDeclarationError::InvalidSchema(_))
        ));
    }

    #[test]
    fn the_declaration_is_inside_the_manifest_signing_payload() {
        let mut without = manifest();
        let hash_without = without.manifest_hash().expect("hash");
        without.conformance = Some(declaration());
        let hash_with = without.manifest_hash().expect("hash");
        assert_ne!(
            hash_without, hash_with,
            "a conformance block must change the manifest hash, or the signature does not cover it"
        );

        // A single bound moved is a different manifest.
        let mut nudged = without.clone();
        if let Some(declaration) = nudged.conformance.as_mut() {
            declaration.envelope.max_tokens_per_call += 1;
        }
        assert_ne!(hash_with, nudged.manifest_hash().expect("hash"));
    }

    #[test]
    fn a_manifest_without_a_declaration_hashes_exactly_as_before() {
        // The studio-board-example pack was signed before this block existed;
        // its committed hash is the regression oracle for "adding an optional
        // signed field broke every pack already in the wild".
        let manifest = manifest();
        assert!(manifest.conformance.is_none());
        let payload = manifest.signing_payload().expect("payload");
        let decoded: serde_json::Value = serde_json::from_slice(&payload).expect("decode payload");
        assert!(
            decoded.get("conformance").is_none(),
            "an absent declaration must not appear in the signing payload"
        );
    }
}
