// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Receipted key-value entity fact store.
//!
//! Facts are lightweight key-value pairs associated with entities. They carry
//! a source receipt reference and confidence score. The store supports BM25-style
//! keyword search over fact values and soft-delete via tombstone events.

use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_FACT_JOURNAL_RECORD_BYTES: usize = 64 * 1024 * 1024;
const LATEST_ONLY_COMPACTION_STALE_BYTES: u64 = 64 * 1024 * 1024;
const LATEST_ONLY_COMPACTION_STALE_EVENTS: usize = 128;

#[derive(Debug)]
struct DurabilityIndeterminate {
    source: std::io::Error,
}

impl std::fmt::Display for DurabilityIndeterminate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "fact journal append durability is indeterminate; restart required: {}",
            self.source
        )
    }
}

impl std::error::Error for DurabilityIndeterminate {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn indeterminate_durability_error(source: std::io::Error) -> std::io::Error {
    std::io::Error::other(DurabilityIndeterminate { source })
}

pub fn is_durability_indeterminate(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<DurabilityIndeterminate>())
}

fn serialize_journal_event_with_limit(event: &JournalEvent, max_bytes: usize) -> std::io::Result<String> {
    let line = serde_json::to_string(event).map_err(std::io::Error::other)?;
    if line.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("fact journal record exceeds the {max_bytes}-byte append ceiling"),
        ));
    }
    Ok(line)
}

/// Journal event for fact persistence.
//
// `large_enum_variant`: `Store` legitimately carries a whole `Fact` and is the
// DOMINANT variant (every write emits one), while the others hold only a few
// Strings. `JournalEvent` is a short-lived serialization DTO — constructed,
// written to one JSONL line, and dropped; it is never held in bulk where the
// size disparity would matter. Boxing the `Fact` would add a heap allocation to
// the hot write path for the common case to save stack bytes we never keep, so
// allowing the lint here is the deliberate, lower-cost choice.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
#[serde(tag = "op")]
enum JournalEvent {
    #[serde(rename = "store")]
    Store { fact: Fact },
    /// Latest-only replacement for bounded control-plane records. Unlike a
    /// versioned store, replay removes the named predecessors from all indexes
    /// before inserting `fact`, so churn cannot accumulate resident history.
    #[serde(rename = "replace_latest")]
    ReplaceLatest { fact: Fact, replaced_fact_ids: Vec<String> },
    #[serde(rename = "store_batch")]
    StoreBatch { facts: Vec<Fact> },
    #[serde(rename = "delete")]
    Delete { fact_id: String, deleted_at: String },
    /// Cross-entity supersession (M6): `fact_id` is retired by `by_fact_id`.
    #[serde(rename = "supersede")]
    Supersede {
        fact_id: String,
        by_fact_id: String,
        superseded_at: String,
    },
    /// Reverse of `Supersede` (M6): un-retire `fact_id`.
    #[serde(rename = "clear_supersede")]
    ClearSupersede { fact_id: String, cleared_at: String },
    /// Bi-temporal valid-time update (Graphiti model). Sets/clears the
    /// world-time interval `[valid_from, valid_to)` on an existing fact
    /// without rewriting its value. `None` on either end means open-ended.
    #[serde(rename = "set_validity")]
    SetValidity {
        fact_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        valid_from: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        valid_to: Option<DateTime<Utc>>,
        set_at: String,
    },
    /// Atomic consolidation (buyer-fit M2). A SINGLE journal event is the whole
    /// mutation's commit point: it stores the canonical fact and retires every
    /// `superseded_fact_id` (the consolidation targets PLUS the canonical's own
    /// prior version). One append ⇒ all-or-nothing; a failed append leaves the
    /// store untouched (no half-applied consolidation, the pre-M2 gap).
    #[serde(rename = "consolidate")]
    Consolidate {
        canonical: Fact,
        superseded_fact_ids: Vec<String>,
        consolidated_at: String,
    },
    /// Content-free consolidation provenance retained by journal compaction.
    /// Replay accepts it only when the canonical and every source already form
    /// the same-tenant supersession edges recorded here.
    #[serde(rename = "consolidation_provenance")]
    ConsolidationProvenance {
        canonical_fact_id: String,
        source_fact_ids: Vec<String>,
        tenant_hash: String,
        recorded_at: String,
    },
    /// Atomic, reversible undo of a `Consolidate` (buyer-fit M2). Retires the
    /// generated canonical and restores (`superseded_by = None`) every source.
    /// One append ⇒ all-or-nothing; idempotent (re-undo of an already-undone
    /// consolidation is a no-op).
    #[serde(rename = "consolidate_undo")]
    ConsolidateUndo {
        canonical_fact_id: String,
        restored_fact_ids: Vec<String>,
        undone_at: String,
    },
}

/// Per-fact freshness horizon class (child ExecPlan
/// `agent-ux-03-freshness-decay-2026-05-27`).
///
/// Drives the deterministic decay function in
/// `corecrux-projections::decay`: `volatile` facts go stale after a day,
/// `medium` after about a month, `stable` after a year, and `none` never
/// decays. The class is per-fact; callers either set it explicitly via
/// `store_fact`/`memory_set_horizon` or accept the default of
/// [`HorizonClass::None`] (preserves pre-freshness behaviour for legacy
/// callers — strict backwards-compat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum HorizonClass {
    /// Goes stale quickly (default policy: 24 hours). Use for deploy state,
    /// process IDs, currently-measured metrics that change daily.
    Volatile,
    /// Goes stale after about a month (default policy: 35 days). Use for
    /// per-tenant counts in active backfill, preferences, traits.
    Medium,
    /// Goes stale after about a year (default policy: 365 days). Use for
    /// architectural counts, naming conventions, layout decisions.
    Stable,
    /// Never decays. Use for identity, immutable history, user-pinned facts.
    None,
}

impl HorizonClass {
    /// Stable string form used in JSON-RPC and the journal.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Volatile => "volatile",
            Self::Medium => "medium",
            Self::Stable => "stable",
            Self::None => "none",
        }
    }

    /// Parse a free-text horizon class. Case-insensitive; returns `None`
    /// for unknown values so callers can surface a typed param error.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "volatile" => Some(Self::Volatile),
            "medium" => Some(Self::Medium),
            "stable" => Some(Self::Stable),
            "none" => Some(Self::None),
            _ => None,
        }
    }

    /// Default horizon class inferred from an entity prefix when none is
    /// explicitly set on a fact. Matches the operator's
    /// `freshness_horizon:` convention from CLAUDE.md §"Freshness
    /// horizons": deploy state and reserved-prefix metrics are
    /// short-lived, bench numbers and architectural records last longer.
    pub fn default_for_entity(entity: &str) -> Self {
        if entity.starts_with("__ops::") {
            Self::Volatile
        } else if entity.starts_with("bench:") || entity.starts_with("__bootstrap__::") {
            Self::Stable
        } else if entity.starts_with("execplan:")
            || entity.starts_with("incident:")
            || entity.starts_with("__candidate_fact__::")
        {
            // Auto-capture candidates (M1) are medium-lived: a pending review
            // should not decay away in a day, but is not a permanent record.
            Self::Medium
        } else {
            Self::None
        }
    }
}

impl Default for HorizonClass {
    fn default() -> Self {
        // Default for replay of pre-freshness journal entries: never
        // decay, never lie about it.
        Self::None
    }
}

/// A single fact in the store.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Fact {
    pub fact_id: String,
    /// Tenant isolation stamp. Historical facts deserialize into the single-
    /// tenant `default` namespace, so no backfill or down-migration is needed.
    #[serde(default = "default_tenant_hash")]
    pub tenant_hash: String,
    pub entity: String,
    pub key: String,
    pub value: String,
    pub source_receipt: Option<String>,
    pub confidence: f32,
    pub stored_at: DateTime<Utc>,
    pub tokens: usize,
    pub deleted: bool,
    /// Monotonic version number for this (entity, key) pair. Starts at 1.
    #[serde(default = "default_version")]
    pub version: u32,
    /// The fact_id this fact supersedes (previous version of the same entity+key).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    /// Private facts are never pushed to a remote during sync.
    #[serde(default)]
    pub private: bool,
    /// Freshness horizon class — drives the deterministic decay function
    /// in `corecrux-projections::decay`. Defaulted to
    /// [`HorizonClass::None`] for replay of pre-freshness journal
    /// entries (additive schema change; existing facts are treated as
    /// never stale).
    #[serde(default)]
    pub horizon_class: HorizonClass,
    /// Re-verification anchor — when set, decay is measured from this
    /// timestamp instead of `stored_at`. Updated by `memory_reverify`
    /// without rewriting the fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reverified_at: Option<DateTime<Utc>>,
    /// Cross-entity supersession marker (M6). When set, this fact has been
    /// EXPLICITLY retired by a newer fact (identified by fact_id) that may
    /// live under a *different* entity — unlike `supersedes`/`version`,
    /// which only chains within the same `(entity, key)` pair. Reversible
    /// soft-state: set by `mark_superseded`, cleared by `clear_superseded`.
    /// `query_facts` hides these by default (opt back in with
    /// `include_superseded`); `memory_view` / `fact_history` still show them.
    /// `#[serde(default)]` so pre-M6 on-disk facts deserialize as `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    /// Durable authorship: the resolved passport_id (or raw agent name) that
    /// wrote this fact. Set by the MCP `store_fact` path when the
    /// `CORECRUXD_AGENT_PASSPORTS` flag is on (agent-passport M1). Additive
    /// schema change — `#[serde(default, skip_serializing_if = "Option::is_none")]`
    /// exactly mirrors `supersedes` / `reverified_at` / `superseded_by` so the
    /// ~2.1k existing on-disk facts and pre-M1 journal-replay entries
    /// deserialize as `actor = None` and serialize without the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<String>,
    /// Bi-temporal VALID-TIME start (Graphiti model). When the fact became
    /// true IN THE WORLD — distinct from `stored_at`, which is *transaction
    /// time* (when this node learned it). `None` = "true since the beginning
    /// of time" (open lower bound). Set via [`FactStore::set_validity`].
    /// Additive schema change: pre-bitemporal on-disk facts and journal
    /// replay entries deserialize as `None` (valid for all past time),
    /// mirroring `supersedes` / `reverified_at` / `superseded_by` / `actor`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    /// Bi-temporal VALID-TIME end (exclusive). When the fact stopped being
    /// true in the world. `None` = "still true" (open upper bound). A fact
    /// retired in transaction time (`superseded_by`) is independent of this:
    /// validity records world-truth, supersession records our belief state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_to: Option<DateTime<Utc>>,
    /// Salience signal (M2): how many times this fact has been returned by
    /// recall. A frequently-recalled fact is evidently important, so decay is
    /// slowed for it (see `corecrux_projections::decay::salience_factor`).
    /// Maintained in-memory by [`FactStore::record_access`] on the read path —
    /// NOT journaled (journaling every recall would balloon the append log on
    /// the hot path); it is a ranking heuristic, not a durable claim, and
    /// re-accumulates after a restart. `#[serde(default)]` ⇒ 0 for all
    /// pre-M2 on-disk facts, where `salience_factor(0) == 1.0` makes decay
    /// byte-identical to pre-salience behaviour.
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub access_count: u32,
    /// Wall-clock of the most recent recall (M2). In-memory companion to
    /// `access_count`; not journaled. `None` until first recalled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_accessed_at: Option<DateTime<Utc>>,
}

fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

fn default_version() -> u32 {
    1
}

/// Tenant namespace used until authenticated contexts carry a tenant claim.
///
/// Keeping the fallback in one helper makes future context-derived stamping a
/// one-line change while preserving existing single-tenant query behaviour.
pub fn default_tenant_hash() -> String {
    "default".to_string()
}

impl Fact {
    /// Bi-temporal predicate: was this fact true IN THE WORLD at `instant`?
    ///
    /// The valid-time interval is half-open `[valid_from, valid_to)`:
    /// `instant >= valid_from` (or `valid_from` is open) AND
    /// `instant < valid_to` (or `valid_to` is open). A fact with both ends
    /// open (the default for pre-bitemporal facts) is valid at every instant,
    /// so adding this filter never hides legacy facts. Pure — no clock read.
    pub fn valid_at(&self, instant: DateTime<Utc>) -> bool {
        let after_start = self.valid_from.is_none_or(|from| instant >= from);
        let before_end = self.valid_to.is_none_or(|to| instant < to);
        after_start && before_end
    }
}

/// Request to store a new fact.
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct StoreFact {
    /// Tenant stamp supplied by the trusted write path. JSON callers cannot
    /// bypass isolation because daemon/MCP handlers overwrite it from their
    /// authenticated context before storage.
    #[serde(default = "default_tenant_hash")]
    pub tenant_hash: String,
    pub entity: String,
    pub key: String,
    pub value: String,
    pub source_receipt: Option<String>,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    /// If true, this fact will never be pushed to a remote during sync.
    #[serde(default)]
    pub private: bool,
    /// Optional freshness horizon class — when omitted, falls back to
    /// [`HorizonClass::default_for_entity`] using the entity name.
    #[serde(default)]
    pub horizon_class: Option<HorizonClass>,
    /// Optional durable authorship (resolved passport_id or raw agent name).
    /// Defaults to `None` so callers that don't set it (and the flag-OFF MCP
    /// path) write `actor = None` — byte-for-byte the pre-M1 behaviour.
    #[serde(default)]
    pub actor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ContradictionCandidateV1 {
    pub entity: String,
    pub key: String,
    pub reason: String,
    pub polarity_a: String,
    pub polarity_b: String,
    pub fact_ids: Vec<String>,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ConsolidationRequestV1 {
    pub consolidation_id: String,
    pub entity: String,
    pub key: String,
    pub canonical_value: String,
    pub target_fact_ids: Vec<String>,
    #[serde(default)]
    pub protected_fact_ids: Vec<String>,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    #[serde(default)]
    pub source_receipt: Option<String>,
    #[serde(default)]
    pub actor: Option<String>,
    #[serde(default)]
    pub horizon_class: Option<HorizonClass>,
    #[serde(default = "default_consolidation_protected_confidence_floor")]
    pub protected_confidence_floor: f32,
}

fn default_consolidation_protected_confidence_floor() -> f32 {
    0.99
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ConsolidationReceiptV1 {
    pub consolidation_id: String,
    pub canonical_fact_id: String,
    /// `blake3:<hex>` of the canonical value — the "after" side of the diff,
    /// carried so the call layer can mint a signed CROWN receipt (M2) without a
    /// re-read. `superseded_fact_ids` is the "before" side (retrievable rows).
    pub canonical_hash: String,
    pub superseded_fact_ids: Vec<String>,
    pub source_fact_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ConsolidationPassReportV1 {
    pub status: String,
    pub receipt: ConsolidationReceiptV1,
}

/// Result of [`FactStore::consolidate_undo_v1`] (buyer-fit M2).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct ConsolidationUndoReportV1 {
    /// `"undone"` or `"already_undone"` (idempotent no-op).
    pub status: String,
    pub canonical_fact_id: String,
    /// The source facts actually restored (`superseded_by` cleared).
    pub restored_fact_ids: Vec<String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ConsolidationErrorV1 {
    #[error("consolidation requires at least one target fact")]
    NoTargets,
    #[error("consolidation_id must not be empty")]
    MissingConsolidationId,
    #[error("target fact not found: {0}")]
    TargetNotFound(String),
    #[error("target fact is deleted: {0}")]
    TargetDeleted(String),
    #[error("target fact is already superseded: {0}")]
    TargetAlreadySuperseded(String),
    #[error("duplicate target fact id: {0}")]
    DuplicateTarget(String),
    #[error("target fact is protected by caller: {0}")]
    TargetPinned(String),
    #[error("target fact is private: {0}")]
    TargetPrivate(String),
    #[error("target fact is receipt-linked: {0}")]
    TargetReceiptLinked(String),
    #[error("target fact belongs to daemon-owned namespace '{prefix}': {fact_id}")]
    TargetDaemonOwned { fact_id: String, prefix: String },
    #[error("target fact confidence is protected: {fact_id} confidence={confidence}")]
    TargetHighConfidence { fact_id: String, confidence: String },
    #[error("target fact is outside requested entity/key: {0}")]
    TargetOutsideEntityKey(String),
    #[error("current prior version must be an explicitly validated target: {0}")]
    ImplicitPriorNotTarget(String),
    #[error("consolidation undo requires a non-empty exact source set")]
    NoUndoSources,
    #[error("fact is not a consolidation canonical: {0}")]
    NotConsolidationCanonical(String),
    #[error("consolidation canonical has a newer successor and cannot be undone: {0}")]
    CanonicalSuperseded(String),
    #[error("consolidation undo source set does not match canonical edges: {0}")]
    UndoSourceMismatch(String),
    #[error("fact journal append failed: {0}")]
    Journal(String),
}

fn default_confidence() -> f32 {
    1.0
}

/// Query parameters for fact retrieval.
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct FactQuery {
    pub query: Option<String>,
    pub entity: Option<String>,
    /// Optional tenant filter. `None` preserves the historical single-tenant
    /// result set; `Some` restricts results to the matching tenant stamp.
    #[serde(default)]
    pub tenant_hash: Option<String>,
    /// Filter entities starting with this prefix (e.g., `__ops__::` or `__bootstrap__::`)
    #[serde(default)]
    pub entity_prefix: Option<String>,
    #[serde(default = "default_top_k")]
    pub top_k: usize,
    pub token_budget: Option<usize>,
    /// Confidence floor (P2): drop facts whose recall-time EFFECTIVE
    /// confidence (stored confidence, stale-demoted per
    /// `corecrux_projections::decay`) is below this. `None` = no floor
    /// (default; behaviour unchanged).
    ///
    /// NOTE: the store's own [`FactStore::query`] ranks by *raw* confidence
    /// and does NOT enforce this (the low-level store has no decay dependency).
    /// It is honoured by the recall surfaces that compute effective confidence:
    /// the MCP `query_facts` handler and `GET /v1/facts`. The field is carried
    /// here so those surfaces can pass it through one query struct.
    #[serde(default)]
    pub min_effective_confidence: Option<f32>,
}

impl Default for FactQuery {
    /// `top_k` defaults to `default_top_k()` (10), matching the serde default —
    /// so `..Default::default()` construction never silently yields `top_k = 0`.
    /// Future field adds only need a line here, not an edit at every call site.
    fn default() -> Self {
        Self {
            query: None,
            entity: None,
            tenant_hash: None,
            entity_prefix: None,
            top_k: default_top_k(),
            token_budget: None,
            min_effective_confidence: None,
        }
    }
}

fn default_top_k() -> usize {
    10
}

/// In-memory fact store with keyword search and optional JSONL persistence.
#[derive(Debug, Default)]
pub struct FactStore {
    facts: HashMap<String, Fact>,
    entity_index: HashMap<String, Vec<String>>,
    /// Index of (tenant, entity, key) → ordered list of fact_ids (version chain).
    ///
    /// Tenant is part of the chain identity: a same-named write in tenant B
    /// must never advance or retire tenant A's predecessor.
    key_index: HashMap<(String, String, String), Vec<String>>,
    /// Canonical fact id → exact source ids recorded by a durable
    /// `JournalEvent::Consolidate`. This is provenance, not caller-controlled
    /// fact content, and is rebuilt on replay.
    consolidation_sources: HashMap<String, Vec<String>>,
    /// Path to the JSONL journal file. `None` for pure in-memory mode.
    journal_path: Option<PathBuf>,
    /// A newline-complete durable append whose fsync outcome is unknown may
    /// replay after restart even though its caller received an error. Block
    /// every later authority-changing durable append so a retry cannot create
    /// a competing history from stale resident state.
    durability_poisoned: std::sync::atomic::AtomicBool,
    /// Number of pre-sidecar `__repo_scan__` journal records skipped by the
    /// bounded replay reader. Each such record is at least 64 MiB, so a scalar
    /// keeps resident recovery state constant-size.
    oversized_legacy_scan_records_skipped: std::sync::atomic::AtomicUsize,
    /// Approximate value bytes and event count made obsolete by latest-only
    /// daemon-control replacements since the last successful compaction.
    latest_only_pruned_bytes: std::sync::atomic::AtomicU64,
    latest_only_pruned_events: std::sync::atomic::AtomicUsize,
    /// A malformed newline-delimited event was skipped during replay. Automatic
    /// compaction must not erase that evidence; only explicit operator
    /// compaction may choose to do so.
    journal_replay_corruption_detected: std::sync::atomic::AtomicBool,
    #[cfg(any(test, feature = "test-support"))]
    fail_next_durable_append_after_write: std::sync::atomic::AtomicBool,
    /// Optional event bus for real-time mutation notifications.
    event_bus: Option<crate::events::EventBus>,
    /// Optional embedder for dense vector retrieval. Any [`crate::embeddings::Embedder`]:
    /// an external HTTP `EmbeddingClient` (BYOE/paid) or the pure-Rust
    /// `LocalHashEmbedder` wired by default when no external URL is set
    /// (buyer-fit M3.2 — dense works offline by default).
    embedder: Option<Box<dyn crate::embeddings::Embedder>>,
    /// Stored embeddings keyed by fact_id.
    embeddings: HashMap<String, Vec<f32>>,
    /// Cosine threshold for store-time semantic-dedup (buyer-fit M3.5). `None`
    /// disables it. When set (and an embedder is present), a newly stored fact
    /// whose vector is ≥ threshold cosine to an existing DISTINCT fact is flagged
    /// as a near-duplicate review candidate.
    dedup_threshold: Option<f32>,
    /// Pending near-duplicate flags (buyer-fit M3.5). The daemon drains these via
    /// [`Self::take_near_duplicates`] after fact writes and files each into the
    /// `__candidate_fact__::` review queue (buyer-fit FU2); the queue, not this
    /// Vec, is the durable review record.
    near_duplicates: Vec<NearDuplicate>,
}

/// A store-time semantic near-duplicate flag (buyer-fit M3.5): `fact_id` is a
/// near-duplicate of the already-stored `similar_to` at cosine `score`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NearDuplicate {
    pub fact_id: String,
    pub similar_to: String,
    pub score: f32,
}

/// Quarantine an unterminated JSONL tail, the signature of a crash during one
/// append. Even parseable JSON is not treated as committed: the append never
/// completed its record delimiter and therefore may not have returned success
/// to the caller. Newline-terminated corruption remains fail-visible.
fn repair_torn_journal_tail(path: &Path) -> std::io::Result<()> {
    repair_torn_journal_tail_with_limit(path, MAX_FACT_JOURNAL_RECORD_BYTES as u64)
}

fn repair_torn_journal_tail_with_limit(path: &Path, max_quarantine_bytes: u64) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last_byte = [0_u8; 1];
    file.read_exact(&mut last_byte)?;
    if last_byte[0] == b'\n' {
        return Ok(());
    }

    let mut cursor = len;
    let mut tail_start = 0_u64;
    let mut block = vec![0_u8; 8 * 1024];
    while cursor > 0 {
        let start = cursor.saturating_sub(block.len() as u64);
        let width = (cursor - start) as usize;
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut block[..width])?;
        if let Some(index) = block[..width].iter().rposition(|byte| *byte == b'\n') {
            tail_start = start + index as u64 + 1;
            break;
        }
        cursor = start;
    }
    let tail_len = len.saturating_sub(tail_start);
    let oversized = tail_len > max_quarantine_bytes;
    let quarantine_suffix = if oversized {
        format!("jsonl.torn.{}.metadata.json", uuid::Uuid::new_v4().simple())
    } else {
        format!("jsonl.torn.{}", uuid::Uuid::new_v4().simple())
    };
    let quarantine = path.with_extension(quarantine_suffix);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut torn = options.open(&quarantine)?;
    if oversized {
        serde_json::to_writer(
            &mut torn,
            &serde_json::json!({
                "schema_version": 1,
                "tail_start": tail_start,
                "tail_len": tail_len,
                "capture_limit_bytes": max_quarantine_bytes,
                "reason": "oversized_unterminated_uncommitted_record",
            }),
        )
        .map_err(std::io::Error::other)?;
        torn.write_all(b"\n")?;
    } else {
        let tail_size = usize::try_from(tail_len)
            .map_err(|_| std::io::Error::other("torn fact journal tail length does not fit usize"))?;
        let mut tail = vec![0_u8; tail_size];
        file.seek(SeekFrom::Start(tail_start))?;
        file.read_exact(&mut tail)?;
        torn.write_all(&tail)?;
    }
    torn.sync_all()?;
    // Fence the quarantine directory entry before destructively truncating
    // the source. A crash must never lose both the uncommitted tail and its
    // quarantine/metadata record.
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    file.set_len(tail_start)?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    tracing::error!(
        journal = %path.display(),
        quarantine = %quarantine.display(),
        bytes = tail_len,
        payload_captured = !oversized,
        "quarantined torn fact-journal tail before durable append"
    );
    Ok(())
}

#[derive(Debug)]
enum BoundedJournalRecord {
    Json(Vec<u8>),
    OversizedLegacyScan,
}

fn read_bounded_journal_record(
    reader: &mut impl BufRead,
    max_bytes: usize,
) -> std::io::Result<Option<BoundedJournalRecord>> {
    let mut line = Vec::with_capacity(max_bytes.min(64 * 1024));
    let mut oversized_legacy_scan = false;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return if line.is_empty() && !oversized_legacy_scan {
                Ok(None)
            } else if oversized_legacy_scan {
                Ok(Some(BoundedJournalRecord::OversizedLegacyScan))
            } else {
                Ok(Some(BoundedJournalRecord::Json(line)))
            };
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let payload_len = newline.unwrap_or(buffer.len());
        if !oversized_legacy_scan {
            if payload_len <= max_bytes.saturating_sub(line.len()) {
                line.extend_from_slice(&buffer[..payload_len]);
            } else {
                let remaining = max_bytes.saturating_sub(line.len());
                line.extend_from_slice(&buffer[..remaining]);
                let is_store_event = line.starts_with(br#"{"op":"store","fact":{"#);
                let legacy_scan_markers = [
                    br#""entity":"__repo_scan__::"#.as_slice(),
                    br#""entity":"__workspace_scan__::"#.as_slice(),
                ];
                let is_legacy_scan = is_store_event
                    && legacy_scan_markers
                        .iter()
                        .any(|marker| line.windows(marker.len()).any(|window| window == *marker));
                if !is_legacy_scan {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("fact journal record exceeds the {max_bytes}-byte replay ceiling"),
                    ));
                }
                oversized_legacy_scan = true;
                line.clear();
                line.shrink_to_fit();
            }
        }
        let consumed = newline.map_or(buffer.len(), |index| index + 1);
        reader.consume(consumed);
        if newline.is_some() {
            return if oversized_legacy_scan {
                Ok(Some(BoundedJournalRecord::OversizedLegacyScan))
            } else {
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                Ok(Some(BoundedJournalRecord::Json(line)))
            };
        }
    }
}

impl FactStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether mutations are backed by the durable JSONL journal.
    pub fn persistence_enabled(&self) -> bool {
        self.journal_path.is_some()
    }

    /// Whether a durable append may have committed on disk without being
    /// reflected in resident state.
    ///
    /// Callers that coordinate destructive cleanup with FactStore authority
    /// must treat this as a global preservation barrier until restart/replay.
    pub fn journal_durability_poisoned(&self) -> bool {
        self.durability_poisoned.load(std::sync::atomic::Ordering::Acquire)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    pub fn fail_next_durable_append_after_write_for_test(&self) {
        self.fail_next_durable_append_after_write
            .store(true, std::sync::atomic::Ordering::Release);
    }

    /// Attach an event bus so that `store()` and `delete()` emit real-time events.
    pub fn set_event_bus(&mut self, bus: crate::events::EventBus) {
        self.event_bus = Some(bus);
    }

    /// Attach an embedder for dense vector retrieval. Any [`crate::embeddings::Embedder`]
    /// — the external HTTP `EmbeddingClient` or the pure-Rust `LocalHashEmbedder`.
    /// When set, facts are embedded at store time and queries use cosine
    /// similarity blended with confidence for ranking.
    pub fn set_embedder(&mut self, embedder: Box<dyn crate::embeddings::Embedder>) {
        tracing::info!(
            model = %embedder.model(),
            dimensions = embedder.dimensions(),
            "fact-store-embeddings-enabled"
        );
        self.embedder = Some(embedder);
    }

    /// Attach an external HTTP embedding client. Thin wrapper over
    /// [`Self::set_embedder`] retained for existing call sites.
    pub fn set_embedding_client(&mut self, client: crate::embeddings::EmbeddingClient) {
        self.set_embedder(Box::new(client));
    }

    /// Returns true if an embedder is configured.
    pub fn embeddings_enabled(&self) -> bool {
        self.embedder.is_some()
    }

    /// Returns true only when the configured embedder executes in this daemon.
    pub fn local_embeddings_enabled(&self) -> bool {
        self.embedder.as_ref().is_some_and(|embedder| embedder.runs_locally())
    }

    /// Runtime state for authenticated CoreCrux embedding delegation. `None`
    /// means the configured embedder, if any, is not a `DelegatingEmbedder`.
    pub fn delegation_status(&self) -> Option<crate::embeddings::DelegationStatus> {
        self.embedder.as_ref().and_then(|embedder| embedder.delegation_status())
    }

    /// Latch a persisted-vector/profile incompatibility into delegation
    /// capability state without incrementing the transport circuit breaker.
    pub fn report_semantic_profile_mismatch(&self) {
        if let Some(embedder) = self.embedder.as_ref() {
            embedder.report_semantic_profile_mismatch();
        }
    }

    /// Clear the persisted-vector/profile mismatch latch after a strict
    /// compatibility check succeeds or incompatible vectors are removed.
    pub fn clear_semantic_profile_mismatch(&self) {
        if let Some(embedder) = self.embedder.as_ref() {
            embedder.clear_semantic_profile_mismatch();
        }
    }

    /// Enable store-time semantic near-duplicate detection at `threshold` cosine
    /// (buyer-fit M3.5). Only effective when an embedder is also configured.
    pub fn set_semantic_dedup(&mut self, threshold: f32) {
        tracing::info!(threshold, "fact-store-semantic-dedup-enabled");
        self.dedup_threshold = Some(threshold);
    }

    /// The near-duplicate review flags recorded so far (buyer-fit M3.5).
    /// Ephemeral in-memory signal; see the `near_duplicates` field note.
    pub fn near_duplicates(&self) -> &[NearDuplicate] {
        &self.near_duplicates
    }

    /// Drain the accumulated near-duplicate flags (buyer-fit FU2). The daemon
    /// layer calls this after fact writes and routes each into the
    /// `__candidate_fact__::` review queue (which this crate cannot reach —
    /// it lives in `corecruxd`). Draining guarantees each flag is routed once.
    pub fn take_near_duplicates(&mut self) -> Vec<NearDuplicate> {
        std::mem::take(&mut self.near_duplicates)
    }

    /// Find the highest-cosine existing DISTINCT fact for `fact` at or above the
    /// dedup threshold (buyer-fit M3.5). Same-`(entity, key)` facts are skipped —
    /// those are version-chain updates, not semantic duplicates. Reserved
    /// (`__…::`) entities — candidates, ops, bootstrap — are excluded on both
    /// sides so internal/candidate facts are never dedup-reviewed (and the
    /// candidate rows FU2 writes can't re-trigger detection). Read-only.
    fn detect_near_duplicate(&self, fact: &Fact, threshold: f32) -> Option<(String, f32)> {
        if fact.entity.starts_with("__") {
            return None;
        }
        let new_vec = self.embeddings.get(&fact.fact_id)?;
        let mut best: Option<(String, f32)> = None;
        for (other_id, other_vec) in &self.embeddings {
            if other_id == &fact.fact_id {
                continue;
            }
            let Some(other) = self.facts.get(other_id) else {
                continue;
            };
            if other.deleted
                || other.tenant_hash != fact.tenant_hash
                || other.entity.starts_with("__")
                || (other.entity == fact.entity && other.key == fact.key)
            {
                continue;
            }
            let sim = crate::embeddings::cosine_similarity(new_vec, other_vec);
            if sim >= threshold && best.as_ref().is_none_or(|(_, s)| sim > *s) {
                best = Some((other_id.clone(), sim));
            }
        }
        best
    }

    /// Return the semantic profile for the configured embedder.
    pub fn semantic_profile(&self) -> Option<crate::embeddings::SemanticProfile> {
        self.embedder.as_ref().map(|embedder| embedder.semantic_profile())
    }

    /// Fallible single-text embedding. `Ok(None)` means no embedder is
    /// configured; a configured provider failure is preserved as `Err` so a
    /// delegation-required caller can surface capability degradation.
    pub fn try_embed_text(&self, text: &str) -> Result<Option<Vec<f32>>, crate::embeddings::EmbeddingError> {
        let Some(embedder) = self.embedder.as_ref() else {
            return Ok(None);
        };
        embedder.embed_one(text).map(Some)
    }

    /// Fallible batch embedding. The batch is all-or-nothing: a provider error
    /// never becomes an empty or partially embedded result.
    pub fn try_embed_texts(&self, texts: &[&str]) -> Result<Option<Vec<Vec<f32>>>, crate::embeddings::EmbeddingError> {
        let Some(embedder) = self.embedder.as_ref() else {
            return Ok(None);
        };
        embedder.embed_batch(texts).map(Some)
    }

    /// Embed a single text with the node's embedder, or `None` when no embedder
    /// is configured or the embed fails. Used by the prose lane (buyer-fit M3.2)
    /// so document and query vectors come from the SAME embedder as the fact
    /// lane — a shared node-wide embedder keeps them fingerprint-compatible.
    pub fn embed_text(&self, text: &str) -> Option<Vec<f32>> {
        match self.try_embed_text(text) {
            Ok(vec) => vec,
            Err(err) => {
                tracing::warn!(?err, "prose-embed-failed");
                None
            }
        }
    }

    /// Batch form of [`Self::embed_text`]. Returns `None` when no embedder is
    /// configured; on a batch error, returns `None` (callers fall back to
    /// BM25-only rather than a partially-embedded corpus).
    pub fn embed_texts(&self, texts: &[&str]) -> Option<Vec<Vec<f32>>> {
        match self.try_embed_texts(texts) {
            Ok(vecs) => vecs,
            Err(err) => {
                tracing::warn!(?err, count = texts.len(), "prose-embed-batch-failed");
                None
            }
        }
    }

    /// Create a fact store backed by a JSONL journal in `data_dir`.
    ///
    /// If `data_dir/facts.jsonl` exists, it is replayed to rebuild in-memory
    /// state. Subsequent `store()` and `delete()` calls append to the journal.
    pub fn with_persistence(data_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        let journal_path = data_dir.join("facts.jsonl");
        let mut store = Self {
            facts: HashMap::new(),
            entity_index: HashMap::new(),
            key_index: HashMap::new(),
            consolidation_sources: HashMap::new(),
            journal_path: Some(journal_path.clone()),
            durability_poisoned: std::sync::atomic::AtomicBool::new(false),
            oversized_legacy_scan_records_skipped: std::sync::atomic::AtomicUsize::new(0),
            latest_only_pruned_bytes: std::sync::atomic::AtomicU64::new(0),
            latest_only_pruned_events: std::sync::atomic::AtomicUsize::new(0),
            journal_replay_corruption_detected: std::sync::atomic::AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            fail_next_durable_append_after_write: std::sync::atomic::AtomicBool::new(false),
            event_bus: None,
            embedder: None,
            embeddings: HashMap::new(),
            dedup_threshold: None,
            near_duplicates: Vec::new(),
        };
        if journal_path.exists() {
            // A record is committed only after its newline-delimited append
            // completed. Repair before replay so a parseable but unterminated
            // crash tail cannot resurrect control state whose caller never
            // observed a successful durable write.
            repair_torn_journal_tail(&journal_path)?;
            store.replay_journal(&journal_path)?;
        }
        Ok(store)
    }

    /// Append a journal event to the JSONL file.
    fn append_journal(&self, event: &JournalEvent) -> std::io::Result<()> {
        if let Some(path) = &self.journal_path {
            repair_torn_journal_tail(path)?;
            let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
            let line = serialize_journal_event_with_limit(event, MAX_FACT_JOURNAL_RECORD_BYTES)?;
            writeln!(file, "{}", line)?;
        }
        Ok(())
    }

    /// Append one journal event and synchronize both the file and its parent
    /// directory before returning. Reserved for authority-changing batches
    /// whose caller must not observe an in-memory commit ahead of durable
    /// storage.
    fn append_journal_durable(&self, event: &JournalEvent) -> std::io::Result<()> {
        let Some(path) = &self.journal_path else {
            return Ok(());
        };
        if self.durability_poisoned.load(std::sync::atomic::Ordering::Acquire) {
            return Err(std::io::Error::other(
                "fact journal durable mutation plane is poisoned; restart required",
            ));
        }
        repair_torn_journal_tail(path)?;
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        let line = serialize_journal_event_with_limit(event, MAX_FACT_JOURNAL_RECORD_BYTES)?;
        if let Err(error) = writeln!(file, "{}", line) {
            self.durability_poisoned
                .store(true, std::sync::atomic::Ordering::Release);
            return Err(indeterminate_durability_error(error));
        }
        #[cfg(any(test, feature = "test-support"))]
        if self
            .fail_next_durable_append_after_write
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            self.durability_poisoned
                .store(true, std::sync::atomic::Ordering::Release);
            return Err(indeterminate_durability_error(std::io::Error::other(
                "injected failure after newline write",
            )));
        }
        if let Err(error) = file.sync_all() {
            self.durability_poisoned
                .store(true, std::sync::atomic::Ordering::Release);
            return Err(indeterminate_durability_error(error));
        }
        if let Some(parent) = path.parent() {
            if let Err(error) = std::fs::File::open(parent).and_then(|directory| directory.sync_all()) {
                self.durability_poisoned
                    .store(true, std::sync::atomic::Ordering::Release);
                return Err(indeterminate_durability_error(error));
            }
        }
        Ok(())
    }

    /// Replay a JSONL journal file to rebuild in-memory state.
    /// Corrupted or blank lines are skipped with a warning.
    fn replay_journal(&mut self, path: &Path) -> std::io::Result<()> {
        self.replay_journal_with_record_limit(path, MAX_FACT_JOURNAL_RECORD_BYTES)
    }

    fn replay_journal_with_record_limit(&mut self, path: &Path, record_limit: usize) -> std::io::Result<()> {
        let file = std::fs::File::open(path)?;
        let mut reader = std::io::BufReader::new(file);
        let mut line_no = 0usize;
        while let Some(record) = read_bounded_journal_record(&mut reader, record_limit)? {
            line_no = line_no.saturating_add(1);
            let BoundedJournalRecord::Json(line) = record else {
                self.oversized_legacy_scan_records_skipped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::error!(
                    line_no,
                    max_bytes = record_limit,
                    "oversized-legacy-scan-journal-record-quarantined-from-replay"
                );
                continue;
            };
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            match serde_json::from_slice::<JournalEvent>(&line) {
                Ok(JournalEvent::Store { mut fact }) => {
                    crate::fact_privacy::enforce_global_fact(&mut fact);
                    self.prune_replayed_latest_only_control_predecessors(&fact);
                    let _ = self.replay_journal_insert(fact);
                }
                Ok(JournalEvent::ReplaceLatest {
                    mut fact,
                    replaced_fact_ids,
                }) => {
                    crate::fact_privacy::enforce_global_fact(&mut fact);
                    for fact_id in replaced_fact_ids {
                        let matching = self.facts.get(&fact_id).is_some_and(|previous| {
                            previous.tenant_hash == fact.tenant_hash
                                && previous.entity == fact.entity
                                && previous.key == fact.key
                        });
                        if matching {
                            if let Some(previous) = self.facts.get(&fact_id) {
                                self.record_latest_only_pruned_fact(previous);
                            }
                            self.hard_remove_fact(&fact_id);
                        }
                    }
                    self.prune_replayed_latest_only_control_predecessors(&fact);
                    let _ = self.replay_journal_insert(fact);
                }
                Ok(JournalEvent::StoreBatch { facts }) => {
                    for mut fact in facts {
                        crate::fact_privacy::enforce_global_fact(&mut fact);
                        self.prune_replayed_latest_only_control_predecessors(&fact);
                        let _ = self.replay_journal_insert(fact);
                    }
                }
                Ok(JournalEvent::Delete { fact_id, .. }) => {
                    let source_tenant = self.facts.get(&fact_id).map(|fact| fact.tenant_hash.clone());
                    let protected_source = source_tenant
                        .as_deref()
                        .is_some_and(|tenant| self.is_active_consolidation_source_for_tenant(&fact_id, tenant));
                    if self.consolidation_sources.contains_key(&fact_id) || protected_source {
                        tracing::warn!(
                            %fact_id,
                            "fact-journal-delete-active-consolidation-member-skip"
                        );
                    } else if let Some(fact) = self.facts.get_mut(&fact_id) {
                        fact.deleted = true;
                    }
                }
                Ok(JournalEvent::Supersede {
                    fact_id, by_fact_id, ..
                }) => {
                    let same_tenant = self
                        .facts
                        .get(&fact_id)
                        .zip(self.facts.get(&by_fact_id))
                        .is_some_and(|(target, successor)| target.tenant_hash == successor.tenant_hash);
                    let source_tenant = self.facts.get(&fact_id).map(|fact| fact.tenant_hash.clone());
                    let protected_source = source_tenant
                        .as_deref()
                        .is_some_and(|tenant| self.is_active_consolidation_source_for_tenant(&fact_id, tenant));
                    if same_tenant && !protected_source {
                        if let Some(fact) = self.facts.get_mut(&fact_id) {
                            fact.superseded_by = Some(by_fact_id);
                        }
                    } else if protected_source {
                        tracing::warn!(
                            %fact_id,
                            %by_fact_id,
                            "fact-journal-supersede-active-consolidation-source-skip"
                        );
                    } else {
                        tracing::warn!(%fact_id, %by_fact_id, "fact-journal-cross-tenant-supersede-skip");
                    }
                }
                Ok(JournalEvent::ClearSupersede { fact_id, .. }) => {
                    let source_tenant = self.facts.get(&fact_id).map(|fact| fact.tenant_hash.clone());
                    let protected_source = source_tenant
                        .as_deref()
                        .is_some_and(|tenant| self.is_active_consolidation_source_for_tenant(&fact_id, tenant));
                    if protected_source {
                        tracing::warn!(
                            %fact_id,
                            "fact-journal-clear-active-consolidation-source-skip"
                        );
                    } else if let Some(fact) = self.facts.get_mut(&fact_id) {
                        fact.superseded_by = None;
                    }
                }
                Ok(JournalEvent::SetValidity {
                    fact_id,
                    valid_from,
                    valid_to,
                    ..
                }) => {
                    if let Some(fact) = self.facts.get_mut(&fact_id) {
                        fact.valid_from = valid_from;
                        fact.valid_to = valid_to;
                    }
                }
                Ok(JournalEvent::Consolidate {
                    mut canonical,
                    superseded_fact_ids,
                    ..
                }) => {
                    if canonical.tenant_hash.trim().is_empty() {
                        canonical.tenant_hash = default_tenant_hash();
                    }
                    let canonical_id = canonical.fact_id.clone();
                    let canonical_tenant = canonical.tenant_hash.clone();
                    let unique_sources: std::collections::HashSet<&str> =
                        superseded_fact_ids.iter().map(String::as_str).collect();
                    let sources_valid = !superseded_fact_ids.is_empty()
                        && unique_sources.len() == superseded_fact_ids.len()
                        && canonical
                            .supersedes
                            .as_deref()
                            .is_none_or(|prior| unique_sources.contains(prior))
                        && superseded_fact_ids.iter().all(|id| {
                            self.facts.get(id).is_some_and(|fact| {
                                !fact.deleted && fact.tenant_hash == canonical_tenant && fact.superseded_by.is_none()
                            })
                        });
                    let canonical_available = !canonical.deleted && !self.facts.contains_key(&canonical_id);
                    if !canonical_available || !sources_valid {
                        tracing::warn!(
                            %canonical_id,
                            %canonical_tenant,
                            "fact-journal-invalid-consolidation-skip"
                        );
                    } else if self.replay_journal_insert(canonical) {
                        for id in &superseded_fact_ids {
                            if let Some(fact) = self.facts.get_mut(id) {
                                fact.superseded_by = Some(canonical_id.clone());
                            }
                        }
                        self.consolidation_sources.insert(canonical_id, superseded_fact_ids);
                    }
                }
                Ok(JournalEvent::ConsolidateUndo {
                    canonical_fact_id,
                    restored_fact_ids,
                    ..
                }) => {
                    let canonical = self.facts.get(&canonical_fact_id);
                    let recorded = self.consolidation_sources.get(&canonical_fact_id).cloned();
                    let mut supplied = restored_fact_ids;
                    supplied.sort();
                    supplied.dedup();
                    let mut expected = recorded.unwrap_or_default();
                    expected.sort();
                    let exact_sources = !expected.is_empty() && supplied == expected;
                    let can_apply = canonical.is_some_and(|canonical| {
                        !canonical.deleted
                            && canonical.superseded_by.is_none()
                            && exact_sources
                            && expected.iter().all(|id| {
                                self.facts.get(id).is_some_and(|fact| {
                                    !fact.deleted
                                        && fact.tenant_hash == canonical.tenant_hash
                                        && fact.superseded_by.as_deref() == Some(canonical_fact_id.as_str())
                                })
                            })
                    });
                    let already_applied = canonical.is_some_and(|canonical| {
                        canonical.deleted
                            && exact_sources
                            && expected.iter().all(|id| {
                                self.facts.get(id).is_some_and(|fact| {
                                    !fact.deleted
                                        && fact.tenant_hash == canonical.tenant_hash
                                        && fact.superseded_by.is_none()
                                })
                            })
                    });
                    if can_apply {
                        if let Some(fact) = self.facts.get_mut(&canonical_fact_id) {
                            fact.deleted = true;
                        }
                        for id in expected {
                            if let Some(fact) = self.facts.get_mut(&id) {
                                fact.superseded_by = None;
                            }
                        }
                    } else if !already_applied {
                        tracing::warn!(
                            %canonical_fact_id,
                            "fact-journal-invalid-consolidation-undo-skip"
                        );
                    }
                }
                Ok(JournalEvent::ConsolidationProvenance {
                    canonical_fact_id,
                    source_fact_ids,
                    tenant_hash,
                    ..
                }) => {
                    let canonical_valid = self
                        .facts
                        .get(&canonical_fact_id)
                        .is_some_and(|fact| !fact.deleted && fact.tenant_hash == tenant_hash);
                    let sources_valid = !source_fact_ids.is_empty()
                        && source_fact_ids.iter().all(|id| {
                            self.facts.get(id).is_some_and(|fact| {
                                !fact.deleted
                                    && fact.tenant_hash == tenant_hash
                                    && fact.superseded_by.as_deref() == Some(canonical_fact_id.as_str())
                            })
                        });
                    if canonical_valid && sources_valid {
                        self.consolidation_sources.insert(canonical_fact_id, source_fact_ids);
                    } else {
                        tracing::warn!(
                            %canonical_fact_id,
                            %tenant_hash,
                            "fact-journal-invalid-consolidation-provenance-skip"
                        );
                    }
                }
                Err(err) => {
                    self.journal_replay_corruption_detected
                        .store(true, std::sync::atomic::Ordering::Release);
                    tracing::warn!(line_no, ?err, "fact-journal-parse-skip");
                }
            }
        }
        self.sanitize_replayed_links();
        Ok(())
    }

    pub fn oversized_legacy_scan_records_skipped(&self) -> usize {
        self.oversized_legacy_scan_records_skipped
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn journal_replay_corruption_detected(&self) -> bool {
        self.journal_replay_corruption_detected
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn prune_replayed_latest_only_control_predecessors(&mut self, fact: &Fact) {
        if !Self::is_latest_only_control_fact(fact) {
            return;
        }
        let chain_key = (fact.tenant_hash.clone(), fact.entity.clone(), fact.key.clone());
        let previous_ids = self.key_index.get(&chain_key).cloned().unwrap_or_default();
        for fact_id in previous_ids {
            if let Some(previous) = self.facts.get(&fact_id) {
                self.record_latest_only_pruned_fact(previous);
            }
            self.hard_remove_fact(&fact_id);
        }
    }

    fn is_latest_only_control_fact(fact: &Fact) -> bool {
        fact.private
            && fact.key == "content"
            && (fact.entity.starts_with("__repo_registry__::")
                || fact.entity.starts_with("__repo_scan__::")
                || fact.entity.starts_with("__workspace_scan__::"))
    }

    fn record_latest_only_pruned_fact(&self, fact: &Fact) {
        if !Self::is_latest_only_control_fact(fact) {
            return;
        }
        let approximate_bytes = (fact.value.len() as u64)
            .saturating_add(fact.entity.len() as u64)
            .saturating_add(fact.key.len() as u64)
            .saturating_add(fact.fact_id.len() as u64)
            .saturating_add(512);
        self.latest_only_pruned_bytes
            .fetch_add(approximate_bytes, std::sync::atomic::Ordering::Relaxed);
        self.latest_only_pruned_events
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn latest_only_compaction_required(&self) -> bool {
        let stale_bytes = self.latest_only_pruned_bytes.load(std::sync::atomic::Ordering::Acquire);
        let stale_events = self
            .latest_only_pruned_events
            .load(std::sync::atomic::Ordering::Acquire);
        stale_bytes >= LATEST_ONLY_COMPACTION_STALE_BYTES || stale_events >= LATEST_ONLY_COMPACTION_STALE_EVENTS
    }

    /// Remove legacy/malicious cross-tenant chain edges after replay without
    /// rewriting version numbers or historical delete tombstones.
    fn sanitize_replayed_links(&mut self) {
        let invalid_supersedes: Vec<String> = self
            .facts
            .values()
            .filter(|fact| {
                fact.supersedes.as_deref().is_some_and(|previous_id| {
                    self.facts.get(previous_id).is_some_and(|previous| {
                        previous.tenant_hash != fact.tenant_hash
                            || previous.entity != fact.entity
                            || previous.key != fact.key
                    })
                })
            })
            .map(|fact| fact.fact_id.clone())
            .collect();
        let invalid_superseded_by: Vec<String> = self
            .facts
            .values()
            .filter(|fact| {
                fact.superseded_by.as_deref().is_some_and(|successor_id| {
                    self.facts
                        .get(successor_id)
                        .is_some_and(|successor| successor.tenant_hash != fact.tenant_hash)
                })
            })
            .map(|fact| fact.fact_id.clone())
            .collect();

        for fact_id in invalid_supersedes {
            if let Some(fact) = self.facts.get_mut(&fact_id) {
                tracing::warn!(%fact_id, "fact-journal-invalid-version-link-cleared");
                fact.supersedes = None;
            }
        }
        for fact_id in invalid_superseded_by {
            if let Some(fact) = self.facts.get_mut(&fact_id) {
                tracing::warn!(%fact_id, "fact-journal-invalid-supersession-link-cleared");
                fact.superseded_by = None;
            }
        }
    }

    /// Insert a fact directly into the HashMap and indexes WITHOUT appending
    /// to the journal. Used during replay to avoid re-writing events.
    fn replay_journal_insert(&mut self, mut fact: Fact) -> bool {
        // Upgrade hardening: rows written before a namespace became
        // born-private must acquire the current privacy classification during
        // replay. Otherwise a stale `private:false` control row can re-enter
        // sync, export, retention, and generic mutation surfaces after restart.
        crate::fact_privacy::enforce_global_fact(&mut fact);
        if fact.tenant_hash.trim().is_empty() {
            fact.tenant_hash = default_tenant_hash();
        }
        if let Some(existing) = self.facts.get(&fact.fact_id) {
            tracing::warn!(
                fact_id = %fact.fact_id,
                existing_tenant = %existing.tenant_hash,
                incoming_tenant = %fact.tenant_hash,
                "fact-journal-duplicate-fact-id-skip"
            );
            return false;
        }
        let fact_id = fact.fact_id.clone();
        let tenant_hash = fact.tenant_hash.clone();
        let entity = fact.entity.clone();
        let key = fact.key.clone();
        self.entity_index
            .entry(entity.clone())
            .or_default()
            .push(fact_id.clone());
        self.key_index
            .entry((tenant_hash, entity, key))
            .or_default()
            .push(fact_id.clone());
        self.facts.insert(fact_id, fact);
        true
    }

    fn build_fact(&self, mut req: StoreFact) -> Fact {
        if req.tenant_hash.trim().is_empty() {
            req.tenant_hash = default_tenant_hash();
        }
        let fact_id = format!("f_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
        let tokens = estimate_tokens(&req.value);

        let key_pair = (req.tenant_hash.clone(), req.entity.clone(), req.key.clone());
        let (version, supersedes) = match self.key_index.get(&key_pair) {
            Some(chain) => {
                let prev = chain
                    .iter()
                    .rev()
                    .find_map(|id| self.facts.get(id).filter(|f| !f.deleted));
                match prev {
                    Some(prev_fact) => (prev_fact.version + 1, Some(prev_fact.fact_id.clone())),
                    None => (1, None),
                }
            }
            None => (1, None),
        };

        let horizon_class = req
            .horizon_class
            .unwrap_or_else(|| HorizonClass::default_for_entity(&req.entity));

        Fact {
            fact_id: fact_id.clone(),
            tenant_hash: req.tenant_hash,
            entity: req.entity.clone(),
            key: req.key.clone(),
            value: req.value,
            source_receipt: req.source_receipt,
            confidence: req.confidence,
            stored_at: Utc::now(),
            tokens,
            deleted: false,
            version,
            supersedes,
            private: req.private,
            horizon_class,
            reverified_at: None,
            superseded_by: None,
            actor: req.actor,
            // Valid-time defaults open on both ends (true for all world-time)
            // until an explicit `set_validity` records when the fact actually
            // held. Keeping it out of `StoreFact` avoids churning the ~300
            // store sites; callers that care set validity right after `store`.
            valid_from: None,
            valid_to: None,
            // Salience starts at zero (never recalled). `record_access` bumps
            // it on the read path; `salience_factor(0) == 1.0` so a brand-new
            // fact decays exactly as before until it is actually recalled.
            access_count: 0,
            last_accessed_at: None,
        }
    }

    /// Update the horizon class for an existing fact in place. Returns
    /// `true` if the fact existed. Used by `memory_set_horizon` so
    /// callers can override the entity-prefix default after the fact
    /// was written (e.g. pin a normally-volatile fact as `stable`).
    pub fn set_horizon(&mut self, fact_id: &str, horizon_class: HorizonClass) -> bool {
        if let Some(fact) = self.facts.get_mut(fact_id) {
            fact.horizon_class = horizon_class;
            true
        } else {
            false
        }
    }

    /// Tenant-authorized variant of [`Self::set_horizon`].
    ///
    /// Fact ids are globally unique identifiers, but they are not authority
    /// tokens. Request-facing callers must use this method so possession of an
    /// id from another tenant cannot mutate that tenant's fact.
    pub fn set_horizon_for_tenant(&mut self, tenant_hash: &str, fact_id: &str, horizon_class: HorizonClass) -> bool {
        if let Some(fact) = self
            .facts
            .get_mut(fact_id)
            .filter(|fact| fact.tenant_hash == tenant_hash)
        {
            fact.horizon_class = horizon_class;
            true
        } else {
            false
        }
    }

    /// Bump the `reverified_at` anchor on a fact, recording that an
    /// agent (or operator) has re-confirmed the fact is still accurate.
    /// Re-anchors decay without rewriting the value.
    ///
    /// Returns `true` if the fact existed.
    pub fn reverify(&mut self, fact_id: &str, now: DateTime<Utc>) -> bool {
        if let Some(fact) = self.facts.get_mut(fact_id) {
            fact.reverified_at = Some(now);
            true
        } else {
            false
        }
    }

    /// Tenant-authorized variant of [`Self::reverify`].
    pub fn reverify_for_tenant(&mut self, tenant_hash: &str, fact_id: &str, now: DateTime<Utc>) -> bool {
        if let Some(fact) = self
            .facts
            .get_mut(fact_id)
            .filter(|fact| fact.tenant_hash == tenant_hash)
        {
            fact.reverified_at = Some(now);
            true
        } else {
            false
        }
    }

    /// Mark `target_fact_id` as explicitly superseded by `by_fact_id` (M6).
    ///
    /// This is the cross-entity retirement primitive: unlike the
    /// `(entity, key)` version chain (`supersedes`/`version`), the
    /// superseding fact may live under a *different* entity. Reversible
    /// soft-state — never hard-deletes the target. The mutation is
    /// journaled (mirrors soft-delete's `try_delete`) so it survives a
    /// restart. Returns `true` only when both facts exist in `tenant_hash`.
    ///
    /// Idempotent: re-marking with the same `by_fact_id` is a no-op write
    /// of the same value (still journaled for an explicit audit trail).
    pub fn mark_superseded(&mut self, tenant_hash: &str, target_fact_id: &str, by_fact_id: &str) -> bool {
        if self.is_active_consolidation_source_for_tenant(target_fact_id, tenant_hash) {
            return false;
        }
        let same_authorized_tenant = self
            .facts
            .get(target_fact_id)
            .zip(self.facts.get(by_fact_id))
            .is_some_and(|(target, successor)| {
                target.tenant_hash == tenant_hash && successor.tenant_hash == tenant_hash
            });
        if !same_authorized_tenant {
            return false;
        }
        if let Err(err) = self.append_journal(&JournalEvent::Supersede {
            fact_id: target_fact_id.to_string(),
            by_fact_id: by_fact_id.to_string(),
            superseded_at: Utc::now().to_rfc3339(),
        }) {
            tracing::warn!(?err, "fact-journal-append-failed");
        }
        if let Some(fact) = self.facts.get_mut(target_fact_id) {
            fact.superseded_by = Some(by_fact_id.to_string());
            true
        } else {
            false
        }
    }

    /// Reverse of [`Self::mark_superseded`] (M6): un-retire a fact by clearing
    /// its `superseded_by` marker. Journaled for restart-survival.
    /// Returns `true` if the fact existed in `tenant_hash`.
    pub fn clear_superseded(&mut self, tenant_hash: &str, fact_id: &str) -> bool {
        if self.is_active_consolidation_source_for_tenant(fact_id, tenant_hash) {
            return false;
        }
        if self
            .facts
            .get(fact_id)
            .is_none_or(|fact| fact.tenant_hash != tenant_hash)
        {
            return false;
        }
        if let Err(err) = self.append_journal(&JournalEvent::ClearSupersede {
            fact_id: fact_id.to_string(),
            cleared_at: Utc::now().to_rfc3339(),
        }) {
            tracing::warn!(?err, "fact-journal-append-failed");
        }
        if let Some(fact) = self.facts.get_mut(fact_id) {
            fact.superseded_by = None;
            true
        } else {
            false
        }
    }

    /// Set the bi-temporal valid-time interval `[valid_from, valid_to)` on an
    /// existing fact without rewriting its value (Graphiti model). Either end
    /// may be `None` for an open bound. Journaled (like `mark_superseded`) so
    /// the world-time record survives a restart — unlike `set_horizon` /
    /// `reverify`, validity is a durable historical claim, not a re-derivable
    /// hint. Returns `true` if the fact existed.
    pub fn set_validity(
        &mut self,
        fact_id: &str,
        valid_from: Option<DateTime<Utc>>,
        valid_to: Option<DateTime<Utc>>,
    ) -> bool {
        if !self.facts.contains_key(fact_id) {
            return false;
        }
        if let Err(err) = self.append_journal(&JournalEvent::SetValidity {
            fact_id: fact_id.to_string(),
            valid_from,
            valid_to,
            set_at: Utc::now().to_rfc3339(),
        }) {
            tracing::warn!(?err, "fact-journal-append-failed");
        }
        if let Some(fact) = self.facts.get_mut(fact_id) {
            fact.valid_from = valid_from;
            fact.valid_to = valid_to;
            true
        } else {
            false
        }
    }

    /// Record that the given facts were just returned by recall (M2 salience).
    /// Increments each fact's `access_count` and stamps `last_accessed_at`,
    /// so frequently-recalled facts decay slower
    /// (see `corecrux_projections::decay::salience_factor`). Unknown/deleted
    /// ids are skipped. Returns the number of facts actually updated.
    ///
    /// Deliberately NOT journaled: this runs on the hot read path and the
    /// signal is a re-derivable ranking heuristic, not a durable claim —
    /// journaling every recall would bloat the append-only log. Access counts
    /// reset on restart and re-accumulate, exactly like a cold cache.
    pub fn record_access(&mut self, fact_ids: &[&str]) -> usize {
        let now = Utc::now();
        let mut updated = 0usize;
        for fact_id in fact_ids {
            if let Some(fact) = self.facts.get_mut(*fact_id) {
                if fact.deleted {
                    continue;
                }
                fact.access_count = fact.access_count.saturating_add(1);
                fact.last_accessed_at = Some(now);
                updated += 1;
            }
        }
        updated
    }

    fn insert_fact_indexes(&mut self, fact: &Fact) {
        self.entity_index
            .entry(fact.entity.clone())
            .or_default()
            .push(fact.fact_id.clone());
        self.key_index
            .entry((fact.tenant_hash.clone(), fact.entity.clone(), fact.key.clone()))
            .or_default()
            .push(fact.fact_id.clone());
        self.facts.insert(fact.fact_id.clone(), fact.clone());
    }

    fn after_fact_stored(&mut self, fact: &Fact) {
        if let Some(embedder) = &self.embedder {
            // Daemon delegation is the prose/index compute lane. Fact writes
            // are durability-first and occur while callers hold this store's
            // write lock; waiting through remote retries here could make an
            // already-committed mutation time out ambiguously. Keep delegated
            // fact enrichment lexical until it can be queued out of band.
            if embedder.delegation_status().is_some() {
                tracing::debug!(fact_id = %fact.fact_id, "delegated-fact-enrichment-skipped");
            } else {
                let text = format!("{} {} {}", fact.entity, fact.key, fact.value);
                match embedder.embed_one(&text) {
                    Ok(vec) => {
                        // Free, Bring-Your-Own-embedder dense lane. This store is
                        // deliberately **uncapped** (ExecPlan
                        // dense-lane-and-extraction-upsell-2026-06-26, constraint C1):
                        // do NOT add a corpus cap or eviction here. Scale/quality is
                        // the metered upsell, never a clip on local dense.
                        self.embeddings.insert(fact.fact_id.clone(), vec);

                        // M3.5: store-time semantic near-duplicate detection. Flags a
                        // near-dup as a review candidate (log + queryable record); it
                        // never mutates or drops the fact — dedup is advisory review,
                        // not silent deletion.
                        if let Some(threshold) = self.dedup_threshold {
                            if let Some((similar_to, score)) = self.detect_near_duplicate(fact, threshold) {
                                tracing::warn!(
                                    fact_id = %fact.fact_id,
                                    similar_to = %similar_to,
                                    score,
                                    "fact-near-duplicate-detected (M3.5 review candidate)"
                                );
                                self.near_duplicates.push(NearDuplicate {
                                    fact_id: fact.fact_id.clone(),
                                    similar_to,
                                    score,
                                });
                            }
                        }
                    }
                    Err(err) => {
                        tracing::warn!(?err, fact_id = %fact.fact_id, "fact-embed-failed");
                    }
                }
            }
        }

        if let Some(bus) = &self.event_bus {
            bus.emit(crate::events::CruxEvent::FactStored {
                fact_id: fact.fact_id.clone(),
                entity: fact.entity.clone(),
                key: fact.key.clone(),
            });
        }
    }

    /// Store a fact and return it. If a fact with the same (entity, key) already
    /// exists, the new fact is assigned the next version number and links to the
    /// previous version via `supersedes`.
    pub fn store(&mut self, mut req: StoreFact) -> Fact {
        crate::fact_privacy::enforce_global(&mut req);
        let fact = self.build_fact(req);
        self.insert_fact_indexes(&fact);
        if let Err(err) = self.append_journal(&JournalEvent::Store { fact: fact.clone() }) {
            tracing::warn!(?err, "fact-journal-append-failed");
        }
        self.supersede_prior_version(&fact);
        self.after_fact_stored(&fact);
        fact
    }

    /// Store a fact only after its journal event has been durably appended.
    pub fn try_store(&mut self, mut req: StoreFact) -> std::io::Result<Fact> {
        crate::fact_privacy::enforce_global(&mut req);
        let fact = self.build_fact(req);
        self.append_journal(&JournalEvent::Store { fact: fact.clone() })?;
        self.insert_fact_indexes(&fact);
        self.supersede_prior_version(&fact);
        self.after_fact_stored(&fact);
        Ok(fact)
    }

    /// Store one authority-bearing fact only after synchronizing its journal
    /// event and parent directory. Kept crate-private so ordinary fact writes
    /// do not accidentally opt into one-fsync-per-fact latency.
    pub(crate) fn try_store_durable(&mut self, mut req: StoreFact) -> std::io::Result<Fact> {
        crate::fact_privacy::enforce_global(&mut req);
        let fact = self.build_fact(req);
        self.append_journal_durable(&JournalEvent::Store { fact: fact.clone() })?;
        self.insert_fact_indexes(&fact);
        self.supersede_prior_version(&fact);
        self.after_fact_stored(&fact);
        Ok(fact)
    }

    /// Atomically replace every resident version of one `(tenant, entity,
    /// key)` with a single latest value. The journal records one replayable
    /// replacement event, so superseded control-plane snapshots do not remain
    /// resident after restart.
    ///
    /// This is for bounded daemon control state whose history is not a domain
    /// audit artifact. Ordinary facts should continue to use [`Self::store`].
    pub fn try_replace_latest_daemon_control(&mut self, mut req: StoreFact) -> std::io::Result<Fact> {
        const LATEST_ONLY_CONTROL_PREFIXES: &[&str] =
            &["__repo_registry__::", "__repo_scan__::", "__workspace_scan__::"];
        if !req.private
            || !LATEST_ONLY_CONTROL_PREFIXES
                .iter()
                .any(|prefix| req.entity.starts_with(prefix))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "latest-only replacement is restricted to private daemon-control snapshots",
            ));
        }
        crate::fact_privacy::enforce_global(&mut req);
        if self.latest_only_compaction_required() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "latest-only fact journal reached its stale-history ceiling; run explicit fact journal compaction before another replacement",
            ));
        }
        let chain_key = (req.tenant_hash.clone(), req.entity.clone(), req.key.clone());
        let replaced_fact_ids = self.key_index.get(&chain_key).cloned().unwrap_or_default();
        if !replaced_fact_ids.is_empty()
            && self
                .active_legal_holds()
                .iter()
                .any(|hold| hold.covers_stored_or_logical_repo_control(&req.tenant_hash, &req.entity))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "latest-only replacement blocked by an active legal hold",
            ));
        }
        let mut fact = self.build_fact(req);
        fact.supersedes = None;
        self.append_journal_durable(&JournalEvent::ReplaceLatest {
            fact: fact.clone(),
            replaced_fact_ids: replaced_fact_ids.clone(),
        })?;
        for fact_id in replaced_fact_ids {
            if let Some(previous) = self.facts.get(&fact_id) {
                self.record_latest_only_pruned_fact(previous);
            }
            self.hard_remove_fact(&fact_id);
        }
        self.insert_fact_indexes(&fact);
        self.after_fact_stored(&fact);
        Ok(fact)
    }

    fn hard_remove_fact(&mut self, fact_id: &str) {
        let Some(fact) = self.facts.remove(fact_id) else {
            return;
        };
        let remove_entity_index = if let Some(ids) = self.entity_index.get_mut(&fact.entity) {
            ids.retain(|candidate| candidate != fact_id);
            ids.is_empty()
        } else {
            false
        };
        if remove_entity_index {
            self.entity_index.remove(&fact.entity);
        }
        let key = (fact.tenant_hash.clone(), fact.entity.clone(), fact.key.clone());
        let remove_key_index = if let Some(ids) = self.key_index.get_mut(&key) {
            ids.retain(|candidate| candidate != fact_id);
            ids.is_empty()
        } else {
            false
        };
        if remove_key_index {
            self.key_index.remove(&key);
        }
        self.embeddings.remove(fact_id);
        self.near_duplicates
            .retain(|candidate| candidate.fact_id != fact_id && candidate.similar_to != fact_id);
        self.consolidation_sources.remove(fact_id);
        for sources in self.consolidation_sources.values_mut() {
            sources.retain(|candidate| candidate != fact_id);
        }
    }

    /// Retire the immediate predecessor of a freshly-stored `(entity, key)`
    /// version in the recall plane. [`Self::build_fact`] sets `fact.supersedes`
    /// to the prior non-deleted version's id when a chain already exists;
    /// marking that predecessor `superseded_by` the new fact makes `query_facts`
    /// return latest-version-wins, while `include_superseded` / `memory_view` /
    /// `memory_history` keep the full chain visible. Reuses the journaled
    /// [`Self::mark_superseded`] primitive so the retirement survives a restart.
    ///
    /// Without this, a re-`store` of an existing `(entity, key)` (the path
    /// `memory_edit` and any value update take) left BOTH versions live in
    /// recall — `query_facts` returned the stale value alongside the corrected
    /// one. The explicit `store_fact(supersedes=[…])` param is unaffected: it
    /// retires *cross-entity* facts and still runs after the store; re-marking
    /// the same predecessor here is idempotent.
    fn supersede_prior_version(&mut self, fact: &Fact) {
        if let Some(prev_id) = fact.supersedes.clone() {
            self.mark_superseded(&fact.tenant_hash, &prev_id, &fact.fact_id);
        }
    }

    /// Store multiple facts in a batch.
    pub fn store_bulk(&mut self, reqs: Vec<StoreFact>) -> Vec<Fact> {
        reqs.into_iter().map(|r| self.store(r)).collect()
    }

    /// Store multiple facts, aborting before mutation if any journal append fails.
    pub fn try_store_bulk(&mut self, reqs: Vec<StoreFact>) -> std::io::Result<Vec<Fact>> {
        let facts: Vec<Fact> = reqs
            .into_iter()
            .map(|mut req| {
                crate::fact_privacy::enforce_global(&mut req);
                self.build_fact(req)
            })
            .collect();
        self.append_journal(&JournalEvent::StoreBatch { facts: facts.clone() })?;
        for fact in &facts {
            self.insert_fact_indexes(fact);
            self.supersede_prior_version(fact);
            self.after_fact_stored(fact);
        }
        Ok(facts)
    }

    /// Store multiple facts as one journal event, fsyncing that event before
    /// mutating in-memory state. This is the high-risk counterpart to
    /// [`Self::try_store_bulk`].
    pub fn try_store_bulk_durable(&mut self, reqs: Vec<StoreFact>) -> std::io::Result<Vec<Fact>> {
        let facts: Vec<Fact> = reqs
            .into_iter()
            .map(|mut req| {
                crate::fact_privacy::enforce_global(&mut req);
                self.build_fact(req)
            })
            .collect();
        self.append_journal_durable(&JournalEvent::StoreBatch { facts: facts.clone() })?;
        for fact in &facts {
            self.insert_fact_indexes(fact);
            self.supersede_prior_version(fact);
            self.after_fact_stored(fact);
        }
        Ok(facts)
    }

    /// Soft-delete a fact by ID. Returns true if it existed in `tenant_hash`.
    pub fn delete(&mut self, tenant_hash: &str, fact_id: &str) -> bool {
        if self.is_consolidation_canonical_for_tenant(fact_id, tenant_hash)
            || self.is_active_consolidation_source_for_tenant(fact_id, tenant_hash)
        {
            return false;
        }
        if let Some(fact) = self
            .facts
            .get_mut(fact_id)
            .filter(|fact| fact.tenant_hash == tenant_hash)
        {
            fact.deleted = true;
            if let Err(err) = self.append_journal(&JournalEvent::Delete {
                fact_id: fact_id.to_string(),
                deleted_at: Utc::now().to_rfc3339(),
            }) {
                tracing::warn!(?err, "fact-journal-append-failed");
            }
            if let Some(bus) = &self.event_bus {
                bus.emit(crate::events::CruxEvent::FactDeleted {
                    fact_id: fact_id.to_string(),
                });
            }
            true
        } else {
            false
        }
    }

    /// Soft-delete a fact only after its tombstone has been durably appended.
    pub fn try_delete(&mut self, tenant_hash: &str, fact_id: &str) -> std::io::Result<bool> {
        if self.is_consolidation_canonical_for_tenant(fact_id, tenant_hash)
            || self.is_active_consolidation_source_for_tenant(fact_id, tenant_hash)
        {
            return Ok(false);
        }
        if self
            .facts
            .get(fact_id)
            .is_none_or(|fact| fact.tenant_hash != tenant_hash)
        {
            return Ok(false);
        }
        self.append_journal_durable(&JournalEvent::Delete {
            fact_id: fact_id.to_string(),
            deleted_at: Utc::now().to_rfc3339(),
        })?;
        if let Some(fact) = self
            .facts
            .get_mut(fact_id)
            .filter(|fact| fact.tenant_hash == tenant_hash)
        {
            fact.deleted = true;
            if let Some(bus) = &self.event_bus {
                bus.emit(crate::events::CruxEvent::FactDeleted {
                    fact_id: fact_id.to_string(),
                });
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get a single fact by ID.
    /// Unfiltered — internal / admin only; does NOT apply the tenant filter. Request-path callers must use the *_for_tenant variant (audit H2).
    pub fn get(&self, fact_id: &str) -> Option<&Fact> {
        self.facts.get(fact_id).filter(|f| !f.deleted)
    }

    pub fn get_for_tenant(&self, fact_id: &str, tenant_hash: &str) -> Option<&Fact> {
        self.get(fact_id).filter(|f| f.tenant_hash == tenant_hash)
    }

    /// Tenant-scoped audit lookup that retains soft-deleted rows.
    pub fn get_for_tenant_including_deleted(&self, fact_id: &str, tenant_hash: &str) -> Option<&Fact> {
        self.facts.get(fact_id).filter(|fact| fact.tenant_hash == tenant_hash)
    }

    /// Whether the id names a canonical created by a durable consolidation in
    /// this tenant. Generic deletion must route such facts through undo.
    pub fn is_consolidation_canonical_for_tenant(&self, fact_id: &str, tenant_hash: &str) -> bool {
        self.consolidation_sources.contains_key(fact_id)
            && self
                .facts
                .get(fact_id)
                .is_some_and(|fact| fact.tenant_hash == tenant_hash)
    }

    /// Whether a fact is currently retired by a live consolidation canonical.
    /// These edges are immutable until the dedicated undo commits.
    pub fn is_active_consolidation_source_for_tenant(&self, fact_id: &str, tenant_hash: &str) -> bool {
        self.active_consolidation_for_source(fact_id, Some(tenant_hash))
            .is_some()
    }

    fn active_consolidation_for_source<'a>(
        &'a self,
        source_fact_id: &str,
        tenant_hash: Option<&str>,
    ) -> Option<&'a str> {
        self.consolidation_sources
            .iter()
            .find(|(canonical_id, source_ids)| {
                source_ids.iter().any(|id| id == source_fact_id)
                    && self.facts.get(*canonical_id).is_some_and(|canonical| {
                        !canonical.deleted && tenant_hash.is_none_or(|tenant| canonical.tenant_hash == tenant)
                    })
            })
            .map(|(canonical_id, _)| canonical_id.as_str())
    }

    /// Get all facts for an entity.
    /// Unfiltered — internal / admin only; does NOT apply the tenant filter. Request-path callers must use the *_for_tenant variant (audit H2).
    pub fn get_by_entity(&self, entity: &str) -> Vec<&Fact> {
        self.entity_index
            .get(entity)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.facts.get(id))
                    .filter(|f| !f.deleted)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get_by_entity_for_tenant(&self, entity: &str, tenant_hash: &str) -> Vec<&Fact> {
        self.get_by_entity(entity)
            .into_iter()
            .filter(|f| f.tenant_hash == tenant_hash)
            .collect()
    }

    /// Internal control-plane lookup that returns exactly one live latest row
    /// per key-chain beneath `entity_prefix`, without relevance ranking or a
    /// `top_k` truncation before deduplication.
    pub fn latest_by_entity_prefix<'a>(
        &'a self,
        tenant_hash: &str,
        entity_prefix: &str,
        key_filter: Option<&str>,
    ) -> Vec<&'a Fact> {
        let mut latest = Vec::new();
        for ((tenant, entity, key), ids) in &self.key_index {
            if tenant != tenant_hash
                || !entity.starts_with(entity_prefix)
                || key_filter.is_some_and(|filter| key != filter)
            {
                continue;
            }
            if let Some(fact) = ids
                .iter()
                .rev()
                .filter_map(|fact_id| self.facts.get(fact_id))
                .filter(|fact| !fact.deleted)
                .max_by_key(|fact| fact.version)
            {
                latest.push(fact);
            }
        }
        latest.sort_by(|left, right| left.entity.cmp(&right.entity).then_with(|| left.key.cmp(&right.key)));
        latest
    }

    /// Query facts by keyword match (simple substring search).
    /// Returns facts sorted by relevance, limited by top_k or token_budget.
    pub fn query(&self, q: &FactQuery) -> FactQueryResult {
        let query_embedding = match self.query_embedding(q) {
            Ok(embedding) => embedding,
            Err(err) => {
                // Legacy in-process metadata lookups retain a lexical path.
                // User-facing operations that require delegated semantics use
                // `try_query` and surface the provider error instead.
                tracing::warn!(?err, "query-embed-failed; using lexical query semantics");
                None
            }
        };
        self.query_inner(q, None, query_embedding.as_deref())
    }

    /// Fallible semantic recall for capability-aware callers. A fact-lane
    /// embedder failure is returned to the caller; it never becomes an empty,
    /// unrelated, or confidence-only result set. Daemon delegation is
    /// deliberately a prose/index compute lane, so fact recall remains lexical
    /// and never performs remote I/O under the store lock.
    pub fn try_query(&self, q: &FactQuery) -> Result<FactQueryResult, crate::embeddings::EmbeddingError> {
        let query_embedding = self.query_embedding(q)?;
        Ok(self.query_inner(q, None, query_embedding.as_deref()))
    }

    /// Bi-temporal recall (Graphiti model): like [`Self::query`], but only
    /// returns facts that were TRUE IN THE WORLD at `as_of` — i.e. whose
    /// valid-time interval `[valid_from, valid_to)` contains `as_of`,
    /// regardless of when (transaction time) they were learned. Answers
    /// "what did we believe about X *as of* date Y". Facts with open valid
    /// bounds (the default) match any `as_of`, so this is a strict superset
    /// filter over [`Self::query`]. Ranking/budget logic is shared.
    pub fn query_as_of(&self, q: &FactQuery, as_of: DateTime<Utc>) -> FactQueryResult {
        let query_embedding = match self.query_embedding(q) {
            Ok(embedding) => embedding,
            Err(err) => {
                tracing::warn!(?err, "as-of-query-embed-failed; using lexical query semantics");
                None
            }
        };
        self.query_inner(q, Some(as_of), query_embedding.as_deref())
    }

    /// Fallible bi-temporal semantic recall. See [`Self::try_query`].
    pub fn try_query_as_of(
        &self,
        q: &FactQuery,
        as_of: DateTime<Utc>,
    ) -> Result<FactQueryResult, crate::embeddings::EmbeddingError> {
        let query_embedding = self.query_embedding(q)?;
        Ok(self.query_inner(q, Some(as_of), query_embedding.as_deref()))
    }

    fn query_embedding(&self, q: &FactQuery) -> Result<Option<Vec<f32>>, crate::embeddings::EmbeddingError> {
        match (&self.embedder, &q.query) {
            (Some(embedder), Some(query_text)) if !query_text.is_empty() && embedder.delegation_status().is_none() => {
                embedder.embed_one(query_text).map(Some)
            }
            _ => Ok(None),
        }
    }

    fn query_inner(
        &self,
        q: &FactQuery,
        as_of: Option<DateTime<Utc>>,
        query_embedding: Option<&[f32]>,
    ) -> FactQueryResult {
        let mut results: Vec<&Fact> = self
            .facts
            .values()
            .filter(|f| !f.deleted)
            .filter(|f| q.tenant_hash.as_ref().is_none_or(|tenant| f.tenant_hash == *tenant))
            .filter(|f| match as_of {
                Some(instant) => f.valid_at(instant),
                None => true,
            })
            .filter(|f| {
                if let Some(prefix) = &q.entity_prefix {
                    if !f.entity.starts_with(prefix.as_str()) {
                        return false;
                    }
                }
                if let Some(entity) = &q.entity {
                    if &f.entity != entity {
                        return false;
                    }
                }
                true
            })
            .filter(|f| {
                // When embeddings are enabled, skip keyword filtering — cosine
                // similarity handles relevance ranking instead.
                if query_embedding.is_some() {
                    return true;
                }
                if let Some(query) = &q.query {
                    let query_lower = query.to_lowercase();
                    let terms: Vec<&str> = query_lower.split_whitespace().collect();
                    let value_lower = f.value.to_lowercase();
                    let key_lower = f.key.to_lowercase();
                    let entity_lower = f.entity.to_lowercase();
                    terms
                        .iter()
                        .any(|t| value_lower.contains(t) || key_lower.contains(t) || entity_lower.contains(t))
                } else {
                    true
                }
            })
            .collect();

        // If embeddings are available and a query is provided, blend cosine
        // similarity with confidence. Otherwise use the explicit lexical
        // selection above and rank by confidence + recency.
        if let Some(qe) = query_embedding {
            // Score = 0.6 * cosine_similarity + 0.4 * confidence.
            // Ranks the WHOLE filtered result set — the token_budget / top_k
            // selection below is a presentation limit, not a corpus cap. Keep it
            // uncapped (ExecPlan dense-lane-and-extraction-upsell C1).
            results.sort_by(|a, b| {
                let sim_a = self
                    .embeddings
                    .get(&a.fact_id)
                    .map_or(0.0, |v| crate::embeddings::cosine_similarity(v, qe));
                let sim_b = self
                    .embeddings
                    .get(&b.fact_id)
                    .map_or(0.0, |v| crate::embeddings::cosine_similarity(v, qe));
                let score_a = 0.6 * sim_a + 0.4 * a.confidence;
                let score_b = 0.6 * sim_b + 0.4 * b.confidence;
                score_b
                    .partial_cmp(&score_a)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.stored_at.cmp(&a.stored_at))
            });
        } else {
            // Fallback: confidence descending, then recency descending
            results.sort_by(|a, b| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| b.stored_at.cmp(&a.stored_at))
            });
        }

        // Apply token budget or top_k
        let (selected, total_tokens) = if let Some(budget) = q.token_budget {
            let mut used = 0usize;
            let mut sel = Vec::new();
            for f in &results {
                if used + f.tokens > budget && !sel.is_empty() {
                    break;
                }
                used += f.tokens;
                sel.push((*f).clone());
                if used >= budget {
                    break;
                }
            }
            let total = used;
            (sel, total)
        } else {
            results.truncate(q.top_k);
            let total: usize = results.iter().map(|f| f.tokens).sum();
            (results.into_iter().cloned().collect(), total)
        };

        FactQueryResult {
            facts: selected,
            total_tokens,
        }
    }

    /// Return all unique entity names from non-deleted facts, sorted.
    pub fn entities(&self) -> Vec<String> {
        let mut ents: Vec<String> = self
            .entity_index
            .keys()
            .filter(|entity| {
                self.entity_index
                    .get(*entity)
                    .is_some_and(|ids| ids.iter().any(|id| self.facts.get(id).is_some_and(|f| !f.deleted)))
            })
            .cloned()
            .collect();
        ents.sort();
        ents
    }

    /// Total number of active (non-deleted) facts.
    pub fn count(&self) -> usize {
        self.facts.values().filter(|f| !f.deleted).count()
    }

    /// Deterministic, 0-LLM aggregate lane (buyer-fit M4, knock-out #5).
    ///
    /// Answers `count` / `sum_numeric` / `distinct` / `temporal_diff` over the
    /// visible (non-deleted, non-superseded, non-private) fact set matching an
    /// optional `entity` / `key` / case-insensitive `query` substring filter.
    /// Pure arithmetic — no model call, ever. `token_budget`, when set, caps how
    /// many candidate facts are scanned (honest, bounded cost); the report says
    /// whether the answer was budget-truncated.
    pub fn aggregate_v1(&self, tenant_hash: &str, req: &AggregateRequestV1) -> AggregateResultV1 {
        // Candidate facts: visible latest rows matching the filter, in a stable
        // order (by fact_id) so the scan + any budget truncation is deterministic.
        let mut candidates: Vec<&Fact> = self
            .facts
            .values()
            .filter(|f| f.tenant_hash == tenant_hash)
            .filter(|f| !f.deleted && f.superseded_by.is_none() && !f.private)
            .filter(|f| req.entity.as_deref().is_none_or(|e| f.entity == e))
            .filter(|f| req.key.as_deref().is_none_or(|k| f.key == k))
            .filter(|f| {
                req.query
                    .as_deref()
                    .is_none_or(|q| f.value.to_lowercase().contains(&q.to_lowercase()))
            })
            .collect();
        candidates.sort_by(|a, b| a.fact_id.cmp(&b.fact_id));

        // Budget: scan at most as many facts as fit under token_budget.
        let mut tokens_scanned = 0usize;
        let mut truncated = false;
        let scanned: Vec<&Fact> = if let Some(budget) = req.token_budget {
            let mut out = Vec::new();
            for f in &candidates {
                if tokens_scanned + f.tokens > budget && !out.is_empty() {
                    truncated = true;
                    break;
                }
                tokens_scanned += f.tokens;
                out.push(*f);
            }
            out
        } else {
            tokens_scanned = candidates.iter().map(|f| f.tokens).sum();
            candidates
        };

        let value = match req.op {
            AggregateOp::Count => serde_json::json!(scanned.len()),
            AggregateOp::SumNumeric => {
                let sum: f64 = scanned.iter().filter_map(|f| parse_leading_number(&f.value)).sum();
                serde_json::json!(sum)
            }
            AggregateOp::Distinct => {
                let set: std::collections::BTreeSet<&str> = scanned.iter().map(|f| f.value.as_str()).collect();
                serde_json::json!(set.len())
            }
            AggregateOp::TemporalDiff => {
                // Numeric change in an (entity,key)'s value between the value
                // that was current at `as_of` and the current value. Requires
                // entity+key; returns null if either endpoint is non-numeric.
                return self.temporal_diff(tenant_hash, req, tokens_scanned);
            }
        };

        AggregateResultV1 {
            op: req.op.as_str().to_string(),
            matched: scanned.len(),
            value,
            llm_calls: 0,
            tokens_scanned,
            budget_truncated: truncated,
        }
    }

    fn temporal_diff(&self, tenant_hash: &str, req: &AggregateRequestV1, tokens_scanned: usize) -> AggregateResultV1 {
        let base = AggregateResultV1 {
            op: AggregateOp::TemporalDiff.as_str().to_string(),
            matched: 0,
            value: serde_json::Value::Null,
            llm_calls: 0,
            tokens_scanned,
            budget_truncated: false,
        };
        let (Some(entity), Some(key)) = (req.entity.as_deref(), req.key.as_deref()) else {
            return base;
        };
        let current = self
            .facts
            .values()
            .filter(|fact| {
                fact.tenant_hash == tenant_hash
                    && fact.entity == entity
                    && fact.key == key
                    && !fact.deleted
                    && !fact.private
                    && fact.superseded_by.is_none()
            })
            .filter(|fact| {
                req.query
                    .as_deref()
                    .is_none_or(|query| fact.value.to_lowercase().contains(&query.to_lowercase()))
            })
            .max_by_key(|fact| fact.version);
        let Some(current) = current else {
            return base;
        };

        // Walk the authenticated tenant's actual predecessor edges. A global
        // `(entity,key)` scan would allow unrelated tenant/private/deleted rows
        // to become a TemporalDiff endpoint.
        let mut history = vec![current];
        let mut child = current;
        let mut seen = std::collections::BTreeSet::from([current.fact_id.as_str()]);
        while let Some(previous_id) = child.supersedes.as_deref() {
            if !seen.insert(previous_id) {
                break;
            }
            let Some(previous) = self.facts.get(previous_id).filter(|previous| {
                previous.tenant_hash == tenant_hash
                    && previous.entity == entity
                    && previous.key == key
                    && !previous.deleted
                    && !previous.private
                    && previous.superseded_by.as_deref() == Some(child.fact_id.as_str())
            }) else {
                break;
            };
            history.push(previous);
            child = previous;
        }

        let old = match req.as_of {
            Some(ts) => history
                .iter()
                .copied()
                .filter(|fact| fact.stored_at <= ts)
                .max_by_key(|fact| fact.version),
            None => history.last().copied(),
        };
        let Some(old) = old else {
            return base;
        };
        match (parse_leading_number(&current.value), parse_leading_number(&old.value)) {
            (Some(c), Some(o)) => AggregateResultV1 {
                matched: history.len(),
                value: serde_json::json!(c - o),
                ..base
            },
            _ => base,
        }
    }

    /// Return an iterator over ALL facts (including deleted).
    /// Unfiltered — internal / admin only; does NOT apply the tenant filter. Request-path callers must use the *_for_tenant variant (audit H2).
    pub fn all_facts(&self) -> impl Iterator<Item = &Fact> {
        self.facts.values()
    }

    pub fn all_facts_for_tenant<'a>(&'a self, tenant_hash: &'a str) -> impl Iterator<Item = &'a Fact> + 'a {
        self.all_facts().filter(move |f| f.tenant_hash == tenant_hash)
    }

    /// Paginated export of facts for the sync push path.
    ///
    /// Facts are sorted by `(stored_at, fact_id)` ascending. If `since` is set,
    /// only facts with `stored_at >= since` are included. If `cursor` is set,
    /// items are skipped until the fact with `fact_id == cursor` is found, then
    /// the export starts from the next item. Returns at most `limit` facts.
    ///
    /// ERASURE (launch-gate 5.1): soft-deleted (tombstoned) facts are EXCLUDED
    /// from export. A deleted fact's value must never leave this node — including
    /// its plaintext in the sync push is a GDPR erasure failure (the deleted
    /// content reaches a remote and persists there). Deletion *propagation* does
    /// not depend on this path: the structured tenant-sync mechanism carries a
    /// separate, value-redacted `__sync_tombstone__::` record (only a
    /// `value_hash`, marked `private: true`) so a remote still learns the fact_id
    /// was retired without ever seeing the original content
    /// (see `sync::offboard_tenant_mirror`).
    pub fn export(&self, since: Option<DateTime<Utc>>, cursor: Option<&str>, limit: usize) -> FactExportResult {
        self.export_scoped(None, since, cursor, limit)
    }

    /// Tenant-scoped counterpart to [`Self::export`]. Tenant filtering happens
    /// before sorting and pagination, so foreign rows cannot starve a page or
    /// influence its cursor.
    pub fn export_for_tenant(
        &self,
        tenant_hash: &str,
        since: Option<DateTime<Utc>>,
        cursor: Option<&str>,
        limit: usize,
    ) -> FactExportResult {
        self.export_scoped(Some(tenant_hash), since, cursor, limit)
    }

    fn export_scoped(
        &self,
        tenant_hash: Option<&str>,
        since: Option<DateTime<Utc>>,
        cursor: Option<&str>,
        limit: usize,
    ) -> FactExportResult {
        // 1. Collect facts, excluding private ones (never leave this node) AND
        //    deleted ones (their content must not leave the box — erasure).
        let mut all: Vec<&Fact> = self
            .facts
            .values()
            .filter(|fact| tenant_hash.is_none_or(|tenant| fact.tenant_hash == tenant))
            .filter(|fact| !fact.private && !fact.deleted)
            .collect();

        // 2. Sort by (stored_at, fact_id) ascending.
        all.sort_by(|a, b| a.stored_at.cmp(&b.stored_at).then_with(|| a.fact_id.cmp(&b.fact_id)));

        // 3. Filter by `since` if set.
        if let Some(since_dt) = since {
            all.retain(|f| f.stored_at >= since_dt);
        }

        // 4. Skip past cursor if set.
        let start = if let Some(cursor_id) = cursor {
            match all.iter().position(|f| f.fact_id == cursor_id) {
                Some(pos) => pos + 1,
                None => 0, // cursor not found — start from beginning
            }
        } else {
            0
        };

        let remaining = &all[start..];

        // 5. Take `limit` items.
        let has_more = remaining.len() > limit;
        let taken: Vec<Fact> = remaining.iter().take(limit).map(|f| (*f).clone()).collect();
        let next_cursor = if has_more {
            taken.last().map(|f| f.fact_id.clone())
        } else {
            None
        };

        FactExportResult {
            facts: taken,
            next_cursor,
            has_more,
        }
    }

    /// Paginated, newest-first listing of facts for console / operator surfaces.
    ///
    /// Unlike [`Self::export`] (which is the sync-push path: ascending order,
    /// `since`-anchored), this is the human-browsing path: **descending**
    /// `(stored_at_millis, fact_id)` order — newest fact first — with an opaque
    /// cursor that resumes the walk *exactly* even if the cursor fact is later
    /// filtered out or deleted (the cursor carries the ordering key, not a
    /// position). Millisecond truncation of the sort key makes the cursor and
    /// the sort agree to the same resolution, so there is no sub-millisecond
    /// skew between "where the cursor points" and "how the page is ordered".
    ///
    /// Always-excluded, matching `export`: `private` facts (never leave the
    /// node) and `deleted` (tombstoned) facts. `include_superseded = false`
    /// additionally drops cross-entity-retired facts (`superseded_by.is_some()`);
    /// the default of `true` keeps them so the caller can badge them (parity
    /// with `/v1/facts` + `/v1/console/facts`, which show retired facts today).
    ///
    /// All *other* filtering — reserved-prefix exclusion, `entity_prefix`, `q`
    /// substring, tenant scoping, passport visibility — is the caller's, passed
    /// as `filter`. The store deliberately does not know the consumer-surface
    /// reserved list (that lives in `crux-mcp`) or the auth context.
    ///
    /// `total_visible` counts everything passing `filter` (+ the built-in
    /// exclusions and superseded gate) BEFORE pagination — computed once, cheap
    /// at the ~5k scale this serves.
    pub fn list_page<F>(
        &self,
        cursor: Option<&FactListCursor>,
        limit: usize,
        include_superseded: bool,
        filter: F,
    ) -> FactListPage
    where
        F: Fn(&Fact) -> bool,
    {
        // 1. Collect the visible set: never private, never deleted; drop
        //    cross-entity-retired facts unless the caller opted them in; then
        //    the caller's own predicate (reserved / prefix / q / tenant).
        let mut all: Vec<&Fact> = self
            .facts
            .values()
            .filter(|f| !f.private && !f.deleted)
            .filter(|f| include_superseded || f.superseded_by.is_none())
            .filter(|f| filter(f))
            .collect();
        let total_visible = all.len();

        // 2. Sort DESCENDING by (stored_at_millis, fact_id) — newest first, with
        //    the unique fact_id as a total-order tiebreak inside a millisecond.
        all.sort_by(|a, b| {
            b.stored_at
                .timestamp_millis()
                .cmp(&a.stored_at.timestamp_millis())
                .then_with(|| b.fact_id.cmp(&a.fact_id))
        });

        // 3. Resume past the cursor: skip every fact whose ordering key is >=
        //    the cursor's key. Because the slice is DESC-sorted by exactly this
        //    key, that prefix is contiguous, so `partition_point` finds the
        //    resume index in O(log n). The cursor fact itself (key == cursor)
        //    was the last row of the previous page, so `>=` correctly excludes
        //    it; a cursor pointing at a now-deleted/filtered fact still lands on
        //    the right boundary because we compare keys, not identities.
        let start = match cursor {
            Some(c) => all.partition_point(|f| {
                (f.stored_at.timestamp_millis(), f.fact_id.as_str()) >= (c.stored_at_ms, c.fact_id.as_str())
            }),
            None => 0,
        };
        let remaining = &all[start..];

        // 4. Take `limit`; the next cursor is the last taken row's key.
        let has_more = remaining.len() > limit;
        let taken: Vec<Fact> = remaining.iter().take(limit).map(|f| (*f).clone()).collect();
        let next_cursor = if has_more {
            taken.last().map(|f| {
                FactListCursor {
                    stored_at_ms: f.stored_at.timestamp_millis(),
                    fact_id: f.fact_id.clone(),
                }
                .encode()
            })
        } else {
            None
        };

        FactListPage {
            facts: taken,
            next_cursor,
            has_more,
            total_visible,
        }
    }

    /// Hard-delete the content of soft-deleted facts from the on-disk journal
    /// (launch-gate 5.1 — GDPR erasure).
    ///
    /// Soft-delete only sets `deleted = true` and appends a `JournalEvent::Delete`
    /// tombstone; the original `JournalEvent::Store` event — and the plaintext
    /// value inside it — remains in `facts.jsonl` forever and is replayed on every
    /// restart. Compaction rewrites the journal so that:
    ///
    /// * each **live** (non-deleted) fact is re-emitted as a single `Store` event
    ///   carrying its current identity, value and version, plus a `Supersede`
    ///   marker if it is cross-entity-retired (`superseded_by`);
    /// * each **deleted** fact_id is re-emitted as a `Delete` tombstone ONLY — the
    ///   original `Store` event (and its value) is dropped. Replay still learns
    ///   the fact_id was deleted, but the value is gone from disk.
    ///
    /// Crash-safe: the new journal is written to a sibling temp file, fsynced,
    /// then atomically renamed over `facts.jsonl` — never truncated in place. A
    /// crash before the rename leaves the original journal intact; a crash after
    /// it leaves the fully-written replacement. The in-memory state is the source
    /// of truth and is left untouched.
    ///
    /// Returns a [`CompactionReport`] describing what was removed. No-op (returns
    /// a zeroed report) when the store has no journal (pure in-memory mode).
    pub fn compact_journal(&self) -> std::io::Result<CompactionReport> {
        self.require_unpoisoned_journal_for_compaction()?;
        if self.oversized_legacy_scan_records_skipped() > 0 && !self.active_legal_holds().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "hard erasure of oversized legacy scan records is blocked while any legal hold is active",
            ));
        }
        let mut covered = self.deleted_facts_covered_by_legal_holds();
        covered.extend(self.pruned_control_facts_covered_by_legal_holds()?);
        if !covered.is_empty() {
            let hold_ids: std::collections::BTreeSet<&str> = covered
                .iter()
                .flat_map(|(_, ids)| ids.iter().map(String::as_str))
                .collect();
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "hard erasure blocked by active legal hold(s): {}",
                    hold_ids.into_iter().collect::<Vec<_>>().join(",")
                ),
            ));
        }
        self.compact_journal_unchecked()
    }

    /// Run compaction after the caller has durably emitted an explicit
    /// `legal_hold_overridden` receipt for a full-tenant GDPR erasure.
    ///
    /// The supplied receipt must enumerate every covered deleted fact and
    /// every blocking hold. This guarded API keeps the ordinary compaction
    /// path fail-closed while preserving the higher-priority GDPR primitive.
    pub fn compact_journal_after_legal_hold_override_receipt(
        &self,
        receipt: &crate::legal_hold::LegalHoldReceiptV1,
    ) -> std::io::Result<CompactionReport> {
        self.require_unpoisoned_journal_for_compaction()?;
        if receipt.kind != crate::legal_hold::LegalHoldReceiptKind::Overridden {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "legal-hold override requires a legal_hold_overridden receipt",
            ));
        }
        if self.oversized_legacy_scan_records_skipped() > 0 && !self.active_legal_holds().is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "oversized legacy scan records require hold-preserving manual recovery before compaction",
            ));
        }
        let mut covered = self.deleted_facts_covered_by_legal_holds();
        covered.extend(self.pruned_control_facts_covered_by_legal_holds()?);
        let receipt_fact_ids: std::collections::BTreeSet<&str> = receipt.fact_ids.iter().map(String::as_str).collect();
        let receipt_hold_ids: std::collections::BTreeSet<&str> = receipt.hold_ids.iter().map(String::as_str).collect();
        let fully_covered = covered.iter().all(|(fact_id, hold_ids)| {
            receipt_fact_ids.contains(fact_id.as_str())
                && hold_ids
                    .iter()
                    .all(|hold_id| receipt_hold_ids.contains(hold_id.as_str()))
        });
        if !fully_covered {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "legal_hold_overridden receipt does not cover every blocked fact and hold",
            ));
        }
        self.compact_journal_unchecked()
    }

    fn pruned_control_facts_covered_by_legal_holds(&self) -> std::io::Result<Vec<(String, Vec<String>)>> {
        let holds = self.active_legal_holds();
        let Some(path) = self.journal_path.as_deref() else {
            return Ok(Vec::new());
        };
        if holds.is_empty() || !path.exists() {
            return Ok(Vec::new());
        }

        // Latest-only control snapshots deliberately do not retain one
        // metadata allocation per historical replacement in resident memory.
        // When compaction is actually requested under a legal hold, recover
        // the exact value-free ids from the journal in one streaming pass.
        let mut covered: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut record = |fact_id: &str, tenant_hash: &str, entity: &str| {
            let hold_ids = holds
                .iter()
                .filter(|hold| hold.covers_stored_or_logical_repo_control(tenant_hash, entity))
                .map(|hold| hold.hold_id.clone())
                .collect::<Vec<_>>();
            if !hold_ids.is_empty() {
                covered.entry(fact_id.to_string()).or_default().extend(hold_ids);
            }
        };
        let is_control = |fact: &Fact| {
            fact.key == "content"
                && (fact.entity.starts_with("__repo_registry__::")
                    || fact.entity.starts_with("__repo_scan__::")
                    || fact.entity.starts_with("__workspace_scan__::"))
        };
        let reader = std::io::BufReader::new(std::fs::File::open(path)?);
        for (line_no, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event = serde_json::from_str::<JournalEvent>(&line).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "cannot verify legal-hold coverage for fact journal line {}: {error}",
                        line_no + 1
                    ),
                )
            })?;
            match event {
                JournalEvent::Store { fact } if is_control(&fact) => {
                    if !self.facts.contains_key(&fact.fact_id) {
                        record(&fact.fact_id, &fact.tenant_hash, &fact.entity);
                    }
                }
                JournalEvent::ReplaceLatest {
                    fact,
                    replaced_fact_ids,
                } if is_control(&fact) => {
                    for fact_id in replaced_fact_ids {
                        if !self.facts.contains_key(&fact_id) {
                            record(&fact_id, &fact.tenant_hash, &fact.entity);
                        }
                    }
                    if !self.facts.contains_key(&fact.fact_id) {
                        record(&fact.fact_id, &fact.tenant_hash, &fact.entity);
                    }
                }
                JournalEvent::StoreBatch { facts } => {
                    for fact in facts {
                        if is_control(&fact) && !self.facts.contains_key(&fact.fact_id) {
                            record(&fact.fact_id, &fact.tenant_hash, &fact.entity);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(covered
            .into_iter()
            .map(|(fact_id, mut hold_ids)| {
                hold_ids.sort();
                hold_ids.dedup();
                (fact_id, hold_ids)
            })
            .collect())
    }

    fn compact_journal_unchecked(&self) -> std::io::Result<CompactionReport> {
        self.compact_journal_unchecked_with_record_limit(MAX_FACT_JOURNAL_RECORD_BYTES)
    }

    fn compact_journal_unchecked_with_record_limit(
        &self,
        max_record_bytes: usize,
    ) -> std::io::Result<CompactionReport> {
        self.require_unpoisoned_journal_for_compaction()?;
        let Some(path) = self.journal_path.clone() else {
            return Ok(CompactionReport::default());
        };

        // Gather deleted fact_ids and live facts from in-memory state.
        let mut deleted_ids: Vec<&String> = Vec::new();
        let mut live: Vec<&Fact> = Vec::new();
        for fact in self.facts.values() {
            if fact.deleted {
                deleted_ids.push(&fact.fact_id);
            } else {
                live.push(fact);
            }
        }
        // Deterministic ordering keeps the rewritten journal stable across runs
        // and makes the compaction reproducible/auditable.
        live.sort_by(|a, b| a.stored_at.cmp(&b.stored_at).then_with(|| a.fact_id.cmp(&b.fact_id)));
        deleted_ids.sort();

        let report = CompactionReport {
            facts_dropped: deleted_ids.len(),
            facts_retained: live.len(),
            tombstones_kept: deleted_ids.len(),
        };

        // Write the replacement journal to a temp file in the same directory so
        // the final rename is atomic (same filesystem).
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let tmp_path = parent.join(format!(
            "facts.jsonl.compact-{}.tmp",
            uuid::Uuid::new_v4().to_string().replace('-', "")
        ));

        let write_result = (|| -> std::io::Result<()> {
            let tmp_file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            let mut writer = std::io::BufWriter::new(tmp_file);

            for fact in &live {
                let event = JournalEvent::Store { fact: (*fact).clone() };
                let line = serialize_journal_event_with_limit(&event, max_record_bytes)?;
                writeln!(writer, "{}", line)?;
                // Preserve cross-entity supersession state for live facts so a
                // replay of the compacted journal re-derives `superseded_by`.
                if let Some(by) = &fact.superseded_by {
                    let sup = JournalEvent::Supersede {
                        fact_id: fact.fact_id.clone(),
                        by_fact_id: by.clone(),
                        superseded_at: Utc::now().to_rfc3339(),
                    };
                    let line = serialize_journal_event_with_limit(&sup, max_record_bytes)?;
                    writeln!(writer, "{}", line)?;
                }
            }

            // Preserve consolidation authority separately from caller-writable
            // fact fields. These events contain no fact values and replay only
            // accepts them when the already-restored same-tenant edges match.
            let mut consolidations: Vec<_> = self.consolidation_sources.iter().collect();
            consolidations.sort_by(|(left, _), (right, _)| left.cmp(right));
            for (canonical_fact_id, source_fact_ids) in consolidations {
                let Some(canonical) = self.facts.get(canonical_fact_id).filter(|fact| !fact.deleted) else {
                    continue;
                };
                let event = JournalEvent::ConsolidationProvenance {
                    canonical_fact_id: canonical_fact_id.clone(),
                    source_fact_ids: source_fact_ids.clone(),
                    tenant_hash: canonical.tenant_hash.clone(),
                    recorded_at: Utc::now().to_rfc3339(),
                };
                let line = serialize_journal_event_with_limit(&event, max_record_bytes)?;
                writeln!(writer, "{}", line)?;
            }

            // Value-free tombstones: replay still marks these fact_ids deleted,
            // but the original value never touches the rewritten journal. The
            // `Delete` arm is a no-op on replay if the fact_id is unknown, which
            // is exactly right — the content Store event is gone.
            for fact_id in &deleted_ids {
                let event = JournalEvent::Delete {
                    fact_id: (*fact_id).clone(),
                    deleted_at: Utc::now().to_rfc3339(),
                };
                let line = serialize_journal_event_with_limit(&event, max_record_bytes)?;
                writeln!(writer, "{}", line)?;
            }

            writer.flush()?;
            // fsync the file contents before the rename so a crash can't leave a
            // half-written replacement that the rename then publishes.
            writer.get_ref().sync_all()?;
            Ok(())
        })();
        if let Err(error) = write_result {
            if let Err(cleanup_error) = std::fs::remove_file(&tmp_path) {
                if cleanup_error.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(
                        ?cleanup_error,
                        path = %tmp_path.display(),
                        "failed-to-remove-aborted-fact-journal-compaction"
                    );
                }
            }
            return Err(error);
        }

        // Atomic publish.
        std::fs::rename(&tmp_path, &path)?;
        // Fence the directory fsync so the rename is durable before we log the
        // compaction as successful. Propagated (not swallowed) to match the
        // hard dir-fsync discipline in storage/append.rs: a crash right after a
        // silently-failed dir fsync could lose the rename while the success log
        // below claimed the compaction landed.
        let dir = std::fs::File::open(parent)?;
        dir.sync_all()?;
        self.oversized_legacy_scan_records_skipped
            .store(0, std::sync::atomic::Ordering::Release);
        self.latest_only_pruned_bytes
            .store(0, std::sync::atomic::Ordering::Release);
        self.latest_only_pruned_events
            .store(0, std::sync::atomic::Ordering::Release);
        self.journal_replay_corruption_detected
            .store(false, std::sync::atomic::Ordering::Release);

        tracing::info!(
            facts_dropped = report.facts_dropped,
            facts_retained = report.facts_retained,
            tombstones_kept = report.tombstones_kept,
            journal = %path.display(),
            "fact-journal-compacted"
        );

        Ok(report)
    }

    fn require_unpoisoned_journal_for_compaction(&self) -> std::io::Result<()> {
        if self.durability_poisoned.load(std::sync::atomic::Ordering::Acquire) {
            return Err(std::io::Error::other(
                "fact journal durable mutation plane is poisoned; restart required before compaction",
            ));
        }
        Ok(())
    }

    /// Mark facts whose `stored_at` is older than `cutoff` as deletion-eligible
    /// (retention sweep — W2.E2). Soft-deletes each matching live fact via the
    /// journaled, **fallible** [`Self::try_delete`] path (so the deletion
    /// survives a restart and a later [`Self::compact_journal`] pass removes the
    /// content). Private facts and the structured `__sync_tombstone__::` records
    /// are left alone.
    ///
    /// Returns the fact_ids that were **actually** newly marked deleted — a fact
    /// whose journal append fails is logged (never silently swallowed) and
    /// excluded from the result, so a caller's retention receipt count reflects
    /// only durably-tombstoned facts. This only *marks*; the content is not
    /// removed from disk until `compact_journal` runs, which the caller invokes
    /// explicitly.
    pub fn mark_retention_eligible(&mut self, cutoff: DateTime<Utc>) -> Vec<String> {
        let holds = self.active_legal_holds();
        let to_delete: Vec<(String, String)> = self
            .facts
            .values()
            .filter(|f| !f.deleted && !f.private && f.stored_at < cutoff)
            .filter(|f| !f.entity.starts_with("__sync_tombstone__::"))
            .filter(|f| crate::fact_privacy::daemon_owned_entity_prefix(&f.entity).is_none())
            .filter(|f| !holds.iter().any(|hold| hold.covers_fact(f)))
            .map(|f| (f.tenant_hash.clone(), f.fact_id.clone()))
            .collect();
        let mut deleted = Vec::with_capacity(to_delete.len());
        for (tenant_hash, fact_id) in &to_delete {
            match self.try_delete(tenant_hash, fact_id) {
                Ok(true) => deleted.push(fact_id.clone()),
                Ok(false) => {}
                Err(err) => {
                    tracing::error!(?err, %fact_id, "retention sweep: journaled delete failed; fact NOT marked");
                }
            }
        }
        deleted
    }

    /// Insert a fact directly with its original identity (fact_id, version,
    /// timestamps). Used for facts arriving from a remote sync — skips version
    /// chain logic but DOES append to the journal for persistence.
    ///
    /// Tenant boundary: sync pull callers (`SyncClient::pull` and
    /// `SyncClient::pull_tenant_mirror`) re-stamp `fact.tenant_hash` from the
    /// locally requested tenant before invoking this low-level primitive. Other
    /// callers remain responsible for supplying an authoritative tenant stamp.
    pub fn store_synced(&mut self, mut fact: Fact) -> bool {
        crate::fact_privacy::enforce_global_fact(&mut fact);
        if fact.tenant_hash.trim().is_empty() {
            fact.tenant_hash = default_tenant_hash();
        }

        let fact_id = fact.fact_id.clone();
        if let Some(existing) = self.facts.get(&fact_id) {
            tracing::warn!(
                %fact_id,
                existing_tenant = %existing.tenant_hash,
                incoming_tenant = %fact.tenant_hash,
                "synced-fact-id-collision-rejected"
            );
            return false;
        }
        let tenant_hash = fact.tenant_hash.clone();
        let entity = fact.entity.clone();
        let key = fact.key.clone();

        self.entity_index
            .entry(entity.clone())
            .or_default()
            .push(fact_id.clone());
        self.key_index
            .entry((tenant_hash, entity, key))
            .or_default()
            .push(fact_id.clone());
        self.facts.insert(fact_id.clone(), fact);

        // A synced page may arrive in either chain order. Re-sanitize the
        // complete graph after each insert so a previously unresolved link is
        // checked as soon as its referenced id becomes live. This closes the
        // runtime window where a cross-tenant or wrong-(entity,key) edge was
        // visible until the next restart.
        self.sanitize_replayed_links();
        let Some(fact) = self.facts.get(&fact_id).cloned() else {
            tracing::error!(%fact_id, "synced-fact-disappeared-after-link-sanitization");
            return false;
        };

        if let Err(err) = self.append_journal(&JournalEvent::Store { fact }) {
            tracing::warn!(?err, "fact-journal-append-failed");
        }
        true
    }

    /// Return all versions of a fact for a given (entity, key) pair, ordered by
    /// version ascending. Includes deleted (superseded) versions for audit trail.
    pub fn fact_history(&self, tenant_hash: &str, entity: &str, key: &str) -> Vec<&Fact> {
        let key_pair = (tenant_hash.to_string(), entity.to_string(), key.to_string());
        match self.key_index.get(&key_pair) {
            Some(chain) => {
                let mut facts: Vec<&Fact> = chain.iter().filter_map(|id| self.facts.get(id)).collect();
                facts.sort_by_key(|f| f.version);
                facts
            }
            None => Vec::new(),
        }
    }

    /// Read-only contradiction-candidate pass (Audit II M1).
    ///
    /// This intentionally emits candidates, not decisions. It only flags
    /// active, non-superseded facts that share `(entity, key)` and carry
    /// opposite deterministic polarity classes (`true` vs `false`,
    /// `active` vs `inactive`, etc.). The pass never mutates memory.
    pub fn contradiction_candidates_v1(&self, tenant_hash: &str, limit: usize) -> Vec<ContradictionCandidateV1> {
        let mut groups: BTreeMap<(String, String), Vec<&Fact>> = BTreeMap::new();
        for fact in self.facts.values() {
            if fact.tenant_hash != tenant_hash || fact.deleted || fact.superseded_by.is_some() || fact.private {
                continue;
            }
            if polarity_class_v1(&fact.value).is_none() {
                continue;
            }
            groups
                .entry((fact.entity.clone(), fact.key.clone()))
                .or_default()
                .push(fact);
        }

        let mut out = Vec::new();
        for ((entity, key), facts) in groups {
            let mut by_polarity: BTreeMap<String, Vec<&Fact>> = BTreeMap::new();
            for fact in facts {
                if let Some(pol) = polarity_class_v1(&fact.value) {
                    by_polarity.entry(pol.to_string()).or_default().push(fact);
                }
            }
            if by_polarity.len() < 2 {
                continue;
            }
            let polarities = by_polarity.keys().cloned().collect::<Vec<_>>();
            let fact_ids = by_polarity
                .values()
                .flat_map(|facts| facts.iter().map(|f| f.fact_id.clone()))
                .collect::<Vec<_>>();
            let values = by_polarity
                .values()
                .flat_map(|facts| facts.iter().map(|f| f.value.clone()))
                .collect::<Vec<_>>();
            out.push(ContradictionCandidateV1 {
                entity,
                key,
                reason: "opposite_polarity_same_entity_key".to_string(),
                polarity_a: polarities.first().cloned().unwrap_or_default(),
                polarity_b: polarities.get(1).cloned().unwrap_or_default(),
                fact_ids,
                values,
            });
            if limit > 0 && out.len() >= limit {
                break;
            }
        }
        out
    }

    /// Safe consolidation pass (Audit II M2).
    ///
    /// Creates a new canonical fact and explicitly supersedes every target
    /// fact, but only after rejecting protected inputs. It never hard-deletes
    /// history; `fact_history` and `all_facts` remain replayable.
    pub fn consolidate_facts_v1(
        &mut self,
        tenant_hash: &str,
        req: ConsolidationRequestV1,
    ) -> Result<ConsolidationPassReportV1, ConsolidationErrorV1> {
        if req.target_fact_ids.is_empty() {
            return Err(ConsolidationErrorV1::NoTargets);
        }
        if req.consolidation_id.trim().is_empty() {
            return Err(ConsolidationErrorV1::MissingConsolidationId);
        }

        let mut unique_targets = std::collections::HashSet::new();
        for fact_id in &req.target_fact_ids {
            if !unique_targets.insert(fact_id.as_str()) {
                return Err(ConsolidationErrorV1::DuplicateTarget(fact_id.clone()));
            }
            let fact = self
                .facts
                .get(fact_id)
                .filter(|fact| fact.tenant_hash == tenant_hash)
                .ok_or_else(|| ConsolidationErrorV1::TargetNotFound(fact_id.clone()))?;
            if fact.deleted {
                return Err(ConsolidationErrorV1::TargetDeleted(fact_id.clone()));
            }
            if fact.superseded_by.is_some() {
                return Err(ConsolidationErrorV1::TargetAlreadySuperseded(fact_id.clone()));
            }
            if req.protected_fact_ids.iter().any(|id| id == fact_id) {
                return Err(ConsolidationErrorV1::TargetPinned(fact_id.clone()));
            }
            if let Some(prefix) = crate::fact_privacy::daemon_owned_entity_prefix(&fact.entity) {
                return Err(ConsolidationErrorV1::TargetDaemonOwned {
                    fact_id: fact_id.clone(),
                    prefix: prefix.to_string(),
                });
            }
            if fact.private {
                return Err(ConsolidationErrorV1::TargetPrivate(fact_id.clone()));
            }
            if fact.source_receipt.is_some() {
                return Err(ConsolidationErrorV1::TargetReceiptLinked(fact_id.clone()));
            }
            if fact.confidence >= req.protected_confidence_floor {
                return Err(ConsolidationErrorV1::TargetHighConfidence {
                    fact_id: fact_id.clone(),
                    confidence: format!("{:.3}", fact.confidence),
                });
            }
            if fact.entity != req.entity || fact.key != req.key {
                return Err(ConsolidationErrorV1::TargetOutsideEntityKey(fact_id.clone()));
            }
        }

        // Build the canonical fact WITHOUT storing it yet (computes version +
        // `supersedes` = the prior (entity,key) version to retire).
        let canonical_value = req.canonical_value;
        let canonical_hash = format!(
            "blake3:{}",
            hex::encode(blake3::hash(canonical_value.as_bytes()).as_bytes())
        );
        let canonical = self.build_fact(StoreFact {
            tenant_hash: tenant_hash.to_string(),
            entity: req.entity.clone(),
            key: req.key.clone(),
            value: canonical_value,
            // A durable marker makes undo authorization structural rather than
            // trusting a caller-supplied arbitrary canonical id.
            source_receipt: Some(format!("consolidation:{}", req.consolidation_id)),
            confidence: req.confidence,
            private: false,
            horizon_class: req.horizon_class,
            actor: req.actor,
        });

        // `build_fact` discovers the current prior version. It must have gone
        // through the exact protection checks above; otherwise a caller could
        // name one low-value target while implicitly retiring a private,
        // receipt-linked, pinned, or high-confidence head.
        if let Some(prior) = canonical.supersedes.clone() {
            if !req.target_fact_ids.contains(&prior) {
                return Err(ConsolidationErrorV1::ImplicitPriorNotTarget(prior));
            }
        }
        let superseded_fact_ids = req.target_fact_ids.clone();

        // THE TRANSACTIONAL BOUNDARY: one journal append is the commit point.
        // On failure nothing is mutated (no half-applied consolidation); the
        // error is propagated, never warn-only.
        self.append_journal(&JournalEvent::Consolidate {
            canonical: canonical.clone(),
            superseded_fact_ids: superseded_fact_ids.clone(),
            consolidated_at: Utc::now().to_rfc3339(),
        })
        .map_err(|err| ConsolidationErrorV1::Journal(err.to_string()))?;

        // Durable: now apply in-memory (mirrors the replay handler exactly).
        let canonical_fact_id = canonical.fact_id.clone();
        let _ = self.replay_journal_insert(canonical);
        for id in &superseded_fact_ids {
            if let Some(fact) = self.facts.get_mut(id).filter(|fact| fact.tenant_hash == tenant_hash) {
                fact.superseded_by = Some(canonical_fact_id.clone());
            }
        }
        self.consolidation_sources
            .insert(canonical_fact_id.clone(), superseded_fact_ids.clone());

        Ok(ConsolidationPassReportV1 {
            status: "consolidated".to_string(),
            receipt: ConsolidationReceiptV1 {
                consolidation_id: req.consolidation_id,
                canonical_fact_id,
                canonical_hash,
                superseded_fact_ids,
                source_fact_ids: req.target_fact_ids,
            },
        })
    }

    /// Atomically UNDO a consolidation (buyer-fit M2): retire the generated
    /// canonical and restore (`superseded_by = None`) every source fact. One
    /// journal append is the commit point — all-or-nothing, restart-durable.
    /// Idempotent: undoing an already-undone consolidation (canonical already
    /// soft-deleted) is a no-op returning `status = "already_undone"`.
    pub fn consolidate_undo_v1(
        &mut self,
        tenant_hash: &str,
        canonical_fact_id: &str,
        source_fact_ids: &[String],
    ) -> Result<ConsolidationUndoReportV1, ConsolidationErrorV1> {
        if source_fact_ids.is_empty() {
            return Err(ConsolidationErrorV1::NoUndoSources);
        }
        let canonical = self
            .facts
            .get(canonical_fact_id)
            .filter(|fact| fact.tenant_hash == tenant_hash)
            .ok_or_else(|| ConsolidationErrorV1::TargetNotFound(canonical_fact_id.to_string()))?;
        let Some(recorded_sources) = self.consolidation_sources.get(canonical_fact_id) else {
            return Err(ConsolidationErrorV1::NotConsolidationCanonical(
                canonical_fact_id.to_string(),
            ));
        };
        if canonical.superseded_by.is_some() {
            return Err(ConsolidationErrorV1::CanonicalSuperseded(canonical_fact_id.to_string()));
        }
        let mut expected = recorded_sources.clone();
        expected.sort();
        let mut supplied = source_fact_ids.to_vec();
        supplied.sort();
        supplied.dedup();
        if expected.is_empty() || supplied != expected {
            return Err(ConsolidationErrorV1::UndoSourceMismatch(canonical_fact_id.to_string()));
        }
        if canonical.deleted {
            let sources_restored = expected.iter().all(|id| {
                self.facts.get(id).is_some_and(|fact| {
                    !fact.deleted && fact.tenant_hash == tenant_hash && fact.superseded_by.is_none()
                })
            });
            if sources_restored {
                return Ok(ConsolidationUndoReportV1 {
                    status: "already_undone".to_string(),
                    canonical_fact_id: canonical_fact_id.to_string(),
                    restored_fact_ids: Vec::new(),
                });
            }
            return Err(ConsolidationErrorV1::UndoSourceMismatch(canonical_fact_id.to_string()));
        }

        // Require the exact non-empty edge set. Silently accepting unknown or
        // omitted ids would let a caller delete an arbitrary tenant fact while
        // restoring nothing (or only a chosen subset).
        let edges_match = expected.iter().all(|id| {
            self.facts.get(id).is_some_and(|fact| {
                !fact.deleted
                    && fact.tenant_hash == tenant_hash
                    && fact.superseded_by.as_deref() == Some(canonical_fact_id)
            })
        });
        if !edges_match {
            return Err(ConsolidationErrorV1::UndoSourceMismatch(canonical_fact_id.to_string()));
        }
        let restored = expected;

        // Transactional boundary: single commit-point append.
        self.append_journal(&JournalEvent::ConsolidateUndo {
            canonical_fact_id: canonical_fact_id.to_string(),
            restored_fact_ids: restored.clone(),
            undone_at: Utc::now().to_rfc3339(),
        })
        .map_err(|err| ConsolidationErrorV1::Journal(err.to_string()))?;

        if let Some(fact) = self.facts.get_mut(canonical_fact_id) {
            fact.deleted = true;
        }
        for id in &restored {
            if let Some(fact) = self.facts.get_mut(id) {
                fact.superseded_by = None;
            }
        }

        Ok(ConsolidationUndoReportV1 {
            status: "undone".to_string(),
            canonical_fact_id: canonical_fact_id.to_string(),
            restored_fact_ids: restored,
        })
    }
}

/// Result of a fact query.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FactQueryResult {
    pub facts: Vec<Fact>,
    pub total_tokens: usize,
}

/// Deterministic aggregate operation (buyer-fit M4, knock-out #5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AggregateOp {
    /// Number of matching facts.
    Count,
    /// Sum of the leading numeric value of each matching fact.
    SumNumeric,
    /// Number of distinct values among matching facts.
    Distinct,
    /// Numeric change in an (entity,key) value between `as_of` and now.
    TemporalDiff,
}

impl AggregateOp {
    pub fn as_str(self) -> &'static str {
        match self {
            AggregateOp::Count => "count",
            AggregateOp::SumNumeric => "sum_numeric",
            AggregateOp::Distinct => "distinct",
            AggregateOp::TemporalDiff => "temporal_diff",
        }
    }
}

/// Request for [`FactStore::aggregate_v1`].
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct AggregateRequestV1 {
    pub op: AggregateOp,
    #[serde(default)]
    pub entity: Option<String>,
    #[serde(default)]
    pub key: Option<String>,
    /// Case-insensitive substring filter on the fact value.
    #[serde(default)]
    pub query: Option<String>,
    /// For `temporal_diff`: the world-time anchor to diff against.
    #[serde(default)]
    pub as_of: Option<DateTime<Utc>>,
    /// Cap on the candidate facts scanned (honest, bounded cost).
    #[serde(default)]
    pub token_budget: Option<usize>,
}

/// Result of [`FactStore::aggregate_v1`] — a deterministic, 0-LLM answer.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct AggregateResultV1 {
    pub op: String,
    /// Facts that contributed to the answer.
    pub matched: usize,
    /// The answer (integer count/distinct, float sum/diff, or null).
    pub value: serde_json::Value,
    /// Always 0 — this lane never calls a model. Reported for honesty.
    pub llm_calls: u32,
    /// Tokens across the scanned candidate set (honest accounting).
    pub tokens_scanned: usize,
    /// True if `token_budget` stopped the scan before all candidates.
    pub budget_truncated: bool,
}

/// Parse the leading numeric value out of a fact value, tolerating currency
/// symbols, thousands separators, and trailing text: `"$450,000 approved"` ⇒
/// `450000.0`, `"3 cats"` ⇒ `3.0`. Returns `None` when there is no number.
fn parse_leading_number(value: &str) -> Option<f64> {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_digit() {
            break;
        }
        if (c == b'-' || c == b'+') && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
            break;
        }
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let mut num = String::new();
    if bytes[i] == b'-' || bytes[i] == b'+' {
        num.push(bytes[i] as char);
        i += 1;
    }
    let mut seen_dot = false;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_digit() {
            num.push(c as char);
        } else if c == b',' {
            // thousands separator — skip
        } else if c == b'.' && !seen_dot {
            seen_dot = true;
            num.push('.');
        } else {
            break;
        }
        i += 1;
    }
    num.parse::<f64>().ok()
}

/// Outcome of a [`FactStore::compact_journal`] pass (launch-gate 5.1 erasure).
#[derive(Debug, Default, Clone, Serialize, utoipa::ToSchema)]
pub struct CompactionReport {
    /// Number of soft-deleted facts whose original content (the `Store` event)
    /// was dropped from the on-disk journal.
    pub facts_dropped: usize,
    /// Number of live (non-deleted) facts re-emitted into the compacted journal.
    pub facts_retained: usize,
    /// Number of value-free `Delete` tombstones kept so replay still excludes
    /// the dropped fact_ids.
    pub tombstones_kept: usize,
}

/// Result of a paginated fact export. Excludes private and soft-deleted facts
/// (erasure: a tombstoned fact's content must not leave the node).
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct FactExportResult {
    pub facts: Vec<Fact>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// Opaque descending-listing cursor for [`FactStore::list_page`].
///
/// Encodes the ordering key of the last row returned — `(stored_at_millis,
/// fact_id)` — so the next page resumes exactly. The wire form is
/// `"<stored_at_ms>:<fact_id>"`: the millisecond field is all digits, so
/// splitting on the FIRST `:` recovers both halves even though `fact_id`
/// (`f_<hex>`) never itself contains a colon. Clients MUST treat it as opaque:
/// only hand back a `next_cursor` from a prior response, never construct one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactListCursor {
    pub stored_at_ms: i64,
    pub fact_id: String,
}

impl FactListCursor {
    /// Serialize to the opaque wire form (`"<ms>:<fact_id>"`).
    pub fn encode(&self) -> String {
        format!("{}:{}", self.stored_at_ms, self.fact_id)
    }

    /// Parse the opaque wire form. Returns `None` for anything malformed
    /// (missing separator, non-numeric millisecond field, empty fact_id) so the
    /// HTTP layer can answer 400 rather than silently restarting the walk.
    pub fn decode(raw: &str) -> Option<Self> {
        let (ms, fact_id) = raw.split_once(':')?;
        let stored_at_ms: i64 = ms.parse().ok()?;
        if fact_id.is_empty() {
            return None;
        }
        Some(Self {
            stored_at_ms,
            fact_id: fact_id.to_string(),
        })
    }
}

/// One page of [`FactStore::list_page`]: the descending (newest-first) slice
/// plus the opaque `next_cursor` (present iff `has_more`) and `total_visible`
/// (the full count matching the caller's filters, before pagination).
#[derive(Debug)]
pub struct FactListPage {
    pub facts: Vec<Fact>,
    pub next_cursor: Option<String>,
    pub has_more: bool,
    pub total_visible: usize,
}

/// Estimate token count from text (bytes / 4 approximation).
fn estimate_tokens(text: &str) -> usize {
    text.len().div_ceil(4)
}

fn polarity_class_v1(value: &str) -> Option<&'static str> {
    let v = value
        .trim()
        .trim_matches(|c: char| !c.is_alphanumeric() && c != '_')
        .to_ascii_lowercase();
    match v.as_str() {
        "true" | "yes" | "y" | "on" | "enabled" | "enable" | "active" | "complete" | "completed" | "passed"
        | "pass" | "approved" | "approve" | "present" => Some("positive"),
        "false" | "no" | "n" | "off" | "disabled" | "disable" | "inactive" | "blocked" | "failed" | "fail"
        | "rejected" | "reject" | "absent" => Some("negative"),
        _ => None,
    }
}

/// Reduce `facts` to one row per (tenant, entity, key) — the row with the highest
/// `version` wins. Preserves Fact ordering otherwise (callers can re-sort).
///
/// `FactStore::query()` returns all live versions of a fact — including
/// superseded ones. Listing surfaces (passports, projects, work, engram
/// overlays) want only the latest version per `(entity, key)`.
pub fn dedup_latest(facts: Vec<Fact>) -> Vec<Fact> {
    let mut by_key: std::collections::BTreeMap<(String, String, String), Fact> = std::collections::BTreeMap::new();
    for fact in facts {
        let key = (fact.tenant_hash.clone(), fact.entity.clone(), fact.key.clone());
        match by_key.get(&key) {
            Some(existing) if existing.version >= fact.version => {}
            _ => {
                by_key.insert(key, fact);
            }
        }
    }
    by_key.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dedup_fixture(id: &str, entity: &str, key: &str, version: u32) -> Fact {
        Fact {
            fact_id: id.to_string(),
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: format!("v{version}"),
            source_receipt: None,
            confidence: 1.0,
            stored_at: chrono::Utc::now(),
            tokens: 1,
            deleted: false,
            version,
            supersedes: if version > 1 { Some("prev".to_string()) } else { None },
            private: false,
            horizon_class: HorizonClass::None,
            reverified_at: None,
            superseded_by: None,
            actor: None,
            valid_from: None,
            valid_to: None,
            access_count: 0,
            last_accessed_at: None,
        }
    }

    fn tenant_fact(tenant: &str, entity: &str, key: &str, value: &str) -> StoreFact {
        StoreFact {
            tenant_hash: tenant.to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        }
    }

    /// Versions arrive OUT of order (1, 3, 2) — the highest version must win,
    /// not the last-seen row. `FactStore::query()` can return superseded
    /// versions in non-monotonic order, so this distinction is load-bearing
    /// for overlay listings (engrams, passports, work).
    #[test]
    fn dedup_keeps_highest_version_per_entity_and_key() {
        let input = vec![
            dedup_fixture("a1", "e1", "k", 1),
            dedup_fixture("a2", "e1", "k", 3),
            dedup_fixture("a3", "e1", "k", 2),
            dedup_fixture("b1", "e2", "k", 5),
        ];
        let mut out = dedup_latest(input);
        out.sort_by(|a, b| a.entity.cmp(&b.entity));
        assert_eq!(out.len(), 2);
        assert_eq!(
            out[0].value, "v3",
            "e1: highest version wins even when v2 arrives after v3"
        );
        assert_eq!(out[1].value, "v5");
    }

    /// Backward-compat (agent-passport M1): a JSON fact written before the
    /// `actor` field existed (e.g. one of the ~2.1k prod facts, or a
    /// pre-M1 journal-replay entry) must deserialize with `actor = None`.
    /// `#[serde(default, skip_serializing_if = "Option::is_none")]` is what
    /// guarantees this — exactly the pattern used by `superseded_by`.
    #[test]
    fn fact_without_actor_key_deserializes_to_none() {
        // Note: no `actor` key, no `version` key, no `superseded_by` key —
        // the shape of an old on-disk fact.
        let json = r#"{
            "fact_id": "f_legacy_0001",
            "entity": "deployment",
            "key": "strategy",
            "value": "canary",
            "source_receipt": null,
            "confidence": 1.0,
            "stored_at": "2026-01-01T00:00:00Z",
            "tokens": 1,
            "deleted": false
        }"#;
        let fact: Fact = serde_json::from_str(json).expect("legacy fact must deserialize");
        assert_eq!(fact.tenant_hash, "default");
        assert_eq!(fact.actor, None, "legacy facts must load with actor = None");
        // And it must not re-serialize the key (skip_serializing_if).
        let round = serde_json::to_string(&fact).unwrap();
        assert!(!round.contains("\"actor\""), "actor=None must not serialize a key");
    }

    #[test]
    fn journal_replay_reclassifies_legacy_control_fact_as_private() {
        let dir = tempfile::tempdir().unwrap();
        let mut fact = dedup_fixture("f_legacy_public_passport", "__passport__::legacy-forgery", "record", 1);
        fact.private = false;
        fact.value = r#"{"tier":"operator"}"#.to_string();
        let line = serde_json::to_string(&JournalEvent::Store { fact }).unwrap();
        std::fs::write(dir.path().join("facts.jsonl"), format!("{line}\n")).unwrap();

        let store = FactStore::with_persistence(dir.path()).unwrap();
        let replayed = store.get("f_legacy_public_passport").unwrap();
        assert!(replayed.private, "current born-private policy must apply on replay");
        assert!(
            store.export(None, None, 10).facts.is_empty(),
            "reclassified control rows must not become sync-export eligible"
        );
    }

    #[test]
    fn store_and_retrieve_fact() {
        let mut store = FactStore::new();

        let fact = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "deployment".to_string(),
            key: "strategy".to_string(),
            value: "canary deployment with evaluator programme".to_string(),
            source_receipt: Some("crx_123".to_string()),
            confidence: 0.95,
            private: false,
            horizon_class: None,
            actor: None,
        });

        assert!(fact.fact_id.starts_with("f_"));
        assert_eq!(fact.entity, "deployment");
        assert_eq!(store.count(), 1);

        let retrieved = store.get(&fact.fact_id).unwrap();
        assert_eq!(retrieved.value, "canary deployment with evaluator programme");
    }

    #[test]
    fn local_embedder_makes_dense_ranking_the_default_with_no_external_service() {
        // buyer-fit M3.2: a FactStore wired with the pure-Rust LocalHashEmbedder
        // (no external URL) ranks by cosine similarity — dense ON by default.
        let mut store = FactStore::new();
        store.set_embedder(Box::new(crate::embeddings::LocalHashEmbedder::default()));
        assert!(store.embeddings_enabled(), "local embedder ⇒ dense enabled");
        assert!(store.local_embeddings_enabled());
        assert_eq!(
            store.semantic_profile().unwrap().model,
            crate::embeddings::LOCAL_HASH_EMBEDDER_MODEL,
            "profile reports the local model"
        );

        let mk = |entity: &str, key: &str, value: &str| StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };
        store.store(mk(
            "infra",
            "terraform",
            "terraform module drift detection infrastructure",
        ));
        store.store(mk(
            "ci",
            "pipeline",
            "continuous integration deployment pipeline automation",
        ));
        store.store(mk(
            "docs",
            "onboarding",
            "developer onboarding guide and setup instructions",
        ));

        // A lexically-overlapping query must surface the terraform fact first,
        // ranked by cosine (keyword substring filtering is bypassed when dense).
        let result = store.query(&FactQuery {
            min_effective_confidence: None,
            query: Some("terraform infrastructure drift".to_string()),
            entity: None,
            tenant_hash: None,
            entity_prefix: None,
            top_k: 3,
            token_budget: None,
        });
        assert!(!result.facts.is_empty(), "dense query returns results");
        assert_eq!(
            result.facts[0].key, "terraform",
            "highest-cosine fact ranks first via the local embedder"
        );
    }

    #[test]
    fn external_embedding_client_is_not_reported_as_local() {
        let mut store = FactStore::new();
        store.set_embedding_client(crate::embeddings::EmbeddingClient::new(
            crate::embeddings::EmbeddingConfig {
                base_url: "http://embed.example.test".to_string(),
                model: "external-test".to_string(),
                dimensions: 8,
            },
        ));

        assert!(store.embeddings_enabled());
        assert!(!store.local_embeddings_enabled());
    }

    #[test]
    fn semantic_dedup_flags_near_duplicate_as_review_candidate() {
        // buyer-fit M3.5: with an embedder + dedup enabled, a semantically-near
        // fact under a DIFFERENT entity/key is flagged (never dropped); a version
        // update of the same (entity,key) is NOT flagged; an unrelated fact isn't.
        let mut store = FactStore::new();
        store.set_embedder(Box::new(crate::embeddings::LocalHashEmbedder::default()));
        store.set_semantic_dedup(0.8);

        let mk = |entity: &str, key: &str, value: &str| StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };

        let value =
            "the production deployment uses a canary rollout strategy with automatic rollback on error budget breach";
        let original = store.store(mk("svc-a", "note", value));
        assert!(
            store.near_duplicates().is_empty(),
            "first fact has nothing to duplicate"
        );

        // Unrelated fact — not flagged.
        store.store(mk(
            "svc-b",
            "misc",
            "quantum chromodynamics lecture notes and problem sets for graduate physics",
        ));
        assert!(
            store.near_duplicates().is_empty(),
            "unrelated fact is not a near-duplicate"
        );

        // Version update of the SAME (entity,key) — not flagged (version chain).
        store.store(mk("svc-a", "note", &format!("{value} now")));
        assert!(
            store.near_duplicates().is_empty(),
            "same entity+key update is a version, not a dup"
        );

        // Same entity, DIFFERENT key, identical value — a genuine near-duplicate,
        // flagged as a review candidate.
        let dup = store.store(mk("svc-a", "summary", value));
        let flags = store.near_duplicates();
        assert_eq!(flags.len(), 1, "the near-duplicate is flagged");
        assert_eq!(flags[0].fact_id, dup.fact_id);
        assert!(flags[0].score >= 0.9, "flagged at/above threshold: {}", flags[0].score);
        // The fact itself is preserved — dedup is advisory, never a silent delete.
        assert!(store.get(&dup.fact_id).is_some());
        assert!(store.get(&original.fact_id).is_some());
    }

    #[test]
    fn fact_store_enforces_born_private_policy_at_every_request_entry_point() {
        let request = |entity: &str, private| StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: "record".to_string(),
            value: "sensitive".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private,
            horizon_class: None,
            actor: None,
        };
        let mut store = FactStore::new();

        let stored = store.store(request("__passport__::alice", false));
        let try_stored = store
            .try_store(request("__constraints__::no-public-write", false))
            .expect("in-memory try_store should succeed");
        let bulk_stored = store
            .try_store_bulk(vec![request("__ops__::coverage::retrieval", false)])
            .expect("in-memory try_store_bulk should succeed");
        let already_private = store.store(request("public::explicitly-private", true));

        assert!(stored.private);
        assert!(try_stored.private);
        assert!(bulk_stored[0].private);
        assert!(already_private.private);
    }

    #[test]
    fn query_by_keyword() {
        let mut store = FactStore::new();

        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "deployment".to_string(),
            key: "strategy".to_string(),
            value: "canary deployment".to_string(),
            source_receipt: None,
            confidence: 0.9,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "testing".to_string(),
            key: "approach".to_string(),
            value: "integration tests with real database".to_string(),
            source_receipt: None,
            confidence: 0.8,
            private: false,
            horizon_class: None,
            actor: None,
        });

        let result = store.query(&FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            entity_prefix: None,
            query: Some("deployment".to_string()),
            entity: None,
            top_k: 10,
            token_budget: None,
        });

        assert_eq!(result.facts.len(), 1);
        assert_eq!(result.facts[0].entity, "deployment");
    }

    #[test]
    fn contradiction_candidates_v1_flags_active_opposite_polarity() {
        let mut store = FactStore::new();

        let first = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "service:api".to_string(),
            key: "enabled".to_string(),
            value: "enabled".to_string(),
            source_receipt: None,
            confidence: 0.7,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let second = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "service:api".to_string(),
            key: "enabled".to_string(),
            value: "disabled".to_string(),
            source_receipt: None,
            confidence: 0.7,
            private: false,
            horizon_class: None,
            actor: None,
        });
        assert!(
            store.clear_superseded("default", &first.fact_id),
            "simulate unresolved remote conflict"
        );

        let candidates = store.contradiction_candidates_v1("default", 10);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].entity, "service:api");
        assert_eq!(candidates[0].key, "enabled");
        assert!(candidates[0].fact_ids.contains(&first.fact_id));
        assert!(candidates[0].fact_ids.contains(&second.fact_id));
        assert_eq!(candidates[0].reason, "opposite_polarity_same_entity_key");
    }

    #[test]
    fn contradiction_candidates_v1_never_surface_private_values() {
        let mut store = FactStore::new();
        let first = store.store(StoreFact {
            tenant_hash: "tenant-a".to_string(),
            entity: "private-state".to_string(),
            key: "enabled".to_string(),
            value: "enabled".to_string(),
            source_receipt: None,
            confidence: 0.4,
            private: true,
            horizon_class: None,
            actor: None,
        });
        store.store(StoreFact {
            tenant_hash: "tenant-a".to_string(),
            entity: "private-state".to_string(),
            key: "enabled".to_string(),
            value: "disabled".to_string(),
            source_receipt: None,
            confidence: 0.4,
            private: true,
            horizon_class: None,
            actor: None,
        });
        assert!(store.clear_superseded("tenant-a", &first.fact_id));
        assert!(
            store.contradiction_candidates_v1("tenant-a", 10).is_empty(),
            "private values must not ride the contradiction review surface"
        );
    }

    #[test]
    fn consolidate_facts_v1_supersedes_targets_without_deleting_history() {
        let mut store = FactStore::new();

        let old = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "blocked".to_string(),
            source_receipt: None,
            confidence: 0.4,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let newer = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "active".to_string(),
            source_receipt: None,
            confidence: 0.5,
            private: false,
            horizon_class: None,
            actor: None,
        });
        assert!(
            store.clear_superseded("default", &old.fact_id),
            "make both targets active"
        );

        let report = store
            .consolidate_facts_v1(
                "default",
                ConsolidationRequestV1 {
                    consolidation_id: "con-1".to_string(),
                    entity: "proj".to_string(),
                    key: "status".to_string(),
                    canonical_value: "active".to_string(),
                    target_fact_ids: vec![old.fact_id.clone(), newer.fact_id.clone()],
                    protected_fact_ids: vec![],
                    confidence: 0.8,
                    source_receipt: None,
                    actor: Some("agent:codex".to_string()),
                    horizon_class: Some(HorizonClass::Stable),
                    protected_confidence_floor: 0.99,
                },
            )
            .expect("consolidate");

        let canonical_id = report.receipt.canonical_fact_id;
        assert_eq!(
            store.get(&old.fact_id).unwrap().superseded_by.as_deref(),
            Some(canonical_id.as_str())
        );
        assert_eq!(
            store.get(&newer.fact_id).unwrap().superseded_by.as_deref(),
            Some(canonical_id.as_str())
        );
        let history = store.fact_history("default", "proj", "status");
        assert_eq!(history.len(), 3, "consolidation must preserve version history");
        assert!(history.iter().any(|f| f.fact_id == old.fact_id));
        assert!(history.iter().any(|f| f.fact_id == newer.fact_id));
        assert!(history.iter().any(|f| f.fact_id == canonical_id));
    }

    #[test]
    fn consolidate_facts_v1_rejects_protected_targets() {
        let mut store = FactStore::new();
        let linked = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "proj".to_string(),
            key: "decision".to_string(),
            value: "approved".to_string(),
            source_receipt: Some("receipt:r1".to_string()),
            confidence: 0.5,
            private: false,
            horizon_class: None,
            actor: None,
        });

        let err = store
            .consolidate_facts_v1(
                "default",
                ConsolidationRequestV1 {
                    consolidation_id: "con-guard".to_string(),
                    entity: "proj".to_string(),
                    key: "decision".to_string(),
                    canonical_value: "approved".to_string(),
                    target_fact_ids: vec![linked.fact_id.clone()],
                    protected_fact_ids: vec![],
                    confidence: 0.8,
                    source_receipt: None,
                    actor: None,
                    horizon_class: None,
                    protected_confidence_floor: 0.99,
                },
            )
            .expect_err("receipt-linked targets are protected");
        assert_eq!(err, ConsolidationErrorV1::TargetReceiptLinked(linked.fact_id.clone()));
        assert!(store.get(&linked.fact_id).unwrap().superseded_by.is_none());
    }

    #[test]
    fn consolidate_facts_v1_rejects_unvalidated_implicit_prior() {
        let mut store = FactStore::new();
        let low = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "blocked".to_string(),
            source_receipt: None,
            confidence: 0.2,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let protected_head = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "approved".to_string(),
            source_receipt: Some("receipt:protected".to_string()),
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        assert!(store.clear_superseded("default", &low.fact_id));

        let err = store
            .consolidate_facts_v1(
                "default",
                ConsolidationRequestV1 {
                    consolidation_id: "con-implicit".to_string(),
                    entity: "proj".to_string(),
                    key: "status".to_string(),
                    canonical_value: "settled".to_string(),
                    target_fact_ids: vec![low.fact_id.clone()],
                    protected_fact_ids: vec![],
                    confidence: 0.5,
                    source_receipt: None,
                    actor: Some("agent:codex".to_string()),
                    horizon_class: None,
                    protected_confidence_floor: 0.99,
                },
            )
            .expect_err("implicit prior must be explicitly validated");
        assert_eq!(
            err,
            ConsolidationErrorV1::ImplicitPriorNotTarget(protected_head.fact_id.clone())
        );
        assert!(store.get(&protected_head.fact_id).unwrap().superseded_by.is_none());
        assert_eq!(store.fact_history("default", "proj", "status").len(), 2);
    }

    #[test]
    fn consolidate_rejects_superseded_or_duplicate_targets_atomically() {
        let mut store = FactStore::new();
        let first = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "blocked".to_string(),
            source_receipt: None,
            confidence: 0.2,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let second = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "active".to_string(),
            source_receipt: None,
            confidence: 0.3,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let original_edge = first
            .superseded_by
            .clone()
            .or_else(|| store.get(&first.fact_id).and_then(|fact| fact.superseded_by.clone()));
        let err = store
            .consolidate_facts_v1(
                "default",
                ConsolidationRequestV1 {
                    consolidation_id: "con-retired".to_string(),
                    entity: "proj".to_string(),
                    key: "status".to_string(),
                    canonical_value: "settled".to_string(),
                    target_fact_ids: vec![first.fact_id.clone(), second.fact_id.clone()],
                    protected_fact_ids: vec![],
                    confidence: 0.5,
                    source_receipt: None,
                    actor: None,
                    horizon_class: None,
                    protected_confidence_floor: 0.99,
                },
            )
            .expect_err("already-retired target must be rejected");
        assert_eq!(
            err,
            ConsolidationErrorV1::TargetAlreadySuperseded(first.fact_id.clone())
        );
        assert_eq!(store.get(&first.fact_id).unwrap().superseded_by, original_edge);
        assert_eq!(store.fact_history("default", "proj", "status").len(), 2);

        assert!(store.clear_superseded("default", &first.fact_id));
        let err = store
            .consolidate_facts_v1(
                "default",
                ConsolidationRequestV1 {
                    consolidation_id: "con-duplicate".to_string(),
                    entity: "proj".to_string(),
                    key: "status".to_string(),
                    canonical_value: "settled".to_string(),
                    target_fact_ids: vec![second.fact_id.clone(), second.fact_id.clone()],
                    protected_fact_ids: vec![],
                    confidence: 0.5,
                    source_receipt: None,
                    actor: None,
                    horizon_class: None,
                    protected_confidence_floor: 0.99,
                },
            )
            .expect_err("duplicate target set must be rejected");
        assert_eq!(err, ConsolidationErrorV1::DuplicateTarget(second.fact_id.clone()));
        assert_eq!(store.fact_history("default", "proj", "status").len(), 2);
    }

    #[test]
    fn consolidate_facts_v1_rejects_legacy_public_daemon_control_target() {
        let mut store = FactStore::new();
        let control = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "__passport__::legacy".to_string(),
            key: "record".to_string(),
            value: "{}".to_string(),
            source_receipt: None,
            confidence: 0.1,
            private: false,
            horizon_class: None,
            actor: None,
        });
        // Simulate a row persisted before born-private enforcement.
        store.facts.get_mut(&control.fact_id).unwrap().private = false;

        let err = store
            .consolidate_facts_v1(
                "default",
                ConsolidationRequestV1 {
                    consolidation_id: "con-control-guard".to_string(),
                    entity: "__passport__::legacy".to_string(),
                    key: "record".to_string(),
                    canonical_value: r#"{"tier":"operator"}"#.to_string(),
                    target_fact_ids: vec![control.fact_id.clone()],
                    protected_fact_ids: vec![],
                    confidence: 0.2,
                    source_receipt: None,
                    actor: Some("operator".to_string()),
                    horizon_class: None,
                    protected_confidence_floor: 0.99,
                },
            )
            .expect_err("daemon control targets are protected independently of privacy");
        assert_eq!(
            err,
            ConsolidationErrorV1::TargetDaemonOwned {
                fact_id: control.fact_id.clone(),
                prefix: "__passport__::".to_string(),
            }
        );
        assert!(store.get(&control.fact_id).unwrap().superseded_by.is_none());
    }

    // ── buyer-fit M2: atomic consolidation + receipted undo ──────────────

    fn seed_two_active(store: &mut FactStore) -> (String, String) {
        let a = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "blocked".to_string(),
            source_receipt: None,
            confidence: 0.4,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let b = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "active".to_string(),
            source_receipt: None,
            confidence: 0.5,
            private: false,
            horizon_class: None,
            actor: None,
        });
        // storing b auto-superseded a via the version chain; reactivate it.
        store.clear_superseded("default", &a.fact_id);
        (a.fact_id, b.fact_id)
    }

    fn consolidate_req(a: &str, b: &str) -> ConsolidationRequestV1 {
        ConsolidationRequestV1 {
            consolidation_id: "con-m2".to_string(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            canonical_value: "settled".to_string(),
            target_fact_ids: vec![a.to_string(), b.to_string()],
            protected_fact_ids: vec![],
            confidence: 0.8,
            source_receipt: None,
            actor: Some("agent:codex".to_string()),
            horizon_class: Some(HorizonClass::Stable),
            protected_confidence_floor: 0.99,
        }
    }

    #[test]
    fn consolidate_is_atomic_and_carries_canonical_hash() {
        let mut store = FactStore::new();
        let (a, b) = seed_two_active(&mut store);
        let report = store
            .consolidate_facts_v1("default", consolidate_req(&a, &b))
            .expect("consolidate");
        let cid = report.receipt.canonical_fact_id.clone();
        // The receipt carries the after-side hash for the signed diff.
        let expected = format!("blake3:{}", hex::encode(blake3::hash(b"settled").as_bytes()));
        assert_eq!(report.receipt.canonical_hash, expected);
        // All targets retired under this canonical.
        assert_eq!(store.get(&a).unwrap().superseded_by.as_deref(), Some(cid.as_str()));
        assert_eq!(store.get(&b).unwrap().superseded_by.as_deref(), Some(cid.as_str()));
        // History preserved (nothing hard-deleted).
        assert_eq!(store.fact_history("default", "proj", "status").len(), 3);
    }

    #[test]
    fn consolidate_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b, cid);
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let (fa, fb) = seed_two_active(&mut store);
            let report = store
                .consolidate_facts_v1("default", consolidate_req(&fa, &fb))
                .expect("consolidate");
            (a, b, cid) = (fa, fb, report.receipt.canonical_fact_id);
        }
        // Reopen → journal replay must reproduce the exact post-consolidation state.
        let store = FactStore::with_persistence(dir.path()).unwrap();
        assert!(store.get(&cid).is_some(), "canonical survives restart");
        assert_eq!(store.get(&a).unwrap().superseded_by.as_deref(), Some(cid.as_str()));
        assert_eq!(store.get(&b).unwrap().superseded_by.as_deref(), Some(cid.as_str()));
    }

    #[test]
    fn consolidate_undo_restores_sources_and_retires_canonical() {
        let mut store = FactStore::new();
        let (a, b) = seed_two_active(&mut store);
        let report = store
            .consolidate_facts_v1("default", consolidate_req(&a, &b))
            .expect("consolidate");
        let cid = report.receipt.canonical_fact_id.clone();
        assert!(
            !store.delete("default", &cid),
            "generic delete must not strand consolidation sources"
        );
        assert!(
            !store.try_delete("default", &cid).unwrap(),
            "journaled generic delete must require dedicated undo"
        );
        assert!(store.get(&cid).is_some());
        assert_eq!(store.get(&a).unwrap().superseded_by.as_deref(), Some(cid.as_str()));
        assert_eq!(store.get(&b).unwrap().superseded_by.as_deref(), Some(cid.as_str()));
        assert!(
            !store.try_delete("default", &a).unwrap(),
            "generic delete must not remove an active consolidation source"
        );
        let unrelated = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "other".to_string(),
            key: "status".to_string(),
            value: "new".to_string(),
            source_receipt: None,
            confidence: 0.2,
            private: false,
            horizon_class: None,
            actor: None,
        });
        assert!(
            !store.mark_superseded("default", &a, &unrelated.fact_id),
            "generic re-retirement must not rewrite consolidation provenance"
        );
        assert_eq!(store.get(&a).unwrap().superseded_by.as_deref(), Some(cid.as_str()));
        let undo = store
            .consolidate_undo_v1("default", &cid, &report.receipt.source_fact_ids)
            .expect("undo");
        assert_eq!(undo.status, "undone");
        // Canonical retired, sources restored (active again).
        assert!(store.get(&cid).is_none(), "canonical soft-deleted by undo");
        assert!(store.get(&a).unwrap().superseded_by.is_none());
        assert!(store.get(&b).unwrap().superseded_by.is_none());
    }

    #[test]
    fn consolidate_undo_rejects_arbitrary_canonical_and_inexact_sources() {
        let mut store = FactStore::new();
        let ordinary = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "ordinary".to_string(),
            key: "value".to_string(),
            value: "keep".to_string(),
            source_receipt: Some("consolidation:forged".to_string()),
            confidence: 0.4,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let empty_err = store
            .consolidate_undo_v1("default", &ordinary.fact_id, &[])
            .expect_err("empty source set must never delete a fact");
        assert_eq!(empty_err, ConsolidationErrorV1::NoUndoSources);
        let err = store
            .consolidate_undo_v1("default", &ordinary.fact_id, &["f_bogus".to_string()])
            .expect_err("ordinary fact is not an undo canonical");
        assert_eq!(
            err,
            ConsolidationErrorV1::NotConsolidationCanonical(ordinary.fact_id.clone())
        );
        assert!(store.get(&ordinary.fact_id).is_some());

        let (a, b) = seed_two_active(&mut store);
        let report = store
            .consolidate_facts_v1("default", consolidate_req(&a, &b))
            .expect("consolidate");
        let cid = report.receipt.canonical_fact_id;
        let err = store
            .consolidate_undo_v1("default", &cid, std::slice::from_ref(&a))
            .expect_err("partial source set must not delete the canonical");
        assert_eq!(err, ConsolidationErrorV1::UndoSourceMismatch(cid.clone()));
        assert!(store.get(&cid).is_some());
        assert_eq!(store.get(&a).unwrap().superseded_by.as_deref(), Some(cid.as_str()));
        assert_eq!(store.get(&b).unwrap().superseded_by.as_deref(), Some(cid.as_str()));
    }

    #[test]
    fn consolidate_undo_rejects_corrupt_deleted_or_superseded_canonical() {
        let mut store = FactStore::new();
        let (a, b) = seed_two_active(&mut store);
        let report = store
            .consolidate_facts_v1("default", consolidate_req(&a, &b))
            .expect("consolidate");
        let cid = report.receipt.canonical_fact_id.clone();
        store.facts.get_mut(&cid).unwrap().deleted = true;
        let err = store
            .consolidate_undo_v1("default", &cid, &report.receipt.source_fact_ids)
            .expect_err("deleted canonical with retired sources is not already undone");
        assert_eq!(err, ConsolidationErrorV1::UndoSourceMismatch(cid.clone()));

        // Restore the canonical only to model a later same-key write.
        store.facts.get_mut(&cid).unwrap().deleted = false;
        let successor = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "newer".to_string(),
            source_receipt: None,
            confidence: 0.5,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let err = store
            .consolidate_undo_v1("default", &cid, &report.receipt.source_fact_ids)
            .expect_err("superseded canonical cannot be safely undone");
        assert_eq!(err, ConsolidationErrorV1::CanonicalSuperseded(cid.clone()));
        assert_eq!(
            store.get(&cid).unwrap().superseded_by.as_deref(),
            Some(successor.fact_id.as_str())
        );
        assert_eq!(store.get(&a).unwrap().superseded_by.as_deref(), Some(cid.as_str()));
        assert_eq!(store.get(&b).unwrap().superseded_by.as_deref(), Some(cid.as_str()));
    }

    #[test]
    fn consolidation_and_undo_reject_cross_tenant_ids() {
        let mut store = FactStore::new();
        let (a, b) = seed_two_active(&mut store);
        let err = store
            .consolidate_facts_v1("tenant-b", consolidate_req(&a, &b))
            .expect_err("tenant-b cannot consolidate default facts");
        assert_eq!(err, ConsolidationErrorV1::TargetNotFound(a.clone()));

        let report = store
            .consolidate_facts_v1("default", consolidate_req(&a, &b))
            .expect("default consolidation");
        let err = store
            .consolidate_undo_v1(
                "tenant-b",
                &report.receipt.canonical_fact_id,
                &report.receipt.source_fact_ids,
            )
            .expect_err("tenant-b cannot undo default consolidation");
        assert_eq!(
            err,
            ConsolidationErrorV1::TargetNotFound(report.receipt.canonical_fact_id)
        );
    }

    #[test]
    fn consolidate_undo_is_idempotent() {
        let mut store = FactStore::new();
        let (a, b) = seed_two_active(&mut store);
        let report = store
            .consolidate_facts_v1("default", consolidate_req(&a, &b))
            .expect("consolidate");
        let cid = report.receipt.canonical_fact_id.clone();
        store
            .consolidate_undo_v1("default", &cid, &report.receipt.source_fact_ids)
            .unwrap();
        let again = store
            .consolidate_undo_v1("default", &cid, &report.receipt.source_fact_ids)
            .unwrap();
        assert_eq!(again.status, "already_undone");
        assert!(again.restored_fact_ids.is_empty());
    }

    #[test]
    fn consolidate_undo_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b, cid);
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let (fa, fb) = seed_two_active(&mut store);
            let report = store
                .consolidate_facts_v1("default", consolidate_req(&fa, &fb))
                .expect("consolidate");
            let c = report.receipt.canonical_fact_id.clone();
            store
                .consolidate_undo_v1("default", &c, &report.receipt.source_fact_ids)
                .expect("undo");
            (a, b, cid) = (fa, fb, c);
        }
        let store = FactStore::with_persistence(dir.path()).unwrap();
        assert!(store.get(&cid).is_none(), "undo (canonical retired) survives restart");
        assert!(
            store.get(&a).unwrap().superseded_by.is_none(),
            "restore survives restart"
        );
        assert!(store.get(&b).unwrap().superseded_by.is_none());
    }

    #[test]
    fn consolidation_provenance_survives_compaction_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b, cid, sources);
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let (fa, fb) = seed_two_active(&mut store);
            let report = store
                .consolidate_facts_v1("default", consolidate_req(&fa, &fb))
                .expect("consolidate");
            cid = report.receipt.canonical_fact_id;
            sources = report.receipt.source_fact_ids;
            (a, b) = (fa, fb);
            store.compact_journal().expect("compact");
        }
        let mut reopened = FactStore::with_persistence(dir.path()).unwrap();
        let undo = reopened
            .consolidate_undo_v1("default", &cid, &sources)
            .expect("compacted provenance authorizes exact undo");
        assert_eq!(undo.status, "undone");
        assert!(reopened.get(&cid).is_none());
        assert!(reopened.get(&a).unwrap().superseded_by.is_none());
        assert!(reopened.get(&b).unwrap().superseded_by.is_none());
    }

    #[test]
    fn replay_rejects_colliding_or_partial_consolidation_events_atomically() {
        fn fixed_fact(id: &str, tenant: &str, value: &str) -> Fact {
            let mut store = FactStore::new();
            let mut fact = store.store(StoreFact {
                tenant_hash: tenant.to_string(),
                entity: "proj".to_string(),
                key: "status".to_string(),
                value: value.to_string(),
                source_receipt: None,
                confidence: 0.2,
                private: false,
                horizon_class: None,
                actor: None,
            });
            fact.fact_id = id.to_string();
            fact.version = 1;
            fact.supersedes = None;
            fact.superseded_by = None;
            fact
        }

        let dir = tempfile::tempdir().unwrap();
        let writer = FactStore::with_persistence(dir.path()).unwrap();
        let tenant_a = fixed_fact("f_collision", "tenant-a", "tenant-a");
        let source = fixed_fact("f_source", "tenant-b", "source");
        let mut colliding_canonical = fixed_fact("f_collision", "tenant-b", "canonical");
        colliding_canonical.version = 2;
        colliding_canonical.supersedes = Some(source.fact_id.clone());
        writer
            .append_journal(&JournalEvent::Store { fact: tenant_a.clone() })
            .unwrap();
        writer
            .append_journal(&JournalEvent::Store { fact: source.clone() })
            .unwrap();
        writer
            .append_journal(&JournalEvent::Consolidate {
                canonical: colliding_canonical,
                superseded_fact_ids: vec![source.fact_id.clone()],
                consolidated_at: Utc::now().to_rfc3339(),
            })
            .unwrap();

        let partial_canonical = fixed_fact("f_partial_canonical", "tenant-b", "partial");
        writer
            .append_journal(&JournalEvent::Consolidate {
                canonical: partial_canonical,
                superseded_fact_ids: vec![source.fact_id.clone(), "f_missing".to_string()],
                consolidated_at: Utc::now().to_rfc3339(),
            })
            .unwrap();
        drop(writer);

        let replayed = FactStore::with_persistence(dir.path()).unwrap();
        assert_eq!(replayed.get("f_collision").unwrap().tenant_hash, "tenant-a");
        assert!(replayed.get("f_partial_canonical").is_none());
        assert!(replayed.get(&source.fact_id).unwrap().superseded_by.is_none());
        assert!(
            !replayed.consolidation_sources.contains_key("f_collision")
                && !replayed.consolidation_sources.contains_key("f_partial_canonical")
        );
    }

    #[test]
    fn replay_rejects_partial_consolidation_undo_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b, cid);
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let (fa, fb) = seed_two_active(&mut store);
            let report = store
                .consolidate_facts_v1("default", consolidate_req(&fa, &fb))
                .unwrap();
            cid = report.receipt.canonical_fact_id;
            (a, b) = (fa, fb);
            store
                .append_journal(&JournalEvent::ConsolidateUndo {
                    canonical_fact_id: cid.clone(),
                    restored_fact_ids: vec![a.clone()],
                    undone_at: Utc::now().to_rfc3339(),
                })
                .unwrap();
        }
        let replayed = FactStore::with_persistence(dir.path()).unwrap();
        assert!(replayed.get(&cid).is_some());
        assert_eq!(replayed.get(&a).unwrap().superseded_by.as_deref(), Some(cid.as_str()));
        assert_eq!(replayed.get(&b).unwrap().superseded_by.as_deref(), Some(cid.as_str()));
    }

    #[test]
    fn soft_delete() {
        let mut store = FactStore::new();

        let fact = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "test".to_string(),
            key: "key".to_string(),
            value: "value".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

        assert_eq!(store.count(), 1);
        store.delete("default", &fact.fact_id);
        assert_eq!(store.count(), 0);
        assert!(store.get(&fact.fact_id).is_none());
    }

    #[test]
    fn token_budget_limits_results() {
        let mut store = FactStore::new();

        // Each value is ~10 tokens (40 bytes)
        for i in 0..10 {
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "item".to_string(),
                key: format!("key_{}", i),
                value: format!("this is a value with about forty bytes here-{:02}", i),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }

        let result = store.query(&FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            entity_prefix: None,
            query: None,
            entity: Some("item".to_string()),
            top_k: 100,
            token_budget: Some(25),
        });

        assert!(result.total_tokens <= 25 || result.facts.len() == 1);
    }

    #[test]
    fn get_by_entity_nonexistent() {
        let store = FactStore::new();
        let results = store.get_by_entity("no_such_entity");
        assert!(results.is_empty());
    }

    #[test]
    fn get_by_entity_filters_deleted() {
        let mut store = FactStore::new();

        let f1 = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "proj".to_string(),
            key: "name".to_string(),
            value: "alpha".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "proj".to_string(),
            key: "status".to_string(),
            value: "active".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

        store.delete("default", &f1.fact_id);
        let results = store.get_by_entity("proj");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "status");
    }

    #[test]
    fn store_bulk() {
        let mut store = FactStore::new();

        let reqs = vec![
            StoreFact {
                tenant_hash: "default".to_string(),
                entity: "a".to_string(),
                key: "k1".to_string(),
                value: "v1".to_string(),
                source_receipt: None,
                confidence: 0.5,
                private: false,
                horizon_class: None,
                actor: None,
            },
            StoreFact {
                tenant_hash: "default".to_string(),
                entity: "b".to_string(),
                key: "k2".to_string(),
                value: "v2".to_string(),
                source_receipt: Some("rcpt".to_string()),
                confidence: 0.9,
                private: false,
                horizon_class: None,
                actor: None,
            },
        ];

        let facts = store.store_bulk(reqs);
        assert_eq!(facts.len(), 2);
        assert_eq!(store.count(), 2);
        assert_eq!(facts[0].entity, "a");
        assert_eq!(facts[1].entity, "b");
    }

    #[test]
    fn query_with_entity_filter() {
        let mut store = FactStore::new();

        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "alpha".to_string(),
            key: "info".to_string(),
            value: "shared keyword here".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "beta".to_string(),
            key: "info".to_string(),
            value: "shared keyword here".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

        let result = store.query(&FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            entity_prefix: None,
            query: Some("keyword".to_string()),
            entity: Some("alpha".to_string()),
            top_k: 10,
            token_budget: None,
        });

        assert_eq!(result.facts.len(), 1);
        assert_eq!(result.facts[0].entity, "alpha");
    }

    #[test]
    fn query_no_query_returns_all() {
        let mut store = FactStore::new();

        for i in 0..3 {
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: format!("e{}", i),
                key: "k".to_string(),
                value: format!("val{}", i),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }

        let result = store.query(&FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            entity_prefix: None,
            query: None,
            entity: None,
            top_k: 100,
            token_budget: None,
        });

        assert_eq!(result.facts.len(), 3);
    }

    #[test]
    fn query_tenant_hash_returns_only_matching_tenant() {
        let mut store = FactStore::new();
        let request = |tenant_hash: &str| StoreFact {
            tenant_hash: tenant_hash.to_string(),
            entity: "shared-entity".to_string(),
            key: "shared-key".to_string(),
            value: "shared-value".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };

        store.store(request("tenant-a"));
        store.store(request("tenant-b"));

        let result = store.query(&FactQuery {
            min_effective_confidence: None,
            query: None,
            entity: None,
            tenant_hash: Some("tenant-a".to_string()),
            entity_prefix: None,
            top_k: 10,
            token_budget: None,
        });

        assert_eq!(result.facts.len(), 1);
        assert_eq!(result.facts[0].tenant_hash, "tenant-a");
    }

    #[test]
    fn tenant_filtered_reads_isolate_cross_tenant() {
        let mut store = FactStore::new();
        let request = |tenant_hash: &str, key: &str| StoreFact {
            tenant_hash: tenant_hash.to_string(),
            entity: "shared-entity".to_string(),
            key: key.to_string(),
            value: "shared-value".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };

        let tenant_a = store.store(request("tenant-a", "tenant-a-key"));
        let tenant_b = store.store(request("tenant-b", "tenant-b-key"));

        let entity_facts = store.get_by_entity_for_tenant("shared-entity", "tenant-a");
        assert_eq!(entity_facts.len(), 1);
        assert_eq!(entity_facts[0].fact_id, tenant_a.fact_id);

        let all_facts = store.all_facts_for_tenant("tenant-a").collect::<Vec<_>>();
        assert_eq!(all_facts.len(), 1);
        assert!(all_facts.iter().all(|fact| fact.tenant_hash == "tenant-a"));
        assert!(all_facts.iter().all(|fact| fact.fact_id != tenant_b.fact_id));

        assert!(store.get_for_tenant(&tenant_b.fact_id, "tenant-a").is_none());
    }

    #[test]
    fn query_without_tenant_hash_preserves_single_tenant_result_set() {
        let mut store = FactStore::new();
        for key in ["first", "second"] {
            store.store(StoreFact {
                tenant_hash: default_tenant_hash(),
                entity: "single-tenant".to_string(),
                key: key.to_string(),
                value: "value".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }

        let result = store.query(&FactQuery {
            min_effective_confidence: None,
            query: None,
            entity: None,
            tenant_hash: None,
            entity_prefix: None,
            top_k: 10,
            token_budget: None,
        });

        assert_eq!(result.facts.len(), 2);
        assert!(result.facts.iter().all(|fact| fact.tenant_hash == "default"));
    }

    #[test]
    fn query_empty_store() {
        let store = FactStore::new();

        let result = store.query(&FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            entity_prefix: None,
            query: Some("anything".to_string()),
            entity: None,
            top_k: 10,
            token_budget: None,
        });

        assert!(result.facts.is_empty());
        assert_eq!(result.total_tokens, 0);
    }

    #[test]
    fn delete_nonexistent_returns_false() {
        let mut store = FactStore::new();
        assert!(!store.delete("default", "nonexistent_id"));
    }

    #[test]
    fn count_empty_store() {
        let store = FactStore::new();
        assert_eq!(store.count(), 0);
    }

    // ── buyer-fit M4: deterministic 0-LLM aggregate lane ─────────────────

    #[test]
    fn parse_leading_number_handles_currency_and_trailing_text() {
        assert_eq!(parse_leading_number("$450,000 approved"), Some(450_000.0));
        assert_eq!(parse_leading_number("3 cats"), Some(3.0));
        assert_eq!(parse_leading_number("1,250.50"), Some(1250.5));
        assert_eq!(parse_leading_number("-12.5C"), Some(-12.5));
        assert_eq!(parse_leading_number("north"), None);
    }

    fn seed_aggregate_corpus() -> FactStore {
        // Golden conformance corpus (buyer-fit-m4-aggregate-v1). Fixed content
        // + fixed expected answers — the shared-schema contract a hosted lane
        // must also satisfy.
        let mut store = FactStore::new();
        for (ent, val) in [
            ("metric:jan", "100"),
            ("metric:feb", "150.5"),
            ("metric:mar", "$1,200"),
            ("metric:apr", "100"), // duplicate value → distinct = 3
        ] {
            store.store(StoreFact {
                tenant_hash: "default".into(),
                entity: ent.into(),
                key: "sales_amount".into(),
                value: val.into(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }
        store
    }

    #[test]
    fn aggregate_count_sum_distinct_are_deterministic_and_0_llm() {
        let store = seed_aggregate_corpus();
        let req = |op| AggregateRequestV1 {
            op,
            entity: None,
            key: Some("sales_amount".into()),
            query: None,
            as_of: None,
            token_budget: None,
        };
        let c = store.aggregate_v1("default", &req(AggregateOp::Count));
        assert_eq!(c.value, serde_json::json!(4));
        assert_eq!(c.llm_calls, 0);

        let s = store.aggregate_v1("default", &req(AggregateOp::SumNumeric));
        assert_eq!(s.value, serde_json::json!(1550.5)); // 100 + 150.5 + 1200 + 100
        assert_eq!(s.llm_calls, 0);

        let d = store.aggregate_v1("default", &req(AggregateOp::Distinct));
        assert_eq!(d.value, serde_json::json!(3)); // {100, 150.5, 1200}
    }

    #[test]
    fn tenant_version_chains_history_and_mutations_are_isolated() {
        let mut store = FactStore::new();
        let a1 = store.store(tenant_fact("tenant-a", "project", "status", "draft-a"));
        let b1 = store.store(tenant_fact("tenant-b", "project", "status", "draft-b"));
        let a2 = store.store(tenant_fact("tenant-a", "project", "status", "active-a"));

        assert_eq!((a1.version, b1.version, a2.version), (1, 1, 2));
        assert_eq!(a2.supersedes.as_deref(), Some(a1.fact_id.as_str()));
        assert_eq!(
            store.get(&a1.fact_id).and_then(|fact| fact.superseded_by.as_deref()),
            Some(a2.fact_id.as_str())
        );
        assert!(store.get(&b1.fact_id).unwrap().superseded_by.is_none());

        assert_eq!(store.fact_history("tenant-a", "project", "status").len(), 2);
        assert_eq!(store.fact_history("tenant-b", "project", "status").len(), 1);
        assert!(!store.mark_superseded("tenant-b", &b1.fact_id, &a2.fact_id));
        assert!(!store.clear_superseded("tenant-b", &a1.fact_id));
        assert!(!store.delete("tenant-b", &a1.fact_id));
        assert!(!store.get(&a1.fact_id).unwrap().deleted);

        let latest = dedup_latest(vec![a1, a2, b1]);
        assert_eq!(latest.len(), 2, "dedup must retain one row per tenant");
    }

    #[test]
    fn tenant_aggregate_count_sum_and_distinct_are_isolated() {
        let mut store = FactStore::new();
        for (tenant, entity, value) in [
            ("tenant-a", "metric:a1", "10"),
            ("tenant-a", "metric:a2", "20"),
            ("tenant-a", "metric:a3", "10"),
            ("tenant-b", "metric:b1", "999"),
        ] {
            store.store(tenant_fact(tenant, entity, "amount", value));
        }
        let request = |op| AggregateRequestV1 {
            op,
            entity: None,
            key: Some("amount".to_string()),
            query: None,
            as_of: None,
            token_budget: None,
        };

        assert_eq!(
            store.aggregate_v1("tenant-a", &request(AggregateOp::Count)).value,
            serde_json::json!(3)
        );
        assert_eq!(
            store.aggregate_v1("tenant-a", &request(AggregateOp::SumNumeric)).value,
            serde_json::json!(40.0)
        );
        assert_eq!(
            store.aggregate_v1("tenant-a", &request(AggregateOp::Distinct)).value,
            serde_json::json!(2)
        );
        assert_eq!(
            store.aggregate_v1("tenant-b", &request(AggregateOp::Count)).value,
            serde_json::json!(1)
        );
    }

    #[test]
    fn temporal_diff_walks_only_public_live_structural_tenant_chain() {
        let mut store = FactStore::new();
        store.store(tenant_fact("tenant-a", "metric:price", "usd", "10"));
        store.store(tenant_fact("tenant-a", "metric:price", "usd", "25"));
        store.store(tenant_fact("tenant-b", "metric:price", "usd", "100"));
        store.store(tenant_fact("tenant-b", "metric:price", "usd", "175"));
        let request = AggregateRequestV1 {
            op: AggregateOp::TemporalDiff,
            entity: Some("metric:price".to_string()),
            key: Some("usd".to_string()),
            query: None,
            as_of: None,
            token_budget: None,
        };

        assert_eq!(store.aggregate_v1("tenant-a", &request).value, serde_json::json!(15.0));
        assert_eq!(store.aggregate_v1("tenant-b", &request).value, serde_json::json!(75.0));

        let private_head = store.store(StoreFact {
            private: true,
            ..tenant_fact("tenant-a", "metric:price", "usd", "1000")
        });
        assert!(private_head.private);
        assert_eq!(
            store.aggregate_v1("tenant-a", &request).value,
            serde_json::Value::Null,
            "a private current endpoint must not reveal its public predecessor"
        );
    }

    #[test]
    fn restart_rebuilds_partitioned_chains_and_sanitizes_cross_tenant_links() {
        let dir = tempfile::tempdir().unwrap();
        let (a1_id, a2_id, b1_id, crafted_id) = {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let a1 = store.store(tenant_fact("tenant-a", "project", "status", "a1"));
            let b1 = store.store(tenant_fact("tenant-b", "project", "status", "b1"));
            let a2 = store.store(tenant_fact("tenant-a", "project", "status", "a2"));

            store
                .append_journal(&JournalEvent::Supersede {
                    fact_id: a1.fact_id.clone(),
                    by_fact_id: b1.fact_id.clone(),
                    superseded_at: Utc::now().to_rfc3339(),
                })
                .unwrap();

            let mut crafted = b1.clone();
            crafted.fact_id = "f_cross_tenant_legacy_link".to_string();
            crafted.version = 9;
            crafted.supersedes = Some(a1.fact_id.clone());
            crafted.superseded_by = Some(a2.fact_id.clone());
            assert!(store.store_synced(crafted.clone()));
            assert!(
                store.get(&crafted.fact_id).unwrap().supersedes.is_none(),
                "synced cross-tenant predecessor must be cleared immediately"
            );
            assert!(
                store.get(&crafted.fact_id).unwrap().superseded_by.is_none(),
                "synced cross-tenant successor must be cleared immediately"
            );

            (a1.fact_id, a2.fact_id, b1.fact_id, crafted.fact_id)
        };

        let store = FactStore::with_persistence(dir.path()).unwrap();
        let a_history = store.fact_history("tenant-a", "project", "status");
        let b_history = store.fact_history("tenant-b", "project", "status");
        assert_eq!(
            a_history.iter().map(|fact| fact.version).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(
            b_history.iter().map(|fact| fact.version).collect::<Vec<_>>(),
            vec![1, 9],
            "persisted versions are preserved, not renumbered"
        );
        assert_eq!(
            store.get(&a1_id).unwrap().superseded_by.as_deref(),
            Some(a2_id.as_str()),
            "malicious later cross-tenant event must not replace the valid edge"
        );
        assert!(store.get(&b1_id).unwrap().superseded_by.is_none());
        assert!(
            store.get(&crafted_id).unwrap().supersedes.is_none(),
            "legacy cross-tenant predecessor edge must be sanitized"
        );
    }

    #[test]
    fn synced_fact_id_collision_cannot_overwrite_another_tenant() {
        let mut store = FactStore::new();
        let original = store.store(tenant_fact("tenant-a", "project", "status", "a"));
        let mut collision = original.clone();
        collision.tenant_hash = "tenant-b".to_string();
        collision.value = "attacker".to_string();

        assert!(!store.store_synced(collision));
        assert_eq!(store.get(&original.fact_id).unwrap().tenant_hash, "tenant-a");
        assert_eq!(store.get(&original.fact_id).unwrap().value, "a");
    }

    #[test]
    fn aggregate_respects_token_budget() {
        let store = seed_aggregate_corpus();
        // A tiny budget scans only the first candidate(s); the count is bounded
        // and the result is flagged truncated (honest, bounded cost).
        let r = store.aggregate_v1(
            "default",
            &AggregateRequestV1 {
                op: AggregateOp::Count,
                entity: None,
                key: Some("sales_amount".into()),
                query: None,
                as_of: None,
                token_budget: Some(1),
            },
        );
        assert!(r.budget_truncated, "tiny budget must truncate the scan");
        assert!(r.matched < 4, "budget-limited count is below the full 4");
        assert!(r.tokens_scanned <= 1 + store.get_by_entity("metric:jan").first().map(|f| f.tokens).unwrap_or(0));
    }

    #[test]
    fn aggregate_temporal_diff_uses_version_history() {
        let mut store = FactStore::new();
        let base = |v: &str| StoreFact {
            tenant_hash: "default".into(),
            entity: "metric:price".into(),
            key: "usd".into(),
            value: v.into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        };
        store.store(base("10"));
        store.store(base("25")); // v2 supersedes v1 in the chain; both in history
        let r = store.aggregate_v1(
            "default",
            &AggregateRequestV1 {
                op: AggregateOp::TemporalDiff,
                entity: Some("metric:price".into()),
                key: Some("usd".into()),
                query: None,
                as_of: None, // diff current vs oldest
                token_budget: None,
            },
        );
        assert_eq!(r.value, serde_json::json!(15.0)); // 25 - 10
    }

    #[test]
    fn query_matches_key_and_entity() {
        let mut store = FactStore::new();

        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "server".to_string(),
            key: "deployment_strategy".to_string(),
            value: "unrelated text".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

        // Query matching key name
        let result = store.query(&FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            entity_prefix: None,
            query: Some("deployment".to_string()),
            entity: None,
            top_k: 10,
            token_budget: None,
        });
        assert_eq!(result.facts.len(), 1);

        // Query matching entity name
        let result = store.query(&FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            entity_prefix: None,
            query: Some("server".to_string()),
            entity: None,
            top_k: 10,
            token_budget: None,
        });
        assert_eq!(result.facts.len(), 1);
    }

    #[test]
    fn query_no_match() {
        let mut store = FactStore::new();

        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "alpha".to_string(),
            key: "info".to_string(),
            value: "some value".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

        let result = store.query(&FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            entity_prefix: None,
            query: Some("zzz_nonexistent_zzz".to_string()),
            entity: None,
            top_k: 10,
            token_budget: None,
        });
        assert!(result.facts.is_empty());
    }

    #[test]
    fn query_sorts_by_confidence_then_time() {
        let mut store = FactStore::new();

        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "e".to_string(),
            key: "k".to_string(),
            value: "match low".to_string(),
            source_receipt: None,
            confidence: 0.5,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "e".to_string(),
            key: "k".to_string(),
            value: "match high".to_string(),
            source_receipt: None,
            confidence: 0.9,
            private: false,
            horizon_class: None,
            actor: None,
        });

        let result = store.query(&FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            entity_prefix: None,
            query: Some("match".to_string()),
            entity: None,
            top_k: 10,
            token_budget: None,
        });

        assert_eq!(result.facts.len(), 2);
        assert!(result.facts[0].confidence >= result.facts[1].confidence);
    }

    #[test]
    fn top_k_limits_results() {
        let mut store = FactStore::new();

        for i in 0..5 {
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "e".to_string(),
                key: format!("k{}", i),
                value: format!("shared term {}", i),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }

        let result = store.query(&FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            entity_prefix: None,
            query: Some("shared".to_string()),
            entity: None,
            top_k: 2,
            token_budget: None,
        });

        assert_eq!(result.facts.len(), 2);
    }

    #[test]
    fn token_budget_includes_first_even_if_over() {
        let mut store = FactStore::new();

        // Store one fact with a large value (many tokens)
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "e".to_string(),
            key: "k".to_string(),
            value: "a".repeat(100), // 25 tokens
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

        // Token budget smaller than the single fact — should still include it
        let result = store.query(&FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            entity_prefix: None,
            query: None,
            entity: None,
            top_k: 100,
            token_budget: Some(1),
        });

        assert_eq!(result.facts.len(), 1);
    }

    #[test]
    fn default_confidence_via_serde() {
        let json = r#"{"entity":"e","key":"k","value":"v"}"#;
        let sf: StoreFact = serde_json::from_str(json).unwrap();
        assert_eq!(sf.confidence, 1.0);
    }

    #[test]
    fn default_top_k_via_serde() {
        let json = r"{}";
        let fq: FactQuery = serde_json::from_str(json).unwrap();
        assert_eq!(fq.top_k, 10);
        assert!(fq.query.is_none());
        assert!(fq.entity.is_none());
        assert!(fq.token_budget.is_none());
    }

    #[test]
    fn fact_serde_roundtrip() {
        let mut store = FactStore::new();
        let fact = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "e".to_string(),
            key: "k".to_string(),
            value: "v".to_string(),
            source_receipt: Some("r".to_string()),
            confidence: 0.75,
            private: false,
            horizon_class: None,
            actor: None,
        });

        let json = serde_json::to_string(&fact).unwrap();
        let deserialized: Fact = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.fact_id, fact.fact_id);
        assert_eq!(deserialized.confidence, 0.75);
        assert!(!deserialized.deleted);
    }

    #[test]
    fn estimate_tokens_fn() {
        assert_eq!(estimate_tokens(""), 0); // (0+3)/4 = 0
        assert_eq!(estimate_tokens("a"), 1); // (1+3)/4 = 1
        assert_eq!(estimate_tokens("abcd"), 1); // (4+3)/4 = 1
        assert_eq!(estimate_tokens("abcde"), 2); // (5+3)/4 = 2
    }

    // ── Persistence tests ─────────────────────────────────────────

    #[test]
    fn test_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let ids: Vec<String>;

        // Store 3 facts, then drop the store.
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let f1 = store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "proj".into(),
                key: "name".into(),
                value: "alpha".into(),
                source_receipt: None,
                confidence: 0.9,
                private: false,
                horizon_class: None,
                actor: None,
            });
            let f2 = store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "proj".into(),
                key: "status".into(),
                value: "active".into(),
                source_receipt: Some("r1".into()),
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
            let f3 = store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "other".into(),
                key: "info".into(),
                value: "details".into(),
                source_receipt: None,
                confidence: 0.5,
                private: false,
                horizon_class: None,
                actor: None,
            });
            ids = vec![f1.fact_id, f2.fact_id, f3.fact_id];
            assert_eq!(store.count(), 3);
        }

        // Rebuild from the same directory.
        {
            let store = FactStore::with_persistence(dir.path()).unwrap();
            assert_eq!(store.count(), 3);
            for id in &ids {
                assert!(store.get(id).is_some(), "fact {} should exist after replay", id);
            }
            let fact = store.get(&ids[0]).unwrap();
            assert_eq!(fact.entity, "proj");
            assert_eq!(fact.key, "name");
            assert_eq!(fact.value, "alpha");
        }
    }

    #[test]
    fn test_persistence_delete_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let fact_id: String;

        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let fact = store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "e".into(),
                key: "k".into(),
                value: "v".into(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
            fact_id = fact.fact_id;
            store.delete("default", &fact_id);
            assert_eq!(store.count(), 0);
        }

        {
            let store = FactStore::with_persistence(dir.path()).unwrap();
            assert_eq!(store.count(), 0);
            assert!(store.get(&fact_id).is_none());
            // The fact should exist in the map but be deleted.
            assert!(store.facts.get(&fact_id).is_some());
            assert!(store.facts.get(&fact_id).unwrap().deleted);
        }
    }

    #[test]
    fn test_compaction_removes_deleted_value_keeps_live() {
        // Launch-gate 5.1: after compaction (a) the deleted fact's value is gone
        // from the on-disk journal, (b) replay still excludes it, (c) non-deleted
        // facts survive intact with correct values and versions.
        let dir = tempfile::tempdir().unwrap();
        let journal = dir.path().join("facts.jsonl");
        let deleted_id: String;
        let live_id: String;

        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let to_delete = store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "e".into(),
                key: "erase-me".into(),
                value: "highly-sensitive-erased-value".into(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
            let to_keep = store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "e".into(),
                key: "keep-me".into(),
                value: "surviving-value".into(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
            deleted_id = to_delete.fact_id;
            live_id = to_keep.fact_id;
            store.delete("default", &deleted_id);

            // Pre-compaction: the deleted value IS still on disk (the leak).
            let raw = std::fs::read_to_string(&journal).unwrap();
            assert!(raw.contains("highly-sensitive-erased-value"));

            let report = store.compact_journal().unwrap();
            assert_eq!(report.facts_dropped, 1);
            assert_eq!(report.facts_retained, 1);
            assert_eq!(report.tombstones_kept, 1);
        }

        // (a) Deleted value is gone from the journal; live value survives.
        let raw = std::fs::read_to_string(&journal).unwrap();
        assert!(
            !raw.contains("highly-sensitive-erased-value"),
            "deleted fact value still present in compacted journal"
        );
        assert!(raw.contains("surviving-value"));

        // (b)+(c) Replay still excludes the deleted fact and preserves the live one.
        {
            let store = FactStore::with_persistence(dir.path()).unwrap();
            assert_eq!(store.count(), 1);
            assert!(store.get(&deleted_id).is_none());
            // Tombstone preserved: the deleted fact_id is still known + flagged.
            assert!(store.facts.get(&deleted_id).map(|f| f.deleted).unwrap_or(true));
            let live = store.get(&live_id).expect("live fact survived replay");
            assert_eq!(live.value, "surviving-value");
            assert_eq!(live.version, 1);
        }
    }

    #[test]
    fn test_compaction_preserves_version_chain() {
        // A re-stored (entity, key) leaves the prior version live-but-superseded;
        // compaction must retain BOTH the current value and the version chain.
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "proj".into(),
                key: "status".into(),
                value: "v1".into(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "proj".into(),
                key: "status".into(),
                value: "v2".into(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
            store.compact_journal().unwrap();
        }
        {
            let store = FactStore::with_persistence(dir.path()).unwrap();
            let history = store.fact_history("default", "proj", "status");
            assert_eq!(history.len(), 2, "version chain lost after compaction");
            assert_eq!(history[0].version, 1);
            assert_eq!(history[1].version, 2);
            // Latest-wins recall returns the current value.
            let latest = store
                .get_by_entity("proj")
                .into_iter()
                .max_by_key(|f| f.version)
                .unwrap();
            assert_eq!(latest.value, "v2");
        }
    }

    #[test]
    fn test_retention_marks_old_facts() {
        // W2.E2: facts older than the cutoff are marked deletion-eligible; a
        // following compaction removes their content. Fresh facts survive.
        let mut store = FactStore::new();
        let mut old = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "e".into(),
            key: "old".into(),
            value: "old-value".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let control = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "__passport__::legacy".into(),
            key: "record".into(),
            value: "{}".into(),
            source_receipt: None,
            confidence: 0.1,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "e".into(),
            key: "new".into(),
            value: "new-value".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        // Backdate the first fact well past the cutoff.
        old.stored_at = Utc::now() - chrono::Duration::days(120);
        store.facts.get_mut(&old.fact_id).unwrap().stored_at = old.stored_at;
        let legacy = store.facts.get_mut(&control.fact_id).unwrap();
        legacy.stored_at = old.stored_at;
        legacy.private = false;

        let cutoff = Utc::now() - chrono::Duration::days(90);
        let marked = store.mark_retention_eligible(cutoff);
        assert_eq!(marked, vec![old.fact_id.clone()]);
        assert!(store.get(&old.fact_id).is_none());
        assert!(store.get(&control.fact_id).is_some());
        assert_eq!(store.count(), 2); // fresh fact + protected legacy control
    }

    #[test]
    fn test_persistence_versioning() {
        let dir = tempfile::tempdir().unwrap();

        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let v1 = store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "proj".into(),
                key: "status".into(),
                value: "draft".into(),
                source_receipt: None,
                confidence: 0.8,
                private: false,
                horizon_class: None,
                actor: None,
            });
            let v2 = store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "proj".into(),
                key: "status".into(),
                value: "active".into(),
                source_receipt: None,
                confidence: 0.9,
                private: false,
                horizon_class: None,
                actor: None,
            });
            assert_eq!(v1.version, 1);
            assert_eq!(v2.version, 2);
            assert_eq!(v2.supersedes, Some(v1.fact_id.clone()));
        }

        {
            let store = FactStore::with_persistence(dir.path()).unwrap();
            let history = store.fact_history("default", "proj", "status");
            assert_eq!(history.len(), 2);
            assert_eq!(history[0].version, 1);
            assert_eq!(history[0].value, "draft");
            assert_eq!(history[1].version, 2);
            assert_eq!(history[1].value, "active");
            assert_eq!(history[1].supersedes, Some(history[0].fact_id.clone()));
        }
    }

    #[test]
    fn try_store_bulk_persists_as_one_replayable_batch() {
        let dir = tempfile::tempdir().unwrap();

        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let facts = store
                .try_store_bulk(vec![
                    StoreFact {
                        tenant_hash: "default".to_string(),
                        entity: "a".into(),
                        key: "k1".into(),
                        value: "v1".into(),
                        source_receipt: None,
                        confidence: 1.0,
                        private: false,
                        horizon_class: None,
                        actor: None,
                    },
                    StoreFact {
                        tenant_hash: "default".to_string(),
                        entity: "b".into(),
                        key: "k2".into(),
                        value: "v2".into(),
                        source_receipt: None,
                        confidence: 1.0,
                        private: false,
                        horizon_class: None,
                        actor: None,
                    },
                ])
                .unwrap();
            assert_eq!(facts.len(), 2);
            assert_eq!(store.count(), 2);
        }

        {
            let store = FactStore::with_persistence(dir.path()).unwrap();
            assert_eq!(store.count(), 2);
            assert_eq!(store.get_by_entity("a").len(), 1);
            assert_eq!(store.get_by_entity("b").len(), 1);
        }
    }

    #[test]
    fn try_store_bulk_durable_persists_as_one_replayable_batch() {
        let dir = tempfile::tempdir().unwrap();
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let facts = store
                .try_store_bulk_durable(vec![
                    StoreFact {
                        tenant_hash: "default".to_string(),
                        entity: "authority::passport".into(),
                        key: "record".into(),
                        value: "passport".into(),
                        source_receipt: Some("ad_mr_test".into()),
                        confidence: 1.0,
                        private: true,
                        horizon_class: Some(HorizonClass::None),
                        actor: Some("reviewer".into()),
                    },
                    StoreFact {
                        tenant_hash: "default".to_string(),
                        entity: "authority::request".into(),
                        key: "record".into(),
                        value: "approved".into(),
                        source_receipt: Some("ad_mr_test".into()),
                        confidence: 1.0,
                        private: true,
                        horizon_class: Some(HorizonClass::None),
                        actor: Some("reviewer".into()),
                    },
                ])
                .unwrap();
            assert_eq!(facts.len(), 2);
            assert_eq!(store.count(), 2);
        }

        let journal = std::fs::read_to_string(dir.path().join("facts.jsonl")).unwrap();
        assert_eq!(journal.lines().count(), 1);
        assert!(journal.contains("store_batch"));
        let replayed = FactStore::with_persistence(dir.path()).unwrap();
        assert_eq!(replayed.count(), 2);
    }

    #[test]
    fn durable_batch_quarantines_torn_unterminated_tail_before_append() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("facts.jsonl");
        let mut store = FactStore::with_persistence(dir.path()).unwrap();
        store
            .try_store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "before".into(),
                key: "record".into(),
                value: "before".into(),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: Some(HorizonClass::None),
                actor: None,
            })
            .unwrap();
        {
            let mut journal = std::fs::OpenOptions::new().append(true).open(&journal_path).unwrap();
            journal.write_all(br#"{"event":"store_batch""#).unwrap();
            journal.sync_all().unwrap();
        }

        store
            .try_store_bulk_durable(vec![StoreFact {
                tenant_hash: "default".to_string(),
                entity: "after".into(),
                key: "record".into(),
                value: "after".into(),
                source_receipt: Some("ad_mr_tail".into()),
                confidence: 1.0,
                private: true,
                horizon_class: Some(HorizonClass::None),
                actor: Some("reviewer".into()),
            }])
            .unwrap();

        let replayed = FactStore::with_persistence(dir.path()).unwrap();
        assert_eq!(replayed.count(), 2);
        assert_eq!(replayed.get_by_entity("before").len(), 1);
        assert_eq!(replayed.get_by_entity("after").len(), 1);
        let quarantines = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains("jsonl.torn."))
            .count();
        assert_eq!(quarantines, 1);
    }

    #[test]
    fn startup_quarantines_parseable_unterminated_tail_before_replay() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("facts.jsonl");
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            store
                .try_store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: "committed".into(),
                    key: "record".into(),
                    value: "committed".into(),
                    source_receipt: None,
                    confidence: 1.0,
                    private: true,
                    horizon_class: Some(HorizonClass::None),
                    actor: None,
                })
                .unwrap();
        }
        let tail_fact = FactStore::new()
            .try_store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "__repo_registry__::tenant::uncommitted".into(),
                key: "content".into(),
                value: "parseable but not newline-committed".into(),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: Some(HorizonClass::None),
                actor: None,
            })
            .unwrap();
        let tail = serde_json::to_vec(&JournalEvent::Store { fact: tail_fact }).unwrap();
        {
            let mut journal = std::fs::OpenOptions::new().append(true).open(&journal_path).unwrap();
            journal.write_all(&tail).unwrap();
            journal.sync_all().unwrap();
        }

        let replayed = FactStore::with_persistence(dir.path()).unwrap();
        assert_eq!(replayed.get_by_entity("committed").len(), 1);
        assert!(replayed
            .get_by_entity("__repo_registry__::tenant::uncommitted")
            .is_empty());
        let quarantined_tail = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| entry.file_name().to_string_lossy().contains("jsonl.torn."))
            .map(|entry| std::fs::read(entry.path()).unwrap())
            .expect("quarantined tail");
        assert_eq!(quarantined_tail, tail);
    }

    #[test]
    fn startup_truncates_oversized_legacy_workspace_torn_tail_with_bounded_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("facts.jsonl");
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            store
                .try_store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: "committed-before-workspace-tail".into(),
                    key: "record".into(),
                    value: "committed".into(),
                    source_receipt: None,
                    confidence: 1.0,
                    private: true,
                    horizon_class: Some(HorizonClass::None),
                    actor: None,
                })
                .unwrap();
        }
        let committed_len = std::fs::metadata(&journal_path).unwrap().len();
        let tail_fact = FactStore::new()
            .try_store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "__workspace_scan__::latest".into(),
                key: "content".into(),
                value: "x".repeat(2048),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: Some(HorizonClass::None),
                actor: None,
            })
            .unwrap();
        let tail = serde_json::to_vec(&JournalEvent::Store { fact: tail_fact }).unwrap();
        assert!(tail.len() > 512);
        {
            let mut journal = std::fs::OpenOptions::new().append(true).open(&journal_path).unwrap();
            journal.write_all(&tail).unwrap();
            journal.sync_all().unwrap();
        }

        repair_torn_journal_tail_with_limit(&journal_path, 512).unwrap();

        assert_eq!(std::fs::metadata(&journal_path).unwrap().len(), committed_len);
        let marker_path = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| {
                path.to_string_lossy().contains("jsonl.torn.") && path.extension().is_some_and(|v| v == "json")
            })
            .expect("bounded torn-tail metadata");
        let marker: serde_json::Value =
            serde_json::from_slice(&std::fs::read(marker_path).unwrap()).expect("decode metadata");
        assert_eq!(marker["tail_start"], committed_len);
        assert_eq!(marker["tail_len"], tail.len() as u64);
        assert_eq!(marker["capture_limit_bytes"], 512);
        assert_eq!(marker["reason"], "oversized_unterminated_uncommitted_record");

        let replayed = FactStore::with_persistence(dir.path()).unwrap();
        assert_eq!(replayed.get_by_entity("committed-before-workspace-tail").len(), 1);
        assert!(replayed.get_by_entity("__workspace_scan__::latest").is_empty());
    }

    #[test]
    fn test_in_memory_mode_no_file() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("facts.jsonl");

        let mut store = FactStore::new();
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "e".into(),
            key: "k".into(),
            value: "v".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.delete("default", "nonexistent");

        assert!(!journal_path.exists(), "in-memory mode should not create journal files");
    }

    // ── Export tests ─────────────────────────────────────────────────

    #[test]
    fn test_export_basic() {
        let mut store = FactStore::new();
        for i in 0..5 {
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: format!("e{i}"),
                key: "k".into(),
                value: format!("v{i}"),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }

        let result = store.export(None, None, 100);
        assert_eq!(result.facts.len(), 5);
        assert!(!result.has_more);
        assert!(result.next_cursor.is_none());

        // Verify ascending stored_at order
        for w in result.facts.windows(2) {
            assert!(w[0].stored_at <= w[1].stored_at);
        }
    }

    #[test]
    fn test_export_with_cursor() {
        let mut store = FactStore::new();
        for i in 0..5 {
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: format!("e{i}"),
                key: "k".into(),
                value: format!("v{i}"),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }

        // First page: get 2
        let page1 = store.export(None, None, 2);
        assert_eq!(page1.facts.len(), 2);
        assert!(page1.has_more);
        assert!(page1.next_cursor.is_some());

        // Second page: use cursor from first page
        let page2 = store.export(None, page1.next_cursor.as_deref(), 2);
        assert_eq!(page2.facts.len(), 2);
        assert!(page2.has_more);

        // Third page: remaining 1
        let page3 = store.export(None, page2.next_cursor.as_deref(), 2);
        assert_eq!(page3.facts.len(), 1);
        assert!(!page3.has_more);
        assert!(page3.next_cursor.is_none());

        // Verify no duplicates across pages
        let all_ids: Vec<String> = page1
            .facts
            .iter()
            .chain(page2.facts.iter())
            .chain(page3.facts.iter())
            .map(|f| f.fact_id.clone())
            .collect();
        assert_eq!(all_ids.len(), 5);
        let deduped: std::collections::HashSet<_> = all_ids.iter().collect();
        assert_eq!(deduped.len(), 5);
    }

    #[test]
    fn tenant_export_filters_before_cursor_and_limit() {
        let mut store = FactStore::new();
        store.store(tenant_fact("tenant-b", "b1", "k", "foreign-first"));
        let a1 = store.store(tenant_fact("tenant-a", "a1", "k", "a-first"));
        store.store(tenant_fact("tenant-b", "b2", "k", "foreign-middle"));
        let a2 = store.store(tenant_fact("tenant-a", "a2", "k", "a-second"));

        let page1 = store.export_for_tenant("tenant-a", None, None, 1);
        assert_eq!(
            page1.facts.iter().map(|fact| &fact.fact_id).collect::<Vec<_>>(),
            vec![&a1.fact_id]
        );
        assert!(page1.has_more);
        assert_eq!(page1.next_cursor.as_deref(), Some(a1.fact_id.as_str()));

        let page2 = store.export_for_tenant("tenant-a", None, page1.next_cursor.as_deref(), 1);
        assert_eq!(
            page2.facts.iter().map(|fact| &fact.fact_id).collect::<Vec<_>>(),
            vec![&a2.fact_id]
        );
        assert!(!page2.has_more);
        assert!(page2.next_cursor.is_none());
    }

    #[test]
    fn test_export_with_since() {
        let mut store = FactStore::new();

        // Store 2 facts, capture a timestamp, then store 3 more
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "e0".into(),
            key: "k".into(),
            value: "v0".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "e1".into(),
            key: "k".into(),
            value: "v1".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

        // All facts stored with Utc::now() so they share the same timestamp
        // (sub-millisecond). To test since filtering properly, we modify
        // stored_at on the first two facts to be in the past.
        let past = Utc::now() - chrono::Duration::hours(1);
        let all_ids: Vec<String> = store.all_facts().map(|f| f.fact_id.clone()).collect();
        for id in &all_ids {
            if let Some(f) = store.facts.get_mut(id) {
                f.stored_at = past;
            }
        }

        let cutoff = Utc::now() - chrono::Duration::minutes(30);

        // Store 3 more (these will have stored_at = now)
        for i in 2..5 {
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: format!("e{i}"),
                key: "k".into(),
                value: format!("v{i}"),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }

        let result = store.export(Some(cutoff), None, 100);
        assert_eq!(result.facts.len(), 3);
        for f in &result.facts {
            assert!(f.stored_at >= cutoff);
        }
    }

    #[test]
    fn test_export_excludes_deleted_facts() {
        // ERASURE (launch-gate 5.1): a soft-deleted fact — and crucially its
        // plaintext value — must NOT appear in the sync export. Including a
        // deleted fact's content in the push path lets erased data leave the
        // box, which is a GDPR erasure failure.
        let mut store = FactStore::new();

        let f1 = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "e".into(),
            key: "k1".into(),
            value: "secret-pii-value".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let f2 = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "e".into(),
            key: "k2".into(),
            value: "v2".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

        store.delete("default", &f1.fact_id);

        let result = store.export(None, None, 100);

        // Only the live fact is exported; the tombstoned fact is absent.
        assert_eq!(result.facts.len(), 1);
        assert_eq!(result.facts[0].fact_id, f2.fact_id);
        assert!(result.facts.iter().all(|f| f.fact_id != f1.fact_id));

        // The deleted value never appears anywhere in the serialised export.
        let serialised = serde_json::to_string(&result.facts).unwrap();
        assert!(
            !serialised.contains("secret-pii-value"),
            "deleted fact value leaked into export output"
        );
    }

    // ── M6: cross-entity supersession ───────────────────────────────

    #[test]
    fn mark_and_clear_superseded_in_memory() {
        let mut store = FactStore::new();
        let old = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "bench:lme-s".into(),
            key: "baseline".into(),
            value: "86.8%".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let new = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "bench:lme-s-v2".into(),
            key: "baseline".into(),
            value: "90.0%".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

        assert!(store.get(&old.fact_id).unwrap().superseded_by.is_none());
        // mark
        assert!(store.mark_superseded("default", &old.fact_id, &new.fact_id));
        assert_eq!(
            store.get(&old.fact_id).unwrap().superseded_by.as_deref(),
            Some(new.fact_id.as_str())
        );
        // clear (reversible)
        assert!(store.clear_superseded("default", &old.fact_id));
        assert!(store.get(&old.fact_id).unwrap().superseded_by.is_none());

        // nonexistent target -> false, no panic.
        assert!(!store.mark_superseded("default", "f_nope", &new.fact_id));
        assert!(!store.clear_superseded("default", "f_nope"));
    }

    #[test]
    fn mark_superseded_persists_across_replay() {
        let dir = tempfile::tempdir().unwrap();
        let (old_id, new_id): (String, String);
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let old = store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "execplan:a".into(),
                key: "decision".into(),
                value: "do X".into(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
            let new = store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "execplan:b".into(),
                key: "decision".into(),
                value: "do Y instead".into(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
            assert!(store.mark_superseded("default", &old.fact_id, &new.fact_id));
            let mut sync_trigger = new.clone();
            sync_trigger.fact_id = "f_cross_entity_sync_sanitizer_trigger".to_string();
            sync_trigger.entity = "sync-trigger".to_string();
            sync_trigger.key = "k".to_string();
            sync_trigger.version = 1;
            sync_trigger.supersedes = None;
            sync_trigger.superseded_by = None;
            assert!(store.store_synced(sync_trigger));
            assert_eq!(
                store.get(&old.fact_id).unwrap().superseded_by.as_deref(),
                Some(new.fact_id.as_str()),
                "sync sanitization must preserve valid same-tenant cross-entity retirement"
            );
            old_id = old.fact_id;
            new_id = new.fact_id;
        }
        // Replay: the supersession marker survives the restart.
        {
            let store = FactStore::with_persistence(dir.path()).unwrap();
            assert_eq!(
                store.get(&old_id).unwrap().superseded_by.as_deref(),
                Some(new_id.as_str()),
                "supersede marker must survive journal replay"
            );
        }
    }

    #[test]
    fn clear_superseded_persists_across_replay() {
        let dir = tempfile::tempdir().unwrap();
        let old_id: String;
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let old = store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "e".into(),
                key: "k".into(),
                value: "v".into(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
            let new = store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "e2".into(),
                key: "k".into(),
                value: "v2".into(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
            store.mark_superseded("default", &old.fact_id, &new.fact_id);
            // Now reverse it; the clear must also persist (not just the mark).
            assert!(store.clear_superseded("default", &old.fact_id));
            old_id = old.fact_id;
        }
        {
            let store = FactStore::with_persistence(dir.path()).unwrap();
            assert!(
                store.get(&old_id).unwrap().superseded_by.is_none(),
                "clear must survive replay (mark then clear -> None)"
            );
        }
    }

    // ── latest-version-wins recall (probe finding 1) ─────────────────

    #[test]
    fn store_same_key_auto_supersedes_prior_version_in_recall() {
        let mut store = FactStore::new();
        let v1 = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "person:carol".into(),
            key: "city".into(),
            value: "Berlin".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        // Re-store the SAME (entity,key): a plain value update (the path
        // memory_edit and any re-store take). The prior version must be
        // retired in the recall plane so query returns latest-wins.
        let v2 = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "person:carol".into(),
            key: "city".into(),
            value: "Munich".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });

        assert_eq!(v2.version, 2);
        assert_eq!(v2.supersedes.as_deref(), Some(v1.fact_id.as_str()));
        assert_eq!(
            store.get(&v1.fact_id).unwrap().superseded_by.as_deref(),
            Some(v2.fact_id.as_str()),
            "prior version must be auto-marked superseded_by the new version"
        );
        assert!(
            store.get(&v2.fact_id).unwrap().superseded_by.is_none(),
            "the new (latest) version is never superseded"
        );
    }

    #[test]
    fn distinct_keys_are_not_auto_superseded() {
        let mut store = FactStore::new();
        let a = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "person:carol".into(),
            key: "city".into(),
            value: "Berlin".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let b = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "person:carol".into(),
            key: "role".into(),
            value: "PM".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        assert!(store.get(&a.fact_id).unwrap().superseded_by.is_none());
        assert!(store.get(&b.fact_id).unwrap().superseded_by.is_none());
        assert_eq!(a.version, 1);
        assert_eq!(b.version, 1);
    }

    #[test]
    fn auto_supersede_survives_replay() {
        let dir = tempfile::tempdir().unwrap();
        let (v1_id, v2_id): (String, String);
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let v1 = store
                .try_store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: "test-fixture-x".into(),
                    key: "baseline".into(),
                    value: "86.8%".into(),
                    source_receipt: None,
                    confidence: 1.0,
                    private: false,
                    horizon_class: None,
                    actor: None,
                })
                .unwrap();
            let v2 = store
                .try_store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: "test-fixture-x".into(),
                    key: "baseline".into(),
                    value: "89.3%".into(),
                    source_receipt: None,
                    confidence: 1.0,
                    private: false,
                    horizon_class: None,
                    actor: None,
                })
                .unwrap();
            v1_id = v1.fact_id;
            v2_id = v2.fact_id;
        }
        // The auto-supersession (a journaled `Supersede` event) survives restart.
        let store = FactStore::with_persistence(dir.path()).unwrap();
        assert_eq!(
            store.get(&v1_id).unwrap().superseded_by.as_deref(),
            Some(v2_id.as_str()),
            "auto-supersede marker must survive journal replay"
        );
        assert!(store.get(&v2_id).unwrap().superseded_by.is_none());
    }

    #[test]
    fn latest_only_replacement_removes_resident_history_and_survives_replay() {
        let dir = tempfile::tempdir().unwrap();
        let first_id;
        let latest_id;
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let request = |value: &str| StoreFact {
                tenant_hash: "default".to_string(),
                entity: "__repo_registry__::fixture::one".into(),
                key: "content".into(),
                value: value.to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: None,
            };
            let first = store.try_replace_latest_daemon_control(request("first")).unwrap();
            let latest = store.try_replace_latest_daemon_control(request("latest")).unwrap();
            first_id = first.fact_id;
            latest_id = latest.fact_id;
            assert!(store.get(&first_id).is_none());
            assert_eq!(store.get_by_entity("__repo_registry__::fixture::one").len(), 1);
            assert_eq!(store.get(&latest_id).unwrap().value, "latest");
        }
        let store = FactStore::with_persistence(dir.path()).unwrap();
        assert!(store.get(&first_id).is_none());
        assert_eq!(store.get_by_entity("__repo_registry__::fixture::one").len(), 1);
        assert_eq!(store.get(&latest_id).unwrap().value, "latest");
    }

    #[test]
    fn latest_only_replacement_churn_is_backpressured_until_explicit_compaction() {
        let dir = tempfile::tempdir().unwrap();
        let entity = "__workspace_scan__::latest";
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            store
                .place_legal_hold(crate::legal_hold::PlaceLegalHold {
                    tenant_id: "unrelated-tenant".to_string(),
                    entity_prefixes: vec!["unrelated::evidence".to_string()],
                    reason: "must not disable exact compaction elsewhere".to_string(),
                    actor: Some("fixture".to_string()),
                })
                .unwrap();
            for version in 0..=LATEST_ONLY_COMPACTION_STALE_EVENTS {
                store
                    .try_replace_latest_daemon_control(StoreFact {
                        tenant_hash: "default".to_string(),
                        entity: entity.to_string(),
                        key: "content".to_string(),
                        value: format!("bounded-workspace-scan-{version}"),
                        source_receipt: None,
                        confidence: 1.0,
                        private: true,
                        horizon_class: None,
                        actor: None,
                    })
                    .unwrap();
            }
            assert_eq!(store.get_by_entity(entity).len(), 1);
            let blocked = store
                .try_replace_latest_daemon_control(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: entity.to_string(),
                    key: "content".to_string(),
                    value: "blocked-at-ceiling".to_string(),
                    source_receipt: None,
                    confidence: 1.0,
                    private: true,
                    horizon_class: None,
                    actor: None,
                })
                .expect_err("stale-history ceiling must stop further journal growth");
            assert_eq!(blocked.kind(), std::io::ErrorKind::WouldBlock);
        }

        let journal_path = dir.path().join("facts.jsonl");
        let journal_records = std::io::BufReader::new(std::fs::File::open(&journal_path).unwrap())
            .lines()
            .count();
        assert!(
            journal_records <= LATEST_ONLY_COMPACTION_STALE_EVENTS + 2,
            "hard backpressure must bound latest-only replay work; got {journal_records} records"
        );
        let mut replayed = FactStore::with_persistence(dir.path()).unwrap();
        let resident = replayed.get_by_entity(entity);
        assert_eq!(resident.len(), 1);
        assert_eq!(
            resident[0].value,
            format!("bounded-workspace-scan-{LATEST_ONLY_COMPACTION_STALE_EVENTS}")
        );
        let blocked = replayed
            .try_replace_latest_daemon_control(StoreFact {
                tenant_hash: "default".to_string(),
                entity: entity.to_string(),
                key: "content".to_string(),
                value: "still-blocked-after-replay".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: None,
            })
            .expect_err("replay must reconstruct the stale-history ceiling");
        assert_eq!(blocked.kind(), std::io::ErrorKind::WouldBlock);

        replayed
            .compact_journal()
            .expect("explicit compaction is exact and unrelated hold does not block it");
        replayed
            .try_replace_latest_daemon_control(StoreFact {
                tenant_hash: "default".to_string(),
                entity: entity.to_string(),
                key: "content".to_string(),
                value: "after-explicit-compaction".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: None,
            })
            .expect("explicit compaction releases backpressure");
    }

    #[test]
    fn replay_corruption_is_preserved_when_stale_history_backpressure_applies() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("facts.jsonl");
        let entity = "__workspace_scan__::latest";
        {
            let mut writer = std::io::BufWriter::new(std::fs::File::create(&journal_path).unwrap());
            writeln!(writer, "{{malformed-journal-event").unwrap();
            for version in 0..=LATEST_ONLY_COMPACTION_STALE_EVENTS {
                let fact = FactStore::new()
                    .try_store(StoreFact {
                        tenant_hash: "default".to_string(),
                        entity: entity.to_string(),
                        key: "content".to_string(),
                        value: format!("legacy-scan-{version}"),
                        source_receipt: None,
                        confidence: 1.0,
                        private: true,
                        horizon_class: None,
                        actor: None,
                    })
                    .unwrap();
                writeln!(
                    writer,
                    "{}",
                    serde_json::to_string(&JournalEvent::Store { fact }).unwrap()
                )
                .unwrap();
            }
            writer.flush().unwrap();
            writer.get_ref().sync_all().unwrap();
        }
        let original_journal = std::fs::read(&journal_path).unwrap();

        let mut replayed = FactStore::with_persistence(dir.path()).unwrap();

        assert_eq!(std::fs::read(&journal_path).unwrap(), original_journal);
        assert_eq!(replayed.get_by_entity(entity).len(), 1);
        let blocked = replayed
            .try_replace_latest_daemon_control(StoreFact {
                tenant_hash: "default".to_string(),
                entity: entity.to_string(),
                key: "content".to_string(),
                value: "must-not-append".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: None,
            })
            .expect_err("stale-history ceiling must backpressure writes while corruption is quarantined");
        assert_eq!(blocked.kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(std::fs::read(&journal_path).unwrap(), original_journal);
    }

    #[test]
    fn workspace_scan_latest_only_replacement_survives_replay() {
        let dir = tempfile::tempdir().unwrap();
        let first_id;
        let latest_id;
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let request = |value: &str| StoreFact {
                tenant_hash: "default".to_string(),
                entity: "__workspace_scan__::latest".into(),
                key: "content".into(),
                value: value.to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: None,
            };
            first_id = store
                .try_replace_latest_daemon_control(request("first"))
                .unwrap()
                .fact_id;
            latest_id = store
                .try_replace_latest_daemon_control(request("latest"))
                .unwrap()
                .fact_id;
            assert!(store.get(&first_id).is_none());
            assert_eq!(store.get_by_entity("__workspace_scan__::latest").len(), 1);
        }

        let store = FactStore::with_persistence(dir.path()).unwrap();
        assert!(store.get(&first_id).is_none());
        assert_eq!(store.get_by_entity("__workspace_scan__::latest").len(), 1);
        assert_eq!(store.get(&latest_id).unwrap().value, "latest");
    }

    #[test]
    fn latest_only_replacement_is_control_scoped_and_legal_hold_aware() {
        let request = |entity: &str, value: &str| StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: "content".into(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        };
        let mut store = FactStore::new();
        let error = store
            .try_replace_latest_daemon_control(request("ordinary", "value"))
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(store
            .try_replace_latest_daemon_control(request("__workspace_scan__::latest", "bounded scan"))
            .is_ok());

        let entity = "__repo_registry__::tenant::held";
        let original = store
            .try_replace_latest_daemon_control(request(entity, "original"))
            .unwrap();
        store
            .place_legal_hold(crate::legal_hold::PlaceLegalHold {
                tenant_id: "tenant".to_string(),
                entity_prefixes: vec!["__repo_registry__::tenant".to_string()],
                reason: "fixture hold".to_string(),
                actor: Some("fixture-operator".to_string()),
            })
            .unwrap();
        let error = store
            .try_replace_latest_daemon_control(request(entity, "replacement"))
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(store.get(&original.fact_id).unwrap().value, "original");
    }

    #[test]
    fn indeterminate_durable_append_poison_blocks_competing_retry_history() {
        let dir = tempfile::tempdir().unwrap();
        let request = |value: &str| StoreFact {
            tenant_hash: "default".to_string(),
            entity: "__repo_registry__::tenant::indeterminate".to_string(),
            key: "content".to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        };
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            store
                .fail_next_durable_append_after_write
                .store(true, std::sync::atomic::Ordering::Release);
            let first = store.try_replace_latest_daemon_control(request("first")).unwrap_err();
            assert!(first.to_string().contains("indeterminate"));
            assert!(
                store.journal_durability_poisoned(),
                "indeterminate append must expose a preservation barrier to coordinated cleanup"
            );
            assert!(
                store
                    .get_by_entity("__repo_registry__::tenant::indeterminate")
                    .is_empty(),
                "failed caller must not see a resident commit"
            );
            let journal_path = dir.path().join("facts.jsonl");
            let indeterminate_journal = std::fs::read(&journal_path).unwrap();
            let compaction = store
                .compact_journal()
                .expect_err("poisoned resident state must never replace the journal");
            assert!(compaction.to_string().contains("poisoned"));
            assert_eq!(std::fs::read(&journal_path).unwrap(), indeterminate_journal);
            let retry = store.try_replace_latest_daemon_control(request("retry")).unwrap_err();
            assert!(retry.to_string().contains("poisoned"));
        }

        let replayed = FactStore::with_persistence(dir.path()).unwrap();
        assert!(
            !replayed.journal_durability_poisoned(),
            "successful restart replay resolves the indeterminate resident state"
        );
        let facts = replayed.get_by_entity("__repo_registry__::tenant::indeterminate");
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].value, "first");
    }

    #[test]
    fn bounded_replay_skips_only_structural_legacy_scan_records_and_compacts_them() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("facts.jsonl");
        let mut builder = FactStore::new();
        let oversized_scan = builder
            .try_store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "__repo_scan__::tenant::repo::latest".to_string(),
                key: "content".to_string(),
                value: "x".repeat(4096),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: None,
            })
            .unwrap();
        let oversized_workspace_scan = builder
            .try_store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "__workspace_scan__::latest".to_string(),
                key: "content".to_string(),
                value: "y".repeat(4096),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: None,
            })
            .unwrap();
        let ordinary = builder
            .try_store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "ordinary".to_string(),
                key: "content".to_string(),
                value: "survives".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            })
            .unwrap();
        let scan_line = serde_json::to_string(&JournalEvent::Store { fact: oversized_scan }).unwrap();
        let workspace_scan_line = serde_json::to_string(&JournalEvent::Store {
            fact: oversized_workspace_scan,
        })
        .unwrap();
        let ordinary_line = serde_json::to_string(&JournalEvent::Store { fact: ordinary.clone() }).unwrap();
        std::fs::write(
            &journal_path,
            format!("{scan_line}\n{workspace_scan_line}\n{ordinary_line}\n"),
        )
        .unwrap();

        let mut replayed = FactStore {
            journal_path: Some(journal_path.clone()),
            ..FactStore::default()
        };
        replayed.replay_journal_with_record_limit(&journal_path, 512).unwrap();
        assert_eq!(replayed.oversized_legacy_scan_records_skipped(), 2);
        assert!(replayed.get_by_entity("__repo_scan__::tenant::repo::latest").is_empty());
        assert!(replayed.get_by_entity("__workspace_scan__::latest").is_empty());
        assert_eq!(replayed.get(&ordinary.fact_id).unwrap().value, "survives");

        replayed.compact_journal().unwrap();
        assert_eq!(replayed.oversized_legacy_scan_records_skipped(), 0);
        let compacted = std::fs::read_to_string(&journal_path).unwrap();
        assert!(!compacted.contains("__repo_scan__::tenant::repo::latest"));
        assert!(!compacted.contains("__workspace_scan__::latest"));
        assert!(compacted.contains("\"entity\":\"ordinary\""));
    }

    #[test]
    fn bounded_replay_never_misclassifies_ordinary_value_text_as_scan_entity() {
        let mut builder = FactStore::new();
        let ordinary = builder
            .try_store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "ordinary".to_string(),
                key: "content".to_string(),
                value: format!("__repo_scan__::{}", "x".repeat(4096)),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            })
            .unwrap();
        let line = serde_json::to_string(&JournalEvent::Store { fact: ordinary }).unwrap();
        let mut reader = std::io::BufReader::new(std::io::Cursor::new(format!("{line}\n")));
        let error = read_bounded_journal_record(&mut reader, 512).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn bounded_replay_never_misclassifies_workspace_marker_in_ordinary_value() {
        let mut builder = FactStore::new();
        let ordinary = builder
            .try_store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "ordinary".to_string(),
                key: "content".to_string(),
                value: format!("__workspace_scan__::{}", "x".repeat(4096)),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            })
            .unwrap();
        let line = serde_json::to_string(&JournalEvent::Store { fact: ordinary }).unwrap();
        let mut reader = std::io::BufReader::new(std::io::Cursor::new(format!("{line}\n")));
        let error = read_bounded_journal_record(&mut reader, 512).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn append_and_replay_share_the_same_record_boundary() {
        let mut builder = FactStore::new();
        let fact = builder
            .try_store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "boundary".to_string(),
                key: "content".to_string(),
                value: "value".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            })
            .unwrap();
        let event = JournalEvent::Store { fact };
        let encoded = serde_json::to_string(&event).unwrap();
        assert!(serialize_journal_event_with_limit(&event, encoded.len()).is_ok());
        assert!(serialize_journal_event_with_limit(&event, encoded.len() - 1).is_err());
        let mut reader = std::io::BufReader::new(std::io::Cursor::new(format!("{encoded}\n")));
        assert!(matches!(
            read_bounded_journal_record(&mut reader, encoded.len()).unwrap(),
            Some(BoundedJournalRecord::Json(_))
        ));
    }

    #[test]
    fn compaction_rejects_oversized_resident_fact_without_replacing_valid_journal() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("facts.jsonl");
        let mut store = FactStore::with_persistence(dir.path()).unwrap();
        let durable = store
            .try_store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "durable".to_string(),
                key: "content".to_string(),
                value: "survives".to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            })
            .unwrap();
        let original_journal = std::fs::read(&journal_path).unwrap();

        // Model the infallible `store()` failure mode: its append can reject a
        // record while the already-built fact remains resident. Compaction
        // must apply the same ceiling and leave the last valid journal intact.
        let oversized = store.build_fact(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "resident-only".to_string(),
            key: "content".to_string(),
            value: "x".repeat(4096),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        store.insert_fact_indexes(&oversized);
        let error = store
            .compact_journal_unchecked_with_record_limit(1024)
            .expect_err("oversized resident fact must abort compaction");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(&journal_path).unwrap(), original_journal);
        assert!(
            std::fs::read_dir(dir.path()).unwrap().all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".compact-")),
            "aborted compaction must remove its temporary journal"
        );

        drop(store);
        let replayed = FactStore::with_persistence(dir.path()).unwrap();
        assert_eq!(replayed.get(&durable.fact_id).unwrap().value, "survives");
        assert!(replayed.get(&oversized.fact_id).is_none());
    }

    #[test]
    fn replay_bounds_legacy_scan_history_and_preserves_later_hold_barrier() {
        let dir = tempfile::tempdir().unwrap();
        let first_id;
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let request = |value: &str| StoreFact {
                tenant_hash: "default".to_string(),
                entity: "__repo_scan__::tenant::repo::latest".to_string(),
                key: "content".to_string(),
                value: value.to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: None,
            };
            first_id = store.try_store(request("first")).unwrap().fact_id;
            store.try_store(request("latest")).unwrap();
        }

        let mut store = FactStore::with_persistence(dir.path()).unwrap();
        assert!(store.get(&first_id).is_none());
        assert_eq!(store.get_by_entity("__repo_scan__::tenant::repo::latest").len(), 1);
        store
            .place_legal_hold(crate::legal_hold::PlaceLegalHold {
                tenant_id: "tenant".to_string(),
                entity_prefixes: vec!["__repo_scan__::tenant::repo".to_string()],
                reason: "fixture hold".to_string(),
                actor: Some("fixture-operator".to_string()),
            })
            .unwrap();
        let error = store.compact_journal().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn replay_bounds_legacy_registry_churn_and_preserves_later_hold_barrier() {
        let dir = tempfile::tempdir().unwrap();
        let journal_path = dir.path().join("facts.jsonl");
        let mut journal = std::io::BufWriter::new(std::fs::File::create(&journal_path).unwrap());
        let mut first_id = String::new();
        let mut latest_id = String::new();
        for version in 0..64 {
            let mut fact = FactStore::new()
                .try_store(StoreFact {
                    tenant_hash: "default".to_string(),
                    entity: "__repo_registry__::tenant::high-churn".to_string(),
                    key: "content".to_string(),
                    value: format!("registration-{version}"),
                    source_receipt: None,
                    confidence: 1.0,
                    // Exercise upgrade replay of rows written before this
                    // daemon namespace became born-private.
                    private: false,
                    horizon_class: None,
                    actor: None,
                })
                .unwrap();
            fact.private = false;
            if version == 0 {
                first_id.clone_from(&fact.fact_id);
            }
            latest_id.clone_from(&fact.fact_id);
            writeln!(
                journal,
                "{}",
                serde_json::to_string(&JournalEvent::Store { fact }).unwrap()
            )
            .unwrap();
        }
        journal.flush().unwrap();
        journal.get_ref().sync_all().unwrap();
        drop(journal);

        let mut store = FactStore::with_persistence(dir.path()).unwrap();
        let resident = store.get_by_entity("__repo_registry__::tenant::high-churn");
        assert_eq!(resident.len(), 1);
        assert_eq!(resident[0].fact_id, latest_id);
        assert_eq!(resident[0].value, "registration-63");
        assert!(resident[0].private);
        assert!(store.get(&first_id).is_none());

        store
            .place_legal_hold(crate::legal_hold::PlaceLegalHold {
                tenant_id: "tenant".to_string(),
                entity_prefixes: vec!["__repo_registry__::tenant::high-churn".to_string()],
                reason: "fixture hold after bounded replay".to_string(),
                actor: Some("fixture-operator".to_string()),
            })
            .unwrap();
        let error = store.compact_journal().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn replay_bounds_legacy_workspace_scan_history_and_preserves_later_hold_barrier() {
        let dir = tempfile::tempdir().unwrap();
        let first_id;
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let request = |value: &str| StoreFact {
                tenant_hash: "default".to_string(),
                entity: "__workspace_scan__::latest".to_string(),
                key: "content".to_string(),
                value: value.to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: None,
            };
            first_id = store.try_store(request("first")).unwrap().fact_id;
            store.try_store(request("latest")).unwrap();
        }

        let mut store = FactStore::with_persistence(dir.path()).unwrap();
        assert!(store.get(&first_id).is_none());
        assert_eq!(store.get_by_entity("__workspace_scan__::latest").len(), 1);
        store
            .place_legal_hold(crate::legal_hold::PlaceLegalHold {
                tenant_id: "default".to_string(),
                entity_prefixes: vec!["__workspace_scan__::".to_string()],
                reason: "fixture hold".to_string(),
                actor: Some("fixture-operator".to_string()),
            })
            .unwrap();
        let error = store.compact_journal().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn fact_without_superseded_by_deserializes_as_none() {
        // Backward-compat: a pre-M6 on-disk fact has no `superseded_by`
        // field. It must deserialize as None (no panic, no error).
        let legacy = r#"{
            "fact_id": "f_legacy",
            "entity": "proj",
            "key": "k",
            "value": "v",
            "source_receipt": null,
            "confidence": 1.0,
            "stored_at": "2026-01-01T00:00:00Z",
            "tokens": 4,
            "deleted": false,
            "version": 1
        }"#;
        let fact: Fact = serde_json::from_str(legacy).unwrap();
        assert!(fact.superseded_by.is_none());
        assert!(fact.reverified_at.is_none());
        assert_eq!(fact.horizon_class, HorizonClass::None);
        // Bi-temporal (M1): a pre-bitemporal fact has open valid bounds and
        // is therefore valid at every instant — the as_of filter never hides
        // legacy facts.
        assert!(fact.valid_from.is_none());
        assert!(fact.valid_to.is_none());
        assert!(fact.valid_at(Utc::now()));
    }

    // ── M1: bi-temporal valid-time (Graphiti model) ─────────────────

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    fn sample_fact(entity: &str, key: &str, value: &str) -> Fact {
        let mut store = FactStore::new();
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.into(),
            key: key.into(),
            value: value.into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: Some(HorizonClass::None),
            actor: None,
        })
    }

    #[test]
    fn valid_at_open_bounds_match_everything() {
        let mut f = sample_fact("e", "k", "v");
        // Both ends open (default).
        assert!(f.valid_at(ts("2000-01-01T00:00:00Z")));
        assert!(f.valid_at(ts("2099-01-01T00:00:00Z")));
        // Open upper bound only: valid from 2026 onward, forever.
        f.valid_from = Some(ts("2026-01-01T00:00:00Z"));
        assert!(!f.valid_at(ts("2025-12-31T23:59:59Z")));
        assert!(f.valid_at(ts("2026-01-01T00:00:00Z")));
        assert!(f.valid_at(ts("2099-01-01T00:00:00Z")));
    }

    #[test]
    fn valid_at_is_half_open_interval() {
        let mut f = sample_fact("e", "k", "v");
        f.valid_from = Some(ts("2026-01-01T00:00:00Z"));
        f.valid_to = Some(ts("2026-06-01T00:00:00Z"));
        // Lower bound inclusive.
        assert!(f.valid_at(ts("2026-01-01T00:00:00Z")));
        // Inside.
        assert!(f.valid_at(ts("2026-03-15T12:00:00Z")));
        // Upper bound EXCLUSIVE.
        assert!(!f.valid_at(ts("2026-06-01T00:00:00Z")));
        // Before / after.
        assert!(!f.valid_at(ts("2025-12-31T23:59:59Z")));
        assert!(!f.valid_at(ts("2026-09-01T00:00:00Z")));
    }

    #[test]
    fn set_validity_and_query_as_of_picks_world_true_fact() {
        let mut store = FactStore::new();
        // Two facts under the same entity describing the office at different
        // world-times. Same transaction time (now); different valid time.
        let old = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "person:alice".into(),
            key: "city".into(),
            value: "London".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: Some(HorizonClass::None),
            actor: None,
        });
        let new = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "person:alice".into(),
            key: "city".into(),
            value: "Berlin".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: Some(HorizonClass::None),
            actor: None,
        });
        // Alice lived in London Jan–Jun 2026, then Berlin from Jun 2026 on.
        assert!(store.set_validity(
            &old.fact_id,
            Some(ts("2026-01-01T00:00:00Z")),
            Some(ts("2026-06-01T00:00:00Z"))
        ));
        assert!(store.set_validity(&new.fact_id, Some(ts("2026-06-01T00:00:00Z")), None));

        let q = FactQuery {
            min_effective_confidence: None,
            tenant_hash: None,
            query: None,
            entity: Some("person:alice".into()),
            entity_prefix: None,
            top_k: 10,
            token_budget: None,
        };

        // As of March: only London is world-true.
        let march = store.query_as_of(&q, ts("2026-03-01T00:00:00Z"));
        assert_eq!(march.facts.len(), 1);
        assert_eq!(march.facts[0].value, "London");

        // As of September: only Berlin is world-true.
        let sept = store.query_as_of(&q, ts("2026-09-01T00:00:00Z"));
        assert_eq!(sept.facts.len(), 1);
        assert_eq!(sept.facts[0].value, "Berlin");

        // Plain query (no as_of) is unfiltered by validity — both come back
        // (one is the superseded prior version, surfaced here only because
        // query() does not hide them; the point is as_of did the filtering).
        let all = store.query(&q);
        assert!(all.facts.len() >= 1);

        // set_validity on a missing fact is a no-op false.
        assert!(!store.set_validity("f_nope", None, None));
    }

    #[test]
    fn set_validity_persists_across_replay() {
        let dir = tempfile::tempdir().unwrap();
        let fact_id: String;
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let f = store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "person:bob".into(),
                key: "role".into(),
                value: "ic".into(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: Some(HorizonClass::None),
                actor: None,
            });
            fact_id = f.fact_id.clone();
            assert!(store.set_validity(
                &fact_id,
                Some(ts("2026-01-01T00:00:00Z")),
                Some(ts("2026-12-31T00:00:00Z"))
            ));
        }
        // Reopen: replay must restore the valid-time interval.
        let store = FactStore::with_persistence(dir.path()).unwrap();
        let f = store.get(&fact_id).unwrap();
        assert_eq!(f.valid_from, Some(ts("2026-01-01T00:00:00Z")));
        assert_eq!(f.valid_to, Some(ts("2026-12-31T00:00:00Z")));
    }

    // ── M2: salience access tracking ────────────────────────────────

    #[test]
    fn record_access_increments_count_and_stamps_time() {
        let mut store = FactStore::new();
        let f = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "e".into(),
            key: "k".into(),
            value: "v".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: Some(HorizonClass::None),
            actor: None,
        });
        // Fresh fact: no accesses yet.
        assert_eq!(store.get(&f.fact_id).unwrap().access_count, 0);
        assert!(store.get(&f.fact_id).unwrap().last_accessed_at.is_none());

        // One recall of one fact updates exactly one fact.
        assert_eq!(store.record_access(&[f.fact_id.as_str()]), 1);
        assert_eq!(store.get(&f.fact_id).unwrap().access_count, 1);
        assert!(store.get(&f.fact_id).unwrap().last_accessed_at.is_some());

        // Repeated recalls accumulate.
        store.record_access(&[f.fact_id.as_str()]);
        store.record_access(&[f.fact_id.as_str()]);
        assert_eq!(store.get(&f.fact_id).unwrap().access_count, 3);

        // Unknown ids are skipped (returns 0, no panic).
        assert_eq!(store.record_access(&["f_nope"]), 0);
    }

    #[test]
    fn record_access_skips_deleted_facts() {
        let mut store = FactStore::new();
        let f = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "e".into(),
            key: "k".into(),
            value: "v".into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: Some(HorizonClass::None),
            actor: None,
        });
        store.delete("default", &f.fact_id);
        // A tombstoned fact is not a recall target.
        assert_eq!(store.record_access(&[f.fact_id.as_str()]), 0);
    }

    #[test]
    fn access_count_is_not_journaled_resets_on_replay() {
        // Salience is an in-memory heuristic: it deliberately does NOT survive
        // a restart (journaling every recall would bloat the hot-path log).
        let dir = tempfile::tempdir().unwrap();
        let fact_id: String;
        {
            let mut store = FactStore::with_persistence(dir.path()).unwrap();
            let f = store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "e".into(),
                key: "k".into(),
                value: "v".into(),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: Some(HorizonClass::None),
                actor: None,
            });
            fact_id = f.fact_id.clone();
            store.record_access(&[fact_id.as_str()]);
            store.record_access(&[fact_id.as_str()]);
            assert_eq!(store.get(&fact_id).unwrap().access_count, 2);
        }
        // Reopen: access_count resets to 0 (cold cache), value intact.
        let store = FactStore::with_persistence(dir.path()).unwrap();
        let f = store.get(&fact_id).unwrap();
        assert_eq!(f.access_count, 0);
        assert!(f.last_accessed_at.is_none());
        assert_eq!(f.value, "v");
    }

    // ── FactStore::list_page (console paged listing route, M1) ──────────────

    /// Store a fact and stamp a deterministic `stored_at` so listing order is
    /// exercised against *distinct* timestamps (not the coarse `Utc::now()` a
    /// tight loop yields). Returns the new fact_id.
    fn store_at(store: &mut FactStore, entity: &str, key: &str, value: &str, stored_at_ms: i64) -> String {
        let fact = store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.into(),
            key: key.into(),
            value: value.into(),
            source_receipt: None,
            confidence: 1.0,
            private: false,
            horizon_class: None,
            actor: None,
        });
        let id = fact.fact_id.clone();
        store.facts.get_mut(&id).unwrap().stored_at = DateTime::<Utc>::from_timestamp_millis(stored_at_ms).unwrap();
        id
    }

    #[test]
    fn list_page_walks_full_store_descending_exactly_once() {
        let mut store = FactStore::new();
        // 25 facts with strictly increasing stored_at (1000ms..=25000ms).
        let mut expected_ids = Vec::new();
        for i in 1..=25i64 {
            expected_ids.push(store_at(
                &mut store,
                "note",
                &format!("k{i}"),
                &format!("v{i}"),
                i * 1000,
            ));
        }
        // Newest-first: expected walk order is the reverse of insertion order.
        expected_ids.reverse();

        let mut seen: Vec<String> = Vec::new();
        let mut cursor: Option<FactListCursor> = None;
        let mut pages = 0;
        loop {
            let page = store.list_page(cursor.as_ref(), 10, true, |_| true);
            pages += 1;
            assert_eq!(page.total_visible, 25);
            for f in &page.facts {
                seen.push(f.fact_id.clone());
            }
            match page.next_cursor {
                Some(ref c) => {
                    assert!(page.has_more);
                    cursor = Some(FactListCursor::decode(c).expect("round-trip cursor"));
                }
                None => {
                    assert!(!page.has_more);
                    break;
                }
            }
        }
        assert_eq!(pages, 3, "25 facts / limit 10 = 3 pages (10 + 10 + 5)");
        assert_eq!(seen.len(), 25);
        assert_eq!(seen, expected_ids, "exact newest-first order, no dupes/gaps");
        let unique: std::collections::BTreeSet<&String> = seen.iter().collect();
        assert_eq!(unique.len(), 25, "every fact exactly once");
    }

    #[test]
    fn list_page_cursor_resumes_even_when_cursor_fact_deleted() {
        let mut store = FactStore::new();
        for i in 1..=5i64 {
            store_at(&mut store, "note", &format!("k{i}"), &format!("v{i}"), i * 1000);
        }
        // Page 1 of 2 (newest first: 5000,4000).
        let page1 = store.list_page(None, 2, true, |_| true);
        assert_eq!(page1.facts.len(), 2);
        assert_eq!(page1.facts[0].value, "v5");
        assert_eq!(page1.facts[1].value, "v4");
        let cursor = FactListCursor::decode(page1.next_cursor.as_ref().unwrap()).unwrap();
        // Delete the cursor fact (v4). The cursor carries the ordering key, not
        // a position, so the next page must still resume at v3 with no dupe.
        let v4_id = page1.facts[1].fact_id.clone();
        store.delete("default", &v4_id);
        let page2 = store.list_page(Some(&cursor), 2, true, |_| true);
        assert_eq!(page2.facts[0].value, "v3");
        assert_eq!(page2.facts[1].value, "v2");
        assert_eq!(page2.total_visible, 4, "v4 now deleted");
    }

    #[test]
    fn list_page_excludes_private_deleted_and_gates_superseded() {
        let mut store = FactStore::new();
        store_at(&mut store, "note", "shared", "public", 1000);
        // Private fact — never listed.
        let mut priv_req = StoreFact {
            tenant_hash: "default".to_string(),
            entity: "secret".into(),
            key: "k".into(),
            value: "hidden".into(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        };
        priv_req.private = true;
        store.store(priv_req);
        // Deleted fact — never listed.
        let del_id = store_at(&mut store, "note", "gone", "deleted-value", 2000);
        store.delete("default", &del_id);
        // Superseded fact.
        let old_id = store_at(&mut store, "note", "retired", "old", 3000);
        let new_id = store_at(&mut store, "note", "current", "new", 4000);
        store.mark_superseded("default", &old_id, &new_id);

        // Default (include_superseded=true): public + current + old(retired) = 3.
        let page = store.list_page(None, 100, true, |_| true);
        assert_eq!(page.total_visible, 3);
        assert!(page
            .facts
            .iter()
            .all(|f| f.value != "hidden" && f.value != "deleted-value"));
        assert!(page.facts.iter().any(|f| f.value == "old"));

        // include_superseded=false: the retired `old` drops out → 2.
        let page = store.list_page(None, 100, false, |_| true);
        assert_eq!(page.total_visible, 2);
        assert!(page.facts.iter().all(|f| f.value != "old"));
    }

    #[test]
    fn list_page_applies_caller_filter_to_visible_count() {
        let mut store = FactStore::new();
        store_at(&mut store, "alpha", "k", "one", 1000);
        store_at(&mut store, "alpha", "k", "two", 2000);
        store_at(&mut store, "beta", "k", "three", 3000);
        let page = store.list_page(None, 100, true, |f| f.entity == "alpha");
        assert_eq!(page.total_visible, 2);
        assert!(page.facts.iter().all(|f| f.entity == "alpha"));
    }

    #[test]
    fn fact_list_cursor_round_trips_and_rejects_garbage() {
        let c = FactListCursor {
            stored_at_ms: 1_726_000_000_000,
            fact_id: "f_deadbeef".into(),
        };
        assert_eq!(FactListCursor::decode(&c.encode()), Some(c));
        assert_eq!(FactListCursor::decode("not-a-cursor"), None);
        assert_eq!(FactListCursor::decode("notanumber:f_x"), None);
        assert_eq!(FactListCursor::decode("123:"), None);
    }
}
