// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Gated auto-capture — the review-only candidate store (ExecPlan
//! `crux-daemon-buyer-fit-buildout-2026-07-13`, M1).
//!
//! An auto-extracted fact is a *proposal*, not a memory. Until an explicit
//! review promotes it, it must be **invisible to recall** — a poisoned or
//! hallucinated candidate can never leak into `query_facts`/`GET /v1/facts`.
//!
//! ## How invisibility is guaranteed
//!
//! Candidates are stored as ordinary [`Fact`]s under the reserved entity prefix
//! [`CANDIDATE_PREFIX`] with **`private = true`**. Two independent mechanisms
//! then hide them from recall:
//! 1. `crux_mcp::scope::fact_visible_to_agent` returns `false` for any
//!    `private` fact to a non-owning caller — and no normal caller owns the
//!    `__candidate_fact__::` namespace — so candidates never appear in HTTP or
//!    MCP recall.
//! 2. The prefix is registered in `fact_privacy::DEFAULT_PRIVATE_PREFIXES` (and
//!    `CRUXPACK_RESERVED_PREFIXES`), so any path that *does* run
//!    `fact_privacy::enforce` also forces `private = true`.
//!
//! We write the candidate directly through [`FactStore::try_store`] (which does
//! NOT run the HTTP-boundary privacy enforcer — see `http::facts`), so this
//! module sets `private: true` **explicitly**; the prefix registration is
//! defence in depth, not the primary guarantee.
//!
//! Promotion/rejection (the review lifecycle + fail-closed gate) lands in M1.3;
//! this module owns the schema, the write, and the read-back.

use corecrux_memory::fact_store::StoreFact;
use corecrux_memory::{Fact, FactStore, HorizonClass};
use serde::{Deserialize, Serialize};

/// Reserved entity prefix for review-only auto-capture candidates. Registered
/// born-private in `corecrux_memory::fact_privacy::DEFAULT_PRIVATE_PREFIXES` and
/// mirrored in `CRUXPACK_RESERVED_PREFIXES`. Distinct from `candidate_links.rs`
/// (identity resolution) on purpose.
pub const CANDIDATE_PREFIX: &str = "__candidate_fact__::";

/// The fixed `key` every candidate record is written under (one candidate per
/// entity; state transitions are new versions of the same `(entity, key)`).
pub const CANDIDATE_KEY: &str = "candidate";

/// Schema tag stamped into every candidate body.
pub const CANDIDATE_SCHEMA_V1: &str = "crux.memory_candidate.v1";

/// Lifecycle state of a candidate. Transitions are recorded as new same-`(entity,
/// key)` versions so history is preserved and every transition is reversible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateStatus {
    /// Proposed, awaiting review. Invisible to recall.
    Candidate,
    /// Reviewed and written to the real store (see `promoted_fact_id`).
    Promoted,
    /// Reviewed and declined (see `reject_reason`). Reversible.
    Rejected,
}

/// Provenance for a candidate: where in the raw material it came from.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CandidateSource {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Observation sequence number within the session's signed JSONL stream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation_seq: Option<u64>,
    /// Verbatim source span the extractor claims supports the fact.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

/// The `crux.memory_candidate.v1` body persisted as the fact `value`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryCandidateV1 {
    pub schema: String,
    pub candidate_id: String,
    pub status: CandidateStatus,
    /// Where the fact WOULD be written on promotion.
    pub proposed_entity: String,
    pub proposed_key: String,
    pub proposed_value: String,
    /// Extractor provenance tag (rule name, or "llm" for the paid path).
    pub rule: String,
    pub confidence: f32,
    /// Freshness class the promoted fact should carry.
    pub decay_class: String,
    pub source: CandidateSource,
    /// Verifier score, if a verifier ran. **`None` = unscored ⇒ review-only,
    /// never auto-promoted** (the fail-closed inversion of CruxEngine's
    /// fail-open verifier). The M1.3 gate keys on this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifier_score: Option<f32>,
    /// Offline-verifiable CROWN receipt envelope (as JSON) minted by the route
    /// layer over this candidate body. Every candidate carries a receipt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt: Option<serde_json::Value>,
    pub created_at: String,
    /// Set when `status = promoted`: the `fact_id` of the real fact written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub promoted_fact_id: Option<String>,
    /// Set when `status = rejected`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reject_reason: Option<String>,
}

impl MemoryCandidateV1 {
    /// Build a fresh `candidate`-state body from an extractor proposal.
    #[allow(clippy::too_many_arguments)]
    pub fn new_candidate(
        candidate_id: String,
        proposed_entity: String,
        proposed_key: String,
        proposed_value: String,
        rule: String,
        confidence: f32,
        decay_class: String,
        source: CandidateSource,
        verifier_score: Option<f32>,
        receipt: Option<serde_json::Value>,
        created_at: String,
    ) -> Self {
        Self {
            schema: CANDIDATE_SCHEMA_V1.to_string(),
            candidate_id,
            status: CandidateStatus::Candidate,
            proposed_entity,
            proposed_key,
            proposed_value,
            rule,
            confidence,
            decay_class,
            source,
            verifier_score,
            receipt,
            created_at,
            promoted_fact_id: None,
            reject_reason: None,
        }
    }
}

/// The reserved entity string for a candidate id.
pub fn candidate_entity(candidate_id: &str) -> String {
    format!("{CANDIDATE_PREFIX}{candidate_id}")
}

/// Persist a candidate as a born-private, receipted fact. Returns the entity it
/// was written under. The caller supplies `candidate_id` (content-addressed or
/// uuid) and the already-built body; the receipt should already be embedded in
/// `body.receipt` and `receipt_body_hash` linked as `source_receipt`.
pub fn write_candidate(
    store: &mut FactStore,
    body: &MemoryCandidateV1,
    receipt_body_hash: Option<String>,
) -> Result<String, String> {
    let entity = candidate_entity(&body.candidate_id);
    let value = serde_json::to_string(body).map_err(|e| format!("serialize candidate: {e}"))?;
    let req = StoreFact {
        tenant_hash: "default".to_string(),
        entity: entity.clone(),
        key: CANDIDATE_KEY.to_string(),
        value,
        source_receipt: receipt_body_hash,
        confidence: body.confidence,
        // Explicit: try_store does NOT run the HTTP privacy enforcer, so we set
        // born-private here. The prefix registration is defence in depth.
        private: true,
        horizon_class: Some(HorizonClass::Medium),
        actor: Some("auto-capture".to_string()),
    };
    store.try_store(req).map_err(|e| format!("store candidate: {e}"))?;
    Ok(entity)
}

/// Read back the latest version of every candidate, optionally filtered by
/// status. Only non-deleted, non-superseded (`superseded_by == None`) records
/// under [`CANDIDATE_PREFIX`] are considered (latest-wins).
pub fn list_candidates(store: &FactStore, status: Option<CandidateStatus>) -> Vec<MemoryCandidateV1> {
    store
        .all_facts()
        .filter(|f: &&Fact| {
            f.entity.starts_with(CANDIDATE_PREFIX) && f.key == CANDIDATE_KEY && !f.deleted && f.superseded_by.is_none()
        })
        .filter_map(|f| serde_json::from_str::<MemoryCandidateV1>(&f.value).ok())
        .filter(|c| status.is_none_or(|s| c.status == s))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_body(id: &str) -> MemoryCandidateV1 {
        MemoryCandidateV1::new_candidate(
            id.to_string(),
            "person:user".to_string(),
            "owns_cat_count".to_string(),
            "3".to_string(),
            "count_item".to_string(),
            0.80,
            "medium".to_string(),
            CandidateSource {
                session_id: Some("sess-1".to_string()),
                observation_seq: Some(4),
                evidence: Some("I have three cats".to_string()),
            },
            None, // unscored
            None,
            "2026-07-14T00:00:00Z".to_string(),
        )
    }

    #[test]
    fn candidate_is_written_born_private_under_reserved_prefix() {
        let mut store = FactStore::new();
        let entity = write_candidate(&mut store, &sample_body("c1"), None).unwrap();
        assert_eq!(entity, "__candidate_fact__::c1");
        let f = store
            .all_facts()
            .find(|f| f.entity == entity)
            .expect("candidate fact present");
        // The load-bearing safety property: a candidate is born private.
        assert!(f.private, "candidate must be born private (invisible to recall)");
        assert_eq!(f.key, CANDIDATE_KEY);
        assert_eq!(f.horizon_class, HorizonClass::Medium);
        assert_eq!(f.actor.as_deref(), Some("auto-capture"));
    }

    #[test]
    fn reserved_prefix_is_born_private_by_policy() {
        // Defence in depth: the prefix is registered so the HTTP enforcer also
        // forces private, independent of the explicit flag above.
        let policy = corecrux_memory::fact_privacy::PrivacyPolicy::from_env();
        assert!(policy.is_always_private("__candidate_fact__::c1"));
    }

    #[test]
    fn list_candidates_roundtrips_and_filters_by_status() {
        let mut store = FactStore::new();
        write_candidate(&mut store, &sample_body("c1"), None).unwrap();
        let all = list_candidates(&store, None);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].candidate_id, "c1");
        assert_eq!(all[0].status, CandidateStatus::Candidate);
        assert_eq!(all[0].verifier_score, None, "unscored by default");
        // No promoted candidates yet.
        assert!(list_candidates(&store, Some(CandidateStatus::Promoted)).is_empty());
        assert_eq!(list_candidates(&store, Some(CandidateStatus::Candidate)).len(), 1);
    }
}
