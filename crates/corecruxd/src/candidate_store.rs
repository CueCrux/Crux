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

/// Latest version of a single candidate by id (None if absent/superseded away).
pub fn get_candidate(store: &FactStore, candidate_id: &str) -> Option<MemoryCandidateV1> {
    let entity = candidate_entity(candidate_id);
    store
        .all_facts()
        .find(|f| f.entity == entity && f.key == CANDIDATE_KEY && !f.deleted && f.superseded_by.is_none())
        .and_then(|f| serde_json::from_str::<MemoryCandidateV1>(&f.value).ok())
}

/// How a promotion is authorised — the distinction IS the fail-closed gate.
pub enum PromotionMode {
    /// An explicit human/agent review decision. Always permitted (a reviewer is
    /// on the hook). `reviewer` is recorded in the promoted fact's `actor`.
    Explicit { reviewer: String },
    /// Automatic promotion. Permitted ONLY when the candidate carries a
    /// `verifier_score` at or above `score_threshold`. An unscored or
    /// below-threshold candidate is REFUSED and stays review-only — the exact
    /// inversion of CruxEngine's fail-open verifier (unscored ⇒ promote).
    Auto { score_threshold: f32 },
}

/// Outcome of a failed promote/reject.
#[derive(Debug, PartialEq, Eq)]
pub enum ReviewError {
    /// No live candidate with that id.
    NotFound,
    /// The candidate is already promoted.
    AlreadyPromoted,
    /// Auto-promotion refused: unscored or below threshold. The candidate is
    /// unchanged and remains review-only.
    FailClosed(String),
    /// Underlying store write failed.
    Store(String),
}

impl std::fmt::Display for ReviewError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReviewError::NotFound => write!(f, "candidate not found"),
            ReviewError::AlreadyPromoted => write!(f, "candidate already promoted"),
            ReviewError::FailClosed(why) => write!(f, "promotion refused (fail-closed): {why}"),
            ReviewError::Store(e) => write!(f, "candidate store error: {e}"),
        }
    }
}
impl std::error::Error for ReviewError {}

/// Promote a candidate: write the proposed fact into the real (recallable)
/// store, then record the candidate as `promoted`. Returns the new fact id.
///
/// The **fail-closed gate**: an `Auto` promotion of an unscored (or
/// below-threshold) candidate is refused — it stays a review-only candidate.
/// An `Explicit` promotion is always honoured (a human/agent decided). Callable
/// from `candidate` or (re-promote) `rejected` state, but not `promoted`.
pub fn promote(
    store: &mut FactStore,
    candidate_id: &str,
    mode: PromotionMode,
    reviewed_at: &str,
) -> Result<String, ReviewError> {
    let cand = get_candidate(store, candidate_id).ok_or(ReviewError::NotFound)?;
    if cand.status == CandidateStatus::Promoted {
        return Err(ReviewError::AlreadyPromoted);
    }
    if let PromotionMode::Auto { score_threshold } = &mode {
        match cand.verifier_score {
            Some(score) if score >= *score_threshold => {}
            Some(score) => {
                return Err(ReviewError::FailClosed(format!(
                    "verifier_score {score} < threshold {score_threshold}"
                )));
            }
            None => {
                return Err(ReviewError::FailClosed(
                    "unscored candidate cannot be auto-promoted (review-only)".to_string(),
                ));
            }
        }
    }

    // Write the real fact under its true entity/key. It goes through the normal
    // store, so it is recallable. Born-private only if the proposed entity is
    // itself a reserved prefix (defence in depth).
    let horizon = HorizonClass::parse(&cand.decay_class)
        .unwrap_or_else(|| HorizonClass::default_for_entity(&cand.proposed_entity));
    let private = corecrux_memory::fact_privacy::global_policy().is_always_private(&cand.proposed_entity);
    let actor = match &mode {
        PromotionMode::Explicit { reviewer } => format!("auto-capture:promoted-by:{reviewer}"),
        PromotionMode::Auto { .. } => "auto-capture:auto-promoted".to_string(),
    };
    let real = StoreFact {
        tenant_hash: "default".to_string(),
        entity: cand.proposed_entity.clone(),
        key: cand.proposed_key.clone(),
        value: cand.proposed_value.clone(),
        // Link the promoted fact back to its originating candidate (which carries
        // the CROWN receipt), so provenance is recoverable.
        source_receipt: Some(candidate_entity(candidate_id)),
        confidence: cand.confidence,
        private,
        horizon_class: Some(horizon),
        actor: Some(actor),
    };
    let promoted = store.try_store(real).map_err(|e| ReviewError::Store(e.to_string()))?;

    // Record the candidate transition as a new same-(entity,key) version.
    let mut updated = cand;
    updated.status = CandidateStatus::Promoted;
    updated.promoted_fact_id = Some(promoted.fact_id.clone());
    updated.reject_reason = None;
    updated.created_at = reviewed_at.to_string();
    write_candidate(store, &updated, None).map_err(ReviewError::Store)?;
    Ok(promoted.fact_id)
}

/// Reject a candidate: record it as `rejected` with a reason. Reversible — a
/// rejected candidate can later be re-promoted. Refuses a `promoted` candidate
/// (retract the promoted fact directly via supersession instead).
pub fn reject(store: &mut FactStore, candidate_id: &str, reason: &str, reviewed_at: &str) -> Result<(), ReviewError> {
    let cand = get_candidate(store, candidate_id).ok_or(ReviewError::NotFound)?;
    if cand.status == CandidateStatus::Promoted {
        return Err(ReviewError::AlreadyPromoted);
    }
    let mut updated = cand;
    updated.status = CandidateStatus::Rejected;
    updated.reject_reason = Some(reason.to_string());
    updated.promoted_fact_id = None;
    updated.created_at = reviewed_at.to_string();
    write_candidate(store, &updated, None).map_err(ReviewError::Store)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Is the proposed fact visible in normal (non-admin) recall?
    fn real_fact_present(store: &FactStore, entity: &str, key: &str) -> Option<Fact> {
        store
            .all_facts()
            .find(|f| f.entity == entity && f.key == key && !f.deleted && f.superseded_by.is_none())
            .cloned()
    }

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

    fn scored_body(id: &str, score: f32) -> MemoryCandidateV1 {
        let mut b = sample_body(id);
        b.verifier_score = Some(score);
        b
    }

    #[test]
    fn auto_promote_refuses_unscored_candidate_fail_closed() {
        let mut store = FactStore::new();
        write_candidate(&mut store, &sample_body("c1"), None).unwrap();
        // Unscored + Auto ⇒ refused, and the candidate is left untouched.
        let err = promote(&mut store, "c1", PromotionMode::Auto { score_threshold: 0.5 }, "t").unwrap_err();
        assert!(
            matches!(err, ReviewError::FailClosed(_)),
            "unscored auto-promote must fail closed"
        );
        assert_eq!(get_candidate(&store, "c1").unwrap().status, CandidateStatus::Candidate);
        // No real fact leaked into recall.
        assert!(real_fact_present(&store, "person:user", "owns_cat_count").is_none());
    }

    #[test]
    fn auto_promote_refuses_below_threshold() {
        let mut store = FactStore::new();
        write_candidate(&mut store, &scored_body("c1", 0.10), None).unwrap();
        let err = promote(&mut store, "c1", PromotionMode::Auto { score_threshold: 0.5 }, "t").unwrap_err();
        assert!(matches!(err, ReviewError::FailClosed(_)));
        assert!(real_fact_present(&store, "person:user", "owns_cat_count").is_none());
    }

    #[test]
    fn auto_promote_succeeds_when_scored_above_threshold() {
        let mut store = FactStore::new();
        write_candidate(&mut store, &scored_body("c1", 0.90), None).unwrap();
        let fid = promote(&mut store, "c1", PromotionMode::Auto { score_threshold: 0.5 }, "t").unwrap();
        assert!(!fid.is_empty());
        // The real fact is now present and recallable (NOT private).
        let real = real_fact_present(&store, "person:user", "owns_cat_count").expect("promoted fact present");
        assert_eq!(real.value, "3");
        assert!(!real.private, "a promoted normal fact must be recallable, not private");
        assert!(real.source_receipt.as_deref() == Some("__candidate_fact__::c1"));
        assert_eq!(get_candidate(&store, "c1").unwrap().status, CandidateStatus::Promoted);
    }

    #[test]
    fn explicit_promote_always_succeeds_even_unscored() {
        let mut store = FactStore::new();
        write_candidate(&mut store, &sample_body("c1"), None).unwrap();
        let fid = promote(
            &mut store,
            "c1",
            PromotionMode::Explicit {
                reviewer: "myles".to_string(),
            },
            "t",
        )
        .unwrap();
        assert!(!fid.is_empty());
        let real = real_fact_present(&store, "person:user", "owns_cat_count").expect("promoted fact present");
        assert_eq!(real.actor.as_deref(), Some("auto-capture:promoted-by:myles"));
        assert_eq!(get_candidate(&store, "c1").unwrap().status, CandidateStatus::Promoted);
    }

    #[test]
    fn reject_then_repromote_is_reversible() {
        let mut store = FactStore::new();
        write_candidate(&mut store, &sample_body("c1"), None).unwrap();
        reject(&mut store, "c1", "hallucinated", "t").unwrap();
        let c = get_candidate(&store, "c1").unwrap();
        assert_eq!(c.status, CandidateStatus::Rejected);
        assert_eq!(c.reject_reason.as_deref(), Some("hallucinated"));
        assert!(real_fact_present(&store, "person:user", "owns_cat_count").is_none());
        // Reversible: re-promote a rejected candidate.
        promote(
            &mut store,
            "c1",
            PromotionMode::Explicit {
                reviewer: "myles".to_string(),
            },
            "t2",
        )
        .unwrap();
        assert_eq!(get_candidate(&store, "c1").unwrap().status, CandidateStatus::Promoted);
        assert!(real_fact_present(&store, "person:user", "owns_cat_count").is_some());
    }

    #[test]
    fn promote_twice_and_reject_promoted_are_refused() {
        let mut store = FactStore::new();
        write_candidate(&mut store, &sample_body("c1"), None).unwrap();
        promote(
            &mut store,
            "c1",
            PromotionMode::Explicit {
                reviewer: "m".to_string(),
            },
            "t",
        )
        .unwrap();
        assert_eq!(
            promote(
                &mut store,
                "c1",
                PromotionMode::Explicit {
                    reviewer: "m".to_string()
                },
                "t"
            ),
            Err(ReviewError::AlreadyPromoted)
        );
        assert_eq!(reject(&mut store, "c1", "x", "t"), Err(ReviewError::AlreadyPromoted));
    }

    #[test]
    fn promote_missing_candidate_is_not_found() {
        let mut store = FactStore::new();
        assert_eq!(
            promote(
                &mut store,
                "nope",
                PromotionMode::Explicit {
                    reviewer: "m".to_string()
                },
                "t"
            ),
            Err(ReviewError::NotFound)
        );
    }
}
