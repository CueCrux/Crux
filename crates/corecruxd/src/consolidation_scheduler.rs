// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Consolidation review scheduler (Audit II gap-closure M4).
//!
//! Periodically runs the read-only contradiction-candidate pass
//! ([`corecrux_memory::FactStore::contradiction_candidates_v1`]) and
//! SURFACES the result as an append-only receipt fact under
//! `__consolidation_review__::<run_id>`. This is the M1/M2 operator-surfacing
//! background hook: it makes the otherwise-dormant cross-entity contradiction
//! pass run on a config-driven cadence so an operator (or the console review
//! panel) sees fresh candidates without having to poll the MCP tool by hand.
//!
//! ## Detect + surface only — never auto-resolve (safety-critical)
//!
//! The scheduler NEVER consolidates, supersedes, or deletes anything. It only
//! reads and writes one bookkeeping receipt per tick. Resolution stays an
//! EXPLICIT operator action through the `memory_consolidate` MCP tool or
//! `POST /v1/console/review/consolidations` — both of which require an
//! authenticated actor and run the full `ConsolidationRequestV1` protection
//! guards. Keeping resolution explicit is the whole point: an automatic
//! collapser could silently lose a fact.
//!
//! ## Protections honoured when surfacing
//!
//! The underlying pass already skips deleted + cross-entity-superseded facts,
//! so a freshly-resolved conflict stops being surfaced. On top of that, a
//! candidate group is dropped from the surfaced set when EVERY member is
//! protected (pinned via `__memory_pin::`, receipt-linked, private, or
//! confidence at/above [`PROTECTED_CONFIDENCE_FLOOR`]) — because such a group
//! is not actionable by `memory_consolidate` anyway (its guards would reject
//! every target). This mirrors the decay-class/confidence protection the M2
//! consolidation path enforces.
//!
//! Gated by `CORECRUXD_CONSOLIDATION_SCHEDULER=1` (default OFF;
//! [`crate::config::Config::consolidation_scheduler_enabled`]). The interval
//! is config-driven via `CORECRUXD_CONSOLIDATION_SCHEDULER_INTERVAL_SECS`
//! (default hourly).

use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::Utc;
use tokio::sync::{broadcast, RwLock};

use corecrux_memory::fact_store::{ContradictionCandidateV1, StoreFact};
use corecrux_memory::{Fact, FactStore, HorizonClass};
use corecrux_projections::decay::{self, Freshness};

/// Receipt-fact entity prefix the scheduler writes each surfaced run under.
/// Reserved (`__…__::`) so it is born private and is filtered from the
/// agent-facing memory panel / freshness listings.
pub const REVIEW_ENTITY_PREFIX: &str = "__consolidation_review__::";

/// Pin-state prefix (mirrors `crux_mcp::tools::memory` / `corecruxctl::memory`).
/// A fact whose id is the suffix of a pin entity is operator-pinned.
const MEMORY_PIN_PREFIX: &str = "__memory_pin::";

/// Confidence at/above which a fact is treated as protected (matches the
/// `ConsolidationRequestV1::protected_confidence_floor` default).
pub const PROTECTED_CONFIDENCE_FLOOR: f32 = 0.99;

/// Stored confidence strictly below which an (unprotected) fact is surfaced as
/// a low-confidence expiry PROPOSAL (P1 widen). Deliberately conservative — the
/// scheduler only surfaces; the operator applies. ponytail: fixed constant, make
/// it config-driven only if a workload actually needs a different floor.
pub const LOW_CONFIDENCE_EXPIRY_CEIL: f32 = 0.3;

/// Default tick interval if the config clamp somehow yields zero: hourly.
const DEFAULT_INTERVAL_SECS: u64 = 3600;

/// Decide whether a single fact is protected from consolidation. A group is
/// only surfaced if at least one member is NOT protected (i.e. is actionable).
fn fact_is_protected(fact: &Fact, pinned_ids: &std::collections::HashSet<String>) -> bool {
    fact.private
        || fact.source_receipt.is_some()
        || fact.confidence >= PROTECTED_CONFIDENCE_FLOOR
        || pinned_ids.contains(&fact.fact_id)
}

/// Collect the set of pinned fact_ids from `__memory_pin::*` records whose
/// value is "1". The pin entity encodes the target fact_id as its trailing
/// path segment (`__memory_pin::<scope>::<fact_id>`).
fn pinned_fact_ids(facts: &[Fact]) -> std::collections::HashSet<String> {
    let mut out = std::collections::HashSet::new();
    for f in facts {
        if !f.entity.starts_with(MEMORY_PIN_PREFIX) {
            continue;
        }
        if f.key != "pinned" || f.value != "1" || f.deleted {
            continue;
        }
        if let Some(target) = f.entity.rsplit("::").next() {
            if !target.is_empty() {
                out.insert(target.to_string());
            }
        }
    }
    out
}

/// Pure selection: given the full fact slice, return the actionable
/// contradiction candidates (groups with at least one unprotected member).
///
/// Mirrors what the scheduler surfaces; factored out so it is testable
/// without a running task. `limit` bounds the underlying pass.
pub fn select_actionable_candidates(store: &FactStore, facts: &[Fact], limit: usize) -> Vec<ContradictionCandidateV1> {
    let pinned = pinned_fact_ids(facts);
    let by_id: std::collections::HashMap<&str, &Fact> = facts.iter().map(|f| (f.fact_id.as_str(), f)).collect();

    store
        .contradiction_candidates_v1(limit)
        .into_iter()
        .filter(|c| {
            // Keep the group only if some member is actionable (unprotected).
            c.fact_ids.iter().any(|id| match by_id.get(id.as_str()) {
                Some(fact) => !fact_is_protected(fact, &pinned),
                // A candidate fact we can't resolve to a record is conservatively
                // treated as actionable (so we never hide a real conflict).
                None => true,
            })
        })
        .collect()
}

/// A read-only expiry PROPOSAL surfaced by the hygiene loop (P1 widen): a fact
/// the loop suggests retiring, plus the reason. The scheduler NEVER expires
/// anything — this only lands in the review receipt for an operator to apply
/// (age-based via `POST /v1/console/review/expiries` → `mark_retention_eligible`,
/// or per-fact via the existing delete/consolidate surfaces).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct ExpiryCandidateV1 {
    pub fact_id: String,
    pub entity: String,
    pub key: String,
    /// `stale_past_horizon` | `low_confidence` | `stale_and_low_confidence`.
    pub reason: String,
    pub confidence: f32,
    pub stored_at: String,
}

/// Pure selection: return unprotected, active facts that are stale past their
/// freshness horizon and/or below the low-confidence ceiling. Read-only; mirrors
/// exactly what the scheduler surfaces so it is unit-testable without a task.
///
/// Protection reuses [`fact_is_protected`] (private, receipt-linked, pinned, or
/// at/above [`PROTECTED_CONFIDENCE_FLOOR`]) so the loop never proposes retiring
/// its own bookkeeping receipts, pinned facts, or receipt-linked evidence.
pub fn select_expiry_candidates(
    facts: &[Fact],
    now: chrono::DateTime<Utc>,
    policy: decay::DecayPolicy,
    limit: usize,
) -> Vec<ExpiryCandidateV1> {
    let pinned = pinned_fact_ids(facts);
    let mut out = Vec::new();
    for fact in facts {
        if out.len() >= limit {
            break;
        }
        if fact.deleted || fact.superseded_by.is_some() || fact_is_protected(fact, &pinned) {
            continue;
        }
        let stale = crux_mcp::tools::freshness::fact_freshness(fact, now, policy) == Freshness::Stale;
        let low_conf = fact.confidence < LOW_CONFIDENCE_EXPIRY_CEIL;
        if !stale && !low_conf {
            continue;
        }
        let reason = match (stale, low_conf) {
            (true, true) => "stale_and_low_confidence",
            (true, false) => "stale_past_horizon",
            (false, true) => "low_confidence",
            (false, false) => unreachable!(),
        };
        out.push(ExpiryCandidateV1 {
            fact_id: fact.fact_id.clone(),
            entity: fact.entity.clone(),
            key: fact.key.clone(),
            reason: reason.to_string(),
            confidence: fact.confidence,
            stored_at: fact.stored_at.to_rfc3339(),
        });
    }
    out
}

/// Run one surfacing pass against the store. Reads candidates under a read
/// lock, then appends a single review-receipt fact under a write lock.
/// Returns the number of actionable candidates surfaced (0 = no receipt
/// written — a clean store produces no noise).
pub async fn run_review_once(store: &Arc<RwLock<FactStore>>, limit: usize) -> usize {
    let surfaced_at = Utc::now();
    let (candidates, expiry_candidates, run_id) = {
        let guard = store.read().await;
        let facts: Vec<Fact> = guard.all_facts().cloned().collect();
        let candidates = select_actionable_candidates(&guard, &facts, limit);
        // P1 widen: also propose stale-past-horizon + low-confidence facts as
        // (read-only) expiry proposals, using the SAME decay logic recall ranks
        // by so "stale" means one thing across the daemon.
        let policy = decay::DecayPolicy::from_env();
        let expiry_candidates = select_expiry_candidates(&facts, surfaced_at, policy, limit);
        (
            candidates,
            expiry_candidates,
            format!("run_{}", uuid::Uuid::new_v4().simple()),
        )
    };
    if candidates.is_empty() && expiry_candidates.is_empty() {
        return 0;
    }

    let body = serde_json::json!({
        "schema": "crux.consolidation_review.v1",
        "run_id": run_id,
        "surfaced_at": surfaced_at.to_rfc3339(),
        "count": candidates.len(),
        "expiry_count": expiry_candidates.len(),
        "resolution": "explicit",
        "note": "detect+surface only; resolve contradictions via memory_consolidate or the console review route; apply expiry proposals via POST /v1/console/review/expiries or per-fact delete",
        "candidates": candidates,
        "expiry_candidates": expiry_candidates,
    });

    // Append-only receipt fact. Stable (never decays) so an audit replay can
    // always find the surfacing event; the scheduler is the only writer.
    let req = StoreFact {
        tenant_hash: "default".to_string(),
        entity: format!("{REVIEW_ENTITY_PREFIX}{run_id}"),
        key: "review".to_string(),
        value: body.to_string(),
        source_receipt: Some(run_id.clone()),
        confidence: 1.0,
        private: false,
        horizon_class: Some(HorizonClass::Stable),
        actor: Some("consolidation-scheduler".to_string()),
    };

    let mut guard = store.write().await;
    if let Err(err) = guard.try_store(req) {
        tracing::warn!(?err, "consolidation-review-receipt-append-failed");
    }
    candidates.len() + expiry_candidates.len()
}

/// Spawn the background consolidation-review task, mirroring
/// [`crate::ephemeral_gc::spawn_ephemeral_gc`].
///
/// Gated at spawn: only started when `enabled` is true. The flag + interval
/// are read once at boot (toggling requires a restart — same convention as
/// the other `CORECRUXD_*` background-task flags). Runs every
/// `interval_secs` until the shutdown signal is received.
pub fn spawn_consolidation_scheduler(
    enabled: bool,
    interval_secs: u64,
    store: Arc<RwLock<FactStore>>,
    mut shutdown: broadcast::Receiver<()>,
) {
    if !enabled {
        return;
    }
    let interval_secs = if interval_secs == 0 {
        DEFAULT_INTERVAL_SECS
    } else {
        interval_secs
    };
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(StdDuration::from_secs(interval_secs));
        // Skip the immediate first tick so we don't sweep mid-boot before the
        // store has finished replaying.
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let n = run_review_once(&store, 200).await;
                    if n > 0 {
                        tracing::info!(surfaced = n, "consolidation-review-surfaced");
                    }
                }
                _ = shutdown.recv() => break,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_fact(store: &mut FactStore, entity: &str, key: &str, value: &str, confidence: f32, private: bool) -> Fact {
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: value.to_string(),
            source_receipt: None,
            confidence,
            private,
            horizon_class: None,
            actor: None,
        })
    }

    /// Seed two active, opposite-polarity facts under (entity, key). The
    /// second store auto-supersedes the first (same version chain), so clear
    /// it to simulate an unresolved conflict — exactly what M1 surfaces.
    fn seed_conflict(store: &mut FactStore, entity: &str, key: &str, conf: f32) -> (String, String) {
        let a = store_fact(store, entity, key, "enabled", conf, false);
        let b = store_fact(store, entity, key, "disabled", conf, false);
        store.clear_superseded(&a.fact_id);
        (a.fact_id, b.fact_id)
    }

    #[test]
    fn surfaces_actionable_conflict() {
        let mut store = FactStore::new();
        seed_conflict(&mut store, "service:api", "enabled", 0.7);
        let facts: Vec<Fact> = store.all_facts().cloned().collect();
        let surfaced = select_actionable_candidates(&store, &facts, 50);
        assert_eq!(surfaced.len(), 1, "one actionable contradiction");
        assert_eq!(surfaced[0].entity, "service:api");
    }

    #[test]
    fn drops_group_where_every_member_is_high_confidence() {
        let mut store = FactStore::new();
        // Both members at/above the protected floor → group is not actionable.
        seed_conflict(&mut store, "service:api", "enabled", 1.0);
        let facts: Vec<Fact> = store.all_facts().cloned().collect();
        let surfaced = select_actionable_candidates(&store, &facts, 50);
        assert!(
            surfaced.is_empty(),
            "all-protected group must not be surfaced, got {surfaced:?}"
        );
    }

    #[test]
    fn keeps_group_with_one_actionable_member() {
        let mut store = FactStore::new();
        // One protected (high-confidence) + one actionable (low-confidence)
        // under the same (entity, key): still surfaced, since the operator
        // could consolidate the actionable one.
        let a = store_fact(&mut store, "svc", "on", "enabled", 1.0, false);
        let b = store_fact(&mut store, "svc", "on", "disabled", 0.5, false);
        store.clear_superseded(&a.fact_id);
        let _ = b;
        let facts: Vec<Fact> = store.all_facts().cloned().collect();
        let surfaced = select_actionable_candidates(&store, &facts, 50);
        assert_eq!(surfaced.len(), 1);
    }

    #[test]
    fn pinned_facts_are_protected() {
        let mut store = FactStore::new();
        let (a_id, b_id) = seed_conflict(&mut store, "svc", "flag", 0.5);
        // Pin BOTH members → group not actionable.
        store_fact(
            &mut store,
            &format!("{MEMORY_PIN_PREFIX}cli::{a_id}"),
            "pinned",
            "1",
            1.0,
            false,
        );
        store_fact(
            &mut store,
            &format!("{MEMORY_PIN_PREFIX}cli::{b_id}"),
            "pinned",
            "1",
            1.0,
            false,
        );
        let facts: Vec<Fact> = store.all_facts().cloned().collect();
        let surfaced = select_actionable_candidates(&store, &facts, 50);
        assert!(surfaced.is_empty(), "both-pinned group must not be surfaced");
    }

    #[tokio::test]
    async fn run_review_once_writes_receipt_and_does_not_mutate_targets() {
        let store = Arc::new(RwLock::new(FactStore::new()));
        let (a_id, b_id) = {
            let mut g = store.write().await;
            seed_conflict(&mut g, "service:api", "enabled", 0.7)
        };

        let n = run_review_once(&store, 200).await;
        assert_eq!(n, 1, "one candidate surfaced");

        let g = store.read().await;
        // A review receipt was written under the reserved prefix.
        let receipt = g
            .all_facts()
            .find(|f| f.entity.starts_with(REVIEW_ENTITY_PREFIX))
            .expect("review receipt written");
        assert!(receipt.value.contains("crux.consolidation_review.v1"));
        assert!(receipt.value.contains("\"resolution\":\"explicit\""));

        // Detect+surface only: the conflicting facts are untouched.
        assert!(g.get(&a_id).unwrap().superseded_by.is_none(), "target a not resolved");
        assert!(g.get(&b_id).unwrap().superseded_by.is_none(), "target b not resolved");
        assert!(!g.get(&a_id).unwrap().deleted);
        assert!(!g.get(&b_id).unwrap().deleted);
    }

    #[tokio::test]
    async fn run_review_once_clean_store_writes_no_receipt() {
        let store = Arc::new(RwLock::new(FactStore::new()));
        {
            let mut g = store.write().await;
            // A single, non-conflicting fact → no candidates.
            store_fact(&mut g, "p", "k", "enabled", 0.5, false);
        }
        let n = run_review_once(&store, 200).await;
        assert_eq!(n, 0, "clean store surfaces nothing");
        let g = store.read().await;
        assert!(
            !g.all_facts().any(|f| f.entity.starts_with(REVIEW_ENTITY_PREFIX)),
            "no receipt for an empty surfacing pass"
        );
    }

    // ── P1 widen: stale / low-confidence expiry proposals ───────────

    /// Build a Fact directly so `stored_at` can be backdated (mirrors the
    /// crux-mcp `synth_fact` approach; `store_synced` skips version logic).
    fn synth(fact_id: &str, entity: &str, conf: f32, horizon: HorizonClass, stored_at: chrono::DateTime<Utc>) -> Fact {
        Fact {
            fact_id: fact_id.to_string(),
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: "state".to_string(),
            value: "v".to_string(),
            source_receipt: None,
            confidence: conf,
            stored_at,
            tokens: 4,
            deleted: false,
            version: 1,
            supersedes: None,
            private: false,
            horizon_class: horizon,
            reverified_at: None,
            superseded_by: None,
            actor: None,
            valid_from: None,
            valid_to: None,
            access_count: 0,
            last_accessed_at: None,
        }
    }

    #[test]
    fn expiry_candidates_flag_low_confidence_and_stale() {
        let now = Utc::now();
        let policy = decay::DecayPolicy::from_env();
        let facts = vec![
            // Low confidence (< 0.3), fresh.
            synth("f_low", "svc", 0.1, HorizonClass::None, now),
            // Stale: volatile, 48h old (> 24h horizon), decent confidence.
            synth(
                "f_stale",
                "svc",
                0.8,
                HorizonClass::Volatile,
                now - chrono::Duration::hours(48),
            ),
            // Healthy: fresh + confident → not a candidate.
            synth("f_ok", "svc", 0.8, HorizonClass::None, now),
        ];
        let out = select_expiry_candidates(&facts, now, policy, 50);
        let ids: std::collections::HashSet<&str> = out.iter().map(|c| c.fact_id.as_str()).collect();
        assert!(ids.contains("f_low"), "low-confidence fact proposed");
        assert!(ids.contains("f_stale"), "stale fact proposed");
        assert!(!ids.contains("f_ok"), "fresh confident fact NOT proposed");
        let low = out.iter().find(|c| c.fact_id == "f_low").unwrap();
        assert_eq!(low.reason, "low_confidence");
        let stale = out.iter().find(|c| c.fact_id == "f_stale").unwrap();
        assert_eq!(stale.reason, "stale_past_horizon");
    }

    #[test]
    fn expiry_candidates_skip_protected_facts() {
        let now = Utc::now();
        let policy = decay::DecayPolicy::from_env();
        // High-confidence (>= PROTECTED_CONFIDENCE_FLOOR) but stale → protected,
        // so never proposed for expiry even though it is stale.
        let facts = vec![synth(
            "f_prot",
            "svc",
            1.0,
            HorizonClass::Volatile,
            now - chrono::Duration::hours(48),
        )];
        assert!(select_expiry_candidates(&facts, now, policy, 50).is_empty());
    }

    #[tokio::test]
    async fn run_review_once_surfaces_expiry_proposals_without_contradictions() {
        let store = Arc::new(RwLock::new(FactStore::new()));
        {
            let mut g = store.write().await;
            // A single low-confidence fact: no contradiction, but an expiry proposal.
            store_fact(&mut g, "svc", "flag", "maybe", 0.1, false);
        }
        let n = run_review_once(&store, 200).await;
        assert_eq!(n, 1, "one expiry proposal surfaced");
        let g = store.read().await;
        let receipt = g
            .all_facts()
            .find(|f| f.entity.starts_with(REVIEW_ENTITY_PREFIX))
            .expect("review receipt written");
        assert!(receipt.value.contains("\"expiry_count\":1"));
        assert!(receipt.value.contains("low_confidence"));
        // Detect+surface only: the fact itself is untouched.
        assert!(g.all_facts().any(|f| f.entity == "svc" && !f.deleted));
    }
}
