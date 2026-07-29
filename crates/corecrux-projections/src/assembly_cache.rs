// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! G21b — assembly cache + hosted-offload dedup (ExecPlan
//! `context-mediation-injection-2026-06-11`, M6).
//!
//! Two cache layers, deliberately distinct from the G21a lever:
//!
//! 1. **Assembly cache** — a daemon-side memo of assembled
//!    [`crate::context_bundle::ContextBundle`]s keyed by
//!    `(passport, session, facts_chain_head)`. Invalidation is *structural*:
//!    a fact write moves the chain head, so the next lookup misses — no
//!    invalidation bus, no staleness window. The cache merely avoids
//!    re-running selection/rendering when nothing changed (byte-stability of
//!    the output is already guaranteed by the assembler; this saves the work,
//!    not the bytes).
//! 2. **Hosted dedup** — identical `(tenant, query, corpus, lane_flags)`
//!    within a TTL serves the cached result **without credit spend**
//!    (anti-double-billing). The receipt for a deduped serve records
//!    `served_from_cache: true` plus the origin `run_id`, so the trail shows
//!    both that the user was served and that no second execution happened.
//!
//! Reconciliation invariant (tested here, restated in the G20 spec): **dedup
//! never double-spends credits** — spend happens iff the executor ran.
//! Free-tier/local surfaces don't meter spend at all; the dedup layer is for
//! hosted offload only.
//!
//! Both layers are pure state machines: caller-supplied clock, deterministic
//! eviction (insertion order), no I/O — same posture as the assembler.

use std::collections::BTreeMap;

use crate::context_bundle::ContextBundle;

// ---------------------------------------------------------------------------
// Layer 1: assembly cache
// ---------------------------------------------------------------------------

/// Cache key for one assembled bundle.
///
/// `facts_chain_head` is the daemon's identifier for the current head of the
/// caller-visible fact chain (last fact/receipt id or a digest over it). Any
/// fact write moves it, which IS the invalidation mechanism.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AssemblyKey {
    pub passport: String,
    pub session_id: Option<String>,
    pub facts_chain_head: String,
}

#[derive(Debug, Clone)]
struct AssemblyEntry {
    bundle: ContextBundle,
    inserted_seq: u64,
}

/// Hit/miss counters (observability; surfaced via `/v1/quota`-style probes
/// later — additive, never load-bearing).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
}

/// Bounded memo of assembled bundles. Eviction is deterministic: when full,
/// the oldest-inserted entry goes first (insertion order, not recency — a
/// replayed call sequence evicts identically).
#[derive(Debug)]
pub struct AssemblyCache {
    max_entries: usize,
    seq: u64,
    entries: BTreeMap<AssemblyKey, AssemblyEntry>,
    stats: CacheStats,
}

impl AssemblyCache {
    /// `max_entries` is clamped to ≥1.
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            seq: 0,
            entries: BTreeMap::new(),
            stats: CacheStats::default(),
        }
    }

    pub fn stats(&self) -> CacheStats {
        self.stats
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Look up an assembled bundle. A miss means the caller should run the
    /// assembler and [`AssemblyCache::insert`] the result.
    pub fn get(&mut self, key: &AssemblyKey) -> Option<&ContextBundle> {
        if self.entries.contains_key(key) {
            self.stats.hits += 1;
            self.entries.get(key).map(|e| &e.bundle)
        } else {
            self.stats.misses += 1;
            None
        }
    }

    /// Insert an assembled bundle, evicting the oldest entry when full.
    pub fn insert(&mut self, key: AssemblyKey, bundle: ContextBundle) {
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.inserted_seq)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.seq += 1;
        self.entries.insert(
            key,
            AssemblyEntry {
                bundle,
                inserted_seq: self.seq,
            },
        );
    }

    /// Drop every entry for a passport regardless of chain head. Not needed
    /// for correctness (chain-head movement already invalidates) — this is
    /// the operator hammer for privacy events (passport revoked, facts
    /// hard-deleted out-of-band).
    pub fn purge_passport(&mut self, passport: &str) -> usize {
        let before = self.entries.len();
        self.entries.retain(|k, _| k.passport != passport);
        before - self.entries.len()
    }
}

// ---------------------------------------------------------------------------
// Layer 2: hosted dedup
// ---------------------------------------------------------------------------

/// Identity of one hosted retrieval execution. `tenant_id` is part of the
/// key by construction (T.1): identical queries from different tenants are
/// different executions, full stop.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DedupKey {
    pub tenant_id: String,
    pub query: String,
    pub corpus: String,
    /// Canonicalized lane flags (caller sorts; the key is byte-compared).
    pub lane_flags: String,
}

/// A cached hosted result plus its billing provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupEntry {
    /// Opaque serialized result payload (the daemon stores the envelope).
    pub result: String,
    /// `run_id` of the execution that paid for this result.
    pub origin_run_id: String,
    pub stored_at_secs: u64,
}

/// What a dedup-aware serve looked like — feeds both the receipt and the
/// ledger. `credits_charged == 0` iff `served_from_cache`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeOutcome {
    pub result: String,
    pub served_from_cache: bool,
    pub credits_charged: u64,
    pub run_id: String,
    pub cache_age_secs: u64,
}

impl ServeOutcome {
    /// Receipt annotation fields for this serve (merged into the mediation /
    /// memory-use receipt body by the daemon). A deduped serve is still a
    /// serve — the trail records it, with the origin run it rode on.
    pub fn receipt_fields(&self) -> serde_json::Value {
        serde_json::json!({
            "served_from_cache": self.served_from_cache,
            "run_id": self.run_id,
            "cache_age_secs": if self.served_from_cache { Some(self.cache_age_secs) } else { None },
            "credits_charged": self.credits_charged,
        })
    }
}

/// TTL'd dedup cache for hosted offload. Pure: caller supplies the clock.
#[derive(Debug)]
pub struct DedupCache {
    ttl_secs: u64,
    max_entries: usize,
    seq: u64,
    entries: BTreeMap<DedupKey, (DedupEntry, u64)>,
}

impl DedupCache {
    pub fn new(ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            ttl_secs,
            max_entries: max_entries.max(1),
            seq: 0,
            entries: BTreeMap::new(),
        }
    }

    /// Fresh-entry lookup; expired entries are treated as absent (and
    /// dropped lazily).
    pub fn lookup(&mut self, key: &DedupKey, now_secs: u64) -> Option<DedupEntry> {
        let expired = match self.entries.get(key) {
            Some((entry, _)) => now_secs.saturating_sub(entry.stored_at_secs) > self.ttl_secs,
            None => return None,
        };
        if expired {
            self.entries.remove(key);
            return None;
        }
        self.entries.get(key).map(|(e, _)| e.clone())
    }

    pub fn insert(&mut self, key: DedupKey, entry: DedupEntry) {
        if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
            if let Some(oldest) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, seq))| *seq)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.seq += 1;
        self.entries.insert(key, (entry, self.seq));
    }

    /// Serve one hosted request with dedup-aware billing.
    ///
    /// On a fresh cache hit: returns the cached result, charges **zero**
    /// credits, does not run `execute`. On a miss: runs `execute` (which
    /// returns the result payload and its `run_id`), charges `cost_credits`,
    /// caches the result. This function is the single place the
    /// never-double-spend invariant lives.
    pub fn serve(
        &mut self,
        key: DedupKey,
        now_secs: u64,
        cost_credits: u64,
        execute: impl FnOnce() -> (String, String),
    ) -> ServeOutcome {
        if let Some(entry) = self.lookup(&key, now_secs) {
            return ServeOutcome {
                result: entry.result,
                served_from_cache: true,
                credits_charged: 0,
                run_id: entry.origin_run_id,
                cache_age_secs: now_secs.saturating_sub(entry.stored_at_secs),
            };
        }
        let (result, run_id) = execute();
        self.insert(
            key,
            DedupEntry {
                result: result.clone(),
                origin_run_id: run_id.clone(),
                stored_at_secs: now_secs,
            },
        );
        ServeOutcome {
            result,
            served_from_cache: false,
            credits_charged: cost_credits,
            run_id,
            cache_age_secs: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context_bundle::{assemble, BundleRequest, FactInput};
    use crate::decay::{DecayPolicy, HorizonClass};

    const T0: u64 = 1_781_222_400;

    fn fact(entity: &str, key: &str, value: &str) -> FactInput {
        FactInput {
            fact_id: format!("f_{entity}_{key}"),
            entity: entity.into(),
            key: key.into(),
            value: value.into(),
            confidence: 1.0,
            written_ms: 1_781_000_000_000,
            horizon_class: HorizonClass::Stable,
            version: 1,
            superseded: false,
            private: false,
            owner: None,
            est_tokens: None,
            addressed: false,
        }
    }

    fn request(actor: &str) -> BundleRequest {
        BundleRequest {
            actor: actor.into(),
            tenant_id: "t1".into(),
            session_id: Some("s1".into()),
            requested_budget: 2_000,
            ceiling: 8_000,
            now_ms: 1_781_222_400_000,
            policy: DecayPolicy::default(),
        }
    }

    fn bundle_for(actor: &str) -> crate::context_bundle::ContextBundle {
        assemble(&request(actor), vec![fact("e", "k", "v")], Vec::new())
    }

    fn key(passport: &str, head: &str) -> AssemblyKey {
        AssemblyKey {
            passport: passport.into(),
            session_id: Some("s1".into()),
            facts_chain_head: head.into(),
        }
    }

    #[test]
    fn assembly_cache_hits_on_same_chain_head() {
        let mut cache = AssemblyCache::new(8);
        let k = key("p1", "head-a");
        assert!(cache.get(&k).is_none());
        let bundle = bundle_for("p1");
        let expected_hash = bundle.stable_hash.clone();
        cache.insert(k.clone(), bundle);
        let hit = cache.get(&k).expect("hit after insert");
        assert_eq!(hit.stable_hash, expected_hash);
        assert_eq!(cache.stats(), CacheStats { hits: 1, misses: 1 });
    }

    #[test]
    fn fact_write_invalidates_structurally_via_chain_head() {
        let mut cache = AssemblyCache::new(8);
        cache.insert(key("p1", "head-a"), bundle_for("p1"));
        // A fact write moved the head: head-b misses without any
        // invalidation call.
        assert!(cache.get(&key("p1", "head-b")).is_none());
        // The old head still hits (replay/audit path).
        assert!(cache.get(&key("p1", "head-a")).is_some());
    }

    #[test]
    fn eviction_is_bounded_and_oldest_first() {
        let mut cache = AssemblyCache::new(2);
        cache.insert(key("p1", "h1"), bundle_for("p1"));
        cache.insert(key("p1", "h2"), bundle_for("p1"));
        cache.insert(key("p1", "h3"), bundle_for("p1"));
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&key("p1", "h1")).is_none(), "oldest evicted");
        assert!(cache.get(&key("p1", "h2")).is_some());
        assert!(cache.get(&key("p1", "h3")).is_some());
    }

    #[test]
    fn purge_passport_is_the_privacy_hammer() {
        let mut cache = AssemblyCache::new(8);
        cache.insert(key("p1", "h1"), bundle_for("p1"));
        cache.insert(key("p1", "h2"), bundle_for("p1"));
        cache.insert(key("p2", "h1"), bundle_for("p2"));
        assert_eq!(cache.purge_passport("p1"), 2);
        assert!(cache.get(&key("p1", "h1")).is_none());
        assert!(cache.get(&key("p2", "h1")).is_some());
    }

    fn dkey(tenant: &str, query: &str) -> DedupKey {
        DedupKey {
            tenant_id: tenant.into(),
            query: query.into(),
            corpus: "LME-S".into(),
            lane_flags: "dense,fused".into(),
        }
    }

    #[test]
    fn dedup_never_double_spends_within_ttl() {
        let mut cache = DedupCache::new(300, 64);
        let mut ledger_spend = 0u64;
        let mut executions = 0u32;
        for i in 0..5u64 {
            let outcome = cache.serve(dkey("t1", "q"), T0 + i * 10, 7, || {
                executions += 1;
                ("result-payload".into(), format!("run-{executions}"))
            });
            ledger_spend += outcome.credits_charged;
            assert_eq!(outcome.result, "result-payload");
            assert_eq!(outcome.served_from_cache, i > 0);
            // Every serve, cached or not, points at the run that paid.
            assert_eq!(outcome.run_id, "run-1");
        }
        assert_eq!(executions, 1, "one execution for five identical requests");
        assert_eq!(ledger_spend, 7, "exactly one spend — dedup never double-bills");
    }

    #[test]
    fn ttl_expiry_is_a_fresh_execution_and_a_fresh_spend() {
        let mut cache = DedupCache::new(300, 64);
        let mut executions = 0u32;
        let mut run = |now: u64| {
            cache.serve(dkey("t1", "q"), now, 7, || {
                executions += 1;
                ("r".into(), format!("run-{executions}"))
            })
        };
        let first = run(T0);
        let cached = run(T0 + 300);
        let expired = run(T0 + 601);
        assert_eq!(first.credits_charged, 7);
        assert_eq!(cached.credits_charged, 0);
        assert!(cached.served_from_cache);
        assert_eq!(cached.cache_age_secs, 300);
        assert_eq!(expired.credits_charged, 7, "post-TTL serve is a real execution");
        assert_eq!(expired.run_id, "run-2");
        assert_eq!(executions, 2);
    }

    #[test]
    fn tenants_never_share_dedup_entries() {
        let mut cache = DedupCache::new(300, 64);
        let mut executions = 0u32;
        let a = cache.serve(dkey("t1", "q"), T0, 5, || {
            executions += 1;
            ("t1-result".into(), "run-a".into())
        });
        // Identical (query, corpus, lane_flags), different tenant: MUST miss.
        let b = cache.serve(dkey("t2", "q"), T0, 5, || {
            executions += 1;
            ("t2-result".into(), "run-b".into())
        });
        assert_eq!(executions, 2);
        assert!(!b.served_from_cache);
        assert_eq!(a.result, "t1-result");
        assert_eq!(b.result, "t2-result");
    }

    #[test]
    fn lane_flags_and_corpus_are_part_of_identity() {
        let mut cache = DedupCache::new(300, 64);
        let mut executions = 0u32;
        let mut exec = || {
            executions += 1;
            ("r".into(), format!("run-{executions}"))
        };
        let base = dkey("t1", "q");
        let _ = cache.serve(base.clone(), T0, 1, &mut exec);
        let mut other_corpus = base.clone();
        other_corpus.corpus = "LME-M".into();
        let _ = cache.serve(other_corpus, T0, 1, &mut exec);
        let mut other_flags = base;
        other_flags.lane_flags = "dense".into();
        let _ = cache.serve(other_flags, T0, 1, &mut exec);
        assert_eq!(executions, 3, "corpus and lane_flags changes are distinct executions");
    }

    #[test]
    fn receipt_fields_record_cache_provenance() {
        let mut cache = DedupCache::new(300, 64);
        let _ = cache.serve(dkey("t1", "q"), T0, 3, || ("r".into(), "run-1".into()));
        let cached = cache.serve(dkey("t1", "q"), T0 + 42, 3, || ("never".into(), "x".into()));
        let fields = cached.receipt_fields();
        assert_eq!(fields["served_from_cache"], true);
        assert_eq!(fields["run_id"], "run-1");
        assert_eq!(fields["cache_age_secs"], 42);
        assert_eq!(fields["credits_charged"], 0);

        let fresh_fields = DedupCache::new(300, 4)
            .serve(dkey("t1", "q2"), T0, 3, || ("r".into(), "run-9".into()))
            .receipt_fields();
        assert_eq!(fresh_fields["served_from_cache"], false);
        assert!(fresh_fields["cache_age_secs"].is_null());
        assert_eq!(fresh_fields["credits_charged"], 3);
    }

    #[test]
    fn dedup_eviction_is_bounded() {
        let mut cache = DedupCache::new(300, 2);
        for q in ["a", "b", "c"] {
            let _ = cache.serve(dkey("t1", q), T0, 1, || ("r".into(), format!("run-{q}")));
        }
        // "a" evicted: serving it again is a fresh execution.
        let again = cache.serve(dkey("t1", "a"), T0, 1, || ("r2".into(), "run-a2".into()));
        assert!(!again.served_from_cache);
    }
}
