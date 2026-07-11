// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Ephemeral reserved-fact garbage collector.
//!
//! Daemon-minted bookkeeping facts accumulate forever in the durable fact
//! store, crowding `memory_view` recency and bloating recall:
//!
//! - `__session_binding__::<hex>` — minted every boot
//!   ([`crate::session_bindings`]).
//! - `__reverify_receipts__::*` — minted by `memory_reverify`
//!   (`crux_mcp::tools::freshness`).
//!
//! This module soft-deletes stale ones via the EXISTING journaled delete
//! path ([`corecrux_memory::FactStore::try_delete`]) — never raw
//! filesystem. Soft-delete is reversible: it appends a
//! `JournalEvent::Delete` tombstone, so the fact is replay-safe and still
//! present in-memory with `deleted = true` (visible via `all_facts()` /
//! `fact_history`), just hidden from `get`/`query`.
//!
//! Gated by `CORECRUXD_EPHEMERAL_GC=1` (default OFF;
//! [`crate::config::Config::ephemeral_gc_enabled`]). The GC NEVER touches
//! non-reserved user facts (private or not), and only ever the two ephemeral
//! prefixes above — each branch of [`select_ephemeral_candidates`] matches its
//! reserved prefix by name.
//!
//! ## Selection rule (safety-critical)
//!
//! - `__reverify_receipts__::*` — delete if `stored_at` is older than
//!   `retain` (default 30 days). Recent receipts are kept.
//! - `__session_binding__::<hex>` — bindings are minted one-per-MCP-session
//!   with a *unique* `session_id_hex`, so a churning client (e.g. a stateless
//!   bridge that re-`initialize`s every poll) accumulates unbounded durable
//!   facts. "Newest per entity" never reclaims this, because every binding is
//!   the sole record for its own entity. Instead: keep the newest
//!   [`SESSION_BINDING_KEEP_N`] bindings **per passport** (by `stored_at`); an
//!   older one is deletable ONLY if it is past the cap AND older than
//!   [`SESSION_BINDING_MIN_AGE_HOURS`] (a safety floor well above the coord
//!   presence TTL, so an active session's just-minted binding is never
//!   orphaned). Caps the durable population at ~`KEEP_N × #passports`.
//!
//! NOTE: these bookkeeping facts are stored `private = true` by
//! `fact_privacy::enforce_global`. The selector therefore does NOT skip
//! private facts wholesale — it scopes eligibility to the two reserved
//! prefixes *by name*, so churned-but-private bindings are reclaimable while
//! non-reserved user facts (private or not) are still never touched.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use tokio::sync::{broadcast, RwLock};

use corecrux_memory::{Fact, FactStore};

use crate::session_bindings::{SessionBinding, SESSION_BINDING_RECORD_KEY};

/// Default retain window for ephemeral facts: 30 days.
pub const DEFAULT_RETAIN_DAYS: i64 = 30;

/// Keep at most this many of the most-recently-stored session bindings per
/// passport. Beyond this, older bindings are reclaimable.
pub const SESSION_BINDING_KEEP_N: usize = 32;

/// Safety floor for session-binding collection: never collect a binding
/// younger than this even when it is beyond the per-passport cap. Set well
/// above the coordination-plane presence TTL (15 min) so that a live
/// session's just-minted binding is never orphaned.
pub const SESSION_BINDING_MIN_AGE_HOURS: i64 = 1;

/// Default GC tick interval: hourly.
const GC_INTERVAL_SECS: u64 = 3600;

/// Pure selection over a fact slice. Returns the `fact_id`s that the GC
/// would soft-delete, applying the conservative, reversible rule
/// documented at the module level.
///
/// Safety invariants (all enforced here, independent of caller):
/// - Only `__session_binding__::*` and `__reverify_receipts__::*` entities
///   are ever eligible — scoped by prefix, so non-reserved user facts
///   (including private ones) are never selected.
/// - Already-deleted facts are skipped (idempotent across ticks).
/// - The newest [`SESSION_BINDING_KEEP_N`] bindings per passport, and any
///   binding younger than the [`SESSION_BINDING_MIN_AGE_HOURS`] floor, are
///   always kept.
pub fn select_ephemeral_candidates(facts: &[Fact], now: DateTime<Utc>, retain: Duration) -> Vec<String> {
    let mut out = Vec::new();

    // `__reverify_receipts__::*` — age-based: any fact past `retain`.
    for f in facts {
        if f.deleted {
            continue;
        }
        if f.entity.starts_with("__reverify_receipts__::") && (now - f.stored_at) > retain {
            out.push(f.fact_id.clone());
        }
    }

    // `__session_binding__::*` — per-passport population cap. Each MCP session
    // mints a unique-id binding, so keep the newest KEEP_N per passport and
    // collect the rest once they age past the safety floor.
    let min_age = Duration::hours(SESSION_BINDING_MIN_AGE_HOURS);
    let mut by_passport: HashMap<String, Vec<(DateTime<Utc>, String)>> = HashMap::new();
    for f in facts {
        if f.deleted || !f.entity.starts_with("__session_binding__::") {
            continue;
        }
        if f.key != SESSION_BINDING_RECORD_KEY {
            continue;
        }
        // Attribute each binding to its passport; unparseable records are kept
        // (conservative — never collect something we cannot classify).
        let Ok(binding) = serde_json::from_str::<SessionBinding>(&f.value) else {
            continue;
        };
        by_passport
            .entry(binding.passport_id)
            .or_default()
            .push((f.stored_at, f.fact_id.clone()));
    }
    for (_passport, mut rows) in by_passport {
        // Newest first; protect the leading KEEP_N, collect aged-out remainder.
        rows.sort_by(|a, b| b.0.cmp(&a.0));
        for (stored_at, fact_id) in rows.into_iter().skip(SESSION_BINDING_KEEP_N) {
            if (now - stored_at) > min_age {
                out.push(fact_id);
            }
        }
    }
    out
}

/// Run one GC sweep against the store. Collects candidates under a read
/// lock, then soft-deletes each via the journaled
/// [`FactStore::try_delete`] under a write lock. Returns the number of
/// facts soft-deleted. Pure no-op when no candidates qualify.
pub async fn run_sweep_once(store: &Arc<RwLock<FactStore>>, now: DateTime<Utc>, retain: Duration) -> usize {
    let candidates = {
        let guard = store.read().await;
        let facts: Vec<Fact> = guard.all_facts().cloned().collect();
        select_ephemeral_candidates(&facts, now, retain)
    };
    if candidates.is_empty() {
        return 0;
    }
    let mut deleted = 0usize;
    let mut guard = store.write().await;
    for id in &candidates {
        match guard.try_delete(id) {
            Ok(true) => deleted += 1,
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(?err, fact_id = %id, "ephemeral-gc-delete-failed");
            }
        }
    }
    deleted
}

/// Spawn the background ephemeral GC task, mirroring
/// [`crate::update::spawn_update_checker`].
///
/// Gated at spawn: the task is only started when
/// `config.ephemeral_gc_enabled` is true. (The flag is read once at boot;
/// toggling it requires a restart — same convention as the other
/// `CORECRUXD_*` background-task flags.) The task runs hourly until the
/// shutdown signal is received.
pub fn spawn_ephemeral_gc(enabled: bool, store: Arc<RwLock<FactStore>>, mut shutdown: broadcast::Receiver<()>) {
    if !enabled {
        return;
    }
    let retain = Duration::days(DEFAULT_RETAIN_DAYS);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(StdDuration::from_secs(GC_INTERVAL_SECS));
        // First tick fires immediately; skip it so we don't sweep mid-boot
        // before the store has finished replaying.
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let n = run_sweep_once(&store, Utc::now(), retain).await;
                    if n > 0 {
                        tracing::info!(deleted = n, "ephemeral-gc-sweep");
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
    use corecrux_memory::fact_store::StoreFact;

    fn store_fact(store: &mut FactStore, entity: &str, key: &str, private: bool) -> Fact {
        store.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: key.to_string(),
            value: "{}".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private,
            horizon_class: None,
            actor: None,
        })
    }

    /// Forcibly backdate a fact's `stored_at` in the in-memory store by
    /// re-storing then patching — we drive selection through the pure fn
    /// on a hand-built slice instead, which is cleaner and deterministic.
    fn fact(entity: &str, fact_id: &str, stored_at: DateTime<Utc>, private: bool) -> Fact {
        Fact {
            fact_id: fact_id.to_string(),
            tenant_hash: "default".to_string(),
            entity: entity.to_string(),
            key: "record".to_string(),
            value: "{}".to_string(),
            source_receipt: None,
            confidence: 1.0,
            stored_at,
            tokens: 8,
            deleted: false,
            version: 1,
            supersedes: None,
            private,
            horizon_class: Default::default(),
            reverified_at: None,
            superseded_by: None,
            actor: None,
            valid_from: None,
            valid_to: None,
            access_count: 0,
            last_accessed_at: None,
        }
    }

    /// A session-binding fact carrying a real JSON `SessionBinding` value
    /// (the selector parses it for the passport). Stored `private = true` to
    /// mirror prod, where `fact_privacy::enforce_global` forces it.
    fn binding_fact(session_hex: &str, fact_id: &str, passport: &str, stored_at: DateTime<Utc>) -> Fact {
        let value = format!(
            r#"{{"session_id_hex":"{session_hex}","project_id":null,"tenant_id":"personal","passport_id":"{passport}","passport_category":"personal","agent_work_gate":false,"bound_at_unix_ms":0}}"#
        );
        Fact {
            fact_id: fact_id.to_string(),
            tenant_hash: "default".to_string(),
            entity: format!("__session_binding__::{session_hex}"),
            key: "record".to_string(),
            value,
            source_receipt: None,
            confidence: 1.0,
            stored_at,
            tokens: 8,
            deleted: false,
            version: 1,
            supersedes: None,
            private: true,
            horizon_class: Default::default(),
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
    fn caps_bindings_per_passport_and_ages_out_private_receipts() {
        let now = Utc::now();
        let old = now - Duration::days(45);
        // A reverify receipt that is PRIVATE and past retain. Regression for
        // the prod gap where the selector skipped all private facts and so
        // never collected anything.
        let mut facts = vec![fact("__reverify_receipts__::f1", "r1", old, true)];
        // 40 aged bindings (all > the 1h safety floor) for one passport.
        // Newest 32 kept; oldest 8 collected. i ascending = newest → oldest.
        for i in 0..40 {
            let ts = now - Duration::hours(2) - Duration::minutes(i as i64);
            facts.push(binding_fact(
                &format!("sess{i:02}"),
                &format!("b{i:02}"),
                "personal-default",
                ts,
            ));
        }
        let selected = select_ephemeral_candidates(&facts, now, Duration::days(DEFAULT_RETAIN_DAYS));
        assert!(
            selected.contains(&"r1".to_string()),
            "private receipt past retain collected"
        );
        let binding_hits: Vec<_> = selected.iter().filter(|id| id.starts_with('b')).cloned().collect();
        assert_eq!(
            binding_hits.len(),
            8,
            "8 oldest bindings beyond the cap collected: {binding_hits:?}"
        );
        assert!(!selected.contains(&"b00".to_string()), "newest binding kept");
    }

    #[test]
    fn keeps_recent_bindings_and_never_touches_nonreserved() {
        let now = Utc::now();
        let old = now - Duration::days(45);
        let mut facts = vec![
            // Non-reserved facts, old → NEVER selected (even the private one).
            fact("user::notes", "u1", old, false),
            fact("execplan:foo", "e1", old, false),
            fact("secret::pii", "p1", old, true),
        ];
        // 50 RECENT bindings (younger than the 1h floor) for one passport:
        // beyond the cap, but none may be collected yet.
        for i in 0..50 {
            let ts = now - Duration::minutes(i as i64);
            facts.push(binding_fact(
                &format!("r{i:02}"),
                &format!("rb{i:02}"),
                "personal-default",
                ts,
            ));
        }
        let selected = select_ephemeral_candidates(&facts, now, Duration::days(DEFAULT_RETAIN_DAYS));
        assert!(selected.is_empty(), "no candidates expected, got {selected:?}");
    }

    #[test]
    fn cap_is_per_passport_not_global() {
        let now = Utc::now();
        // 40 aged bindings each for two passports. The cap is per-passport, so
        // each contributes 8 collectable (40 - 32), never starving one passport
        // because another is busy.
        let mut facts = Vec::new();
        for (p, prefix) in [("personal-default", "a"), ("work-default", "c")] {
            for i in 0..40 {
                let ts = now - Duration::hours(2) - Duration::minutes(i as i64);
                facts.push(binding_fact(
                    &format!("{prefix}{i:02}"),
                    &format!("{prefix}{i:02}"),
                    p,
                    ts,
                ));
            }
        }
        let selected = select_ephemeral_candidates(&facts, now, Duration::days(DEFAULT_RETAIN_DAYS));
        assert_eq!(selected.len(), 16, "8 per passport × 2 passports");
    }

    #[tokio::test]
    async fn full_sweep_soft_deletes_only_ephemeral_and_leaves_tombstone() {
        let store = Arc::new(RwLock::new(FactStore::new()));
        let now = Utc::now();
        let retain = Duration::days(DEFAULT_RETAIN_DAYS);

        // Seed a PRIVATE reverify receipt (mirrors prod privacy) + a user fact.
        let (receipt_id, user_id) = {
            let mut g = store.write().await;
            let receipt = store_fact(&mut g, "__reverify_receipts__::f1", "r1", true);
            let user = store_fact(&mut g, "user::notes", "u1", false);
            (receipt.fact_id, user.fact_id)
        };

        // Backdate via a hand-built slice fed to the pure selector → only the
        // aged ephemeral receipt qualifies (the user fact never does).
        let backdated = vec![
            fact("__reverify_receipts__::f1", &receipt_id, now - Duration::days(45), true),
            fact("user::notes", &user_id, now - Duration::days(45), false),
        ];
        let selected = select_ephemeral_candidates(&backdated, now, retain);
        assert_eq!(selected, vec![receipt_id.clone()], "only the aged ephemeral receipt");

        // Drive the real journaled delete path.
        {
            let mut g = store.write().await;
            assert!(g.try_delete(&receipt_id).expect("journaled delete"));
        }

        let g = store.read().await;
        // Soft-deleted fact is hidden from get(), user fact retained.
        assert!(g.get(&receipt_id).is_none(), "deleted receipt hidden from get");
        assert!(g.get(&user_id).is_some(), "user fact retained");
        // Reversibility: the tombstone still exists in all_facts() with deleted = true.
        let tombstone = g
            .all_facts()
            .find(|f| f.fact_id == receipt_id)
            .expect("tombstone present in all_facts");
        assert!(tombstone.deleted, "soft-deleted fact is a tombstone, not erased");
        let user_fact = g.all_facts().find(|f| f.fact_id == user_id).expect("user fact present");
        assert!(!user_fact.deleted, "user fact untouched");
    }

    #[tokio::test]
    async fn run_sweep_once_is_idempotent_and_noop_when_disabled_set_empty() {
        let store = Arc::new(RwLock::new(FactStore::new()));
        let now = Utc::now();
        let retain = Duration::days(DEFAULT_RETAIN_DAYS);
        // No facts → zero deletions.
        assert_eq!(run_sweep_once(&store, now, retain).await, 0);
        // A single recent, valid binding → kept (under the cap, younger than
        // the safety floor).
        {
            let mut g = store.write().await;
            g.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: "__session_binding__::z".to_string(),
                key: "record".to_string(),
                value: r#"{"session_id_hex":"z","project_id":null,"tenant_id":"personal","passport_id":"personal-default","passport_category":"personal","agent_work_gate":false,"bound_at_unix_ms":0}"#.to_string(),
                source_receipt: None,
                confidence: 1.0,
                private: true,
                horizon_class: None,
                actor: None,
            });
        }
        assert_eq!(run_sweep_once(&store, now, retain).await, 0);
    }
}
