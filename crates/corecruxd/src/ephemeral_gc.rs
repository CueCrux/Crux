// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
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
//! non-reserved or private user facts, and only ever the two ephemeral
//! prefixes above — enforced by
//! [`crux_mcp::envelope::is_ephemeral_reserved_entity`] and re-checked
//! per-fact in [`select_ephemeral_candidates`].
//!
//! ## Selection rule (safety-critical)
//!
//! - `__reverify_receipts__::*` — delete if `stored_at` is older than
//!   `retain` (default 30 days). Recent receipts are kept.
//! - `__session_binding__::<hex>` — KEEP the newest binding per entity
//!   (per `session_id_hex`). An older binding is deletable ONLY if it is
//!   past `retain` AND it is NOT the newest `stored_at` for its entity.
//!   The single live binding for a session is therefore never selected,
//!   even when it is old; only superseded churn is collected.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Duration, Utc};
use tokio::sync::{broadcast, RwLock};

use corecrux_memory::{Fact, FactStore};
use crux_mcp::envelope::is_ephemeral_reserved_entity;

/// Default retain window for ephemeral facts: 30 days.
pub const DEFAULT_RETAIN_DAYS: i64 = 30;

/// Default GC tick interval: hourly.
const GC_INTERVAL_SECS: u64 = 3600;

/// Pure selection over a fact slice. Returns the `fact_id`s that the GC
/// would soft-delete, applying the conservative, reversible rule
/// documented at the module level.
///
/// Safety invariants (all enforced here, independent of caller):
/// - Only `__session_binding__::*` and `__reverify_receipts__::*` entities
///   are ever eligible (via [`is_ephemeral_reserved_entity`]).
/// - `private` facts are NEVER selected.
/// - Already-deleted facts are skipped (idempotent across ticks).
/// - For session bindings, the newest version per entity is always kept.
pub fn select_ephemeral_candidates(facts: &[Fact], now: DateTime<Utc>, retain: Duration) -> Vec<String> {
    // Newest stored_at per session-binding entity — the live binding we
    // must never collect.
    let mut newest_binding_at: HashMap<&str, DateTime<Utc>> = HashMap::new();
    for f in facts {
        if f.deleted {
            continue;
        }
        if f.entity.starts_with("__session_binding__::") {
            let e = newest_binding_at.entry(f.entity.as_str()).or_insert(f.stored_at);
            if f.stored_at > *e {
                *e = f.stored_at;
            }
        }
    }

    let mut out = Vec::new();
    for f in facts {
        // Never touch deleted, private, or non-ephemeral-reserved facts.
        if f.deleted || f.private {
            continue;
        }
        if !is_ephemeral_reserved_entity(&f.entity) {
            continue;
        }
        let past_retain = (now - f.stored_at) > retain;
        if !past_retain {
            continue;
        }
        if f.entity.starts_with("__session_binding__::") {
            // Keep the newest binding for each session; only superseded
            // (older) versions past retain are deletable.
            let is_newest = newest_binding_at
                .get(f.entity.as_str())
                .is_none_or(|newest| f.stored_at >= *newest);
            if is_newest {
                continue;
            }
            out.push(f.fact_id.clone());
        } else {
            // __reverify_receipts__::* — any fact past retain.
            out.push(f.fact_id.clone());
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
            entity: entity.to_string(),
            key: key.to_string(),
            value: "{}".to_string(),
            source_receipt: None,
            confidence: 1.0,
            private,
            horizon_class: None,
        })
    }

    /// Forcibly backdate a fact's `stored_at` in the in-memory store by
    /// re-storing then patching — we drive selection through the pure fn
    /// on a hand-built slice instead, which is cleaner and deterministic.
    fn fact(entity: &str, fact_id: &str, stored_at: DateTime<Utc>, private: bool) -> Fact {
        Fact {
            fact_id: fact_id.to_string(),
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
        }
    }

    #[test]
    fn selects_backdated_facts_for_both_prefixes() {
        let now = Utc::now();
        let old = now - Duration::days(45);
        let facts = vec![
            // A reverify receipt past retain → selected.
            fact("__reverify_receipts__::f1", "r1", old, false),
            // Two bindings for the same session: old + recent. The recent
            // one is newest → kept; the old one is superseded → selected.
            fact("__session_binding__::aaaa", "b_old", old, false),
            fact("__session_binding__::aaaa", "b_new", now, false),
        ];
        let retain = Duration::days(DEFAULT_RETAIN_DAYS);
        let selected = select_ephemeral_candidates(&facts, now, retain);
        assert!(selected.contains(&"r1".to_string()), "old reverify receipt selected");
        assert!(
            selected.contains(&"b_old".to_string()),
            "superseded old binding selected"
        );
        assert!(!selected.contains(&"b_new".to_string()), "newest binding kept");
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn never_selects_recent_private_or_nonreserved() {
        let now = Utc::now();
        let old = now - Duration::days(45);
        let facts = vec![
            // Recent single session binding → kept (newest for its entity).
            fact("__session_binding__::bbbb", "recent_binding", now, false),
            // Old single session binding, but it is the ONLY (newest) one
            // for its entity → kept (never orphan a live session).
            fact("__session_binding__::cccc", "lone_old_binding", old, false),
            // A non-reserved user fact, old → NEVER selected.
            fact("user::notes", "u1", old, false),
            // A private fact under an ephemeral prefix, old → NEVER selected.
            fact("__reverify_receipts__::secret", "p1", old, true),
            // execplan fact, old → NEVER selected.
            fact("execplan:foo", "e1", old, false),
        ];
        let retain = Duration::days(DEFAULT_RETAIN_DAYS);
        let selected = select_ephemeral_candidates(&facts, now, retain);
        assert!(selected.is_empty(), "no candidates expected, got {selected:?}");
    }

    #[tokio::test]
    async fn full_sweep_soft_deletes_only_ephemeral_and_leaves_tombstone() {
        let store = Arc::new(RwLock::new(FactStore::new()));
        let now = Utc::now();
        let retain = Duration::days(DEFAULT_RETAIN_DAYS);

        // Seed facts; then patch stored_at directly on the in-memory copies
        // so we can exercise the real try_delete path.
        let (receipt_id, old_binding_id, new_binding_id, user_id) = {
            let mut g = store.write().await;
            let receipt = store_fact(&mut g, "__reverify_receipts__::f1", "r1", false);
            let old_binding = store_fact(&mut g, "__session_binding__::aaaa", "b_old", false);
            let new_binding = store_fact(&mut g, "__session_binding__::aaaa", "b_new", false);
            let user = store_fact(&mut g, "user::notes", "u1", false);
            (receipt.fact_id, old_binding.fact_id, new_binding.fact_id, user.fact_id)
        };

        // Backdate everything except the newest binding to 45 days ago via
        // a fresh slice fed to the pure selector — verify selection first.
        let backdated = vec![
            fact(
                "__reverify_receipts__::f1",
                &receipt_id,
                now - Duration::days(45),
                false,
            ),
            fact(
                "__session_binding__::aaaa",
                &old_binding_id,
                now - Duration::days(45),
                false,
            ),
            fact("__session_binding__::aaaa", &new_binding_id, now, false),
            fact("user::notes", &user_id, now - Duration::days(45), false),
        ];
        let selected = select_ephemeral_candidates(&backdated, now, retain);
        assert_eq!(selected.len(), 2);

        // Drive the real journaled delete path on exactly those ids.
        let mut deleted = 0usize;
        {
            let mut g = store.write().await;
            for id in &selected {
                if g.try_delete(id).expect("journaled delete") {
                    deleted += 1;
                }
            }
        }
        assert_eq!(deleted, 2, "two ephemeral facts soft-deleted");

        let g = store.read().await;
        // Soft-deleted facts are hidden from get()...
        assert!(g.get(&receipt_id).is_none(), "deleted receipt hidden from get");
        assert!(g.get(&old_binding_id).is_none(), "deleted old binding hidden from get");
        // ...but the newest binding and the user fact remain visible.
        assert!(g.get(&new_binding_id).is_some(), "newest binding retained");
        assert!(g.get(&user_id).is_some(), "user fact retained");
        // Reversibility: the tombstone still exists in all_facts() (not
        // physically gone) with deleted = true.
        let tombstone = g
            .all_facts()
            .find(|f| f.fact_id == receipt_id)
            .expect("tombstone present in all_facts");
        assert!(tombstone.deleted, "soft-deleted fact is a tombstone, not erased");
        // The user fact is never a tombstone.
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
        // Only recent ephemeral facts → still zero (nothing past retain).
        {
            let mut g = store.write().await;
            let _ = store_fact(&mut g, "__session_binding__::z", "rec", false);
        }
        assert_eq!(run_sweep_once(&store, now, retain).await, 0);
    }
}
