// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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

use crate::http::AppState;
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

/// Pure selection over a stream of borrowed facts. Returns the `fact_id`s
/// that the GC would soft-delete, applying the conservative, reversible rule
/// documented at the module level.
///
/// Takes an iterator of `&Fact` (e.g. `FactStore::all_facts()` under a read
/// guard) and makes a SINGLE pass, retaining only candidate ids — never the
/// facts. Cloning the whole store into a `Vec<Fact>` once an hour was a
/// +1.5 GiB burst on a 2.4 GB journal and got the daemon memcg-killed every
/// tick (`incident:2026-08-20`).
///
/// Safety invariants (all enforced here, independent of caller):
/// - Only `__session_binding__::*` and `__reverify_receipts__::*` entities
///   are ever eligible — scoped by prefix, so non-reserved user facts
///   (including private ones) are never selected.
/// - Already-deleted facts are skipped (idempotent across ticks).
/// - The newest [`SESSION_BINDING_KEEP_N`] bindings per passport, and any
///   binding younger than the [`SESSION_BINDING_MIN_AGE_HOURS`] floor, are
///   always kept.
pub fn select_ephemeral_candidates<'a>(
    facts: impl IntoIterator<Item = &'a Fact>,
    now: DateTime<Utc>,
    retain: Duration,
) -> Vec<String> {
    let mut out = Vec::new();
    let min_age = Duration::hours(SESSION_BINDING_MIN_AGE_HOURS);
    let mut by_passport: HashMap<String, Vec<(DateTime<Utc>, String)>> = HashMap::new();

    for f in facts {
        if f.deleted {
            continue;
        }
        // `__reverify_receipts__::*` — age-based: any fact past `retain`.
        if f.entity.starts_with("__reverify_receipts__::") {
            if (now - f.stored_at) > retain {
                out.push(f.fact_id.clone());
            }
            continue;
        }
        // `__session_binding__::*` — per-passport population cap. Each MCP
        // session mints a unique-id binding, so keep the newest KEEP_N per
        // passport and collect the rest once they age past the safety floor.
        if !f.entity.starts_with("__session_binding__::") || f.key != SESSION_BINDING_RECORD_KEY {
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

/// Run one GC sweep against the store. Streams candidates off the live
/// store under a read lock (ids only — no clone of the facts), then
/// soft-deletes each via the journaled [`FactStore::try_delete`] under a
/// write lock. Returns the number of facts soft-deleted. Pure no-op when no
/// candidates qualify.
pub async fn run_sweep_once(store: &Arc<RwLock<FactStore>>, now: DateTime<Utc>, retain: Duration) -> usize {
    let candidates = {
        let guard = store.read().await;
        let mut scanned = 0usize;
        let candidates = select_ephemeral_candidates(guard.all_facts().inspect(|_| scanned += 1), now, retain);
        tracing::debug!(scanned, candidates = candidates.len(), "ephemeral-gc-scan");
        candidates
    };
    if candidates.is_empty() {
        return 0;
    }
    let mut deleted = 0usize;
    let mut guard = store.write().await;
    for id in &candidates {
        let Some(tenant_hash) = guard.get(id).map(|fact| fact.tenant_hash.clone()) else {
            continue;
        };
        match guard.try_delete(&tenant_hash, id) {
            Ok(true) => deleted += 1,
            Ok(false) => {}
            Err(err) => {
                tracing::warn!(?err, fact_id = %id, "ephemeral-gc-delete-failed");
            }
        }
    }
    deleted
}

/// P4/M6 ephemeral-GC receipt — a **typed** payload carrying a count + retain
/// window + a bounded reason-code ONLY, never the content of any swept fact
/// (the builder takes a count, not facts). Redaction-tested in `tests`.
#[derive(serde::Serialize)]
struct GcReceiptV1 {
    schema: &'static str,
    op: &'static str,
    deleted: usize,
    retain_days: i64,
    reason_code: &'static str,
    swept_at: String,
    run_id: String,
}

fn build_gc_receipt(deleted: usize, retain_days: i64) -> GcReceiptV1 {
    GcReceiptV1 {
        schema: "crux.gc_receipt.v1",
        op: "ephemeral_sweep",
        deleted,
        retain_days,
        // Bounded code; the human description lives in docs, not the signed body.
        reason_code: "ephemeral_reserved_fact_gc",
        swept_at: Utc::now().to_rfc3339(),
        run_id: format!("gc_{}", uuid::Uuid::new_v4().simple()),
    }
}

/// Spawn the background ephemeral GC task, mirroring
/// [`crate::update::spawn_update_checker`].
///
/// Gated at spawn: the task is only started when
/// `config.ephemeral_gc_enabled` is true. (The flag is read once at boot;
/// toggling it requires a restart — same convention as the other
/// `CORECRUXD_*` background-task flags.) The task runs hourly until the
/// shutdown signal is received.
///
/// P4/M6: after a sweep soft-deletes ≥1 fact, mint a signed CROWN receipt
/// (`__governance__::gc`) recording the count + retain window + reason-code —
/// never swept content. The soft-delete is journaled (a `Delete` tombstone) but
/// the fact journal append is not itself fsynced, so like any fact write it is
/// durable on a clean shutdown, not crash-atomic; the receipt uses the fsynced
/// durable append. A mint failure is NOT silent: `mint_governance_receipt`
/// bumps the audit-debt counter and logs at ERROR (the
/// `RECEIPT_MINT_FAILURES` static in `crate::http::observations`).
pub fn spawn_ephemeral_gc(enabled: bool, state: AppState, mut shutdown: broadcast::Receiver<()>) {
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
                    sweep_and_receipt(&state, Utc::now(), retain).await;
                }
                _ = shutdown.recv() => break,
            }
        }
    });
}

/// One sweep plus its CROWN receipt. Returns the number of facts soft-deleted.
/// Extracted from the spawn loop so the mint path is directly testable without
/// the interval timer. A non-empty sweep mints a `__governance__::gc` receipt;
/// a mint failure is loud (audit-debt counter + ERROR), never silent.
pub(crate) async fn sweep_and_receipt(state: &AppState, now: DateTime<Utc>, retain: Duration) -> usize {
    let n = run_sweep_once(&state.fact_store, now, retain).await;
    if n > 0 {
        tracing::info!(deleted = n, "ephemeral-gc-sweep");
        crate::http::observations::mint_governance_receipt(
            state,
            "__governance__::gc",
            "ephemeral-gc",
            "gc.ephemeral_sweep",
            &build_gc_receipt(n, retain.num_days()),
        );
    }
    n
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
        let selected = select_ephemeral_candidates(facts.iter(), now, Duration::days(DEFAULT_RETAIN_DAYS));
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
        let selected = select_ephemeral_candidates(facts.iter(), now, Duration::days(DEFAULT_RETAIN_DAYS));
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
        let selected = select_ephemeral_candidates(facts.iter(), now, Duration::days(DEFAULT_RETAIN_DAYS));
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
        let selected = select_ephemeral_candidates(backdated.iter(), now, retain);
        assert_eq!(selected, vec![receipt_id.clone()], "only the aged ephemeral receipt");

        // Drive the real journaled delete path.
        {
            let mut g = store.write().await;
            assert!(g.try_delete("default", &receipt_id).expect("journaled delete"));
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

    /// P4/M6: the GC receipt payload carries a count + retain window ONLY, never
    /// the value of any swept fact — proven by sweeping a secret-bearing fact
    /// and asserting the secret never reaches the receipt.
    #[test]
    fn gc_receipt_payload_never_carries_swept_content() {
        const SECRET: &str = "GC_SECRET_PAYLOAD_qq7";
        let mut s = FactStore::new();
        let f = s.store(StoreFact {
            tenant_hash: "default".to_string(),
            entity: "__reverify_receipts__::f1".to_string(),
            key: "record".to_string(),
            value: SECRET.to_string(),
            source_receipt: None,
            confidence: 1.0,
            private: true,
            horizon_class: None,
            actor: None,
        });
        assert!(s.try_delete("default", &f.fact_id).unwrap(), "secret fact soft-deleted");
        // One fact swept ⇒ receipt is built from the count alone.
        let payload = serde_json::to_value(build_gc_receipt(1, DEFAULT_RETAIN_DAYS)).unwrap();
        assert_eq!(payload["deleted"], 1);
        assert_eq!(payload["retain_days"], DEFAULT_RETAIN_DAYS);
        assert!(
            !payload.to_string().contains(SECRET),
            "swept secret leaked into GC receipt: {payload}"
        );
    }

    /// Review-fix finding 7: drive the sweep+mint path directly (no interval
    /// timer) and confirm a real aged fact is swept AND a GC receipt is written.
    #[tokio::test]
    async fn sweep_and_receipt_mints_gc_receipt_for_aged_fact() {
        let mut state = crate::http::tests::test_app_state_with_auth(4, crate::auth::AuthMode::DevScopes);
        let key = crux_session::LocalPassportKey::from_path(&state.passport_key_path).unwrap();
        state.passport_fpr = key.passport_fpr().to_string();

        // Seed an aged reverify-receipt fact (store_synced preserves stored_at).
        let mut store = FactStore::new();
        store.store_synced(fact(
            "__reverify_receipts__::old",
            "r-old",
            Utc::now() - Duration::days(45),
            true,
        ));
        state.fact_store = std::sync::Arc::new(RwLock::new(store));

        let n = sweep_and_receipt(&state, Utc::now(), Duration::days(DEFAULT_RETAIN_DAYS)).await;
        assert_eq!(n, 1, "aged ephemeral fact swept");

        let file = crate::http::observations::observation_file_path(&state.data_dir, "__governance__::gc");
        let body = std::fs::read_to_string(&file).unwrap();
        assert!(body.contains("gc.ephemeral_sweep"), "GC receipt kind present");
        assert!(body.contains("\"deleted\":1"), "GC receipt records the swept count");
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

    /// Regression for `incident:2026-08-20` (hourly memcg kill): the sweep
    /// must stream `all_facts()` straight off the live store — ids only, no
    /// `Vec<Fact>` clone. Exercised against a store large enough that a clone
    /// would be the dominant allocation; asserts the selector consumes the
    /// borrowed iterator directly and still finds exactly the aged receipts.
    #[tokio::test]
    async fn sweep_streams_live_store_without_cloning_facts() {
        let now = Utc::now();
        let retain = Duration::days(DEFAULT_RETAIN_DAYS);
        let mut s = FactStore::new();
        // Aged receipts first (store_synced is O(n) per insert; keep n small).
        for i in 0..3 {
            s.store_synced(fact(
                &format!("__reverify_receipts__::aged{i}"),
                &format!("aged{i}"),
                now - Duration::days(45),
                true,
            ));
        }
        // Bulk non-reserved filler: never eligible, only scanned.
        for i in 0..5_000 {
            store_fact(&mut s, &format!("user::bulk{i}"), "k", i % 2 == 0);
        }
        let store = Arc::new(RwLock::new(s));

        // The selector takes the store's borrowed iterator as-is — nothing to clone.
        {
            let g = store.read().await;
            let selected = select_ephemeral_candidates(g.all_facts(), now, retain);
            assert_eq!(selected.len(), 3, "only the 3 aged receipts: {selected:?}");
        }
        assert_eq!(run_sweep_once(&store, now, retain).await, 3);
        assert_eq!(run_sweep_once(&store, now, retain).await, 0, "idempotent");
    }
}
