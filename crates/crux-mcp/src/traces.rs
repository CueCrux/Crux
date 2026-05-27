// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Per-turn typed action trace ring buffer (master plan §"Tier mapping"
//! row 6, child plan `agent-ux-06-typed-action-traces-2026-05-27`).
//!
//! ## What this is
//!
//! Each tool dispatch records a [`TraceEntry`] (tool name, timestamp,
//! predicted effects, outcome) into a per-passport in-memory ring buffer
//! keyed by `turn_id`. The new `tool_trace_recent` MCP tool reads from
//! the ring so an agent (or a console panel) can render a chronological
//! "what did I just do" timeline.
//!
//! ## Privacy & isolation rules
//!
//! - Buffers are keyed by **passport name** (or the unauth sentinel
//!   `__anon__`). A `tool_trace_recent` call only sees traces written by
//!   the same passport — there is no cross-passport leak (master plan
//!   T.3).
//! - Reserved-prefix predicted effects (`__agent::`, `__ops::`,
//!   `__bootstrap__::` entities) are filtered out of the response just
//!   like the envelope's `memories_used` (T.1).
//! - Sliding-window retention: entries older than [`DEFAULT_RETENTION`]
//!   are evicted at read time and the buffer is capped at
//!   [`MAX_TRACES_PER_PASSPORT`] entries to bound memory.
//!
//! ## Feature flag
//!
//! Recording is gated by `CORECRUXD_FEATURE_TOOL_TRACES=1`; default OFF
//! so legacy deploys see zero behavioural change.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::Mutex;

use crate::envelope::{is_reserved_entity, PredictedEffect};

/// Environment variable that gates trace recording. Default off.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_TOOL_TRACES";

/// Default sliding-window retention horizon (1 hour). Overridable via
/// `CORECRUXD_FEATURE_TOOL_TRACES_TTL_SECS`.
pub const DEFAULT_RETENTION: Duration = Duration::from_secs(60 * 60);

/// Per-passport ring-buffer hard cap. Tuned for interactive sessions —
/// at ~50 tools/turn × 100 turns/h this still fits comfortably; older
/// entries are evicted FIFO.
pub const MAX_TRACES_PER_PASSPORT: usize = 5_000;

/// Sentinel passport id used when the caller is unauthenticated. Traces
/// from unauth callers are partitioned from any named passport and can
/// only be re-read by another unauth caller on the same daemon.
pub const ANON_PASSPORT: &str = "__anon__";

/// Return true if trace recording is enabled via the feature flag.
pub fn traces_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

/// Read the configured retention horizon, falling back to
/// [`DEFAULT_RETENTION`] when the env var is missing or unparseable.
pub fn retention() -> Duration {
    match std::env::var("CORECRUXD_FEATURE_TOOL_TRACES_TTL_SECS") {
        Ok(v) => v
            .trim()
            .parse::<u64>()
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_RETENTION),
        Err(_) => DEFAULT_RETENTION,
    }
}

/// Outcome of a single tool dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TraceOutcome {
    Ok,
    Error,
}

/// A single recorded tool dispatch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    /// Tool name (e.g. `query_facts`).
    pub tool: String,
    /// Optional turn id supplied by the caller (`turn_id` argument or
    /// the envelope's). `None` when the caller didn't tag the dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    /// Microseconds since UNIX epoch when the dispatch finished.
    pub ts_us: i64,
    /// Typed effects observed during the dispatch.
    pub predicted_effects: Vec<PredictedEffect>,
    /// Whether the dispatch succeeded.
    pub outcome: TraceOutcome,
}

/// Per-passport sliding-window store of [`TraceEntry`] values.
///
/// The store is a process-wide singleton accessed via [`global`]; it
/// owns one `Mutex` so writes from concurrent tool dispatches serialise
/// briefly (push is `O(1)`).
#[derive(Debug, Default)]
pub struct TraceStore {
    by_passport: HashMap<String, Vec<TraceEntry>>,
}

impl TraceStore {
    /// Append an entry for the given passport. Returns the number of
    /// entries currently retained for that passport (post-insert,
    /// post-eviction).
    pub fn push(&mut self, passport: &str, entry: TraceEntry) -> usize {
        let bucket = self.by_passport.entry(passport.to_string()).or_default();
        bucket.push(entry);
        Self::trim_bucket(bucket, retention());
        bucket.len()
    }

    /// Read up to `top_k` most-recent entries for `passport`, newest
    /// first. Reserved-prefix predicted effects are stripped from the
    /// response so the read surface mirrors the envelope's privacy
    /// guarantee (T.1).
    pub fn recent(&mut self, passport: &str, top_k: usize) -> Vec<TraceEntry> {
        let Some(bucket) = self.by_passport.get_mut(passport) else {
            return Vec::new();
        };
        Self::trim_bucket(bucket, retention());
        let len = bucket.len();
        let take = top_k.min(len);
        let mut out: Vec<TraceEntry> = bucket.iter().rev().take(take).cloned().collect();
        for entry in &mut out {
            entry.predicted_effects.retain(|e| !is_reserved_entity(&e.entity));
        }
        out
    }

    /// Wipe the per-passport bucket. Intended for tests only.
    #[cfg(test)]
    pub fn clear_for_test(&mut self, passport: &str) {
        self.by_passport.remove(passport);
    }

    /// Wipe every passport bucket. Tests only.
    #[cfg(test)]
    pub fn clear_all_for_test(&mut self) {
        self.by_passport.clear();
    }

    fn trim_bucket(bucket: &mut Vec<TraceEntry>, ttl: Duration) {
        let now_us = Utc::now().timestamp_micros();
        let ttl_us = ttl.as_micros() as i64;
        let cutoff = now_us.saturating_sub(ttl_us);
        // FIFO age eviction.
        let split = bucket.iter().position(|e| e.ts_us >= cutoff).unwrap_or(bucket.len());
        if split > 0 {
            bucket.drain(0..split);
        }
        // Hard-cap eviction.
        if bucket.len() > MAX_TRACES_PER_PASSPORT {
            let overflow = bucket.len() - MAX_TRACES_PER_PASSPORT;
            bucket.drain(0..overflow);
        }
    }
}

/// Process-wide trace store (lazy-init, single mutex).
pub fn global() -> &'static Mutex<TraceStore> {
    static STORE: OnceLock<Mutex<TraceStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(TraceStore::default()))
}

/// Test-only serialisation lock for tests that mutate the global trace
/// store or `CORECRUXD_FEATURE_TOOL_TRACES` env var. Both this module and
/// `tools::traces::tests` must take the SAME lock so the process-wide
/// flag toggling doesn't race between modules.
#[cfg(test)]
pub fn test_env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Record a single tool dispatch into the global per-passport ring.
///
/// Returns `Ok(())` on a clean record; otherwise silently drops the
/// entry (the trace ring is observability infrastructure — it must
/// never block tool dispatch per master plan T.4).
pub async fn record_dispatch(
    passport: &str,
    tool: &str,
    turn_id: Option<&str>,
    predicted_effects: Vec<PredictedEffect>,
    outcome: TraceOutcome,
) {
    if !traces_enabled() {
        return;
    }
    let entry = TraceEntry {
        tool: tool.to_string(),
        turn_id: turn_id.map(|s| s.to_string()),
        ts_us: Utc::now().timestamp_micros(),
        predicted_effects,
        outcome,
    };
    let mut store = global().lock().await;
    store.push(passport, entry);
}

/// Render the `tool_trace_recent` payload directly to JSON.
///
/// `token_budget` is honoured loosely: each [`TraceEntry`] is roughly
/// 200 chars of JSON; we cap returned entries at `token_budget / 50` so
/// a 500-token budget surfaces ~10 entries. This is the same cheap
/// heuristic used elsewhere in the codebase (master plan §"Two
/// structural rules — token_budget is mandatory").
pub fn trace_payload(entries: Vec<TraceEntry>, token_budget: Option<usize>) -> Value {
    let trimmed = if let Some(budget) = token_budget {
        let cap = (budget / 50).max(1);
        entries.into_iter().take(cap).collect::<Vec<_>>()
    } else {
        entries
    };
    serde_json::json!({
        "traces": trimmed,
        "count": trimmed.len(),
    })
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn effect(entity: &str, key: &str) -> PredictedEffect {
        PredictedEffect::now("fact_write", entity, key)
    }

    fn entry(tool: &str, effects: Vec<PredictedEffect>) -> TraceEntry {
        TraceEntry {
            tool: tool.to_string(),
            turn_id: Some("turn-001".to_string()),
            ts_us: Utc::now().timestamp_micros(),
            predicted_effects: effects,
            outcome: TraceOutcome::Ok,
        }
    }

    #[test]
    fn feature_flag_default_off() {
        std::env::remove_var(FEATURE_FLAG_ENV);
        assert!(!traces_enabled());
    }

    #[test]
    fn store_push_and_recent_round_trip() {
        let mut store = TraceStore::default();
        store.push("alice", entry("query_facts", vec![effect("p", "k")]));
        store.push("alice", entry("store_fact", vec![effect("p", "k2")]));
        let recent = store.recent("alice", 10);
        assert_eq!(recent.len(), 2);
        // Newest first.
        assert_eq!(recent[0].tool, "store_fact");
        assert_eq!(recent[1].tool, "query_facts");
    }

    #[test]
    fn store_isolates_passports() {
        let mut store = TraceStore::default();
        store.push("alice", entry("query_facts", vec![effect("p", "k")]));
        store.push("bob", entry("store_fact", vec![effect("p", "k2")]));
        let alice = store.recent("alice", 10);
        let bob = store.recent("bob", 10);
        assert_eq!(alice.len(), 1);
        assert_eq!(bob.len(), 1);
        assert_eq!(alice[0].tool, "query_facts");
        assert_eq!(bob[0].tool, "store_fact");
    }

    #[test]
    fn store_strips_reserved_prefix_effects_on_read() {
        let mut store = TraceStore::default();
        store.push(
            "alice",
            entry(
                "store_fact",
                vec![
                    effect("project-x", "status"),
                    effect("__ops::config-audit", "sha"),
                    effect("__bootstrap__::pattern", "retry"),
                    effect("__agent::alice::priv", "k"),
                ],
            ),
        );
        let recent = store.recent("alice", 10);
        assert_eq!(recent.len(), 1);
        let kept: Vec<&str> = recent[0].predicted_effects.iter().map(|e| e.entity.as_str()).collect();
        assert_eq!(kept, vec!["project-x"], "reserved entities must be stripped");
    }

    #[test]
    fn store_caps_at_hard_limit() {
        let mut store = TraceStore::default();
        // Push more than the hard cap and assert FIFO drop.
        for i in 0..(MAX_TRACES_PER_PASSPORT + 5) {
            store.push("alice", entry(&format!("t{i}"), vec![]));
        }
        let recent = store.recent("alice", MAX_TRACES_PER_PASSPORT + 10);
        assert_eq!(recent.len(), MAX_TRACES_PER_PASSPORT);
        // Oldest 5 should be gone — newest entry must still be present.
        assert_eq!(recent[0].tool, format!("t{}", MAX_TRACES_PER_PASSPORT + 4));
    }

    #[test]
    fn store_top_k_truncates_response() {
        let mut store = TraceStore::default();
        for i in 0..10 {
            store.push("alice", entry(&format!("t{i}"), vec![]));
        }
        let recent = store.recent("alice", 3);
        assert_eq!(recent.len(), 3);
    }

    #[test]
    fn trace_payload_respects_token_budget() {
        let mut entries = Vec::new();
        for i in 0..30 {
            entries.push(entry(&format!("t{i}"), vec![]));
        }
        let payload = trace_payload(entries, Some(500));
        // 500 / 50 = 10 entries
        assert_eq!(payload["count"], 10);
        assert_eq!(payload["traces"].as_array().unwrap().len(), 10);
    }

    #[tokio::test]
    async fn record_dispatch_is_noop_when_flag_off() {
        let _g = test_env_lock().lock().await;
        std::env::remove_var(FEATURE_FLAG_ENV);
        // Use a unique passport so the assertion is independent of other tests.
        let passport = "test-passport-noop-when-off";
        global().lock().await.clear_for_test(passport);
        record_dispatch(passport, "query_facts", None, vec![effect("p", "k")], TraceOutcome::Ok).await;
        let store = global().lock().await;
        // Bucket should not exist (no entries pushed).
        assert!(store.by_passport.get(passport).is_none());
    }
}
