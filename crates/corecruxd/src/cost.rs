// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! In-memory store for ground-truth **token-burn cost reports**.
//!
//! The cost lens is computed client-side (`corecruxctl session cost`, which
//! parses the operator's local Claude Code transcript — the daemon never sees
//! the transcript). The CLI `--post`s the resulting [`CostReport`] here so the
//! console `cx-cost` page can render it.
//!
//! It is a process-wide `Mutex`-guarded map keyed by
//! `(tenant_id, session_id)`, holding the **latest** report per session. It is
//! pure in-memory (no dataplane, no disk) so it works on the CPU/dataplane-off
//! console build, and it is gated by `CORECRUXD_FEATURE_COST_LENS` (default
//! OFF) so the daemon behaves exactly as today when the flag is unset.

use std::collections::HashMap;
use std::sync::OnceLock;

use chrono::Utc;
use crux_cost::CostReport;
use serde::Serialize;
use tokio::sync::Mutex;

/// Environment variable that gates the cost-lens endpoints. **Default OFF**.
pub const FEATURE_FLAG_ENV: &str = "CORECRUXD_FEATURE_COST_LENS";

/// Sentinel passport id used when the poster is unauthenticated (T.3).
pub const ANON_PASSPORT: &str = "__anon__";

/// Return true if the cost lens is enabled. **Default OFF** — an empty value
/// also counts as off (matches the activity-log truthiness parser).
pub fn cost_lens_enabled() -> bool {
    match std::env::var(FEATURE_FLAG_ENV) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

/// A posted [`CostReport`] plus the daemon-side receipt metadata.
#[derive(Debug, Clone, Serialize)]
pub struct StoredReport {
    /// Owning tenant.
    pub tenant_id: String,
    /// Session key (the report's `session_id`, or its `source` filename when
    /// the transcript carried no id).
    pub session_id: String,
    /// Passport that posted it (or [`ANON_PASSPORT`]).
    pub actor_passport: String,
    /// RFC3339 receive time (the daemon owns this clock).
    pub received_at: String,
    /// The ground-truth report.
    pub report: CostReport,
}

/// One row of the session picker (for the console dropdown).
#[derive(Debug, Clone, Serialize)]
pub struct SessionMeta {
    /// Session key.
    pub session_id: String,
    /// Transcript file name (corpus identity).
    pub source: String,
    /// When the CLI generated the report.
    pub generated_at: Option<String>,
    /// When the daemon received it.
    pub received_at: String,
    /// Headline burn metric.
    pub context_tokens_per_turn: u64,
    /// Number of model turns.
    pub assistant_turns: u64,
}

/// Process-wide store of the latest report per `(tenant_id, session_id)`.
#[derive(Debug, Default)]
pub struct CostStore {
    by_session: HashMap<(String, String), StoredReport>,
}

impl CostStore {
    /// Upsert the latest report for a session, returning the stored record.
    pub fn put(
        &mut self,
        tenant_id: String,
        session_id: String,
        actor_passport: String,
        report: CostReport,
    ) -> StoredReport {
        let stored = StoredReport {
            tenant_id: tenant_id.clone(),
            session_id: session_id.clone(),
            actor_passport,
            received_at: Utc::now().to_rfc3339(),
            report,
        };
        self.by_session.insert((tenant_id, session_id), stored.clone());
        stored
    }

    /// The report for a specific `(tenant, session)`.
    pub fn get(&self, tenant_id: &str, session_id: &str) -> Option<StoredReport> {
        self.by_session
            .get(&(tenant_id.to_owned(), session_id.to_owned()))
            .cloned()
    }

    /// The most-recently-received report for a tenant.
    pub fn latest_for_tenant(&self, tenant_id: &str) -> Option<StoredReport> {
        self.by_session
            .values()
            .filter(|s| s.tenant_id == tenant_id)
            .max_by(|a, b| a.received_at.cmp(&b.received_at))
            .cloned()
    }

    /// Session-picker rows for a tenant, newest received first.
    pub fn sessions(&self, tenant_id: &str) -> Vec<SessionMeta> {
        let mut rows: Vec<SessionMeta> = self
            .by_session
            .values()
            .filter(|s| s.tenant_id == tenant_id)
            .map(|s| SessionMeta {
                session_id: s.session_id.clone(),
                source: s.report.source.clone(),
                generated_at: s.report.generated_at.clone(),
                received_at: s.received_at.clone(),
                context_tokens_per_turn: s.report.headline.context_tokens_per_turn,
                assistant_turns: s.report.headline.assistant_turns,
            })
            .collect();
        rows.sort_by(|a, b| b.received_at.cmp(&a.received_at));
        rows
    }
}

/// The process-wide cost store.
pub fn global() -> &'static Mutex<CostStore> {
    static STORE: OnceLock<Mutex<CostStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(CostStore::default()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sample(session: &str, source: &str, ctx_per_turn: u64) -> CostReport {
        CostReport {
            schema: crux_cost::COST_REPORT_SCHEMA.to_owned(),
            session_id: session.to_owned(),
            source: source.to_owned(),
            generated_at: Some("2026-06-21T00:00:00Z".to_owned()),
            headline: crux_cost::Headline {
                assistant_turns: 10,
                tasks: 2,
                segments: 1,
                context_tokens_per_turn: ctx_per_turn,
                cache_read_to_output_ratio: 100.0,
                measured_context_total: ctx_per_turn * 10,
                prefix_pct: 60.0,
            },
            measured: crux_cost::Measured::default(),
            buckets: Vec::new(),
            top_blocks: Vec::new(),
            levers: Vec::new(),
        }
    }

    #[test]
    fn put_get_and_latest() {
        let mut store = CostStore::default();
        store.put(
            "t".to_owned(),
            "s1".to_owned(),
            "p".to_owned(),
            sample("s1", "s1.jsonl", 100),
        );
        store.put(
            "t".to_owned(),
            "s2".to_owned(),
            "p".to_owned(),
            sample("s2", "s2.jsonl", 200),
        );
        // Other tenant must not bleed across (T.1).
        store.put(
            "other".to_owned(),
            "s3".to_owned(),
            "p".to_owned(),
            sample("s3", "s3.jsonl", 999),
        );

        assert_eq!(
            store.get("t", "s1").unwrap().report.headline.context_tokens_per_turn,
            100
        );
        assert!(store.get("t", "missing").is_none());
        // Latest-received is s2 (inserted after s1); s3 is a different tenant.
        assert_eq!(store.latest_for_tenant("t").unwrap().session_id, "s2");
        let sessions = store.sessions("t");
        assert_eq!(sessions.len(), 2);
        assert!(sessions.iter().all(|m| m.session_id != "s3"));
    }

    #[test]
    fn put_overwrites_latest_per_session() {
        let mut store = CostStore::default();
        store.put(
            "t".to_owned(),
            "s1".to_owned(),
            "p".to_owned(),
            sample("s1", "a.jsonl", 100),
        );
        store.put(
            "t".to_owned(),
            "s1".to_owned(),
            "p".to_owned(),
            sample("s1", "a.jsonl", 555),
        );
        assert_eq!(store.sessions("t").len(), 1);
        assert_eq!(
            store.get("t", "s1").unwrap().report.headline.context_tokens_per_turn,
            555
        );
    }
}
