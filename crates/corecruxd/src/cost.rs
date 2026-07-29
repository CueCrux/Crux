// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

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
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use chrono::Utc;
use crux_cost::CostReport;
use serde::{Deserialize, Serialize};
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
///
/// `Deserialize` is derived so the report can be replayed from the on-disk
/// journal (see [`init_persistence`]) — every field round-trips, including the
/// daemon-owned `received_at`, so a replayed report is byte-identical to the one
/// that was live in memory before a restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    // --- Additive (console-surfaces-remediation M5) — the fields the console
    //     `cx-cost` sessions×burn table needs directly off the picker, so the
    //     page does not have to pull each report body one-by-one. All derived
    //     from the stored report the daemon already holds (no new content). ---
    /// Transcript active-window start (RFC3339), when the report carried one.
    pub started_at: Option<String>,
    /// Transcript active-window end (RFC3339), when the report carried one.
    pub ended_at: Option<String>,
    /// Σ measured context tokens over the session (the headline burn number).
    pub context_tokens: u64,
    /// Σ output tokens generated over the session.
    pub output_tokens: u64,
    /// Poster passport (or [`ANON_PASSPORT`]) — drives the console passport filter.
    pub actor_passport: String,
    /// Producer-derived ExecPlan slug(s) this session worked (the precise link
    /// lane). Empty ⇒ the burn attributes to plans by window-overlap.
    pub execplan_slugs: Vec<String>,
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

    /// All stored reports for a tenant (clones), for the read-time per-ExecPlan
    /// token-burn join. Unordered — the attribution join is order-independent.
    pub fn reports_for_tenant(&self, tenant_id: &str) -> Vec<StoredReport> {
        self.by_session
            .values()
            .filter(|s| s.tenant_id == tenant_id)
            .cloned()
            .collect()
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
                started_at: s.report.started_at.clone(),
                ended_at: s.report.ended_at.clone(),
                context_tokens: s.report.headline.measured_context_total,
                output_tokens: s.report.measured.output,
                actor_passport: s.actor_passport.clone(),
                execplan_slugs: s.report.execplan_slugs.clone(),
            })
            .collect();
        rows.sort_by(|a, b| b.received_at.cmp(&a.received_at));
        rows
    }

    /// Insert a pre-built stored report **as-is**, preserving its `received_at`
    /// (unlike [`Self::put`], which stamps the receive clock). Used by journal
    /// replay at startup; latest line per `(tenant, session)` wins — the same
    /// latest-wins semantics as the live path, since the journal is append-only
    /// in receive order.
    pub fn insert(&mut self, stored: StoredReport) {
        self.by_session
            .insert((stored.tenant_id.clone(), stored.session_id.clone()), stored);
    }
}

/// The process-wide cost store.
pub fn global() -> &'static Mutex<CostStore> {
    static STORE: OnceLock<Mutex<CostStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(CostStore::default()))
}

// ── Persistence ─────────────────────────────────────────────────────────────
//
// The in-memory [`CostStore`] is emptied on every process restart, which is why
// the console `cx-cost` page (and per-ExecPlan `token_burn`) read empty on a
// fresh daemon until `corecruxctl session cost --post` re-posts. To make cost
// attribution survive restarts, each accepted POST is journalled to an
// append-only JSONL under `<data_dir>/cost/reports.jsonl`, and the journal is
// replayed into the store at startup (latest line per `(tenant, session)` wins —
// the same latest-wins semantics the store already has).
//
// It is intentionally minimal: enabled only when the cost lens is on, no config,
// no compaction (the file holds one small line per active session), and a
// journal failure never fails the request (the in-memory store is authoritative
// at runtime; the journal is only a restart backstop).

/// Process-wide journal target. `Some(path)` when persistence is live,
/// `Some(None)`/unset when the lens is off or the dir could not be created — in
/// which case [`append_report_to_journal`] is a strict no-op.
static JOURNAL_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

/// The journal path under `data_dir`, or `None` when the lens is disabled — so
/// "feature off ⇒ no on-disk writes" is a single, purely-testable decision.
fn journal_dir_for(data_dir: &Path, enabled: bool) -> Option<PathBuf> {
    enabled.then(|| data_dir.join("cost").join("reports.jsonl"))
}

/// Append one stored report as a single JSON line. Callers treat a failure as
/// non-fatal (the POST still succeeds; the report just isn't restart-durable).
fn append_line(path: &Path, stored: &StoredReport) -> std::io::Result<()> {
    let line = serde_json::to_string(stored)?;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    Ok(())
}

/// Read + parse a reports journal in file (receive) order. A missing file is an
/// empty history; a malformed line is logged and skipped (a single bad line must
/// never abort replay of the rest).
fn read_journal(path: &Path) -> Vec<StoredReport> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (i, line) in std::io::BufReader::new(file).lines().enumerate() {
        let Ok(line) = line else { continue };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<StoredReport>(trimmed) {
            Ok(rec) => out.push(rec),
            Err(e) => tracing::warn!(line = i + 1, error = %e, "cost: skipping malformed journal line"),
        }
    }
    out
}

/// Journal one accepted report. No-op unless [`init_persistence`] armed a path
/// (lens on + writable dir). Never fails the caller — a write error is logged
/// and the in-memory store (already updated) remains authoritative.
pub fn append_report_to_journal(stored: &StoredReport) {
    let Some(Some(path)) = JOURNAL_PATH.get() else {
        return;
    };
    if let Err(e) = append_line(path, stored) {
        tracing::warn!(error = %e, "cost: failed to journal report (in-memory store unaffected)");
    }
}

/// Arm cost-report persistence and replay any existing journal into the store.
/// No-op (records no path) unless the cost lens is enabled. Call once at startup
/// inside the async runtime; latest line per `(tenant, session)` wins.
pub async fn init_persistence(data_dir: &Path) {
    let Some(path) = journal_dir_for(data_dir, cost_lens_enabled()) else {
        let _ = JOURNAL_PATH.set(None);
        return;
    };
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!(error = %e, dir = %parent.display(), "cost: cannot create journal dir; persistence disabled");
            let _ = JOURNAL_PATH.set(None);
            return;
        }
    }
    let records = read_journal(&path);
    let replayed = records.len();
    if replayed > 0 {
        let mut store = global().lock().await;
        for rec in records {
            store.insert(rec);
        }
    }
    let _ = JOURNAL_PATH.set(Some(path.clone()));
    tracing::info!(reports = replayed, path = %path.display(), "cost: cost-report persistence enabled");
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
            started_at: None,
            ended_at: None,
            execplan_slugs: Vec::new(),
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

    // ── Persistence (console-surfaces-remediation M5) ───────────────────────

    /// A stored record with an explicit `received_at`, built off [`sample`].
    fn stored_report(session: &str, received: &str, ctx_per_turn: u64) -> StoredReport {
        StoredReport {
            tenant_id: "default".to_owned(),
            session_id: session.to_owned(),
            actor_passport: ANON_PASSPORT.to_owned(),
            received_at: received.to_owned(),
            report: sample(session, &format!("{session}.jsonl"), ctx_per_turn),
        }
    }

    #[test]
    fn journal_target_is_none_when_disabled() {
        // Feature OFF ⇒ no journal path ⇒ append_report_to_journal is a strict
        // no-op ⇒ nothing is ever written to disk.
        let dir = Path::new("/tmp/does-not-matter");
        assert!(journal_dir_for(dir, false).is_none());
        // Feature ON ⇒ the path is exactly <data_dir>/cost/reports.jsonl.
        assert_eq!(journal_dir_for(dir, true), Some(dir.join("cost").join("reports.jsonl")));
    }

    #[test]
    fn journal_round_trips_via_append_and_read() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("reports.jsonl");
        let rec = stored_report("s1", "2026-07-22T10:00:00Z", 123);
        append_line(&path, &rec).unwrap();

        let back = read_journal(&path);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].session_id, "s1");
        assert_eq!(back[0].received_at, "2026-07-22T10:00:00Z");
        assert_eq!(back[0].actor_passport, ANON_PASSPORT);
        // The full report body round-trips (CostReport: PartialEq).
        assert_eq!(back[0].report, rec.report);
    }

    #[test]
    fn read_journal_skips_malformed_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("reports.jsonl");
        append_line(&path, &stored_report("good1", "2026-07-22T10:00:00Z", 1)).unwrap();
        // Inject a blank line and a garbage line between two good records.
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(b"\n{ this is not json }\n").unwrap();
        }
        append_line(&path, &stored_report("good2", "2026-07-22T11:00:00Z", 2)).unwrap();

        let back = read_journal(&path);
        // Only the two well-formed records survive, in file order.
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].session_id, "good1");
        assert_eq!(back[1].session_id, "good2");
    }

    #[test]
    fn read_missing_journal_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("nope").join("reports.jsonl");
        assert!(read_journal(&missing).is_empty());
    }

    #[test]
    fn replay_insert_is_latest_wins_per_session() {
        // Two journal lines for the same (tenant, session): the LATER one (file
        // order) wins on replay, and its received_at is preserved as-is (not
        // re-stamped) — the restart-durability contract.
        let mut store = CostStore::default();
        for rec in read_replay_fixture() {
            store.insert(rec);
        }
        assert_eq!(store.sessions("default").len(), 1);
        let got = store.get("default", "s1").unwrap();
        assert_eq!(got.report.headline.context_tokens_per_turn, 999);
        assert_eq!(got.received_at, "2026-07-22T12:00:00Z"); // preserved, not "now"
    }

    /// An in-file-order pair of records for the same session (older, then newer).
    fn read_replay_fixture() -> Vec<StoredReport> {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("reports.jsonl");
        append_line(&path, &stored_report("s1", "2026-07-22T11:00:00Z", 100)).unwrap();
        append_line(&path, &stored_report("s1", "2026-07-22T12:00:00Z", 999)).unwrap();
        read_journal(&path)
    }

    #[test]
    fn sessions_expose_window_burn_passport_and_slugs() {
        // The picker row surfaces the additive M5 fields the console table reads.
        let mut report = sample("s1", "s1.jsonl", 100);
        report.started_at = Some("2026-07-22T09:00:00Z".to_owned());
        report.ended_at = Some("2026-07-22T09:30:00Z".to_owned());
        report.execplan_slugs = vec!["some-plan".to_owned()];
        report.headline.measured_context_total = 4242;
        report.measured.output = 99;

        let mut store = CostStore::default();
        store.put("default".to_owned(), "s1".to_owned(), "alice".to_owned(), report);

        let rows = store.sessions("default");
        assert_eq!(rows.len(), 1);
        let r = &rows[0];
        assert_eq!(r.started_at.as_deref(), Some("2026-07-22T09:00:00Z"));
        assert_eq!(r.ended_at.as_deref(), Some("2026-07-22T09:30:00Z"));
        assert_eq!(r.context_tokens, 4242);
        assert_eq!(r.output_tokens, 99);
        assert_eq!(r.actor_passport, "alice");
        assert_eq!(r.execplan_slugs, vec!["some-plan".to_owned()]);
    }
}
