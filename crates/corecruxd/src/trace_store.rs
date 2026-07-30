// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `trace_store` — durable runtime traces, joined to the static code graph.
//!
//! ExecPlan `crux-runtime-codemap-and-agent-query-api-2026-07-27`, milestone M4.
//!
//! Drains the M2 [`SpanRing`](crux_observe::span_layer::SpanRing), resolves each span's `(file, name, line)` to a
//! stable `symbol_id` via M1's resolver, and appends the result to a rolling
//! JSONL file under the data dir.
//!
//! # Why a standalone JSONL and not the shard store
//!
//! Introducing a new artifact *type* into the shard store means updating the
//! storage allowlist, projection registry and load-at-startup together — miss
//! one and you get the documented quarantine-on-restart bug. Traces need none
//! of that machinery: they are high-volume, lossy-by-design, and expire. So they
//! follow the `credit-meter.jsonl` precedent instead — one append-only file,
//! opened at startup, with no shard-store involvement and therefore no
//! three-place wiring to get wrong.
//!
//! They are deliberately **not** facts either: the workspace practices warn that
//! reflexive high-volume writes dilute fact recall, and a span is exactly that.
//!
//! # Resolution happens at write time
//!
//! The span→symbol join is done once, on flush, rather than on every read. A
//! trace recorded today therefore keeps the identity the code had when it ran,
//! which is the correct semantics: if a function is later renamed, the recorded
//! trace still points at what actually executed.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::symbol_resolve::SymbolResolver;
use crux_observe::span_layer::SpanRecord;

/// Enables the background flusher. Independent of capture: you can capture into
/// the ring for live inspection without ever persisting.
pub const TRACE_PERSIST_ENV: &str = "CORECRUXD_TRACE_PERSIST";
/// Flush cadence in seconds.
pub const TRACE_FLUSH_SECS_ENV: &str = "CORECRUXD_TRACE_FLUSH_SECS";
/// Retention cap: the store is truncated to the newest N records on rotate.
pub const TRACE_MAX_RECORDS_ENV: &str = "CORECRUXD_TRACE_MAX_RECORDS";
/// Per-tenant retained-span ceiling — the M5 margin guard.
pub const TRACE_TENANT_CEILING_ENV: &str = "CORECRUXD_TRACE_TENANT_CEILING";
/// Release label applied to spans captured by this daemon (M6).
pub const TRACE_RELEASE_ENV: &str = "CORECRUXD_TRACE_RELEASE";
/// Retention window in days — how long retained spans are kept (M6).
pub const TRACE_RETENTION_DAYS_ENV: &str = "CORECRUXD_TRACE_RETENTION_DAYS";

const DEFAULT_FLUSH_SECS: u64 = 10;
const DEFAULT_MAX_RECORDS: usize = 200_000;
/// Default per-tenant ceiling. 10M retained spans is ~800 MB gzipped at the
/// measured 399 bytes/span, which is the volume the M5 cost model prices as
/// comfortable inside one Pro seat-block. The operator sets the real number.
const DEFAULT_TENANT_CEILING: usize = 10_000_000;
/// See [`retention_days`]. Decided 2026-07-30; Governance overrides to 365.
const DEFAULT_RETENTION_DAYS: u64 = 90;

/// A captured span plus the static symbol it was resolved to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StoredSpan {
    #[serde(flatten)]
    pub span: SpanRecord,
    /// Resolved symbol, or `None` when the span had no file/line or the
    /// resolver declined (ambiguous / miss). Absence is meaningful and is
    /// preserved rather than dropped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_id: Option<String>,
    /// How the join was made: `extracted` / `inferred` / `ambiguous` / `miss` /
    /// `no_location`. Lets a reader weigh the attribution.
    pub join: String,
    /// Unix millis at flush time.
    pub stored_at_unix_ms: u64,
    /// Owning tenant, stamped at flush time.
    ///
    /// Empty means a **legacy record** written before the store was partitioned.
    /// It is not a wildcard: [`TraceStore::load_for_tenant`] resolves an empty
    /// tenant to this daemon's configured capture tenant and nothing else, so a
    /// legacy span can never answer for a tenant that did not capture it.
    ///
    /// `default` rather than required so an existing `spans.jsonl` keeps
    /// deserialising — dropping a user's captured history to add a field would
    /// be a worse failure than the one this field fixes.
    #[serde(default)]
    pub tenant_id: String,
    /// Release this span was captured under (M6).
    ///
    /// What makes `trace_diff` operational: "what executes now that did not
    /// before a release" needs the two sides labelled, and a timestamp cannot
    /// tell you which deploy a span belongs to when releases overlap.
    ///
    /// Empty means captured before release labelling, the same convention
    /// `tenant_id` uses — it is a legacy marker, never a wildcard.
    #[serde(default)]
    pub release: String,
}

#[derive(Debug)]
pub struct TraceStore {
    path: PathBuf,
    max_records: usize,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct FlushReport {
    pub spans_drained: usize,
    pub resolved: usize,
    pub ambiguous: usize,
    pub missed: usize,
    pub no_location: usize,
    /// Spans refused because the tenant is at its retained-span ceiling (M5).
    ///
    /// Refused at ingest, never by deleting what is already stored: a customer
    /// who hits the ceiling loses new capture, not the history they have already
    /// been answering questions from.
    pub refused_over_ceiling: usize,
}

impl TraceStore {
    /// Open (creating the parent directory if needed). Called once at startup —
    /// the load-at-startup half of the wiring.
    pub fn open(path: PathBuf, max_records: usize) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        Ok(Self {
            path,
            max_records: max_records.max(1),
        })
    }

    /// The backing file. Used by the restart-survival tests and by operators
    /// reading the store directly.
    #[cfg(test)]
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Resolve and append. Returns what happened, so a caller can surface the
    /// join quality rather than assuming it.
    /// Append a drained batch, stamping each span with `tenant_id`.
    ///
    /// The tenant is a parameter rather than read from the environment here so
    /// that a future multi-tenant flusher can stamp per batch without this
    /// method changing shape, and so tests can write two tenants into one store.
    pub fn append_resolved(
        &self,
        spans: Vec<SpanRecord>,
        resolver: Option<&SymbolResolver>,
        tenant_id: &str,
    ) -> std::io::Result<FlushReport> {
        let mut report = FlushReport {
            spans_drained: spans.len(),
            ..Default::default()
        };
        if spans.is_empty() {
            return Ok(report);
        }

        // M5 ceiling. Counted once per flush batch, not per span: the read is
        // O(store) and a flush is per-interval, so this is a bounded cost paid
        // rarely rather than a per-span tax on the hot path.
        let ceiling = tenant_ceiling();
        let already = self.load_for_tenant(tenant_id).map(|v| v.len()).unwrap_or(0);
        let mut headroom = ceiling.saturating_sub(already);

        let now = now_unix_ms();
        let release = capture_release();
        let mut buf = String::with_capacity(spans.len() * 256);

        for span in spans {
            let (symbol_id, join) = match (&span.file, resolver) {
                (Some(file), Some(r)) => match r.resolve(file, &span.name, span.line.map(|l| l as usize), None) {
                    Some(res) => match res.symbol_id() {
                        Some(id) => {
                            report.resolved += 1;
                            let kind = match res {
                                crate::symbol_resolve::Resolution::Extracted { .. } => "extracted",
                                _ => "inferred",
                            };
                            (Some(id.to_string()), kind)
                        }
                        None => {
                            report.ambiguous += 1;
                            (None, "ambiguous")
                        }
                    },
                    None => {
                        report.missed += 1;
                        (None, "miss")
                    }
                },
                (None, _) => {
                    report.no_location += 1;
                    (None, "no_location")
                }
                (Some(_), None) => {
                    report.missed += 1;
                    (None, "no_resolver")
                }
            };

            if headroom == 0 {
                report.refused_over_ceiling += 1;
                continue;
            }
            headroom -= 1;

            let stored = StoredSpan {
                span,
                symbol_id,
                join: join.to_string(),
                stored_at_unix_ms: now,
                tenant_id: tenant_id.to_string(),
                release: release.clone(),
            };
            if let Ok(line) = serde_json::to_string(&stored) {
                buf.push_str(&line);
                buf.push('\n');
            }
        }

        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        file.write_all(buf.as_bytes())?;
        file.flush()?;
        self.rotate_if_needed()?;
        Ok(report)
    }

    /// Read everything back. This is the restart-survival path.
    /// Every span in the store, **unfiltered**.
    ///
    /// Deliberately private. The public read is [`Self::load_for_tenant`]: a
    /// caller that can obtain unfiltered spans is one refactor away from
    /// answering one tenant's question with another's data, which is the defect
    /// M2 found. Keeping this uncallable from outside the module is what stops
    /// that regressing, rather than a convention someone has to remember.
    fn load_all(&self) -> std::io::Result<Vec<StoredSpan>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = OpenOptions::new().read(true).open(&self.path)?;
        // A torn final line (crash mid-write) must not poison the whole store,
        // so undecodable lines are skipped rather than propagated as an error.
        Ok(BufReader::new(file)
            .lines()
            .map_while(Result::ok)
            .filter_map(|l| serde_json::from_str::<StoredSpan>(&l).ok())
            .collect())
    }

    /// This daemon's configured capture tenant — the tenant every span it writes
    /// belongs to, and the only tenant a legacy unlabelled span can answer for.
    pub fn capture_tenant() -> String {
        std::env::var("CORECRUXD_TRACE_TENANT_ID").unwrap_or_else(|_| "local".to_string())
    }

    /// Spans belonging to `tenant_id`, and only those.
    ///
    /// Fails closed on two axes:
    ///
    /// * a span stamped with a different tenant is never returned, and
    /// * a legacy span (empty `tenant_id`, written before partitioning) is
    ///   returned **only** to this daemon's own capture tenant. It was captured
    ///   by this process under that configuration, so attributing it there is
    ///   accurate; attributing it to whoever happens to ask would recreate the
    ///   exact defect partitioning exists to close.
    pub fn load_for_tenant(&self, tenant_id: &str) -> std::io::Result<Vec<StoredSpan>> {
        let capture = Self::capture_tenant();
        Ok(self
            .load_all()?
            .into_iter()
            .filter(|s| {
                if s.tenant_id.is_empty() {
                    tenant_id == capture
                } else {
                    s.tenant_id == tenant_id
                }
            })
            .collect())
    }

    /// Report one tenant's retained volume against the ceiling.
    pub fn volume_for_tenant(&self, tenant_id: &str) -> std::io::Result<SpanVolume> {
        let retained = self.load_for_tenant(tenant_id)?.len();
        let ceiling = tenant_ceiling();
        let pct = retained.saturating_mul(100) / ceiling.max(1);
        Ok(SpanVolume {
            tenant_id: tenant_id.to_string(),
            retained,
            ceiling,
            pct_of_ceiling: pct,
            approaching: pct >= APPROACH_PCT,
            at_ceiling: retained >= ceiling,
        })
    }

    /// Spans for one tenant captured under `release`.
    pub fn load_for_release(&self, tenant_id: &str, release: &str) -> std::io::Result<Vec<StoredSpan>> {
        Ok(self
            .load_for_tenant(tenant_id)?
            .into_iter()
            .filter(|s| s.release == release)
            .collect())
    }

    /// Distinct releases held for a tenant, oldest first, with span counts.
    pub fn releases_for_tenant(&self, tenant_id: &str) -> std::io::Result<Vec<(String, usize)>> {
        let mut first_seen: BTreeMap<String, (u64, usize)> = BTreeMap::new();
        for s in self.load_for_tenant(tenant_id)? {
            let e = first_seen.entry(s.release.clone()).or_insert((s.stored_at_unix_ms, 0));
            e.0 = e.0.min(s.stored_at_unix_ms);
            e.1 += 1;
        }
        let mut v: Vec<(String, u64, usize)> = first_seen.into_iter().map(|(r, (t, c))| (r, t, c)).collect();
        v.sort_by_key(|(_, t, _)| *t);
        Ok(v.into_iter().map(|(r, _, c)| (r, c)).collect())
    }

    /// Drop spans older than the retention window.
    ///
    /// **This deletes, and that is the difference from the M5 ceiling.** The
    /// ceiling refuses *new* spans when a tenant is holding too many and never
    /// removes history; retention removes history that is past its window. Two
    /// limits on two axes — volume and age — and conflating them would mean
    /// either a customer silently losing recent data to a volume cap, or a
    /// tenant holding unbounded history because it stayed under one.
    ///
    /// Returns the number pruned.
    pub fn prune_expired(&self, now_unix_ms_value: u64) -> std::io::Result<usize> {
        let window_ms = retention_days().saturating_mul(24 * 60 * 60 * 1000);
        let cutoff = now_unix_ms_value.saturating_sub(window_ms);
        let all = self.load_all()?;
        let keep: Vec<&StoredSpan> = all.iter().filter(|s| s.stored_at_unix_ms >= cutoff).collect();
        if keep.len() == all.len() {
            return Ok(0);
        }
        let pruned = all.len() - keep.len();
        let tmp = self.path.with_extension("jsonl.tmp");
        {
            let mut f = OpenOptions::new().create(true).truncate(true).write(true).open(&tmp)?;
            for s in keep {
                if let Ok(line) = serde_json::to_string(s) {
                    f.write_all(line.as_bytes())?;
                    f.write_all(b"\n")?;
                }
            }
            f.flush()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(pruned)
    }

    /// All spans of one trace, in capture order.
    /// One trace, scoped to `tenant_id`.
    ///
    /// `trace_id` is a u64 drawn from the same space for every tenant, so an
    /// unscoped lookup is a trace-id-guessing oracle. Scoping here rather than
    /// at the handler keeps the guarantee with the data.
    pub fn load_trace(&self, trace_id: u64, tenant_id: &str) -> std::io::Result<Vec<StoredSpan>> {
        let mut spans: Vec<StoredSpan> = self
            .load_for_tenant(tenant_id)?
            .into_iter()
            .filter(|s| s.span.trace_id == trace_id)
            .collect();
        spans.sort_by_key(|s| (s.span.depth, s.span.span_id));
        Ok(spans)
    }

    /// Distinct traces for one tenant, newest first, with a span count each.
    ///
    /// Scoped for the same reason as [`Self::load_trace`]: an unscoped listing
    /// discloses the existence, count and shape of another tenant's activity
    /// even without returning a single span body.
    pub fn list_traces(&self, limit: usize, tenant_id: &str) -> std::io::Result<Vec<(u64, usize)>> {
        let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
        for s in self.load_for_tenant(tenant_id)? {
            *counts.entry(s.span.trace_id).or_insert(0) += 1;
        }
        let mut v: Vec<(u64, usize)> = counts.into_iter().collect();
        v.reverse();
        v.truncate(limit);
        Ok(v)
    }

    /// Truncate to the newest `max_records` once the file exceeds it.
    ///
    /// Rewrites in place via a temp file so a crash mid-rotate leaves either the
    /// old file or the new one, never a half-written store.
    fn rotate_if_needed(&self) -> std::io::Result<()> {
        let all = self.load_all()?;
        if all.len() <= self.max_records {
            return Ok(());
        }
        let keep = &all[all.len() - self.max_records..];
        let tmp = self.path.with_extension("jsonl.tmp");
        {
            let mut f = OpenOptions::new().create(true).truncate(true).write(true).open(&tmp)?;
            for s in keep {
                if let Ok(line) = serde_json::to_string(s) {
                    f.write_all(line.as_bytes())?;
                    f.write_all(b"\n")?;
                }
            }
            f.flush()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

pub fn persist_enabled() -> bool {
    std::env::var(TRACE_PERSIST_ENV).is_ok_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        matches!(v.as_str(), "1" | "true" | "yes" | "on")
    })
}

pub fn flush_interval_secs() -> u64 {
    std::env::var(TRACE_FLUSH_SECS_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_FLUSH_SECS)
        .max(1)
}

/// Retained spans one tenant may hold before new capture is refused.
///
/// **Distinct from `max_records`**, which rotates the whole store by dropping
/// the oldest records. That is a local disk valve and it deletes. This is the
/// hosted margin guard and it does not: on breach it stops admitting new spans
/// and leaves retained history intact. Selling on repo count while the real cost
/// is span volume is the plan's Constraint 1, and this is the limit that
/// actually holds the cost line.
pub fn tenant_ceiling() -> usize {
    std::env::var(TRACE_TENANT_CEILING_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_TENANT_CEILING)
        .max(1)
}

/// What one tenant is holding against its ceiling.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SpanVolume {
    pub tenant_id: String,
    pub retained: usize,
    pub ceiling: usize,
    /// Percent of ceiling used, rounded down.
    pub pct_of_ceiling: usize,
    /// At or past `APPROACH_PCT`. Surfaced so the customer sees it **before** it
    /// bites rather than discovering it as missing data afterwards.
    pub approaching: bool,
    pub at_ceiling: bool,
}

/// Percent of ceiling at which the customer is warned.
pub const APPROACH_PCT: usize = 80;

/// This daemon's release label, defaulting to its own version.
pub fn capture_release() -> String {
    std::env::var(TRACE_RELEASE_ENV).unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string())
}

/// Retention window in days.
///
/// **90 days is the decided Pro default** (operator, 2026-07-30), not a
/// placeholder. Chosen from the cost model rather than by splitting the range:
/// 30 days makes release-over-release `trace_diff` useless to anyone shipping
/// quarterly, which is the audience P2 is for; 365 makes retention the largest
/// storage line on the account for a capability most teams query over weeks, not
/// years. Governance buys 365 because compliance evidence is the case where the
/// long tail is the product.
///
/// Anything user-facing that states this number must agree with the published
/// price list — `/v1/code-intel/releases` reports the active window alongside
/// the releases it retained, so a mismatch is visible rather than silent.
pub fn retention_days() -> u64 {
    std::env::var(TRACE_RETENTION_DAYS_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_RETENTION_DAYS)
        .max(1)
}

pub fn max_records() -> usize {
    std::env::var(TRACE_MAX_RECORDS_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_RECORDS)
        .max(1)
}

/// Caches a [`SymbolResolver`] keyed by the scan it was built from.
///
/// Rebuilding a 17k-symbol index on every flush would be wasteful, so the
/// resolver is rebuilt only when the registered repo reports a new `scan_id` —
/// i.e. when the watch loop has re-scanned and symbol positions may have moved.
#[derive(Default)]
pub struct ResolverCache {
    scan_id: Option<String>,
    resolver: Option<std::sync::Arc<SymbolResolver>>,
}

impl ResolverCache {
    /// Return a resolver for `(tenant, repo)`, rebuilding only on scan change.
    pub fn get(
        &mut self,
        store: &corecrux_memory::fact_store::FactStore,
        tenant_id: &str,
        repo_id: &str,
    ) -> Option<std::sync::Arc<SymbolResolver>> {
        let repo = crate::repo_registry::get_repo(store, tenant_id, repo_id)?;
        if repo.last_scan_id.is_some() && repo.last_scan_id == self.scan_id {
            return self.resolver.clone();
        }
        let scan_json = crate::repo_registry::load_scan_json(store, tenant_id, repo_id)?;
        let scan: crate::workspace_scan::WorkspaceScan = serde_json::from_str(&scan_json).ok()?;
        let resolver = std::sync::Arc::new(SymbolResolver::from_scan(&scan));
        self.scan_id.clone_from(&repo.last_scan_id);
        self.resolver = Some(std::sync::Arc::clone(&resolver));
        Some(resolver)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_scan::{SymbolInfo, WorkspaceScan};

    fn span(name: &str, file: Option<&str>, line: Option<u32>, trace: u64, span_id: u64) -> SpanRecord {
        SpanRecord {
            trace_id: trace,
            span_id,
            parent_span_id: None,
            name: name.into(),
            target: "t".into(),
            file: file.map(str::to_string),
            line,
            module_path: None,
            duration_ns: 100,
            depth: 0,
            had_error: false,
        }
    }

    fn resolver_with(symbols: Vec<SymbolInfo>) -> SymbolResolver {
        SymbolResolver::from_scan(&WorkspaceScan {
            symbols,
            ..Default::default()
        })
    }

    fn sym(file: &str, name: &str, line: usize) -> SymbolInfo {
        SymbolInfo {
            crate_name: "c".into(),
            module_path: "c::m".into(),
            file_rel_path: file.into(),
            line,
            kind: "fn".into(),
            name: name.into(),
            is_pub: true,
        }
    }

    #[test]
    fn resolves_and_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("traces").join("spans.jsonl");
        let store = TraceStore::open(path.clone(), 1000).unwrap();
        let r = resolver_with(vec![sym("a.rs", "handler", 10)]);

        let report = store
            .append_resolved(vec![span("handler", Some("a.rs"), Some(9), 1, 1)], Some(&r), "local")
            .unwrap();
        assert_eq!(report.resolved, 1);
        assert_eq!(report.spans_drained, 1);

        // Restart survival: a brand-new handle over the same path sees it.
        let reopened = TraceStore::open(path, 1000).unwrap();
        let all = reopened.load_all().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].join, "extracted");
        assert!(all[0].symbol_id.is_some());
        assert_eq!(all[0].span.name, "handler");
    }

    #[test]
    fn unresolvable_spans_are_kept_with_an_honest_join_label() {
        let tmp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(tmp.path().join("t.jsonl"), 1000).unwrap();
        // Two same-named symbols 1 line apart => near-tie => ambiguous.
        let r = resolver_with(vec![sym("a.rs", "dup", 10), sym("a.rs", "dup", 11)]);

        let report = store
            .append_resolved(
                vec![
                    span("dup", Some("a.rs"), Some(10), 1, 1),  // ambiguous
                    span("ghost", Some("a.rs"), Some(1), 1, 2), // miss
                    span("nofile", None, None, 1, 3),           // no location
                ],
                Some(&r),
                "local",
            )
            .unwrap();

        assert_eq!(report.ambiguous, 1);
        assert_eq!(report.missed, 1);
        assert_eq!(report.no_location, 1);
        assert_eq!(report.resolved, 0);

        // Crucially: nothing was dropped. An unjoinable span is still evidence
        // that code ran.
        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 3);
        let joins: Vec<&str> = all.iter().map(|s| s.join.as_str()).collect();
        assert!(joins.contains(&"ambiguous"));
        assert!(joins.contains(&"miss"));
        assert!(joins.contains(&"no_location"));
        assert!(all.iter().all(|s| s.symbol_id.is_none()));
    }

    #[test]
    fn rotation_caps_the_file_and_keeps_the_newest() {
        let tmp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(tmp.path().join("t.jsonl"), 10).unwrap();
        let r = resolver_with(vec![sym("a.rs", "h", 10)]);

        for i in 0..50u64 {
            store
                .append_resolved(vec![span("h", Some("a.rs"), Some(10), i, i)], Some(&r), "local")
                .unwrap();
        }
        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 10, "store must be capped");
        // Newest kept: trace ids 40..49.
        assert_eq!(all.first().unwrap().span.trace_id, 40);
        assert_eq!(all.last().unwrap().span.trace_id, 49);
    }

    #[test]
    fn torn_final_line_does_not_poison_the_store() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("t.jsonl");
        let store = TraceStore::open(path.clone(), 1000).unwrap();
        let r = resolver_with(vec![sym("a.rs", "h", 10)]);
        store
            .append_resolved(vec![span("h", Some("a.rs"), Some(10), 1, 1)], Some(&r), "local")
            .unwrap();

        // Simulate a crash mid-append.
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(b"{\"span\":{\"trace_id\":2,\"incomp").unwrap();
        drop(f);

        let all = store.load_all().unwrap();
        assert_eq!(all.len(), 1, "the good record still reads back");
    }

    #[test]
    fn load_trace_filters_and_orders() {
        let tmp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(tmp.path().join("t.jsonl"), 1000).unwrap();
        let r = resolver_with(vec![sym("a.rs", "h", 10)]);
        let mut child = span("h", Some("a.rs"), Some(10), 7, 2);
        child.depth = 1;
        store
            .append_resolved(
                vec![
                    child,
                    span("h", Some("a.rs"), Some(10), 7, 1),
                    span("h", Some("a.rs"), Some(10), 8, 3),
                ],
                Some(&r),
                "local",
            )
            .unwrap();

        let t7 = store.load_trace(7, "local").unwrap();
        assert_eq!(t7.len(), 2);
        assert_eq!(t7[0].span.depth, 0, "roots first");
        assert_eq!(t7[1].span.depth, 1);
    }

    #[test]
    fn empty_flush_is_a_no_op() {
        let tmp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(tmp.path().join("t.jsonl"), 1000).unwrap();
        let report = store.append_resolved(vec![], None, "local").unwrap();
        assert_eq!(report.spans_drained, 0);
        assert!(!store.path().exists(), "no file created for an empty flush");
    }

    // ── M3: tenant partitioning of the runtime span plane ───────────────────
    // The defect M2 found was an authorization check with no matching data
    // filter. These pin the filter itself, at the level the guarantee lives.

    #[test]
    fn spans_are_stamped_with_the_tenant_that_captured_them() {
        let dir = tempfile::tempdir().unwrap();
        let store = TraceStore::open(dir.path().join("s.jsonl"), 1000).unwrap();
        store
            .append_resolved(vec![span("a", Some("f.rs"), Some(1), 1, 1)], None, "tenant-a")
            .unwrap();
        let got = store.load_for_tenant("tenant-a").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].tenant_id, "tenant-a");
    }

    #[test]
    fn one_tenants_spans_are_invisible_to_another() {
        let dir = tempfile::tempdir().unwrap();
        let store = TraceStore::open(dir.path().join("s.jsonl"), 1000).unwrap();
        store
            .append_resolved(vec![span("a", Some("a.rs"), Some(1), 1, 1)], None, "tenant-a")
            .unwrap();
        store
            .append_resolved(vec![span("b", Some("b.rs"), Some(1), 2, 2)], None, "tenant-b")
            .unwrap();

        let a = store.load_for_tenant("tenant-a").unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].span.name, "a", "tenant-a must not see tenant-b's span");

        let b = store.load_for_tenant("tenant-b").unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].span.name, "b");

        // A tenant with nothing in the store gets nothing, not everything.
        assert!(store.load_for_tenant("tenant-c").unwrap().is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn a_legacy_unlabelled_span_answers_only_for_the_capture_tenant() {
        // Records written before partitioning have no tenant field. They must
        // not become wildcards — that would be the original defect wearing a
        // different hat.
        std::env::set_var("CORECRUXD_TRACE_TENANT_ID", "the-capture-tenant");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.jsonl");
        let legacy = serde_json::json!({
            "trace_id": 1, "span_id": 1, "parent_span_id": null,
            "name": "old", "target": "t", "file": "f.rs", "line": 1,
            "module_path": null, "duration_ns": 1, "depth": 0, "had_error": false,
            "join": "miss", "stored_at_unix_ms": 0
        });
        std::fs::write(&path, format!("{legacy}\n")).unwrap();
        let store = TraceStore::open(path, 1000).unwrap();

        assert_eq!(
            store.load_for_tenant("the-capture-tenant").unwrap().len(),
            1,
            "the daemon that captured it must still see its own history"
        );
        assert!(
            store.load_for_tenant("someone-else").unwrap().is_empty(),
            "an unlabelled legacy span must never answer for another tenant"
        );
        std::env::remove_var("CORECRUXD_TRACE_TENANT_ID");
    }

    #[test]
    fn trace_lookup_by_id_is_tenant_scoped() {
        // trace_id is a u64 from one space shared by every tenant, so an
        // unscoped lookup would be a guessing oracle.
        let dir = tempfile::tempdir().unwrap();
        let store = TraceStore::open(dir.path().join("s.jsonl"), 1000).unwrap();
        store
            .append_resolved(vec![span("a", Some("a.rs"), Some(1), 42, 1)], None, "tenant-a")
            .unwrap();

        assert_eq!(store.load_trace(42, "tenant-a").unwrap().len(), 1);
        assert!(
            store.load_trace(42, "tenant-b").unwrap().is_empty(),
            "knowing the trace_id must not be enough to read it"
        );
    }

    #[test]
    fn trace_listing_does_not_disclose_another_tenants_activity() {
        // Even without span bodies, a listing leaks existence, count and shape.
        let dir = tempfile::tempdir().unwrap();
        let store = TraceStore::open(dir.path().join("s.jsonl"), 1000).unwrap();
        store
            .append_resolved(vec![span("a", Some("a.rs"), Some(1), 7, 1)], None, "tenant-a")
            .unwrap();
        store
            .append_resolved(vec![span("b", Some("b.rs"), Some(1), 8, 2)], None, "tenant-b")
            .unwrap();

        let a = store.list_traces(100, "tenant-a").unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].0, 7);
        let b = store.list_traces(100, "tenant-b").unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].0, 8);
    }

    // ── M5: the retained-span ceiling ───────────────────────────────────────
    // Repo count is what the customer buys; span volume is what costs money.
    // This is the limit that actually holds the cost line.

    #[test]
    #[serial_test::serial]
    fn at_the_ceiling_new_spans_are_refused_and_retained_ones_survive() {
        // The defining property: containment must not be achieved by deletion.
        // A customer at the ceiling loses new capture, not the history their
        // answers have been coming from.
        std::env::set_var(TRACE_TENANT_CEILING_ENV, "3");
        let dir = tempfile::tempdir().unwrap();
        let store = TraceStore::open(dir.path().join("s.jsonl"), 1_000_000).unwrap();

        let batch: Vec<_> = (0..3).map(|i| span("a", Some("a.rs"), Some(1), 1, i)).collect();
        let r1 = store.append_resolved(batch, None, "t1").unwrap();
        assert_eq!(r1.refused_over_ceiling, 0);
        assert_eq!(store.load_for_tenant("t1").unwrap().len(), 3);

        // Two more against a ceiling of three: both refused, nothing deleted.
        let more: Vec<_> = (10..12).map(|i| span("b", Some("b.rs"), Some(1), 2, i)).collect();
        let r2 = store.append_resolved(more, None, "t1").unwrap();
        assert_eq!(
            r2.refused_over_ceiling, 2,
            "over-ceiling spans must be refused at ingest"
        );
        let kept = store.load_for_tenant("t1").unwrap();
        assert_eq!(kept.len(), 3, "retained history must be untouched");
        assert!(
            kept.iter().all(|s| s.span.name == "a"),
            "the ORIGINAL spans must survive; refusing new must not evict old"
        );
        std::env::remove_var(TRACE_TENANT_CEILING_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn one_tenants_ceiling_does_not_contain_another() {
        // A noisy neighbour must not exhaust a quiet tenant's headroom — the
        // ceiling is per account, which is the whole point of it being a margin
        // guard rather than a global disk valve.
        std::env::set_var(TRACE_TENANT_CEILING_ENV, "2");
        let dir = tempfile::tempdir().unwrap();
        let store = TraceStore::open(dir.path().join("s.jsonl"), 1_000_000).unwrap();

        let noisy: Vec<_> = (0..5).map(|i| span("n", Some("n.rs"), Some(1), 1, i)).collect();
        let rn = store.append_resolved(noisy, None, "noisy").unwrap();
        assert_eq!(rn.refused_over_ceiling, 3);

        let quiet = vec![span("q", Some("q.rs"), Some(1), 2, 99)];
        let rq = store.append_resolved(quiet, None, "quiet").unwrap();
        assert_eq!(rq.refused_over_ceiling, 0, "quiet tenant keeps its own headroom");
        assert_eq!(store.load_for_tenant("quiet").unwrap().len(), 1);
        assert_eq!(store.load_for_tenant("noisy").unwrap().len(), 2);
        std::env::remove_var(TRACE_TENANT_CEILING_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn volume_warns_before_it_bites() {
        // "Visible to the customer before it bites" is the gate. A limit whose
        // first signal is missing data is a support ticket, not a limit.
        std::env::set_var(TRACE_TENANT_CEILING_ENV, "10");
        let dir = tempfile::tempdir().unwrap();
        let store = TraceStore::open(dir.path().join("s.jsonl"), 1_000_000).unwrap();

        let batch: Vec<_> = (0..8).map(|i| span("a", Some("a.rs"), Some(1), 1, i)).collect();
        store.append_resolved(batch, None, "t1").unwrap();

        let v = store.volume_for_tenant("t1").unwrap();
        assert_eq!(v.retained, 8);
        assert_eq!(v.ceiling, 10);
        assert_eq!(v.pct_of_ceiling, 80);
        assert!(v.approaching, "80% must warn");
        assert!(!v.at_ceiling, "80% is not yet the limit — warning precedes refusal");
        std::env::remove_var(TRACE_TENANT_CEILING_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn a_partially_full_batch_admits_what_fits() {
        // Containment is per span, not per batch: a batch that straddles the
        // ceiling stores the part that fits rather than discarding all of it.
        std::env::set_var(TRACE_TENANT_CEILING_ENV, "4");
        let dir = tempfile::tempdir().unwrap();
        let store = TraceStore::open(dir.path().join("s.jsonl"), 1_000_000).unwrap();

        let batch: Vec<_> = (0..6).map(|i| span("a", Some("a.rs"), Some(1), 1, i)).collect();
        let r = store.append_resolved(batch, None, "t1").unwrap();
        assert_eq!(r.refused_over_ceiling, 2);
        assert_eq!(store.load_for_tenant("t1").unwrap().len(), 4);
        std::env::remove_var(TRACE_TENANT_CEILING_ENV);
    }

    // ── M6: retention and release-over-release history ──────────────────────

    #[test]
    #[serial_test::serial]
    fn spans_are_labelled_with_the_release_that_captured_them() {
        std::env::set_var(TRACE_RELEASE_ENV, "v1.4.0");
        let dir = tempfile::tempdir().unwrap();
        let store = TraceStore::open(dir.path().join("s.jsonl"), 1_000_000).unwrap();
        store
            .append_resolved(vec![span("a", Some("a.rs"), Some(1), 1, 1)], None, "t1")
            .unwrap();
        let got = store.load_for_tenant("t1").unwrap();
        assert_eq!(got[0].release, "v1.4.0");
        std::env::remove_var(TRACE_RELEASE_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn two_releases_are_separable_weeks_apart() {
        // The M6 gate: compare v1.3 against v1.4, not two windows in the same
        // afternoon. A timestamp cannot answer this when releases overlap.
        let dir = tempfile::tempdir().unwrap();
        let store = TraceStore::open(dir.path().join("s.jsonl"), 1_000_000).unwrap();

        std::env::set_var(TRACE_RELEASE_ENV, "v1.3.0");
        store
            .append_resolved(vec![span("old_handler", Some("a.rs"), Some(1), 1, 1)], None, "t1")
            .unwrap();
        std::env::set_var(TRACE_RELEASE_ENV, "v1.4.0");
        store
            .append_resolved(vec![span("new_handler", Some("b.rs"), Some(1), 2, 2)], None, "t1")
            .unwrap();
        std::env::remove_var(TRACE_RELEASE_ENV);

        let old = store.load_for_release("t1", "v1.3.0").unwrap();
        let new = store.load_for_release("t1", "v1.4.0").unwrap();
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].span.name, "old_handler");
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].span.name, "new_handler");

        // "What executes now that did not before" — the question that makes the
        // tool operational rather than a curiosity.
        let names_old: std::collections::BTreeSet<_> = old.iter().map(|s| s.span.name.clone()).collect();
        let names_new: std::collections::BTreeSet<_> = new.iter().map(|s| s.span.name.clone()).collect();
        let appeared: Vec<_> = names_new.difference(&names_old).collect();
        assert_eq!(appeared, vec![&"new_handler".to_string()]);
    }

    #[test]
    #[serial_test::serial]
    fn releases_are_listed_oldest_first_with_counts() {
        let dir = tempfile::tempdir().unwrap();
        let store = TraceStore::open(dir.path().join("s.jsonl"), 1_000_000).unwrap();
        std::env::set_var(TRACE_RELEASE_ENV, "v1.0.0");
        store
            .append_resolved(vec![span("a", Some("a.rs"), Some(1), 1, 1)], None, "t1")
            .unwrap();
        std::env::set_var(TRACE_RELEASE_ENV, "v2.0.0");
        let two: Vec<_> = (0..2).map(|i| span("b", Some("b.rs"), Some(1), 2, i)).collect();
        store.append_resolved(two, None, "t1").unwrap();
        std::env::remove_var(TRACE_RELEASE_ENV);

        let releases = store.releases_for_tenant("t1").unwrap();
        assert_eq!(releases.len(), 2);
        assert!(releases.iter().any(|(r, c)| r == "v1.0.0" && *c == 1));
        assert!(releases.iter().any(|(r, c)| r == "v2.0.0" && *c == 2));
    }

    #[test]
    #[serial_test::serial]
    fn retention_prunes_past_the_window_and_keeps_what_is_inside_it() {
        // Retention DELETES — that is the difference from the M5 ceiling, which
        // refuses new spans and never removes history. Two limits, two axes.
        std::env::set_var(TRACE_RETENTION_DAYS_ENV, "30");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("s.jsonl");
        let day_ms: u64 = 24 * 60 * 60 * 1000;
        let now: u64 = 1_000 * day_ms;

        let mk = |name: &str, at: u64| {
            serde_json::json!({
                "trace_id": 1, "span_id": 1, "parent_span_id": null,
                "name": name, "target": "t", "file": "f.rs", "line": 1,
                "module_path": null, "duration_ns": 1, "depth": 0, "had_error": false,
                "join": "miss", "stored_at_unix_ms": at, "tenant_id": "t1", "release": "v1"
            })
            .to_string()
        };
        // 10 days old (inside a 30-day window) and 60 days old (outside it).
        std::fs::write(
            &path,
            format!(
                "{}\n{}\n",
                mk("recent", now - 10 * day_ms),
                mk("ancient", now - 60 * day_ms)
            ),
        )
        .unwrap();
        let store = TraceStore::open(path, 1_000_000).unwrap();

        let pruned = store.prune_expired(now).unwrap();
        assert_eq!(pruned, 1, "only the out-of-window span may be pruned");
        let left = store.load_for_tenant("t1").unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].span.name, "recent", "in-window history must survive");
        std::env::remove_var(TRACE_RETENTION_DAYS_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn pruning_nothing_leaves_the_store_untouched() {
        // A no-op prune must not rewrite the file — a rewrite is a crash window,
        // and paying it for nothing is how retention loses data it should keep.
        std::env::set_var(TRACE_RETENTION_DAYS_ENV, "3650");
        let dir = tempfile::tempdir().unwrap();
        let store = TraceStore::open(dir.path().join("s.jsonl"), 1_000_000).unwrap();
        store
            .append_resolved(vec![span("a", Some("a.rs"), Some(1), 1, 1)], None, "t1")
            .unwrap();
        assert_eq!(store.prune_expired(now_unix_ms()).unwrap(), 0);
        assert_eq!(store.load_for_tenant("t1").unwrap().len(), 1);
        std::env::remove_var(TRACE_RETENTION_DAYS_ENV);
    }
}
