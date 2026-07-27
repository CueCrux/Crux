// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `trace_store` — durable runtime traces, joined to the static code graph.
//!
//! ExecPlan `crux-runtime-codemap-and-agent-query-api-2026-07-27`, milestone M4.
//!
//! Drains the M2 [`SpanRing`], resolves each span's `(file, name, line)` to a
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

const DEFAULT_FLUSH_SECS: u64 = 10;
const DEFAULT_MAX_RECORDS: usize = 200_000;

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
    pub fn append_resolved(
        &self,
        spans: Vec<SpanRecord>,
        resolver: Option<&SymbolResolver>,
    ) -> std::io::Result<FlushReport> {
        let mut report = FlushReport {
            spans_drained: spans.len(),
            ..Default::default()
        };
        if spans.is_empty() {
            return Ok(report);
        }

        let now = now_unix_ms();
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

            let stored = StoredSpan {
                span,
                symbol_id,
                join: join.to_string(),
                stored_at_unix_ms: now,
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
    pub fn load_all(&self) -> std::io::Result<Vec<StoredSpan>> {
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

    /// All spans of one trace, in capture order.
    pub fn load_trace(&self, trace_id: u64) -> std::io::Result<Vec<StoredSpan>> {
        let mut spans: Vec<StoredSpan> = self
            .load_all()?
            .into_iter()
            .filter(|s| s.span.trace_id == trace_id)
            .collect();
        spans.sort_by_key(|s| (s.span.depth, s.span.span_id));
        Ok(spans)
    }

    /// Distinct traces, newest first, with a span count each.
    pub fn list_traces(&self, limit: usize) -> std::io::Result<Vec<(u64, usize)>> {
        let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
        for s in self.load_all()? {
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
            .append_resolved(vec![span("handler", Some("a.rs"), Some(9), 1, 1)], Some(&r))
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
                .append_resolved(vec![span("h", Some("a.rs"), Some(10), i, i)], Some(&r))
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
            .append_resolved(vec![span("h", Some("a.rs"), Some(10), 1, 1)], Some(&r))
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
            )
            .unwrap();

        let t7 = store.load_trace(7).unwrap();
        assert_eq!(t7.len(), 2);
        assert_eq!(t7[0].span.depth, 0, "roots first");
        assert_eq!(t7[1].span.depth, 1);
    }

    #[test]
    fn empty_flush_is_a_no_op() {
        let tmp = tempfile::tempdir().unwrap();
        let store = TraceStore::open(tmp.path().join("t.jsonl"), 1000).unwrap();
        let report = store.append_resolved(vec![], None).unwrap();
        assert_eq!(report.spans_drained, 0);
        assert!(!store.path().exists(), "no file created for an empty flush");
    }
}
