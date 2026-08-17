// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `span_layer` — runtime execution capture for the code map.
//!
//! ExecPlan `crux-runtime-codemap-and-agent-query-api-2026-07-27`, milestone M2.
//!
//! A [`tracing_subscriber::Layer`] that records the span tree — which code
//! actually ran, in what order, nested how, for how long — into a bounded
//! in-memory ring. Each record carries `file` and `line` straight off
//! [`tracing::Metadata`], which is the join key back to the static code graph
//! via `corecruxd::symbol_resolve`.
//!
//! # Why a second layer rather than extending `OpsObserveLayer`
//!
//! [`crate::ops_layer::OpsObserveLayer`] is deliberately narrow: ERROR/WARN
//! *events* promoted straight to durable facts. Span capture is high-volume and
//! ephemeral. Mixing them would dilute fact recall, which the workspace
//! practices warn against directly, so they stay separate.
//!
//! # Cost when disabled
//!
//! Zero. The layer is not constructed unless `CORECRUXD_TRACE_CAPTURE` is set,
//! so there is no installed-but-early-returning path — see
//! [`CruxSpanLayer::from_env`].
//!
//! # Sampling is per-trace, not per-span
//!
//! The decision is made once when a root span opens and is inherited by every
//! descendant. A half-sampled trace is worse than no trace: it yields a call
//! graph with holes that read as calls that never happened.
//!
//! # Bounded, lossy, and never in the way
//!
//! The ring drops the *oldest* record when full. Capture must never block a
//! request, never fail one, and never grow without limit; losing old spans is
//! the acceptable failure mode.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tracing::span::{Attributes, Id};
use tracing::Subscriber;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

/// Environment switch. Unset ⇒ the layer is never built.
pub const TRACE_CAPTURE_ENV: &str = "CORECRUXD_TRACE_CAPTURE";
/// Ring capacity override.
pub const TRACE_CAPACITY_ENV: &str = "CORECRUXD_TRACE_CAPACITY";
/// Sample rate override: keep 1 trace in N. `1` keeps everything.
pub const TRACE_SAMPLE_ENV: &str = "CORECRUXD_TRACE_SAMPLE_RATE";

const DEFAULT_CAPACITY: usize = 16_384;
const DEFAULT_SAMPLE_RATE: u64 = 1;

/// The span field a site records its outcome on.
///
/// Matched by name in [`CruxSpanLayer::on_record`]. A span that never declares
/// this field never reaches that path, which is what keeps the cost of the
/// outcome dimension off every span that does not opt in.
pub const OUTCOME_FIELD: &str = "crux.outcome";

/// Did this span's work come back empty?
///
/// `had_error` already makes a panic or an `Err` visible. This is the other
/// silent failure: a function that runs normally and returns `None`, an empty
/// collection, or a zero count is otherwise indistinguishable from one that
/// returned a full result — `executed: true` is true, and useless.
///
/// # Three states, not a `bool`
///
/// [`Unrecorded`](Self::Unrecorded) must stay distinguishable from
/// [`NonEmpty`](Self::NonEmpty). Collapsing them would make an absent signal
/// read as a healthy one — the exact defect this dimension exists to catch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SpanOutcome {
    /// The site never declared an outcome. What every pre-existing span and
    /// every uninstrumented site reads as. Not a claim that work was produced.
    #[default]
    Unrecorded,
    /// Ran and produced nothing: `None`, an empty collection, a zero count.
    Empty,
    /// Ran and produced something.
    NonEmpty,
}

impl SpanOutcome {
    /// `true` only for [`Empty`](Self::Empty) — `Unrecorded` is not emptiness.
    pub fn is_empty_result(self) -> bool {
        matches!(self, Self::Empty)
    }

    /// `true` when a site actually spoke, whatever it said.
    pub fn is_recorded(self) -> bool {
        !matches!(self, Self::Unrecorded)
    }

    fn from_bool(is_empty: bool) -> Self {
        if is_empty {
            Self::Empty
        } else {
            Self::NonEmpty
        }
    }
}

/// Declare whether the current span's work came back empty.
///
/// Call this at a site where returning nothing is *suspicious* — where an
/// always-empty result would mean a bug. The enclosing span must declare the
/// field, or `tracing` discards the value:
///
/// ```ignore
/// #[tracing::instrument(fields(crux.outcome = tracing::field::Empty))]
/// fn load_latest_workspace_blocking(...) -> Option<WorkspaceScan> {
///     let scan = lookup();
///     crux_observe::span_layer::record_outcome(scan.is_none());
///     scan
/// }
/// ```
///
/// A no-op when no span is active or capture is off.
pub fn record_outcome(is_empty: bool) {
    tracing::Span::current().record(OUTCOME_FIELD, if is_empty { "empty" } else { "non_empty" });
}

/// Record an outcome by passing the value through, so instrumenting a site does
/// not mean restructuring its returns.
///
/// ```ignore
/// fn list_dossiers(&self) -> Vec<Dossier> {
///     self.scan_prefix("dossier:").record_outcome_through()
/// }
/// ```
pub trait OutcomeExt: Sized {
    /// Is this value the empty case?
    fn is_empty_result(&self) -> bool;

    /// Record the outcome on the current span and return `self` unchanged.
    fn record_outcome_through(self) -> Self {
        record_outcome(self.is_empty_result());
        self
    }
}

impl<T> OutcomeExt for Option<T> {
    fn is_empty_result(&self) -> bool {
        self.is_none()
    }
}

impl<T> OutcomeExt for Vec<T> {
    fn is_empty_result(&self) -> bool {
        self.is_empty()
    }
}

impl<T, E> OutcomeExt for Result<T, E>
where
    T: OutcomeExt,
{
    /// An `Err` is **not** empty — `had_error` already covers failure, and
    /// conflating the two would let a loud failure masquerade as a silent one.
    /// Only the `Ok` payload is judged.
    fn is_empty_result(&self) -> bool {
        self.as_ref().is_ok_and(OutcomeExt::is_empty_result)
    }
}

/// One completed span: a node in the runtime call tree.
///
/// `file` + `line` + `name` are the join key into the static code graph. `name`
/// is the span name, which for `#[tracing::instrument]` defaults to the function
/// name — exactly what the resolver expects.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SpanRecord {
    /// Root span id of this trace. Every span in one logical operation shares it.
    pub trace_id: u64,
    pub span_id: u64,
    /// `None` for a root span.
    pub parent_span_id: Option<u64>,
    pub name: String,
    pub target: String,
    /// Source file as `tracing` reports it, or `None` for spans without location.
    pub file: Option<String>,
    pub line: Option<u32>,
    pub module_path: Option<String>,
    /// Wall-clock nanoseconds between `on_enter` and `on_close`.
    pub duration_ns: u64,
    /// Nesting depth; 0 for a root.
    pub depth: u32,
    /// Whether the span closed with an error recorded on it.
    pub had_error: bool,
    /// Whether the span's work came back empty, when the site said so.
    ///
    /// `#[serde(default)]` so a `spans.jsonl` written before this field existed
    /// still loads, reading as [`SpanOutcome::Unrecorded`] — which is the honest
    /// answer for a record captured before anything could declare an outcome.
    #[serde(default)]
    pub outcome: SpanOutcome,
}

/// A completed span as captured on the hot path: **allocation-free**.
///
/// Every string `tracing::Metadata` exposes is already `&'static str` (they come
/// from the macro callsite), so capture borrows them instead of copying. This is
/// the difference between ~380ns and ~100ns per span — measured, see
/// `benches/span_capture.rs`. Owned [`SpanRecord`]s are materialised only when
/// the ring is read, which happens off the request path.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RawSpan {
    pub trace_id: u64,
    pub span_id: u64,
    pub parent_span_id: Option<u64>,
    pub name: &'static str,
    pub target: &'static str,
    pub file: Option<&'static str>,
    pub line: Option<u32>,
    pub module_path: Option<&'static str>,
    pub duration_ns: u64,
    pub depth: u32,
    pub had_error: bool,
    /// One `Copy` byte. Keeps [`RawSpan`] allocation-free, so the outcome
    /// dimension costs the capture path nothing it did not already pay.
    pub outcome: SpanOutcome,
}

impl RawSpan {
    /// Materialise the owned, serialisable form. Called on read, never on capture.
    pub fn to_record(self) -> SpanRecord {
        SpanRecord {
            trace_id: self.trace_id,
            span_id: self.span_id,
            parent_span_id: self.parent_span_id,
            name: self.name.to_string(),
            target: self.target.to_string(),
            file: self.file.map(str::to_string),
            line: self.line,
            module_path: self.module_path.map(str::to_string),
            duration_ns: self.duration_ns,
            depth: self.depth,
            had_error: self.had_error,
            outcome: self.outcome,
        }
    }
}

/// Fixed-capacity, head-dropping ring of completed spans.
#[derive(Debug, Default)]
pub struct SpanRing {
    inner: Mutex<VecDeque<RawSpan>>,
    capacity: usize,
    dropped: AtomicU64,
    captured: AtomicU64,
}

impl SpanRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity.min(1024))),
            capacity: capacity.max(1),
            dropped: AtomicU64::new(0),
            captured: AtomicU64::new(0),
        }
    }

    /// Push a span, evicting the oldest if full.
    ///
    /// Takes `&self` and swallows lock poisoning: a panic elsewhere must not
    /// turn trace capture into a second failure.
    pub fn push(&self, span: RawSpan) {
        let Ok(mut q) = self.inner.lock() else {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        while q.len() >= self.capacity {
            q.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        q.push_back(span);
        self.captured.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot every retained span as owned records, newest last. Does not drain.
    pub fn snapshot(&self) -> Vec<SpanRecord> {
        self.inner
            .lock()
            .map(|q| q.iter().map(|s| s.to_record()).collect())
            .unwrap_or_default()
    }

    /// Take everything, leaving the ring empty. Used by the M4 flusher.
    pub fn drain(&self) -> Vec<SpanRecord> {
        self.inner
            .lock()
            .map(|mut q| q.drain(..).map(|s| s.to_record()).collect())
            .unwrap_or_default()
    }

    /// Records currently retained.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|q| q.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Records evicted or lost since start — the honest data-loss counter.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Records successfully captured since start.
    pub fn captured(&self) -> u64 {
        self.captured.load(Ordering::Relaxed)
    }
}

/// Per-span state held in the registry's extensions.
#[derive(Debug)]
struct SpanState {
    trace_id: u64,
    depth: u32,
    entered_at: Option<Instant>,
    /// Accumulated across re-entries, so an async span polled many times reports
    /// total time on-CPU rather than only its final poll.
    elapsed_ns: u64,
    sampled: bool,
    had_error: bool,
    outcome: SpanOutcome,
}

/// Reads `crux.outcome` off a `record` call and ignores every other field.
struct OutcomeVisitor(Option<SpanOutcome>);

impl tracing::field::Visit for OutcomeVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == OUTCOME_FIELD {
            self.0 = match value {
                "empty" => Some(SpanOutcome::Empty),
                "non_empty" => Some(SpanOutcome::NonEmpty),
                _ => None,
            };
        }
    }

    /// Also accept `record(OUTCOME_FIELD, true)` for callers who prefer a bool.
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        if field.name() == OUTCOME_FIELD {
            self.0 = Some(SpanOutcome::from_bool(value));
        }
    }

    fn record_debug(&mut self, _field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {
        // Every other field type is irrelevant here. Deliberately empty rather
        // than absent: `Visit` requires it, and doing anything would mean
        // paying for fields this layer does not care about.
    }
}

/// The capture layer. Clone-cheap; the ring is shared.
#[derive(Debug, Clone)]
pub struct CruxSpanLayer {
    ring: Arc<SpanRing>,
    sample_rate: u64,
    traces_seen: Arc<AtomicU64>,
}

impl CruxSpanLayer {
    pub fn new(ring: Arc<SpanRing>, sample_rate: u64) -> Self {
        Self {
            ring,
            sample_rate: sample_rate.max(1),
            traces_seen: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Build from the environment, or `None` when capture is off.
    ///
    /// Returning `None` is what keeps the disabled path free: the caller skips
    /// `.with(layer)` entirely rather than installing an inert layer.
    pub fn from_env() -> Option<(Self, Arc<SpanRing>)> {
        if !env_truthy(TRACE_CAPTURE_ENV) {
            return None;
        }
        let capacity = std::env::var(TRACE_CAPACITY_ENV)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(DEFAULT_CAPACITY);
        let sample_rate = std::env::var(TRACE_SAMPLE_ENV)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(DEFAULT_SAMPLE_RATE);
        let ring = Arc::new(SpanRing::new(capacity));
        Some((Self::new(Arc::clone(&ring), sample_rate), ring))
    }

    pub fn ring(&self) -> &Arc<SpanRing> {
        &self.ring
    }
}

/// `1`/`true`/`yes`/`on` are true; everything else (including unset) is false.
fn env_truthy(key: &str) -> bool {
    std::env::var(key).is_ok_and(|v| {
        let v = v.trim().to_ascii_lowercase();
        matches!(v.as_str(), "1" | "true" | "yes" | "on")
    })
}

impl<S> Layer<S> for CruxSpanLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, _attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };

        // Inherit trace identity and the sampling decision from the parent, so a
        // captured trace is always structurally complete.
        let (trace_id, depth, sampled) = match span.parent() {
            Some(parent) => parent
                .extensions()
                .get::<SpanState>()
                .map_or((id.into_u64(), 0, true), |p| (p.trace_id, p.depth + 1, p.sampled)),
            None => {
                let n = self.traces_seen.fetch_add(1, Ordering::Relaxed);
                (id.into_u64(), 0, n % self.sample_rate == 0)
            }
        };

        span.extensions_mut().insert(SpanState {
            trace_id,
            depth,
            entered_at: None,
            elapsed_ns: 0,
            sampled,
            had_error: false,
            outcome: SpanOutcome::Unrecorded,
        });
    }

    fn on_record(&self, id: &Id, values: &tracing::span::Record<'_>, ctx: Context<'_, S>) {
        let mut visitor = OutcomeVisitor(None);
        values.record(&mut visitor);
        let Some(outcome) = visitor.0 else { return };
        let Some(span) = ctx.span(id) else { return };
        let mut ext = span.extensions_mut();
        if let Some(state) = ext.get_mut::<SpanState>() {
            state.outcome = outcome;
        }
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut ext = span.extensions_mut();
        if let Some(state) = ext.get_mut::<SpanState>() {
            state.entered_at = Some(Instant::now());
        }
    }

    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut ext = span.extensions_mut();
        if let Some(state) = ext.get_mut::<SpanState>() {
            if let Some(started) = state.entered_at.take() {
                state.elapsed_ns = state.elapsed_ns.saturating_add(started.elapsed().as_nanos() as u64);
            }
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        // Mark the enclosing span so a caller can find failing paths without
        // correlating a separate error stream.
        if *event.metadata().level() != tracing::Level::ERROR {
            return;
        }
        if let Some(span) = ctx.event_span(event) {
            let mut ext = span.extensions_mut();
            if let Some(state) = ext.get_mut::<SpanState>() {
                state.had_error = true;
            }
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };

        let Some(state) = span.extensions_mut().remove::<SpanState>() else {
            return;
        };
        if !state.sampled {
            return;
        }

        // A span closed without ever exiting (dropped mid-flight) still counts:
        // fold any open interval in rather than losing the record.
        let duration_ns = match state.entered_at {
            Some(started) => state.elapsed_ns.saturating_add(started.elapsed().as_nanos() as u64),
            None => state.elapsed_ns,
        };

        // Borrowed, not cloned: every one of these is `&'static str` from the
        // macro callsite, so the capture path allocates nothing at all.
        let meta = span.metadata();
        self.ring.push(RawSpan {
            trace_id: state.trace_id,
            span_id: id.into_u64(),
            parent_span_id: span.parent().map(|p| p.id().into_u64()),
            name: meta.name(),
            target: meta.target(),
            file: meta.file(),
            line: meta.line(),
            module_path: meta.module_path(),
            duration_ns,
            depth: state.depth,
            had_error: state.had_error,
            outcome: state.outcome,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    fn ring_of(capacity: usize) -> Arc<SpanRing> {
        Arc::new(SpanRing::new(capacity))
    }

    fn rec(trace: u64, span: u64) -> RawSpan {
        RawSpan {
            trace_id: trace,
            span_id: span,
            parent_span_id: None,
            name: "n",
            target: "t",
            file: None,
            line: None,
            module_path: None,
            duration_ns: 0,
            depth: 0,
            had_error: false,
            outcome: Default::default(),
        }
    }

    #[test]
    fn ring_is_bounded_and_drops_oldest() {
        let ring = SpanRing::new(10);
        for i in 0..10_000u64 {
            ring.push(rec(1, i));
        }
        assert_eq!(ring.len(), 10, "ring must never exceed capacity");
        assert_eq!(ring.captured(), 10_000);
        assert_eq!(ring.dropped(), 9_990, "eviction count must be honest");
        let snap = ring.snapshot();
        // Head-drop: the survivors are the newest.
        assert_eq!(snap.first().unwrap().span_id, 9_990);
        assert_eq!(snap.last().unwrap().span_id, 9_999);
    }

    #[test]
    fn drain_empties_the_ring() {
        let ring = SpanRing::new(100);
        for i in 0..5 {
            ring.push(rec(1, i));
        }
        assert_eq!(ring.drain().len(), 5);
        assert!(ring.is_empty());
        assert_eq!(ring.drain().len(), 0);
    }

    #[test]
    fn captures_span_tree_with_file_and_line() {
        let ring = ring_of(64);
        let layer = CruxSpanLayer::new(Arc::clone(&ring), 1);
        let sub = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(sub, || {
            let outer = tracing::info_span!("outer");
            let _o = outer.enter();
            let inner = tracing::info_span!("inner");
            let _i = inner.enter();
        });

        let spans = ring.snapshot();
        assert_eq!(spans.len(), 2, "both spans captured, got {spans:?}");

        let inner = spans.iter().find(|s| s.name == "inner").expect("inner");
        let outer = spans.iter().find(|s| s.name == "outer").expect("outer");

        // The join key must be populated — without it nothing resolves.
        assert!(inner.file.is_some(), "file is the join key and must be set");
        assert!(inner.line.is_some(), "line is the join key and must be set");

        assert_eq!(outer.depth, 0);
        assert_eq!(inner.depth, 1);
        assert_eq!(inner.parent_span_id, Some(outer.span_id));
        assert_eq!(inner.trace_id, outer.trace_id, "one trace id across the tree");
        assert_eq!(outer.parent_span_id, None, "root has no parent");
    }

    #[test]
    fn sampling_is_per_trace_so_captured_traces_are_whole() {
        let ring = ring_of(256);
        // Keep 1 trace in 2.
        let layer = CruxSpanLayer::new(Arc::clone(&ring), 2);
        let sub = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(sub, || {
            for _ in 0..4 {
                let root = tracing::info_span!("root");
                let _r = root.enter();
                let child = tracing::info_span!("child");
                let _c = child.enter();
            }
        });

        let spans = ring.snapshot();
        // 4 traces, every other one kept => 2 traces x 2 spans.
        assert_eq!(spans.len(), 4, "got {spans:?}");
        // The critical property: no trace is half-present.
        for tid in spans
            .iter()
            .map(|s| s.trace_id)
            .collect::<std::collections::BTreeSet<_>>()
        {
            let in_trace = spans.iter().filter(|s| s.trace_id == tid).count();
            assert_eq!(in_trace, 2, "trace {tid} must be complete, not partial");
        }
    }

    #[test]
    fn error_events_mark_the_enclosing_span() {
        let ring = ring_of(16);
        let layer = CruxSpanLayer::new(Arc::clone(&ring), 1);
        let sub = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(sub, || {
            let ok = tracing::info_span!("clean");
            {
                let _g = ok.enter();
            }
            let bad = tracing::info_span!("failing");
            let _g = bad.enter();
            tracing::error!("boom");
        });

        let spans = ring.snapshot();
        assert!(spans.iter().find(|s| s.name == "failing").unwrap().had_error);
        assert!(!spans.iter().find(|s| s.name == "clean").unwrap().had_error);
    }

    #[test]
    fn duration_accumulates_across_re_entry() {
        let ring = ring_of(16);
        let layer = CruxSpanLayer::new(Arc::clone(&ring), 1);
        let sub = tracing_subscriber::registry().with(layer);

        tracing::subscriber::with_default(sub, || {
            let s = tracing::info_span!("polled_twice");
            for _ in 0..2 {
                let _g = s.enter();
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        });

        let spans = ring.snapshot();
        let s = spans.iter().find(|s| s.name == "polled_twice").unwrap();
        // Two 2ms entries: total must reflect both, not just the last.
        assert!(
            s.duration_ns >= 3_000_000,
            "expected >=3ms accumulated, got {}ns",
            s.duration_ns
        );
    }

    #[test]
    fn from_env_returns_none_when_disabled() {
        // The disabled path must yield nothing to install.
        std::env::remove_var(TRACE_CAPTURE_ENV);
        assert!(CruxSpanLayer::from_env().is_none());
        std::env::set_var(TRACE_CAPTURE_ENV, "0");
        assert!(CruxSpanLayer::from_env().is_none());
        std::env::set_var(TRACE_CAPTURE_ENV, "off");
        assert!(CruxSpanLayer::from_env().is_none());
        std::env::remove_var(TRACE_CAPTURE_ENV);
    }

    #[test]
    fn record_round_trips_as_json() {
        // M4 persists these; a schema break must fail here first.
        let r = SpanRecord {
            trace_id: 7,
            span_id: 9,
            parent_span_id: Some(7),
            name: "handler".into(),
            target: "corecruxd::http".into(),
            file: Some("crates/corecruxd/src/http/mod.rs".into()),
            line: Some(42),
            module_path: Some("corecruxd::http".into()),
            duration_ns: 1234,
            depth: 1,
            had_error: false,
            outcome: Default::default(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<SpanRecord>(&json).unwrap(), r);
    }

    // ── outcome dimension (ExecPlan crux-code-intel-silent-empty-outcomes, M0) ──

    /// The non-negotiable one: `trace_store` loads real `spans.jsonl` files
    /// written before this field existed. They must still parse, and must read
    /// as `Unrecorded` — never as `NonEmpty`, which would be a silent claim
    /// that work was produced.
    #[test]
    fn a_span_record_written_before_the_outcome_field_still_loads() {
        let legacy = r#"{"trace_id":1,"span_id":2,"parent_span_id":null,"name":"old",
            "target":"t","file":null,"line":null,"module_path":null,
            "duration_ns":5,"depth":0,"had_error":false}"#;
        let parsed: SpanRecord = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.outcome, SpanOutcome::Unrecorded);
        assert!(!parsed.outcome.is_recorded());
        assert!(!parsed.outcome.is_empty_result(), "unrecorded is not emptiness");
    }

    #[test]
    fn outcome_serialises_as_snake_case() {
        assert_eq!(serde_json::to_string(&SpanOutcome::NonEmpty).unwrap(), "\"non_empty\"");
        assert_eq!(serde_json::to_string(&SpanOutcome::Empty).unwrap(), "\"empty\"");
        assert_eq!(
            serde_json::to_string(&SpanOutcome::Unrecorded).unwrap(),
            "\"unrecorded\""
        );
    }

    #[test]
    fn record_outcome_marks_the_enclosing_span() {
        let ring = ring_of(16);
        let layer = CruxSpanLayer::new(Arc::clone(&ring), 1);
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
            tracing::info_span!("empty_one", crux.outcome = tracing::field::Empty).in_scope(|| {
                record_outcome(true);
            });
            tracing::info_span!("full_one", crux.outcome = tracing::field::Empty).in_scope(|| {
                record_outcome(false);
            });
            tracing::info_span!("silent_one").in_scope(|| {});
        });
        let spans = ring.snapshot();
        let by = |n: &str| spans.iter().find(|s| s.name == n).unwrap().outcome;
        assert_eq!(by("empty_one"), SpanOutcome::Empty);
        assert_eq!(by("full_one"), SpanOutcome::NonEmpty);
        // Never opted in, so it never reached `on_record`.
        assert_eq!(by("silent_one"), SpanOutcome::Unrecorded);
    }

    /// `on_record` must ignore every field that is not `crux.outcome`, or an
    /// unrelated `Span::record` elsewhere in the daemon would corrupt this one.
    #[test]
    fn on_record_ignores_unrelated_fields() {
        let ring = ring_of(8);
        let layer = CruxSpanLayer::new(Arc::clone(&ring), 1);
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
            tracing::info_span!(
                "noisy",
                other = tracing::field::Empty,
                crux.outcome = tracing::field::Empty
            )
            .in_scope(|| {
                tracing::Span::current().record("other", "empty");
            });
        });
        assert_eq!(ring.snapshot()[0].outcome, SpanOutcome::Unrecorded);
    }

    #[test]
    fn outcome_ext_passes_the_value_through() {
        let ring = ring_of(8);
        let layer = CruxSpanLayer::new(Arc::clone(&ring), 1);
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
            tracing::info_span!("opt", crux.outcome = tracing::field::Empty).in_scope(|| {
                let v: Option<u8> = None;
                assert!(v.record_outcome_through().is_none());
            });
            tracing::info_span!("vec", crux.outcome = tracing::field::Empty).in_scope(|| {
                assert_eq!(vec![1u8, 2].record_outcome_through().len(), 2);
            });
        });
        let spans = ring.snapshot();
        let by = |n: &str| spans.iter().find(|s| s.name == n).unwrap().outcome;
        assert_eq!(by("opt"), SpanOutcome::Empty);
        assert_eq!(by("vec"), SpanOutcome::NonEmpty);
    }

    /// The M1 gate, as a deterministic test rather than a benchmark.
    ///
    /// The overhead claim for the outcome dimension is *structural*: a span
    /// that does not declare `crux.outcome` never reaches [`Layer::on_record`],
    /// because `tracing` only dispatches a record for a field present in the
    /// span's metadata. So an uninstrumented span cannot pay for this feature.
    ///
    /// A benchmark cannot show that at the precision required — run-to-run
    /// drift on a shared machine is larger than the effect. This asserts the
    /// mechanism directly: `record_outcome` inside an undeclared span is inert,
    /// and the span still closes as `Unrecorded`.
    ///
    /// It doubles as the contract for M2: a site that forgets `fields(crux
    /// .outcome = tracing::field::Empty)` records nothing, silently. That is
    /// the one sharp edge of this design, and this test is where it is written
    /// down.
    #[test]
    fn record_outcome_is_inert_when_the_span_never_declared_the_field() {
        let ring = ring_of(8);
        let layer = CruxSpanLayer::new(Arc::clone(&ring), 1);
        tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
            // No `fields(crux.outcome = ...)` on this span.
            tracing::info_span!("undeclared").in_scope(|| {
                record_outcome(true);
            });
        });
        let spans = ring.snapshot();
        assert_eq!(spans.len(), 1);
        assert_eq!(
            spans[0].outcome,
            SpanOutcome::Unrecorded,
            "an undeclared span must not be markable, or the no-cost claim is false"
        );
    }

    /// An `Err` is a failure, not an empty result — `had_error` covers it.
    /// Conflating them would let a loud failure read as a silent one.
    #[test]
    fn an_err_is_not_an_empty_result() {
        let ok_empty: Result<Vec<u8>, ()> = Ok(vec![]);
        let ok_full: Result<Vec<u8>, ()> = Ok(vec![1]);
        let failed: Result<Vec<u8>, ()> = Err(());
        assert!(ok_empty.is_empty_result());
        assert!(!ok_full.is_empty_result());
        assert!(!failed.is_empty_result(), "Err must not read as empty");
    }
}
