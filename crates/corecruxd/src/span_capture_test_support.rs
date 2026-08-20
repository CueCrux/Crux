// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Test-only support for asserting what the span-capture layer recorded.
//!
//! Introduced with the curated outcome sites of ExecPlan
//! `crux-code-intel-silent-empty-outcomes-2026-08-03` (M2), which need to assert
//! that a given function declared `Empty` or `NonEmpty` on a given call.
//!
//! ## Why a global subscriber rather than `with_default`
//!
//! `tracing` caches callsite `Interest` **process-wide**, computed by whichever
//! thread reaches the callsite first. A *scoped* subscriber
//! ([`tracing::subscriber::with_default`]) therefore cannot own that cache: the
//! instrumented sites here are also reached from ordinary production paths —
//! `load_latest_workspace_blocking` via `dossier::build` and
//! `storybook::generate`, the listers via their handlers — and an unrelated test
//! touching one of those on a thread with no subscriber caches the callsite as
//! `Interest::never()` for the whole process. The span is then never built, and
//! the assertion reads "the site recorded nothing".
//!
//! Serialising the capturing tests against each other does not help, because the
//! invalidating registration comes from a test that is not capturing at all.
//! Calling [`tracing::callsite::rebuild_interest_cache`] does not close it
//! either — it only re-runs the same race, and lost it on roughly one full-suite
//! run in four.
//!
//! So the capture subscriber is installed **once, globally**, and declares
//! [`Interest::sometimes`]: interest is never cached, so no thread can poison it,
//! and [`Layer::enabled`] decides per call. When no capture is running that
//! answer is `false`, which keeps all 398 instrumented sites in this binary as
//! cheap as they were before — no span is built.
//!
//! Capture is additionally scoped to the *capturing thread*, so a concurrent
//! test's spans can never displace the ones under assertion in a small ring.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::ThreadId;

use tracing::subscriber::Interest;
use tracing::{Metadata, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use crux_observe::span_layer::{CruxSpanLayer, SpanOutcome, SpanRecord, SpanRing};

/// Serialises captures so only one ring is installed at a time.
fn capture_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    // Poisoning is irrelevant here: the guard orders captures, it does not
    // protect data that a panicking test could leave inconsistent.
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Fast path for the overwhelmingly common case: no capture in flight, so
/// `enabled` answers `false` without touching a lock.
static CAPTURING: AtomicBool = AtomicBool::new(false);

/// The layer the capturing thread is currently writing through, if any.
static SLOT: OnceLock<Mutex<Option<(ThreadId, CruxSpanLayer)>>> = OnceLock::new();

fn slot() -> MutexGuard<'static, Option<(ThreadId, CruxSpanLayer)>> {
    SLOT.get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The active capture layer, but only for the thread that installed it.
fn active_layer() -> Option<CruxSpanLayer> {
    if !CAPTURING.load(Ordering::Acquire) {
        return None;
    }
    let slot = slot();
    let (thread, layer) = slot.as_ref()?;
    (*thread == std::thread::current().id()).then(|| layer.clone())
}

/// Forwards to whichever [`CruxSpanLayer`] the capturing thread installed.
///
/// The indirection is what lets a single, permanently-installed subscriber back
/// a per-test ring — see the module docs for why the subscriber cannot be
/// scoped.
struct RoutingLayer;

impl<S> Layer<S> for RoutingLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    /// Never cached. Interest here depends on whether a capture is running on
    /// the current thread, which changes over the process lifetime; letting
    /// `tracing` cache a `never` for a callsite is the whole defect this module
    /// exists to avoid.
    fn register_callsite(&self, _meta: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, _meta: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        active_layer().is_some()
    }

    fn on_new_span(&self, attrs: &tracing::span::Attributes<'_>, id: &tracing::Id, ctx: Context<'_, S>) {
        if let Some(layer) = active_layer() {
            layer.on_new_span(attrs, id, ctx);
        }
    }

    fn on_record(&self, id: &tracing::Id, values: &tracing::span::Record<'_>, ctx: Context<'_, S>) {
        if let Some(layer) = active_layer() {
            layer.on_record(id, values, ctx);
        }
    }

    fn on_enter(&self, id: &tracing::Id, ctx: Context<'_, S>) {
        if let Some(layer) = active_layer() {
            layer.on_enter(id, ctx);
        }
    }

    fn on_exit(&self, id: &tracing::Id, ctx: Context<'_, S>) {
        if let Some(layer) = active_layer() {
            layer.on_exit(id, ctx);
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        if let Some(layer) = active_layer() {
            layer.on_event(event, ctx);
        }
    }

    fn on_close(&self, id: tracing::Id, ctx: Context<'_, S>) {
        if let Some(layer) = active_layer() {
            layer.on_close(id, ctx);
        }
    }
}

/// Install the routing subscriber exactly once for the test binary.
fn install() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        use tracing_subscriber::layer::SubscriberExt;
        // Not `.expect()`: this module's `#[cfg(test)]` gate lives in `main.rs`,
        // out of file, so `scripts/unwrap-ratchet.sh` cannot see it and would
        // count an `expect` here as a new PRODUCTION unwrap site.
        //
        // Failing loudly matters: if some other subscriber won the race, every
        // capture below would quietly record nothing, which is precisely the
        // silent-empty reading these tests exist to distinguish from a real one.
        if let Err(error) = tracing::subscriber::set_global_default(tracing_subscriber::registry().with(RoutingLayer)) {
            panic!("span capture needs the global subscriber, but it was already set: {error}");
        }
    });
}

/// Clears the capture slot even if the body panics, so one failing assertion
/// cannot leave every later capture pointed at a dead ring.
struct CaptureGuard;

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        CAPTURING.store(false, Ordering::Release);
        *slot() = None;
    }
}

/// Run `f` with span capture active on this thread, returning its value and
/// every span captured while it ran, oldest first.
///
/// Sample rate is 1 (keep everything) — a test that dropped traces would be
/// asserting on whichever ones survived.
pub(crate) fn capture_spans<T>(capacity: usize, f: impl FnOnce() -> T) -> (T, Vec<SpanRecord>) {
    let _ordering = capture_lock();
    install();

    let ring = Arc::new(SpanRing::new(capacity));
    *slot() = Some((std::thread::current().id(), CruxSpanLayer::new(Arc::clone(&ring), 1)));
    let _guard = CaptureGuard;
    CAPTURING.store(true, Ordering::Release);

    let value = f();

    (value, ring.snapshot())
}

/// As [`capture_spans`], for an `async` body. The future is driven to
/// completion on the calling thread so it observes the same thread-scoped
/// capture the closure form does.
pub(crate) fn capture_spans_async<T, F>(capacity: usize, f: impl FnOnce() -> F) -> (T, Vec<SpanRecord>)
where
    F: std::future::Future<Output = T>,
{
    capture_spans(capacity, || {
        // Not `.expect()`, for the ratchet reason given in `install`.
        let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(runtime) => runtime,
            Err(error) => panic!("current-thread runtime for span capture: {error}"),
        };
        runtime.block_on(f())
    })
}

/// The outcomes recorded by spans named `span_name`, in the order they closed.
///
/// A site that never declared `crux.outcome` yields
/// [`SpanOutcome::Unrecorded`] here rather than being absent, which is what
/// makes a dropped `fields(crux.outcome = ..)` clause fail a test instead of
/// quietly weakening it.
pub(crate) fn outcomes_of(spans: &[SpanRecord], span_name: &str) -> Vec<SpanOutcome> {
    spans
        .iter()
        .filter(|s| s.name == span_name)
        .map(|s| s.outcome)
        .collect()
}
