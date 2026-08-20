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
//! ## Why the lock
//!
//! `tracing` caches callsite interest **globally**, and a scoped subscriber
//! installed with [`tracing::subscriber::with_default`] rebuilds that cache both
//! when it is installed and again when it is dropped. Two tests capturing spans
//! on different threads therefore race: one test leaving its scope can rebuild
//! the cache to "nothing is interested in this callsite" inside the window where
//! the other is about to create its span, and that span is then silently never
//! built at all.
//!
//! The failure mode is nasty precisely because it is silent — it reads as
//! "the site recorded nothing", which is the same observation this dimension
//! exists to make about production code. It shows up as a test that passes on
//! its own and fails in a full run.
//!
//! Every span-capturing assertion in this binary goes through [`capture_spans`],
//! so they are serialised against each other and against nothing else.

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use crux_observe::span_layer::{CruxSpanLayer, SpanOutcome, SpanRecord, SpanRing};

fn capture_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    // Poisoning is irrelevant here: the guard orders subscriber installs, it
    // does not protect data that a panicking test could leave inconsistent.
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Run `f` with a span-capturing subscriber installed, returning its value and
/// every span captured while it ran, oldest first.
///
/// Sample rate is 1 (keep everything) — a test that dropped traces would be
/// asserting on whichever ones survived.
pub(crate) fn capture_spans<T>(capacity: usize, f: impl FnOnce() -> T) -> (T, Vec<SpanRecord>) {
    use tracing_subscriber::layer::SubscriberExt;

    let _ordering = capture_lock();
    let ring = Arc::new(SpanRing::new(capacity));
    let layer = CruxSpanLayer::new(Arc::clone(&ring), 1);
    let value = tracing::subscriber::with_default(tracing_subscriber::registry().with(layer), || {
        // `Interest` is cached per callsite, process-wide. A previous capture
        // leaving its scope can cache an instrumented function as "nothing is
        // interested", and it then stays uninstrumented for every later
        // capture — the span is simply never built, and the assertion reads
        // "the site recorded nothing". Re-evaluating with this subscriber
        // installed, under the lock above, makes that deterministic.
        tracing::callsite::rebuild_interest_cache();
        f()
    });
    (value, ring.snapshot())
}

/// As [`capture_spans`], for an `async` body. The future is driven to
/// completion on the calling thread so it observes the same thread-local
/// subscriber the closure form does.
pub(crate) fn capture_spans_async<T, F>(capacity: usize, f: impl FnOnce() -> F) -> (T, Vec<SpanRecord>)
where
    F: std::future::Future<Output = T>,
{
    capture_spans(capacity, || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
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
