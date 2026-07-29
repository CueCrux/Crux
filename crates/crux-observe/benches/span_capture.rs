// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! M2 gate — what runtime span capture costs.
//!
//! ExecPlan `crux-runtime-codemap-and-agent-query-api-2026-07-27`, milestone M2.
//!
//! Three comparisons, each over the same synthetic handler (a root span with
//! nested child spans, the shape of a real HTTP request):
//!
//! * `capture_off` — a plain registry with no span layer. This is what the
//!   daemon runs when `CORECRUXD_TRACE_CAPTURE` is unset, because
//!   `CruxSpanLayer::from_env` returns `None` and nothing is installed. It is
//!   the baseline the "no cost when disabled" claim rests on.
//! * `capture_on` — the layer installed, sampling every trace. Worst case.
//! * `capture_sampled` — installed at 1-in-10, the realistic production setting.
//!
//! The ring is also exercised directly to show push cost in isolation.
//!
//! Run: `cargo bench -p crux-observe --bench span_capture`

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use crux_observe::span_layer::{CruxSpanLayer, RawSpan, SpanRing};
use tracing_subscriber::prelude::*;

/// Synthetic unit of work: one root span with `children` nested spans beneath
/// it, matching the shape M3 will instrument (handler → storage → retrieval).
fn simulated_request(children: usize) {
    let root = tracing::info_span!("http_handler", route = "/v1/query/text-search");
    let _r = root.enter();
    for i in 0..children {
        let child = tracing::info_span!("storage_read", shard = i);
        let _c = child.enter();
        // Stand-in for real work so the benchmark is not pure span overhead.
        std::hint::black_box(i * 2);
    }
}

fn bench_layer_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("span_capture");

    group.bench_function("capture_off", |b| {
        let sub = tracing_subscriber::registry();
        tracing::subscriber::with_default(sub, || {
            b.iter(|| simulated_request(8));
        });
    });

    group.bench_function("capture_on", |b| {
        let ring = Arc::new(SpanRing::new(16_384));
        let sub = tracing_subscriber::registry().with(CruxSpanLayer::new(Arc::clone(&ring), 1));
        tracing::subscriber::with_default(sub, || {
            b.iter(|| simulated_request(8));
        });
    });

    group.bench_function("capture_sampled_1_in_10", |b| {
        let ring = Arc::new(SpanRing::new(16_384));
        let sub = tracing_subscriber::registry().with(CruxSpanLayer::new(Arc::clone(&ring), 10));
        tracing::subscriber::with_default(sub, || {
            b.iter(|| simulated_request(8));
        });
    });

    group.finish();
}

/// The same span shape, but around work that takes as long as a real handler.
///
/// The span-only benchmarks above isolate capture cost, which makes the
/// *relative* number look alarming: 9 spans over a loop that does nothing is
/// almost pure overhead. The gate is about a representative handler, so this
/// pair measures the honest ratio — span capture wrapped around ~200µs of actual
/// work, which is the right order for a `corecruxd` request touching storage.
fn simulated_request_with_work(children: usize, work_iters: u64) {
    let root = tracing::info_span!("http_handler", route = "/v1/query/text-search");
    let _r = root.enter();
    for i in 0..children {
        let child = tracing::info_span!("storage_read", shard = i);
        let _c = child.enter();
        let mut acc = 0u64;
        for k in 0..work_iters {
            acc = acc.wrapping_add(k).wrapping_mul(2_654_435_761);
        }
        std::hint::black_box(acc);
    }
}

fn bench_realistic_handler(c: &mut Criterion) {
    // ~25k iterations per child x 8 children lands near 200µs total.
    const WORK: u64 = 25_000;
    let mut group = c.benchmark_group("realistic_handler");

    group.bench_function("capture_off", |b| {
        let sub = tracing_subscriber::registry();
        tracing::subscriber::with_default(sub, || {
            b.iter(|| simulated_request_with_work(8, WORK));
        });
    });

    group.bench_function("capture_on", |b| {
        let ring = Arc::new(SpanRing::new(16_384));
        let sub = tracing_subscriber::registry().with(CruxSpanLayer::new(Arc::clone(&ring), 1));
        tracing::subscriber::with_default(sub, || {
            b.iter(|| simulated_request_with_work(8, WORK));
        });
    });

    group.finish();
}

fn bench_ring(c: &mut Criterion) {
    let mut group = c.benchmark_group("span_ring");

    let record = || RawSpan {
        trace_id: 1,
        span_id: 2,
        parent_span_id: Some(1),
        name: "storage_read",
        target: "corecruxd::storage",
        file: Some("crates/corecrux-storage/src/append.rs"),
        line: Some(1473),
        module_path: Some("corecrux_storage::append"),
        duration_ns: 4_200,
        depth: 1,
        had_error: false,
    };

    group.bench_function("push_uncontended", |b| {
        let ring = SpanRing::new(16_384);
        b.iter_batched(record, |r| ring.push(r), BatchSize::SmallInput);
    });

    // Steady state once the ring is full: every push also evicts.
    group.bench_function("push_at_capacity", |b| {
        let ring = SpanRing::new(64);
        for _ in 0..64 {
            ring.push(record());
        }
        b.iter_batched(record, |r| ring.push(r), BatchSize::SmallInput);
    });

    group.finish();
}

criterion_group!(benches, bench_layer_overhead, bench_realistic_handler, bench_ring);
criterion_main!(benches);
