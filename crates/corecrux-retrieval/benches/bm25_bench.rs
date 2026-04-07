// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

use corecrux_index::CcxiBuilder;
use corecrux_index::CcxiReader;
use corecrux_retrieval::bm25::{bm25_score_multi, bm25_search, Bm25Params};

/// Build a test .ccxi index with `n` documents.
/// Documents contain synthetic text with varying vocabulary to produce
/// realistic BM25 scoring distributions.
fn build_index(n: usize) -> Vec<u8> {
    let topics = [
        "terraform module drift detection infrastructure provisioning",
        "kubernetes deployment strategy container orchestration scaling",
        "database migration schema versioning rollback recovery",
        "authentication oauth token refresh session management",
        "observability metrics tracing alerting dashboard grafana",
        "networking load balancer ingress TLS certificate rotation",
        "storage backup snapshot replication disaster recovery",
        "CI pipeline build test deploy artifact registry",
        "security vulnerability scanning CVE patch management",
        "API gateway rate limiting throttle circuit breaker",
    ];

    let mut builder = CcxiBuilder::new(0, 1, 100);
    for i in 0..n {
        let base = &topics[i % topics.len()];
        let text = format!("{base} document-{i} extra-term-{}", i % 50);
        builder.add_document(i as u32, &text, (i * 100) as u32, 0x1234);
    }
    builder.build()
}

fn bench_bm25_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("bm25_search");

    for size in [100, 1_000, 10_000] {
        let bytes = build_index(size);
        let reader = CcxiReader::from_bytes(&bytes).unwrap();
        let readers = vec![&reader];
        let params = Bm25Params::default();

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                bm25_search(
                    black_box(&readers),
                    black_box("terraform drift detection"),
                    black_box(10),
                    None,
                    &params,
                    Some(0.1),
                )
            });
        });
    }

    group.finish();
}

fn bench_bm25_score_multi(c: &mut Criterion) {
    let mut group = c.benchmark_group("bm25_score_multi");

    // Build multiple segments to simulate multi-segment scoring
    for num_segments in [2, 4, 8] {
        let segment_bytes: Vec<Vec<u8>> = (0..num_segments).map(|_| build_index(1_000)).collect();
        let readers: Vec<CcxiReader> = segment_bytes
            .iter()
            .map(|b| CcxiReader::from_bytes(b).unwrap())
            .collect();
        let reader_refs: Vec<&CcxiReader> = readers.iter().collect();
        let params = Bm25Params::default();

        group.bench_with_input(BenchmarkId::new("segments", num_segments), &num_segments, |b, _| {
            b.iter(|| {
                bm25_score_multi(
                    black_box(&reader_refs),
                    black_box("kubernetes deployment scaling"),
                    black_box(10),
                    None,
                    &params,
                )
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_bm25_search, bench_bm25_score_multi);
criterion_main!(benches);
