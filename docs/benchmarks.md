# Benchmarks

## Criterion Benchmarks

The `corecrux-retrieval` crate includes a Criterion benchmark for BM25 scoring:

```bash
cargo bench -p corecrux-retrieval --bench bm25_bench
```

Results are written to `target/criterion/` with HTML reports.

### Latest Results

Measured on the development host (WSL2, Linux 5.15). Times are wall-clock per iteration (lower is better).

#### BM25 Single-Segment Search (`bm25_search`)

| Corpus size | Median | 95 % CI |
|---|---|---|
| 100 docs | 583 ns | [581 ns, 586 ns] |
| 1,000 docs | 2.62 us | [2.62 us, 2.65 us] |
| 10,000 docs | 23.1 us | [23.1 us, 23.8 us] |

#### BM25 Multi-Segment Scoring (`bm25_score_multi`)

| Segments | Median | 95 % CI |
|---|---|---|
| 2 | 8.75 us | [8.74 us, 8.77 us] |
| 4 | 23.5 us | [23.1 us, 23.5 us] |
| 8 | 72.2 us | [72.0 us, 72.4 us] |

Scaling is roughly linear with segment count (2x segments ~ 2.7x time), confirming no contention overhead in the multi-reader merge path.

## Performance Regression Gates

The `tests/bench/` directory contains JSON gate files used by CI to detect performance regressions:

```
tests/bench/
  perf_regression_gates/    # Startup and append latency baselines
  replay_gates/             # Deterministic replay throughput baselines
  replay_many_gates/        # Multi-stream replay baselines
```

Each directory contains:
- **`baseline_*.json`** — The accepted performance baseline (established by a known-good build)
- **`candidate_*_pass.json`** — A candidate result that meets the gate threshold
- **`candidate_*_fail.json`** — A candidate result that fails the gate (used for gate validation)

### Gate Thresholds

#### Perf Regression Gates (`baseline_startupfix_v3`)

**Append:**

| Metric | Baseline | Threshold |
|---|---|---|
| Throughput | 25,422 events/sec | Min 85 % of baseline |
| p95 latency | 9.98 ms | Max 125 % of baseline |
| Fence wait (avg) | 1.7 ms | Max 135 % of baseline |
| Lane wait (avg) | 5.0 ms | Max 135 % of baseline |
| Store lock wait (avg) | 3.9 ms | Max 135 % of baseline, abs max 0.5 ms |

**Replay (3 workload profiles):**

| Profile | Throughput (reads/sec) | p95 (ms) | Min throughput ratio | Max p95 ratio |
|---|---|---|---|---|
| A | 21,328 | 0.52 | 0.85 | 1.25 |
| B | 15,376 | 0.74 | 0.80 | 1.35 |
| C | 19,750 | 0.57 | 0.85 | 1.25 |

All replay profiles require `eventsReadRatio >= 0.98` and `sessionUseFrames = false`.

#### Replay Gates (`baseline_append`)

| Metric | Baseline |
|---|---|
| Total events | 600,000 |
| Batches | 10,000 |
| p50 latency | 3.4 ms |
| p95 latency | 9.1 ms |
| Throughput | 10,000 events/sec |

#### Replay-Many Gates (multi-stream baselines)

| Profile | Throughput (reads/sec) | p95 (ms) | Avg reads/RPC |
|---|---|---|---|
| A | 3,200 | 3.4 | 8.0 |
| B | 850 | 12.0 | 8.0 |
| C | 2,900 | 4.2 | 8.0 |

### Gate File Format

```json
{
  "metric": "append_p99_ms",
  "baseline": 2.1,
  "candidate": 2.3,
  "threshold_pct": 15.0,
  "pass": true
}
```

A candidate passes if `(candidate - baseline) / baseline * 100 <= threshold_pct`.

## Running Benchmarks Locally

```bash
# BM25 scoring benchmark (Criterion)
cargo bench -p corecrux-retrieval --bench bm25_bench

# Replay benchmark (requires a data directory with sealed segments)
CORECRUXD_DATA_DIR=./data cargo run --release --bin corecruxctl -- replay --scope full

# Verify-store integrity benchmark
CORECRUXD_DATA_DIR=./data cargo run --release --bin corecruxctl -- verify-store --scope full
```

## Adding a New Benchmark

1. For micro-benchmarks: Add a `[[bench]]` entry to the relevant crate's `Cargo.toml` and create a Criterion benchmark file in `benches/`.
2. For regression gates: Add baseline + candidate JSON files to the appropriate `tests/bench/` subdirectory.
