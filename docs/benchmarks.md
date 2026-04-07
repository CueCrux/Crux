# Benchmarks

## Criterion Benchmarks

The `corecrux-retrieval` crate includes a Criterion benchmark for BM25 scoring:

```bash
cargo bench -p corecrux-retrieval --bench bm25_bench
```

Results are written to `target/criterion/` with HTML reports.

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
