# Token-Savings Methodology — Holdout + 95% CI (M5)

> Token-efficiency learnings (Headroom *holdout* port) — milestone **M5**.
> Module: [`crates/crux-mcp/src/holdout.rs`](../../crates/crux-mcp/src/holdout.rs).
> Harness: [`crates/crux-mcp/examples/token_bench.rs`](../../crates/crux-mcp/examples/token_bench.rs).
> Flag: `CRUX_OUTPUT_HOLDOUT` (default `0.0` = OFF).

## Why a holdout

A token-savings number is only honest if it is measured against a **control**,
not a counterfactual ("we would have spent X"). Headroom keeps
`HEADROOM_OUTPUT_HOLDOUT=0.1` of traffic unshaped and reports
`28.0% (95% CI 24.1–31.9%)`. This port adopts both halves: a live control group
and an interval, never a bare point estimate (plan risk **R5**; QC.4/QC.5).

## Control-group assignment (`is_control`)

`CRUX_OUTPUT_HOLDOUT=f` diverts a fraction `f ∈ [0,1]` of requests to the
**control** arm, where every efficiency flag (`CRUX_PAYLOAD_COMPACT`,
`CRUX_BUDGET_REVERSIBLE`) is treated as OFF. Assignment is **deterministic per
request key**: the key is hashed (FNV-1a + splitmix64 finalizer) to a stable
point in `[0,1)` and compared against `f`. Consequences:

- The same request always lands in the same arm — reproducible, unbiased, and
  (critically) **no rng**, so the bench harness stays byte-identical run-to-run.
- `f = 0.0` (default) ⇒ no request is ever control ⇒ byte-identical to pre-M5.
- `f = 1.0` ⇒ everything is control (efficiency OFF).

## Savings estimate with a 95% CI (`paired_savings`)

For each measured scenario we record the response token cost under control
(flags OFF) and treatment (flags ON). The per-scenario reduction is

```
r_i = (control_i − treatment_i) / control_i      (control_i > 0)
```

The report is the **mean** of `r_i` with a normal-approximation 95% CI:

```
reduction = mean(r_i)
SE        = stddev(r_i) / sqrt(n)        # sample stddev, n−1
CI95      = reduction ± 1.96 · SE
```

Scenarios with `control_i = 0` are skipped (no defined reduction). For `n < 2`
the CI collapses to the point estimate (a single sample has no dispersion).

`SavingsReport::format` renders the QC.4/QC.5 line, carrying the **named corpus**
and **commit_sha**:

```
token savings 21.0% (95% CI 12.5–29.4%) · n=7 · control_tokens=… · treatment_tokens=… · corpus=__synthetic__::token-bench · commit=…
```

## Reproducing the M3 saving through the holdout path

The harness measures the compaction-sensitive scenarios (`query@{500,2000,4000}`,
`query_facts@{…}`, `query_scan`) twice — control (all flags OFF) then treatment
(M3 `CRUX_PAYLOAD_COMPACT` ON) — and emits the paired savings under the JSON
`savings` block. M3 is the clean reproduction: identical hits, pure wire
reduction. (M1 is a *recall* lift, not a pure token saving, so it is not the
treatment for this savings demo.)

```bash
cargo run -p crux-mcp --example token_bench   # see the `savings` block + stderr line
```

## Gate

- **Savings-with-CI (M5 gate):** the `savings` block reproduces the M3 saving as
  a point estimate **with a 95% CI**, not a bare number — `corpus` + `commit_sha`
  attached.
- **Determinism (CI test):** `tests/token_bench_determinism.rs` runs the harness
  twice and asserts byte-identical stdout (records **and** the savings block).
  Run: `cargo test -p crux-mcp --test token_bench_determinism`.
- **CI math:** unit-tested in `holdout.rs` (`paired_savings_*`, deterministic
  report, control-split fraction).
