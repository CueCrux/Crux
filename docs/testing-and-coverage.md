# Testing & coverage

How the Crux Daemon is tested, how coverage is measured and gated, and an honest
account of why the gated number sits where it does.

> **Snapshot (2026-07-30, `main`):** **6,317** test functions; **88.49%** gated
> region coverage (ungated, whole tree: **87.20%**).
> CI is the source of truth — the live numbers are printed in
> the [Coverage job](../.github/workflows/ci.yml) of every run and attested by
> [`coverage-attestation.yml`](../.github/workflows/coverage-attestation.yml).

## Running the tests

```bash
cargo test --workspace            # the full suite (4,489 tests)
cargo test -p corecruxd           # one crate (corecruxd is a binary crate — no lib target)
cargo fmt --check                 # formatting gate
cargo clippy --workspace -- -D warnings   # lint gate (lib + bins; not #[cfg(test)] code)
```

Coverage locally (matches CI exactly — same ignore regex):

```bash
RX='(.*/corecruxd/src/pool\.rs|.*/corecruxd/src/dataplane_store\.rs|.*/corecruxd/src/http/dataplane\.rs|.*/corecruxd/src/main\.rs|.*/corecruxctl/src/main\.rs|.*/crux-claude-hooks/src/main\.rs|.*/crux-claude-hooks/src/bin/crux_llm_shim\.rs|.*/crux-config-wizard/src/main\.rs|.*/crux-config-wizard/src/interactive\.rs)$'
cargo llvm-cov --workspace --ignore-filename-regex "$RX" --summary-only
```

(Needs `cargo-llvm-cov` + the `llvm-tools-preview` component, and a C toolchain
for linking — `apt install build-essential` on a bare box.)

## What the gate measures

The CI gate uses **region coverage** — column 4 of the `cargo llvm-cov` `TOTAL`
line — not line coverage. Region coverage is the stricter of the two (it counts
distinct branch regions, so a half-executed line doesn't read as fully covered).

The [`Coverage` job in `ci.yml`](../.github/workflows/ci.yml) enforces:

| Scope | Floor | Actual (snapshot) | Notes |
|---|---|---|---|
| **Workspace total** | **86%** | 86.97% | the headline gate |
| `corecrux-memory` | 93% | 93.5% | ratchet target **95** (see below) |
| `crux-sync` | 98% | 99.0% | |
| `crux-contrib` | 99% | 100% | |
| `corecrux-receipts` | 88% | 88.6% | trust core (CROWN receipts) |
| `corecrux-segment` | 85% | 86.2% | trust core (sealed `.ccxseg`) |
| `corecrux-storage` | 79% | 80.2% | trust core (append-only store) |

Floors are set **at current-rounded-down** ("ratchet from reality"): they prevent
regression today and are raised as coverage improves. The job also prints the
**ungated** total (full tree, no exclusions) next to the gated one, so the
exclusion list below can never quietly hide low-coverage code from review.

> **Note on the memory floor.** The per-crate floor check was historically a
> no-op (the awk summed the file-path column → always "100.0"), so the
> long-stated `corecrux-memory` ≥95% target was never actually enforced. The
> check is now correct; `corecrux-memory` is 93.5% today, so the enforced floor
> is 93 with **95 as the ratchet target**.

### What is excluded from the gate — and why

The ignore list is deliberately narrow: only code that is **not meaningfully
unit-testable**.

- **Binary entry points** — `main.rs` (`#[tokio::main]` bootstrap / clap
  dispatch) for `corecruxd`, `corecruxctl`, `crux-claude-hooks`,
  `crux-config-wizard`, plus the `crux_llm_shim` bin.
- **The interactive config wizard** — `crux-config-wizard/src/interactive.rs`
  (stdin-driven prompts).
- **The dataplane layer**, which is an **unconstructable typecheck stub** in the
  CPU-only CE build: [`pool.rs`](../crates/corecruxd/src/pool.rs)
  (`DataPlanePool { _private: () }`, every method `unreachable!()`, never
  constructed), `dataplane_store.rs`, and
  [`http/dataplane.rs`](../crates/corecruxd/src/http/dataplane.rs)
  (`PoolBackedHttpDataplane` whose `pool` is always `None`). The real dataplane —
  and its append→read→verify integration coverage — lives in the
  dataplane-enabled (CoreCrux) distribution, not this repo. The CE handlers'
  contract is covered against the `FakeHttpDataplane` test double in
  [`http/tests.rs`](../crates/corecruxd/src/http/tests.rs).

Everything else — including the critical append, query, receipt, projection, and
admin HTTP surfaces — is gated.

## Tests per crate (top)

| Crate | Tests | | Crate | Tests |
|---|---:|---|---|---:|
| `corecruxd` | 1537 | | `corecrux-receipts` | 170 |
| `corecruxctl` | 933 | | `corecrux-storage` | 143 |
| `crux-mcp` | 622 | | `crux-claude-hooks` | 108 |
| `corecrux-projections` | 269 | | `crux-session` | 76 |
| `corecrux-memory` | 176 | | `corecrux-segment` | 54 |

## Why the gated number is ~87%, not higher

This is the honest part. 86.97% is what an *accurate* gate over the
*meaningfully-testable* tree reports — it is not a target someone padded up to.

1. **The trust-core crates pull the average down on purpose.**
   `corecrux-storage` (80%), `corecrux-segment` (86%), and `corecrux-receipts`
   (89%) are large and full of deep I/O and error branches. The
   **security-critical** paths in them *are* covered — tamper-rejection in
   [`corecrux-segment/tests/corruption_matrix.rs`](../crates/corecrux-segment/tests/corruption_matrix.rs)
   (magic / version / CRC / record-hash / TOC corruption all rejected) and
   fail-closed signature verification in
   [`corecrux-receipts/src/verify_v1.rs`](../crates/corecrux-receipts/src/verify_v1.rs)
   (`assert!(!report.signature_valid)`). What's *un*covered is mostly
   exhaustive error/IO-branch fan-out, not the invariants (see
   [`docs/agent/INVARIANTS.md`](agent/INVARIANTS.md)).

2. **`corecruxd` is an ~87k-LOC surface.** Most handlers are covered. The three
   that this doc previously recorded at 0% — `http/events.rs`, `http/infra.rs`,
   `http/policy.rs` — were closed on 2026-07-30 and now sit at **95.4%**,
   **98.8%** and **98.7%** region coverage respectively. They were *gated* (not
   excluded) throughout, which is why they showed up as debt rather than
   staying hidden. Remaining `corecruxd` debt is tracked per-file in the
   Coverage job log.

   A related trap worth knowing: **no CI job runs `cargo test -- --ignored`**, so
   an `#[ignore]`d test contributes nothing to the gate. Two exist today —
   `sse_session_survives_30s_idle` (>35s wall clock) and `witness_submit`'s live
   Rekor probe. Both are ignored for good reasons, but the SSE endpoint's
   *only* test was one of them, which is how a whole handler sat at 0% while
   looking tested. Prefer a fast handler-level test alongside any long-running
   or network-dependent one.

3. **The denominator includes the test code itself.** `#[cfg(test)]` regions
   count toward the total, so each new test batch raises coverage by less than
   its raw covered-region count.

4. **Coverage measures execution, not assertion strength.** Region coverage
   proves a line ran; it does not prove a test would catch a regression.
   Mutation testing fills that gap on the trust-core crates
   (`corecrux-receipts`, `corecrux-segment`, `corecrux-storage`):

   - Nightly [`mutants.yml`](../.github/workflows/mutants.yml) runs
     `cargo-mutants` sharded 8 ways, merges the shard reports into a
     per-crate mutation-score table in the job summary, and **ratchets**
     against [`mutants-baseline.txt`](../.github/mutants-baseline.txt):
     a *new* survivor (a mutant no test kills that isn't in the baseline)
     turns the nightly red; survivors that become caught are listed so the
     baseline can be shrunk. Neither is a required PR check.
   - PR-time [`mutants-diff.yml`](../.github/workflows/mutants-diff.yml)
     runs `cargo mutants --in-diff` over the PR's changes to the trust-core
     crates, so assertion-free new code is caught at review time in minutes
     instead of overnight.
   - To burn a survivor down: write a test that kills it, run
     `cargo mutants --file <file> -p <crate> --timeout 120` to confirm, and
     delete its line from the baseline. Only genuinely inert mutations
     (logging, metrics) belong in the baseline long-term — prefer
     `#[mutants::skip]` with a comment for those so the baseline shrinks.

## Maintaining the gate

- **To raise a floor:** add tests for the crate, confirm the new per-crate number
  in the Coverage job log, then bump the `pair` floor in
  [`ci.yml`](../.github/workflows/ci.yml) (keep it ≤ actual). Raising
  `corecrux-memory` to its 95 target is the first such opportunity.
- **Keep the regex in lock-step:** the `COVERAGE_IGNORE_REGEX` is duplicated in
  `ci.yml` and `coverage-attestation.yml` — change both together.
- **Adding an exclusion is a reviewed decision:** justify it inline (the only
  acceptable classes are entry points, interactive surfaces, and
  platform-inert/unconstructable code). Prefer testing over excluding.

## See also

- [`AGENTS.md`](../AGENTS.md) — the 60-second trust-core tour + "verify the
  claims yourself".
- [`docs/agent/CLAIMS.md`](agent/CLAIMS.md) — each product claim → code → the
  test that proves it.
- [`docs/code-health-harvest.md`](code-health-harvest.md) — the code-health
  (dead-code / stub / unused-dep) harvester.
