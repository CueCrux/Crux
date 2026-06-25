// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! M5 — CI determinism gate for the `token_bench` harness.
//!
//! ExecPlan: `crux-headroom-token-efficiency-learnings-2026-06-24` (milestone M5).
//!
//! The M0 reproducibility gate — and the M5 holdout savings line — only hold if
//! the harness is clock/rng-free. This test promotes that from a manual "run it
//! twice" check into an automated one: it runs the example twice (with the same
//! env, including a pinned `CRUX_BENCH_COMMIT`/`CRUX_BENCH_RUN_ID`) and asserts
//! the stdout JSON — records **and** the `savings` block with its 95% CI — is
//! byte-identical.

use std::process::Command;

fn run_bench() -> String {
    let output = Command::new(env!("CARGO"))
        .args(["run", "--quiet", "-p", "crux-mcp", "--example", "token_bench"])
        .env("CRUX_BENCH_COMMIT", "determinism-test")
        .env("CRUX_BENCH_RUN_ID", "fixed")
        // Pin efficiency flags OFF for the *primary* records pass so the run is
        // fully specified; the holdout savings pass toggles them internally.
        .env("CRUX_PAYLOAD_COMPACT", "0")
        .env("CRUX_BUDGET_REVERSIBLE", "0")
        .output()
        .expect("run token_bench example");
    assert!(
        output.status.success(),
        "token_bench exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

#[test]
fn token_bench_stdout_is_byte_identical_across_runs() {
    let a = run_bench();
    let b = run_bench();
    assert_eq!(a, b, "token_bench stdout must be deterministic (no clock/rng)");
    // Sanity: the savings block with its CI is present (the M5 gate artifact).
    assert!(a.contains("\"savings\""), "savings block missing");
    assert!(a.contains("95% CI"), "savings report must carry a 95% CI");
}
