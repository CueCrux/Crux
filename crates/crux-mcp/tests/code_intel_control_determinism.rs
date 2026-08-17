// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! M0 reproducibility gate for the control-arm harness.
//!
//! ExecPlan: `crux-codemap-agent-surface-and-measured-savings-2026-07-27` (M0).
//!
//! The baseline is only worth anything if it is reproducible: a control number
//! that moves between runs cannot support a savings claim, because any later
//! difference could be the harness rather than the treatment. This promotes
//! "run it twice and eyeball it" into a gate.

use std::process::Command;

fn run_control() -> String {
    let output = Command::new(env!("CARGO"))
        .args(["run", "--quiet", "-p", "crux-mcp", "--example", "code_intel_control"])
        .output()
        .expect("run code_intel_control example");
    assert!(
        output.status.success(),
        "code_intel_control exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

#[test]
fn control_arm_stdout_is_byte_identical_across_runs() {
    let first = run_control();
    let second = run_control();
    assert_eq!(
        first, second,
        "control arm is not reproducible — it must be clock-free and rng-free"
    );
}

#[test]
fn control_arm_reports_every_grid_cell_and_a_cheapest_headline() {
    let out: serde_json::Value = serde_json::from_str(&run_control()).expect("stdout is JSON");

    assert_eq!(out["arm"], "control", "this harness measures the control only");
    assert_eq!(out["questions"].as_u64().unwrap(), 22);

    let cells = out["cell_totals"].as_object().expect("cell_totals");
    assert_eq!(cells.len(), 9, "3 file caps x 3 windows must all be reported");

    // The headline must be the cheapest cell, not a chosen one. A baseline that
    // picks a favourable cell after the fact is the failure this rule exists to
    // prevent.
    let headline = out["headline_control"]["cell"].as_str().expect("headline cell");
    let headline_total = out["headline_control"]["total_tokens"]
        .as_u64()
        .expect("headline total");
    let cheapest = cells.values().filter_map(serde_json::Value::as_u64).min().unwrap();
    assert_eq!(
        headline_total, cheapest,
        "headline control ({headline}) is not the cheapest cell in the grid"
    );

    // Sanity: every question costs something, and reading more files never
    // costs less than reading fewer.
    for record in out["records"].as_array().expect("records") {
        let id = record["id"].as_str().unwrap();
        let k3 = record["cells"]["k3_window_40"]["tokens"].as_u64().unwrap();
        let k10 = record["cells"]["k10_window_40"]["tokens"].as_u64().unwrap();
        assert!(k3 > 0, "{id}: control cost must be non-zero");
        assert!(k10 >= k3, "{id}: reading 10 files cannot cost less than reading 3");
    }
}
