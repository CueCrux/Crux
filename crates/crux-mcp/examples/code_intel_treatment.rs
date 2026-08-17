// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! M2 — the treatment arm, and the paired saving with its 95% CI.
//!
//! ExecPlan: `crux-codemap-agent-surface-and-measured-savings-2026-07-27` (M2).
//!
//! The control arm ([`code_intel_control`](../examples/code_intel_control.rs))
//! measured what a competent agent spends with grep and a file reader. This
//! measures what the same 22 questions cost through the code-intel surface, and
//! pairs the two.
//!
//! ## The pairing rule, fixed before either number was seen
//!
//! **Cheapest control against dearest treatment.** M0 fixed the headline control
//! as the cheapest cell of its grid; this fixes the headline treatment as the
//! *largest* token budget of its sweep. Both choices cut against the saving. A
//! figure that survives the most favourable baseline and the most expensive tool
//! call is one a customer cannot overturn by re-running it differently.
//!
//! ## Why the answers are stored, not just their size
//!
//! A cheap answer that is wrong is not a saving, it is a defect. Every response
//! body is written to the output so M3 can score correctness against the
//! corpus's ground truth without re-running the daemon.
//!
//! Run against an already-running, capture-enabled daemon:
//!
//!     CRUX_BENCH_DAEMON=http://127.0.0.1:14899 \
//!       cargo run -p crux-mcp --example code_intel_treatment -- <control.json>
//!
//! `scripts/code-intel-bench.sh` starts that daemon, generates the traffic, and
//! drives both arms.

#![allow(clippy::print_stdout, clippy::print_stderr, clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::io::Read;

use crux_mcp::holdout::paired_savings;
use crux_mcp::token_estimate::estimate_tokens_str;
use serde_json::{json, Value};

const CORPUS_JSON: &str = include_str!("../corpora/code-intel-questions.json");

/// Token budgets swept. The headline is the **largest** — the dearest the tool
/// call can be — so the reported saving is the conservative one.
const BUDGETS: [u64; 3] = [300, 500, 2000];

const TENANT: &str = "local";

fn daemon_base() -> String {
    std::env::var("CRUX_BENCH_DAEMON").unwrap_or_else(|_| "http://127.0.0.1:14899".to_string())
}

fn repo_id() -> String {
    std::env::var("CRUX_BENCH_REPO").unwrap_or_else(|_| "crux".to_string())
}

fn encode(value: &str) -> String {
    value
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The route an agent would reach for, given the question's shape.
///
/// `dead_code` deliberately routes to the evidence ladder rather than to
/// `liveness`: the question is "is this safe to delete", and the ladder is the
/// surface that carries the per-tier evidence and the `actionable` flag that a
/// deletion decision needs. It is also the more expensive of the two, which is
/// the direction this benchmark errs in.
///
/// It passes `symbol`, because that is what an agent with a symbol in mind
/// would do. Before the ladder could be scoped, this question was unanswerable
/// at any budget: the repo-wide list truncated away the symbol asked about.
fn route(kind: &str, probe: &str, budget: u64) -> String {
    let base = daemon_base();
    let repo = repo_id();
    match kind {
        "code_path" => format!(
            "{base}/v1/code-intel/path?tenant_id={TENANT}&entry_point={}&token_budget={budget}",
            encode(probe)
        ),
        "blast_radius" => format!(
            "{base}/v1/code-intel/blast-radius?tenant_id={TENANT}&repo_id={}&symbol={}&token_budget={budget}",
            encode(&repo),
            encode(probe)
        ),
        "liveness" => format!(
            "{base}/v1/code-intel/liveness?tenant_id={TENANT}&repo_id={}&symbol={}&token_budget={budget}",
            encode(&repo),
            encode(probe)
        ),
        "dead_code" => format!(
            "{base}/v1/code-intel/dead-code?tenant_id={TENANT}&repo_id={}&symbol={}&token_budget={budget}",
            encode(&repo),
            encode(probe)
        ),
        other => panic!("no route for question kind {other}"),
    }
}

fn get(url: &str) -> (u16, String) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(120)))
        .build()
        .into();
    match agent.get(url).header("Accept", "application/json").call() {
        Ok(mut r) => {
            let status = r.status().as_u16();
            let mut body = String::new();
            let _ = r.body_mut().as_reader().read_to_string(&mut body);
            (status, body)
        }
        Err(ureq::Error::StatusCode(code)) => (code, String::new()),
        Err(e) => panic!("request to {url} failed: {e} — is a capture-enabled daemon running?"),
    }
}

fn main() {
    let control_path = std::env::args().nth(1);
    let corpus: Value = serde_json::from_str(CORPUS_JSON).expect("corpus JSON parses");
    let corpus_name = corpus["corpus"].as_str().expect("corpus name");
    let corpus_commit = corpus["commit_sha"].as_str().expect("corpus commit");
    let questions = corpus["questions"].as_array().expect("questions array");

    // The window the runtime half of every answer is true for. Reported with
    // the saving, because a liveness or dead-code answer is only ever as strong
    // as the traffic behind it.
    let (_, stats_body) = get(&format!("{}/v1/traces/stats", daemon_base()));
    let trace_stats: Value = serde_json::from_str(&stats_body).unwrap_or(Value::Null);

    let headline_budget = *BUDGETS.iter().max().expect("budgets non-empty");
    let mut records = Vec::new();
    let mut budget_totals: BTreeMap<String, u64> = BTreeMap::new();

    for q in questions {
        let id = q["id"].as_str().expect("id").to_string();
        let kind = q["kind"].as_str().expect("kind");
        let probe = q["probe"].as_str().expect("probe");

        let mut cells = serde_json::Map::new();
        let mut headline_answer = Value::Null;
        for &budget in &BUDGETS {
            let url = route(kind, probe, budget);
            let (status, body) = get(&url);
            assert!(
                (200..300).contains(&status),
                "{id}: {url} returned {status} — the treatment arm needs a scanned repo and a live daemon"
            );
            let tokens = estimate_tokens_str(&body);
            *budget_totals.entry(format!("budget_{budget}")).or_default() += tokens;
            if budget == headline_budget {
                headline_answer = serde_json::from_str(&body).unwrap_or(Value::Null);
            }
            cells.insert(format!("budget_{budget}"), json!({ "tokens": tokens }));
        }

        records.push(json!({
            "id": id,
            "kind": kind,
            "probe": probe,
            "cells": Value::Object(cells),
            // Kept for M3: correctness is scored from these, not re-fetched.
            "answer": headline_answer,
        }));
    }

    let headline_key = format!("budget_{headline_budget}");
    let treatment_total = budget_totals[&headline_key];

    let mut out = json!({
        "harness": "code_intel_treatment",
        "arm": "treatment",
        "corpus": corpus_name,
        "corpus_commit": corpus_commit,
        "questions": records.len(),
        "budgets": BUDGETS,
        "headline_treatment": {
            "budget": headline_budget,
            "total_tokens": treatment_total,
            "mean_tokens_per_question": treatment_total / records.len() as u64,
            "rule": "largest budget in the sweep — the dearest the tool call can be",
        },
        "budget_totals": budget_totals,
        "observation_window": trace_stats,
        "records": records,
    });

    // Pair against the control when one is supplied. Reported via
    // SavingsReport::format so the figure cannot be rendered without its
    // interval, its corpus and its commit.
    if let Some(path) = control_path {
        let control: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("read control JSON"))
            .expect("control JSON parses");
        assert_eq!(
            control["corpus"], corpus["corpus"],
            "control and treatment must be measured over the same corpus"
        );
        let control_cell = control["headline_control"]["cell"]
            .as_str()
            .expect("control headline cell");

        let by_id: BTreeMap<&str, &Value> = control["records"]
            .as_array()
            .expect("control records")
            .iter()
            .map(|r| (r["id"].as_str().expect("control id"), r))
            .collect();

        let mut control_tokens = Vec::new();
        let mut treatment_tokens = Vec::new();
        let mut per_question = Vec::new();
        for r in &records {
            let id = r["id"].as_str().expect("id");
            let c = by_id[id]["cells"][control_cell]["tokens"]
                .as_u64()
                .expect("control tokens");
            let t = r["cells"][&headline_key]["tokens"].as_u64().expect("treatment tokens");
            control_tokens.push(c);
            treatment_tokens.push(t);
            per_question.push(json!({
                "id": id,
                "kind": r["kind"],
                "probe": r["probe"],
                "control_tokens": c,
                "treatment_tokens": t,
                "reduction": (c as f64 - t as f64) / c as f64,
            }));
        }

        let report = paired_savings(&control_tokens, &treatment_tokens);
        out["savings"] = json!({
            "line": report.format(corpus_name, corpus_commit),
            "n": report.n,
            "reduction": report.reduction,
            "ci_low": report.ci_low,
            "ci_high": report.ci_high,
            "control_tokens": report.control_tokens,
            "treatment_tokens": report.treatment_tokens,
            "control_cell": control_cell,
            "treatment_budget": headline_budget,
            "pairing_rule": "cheapest control cell vs dearest treatment budget — both chosen to cut against the saving",
            "per_question": per_question,
        });
        eprintln!("{}", report.format(corpus_name, corpus_commit));
    }

    println!("{}", serde_json::to_string_pretty(&out).expect("serialise"));
    eprintln!(
        "treatment arm — corpus {corpus_name} @ {corpus_commit}, {} questions, headline budget {headline_budget}",
        records.len()
    );
    for (budget, total) in &budget_totals {
        eprintln!("  {budget:12} total={total:7}  mean={:6}", total / records.len() as u64);
    }
}
