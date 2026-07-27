// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! M3 — is the cheaper answer also the right one?
//!
//! ExecPlan: `crux-codemap-agent-surface-and-measured-savings-2026-07-27` (M3).
//!
//! M2 measured cost. A cheap answer that is wrong is not a saving, it is a
//! defect, so this scores every treatment answer against the corpus's ground
//! truth. It reads the JSON M2 already wrote — the daemon is not re-queried, so
//! the answers scored are exactly the answers priced.
//!
//! ## What counts as wrong
//!
//! Not "incomplete". An answer that says *"not observed in this window"* is
//! honest and useful; the window is part of it. What is scored wrong is an
//! answer that would lead a competent agent to do the wrong thing:
//!
//!   * calling a symbol dead when production code calls it — someone deletes it;
//!   * reporting an empty blast radius when a caller exists — someone changes a
//!     signature and breaks the caller.
//!
//! Both are *confidently wrong*, which is worse than expensive.
//!
//! Run:
//!
//!     cargo run -p crux-mcp --example code_intel_score -- <treatment.json>

#![allow(clippy::print_stdout, clippy::print_stderr, clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;

use serde_json::{json, Value};

const CORPUS_JSON: &str = include_str!("../corpora/code-intel-questions.json");

/// Verdict on one answer.
struct Score {
    correct: bool,
    /// True when the answer is not just wrong but *confidently* wrong — it
    /// would drive an incorrect edit rather than prompt more digging.
    misleading: bool,
    detail: String,
}

fn ok(detail: impl Into<String>) -> Score {
    Score {
        correct: true,
        misleading: false,
        detail: detail.into(),
    }
}

fn wrong(detail: impl Into<String>) -> Score {
    Score {
        correct: false,
        misleading: true,
        detail: detail.into(),
    }
}

fn weak(detail: impl Into<String>) -> Score {
    Score {
        correct: false,
        misleading: false,
        detail: detail.into(),
    }
}

fn files_of(refs: &Value) -> BTreeSet<String> {
    refs.as_array()
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .filter_map(|s| s.rsplit_once(':').map(|(f, _)| f.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// `code_path` — did the answer name the handler's own file?
fn score_path(gt: &Value, answer: &Value) -> Score {
    let want = files_of(&gt["definition"]);
    let got: BTreeSet<String> = answer["steps"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s["file"].as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let matched = want.intersection(&got).count();
    if matched > 0 {
        ok(format!("named the handler's file among {} observed steps", got.len()))
    } else if got.is_empty() {
        weak("no steps observed — the entry point did not run in this window")
    } else {
        weak(format!(
            "observed {} steps but none in the handler's own file",
            got.len()
        ))
    }
}

/// `blast_radius` — an empty radius when a production caller exists is the
/// dangerous answer: it reads as "nothing breaks".
fn score_blast_radius(gt: &Value, answer: &Value) -> Score {
    let prod = gt["production_refs"].as_array().map_or(0, Vec::len);
    let dependents = answer["dependents"].as_array().map_or(0, Vec::len);
    let static_dependents = answer["static_dependents"].as_u64().unwrap_or(0);
    let runtime_callers = answer["runtime_callers"].as_u64().unwrap_or(0);

    if prod == 0 {
        return ok("no production caller to find");
    }
    if dependents == 0 && static_dependents == 0 && runtime_callers == 0 {
        return wrong(format!(
            "reported an EMPTY blast radius while {prod} production reference site(s) exist — reads as 'nothing breaks'"
        ));
    }
    ok(format!(
        "{static_dependents} static + {runtime_callers} runtime dependents against {prod} known production site(s)"
    ))
}

/// `liveness` / `dead_code` — the failure that matters is calling live code dead.
fn score_liveness(gt: &Value, answer: &Value) -> Score {
    let truth = gt["verdict"].as_str().unwrap_or("");
    let verdict = answer["verdict"].as_str().unwrap_or("");
    let says_dead = verdict.contains("dead_candidate");

    match truth {
        "alive_in_production" if says_dead => wrong(format!(
            "verdict `{verdict}` on a symbol called from production — a deletion here breaks the build"
        )),
        "alive_in_production" => ok(format!("`{verdict}` — did not call live code dead")),
        _ if says_dead => ok(format!("`{verdict}` matches ground truth `{truth}`")),
        _ => weak(format!(
            "`{verdict}` — true verdict is `{truth}`; not wrong, but the window was too thin to say so"
        )),
    }
}

/// The ladder answers about the whole repo, so find this symbol's verdict in it.
fn score_dead_code(gt: &Value, probe: &str, answer: &Value) -> Score {
    let truth = gt["verdict"].as_str().unwrap_or("");
    let verdict = answer["verdicts"]
        .as_array()
        .and_then(|v| v.iter().find(|s| s["symbol"].as_str() == Some(probe)));

    let Some(v) = verdict else {
        return weak(format!(
            "`{probe}` does not appear in the ladder at this budget — the agent cannot answer without a wider one"
        ));
    };
    let actionable = v["actionable"].as_bool().unwrap_or(false);
    let single = v["single_signal"].as_bool().unwrap_or(false);

    if truth == "alive_in_production" && actionable {
        return wrong(format!(
            "marked `{probe}` actionable-for-deletion while production code calls it"
        ));
    }
    if actionable {
        return ok("actionable, and ground truth agrees nothing in production calls it");
    }
    ok(format!(
        "not actionable (single_signal={single}) — correctly withheld a deletion verdict"
    ))
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: code_intel_score <treatment.json>");
    let treatment: Value = serde_json::from_str(&std::fs::read_to_string(&path).expect("read treatment JSON"))
        .expect("treatment JSON parses");
    let corpus: Value = serde_json::from_str(CORPUS_JSON).expect("corpus JSON parses");
    assert_eq!(
        treatment["corpus"], corpus["corpus"],
        "treatment and corpus must be the same corpus"
    );

    let mut scored = Vec::new();
    let (mut correct, mut misleading) = (0usize, 0usize);

    for q in corpus["questions"].as_array().expect("questions") {
        let id = q["id"].as_str().expect("id");
        let kind = q["kind"].as_str().expect("kind");
        let probe = q["probe"].as_str().expect("probe");
        let gt = &q["ground_truth"];
        let answer = treatment["records"]
            .as_array()
            .expect("records")
            .iter()
            .find(|r| r["id"].as_str() == Some(id))
            .map(|r| &r["answer"])
            .expect("every corpus question must have a treatment answer");

        let score = match kind {
            "code_path" => score_path(gt, answer),
            "blast_radius" => score_blast_radius(gt, answer),
            "liveness" => score_liveness(gt, answer),
            "dead_code" => score_dead_code(gt, probe, answer),
            other => panic!("no scorer for kind {other}"),
        };
        if score.correct {
            correct += 1;
        }
        if score.misleading {
            misleading += 1;
        }
        scored.push(json!({
            "id": id,
            "kind": kind,
            "probe": probe,
            "ground_truth": gt["verdict"],
            "correct": score.correct,
            "misleading": score.misleading,
            "detail": score.detail,
        }));
    }

    let n = scored.len();
    let out = json!({
        "harness": "code_intel_score",
        "corpus": corpus["corpus"],
        "corpus_commit": corpus["commit_sha"],
        "observation_window": treatment["observation_window"],
        "n": n,
        "correct": correct,
        "accuracy": correct as f64 / n as f64,
        "misleading": misleading,
        "scoring_rule": "An answer is WRONG only when it would drive an incorrect edit — calling \
                         live code dead, or reporting an empty blast radius where a caller exists. \
                         'Not observed in this window' is honest, and is scored weak-not-wrong.",
        "savings_for_context": treatment["savings"]["line"],
        "scores": scored,
    });
    println!("{}", serde_json::to_string_pretty(&out).expect("serialise"));

    eprintln!(
        "accuracy {correct}/{n} ({:.1}%) · {misleading} confidently-wrong answer(s)",
        correct as f64 / n as f64 * 100.0
    );
    for s in out["scores"].as_array().expect("scores") {
        if !s["correct"].as_bool().unwrap_or(false) {
            let flag = if s["misleading"].as_bool().unwrap_or(false) {
                "WRONG"
            } else {
                "weak "
            };
            eprintln!(
                "  {flag} {:4} {:32} {}",
                s["id"].as_str().unwrap_or(""),
                s["probe"].as_str().unwrap_or(""),
                s["detail"].as_str().unwrap_or("")
            );
        }
    }
}
