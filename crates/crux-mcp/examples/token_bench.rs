// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! M0 — token-efficiency baseline + measurement harness.
//!
//! ExecPlan: `crux-headroom-token-efficiency-learnings-2026-06-24` (milestone M0).
//! Establishes a named-corpus baseline so every later milestone's saving is
//! attributable (QC.4) rather than a counterfactual claim. The harness seeds a
//! deterministic synthetic corpus (`__synthetic__::token-bench`) entirely
//! in-process — no daemon, no network, no prod data — and measures the exact
//! code paths the plan targets:
//!
//!   * segment query budget enforcement (`tools::query` `take_while`-drop) — M1 target
//!   * `query_facts` budget enforcement (`tools::memory`/`facts`)            — M1 target
//!   * `to_string_pretty` wire serialization                                 — M3 target
//!   * `get_bootstrap` assembly (no budget knob — itself a finding)          — M2 context
//!
//! Run (machine-parseable JSON to stdout; human summary to stderr):
//!
//!     cargo run -p crux-mcp --example token_bench
//!
//! Attribution for a `bench:` fact (optional; harness output is otherwise
//! deterministic and reproducible — same inputs => byte-identical records):
//!
//!     CRUX_BENCH_COMMIT=<sha> CRUX_BENCH_RUN_ID=<id> cargo run -p crux-mcp --example token_bench
//!
//! Reproducibility gate (M0): two consecutive runs emit identical `records`.

#![allow(clippy::print_stdout, clippy::print_stderr, clippy::expect_used, clippy::unwrap_used)]

use corecrux_index::CcxiBuilder;
use corecrux_memory::fact_store::StoreFact;
use crux_mcp::dispatch::McpContext;
use crux_mcp::token_estimate::estimate_tokens_str;
use crux_mcp::tools::{facts, query};
use serde_json::{json, Value};

/// Named corpus identity (QC.4) — every record carries this.
const CORPUS: &str = "__synthetic__::token-bench";
/// Concrete tenant for the retrieval (segment) plane.
const TENANT: &str = "token-bench";
/// The three standard budgets the plan measures against.
const BUDGETS: [usize; 3] = [500, 2000, 4000];
/// Number of synthetic segment docs / facts to seed. Lengths vary so the
/// cumulative budget cut lands at a different survivor count per budget.
const N_DOCS: u32 = 30;

fn tenant_hash(t: &str) -> u64 {
    xxhash_rust::xxh64::xxh64(t.as_bytes(), 0)
}

/// Deterministic filler of roughly `tokens` whitespace-separated words, all
/// containing the match term so BM25 / keyword search returns the doc/fact.
fn body(term: &str, doc_ix: u32, tokens: usize) -> String {
    let lexicon = [
        "context",
        "compression",
        "budget",
        "pointer",
        "epitome",
        "segment",
        "receipt",
        "freshness",
        "horizon",
        "supersession",
        "tenant",
        "lexical",
        "fusion",
        "envelope",
    ];
    let mut words = Vec::with_capacity(tokens);
    for i in 0..tokens {
        if i % 5 == 0 {
            words.push(term.to_string());
        } else {
            // doc_ix in the word keeps docs distinct without breaking the match term.
            words.push(format!(
                "{}{}",
                lexicon[(i + doc_ix as usize) % lexicon.len()],
                doc_ix % 7
            ));
        }
    }
    words.join(" ")
}

/// Token length for synthetic doc/fact `i`: varied in [40, 250] so the budget
/// cut is meaningful and uneven (mirrors a real mixed-length result set).
fn varied_len(i: u32) -> usize {
    40 + ((i % 8) as usize) * 30
}

/// Seed the in-process corpus: one `.ccxi` segment (retrieval plane) + facts
/// (`query_facts` plane) + bootstrap patterns (`get_bootstrap` plane).
async fn seed(ctx: &McpContext) {
    // ── Retrieval plane: one segment, N_DOCS docs of varied length ──
    let th = tenant_hash(TENANT);
    let mut builder = CcxiBuilder::new(0, 1, 1);
    for i in 0..N_DOCS {
        let text = body("alpha", i, varied_len(i));
        builder.add_document(i, &text, i * 1000, th);
    }
    let bytes = builder.build();
    ctx.retrieval_index
        .write()
        .await
        .load_ccxi_bytes(&bytes)
        .expect("load synthetic .ccxi");

    // ── Fact plane: N_DOCS facts under the corpus entity, value carries "needle" ──
    {
        let mut store = ctx.fact_store.write().await;
        for i in 0..N_DOCS {
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: CORPUS.to_string(),
                key: format!("k{i:02}"),
                value: body("needle", i, varied_len(i)),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }
        // ── Bootstrap plane: a handful of pattern playbooks (no budget knob) ──
        for i in 0..8 {
            store.store(StoreFact {
                tenant_hash: "default".to_string(),
                entity: format!("__bootstrap__::pattern:p{i}"),
                key: "playbook".to_string(),
                value: body("pattern", i, 60),
                source_receipt: None,
                confidence: 1.0,
                private: false,
                horizon_class: None,
                actor: None,
            });
        }
    }
}

/// Pull the single `content[0].text` string out of a tool response.
fn content_text(resp: &Value) -> String {
    resp.get("content")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("text"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// Count the inline hits a response actually carries (CRC-v1 `pointers`, or
/// legacy `results`/`scan`; for the fact path, `content`/`pointers`). For
/// non-JSON text surfaces (e.g. `get_bootstrap`, which emits newline-joined
/// lines) fall back to the non-empty line count.
fn inline_hits(text: &str) -> u64 {
    match serde_json::from_str::<Value>(text) {
        Ok(parsed) => {
            for key in ["pointers", "results", "scan", "content"] {
                if let Some(a) = parsed.get(key).and_then(Value::as_array) {
                    return a.len() as u64;
                }
            }
            0
        }
        Err(_) => text.lines().filter(|l| !l.trim().is_empty()).count() as u64,
    }
}

/// Total candidates available (so M1's "demote, don't drop" recall delta is
/// computable against the baseline). CRC-v1 folds it under `meta`.
fn candidates(text: &str) -> u64 {
    let parsed: Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    parsed
        .get("total_candidates")
        .or_else(|| parsed.get("meta").and_then(|m| m.get("total_candidates")))
        .and_then(Value::as_u64)
        .unwrap_or_else(|| inline_hits(text))
}

struct RunMeta {
    commit: String,
    run_id: String,
    lane_flags: String,
}

/// Run the compaction-sensitive scenarios and return `(scenario_key, response_text)`
/// for each, honouring whatever `CRUX_OUTPUT_HOLDOUT` fraction is set (the
/// handlers read it at call time). Used by the M5 paired holdout measurement,
/// which calls this once with holdout=1 (unshaped control) and once with
/// holdout=0 (fully shaped treatment).
async fn measure_scenarios(ctx: &McpContext) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for &budget in &BUDGETS {
        let q = query::handle_query(
            &json!({"tenant_id": TENANT, "query": "alpha", "limit": 50, "token_budget": budget}),
            ctx,
        )
        .await
        .expect("query");
        out.push((format!("query@{budget}"), content_text(&q)));

        let qf = facts::handle_query_facts(&json!({"query": "needle", "token_budget": budget, "top_k": 50}), ctx)
            .await
            .expect("query_facts");
        out.push((format!("query_facts@{budget}"), content_text(&qf)));
    }
    let qs = query::handle_query_scan(&json!({"tenant_id": TENANT, "query": "alpha", "limit": 50}), ctx)
        .await
        .expect("query_scan");
    out.push(("query_scan".to_string(), content_text(&qs)));
    out
}

/// M5 — paired NET savings of the fully-shaped path (reversible-cap + compaction)
/// vs. the unshaped control (legacy drop + pretty), measured on the same
/// scenarios, with a 95% CI. Since CO-5 removed the per-mechanism env flags, the
/// shaped/unshaped lever is the holdout fraction: `=1` forces every request into
/// the unshaped control arm, `=0` is fully shaped. Env is saved/restored.
async fn paired_holdout_savings(ctx: &McpContext) -> crux_mcp::holdout::SavingsReport {
    use crux_mcp::holdout::HOLDOUT_ENV;
    let saved = std::env::var(HOLDOUT_ENV).ok();

    // Control arm: holdout=1 ⇒ every request unshaped (legacy drop + pretty).
    std::env::set_var(HOLDOUT_ENV, "1");
    let control = measure_scenarios(ctx).await;

    // Treatment arm: holdout=0 ⇒ fully shaped (reversible-cap + compaction).
    std::env::set_var(HOLDOUT_ENV, "0");
    let treatment = measure_scenarios(ctx).await;

    match saved {
        Some(v) => std::env::set_var(HOLDOUT_ENV, v),
        None => std::env::remove_var(HOLDOUT_ENV),
    }

    let control_tokens: Vec<u64> = control.iter().map(|(_, t)| estimate_tokens_str(t)).collect();
    let treatment_tokens: Vec<u64> = treatment.iter().map(|(_, t)| estimate_tokens_str(t)).collect();
    crux_mcp::holdout::paired_savings(&control_tokens, &treatment_tokens)
}

fn record(scenario: &str, budget: Option<usize>, text: &str, m: &RunMeta) -> Value {
    json!({
        "corpus": CORPUS,
        "scenario": scenario,
        "budget": budget,
        "inline_tokens": estimate_tokens_str(text),
        "inline_bytes": text.len() as u64,
        "inline_hits": inline_hits(text),
        "candidates": candidates(text),
        "contract": "crc-v1",
        "lane_flags": m.lane_flags,
        "commit_sha": m.commit,
        "run_id": m.run_id,
    })
}

#[tokio::main]
async fn main() {
    // Since CO-5 the efficiency mechanisms (m1 reversible-cap + m3 compaction) are
    // unconditional; the primary records pass runs fully shaped unless a holdout
    // fraction diverts a sample to the unshaped control. lane_flags documents that.
    let lane_flags = format!(
        "m1+m3:unconditional;holdout={:.3}",
        crux_mcp::holdout::holdout_fraction()
    );
    let m = RunMeta {
        commit: std::env::var("CRUX_BENCH_COMMIT").unwrap_or_else(|_| "unknown".to_string()),
        run_id: std::env::var("CRUX_BENCH_RUN_ID").unwrap_or_else(|_| "local".to_string()),
        lane_flags,
    };

    let ctx = McpContext::new_default("token-bench-node");
    seed(&ctx).await;

    let mut records: Vec<Value> = Vec::new();

    for &budget in &BUDGETS {
        // segment query (M1 take_while-drop + M3 serialization target)
        let q = query::handle_query(
            &json!({"tenant_id": TENANT, "query": "alpha", "limit": 50, "token_budget": budget}),
            &ctx,
        )
        .await
        .expect("query");
        records.push(record("query", Some(budget), &content_text(&q), &m));

        // query_facts (M1 budget cut on the fact plane)
        let qf = facts::handle_query_facts(&json!({"query": "needle", "token_budget": budget, "top_k": 50}), &ctx)
            .await
            .expect("query_facts");
        records.push(record("query_facts", Some(budget), &content_text(&qf), &m));
    }

    // query_scan — metadata-only; measured once (no budget knob in the handler).
    let qs = query::handle_query_scan(&json!({"tenant_id": TENANT, "query": "alpha", "limit": 50}), &ctx)
        .await
        .expect("query_scan");
    records.push(record("query_scan", None, &content_text(&qs), &m));

    // M5 — paired NET holdout savings (fully-shaped treatment vs. unshaped
    // control), reported as a point estimate WITH a 95% CI (never a bare number).
    let savings = paired_holdout_savings(&ctx).await;
    let savings_line = savings.format(CORPUS, &m.commit);

    // get_bootstrap — no budget enforcement today (FactQuery.token_budget=None);
    // measured once. The absence of a budget knob is the M2 cache-align context.
    let gb = facts::handle_get_bootstrap(&json!({"topic": "patterns"}), &ctx)
        .await
        .expect("get_bootstrap");
    records.push(record("get_bootstrap", None, &content_text(&gb), &m));

    let out = json!({
        "harness": "token_bench",
        "harness_version": 1,
        "corpus": CORPUS,
        "n_docs": N_DOCS,
        "budgets": BUDGETS,
        "commit_sha": m.commit,
        "run_id": m.run_id,
        "lane_flags": m.lane_flags,
        "records": records,
        // M5 — net holdout savings: fully-shaped (treatment) vs unshaped (control),
        // paired per scenario, with a 95% CI (Headroom holdout / QC.4 / QC.5).
        "savings": {
            "treatment": "m1+m3:fully-shaped",
            "control": "unshaped:legacy-drop+pretty",
            "method": "paired per-scenario reduction, 95% CI (normal approx, z=1.96)",
            "n": savings.n,
            "reduction_pct": savings.reduction * 100.0,
            "ci95_low_pct": savings.ci_low * 100.0,
            "ci95_high_pct": savings.ci_high * 100.0,
            "control_tokens": savings.control_tokens,
            "treatment_tokens": savings.treatment_tokens,
            "report": savings_line,
        },
    });

    // Human summary to stderr (does not pollute the JSON on stdout).
    eprintln!(
        "token_bench — corpus={CORPUS} commit={} run_id={} lane_flags={}",
        m.commit, m.run_id, m.lane_flags
    );
    eprintln!(
        "{:<14} {:>7} {:>8} {:>8} {:>6} {:>11}",
        "scenario", "budget", "tokens", "bytes", "hits", "candidates"
    );
    for r in &records {
        eprintln!(
            "{:<14} {:>7} {:>8} {:>8} {:>6} {:>11}",
            r["scenario"].as_str().unwrap_or(""),
            r["budget"].as_u64().map_or_else(|| "-".to_string(), |b| b.to_string()),
            r["inline_tokens"].as_u64().unwrap_or(0),
            r["inline_bytes"].as_u64().unwrap_or(0),
            r["inline_hits"].as_u64().unwrap_or(0),
            r["candidates"].as_u64().unwrap_or(0),
        );
    }

    eprintln!("M5 holdout — {savings_line}");

    // Machine-parseable JSON to stdout (the bench record).
    println!("{}", serde_json::to_string_pretty(&out).expect("serialise"));
}
