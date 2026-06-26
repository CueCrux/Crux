// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

#![deny(clippy::unwrap_used)]

//! `crux-cost` — the ground-truth **token-burn cost lens**.
//!
//! Given a Claude Code transcript (`<session>.jsonl`), this crate measures what
//! a coding session actually cost and *why*, then says what to do about it:
//!
//! 1. **Measure** — read the transcript's `message.usage` (ground truth: input,
//!    output, cache-read, cache-creation). See [`transcript`].
//! 2. **Attribute** — apportion the measured context across sources using the
//!    carried-cost model (a block re-read `k − e` times costs `est × (k − e)`),
//!    reconciling exactly to the measured total. See [`attribution`].
//! 3. **Advise** — emit grounded [reduction levers](report::Lever): "what you
//!    can do to reduce burn." See [`levers`].
//!
//! The output is a single [`CostReport`] — the shared contract the
//! `corecruxctl session cost` CLI produces, the daemon `/v1/cost/report`
//! endpoint stores, and the console `cx-cost` page renders.
//!
//! Estimation (chars/4) is used only to *apportion* the measured spend; the
//! headline numbers are always the transcript's real `usage`.

pub mod attribution;
pub mod levers;
pub mod report;
pub mod summary;
pub mod transcript;

pub use report::{BlockCost, Bucket, CostReport, Headline, Lever, Measured, Severity, COST_REPORT_SCHEMA};
pub use transcript::{ExecPlanSignal, SignalStrength};

use std::path::Path;

/// Maximum number of top carried-cost blocks retained in a report.
pub const TOP_BLOCKS: usize = 25;

/// Upper bound on the distinct ExecPlan slugs carried on a report's
/// `execplan_slugs`. This is a **sanity bound, not a precision cap** (OD-30 v2):
/// the daemon **even-splits** a session's burn across its linked plans, so a
/// high-fan-out session no longer over-credits — there is no inflation to defend
/// against by truncating. The bound only guards against a pathological transcript
/// emitting an unbounded list; real sessions top out well under it (observed max
/// 16). Slugs beyond the bound are the lowest-evidence ones (ranked last).
pub const MAX_EXECPLAN_SLUGS: usize = 25;

/// Parse and analyze a transcript file into a [`CostReport`], with `source` set
/// to the file name (corpus identity — QC.4).
///
/// # Errors
/// Returns the underlying [`std::io::Error`] if the file cannot be opened.
pub fn analyze_file(path: &Path) -> std::io::Result<CostReport> {
    let events = transcript::parse_file(path)?;
    let mut report = attribution::analyze(&events);
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .clone_into(&mut report.source);
    Ok(report)
}

/// Analyze an in-memory transcript (one JSON object per line). `source` names
/// the corpus for the report.
#[must_use]
pub fn analyze_str(text: &str, source: impl Into<String>) -> CostReport {
    let events = transcript::parse_str(text);
    let mut report = attribution::analyze(&events);
    report.source = source.into();
    report
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A small but structurally-real 3-turn, single-segment transcript.
    fn fixture() -> String {
        let build_output = "x".repeat(800);
        let edit_input = "y".repeat(600);
        let records = [
            json!({"type":"user","sessionId":"test-sess",
                   "message":{"role":"user","content":"Please run the build and fix the errors"}}),
            json!({"type":"assistant","sessionId":"test-sess","message":{"role":"assistant",
            "usage":{"input_tokens":100,"output_tokens":50,
                     "cache_read_input_tokens":1000,"cache_creation_input_tokens":200},
            "content":[
              {"type":"thinking","thinking":"SECRET_REASONING_PHRASE — weigh the build steps"},
              {"type":"text","text":"Running the build now."},
              {"type":"tool_use","id":"t1","name":"Bash","input":{"command":"cargo build --release"}}
            ]}}),
            json!({"type":"user","sessionId":"test-sess","message":{"role":"user","content":[
                     {"type":"tool_result","tool_use_id":"t1","content":build_output}]}}),
            json!({"type":"assistant","sessionId":"test-sess","message":{"role":"assistant",
            "usage":{"input_tokens":80,"output_tokens":40,
                     "cache_read_input_tokens":3000,"cache_creation_input_tokens":0},
            "content":[
              {"type":"text","text":"Build failed on one file, applying a fix."},
              {"type":"tool_use","id":"t2","name":"Edit","input":{"patch":edit_input}}
            ]}}),
            json!({"type":"user","sessionId":"test-sess","message":{"role":"user","content":[
                     {"type":"tool_result","tool_use_id":"t2","content":"Edit applied cleanly."}]}}),
            json!({"type":"assistant","sessionId":"test-sess","message":{"role":"assistant",
                   "usage":{"input_tokens":50,"output_tokens":20,
                            "cache_read_input_tokens":5000,"cache_creation_input_tokens":0},
                   "content":[{"type":"text","text":"All green now."}]}}),
        ];
        records.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n")
    }

    #[test]
    fn measured_and_headline_are_ground_truth() {
        let r = analyze_str(&fixture(), "fixture.jsonl");
        assert_eq!(r.measured.input, 230);
        assert_eq!(r.measured.output, 110);
        assert_eq!(r.measured.cache_read, 9000);
        assert_eq!(r.measured.cache_creation, 200);
        // Σ(cache_read + cache_creation + input) = 9430.
        assert_eq!(r.headline.measured_context_total, 9430);
        assert_eq!(r.headline.assistant_turns, 3);
        assert_eq!(r.headline.tasks, 1);
        assert_eq!(r.headline.segments, 1);
        assert_eq!(r.headline.context_tokens_per_turn, 9430 / 3);
        // 9000 / 110 = 81.8181… → 81.82.
        assert!((r.headline.cache_read_to_output_ratio - 81.82).abs() < 1e-9);
        assert_eq!(r.session_id, "test-sess");
        assert_eq!(r.source, "fixture.jsonl");
        assert_eq!(r.schema, COST_REPORT_SCHEMA);
    }

    #[test]
    fn buckets_reconcile_to_measured_total() {
        let r = analyze_str(&fixture(), "fixture.jsonl");
        let sum: u64 = r.buckets.iter().map(|b| b.carried_cost).sum();
        assert_eq!(
            sum, r.headline.measured_context_total,
            "buckets must reconcile exactly to the measured context total"
        );
        // cache_read dominates → the fixed prefix is the largest bucket.
        assert_eq!(r.buckets[0].source, "session_prefix");
        assert!(r.headline.prefix_pct > 50.0);
        // Tool I/O is present and coarsened.
        assert!(r.buckets.iter().any(|b| b.source == "tool_result"));
    }

    #[test]
    fn thinking_text_never_surfaces() {
        let r = analyze_str(&fixture(), "fixture.jsonl");
        let serialized = serde_json::to_string(&r).expect("serialize report");
        assert!(
            !serialized.contains("SECRET_REASONING_PHRASE"),
            "raw thinking text must never appear in the cost report (R1 posture)"
        );
        // The thinking block is still counted, with a redacted preview.
        assert!(r
            .top_blocks
            .iter()
            .filter(|b| b.source == "assistant_thinking")
            .all(|b| b.preview.starts_with("(thinking")));
    }

    #[test]
    fn compaction_boundary_splits_segments() {
        let mut lines = fixture();
        lines.push('\n');
        lines.push_str(&json!({"type":"system","subtype":"compact_boundary","sessionId":"test-sess"}).to_string());
        lines.push('\n');
        lines.push_str(
            &json!({"type":"assistant","sessionId":"test-sess","message":{"role":"assistant",
                    "usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":100},
                    "content":[{"type":"text","text":"After compaction."}]}})
            .to_string(),
        );
        let r = analyze_str(&lines, "fixture.jsonl");
        assert_eq!(r.headline.segments, 2);
        assert_eq!(r.headline.assistant_turns, 4);
    }

    #[test]
    fn malformed_lines_are_skipped() {
        let mut lines = String::from("{ this is not json\n");
        lines.push_str(&fixture());
        lines.push_str("\nnot json either\n");
        let r = analyze_str(&lines, "fixture.jsonl");
        // Parsing survived; the real records still analyzed.
        assert_eq!(r.headline.assistant_turns, 3);
    }

    #[test]
    fn session_window_spans_earliest_to_latest_timestamp() {
        // Out-of-order + a meta (queue-operation) record: the window must be the
        // lexical min/max across all records, meta included.
        let lines = [
            json!({"type":"assistant","sessionId":"w","timestamp":"2026-06-25T11:38:40.060Z",
                   "message":{"role":"assistant","usage":{"input_tokens":1,"output_tokens":1,"cache_read_input_tokens":1},
                   "content":[{"type":"text","text":"mid"}]}}),
            json!({"type":"queue-operation","sessionId":"w","timestamp":"2026-06-25T11:30:00.000Z","operation":"x"}),
            json!({"type":"assistant","sessionId":"w","timestamp":"2026-06-25T12:05:09.500Z",
                   "message":{"role":"assistant","usage":{"input_tokens":1,"output_tokens":1,"cache_read_input_tokens":1},
                   "content":[{"type":"text","text":"end"}]}}),
            // Malformed timestamp must be ignored, not widen the window.
            json!({"type":"user","sessionId":"w","timestamp":"not-a-timestamp",
                   "message":{"role":"user","content":"hi"}}),
        ]
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
        let r = analyze_str(&lines, "w.jsonl");
        assert_eq!(r.started_at.as_deref(), Some("2026-06-25T11:30:00.000Z"));
        assert_eq!(r.ended_at.as_deref(), Some("2026-06-25T12:05:09.500Z"));
    }

    #[test]
    fn session_window_none_when_no_timestamps() {
        let r = analyze_str(&fixture(), "fixture.jsonl");
        // The fixture records carry no `timestamp` field.
        assert!(r.started_at.is_none());
        assert!(r.ended_at.is_none());
    }

    #[test]
    fn empty_transcript_yields_no_levers() {
        let r = analyze_str("", "empty.jsonl");
        assert_eq!(r.headline.assistant_turns, 0);
        assert!(r.levers.is_empty());
        assert!(r.buckets.is_empty());
    }

    #[test]
    fn levers_fire_on_grounded_thresholds() {
        let headline = Headline {
            assistant_turns: 50,
            tasks: 5,
            segments: 1,
            context_tokens_per_turn: 150_000,
            cache_read_to_output_ratio: 300.0,
            measured_context_total: 7_500_000,
            prefix_pct: 60.0,
        };
        let buckets = vec![
            Bucket {
                source: "session_prefix".to_owned(),
                carried_cost: 4_500_000,
                pct: 60.0,
            },
            Bucket {
                source: "tool_result".to_owned(),
                carried_cost: 2_250_000,
                pct: 30.0,
            },
            Bucket {
                source: "tool_use_args".to_owned(),
                carried_cost: 600_000,
                pct: 8.0,
            },
        ];
        let blocks = vec![BlockCost {
            source: "tool_result:Bash".to_owned(),
            tool: Some("Bash".to_owned()),
            est_tokens: 1000,
            turns_live: 10,
            carried_cost: 10_000,
            preview: "build log".to_owned(),
        }];
        let levers = levers::generate(&headline, &buckets, &blocks);
        let ids: Vec<&str> = levers.iter().map(|l| l.id.as_str()).collect();
        assert!(ids.contains(&"trim-prefix"));
        assert!(ids.contains(&"offload-tool-output"));
        assert!(ids.contains(&"compact-between-tasks"));
        assert!(ids.contains(&"context-replay-framing"));
        // tool_use_args at 8% is below the 15% threshold — no edit lever.
        assert!(!ids.contains(&"targeted-edits"));
        // Highest-severity lever sorts first.
        assert_eq!(levers[0].severity, Severity::High);
        // The offload lever names the biggest offender.
        let offload = levers
            .iter()
            .find(|l| l.id == "offload-tool-output")
            .expect("offload lever present");
        assert!(offload.detail.contains("Bash"));
    }

    /// A transcript that writes a fact to `execplan:foo`, edits `bar`'s plan
    /// file, and merely mentions `[[baz-2026-01-01]]` in prose. The fact-write +
    /// edit are picked up (foo strongest, bar strong); the bare mention is weak
    /// and so dropped.
    fn linked_transcript() -> String {
        [
            json!({"type":"user","sessionId":"s","message":{"role":"user",
                "content":"start [[baz-2026-01-01]]"}}),
            json!({"type":"assistant","sessionId":"s","message":{"role":"assistant",
            "usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":100},
            "content":[
              {"type":"tool_use","id":"t1","name":"mcp__crux__store_fact",
               "input":{"entity":"execplan:foo-2026-06-26","key":"gate:M1","value":"x"}},
              {"type":"tool_use","id":"t2","name":"Edit",
               "input":{"file_path":"/x/.agent/execplans/bar-2026-06-26.md","old_string":"a","new_string":"b"}}
            ]}}),
        ]
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
    }

    #[test]
    fn execplan_slugs_extracted_and_ranked_end_to_end() {
        let r = analyze_str(&linked_transcript(), "s.jsonl");
        // Strongest (fact-write) ranks above strong (plan-file edit); the weak
        // `[[baz]]` mention has no other evidence and is dropped.
        assert_eq!(r.execplan_slugs, vec!["foo-2026-06-26", "bar-2026-06-26"]);
    }

    #[test]
    fn plain_transcript_has_no_slugs() {
        // The base fixture touches no plan facts/files.
        let r = analyze_str(&fixture(), "fixture.jsonl");
        assert!(r.execplan_slugs.is_empty());
        let empty = analyze_str("", "empty.jsonl");
        assert!(empty.execplan_slugs.is_empty());
    }

    #[test]
    fn execplan_slugs_skipped_on_wire_when_empty() {
        // Back-compat: a slug-less report omits the field entirely (an old daemon
        // sees a byte-identical shape); a linked report carries it.
        let plain = analyze_str(&fixture(), "fixture.jsonl");
        let plain_json = serde_json::to_string(&plain).expect("serialize");
        assert!(!plain_json.contains("execplan_slugs"));

        let linked = analyze_str(&linked_transcript(), "s.jsonl");
        let linked_json = serde_json::to_string(&linked).expect("serialize");
        assert!(linked_json.contains("execplan_slugs"));
        // Round-trips.
        let back: CostReport = serde_json::from_str(&linked_json).expect("deserialize");
        assert_eq!(back.execplan_slugs, linked.execplan_slugs);
    }
}
