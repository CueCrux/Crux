// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `code_intel` — the agent-facing query layer over static structure + runtime traces.
//!
//! ExecPlan `crux-runtime-codemap-and-agent-query-api-2026-07-27`, milestone M5.
//!
//! This is the milestone the plan exists for. M0–M4 build the substrate; this
//! turns it into answers an agent can afford. Four questions a static graph
//! cannot answer on its own:
//!
//! * [`code_path`] — what *actually executes* for an entry point, in order, with
//!   observed cost. A static call graph is guesswork the moment it meets dynamic
//!   dispatch, trait objects, async or feature flags.
//! * [`blast_radius`] — who depends on a symbol, separating static references
//!   from *observed* runtime callers, and labelling which evidence supports each.
//! * [`liveness`] — did this run, in a stated window? Dead-code with evidence
//!   rather than inference.
//! * [`trace_diff`] — where two traces diverge, for regression localisation.
//!
//! # Token budget is mandatory, not decorative
//!
//! Every entry point takes a `token_budget` and truncates to fit, reporting what
//! it dropped. The point of this API is that an agent asking "what runs when
//! /v1/query/text-search fires" spends a few hundred tokens instead of reading
//! forty files — an answer that blows the context defeats its own purpose.
//!
//! # Every answer states its window
//!
//! "Not executed" is meaningless without "in what period". Absence of evidence
//! over 20 minutes of local traffic is not evidence of absence, and the response
//! shape makes callers confront that rather than letting them read a bare
//! boolean as proof.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::trace_store::StoredSpan;
use crate::workspace_scan::WorkspaceScan;

/// Rough token estimate. Deliberately conservative — over-estimating truncates
/// early, which is a smaller failure than blowing a caller's context.
fn est_tokens(s: &str) -> usize {
    s.len().div_ceil(3)
}

/// Fixed cost of the response envelope, in tokens.
///
/// Measured, not guessed: the `Window` struct alone carries a ~150-character
/// caveat string, and the surrounding JSON keys add more. An earlier version
/// budgeted only the payload and overshot a 500-token budget by 50%, which
/// breaks the one contract this API must honour.
const ENVELOPE_TOKENS: usize = 130;

/// Per-item JSON overhead: braces, quoted keys, separators.
const ITEM_JSON_TOKENS: usize = 18;

/// The observation window a runtime claim rests on.
#[derive(Debug, Clone, Serialize)]
pub struct Window {
    pub spans_examined: usize,
    pub traces_examined: usize,
    pub earliest_unix_ms: Option<u64>,
    pub latest_unix_ms: Option<u64>,
    /// Human-facing caveat, always present so a caller cannot read a runtime
    /// negative as proof of death.
    pub caveat: &'static str,
}

impl Window {
    fn of(spans: &[StoredSpan]) -> Self {
        let traces: BTreeSet<u64> = spans.iter().map(|s| s.span.trace_id).collect();
        Self {
            spans_examined: spans.len(),
            traces_examined: traces.len(),
            earliest_unix_ms: spans.iter().map(|s| s.stored_at_unix_ms).min(),
            latest_unix_ms: spans.iter().map(|s| s.stored_at_unix_ms).max(),
            caveat: "absence of execution in this window is not proof the code is dead; \
                     rare paths need a longer observation period",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PathStep {
    pub depth: u32,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// How many times this step was observed across matching traces.
    pub calls: usize,
    /// Total observed nanoseconds across those calls.
    pub total_ns: u64,
    pub join: String,
    pub had_error: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodePath {
    pub entry_point: String,
    pub matched_traces: usize,
    pub steps: Vec<PathStep>,
    pub truncated: bool,
    pub omitted_steps: usize,
    pub window: Window,
}

/// What actually executes for `entry_point`, ordered by depth then cost.
///
/// `entry_point` matches a span name or a route substring, so both
/// `post_query_text_search` and `/v1/query/text-search` work.
pub fn code_path(spans: &[StoredSpan], entry_point: &str, token_budget: usize) -> CodePath {
    let needle = entry_point.trim().to_ascii_lowercase();

    // A trace matches if ANY span in it names the entry point; then the whole
    // trace is in scope, because the interesting part is what the entry point
    // *called*, not the entry span itself.
    let matching: BTreeSet<u64> = spans
        .iter()
        .filter(|s| s.span.name.to_ascii_lowercase().contains(&needle))
        .map(|s| s.span.trace_id)
        .collect();

    let in_scope: Vec<&StoredSpan> = spans.iter().filter(|s| matching.contains(&s.span.trace_id)).collect();

    // Fold repeated executions of the same symbol into one step with counts.
    let mut agg: BTreeMap<(u32, String), PathStep> = BTreeMap::new();
    for s in &in_scope {
        let key = (s.span.depth, s.span.name.clone());
        let e = agg.entry(key).or_insert_with(|| PathStep {
            depth: s.span.depth,
            name: s.span.name.clone(),
            symbol_id: s.symbol_id.clone(),
            file: s.span.file.clone(),
            line: s.span.line,
            calls: 0,
            total_ns: 0,
            join: s.join.clone(),
            had_error: false,
        });
        e.calls += 1;
        e.total_ns = e.total_ns.saturating_add(s.span.duration_ns);
        e.had_error |= s.span.had_error;
    }

    let mut steps: Vec<PathStep> = agg.into_values().collect();
    // Depth first (execution order), then cost — so truncation drops the
    // cheapest leaves rather than the shape of the path.
    steps.sort_by(|a, b| a.depth.cmp(&b.depth).then(b.total_ns.cmp(&a.total_ns)));

    let total = steps.len();
    let mut kept = Vec::new();
    let mut used = est_tokens(entry_point) + ENVELOPE_TOKENS;
    for step in steps {
        let cost = est_tokens(&step.name) + est_tokens(step.file.as_deref().unwrap_or("")) + ITEM_JSON_TOKENS + 24;
        if used + cost > token_budget && !kept.is_empty() {
            break;
        }
        used += cost;
        kept.push(step);
    }
    let omitted = total - kept.len();

    CodePath {
        entry_point: entry_point.to_string(),
        matched_traces: matching.len(),
        steps: kept,
        truncated: omitted > 0,
        omitted_steps: omitted,
        window: Window::of(spans),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Dependent {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// `static` (referenced in source), `runtime` (observed calling it), or
    /// `both` — the strongest signal.
    pub evidence: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlastRadius {
    pub symbol: String,
    pub static_dependents: usize,
    pub runtime_callers: usize,
    pub dependents: Vec<Dependent>,
    pub truncated: bool,
    pub omitted: usize,
    pub window: Window,
}

/// Who breaks if `symbol` changes — static references union observed callers,
/// each labelled by the evidence that supports it.
pub fn blast_radius(scan: &WorkspaceScan, spans: &[StoredSpan], symbol: &str, token_budget: usize) -> BlastRadius {
    // Static side: exact `to_symbol` matches from the AST reference graph. Where
    // the scanner resolved the enclosing fn (`from_symbol`) we name that;
    // otherwise we fall back to the file, which is still actionable.
    let mut static_refs: BTreeMap<String, String> = BTreeMap::new();
    for f in &scan.files {
        for r in f.references.iter().filter(|r| r.to_symbol == symbol) {
            let who = r.from_symbol.clone().unwrap_or_else(|| f.rel_path.clone());
            static_refs.insert(who, f.rel_path.clone());
        }
    }

    // Runtime side: the parent span of any span named `symbol`.
    let by_id: BTreeMap<u64, &StoredSpan> = spans.iter().map(|s| (s.span.span_id, s)).collect();
    let mut runtime_callers: BTreeSet<String> = BTreeSet::new();
    for s in spans.iter().filter(|s| s.span.name == symbol) {
        if let Some(parent) = s.span.parent_span_id.and_then(|p| by_id.get(&p)) {
            runtime_callers.insert(parent.span.name.clone());
        }
    }

    let mut dependents: Vec<Dependent> = Vec::new();
    for caller in &runtime_callers {
        dependents.push(Dependent {
            name: caller.clone(),
            file: static_refs.get(caller).cloned(),
            // "both" is the strongest evidence: the source references it AND we
            // watched it happen.
            evidence: if static_refs.contains_key(caller) {
                "both"
            } else {
                "runtime"
            },
        });
    }
    for (who, file) in &static_refs {
        if runtime_callers.contains(who) {
            continue; // already emitted as "both"
        }
        dependents.push(Dependent {
            name: who.clone(),
            file: Some(file.clone()),
            evidence: "static",
        });
    }

    // Runtime evidence first: an observed caller is a stronger signal than a
    // textual reference, so truncation should keep it.
    dependents.sort_by_key(|d| match d.evidence {
        "both" => 0,
        "runtime" => 1,
        _ => 2,
    });

    let total = dependents.len();
    let mut used = est_tokens(symbol) + ENVELOPE_TOKENS;
    let mut kept = Vec::new();
    for d in dependents {
        let cost = est_tokens(&d.name) + est_tokens(d.file.as_deref().unwrap_or("")) + ITEM_JSON_TOKENS;
        if used + cost > token_budget && !kept.is_empty() {
            break;
        }
        used += cost;
        kept.push(d);
    }
    let omitted = total - kept.len();

    BlastRadius {
        symbol: symbol.to_string(),
        static_dependents: static_refs.len(),
        runtime_callers: runtime_callers.len(),
        dependents: kept,
        truncated: omitted > 0,
        omitted,
        window: Window::of(spans),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Liveness {
    pub symbol: String,
    /// Observed executing in the window. `false` means "not seen", never "dead".
    pub executed: bool,
    pub executions: usize,
    pub total_ns: u64,
    /// Present in the static graph at all.
    pub exists_statically: bool,
    /// Flagged dead by the AST reachability tier.
    pub flagged_dead_static: bool,
    /// The joined verdict, spelled out so a caller does not have to infer it.
    pub verdict: &'static str,
    pub window: Window,
}

/// Did this symbol run? The dead-code answer with runtime evidence.
pub fn liveness(scan: &WorkspaceScan, spans: &[StoredSpan], symbol: &str) -> Liveness {
    let executions: Vec<&StoredSpan> = spans.iter().filter(|s| s.span.name == symbol).collect();
    let exists = scan.symbols.iter().any(|s| s.name == symbol);
    let flagged_dead = scan.dead_code.iter().any(|d| d.name == symbol);
    let executed = !executions.is_empty();

    // The cross-product that no single tier can produce.
    let verdict = match (exists, flagged_dead, executed) {
        (false, _, _) => "unknown_symbol",
        (true, true, true) => "static_dead_but_executed__extractor_false_positive",
        (true, true, false) => "dead_candidate__static_and_runtime_agree",
        (true, false, true) => "live",
        (true, false, false) => "reachable_but_unobserved__widen_the_window",
    };

    Liveness {
        symbol: symbol.to_string(),
        executed,
        executions: executions.len(),
        total_ns: executions.iter().map(|s| s.span.duration_ns).sum(),
        exists_statically: exists,
        flagged_dead_static: flagged_dead,
        verdict,
        window: Window::of(spans),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceDiff {
    pub trace_a: u64,
    pub trace_b: u64,
    /// First step present in one and not the other, in execution order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_divergence: Option<String>,
    pub only_in_a: Vec<String>,
    pub only_in_b: Vec<String>,
    /// Steps in both, where b took materially longer (>2x and >1ms).
    pub slower_in_b: Vec<String>,
    pub truncated: bool,
}

/// Where two traces diverge — regression localisation.
pub fn trace_diff(spans: &[StoredSpan], a: u64, b: u64, token_budget: usize) -> TraceDiff {
    let seq = |t: u64| -> Vec<(u32, String, u64)> {
        let mut v: Vec<(u32, String, u64)> = spans
            .iter()
            .filter(|s| s.span.trace_id == t)
            .map(|s| (s.span.depth, s.span.name.clone(), s.span.duration_ns))
            .collect();
        v.sort();
        v
    };
    let (sa, sb) = (seq(a), seq(b));
    let names_a: BTreeSet<&String> = sa.iter().map(|(_, n, _)| n).collect();
    let names_b: BTreeSet<&String> = sb.iter().map(|(_, n, _)| n).collect();

    let only_a: Vec<String> = names_a.difference(&names_b).map(|s| (*s).clone()).collect();
    let only_b: Vec<String> = names_b.difference(&names_a).map(|s| (*s).clone()).collect();

    // Walk in execution order so the first divergence is the earliest one,
    // which is where a regression usually starts.
    let first = sa
        .iter()
        .find(|(_, n, _)| !names_b.contains(n))
        .or_else(|| sb.iter().find(|(_, n, _)| !names_a.contains(n)))
        .map(|(_, n, _)| n.clone());

    let dur_a: BTreeMap<&String, u64> = sa.iter().map(|(_, n, d)| (n, *d)).collect();
    let slower: Vec<String> = sb
        .iter()
        .filter(|(_, n, d)| {
            dur_a
                .get(n)
                .is_some_and(|&da| *d > da.saturating_mul(2) && d.saturating_sub(da) > 1_000_000)
        })
        .map(|(_, n, _)| n.clone())
        .collect();

    let budget_items = token_budget / 12;
    let truncated = only_a.len() + only_b.len() + slower.len() > budget_items;

    TraceDiff {
        trace_a: a,
        trace_b: b,
        first_divergence: first,
        only_in_a: only_a.into_iter().take(budget_items).collect(),
        only_in_b: only_b.into_iter().take(budget_items).collect(),
        slower_in_b: slower.into_iter().take(budget_items).collect(),
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_scan::{DeadSymbol, SymbolInfo};
    use crux_observe::span_layer::SpanRecord;

    fn stored(trace: u64, id: u64, parent: Option<u64>, depth: u32, name: &str, ns: u64) -> StoredSpan {
        StoredSpan {
            span: SpanRecord {
                trace_id: trace,
                span_id: id,
                parent_span_id: parent,
                name: name.into(),
                target: "t".into(),
                file: Some("a.rs".into()),
                line: Some(10),
                module_path: None,
                duration_ns: ns,
                depth,
                had_error: false,
            },
            symbol_id: Some(format!("sym_{name}")),
            join: "extracted".into(),
            stored_at_unix_ms: 1_000 + id,
        }
    }

    fn scan_with(symbols: Vec<&str>, dead: Vec<&str>) -> WorkspaceScan {
        WorkspaceScan {
            symbols: symbols
                .into_iter()
                .map(|n| SymbolInfo {
                    crate_name: "c".into(),
                    module_path: "c".into(),
                    file_rel_path: "a.rs".into(),
                    line: 10,
                    kind: "fn".into(),
                    name: n.into(),
                    is_pub: true,
                })
                .collect(),
            dead_code: dead
                .into_iter()
                .map(|n| DeadSymbol {
                    crate_name: "c".into(),
                    module_path: "c".into(),
                    file_rel_path: "a.rs".into(),
                    line: 10,
                    kind: "fn".into(),
                    name: n.into(),
                    confidence: 0.75,
                    note: "n".into(),
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn code_path_returns_whole_trace_in_execution_order() {
        let spans = vec![
            stored(1, 1, None, 0, "http_request", 900),
            stored(1, 2, Some(1), 1, "handler", 800),
            stored(1, 3, Some(2), 2, "storage_read", 500),
        ];
        let p = code_path(&spans, "handler", 4000);
        assert_eq!(p.matched_traces, 1);
        // The whole trace is in scope, not just the named span: the useful
        // answer is what the entry point *called*.
        assert_eq!(p.steps.len(), 3);
        assert_eq!(p.steps[0].depth, 0);
        assert_eq!(p.steps[2].name, "storage_read");
        assert!(!p.truncated);
    }

    #[test]
    fn code_path_folds_repeats_into_call_counts() {
        let spans = vec![
            stored(1, 1, None, 0, "root", 900),
            stored(1, 2, Some(1), 1, "shard_read", 100),
            stored(1, 3, Some(1), 1, "shard_read", 150),
            stored(1, 4, Some(1), 1, "shard_read", 50),
        ];
        let p = code_path(&spans, "root", 4000);
        let s = p.steps.iter().find(|s| s.name == "shard_read").unwrap();
        assert_eq!(s.calls, 3, "repeats fold rather than flooding the answer");
        assert_eq!(s.total_ns, 300);
    }

    /// The budget is a contract, not a hint: the serialised response must
    /// actually fit. An earlier estimator counted only payload strings and
    /// overshot a 500-token budget by 50% on real data.
    #[test]
    fn serialised_response_actually_fits_the_budget() {
        let scan = scan_with(vec!["target"], vec![]);
        let mut spans = vec![stored(1, 1, None, 0, "caller", 100)];
        for i in 0..300u64 {
            spans.push(stored(1, i + 2, Some(1), 1, "target", 10));
        }
        for budget in [200usize, 500, 2000] {
            let b = blast_radius(&scan, &spans, "target", budget);
            let bytes = serde_json::to_string(&b).unwrap().len();
            assert!(
                bytes / 3 <= budget,
                "blast_radius overshot: budget {budget}, got ~{} tokens ({bytes} bytes)",
                bytes / 3
            );
            let p = code_path(&spans, "caller", budget);
            let bytes = serde_json::to_string(&p).unwrap().len();
            assert!(
                bytes / 3 <= budget,
                "code_path overshot: budget {budget}, got ~{} tokens ({bytes} bytes)",
                bytes / 3
            );
        }
    }

    #[test]
    fn code_path_respects_token_budget_and_says_what_it_dropped() {
        let mut spans = vec![stored(1, 1, None, 0, "root", 900)];
        for i in 0..200u64 {
            spans.push(stored(1, i + 2, Some(1), 1, &format!("callee_{i}"), 10));
        }
        let tight = code_path(&spans, "root", 200);
        assert!(tight.truncated);
        assert!(tight.omitted_steps > 0);
        assert!(!tight.steps.is_empty(), "always returns something");
        let wide = code_path(&spans, "root", 100_000);
        assert!(!wide.truncated);
        assert!(wide.steps.len() > tight.steps.len());
    }

    #[test]
    fn liveness_names_the_extractor_false_positive_cell() {
        let scan = scan_with(vec!["ghost", "runner"], vec!["ghost", "runner"]);
        let spans = vec![stored(1, 1, None, 0, "runner", 10)];

        // Flagged dead statically but observed running: the calibration signal.
        let live = liveness(&scan, &spans, "runner");
        assert_eq!(live.verdict, "static_dead_but_executed__extractor_false_positive");
        assert!(live.executed);

        // Flagged dead and never seen: both tiers agree.
        let dead = liveness(&scan, &spans, "ghost");
        assert_eq!(dead.verdict, "dead_candidate__static_and_runtime_agree");
        assert!(!dead.executed);
    }

    #[test]
    fn liveness_distinguishes_unobserved_from_dead() {
        let scan = scan_with(vec!["rare"], vec![]);
        let l = liveness(&scan, &[], "rare");
        assert_eq!(l.verdict, "reachable_but_unobserved__widen_the_window");
        assert!(!l.executed, "not seen");
        // The caveat must travel with the answer.
        assert!(l.window.caveat.contains("not proof"));
    }

    #[test]
    fn liveness_flags_unknown_symbols_rather_than_calling_them_dead() {
        let scan = scan_with(vec!["a"], vec![]);
        assert_eq!(liveness(&scan, &[], "nope").verdict, "unknown_symbol");
    }

    #[test]
    fn blast_radius_separates_runtime_callers_from_static_refs() {
        let scan = scan_with(vec!["target"], vec![]);
        let spans = vec![
            stored(1, 1, None, 0, "caller_one", 100),
            stored(1, 2, Some(1), 1, "target", 50),
        ];
        let b = blast_radius(&scan, &spans, "target", 4000);
        assert_eq!(b.runtime_callers, 1);
        assert!(b
            .dependents
            .iter()
            .any(|d| d.name == "caller_one" && d.evidence == "runtime"));
    }

    #[test]
    fn trace_diff_finds_the_first_divergence() {
        let spans = vec![
            stored(1, 1, None, 0, "root", 100),
            stored(1, 2, Some(1), 1, "cache_hit", 10),
            stored(2, 3, None, 0, "root", 100),
            stored(2, 4, Some(3), 1, "cache_miss", 900),
        ];
        let d = trace_diff(&spans, 1, 2, 2000);
        assert_eq!(d.first_divergence.as_deref(), Some("cache_hit"));
        assert_eq!(d.only_in_a, vec!["cache_hit"]);
        assert_eq!(d.only_in_b, vec!["cache_miss"]);
    }

    #[test]
    fn trace_diff_flags_materially_slower_steps() {
        let spans = vec![
            stored(1, 1, None, 0, "root", 1_000_000),
            stored(2, 2, None, 0, "root", 50_000_000),
        ];
        let d = trace_diff(&spans, 1, 2, 2000);
        assert_eq!(d.slower_in_b, vec!["root"]);
        // Same shape, so no structural divergence.
        assert!(d.only_in_a.is_empty() && d.only_in_b.is_empty());
    }

    #[test]
    fn spatial_layout_is_stable_across_rescans() {
        use crate::workspace_scan::FileInfo;
        let mk = |p: &str, c: &str, loc: usize| FileInfo {
            rel_path: p.into(),
            crate_name: c.into(),
            module_path: "m".into(),
            loc,
            symbol_count: 5,
            stub_count: 0,
            doc_summary: None,
            doc_full: None,
            defines: vec![],
            references: vec![],
            referenced_by: vec![],
            is_test_file: false,
        };
        let a = WorkspaceScan {
            files: vec![mk("a.rs", "one", 100), mk("b.rs", "two", 50), mk("c.rs", "one", 80)],
            ..Default::default()
        };
        // Same tree, different emission order: layout must not move.
        let b = WorkspaceScan {
            files: vec![mk("c.rs", "one", 80), mk("b.rs", "two", 50), mk("a.rs", "one", 100)],
            ..Default::default()
        };
        let ma = spatial_map(&a, &[]);
        let mb = spatial_map(&b, &[]);
        assert_eq!(
            ma.layout_digest, mb.layout_digest,
            "a map that reshuffles between sessions destroys spatial memory"
        );
        let pos = |m: &SpatialMap, f: &str| m.buildings.iter().find(|b| b.file == f).map(|b| (b.x, b.z)).unwrap();
        assert_eq!(pos(&ma, "a.rs"), pos(&mb, "a.rs"));
        assert_eq!(pos(&ma, "c.rs"), pos(&mb, "c.rs"));
    }

    #[test]
    fn spiral_slots_are_unique() {
        // Overlapping districts would stack crates on top of each other.
        let seen: BTreeSet<(i64, i64)> = (0..60).map(spiral_slot).collect();
        assert_eq!(seen.len(), 60, "every district needs its own slot");
    }

    #[test]
    fn ladder_never_marks_a_single_signal_actionable() {
        let scan = scan_with(vec!["ghost"], vec!["ghost"]);
        // Empty runtime window: the static tier is alone, so nothing is
        // actionable no matter how confident that tier is.
        let l = dead_code_ladder(&scan, &[], 100_000);
        assert_eq!(l.verdicts.len(), 1);
        let v = &l.verdicts[0];
        assert_eq!(v.verdict, "dead_candidate__static_only");
        assert!(v.single_signal);
        assert!(!v.actionable, "a lone tier must never authorise deletion");
    }

    #[test]
    fn ladder_promotes_to_actionable_only_on_two_agreeing_tiers() {
        let scan = scan_with(vec!["ghost", "other"], vec!["ghost"]);
        // Non-empty window that never saw `ghost`: static + runtime agree.
        let spans = vec![stored(1, 1, None, 0, "other", 10)];
        let l = dead_code_ladder(&scan, &spans, 100_000);
        let v = l.verdicts.iter().find(|v| v.symbol == "ghost").unwrap();
        assert_eq!(v.verdict, "dead_candidate__static_and_runtime_agree");
        assert_eq!(v.agreeing_tiers, 2);
        assert!(!v.single_signal);
        assert!(v.actionable);
    }

    #[test]
    fn ladder_surfaces_extractor_false_positives_as_a_calibration_corpus() {
        let scan = scan_with(vec!["runner"], vec!["runner"]);
        let spans = vec![stored(1, 1, None, 0, "runner", 10)];
        let l = dead_code_ladder(&scan, &spans, 100_000);
        let v = &l.verdicts[0];
        assert_eq!(v.verdict, "extractor_false_positive__static_dead_but_executed");
        assert!(!v.actionable, "a false positive must never be actionable-for-deletion");
        assert_eq!(l.extractor_false_positives, vec!["runner"]);
        // Both tiers spoke, and they disagreed — that disagreement IS the value.
        assert_eq!(v.evidence.len(), 2);
        assert!(v
            .evidence
            .iter()
            .any(|e| e.tier == "runtime_execution" && e.says == "alive"));
    }

    #[test]
    fn ladder_finding_ids_match_code_health_so_verdicts_supersede() {
        let scan = scan_with(vec!["ghost"], vec!["ghost"]);
        let l = dead_code_ladder(&scan, &[], 100_000);
        assert_eq!(l.verdicts[0].finding_id, "dead:a.rs:10");
    }

    #[test]
    fn ladder_respects_its_token_budget() {
        let names: Vec<String> = (0..300).map(|i| format!("dead_{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let scan = scan_with(refs.clone(), refs);
        for budget in [300usize, 1000, 5000] {
            let l = dead_code_ladder(&scan, &[], budget);
            let bytes = serde_json::to_string(&l.verdicts).unwrap().len();
            // Either it fits, or it says plainly that it could not. One verdict
            // carries several evidence strings and can exceed a small budget on
            // its own; answering with nothing would be worse than answering with
            // one and flagging it.
            assert!(
                bytes / 3 <= budget || l.budget_exceeded,
                "ladder overshot budget {budget} (~{} tokens) WITHOUT setting budget_exceeded",
                bytes / 3
            );
            if l.budget_exceeded {
                assert_eq!(l.verdicts.len(), 1, "an over-budget answer returns exactly one verdict");
            }
        }
    }

    #[test]
    fn trace_diff_ignores_sub_millisecond_noise() {
        let spans = vec![stored(1, 1, None, 0, "root", 100), stored(2, 2, None, 0, "root", 900)];
        // 9x slower but under 1ms absolute: noise, not a regression.
        assert!(trace_diff(&spans, 1, 2, 2000).slower_in_b.is_empty());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// M6 — the dead-code evidence ladder.
//
// Crux already ran six dead-code tiers before this plan and cross-referenced
// none of them. Each has a documented blind spot: the compiler lint is blind to
// `pub`, AST reachability to trait/macro dispatch, coverage to production,
// mutation testing to whether the code matters, and runtime to rare paths.
//
// The value is the cross-product, not any single tier. Measured on this
// workspace (M0 baseline), a 12-symbol sample of tier 5's 224 findings split
// three ways despite all carrying an identical 0.75 confidence: truly
// unreferenced, production-used false positives, and test-only code.
// ─────────────────────────────────────────────────────────────────────────────

/// One tier's opinion about a symbol.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TierEvidence {
    /// `ast_reachability`, `runtime_execution`, `binary_presence`, …
    pub tier: &'static str,
    /// What this tier says: `dead`, `alive`, or `unknown`.
    pub says: &'static str,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolVerdict {
    pub symbol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    pub verdict: &'static str,
    /// Every tier that had an opinion, so a reader can check the reasoning.
    pub evidence: Vec<TierEvidence>,
    /// Independent tiers that agree with the verdict direction.
    pub agreeing_tiers: usize,
    /// True when only one tier had an opinion. A deletion must never rest on
    /// this without a human looking.
    pub single_signal: bool,
    /// Set when the verdict is safe to act on: two or more independent tiers
    /// agree AND the runtime window was non-empty.
    pub actionable: bool,
    /// Stable id matching `corecruxctl code-health`'s `dead:<file>:<line>`, so
    /// verdicts supersede those findings rather than duplicating them.
    pub finding_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeadCodeLadder {
    pub verdicts: Vec<SymbolVerdict>,
    pub counts: BTreeMap<String, usize>,
    /// Symbols flagged dead by AST but observed executing — the calibration
    /// corpus for the extractor, not merely a defect list.
    pub extractor_false_positives: Vec<String>,
    pub window: Window,
    pub truncated: bool,
    pub omitted: usize,
    /// Set when even a single verdict could not fit the requested budget.
    ///
    /// One verdict carries several evidence strings and can exceed a small
    /// budget on its own. Returning an empty answer would be useless, so we
    /// return one and say so — the contract is "never silently overshoot",
    /// not "never exceed".
    pub budget_exceeded: bool,
}

/// Build the ladder over every symbol the AST tier flagged dead, plus any
/// symbol observed at runtime (so false positives surface even when the static
/// tier is silent).
pub fn dead_code_ladder(scan: &WorkspaceScan, spans: &[StoredSpan], token_budget: usize) -> DeadCodeLadder {
    let executed: BTreeMap<&str, usize> = spans.iter().fold(BTreeMap::new(), |mut m, s| {
        *m.entry(s.span.name.as_str()).or_insert(0) += 1;
        m
    });
    let runtime_window_empty = spans.is_empty();

    let mut verdicts = Vec::new();
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut false_positives = Vec::new();

    for d in &scan.dead_code {
        let runs = executed.get(d.name.as_str()).copied().unwrap_or(0);
        let mut evidence = vec![TierEvidence {
            tier: "ast_reachability",
            says: "dead",
            detail: format!("{} (confidence {})", d.note, d.confidence),
        }];

        // The runtime tier only gets an opinion when it actually observed
        // something. Silence in an empty window is not evidence.
        if runs > 0 {
            evidence.push(TierEvidence {
                tier: "runtime_execution",
                says: "alive",
                detail: format!("observed executing {runs}x in the window"),
            });
        } else if !runtime_window_empty {
            evidence.push(TierEvidence {
                tier: "runtime_execution",
                says: "dead",
                detail: "not observed in the window".to_string(),
            });
        }

        let (verdict, agreeing) = if runs > 0 {
            false_positives.push(d.name.clone());
            ("extractor_false_positive__static_dead_but_executed", 1)
        } else if runtime_window_empty {
            ("dead_candidate__static_only", 1)
        } else {
            ("dead_candidate__static_and_runtime_agree", 2)
        };

        let single = evidence.len() < 2;
        *counts.entry(verdict.to_string()).or_insert(0) += 1;
        verdicts.push(SymbolVerdict {
            symbol: d.name.clone(),
            file: Some(d.file_rel_path.clone()),
            line: Some(d.line),
            verdict,
            evidence,
            agreeing_tiers: agreeing,
            single_signal: single,
            // Only a two-tier agreement over a non-empty window is safe to act
            // on. Everything else is a lead, not a licence to delete.
            actionable: agreeing >= 2 && !runtime_window_empty && runs == 0,
            finding_id: format!("dead:{}:{}", d.file_rel_path, d.line),
        });
    }

    // Rank so the most decision-ready entries survive truncation, and the
    // calibration signal (false positives) is never buried.
    verdicts.sort_by_key(|v| match v.verdict {
        "extractor_false_positive__static_dead_but_executed" => 0,
        "dead_candidate__static_and_runtime_agree" => 1,
        _ => 2,
    });

    let total = verdicts.len();
    let mut used = ENVELOPE_TOKENS;
    let mut kept = Vec::new();
    let mut budget_exceeded = false;
    for v in verdicts {
        // Measure the real serialised size rather than estimating from field
        // lengths. A verdict carries a long verdict string, a finding_id and a
        // nested evidence array, and every hand-rolled estimate of that
        // undercounted — this is exact by construction.
        let cost = serde_json::to_string(&v).map_or(ITEM_JSON_TOKENS, |j| est_tokens(&j));
        if used + cost > token_budget {
            if kept.is_empty() {
                // Cannot satisfy the budget at all; return one and flag it
                // rather than answering with nothing.
                budget_exceeded = true;
                kept.push(v);
            }
            break;
        }
        used += cost;
        kept.push(v);
    }
    let omitted = total - kept.len();

    DeadCodeLadder {
        verdicts: kept,
        counts,
        extractor_false_positives: false_positives,
        window: Window::of(spans),
        truncated: omitted > 0,
        omitted,
        budget_exceeded,
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// M8 — the spatial seam.
//
// Coordinates only; no renderer. The eventual 3D map (files as buildings,
// symbols as interior machines, traces as animated pipes) is a successor plan.
// What it needs from the daemon is a layout that is STABLE: computed in Rust
// once, identical across rescans of an unchanged tree, and changing only where
// the code changed. Force-directed layout over 22k nodes in a browser is a
// non-starter, and a map that reshuffles between sessions destroys the spatial
// memory that is most of the human value.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Building {
    pub file: String,
    pub crate_name: String,
    /// District (crate) this building sits in.
    pub district: String,
    pub x: i64,
    pub z: i64,
    /// Footprint side length, derived from LOC.
    pub footprint: u32,
    /// Storeys, derived from symbol count — the "machines inside".
    pub storeys: u32,
    pub loc: usize,
    pub symbols: usize,
    /// Observed executions across the window, for heat.
    pub executions: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct District {
    pub name: String,
    pub x: i64,
    pub z: i64,
    pub buildings: usize,
    pub loc: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpatialMap {
    pub districts: Vec<District>,
    pub buildings: Vec<Building>,
    /// District-to-district edge bundles. Individual file edges are deliberately
    /// not emitted: a 22k-file graph has >100k of them and renders as grey fur.
    pub bundles: Vec<(String, String, usize)>,
    /// Deterministic digest of the layout inputs. Two scans of an unchanged tree
    /// produce the same value — the stability contract, checkable by a client.
    pub layout_digest: String,
}

/// Deterministic spatial layout. No randomness, no iteration order dependence.
///
/// Districts are placed on a spiral by descending size so the biggest crates sit
/// near the origin; buildings fill a row-major grid within their district. Both
/// orderings are derived from sorted keys, never from hash iteration, which is
/// what makes the result reproducible.
pub fn spatial_map(scan: &WorkspaceScan, spans: &[StoredSpan]) -> SpatialMap {
    let executions: BTreeMap<&str, usize> = spans.iter().fold(BTreeMap::new(), |mut m, s| {
        if let Some(f) = s.span.file.as_deref() {
            *m.entry(f).or_insert(0) += 1;
        }
        m
    });

    // Group files by crate, in a deterministic order.
    let mut by_crate: BTreeMap<String, Vec<&crate::workspace_scan::FileInfo>> = BTreeMap::new();
    for f in &scan.files {
        by_crate.entry(f.crate_name.clone()).or_default().push(f);
    }

    // Districts ordered by LOC descending, then name — so ties break stably.
    let mut order: Vec<(String, usize)> = by_crate
        .iter()
        .map(|(name, files)| (name.clone(), files.iter().map(|f| f.loc).sum()))
        .collect();
    order.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    const DISTRICT_PITCH: i64 = 220;
    const BUILDING_PITCH: i64 = 26;

    let mut districts = Vec::new();
    let mut buildings = Vec::new();

    for (i, (crate_name, loc)) in order.iter().enumerate() {
        // Square spiral: ring r holds the next 8r slots.
        let (dx, dz) = spiral_slot(i);
        let (cx, cz) = (dx * DISTRICT_PITCH, dz * DISTRICT_PITCH);

        let mut files = by_crate.get(crate_name).cloned().unwrap_or_default();
        files.sort_by(|a, b| b.loc.cmp(&a.loc).then(a.rel_path.cmp(&b.rel_path)));

        let side = (files.len() as f64).sqrt().ceil().max(1.0) as i64;
        for (j, f) in files.iter().enumerate() {
            let j = j as i64;
            let (gx, gz) = (j % side, j / side);
            buildings.push(Building {
                file: f.rel_path.clone(),
                crate_name: f.crate_name.clone(),
                district: crate_name.clone(),
                x: cx + (gx - side / 2) * BUILDING_PITCH,
                z: cz + (gz - side / 2) * BUILDING_PITCH,
                // LOC -> footprint, damped so a 5k-line file does not dwarf the
                // district; symbols -> storeys, the "machines inside".
                footprint: ((f.loc as f64).sqrt().max(2.0) as u32).min(40),
                storeys: (f.symbol_count as u32).clamp(1, 60),
                loc: f.loc,
                symbols: f.symbol_count,
                executions: executions.get(f.rel_path.as_str()).copied().unwrap_or(0),
            });
        }

        districts.push(District {
            name: crate_name.clone(),
            x: cx,
            z: cz,
            buildings: files.len(),
            loc: *loc,
        });
    }

    // Aggregate file-level dependencies into district bundles.
    let crate_of: BTreeMap<&str, &str> = scan
        .files
        .iter()
        .map(|f| (f.rel_path.as_str(), f.crate_name.as_str()))
        .collect();
    let mut bundle_counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    for f in &scan.files {
        for r in &f.references {
            if let Some(to_crate) = crate_of.get(r.to_file.as_str()) {
                if *to_crate != f.crate_name {
                    *bundle_counts
                        .entry((f.crate_name.clone(), (*to_crate).to_string()))
                        .or_insert(0) += r.call_count.max(1);
                }
            }
        }
    }
    let bundles: Vec<(String, String, usize)> = bundle_counts.into_iter().map(|((a, b), n)| (a, b, n)).collect();

    // Digest the layout inputs, not the output: a client can detect "the map
    // moved" without diffing coordinates.
    let mut hasher = blake3::Hasher::new();
    for b in &buildings {
        hasher.update(b.file.as_bytes());
        hasher.update(&b.x.to_le_bytes());
        hasher.update(&b.z.to_le_bytes());
        hasher.update(&b.footprint.to_le_bytes());
        hasher.update(&b.storeys.to_le_bytes());
    }

    SpatialMap {
        districts,
        buildings,
        bundles,
        layout_digest: hasher.finalize().to_hex()[..16].to_string(),
    }
}

/// Square-spiral slot `i` -> grid coordinates, walking outward from the origin.
fn spiral_slot(i: usize) -> (i64, i64) {
    if i == 0 {
        return (0, 0);
    }
    let mut ring = 1i64;
    let mut start = 1usize;
    loop {
        let count = (8 * ring) as usize;
        if i < start + count {
            let offset = (i - start) as i64;
            let side_len = 2 * ring;
            let (x, z) = match offset / side_len {
                0 => (-ring + offset % side_len, -ring),
                1 => (ring, -ring + offset % side_len),
                2 => (ring - offset % side_len, ring),
                _ => (-ring, ring - offset % side_len),
            };
            return (x, z);
        }
        start += count;
        ring += 1;
    }
}
