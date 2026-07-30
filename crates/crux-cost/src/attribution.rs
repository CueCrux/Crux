// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Carried-context attribution.
//!
//! The model (ported from the `tokenburn` Python harness): within a compaction
//! segment of `k` assistant turns, a content block that becomes visible at turn
//! `e` is re-read by every later turn, i.e. `k − e` times. Its *carried cost* is
//! `est_tokens × (k − e)`. Compaction boundaries reset the segment (the prior
//! blocks fall out of the live window).
//!
//! The buckets reconcile **exactly** against the measured context total: the
//! `session_prefix` bucket is the remainder `measured_context_total −
//! Σ(attributed)`, which captures the fixed overhead (system prompt + tool
//! schemas + CLAUDE.md/MEMORY.md) that is not represented as transcript content.

use std::collections::HashMap;

use crate::levers;
use crate::report::{BlockCost, Bucket, CostReport, Headline, Measured, COST_REPORT_SCHEMA};
use crate::transcript::{Event, EventKind, ExecPlanSignal, SignalStrength};
use crate::{MAX_EXECPLAN_SLUGS, TOP_BLOCKS};

/// A block parked in the current segment, awaiting flush (when `k` is known).
struct Pending {
    source: String,
    tool: Option<String>,
    est: u64,
    entry_turn: u64,
    preview: String,
}

/// Build a [`CostReport`] from parsed transcript events. The `source` field is
/// left empty for the caller to fill with the transcript file name.
#[must_use]
pub fn analyze(events: &[Event]) -> CostReport {
    let mut measured = Measured::default();
    let mut measured_context_total: u64 = 0;
    let mut assistant_turns: u64 = 0;
    let mut tasks: u64 = 0;
    let mut segments: u64 = 0;
    let mut fine_buckets: HashMap<String, u64> = HashMap::new();
    let mut all_blocks: Vec<BlockCost> = Vec::new();
    let mut session_id = String::new();
    // Session active window: lexical min/max over the records' RFC3339 `Z`
    // timestamps (fixed-width UTC strings sort chronologically). Every record —
    // turns and meta alike — contributes, so the window spans the whole
    // transcript. The daemon overlaps this against each ExecPlan's fact window.
    let mut started_at: Option<&str> = None;
    let mut ended_at: Option<&str> = None;

    let mut seg: Vec<Pending> = Vec::new();
    let mut seg_turn: u64 = 0;

    for ev in events {
        if session_id.is_empty() {
            if let Some(sid) = ev.session_id.as_deref() {
                if !sid.is_empty() {
                    sid.clone_into(&mut session_id);
                }
            }
        }
        if let Some(ts) = ev.timestamp.as_deref() {
            if started_at.is_none_or(|s| ts < s) {
                started_at = Some(ts);
            }
            if ended_at.is_none_or(|e| ts > e) {
                ended_at = Some(ts);
            }
        }
        if let Some(u) = ev.usage {
            measured.input = measured.input.saturating_add(u.input);
            measured.output = measured.output.saturating_add(u.output);
            measured.cache_read = measured.cache_read.saturating_add(u.cache_read);
            measured.cache_creation = measured.cache_creation.saturating_add(u.cache_creation);
            measured_context_total = measured_context_total.saturating_add(u.context_read());
        }

        match ev.kind {
            EventKind::Compaction => {
                flush_segment(
                    &mut seg,
                    &mut seg_turn,
                    &mut segments,
                    &mut fine_buckets,
                    &mut all_blocks,
                );
            }
            EventKind::Assistant => {
                assistant_turns += 1;
                seg_turn += 1;
                park_blocks(ev, seg_turn, &mut seg);
            }
            EventKind::User => {
                if ev.blocks.iter().any(|b| b.source == "user_prompt") {
                    tasks += 1;
                }
                // User-turn content is visible from the current assistant-turn
                // count onward (it is re-read by every subsequent model call).
                park_blocks(ev, seg_turn, &mut seg);
            }
            EventKind::Meta => {}
        }
    }
    flush_segment(
        &mut seg,
        &mut seg_turn,
        &mut segments,
        &mut fine_buckets,
        &mut all_blocks,
    );

    // Coarsen (tool_result:Bash → tool_result) and reconcile the prefix remainder.
    let mut coarse: HashMap<String, u64> = HashMap::new();
    for (src, cost) in &fine_buckets {
        *coarse.entry(coarse_source(src).to_owned()).or_default() += *cost;
    }
    let content_attributed: u64 = coarse.values().copied().sum();
    let session_prefix = measured_context_total.saturating_sub(content_attributed);
    if session_prefix > 0 {
        coarse.insert("session_prefix".to_owned(), session_prefix);
    }

    let mut buckets: Vec<Bucket> = coarse
        .into_iter()
        .map(|(source, carried_cost)| Bucket {
            source,
            carried_cost,
            pct: pct_of(carried_cost, measured_context_total),
        })
        .collect();
    buckets.sort_by(|a, b| {
        b.carried_cost
            .cmp(&a.carried_cost)
            .then_with(|| a.source.cmp(&b.source))
    });

    all_blocks.sort_by(|a, b| b.carried_cost.cmp(&a.carried_cost));
    all_blocks.truncate(TOP_BLOCKS);

    let context_tokens_per_turn = if assistant_turns > 0 {
        measured_context_total / assistant_turns
    } else {
        0
    };
    let headline = Headline {
        assistant_turns,
        tasks,
        segments,
        context_tokens_per_turn,
        cache_read_to_output_ratio: ratio2(measured.cache_read, measured.output),
        measured_context_total,
        prefix_pct: pct_of(session_prefix, measured_context_total),
    };

    let levers = levers::generate(&headline, &buckets, &all_blocks);

    // OD-29: rank the transcript's ExecPlan-link signals into the top-K slugs the
    // session actually worked. The daemon prefers these over window-overlap.
    let signals: Vec<ExecPlanSignal> = events.iter().flat_map(|e| e.execplan_signals.iter().cloned()).collect();
    let branch = most_common_branch(events);
    let branch_leaf = branch.as_deref().map(branch_leaf_of);
    let execplan_slugs = rank_execplan_slugs(&signals, branch_leaf, MAX_EXECPLAN_SLUGS);

    // The model/effort axis. `model`/`effort` are the dominant pair, for callers
    // that want one label per session; `breakdown` is the whole distribution and
    // reconciles to `measured_context_total`.
    let breakdown = crate::models::breakdown(events);
    let (model, effort) = breakdown.as_ref().map_or((None, None), crate::models::primary);
    let cwd = crate::models::most_common(events, |e| e.cwd.as_deref());

    CostReport {
        schema: COST_REPORT_SCHEMA.to_owned(),
        session_id,
        source: String::new(),
        generated_at: None,
        started_at: started_at.map(str::to_owned),
        ended_at: ended_at.map(str::to_owned),
        execplan_slugs,
        model,
        effort,
        cwd,
        git_branch: branch,
        breakdown,
        headline,
        measured,
        buckets,
        top_blocks: all_blocks,
        levers,
    }
}

/// Rank ExecPlan-link signals into the top-K distinct slugs the session worked
/// (OD-29). Each slug accumulates its signals' [`SignalStrength::weight`]; a slug
/// whose strongest signal is only [`SignalStrength::Weak`] (e.g. a bare
/// `[[slug]]` mention) is dropped — **weak is a tie-breaker, never sole
/// evidence**. Ranking: total weight desc, then `git`-branch affinity, then
/// first-appearance order (stable), then slug — all deterministic, no clock.
#[must_use]
pub fn rank_execplan_slugs(signals: &[ExecPlanSignal], branch_leaf: Option<&str>, k: usize) -> Vec<String> {
    if signals.is_empty() || k == 0 {
        return Vec::new();
    }
    struct Agg {
        score: u32,
        max: SignalStrength,
        first: usize,
    }
    let mut agg: HashMap<String, Agg> = HashMap::new();
    for (i, sig) in signals.iter().enumerate() {
        let e = agg.entry(sig.slug.clone()).or_insert_with(|| Agg {
            score: 0,
            max: SignalStrength::Weak,
            first: i,
        });
        e.score = e.score.saturating_add(sig.strength.weight());
        if sig.strength > e.max {
            e.max = sig.strength;
        }
    }
    let mut candidates: Vec<(String, Agg)> = agg.into_iter().filter(|(_, a)| a.max > SignalStrength::Weak).collect();
    candidates.sort_by(|(sa, a), (sb, b)| {
        b.score
            .cmp(&a.score)
            .then_with(|| branch_affinity(sb, branch_leaf).cmp(&branch_affinity(sa, branch_leaf)))
            .then_with(|| a.first.cmp(&b.first))
            .then_with(|| sa.cmp(sb))
    });
    candidates.into_iter().take(k).map(|(slug, _)| slug).collect()
}

/// 1 when the slug starts with the (non-empty) branch leaf — a deterministic
/// tie-breaker that can only reorder already-evidenced slugs, never introduce one.
fn branch_affinity(slug: &str, branch_leaf: Option<&str>) -> u8 {
    u8::from(matches!(branch_leaf, Some(leaf) if !leaf.is_empty() && slug.starts_with(leaf)))
}

/// The trailing path segment of a branch name: `feat/token-burn` → `token-burn`.
fn branch_leaf_of(branch: &str) -> &str {
    branch.rsplit('/').next().unwrap_or(branch)
}

/// The most frequently-seen `gitBranch` across the records (ties broken
/// lexically). Branches rarely change mid-session, so this is effectively *the*
/// branch; used only as a ranking tie-breaker.
fn most_common_branch(events: &[Event]) -> Option<String> {
    let mut counts: HashMap<&str, u32> = HashMap::new();
    for e in events {
        if let Some(b) = e.git_branch.as_deref() {
            *counts.entry(b).or_default() += 1;
        }
    }
    let mut entries: Vec<(&str, u32)> = counts.into_iter().collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    entries.first().map(|(b, _)| (*b).to_owned())
}

fn park_blocks(ev: &Event, entry_turn: u64, seg: &mut Vec<Pending>) {
    for b in &ev.blocks {
        seg.push(Pending {
            source: b.source.clone(),
            tool: b.tool.clone(),
            est: est_tokens(b.text_chars),
            entry_turn,
            preview: b.preview.clone(),
        });
    }
}

fn flush_segment(
    seg: &mut Vec<Pending>,
    seg_turn: &mut u64,
    segments: &mut u64,
    fine_buckets: &mut HashMap<String, u64>,
    all_blocks: &mut Vec<BlockCost>,
) {
    if *seg_turn > 0 {
        *segments += 1;
    }
    let k = *seg_turn;
    for p in seg.drain(..) {
        let reads = k.saturating_sub(p.entry_turn);
        if reads == 0 || p.est == 0 {
            continue;
        }
        let carried = p.est.saturating_mul(reads);
        *fine_buckets.entry(p.source.clone()).or_default() += carried;
        all_blocks.push(BlockCost {
            source: p.source,
            tool: p.tool,
            est_tokens: p.est,
            turns_live: reads,
            carried_cost: carried,
            preview: p.preview,
        });
    }
    *seg_turn = 0;
}

/// chars/4 token estimate (ceiling), matching the `tokenburn` `char4` tokenizer.
fn est_tokens(chars: usize) -> u64 {
    to_u64(chars.div_ceil(4))
}

/// `tool_result:Bash` → `tool_result`; leaves prose/prompt/prefix untouched.
fn coarse_source(src: &str) -> &str {
    src.split_once(':').map_or(src, |(head, _)| head)
}

#[allow(
    clippy::cast_precision_loss,
    reason = "token counts are < 2^53, exactly representable in f64"
)]
fn pct_of(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        round2(100.0 * part as f64 / whole as f64)
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "token counts are < 2^53, exactly representable in f64"
)]
fn ratio2(num: u64, den: u64) -> f64 {
    round2(num as f64 / den.max(1) as f64)
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

fn to_u64(x: usize) -> u64 {
    u64::try_from(x).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod slug_rank_tests {
    use super::*;

    fn sig(slug: &str, strength: SignalStrength) -> ExecPlanSignal {
        ExecPlanSignal {
            slug: slug.to_owned(),
            strength,
        }
    }

    #[test]
    fn empty_or_zero_k_yields_empty() {
        assert!(rank_execplan_slugs(&[], None, 3).is_empty());
        assert!(rank_execplan_slugs(&[sig("a-plan", SignalStrength::Strongest)], None, 0).is_empty());
    }

    #[test]
    fn strength_orders_when_frequency_is_equal() {
        let signals = [
            sig("strong-plan", SignalStrength::Strong),
            sig("strongest-plan", SignalStrength::Strongest),
        ];
        // 3 (strongest) > 2 (strong).
        assert_eq!(
            rank_execplan_slugs(&signals, None, 3),
            vec!["strongest-plan", "strong-plan"]
        );
    }

    #[test]
    fn accumulated_weight_beats_a_single_stronger_signal() {
        // Two Strong hits (2+2=4) on `edited` outrank one Strongest (3) on `wrote`.
        let signals = [
            sig("wrote", SignalStrength::Strongest),
            sig("edited", SignalStrength::Strong),
            sig("edited", SignalStrength::Strong),
        ];
        assert_eq!(rank_execplan_slugs(&signals, None, 3), vec!["edited", "wrote"]);
    }

    #[test]
    fn weak_only_slug_is_dropped_but_weak_plus_strong_is_kept() {
        let signals = [
            sig("mentioned-only", SignalStrength::Weak),
            sig("worked-plan", SignalStrength::Weak),
            sig("worked-plan", SignalStrength::Strong),
        ];
        // `mentioned-only` has weak-only evidence → dropped; `worked-plan` survives.
        assert_eq!(rank_execplan_slugs(&signals, None, 3), vec!["worked-plan"]);
    }

    #[test]
    fn caps_at_the_k_parameter() {
        let signals: Vec<ExecPlanSignal> = ["p1", "p2", "p3", "p4"]
            .iter()
            .map(|s| sig(s, SignalStrength::Strong))
            .collect();
        // Explicit small k caps; equal score → stable first-seen order.
        assert_eq!(rank_execplan_slugs(&signals, None, 2), vec!["p1", "p2"]);
        // Under the production sanity bound, all are kept (no precision cap — the
        // daemon even-splits, so high fan-out is not over-credited by keeping them).
        assert_eq!(
            rank_execplan_slugs(&signals, None, MAX_EXECPLAN_SLUGS),
            vec!["p1", "p2", "p3", "p4"]
        );
    }

    #[test]
    fn sanity_bound_truncates_only_pathological_lists() {
        let slugs: Vec<String> = (0..30).map(|i| format!("p{i:02}-plan")).collect();
        let signals: Vec<ExecPlanSignal> = slugs.iter().map(|s| sig(s, SignalStrength::Strong)).collect();
        let out = rank_execplan_slugs(&signals, None, MAX_EXECPLAN_SLUGS);
        assert_eq!(out.len(), MAX_EXECPLAN_SLUGS); // bounded at 25, far above real sessions (max ~16)
    }

    #[test]
    fn branch_affinity_breaks_score_ties() {
        let signals = [
            sig("alpha-plan", SignalStrength::Strong),
            sig("beta-plan", SignalStrength::Strong),
        ];
        // Equal score; the branch leaf prefixes `beta-plan` → it sorts first,
        // overriding the alphabetical/first-seen order that would pick alpha.
        assert_eq!(
            rank_execplan_slugs(&signals, Some("beta-plan"), 3),
            vec!["beta-plan", "alpha-plan"]
        );
        // Without the branch hint, first-seen wins.
        assert_eq!(rank_execplan_slugs(&signals, None, 3), vec!["alpha-plan", "beta-plan"]);
    }

    #[test]
    fn ranking_is_deterministic() {
        let signals = [
            sig("b-plan", SignalStrength::Strong),
            sig("a-plan", SignalStrength::Strong),
            sig("a-plan", SignalStrength::Weak),
        ];
        let once = rank_execplan_slugs(&signals, None, 3);
        let twice = rank_execplan_slugs(&signals, None, 3);
        assert_eq!(once, twice);
        // a-plan (2+1=3) outranks b-plan (2).
        assert_eq!(once, vec!["a-plan", "b-plan"]);
    }

    #[test]
    fn branch_helpers() {
        assert_eq!(branch_leaf_of("feat/token-burn"), "token-burn");
        assert_eq!(branch_leaf_of("main"), "main");
        assert_eq!(branch_affinity("token-burn-x", Some("token-burn")), 1);
        assert_eq!(branch_affinity("other", Some("token-burn")), 0);
        assert_eq!(branch_affinity("any", None), 0);
        assert_eq!(branch_affinity("any", Some("")), 0);
    }
}
