// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
use crate::transcript::{Event, EventKind};
use crate::TOP_BLOCKS;

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

    CostReport {
        schema: COST_REPORT_SCHEMA.to_owned(),
        session_id,
        source: String::new(),
        generated_at: None,
        headline,
        measured,
        buckets,
        top_blocks: all_blocks,
        levers,
    }
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
