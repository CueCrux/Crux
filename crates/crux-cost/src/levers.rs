// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Reduction levers — the "what you can do to reduce token burn" analysis.
//!
//! Every lever is **grounded in this session's measured numbers**: it only
//! fires when its bucket crosses a threshold, and the advice interpolates the
//! actual share so the user sees *why*. The prefix advice reflects the honest
//! TokenBurn finding — the movable prefix is the MCP tool surface and an
//! over-budget `MEMORY.md`, not rewording `CLAUDE.md` (editable files were only
//! ~8% of the measured prefix).

use crate::report::{BlockCost, Bucket, Headline, Lever, Severity};

/// Generate the ordered lever list (High → Low, then by addressable share).
#[must_use]
pub fn generate(headline: &Headline, buckets: &[Bucket], top_blocks: &[BlockCost]) -> Vec<Lever> {
    if headline.assistant_turns == 0 {
        return Vec::new();
    }
    let mut levers = Vec::new();
    let turns = headline.assistant_turns;

    // 1. Fixed prefix — the per-turn tax.
    let prefix_pct = bucket_pct(buckets, "session_prefix");
    if prefix_pct >= 40.0 {
        levers.push(Lever {
            id: "trim-prefix".to_owned(),
            severity: sev(prefix_pct, 55.0),
            title: "Trim the fixed prefix (MCP tool surface + MEMORY.md)".to_owned(),
            detail: format!(
                "The fixed prefix — system prompt, MCP tool schemas, and your CLAUDE.md/MEMORY.md — \
                 is re-read on every one of your {turns} turns and is {prefix_pct:.0}% of carried \
                 context. Editable files are only ~8% of that prefix, so the real lever is fewer \
                 connected MCP tools and trimming MEMORY.md to its line budget: each removed tool \
                 schema saves its tokens on every turn, not once."
            ),
            est_pct: prefix_pct,
        });
    }

    // 2. Tool results — large outputs carried forward.
    let tr_pct = bucket_pct(buckets, "tool_result");
    if tr_pct >= 20.0 {
        let offender = top_tool(top_blocks, "tool_result")
            .map(|t| format!(" — {t} is the biggest single source"))
            .unwrap_or_default();
        levers.push(Lever {
            id: "offload-tool-output".to_owned(),
            severity: sev(tr_pct, 30.0),
            title: "Offload large tool outputs to files".to_owned(),
            detail: format!(
                "Tool results are {tr_pct:.0}% of carried cost{offender}. A large command or file \
                 output is re-read from cache on every later turn until the next compaction. Pipe \
                 big outputs to a file and read only the ranges you need, or ask for a summary \
                 instead of the raw dump."
            ),
            est_pct: tr_pct,
        });
    }

    // 3. Tool-call arguments — usually full file contents passed to Write/Edit.
    let ta_pct = bucket_pct(buckets, "tool_use_args");
    if ta_pct >= 15.0 {
        let offender = top_tool(top_blocks, "tool_use_args").unwrap_or_else(|| "tools like Write/Edit".to_owned());
        levers.push(Lever {
            id: "targeted-edits".to_owned(),
            severity: sev(ta_pct, 25.0),
            title: "Prefer targeted edits over rewriting files".to_owned(),
            detail: format!(
                "Tool-call arguments — the contents you pass to {offender} — are {ta_pct:.0}% of \
                 carried cost and are re-read every subsequent turn. Prefer small targeted edits \
                 over rewriting whole files, and avoid pasting large blobs as arguments."
            ),
            est_pct: ta_pct,
        });
    }

    // 3b. Pasted / attached file content.
    let at_pct = bucket_pct(buckets, "attachment");
    if at_pct >= 15.0 {
        levers.push(Lever {
            id: "reference-not-paste".to_owned(),
            severity: sev(at_pct, 25.0),
            title: "Reference files by path instead of pasting".to_owned(),
            detail: format!(
                "Attached / pasted file content is {at_pct:.0}% of carried cost and is re-read on \
                 every turn. Point the agent at a path (it reads the ranges it needs) instead of \
                 pasting whole files into the prompt."
            ),
            est_pct: at_pct,
        });
    }

    // 4. Conversation history piling up in one long segment.
    let hist_pct = bucket_pct(buckets, "assistant_prose") + bucket_pct(buckets, "assistant_thinking");
    if headline.context_tokens_per_turn >= 100_000 || (headline.segments <= 1 && turns >= 30) {
        levers.push(Lever {
            id: "compact-between-tasks".to_owned(),
            severity: Severity::Medium,
            title: "Reset context between unrelated tasks".to_owned(),
            detail: format!(
                "Each model call re-reads about {ctx} tokens of context, and you ran {turns} turns \
                 across only {segs} compaction segment(s). When you switch to an unrelated task, \
                 /clear or /compact resets the carried window instead of letting history \
                 (currently {hist_pct:.0}% of carried cost) pile up.",
                ctx = fmt_k(headline.context_tokens_per_turn),
                segs = headline.segments,
            ),
            est_pct: hist_pct,
        });
    }

    // 5. Framing lever — always present for a real session.
    if headline.cache_read_to_output_ratio >= 20.0 {
        levers.push(Lever {
            id: "context-replay-framing".to_owned(),
            severity: Severity::Low,
            title: "Most spend is context replay, not generation".to_owned(),
            detail: format!(
                "For every output token you generate, {ratio:.0}× context tokens are re-read. \
                 Shortening the session and offloading tool output to files moves the needle far \
                 more than terser prompts — generation is a rounding error at this ratio.",
                ratio = headline.cache_read_to_output_ratio,
            ),
            est_pct: 0.0,
        });
    }

    levers.sort_by(|a, b| {
        sev_rank(a.severity)
            .cmp(&sev_rank(b.severity))
            .then_with(|| b.est_pct.partial_cmp(&a.est_pct).unwrap_or(std::cmp::Ordering::Equal))
    });
    levers
}

fn bucket_pct(buckets: &[Bucket], source: &str) -> f64 {
    buckets.iter().find(|b| b.source == source).map_or(0.0, |b| b.pct)
}

/// The tool name of the highest-carried-cost block under a coarse source.
/// `top_blocks` is pre-sorted desc by carried cost, so the first match wins.
fn top_tool(top_blocks: &[BlockCost], coarse: &str) -> Option<String> {
    top_blocks
        .iter()
        .find(|b| b.source.split_once(':').map(|(h, _)| h) == Some(coarse) && b.tool.is_some())
        .and_then(|b| b.tool.clone())
}

fn sev(pct: f64, high_at: f64) -> Severity {
    if pct >= high_at {
        Severity::High
    } else {
        Severity::Medium
    }
}

fn sev_rank(s: Severity) -> u8 {
    match s {
        Severity::High => 0,
        Severity::Medium => 1,
        Severity::Low => 2,
    }
}

fn fmt_k(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.0}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}
