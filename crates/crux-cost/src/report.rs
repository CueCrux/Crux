// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! The shared `CostReport` wire contract.
//!
//! This is the single source of truth for the token-burn cost lens that flows
//! between three surfaces:
//!
//! * **producer** — `corecruxctl session cost` parses a real Claude Code
//!   transcript and builds a [`CostReport`];
//! * **store/relay** — the daemon's `/v1/cost/report` endpoint persists the
//!   last posted report per session (in memory) and serves it back;
//! * **consumer** — the console `cx-cost` page renders the headline, buckets,
//!   top blocks, and [reduction levers](Lever).
//!
//! Keeping the types here (not duplicated in each crate) means the contract
//! cannot drift between the CLI that writes it and the daemon that reads it.

use serde::{Deserialize, Serialize};

/// Schema tag stamped on every emitted report.
pub const COST_REPORT_SCHEMA: &str = "crux.cost.report.v1";

/// A ground-truth token-burn summary for a single coding session.
///
/// "Ground-truth" means the headline numbers come from the transcript's
/// measured `message.usage` fields, **not** the chars/4 dispatch estimate — see
/// [`Measured`]. Estimation (chars/4) is used only to *apportion* that measured
/// total across [buckets](Bucket); the buckets reconcile exactly back to
/// [`Headline::measured_context_total`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CostReport {
    /// Always [`COST_REPORT_SCHEMA`]. Lets the console/daemon reject stale shapes.
    pub schema: String,
    /// The transcript's session id (corpus identity — QC.4). May be empty if
    /// the transcript carried no `sessionId`.
    pub session_id: String,
    /// The transcript file name (corpus identity — name the corpus, never a
    /// bare number). e.g. `4f0c0fcb...jsonl`.
    pub source: String,
    /// RFC3339 timestamp set by the *caller* (CLI/daemon) at emit time. The
    /// analyzer leaves this `None` — the crate has no clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    /// RFC3339 timestamp of the transcript's **earliest** record — the session's
    /// active-window start. Derived from the per-record `timestamp` fields, so it
    /// reflects when work actually happened (not [`Self::generated_at`], the
    /// later analysis time). `None` when no record carried a parseable timestamp.
    /// Consumed by the daemon's per-ExecPlan token-burn attribution (the session
    /// window is overlapped against each plan's fact-activity window).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// RFC3339 timestamp of the transcript's **latest** record — the session's
    /// active-window end. Pairs with [`Self::started_at`]. `None` when no record
    /// carried a parseable timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    /// The ExecPlan slug(s) this session actually **worked**, derived from the
    /// transcript (MCP fact-writes to `execplan:<slug>`, edits to a plan file) and
    /// ranked top-K — see `crux_cost::transcript`'s signal extraction. Lets the
    /// daemon attribute this session's burn to *those* plans (`method = "link"`,
    /// precise) instead of every plan whose fact-window happens to overlap
    /// (`method = "window"`, coarse). Empty when no link could be derived (the
    /// daemon then falls back to window-overlap). Additive + serde-default +
    /// skip-if-empty, so an old daemon ignores it and a slug-less legacy report is
    /// unchanged on the wire.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub execplan_slugs: Vec<String>,
    /// The model that took the most turns this session (normalised id; an
    /// unrecognised id is carried verbatim). `None` for a transcript whose
    /// records named no model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// That model's dominant `effort` setting, when its records carried one.
    /// Read it against [`ModelBurn::effort_coverage_pct`] in [`Self::breakdown`]
    /// — `effort` is absent on 61% of the measured corpus, and non-randomly so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<String>,
    /// The session's modal working directory. Already in every transcript
    /// record; previously parsed and discarded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// The session's modal `gitBranch`. Parsed since the ExecPlan-attribution
    /// work but consumed only as an internal slug-ranking tie-breaker; promoted
    /// here so the report can say which branch the burn happened on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    /// Per-model burn, with per-effort burn *within* each model. Additive +
    /// serde-default + skip-if-absent, like [`Self::execplan_slugs`]: an old
    /// daemon ignores it, and a legacy report without it is unchanged on the
    /// wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub breakdown: Option<ModelBreakdown>,
    /// The screenshot-worthy top-line numbers.
    pub headline: Headline,
    /// The four measured `usage` totals summed across the session.
    pub measured: Measured,
    /// Coarse carried-cost buckets (`tool_result`, `tool_use_args`,
    /// `assistant_prose`, …, `session_prefix`), sorted by `carried_cost` desc.
    /// Sums to [`Headline::measured_context_total`].
    pub buckets: Vec<Bucket>,
    /// The single most expensive content blocks (highest carried cost),
    /// previews truncated. Bounded length (≤ [`crate::TOP_BLOCKS`]).
    pub top_blocks: Vec<BlockCost>,
    /// Actionable "what you can do to reduce burn" recommendations, derived from
    /// the buckets + headline. Sorted by addressable share desc.
    pub levers: Vec<Lever>,
}

impl CostReport {
    /// Stamp the emit timestamp (callers own the clock).
    #[must_use]
    pub fn with_generated_at(mut self, ts: impl Into<String>) -> Self {
        self.generated_at = Some(ts.into());
        self
    }
}

/// Per-model burn for one session, plus the pieces that keep it honest.
///
/// `models` excludes `<synthetic>` — Claude Code's marker for records it
/// generated itself, which is not a model and must not be charted as one. It is
/// carried in [`Self::synthetic`] instead, so it is visible but never ranked.
///
/// **Reconciliation.** `Σ models[].context_total + synthetic.context_total +
/// unattributed_context == Headline::measured_context_total`, exactly. Tested.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelBreakdown {
    /// Real models, biggest burn first.
    pub models: Vec<ModelBurn>,
    /// The `<synthetic>` pseudo-model, when the transcript had any. Reported
    /// separately rather than dropped, so the totals still add up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub synthetic: Option<ModelBurn>,
    /// Context from records that carried `usage` but named no model. Non-zero
    /// only for older/partial transcripts; present so the sum reconciles.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unattributed_context: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// One model's share of a session's burn.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModelBurn {
    /// Normalised model id, or the raw string verbatim when unrecognised — a
    /// new id becomes its own visible row rather than merging into an old one.
    pub model: String,
    /// Records attributed to this model.
    pub turns: u64,
    /// The four measured `usage` accumulators over those records.
    pub measured: Measured,
    /// Σ `cache_read + cache_creation + input` over those records.
    pub context_total: u64,
    /// Percentage of this model's turns that carried an `effort` value, 0..100.
    ///
    /// **Every surface rendering [`Self::efforts`] must render this beside it.**
    /// `effort` is missing non-randomly — coverage ran 100% / 100% / 22.5% /
    /// 9.4% by model across the 2026-07-30 corpus — so an effort figure without
    /// its coverage invites a cross-model comparison that is confounded at
    /// source. This is a publishing hazard, not a runtime one: it will not fail
    /// a test, which is exactly why the number rides along in the type.
    pub effort_coverage_pct: f64,
    /// Per-effort burn *within* this model, biggest first. Empty when none of
    /// this model's records carried an `effort`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub efforts: Vec<EffortBurn>,
}

/// One effort setting's share of a single model's burn.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffortBurn {
    /// `xhigh`, `high`, `max`, … carried verbatim.
    pub effort: String,
    /// Records at this effort.
    pub turns: u64,
    /// Σ context read over those records.
    pub context_total: u64,
    /// Σ `output_tokens` over those records.
    pub output: u64,
}

/// The top-line numbers — the wedge. The headline metric is
/// `context_tokens_per_turn`, the average context re-read on every model call.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Headline {
    /// Number of assistant (model) turns in the transcript.
    pub assistant_turns: u64,
    /// Number of distinct user prompts (tasks).
    pub tasks: u64,
    /// Number of compaction segments (1 + number of `/compact` boundaries).
    pub segments: u64,
    /// `measured_context_total / assistant_turns` — the headline burn metric.
    pub context_tokens_per_turn: u64,
    /// `cache_read / output`, rounded to 2 dp. The "context replay vs
    /// generation" ratio — typically very large (e.g. 369×).
    pub cache_read_to_output_ratio: f64,
    /// Σ over assistant turns of `cache_read + cache_creation + input`. The
    /// denominator everything reconciles against.
    pub measured_context_total: u64,
    /// Share of `measured_context_total` attributed to the fixed
    /// `session_prefix` (system prompt + tool schemas + CLAUDE.md/MEMORY.md),
    /// as a percentage 0..100.
    pub prefix_pct: f64,
}

/// The four measured `usage` accumulators (ground truth from the transcript).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Measured {
    /// `input_tokens` — fresh (uncached) input this turn.
    pub input: u64,
    /// `output_tokens` — generated tokens.
    pub output: u64,
    /// `cache_read_input_tokens` — context re-read from the prompt cache.
    pub cache_read: u64,
    /// `cache_creation_input_tokens` — newly-cached context this turn.
    pub cache_creation: u64,
}

impl Measured {
    /// Total context read into the model this/those turn(s): cached + new-cache + fresh.
    #[must_use]
    pub fn context_read(&self) -> u64 {
        self.cache_read
            .saturating_add(self.cache_creation)
            .saturating_add(self.input)
    }
}

/// One coarse carried-cost bucket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Bucket {
    /// Coarse source key: `tool_result`, `tool_use_args`, `assistant_prose`,
    /// `assistant_thinking`, `user_prompt`, `attachment`, or `session_prefix`.
    pub source: String,
    /// Carried cost = Σ over blocks of `est_tokens × times_re_read`.
    pub carried_cost: u64,
    /// `carried_cost / measured_context_total × 100`, 0..100.
    pub pct: f64,
}

/// A single high-cost content block (for the "biggest offenders" list).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockCost {
    /// Fine-grained source, e.g. `tool_result:Bash`, `tool_use_args:Write`.
    pub source: String,
    /// The tool name when the block is tool I/O, else `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Estimated tokens in the block (chars/4).
    pub est_tokens: u64,
    /// How many later turns re-read it (`k - e`).
    pub turns_live: u64,
    /// `est_tokens × turns_live`.
    pub carried_cost: u64,
    /// First ~80 chars of the block, single-lined — never the full content.
    pub preview: String,
}

/// Severity of a reduction lever — drives ordering/colour in the console.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Addresses a large, clearly-movable share of carried cost.
    High,
    /// Worth doing; moderate share.
    Medium,
    /// Framing / minor, but still true.
    Low,
}

impl Severity {
    /// Lowercase wire string (`"high"`, `"medium"`, `"low"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

/// One actionable recommendation for reducing token burn, grounded in this
/// session's measured numbers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Lever {
    /// Stable identifier, e.g. `offload-tool-output`, `trim-prefix`. Lets the
    /// console attach docs/links without parsing the prose.
    pub id: String,
    /// Severity (also the sort key, high → low).
    pub severity: Severity,
    /// Short imperative title.
    pub title: String,
    /// The specific advice, with this session's numbers interpolated in.
    pub detail: String,
    /// Approximate share of carried cost this lever addresses (0..100).
    pub est_pct: f64,
}
