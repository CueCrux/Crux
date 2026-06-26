// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
