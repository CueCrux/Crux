// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! The **cache-invalidation ledger**: why a session re-wrote its prompt cache,
//! and what each rewrite cost.
//!
//! Claude Code caches the prompt prefix with a 1-hour TTL. On the measured
//! corpus (`drivew-host-claude-transcripts-2026-09`, the 27 most recent sessions
//! with ≥ 5 API turns) the cache hits 98.2% of the time — but 60% of all
//! cache-*write* tokens are rewrites of a prefix that was already cached, billed
//! at the 2x 1h write rate. This module names those rewrites.
//!
//! Three things make the numbers trustworthy:
//!
//! 1. **API turns, not JSONL lines.** One API response is written as several
//!    `assistant` records sharing a `message.id` and repeating the same `usage`.
//!    [`crate::transcript`] clears the duplicates' usage at parse time; this
//!    module walks what is left, so one turn is one API call.
//! 2. **The detection rule is the measured baseline rule**, not a fresh guess —
//!    see [`CacheInvalidation`].
//! 3. **Precedence is measured, not intuitive.** `hook_*` attachments look
//!    damning (17.6% of invalidating windows vs a 0.11% base rate) but they fire
//!    at SessionStart/resume — the same moment a long idle gap expired the
//!    cache. They are a marker of a cold resume, not its cause, so an idle gap
//!    always wins. See [`CacheClass`].

use crate::report::{CacheClass, CacheInvalidation, ToolDeltaKind};
use crate::transcript::{epoch_seconds, AttachmentInfo, Event, EventKind};
use crate::MAX_INVALIDATIONS;

/// Minimum previous-turn context for a window to be judged at all. Below this
/// there is no prefix worth caching and the ratios are noise.
const MIN_CONTEXT: u64 = 5_000;
/// A turn re-read less than this share of the previous context …
const READ_RATIO: f64 = 0.5;
/// … while writing more than this share of it, is a rewrite.
const WRITE_RATIO: f64 = 0.4;
/// Idle minutes at or beyond which the 1-hour TTL has certainly expired.
const TTL_MINUTES: f64 = 60.0;

/// One API turn, reduced to what the ledger needs.
struct Turn {
    /// Index into the `events` slice (for the between-turns attachment window).
    event_idx: usize,
    cache_read: u64,
    cache_creation: u64,
    input: u64,
    ephemeral_5m: u64,
    ephemeral_1h: u64,
    /// A compaction boundary sits between the previous turn and this one.
    compaction_before: bool,
    /// Epoch seconds, when the record carried a parseable timestamp.
    at: Option<i64>,
}

impl Turn {
    /// The context this turn read: cached + newly-cached + fresh.
    fn context(&self) -> u64 {
        self.cache_read
            .saturating_add(self.cache_creation)
            .saturating_add(self.input)
    }
}

/// The ledger totals for one session.
pub struct Ledger {
    /// API turns (deduped by `message.id`) that carried usage.
    pub api_turns: u64,
    /// Σ `cache_creation.ephemeral_5m_input_tokens`.
    pub cache_creation_5m: u64,
    /// Σ `cache_creation.ephemeral_1h_input_tokens`.
    pub cache_creation_1h: u64,
    /// Σ `cache_creation` over invalidating turns.
    pub invalidation_tokens: u64,
    /// The detected invalidations, transcript order, bounded by
    /// [`MAX_INVALIDATIONS`].
    pub invalidations: Vec<CacheInvalidation>,
}

/// Build the cache-invalidation ledger for a parsed transcript.
#[must_use]
pub fn ledger(events: &[Event]) -> Ledger {
    let turns = api_turns(events);
    let mut out = Ledger {
        api_turns: turns.len() as u64,
        cache_creation_5m: turns.iter().map(|t| t.ephemeral_5m).sum(),
        cache_creation_1h: turns.iter().map(|t| t.ephemeral_1h).sum(),
        invalidation_tokens: 0,
        invalidations: Vec::new(),
    };

    for (i, pair) in turns.windows(2).enumerate() {
        let (prev, cur) = (&pair[0], &pair[1]);
        let ctx = prev.context();
        // A compaction was *supposed* to rebuild the context, and a tiny prefix
        // is not worth caching: neither is an invalidation.
        if cur.compaction_before || ctx < MIN_CONTEXT {
            continue;
        }
        let ctx = ctx as f64;
        if !((cur.cache_read as f64) < READ_RATIO * ctx && (cur.cache_creation as f64) > WRITE_RATIO * ctx) {
            continue;
        }
        let gap_minutes = match (prev.at, cur.at) {
            (Some(a), Some(b)) => Some((b - a) as f64 / 60.0),
            _ => None,
        };
        let window: Vec<&AttachmentInfo> = events
            .get(prev.event_idx + 1..cur.event_idx)
            .unwrap_or_default()
            .iter()
            .filter_map(|e| e.attachment.as_ref())
            .collect();
        let (class, server, tool_delta) = classify(gap_minutes, &window);
        out.invalidation_tokens = out.invalidation_tokens.saturating_add(cur.cache_creation);
        if out.invalidations.len() < MAX_INVALIDATIONS {
            out.invalidations.push(CacheInvalidation {
                // `windows(2)` index `i` is the *previous* turn; the
                // invalidating turn is the next one.
                index: (i + 1) as u64,
                class,
                sub_bucket: sub_bucket(class, gap_minutes),
                tokens: cur.cache_creation,
                gap_minutes: gap_minutes.map(|g| (g * 10.0).round() / 10.0),
                server,
                tool_delta,
            });
        }
    }
    out
}

/// Collapse the event stream into API turns, carrying a "a compaction happened
/// since the last turn" flag forward onto the turn that follows it.
fn api_turns(events: &[Event]) -> Vec<Turn> {
    let mut turns = Vec::new();
    let mut compaction_pending = false;
    for (idx, ev) in events.iter().enumerate() {
        if ev.kind == EventKind::Compaction {
            compaction_pending = true;
            continue;
        }
        if ev.kind != EventKind::Assistant {
            continue;
        }
        // `usage` is `None` on a duplicate `message.id` line (already counted).
        let Some(u) = ev.usage else { continue };
        turns.push(Turn {
            event_idx: idx,
            cache_read: u.cache_read,
            cache_creation: u.cache_creation,
            input: u.input,
            ephemeral_5m: ev.cache_creation_5m,
            ephemeral_1h: ev.cache_creation_1h,
            compaction_before: compaction_pending,
            at: ev.timestamp.as_deref().and_then(epoch_seconds),
        });
        compaction_pending = false;
    }
    turns
}

/// Blame one invalidation on the first matching cause, in measured precedence
/// order. See [`CacheClass`] for why the idle gap outranks the hook markers.
fn classify(
    gap_minutes: Option<f64>,
    window: &[&AttachmentInfo],
) -> (CacheClass, Option<String>, Option<ToolDeltaKind>) {
    let has = |kind: &str| window.iter().any(|a| a.kind == kind);
    if gap_minutes.is_some_and(|g| g >= TTL_MINUTES) {
        return (CacheClass::TtlExpiry, None, None);
    }
    if has("ultra_effort_enter") || has("ultra_effort_exit") {
        return (CacheClass::EffortChange, None, None);
    }
    if has("date_change") {
        return (CacheClass::DateChange, None, None);
    }
    let tool_deltas: Vec<&&AttachmentInfo> = window.iter().filter(|a| a.kind == "deferred_tools_delta").collect();
    if !tool_deltas.is_empty() {
        let merged = AttachmentInfo {
            kind: "deferred_tools_delta".to_owned(),
            added_names: tool_deltas.iter().flat_map(|a| a.added_names.clone()).collect(),
            removed_names: tool_deltas.iter().flat_map(|a| a.removed_names.clone()).collect(),
        };
        let kind = if merged.removed_names.is_empty() {
            ToolDeltaKind::AddOnly
        } else {
            ToolDeltaKind::WithRemovals
        };
        return (CacheClass::ToolDelta, merged.dominant_server(), Some(kind));
    }
    if has("mcp_instructions_delta") {
        return (CacheClass::McpInstructionsDelta, None, None);
    }
    if window.iter().any(|a| a.kind.starts_with("hook_")) {
        return (CacheClass::HookBlock, None, None);
    }
    (CacheClass::Unattributed, None, None)
}

/// Idle sub-band for a TTL expiry. `60-65m` is the one that matters most: it is
/// a self-paced wakeup that just missed the TTL (7 of 76 measured events).
fn sub_bucket(class: CacheClass, gap_minutes: Option<f64>) -> Option<String> {
    if class != CacheClass::TtlExpiry {
        return None;
    }
    let g = gap_minutes?;
    Some(
        if g < 65.0 {
            "60-65m"
        } else if g < 120.0 {
            "65-120m"
        } else if g < 480.0 {
            "120-480m"
        } else {
            "480m+"
        }
        .to_owned(),
    )
}

/// The class responsible for the most rewritten tokens, with its token total.
/// Used by the `cache-thrash` lever to name the dominant cause.
#[must_use]
pub fn dominant_class(invalidations: &[CacheInvalidation]) -> Option<(CacheClass, u64)> {
    let mut totals: Vec<(CacheClass, u64)> = Vec::new();
    for inv in invalidations {
        match totals.iter_mut().find(|(c, _)| *c == inv.class) {
            Some((_, t)) => *t = t.saturating_add(inv.tokens),
            None => totals.push((inv.class, inv.tokens)),
        }
    }
    // Tokens desc, then class name — deterministic.
    totals
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.as_str().cmp(a.0.as_str())))
}
