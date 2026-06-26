// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Read-time attribution of session **token-burn** cost reports to ExecPlans.
//!
//! The cost lens stores one [`crate::cost::StoredReport`] per coding session
//! (keyed by transcript UUID, not ExecPlan). A single ExecPlan is usually worked
//! across several sessions, and a single session may touch several plans — so
//! "token burn per ExecPlan" is a **join**, recomputed at read time so it always
//! reflects the latest facts (no stale stored tags).
//!
//! ## OD-28 — the join key: window-overlap v1, passport-refined
//!
//! A cost report carries a session **active window** `[Rs, Re]` (the transcript's
//! earliest→latest record timestamp; see `crux_cost`'s `started_at`/`ended_at`)
//! and the **poster passport** `P` (corecruxctl's login identity). An ExecPlan
//! carries a **fact-activity window** `[Es, Ee]` (its first→last fact) and the
//! set of **contributing agents** `A` (the real principals who wrote its facts —
//! from [`crate::work::Provenance`]).
//!
//! A session is attributed to a plan iff the windows **overlap**
//! (`Rs ≤ Ee ∧ Es ≤ Re`). When the session's poster `P` is a real principal in
//! the plan's agents `A`, the match is **passport-confirmed** (stronger); a
//! window-only match is **window-inferred**. The poster passport often does *not*
//! equal the fact passport (different identities), so passport is a *refinement*,
//! never a filter — window-overlap is the primary signal.
//!
//! A session that overlaps N plans credits all N. That is coarse **by design** —
//! the [`TokenBurn::method`] label is surfaced so the attribution is never
//! silently wrong. The explicit hook-written `session:<uuid> → execplan:<slug>`
//! link (candidate (c) in the plan) is the precision upgrade if window-overlap
//! proves too coarse against real sessions.
//!
//! This module is split:
//! * [`attribute`] is the **pure** core (no IO, no clock) — unit-tested
//!   exhaustively against synthetic windows.
//! * [`session_burns_from_reports`] / [`stamp_token_burn`] are the thin glue that
//!   parses RFC3339 windows and stamps the result onto [`crate::work::WorkItem`]s.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::cost::{StoredReport, ANON_PASSPORT};
use crate::work::WorkItem;

/// One coding session's measured burn plus the window + identity used to place
/// it. Windows are ms since epoch with `start <= end`; a legacy report with no
/// transcript window collapses to a zero-width point (see [`window_ms`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionBurn {
    /// Transcript UUID (corpus identity).
    pub session_id: String,
    /// Active-window start (ms since epoch).
    pub start_ms: i64,
    /// Active-window end (ms since epoch, `>= start_ms`).
    pub end_ms: i64,
    /// Poster passport, or `None` when anonymous (`__anon__`) — i.e. no passport
    /// refinement is possible for this session.
    pub poster_passport: Option<String>,
    /// Σ measured context (`cache_read + cache_creation + input`) over the
    /// session — the headline burn number.
    pub context_tokens: u64,
    /// Σ output tokens over the session.
    pub output_tokens: u64,
}

/// One ExecPlan's fact-activity window plus the principals who wrote its facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanWindow {
    /// Work-item id (`execplan:<slug>`).
    pub id: String,
    /// Fact-window start (ms since epoch).
    pub start_ms: i64,
    /// Fact-window end (ms since epoch, `>= start_ms`).
    pub end_ms: i64,
    /// Real-principal actors who contributed facts (passport-refine set).
    pub agents: Vec<String>,
}

/// Per-ExecPlan token-burn rollup, stamped onto [`crate::work::WorkItem`].
/// Additive, all-`u64`/`String` (so `Eq`), `#[serde(default)]` on the field so
/// the kanban path stays byte-compatible.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TokenBurn {
    /// Σ measured context tokens across attributed sessions — the headline burn.
    pub context_tokens: u64,
    /// Σ output tokens across attributed sessions.
    pub output_tokens: u64,
    /// Number of distinct sessions attributed to this plan.
    pub sessions: u32,
    /// How the sessions were attributed, so the UI never reads as falsely
    /// precise: `passport+window` (every attributed session's poster matched a
    /// plan agent), `window` (all window-only), or `mixed`.
    pub method: String,
}

/// Inclusive window-overlap test.
fn overlaps(a0: i64, a1: i64, b0: i64, b1: i64) -> bool {
    a0 <= b1 && b0 <= a1
}

/// Pure join: attribute each session's burn to every ExecPlan whose fact window
/// overlaps the session window. Returns `plan id → TokenBurn` for the plans that
/// received at least one session. No IO, no clock — deterministic in its inputs.
#[must_use]
pub fn attribute(sessions: &[SessionBurn], plans: &[PlanWindow]) -> BTreeMap<String, TokenBurn> {
    /// Per-plan accumulator (`passport_hits` tracks how many attributed sessions
    /// were passport-confirmed, to derive the method label).
    #[derive(Default)]
    struct Acc {
        ctx: u64,
        out: u64,
        sessions: u32,
        passport_hits: u32,
    }
    let mut acc: BTreeMap<String, Acc> = BTreeMap::new();
    for s in sessions {
        for p in plans {
            if !overlaps(s.start_ms, s.end_ms, p.start_ms, p.end_ms) {
                continue;
            }
            let e = acc.entry(p.id.clone()).or_default();
            e.ctx = e.ctx.saturating_add(s.context_tokens);
            e.out = e.out.saturating_add(s.output_tokens);
            e.sessions += 1;
            let confirmed = s
                .poster_passport
                .as_deref()
                .is_some_and(|pp| p.agents.iter().any(|a| a == pp));
            if confirmed {
                e.passport_hits += 1;
            }
        }
    }
    acc.into_iter()
        .map(|(id, a)| {
            let method = if a.passport_hits == 0 {
                "window"
            } else if a.passport_hits == a.sessions {
                "passport+window"
            } else {
                "mixed"
            };
            (
                id,
                TokenBurn {
                    context_tokens: a.ctx,
                    output_tokens: a.out,
                    sessions: a.sessions,
                    method: method.to_string(),
                },
            )
        })
        .collect()
}

/// Parse an RFC3339 timestamp to ms since epoch.
fn rfc3339_ms(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|d| d.timestamp_millis())
}

/// Resolve a stored report's window. Prefers the transcript window
/// (`started_at`/`ended_at`); falls back to a zero-width point at `generated_at`,
/// then the daemon's `received_at`, so a legacy windowless report still places
/// somewhere rather than vanishing. `None` only if nothing parses.
fn window_ms(s: &StoredReport) -> Option<(i64, i64)> {
    let start = s.report.started_at.as_deref().and_then(rfc3339_ms);
    let end = s.report.ended_at.as_deref().and_then(rfc3339_ms);
    if let (Some(a), Some(b)) = (start, end) {
        return Some((a.min(b), a.max(b)));
    }
    let point = s
        .report
        .generated_at
        .as_deref()
        .and_then(rfc3339_ms)
        .or_else(|| rfc3339_ms(&s.received_at))?;
    Some((point, point))
}

/// Convert stored cost reports into [`SessionBurn`]s ready for [`attribute`].
/// Reports whose window cannot be resolved at all are dropped.
#[must_use]
pub fn session_burns_from_reports(reports: &[StoredReport]) -> Vec<SessionBurn> {
    reports
        .iter()
        .filter_map(|r| {
            let (start_ms, end_ms) = window_ms(r)?;
            let poster = (r.actor_passport != ANON_PASSPORT && !r.actor_passport.trim().is_empty())
                .then(|| r.actor_passport.clone());
            Some(SessionBurn {
                session_id: r.session_id.clone(),
                start_ms,
                end_ms,
                poster_passport: poster,
                context_tokens: r.report.headline.measured_context_total,
                output_tokens: r.report.measured.output,
            })
        })
        .collect()
}

/// Derive a [`PlanWindow`] from a work item. Prefers the provenance fact-window
/// and its contributing agents; falls back to the item's created/updated window
/// and its assignee passport when provenance is absent.
fn plan_window(item: &WorkItem) -> PlanWindow {
    let (start, end, agents) = match &item.provenance {
        Some(p) => (
            p.first_activity_unix_ms,
            p.last_activity_unix_ms,
            p.contributing_agents.clone(),
        ),
        None => (
            item.created_at_unix_ms,
            item.updated_at_unix_ms,
            item.assignee_passport.clone().into_iter().collect(),
        ),
    };
    PlanWindow {
        id: item.id.clone(),
        start_ms: start as i64,
        end_ms: (end.max(start)) as i64,
        agents,
    }
}

/// Stamp `token_burn` onto each ExecPlan work item by joining it against the
/// session burns. Items with no attributed session are left untouched
/// (`token_burn` stays `None`, so the field is omitted on the wire).
pub fn stamp_token_burn(items: &mut [WorkItem], sessions: &[SessionBurn]) {
    if sessions.is_empty() {
        return;
    }
    let plans: Vec<PlanWindow> = items.iter().map(plan_window).collect();
    let mut burns = attribute(sessions, &plans);
    for item in items.iter_mut() {
        if let Some(tb) = burns.remove(&item.id) {
            item.token_burn = Some(tb);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn sess(id: &str, start: i64, end: i64, poster: Option<&str>, ctx: u64, out: u64) -> SessionBurn {
        SessionBurn {
            session_id: id.to_string(),
            start_ms: start,
            end_ms: end,
            poster_passport: poster.map(str::to_string),
            context_tokens: ctx,
            output_tokens: out,
        }
    }

    fn plan(id: &str, start: i64, end: i64, agents: &[&str]) -> PlanWindow {
        PlanWindow {
            id: id.to_string(),
            start_ms: start,
            end_ms: end,
            agents: agents.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn overlap_is_inclusive_and_symmetric() {
        assert!(overlaps(0, 10, 10, 20)); // touch at a point
        assert!(overlaps(0, 10, 5, 7)); // contained
        assert!(overlaps(5, 7, 0, 10)); // container
        assert!(!overlaps(0, 10, 11, 20)); // disjoint
        assert!(!overlaps(11, 20, 0, 10)); // disjoint other way
    }

    #[test]
    fn window_overlap_attributes_and_sums() {
        let sessions = vec![
            sess("s1", 100, 200, None, 1000, 50),
            sess("s2", 150, 160, None, 500, 20),
            sess("s3", 900, 950, None, 7777, 7), // disjoint from the plan
        ];
        let plans = vec![plan("execplan:a", 120, 400, &[])];
        let out = attribute(&sessions, &plans);
        let a = out.get("execplan:a").unwrap();
        // s1 and s2 overlap [120,400]; s3 does not.
        assert_eq!(a.sessions, 2);
        assert_eq!(a.context_tokens, 1500);
        assert_eq!(a.output_tokens, 70);
        assert_eq!(a.method, "window");
    }

    #[test]
    fn passport_confirmed_when_poster_is_a_plan_agent() {
        let sessions = vec![sess("s1", 100, 200, Some("alice"), 1000, 10)];
        let plans = vec![plan("execplan:a", 100, 300, &["alice", "bob"])];
        let out = attribute(&sessions, &plans);
        assert_eq!(out.get("execplan:a").unwrap().method, "passport+window");
    }

    #[test]
    fn mixed_method_when_some_sessions_confirm_and_others_dont() {
        let sessions = vec![
            sess("s1", 100, 200, Some("alice"), 1000, 10), // confirmed
            sess("s2", 100, 200, Some("mallory"), 500, 5), // poster not an agent
            sess("s3", 100, 200, None, 200, 2),            // anonymous
        ];
        let plans = vec![plan("execplan:a", 100, 300, &["alice"])];
        let out = attribute(&sessions, &plans);
        let a = out.get("execplan:a").unwrap();
        assert_eq!(a.sessions, 3);
        assert_eq!(a.method, "mixed");
    }

    #[test]
    fn one_session_credits_every_overlapping_plan() {
        // A session touching 3 plans credits all 3 (coarse by design).
        let sessions = vec![sess("s1", 100, 200, None, 900, 9)];
        let plans = vec![
            plan("execplan:a", 50, 150, &[]),
            plan("execplan:b", 180, 500, &[]),
            plan("execplan:c", 0, 99, &[]), // disjoint (ends before s1 starts)
        ];
        let out = attribute(&sessions, &plans);
        assert_eq!(out.len(), 2);
        assert!(out.contains_key("execplan:a"));
        assert!(out.contains_key("execplan:b"));
        assert!(!out.contains_key("execplan:c"));
        assert_eq!(out.get("execplan:a").unwrap().context_tokens, 900);
        assert_eq!(out.get("execplan:b").unwrap().context_tokens, 900);
    }

    #[test]
    fn empty_inputs_yield_empty_map() {
        assert!(attribute(&[], &[plan("execplan:a", 0, 10, &[])]).is_empty());
        assert!(attribute(&[sess("s", 0, 10, None, 1, 1)], &[]).is_empty());
    }

    #[test]
    fn window_ms_prefers_transcript_window_over_point() {
        let mut s = stored("2026-06-25T11:00:00.000Z", "2026-06-25T12:00:00.000Z");
        let (a, b) = window_ms(&s).unwrap();
        assert!(b > a);
        assert_eq!(a, rfc3339_ms("2026-06-25T11:00:00.000Z").unwrap());
        // Drop the window → falls back to a generated_at point.
        s.report.started_at = None;
        s.report.ended_at = None;
        s.report.generated_at = Some("2026-06-25T13:00:00Z".to_string());
        let (a2, b2) = window_ms(&s).unwrap();
        assert_eq!(a2, b2, "windowless report collapses to a point");
        assert_eq!(a2, rfc3339_ms("2026-06-25T13:00:00Z").unwrap());
    }

    #[test]
    fn session_burns_drop_anon_poster_and_carry_measured() {
        let s = stored("2026-06-25T11:00:00.000Z", "2026-06-25T12:00:00.000Z");
        let burns = session_burns_from_reports(std::slice::from_ref(&s));
        assert_eq!(burns.len(), 1);
        // The sample stored report posts as ANON → poster is None.
        assert!(burns[0].poster_passport.is_none());
        assert_eq!(burns[0].context_tokens, s.report.headline.measured_context_total);
    }

    #[test]
    fn stamp_token_burn_uses_provenance_window_and_only_marks_overlap() {
        // Two ExecPlan items: `a`'s fact window overlaps the session, `b`'s does
        // not. Provenance windows drive the join; only `a` should be stamped.
        let mut items = vec![
            wi_with_provenance("execplan:a", 1_000, 2_000, &["alice"]),
            wi_with_provenance("execplan:b", 9_000, 9_500, &[]),
        ];
        let sessions = vec![sess("s1", 1_500, 1_800, Some("alice"), 4_242, 99)];
        stamp_token_burn(&mut items, &sessions);

        let a = items[0].token_burn.as_ref().expect("a is stamped");
        assert_eq!(a.context_tokens, 4_242);
        assert_eq!(a.output_tokens, 99);
        assert_eq!(a.sessions, 1);
        assert_eq!(a.method, "passport+window"); // poster "alice" is a plan agent
        assert!(items[1].token_burn.is_none(), "b does not overlap → untouched");
    }

    #[test]
    fn stamp_token_burn_no_sessions_is_a_noop() {
        let mut items = vec![wi_with_provenance("execplan:a", 1_000, 2_000, &[])];
        stamp_token_burn(&mut items, &[]);
        assert!(items[0].token_burn.is_none());
    }

    /// Minimal ExecPlan-shaped [`WorkItem`] with a provenance fact-window, for the
    /// stamping tests.
    fn wi_with_provenance(id: &str, first_ms: u64, last_ms: u64, agents: &[&str]) -> WorkItem {
        WorkItem {
            id: id.to_string(),
            project_id: "execplans".to_string(),
            state: "in_progress".to_string(),
            title: id.to_string(),
            body: String::new(),
            assignee_passport: None,
            tenant_id: None,
            linked_pr: None,
            linked_issue: None,
            blocker_reason: None,
            created_by_passport: "system:execplan-aggregator".to_string(),
            created_at_unix_ms: first_ms,
            updated_at_unix_ms: last_ms,
            plan_path: None,
            current_milestone: None,
            superseded_by: None,
            depends_on: Vec::new(),
            extended_by: Vec::new(),
            open_decisions: Vec::new(),
            orchestrator_id: None,
            milestones_done: None,
            milestones_total: None,
            notes_count: None,
            provenance: Some(crate::work::Provenance {
                first_activity_unix_ms: first_ms,
                last_activity_unix_ms: last_ms,
                contributing_agents: agents.iter().map(|s| s.to_string()).collect(),
                commit_shas: Vec::new(),
                decision_count: 0,
            }),
            stale: None,
            token_burn: None,
        }
    }

    /// Build a stored report with a given transcript window for the glue tests.
    fn stored(started: &str, ended: &str) -> StoredReport {
        StoredReport {
            tenant_id: "default".to_string(),
            session_id: "sess".to_string(),
            actor_passport: ANON_PASSPORT.to_string(),
            received_at: "2026-06-25T12:30:00.000Z".to_string(),
            report: crux_cost::CostReport {
                schema: crux_cost::COST_REPORT_SCHEMA.to_string(),
                session_id: "sess".to_string(),
                source: "sess.jsonl".to_string(),
                generated_at: Some("2026-06-25T12:31:00Z".to_string()),
                started_at: Some(started.to_string()),
                ended_at: Some(ended.to_string()),
                execplan_slugs: Vec::new(),
                headline: crux_cost::Headline {
                    assistant_turns: 10,
                    tasks: 2,
                    segments: 1,
                    context_tokens_per_turn: 1000,
                    cache_read_to_output_ratio: 50.0,
                    measured_context_total: 12_345,
                    prefix_pct: 50.0,
                },
                measured: crux_cost::Measured {
                    input: 1,
                    output: 678,
                    cache_read: 2,
                    cache_creation: 3,
                },
                buckets: Vec::new(),
                top_blocks: Vec::new(),
                levers: Vec::new(),
            },
        }
    }
}
