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
//! silently wrong.
//!
//! ## OD-30 — link-preferring upgrade (landed)
//!
//! Window-overlap proved too coarse on real data (~186 multi-day sessions credited
//! 753/~934 plans). The precision fix is the producer-derived link: a cost report
//! now carries the ExecPlan slug(s) the session actually worked
//! (`crux_cost`'s `execplan_slugs`, see [`SessionBurn::execplan_slugs`]). When a
//! session carries that link, [`attribute`] credits **only** those plans
//! (`method = "link"`) and skips window-overlap entirely for it; a session with no
//! link still uses the window-overlap fallback. OD-30 (how to split a multi-plan
//! session) is resolved as **even-split** (v2): each linked plan gets `burn / N`,
//! so high-fan-out sessions are not inflated — see [`attribute`].
//!
//! This module is split:
//! * [`attribute`] is the **pure** core (no IO, no clock) — unit-tested
//!   exhaustively against synthetic windows.
//! * [`session_burns_from_reports`] / [`stamp_token_burn`] are the thin glue that
//!   parses RFC3339 windows and stamps the result onto [`crate::work::WorkItem`]s.

use std::collections::{BTreeMap, HashSet};

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
    /// The ExecPlan slug(s) this session actually **worked**, derived from the
    /// transcript by the producer (see `crux_cost`'s `execplan_slugs`). When
    /// non-empty the join attributes the burn **only** to these plans
    /// (`method = "link"`, precise); when empty it falls back to window-overlap.
    pub execplan_slugs: Vec<String>,
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
    /// precise: `link` (every attributed session named this plan in its
    /// transcript — precise), `passport+window` (all window-overlap with the
    /// poster matching a plan agent), `window` (all window-only — coarse), or
    /// `mixed` (a combination, e.g. one linked session and one window overlap).
    pub method: String,
}

/// Inclusive window-overlap test.
fn overlaps(a0: i64, a1: i64, b0: i64, b1: i64) -> bool {
    a0 <= b1 && b0 <= a1
}

/// Pure join: attribute each session's burn to the ExecPlans it worked.
///
/// **Link-preferring (OD-30).** A session that carries `execplan_slugs` (the
/// producer derived which plans it actually worked) is credited **only** to those
/// plans — precise, `method = "link"`. A session with no link falls back to the
/// window-overlap path (every plan whose fact window overlaps the session window),
/// passport-refined as before. This is the precision fix for the parent plan's
/// `finding:window-overlap-too-coarse` (a multi-day session credited ~every
/// concurrently-active plan).
///
/// **OD-30 v2 — multi-plan split: even-split.** When a session links N plans, its
/// burn is split **evenly** — each linked plan receives `burn / N` (N = the
/// emitted slug count). This keeps a high-fan-out session (observed: up to 16
/// plans) from inflating every plan it touched: the sum across plans is ≤ the
/// session total, never a multiple of it. A single-plan session still gives the
/// full burn. The denominator is the worked-plan count, not the projected count,
/// so a plan's share is stable as siblings project. (v1 was full-credit-each,
/// which over-counted high-fan-out sessions and relied on a tight top-K cap to
/// hide it; the cap is now just a sanity bound — see `crux_cost::MAX_EXECPLAN_SLUGS`.)
///
/// Returns `plan id → TokenBurn` for the plans that received at least one session.
/// No IO, no clock — deterministic in its inputs.
#[must_use]
pub fn attribute(sessions: &[SessionBurn], plans: &[PlanWindow]) -> BTreeMap<String, TokenBurn> {
    /// Per-plan accumulator. `link_hits`/`window_hits` count how each attributed
    /// session reached this plan; `passport_hits ⊆ window_hits` are the
    /// poster-confirmed window edges. The `method` label is derived from these.
    #[derive(Default)]
    struct Acc {
        ctx: u64,
        out: u64,
        sessions: u32,
        link_hits: u32,
        window_hits: u32,
        passport_hits: u32,
    }

    // Plan ids that currently project as work items. The link path only credits a
    // slug that resolves to a known plan; an as-yet-unprojected slug (rsync lag)
    // is skipped, and the read-time recompute self-heals once it lands.
    let plan_ids: HashSet<&str> = plans.iter().map(|p| p.id.as_str()).collect();

    let mut acc: BTreeMap<String, Acc> = BTreeMap::new();
    for s in sessions {
        if s.execplan_slugs.is_empty() {
            // Fallback: window-overlap, passport-refined (v1 behaviour, unchanged).
            for p in plans {
                if !overlaps(s.start_ms, s.end_ms, p.start_ms, p.end_ms) {
                    continue;
                }
                let e = acc.entry(p.id.clone()).or_default();
                e.ctx = e.ctx.saturating_add(s.context_tokens);
                e.out = e.out.saturating_add(s.output_tokens);
                e.sessions += 1;
                e.window_hits += 1;
                let confirmed = s
                    .poster_passport
                    .as_deref()
                    .is_some_and(|pp| p.agents.iter().any(|a| a == pp));
                if confirmed {
                    e.passport_hits += 1;
                }
            }
        } else {
            // Precise: split the session's burn EVENLY across the plans it worked
            // (OD-30 v2). The denominator is the worked-plan **count** (len of the
            // emitted slugs), so a plan's share is stable even if a sibling slug
            // has not yet projected as a work item (it does not jump when the
            // sibling lands). Integer division floors the share — the dropped
            // remainder means the sum across plans is ≤ the session total, never
            // inflated. A single-plan session (n=1) still gets the full burn.
            let n = s.execplan_slugs.len() as u64; // ≥ 1 in this branch (non-empty)
            let ctx_share = s.context_tokens / n;
            let out_share = s.output_tokens / n;
            for slug in &s.execplan_slugs {
                let id = format!("execplan:{slug}");
                if !plan_ids.contains(id.as_str()) {
                    continue;
                }
                let e = acc.entry(id).or_default();
                e.ctx = e.ctx.saturating_add(ctx_share);
                e.out = e.out.saturating_add(out_share);
                e.sessions += 1;
                e.link_hits += 1;
            }
        }
    }
    acc.into_iter()
        .map(|(id, a)| {
            let method = if a.link_hits > 0 && a.window_hits == 0 {
                "link"
            } else if a.link_hits > 0 {
                // Some sessions linked precisely, others window-overlapped this plan.
                "mixed"
            } else if a.passport_hits == 0 {
                "window"
            } else if a.passport_hits == a.window_hits {
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
                execplan_slugs: r.report.execplan_slugs.clone(),
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
            execplan_slugs: Vec::new(),
            context_tokens: ctx,
            output_tokens: out,
        }
    }

    /// A session carrying a transcript-derived link to one or more plan slugs.
    /// Window is irrelevant for the link path, so it is left at a point.
    fn sess_linked(id: &str, ctx: u64, out: u64, slugs: &[&str]) -> SessionBurn {
        SessionBurn {
            session_id: id.to_string(),
            start_ms: 0,
            end_ms: 0,
            poster_passport: None,
            execplan_slugs: slugs.iter().map(|s| (*s).to_string()).collect(),
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
    fn link_credits_only_worked_plans_and_skips_window() {
        // The session's *window* overlaps a, b AND c, but its transcript link
        // names only `a`. Window-overlap would credit all three; the link path
        // credits a alone, precisely.
        let sessions = vec![SessionBurn {
            session_id: "s".to_string(),
            start_ms: 100,
            end_ms: 200,
            poster_passport: None,
            execplan_slugs: vec!["a".to_string()],
            context_tokens: 1000,
            output_tokens: 10,
        }];
        let plans = vec![
            plan("execplan:a", 100, 300, &[]),
            plan("execplan:b", 100, 300, &[]),
            plan("execplan:c", 100, 300, &[]),
        ];
        let out = attribute(&sessions, &plans);
        assert_eq!(out.len(), 1);
        let a = out.get("execplan:a").unwrap();
        assert_eq!(a.context_tokens, 1000);
        assert_eq!(a.output_tokens, 10);
        assert_eq!(a.sessions, 1);
        assert_eq!(a.method, "link");
        assert!(!out.contains_key("execplan:b"));
        assert!(!out.contains_key("execplan:c"));
    }

    #[test]
    fn link_even_split_across_multi_plan_session() {
        // OD-30 v2: a session that worked two plans splits its burn evenly.
        let sessions = vec![sess_linked("s", 900, 9, &["a", "b"])];
        let plans = vec![plan("execplan:a", 0, 1, &[]), plan("execplan:b", 0, 1, &[])];
        let out = attribute(&sessions, &plans);
        assert_eq!(out.get("execplan:a").unwrap().context_tokens, 450); // 900 / 2
        assert_eq!(out.get("execplan:b").unwrap().context_tokens, 450);
        assert_eq!(out.get("execplan:a").unwrap().output_tokens, 4); // 9 / 2, floored
        assert_eq!(out.get("execplan:a").unwrap().method, "link");
        // Sum across plans never exceeds the session total (no inflation).
        let total: u64 = out.values().map(|t| t.context_tokens).sum();
        assert!(total <= 900);
    }

    #[test]
    fn link_single_plan_session_gets_full_burn() {
        let sessions = vec![sess_linked("s", 1000, 10, &["solo"])];
        let plans = vec![plan("execplan:solo", 0, 1, &[])];
        let out = attribute(&sessions, &plans);
        assert_eq!(out.get("execplan:solo").unwrap().context_tokens, 1000); // n=1
    }

    #[test]
    fn link_denominator_is_worked_count_not_projected_count() {
        // `ghost` has no work item yet (rsync lag) → not credited; but the split
        // denominator is still 2 (the worked-plan count), so `known` gets 500/2,
        // NOT 500/1 — its share stays stable when `ghost` later projects.
        let sessions = vec![sess_linked("s", 500, 5, &["known", "ghost"])];
        let plans = vec![plan("execplan:known", 0, 1, &[])];
        let out = attribute(&sessions, &plans);
        assert_eq!(out.len(), 1);
        assert_eq!(out.get("execplan:known").unwrap().context_tokens, 250); // 500 / 2
        assert!(!out.contains_key("execplan:ghost"));
    }

    #[test]
    fn linked_session_with_no_known_slug_contributes_nothing() {
        // A session that *does* carry a link never falls back to window-overlap,
        // even if none of its slugs project yet (avoids re-introducing over-credit).
        let sessions = vec![SessionBurn {
            session_id: "s".to_string(),
            start_ms: 100,
            end_ms: 200,
            poster_passport: None,
            execplan_slugs: vec!["ghost".to_string()],
            context_tokens: 1000,
            output_tokens: 10,
        }];
        let plans = vec![plan("execplan:a", 100, 300, &[])]; // window overlaps, but no link match
        assert!(attribute(&sessions, &plans).is_empty());
    }

    #[test]
    fn mixed_method_when_one_session_links_and_another_windows() {
        // Plan a is reached by a precise link (session 1) and a coarse window
        // overlap (session 2) → honestly labelled `mixed`.
        let sessions = vec![sess_linked("s1", 100, 1, &["a"]), sess("s2", 100, 200, None, 50, 1)];
        let plans = vec![plan("execplan:a", 100, 300, &[])];
        let out = attribute(&sessions, &plans);
        let a = out.get("execplan:a").unwrap();
        assert_eq!(a.sessions, 2);
        assert_eq!(a.context_tokens, 150);
        assert_eq!(a.method, "mixed");
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

    #[test]
    fn stamp_token_burn_prefers_link_over_window() {
        // Both items' fact windows overlap the session; the session links only `a`.
        // End-to-end through the glue: only `a` is stamped (precise), not `b`.
        let mut items = vec![
            wi_with_provenance("execplan:a", 1_000, 2_000, &["alice"]),
            wi_with_provenance("execplan:b", 1_000, 2_000, &["alice"]),
        ];
        let sessions = vec![SessionBurn {
            session_id: "s".to_string(),
            start_ms: 1_500,
            end_ms: 1_800,
            poster_passport: Some("alice".to_string()),
            execplan_slugs: vec!["a".to_string()],
            context_tokens: 4_242,
            output_tokens: 99,
        }];
        stamp_token_burn(&mut items, &sessions);
        let a = items[0].token_burn.as_ref().expect("a stamped via link");
        assert_eq!(a.context_tokens, 4_242);
        assert_eq!(a.method, "link"); // link wins even though the poster is a plan agent
        assert!(
            items[1].token_burn.is_none(),
            "b is not linked → untouched despite window overlap"
        );
    }

    #[test]
    fn session_burns_carry_execplan_slugs() {
        let mut s = stored("2026-06-25T11:00:00.000Z", "2026-06-25T12:00:00.000Z");
        s.report.execplan_slugs = vec!["worked-plan".to_string()];
        let burns = session_burns_from_reports(std::slice::from_ref(&s));
        assert_eq!(burns[0].execplan_slugs, vec!["worked-plan".to_string()]);
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
            next_ready_milestone: None,
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
