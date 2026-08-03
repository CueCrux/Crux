// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Server-side attention roll-up (ExecPlan `crux-hosted-relay-gateway-2026-07-30`,
//! M7a).
//!
//! # Why this exists
//!
//! Until now there was **no server-side attention signal at all**. The console
//! computes "N need you · N running · N awaiting review" in the browser
//! (`console/v2/render.js`, `deriveAttentionZone` + `fillNeedsYou`) by fetching
//! three feeds and joining them client-side. That is fine for an operator on
//! the same machine and useless for the hosted cross-daemon view, because both
//! of the feeds it leans on are **disqualified from the frozen read-only
//! subset** (contract v1 §7): `/v1/work` carries customer plan names and
//! `/v1/coord/active` carries local source paths.
//!
//! So the hosted shell had two options: show nothing, or ship the raw feeds and
//! leak. This module is the third — recompute the same classification here and
//! return **only the counts**.
//!
//! # Counts only, and that is a hard boundary
//!
//! [`AttentionSummary`] carries four integers and a clock. No titles, ids,
//! paths, passports, plan slugs, tenant names or blocker reasons. Nothing in
//! here should ever grow an "and also which ones" field: the moment it does, it
//! stops being safely servable to a hosted viewer and the leak it was written
//! to avoid comes back through the front door. A caller who needs *which* items
//! is asking for `/v1/work`, which is a different authorization question.
//!
//! **The consequence for product copy:** until an item-level surface exists,
//! the hosted cross-daemon view is a **health roll-up, not an attention
//! inbox**, and copy must not claim otherwise. A number you cannot click is not
//! an inbox.
//!
//! # Parity with the console
//!
//! [`derive_zone`] is a line-for-line port of `deriveAttentionZone`, including
//! its precedence (`needs_you` > `running` > `done_review`), its staleness
//! window, and its treatment of a future heartbeat. Divergence here would be
//! worse than having no endpoint: two surfaces quoting different numbers for
//! the same daemon is a bug an operator cannot diagnose from either one.
//! [`ATTENTION_LIVENESS_STALE_MS`] and the truth table are asserted against the
//! JS values in this module's tests.
//!
//! One deliberate difference: the console *infers* "waiting for input" from an
//! intent note with a regex, and labels those cards `inferred` in the UI. A
//! bare number cannot carry that hedge — an operator reading `3 need you` has
//! no way to see that one of the three is a guess — so this module **does not
//! infer**. `waiting_for_input` is wired to the structured signal that does not
//! exist yet, and until it does, a waiting session simply is not counted. An
//! undercount an operator can reason about beats an overcount they cannot.

use serde::{Deserialize, Serialize};

/// Heartbeat age past which a live session stops counting as `running`.
///
/// Mirrors `ATTENTION_LIVENESS_STALE_MS` in `console/v2/render.js`. Deliberately
/// far below the coord presence TTL (900s) so the roll-up reflects live work
/// rather than mere presence: a session someone walked away from an hour ago
/// still holds presence, and counting it as running would inflate the number an
/// operator uses to decide whether anything is happening.
pub const ATTENTION_LIVENESS_STALE_MS: u64 = 5 * 60 * 1000;

/// The zone one item sorts into. `None` is a real answer — a planned plan and a
/// stale-heartbeat session are in no zone, not in a default one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttentionZone {
    /// A human must act.
    NeedsYou,
    /// Work actively in flight.
    Running,
    /// Finished, awaiting review.
    DoneReview,
}

/// The normalised signals [`derive_zone`] classifies on.
///
/// Deliberately not a work item or a session — both feed in, and keeping the
/// classifier over a narrow struct is what makes the truth table testable
/// without constructing either.
#[derive(Debug, Clone, Default)]
pub struct AttentionItem<'a> {
    /// A gated transition referencing this item awaits approval.
    pub gate_pending: bool,
    /// Work state, from `work::WORK_STATES`. `None` for a session.
    pub state: Option<&'a str>,
    /// A session is waiting on the operator. See the module note: this is wired
    /// to a structured signal that does not exist yet and is never inferred.
    pub waiting_for_input: bool,
    /// This item is a live coord session.
    pub live_session: bool,
    /// Coord liveness heartbeat. **Passport-level, not session-level**
    /// (`coord.rs`) — sibling sessions of one passport share it — so a fresh
    /// value means "this identity is around", not "this session is working".
    pub last_seen_unix_ms: Option<u64>,
    /// Finished, awaiting review.
    pub review_pending: bool,
}

/// Sort one item into exactly one zone.
///
/// Precedence is high → low: `needs_you` > `running` > `done_review`. Exactly
/// one zone per item is what keeps the counts from double-counting a gated
/// in-progress plan.
///
/// Staleness: a live session is `running` only while its heartbeat age is in
/// `[0, ATTENTION_LIVENESS_STALE_MS]`. A **future** heartbeat (clock skew, so
/// the age is negative) is not running — treating skew as freshness would let a
/// misconfigured clock manufacture activity that is not happening.
#[must_use]
pub fn derive_zone(item: &AttentionItem<'_>, now_unix_ms: u64) -> Option<AttentionZone> {
    // needs_you — an approval is pending, a plan is blocked, or a session is
    // waiting on a person.
    if item.gate_pending || item.state == Some("blocked") || item.waiting_for_input {
        return Some(AttentionZone::NeedsYou);
    }
    // running — an in_progress plan, or a live session with a fresh heartbeat.
    if item.state == Some("in_progress") {
        return Some(AttentionZone::Running);
    }
    if item.live_session && item.last_seen_unix_ms.is_some_and(|last| is_fresh(last, now_unix_ms)) {
        return Some(AttentionZone::Running);
    }
    // done_review — no `reviewed` flag exists on a WorkItem, so a `complete`
    // plan is by default awaiting review.
    if item.review_pending || item.state == Some("complete") {
        return Some(AttentionZone::DoneReview);
    }
    None
}

/// Heartbeat freshness, with the future-timestamp rule stated once.
fn is_fresh(last_seen_unix_ms: u64, now_unix_ms: u64) -> bool {
    // `checked_sub` is the negative-age branch: a heartbeat from the future
    // yields `None` and is not fresh.
    now_unix_ms
        .checked_sub(last_seen_unix_ms)
        .is_some_and(|age| age <= ATTENTION_LIVENESS_STALE_MS)
}

/// Counts only. See the module docs — this must not grow an item list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AttentionSummary {
    /// Distinct items a human must act on.
    pub needs_you: usize,
    /// Work actively in flight.
    pub running: usize,
    /// Finished, awaiting review.
    pub done_review: usize,
    /// Pending gated transitions. Reported separately because it answers a
    /// different question from `needs_you`: every pending gate is *inside*
    /// `needs_you`, but `needs_you` also counts blocked plans, so an operator
    /// deciding "is there an approval queue?" cannot read it off `needs_you`.
    pub gate_pending: usize,
    /// The clock the classification used, so a caller can tell a genuinely
    /// quiet daemon from a stale response.
    pub now_unix_ms: u64,
}

/// The minimal shape a work item needs to be counted.
///
/// Borrowed rather than owned, and narrow rather than the full `WorkItem`, so
/// the summary path cannot accidentally carry a title or a plan path into a
/// response.
#[derive(Debug, Clone, Copy)]
pub struct WorkSignal<'a> {
    pub id: &'a str,
    pub state: &'a str,
    pub superseded: bool,
}

/// The minimal shape a coord session needs to be counted.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionSignal {
    pub last_seen_unix_ms: u64,
}

/// Roll up the three feeds into counts.
///
/// `gate_work_ids` are the work ids of **pending** gates; `gate_pending_total`
/// is how many pending gates there are in total. They differ whenever two gates
/// reference one work item, or a gate references an item absent from `work`.
///
/// The join by work id is load-bearing, not an optimisation: without it a gated
/// `in_progress` plan is counted once as `needs_you` (via the gate) and again as
/// `running` (via its state), and the two numbers stop summing to anything an
/// operator can act on. Gates whose work item is not in the feed are still
/// counted once — a gate that vanishes from the roll-up because its plan was
/// archived is an approval nobody is told about.
#[must_use]
pub fn summarize(
    work: &[WorkSignal<'_>],
    gate_work_ids: &[&str],
    gate_pending_total: usize,
    sessions: &[SessionSignal],
    now_unix_ms: u64,
) -> AttentionSummary {
    let mut summary = AttentionSummary {
        gate_pending: gate_pending_total,
        now_unix_ms,
        ..Default::default()
    };

    let gated: std::collections::HashSet<&str> = gate_work_ids.iter().copied().collect();
    let mut joined: std::collections::HashSet<&str> = std::collections::HashSet::new();

    for item in work {
        // A superseded plan is not live attention — it was replaced, and the
        // replacement is what carries the work.
        if item.superseded {
            continue;
        }
        let gate_pending = gated.contains(item.id);
        if gate_pending {
            joined.insert(item.id);
        }
        match derive_zone(
            &AttentionItem {
                gate_pending,
                state: Some(item.state),
                ..Default::default()
            },
            now_unix_ms,
        ) {
            Some(AttentionZone::NeedsYou) => summary.needs_you += 1,
            Some(AttentionZone::Running) => summary.running += 1,
            Some(AttentionZone::DoneReview) => summary.done_review += 1,
            None => {}
        }
    }

    // Pending gates with no matching work item still need an operator. Counted
    // by distinct work id, so two gates on one absent item do not inflate the
    // number past the one decision they actually represent.
    let unjoined: std::collections::HashSet<&str> = gated.difference(&joined).copied().collect();
    summary.needs_you += unjoined.len();

    // Sessions are a separate axis from work items, so there is no double-count
    // to guard against here.
    for session in sessions {
        if let Some(AttentionZone::Running) = derive_zone(
            &AttentionItem {
                live_session: true,
                last_seen_unix_ms: Some(session.last_seen_unix_ms),
                ..Default::default()
            },
            now_unix_ms,
        ) {
            summary.running += 1;
        }
    }

    summary
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn work<'a>(id: &'a str, state: &'a str) -> WorkSignal<'a> {
        WorkSignal {
            id,
            state,
            superseded: false,
        }
    }

    const NOW: u64 = 1_700_000_000_000;

    // ── classifier parity with console/v2/render.js ──────────────────────────

    #[test]
    fn the_staleness_window_matches_the_console() {
        // If these drift, two surfaces quote different numbers for the same
        // daemon and an operator cannot tell which is lying.
        assert_eq!(ATTENTION_LIVENESS_STALE_MS, 5 * 60 * 1000);
    }

    #[test]
    fn precedence_is_needs_you_then_running_then_done_review() {
        // A gated in_progress plan is needs_you, NOT running. Getting this
        // backwards is how an item lands in two zones at once.
        let gated_running = AttentionItem {
            gate_pending: true,
            state: Some("in_progress"),
            ..Default::default()
        };
        assert_eq!(derive_zone(&gated_running, NOW), Some(AttentionZone::NeedsYou));

        let gated_complete = AttentionItem {
            gate_pending: true,
            state: Some("complete"),
            ..Default::default()
        };
        assert_eq!(derive_zone(&gated_complete, NOW), Some(AttentionZone::NeedsYou));

        let running = AttentionItem {
            state: Some("in_progress"),
            ..Default::default()
        };
        assert_eq!(derive_zone(&running, NOW), Some(AttentionZone::Running));
    }

    #[test]
    fn blocked_is_needs_you_and_complete_is_awaiting_review() {
        let blocked = AttentionItem {
            state: Some("blocked"),
            ..Default::default()
        };
        assert_eq!(derive_zone(&blocked, NOW), Some(AttentionZone::NeedsYou));

        let complete = AttentionItem {
            state: Some("complete"),
            ..Default::default()
        };
        assert_eq!(derive_zone(&complete, NOW), Some(AttentionZone::DoneReview));
    }

    #[test]
    fn an_idle_plan_is_in_no_zone_rather_than_a_default_one() {
        for state in ["planned", "deployed", "archive", "drafting", "pending_approval"] {
            let item = AttentionItem {
                state: Some(state),
                ..Default::default()
            };
            assert_eq!(derive_zone(&item, NOW), None, "{state} must not occupy a zone");
        }
    }

    #[test]
    fn a_live_session_runs_only_inside_the_staleness_window() {
        let at = |last: u64| {
            derive_zone(
                &AttentionItem {
                    live_session: true,
                    last_seen_unix_ms: Some(last),
                    ..Default::default()
                },
                NOW,
            )
        };

        assert_eq!(at(NOW), Some(AttentionZone::Running), "a beat right now is running");
        assert_eq!(
            at(NOW - ATTENTION_LIVENESS_STALE_MS),
            Some(AttentionZone::Running),
            "the window edge is inclusive, matching the console's `age <= STALE`"
        );
        assert_eq!(
            at(NOW - ATTENTION_LIVENESS_STALE_MS - 1),
            None,
            "one millisecond past the window is idle, not running"
        );
    }

    #[test]
    fn a_heartbeat_from_the_future_is_not_running() {
        // Clock skew must not manufacture activity. The console rules this out
        // with `age >= 0`; here it is `checked_sub` returning None.
        let skewed = AttentionItem {
            live_session: true,
            last_seen_unix_ms: Some(NOW + 1),
            ..Default::default()
        };
        assert_eq!(derive_zone(&skewed, NOW), None);
    }

    #[test]
    fn a_session_with_no_heartbeat_is_not_running() {
        let no_beat = AttentionItem {
            live_session: true,
            ..Default::default()
        };
        assert_eq!(derive_zone(&no_beat, NOW), None);
    }

    // ── roll-up ──────────────────────────────────────────────────────────────

    #[test]
    fn a_gated_in_progress_plan_is_counted_once_not_twice() {
        // The join's whole purpose. Without it this reads needs_you=1 AND
        // running=1 for one plan.
        let summary = summarize(&[work("w1", "in_progress")], &["w1"], 1, &[], NOW);

        assert_eq!(summary.needs_you, 1);
        assert_eq!(
            summary.running, 0,
            "the gate wins; the item must not also count as running"
        );
        assert_eq!(summary.gate_pending, 1);
    }

    #[test]
    fn a_pending_gate_with_no_work_item_still_counts() {
        // A gate whose plan was archived is still an approval somebody owes.
        // Dropping it would make the queue silently shorter than it is.
        let summary = summarize(&[], &["ghost"], 1, &[], NOW);

        assert_eq!(summary.needs_you, 1);
        assert_eq!(summary.gate_pending, 1);
    }

    #[test]
    fn two_gates_on_one_absent_item_are_one_decision() {
        let summary = summarize(&[], &["ghost", "ghost"], 2, &[], NOW);

        assert_eq!(summary.needs_you, 1, "one work item, one attention item");
        assert_eq!(summary.gate_pending, 2, "but two gates are genuinely queued");
    }

    #[test]
    fn gate_pending_is_reported_separately_from_needs_you() {
        // They answer different questions and are not interchangeable: here a
        // blocked plan lifts needs_you without any gate behind it.
        let summary = summarize(
            &[work("w1", "blocked"), work("w2", "in_progress")],
            &["w2"],
            1,
            &[],
            NOW,
        );

        assert_eq!(summary.needs_you, 2, "the blocked plan and the gated one");
        assert_eq!(summary.gate_pending, 1, "only one of them has a gate");
        assert_eq!(summary.running, 0);
    }

    #[test]
    fn a_superseded_plan_is_not_live_attention() {
        let superseded = WorkSignal {
            id: "old",
            state: "blocked",
            superseded: true,
        };
        let summary = summarize(&[superseded], &[], 0, &[], NOW);

        assert_eq!(summary.needs_you, 0, "the replacement carries the work now");
    }

    #[test]
    fn a_superseded_plan_does_not_swallow_its_own_pending_gate() {
        // The item is skipped, so its gate must fall through to the unjoined
        // branch rather than vanishing with it.
        let superseded = WorkSignal {
            id: "old",
            state: "blocked",
            superseded: true,
        };
        let summary = summarize(&[superseded], &["old"], 1, &[], NOW);

        assert_eq!(summary.needs_you, 1, "the approval is still owed");
        assert_eq!(summary.gate_pending, 1);
    }

    #[test]
    fn sessions_add_to_running_without_touching_the_work_axis() {
        let fresh = SessionSignal {
            last_seen_unix_ms: NOW - 1_000,
        };
        let stale = SessionSignal {
            last_seen_unix_ms: NOW - ATTENTION_LIVENESS_STALE_MS - 1,
        };

        let summary = summarize(&[work("w1", "in_progress")], &[], 0, &[fresh, stale], NOW);

        assert_eq!(summary.running, 2, "one in_progress plan + one fresh session");
        assert_eq!(summary.needs_you, 0);
        assert_eq!(summary.done_review, 0);
    }

    #[test]
    fn a_quiet_daemon_reports_zeroes_and_a_clock() {
        // Distinguishing "nothing needs you" from "the response is stale" is
        // the only reason a clock is in a counts-only payload.
        let summary = summarize(&[], &[], 0, &[], NOW);

        assert_eq!(
            summary,
            AttentionSummary {
                needs_you: 0,
                running: 0,
                done_review: 0,
                gate_pending: 0,
                now_unix_ms: NOW,
            }
        );
    }

    #[test]
    fn the_payload_carries_counts_and_nothing_identifying() {
        // The frozen-subset boundary, asserted rather than documented: this is
        // servable to a hosted viewer precisely because the serialised shape
        // has no room for a title, a path or a passport.
        let summary = summarize(
            &[work("secret-plan-slug", "blocked")],
            &["secret-plan-slug"],
            1,
            &[SessionSignal { last_seen_unix_ms: NOW }],
            NOW,
        );

        let json = serde_json::to_value(summary).expect("summary must serialise");
        let object = json.as_object().expect("an object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["done_review", "gate_pending", "needs_you", "now_unix_ms", "running"],
            "adding a field here changes what a hosted viewer can see"
        );
        assert!(
            !json.to_string().contains("secret-plan-slug"),
            "no identifier may reach the wire"
        );
    }
}
