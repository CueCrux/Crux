// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `enrich_budget` — the per-seat rate ceiling on LLM-enriched verdicts.
//!
//! ExecPlan `crux-code-intel-pro-hosted-surface-2026-07-28`, milestone M8.
//!
//! # Why a ceiling when there is already a wallet
//!
//! The credit wallet already refuses when an account runs out of credit, so a
//! ceiling that also counted *per month* would bind at the same moment and add
//! nothing: at 5cr a verdict, Pro's 1000cr grant is 200 verdicts either way.
//!
//! What the wallet cannot do is bound the **rate**. The wallet is account-wide,
//! so one agent in a loop can burn a whole team's monthly grant in minutes, and
//! the first anyone knows is a `402` for everybody. This ceiling is per seat and
//! per rolling window, so a runaway loop costs that seat its hour and leaves the
//! rest of the account working.
//!
//! That is the margin-inversion protection the plan asked for. Enrichment is the
//! one rung whose cost is per-call and unbounded, and it is the only place in
//! this program where a single customer can cost more than they pay.
//!
//! # Why the default is far above normal use
//!
//! 200 verdicts a month is roughly seven a day. A ceiling of 20 an hour is an
//! order of magnitude above any human-paced use and still stops a loop within
//! seconds. A limit tuned close to normal use would fire on legitimate bursts
//! and teach people to ignore it.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// Enriched verdicts one seat may request per window.
pub const SEAT_CEILING_ENV: &str = "CORECRUXD_ENRICH_SEAT_CEILING";
/// Window length in seconds.
pub const SEAT_WINDOW_SECS_ENV: &str = "CORECRUXD_ENRICH_SEAT_WINDOW_SECS";

const DEFAULT_SEAT_CEILING: u32 = 20;
const DEFAULT_WINDOW_SECS: u64 = 3_600;

/// Percent of ceiling at which the caller is warned.
///
/// Same threshold as the retained-span ceiling, for the same reason: a limit
/// whose first signal is a refusal is a support ticket, not a limit.
pub const APPROACH_PCT: u32 = 80;

pub fn seat_ceiling() -> u32 {
    std::env::var(SEAT_CEILING_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_SEAT_CEILING)
        .max(1)
}

pub fn window_secs() -> u64 {
    std::env::var(SEAT_WINDOW_SECS_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_WINDOW_SECS)
        .max(1)
}

/// What one seat has spent against its ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrichBudget {
    pub tenant_id: String,
    pub seat_id: String,
    pub used_in_window: u32,
    pub ceiling: u32,
    pub window_secs: u64,
    pub remaining: u32,
    pub pct_of_ceiling: u32,
    /// At or past [`APPROACH_PCT`]. Readable **before** the ceiling bites.
    pub approaching: bool,
    pub at_ceiling: bool,
}

/// Rolling-window counters, keyed by `(tenant, seat)`.
///
/// Deliberately in-memory. A rate ceiling that survives restart would need to be
/// durable, and durability here would mean a disk write on the hot path of every
/// enrichment to defend against an attacker who can restart the daemon — which is
/// a different threat model entirely. Restarting resets the window, and that is
/// an accepted, stated limit rather than an oversight.
#[derive(Default)]
pub struct EnrichBudgets {
    hits: HashMap<(String, String), Vec<Instant>>,
}

impl EnrichBudgets {
    /// Drop timestamps that have fallen out of the window.
    fn prune(&mut self, key: &(String, String), now: Instant, window: Duration) {
        if let Some(v) = self.hits.get_mut(key) {
            v.retain(|t| now.duration_since(*t) < window);
            if v.is_empty() {
                self.hits.remove(key);
            }
        }
    }

    /// Report without consuming. This is what makes the counter visible before
    /// the limit rather than at it.
    pub fn peek(&mut self, tenant_id: &str, seat_id: &str) -> EnrichBudget {
        self.peek_at(tenant_id, seat_id, Instant::now())
    }

    fn peek_at(&mut self, tenant_id: &str, seat_id: &str, now: Instant) -> EnrichBudget {
        let key = (tenant_id.to_string(), seat_id.to_string());
        let window = Duration::from_secs(window_secs());
        self.prune(&key, now, window);
        let ceiling = seat_ceiling();
        let used = u32::try_from(self.hits.get(&key).map_or(0, Vec::len)).unwrap_or(u32::MAX);
        let pct = used.saturating_mul(100) / ceiling.max(1);
        EnrichBudget {
            tenant_id: tenant_id.to_string(),
            seat_id: seat_id.to_string(),
            used_in_window: used,
            ceiling,
            window_secs: window.as_secs(),
            remaining: ceiling.saturating_sub(used),
            pct_of_ceiling: pct,
            approaching: pct >= APPROACH_PCT,
            at_ceiling: used >= ceiling,
        }
    }

    /// Take one from the seat's allowance, or report that it is exhausted.
    ///
    /// Returns the budget *after* a successful take, so a caller can surface the
    /// remaining headroom on the same response that used some of it.
    pub fn try_consume(&mut self, tenant_id: &str, seat_id: &str) -> Result<EnrichBudget, EnrichBudget> {
        self.try_consume_at(tenant_id, seat_id, Instant::now())
    }

    fn try_consume_at(&mut self, tenant_id: &str, seat_id: &str, now: Instant) -> Result<EnrichBudget, EnrichBudget> {
        let before = self.peek_at(tenant_id, seat_id, now);
        if before.at_ceiling {
            return Err(before);
        }
        let key = (tenant_id.to_string(), seat_id.to_string());
        self.hits.entry(key).or_default().push(now);
        Ok(self.peek_at(tenant_id, seat_id, now))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budgets() -> EnrichBudgets {
        EnrichBudgets::default()
    }

    #[test]
    #[serial_test::serial]
    fn a_deliberate_loop_is_stopped_at_the_ceiling() {
        // The M8 gate. An agent that calls in a tight loop must be cut off, and
        // cut off at a bounded cost rather than after burning the account.
        std::env::set_var(SEAT_CEILING_ENV, "5");
        let mut b = budgets();
        for i in 0..5 {
            assert!(b.try_consume("t1", "seat-a").is_ok(), "call {i} should be admitted");
        }
        for i in 0..100 {
            let refused = b.try_consume("t1", "seat-a");
            assert!(refused.is_err(), "loop iteration {i} must be refused");
            let budget = refused.unwrap_err();
            assert!(budget.at_ceiling);
            assert_eq!(budget.remaining, 0);
            assert_eq!(
                budget.used_in_window, 5,
                "a refused call must not count against the seat — otherwise a loop \
                 inflates its own usage and the number stops meaning anything"
            );
        }
        std::env::remove_var(SEAT_CEILING_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn the_counter_is_readable_before_the_ceiling_bites() {
        // "Visible before the limit, not at it." A caller must be able to see
        // the approach without triggering it.
        std::env::set_var(SEAT_CEILING_ENV, "10");
        let mut b = budgets();
        for _ in 0..8 {
            b.try_consume("t1", "seat-a").expect("under ceiling");
        }
        let v = b.peek("t1", "seat-a");
        assert_eq!(v.used_in_window, 8);
        assert_eq!(v.pct_of_ceiling, 80);
        assert!(v.approaching, "80% must warn");
        assert!(!v.at_ceiling, "80% is not the limit — the warning precedes refusal");
        assert_eq!(v.remaining, 2);
        std::env::remove_var(SEAT_CEILING_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn peeking_never_consumes() {
        std::env::set_var(SEAT_CEILING_ENV, "3");
        let mut b = budgets();
        for _ in 0..50 {
            let v = b.peek("t1", "seat-a");
            assert_eq!(v.used_in_window, 0, "reading the counter must not spend the budget");
        }
        assert!(b.try_consume("t1", "seat-a").is_ok());
        std::env::remove_var(SEAT_CEILING_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn one_seat_cannot_exhaust_another() {
        // The whole point of being per seat rather than per account: a runaway
        // agent costs its own seat its window and leaves colleagues working.
        std::env::set_var(SEAT_CEILING_ENV, "2");
        let mut b = budgets();
        assert!(b.try_consume("t1", "noisy").is_ok());
        assert!(b.try_consume("t1", "noisy").is_ok());
        assert!(b.try_consume("t1", "noisy").is_err(), "noisy seat exhausted");

        assert!(
            b.try_consume("t1", "quiet").is_ok(),
            "a quiet seat keeps its own headroom"
        );
        assert_eq!(b.peek("t1", "quiet").used_in_window, 1);
        std::env::remove_var(SEAT_CEILING_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn one_tenant_cannot_exhaust_another_with_the_same_seat_name() {
        // `seat-a` is not globally unique; two accounts may both have one.
        std::env::set_var(SEAT_CEILING_ENV, "1");
        let mut b = budgets();
        assert!(b.try_consume("tenant-a", "seat-a").is_ok());
        assert!(b.try_consume("tenant-a", "seat-a").is_err());
        assert!(
            b.try_consume("tenant-b", "seat-a").is_ok(),
            "a same-named seat in another tenant must have its own budget"
        );
        std::env::remove_var(SEAT_CEILING_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn the_window_rolls_so_a_seat_recovers() {
        // A ceiling that never released would be a ban, not a rate limit.
        std::env::set_var(SEAT_CEILING_ENV, "2");
        std::env::set_var(SEAT_WINDOW_SECS_ENV, "60");
        let mut b = budgets();
        let t0 = Instant::now();
        assert!(b.try_consume_at("t1", "seat-a", t0).is_ok());
        assert!(b.try_consume_at("t1", "seat-a", t0).is_ok());
        assert!(
            b.try_consume_at("t1", "seat-a", t0).is_err(),
            "exhausted inside the window"
        );

        let later = t0 + Duration::from_secs(61);
        assert!(
            b.try_consume_at("t1", "seat-a", later).is_ok(),
            "past the window the seat recovers"
        );
        assert_eq!(b.peek_at("t1", "seat-a", later).used_in_window, 1);
        std::env::remove_var(SEAT_CEILING_ENV);
        std::env::remove_var(SEAT_WINDOW_SECS_ENV);
    }

    #[test]
    #[serial_test::serial]
    fn an_empty_seat_reports_full_headroom_not_an_error() {
        std::env::set_var(SEAT_CEILING_ENV, "20");
        let mut b = budgets();
        let v = b.peek("t1", "never-used");
        assert_eq!(v.used_in_window, 0);
        assert_eq!(v.remaining, 20);
        assert!(!v.approaching);
        assert!(!v.at_ceiling);
        std::env::remove_var(SEAT_CEILING_ENV);
    }
}
