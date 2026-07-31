// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `repo_allowance` — how many repos a Pro account may aggregate, and how many it uses.
//!
//! ExecPlan `crux-code-intel-pro-hosted-surface-2026-07-28`, milestone M1.
//!
//! # What this is not
//!
//! **Accounting only. Nothing here blocks, degrades or refuses anything.** M1's
//! gate is explicitly "zero behaviour change for any existing caller": the numbers
//! are computed and reported so the shape can be checked against reality before
//! any of it is load-bearing. Enforcement is M4, and the retained-span ceiling
//! that actually protects margin is M5.
//!
//! # Why repos are counted at all
//!
//! Repo count is the meter the customer *buys*, because it is the one they can
//! predict. It is deliberately **not** the thing that costs CueCrux money — that
//! is retained span volume, and two repos with different traffic differ by orders
//! of magnitude (M5 spec §4). Keeping those two limits in separate milestones is
//! the plan's Constraint 1; this module is only ever the first of the pair, and
//! must not grow into the second.
//!
//! # Seats
//!
//! Seat count is **not yet sourced from the subscription** — that arrives with the
//! entitlement work in `crux-pro-capabilities-rcx-entitled-2026-07-27`. Until then
//! the caller supplies it, and the default of one seat is the honest reading of
//! "we do not know yet" rather than a claim about the account.

use serde::{Deserialize, Serialize};

use crate::repo_registry::{self, RepoRegistration};

/// Repos included before any add-on, per account, regardless of seat count.
///
/// Frozen at M0 (fact `gate:M0`). The base exists so a solo developer is not at
/// the wall immediately: one seat resolves to eight repos, which covers the
/// common case, while a large team's allowance still tracks its seats.
pub const BASE_REPOS_PER_ACCOUNT: u32 = 5;

/// Additional repos included per seat, pooled across the account.
pub const REPOS_PER_SEAT: u32 = 3;

/// Repos added by one purchased pack.
pub const REPOS_PER_PACK: u32 = 10;

/// The included-repo formula, so a caller can report what it applied rather than
/// restating the constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowanceFormula {
    pub base_per_account: u32,
    pub per_seat: u32,
    pub per_pack: u32,
}

impl Default for AllowanceFormula {
    fn default() -> Self {
        Self {
            base_per_account: BASE_REPOS_PER_ACCOUNT,
            per_seat: REPOS_PER_SEAT,
            per_pack: REPOS_PER_PACK,
        }
    }
}

impl AllowanceFormula {
    /// Included repos for `seats` seats plus `packs` purchased packs.
    ///
    /// Saturating throughout: an absurd seat count reports a huge allowance rather
    /// than wrapping to a small one. Reporting "unlimited-ish" is a visible
    /// nonsense; wrapping to a tiny allowance would look like a real limit and
    /// would be acted on.
    pub fn included(&self, seats: u32, packs: u32) -> u32 {
        self.base_per_account
            .saturating_add(self.per_seat.saturating_mul(seats))
            .saturating_add(self.per_pack.saturating_mul(packs))
    }
}

/// What an account is entitled to and what it is using.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoAllowance {
    pub tenant_id: String,
    pub seats: u32,
    pub packs: u32,
    /// Repos included by the formula.
    pub included: u32,
    /// Enabled registrations counted against the allowance.
    pub used: u32,
    /// Registrations present but disabled. Reported separately because they cost
    /// nothing to aggregate and so are deliberately *not* charged.
    pub disabled: u32,
    /// `used` beyond `included`, or zero. Non-zero is a commercial signal, not a
    /// technical one — see the module docs.
    pub over_by: u32,
    /// Whether `used` exceeds `included`.
    pub over_allowance: bool,
    /// Headroom remaining, or zero when over.
    pub remaining: u32,
    pub formula: AllowanceFormula,
}

/// Count `repos` against `seats`/`packs` under `formula`.
///
/// Split from the store read so the arithmetic is testable without a fact store,
/// and so the counting rule has exactly one definition.
pub fn allowance_for(
    tenant_id: &str,
    repos: &[RepoRegistration],
    seats: u32,
    packs: u32,
    formula: AllowanceFormula,
) -> RepoAllowance {
    // Disabled repos are not aggregated, so they do not consume allowance. A user
    // who disables a repo to get under the line has genuinely stopped costing us
    // anything, and billing them for it would be indefensible.
    let used = u32::try_from(repos.iter().filter(|r| r.enabled).count()).unwrap_or(u32::MAX);
    let disabled = u32::try_from(repos.iter().filter(|r| !r.enabled).count()).unwrap_or(u32::MAX);
    let included = formula.included(seats, packs);

    RepoAllowance {
        tenant_id: tenant_id.to_string(),
        seats,
        packs,
        included,
        used,
        disabled,
        over_by: used.saturating_sub(included),
        over_allowance: used > included,
        remaining: included.saturating_sub(used),
        formula,
    }
}

/// Read the registry and report the allowance for one tenant.
pub fn allowance_for_tenant(
    store: &corecrux_memory::fact_store::FactStore,
    tenant_id: &str,
    seats: u32,
    packs: u32,
) -> RepoAllowance {
    let repos = repo_registry::list_repos(store, tenant_id);
    allowance_for(tenant_id, &repos, seats, packs, AllowanceFormula::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(repo_id: &str, tenant_id: &str, enabled: bool) -> RepoRegistration {
        RepoRegistration {
            repo_id: repo_id.to_string(),
            tenant_id: tenant_id.to_string(),
            root_path: None,
            clone_url: None,
            languages: Vec::new(),
            enabled,
            added_at_unix_ms: 0,
            generation_id: format!("fixture-{tenant_id}-{repo_id}"),
            last_scan_id: None,
            scan_status: None,
            scan_error: None,
            scan_queued_at_unix_ms: None,
            scan_finished_at_unix_ms: None,
        }
    }

    #[test]
    fn one_seat_includes_the_base_plus_one_seats_worth() {
        // The M0 example: 1 seat = 8. If this number moves, the pricing page and
        // the fact `gate:M0` move with it.
        assert_eq!(AllowanceFormula::default().included(1, 0), 8);
        assert_eq!(AllowanceFormula::default().included(5, 0), 20);
        assert_eq!(AllowanceFormula::default().included(10, 0), 35);
    }

    #[test]
    fn a_pack_adds_exactly_ten() {
        let f = AllowanceFormula::default();
        assert_eq!(f.included(1, 1), 18);
        assert_eq!(f.included(1, 2), 28);
    }

    #[test]
    fn zero_seats_still_gets_the_account_base() {
        // An account with no seats resolved yet must not report a negative or
        // zero allowance — it reports the base, which is what it is entitled to.
        assert_eq!(AllowanceFormula::default().included(0, 0), 5);
    }

    #[test]
    fn only_enabled_repos_consume_allowance() {
        let repos = vec![reg("a", "t1", true), reg("b", "t1", true), reg("c", "t1", false)];
        let a = allowance_for("t1", &repos, 1, 0, AllowanceFormula::default());
        assert_eq!(a.used, 2, "disabled repo must not be charged");
        assert_eq!(a.disabled, 1);
        assert!(!a.over_allowance);
        assert_eq!(a.remaining, 6);
    }

    #[test]
    fn over_allowance_reports_the_overage_without_clamping_used() {
        // 9 enabled against an 8-repo allowance. `used` must stay truthful at 9;
        // reporting 8 would hide the thing the number exists to surface.
        let repos: Vec<_> = (0..9).map(|i| reg(&format!("r{i}"), "t1", true)).collect();
        let a = allowance_for("t1", &repos, 1, 0, AllowanceFormula::default());
        assert_eq!(a.used, 9);
        assert_eq!(a.included, 8);
        assert!(a.over_allowance);
        assert_eq!(a.over_by, 1);
        assert_eq!(a.remaining, 0, "remaining floors at zero, never wraps");
    }

    #[test]
    fn exactly_at_the_line_is_not_over() {
        let repos: Vec<_> = (0..8).map(|i| reg(&format!("r{i}"), "t1", true)).collect();
        let a = allowance_for("t1", &repos, 1, 0, AllowanceFormula::default());
        assert_eq!(a.used, 8);
        assert!(!a.over_allowance, "at the limit is within it");
        assert_eq!(a.over_by, 0);
        assert_eq!(a.remaining, 0);
    }

    #[test]
    fn a_pack_restores_headroom_for_an_over_allowance_account() {
        // The M4 promise, checked at the arithmetic level: buying a pack must
        // move an over-allowance account back under without anything else changing.
        let repos: Vec<_> = (0..9).map(|i| reg(&format!("r{i}"), "t1", true)).collect();
        let before = allowance_for("t1", &repos, 1, 0, AllowanceFormula::default());
        let after = allowance_for("t1", &repos, 1, 1, AllowanceFormula::default());
        assert!(before.over_allowance);
        assert!(!after.over_allowance);
        assert_eq!(after.remaining, 9);
        assert_eq!(after.used, before.used, "buying a pack changes entitlement, not usage");
    }

    #[test]
    fn an_absurd_seat_count_saturates_rather_than_wrapping() {
        // u32::MAX seats would overflow per_seat * seats. Saturating means the
        // account reports an enormous allowance; wrapping would report a tiny one
        // and read as a real limit.
        let f = AllowanceFormula::default();
        assert_eq!(f.included(u32::MAX, 0), u32::MAX);
        assert_eq!(f.included(u32::MAX, u32::MAX), u32::MAX);
    }

    #[test]
    fn counting_is_order_independent() {
        // Add/remove/disable in any order must converge to the same count — the
        // registry has no ordering guarantee this could accidentally depend on.
        let a = vec![reg("x", "t1", true), reg("y", "t1", false), reg("z", "t1", true)];
        let b = vec![reg("z", "t1", true), reg("x", "t1", true), reg("y", "t1", false)];
        let fa = allowance_for("t1", &a, 2, 0, AllowanceFormula::default());
        let fb = allowance_for("t1", &b, 2, 0, AllowanceFormula::default());
        assert_eq!(fa.used, fb.used);
        assert_eq!(fa.disabled, fb.disabled);
        assert_eq!(fa, fb);
    }

    #[test]
    fn an_empty_account_is_not_over_allowance() {
        let a = allowance_for("t1", &[], 1, 0, AllowanceFormula::default());
        assert_eq!(a.used, 0);
        assert!(!a.over_allowance);
        assert_eq!(a.remaining, 8);
    }
}
