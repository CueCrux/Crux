// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! M1 — reversible overflow on `token_budget` (Headroom *CCR* analogue).
//!
//! ExecPlan: `crux-headroom-token-efficiency-learnings-2026-06-24` (milestone M1,
//! part 1 — the segment `query` path).
//!
//! **The bug the M0 baseline measured.** `tools::query` enforces `token_budget`
//! with a `take_while` over each hit's *full-doc* token count
//! (`doc_length_tokens`) and *drops* every hit past the cut. But the daemon's
//! segment query is metadata-only: it emits *pointers* (`result_id` + score),
//! never the doc text (text lives in the dataplane frame store, out of this
//! repo). So the budget is charged at the **hydration** price while the response
//! only ever pays the **pointer** price — a mismatch that over-drops: at budget
//! 500 the baseline kept just 2 of 30 candidates for a 348-token payload.
//!
//! **The fix (OD-B, resolved):** budget the *emitted* tier. A pointer costs
//! [`POINTER_TOKENS`] (mirrors the CRC-v1 `cost_estimate.pointer` weight), so a
//! budget of `B` admits `B / POINTER_TOKENS` pointers — far more candidates for
//! the same token budget (500 → ~12, a 6× recall lift) while the *emitted*
//! payload still respects the asked budget (QC.2). The full-doc hydration price
//! stays visible in `cost_estimate.full`, and `total_candidates` discloses any
//! capped remainder, so nothing is silently lost: the agent expands the pointers
//! it wants via `query_expand` (handle = `result_id`, OD-A).
//!
//! Flag `CRUX_BUDGET_REVERSIBLE` (default **OFF**). OFF ⇒ the legacy
//! `take_while`-drop, byte-identical to pre-M1.

/// Per-pointer token weight — mirrors `crc_v1`'s `cost_estimate.pointer`
/// (`n * 40`). The reversible budget admits `budget / POINTER_TOKENS` pointers.
pub const POINTER_TOKENS: usize = 40;

/// Env flag name for M1 reversible overflow. Default OFF.
pub const REVERSIBLE_ENV: &str = "CRUX_BUDGET_REVERSIBLE";

/// Truthy-env parse matching the crate convention (see `ledger::env_truthy`).
fn env_truthy(var: &str) -> bool {
    match std::env::var(var) {
        Ok(v) => {
            let v = v.trim().to_ascii_lowercase();
            !matches!(v.as_str(), "" | "0" | "false" | "off" | "no")
        }
        Err(_) => false,
    }
}

/// True when reversible overflow is enabled via `CRUX_BUDGET_REVERSIBLE`.
pub fn reversible_enabled() -> bool {
    env_truthy(REVERSIBLE_ENV)
}

/// Number of pointers that fit `budget` at the emitted pointer price (≥1, so a
/// tiny budget still returns the top hit rather than nothing).
pub fn pointers_within_budget(budget: usize) -> usize {
    (budget / POINTER_TOKENS).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_budget_admits_more_than_full_doc_drop() {
        // Budget 500: at the pointer price we admit 12; the legacy full-doc
        // take_while admitted ~2 in the M0 baseline. Strict recall lift.
        assert_eq!(pointers_within_budget(500), 12);
        assert_eq!(pointers_within_budget(2000), 50);
        assert_eq!(pointers_within_budget(4000), 100);
    }

    #[test]
    fn tiny_budget_still_returns_one() {
        assert_eq!(pointers_within_budget(0), 1);
        assert_eq!(pointers_within_budget(10), 1);
    }

    #[test]
    fn env_truthy_matches_convention() {
        std::env::set_var("CRUX_BUDGET_REVERSIBLE_TEST_A", "1");
        assert!(env_truthy("CRUX_BUDGET_REVERSIBLE_TEST_A"));
        std::env::set_var("CRUX_BUDGET_REVERSIBLE_TEST_A", "no");
        assert!(!env_truthy("CRUX_BUDGET_REVERSIBLE_TEST_A"));
        std::env::remove_var("CRUX_BUDGET_REVERSIBLE_TEST_A");
        assert!(!env_truthy("CRUX_BUDGET_REVERSIBLE_TEST_A"));
    }
}
