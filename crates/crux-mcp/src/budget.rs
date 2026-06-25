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

/// M1 part 2 — fact-path reversible overflow. Greedy boundary: the number of
/// leading facts (ranked order) whose **full** token costs fit within `budget`;
/// every fact past the boundary is *demoted* to an epitome-only pointer instead
/// of dropped. At least one fact is always full (a tiny budget still hydrates the
/// top hit). The fact path differs from the segment path in that the full text is
/// inline (`fact.value`), so the demote target is the epitome tier the CRC-v1
/// `wrap_facts` envelope already emits — no separate hydration round-trip.
pub fn fact_full_within_budget(token_costs: &[usize], budget: usize) -> usize {
    let mut used = 0usize;
    let mut full = 0usize;
    for &cost in token_costs {
        if full > 0 && used + cost > budget {
            break;
        }
        used += cost;
        full += 1;
        if used >= budget {
            break;
        }
    }
    full.max(1).min(token_costs.len())
}

/// M1 part 2 — OD-A content hash. A short, stable, dependency-free digest of a
/// fact value, carried on a *demoted* fact pointer so a caller can detect
/// staleness when it re-addresses the fact (entity+key): a hash mismatch means
/// the value changed; a "no facts found" re-address means it was forgotten
/// (evicted). Change-detection only — not security-sensitive. FNV-1a + a
/// splitmix64 finalizer (mirrors `crate::holdout`), rendered as 16 hex chars.
pub fn content_hash(value: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in value.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash = hash.wrapping_add(0x9e37_79b9_7f4a_7c15);
    hash = (hash ^ (hash >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash = (hash ^ (hash >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^= hash >> 31;
    format!("{hash:016x}")
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

    // ---- M1 part 2 — fact-path reversible overflow -------------------------

    #[test]
    fn fact_boundary_matches_legacy_drop_count() {
        // Drop→demote parity: the boundary must equal the count the legacy
        // store-budget drop kept (facts.rs: `used + tokens > budget` stops BEFORE
        // admitting the over-budget fact). costs 100,100,100,100 @ budget 250 ⇒
        // keep 2 full (used 200; the 3rd would cross 250), demote the rest.
        let costs = [100, 100, 100, 100];
        assert_eq!(fact_full_within_budget(&costs, 250), 2);
    }

    #[test]
    fn fact_boundary_always_hydrates_at_least_one() {
        // Even a budget smaller than the top fact keeps that fact full (the rest
        // demote) rather than returning nothing.
        assert_eq!(fact_full_within_budget(&[500, 80, 80], 100), 1);
        assert_eq!(fact_full_within_budget(&[], 100), 0); // …but no facts ⇒ 0
    }

    #[test]
    fn fact_boundary_all_fit_under_budget() {
        assert_eq!(fact_full_within_budget(&[10, 10, 10], 1000), 3);
    }

    #[test]
    fn content_hash_is_stable_and_change_sensitive() {
        let a = content_hash("status = green");
        assert_eq!(a, content_hash("status = green"), "stable for identical input");
        assert_ne!(a, content_hash("status = red"), "changes when the value changes");
        assert_eq!(a.len(), 16, "16 hex chars");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
