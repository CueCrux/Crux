// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Whole-response token budgeting.
//!
//! ExecPlan: `crux-memory-parity-and-codex-bridge-2026-09-17`, milestone M1.
//!
//! ## The defect this closes
//!
//! `token_budget` used to govern only the **fact tier** — the rows selected out
//! of the store ([`crate::budget::fact_emit_within_budget`] and the equivalent
//! `take_within_budget` on the HTTP side). Everything wrapped around those rows
//! — the CRC-v1 envelope, `cost_estimate`, `agent_decision`, `next`, `meta`, the
//! inline `content[]` and, on the MCP surface, the legacy `structuredContent.rows`
//! duplicate — was unmetered. Measured on the live daemon: a `query_facts` call
//! with `token_budget=300` returned **12,034 bytes** (~3,000 tokens), a 10x
//! overrun of the number the caller set.
//!
//! ## What this module does
//!
//! [`fit`] takes the budget, the candidate row count, and a builder that can
//! render the response at any `(full, emitted)` hydration pair, and searches for
//! the largest pair whose **fully serialised** response fits. The search is
//! monotone in both knobs (fewer hydrated rows ⇒ fewer bytes; fewer emitted rows
//! ⇒ fewer bytes), so a binary search is exact and costs `O(log n)` builds.
//!
//! Degradation ladder, in order:
//! 1. every row hydrated (`full == emitted == rows`) — the pre-M1 shape,
//! 2. demote rows to epitome-only pointers (`full` shrinks; nothing dropped),
//! 3. drop pointers beyond the budget (`emitted` shrinks; `total_candidates`
//!    discloses the remainder),
//! 4. if not even `(0, 0)` fits, return the pointer tier with one addressable
//!    row and report [`FitOutcome::fits`] `== false` — the caller is told the
//!    budget could not be honoured rather than being handed a silent overrun.
//!
//! The builder is called with `(rows, rows)` first, so a response already inside
//! its budget is rendered exactly once and byte-identically to the pre-M1 path.

use serde_json::Value;

/// What [`fit`] settled on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FitOutcome {
    /// Rows hydrated with inline content.
    pub full: usize,
    /// Rows present in the response at all (hydrated or epitome-only).
    pub emitted: usize,
    /// Estimated tokens of the serialised response that was chosen.
    pub tokens: u64,
    /// `false` when even the minimal `(0, 0)` response exceeds the budget. The
    /// response is then the pointer tier with one addressable row, and the
    /// caller discloses the overrun rather than pretending the budget held.
    pub fits: bool,
}

/// Estimated token cost of a candidate response.
fn cost(value: &Value) -> u64 {
    crate::token_estimate::estimate_tokens(value)
}

/// The budget disclosure block, in its **widest** form.
///
/// The disclosure is part of the response, so it has to be inside the budget it
/// reports on — a block added after [`fit`] measured would push the response
/// back over. The builder therefore emits this placeholder (`u64::MAX` digits,
/// `within_budget: false` — the wider of the two booleans) and
/// [`finalize_block`] overwrites it once the shape is settled. Substitution can
/// only narrow the JSON, so the measured bound still holds.
pub fn placeholder_block(
    token_budget: usize,
    governs: &str,
    full: usize,
    emitted: usize,
    total_candidates: usize,
) -> Value {
    serde_json::json!({
        "token_budget": token_budget,
        "tokens_emitted": u64::MAX,
        "governs": governs,
        "rows_hydrated": full,
        "rows_emitted": emitted,
        "rows_dropped": total_candidates.saturating_sub(emitted),
        "within_budget": false,
    })
}

/// Replace the [`placeholder_block`] at `pointer` with the settled numbers.
///
/// `tokens_emitted` is measured with the placeholder still in place, so it is an
/// upper bound on the final payload — it never understates what the caller pays.
pub fn finalize_block(result: &mut Value, pointer: &str, token_budget: usize) {
    let measured = cost(result);
    let Some(block) = result.pointer_mut(pointer).and_then(Value::as_object_mut) else {
        return;
    };
    block.insert("tokens_emitted".into(), serde_json::json!(measured));
    block.insert(
        "within_budget".into(),
        serde_json::json!(measured <= token_budget as u64),
    );
}

/// Shrink `build(full, emitted)` until the whole serialised response fits
/// `budget` tokens.
///
/// `build` must be pure with respect to its arguments and must satisfy
/// `full <= emitted <= rows`; [`fit`] never calls it outside that range.
pub fn fit<F>(budget: usize, rows: usize, mut build: F) -> (Value, FitOutcome)
where
    F: FnMut(usize, usize) -> Value,
{
    let budget = budget as u64;

    // Tier 1 — everything hydrated. The common case: one build, byte-identical
    // to the pre-M1 response when it already fits.
    let candidate = build(rows, rows);
    let tokens = cost(&candidate);
    if tokens <= budget {
        return (
            candidate,
            FitOutcome {
                full: rows,
                emitted: rows,
                tokens,
                fits: true,
            },
        );
    }

    // Tier 2 — demote hydrated rows to epitome-only pointers, keeping every
    // candidate addressable. Largest `full` in 0..rows that fits.
    let all_demoted = build(0, rows);
    if cost(&all_demoted) <= budget {
        let (value, full, tokens) = largest_fitting(budget, rows, |n| build(n, rows), all_demoted);
        return (
            value,
            FitOutcome {
                full,
                emitted: rows,
                tokens,
                fits: true,
            },
        );
    }

    // Tier 3 — drop pointers beyond the budget. Largest `emitted` that fits.
    let minimal = build(0, 0);
    let minimal_tokens = cost(&minimal);
    if minimal_tokens > budget {
        // Tier 4 — the budget cannot fit even one pointer. Return the pointer
        // tier anyway (one addressable row, so the caller has somewhere to go)
        // and SAY SO via `fits: false`, rather than silently returning nothing
        // or silently overrunning.
        let floor_rows = rows.min(1);
        let floor = build(0, floor_rows);
        let floor_tokens = cost(&floor);
        return (
            floor,
            FitOutcome {
                full: 0,
                emitted: floor_rows,
                tokens: floor_tokens,
                fits: false,
            },
        );
    }
    let (value, emitted, tokens) = largest_fitting(budget, rows, |n| build(0, n), minimal);
    (
        value,
        FitOutcome {
            full: 0,
            emitted,
            tokens,
            fits: true,
        },
    )
}

/// Binary-search the largest `n` in `0..=hi` for which `build(n)` fits `budget`,
/// given that `build(0)` already fits and produced `zero_value`.
fn largest_fitting<F>(budget: u64, hi: usize, mut build: F, zero_value: Value) -> (Value, usize, u64)
where
    F: FnMut(usize) -> Value,
{
    let mut best_tokens = cost(&zero_value);
    let mut best = (zero_value, 0usize);
    let mut low = 1usize;
    let mut high = hi;
    while low <= high {
        let mid = low + (high - low) / 2;
        let candidate = build(mid);
        let tokens = cost(&candidate);
        if tokens <= budget {
            best = (candidate, mid);
            best_tokens = tokens;
            low = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            high = mid - 1;
        }
    }
    (best.0, best.1, best_tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A response whose size grows with both knobs: `emitted` pointers plus
    /// `full` inline bodies, around a fixed envelope.
    fn builder(full: usize, emitted: usize) -> Value {
        assert!(full <= emitted, "fit must never ask for full > emitted");
        let pointers: Vec<Value> = (0..emitted).map(|i| json!({"id": format!("f_{i:04}")})).collect();
        let content: Vec<Value> = (0..full)
            .map(|i| json!({"id": format!("f_{i:04}"), "text": "x".repeat(200)}))
            .collect();
        json!({"envelope": {"scaffolding": "fixed"}, "pointers": pointers, "content": content})
    }

    #[test]
    fn already_inside_budget_is_returned_untouched() {
        let (value, outcome) = fit(100_000, 5, builder);
        assert!(outcome.fits);
        assert_eq!(outcome.full, 5);
        assert_eq!(outcome.emitted, 5);
        assert_eq!(value, builder(5, 5));
    }

    #[test]
    fn overflow_demotes_content_before_dropping_pointers() {
        // 20 rows * 200 chars of content = far over; pointers alone are cheap.
        let (value, outcome) = fit(200, 20, builder);
        assert!(outcome.fits);
        assert_eq!(outcome.emitted, 20, "nothing dropped while demotion suffices");
        assert!(outcome.full < 20);
        assert!(outcome.tokens <= 200, "{}", outcome.tokens);
        assert_eq!(value["pointers"].as_array().map(Vec::len), Some(20));
    }

    #[test]
    fn tight_budget_drops_pointers_and_still_fits() {
        let (value, outcome) = fit(30, 200, builder);
        assert!(outcome.fits);
        assert_eq!(outcome.full, 0);
        assert!(outcome.emitted < 200);
        assert!(outcome.tokens <= 30, "{}", outcome.tokens);
        assert_eq!(
            value["content"].as_array().map(Vec::len),
            Some(0),
            "pointer tier carries no inline content"
        );
    }

    #[test]
    fn budget_too_small_for_the_envelope_returns_the_pointer_tier_and_says_so() {
        let (value, outcome) = fit(1, 10, builder);
        assert!(!outcome.fits, "a budget that cannot fit one pointer must say so");
        // One addressable pointer, no inline content: the caller still has a
        // handle to re-address with.
        assert_eq!(outcome.emitted, 1);
        assert_eq!(outcome.full, 0);
        assert_eq!(value["pointers"].as_array().map(Vec::len), Some(1));
        assert_eq!(value["content"].as_array().map(Vec::len), Some(0));
        // ...and with nothing to point at, it stays empty.
        let (_, empty) = fit(1, 0, builder);
        assert_eq!(empty.emitted, 0);
    }

    #[test]
    fn zero_rows_is_the_empty_envelope() {
        let (value, outcome) = fit(1000, 0, builder);
        assert!(outcome.fits);
        assert_eq!(outcome.emitted, 0);
        assert_eq!(value["pointers"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn search_finds_the_maximum_that_fits() {
        // Sweep budgets and assert the result is maximal: emitting one more
        // row would exceed the budget.
        for budget in [40usize, 80, 160, 320] {
            let (_, outcome) = fit(budget, 50, builder);
            if !outcome.fits {
                continue;
            }
            assert!(outcome.tokens <= budget as u64);
            if outcome.full < outcome.emitted {
                let next = builder(outcome.full + 1, outcome.emitted);
                assert!(cost(&next) > budget as u64, "budget {budget}: not maximal in `full`");
            } else if outcome.emitted < 50 {
                let next = builder(outcome.full, outcome.emitted + 1);
                assert!(cost(&next) > budget as u64, "budget {budget}: not maximal in `emitted`");
            }
        }
    }
}
