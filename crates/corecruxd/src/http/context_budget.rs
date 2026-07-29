// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Shared token budgeting for the context-graph reads (storybook, dossiers).
//!
//! The budget is a **contract, not a hint**: a caller that asks for 500 tokens
//! must be able to paste the whole response into a prompt and have it cost
//! about 500 tokens. The `code_intel` surface shipped this same feature once
//! with the estimator counting only payload strings and not the JSON envelope,
//! and it overshot a 500-token budget by 50%. Both modules here therefore
//! measure the **serialised** response and have a test that asserts it fits.
//!
//! Neither surface applies a budget unless the caller asks for one — omitting
//! `token_budget` returns the full document, byte-identical to the pre-budget
//! response shape.

/// Rough token estimate: ~4 characters per token, rounded up.
///
/// Matches `workbench::estimate_tokens` and `code_intel::est_tokens` so the
/// three budgeted surfaces on this daemon quote the same currency.
pub(super) fn est_tokens(text: &str) -> usize {
    text.len().div_ceil(4)
}

/// Serialised token cost of a value, measured rather than estimated from its
/// parts. Returns 0 if the value cannot be serialised, which cannot happen for
/// the response types here and would only ever under-report.
pub(super) fn serialised_tokens<T: serde::Serialize>(value: &T) -> usize {
    serde_json::to_string(value).map_or(0, |s| est_tokens(&s))
}

/// Budget left for payload once a **measured** envelope is paid for.
///
/// The envelope is not a constant. Two of its fields — `sections_omitted` and
/// `claims_omitted` — are *reporting* fields that grow as the payload shrinks,
/// so a fixed reservation is wrong in exactly the direction that matters: the
/// tighter the budget, the more it undercounts. Callers therefore build an
/// empty-payload probe carrying the **full** omission list, measure that, and
/// pass the result here. That is the worst case, so admitting payload against
/// it can only end under budget.
///
/// Saturating: a budget smaller than its own envelope yields zero, and the
/// caller emits an empty-but-honest payload with `truncated: true`.
pub(super) fn payload_budget(token_budget: usize, measured_envelope: usize) -> usize {
    token_budget.saturating_sub(measured_envelope)
}

/// Parse the repeatable-as-comma-separated `section=` filter into trimmed,
/// non-empty terms. `None` and an all-blank value both mean "no filter".
pub(super) fn parse_section_filter(raw: Option<&str>) -> Vec<String> {
    raw.map(|s| {
        s.split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default()
}

/// A section key matches the filter when it is a prefix match against any term,
/// so `section=50` selects `50_workspace_health` and `section=30_plane_` selects
/// every per-plane section. An empty filter matches everything.
pub(super) fn section_matches(key: &str, filter: &[String]) -> bool {
    filter.is_empty() || filter.iter().any(|term| key.starts_with(term.as_str()))
}

/// Canonical render order for storybook section keys.
///
/// Plain `BTreeMap` order would place `30_plane_<id>` *before*
/// `30_planes_intro` (`'_' < 's'`), putting each plane's detail above the
/// heading that introduces them. The intro is remapped to a key that sorts
/// first within the `30_` band; every other key orders lexicographically, which
/// is what the numeric prefixes were chosen for.
pub(super) fn section_order_key(key: &str) -> String {
    if key == "30_planes_intro" {
        "30_plane".to_string()
    } else {
        key.to_string()
    }
}

/// Section keys kept ahead of everything else when a budget forces a choice.
///
/// Front matter says what the readout is *of*; alerts say what is wrong. They
/// are what a reader skims first, so they are what survives a small budget.
pub(super) const PRIORITY_SECTIONS: [&str; 2] = ["00_front", "60_alerts"];

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn est_tokens_rounds_up_by_four() {
        assert_eq!(est_tokens(""), 0);
        assert_eq!(est_tokens("abc"), 1);
        assert_eq!(est_tokens("abcd"), 1);
        assert_eq!(est_tokens("abcde"), 2);
    }

    #[test]
    fn payload_budget_saturates_below_the_envelope() {
        assert_eq!(payload_budget(1000, 120), 880);
        assert_eq!(payload_budget(10, 120), 0);
        assert_eq!(payload_budget(0, 0), 0);
    }

    #[test]
    fn serialised_tokens_measures_the_encoded_form() {
        // 17 bytes of JSON — the quoting and braces are part of the cost.
        let v = serde_json::json!({ "k": "value" });
        assert_eq!(serialised_tokens(&v), est_tokens(&v.to_string()));
        assert!(serialised_tokens(&v) > est_tokens("value"));
    }

    #[test]
    fn section_filter_parses_and_prefix_matches() {
        assert!(parse_section_filter(None).is_empty());
        assert!(parse_section_filter(Some("  , ")).is_empty());
        let f = parse_section_filter(Some("50, 30_plane_"));
        assert_eq!(f, vec!["50".to_string(), "30_plane_".to_string()]);
        assert!(section_matches("50_workspace_health", &f));
        assert!(section_matches("30_plane_alpha", &f));
        assert!(!section_matches("10_vision", &f));
        // Empty filter matches everything.
        assert!(section_matches("10_vision", &[]));
    }

    #[test]
    fn planes_intro_orders_before_individual_planes() {
        let mut keys = vec!["30_plane_zeta", "30_planes_intro", "30_plane_alpha", "40_coverage"];
        keys.sort_by_key(|k| section_order_key(k));
        assert_eq!(
            keys,
            vec!["30_planes_intro", "30_plane_alpha", "30_plane_zeta", "40_coverage"]
        );
    }
}
