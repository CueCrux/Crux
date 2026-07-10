// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! M4 — deterministic `crux learn` session-mining (Headroom *loop-weighting* analogue).
//!
//! ExecPlan: `crux-headroom-token-efficiency-learnings-2026-06-24` (milestone M4).
//!
//! Headroom's `headroom learn` flags any tool signature repeated ≥3× in a
//! session and ranks candidate guardrails by *measured* token waste — real bytes
//! summed across the repeats, with pagination variants folded to one canonical
//! signature — then proposes (never auto-writes) a guardrail. The parity bug it
//! fixed: ranking by single-call size makes a one-time big response outrank a
//! many-times small loop, so the loop never gets a guardrail. Ranking by *total
//! waste across repeats* fixes it.
//!
//! This module ports that as a pure, deterministic analyzer over a session's
//! tool-call events (`tool` + canonical-arg signature + measured response
//! tokens). It is **read-only and propose-only** (OD-C): it returns
//! [`GuardrailProposal`] rows; the operator decides whether any becomes a
//! deliberate, passport-attributed fact. No fact is written here, and nothing
//! runs behind a hook (Crux don't-list).

use std::collections::HashMap;

use serde_json::Value;

/// A tool signature must recur at least this many times in a session before it
/// is considered a loop worth a guardrail (Headroom's `≥3×` threshold).
pub const MIN_REPEATS: usize = 3;

/// Argument keys treated as pagination / cursor noise. They are folded out of
/// the canonical signature so `query(q=x, offset=0)`, `…offset=20`, `…offset=40`
/// dedup to a single loop rather than three distinct one-off calls — the
/// canonical-signature dedup that makes paginated re-fetches legible as waste.
const PAGINATION_KEYS: &[&str] = &[
    "offset",
    "cursor",
    "page",
    "page_token",
    "after",
    "before",
    "start",
    "from",
    "next",
    "continuation",
    "skip",
];

/// One observed tool call in a session: its canonical signature and the measured
/// token cost of its response. The signature is produced by
/// [`canonical_signature`]; `response_tokens` is the estimator's output for the
/// emitted payload (the same `est_out` the dispatch path already computes).
#[derive(Clone, Debug)]
pub struct ToolEvent {
    pub signature: String,
    pub response_tokens: u64,
}

/// A proposed guardrail for one looping signature. **Propose-only**: this is a
/// suggestion plus the measured waste that justifies it — never an auto-write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardrailProposal {
    /// Canonical tool signature that looped.
    pub signature: String,
    /// How many times it was called in the session (≥ [`MIN_REPEATS`]).
    pub occurrences: usize,
    /// Measured token waste = response tokens across the *redundant* re-fetches
    /// (every call after the first; the first fetch is legitimate).
    pub wasted_tokens: u64,
    /// Human-readable draft guardrail the operator may choose to adopt.
    pub draft_guardrail: String,
}

/// Recursively canonicalize a JSON value to a deterministic string: object keys
/// are sorted, so the result is independent of serde's map ordering (whether or
/// not the `preserve_order` feature is enabled).
fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let inner: Vec<String> = keys
                .iter()
                .map(|k| format!("{}={}", k, canonical_json(&map[*k])))
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => other.to_string(),
    }
}

/// Build a deterministic, pagination-insensitive signature for a tool call.
/// Top-level pagination keys are dropped; the remaining args are rendered in
/// sorted-key canonical form. Two calls that differ only by pagination cursor
/// produce the *same* signature.
pub fn canonical_signature(tool: &str, args: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(obj) = args.as_object() {
        let mut keys: Vec<&String> = obj.keys().filter(|k| !PAGINATION_KEYS.contains(&k.as_str())).collect();
        keys.sort();
        for k in keys {
            parts.push(format!("{}={}", k, canonical_json(&obj[k])));
        }
    }
    format!("{tool}({})", parts.join(","))
}

/// Draft guardrail text for a looping signature. Deterministic (no clock/rng).
fn draft_for(signature: &str, occurrences: usize, wasted_tokens: u64) -> String {
    format!(
        "`{signature}` was called {occurrences}× this session (~{wasted_tokens} redundant tokens \
         after the first fetch). Cache the first result and reuse it instead of re-fetching; if you \
         need more, raise `token_budget` once rather than paginating repeatedly."
    )
}

/// Detect looping tool signatures and rank candidate guardrails by *measured*
/// token waste. Deterministic: groups are flagged at `min_repeats`, waste is the
/// response-token sum across redundant re-fetches, and proposals are sorted by
/// waste desc, then occurrences desc, then signature asc (a total order, so the
/// output is stable for identical input). Returns an empty vec when no signature
/// loops — the honest "nothing to propose".
pub fn detect_loops(events: &[ToolEvent], min_repeats: usize) -> Vec<GuardrailProposal> {
    // Group by signature, preserving first-seen order for determinism before the
    // final sort, and accumulate per-call response tokens.
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<u64>> = HashMap::new();
    for e in events {
        groups
            .entry(e.signature.clone())
            .or_insert_with(|| {
                order.push(e.signature.clone());
                Vec::new()
            })
            .push(e.response_tokens);
    }

    let mut proposals: Vec<GuardrailProposal> = order
        .iter()
        .filter_map(|sig| {
            let toks = &groups[sig];
            if toks.len() < min_repeats {
                return None;
            }
            // Waste = everything past the first (legitimate) fetch. Ranking by
            // this total — not per-call size — is the loop-weighting fix.
            let total: u64 = toks.iter().sum();
            let wasted = total.saturating_sub(toks[0]);
            Some(GuardrailProposal {
                signature: sig.clone(),
                occurrences: toks.len(),
                wasted_tokens: wasted,
                draft_guardrail: draft_for(sig, toks.len(), wasted),
            })
        })
        .collect();

    proposals.sort_by(|a, b| {
        b.wasted_tokens
            .cmp(&a.wasted_tokens)
            .then(b.occurrences.cmp(&a.occurrences))
            .then(a.signature.cmp(&b.signature))
    });
    proposals
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev(sig: &str, toks: u64) -> ToolEvent {
        ToolEvent {
            signature: sig.to_string(),
            response_tokens: toks,
        }
    }

    #[test]
    fn pagination_variants_share_one_signature() {
        let a = canonical_signature("query", &json!({"q": "alpha", "offset": 0}));
        let b = canonical_signature("query", &json!({"q": "alpha", "offset": 20}));
        let c = canonical_signature("query", &json!({"q": "alpha", "offset": 40, "cursor": "z"}));
        assert_eq!(a, b);
        assert_eq!(b, c);
        // …but a different query term is a different signature.
        assert_ne!(a, canonical_signature("query", &json!({"q": "beta"})));
    }

    #[test]
    fn signature_is_key_order_independent() {
        let a = canonical_signature("t", &json!({"a": 1, "b": {"x": 1, "y": 2}}));
        let b = canonical_signature("t", &json!({"b": {"y": 2, "x": 1}, "a": 1}));
        assert_eq!(a, b);
    }

    #[test]
    fn below_threshold_is_not_flagged() {
        // Two calls — not a loop.
        let events = [ev("query(q=x)", 100), ev("query(q=x)", 100)];
        assert!(detect_loops(&events, MIN_REPEATS).is_empty());
    }

    #[test]
    fn gate_m4_loop_ranks_above_one_time_mistake() {
        // The M4 gate: a 6× re-fetch loop (small per-call) must outrank — and a
        // one-time 200-token mistake must NOT even be proposed (it never loops).
        let mut events = vec![ev("paginated_fetch(q=docs)", 50); 6]; // 6× × 50 tok
        events.push(ev("expensive_one_off(q=huge)", 200)); // single 200-tok mistake

        let proposals = detect_loops(&events, MIN_REPEATS);
        assert_eq!(proposals.len(), 1, "only the loop is a guardrail candidate");
        assert_eq!(proposals[0].signature, "paginated_fetch(q=docs)");
        // Redundant waste = 5 re-fetches × 50 = 250, which exceeds the one-time
        // 200-token mistake — so the loop ranks above it (the parity property).
        assert_eq!(proposals[0].occurrences, 6);
        assert_eq!(proposals[0].wasted_tokens, 250);
        assert!(proposals[0].wasted_tokens > 200);
    }

    #[test]
    fn ranks_by_total_waste_not_per_call_size() {
        // The exact parity bug: a frequent-small loop wastes more in aggregate
        // than a rare-large one, even though its per-call size is smaller.
        let mut events = vec![ev("frequent_small(q=a)", 60); 5]; // waste = 4×60 = 240
        events.extend(vec![ev("rare_large(q=b)", 100); 3]); // waste = 2×100 = 200

        let proposals = detect_loops(&events, MIN_REPEATS);
        assert_eq!(proposals.len(), 2);
        assert_eq!(proposals[0].signature, "frequent_small(q=a)");
        assert_eq!(proposals[0].wasted_tokens, 240);
        assert_eq!(proposals[1].signature, "rare_large(q=b)");
        assert_eq!(proposals[1].wasted_tokens, 200);
    }

    #[test]
    fn paginated_loop_detected_after_dedup() {
        // Three paginated calls collapse to one signature and register as a loop.
        let events: Vec<ToolEvent> = [0u64, 20, 40]
            .iter()
            .map(|off| ToolEvent {
                signature: canonical_signature("search", &json!({"q": "x", "offset": off})),
                response_tokens: 80,
            })
            .collect();
        let proposals = detect_loops(&events, MIN_REPEATS);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].occurrences, 3);
        assert_eq!(proposals[0].wasted_tokens, 160); // 2 redundant × 80
    }

    #[test]
    fn output_is_deterministic_and_proposes_nothing_writes_nothing() {
        let events = vec![ev("a(q=1)", 30); 3];
        let first = detect_loops(&events, MIN_REPEATS);
        let second = detect_loops(&events, MIN_REPEATS);
        assert_eq!(first, second);
        // The draft is advisory text — there is no mutation surface on the type.
        assert!(first[0].draft_guardrail.contains("Cache the first result"));
    }
}
