// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Per-model (and per-effort-within-model) burn rollup.
//!
//! The cost lens measures *what* a session cost. This module adds the one axis
//! that makes the number worth reading: **which model, at which effort setting,
//! burned it**.
//!
//! Two properties are load-bearing:
//!
//! 1. **Reconciliation.** Σ over models of `context_total`, plus the synthetic
//!    pseudo-model, plus records that carried usage but named no model, equals
//!    [`crate::report::Headline::measured_context_total`] exactly. A breakdown
//!    that does not add up is worse than no breakdown.
//! 2. **Coverage traffics with the number.** `effort` is missing non-randomly —
//!    its presence correlates with model (100% / 100% / 22.5% / 9.4% across the
//!    2026-07-30 corpus). Every [`ModelBurn`] therefore carries
//!    [`ModelBurn::effort_coverage_pct`], so no surface can render an effort
//!    figure without the denominator that qualifies it. Comparing one model's
//!    effort level against another's is confounded at source and no sample size
//!    fixes it; this type makes that visible rather than documented.

use std::collections::HashMap;

use crate::report::{EffortBurn, Measured, ModelBreakdown, ModelBurn};
use crate::transcript::{Event, SYNTHETIC_MODEL};

/// Build the per-model breakdown from parsed events. Returns `None` when no
/// record named a model at all (a legacy transcript), so the report omits the
/// field entirely rather than carrying an empty shell.
#[must_use]
pub fn breakdown(events: &[Event]) -> Option<ModelBreakdown> {
    /// Mutable accumulator; converted to the wire type once totals are known.
    #[derive(Default)]
    struct Acc {
        turns: u64,
        measured: Measured,
        context_total: u64,
        with_effort: u64,
        efforts: HashMap<String, EffortAcc>,
        first: usize,
    }
    #[derive(Default)]
    struct EffortAcc {
        turns: u64,
        context_total: u64,
        output: u64,
        first: usize,
    }

    let mut by_model: HashMap<String, Acc> = HashMap::new();
    let mut unattributed_context: u64 = 0;
    let mut saw_model = false;

    for (i, ev) in events.iter().enumerate() {
        let Some(model) = ev.model.as_deref() else {
            // A record with usage but no model still has to land somewhere, or
            // the breakdown stops reconciling against the measured total.
            if let Some(u) = ev.usage {
                unattributed_context = unattributed_context.saturating_add(u.context_read());
            }
            continue;
        };
        saw_model = true;
        let acc = by_model.entry(model.to_owned()).or_insert_with(|| Acc {
            first: i,
            ..Acc::default()
        });
        acc.turns += 1;
        if let Some(u) = ev.usage {
            acc.measured.input = acc.measured.input.saturating_add(u.input);
            acc.measured.output = acc.measured.output.saturating_add(u.output);
            acc.measured.cache_read = acc.measured.cache_read.saturating_add(u.cache_read);
            acc.measured.cache_creation = acc.measured.cache_creation.saturating_add(u.cache_creation);
            acc.context_total = acc.context_total.saturating_add(u.context_read());
        }
        if let Some(effort) = ev.effort.as_deref() {
            acc.with_effort += 1;
            let e = acc.efforts.entry(effort.to_owned()).or_insert_with(|| EffortAcc {
                first: i,
                ..EffortAcc::default()
            });
            e.turns += 1;
            if let Some(u) = ev.usage {
                e.context_total = e.context_total.saturating_add(u.context_read());
                e.output = e.output.saturating_add(u.output);
            }
        }
    }

    if !saw_model && unattributed_context == 0 {
        return None;
    }

    let mut synthetic = None;
    // (first-seen index, burn) — the index is a deterministic tie-break, kept
    // local so it never reaches the wire contract.
    let mut models: Vec<(usize, ModelBurn)> = Vec::new();
    for (model, acc) in by_model {
        let mut efforts: Vec<EffortBurn> = acc
            .efforts
            .iter()
            .map(|(effort, e)| EffortBurn {
                effort: effort.clone(),
                turns: e.turns,
                context_total: e.context_total,
                output: e.output,
            })
            .collect();
        // Burn desc, then first-seen, then name — deterministic, no clock.
        let order: HashMap<&str, usize> = acc.efforts.iter().map(|(k, v)| (k.as_str(), v.first)).collect();
        efforts.sort_by(|a, b| {
            b.context_total
                .cmp(&a.context_total)
                .then_with(|| order.get(a.effort.as_str()).cmp(&order.get(b.effort.as_str())))
                .then_with(|| a.effort.cmp(&b.effort))
        });
        let burn = ModelBurn {
            effort_coverage_pct: pct_of(acc.with_effort, acc.turns),
            model,
            turns: acc.turns,
            measured: acc.measured,
            context_total: acc.context_total,
            efforts,
        };
        // `<synthetic>` is not a model. Counted so the totals reconcile, but
        // reported on its own rather than charted alongside real ones.
        if burn.model == SYNTHETIC_MODEL {
            synthetic = Some(burn);
        } else {
            models.push((acc.first, burn));
        }
    }
    models.sort_by(|(fa, a), (fb, b)| {
        b.context_total
            .cmp(&a.context_total)
            .then_with(|| fa.cmp(fb))
            .then_with(|| a.model.cmp(&b.model))
    });

    Some(ModelBreakdown {
        models: models.into_iter().map(|(_, m)| m).collect(),
        synthetic,
        unattributed_context,
    })
}

/// The single model and effort that dominate a breakdown by turn count — the
/// scalar `CostReport.model` / `.effort`, for callers that want one label per
/// session without walking the breakdown. Ties broken by burn, then name.
#[must_use]
pub fn primary(b: &ModelBreakdown) -> (Option<String>, Option<String>) {
    let top = b.models.iter().max_by(|a, c| {
        a.turns
            .cmp(&c.turns)
            .then_with(|| a.context_total.cmp(&c.context_total))
            .then_with(|| c.model.cmp(&a.model))
    });
    let Some(top) = top else { return (None, None) };
    let effort = top
        .efforts
        .iter()
        .max_by(|a, c| {
            a.turns
                .cmp(&c.turns)
                .then_with(|| a.context_total.cmp(&c.context_total))
                .then_with(|| c.effort.cmp(&a.effort))
        })
        .map(|e| e.effort.clone());
    (Some(top.model.clone()), effort)
}

/// The most frequently-seen value of a per-record optional string, ties broken
/// lexically. Used for `cwd` and `git_branch`, both of which can change
/// mid-session but rarely do.
#[must_use]
pub fn most_common(events: &[Event], pick: impl Fn(&Event) -> Option<&str>) -> Option<String> {
    let mut counts: HashMap<&str, u32> = HashMap::new();
    for e in events {
        if let Some(v) = pick(e) {
            *counts.entry(v).or_default() += 1;
        }
    }
    let mut entries: Vec<(&str, u32)> = counts.into_iter().collect();
    entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    entries.first().map(|(v, _)| (*v).to_owned())
}

#[allow(
    clippy::cast_precision_loss,
    reason = "turn counts are < 2^53, exactly representable in f64"
)]
fn pct_of(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        0.0
    } else {
        (100.0 * part as f64 / whole as f64 * 100.0).round() / 100.0
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::transcript::parse_str;
    use serde_json::json;

    /// Two models, mixed effort coverage, plus a synthetic record — the shape
    /// the real corpus has.
    fn mixed() -> String {
        [
            json!({"type":"assistant","sessionId":"s","effort":"xhigh","cwd":"/w","gitBranch":"main",
                   "message":{"role":"assistant","model":"claude-opus-5",
                   "usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":100},
                   "content":[{"type":"text","text":"a"}]}}),
            json!({"type":"assistant","sessionId":"s","effort":"high","cwd":"/w",
                   "message":{"role":"assistant","model":"claude-opus-5",
                   "usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":200},
                   "content":[{"type":"text","text":"b"}]}}),
            // fable with no effort field — the 22.5%-coverage case.
            json!({"type":"assistant","sessionId":"s","cwd":"/w",
                   "message":{"role":"assistant","model":"claude-fable-5",
                   "usage":{"input_tokens":1,"output_tokens":1,"cache_read_input_tokens":50},
                   "content":[{"type":"text","text":"c"}]}}),
            json!({"type":"assistant","sessionId":"s","effort":"max","cwd":"/w",
                   "message":{"role":"assistant","model":"claude-fable-5",
                   "usage":{"input_tokens":1,"output_tokens":1,"cache_read_input_tokens":50},
                   "content":[{"type":"text","text":"d"}]}}),
            json!({"type":"assistant","sessionId":"s",
                   "message":{"role":"assistant","model":"<synthetic>",
                   "usage":{"input_tokens":0,"output_tokens":0,"cache_read_input_tokens":7},
                   "content":[{"type":"text","text":"e"}]}}),
        ]
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n")
    }

    #[test]
    fn per_model_counts_and_burn_are_exact() {
        let b = breakdown(&parse_str(&mixed())).expect("breakdown");
        assert_eq!(b.models.len(), 2, "synthetic must not be charted as a model");
        // opus-5: 2 turns, context 110 + 210 = 320 (biggest → first).
        let opus = &b.models[0];
        assert_eq!(opus.model, "claude-opus-5");
        assert_eq!(opus.turns, 2);
        assert_eq!(opus.context_total, 320);
        assert_eq!(opus.measured.output, 10);
        // fable: 2 turns, (1 + 50) each.
        let fable = &b.models[1];
        assert_eq!(fable.model, "claude-fable-5");
        assert_eq!(fable.turns, 2);
        assert_eq!(fable.context_total, 102);
    }

    #[test]
    fn effort_coverage_is_per_model_and_reported_beside_the_efforts() {
        let b = breakdown(&parse_str(&mixed())).expect("breakdown");
        let opus = b.models.iter().find(|m| m.model == "claude-opus-5").unwrap();
        assert!((opus.effort_coverage_pct - 100.0).abs() < 1e-9);
        assert_eq!(opus.efforts.len(), 2);
        // Highest-burn effort first: high (210) over xhigh (110).
        assert_eq!(opus.efforts[0].effort, "high");
        assert_eq!(opus.efforts[0].context_total, 210);

        // The confounded case: half of fable's turns carry effort at all.
        let fable = b.models.iter().find(|m| m.model == "claude-fable-5").unwrap();
        assert!((fable.effort_coverage_pct - 50.0).abs() < 1e-9);
        assert_eq!(fable.efforts.len(), 1);
        assert_eq!(fable.efforts[0].effort, "max");
        // The effort rows cover only half the model's burn — which is exactly
        // why the coverage figure has to travel with them.
        assert!(fable.efforts.iter().map(|e| e.context_total).sum::<u64>() < fable.context_total);
    }

    #[test]
    fn synthetic_is_separated_not_dropped() {
        let b = breakdown(&parse_str(&mixed())).expect("breakdown");
        let syn = b.synthetic.as_ref().expect("synthetic reported separately");
        assert_eq!(syn.model, SYNTHETIC_MODEL);
        assert_eq!(syn.turns, 1);
        assert_eq!(syn.context_total, 7);
        assert!(!b.models.iter().any(|m| m.model == SYNTHETIC_MODEL));
    }

    #[test]
    fn breakdown_reconciles_to_the_measured_total() {
        let events = parse_str(&mixed());
        let b = breakdown(&events).expect("breakdown");
        let measured: u64 = events
            .iter()
            .filter_map(|e| e.usage)
            .map(|u| u.context_read())
            .fold(0, u64::saturating_add);
        let from_breakdown = b.models.iter().map(|m| m.context_total).sum::<u64>()
            + b.synthetic.as_ref().map_or(0, |s| s.context_total)
            + b.unattributed_context;
        assert_eq!(
            from_breakdown, measured,
            "a breakdown that does not add up is worse than none"
        );
    }

    #[test]
    fn usage_without_a_model_lands_in_unattributed() {
        let line = json!({"type":"assistant","sessionId":"s",
                          "message":{"role":"assistant",
                          "usage":{"input_tokens":3,"output_tokens":1,"cache_read_input_tokens":9},
                          "content":[{"type":"text","text":"x"}]}})
        .to_string();
        let b = breakdown(&parse_str(&line)).expect("breakdown");
        assert!(b.models.is_empty());
        assert_eq!(b.unattributed_context, 12);
    }

    #[test]
    fn no_model_and_no_usage_yields_no_breakdown() {
        let line = json!({"type":"user","sessionId":"s","message":{"role":"user","content":"hi"}}).to_string();
        assert!(breakdown(&parse_str(&line)).is_none());
        assert!(breakdown(&[]).is_none());
    }

    #[test]
    fn primary_picks_the_dominant_model_and_its_dominant_effort() {
        let b = breakdown(&parse_str(&mixed())).expect("breakdown");
        // opus-5 and fable-5 both have 2 turns; opus-5 wins on burn.
        let (model, effort) = primary(&b);
        assert_eq!(model.as_deref(), Some("claude-opus-5"));
        // Its two efforts tie on turns; `high` wins on burn.
        assert_eq!(effort.as_deref(), Some("high"));
    }

    #[test]
    fn most_common_picks_the_modal_value() {
        let events = parse_str(&mixed());
        assert_eq!(most_common(&events, |e| e.cwd.as_deref()).as_deref(), Some("/w"));
        assert_eq!(
            most_common(&events, |e| e.git_branch.as_deref()).as_deref(),
            Some("main")
        );
        assert!(most_common(&[], |e| e.cwd.as_deref()).is_none());
    }

    #[test]
    fn ordering_is_deterministic() {
        let events = parse_str(&mixed());
        let a = breakdown(&events).expect("breakdown");
        let b = breakdown(&events).expect("breakdown");
        let names = |x: &ModelBreakdown| x.models.iter().map(|m| m.model.clone()).collect::<Vec<_>>();
        assert_eq!(names(&a), names(&b));
    }
}
