// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! M5 — holdout-group measurement + CI reporting (Headroom *holdout* analogue).
//!
//! ExecPlan: `crux-headroom-token-efficiency-learnings-2026-06-24` (milestone M5).
//!
//! Headroom keeps `HEADROOM_OUTPUT_HOLDOUT=0.1` of traffic **unshaped** as a live
//! control and reports savings as `28.0% (95% CI 24.1–31.9%)` — never a bare
//! counterfactual point estimate (the exact trap the plan's R5 calls out). This
//! module ports the two deterministic primitives that make such a claim honest:
//!
//! 1. [`is_control`] — a deterministic, per-request control-group assignment from
//!    `CRUX_OUTPUT_HOLDOUT` (default `0.0` ⇒ OFF). The *same* request key always
//!    lands in the same arm, so the split is reproducible and unbiased (no rng,
//!    so the bench harness stays clock/rng-free, the M0 reproducibility gate).
//! 2. [`paired_savings`] — the savings of a treatment arm vs. its control arm as
//!    a point estimate **with a 95 % CI**, computed from paired per-request token
//!    counts. [`SavingsReport::format`] renders the QC.4/QC.5 line (corpus +
//!    commit_sha), so no saving is ever reported as a number without its interval.
//!
//! Default `CRUX_OUTPUT_HOLDOUT` unset ⇒ fraction `0.0` ⇒ no request is ever
//! diverted to control ⇒ byte-identical to pre-M5.

/// Env flag name for the M5 output holdout fraction. Default `0.0` (OFF).
pub const HOLDOUT_ENV: &str = "CRUX_OUTPUT_HOLDOUT";

/// 95% two-sided normal-approximation multiplier. Documented in
/// `docs/bench/token-savings-methodology.md`.
pub const Z_95: f64 = 1.96;

/// Parse the holdout fraction from `CRUX_OUTPUT_HOLDOUT`, clamped to `[0, 1]`.
/// Unset / unparseable ⇒ `0.0` (no control group; efficiency flags apply to all
/// traffic exactly as before M5).
pub fn holdout_fraction() -> f64 {
    std::env::var(HOLDOUT_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .map_or(0.0, |f| f.clamp(0.0, 1.0))
}

/// FNV-1a 64-bit hash followed by a splitmix64 finalizer — small,
/// dependency-free, deterministic. FNV alone has weak avalanche on short
/// sequential keys (`key-0`, `key-1`, …), which skews the bucket split; the
/// finalizer decorrelates the bits. Used only to bucket a request key into
/// `[0, 1)`; not security-sensitive.
fn fnv1a(key: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in key.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // splitmix64 finalizer.
    hash = hash.wrapping_add(0x9e37_79b9_7f4a_7c15);
    hash = (hash ^ (hash >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash = (hash ^ (hash >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^ (hash >> 31)
}

/// Deterministic control-group assignment: `true` when this request key belongs
/// to the unshaped control arm. The key is hashed to a stable point in `[0, 1)`
/// and compared against `fraction`, so the same key is always in the same arm
/// and roughly `fraction` of distinct keys are control. `fraction <= 0` ⇒ never
/// control; `fraction >= 1` ⇒ always control.
pub fn is_control(key: &str, fraction: f64) -> bool {
    if fraction <= 0.0 {
        return false;
    }
    if fraction >= 1.0 {
        return true;
    }
    // Map the hash to [0, 1) with 53 bits of mantissa precision.
    let bucket = (fnv1a(key) >> 11) as f64 / (1u64 << 53) as f64;
    bucket < fraction
}

/// A token-savings estimate with a 95% confidence interval, all as fractions in
/// `[0, 1]` (`format` renders them as percentages). Computed by
/// [`paired_savings`] over paired control/treatment per-request token counts.
#[derive(Clone, Debug, PartialEq)]
pub struct SavingsReport {
    /// Number of paired samples that contributed (control tokens > 0).
    pub n: usize,
    /// Mean per-request token reduction fraction (the point estimate).
    pub reduction: f64,
    /// Lower bound of the 95% CI on the mean reduction.
    pub ci_low: f64,
    /// Upper bound of the 95% CI on the mean reduction.
    pub ci_high: f64,
    /// Total control tokens summed across samples (for context).
    pub control_tokens: u64,
    /// Total treatment tokens summed across samples (for context).
    pub treatment_tokens: u64,
}

/// Compute the paired token savings of `treatment` vs. `control` with a 95% CI.
///
/// `control[i]` and `treatment[i]` are the token costs of the **same** request
/// run with efficiency flags OFF (control) and ON (treatment). The per-request
/// reduction is `(control - treatment) / control`; the report is the mean of
/// those reductions with a normal-approximation 95% CI (`mean ± Z_95 · SE`,
/// `SE = s / √n`, `s` the sample standard deviation). Samples with
/// `control == 0` are skipped (no defined reduction). For `n < 2` the CI
/// collapses to the point estimate (no dispersion from one sample).
///
/// Deterministic: identical inputs ⇒ identical output (no clock, no rng).
pub fn paired_savings(control: &[u64], treatment: &[u64]) -> SavingsReport {
    let mut reductions: Vec<f64> = Vec::new();
    let mut control_tokens: u64 = 0;
    let mut treatment_tokens: u64 = 0;
    for (c, t) in control.iter().zip(treatment.iter()) {
        control_tokens += *c;
        treatment_tokens += *t;
        if *c == 0 {
            continue;
        }
        reductions.push((*c as f64 - *t as f64) / *c as f64);
    }

    let n = reductions.len();
    if n == 0 {
        return SavingsReport {
            n: 0,
            reduction: 0.0,
            ci_low: 0.0,
            ci_high: 0.0,
            control_tokens,
            treatment_tokens,
        };
    }

    let mean = reductions.iter().sum::<f64>() / n as f64;
    let se = if n >= 2 {
        let var = reductions.iter().map(|r| (r - mean).powi(2)).sum::<f64>() / (n as f64 - 1.0);
        (var / n as f64).sqrt()
    } else {
        0.0
    };
    SavingsReport {
        n,
        reduction: mean,
        ci_low: mean - Z_95 * se,
        ci_high: mean + Z_95 * se,
        control_tokens,
        treatment_tokens,
    }
}

impl SavingsReport {
    /// Render the QC.4/QC.5 savings line: a point estimate with its 95% CI, the
    /// named corpus, and the commit_sha — e.g.
    /// `token savings 28.0% (95% CI 24.1–31.9%) · n=7 · corpus=… · commit=…`.
    /// Percentages are fixed to one decimal so the string is stable.
    pub fn format(&self, corpus: &str, commit_sha: &str) -> String {
        format!(
            "token savings {:.1}% (95% CI {:.1}–{:.1}%) · n={} · control_tokens={} · treatment_tokens={} · corpus={} · commit={}",
            self.reduction * 100.0,
            self.ci_low * 100.0,
            self.ci_high * 100.0,
            self.n,
            self.control_tokens,
            self.treatment_tokens,
            corpus,
            commit_sha,
        )
    }
}

// ── CO-4: live holdout accumulator + unpaired savings ───────────────────────

use std::sync::{Mutex, OnceLock};

/// Per-arm bounded ring of emitted-token samples for the *live* holdout. Live
/// traffic is **unpaired** (a control request and a treatment request are
/// different requests), so we accumulate each arm's per-request token counts
/// separately and compare them with [`unpaired_savings`].
#[derive(Default)]
pub struct HoldoutAccumulator {
    control: Vec<u64>,
    treatment: Vec<u64>,
    // CO-5 per-mechanism: paired (pretty, compact) token counts of the SAME
    // emitted payload, so the compaction (M3) saving is measured exactly and in
    // isolation from the reversible (M1) recall cost the net arm folds in.
    compaction_pretty: Vec<u64>,
    compaction_compact: Vec<u64>,
}

/// Per-arm hard cap — keeps the accumulator memory-bounded; oldest samples are
/// evicted FIFO so the report reflects a rolling recent window.
pub const MAX_SAMPLES_PER_ARM: usize = 5_000;

impl HoldoutAccumulator {
    fn push(&mut self, is_control: bool, tokens: u64) {
        let arm = if is_control {
            &mut self.control
        } else {
            &mut self.treatment
        };
        arm.push(tokens);
        if arm.len() > MAX_SAMPLES_PER_ARM {
            let overflow = arm.len() - MAX_SAMPLES_PER_ARM;
            arm.drain(0..overflow);
        }
    }

    fn push_compaction(&mut self, pretty: u64, compact: u64) {
        self.compaction_pretty.push(pretty);
        self.compaction_compact.push(compact);
        if self.compaction_pretty.len() > MAX_SAMPLES_PER_ARM {
            let overflow = self.compaction_pretty.len() - MAX_SAMPLES_PER_ARM;
            self.compaction_pretty.drain(0..overflow);
            self.compaction_compact.drain(0..overflow);
        }
    }

    /// Per-mechanism snapshot. The **compaction** report is the *exact* M3 saving
    /// (paired pretty→compact on the same payloads — always ≥ 0); the **net**
    /// report is the unpaired holdout (all-shaped vs all-unshaped), which folds in
    /// the reversible recall cost and can be negative.
    pub fn report(&self) -> HoldoutSnapshot {
        HoldoutSnapshot {
            n_control: self.control.len(),
            n_treatment: self.treatment.len(),
            net: unpaired_savings(&self.control, &self.treatment),
            n_compaction: self.compaction_pretty.len(),
            compaction: paired_savings(&self.compaction_pretty, &self.compaction_compact),
        }
    }

    #[cfg(test)]
    pub fn clear_for_test(&mut self) {
        self.control.clear();
        self.treatment.clear();
        self.compaction_pretty.clear();
        self.compaction_compact.clear();
    }
}

/// Per-mechanism live holdout snapshot (CO-5): the isolated compaction saving and
/// the conflated net, so the operator never reads one as the other.
#[derive(Clone, Debug)]
pub struct HoldoutSnapshot {
    pub n_control: usize,
    pub n_treatment: usize,
    /// All-shaped vs all-unshaped (folds in reversible's recall cost; may be < 0).
    pub net: SavingsReport,
    pub n_compaction: usize,
    /// Compaction-only (M3) saving — exact, paired, always ≥ 0.
    pub compaction: SavingsReport,
}

/// Process-wide live holdout accumulator.
pub fn accumulator() -> &'static Mutex<HoldoutAccumulator> {
    static ACC: OnceLock<Mutex<HoldoutAccumulator>> = OnceLock::new();
    ACC.get_or_init(|| Mutex::new(HoldoutAccumulator::default()))
}

/// Per-request control-arm decision for a live retrieval. `key` should be a
/// stable per-request string (e.g. the serialized tool args) so the same request
/// always lands in the same arm. Returns `false` whenever the holdout is OFF
/// (`fraction == 0`, the default) ⇒ no request is ever unshaped ⇒ behaviour is
/// byte-identical to holdout-off. When this returns `true`, the caller must
/// force the efficiency flags OFF for that request (the unshaped control arm).
pub fn request_is_control(key: &str) -> bool {
    let fraction = holdout_fraction();
    fraction > 0.0 && is_control(key, fraction)
}

/// Record one live retrieval's emitted token cost into its arm. No-op unless the
/// holdout is enabled (`fraction > 0`) — when OFF there is no control arm to
/// measure against, so we don't accumulate noise.
pub fn record_sample(is_control: bool, tokens: u64) {
    if holdout_fraction() <= 0.0 {
        return;
    }
    if let Ok(mut acc) = accumulator().lock() {
        acc.push(is_control, tokens);
    }
}

/// CO-5 — sample the **compaction-only** saving for one retrieval, exactly. For a
/// sampled fraction of requests (independent of the holdout arm, salted key) we
/// serialize the *same* emitted `value` both pretty and compact and record the
/// paired token counts, so the M3 saving is measured in isolation from M1's
/// recall cost. No-op when the holdout is OFF. Cheap: one extra serialization on
/// ~`fraction` of requests.
pub fn sample_compaction(key: &str, value: &serde_json::Value) {
    let fraction = holdout_fraction();
    if fraction <= 0.0 {
        return;
    }
    if !is_control(&format!("{key}:m3"), fraction) {
        return;
    }
    let pretty = crate::token_estimate::estimate_tokens_str(&serde_json::to_string_pretty(value).unwrap_or_default());
    let compact = crate::token_estimate::estimate_tokens_str(&serde_json::to_string(value).unwrap_or_default());
    if let Ok(mut acc) = accumulator().lock() {
        acc.push_compaction(pretty, compact);
    }
}

fn mean_var(xs: &[u64]) -> (f64, f64) {
    let n = xs.len() as f64;
    let mean = xs.iter().map(|x| *x as f64).sum::<f64>() / n;
    let var = if xs.len() >= 2 {
        xs.iter().map(|x| (*x as f64 - mean).powi(2)).sum::<f64>() / (n - 1.0)
    } else {
        0.0
    };
    (mean, var)
}

/// Savings of the treatment (shaped) arm vs. the control (unshaped) arm for
/// **unpaired** live traffic. `reduction = 1 - mean_treatment / mean_control`,
/// with a 95% CI on that ratio via the delta method:
/// `Var(ratio) ≈ ratio² · (var_t/(n_t·mean_t²) + var_c/(n_c·mean_c²))`.
/// Needs ≥2 samples in each arm and a positive control mean; otherwise the CI
/// collapses to the point estimate. Deterministic for identical inputs.
pub fn unpaired_savings(control: &[u64], treatment: &[u64]) -> SavingsReport {
    let control_tokens: u64 = control.iter().sum();
    let treatment_tokens: u64 = treatment.iter().sum();
    let n = control.len() + treatment.len();
    if control.is_empty() || treatment.is_empty() {
        return SavingsReport {
            n,
            reduction: 0.0,
            ci_low: 0.0,
            ci_high: 0.0,
            control_tokens,
            treatment_tokens,
        };
    }
    let (mean_c, var_c) = mean_var(control);
    let (mean_t, var_t) = mean_var(treatment);
    if mean_c <= 0.0 {
        return SavingsReport {
            n,
            reduction: 0.0,
            ci_low: 0.0,
            ci_high: 0.0,
            control_tokens,
            treatment_tokens,
        };
    }
    let ratio = mean_t / mean_c;
    let reduction = 1.0 - ratio;
    let se = if control.len() >= 2 && treatment.len() >= 2 {
        let rel_var_t = var_t / (treatment.len() as f64 * mean_t.max(f64::EPSILON).powi(2));
        let rel_var_c = var_c / (control.len() as f64 * mean_c.powi(2));
        (ratio.powi(2) * (rel_var_t + rel_var_c)).sqrt()
    } else {
        0.0
    };
    SavingsReport {
        n,
        reduction,
        ci_low: reduction - Z_95 * se,
        ci_high: reduction + Z_95 * se,
        control_tokens,
        treatment_tokens,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holdout_fraction_default_zero() {
        std::env::remove_var(HOLDOUT_ENV);
        assert_eq!(holdout_fraction(), 0.0);
    }

    #[test]
    fn is_control_bounds() {
        // fraction 0 ⇒ nobody is control; fraction 1 ⇒ everybody.
        assert!(!is_control("req-1", 0.0));
        assert!(is_control("req-1", 1.0));
    }

    #[test]
    fn is_control_is_deterministic_per_key() {
        // Same key ⇒ same arm, every time (reproducible split).
        let a = is_control("query:alpha:500", 0.3);
        let b = is_control("query:alpha:500", 0.3);
        assert_eq!(a, b);
    }

    #[test]
    fn is_control_splits_roughly_at_fraction() {
        // Over many distinct keys, ~10% land in control. Deterministic, so this
        // assertion is stable run-to-run (no rng).
        let n = 10_000;
        let control = (0..n).filter(|i| is_control(&format!("key-{i}"), 0.1)).count();
        let frac = control as f64 / n as f64;
        assert!((0.08..0.12).contains(&frac), "control fraction {frac} not ≈ 0.10");
    }

    #[test]
    fn paired_savings_clean_reduction_with_ci() {
        // Treatment uniformly ~25% cheaper ⇒ point estimate 25%, tight CI.
        let control = [100u64, 200, 400, 80];
        let treatment = [75u64, 150, 300, 60];
        let r = paired_savings(&control, &treatment);
        assert_eq!(r.n, 4);
        assert!((r.reduction - 0.25).abs() < 1e-9, "reduction {}", r.reduction);
        // All reductions identical ⇒ zero variance ⇒ CI collapses to the point.
        assert!((r.ci_low - 0.25).abs() < 1e-9);
        assert!((r.ci_high - 0.25).abs() < 1e-9);
        assert_eq!(r.control_tokens, 780);
        assert_eq!(r.treatment_tokens, 585);
    }

    #[test]
    fn paired_savings_ci_widens_with_variance() {
        // Mixed reductions ⇒ non-degenerate CI straddling the mean.
        let control = [100u64, 100, 100, 100];
        let treatment = [90u64, 70, 80, 60]; // reductions 0.10/0.30/0.20/0.40
        let r = paired_savings(&control, &treatment);
        assert_eq!(r.n, 4);
        assert!((r.reduction - 0.25).abs() < 1e-9);
        assert!(r.ci_low < r.reduction, "ci_low {} !< mean", r.ci_low);
        assert!(r.ci_high > r.reduction, "ci_high {} !> mean", r.ci_high);
    }

    #[test]
    fn paired_savings_skips_zero_control() {
        let control = [0u64, 100];
        let treatment = [0u64, 50];
        let r = paired_savings(&control, &treatment);
        assert_eq!(r.n, 1); // the zero-control pair is skipped
        assert!((r.reduction - 0.5).abs() < 1e-9);
    }

    #[test]
    fn unpaired_savings_reduction_and_ci() {
        // Control (unshaped) averages ~400 tok, treatment (shaped) ~300 ⇒ ~25%.
        let control = [400u64, 420, 380, 400, 410, 390];
        let treatment = [300u64, 310, 290, 300, 305, 295];
        let r = unpaired_savings(&control, &treatment);
        assert!((r.reduction - 0.25).abs() < 0.02, "reduction {}", r.reduction);
        assert!(r.ci_low < r.reduction && r.ci_high > r.reduction, "CI straddles point");
        assert!(r.ci_low > 0.0, "a real saving's CI should clear zero here");
    }

    #[test]
    fn unpaired_savings_empty_arm_is_zero() {
        let r = unpaired_savings(&[100, 100], &[]);
        assert_eq!(r.reduction, 0.0);
        assert_eq!(r.control_tokens, 200);
    }

    #[test]
    fn accumulator_records_per_arm_and_reports() {
        let acc = accumulator();
        {
            let mut a = acc.lock().unwrap();
            a.clear_for_test();
            for _ in 0..5 {
                a.push(true, 400); // control
                a.push(false, 300); // treatment
            }
        }
        let snap = acc.lock().unwrap().report();
        assert_eq!((snap.n_control, snap.n_treatment), (5, 5));
        assert!((snap.net.reduction - 0.25).abs() < 1e-9);
        acc.lock().unwrap().clear_for_test();
    }

    #[test]
    fn snapshot_separates_compaction_from_net() {
        let acc = accumulator();
        {
            let mut a = acc.lock().unwrap();
            a.clear_for_test();
            // Net arm: treatment (shaped, reversible recall) BIGGER than control
            // (unshaped, dropped) ⇒ a NEGATIVE net, like the live finding.
            for _ in 0..6 {
                a.push(true, 400); // control (unshaped)
                a.push(false, 600); // treatment (shaped — reversible added tokens)
            }
            // Compaction arm: same payload pretty→compact ⇒ a clean +25%.
            for _ in 0..6 {
                a.push_compaction(400, 300);
            }
        }
        let snap = acc.lock().unwrap().report();
        // Net is negative (reversible dominates)…
        assert!(
            snap.net.reduction < 0.0,
            "net {} should be negative",
            snap.net.reduction
        );
        // …but compaction is cleanly positive and isolated.
        assert!((snap.compaction.reduction - 0.25).abs() < 1e-9);
        assert_eq!(snap.n_compaction, 6);
        acc.lock().unwrap().clear_for_test();
    }

    #[test]
    fn report_is_deterministic_and_carries_provenance() {
        let r = paired_savings(&[100, 100, 100], &[70, 80, 75]);
        let a = r.format("__synthetic__::token-bench", "abc123");
        let b = r.format("__synthetic__::token-bench", "abc123");
        assert_eq!(a, b, "report must be byte-identical for identical inputs");
        assert!(a.contains("95% CI"));
        assert!(a.contains("corpus=__synthetic__::token-bench"));
        assert!(a.contains("commit=abc123"));
    }
}
