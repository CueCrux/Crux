// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
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
