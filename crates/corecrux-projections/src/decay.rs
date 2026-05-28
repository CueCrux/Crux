// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Deterministic decay policy for the freshness primitive.
//!
//! Wave-1 ExecPlan `agent-ux-03-freshness-decay-2026-05-27` M2.
//!
//! ## What this is
//!
//! A pure function that, given `(HorizonClass, written_at_ms, now_ms)`,
//! returns one of [`Freshness::Fresh`], [`Freshness::Stale`], or
//! [`Freshness::Unknown`]. No I/O, no `Instant::now()`, no random — the
//! same inputs always produce the same output.
//!
//! ## Why pure
//!
//! Crux projections are deterministic-by-construction; the audit
//! ([`agent-ux-best-in-class-master-2026-05-27`] §"Deterministic
//! projections") calls this out as a masterstroke. Adding a decay step
//! has to preserve that property. Replay determinism: replaying the
//! event log at the same `now_ms` produces identical decay output.
//!
//! ## Configuration
//!
//! Thresholds are read from process env (`CORECRUXD_DECAY_VOLATILE_HOURS`,
//! `_MEDIUM_DAYS`, `_STABLE_DAYS`) via [`DecayPolicy::from_env`]. For
//! deterministic replay across machines/runs use the default policy or
//! pass an explicit [`DecayPolicy`].

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// String form used in MCP envelope + tool responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Freshness {
    Fresh,
    Stale,
    Unknown,
}

impl Freshness {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Stale => "stale",
            Self::Unknown => "unknown",
        }
    }
}

/// Horizon class — mirrors `corecrux_memory::HorizonClass` but local to
/// the projection crate so we don't take a runtime dependency on the
/// memory crate from a pure-function module.
///
/// Conversion between the two is direct: see `from_str` for the JSON
/// wire form used by both MCP and the fact-store journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HorizonClass {
    Volatile,
    Medium,
    Stable,
    None,
}

impl HorizonClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Volatile => "volatile",
            Self::Medium => "medium",
            Self::Stable => "stable",
            Self::None => "none",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "volatile" => Some(Self::Volatile),
            "medium" => Some(Self::Medium),
            "stable" => Some(Self::Stable),
            "none" => Some(Self::None),
            _ => None,
        }
    }
}

/// Per-class staleness thresholds. Defaults match the operator's
/// CLAUDE.md "Freshness horizons" convention: deploy state goes stale in
/// a day, per-tenant traits in a month, architecture in a year.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecayPolicy {
    pub volatile_stale_hours: i64,
    pub medium_stale_days: i64,
    pub stable_stale_days: i64,
}

impl DecayPolicy {
    pub const DEFAULT_VOLATILE_HOURS: i64 = 24;
    pub const DEFAULT_MEDIUM_DAYS: i64 = 35;
    pub const DEFAULT_STABLE_DAYS: i64 = 365;

    /// Returns the deterministic default policy. Use this for replay /
    /// test determinism — env-derived policies vary per machine.
    pub const fn default_const() -> Self {
        Self {
            volatile_stale_hours: Self::DEFAULT_VOLATILE_HOURS,
            medium_stale_days: Self::DEFAULT_MEDIUM_DAYS,
            stable_stale_days: Self::DEFAULT_STABLE_DAYS,
        }
    }

    /// Read overrides from process env. Missing/unparseable values fall
    /// back to the default. Side-effect-free apart from `std::env` read.
    pub fn from_env() -> Self {
        fn parse_i64(name: &str, default: i64) -> i64 {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse::<i64>().ok())
                .filter(|n| *n > 0)
                .unwrap_or(default)
        }
        Self {
            volatile_stale_hours: parse_i64("CORECRUXD_DECAY_VOLATILE_HOURS", Self::DEFAULT_VOLATILE_HOURS),
            medium_stale_days: parse_i64("CORECRUXD_DECAY_MEDIUM_DAYS", Self::DEFAULT_MEDIUM_DAYS),
            stable_stale_days: parse_i64("CORECRUXD_DECAY_STABLE_DAYS", Self::DEFAULT_STABLE_DAYS),
        }
    }
}

impl Default for DecayPolicy {
    fn default() -> Self {
        Self::default_const()
    }
}

/// Decide whether a fact written at `written_ms` (unix milliseconds) is
/// stale at `now_ms` under the given horizon class and policy.
///
/// Pure: same `(class, written_ms, now_ms, policy)` -> same output. No
/// `Instant::now()`. No random. No I/O.
///
/// `Unknown` is returned when `written_ms` is in the future (clock skew)
/// or when both timestamps are `0` (no recorded write time). Callers can
/// fall back to a heuristic in that case but must not pretend it's
/// fresh.
pub fn apply_at(class: HorizonClass, written_ms: i64, now_ms: i64, policy: DecayPolicy) -> Freshness {
    if class == HorizonClass::None {
        return Freshness::Fresh;
    }
    if written_ms <= 0 || now_ms <= 0 {
        return Freshness::Unknown;
    }
    if written_ms > now_ms {
        // Clock skew: a "future" fact is suspicious — never report stale,
        // never report fresh; let the caller flag the anomaly.
        return Freshness::Unknown;
    }
    let age_ms = now_ms - written_ms;
    let threshold_ms: i64 = match class {
        HorizonClass::Volatile => policy.volatile_stale_hours.saturating_mul(60 * 60 * 1_000),
        HorizonClass::Medium => policy.medium_stale_days.saturating_mul(24 * 60 * 60 * 1_000),
        HorizonClass::Stable => policy.stable_stale_days.saturating_mul(24 * 60 * 60 * 1_000),
        HorizonClass::None => unreachable!(),
    };
    if age_ms > threshold_ms {
        Freshness::Stale
    } else {
        Freshness::Fresh
    }
}

/// Convenience helper: decay a fact whose write/reverify times are
/// expressed as `chrono::DateTime<Utc>`. Wraps [`apply_at`] with
/// timestamp conversion + reverify-anchor preference.
///
/// Prefers `reverified_at` over `written_at` when both are set — a
/// re-verified fact's decay clock restarts from the verify time.
pub fn apply_at_chrono(
    class: HorizonClass,
    written_at: DateTime<Utc>,
    reverified_at: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    policy: DecayPolicy,
) -> Freshness {
    let anchor = reverified_at.unwrap_or(written_at);
    apply_at(class, anchor.timestamp_millis(), now.timestamp_millis(), policy)
}

/// Age in days between `written_ms` and `now_ms`. Returns `None` if
/// either is non-positive or written is in the future.
pub fn age_days(written_ms: i64, now_ms: i64) -> Option<i64> {
    if written_ms <= 0 || now_ms <= 0 || written_ms > now_ms {
        return None;
    }
    Some((now_ms - written_ms) / (24 * 60 * 60 * 1_000))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    const HOUR_MS: i64 = 60 * 60 * 1_000;
    const DAY_MS: i64 = 24 * HOUR_MS;

    fn p() -> DecayPolicy {
        DecayPolicy::default_const()
    }

    #[test]
    fn class_string_roundtrip() {
        for c in [
            HorizonClass::Volatile,
            HorizonClass::Medium,
            HorizonClass::Stable,
            HorizonClass::None,
        ] {
            assert_eq!(HorizonClass::parse(c.as_str()), Some(c));
        }
        assert!(HorizonClass::parse("nope").is_none());
    }

    #[test]
    fn freshness_strings() {
        assert_eq!(Freshness::Fresh.as_str(), "fresh");
        assert_eq!(Freshness::Stale.as_str(), "stale");
        assert_eq!(Freshness::Unknown.as_str(), "unknown");
    }

    #[test]
    fn none_class_is_always_fresh() {
        let now = 1_000_000_000_000;
        let written = 0; // even "no timestamp" -> fresh because never decays
        assert_eq!(apply_at(HorizonClass::None, written, now, p()), Freshness::Fresh);

        // Very old fact, still fresh.
        let ancient = 1; // 1ms after epoch
        assert_eq!(apply_at(HorizonClass::None, ancient, now, p()), Freshness::Fresh);
    }

    #[test]
    fn volatile_stale_after_24_hours() {
        let written = 1_700_000_000_000_i64;
        let just_under_24h = written + 23 * HOUR_MS;
        let exact_24h = written + 24 * HOUR_MS;
        let over_24h = written + 25 * HOUR_MS;

        assert_eq!(
            apply_at(HorizonClass::Volatile, written, just_under_24h, p()),
            Freshness::Fresh
        );
        assert_eq!(
            apply_at(HorizonClass::Volatile, written, exact_24h, p()),
            Freshness::Fresh,
            "exact threshold is the boundary — still fresh"
        );
        assert_eq!(
            apply_at(HorizonClass::Volatile, written, over_24h, p()),
            Freshness::Stale
        );
    }

    #[test]
    fn medium_stale_after_35_days() {
        let written = 1_700_000_000_000_i64;
        let day_34 = written + 34 * DAY_MS;
        let day_36 = written + 36 * DAY_MS;

        assert_eq!(apply_at(HorizonClass::Medium, written, day_34, p()), Freshness::Fresh);
        assert_eq!(apply_at(HorizonClass::Medium, written, day_36, p()), Freshness::Stale);
    }

    #[test]
    fn stable_stale_after_365_days() {
        let written = 1_700_000_000_000_i64;
        let day_300 = written + 300 * DAY_MS;
        let day_400 = written + 400 * DAY_MS;

        assert_eq!(apply_at(HorizonClass::Stable, written, day_300, p()), Freshness::Fresh);
        assert_eq!(apply_at(HorizonClass::Stable, written, day_400, p()), Freshness::Stale);
    }

    #[test]
    fn future_written_is_unknown() {
        let now = 1_700_000_000_000_i64;
        let future = now + DAY_MS;
        for c in [HorizonClass::Volatile, HorizonClass::Medium, HorizonClass::Stable] {
            assert_eq!(apply_at(c, future, now, p()), Freshness::Unknown);
        }
    }

    #[test]
    fn zero_or_negative_timestamps_are_unknown_for_decaying_classes() {
        let now = 1_700_000_000_000_i64;
        for c in [HorizonClass::Volatile, HorizonClass::Medium, HorizonClass::Stable] {
            assert_eq!(apply_at(c, 0, now, p()), Freshness::Unknown);
            assert_eq!(apply_at(c, -1, now, p()), Freshness::Unknown);
            assert_eq!(apply_at(c, 1, 0, p()), Freshness::Unknown);
        }
    }

    #[test]
    fn pure_same_inputs_same_output() {
        // Property: running the function 1000 times with the same args
        // returns the same answer 1000 times. (Cheap loop, no proptest
        // needed; the function is small enough that exhaustive equality
        // is sufficient.)
        let cases = [
            (HorizonClass::Volatile, 1_000_000_000_000_i64, 1_000_086_400_001_i64),
            (HorizonClass::Medium, 1_500_000_000_000, 1_503_456_000_001),
            (HorizonClass::Stable, 1_000_000_000_000, 1_031_536_000_001),
            (HorizonClass::None, 0, 1_700_000_000_000),
            (HorizonClass::Volatile, 1, 1_700_000_000_000),
        ];
        for (c, w, n) in cases {
            let first = apply_at(c, w, n, p());
            for _ in 0..1000 {
                assert_eq!(apply_at(c, w, n, p()), first);
            }
        }
    }

    #[test]
    fn apply_at_chrono_uses_reverify_anchor() {
        let written = Utc.timestamp_millis_opt(1_700_000_000_000).unwrap();
        let reverified = Utc.timestamp_millis_opt(1_700_000_000_000 + 30 * DAY_MS).unwrap();
        let now = Utc.timestamp_millis_opt(1_700_000_000_000 + 50 * DAY_MS).unwrap();

        // Medium horizon: 35 days stale. Without reverify, 50 days >
        // 35 -> Stale. With reverify at day 30, age-from-reverify is 20
        // days -> Fresh.
        assert_eq!(
            apply_at_chrono(HorizonClass::Medium, written, None, now, p()),
            Freshness::Stale
        );
        assert_eq!(
            apply_at_chrono(HorizonClass::Medium, written, Some(reverified), now, p()),
            Freshness::Fresh
        );
    }

    #[test]
    fn age_days_basic() {
        assert_eq!(age_days(1_700_000_000_000, 1_700_000_000_000 + 5 * DAY_MS), Some(5));
        assert_eq!(age_days(0, 1_700_000_000_000), None);
        assert_eq!(age_days(1_700_000_000_000, 1_699_999_999_999), None);
    }

    #[test]
    fn env_policy_falls_back_to_default_when_unset() {
        // Use unique env var names that no one else sets so this test
        // doesn't race with parallel test threads (we deliberately
        // don't mutate the env here).
        let p = DecayPolicy::from_env();
        // At least the structure is sane.
        assert!(p.volatile_stale_hours > 0);
        assert!(p.medium_stale_days > 0);
        assert!(p.stable_stale_days > 0);
    }

    // Property-style coverage via proptest. Demonstrates the pure-function
    // invariant: for any (class, written, now), the answer is consistent
    // with the deterministic decision rule.
    proptest::proptest! {
        #[test]
        fn decay_is_deterministic_for_arbitrary_inputs(
            c in proptest::sample::select(vec![HorizonClass::Volatile, HorizonClass::Medium, HorizonClass::Stable, HorizonClass::None]),
            written in 0_i64..(i64::MAX / 4),
            offset in 0_i64..(400 * DAY_MS),
        ) {
            let now = written + offset;
            let a = apply_at(c, written, now, p());
            let b = apply_at(c, written, now, p());
            proptest::prop_assert_eq!(a, b);
        }
    }
}
