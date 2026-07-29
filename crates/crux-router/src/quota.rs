// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Per-surface request quota — the third fragment of the unified G20 spec
//! (ExecPlan `context-mediation-injection-2026-06-11`, M5).
//!
//! The three rate-limit fragments and where they live:
//!
//! 1. **Capability-token gate** (which backends/capabilities at all) — this
//!    crate's routing decisions over `RcxCapabilityToken`.
//! 2. **Credit balance** (metered spend) — `DenialReason::InsufficientCredit`
//!    + the ledger (plan D reconciliation owns spend).
//! 3. **Per-surface request limits** (this module) — a token bucket per
//!    `(passport, surface)`, generous defaults, protecting the *daemon*, not
//!    the business.
//!
//! Free-tier posture (normative): **local compute is never rate-limited** —
//! it is the user's CPU. Limits apply only to hosted surfaces. Backpressure
//! is `429` + `Retry-After` + remaining-quota headers; quota state is
//! queryable (`GET /v1/quota`, wired daemon-side).
//!
//! Like the rest of `crux-router`, this module is deliberately pure: the
//! caller supplies the clock (`now_secs`), state is an in-memory ledger, and
//! identical call sequences produce identical decisions (integer math only —
//! buckets are tracked in millitokens, no floats).

use std::collections::BTreeMap;

/// Surface classification for quota purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SurfaceClass {
    /// Local compute (the user's own CPU/daemon): NEVER rate-limited on the
    /// free tier — this is normative, not a default.
    LocalCompute,
    /// Hosted surfaces (remote daemon endpoints, hosted offload): token
    /// bucket applies.
    Hosted,
}

/// Token-bucket parameters for one surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaPolicy {
    /// Bucket capacity (burst) in requests.
    pub capacity: u32,
    /// Sustained refill rate, requests per minute.
    pub refill_per_minute: u32,
}

impl QuotaPolicy {
    /// Generous default for hosted surfaces: 120 burst, 60/min sustained.
    /// Protects the daemon from a runaway loop; an interactive agent never
    /// notices it.
    pub const HOSTED_DEFAULT: QuotaPolicy = QuotaPolicy {
        capacity: 120,
        refill_per_minute: 60,
    };

    /// Clamp degenerate configs (zero capacity/refill would deadlock a
    /// surface permanently — a misconfiguration, not a policy).
    fn normalized(self) -> QuotaPolicy {
        QuotaPolicy {
            capacity: self.capacity.max(1),
            refill_per_minute: self.refill_per_minute.max(1),
        }
    }
}

const MILLI: u64 = 1000;

/// Outcome of a quota check, carrying everything the HTTP layer needs to
/// emit `429` semantics without recomputing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaDecision {
    /// Request admitted. `remaining`/`limit` are `None` for unlimited
    /// (local-compute) surfaces.
    Allowed { remaining: Option<u64>, limit: Option<u64> },
    /// Request refused: `429 Too Many Requests` + `Retry-After`.
    Denied { retry_after_secs: u64, limit: u64 },
}

impl QuotaDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, QuotaDecision::Allowed { .. })
    }

    /// Response headers for this decision: `X-Crux-Quota-Limit` /
    /// `X-Crux-Quota-Remaining` when limited, plus `Retry-After` on denial.
    /// Unlimited surfaces emit no quota headers (nothing to back off from).
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        match self {
            QuotaDecision::Allowed {
                remaining: Some(remaining),
                limit: Some(limit),
            } => vec![
                ("X-Crux-Quota-Limit", limit.to_string()),
                ("X-Crux-Quota-Remaining", remaining.to_string()),
            ],
            QuotaDecision::Allowed { .. } => Vec::new(),
            QuotaDecision::Denied {
                retry_after_secs,
                limit,
            } => vec![
                ("X-Crux-Quota-Limit", limit.to_string()),
                ("X-Crux-Quota-Remaining", "0".to_string()),
                ("Retry-After", retry_after_secs.to_string()),
            ],
        }
    }
}

#[derive(Debug, Clone)]
struct Bucket {
    /// Available tokens in millitokens (integer math keeps decisions
    /// deterministic and replayable).
    millitokens: u64,
    /// Last refill timestamp (caller clock, seconds).
    last_refill_secs: u64,
    policy: QuotaPolicy,
}

impl Bucket {
    fn refill(&mut self, now_secs: u64) {
        let elapsed = now_secs.saturating_sub(self.last_refill_secs);
        if elapsed == 0 {
            return;
        }
        let earned = elapsed
            .saturating_mul(u64::from(self.policy.refill_per_minute))
            .saturating_mul(MILLI)
            / 60;
        let cap = u64::from(self.policy.capacity) * MILLI;
        self.millitokens = (self.millitokens.saturating_add(earned)).min(cap);
        self.last_refill_secs = now_secs;
    }

    /// Seconds until at least one whole token is available.
    fn retry_after_secs(&self) -> u64 {
        let deficit = MILLI.saturating_sub(self.millitokens);
        if deficit == 0 {
            return 0;
        }
        // ceil(deficit * 60 / (rate * MILLI)), rate >= 1 by normalization.
        let rate_milli_per_min = u64::from(self.policy.refill_per_minute) * MILLI;
        deficit.saturating_mul(60).div_ceil(rate_milli_per_min).max(1)
    }
}

/// Read-only view of one `(passport, surface)` bucket, for `GET /v1/quota`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaSnapshotEntry {
    pub surface: String,
    pub limit: u64,
    pub remaining: u64,
    pub refill_per_minute: u32,
}

/// In-memory quota ledger: one token bucket per `(passport, surface)`.
///
/// Pure state machine — the daemon owns persistence (quota buckets are
/// deliberately ephemeral: a restart refills everyone, which errs on the
/// side of the user).
#[derive(Debug, Default)]
pub struct QuotaLedger {
    /// Per-surface policy overrides; surfaces not listed use
    /// [`QuotaPolicy::HOSTED_DEFAULT`].
    policies: BTreeMap<String, QuotaPolicy>,
    buckets: BTreeMap<(String, String), Bucket>,
}

impl QuotaLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a per-surface policy (normalized: zero capacity/refill clamped
    /// to 1 — a quota must throttle, never deadlock).
    pub fn set_policy(&mut self, surface: &str, policy: QuotaPolicy) {
        self.policies.insert(surface.to_string(), policy.normalized());
    }

    fn policy_for(&self, surface: &str) -> QuotaPolicy {
        self.policies
            .get(surface)
            .copied()
            .unwrap_or(QuotaPolicy::HOSTED_DEFAULT)
            .normalized()
    }

    /// Admit or refuse one request on `surface` for `passport` at `now_secs`.
    ///
    /// `SurfaceClass::LocalCompute` is always admitted with no accounting —
    /// the free tier never limits the user's own compute (normative).
    pub fn check(&mut self, passport: &str, surface: &str, class: SurfaceClass, now_secs: u64) -> QuotaDecision {
        if class == SurfaceClass::LocalCompute {
            return QuotaDecision::Allowed {
                remaining: None,
                limit: None,
            };
        }
        let policy = self.policy_for(surface);
        let key = (passport.to_string(), surface.to_string());
        let bucket = self.buckets.entry(key).or_insert_with(|| Bucket {
            millitokens: u64::from(policy.capacity) * MILLI,
            last_refill_secs: now_secs,
            policy,
        });
        bucket.policy = policy;
        bucket.refill(now_secs);
        if bucket.millitokens >= MILLI {
            bucket.millitokens -= MILLI;
            QuotaDecision::Allowed {
                remaining: Some(bucket.millitokens / MILLI),
                limit: Some(u64::from(policy.capacity)),
            }
        } else {
            QuotaDecision::Denied {
                retry_after_secs: bucket.retry_after_secs(),
                limit: u64::from(policy.capacity),
            }
        }
    }

    /// Per-surface state for one passport (the `GET /v1/quota` payload).
    /// Surfaces the passport has never touched report a full bucket.
    pub fn snapshot(&mut self, passport: &str, now_secs: u64) -> Vec<QuotaSnapshotEntry> {
        let mut entries = Vec::new();
        let surfaces: Vec<String> = self.policies.keys().cloned().collect();
        for surface in surfaces {
            let policy = self.policy_for(&surface);
            let key = (passport.to_string(), surface.clone());
            let remaining = match self.buckets.get_mut(&key) {
                Some(bucket) => {
                    bucket.refill(now_secs);
                    bucket.millitokens / MILLI
                }
                None => u64::from(policy.capacity),
            };
            entries.push(QuotaSnapshotEntry {
                surface,
                limit: u64::from(policy.capacity),
                remaining,
                refill_per_minute: policy.refill_per_minute,
            });
        }
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: u64 = 1_781_222_400; // 2026-06-12T00:00:00Z

    #[test]
    fn local_compute_is_always_unlimited() {
        let mut ledger = QuotaLedger::new();
        for i in 0..10_000u64 {
            let decision = ledger.check("p1", "mcp_local", SurfaceClass::LocalCompute, T0 + i / 100);
            assert_eq!(
                decision,
                QuotaDecision::Allowed {
                    remaining: None,
                    limit: None
                }
            );
            assert!(
                decision.headers().is_empty(),
                "unlimited surfaces emit no quota headers"
            );
        }
        // No bucket state is even created for local surfaces.
        assert!(ledger.buckets.is_empty());
    }

    #[test]
    fn hosted_bucket_drains_to_429_with_retry_after() {
        let mut ledger = QuotaLedger::new();
        ledger.set_policy(
            "hosted_offload",
            QuotaPolicy {
                capacity: 3,
                refill_per_minute: 60,
            },
        );
        for expected_remaining in [2u64, 1, 0] {
            let decision = ledger.check("p1", "hosted_offload", SurfaceClass::Hosted, T0);
            assert_eq!(
                decision,
                QuotaDecision::Allowed {
                    remaining: Some(expected_remaining),
                    limit: Some(3)
                }
            );
        }
        let denied = ledger.check("p1", "hosted_offload", SurfaceClass::Hosted, T0);
        // 60/min = 1 token/sec → next token in 1s.
        assert_eq!(
            denied,
            QuotaDecision::Denied {
                retry_after_secs: 1,
                limit: 3
            }
        );
        let headers = denied.headers();
        assert!(headers.contains(&("Retry-After", "1".to_string())));
        assert!(headers.contains(&("X-Crux-Quota-Remaining", "0".to_string())));
    }

    #[test]
    fn hosted_burst_load_admits_exact_capacity() {
        let mut ledger = QuotaLedger::new();
        ledger.set_policy(
            "hosted_offload",
            QuotaPolicy {
                capacity: 128,
                refill_per_minute: 1,
            },
        );

        let decisions: Vec<_> = (0..256)
            .map(|_| ledger.check("paid-passport", "hosted_offload", SurfaceClass::Hosted, T0))
            .collect();
        let allowed = decisions.iter().filter(|decision| decision.is_allowed()).count();
        let denied = decisions.len() - allowed;

        assert_eq!(allowed, 128);
        assert_eq!(denied, 128);
        assert!(decisions[128..].iter().all(|decision| {
            matches!(
                decision,
                QuotaDecision::Denied {
                    retry_after_secs: 60,
                    limit: 128
                }
            )
        }));
        let snapshot = ledger.snapshot("paid-passport", T0);
        assert_eq!(snapshot[0].remaining, 0);
        assert_eq!(snapshot[0].limit, 128);
    }

    #[test]
    fn refill_restores_admission() {
        let mut ledger = QuotaLedger::new();
        ledger.set_policy(
            "hosted_offload",
            QuotaPolicy {
                capacity: 2,
                refill_per_minute: 30,
            },
        );
        assert!(ledger
            .check("p1", "hosted_offload", SurfaceClass::Hosted, T0)
            .is_allowed());
        assert!(ledger
            .check("p1", "hosted_offload", SurfaceClass::Hosted, T0)
            .is_allowed());
        assert!(!ledger
            .check("p1", "hosted_offload", SurfaceClass::Hosted, T0)
            .is_allowed());
        // 30/min = 1 token per 2s. At T0+2 exactly one token has refilled.
        let decision = ledger.check("p1", "hosted_offload", SurfaceClass::Hosted, T0 + 2);
        assert_eq!(
            decision,
            QuotaDecision::Allowed {
                remaining: Some(0),
                limit: Some(2)
            }
        );
        // …and only one.
        assert!(!ledger
            .check("p1", "hosted_offload", SurfaceClass::Hosted, T0 + 2)
            .is_allowed());
    }

    #[test]
    fn refill_caps_at_capacity() {
        let mut ledger = QuotaLedger::new();
        ledger.set_policy(
            "s",
            QuotaPolicy {
                capacity: 5,
                refill_per_minute: 600,
            },
        );
        assert!(ledger.check("p1", "s", SurfaceClass::Hosted, T0).is_allowed());
        // A year later the bucket holds capacity, not capacity + a year of refill.
        let decision = ledger.check("p1", "s", SurfaceClass::Hosted, T0 + 31_536_000);
        assert_eq!(
            decision,
            QuotaDecision::Allowed {
                remaining: Some(4),
                limit: Some(5)
            }
        );
    }

    #[test]
    fn passports_and_surfaces_are_isolated() {
        let mut ledger = QuotaLedger::new();
        ledger.set_policy(
            "a",
            QuotaPolicy {
                capacity: 1,
                refill_per_minute: 1,
            },
        );
        ledger.set_policy(
            "b",
            QuotaPolicy {
                capacity: 1,
                refill_per_minute: 1,
            },
        );
        assert!(ledger.check("p1", "a", SurfaceClass::Hosted, T0).is_allowed());
        assert!(!ledger.check("p1", "a", SurfaceClass::Hosted, T0).is_allowed());
        // p2 on the same surface, and p1 on another surface, are unaffected.
        assert!(ledger.check("p2", "a", SurfaceClass::Hosted, T0).is_allowed());
        assert!(ledger.check("p1", "b", SurfaceClass::Hosted, T0).is_allowed());
    }

    #[test]
    fn decisions_are_deterministic_for_identical_sequences() {
        let run = || {
            let mut ledger = QuotaLedger::new();
            ledger.set_policy(
                "s",
                QuotaPolicy {
                    capacity: 4,
                    refill_per_minute: 7,
                },
            );
            let mut decisions = Vec::new();
            for i in 0..200u64 {
                decisions.push(ledger.check("p", "s", SurfaceClass::Hosted, T0 + i * 3));
            }
            decisions
        };
        assert_eq!(run(), run(), "same clock sequence must yield identical decisions");
    }

    #[test]
    fn retry_after_reflects_slow_refill() {
        let mut ledger = QuotaLedger::new();
        // 1/min: a full minute to the next token.
        ledger.set_policy(
            "slow",
            QuotaPolicy {
                capacity: 1,
                refill_per_minute: 1,
            },
        );
        assert!(ledger.check("p", "slow", SurfaceClass::Hosted, T0).is_allowed());
        let denied = ledger.check("p", "slow", SurfaceClass::Hosted, T0);
        assert_eq!(
            denied,
            QuotaDecision::Denied {
                retry_after_secs: 60,
                limit: 1
            }
        );
    }

    #[test]
    fn degenerate_policies_are_clamped_not_deadlocked() {
        let mut ledger = QuotaLedger::new();
        ledger.set_policy(
            "z",
            QuotaPolicy {
                capacity: 0,
                refill_per_minute: 0,
            },
        );
        // Clamped to 1/1: one request admitted, then a bounded retry-after.
        assert!(ledger.check("p", "z", SurfaceClass::Hosted, T0).is_allowed());
        let denied = ledger.check("p", "z", SurfaceClass::Hosted, T0);
        assert!(!denied.is_allowed(), "expected denial, got {denied:?}");
        if let QuotaDecision::Denied { retry_after_secs, .. } = denied {
            assert!(retry_after_secs <= 60, "retry must be bounded, got {retry_after_secs}");
        }
    }

    #[test]
    fn snapshot_reports_per_surface_state() {
        let mut ledger = QuotaLedger::new();
        ledger.set_policy(
            "a",
            QuotaPolicy {
                capacity: 3,
                refill_per_minute: 60,
            },
        );
        ledger.set_policy(
            "b",
            QuotaPolicy {
                capacity: 9,
                refill_per_minute: 60,
            },
        );
        let _ = ledger.check("p", "a", SurfaceClass::Hosted, T0);
        let snap = ledger.snapshot("p", T0);
        assert_eq!(snap.len(), 2);
        assert_eq!(snap[0].surface, "a");
        assert_eq!(snap[0].remaining, 2);
        assert_eq!(snap[0].limit, 3);
        // Untouched surface reports a full bucket.
        assert_eq!(snap[1].surface, "b");
        assert_eq!(snap[1].remaining, 9);
    }

    #[test]
    fn unknown_surface_uses_generous_hosted_default() {
        let mut ledger = QuotaLedger::new();
        let decision = ledger.check("p", "new_surface", SurfaceClass::Hosted, T0);
        assert_eq!(
            decision,
            QuotaDecision::Allowed {
                remaining: Some(119),
                limit: Some(120)
            }
        );
    }
}
