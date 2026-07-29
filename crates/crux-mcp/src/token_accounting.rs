// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! In-memory per-passport token accounting (action-ledger M1).
//!
//! Every `tools/call` dispatch increments a per-passport accumulator
//! with the estimated token cost of its arguments and result (see
//! [`crate::token_estimate`]). The `session_token_usage` MCP tool reads
//! it back as `{used, limit, pct}`.
//!
//! Design notes:
//! - This deliberately does NOT live on
//!   `corecrux_memory::SessionState` — that struct is the *persisted
//!   session document* (JSONL-journaled, event-bus-notified); mutating
//!   it on every tool call would spam the journal. The accumulator is
//!   process-local observability state, exactly like the trace ring in
//!   [`crate::traces`]. The durable per-call record is the
//!   `agent.tool_invocation.v1` ledger event (M2).
//! - Unauthenticated callers accumulate under the
//!   [`crate::traces::ANON_PASSPORT`] sentinel, partitioned from every
//!   named passport (QC.3: anon is counted, but counted separately).
//! - Recording is unconditional (no feature flag): it is O(1) work on
//!   numbers already computed for the ledger, holds the mutex for a
//!   few loads/stores, and changes no wire behaviour.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde::Serialize;
use tokio::sync::Mutex;

/// Optional per-session/per-passport token budget limit, read from the
/// environment. `0`, empty, or unset means "no limit" (pct omitted).
pub const SESSION_BUDGET_ENV: &str = "CORECRUXD_SESSION_TOKEN_BUDGET";

/// Accumulated usage for one passport.
#[derive(Debug, Default, Clone, Serialize)]
pub struct PassportUsage {
    /// Number of `tools/call` dispatches recorded.
    pub calls: u64,
    /// Estimated tokens in tool arguments.
    pub tokens_in: u64,
    /// Estimated tokens in tool results (or error messages).
    pub tokens_out: u64,
    /// Sum of explicit `token_budget` arguments the caller declared
    /// (QC.2 conformance signal: compare against `tokens_out`).
    pub declared_budget_in: u64,
}

impl PassportUsage {
    /// Total estimated tokens used (in + out).
    pub fn total(&self) -> u64 {
        self.tokens_in.saturating_add(self.tokens_out)
    }
}

#[derive(Debug, Default)]
struct UsageStore {
    by_passport: HashMap<String, PassportUsage>,
}

fn global() -> &'static Mutex<UsageStore> {
    static STORE: OnceLock<Mutex<UsageStore>> = OnceLock::new();
    STORE.get_or_init(|| Mutex::new(UsageStore::default()))
}

/// Record one dispatch into the passport's accumulator.
pub async fn record_usage(passport: &str, tokens_in: u64, tokens_out: u64, declared_budget_in: Option<u64>) {
    let mut store = global().lock().await;
    let entry = store.by_passport.entry(passport.to_string()).or_default();
    entry.calls += 1;
    entry.tokens_in = entry.tokens_in.saturating_add(tokens_in);
    entry.tokens_out = entry.tokens_out.saturating_add(tokens_out);
    if let Some(b) = declared_budget_in {
        entry.declared_budget_in = entry.declared_budget_in.saturating_add(b);
    }
}

/// Read back the accumulator for one passport (zeroed default when the
/// passport has made no calls yet).
pub async fn usage_for(passport: &str) -> PassportUsage {
    global()
        .lock()
        .await
        .by_passport
        .get(passport)
        .cloned()
        .unwrap_or_default()
}

/// Configured session token budget limit, if any.
pub fn session_budget_limit() -> Option<u64> {
    match std::env::var(SESSION_BUDGET_ENV) {
        Ok(v) => match v.trim().parse::<u64>() {
            Ok(0) | Err(_) => None,
            Ok(n) => Some(n),
        },
        Err(_) => None,
    }
}

/// Test-only: clear one passport's bucket so tests are independent of
/// each other and of dispatch ordering.
#[cfg(test)]
pub async fn clear_for_test(passport: &str) {
    global().lock().await.by_passport.remove(passport);
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn accumulates_per_passport() {
        let p = "token-accounting-test::accumulates";
        clear_for_test(p).await;
        record_usage(p, 10, 200, Some(500)).await;
        record_usage(p, 5, 100, None).await;
        let u = usage_for(p).await;
        assert_eq!(u.calls, 2);
        assert_eq!(u.tokens_in, 15);
        assert_eq!(u.tokens_out, 300);
        assert_eq!(u.declared_budget_in, 500);
        assert_eq!(u.total(), 315);
    }

    #[tokio::test]
    async fn isolates_passports() {
        let a = "token-accounting-test::iso-a";
        let b = "token-accounting-test::iso-b";
        clear_for_test(a).await;
        clear_for_test(b).await;
        record_usage(a, 1, 2, None).await;
        let ub = usage_for(b).await;
        assert_eq!(ub.calls, 0);
        assert_eq!(ub.total(), 0);
    }

    #[tokio::test]
    async fn total_saturates_instead_of_overflowing() {
        let p = "token-accounting-test::saturate";
        clear_for_test(p).await;
        record_usage(p, u64::MAX, u64::MAX, None).await;
        record_usage(p, u64::MAX, u64::MAX, Some(u64::MAX)).await;
        let u = usage_for(p).await;
        assert_eq!(u.tokens_in, u64::MAX);
        assert_eq!(u.tokens_out, u64::MAX);
        assert_eq!(u.total(), u64::MAX);
    }

    #[tokio::test]
    async fn budget_limit_parses_env_shapes() {
        // Mutates process env — serialise behind the crate-wide env
        // lock shared by every env-mutating test in crux-mcp.
        let _g = crate::test_env_lock().lock().await;
        std::env::remove_var(SESSION_BUDGET_ENV);
        assert_eq!(session_budget_limit(), None);
        std::env::set_var(SESSION_BUDGET_ENV, "0");
        assert_eq!(session_budget_limit(), None);
        std::env::set_var(SESSION_BUDGET_ENV, "not-a-number");
        assert_eq!(session_budget_limit(), None);
        std::env::set_var(SESSION_BUDGET_ENV, "250000");
        assert_eq!(session_budget_limit(), Some(250_000));
        std::env::remove_var(SESSION_BUDGET_ENV);
    }
}
