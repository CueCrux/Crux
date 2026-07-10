// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

#![recursion_limit = "256"]

//! `crux-mcp` — MCP server for agent integration with Crux Daemon.
//!
//! Implements JSON-RPC 2.0 transport, tool dispatch, and an axum HTTP server
//! that exposes CoreCrux capabilities over the MCP Streamable HTTP protocol.
//!
//! ## Tools exposed
//!
//! - `query` — BM25 full-text search with coverage reporting
//! - `store_fact` — write a receipted fact to entity memory
//! - `query_facts` — search the fact store
//! - `save_session` / `load_session` — persist and resume session state
//! - `create_handoff` / `accept_handoff` — multi-agent context transfer
//!
//! ## Authentication
//!
//! Agents authenticate via `CRUX_AGENT_TOKEN` (Bearer token). The token is
//! validated in the [`agent`] module before any tool dispatch.

#![deny(clippy::unwrap_used)]

pub mod agent;
pub mod agent_card;
pub mod agent_passport;
pub mod budget;
pub mod category_enforce;
pub mod crc_v1;
pub mod dispatch;
pub mod envelope;
pub mod handoff;
pub mod holdout;
pub mod learn;
pub mod ledger;
pub mod oauth;
pub mod otel;
pub mod payload;
pub mod protocol;
pub mod scope;
pub mod server;
pub mod sse;
pub mod tenant_category;
pub mod token_accounting;
pub mod token_estimate;
pub mod tools;
pub mod traces;

/// agent-passport M5 T.1 regression suite — the merge bar for the
/// cross-tenant-leak surface. Exhaustively probes write-enforcement,
/// private-scope hardening, adversarial cross-tenant reads, migration
/// back-compat, and the flag-OFF byte-for-byte control across `query_facts`,
/// `memory_view`, `fact_history`, `delete_fact`, supersede, and the `query`
/// (BM25 retrieval) path. See the module header for the exact guarantee
/// matrix.
#[cfg(test)]
mod t1_regression;

/// Process-wide test lock for every env-var mutating test in `crux-mcp`.
///
/// Rust's `std::env::{set_var, remove_var, var}` are not thread-safe —
/// they wrap C's `setenv` / `getenv` which mutate a single process-wide
/// `environ` pointer array without synchronisation. Holding per-module
/// locks is insufficient: concurrent threads each holding their own
/// per-module lock still race on `environ`, and a sibling thread's
/// concurrent `set_var` (for an unrelated variable) can interleave the
/// underlying allocation/copy/swap so that a `var()` read briefly
/// observes a stale or partially-updated array. The visible symptom is
/// flakes like `tools::traces::tests::*` returning `Number(0)` when a
/// preceding `set_var(FEATURE_FLAG, "1")` should have made
/// `traces_enabled()` return true.
///
/// Every test in this crate that calls `std::env::set_var` /
/// `std::env::remove_var` (or reads an env var whose value matters)
/// MUST acquire this single lock. Module-local lock functions in this
/// crate now delegate here so existing import paths keep working.
///
/// Not gated on `#[cfg(test)]` because a handful of test-helper
/// functions (`tools::approvals::_approvals_test_lock`,
/// `tools::artefacts::artefact_flag_lock`) are exposed `pub` for
/// cross-module test wiring and must be callable from non-`test` build
/// modes too. The function has no side effects when not invoked.
#[doc(hidden)]
pub fn test_env_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}
