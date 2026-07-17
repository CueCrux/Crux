// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

// Tests use unwrap/expect freely; production code denies them.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! `crux-claude-hooks` — Claude Code lifecycle hook binaries for the Crux Daemon.
//!
//! Three subcommands, each fired by the Claude Code harness at a specific
//! lifecycle event:
//!
//! - `context-monitor` (PostToolUse): read-only loop / file-scope warnings,
//!   surfaced inline via `additionalContext`. Never writes facts.
//! - `pre-compact` (PreCompact): snapshots session state to the Crux daemon
//!   via MCP `save_session`. Best-effort, non-blocking.
//! - `session-start` (SessionStart): calls `sync_status` and
//!   `get_bootstrap("patterns")` with `token_budget=500`, returns the result
//!   as `additionalContext`.

pub mod cmds;
pub mod config_audit;
pub mod daemon_client;
pub mod hook_input;
pub mod hook_output;
pub mod llm_shim;
pub mod mcp_client;
pub mod observe_capture;
pub mod observe_filemod;
pub mod snapshot_crypto;
pub mod state;

/// Default Crux MCP endpoint. Override with `CRUX_MCP_URL`.
pub const DEFAULT_MCP_URL: &str = "http://127.0.0.1:14801/mcp";

/// Default Crux daemon HTTP endpoint. Override with `CRUX_HTTP_URL`. The
/// audit-capture hooks talk to the daemon directly over HTTP (the observe
/// surface has no MCP tool — capture writes go to `/v1/observe/*`).
pub const DEFAULT_HTTP_URL: &str = "http://127.0.0.1:14800";

/// MCP call timeout. Hooks must stay cheap on the PostToolUse path.
pub const MCP_TIMEOUT_SECS: u64 = 2;

/// Test-only support shared across the crate's unit tests.
///
/// Several tests toggle process-global env vars (`CRUX_HTTP_URL`,
/// `CRUX_AGENT_TOKEN`, `CRUX_MCP_URL`, `CRUX_HOOK_OBSERVE_CAPTURE`, …). Cargo
/// runs unit tests in one process across many threads, so two tests racing on
/// the same var read each other's writes. Every env-mutating test acquires
/// [`test_support::env_guard`] first, serialising them through one mutex (the
/// crate-wide-lock pattern from the `crux-mcp` test suite).
#[cfg(test)]
pub mod test_support {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    /// Acquire the crate-wide env-mutation lock. Hold the returned guard for the
    /// duration of any test that reads or writes process env. Poisoning is
    /// recovered (a panicking test must not wedge the whole suite).
    pub fn env_guard() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}
