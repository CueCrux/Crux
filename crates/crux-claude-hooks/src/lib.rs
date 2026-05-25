// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
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
pub mod hook_input;
pub mod hook_output;
pub mod mcp_client;
pub mod state;

/// Default Crux MCP endpoint. Override with `CRUX_MCP_URL`.
pub const DEFAULT_MCP_URL: &str = "http://127.0.0.1:14801/mcp";

/// MCP call timeout. Hooks must stay cheap on the PostToolUse path.
pub const MCP_TIMEOUT_SECS: u64 = 2;
