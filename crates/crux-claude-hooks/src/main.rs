// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

// Hook binary — writes JSON to stdout per Claude Code hook protocol.
#![allow(clippy::print_stdout, clippy::print_stderr)]

//! `crux-hook` binary entry point — Claude Code lifecycle hooks.
//!
//! Clap-based dispatcher routing `context-monitor`, `pre-compact`, and
//! `session-start` subcommands to handlers in the `crux-claude-hooks`
//! library crate. Reads JSON hook input on stdin, emits hook output JSON
//! on stdout per the Claude Code hook protocol. See library docs for
//! per-subcommand semantics.

use clap::{Parser, Subcommand};
use crux_claude_hooks::cmds;

#[derive(Debug, Parser)]
#[command(
    name = "crux-hook",
    about = "Claude Code lifecycle hooks for the Crux Daemon.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// PreToolUse hook (code-intelligence M5): inject a `code:<repo>:<path>`
    /// file-context fact as additionalContext when a file is Read. Default-OFF
    /// behind `CRUX_HOOK_CODE_CONTEXT`. Always allows; never blocks.
    CodeContext,
    /// PostToolUse hook: read-only operational anomaly warnings.
    ContextMonitor,
    /// PostToolUse hook (agent-ux-02): emit "Memory used: …" annotation
    /// from an envelope-emitting tool's response. Gated by
    /// `CORECRUXD_FEATURE_MEMORY_ACK_INLINE=1`.
    MemoryAckInline,
    /// PreToolUse hook (Package S): shared capture + punchcard-enforce hook.
    /// Probes the daemon for a lease on Edit/Write targets (fail-open) and
    /// fire-and-forget OPENs an audit step. Always allows unless the daemon
    /// clearly reports a held-by-another lease in enforce mode.
    ObservePre,
    /// PostToolUse hook (observe plan): CLOSE the audit step that `observe-pre`
    /// opened for the tool call — appends outputs + terminal status. Gated by
    /// `CRUX_HOOK_OBSERVE_CAPTURE`; best-effort, never blocks.
    ObservePost,
    /// PreCompact hook: snapshot session state to the Crux daemon.
    PreCompact,
    /// SessionStart hook: run §11.1 boot ritual, inject bootstrap context.
    SessionStart,
}

fn main() {
    let cli = Cli::parse();
    let stdin = std::io::stdin();
    let result = match cli.command {
        Command::CodeContext => cmds::code_context::run(stdin.lock()),
        Command::ContextMonitor => cmds::context_monitor::run(stdin.lock()),
        Command::MemoryAckInline => cmds::memory_ack_inline::run(stdin.lock()),
        Command::ObservePre => cmds::observe_pre::run(stdin.lock()),
        Command::ObservePost => cmds::observe_post::run(stdin.lock()),
        Command::PreCompact => cmds::pre_compact::run(stdin.lock()),
        Command::SessionStart => cmds::session_start::run(stdin.lock()),
    };

    // Hooks are best-effort: log errors to stderr but never exit non-zero.
    // A non-zero exit would block tool execution in the Claude Code harness.
    if let Err(err) = result {
        eprintln!("crux-hook: {err}");
    }
    std::process::exit(0);
}
