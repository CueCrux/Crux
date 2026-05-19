// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
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
    /// PostToolUse hook: read-only operational anomaly warnings.
    ContextMonitor,
    /// PreCompact hook: snapshot session state to the Crux daemon.
    PreCompact,
    /// SessionStart hook: run §11.1 boot ritual, inject bootstrap context.
    SessionStart,
}

fn main() {
    let cli = Cli::parse();
    let stdin = std::io::stdin();
    let result = match cli.command {
        Command::ContextMonitor => cmds::context_monitor::run(stdin.lock()),
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
