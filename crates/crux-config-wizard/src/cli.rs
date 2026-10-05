// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! CLI definitions (clap).

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "crux-config-wizard",
    about = "Compose CLAUDE.md and AGENTS.md from versioned Crux profile fragments.",
    version
)]
pub struct Cli {
    /// Workspace root. Defaults to the current directory.
    #[arg(long, global = true)]
    pub workspace: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// First-run: interactive profile selection, writes .crux/agent-profile.toml
    /// and the composed CLAUDE.md / AGENTS.md. Errors if config already exists.
    Init {
        /// Skip prompts and use the supplied comma-separated profile list.
        #[arg(long)]
        non_interactive: bool,
        /// Comma-separated profile names (required if --non-interactive).
        #[arg(long)]
        profiles: Option<String>,
        /// Don't install the Claude Code hooks (banner / observe / cost /
        /// scratchpad-survival) via `corecruxctl hooks install`. By default
        /// `init` installs them so one command sets up the whole workspace.
        #[arg(long)]
        no_hooks: bool,
        /// Don't install the bundled Claude Code skills (e.g. `execplan-run`)
        /// into `~/.claude/skills/`. By default `init` installs them alongside
        /// the hooks, for the same reason: one command sets up the workspace.
        #[arg(long)]
        no_skills: bool,
        /// Don't install the `crux-desktop` Claude Code mod. Without it the
        /// classic hooks keep the SessionStart banner and PreCompact save.
        #[arg(long)]
        no_mod: bool,
    },
    /// Re-compose CLAUDE.md and AGENTS.md from the saved .crux/agent-profile.toml.
    /// Refuses to overwrite hand-edited managed sections unless --force.
    Regenerate {
        #[arg(long)]
        force: bool,
        /// Also refresh the Claude Code hooks via `corecruxctl hooks install`
        /// (e.g. after a corecruxctl upgrade adds a new hook). Off by default.
        #[arg(long)]
        hooks: bool,
        /// Also refresh the bundled Claude Code skills in `~/.claude/skills/`
        /// (e.g. after an upgrade revises the `execplan-run` procedure).
        /// Off by default.
        #[arg(long)]
        skills: bool,
    },
    /// CI mode: exit 0 if files match what regenerate would produce, non-zero otherwise.
    Check {
        /// Treat advisory warnings (free-span duplication, oversize) as failures (exit 1).
        #[arg(long)]
        strict: bool,
    },
    /// List available bundled profiles and which are enabled in this workspace.
    List,
    /// Enable a profile and re-compose.
    Add { name: String },
    /// Disable a profile and re-compose.
    Remove { name: String },
    /// Show the diff between current files and what regenerate would produce.
    Diff {
        /// Treat advisory warnings (free-span duplication, oversize) as failures (exit 1).
        #[arg(long)]
        strict: bool,
    },
    /// Install or inspect the Claude Code hooks and banner stack.
    ///
    /// Self-contained: the assets ship inside this binary, so a client machine
    /// needs nothing else installed. `corecruxctl hooks install` remains
    /// available and additionally configures the daemon endpoint the hooks read.
    Hooks {
        #[command(subcommand)]
        action: HooksAction,
    },
    /// Install or inspect the bundled Claude Code skills.
    ///
    /// Skills are files under `~/.claude/skills/<name>/` — no `settings.json`
    /// wiring, so unlike `hooks` this is purely a write-and-verify operation.
    Skills {
        #[command(subcommand)]
        action: SkillsAction,
    },
    /// Install, remove or inspect the `crux-desktop` Claude Code mod.
    ///
    /// The mod owns session continuity (context on the first prompt, a save
    /// after every turn and before compaction) and adds the `/crux` pane. It is
    /// loaded from `~/.claude/mods/crux-desktop` via `CLAUDE_CODE_PLUGIN_DIRS`.
    Mods {
        #[command(subcommand)]
        action: ModsAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum ModsAction {
    /// Write the mod, add it to `CLAUDE_CODE_PLUGIN_DIRS`, and register the
    /// daemon as a user-scope MCP server (unless one of that name exists).
    Install {
        /// MCP server name the mod uses (default: keep the current setting, or
        /// `crux`).
        #[arg(long)]
        server: Option<String>,
        /// Daemon MCP endpoint to register (default: http://127.0.0.1:14801/mcp).
        #[arg(long)]
        mcp_url: Option<String>,
        /// Don't touch `~/.claude.json`.
        #[arg(long)]
        no_mcp: bool,
    },
    /// Remove the mod and its settings entries. The MCP server is kept.
    Uninstall,
    /// Report whether the mod is installed, current and on the plugin path.
    Status,
}

#[derive(Debug, Subcommand)]
pub enum SkillsAction {
    /// Write the bundled skills into `~/.claude/skills/`. Idempotent: unchanged
    /// files are not rewritten, and an operator edit is backed up to `.bak`
    /// before being replaced.
    Install,
    /// Report which bundled skill files are installed and whether each matches
    /// the bytes this binary ships (a present-but-stale file looks installed).
    Status,
}

#[derive(Debug, Subcommand)]
pub enum HooksAction {
    /// Write the hook scripts + banner stack and wire them into settings.json.
    /// Idempotent: unchanged files are not rewritten, foreign hooks are
    /// preserved, and an existing `statusLine` is never overwritten.
    Install {
        /// Target the user settings (`~/.claude/settings.json`) instead of the
        /// project-local `.claude/settings.local.json`.
        #[arg(long)]
        user: bool,
    },
    /// Report which hooks are wired, and whether the banner stack on disk
    /// matches the bytes this binary ships.
    Status {
        /// Inspect the user settings rather than the project-local file.
        #[arg(long)]
        user: bool,
    },
}
