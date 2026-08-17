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
