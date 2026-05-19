// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

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
    },
    /// Re-compose CLAUDE.md and AGENTS.md from the saved .crux/agent-profile.toml.
    /// Refuses to overwrite hand-edited managed sections unless --force.
    Regenerate {
        #[arg(long)]
        force: bool,
    },
    /// CI mode: exit 0 if files match what regenerate would produce, non-zero otherwise.
    Check,
    /// List available bundled profiles and which are enabled in this workspace.
    List,
    /// Enable a profile and re-compose.
    Add { name: String },
    /// Disable a profile and re-compose.
    Remove { name: String },
    /// Show the diff between current files and what regenerate would produce.
    Diff,
}
