// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `crux-config-wizard` binary entry point.
//!
//! CLI tool — `println!`/`eprintln!` are correct behaviour; `unwrap`/`expect`
//! at startup are acceptable when the alternative is a more confusing error.
#![allow(clippy::print_stdout, clippy::print_stderr, clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

use crux_config_wizard::commands::{
    run_add, run_check, run_diff, run_init, run_list, run_regenerate, run_remove, CommandOutcome, CommandReport,
};
use crux_config_wizard::config::AgentProfileConfig;
use crux_config_wizard::profile::load_bundled_profiles;

mod cli;
mod interactive;

fn main() -> ExitCode {
    let args = cli::Cli::parse();
    let workspace = args.workspace.clone().unwrap_or_else(|| PathBuf::from("."));

    match run(&workspace, args.command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(workspace: &Path, cmd: cli::Command) -> std::io::Result<ExitCode> {
    let workspace = workspace.canonicalize().unwrap_or_else(|_| workspace.to_path_buf());
    let report = match cmd {
        cli::Command::Init {
            non_interactive,
            profiles,
        } => init_dispatch(&workspace, non_interactive, profiles)?,
        cli::Command::Regenerate { force } => run_regenerate(&workspace, force)?,
        cli::Command::Check => run_check(&workspace)?,
        cli::Command::List => run_list(&workspace)?,
        cli::Command::Add { name } => run_add(&workspace, &name)?,
        cli::Command::Remove { name } => run_remove(&workspace, &name)?,
        cli::Command::Diff => run_diff(&workspace)?,
    };
    emit(&report);
    Ok(match report.outcome {
        CommandOutcome::Ok => ExitCode::SUCCESS,
        CommandOutcome::Exit(c) => ExitCode::from(c),
    })
}

/// `init` wraps `run_init` with TTY-detection + interactive prompts + the
/// `--profiles=all` shorthand. Kept binary-side because it touches stdin.
fn init_dispatch(
    workspace: &Path,
    non_interactive: bool,
    profiles_arg: Option<String>,
) -> std::io::Result<CommandReport> {
    if AgentProfileConfig::workspace_path(workspace).exists() {
        // Delegate the "already initialised" path to run_init so the message
        // shape stays in one place.
        return run_init(workspace, &[]);
    }

    let bundled = load_bundled_profiles().map_err(std::io::Error::other)?;

    let chosen_names: Vec<String> = if non_interactive {
        let raw = profiles_arg
            .ok_or_else(|| std::io::Error::other("--non-interactive requires --profiles=<csv> (or 'all')"))?;
        if raw == "all" {
            crux_config_wizard::DEFAULT_PROFILES
                .iter()
                .map(|s| (*s).to_string())
                .collect()
        } else {
            raw.split(',').map(|s| s.trim().to_string()).collect()
        }
    } else {
        if !is_tty() {
            return Err(std::io::Error::other(
                "no TTY detected; pass --non-interactive --profiles=<csv>",
            ));
        }
        interactive::prompt_for_profiles(&bundled)?
    };

    run_init(workspace, &chosen_names)
}

fn emit(report: &CommandReport) {
    if !report.stdout.is_empty() {
        print!("{}", report.stdout);
    }
    if !report.stderr.is_empty() {
        eprint!("{}", report.stderr);
    }
}

fn is_tty() -> bool {
    use std::io::IsTerminal as _;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}
