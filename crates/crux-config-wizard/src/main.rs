// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
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
mod hooks_bridge;
mod interactive;

fn main() -> ExitCode {
    let args = cli::Cli::parse();
    let workspace = args.workspace.clone().unwrap_or_else(|| PathBuf::from("."));

    // `hooks` is a standalone client-side action: it composes nothing, so it is
    // dispatched here rather than threaded through the profile pipeline in
    // `run`, which is built around a CommandReport it has no business faking.
    if let cli::Command::Hooks { action } = args.command {
        let workspace = workspace.canonicalize().unwrap_or(workspace);
        return run_hooks(&workspace, action);
    }

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

    // Decide whether to hand off to `corecruxctl hooks install` after composing.
    // `init` installs by default (prompting on a TTY); `regenerate` only with
    // `--hooks`. Computed before `cmd` is consumed by the match below.
    let hooks_plan = match &cmd {
        cli::Command::Init {
            non_interactive,
            no_hooks,
            ..
        } if !no_hooks => Some(if !*non_interactive && is_tty() {
            hooks_bridge::Mode::Prompt
        } else {
            hooks_bridge::Mode::Auto
        }),
        cli::Command::Regenerate { hooks: true, .. } => Some(hooks_bridge::Mode::Auto),
        _ => None,
    };

    let report = match cmd {
        cli::Command::Init {
            non_interactive,
            profiles,
            no_hooks: _,
        } => init_dispatch(&workspace, non_interactive, profiles)?,
        cli::Command::Regenerate { force, hooks: _ } => run_regenerate(&workspace, force)?,
        cli::Command::Check { strict } => run_check(&workspace, strict)?,
        cli::Command::List => run_list(&workspace)?,
        cli::Command::Add { name } => run_add(&workspace, &name)?,
        cli::Command::Remove { name } => run_remove(&workspace, &name)?,
        cli::Command::Diff { strict } => run_diff(&workspace, strict)?,
        // Dispatched in `main` before this pipeline runs.
        cli::Command::Hooks { .. } => unreachable!("hooks is handled in main()"),
    };
    emit(&report);

    // Only install hooks when the compose step itself succeeded; a hooks
    // problem is non-fatal and never changes the wizard's exit code.
    if matches!(report.outcome, CommandOutcome::Ok) {
        if let Some(mode) = hooks_plan {
            hooks_bridge::ensure_hooks(mode);
        }
    }

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

/// `crux-config-wizard hooks {install,status}`.
///
/// Deliberately self-contained: everything it writes is embedded in this binary,
/// so a client machine with only `crux-hook` installed can repair its own banner
/// stack without `corecruxctl` or a source checkout. A hooks failure is reported
/// and exits non-zero, but it never touches the composed profile files.
fn run_hooks(workspace: &Path, action: cli::HooksAction) -> ExitCode {
    let (result, what) = match action {
        cli::HooksAction::Install { user } => {
            let project = (!user).then(|| workspace.to_path_buf());
            (
                crux_config_wizard::hooks_install::install(user, project).map(|summary| {
                    println!("{summary}");
                }),
                "install",
            )
        }
        cli::HooksAction::Status { user } => {
            let project = (!user).then(|| workspace.to_path_buf());
            let r = crux_config_wizard::hooks_install::status(user, project).map(|report| {
                println!("{report}");
            });
            // Status also reports banner-stack drift, which plain settings
            // inspection cannot see: a present-but-stale script looks wired.
            let a = crux_config_wizard::hooks_install::audit();
            match a.advice() {
                Some(advice) => println!("banner stack: {advice}"),
                None => println!("banner stack: current"),
            }
            (r, "status")
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("hooks {what}: {e}");
            ExitCode::FAILURE
        }
    }
}
