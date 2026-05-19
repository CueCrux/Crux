// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `crux-config-wizard` binary entry point.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;

use crux_config_wizard::compose::{compose_file, ComposeError};
use crux_config_wizard::config::{workspace_fingerprint, AgentProfileConfig};
use crux_config_wizard::drift::check_workspace;
use crux_config_wizard::profile::load_bundled_profiles;
use crux_config_wizard::Target;

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
    match cmd {
        cli::Command::Init {
            non_interactive,
            profiles,
        } => cmd_init(&workspace, non_interactive, profiles),
        cli::Command::Regenerate { force } => cmd_regenerate(&workspace, force),
        cli::Command::Check => cmd_check(&workspace),
        cli::Command::List => cmd_list(&workspace),
        cli::Command::Add { name } => cmd_add(&workspace, &name),
        cli::Command::Remove { name } => cmd_remove(&workspace, &name),
        cli::Command::Diff => cmd_diff(&workspace),
    }
}

fn cmd_init(workspace: &Path, non_interactive: bool, profiles_arg: Option<String>) -> std::io::Result<ExitCode> {
    let cfg_path = AgentProfileConfig::workspace_path(workspace);
    if cfg_path.exists() {
        eprintln!(
            "config already exists at {}; use `regenerate` or `add/remove` instead.",
            cfg_path.display()
        );
        return Ok(ExitCode::from(2));
    }

    let bundled = load_bundled_profiles().map_err(std::io::Error::other)?;

    let chosen_names: Vec<String> = if non_interactive {
        let raw = profiles_arg
            .ok_or_else(|| std::io::Error::other("--non-interactive requires --profiles=<csv> (or 'all')"))?;
        if raw == "all" {
            crux_config_wizard::DEFAULT_PROFILES
                .iter()
                .map(|s| s.to_string())
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

    // Validate names against bundled set.
    for n in &chosen_names {
        if !bundled.iter().any(|f| &f.frontmatter.name == n) {
            return Err(std::io::Error::other(format!(
                "unknown profile '{n}' (run `crux-config-wizard list` to see options)"
            )));
        }
    }

    let mut cfg = AgentProfileConfig::new(workspace_fingerprint(workspace));
    for n in &chosen_names {
        let frag = bundled
            .iter()
            .find(|f| &f.frontmatter.name == n)
            .expect("validated above");
        cfg.enable(n, frag.frontmatter.version);
    }
    cfg.save(workspace).map_err(std::io::Error::other)?;

    // Compose CLAUDE.md + AGENTS.md.
    let enabled: Vec<_> = bundled
        .into_iter()
        .filter(|f| chosen_names.contains(&f.frontmatter.name))
        .collect();
    for t in [Target::ClaudeMd, Target::AgentsMd] {
        let r = compose_file(workspace, t, &enabled, false, false).map_err(map_compose_err)?;
        println!(
            "{}: wrote={}, sections_added={}",
            t.filename(),
            r.wrote,
            r.managed_sections_added
        );
    }
    println!(
        "Initialised {} profile(s) for {}.",
        chosen_names.len(),
        workspace.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_regenerate(workspace: &Path, force: bool) -> std::io::Result<ExitCode> {
    let cfg = AgentProfileConfig::load(workspace).map_err(std::io::Error::other)?;
    let bundled = load_bundled_profiles().map_err(std::io::Error::other)?;
    let enabled: Vec<_> = bundled
        .into_iter()
        .filter(|f| cfg.profiles.contains_key(&f.frontmatter.name))
        .collect();
    for t in [Target::ClaudeMd, Target::AgentsMd] {
        match compose_file(workspace, t, &enabled, force, false) {
            Ok(r) => println!(
                "{}: wrote={}, updated={}, added={}",
                t.filename(),
                r.wrote,
                r.managed_sections_updated,
                r.managed_sections_added
            ),
            Err(e) => {
                eprintln!("error: {e}");
                return Ok(ExitCode::from(1));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_check(workspace: &Path) -> std::io::Result<ExitCode> {
    let report = check_workspace(workspace)?;
    if report.drifted() {
        println!("{}", report.message_for_claude());
        Ok(ExitCode::from(1))
    } else {
        println!("crux-config-wizard: workspace clean.");
        Ok(ExitCode::SUCCESS)
    }
}

fn cmd_list(workspace: &Path) -> std::io::Result<ExitCode> {
    let bundled = load_bundled_profiles().map_err(std::io::Error::other)?;
    let cfg_opt = AgentProfileConfig::load(workspace).ok();
    println!("Available profiles:");
    for f in &bundled {
        let enabled = cfg_opt
            .as_ref()
            .map(|c| c.profiles.contains_key(&f.frontmatter.name))
            .unwrap_or(false);
        let marker = if enabled { "[x]" } else { "[ ]" };
        println!(
            "  {marker} {} (v{}, risk={}) — {}",
            f.frontmatter.name, f.frontmatter.version, f.frontmatter.risk_class, f.frontmatter.description
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_add(workspace: &Path, name: &str) -> std::io::Result<ExitCode> {
    let mut cfg = AgentProfileConfig::load(workspace).map_err(std::io::Error::other)?;
    let bundled = load_bundled_profiles().map_err(std::io::Error::other)?;
    let frag = bundled
        .iter()
        .find(|f| f.frontmatter.name == name)
        .ok_or_else(|| std::io::Error::other(format!("unknown profile '{name}'")))?;
    cfg.enable(name, frag.frontmatter.version);
    cfg.save(workspace).map_err(std::io::Error::other)?;
    cmd_regenerate(workspace, false)
}

fn cmd_remove(workspace: &Path, name: &str) -> std::io::Result<ExitCode> {
    let mut cfg = AgentProfileConfig::load(workspace).map_err(std::io::Error::other)?;
    if !cfg.disable(name) {
        eprintln!("profile '{name}' was not enabled.");
        return Ok(ExitCode::from(2));
    }
    cfg.save(workspace).map_err(std::io::Error::other)?;
    cmd_regenerate(workspace, false)
}

fn cmd_diff(workspace: &Path) -> std::io::Result<ExitCode> {
    let report = check_workspace(workspace)?;
    if report.drifted() {
        println!("{}", report.message_for_claude());
        Ok(ExitCode::from(1))
    } else {
        println!("no diff.");
        Ok(ExitCode::SUCCESS)
    }
}

fn is_tty() -> bool {
    use std::io::IsTerminal as _;
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

fn map_compose_err(e: ComposeError) -> std::io::Error {
    std::io::Error::other(e.to_string())
}
