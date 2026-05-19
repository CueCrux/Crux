// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Library-side command implementations.
//!
//! Each `run_*` function takes a workspace path and writes its narrative to a
//! `String` so callers can either print it (the binary) or assert against it
//! (tests). Exit codes are returned as `CommandOutcome::Exit(u8)`.

use std::fmt::Write as _;
use std::path::Path;

use crate::compose::{compose_file, ComposeError};
use crate::config::{workspace_fingerprint, AgentProfileConfig};
use crate::drift::check_workspace;
use crate::profile::load_bundled_profiles;
use crate::Target;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandOutcome {
    Ok,
    Exit(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandReport {
    pub outcome: CommandOutcome,
    pub stdout: String,
    pub stderr: String,
}

impl CommandReport {
    fn ok(stdout: String) -> Self {
        Self {
            outcome: CommandOutcome::Ok,
            stdout,
            stderr: String::new(),
        }
    }
    fn exit(code: u8, stdout: String, stderr: String) -> Self {
        Self {
            outcome: CommandOutcome::Exit(code),
            stdout,
            stderr,
        }
    }
}

pub fn run_init(workspace: &Path, profile_names: &[String]) -> std::io::Result<CommandReport> {
    let cfg_path = AgentProfileConfig::workspace_path(workspace);
    if cfg_path.exists() {
        return Ok(CommandReport::exit(
            2,
            String::new(),
            format!(
                "config already exists at {}; use `regenerate` or `add/remove` instead.\n",
                cfg_path.display()
            ),
        ));
    }
    let bundled = load_bundled_profiles().map_err(std::io::Error::other)?;
    for n in profile_names {
        if !bundled.iter().any(|f| &f.frontmatter.name == n) {
            return Err(std::io::Error::other(format!("unknown profile '{n}'")));
        }
    }
    let mut cfg = AgentProfileConfig::new(workspace_fingerprint(workspace));
    for n in profile_names {
        let frag = bundled
            .iter()
            .find(|f| &f.frontmatter.name == n)
            .expect("validated above");
        cfg.enable(n, frag.frontmatter.version);
    }
    cfg.save(workspace).map_err(std::io::Error::other)?;
    let enabled: Vec<_> = bundled
        .into_iter()
        .filter(|f| profile_names.contains(&f.frontmatter.name))
        .collect();
    let mut stdout = String::new();
    for t in [Target::ClaudeMd, Target::AgentsMd] {
        let r = compose_file(workspace, t, &enabled, false, false).map_err(map_compose)?;
        writeln!(
            stdout,
            "{}: wrote={}, sections_added={}",
            t.filename(),
            r.wrote,
            r.managed_sections_added
        )
        .expect("write to String cannot fail");
    }
    writeln!(
        stdout,
        "Initialised {} profile(s) for {}.",
        profile_names.len(),
        workspace.display()
    )
    .expect("write to String cannot fail");
    Ok(CommandReport::ok(stdout))
}

pub fn run_regenerate(workspace: &Path, force: bool) -> std::io::Result<CommandReport> {
    let cfg = AgentProfileConfig::load(workspace).map_err(std::io::Error::other)?;
    let bundled = load_bundled_profiles().map_err(std::io::Error::other)?;
    let enabled: Vec<_> = bundled
        .into_iter()
        .filter(|f| cfg.profiles.contains_key(&f.frontmatter.name))
        .collect();
    let mut stdout = String::new();
    for t in [Target::ClaudeMd, Target::AgentsMd] {
        match compose_file(workspace, t, &enabled, force, false) {
            Ok(r) => writeln!(
                stdout,
                "{}: wrote={}, updated={}, added={}",
                t.filename(),
                r.wrote,
                r.managed_sections_updated,
                r.managed_sections_added
            )
            .expect("write to String cannot fail"),
            Err(e) => {
                return Ok(CommandReport::exit(1, stdout, format!("error: {e}\n")));
            }
        }
    }
    Ok(CommandReport::ok(stdout))
}

pub fn run_check(workspace: &Path) -> std::io::Result<CommandReport> {
    let report = check_workspace(workspace)?;
    if report.drifted() {
        Ok(CommandReport::exit(1, report.message_for_claude(), String::new()))
    } else {
        Ok(CommandReport::ok("crux-config-wizard: workspace clean.\n".into()))
    }
}

pub fn run_list(workspace: &Path) -> std::io::Result<CommandReport> {
    let bundled = load_bundled_profiles().map_err(std::io::Error::other)?;
    let cfg_opt = AgentProfileConfig::load(workspace).ok();
    let mut stdout = String::from("Available profiles:\n");
    for f in &bundled {
        let enabled = cfg_opt
            .as_ref()
            .is_some_and(|c| c.profiles.contains_key(&f.frontmatter.name));
        let marker = if enabled { "[x]" } else { "[ ]" };
        writeln!(
            stdout,
            "  {marker} {} (v{}, risk={}) — {}",
            f.frontmatter.name, f.frontmatter.version, f.frontmatter.risk_class, f.frontmatter.description
        )
        .expect("write to String cannot fail");
    }
    Ok(CommandReport::ok(stdout))
}

pub fn run_add(workspace: &Path, name: &str) -> std::io::Result<CommandReport> {
    let mut cfg = AgentProfileConfig::load(workspace).map_err(std::io::Error::other)?;
    let bundled = load_bundled_profiles().map_err(std::io::Error::other)?;
    let frag = bundled
        .iter()
        .find(|f| f.frontmatter.name == name)
        .ok_or_else(|| std::io::Error::other(format!("unknown profile '{name}'")))?;
    cfg.enable(name, frag.frontmatter.version);
    cfg.save(workspace).map_err(std::io::Error::other)?;
    run_regenerate(workspace, false)
}

pub fn run_remove(workspace: &Path, name: &str) -> std::io::Result<CommandReport> {
    let mut cfg = AgentProfileConfig::load(workspace).map_err(std::io::Error::other)?;
    if !cfg.disable(name) {
        return Ok(CommandReport::exit(
            2,
            String::new(),
            format!("profile '{name}' was not enabled.\n"),
        ));
    }
    cfg.save(workspace).map_err(std::io::Error::other)?;
    run_regenerate(workspace, false)
}

pub fn run_diff(workspace: &Path) -> std::io::Result<CommandReport> {
    let report = check_workspace(workspace)?;
    if report.drifted() {
        Ok(CommandReport::exit(1, report.message_for_claude(), String::new()))
    } else {
        Ok(CommandReport::ok("no diff.\n".into()))
    }
}

fn map_compose(e: ComposeError) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fresh_ws() -> TempDir {
        TempDir::new().unwrap()
    }

    #[test]
    fn init_writes_config_and_files() {
        let ws = fresh_ws();
        let names = vec!["memory-practices".to_string(), "token-conservation".to_string()];
        let r = run_init(ws.path(), &names).unwrap();
        assert_eq!(r.outcome, CommandOutcome::Ok);
        assert!(r.stdout.contains("CLAUDE.md"));
        assert!(r.stdout.contains("AGENTS.md"));
        assert!(ws.path().join(".crux/agent-profile.toml").exists());
        assert!(ws.path().join("CLAUDE.md").exists());
        assert!(ws.path().join("AGENTS.md").exists());
    }

    #[test]
    fn init_refuses_when_config_exists() {
        let ws = fresh_ws();
        let names = vec!["memory-practices".to_string()];
        run_init(ws.path(), &names).unwrap();
        let r = run_init(ws.path(), &names).unwrap();
        assert_eq!(r.outcome, CommandOutcome::Exit(2));
        assert!(r.stderr.contains("already exists"));
    }

    #[test]
    fn init_unknown_profile_errors() {
        let ws = fresh_ws();
        let names = vec!["does-not-exist".to_string()];
        let err = run_init(ws.path(), &names).unwrap_err();
        assert!(err.to_string().contains("unknown profile"));
    }

    #[test]
    fn regenerate_idempotent_after_init() {
        let ws = fresh_ws();
        run_init(ws.path(), &["memory-practices".into()]).unwrap();
        let r = run_regenerate(ws.path(), false).unwrap();
        assert_eq!(r.outcome, CommandOutcome::Ok);
        assert!(r.stdout.contains("wrote=false"));
    }

    #[test]
    fn check_clean_after_init() {
        let ws = fresh_ws();
        run_init(ws.path(), &["memory-practices".into()]).unwrap();
        let r = run_check(ws.path()).unwrap();
        assert_eq!(r.outcome, CommandOutcome::Ok);
        assert!(r.stdout.contains("workspace clean"));
    }

    #[test]
    fn check_empty_workspace_is_clean() {
        let ws = fresh_ws();
        let r = run_check(ws.path()).unwrap();
        assert_eq!(r.outcome, CommandOutcome::Ok);
    }

    #[test]
    fn list_shows_all_profiles_with_enabled_marker() {
        let ws = fresh_ws();
        run_init(ws.path(), &["memory-practices".into()]).unwrap();
        let r = run_list(ws.path()).unwrap();
        assert!(r.stdout.contains("Available profiles"));
        assert!(r.stdout.contains("[x] memory-practices"));
        assert!(r.stdout.contains("[ ] eu-ai-act"));
    }

    #[test]
    fn list_without_init_shows_all_unchecked() {
        let ws = fresh_ws();
        let r = run_list(ws.path()).unwrap();
        // 8 bundled, none enabled.
        assert_eq!(r.stdout.matches("[ ]").count(), 8);
        assert_eq!(r.stdout.matches("[x]").count(), 0);
    }

    #[test]
    fn add_then_remove_round_trip() {
        let ws = fresh_ws();
        run_init(ws.path(), &["memory-practices".into()]).unwrap();
        let r = run_add(ws.path(), "eu-ai-act").unwrap();
        assert_eq!(r.outcome, CommandOutcome::Ok);
        let after_add = run_list(ws.path()).unwrap();
        assert!(after_add.stdout.contains("[x] eu-ai-act"));
        let r = run_remove(ws.path(), "eu-ai-act").unwrap();
        assert_eq!(r.outcome, CommandOutcome::Ok);
        let after_remove = run_list(ws.path()).unwrap();
        assert!(after_remove.stdout.contains("[ ] eu-ai-act"));
    }

    #[test]
    fn add_unknown_profile_errors() {
        let ws = fresh_ws();
        run_init(ws.path(), &["memory-practices".into()]).unwrap();
        let err = run_add(ws.path(), "does-not-exist").unwrap_err();
        assert!(err.to_string().contains("unknown profile"));
    }

    #[test]
    fn remove_not_enabled_returns_exit_2() {
        let ws = fresh_ws();
        run_init(ws.path(), &["memory-practices".into()]).unwrap();
        let r = run_remove(ws.path(), "eu-ai-act").unwrap();
        assert_eq!(r.outcome, CommandOutcome::Exit(2));
        assert!(r.stderr.contains("was not enabled"));
    }

    #[test]
    fn diff_clean_after_init() {
        let ws = fresh_ws();
        run_init(ws.path(), &["memory-practices".into()]).unwrap();
        let r = run_diff(ws.path()).unwrap();
        assert_eq!(r.outcome, CommandOutcome::Ok);
        assert!(r.stdout.contains("no diff"));
    }

    #[test]
    fn diff_drift_after_manual_edit_returns_exit_1() {
        let ws = fresh_ws();
        run_init(ws.path(), &["memory-practices".into()]).unwrap();
        let path = ws.path().join("CLAUDE.md");
        let text = std::fs::read_to_string(&path).unwrap();
        let tampered = text.replace("Crux Daemon Memory Practices", "TAMPERED HEADER");
        std::fs::write(&path, tampered).unwrap();
        let r = run_diff(ws.path()).unwrap();
        assert_eq!(r.outcome, CommandOutcome::Exit(1));
    }

    #[test]
    fn regenerate_refuses_drift_without_force_returns_exit_1() {
        let ws = fresh_ws();
        run_init(ws.path(), &["memory-practices".into()]).unwrap();
        let path = ws.path().join("CLAUDE.md");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("Memory Practices", "TAMPERED")).unwrap();
        let r = run_regenerate(ws.path(), false).unwrap();
        assert_eq!(r.outcome, CommandOutcome::Exit(1));
        assert!(r.stderr.contains("manual edit detected"));
    }

    #[test]
    fn regenerate_with_force_overwrites_drift() {
        let ws = fresh_ws();
        run_init(ws.path(), &["memory-practices".into()]).unwrap();
        let path = ws.path().join("CLAUDE.md");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("Memory Practices", "TAMPERED")).unwrap();
        let r = run_regenerate(ws.path(), true).unwrap();
        assert_eq!(r.outcome, CommandOutcome::Ok);
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("Memory Practices"));
        assert!(!after.contains("TAMPERED"));
    }
}
