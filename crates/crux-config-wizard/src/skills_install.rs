// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Claude Code **skill** installation.
//!
//! Skills are plain files under `~/.claude/skills/<name>/`; unlike hooks they
//! need no `settings.json` wiring — Claude Code discovers them by directory.
//! So this module is the file half of [`crate::hooks_install`] and nothing
//! more: embed the assets with `include_str!`, write them idempotently, and
//! report drift.
//!
//! Why the wizard owns them: a skill that encodes workspace procedure
//! (`execplan-run` encodes the ExecPlan execution + closeout loop) is the same
//! class of artefact as a profile fragment — versioned, regenerable, and
//! useless if it only exists on one machine.

use std::path::{Path, PathBuf};

type DynErr = Box<dyn std::error::Error>;

/// One installed file within a skill directory.
struct SkillFile {
    /// Path relative to `~/.claude/skills/`.
    rel: &'static str,
    body: &'static str,
    /// Scripts need the exec bit; markdown does not.
    exec: bool,
}

/// Bundled skills. Adding a skill means adding its files here — `include_str!`
/// resolves at compile time, so the binary stays self-contained and a missing
/// asset is a build error rather than a silent no-op at install time.
const BUNDLED: &[SkillFile] = &[
    SkillFile {
        rel: "execplan-run/SKILL.md",
        body: include_str!("../assets/skills/execplan-run/SKILL.md"),
        exec: false,
    },
    SkillFile {
        rel: "execplan-run/references/orchestrator.md",
        body: include_str!("../assets/skills/execplan-run/references/orchestrator.md"),
        exec: false,
    },
    SkillFile {
        rel: "execplan-run/references/milestone-loop.md",
        body: include_str!("../assets/skills/execplan-run/references/milestone-loop.md"),
        exec: false,
    },
    SkillFile {
        rel: "execplan-run/references/closeout.md",
        body: include_str!("../assets/skills/execplan-run/references/closeout.md"),
        exec: false,
    },
    SkillFile {
        rel: "execplan-run/scripts/ep",
        body: include_str!("../assets/skills/execplan-run/scripts/ep"),
        exec: true,
    },
];

/// Names of the skills this binary ships, for `list` output and tests.
#[must_use]
pub fn bundled_skill_names() -> Vec<&'static str> {
    let mut names: Vec<&str> = BUNDLED.iter().filter_map(|f| f.rel.split('/').next()).collect();
    names.sort_unstable();
    names.dedup();
    names
}

fn skills_dir() -> Result<PathBuf, DynErr> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(Path::new(&home).join(".claude").join("skills"))
}

#[cfg(unix)]
fn write_file(path: &Path, body: &str, exec: bool) -> Result<(), DynErr> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(if exec { 0o755 } else { 0o644 })
        .open(path)?;
    f.write_all(body.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_file(path: &Path, body: &str, _exec: bool) -> Result<(), DynErr> {
    std::fs::write(path, body)?;
    Ok(())
}

/// Write-on-change, backing up any differing operator edit to `<path>.bak`
/// first. Same contract as the hooks installer: unchanged files are not
/// rewritten, so `install` is idempotent and leaves no `.bak` litter on a
/// second run.
fn write_on_change(path: &Path, body: &str, exec: bool) -> Result<bool, DynErr> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        if existing == body {
            return Ok(false);
        }
        std::fs::write(format!("{}.bak", path.display()), existing.as_bytes())?;
    }
    write_file(path, body, exec)?;
    Ok(true)
}

/// Install every bundled skill into `~/.claude/skills/`. Returns a summary
/// naming what changed; the library crate forbids printing, so the caller owns
/// the output surface.
pub fn install() -> Result<String, DynErr> {
    let root = skills_dir()?;
    let mut written = Vec::new();
    for f in BUNDLED {
        let dest = root.join(f.rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if write_on_change(&dest, f.body, f.exec)? {
            written.push(f.rel);
        }
    }
    let names = bundled_skill_names().join(", ");
    Ok(if written.is_empty() {
        format!("skills: {names} already current at {}", root.display())
    } else {
        format!(
            "skills: {names} → {} ({} file(s) written: {})",
            root.display(),
            written.len(),
            written.join(", ")
        )
    })
}

/// Per-file state, mirroring `hooks_install::ComponentState` semantics: a
/// present-but-stale file is the failure mode plain presence checks miss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileState {
    Current,
    Stale,
    Missing,
}

impl FileState {
    fn mark(self) -> &'static str {
        match self {
            Self::Current => "✓ current",
            Self::Stale => "! stale",
            Self::Missing => "✗ missing",
        }
    }
}

/// Report which bundled skill files are installed, and whether each matches the
/// bytes this binary ships.
pub fn status() -> Result<String, DynErr> {
    use std::fmt::Write as _;
    let root = skills_dir()?;
    let mut out = format!("skills dir: {}\n", root.display());
    let mut stale = 0usize;
    let mut missing = 0usize;
    for f in BUNDLED {
        let state = match std::fs::read_to_string(root.join(f.rel)) {
            Ok(on_disk) if on_disk == f.body => FileState::Current,
            Ok(_) => {
                stale += 1;
                FileState::Stale
            }
            Err(_) => {
                missing += 1;
                FileState::Missing
            }
        };
        let _ = writeln!(out, "  {:<44} {}", f.rel, state.mark());
    }
    let _ = write!(
        out,
        "{}",
        if stale + missing == 0 {
            "all bundled skills current".to_string()
        } else {
            format!("{stale} stale, {missing} missing — run `crux-config-wizard skills install`")
        }
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_assets_are_substantive() {
        for f in BUNDLED {
            assert!(
                f.body.len() > 200,
                "{} looks truncated ({} bytes) — check the include_str! path",
                f.rel,
                f.body.len()
            );
        }
    }

    #[test]
    fn every_skill_ships_a_skill_md_with_frontmatter() {
        for name in bundled_skill_names() {
            let found = BUNDLED.iter().find(|f| f.rel == format!("{name}/SKILL.md"));
            assert!(found.is_some(), "skill {name} has no SKILL.md");
            let Some(entry) = found else { continue };
            assert!(
                entry.body.starts_with("---\nname: "),
                "{name}/SKILL.md must open with YAML frontmatter declaring `name:`"
            );
            assert!(
                entry.body.contains("description:"),
                "{name}/SKILL.md frontmatter must carry a `description:` — it is the only \
                 thing loaded at startup, so an absent one means the skill never triggers"
            );
        }
    }

    #[test]
    fn scripts_are_marked_executable_and_others_are_not() {
        for f in BUNDLED {
            assert_eq!(
                f.exec,
                f.rel.contains("/scripts/"),
                "{} exec bit disagrees with its path",
                f.rel
            );
        }
    }

    // `#[serial]` for the same reason the hooks_install tests are: this
    // overrides the process-global `HOME`, and a sibling test doing the same
    // concurrently sends `install()` at the wrong directory.
    #[test]
    #[serial_test::serial]
    fn install_is_idempotent_and_status_goes_green() {
        let tmp = std::env::temp_dir().join(format!("crux-skills-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        // `HOME` is process-global; these asserts run in one test to keep the
        // override scoped rather than racing sibling tests.
        let prev = std::env::var_os("HOME");
        std::env::set_var("HOME", &tmp);

        let first = install().unwrap();
        assert!(first.contains("file(s) written"), "first install writes: {first}");
        assert!(status().unwrap().contains("all bundled skills current"));

        let second = install().unwrap();
        assert!(
            second.contains("already current"),
            "second install is a no-op: {second}"
        );

        // A hand-edited file reads as stale, and re-install backs it up.
        let touched = tmp.join(".claude/skills/execplan-run/SKILL.md");
        std::fs::write(&touched, "edited by the operator").unwrap();
        assert!(status().unwrap().contains("! stale"));
        install().unwrap();
        assert!(tmp.join(".claude/skills/execplan-run/SKILL.md.bak").exists());
        assert!(status().unwrap().contains("all bundled skills current"));

        match prev {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
