// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Client-side path and command helpers shared by the installers.
//!
//! Everything the wizard installs lives under the user's home directory and is
//! later run by Claude Code's hook runner, which is a POSIX shell on every
//! platform (Git Bash on Windows). Native Windows has no `HOME` and spells
//! paths with backslashes, so both need handling once, here, rather than in
//! each installer.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The user's home directory: `HOME`, then (on Windows, where `HOME` is
/// usually unset outside Git Bash) `USERPROFILE`.
///
/// # Errors
/// When neither variable is set.
pub fn home_dir() -> Result<PathBuf, &'static str> {
    home_from(
        std::env::var_os("HOME").as_deref(),
        std::env::var_os("USERPROFILE").as_deref(),
    )
}

/// [`home_dir`] over explicit values, so it is testable without mutating the
/// process environment.
fn home_from(home: Option<&OsStr>, userprofile: Option<&OsStr>) -> Result<PathBuf, &'static str> {
    let non_empty = |v: Option<&OsStr>| v.filter(|s| !s.is_empty()).map(PathBuf::from);
    non_empty(home)
        .or_else(|| if cfg!(windows) { non_empty(userprofile) } else { None })
        .ok_or("neither HOME nor USERPROFILE is set")
}

/// Claude Code's config directory: `CLAUDE_CONFIG_DIR` when set, else
/// `~/.claude`. `settings.json` lives in it.
///
/// # Errors
/// When no home directory can be resolved.
pub fn claude_config_dir() -> Result<PathBuf, &'static str> {
    match std::env::var_os("CLAUDE_CONFIG_DIR").filter(|s| !s.is_empty()) {
        Some(dir) => Ok(PathBuf::from(dir)),
        None => Ok(home_dir()?.join(".claude")),
    }
}

/// Claude Code's global state file, which holds user-scope MCP servers:
/// `$CLAUDE_CONFIG_DIR/.claude.json` when that is set, else `~/.claude.json`.
///
/// # Errors
/// When no home directory can be resolved.
pub fn claude_json_path() -> Result<PathBuf, &'static str> {
    match std::env::var_os("CLAUDE_CONFIG_DIR").filter(|s| !s.is_empty()) {
        Some(dir) => Ok(PathBuf::from(dir).join(".claude.json")),
        None => Ok(home_dir()?.join(".claude.json")),
    }
}

/// `path` as one word of a POSIX shell command, the form Claude Code's hook
/// runner executes. Backslashes become forward slashes on Windows (Git Bash
/// reads `C:/Users/...` but eats `\U` as an escape), and anything a shell
/// would split or expand is single-quoted.
#[must_use]
pub fn shell_word(path: &Path) -> String {
    let raw = path.display().to_string();
    let s = if cfg!(windows) { raw.replace('\\', "/") } else { raw };
    let plain = |c: char| c.is_ascii_alphanumeric() || "/._-+:@%,=~".contains(c);
    if !s.is_empty() && s.chars().all(plain) {
        s
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// Find an executable named `name` in `dir`, accepting the `.exe` spelling on
/// Windows (a bare `crux-hook` never exists there).
#[must_use]
pub fn executable_in(dir: &Path, name: &str) -> Option<PathBuf> {
    let candidates: &[&str] = if cfg!(windows) { &["", ".exe", ".cmd"] } else { &[""] };
    candidates
        .iter()
        .map(|ext| dir.join(format!("{name}{ext}")))
        .find(|p| p.is_file())
}

/// Find `name` on `PATH` (with the Windows spellings, as [`executable_in`]).
#[must_use]
pub fn on_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths).find_map(|d| executable_in(&d, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_prefers_home_and_ignores_empty_values() {
        assert_eq!(
            home_from(Some(OsStr::new("/h")), Some(OsStr::new("/u"))).unwrap(),
            PathBuf::from("/h")
        );
        let fallback = home_from(Some(OsStr::new("")), Some(OsStr::new("/u")));
        if cfg!(windows) {
            assert_eq!(fallback.unwrap(), PathBuf::from("/u"));
        } else {
            assert!(fallback.is_err(), "USERPROFILE is a Windows-only fallback");
        }
        assert!(home_from(None, None).is_err());
    }

    #[test]
    fn shell_word_leaves_plain_paths_bare() {
        assert_eq!(
            shell_word(Path::new("/home/me/.local/bin/crux-coord")),
            "/home/me/.local/bin/crux-coord"
        );
    }

    #[test]
    fn shell_word_quotes_spaces_and_quotes() {
        assert_eq!(shell_word(Path::new("/home/a b/x.sh")), "'/home/a b/x.sh'");
        assert_eq!(shell_word(Path::new("/home/o'neil/x")), r"'/home/o'\''neil/x'");
    }

    #[cfg(windows)]
    #[test]
    fn shell_word_uses_forward_slashes_on_windows() {
        assert_eq!(
            shell_word(Path::new(r"C:\Users\me\.local\bin\crux-coord")),
            "C:/Users/me/.local/bin/crux-coord"
        );
    }
}
