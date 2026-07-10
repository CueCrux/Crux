// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// SPDX-License-Identifier: LicenseRef-CCL-1.0
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! Binary-side bridge to `corecruxctl hooks install`.
//!
//! After the wizard composes the managed CLAUDE.md / AGENTS.md sections, it hands
//! off to the co-installed `corecruxctl` so a single `crux-config-wizard init`
//! sets up **both** the profiles and the Claude Code hooks (banner, observe, cost,
//! scratchpad-survival). Kept out of the library crate — it shells out to a
//! sibling binary — so the composer stays pure + unit-testable, and the lean
//! wizard doesn't take on corecruxctl's dependency tree.
//!
//! Everything here is best-effort: a missing or failing `corecruxctl` prints a
//! one-line "run it yourself" note and never fails the wizard (the profiles are
//! already written).

use std::path::{Path, PathBuf};
use std::process::Command;

/// How to run the hooks step.
#[derive(Clone, Copy)]
pub enum Mode {
    /// Ask first (interactive `init` on a TTY).
    Prompt,
    /// Just run it (non-interactive `init`, or `regenerate --hooks`).
    Auto,
}

/// Locate the co-installed `corecruxctl`: PATH first, then the conventional
/// user bin dirs (`~/.local/bin`, `$CARGO_HOME/bin`). `None` ⇒ not installed.
fn locate_corecruxctl() -> Option<PathBuf> {
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let p = dir.join("corecruxctl");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    let candidates = [
        std::env::var_os("HOME").map(|h| Path::new(&h).join(".local").join("bin")),
        std::env::var_os("CARGO_HOME").map(|c| Path::new(&c).join("bin")),
    ];
    for base in candidates.into_iter().flatten() {
        let p = base.join("corecruxctl");
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Install / refresh the Claude Code hooks via `corecruxctl hooks install --user`.
/// Best-effort and non-fatal — prints a manual-fallback note on any problem.
pub fn ensure_hooks(mode: Mode) {
    let Some(ctl) = locate_corecruxctl() else {
        println!(
            "\nClaude Code hooks: `corecruxctl` not found on PATH — run \
             `corecruxctl hooks install` to enable the banner / observe / cost / \
             scratchpad-survival hooks."
        );
        return;
    };

    if matches!(mode, Mode::Prompt) && !crate::interactive::confirm_install_hooks() {
        println!("Skipped Claude Code hooks — run `corecruxctl hooks install` when you're ready.");
        return;
    }

    println!("\nInstalling Claude Code hooks via corecruxctl…");
    match Command::new(&ctl).args(["hooks", "install", "--user"]).status() {
        Ok(status) if status.success() => {}
        Ok(status) => eprintln!(
            "corecruxctl hooks install exited with {status}; run `{} hooks install` manually.",
            ctl.display()
        ),
        Err(e) => eprintln!(
            "could not run corecruxctl ({e}); run `{} hooks install` manually.",
            ctl.display()
        ),
    }
}
