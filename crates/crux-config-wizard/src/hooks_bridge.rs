// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Post-compose hook installation for `init` / `regenerate --hooks`.
//!
//! This used to shell out to `corecruxctl hooks install` and print a "run it
//! yourself" note when that binary was absent. On client machines it usually
//! *is* absent, and the note was easy to miss — so workspaces ended up with a
//! composed CLAUDE.md documenting a three-channel banner (see the `boot-banner`
//! profile) while the two channels a human can actually see were never
//! installed. The failure was silent in the only direction that matters.
//!
//! The install now lives in this crate (`hooks_install`), so we call it directly
//! and it cannot fail for want of a sibling binary. `corecruxctl hooks install`
//! still exists and additionally configures the daemon endpoint; that extra step
//! is the one thing we cannot do from here, so it stays the recommended entry
//! point when `corecruxctl` is present — we just no longer *depend* on it.
//!
//! Still best-effort: a hooks problem prints and never fails the wizard, because
//! the profiles are already written by the time we run.

use std::path::PathBuf;

use crux_config_wizard::hooks_install;

/// How to run the hooks step.
#[derive(Clone, Copy)]
pub enum Mode {
    /// Ask first (interactive `init` on a TTY).
    Prompt,
    /// Just run it (non-interactive `init`, or `regenerate --hooks`).
    Auto,
}

/// Install / refresh the Claude Code hooks into the user settings.
/// Best-effort and non-fatal.
pub fn ensure_hooks(mode: Mode) {
    if matches!(mode, Mode::Prompt) && !crate::interactive::confirm_install_hooks() {
        println!("Skipped Claude Code hooks — run `crux-config-wizard hooks install --user` when you're ready.");
        return;
    }

    println!("\nInstalling Claude Code hooks…");
    match hooks_install::install(true, None) {
        Ok(summary) => {
            println!("{summary}");
            // The endpoint the hooks resolve at runtime is corecruxctl's to
            // configure; say so once here rather than failing for its absence.
            if !endpoint_configured() {
                println!(
                    "  note: no daemon endpoint configured yet — hooks fall back to the local default. \
                     Set one with `corecruxctl login --url <url>` (or `corecruxctl hooks install --endpoint <url>`)."
                );
            }
        }
        Err(e) => eprintln!(
            "could not install Claude Code hooks ({e}); run `crux-config-wizard hooks install --user` manually."
        ),
    }
}

/// Has an operator written a daemon endpoint to `~/.config/cuecrux/env`?
/// Read-only probe — we never write that file from here (it is `corecruxctl
/// login`'s, and it holds the bearer token).
fn endpoint_configured() -> bool {
    let Some(home) = std::env::var_os("HOME") else {
        return false;
    };
    let env = PathBuf::from(home).join(".config").join("cuecrux").join("env");
    std::fs::read_to_string(env).is_ok_and(|s| {
        s.lines()
            .any(|l| l.trim_start().starts_with("CRUX_HTTP_URL") || l.trim_start().starts_with("CORECRUXD_URL"))
    })
}
