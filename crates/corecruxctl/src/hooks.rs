// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! `corecruxctl hooks` — install + inspect the Crux Claude Code hooks.
//!
//! The install itself lives in `crux_config_wizard::hooks_install`; this module
//! is the `corecruxctl` front door for it. The split exists because the hook
//! assets (launcher, observe/filemod/scratchpad helpers, and the Python banner
//! stack) are plain source that a client needs whether or not `corecruxctl` is
//! present — and on most client machines it is not. Keeping them in the wizard
//! crate means `crux-hook`, which already depends on it, carries them too.
//!
//! What stays here is the one thing that genuinely belongs to `corecruxctl`:
//! configuring the daemon endpoint the hooks resolve at runtime
//! (`~/.config/cuecrux/env`, written by `login`). The wizard side is deliberately
//! endpoint-free.

use std::path::PathBuf;

use crux_config_wizard::hooks_install;

type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// Core install used by both the `hooks install` subcommand and `login`.
/// Returns a human-readable summary. Delegates to the wizard crate.
pub fn install(user: bool, project: Option<PathBuf>) -> Result<String, DynErr> {
    hooks_install::install(user, project)
}

/// `corecruxctl hooks install`.
///
/// Before wiring the hooks, ensure the daemon endpoint they read
/// (`~/.config/cuecrux/env`) is configured: `--endpoint <url>` saves it
/// non-interactively; otherwise, when nothing is configured yet and we have a
/// terminal, prompt for it (default: the loopback daemon).
pub fn run_install(user: bool, project: Option<PathBuf>, endpoint: Option<String>) -> Result<(), DynErr> {
    configure_endpoint(endpoint)?;
    println!("{}", install(user, project)?);
    Ok(())
}

/// `corecruxctl hooks status` — show whether Crux hooks are wired in the target.
pub fn run_status(user: bool, project: Option<PathBuf>) -> Result<(), DynErr> {
    println!("{}", hooks_install::status(user, project)?);
    Ok(())
}
/// Save / confirm the daemon endpoint the hooks resolve at runtime.
fn configure_endpoint(endpoint: Option<String>) -> Result<(), DynErr> {
    use std::io::IsTerminal as _;

    if let Some(url) = endpoint {
        let (http, mcp, path) = crate::login::save_endpoint(&url)?;
        println!("endpoint saved → {}", path.display());
        println!("  CRUX_HTTP_URL={http}");
        println!("  CRUX_MCP_URL={mcp}");
        return Ok(());
    }
    if let Some(existing) = crate::login::configured_endpoint() {
        println!("endpoint already configured: {existing} (change with `hooks install --endpoint <url>`)");
        return Ok(());
    }
    // Nothing configured yet. Prompt when interactive; otherwise note the default.
    if !std::io::stdin().is_terminal() {
        println!(
            "note: no daemon endpoint configured — hooks default to {}.\n  \
             point them at a remote daemon with `hooks install --endpoint <url>` (or `corecruxctl login --url <url>`).",
            crate::login::DEFAULT_HTTP_BASE
        );
        return Ok(());
    }
    let answer = prompt_endpoint();
    let url = if answer.is_empty() {
        crate::login::DEFAULT_HTTP_BASE.to_string()
    } else {
        answer
    };
    let (http, mcp, path) = crate::login::save_endpoint(&url)?;
    println!("endpoint saved → {}", path.display());
    println!("  CRUX_HTTP_URL={http}");
    println!("  CRUX_MCP_URL={mcp}");
    Ok(())
}

/// Prompt for the daemon HTTP endpoint, returning the trimmed answer (empty ⇒
/// caller substitutes the default).
fn prompt_endpoint() -> String {
    use std::io::Write as _;
    print!(
        "Crux daemon HTTP endpoint (host:port or URL) [{}]: ",
        crate::login::DEFAULT_HTTP_BASE
    );
    let _ = std::io::stdout().flush();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap_or(0);
    input.trim().to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The hooks surface must remain reachable through `corecruxctl` after the
    /// move, so an operator's existing `corecruxctl hooks install` / `status`
    /// keeps working unchanged. Behavioural coverage lives with the code, in
    /// `crux_config_wizard::hooks_install`; this only pins the delegation.
    ///
    /// Uses the project-scoped path so the test needs no `HOME` mutation.
    #[test]
    fn status_delegates_to_the_wizard_crate() {
        let dir = std::env::temp_dir().join(format!("cx-hooks-delegate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // No settings file present -> the wizard reports "not present" and returns Ok.
        run_status(false, Some(dir.clone())).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
