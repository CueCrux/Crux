// Copyright (c) 2026 CueCrux Ltd. All rights reserved.
// Licensed under the CueCrux Community Licence (CCL v1.0).
// See LICENCE.md in the repository root.

//! `corecruxctl hooks` — install + inspect the Crux Claude Code hooks.
//!
//! Installs two fire-and-forget integrations into a Claude Code `settings.json`:
//!
//! - the **banner** + context/pre-compact hooks via the `crux-hook` binary
//!   (only when that binary is found on `PATH` or `~/.local/bin`), and
//! - the **observe capture** hooks via the embedded `crux-observe.sh` (signed
//!   lifecycle evidence → daemon).
//!
//! Both run through a launcher (`crux-hook-env.sh`) that sources
//! `~/.config/cuecrux/env` (0600, written by `corecruxctl login`) so the daemon
//! URL + bearer token never live in `settings.json`. Idempotent; backs up the
//! settings file before writing.

use std::path::{Path, PathBuf};

type DynErr = Box<dyn std::error::Error + Send + Sync>;

/// Where hook helper scripts are installed (stable, repo-independent).
fn hooks_dir() -> Result<PathBuf, DynErr> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(Path::new(&home).join(".local").join("share").join("crux").join("hooks"))
}

/// The embedded launcher: sources the cuecrux env, maps it to the names each
/// hook expects, then dispatches. Kept in sync with the in-repo copy.
const WRAPPER_SH: &str = r#"#!/usr/bin/env bash
# Crux hook launcher for Claude Code (installed by `corecruxctl hooks install`).
# Sources ~/.config/cuecrux/env (0600) so the token never lives in settings.json.
set -a
# shellcheck disable=SC1090
. "$HOME/.config/cuecrux/env" 2>/dev/null || true
set +a
export PATH="$HOME/.local/bin:$PATH"
export CRUX_MCP_URL="${CRUX_MCP_URL:-http://127.0.0.1:14801/mcp}"
export CRUX_HTTP_URL="${CRUX_HTTP_URL:-http://127.0.0.1:14800}"
export CORECRUXD_URL="${CRUX_HTTP_URL}"
export CORECRUXD_AUTH_TOKEN="${CRUX_AGENT_TOKEN:-}"
mode="${1:-}"; shift || true
OBSERVE="$HOME/.local/share/crux/hooks/crux-observe.sh"
case "$mode" in
  banner)     exec crux-hook session-start ;;
  context)    exec crux-hook context-monitor ;;
  precompact) exec crux-hook pre-compact ;;
  observe)    exec "$OBSERVE" "$@" ;;
  cost)
    # SessionEnd: post the just-ended transcript's token-burn cost report to the
    # daemon (feeds the cx-cost lens + per-ExecPlan token_burn). Read the hook
    # payload on stdin for the exact transcript path; fall back to the newest.
    # Quiet + non-fatal — a missing corecruxctl / expired token / parse error
    # must never block session end (the cost-sweep timer backstops misses).
    payload="$(cat 2>/dev/null || true)"
    tx="$(printf '%s' "$payload" | jq -r '.transcript_path // empty' 2>/dev/null || true)"
    ctl="$(command -v corecruxctl 2>/dev/null || echo "$HOME/.local/bin/corecruxctl")"
    if [ -x "$ctl" ]; then
      if [ -n "$tx" ] && [ -f "$tx" ]; then
        "$ctl" session cost --post --file "$tx" --url "${CRUX_HTTP_URL}" >/dev/null 2>&1 || true
      else
        "$ctl" session cost --post --url "${CRUX_HTTP_URL}" >/dev/null 2>&1 || true
      fi
    fi
    exit 0 ;;
  *) echo "crux-hook-env: unknown mode '$mode'" >&2; exit 0 ;;
esac
"#;

/// The observe-capture script, embedded so install works without the repo.
const OBSERVE_SH: &str = include_str!("../../../integrations/claude-code/hooks/crux-observe.sh");

/// Resolve the `crux-hook` binary (banner/context/pre-compact). `None` ⇒ install
/// observe-only and note the banner needs the binary.
fn locate_crux_hook() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        let p = Path::new(&home).join(".local").join("bin").join("crux-hook");
        if p.is_file() {
            return Some(p);
        }
    }
    // PATH scan.
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            let p = dir.join("crux-hook");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

fn jq_present() -> bool {
    std::env::var_os("PATH").is_some_and(|paths| std::env::split_paths(&paths).any(|d| d.join("jq").is_file()))
        || std::env::var_os("HOME").is_some_and(|h| Path::new(&h).join(".local/bin/jq").is_file())
}

#[cfg(unix)]
fn write_exec(path: &Path, body: &str) -> Result<(), DynErr> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o755)
        .open(path)?;
    f.write_all(body.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_exec(path: &Path, body: &str) -> Result<(), DynErr> {
    std::fs::write(path, body)?;
    Ok(())
}

/// Install the helper scripts to `~/.local/share/crux/hooks`. Returns the
/// launcher path + whether the `crux-hook` binary was found.
fn install_assets() -> Result<(PathBuf, bool), DynErr> {
    let dir = hooks_dir()?;
    std::fs::create_dir_all(&dir)?;
    let wrapper = dir.join("crux-hook-env.sh");
    write_exec(&wrapper, WRAPPER_SH)?;
    write_exec(&dir.join("crux-observe.sh"), OBSERVE_SH)?;
    Ok((wrapper, locate_crux_hook().is_some()))
}

/// Resolve the target `settings.json`: user (`~/.claude/settings.json`) or a
/// project dir (`<dir>/.claude/settings.local.json`, default cwd).
fn settings_path(user: bool, project: Option<PathBuf>) -> Result<PathBuf, DynErr> {
    if user {
        let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
        return Ok(Path::new(&home).join(".claude").join("settings.json"));
    }
    let base = match project {
        Some(p) => p,
        None => std::env::current_dir()?,
    };
    Ok(base.join(".claude").join("settings.local.json"))
}

fn cmd(wrapper: &Path, args: &str) -> serde_json::Value {
    serde_json::json!({ "type": "command", "command": format!("{} {args}", wrapper.display()) })
}

fn event(hooks: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!([{ "matcher": ".*", "hooks": hooks }])
}

/// Build the `hooks` block. Observe runs on all five lifecycle events; the
/// banner/context/pre-compact entries are added only when `crux-hook` exists.
fn build_hooks_block(wrapper: &Path, have_binary: bool) -> serde_json::Value {
    let mut session_start = vec![cmd(wrapper, "observe session_start")];
    let mut post_tool = vec![cmd(wrapper, "observe tool_use")];
    let mut map = serde_json::Map::new();
    if have_binary {
        session_start.insert(0, cmd(wrapper, "banner"));
        post_tool.push(cmd(wrapper, "context"));
        map.insert("PreCompact".to_string(), event(vec![cmd(wrapper, "precompact")]));
    }
    map.insert("SessionStart".to_string(), event(session_start));
    map.insert(
        "UserPromptSubmit".to_string(),
        event(vec![cmd(wrapper, "observe user_prompt")]),
    );
    map.insert("PostToolUse".to_string(), event(post_tool));
    map.insert("Stop".to_string(), event(vec![cmd(wrapper, "observe stop")]));
    // SessionEnd: capture the lifecycle node AND post the token-burn cost report
    // (cost runs corecruxctl directly, so it is independent of the crux-hook
    // binary and is always wired).
    map.insert(
        "SessionEnd".to_string(),
        event(vec![cmd(wrapper, "observe session_end"), cmd(wrapper, "cost")]),
    );
    serde_json::Value::Object(map)
}

/// Merge the Crux hooks block into `path`, preserving other keys. Backs up the
/// existing file to `<path>.bak`.
fn merge_into_settings(path: &Path, hooks: serde_json::Value) -> Result<(), DynErr> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut root: serde_json::Value = match std::fs::read_to_string(path) {
        Ok(s) if !s.trim().is_empty() => {
            std::fs::write(format!("{}.bak", path.display()), &s)?;
            serde_json::from_str(&s)?
        }
        _ => serde_json::json!({}),
    };
    if !root.is_object() {
        return Err(format!("{} is not a JSON object", path.display()).into());
    }
    root["hooks"] = hooks;
    std::fs::write(path, serde_json::to_string_pretty(&root)? + "\n")?;
    Ok(())
}

/// Core install used by both the `hooks install` subcommand and `login`.
/// Returns a human-readable summary.
pub fn install(user: bool, project: Option<PathBuf>) -> Result<String, DynErr> {
    let (wrapper, have_binary) = install_assets()?;
    let target = settings_path(user, project)?;
    let hooks = build_hooks_block(&wrapper, have_binary);
    merge_into_settings(&target, hooks)?;

    let mut summary = format!("hooks installed → {}", target.display());
    summary.push_str(if have_binary {
        " (banner + observe)"
    } else {
        " (observe only — `crux-hook` binary not found on PATH/~/.local/bin; banner skipped)"
    });
    if !jq_present() {
        summary.push_str("\n  note: `jq` not found — the observe hooks need it (install jq, e.g. to ~/.local/bin)");
    }
    summary.push_str("\n  restart Claude Code (new session) for hooks to take effect");
    Ok(summary)
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

/// `corecruxctl hooks status` — show whether Crux hooks are wired in the target.
pub fn run_status(user: bool, project: Option<PathBuf>) -> Result<(), DynErr> {
    let target = settings_path(user, project)?;
    let Ok(s) = std::fs::read_to_string(&target) else {
        println!("{}: not present (no hooks)", target.display());
        return Ok(());
    };
    let root: serde_json::Value = serde_json::from_str(&s)?;
    let hooks = root.get("hooks").and_then(|h| h.as_object());
    println!("settings: {}", target.display());
    match hooks {
        Some(map) if !map.is_empty() => {
            for (event, _) in map {
                let crux = root["hooks"][event].to_string().contains("crux-hook-env.sh");
                println!("  {event:<16} {}", if crux { "crux ✓" } else { "(other)" });
            }
        }
        _ => println!("  (no hooks configured)"),
    }
    println!(
        "crux-hook binary: {}",
        locate_crux_hook().map_or("not found".into(), |p| p.display().to_string())
    );
    println!(
        "jq: {}",
        if jq_present() {
            "found"
        } else {
            "MISSING (observe hooks need it)"
        }
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn hooks_block_observe_only_when_no_binary() {
        let w = Path::new("/x/crux-hook-env.sh");
        let h = build_hooks_block(w, false);
        let map = h.as_object().unwrap();
        for ev in ["SessionStart", "UserPromptSubmit", "PostToolUse", "Stop", "SessionEnd"] {
            assert!(map.contains_key(ev), "missing {ev}");
        }
        assert!(!map.contains_key("PreCompact"));
        assert!(!h.to_string().contains("banner"));
        // The cost-post is always wired on SessionEnd (independent of crux-hook).
        assert!(
            map["SessionEnd"].to_string().contains("cost"),
            "SessionEnd must post the cost report"
        );
    }

    #[test]
    fn session_end_wires_observe_then_cost() {
        let w = Path::new("/x/crux-hook-env.sh");
        let h = build_hooks_block(w, true);
        let hooks = h["SessionEnd"][0]["hooks"].as_array().unwrap();
        let cmds: Vec<String> = hooks
            .iter()
            .map(|c| c["command"].as_str().unwrap_or("").to_string())
            .collect();
        assert!(cmds.iter().any(|c| c.ends_with("observe session_end")));
        assert!(cmds.iter().any(|c| c.ends_with(" cost")), "cost mode wired: {cmds:?}");
        // And the launcher knows the `cost` mode.
        assert!(WRAPPER_SH.contains("session cost --post"));
    }

    #[test]
    fn hooks_block_adds_banner_when_binary_present() {
        let w = Path::new("/x/crux-hook-env.sh");
        let h = build_hooks_block(w, true);
        assert!(h.as_object().unwrap().contains_key("PreCompact"));
        let s = h.to_string();
        assert!(s.contains("banner"));
        assert!(s.contains("precompact"));
        assert!(s.contains("context"));
    }

    #[test]
    fn merge_is_idempotent_and_preserves_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{"permissions":{"allow":["x"]}}"#).unwrap();
        let w = Path::new("/x/crux-hook-env.sh");

        merge_into_settings(&path, build_hooks_block(w, true)).unwrap();
        let after1 = std::fs::read_to_string(&path).unwrap();
        merge_into_settings(&path, build_hooks_block(w, true)).unwrap();
        let after2 = std::fs::read_to_string(&path).unwrap();

        assert_eq!(after1, after2, "merge must be idempotent");
        let v: serde_json::Value = serde_json::from_str(&after2).unwrap();
        assert_eq!(v["permissions"]["allow"][0], "x", "preserves existing keys");
        assert!(v["hooks"]["SessionStart"].is_array());
    }

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("crux-hooks-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    #[serial_test::serial]
    fn settings_path_user_project_and_default() {
        let home = tmp();
        std::env::set_var("HOME", &home);
        assert_eq!(settings_path(true, None).unwrap(), home.join(".claude/settings.json"));
        let proj = tmp();
        assert_eq!(
            settings_path(false, Some(proj.clone())).unwrap(),
            proj.join(".claude/settings.local.json")
        );
        // default (cwd) variant just needs to resolve without error.
        assert!(settings_path(false, None).is_ok());
    }

    #[test]
    #[serial_test::serial]
    fn locate_and_jq_probes_follow_home_and_path() {
        let home = tmp();
        std::env::set_var("HOME", &home);
        std::env::set_var("PATH", ""); // nothing on PATH
        assert!(locate_crux_hook().is_none());
        assert!(!jq_present());

        // Drop a fake crux-hook + jq under ~/.local/bin.
        let bin = home.join(".local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("crux-hook"), "#!/bin/sh\n").unwrap();
        std::fs::write(bin.join("jq"), "#!/bin/sh\n").unwrap();
        assert_eq!(locate_crux_hook(), Some(bin.join("crux-hook")));
        assert!(jq_present());
    }

    #[test]
    #[serial_test::serial]
    fn install_observe_only_then_with_binary_and_status() {
        let home = tmp();
        std::env::set_var("HOME", &home);
        std::env::set_var("PATH", "");

        // No crux-hook binary → observe-only install.
        let summary = install(true, None).unwrap();
        assert!(summary.contains("observe only"));
        let settings = home.join(".claude/settings.json");
        assert!(settings.is_file());
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert!(v["hooks"]["SessionStart"].is_array());
        assert!(!v["hooks"].as_object().unwrap().contains_key("PreCompact"));
        // launcher + observe script landed under ~/.local/share/crux/hooks.
        assert!(home.join(".local/share/crux/hooks/crux-hook-env.sh").is_file());
        assert!(home.join(".local/share/crux/hooks/crux-observe.sh").is_file());

        // run_install + run_status execute without error. (No endpoint + no TTY
        // in tests → configure_endpoint takes the non-interactive note branch.)
        run_install(true, None, None).unwrap();
        run_status(true, None).unwrap();

        // Now add the binary → banner + PreCompact appear.
        let bin = home.join(".local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("crux-hook"), "#!/bin/sh\n").unwrap();
        let summary = install(true, None).unwrap();
        assert!(summary.contains("banner + observe"));
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert!(v["hooks"].as_object().unwrap().contains_key("PreCompact"));
    }

    #[test]
    #[serial_test::serial]
    fn run_status_when_settings_absent() {
        let home = tmp();
        std::env::set_var("HOME", &home);
        // No ~/.claude/settings.json → the "not present" branch.
        run_status(true, None).unwrap();
    }
}
