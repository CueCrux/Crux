// Copyright (c) 2026 CueCrux Ltd.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0.
// See LICENSE in the repository root.

//! Claude Code hook + banner-stack installation.
//!
//! This module owns the **client-side** install: the launcher, the observe /
//! filemod / scratchpad helpers, and the two-channel Python banner stack
//! (`crux-claude-banner`, `crux-statusline`), plus the `settings.json` merge that
//! wires them.
//!
//! It lives in `crux-config-wizard` rather than `corecruxctl` on purpose. The
//! banner assets are plain Python source, not build artefacts, and the crate that
//! composes a workspace's agent config is the one that should also be able to
//! install the hooks that config documents (see the `boot-banner` profile). More
//! practically: `crux-claude-hooks` (the `crux-hook` binary, the one component
//! actually present on every client machine) already depends on this crate, so
//! putting the assets here means a fresh machine needs no extra build to get a
//! working banner. Previously the assets were reachable only through
//! `corecruxctl`, which is frequently absent on clients — the banner then fails
//! silently to the two channels a human can see.
//!
//! Nothing here depends on a daemon endpoint or on `corecruxctl`. Endpoint
//! configuration stays with the caller (`corecruxctl hooks install` prompts and
//! saves it via its own `login` module before delegating here), which keeps this
//! module free of network and credential concerns and unit-testable in a tempdir.

use std::path::{Path, PathBuf};

/// Boxed error type for the install path.
pub type DynErr = Box<dyn std::error::Error + Send + Sync>;
/// Where hook helper scripts are installed (stable, repo-independent).
fn hooks_dir() -> Result<PathBuf, DynErr> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(Path::new(&home).join(".local").join("share").join("crux").join("hooks"))
}

/// Where helper *binaries* the agent invokes directly live (on PATH). The
/// scratchpad-survival helper lands here so `crux-scratchpad-persist --execplan`
/// is callable from any shell, and the SessionEnd launcher mode execs it here.
fn local_bin_dir() -> Result<PathBuf, DynErr> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(Path::new(&home).join(".local").join("bin"))
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
# Since the 2026-07-18 daemon redeploy the MCP endpoint accepts only registered
# agent tokens (crux-mcp authenticate_agent: registry/OAuth, no JWT). The JWT
# stays in CORECRUXD_AUTH_TOKEN above for the HTTP API (:14800); crux-hook's
# MCP client reads CRUX_AGENT_TOKEN, so swap it to the registered token.
mcp_tok="$HOME/.config/cuecrux/crux-tokens/anthropic.mcp-token"
if [ -f "$mcp_tok" ]; then
  CRUX_AGENT_TOKEN="$(tr -d ' \r\n' < "$mcp_tok")"
  export CRUX_AGENT_TOKEN
fi
mode="${1:-}"; shift || true
OBSERVE="$HOME/.local/share/crux/hooks/crux-observe.sh"
case "$mode" in
  banner)     exec crux-hook session-start ;;
  context)    exec crux-hook context-monitor ;;
  precompact) exec crux-hook pre-compact ;;
  observe)    exec "$OBSERVE" "$@" ;;
  filemod)    exec "$HOME/.local/share/crux/hooks/crux-filemod.sh" "$@" ;;
  scratchpad) exec "$HOME/.local/bin/crux-scratchpad-persist" --hook ;;
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

/// The B4 write-side file-modification ledger script, embedded so install works
/// without the repo. Shipped executable into the hooks dir; its `settings.json`
/// wiring stays operator/opt-in (script self-gates on `CRUX_HOOK_FILEMOD`).
const FILEMOD_SH: &str = include_str!("../../../integrations/claude-code/hooks/crux-filemod.sh");

/// The scratchpad-survival helper: copies a session's ephemeral
/// `/tmp/.../scratchpad` (+ background task outputs) into
/// `~/.crux/scratchpad-archive/` so work product survives session close. Wired on
/// SessionEnd via the `scratchpad` launcher mode (`--hook`: fact-free, best-effort
/// backstop); the agent calls it directly with `--execplan <slug>` for a
/// deliberate, fact-emitting handoff. Installed to `~/.local/bin` (on PATH).
const SCRATCHPAD_SH: &str = include_str!("../../../integrations/claude-code/hooks/crux-scratchpad-persist");

/// The Python SessionStart banner (Channels 2+3 of crux-banner-redesign): the
/// token-lean agent brief + conditional first-reply card. Registered-token auth
/// (reads `crux-tokens/anthropic.mcp-token`) so it works post-2026-07-18 daemon
/// redeploy. Installed to `~/.local/bin/crux-claude-banner` (no `.py` suffix).
const CLAUDE_BANNER_PY: &str = include_str!("../assets/hooks/crux-claude-banner.py");

/// The Python statusline (Channel 1): a persistent, zero-model-token human
/// surface rendered from a 60s cache. Installed to `~/.local/bin/crux-statusline`.
const STATUSLINE_PY: &str = include_str!("../assets/hooks/crux-statusline.py");

/// Coordination-plane presence for this session. Binds via `cuecrux_session`,
/// announces focus over `POST /v1/coord/announce`, and warns on `PreToolUse`
/// when a peer session has claimed the path about to be edited.
///
/// Exists because presence is opt-in and nothing was opting in: concurrent
/// sessions on one tree produced an empty board, so each believed it was alone.
/// Announcing needs the *bound* `cuecrux_session` id, not the Claude session
/// UUID — announcing with the UUID returns 200 and never joins presence, which
/// is why the gap was invisible. Advisory and fail-open throughout; disable with
/// `CRUX_COORD=0`. Installed to `~/.local/bin/crux-coord`.
const COORD_PY: &str = include_str!("../assets/hooks/crux-coord.py");

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

/// Write-on-change: skip if the destination already holds `body` (idempotence);
/// otherwise back the current contents up to `<path>.bak` before overwriting.
/// A non-existent (or non-UTF-8) destination is written without a backup.
fn write_exec_on_change(path: &Path, body: &str) -> Result<(), DynErr> {
    if let Ok(existing) = std::fs::read_to_string(path) {
        if existing == body {
            return Ok(());
        }
        std::fs::write(format!("{}.bak", path.display()), existing.as_bytes())?;
    }
    write_exec(path, body)
}

/// Is `python3` findable (PATH or `~/.local/bin`)? Gates the Python banner stack;
/// absent ⇒ fall back to the legacy wrapper `banner` mode.
fn python3_present() -> bool {
    std::env::var_os("PATH").is_some_and(|paths| std::env::split_paths(&paths).any(|d| d.join("python3").is_file()))
        || std::env::var_os("HOME").is_some_and(|h| Path::new(&h).join(".local/bin/python3").is_file())
}

/// Command substrings that mark a settings.json hook group as Crux-managed. A
/// group is ours (safe to drop + re-add) if any of its commands contains one of
/// these; everything else is a foreign/operator hook we must preserve.
const CRUX_HOOK_MARKERS: &[&str] = &[
    "crux-hook-env.sh",
    "crux-claude-banner",
    "crux-hook ",
    "crux-filemod.sh",
    "crux-observe.sh",
    "crux-scratchpad-persist",
];

/// True if `group` (a `{matcher, hooks:[…]}` entry) is Crux-managed.
fn is_crux_managed(group: &serde_json::Value) -> bool {
    let s = group.to_string();
    CRUX_HOOK_MARKERS.iter().any(|m| s.contains(m))
}

/// statusLine outcome for the install summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StatuslineOutcome {
    /// We set our statusLine (the key was absent).
    Set,
    /// An existing statusLine was left untouched.
    KeptExisting,
}

/// Install the helper scripts to `~/.local/share/crux/hooks` and the banner
/// stack to `~/.local/bin`. Returns the launcher path, the `~/.local/bin` dir,
/// and whether the `crux-hook` binary was found. The wrapper + banner-stack
/// scripts are written on-change (backup-then-write) so a re-run that already
/// holds the canonical bytes is a true no-op (no spurious `.bak`).
fn install_assets() -> Result<(PathBuf, PathBuf, bool), DynErr> {
    let dir = hooks_dir()?;
    std::fs::create_dir_all(&dir)?;
    let wrapper = dir.join("crux-hook-env.sh");
    write_exec_on_change(&wrapper, WRAPPER_SH)?;
    write_exec(&dir.join("crux-observe.sh"), OBSERVE_SH)?;
    write_exec(&dir.join("crux-filemod.sh"), FILEMOD_SH)?;
    // The scratchpad-survival helper + banner stack go on PATH (~/.local/bin) so
    // the agent can call `crux-scratchpad-persist --execplan <slug>` directly, the
    // SessionEnd `scratchpad` launcher mode execs it by absolute path, and the
    // SessionStart banner / statusLine entries point at the two Python scripts.
    let bin = local_bin_dir()?;
    std::fs::create_dir_all(&bin)?;
    write_exec(&bin.join("crux-scratchpad-persist"), SCRATCHPAD_SH)?;
    write_exec_on_change(&bin.join("crux-claude-banner"), CLAUDE_BANNER_PY)?;
    write_exec_on_change(&bin.join("crux-statusline"), STATUSLINE_PY)?;
    write_exec_on_change(&bin.join("crux-coord"), COORD_PY)?;
    Ok((wrapper, bin, locate_crux_hook().is_some()))
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

/// A `crux-coord <verb>` hook entry (absolute path; not routed via the wrapper,
/// which only dispatches `crux-hook` modes).
fn coord(local_bin: &Path, verb: &str) -> serde_json::Value {
    serde_json::json!({
        "type": "command",
        "command": format!("{} {verb}", local_bin.join("crux-coord").display()),
        "timeout": 6
    })
}

fn event(hooks: Vec<serde_json::Value>) -> serde_json::Value {
    event_matched(".*", hooks)
}

/// A single matcher-scoped hook group (for events whose hooks should only fire
/// on specific tool names, e.g. the opt-in `filemod` ledger on edit tools).
fn event_matched(matcher: &str, hooks: Vec<serde_json::Value>) -> serde_json::Value {
    serde_json::json!([{ "matcher": matcher, "hooks": hooks }])
}

/// Tool-name matcher for the write-side `filemod` ledger (mirrors the script's
/// own `case "$TOOL"` allowlist).
const FILEMOD_MATCHER: &str = "Edit|Write|MultiEdit|NotebookEdit";

/// Build the `hooks` block. Observe runs on all five lifecycle events. The
/// SessionStart banner prefers the Python banner stack (`crux-claude-banner`,
/// gated on `python3`); absent python3, it falls back to the legacy wrapper
/// `banner` mode (gated on the `crux-hook` binary). context-monitor + pre-compact
/// remain `crux-hook` features.
fn build_hooks_block(wrapper: &Path, local_bin: &Path, have_binary: bool, have_python: bool) -> serde_json::Value {
    let mut session_start = vec![cmd(wrapper, "observe session_start")];
    let mut post_tool = vec![cmd(wrapper, "observe tool_use")];
    let mut map = serde_json::Map::new();
    // Banner first in SessionStart so its brief/card lands before observe.
    if have_python {
        let banner = local_bin.join("crux-claude-banner");
        session_start.insert(
            0,
            serde_json::json!({ "type": "command", "command": banner.display().to_string(), "timeout": 10 }),
        );
        // Announce presence right after the banner: the banner reports the board,
        // this puts us on it. Without it every session reads "0 live sessions"
        // and concurrent writers stay invisible to each other.
        session_start.push(coord(local_bin, "announce"));
    } else if have_binary {
        session_start.insert(0, cmd(wrapper, "banner"));
    }
    if have_binary {
        post_tool.push(cmd(wrapper, "context"));
        map.insert("PreCompact".to_string(), event(vec![cmd(wrapper, "precompact")]));
    }
    map.insert("SessionStart".to_string(), event(session_start));
    map.insert(
        "UserPromptSubmit".to_string(),
        event(vec![cmd(wrapper, "observe user_prompt")]),
    );
    // PreToolUse: stash the pre-edit before-image for the opt-in filemod ledger.
    // Scoped to the edit tools; inert until the operator sets CRUX_HOOK_FILEMOD=1
    // (the script self-gates and always exits 0).
    // …and, when the Python stack is present, warn if a peer session has declared
    // the path we are about to edit. Advisory: prints to stderr and exits 0, so a
    // coord outage never blocks an edit.
    let mut pre_tool = vec![cmd(wrapper, "filemod pre")];
    if have_python {
        pre_tool.push(coord(local_bin, "check"));
    }
    map.insert("PreToolUse".to_string(), event_matched(FILEMOD_MATCHER, pre_tool));
    // PostToolUse: the existing observe (`.*`) group, plus the opt-in filemod
    // post leg scoped to the edit tools (hash + line-delta → daemon).
    let mut post_tool_groups = event(post_tool);
    if let Some(arr) = post_tool_groups.as_array_mut() {
        if let Some(group) = event_matched(FILEMOD_MATCHER, vec![cmd(wrapper, "filemod post")])
            .as_array_mut()
            .and_then(|g| g.first().cloned())
        {
            arr.push(group);
        }
    }
    map.insert("PostToolUse".to_string(), post_tool_groups);
    map.insert("Stop".to_string(), event(vec![cmd(wrapper, "observe stop")]));
    // SessionEnd: capture the lifecycle node, post the token-burn cost report, AND
    // archive the session scratchpad so its work product survives session close
    // (all three run independent of the crux-hook binary, so always wired). The
    // scratchpad leg is best-effort + fact-free (`--hook`); deliberate handoff
    // facts come from the agent's explicit `--execplan` call.
    let mut session_end = vec![
        cmd(wrapper, "observe session_end"),
        cmd(wrapper, "cost"),
        cmd(wrapper, "scratchpad"),
    ];
    if have_python {
        // Release the intent on the way out; otherwise a finished session keeps
        // claiming its paths until the presence TTL expires.
        session_end.push(coord(local_bin, "clear"));
    }
    map.insert("SessionEnd".to_string(), event(session_end));
    serde_json::Value::Object(map)
}

/// Merge the Crux hooks block into `path`, converging (not clobbering) the
/// operator's config:
///
/// - **Per-event, not wholesale.** For each event WE manage, drop the existing
///   Crux-managed groups (old + our own prior run) and prepend our fresh groups,
///   preserving every foreign group in its original relative order. Events we
///   don't manage are left untouched — the old `root["hooks"] = block` dropped
///   them, silently regressing operator hooks.
/// - **statusLine only-if-absent.** We never overwrite an existing statusLine.
/// - **Write-on-change.** If the composed file equals what's on disk, skip the
///   write entirely (no `.bak`, idempotent); otherwise back up then write.
fn merge_into_settings(
    path: &Path,
    hooks: serde_json::Value,
    statusline_cmd: &str,
) -> Result<StatuslineOutcome, DynErr> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let existing = std::fs::read_to_string(path).unwrap_or_default();
    let mut root: serde_json::Value = if existing.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(&existing)?
    };
    if !root.is_object() {
        return Err(format!("{} is not a JSON object", path.display()).into());
    }

    // Ensure `hooks` is an object we can merge into (existing non-object → reset).
    if !root.get("hooks").is_some_and(|h| h.is_object()) {
        root["hooks"] = serde_json::json!({});
    }
    let our = hooks
        .as_object()
        .ok_or("internal: built hooks block is not a JSON object")?;
    for (event, our_groups) in our {
        let our_arr = our_groups.as_array().cloned().unwrap_or_default();
        let existing_arr = root["hooks"]
            .get(event)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let foreign = existing_arr.into_iter().filter(|g| !is_crux_managed(g));
        let mut merged = our_arr;
        merged.extend(foreign);
        root["hooks"][event] = serde_json::Value::Array(merged);
    }

    // statusLine: set only when the key is absent; never overwrite an operator's.
    let sl_outcome = if root.get("statusLine").is_some() {
        StatuslineOutcome::KeptExisting
    } else {
        root["statusLine"] = serde_json::json!({ "type": "command", "command": statusline_cmd });
        StatuslineOutcome::Set
    };

    let new_text = serde_json::to_string_pretty(&root)? + "\n";
    if new_text != existing {
        if !existing.trim().is_empty() {
            std::fs::write(format!("{}.bak", path.display()), existing.as_bytes())?;
        }
        std::fs::write(path, &new_text)?;
    }
    Ok(sl_outcome)
}

/// Core install used by both the `hooks install` subcommand and `login`.
/// Returns a human-readable summary.
pub fn install(user: bool, project: Option<PathBuf>) -> Result<String, DynErr> {
    let (wrapper, local_bin, have_binary) = install_assets()?;
    let have_python = python3_present();
    let target = settings_path(user, project)?;
    let hooks = build_hooks_block(&wrapper, &local_bin, have_binary, have_python);
    let statusline_cmd = local_bin.join("crux-statusline").display().to_string();
    let sl = merge_into_settings(&target, hooks, &statusline_cmd)?;

    let mut summary = format!("hooks installed → {}", target.display());
    if have_python {
        summary.push_str(" (banner: crux-claude-banner + observe)");
    } else if have_binary {
        summary.push_str(
            " (banner: legacy crux-hook — python3 not found on PATH/~/.local/bin, banner-stack skipped; + observe)",
        );
    } else {
        summary.push_str(" (observe only — no python3 and no `crux-hook` binary; banner skipped)");
    }
    summary.push_str(match sl {
        StatuslineOutcome::Set => "\n  statusLine → crux-statusline (key was absent)",
        StatuslineOutcome::KeptExisting => "\n  statusLine left as-is (existing entry preserved)",
    });
    if !jq_present() {
        summary.push_str("\n  note: `jq` not found — the observe hooks need it (install jq, e.g. to ~/.local/bin)");
    }
    summary.push_str("\n  restart Claude Code (new session) for hooks to take effect");
    Ok(summary)
}

/// `hooks status` — report whether the Crux hooks are wired in the target
/// settings file. Endpoint-free, so `corecruxctl` and the wizard binary share
/// it. Returns the report rather than printing it: this is the library crate,
/// which forbids `print_stdout` so callers own their output surface (the same
/// shape as `commands::CommandReport`).
pub fn status(user: bool, project: Option<PathBuf>) -> Result<String, DynErr> {
    use std::fmt::Write as _;
    let target = settings_path(user, project)?;
    let Ok(s) = std::fs::read_to_string(&target) else {
        return Ok(format!("{}: not present (no hooks)", target.display()));
    };
    let root: serde_json::Value = serde_json::from_str(&s)?;
    let hooks = root.get("hooks").and_then(|h| h.as_object());
    let mut out = format!("settings: {}\n", target.display());
    match hooks {
        Some(map) if !map.is_empty() => {
            for (event, _) in map {
                let crux = is_crux_managed(&root["hooks"][event]);
                let _ = writeln!(out, "  {event:<16} {}", if crux { "crux ✓" } else { "(other)" });
            }
        }
        _ => out.push_str("  (no hooks configured)\n"),
    }
    let _ = writeln!(
        out,
        "crux-hook binary: {}",
        locate_crux_hook().map_or("not found".into(), |p| p.display().to_string())
    );
    let _ = write!(
        out,
        "jq: {}",
        if jq_present() {
            "found"
        } else {
            "MISSING (observe hooks need it)"
        }
    );
    Ok(out)
}

/// One component of the client-side banner stack, and how its on-disk state
/// compares with the bytes this binary would install.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentState {
    /// On disk and byte-identical to what we ship.
    Current,
    /// On disk but the contents differ — an older install, or a hand-edit.
    Stale,
    /// Not on disk at all.
    Missing,
}

/// A read-only audit of the installed banner stack. Deliberately does no I/O
/// beyond reading the two scripts and the settings file, and never writes, so a
/// session-start hook can call it on every boot without cost or risk.
#[derive(Debug, Clone)]
pub struct InstallAudit {
    pub banner: ComponentState,
    pub statusline: ComponentState,
    /// Is a `statusLine` key present in the user settings file?
    pub statusline_wired: bool,
    /// Is python3 resolvable? The Python banner stack is inert without it.
    pub python3: bool,
}

impl InstallAudit {
    /// True when every visible channel is installed, current, and wired — i.e.
    /// nothing to tell the operator about.
    pub fn healthy(&self) -> bool {
        self.banner == ComponentState::Current
            && self.statusline == ComponentState::Current
            && self.statusline_wired
            && self.python3
    }

    /// A one-line remedy, or `None` when healthy. Phrased for an agent brief:
    /// terse, actionable, no console URLs.
    pub fn advice(&self) -> Option<String> {
        if self.healthy() {
            return None;
        }
        if !self.python3 {
            return Some("banner stack inert: python3 not found on PATH or ~/.local/bin".into());
        }
        let mut missing = Vec::new();
        if self.banner != ComponentState::Current {
            missing.push(match self.banner {
                ComponentState::Missing => "crux-claude-banner absent",
                _ => "crux-claude-banner stale",
            });
        }
        if self.statusline != ComponentState::Current {
            missing.push(match self.statusline {
                ComponentState::Missing => "crux-statusline absent",
                _ => "crux-statusline stale",
            });
        }
        if !self.statusline_wired {
            missing.push("statusLine not wired in settings.json");
        }
        Some(format!(
            "{} — run `crux-config-wizard hooks install --user`",
            missing.join(", ")
        ))
    }
}

/// Compare one installed script against the bytes we embed.
fn component_state(path: &Path, want: &str) -> ComponentState {
    match std::fs::read_to_string(path) {
        Ok(got) if got == want => ComponentState::Current,
        Ok(_) => ComponentState::Stale,
        Err(_) => ComponentState::Missing,
    }
}

/// Audit the installed banner stack against what this binary ships. Used by the
/// session-start self-check so a client whose install is missing or stale says
/// so, instead of silently degrading to the channels nobody can see.
pub fn audit() -> InstallAudit {
    let bin = local_bin_dir().ok();
    let (banner, statusline) = match &bin {
        Some(b) => (
            component_state(&b.join("crux-claude-banner"), CLAUDE_BANNER_PY),
            component_state(&b.join("crux-statusline"), STATUSLINE_PY),
        ),
        None => (ComponentState::Missing, ComponentState::Missing),
    };
    let statusline_wired = settings_path(true, None)
        .ok()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .is_some_and(|v| v.get("statusLine").is_some());
    InstallAudit {
        banner,
        statusline,
        statusline_wired,
        python3: python3_present(),
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const LB: &str = "/x/.local/bin";

    #[test]
    fn coordination_hook_preserves_fail_open_and_safe_cache_contracts() {
        assert!(
            COORD_PY.contains("hashlib.sha256"),
            "hook cache filenames must not contain raw external session ids"
        );
        for error_type in [
            "_McpError",
            "urllib.error.URLError",
            "OSError",
            "ValueError",
            "TypeError",
            "AttributeError",
            "KeyError",
        ] {
            assert!(
                COORD_PY.contains(error_type),
                "{error_type} must stay inside the advisory fail-open boundary"
            );
        }
        assert!(
            COORD_PY.contains("error.status != 403"),
            "an ownership denial must invalidate one stale cached session and remint"
        );
    }

    #[test]
    fn coordination_hook_direct_invocation_prefers_registered_mcp_token() {
        let python_available = std::process::Command::new("python3")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success());
        if !python_available {
            return;
        }

        let home = tmp();
        let config = home.join(".config/cuecrux");
        let tokens = config.join("crux-tokens");
        std::fs::create_dir_all(&tokens).unwrap();
        std::fs::write(
            config.join("env"),
            "CRUX_MCP_URL=http://env.example:14801/mcp\nCRUX_AGENT_TOKEN=http-jwt\n",
        )
        .unwrap();
        std::fs::write(tokens.join("anthropic.mcp-token"), "registered-mcp-token\n").unwrap();

        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/hooks/crux-coord.py");
        let probe = concat!(
            "import json, runpy, sys; ",
            "module = runpy.run_path(sys.argv[1], run_name='crux_coord_test'); ",
            "print(json.dumps({'mcp': module['MCP'], 'token': module['TOKEN']}))"
        );
        let output = std::process::Command::new("python3")
            .arg("-c")
            .arg(probe)
            .arg(script)
            .env("HOME", &home)
            .env_remove("CRUX_MCP_URL")
            .env("CRUX_AGENT_TOKEN", "inherited-http-jwt")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "direct hook import failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let selected: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(selected["mcp"], "http://env.example:14801/mcp");
        assert_eq!(selected["token"], "registered-mcp-token");
    }

    #[test]
    fn hooks_block_observe_only_when_no_binary() {
        let w = Path::new("/x/crux-hook-env.sh");
        let lb = Path::new(LB);
        // No python3, no crux-hook binary → observe-only, no banner at all.
        let h = build_hooks_block(w, lb, false, false);
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
        let h = build_hooks_block(w, Path::new(LB), true, true);
        let hooks = h["SessionEnd"][0]["hooks"].as_array().unwrap();
        let cmds: Vec<String> = hooks
            .iter()
            .map(|c| c["command"].as_str().unwrap_or("").to_string())
            .collect();
        assert!(cmds.iter().any(|c| c.ends_with("observe session_end")));
        assert!(cmds.iter().any(|c| c.ends_with(" cost")), "cost mode wired: {cmds:?}");
        // …and the scratchpad-survival backstop is wired alongside cost.
        assert!(
            cmds.iter().any(|c| c.ends_with(" scratchpad")),
            "scratchpad mode wired: {cmds:?}"
        );
        // And the launcher knows the `cost` + `scratchpad` modes.
        assert!(WRAPPER_SH.contains("session cost --post"));
        assert!(WRAPPER_SH.contains("scratchpad)"));
        assert!(WRAPPER_SH.contains("crux-scratchpad-persist"));
    }

    #[test]
    fn hooks_block_wires_opt_in_filemod_pre_and_post() {
        let w = Path::new("/x/crux-hook-env.sh");
        // Wiring is present regardless of the crux-hook binary (filemod is
        // independent of it, like the cost leg).
        for have_binary in [false, true] {
            let h = build_hooks_block(w, Path::new(LB), have_binary, true);
            let map = h.as_object().unwrap();

            // PreToolUse: a single matcher group scoped to the edit tools, running
            // `filemod pre`.
            let pre = map.get("PreToolUse").unwrap_or_else(|| panic!("missing PreToolUse"));
            let pre_groups = pre.as_array().unwrap();
            assert!(
                pre_groups
                    .iter()
                    .any(|g| g["matcher"] == FILEMOD_MATCHER && g["hooks"].to_string().contains("filemod pre")),
                "PreToolUse must wire `filemod pre` on {FILEMOD_MATCHER}: {pre}"
            );

            // PostToolUse: keeps the existing observe (`.*`) group AND adds a
            // matcher-scoped `filemod post` group.
            let post = map.get("PostToolUse").unwrap();
            let post_groups = post.as_array().unwrap();
            assert!(
                post_groups
                    .iter()
                    .any(|g| g["matcher"] == ".*" && g["hooks"].to_string().contains("observe tool_use")),
                "PostToolUse must keep the observe group: {post}"
            );
            assert!(
                post_groups
                    .iter()
                    .any(|g| g["matcher"] == FILEMOD_MATCHER && g["hooks"].to_string().contains("filemod post")),
                "PostToolUse must wire `filemod post` on {FILEMOD_MATCHER}: {post}"
            );

            // The launcher knows the `filemod` mode and dispatches to the script.
            assert!(WRAPPER_SH.contains("filemod)"));
            assert!(WRAPPER_SH.contains("crux-filemod.sh"));
        }
    }

    #[test]
    fn hooks_block_adds_context_and_precompact_when_binary_present() {
        // have_binary=true, no python3 → legacy wrapper banner + context/precompact.
        let w = Path::new("/x/crux-hook-env.sh");
        let h = build_hooks_block(w, Path::new(LB), true, false);
        assert!(h.as_object().unwrap().contains_key("PreCompact"));
        let s = h.to_string();
        assert!(s.contains("banner")); // legacy `crux-hook-env.sh banner`
        assert!(!s.contains("crux-claude-banner"), "no python banner without python3");
        assert!(s.contains("precompact"));
        assert!(s.contains("context"));
    }

    #[test]
    fn session_start_prefers_python_banner_first() {
        // python3 present → SessionStart leads with crux-claude-banner (timeout 10),
        // then observe. Independent of the crux-hook binary.
        let w = Path::new("/x/crux-hook-env.sh");
        let h = build_hooks_block(w, Path::new(LB), false, true);
        let hooks = h["SessionStart"][0]["hooks"].as_array().unwrap();
        assert!(
            hooks[0]["command"].as_str().unwrap().ends_with("/crux-claude-banner"),
            "banner must be first: {hooks:?}"
        );
        assert_eq!(hooks[0]["timeout"], 10);
        assert!(hooks[1]["command"].as_str().unwrap().ends_with("observe session_start"));
        // The legacy wrapper `banner` mode must NOT be wired when python3 is present.
        assert!(!h.to_string().contains("crux-hook-env.sh banner"));
    }

    fn block(w: &Path) -> serde_json::Value {
        build_hooks_block(w, Path::new(LB), true, true)
    }

    #[test]
    fn merge_is_idempotent_and_preserves_other_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{"permissions":{"allow":["x"]}}"#).unwrap();
        let w = Path::new("/x/crux-hook-env.sh");
        let sl = "/x/.local/bin/crux-statusline";

        let bak = path.with_file_name("settings.json.bak");
        let o1 = merge_into_settings(&path, block(w), sl).unwrap();
        assert_eq!(o1, StatuslineOutcome::Set, "first run sets the absent statusLine");
        let after1 = std::fs::read_to_string(&path).unwrap();
        // Run 1 converged a non-empty file, so it legitimately backed the original up.
        let bak1 = std::fs::read_to_string(&bak).unwrap();
        let o2 = merge_into_settings(&path, block(w), sl).unwrap();
        assert_eq!(o2, StatuslineOutcome::KeptExisting, "second run keeps our statusLine");
        let after2 = std::fs::read_to_string(&path).unwrap();

        assert_eq!(after1, after2, "merge must be idempotent");
        // The no-op re-run must not touch the backup (write-on-change skipped the write).
        assert_eq!(
            bak1,
            std::fs::read_to_string(&bak).unwrap(),
            ".bak untouched on no-op re-run"
        );
        let v: serde_json::Value = serde_json::from_str(&after2).unwrap();
        assert_eq!(v["permissions"]["allow"][0], "x", "preserves existing keys");
        assert!(v["hooks"]["SessionStart"].is_array());
        assert_eq!(v["statusLine"]["command"], sl);
    }

    #[test]
    fn merge_preserves_foreign_hooks_and_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        // A foreign SessionStart group, a foreign PostToolUse group, and an event
        // we don't manage at all (Notification).
        std::fs::write(
            &path,
            r#"{
              "hooks": {
                "SessionStart": [{"matcher":".*","hooks":[{"type":"command","command":"/opt/foo/my-start.sh"}]}],
                "PostToolUse":  [{"matcher":".*","hooks":[{"type":"command","command":"/opt/foo/my-post.sh"}]}],
                "Notification": [{"matcher":".*","hooks":[{"type":"command","command":"/opt/foo/notify.sh"}]}]
              }
            }"#,
        )
        .unwrap();
        let w = Path::new("/x/crux-hook-env.sh");
        merge_into_settings(&path, block(w), "/x/.local/bin/crux-statusline").unwrap();
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let flat = v["hooks"].to_string();

        // Foreign entries survive.
        assert!(flat.contains("/opt/foo/my-start.sh"), "foreign SessionStart preserved");
        assert!(flat.contains("/opt/foo/my-post.sh"), "foreign PostToolUse preserved");
        // The unmanaged event is untouched.
        assert!(
            flat.contains("/opt/foo/notify.sh"),
            "unmanaged Notification event preserved"
        );
        // Our banner is present and leads SessionStart.
        let ss = v["hooks"]["SessionStart"].as_array().unwrap();
        assert!(ss[0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .ends_with("/crux-claude-banner"));
    }

    #[test]
    fn merge_converges_from_old_crux_wiring() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        // The OLD wiring: SessionStart wholesale-managed group with the wrapper
        // `banner` mode + observe, plus a foreign group the operator added.
        std::fs::write(
            &path,
            r#"{
              "hooks": {
                "SessionStart": [
                  {"matcher":".*","hooks":[
                    {"type":"command","command":"/home/me/.local/share/crux/hooks/crux-hook-env.sh banner"},
                    {"type":"command","command":"/home/me/.local/share/crux/hooks/crux-hook-env.sh observe session_start"}
                  ]},
                  {"matcher":".*","hooks":[{"type":"command","command":"/opt/foo/my-start.sh"}]}
                ]
              }
            }"#,
        )
        .unwrap();
        let w = Path::new("/x/crux-hook-env.sh");
        merge_into_settings(&path, block(w), "/x/.local/bin/crux-statusline").unwrap();
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let ss = v["hooks"]["SessionStart"].as_array().unwrap();

        // Banner-first, and the stale `crux-hook-env.sh banner` group is gone.
        assert!(ss[0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .ends_with("/crux-claude-banner"));
        let flat = v["hooks"]["SessionStart"].to_string();
        assert!(
            !flat.contains("crux-hook-env.sh banner"),
            "old wrapper banner entry removed: {flat}"
        );
        // Foreign group intact.
        assert!(flat.contains("/opt/foo/my-start.sh"), "foreign group preserved");
    }

    #[test]
    fn statusline_only_set_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let w = Path::new("/x/crux-hook-env.sh");

        // Absent → we set ours.
        let a = dir.path().join("a.json");
        std::fs::write(&a, "{}").unwrap();
        let out = merge_into_settings(&a, block(w), "/x/.local/bin/crux-statusline").unwrap();
        assert_eq!(out, StatuslineOutcome::Set);
        let va: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&a).unwrap()).unwrap();
        assert_eq!(va["statusLine"]["command"], "/x/.local/bin/crux-statusline");

        // Present → left untouched.
        let b = dir.path().join("b.json");
        std::fs::write(
            &b,
            r#"{"statusLine":{"type":"command","command":"/my/own/statusline"}}"#,
        )
        .unwrap();
        let out = merge_into_settings(&b, block(w), "/x/.local/bin/crux-statusline").unwrap();
        assert_eq!(out, StatuslineOutcome::KeptExisting);
        let vb: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&b).unwrap()).unwrap();
        assert_eq!(
            vb["statusLine"]["command"], "/my/own/statusline",
            "existing statusLine untouched"
        );
    }

    #[test]
    fn wrapper_template_carries_mcp_token_swap() {
        // The MCP registered-token swap (post-2026-07-18) must ship in the template.
        assert!(
            WRAPPER_SH.contains("anthropic.mcp-token"),
            "wrapper must swap CRUX_AGENT_TOKEN"
        );
        assert!(WRAPPER_SH.contains("CRUX_AGENT_TOKEN=\"$(tr -d"));
    }

    #[test]
    #[serial_test::serial]
    fn install_is_idempotent_no_new_bak() {
        let home = tmp();
        std::env::set_var("HOME", &home);
        // A PATH with a fake python3 so the banner-stack (crux-claude-banner) path
        // is exercised deterministically; no crux-hook binary → observe-only extras.
        let fakebin = home.join("fakebin");
        std::fs::create_dir_all(&fakebin).unwrap();
        std::fs::write(fakebin.join("python3"), "#!/bin/sh\n").unwrap();
        std::env::set_var("PATH", &fakebin);

        install(true, None).unwrap();
        let settings = home.join(".claude/settings.json");
        let s1 = std::fs::read_to_string(&settings).unwrap();
        let banner1 = std::fs::read_to_string(home.join(".local/bin/crux-claude-banner")).unwrap();
        let sl1 = std::fs::read_to_string(home.join(".local/bin/crux-statusline")).unwrap();

        install(true, None).unwrap();
        let s2 = std::fs::read_to_string(&settings).unwrap();
        let banner2 = std::fs::read_to_string(home.join(".local/bin/crux-claude-banner")).unwrap();
        let sl2 = std::fs::read_to_string(home.join(".local/bin/crux-statusline")).unwrap();

        assert_eq!(s1, s2, "settings must be byte-identical across installs");
        assert_eq!(banner1, banner2, "banner asset stable");
        assert_eq!(sl1, sl2, "statusline asset stable");
        // No `.bak` files anywhere the write-on-change helper touches.
        assert!(!home.join(".claude/settings.json.bak").exists(), "no settings .bak");
        assert!(
            !home.join(".local/bin/crux-claude-banner.bak").exists(),
            "no banner .bak"
        );
        assert!(
            !home.join(".local/bin/crux-statusline.bak").exists(),
            "no statusline .bak"
        );
        assert!(
            !home.join(".local/share/crux/hooks/crux-hook-env.sh.bak").exists(),
            "no wrapper .bak"
        );
        // The banner is wired first in SessionStart, statusLine set.
        let v: serde_json::Value = serde_json::from_str(&s2).unwrap();
        assert!(v["hooks"]["SessionStart"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .ends_with("/crux-claude-banner"));
        assert!(v["statusLine"]["command"]
            .as_str()
            .unwrap()
            .ends_with("/crux-statusline"));
    }

    /// Unique temp dir without pulling in a uuid dev-dependency: pid plus a
    /// monotonic counter is enough, and these tests are `#[serial]` anyway.
    pub(super) fn tmp() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let d = std::env::temp_dir().join(format!(
            "crux-hooks-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
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
        // launcher + observe + filemod scripts landed under ~/.local/share/crux/hooks.
        assert!(home.join(".local/share/crux/hooks/crux-hook-env.sh").is_file());
        assert!(home.join(".local/share/crux/hooks/crux-observe.sh").is_file());
        let filemod = home.join(".local/share/crux/hooks/crux-filemod.sh");
        assert!(filemod.is_file(), "crux-filemod.sh must be installed");
        // It must be executable (write_exec sets mode 0o755 on unix).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&filemod).unwrap().permissions().mode();
            assert_eq!(mode & 0o111, 0o111, "crux-filemod.sh must be executable: {mode:o}");
        }
        // The scratchpad-survival helper lands on PATH (~/.local/bin), executable.
        let scratch = home.join(".local/bin/crux-scratchpad-persist");
        assert!(
            scratch.is_file(),
            "crux-scratchpad-persist must be installed to ~/.local/bin"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&scratch).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o111,
                0o111,
                "crux-scratchpad-persist must be executable: {mode:o}"
            );
        }

        // install + status execute without error. (Endpoint config is the
        // in tests → configure_endpoint takes the non-interactive note branch.)
        install(true, None).unwrap();
        status(true, None).unwrap();

        // Now add the crux-hook binary. PATH is still "" (no python3), so the
        // banner falls back to the legacy wrapper mode; PreCompact/context appear.
        let bin = home.join(".local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("crux-hook"), "#!/bin/sh\n").unwrap();
        let summary = install(true, None).unwrap();
        assert!(summary.contains("legacy crux-hook"), "legacy fallback noted: {summary}");
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&settings).unwrap()).unwrap();
        assert!(v["hooks"].as_object().unwrap().contains_key("PreCompact"));
    }

    #[test]
    #[serial_test::serial]
    fn run_status_when_settings_absent() {
        let home = tmp();
        std::env::set_var("HOME", &home);
        // No ~/.claude/settings.json → the "not present" branch.
        status(true, None).unwrap();
    }
}

/// Assurance tests for the client-install path. These exist because the
/// failure mode this module was written to fix is *silent*: a client whose
/// banner stack is absent or stale still boots, still shows an agent brief, and
/// only loses the channels a human can see. Each test pins one way that could
/// come back.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod assurance {
    use super::*;

    /// The embedded assets must be the real scripts, not placeholders — a
    /// truncated or stubbed asset would install "successfully" and produce a
    /// dead banner.
    #[test]
    fn embedded_assets_are_substantive_python() {
        for (name, body) in [
            ("crux-claude-banner", CLAUDE_BANNER_PY),
            ("crux-statusline", STATUSLINE_PY),
        ] {
            assert!(
                body.len() > 4096,
                "{name} looks truncated ({} bytes) — check the include_str! path",
                body.len()
            );
            assert!(
                body.starts_with("#!") && body.contains("python"),
                "{name} must be an executable python script"
            );
        }
    }

    /// `audit()` must call a missing stack missing. Guards the self-check that
    /// tells an operator their client is broken.
    #[test]
    fn audit_reports_missing_components() {
        let a = InstallAudit {
            banner: ComponentState::Missing,
            statusline: ComponentState::Missing,
            statusline_wired: false,
            python3: true,
        };
        assert!(!a.healthy());
        let advice = a.advice().unwrap();
        assert!(advice.contains("crux-claude-banner absent"), "{advice}");
        assert!(advice.contains("crux-statusline absent"), "{advice}");
        assert!(advice.contains("statusLine not wired"), "{advice}");
        assert!(
            advice.contains("hooks install"),
            "advice must name the remedy: {advice}"
        );
    }

    /// A present-but-drifted script is the sneaky case: it looks installed.
    /// `audit()` must distinguish stale from missing and from current.
    #[test]
    fn audit_distinguishes_stale_from_current() {
        let a = InstallAudit {
            banner: ComponentState::Stale,
            statusline: ComponentState::Current,
            statusline_wired: true,
            python3: true,
        };
        assert!(!a.healthy());
        assert!(a.advice().unwrap().contains("crux-claude-banner stale"));

        let healthy = InstallAudit {
            banner: ComponentState::Current,
            statusline: ComponentState::Current,
            statusline_wired: true,
            python3: true,
        };
        assert!(healthy.healthy());
        assert!(healthy.advice().is_none(), "healthy must stay silent");
    }

    /// No python3 ⇒ the whole stack is inert. That must be the headline advice,
    /// not a note buried behind two "absent" lines the operator can't act on.
    #[test]
    fn audit_leads_with_missing_python() {
        let a = InstallAudit {
            banner: ComponentState::Missing,
            statusline: ComponentState::Missing,
            statusline_wired: false,
            python3: false,
        };
        let advice = a.advice().unwrap();
        assert!(advice.contains("python3"), "{advice}");
    }

    /// `component_state` is the primitive the self-check rests on.
    #[test]
    fn component_state_detects_all_three() {
        let dir = super::tests::tmp();
        let p = dir.join("script");
        assert_eq!(component_state(&p, "body"), ComponentState::Missing);
        std::fs::write(&p, "body").unwrap();
        assert_eq!(component_state(&p, "body"), ComponentState::Current);
        std::fs::write(&p, "other").unwrap();
        assert_eq!(component_state(&p, "body"), ComponentState::Stale);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
