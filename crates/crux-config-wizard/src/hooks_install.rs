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

use std::ffi::OsStr;
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
# Bumped whenever a launcher mode changes behaviour an operator can observe, so
# `corecruxctl hooks status` can name a stale install instead of leaving the
# operator to wonder why a shipped fix appears to do nothing.
CRUX_HOOK_ENV_VERSION=2
set -a
# shellcheck disable=SC1090
. "$HOME/.config/cuecrux/env" 2>/dev/null || true
set +a
export PATH="$HOME/.local/bin:$PATH"
export CRUX_MCP_URL="${CRUX_MCP_URL:-http://127.0.0.1:14801/mcp}"
# Remember whether the endpoint came from the operator's env file or from the
# built-in loopback default *before* defaulting collapses the difference. A
# posting failure against an unconfigured default is a setup problem
# ("you never ran `corecruxctl login --url`"), not an outage, and the cost
# hook's outcome record is the only place that distinction ever surfaces.
if [ -n "${CRUX_HTTP_URL:-}" ]; then
  CRUX_HTTP_URL_SOURCE=config
else
  CRUX_HTTP_URL_SOURCE=default
fi
export CRUX_HTTP_URL_SOURCE
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
    #
    # Quiet + non-fatal — a missing corecruxctl / expired token / parse error
    # must never block session end (the cost-sweep timer backstops misses), so
    # `exit 0` is unconditional on every path below. Quiet is not the same as
    # undiagnosable, though: the previous version swallowed all three failure
    # modes with `|| true` and left no way to tell "no sessions ran" apart from
    # "every session silently failed to post". Every attempt now writes its
    # outcome to $cost_state, and failures append one line to $cost_log.
    cost_dir="$HOME/.claude/hooks"
    cost_state="$cost_dir/crux-cost.state.json"
    cost_log="$cost_dir/crux-cost.errors.log"
    mkdir -p "$cost_dir" 2>/dev/null || true
    # Strip the two characters that would break the single-line JSON record, and
    # flatten newlines: reasons carry CLI stderr, which is neither short nor tame.
    cost_clean() { printf '%s' "$1" | tr -d '\\"' | tr '\n\r\t' '   ' | cut -c1-300; }
    # $1 = ok|failed|never_attempted, $2 = reason (empty on ok), $3 = transcript
    cost_record() {
      cost_ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo unknown)"
      printf '{"at":"%s","result":"%s","reason":"%s","transcript":"%s","url":"%s","url_source":"%s","hook_version":"%s"}\n' \
        "$cost_ts" "$1" "$(cost_clean "$2")" "$(cost_clean "$3")" \
        "$(cost_clean "$CRUX_HTTP_URL")" "$CRUX_HTTP_URL_SOURCE" "$CRUX_HOOK_ENV_VERSION" \
        > "$cost_state" 2>/dev/null || true
      if [ "$1" != ok ]; then
        printf '%s [cost] %s: %s (url=%s source=%s)\n' \
          "$cost_ts" "$1" "$(cost_clean "$2")" "$CRUX_HTTP_URL" "$CRUX_HTTP_URL_SOURCE" \
          >> "$cost_log" 2>/dev/null || true
      fi
    }
    payload="$(cat 2>/dev/null || true)"
    tx="$(printf '%s' "$payload" | jq -r '.transcript_path // empty' 2>/dev/null || true)"
    ctl="$(command -v corecruxctl 2>/dev/null || echo "$HOME/.local/bin/corecruxctl")"
    if [ ! -x "$ctl" ]; then
      cost_record never_attempted "corecruxctl not found or not executable at $ctl" "$tx"
      exit 0
    fi
    if [ -n "$tx" ] && [ -f "$tx" ]; then
      cost_err="$("$ctl" session cost --post --file "$tx" --url "${CRUX_HTTP_URL}" 2>&1 >/dev/null)"; cost_rc=$?
    else
      tx=""
      cost_err="$("$ctl" session cost --post --url "${CRUX_HTTP_URL}" 2>&1 >/dev/null)"; cost_rc=$?
    fi
    if [ "$cost_rc" -eq 0 ]; then
      cost_record ok "" "$tx"
    elif [ "$CRUX_HTTP_URL_SOURCE" = default ]; then
      # The endpoint was never configured, so this is the loopback default. Say
      # that rather than reporting a connection refused the operator cannot place.
      cost_record failed "post failed (rc=$cost_rc) against the unconfigured default endpoint - run: corecruxctl hooks install --endpoint <url>: $cost_err" "$tx"
    else
      cost_record failed "post failed (rc=$cost_rc): $cost_err" "$tx"
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

/// Where is `python3`, if it is findable **and runnable** (PATH or
/// `~/.local/bin`)? Gates the Python banner stack; `None` ⇒ fall back to the
/// legacy wrapper `banner` mode.
///
/// Executability is checked, not just existence. A PATH entry holding a
/// non-executable file named `python3` used to satisfy this, after which the
/// caller's `Command::new("python3")` failed with `PermissionDenied` — the guard
/// said "present", the exec said otherwise. That is exactly what happened on CI
/// runner `runner-hel1-4` on 2026-08-08.
///
/// The resolved path is returned rather than a bare bool because the two legs
/// are not interchangeable at exec time: a hit via the `~/.local/bin` fallback
/// is *not* reachable by a bare `Command::new("python3")`, which searches PATH
/// only. Returning a bool let a caller pair "present" with a bare-name exec and
/// get `NotFound` — the same guard-vs-exec split as above, one leg over. Callers
/// that exec must use this path; `python3_present` is for gating alone.
fn python3_path() -> Option<PathBuf> {
    resolve_python3(std::env::var_os("PATH").as_deref(), std::env::var_os("HOME").as_deref())
}

/// The resolution itself, over explicit `PATH`/`HOME` so it is testable without
/// mutating process env (which is `unsafe` and racy across parallel tests).
fn resolve_python3(path_var: Option<&OsStr>, home: Option<&OsStr>) -> Option<PathBuf> {
    fn runnable(p: &Path) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        }
        #[cfg(not(unix))]
        {
            p.is_file()
        }
    }
    let on_path = path_var.and_then(|paths| std::env::split_paths(paths).map(|d| d.join("python3")).find(|p| runnable(p)));
    on_path.or_else(|| {
        home.map(|h| Path::new(h).join(".local/bin/python3"))
            .filter(|p| runnable(p))
    })
}

/// Is `python3` findable and runnable? See [`python3_path`] — callers that go on
/// to exec it must use that path, not the bare name.
fn python3_present() -> bool {
    python3_path().is_some()
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
    // `crux-coord` must be here even though it was installed before this entry
    // existed. Until the Bash guard, every group carrying `crux-coord` also
    // carried another marker (`filemod pre` on PreToolUse, the banner on
    // SessionStart), so the omission was invisible. The Bash group carries
    // `crux-coord check` alone: without this marker the merge reads it as a
    // foreign operator hook, preserves it, re-adds ours, and the group doubles
    // on every install. Caught by `merge_is_idempotent_and_preserves_other_keys`.
    "crux-coord",
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

/// Matcher for the coord destructive-command guard. Bash is the only tool that
/// can wipe a tree the coordination plane is tracking; the hook then self-filters
/// to `git clean` / `reset --hard` / `checkout -f` / `stash` / `worktree remove`,
/// so a normal `cargo test` costs one process that exits immediately.
const BASH_MATCHER: &str = "Bash";

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
    let mut pre_tool_groups = event_matched(FILEMOD_MATCHER, pre_tool);
    // …and a second group on Bash, for the destructive half. Announcing intent
    // only covers edits: a peer saying "I am working in this tree" says nothing
    // about the session about to `git clean` it. On 2026-08-06 one session
    // cleaned a shared checkout and destroyed another's uncommitted artefact,
    // both live, neither warned, because coord only ever saw Edit/Write. The
    // hook self-filters to tree-destroying git verbs, so the overwhelming
    // majority of Bash calls cost one no-op process.
    if have_python {
        if let Some(arr) = pre_tool_groups.as_array_mut() {
            if let Some(group) = event_matched(BASH_MATCHER, vec![coord(local_bin, "check")])
                .as_array_mut()
                .and_then(|g| g.first().cloned())
            {
                arr.push(group);
            }
        }
    }
    map.insert("PreToolUse".to_string(), pre_tool_groups);
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
    let _ = writeln!(
        out,
        "jq: {}",
        if jq_present() {
            "found"
        } else {
            "MISSING (observe hooks need it)"
        }
    );
    let _ = write!(out, "{}", cost_capture()?.report());
    Ok(out)
}

// ── SessionEnd cost-capture diagnosability ──────────────────────────────────

/// Version of the `WRAPPER_SH` launcher template this binary ships. Bumped
/// whenever a launcher mode changes observable behaviour; the `cost)` branch
/// stamps it into every outcome record so a stale on-disk launcher is
/// self-identifying rather than mysterious.
pub const HOOK_ENV_VERSION: &str = "2";

/// Where the `cost)` launcher mode records its last outcome. Sits beside the
/// observe/filemod error logs (`~/.claude/hooks/`) rather than under the hooks
/// *script* dir, because it is operator-facing state, not an installed asset.
fn cost_state_path() -> Result<PathBuf, DynErr> {
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(Path::new(&home)
        .join(".claude")
        .join("hooks")
        .join("crux-cost.state.json"))
}

/// The last recorded outcome of the SessionEnd cost-capture hook, plus whether
/// the launcher that would run next is the version this binary ships.
///
/// Exists because the previous `cost)` branch failed silently on three paths, so
/// an operator had no way to tell "no sessions ran" from "every session failed
/// to post". One command now answers that.
#[derive(Debug, Clone)]
pub struct CostCapture {
    /// `ok`, `failed`, or `never_attempted`; `None` when no attempt was ever
    /// recorded (either the hook has not run, or it predates the outcome record).
    pub result: Option<String>,
    /// RFC3339 timestamp of that attempt.
    pub at: Option<String>,
    /// Terse failure reason; empty/absent on success.
    pub reason: Option<String>,
    /// Endpoint the post was aimed at, and whether it was configured or the
    /// built-in loopback default — the single most common cause of a silent miss.
    pub url: Option<String>,
    /// `config` or `default`.
    pub url_source: Option<String>,
    /// `CRUX_HOOK_ENV_VERSION` parsed out of the *installed* launcher script;
    /// `None` when the launcher is absent or predates the marker.
    pub installed_version: Option<String>,
    /// Path of the state file (named so the operator can go and read it).
    pub state_path: PathBuf,
}

impl CostCapture {
    /// True when the installed launcher is the version this binary ships — i.e.
    /// the shipped fix is actually the code that will run at the next session end.
    #[must_use]
    pub fn launcher_current(&self) -> bool {
        self.installed_version.as_deref() == Some(HOOK_ENV_VERSION)
    }

    /// Human report block, appended to `hooks status`.
    #[must_use]
    pub fn report(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::from("\ncost capture (SessionEnd → /v1/cost/report):\n");
        match self.result.as_deref() {
            Some(r) => {
                let _ = writeln!(out, "  last attempt: {r} at {}", self.at.as_deref().unwrap_or("?"));
                if let Some(reason) = self.reason.as_deref().filter(|s| !s.is_empty()) {
                    let _ = writeln!(out, "    reason: {reason}");
                }
                if let Some(url) = self.url.as_deref() {
                    let src = self.url_source.as_deref().unwrap_or("?");
                    let _ = writeln!(out, "    endpoint: {url} ({src})");
                }
            }
            None => {
                let _ = writeln!(
                    out,
                    "  last attempt: none recorded — no session has ended since the hook was installed, \
                     or the launcher predates outcome recording"
                );
            }
        }
        match &self.installed_version {
            Some(v) if v == HOOK_ENV_VERSION => {
                let _ = writeln!(out, "  launcher: v{v} (current)");
            }
            Some(v) => {
                let _ = writeln!(
                    out,
                    "  launcher: v{v} — STALE (this binary ships v{HOOK_ENV_VERSION}); \
                     re-run `corecruxctl hooks install` or cost capture keeps failing silently"
                );
            }
            None => {
                let _ = writeln!(
                    out,
                    "  launcher: pre-v{HOOK_ENV_VERSION} or not installed — the old `cost)` branch swallows \
                     every failure; re-run `corecruxctl hooks install`"
                );
            }
        }
        let _ = write!(out, "  state: {}", self.state_path.display());
        out
    }
}

/// Read the cost-capture outcome record and the installed launcher's version.
/// Read-only and fail-soft — a missing or malformed record reports "none", never
/// an error, so a status call is safe on a machine that has never run the hook.
///
/// # Errors
/// Returns an error only when `HOME` is unset (no path can be resolved at all).
pub fn cost_capture() -> Result<CostCapture, DynErr> {
    let state_path = cost_state_path()?;
    let installed_version = std::fs::read_to_string(hooks_dir()?.join("crux-hook-env.sh"))
        .ok()
        .and_then(|s| parse_hook_env_version(&s));
    let record: Option<serde_json::Value> = std::fs::read_to_string(&state_path)
        .ok()
        .and_then(|s| serde_json::from_str(s.trim()).ok());
    let field = |k: &str| {
        record
            .as_ref()
            .and_then(|v| v.get(k))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    Ok(CostCapture {
        result: field("result"),
        at: field("at"),
        reason: field("reason"),
        url: field("url"),
        url_source: field("url_source"),
        installed_version,
        state_path,
    })
}

/// Pull `CRUX_HOOK_ENV_VERSION=<v>` out of an installed launcher script.
fn parse_hook_env_version(script: &str) -> Option<String> {
    script.lines().find_map(|l| {
        l.trim()
            .strip_prefix("CRUX_HOOK_ENV_VERSION=")
            .map(|v| v.trim().trim_matches(&['"', '\''][..]).to_owned())
            .filter(|v| !v.is_empty())
    })
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
    /// The destructive-command guard: a second PreToolUse group on Bash running
    /// `coord check`. Without it the coordination plane sees edits only, which
    /// is how a `git clean` destroyed a live peer's work on 2026-08-06.
    #[test]
    fn hooks_block_wires_coord_check_on_bash_when_python_present() {
        let w = Path::new("/x/crux-hook-env.sh");
        let h = build_hooks_block(w, Path::new(LB), true, true);
        let pre = h.as_object().and_then(|m| m.get("PreToolUse")).expect("PreToolUse");
        let groups = pre.as_array().expect("PreToolUse is an array");
        assert!(
            groups
                .iter()
                .any(|g| g["matcher"] == BASH_MATCHER && g["hooks"].to_string().contains("coord")),
            "PreToolUse must wire `coord check` on {BASH_MATCHER}: {pre}"
        );
        // The edit-scoped group must survive alongside it, not be replaced.
        assert!(
            groups
                .iter()
                .any(|g| g["matcher"] == FILEMOD_MATCHER && g["hooks"].to_string().contains("filemod pre")),
            "the Bash group must be additive to the edit group: {pre}"
        );
        // No Python ⇒ no coord leg at all; the Bash group would be a process
        // spawned on every command for a script that cannot run.
        let no_py = build_hooks_block(w, Path::new(LB), true, false);
        let no_py_pre = no_py.as_object().and_then(|m| m.get("PreToolUse")).expect("PreToolUse");
        assert!(
            !no_py_pre
                .as_array()
                .expect("array")
                .iter()
                .any(|g| g["matcher"] == BASH_MATCHER),
            "without python3 there must be no Bash group: {no_py_pre}"
        );
    }

    /// Gate the hook's own offline assertions in CI. The matcher decides whether
    /// a command is tree-destroying; a false negative is a silently-missed
    /// warning, which is the exact failure the guard exists to close. Skipped
    /// (not failed) where python3 is absent — the banner stack is already inert
    /// there and `hooks_install` handles that case explicitly.
    /// Regression: the guard used to accept a non-executable file named `python3`
    /// on PATH, so it reported "present" and the caller's `Command::new("python3")`
    /// then failed with `PermissionDenied`. Reproduced on CI runner `runner-hel1-4`
    /// on 2026-08-08, where it took down an unrelated PR.
    #[cfg(unix)]
    #[test]
    fn python3_present_requires_the_executable_bit_not_just_a_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tests::tmp();
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let fake = dir.join("python3");
        std::fs::write(&fake, "not really python").expect("write fake");

        // Mode 0644: exists, is a file, cannot be exec'd.
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o644)).expect("chmod 644");
        let only_fake = std::env::join_paths([dir.as_path()]).expect("join_paths");
        let saw_non_executable = std::env::split_paths(&only_fake).any(|d| {
            let p = d.join("python3");
            std::fs::metadata(&p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        });
        assert!(!saw_non_executable, "a 0644 python3 must NOT count as present");

        // Same path, now executable.
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).expect("chmod 755");
        let saw_executable = std::env::split_paths(&only_fake).any(|d| {
            let p = d.join("python3");
            std::fs::metadata(&p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        });
        assert!(saw_executable, "a 0755 python3 must count as present");
    }

    /// A hit via the `~/.local/bin` fallback must come back as its full path.
    /// It reported only "present" before, and the caller then exec'd the bare
    /// name — which searches PATH, where this interpreter is *not*. That is the
    /// `run python3: NotFound` that failed Coverage on the runner whose
    /// `$HOME/.local/bin` is off PATH (PR #682, 2026-08-09).
    #[cfg(unix)]
    #[test]
    fn resolve_python3_returns_the_fallback_path_not_just_presence() {
        use std::os::unix::fs::PermissionsExt;
        let home = tests::tmp();
        let bin = home.join(".local/bin");
        std::fs::create_dir_all(&bin).expect("bin dir");
        let py = bin.join("python3");
        std::fs::write(&py, "#!/bin/sh\n").expect("write python3");
        std::fs::set_permissions(&py, std::fs::Permissions::from_mode(0o755)).expect("chmod 755");

        // An empty PATH cannot resolve `python3`; only the HOME leg can.
        let empty = std::env::join_paths([tests::tmp().join("no-python-here")]).expect("join_paths");
        let found = resolve_python3(Some(empty.as_os_str()), Some(home.as_os_str()));
        assert_eq!(
            found.as_deref(),
            Some(py.as_path()),
            "the fallback interpreter must resolve to its full path, since a bare `python3` would not find it"
        );

        // And with neither leg satisfiable, it stays absent rather than handing
        // back a name the caller would fail to exec.
        assert_eq!(
            resolve_python3(Some(empty.as_os_str()), Some(tests::tmp().join("empty-home").as_os_str())),
            None
        );
    }

    /// PATH wins when both legs resolve: that is the interpreter a bare-name
    /// exec would have picked, so preferring it keeps behaviour unchanged where
    /// the old bool was already correct.
    #[cfg(unix)]
    #[test]
    fn resolve_python3_prefers_path_over_the_home_fallback() {
        use std::os::unix::fs::PermissionsExt;
        let home = tests::tmp();
        let home_bin = home.join(".local/bin");
        std::fs::create_dir_all(&home_bin).expect("home bin");
        let home_py = home_bin.join("python3");
        std::fs::write(&home_py, "#!/bin/sh\n").expect("write home python3");
        std::fs::set_permissions(&home_py, std::fs::Permissions::from_mode(0o755)).expect("chmod 755");

        let path_dir = tests::tmp();
        std::fs::create_dir_all(&path_dir).expect("path dir");
        let path_py = path_dir.join("python3");
        std::fs::write(&path_py, "#!/bin/sh\n").expect("write path python3");
        std::fs::set_permissions(&path_py, std::fs::Permissions::from_mode(0o755)).expect("chmod 755");

        let path_var = std::env::join_paths([path_dir.as_path()]).expect("join_paths");
        assert_eq!(
            resolve_python3(Some(path_var.as_os_str()), Some(home.as_os_str())).as_deref(),
            Some(path_py.as_path())
        );
    }

    #[test]
    fn coord_hook_selftest_passes() {
        // Exec the *resolved* interpreter: a `~/.local/bin/python3` that is not
        // on PATH is "present" but not reachable by bare name, which is how this
        // test failed on the coverage runner (`run python3: NotFound`).
        let Some(python3) = python3_path() else {
            eprintln!("python3 absent — skipping coord selftest");
            return;
        };
        let dir = tests::tmp();
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let script = dir.join("crux-coord.py");
        std::fs::write(&script, COORD_PY).expect("write hook");
        let out = std::process::Command::new(&python3)
            .arg(&script)
            .arg("selftest")
            .output()
            .expect("run python3");
        assert!(
            out.status.success(),
            "coord selftest failed:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }

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
        let fake_python = fakebin.join("python3");
        std::fs::write(&fake_python, "#!/bin/sh\n").unwrap();
        // Must be EXECUTABLE to stand in for a real python3. `fs::write` creates
        // 0644, and this fixture previously relied on `python3_present()` accepting
        // a non-executable file — the same bug that broke CI on runner-hel1-4.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake_python, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
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

    #[test]
    fn hook_env_version_marker_matches_the_shipped_constant() {
        // The launcher stamps this into every outcome record, and `hooks status`
        // compares it against the on-disk script to name a stale install. If the
        // two drift, a stale launcher reports itself as current.
        assert!(
            WRAPPER_SH.contains(&format!("CRUX_HOOK_ENV_VERSION={HOOK_ENV_VERSION}")),
            "WRAPPER_SH must declare CRUX_HOOK_ENV_VERSION={HOOK_ENV_VERSION}"
        );
        assert_eq!(parse_hook_env_version(WRAPPER_SH).as_deref(), Some(HOOK_ENV_VERSION));
    }

    #[test]
    fn hook_env_version_parses_quoted_and_missing() {
        assert_eq!(
            parse_hook_env_version("CRUX_HOOK_ENV_VERSION=\"7\"\n").as_deref(),
            Some("7")
        );
        assert_eq!(
            parse_hook_env_version("CRUX_HOOK_ENV_VERSION='9'\n").as_deref(),
            Some("9")
        );
        // The pre-fix launcher carried no marker at all — that is what "stale".
        assert_eq!(parse_hook_env_version("set -a\nexec crux-hook\n"), None);
        assert_eq!(parse_hook_env_version("CRUX_HOOK_ENV_VERSION=\n"), None);
    }

    #[test]
    #[serial_test::serial]
    fn cost_capture_reports_no_record_and_a_stale_launcher() {
        let home = tmp();
        std::env::set_var("HOME", &home);
        // Nothing installed: no record, no launcher.
        let c = cost_capture().unwrap();
        assert!(c.result.is_none());
        assert!(!c.launcher_current());
        assert!(c.report().contains("none recorded"));

        // A pre-fix launcher on disk must be named STALE, not silently accepted.
        let dir = home.join(".local/share/crux/hooks");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("crux-hook-env.sh"), "#!/usr/bin/env bash\nexit 0\n").unwrap();
        let c = cost_capture().unwrap();
        assert!(!c.launcher_current());
        assert!(c.report().contains("hooks install"), "must give the remedy");

        // The shipped launcher reads as current.
        std::fs::write(dir.join("crux-hook-env.sh"), WRAPPER_SH).unwrap();
        let c = cost_capture().unwrap();
        assert!(c.launcher_current());
        assert!(c.report().contains("(current)"));
    }

    #[test]
    #[serial_test::serial]
    fn cost_capture_reads_a_recorded_outcome() {
        let home = tmp();
        std::env::set_var("HOME", &home);
        let hooks = home.join(".claude/hooks");
        std::fs::create_dir_all(&hooks).unwrap();
        std::fs::write(
            hooks.join("crux-cost.state.json"),
            r#"{"at":"2026-07-30T10:00:00Z","result":"failed","reason":"post failed (rc=1)","transcript":"","url":"http://127.0.0.1:14800","url_source":"default","hook_version":"2"}"#,
        )
        .unwrap();
        let c = cost_capture().unwrap();
        assert_eq!(c.result.as_deref(), Some("failed"));
        assert_eq!(c.url_source.as_deref(), Some("default"));
        let r = c.report();
        assert!(r.contains("failed at 2026-07-30T10:00:00Z"));
        assert!(r.contains("post failed (rc=1)"));
        assert!(r.contains("(default)"));

        // A truncated / half-written record must degrade to "none", never error.
        std::fs::write(hooks.join("crux-cost.state.json"), "{not json").unwrap();
        assert!(cost_capture().unwrap().result.is_none());
    }
}

/// Shell-level tests for the SessionEnd `cost)` launcher mode.
///
/// This is the branch that failed silently on three paths, and it had **no**
/// coverage of any kind — which is exactly why the defect survived long enough
/// for the cost leg and the observation leg to reach zero empirical overlap.
/// Each test runs the *embedded* `WRAPPER_SH` under `bash` in a tempdir HOME, so
/// it cannot drift from what `hooks install` writes. Every one asserts exit 0:
/// a SessionEnd hook must never block session end, whatever else it records.
#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod cost_hook_shell {
    use super::*;
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    /// Outcome of one launcher run: exit code, the parsed state record, and the
    /// error log (empty when absent).
    struct Run {
        code: i32,
        state: Option<serde_json::Value>,
        log: String,
    }

    impl Run {
        fn field(&self, k: &str) -> String {
            self.state
                .as_ref()
                .and_then(|v| v.get(k))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned()
        }
    }

    /// Materialise the launcher into a tempdir HOME and run `cost` with `payload`
    /// on stdin. `ctl` is the body of a stub `corecruxctl` (None ⇒ do not install
    /// one, i.e. the "absent" path). `url` sets `CRUX_HTTP_URL`; None leaves it
    /// unset, which is the unconfigured-default path.
    fn run_cost(ctl: Option<&str>, url: Option<&str>, payload: &str) -> Run {
        let home = super::tests::tmp();
        let stub = home.join("stubbin");
        std::fs::create_dir_all(&stub).unwrap();
        if let Some(body) = ctl {
            let p = stub.join("corecruxctl");
            std::fs::write(&p, body).unwrap();
            chmod_exec(&p);
        }
        // The launcher reads the payload with jq. Link the ambient one into the
        // stub dir rather than trusting /usr/bin: on a machine that installs jq
        // to ~/.local/bin (this one) the constrained PATH would not find it, and
        // the payload test would quietly degrade into a no-op.
        if let Some(jq) = resolve_on_path("jq") {
            let _ = std::os::unix::fs::symlink(jq, stub.join("jq"));
        }
        let wrapper = home.join("crux-hook-env.sh");
        std::fs::write(&wrapper, WRAPPER_SH).unwrap();
        chmod_exec(&wrapper);

        let path = format!("{}:/usr/bin:/bin", stub.display());
        let mut cmd = Command::new("bash");
        cmd.arg(&wrapper)
            .arg("cost")
            .env("HOME", &home)
            .env("PATH", &path)
            .env_remove("CRUX_HTTP_URL")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(u) = url {
            cmd.env("CRUX_HTTP_URL", u);
        }
        let mut child = cmd.spawn().unwrap();
        if let Some(mut si) = child.stdin.take() {
            let _ = si.write_all(payload.as_bytes());
        }
        let code = child.wait().unwrap().code().unwrap_or(-1);

        let hooks = home.join(".claude/hooks");
        let state = std::fs::read_to_string(hooks.join("crux-cost.state.json"))
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(s.trim()).ok());
        let log = std::fs::read_to_string(hooks.join("crux-cost.errors.log")).unwrap_or_default();
        Run { code, state, log }
    }

    fn chmod_exec(p: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// First `name` on the *ambient* PATH (the test process's, not the
    /// constrained one handed to the launcher).
    fn resolve_on_path(name: &str) -> Option<PathBuf> {
        let paths = std::env::var_os("PATH")?;
        std::env::split_paths(&paths)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
    }

    /// Path 1 of the defect: `corecruxctl` absent or not executable. The old
    /// branch skipped the whole `if` and exited 0 with no trace whatsoever.
    #[test]
    fn missing_corecruxctl_records_never_attempted_and_exits_zero() {
        assert!(
            !Path::new("/usr/bin/corecruxctl").exists() && !Path::new("/bin/corecruxctl").exists(),
            "test needs corecruxctl to be unresolvable on the constrained PATH"
        );
        let r = run_cost(None, Some("http://127.0.0.1:14800"), "{}");
        assert_eq!(r.code, 0, "SessionEnd must never block session end");
        assert_eq!(r.field("result"), "never_attempted");
        assert!(
            r.field("reason").contains("corecruxctl"),
            "reason: {}",
            r.field("reason")
        );
        assert!(r.log.contains("never_attempted"), "failures must also hit the log");
    }

    /// Path 2: no endpoint was ever configured, so the post goes to the built-in
    /// loopback default and fails. The record must name *that*, not a bare
    /// connection error the operator cannot place.
    #[test]
    fn unconfigured_endpoint_records_failed_with_the_setup_remedy() {
        let r = run_cost(Some("#!/bin/sh\nexit 7\n"), None, "{}");
        assert_eq!(r.code, 0);
        assert_eq!(r.field("result"), "failed");
        assert_eq!(r.field("url_source"), "default");
        assert_eq!(r.field("url"), "http://127.0.0.1:14800");
        let reason = r.field("reason");
        assert!(reason.contains("unconfigured default"), "reason: {reason}");
        assert!(reason.contains("rc=7"), "reason must carry the exit code: {reason}");
    }

    /// Path 3: a configured endpoint, post rejected (expired token, daemon down,
    /// parse error). The CLI's stderr must survive into the reason.
    #[test]
    fn post_failure_records_the_reason_and_exits_zero() {
        let ctl = "#!/bin/sh\necho 'cost report post failed (HTTP 401)' >&2\nexit 1\n";
        let r = run_cost(Some(ctl), Some("http://crux.example:14800"), "{}");
        assert_eq!(r.code, 0);
        assert_eq!(r.field("result"), "failed");
        assert_eq!(r.field("url_source"), "config");
        assert!(r.field("reason").contains("HTTP 401"), "reason: {}", r.field("reason"));
        assert!(r.log.contains("HTTP 401"));
    }

    /// The success path stays quiet: a record, and nothing in the error log.
    #[test]
    fn successful_post_records_ok_and_writes_no_error_log() {
        let r = run_cost(Some("#!/bin/sh\nexit 0\n"), Some("http://crux.example:14800"), "{}");
        assert_eq!(r.code, 0);
        assert_eq!(r.field("result"), "ok");
        assert_eq!(r.field("reason"), "");
        assert_eq!(r.field("hook_version"), HOOK_ENV_VERSION);
        assert!(r.log.is_empty(), "success must not write to the error log");
    }

    /// Stderr is arbitrary text. Quotes, backslashes and newlines in it must not
    /// be able to produce a state file the reader cannot parse — a corrupt record
    /// would put us straight back to "undiagnosable".
    #[test]
    fn hostile_stderr_still_yields_parseable_json() {
        let ctl = "#!/bin/sh\nprintf 'he said \"no\"\\nand \\\\ broke\\n' >&2\nexit 3\n";
        let r = run_cost(Some(ctl), Some("http://crux.example:14800"), "{}");
        assert_eq!(r.code, 0);
        assert!(r.state.is_some(), "state file must still be valid JSON");
        assert_eq!(r.field("result"), "failed");
        let reason = r.field("reason");
        assert!(!reason.contains('\n') && !reason.contains('"') && !reason.contains('\\'));
        assert!(reason.contains("he said"), "reason: {reason}");
    }

    /// The transcript path from the hook payload is passed through to the CLI and
    /// recorded, so an operator can tell *which* session was (not) captured.
    #[test]
    fn payload_transcript_path_is_used_and_recorded() {
        // Only meaningful where jq is present — the launcher degrades to the
        // newest-transcript fallback without it, by design (no new dependency).
        let Some(_) = resolve_on_path("jq") else { return };
        let home = super::tests::tmp();
        let tx = home.join("session.jsonl");
        std::fs::write(&tx, "{}\n").unwrap();
        // Echo the argv the launcher used, so we can assert `--file <tx>`.
        let ctl = "#!/bin/sh\necho \"$@\" >&2\nexit 5\n";
        let payload = format!(r#"{{"transcript_path":"{}"}}"#, tx.display());
        let r = run_cost(Some(ctl), Some("http://crux.example:14800"), &payload);
        assert_eq!(r.code, 0);
        assert_eq!(r.field("transcript"), tx.display().to_string());
        assert!(
            r.field("reason").contains("--file"),
            "launcher must pass --file: {}",
            r.field("reason")
        );
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
