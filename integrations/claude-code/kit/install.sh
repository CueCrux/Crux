#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd.
# Licensed under the Apache License, Version 2.0.
#
# Compaction Survival Kit — one-command installer.
# Installs the FREE compaction-survival preset (also open source in the
# Crux repo, integrations/claude-code/compaction-survival/) and wires the same
# PreCompact + SessionStart hooks for BOTH Claude Code and OpenAI Codex — both
# now expose that contract. Idempotent; safe to re-run.
#
# Security: umask 077; refuses to modify a symlinked settings file; writes via a
# same-dir temp + atomic rename at 0600; single-quotes the hook path so spaces /
# metacharacters in it stay literal.
#
# Env overrides: CRUX_COMPACTION_INSTALL_DIR (~/.local/share/crux-compaction),
#   CLAUDE_SETTINGS (~/.claude/settings.json), CODEX_HOOKS (~/.codex/hooks.json).
set -euo pipefail
umask 077
here="$(cd "$(dirname "$0")" && pwd)"
HOME_DIR="${HOME:-/tmp}"
INSTALL_DIR="${CRUX_COMPACTION_INSTALL_DIR:-$HOME_DIR/.local/share/crux-compaction}"
CLAUDE_SETTINGS="${CLAUDE_SETTINGS:-$HOME_DIR/.claude/settings.json}"
CODEX_HOOKS="${CODEX_HOOKS:-$HOME_DIR/.codex/hooks.json}"

command -v jq >/dev/null 2>&1 || { echo "error: jq is required (https://jqlang.github.io/jq/)." >&2; exit 1; }

# 1) install the hook scripts
mkdir -p "$INSTALL_DIR"
cp "$here/hooks/snapshot.sh" "$here/hooks/restore.sh" "$INSTALL_DIR/"
chmod 0755 "$INSTALL_DIR/snapshot.sh" "$INSTALL_DIR/restore.sh"
snap_path="$INSTALL_DIR/snapshot.sh"
restore_path="$INSTALL_DIR/restore.sh"
case "$snap_path$restore_path" in *[$'\n\r']*) echo "error: install path contains control characters." >&2; exit 1 ;; esac
echo "installed hooks         -> $INSTALL_DIR"

# POSIX single-quote a path so the stored shell-form command is space/metachar safe.
sq(){ printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }
snap_cmd="$(sq "$snap_path")"
restore_cmd="$(sq "$restore_path")"

# Append a hook group for (event, command) only if that exact command is absent.
JQ_PROG='
def ensure(ev; cmd):
  (.hooks[ev] // []) as $a
  | if ($a | any(.hooks[]?.command == cmd)) then .
    else .hooks[ev] = ($a + [{"matcher":"", "hooks":[{"type":"command","command":cmd,"timeout":10}]}]) end;
ensure("PreCompact"; $sc) | ensure("SessionStart"; $rc)'

wire(){ # <settings-file>
  local f="$1" dir base tmp
  dir="$(dirname "$f")"; mkdir -p "$dir"
  [ -L "$f" ] && { echo "error: $f is a symlink; refusing to modify it. Resolve the link and re-run." >&2; exit 1; }
  base='{}'; [ -f "$f" ] && base="$(cat "$f")"
  tmp="$(mktemp "$dir/.cfg.XXXXXX")" || { echo "error: mktemp failed in $dir" >&2; exit 1; }
  if printf '%s' "$base" | jq --arg sc "$snap_cmd" --arg rc "$restore_cmd" "$JQ_PROG" > "$tmp" && jq empty "$tmp"; then
    chmod 0600 "$tmp"; mv -f "$tmp" "$f"
  else
    rm -f "$tmp"; echo "error: failed to update $f (is the existing file valid JSON?)." >&2; exit 1
  fi
}

# 2) wire Claude Code, 3) wire Codex — same PreCompact + SessionStart hooks.
wire "$CLAUDE_SETTINGS"; echo "wired Claude Code       -> $CLAUDE_SETTINGS"
wire "$CODEX_HOOKS";     echo "wired Codex             -> $CODEX_HOOKS"

cat <<EOF

Done. Restart Claude Code (and/or Codex).

  Self-test the hooks:  bash "$here/hooks/selftest.sh"
  Local event report:   bash "$here/event-report.sh"

The compaction-survival capability is free and open source in the Crux
repo (integrations/claude-code/compaction-survival/) under the Apache License,
Version 2.0; the standalone proof-of-loss mini-repo is MIT-licensed. This kit
packages the tested installer, the dual-agent configs, the event report, and
the comparison doc — it does not gate the capability.

Note: Codex uses the same PreCompact/SessionStart hooks, but Codex's transcript
format is not a stable interface, so snapshot *capture* on Codex is best-effort;
restore always works. See COMPARISON.md.
EOF
