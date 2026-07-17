#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# Compaction Survival Kit — one-command installer.
# Installs the FREE compaction-survival preset (also source-available in the
# Crux repo, integrations/claude-code/compaction-survival/) and wires tested
# Claude Code AND Codex hook configs. Idempotent — safe to re-run.
#
# Env overrides:
#   CRUX_COMPACTION_INSTALL_DIR (default ~/.local/share/crux-compaction)
#   CLAUDE_SETTINGS             (default ~/.claude/settings.json)
#   CODEX_HOOKS                 (default ~/.codex/hooks.json)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
INSTALL_DIR="${CRUX_COMPACTION_INSTALL_DIR:-$HOME/.local/share/crux-compaction}"
CLAUDE_SETTINGS="${CLAUDE_SETTINGS:-$HOME/.claude/settings.json}"
CODEX_HOOKS="${CODEX_HOOKS:-$HOME/.codex/hooks.json}"

command -v jq >/dev/null 2>&1 || { echo "error: jq is required (https://jqlang.github.io/jq/)." >&2; exit 1; }

# 1) install the hook scripts
mkdir -p "$INSTALL_DIR"
cp "$here/hooks/snapshot.sh" "$here/hooks/restore.sh" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/snapshot.sh" "$INSTALL_DIR/restore.sh"
snap_cmd="$INSTALL_DIR/snapshot.sh"
restore_cmd="$INSTALL_DIR/restore.sh"
echo "installed hooks         -> $INSTALL_DIR"

# jq program: append a hook group for (event, command) only if absent (idempotent).
read -r -d '' CLAUDE_JQ <<'JQ' || true
def ensure(ev; cmd):
  (.hooks[ev] // []) as $a
  | if ($a | any(.hooks[]?.command == cmd)) then .
    else .hooks[ev] = ($a + [{"matcher":"", "hooks":[{"type":"command","command":cmd}]}]) end;
ensure("PreCompact"; $sc) | ensure("SessionStart"; $rc)
JQ

read -r -d '' CODEX_JQ <<'JQ' || true
def ensure(ev; cmd):
  (.hooks[ev] // []) as $a
  | if ($a | any(.hooks[]?.command == cmd)) then .
    else .hooks[ev] = ($a + [{"hooks":[{"type":"command","command":cmd,"async":false,"timeout":8}]}]) end;
ensure("SessionStart"; $rc) | ensure("UserPromptSubmit"; $sc)
JQ

wire() { # <settings-file> <jq-program>
  local f="$1" prog="$2" base='{}'
  mkdir -p "$(dirname "$f")"
  [ -f "$f" ] && base="$(cat "$f")"
  printf '%s' "$base" | jq --arg sc "$snap_cmd" --arg rc "$restore_cmd" "$prog" > "$f.tmp"
  jq empty "$f.tmp"                    # fail loudly rather than write invalid JSON
  mv "$f.tmp" "$f"
}

# 2) Claude Code: snapshot on PreCompact, restore on SessionStart.
wire "$CLAUDE_SETTINGS" "$CLAUDE_JQ"
echo "wired Claude Code       -> $CLAUDE_SETTINGS"

# 3) Codex: restore on SessionStart + best-effort snapshot on UserPromptSubmit.
#    Codex has no PreCompact event, so full pre-compaction capture is Claude Code
#    only; this keeps a rolling snapshot and restores it on resume. (See COMPARISON.md.)
wire "$CODEX_HOOKS" "$CODEX_JQ"
echo "wired Codex             -> $CODEX_HOOKS"

cat <<EOF

Done. Restart Claude Code (and/or Codex).

  Verify the capability:  bash "$here/hooks/proof.sh"
  Human-readable report:  bash "$here/proof-report.sh"

The compaction-survival capability is FREE and source-available in the Crux
repo (integrations/claude-code/compaction-survival/). This kit packages the
tested installer, the dual-agent (Claude Code + Codex) configs, the proof-report
generator, and the comparison doc — it does not gate the capability.
EOF
