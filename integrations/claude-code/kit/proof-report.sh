#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# proof-report.sh — turn the snapshot/restore log into a human-readable markdown
# report. Shows every capture/restore event and the latest recovered snapshot,
# so you can see the kit actually did something on your machine.
#
# Writes to stdout (redirect to a file). Env: CRUX_COMPACTION_SNAPSHOT_DIR,
# CRUX_COMPACTION_LOG (same defaults as the hooks).
set -uo pipefail
SNAP_DIR="${CRUX_COMPACTION_SNAPSHOT_DIR:-$HOME/.claude/compaction-snapshots}"
LOG="${CRUX_COMPACTION_LOG:-$SNAP_DIR/compaction.log}"

echo "# Compaction Survival — proof report"
echo
echo "_Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) · snapshot dir \`$SNAP_DIR\`_"
echo
echo "## Events"
echo
if [ -s "$LOG" ]; then
  echo "| time (UTC) | event | session | detail |"
  echo "|---|---|---|---|"
  # log lines are tab-separated: <ts>\t<event>\t<session>\t<detail>
  while IFS=$'\t' read -r ts ev sid detail; do
    [ -n "${ts:-}" ] || continue
    echo "| $ts | $ev | \`$sid\` | ${detail:-} |"
  done < "$LOG"
  snaps="$(printf '%s' "$(grep -c $'\tsnapshot\t' "$LOG" 2>/dev/null || echo 0)")"
  restores="$(printf '%s' "$(grep -c $'\trestore\t' "$LOG" 2>/dev/null || echo 0)")"
  echo
  echo "**$snaps** snapshots captured · **$restores** restores served."
else
  echo "_No events logged yet. Run \`hooks/proof.sh\`, or trigger a real compaction, then re-run._"
fi

echo
echo "## Latest recovered snapshot"
echo
latest="$(ls -t "$SNAP_DIR"/*.md 2>/dev/null | head -1)"
if [ -n "$latest" ] && [ -f "$latest" ]; then
  echo "_from \`$latest\`_"
  echo
  cat "$latest"
else
  echo "_none on disk yet_"
fi
