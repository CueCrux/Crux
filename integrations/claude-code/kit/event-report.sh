#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# event-report.sh — render the local capture/restore event log to markdown.
# This is a LOCAL event report from an unsigned log, not a signed/verifiable
# record of what happened. Metadata only by default (timestamps + counts). Pass
# --include-sensitive-snapshot to also dump the latest snapshot BODY, which can
# contain sensitive transcript excerpts — keep that output private.
#
# Env: CRUX_COMPACTION_SNAPSHOT_DIR, CRUX_COMPACTION_LOG (same as the hooks).
set -uo pipefail
HOME_DIR="${HOME:-/tmp}"
SNAP_DIR="${CRUX_COMPACTION_SNAPSHOT_DIR:-$HOME_DIR/.claude/compaction-snapshots}"
LOG="${CRUX_COMPACTION_LOG:-$SNAP_DIR/compaction.log}"
INCLUDE=0; [ "${1:-}" = "--include-sensitive-snapshot" ] && INCLUDE=1

echo "# Compaction Survival — local event report"
echo
echo "_Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) · snapshot dir \`$SNAP_DIR\` (snapshot files are mode 0600)_"
echo
echo "## Events"
echo
if [ -s "$LOG" ]; then
  echo "| time (UTC) | event | session | detail |"
  echo "|---|---|---|---|"
  while IFS=$'\t' read -r ts ev sid detail; do
    [ -n "${ts:-}" ] || continue
    echo "| $ts | $ev | \`$sid\` | ${detail:-} |"
  done < "$LOG"
  echo
  echo "**$(grep -c $'\tsnapshot\t' "$LOG" 2>/dev/null || echo 0)** snapshots captured · **$(grep -c $'\trestore\t' "$LOG" 2>/dev/null || echo 0)** restores served."
else
  echo "_No events logged yet. Run \`hooks/selftest.sh\`, or trigger a real compaction, then re-run._"
fi
echo
if [ "$INCLUDE" = 1 ]; then
  echo "## Latest snapshot body (sensitive — keep private)"
  echo
  latest="$(ls -t "$SNAP_DIR"/*.md 2>/dev/null | head -1)"
  if [ -n "$latest" ] && [ -f "$latest" ]; then echo "_from \`$latest\`_"; echo; cat "$latest"; else echo "_none on disk_"; fi
else
  echo "_Snapshot bodies omitted: they can contain sensitive transcript excerpts. Re-run with \`--include-sensitive-snapshot\` to include the latest, and don't paste it where others can read it. Snapshots auto-prune after CRUX_COMPACTION_RETENTION_DAYS days (default 14); delete now with \`rm -f \"$SNAP_DIR\"/*.md\`._"
fi
