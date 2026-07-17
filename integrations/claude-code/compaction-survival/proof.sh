#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# proof.sh — assert-based proof harness for the compaction-survival preset.
# Demonstrates, against a fixture transcript, the loss-without vs survival-with
# difference:
#   [1] WITHOUT a snapshot, a post-compact SessionStart restores nothing (loss).
#   [2] The PreCompact hook captures todos + files + notes.
#   [3] WITH the snapshot, the post-compact SessionStart re-injects it (survival).
#   [4] A foreign (non-Claude-Code) payload still snapshots safely, never errors.
# Exits non-zero on any failed assertion.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
export CRUX_COMPACTION_SNAPSHOT_DIR="$tmp/snaps"
export CRUX_COMPACTION_LOG="$tmp/snaps/compaction.log"

SID="proof-session-1"
TRANSCRIPT="$here/fixtures/transcript.jsonl"
fail(){ echo "FAIL: $1" >&2; exit 1; }
ok(){ echo "  ok: $1"; }

# Invoke via `bash` so the harness works even when the exec bit was stripped
# (e.g. scripts extracted from a delivery zip). The installed runtime copies are
# chmod +x by install.sh, so Claude Code runs them directly regardless.
echo "[1] loss WITHOUT snapshot — post-compact restore against an empty store"
out_loss="$(printf '{"session_id":"%s","cwd":"/repo","hook_event_name":"SessionStart","source":"compact"}' "$SID" | bash "$here/restore.sh")"
[ -z "$out_loss" ] || fail "expected empty restore output, got: $out_loss"
ok "restore emitted nothing — the plan/todos/files are simply gone (the pain)"

echo "[2] PreCompact snapshot captures the working state"
printf '{"session_id":"%s","transcript_path":"%s","cwd":"/repo","hook_event_name":"PreCompact","trigger":"auto","custom_instructions":""}' "$SID" "$TRANSCRIPT" | bash "$here/snapshot.sh"
snap="$CRUX_COMPACTION_SNAPSHOT_DIR/$SID.md"
[ -f "$snap" ] || fail "snapshot file not created"
grep -q "fix the auth token refresh" "$snap" || fail "todo not captured"
grep -q "auth.ts"  "$snap" || fail "in-play file auth.ts not captured"
grep -q "billing.ts" "$snap" || fail "do-not-touch note (billing.ts) not captured"
ok "snapshot has open todos + files-in-play + latest notes"

echo "[3] survival WITH snapshot — post-compact restore re-injects it"
out_win="$(printf '{"session_id":"%s","cwd":"/repo","hook_event_name":"SessionStart","source":"compact"}' "$SID" | bash "$here/restore.sh")"
echo "$out_win" | jq -e '.hookSpecificOutput.hookEventName=="SessionStart"' >/dev/null 2>&1 || fail "not a valid SessionStart output object"
ctx="$(echo "$out_win" | jq -r '.hookSpecificOutput.additionalContext')"
printf '%s' "$ctx" | grep -q "fix the auth token refresh" || fail "restored context missing the todo"
printf '%s' "$ctx" | grep -q "do NOT touch billing.ts"     || fail "restored context missing the guard note"
ok "restore re-injected the exact working state as additionalContext"

echo "[4] foreign payload (no CC transcript, e.g. Codex) still snapshots, never errors"
printf '{"session_id":"codex-1","cwd":"/y","hook_event_name":"PreCompact"}' | bash "$here/snapshot.sh"
[ -f "$CRUX_COMPACTION_SNAPSHOT_DIR/codex-1.md" ] || fail "foreign-payload snapshot not created"
ok "degraded-but-safe on non-Claude-Code payloads"

echo
echo "PROOF PASSED — without the hook, compaction erases the plan; with it, the plan survives."
