#!/usr/bin/env bash
# Copyright (c) 2026 CueCrux Ltd. All rights reserved.
# Licensed under the CueCrux Community Licence (CCL v1.0).
#
# selftest.sh — assert-based fixture self-test for the compaction-survival preset.
# This is a LOCAL self-test against a bundled fixture transcript, NOT a signed
# proof of anything that happened on your machine. It checks the hooks behave:
# loss-without vs survival-with, plus the security guards. Exits non-zero on any
# failed assertion.
#
# Invokes the hooks via `bash` so it works even when the exec bit was stripped
# (e.g. scripts unzipped from a delivery archive); installed runtime copies are
# chmod +x by install.sh, so the agents run them directly.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
export CRUX_COMPACTION_SNAPSHOT_DIR="$tmp/snaps"
export CRUX_COMPACTION_LOG="$tmp/snaps/compaction.log"
SID="selftest-session-1"
TRANSCRIPT="$here/fixtures/transcript.jsonl"
fail(){ echo "FAIL: $1" >&2; exit 1; }
ok(){ echo "  ok: $1"; }

# Build hook payloads with jq (no raw string interpolation into JSON).
pc(){ jq -n --arg s "$SID" --arg t "$TRANSCRIPT" '{session_id:$s,transcript_path:$t,cwd:"/repo",hook_event_name:"PreCompact",trigger:"auto",custom_instructions:""}'; }
ss(){ jq -n --arg s "$SID" '{session_id:$s,cwd:"/repo",hook_event_name:"SessionStart",source:"compact"}'; }

echo "[1] loss WITHOUT snapshot — post-compact restore against an empty store"
out_loss="$(ss | bash "$here/restore.sh")"
[ -z "$out_loss" ] || fail "expected empty restore output, got: $out_loss"
ok "restore emitted nothing — the plan/todos/files are simply gone (the pain)"

echo "[2] PreCompact snapshot captures the working state"
pc | bash "$here/snapshot.sh"
snap="$CRUX_COMPACTION_SNAPSHOT_DIR/$SID.md"
[ -f "$snap" ] || fail "snapshot file not created"
grep -q "fix the auth token refresh" "$snap" || fail "active todo not captured"
grep -q "add a regression test"       "$snap" || fail "pending todo not captured"
grep -q "auth.ts"                     "$snap" || fail "in-play file auth.ts not captured"
grep -q "do NOT touch billing.ts"     "$snap" || fail "guard note not captured"
grep -q "read the auth module"        "$snap" && fail "completed todo should be filtered out"
ok "snapshot has active (not completed) todos + files-in-play + latest activity"

echo "[2b] snapshot file is private (0600)"
perm="$(stat -c '%a' "$snap" 2>/dev/null || stat -f '%Lp' "$snap" 2>/dev/null)"
[ "$perm" = "600" ] || fail "snapshot perms are $perm, expected 600"
ok "snapshot is mode 600"

echo "[3] survival WITH snapshot — post-compact restore re-injects it (as quoted data)"
out_win="$(ss | bash "$here/restore.sh")"
echo "$out_win" | jq -e '.hookSpecificOutput.hookEventName=="SessionStart"' >/dev/null 2>&1 || fail "not a valid SessionStart output object"
ctx="$(echo "$out_win" | jq -r '.hookSpecificOutput.additionalContext')"
printf '%s' "$ctx" | grep -q "pre-compaction-snapshot" || fail "restored context not fenced as untrusted quoted data"
printf '%s' "$ctx" | grep -q "fix the auth token refresh" || fail "restored context missing the todo"
printf '%s' "$ctx" | grep -q "do NOT touch billing.ts"     || fail "restored context missing the guard note"
ok "restore re-injected the working state, fenced as quoted historical data"

echo "[4] path-traversal session_id is rejected"
jq -n --arg t "$TRANSCRIPT" '{session_id:"../evil",transcript_path:$t,cwd:"/x",hook_event_name:"PreCompact",trigger:"auto"}' | bash "$here/snapshot.sh"
[ ! -e "$tmp/evil.md" ] || fail "path traversal not blocked (wrote outside snapshot dir)"
ok "malicious session_id rejected, no file escaped the snapshot dir"

echo "[5] empty capture does not clobber a good snapshot"
prev="$(cat "$snap")"
jq -n --arg s "$SID" '{session_id:$s,cwd:"/repo",hook_event_name:"PreCompact"}' | bash "$here/snapshot.sh"   # no transcript => empty capture
[ "$(cat "$snap")" = "$prev" ] || fail "good snapshot was clobbered by an empty capture"
ok "non-empty snapshot preserved against empty re-capture"

echo "[6] wrong event name is ignored (no snapshot, no restore output)"
jq -n '{session_id:"other",hook_event_name:"PreToolUse"}' | bash "$here/snapshot.sh"
[ ! -e "$CRUX_COMPACTION_SNAPSHOT_DIR/other.md" ] || fail "snapshot written for a non-PreCompact event"
out_wrong="$(jq -n --arg s "$SID" '{session_id:$s,hook_event_name:"UserPromptSubmit",source:"compact"}' | bash "$here/restore.sh")"
[ -z "$out_wrong" ] || fail "restore emitted for a non-SessionStart event"
ok "non-matching events ignored"

echo
echo "SELF-TEST PASSED — without the hook, compaction erases the plan; with it, the plan survives."
