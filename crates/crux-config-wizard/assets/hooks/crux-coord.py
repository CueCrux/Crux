#!/usr/bin/env python3
"""crux-coord — make a Claude Code session visible on the Crux coordination board.

Why this exists
---------------
The coordination plane (GET /v1/coord/active, POST /v1/coord/announce) works, but
presence is opt-in and nothing was opting in: 13 concurrent sessions, an empty
board, and four commits landing under a session that believed it was alone.

Two things were not obvious and are encoded here so nobody has to rediscover them:

1. `coord_announce` needs the *bound CueCrux session id* returned by the
   `cuecrux_session` MCP call — NOT the Claude Code session UUID. Announcing with
   the Claude UUID records an intent that never joins presence, so the board stays
   empty and the announce looks like it worked. This is the whole bug.

2. The coord_* MCP tools are tier-gated and are not advertised to a free/local
   agent token, so an agent cannot announce over MCP. The HTTP routes accept the
   same CRUX_AGENT_TOKEN. We therefore bind over MCP and announce over HTTP.

3. Announcing intent only covers half the risk. A peer declaring "I am editing
   this tree" says nothing about the session that is about to `git clean` it.
   On 2026-08-06 one session cleaned a shared checkout and deleted another's
   uncommitted artefact; both were live, neither was warned, because the
   coordination plane only ever saw *edits*. `check` therefore also inspects
   Bash commands for tree-destroying git verbs — see `destructive_target`.

Verbs
-----
  announce   bind (once, cached) then declare focus for this session + cwd
  check      warn when a peer session has claimed what we are about to touch —
             the file for an Edit/Write, or the tree for a destructive Bash git
  clear      zero-TTL announce, releasing this session's intent
  selftest   run the offline assertions for `destructive_target` (no daemon, no
             network); exits non-zero on a miss so CI can gate the matcher

Everything is advisory and fail-open: a coord outage must never block an edit.
Reads the hook payload on stdin (Claude Code passes session_id / cwd / tool_input).
"""
import json
import os
import re
import socket
import sys
import urllib.error
import urllib.request

HTTP = os.environ.get("CRUX_HTTP_URL", "http://100.70.12.73:14800").rstrip("/")
MCP = os.environ.get("CRUX_MCP_URL", "http://100.70.12.73:14801/mcp")
TOKEN = os.environ.get("CRUX_AGENT_TOKEN", "")
PROJECT = os.environ.get("CRUX_COORD_PROJECT", "crux")
TTL = int(os.environ.get("CRUX_COORD_TTL_SECS", "900"))
CACHE = os.path.expanduser("~/.cache/crux-coord")
TIMEOUT = 4  # a hook must not stall the session; coord is advisory


def _post(url, payload, headers):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def _auth():
    return {"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}


def bound_session_id(claude_sid):
    """The cuecrux_session id for this Claude session, minted once and cached.

    Cached because cuecrux_session mints a new id per call; re-minting every hook
    would scatter one agent across many phantom presence rows.
    """
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, f"{claude_sid or 'unknown'}.id")
    if os.path.exists(path):
        cached = open(path).read().strip()
        if cached:
            return cached
    body = _post(MCP, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "cuecrux_session", "arguments": {"intent": "claude_code"}}},
                 {**_auth(), "Accept": "application/json, text/event-stream"})
    sid = _extract_session_id(body)
    if sid:
        with open(path, "w") as fh:
            fh.write(sid)
    return sid


def _extract_session_id(body):
    """cuecrux_session's id, wherever the MCP envelope put it."""
    result = (body or {}).get("result") or {}
    if isinstance(result.get("structuredContent"), dict):
        sid = result["structuredContent"].get("session_id")
        if sid:
            return sid
    for item in result.get("content") or []:
        try:
            return json.loads(item.get("text", "")).get("session_id")
        except (ValueError, AttributeError):
            continue
    return None


def announce(hook, clear=False):
    sid = bound_session_id(hook.get("session_id"))
    if not sid:
        return  # unbound: stay silent rather than write a presence row we cannot join
    cwd = hook.get("cwd") or os.getcwd()
    _post(f"{HTTP}/v1/coord/announce", {
        "session_id": sid,
        "project_id": PROJECT,
        "paths": [cwd],
        # Paths are machine-local, so a second workstation with the same checkout
        # path looks like a same-tree collision. Stamp the host so the operator can
        # tell "the other PC has this repo open" from "another session on THIS box
        # is editing the file I am about to write".
        "note": f"claude-code {os.path.basename(cwd)} @{socket.gethostname()}",
        "ttl_seconds": 0 if clear else TTL,
    }, _auth())


# Git verbs that discard uncommitted or untracked work in a tree. `stash` is
# here because `git stash -u` removes untracked files exactly as `clean` does;
# `stash list`/`show` are read-only and excluded. `worktree remove` is included
# because the worktree reaper runs it against trees other sessions may be in.
#
# Deliberately git-only. `rm -rf` is more destructive still, but its target is
# not reliably recoverable from the command line (globs, several args, relative
# paths), and warning on the session cwd instead would fire on every `rm -rf`
# of an unrelated temp dir. A guard that cries wolf gets switched off.
_DESTRUCTIVE_GIT = re.compile(
    r"\bgit\b(?:\s+-C\s+(?P<dir>\S+))?[^|;&]*?\s"
    r"(?:clean\b|reset\s+--hard\b|checkout\s+(?:-f|--force)\b"
    r"|stash(?!\s+(?:list|show))\b|worktree\s+remove\b)"
)


def destructive_target(command, cwd):
    """The tree a destructive git command would act on, or None if it is benign.

    `git -C <dir>` retargets the command, so the tree at risk is <dir>, not the
    session cwd — missing that would warn about the wrong repo, or stay silent
    on the right one. Returns an absolute path so it compares against the
    absolute paths peers announce.
    """
    if not command:
        return None
    m = _DESTRUCTIVE_GIT.search(command)
    if not m:
        return None
    d = m.group("dir")
    if not d:
        return cwd or None
    return d if os.path.isabs(d) else os.path.normpath(os.path.join(cwd or "", d))


def _under(child, parent):
    parent = parent.rstrip("/")
    return child == parent or child.startswith(parent + "/")


def _overlaps(target, claimed, destructive):
    """Does `target` collide with a peer's `claimed` path?

    For an edit, only one direction matters: the file is inside the claimed
    tree. For a destructive command the target is itself a *tree*, so the
    reverse also counts — `git clean` at a repo root wipes every announced path
    beneath it, and that is the more damaging direction, not the less.
    """
    if _under(target, claimed):
        return True
    return destructive and _under(claimed, target)


def check(hook):
    """Warn when a peer has claimed what this tool call is about to touch.

    Two shapes: an Edit/Write names a `file_path`; a Bash call names a
    `command`, which matters only when it would destroy a tree.
    """
    tool_input = hook.get("tool_input") or {}
    target = tool_input.get("file_path") or ""
    destructive = False
    if not target:
        target = destructive_target(tool_input.get("command") or "", hook.get("cwd") or os.getcwd()) or ""
        destructive = bool(target)
    if not target:
        return
    mine = None
    idfile = os.path.join(CACHE, f"{hook.get('session_id') or 'unknown'}.id")
    if os.path.exists(idfile):
        mine = open(idfile).read().strip()
    req = urllib.request.Request(f"{HTTP}/v1/coord/active", headers=_auth())
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        data = json.loads(r.read().decode("utf-8", errors="replace"))
    hits = []
    for s in data.get("active_sessions") or []:
        if s.get("session_id_hex") == mine:
            continue
        for p in ((s.get("intent") or {}).get("paths") or []):
            if p and _overlaps(target, p, destructive):
                intent = s.get("intent") or {}
                slug = intent.get("execplan_slug") or "no plan"
                # Surface the host: matching is path-based, so a second
                # workstation with an identical checkout path matches too. Same
                # host means a real concurrent write; a different host means the
                # same repo open elsewhere, which conflicts at merge, not on disk.
                note = intent.get("note") or ""
                host = note.rsplit("@", 1)[-1] if "@" in note else "?"
                where = "this host" if host == socket.gethostname() else f"host {host}"
                hits.append(f"{s.get('session_id_hex', '?')[:12]} ({slug}, {where})")
    if hits:
        # stderr, exit 0: advisory. Blocking on a peer's advisory claim would
        # turn a coordination aid into an outage the moment coord is wrong.
        who = ", ".join(sorted(set(hits)))
        if destructive:
            print(f"[crux-coord] DESTRUCTIVE: this command discards uncommitted/untracked work "
                  f"under {target}, claimed by {who}. Uncommitted work there is not recoverable.",
                  file=sys.stderr)
        else:
            print(f"[crux-coord] peer session(s) claim {target}: {who}", file=sys.stderr)


def selftest():
    """Offline assertions for the matcher. No daemon, no network, no stdin.

    `check` itself needs a live coord plane, so the part worth gating in CI is
    the pure decision: does this command destroy a tree, and which one. A false
    negative here is a silently-missed warning — the exact failure this guard
    exists to close.
    """
    cwd = "/w/repo"
    for cmd in [
        "git clean -fd",
        "git reset --hard origin/main",
        "git checkout -f main",
        "git checkout --force main",
        "git stash",
        "git stash -u",
        "git worktree remove /w/repo-worktrees/x",
    ]:
        assert destructive_target(cmd, cwd) == cwd, f"missed destructive: {cmd}"
    for cmd in [
        "git status",
        "git stash list",
        "git stash show",
        "git checkout main",
        "git reset --soft HEAD~1",
        "cargo test --workspace",
        "",
    ]:
        assert destructive_target(cmd, cwd) is None, f"false positive: {cmd}"
    # `-C` retargets the command; warning about the session cwd would name the
    # wrong repo and stay silent on the one actually at risk.
    assert destructive_target("git -C /other/repo clean -fd", cwd) == "/other/repo"
    assert destructive_target("git -C ../sib clean -fd", cwd) == "/w/sib"
    # Overlap is one-directional for an edit, bidirectional for a destroy: a
    # clean at a repo root wipes every announced path beneath it.
    assert _overlaps("/w/repo/src/a.rs", "/w/repo", False)
    assert not _overlaps("/w/repo", "/w/repo/src", False)
    assert _overlaps("/w/repo", "/w/repo/src", True)
    assert not _overlaps("/w/other", "/w/repo", True)
    # A sibling whose name merely starts with the claimed path is not inside it.
    assert not _overlaps("/w/repo-backup/x", "/w/repo", True)
    print("[crux-coord] selftest ok")
    return 0


def main():
    # First, and ahead of the CRUX_COORD gate: selftest is an offline CI entry
    # point, not a hook. Behind the gate, a workstation or runner with
    # CRUX_COORD=0 would exit 0 without asserting anything — a green run that
    # tested nothing, which is worse than a red one.
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        return selftest()
    # `check` runs on every Edit/Write and Bash call, so it must be switchable
    # off without editing settings.json — an unhealthy daemon should cost one
    # env var, not a hook-config edit on every workstation.
    if os.environ.get("CRUX_COORD", "1") == "0":
        return 0
    verb = sys.argv[1] if len(sys.argv) > 1 else "announce"
    try:
        raw = sys.stdin.read() if not sys.stdin.isatty() else ""
        hook = json.loads(raw) if raw.strip() else {}
    except (ValueError, OSError):
        hook = {}
    try:
        if verb == "announce":
            announce(hook)
        elif verb == "check":
            check(hook)
        elif verb == "clear":
            announce(hook, clear=True)
    except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
        # Fail open, but say so — a silent failure here is what produced the
        # confident "0 sessions" this script exists to prevent.
        print(f"[crux-coord] {verb} unavailable: {type(e).__name__}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
