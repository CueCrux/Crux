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

Verbs
-----
  announce   bind (once, cached) then declare focus for this session + cwd
  check      warn when a peer session has declared the path we are about to edit
  clear      zero-TTL announce, releasing this session's intent

Everything is advisory and fail-open: a coord outage must never block an edit.
Reads the hook payload on stdin (Claude Code passes session_id / cwd / tool_input).
"""
import json
import os
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


def check(hook):
    """Warn when a peer has declared the path this Edit/Write is about to touch."""
    target = (hook.get("tool_input") or {}).get("file_path") or ""
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
            if p and (target.startswith(p.rstrip("/") + "/") or target == p):
                slug = (s.get("intent") or {}).get("execplan_slug") or "no plan"
                hits.append(f"{s.get('session_id_hex', '?')[:12]} ({slug})")
    if hits:
        # stderr, exit 0: advisory. Blocking on a peer's advisory claim would
        # turn a coordination aid into an outage the moment coord is wrong.
        print(f"[crux-coord] peer session(s) claim {target}: {', '.join(sorted(set(hits)))}",
              file=sys.stderr)


def main():
    # `check` runs on every Edit/Write, so it must be switchable off without
    # editing settings.json — an unhealthy daemon should cost one env var, not a
    # hook-config edit on every workstation.
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
