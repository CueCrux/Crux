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

2. Binding, announcing, and reading status use the MCP tools over one
   authenticated transport. Native MCP calls preserve the exact registered
   agent bearer and pair it with a process-local loopback proof; the credential
   is never exposed to the tool payload.

Verbs
-----
  announce   bind (once, cached) then declare focus for this session + cwd
  check      warn when a peer session has declared the path we are about to edit
  clear      zero-TTL announce, releasing this session's intent

Everything is advisory and fail-open: a coord outage must never block an edit.
Reads the hook payload on stdin (Claude Code passes session_id / cwd / tool_input).
"""
import hashlib
import json
import os
import socket
import sys
import urllib.error
import urllib.request

HOME = os.path.expanduser("~")
ENV_FILE = os.path.join(HOME, ".config/cuecrux/env")
MCP_TOKEN_FILE = os.path.join(HOME, ".config/cuecrux/crux-tokens/anthropic.mcp-token")


def _load_env_file():
    """Read simple KEY=VALUE settings without evaluating shell syntax."""
    values = {}
    try:
        with open(ENV_FILE) as source:
            for line in source:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                if key.startswith("export "):
                    key = key[7:].strip()
                if key:
                    values[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass
    return values


def _read_registered_mcp_token():
    try:
        with open(MCP_TOKEN_FILE) as source:
            return source.read().strip()
    except OSError:
        return ""


_FILE_ENV = _load_env_file()


def _setting(name, default=""):
    return os.environ.get(name) or _FILE_ENV.get(name) or default


MCP = _setting("CRUX_MCP_URL", "http://127.0.0.1:14801/mcp")
# The MCP listener accepts its registered agent token, while the inherited
# CRUX_AGENT_TOKEN may be the daemon HTTP JWT. Prefer the exact MCP credential.
TOKEN = _read_registered_mcp_token() or _setting("CRUX_AGENT_TOKEN")
PROJECT = _setting("CRUX_COORD_PROJECT", "crux")
try:
    TTL = int(_setting("CRUX_COORD_TTL_SECS", "14400"))
except (TypeError, ValueError):
    TTL = 14400
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


class _McpError(Exception):
    def __init__(self, error):
        detail = error if isinstance(error, dict) else {}
        data = detail.get("data") if isinstance(detail.get("data"), dict) else {}
        super().__init__(str(detail.get("message") or "MCP tool call failed"))
        self.status = data.get("status")


def _mcp_call(name, arguments):
    body = _post(
        MCP,
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": name, "arguments": arguments}},
        {**_auth(), "Accept": "application/json, text/event-stream"},
    )
    if not isinstance(body, dict):
        raise _McpError({"message": "MCP returned a non-object response"})
    if body.get("error"):
        raise _McpError(body["error"])
    return body


def _extract_tool_json(body):
    if not isinstance(body, dict):
        return {}
    result = body.get("result") or {}
    if not isinstance(result, dict):
        return {}
    if isinstance(result.get("structuredContent"), dict):
        return result["structuredContent"]
    for item in result.get("content") or []:
        try:
            parsed = json.loads(item.get("text", ""))
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, AttributeError):
            continue
    return {}


def _cache_path(claude_sid):
    cache_key = hashlib.sha256(str(claude_sid or "unknown").encode("utf-8")).hexdigest()
    return os.path.join(CACHE, f"{cache_key}.id")


def _invalidate_bound_session(claude_sid):
    path = _cache_path(claude_sid)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def bound_session_id(claude_sid):
    """The cuecrux_session id for this Claude session, minted once and cached.

    Cached because cuecrux_session mints a new id per call; re-minting every hook
    would scatter one agent across many phantom presence rows.
    """
    os.makedirs(CACHE, exist_ok=True)
    path = _cache_path(claude_sid)
    if os.path.exists(path):
        cached = open(path).read().strip()
        if cached:
            return cached
    body = _mcp_call("cuecrux_session", {"intent": "claude_code", "project_id": PROJECT})
    sid = _extract_session_id(body)
    if sid:
        with open(path, "w") as fh:
            fh.write(sid)
    return sid


def _extract_session_id(body):
    """cuecrux_session's id, wherever the MCP envelope put it."""
    return _extract_tool_json(body).get("session_id")


def announce(hook, clear=False):
    claude_sid = hook.get("session_id")
    cwd = hook.get("cwd") or os.getcwd()
    for attempt in range(2):
        sid = bound_session_id(claude_sid)
        if not sid:
            return  # unbound: stay silent rather than write a row we cannot join
        try:
            _mcp_call("coord_announce", {
                "session_id": sid,
                "project_id": PROJECT,
                "paths": [cwd],
                # Paths are machine-local, so a second workstation with the same checkout
                # path looks like a same-tree collision. Stamp the host so the operator can
                # tell "the other PC has this repo open" from "another session on THIS box
                # is editing the file I am about to write".
                "note": f"claude-code {os.path.basename(cwd)} @{socket.gethostname()}",
                "ttl_seconds": 0 if clear else TTL,
            })
            return
        except _McpError as error:
            # M14 tightened session ownership/project binding. A cached M13 id
            # can therefore be valid data but ineligible to announce. Invalidate
            # once and mint a project-bound session with the same credential.
            if error.status != 403 or attempt:
                raise
            _invalidate_bound_session(claude_sid)


def check(hook):
    """Warn when a peer has declared the path this Edit/Write is about to touch."""
    tool_input = hook.get("tool_input")
    if not isinstance(tool_input, dict):
        tool_input = {}
    target = tool_input.get("file_path") or ""
    if not target:
        return
    mine = None
    idfile = _cache_path(hook.get("session_id"))
    if os.path.exists(idfile):
        mine = open(idfile).read().strip()
    data = _extract_tool_json(_mcp_call("coord_status", {"project_id": PROJECT}))
    hits = []
    for s in data.get("active_sessions") or []:
        if s.get("session_id_hex") == mine:
            continue
        for p in ((s.get("intent") or {}).get("paths") or []):
            if p and (target.startswith(p.rstrip("/") + "/") or target == p):
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
        if not isinstance(hook, dict):
            hook = {}
    except (ValueError, OSError):
        hook = {}
    try:
        if verb == "announce":
            announce(hook)
        elif verb == "check":
            check(hook)
        elif verb == "clear":
            announce(hook, clear=True)
    except (_McpError, urllib.error.URLError, OSError, ValueError, TypeError, AttributeError, KeyError) as e:
        # Fail open, but say so — a silent failure here is what produced the
        # confident "0 sessions" this script exists to prevent.
        print(f"[crux-coord] {verb} unavailable: {type(e).__name__}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
