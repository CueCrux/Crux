#!/usr/bin/env python3
# Copyright (c) 2026 CueCrux Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.
"""Crux statusline for Claude Code (M3 of crux-banner-redesign-2026-07-21).

Hot path: read a 60s-TTL cache, render one ANSI line (<50ms, no network); if the
cache is stale/missing, render stale data and spawn a detached `--refresh` that
does the network I/O and rewrites the cache. Stdin is parsed for `session_id`
only (any other shape, or empty, is tolerated) so the prompt-cache clock can be
scoped to the session being rendered.
SECURITY: tokens are read from files into request headers only, never logged.
"""
import datetime, json, os, re, subprocess, sys, tempfile, time, urllib.request
from concurrent.futures import ThreadPoolExecutor

ENV_FILE = os.path.expanduser("~/.config/cuecrux/env")
MCP_TOKEN_FILE = os.path.expanduser("~/.config/cuecrux/crux-tokens/anthropic.mcp-token")
G, R, Y, D, X = "\033[32m", "\033[31m", "\033[1;33m", "\033[2m", "\033[0m"  # green red yellow-bold dim reset

def cache_path():
    return os.environ.get("CRUX_STATUSLINE_CACHE") or os.path.expanduser("~/.cache/crux/statusline.json")

def lock_path():
    return os.path.join(os.path.dirname(cache_path()), "statusline.lock")

def read_env():
    cfg = {}
    try:
        with open(ENV_FILE) as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#") or "=" not in ln:
                    continue
                k, v = ln.split("=", 1)
                cfg[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return cfg

def load_cache():
    try:
        with open(cache_path()) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None

def save_cache(d):
    p = cache_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(p), prefix=".statusline.")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(d, f)
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

# ---------------------------------------------------------------- fetch helpers

def _api(cfg, path, auth=True):
    """GET {HTTP}{path} -> parsed JSON. Raises on any failure (callers catch)."""
    req = urllib.request.Request(cfg["CRUX_HTTP_URL"].rstrip("/") + path)
    if auth and cfg.get("CRUX_AGENT_TOKEN"):
        req.add_header("Authorization", "Bearer " + cfg["CRUX_AGENT_TOKEN"])
    with urllib.request.urlopen(req, timeout=3) as r:
        return r.status, r.read()

def f_ready(cfg):
    try:
        st, _ = _api(cfg, "/readyz", auth=False)
        return {"reachable": st == 200}
    except Exception:
        return {"reachable": False}

def f_work(cfg):
    try:
        _, body = _api(cfg, "/v1/work?source=all")
        c = {}
        for i in json.loads(body).get("work") or []:
            c[i.get("state")] = c.get(i.get("state"), 0) + 1
        return {"wip": c.get("in_progress", 0), "blocked": c.get("blocked", 0), "planned": c.get("planned", 0)}
    except Exception:
        return {"wip": None, "blocked": None, "planned": None}

def f_gate(cfg):
    try:
        _, body = _api(cfg, "/v1/work/gate/pending")
        return {"gate_pending": json.loads(body).get("count")}
    except Exception:
        return {"gate_pending": None}

def f_coord(cfg):
    try:
        _, body = _api(cfg, "/v1/coord/active")
        return {"live": len(json.loads(body).get("active_sessions") or [])}
    except Exception:
        return {"live": None}

def f_engine(cfg):
    try:
        _, body = _api(cfg, "/v1/console/engine/summary")
        ms = json.loads(body).get("engine_latency_ms")
        return {"engine_ms": int(round(ms)) if isinstance(ms, (int, float)) else None}
    except Exception:
        return {"engine_ms": None}

def _mcp_tool(cfg, tool):
    """Call one MCP tool, return its inner text payload ('' on any failure)."""
    mcp = cfg.get("CRUX_MCP_URL")
    with open(MCP_TOKEN_FILE) as f:
        mtok = f.read().strip()
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                          "params": {"name": tool, "arguments": {}}}).encode()
    req = urllib.request.Request(mcp, data=payload, method="POST")
    req.add_header("Authorization", "Bearer " + mtok)
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    with urllib.request.urlopen(req, timeout=3) as r:
        raw = r.read().decode()
    # SSE framing: join `data:` lines if present, else the whole body is JSON.
    data = [l[5:].strip() for l in raw.splitlines() if l.startswith("data:")]
    env = json.loads("".join(data) if data else raw)
    return env["result"]["content"][0]["text"]

def f_mcp(cfg):
    out = {"mode": None, "facts": None}
    try:
        text = _mcp_tool(cfg, "sync_status")
        try:
            inner = json.loads(text)
            out["mode"] = inner.get("mode")
            fc = inner.get("local_fact_count")
            out["facts"] = int(str(fc).replace(",", "")) if fc is not None else None
        except ValueError:  # fall back to regex over human/JSON text
            m = re.search(r'"?mode"?\s*[:=]\s*"?([a-z_]+)', text)
            n = re.search(r'(?:local_fact_count|facts)"?\s*[:=]\s*"?([\d,]+)', text)
            out["mode"] = m.group(1) if m else None
            out["facts"] = int(n.group(1).replace(",", "")) if n else None
    except Exception:
        pass
    return out

def f_cache(cfg, session_id):
    """Prompt-cache clock for this session (M3 of crux-prompt-cache-1h-ttl).

    Stores the *timestamp*, not the countdown: the hot path re-derives
    `ttl_seconds_remaining` from it on every render, so the number stays honest
    between 60s refreshes instead of ageing with the cache file.
    """
    out = {"cache_session": None, "cache_last_request_at": None,
           "cache_ttl_seconds": None, "cache_est_rewrite_tokens": None}
    if not session_id:
        return out
    try:
        _, body = _api(cfg, f"/v1/sessions/{session_id}/cache")
        inner = json.loads(body)
        at = _epoch(inner.get("last_request_at"))
        if at is None:
            return out
        out["cache_session"] = session_id
        out["cache_last_request_at"] = at
        # "5m" is the API-key/credit billing TTL; "1h" and "unknown" both count
        # down from an hour (the endpoint reports which in `ttl_policy_basis`).
        out["cache_ttl_seconds"] = 300 if inner.get("ttl_policy") == "5m" else 3600
        tokens = inner.get("est_rewrite_tokens")
        out["cache_est_rewrite_tokens"] = tokens if isinstance(tokens, int) else None
    except Exception:
        pass
    return out

def _epoch(rfc3339):
    """RFC3339 -> epoch seconds, or None. Tolerates the trailing `Z`."""
    if not isinstance(rfc3339, str) or not rfc3339:
        return None
    try:
        return datetime.datetime.fromisoformat(rfc3339.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None

def f_update(cfg):
    # basis "binary" = drift of the running daemon (post-M6a); "checkout"/absent
    # = the src clone update_status tracks — rendered dim as ▲src<n>, never as
    # daemon staleness (ExecPlan crux-banner-redesign D8).
    out = {"upd_behind": None, "upd_basis": None}
    try:
        inner = json.loads(_mcp_tool(cfg, "update_status"))
        if inner.get("state") == "behind":
            out["upd_behind"] = int(inner.get("behind_by") or 0)
            out["upd_basis"] = inner.get("basis") or "checkout"
    except Exception:
        pass
    return out

def refresh(session_id=None):
    cfg = read_env()
    cache = {"ts": time.time()}
    fetchers = [f_ready, f_work, f_gate, f_coord, f_engine, f_mcp, f_update,
                lambda c: f_cache(c, session_id)]
    with ThreadPoolExecutor(max_workers=len(fetchers)) as ex:
        for frag in ex.map(lambda fn: fn(cfg), fetchers):
            cache.update(frag)
    save_cache(cache)

# --------------------------------------------------------------------- render

def _vis(s):
    return len(re.sub(r"\033\[[0-9;]*m", "", s))

def _tokens(n):
    """Coarse token count for a statusline cell: 181,447 -> `181k`."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{round(n / 1_000)}k"
    return str(n)

def cache_segment(c, now, session_id):
    """The prompt-cache clock cell, or None when it does not apply.

    Derived from `last_request_at` + the TTL policy, never from a stored
    countdown, so it stays correct however stale the cache file is. Scoped to
    `session_id`: a cell fetched for another session is not shown.
    """
    if not session_id or c.get("cache_session") != session_id:
        return None
    at, ttl = c.get("cache_last_request_at"), c.get("cache_ttl_seconds")
    if at is None or not ttl:
        return None
    remaining = ttl - (now - at)
    if remaining <= 0:
        tokens = c.get("cache_est_rewrite_tokens")
        return f"{Y}cache COLD{X}" if tokens is None else f"{Y}cache COLD ~{_tokens(tokens)}{X}"
    mins = int(remaining // 60)
    # Amber inside the last 10 minutes: still recoverable by prompting now.
    return f"{Y}cache {mins}m{X}" if remaining < 600 else f"cache {mins}m"

def render(c, now, session_id=None):
    if c is None:
        return f"{D}⧉ CRUX … warming{X}"
    age = now - c.get("ts", now)
    if not c.get("reachable"):
        segs = [f"{R}⧉ CRUX ✗ unreachable{X}"]
        extra = []
        if c.get("mode"):
            extra.append(c["mode"])
        if c.get("facts") is not None:
            extra.append(f"{c['facts']:,} facts")
        if extra:
            segs.append(f"{D}{' · '.join(extra)}{X}")
        line = " · ".join(segs)
    else:
        segs = [f"{G}⧉ CRUX ok{X}"]
        if c.get("mode"):
            segs.append(c["mode"])
        if c.get("facts") is not None:
            segs.append(f"{c['facts']:,} facts")
        # Early in the list deliberately: the ponytail below drops from the tail,
        # and a cold cache is the most expensive thing the line can tell you.
        cache_cell = cache_segment(c, now, session_id)
        if cache_cell:
            segs.append(cache_cell)
        if c.get("upd_behind"):
            if c.get("upd_basis") == "binary":
                segs.append(f"{Y}▲{c['upd_behind']}{X}")
            else:
                segs.append(f"{D}▲src{c['upd_behind']}{X}")
        gp, bl = c.get("gate_pending"), c.get("blocked")
        if gp is not None or bl is not None:
            need = (gp or 0) + (bl or 0)
            segs.append(f"{Y}⚠ {need} need you{X}" if need > 0 else f"{need} need you")
        if c.get("wip") is not None:
            blk = bl or 0
            segs.append(f"{c['wip']} wip/" + (f"{Y}{blk} blk{X}" if blk > 0 else f"{blk} blk"))
        if c.get("live") is not None:
            segs.append(f"{c['live']} live")
        if c.get("engine_ms") is not None:
            segs.append(f"engine {c['engine_ms']}ms")
        while _vis(" · ".join(segs)) > 110 and len(segs) > 1:
            segs.pop()  # ponytail: drop least-important trailing segment (engine, then live)
        line = " · ".join(segs)
    if age > 300:
        line += f" {D}(stale {int(age // 60)}m){X}"
    return line

def maybe_spawn_refresh(session_id=None):
    lp = lock_path()
    try:
        if os.path.exists(lp) and time.time() - os.path.getmtime(lp) < 30:
            return  # a recent refresher is likely still running; no stampede
    except OSError:
        pass
    try:
        os.makedirs(os.path.dirname(lp), exist_ok=True)
        with open(lp, "w") as f:
            f.write(str(time.time()))
        argv = [sys.executable, os.path.abspath(__file__), "--refresh"]
        if session_id:
            argv.append(session_id)
        subprocess.Popen(argv,
                         start_new_session=True, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

def read_session_id():
    """`session_id` off the statusline payload, or None. Never raises."""
    try:
        raw = sys.stdin.read()
    except Exception:
        return None
    try:
        sid = json.loads(raw).get("session_id")
    except (ValueError, AttributeError):
        return None
    return sid if isinstance(sid, str) and sid else None

def hot_path():
    session_id = read_session_id()
    c = load_cache()
    now = time.time()
    if c is None or now - c.get("ts", 0) > 60:
        maybe_spawn_refresh(session_id)
    sys.stdout.write(render(c, now, session_id) + "\n")

def selfcheck():
    d = tempfile.mkdtemp(prefix="crux-sl-")
    os.environ["CRUX_STATUSLINE_CACHE"] = os.path.join(d, "statusline.json")
    now = time.time()
    healthy = {"ts": now, "reachable": True, "mode": "local_only", "facts": 4596,
               "gate_pending": 0, "blocked": 0, "wip": 58, "live": 2, "engine_ms": 4}
    attention = {**healthy, "blocked": 5}
    unreachable = {"ts": now, "reachable": False, "mode": "local_only", "facts": 4596}
    stale = {**healthy, "ts": now - 600}
    for fx, checks in [(healthy, ["ok", "wip", "58 wip/0 blk"]), (attention, ["⚠", "need you"]),
                       (unreachable, ["✗", "unreachable"]), (stale, ["stale"])]:
        save_cache(fx)
        line = render(load_cache(), time.time())
        for sub in checks:
            assert sub in line, f"expected {sub!r} in {line!r}"
    assert "⚠" not in render(healthy, now), "healthy must not warn"

    # --- prompt-cache clock (M3 of crux-prompt-cache-1h-ttl-2026-09-17) -------
    sid = "sess-abc"
    warm = {**healthy, "cache_session": sid, "cache_last_request_at": now - 1560,
            "cache_ttl_seconds": 3600, "cache_est_rewrite_tokens": 181_447}
    # 3600 - 1560 = 2040s left -> 34m, not amber.
    assert "cache 34m" in render(warm, now, sid), render(warm, now, sid)
    assert f"{Y}cache 34m" not in render(warm, now, sid), "34m left must not be amber"
    # The countdown is derived from last_request_at, so it ages with wall clock
    # and not with the cache file: same fixture, 10 minutes later.
    assert "cache 24m" in render(warm, now + 600, sid), "countdown must track wall clock"
    expiring = {**warm, "cache_last_request_at": now - 3300}  # 5m left
    assert f"{Y}cache 5m{X}" in render(expiring, now, sid), "under 10m must be amber"
    cold = {**warm, "cache_last_request_at": now - 4000}
    assert "cache COLD ~181k" in render(cold, now, sid), render(cold, now, sid)
    # Never borrow another session's clock, and never invent one.
    assert "cache" not in render(cold, now, "other-session")
    assert "cache" not in render(cold, now, None)
    assert "cache" not in render(healthy, now, sid)
    # An un-costed session reports null tokens: say COLD without a number.
    assert "cache COLD" in render({**cold, "cache_est_rewrite_tokens": None}, now, sid)
    assert "~" not in render({**cold, "cache_est_rewrite_tokens": None}, now, sid)
    # A malformed/empty statusline payload must never break the hot path.
    assert _epoch(None) is None and _epoch("not-a-date") is None
    assert _epoch("2026-09-17T14:02:00Z") is not None

    os.unlink(cache_path())
    assert "warming" in render(load_cache(), now), "no-cache hot path must show warming"
    print("selfcheck OK")

def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--refresh":
        refresh(sys.argv[2] if len(sys.argv) > 2 else None)
    elif arg == "--selfcheck":
        selfcheck()
    else:
        hot_path()

if __name__ == "__main__":
    main()
