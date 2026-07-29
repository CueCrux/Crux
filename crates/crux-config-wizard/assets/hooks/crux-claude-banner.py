#!/usr/bin/env python3
# Copyright (c) 2026 CueCrux Ltd.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0.
# See LICENSE in the repository root.
"""Crux SessionStart banner for Claude Code — agent brief + conditional card.

Channels 2+3 of the crux-banner-redesign ExecPlan (M2/M4): token-lean brief +
optional first-reply CRUX card, replacing crux-boot-banner's markdown table.
Plumbing (call_tool, ThreadPoolExecutor fan-out, degraded fallback) is forked
from crux-boot-banner; the output is new (no table, no URLs, no echo). Emits
SessionStart hook JSON; exit 0 always.

SECURITY: tokens read from files into locals only — never printed/logged.

Config ~/.config/cuecrux/env: CRUX_MCP_URL, CRUX_HTTP_URL, CRUX_AGENT_TOKEN
(HS256 JWT, HTTP :14800 only). MCP bearer read from crux-tokens/anthropic.mcp-
token (MCP 401s JWTs). Switches: CRUX_BANNER_AGENT=brief|off,
CRUX_BANNER_CARD=auto|always|off, CRUX_BOOT_TIMEOUT (default 4s).
"""
from __future__ import annotations

import concurrent.futures
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter

HOME = os.path.expanduser("~")
ENV_FILE = os.path.join(HOME, ".config/cuecrux/env")
MCP_TOKEN_FILE = os.path.join(HOME, ".config/cuecrux/crux-tokens/anthropic.mcp-token")
TIMEOUT = float(os.environ.get("CRUX_BOOT_TIMEOUT", "4"))
BRIEF_CAP = 1800
LIVE_STALE_MS = 5 * 60 * 1000  # console deriveAttentionZone: 5-min liveness
_DATE = re.compile(r"-\d{4}-\d{2}-\d{2}$")

def load_env_file() -> dict:
    cfg: dict[str, str] = {}
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

def read_mcp_token() -> str:
    try:
        with open(MCP_TOKEN_FILE) as f:
            return f.read().strip()
    except OSError:
        return ""

def _parse_mcp_body(raw: str) -> dict:
    """MCP responses are plain JSON or SSE-framed (`data:` lines). Return the
    JSON-RPC envelope from either; last complete data frame wins."""
    raw = raw.strip()
    if raw.startswith("{"):
        return json.loads(raw)
    obj = None
    for ln in raw.splitlines():
        ln = ln.strip()
        if ln.startswith("data:"):
            chunk = ln[5:].strip()
            if chunk and chunk != "[DONE]":
                try:
                    obj = json.loads(chunk)
                except json.JSONDecodeError:
                    pass
    if obj is None:
        raise json.JSONDecodeError("no JSON data frame", raw or "", 0)
    return obj

def call_tool(name: str, args: dict, mcp_url: str, token: str) -> dict:
    """POST one tools/call. Returns parsed JSON, {"_raw": text} for non-JSON
    tool bodies (identity/patterns), or {"_error": msg}."""
    payload = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args or {}},
    }).encode("utf-8")
    req = urllib.request.Request(
        mcp_url, data=payload, method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"_error": f"{type(e).__name__}: {e}"}
    try:
        outer = _parse_mcp_body(raw)
    except json.JSONDecodeError as e:
        return {"_error": f"non-JSON MCP response: {e}"}
    if "error" in outer:
        return {"_error": outer["error"].get("message", "MCP error")}
    content = (outer.get("result") or {}).get("content", [])
    if not content:
        return {"_error": "empty MCP result"}
    text = content[0].get("text", "")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"_raw": text}

def http_get(url: str, token: str) -> dict:
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, OSError, ValueError, json.JSONDecodeError) as e:
        return {"_error": f"{type(e).__name__}: {e}"}

# MCP tools (name, args) and HTTP paths (key, path). update_status is added to
# the spec's MCP list because the brief/card "behind" line needs it; it degrades
# independently like every other section.
MCP_TASKS = [
    ("sync_status", {}),
    ("get_bootstrap", {"topic": "patterns", "token_budget": 500}),
    ("get_agent_identity", {}),
    ("coord_status", {}),
    ("update_status", {}),
]
HTTP_TASKS = [
    ("work", "/v1/work?source=all"),
    ("gate", "/v1/work/gate/pending"),
    ("engine", "/v1/console/engine/summary"),
    ("review", "/v1/console/review/queue"),
    ("gaps", "/v1/features/capabilities/analysis/gaps"),
]

def fetch_all(mcp_url: str, mcp_token: str, http_url: str, jwt: str) -> dict:
    out: dict[str, dict] = {}
    n = len(MCP_TASKS) + len(HTTP_TASKS)
    with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
        futs = {}
        for name, args in MCP_TASKS:
            futs[ex.submit(call_tool, name, args, mcp_url, mcp_token)] = name
        for key, path in HTTP_TASKS:
            futs[ex.submit(http_get, http_url + path, jwt)] = key
        for fut in concurrent.futures.as_completed(futs):
            out[futs[fut]] = fut.result()
    return out

def _slug(wid: str) -> str:
    s = wid[len("execplan:"):] if wid.startswith("execplan:") else wid
    return _DATE.sub("", s)

def _trim(s: str, n: int) -> str:
    s = (s or "").replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 1] + "…"

def parse_patterns(bp: dict) -> list[str]:
    raw = bp.get("_raw", "") if isinstance(bp, dict) else ""
    names = []
    for ln in raw.splitlines():
        i = ln.find("pattern:")
        if i < 0:
            continue
        start = i + len("pattern:")
        end = ln.find("]", start)
        if end > start:
            names.append(ln[start:end])
    return names

def summarize_work(work: dict):
    items = work.get("work", []) if isinstance(work, dict) else []
    counts = Counter(w.get("state") for w in items)
    in_prog = [w for w in items if w.get("state") == "in_progress"]
    # Prefer items with a current_milestone (resumable) for the top-3.
    in_prog.sort(key=lambda w: 0 if w.get("current_milestone") else 1)
    blocked = [w for w in items if w.get("state") == "blocked"]
    # "done in the last 30 days". updated_at_unix_ms is a TRAP on execplan-
    # projection rows: it's a read-time re-stamp (558/560 completed showed <7d
    # old). Use provenance.last_activity_unix_ms (real facts/decisions activity)
    # when present; kanban rows keep their genuine state-change stamp; rows with
    # neither are pre-provenance-era plans — old, so counted as not-recent.
    cutoff_ms = (time.time() - 30 * 86400) * 1000
    done30 = 0
    for w in items:
        if w.get("state") not in ("complete", "deployed"):
            continue
        ts = (w.get("provenance") or {}).get("last_activity_unix_ms")
        if ts is None and w.get("project_id") != "execplans":
            ts = w.get("updated_at_unix_ms")
        if ts is not None and ts >= cutoff_ms:
            done30 += 1
    return counts, in_prog[:3], blocked, done30

def live_sessions(coord: dict):
    """(count_live, sessions, cwd_overlap_path). Live = heartbeat <5min when a
    last_seen timestamp is present, else counted anyway (spec: else count all)."""
    # None (not 0) when the coord call failed: "we could not ask" and "we asked
    # and nobody is there" are different facts, and collapsing them to 0 reports
    # an empty board with full confidence while peers are live. Callers must
    # render the None case as unavailable rather than as a count.
    if not isinstance(coord, dict) or "_error" in coord:
        return None, [], None
    sess = coord.get("active_sessions") or []
    now = coord.get("now_unix_ms")
    live = 0
    for s in sess:
        ls = s.get("last_seen_at_unix_ms") or s.get("last_seen_unix_ms")
        if ls and now:
            if now - ls < LIVE_STALE_MS:
                live += 1
        else:
            live += 1
    cwd = os.getcwd()
    overlap = None
    for s in sess:
        for p in ((s.get("intent") or {}).get("paths") or []):
            pp = str(p).split("://", 1)[-1].rstrip("/")
            # ponytail: substring containment is a loose advisory flag, not a
            # security check — upgrade to segment-prefix if false positives bite.
            if pp and (pp in cwd or cwd in pp):
                overlap = pp
    return live, sess, overlap

def build(data: dict, card_mode: str) -> dict:
    """Pure renderer: data dict -> hook JSON dict. Testable offline."""
    ss = data.get("sync_status") or {}
    bp = data.get("get_bootstrap") or {}
    ai = data.get("get_agent_identity") or {}
    us = data.get("update_status") or {}
    engine = data.get("engine") or {}
    gate = data.get("gate") or {}
    review = data.get("review") or {}
    gaps = data.get("gaps") or {}

    mode = ss.get("mode") if "_error" not in ss else "unreachable"
    mode = mode or "unknown"
    degraded = bool(ss.get("degraded")) if "_error" not in ss else False
    facts = ss.get("local_fact_count")
    facts_s = f"{facts:,}" if isinstance(facts, int) else "?"

    behind = 0
    # basis: "binary" = drift of the running daemon (post-M6a daemons);
    # "checkout"/absent = drift of the src clone update_status tracks — label
    # it honestly and don't present it as daemon staleness (D8).
    basis = "checkout"
    if "_error" not in us:
        b = us.get("behind_by")
        if isinstance(b, int) and (us.get("state") == "behind" or b > 0):
            behind = b
        if us.get("basis") == "binary":
            basis = "binary"

    agent = "?"
    if isinstance(ai, dict) and "_error" not in ai:
        agent = (ai.get("_raw") or "").strip().strip('"') or "anonymous"

    patterns = parse_patterns(bp)
    counts, top, blocked, done30 = summarize_work(data.get("work") or {})
    wip = counts.get("in_progress", 0)
    nblocked = len(blocked)
    planned = counts.get("planned", 0)

    gate_n = gate.get("count", 0) if isinstance(gate, dict) and "_error" not in gate else 0
    review_n = review.get("live_count", 0) if isinstance(review, dict) and "_error" not in review else 0
    need_you = gate_n + nblocked
    live_n, sessions, cwd_overlap = live_sessions(data.get("coord_status") or {})

    gap_n = 0
    if isinstance(gaps, dict) and "_error" not in gaps:
        gap_n = sum(1 for g in gaps.get("gaps", []) if g.get("severity") in ("critical", "high"))

    # --- brief lines: (importance, text). Higher importance kept longer. ---
    lines: list[tuple[int, str]] = []
    if patterns:
        lines.append((100, f"patterns({len(patterns)}): {', '.join(patterns)}"))
    lines.append((95, f"mode={mode} degraded={'yes' if degraded else 'no'} facts={facts_s}"))
    if behind:
        if basis == "binary":
            lines.append((90, f"update: binary behind by {behind} — rebuild/redeploy before relying on newest features"))
        else:
            lines.append((90, f"update: src-clone behind by {behind}; binary drift unverified — check /v1/version commit before deploy-gating"))
    running = "?" if live_n is None else live_n
    lines.append((92, f"attention: {need_you} need you · {running} running · {review_n} awaiting review"))
    lines.append((60, f"agent={agent}"))
    if counts:
        resume = ", ".join(f"{_slug(w.get('id', '?'))}@{w.get('current_milestone', '?')}" for w in top)
        # Board triple (planned/active/done-30d) leads; blocked has its own line.
        wl = f"board: {planned} planned · {wip} active · {done30} done/30d"
        if resume:
            wl += f"; top: {resume}"
        lines.append((85, wl))
    if blocked:
        shown = []
        for w in blocked[:3]:
            wid = w.get("id", "?")
            sid = wid[:10] if wid.startswith("w_") else _slug(wid)[:24]
            shown.append(f'{sid} "{_trim(w.get("title", ""), 45)}"')
        bl = "blocked⚠: " + "; ".join(shown)
        if nblocked > 3:
            bl += f" (+{nblocked - 3} more)"
        lines.append((80, bl))
    if sessions:
        pc = Counter(s.get("passport_id", "?") for s in sessions)
        who = ", ".join(f"{p}×{c}" if c > 1 else p for p, c in pc.items())
        slugs = [s2 for s2 in ((s.get("intent") or {}).get("execplan_slug") for s in sessions) if s2]
        ll = f"live: {live_n} sessions ({who})"
        if slugs:
            ll += " · " + ", ".join(sorted(set(slugs)))
        ll += f" · {'⚠ overlap ' + cwd_overlap if cwd_overlap else 'no overlaps'} with cwd"
        lines.append((55, ll))
    if review_n:
        lines.append((40, f"review: {review_n} in hygiene queue"))
    if gap_n:
        lines.append((38, f"gaps: {gap_n} crit/high"))
    if isinstance(engine, dict) and "_error" not in engine:
        if engine.get("engine_reachable"):
            lines.append((30, f"engine: reachable {engine.get('engine_latency_ms', '?')}ms"))
        else:
            lines.append((30, "engine: unreachable"))

    # --- card / suppressed instruction (appended to brief) ---
    # src-clone drift alone is not attention-worthy — only binary drift,
    # blocked/gate items, or degradation should force the card (D8).
    binary_behind = behind if basis == "binary" else 0
    show_card = (card_mode == "always") or (
        card_mode == "auto" and (need_you > 0 or degraded or binary_behind > 0)
    )
    if card_mode == "off":
        show_card = False
    if show_card:
        c1 = f"⧉ CRUX · {mode} · {facts_s} facts"
        if behind:
            c1 += f" · ▲{behind} behind" if basis == "binary" else f" · ▲{behind} src"
        card_lines = [c1]
        if need_you > 0:
            first = (blocked[0] if blocked else (gate.get("pending") or [{}])[0]) or {}
            title = _trim(first.get("title", ""), 48) or "gate item"
            more = f" (+{need_you - 1} more)" if need_you > 1 else ""
            card_lines.append(f"⚠ {need_you} need you — {title}{more}")
        if top:
            t0 = top[0]
            card_lines.append(f"▶ resume: {_slug(t0.get('id', '?'))} @ {t0.get('current_milestone', '?')}")
        if counts:
            # One link only: the console Work panel is the deepest link the SPA
            # supports (segment routing, no per-state filters) — three separate
            # metric links would all open the same panel.
            # CRUX_CONSOLE_BASE already includes /console (e.g. https://…/console).
            console = (os.environ.get("CRUX_CONSOLE_BASE") or load_env_file().get("CRUX_CONSOLE_BASE") or "").rstrip("/")
            board = f"{planned} planned · {wip} active · {done30} done/30d"
            card_lines.append(f"[board]({console}#/work): {board}" if console else f"board: {board}")
        if live_n is None:
            card_lines.append("live: ⚠ coord unavailable — peer sessions NOT checked")
        else:
            ov = f"⚠ overlap {cwd_overlap}" if cwd_overlap else "no overlaps"
            card_lines.append(f"live: {live_n} sessions · {ov}")
        card = ("\n---\nOpen your first reply with exactly this block, then "
                "continue normally:\n" + "\n".join(card_lines[:7]))
    else:
        card = ("\n---\nOpen your first reply with this single line, then "
                f"continue normally:\n⧉ Crux engaged · {mode} · {facts_s} facts · {wip} wip")

    brief = fit_brief(lines, card, BRIEF_CAP)

    title = f"CRUX · {need_you} need you · {wip} wip"
    oneliner = (f"⧉ Crux engaged · {mode} · {facts_s} facts · "
                f"{need_you} need you · {wip} wip/{nblocked} blocked")
    return {
        "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": brief},
        "sessionTitle": title,
        "systemMessage": oneliner,
    }

def fit_brief(lines: list[tuple[int, str]], card: str, cap: int) -> str:
    """Assemble brief+card; while over cap, drop the least-important line."""
    cur = list(lines)

    def assemble(ls):
        return "\n".join(t for _, t in ls) + card

    while cur and len(assemble(cur)) > cap:
        i = min(range(len(cur)), key=lambda k: cur[k][0])
        cur.pop(i)
    out = assemble(cur)
    return out if len(out) <= cap else out[:cap]  # last-ditch hard clip

def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()

def emit_degraded(reason: str) -> None:
    emit({
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": f"CRUX banner degraded: {reason}",
        },
        "sessionTitle": "CRUX · degraded",
        "systemMessage": "⧉ Crux banner degraded",
    })

def main() -> None:
    if os.environ.get("CRUX_BANNER_AGENT", "brief").lower() == "off":
        emit({})
        return
    cfg = load_env_file()
    mcp_url = os.environ.get("CRUX_MCP_URL") or cfg.get("CRUX_MCP_URL") or "https://crux.cuecrux.com/mcp"
    http_url = (os.environ.get("CRUX_HTTP_URL") or cfg.get("CRUX_HTTP_URL") or "http://100.70.12.73:14800").rstrip("/")
    jwt = cfg.get("CRUX_AGENT_TOKEN", "")  # env-file only: wrapper may repurpose the env var
    mcp_token = read_mcp_token()
    card_mode = (os.environ.get("CRUX_BANNER_CARD") or cfg.get("CRUX_BANNER_CARD") or "auto").lower()

    if not jwt and not mcp_token:
        emit_degraded(f"no auth tokens ({ENV_FILE}, {MCP_TOKEN_FILE})")
        return

    data = fetch_all(mcp_url, mcp_token, http_url, jwt)
    mcp_dead = all("_error" in (data.get(n) or {}) for n, _ in MCP_TASKS)
    http_dead = all("_error" in (data.get(k) or {}) for k, _ in HTTP_TASKS)
    if mcp_dead and http_dead:
        m = (data.get("sync_status") or {}).get("_error", "mcp down")
        h = (data.get("work") or {}).get("_error", "http down")
        emit_degraded(f"all calls failed — mcp: {m}; http: {h}")
        return
    emit(build(data, card_mode))

def _selfcheck() -> int:
    # Maximal: long patterns, 58 wip / 5 blocked / 165 planned, degraded, behind,
    # overlapping live session, review+gaps>0 — the worst case for the 1800 cap.
    maximal = {
        "sync_status": {"mode": "local_only", "degraded": True, "local_fact_count": 4615},
        "get_bootstrap": {"_raw": "\n".join(f"[__bootstrap__::pattern:pattern-name-number-{i}] b" for i in range(12))},
        "get_agent_identity": {"_raw": "anthropic"},
        "update_status": {"state": "behind", "behind_by": 650},
        "coord_status": {"now_unix_ms": 1000, "active_sessions": [
            {"passport_id": "personal-default", "last_seen_at_unix_ms": 900,
             "intent": {"execplan_slug": "some-plan", "paths": [os.getcwd()]}},
            {"passport_id": "personal-default", "last_seen_at_unix_ms": 900}]},
        "work": {"work":
            [{"id": f"execplan:plan-with-a-long-slug-name-{i}-2026-07-21", "state": "in_progress",
              "current_milestone": f"M{i}", "title": "x" * 60} for i in range(58)]
            + [{"id": "w_" + "a" * 32, "state": "blocked", "title": "HANDOFF: erase tenant " * 4}] * 5
            + [{"id": f"execplan:planned-{i}", "state": "planned"} for i in range(165)]},
        "gate": {"count": 0, "pending": []}, "engine": {"engine_reachable": True, "engine_latency_ms": 9},
        "review": {"live_count": 4}, "gaps": {"gaps": [{"severity": s} for s in ("critical", "high", "low")]},
    }
    clean = {
        "sync_status": {"mode": "local_only", "degraded": False, "local_fact_count": 100},
        "get_bootstrap": {"_raw": "[__bootstrap__::pattern:only-one] body"}, "get_agent_identity": {"_raw": "anthropic"},
        "update_status": {"state": "up_to_date", "behind_by": 0}, "coord_status": {"active_sessions": []},
        "work": {"work": [{"id": "execplan:a-plan-2026-07-21", "state": "in_progress", "current_milestone": "M2", "title": "t"}]},
        "gate": {"count": 0, "pending": []}, "engine": {"engine_reachable": True, "engine_latency_ms": 5},
        "review": {"live_count": 0}, "gaps": {"gaps": []},
    }
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    out = build(maximal, "auto")
    check(set(out) >= {"hookSpecificOutput", "sessionTitle", "systemMessage"}, "three fields")
    check("hookEventName" in out["hookSpecificOutput"], "hookEventName present")
    ctx = out["hookSpecificOutput"]["additionalContext"]
    check(json.loads(json.dumps(out)) == out, "round-trips as JSON")
    check(len(ctx) <= BRIEF_CAP, f"maximal brief {len(ctx)} > {BRIEF_CAP}")
    check("⧉ CRUX ·" in ctx, "card shown on blocked>0 (auto)")

    clean_ctx = build(clean, "auto")["hookSpecificOutput"]["additionalContext"]
    check("⧉ CRUX ·" not in clean_ctx, "card suppressed on clean (auto)")
    check("Open your first reply with this single line" in clean_ctx, "single-line on clean")

    import io
    buf, real = io.StringIO(), sys.stdout
    sys.stdout = buf
    try:
        emit_degraded("test reason")
    finally:
        sys.stdout = real
    dj = json.loads(buf.getvalue())
    check(set(dj) >= {"hookSpecificOutput", "sessionTitle", "systemMessage"}, "degraded three fields")
    check(dj["sessionTitle"] == "CRUX · degraded", "degraded title")

    for m in fails:
        sys.stderr.write(f"selfcheck FAIL: {m}\n")
    print("selfcheck OK" if not fails else "selfcheck FAILED")
    return 0 if not fails else 1

if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        sys.exit(_selfcheck())
    try:
        main()
    except Exception as e:  # any unexpected failure -> valid degraded JSON
        emit_degraded(f"banner crashed: {type(e).__name__}: {e}")
    sys.exit(0)
